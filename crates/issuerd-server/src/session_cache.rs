// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Session-validity cache-aside layer: keeps the per-request "does this
// session still exist" check off the database (userinfo / introspect / token
// resolution hot paths).

//! Cache-aside snapshots of user-session validity.
//!
//! Every `userinfo` and `introspect` call must confirm the token's user
//! session still exists in storage; that check used to cost two SQL queries
//! per request. This module caches the answer under
//! `cache_keys::session(realm, sid)` as a small JSON value:
//!
//! - positive: `{"u": "<user_id>", "v": <u64 version>}`, TTL
//!   `[cache] read_cache_ttl_secs` (default 60 s, `0` disables the
//!   cache entirely — pure-DB behavior);
//! - negative: `{"x":1}` with a short TTL (absorbs replay floods of
//!   deleted-session tokens; forged sids are impossible because token
//!   signature validation runs before this layer).
//!
//! Invalidation:
//! - single-session deletes (logout, admin revoke, idle cleanup) call
//!   [`invalidate_session`] synchronously — revocation is immediate;
//! - bulk per-user revocation (user delete, which DB-cascades sessions
//!   without touching Rust) bumps the `sessv:{realm}:{user_id}` counter via
//!   [`bump_user_session_version`]; cached snapshots carrying an older
//!   version are treated as misses and re-read from storage;
//! - anything that still bypasses both (e.g. a realm delete cascade on a
//!   node that missed invalidation) is bounded by the positive TTL —
//!   the accepted staleness window, same class as Keycloak's Infinispan
//!   invalidation latency. Realm deletes are additionally covered because
//!   `resolve_issuer_realm` invalidation makes the issuer unresolvable.
//!
//! Cache outages degrade, never fail: every cache error falls back to the
//! storage path with a WARN, so a Redis hiccup costs latency, not answers.

use std::sync::Arc;
use std::time::Duration;

use issuerd_cluster::cache_keys;
use issuerd_core::{DistributedCache, RealmId, SessionId, UserId};
use tracing::{debug, warn};

use crate::state::ServerState;

/// TTL of the negative ("session does not exist") marker. Short on purpose:
/// it only needs to absorb replay bursts of a deleted-session token.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// The validity-relevant slice of a user session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub user_id: UserId,
}

/// Cached entry: positive (`u`/`v`) or the negative marker (`x`).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum CacheEntry {
    Negative { x: u8 },
    Positive { u: String, v: u64 },
}

fn parse_entry(bytes: &[u8]) -> Option<CacheEntry> {
    serde_json::from_slice(bytes).ok()
}

/// Read the per-user session version counter; a missing key is version 0.
/// Cache errors report `None` so callers fall back to the database.
async fn current_version(
    cache: &Arc<dyn DistributedCache>,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Option<u64> {
    let key = cache_keys::session_version(realm_id.as_ref(), user_id.as_ref());
    match cache.get(&key).await {
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes).ok()?.parse::<u64>() {
            Ok(v) => Some(v),
            Err(_) => {
                warn!(realm = %realm_id, "session version counter unparsable; treating as 0");
                Some(0)
            }
        },
        Ok(None) => Some(0),
        Err(e) => {
            warn!(realm = %realm_id, error = %e, "session version read failed; falling back to storage");
            None
        }
    }
}

/// Resolve a session's validity snapshot, cache-aside.
///
/// `Some` means the session exists (presence is the validity signal, exactly
/// as the previous direct `get_user_session` check defined it); `None` means
/// missing, unreadable, or stale-versioned — callers keep their existing
/// fail-closed handling. Storage errors also surface as `None` here; the
/// caller's `is_sessionless_client_token` logic decides the final verdict.
pub async fn session_snapshot(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    sid: &SessionId,
) -> Option<SessionSnapshot> {
    let ttl_secs = state.config.cache.read_cache_ttl_secs;
    if ttl_secs == 0 {
        // Cache disabled: pure-DB behavior.
        return match state.storage.get_user_session(realm_id, sid).await {
            Ok(Some(session)) => Some(SessionSnapshot {
                user_id: session.user_id,
            }),
            Ok(None) => None,
            Err(e) => {
                debug!(realm = %realm_id, error = %e, "session read failed");
                None
            }
        };
    }

    let key = cache_keys::session(realm_id.as_ref(), sid.as_ref());
    match state.cache.get(&key).await {
        Ok(Some(bytes)) => match parse_entry(&bytes) {
            Some(CacheEntry::Negative { .. }) => {
                debug!(realm = %realm_id, "session cache: negative hit");
                None
            }
            Some(CacheEntry::Positive { u, v }) => {
                let Ok(user_id) = UserId::new(&u) else {
                    debug!(realm = %realm_id, "session cache: malformed user id; re-reading");
                    return load_and_cache(state, realm_id, sid, ttl_secs).await;
                };
                match current_version(&state.cache, realm_id, &user_id).await {
                    Some(current) if current == v => {
                        debug!(realm = %realm_id, "session cache: hit");
                        Some(SessionSnapshot { user_id })
                    }
                    // Version mismatch (bulk revocation) or version read
                    // failure: re-read from storage.
                    _ => load_and_cache(state, realm_id, sid, ttl_secs).await,
                }
            }
            None => {
                debug!(realm = %realm_id, "session cache: malformed entry; re-reading");
                load_and_cache(state, realm_id, sid, ttl_secs).await
            }
        },
        Ok(None) => load_and_cache(state, realm_id, sid, ttl_secs).await,
        Err(e) => {
            warn!(realm = %realm_id, error = %e, "session cache read failed; falling back to storage");
            load_and_cache(state, realm_id, sid, ttl_secs).await
        }
    }
}

/// Storage read + cache populate behind [`session_snapshot`].
async fn load_and_cache(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    sid: &SessionId,
    ttl_secs: u64,
) -> Option<SessionSnapshot> {
    let key = cache_keys::session(realm_id.as_ref(), sid.as_ref());
    match state.storage.get_user_session(realm_id, sid).await {
        Ok(Some(session)) => {
            // Best-effort version tag: an unreadable counter stores v=0, which
            // simply re-validates against storage after any bump (a real
            // version >0 never matches the stored 0, so the entry misses).
            let version =
                current_version(&state.cache, realm_id, &session.user_id).await.unwrap_or(0);
            let entry = CacheEntry::Positive {
                u: session.user_id.to_string(),
                v: version,
            };
            if let Ok(bytes) = serde_json::to_vec(&entry) {
                if let Err(e) =
                    state.cache.set(&key, bytes, Some(Duration::from_secs(ttl_secs))).await
                {
                    warn!(realm = %realm_id, error = %e, "session cache write failed");
                }
            }
            Some(SessionSnapshot {
                user_id: session.user_id,
            })
        }
        Ok(None) => {
            if let Ok(bytes) = serde_json::to_vec(&CacheEntry::Negative { x: 1 }) {
                if let Err(e) = state.cache.set(&key, bytes, Some(NEGATIVE_TTL)).await {
                    warn!(realm = %realm_id, error = %e, "session cache write failed");
                }
            }
            None
        }
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "session read failed");
            None
        }
    }
}

/// Drop a session's cached snapshot after its deletion (logout, admin
/// revoke, idle cleanup). Best-effort: the positive TTL bounds staleness if
/// the delete fails.
pub async fn invalidate_session(state: &Arc<ServerState>, realm_id: &RealmId, sid: &SessionId) {
    invalidate_session_entry(state.cache.as_ref(), realm_id, sid).await;
}

/// [`invalidate_session`] over a bare cache reference — shared by callers
/// that do not hold a full [`ServerState`].
pub async fn invalidate_session_entry(
    cache: &dyn DistributedCache,
    realm_id: &RealmId,
    sid: &SessionId,
) {
    let key = cache_keys::session(realm_id.as_ref(), sid.as_ref());
    if let Err(e) = cache.delete(&key).await {
        warn!(realm = %realm_id, error = %e, "session cache invalidation failed");
    }
}

/// Bump the per-user session-validity version counter (bulk revocation:
/// user delete / logout-all). Every cached snapshot of this user's sessions
/// misses on its next read. No TTL: the counter must outlive any cached
/// snapshot it invalidates. Best-effort: snapshots keep their TTL as the
/// fail-safe bound if the bump fails.
pub async fn bump_user_session_version(
    cache: &dyn DistributedCache,
    realm_id: &RealmId,
    user_id: &UserId,
) {
    let key = cache_keys::session_version(realm_id.as_ref(), user_id.as_ref());
    if let Err(e) = cache.increment(&key, None).await {
        warn!(realm = %realm_id, error = %e, "session version bump failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{AuthMethod, UserSession, Username};

    async fn setup() -> (Arc<ServerState>, issuerd_core::RealmId, UserId, SessionId) {
        let state = Arc::new(
            ServerState::from_config(&crate::config::ServerConfig::default()).await.unwrap(),
        );
        let realm_id = RealmId::new("master").unwrap();
        let user_id = UserId::new("admin").unwrap();
        let sid = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        (state, realm_id, user_id, sid)
    }

    fn session(realm_id: &RealmId, user_id: &UserId, sid: &SessionId) -> UserSession {
        UserSession {
            id: sid.clone(),
            realm_id: realm_id.clone(),
            user_id: user_id.clone(),
            login_username: Username::new("admin").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: chrono::Utc::now(),
            last_session_refresh: chrono::Utc::now(),
            auth_time: chrono::Utc::now(),
            impersonator: None,
            clients: vec![],
        }
    }

    fn cache_key(realm_id: &RealmId, sid: &SessionId) -> String {
        cache_keys::session(realm_id.as_ref(), sid.as_ref())
    }

    #[tokio::test]
    async fn snapshot_caches_positive_entry() {
        let (state, realm_id, user_id, sid) = setup().await;
        state
            .storage
            .create_user_session(&realm_id, &session(&realm_id, &user_id, &sid))
            .await
            .unwrap();

        let snap = session_snapshot(&state, &realm_id, &sid).await.expect("snapshot");
        assert_eq!(snap.user_id, user_id);

        // Second read must come from the cache: deleting the row directly
        // (bypassing invalidation) still answers within the TTL window —
        // the documented bounded-staleness trade-off.
        state.storage.delete_user_session(&realm_id, &sid).await.unwrap();
        let snap = session_snapshot(&state, &realm_id, &sid).await;
        assert!(snap.is_some(), "stale positive entry served within TTL");

        // Synchronous invalidation takes effect immediately.
        state
            .storage
            .create_user_session(&realm_id, &session(&realm_id, &user_id, &sid))
            .await
            .unwrap();
        invalidate_session(&state, &realm_id, &sid).await;
        state.storage.delete_user_session(&realm_id, &sid).await.unwrap();
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_none());
    }

    #[tokio::test]
    async fn snapshot_negative_entry_absorbs_replays() {
        let (state, realm_id, _, sid) = setup().await;

        // First miss hits storage and caches the negative marker.
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_none());
        let raw = state
            .cache
            .get(&cache_key(&realm_id, &sid))
            .await
            .unwrap()
            .expect("negative marker cached");
        assert_eq!(std::str::from_utf8(&raw).unwrap(), r#"{"x":1}"#);

        // A session appearing under the same id within the negative window is
        // NOT seen (replay absorption); after the marker is dropped the new
        // session resolves.
        let user_id = UserId::new("admin").unwrap();
        state
            .storage
            .create_user_session(&realm_id, &session(&realm_id, &user_id, &sid))
            .await
            .unwrap();
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_none());
        state.cache.delete(&cache_key(&realm_id, &sid)).await.unwrap();
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_some());
    }

    #[tokio::test]
    async fn version_bump_invalidates_cached_snapshot() {
        let (state, realm_id, user_id, sid) = setup().await;
        state
            .storage
            .create_user_session(&realm_id, &session(&realm_id, &user_id, &sid))
            .await
            .unwrap();
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_some());

        // Bulk per-user revocation: sessions cascade away in storage and the
        // version bump makes every cached snapshot of the user miss.
        state.storage.delete_user(&realm_id, &user_id).await.unwrap();
        bump_user_session_version(state.cache.as_ref(), &realm_id, &user_id).await;
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_none());

        // The version counter persists (no TTL).
        let v = state
            .cache
            .get(&cache_keys::session_version(realm_id.as_ref(), user_id.as_ref()))
            .await
            .unwrap()
            .expect("version counter present");
        assert_eq!(std::str::from_utf8(&v).unwrap(), "1");
    }

    #[tokio::test]
    async fn version_bump_alone_does_not_hide_live_session() {
        let (state, realm_id, user_id, sid) = setup().await;
        state
            .storage
            .create_user_session(&realm_id, &session(&realm_id, &user_id, &sid))
            .await
            .unwrap();
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_some());

        // A bump without an underlying delete re-reads from storage and
        // re-caches at the new version — the session stays valid.
        bump_user_session_version(state.cache.as_ref(), &realm_id, &user_id).await;
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_some());
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_some());
    }

    #[tokio::test]
    async fn disabled_cache_is_pure_db() {
        let mut cfg = crate::config::ServerConfig::default();
        cfg.cache.read_cache_ttl_secs = 0;
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm_id = RealmId::new("master").unwrap();
        let user_id = UserId::new("admin").unwrap();
        let sid = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        state
            .storage
            .create_user_session(&realm_id, &session(&realm_id, &user_id, &sid))
            .await
            .unwrap();

        assert!(session_snapshot(&state, &realm_id, &sid).await.is_some());
        // Nothing was cached.
        assert!(state.cache.get(&cache_key(&realm_id, &sid)).await.unwrap().is_none());
        // A direct storage delete is seen immediately (no TTL window).
        state.storage.delete_user_session(&realm_id, &sid).await.unwrap();
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_none());
        assert!(state.cache.get(&cache_key(&realm_id, &sid)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cache_outage_falls_back_to_storage() {
        #[derive(Debug)]
        struct DeadCache;
        #[async_trait::async_trait]
        impl DistributedCache for DeadCache {
            async fn get(&self, _: &str) -> Result<Option<Vec<u8>>, issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("cache down".into()))
            }
            async fn set(
                &self,
                _: &str,
                _: Vec<u8>,
                _: Option<Duration>,
            ) -> Result<(), issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("cache down".into()))
            }
            async fn delete(&self, _: &str) -> Result<(), issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("cache down".into()))
            }
            async fn compare_and_swap(
                &self,
                _: &str,
                _: Option<Vec<u8>>,
                _: Vec<u8>,
            ) -> Result<bool, issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("cache down".into()))
            }
            async fn publish(&self, _: &str, _: Vec<u8>) -> Result<(), issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("cache down".into()))
            }
            async fn subscribe(
                &self,
                _: &str,
                _: Box<dyn Fn(Vec<u8>) + Send + Sync>,
            ) -> Result<(), issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("cache down".into()))
            }
        }

        let cfg = crate::config::ServerConfig::default();
        let storage: Arc<dyn issuerd_core::Storage> =
            Arc::new(issuerd_storage::InMemoryStorage::new());
        let state = Arc::new(
            ServerState::from_components(&cfg, storage, Arc::new(DeadCache)).await.unwrap(),
        );
        let realm_id = RealmId::new("master").unwrap();
        let user_id = UserId::new("admin").unwrap();
        let sid = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        state
            .storage
            .create_user_session(&realm_id, &session(&realm_id, &user_id, &sid))
            .await
            .unwrap();

        // Reads and writes fail; answers still come from storage.
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_some());
        state.storage.delete_user_session(&realm_id, &sid).await.unwrap();
        assert!(session_snapshot(&state, &realm_id, &sid).await.is_none());
    }
}
