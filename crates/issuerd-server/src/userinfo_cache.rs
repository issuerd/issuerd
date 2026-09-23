// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Rendered-response cache for the userinfo endpoint.

//! Caches the fully rendered userinfo JSON body so a warm-cache request
//! skips user/role/catalog reads, mapper evaluation, and response-tree
//! building entirely — the logical end-point of the claims read-model
//! approach (`claims_cache.rs`).
//!
//! The rendered body is a pure function of:
//!
//! - the resolved user (`session.user_id`, or `sub` for session-less
//!   client-credentials tokens) — covered by `usergen:{realm}:{user_id}`;
//! - the issuing client (`aud`) and its mapper config — covered by
//!   `clientgen:{realm}:{client_id}`;
//! - the realm's role/scope definitions — covered by `claimsepoch:{realm}`;
//! - the token's scope set and optional `claims` / `authorization_details`
//!   parameters — embedded in the entry's fingerprint.
//!
//! Every entry is a 24-byte header (`epoch | usergen | clientgen`,
//! big-endian) prepended to the body bytes; a hit is valid only when all
//! three counters match the current values, so a role/attribute/mapper
//! change takes effect on the very next request (the invalidation helpers
//! in `issuerd_cluster::invalidate` bump the generations; definition changes
//! bump the epoch). Validity gates — token signature, expiry, revocation
//! list, realm `not_before`, and the user-session check — run per request
//! BEFORE this cache is consulted, so a logged-out or revoked token never
//! reaches it.
//!
//! Degradation mirrors `claims_cache`: `[cache] read_cache_ttl_secs = 0`
//! disables the layer; cache errors are a miss (the handler recomputes via
//! the read model) and skip the write — an outage costs latency, never
//! answers. Entries built from a partially-degraded read model during a
//! storage blip may be served until the TTL expires — the same staleness
//! class the read model documents for its TTL.
//!
//! Fingerprint collisions: the fingerprint embeds the client identifier and
//! the sorted scope list verbatim; a scope name containing `|` plus a
//! crafted 16-hex-char suffix could alias another entry's `claims` hash
//! slot. Scope names are realm-admin controlled, so this is a
//! configuration-hygiene note, not an attack surface.

use std::sync::Arc;
use std::time::Duration;

use issuerd_cluster::cache_keys;
use issuerd_core::{AccessTokenClaims, RealmId, UserId};
use tracing::{debug, warn};

use crate::state::ServerState;

const HEADER_LEN: usize = 24; // epoch | usergen | clientgen, u64 big-endian each

/// Fingerprint of the token-derived inputs to the rendered body:
/// `aud | sorted-scope-csv [|c:<hash>] [|r:<hash>]`.
pub fn fingerprint(claims: &AccessTokenClaims) -> String {
    let mut fp = String::with_capacity(claims.aud.as_str().len() + 64);
    fp.push_str(claims.aud.as_str());
    fp.push('|');
    let mut scopes = claims.scope.to_vec();
    scopes.sort_unstable();
    fp.push_str(&scopes.join(" "));
    if let Some(c) = &claims.claims {
        fp.push_str("|c:");
        fp.push_str(&content_hash(c));
    }
    if let Some(r) = &claims.authorization_details {
        fp.push_str("|r:");
        fp.push_str(&content_hash(r));
    }
    fp
}

/// SHA-256 over the deterministic JSON serialization (serde_json maps are
/// BTreeMap-ordered), truncated to 16 hex chars — key material only.
fn content_hash<T: serde::Serialize>(value: &T) -> String {
    use sha2::Digest;
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let digest = sha2::Sha256::digest(&bytes);
    let mut out = String::with_capacity(16);
    for b in &digest[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The current (epoch, usergen, clientgen) counters, read concurrently.
/// `None` on any cache error — callers treat it as a cache outage and
/// bypass the layer (recompute, skip the write).
async fn counters(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    user_id: &UserId,
    client_id: &str,
) -> Option<(u64, u64, u64)> {
    let read = |key: String| async move {
        match state.cache.get(&key).await {
            Ok(Some(bytes)) => std::str::from_utf8(&bytes).ok()?.parse::<u64>().ok(),
            Ok(None) => Some(0),
            Err(e) => {
                warn!(error = %e, "userinfo response cache: counter read failed");
                None
            }
        }
    };
    let realm = realm_id.as_ref();
    let (epoch, usergen, clientgen) = tokio::join!(
        read(cache_keys::claims_epoch(realm)),
        read(cache_keys::user_claims_generation(realm, user_id.as_ref())),
        read(cache_keys::client_claims_generation(realm, client_id)),
    );
    Some((epoch?, usergen?, clientgen?))
}

/// A valid cached body for (user, fingerprint); `None` on miss, staleness,
/// outage, or a disabled cache. `client_id` is the token's `aud` — passed
/// separately (not parsed out of the fingerprint) because client
/// identifiers may legitimately contain the fingerprint's `|` separator.
pub async fn read(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    user_id: &UserId,
    client_id: &str,
    fingerprint: &str,
) -> Option<Vec<u8>> {
    let ttl = state.config.cache.read_cache_ttl_secs;
    if ttl == 0 {
        return None;
    }
    let (epoch, usergen, clientgen) = counters(state, realm_id, user_id, client_id).await?;
    let key = cache_keys::userinfo_response(realm_id.as_ref(), user_id.as_ref(), fingerprint);
    let bytes = match state.cache.get(&key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return None,
        Err(e) => {
            warn!(realm = %realm_id, error = %e, "userinfo response cache read failed");
            return None;
        }
    };
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let header = u64::from_be_bytes;
    let stored = (
        header(bytes[0..8].try_into().ok()?),
        header(bytes[8..16].try_into().ok()?),
        header(bytes[16..24].try_into().ok()?),
    );
    if stored != (epoch, usergen, clientgen) {
        debug!(realm = %realm_id, "userinfo response cache: stale entry");
        return None;
    }
    debug!(realm = %realm_id, "userinfo response cache: hit");
    Some(bytes[HEADER_LEN..].to_vec())
}

/// Store the rendered body (validated on read against the counters).
/// Best-effort: failures are logged and swallowed.
pub async fn write(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    user_id: &UserId,
    client_id: &str,
    fingerprint: &str,
    body: &[u8],
) {
    let ttl = state.config.cache.read_cache_ttl_secs;
    if ttl == 0 {
        return;
    }
    let Some((epoch, usergen, clientgen)) = counters(state, realm_id, user_id, client_id).await
    else {
        return;
    };
    let key = cache_keys::userinfo_response(realm_id.as_ref(), user_id.as_ref(), fingerprint);
    let mut bytes = Vec::with_capacity(HEADER_LEN + body.len());
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&usergen.to_be_bytes());
    bytes.extend_from_slice(&clientgen.to_be_bytes());
    bytes.extend_from_slice(body);
    if let Err(e) = state.cache.set(&key, bytes, Some(Duration::from_secs(ttl))).await {
        warn!(realm = %realm_id, error = %e, "userinfo response cache write failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{ClientId, Username};
    use std::collections::HashMap;

    async fn setup() -> (Arc<ServerState>, RealmId, UserId) {
        let state = Arc::new(
            ServerState::from_config(&crate::config::ServerConfig::default()).await.unwrap(),
        );
        let realm_id = RealmId::new("master").unwrap();
        let user_id = UserId::new("alice").unwrap();
        let user = issuerd_core::User {
            id: user_id.clone(),
            realm_id: realm_id.clone(),
            username: Username::new("alice").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();
        (state, realm_id, user_id)
    }

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let (state, realm, user) = setup().await;
        write(&state, &realm, &user, "app", "app|openid", b"{\"sub\":\"alice\"}").await;
        let body = read(&state, &realm, &user, "app", "app|openid").await.expect("hit");
        assert_eq!(body, b"{\"sub\":\"alice\"}");
        // A different fingerprint misses.
        assert!(read(&state, &realm, &user, "app", "app|openid profile").await.is_none());
    }

    #[tokio::test]
    async fn epoch_bump_invalidates() {
        let (state, realm, user) = setup().await;
        write(&state, &realm, &user, "app", "app|openid", b"{}").await;
        assert!(read(&state, &realm, &user, "app", "app|openid").await.is_some());
        issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm).await;
        assert!(read(&state, &realm, &user, "app", "app|openid").await.is_none());
    }

    #[tokio::test]
    async fn user_invalidation_invalidates() {
        let (state, realm, user) = setup().await;
        write(&state, &realm, &user, "app", "app|openid", b"{}").await;
        assert!(read(&state, &realm, &user, "app", "app|openid").await.is_some());
        issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm, &user)
            .await;
        assert!(read(&state, &realm, &user, "app", "app|openid").await.is_none());
    }

    #[tokio::test]
    async fn client_invalidation_invalidates() {
        let (state, realm, user) = setup().await;
        write(&state, &realm, &user, "app", "app|openid", b"{}").await;
        assert!(read(&state, &realm, &user, "app", "app|openid").await.is_some());
        issuerd_cluster::invalidate::invalidate_client_claims(
            state.cache.as_ref(),
            &realm,
            &ClientId::new("uuid-1").unwrap(),
            "app",
        )
        .await;
        assert!(read(&state, &realm, &user, "app", "app|openid").await.is_none());
        // An unrelated client's bump leaves the entry alone.
        write(&state, &realm, &user, "app", "app|openid", b"{}").await;
        issuerd_cluster::invalidate::invalidate_client_claims(
            state.cache.as_ref(),
            &realm,
            &ClientId::new("uuid-2").unwrap(),
            "other-app",
        )
        .await;
        assert!(read(&state, &realm, &user, "app", "app|openid").await.is_some());
    }

    #[tokio::test]
    async fn disabled_cache_never_serves() {
        let mut cfg = crate::config::ServerConfig::default();
        cfg.cache.read_cache_ttl_secs = 0;
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm = RealmId::new("master").unwrap();
        let user = UserId::new("alice").unwrap();
        write(&state, &realm, &user, "app", "app|openid", b"{}").await;
        assert!(read(&state, &realm, &user, "app", "app|openid").await.is_none());
    }

    #[tokio::test]
    async fn cache_outage_is_a_miss_not_an_error() {
        #[derive(Debug)]
        struct DeadCache;
        #[async_trait::async_trait]
        impl issuerd_core::DistributedCache for DeadCache {
            async fn get(&self, _: &str) -> Result<Option<Vec<u8>>, issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("down".into()))
            }
            async fn set(
                &self,
                _: &str,
                _: Vec<u8>,
                _: Option<Duration>,
            ) -> Result<(), issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("down".into()))
            }
            async fn delete(&self, _: &str) -> Result<(), issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("down".into()))
            }
            async fn compare_and_swap(
                &self,
                _: &str,
                _: Option<Vec<u8>>,
                _: Vec<u8>,
            ) -> Result<bool, issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("down".into()))
            }
            async fn publish(&self, _: &str, _: Vec<u8>) -> Result<(), issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("down".into()))
            }
            async fn subscribe(
                &self,
                _: &str,
                _: Box<dyn Fn(Vec<u8>) + Send + Sync>,
            ) -> Result<(), issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("down".into()))
            }
        }
        let cfg = crate::config::ServerConfig::default();
        let storage: Arc<dyn issuerd_core::Storage> =
            Arc::new(issuerd_storage::InMemoryStorage::new());
        let state = Arc::new(
            ServerState::from_components(&cfg, storage, Arc::new(DeadCache)).await.unwrap(),
        );
        let realm = RealmId::new("master").unwrap();
        let user = UserId::new("alice").unwrap();
        assert!(read(&state, &realm, &user, "app", "app|openid").await.is_none());
        write(&state, &realm, &user, "app", "app|openid", b"{}").await; // must not panic
    }

    #[test]
    fn fingerprint_distinguishes_scope_order_and_params() {
        use issuerd_core::{Audience, Issuer, JwtId, JwtType, Scope, SessionId};
        let claims = |scope: &str, claims_param: Option<serde_json::Value>| AccessTokenClaims {
            jti: JwtId::new("j").unwrap(),
            iss: Issuer::new("http://localhost/realms/r").unwrap(),
            sub: UserId::new("u").unwrap(),
            aud: Audience::new("app").unwrap(),
            exp: 0,
            iat: 0,
            nbf: 0,
            scope: Scope::parse(scope),
            typ: JwtType::Bearer,
            azp: None,
            session_state: None,
            realm_access: None,
            resource_access: None,
            sid: Some(SessionId::new("s").unwrap()),
            claims: claims_param,
            cnf: None,
            authorization_details: None,
        };
        // Scope order is normalized.
        assert_eq!(
            fingerprint(&claims("openid profile", None)),
            fingerprint(&claims("profile openid", None))
        );
        // Client, scope set, and claims parameter each change the fingerprint.
        assert_ne!(
            fingerprint(&claims("openid", None)),
            fingerprint(&claims("openid profile", None))
        );
        assert_ne!(
            fingerprint(&claims("openid", None)),
            fingerprint(&claims("openid", Some(serde_json::json!({"userinfo": {"name": null}}))))
        );
    }
}
