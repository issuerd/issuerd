// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Pre-rendered OIDC discovery document cache.

//! The discovery document is a pure function of the realm row (name, PAR
//! policy, registration toggle, authorization-details types) and the active
//! signing-key set (advertised algorithms), yet was rebuilt — a dozen URL
//! parses plus a full struct serialization — on every one of the hottest
//! requests an OIDC provider serves.
//!
//! Entries live under `discovery-resp:{realm_name}` in the shared
//! `DistributedCache` as `8-byte realm hash | 8-byte keyset generation |
//! body`. The realm hash is SHA-256 (truncated) over the serialized realm
//! row the handler just resolved, so any realm mutation (which
//! precise-deletes the `realm-by-name` entry) yields a different hash on the
//! very next request; key rotation/disable bumps the keyset generation on
//! reload (`ServerState.keyset_generation`). A mismatch is a rebuild, never
//! a stale answer.
//!
//! Degradation mirrors the other read-model caches:
//! `[cache] read_cache_ttl_secs = 0` disables the layer; cache errors are a
//! miss + rebuild and skip the write.

use std::sync::Arc;
use std::time::Duration;

use issuerd_cluster::cache_keys;
use issuerd_core::Realm;
use tracing::warn;

use crate::state::ServerState;

const HEADER_LEN: usize = 16; // realm content hash | keyset generation, u64 big-endian each

/// SHA-256 over the serialized realm row, truncated to 8 bytes.
fn realm_hash(realm: &Realm) -> u64 {
    use sha2::Digest;
    let bytes = serde_json::to_vec(realm).unwrap_or_default();
    let digest = sha2::Sha256::digest(&bytes);
    u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]))
}

/// The cached discovery body when its (realm hash, keyset generation)
/// header matches the current values; `None` on miss, staleness, outage, or
/// a disabled cache.
pub async fn read(state: &Arc<ServerState>, realm: &Realm, keyset_gen: u64) -> Option<Vec<u8>> {
    let ttl = state.config.cache.read_cache_ttl_secs;
    if ttl == 0 {
        return None;
    }
    let key = cache_keys::discovery_response(realm.name.as_str());
    let bytes = match state.cache.get(&key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return None,
        Err(e) => {
            warn!(realm = %realm.id, error = %e, "discovery cache read failed");
            return None;
        }
    };
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let stored_hash = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
    let stored_gen = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
    if stored_hash != realm_hash(realm) || stored_gen != keyset_gen {
        return None;
    }
    Some(bytes[HEADER_LEN..].to_vec())
}

/// Store the rendered discovery body. Best-effort: failures are logged and
/// swallowed.
pub async fn write(state: &Arc<ServerState>, realm: &Realm, keyset_gen: u64, body: &[u8]) {
    let ttl = state.config.cache.read_cache_ttl_secs;
    if ttl == 0 {
        return;
    }
    let key = cache_keys::discovery_response(realm.name.as_str());
    let mut bytes = Vec::with_capacity(HEADER_LEN + body.len());
    bytes.extend_from_slice(&realm_hash(realm).to_be_bytes());
    bytes.extend_from_slice(&keyset_gen.to_be_bytes());
    bytes.extend_from_slice(body);
    if let Err(e) = state.cache.set(&key, bytes, Some(Duration::from_secs(ttl))).await {
        warn!(realm = %realm.id, error = %e, "discovery cache write failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{RealmId, RealmName};

    async fn setup() -> (Arc<ServerState>, Realm) {
        let state = Arc::new(
            ServerState::from_config(&crate::config::ServerConfig::default()).await.unwrap(),
        );
        let realm = Realm {
            id: RealmId::new("test").unwrap(),
            name: RealmName::new("test").unwrap(),
            ..Default::default()
        };
        (state, realm)
    }

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let (state, realm) = setup().await;
        write(&state, &realm, 0, b"{\"issuer\":\"x\"}").await;
        let body = read(&state, &realm, 0).await.expect("hit");
        assert_eq!(body, b"{\"issuer\":\"x\"}");
    }

    #[tokio::test]
    async fn realm_change_invalidates() {
        let (state, mut realm) = setup().await;
        write(&state, &realm, 0, b"{}").await;
        assert!(read(&state, &realm, 0).await.is_some());
        realm.display_name = Some(issuerd_core::DisplayName::new("renamed").unwrap());
        assert!(read(&state, &realm, 0).await.is_none(), "changed realm row misses");
    }

    #[tokio::test]
    async fn keyset_generation_bump_invalidates() {
        let (state, realm) = setup().await;
        write(&state, &realm, 0, b"{}").await;
        assert!(read(&state, &realm, 0).await.is_some());
        assert!(read(&state, &realm, 1).await.is_none(), "rotated keyset misses");
    }

    #[tokio::test]
    async fn disabled_cache_never_serves() {
        let mut cfg = crate::config::ServerConfig::default();
        cfg.cache.read_cache_ttl_secs = 0;
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm = Realm {
            id: RealmId::new("test").unwrap(),
            name: RealmName::new("test").unwrap(),
            ..Default::default()
        };
        write(&state, &realm, 0, b"{}").await;
        assert!(read(&state, &realm, 0).await.is_none());
    }
}
