// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Best-effort invalidation primitives for the claims read-model caches.

//! Synchronous invalidation for the claims read-model cache.
//!
//! Writers call these right after the storage mutation commits; failures
//! are logged and swallowed (best-effort) because the entry TTL is the
//! documented fail-safe bound on staleness. Three granularities:
//!
//! - precise deletes: [`invalidate_user_claims`] (one user's bundle),
//!   [`invalidate_client_claims`] (one client's three keys);
//! - per-entity generation counters (`usergen:` / `clientgen:`) bumped by
//!   the same functions — the rendered userinfo response cache embeds them
//!   in its entries, so content changes take effect on the next request
//!   without knowing every derived response key;
//! - realm-wide epoch bump: [`bump_claims_epoch`] — every cached claims
//!   entry of the realm carries the epoch it was written at and misses on
//!   its next read once the counter moves. Used for definition changes
//!   that fan out to many cached entries (role/scope/mapper/group CRUD,
//!   composites, bulk imports, federation sync runs).

use issuerd_core::{ClientId, DistributedCache, RealmId, UserId};

use crate::cache_keys;

/// Delete one cache key, logging (never propagating) failures.
pub async fn delete_best_effort(cache: &dyn DistributedCache, realm: &RealmId, key: &str) {
    if let Err(e) = cache.delete(key).await {
        tracing::warn!(realm = %realm, error = %e, "claims cache invalidation failed");
    }
}

/// Drop one user's claims bundle (`user-claims:{realm}:{user_id}`) and bump
/// the user's claims-content generation (`usergen:{realm}:{user_id}`):
/// user update/delete, per-user role-mapping or group-membership changes.
/// The generation counter invalidates the rendered userinfo response cache
/// (its entries embed the generation); the bump precedes the delete so the
/// response layer never outlives the read-model entry.
pub async fn invalidate_user_claims(
    cache: &dyn DistributedCache,
    realm_id: &RealmId,
    user_id: &UserId,
) {
    if let Err(e) = cache
        .increment(&cache_keys::user_claims_generation(realm_id.as_ref(), user_id.as_ref()), None)
        .await
    {
        tracing::warn!(realm = %realm_id, error = %e, "user claims generation bump failed");
    }
    delete_best_effort(
        cache,
        realm_id,
        &cache_keys::user_claims(realm_id.as_ref(), user_id.as_ref()),
    )
    .await;
}

/// Drop every cache entry derived from one client: the client bundle
/// (`client:{realm}:{client_id}`), its default-scope assignments
/// (`client-scopes:{realm}:{uuid}`), and the uuid→identifier reverse map
/// (`client-uuid:{realm}:{uuid}`), plus a bump of the client's
/// claims-content generation (`clientgen:{realm}:{client_id}`) for the
/// rendered userinfo response cache. Client update/delete, client-local
/// mapper CRUD, scope-assignment changes.
pub async fn invalidate_client_claims(
    cache: &dyn DistributedCache,
    realm_id: &RealmId,
    client_uuid: &ClientId,
    client_identifier: &str,
) {
    if let Err(e) = cache
        .increment(
            &cache_keys::client_claims_generation(realm_id.as_ref(), client_identifier),
            None,
        )
        .await
    {
        tracing::warn!(realm = %realm_id, error = %e, "client claims generation bump failed");
    }
    delete_best_effort(cache, realm_id, &cache_keys::client(realm_id.as_ref(), client_identifier))
        .await;
    delete_best_effort(
        cache,
        realm_id,
        &cache_keys::client_scopes(realm_id.as_ref(), client_uuid.as_ref()),
    )
    .await;
    delete_best_effort(
        cache,
        realm_id,
        &cache_keys::client_uuid(realm_id.as_ref(), client_uuid.as_ref()),
    )
    .await;
}

/// Bump the realm's claims epoch (`claimsepoch:{realm}`). No TTL: the
/// counter must outlive every cached entry it invalidates.
pub async fn bump_claims_epoch(cache: &dyn DistributedCache, realm_id: &RealmId) {
    if let Err(e) = cache.increment(&cache_keys::claims_epoch(realm_id.as_ref()), None).await {
        tracing::warn!(realm = %realm_id, error = %e, "claims epoch bump failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryCache;
    use std::sync::Arc;

    fn ids() -> (RealmId, UserId, ClientId) {
        (
            RealmId::new("realm-1").unwrap(),
            UserId::new("user-1").unwrap(),
            ClientId::new("client-uuid-1").unwrap(),
        )
    }

    #[tokio::test]
    async fn invalidate_user_claims_deletes_only_that_key() {
        let cache = InMemoryCache::new();
        let (realm, user, _) = ids();
        cache
            .set(&cache_keys::user_claims("realm-1", "user-1"), b"x".to_vec(), None)
            .await
            .unwrap();
        cache
            .set(&cache_keys::user_claims("realm-1", "user-2"), b"x".to_vec(), None)
            .await
            .unwrap();

        invalidate_user_claims(&cache, &realm, &user).await;

        assert!(cache
            .get(&cache_keys::user_claims("realm-1", "user-1"))
            .await
            .unwrap()
            .is_none());
        assert!(cache
            .get(&cache_keys::user_claims("realm-1", "user-2"))
            .await
            .unwrap()
            .is_some());
        // The per-user generation counter is bumped for the rendered
        // response cache (starts at 1 on a fresh key).
        let gen = cache
            .get(&cache_keys::user_claims_generation("realm-1", "user-1"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&gen).unwrap(), "1");
        assert!(cache
            .get(&cache_keys::user_claims_generation("realm-1", "user-2"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn invalidate_client_claims_deletes_all_three_keys() {
        let cache = InMemoryCache::new();
        let (realm, _, uuid) = ids();
        for key in [
            cache_keys::client("realm-1", "my-app"),
            cache_keys::client_scopes("realm-1", "client-uuid-1"),
            cache_keys::client_uuid("realm-1", "client-uuid-1"),
        ] {
            cache.set(&key, b"x".to_vec(), None).await.unwrap();
        }

        invalidate_client_claims(&cache, &realm, &uuid, "my-app").await;

        assert!(cache.get(&cache_keys::client("realm-1", "my-app")).await.unwrap().is_none());
        assert!(cache
            .get(&cache_keys::client_scopes("realm-1", "client-uuid-1"))
            .await
            .unwrap()
            .is_none());
        assert!(cache
            .get(&cache_keys::client_uuid("realm-1", "client-uuid-1"))
            .await
            .unwrap()
            .is_none());
        // Per-client generation counter bumped for the response cache.
        let gen = cache
            .get(&cache_keys::client_claims_generation("realm-1", "my-app"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&gen).unwrap(), "1");
    }

    #[tokio::test]
    async fn bump_claims_epoch_increments_counter() {
        let cache = InMemoryCache::new();
        let (realm, ..) = ids();
        bump_claims_epoch(&cache, &realm).await;
        bump_claims_epoch(&cache, &realm).await;
        let v = cache.get(&cache_keys::claims_epoch("realm-1")).await.unwrap().unwrap();
        assert_eq!(std::str::from_utf8(&v).unwrap(), "2");
    }

    #[tokio::test]
    async fn cache_outage_is_swallowed() {
        #[derive(Debug)]
        struct DeadCache;
        #[async_trait::async_trait]
        impl DistributedCache for DeadCache {
            async fn get(&self, _: &str) -> Result<Option<Vec<u8>>, issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("down".into()))
            }
            async fn set(
                &self,
                _: &str,
                _: Vec<u8>,
                _: Option<std::time::Duration>,
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
        let (realm, user, uuid) = ids();
        let cache = DeadCache;
        // Must not panic or propagate.
        invalidate_user_claims(&cache, &realm, &user).await;
        invalidate_client_claims(&cache, &realm, &uuid, "my-app").await;
        bump_claims_epoch(&cache, &realm).await;
        let _ = Arc::new(cache);
    }
}
