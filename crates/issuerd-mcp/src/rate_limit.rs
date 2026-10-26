// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::sync::Arc;
use std::time::Duration;

use issuerd_core::DistributedCache;
use sha2::{Digest, Sha256};

use crate::{auth::McpAuthContext, error::McpError};

pub const WINDOW_SECS: u64 = 60;

#[derive(Clone)]
pub struct McpRateLimiter {
    cache: Arc<dyn DistributedCache>,
    per_minute: u64,
}

impl McpRateLimiter {
    pub fn new(cache: Arc<dyn DistributedCache>, per_minute: u64) -> Self {
        Self { cache, per_minute }
    }

    pub fn per_minute(&self) -> u64 {
        self.per_minute
    }

    pub async fn acquire(&self, auth: &McpAuthContext, now: u64) -> Result<(), McpError> {
        let window = now / WINDOW_SECS;
        let key = invocation_key(auth, window);
        let count = self
            .cache
            .increment(&key, Some(Duration::from_secs(WINDOW_SECS)))
            .await
            .map_err(|_| McpError::TemporarilyUnavailable("invocation counter"))?;
        if count > self.per_minute {
            return Err(McpError::RateLimited {
                retry_after_secs: WINDOW_SECS - (now % WINDOW_SECS),
            });
        }
        Ok(())
    }
}

fn invocation_key(auth: &McpAuthContext, window: u64) -> String {
    let mut hasher = Sha256::new();
    hash_component(&mut hasher, auth.realm_id.as_ref().as_bytes());
    hash_component(&mut hasher, auth.azp.as_str().as_bytes());
    hash_component(&mut hasher, auth.user_id.as_ref().as_bytes());
    hasher.update(window.to_be_bytes());
    let digest = hasher.finalize();
    let mut key = String::with_capacity(16 + 20 + 64);
    key.push_str("mcp:invocation:v1:");
    key.push_str(&window.to_string());
    key.push(':');
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut key, "{byte:02x}").expect("writing to a string cannot fail");
    }
    key
}

fn hash_component(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_cluster::InMemoryCache;
    use issuerd_core::{
        AccessTokenClaims, Audience, ClientIdentifier, Issuer, JwtId, JwtType, RealmAccess,
        RealmId, RealmName, RoleName, Scope, UserId,
    };

    fn auth_with(realm: &str, azp: &str, user: &str) -> McpAuthContext {
        McpAuthContext {
            realm_id: RealmId::new(realm).unwrap(),
            realm_name: RealmName::new("demo").unwrap(),
            user_id: UserId::new(user).unwrap(),
            azp: ClientIdentifier::new(azp).unwrap(),
            claims: AccessTokenClaims {
                jti: JwtId::new("jti").unwrap(),
                iss: Issuer::new("https://issuer.example/realms/demo").unwrap(),
                sub: UserId::new("subject").unwrap(),
                aud: Audience::new("agent").unwrap(),
                exp: 100,
                iat: 1,
                nbf: 1,
                scope: Scope::parse("mcp:read"),
                typ: JwtType::Bearer,
                azp: Some(azp.into()),
                session_state: None,
                realm_access: Some(RealmAccess {
                    roles: vec![RoleName::new("view-realm").unwrap()],
                }),
                resource_access: None,
                sid: None,
                claims: None,
                cnf: None,
                authorization_details: None,
                resource: None,
            },
        }
    }

    #[tokio::test]
    async fn boundary_window_and_retry_after() {
        let cache = Arc::new(InMemoryCache::new());
        let limiter = McpRateLimiter::new(cache, 2);
        let auth = auth_with("realm", "agent", "user");
        limiter.acquire(&auth, 121).await.unwrap();
        limiter.acquire(&auth, 121).await.unwrap();
        assert_eq!(
            limiter.acquire(&auth, 121).await,
            Err(McpError::RateLimited {
                retry_after_secs: 59
            })
        );
        limiter.acquire(&auth, 180).await.unwrap();
    }

    #[tokio::test]
    async fn separate_limiter_instances_share_the_distributed_counter() {
        let cache: Arc<dyn DistributedCache> = Arc::new(InMemoryCache::new());
        let first = McpRateLimiter::new(Arc::clone(&cache), 2);
        let second = McpRateLimiter::new(cache, 2);
        let auth = auth_with("realm", "agent", "user");
        first.acquire(&auth, 60).await.unwrap();
        second.acquire(&auth, 60).await.unwrap();
        assert!(matches!(first.acquire(&auth, 60).await, Err(McpError::RateLimited { .. })));
    }

    #[tokio::test]
    async fn zero_limit_fails_closed() {
        let limiter = McpRateLimiter::new(Arc::new(InMemoryCache::new()), 0);
        let auth = auth_with("realm", "agent", "user");
        assert_eq!(
            limiter.acquire(&auth, 60).await,
            Err(McpError::RateLimited {
                retry_after_secs: 60
            })
        );
        assert!(matches!(limiter.acquire(&auth, 61).await, Err(McpError::RateLimited { .. })));
    }

    #[tokio::test]
    async fn key_is_length_prefixed_and_principal_scoped() {
        let first = auth_with("a", "bc", "d");
        let second = auth_with("ab", "c", "d");
        assert_ne!(invocation_key(&first, 1), invocation_key(&second, 1));
        assert_ne!(invocation_key(&first, 1), invocation_key(&first, 2));
        assert_ne!(invocation_key(&first, 1), invocation_key(&auth_with("a", "bc", "other"), 1));
    }

    #[derive(Debug)]
    struct FailingCache;

    #[async_trait::async_trait]
    impl DistributedCache for FailingCache {
        async fn get(&self, _: &str) -> Result<Option<Vec<u8>>, issuerd_core::IssuerdError> {
            unimplemented!()
        }
        async fn set(
            &self,
            _: &str,
            _: Vec<u8>,
            _: Option<Duration>,
        ) -> Result<(), issuerd_core::IssuerdError> {
            unimplemented!()
        }
        async fn delete(&self, _: &str) -> Result<(), issuerd_core::IssuerdError> {
            unimplemented!()
        }
        async fn compare_and_swap(
            &self,
            _: &str,
            _: Option<Vec<u8>>,
            _: Vec<u8>,
        ) -> Result<bool, issuerd_core::IssuerdError> {
            unimplemented!()
        }
        async fn increment(
            &self,
            _: &str,
            _: Option<Duration>,
        ) -> Result<u64, issuerd_core::IssuerdError> {
            Err(issuerd_core::IssuerdError::ServerError("cache down".into()))
        }
        async fn publish(&self, _: &str, _: Vec<u8>) -> Result<(), issuerd_core::IssuerdError> {
            unimplemented!()
        }
        async fn subscribe(
            &self,
            _: &str,
            _: Box<dyn Fn(Vec<u8>) + Send + Sync>,
        ) -> Result<(), issuerd_core::IssuerdError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn cache_failure_is_temporary() {
        let limiter = McpRateLimiter::new(Arc::new(FailingCache), 60);
        let error = limiter.acquire(&auth_with("realm", "agent", "user"), 60).await.unwrap_err();
        assert_eq!(error, McpError::TemporarilyUnavailable("invocation counter"));
        assert!(error.is_temporary());
    }
}
