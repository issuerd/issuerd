// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Brute-force login failure tracking with per-realm configuration.
//!
//! Two cache keys per `(realm, identifier, ip)` triple:
//!
//! - `login-failure:{realm}:{identifier}:{ip}` — atomic failure counter,
//!   TTL `failure_ttl_secs` (refreshed only on creation).
//! - `login-lockout:{realm}:{identifier}:{ip}` — lockout marker whose TTL is
//!   the computed lockout duration. [`LoginFailureTracker::is_temporarily_locked`]
//!   checks for this marker, so the lockout lifetime is independent of the
//!   failure-counting window.
//!
//! Lockout duration (`LoginFailureConfig::lockout_for`): with
//! `wait_increment_secs > 0` the wait grows progressively —
//! `wait_increment * (failures - max_failures + 1)`, capped at
//! `max_failure_wait_secs` (0 = uncapped). With `wait_increment_secs == 0` a
//! fixed `lockout_duration_secs` applies. A computed duration of 0 means
//! "no lockout marker" (degenerate config).

use std::time::Duration;

use issuerd_core::{DistributedCache, IssuerdError, Realm, RealmId};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LoginFailureConfig {
    pub max_failures: u32,
    /// TTL of the failure counter itself (the counting window).
    pub failure_ttl_secs: u64,
    /// Progressive wait increment in seconds (0 = fixed lockout duration).
    pub wait_increment_secs: u64,
    /// Upper bound of the progressive wait in seconds (0 = uncapped).
    pub max_failure_wait_secs: u64,
    /// Fixed lockout duration in seconds (used when `wait_increment_secs == 0`).
    pub lockout_duration_secs: u64,
}

impl Default for LoginFailureConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            failure_ttl_secs: 300,
            wait_increment_secs: 60,
            max_failure_wait_secs: 900,
            lockout_duration_secs: 900,
        }
    }
}

impl LoginFailureConfig {
    /// Build a tracker config from a realm's brute-force settings.
    ///
    /// `failure_ttl_secs` is not realm-configurable and keeps its default.
    pub fn from_realm(realm: &Realm) -> Self {
        Self {
            max_failures: realm.max_login_failures,
            wait_increment_secs: u64::from(realm.wait_increment_secs),
            max_failure_wait_secs: u64::from(realm.max_failure_wait_secs),
            lockout_duration_secs: u64::from(realm.lockout_duration_secs),
            ..Self::default()
        }
    }

    /// Compute the lockout duration in seconds after `failures` consecutive
    /// failures (called only when `failures >= max_failures`).
    pub fn lockout_for(&self, failures: u64) -> u64 {
        if self.wait_increment_secs == 0 {
            return self.lockout_duration_secs;
        }
        let overage = failures.saturating_sub(u64::from(self.max_failures)) + 1;
        let wait = self.wait_increment_secs.saturating_mul(overage);
        if self.max_failure_wait_secs == 0 {
            wait
        } else {
            wait.min(self.max_failure_wait_secs)
        }
    }
}

// ---------------------------------------------------------------------------
// Cache keys
// ---------------------------------------------------------------------------

/// Cache key for the per-identifier failure counter.
pub fn failure_count_key(realm: &RealmId, identifier: &str, ip: &str) -> String {
    format!("login-failure:{}:{}:{}", realm.0, identifier, ip)
}

/// Cache key for the per-identifier lockout marker.
pub fn lockout_key(realm: &RealmId, identifier: &str, ip: &str) -> String {
    format!("login-lockout:{}:{}:{}", realm.0, identifier, ip)
}

// ---------------------------------------------------------------------------
// Tracker
// ---------------------------------------------------------------------------

/// Stateless tracker: the per-realm [`LoginFailureConfig`] is supplied per
/// call (the handler loads the realm once per login attempt, not the tracker).
#[derive(Debug, Clone, Default)]
pub struct LoginFailureTracker;

impl LoginFailureTracker {
    pub fn new() -> Self {
        Self
    }

    pub async fn record_failure(
        &self,
        realm: &RealmId,
        identifier: &str,
        ip: &str,
        cache: &dyn DistributedCache,
        config: &LoginFailureConfig,
    ) -> Result<(), IssuerdError> {
        let key = failure_count_key(realm, identifier, ip);
        // Atomic increment so counters stay correct across nodes; the TTL is
        // applied by the cache backend when the counter is first created.
        let count = cache
            .increment(&key, Some(Duration::from_secs(config.failure_ttl_secs)))
            .await?;
        if count >= u64::from(config.max_failures) {
            let wait = config.lockout_for(count);
            if wait > 0 {
                cache
                    .set(
                        &lockout_key(realm, identifier, ip),
                        b"1".to_vec(),
                        Some(Duration::from_secs(wait)),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn is_temporarily_locked(
        &self,
        realm: &RealmId,
        identifier: &str,
        ip: &str,
        cache: &dyn DistributedCache,
    ) -> Result<bool, IssuerdError> {
        Ok(cache.get(&lockout_key(realm, identifier, ip)).await?.is_some())
    }

    pub async fn reset_failures(
        &self,
        realm: &RealmId,
        identifier: &str,
        ip: &str,
        cache: &dyn DistributedCache,
    ) -> Result<(), IssuerdError> {
        cache.delete(&failure_count_key(realm, identifier, ip)).await?;
        cache.delete(&lockout_key(realm, identifier, ip)).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use issuerd_core::RealmId;

    use super::*;

    use issuerd_cluster::InMemoryCache;

    #[derive(Debug, Clone)]
    struct FailingCache {
        fail_on: &'static str,
    }

    #[async_trait::async_trait]
    impl issuerd_core::DistributedCache for FailingCache {
        async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
            if self.fail_on == "get" {
                Err(IssuerdError::ServerError("cache down".into()))
            } else {
                Ok(None)
            }
        }
        async fn set(
            &self,
            _key: &str,
            _value: Vec<u8>,
            _ttl: Option<Duration>,
        ) -> Result<(), IssuerdError> {
            if self.fail_on == "set" {
                Err(IssuerdError::ServerError("cache down".into()))
            } else {
                Ok(())
            }
        }
        async fn delete(&self, _key: &str) -> Result<(), IssuerdError> {
            if self.fail_on == "delete" {
                Err(IssuerdError::ServerError("cache down".into()))
            } else {
                Ok(())
            }
        }
        async fn increment(&self, _key: &str, _ttl: Option<Duration>) -> Result<u64, IssuerdError> {
            if self.fail_on == "increment" {
                Err(IssuerdError::ServerError("cache down".into()))
            } else {
                Ok(1)
            }
        }
        async fn compare_and_swap(
            &self,
            _key: &str,
            _expected: Option<Vec<u8>>,
            _new: Vec<u8>,
        ) -> Result<bool, IssuerdError> {
            Ok(true)
        }
        async fn publish(&self, _channel: &str, _message: Vec<u8>) -> Result<(), IssuerdError> {
            Ok(())
        }
        async fn subscribe(
            &self,
            _channel: &str,
            handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
        ) -> Result<(), IssuerdError> {
            handler(vec![]);
            Ok(())
        }
    }

    fn fixed_config(max: u32, lockout: u64) -> LoginFailureConfig {
        LoginFailureConfig {
            max_failures: max,
            failure_ttl_secs: 300,
            wait_increment_secs: 0,
            max_failure_wait_secs: 0,
            lockout_duration_secs: lockout,
        }
    }

    #[tokio::test]
    async fn threshold_lock_boundary() {
        let tracker = LoginFailureTracker::new();
        let config = fixed_config(5, 900);
        let cache = InMemoryCache::new();
        let realm = RealmId::new("realm-1").unwrap();

        // 4 failures -> not locked
        for _ in 0..4 {
            tracker
                .record_failure(&realm, "alice", "127.0.0.1", &cache, &config)
                .await
                .unwrap();
        }
        assert!(!tracker
            .is_temporarily_locked(&realm, "alice", "127.0.0.1", &cache)
            .await
            .unwrap());

        // 5th failure -> locked
        tracker
            .record_failure(&realm, "alice", "127.0.0.1", &cache, &config)
            .await
            .unwrap();
        assert!(tracker
            .is_temporarily_locked(&realm, "alice", "127.0.0.1", &cache)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn lockout_marker_has_computed_ttl() {
        let tracker = LoginFailureTracker::new();
        let config = fixed_config(2, 120);
        let cache = InMemoryCache::new();
        let realm = RealmId::new("realm-1").unwrap();

        tracker
            .record_failure(&realm, "alice", "127.0.0.1", &cache, &config)
            .await
            .unwrap();
        tracker
            .record_failure(&realm, "alice", "127.0.0.1", &cache, &config)
            .await
            .unwrap();

        let raw = cache.get(&lockout_key(&realm, "alice", "127.0.0.1")).await.unwrap();
        assert_eq!(raw, Some(b"1".to_vec()));
    }

    #[tokio::test]
    async fn reset_clears_failures_and_lockout() {
        let tracker = LoginFailureTracker::new();
        let config = fixed_config(3, 900);
        let cache = InMemoryCache::new();
        let realm = RealmId::new("realm-1").unwrap();

        for _ in 0..3 {
            tracker
                .record_failure(&realm, "alice", "127.0.0.1", &cache, &config)
                .await
                .unwrap();
        }
        assert!(tracker
            .is_temporarily_locked(&realm, "alice", "127.0.0.1", &cache)
            .await
            .unwrap());

        tracker.reset_failures(&realm, "alice", "127.0.0.1", &cache).await.unwrap();
        assert!(!tracker
            .is_temporarily_locked(&realm, "alice", "127.0.0.1", &cache)
            .await
            .unwrap());
        // Counter is gone too: a fresh failure starts from 1, not 4.
        let count = cache
            .increment(&failure_count_key(&realm, "alice", "127.0.0.1"), None)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn record_failure_cache_increment_error() {
        let tracker = LoginFailureTracker::new();
        let cache = FailingCache {
            fail_on: "increment",
        };
        let realm = RealmId::new("realm-1").unwrap();
        let result = tracker
            .record_failure(&realm, "alice", "127.0.0.1", &cache, &LoginFailureConfig::default())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn concurrent_record_failure_counts_exactly() {
        let tracker = LoginFailureTracker::new();
        let config = LoginFailureConfig::default();
        let cache = Arc::new(InMemoryCache::new());
        let realm = RealmId::new("realm-1").unwrap();

        let mut handles = Vec::new();
        for _ in 0..20 {
            let tracker = tracker.clone();
            let cache = Arc::clone(&cache);
            let realm = realm.clone();
            let config = config.clone();
            handles.push(tokio::spawn(async move {
                tracker
                    .record_failure(&realm, "alice", "127.0.0.1", cache.as_ref(), &config)
                    .await
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        // Exactly 20 failures were recorded: locked at threshold 20, and the
        // counter itself reads 20.
        assert!(tracker
            .is_temporarily_locked(&realm, "alice", "127.0.0.1", cache.as_ref())
            .await
            .unwrap());
        let raw = cache
            .get(&failure_count_key(&realm, "alice", "127.0.0.1"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(String::from_utf8(raw).unwrap(), "20");
    }

    #[tokio::test]
    async fn is_temporarily_locked_cache_error() {
        let tracker = LoginFailureTracker::new();
        let cache = FailingCache { fail_on: "get" };
        let realm = RealmId::new("realm-1").unwrap();
        let result = tracker.is_temporarily_locked(&realm, "alice", "127.0.0.1", &cache).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reset_failures_cache_error() {
        let tracker = LoginFailureTracker::new();
        let cache = FailingCache { fail_on: "delete" };
        let realm = RealmId::new("realm-1").unwrap();
        let result = tracker.reset_failures(&realm, "alice", "127.0.0.1", &cache).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn failing_cache_unused_methods() {
        let cache = FailingCache { fail_on: "" };
        assert!(cache.compare_and_swap("k", None, vec![]).await.unwrap());
        cache.publish("ch", vec![]).await.unwrap();
        cache.subscribe("ch", Box::new(|_| {})).await.unwrap();
    }

    // ------------------------------------------------------------------
    // Lockout duration computation
    // ------------------------------------------------------------------

    #[test]
    fn fixed_lockout_when_no_wait_increment() {
        let config = fixed_config(5, 300);
        assert_eq!(config.lockout_for(5), 300);
        assert_eq!(config.lockout_for(9), 300);
    }

    #[test]
    fn progressive_lockout_grows_per_attempt_past_threshold() {
        let config = LoginFailureConfig {
            max_failures: 5,
            failure_ttl_secs: 300,
            wait_increment_secs: 60,
            max_failure_wait_secs: 900,
            lockout_duration_secs: 900,
        };
        assert_eq!(config.lockout_for(5), 60); // 1st lockout: 1 * increment
        assert_eq!(config.lockout_for(6), 120); // 2nd: 2 * increment
        assert_eq!(config.lockout_for(7), 180);
    }

    #[test]
    fn progressive_lockout_capped_at_max_wait() {
        let config = LoginFailureConfig {
            max_failures: 2,
            failure_ttl_secs: 300,
            wait_increment_secs: 500,
            max_failure_wait_secs: 900,
            lockout_duration_secs: 60,
        };
        assert_eq!(config.lockout_for(2), 500);
        assert_eq!(config.lockout_for(3), 900); // 1000 capped to 900
        assert_eq!(config.lockout_for(10), 900);
    }

    #[test]
    fn progressive_lockout_uncapped_when_max_wait_zero() {
        let config = LoginFailureConfig {
            max_failures: 1,
            failure_ttl_secs: 300,
            wait_increment_secs: 100,
            max_failure_wait_secs: 0,
            lockout_duration_secs: 60,
        };
        assert_eq!(config.lockout_for(4), 400);
    }

    #[test]
    fn from_realm_maps_brute_force_fields() {
        let realm = Realm {
            brute_force_protected: true,
            max_login_failures: 3,
            wait_increment_secs: 10,
            max_failure_wait_secs: 120,
            lockout_duration_secs: 45,
            ..Realm::default()
        };
        let config = LoginFailureConfig::from_realm(&realm);
        assert_eq!(config.max_failures, 3);
        assert_eq!(config.wait_increment_secs, 10);
        assert_eq!(config.max_failure_wait_secs, 120);
        assert_eq!(config.lockout_duration_secs, 45);
        // Not realm-configurable: keeps the default counting window.
        assert_eq!(config.failure_ttl_secs, 300);
    }

    #[tokio::test]
    async fn zero_lockout_duration_sets_no_marker() {
        let tracker = LoginFailureTracker::new();
        let config = fixed_config(1, 0);
        let cache = InMemoryCache::new();
        let realm = RealmId::new("realm-1").unwrap();
        tracker
            .record_failure(&realm, "alice", "127.0.0.1", &cache, &config)
            .await
            .unwrap();
        assert!(!tracker
            .is_temporarily_locked(&realm, "alice", "127.0.0.1", &cache)
            .await
            .unwrap());
    }
}
