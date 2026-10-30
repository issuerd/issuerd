// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// In-memory distributed cache for development and single-node deployments.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use issuerd_core::{DistributedCache, IssuerdError};

type Handler = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// Minimum time between two sweeps of expired entries.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// In-memory distributed cache for development and single-node deployments.
///
/// Uses `DashMap` for concurrent access and supports TTL via lazy eviction.
/// Writes also sweep out all expired entries at most once per
/// [`SWEEP_INTERVAL`], so keys that are written once and never read again
/// (abandoned login flows, replay markers) do not stay in memory forever.
pub struct InMemoryCache {
    store: DashMap<String, (Vec<u8>, Option<Instant>)>,
    subscribers: DashMap<String, Vec<Handler>>,
    created: Instant,
    /// Milliseconds after `created` at which the last sweep started.
    last_sweep_ms: AtomicU64,
    sweep_interval: Duration,
    multi_key_lock: tokio::sync::Mutex<()>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self::with_sweep_interval(SWEEP_INTERVAL)
    }

    fn with_sweep_interval(sweep_interval: Duration) -> Self {
        Self {
            store: DashMap::new(),
            subscribers: DashMap::new(),
            created: Instant::now(),
            last_sweep_ms: AtomicU64::new(0),
            sweep_interval,
            multi_key_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Removes every expired entry once `sweep_interval` has passed since the
    /// last sweep; only the caller that claims the slot pays for the pass.
    /// Expired entries are already invisible to every operation, so this
    /// only reclaims memory. Must not be called while holding a guard into
    /// `store` (the sweep write-locks every shard).
    fn maybe_sweep_expired(&self) {
        let now = u64::try_from(self.created.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        let interval = u64::try_from(self.sweep_interval.as_millis()).unwrap_or(u64::MAX);
        if now.saturating_sub(last) < interval {
            return;
        }
        if self
            .last_sweep_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.store.retain(|_, entry| !Self::is_expired(entry));
    }

    fn is_expired(entry: &(Vec<u8>, Option<Instant>)) -> bool {
        match entry.1 {
            Some(expiry) => Instant::now() >= expiry,
            None => false,
        }
    }
}

/// Match `key` against a glob `pattern` where `*` is the only wildcard and
/// matches zero or more arbitrary bytes. `\` makes the next pattern byte
/// literal (Redis-compatible, see `issuerd_core::escape_scan_pattern`); a
/// trailing lone `\` matches itself. All other bytes match literally (no
/// `?`, no character classes). An empty pattern matches only an empty key.
fn glob_match(pattern: &str, key: &str) -> bool {
    let (p, k) = (pattern.as_bytes(), key.as_bytes());
    let (mut pi, mut ki) = (0usize, 0usize);
    // Backtracking state: index of the most recent `*` in the pattern and
    // the key index from which that star's expansion is retried.
    let mut star: Option<(usize, usize)> = None;
    while ki < k.len() {
        // Pattern width of the literal at `pi` when it matches `k[ki]`.
        let literal_width = match p.get(pi) {
            Some(b'\\') if pi + 1 < p.len() => (p[pi + 1] == k[ki]).then_some(2),
            Some(b'*') | None => None,
            Some(&b) => (b == k[ki]).then_some(1),
        };
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ki));
            pi += 1;
        } else if let Some(width) = literal_width {
            pi += width;
            ki += 1;
        } else if let Some((star_pi, star_ki)) = star {
            // Mismatch: let the last `*` absorb one more byte and retry.
            pi = star_pi + 1;
            ki = star_ki + 1;
            star = Some((star_pi, ki));
        } else {
            return false;
        }
    }
    // Trailing `*`s in the pattern match the empty remainder of the key.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DistributedCache for InMemoryCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
        if let Some(entry) = self.store.get(key) {
            if Self::is_expired(&entry) {
                drop(entry);
                self.store.remove(key);
                return Ok(None);
            }
            return Ok(Some(entry.0.clone()));
        }
        Ok(None)
    }

    async fn set(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Option<std::time::Duration>,
    ) -> Result<(), IssuerdError> {
        self.maybe_sweep_expired();
        let expiry = ttl.map(|d| Instant::now() + d);
        self.store.insert(key.to_string(), (value, expiry));
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), IssuerdError> {
        self.store.remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
        let removed = self.store.remove(key);
        if let Some((_, entry)) = &removed {
            if Self::is_expired(entry) {
                return Ok(None);
            }
        }
        Ok(removed.map(|(_, entry)| entry.0))
    }

    async fn compare_and_delete(&self, key: &str, expected: Vec<u8>) -> Result<bool, IssuerdError> {
        self.maybe_sweep_expired();
        match self.store.entry(key.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                if Self::is_expired(occupied.get()) {
                    occupied.remove();
                    return Ok(false);
                }
                if occupied.get().0.as_slice() == expected.as_slice() {
                    occupied.remove();
                    return Ok(true);
                }
                Ok(false)
            }
            dashmap::mapref::entry::Entry::Vacant(_) => Ok(false),
        }
    }

    async fn claim_and_create(
        &self,
        claim_key: &str,
        expected: Vec<u8>,
        create_key: &str,
        create_value: Vec<u8>,
        create_ttl: Option<std::time::Duration>,
    ) -> Result<bool, IssuerdError> {
        let _guard = self.multi_key_lock.lock().await;
        self.maybe_sweep_expired();
        let matches = self
            .store
            .get(claim_key)
            .is_some_and(|entry| !Self::is_expired(&entry) && entry.0.as_slice() == expected);
        if !matches {
            return Ok(false);
        }
        self.store.remove(claim_key);
        let expiry = create_ttl.map(|duration| Instant::now() + duration);
        self.store.insert(create_key.to_string(), (create_value, expiry));
        Ok(true)
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> Result<bool, IssuerdError> {
        self.maybe_sweep_expired();
        match self.store.entry(key.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                if Self::is_expired(occupied.get()) {
                    occupied.remove();
                    // Key was expired, so if expected is None, we can insert
                    if expected.is_none() {
                        self.store.insert(key.to_string(), (new, None));
                        return Ok(true);
                    }
                    return Ok(false);
                }
                let current = occupied.get().0.clone();
                match expected {
                    Some(expected_value) if current == expected_value => {
                        occupied.insert((new, None));
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                if expected.is_none() {
                    vacant.insert((new, None));
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    async fn increment(
        &self,
        key: &str,
        ttl: Option<std::time::Duration>,
    ) -> Result<u64, IssuerdError> {
        self.maybe_sweep_expired();
        match self.store.entry(key.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                if Self::is_expired(occupied.get()) {
                    // Expired entries are recreated with the counter reset to 1.
                    let expiry = ttl.map(|d| Instant::now() + d);
                    occupied.insert((b"1".to_vec(), expiry));
                    return Ok(1);
                }
                let current = std::str::from_utf8(&occupied.get().0)
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let new_value = current + 1;
                // Keep the existing expiry instant: the TTL is only applied
                // when the counter is first created.
                let expiry = occupied.get().1;
                occupied.insert((new_value.to_string().into_bytes(), expiry));
                Ok(new_value)
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                let expiry = ttl.map(|d| Instant::now() + d);
                vacant.insert((b"1".to_vec(), expiry));
                Ok(1)
            }
        }
    }

    async fn publish(&self, channel: &str, message: Vec<u8>) -> Result<(), IssuerdError> {
        if let Some(handlers) = self.subscribers.get(channel) {
            for handler in handlers.iter() {
                handler(message.clone());
            }
        }
        Ok(())
    }

    async fn subscribe(
        &self,
        channel: &str,
        handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
    ) -> Result<(), IssuerdError> {
        let handler: Handler = Arc::from(handler);
        self.subscribers
            .entry(channel.to_string())
            .and_modify(|v| v.push(Arc::clone(&handler)))
            .or_insert_with(|| vec![handler]);
        Ok(())
    }

    async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>, IssuerdError> {
        let keys = self
            .store
            .iter()
            .filter(|entry| !Self::is_expired(entry.value()) && glob_match(pattern, entry.key()))
            .map(|entry| entry.key().clone())
            .collect();
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn get_set_delete_roundtrip() {
        let cache = InMemoryCache::new();
        assert_eq!(cache.get("key1").await.unwrap(), None);

        cache.set("key1", b"value1".to_vec(), None).await.unwrap();
        assert_eq!(cache.get("key1").await.unwrap(), Some(b"value1".to_vec()));

        cache.delete("key1").await.unwrap();
        assert_eq!(cache.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn ttl_expiration() {
        let cache = InMemoryCache::new();
        cache
            .set("key1", b"value1".to_vec(), Some(Duration::from_millis(50)))
            .await
            .unwrap();
        assert_eq!(cache.get("key1").await.unwrap(), Some(b"value1".to_vec()));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cache.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn cas_key_absent() {
        let cache = InMemoryCache::new();
        let result = cache.compare_and_swap("key1", None, b"value1".to_vec()).await.unwrap();
        assert!(result);
        assert_eq!(cache.get("key1").await.unwrap(), Some(b"value1".to_vec()));

        // Second CAS with expected None should fail
        let result2 = cache.compare_and_swap("key1", None, b"value2".to_vec()).await.unwrap();
        assert!(!result2);
    }

    #[tokio::test]
    async fn cas_key_present() {
        let cache = InMemoryCache::new();
        cache.set("key1", b"old".to_vec(), None).await.unwrap();

        // Wrong expected
        let result = cache
            .compare_and_swap("key1", Some(b"wrong".to_vec()), b"new".to_vec())
            .await
            .unwrap();
        assert!(!result);

        // Correct expected
        let result2 = cache
            .compare_and_swap("key1", Some(b"old".to_vec()), b"new".to_vec())
            .await
            .unwrap();
        assert!(result2);
        assert_eq!(cache.get("key1").await.unwrap(), Some(b"new".to_vec()));
    }

    #[tokio::test]
    async fn pub_sub_single_handler() {
        let cache = InMemoryCache::new();
        let received = Arc::new(std::sync::Mutex::new(None));
        let received_clone = Arc::clone(&received);

        cache
            .subscribe(
                "chan1",
                Box::new(move |msg| {
                    *received_clone.lock().unwrap() = Some(msg);
                }),
            )
            .await
            .unwrap();

        cache.publish("chan1", b"hello".to_vec()).await.unwrap();

        assert_eq!(received.lock().unwrap().clone(), Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn pub_sub_multiple_handlers() {
        let cache = InMemoryCache::new();
        let count1 = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::new(AtomicUsize::new(0));
        let c1 = Arc::clone(&count1);
        let c2 = Arc::clone(&count2);

        cache
            .subscribe(
                "chan1",
                Box::new(move |_msg| {
                    c1.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .await
            .unwrap();
        cache
            .subscribe(
                "chan1",
                Box::new(move |_msg| {
                    c2.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .await
            .unwrap();

        cache.publish("chan1", b"hello".to_vec()).await.unwrap();

        assert_eq!(count1.load(Ordering::SeqCst), 1);
        assert_eq!(count2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pub_to_channel_with_no_subscribers() {
        let cache = InMemoryCache::new();
        // Should not panic and return Ok
        cache.publish("empty_chan", b"msg".to_vec()).await.unwrap();
    }

    #[tokio::test]
    async fn cas_contention_two_concurrent_none() {
        let cache = Arc::new(InMemoryCache::new());
        let cache1 = Arc::clone(&cache);
        let cache2 = Arc::clone(&cache);

        let handle1 = tokio::spawn(async move {
            cache1.compare_and_swap("contend", None, b"v1".to_vec()).await.unwrap()
        });
        let handle2 = tokio::spawn(async move {
            cache2.compare_and_swap("contend", None, b"v2".to_vec()).await.unwrap()
        });

        let (r1, r2) = tokio::join!(handle1, handle2);
        let results = [r1.unwrap(), r2.unwrap()];
        assert_eq!(results.iter().filter(|&&x| x).count(), 1, "exactly one CAS should succeed");
        assert_eq!(results.iter().filter(|&&x| !x).count(), 1, "exactly one CAS should fail");
    }

    #[tokio::test]
    async fn cas_contention_with_expected_value() {
        let cache = Arc::new(InMemoryCache::new());
        cache.set("contend2", b"old".to_vec(), None).await.unwrap();

        let cache1 = Arc::clone(&cache);
        let cache2 = Arc::clone(&cache);

        let handle1 = tokio::spawn(async move {
            cache1
                .compare_and_swap("contend2", Some(b"old".to_vec()), b"v1".to_vec())
                .await
                .unwrap()
        });
        let handle2 = tokio::spawn(async move {
            cache2
                .compare_and_swap("contend2", Some(b"old".to_vec()), b"v2".to_vec())
                .await
                .unwrap()
        });

        let (r1, r2) = tokio::join!(handle1, handle2);
        let results = [r1.unwrap(), r2.unwrap()];
        assert_eq!(results.iter().filter(|&&x| x).count(), 1, "exactly one CAS should succeed");
        assert_eq!(results.iter().filter(|&&x| !x).count(), 1, "exactly one CAS should fail");
    }

    #[tokio::test]
    async fn increment_fresh_key_starts_at_one_with_ttl() {
        let cache = InMemoryCache::new();
        let value = cache.increment("counter", Some(Duration::from_millis(50))).await.unwrap();
        assert_eq!(value, 1);
        assert_eq!(cache.get("counter").await.unwrap(), Some(b"1".to_vec()));

        // The TTL passed on the first increment is applied to the new key.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cache.get("counter").await.unwrap(), None);
    }

    #[tokio::test]
    async fn increment_existing_key_does_not_extend_ttl() {
        let cache = InMemoryCache::new();
        let value = cache.increment("counter", Some(Duration::from_millis(300))).await.unwrap();
        assert_eq!(value, 1);

        tokio::time::sleep(Duration::from_millis(100)).await;
        let value = cache.increment("counter", Some(Duration::from_millis(300))).await.unwrap();
        assert_eq!(value, 2);
        assert_eq!(cache.get("counter").await.unwrap(), Some(b"2".to_vec()));

        // At ~350ms after creation the key is gone: the second increment did
        // not extend the original 300ms TTL (which would expire at ~400ms).
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(cache.get("counter").await.unwrap(), None);
    }

    #[tokio::test]
    async fn increment_is_atomic_under_concurrency() {
        let cache = Arc::new(InMemoryCache::new());

        let mut handles = Vec::new();
        for _ in 0..100 {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache.increment("counter", None).await.unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        let stored = cache.get("counter").await.unwrap().unwrap();
        let count: u64 = String::from_utf8(stored).unwrap().parse().unwrap();
        assert_eq!(count, 100);
    }

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("foo", "foo"));
        assert!(!glob_match("foo", "fooo"));
        assert!(!glob_match("foo", "fo"));
        assert!(!glob_match("foo", "bar"));
    }

    #[test]
    fn glob_prefix_star() {
        assert!(glob_match("foo*", "foo"));
        assert!(glob_match("foo*", "foobar"));
        assert!(glob_match("foo*", "foo:bar:baz"));
        assert!(!glob_match("foo*", "fobar"));
        assert!(!glob_match("foo*", "afoo"));
    }

    #[test]
    fn glob_suffix_star() {
        assert!(glob_match("*bar", "bar"));
        assert!(glob_match("*bar", "foobar"));
        assert!(glob_match("*bar", "a:b:bar"));
        assert!(!glob_match("*bar", "bars"));
        assert!(!glob_match("*bar", "bara"));
    }

    #[test]
    fn glob_contains_star() {
        assert!(glob_match("*mid*", "mid"));
        assert!(glob_match("*mid*", "a-mid-b"));
        assert!(glob_match("*mid*", "amid"));
        assert!(glob_match("*mid*", "midb"));
        assert!(!glob_match("*mid*", "mdi"));
    }

    #[test]
    fn glob_multiple_stars() {
        assert!(glob_match("a*b*c", "abc"));
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(glob_match("a*b*c", "abbc"));
        assert!(glob_match("a*b*c", "a-bb-cc"));
        assert!(!glob_match("a*b*c", "a-b-c-extra"));
        assert!(!glob_match("a*b*c", "acb"));
        assert!(!glob_match("a*b*c", "abcb"));
        assert!(!glob_match("a*b*c", "xbc"));
    }

    #[test]
    fn glob_only_star_matches_everything() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything at all"));
        assert!(glob_match("**", "anything at all"));
    }

    #[test]
    fn glob_empty_pattern() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
        assert!(!glob_match("a", ""));
    }

    #[test]
    fn glob_star_only_wildcard() {
        // `?` and character classes are literal bytes, not wildcards.
        assert!(!glob_match("fo?", "foo"));
        assert!(glob_match("fo?", "fo?"));
        assert!(!glob_match("[ab]", "a"));
        assert!(glob_match("[ab]", "[ab]"));
    }

    #[test]
    fn glob_backslash_escapes_next_byte() {
        assert!(glob_match("a\\*", "a*"));
        assert!(!glob_match("a\\*", "ab"));
        assert!(glob_match("a\\\\b", "a\\b"));
        assert!(!glob_match("a\\\\b", "a\\\\b"));
        assert!(glob_match("\\a", "a"));
        // A trailing lone backslash is literal (Redis parity).
        assert!(glob_match("a\\", "a\\"));
        // Escaped star inside a wildcard pattern still needs a literal `*`.
        assert!(glob_match("x:\\*:*", "x:*:1.2.3.4"));
        assert!(!glob_match("x:\\*:*", "x:alice:1.2.3.4"));
        assert!(!glob_match("x:\\*", "x:"));
    }

    #[tokio::test]
    async fn scan_keys_escaped_literal_does_not_wildcard() {
        let cache = InMemoryCache::new();
        cache.set("login-failure:r1:*:1.1.1.1", b"1".to_vec(), None).await.unwrap();
        cache.set("login-failure:r1:alice:1.1.1.1", b"1".to_vec(), None).await.unwrap();
        cache.set("login-failure:r1:a\\b:otp", b"1".to_vec(), None).await.unwrap();

        let star = issuerd_core::escape_scan_pattern("login-failure:r1:*:");
        assert_eq!(
            cache.scan_keys(&format!("{star}*")).await.unwrap(),
            vec!["login-failure:r1:*:1.1.1.1"]
        );
        let backslash = issuerd_core::escape_scan_pattern("login-failure:r1:a\\b:");
        assert_eq!(
            cache.scan_keys(&format!("{backslash}*")).await.unwrap(),
            vec!["login-failure:r1:a\\b:otp"]
        );
    }

    fn sorted(mut keys: Vec<String>) -> Vec<String> {
        keys.sort();
        keys
    }

    #[tokio::test]
    async fn scan_keys_matches_glob_patterns() {
        let cache = InMemoryCache::new();
        cache.set("login-failure:realm-1:alice", b"1".to_vec(), None).await.unwrap();
        cache.set("login-failure:realm-1:bob", b"2".to_vec(), None).await.unwrap();
        cache
            .set("login-failure:realm-2:carol", b"1".to_vec(), Some(Duration::from_secs(60)))
            .await
            .unwrap();
        cache
            .set("login-lockout:realm-1:alice", b"x".to_vec(), Some(Duration::from_secs(60)))
            .await
            .unwrap();
        cache.set("session:realm-1:xyz", b"s".to_vec(), None).await.unwrap();

        assert_eq!(
            sorted(cache.scan_keys("login-failure:realm-1:*").await.unwrap()),
            vec!["login-failure:realm-1:alice", "login-failure:realm-1:bob"]
        );
        assert_eq!(
            sorted(cache.scan_keys("login-*").await.unwrap()),
            vec![
                "login-failure:realm-1:alice",
                "login-failure:realm-1:bob",
                "login-failure:realm-2:carol",
                "login-lockout:realm-1:alice",
            ]
        );
        assert_eq!(
            sorted(cache.scan_keys("*:realm-1:*").await.unwrap()),
            vec![
                "login-failure:realm-1:alice",
                "login-failure:realm-1:bob",
                "login-lockout:realm-1:alice",
                "session:realm-1:xyz",
            ]
        );
        // Exact match without wildcard.
        assert_eq!(
            cache.scan_keys("session:realm-1:xyz").await.unwrap(),
            vec!["session:realm-1:xyz"]
        );
        // No match.
        assert!(cache.scan_keys("login-failure:realm-3:*").await.unwrap().is_empty());
        assert!(cache.scan_keys("").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn scan_keys_excludes_expired_entries() {
        let cache = InMemoryCache::new();
        cache
            .set("login-failure:realm-1:alice", b"1".to_vec(), Some(Duration::from_millis(50)))
            .await
            .unwrap();
        cache.set("login-failure:realm-1:bob", b"1".to_vec(), None).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            cache.scan_keys("login-failure:realm-1:*").await.unwrap(),
            vec!["login-failure:realm-1:bob"]
        );
    }

    #[tokio::test]
    async fn pub_sub_latency_is_near_zero() {
        let cache = InMemoryCache::new();
        let received = Arc::new(std::sync::Mutex::new(None));
        let received_clone = Arc::clone(&received);

        cache
            .subscribe(
                "latency",
                Box::new(move |msg| {
                    *received_clone.lock().unwrap() = Some(msg);
                }),
            )
            .await
            .unwrap();

        // Single wall-clock samples are at the mercy of CI runner scheduling;
        // assert on the best of many after a warm-up publish.
        cache.publish("latency", b"warmup".to_vec()).await.unwrap();
        let mut elapsed = Duration::from_secs(1);
        for _ in 0..100 {
            let start = Instant::now();
            cache.publish("latency", b"ping".to_vec()).await.unwrap();
            elapsed = elapsed.min(start.elapsed());
        }

        assert_eq!(received.lock().unwrap().clone(), Some(b"ping".to_vec()));
        assert!(
            elapsed < Duration::from_millis(1),
            "in-memory pub/sub should be sub-millisecond, got {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn increment_after_expiry_recreates_a_live_key() {
        let cache = InMemoryCache::new();
        assert_eq!(cache.increment("counter", Some(Duration::from_millis(50))).await.unwrap(), 1);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The counter expired: recreation resets it to 1 under the new TTL.
        assert_eq!(cache.increment("counter", Some(Duration::from_millis(300))).await.unwrap(), 1);
        // The recreated key must be live immediately (its expiry is in the future).
        assert_eq!(cache.get("counter").await.unwrap(), Some(b"1".to_vec()));
    }

    #[tokio::test]
    async fn get_and_delete_returns_value_once() {
        let cache = InMemoryCache::new();
        cache.set("k", b"v".to_vec(), None).await.unwrap();

        assert_eq!(cache.get_and_delete("k").await.unwrap(), Some(b"v".to_vec()));
        // Consumed: the key is gone.
        assert_eq!(cache.get_and_delete("k").await.unwrap(), None);
        assert_eq!(cache.get("k").await.unwrap(), None);

        // Absent key: None.
        assert_eq!(cache.get_and_delete("absent").await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_and_delete_expired_entry_yields_none() {
        let cache = InMemoryCache::new();
        cache.set("k", b"v".to_vec(), Some(Duration::from_millis(50))).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(cache.get_and_delete("k").await.unwrap(), None);
    }

    #[tokio::test]
    async fn write_sweeps_expired_keys_that_are_never_read_again() {
        let cache = InMemoryCache::with_sweep_interval(Duration::ZERO);
        for i in 0..100 {
            let key = format!("pending_auth:realm-1:{i}");
            cache
                .set(&key, b"flow".to_vec(), Some(Duration::from_millis(50)))
                .await
                .unwrap();
        }
        cache.set("persistent", b"p".to_vec(), None).await.unwrap();
        cache.set("live", b"l".to_vec(), Some(Duration::from_secs(60))).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        cache.set("trigger", b"t".to_vec(), None).await.unwrap();

        assert_eq!(cache.store.len(), 3, "expired entries must be freed without being read");
        assert_eq!(cache.get("persistent").await.unwrap(), Some(b"p".to_vec()));
        assert_eq!(cache.get("live").await.unwrap(), Some(b"l".to_vec()));
        assert_eq!(cache.get("trigger").await.unwrap(), Some(b"t".to_vec()));
    }

    #[tokio::test]
    async fn increment_and_cas_also_sweep_expired_keys() {
        let cache = InMemoryCache::with_sweep_interval(Duration::ZERO);
        cache
            .set("old-a", b"a".to_vec(), Some(Duration::from_millis(50)))
            .await
            .unwrap();
        cache
            .set("old-b", b"b".to_vec(), Some(Duration::from_millis(50)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cache.increment("counter", None).await.unwrap(), 1);
        assert_eq!(cache.store.len(), 1);

        cache.store.insert("old-c".to_string(), (b"c".to_vec(), Some(Instant::now())));
        assert!(cache.compare_and_swap("cas", None, b"v".to_vec()).await.unwrap());
        assert_eq!(
            sorted(cache.store.iter().map(|e| e.key().clone()).collect()),
            ["cas", "counter"]
        );
    }

    #[tokio::test]
    async fn sweep_waits_for_the_interval() {
        let mut cache = InMemoryCache::with_sweep_interval(Duration::from_secs(3600));
        cache.set("old", b"v".to_vec(), Some(Duration::from_millis(50))).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Interval not yet elapsed: the write does not pay for a sweep.
        cache.set("a", b"v".to_vec(), None).await.unwrap();
        assert_eq!(cache.store.len(), 2);

        cache.sweep_interval = Duration::ZERO;
        cache.set("b", b"v".to_vec(), None).await.unwrap();
        assert_eq!(sorted(cache.store.iter().map(|e| e.key().clone()).collect()), ["a", "b"]);
    }

    #[tokio::test]
    async fn claim_and_create_is_exact_single_use_and_applies_expiry() {
        let cache = InMemoryCache::new();
        cache
            .set("operation", b"pending".to_vec(), Some(Duration::from_secs(60)))
            .await
            .unwrap();
        assert!(!cache
            .claim_and_create("operation", b"wrong".to_vec(), "request", b"value".to_vec(), None,)
            .await
            .unwrap());
        assert_eq!(cache.get("operation").await.unwrap(), Some(b"pending".to_vec()));
        assert_eq!(cache.get("request").await.unwrap(), None);

        assert!(cache
            .claim_and_create(
                "operation",
                b"pending".to_vec(),
                "request",
                b"value".to_vec(),
                Some(Duration::from_millis(25)),
            )
            .await
            .unwrap());
        assert_eq!(cache.get("operation").await.unwrap(), None);
        assert_eq!(cache.get("request").await.unwrap(), Some(b"value".to_vec()));
        assert!(!cache
            .claim_and_create("operation", b"pending".to_vec(), "other", b"value".to_vec(), None,)
            .await
            .unwrap());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(cache.get("request").await.unwrap(), None);
    }

    #[test]
    fn default_cache_constructs_outside_a_runtime() {
        let cache = InMemoryCache::default();
        assert_eq!(cache.sweep_interval, SWEEP_INTERVAL);
        assert!(cache.store.is_empty());
    }
}
