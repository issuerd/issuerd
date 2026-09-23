// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// In-memory distributed cache for development and single-node deployments.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use dashmap::DashMap;
use issuerd_core::{DistributedCache, IssuerdError};

type Handler = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// In-memory distributed cache for development and single-node deployments.
///
/// Uses `DashMap` for concurrent access and supports TTL via lazy eviction.
pub struct InMemoryCache {
    store: DashMap<String, (Vec<u8>, Option<Instant>)>,
    subscribers: DashMap<String, Vec<Handler>>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self {
            store: DashMap::new(),
            subscribers: DashMap::new(),
        }
    }

    fn is_expired(entry: &(Vec<u8>, Option<Instant>)) -> bool {
        match entry.1 {
            Some(expiry) => Instant::now() >= expiry,
            None => false,
        }
    }
}

/// Match `key` against a glob `pattern` where `*` is the only wildcard and
/// matches zero or more arbitrary bytes. All other bytes match literally
/// (no `?`, no character classes, no escaping). An empty pattern matches
/// only an empty key.
fn glob_match(pattern: &str, key: &str) -> bool {
    let (p, k) = (pattern.as_bytes(), key.as_bytes());
    let (mut pi, mut ki) = (0usize, 0usize);
    // Backtracking state: index of the most recent `*` in the pattern and
    // the key index from which that star's expansion is retried.
    let mut star: Option<(usize, usize)> = None;
    while ki < k.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ki));
            pi += 1;
        } else if pi < p.len() && p[pi] == k[ki] {
            pi += 1;
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

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> Result<bool, IssuerdError> {
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

        let start = Instant::now();
        cache.publish("latency", b"ping".to_vec()).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(received.lock().unwrap().clone(), Some(b"ping".to_vec()));
        assert!(
            elapsed < Duration::from_millis(1),
            "in-memory pub/sub should be sub-millisecond, got {:?}",
            elapsed
        );
    }
}
