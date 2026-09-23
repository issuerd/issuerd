// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Redis-backed distributed cache supporting single-node and cluster modes.

use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use issuerd_core::{DistributedCache, IssuerdError};
use tracing::{error, info, instrument, warn};

enum RedisConn {
    Single(redis::aio::MultiplexedConnection),
    Cluster(redis::cluster_async::ClusterConnection),
}

/// Strip credentials from a Redis URL for logs and error messages:
/// `redis://user:secret@host:6379/0` becomes `redis://***@host:6379/0`.
/// Best-effort string surgery; a value without recognizable userinfo is
/// returned unchanged.
fn sanitize_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme_end + 3..];
    let authority_end = rest.find('/').unwrap_or(rest.len());
    if let Some(at) = rest[..authority_end].rfind('@') {
        format!("{}://***@{}", &url[..scheme_end], &rest[at + 1..])
    } else {
        url.to_string()
    }
}

/// Render an upstream Redis error safe to log: client-creation parse errors
/// may embed the connection URL (including its password), so replace every
/// occurrence of the raw URL with its credential-stripped form.
fn sanitized_error(e: &redis::RedisError, urls: &[&str]) -> String {
    let mut text = e.to_string();
    for url in urls {
        text = text.replace(url, &sanitize_url(url));
    }
    text
}

/// Redis-backed distributed cache supporting single-node and cluster modes.
pub struct RedisCache {
    client: Option<redis::Client>,
    conn: tokio::sync::Mutex<RedisConn>,
}

impl RedisCache {
    #[instrument(skip_all)]
    pub async fn connect(redis_url: &str) -> Result<Self, IssuerdError> {
        info!("connecting to Redis");
        let client = redis::Client::open(redis_url).map_err(|e| {
            let e = sanitized_error(&e, &[redis_url]);
            error!(error = %e, "redis client creation failed");
            IssuerdError::ServerError(format!("redis client create failed: {e}"))
        })?;
        let conn = client.get_multiplexed_tokio_connection().await.map_err(|e| {
            let e = sanitized_error(&e, &[redis_url]);
            error!(error = %e, "redis connection failed");
            IssuerdError::ServerError(format!("redis connection failed: {e}"))
        })?;
        Ok(Self {
            client: Some(client),
            conn: tokio::sync::Mutex::new(RedisConn::Single(conn)),
        })
    }

    #[instrument(skip_all)]
    pub async fn connect_cluster(nodes: &[String]) -> Result<Self, IssuerdError> {
        info!("connecting to Redis cluster");
        let client = redis::cluster::ClusterClient::new(nodes.to_vec()).map_err(|e| {
            let urls: Vec<&str> = nodes.iter().map(String::as_str).collect();
            let e = sanitized_error(&e, &urls);
            error!(error = %e, "redis cluster client creation failed");
            IssuerdError::ServerError(format!("redis cluster client create failed: {e}"))
        })?;
        let conn = client.get_async_connection().await.map_err(|e| {
            let urls: Vec<&str> = nodes.iter().map(String::as_str).collect();
            let e = sanitized_error(&e, &urls);
            error!(error = %e, "redis cluster connection failed");
            IssuerdError::ServerError(format!("redis cluster connection failed: {e}"))
        })?;
        Ok(Self {
            client: None,
            conn: tokio::sync::Mutex::new(RedisConn::Cluster(conn)),
        })
    }
}

#[async_trait]
impl DistributedCache for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
        let mut guard = self.conn.lock().await;
        let result: Option<Vec<u8>> = match &mut *guard {
            RedisConn::Single(conn) => redis::Cmd::get(key)
                .query_async(conn)
                .await
                .map_err(|e| IssuerdError::ServerError(format!("redis get failed: {e}")))?,
            RedisConn::Cluster(conn) => redis::Cmd::get(key)
                .query_async(conn)
                .await
                .map_err(|e| IssuerdError::ServerError(format!("redis cluster get failed: {e}")))?,
        };
        Ok(result)
    }

    async fn set(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Option<Duration>,
    ) -> Result<(), IssuerdError> {
        let mut guard = self.conn.lock().await;
        match &mut *guard {
            RedisConn::Single(conn) => {
                let mut cmd = redis::Cmd::set(key, value);
                if let Some(ttl) = ttl {
                    cmd.arg("PX").arg(ttl.as_millis() as u64);
                }
                cmd.query_async::<()>(conn)
                    .await
                    .map_err(|e| IssuerdError::ServerError(format!("redis set failed: {e}")))?;
            }
            RedisConn::Cluster(conn) => {
                let mut cmd = redis::Cmd::set(key, value);
                if let Some(ttl) = ttl {
                    cmd.arg("PX").arg(ttl.as_millis() as u64);
                }
                cmd.query_async::<()>(conn).await.map_err(|e| {
                    IssuerdError::ServerError(format!("redis cluster set failed: {e}"))
                })?;
            }
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), IssuerdError> {
        let mut guard = self.conn.lock().await;
        match &mut *guard {
            RedisConn::Single(conn) => redis::Cmd::del(key)
                .query_async::<()>(conn)
                .await
                .map_err(|e| IssuerdError::ServerError(format!("redis del failed: {e}")))?,
            RedisConn::Cluster(conn) => redis::Cmd::del(key)
                .query_async::<()>(conn)
                .await
                .map_err(|e| IssuerdError::ServerError(format!("redis cluster del failed: {e}")))?,
        }
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
        let mut guard = self.conn.lock().await;
        let result: Option<Vec<u8>> = match &mut *guard {
            RedisConn::Single(conn) => redis::cmd("GETDEL")
                .arg(key)
                .query_async(conn)
                .await
                .map_err(|e| IssuerdError::ServerError(format!("redis getdel failed: {e}")))?,
            RedisConn::Cluster(conn) => {
                redis::cmd("GETDEL").arg(key).query_async(conn).await.map_err(|e| {
                    IssuerdError::ServerError(format!("redis cluster getdel failed: {e}"))
                })?
            }
        };
        Ok(result)
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> Result<bool, IssuerdError> {
        let mut guard = self.conn.lock().await;
        match &mut *guard {
            RedisConn::Single(conn) => {
                if let Some(expected_value) = expected {
                    let script = redis::Script::new(
                        r#"
                        if redis.call("get", KEYS[1]) == ARGV[1] then
                            redis.call("set", KEYS[1], ARGV[2])
                            return 1
                        else
                            return 0
                        end
                        "#,
                    );
                    let result: i64 = script
                        .key(key)
                        .arg(&expected_value)
                        .arg(&new)
                        .invoke_async(conn)
                        .await
                        .map_err(|e| IssuerdError::ServerError(format!("redis cas failed: {e}")))?;
                    Ok(result == 1)
                } else {
                    let script = redis::Script::new(
                        r#"
                        if redis.call("exists", KEYS[1]) == 0 then
                            redis.call("set", KEYS[1], ARGV[1])
                            return 1
                        else
                            return 0
                        end
                        "#,
                    );
                    let result: i64 =
                        script.key(key).arg(&new).invoke_async(conn).await.map_err(|e| {
                            IssuerdError::ServerError(format!("redis cas failed: {e}"))
                        })?;
                    Ok(result == 1)
                }
            }
            RedisConn::Cluster(conn) => {
                if let Some(expected_value) = expected {
                    let script = redis::Script::new(
                        r#"
                        if redis.call("get", KEYS[1]) == ARGV[1] then
                            redis.call("set", KEYS[1], ARGV[2])
                            return 1
                        else
                            return 0
                        end
                        "#,
                    );
                    let result: i64 = script
                        .key(key)
                        .arg(&expected_value)
                        .arg(&new)
                        .invoke_async(conn)
                        .await
                        .map_err(|e| {
                            IssuerdError::ServerError(format!("redis cluster cas failed: {e}"))
                        })?;
                    Ok(result == 1)
                } else {
                    let script = redis::Script::new(
                        r#"
                        if redis.call("exists", KEYS[1]) == 0 then
                            redis.call("set", KEYS[1], ARGV[1])
                            return 1
                        else
                            return 0
                        end
                        "#,
                    );
                    let result: i64 =
                        script.key(key).arg(&new).invoke_async(conn).await.map_err(|e| {
                            IssuerdError::ServerError(format!("redis cluster cas failed: {e}"))
                        })?;
                    Ok(result == 1)
                }
            }
        }
    }

    async fn increment(&self, key: &str, ttl: Option<Duration>) -> Result<u64, IssuerdError> {
        // INCR is atomic server-side; PEXPIRE is applied only when the counter
        // is first created (v == 1), matching the trait contract. An empty
        // ARGV[1] means "no TTL".
        let ttl_millis = ttl.map(|t| (t.as_millis() as u64).to_string()).unwrap_or_default();
        let script = redis::Script::new(
            r#"
            local v = redis.call('INCR', KEYS[1])
            if v == 1 and ARGV[1] ~= '' then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
            return v
            "#,
        );
        let mut guard = self.conn.lock().await;
        let result: u64 = match &mut *guard {
            RedisConn::Single(conn) => {
                script.key(key).arg(&ttl_millis).invoke_async(conn).await.map_err(|e| {
                    IssuerdError::ServerError(format!("redis increment failed: {e}"))
                })?
            }
            RedisConn::Cluster(conn) => {
                script.key(key).arg(&ttl_millis).invoke_async(conn).await.map_err(|e| {
                    IssuerdError::ServerError(format!("redis cluster increment failed: {e}"))
                })?
            }
        };
        Ok(result)
    }

    async fn publish(&self, channel: &str, message: Vec<u8>) -> Result<(), IssuerdError> {
        let mut guard = self.conn.lock().await;
        match &mut *guard {
            RedisConn::Single(conn) => redis::Cmd::publish(channel, message)
                .query_async::<()>(conn)
                .await
                .map_err(|e| IssuerdError::ServerError(format!("redis publish failed: {e}")))?,
            RedisConn::Cluster(conn) => {
                redis::Cmd::publish(channel, message).query_async::<()>(conn).await.map_err(
                    |e| IssuerdError::ServerError(format!("redis cluster publish failed: {e}")),
                )?
            }
        }
        Ok(())
    }

    /// Uses `SCAN` with `MATCH <pattern>` and `COUNT 500`, iterating the
    /// cursor until it returns to 0. Unlike `KEYS`, `SCAN` is incremental
    /// and does not block the server.
    ///
    /// Under Redis Cluster the `SCAN` command is routed to a single node, so
    /// the result covers only that node's keyspace (best-effort for admin
    /// views); the shipped deployment is single-node.
    async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>, IssuerdError> {
        let mut guard = self.conn.lock().await;
        let mut cursor = 0u64;
        let mut keys = Vec::new();
        loop {
            // SCAN replies with a (next-cursor, keys) tuple.
            let (next, batch): (u64, Vec<String>) = match &mut *guard {
                RedisConn::Single(conn) => redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(pattern)
                    .arg("COUNT")
                    .arg(500)
                    .query_async(conn)
                    .await
                    .map_err(|e| IssuerdError::ServerError(format!("redis scan failed: {e}")))?,
                RedisConn::Cluster(conn) => redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(pattern)
                    .arg("COUNT")
                    .arg(500)
                    .query_async(conn)
                    .await
                    .map_err(|e| {
                        IssuerdError::ServerError(format!("redis cluster scan failed: {e}"))
                    })?,
            };
            keys.extend(batch);
            cursor = next;
            if cursor == 0 {
                return Ok(keys);
            }
        }
    }

    async fn subscribe(
        &self,
        channel: &str,
        handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
    ) -> Result<(), IssuerdError> {
        match &self.client {
            Some(client) => {
                let mut pubsub = client.get_async_pubsub().await.map_err(|e| {
                    IssuerdError::ServerError(format!("redis pubsub create failed: {e}"))
                })?;
                pubsub.subscribe(channel).await.map_err(|e| {
                    IssuerdError::ServerError(format!("redis subscribe failed: {e}"))
                })?;
                let channel = channel.to_string();
                tokio::spawn(async move {
                    let mut stream = pubsub.into_on_message();
                    while let Some(msg) = stream.next().await {
                        let payload: Result<Vec<u8>, _> = msg.get_payload();
                        if let Ok(payload) = payload {
                            handler(payload);
                        }
                    }
                    warn!(channel = %channel, "Redis pub/sub task ended unexpectedly");
                });
                Ok(())
            }
            None => Err(IssuerdError::ServerError("cluster pub/sub not yet implemented".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;
    use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage};

    #[test]
    fn sanitize_url_strips_userinfo() {
        assert_eq!(
            sanitize_url("redis://user:secret@redis.example.com:6379/0"),
            "redis://***@redis.example.com:6379/0"
        );
        assert_eq!(sanitize_url("redis://:secret@10.0.0.1:6379"), "redis://***@10.0.0.1:6379");
        assert_eq!(sanitize_url("redis://10.0.0.1:6379/2"), "redis://10.0.0.1:6379/2");
        assert_eq!(sanitize_url("not a url"), "not a url");
    }

    #[test]
    fn sanitized_error_redacts_embedded_url() {
        let url = "redis://admin:hunter2@cache:6379";
        // redis 0.27 parse errors carry (kind, desc, detail); fabricate one
        // whose detail embedded the raw URL, as a defensive regression case.
        let e: redis::RedisError = (
            redis::ErrorKind::InvalidClientConfig,
            "Redis URL did not parse",
            format!("could not parse {url}"),
        )
            .into();
        let redacted = sanitized_error(&e, &[url]);
        assert!(!redacted.contains("hunter2"), "password must not survive: {redacted}");
        assert!(redacted.contains("redis://***@cache:6379"));
    }

    async fn setup_redis() -> (RedisCache, testcontainers::ContainerAsync<GenericImage>) {
        let img = GenericImage::new("redis", "7-alpine")
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .with_exposed_port(testcontainers::core::ContainerPort::Tcp(6379));
        let container = img.start().await.expect("redis container start");
        let host = container.get_host().await.expect("host");
        let port = container.get_host_port_ipv4(6379).await.expect("port");
        let url = format!("redis://{host}:{port}");
        let cache = RedisCache::connect(&url).await.expect("redis connect");
        (cache, container)
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn redis_get_set_delete_roundtrip() {
        let (cache, _container) = setup_redis().await;
        assert_eq!(cache.get("key1").await.unwrap(), None);

        cache.set("key1", b"value1".to_vec(), None).await.unwrap();
        assert_eq!(cache.get("key1").await.unwrap(), Some(b"value1".to_vec()));

        cache.delete("key1").await.unwrap();
        assert_eq!(cache.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn redis_ttl_expiration() {
        let (cache, _container) = setup_redis().await;
        cache
            .set("key1", b"value1".to_vec(), Some(Duration::from_millis(50)))
            .await
            .unwrap();
        assert_eq!(cache.get("key1").await.unwrap(), Some(b"value1".to_vec()));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cache.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn redis_cas_key_absent() {
        let (cache, _container) = setup_redis().await;
        let result = cache.compare_and_swap("key1", None, b"value1".to_vec()).await.unwrap();
        assert!(result);
        assert_eq!(cache.get("key1").await.unwrap(), Some(b"value1".to_vec()));

        let result2 = cache.compare_and_swap("key1", None, b"value2".to_vec()).await.unwrap();
        assert!(!result2);
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn redis_cas_key_present() {
        let (cache, _container) = setup_redis().await;
        cache.set("key1", b"old".to_vec(), None).await.unwrap();

        let result = cache
            .compare_and_swap("key1", Some(b"wrong".to_vec()), b"new".to_vec())
            .await
            .unwrap();
        assert!(!result);

        let result2 = cache
            .compare_and_swap("key1", Some(b"old".to_vec()), b"new".to_vec())
            .await
            .unwrap();
        assert!(result2);
        assert_eq!(cache.get("key1").await.unwrap(), Some(b"new".to_vec()));
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn redis_increment_counter() {
        let (cache, _container) = setup_redis().await;

        // Fresh key starts at 1 and gets the TTL.
        assert_eq!(cache.increment("counter", Some(Duration::from_millis(300))).await.unwrap(), 1);
        // Subsequent increments keep counting without touching the TTL.
        assert_eq!(cache.increment("counter", Some(Duration::from_millis(300))).await.unwrap(), 2);
        assert_eq!(cache.increment("counter", None).await.unwrap(), 3);

        // The TTL applied on creation expires the key.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(cache.get("counter").await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn redis_pub_sub_single_handler() {
        let (cache, _container) = setup_redis().await;
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

        // Give pubsub a moment to establish
        tokio::time::sleep(Duration::from_millis(50)).await;

        cache.publish("chan1", b"hello".to_vec()).await.unwrap();

        // Wait for message delivery
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if received.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(received.lock().unwrap().clone(), Some(b"hello".to_vec()));
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn redis_pub_sub_multiple_handlers() {
        let (cache, _container) = setup_redis().await;
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

        tokio::time::sleep(Duration::from_millis(50)).await;

        cache.publish("chan1", b"hello".to_vec()).await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if count1.load(Ordering::SeqCst) > 0 && count2.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(count1.load(Ordering::SeqCst), 1);
        assert_eq!(count2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn redis_scan_keys() {
        let (cache, _container) = setup_redis().await;

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

        let sorted = |mut keys: Vec<String>| {
            keys.sort();
            keys
        };

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
        assert!(cache.scan_keys("login-failure:realm-3:*").await.unwrap().is_empty());
    }
}
