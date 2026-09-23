// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Cluster event bus for cache invalidation and coordination.

use std::sync::Arc;

use issuerd_core::{DistributedCache, IssuerdError};
use serde::{Deserialize, Serialize};

/// Events broadcast across the cluster for cache invalidation and coordination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClusterEvent {
    SessionInvalidated { realm: String, session_id: String },
    RealmUpdated { realm_id: String },
    ClientUpdated { realm: String, client_id: String },
    KeyRotated { realm: String, kid: String },
    UserUpdated { realm: String, user_id: String },
}

/// Broadcasts and subscribes to cluster events over a `DistributedCache` backend.
pub struct ClusterEventBus {
    cache: Arc<dyn DistributedCache>,
}

impl ClusterEventBus {
    pub fn new(cache: Arc<dyn DistributedCache>) -> Self {
        Self { cache }
    }

    pub async fn broadcast(&self, event: &ClusterEvent) -> Result<(), IssuerdError> {
        let bytes = serde_json::to_vec(event)
            .map_err(|e| IssuerdError::ServerError(format!("event serialization failed: {e}")))?;
        self.cache.publish("cluster:events", bytes).await
    }

    pub async fn subscribe(
        &self,
    ) -> Result<tokio::sync::mpsc::Receiver<ClusterEvent>, IssuerdError> {
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let tx = Arc::new(tokio::sync::Mutex::new(tx));
        let cache = Arc::clone(&self.cache);

        // Subscribe to a global cluster events channel.
        // Individual realm-scoped events are also published to realm-specific
        // channels; for simplicity we subscribe to the wildcard-ish global.
        // In production this may be expanded to subscribe to all realm channels.
        let handler = Box::new(move |msg: Vec<u8>| {
            if let Ok(event) = serde_json::from_slice::<ClusterEvent>(&msg) {
                // Try to send; ignore errors if the receiver has been dropped.
                let tx = Arc::clone(&tx);
                tokio::spawn(async move {
                    let guard = tx.lock().await;
                    let _ = guard.send(event).await;
                });
            }
        });

        cache.subscribe("cluster:events", handler).await?;
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::InMemoryCache;
    use issuerd_core::DistributedCache;

    #[test]
    fn cluster_event_session_invalidated_roundtrip() {
        let event = ClusterEvent::SessionInvalidated {
            realm: "master".into(),
            session_id: "sess-1".into(),
        };
        let json = serde_json::to_vec(&event).unwrap();
        let back: ClusterEvent = serde_json::from_slice(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn cluster_event_realm_updated_roundtrip() {
        let event = ClusterEvent::RealmUpdated {
            realm_id: "master".into(),
        };
        let json = serde_json::to_vec(&event).unwrap();
        let back: ClusterEvent = serde_json::from_slice(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn cluster_event_client_updated_roundtrip() {
        let event = ClusterEvent::ClientUpdated {
            realm: "master".into(),
            client_id: "my-app".into(),
        };
        let json = serde_json::to_vec(&event).unwrap();
        let back: ClusterEvent = serde_json::from_slice(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn cluster_event_key_rotated_roundtrip() {
        let event = ClusterEvent::KeyRotated {
            realm: "master".into(),
            kid: "kid-1".into(),
        };
        let json = serde_json::to_vec(&event).unwrap();
        let back: ClusterEvent = serde_json::from_slice(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn cluster_event_user_updated_roundtrip() {
        let event = ClusterEvent::UserUpdated {
            realm: "master".into(),
            user_id: "user-1".into(),
        };
        let json = serde_json::to_vec(&event).unwrap();
        let back: ClusterEvent = serde_json::from_slice(&json).unwrap();
        assert_eq!(event, back);
    }

    #[tokio::test]
    async fn event_bus_broadcast_and_subscribe() {
        let cache: Arc<dyn DistributedCache> = Arc::new(InMemoryCache::new());
        let bus = ClusterEventBus::new(Arc::clone(&cache));

        let mut rx = bus.subscribe().await.unwrap();

        let event = ClusterEvent::RealmUpdated {
            realm_id: "master".into(),
        };
        bus.broadcast(&event).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(received, event);
    }

    #[tokio::test]
    async fn event_bus_multiple_subscribers() {
        let cache: Arc<dyn DistributedCache> = Arc::new(InMemoryCache::new());
        let bus1 = ClusterEventBus::new(Arc::clone(&cache));
        let bus2 = ClusterEventBus::new(Arc::clone(&cache));

        let mut rx1 = bus1.subscribe().await.unwrap();
        let mut rx2 = bus2.subscribe().await.unwrap();

        let event = ClusterEvent::SessionInvalidated {
            realm: "master".into(),
            session_id: "sess-1".into(),
        };
        bus1.broadcast(&event).await.unwrap();

        let recv1 = tokio::time::timeout(std::time::Duration::from_secs(2), rx1.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        let recv2 = tokio::time::timeout(std::time::Duration::from_secs(2), rx2.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(recv1, event);
        assert_eq!(recv2, event);
    }
}
