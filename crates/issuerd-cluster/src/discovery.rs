// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Cluster node discovery: node info, topology events, and static discovery.

use std::collections::HashMap;

use async_trait::async_trait;
use issuerd_core::IssuerdError;

/// Information about a cluster node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: String,
    pub addr: String,
    pub metadata: HashMap<String, String>,
}

/// Events emitted when the node topology changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    Joined(NodeInfo),
    Left(String),
}

/// Trait for discovering nodes in the cluster.
#[async_trait]
pub trait NodeDiscovery: Send + Sync {
    async fn current_nodes(&self) -> Result<Vec<NodeInfo>, IssuerdError>;
    async fn subscribe(&self) -> Result<tokio::sync::mpsc::Receiver<NodeEvent>, IssuerdError>;
}

/// Static node discovery backed by a fixed configuration list.
pub struct StaticDiscovery {
    nodes: Vec<NodeInfo>,
    _tx: tokio::sync::broadcast::Sender<NodeEvent>,
}

impl StaticDiscovery {
    pub fn from_config(nodes: &[String]) -> Self {
        let node_infos: Vec<NodeInfo> = nodes
            .iter()
            .map(|s| {
                let parts: Vec<&str> = s.splitn(2, '@').collect();
                if parts.len() == 2 {
                    NodeInfo {
                        id: parts[0].to_string(),
                        addr: parts[1].to_string(),
                        metadata: HashMap::new(),
                    }
                } else {
                    NodeInfo {
                        id: s.clone(),
                        addr: s.clone(),
                        metadata: HashMap::new(),
                    }
                }
            })
            .collect();
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        Self {
            nodes: node_infos,
            _tx: tx,
        }
    }
}

#[async_trait]
impl NodeDiscovery for StaticDiscovery {
    async fn current_nodes(&self) -> Result<Vec<NodeInfo>, IssuerdError> {
        Ok(self.nodes.clone())
    }

    async fn subscribe(&self) -> Result<tokio::sync::mpsc::Receiver<NodeEvent>, IssuerdError> {
        // Static list never changes; create a channel that will simply never
        // produce events.
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(tx);
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_discovery_from_config_with_id() {
        let nodes = vec!["node1@127.0.0.1:8080".to_string()];
        let discovery = StaticDiscovery::from_config(&nodes);
        let current = discovery.current_nodes().await.unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].id, "node1");
        assert_eq!(current[0].addr, "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn static_discovery_from_config_without_id() {
        let nodes = vec!["127.0.0.1:8080".to_string()];
        let discovery = StaticDiscovery::from_config(&nodes);
        let current = discovery.current_nodes().await.unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].id, "127.0.0.1:8080");
        assert_eq!(current[0].addr, "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn static_discovery_current_nodes_returns_all() {
        let nodes = vec!["a@10.0.0.1:8080".to_string(), "b@10.0.0.2:8080".to_string()];
        let discovery = StaticDiscovery::from_config(&nodes);
        let current = discovery.current_nodes().await.unwrap();
        assert_eq!(current.len(), 2);
    }

    #[tokio::test]
    async fn static_discovery_subscribe_does_not_panic() {
        let nodes = vec!["node1@127.0.0.1:8080".to_string()];
        let discovery = StaticDiscovery::from_config(&nodes);
        let mut rx = discovery.subscribe().await.unwrap();
        // Channel is closed immediately, so recv returns None
        assert!(rx.recv().await.is_none());
    }
}
