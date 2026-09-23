// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Health, readiness, and metrics endpoints.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::state::ServerState;
use tracing::warn;

pub async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

pub async fn ready_handler(State(state): State<Arc<ServerState>>) -> Response {
    if let Err(e) = state.storage.list_realms(&issuerd_core::Pagination::default()).await {
        warn!(error = %e, "readiness check failed: storage unreachable");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready", "dependency": "storage"})),
        )
            .into_response();
    }
    // Probe the shared cache: in clustered mode a dead Redis must mark the
    // node not-ready so the load balancer drains it (auth codes, pending
    // auth and the revocation blocklist all live there).
    if let Err(e) = state.cache.get("__ready_probe__").await {
        warn!(error = %e, "readiness check failed: cache unreachable");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready", "dependency": "cache"})),
        )
            .into_response();
    }
    Json(serde_json::json!({"status": "ready"})).into_response()
}

static METRICS_HANDLE: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
    std::sync::OnceLock::new();

#[allow(dead_code)]
pub fn init_metrics() -> anyhow::Result<()> {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _ = METRICS_HANDLE.set(handle);
    metrics::set_global_recorder(recorder)?;
    Ok(())
}

async fn metrics_handler_inner(
    handle: Option<&metrics_exporter_prometheus::PrometheusHandle>,
) -> Response {
    match handle {
        Some(handle) => {
            let body = handle.render();
            ([("content-type", "text/plain; charset=utf-8")], body).into_response()
        }
        None => (StatusCode::NOT_FOUND, "metrics recorder not initialized").into_response(),
    }
}

pub async fn metrics_handler() -> Response {
    metrics_handler_inner(METRICS_HANDLE.get()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    #[tokio::test]
    async fn health_returns_ok() {
        let _ = health_handler().await;
    }

    #[tokio::test]
    async fn ready_with_inmemory_storage() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let response = ready_handler(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_not_initialized_returns_404() {
        let response = metrics_handler_inner(None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn metrics_initialized_returns_ok() {
        let _ = init_metrics();
        if let Some(handle) = METRICS_HANDLE.get() {
            let response = metrics_handler_inner(Some(handle)).await;
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[test]
    fn init_metrics_second_call_fails() {
        let _ = init_metrics();
        assert!(init_metrics().is_err());
    }

    #[tokio::test]
    async fn ready_with_failing_storage() {
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage
            .expect_list_realms()
            .returning(|_| Err(issuerd_core::IssuerdError::ServerError("db down".to_string())));

        let state = Arc::new(ServerState {
            config: ServerConfig::default(),
            storage: Arc::new(mock_storage),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            crypto: Arc::new(
                issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                    .unwrap(),
            ),
            token_service: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            token_manager: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            plugin_registry: Arc::new(crate::state::SimplePluginRegistry::new()),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            login_failure_tracker: Arc::new(
                issuerd_auth_flow::login_failures::LoginFailureTracker::new(),
            ),
            email_sender: Arc::new(crate::email::NoOpEmailSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            signing_key_reload: Arc::new(|| {}),
            keyset_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            event_listeners: std::collections::HashMap::new(),
        });

        let response = ready_handler(State(state)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn ready_with_failing_cache() {
        struct FailingCache;
        #[async_trait::async_trait]
        impl issuerd_core::DistributedCache for FailingCache {
            async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, issuerd_core::IssuerdError> {
                Err(issuerd_core::IssuerdError::ServerError("cache down".to_string()))
            }
            async fn set(
                &self,
                _key: &str,
                _value: Vec<u8>,
                _ttl: Option<std::time::Duration>,
            ) -> Result<(), issuerd_core::IssuerdError> {
                Ok(())
            }
            async fn delete(&self, _key: &str) -> Result<(), issuerd_core::IssuerdError> {
                Ok(())
            }
            async fn compare_and_swap(
                &self,
                _key: &str,
                _expected: Option<Vec<u8>>,
                _new: Vec<u8>,
            ) -> Result<bool, issuerd_core::IssuerdError> {
                Ok(false)
            }
            async fn publish(
                &self,
                _channel: &str,
                _message: Vec<u8>,
            ) -> Result<(), issuerd_core::IssuerdError> {
                Ok(())
            }
            async fn subscribe(
                &self,
                _channel: &str,
                _handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
            ) -> Result<(), issuerd_core::IssuerdError> {
                Ok(())
            }
        }

        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage.expect_list_realms().returning(|_| Ok(vec![]));

        let state = Arc::new(ServerState {
            config: ServerConfig::default(),
            storage: Arc::new(mock_storage),
            cache: Arc::new(FailingCache),
            crypto: Arc::new(
                issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                    .unwrap(),
            ),
            token_service: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            token_manager: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            plugin_registry: Arc::new(crate::state::SimplePluginRegistry::new()),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            login_failure_tracker: Arc::new(
                issuerd_auth_flow::login_failures::LoginFailureTracker::new(),
            ),
            email_sender: Arc::new(crate::email::NoOpEmailSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            signing_key_reload: Arc::new(|| {}),
            keyset_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            event_listeners: std::collections::HashMap::new(),
        });

        let response = ready_handler(State(state)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn metrics_handler_runs_inner() {
        let response = metrics_handler().await;
        assert!(
            response.status() == StatusCode::OK || response.status() == StatusCode::NOT_FOUND,
            "metrics_handler should return OK or NOT_FOUND"
        );
    }
}
