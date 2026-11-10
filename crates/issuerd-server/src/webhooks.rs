// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Durable at-least-once HTTPS delivery for webhook subscriptions.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use issuerd_core::*;
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::broker::SsrfGuardedClient;
use crate::config::ServerConfig;

const DEFAULT_BATCH_SIZE: u32 = 32;
const DEFAULT_LEASE_SECS: u64 = 30;
const DEFAULT_POLL_SECS: u64 = 1;
const DEFAULT_MAX_ATTEMPTS: u32 = 8;
const MAX_BACKOFF_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryDecision {
    Delivered,
    Retry,
    Dead,
}

pub struct WebhookWorker {
    storage: Arc<dyn Storage>,
    http: SsrfGuardedClient,
    worker_id: String,
    batch_size: u32,
    lease_duration: Duration,
    poll_interval: Duration,
    max_attempts: u32,
}

impl WebhookWorker {
    pub fn from_config(
        storage: Arc<dyn Storage>,
        config: &ServerConfig,
    ) -> Result<Self, IssuerdError> {
        let roots = config.outbound_http.load_extra_roots()?;
        Self::with_policy(storage, &roots, config.outbound_http.allow_private_addresses)
    }

    pub fn with_policy(
        storage: Arc<dyn Storage>,
        extra_roots: &[reqwest::Certificate],
        allow_private_addresses: bool,
    ) -> Result<Self, IssuerdError> {
        let http =
            SsrfGuardedClient::new(extra_roots, allow_private_addresses, Duration::from_secs(10))
                .map_err(|e| IssuerdError::ServerError(format!("webhook http client: {e}")))?;
        Ok(Self {
            storage,
            http,
            worker_id: format!("webhook-{}", issuerd_core::utils::generate_id()),
            batch_size: DEFAULT_BATCH_SIZE,
            lease_duration: Duration::from_secs(DEFAULT_LEASE_SECS),
            poll_interval: Duration::from_secs(DEFAULT_POLL_SECS),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        loop {
            let processed = match self.process_batch().await {
                Ok(processed) => processed,
                Err(error) => {
                    warn!(error = %error, "webhook delivery batch failed");
                    0
                }
            };
            if processed > 0 {
                continue;
            }
            tokio::select! {
                () = tokio::time::sleep(self.poll_interval) => {}
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    pub async fn process_batch(&self) -> Result<usize, IssuerdError> {
        let tasks = self
            .storage
            .claim_webhook_deliveries(&self.worker_id, self.batch_size, self.lease_duration)
            .await?;
        let count = tasks.len();
        for task in tasks {
            self.deliver(task).await?;
        }
        Ok(count)
    }

    async fn deliver(&self, task: WebhookDeliveryTask) -> Result<(), IssuerdError> {
        let realm = task.subscription.realm_id.clone();
        let delivery_id = task.delivery.id.clone();
        let timestamp = Utc::now().timestamp();
        let signature = sign_webhook(&task.subscription.secret, timestamp, &task.delivery.payload);
        let event_id = task.delivery.event_id.to_string();
        let headers = [
            ("Idempotency-Key", event_id.as_str()),
            ("X-Issuerd-Event-Id", event_id.as_str()),
            ("X-Issuerd-Signature", signature.as_str()),
        ];
        let result = self
            .http
            .post_json(&task.subscription.url, &task.delivery.payload, &headers)
            .await;
        match result {
            Ok(response) if response.status.is_success() => {
                self.storage
                    .complete_webhook_delivery(&realm, &delivery_id, lease_owner(&task)?)
                    .await?;
                debug!(delivery = %delivery_id, event = %event_id, "webhook delivered");
                Ok(())
            }
            Ok(response) => {
                let decision = retry_decision(response.status);
                self.record_failure(
                    task,
                    decision,
                    format!("http status {}", response.status),
                    response.retry_after,
                )
                .await
            }
            Err(error) => {
                self.record_failure(task, RetryDecision::Retry, error.to_string(), None).await
            }
        }
    }

    async fn record_failure(
        &self,
        task: WebhookDeliveryTask,
        decision: RetryDecision,
        error: String,
        retry_after: Option<Duration>,
    ) -> Result<(), IssuerdError> {
        let retry = decision == RetryDecision::Retry
            && task.delivery.attempts.saturating_add(1) < self.max_attempts;
        let next_attempt_at = if retry {
            let backoff =
                delivery_backoff(task.delivery.attempts, &task.delivery.event_id, retry_after);
            let backoff = chrono::Duration::from_std(backoff)
                .map_err(|e| IssuerdError::ServerError(format!("webhook backoff: {e}")))?;
            Some(
                Utc::now()
                    .checked_add_signed(backoff)
                    .ok_or_else(|| IssuerdError::ServerError("webhook backoff overflow".into()))?,
            )
        } else {
            None
        };
        let realm = task.subscription.realm_id.clone();
        let delivery_id = task.delivery.id.clone();
        self.storage
            .fail_webhook_delivery(
                &realm,
                &delivery_id,
                lease_owner(&task)?,
                &error,
                next_attempt_at,
            )
            .await?;
        if next_attempt_at.is_some() {
            debug!(delivery = %delivery_id, error = %error, "webhook delivery scheduled for retry");
        } else {
            warn!(delivery = %delivery_id, error = %error, "webhook delivery is dead");
        }
        Ok(())
    }
}

fn lease_owner(task: &WebhookDeliveryTask) -> Result<&str, IssuerdError> {
    task.delivery
        .lease_owner
        .as_deref()
        .ok_or_else(|| IssuerdError::ServerError("claimed webhook delivery has no lease".into()))
}

fn retry_decision(status: reqwest::StatusCode) -> RetryDecision {
    if status.is_success() {
        RetryDecision::Delivered
    } else if matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_EARLY
            | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
    {
        RetryDecision::Retry
    } else {
        RetryDecision::Dead
    }
}

fn delivery_backoff(attempts: u32, event_id: &EventId, retry_after: Option<Duration>) -> Duration {
    let exponent = attempts.min(6);
    let seconds = (1_u64 << exponent).min(60);
    let jitter_millis = uuid::Uuid::parse_str(event_id.as_ref())
        .ok()
        .map(|id| u64::from(id.as_bytes()[0]) % 1000)
        .unwrap_or(0);
    let backoff = Duration::from_secs(seconds) + Duration::from_millis(jitter_millis);
    backoff
        .max(retry_after.unwrap_or(Duration::ZERO))
        .min(Duration::from_secs(MAX_BACKOFF_SECS))
}

fn sign_webhook(secret: &WebhookSecret, timestamp: i64, payload: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_str().as_bytes());
    let input = webhook_signing_input(timestamp, payload);
    let tag = ring::hmac::sign(&key, input.as_bytes());
    let signature = tag.as_ref().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    format!("t={timestamp},v1={signature}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classification_is_bounded_and_explicit() {
        for status in [200, 201, 202, 204] {
            assert_eq!(
                retry_decision(reqwest::StatusCode::from_u16(status).unwrap()),
                RetryDecision::Delivered
            );
        }
        for status in [408, 425, 429, 500, 502, 503, 599] {
            assert_eq!(
                retry_decision(reqwest::StatusCode::from_u16(status).unwrap()),
                RetryDecision::Retry
            );
        }
        for status in [301, 400, 401, 403, 404, 409, 410, 422] {
            assert_eq!(
                retry_decision(reqwest::StatusCode::from_u16(status).unwrap()),
                RetryDecision::Dead
            );
        }
    }

    #[test]
    fn backoff_is_capped_and_honors_retry_after() {
        let event = EventId::new(uuid::Uuid::nil().to_string()).unwrap();
        assert_eq!(delivery_backoff(0, &event, None), Duration::from_secs(1));
        assert_eq!(delivery_backoff(1, &event, None), Duration::from_secs(2));
        assert_eq!(delivery_backoff(6, &event, None), Duration::from_secs(60));
        assert_eq!(delivery_backoff(7, &event, None), Duration::from_secs(60));
        assert_eq!(
            delivery_backoff(6, &event, Some(Duration::from_secs(7200))),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn signature_uses_the_documented_raw_body_contract() {
        let secret = WebhookSecret::new("key").unwrap();
        let signature = sign_webhook(&secret, 42, "The quick brown fox jumps over the lazy dog");
        assert!(signature.starts_with("t=42,v1="));
        assert_eq!(signature.len(), "t=42,v1=".len() + 64);
    }
}

#[cfg(test)]
mod delivery_tests {
    use super::*;
    use axum::{body::Bytes, extract::State, http::HeaderMap, routing::post, Router};
    use issuerd_storage::InMemoryStorage;
    use std::collections::VecDeque;

    #[derive(Clone)]
    struct RecordedRequest {
        headers: HeaderMap,
        body: String,
    }

    #[derive(Clone)]
    struct ReceiverState {
        statuses: Arc<std::sync::Mutex<VecDeque<reqwest::StatusCode>>>,
        requests: Arc<std::sync::Mutex<Vec<RecordedRequest>>>,
    }

    async fn start_receiver(
        statuses: Vec<reqwest::StatusCode>,
    ) -> (String, reqwest::Certificate, Arc<std::sync::Mutex<Vec<RecordedRequest>>>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "issuerd webhook test CA");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .signed_by(&server_key, &ca_cert)
            .unwrap();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            server_cert.pem().into_bytes(),
            server_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = ReceiverState {
            statuses: Arc::new(std::sync::Mutex::new(statuses.into_iter().collect())),
            requests: Arc::clone(&requests),
        };
        let app = Router::new().route(
            "/events",
            post(
                |State(state): State<ReceiverState>, headers: HeaderMap, body: Bytes| async move {
                    let body = String::from_utf8(body.to_vec()).unwrap();
                    state.requests.lock().unwrap().push(RecordedRequest {
                        headers: headers.clone(),
                        body,
                    });
                    state.statuses.lock().unwrap().pop_front().unwrap_or(reqwest::StatusCode::OK)
                },
            ),
        )
        .with_state(state);
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        let root = reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).unwrap();
        (format!("https://127.0.0.1:{port}/events"), root, requests)
    }

    fn subscription(url: String) -> WebhookSubscription {
        WebhookSubscription {
            id: WebhookSubscriptionId::new("subscription-1").unwrap(),
            realm_id: RealmId::new("master").unwrap(),
            url,
            secret: WebhookSecret::new("secret").unwrap(),
            enabled: true,
            event_types: vec!["*".to_string()],
            include_representation: false,
            created_by: None,
            created_at: Utc::now(),
        }
    }

    fn event() -> WebhookEvent {
        WebhookEvent::from_user_event(
            &Event {
                id: EventId::new(uuid::Uuid::nil().to_string()).unwrap(),
                realm_id: RealmId::new("master").unwrap(),
                event_time: Utc::now(),
                event_type: EventType::Login,
                ip_address: None,
                client_id: None,
                user_id: None,
                session_id: None,
                error: None,
                details: Default::default(),
            },
            "master",
            None,
        )
    }

    async fn storage_with_delivery(url: String) -> (Arc<InMemoryStorage>, WebhookDeliveryId) {
        let storage = Arc::new(InMemoryStorage::new());
        let realm = RealmId::new("master").unwrap();
        let subscription = subscription(url);
        storage.create_webhook_subscription(&realm, &subscription).await.unwrap();
        storage
            .enqueue_webhook_delivery(&realm, &subscription.id, &event())
            .await
            .unwrap();
        let deliveries = storage
            .list_webhook_deliveries(&realm, None, &Pagination::default())
            .await
            .unwrap();
        (storage, deliveries[0].id.clone())
    }

    async fn history(storage: &InMemoryStorage) -> Vec<WebhookDelivery> {
        storage
            .list_webhook_deliveries(&RealmId::new("master").unwrap(), None, &Pagination::default())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn https_delivery_sends_exact_payload_and_verifiable_signature() {
        let (url, root, requests) = start_receiver(vec![reqwest::StatusCode::OK]).await;
        let (storage, _) = storage_with_delivery(url).await;
        let worker = WebhookWorker::with_policy(storage.clone(), &[root], true).unwrap();
        assert_eq!(worker.process_batch().await.unwrap(), 1);

        let history = history(&storage).await;
        assert_eq!(history[0].status, WebhookDeliveryStatus::Delivered);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.body, history[0].payload);
        let event_id = history[0].event_id.to_string();
        assert_eq!(request.headers["idempotency-key"], event_id);
        assert_eq!(request.headers["x-issuerd-event-id"], event_id);
        let signature = request.headers["x-issuerd-signature"].to_str().unwrap();
        let timestamp = signature
            .strip_prefix("t=")
            .and_then(|value| value.split(",v1=").next())
            .unwrap()
            .parse::<i64>()
            .unwrap();
        assert_eq!(
            signature,
            sign_webhook(&subscription("unused".into()).secret, timestamp, &request.body)
        );
    }

    #[tokio::test]
    async fn server_error_retries_with_the_same_idempotency_key() {
        let (url, root, requests) = start_receiver(vec![
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::OK,
        ])
        .await;
        let (storage, _) = storage_with_delivery(url).await;
        let worker = WebhookWorker::with_policy(storage.clone(), &[root], true).unwrap();
        assert_eq!(worker.process_batch().await.unwrap(), 1);
        assert_eq!(history(&storage).await[0].status, WebhookDeliveryStatus::Pending);
        assert_eq!(history(&storage).await[0].attempts, 1);

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(worker.process_batch().await.unwrap(), 1);
        assert_eq!(history(&storage).await[0].status, WebhookDeliveryStatus::Delivered);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].headers["idempotency-key"], requests[1].headers["idempotency-key"]);
    }

    #[tokio::test]
    async fn ordinary_client_error_marks_delivery_dead() {
        let (url, root, requests) = start_receiver(vec![reqwest::StatusCode::BAD_REQUEST]).await;
        let (storage, _) = storage_with_delivery(url).await;
        let worker = WebhookWorker::with_policy(storage.clone(), &[root], true).unwrap();
        assert_eq!(worker.process_batch().await.unwrap(), 1);
        assert_eq!(history(&storage).await[0].status, WebhookDeliveryStatus::Dead);
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn redirect_marks_delivery_dead_without_retry() {
        let (url, root, requests) = start_receiver(vec![
            reqwest::StatusCode::MOVED_PERMANENTLY,
            reqwest::StatusCode::OK,
        ])
        .await;
        let (storage, _) = storage_with_delivery(url).await;
        let worker = WebhookWorker::with_policy(storage.clone(), &[root], true).unwrap();

        assert_eq!(worker.process_batch().await.unwrap(), 1);
        assert_eq!(history(&storage).await[0].status, WebhookDeliveryStatus::Dead);
        assert_eq!(requests.lock().unwrap().len(), 1);
        assert_eq!(worker.process_batch().await.unwrap(), 0);
    }
}
