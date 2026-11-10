// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// End-to-end webhook subscription, event publication, HTTPS delivery, and replay.

use std::sync::{Arc, Mutex};

use axum::{body::Bytes, http::HeaderMap, routing::post, Router};
use issuerd_core::{Pagination, RealmId, WebhookDeliveryStatus, WebhookSecret};
use issuerd_server::webhooks::WebhookWorker;

use crate::harness::TestHarness;

#[derive(Clone)]
struct RecordedRequest {
    headers: HeaderMap,
    body: String,
}

async fn start_receiver() -> (String, reqwest::Certificate, Arc<Mutex<Vec<RecordedRequest>>>) {
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
        .push(rcgen::DnType::CommonName, "issuerd integration webhook CA");
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
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let app = Router::new().route(
        "/events",
        post(move |headers: HeaderMap, body: Bytes| {
            let recorded = Arc::clone(&recorded);
            async move {
                recorded.lock().unwrap().push(RecordedRequest {
                    headers,
                    body: String::from_utf8(body.to_vec()).unwrap(),
                });
                axum::http::StatusCode::OK
            }
        }),
    );
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

fn expected_signature(secret: &WebhookSecret, timestamp: i64, payload: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_str().as_bytes());
    let input = issuerd_core::webhook_signing_input(timestamp, payload);
    let tag = ring::hmac::sign(&key, input.as_bytes());
    let signature = tag.as_ref().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    format!("t={timestamp},v1={signature}")
}

#[tokio::test]
async fn failed_login_is_delivered_to_https_webhook_with_hmac() {
    let (url, root, requests) = start_receiver().await;
    let harness = TestHarness::new().await;
    harness.create_realm("webhook-it").await;
    let client = harness.create_client("webhook-it", false).await;
    harness.create_user("webhook-it", "alice", "password123").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    let response = harness
        .post_json_auth(
            "/admin/realms/webhook-it/webhooks",
            &admin,
            serde_json::json!({
                "url": url,
                "secret": "test-secret",
                "eventTypes": ["USER.LOGIN_ERROR"]
            }),
        )
        .await;
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    let created = response_json(response).await;
    assert!(created.get("secret").is_none());
    let subscription_id = created["id"].as_str().unwrap().to_string();

    let auth_path = format!(
        "/realms/webhook-it/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid",
        client.client_id
    );
    let auth_response = harness.get(&auth_path).await;
    let location = auth_response.headers()["location"].to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");
    let login_response = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=webhook-it",
            serde_json::json!({
                "execution_id": execution_id,
                "username": "alice",
                "password": "wrong-password"
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_response.status(), axum::http::StatusCode::UNAUTHORIZED);

    let worker = WebhookWorker::with_policy(harness.storage.clone(), &[root], true).unwrap();
    assert_eq!(worker.process_batch().await.unwrap(), 1);

    let (_, event_id) = {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        let payload: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(payload["schemaVersion"], 1);
        assert_eq!(payload["kind"], "USER");
        assert_eq!(payload["type"], "LOGIN_ERROR");
        assert_eq!(payload["realmName"], "webhook-it");
        assert_eq!(payload["clientId"], client.client_id.as_str());
        assert_eq!(payload["details"]["username"], "alice");
        let event_id = payload["id"].as_str().unwrap();
        assert_eq!(request.headers["idempotency-key"], event_id);
        assert_eq!(request.headers["x-issuerd-event-id"], event_id);
        let signature = request.headers["x-issuerd-signature"].to_str().unwrap();
        let timestamp = signature
            .strip_prefix("t=")
            .and_then(|value| value.split(",v1=").next())
            .unwrap()
            .parse::<i64>()
            .unwrap();
        let secret = WebhookSecret::new("test-secret").unwrap();
        assert_eq!(signature, expected_signature(&secret, timestamp, &request.body));
        (signature.to_string(), event_id.to_string())
    };

    let history_response = harness
        .get_auth(
            &format!("/admin/realms/webhook-it/webhooks/{subscription_id}/deliveries"),
            &admin,
        )
        .await;
    assert_eq!(history_response.status(), axum::http::StatusCode::OK);
    let history = response_json(history_response).await;
    assert_eq!(history.as_array().unwrap().len(), 1);
    assert_eq!(history[0]["status"], "delivered");
    assert!(history[0].get("payload").is_none());

    let realm = RealmId::new("webhook-it").unwrap();
    let subscription = issuerd_core::WebhookSubscriptionId::new(&subscription_id).unwrap();
    let deliveries = harness
        .storage
        .list_webhook_deliveries(&realm, Some(subscription), &Pagination::default())
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].status, WebhookDeliveryStatus::Delivered);
    assert_eq!(deliveries[0].event_id.to_string(), event_id);
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}
