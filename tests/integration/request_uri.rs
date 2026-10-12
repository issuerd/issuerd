// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// JAR-by-reference (`request_uri`, OIDC Core §6.2) integration tests.

//! JAR-by-reference integration tests (Issuerd-only).
//!
//! Covered: a signed request object fetched from a client-registered
//! `request_uri` (the DCR `request_uris` metadata list) runs the full
//! authorization flow; unregistered URIs are refused before any fetch;
//! `request` + `request_uri` are mutually exclusive; fetch failures and
//! unsigned objects are rejected.

use std::sync::Arc;

use axum::http::StatusCode;

use crate::harness::TestHarness;
use issuerd_core::CryptoProvider;
use issuerd_server::state::ServerState;

const REDIRECT_URI: &str = "http://localhost:8080/cb";
const PASSWORD: &str = "Password123!";
/// The pre-registered request_uri used throughout (https, so the SSRF guard
/// would allow it — the fetch itself is stubbed by the mock broker client).
const REQUEST_URI: &str = "https://rp.example.com/request-object.jwt";

fn auth_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/auth")
}

/// A confidential client with the given `request_uris` list (and inline JWKS
/// when the test signs RS256), persisted.
async fn client_with_request_uris(
    harness: &TestHarness,
    realm: &str,
    uris: &[&str],
    jwks_string: Option<&str>,
) -> issuerd_core::Client {
    let mut client = harness.create_client(realm, false).await;
    let encoded = serde_json::to_string(&uris).unwrap();
    client.attributes.insert("request_uris".to_string(), encoded);
    if let Some(jwks) = jwks_string {
        client.attributes.insert("use.jwks.string".to_string(), "true".to_string());
        client.attributes.insert("jwks.string".to_string(), jwks.to_string());
    }
    harness
        .storage
        .update_client(&issuerd_core::RealmId::new(realm).unwrap(), &client)
        .await
        .unwrap();
    client
}

/// A harness whose broker client serves the shared cell's current content
/// for the guarded text fetch (set it once the request object is signed).
async fn harness_serving(
    body: Arc<std::sync::RwLock<String>>,
) -> (TestHarness, Arc<std::sync::atomic::AtomicUsize>) {
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hit = hits.clone();
    let mut broker = issuerd_core::MockBrokerClient::new();
    broker.expect_get_text_ssrf_guarded().returning(move |_| {
        hit.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(body.read().unwrap().clone())
    });
    let base = ServerState::from_config(&issuerd_server::config::ServerConfig::default())
        .await
        .unwrap();
    let harness = TestHarness::with_state(Arc::new(ServerState {
        broker_client: Arc::new(broker),
        ..base
    }));
    (harness, hits)
}

/// Sign a request object with the client secret (HS256).
fn sign_hs256(claims: &serde_json::Value, secret: &str) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

/// The request-object claims for a code flow.
fn object_claims(harness: &TestHarness, realm: &str, client_id: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": client_id,
        "aud": format!("{}/realms/{realm}", harness.base_url),
        "exp": chrono::Utc::now().timestamp() + 300,
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "object-state",
        "nonce": "n-1",
    })
}

/// Authorize → expect the login-page redirect → form-login → return the
/// packaged authorization response.
async fn run_flow(
    harness: &TestHarness,
    realm: &str,
    query: &str,
    username: &str,
) -> axum::response::Response {
    let resp = harness.get(&format!("{}?{query}", auth_path(realm))).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains("/login.html"), "expected the login page, got: {location}");
    let execution_id =
        TestHarness::extract_query_param(&location, "execution_id").expect("missing execution_id");
    harness
        .post_form_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            &[
                ("execution_id", &execution_id),
                ("username", username),
                ("password", PASSWORD),
            ],
            &TestHarness::flow_cookie(&execution_id),
        )
        .await
}

// ---------------------------------------------------------------------------
// The full flow
// ---------------------------------------------------------------------------

/// A signed request object fetched from the client-registered `request_uri`
/// runs the full authorization flow; the object's parameters win.
#[tokio::test]
async fn request_uri_signed_object_runs_the_full_flow() {
    let served = Arc::new(std::sync::RwLock::new(String::new()));
    let (harness, hits) = harness_serving(served.clone()).await;
    harness.create_realm("test").await;
    let client = client_with_request_uris(&harness, "test", &[REQUEST_URI], None).await;
    harness.create_user("test", "alice", PASSWORD).await;

    // The object is what the mock broker serves (signed HS256 with the
    // client secret).
    let object = sign_hs256(
        &object_claims(&harness, "test", client.client_id.as_ref()),
        client.secret.as_deref().unwrap(),
    );
    *served.write().unwrap() = object;

    let resp = run_flow(
        &harness,
        "test",
        &format!(
            "client_id={}&request_uri={}",
            client.client_id,
            REQUEST_URI.replace(':', "%3A").replace('/', "%2F")
        ),
        "alice",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(
        location.starts_with(&format!("{REDIRECT_URI}?")),
        "the object's flow completes against its redirect_uri: {location}"
    );
    assert!(
        TestHarness::extract_query_param(&location, "code").is_some(),
        "no code issued: {location}"
    );
    assert_eq!(
        TestHarness::extract_query_param(&location, "state").as_deref(),
        Some("object-state"),
        "object params win: {location}"
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1, "exactly one fetch");
}

/// Same flow, with the object signed RS256 against the client's registered
/// inline JWKS (the certification module's shape).
#[tokio::test]
async fn request_uri_rs256_object_against_inline_jwks() {
    let served = Arc::new(std::sync::RwLock::new(String::new()));
    let (harness, _hits) = harness_serving(served.clone()).await;
    harness.create_realm("test").await;
    harness.create_user("test", "alice", PASSWORD).await;

    let crypto = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
        default_alg: issuerd_core::Algorithm::Rs256,
        rsa_key_size: 2048,
    })
    .unwrap();
    let jwks = serde_json::to_value(crypto.get_public_keys().await.unwrap()).unwrap();
    let kid = jwks["keys"][0]["kid"].as_str().unwrap().to_string();
    let jwks_string = serde_json::to_string(&jwks).unwrap();
    let client =
        client_with_request_uris(&harness, "test", &[REQUEST_URI], Some(&jwks_string)).await;

    let object = crypto
        .sign(
            &object_claims(&harness, "test", client.client_id.as_ref()).to_string(),
            issuerd_core::Algorithm::Rs256,
            &issuerd_core::KeyId::new(kid).unwrap(),
        )
        .await
        .unwrap();
    *served.write().unwrap() = object;

    let resp = run_flow(
        &harness,
        "test",
        &format!(
            "client_id={}&request_uri={}",
            client.client_id,
            REQUEST_URI.replace(':', "%3A").replace('/', "%2F")
        ),
        "alice",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(&format!("{REDIRECT_URI}?")), "{location}");
    assert!(
        TestHarness::extract_query_param(&location, "code").is_some(),
        "no code issued: {location}"
    );
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

/// A `request_uri` the client never registered is refused before any fetch.
#[tokio::test]
async fn unregistered_request_uri_rejected_without_fetch() {
    let served = Arc::new(std::sync::RwLock::new(String::new()));
    let (harness, hits) = harness_serving(served).await;
    harness.create_realm("test").await;
    let client = client_with_request_uris(&harness, "test", &[REQUEST_URI], None).await;

    let resp = harness
        .get(&format!(
            "{}?client_id={}&request_uri={}",
            auth_path("test"),
            client.client_id,
            "https://evil.example.com/object.jwt".replace(':', "%3A").replace('/', "%2F")
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_request");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "no fetch attempted");
}

/// `request` and `request_uri` in one request are mutually exclusive
/// (RFC 9101 §4).
#[tokio::test]
async fn request_and_request_uri_are_mutually_exclusive() {
    let served = Arc::new(std::sync::RwLock::new(String::new()));
    let (harness, _hits) = harness_serving(served).await;
    harness.create_realm("test").await;
    let client = client_with_request_uris(&harness, "test", &[REQUEST_URI], None).await;
    let object = sign_hs256(
        &object_claims(&harness, "test", client.client_id.as_ref()),
        client.secret.as_deref().unwrap(),
    );

    let resp = harness
        .get(&format!(
            "{}?client_id={}&request={}&request_uri={}",
            auth_path("test"),
            client.client_id,
            object,
            REQUEST_URI.replace(':', "%3A").replace('/', "%2F")
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_request");
}

/// A fetch failure (unreachable/erroring URL) is rejected.
#[tokio::test]
async fn request_uri_fetch_failure_rejected() {
    let mut broker = issuerd_core::MockBrokerClient::new();
    broker.expect_get_text_ssrf_guarded().returning(move |_| {
        Err(issuerd_core::IssuerdError::InvalidRequest(
            "untrusted URL could not be fetched".to_string(),
        ))
    });
    let base = ServerState::from_config(&issuerd_server::config::ServerConfig::default())
        .await
        .unwrap();
    let harness = TestHarness::with_state(Arc::new(ServerState {
        broker_client: Arc::new(broker),
        ..base
    }));
    harness.create_realm("test").await;
    let client = client_with_request_uris(&harness, "test", &[REQUEST_URI], None).await;

    let resp = harness
        .get(&format!(
            "{}?client_id={}&request_uri={}",
            auth_path("test"),
            client.client_id,
            REQUEST_URI.replace(':', "%3A").replace('/', "%2F")
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_request");
}

/// An unsigned object fetched by reference is rejected (signed-only posture:
/// `none` is never accepted for request objects).
#[tokio::test]
async fn unsigned_request_uri_object_rejected() {
    use base64::Engine;
    let served = Arc::new(std::sync::RwLock::new(String::new()));
    let (harness, _hits) = harness_serving(served.clone()).await;
    harness.create_realm("test").await;
    let client = client_with_request_uris(&harness, "test", &[REQUEST_URI], None).await;
    harness.create_user("test", "alice", PASSWORD).await;

    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        object_claims(&harness, "test", client.client_id.as_ref())
            .to_string()
            .as_bytes(),
    );
    *served.write().unwrap() = format!("{header}.{payload}.");

    let resp = harness
        .get(&format!(
            "{}?client_id={}&request_uri={}",
            auth_path("test"),
            client.client_id,
            REQUEST_URI.replace(':', "%3A").replace('/', "%2F")
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_request");
}
