// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// JWT client authentication (private_key_jwt / client_secret_jwt) integration tests.

//! JWT client authentication (`private_key_jwt`,
//! `client_secret_jwt`; RFC 7523 §2.2 / OIDC Core §9) integration tests
//! (Issuerd-only).
//!
//! Covered: valid assertions at all client-authenticated endpoints (token,
//! PAR, introspect, revoke), the rejection matrix (bad signature, wrong
//! iss/sub, wrong/missing aud, expired exp, replayed jti, both-methods),
//! configured-method enforcement, the JWKS-URL fetch path with a
//! refetch-on-rotation retry against a loopback HTTP server, and discovery
//! advertisement.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::http::StatusCode;
use issuerd_core::{ClientAuthenticatorType, CryptoProvider};

use crate::harness::TestHarness;

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

fn token_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token")
}

fn par_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/ext/par")
}

fn introspect_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token/introspect")
}

fn revoke_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/revoke")
}

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ---------------------------------------------------------------------------
// Assertion minting
// ---------------------------------------------------------------------------

/// Claims accepted by the harness issuer (`harness.base_url`) for `realm`
/// when authenticating `client_id` at the token endpoint.
fn assertion_claims(harness: &TestHarness, realm: &str, client_id: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": format!("{}/realms/{realm}/protocol/openid-connect/token", harness.base_url),
        "exp": now() + 240,
        "iat": now(),
        "jti": issuerd_core::utils::generate_id(),
    })
}

fn sign_hs256(claims: &serde_json::Value, secret: &str) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

/// An RSA signing key + its public JWKS, for `private_key_jwt` tests.
struct RsaKey {
    crypto: issuerd_token::RingCryptoProvider,
    jwks: serde_json::Value,
    kid: String,
}

async fn rsa_key() -> RsaKey {
    let crypto = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
        default_alg: issuerd_core::Algorithm::Rs256,
        rsa_key_size: 2048,
    })
    .unwrap();
    let jwks = serde_json::to_value(crypto.get_public_keys().await.unwrap()).unwrap();
    let kid = jwks["keys"][0]["kid"].as_str().unwrap().to_string();
    RsaKey { crypto, jwks, kid }
}

impl RsaKey {
    async fn sign(&self, claims: &serde_json::Value) -> String {
        self.crypto
            .sign(
                &serde_json::to_string(claims).unwrap(),
                issuerd_core::Algorithm::Rs256,
                &issuerd_core::KeyId::new(self.kid.clone()).unwrap(),
            )
            .await
            .unwrap()
    }
}

// ---------------------------------------------------------------------------
// Client setup
// ---------------------------------------------------------------------------

/// Create a confidential client pinned to `auth_type`, with optional extra
/// attributes (JWKS config), persisted back to storage.
async fn create_jwt_client(
    harness: &TestHarness,
    realm: &str,
    auth_type: ClientAuthenticatorType,
    attributes: &[(&str, &str)],
) -> issuerd_core::Client {
    let mut client = harness.create_client(realm, false).await;
    client.client_authenticator_type = auth_type;
    for (k, v) in attributes {
        client.attributes.insert((*k).to_string(), (*v).to_string());
    }
    harness
        .storage
        .update_client(&issuerd_core::RealmId::new(realm).unwrap(), &client)
        .await
        .unwrap();
    client
}

/// Form params authenticating `client` with the given assertion.
fn assertion_form<'a>(client_id: &'a str, assertion: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("client_id", client_id),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion),
    ]
}

/// POST a client-credentials grant authenticated by the assertion.
async fn cc_grant_with_assertion(
    harness: &TestHarness,
    realm: &str,
    client_id: &str,
    assertion: &str,
) -> axum::response::Response {
    let mut params = vec![("grant_type", "client_credentials"), ("scope", "openid")];
    params.extend(assertion_form(client_id, assertion));
    harness.post_form(&token_path(realm), &params).await
}

// ---------------------------------------------------------------------------
// Happy paths — every client-authenticated endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_secret_jwt_accepted_at_token_endpoint() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-secret").await;
    let client =
        create_jwt_client(&harness, "jwt-ca-secret", ClientAuthenticatorType::ClientSecretJwt, &[])
            .await;

    let claims = assertion_claims(&harness, "jwt-ca-secret", client.client_id.as_ref());
    let assertion = sign_hs256(&claims, client.secret.as_deref().unwrap());
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-secret", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn private_key_jwt_inline_jwks_accepted_at_token_endpoint() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-inline").await;
    let key = rsa_key().await;
    let jwks_string = serde_json::to_string(&key.jwks).unwrap();
    let client = create_jwt_client(
        &harness,
        "jwt-ca-inline",
        ClientAuthenticatorType::ClientJwt,
        &[("use.jwks.string", "true"), ("jwks.string", &jwks_string)],
    )
    .await;

    let claims = assertion_claims(&harness, "jwt-ca-inline", client.client_id.as_ref());
    let assertion = key.sign(&claims).await;
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-inline", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn private_key_jwt_accepted_at_par_endpoint() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-par").await;
    let key = rsa_key().await;
    let jwks_string = serde_json::to_string(&key.jwks).unwrap();
    let client = create_jwt_client(
        &harness,
        "jwt-ca-par",
        ClientAuthenticatorType::ClientJwt,
        &[("use.jwks.string", "true"), ("jwks.string", &jwks_string)],
    )
    .await;

    let claims = assertion_claims(&harness, "jwt-ca-par", client.client_id.as_ref());
    let assertion = key.sign(&claims).await;
    let mut params = vec![
        ("response_type", "code"),
        ("redirect_uri", "http://localhost:8080/cb"),
        ("scope", "openid"),
    ];
    params.extend(assertion_form(client.client_id.as_ref(), &assertion));
    let resp = harness.post_form(&par_path("jwt-ca-par"), &params).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert!(json["request_uri"]
        .as_str()
        .unwrap()
        .starts_with("urn:ietf:params:oauth:request_uri:"));
}

#[tokio::test]
async fn client_secret_jwt_accepted_at_introspect_and_revoke() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-intro").await;
    let client =
        create_jwt_client(&harness, "jwt-ca-intro", ClientAuthenticatorType::ClientSecretJwt, &[])
            .await;
    let secret = client.secret.as_deref().unwrap();

    // Get a token first (also via assertion auth).
    let claims = assertion_claims(&harness, "jwt-ca-intro", client.client_id.as_ref());
    let assertion = sign_hs256(&claims, secret);
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-intro", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let access_token = json_body(resp).await["access_token"].as_str().unwrap().to_string();

    // Introspect: active.
    let claims = assertion_claims(&harness, "jwt-ca-intro", client.client_id.as_ref());
    let assertion = sign_hs256(&claims, secret);
    let mut params = vec![("token", access_token.as_str())];
    params.extend(assertion_form(client.client_id.as_ref(), &assertion));
    let resp = harness.post_form(&introspect_path("jwt-ca-intro"), &params).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["active"], true);

    // Revoke with a fresh assertion.
    let claims = assertion_claims(&harness, "jwt-ca-intro", client.client_id.as_ref());
    let assertion = sign_hs256(&claims, secret);
    let mut params = vec![("token", access_token.as_str())];
    params.extend(assertion_form(client.client_id.as_ref(), &assertion));
    let resp = harness.post_form(&revoke_path("jwt-ca-intro"), &params).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Introspect again with a fresh assertion: now inactive.
    let claims = assertion_claims(&harness, "jwt-ca-intro", client.client_id.as_ref());
    let assertion = sign_hs256(&claims, secret);
    let mut params = vec![("token", access_token.as_str())];
    params.extend(assertion_form(client.client_id.as_ref(), &assertion));
    let resp = harness.post_form(&introspect_path("jwt-ca-intro"), &params).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["active"], false);
}

// ---------------------------------------------------------------------------
// Rejection matrix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bad_signature_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-badsig").await;
    let client =
        create_jwt_client(&harness, "jwt-ca-badsig", ClientAuthenticatorType::ClientSecretJwt, &[])
            .await;

    let claims = assertion_claims(&harness, "jwt-ca-badsig", client.client_id.as_ref());
    let assertion = sign_hs256(&claims, "not-the-client-secret");
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-badsig", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_client");
}

#[tokio::test]
async fn wrong_iss_or_sub_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-isssub").await;
    let client =
        create_jwt_client(&harness, "jwt-ca-isssub", ClientAuthenticatorType::ClientSecretJwt, &[])
            .await;
    let secret = client.secret.as_deref().unwrap();

    for (field, value) in [("iss", "other-client"), ("sub", "other-client")] {
        let mut claims = assertion_claims(&harness, "jwt-ca-isssub", client.client_id.as_ref());
        claims[field] = serde_json::json!(value);
        let assertion = sign_hs256(&claims, secret);
        let resp = cc_grant_with_assertion(
            &harness,
            "jwt-ca-isssub",
            client.client_id.as_ref(),
            &assertion,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{field} mismatch must reject");
    }
}

#[tokio::test]
async fn wrong_or_missing_audience_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-aud").await;
    let client =
        create_jwt_client(&harness, "jwt-ca-aud", ClientAuthenticatorType::ClientSecretJwt, &[])
            .await;
    let secret = client.secret.as_deref().unwrap();

    // aud names none of the accepted values.
    let mut claims = assertion_claims(&harness, "jwt-ca-aud", client.client_id.as_ref());
    claims["aud"] = serde_json::json!("https://attacker.example.com/token");
    let assertion = sign_hs256(&claims, secret);
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-aud", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // aud missing entirely.
    let mut claims = assertion_claims(&harness, "jwt-ca-aud", client.client_id.as_ref());
    claims.as_object_mut().unwrap().remove("aud");
    let assertion = sign_hs256(&claims, secret);
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-aud", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn expired_assertion_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-exp").await;
    let client =
        create_jwt_client(&harness, "jwt-ca-exp", ClientAuthenticatorType::ClientSecretJwt, &[])
            .await;

    let mut claims = assertion_claims(&harness, "jwt-ca-exp", client.client_id.as_ref());
    claims["exp"] = serde_json::json!(now() - 3600);
    claims["iat"] = serde_json::json!(now() - 3700);
    let assertion = sign_hs256(&claims, client.secret.as_deref().unwrap());
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-exp", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn replayed_jti_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-replay").await;
    let client =
        create_jwt_client(&harness, "jwt-ca-replay", ClientAuthenticatorType::ClientSecretJwt, &[])
            .await;

    let claims = assertion_claims(&harness, "jwt-ca-replay", client.client_id.as_ref());
    let assertion = sign_hs256(&claims, client.secret.as_deref().unwrap());

    // First use succeeds.
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-replay", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    // Replaying the identical assertion (same jti) fails.
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-replay", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_client");
}

#[tokio::test]
async fn secret_and_assertion_together_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-both").await;
    let client =
        create_jwt_client(&harness, "jwt-ca-both", ClientAuthenticatorType::ClientSecretJwt, &[])
            .await;
    let secret = client.secret.as_deref().unwrap();

    let claims = assertion_claims(&harness, "jwt-ca-both", client.client_id.as_ref());
    let assertion = sign_hs256(&claims, secret);
    let mut params = vec![
        ("grant_type", "client_credentials"),
        ("scope", "openid"),
        ("client_id", client.client_id.as_ref()),
        ("client_secret", secret),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ];
    let resp = harness.post_form(&token_path("jwt-ca-both"), &params).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Wrong assertion type is rejected as well.
    let claims = assertion_claims(&harness, "jwt-ca-both", client.client_id.as_ref());
    let assertion = sign_hs256(&claims, secret);
    params = vec![
        ("grant_type", "client_credentials"),
        ("scope", "openid"),
        ("client_id", client.client_id.as_ref()),
        ("client_assertion_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("client_assertion", assertion.as_str()),
    ];
    let resp = harness.post_form(&token_path("jwt-ca-both"), &params).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Configured-method enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn configured_method_is_enforced() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-pinned").await;
    let key = rsa_key().await;

    // client-jwt pinned: a correct secret is NOT accepted.
    let jwks_string = serde_json::to_string(&key.jwks).unwrap();
    let pkj_client = create_jwt_client(
        &harness,
        "jwt-ca-pinned",
        ClientAuthenticatorType::ClientJwt,
        &[("use.jwks.string", "true"), ("jwks.string", &jwks_string)],
    )
    .await;
    let resp = harness
        .post_form(
            &token_path("jwt-ca-pinned"),
            &[
                ("grant_type", "client_credentials"),
                ("scope", "openid"),
                ("client_id", pkj_client.client_id.as_ref()),
                ("client_secret", pkj_client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "secret must not satisfy client-jwt");

    // client-jwt pinned: an HMAC assertion is NOT accepted (asymmetric only).
    let claims = assertion_claims(&harness, "jwt-ca-pinned", pkj_client.client_id.as_ref());
    let assertion = sign_hs256(&claims, pkj_client.secret.as_deref().unwrap());
    let resp = cc_grant_with_assertion(
        &harness,
        "jwt-ca-pinned",
        pkj_client.client_id.as_ref(),
        &assertion,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "HMAC must not satisfy client-jwt");

    // client-secret-jwt pinned: an RS256 assertion is NOT accepted.
    let hs_client =
        create_jwt_client(&harness, "jwt-ca-pinned", ClientAuthenticatorType::ClientSecretJwt, &[])
            .await;
    let claims = assertion_claims(&harness, "jwt-ca-pinned", hs_client.client_id.as_ref());
    let assertion = key.sign(&claims).await;
    let resp = cc_grant_with_assertion(
        &harness,
        "jwt-ca-pinned",
        hs_client.client_id.as_ref(),
        &assertion,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "RS256 must not satisfy client-secret-jwt"
    );

    // Default client-secret client: an assertion is NOT accepted.
    let plain = harness.create_client("jwt-ca-pinned", false).await;
    let claims = assertion_claims(&harness, "jwt-ca-pinned", plain.client_id.as_ref());
    let assertion = sign_hs256(&claims, plain.secret.as_deref().unwrap());
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-pinned", plain.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "assertion must not satisfy client-secret"
    );
}

// ---------------------------------------------------------------------------
// JWKS URL fetch + refetch on key rotation
// ---------------------------------------------------------------------------

/// A loopback JWKS HTTP server whose served document can be swapped,
/// counting requests.
struct LoopbackJwks {
    url: String,
    current: Arc<tokio::sync::RwLock<serde_json::Value>>,
    hits: Arc<AtomicUsize>,
}

async fn start_loopback_jwks(initial: serde_json::Value) -> LoopbackJwks {
    use axum::routing::get;
    let current = Arc::new(tokio::sync::RwLock::new(initial));
    let hits = Arc::new(AtomicUsize::new(0));
    let cur = current.clone();
    let hit = hits.clone();
    let app = axum::Router::new().route(
        "/jwks",
        get(move || {
            let cur = cur.clone();
            let hit = hit.clone();
            async move {
                hit.fetch_add(1, Ordering::SeqCst);
                axum::Json(cur.read().await.clone())
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    LoopbackJwks {
        url: format!("http://{addr}/jwks"),
        current,
        hits,
    }
}

#[tokio::test]
async fn private_key_jwt_jwks_url_refetches_on_rotation() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-url").await;

    let client_key = rsa_key().await;
    let stale_key = rsa_key().await;
    let server = start_loopback_jwks(stale_key.jwks.clone()).await;

    let client = create_jwt_client(
        &harness,
        "jwt-ca-url",
        ClientAuthenticatorType::ClientJwt,
        &[("use.jwks.url", "true"), ("jwks.url", &server.url)],
    )
    .await;

    // Attempt 1: the JWKS endpoint serves the stale key — the assertion's
    // kid is unknown even after the refetch retry → rejected.
    let claims = assertion_claims(&harness, "jwt-ca-url", client.client_id.as_ref());
    let assertion = client_key.sign(&claims).await;
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-url", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(server.hits.load(Ordering::SeqCst), 2, "initial fetch + one refetch retry");

    // The kid-miss refetch armed the 60 s per-client cooldown (2026-09 DoS
    // hardening: an unauthenticated unknown-kid flood must not force an
    // outbound fetch per request). Expire the marker to simulate the
    // post-cooldown retry.
    harness
        .cache
        .delete(&format!("client_jwks_kid_miss:jwt-ca-url:{}", client.id))
        .await
        .unwrap();

    // The client "rotates" keys: the JWKS endpoint now serves the key that
    // signed the assertions. The cached stale set still does not cover the
    // kid, so the server refetches once and then validates successfully.
    *server.current.write().await = client_key.jwks.clone();
    let claims = assertion_claims(&harness, "jwt-ca-url", client.client_id.as_ref());
    let assertion = client_key.sign(&claims).await;
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-url", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(server.hits.load(Ordering::SeqCst), 3, "one more refetch after the kid-miss");

    // The fresh JWKS is cached now: no further fetches.
    let claims = assertion_claims(&harness, "jwt-ca-url", client.client_id.as_ref());
    let assertion = client_key.sign(&claims).await;
    let resp =
        cc_grant_with_assertion(&harness, "jwt-ca-url", client.client_id.as_ref(), &assertion)
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        server.hits.load(Ordering::SeqCst),
        3,
        "cached JWKS serves subsequent validations"
    );
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_advertises_jwt_client_auth() {
    let harness = TestHarness::new().await;
    harness.create_realm("jwt-ca-disc").await;
    let resp = harness.get("/realms/jwt-ca-disc/.well-known/openid-configuration").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;

    let methods = json["token_endpoint_auth_methods_supported"].as_array().unwrap();
    for method in [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
    ] {
        assert!(methods.iter().any(|m| m == method), "missing {method}");
    }
    let algs = json["token_endpoint_auth_signing_alg_values_supported"].as_array().unwrap();
    for alg in ["RS256", "ES256", "EdDSA", "HS256", "HS384", "HS512"] {
        assert!(algs.iter().any(|a| a == alg), "missing {alg}");
    }
}
