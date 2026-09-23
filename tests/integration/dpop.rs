// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// DPoP (RFC 9449) integration tests.

//! DPoP (RFC 9449) integration tests (Issuerd-only).
//!
//! Covered: token-endpoint proof verification + `cnf.jkt` binding (password
//! and client-credentials grants), the `token_type: DPoP` response switch,
//! the htm/htu/iat/jti rejection matrix, userinfo sender-constraining
//! (`DPoP` scheme + `ath` + thumbprint match, Bearer downgrade rejected),
//! bound refresh-token enforcement + rotation slide, introspection
//! passthrough (RFC 9449 §6.1), and discovery advertisement.

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use base64::Engine as _;
use ring::signature::KeyPair as _;
use tower::ServiceExt as _;

use crate::harness::TestHarness;

fn token_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token")
}

fn userinfo_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/userinfo")
}

fn introspect_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token/introspect")
}

fn discovery_path(realm: &str) -> String {
    format!("/realms/{realm}/.well-known/openid-configuration")
}

fn token_htu(harness: &TestHarness, realm: &str) -> String {
    format!("{}/realms/{realm}/protocol/openid-connect/token", harness.base_url)
}

fn userinfo_htu(harness: &TestHarness, realm: &str) -> String {
    format!("{}/realms/{realm}/protocol/openid-connect/userinfo", harness.base_url)
}

async fn json_body(resp: Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Decode a JWT payload without verification (these tests inspect claims of
/// tokens the harness itself issued).
fn decode_payload(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// DPoP key + proof minting (hand-rolled compact JWS: the header must carry
// the `jwk` claim, which the server's CryptoProvider cannot produce)
// ---------------------------------------------------------------------------

struct DpopKey {
    pair: ring::signature::EcdsaKeyPair,
    jwk: serde_json::Value,
}

fn dpop_key() -> DpopKey {
    let rng = ring::rand::SystemRandom::new();
    let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        doc.as_ref(),
        &rng,
    )
    .unwrap();
    let public = pair.public_key().as_ref();
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let jwk = serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": b64(&public[1..33]), "y": b64(&public[33..65]),
    });
    DpopKey { pair, jwk }
}

/// Proof overrides; `Default` produces a valid token-endpoint POST proof.
struct ProofOpts {
    htm: String,
    htu: String,
    jti: String,
    iat: i64,
    ath: Option<String>,
    typ: String,
    nonce: Option<String>,
}

impl DpopKey {
    fn jkt(&self) -> String {
        issuerd_token::jwk_thumbprint(&self.jwk).unwrap()
    }

    fn proof(&self, opts: &ProofOpts) -> String {
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header = serde_json::json!({"alg": "ES256", "typ": opts.typ, "jwk": self.jwk});
        let mut claims = serde_json::json!({
            "jti": opts.jti,
            "htm": opts.htm,
            "htu": opts.htu,
            "iat": opts.iat,
        });
        if let Some(ref ath) = opts.ath {
            claims["ath"] = serde_json::json!(issuerd_token::access_token_hash(ath));
        }
        if let Some(ref nonce) = opts.nonce {
            claims["nonce"] = serde_json::json!(nonce);
        }
        let input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(&header).unwrap()),
            b64(&serde_json::to_vec(&claims).unwrap())
        );
        let rng = ring::rand::SystemRandom::new();
        let sig = self.pair.sign(&rng, input.as_bytes()).unwrap();
        format!("{input}.{}", b64(sig.as_ref()))
    }

    fn token_proof(&self, harness: &TestHarness, realm: &str) -> String {
        self.token_proof_with_nonce(harness, realm, None)
    }

    fn token_proof_with_nonce(
        &self,
        harness: &TestHarness,
        realm: &str,
        nonce: Option<&str>,
    ) -> String {
        self.proof(&ProofOpts {
            htm: "POST".to_string(),
            htu: token_htu(harness, realm),
            jti: issuerd_core::utils::generate_id(),
            iat: chrono::Utc::now().timestamp(),
            ath: None,
            typ: "dpop+jwt".to_string(),
            nonce: nonce.map(str::to_string),
        })
    }

    fn userinfo_proof(&self, harness: &TestHarness, realm: &str, method: &str, at: &str) -> String {
        self.userinfo_proof_with_nonce(harness, realm, method, at, None)
    }

    fn userinfo_proof_with_nonce(
        &self,
        harness: &TestHarness,
        realm: &str,
        method: &str,
        at: &str,
        nonce: Option<&str>,
    ) -> String {
        self.proof(&ProofOpts {
            htm: method.to_string(),
            htu: userinfo_htu(harness, realm),
            jti: issuerd_core::utils::generate_id(),
            iat: chrono::Utc::now().timestamp(),
            ath: Some(at.to_string()),
            typ: "dpop+jwt".to_string(),
            nonce: nonce.map(str::to_string),
        })
    }
}

// ---------------------------------------------------------------------------
// Request helpers (the harness helpers do not carry custom headers)
// ---------------------------------------------------------------------------

async fn post_token(
    harness: &TestHarness,
    realm: &str,
    params: &[(&str, &str)],
    proof: Option<&str>,
) -> Response {
    let body = serde_urlencoded::to_string(params).unwrap();
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(token_path(realm))
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(proof) = proof {
        builder = builder.header("dpop", proof);
    }
    let req = builder.body(Body::from(body)).unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

async fn userinfo_request(
    harness: &TestHarness,
    realm: &str,
    method: &str,
    authorization: Option<&str>,
    proof: Option<&str>,
) -> Response {
    let mut builder = axum::http::Request::builder().method(method).uri(userinfo_path(realm));
    if let Some(auth) = authorization {
        builder = builder.header("authorization", auth);
    }
    if let Some(proof) = proof {
        builder = builder.header("dpop", proof);
    }
    let req = builder.body(Body::empty()).unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

/// Realm + confidential client + user fixture.
struct Fixture {
    realm: String,
    client_id: String,
    client_secret: String,
    user_id: String,
}

async fn fixture(harness: &TestHarness) -> Fixture {
    let realm = format!("dpop-{}", issuerd_core::utils::generate_id());
    harness.create_realm(&realm).await;
    let client = harness.create_client(&realm, false).await;
    let user = harness.create_user(&realm, "alice", "password123").await;
    Fixture {
        realm,
        client_id: client.client_id.to_string(),
        client_secret: client.secret.unwrap(),
        user_id: user.id.to_string(),
    }
}

impl Fixture {
    fn password_form(&self) -> Vec<(&str, &str)> {
        vec![
            ("grant_type", "password"),
            ("username", "alice"),
            ("password", "password123"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", "openid"),
        ]
    }

    fn refresh_form<'a>(&'a self, refresh_token: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ]
    }
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn password_grant_with_proof_binds_tokens() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();

    let proof = key.token_proof(&harness, &fx.realm);
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;

    // RFC 9449 §4.2: the response signals the DPoP token type.
    assert_eq!(json["token_type"], "DPoP");

    let access = decode_payload(json["access_token"].as_str().unwrap());
    assert_eq!(access["cnf"]["jkt"], key.jkt().as_str());
    let refresh = decode_payload(json["refresh_token"].as_str().unwrap());
    assert_eq!(refresh["cnf"]["jkt"], key.jkt().as_str());
}

#[tokio::test]
async fn password_grant_without_proof_stays_bearer() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;

    let resp = post_token(&harness, &fx.realm, &fx.password_form(), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;

    assert_eq!(json["token_type"], "Bearer");
    let access = decode_payload(json["access_token"].as_str().unwrap());
    assert!(access.get("cnf").is_none());
    let refresh = decode_payload(json["refresh_token"].as_str().unwrap());
    assert!(refresh.get("cnf").is_none());
}

#[tokio::test]
async fn client_credentials_with_proof_binds_token() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();

    let form = vec![
        ("grant_type", "client_credentials"),
        ("client_id", fx.client_id.as_str()),
        ("client_secret", fx.client_secret.as_str()),
    ];
    let proof = key.token_proof(&harness, &fx.realm);
    let resp = post_token(&harness, &fx.realm, &form, Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;

    assert_eq!(json["token_type"], "DPoP");
    let access = decode_payload(json["access_token"].as_str().unwrap());
    assert_eq!(access["cnf"]["jkt"], key.jkt().as_str());
}

#[tokio::test]
async fn proof_rejection_matrix() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();
    let now = chrono::Utc::now().timestamp();

    let cases = vec![
        // htm mismatch
        ProofOpts {
            htm: "GET".to_string(),
            htu: token_htu(&harness, &fx.realm),
            jti: issuerd_core::utils::generate_id(),
            iat: now,
            ath: None,
            typ: "dpop+jwt".to_string(),
            nonce: None,
        },
        // htu mismatch (userinfo URL against the token endpoint)
        ProofOpts {
            htm: "POST".to_string(),
            htu: userinfo_htu(&harness, &fx.realm),
            jti: issuerd_core::utils::generate_id(),
            iat: now,
            ath: None,
            typ: "dpop+jwt".to_string(),
            nonce: None,
        },
        // stale iat
        ProofOpts {
            htm: "POST".to_string(),
            htu: token_htu(&harness, &fx.realm),
            jti: issuerd_core::utils::generate_id(),
            iat: now - 600,
            ath: None,
            typ: "dpop+jwt".to_string(),
            nonce: None,
        },
        // wrong typ
        ProofOpts {
            htm: "POST".to_string(),
            htu: token_htu(&harness, &fx.realm),
            jti: issuerd_core::utils::generate_id(),
            iat: now,
            ath: None,
            typ: "JWT".to_string(),
            nonce: None,
        },
    ];

    for opts in cases {
        let proof = key.proof(&opts);
        let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "case: htm={} htu={}",
            opts.htm,
            opts.htu
        );
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    // Malformed (not a JWT).
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some("garbage")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn proof_jti_replay_rejected() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();

    let proof = key.token_proof(&harness, &fx.realm);
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // The very same proof again: jti replay.
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_dpop_proof");
}

// ---------------------------------------------------------------------------
// Userinfo (resource-side proof, RFC 9449 §7.1)
// ---------------------------------------------------------------------------

/// Issue a DPoP-bound token pair for the fixture via the password grant.
async fn bound_tokens(harness: &TestHarness, fx: &Fixture, key: &DpopKey) -> (String, String) {
    let proof = key.token_proof(harness, &fx.realm);
    let resp = post_token(harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    (
        json["access_token"].as_str().unwrap().to_string(),
        json["refresh_token"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn userinfo_dpop_scheme_with_valid_proof() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();
    let (access, _) = bound_tokens(&harness, &fx, &key).await;

    // GET
    let proof = key.userinfo_proof(&harness, &fx.realm, "GET", &access);
    let resp =
        userinfo_request(&harness, &fx.realm, "GET", Some(&format!("DPoP {access}")), Some(&proof))
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["sub"], fx.user_id.as_str());

    // POST (htm checked against the actual method)
    let proof = key.userinfo_proof(&harness, &fx.realm, "POST", &access);
    let resp = userinfo_request(
        &harness,
        &fx.realm,
        "POST",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn userinfo_rejects_bearer_presentation_of_bound_token() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();
    let (access, _) = bound_tokens(&harness, &fx, &key).await;

    // Bound token as plain Bearer: rejected, with the DPoP challenge header.
    let resp =
        userinfo_request(&harness, &fx.realm, "GET", Some(&format!("Bearer {access}")), None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp.headers().get("www-authenticate").unwrap().to_str().unwrap().to_string();
    assert!(www.starts_with("DPoP "), "expected DPoP challenge, got: {www}");
    assert_eq!(json_body(resp).await["error"], "invalid_token");
}

#[tokio::test]
async fn userinfo_dpop_rejection_matrix() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();
    let (access, _) = bound_tokens(&harness, &fx, &key).await;
    let auth = format!("DPoP {access}");

    // DPoP scheme without a proof header.
    let resp = userinfo_request(&harness, &fx.realm, "GET", Some(&auth), None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(resp).await["error"], "invalid_dpop_proof");

    // ath computed over a different token.
    let proof = key.userinfo_proof(&harness, &fx.realm, "GET", "some-other-token");
    let resp = userinfo_request(&harness, &fx.realm, "GET", Some(&auth), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(resp).await["error"], "invalid_dpop_proof");

    // Proof from a DIFFERENT key (valid proof, wrong thumbprint).
    let other = dpop_key();
    let proof = other.userinfo_proof(&harness, &fx.realm, "GET", &access);
    let resp = userinfo_request(&harness, &fx.realm, "GET", Some(&auth), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(resp).await["error"], "invalid_token");

    // Replayed jti.
    let proof = key.userinfo_proof(&harness, &fx.realm, "GET", &access);
    let resp = userinfo_request(&harness, &fx.realm, "GET", Some(&auth), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = userinfo_request(&harness, &fx.realm, "GET", Some(&auth), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(resp).await["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn unbound_token_rejects_dpop_scheme() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();

    // Unbound (Bearer) token.
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let access = json_body(resp).await["access_token"].as_str().unwrap().to_string();

    // Bearer presentation still works.
    let resp =
        userinfo_request(&harness, &fx.realm, "GET", Some(&format!("Bearer {access}")), None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // DPoP scheme on an unbound token is rejected (RFC 9449 §7.1: the proof
    // is only meaningful for bound tokens).
    let proof = key.userinfo_proof(&harness, &fx.realm, "GET", &access);
    let resp =
        userinfo_request(&harness, &fx.realm, "GET", Some(&format!("DPoP {access}")), Some(&proof))
            .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(resp).await["error"], "invalid_token");
}

// ---------------------------------------------------------------------------
// Refresh binding (RFC 9449 §5.1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bound_refresh_requires_matching_proof_and_slides() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();
    let (access, refresh) = bound_tokens(&harness, &fx, &key).await;
    drop(access);

    // Without a proof: invalid_grant.
    let resp = post_token(&harness, &fx.realm, &fx.refresh_form(&refresh), None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_grant");

    // Proof from a different key: invalid_grant (and the token is not burned).
    let other = dpop_key();
    let proof = other.token_proof(&harness, &fx.realm);
    let resp = post_token(&harness, &fx.realm, &fx.refresh_form(&refresh), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_grant");

    // The matching key: rotation succeeds and the binding slides onto the
    // new tokens.
    let proof = key.token_proof(&harness, &fx.realm);
    let resp = post_token(&harness, &fx.realm, &fx.refresh_form(&refresh), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["token_type"], "DPoP");
    let new_access = decode_payload(json["access_token"].as_str().unwrap());
    assert_eq!(new_access["cnf"]["jkt"], key.jkt().as_str());
    let new_refresh_token = json["refresh_token"].as_str().unwrap().to_string();
    let new_refresh = decode_payload(&new_refresh_token);
    assert_eq!(new_refresh["cnf"]["jkt"], key.jkt().as_str());

    // Second rotation with the same key still works (the binding slid).
    let proof = key.token_proof(&harness, &fx.realm);
    let resp =
        post_token(&harness, &fx.realm, &fx.refresh_form(&new_refresh_token), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unbound_refresh_unaffected() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;

    let resp = post_token(&harness, &fx.realm, &fx.password_form(), None).await;
    let json = json_body(resp).await;
    let refresh = json["refresh_token"].as_str().unwrap().to_string();

    let resp = post_token(&harness, &fx.realm, &fx.refresh_form(&refresh), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["token_type"], "Bearer");
}

// ---------------------------------------------------------------------------
// Introspection + discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn introspection_reports_dpop_binding() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();
    let (access, _) = bound_tokens(&harness, &fx, &key).await;

    let form = vec![
        ("token", access.as_str()),
        ("client_id", fx.client_id.as_str()),
        ("client_secret", fx.client_secret.as_str()),
    ];
    let resp = harness.post_form(&introspect_path(&fx.realm), &form).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;

    // RFC 9449 §6.1: introspection discloses the binding.
    assert_eq!(json["active"], true);
    assert_eq!(json["token_type"], "DPoP");
    assert_eq!(json["cnf"]["jkt"], key.jkt().as_str());
}

#[tokio::test]
async fn discovery_advertises_dpop_algs() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;

    let resp = harness.get(&discovery_path(&fx.realm)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(
        json["dpop_signing_alg_values_supported"],
        serde_json::json!(["RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"])
    );
}

// ---------------------------------------------------------------------------
// Server-provided nonces ([dpop.nonce], RFC 9449 §8/§9)
// ---------------------------------------------------------------------------

/// Harness variant with a specific nonce mode (`TestHarness::new` runs the
/// default `disabled`).
async fn harness_with_nonce_mode(mode: issuerd_server::config::DpopNonceMode) -> TestHarness {
    let mut config = issuerd_server::config::ServerConfig::default();
    config.dpop.nonce.mode = mode;
    let state = std::sync::Arc::new(
        issuerd_server::state::ServerState::from_config(&config).await.unwrap(),
    );
    TestHarness::with_state(state)
}

/// The `DPoP-Nonce` response header value, if present.
fn response_nonce(resp: &Response) -> Option<String> {
    resp.headers().get("dpop-nonce").map(|v| v.to_str().unwrap().to_string())
}

#[tokio::test]
async fn disabled_mode_never_sends_a_nonce_header() {
    let harness = TestHarness::new().await;
    let fx = fixture(&harness).await;
    let key = dpop_key();

    // Proof without a nonce claim: current behavior, no header.
    let proof = key.token_proof(&harness, &fx.realm);
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(response_nonce(&resp).is_none());
    assert_eq!(json_body(resp).await["token_type"], "DPoP");

    // A nonce claim is ignored (not verified, no header issued).
    let proof = key.token_proof_with_nonce(&harness, &fx.realm, Some("made-up"));
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(response_nonce(&resp).is_none());

    // Plain Bearer: no header either.
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(response_nonce(&resp).is_none());
}

#[tokio::test]
async fn required_mode_token_endpoint_nonce_flow() {
    let harness = harness_with_nonce_mode(issuerd_server::config::DpopNonceMode::Required).await;
    let fx = fixture(&harness).await;
    let key = dpop_key();

    // Plain Bearer requests are untouched (no proof → no nonce semantics).
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(response_nonce(&resp).is_none());

    // A well-formed proof with a fresh iat/jti but no server nonce is
    // rejected: 400 + `use_dpop_nonce` + a fresh nonce in the header.
    let proof = key.token_proof(&harness, &fx.realm);
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let nonce = response_nonce(&resp).expect("challenge carries a fresh nonce");
    let json = json_body(resp).await;
    assert_eq!(json["error"], "use_dpop_nonce");

    // Replaying the exact captured proof changes nothing (the nonce gate
    // fires before the jti burn, so the jti is still unused — it is the
    // missing nonce that dooms it).
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "use_dpop_nonce");

    // A made-up nonce never validates.
    let forged = key.token_proof_with_nonce(&harness, &fx.realm, Some("attacker-guess"));
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&forged)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "use_dpop_nonce");

    // Retry echoing the server-issued nonce: success, the token is bound,
    // and the response issues the NEXT nonce.
    let proof = key.token_proof_with_nonce(&harness, &fx.realm, Some(&nonce));
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let next = response_nonce(&resp).expect("success issues the next nonce");
    assert_ne!(next, nonce);
    let json = json_body(resp).await;
    assert_eq!(json["token_type"], "DPoP");
    let access = decode_payload(json["access_token"].as_str().unwrap());
    assert_eq!(access["cnf"]["jkt"], key.jkt().as_str());

    // The consumed nonce is burned (single-use): a fresh proof reusing it is
    // challenged again.
    let proof = key.token_proof_with_nonce(&harness, &fx.realm, Some(&nonce));
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(response_nonce(&resp).is_some());
    assert_eq!(json_body(resp).await["error"], "use_dpop_nonce");
}

#[tokio::test]
async fn supported_mode_accepts_absent_nonce_and_challenges_unknown() {
    let harness = harness_with_nonce_mode(issuerd_server::config::DpopNonceMode::Supported).await;
    let fx = fixture(&harness).await;
    let key = dpop_key();

    // Absence is not an error: success, and a fresh nonce rides the header.
    let proof = key.token_proof(&harness, &fx.realm);
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let nonce = response_nonce(&resp).expect("supported mode always issues");
    let json = json_body(resp).await;
    let access = json["access_token"].as_str().unwrap().to_string();

    // Nonces are realm-scoped: the token-endpoint nonce is equally valid at
    // userinfo (Issuerd is both the authorization and the resource server).
    let proof = key.userinfo_proof_with_nonce(&harness, &fx.realm, "GET", &access, Some(&nonce));
    let resp =
        userinfo_request(&harness, &fx.realm, "GET", Some(&format!("DPoP {access}")), Some(&proof))
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(response_nonce(&resp).is_some());

    // A presented nonce must still be live: unknown values get the RFC
    // challenge (401 + WWW-Authenticate at the resource endpoint).
    let proof = key.userinfo_proof_with_nonce(&harness, &fx.realm, "GET", &access, Some("stale"));
    let resp =
        userinfo_request(&harness, &fx.realm, "GET", Some(&format!("DPoP {access}")), Some(&proof))
            .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(response_nonce(&resp).is_some());
    let www = resp.headers().get("www-authenticate").unwrap().to_str().unwrap().to_string();
    assert!(www.starts_with("DPoP error=\"use_dpop_nonce\""), "got: {www}");
    assert_eq!(json_body(resp).await["error"], "use_dpop_nonce");

    // Plain Bearer requests carry no header in this mode either.
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(response_nonce(&resp).is_none());
}

#[tokio::test]
async fn required_mode_userinfo_nonce_flow() {
    let harness = harness_with_nonce_mode(issuerd_server::config::DpopNonceMode::Required).await;
    let fx = fixture(&harness).await;
    let key = dpop_key();

    // Mint a bound token the required-mode way: challenged, then retried
    // with the server nonce.
    let proof = key.token_proof(&harness, &fx.realm);
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let nonce = response_nonce(&resp).unwrap();
    let proof = key.token_proof_with_nonce(&harness, &fx.realm, Some(&nonce));
    let resp = post_token(&harness, &fx.realm, &fx.password_form(), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let access = json["access_token"].as_str().unwrap().to_string();
    let auth = format!("DPoP {access}");

    // userinfo proof (correct ath/jti/iat) without a nonce: 401 +
    // `use_dpop_nonce` challenge with a fresh nonce.
    let proof = key.userinfo_proof(&harness, &fx.realm, "GET", &access);
    let resp = userinfo_request(&harness, &fx.realm, "GET", Some(&auth), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge = response_nonce(&resp).expect("401 challenge carries a fresh nonce");
    let www = resp.headers().get("www-authenticate").unwrap().to_str().unwrap().to_string();
    assert!(www.starts_with("DPoP error=\"use_dpop_nonce\""), "got: {www}");
    assert_eq!(json_body(resp).await["error"], "use_dpop_nonce");

    // Retry with the server nonce: success.
    let proof =
        key.userinfo_proof_with_nonce(&harness, &fx.realm, "GET", &access, Some(&challenge));
    let resp = userinfo_request(&harness, &fx.realm, "GET", Some(&auth), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(response_nonce(&resp).is_some());
    assert_eq!(json_body(resp).await["sub"], fx.user_id.as_str());

    // Replaying the same nonce (fresh jti, valid ath) is challenged: the
    // nonce is single-use.
    let proof =
        key.userinfo_proof_with_nonce(&harness, &fx.realm, "GET", &access, Some(&challenge));
    let resp = userinfo_request(&harness, &fx.realm, "GET", Some(&auth), Some(&proof)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(resp).await["error"], "use_dpop_nonce");
}
