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
        self.proof(&ProofOpts {
            htm: "POST".to_string(),
            htu: token_htu(harness, realm),
            jti: issuerd_core::utils::generate_id(),
            iat: chrono::Utc::now().timestamp(),
            ath: None,
            typ: "dpop+jwt".to_string(),
        })
    }

    fn userinfo_proof(&self, harness: &TestHarness, realm: &str, method: &str, at: &str) -> String {
        self.proof(&ProofOpts {
            htm: method.to_string(),
            htu: userinfo_htu(harness, realm),
            jti: issuerd_core::utils::generate_id(),
            iat: chrono::Utc::now().timestamp(),
            ath: Some(at.to_string()),
            typ: "dpop+jwt".to_string(),
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
        },
        // htu mismatch (userinfo URL against the token endpoint)
        ProofOpts {
            htm: "POST".to_string(),
            htu: userinfo_htu(&harness, &fx.realm),
            jti: issuerd_core::utils::generate_id(),
            iat: now,
            ath: None,
            typ: "dpop+jwt".to_string(),
        },
        // stale iat
        ProofOpts {
            htm: "POST".to_string(),
            htu: token_htu(&harness, &fx.realm),
            jti: issuerd_core::utils::generate_id(),
            iat: now - 600,
            ath: None,
            typ: "dpop+jwt".to_string(),
        },
        // wrong typ
        ProofOpts {
            htm: "POST".to_string(),
            htu: token_htu(&harness, &fx.realm),
            jti: issuerd_core::utils::generate_id(),
            iat: now,
            ath: None,
            typ: "JWT".to_string(),
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
