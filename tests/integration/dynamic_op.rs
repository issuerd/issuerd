// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Dynamic-OP feature set integration tests.

//! Dynamic-OP feature integration tests (Issuerd-only).
//!
//! Covered: the per-client `id_token_signed_response_alg` override (RS256
//! pinning against the realm key set, a pinned algorithm with no live key
//! failing issuance loudly, the realm/server default otherwise), signed
//! userinfo (`userinfo_signed_response_alg`, OIDC Core §5.3.2 —
//! `application/jwt` body, verifiable against the realm JWKS), discovery
//! advertisement of the userinfo signing algorithms, and pairwise
//! `sector_identifier_uri` validation through dynamic client registration
//! (the sector document is fetched at registration; the issued `sub`
//! matches the pairwise derivation).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::http::StatusCode;

use crate::harness::TestHarness;
use issuerd_server::state::ServerState;

const PASSWORD: &str = "Password123!";

/// Extract a JSON body from a response.
async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Create a confidential client carrying the given attributes, persisted.
async fn client_with_attributes(
    harness: &TestHarness,
    realm: &str,
    attributes: &[(&str, &str)],
) -> issuerd_core::Client {
    let mut client = harness.create_client(realm, false).await;
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

/// Verify a realm-signed JWT against the realm's live JWKS and return its
/// claims (audience-checked).
async fn verify_realm_jwt(
    harness: &TestHarness,
    realm: &str,
    audience: &str,
    token: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let resp = harness.get(&format!("/realms/{realm}/protocol/openid-connect/certs")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let jwks = json_body(resp).await;

    let header = jsonwebtoken::decode_header(token).unwrap();
    let kid = header.kid.as_deref().expect("the JWT carries a kid");
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"].as_str() == Some(kid))
        .expect("realm JWKS covers the kid");
    // Build the decoding key from the JWK family so the helper follows
    // whichever algorithm the signing key uses.
    let key = match jwk["kty"].as_str().unwrap() {
        "RSA" => jsonwebtoken::DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap(),
        "OKP" => jsonwebtoken::DecodingKey::from_ed_components(jwk["x"].as_str().unwrap()).unwrap(),
        "EC" => jsonwebtoken::DecodingKey::from_ec_components(
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
        )
        .unwrap(),
        other => panic!("unexpected JWK kty: {other}"),
    };
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_audience(&[audience]);
    // The signed userinfo JWT carries no `exp` — validate it when present
    // (id tokens) instead of requiring it.
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(token, &key, &validation)
        .expect("the JWT verifies against the realm JWKS")
        .claims
}

// ---------------------------------------------------------------------------
// Per-client id_token_signed_response_alg
// ---------------------------------------------------------------------------

/// A client registered with `id_token_signed_response_alg = RS256` gets
/// RS256-signed ID tokens while a default client in the same realm keeps
/// the server default (EdDSA).
#[tokio::test]
async fn per_client_id_token_alg_override_signs_rs256() {
    let harness = TestHarness::new().await;
    harness.create_realm("dyn-alg").await;
    harness.create_user("dyn-alg", "alice", PASSWORD).await;
    let pinned = client_with_attributes(
        &harness,
        "dyn-alg",
        &[(issuerd_core::Client::ID_TOKEN_SIGNED_RESPONSE_ALG_ATTRIBUTE, "RS256")],
    )
    .await;
    let default = harness.create_client("dyn-alg", false).await;

    let tokens = harness
        .authenticate_user("dyn-alg", pinned.client_id.as_ref(), "alice", PASSWORD)
        .await;
    let id_token = tokens.id_token.expect("id_token issued");
    let header = jsonwebtoken::decode_header(&id_token).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256, "the pinned alg wins");
    assert!(header.kid.is_some(), "the header names the signing key");
    let claims = verify_realm_jwt(&harness, "dyn-alg", pinned.client_id.as_ref(), &id_token).await;
    assert_eq!(claims["iss"], format!("{}/realms/dyn-alg", harness.base_url));

    let tokens = harness
        .authenticate_user("dyn-alg", default.client_id.as_ref(), "alice", PASSWORD)
        .await;
    let header = jsonwebtoken::decode_header(tokens.id_token.as_deref().unwrap()).unwrap();
    assert_eq!(
        header.alg,
        jsonwebtoken::Algorithm::EdDSA,
        "a client without the attribute keeps the server default"
    );
}

/// A pinned algorithm with no live signing key fails issuance loudly
/// (HTTP 500) instead of silently falling back to another key.
#[tokio::test]
async fn per_client_id_token_alg_without_a_live_key_fails_loudly() {
    let harness = TestHarness::new().await;
    harness.create_realm("dyn-alg-missing").await;
    harness.create_user("dyn-alg-missing", "alice", PASSWORD).await;
    // The harness key set boots with EdDSA + RS256 — no ES256 key exists.
    let client = client_with_attributes(
        &harness,
        "dyn-alg-missing",
        &[(issuerd_core::Client::ID_TOKEN_SIGNED_RESPONSE_ALG_ATTRIBUTE, "ES256")],
    )
    .await;

    // Pure implicit mints the ID token at login completion — the failure
    // surfaces on the login POST itself.
    let resp = harness
        .get(&format!(
            "/realms/dyn-alg-missing/protocol/openid-connect/auth?response_type=id_token&client_id={}&redirect_uri={}&scope=openid&nonce=n-1",
            client.client_id,
            "http://localhost:8080/cb".replace(':', "%3A").replace('/', "%2F"),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let execution_id =
        TestHarness::extract_query_param(&location, "execution_id").expect("missing execution_id");
    let resp = harness
        .post_form_with_cookie(
            "/api/v1/auth/login?realm=dyn-alg-missing",
            &[
                ("execution_id", &execution_id),
                ("username", "alice"),
                ("password", PASSWORD),
            ],
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a pinned alg without a live key must fail loudly"
    );
}

// ---------------------------------------------------------------------------
// Signed userinfo (userinfo_signed_response_alg)
// ---------------------------------------------------------------------------

/// A client registered with `userinfo_signed_response_alg = RS256` gets the
/// userinfo response as a signed JWT (`application/jwt`); the default stays
/// plain JSON.
#[tokio::test]
async fn signed_userinfo_returns_a_verifiable_jwt() {
    let harness = TestHarness::new().await;
    harness.create_realm("dyn-uinfo").await;
    let user = harness.create_user("dyn-uinfo", "alice", PASSWORD).await;
    let signed = client_with_attributes(
        &harness,
        "dyn-uinfo",
        &[(issuerd_core::Client::USERINFO_SIGNED_RESPONSE_ALG_ATTRIBUTE, "RS256")],
    )
    .await;
    let plain = harness.create_client("dyn-uinfo", false).await;

    let userinfo_path = "/realms/dyn-uinfo/protocol/openid-connect/userinfo";

    let tokens = harness
        .authenticate_user("dyn-uinfo", signed.client_id.as_ref(), "alice", PASSWORD)
        .await;
    let resp = harness.get_auth(userinfo_path, &tokens.access_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "application/jwt",
        "a signed-userinfo client gets a JWT body"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let jwt = String::from_utf8(body.to_vec()).unwrap();
    let header = jsonwebtoken::decode_header(&jwt).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    let claims = verify_realm_jwt(&harness, "dyn-uinfo", signed.client_id.as_ref(), &jwt).await;
    assert_eq!(claims["sub"], user.id.0.as_str());
    assert_eq!(claims["iss"], format!("{}/realms/dyn-uinfo", harness.base_url));
    assert_eq!(claims["aud"], signed.client_id.as_ref());
    assert!(claims["iat"].as_i64().is_some(), "the envelope carries iat");

    // A client without the attribute keeps the plain JSON response.
    let tokens = harness
        .authenticate_user("dyn-uinfo", plain.client_id.as_ref(), "alice", PASSWORD)
        .await;
    let resp = harness.get_auth(userinfo_path, &tokens.access_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-type"].to_str().unwrap().starts_with("application/json"),
        "the default userinfo response stays JSON"
    );
}

/// Discovery advertises the userinfo signing algorithms (mirroring the
/// realm's active signing keys) and JAR-by-reference support.
#[tokio::test]
async fn discovery_advertises_signed_userinfo_algs() {
    let harness = TestHarness::new().await;
    harness.create_realm("dyn-disc").await;

    let resp = harness.get("/realms/dyn-disc/.well-known/openid-configuration").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let algs: Vec<&str> = json["userinfo_signing_alg_values_supported"]
        .as_array()
        .expect("userinfo_signing_alg_values_supported advertised")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for alg in ["RS256", "EdDSA"] {
        assert!(algs.contains(&alg), "userinfo signing algs missing {alg}");
    }
    assert_eq!(json["request_uri_parameter_supported"], true);
}

// ---------------------------------------------------------------------------
// Pairwise sector_identifier_uri through DCR
// ---------------------------------------------------------------------------

/// A harness whose broker client serves `sector_doc` for the SSRF-guarded
/// JSON fetch (the `sector_identifier_uri` document at registration).
async fn harness_serving_sector_doc(
    sector_doc: serde_json::Value,
) -> (TestHarness, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hit = hits.clone();
    let mut broker = issuerd_core::MockBrokerClient::new();
    broker.expect_get_json_ssrf_guarded().returning(move |_| {
        hit.fetch_add(1, Ordering::SeqCst);
        Ok(sector_doc.clone())
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

/// Enable dynamic client registration on the realm.
async fn enable_registration(harness: &TestHarness, realm: &str) {
    // Re-read from storage: `create_realm` returns the realm as submitted,
    // while the stored row carries the seeded pairwise sector key — updating
    // the unsubmitted copy would strip it.
    let realm_id = issuerd_core::RealmId::new(realm).unwrap();
    let mut realm = harness.storage.get_realm(&realm_id).await.unwrap().unwrap();
    realm.attributes.insert(
        issuerd_core::Realm::DYNAMIC_CLIENT_REGISTRATION_ATTRIBUTE.to_string(),
        "true".to_string(),
    );
    harness.storage.update_realm(&realm).await.unwrap();
}

/// A pairwise client registered through DCR with a `sector_identifier_uri`:
/// the sector document is fetched at registration and the issued ID token
/// carries the derived pairwise subject.
#[tokio::test]
async fn dcr_pairwise_sector_identifier_uri_fetched_and_honored() {
    let (harness, hits) =
        harness_serving_sector_doc(serde_json::json!(["http://localhost:8080/cb"])).await;
    harness.create_realm("dyn-sector").await;
    enable_registration(&harness, "dyn-sector").await;
    let user = harness.create_user("dyn-sector", "alice", PASSWORD).await;

    let resp = harness
        .post_json(
            "/realms/dyn-sector/clients-registrations/default",
            serde_json::json!({
                "redirect_uris": ["http://localhost:8080/cb"],
                "scope": "openid",
                "subject_type": "pairwise",
                "sector_identifier_uri": "https://sector.example.com/doc.json",
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let registration = json_body(resp).await;
    assert_eq!(registration["subject_type"], "pairwise");
    assert_eq!(registration["sector_identifier_uri"], "https://sector.example.com/doc.json");
    let client_id = registration["client_id"].as_str().unwrap().to_string();
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the sector document was fetched once");

    let tokens = harness.authenticate_user("dyn-sector", &client_id, "alice", PASSWORD).await;
    let id_token = tokens.id_token.expect("id_token issued");

    // The pairwise sub matches the sector derivation exactly.
    let realm_id = issuerd_core::RealmId::new("dyn-sector").unwrap();
    let realm_model = harness.storage.get_realm(&realm_id).await.unwrap().unwrap();
    let client_model = harness
        .storage
        .get_client_by_client_id(
            &realm_id,
            &issuerd_core::ClientIdentifier::new(&client_id).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let expected =
        issuerd_token::pairwise::effective_subject(&user, &client_model, &realm_model).unwrap();
    let claims = verify_realm_jwt(&harness, "dyn-sector", &client_id, &id_token).await;
    assert_eq!(claims["sub"], expected.0.as_str());
    assert_ne!(claims["sub"], user.id.0.as_str(), "the raw user id must not leak");
}

/// A sector document that does not list the client's redirect URI fails the
/// registration with `invalid_client_metadata`.
#[tokio::test]
async fn dcr_pairwise_sector_document_mismatch_rejected() {
    let (harness, hits) =
        harness_serving_sector_doc(serde_json::json!(["https://other.example.com/cb"])).await;
    harness.create_realm("dyn-sector-bad").await;
    enable_registration(&harness, "dyn-sector-bad").await;

    let resp = harness
        .post_json(
            "/realms/dyn-sector-bad/clients-registrations/default",
            serde_json::json!({
                "redirect_uris": ["http://localhost:8080/cb"],
                "subject_type": "pairwise",
                "sector_identifier_uri": "https://sector.example.com/doc.json",
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_client_metadata");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the sector document was fetched");
}
