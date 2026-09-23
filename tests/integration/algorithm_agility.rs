// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Algorithm agility and per-realm signing algorithm selection integration tests.

//! Algorithm agility integration tests.
//!
//! Covers the ES512 mapping fix end-to-end, per-realm signing algorithm
//! selection (`default_signature_algorithm` realm attribute over the
//! server-global signing keys), fallback when the configured algorithm has no
//! active key, and discovery truthfulness
//! (`id_token_signing_alg_values_supported` lists exactly the active
//! algorithms).

use axum::http::StatusCode;
use base64::Engine as _;
use tower::ServiceExt as _;

use crate::harness::TestHarness;

fn jwt_header(token: &str) -> serde_json::Value {
    let header = token.split('.').next().expect("jwt header segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Resource-owner password grant; asserts 200 and returns the token response.
async fn password_grant_ok(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    password: &str,
) -> serde_json::Value {
    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/token"),
            &[
                ("grant_type", "password"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("username", username),
                ("password", password),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

/// Rotate a new active key for `algorithm` via the admin API and wait until
/// this node's keystore has reloaded (the reload hook is fire-and-forget).
async fn rotate_and_wait(harness: &TestHarness, admin: &str, algorithm: &str) -> String {
    let resp = harness
        .post_json_auth(
            "/admin/realms/master/keys/rotate",
            admin,
            serde_json::json!({"algorithm": algorithm}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let meta = body_json(resp).await;
    let kid = meta["active"][algorithm].as_str().expect("rotated kid").to_string();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let resp = harness.get("/realms/master/protocol/openid-connect/certs").await;
        let jwks = body_json(resp).await;
        let found = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["kid"] == kid && k["alg"] == algorithm);
        if found {
            return kid;
        }
        assert!(std::time::Instant::now() < deadline, "keystore did not reload {algorithm} key");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

async fn set_realm_algorithm(harness: &TestHarness, realm_name: &str, alg: &str) {
    let mut realm = harness
        .storage
        .get_realm_by_name(realm_name)
        .await
        .unwrap()
        .expect("realm exists");
    realm.attributes.insert(
        issuerd_core::Realm::DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE.to_string(),
        alg.to_string(),
    );
    harness.storage.update_realm(&realm).await.unwrap();
    // Direct storage writes bypass the admin API's synchronous invalidation
    // of the realm-by-name cache; drop the entry so subsequent realm
    // resolutions (token issuance) see the new algorithm immediately.
    harness
        .cache
        .delete(&issuerd_cluster::cache_keys::realm_by_name(realm_name))
        .await
        .unwrap();
}

/// Fresh deployments start on EdDSA: the first-boot signing key is Ed25519
/// and realms without a `default_signature_algorithm` attribute get EdDSA
/// tokens that validate end-to-end. RS256 stays available as an explicit
/// opt-in (covered by the other tests in this file).
#[tokio::test]
async fn fresh_deployment_defaults_to_eddsa_signing() {
    let harness = TestHarness::new().await;
    harness.create_realm("default-realm").await;
    let client = harness.create_client("default-realm", false).await;
    harness.create_user("default-realm", "dave", "password123").await;

    // The boot key set holds exactly one active key, and it is EdDSA.
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let resp = harness.get_auth("/admin/realms/master/keys", &admin).await;
    let meta = body_json(resp).await;
    let boot_kid = meta["active"]["EdDSA"].as_str().expect("EdDSA boot key").to_string();
    assert_eq!(meta["active"].as_object().unwrap().len(), 1, "fresh boot keeps one active key");

    // An un-configured realm gets EdDSA tokens signed by the boot key.
    let tokens = password_grant_ok(&harness, "default-realm", &client, "dave", "password123").await;
    let access = tokens["access_token"].as_str().unwrap();
    let header = jwt_header(access);
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["kid"], boot_kid);
    assert_eq!(jwt_header(tokens["id_token"].as_str().unwrap())["alg"], "EdDSA");

    // The EdDSA token validates at userinfo (stateless OKP verification).
    let resp = harness
        .get_auth("/realms/default-realm/protocol/openid-connect/userinfo", access)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // JWKS publishes the OKP key with the Ed25519 curve and no private material.
    let resp = harness.get("/realms/default-realm/protocol/openid-connect/certs").await;
    let jwks = body_json(resp).await;
    let key = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"].as_str() == Some(boot_kid.as_str()))
        .expect("boot key published");
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert!(key.get("k").is_none() || key["k"].is_null(), "no symmetric material exposed");
}

#[tokio::test]
async fn realm_es256_signs_tokens_old_rs256_tokens_still_validate() {
    let harness = TestHarness::new().await;
    harness.create_realm("es256-realm").await;
    let client = harness.create_client("es256-realm", false).await;
    harness.create_user("es256-realm", "alice", "password123").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // RS256 as the explicit compatibility choice: pin the realm to an RS256
    // key (rotated in deliberately) even though the server default is EdDSA.
    let rs256_kid = rotate_and_wait(&harness, &admin, "RS256").await;
    set_realm_algorithm(&harness, "es256-realm", "RS256").await;
    let rs256_tokens =
        password_grant_ok(&harness, "es256-realm", &client, "alice", "password123").await;
    let rs256_header = jwt_header(rs256_tokens["access_token"].as_str().unwrap());
    assert_eq!(rs256_header["alg"], "RS256");
    assert_eq!(rs256_header["kid"], rs256_kid);

    // Generate an ES256 active key (server-global) and pin the realm to it.
    let es256_kid = rotate_and_wait(&harness, &admin, "ES256").await;
    set_realm_algorithm(&harness, "es256-realm", "ES256").await;

    // New tokens for the realm are ES256, signed by the new key.
    let es256_tokens =
        password_grant_ok(&harness, "es256-realm", &client, "alice", "password123").await;
    let access = es256_tokens["access_token"].as_str().unwrap();
    let header = jwt_header(access);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], es256_kid);
    let id_token = es256_tokens["id_token"].as_str().unwrap();
    assert_eq!(jwt_header(id_token)["alg"], "ES256");

    // The ES256 token works against userinfo and introspection.
    let resp = harness
        .get_auth("/realms/es256-realm/protocol/openid-connect/userinfo", access)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Tokens signed by the previous RS256 key still validate (both keys are
    // published in JWKS).
    let resp = harness
        .get_auth(
            "/realms/es256-realm/protocol/openid-connect/userinfo",
            rs256_tokens["access_token"].as_str().unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "old RS256 token must still validate");

    // JWKS exposes both keys.
    let resp = harness.get("/realms/es256-realm/protocol/openid-connect/certs").await;
    let jwks = body_json(resp).await;
    let algs: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["alg"].as_str().unwrap())
        .collect();
    assert!(algs.contains(&"ES256") && algs.contains(&"RS256"));

    // Discovery lists exactly the active algorithms (newest first; the EdDSA
    // boot key is the oldest active key).
    let resp = harness.get("/realms/es256-realm/.well-known/openid-configuration").await;
    let discovery = body_json(resp).await;
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        serde_json::json!(["ES256", "RS256", "EdDSA"])
    );
}

#[tokio::test]
async fn realm_es512_signs_and_validates_end_to_end() {
    let harness = TestHarness::new().await;
    harness.create_realm("es512-realm").await;
    let client = harness.create_client("es512-realm", false).await;
    harness.create_user("es512-realm", "bob", "password123").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    let es512_kid = rotate_and_wait(&harness, &admin, "ES512").await;
    set_realm_algorithm(&harness, "es512-realm", "ES512").await;

    let tokens = password_grant_ok(&harness, "es512-realm", &client, "bob", "password123").await;
    let access = tokens["access_token"].as_str().unwrap();
    let header = jwt_header(access);
    assert_eq!(header["alg"], "ES512");
    assert_eq!(header["kid"], es512_kid);
    assert_eq!(jwt_header(tokens["id_token"].as_str().unwrap())["alg"], "ES512");
    assert_eq!(jwt_header(tokens["refresh_token"].as_str().unwrap())["alg"], "ES512");

    // Stateless validation paths accept ES512: userinfo and introspection.
    let resp = harness
        .get_auth("/realms/es512-realm/protocol/openid-connect/userinfo", access)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            "/realms/es512-realm/protocol/openid-connect/token/introspect",
            &[
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("token", access),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let introspection = body_json(resp).await;
    assert_eq!(introspection["active"], true);

    // The ES512 refresh token rotates into fresh ES512 tokens.
    let resp = harness
        .post_form(
            "/realms/es512-realm/protocol/openid-connect/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let rotated = body_json(resp).await;
    assert_eq!(jwt_header(rotated["access_token"].as_str().unwrap())["alg"], "ES512");
}

#[tokio::test]
async fn realm_algorithm_without_active_key_falls_back_to_default() {
    let harness = TestHarness::new().await;
    harness.create_realm("fallback-realm").await;
    let client = harness.create_client("fallback-realm", false).await;
    harness.create_user("fallback-realm", "carol", "password123").await;

    // No ES384 key exists: issuance falls back to the default (EdDSA boot) key.
    set_realm_algorithm(&harness, "fallback-realm", "ES384").await;
    let tokens =
        password_grant_ok(&harness, "fallback-realm", &client, "carol", "password123").await;
    assert_eq!(jwt_header(tokens["access_token"].as_str().unwrap())["alg"], "EdDSA");

    // An invalid algorithm value is ignored the same way.
    set_realm_algorithm(&harness, "fallback-realm", "FOOBAR").await;
    let tokens =
        password_grant_ok(&harness, "fallback-realm", &client, "carol", "password123").await;
    assert_eq!(jwt_header(tokens["access_token"].as_str().unwrap())["alg"], "EdDSA");

    // Symmetric algorithms are never selected for realm token signing (HS*
    // keys publish no usable public material), so this falls back too.
    set_realm_algorithm(&harness, "fallback-realm", "HS256").await;
    let tokens =
        password_grant_ok(&harness, "fallback-realm", &client, "carol", "password123").await;
    assert_eq!(jwt_header(tokens["access_token"].as_str().unwrap())["alg"], "EdDSA");
}

#[tokio::test]
async fn rotate_keeps_one_active_key_per_algorithm() {
    let harness = TestHarness::new().await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // Boot state: one active EdDSA key.
    let resp = harness.get_auth("/admin/realms/master/keys", &admin).await;
    let meta = body_json(resp).await;
    let eddsa_kid = meta["active"]["EdDSA"].as_str().unwrap().to_string();

    // ES256 rotation: the EdDSA key stays active alongside.
    rotate_and_wait(&harness, &admin, "ES256").await;
    let resp = harness.get_auth("/admin/realms/master/keys", &admin).await;
    let meta = body_json(resp).await;
    assert_eq!(meta["active"]["EdDSA"], eddsa_kid);
    let es_kid = meta["active"]["ES256"].as_str().unwrap().to_string();

    // A bare rotate refreshes the newest algorithm's key only; the EdDSA
    // active key is untouched.
    let resp = harness
        .post_json_auth("/admin/realms/master/keys/rotate", &admin, serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let meta = body_json(resp).await;
    assert_eq!(meta["active"]["EdDSA"], eddsa_kid);
    assert_ne!(meta["active"]["ES256"].as_str().unwrap(), es_kid);
}

#[tokio::test]
async fn rotate_with_unknown_algorithm_rejected() {
    let harness = TestHarness::new().await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    let resp = harness
        .post_json_auth(
            "/admin/realms/master/keys/rotate",
            &admin,
            serde_json::json!({"algorithm": "FOOBAR"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn discovery_default_realm_lists_eddsa_only() {
    let harness = TestHarness::new().await;
    let resp = harness.get("/realms/master/.well-known/openid-configuration").await;
    let discovery = body_json(resp).await;
    assert_eq!(discovery["id_token_signing_alg_values_supported"], serde_json::json!(["EdDSA"]));
}

// ---------------------------------------------------------------------------
// 2026-09 review hardening: disabled keys never sign; rotation guardrails
// ---------------------------------------------------------------------------

/// PUT keys/{kid}/disable on the only active key of a realm-pinned algorithm
/// must stop that key from signing — the realm falls back to the default
/// active key instead of silently continuing with the disabled one (the
/// documented contract: "still validates, never signs").
#[tokio::test]
async fn disabled_key_never_signs_for_pinned_realm() {
    let harness = TestHarness::new().await;
    harness.create_realm("disable-realm").await;
    let client = harness.create_client("disable-realm", false).await;
    harness.create_user("disable-realm", "alice", "password123").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // Active ES256 key + realm pinned to ES256.
    let es256_kid = rotate_and_wait(&harness, &admin, "ES256").await;
    set_realm_algorithm(&harness, "disable-realm", "ES256").await;

    let tokens =
        password_grant_ok(&harness, "disable-realm", &client, "alice", "password123").await;
    let bound_token = tokens["access_token"].as_str().unwrap().to_string();
    assert_eq!(jwt_header(&bound_token)["kid"], es256_kid);

    // Disable the realm's only active ES256 key.
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/admin/realms/master/keys/{es256_kid}/disable"))
        .header("authorization", format!("Bearer {admin}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // New tokens for the pinned realm must NOT carry the disabled kid — the
    // fallback signs with the newest active key (EdDSA boot key). The reload
    // hook is fire-and-forget, so poll briefly.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let tokens =
            password_grant_ok(&harness, "disable-realm", &client, "alice", "password123").await;
        let header = jwt_header(tokens["access_token"].as_str().unwrap());
        if header["kid"] != es256_kid {
            assert_eq!(header["alg"], "EdDSA", "fallback must sign with the default active key");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "disabled ES256 key kept signing for the pinned realm"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // The disabled key still VALIDATES: the pre-disable token works at
    // userinfo (published as a passive key in JWKS).
    let resp = harness
        .get_auth("/realms/disable-realm/protocol/openid-connect/userinfo", &bound_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "passive key must still verify");
}

/// Rotation refuses symmetric (HMAC) algorithms — they could never be
/// validated publicly (`k` is stripped from the JWK) — and bounds RSA sizes.
#[tokio::test]
async fn rotate_rejects_symmetric_algorithm_and_bounds_key_size() {
    let harness = TestHarness::new().await;
    harness.create_realm("rotate-guard").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    for body in [
        serde_json::json!({"algorithm": "HS256"}),
        serde_json::json!({"algorithm": "HS512"}),
        serde_json::json!({"algorithm": "RS256", "key_size": 512}),
        serde_json::json!({"algorithm": "RS256", "key_size": 16384}),
    ] {
        let resp = harness
            .post_json_auth("/admin/realms/master/keys/rotate", &admin, body.clone())
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "body: {body}");
    }

    // No symmetric key was created or advertised.
    let resp = harness.get("/realms/master/.well-known/openid-configuration").await;
    let discovery = body_json(resp).await;
    let algs = discovery["id_token_signing_alg_values_supported"].as_array().unwrap();
    assert!(
        !algs.iter().any(|a| a.as_str().unwrap_or("").starts_with("HS")),
        "discovery must never advertise HMAC signing: {algs:?}"
    );
}
