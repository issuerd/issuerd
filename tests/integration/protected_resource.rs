// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// RFC 9728 protected-resource metadata integration tests.

//! RFC 9728 OAuth 2.0 Protected Resource Metadata integration tests
//! (Issuerd-only — Keycloak has no such endpoint).
//!
//! Covered: the `[mcp] enabled` gate (uniform 404 when disabled), the bare
//! master-realm route, the path-suffixed per-realm route, the unknown-realm
//! 404, the exact document shape (five fields, no nulls), the response
//! headers mirroring the OIDC discovery document, and the DPoP alg list's
//! equality with the OIDC discovery advertisement.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use tower::ServiceExt as _;

use crate::harness::TestHarness;

const BARE_PATH: &str = "/.well-known/oauth-protected-resource";

fn realm_path(realm: &str) -> String {
    format!("/.well-known/oauth-protected-resource/realms/{realm}/mcp")
}

/// Harness with `[mcp] enabled = true` (`TestHarness::new` runs the default
/// `false`).
async fn harness_with_mcp_enabled() -> TestHarness {
    let mut config = crate::harness::test_config();
    config.mcp.enabled = true;
    let state = std::sync::Arc::new(
        issuerd_server::state::ServerState::from_config(&config).await.unwrap(),
    );
    TestHarness::with_state(state)
}

async fn get(harness: &TestHarness, path: &str) -> Response {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

async fn json_body(resp: Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn disabled_gate_answers_404_on_both_routes() {
    let harness = TestHarness::new().await;
    for path in [BARE_PATH.to_string(), realm_path("master")] {
        let resp = get(&harness, &path).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} must 404 while [mcp] enabled = false"
        );
        let json = json_body(resp).await;
        assert_eq!(json["error"], "not_found");
    }
}

#[tokio::test]
async fn bare_route_serves_master_realm_resource() {
    let harness = harness_with_mcp_enabled().await;
    let resp = get(&harness, BARE_PATH).await;
    assert_eq!(resp.status(), StatusCode::OK);
    // Response headers mirror the OIDC discovery document exactly: JSON
    // content type, no Cache-Control.
    assert_eq!(
        resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert!(resp.headers().get(axum::http::header::CACHE_CONTROL).is_none());

    let json = json_body(resp).await;
    let issuer = format!("{}/realms/master", harness.base_url);
    assert_eq!(json["resource"], format!("{issuer}/mcp"));
    assert_eq!(json["authorization_servers"], serde_json::json!([issuer]));
    assert_eq!(json["scopes_supported"], serde_json::json!(["mcp:read", "mcp:write"]));
    // The served DPoP alg set IS the proof validator's accept set.
    let expected_algs: Vec<&str> = issuerd_core::Algorithm::DPOP_SIGNING_ALG_VALUES_SUPPORTED
        .iter()
        .map(|alg| alg.as_str())
        .collect();
    assert_eq!(json["dpop_signing_alg_values_supported"], serde_json::json!(expected_algs));
    assert_eq!(json["bearer_methods_supported"], serde_json::json!(["header"]));
    // Exactly these five fields, no extras, no nulls (RFC 9728 §3.2).
    let mut keys: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "authorization_servers",
            "bearer_methods_supported",
            "dpop_signing_alg_values_supported",
            "resource",
            "scopes_supported"
        ]
    );
}

#[tokio::test]
async fn path_suffixed_route_serves_the_named_realm() {
    let harness = harness_with_mcp_enabled().await;
    harness.create_realm("demo").await;
    let resp = get(&harness, &realm_path("demo")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let issuer = format!("{}/realms/demo", harness.base_url);
    assert_eq!(json["resource"], format!("{issuer}/mcp"));
    assert_eq!(json["authorization_servers"], serde_json::json!([issuer]));
}

#[tokio::test]
async fn issuer_path_prefix_uses_the_rfc_derived_metadata_url() {
    let mut config = crate::harness::test_config();
    config.issuer_url = "http://localhost:8080/iam".to_string();
    config.mcp.enabled = true;
    let state = std::sync::Arc::new(
        issuerd_server::state::ServerState::from_config(&config).await.unwrap(),
    );
    let harness = TestHarness::with_state(state);
    harness.create_realm("demo").await;

    let metadata_url =
        issuerd_protocol::discovery::ProtectedResourceMetadata::metadata_url_for_realm(
            &harness.base_url,
            "demo",
        );
    assert_eq!(metadata_url.path(), "/.well-known/oauth-protected-resource/iam/realms/demo/mcp");
    let resp = get(&harness, metadata_url.path()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["resource"], "http://localhost:8080/iam/realms/demo/mcp");
    assert_eq!(
        json["authorization_servers"],
        serde_json::json!(["http://localhost:8080/iam/realms/demo"])
    );
}

#[tokio::test]
async fn percent_encoded_realm_name_resolves_to_canonical_metadata() {
    let harness = harness_with_mcp_enabled().await;
    let realm = issuerd_core::Realm {
        id: issuerd_core::RealmId::new(issuerd_core::utils::generate_id()).unwrap(),
        name: issuerd_core::RealmName::new("tenant{one}").unwrap(),
        ..Default::default()
    };
    harness.storage.create_realm(&realm).await.unwrap();
    let metadata_url =
        issuerd_protocol::discovery::ProtectedResourceMetadata::metadata_url_for_realm(
            &harness.base_url,
            "tenant{one}",
        );
    assert!(metadata_url.path().contains("tenant%7Bone%7D"));
    let resp = get(&harness, metadata_url.path()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        json_body(resp).await["resource"],
        format!("{}/realms/tenant%7Bone%7D/mcp", harness.base_url)
    );
}

#[tokio::test]
async fn realm_id_alias_is_not_a_second_metadata_resource() {
    let harness = harness_with_mcp_enabled().await;
    let realm = issuerd_core::Realm {
        id: issuerd_core::RealmId::new(issuerd_core::utils::generate_id()).unwrap(),
        name: issuerd_core::RealmName::new("demo").unwrap(),
        ..Default::default()
    };
    harness.storage.create_realm(&realm).await.unwrap();
    let resp = get(&harness, &realm_path(realm.id.as_ref())).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mcp_enabled_boot_rejects_legacy_default_scope_but_disabled_boots() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("demo").await;
    let mut client = harness.create_client("demo", false).await;
    client.default_scopes = issuerd_core::Scope::parse("openid mcp:write");
    harness.storage.update_client(&realm.id, &client).await.unwrap();

    let disabled = crate::harness::test_config();
    issuerd_server::state::ServerState::from_components(
        &disabled,
        harness.storage.clone(),
        harness.cache.clone(),
    )
    .await
    .unwrap();

    let mut enabled = crate::harness::test_config();
    enabled.mcp.enabled = true;
    let err = issuerd_server::state::ServerState::from_components(
        &enabled,
        harness.storage.clone(),
        harness.cache.clone(),
    )
    .await
    .err()
    .expect("MCP-enabled boot must reject the legacy default assignment");
    assert!(err.to_string().contains("MCP scope collision"));
}

#[tokio::test]
async fn challenge_metadata_url_roundtrips_to_the_same_resource() {
    let harness = harness_with_mcp_enabled().await;
    harness.create_realm("demo").await;
    let resource = format!("{}/realms/demo/mcp", harness.base_url);
    let metadata_url =
        issuerd_protocol::discovery::ProtectedResourceMetadata::metadata_url_for_realm(
            &harness.base_url,
            "demo",
        );
    let challenge =
        issuerd_server::challenges::invalid_token_challenge(metadata_url.as_str(), None);
    assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge.headers()[axum::http::header::WWW_AUTHENTICATE].to_str().unwrap(),
        format!("Bearer resource_metadata=\"{metadata_url}\"")
    );

    let resp = get(&harness, metadata_url.path()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["resource"], resource);
}

#[tokio::test]
async fn unknown_realm_answers_404() {
    let harness = harness_with_mcp_enabled().await;
    let resp = get(&harness, &realm_path("no-such-realm")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "not_found");
}

#[tokio::test]
async fn dpop_alg_list_matches_the_oidc_discovery_document() {
    let harness = harness_with_mcp_enabled().await;
    let oidc = json_body(get(&harness, "/.well-known/openid-configuration").await).await;
    let metadata = json_body(get(&harness, BARE_PATH).await).await;
    assert_eq!(
        oidc["dpop_signing_alg_values_supported"], metadata["dpop_signing_alg_values_supported"],
        "both documents must advertise the proof validator's accept set"
    );
}
