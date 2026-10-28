// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OIDC discovery and JWKS endpoint integration tests (dual-target).

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt as _;

use crate::harness::for_each_target;

#[tokio::test]
async fn discovery_returns_mandatory_fields() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let resp = target
            .get(&format!("/realms/{}/.well-known/openid-configuration", realm.name))
            .await;
        assert_eq!(resp.status(), 200);
        let json = resp.json().unwrap();
        assert!(json["issuer"].is_string());
        assert!(json["authorization_endpoint"].is_string());
        assert!(json["token_endpoint"].is_string());
        assert!(json["userinfo_endpoint"].is_string());
        assert!(json["jwks_uri"].is_string());
        assert!(json["response_types_supported"].as_array().unwrap().contains(&"code".into()));
        assert!(json["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&"authorization_code".into()));
        assert!(json["subject_types_supported"].is_array());
        assert!(json["id_token_signing_alg_values_supported"].is_array());

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn certs_returns_valid_jwks() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let resp = target
            .get(&format!("/realms/{}/protocol/openid-connect/certs", realm.name))
            .await;
        assert_eq!(resp.status(), 200);
        let json = resp.json().unwrap();
        let keys = json["keys"].as_array().unwrap();
        assert!(!keys.is_empty());
        assert!(keys[0]["kty"].is_string());
        assert!(keys[0]["kid"].is_string());

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn issuerd_discovery_advertises_public_client_auth_and_rfc9207() {
    let harness = crate::harness::TestHarness::new().await;
    let request = Request::builder()
        .uri("/.well-known/openid-configuration")
        .body(Body::empty())
        .unwrap();
    let response = harness.app.clone().oneshot(harness.add_connect_info(request)).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("none")));
    assert_eq!(json["authorization_response_iss_parameter_supported"], true);
}
