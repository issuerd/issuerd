// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Pushed Authorization Requests (RFC 9126) integration tests (Issuerd-only).

//! Pushed Authorization Requests (RFC 9126) integration tests
//! (Issuerd-only).
//!
//! Covered: PAR push (client auth, push-time validation), single-use +
//! client-bound `request_uri` consumption at the authorization endpoint, full
//! roundtrip to an authorization code, the realm-wide and per-client
//! require-PAR policy flags, and discovery advertisement.

use axum::http::StatusCode;

use crate::harness::TestHarness;

const PAR_REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

fn par_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/ext/par")
}

fn auth_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/auth")
}

/// Percent-encode a `request_uri` URN for use as a query value.
fn encode_request_uri(request_uri: &str) -> String {
    request_uri.replace(':', "%3A")
}

/// Extract a JSON body from a response.
async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Push an authorization request for a confidential client; returns the
/// response for assertion.
async fn push_par(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    extra: &[(&str, &str)],
) -> axum::response::Response {
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", client.client_id.as_ref()),
        ("redirect_uri", "http://localhost:8080/cb"),
        ("scope", "openid"),
        ("state", "xyz"),
        ("client_secret", client.secret.as_deref().unwrap_or("")),
    ];
    params.extend_from_slice(extra);
    harness.post_form(&par_path(realm), &params).await
}

/// Push a well-formed request and return the minted `request_uri`.
async fn push_par_ok(harness: &TestHarness, realm: &str, client: &issuerd_core::Client) -> String {
    let resp = push_par(harness, realm, client, &[]).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert_eq!(json["expires_in"], 90);
    let request_uri = json["request_uri"].as_str().expect("request_uri missing");
    assert!(
        request_uri.starts_with(PAR_REQUEST_URI_PREFIX),
        "unexpected request_uri scheme: {request_uri}"
    );
    request_uri.to_string()
}

/// GET the authorization endpoint with raw extra query params.
async fn authorize(harness: &TestHarness, realm: &str, query: &str) -> axum::response::Response {
    harness.get(&format!("{}?{query}", auth_path(realm))).await
}

#[tokio::test]
async fn par_roundtrip_full_code_flow() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-roundtrip").await;
    let client = harness.create_client("par-roundtrip", false).await;
    harness.create_user("par-roundtrip", "anna", "Password123!").await;

    // 1. Push the authorization request.
    let request_uri = push_par_ok(&harness, "par-roundtrip", &client).await;

    // 2. The authorization endpoint consumes it and starts the normal login
    //    flow (redirect to the login page with a fresh execution id).
    let resp = authorize(
        &harness,
        "par-roundtrip",
        &format!(
            "client_id={}&request_uri={}",
            client.client_id,
            encode_request_uri(&request_uri)
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains("/login.html"), "expected login redirect, got: {location}");
    let execution_id =
        TestHarness::extract_query_param(&location, "execution_id").expect("missing execution_id");

    // 3. Log in; the stored request (redirect_uri, state) drives the flow.
    let login_resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=par-roundtrip",
            serde_json::json!({
                "execution_id": execution_id,
                "username": "anna",
                "password": "Password123!",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_json = json_body(login_resp).await;
    let code = login_json["code"].as_str().expect("no code issued").to_string();

    // 4. Redeem the code — proves the stored redirect_uri round-tripped.
    let token_resp = harness
        .post_form(
            "/realms/par-roundtrip/protocol/openid-connect/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(token_resp.status(), StatusCode::OK);
    let token_json = json_body(token_resp).await;
    assert!(token_json["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn par_request_uri_is_single_use() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-single-use").await;
    let client = harness.create_client("par-single-use", false).await;

    let request_uri = push_par_ok(&harness, "par-single-use", &client).await;
    let query = format!(
        "client_id={}&request_uri={}",
        client.client_id,
        encode_request_uri(&request_uri)
    );

    let first = authorize(&harness, "par-single-use", &query).await;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);

    let second = authorize(&harness, "par-single-use", &query).await;
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    let json = json_body(second).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn par_unknown_request_uri_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-unknown").await;
    let client = harness.create_client("par-unknown", false).await;

    let resp = authorize(
        &harness,
        "par-unknown",
        &format!(
            "client_id={}&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Ano-such-entry",
            client.client_id
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn par_foreign_request_uri_scheme_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-foreign").await;
    let client = harness.create_client("par-foreign", false).await;

    // A JAR-by-reference URL stays unsupported.
    let resp = authorize(
        &harness,
        "par-foreign",
        &format!(
            "client_id={}&request_uri=https%3A%2F%2Fexample.com%2Frequest.jwt",
            client.client_id
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "request_not_supported");
}

#[tokio::test]
async fn par_request_and_request_uri_together_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-both").await;
    let client = harness.create_client("par-both", false).await;

    let resp = authorize(
        &harness,
        "par-both",
        &format!(
            "client_id={}&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Ax&request=eyJhbGciOiJub25lIn0.e30.",
            client.client_id
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn par_extra_query_params_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-extra").await;
    let client = harness.create_client("par-extra", false).await;

    let request_uri = push_par_ok(&harness, "par-extra", &client).await;
    // `state` was already pushed; repeating it at the authorization endpoint
    // is rejected — only client_id may accompany request_uri.
    let resp = authorize(
        &harness,
        "par-extra",
        &format!(
            "client_id={}&request_uri={}&state=abc",
            client.client_id,
            encode_request_uri(&request_uri)
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn par_client_id_mismatch_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-mismatch").await;
    let client_a = harness.create_client("par-mismatch", false).await;
    let client_b = harness.create_client("par-mismatch", false).await;

    let request_uri = push_par_ok(&harness, "par-mismatch", &client_a).await;
    let resp = authorize(
        &harness,
        "par-mismatch",
        &format!(
            "client_id={}&request_uri={}",
            client_b.client_id,
            encode_request_uri(&request_uri)
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn par_push_rejects_unregistered_redirect_uri() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-badrdir").await;
    let client = harness.create_client("par-badrdir", false).await;

    let secret = client.secret.as_deref().unwrap();
    let resp = harness
        .post_form(
            &par_path("par-badrdir"),
            &[
                ("response_type", "code"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", "http://evil.example.com/cb"),
                ("scope", "openid"),
                ("client_secret", secret),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn par_push_rejects_unsupported_response_type() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-badrt").await;
    let client = harness.create_client("par-badrt", false).await;

    let secret = client.secret.as_deref().unwrap();
    let resp = harness
        .post_form(
            &par_path("par-badrt"),
            &[
                ("response_type", "token"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("scope", "openid"),
                ("client_secret", secret),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "unsupported_response_type");
}

#[tokio::test]
async fn par_push_rejects_request_uri_param() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-nested").await;
    let client = harness.create_client("par-nested", false).await;

    let resp = push_par(
        &harness,
        "par-nested",
        &client,
        &[("request_uri", "urn:ietf:params:oauth:request_uri:nested")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn par_push_requires_client_authentication() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-auth").await;
    let client = harness.create_client("par-auth", false).await;

    // No secret at all.
    let resp = harness
        .post_form(
            &par_path("par-auth"),
            &[
                ("response_type", "code"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_client");

    // Wrong secret.
    let resp = harness
        .post_form(
            &par_path("par-auth"),
            &[
                ("response_type", "code"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("scope", "openid"),
                ("client_secret", "wrong"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn par_push_supports_basic_auth() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-basic").await;
    let client = harness.create_client("par-basic", false).await;

    use base64::Engine;
    let creds = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        client.client_id,
        client.secret.as_deref().unwrap()
    ));
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(par_path("par-basic"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", format!("Basic {creds}"))
        .body(axum::body::Body::from(
            "response_type=code&redirect_uri=http://localhost:8080/cb&scope=openid",
        ))
        .unwrap();
    let req = harness.add_connect_info(req);
    let resp = tower::ServiceExt::oneshot(harness.app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// RFC 9126 §1.1's own example pushes with `Authorization: Basic …` AND a
/// body `client_id` — the header authenticates, the parameter identifies.
/// (Previously the body `client_id` made the server ignore the header and
/// the push failed 401.)
#[tokio::test]
async fn par_push_supports_basic_auth_with_body_client_id() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-basic-id").await;
    let client = harness.create_client("par-basic-id", false).await;

    use base64::Engine;
    let creds = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        client.client_id,
        client.secret.as_deref().unwrap()
    ));
    let body = format!(
        "response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid",
        client.client_id
    );
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(par_path("par-basic-id"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", format!("Basic {creds}"))
        .body(axum::body::Body::from(body))
        .unwrap();
    let req = harness.add_connect_info(req);
    let resp = tower::ServiceExt::oneshot(harness.app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // The pushed request is consumable — proof the entry was stored.
    let json = json_body(resp).await;
    let request_uri = json["request_uri"].as_str().unwrap();
    let resp = authorize(
        &harness,
        "par-basic-id",
        &format!("client_id={}&request_uri={}", client.client_id, encode_request_uri(request_uri)),
    )
    .await;
    assert_ne!(resp.status(), StatusCode::BAD_REQUEST);
}

/// A body `client_id` contradicting the Basic-authenticated identity is
/// `invalid_client` with a `WWW-Authenticate` challenge (RFC 6749 §5.2).
#[tokio::test]
async fn par_push_rejects_mismatched_basic_client_id() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-basic-mismatch").await;
    let client = harness.create_client("par-basic-mismatch", false).await;
    let other = harness.create_client("par-basic-mismatch", false).await;

    use base64::Engine;
    let creds = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        client.client_id,
        client.secret.as_deref().unwrap()
    ));
    let body = format!(
        "response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid",
        other.client_id
    );
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(par_path("par-basic-mismatch"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", format!("Basic {creds}"))
        .body(axum::body::Body::from(body))
        .unwrap();
    let req = harness.add_connect_info(req);
    let resp = tower::ServiceExt::oneshot(harness.app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("Basic")),
        "expected a WWW-Authenticate challenge"
    );
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn par_public_client_push_with_pkce() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-public").await;
    let client = harness.create_client("par-public", true).await;

    // RFC 7636 S256 challenge from the RFC 9126 example; public clients push
    // without a secret and must supply PKCE.
    let resp = harness
        .post_form(
            &par_path("par-public"),
            &[
                ("response_type", "code"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("scope", "openid"),
                ("code_challenge", "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U"),
                ("code_challenge_method", "S256"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn par_realm_require_pushed_authorization_requests() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("par-required").await;
    let client = harness.create_client("par-required", false).await;

    // Flip the realm attribute (Keycloak-compatible name).
    realm
        .attributes
        .insert("require_pushed_authorization_requests".to_string(), "true".to_string());
    harness.storage.update_realm(&realm).await.unwrap();

    // Plain authorization requests are refused with invalid_request.
    let resp = authorize(
        &harness,
        "par-required",
        &format!(
            "response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid",
            client.client_id
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");

    // Discovery advertises the policy for this realm.
    let resp = harness.get("/realms/par-required/.well-known/openid-configuration").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["require_pushed_authorization_requests"], true);

    // The PAR flow still works.
    let request_uri = push_par_ok(&harness, "par-required", &client).await;
    let resp = authorize(
        &harness,
        "par-required",
        &format!(
            "client_id={}&request_uri={}",
            client.client_id,
            encode_request_uri(&request_uri)
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn par_client_require_pushed_authorization_requests() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-clientreq").await;
    let mut client = harness.create_client("par-clientreq", false).await;

    // Pin the client to PAR (Keycloak attribute spelling).
    client
        .attributes
        .insert("require.pushed.authorization.requests".to_string(), "true".to_string());
    harness.storage.update_client(&client.realm_id.clone(), &client).await.unwrap();

    // A plain request is refused with a redirect to the registered
    // redirect_uri (validation has passed at that point).
    let resp = authorize(
        &harness,
        "par-clientreq",
        &format!(
            "response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
            client.client_id
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with("http://localhost:8080/cb?"), "got: {location}");
    assert!(location.contains("error=invalid_request"), "got: {location}");
    assert!(location.contains("state=xyz"), "got: {location}");

    // The PAR flow is unaffected.
    let request_uri = push_par_ok(&harness, "par-clientreq", &client).await;
    let resp = authorize(
        &harness,
        "par-clientreq",
        &format!(
            "client_id={}&request_uri={}",
            client.client_id,
            encode_request_uri(&request_uri)
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn par_discovery_advertises_endpoint() {
    let harness = TestHarness::new().await;
    harness.create_realm("par-disc").await;

    let resp = harness.get("/realms/par-disc/.well-known/openid-configuration").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let endpoint = json["pushed_authorization_request_endpoint"]
        .as_str()
        .expect("pushed_authorization_request_endpoint missing");
    assert!(
        endpoint.ends_with("/realms/par-disc/protocol/openid-connect/ext/par"),
        "unexpected endpoint: {endpoint}"
    );
    // Default policy is false (PAR optional).
    assert_eq!(json["require_pushed_authorization_requests"], false);
    // JAR via `request` is implemented; JAR-by-reference is
    // advertised truthfully as unsupported.
    assert_eq!(json["request_parameter_supported"], true);
    assert_eq!(json["request_uri_parameter_supported"], false);
}
