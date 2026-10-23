// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// RFC 8707 Resource Indicators integration tests (Issuerd-only — Keycloak
// has no RFC 8707 support).

//! RFC 8707 `resource` parameter integration tests (Issuerd-only).
//!
//! Covered: the fail-closed `[mcp] enabled` gate (any present `resource` is
//! `invalid_target` while disabled), structural validation at the
//! authorization and token endpoints (absolute URI, no fragment), the exact
//! allowlist (only the realm's MCP resource URI), the full authorize → code →
//! token roundtrip (`aud = [client_id, resource]` on the access token, the
//! `resource` claim on the refresh token, the ID token untouched), the code
//! redemption restate/inherit/introduce rules (§2.2), the refresh
//! restate/omit/reject rules, rejection for every other grant, and PAR
//! push-time validation + pass-through.

use axum::http::StatusCode;
use base64::Engine;

use crate::harness::TestHarness;

const REDIRECT_URI: &str = "http://localhost:8080/cb";

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

/// The single allowlisted resource indicator for a realm: its MCP resource
/// URI, exactly as the RFC 9728 metadata document publishes it.
fn mcp_resource(harness: &TestHarness, realm: &str) -> String {
    format!("{}/realms/{realm}/mcp", harness.base_url)
}

fn auth_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/auth")
}

fn token_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token")
}

fn par_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/ext/par")
}

/// Percent-encode a query parameter value.
fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Decode the payload segment of a JWT without verifying the signature.
fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Extract a JSON body from a response.
async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// GET the authorization endpoint with raw query params.
async fn authorize(harness: &TestHarness, realm: &str, query: &str) -> axum::response::Response {
    harness.get(&format!("{}?{query}", auth_path(realm))).await
}

/// Drive the browser login for a pending flow; returns the authorization code.
async fn browser_login(
    harness: &TestHarness,
    realm: &str,
    location: &str,
    username: &str,
) -> String {
    assert!(location.contains("/login.html"), "expected login redirect, got: {location}");
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");
    let login_resp = harness
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            serde_json::json!({
                "execution_id": execution_id,
                "username": username,
                "password": "Password123!",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_json = json_body(login_resp).await;
    login_json["code"].as_str().expect("no code issued").to_string()
}

/// Standard code-flow authorize query; `extra_query` is appended verbatim
/// (already encoded).
fn code_flow_query(client: &issuerd_core::Client, extra_query: &str) -> String {
    format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=ri-state{}",
        client.client_id,
        enc(REDIRECT_URI),
        extra_query
    )
}

/// Authorize (expecting the login-page redirect) + log in → authorization code.
async fn run_code_flow(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    extra_query: &str,
) -> String {
    let resp = authorize(harness, realm, &code_flow_query(client, extra_query)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    browser_login(harness, realm, &location, username).await
}

/// Redeem an authorization code; returns (status, body) without asserting.
async fn redeem_code(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    code: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client.client_id.as_ref()),
        ("client_secret", client.secret.as_deref().unwrap_or("")),
    ];
    params.extend_from_slice(extra);
    let resp = harness.post_form(&token_path(realm), &params).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

/// Refresh grant; returns (status, body) without asserting.
async fn refresh(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    refresh_token: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client.client_id.as_ref()),
        ("client_secret", client.secret.as_deref().unwrap_or("")),
    ];
    params.extend_from_slice(extra);
    let resp = harness.post_form(&token_path(realm), &params).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

/// Assert the error is the RFC 8707 `invalid_target` code.
fn assert_invalid_target(json: &serde_json::Value) {
    assert_eq!(json["error"], "invalid_target", "body: {json}");
}

#[tokio::test]
async fn disabled_gate_rejects_resource_everywhere() {
    // Default harness: `[mcp] enabled = false`. Any present `resource` —
    // even a perfectly well-formed one — is refused fail-closed (§2.1).
    let harness = TestHarness::new().await;
    harness.create_realm("ri-off").await;
    let client = harness.create_client("ri-off", false).await;
    harness.create_user("ri-off", "anna", "Password123!").await;
    let resource = mcp_resource(&harness, "ri-off");

    // Authorization endpoint: the registered redirect_uri carries the error.
    let resp = authorize(
        &harness,
        "ri-off",
        &code_flow_query(&client, &format!("&resource={}", enc(&resource))),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains("error=invalid_target"), "location: {location}");
    assert!(location.contains("state=ri-state"), "state not preserved: {location}");

    // Token endpoint (password grant — the grant gate fires first).
    let resp = harness
        .post_form(
            &token_path("ri-off"),
            &[
                ("grant_type", "password"),
                ("username", "anna"),
                ("password", "Password123!"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("scope", "openid"),
                ("resource", &resource),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_invalid_target(&json_body(resp).await);

    // PAR endpoint.
    let resp = harness
        .post_form(
            &par_path("ri-off"),
            &[
                ("response_type", "code"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", REDIRECT_URI),
                ("scope", "openid"),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("resource", &resource),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_invalid_target(&json_body(resp).await);
}

#[tokio::test]
async fn malformed_resource_rejected_at_authorize_and_token() {
    let harness = harness_with_mcp_enabled().await;
    harness.create_realm("ri-malformed").await;
    let client = harness.create_client("ri-malformed", false).await;
    harness.create_user("ri-malformed", "boris", "Password123!").await;

    // RFC 8707 §2: absolute URI, no fragment component; present-but-empty is
    // rejected rather than silently dropped.
    for raw in [
        "not-a-uri",
        "/relative/path",
        "https://example.com/mcp#frag",
        "",
    ] {
        let resp = authorize(
            &harness,
            "ri-malformed",
            &code_flow_query(&client, &format!("&resource={}", enc(raw))),
        )
        .await;
        // The client+redirect_uri are known-good, so even the parse failure
        // rides the authorization error redirect (RFC 6749 §4.1.2.1).
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "input: {raw:?}");
        let location = resp.headers()["location"].to_str().unwrap().to_string();
        assert!(
            location.contains("error=invalid_target"),
            "input: {raw:?}, location: {location}"
        );
        assert!(location.contains("state=ri-state"), "state not preserved: {location}");

        let resp = harness
            .post_form(
                &token_path("ri-malformed"),
                &[
                    ("grant_type", "password"),
                    ("username", "boris"),
                    ("password", "Password123!"),
                    ("client_id", client.client_id.as_ref()),
                    ("client_secret", client.secret.as_deref().unwrap()),
                    ("resource", raw),
                ],
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "input: {raw:?}");
        assert_invalid_target(&json_body(resp).await);
    }
}

#[tokio::test]
async fn enabled_rejects_non_allowlisted_resource() {
    let harness = harness_with_mcp_enabled().await;
    harness.create_realm("ri-allow").await;
    harness.create_realm("ri-other").await;
    let client = harness.create_client("ri-allow", false).await;

    let good = mcp_resource(&harness, "ri-allow");
    for bad in [
        // Another realm's MCP resource.
        mcp_resource(&harness, "ri-other"),
        // Trailing slash, query, parent path — no normalization tricks.
        format!("{good}/"),
        format!("{good}?x=1"),
        mcp_resource(&harness, "ri-allow").trim_end_matches("/mcp").to_string(),
        // A different host entirely.
        "https://api.example.com/mcp".to_string(),
    ] {
        let resp = authorize(
            &harness,
            "ri-allow",
            &code_flow_query(&client, &format!("&resource={}", enc(&bad))),
        )
        .await;
        // Well-formed but not allowlisted: the client+redirect_uri are
        // known-good, so the error rides the authorization error redirect.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "input: {bad}");
        let location = resp.headers()["location"].to_str().unwrap().to_string();
        assert!(location.contains("error=invalid_target"), "input: {bad}, location: {location}");
        assert!(location.contains("state=ri-state"), "state not preserved: {location}");
    }
}

#[tokio::test]
async fn code_flow_binds_resource_as_access_token_audience() {
    let harness = harness_with_mcp_enabled().await;
    harness.create_realm("ri-flow").await;
    let client = harness.create_client("ri-flow", false).await;
    harness.create_user("ri-flow", "carol", "Password123!").await;
    let resource = mcp_resource(&harness, "ri-flow");

    let code = run_code_flow(
        &harness,
        "ri-flow",
        &client,
        "carol",
        &format!("&resource={}", enc(&resource)),
    )
    .await;
    let (status, json) = redeem_code(&harness, "ri-flow", &client, &code, &[]).await;
    assert_eq!(status, StatusCode::OK, "redemption failed: {json}");

    // RFC 8707 §2.1: the access token's audience is the client plus the
    // granted resource, client id first.
    let access_claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(access_claims["aud"], serde_json::json!([client.client_id.as_ref(), resource]));

    // The refresh token is the durable artifact of the grant: it carries
    // the resource claim.
    let refresh_claims = jwt_claims(json["refresh_token"].as_str().unwrap());
    assert_eq!(refresh_claims["resource"], serde_json::json!(resource));

    // The ID token is untouched: its audience stays the client alone.
    let id_claims = jwt_claims(json["id_token"].as_str().unwrap());
    assert_eq!(id_claims["aud"], client.client_id.as_ref());
}

#[tokio::test]
async fn code_redemption_restate_inherit_introduce() {
    let harness = harness_with_mcp_enabled().await;
    harness.create_realm("ri-redeem").await;
    let client = harness.create_client("ri-redeem", false).await;
    harness.create_user("ri-redeem", "dora", "Password123!").await;
    let resource = mcp_resource(&harness, "ri-redeem");
    let expected_aud = serde_json::json!([client.client_id.as_ref(), resource]);

    // (a) Restate verbatim: code granted the resource, token request
    // repeats it.
    let code = run_code_flow(
        &harness,
        "ri-redeem",
        &client,
        "dora",
        &format!("&resource={}", enc(&resource)),
    )
    .await;
    let (status, json) =
        redeem_code(&harness, "ri-redeem", &client, &code, &[("resource", &resource)]).await;
    assert_eq!(status, StatusCode::OK, "restate failed: {json}");
    assert_eq!(jwt_claims(json["access_token"].as_str().unwrap())["aud"], expected_aud);

    // (b) Inherit: code granted the resource, token request omits it.
    let code = run_code_flow(
        &harness,
        "ri-redeem",
        &client,
        "dora",
        &format!("&resource={}", enc(&resource)),
    )
    .await;
    let (status, json) = redeem_code(&harness, "ri-redeem", &client, &code, &[]).await;
    assert_eq!(status, StatusCode::OK, "inherit failed: {json}");
    assert_eq!(jwt_claims(json["access_token"].as_str().unwrap())["aud"], expected_aud);

    // (c) Introduce: the code carries no resource, the token request names
    // an allowlisted one (§2.2 — the AS may issue a token for it).
    let code = run_code_flow(&harness, "ri-redeem", &client, "dora", "").await;
    let (status, json) =
        redeem_code(&harness, "ri-redeem", &client, &code, &[("resource", &resource)]).await;
    assert_eq!(status, StatusCode::OK, "introduce failed: {json}");
    assert_eq!(jwt_claims(json["access_token"].as_str().unwrap())["aud"], expected_aud);

    // A contradicting pair (granted A, requested B with both allowlisted) is
    // unreachable here: the allowlist holds exactly one value per realm, so
    // any deviation dies at the grant gate as a non-allowlisted value.
}

#[tokio::test]
async fn refresh_restate_omit_and_reject() {
    let harness = harness_with_mcp_enabled().await;
    harness.create_realm("ri-refresh").await;
    let client = harness.create_client("ri-refresh", false).await;
    harness.create_user("ri-refresh", "erin", "Password123!").await;
    let resource = mcp_resource(&harness, "ri-refresh");
    let expected_aud = serde_json::json!([client.client_id.as_ref(), resource]);

    let code = run_code_flow(
        &harness,
        "ri-refresh",
        &client,
        "erin",
        &format!("&resource={}", enc(&resource)),
    )
    .await;
    let (status, json) = redeem_code(&harness, "ri-refresh", &client, &code, &[]).await;
    assert_eq!(status, StatusCode::OK, "redemption failed: {json}");
    let refresh_token = json["refresh_token"].as_str().unwrap().to_string();

    // Omit = inherit: the rotated pair keeps the grant's resource.
    let (status, json) = refresh(&harness, "ri-refresh", &client, &refresh_token, &[]).await;
    assert_eq!(status, StatusCode::OK, "inheriting refresh failed: {json}");
    assert_eq!(jwt_claims(json["access_token"].as_str().unwrap())["aud"], expected_aud);
    let rotated = json["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(jwt_claims(&rotated)["resource"], serde_json::json!(resource));

    // Restate verbatim: accepted, same binding.
    let (status, json) =
        refresh(&harness, "ri-refresh", &client, &rotated, &[("resource", &resource)]).await;
    assert_eq!(status, StatusCode::OK, "restating refresh failed: {json}");
    assert_eq!(jwt_claims(json["access_token"].as_str().unwrap())["aud"], expected_aud);
    let rotated = json["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(jwt_claims(&rotated)["resource"], serde_json::json!(resource));

    // A different value widens the grant — refused (§2.2). (Any value other
    // than the grant's also fails the allowlist gate first.)
    let (status, json) = refresh(
        &harness,
        "ri-refresh",
        &client,
        &rotated,
        &[("resource", "https://api.example.com/other")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_invalid_target(&json);

    // A resource-less grant cannot gain one at refresh time.
    let code = run_code_flow(&harness, "ri-refresh", &client, "erin", "").await;
    let (status, json) = redeem_code(&harness, "ri-refresh", &client, &code, &[]).await;
    assert_eq!(status, StatusCode::OK, "plain redemption failed: {json}");
    let plain_refresh = json["refresh_token"].as_str().unwrap().to_string();
    assert!(jwt_claims(&plain_refresh).get("resource").is_none());
    let (status, json) =
        refresh(&harness, "ri-refresh", &client, &plain_refresh, &[("resource", &resource)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_invalid_target(&json);
}

#[tokio::test]
async fn resource_rejected_for_other_grants() {
    let harness = harness_with_mcp_enabled().await;
    harness.create_realm("ri-grants").await;
    let client = harness.create_client("ri-grants", false).await;
    harness.create_user("ri-grants", "frank", "Password123!").await;
    let resource = mcp_resource(&harness, "ri-grants");

    // Password grant.
    let resp = harness
        .post_form(
            &token_path("ri-grants"),
            &[
                ("grant_type", "password"),
                ("username", "frank"),
                ("password", "Password123!"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("scope", "openid"),
                ("resource", &resource),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_invalid_target(&json_body(resp).await);

    // Client credentials grant.
    let resp = harness
        .post_form(
            &token_path("ri-grants"),
            &[
                ("grant_type", "client_credentials"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("resource", &resource),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_invalid_target(&json_body(resp).await);
}

#[tokio::test]
async fn par_push_validates_and_roundtrips_resource() {
    let harness = harness_with_mcp_enabled().await;
    harness.create_realm("ri-par").await;
    let client = harness.create_client("ri-par", false).await;
    harness.create_user("ri-par", "gwen", "Password123!").await;
    let resource = mcp_resource(&harness, "ri-par");

    // A non-allowlisted resource fails at push time (RFC 9126 §2.1 rule 3:
    // the pushed request is validated as an authorization request).
    let resp = harness
        .post_form(
            &par_path("ri-par"),
            &[
                ("response_type", "code"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", REDIRECT_URI),
                ("scope", "openid"),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("resource", "https://api.example.com/other"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_invalid_target(&json_body(resp).await);

    // An allowlisted resource rides the pushed request through the whole
    // flow and lands on the access token's audience.
    let resp = harness
        .post_form(
            &par_path("ri-par"),
            &[
                ("response_type", "code"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", REDIRECT_URI),
                ("scope", "openid"),
                ("state", "ri-par-state"),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("resource", &resource),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let request_uri = json_body(resp).await["request_uri"].as_str().unwrap().to_string();

    let resp = authorize(
        &harness,
        "ri-par",
        &format!("client_id={}&request_uri={}", client.client_id, request_uri.replace(':', "%3A")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let code = browser_login(&harness, "ri-par", &location, "gwen").await;

    let (status, json) = redeem_code(&harness, "ri-par", &client, &code, &[]).await;
    assert_eq!(status, StatusCode::OK, "PAR redemption failed: {json}");
    assert_eq!(
        jwt_claims(json["access_token"].as_str().unwrap())["aud"],
        serde_json::json!([client.client_id.as_ref(), resource])
    );
}
