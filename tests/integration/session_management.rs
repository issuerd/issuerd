// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OIDC Session Management 1.0 integration tests (Issuerd-only).

//! OIDC Session Management 1.0 (Issuerd-only).
//!
//! Covered: `session_state` in every success authorization response (and the
//! SPA `LoginResponse`), the `issuerd_session_state_{realm}` companion cookie
//! written at login (JS-readable, SameSite posture per TLS), the
//! `check_session_iframe` OP page (discovery advertisement + the self-contained
//! postMessage handler), and the companion-cookie clear on every
//! browser-present logout path.

use std::collections::HashMap;

use axum::http::StatusCode;
use base64::Engine;

use crate::harness::TestHarness;

const REDIRECT_URI: &str = "http://localhost:8080/cb";
const PASSWORD: &str = "Password123!";

fn auth_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/auth")
}

fn token_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token")
}

fn iframe_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/check_session_iframe")
}

fn authz_query(client: &issuerd_core::Client, response_type: &str, extra: &str) -> String {
    format!(
        "response_type={}&client_id={}&redirect_uri={REDIRECT_URI}&scope=openid&state=s-1{extra}",
        response_type.replace(' ', "%20"),
        client.client_id,
    )
}

/// Decode a JWT's payload segment without verifying the signature.
fn jwt_payload(token: &str) -> serde_json::Value {
    let segment = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(segment).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The authorization response's parameter map, from whichever channel the
/// Location carries (query for the code flow, fragment for token-bearing
/// response types).
fn params_of(location: &str) -> HashMap<String, String> {
    let url = url::Url::parse(location).expect("location is a URL");
    let encoded = [url.query(), url.fragment()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("&");
    url::form_urlencoded::parse(encoded.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// All `Set-Cookie` response headers, as strings.
fn set_cookies(resp: &axum::response::Response) -> Vec<String> {
    resp.headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// Authorize → expect the login-page redirect → form-login (the browser
/// path, so the answer is the packaged authorization response) → return it.
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

/// A fresh realm + confidential client + user on a fresh harness.
async fn fresh_fixture() -> (TestHarness, issuerd_core::Client) {
    let harness = TestHarness::new().await;
    harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    harness.create_user("test", "alice", PASSWORD).await;
    (harness, client)
}

/// Login and return `(authorization response, session_state)`.
async fn login_with_session_state(
    harness: &TestHarness,
    client: &issuerd_core::Client,
) -> (axum::response::Response, String) {
    let resp = run_flow(harness, "test", &authz_query(client, "code", ""), "alice").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let session_state = params
        .get("session_state")
        .expect("session_state in the authorization response")
        .clone();
    (resp, session_state)
}

// ---------------------------------------------------------------------------
// session_state in authorization responses (+ the companion cookie)
// ---------------------------------------------------------------------------

/// The code flow's authorization response carries `session_state`; the login
/// response sets the companion cookie with the same value, JS-readable
/// (no HttpOnly), SameSite=Lax on plain HTTP; and the redeemed ID token's
/// `sid` is the same value.
#[tokio::test]
async fn code_flow_sets_session_state_and_companion_cookie() {
    let (harness, client) = fresh_fixture().await;

    let (resp, session_state) = login_with_session_state(&harness, &client).await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);

    // The companion cookie carries the session_state, JS-readable.
    let companion = set_cookies(&resp)
        .into_iter()
        .find(|c| c.starts_with("issuerd_session_state_test="))
        .expect("companion cookie set at login");
    assert!(
        companion.starts_with(&format!("issuerd_session_state_test={session_state};")),
        "cookie value is the session id: {companion}"
    );
    assert!(companion.contains("SameSite=Lax"), "plain-HTTP posture: {companion}");
    assert!(companion.contains("Path=/"), "{companion}");
    assert!(!companion.contains("HttpOnly"), "the OP iframe's JS must read it: {companion}");
    // The SSO cookie is untouched by all this.
    assert!(set_cookies(&resp)
        .into_iter()
        .any(|c| c.starts_with("issuerd_session_") && c.contains("HttpOnly")));

    // The id_token's sid is the same value.
    let resp = harness
        .post_form(
            &token_path("test"),
            &[
                ("grant_type", "authorization_code"),
                ("code", &params["code"]),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let id_token = jwt_payload(json["id_token"].as_str().unwrap());
    assert_eq!(id_token["sid"].as_str().unwrap(), session_state);
}

/// Every token-bearing type carries `session_state` in the fragment, and the
/// SPA (JSON) login path reports it as well.
#[tokio::test]
async fn hybrid_flow_carries_session_state_and_spa_login_reports_it() {
    let (harness, client) = fresh_fixture().await;

    // Browser path: code id_token token → fragment carries session_state,
    // and the id_token's sid matches.
    let resp = run_flow(
        &harness,
        "test",
        &authz_query(&client, "code id_token token", "&nonce=n-1"),
        "alice",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let session_state = params.get("session_state").expect("session_state in fragment");
    let id_token = jwt_payload(&params["id_token"]);
    assert_eq!(id_token["sid"].as_str().unwrap(), session_state);

    // SPA path (JSON login): the typed LoginResponse carries session_state.
    let (harness, client) = fresh_fixture().await;
    let resp = harness
        .get(&format!("{}?{}", auth_path("test"), authz_query(&client, "code", "")))
        .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let execution_id =
        TestHarness::extract_query_param(&location, "execution_id").expect("missing execution_id");
    let resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=test",
            serde_json::json!({
                "execution_id": execution_id,
                "username": "alice",
                "password": PASSWORD,
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookies = set_cookies(&resp);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["session_state"].as_str().is_some_and(|s| !s.is_empty()), "{json}");
    assert!(json["code"].is_string());
    // The companion cookie is set on the SPA path too.
    assert!(cookies.into_iter().any(|c| c.starts_with("issuerd_session_state_test=")));
}

// ---------------------------------------------------------------------------
// check_session_iframe
// ---------------------------------------------------------------------------

/// Discovery advertises the OP iframe (unconditionally), and the endpoint
/// serves the self-contained postMessage page.
#[tokio::test]
async fn discovery_advertises_and_serves_check_session_iframe() {
    let (harness, _client) = fresh_fixture().await;

    // Discovery advertises it.
    let resp = harness.get("/realms/test/.well-known/openid-configuration").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["check_session_iframe"].as_str().unwrap(),
        format!("{}/realms/test/protocol/openid-connect/check_session_iframe", harness.base_url)
    );

    // The endpoint serves the self-contained page (no-store, text/html).
    let resp = harness.get(&iframe_path("test")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get(axum::http::header::CACHE_CONTROL).unwrap(), "no-store");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("addEventListener"), "{html}");
    assert!(html.contains("postMessage"), "{html}");
    assert!(html.contains("issuerd_session_state_test"), "{html}");
    assert!(!html.contains("src="), "self-contained: {html}");

    // Unknown realm: 404.
    let resp = harness.get(&iframe_path("no-such-realm")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Logout clears the companion cookie
// ---------------------------------------------------------------------------

/// RP-initiated logout clears the companion cookie (the next RP iframe poll
/// must answer "changed").
#[tokio::test]
async fn rp_initiated_logout_clears_the_companion_cookie() {
    let (harness, client) = fresh_fixture().await;
    let (_resp, session_state) = login_with_session_state(&harness, &client).await;

    // Redeem for the id_token hint.
    let location = _resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let resp = harness
        .post_form(
            &token_path("test"),
            &[
                ("grant_type", "authorization_code"),
                ("code", &params["code"]),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let id_token = json["id_token"].as_str().unwrap();

    // Logout (GET with the hint, no redirect target → confirmation page).
    let resp = harness
        .get(&format!("/realms/test/protocol/openid-connect/logout?id_token_hint={id_token}"))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let clear = set_cookies(&resp)
        .into_iter()
        .find(|c| c.starts_with("issuerd_session_state_test="))
        .expect("companion cookie cleared at logout");
    assert!(clear.contains("Max-Age=0"), "{clear}");
    assert!(clear.contains("Path=/"), "{clear}");
    let _ = session_state;
}

/// The SPA logout API clears the companion cookie alongside the SSO/remember
/// cookies.
#[tokio::test]
async fn spa_logout_api_clears_the_companion_cookie() {
    let (harness, client) = fresh_fixture().await;
    let (_resp, session_state) = login_with_session_state(&harness, &client).await;

    // The browser sends the companion cookie; the logout response clears it.
    let resp = harness
        .post_form_with_cookie(
            "/api/v1/auth/logout",
            &[],
            &format!("issuerd_session_state_test={session_state}"),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let clear = set_cookies(&resp)
        .into_iter()
        .find(|c| c.starts_with("issuerd_session_state_test="))
        .expect("companion cookie cleared by the SPA logout API");
    assert!(clear.contains("Max-Age=0"), "{clear}");
}
