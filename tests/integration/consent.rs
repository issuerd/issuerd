// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Consent screen integration tests.

//! Consent screen integration tests (Issuerd-only).
//!
//! A client with `consent_required = true` pauses the login after successful
//! authentication (and after any required actions) until the user grants the
//! requested scopes on the consent page. The grant is persisted (upsert) and
//! consulted on later logins: the page is skipped while the grant covers the
//! requested scopes, `prompt=consent` forces it regardless, revoking the
//! grant via the account API re-triggers it, denial redirects `access_denied`
//! to the client's redirect URI, and `prompt=none` never renders the page —
//! it reports `consent_required` to the client instead (OIDC Core 3.1.2.6).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crate::harness::TestHarness;

/// Create a client with `consent_required` flipped on.
async fn create_consent_client(harness: &TestHarness, realm: &str) -> issuerd_core::Client {
    let mut client = harness.create_client(realm, false).await;
    client.consent_required = true;
    harness.storage.update_client(&client.realm_id.clone(), &client).await.unwrap();
    client
}

/// Start an authorization code flow (extra raw query params appended) and
/// return the browser flow id.
async fn start_auth_flow(
    harness: &TestHarness,
    realm: &str,
    client_id: &str,
    extra: &str,
) -> String {
    let auth_path = format!(
        "/realms/{realm}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz{extra}"
    );
    let resp = harness.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    TestHarness::extract_query_param(&location, "execution_id").expect("missing execution_id")
}

/// POST the browser login form.
async fn submit_login_form(
    harness: &TestHarness,
    realm: &str,
    execution_id: &str,
    username: &str,
    password: &str,
) -> axum::response::Response {
    harness
        .post_form_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            &[
                ("execution_id", execution_id),
                ("username", username),
                ("password", password),
            ],
            &TestHarness::flow_cookie(execution_id),
        )
        .await
}

fn location_header(resp: &axum::response::Response) -> String {
    resp.headers().get("location").unwrap().to_str().unwrap().to_string()
}

/// Extract the consent execution id from a `/realms/{r}/login/consent/{e}`
/// redirect location.
fn consent_execution(location: &str) -> &str {
    location.rsplit('/').next().expect("consent execution segment")
}

/// Walk a fresh browser-form login up to the consent page; returns the
/// consent-page URL (also the POST target).
async fn reach_consent_page(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    extra: &str,
) -> String {
    let exec = start_auth_flow(harness, realm, client.client_id.as_ref(), extra).await;
    let resp = submit_login_form(harness, realm, &exec, username, "Password123!").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = location_header(&resp);
    assert!(
        location.contains("/login/consent/"),
        "expected consent redirect, got: {location}"
    );
    location
}

#[tokio::test]
async fn consent_required_client_pauses_login_then_grant_is_persisted_and_reused() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("consent-basic").await;
    let client = create_consent_client(&harness, "consent-basic").await;
    let user = harness.create_user("consent-basic", "anna", "Password123!").await;

    // First login pauses on the consent page.
    let consent_url = reach_consent_page(&harness, "consent-basic", &client, "anna", "").await;
    let consent_exec = consent_execution(&consent_url).to_string();

    // The page renders the client display name and the requested scopes.
    let page = harness.get(&consent_url).await;
    assert_eq!(page.status(), StatusCode::OK);
    let body = axum::body::to_bytes(page.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("Grant access"), "consent title missing: {body}");
    assert!(body.contains("Test Client"), "client display name missing: {body}");
    assert!(body.contains("<li>openid</li>"), "scope list missing: {body}");

    // Approve: the paused login resumes and lands on the client redirect URI
    // with an authorization code.
    let resp = harness
        .post_form_with_cookie(
            &consent_url,
            &[("decision", "allow")],
            &TestHarness::flow_cookie(&consent_exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = location_header(&resp);
    assert!(
        location.starts_with("http://localhost:8080/cb") && location.contains("code="),
        "expected code redirect, got: {location}"
    );
    assert!(location.contains("state=xyz"), "state missing: {location}");

    // The grant is persisted against the internal client id.
    let consents = harness.storage.get_consents(&realm.id, &user.id).await.unwrap();
    assert_eq!(consents.len(), 1);
    assert_eq!(consents[0].client_id, client.id);
    assert!(consents[0].granted_scopes.contains("openid"));

    // Second login for the same client skips the page entirely.
    let exec = start_auth_flow(&harness, "consent-basic", client.client_id.as_ref(), "").await;
    let resp = submit_login_form(&harness, "consent-basic", &exec, "anna", "Password123!").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = location_header(&resp);
    assert!(location.contains("code="), "expected direct code redirect, got: {location}");
}

#[tokio::test]
async fn prompt_consent_forces_page_despite_stored_grant() {
    let harness = TestHarness::new().await;
    harness.create_realm("consent-prompt").await;
    let client = create_consent_client(&harness, "consent-prompt").await;
    harness.create_user("consent-prompt", "boris", "Password123!").await;

    // Grant once...
    let consent_url = reach_consent_page(&harness, "consent-prompt", &client, "boris", "").await;
    let consent_exec = consent_execution(&consent_url).to_string();
    let resp = harness
        .post_form_with_cookie(
            &consent_url,
            &[("decision", "allow")],
            &TestHarness::flow_cookie(&consent_exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // ...a plain login now skips the page...
    let exec = start_auth_flow(&harness, "consent-prompt", client.client_id.as_ref(), "").await;
    let resp = submit_login_form(&harness, "consent-prompt", &exec, "boris", "Password123!").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location_header(&resp).contains("code="));

    // ...but prompt=consent forces it again.
    reach_consent_page(&harness, "consent-prompt", &client, "boris", "&prompt=consent").await;
}

#[tokio::test]
async fn consent_denied_redirects_access_denied_to_client() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("consent-deny").await;
    let client = create_consent_client(&harness, "consent-deny").await;
    let user = harness.create_user("consent-deny", "carla", "Password123!").await;

    let consent_url = reach_consent_page(&harness, "consent-deny", &client, "carla", "").await;
    let consent_exec = consent_execution(&consent_url).to_string();
    let resp = harness
        .post_form_with_cookie(
            &consent_url,
            &[("decision", "deny")],
            &TestHarness::flow_cookie(&consent_exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = location_header(&resp);
    assert!(
        location.starts_with("http://localhost:8080/cb?")
            && location.contains("error=access_denied"),
        "expected access_denied redirect, got: {location}"
    );
    assert!(location.contains("state=xyz"), "state missing: {location}");

    // Denial persists nothing.
    assert!(harness.storage.get_consents(&realm.id, &user.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn consent_post_without_flow_cookie_is_forbidden() {
    let harness = TestHarness::new().await;
    harness.create_realm("consent-csrf").await;
    let client = create_consent_client(&harness, "consent-csrf").await;
    harness.create_user("consent-csrf", "dora", "Password123!").await;

    let consent_url = reach_consent_page(&harness, "consent-csrf", &client, "dora", "").await;
    let resp = harness.post_form(&consent_url, &[("decision", "allow")]).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn prompt_none_with_live_sso_session_returns_consent_required() {
    let harness = TestHarness::new().await;
    harness.create_realm("consent-none").await;
    // Client A establishes the SSO session (no consent required)...
    let client_a = harness.create_client("consent-none", false).await;
    // ...client B requires consent and has no stored grant.
    let client_b = create_consent_client(&harness, "consent-none").await;
    harness.create_user("consent-none", "emil", "Password123!").await;

    let exec = start_auth_flow(&harness, "consent-none", client_a.client_id.as_ref(), "").await;
    let resp = submit_login_form(&harness, "consent-none", &exec, "emil", "Password123!").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookies: Vec<String> = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let sso = cookies
        .iter()
        .find_map(|c| {
            c.strip_prefix("issuerd_session_consent-none=")
                .map(|rest| rest.split(';').next().unwrap().to_string())
        })
        .expect("issuerd_session cookie");

    // prompt=none + consent pending ⇒ OIDC Core 3.1.2.6 consent_required.
    let auth_path = format!(
        "/realms/consent-none/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz&prompt=none",
        client_b.client_id
    );
    let req = Request::builder()
        .method("GET")
        .uri(&auth_path)
        .header("cookie", format!("issuerd_session_consent-none={sso}"))
        .body(Body::empty())
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = location_header(&resp);
    assert!(
        location.starts_with("http://localhost:8080/cb?")
            && location.contains("error=consent_required"),
        "expected consent_required redirect, got: {location}"
    );
    assert!(location.contains("state=xyz"), "state missing: {location}");
}

#[tokio::test]
async fn revoked_consent_via_account_api_retriggers_page() {
    let harness = TestHarness::new().await;
    harness.create_realm("consent-revoke").await;
    let client = create_consent_client(&harness, "consent-revoke").await;
    // A second, consent-free client mints the account-console token.
    let account_client = harness.create_client("consent-revoke", false).await;
    harness.create_user("consent-revoke", "frida", "Password123!").await;

    // Grant consent.
    let consent_url = reach_consent_page(&harness, "consent-revoke", &client, "frida", "").await;
    let consent_exec = consent_execution(&consent_url).to_string();
    let resp = harness
        .post_form_with_cookie(
            &consent_url,
            &[("decision", "allow")],
            &TestHarness::flow_cookie(&consent_exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Revoke through the account console API.
    let token = harness
        .authenticate_user(
            "consent-revoke",
            account_client.client_id.as_ref(),
            "frida",
            "Password123!",
        )
        .await
        .access_token;
    let resp = harness
        .delete_auth(
            &format!("/realms/consent-revoke/account/api/consents/{}", client.client_id),
            &token,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The next login asks again.
    reach_consent_page(&harness, "consent-revoke", &client, "frida", "").await;
}

#[tokio::test]
async fn json_login_pause_returns_consent_redirect_without_code() {
    let harness = TestHarness::new().await;
    harness.create_realm("consent-json").await;
    let client = create_consent_client(&harness, "consent-json").await;
    harness.create_user("consent-json", "greta", "Password123!").await;

    let exec = start_auth_flow(&harness, "consent-json", client.client_id.as_ref(), "").await;
    // SPA login (JSON body): the consent pause is reported as a redirect_uri
    // pointing at the consent page, with no code.
    let resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=consent-json",
            serde_json::json!({
                "execution_id": exec,
                "username": "greta",
                "password": "Password123!",
            }),
            &TestHarness::flow_cookie(&exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let redirect = json["redirect_uri"].as_str().expect("consent redirect_uri");
    assert!(redirect.contains("/login/consent/"), "got: {redirect}");
    assert!(json["code"].is_null(), "no code before consent: {json}");
}
