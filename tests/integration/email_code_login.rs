// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Passwordless email-code login integration tests (Issuerd-only).
//!
//! Covers the full browser dance against an in-process server whose browser
//! flow is a custom `cookie` + `auth-email-code` flow: the login context
//! flag, the code-challenge page (masked email, resend form), wrong-code
//! re-render, resend, the unknown-address no-leak behavior, and the JSON
//! caller challenge contract. The minted code is captured from a recording
//! [`issuerd_core::EmailSender`] injected at state-construction time (the plugin
//! registry binds the mailer when it is built, so swapping
//! `state.email_sender` afterwards would not reach the authenticator).

use std::sync::Arc;

use axum::http::StatusCode;
use issuerd_server::{config::ServerConfig, state::ServerState};

use crate::harness::TestHarness;

/// Captures every outbound mail: (to, subject, text body, html body).
#[derive(Default)]
struct RecordingSender {
    sent: std::sync::Mutex<Vec<(String, String, String, Option<String>)>>,
}

#[async_trait::async_trait]
impl issuerd_core::EmailSender for RecordingSender {
    async fn send(
        &self,
        _realm: &issuerd_core::Realm,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: Option<String>,
    ) -> Result<(), issuerd_core::IssuerdError> {
        self.sent.lock().unwrap().push((
            to.to_string(),
            subject.to_string(),
            text_body.to_string(),
            html_body,
        ));
        Ok(())
    }
}

impl RecordingSender {
    fn mails(&self) -> Vec<(String, String, String, Option<String>)> {
        self.sent.lock().unwrap().clone()
    }
}

/// Harness wired with the recording sender (registry + state agree on it).
async fn email_code_harness() -> (TestHarness, Arc<RecordingSender>) {
    let config = ServerConfig::default();
    let recorder = Arc::new(RecordingSender::default());
    let state = ServerState::from_components_with_email_sender(
        &config,
        Arc::new(issuerd_storage::InMemoryStorage::new()),
        Arc::new(issuerd_cluster::InMemoryCache::new()),
        recorder.clone(),
    )
    .await
    .unwrap();
    (TestHarness::with_state(Arc::new(state)), recorder)
}

/// Create a realm in email-code mode bound to a custom browser flow:
/// `auth-cookie` alternative (SSO re-login), then `auth-email-code`
/// alternative. The code stage must sit in the alternative group — with this
/// executor an all-Attempted alternative group fails the flow immediately, so
/// a Required stage after a lone Alternative cookie stage would never run.
async fn create_email_code_realm(harness: &TestHarness, realm: &str) {
    let mut r = harness.create_realm(realm).await;
    r.attributes.insert("email_code_login".to_string(), "true".to_string());
    r.browser_flow = Some("email-code-browser".to_string());
    harness.storage.update_realm(&r).await.unwrap();

    let realm_id = issuerd_core::RealmId::new(realm).unwrap();
    let flow = issuerd_core::FlowConfig {
        alias: issuerd_core::Alias::new("email-code-browser").unwrap(),
        realm_id: realm_id.clone(),
        provider_id: "basic-flow".to_string(),
        top_level: true,
        built_in: false,
        stages: vec![
            issuerd_core::FlowStage {
                id: issuerd_core::FlowStageId::new("cookie-auth").unwrap(),
                requirement: issuerd_core::Requirement::Alternative,
                authenticator: issuerd_core::Alias::new("auth-cookie").unwrap(),
                priority: 1,
                sub_flow_alias: None,
                authenticator_config: None,
            },
            issuerd_core::FlowStage {
                id: issuerd_core::FlowStageId::new("email-code").unwrap(),
                requirement: issuerd_core::Requirement::Alternative,
                authenticator: issuerd_core::Alias::new("auth-email-code").unwrap(),
                priority: 2,
                sub_flow_alias: None,
                authenticator_config: None,
            },
        ],
    };
    harness.storage.create_flow_config(&realm_id, &flow).await.unwrap();
}

/// Start an authorization code flow and return the browser flow id.
async fn start_auth_flow(harness: &TestHarness, realm: &str, client_id: &str) -> String {
    let auth_path = format!(
        "/realms/{realm}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz"
    );
    let resp = harness.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id")
}

/// POST the browser login form (content-type form-urlencoded + flow cookie).
async fn submit_login_form(
    harness: &TestHarness,
    realm: &str,
    execution_id: &str,
    params: &[(&str, &str)],
) -> axum::response::Response {
    let mut all = vec![("execution_id", execution_id)];
    all.extend_from_slice(params);
    harness
        .post_form_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            &all,
            &TestHarness::flow_cookie(execution_id),
        )
        .await
}

/// Consume the response body as a UTF-8 string.
async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Extract the 6-digit code from a recorded mail's text body.
fn code_from_mail(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| l.len() == 6 && l.chars().all(|c| c.is_ascii_digit()))
        .expect("6-digit code in the mail text body")
        .to_string()
}

/// Exchange an authorization code for tokens; asserts success.
async fn exchange_code(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    code: &str,
) -> serde_json::Value {
    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/token"),
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn email_code_login_end_to_end() {
    let (harness, recorder) = email_code_harness().await;
    create_email_code_realm(&harness, "ec-e2e").await;
    let client = harness.create_client("ec-e2e", false).await;
    harness.create_user("ec-e2e", "alice", "Unused123!").await;

    // The login context advertises email-code mode for the login page…
    let resp = harness.get("/realms/ec-e2e/login/context").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ctx: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(ctx["email_code_login"], true);
    // …while a regular realm reports `false`.
    let resp = harness.get("/realms/master/login/context").await;
    let ctx: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(ctx["email_code_login"], false);

    // Submitting the email address mints and mails the code, then renders
    // the code page with the masked destination and a resend form.
    let exec = start_auth_flow(&harness, "ec-e2e", client.client_id.as_ref()).await;
    let resp =
        submit_login_form(&harness, "ec-e2e", &exec, &[("username", "alice@example.com")]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Check your email"), "expected code page: {page}");
    assert!(page.contains("a***@e***.com"), "expected masked email: {page}");
    assert!(page.contains("name=\"otp\""), "expected otp input: {page}");
    assert!(page.contains("name=\"resend\""), "expected resend form: {page}");
    assert!(
        page.contains(&format!("value=\"{exec}\"")),
        "expected hidden execution id in page: {page}"
    );

    let mails = recorder.mails();
    assert_eq!(mails.len(), 1, "exactly one mail: {mails:?}");
    assert_eq!(mails[0].0, "alice@example.com");
    assert_eq!(mails[0].1, "Your sign-in code");
    let code = code_from_mail(&mails[0].2);
    let html = mails[0].3.as_deref().expect("multipart mail with HTML part");
    assert!(html.contains(&code), "code missing from HTML body");

    // The correct code completes the login with an authorization code.
    let resp = submit_login_form(&harness, "ec-e2e", &exec, &[("otp", &code)]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("http://localhost:8080/cb?"), "unexpected: {location}");
    let auth_code = TestHarness::extract_query_param(location, "code").expect("code in redirect");
    let tokens = exchange_code(&harness, "ec-e2e", &client, &auth_code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn email_code_wrong_code_renders_error_and_resend_mails_fresh_code() {
    let (harness, recorder) = email_code_harness().await;
    create_email_code_realm(&harness, "ec-resend").await;
    let client = harness.create_client("ec-resend", false).await;
    harness.create_user("ec-resend", "bob", "Unused123!").await;

    let exec = start_auth_flow(&harness, "ec-resend", client.client_id.as_ref()).await;
    let resp =
        submit_login_form(&harness, "ec-resend", &exec, &[("username", "bob@example.com")]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let first_code = code_from_mail(&recorder.mails()[0].2);

    // A wrong code re-renders the page with the error banner.
    let wrong = if first_code == "000000" {
        "000001"
    } else {
        "000000"
    };
    let resp = submit_login_form(&harness, "ec-resend", &exec, &[("otp", wrong)]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Invalid or expired code."), "expected error banner: {page}");

    // Resend mails a fresh code and re-renders the page without an error.
    let resp = submit_login_form(&harness, "ec-resend", &exec, &[("resend", "1")]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Check your email"), "expected code page: {page}");
    assert!(!page.contains("Invalid or expired code."), "resend must not error: {page}");
    let mails = recorder.mails();
    assert_eq!(mails.len(), 2, "resend must mail a fresh code");
    let second_code = code_from_mail(&mails[1].2);

    // The fresh code completes the login.
    let resp = submit_login_form(&harness, "ec-resend", &exec, &[("otp", &second_code)]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let auth_code = TestHarness::extract_query_param(location, "code").expect("code in redirect");
    let tokens = exchange_code(&harness, "ec-resend", &client, &auth_code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn email_code_unknown_address_never_leaks_account_existence() {
    let (harness, recorder) = email_code_harness().await;
    create_email_code_realm(&harness, "ec-unknown").await;
    let client = harness.create_client("ec-unknown", false).await;

    let exec = start_auth_flow(&harness, "ec-unknown", client.client_id.as_ref()).await;
    let resp =
        submit_login_form(&harness, "ec-unknown", &exec, &[("username", "ghost@example.com")])
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Check your email"), "same page as for real users: {page}");
    assert!(
        page.contains("Enter the 6-digit code we sent to your email address."),
        "generic copy without an address: {page}"
    );
    assert!(!page.contains("ghost"), "address must not be reflected: {page}");
    assert!(recorder.mails().is_empty(), "no mail for unknown addresses");

    // A code submission verifies nothing and just re-renders the page.
    let resp = submit_login_form(&harness, "ec-unknown", &exec, &[("otp", "123456")]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Check your email"), "still the code page: {page}");

    // Resend without a bound user sends nothing either.
    let resp = submit_login_form(&harness, "ec-unknown", &exec, &[("resend", "1")]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(recorder.mails().is_empty(), "no mail without a bound user");
}

#[tokio::test]
async fn email_code_json_caller_gets_challenge_contract() {
    let (harness, recorder) = email_code_harness().await;
    create_email_code_realm(&harness, "ec-json").await;
    let client = harness.create_client("ec-json", false).await;
    harness.create_user("ec-json", "carol", "Unused123!").await;

    // JSON callers never get the HTML page: 401 + machine-readable challenge.
    let exec = start_auth_flow(&harness, "ec-json", client.client_id.as_ref()).await;
    let resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=ec-json",
            serde_json::json!({
                "execution_id": exec,
                "username": "carol@example.com",
            }),
            &TestHarness::flow_cookie(&exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(body["error"], "authentication_challenge");
    assert_eq!(body["challenge"], "email_code");

    let code = code_from_mail(&recorder.mails()[0].2);

    // The same flow completes when the code is included in the JSON POST.
    let resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=ec-json",
            serde_json::json!({
                "execution_id": exec,
                "otp": code,
            }),
            &TestHarness::flow_cookie(&exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert!(body["code"].as_str().unwrap().len() > 10);
}
