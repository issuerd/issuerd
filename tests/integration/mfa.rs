// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! MFA (TOTP) integration tests (Issuerd-only).
//!
//! Covers the browser second-factor challenge (OTP page after a successful
//! password check, wrong-code re-render, replay rejection), the JSON-caller
//! challenge contract, the CONFIGURE_TOTP required-action enrollment loop,
//! and the account console self-service enrollment endpoints
//! (start/verify/delete).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use issuerd_auth_flow::totp;
use issuerd_core::{Credential, CredentialId, CredentialType, OtpHashAlgorithm};
use tower::ServiceExt;

use crate::harness::TestHarness;

/// Standard RFC 6238 Appendix B SHA-1 test key, base32-encoded.
const TEST_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// Minimal RFC 4648 base32 decode (padding optional, whitespace ignored),
/// mirroring the crate-private decoder in `issuerd_auth_flow::totp` so tests can
/// derive the raw key from a server-generated secret.
fn base32_decode(input: &str) -> Vec<u8> {
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in input.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=') {
        let upper = c.to_ascii_uppercase();
        let value = match upper {
            b'A'..=b'Z' => u32::from(upper - b'A'),
            b'2'..=b'7' => u32::from(upper - b'2') + 26,
            _ => panic!("invalid base32 character: {}", c as char),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

/// Current 6-digit code for a base32 secret under the default OTP policy.
fn current_code(secret_b32: &str) -> String {
    let key = base32_decode(secret_b32);
    let step = issuerd_core::utils::now_secs() / 30;
    totp::totp_at(&key, step, 6, &OtpHashAlgorithm::HmacSha1)
}

/// Code for the NEXT step. Accepted via the look-ahead window; used right
/// after an enrollment/login consumed the current step, when the replay
/// watermark rejects the current-step code.
fn next_code(secret_b32: &str) -> String {
    let key = base32_decode(secret_b32);
    let step = issuerd_core::utils::now_secs() / 30;
    totp::totp_at(&key, step + 1, 6, &OtpHashAlgorithm::HmacSha1)
}

/// A code that is definitely NOT valid for the secret right now (checked
/// against the full acceptance window, so no accidental near-step match).
fn wrong_code(secret_b32: &str) -> String {
    let policy = issuerd_core::OtpPolicy::default();
    let now = issuerd_core::utils::now_secs();
    for n in 0..1000u32 {
        let candidate = format!("{n:06}");
        if totp::verify(secret_b32, &candidate, now, &policy, None).is_none() {
            return candidate;
        }
    }
    panic!("no wrong code found in first 1000 candidates");
}

/// Attach a TOTP credential with the standard test secret to a user.
async fn add_totp_credential(harness: &TestHarness, realm: &str, user: &issuerd_core::User) {
    let realm_id = issuerd_core::RealmId::new(realm).unwrap();
    let cred = Credential {
        id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: CredentialType::Totp,
        user_label: None,
        created_date: chrono::Utc::now(),
        secret_data: TEST_SECRET_B32.as_bytes().to_vec(),
        credential_data: serde_json::json!({
            "algorithm": "HmacSHA1",
            "digits": 6,
            "period": 30,
            "last_used_step": null,
        }),
        priority: 0,
    };
    harness.storage.create_credential(&realm_id, &user.id, &cred).await.unwrap();
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

/// Extract the code out of a 303 client redirect.
fn code_from_redirect(resp: &axum::response::Response) -> String {
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("http://localhost:8080/cb?"), "unexpected: {location}");
    TestHarness::extract_query_param(location, "code").expect("code in redirect")
}

// ---------------------------------------------------------------------------
// Browser second-factor challenge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn otp_login_end_to_end() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("mfa-e2e").await;
    let client = harness.create_client("mfa-e2e", false).await;
    let user = harness.create_user("mfa-e2e", "mia", "Password123!").await;
    add_totp_credential(&harness, "mfa-e2e", &user).await;

    // Password check succeeds, then the flow pauses on the OTP page.
    let exec = start_auth_flow(&harness, "mfa-e2e", client.client_id.as_ref()).await;
    let resp = submit_login_form(
        &harness,
        "mfa-e2e",
        &exec,
        &[("username", "mia"), ("password", "Password123!")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Two-factor authentication"), "expected OTP page: {page}");
    assert!(page.contains("name=\"otp\""), "expected otp input: {page}");
    assert!(
        page.contains(&format!("value=\"{exec}\"")),
        "expected hidden execution id in page: {page}"
    );

    // A wrong code re-renders the page with the error banner (never a Failure
    // — a swallowed conditional-stage failure would bypass the factor).
    let resp =
        submit_login_form(&harness, "mfa-e2e", &exec, &[("otp", &wrong_code(TEST_SECRET_B32))])
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Invalid one-time code."), "expected error banner: {page}");

    // The correct code completes the login with a code redirect.
    let resp =
        submit_login_form(&harness, "mfa-e2e", &exec, &[("otp", &current_code(TEST_SECRET_B32))])
            .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let code = code_from_redirect(&resp);

    // The code redeems into a full token set.
    let tokens = exchange_code(&harness, "mfa-e2e", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
    assert!(tokens["refresh_token"].as_str().is_some());
}

#[tokio::test]
async fn otp_json_caller_gets_challenge_contract() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("mfa-json").await;
    let client = harness.create_client("mfa-json", false).await;
    let user = harness.create_user("mfa-json", "jake", "Password123!").await;
    add_totp_credential(&harness, "mfa-json", &user).await;

    // JSON callers never get the HTML page: 401 + machine-readable challenge.
    let exec = start_auth_flow(&harness, "mfa-json", client.client_id.as_ref()).await;
    let resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=mfa-json",
            serde_json::json!({
                "execution_id": exec,
                "username": "jake",
                "password": "Password123!",
            }),
            &TestHarness::flow_cookie(&exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(body["error"], "authentication_challenge");
    assert_eq!(body["challenge"], "otp");

    // The same flow completes when the code is included in the JSON POST.
    let resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=mfa-json",
            serde_json::json!({
                "execution_id": exec,
                "otp": current_code(TEST_SECRET_B32),
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

#[tokio::test]
async fn user_without_totp_logs_in_unchanged() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("mfa-none").await;
    let client = harness.create_client("mfa-none", false).await;
    let _user = harness.create_user("mfa-none", "noah", "Password123!").await;

    // No TOTP credential: the conditional stage passes through and the login
    // completes in one POST, exactly as before MFA was added.
    let exec = start_auth_flow(&harness, "mfa-none", client.client_id.as_ref()).await;
    let resp = submit_login_form(
        &harness,
        "mfa-none",
        &exec,
        &[("username", "noah"), ("password", "Password123!")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let code = code_from_redirect(&resp);
    let tokens = exchange_code(&harness, "mfa-none", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn otp_replay_is_rejected() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("mfa-replay").await;
    let client = harness.create_client("mfa-replay", false).await;
    let user = harness.create_user("mfa-replay", "ruth", "Password123!").await;
    add_totp_credential(&harness, "mfa-replay", &user).await;

    // First login consumes the code (the matched step is persisted as the
    // replay watermark on the credential).
    let code_value = current_code(TEST_SECRET_B32);
    let exec = start_auth_flow(&harness, "mfa-replay", client.client_id.as_ref()).await;
    let resp = submit_login_form(
        &harness,
        "mfa-replay",
        &exec,
        &[("username", "ruth"), ("password", "Password123!")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = submit_login_form(&harness, "mfa-replay", &exec, &[("otp", &code_value)]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Second login with the SAME code: rejected even while the code is still
    // inside the validity window.
    let exec = start_auth_flow(&harness, "mfa-replay", client.client_id.as_ref()).await;
    let resp = submit_login_form(
        &harness,
        "mfa-replay",
        &exec,
        &[("username", "ruth"), ("password", "Password123!")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = submit_login_form(&harness, "mfa-replay", &exec, &[("otp", &code_value)]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Invalid one-time code."), "expected replay rejection: {page}");
}

// ---------------------------------------------------------------------------
// CONFIGURE_TOTP required action
// ---------------------------------------------------------------------------

#[tokio::test]
async fn configure_totp_required_action_e2e() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("mfa-enroll").await;
    let client = harness.create_client("mfa-enroll", false).await;
    let mut user = harness.create_user("mfa-enroll", "emma", "Password123!").await;
    user.required_actions = vec!["CONFIGURE_TOTP".to_string()];
    let realm_id = issuerd_core::RealmId::new("mfa-enroll").unwrap();
    harness.storage.update_user(&realm_id, &user).await.unwrap();

    // Login pauses on the required-action continuation.
    let exec = start_auth_flow(&harness, "mfa-enroll", client.client_id.as_ref()).await;
    let resp = submit_login_form(
        &harness,
        "mfa-enroll",
        &exec,
        &[("username", "emma"), ("password", "Password123!")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(
        location.starts_with("/realms/mfa-enroll/login/required-action/"),
        "expected continuation redirect, got {location}"
    );
    let continuation_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("continuation flow cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // The enrollment page shows the pending secret (grouped base32) + QR SVG.
    let resp = harness.get(&location).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Configure authenticator app"), "expected enroll page: {page}");
    assert!(page.contains("<svg"), "expected QR svg: {page}");
    let secret_b32 = extract_enrollment_secret(&page);
    assert!(!secret_b32.is_empty(), "no base32 secret in page: {page}");

    // Wrong code: page re-renders with the error, enrollment NOT completed.
    let resp = harness
        .post_form_with_cookie(
            &location,
            &[("totp_code", &wrong_code(&secret_b32))],
            &continuation_cookie,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let resp = harness.get(&location).await;
    let page = body_string(resp).await;
    assert!(page.contains("Invalid authenticator code"), "expected error: {page}");

    // Correct code: continuation finishes with the client redirect.
    let resp = harness
        .post_form_with_cookie(
            &location,
            &[("totp_code", &current_code(&secret_b32))],
            &continuation_cookie,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let redirect = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(redirect.starts_with("http://localhost:8080/cb?"), "unexpected: {redirect}");
    let code = TestHarness::extract_query_param(&redirect, "code").expect("code in redirect");
    let tokens = exchange_code(&harness, "mfa-enroll", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);

    // Assignment cleared, credential persisted.
    let user = harness.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
    assert!(user.required_actions.is_empty());
    let creds = harness
        .storage
        .get_credentials(&realm_id, &user.id, CredentialType::Totp)
        .await
        .unwrap();
    assert_eq!(creds.len(), 1);

    // The NEXT login now hits the OTP second-factor page with the enrolled
    // secret — enrollment is live end to end.
    let exec = start_auth_flow(&harness, "mfa-enroll", client.client_id.as_ref()).await;
    let resp = submit_login_form(
        &harness,
        "mfa-enroll",
        &exec,
        &[("username", "emma"), ("password", "Password123!")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Two-factor authentication"), "expected OTP page: {page}");
    // The enrollment consumed the current step's code (replay watermark), so
    // the immediate next login must use the look-ahead step's code.
    let resp =
        submit_login_form(&harness, "mfa-enroll", &exec, &[("otp", &next_code(&secret_b32))]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

/// Pull the grouped base32 setup key out of the enrollment page's `<code>`
/// block and strip the grouping spaces.
fn extract_enrollment_secret(page: &str) -> String {
    let start = page.find("<code").expect("code element");
    let gt = page[start..].find('>').expect("code open tag end") + start + 1;
    let end = page[gt..].find("</code>").expect("code close tag") + gt;
    page[gt..end].split_whitespace().collect()
}

// ---------------------------------------------------------------------------
// Account console self-service enrollment
// ---------------------------------------------------------------------------

/// DELETE with a bearer token (the harness has no DELETE helper).
async fn delete_auth(harness: &TestHarness, path: &str, token: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("DELETE")
        .uri(path)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

#[tokio::test]
async fn account_totp_enrollment_e2e() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("mfa-acct").await;
    let client = harness.create_client("mfa-acct", false).await;
    let _user = harness.create_user("mfa-acct", "liam", "Password123!").await;
    let token = harness
        .authenticate_user("mfa-acct", client.client_id.as_ref(), "liam", "Password123!")
        .await
        .access_token;

    // Start: secret + otpauth URL + locally rendered QR SVG.
    let resp = harness
        .post_json_auth(
            "/realms/mfa-acct/account/api/credentials/totp/start",
            &token,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    let secret = body["secret"].as_str().expect("secret in start response").to_string();
    let otpauth_url = body["otpauthUrl"].as_str().expect("otpauthUrl");
    assert!(otpauth_url.starts_with("otpauth://totp/"), "unexpected: {otpauth_url}");
    assert!(otpauth_url.contains(&format!("secret={secret}")), "secret not in url");
    assert!(body["qrSvg"].as_str().unwrap().starts_with("<svg"), "expected svg");

    // No credential yet.
    let resp = harness.get_auth("/realms/mfa-acct/account/api/credentials", &token).await;
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(body["totp"], false);

    // Wrong code: 400 and the pending enrollment survives (not consumed).
    let resp = harness
        .post_json_auth(
            "/realms/mfa-acct/account/api/credentials/totp/verify",
            &token,
            serde_json::json!({"code": wrong_code(&secret)}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Correct code: credential created.
    let resp = harness
        .post_json_auth(
            "/realms/mfa-acct/account/api/credentials/totp/verify",
            &token,
            serde_json::json!({"code": current_code(&secret)}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth("/realms/mfa-acct/account/api/credentials", &token).await;
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(body["totp"], true);

    // A consumed enrollment cannot be verified against again.
    let resp = harness
        .post_json_auth(
            "/realms/mfa-acct/account/api/credentials/totp/verify",
            &token,
            serde_json::json!({"code": current_code(&secret)}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Delete is idempotent: 204 twice, credential gone.
    let resp = delete_auth(&harness, "/realms/mfa-acct/account/api/credentials/totp", &token).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth("/realms/mfa-acct/account/api/credentials", &token).await;
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(body["totp"], false);
    let resp = delete_auth(&harness, "/realms/mfa-acct/account/api/credentials/totp", &token).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn account_totp_verify_without_start_is_rejected() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("mfa-nostart").await;
    let client = harness.create_client("mfa-nostart", false).await;
    let _user = harness.create_user("mfa-nostart", "olivia", "Password123!").await;
    let token = harness
        .authenticate_user("mfa-nostart", client.client_id.as_ref(), "olivia", "Password123!")
        .await
        .access_token;

    let resp = harness
        .post_json_auth(
            "/realms/mfa-nostart/account/api/credentials/totp/verify",
            &token,
            serde_json::json!({"code": "123456"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn account_totp_endpoints_require_auth() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("mfa-noauth").await;

    let resp = harness
        .post_json("/realms/mfa-noauth/account/api/credentials/totp/start", serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = harness
        .post_json(
            "/realms/mfa-noauth/account/api/credentials/totp/verify",
            serde_json::json!({"code": "123456"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let req = Request::builder()
        .method("DELETE")
        .uri("/realms/mfa-noauth/account/api/credentials/totp")
        .body(Body::empty())
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
