// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Email and account security integration tests.

//! Email & account security integration tests (Issuerd-only).
//!
//! Covers the four plan acceptance flows end to end through the HTTP stack:
//! temporary password → forced change → session; verify-email link roundtrip;
//! realm-configured brute-force lockout + admin unlock; password-policy 400s.

use std::sync::Arc;

use axum::http::StatusCode;

use crate::harness::TestHarness;

/// Create a user whose only password credential is temporary (as an admin
/// reset would leave it) and who carries the UPDATE_PASSWORD assignment.
async fn create_user_with_temp_password(
    harness: &TestHarness,
    realm: &str,
    username: &str,
    temp_password: &str,
) -> issuerd_core::User {
    let user = harness.create_user(realm, username, temp_password).await;
    // Mark the seeded password credential as temporary.
    let realm_id = issuerd_core::RealmId::new(realm).unwrap();
    let creds = harness
        .storage
        .get_credentials(&realm_id, &user.id, issuerd_core::CredentialType::Password)
        .await
        .unwrap();
    for cred in &creds {
        let mut updated = cred.clone();
        updated
            .credential_data
            .as_object_mut()
            .unwrap()
            .insert("temporary".to_string(), serde_json::json!(true));
        harness.storage.update_credential(&realm_id, &user.id, &updated).await.unwrap();
    }
    let mut user = user;
    user.required_actions = vec!["UPDATE_PASSWORD".to_string()];
    harness.storage.update_user(&realm_id, &user).await.unwrap();
    user
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

/// POST the browser login form; returns the response (usually a redirect).
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

/// Resource-owner password grant attempt (raw response; status varies).
async fn password_grant(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    password: &str,
) -> axum::response::Response {
    let client_id = client.client_id.to_string();
    harness
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
        .await
}

#[tokio::test]
async fn temp_password_forces_change_then_session_is_issued() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("sec-temp").await;
    let client = harness.create_client("sec-temp", false).await;
    let user = create_user_with_temp_password(&harness, "sec-temp", "ivy", "Temp1234!").await;

    // Login with the temporary password: instead of a code, the browser is
    // sent into the required-action continuation.
    let exec = start_auth_flow(&harness, "sec-temp", client.client_id.as_ref()).await;
    let resp = submit_login_form(&harness, "sec-temp", &exec, "ivy", "Temp1234!").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(
        location.starts_with("/realms/sec-temp/login/required-action/"),
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
    assert!(continuation_cookie.starts_with("issuerd_flow_"));

    // The continuation page renders the password form.
    let resp = harness.get(&location).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Update your password"));

    // Submit the new password: login completes with a code redirect.
    let resp = harness
        .post_form_with_cookie(
            &location,
            &[
                ("new_password", "N3wPassword!"),
                ("confirm_password", "N3wPassword!"),
            ],
            &continuation_cookie,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let redirect = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(redirect.starts_with("http://localhost:8080/cb?"), "unexpected: {redirect}");
    let code = TestHarness::extract_query_param(&redirect, "code").expect("code in redirect");

    // The code redeems into a full token set (session was created).
    let tokens = exchange_code(&harness, "sec-temp", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
    assert!(tokens["refresh_token"].as_str().is_some());

    // Assignment cleared; old temporary password dead, new password works.
    let realm_id = issuerd_core::RealmId::new("sec-temp").unwrap();
    let user = harness.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
    assert!(user.required_actions.is_empty());
    let resp = password_grant(&harness, "sec-temp", &client, "ivy", "Temp1234!").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = password_grant(&harness, "sec-temp", &client, "ivy", "N3wPassword!").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn realm_verify_email_toggle_drives_link_roundtrip() {
    use issuerd_server::{config::ServerConfig, state::ServerState};

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

    let config = ServerConfig::default();
    let mut state = ServerState::from_config(&config).await.unwrap();
    let recorder = Arc::new(RecordingSender::default());
    state.email_sender = recorder.clone();
    let state = Arc::new(state);
    let cache = state.cache.clone();
    let harness = TestHarness::with_state(state);

    // Realm with the verify-email toggle; user has NO explicit assignment —
    // the realm setting alone must trigger VERIFY_EMAIL on login.
    let mut realm = harness.create_realm("sec-verify").await;
    realm.verify_email_enabled = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("sec-verify", false).await;
    let realm_id = issuerd_core::RealmId::new("sec-verify").unwrap();
    let user = harness.create_user("sec-verify", "judy", "Password123!").await;
    let mut user = user;
    user.email_verified = false;
    harness.storage.update_user(&realm_id, &user).await.unwrap();

    let exec = start_auth_flow(&harness, "sec-verify", client.client_id.as_ref()).await;
    let resp = submit_login_form(&harness, "sec-verify", &exec, "judy", "Password123!").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(location.contains("/login/required-action/"), "unexpected: {location}");

    // The continuation page sends the verification email on first render.
    let resp = harness.get(&location).await;
    assert_eq!(resp.status(), StatusCode::OK);
    // Copy the recorded mail out of the lock before any further .await
    // (clippy::await_holding_lock).
    let (to, text, html) = {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        (sent[0].0.clone(), sent[0].2.clone(), sent[0].3.clone())
    };
    assert_eq!(to, "judy@example.com");
    let html = html.expect("multipart mail with HTML part");
    assert!(html.contains("v:roundrect"), "Outlook VML button missing");
    let link = text
        .lines()
        .find(|l| l.contains("/login/verify-email?token="))
        .expect("verification link in text body")
        .trim()
        .to_string();

    // Follow the link through the HTTP stack (path + query only).
    let path = link.strip_prefix("http://localhost:8080").unwrap_or(&link).to_string();
    let resp = harness.get(&path).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Email address verified"));

    // User record updated; token consumed.
    let user = harness.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
    assert!(user.email_verified);
    let resp = harness.get(&path).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(cache.scan_keys("verify-email:*").await.unwrap().is_empty());

    // The continuation now completes the login.
    let resp = harness.get(&location).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let redirect = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let code = TestHarness::extract_query_param(&redirect, "code").expect("code in redirect");
    let tokens = exchange_code(&harness, "sec-verify", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn realm_brute_force_lockout_and_admin_unlock() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("sec-lock").await;
    realm.brute_force_protected = true;
    realm.max_login_failures = 2;
    realm.wait_increment_secs = 0; // fixed lockout duration
    realm.lockout_duration_secs = 300;
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("sec-lock", false).await;
    let user = harness.create_user("sec-lock", "mallory-target", "RightPass1!").await;

    // Two failures engage the lockout (max_login_failures = 2).
    for _ in 0..2 {
        let resp = password_grant(&harness, "sec-lock", &client, "mallory-target", "wrong").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    // The third attempt is rejected even with the correct password.
    let resp = password_grant(&harness, "sec-lock", &client, "mallory-target", "RightPass1!").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Attack detection surfaces the lockout.
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;
    let resp = harness
        .get_auth("/admin/realms/sec-lock/attack-detection/brute-force/users", &admin_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let rows = json.as_array().unwrap();
    assert!(
        rows.iter()
            .any(|r| r["username"] == "mallory-target" && r["userId"] == user.id.0),
        "expected locked user with resolved userId in attack-detection list: {json}"
    );

    // Admin unlock → the correct password works again.
    let resp = {
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!(
                "/admin/realms/sec-lock/attack-detection/brute-force/users/{}",
                user.id.0
            ))
            .header("Authorization", format!("Bearer {admin_token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        use tower::ServiceExt;
        harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
    };
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = password_grant(&harness, "sec-lock", &client, "mallory-target", "RightPass1!").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unprotected_realm_never_locks_out() {
    let harness = TestHarness::new().await;
    // Default realm: brute_force_protected = false.
    let _realm = harness.create_realm("sec-open").await;
    let client = harness.create_client("sec-open", false).await;
    let _user = harness.create_user("sec-open", "trent", "RightPass1!").await;

    for _ in 0..6 {
        let resp = password_grant(&harness, "sec-open", &client, "trent", "wrong").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    // No lockout without the realm toggle: the correct password still works.
    let resp = password_grant(&harness, "sec-open", &client, "trent", "RightPass1!").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ropc_rejects_account_with_pending_required_actions() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("sec-ropc").await;
    let client = harness.create_client("sec-ropc", false).await;
    let user = harness.create_user("sec-ropc", "victor", "Password123!").await;

    let realm_id = issuerd_core::RealmId::new("sec-ropc").unwrap();
    let mut user = user;
    user.required_actions = vec!["UPDATE_PROFILE".to_string()];
    harness.storage.update_user(&realm_id, &user).await.unwrap();

    let resp = password_grant(&harness, "sec-ropc", &client, "victor", "Password123!").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
    assert_eq!(json["error_description"], "Account is not fully set up");
}

#[tokio::test]
async fn admin_create_user_enforces_password_policy() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("sec-policy").await;
    realm.password_policy.require_digits = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    // Digit-less password violates the realm policy → 400 with violations.
    let resp = harness
        .post_json_auth(
            "/admin/realms/sec-policy/users",
            &admin_token,
            serde_json::json!({
                "username": "peggy",
                "enabled": true,
                "credentials": [{"type": "password", "value": "nodigits!", "temporary": false}],
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let violations = json["policyViolations"].as_array().expect("policyViolations array");
    assert!(
        violations.iter().any(|v| v["code"] == "require_digits"),
        "expected require_digits violation: {json}"
    );

    // A compliant password passes.
    let resp = harness
        .post_json_auth(
            "/admin/realms/sec-policy/users",
            &admin_token,
            serde_json::json!({
                "username": "peggy",
                "enabled": true,
                "credentials": [{"type": "password", "value": "has1digit!", "temporary": false}],
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn admin_temporary_password_assigns_update_password_action() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("sec-admin-temp").await;
    let user = harness.create_user("sec-admin-temp", "walter", "Password123!").await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    // Reset with temporary=true must assign UPDATE_PASSWORD.
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/admin/realms/sec-admin-temp/users/{}/reset-password", user.id.0))
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {admin_token}"))
        .body(axum::body::Body::from(
            serde_json::json!({"type": "password", "value": "Temp999!", "temporary": true})
                .to_string(),
        ))
        .unwrap();
    use tower::ServiceExt;
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = harness
        .get_auth(&format!("/admin/realms/sec-admin-temp/users/{}", user.id.0), &admin_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let actions = json["requiredActions"].as_array().expect("requiredActions array");
    assert!(
        actions.iter().any(|a| a == "UPDATE_PASSWORD"),
        "expected UPDATE_PASSWORD in {json}"
    );
}
