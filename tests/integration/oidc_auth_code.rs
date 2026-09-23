// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OIDC authorization code flow integration tests.

use crate::harness::TestHarness;
use base64::Engine;
use tower::ServiceExt;

#[tokio::test]
async fn authorization_code_flow_success() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let tokens = harness
        .authenticate_user("test", &client.client_id, "alice", "password123")
        .await;

    assert!(!tokens.access_token.is_empty());
    assert!(tokens.refresh_token.is_some());
    assert!(tokens.id_token.is_some());
}

#[tokio::test]
async fn authorization_code_state_roundtrip() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let state_value = "my-unique-state-123";
    let auth_path = format!(
        "/realms/test/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state={}",
        client.client_id, state_value
    );
    let auth_resp = harness.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");

    let login_resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=test",
            serde_json::json!({
                "execution_id": execution_id,
                "username": "alice",
                "password": "password123",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // State must be echoed back in the login response
    assert_eq!(
        login_json["state"].as_str(),
        Some(state_value),
        "state parameter must be preserved through the auth flow"
    );
}

#[tokio::test]
async fn authorization_code_invalid_code_rejected() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;

    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", "bogus-code"),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn authorization_code_redirect_uri_mismatch_rejected() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    // Obtain a valid code
    let auth_path = format!(
        "/realms/test/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        client.client_id
    );
    let auth_resp = harness.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");

    let login_resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=test",
            serde_json::json!({
                "execution_id": execution_id,
                "username": "alice",
                "password": "password123",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let code = login_json["code"].as_str().unwrap();

    // Exchange with wrong redirect_uri
    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", "http://evil.com/cb"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn pkce_s256_success() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    // Generate verifier and challenge (must be 43-128 chars per RFC 7636)
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(code_verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    };

    let tokens = harness
        .authenticate_user_with_pkce(
            "test",
            &client.client_id,
            "alice",
            "password123",
            &code_challenge,
            "S256",
            code_verifier,
        )
        .await;

    assert!(!tokens.access_token.is_empty());
}

#[tokio::test]
async fn pkce_s256_wrong_verifier_rejected() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(code_verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    };

    let auth_path = format!(
        "/realms/test/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz&code_challenge={}&code_challenge_method=S256",
        client.client_id, code_challenge
    );
    let auth_resp = harness.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");

    let login_resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=test",
            serde_json::json!({
                "execution_id": execution_id,
                "username": "alice",
                "password": "password123",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let code = login_json["code"].as_str().unwrap();

    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("code_verifier", "wrong-verifier"),
            ],
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn pkce_plain_success() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let code_verifier = "my-plain-verifier-that-is-long-enough-for-rfc-7636-43-chars";
    let code_challenge = code_verifier;

    let tokens = harness
        .authenticate_user_with_pkce(
            "test",
            &client.client_id,
            "alice",
            "password123",
            code_challenge,
            "plain",
            code_verifier,
        )
        .await;

    assert!(!tokens.access_token.is_empty());
}

#[tokio::test]
async fn authorization_endpoint_post_with_session_succeeds() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    // Step 1: Authenticate via normal GET flow to obtain session cookie
    let auth_path = format!(
        "/realms/test/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        client.client_id
    );
    let auth_resp = harness.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");

    let login_resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=test",
            serde_json::json!({
                "execution_id": execution_id,
                "username": "alice",
                "password": "password123",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), axum::http::StatusCode::OK);

    // Extract Set-Cookie header from login response
    let set_cookie = login_resp
        .headers()
        .get("set-cookie")
        .expect("missing set-cookie")
        .to_str()
        .unwrap()
        .to_string();

    // Step 2: POST to auth endpoint with session cookie and form body
    let form_body = format!(
        "response_type=code&client_id={}&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcb&scope=openid&state=xyz",
        client.client_id
    );
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/realms/test/protocol/openid-connect/auth")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", set_cookie)
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let post_auth_resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();

    assert_eq!(
        post_auth_resp.status(),
        axum::http::StatusCode::SEE_OTHER,
        "POST auth endpoint should redirect to callback when session is valid"
    );
    let location = post_auth_resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("http://localhost:8080/cb"));
    assert!(location.contains("code="));
}

#[tokio::test]
async fn authorization_endpoint_post_without_session_redirects_to_login() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;

    let form_body = format!(
        "response_type=code&client_id={}&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcb&scope=openid&state=xyz",
        client.client_id
    );
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/realms/test/protocol/openid-connect/auth")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let post_auth_resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();

    assert_eq!(
        post_auth_resp.status(),
        axum::http::StatusCode::SEE_OTHER,
        "POST auth endpoint should redirect to login when no session"
    );
    let location = post_auth_resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("/login.html"));
}

/// Keycloak-style trailing-`*` redirect URIs (what real deployments — and the
/// lab rig — provision) must work end to end: authorize → login → code →
/// token redemption.
#[tokio::test]
async fn authorization_code_flow_with_wildcard_redirect_uri() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let mut wildcard = client.clone();
    wildcard.redirect_uris =
        vec![issuerd_core::RedirectUri::new("http://localhost:8080/*").unwrap()];
    harness.storage.update_client(&wildcard.realm_id, &wildcard).await.unwrap();

    // `authenticate_user` requests redirect_uri=http://localhost:8080/cb,
    // which matches the wildcard registration.
    let tokens = harness
        .authenticate_user("test", &client.client_id, "alice", "password123")
        .await;

    assert!(!tokens.access_token.is_empty());
    assert!(tokens.refresh_token.is_some());
    assert!(tokens.id_token.is_some());
}

/// Regression (rig/PostgreSQL, 2026-09): the login ceremony persists the
/// session; code redemption must attach to it, not re-create it — and the
/// client session must carry the client's INTERNAL id (`client.id`, a UUID
/// on PostgreSQL), never the public `client_id` name. Both bugs were
/// invisible on the in-memory backend and hard-failed login on PostgreSQL.
#[tokio::test]
async fn code_redemption_attaches_to_ceremony_session_with_internal_client_id() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let user = harness.create_user("test", "alice", "password123").await;

    let tokens = harness
        .authenticate_user("test", &client.client_id, "alice", "password123")
        .await;

    let payload = tokens.access_token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let sid = claims["sid"].as_str().expect("sid claim");

    let session = harness
        .storage
        .get_user_session(&client.realm_id, &issuerd_core::SessionId::new(sid).unwrap())
        .await
        .unwrap()
        .expect("session persisted");
    assert_eq!(session.user_id, user.id);
    assert_eq!(
        session.clients.len(),
        1,
        "redemption must not duplicate the client session: {:?}",
        session.clients
    );
    assert_eq!(
        session.clients[0].client_id, client.id,
        "client session must store the internal id, not the public client_id"
    );
    assert_ne!(
        session.clients[0].client_id.as_ref(),
        client.client_id.as_ref(),
        "harness sanity: internal id and public name differ in this fixture"
    );
}
