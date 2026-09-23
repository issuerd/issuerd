// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Cross-realm session/cookie isolation integration tests.

use crate::harness::TestHarness;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

#[tokio::test]
async fn cross_realm_cookie_is_ignored_at_auth_endpoint() {
    let harness = TestHarness::new().await;

    // Create two realms with a user that has the same username in both.
    let _realm_a = harness.create_realm("realm-a").await;
    let client_a = harness.create_client("realm-a", false).await;
    let _user_a = harness.create_user("realm-a", "alice", "password-a").await;

    let _realm_b = harness.create_realm("realm-b").await;
    let client_b = harness.create_client("realm-b", false).await;
    let _user_b = harness.create_user("realm-b", "alice", "password-b").await;

    // Authenticate in realm-a and capture the session cookie.
    let tokens_a = harness
        .authenticate_user("realm-a", &client_a.client_id, "alice", "password-a")
        .await;

    // Request the auth endpoint in realm-b with realm-a's cookie.
    // The server must NOT short-circuit using the foreign cookie; it should
    // issue a login challenge for realm-b.
    let auth_path = format!(
        "/realms/realm-b/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        client_b.client_id
    );
    let req = Request::builder()
        .method("GET")
        .uri(&auth_path)
        .header("Cookie", format!("issuerd_session={}", tokens_a.access_token))
        .body(Body::empty())
        .unwrap();
    let req = harness.add_connect_info(req);
    let resp = harness.app.clone().oneshot(req).await.unwrap();

    assert_eq!(resp.status(), axum::http::StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with("/login.html"),
        "expected redirect to login page, got {}",
        location
    );
    assert!(location.contains("realm=realm-b"), "login redirect must target realm-b");
}

#[tokio::test]
async fn account_api_rejects_token_from_different_realm() {
    let harness = TestHarness::new().await;

    let _realm_a = harness.create_realm("realm-a").await;
    let client_a = harness.create_client("realm-a", false).await;
    let _user_a = harness.create_user("realm-a", "alice", "password-a").await;

    // realm-b must actually exist so the request reaches the issuer/realm
    // comparison instead of failing earlier on realm resolution.
    let _realm_b = harness.create_realm("realm-b").await;

    let tokens_a = harness
        .authenticate_user("realm-a", &client_a.client_id, "alice", "password-a")
        .await;

    // Use realm-a's access token against realm-b's account API.
    let req = Request::builder()
        .method("GET")
        .uri("/realms/realm-b/account/api/me")
        .header("Authorization", format!("Bearer {}", tokens_a.access_token))
        .body(Body::empty())
        .unwrap();
    let req = harness.add_connect_info(req);
    let resp = harness.app.clone().oneshot(req).await.unwrap();

    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pending_auth_realm_mismatch_is_rejected() {
    let harness = TestHarness::new().await;

    let _realm_a = harness.create_realm("realm-a").await;
    let client_a = harness.create_client("realm-a", false).await;
    let _user_a = harness.create_user("realm-a", "alice", "password-a").await;

    // realm-b must also exist so the login handler reaches pending-auth validation.
    let _realm_b = harness.create_realm("realm-b").await;

    // Start a flow in realm-a.
    let auth_path = format!(
        "/realms/realm-a/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        client_a.client_id
    );
    let auth_resp = harness.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);
    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");

    // Attempt to resume the flow under realm-b. This must fail instead of
    // creating a cross-realm session.
    let username = "alice".to_string();
    let password = "password-a".to_string();
    let exec = execution_id.clone();
    let params: [(&str, &str); 3] = [
        ("execution_id", &exec),
        ("username", &username),
        ("password", &password),
    ];
    let login_resp = harness
        .post_form_with_cookie(
            "/api/v1/auth/login?realm=realm-b",
            &params,
            &TestHarness::flow_cookie(&exec),
        )
        .await;

    assert_eq!(login_resp.status(), axum::http::StatusCode::SEE_OTHER);
    let location = login_resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("/login.html"), "expected redirect to login page");
    assert!(location.contains("error=invalid_grant"), "expected invalid_grant error");
}
