// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OIDC spec conformance tests: implicit/hybrid flows, device and CIBA grants.

use crate::harness::TestHarness;

#[tokio::test]
async fn implicit_flow_id_token_only() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", true).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    // Step 1: Authorization request (unauthenticated -> challenge redirect)
    let auth_path = format!(
        "/realms/test/protocol/openid-connect/auth?response_type=id_token&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz&nonce=abc",
        client.client_id
    );
    let auth_resp = harness.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");

    // Step 2: Login via API
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
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["id_token"].is_string());
    assert!(json["id_token"].as_str().unwrap().len() > 10);
    assert!(json["code"].is_null());
    assert!(!json["id_token"].as_str().unwrap().is_empty());
    assert_eq!(json["redirect_uri"], "http://localhost:8080/cb");
    assert_eq!(json["state"], "xyz");
}

#[tokio::test]
async fn hybrid_flow_code_id_token() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    // Step 1: Authorization request (unauthenticated -> challenge redirect)
    let auth_path = format!(
        "/realms/test/protocol/openid-connect/auth?response_type=code%20id_token&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz&nonce=abc",
        client.client_id
    );
    let auth_resp = harness.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");

    // Step 2: Login via API
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
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Both code and id_token must be present
    assert!(json["code"].is_string());
    assert!(json["code"].as_str().unwrap().len() > 5);
    assert!(json["id_token"].is_string());
    assert!(json["id_token"].as_str().unwrap().len() > 10);
    assert_eq!(json["redirect_uri"], "http://localhost:8080/cb");
    assert_eq!(json["state"], "xyz");

    // Step 3: Exchange code at token endpoint
    let code = json["code"].as_str().unwrap();
    let token_resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(token_resp.status(), axum::http::StatusCode::OK);

    let token_body = axum::body::to_bytes(token_resp.into_body(), usize::MAX).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_body).unwrap();
    assert!(token_json["access_token"].is_string());
    assert!(token_json["id_token"].is_string());
}

#[tokio::test]
async fn device_authorization_grant() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", true).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    // Step 1: Device authorization request
    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/auth/device",
            &[("client_id", &client.client_id), ("scope", "openid")],
        )
        .await;
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["device_code"].is_string());
    assert!(json["user_code"].is_string());
    assert!(json["verification_uri"].is_string());
    let device_code = json["device_code"].as_str().unwrap();
    let user_code = json["user_code"].as_str().unwrap();

    // Step 2: Poll token endpoint — should be authorization_pending
    let token_resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", &client.client_id),
                ("device_code", device_code),
            ],
        )
        .await;
    assert_eq!(token_resp.status(), 400);
    let token_body = axum::body::to_bytes(token_resp.into_body(), usize::MAX).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_body).unwrap();
    assert_eq!(token_json["error"], "authorization_pending");

    // Step 3: User verifies the device code
    let verify_resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/auth/device-verify",
            &[
                ("user_code", user_code),
                ("username", "alice"),
                ("password", "password123"),
            ],
        )
        .await;
    assert_eq!(verify_resp.status(), 200);

    // Step 4: Poll token endpoint again — should succeed
    let token_resp2 = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", &client.client_id),
                ("device_code", device_code),
            ],
        )
        .await;
    assert_eq!(token_resp2.status(), 200);
    let token_body2 = axum::body::to_bytes(token_resp2.into_body(), usize::MAX).await.unwrap();
    let token_json2: serde_json::Value = serde_json::from_slice(&token_body2).unwrap();
    assert!(token_json2["access_token"].is_string());
}

#[tokio::test]
async fn ciba_grant() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    // Step 1: Initiate CIBA backchannel auth request
    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/ext/ciba/auth",
            &[
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid"),
                ("login_hint", "alice"),
            ],
        )
        .await;
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["auth_req_id"].is_string());
    assert!(json["expires_in"].is_number());
    let auth_req_id = json["auth_req_id"].as_str().unwrap();

    // Step 2: Poll token endpoint — should be authorization_pending
    let token_resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "urn:openid:params:grant-type:ciba"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("auth_req_id", auth_req_id),
            ],
        )
        .await;
    assert_eq!(token_resp.status(), 400);
    let token_body = axum::body::to_bytes(token_resp.into_body(), usize::MAX).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&token_body).unwrap();
    assert_eq!(token_json["error"], "authorization_pending");

    // Step 3: Approve the CIBA request, authenticated as the bound user
    let tokens = harness
        .authenticate_user("test", &client.client_id, "alice", "password123")
        .await;
    let approve_resp = harness
        .post_form_with_cookie(
            "/realms/test/protocol/openid-connect/ext/ciba/approve",
            &[("auth_req_id", auth_req_id), ("action", "approve")],
            &format!("issuerd_session={}", tokens.access_token),
        )
        .await;
    assert_eq!(approve_resp.status(), 200);

    // Step 4: Poll token endpoint again — should succeed
    let token_resp2 = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "urn:openid:params:grant-type:ciba"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("auth_req_id", auth_req_id),
            ],
        )
        .await;
    assert_eq!(token_resp2.status(), 200);
    let token_body2 = axum::body::to_bytes(token_resp2.into_body(), usize::MAX).await.unwrap();
    let token_json2: serde_json::Value = serde_json::from_slice(&token_body2).unwrap();
    assert!(token_json2["access_token"].is_string());
}

/// Scope assignments are enforced at the device-authorization endpoint too
/// (2026-09 review fix): a client that was never assigned `offline_access`
/// cannot smuggle it in through the device flow and mint a 30-day offline
/// session.
#[tokio::test]
async fn device_authorization_enforces_scope_assignments() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", true).await;

    // The harness client has no `offline_access` assignment.
    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/auth/device",
            &[
                ("client_id", &client.client_id),
                ("scope", "openid offline_access"),
            ],
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_scope");

    // The assigned subset still works.
    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/auth/device",
            &[("client_id", &client.client_id), ("scope", "openid")],
        )
        .await;
    assert_eq!(resp.status(), 200);
}

/// Same assignment rule at the CIBA backchannel endpoint (2026-09 review
/// fix): CIBA must not be a side channel around the authorize-endpoint scope
/// check.
#[tokio::test]
async fn ciba_enforces_scope_assignments() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/ext/ciba/auth",
            &[
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid offline_access"),
                ("login_hint", "alice"),
            ],
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_scope");
}

// ---------------------------------------------------------------------------
// CIBA audit events
// ---------------------------------------------------------------------------

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// PUT a JSON body with a bearer token (the harness has no PUT helper).
async fn put_json_auth(
    harness: &TestHarness,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let req = Request::builder()
        .method("PUT")
        .uri(path)
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

/// Enable login-event recording explicitly (the realm default is already ON)
/// and return the admin token used to query the events API.
async fn enable_events(harness: &TestHarness, realm: &str) -> String {
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let resp = put_json_auth(
        harness,
        &format!("/admin/realms/{realm}/events/config"),
        &admin,
        serde_json::json!({ "eventsEnabled": true }),
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);
    admin
}

async fn fetch_events(harness: &TestHarness, realm: &str, admin: &str) -> Vec<serde_json::Value> {
    let resp = harness.get_auth(&format!("/admin/realms/{realm}/events?max=100"), admin).await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    body_json(resp).await.as_array().unwrap().clone()
}

fn ciba_poll_form<'a>(
    client: &'a issuerd_core::Client,
    auth_req_id: &'a str,
) -> [(&'a str, &'a str); 4] {
    [
        ("grant_type", "urn:openid:params:grant-type:ciba"),
        ("client_id", &client.client_id),
        ("client_secret", client.secret.as_deref().unwrap_or("")),
        ("auth_req_id", auth_req_id),
    ]
}

/// The happy path records the full decision chain: ciba_auth on request
/// acceptance, ciba_approve on the user's decision, and a login event with
/// `details.method=ciba` when the poll mints the tokens. Pending polls are
/// protocol chatter and record nothing.
#[tokio::test]
async fn ciba_audit_events_record_lifecycle() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let user = harness.create_user("test", "alice", "password123").await;
    let admin = enable_events(&harness, "test").await;

    // Step 1: accepted backchannel request -> ciba_auth
    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/ext/ciba/auth",
            &[
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid"),
                ("login_hint", "alice"),
                ("binding_message", "Refund $150"),
            ],
        )
        .await;
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let auth_req_id = json["auth_req_id"].as_str().unwrap().to_string();

    // Step 2: a pending poll answers authorization_pending and records nothing.
    let poll = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &ciba_poll_form(&client, &auth_req_id),
        )
        .await;
    assert_eq!(poll.status(), 400);

    let events = fetch_events(&harness, "test", &admin).await;
    assert_eq!(events.len(), 1, "only ciba_auth so far: {events:?}");
    let event = &events[0];
    assert_eq!(event["event_type"], "ciba_auth");
    assert_eq!(event["client_id"], client.id.0);
    assert_eq!(event["user_id"], user.id.0);
    assert_eq!(event["details"]["scope"], "openid");
    // The binding message text is never recorded (it can carry PII) — only
    // its length.
    assert_eq!(event["details"]["binding_message_len"], "11");
    assert!(event["details"].get("binding_message").is_none());

    // Step 3: the user's approval -> ciba_approve
    let tokens = harness
        .authenticate_user("test", &client.client_id, "alice", "password123")
        .await;
    let approve = harness
        .post_form_with_cookie(
            "/realms/test/protocol/openid-connect/ext/ciba/approve",
            &[("auth_req_id", auth_req_id.as_str()), ("action", "approve")],
            &format!("issuerd_session={}", tokens.access_token),
        )
        .await;
    assert_eq!(approve.status(), 200);

    // Step 4: the successful poll mints tokens -> login with method=ciba
    let poll = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &ciba_poll_form(&client, &auth_req_id),
        )
        .await;
    assert_eq!(poll.status(), 200);

    let events = fetch_events(&harness, "test", &admin).await;
    let approve_event = events
        .iter()
        .find(|e| e["event_type"] == "ciba_approve")
        .unwrap_or_else(|| panic!("expected a ciba_approve event: {events:?}"));
    assert_eq!(approve_event["user_id"], user.id.0);
    assert_eq!(approve_event["client_id"], client.id.0);
    assert_eq!(approve_event["details"]["scope"], "openid");
    assert!(approve_event["session_id"].is_string());

    let login_event = events
        .iter()
        .find(|e| e["event_type"] == "login" && e["details"]["method"] == "ciba")
        .unwrap_or_else(|| panic!("expected a login event with method=ciba: {events:?}"));
    assert_eq!(login_event["user_id"], user.id.0);
    assert_eq!(login_event["client_id"], client.id.0);

    assert!(
        events.iter().all(|e| e["event_type"] != "login_error"),
        "no login_error on the happy path: {events:?}"
    );
}

/// Rejections are audited too: invalid_scope at the backchannel endpoint, an
/// expired/unknown auth_req_id at the approval endpoint, the user's denial,
/// and the denied poll's login_error.
#[tokio::test]
async fn ciba_audit_events_record_rejections() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let user = harness.create_user("test", "alice", "password123").await;
    let admin = enable_events(&harness, "test").await;

    // The client has no offline_access assignment -> invalid_scope.
    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/ext/ciba/auth",
            &[
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid offline_access"),
                ("login_hint", "alice"),
            ],
        )
        .await;
    assert_eq!(resp.status(), 400);

    // Approving an unknown auth_req_id -> expired_token error event.
    let tokens = harness
        .authenticate_user("test", &client.client_id, "alice", "password123")
        .await;
    let cookie = format!("issuerd_session={}", tokens.access_token);
    let approve = harness
        .post_form_with_cookie(
            "/realms/test/protocol/openid-connect/ext/ciba/approve",
            &[("auth_req_id", "no-such-request"), ("action", "approve")],
            &cookie,
        )
        .await;
    assert_eq!(approve.status(), 400);

    // A denied request: ciba_deny at the approval endpoint, then
    // access_denied (login_error) at the poll.
    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/ext/ciba/auth",
            &[
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid"),
                ("login_hint", "alice"),
            ],
        )
        .await;
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let auth_req_id = json["auth_req_id"].as_str().unwrap().to_string();

    let deny = harness
        .post_form_with_cookie(
            "/realms/test/protocol/openid-connect/ext/ciba/approve",
            &[("auth_req_id", auth_req_id.as_str()), ("action", "deny")],
            &cookie,
        )
        .await;
    assert_eq!(deny.status(), 200);

    let poll = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &ciba_poll_form(&client, &auth_req_id),
        )
        .await;
    assert_eq!(poll.status(), 400);
    let poll_json = body_json(poll).await;
    assert_eq!(poll_json["error"], "access_denied");

    let events = fetch_events(&harness, "test", &admin).await;

    let scope_error = events
        .iter()
        .find(|e| e["event_type"] == "ciba_auth_error" && e["error"] == "invalid_scope")
        .unwrap_or_else(|| panic!("expected a ciba_auth_error/invalid_scope event: {events:?}"));
    assert_eq!(scope_error["client_id"], client.id.0);

    assert!(
        events
            .iter()
            .any(|e| e["event_type"] == "ciba_auth_error" && e["error"] == "expired_token"),
        "expected a ciba_auth_error/expired_token event: {events:?}"
    );

    let deny_event = events
        .iter()
        .find(|e| e["event_type"] == "ciba_deny")
        .unwrap_or_else(|| panic!("expected a ciba_deny event: {events:?}"));
    assert_eq!(deny_event["user_id"], user.id.0);
    assert_eq!(deny_event["client_id"], client.id.0);

    let denied_poll = events
        .iter()
        .find(|e| {
            e["event_type"] == "login_error"
                && e["error"] == "access_denied"
                && e["details"]["method"] == "ciba"
        })
        .unwrap_or_else(|| panic!("expected a login_error/access_denied event: {events:?}"));
    assert_eq!(denied_poll["user_id"], user.id.0);
}
