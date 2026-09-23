// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Admin REST API end-to-end integration tests.

use crate::harness::TestHarness;

#[tokio::test]
async fn admin_create_realm_and_user() {
    let harness = TestHarness::new().await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    // Create realm
    let resp = harness
        .post_json_auth(
            "/admin/realms",
            &admin_token,
            serde_json::json!({
                "realm": "e2e-realm",
                "display_name": "E2E Realm",
                "enabled": true,
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);

    // Verify realm exists
    let get_resp = harness.get_auth("/admin/realms/e2e-realm", &admin_token).await;
    assert_eq!(get_resp.status(), 200);

    // Create user
    let create_user_resp = harness
        .post_json_auth(
            "/admin/realms/e2e-realm/users",
            &admin_token,
            serde_json::json!({
                "username": "bob",
                "email": "bob@example.com",
                "enabled": true,
            }),
        )
        .await;
    assert_eq!(create_user_resp.status(), 201);

    let body = axum::body::to_bytes(create_user_resp.into_body(), usize::MAX).await.unwrap();
    let user_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let user_id = user_json["id"].as_str().unwrap();

    // Verify user
    let get_user_resp = harness
        .get_auth(&format!("/admin/realms/e2e-realm/users/{}", user_id), &admin_token)
        .await;
    assert_eq!(get_user_resp.status(), 200);
}

#[tokio::test]
async fn admin_user_credentials_and_sessions() {
    let harness = TestHarness::new().await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    let _realm = harness.create_realm("cred-test").await;
    let user = harness.create_user("cred-test", "carol", "password123").await;
    let client = harness.create_client("cred-test", false).await;

    // Authenticate via OIDC to create a session
    let _tokens = harness
        .authenticate_user("cred-test", &client.client_id, "carol", "password123")
        .await;

    // Get sessions
    let sessions_resp = harness
        .get_auth(&format!("/admin/realms/cred-test/users/{}/sessions", user.id.0), &admin_token)
        .await;
    assert_eq!(sessions_resp.status(), 200);
    let body = axum::body::to_bytes(sessions_resp.into_body(), usize::MAX).await.unwrap();
    let sessions: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(!sessions.is_empty());
}

#[tokio::test]
async fn admin_client_crud_and_secret_rotation() {
    let harness = TestHarness::new().await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    let _realm = harness.create_realm("client-test").await;

    // Create client
    let resp = harness
        .post_json_auth(
            "/admin/realms/client-test/clients",
            &admin_token,
            serde_json::json!({
                "client_id": "my-client",
                "name": "My Client",
                "enabled": true,
                "public_client": false,
                "redirect_uris": ["http://localhost/cb"],
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let client_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let client_id = client_json["id"].as_str().unwrap();

    // Get client
    let get_resp = harness
        .get_auth(&format!("/admin/realms/client-test/clients/{}", client_id), &admin_token)
        .await;
    assert_eq!(get_resp.status(), 200);

    // Rotate secret
    let rotate_resp = harness
        .post_json_auth(
            &format!("/admin/realms/client-test/clients/{}/client-secret", client_id),
            &admin_token,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(rotate_resp.status(), 200);
    let rotate_body = axum::body::to_bytes(rotate_resp.into_body(), usize::MAX).await.unwrap();
    let rotate_json: serde_json::Value = serde_json::from_slice(&rotate_body).unwrap();
    assert!(rotate_json["value"].as_str().unwrap().len() > 5);
}

#[tokio::test]
async fn admin_role_and_group_crud() {
    let harness = TestHarness::new().await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    let _realm = harness.create_realm("role-test").await;

    // Create role
    let resp = harness
        .post_json_auth(
            "/admin/realms/role-test/roles",
            &admin_token,
            serde_json::json!({
                "name": "test-role",
                "description": "A test role",
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);

    // Get role by name
    let get_resp = harness.get_auth("/admin/realms/role-test/roles/test-role", &admin_token).await;
    assert_eq!(get_resp.status(), 200);

    // Create group
    let group_resp = harness
        .post_json_auth(
            "/admin/realms/role-test/groups",
            &admin_token,
            serde_json::json!({
                "name": "test-group",
            }),
        )
        .await;
    assert_eq!(group_resp.status(), 201);

    let group_body = axum::body::to_bytes(group_resp.into_body(), usize::MAX).await.unwrap();
    let group_json: serde_json::Value = serde_json::from_slice(&group_body).unwrap();
    let group_id = group_json["id"].as_str().unwrap();

    // Get group
    let get_group_resp = harness
        .get_auth(&format!("/admin/realms/role-test/groups/{}", group_id), &admin_token)
        .await;
    assert_eq!(get_group_resp.status(), 200);
}

#[tokio::test]
async fn admin_unauthorized_without_token() {
    let harness = TestHarness::new().await;

    let resp = harness
        .post_json(
            "/admin/realms",
            serde_json::json!({
                "realm": "unauthorized-realm",
                "enabled": true,
            }),
        )
        .await;
    assert_eq!(resp.status(), 401);
}
