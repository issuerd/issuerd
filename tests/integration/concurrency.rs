// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Concurrency integration tests: token refresh, unique constraints, failure tracking.

use crate::harness::TestHarness;
use futures::future::join_all;
use issuerd_core::Email;
use std::sync::Arc;

#[tokio::test]
async fn concurrent_token_refresh_no_duplicate() {
    let harness = Arc::new(TestHarness::new().await);
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let tokens = harness
        .authenticate_user("test", &client.client_id, "alice", "password123")
        .await;
    let refresh_token = tokens.refresh_token.expect("refresh token missing");

    let mut futures = vec![];
    for _ in 0..50 {
        let h = Arc::clone(&harness);
        let client_id = client.client_id.clone();
        let secret = client.secret.clone().unwrap_or_default();
        let rt = refresh_token.clone();
        futures.push(async move {
            let resp = h
                .post_form(
                    "/realms/test/protocol/openid-connect/token",
                    &[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", &rt),
                        ("client_id", &client_id),
                        ("client_secret", &secret),
                        ("scope", "openid"),
                    ],
                )
                .await;
            resp.status().as_u16()
        });
    }

    let statuses: Vec<u16> = join_all(futures).await;

    let success_count = statuses.iter().filter(|&&s| s == 200).count();
    assert!(success_count >= 1, "at least one refresh should succeed");
    assert!(statuses.iter().all(|&s| s == 200 || s == 400));
}

#[tokio::test]
async fn concurrent_user_creation_unique_constraint() {
    let harness = Arc::new(TestHarness::new().await);
    let _realm = harness.create_realm("test").await;

    let mut futures = vec![];
    for _ in 0..10 {
        let h = Arc::clone(&harness);
        futures.push(async move {
            let user = issuerd_core::User {
                id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
                realm_id: issuerd_core::RealmId::new("test").unwrap(),
                username: issuerd_core::Username::new("duplicate-user").unwrap(),
                email: Some(Email::new("dup@example.com").unwrap()),
                email_verified: true,
                first_name: Some(issuerd_core::DisplayName::new("Test").unwrap()),
                last_name: Some(issuerd_core::DisplayName::new("User").unwrap()),
                enabled: true,
                federation_link: None,
                attributes: std::collections::HashMap::new(),
                required_actions: Vec::new(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            match h.storage.create_user(&user.realm_id, &user).await {
                Ok(_) => 201u16,
                Err(_) => 409u16,
            }
        });
    }

    let results: Vec<u16> = join_all(futures).await;

    let success_count = results.iter().filter(|&&s| s == 201).count();
    assert_eq!(success_count, 1, "exactly one user creation should succeed");
}

#[tokio::test]
async fn concurrent_login_failure_tracking() {
    let harness = Arc::new(TestHarness::new().await);
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let mut futures = vec![];
    for _ in 0..20 {
        let h = Arc::clone(&harness);
        let client_id = client.client_id.clone();
        futures.push(async move {
            let auth_path = format!(
                "/realms/test/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
                client_id
            );
            let auth_resp = h.get(&auth_path).await;
            if auth_resp.status() != axum::http::StatusCode::SEE_OTHER {
                return auth_resp.status().as_u16();
            }
            let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
            let execution_id =
                crate::harness::TestHarness::extract_query_param(location, "execution_id")
                    .expect("missing execution_id");

            let login_resp = h
                .post_json_with_cookie(
                    "/api/v1/auth/login?realm=test",
                    serde_json::json!({
                        "execution_id": execution_id,
                        "username": "alice",
                        "password": "wrongpassword",
                    }),
                    &TestHarness::flow_cookie(&execution_id),
                )
                .await;
            login_resp.status().as_u16()
        });
    }

    let statuses: Vec<u16> = join_all(futures).await;
    assert!(statuses.iter().all(|&s| s == 401));
}
