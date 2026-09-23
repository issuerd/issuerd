// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Concurrency integration tests: token refresh, unique constraints, failure tracking.

use crate::harness::TestHarness;
use futures::future::join_all;
use issuerd_core::Email;
use std::sync::Arc;

/// Run one CIBA backchannel request through approval and return its
/// `auth_req_id`, ready for the first token poll.
async fn approved_ciba_request(harness: &TestHarness, client: &issuerd_core::Client) -> String {
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
    let auth_req_id = json["auth_req_id"].as_str().unwrap().to_string();

    // Approve as the bound user (SSO session cookie).
    let tokens = harness
        .authenticate_user("test", &client.client_id, "alice", "password123")
        .await;
    let approve_resp = harness
        .post_form_with_cookie(
            "/realms/test/protocol/openid-connect/ext/ciba/approve",
            &[("auth_req_id", auth_req_id.as_str()), ("action", "approve")],
            &format!("issuerd_session={}", tokens.access_token),
        )
        .await;
    assert_eq!(approve_resp.status(), 200);
    auth_req_id
}

/// Run one device authorization request through user verification and return
/// its `device_code`, ready for the first token poll.
async fn approved_device_code(harness: &TestHarness, client: &issuerd_core::Client) -> String {
    let resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/auth/device",
            &[("client_id", &client.client_id), ("scope", "openid")],
        )
        .await;
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let device_code = json["device_code"].as_str().unwrap().to_string();
    let user_code = json["user_code"].as_str().unwrap().to_string();

    let verify_resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/auth/device-verify",
            &[
                ("user_code", user_code.as_str()),
                ("username", "alice"),
                ("password", "password123"),
            ],
        )
        .await;
    assert_eq!(verify_resp.status(), 200);
    device_code
}

/// Fire `n` concurrent CIBA token polls; return the response statuses.
async fn concurrent_ciba_polls(
    harness: &Arc<TestHarness>,
    client: &issuerd_core::Client,
    auth_req_id: &str,
    n: usize,
) -> Vec<u16> {
    let mut futures = vec![];
    for _ in 0..n {
        let h = Arc::clone(harness);
        let client_id = client.client_id.clone();
        let secret = client.secret.clone().unwrap_or_default();
        let auth_req_id = auth_req_id.to_string();
        futures.push(async move {
            h.post_form(
                "/realms/test/protocol/openid-connect/token",
                &[
                    ("grant_type", "urn:openid:params:grant-type:ciba"),
                    ("client_id", &client_id),
                    ("client_secret", &secret),
                    ("auth_req_id", &auth_req_id),
                ],
            )
            .await
            .status()
            .as_u16()
        });
    }
    join_all(futures).await
}

/// Fire `n` concurrent device-grant token polls; return the response statuses.
async fn concurrent_device_polls(
    harness: &Arc<TestHarness>,
    client: &issuerd_core::Client,
    device_code: &str,
    n: usize,
) -> Vec<u16> {
    let mut futures = vec![];
    for _ in 0..n {
        let h = Arc::clone(harness);
        let client_id = client.client_id.clone();
        let device_code = device_code.to_string();
        futures.push(async move {
            h.post_form(
                "/realms/test/protocol/openid-connect/token",
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", &client_id),
                    ("device_code", &device_code),
                ],
            )
            .await
            .status()
            .as_u16()
        });
    }
    join_all(futures).await
}

/// An approved grant is single-use: exactly one poll mints tokens, every
/// other poll fails (400 — `expired_token` for the polls that lost the
/// atomic consume, `slow_down` for the ones gated by poll pacing).
fn assert_single_success(statuses: &[u16]) {
    let success_count = statuses.iter().filter(|&&s| s == 200).count();
    assert_eq!(success_count, 1, "exactly one poll may succeed: {statuses:?}");
    assert!(
        statuses.iter().all(|&s| s == 200 || s == 400),
        "polls only ever succeed or fail with a 400 grant error: {statuses:?}"
    );
}

#[tokio::test]
async fn concurrent_ciba_poll_consumes_once() {
    let harness = Arc::new(TestHarness::new().await);
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let auth_req_id = approved_ciba_request(&harness, &client).await;
    let statuses = concurrent_ciba_polls(&harness, &client, &auth_req_id, 32).await;
    assert_single_success(&statuses);

    // The consumed auth_req_id stays burned: a follow-up poll fails too.
    let follow_up = concurrent_ciba_polls(&harness, &client, &auth_req_id, 1).await;
    assert_eq!(follow_up, vec![400]);
}

#[tokio::test]
async fn concurrent_device_poll_consumes_once() {
    let harness = Arc::new(TestHarness::new().await);
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", true).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let device_code = approved_device_code(&harness, &client).await;
    let statuses = concurrent_device_polls(&harness, &client, &device_code, 32).await;
    assert_single_success(&statuses);

    // The consumed device code stays burned: a follow-up poll fails too.
    let follow_up = concurrent_device_polls(&harness, &client, &device_code, 1).await;
    assert_eq!(follow_up, vec![400]);
}

/// Same single-use guarantee on the Redis-backed cache (the production
/// topology, where `GETDEL` provides the atomic consume). Skips gracefully
/// when no Redis is reachable on the integration-stack address.
#[tokio::test]
async fn concurrent_grant_polls_consume_once_redis() {
    if std::net::TcpStream::connect_timeout(
        &"127.0.0.1:6379".parse().unwrap(),
        std::time::Duration::from_secs(2),
    )
    .is_err()
    {
        eprintln!("SKIP: Redis not available on 127.0.0.1:6379");
        return;
    }
    let cache: Arc<dyn issuerd_core::DistributedCache> =
        match issuerd_cluster::RedisCache::connect("redis://127.0.0.1:6379").await {
            Ok(cache) => Arc::new(cache),
            Err(e) => {
                eprintln!("SKIP: Redis connect failed: {e}");
                return;
            }
        };
    let config = issuerd_server::config::ServerConfig::default();
    let storage: Arc<dyn issuerd_core::Storage> = Arc::new(issuerd_storage::InMemoryStorage::new());
    let state = Arc::new(
        issuerd_server::state::ServerState::from_components(&config, storage, cache)
            .await
            .unwrap(),
    );
    let harness = Arc::new(TestHarness::with_state(state));
    let _realm = harness.create_realm("test").await;
    let confidential = harness.create_client("test", false).await;
    let public = harness.create_client("test", true).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let auth_req_id = approved_ciba_request(&harness, &confidential).await;
    let statuses = concurrent_ciba_polls(&harness, &confidential, &auth_req_id, 32).await;
    assert_single_success(&statuses);

    let device_code = approved_device_code(&harness, &public).await;
    let statuses = concurrent_device_polls(&harness, &public, &device_code, 32).await;
    assert_single_success(&statuses);
}

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
