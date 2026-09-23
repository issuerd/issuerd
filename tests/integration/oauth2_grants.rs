// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OAuth2 grant integration tests (dual-target: Issuerd and Keycloak).

use crate::harness::for_each_target;

#[tokio::test]
async fn password_grant_success() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let client = target.create_client(&realm.name, false).await;
        let _user = target.create_user(&realm.name, "alice", "password123").await;

        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token", realm.name),
                &[
                    ("grant_type", "password"),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                    ("username", "alice"),
                    ("password", "password123"),
                    ("scope", "openid profile"),
                ],
            )
            .await;
        assert_eq!(resp.status(), 200);
        let json = resp.json().unwrap();
        assert!(json["access_token"].as_str().unwrap().len() > 10);
        assert!(json["id_token"].as_str().is_some());

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn password_grant_wrong_password() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let client = target.create_client(&realm.name, false).await;
        let _user = target.create_user(&realm.name, "alice", "password123").await;

        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token", realm.name),
                &[
                    ("grant_type", "password"),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                    ("username", "alice"),
                    ("password", "wrongpassword"),
                    ("scope", "openid"),
                ],
            )
            .await;
        assert_eq!(resp.status(), 401);
        let json = resp.json().unwrap();
        assert_eq!(json["error"], "invalid_grant");

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn client_credentials_grant_success() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let client = target.create_client(&realm.name, false).await;

        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token", realm.name),
                &[
                    ("grant_type", "client_credentials"),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                    ("scope", "openid"),
                ],
            )
            .await;
        assert_eq!(resp.status(), 200);
        let json = resp.json().unwrap();
        assert!(json["access_token"].as_str().unwrap().len() > 10);
        assert!(json["refresh_token"].is_null());
        // Keycloak returns an id_token for client_credentials when scope includes openid;
        // Issuerd does not. Accept either behaviour.

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn client_credentials_public_client_rejected() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let client = target.create_client(&realm.name, true).await;

        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token", realm.name),
                &[
                    ("grant_type", "client_credentials"),
                    ("client_id", &client.client_id),
                    ("client_secret", ""),
                    ("scope", "openid"),
                ],
            )
            .await;
        assert_eq!(resp.status(), 401);
        let json = resp.json().unwrap();
        assert_eq!(json["error"], "unauthorized_client");

        target.cleanup().await;
    })
    .await;
}

// ---------------------------------------------------------------------------
// 2026-09 review hardening (Issuerd-only: pins our exact error shape)
// ---------------------------------------------------------------------------

/// A disabled client must not obtain tokens at all — not even with correct
/// credentials (disabling is the administrative containment action).
#[tokio::test]
async fn disabled_client_rejected_at_token_endpoint() {
    use crate::harness::TestHarness;

    let harness = TestHarness::new().await;
    let realm = harness.create_realm("disabled-client").await;
    let client = harness.create_client(realm.name.as_ref(), false).await;
    harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let mut disabled = client.clone();
    disabled.enabled = false;
    harness.storage.update_client(&realm.id, &disabled).await.unwrap();

    let token_path = format!("/realms/{}/protocol/openid-connect/token", realm.name);

    // Password grant with CORRECT credentials still fails.
    let resp = harness
        .post_form(
            &token_path,
            &[
                ("grant_type", "password"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("username", "alice"),
                ("password", "password123"),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client");

    // Client credentials grant likewise.
    let resp = harness
        .post_form(
            &token_path,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client");

    // Re-enabling restores access (containment is reversible by admins).
    let mut enabled = disabled.clone();
    enabled.enabled = true;
    harness.storage.update_client(&realm.id, &enabled).await.unwrap();
    let resp = harness
        .post_form(
            &token_path,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), 200);
}
