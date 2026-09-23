// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Token validation and userinfo integration tests (dual-target).

use crate::harness::for_each_target;

#[tokio::test]
async fn userinfo_with_valid_token() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let client = target.create_client(&realm.name, false).await;
        let _user = target.create_user(&realm.name, "alice", "password123").await;

        let tokens = target
            .get_token_via_password_grant(
                &realm.name,
                &client.client_id,
                client.secret.as_deref(),
                "alice",
                "password123",
                "openid",
            )
            .await;

        let resp = target
            .get_auth(
                &format!("/realms/{}/protocol/openid-connect/userinfo", realm.name),
                &tokens.access_token,
            )
            .await;

        assert_eq!(resp.status(), 200);
        let json = resp.json().unwrap();
        assert!(json["sub"].is_string());

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn userinfo_with_missing_token() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;

        let resp = target
            .get(&format!("/realms/{}/protocol/openid-connect/userinfo", realm.name))
            .await;
        assert_eq!(resp.status(), 401);
        // Keycloak returns an empty body; Issuerd returns JSON.
        // Only assert the error JSON when present.
        if let Ok(json) = resp.json() {
            assert_eq!(json["error"], "invalid_token");
        }

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn introspection_active_token() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let client = target.create_client(&realm.name, false).await;
        let _user = target.create_user(&realm.name, "alice", "password123").await;

        let tokens = target
            .get_token_via_password_grant(
                &realm.name,
                &client.client_id,
                client.secret.as_deref(),
                "alice",
                "password123",
                "openid",
            )
            .await;

        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token/introspect", realm.name),
                &[
                    ("token", &tokens.access_token),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                ],
            )
            .await;
        assert_eq!(resp.status(), 200);
        let json = resp.json().unwrap();
        assert_eq!(json["active"], true);
        assert!(json["scope"].is_string());
        assert!(json["client_id"].is_string());
        assert!(json["exp"].is_number());

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn introspection_inactive_token() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let client = target.create_client(&realm.name, false).await;

        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token/introspect", realm.name),
                &[
                    ("token", "random-invalid-token"),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                ],
            )
            .await;
        assert_eq!(resp.status(), 200);
        let json = resp.json().unwrap();
        assert_eq!(json["active"], false);

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn revocation_returns_ok() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let client = target.create_client(&realm.name, false).await;
        let _user = target.create_user(&realm.name, "alice", "password123").await;

        let tokens = target
            .get_token_via_password_grant(
                &realm.name,
                &client.client_id,
                client.secret.as_deref(),
                "alice",
                "password123",
                "openid",
            )
            .await;

        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/revoke", realm.name),
                &[
                    ("token", &tokens.access_token),
                    ("token_type_hint", "access_token"),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                ],
            )
            .await;
        assert_eq!(resp.status(), 200);

        // Introspect again
        let resp2 = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token/introspect", realm.name),
                &[
                    ("token", &tokens.access_token),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                ],
            )
            .await;
        assert_eq!(resp2.status(), 200);
        let json = resp2.json().unwrap();
        assert_eq!(json["active"], false);

        target.cleanup().await;
    })
    .await;
}
