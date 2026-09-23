// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Refresh token lifecycle integration tests (dual-target).

use crate::harness::for_each_target;

#[tokio::test]
async fn refresh_token_issued_and_exchangeable() {
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
        let refresh_token = tokens.refresh_token.expect("refresh token missing");

        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token", realm.name),
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh_token),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                    ("scope", "openid"),
                ],
            )
            .await;
        assert_eq!(resp.status(), 200);
        let json = resp.json().unwrap();
        assert!(json["access_token"].as_str().unwrap().len() > 10);

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn refresh_token_with_invalid_token_rejected() {
    for_each_target(|target| async move {
        let realm_name = format!("test-{}", issuerd_core::utils::generate_id());
        let realm = target.create_realm(&realm_name).await;
        let client = target.create_client(&realm.name, false).await;

        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token", realm.name),
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", "bogus"),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                    ("scope", "openid"),
                ],
            )
            .await;
        assert_eq!(resp.status(), 400);
        let json = resp.json().unwrap();
        assert_eq!(json["error"], "invalid_grant");

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn logout_clears_session_and_refresh_fails() {
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
        let refresh_token = tokens.refresh_token.expect("refresh token missing");

        // Logout
        let logout_resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/logout", realm.name),
                &[
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                    ("refresh_token", &refresh_token),
                ],
            )
            .await;
        // Keycloak may return 200, Issuerd returns 204 — accept either
        assert!(
            logout_resp.status() == 200 || logout_resp.status() == 204,
            "logout returned unexpected status: {}",
            logout_resp.status()
        );

        // Refresh should now fail
        let resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token", realm.name),
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh_token),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                    ("scope", "openid"),
                ],
            )
            .await;
        assert_eq!(resp.status(), 400);
        let json = resp.json().unwrap();
        assert_eq!(json["error"], "invalid_grant");

        target.cleanup().await;
    })
    .await;
}

#[tokio::test]
async fn revoke_access_token_makes_introspection_inactive() {
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
        let access_token = &tokens.access_token;

        // Introspect before revocation - should be active
        let introspect_resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token/introspect", realm.name),
                &[
                    ("token", access_token),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                ],
            )
            .await;
        assert_eq!(introspect_resp.status(), 200);
        let json = introspect_resp.json().unwrap();
        assert_eq!(json["active"], true);

        // Revoke
        let revoke_resp = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/revoke", realm.name),
                &[
                    ("token", access_token),
                    ("token_type_hint", "access_token"),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                ],
            )
            .await;
        assert_eq!(revoke_resp.status(), 200);

        // Introspect after revocation - should be inactive
        let introspect_resp2 = target
            .post_form(
                &format!("/realms/{}/protocol/openid-connect/token/introspect", realm.name),
                &[
                    ("token", access_token),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                ],
            )
            .await;
        assert_eq!(introspect_resp2.status(), 200);
        let json2 = introspect_resp2.json().unwrap();
        assert_eq!(json2["active"], false);

        target.cleanup().await;
    })
    .await;
}
