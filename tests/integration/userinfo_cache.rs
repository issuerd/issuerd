// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
//! End-to-end semantics of the rendered userinfo response cache
//! (`issuerd_server::userinfo_cache`): identical bodies on repeat calls,
//! next-request visibility of user/definition changes, and the validity
//! gates (logout) that run above the cache on every request.

use crate::harness::TestHarness;

/// Password-grant token for the realm's confidential client.
async fn password_token(
    harness: &TestHarness,
    realm: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> serde_json::Value {
    let resp = harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/token"),
            &[
                ("grant_type", "password"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("username", "alice"),
                ("password", "password123"),
                ("scope", scope),
            ],
        )
        .await;
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn userinfo(harness: &TestHarness, realm: &str, token: &str) -> (u16, serde_json::Value) {
    let resp = harness
        .get_auth(&format!("/realms/{realm}/protocol/openid-connect/userinfo"), token)
        .await;
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn repeat_userinfo_serves_identical_body() {
    let harness = TestHarness::new().await;
    harness.create_realm("ui-cache").await;
    let client = harness.create_client("ui-cache", false).await;
    harness.create_user("ui-cache", "alice", "password123").await;

    let tokens = password_token(
        &harness,
        "ui-cache",
        &client.client_id,
        client.secret.as_deref().unwrap(),
        "openid profile",
    )
    .await;
    let token = tokens["access_token"].as_str().unwrap();

    let (s1, body1) = userinfo(&harness, "ui-cache", token).await;
    let (s2, body2) = userinfo(&harness, "ui-cache", token).await;
    assert_eq!((s1, s2), (200, 200));
    assert_eq!(body1, body2, "cached body must be byte-identical");
    assert_eq!(body1["given_name"], "Test", "profile scope maps first_name");
}

#[tokio::test]
async fn user_change_is_visible_on_the_next_request() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("ui-cache-edit").await;
    let client = harness.create_client("ui-cache-edit", false).await;
    let user = harness.create_user("ui-cache-edit", "alice", "password123").await;

    let tokens = password_token(
        &harness,
        "ui-cache-edit",
        &client.client_id,
        client.secret.as_deref().unwrap(),
        "openid profile",
    )
    .await;
    let token = tokens["access_token"].as_str().unwrap();

    let (_, body) = userinfo(&harness, "ui-cache-edit", token).await;
    assert_eq!(body["given_name"], "Test");
    // Second call populates + serves the rendered-response cache entry.
    let (_, body) = userinfo(&harness, "ui-cache-edit", token).await;
    assert_eq!(body["given_name"], "Test");

    // Direct storage mutation + the documented invalidation helper (the
    // AGENTS.md contract for tests bypassing the admin API).
    let mut renamed = user.clone();
    renamed.first_name = Some(issuerd_core::DisplayName::new("Changed").unwrap());
    harness.storage.update_user(&realm.id, &renamed).await.unwrap();
    issuerd_cluster::invalidate::invalidate_user_claims(
        harness.cache.as_ref(),
        &realm.id,
        &user.id,
    )
    .await;

    let (status, body) = userinfo(&harness, "ui-cache-edit", token).await;
    assert_eq!(status, 200);
    assert_eq!(body["given_name"], "Changed", "edit must be visible on the next request");
}

#[tokio::test]
async fn definition_change_epoch_bump_rebuilds_immediately() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("ui-cache-epoch").await;
    let client = harness.create_client("ui-cache-epoch", false).await;
    harness.create_user("ui-cache-epoch", "alice", "password123").await;

    let tokens = password_token(
        &harness,
        "ui-cache-epoch",
        &client.client_id,
        client.secret.as_deref().unwrap(),
        "openid profile",
    )
    .await;
    let token = tokens["access_token"].as_str().unwrap();

    let (_, body1) = userinfo(&harness, "ui-cache-epoch", token).await;
    // Realm-wide definition change (role/scope/mapper CRUD) bumps the epoch.
    issuerd_cluster::invalidate::bump_claims_epoch(harness.cache.as_ref(), &realm.id).await;
    let (status, body2) = userinfo(&harness, "ui-cache-epoch", token).await;
    assert_eq!(status, 200);
    assert_eq!(body1, body2, "rebuild after epoch bump serves the same content");
}

#[tokio::test]
async fn logout_invalidates_immediately_despite_response_cache() {
    let harness = TestHarness::new().await;
    harness.create_realm("ui-cache-logout").await;
    let client = harness.create_client("ui-cache-logout", false).await;
    harness.create_user("ui-cache-logout", "alice", "password123").await;

    let tokens = password_token(
        &harness,
        "ui-cache-logout",
        &client.client_id,
        client.secret.as_deref().unwrap(),
        "openid profile",
    )
    .await;
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");

    // Warm the response cache.
    assert_eq!(userinfo(&harness, "ui-cache-logout", access).await.0, 200);
    assert_eq!(userinfo(&harness, "ui-cache-logout", access).await.0, 200);

    // Logout via the RP-initiated endpoint (kills the session synchronously).
    let resp = harness
        .post_form(
            "/realms/ui-cache-logout/protocol/openid-connect/logout",
            &[
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("refresh_token", refresh),
            ],
        )
        .await;
    assert!(resp.status() == 200 || resp.status() == 204, "logout: {}", resp.status());

    let (status, _) = userinfo(&harness, "ui-cache-logout", access).await;
    assert_eq!(status, 401, "a cached body must never outlive the session");
}

#[tokio::test]
async fn scope_sets_get_separate_cache_entries() {
    let harness = TestHarness::new().await;
    harness.create_realm("ui-cache-fp").await;
    let client = harness.create_client("ui-cache-fp", false).await;
    harness.create_user("ui-cache-fp", "alice", "password123").await;

    let full = password_token(
        &harness,
        "ui-cache-fp",
        &client.client_id,
        client.secret.as_deref().unwrap(),
        "openid profile",
    )
    .await;
    let narrow = password_token(
        &harness,
        "ui-cache-fp",
        &client.client_id,
        client.secret.as_deref().unwrap(),
        "openid",
    )
    .await;

    let (_, full_body) =
        userinfo(&harness, "ui-cache-fp", full["access_token"].as_str().unwrap()).await;
    let (_, narrow_body) =
        userinfo(&harness, "ui-cache-fp", narrow["access_token"].as_str().unwrap()).await;
    assert!(full_body.get("given_name").is_some());
    assert!(
        narrow_body.get("given_name").is_none(),
        "profile claims must not leak into the openid-only response: {narrow_body:?}"
    );

    // Repeat both: the cached entries stay distinct.
    let (_, full_body2) =
        userinfo(&harness, "ui-cache-fp", full["access_token"].as_str().unwrap()).await;
    let (_, narrow_body2) =
        userinfo(&harness, "ui-cache-fp", narrow["access_token"].as_str().unwrap()).await;
    assert_eq!(full_body, full_body2);
    assert_eq!(narrow_body, narrow_body2);
}
