// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Offline token semantics integration tests (Issuerd-only).
//!
//! Keycloak semantics (plan option b): every flow keeps issuing refresh
//! tokens, but the **offline** class (`typ: Offline`, own idle timeout via
//! `Realm.offline_session_idle_timeout`, survives SSO session expiry) is
//! unlocked only when the granted scopes include `offline_access`. The auth
//! code flow additionally keeps the SSO session and the offline session as
//! separate rows, mirroring Keycloak's `createOrUpdateOfflineSession`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use crate::harness::TestHarness;

/// Decode the payload segment of a JWT without verifying the signature.
fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Create a confidential client with `offline_access` among its optional
/// scopes (requested scopes are validated against the client's assigned
/// scopes, so the scope must be assignable before it can be granted).
async fn create_offline_client(harness: &TestHarness, realm: &str) -> issuerd_core::Client {
    let mut client = harness.create_client(realm, false).await;
    client.optional_scopes = issuerd_core::Scope::parse("email offline_access");
    harness.storage.update_client(&client.realm_id, &client).await.unwrap();
    client
}

/// ROPC login; asserts HTTP 200 and returns the decoded token response.
async fn password_grant(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    password: &str,
    scope: &str,
) -> serde_json::Value {
    let resp = harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/token"),
            &[
                ("grant_type", "password"),
                ("username", username),
                ("password", password),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", scope),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Run the refresh grant; returns the raw response.
async fn refresh_grant(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    refresh_token: &str,
) -> axum::response::Response {
    harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/token"),
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await
}

/// Move a session's idle clock back by `age_secs`.
async fn age_session(
    harness: &TestHarness,
    realm_id: &issuerd_core::RealmId,
    session_id: &issuerd_core::SessionId,
    age_secs: i64,
) {
    let mut session = harness
        .storage
        .get_user_session(realm_id, session_id)
        .await
        .unwrap()
        .expect("session must exist");
    session.last_session_refresh = chrono::Utc::now() - chrono::Duration::seconds(age_secs);
    harness.storage.update_user_session(realm_id, &session).await.unwrap();
}

/// The single session currently stored for the user (ROPC flows create one).
async fn only_session(
    harness: &TestHarness,
    realm_id: &issuerd_core::RealmId,
    user_id: &issuerd_core::UserId,
) -> issuerd_core::UserSession {
    let sessions = harness
        .storage
        .list_sessions(realm_id, Some(user_id.clone()), &issuerd_core::Pagination::default())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1, "expected exactly one session");
    sessions.into_iter().next().unwrap()
}

#[tokio::test]
async fn password_grant_without_offline_scope_issues_online_refresh_token() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("off-plain").await;
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let json =
        password_grant(&harness, realm.name.as_ref(), &client, "alice", "password123", "openid")
            .await;
    let refresh = json["refresh_token"].as_str().expect("refresh token");
    let claims = jwt_claims(refresh);
    assert_eq!(claims["typ"], "Refresh");
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        realm.refresh_token_lifespan.get() as i64
    );

    let session = only_session(&harness, &realm.id, &user.id).await;
    assert!(!session.offline);
    assert_eq!(session.id.as_ref(), claims["sid"].as_str().unwrap());
}

#[tokio::test]
async fn password_grant_with_offline_scope_issues_offline_token_and_session() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("off-ropc").await;
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let json = password_grant(
        &harness,
        realm.name.as_ref(),
        &client,
        "alice",
        "password123",
        "openid offline_access",
    )
    .await;
    let refresh = json["refresh_token"].as_str().expect("refresh token");
    let claims = jwt_claims(refresh);
    assert_eq!(claims["typ"], "Offline");
    assert!(claims["scope"].as_str().unwrap().contains("offline_access"));
    // Offline tokens derive their lifetime from the offline idle window.
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        realm.offline_session_idle_timeout.get() as i64
    );

    let session = only_session(&harness, &realm.id, &user.id).await;
    assert!(session.offline);
    assert_eq!(session.id.as_ref(), claims["sid"].as_str().unwrap());
}

#[tokio::test]
async fn refresh_rotation_preserves_offline_class() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("off-rotate").await;
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let _user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let json = password_grant(
        &harness,
        realm.name.as_ref(),
        &client,
        "alice",
        "password123",
        "openid offline_access",
    )
    .await;
    let refresh = json["refresh_token"].as_str().unwrap();
    let original_sid = jwt_claims(refresh)["sid"].as_str().unwrap().to_string();

    let resp = refresh_grant(&harness, realm.name.as_ref(), &client, refresh).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let rotated: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_refresh = rotated["refresh_token"].as_str().expect("rotated refresh token");
    let new_claims = jwt_claims(new_refresh);
    assert_eq!(new_claims["typ"], "Offline");
    assert_eq!(new_claims["sid"].as_str().unwrap(), original_sid);

    // The rotated token works; the old one was revoked by rotation.
    let resp = refresh_grant(&harness, realm.name.as_ref(), &client, new_refresh).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = refresh_grant(&harness, realm.name.as_ref(), &client, refresh).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn offline_refresh_survives_sso_idle_expiry() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("off-sso-idle").await;
    realm.sso_session_idle_timeout = issuerd_core::SecondsNonZero::new(60);
    harness.storage.update_realm(&realm).await.unwrap();
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let json = password_grant(
        &harness,
        realm.name.as_ref(),
        &client,
        "alice",
        "password123",
        "openid offline_access",
    )
    .await;
    let refresh = json["refresh_token"].as_str().unwrap().to_string();

    // Age the offline session past the SSO idle window (60s): an online
    // session would be rejected and deleted here.
    let session = only_session(&harness, &realm.id, &user.id).await;
    age_session(&harness, &realm.id, &session.id, 3600).await;

    let resp = refresh_grant(&harness, realm.name.as_ref(), &client, &refresh).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn offline_refresh_cut_off_past_offline_idle() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("off-idle-cut").await;
    realm.offline_session_idle_timeout = issuerd_core::SecondsNonZero::new(60);
    harness.storage.update_realm(&realm).await.unwrap();
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let json = password_grant(
        &harness,
        realm.name.as_ref(),
        &client,
        "alice",
        "password123",
        "openid offline_access",
    )
    .await;
    let refresh = json["refresh_token"].as_str().unwrap().to_string();

    // Past the offline idle window the refresh fails and the offline session
    // is cleaned up (the token's own exp — minted as now + 60s — still holds
    // because `update_user_session` does not touch the signed JWT).
    let session = only_session(&harness, &realm.id, &user.id).await;
    age_session(&harness, &realm.id, &session.id, 3600).await;

    let resp = refresh_grant(&harness, realm.name.as_ref(), &client, &refresh).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
    assert!(
        harness
            .storage
            .get_user_session(&realm.id, &session.id)
            .await
            .unwrap()
            .is_none(),
        "idle-expired offline session must be deleted"
    );
}

#[tokio::test]
async fn online_refresh_still_bound_by_sso_idle() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("off-online-idle").await;
    realm.sso_session_idle_timeout = issuerd_core::SecondsNonZero::new(60);
    harness.storage.update_realm(&realm).await.unwrap();
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let json =
        password_grant(&harness, realm.name.as_ref(), &client, "alice", "password123", "openid")
            .await;
    let refresh = json["refresh_token"].as_str().unwrap().to_string();

    let session = only_session(&harness, &realm.id, &user.id).await;
    assert!(!session.offline);
    age_session(&harness, &realm.id, &session.id, 3600).await;

    let resp = refresh_grant(&harness, realm.name.as_ref(), &client, &refresh).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_session_listing_marks_offline_sessions() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("off-admin").await;
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let _user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    password_grant(&harness, realm.name.as_ref(), &client, "alice", "password123", "openid").await;
    password_grant(
        &harness,
        realm.name.as_ref(),
        &client,
        "alice",
        "password123",
        "openid offline_access",
    )
    .await;

    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let resp = harness
        .get_auth(&format!("/admin/realms/{}/sessions", realm.name), &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let sessions: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let rows = sessions.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let offline_count = rows.iter().filter(|s| s["offline"] == true).count();
    assert_eq!(offline_count, 1, "exactly one session must be marked offline");
}

#[tokio::test]
async fn auth_code_flow_mints_separate_offline_session_that_survives_sso() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("off-code").await;
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    // Browser login with the offline_access scope requested.
    let auth_path = format!(
        "/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid%20offline_access&state=xyz",
        realm.name, client.client_id
    );
    let resp = harness.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("execution_id");

    let login_resp = harness
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={}", realm.name),
            serde_json::json!({
                "execution_id": execution_id,
                "username": "alice",
                "password": "password123",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let sso_prefix = format!("issuerd_session_{}=", realm.id);
    let sso_cookie = login_resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().unwrap().strip_prefix(sso_prefix.as_str()))
        .map(|rest| rest.split(';').next().unwrap().to_string())
        .next()
        .expect("issuerd_session cookie");
    let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let code = login_json["code"].as_str().unwrap();

    let resp = harness
        .post_form(
            &format!("/realms/{}/protocol/openid-connect/token", realm.name),
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refresh = token_json["refresh_token"].as_str().unwrap().to_string();
    let refresh_claims = jwt_claims(&refresh);

    // Two sessions: the online SSO session (cookie) and the offline session
    // backing the refresh token.
    let sessions = harness
        .storage
        .list_sessions(&realm.id, Some(user.id.clone()), &issuerd_core::Pagination::default())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2, "expected online + offline sessions");
    let offline_session = sessions.iter().find(|s| s.offline).expect("offline session");
    let online_session = sessions.iter().find(|s| !s.offline).expect("online session");

    let cookie_sid = jwt_claims(&sso_cookie)["sid"].as_str().unwrap().to_string();
    assert_eq!(cookie_sid, online_session.id.as_ref());
    assert_eq!(refresh_claims["typ"], "Offline");
    assert_eq!(refresh_claims["sid"].as_str().unwrap(), offline_session.id.as_ref());
    // The access token from the redemption also rides the offline session.
    let access_claims = jwt_claims(token_json["access_token"].as_str().unwrap());
    assert_eq!(access_claims["sid"].as_str().unwrap(), offline_session.id.as_ref());

    // The offline session is invisible to SSO cookie resolution: a browser
    // presenting an offline-session token gets no SSO login...
    let auth_resp = harness
        .get(&format!(
            "/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
            realm.name, client.client_id
        ))
        .await;
    // sanity: endpoint reachable (no cookie) → redirected to login
    assert_eq!(auth_resp.status(), StatusCode::SEE_OTHER);

    // ...and killing the SSO session (logout / idle expiry) does not stop
    // the offline refresh token.
    harness
        .storage
        .delete_user_session(&realm.id, &online_session.id)
        .await
        .unwrap();
    let resp = refresh_grant(&harness, realm.name.as_ref(), &client, &refresh).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Deleting the offline session does cut the token off.
    harness
        .storage
        .delete_user_session(&realm.id, &offline_session.id)
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let rotated: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let resp = refresh_grant(
        &harness,
        realm.name.as_ref(),
        &client,
        rotated["refresh_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// An offline session must never serve as an SSO session: a cookie carrying
/// an access token whose sid belongs to an offline session resolves to "no
/// SSO session" instead of silently extending the offline session's life via
/// the browser idle rules.
#[tokio::test]
async fn offline_session_not_resolvable_via_sso_cookie() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("off-cookie").await;
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let _user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let json = password_grant(
        &harness,
        realm.name.as_ref(),
        &client,
        "alice",
        "password123",
        "openid offline_access",
    )
    .await;
    let access = json["access_token"].as_str().unwrap();

    // Forging an issuerd_session cookie out of the ROPC access token: the
    // authorize endpoint must NOT treat the offline session as SSO state
    // (it would 303 straight to the redirect_uri with a code if it did).
    let auth_path = format!(
        "/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        realm.name, client.client_id
    );
    let req = Request::builder()
        .method("GET")
        .uri(&auth_path)
        .header("cookie", format!("issuerd_session_{}={access}", realm.id))
        .body(Body::empty())
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.contains("/login.html"),
        "offline session must not satisfy SSO; got redirect to {location}"
    );
}

/// Real HTTP RP-initiated logout (2026-09 review fix): the browser logout must
/// destroy the ONLINE SSO session referenced by the `issuerd_session` cookie while
/// leaving the OFFLINE session — and its offline refresh token — alive. The
/// issued tokens point at the offline session, so the pre-fix behavior was
/// exactly inverted (offline killed, online kept).
#[tokio::test]
async fn http_logout_ends_cookie_sso_session_but_preserves_offline_grant() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("off-logout").await;
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    // Full browser login with offline_access.
    let auth_path = format!(
        "/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid%20offline_access&state=xyz",
        realm.name, client.client_id
    );
    let resp = harness.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("execution_id");

    let login_resp = harness
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={}", realm.name),
            serde_json::json!({
                "execution_id": execution_id,
                "username": "alice",
                "password": "password123",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let sso_prefix = format!("issuerd_session_{}=", realm.id);
    let sso_cookie = login_resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().unwrap().strip_prefix(sso_prefix.as_str()))
        .map(|rest| rest.split(';').next().unwrap().to_string())
        .next()
        .expect("issuerd_session cookie");
    let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let code = login_json["code"].as_str().unwrap();

    let resp = harness
        .post_form(
            &format!("/realms/{}/protocol/openid-connect/token", realm.name),
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let id_token = token_json["id_token"].as_str().unwrap().to_string();
    let refresh = token_json["refresh_token"].as_str().unwrap().to_string();

    let sessions = harness
        .storage
        .list_sessions(&realm.id, Some(user.id.clone()), &issuerd_core::Pagination::default())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2, "expected online + offline sessions");
    let offline_id = sessions.iter().find(|s| s.offline).unwrap().id.clone();
    let online_id = sessions.iter().find(|s| !s.offline).unwrap().id.clone();

    // RP-initiated logout: id_token_hint + the browser's SSO cookie.
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/realms/{}/protocol/openid-connect/logout?id_token_hint={}",
            realm.name, id_token
        ))
        .header("cookie", format!("issuerd_session_{}={sso_cookie}", realm.id))
        .body(Body::empty())
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The online SSO session is gone…
    assert!(
        harness.storage.get_user_session(&realm.id, &online_id).await.unwrap().is_none(),
        "browser logout must destroy the SSO session"
    );
    // …and the offline session (the id_token_hint's sid) survived.
    assert!(
        harness
            .storage
            .get_user_session(&realm.id, &offline_id)
            .await
            .unwrap()
            .is_some(),
        "browser logout must not destroy the offline session"
    );

    // The offline refresh token still redeems.
    let resp = refresh_grant(&harness, realm.name.as_ref(), &client, &refresh).await;
    assert_eq!(resp.status(), StatusCode::OK, "offline grant must survive browser logout");

    // And the destroyed SSO session no longer authenticates the browser:
    // authorize with the old cookie must fall back to the login page, not
    // silently mint a code.
    let req = Request::builder()
        .method("GET")
        .uri(&auth_path)
        .header("cookie", format!("issuerd_session_{}={sso_cookie}", realm.id))
        .body(Body::empty())
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.contains("/login.html"),
        "dead SSO session must not re-authenticate; got {location}"
    );
}

/// Logout with an explicitly presented refresh token terminates that grant —
/// including an offline session (RFC 7009-style termination via logout).
#[tokio::test]
async fn http_logout_with_refresh_token_terminates_offline_grant() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("off-logout-rt").await;
    let client = create_offline_client(&harness, realm.name.as_ref()).await;
    let user = harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let json = password_grant(
        &harness,
        realm.name.as_ref(),
        &client,
        "alice",
        "password123",
        "openid offline_access",
    )
    .await;
    let refresh = json["refresh_token"].as_str().unwrap().to_string();
    let session = only_session(&harness, &realm.id, &user.id).await;
    assert!(session.offline);

    let resp = harness
        .post_form(
            &format!("/realms/{}/protocol/openid-connect/logout", realm.name),
            &[("refresh_token", refresh.as_str())],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The offline session is gone and the rotated-token chain is dead.
    assert!(harness
        .storage
        .get_user_session(&realm.id, &session.id)
        .await
        .unwrap()
        .is_none());
    let resp = refresh_grant(&harness, realm.name.as_ref(), &client, &refresh).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Refresh-time narrowing (RFC 6749 §6) restricts only the new access token:
/// the rotated refresh token keeps the original grant, so narrowing does not
/// accumulate across rotations (2026-09 review fix).
#[tokio::test]
async fn refresh_narrowing_does_not_shrink_the_grant() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("off-narrow").await;
    let client = harness.create_client(realm.name.as_ref(), false).await;
    harness.create_user(realm.name.as_ref(), "alice", "password123").await;

    let json = password_grant(
        &harness,
        realm.name.as_ref(),
        &client,
        "alice",
        "password123",
        "openid profile email",
    )
    .await;
    let refresh = json["refresh_token"].as_str().unwrap().to_string();

    // Narrow the next access token to `openid`…
    let resp = harness
        .post_form(
            &format!("/realms/{}/protocol/openid-connect/token", realm.name),
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let narrowed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(narrowed["scope"].as_str().unwrap(), "openid");
    assert_eq!(
        jwt_claims(narrowed["access_token"].as_str().unwrap())["scope"]
            .as_str()
            .unwrap(),
        "openid"
    );

    // …then widen back to the full grant with the rotated token: this must
    // succeed (the grant itself was never narrowed).
    let rotated = narrowed["refresh_token"].as_str().unwrap();
    let resp = harness
        .post_form(
            &format!("/realms/{}/protocol/openid-connect/token", realm.name),
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", rotated),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid profile email"),
            ],
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "rotated refresh token must keep the original grant scope"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let restored: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Scope tokens are normalized (sorted) on the wire.
    assert_eq!(restored["scope"].as_str().unwrap(), "email openid profile");
}
