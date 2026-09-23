// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// User self-service integration tests: remember-me cookie and SSO idle enforcement.

//! User self-service integration tests (Issuerd-only).
//!
//! Remember-me (plan §3): the login checkbox issues a long-lived, realm-bound
//! `issuerd_remember` action-token cookie and marks the stored session; the cookie
//! silently re-establishes a remembered session after SSO idle expiry; the
//! realm toggle gates honoring it; and the SSO/remember-me idle split is
//! enforced both on cookie resolution and on the refresh-token grant.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use crate::harness::TestHarness;

/// Create a realm with the remember-me toggle in the requested state.
async fn create_realm_with_remember_me(
    harness: &TestHarness,
    name: &str,
    enabled: bool,
) -> issuerd_core::Realm {
    let mut realm = harness.create_realm(name).await;
    realm.remember_me_enabled = enabled;
    harness.storage.update_realm(&realm).await.unwrap();
    realm
}

/// Start an authorization code flow and return the browser flow id.
async fn start_auth_flow(harness: &TestHarness, realm: &str, client_id: &str) -> String {
    let auth_path = format!(
        "/realms/{realm}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz"
    );
    let resp = harness.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id")
}

/// POST the browser login form; `remember_me` is the raw form value of the
/// checkbox (`Some("on")` when ticked, `None` when absent).
async fn submit_login_form(
    harness: &TestHarness,
    realm: &str,
    execution_id: &str,
    username: &str,
    password: &str,
    remember_me: Option<&str>,
) -> axum::response::Response {
    let mut params = vec![
        ("execution_id", execution_id),
        ("username", username),
        ("password", password),
    ];
    if let Some(v) = remember_me {
        params.push(("remember_me", v));
    }
    harness
        .post_form_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            &params,
            &TestHarness::flow_cookie(execution_id),
        )
        .await
}

/// Exchange an authorization code for tokens; asserts success.
async fn exchange_code(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    code: &str,
) -> serde_json::Value {
    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/token"),
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// GET the authorize endpoint with a raw Cookie header.
async fn get_authorize_with_cookie(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    cookie: &str,
) -> axum::response::Response {
    let auth_path = format!(
        "/realms/{realm}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        client.client_id
    );
    let req = Request::builder()
        .method("GET")
        .uri(&auth_path)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

/// Collect every `Set-Cookie` header value of a response.
fn set_cookies(resp: &axum::response::Response) -> Vec<String> {
    resp.headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// Extract the value of one cookie out of `Set-Cookie` header values.
fn cookie_value(cookies: &[String], name: &str) -> Option<String> {
    cookies.iter().find_map(|c| {
        c.strip_prefix(&format!("{name}="))
            .map(|rest| rest.split(';').next().unwrap().to_string())
    })
}

/// Decode the payload segment of a JWT without verifying the signature.
fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Load the stored session referenced by an `issuerd_session` cookie JWT.
async fn session_for_sso_cookie(
    harness: &TestHarness,
    realm_id: &issuerd_core::RealmId,
    sso_cookie: &str,
) -> issuerd_core::UserSession {
    let sid = jwt_claims(sso_cookie)["sid"].as_str().expect("sid claim").to_string();
    let sid = issuerd_core::SessionId::new(sid).unwrap();
    harness
        .storage
        .get_user_session(realm_id, &sid)
        .await
        .unwrap()
        .expect("stored session")
}

/// Per-realm cookie names (must match `issuerd_server::routes::oidc`'s helpers).
fn sso_cookie_name(realm_id: &issuerd_core::RealmId) -> String {
    format!("issuerd_session_{realm_id}")
}
fn remember_cookie_name(realm_id: &issuerd_core::RealmId) -> String {
    format!("issuerd_remember_{realm_id}")
}

/// Log in through the browser form with remember-me ticked; returns the raw
/// per-realm `issuerd_session_{realm}` / `issuerd_remember_{realm}` cookie values and
/// the stored session.
async fn login_with_remember_me(
    harness: &TestHarness,
    realm: &issuerd_core::Realm,
    client: &issuerd_core::Client,
    username: &str,
    password: &str,
) -> (String, String, issuerd_core::UserSession) {
    let exec = start_auth_flow(harness, realm.name.as_ref(), client.client_id.as_ref()).await;
    let resp =
        submit_login_form(harness, realm.name.as_ref(), &exec, username, password, Some("on"))
            .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookies = set_cookies(&resp);
    let sso = cookie_value(&cookies, &sso_cookie_name(&realm.id)).expect("issuerd_session cookie");
    let remember =
        cookie_value(&cookies, &remember_cookie_name(&realm.id)).expect("issuerd_remember cookie");
    let session = session_for_sso_cookie(harness, &realm.id, &sso).await;
    (sso, remember, session)
}

#[tokio::test]
async fn remember_me_login_sets_cookie_and_marks_session() {
    let harness = TestHarness::new().await;
    let realm = create_realm_with_remember_me(&harness, "rm-login", true).await;
    let client = harness.create_client("rm-login", false).await;
    let user = harness.create_user("rm-login", "carol", "password123").await;

    let (_sso, remember, session) =
        login_with_remember_me(&harness, &realm, &client, "carol", "password123").await;

    // The session is flagged, and the remember cookie is a realm-bound action
    // token carrying the original authentication time.
    assert!(session.remember_me);
    let claims = jwt_claims(&remember);
    assert_eq!(
        claims["purpose"].as_str().unwrap(),
        issuerd_core::ACTION_TOKEN_PURPOSE_REMEMBER_ME
    );
    assert_eq!(claims["sub"].as_str().unwrap(), user.id.as_ref());
    assert_eq!(claims["realm"].as_str().unwrap(), realm.id.as_ref());
    assert_eq!(claims["auth_time"].as_i64(), Some(session.auth_time.timestamp()));

    // Cookie attributes: long-lived, browser-hardened.
    let exec = start_auth_flow(&harness, "rm-login", client.client_id.as_ref()).await;
    let resp =
        submit_login_form(&harness, "rm-login", &exec, "carol", "password123", Some("on")).await;
    let header = set_cookies(&resp)
        .into_iter()
        .find(|c| c.starts_with(&format!("{}=", remember_cookie_name(&realm.id))))
        .expect("issuerd_remember set-cookie header");
    assert!(header.contains("HttpOnly"), "header: {header}");
    assert!(header.contains("Secure"), "header: {header}");
    assert!(header.contains("SameSite=Lax"), "header: {header}");
    assert!(header.contains("Path=/"), "header: {header}");
    assert!(header.contains("Max-Age=604800"), "header: {header}");

    // A login without the checkbox sets no remember cookie and a plain session.
    let exec = start_auth_flow(&harness, "rm-login", client.client_id.as_ref()).await;
    let resp = submit_login_form(&harness, "rm-login", &exec, "carol", "password123", None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookies = set_cookies(&resp);
    assert!(cookie_value(&cookies, &remember_cookie_name(&realm.id)).is_none());
    assert!(cookie_value(&cookies, "issuerd_remember").is_none());
    let sso = cookie_value(&cookies, &sso_cookie_name(&realm.id)).expect("issuerd_session cookie");
    let session = session_for_sso_cookie(&harness, &realm.id, &sso).await;
    assert!(!session.remember_me);
}

#[tokio::test]
async fn remember_me_reestablishes_session_after_sso_idle() {
    let harness = TestHarness::new().await;
    let realm = create_realm_with_remember_me(&harness, "rm-sso", true).await;
    let client = harness.create_client("rm-sso", false).await;
    let _user = harness.create_user("rm-sso", "dave", "password123").await;

    let (_sso, remember, old_session) =
        login_with_remember_me(&harness, &realm, &client, "dave", "password123").await;

    // Simulate SSO idle expiry: the stored session is gone.
    harness.storage.delete_user_session(&realm.id, &old_session.id).await.unwrap();

    // The remember cookie alone silently re-establishes the session: the
    // authorize endpoint redirects straight to the client with a code instead
    // of bouncing to the login page.
    let resp = get_authorize_with_cookie(
        &harness,
        "rm-sso",
        &client,
        &format!("{}={remember}", remember_cookie_name(&realm.id)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(
        location.starts_with("http://localhost:8080/cb?"),
        "expected client redirect, got {location}"
    );
    let code = TestHarness::extract_query_param(&location, "code").expect("code in redirect");

    // The code redeems; the new session is a *remembered* session carrying the
    // original authentication time.
    let tokens = exchange_code(&harness, "rm-sso", &client, &code).await;
    let new_sid = jwt_claims(tokens["access_token"].as_str().unwrap())["sid"]
        .as_str()
        .unwrap()
        .to_string();
    let new_sid = issuerd_core::SessionId::new(new_sid).unwrap();
    let new_session = harness
        .storage
        .get_user_session(&realm.id, &new_sid)
        .await
        .unwrap()
        .expect("new session");
    assert_ne!(new_session.id, old_session.id);
    assert!(new_session.remember_me);
    assert_eq!(new_session.auth_time.timestamp(), old_session.auth_time.timestamp());
}

#[tokio::test]
async fn remember_me_cookie_not_honored_when_realm_disables_it() {
    let harness = TestHarness::new().await;
    let realm = create_realm_with_remember_me(&harness, "rm-toggle", true).await;
    let client = harness.create_client("rm-toggle", false).await;
    let _user = harness.create_user("rm-toggle", "erin", "password123").await;

    // Mint the cookie while the toggle is on, then switch the realm off.
    let (_sso, remember, old_session) =
        login_with_remember_me(&harness, &realm, &client, "erin", "password123").await;
    harness.storage.delete_user_session(&realm.id, &old_session.id).await.unwrap();
    let mut realm = realm;
    realm.remember_me_enabled = false;
    harness.storage.update_realm(&realm).await.unwrap();
    // Direct storage writes bypass the admin API's synchronous invalidation
    // of the realm-by-name cache; drop the entry so the next resolution sees
    // the disabled toggle.
    harness
        .cache
        .delete(&issuerd_cluster::cache_keys::realm_by_name("rm-toggle"))
        .await
        .unwrap();

    // The cookie must not be honored: the flow falls through to the login page.
    let resp = get_authorize_with_cookie(
        &harness,
        "rm-toggle",
        &client,
        &format!("{}={remember}", remember_cookie_name(&realm.id)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(
        location.starts_with("/login.html"),
        "expected login page redirect, got {location}"
    );
}

#[tokio::test]
async fn sso_idle_timeout_rejects_refresh_and_deletes_session() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("rm-idle").await;
    let client = harness.create_client("rm-idle", false).await;
    let _user = harness.create_user("rm-idle", "frank", "password123").await;

    let tokens = harness
        .authenticate_user("rm-idle", client.client_id.as_ref(), "frank", "password123")
        .await;
    let realm_id = issuerd_core::RealmId::new("rm-idle").unwrap();
    let mut session = session_for_sso_cookie(&harness, &realm_id, &tokens.access_token).await;
    assert!(!session.remember_me);

    // Push the session past the realm's SSO idle timeout (default 1800 s).
    session.last_session_refresh = chrono::Utc::now() - chrono::Duration::seconds(1800 + 60);
    harness.storage.update_user_session(&realm_id, &session).await.unwrap();

    let resp = harness
        .post_form(
            "/realms/rm-idle/protocol/openid-connect/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", tokens.refresh_token.as_deref().unwrap()),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"].as_str().unwrap(), "invalid_grant");

    // The idle-expired session is gone.
    assert!(harness
        .storage
        .get_user_session(&realm_id, &session.id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn refresh_within_idle_window_extends_session() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("rm-refresh").await;
    let client = harness.create_client("rm-refresh", false).await;
    let _user = harness.create_user("rm-refresh", "grace", "password123").await;

    let tokens = harness
        .authenticate_user("rm-refresh", client.client_id.as_ref(), "grace", "password123")
        .await;
    let realm_id = issuerd_core::RealmId::new("rm-refresh").unwrap();
    let mut session = session_for_sso_cookie(&harness, &realm_id, &tokens.access_token).await;

    // Well within the idle window: the refresh must succeed and bump
    // `last_session_refresh` back to ~now.
    let rewound = chrono::Utc::now() - chrono::Duration::seconds(60);
    session.last_session_refresh = rewound;
    harness.storage.update_user_session(&realm_id, &session).await.unwrap();

    let resp = harness
        .post_form(
            "/realms/rm-refresh/protocol/openid-connect/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", tokens.refresh_token.as_deref().unwrap()),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let session = harness.storage.get_user_session(&realm_id, &session.id).await.unwrap().unwrap();
    assert!(
        session.last_session_refresh > rewound + chrono::Duration::seconds(30),
        "last_session_refresh not bumped: {}",
        session.last_session_refresh
    );
}

#[tokio::test]
async fn remembered_session_survives_plain_sso_idle_on_cookie() {
    let harness = TestHarness::new().await;
    let realm = create_realm_with_remember_me(&harness, "rm-split", true).await;
    let client = harness.create_client("rm-split", false).await;
    let _user = harness.create_user("rm-split", "heidi", "password123").await;

    let (sso, _remember, mut session) =
        login_with_remember_me(&harness, &realm, &client, "heidi", "password123").await;

    // Past the plain SSO idle timeout (1800 s) but far inside the remember-me
    // window (604800 s): the session cookie must still authenticate.
    session.last_session_refresh = chrono::Utc::now() - chrono::Duration::seconds(1800 + 60);
    harness.storage.update_user_session(&realm.id, &session).await.unwrap();

    let resp = get_authorize_with_cookie(
        &harness,
        "rm-split",
        &client,
        &format!("{}={sso}", sso_cookie_name(&realm.id)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(
        location.starts_with("http://localhost:8080/cb?"),
        "expected client redirect, got {location}"
    );
    assert!(TestHarness::extract_query_param(&location, "code").is_some());

    // A plain (not remembered) session past the same point is instead deleted
    // and the browser is sent to the login page.
    let exec = start_auth_flow(&harness, "rm-split", client.client_id.as_ref()).await;
    let resp = submit_login_form(&harness, "rm-split", &exec, "heidi", "password123", None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookies = set_cookies(&resp);
    let plain_sso =
        cookie_value(&cookies, &sso_cookie_name(&realm.id)).expect("issuerd_session cookie");
    let mut plain_session = session_for_sso_cookie(&harness, &realm.id, &plain_sso).await;
    assert!(!plain_session.remember_me);
    plain_session.last_session_refresh = chrono::Utc::now() - chrono::Duration::seconds(1800 + 60);
    harness.storage.update_user_session(&realm.id, &plain_session).await.unwrap();

    let resp = get_authorize_with_cookie(
        &harness,
        "rm-split",
        &client,
        &format!("{}={plain_sso}", sso_cookie_name(&realm.id)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(
        location.starts_with("/login.html"),
        "expected login page redirect, got {location}"
    );
    assert!(
        harness
            .storage
            .get_user_session(&realm.id, &plain_session.id)
            .await
            .unwrap()
            .is_none(),
        "idle-expired plain session must be deleted"
    );
}

// ---------------------------------------------------------------------------
// Self-registration (plan §1)
// ---------------------------------------------------------------------------

/// Create a realm with the registration toggle in the requested state.
async fn create_realm_with_registration(
    harness: &TestHarness,
    name: &str,
    enabled: bool,
) -> issuerd_core::Realm {
    let mut realm = harness.create_realm(name).await;
    realm.registration_enabled = enabled;
    harness.storage.update_realm(&realm).await.unwrap();
    realm
}

/// GET the registration page; asserts 200 and returns the flow id.
async fn start_registration(harness: &TestHarness, realm: &str) -> String {
    start_registration_at(harness, &format!("/realms/{realm}/login/register")).await
}

/// GET a registration page URL; asserts 200 and returns the flow id.
async fn start_registration_at(harness: &TestHarness, path: &str) -> String {
    let resp = harness.get(path).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("registration flow cookie");
    cookie
        .strip_prefix("issuerd_flow_")
        .expect("flow cookie name")
        .split('=')
        .next()
        .unwrap()
        .to_string()
}

/// POST the registration form with the correlation cookie a browser sends.
async fn submit_registration(
    harness: &TestHarness,
    realm: &str,
    flow_id: &str,
    fields: &[(&str, &str)],
) -> axum::response::Response {
    let mut params = vec![("flow", flow_id)];
    params.extend_from_slice(fields);
    harness
        .post_form_with_cookie(
            &format!("/realms/{realm}/login/register"),
            &params,
            &TestHarness::flow_cookie(flow_id),
        )
        .await
}

/// A full, valid registration form submission.
fn registration_fields<'a>(
    username: &'a str,
    email: &'a str,
    password: &'a str,
) -> [(&'a str, &'a str); 6] {
    [
        ("username", username),
        ("email", email),
        ("first_name", "Test"),
        ("last_name", "User"),
        ("password", password),
        ("confirm_password", password),
    ]
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn registration_disabled_returns_404() {
    let harness = TestHarness::new().await;
    let _realm = create_realm_with_registration(&harness, "reg-off", false).await;

    let resp = harness.get("/realms/reg-off/login/register").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = harness
        .post_form(
            "/realms/reg-off/login/register",
            &registration_fields("x", "x@example.com", "password123"),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn registration_creates_user_who_can_log_in() {
    let harness = TestHarness::new().await;
    let mut realm = create_realm_with_registration(&harness, "reg-on", true).await;
    let client = harness.create_client("reg-on", false).await;

    // Realm default role, the way the admin API provisions it.
    let role = issuerd_core::Role {
        id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
        name: issuerd_core::RoleName::new("user").unwrap(),
        description: None,
        realm_id: realm.id.clone(),
        client_role: false,
        client_id: None,
        composite: false,
        composites: vec![],
        attributes: std::collections::HashMap::new(),
    };
    harness.storage.create_role(&realm.id, &role).await.unwrap();
    realm.default_role = Some("user".to_string());
    harness.storage.update_realm(&realm).await.unwrap();

    // The form renders.
    let flow_id = start_registration(&harness, "reg-on").await;

    // Submitting it creates the account.
    let resp = submit_registration(
        &harness,
        "reg-on",
        &flow_id,
        &registration_fields("olga", "olga@example.com", "password123"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Registration successful"), "body: {body}");

    let user = harness
        .storage
        .get_user_by_username(&realm.id, "olga")
        .await
        .unwrap()
        .expect("registered user in storage");
    assert!(user.enabled);
    assert!(!user.email_verified);
    assert_eq!(user.email.as_ref().unwrap().as_str(), "olga@example.com");
    assert!(user.required_actions.is_empty());

    // The realm default role was assigned.
    let roles = harness.storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
    assert!(roles.contains(&role.id));

    // The new account logs in through the normal browser login flow.
    let tokens = harness
        .authenticate_user("reg-on", client.client_id.as_ref(), "olga", "password123")
        .await;
    assert!(tokens.access_token.len() > 10);
}

#[tokio::test]
async fn registration_password_policy_violation_rerenders_form() {
    let harness = TestHarness::new().await;
    let mut realm = create_realm_with_registration(&harness, "reg-policy", true).await;
    realm.password_policy.require_digits = true;
    realm.password_policy.require_upper = true;
    harness.storage.update_realm(&realm).await.unwrap();

    let flow_id = start_registration(&harness, "reg-policy").await;
    let resp = submit_registration(
        &harness,
        "reg-policy",
        &flow_id,
        &registration_fields("pavel", "pavel@example.com", "alllowercase"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("require_digits"), "body: {body}");
    assert!(body.contains("require_upper"), "body: {body}");
    // The form is re-rendered with the non-secret values prefilled.
    assert!(body.contains("value=\"pavel\""), "body: {body}");
    assert!(body.contains("value=\"pavel@example.com\""), "body: {body}");

    // No account was created.
    assert!(harness
        .storage
        .get_user_by_username(&realm.id, "pavel")
        .await
        .unwrap()
        .is_none());

    // The same flow id accepts a corrected submission (entry was re-stored).
    let resp = submit_registration(
        &harness,
        "reg-policy",
        &flow_id,
        &registration_fields("pavel", "pavel@example.com", "Str0ngPassword"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Registration successful"));
}

#[tokio::test]
async fn registration_duplicate_email_follows_realm_toggle() {
    let harness = TestHarness::new().await;
    let mut realm = create_realm_with_registration(&harness, "reg-dupe", true).await;
    // Existing account holds the address; duplicates are disallowed by default.
    let _existing = harness.create_user("reg-dupe", "quinn", "password123").await;

    let flow_id = start_registration(&harness, "reg-dupe").await;
    let resp = submit_registration(
        &harness,
        "reg-dupe",
        &flow_id,
        &registration_fields("ruth", "quinn@example.com", "password123"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("email already in use"), "body: {body}");
    assert!(harness.storage.get_user_by_username(&realm.id, "ruth").await.unwrap().is_none());

    // Allow duplicates: the same address now registers a second account.
    realm.duplicate_emails_allowed = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let flow_id = start_registration(&harness, "reg-dupe").await;
    let resp = submit_registration(
        &harness,
        "reg-dupe",
        &flow_id,
        &registration_fields("ruth", "quinn@example.com", "password123"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Registration successful"));
    assert!(harness.storage.get_user_by_username(&realm.id, "ruth").await.unwrap().is_some());
}

#[tokio::test]
async fn registration_verify_email_roundtrip() {
    use issuerd_server::{config::ServerConfig, state::ServerState};

    #[derive(Default)]
    struct RecordingSender {
        sent: std::sync::Mutex<Vec<(String, String, String, Option<String>)>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::EmailSender for RecordingSender {
        async fn send(
            &self,
            _realm: &issuerd_core::Realm,
            to: &str,
            subject: &str,
            text_body: &str,
            html_body: Option<String>,
        ) -> Result<(), issuerd_core::IssuerdError> {
            self.sent.lock().unwrap().push((
                to.to_string(),
                subject.to_string(),
                text_body.to_string(),
                html_body,
            ));
            Ok(())
        }
    }

    let config = ServerConfig::default();
    let mut state = ServerState::from_config(&config).await.unwrap();
    let recorder = std::sync::Arc::new(RecordingSender::default());
    state.email_sender = recorder.clone();
    let harness = TestHarness::with_state(std::sync::Arc::new(state));

    let mut realm = create_realm_with_registration(&harness, "reg-verify", true).await;
    realm.verify_email_enabled = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("reg-verify", false).await;

    let flow_id = start_registration(&harness, "reg-verify").await;
    let resp = submit_registration(
        &harness,
        "reg-verify",
        &flow_id,
        &registration_fields("sofia", "sofia@example.com", "password123"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("verification link"), "body: {body}");

    // The account carries VERIFY_EMAIL and the mail went out immediately.
    let user = harness
        .storage
        .get_user_by_username(&realm.id, "sofia")
        .await
        .unwrap()
        .expect("registered user");
    assert!(!user.email_verified);
    assert_eq!(user.required_actions, vec!["VERIFY_EMAIL".to_string()]);
    // Copy the recorded mail out of the lock before any further .await
    // (clippy::await_holding_lock).
    let (to, text) = {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        (sent[0].0.clone(), sent[0].2.clone())
    };
    assert_eq!(to, "sofia@example.com");
    let link = text
        .lines()
        .find(|l| l.contains("/login/verify-email?token="))
        .expect("verification link in text body")
        .trim()
        .to_string();

    // Follow the link: the email is verified and the action assignment gone.
    let path = link.strip_prefix("http://localhost:8080").unwrap_or(&link).to_string();
    let resp = harness.get(&path).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Email address verified"));
    let user = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert!(user.email_verified);
    assert!(user.required_actions.is_empty());

    // Full acceptance loop: register → verify email → log in.
    let tokens = harness
        .authenticate_user("reg-verify", client.client_id.as_ref(), "sofia", "password123")
        .await;
    assert!(tokens.access_token.len() > 10);
}

#[tokio::test]
async fn registration_post_without_flow_cookie_is_rejected() {
    let harness = TestHarness::new().await;
    let _realm = create_realm_with_registration(&harness, "reg-csrf", true).await;

    // No correlation cookie: login-CSRF protection rejects the POST.
    let resp = harness
        .post_form(
            "/realms/reg-csrf/login/register",
            &registration_fields("ted", "ted@example.com", "password123"),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(harness
        .storage
        .get_user_by_username(&issuerd_core::RealmId::new("reg-csrf").unwrap(), "ted")
        .await
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// In-flow registration (the login page's Register link keeps the execution id)
// ---------------------------------------------------------------------------

/// Start an authorize request and return the login-flow execution id.
async fn start_login_flow(harness: &TestHarness, realm: &str, client_id: &str) -> String {
    let auth_path = format!(
        "/realms/{realm}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz"
    );
    let resp = harness.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    TestHarness::extract_query_param(location, "execution_id")
        .expect("missing execution_id in redirect")
}

/// POST the registration form the way a browser in a login flow does: the
/// registration correlation cookie plus the paused login flow's cookie.
async fn submit_registration_in_flow(
    harness: &TestHarness,
    realm: &str,
    flow_id: &str,
    execution_id: &str,
    fields: &[(&str, &str)],
) -> axum::response::Response {
    let mut params = vec![("flow", flow_id)];
    params.extend_from_slice(fields);
    let cookies = format!(
        "{}; {}",
        TestHarness::flow_cookie(flow_id),
        TestHarness::flow_cookie(execution_id)
    );
    harness
        .post_form_with_cookie(&format!("/realms/{realm}/login/register"), &params, &cookies)
        .await
}

#[tokio::test]
async fn registration_inside_login_flow_completes_into_the_app() {
    let harness = TestHarness::new().await;
    let _realm = create_realm_with_registration(&harness, "reg-inflow", true).await;
    let client = harness.create_client("reg-inflow", false).await;

    // The login page's Register link keeps the login flow's execution id.
    let execution_id = start_login_flow(&harness, "reg-inflow", client.client_id.as_ref()).await;
    let flow_id = start_registration_at(
        &harness,
        &format!("/realms/reg-inflow/login/register?execution_id={execution_id}"),
    )
    .await;

    // A successful registration resumes the paused login: the response is the
    // app redirect carrying the authorization code, not the success page.
    let resp = submit_registration_in_flow(
        &harness,
        "reg-inflow",
        &flow_id,
        &execution_id,
        &registration_fields("ida", "ida@example.com", "password123"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(location.starts_with("http://localhost:8080/cb?"), "location: {location}");
    assert!(location.contains("state=xyz"), "location: {location}");
    let code = TestHarness::extract_query_param(&location, "code").expect("authorization code");

    // The code is real: it exchanges for tokens.
    let token_resp = harness
        .post_form(
            "/realms/reg-inflow/protocol/openid-connect/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(token_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn registration_hint_authorize_redirects_to_register_and_completes_into_the_app() {
    let harness = TestHarness::new().await;
    let _realm = create_realm_with_registration(&harness, "reg-hint", true).await;
    let client = harness.create_client("reg-hint", false).await;

    // Authorize with the `registration=true` hint: the browser is sent
    // straight to the registration form, keeping the paused login flow's
    // execution id.
    let auth_path = format!(
        "/realms/reg-hint/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz&registration=true",
        client.client_id
    );
    let resp = harness.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(
        location.starts_with("/realms/reg-hint/login/register?execution_id="),
        "location: {location}"
    );
    let execution_id = TestHarness::extract_query_param(&location, "execution_id")
        .expect("execution id in register redirect");

    // The register page and POST then behave exactly like an in-flow
    // registration started from the login page's Register link.
    let flow_id = start_registration_at(&harness, &location).await;
    let resp = submit_registration_in_flow(
        &harness,
        "reg-hint",
        &flow_id,
        &execution_id,
        &registration_fields("kara", "kara@example.com", "password123"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(location.starts_with("http://localhost:8080/cb?"), "location: {location}");
    assert!(location.contains("state=xyz"), "location: {location}");
    assert!(TestHarness::extract_query_param(&location, "code").is_some());
}

#[tokio::test]
async fn registration_inside_login_flow_with_verify_email_resumes_via_action_link() {
    use issuerd_server::{config::ServerConfig, state::ServerState};

    let config = ServerConfig::default();
    let mut state = ServerState::from_config(&config).await.unwrap();
    let recorder = std::sync::Arc::new(RecordingSender::default());
    state.email_sender = recorder.clone();
    let harness = TestHarness::with_state(std::sync::Arc::new(state));

    let mut realm = create_realm_with_registration(&harness, "reg-vflow", true).await;
    realm.verify_email_enabled = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("reg-vflow", false).await;

    let execution_id = start_login_flow(&harness, "reg-vflow", client.client_id.as_ref()).await;
    let flow_id = start_registration_at(
        &harness,
        &format!("/realms/reg-vflow/login/register?execution_id={execution_id}"),
    )
    .await;

    // The credentials check out but VERIFY_EMAIL pauses the login: redirect
    // to the required-action continuation, not the standalone success page.
    let resp = submit_registration_in_flow(
        &harness,
        "reg-vflow",
        &flow_id,
        &execution_id,
        &registration_fields("mia", "mia@example.com", "password123"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let continuation = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(continuation.contains("/login/required-action/"), "location: {continuation}");

    // Rendering the continuation page mails the verification link (exactly
    // one mail — registration sent none itself).
    let resp = harness.get(&continuation).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Verify your email address"));
    let text = {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "expected exactly one verification mail");
        sent[0].2.clone()
    };
    let link = text
        .lines()
        .find(|l| l.contains("/login/verify-email?token="))
        .expect("verification link in text body")
        .trim()
        .to_string();
    assert!(link.contains("&execution="), "link: {link}");

    // Click the link: the address verifies.
    let path = link.strip_prefix("http://localhost:8080").unwrap_or(&link).to_string();
    let resp = harness.get(&path).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Email address verified"));

    // The paused continuation now advances by itself: following it lands on
    // the app redirect with an authorization code.
    let resp = harness.get(&continuation).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(location.starts_with("http://localhost:8080/cb?"), "location: {location}");
    assert!(TestHarness::extract_query_param(&location, "code").is_some());
}

#[tokio::test]
async fn registration_with_unknown_login_execution_degrades_to_standalone() {
    let harness = TestHarness::new().await;
    let _realm = create_realm_with_registration(&harness, "reg-stale", true).await;

    // A stale/unknown execution id is dropped at the register page: the
    // registration proceeds standalone and the success link threads nothing.
    let flow_id = start_registration_at(
        &harness,
        "/realms/reg-stale/login/register?execution_id=no-such-flow",
    )
    .await;
    let resp = submit_registration(
        &harness,
        "reg-stale",
        &flow_id,
        &registration_fields("noa", "noa@example.com", "password123"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Registration successful"), "body: {body}");
    assert!(body.contains("/login.html?realm=reg-stale"), "body: {body}");
    assert!(!body.contains("execution_id"), "body: {body}");
}

#[tokio::test]
async fn passwordless_registration_inside_login_flow_threads_execution_through_verify_email() {
    use issuerd_server::{config::ServerConfig, state::ServerState};

    // Built with the recording sender: the email-code authenticator's mailer
    // is captured at construction, so a post-hoc email_sender swap would not
    // reach it.
    let config = ServerConfig::default();
    let recorder = std::sync::Arc::new(RecordingSender::default());
    let state = ServerState::from_components_with_email_sender(
        &config,
        std::sync::Arc::new(issuerd_storage::InMemoryStorage::new()),
        std::sync::Arc::new(issuerd_cluster::InMemoryCache::new()),
        recorder.clone(),
    )
    .await
    .unwrap();
    let harness = TestHarness::with_state(std::sync::Arc::new(state));

    // Passwordless email-code realm: registration collects no password and
    // the browser flow is cookie-or-email-code (the app2 shape).
    let mut realm = create_realm_with_registration(&harness, "reg-pl", true).await;
    realm.verify_email_enabled = true;
    realm
        .attributes
        .insert("registration_passwordless".to_string(), "true".to_string());
    realm.attributes.insert("email_code_login".to_string(), "true".to_string());
    realm.browser_flow = Some("email-code-browser".to_string());
    harness.storage.update_realm(&realm).await.unwrap();
    let realm_id = realm.id.clone();
    let flow = issuerd_core::FlowConfig {
        alias: issuerd_core::Alias::new("email-code-browser").unwrap(),
        realm_id: realm_id.clone(),
        provider_id: "basic-flow".to_string(),
        top_level: true,
        built_in: false,
        stages: vec![
            issuerd_core::FlowStage {
                id: issuerd_core::FlowStageId::new("cookie-auth").unwrap(),
                requirement: issuerd_core::Requirement::Alternative,
                authenticator: issuerd_core::Alias::new("auth-cookie").unwrap(),
                priority: 1,
                sub_flow_alias: None,
                authenticator_config: None,
            },
            issuerd_core::FlowStage {
                id: issuerd_core::FlowStageId::new("email-code").unwrap(),
                requirement: issuerd_core::Requirement::Alternative,
                authenticator: issuerd_core::Alias::new("auth-email-code").unwrap(),
                priority: 2,
                sub_flow_alias: None,
                authenticator_config: None,
            },
        ],
    };
    harness.storage.create_flow_config(&realm_id, &flow).await.unwrap();
    let client = harness.create_client("reg-pl", false).await;

    // Register from inside the login flow (no password collected).
    let execution_id = start_login_flow(&harness, "reg-pl", client.client_id.as_ref()).await;
    let flow_id = start_registration_at(
        &harness,
        &format!("/realms/reg-pl/login/register?execution_id={execution_id}"),
    )
    .await;
    let fields: [(&str, &str); 4] = [
        ("username", "lena"),
        ("email", "lena@example.com"),
        ("first_name", "Lena"),
        ("last_name", "Test"),
    ];
    let resp =
        submit_registration_in_flow(&harness, "reg-pl", &flow_id, &execution_id, &fields).await;

    // Passwordless: there are no credentials to replay, so the response is the
    // success page — but its sign-in link keeps the paused login execution.
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Registration successful"), "body: {body}");
    assert!(body.contains("execution_id="), "body: {body}");

    // The verification mail's link threads the same execution.
    let text = {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "expected the verification mail");
        sent[0].2.clone()
    };
    let link = text
        .lines()
        .find(|l| l.contains("/login/verify-email?token="))
        .expect("verification link in text body")
        .trim()
        .to_string();
    assert!(link.contains("&login_execution="), "link: {link}");

    // Click it: the verified page's sign-in link points back into the flow.
    let path = link.strip_prefix("http://localhost:8080").unwrap_or(&link).to_string();
    let resp = harness.get(&path).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Email address verified"), "body: {body}");
    assert!(body.contains("execution_id="), "body: {body}");

    // Follow it: the email-code login completes into the app.
    let resp = harness
        .post_form_with_cookie(
            "/api/v1/auth/login?realm=reg-pl",
            &[
                ("execution_id", execution_id.as_str()),
                ("username", "lena@example.com"),
            ],
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Check your email"), "expected code page: {page}");

    let code = {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 2, "verify mail + login code mail");
        sent[1]
            .2
            .lines()
            .map(str::trim)
            .find(|l| l.len() == 6 && l.chars().all(|c| c.is_ascii_digit()))
            .expect("6-digit code in the login mail")
            .to_string()
    };
    let resp = harness
        .post_form_with_cookie(
            "/api/v1/auth/login?realm=reg-pl",
            &[
                ("execution_id", execution_id.as_str()),
                ("otp", code.as_str()),
            ],
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(location.starts_with("http://localhost:8080/cb?"), "location: {location}");
    let code = TestHarness::extract_query_param(&location, "code").expect("authorization code");

    let token_resp = harness
        .post_form(
            "/realms/reg-pl/protocol/openid-connect/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(token_resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Forgot / reset password (plan §2)
// ---------------------------------------------------------------------------

/// Email sender that records every message instead of delivering it.
#[derive(Default)]
struct RecordingSender {
    sent: std::sync::Mutex<Vec<(String, String, String, Option<String>)>>,
}

#[async_trait::async_trait]
impl issuerd_core::EmailSender for RecordingSender {
    async fn send(
        &self,
        _realm: &issuerd_core::Realm,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: Option<String>,
    ) -> Result<(), issuerd_core::IssuerdError> {
        self.sent.lock().unwrap().push((
            to.to_string(),
            subject.to_string(),
            text_body.to_string(),
            html_body,
        ));
        Ok(())
    }
}

/// Harness with the recording sender wired in; returns the recorder too.
async fn harness_with_recorder() -> (TestHarness, std::sync::Arc<RecordingSender>) {
    use issuerd_server::{config::ServerConfig, state::ServerState};
    let config = ServerConfig::default();
    let mut state = ServerState::from_config(&config).await.unwrap();
    let recorder = std::sync::Arc::new(RecordingSender::default());
    state.email_sender = recorder.clone();
    let harness = TestHarness::with_state(std::sync::Arc::new(state));
    (harness, recorder)
}

/// Create a realm with the reset-password toggle in the requested state.
async fn create_realm_with_reset(
    harness: &TestHarness,
    name: &str,
    allowed: bool,
) -> issuerd_core::Realm {
    let mut realm = harness.create_realm(name).await;
    realm.reset_password_allowed = allowed;
    harness.storage.update_realm(&realm).await.unwrap();
    realm
}

/// Resource-owner password grant attempt (raw response; status varies).
async fn password_grant(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    password: &str,
) -> axum::response::Response {
    let client_id = client.client_id.to_string();
    harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/token"),
            &[
                ("grant_type", "password"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("username", username),
                ("password", password),
                ("scope", "openid"),
            ],
        )
        .await
}

/// Request a reset link and return the action token from the captured email.
async fn request_reset_token(
    harness: &TestHarness,
    recorder: &RecordingSender,
    realm: &str,
    login: &str,
) -> String {
    let resp = harness
        .post_form(&format!("/realms/{realm}/login/reset-credentials"), &[("username", login)])
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // Copy the recorded mail out of the lock before any further .await
    // (clippy::await_holding_lock).
    let text = {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "expected exactly one reset email");
        sent[0].2.clone()
    };
    let link = text
        .lines()
        .find(|l| l.contains("/login/update-credentials?token="))
        .expect("reset link in text body")
        .trim()
        .to_string();
    TestHarness::extract_query_param(&link, "token").expect("token in reset link")
}

/// POST the update-credentials form with the given token and passwords.
async fn submit_new_password(
    harness: &TestHarness,
    realm: &str,
    token: &str,
    new_password: &str,
    confirm_password: &str,
) -> axum::response::Response {
    harness
        .post_form(
            &format!("/realms/{realm}/login/update-credentials"),
            &[
                ("token", token),
                ("new_password", new_password),
                ("confirm_password", confirm_password),
            ],
        )
        .await
}

#[tokio::test]
async fn reset_credentials_disabled_returns_404() {
    let harness = TestHarness::new().await;
    let _realm = create_realm_with_reset(&harness, "rs-off", false).await;

    let resp = harness.get("/realms/rs-off/login/reset-credentials").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = harness
        .post_form("/realms/rs-off/login/reset-credentials", &[("username", "x")])
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = harness.get("/realms/rs-off/login/update-credentials?token=abc").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = submit_new_password(&harness, "rs-off", "abc", "password123", "password123").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reset_credentials_unknown_user_sends_no_email() {
    let (harness, recorder) = harness_with_recorder().await;
    let realm = create_realm_with_reset(&harness, "rs-unknown", true).await;

    let resp = harness
        .post_form("/realms/rs-unknown/login/reset-credentials", &[("username", "ghost")])
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(body.is_empty(), "204 must carry no body");
    assert!(recorder.sent.lock().unwrap().is_empty(), "no mail for unknown users");

    // JSON bodies are accepted too — same neutral answer.
    let resp = harness
        .post_json(
            "/realms/rs-unknown/login/reset-credentials",
            serde_json::json!({"username": "ghost"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(recorder.sent.lock().unwrap().is_empty());

    // Disabled accounts are skipped silently as well.
    let mut user = harness.create_user("rs-unknown", "ivan", "Password123!").await;
    user.enabled = false;
    harness.storage.update_user(&realm.id, &user).await.unwrap();
    let resp = harness
        .post_form("/realms/rs-unknown/login/reset-credentials", &[("username", "ivan")])
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(recorder.sent.lock().unwrap().is_empty(), "no mail for disabled users");
}

#[tokio::test]
async fn reset_credentials_known_user_receives_link() {
    let (harness, recorder) = harness_with_recorder().await;
    let _realm = create_realm_with_reset(&harness, "rs-known", true).await;
    let _user = harness.create_user("rs-known", "kyle", "Password123!").await;

    // Lookup by username.
    let resp = harness
        .post_form("/realms/rs-known/login/reset-credentials", &[("username", "kyle")])
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "kyle@example.com");
        assert_eq!(sent[0].1, "Reset your password");
        assert!(sent[0].2.contains("/login/update-credentials?token="));
        assert!(sent[0].3.as_ref().expect("html part").contains("v:roundrect"));
    }

    // Lookup by email (login_with_email_allowed defaults to true).
    let resp = harness
        .post_form("/realms/rs-known/login/reset-credentials", &[("username", "kyle@example.com")])
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(recorder.sent.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn reset_credentials_roundtrip_changes_password_and_clears_update_password() {
    let (harness, recorder) = harness_with_recorder().await;
    let realm = create_realm_with_reset(&harness, "rs-round", true).await;
    let client = harness.create_client("rs-round", false).await;
    let mut user = harness.create_user("rs-round", "laura", "OldPassword1!").await;
    user.required_actions = vec!["UPDATE_PASSWORD".to_string()];
    harness.storage.update_user(&realm.id, &user).await.unwrap();

    let token = request_reset_token(&harness, &recorder, "rs-round", "laura").await;

    // The link opens the new-password form with the token round-tripped.
    let path = format!("/realms/rs-round/login/update-credentials?token={token}");
    let resp = harness.get(&path).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Choose a new password"), "body: {body}");
    assert!(body.contains(&format!("value=\"{token}\"")), "hidden token round-tripped");

    // A mismatched confirmation re-renders the form with an error.
    let resp =
        submit_new_password(&harness, "rs-round", &token, "N3wPassword!x", "different").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("do not match"), "body: {body}");

    // Submitting matching passwords updates the account.
    let resp =
        submit_new_password(&harness, "rs-round", &token, "N3wPassword!x", "N3wPassword!x").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Password updated"), "body: {body}");
    assert!(body.contains("/login.html?realm=rs-round"));

    // The reset satisfied the UPDATE_PASSWORD required action.
    let user = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert!(user.required_actions.is_empty());

    // Old password is dead, the new one logs in.
    let resp = password_grant(&harness, "rs-round", &client, "laura", "OldPassword1!").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = password_grant(&harness, "rs-round", &client, "laura", "N3wPassword!x").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn reset_credentials_token_is_single_use() {
    let (harness, recorder) = harness_with_recorder().await;
    let _realm = create_realm_with_reset(&harness, "rs-once", true).await;
    let _user = harness.create_user("rs-once", "mia", "OldPassword1!").await;

    let token = request_reset_token(&harness, &recorder, "rs-once", "mia").await;
    let path = format!("/realms/rs-once/login/update-credentials?token={token}");

    // First submission consumes the token.
    let resp =
        submit_new_password(&harness, "rs-once", &token, "N3wPassword!x", "N3wPassword!x").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Password updated"));

    // Replaying the same token is rejected as already used.
    let resp =
        submit_new_password(&harness, "rs-once", &token, "OtherPassword1", "OtherPassword1").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(body.contains("already been used"), "body: {body}");

    // GET with the consumed link errors the same way.
    let resp = harness.get(&path).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("already been used"));
}

#[tokio::test]
async fn reset_credentials_expired_token_is_rejected() {
    use issuerd_server::{config::ServerConfig, state::ServerState};

    let config = ServerConfig::default();
    let mut state = ServerState::from_config(&config).await.unwrap();
    state.email_sender = std::sync::Arc::new(RecordingSender::default());
    let crypto = state.crypto.clone();
    let harness = TestHarness::with_state(std::sync::Arc::new(state));
    let realm = create_realm_with_reset(&harness, "rs-expired", true).await;
    let user = harness.create_user("rs-expired", "mike", "Password123!").await;

    // Craft an already-expired token (past the 60 s verification leeway).
    let now = chrono::Utc::now().timestamp();
    let claims = issuerd_core::ActionTokenClaims {
        sub: user.id.to_string(),
        realm: realm.id.to_string(),
        purpose: issuerd_core::ACTION_TOKEN_PURPOSE_RESET_CREDENTIALS.to_string(),
        exp: now - 3600,
        iat: now - 3700,
        jti: issuerd_core::utils::generate_id(),
        auth_time: None,
    };
    let payload = serde_json::to_string(&claims).unwrap();
    let jwks = crypto.get_public_keys().await.unwrap();
    let key = jwks.keys.first().expect("active signing key");
    let token = crypto.sign(&payload, key.alg, &key.kid).await.unwrap();

    let resp = harness
        .get(&format!("/realms/rs-expired/login/update-credentials?token={token}"))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(body.contains("invalid or has expired"), "body: {body}");
    assert!(body.contains("href=\"/realms/rs-expired/login/reset-credentials\""));

    let resp =
        submit_new_password(&harness, "rs-expired", &token, "Whatever123!", "Whatever123!").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("invalid or has expired"));
}

#[tokio::test]
async fn reset_credentials_password_policy_enforced_without_consuming_token() {
    let (harness, recorder) = harness_with_recorder().await;
    let mut realm = create_realm_with_reset(&harness, "rs-policy", true).await;
    realm.password_policy.min_length = issuerd_core::PasswordLength::new(16);
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("rs-policy", false).await;
    let _user = harness.create_user("rs-policy", "nina", "OldPassword1!").await;

    let token = request_reset_token(&harness, &recorder, "rs-policy", "nina").await;

    // A weak password re-renders the form with the violation; the token is
    // NOT consumed and the old password stays active.
    let resp = submit_new_password(&harness, "rs-policy", &token, "short", "short").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("at least 16 characters"), "body: {body}");
    assert!(body.contains("Choose a new password"), "form re-rendered: {body}");
    let resp = password_grant(&harness, "rs-policy", &client, "nina", "OldPassword1!").await;
    assert_eq!(resp.status(), StatusCode::OK);

    // The same link accepts a compliant retry.
    let resp = submit_new_password(
        &harness,
        "rs-policy",
        &token,
        "MuchBetterPassword!",
        "MuchBetterPassword!",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Password updated"));
    let resp = password_grant(&harness, "rs-policy", &client, "nina", "MuchBetterPassword!").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Account console self-service API (plan §4)
// ---------------------------------------------------------------------------

/// PUT a JSON body with a bearer token (the harness has no PUT helper).
async fn put_json_auth(
    harness: &TestHarness,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    let req = Request::builder()
        .method("PUT")
        .uri(path)
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

/// DELETE with a bearer token (the harness has no DELETE helper).
async fn delete_auth(harness: &TestHarness, path: &str, token: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("DELETE")
        .uri(path)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

/// Consume the response body as parsed JSON.
async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Authenticate and return just the access token.
async fn account_token(harness: &TestHarness, realm: &str, client_id: &str, user: &str) -> String {
    harness
        .authenticate_user(realm, client_id, user, "Password123!")
        .await
        .access_token
}

#[tokio::test]
async fn account_update_me_updates_profile_fields() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("acct-me").await;
    let client = harness.create_client("acct-me", false).await;
    let user = harness.create_user("acct-me", "oliver", "Password123!").await;
    let token = account_token(&harness, "acct-me", client.client_id.as_ref(), "oliver").await;

    // Set first name, clear last name; absent fields stay unchanged.
    let resp = put_json_auth(
        &harness,
        "/realms/acct-me/account/api/me",
        &token,
        serde_json::json!({"first_name": "Oliver", "last_name": null}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["id"], user.id.as_ref());
    assert_eq!(body["username"], "oliver");
    assert_eq!(body["first_name"], "Oliver");
    assert_eq!(body["last_name"], serde_json::Value::Null);
    assert_eq!(body["email"], "oliver@example.com");
    assert_eq!(body["email_verified"], true);
    assert_eq!(body["enabled"], true);
    assert!(body["roles"].is_array());

    let stored = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert_eq!(stored.first_name.as_ref().unwrap().as_str(), "Oliver");
    assert!(stored.last_name.is_none());
}

#[tokio::test]
async fn account_update_me_username_change_respects_realm_toggle() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("acct-user").await;
    realm.edit_username_allowed = false;
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("acct-user", false).await;
    let user = harness.create_user("acct-user", "petra", "Password123!").await;
    let token = account_token(&harness, "acct-user", client.client_id.as_ref(), "petra").await;

    // Disallowed: 400 and the stored username is unchanged.
    let resp = put_json_auth(
        &harness,
        "/realms/acct-user/account/api/me",
        &token,
        serde_json::json!({"username": "petra2"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(json_body(resp).await["error"].as_str().unwrap().contains("username"));
    let stored = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert_eq!(stored.username.as_str(), "petra");

    // Resending the current username is a no-op, not a change attempt.
    let resp = put_json_auth(
        &harness,
        "/realms/acct-user/account/api/me",
        &token,
        serde_json::json!({"username": "petra"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Allowed: the rename is persisted and reflected in the response.
    realm.edit_username_allowed = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let resp = put_json_auth(
        &harness,
        "/realms/acct-user/account/api/me",
        &token,
        serde_json::json!({"username": "petra2"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["username"], "petra2");
    let stored = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert_eq!(stored.username.as_str(), "petra2");
}

#[tokio::test]
async fn account_update_me_email_change_triggers_verification_email() {
    let (harness, recorder) = harness_with_recorder().await;
    let mut realm = harness.create_realm("acct-email").await;
    realm.verify_email_enabled = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("acct-email", false).await;
    let user = harness.create_user("acct-email", "quincy", "Password123!").await;
    let token = account_token(&harness, "acct-email", client.client_id.as_ref(), "quincy").await;

    let resp = put_json_auth(
        &harness,
        "/realms/acct-email/account/api/me",
        &token,
        serde_json::json!({"email": "quincy-new@example.com"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["email"], "quincy-new@example.com");
    assert_eq!(body["email_verified"], false);

    // The change cleared verification and assigned VERIFY_EMAIL exactly once.
    let stored = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert!(!stored.email_verified);
    assert_eq!(stored.required_actions, vec!["VERIFY_EMAIL".to_string()]);

    // The verification mail went out to the new address; the standalone link
    // completes the verification without any flow execution.
    let text = {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "quincy-new@example.com");
        sent[0].2.clone()
    };
    let link = text
        .lines()
        .find(|l| l.contains("/login/verify-email?token="))
        .expect("verification link in text body")
        .trim()
        .to_string();
    let path = link.strip_prefix("http://localhost:8080").unwrap_or(&link).to_string();
    let resp = harness.get(&path).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let stored = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert!(stored.email_verified);
    assert!(stored.required_actions.is_empty());
}

#[tokio::test]
async fn account_update_me_email_change_without_verify_just_clears_flag() {
    // verify_email_enabled defaults to false: no mail, no action assignment,
    // but the change still invalidates the previous verification.
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("acct-email2").await;
    let client = harness.create_client("acct-email2", false).await;
    let user = harness.create_user("acct-email2", "rachel", "Password123!").await;
    let token = account_token(&harness, "acct-email2", client.client_id.as_ref(), "rachel").await;

    let resp = put_json_auth(
        &harness,
        "/realms/acct-email2/account/api/me",
        &token,
        serde_json::json!({"email": "rachel-new@example.com"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let stored = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert!(!stored.email_verified);
    assert!(stored.required_actions.is_empty());

    // Leaving the email out of the body leaves verification untouched.
    let resp = put_json_auth(
        &harness,
        "/realms/acct-email2/account/api/me",
        &token,
        serde_json::json!({"first_name": "Rachel"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let stored = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert!(!stored.email_verified, "unchanged email keeps its flag");
}

#[tokio::test]
async fn account_update_me_duplicate_email_rejected_unless_allowed() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("acct-dupe").await;
    let client = harness.create_client("acct-dupe", false).await;
    let _other = harness.create_user("acct-dupe", "sam", "Password123!").await;
    let user = harness.create_user("acct-dupe", "tina", "Password123!").await;
    let token = account_token(&harness, "acct-dupe", client.client_id.as_ref(), "tina").await;

    // sam@example.com is taken; duplicates are disallowed by default.
    let resp = put_json_auth(
        &harness,
        "/realms/acct-dupe/account/api/me",
        &token,
        serde_json::json!({"email": "sam@example.com"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "email already in use");
    let stored = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert_eq!(stored.email.as_ref().unwrap().as_str(), "tina@example.com");

    // Keeping your own address is always fine.
    let resp = put_json_auth(
        &harness,
        "/realms/acct-dupe/account/api/me",
        &token,
        serde_json::json!({"email": "tina@example.com"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Toggle duplicates on: the same change now succeeds.
    realm.duplicate_emails_allowed = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let resp = put_json_auth(
        &harness,
        "/realms/acct-dupe/account/api/me",
        &token,
        serde_json::json!({"email": "sam@example.com"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let stored = harness.storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
    assert_eq!(stored.email.as_ref().unwrap().as_str(), "sam@example.com");
}

#[tokio::test]
async fn account_change_password_wrong_current_is_rejected() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("acct-pw").await;
    let client = harness.create_client("acct-pw", false).await;
    let _user = harness.create_user("acct-pw", "uma", "OldPassword1!").await;
    let tokens = harness
        .authenticate_user("acct-pw", client.client_id.as_ref(), "uma", "OldPassword1!")
        .await;

    let resp = harness
        .post_json_auth(
            "/realms/acct-pw/account/api/credentials/password",
            &tokens.access_token,
            serde_json::json!({"current_password": "wrong-password", "new_password": "NewPass1!x"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "current password is incorrect");

    // The old password still works.
    let resp = password_grant(&harness, "acct-pw", &client, "uma", "OldPassword1!").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn account_change_password_policy_violations_are_machine_readable() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("acct-pwp").await;
    realm.password_policy.min_length = issuerd_core::PasswordLength::new(16);
    realm.password_policy.require_digits = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("acct-pwp", false).await;
    let _user = harness.create_user("acct-pwp", "vera", "OldPassword1!").await;
    let tokens = harness
        .authenticate_user("acct-pwp", client.client_id.as_ref(), "vera", "OldPassword1!")
        .await;

    let resp = harness
        .post_json_auth(
            "/realms/acct-pwp/account/api/credentials/password",
            &tokens.access_token,
            serde_json::json!({"current_password": "OldPassword1!", "new_password": "short"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    let violations = body["policyViolations"].as_array().expect("policyViolations array");
    assert!(!violations.is_empty());
    assert!(violations.iter().any(|v| v["code"] == "min_length"));
    assert!(violations.iter().any(|v| v["code"] == "require_digits"));

    // Rejected before storage: the old password is still active.
    let resp = password_grant(&harness, "acct-pwp", &client, "vera", "OldPassword1!").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn account_change_password_roundtrip() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("acct-pwt").await;
    let client = harness.create_client("acct-pwt", false).await;
    let _user = harness.create_user("acct-pwt", "wendy", "OldPassword1!").await;
    let tokens = harness
        .authenticate_user("acct-pwt", client.client_id.as_ref(), "wendy", "OldPassword1!")
        .await;

    let resp = harness
        .post_json_auth(
            "/realms/acct-pwt/account/api/credentials/password",
            &tokens.access_token,
            serde_json::json!({"current_password": "OldPassword1!", "new_password": "NewPass1!x"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The old password is dead, the new one logs in.
    let resp = password_grant(&harness, "acct-pwt", &client, "wendy", "OldPassword1!").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = password_grant(&harness, "acct-pwt", &client, "wendy", "NewPass1!x").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn account_credentials_reports_presence_flags() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("acct-cred").await;
    let client = harness.create_client("acct-cred", false).await;
    let _user = harness.create_user("acct-cred", "xena", "Password123!").await;
    let token = account_token(&harness, "acct-cred", client.client_id.as_ref(), "xena").await;

    let resp = harness.get_auth("/realms/acct-cred/account/api/credentials", &token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body, serde_json::json!({"password": true, "totp": false, "webauthn": false}));
}

#[tokio::test]
async fn account_consents_list_and_revoke() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("acct-consent").await;
    let client = harness.create_client("acct-consent", false).await;
    let user = harness.create_user("acct-consent", "yara", "Password123!").await;
    let token = account_token(&harness, "acct-consent", client.client_id.as_ref(), "yara").await;

    // The consent-grant flow is not part of this scenario, so seed the row directly.
    let consent = issuerd_core::Consent {
        client_id: client.id.clone(),
        user_id: user.id.clone(),
        granted_scopes: issuerd_core::Scope::parse("openid profile email"),
        granted_realm_roles: vec![],
        granted_client_roles: std::collections::HashMap::new(),
        created_at: chrono::Utc::now(),
        last_updated_at: chrono::Utc::now(),
    };
    harness.storage.create_consent(&realm.id, &consent).await.unwrap();

    let resp = harness.get_auth("/realms/acct-consent/account/api/consents", &token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let entries = body.as_array().expect("consents array");
    assert_eq!(entries.len(), 1);
    // The API exposes the human client_id, not the internal UUID.
    assert_eq!(entries[0]["client_id"], client.client_id.to_string());
    assert_eq!(entries[0]["granted_scopes"], serde_json::json!(["email", "openid", "profile"]));
    chrono::DateTime::parse_from_rfc3339(entries[0]["created_at"].as_str().unwrap()).unwrap();
    chrono::DateTime::parse_from_rfc3339(entries[0]["last_updated_at"].as_str().unwrap()).unwrap();

    // Revoke: 204 and the storage row is gone; a repeat revoke is still 204.
    let path = format!("/realms/acct-consent/account/api/consents/{}", client.client_id);
    let resp = delete_auth(&harness, &path, &token).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(harness.storage.get_consents(&realm.id, &user.id).await.unwrap().is_empty());
    let resp = delete_auth(&harness, &path, &token).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Unknown client string: 404.
    let resp =
        delete_auth(&harness, "/realms/acct-consent/account/api/consents/no-such-client", &token)
            .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(resp).await["error"], "client not found");
}

#[tokio::test]
async fn account_api_mutations_reject_token_from_different_realm() {
    let harness = TestHarness::new().await;
    let _realm_a = harness.create_realm("acct-realm-a").await;
    let client_a = harness.create_client("acct-realm-a", false).await;
    let _user_a = harness.create_user("acct-realm-a", "zack", "Password123!").await;
    // realm-b must exist so the request reaches the issuer/realm comparison.
    let _realm_b = harness.create_realm("acct-realm-b").await;

    let token = account_token(&harness, "acct-realm-a", client_a.client_id.as_ref(), "zack").await;

    let resp = put_json_auth(
        &harness,
        "/realms/acct-realm-b/account/api/me",
        &token,
        serde_json::json!({"first_name": "Zack"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = harness
        .post_json_auth(
            "/realms/acct-realm-b/account/api/credentials/password",
            &token,
            serde_json::json!({"current_password": "x", "new_password": "y"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = harness.get_auth("/realms/acct-realm-b/account/api/credentials", &token).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = harness.get_auth("/realms/acct-realm-b/account/api/consents", &token).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp =
        delete_auth(&harness, "/realms/acct-realm-b/account/api/consents/some-client", &token)
            .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
