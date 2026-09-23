// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Identity brokering integration tests against a loopback external IdP.

//! Identity brokering integration tests (Issuerd-only, no Docker).
//!
//! The "external IdP" is a **loopback broker**: a second full Issuerd server
//! state served in-process on a real TCP port (`127.0.0.1:0`), so the broker's
//! server-to-server calls (discovery, code exchange, JWKS fetch) exercise the
//! production `ReqwestBrokerClient` over real HTTP. The internal realm brokers
//! logins against it exactly like it would against Google or Entra ID.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use issuerd_server::{config::ServerConfig, routes::app_router, state::ServerState};
use tower::ServiceExt;

use crate::harness::TestHarness;

const INTERNAL: &str = "internal";
const EXT_REALM: &str = "ext";
const EXT_ALIAS: &str = "ext";
const EXT_CLIENT_ID: &str = "broker-client";
const EXT_CLIENT_SECRET: &str = "broker-secret";
const EXT_USER: &str = "extuser";
const EXT_PASSWORD: &str = "ext-pass-123";
const APP_REDIRECT: &str = "http://localhost:8080/cb";

// ---------------------------------------------------------------------------
// Rig: internal realm (broker) + loopback external IdP
// ---------------------------------------------------------------------------

/// The loopback external IdP: a second Issuerd server on a real port.
struct LoopbackIdp {
    base_url: String,
    /// Harness over the loopback state, used for storage setup helpers only
    /// (its router is not the one being served).
    harness: TestHarness,
}

async fn start_loopback_idp() -> LoopbackIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let config = ServerConfig {
        issuer_url: base_url.clone(),
        ..Default::default()
    };
    let state = Arc::new(ServerState::from_config(&config).await.unwrap());
    let harness = TestHarness::with_state(state.clone());
    let app = app_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    LoopbackIdp { base_url, harness }
}

struct BrokerRig {
    internal: TestHarness,
    ext: LoopbackIdp,
    /// Public client in the internal realm the end-user app uses.
    app_client: issuerd_core::Client,
    /// The external user on the loopback IdP.
    ext_user: issuerd_core::User,
}

/// The internal realm's callback URL as the external IdP must register it.
/// The internal harness uses the default issuer (`http://localhost:8080`).
fn broker_callback_uri() -> String {
    format!("http://localhost:8080/realms/{INTERNAL}/broker/{EXT_ALIAS}/endpoint")
}

/// Confidential client on the loopback IdP representing "Issuerd internal
/// realm" as a registered application.
async fn create_ext_client(ext: &LoopbackIdp) {
    let realm_id = issuerd_core::RealmId::new(EXT_REALM).unwrap();
    let client = issuerd_core::Client {
        id: issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm_id.clone(),
        client_id: issuerd_core::ClientIdentifier::new(EXT_CLIENT_ID).unwrap(),
        name: Some(issuerd_core::DisplayName::new("Issuerd Broker").unwrap()),
        description: None,
        enabled: true,
        protocol: issuerd_core::ClientProtocol::OpenIdConnect,
        public_client: false,
        bearer_only: false,
        client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
        secret: Some(EXT_CLIENT_SECRET.to_string()),
        redirect_uris: vec![issuerd_core::RedirectUri::new(broker_callback_uri()).unwrap()],
        web_origins: vec![],
        default_scopes: issuerd_core::Scope::parse("openid profile email"),
        optional_scopes: issuerd_core::Scope::parse(""),
        consent_required: false,
        full_scope_allowed: true,
        service_accounts_enabled: false,
        protocol_mappers: Vec::new(),
        scope_mappings: Default::default(),
        attributes: HashMap::new(),
    };
    ext.harness.storage.create_client(&realm_id, &client).await.unwrap();
}

/// Register the loopback IdP as a broker provider in the internal realm.
async fn create_ext_idp(rig_internal: &TestHarness, ext: &LoopbackIdp, extra: &[(&str, &str)]) {
    let mut config = HashMap::new();
    config.insert("clientId".to_string(), EXT_CLIENT_ID.to_string());
    config.insert("clientSecret".to_string(), EXT_CLIENT_SECRET.to_string());
    config.insert("issuer".to_string(), format!("{}/realms/{EXT_REALM}", ext.base_url));
    for (k, v) in extra {
        config.insert((*k).to_string(), (*v).to_string());
    }
    let idp = issuerd_core::IdentityProviderConfig {
        id: issuerd_core::IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap(),
        alias: issuerd_core::Alias::new(EXT_ALIAS).unwrap(),
        provider_id: issuerd_core::ProviderId::new("oidc"),
        enabled: true,
        config,
    };
    let realm_id = issuerd_core::RealmId::new(INTERNAL).unwrap();
    rig_internal.storage.create_identity_provider(&realm_id, &idp).await.unwrap();
}

/// Full rig: internal realm + public app client + broker IdP config;
/// loopback realm + broker client + one external user.
async fn broker_rig(idp_extra: &[(&str, &str)]) -> BrokerRig {
    let internal = TestHarness::new().await;
    let ext = start_loopback_idp().await;

    ext.harness.create_realm(EXT_REALM).await;
    create_ext_client(&ext).await;
    let ext_user = ext.harness.create_user(EXT_REALM, EXT_USER, EXT_PASSWORD).await;

    internal.create_realm(INTERNAL).await;
    // Confidential client: the server requires PKCE from public clients, and
    // the harness's plain code flow uses client-secret authentication.
    let app_client = internal.create_client(INTERNAL, false).await;
    create_ext_idp(&internal, &ext, idp_extra).await;

    BrokerRig {
        internal,
        ext,
        app_client,
        ext_user,
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn no_redirect_http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn get_with_cookie(harness: &TestHarness, path: &str, cookie: &str) -> Response {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

fn location(resp: &Response) -> String {
    resp.headers().get("location").unwrap().to_str().unwrap().to_string()
}

fn query_param(url: &str, key: &str) -> String {
    TestHarness::extract_query_param(url, key).unwrap_or_else(|| panic!("missing {key} in {url}"))
}

/// Extract `issuerd_session=<token>` from a login response's Set-Cookie header.
fn session_cookie(resp: &Response) -> String {
    let raw = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .unwrap_or_else(|| panic!("login response carries no Set-Cookie: {:?}", resp.status()))
        .to_str()
        .unwrap()
        .to_string();
    raw.split(';').next().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Flow drivers
// ---------------------------------------------------------------------------

/// Drive the internal authorize endpoint with `kc_idp_hint` and the broker
/// kickoff, returning the external authorize URL, the broker `state` param,
/// and the internal browser flow id.
async fn begin_broker_login(rig: &BrokerRig) -> (String, String, String) {
    let app_client_id = rig.app_client.client_id.to_string();
    let auth_path = format!(
        "/realms/{INTERNAL}/protocol/openid-connect/auth?response_type=code&client_id={app_client_id}&redirect_uri={APP_REDIRECT}&scope=openid&state=appstate&kc_idp_hint={EXT_ALIAS}"
    );
    let resp = rig.internal.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize with hint");
    let loc = location(&resp);
    assert!(
        loc.starts_with(&format!("/realms/{INTERNAL}/broker/{EXT_ALIAS}/login?flow=")),
        "expected broker login redirect, got {loc}"
    );
    let flow_id = query_param(&loc, "flow");

    let resp = get_with_cookie(&rig.internal, &loc, &TestHarness::flow_cookie(&flow_id)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "broker kickoff");
    let ext_auth_url = location(&resp);
    assert!(
        ext_auth_url.starts_with(&format!("{}/realms/{EXT_REALM}/", rig.ext.base_url)),
        "expected external authorize URL, got {ext_auth_url}"
    );
    let broker_state = query_param(&ext_auth_url, "state");
    (ext_auth_url, broker_state, flow_id)
}

/// Log in at the loopback IdP and return the authorization code it issues
/// for the broker client.
async fn external_login(
    ext: &LoopbackIdp,
    ext_auth_url: &str,
    username: &str,
    password: &str,
) -> String {
    let http = no_redirect_http();
    let resp = http.get(ext_auth_url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "external authorize");
    let login_page = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let execution_id = query_param(&login_page, "execution_id");

    let resp = http
        .post(format!("{}/api/v1/auth/login?realm={EXT_REALM}", ext.base_url))
        .header("content-type", "application/json")
        .header("cookie", TestHarness::flow_cookie(&execution_id))
        .body(
            serde_json::json!({
                "execution_id": execution_id,
                "username": username,
                "password": password,
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "external login");
    let body: serde_json::Value = resp.json().await.unwrap();
    body["code"].as_str().expect("external login returns a code").to_string()
}

/// The broker endpoint callback: deliver code+state to the internal realm.
async fn broker_callback(rig: &BrokerRig, code: &str, broker_state: &str) -> Response {
    rig.internal
        .get(&format!(
            "/realms/{INTERNAL}/broker/{EXT_ALIAS}/endpoint?code={code}&state={broker_state}"
        ))
        .await
}

/// Full roundtrip up to the callback response (which depends on the
/// first-broker-login decision the test configured).
async fn drive_to_callback(rig: &BrokerRig, username: &str, password: &str) -> Response {
    let (ext_auth_url, broker_state, _flow) = begin_broker_login(rig).await;
    let code = external_login(&rig.ext, &ext_auth_url, username, password).await;
    broker_callback(rig, &code, &broker_state).await
}

/// Redeem the code carried by a final app redirect at the internal token
/// endpoint; asserts success and returns the token response.
async fn redeem_app_code(rig: &BrokerRig, app_location: &str) -> serde_json::Value {
    assert!(
        app_location.starts_with(&format!("{APP_REDIRECT}?")),
        "expected redirect to the app, got {app_location}"
    );
    assert_eq!(query_param(app_location, "state"), "appstate");
    let code = query_param(app_location, "code");
    let resp = rig
        .internal
        .post_form(
            &format!("/realms/{INTERNAL}/protocol/openid-connect/token"),
            &[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", APP_REDIRECT),
                ("client_id", rig.app_client.client_id.as_ref()),
                ("client_secret", rig.app_client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "app code redemption");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn internal_realm_id() -> issuerd_core::RealmId {
    issuerd_core::RealmId::new(INTERNAL).unwrap()
}

/// The stored link for the external user, if any.
async fn ext_link(rig: &BrokerRig) -> Option<issuerd_core::IdentityProviderLink> {
    rig.internal
        .storage
        .get_identity_provider_link(&internal_realm_id(), EXT_ALIAS, rig.ext_user.id.as_ref())
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// trustEmail + no conflict → AutoCreate: the user is created on the fly and
/// the login completes with tokens, a link row, and `federation_link` set.
#[tokio::test]
async fn broker_login_full_roundtrip_creates_user_and_tokens() {
    let rig = broker_rig(&[("trustEmail", "true")]).await;

    let resp = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "final redirect to app");
    let tokens = redeem_app_code(&rig, &location(&resp)).await;
    assert!(tokens["access_token"].as_str().is_some_and(|t| !t.is_empty()));
    assert!(tokens["id_token"].as_str().is_some_and(|t| !t.is_empty()));

    // The brokered user was imported with the expected shape.
    let user = rig
        .internal
        .storage
        .get_user_by_email(&internal_realm_id(), "extuser@example.com")
        .await
        .unwrap()
        .expect("brokered user created");
    assert_eq!(user.federation_link.as_deref(), Some("idp:ext"));
    assert!(user.email_verified, "trusted IdP email stays verified");

    let link = ext_link(&rig).await.expect("link row created");
    assert_eq!(link.user_id, user.id);
    assert_eq!(link.external_username.as_deref(), Some("extuser"));
}

/// The second login through the same external account hits the stored link:
/// no new user, straight to tokens.
#[tokio::test]
async fn broker_login_second_time_reuses_link() {
    let rig = broker_rig(&[("trustEmail", "true")]).await;

    let first = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    redeem_app_code(&rig, &location(&first)).await;
    let user_id = ext_link(&rig).await.unwrap().user_id;

    let second = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(second.status(), StatusCode::SEE_OTHER);
    redeem_app_code(&rig, &location(&second)).await;
    let link = ext_link(&rig).await.unwrap();
    assert_eq!(link.user_id, user_id, "second login must reuse the same user");
}

/// An unknown `kc_idp_hint` does not break the flow: it falls through to the
/// ordinary login page.
#[tokio::test]
async fn unknown_kc_idp_hint_falls_through_to_login_form() {
    let rig = broker_rig(&[]).await;
    let app_client_id = rig.app_client.client_id.to_string();
    let resp = rig
        .internal
        .get(&format!(
            "/realms/{INTERNAL}/protocol/openid-connect/auth?response_type=code&client_id={app_client_id}&redirect_uri={APP_REDIRECT}&scope=openid&kc_idp_hint=nope"
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(loc.starts_with("/login.html"), "expected login form, got {loc}");
}

/// A callback with an unknown/expired state key is rejected.
#[tokio::test]
async fn broker_callback_with_bad_state_rejected() {
    let rig = broker_rig(&[]).await;
    let resp = rig
        .internal
        .get(&format!(
            "/realms/{INTERNAL}/broker/{EXT_ALIAS}/endpoint?code=whatever&state=bogus"
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// An IdP-side error (user cancelled) consumes the state and redirects back
/// to the login page with an error flag.
#[tokio::test]
async fn broker_callback_with_idp_error_redirects_to_login() {
    let rig = broker_rig(&[]).await;
    let (_url, broker_state, flow_id) = begin_broker_login(&rig).await;
    let resp = rig
        .internal
        .get(&format!(
            "/realms/{INTERNAL}/broker/{EXT_ALIAS}/endpoint?error=access_denied&state={broker_state}"
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(loc.starts_with("/login.html"), "expected login redirect, got {loc}");
    assert_eq!(query_param(&loc, "error"), "identity_provider_error");
    assert_eq!(query_param(&loc, "execution_id"), flow_id);
}

/// Email conflict without trustEmail: the first-login page offers
/// link-via-password; the link lands on the EXISTING user.
#[tokio::test]
async fn broker_first_login_email_conflict_links_via_password() {
    let rig = broker_rig(&[]).await;
    // Local account whose email matches the external identity.
    let local = rig.internal.create_user(INTERNAL, EXT_USER, "local-pass-1").await;

    let resp = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "redirect to first-login page");
    let loc = location(&resp);
    assert!(loc.starts_with(&format!("/realms/{INTERNAL}/broker/first-login/")), "got {loc}");
    let execution = loc.rsplit('/').next().unwrap().to_string();

    // The page renders the link form.
    let page = rig.internal.get(&loc).await;
    assert_eq!(page.status(), StatusCode::OK);
    let body = axum::body::to_bytes(page.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("Link your account"), "link mode page: {body}");

    // Wrong password re-renders with an error (PRG).
    let resp = rig
        .internal
        .post_form_with_cookie(
            &loc,
            &[("action", "link"), ("password", "wrong-password")],
            &TestHarness::flow_cookie(&execution),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "PRG after bad password");

    // Correct password links and completes the login.
    let resp = rig
        .internal
        .post_form_with_cookie(
            &loc,
            &[("action", "link"), ("password", "local-pass-1")],
            &TestHarness::flow_cookie(&execution),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "final redirect to app");
    let tokens = redeem_app_code(&rig, &location(&resp)).await;
    assert!(tokens["access_token"].as_str().is_some_and(|t| !t.is_empty()));

    let link = ext_link(&rig).await.expect("link row created");
    assert_eq!(link.user_id, local.id, "link must point at the pre-existing user");
}

/// No trustEmail and no conflict: the review-profile page lets the user edit
/// the suggested username before the account is created.
#[tokio::test]
async fn broker_first_login_review_profile_creates_distinct_account() {
    let rig = broker_rig(&[]).await;

    let resp = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(loc.starts_with(&format!("/realms/{INTERNAL}/broker/first-login/")), "got {loc}");
    let execution = loc.rsplit('/').next().unwrap().to_string();

    let page = rig.internal.get(&loc).await;
    let body = axum::body::to_bytes(page.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("Review your profile"), "review mode page: {body}");

    let resp = rig
        .internal
        .post_form_with_cookie(
            &loc,
            &[
                ("action", "review"),
                ("username", "chosen-name"),
                ("email", "extuser@example.com"),
                ("first_name", "Ext"),
                ("last_name", "User"),
            ],
            &TestHarness::flow_cookie(&execution),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    redeem_app_code(&rig, &location(&resp)).await;

    let user = rig
        .internal
        .storage
        .get_user_by_username(&internal_realm_id(), "chosen-name")
        .await
        .unwrap()
        .expect("review-created user exists");
    assert_eq!(user.federation_link.as_deref(), Some("idp:ext"));
    let link = ext_link(&rig).await.unwrap();
    assert_eq!(link.user_id, user.id);
}

/// A disabled user holding a valid link cannot log in through the broker.
#[tokio::test]
async fn broker_login_disabled_user_rejected() {
    let rig = broker_rig(&[("trustEmail", "true")]).await;

    let first = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    redeem_app_code(&rig, &location(&first)).await;

    let link = ext_link(&rig).await.unwrap();
    let mut user = rig
        .internal
        .storage
        .get_user(&internal_realm_id(), &link.user_id)
        .await
        .unwrap()
        .unwrap();
    user.enabled = false;
    rig.internal.storage.update_user(&internal_realm_id(), &user).await.unwrap();

    let resp = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "disabled account rejected");
}

/// Attribute + role mappers with syncMode=force apply on every login.
#[tokio::test]
async fn broker_mappers_apply_on_login() {
    let mappers = serde_json::json!([
        {"name": "email-attr", "mapper_type": "attribute",
         "config": {"claim": "email", "attribute": "broker_email"}},
        {"name": "admins", "mapper_type": "role",
         "config": {"claim": "preferred_username", "claim_value": EXT_USER, "role": "broker-role"}},
    ])
    .to_string();
    let rig = broker_rig(&[
        ("trustEmail", "true"),
        ("syncMode", "force"),
        ("mappers", &mappers),
    ])
    .await;

    // The role must exist beforehand — mappers never conjure roles.
    let role = issuerd_core::Role {
        id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
        name: issuerd_core::RoleName::new("broker-role").unwrap(),
        description: None,
        realm_id: internal_realm_id(),
        client_role: false,
        client_id: None,
        composite: false,
        composites: vec![],
        attributes: HashMap::new(),
    };
    rig.internal.storage.create_role(&internal_realm_id(), &role).await.unwrap();

    let resp = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    redeem_app_code(&rig, &location(&resp)).await;

    let link = ext_link(&rig).await.unwrap();
    let user = rig
        .internal
        .storage
        .get_user(&internal_realm_id(), &link.user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        user.attributes.get("broker_email").map(|v| v.as_slice()),
        Some(&["extuser@example.com".to_string()][..]),
        "attribute mapper applied"
    );
    let role_ids = rig
        .internal
        .storage
        .list_user_realm_roles(&internal_realm_id(), &user.id)
        .await
        .unwrap();
    assert!(role_ids.contains(&role.id), "role mapper applied");

    // Force sync: the mapping is re-applied on the next login even after the
    // assignment was removed out of band.
    rig.internal
        .storage
        .remove_user_realm_role(&internal_realm_id(), &user.id, &role.id)
        .await
        .ok();
    let resp = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    redeem_app_code(&rig, &location(&resp)).await;
    let role_ids = rig
        .internal
        .storage
        .list_user_realm_roles(&internal_realm_id(), &user.id)
        .await
        .unwrap();
    assert!(role_ids.contains(&role.id), "role re-applied on login");
}

/// Account console: link a second provider to an existing account through the
/// signed link-token ceremony, guarded by the `issuerd_session` cookie.
#[tokio::test]
async fn account_linking_ceremony() {
    let rig = broker_rig(&[]).await;
    let alice = rig.internal.create_user(INTERNAL, "alice", "alice-pass-1").await;

    // Log alice in through the browser flow to obtain a bearer token AND the
    // issuerd_session cookie (the linking callback requires both to match).
    let app_client_id = rig.app_client.client_id.to_string();
    let auth_path = format!(
        "/realms/{INTERNAL}/protocol/openid-connect/auth?response_type=code&client_id={app_client_id}&redirect_uri={APP_REDIRECT}&scope=openid"
    );
    let resp = rig.internal.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let execution = query_param(&location(&resp), "execution_id");
    let resp = rig
        .internal
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={INTERNAL}"),
            serde_json::json!({
                "execution_id": execution,
                "username": "alice",
                "password": "alice-pass-1",
            }),
            &TestHarness::flow_cookie(&execution),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let alice_session = session_cookie(&resp);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let code = login_json["code"].as_str().unwrap().to_string();
    let tokens = rig
        .internal
        .post_form(
            &format!("/realms/{INTERNAL}/protocol/openid-connect/token"),
            &[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", APP_REDIRECT),
                ("client_id", rig.app_client.client_id.as_ref()),
                ("client_secret", rig.app_client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    let body = axum::body::to_bytes(tokens.into_body(), usize::MAX).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let bearer = token_json["access_token"].as_str().unwrap().to_string();

    // The account API lists no links yet, then starts the ceremony.
    let resp = rig
        .internal
        .get_auth(&format!("/realms/{INTERNAL}/account/api/linked-accounts"), &bearer)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let links: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(links.as_array().unwrap().len(), 0);

    let resp = rig
        .internal
        .post_json_auth(
            &format!("/realms/{INTERNAL}/account/api/linked-accounts/{EXT_ALIAS}"),
            &bearer,
            serde_json::json!(null),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "link start");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let start: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let redirect_url = start["redirect_url"].as_str().unwrap().to_string();
    assert!(redirect_url.starts_with(&format!("/realms/{INTERNAL}/broker/{EXT_ALIAS}/login?link=")));

    // Broker kickoff in link mode (no flow cookie required) → external IdP.
    let resp = rig.internal.get(&redirect_url).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let ext_auth_url = location(&resp);
    let broker_state = query_param(&ext_auth_url, "state");

    let code = external_login(&rig.ext, &ext_auth_url, EXT_USER, EXT_PASSWORD).await;

    // Without the issuerd_session cookie the linking callback refuses to bind.
    let resp = broker_callback(&rig, &code, &broker_state).await;
    let loc = location(&resp);
    assert!(
        loc.contains("error=link-session-mismatch"),
        "missing session cookie must fail, got {loc}"
    );

    // The state was consumed by the failed attempt — run the ceremony again,
    // this time presenting alice's session cookie.
    let resp = rig
        .internal
        .post_json_auth(
            &format!("/realms/{INTERNAL}/account/api/linked-accounts/{EXT_ALIAS}"),
            &bearer,
            serde_json::json!(null),
        )
        .await;
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let start: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let redirect_url = start["redirect_url"].as_str().unwrap().to_string();
    let resp = rig.internal.get(&redirect_url).await;
    let ext_auth_url = location(&resp);
    let broker_state = query_param(&ext_auth_url, "state");
    let code = external_login(&rig.ext, &ext_auth_url, EXT_USER, EXT_PASSWORD).await;

    let resp = get_with_cookie(
        &rig.internal,
        &format!("/realms/{INTERNAL}/broker/{EXT_ALIAS}/endpoint?code={code}&state={broker_state}"),
        &alice_session,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.starts_with(&format!("/realms/{INTERNAL}/account/linked-accounts?linked={EXT_ALIAS}")),
        "link success redirect, got {loc}"
    );

    // The link is listed now and can be unlinked (alice has a password).
    let resp = rig
        .internal
        .get_auth(&format!("/realms/{INTERNAL}/account/api/linked-accounts"), &bearer)
        .await;
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let links: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = links.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["alias"].as_str().unwrap(), EXT_ALIAS);
    assert_eq!(arr[0]["display_name"].as_str().unwrap(), EXT_ALIAS);

    let link = ext_link(&rig).await.unwrap();
    assert_eq!(link.user_id, alice.id);

    let resp = rig
        .internal
        .delete_auth(
            &format!("/realms/{INTERNAL}/account/api/linked-accounts/{EXT_ALIAS}"),
            &bearer,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "unlink allowed with password set");
    assert!(ext_link(&rig).await.is_none(), "link removed");
}

/// The last-method guard: a broker-created user (no password) cannot unlink
/// its only sign-in method until a password credential exists.
#[tokio::test]
async fn unlink_last_sign_in_method_guarded() {
    let rig = broker_rig(&[("trustEmail", "true")]).await;

    // Broker-created user: no password credential, exactly one link.
    let resp = drive_to_callback(&rig, EXT_USER, EXT_PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let app_loc = location(&resp);
    let tokens = redeem_app_code(&rig, &app_loc).await;
    let bearer = tokens["access_token"].as_str().unwrap().to_string();

    let resp = rig
        .internal
        .delete_auth(
            &format!("/realms/{INTERNAL}/account/api/linked-accounts/{EXT_ALIAS}"),
            &bearer,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "last method unlink refused");
    assert!(ext_link(&rig).await.is_some(), "link kept");

    // Give the user a password (as an admin reset would) and unlink succeeds.
    let link = ext_link(&rig).await.unwrap();
    issuerd_auth_flow::built_in::set_user_password(
        rig.internal.storage.as_ref(),
        &internal_realm_id(),
        &link.user_id,
        "new-password-1",
        0,
        false,
    )
    .await
    .unwrap();
    let resp = rig
        .internal
        .delete_auth(
            &format!("/realms/{INTERNAL}/account/api/linked-accounts/{EXT_ALIAS}"),
            &bearer,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(ext_link(&rig).await.is_none());

    // Deleting a link that does not exist is idempotent.
    let resp = rig
        .internal
        .delete_auth(
            &format!("/realms/{INTERNAL}/account/api/linked-accounts/{EXT_ALIAS}"),
            &bearer,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}
