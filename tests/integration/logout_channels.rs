// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Back-channel and front-channel logout integration tests.
//!
//! Back-channel: destroying a session (RP-initiated logout, admin session
//! delete) POSTs a signed logout token (`logout_token=<jwt>`) to every client
//! session whose client configured a `backchannel_logout_uri` attribute.
//! Delivery is fire-and-forget — it never blocks or fails the logout — and
//! each delivery outcome is recorded as an admin event. Front-channel: the
//! RP-initiated logout endpoint renders an interstitial with one hidden
//! iframe per client session whose client configured `frontchannel_logout_uri`
//! (called with `iss` + `sid`), then continues to the validated
//! `post_logout_redirect_uri`.
//!
//! The receiving client is a loopback axum server on `127.0.0.1:0`, so
//! delivery exercises the production reqwest dispatcher over real HTTP.

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use base64::Engine;

use crate::harness::TestHarness;

// ---------------------------------------------------------------------------
// Loopback logout-token receiver
// ---------------------------------------------------------------------------

struct LogoutReceiver {
    base_url: String,
    bodies: Arc<Mutex<Vec<String>>>,
}

async fn start_receiver() -> LogoutReceiver {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&bodies);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |body: String| {
            let captured = Arc::clone(&captured);
            async move {
                captured.lock().unwrap().push(body);
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    LogoutReceiver {
        base_url: format!("http://127.0.0.1:{port}"),
        bodies,
    }
}

impl LogoutReceiver {
    /// Delivery is fire-and-forget on a spawned task: poll until at least
    /// `min` bodies arrived (or the deadline passes) and return the snapshot.
    async fn wait_for_bodies(&self, min: usize) -> Vec<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let snapshot = self.bodies.lock().unwrap().clone();
            if snapshot.len() >= min || std::time::Instant::now() > deadline {
                return snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode the payload segment of a JWT without verifying the signature.
fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Register a logout URI attribute on the client.
async fn set_client_attr(
    harness: &TestHarness,
    client: &issuerd_core::Client,
    key: &str,
    value: &str,
) {
    let mut client = client.clone();
    client.attributes.insert(key.to_string(), value.to_string());
    harness.storage.update_client(&client.realm_id.clone(), &client).await.unwrap();
}

/// Log in through the full auth-code flow (creates the SSO session and the
/// client session) and return the token bundle.
async fn login(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
) -> crate::harness::TokenBundleLegacy {
    harness
        .authenticate_user(realm, client.client_id.as_ref(), username, "Password123!")
        .await
}

/// POST the RP-initiated logout endpoint with an `id_token_hint`.
async fn logout_with_hint(harness: &TestHarness, realm: &str, id_token: &str) -> StatusCode {
    let resp = harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/logout"),
            &[("id_token_hint", id_token)],
        )
        .await;
    resp.status()
}

/// Poll the admin-event log until an entry matches `pred`.
async fn wait_for_admin_event(
    harness: &TestHarness,
    realm_id: &issuerd_core::RealmId,
    pred: impl Fn(&issuerd_core::AdminEvent) -> bool,
) -> Option<issuerd_core::AdminEvent> {
    let query = issuerd_core::AdminEventQuery {
        operation_type: None,
        resource_type: Some(issuerd_core::ResourceType::Session),
        auth_user_id: None,
        date_from: None,
        date_to: None,
        pagination: issuerd_core::Pagination::default(),
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Ok(events) = harness.storage.query_admin_events(realm_id, &query).await {
            if let Some(e) = events.into_iter().find(|e| pred(e)) {
                return Some(e);
            }
        }
        if std::time::Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

// ---------------------------------------------------------------------------
// Back-channel logout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backchannel_logout_delivers_signed_logout_token() {
    let receiver = start_receiver().await;
    let harness = TestHarness::new().await;
    // Admin events are opt-in per realm (Keycloak default off); this
    // test asserts on the recorded delivery event.
    let mut realm = harness.create_realm("bc-basic").await;
    realm.admin_events_enabled = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("bc-basic", false).await;
    set_client_attr(&harness, &client, "backchannel_logout_uri", &receiver.base_url).await;
    let user = harness.create_user("bc-basic", "henrik", "Password123!").await;

    let tokens = login(&harness, "bc-basic", &client, "henrik").await;
    let id_token = tokens.id_token.expect("id token");
    let sid = jwt_claims(&id_token)["sid"].as_str().expect("sid claim").to_string();

    let status = logout_with_hint(&harness, "bc-basic", &id_token).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The session is gone, and exactly one logout token arrived.
    let sid_typed = issuerd_core::SessionId::new(&sid).unwrap();
    assert!(
        harness.storage.get_user_session(&realm.id, &sid_typed).await.unwrap().is_none(),
        "session must be deleted"
    );
    let bodies = receiver.wait_for_bodies(1).await;
    assert_eq!(bodies.len(), 1, "expected one delivery, got: {bodies:?}");
    let form: std::collections::HashMap<String, String> =
        serde_urlencoded::from_str(&bodies[0]).unwrap();
    let logout_token = form.get("logout_token").expect("logout_token form field");
    let claims = jwt_claims(logout_token);

    // OIDC Back-Channel Logout 1.0 §2.4 claim shape.
    assert_eq!(claims["sid"].as_str().unwrap(), sid);
    assert_eq!(claims["aud"].as_str().unwrap(), client.client_id.as_ref());
    assert_eq!(claims["sub"].as_str().unwrap(), user.id.as_ref());
    assert_eq!(
        claims["iss"].as_str().unwrap(),
        format!("{}/realms/{}", harness.base_url, realm.name)
    );
    assert!(
        claims["events"]
            .get("http://schemas.openid.net/event/backchannel-logout")
            .is_some(),
        "backchannel event claim missing: {claims}"
    );
    assert!(claims.get("nonce").is_none(), "logout token must not carry a nonce");

    // Delivery success is recorded as an admin event.
    let event = wait_for_admin_event(&harness, &realm.id, |e| {
        e.resource_path == format!("backchannel-logout/{}", client.client_id)
    })
    .await;
    let event = event.expect("backchannel admin event");
    assert!(event.error.is_none(), "delivery should succeed: {event:?}");
}

#[tokio::test]
async fn backchannel_delivery_failure_never_blocks_logout() {
    let harness = TestHarness::new().await;
    // Admin events are opt-in per realm; the failed delivery must
    // be recorded, so enable recording here.
    let mut realm = harness.create_realm("bc-down").await;
    realm.admin_events_enabled = true;
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("bc-down", false).await;
    // Nothing listens on the discard port: connection refused.
    set_client_attr(&harness, &client, "backchannel_logout_uri", "http://127.0.0.1:9/").await;
    harness.create_user("bc-down", "ingrid", "Password123!").await;

    let tokens = login(&harness, "bc-down", &client, "ingrid").await;
    let id_token = tokens.id_token.expect("id token");
    let sid = jwt_claims(&id_token)["sid"].as_str().expect("sid claim").to_string();

    // The logout itself succeeds normally despite the unreachable client.
    let status = logout_with_hint(&harness, "bc-down", &id_token).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let sid_typed = issuerd_core::SessionId::new(&sid).unwrap();
    assert!(harness.storage.get_user_session(&realm.id, &sid_typed).await.unwrap().is_none());

    // ...and the failed delivery surfaces as an admin event with an error.
    let event = wait_for_admin_event(&harness, &realm.id, |e| {
        e.resource_path == format!("backchannel-logout/{}", client.client_id) && e.error.is_some()
    })
    .await;
    assert!(event.is_some(), "failed delivery must be recorded as an admin event");
}

#[tokio::test]
async fn admin_session_delete_triggers_backchannel_logout() {
    let receiver = start_receiver().await;
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("bc-admin").await;
    let client = harness.create_client("bc-admin", false).await;
    set_client_attr(&harness, &client, "backchannel_logout_uri", &receiver.base_url).await;
    harness.create_user("bc-admin", "jakob", "Password123!").await;

    let tokens = login(&harness, "bc-admin", &client, "jakob").await;
    let sid = jwt_claims(tokens.id_token.as_deref().unwrap())["sid"]
        .as_str()
        .unwrap()
        .to_string();

    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let resp = harness
        .delete_auth(&format!("/admin/realms/bc-admin/sessions/{sid}"), &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let bodies = receiver.wait_for_bodies(1).await;
    assert_eq!(bodies.len(), 1, "expected one delivery, got: {bodies:?}");
    let form: std::collections::HashMap<String, String> =
        serde_urlencoded::from_str(&bodies[0]).unwrap();
    let claims = jwt_claims(form.get("logout_token").unwrap());
    assert_eq!(claims["sid"].as_str().unwrap(), sid);
    let sid_typed = issuerd_core::SessionId::new(&sid).unwrap();
    assert!(harness.storage.get_user_session(&realm.id, &sid_typed).await.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Front-channel logout
// ---------------------------------------------------------------------------

/// GET the RP-initiated logout endpoint with query params.
async fn logout_get(
    harness: &TestHarness,
    realm: &str,
    params: &[(&str, &str)],
) -> axum::response::Response {
    let query = serde_urlencoded::to_string(params).unwrap();
    let path = format!("/realms/{realm}/protocol/openid-connect/logout?{query}");
    harness.get(&path).await
}

#[tokio::test]
async fn frontchannel_logout_renders_iframe_interstitial_then_continues() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("fc-basic").await;
    let client = harness.create_client("fc-basic", false).await;
    set_client_attr(
        &harness,
        &client,
        "frontchannel_logout_uri",
        "http://localhost:8080/fc-logout",
    )
    .await;
    harness.create_user("fc-basic", "kirsten", "Password123!").await;

    let tokens = login(&harness, "fc-basic", &client, "kirsten").await;
    let id_token = tokens.id_token.expect("id token");
    let sid = jwt_claims(&id_token)["sid"].as_str().unwrap().to_string();

    let resp = logout_get(
        &harness,
        "fc-basic",
        &[
            ("id_token_hint", &id_token),
            ("post_logout_redirect_uri", "http://localhost:8080/cb"),
            ("state", "logout-state"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();

    // Hidden iframe per OIDC Front-Channel Logout 1.0 (iss + sid query params,
    // HTML-escaped in the page).
    let expected_prefix = "<iframe src=\"http://localhost:8080/fc-logout?iss=";
    assert!(body.contains(expected_prefix), "iframe missing: {body}");
    assert!(body.contains(&format!("&amp;sid={sid}")), "sid param missing: {body}");
    // The page continues to the validated post-logout target (with state).
    assert!(
        body.contains("http://localhost:8080/cb?state=logout-state"),
        "continue target: {body}"
    );

    // The session is destroyed regardless of the interstitial rendering.
    let sid_typed = issuerd_core::SessionId::new(&sid).unwrap();
    assert!(harness.storage.get_user_session(&realm.id, &sid_typed).await.unwrap().is_none());
}

#[tokio::test]
async fn frontchannel_logout_without_redirect_target_renders_confirmation() {
    let harness = TestHarness::new().await;
    harness.create_realm("fc-plain").await;
    let client = harness.create_client("fc-plain", false).await;
    set_client_attr(
        &harness,
        &client,
        "frontchannel_logout_uri",
        "http://localhost:8080/fc-logout",
    )
    .await;
    harness.create_user("fc-plain", "lars", "Password123!").await;

    let tokens = login(&harness, "fc-plain", &client, "lars").await;
    let id_token = tokens.id_token.expect("id token");

    let resp = logout_get(&harness, "fc-plain", &[("id_token_hint", &id_token)]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("signed out"), "confirmation text missing: {body}");
    assert!(
        body.contains("<iframe src=\"http://localhost:8080/fc-logout?iss="),
        "iframe: {body}"
    );
    // No post-logout target: no continue link, no meta refresh.
    assert!(!body.contains("Continue"), "unexpected continue link: {body}");
}

#[tokio::test]
async fn logout_without_frontchannel_clients_keeps_plain_redirect_behavior() {
    let harness = TestHarness::new().await;
    harness.create_realm("fc-none").await;
    let client = harness.create_client("fc-none", false).await;
    harness.create_user("fc-none", "mona", "Password123!").await;

    let tokens = login(&harness, "fc-none", &client, "mona").await;
    let id_token = tokens.id_token.expect("id token");

    // No frontchannel_logout_uri on the client: unchanged behavior without
    // logout channels — a plain 303 to the validated post-logout target.
    let resp = logout_get(
        &harness,
        "fc-none",
        &[
            ("id_token_hint", &id_token),
            ("post_logout_redirect_uri", "http://localhost:8080/cb"),
            ("state", "s1"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "http://localhost:8080/cb?state=s1");
}
