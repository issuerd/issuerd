// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Token exchange (RFC 8693) integration tests (Issuerd-only, in-process).

//! Token exchange (RFC 8693) integration tests (Issuerd-only,
//! in-process).
//!
//! Covers both shipped modes end to end through the HTTP stack:
//! - internal exchange (`audience` = target client) gated by the target
//!   client's `token.exchange.enabled=true` attribute;
//! - impersonation exchange (`requested_subject` = target user id) gated by
//!   the caller's realm `impersonation` role, with admin-event audit treatment.
//!
//! Plus the rejection matrix: cross-realm / revoked / session-less / disabled
//! subject tokens, scope widening, delegation (`actor_token`), DPoP
//! laundering resistance (RFC 9449 §7.1), target-client scope intersection,
//! and the discovery advertisement.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use ring::signature::KeyPair as _;
use tower::ServiceExt;

use crate::harness::TestHarness;

const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Decode a JWT payload without verifying the signature (test inspection).
fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn token_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token")
}

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

/// Password-grant an access token for `username` via `client`.
async fn password_grant_token(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    password: &str,
    scope: &str,
) -> String {
    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            &token_path(realm),
            &[
                ("grant_type", "password"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("username", username),
                ("password", password),
                ("scope", scope),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "password grant must succeed");
    let json = body_json(resp).await;
    json["access_token"].as_str().unwrap().to_string()
}

/// Post a token-exchange request (raw response; status varies).
struct ExchangeRequest<'a> {
    subject_token: &'a str,
    audience: Option<&'a str>,
    requested_subject: Option<&'a str>,
    scope: Option<&'a str>,
    subject_token_type: Option<&'a str>,
    requested_token_type: Option<&'a str>,
    actor_token: Option<&'a str>,
}

impl<'a> ExchangeRequest<'a> {
    fn new(subject_token: &'a str) -> Self {
        Self {
            subject_token,
            audience: None,
            requested_subject: None,
            scope: None,
            subject_token_type: None,
            requested_token_type: None,
            actor_token: None,
        }
    }
}

async fn exchange(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    req: &ExchangeRequest<'_>,
) -> axum::response::Response {
    let client_id = client.client_id.to_string();
    let secret = client.secret.as_deref().unwrap_or("").to_string();
    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", EXCHANGE_GRANT),
        ("client_id", &client_id),
        ("client_secret", &secret),
        ("subject_token", req.subject_token),
        ("subject_token_type", req.subject_token_type.unwrap_or(ACCESS_TOKEN_TYPE)),
    ];
    if let Some(audience) = req.audience {
        params.push(("audience", audience));
    }
    if let Some(requested_subject) = req.requested_subject {
        params.push(("requested_subject", requested_subject));
    }
    if let Some(scope) = req.scope {
        params.push(("scope", scope));
    }
    if let Some(requested_token_type) = req.requested_token_type {
        params.push(("requested_token_type", requested_token_type));
    }
    if let Some(actor_token) = req.actor_token {
        params.push(("actor_token", actor_token));
    }
    harness.post_form(&token_path(realm), &params).await
}

/// Set (or clear) the `token.exchange.enabled` attribute on a client.
async fn set_exchange_flag(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    enabled: bool,
) {
    let mut client = client.clone();
    if enabled {
        client
            .attributes
            .insert("token.exchange.enabled".to_string(), "true".to_string());
    } else {
        client.attributes.remove("token.exchange.enabled");
    }
    harness
        .storage
        .update_client(&issuerd_core::RealmId::new(realm).unwrap(), &client)
        .await
        .unwrap();
}

/// Create the realm `impersonation` role and assign it to `user_id`.
async fn grant_impersonation_role(
    harness: &TestHarness,
    realm: &str,
    admin_token: &str,
    user_id: &str,
) {
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/{realm}/roles"),
            admin_token,
            serde_json::json!({ "name": "impersonation" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "create impersonation role");

    let resp = harness
        .get_auth(&format!("/admin/realms/{realm}/roles/impersonation"), admin_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let role = body_json(resp).await;

    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/{realm}/users/{user_id}/role-mappings/realm"),
            admin_token,
            serde_json::json!([{ "id": role["id"], "name": "impersonation" }]),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "assign impersonation role");
}

// ---------------------------------------------------------------------------
// Internal exchange
// ---------------------------------------------------------------------------

#[tokio::test]
async fn internal_exchange_mints_narrowed_token_for_target_client() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-basic").await;
    let requesting = harness.create_client("ex-basic", false).await;
    let target = harness.create_client("ex-basic", false).await;
    set_exchange_flag(&harness, "ex-basic", &target, true).await;
    let user = harness.create_user("ex-basic", "alice", "Password123!").await;

    // Record events so the exchange audit event can be asserted.
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let resp = put_json_auth(
        &harness,
        "/admin/realms/ex-basic/events/config",
        &admin,
        serde_json::json!({ "eventsEnabled": true }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let subject = password_grant_token(
        &harness,
        "ex-basic",
        &requesting,
        "alice",
        "Password123!",
        "openid profile email",
    )
    .await;

    let mut req = ExchangeRequest::new(&subject);
    req.audience = Some(target.client_id.as_ref());
    req.scope = Some("openid profile");
    let resp = exchange(&harness, "ex-basic", &requesting, &req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;

    // RFC 8693 §2.2 response shape.
    assert_eq!(json["issued_token_type"].as_str().unwrap(), ACCESS_TOKEN_TYPE);
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["expires_in"].as_u64().unwrap() > 0);
    // No refresh/ID tokens are issued on exchange (Keycloak parity: refresh
    // tokens only for offline-style requests, which are out of scope).
    assert!(json["refresh_token"].is_null());
    assert!(json["id_token"].is_null());

    let claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(claims["aud"].as_str().unwrap(), target.client_id.as_ref());
    assert_eq!(claims["azp"].as_str().unwrap(), target.client_id.as_ref());
    assert_eq!(claims["sub"].as_str().unwrap(), user.id.0);
    assert_eq!(claims["scope"].as_str().unwrap(), "openid profile");
    assert!(claims.get("impersonator").is_none(), "no impersonator claim on plain exchange");

    // The exchange emitted a `token_exchange` event.
    let resp = harness.get_auth("/admin/realms/ex-basic/events", &admin).await;
    let events = body_json(resp).await;
    let events = events.as_array().unwrap();
    assert!(
        events.iter().any(|e| e["event_type"] == "token_exchange"),
        "expected a token_exchange event: {events:?}"
    );
}

#[tokio::test]
async fn internal_exchange_without_target_flag_is_denied() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-deny").await;
    let requesting = harness.create_client("ex-deny", false).await;
    // Target client WITHOUT the exchange flag.
    let target = harness.create_client("ex-deny", false).await;
    harness.create_user("ex-deny", "bob", "Password123!").await;

    let subject =
        password_grant_token(&harness, "ex-deny", &requesting, "bob", "Password123!", "openid")
            .await;

    let mut req = ExchangeRequest::new(&subject);
    req.audience = Some(target.client_id.as_ref());
    let resp = exchange(&harness, "ex-deny", &requesting, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn internal_exchange_unknown_or_disabled_audience_is_denied() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-aud").await;
    let requesting = harness.create_client("ex-aud", false).await;
    harness.create_user("ex-aud", "carol", "Password123!").await;
    let subject =
        password_grant_token(&harness, "ex-aud", &requesting, "carol", "Password123!", "openid")
            .await;

    // Unknown client as audience.
    let mut req = ExchangeRequest::new(&subject);
    req.audience = Some("no-such-client");
    let resp = exchange(&harness, "ex-aud", &requesting, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");

    // Disabled client as audience (flag set, but enabled = false).
    let mut disabled = harness.create_client("ex-aud", false).await;
    disabled
        .attributes
        .insert("token.exchange.enabled".to_string(), "true".to_string());
    disabled.enabled = false;
    harness
        .storage
        .update_client(&issuerd_core::RealmId::new("ex-aud").unwrap(), &disabled)
        .await
        .unwrap();
    let mut req = ExchangeRequest::new(&subject);
    req.audience = Some(disabled.client_id.as_ref());
    let resp = exchange(&harness, "ex-aud", &requesting, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn internal_exchange_self_targeting_still_requires_flag() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-self").await;
    let client = harness.create_client("ex-self", false).await;
    harness.create_user("ex-self", "dave", "Password123!").await;
    let subject =
        password_grant_token(&harness, "ex-self", &client, "dave", "Password123!", "openid").await;

    // No audience => the requesting client itself is the target; without the
    // flag the exchange is denied.
    let req = ExchangeRequest::new(&subject);
    let resp = exchange(&harness, "ex-self", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");

    // With the flag set the self-exchange succeeds and keeps the audience.
    set_exchange_flag(&harness, "ex-self", &client, true).await;
    let req = ExchangeRequest::new(&subject);
    let resp = exchange(&harness, "ex-self", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(claims["aud"].as_str().unwrap(), client.client_id.as_ref());
}

#[tokio::test]
async fn internal_exchange_scope_narrowing_rules() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-scope").await;
    let requesting = harness.create_client("ex-scope", false).await;
    let target = harness.create_client("ex-scope", false).await;
    set_exchange_flag(&harness, "ex-scope", &target, true).await;
    harness.create_user("ex-scope", "erin", "Password123!").await;

    let subject = password_grant_token(
        &harness,
        "ex-scope",
        &requesting,
        "erin",
        "Password123!",
        "openid profile",
    )
    .await;

    // Widening beyond the subject grant is rejected (email was never granted).
    let mut req = ExchangeRequest::new(&subject);
    req.audience = Some(target.client_id.as_ref());
    req.scope = Some("openid email");
    let resp = exchange(&harness, "ex-scope", &requesting, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_scope");

    // Narrowing to a subset succeeds.
    let mut req = ExchangeRequest::new(&subject);
    req.audience = Some(target.client_id.as_ref());
    req.scope = Some("openid");
    let resp = exchange(&harness, "ex-scope", &requesting, &req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["scope"].as_str().unwrap(), "openid");

    // An omitted scope keeps the subject token's grant.
    let mut req = ExchangeRequest::new(&subject);
    req.audience = Some(target.client_id.as_ref());
    let resp = exchange(&harness, "ex-scope", &requesting, &req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(claims["scope"].as_str().unwrap(), "openid profile");
}

// ---------------------------------------------------------------------------
// Subject-token rejection matrix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cross_realm_subject_token_is_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-a").await;
    harness.create_realm("ex-b").await;
    let client_a = harness.create_client("ex-a", false).await;
    let client_b = harness.create_client("ex-b", false).await;
    set_exchange_flag(&harness, "ex-b", &client_b, true).await;
    harness.create_user("ex-a", "frank", "Password123!").await;

    let subject =
        password_grant_token(&harness, "ex-a", &client_a, "frank", "Password123!", "openid").await;

    // The token of realm ex-a must not be exchangeable in realm ex-b.
    let req = ExchangeRequest::new(&subject);
    let resp = exchange(&harness, "ex-b", &client_b, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn revoked_subject_token_is_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-revoked").await;
    let client = harness.create_client("ex-revoked", false).await;
    set_exchange_flag(&harness, "ex-revoked", &client, true).await;
    harness.create_user("ex-revoked", "grace", "Password123!").await;
    let subject =
        password_grant_token(&harness, "ex-revoked", &client, "grace", "Password123!", "openid")
            .await;

    // Revoke the access token (RFC 7009).
    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            "/realms/ex-revoked/protocol/openid-connect/revoke",
            &[
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("token", &subject),
                ("token_type_hint", "access_token"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "revocation accepted");

    let req = ExchangeRequest::new(&subject);
    let resp = exchange(&harness, "ex-revoked", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn logged_out_session_subject_token_is_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-logout").await;
    let client = harness.create_client("ex-logout", false).await;
    set_exchange_flag(&harness, "ex-logout", &client, true).await;
    harness.create_user("ex-logout", "heidi", "Password123!").await;
    let subject =
        password_grant_token(&harness, "ex-logout", &client, "heidi", "Password123!", "openid")
            .await;

    // Tear down the underlying user session (as logout would).
    let sid = jwt_claims(&subject)["sid"].as_str().unwrap().to_string();
    harness
        .storage
        .delete_user_session(
            &issuerd_core::RealmId::new("ex-logout").unwrap(),
            &issuerd_core::SessionId::new(sid).unwrap(),
        )
        .await
        .unwrap();

    let req = ExchangeRequest::new(&subject);
    let resp = exchange(&harness, "ex-logout", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn disabled_subject_user_is_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-disabled").await;
    let client = harness.create_client("ex-disabled", false).await;
    set_exchange_flag(&harness, "ex-disabled", &client, true).await;
    let user = harness.create_user("ex-disabled", "ivan", "Password123!").await;
    let subject =
        password_grant_token(&harness, "ex-disabled", &client, "ivan", "Password123!", "openid")
            .await;

    let mut user = user;
    user.enabled = false;
    harness
        .storage
        .update_user(&issuerd_core::RealmId::new("ex-disabled").unwrap(), &user)
        .await
        .unwrap();
    // The admin write path invalidates the claims read-model cache
    // synchronously — mirror that here since the test writes storage directly.
    issuerd_cluster::invalidate::invalidate_user_claims(
        harness.cache.as_ref(),
        &issuerd_core::RealmId::new("ex-disabled").unwrap(),
        &user.id,
    )
    .await;

    let req = ExchangeRequest::new(&subject);
    let resp = exchange(&harness, "ex-disabled", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_token_as_subject_is_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-refresh").await;
    let client = harness.create_client("ex-refresh", false).await;
    set_exchange_flag(&harness, "ex-refresh", &client, true).await;
    harness.create_user("ex-refresh", "judy", "Password123!").await;

    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            &token_path("ex-refresh"),
            &[
                ("grant_type", "password"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("username", "judy"),
                ("password", "Password123!"),
                ("scope", "openid"),
            ],
        )
        .await;
    let json = body_json(resp).await;
    let refresh = json["refresh_token"].as_str().unwrap();

    // Even with the access-token type URN, a refresh token fails access-token
    // validation.
    let req = ExchangeRequest::new(refresh);
    let resp = exchange(&harness, "ex-refresh", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");

    // And declaring the refresh-token type URN is rejected at validation.
    let mut req = ExchangeRequest::new(refresh);
    req.subject_token_type = Some("urn:ietf:params:oauth:token-type:refresh_token");
    let resp = exchange(&harness, "ex-refresh", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_request");
}

#[tokio::test]
async fn delegation_and_unsupported_requested_type_are_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-deleg").await;
    let client = harness.create_client("ex-deleg", false).await;
    set_exchange_flag(&harness, "ex-deleg", &client, true).await;
    harness.create_user("ex-deleg", "karl", "Password123!").await;
    let subject =
        password_grant_token(&harness, "ex-deleg", &client, "karl", "Password123!", "openid").await;

    // actor_token (delegation) is out of scope.
    let mut req = ExchangeRequest::new(&subject);
    req.actor_token = Some("actor.jwt");
    let resp = exchange(&harness, "ex-deleg", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_request");

    // Only access tokens are issued.
    let mut req = ExchangeRequest::new(&subject);
    req.requested_token_type = Some("urn:ietf:params:oauth:token-type:id_token");
    let resp = exchange(&harness, "ex-deleg", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_request");
}

// ---------------------------------------------------------------------------
// Impersonation exchange
// ---------------------------------------------------------------------------

#[tokio::test]
async fn impersonation_exchange_mints_audited_token() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-imp").await;
    let client = harness.create_client("ex-imp", false).await;
    // The audience client deliberately has NO exchange flag: the
    // impersonation role is the only gate in this mode.
    let audience_client = harness.create_client("ex-imp", false).await;
    let caller = harness.create_user("ex-imp", "carol-admin", "Password123!").await;
    let target = harness.create_user("ex-imp", "victim", "Password123!").await;

    let admin = harness.get_admin_token("master", "admin", "admin").await;
    grant_impersonation_role(&harness, "ex-imp", &admin, &caller.id.0).await;

    // Enable admin events (login events are bypass-gated and need no config).
    let resp = put_json_auth(
        &harness,
        "/admin/realms/ex-imp/events/config",
        &admin,
        serde_json::json!({ "adminEventsEnabled": true }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let subject =
        password_grant_token(&harness, "ex-imp", &client, "carol-admin", "Password123!", "openid")
            .await;
    assert!(
        jwt_claims(&subject)["realm_access"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "impersonation"),
        "subject token must carry the impersonation realm role"
    );

    let mut req = ExchangeRequest::new(&subject);
    req.requested_subject = Some(&target.id.0);
    req.audience = Some(audience_client.client_id.as_ref());
    let resp = exchange(&harness, "ex-imp", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["issued_token_type"].as_str().unwrap(), ACCESS_TOKEN_TYPE);

    let claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(claims["sub"].as_str().unwrap(), target.id.0);
    assert_eq!(claims["impersonator"].as_str().unwrap(), caller.id.0);
    assert_eq!(claims["aud"].as_str().unwrap(), audience_client.client_id.as_ref());

    // The impersonation session record proves who impersonated whom.
    let realm_id = issuerd_core::RealmId::new("ex-imp").unwrap();
    let sessions = harness
        .storage
        .list_sessions(&realm_id, Some(target.id.clone()), &issuerd_core::Pagination::default())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].impersonator, Some(caller.id.clone()));

    // Audited: an ACTION admin event on the impersonation resource path ...
    let resp = harness.get_auth("/admin/realms/ex-imp/admin-events", &admin).await;
    let events = body_json(resp).await;
    let events = events.as_array().unwrap();
    assert!(
        events.iter().any(|e| e["operation_type"] == "ACTION"
            && e["resource_path"].as_str().is_some_and(|p| p.contains("impersonation"))),
        "expected impersonation admin event: {events:?}"
    );

    // ... and a login event that bypasses the (disabled) events gate.
    let resp = harness.get_auth("/admin/realms/ex-imp/events", &admin).await;
    let events = body_json(resp).await;
    let events = events.as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["event_type"] == "login" && e["details"]["method"] == "impersonation"),
        "expected impersonation login event: {events:?}"
    );
}

#[tokio::test]
async fn impersonation_exchange_requires_the_role() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-imp-deny").await;
    let client = harness.create_client("ex-imp-deny", false).await;
    harness.create_user("ex-imp-deny", "regular-user", "Password123!").await;
    let target = harness.create_user("ex-imp-deny", "victim", "Password123!").await;

    let subject = password_grant_token(
        &harness,
        "ex-imp-deny",
        &client,
        "regular-user",
        "Password123!",
        "openid",
    )
    .await;

    let mut req = ExchangeRequest::new(&subject);
    req.requested_subject = Some(&target.id.0);
    let resp = exchange(&harness, "ex-imp-deny", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn impersonation_exchange_target_guards() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-imp-guard").await;
    let client = harness.create_client("ex-imp-guard", false).await;
    let caller = harness.create_user("ex-imp-guard", "boss", "Password123!").await;
    let disabled = harness.create_user("ex-imp-guard", "offboarded", "Password123!").await;

    let admin = harness.get_admin_token("master", "admin", "admin").await;
    grant_impersonation_role(&harness, "ex-imp-guard", &admin, &caller.id.0).await;

    let mut offboarded = disabled.clone();
    offboarded.enabled = false;
    harness
        .storage
        .update_user(&issuerd_core::RealmId::new("ex-imp-guard").unwrap(), &offboarded)
        .await
        .unwrap();

    let subject =
        password_grant_token(&harness, "ex-imp-guard", &client, "boss", "Password123!", "openid")
            .await;

    // Self-impersonation is rejected.
    let mut req = ExchangeRequest::new(&subject);
    req.requested_subject = Some(&caller.id.0);
    let resp = exchange(&harness, "ex-imp-guard", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");

    // Unknown target user is rejected.
    let mut req = ExchangeRequest::new(&subject);
    req.requested_subject = Some("no-such-user");
    let resp = exchange(&harness, "ex-imp-guard", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");

    // Disabled target user is rejected.
    let mut req = ExchangeRequest::new(&subject);
    req.requested_subject = Some(&disabled.id.0);
    let resp = exchange(&harness, "ex-imp-guard", &client, &req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_advertises_token_exchange_grant() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-disc").await;

    let resp = harness.get("/realms/ex-disc/.well-known/openid-configuration").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(
        json["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&EXCHANGE_GRANT.into()),
        "grant_types_supported must list token exchange: {}",
        json["grant_types_supported"]
    );
}

// ---------------------------------------------------------------------------
// DPoP laundering resistance (RFC 9449 §7.1) — 2026-09 review hardening
// ---------------------------------------------------------------------------

/// Minimal DPoP key + proof minting (same hand-rolled compact JWS pattern as
/// dpop.rs — the proof header must carry the public `jwk`, which the server's
/// own CryptoProvider cannot produce).
struct DpopKey {
    pair: ring::signature::EcdsaKeyPair,
    jwk: serde_json::Value,
}

impl DpopKey {
    fn new() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            doc.as_ref(),
            &rng,
        )
        .unwrap();
        let public = pair.public_key().as_ref();
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": b64(&public[1..33]), "y": b64(&public[33..65]),
        });
        Self { pair, jwk }
    }

    fn jkt(&self) -> String {
        issuerd_token::jwk_thumbprint(&self.jwk).unwrap()
    }

    /// A fresh, valid proof for the token endpoint (fresh `jti` every call —
    /// proofs are single-use).
    fn token_proof(&self, harness: &TestHarness, realm: &str) -> String {
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header = serde_json::json!({"alg": "ES256", "typ": "dpop+jwt", "jwk": self.jwk});
        let claims = serde_json::json!({
            "jti": issuerd_core::utils::generate_id(),
            "htm": "POST",
            "htu": format!("{}/realms/{realm}/protocol/openid-connect/token", harness.base_url),
            "iat": chrono::Utc::now().timestamp(),
        });
        let input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(&header).unwrap()),
            b64(&serde_json::to_vec(&claims).unwrap())
        );
        let rng = ring::rand::SystemRandom::new();
        let sig = self.pair.sign(&rng, input.as_bytes()).unwrap();
        format!("{input}.{}", b64(sig.as_ref()))
    }
}

/// Password grant carrying a DPoP proof → the issued access token is bound to
/// the proof key.
async fn dpop_password_grant(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    password: &str,
    key: &DpopKey,
) -> String {
    let client_id = client.client_id.to_string();
    let secret = client.secret.as_deref().unwrap_or("").to_string();
    let params: Vec<(&str, &str)> = vec![
        ("grant_type", "password"),
        ("client_id", &client_id),
        ("client_secret", &secret),
        ("username", username),
        ("password", password),
        ("scope", "openid profile email"),
    ];
    let body = serde_urlencoded::to_string(params).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(token_path(realm))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("dpop", key.token_proof(harness, realm))
        .body(Body::from(body))
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "DPoP password grant must succeed");
    let json = body_json(resp).await;
    assert_eq!(json["token_type"], "DPoP");
    json["access_token"].as_str().unwrap().to_string()
}

/// Token exchange with an optional DPoP proof header.
async fn exchange_with_proof(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    req: &ExchangeRequest<'_>,
    proof: Option<&str>,
) -> axum::response::Response {
    let client_id = client.client_id.to_string();
    let secret = client.secret.as_deref().unwrap_or("").to_string();
    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", EXCHANGE_GRANT),
        ("client_id", &client_id),
        ("client_secret", &secret),
        ("subject_token", req.subject_token),
        ("subject_token_type", req.subject_token_type.unwrap_or(ACCESS_TOKEN_TYPE)),
    ];
    if let Some(audience) = req.audience {
        params.push(("audience", audience));
    }
    if let Some(scope) = req.scope {
        params.push(("scope", scope));
    }
    let body = serde_urlencoded::to_string(params).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri(token_path(realm))
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(proof) = proof {
        builder = builder.header("dpop", proof);
    }
    let http_req = builder.body(Body::from(body)).unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(http_req)).await.unwrap()
}

/// A DPoP-bound subject token may only be exchanged by its key holder —
/// otherwise a stolen bound token could be laundered into a plain bearer
/// token (or re-bound to the attacker's key).
#[tokio::test]
async fn dpop_bound_subject_token_requires_matching_proof() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-dpop").await;
    let client = harness.create_client("ex-dpop", false).await;
    // Self-exchange: without `audience` the target IS the requesting client,
    // which must still opt in via the exchange flag.
    set_exchange_flag(&harness, "ex-dpop", &client, true).await;
    harness.create_user("ex-dpop", "alice", "Password123!").await;

    let key = DpopKey::new();
    let subject =
        dpop_password_grant(&harness, "ex-dpop", &client, "alice", "Password123!", &key).await;
    assert_eq!(
        jwt_claims(&subject)["cnf"]["jkt"].as_str().unwrap(),
        key.jkt(),
        "subject token must be DPoP-bound"
    );

    // No proof → rejected (this was the laundering hole).
    let req = ExchangeRequest::new(&subject);
    let resp = exchange_with_proof(&harness, "ex-dpop", &client, &req, None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");

    // Proof from a DIFFERENT key → rejected.
    let other = DpopKey::new();
    let resp = exchange_with_proof(
        &harness,
        "ex-dpop",
        &client,
        &req,
        Some(&other.token_proof(&harness, "ex-dpop")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");

    // Proof from the SAME key → succeeds, and the minted token stays bound
    // to that key.
    let resp = exchange_with_proof(
        &harness,
        "ex-dpop",
        &client,
        &req,
        Some(&key.token_proof(&harness, "ex-dpop")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["token_type"], "DPoP");
    let claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(claims["cnf"]["jkt"].as_str().unwrap(), key.jkt());
}

/// An unbound (Bearer) subject token still exchanges without any proof — the
/// binding requirement only applies to bound tokens.
#[tokio::test]
async fn bearer_subject_token_exchanges_without_proof() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-dpop-bearer").await;
    let client = harness.create_client("ex-dpop-bearer", false).await;
    set_exchange_flag(&harness, "ex-dpop-bearer", &client, true).await;
    harness.create_user("ex-dpop-bearer", "alice", "Password123!").await;

    let subject = password_grant_token(
        &harness,
        "ex-dpop-bearer",
        &client,
        "alice",
        "Password123!",
        "openid",
    )
    .await;
    let req = ExchangeRequest::new(&subject);
    let resp = exchange_with_proof(&harness, "ex-dpop-bearer", &client, &req, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["token_type"], "Bearer");
}

// ---------------------------------------------------------------------------
// Target-client scope intersection — 2026-09 review hardening
// ---------------------------------------------------------------------------

/// The exchanged token's scope is intersected with the TARGET client's
/// assigned scopes: a scope the requesting client holds but the target was
/// never assigned must not leak into the target's audience.
#[tokio::test]
async fn exchange_scope_intersected_with_target_assignments() {
    let harness = TestHarness::new().await;
    harness.create_realm("ex-scope-intersect").await;
    let requesting = harness.create_client("ex-scope-intersect", false).await;
    let target = harness.create_client("ex-scope-intersect", false).await;
    set_exchange_flag(&harness, "ex-scope-intersect", &target, true).await;
    harness.create_user("ex-scope-intersect", "alice", "Password123!").await;

    // The target keeps only `openid` — `profile`/`email` stay assigned to the
    // requesting client alone. (Re-fetch the flagged client first: the flag
    // update went straight to storage, and cloning the stale `target` would
    // drop the attribute.)
    let realm_id = issuerd_core::RealmId::new("ex-scope-intersect").unwrap();
    let mut narrowed_target = harness
        .storage
        .get_client_by_client_id(&realm_id, &target.client_id)
        .await
        .unwrap()
        .unwrap();
    narrowed_target.default_scopes = issuerd_core::Scope::parse("openid");
    narrowed_target.optional_scopes = issuerd_core::Scope::empty();
    harness.storage.update_client(&realm_id, &narrowed_target).await.unwrap();

    let subject = password_grant_token(
        &harness,
        "ex-scope-intersect",
        &requesting,
        "alice",
        "Password123!",
        "openid profile email",
    )
    .await;

    let mut req = ExchangeRequest::new(&subject);
    req.audience = Some(target.client_id.as_ref());
    let resp = exchange(&harness, "ex-scope-intersect", &requesting, &req).await;
    let status = resp.status();
    let json = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "exchange failed: {json}");
    let claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(
        claims["scope"].as_str().unwrap(),
        "openid",
        "target-unassigned scopes must not leak into the exchanged token"
    );
    assert_eq!(json["scope"].as_str().unwrap(), "openid");

    // Self-exchange (no audience) targets the requesting client itself; with
    // the exchange flag set, its own assignments apply unchanged — the
    // intersection only narrows, never widens.
    set_exchange_flag(&harness, "ex-scope-intersect", &requesting, true).await;
    let req = ExchangeRequest::new(&subject);
    let resp = exchange(&harness, "ex-scope-intersect", &requesting, &req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["scope"].as_str().unwrap(), "email openid profile");
}
