// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Dynamic client registration (RFC 7591/7592) integration tests.

//! Dynamic client registration (RFC 7591/7592) integration
//! tests (Issuerd-only).
//!
//! Covered: the realm toggle (404 + no discovery advertisement when off),
//! open registration (roundtrip, validation errors, rate limiting),
//! initial-access-token-gated registration (mint/list/revoke via the admin
//! API, count exhaustion), registration-access-token CRUD with rotation on
//! update, and an end-to-end check that a registered client works at the
//! token endpoint.

use axum::http::StatusCode;

use crate::harness::TestHarness;

fn registrations_path(realm: &str, provider: &str) -> String {
    format!("/realms/{realm}/clients-registrations/{provider}")
}

fn registration_client_path(realm: &str, client_id: &str) -> String {
    format!("/realms/{realm}/clients-registrations/openid-connect/{client_id}")
}

fn initial_access_path(realm: &str) -> String {
    format!("/admin/realms/{realm}/clients-initial-access")
}

/// Extract a JSON body from a response.
async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Enable dynamic client registration on the realm.
async fn enable_registration(harness: &TestHarness, realm: &issuerd_core::Realm) {
    let mut realm = realm.clone();
    realm.attributes.insert(
        issuerd_core::Realm::DYNAMIC_CLIENT_REGISTRATION_ATTRIBUTE.to_string(),
        "true".to_string(),
    );
    harness.storage.update_realm(&realm).await.unwrap();
}

/// PUT a JSON body with a bearer token (the harness has no PUT helper).
async fn put_json_auth(
    harness: &TestHarness,
    path: &str,
    body: serde_json::Value,
    token: &str,
) -> axum::response::Response {
    use tower::ServiceExt;
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

/// Mint an initial access token via the admin API; returns the response JSON.
async fn mint_initial_access(
    harness: &TestHarness,
    realm: &str,
    expiration: u64,
    count: u32,
) -> serde_json::Value {
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;
    let resp = harness
        .post_json_auth(
            &initial_access_path(realm),
            &admin_token,
            serde_json::json!({"expiration": expiration, "count": count}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    json_body(resp).await
}

/// Register a client at the open endpoint; asserts 201 and returns the body.
async fn register_open_ok(harness: &TestHarness, realm: &str) -> serde_json::Value {
    let resp = harness
        .post_json(
            &registrations_path(realm, "default"),
            serde_json::json!({
                "name": "Registered App",
                "redirect_uris": ["http://localhost:8080/cb"],
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    json_body(resp).await
}

// ---------------------------------------------------------------------------
// Toggle + discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disabled_realm_returns_404_and_no_discovery_advertisement() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-off").await;

    // Every registration endpoint 404s while the toggle is off.
    for (method, path) in [
        ("POST", registrations_path(realm.name.as_ref(), "default")),
        ("POST", registrations_path(realm.name.as_ref(), "openid-connect")),
        ("GET", registration_client_path(realm.name.as_ref(), "whatever")),
        ("PUT", registration_client_path(realm.name.as_ref(), "whatever")),
        ("DELETE", registration_client_path(realm.name.as_ref(), "whatever")),
    ] {
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .method(method)
            .uri(&path)
            .header("content-type", "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{method} {path}");
    }

    // Discovery does not advertise a registration endpoint.
    let resp = harness
        .get(&format!("/realms/{}/.well-known/openid-configuration", realm.name))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json.get("registration_endpoint").is_none());
}

#[tokio::test]
async fn enabled_realm_advertises_registration_endpoint() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-on").await;
    enable_registration(&harness, &realm).await;

    let resp = harness
        .get(&format!("/realms/{}/.well-known/openid-configuration", realm.name))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(
        json["registration_endpoint"].as_str().unwrap(),
        format!("{}/realms/{}/clients-registrations/openid-connect", harness.base_url, realm.id)
    );
}

// ---------------------------------------------------------------------------
// Open registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_registration_roundtrip() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-open").await;
    enable_registration(&harness, &realm).await;

    let json = register_open_ok(&harness, realm.name.as_ref()).await;
    let client_id = json["client_id"].as_str().expect("client_id assigned");
    let secret = json["secret"].as_str().expect("confidential by default");
    assert!(!secret.is_empty());
    let registration_token = json["registrationAccessToken"]
        .as_str()
        .expect("registration access token present");

    // The client exists in storage with the realm's default scopes seeded
    // (create_realm seeds the built-in scope tables: profile/email/roles
    // default, the rest optional).
    let client = harness
        .storage
        .get_client_by_client_id(
            &realm.id,
            &issuerd_core::ClientIdentifier::new(client_id).unwrap(),
        )
        .await
        .unwrap()
        .expect("registered client persisted");
    let default_scopes: Vec<String> = client.default_scopes.to_vec();
    for scope in ["profile", "email", "roles"] {
        assert!(default_scopes.contains(&scope.to_string()), "missing default scope {scope}");
    }

    // GET with the registration access token echoes the same token and
    // shows the secret.
    let resp = harness
        .get_auth(&registration_client_path(realm.name.as_ref(), client_id), registration_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["registrationAccessToken"].as_str().unwrap(), registration_token);
    assert_eq!(json["secret"].as_str().unwrap(), secret);
    assert_eq!(json["name"].as_str().unwrap(), "Registered App");
}

#[tokio::test]
async fn open_registration_explicit_client_id_and_conflict() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-conflict").await;
    enable_registration(&harness, &realm).await;

    let resp = harness
        .post_json(
            &registrations_path(realm.name.as_ref(), "default"),
            serde_json::json!({"client_id": "my-app", "redirect_uris": ["http://localhost/cb"]}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Re-registering the same client_id is rejected.
    let resp = harness
        .post_json(
            &registrations_path(realm.name.as_ref(), "default"),
            serde_json::json!({"client_id": "my-app", "redirect_uris": ["http://localhost/cb"]}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn open_registration_validation_errors() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-invalid").await;
    enable_registration(&harness, &realm).await;

    // Malformed redirect URI → invalid_redirect_uri.
    let resp = harness
        .post_json(
            &registrations_path(realm.name.as_ref(), "default"),
            serde_json::json!({"redirect_uris": ["not a uri at all::"]}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_redirect_uri");

    // Body that is not a client representation → invalid_client_metadata.
    let resp = harness
        .post_json(&registrations_path(realm.name.as_ref(), "default"), serde_json::json!(["nope"]))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn open_registration_is_rate_limited() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-rate").await;
    enable_registration(&harness, &realm).await;

    // 50 registrations per hour per IP succeed; the 51st trips the limit.
    for _ in 0..50 {
        register_open_ok(&harness, realm.name.as_ref()).await;
    }
    let resp = harness
        .post_json(
            &registrations_path(realm.name.as_ref(), "default"),
            serde_json::json!({"name": "One Too Many"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "rate_limited");
}

// ---------------------------------------------------------------------------
// Token-gated registration (initial access tokens)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_gated_registration_requires_initial_access_token() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-gated").await;
    enable_registration(&harness, &realm).await;

    // No token at all.
    let resp = harness
        .post_json(
            &registrations_path(realm.name.as_ref(), "openid-connect"),
            serde_json::json!({"name": "App"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().contains_key(axum::http::header::WWW_AUTHENTICATE));

    // Garbage token.
    let resp = harness
        .post_json_auth(
            &registrations_path(realm.name.as_ref(), "openid-connect"),
            "not-a-real-token",
            serde_json::json!({"name": "App"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_gated_registration_roundtrip_and_count_exhaustion() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-token").await;
    enable_registration(&harness, &realm).await;

    // Mint a single-use initial access token via the admin API.
    let minted = mint_initial_access(&harness, realm.name.as_ref(), 3600, 1).await;
    let token_id = minted["id"].as_str().unwrap().to_string();
    let token = minted["token"].as_str().expect("raw token returned once").to_string();
    assert_eq!(minted["count"], 1);
    assert_eq!(minted["remaining_count"], 1);

    // First registration succeeds.
    let resp = harness
        .post_json_auth(
            &registrations_path(realm.name.as_ref(), "openid-connect"),
            &token,
            serde_json::json!({"name": "Token App", "redirect_uris": ["http://localhost/cb"]}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    assert!(json["registrationAccessToken"].as_str().is_some());

    // Second use is rejected (count exhausted).
    let resp = harness
        .post_json_auth(
            &registrations_path(realm.name.as_ref(), "openid-connect"),
            &token,
            serde_json::json!({"name": "Second App"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The admin list shows the token without raw material and with no uses
    // remaining.
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;
    let resp = harness.get_auth(&initial_access_path(realm.name.as_ref()), &admin_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let list = json_body(resp).await;
    let entry = list
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == token_id)
        .expect("minted token listed");
    assert!(entry.get("token").is_none());
    assert_eq!(entry["remaining_count"], 0);
}

#[tokio::test]
async fn revoked_initial_access_token_is_rejected() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-revoke").await;
    enable_registration(&harness, &realm).await;

    let minted = mint_initial_access(&harness, realm.name.as_ref(), 0, 0).await;
    let token_id = minted["id"].as_str().unwrap().to_string();
    let token = minted["token"].as_str().unwrap().to_string();

    let admin_token = harness.get_admin_token("master", "admin", "admin").await;
    let resp = harness
        .delete_auth(
            &format!("{}/{}", initial_access_path(realm.name.as_ref()), token_id),
            &admin_token,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = harness
        .post_json_auth(
            &registrations_path(realm.name.as_ref(), "openid-connect"),
            &token,
            serde_json::json!({"name": "App"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn initial_access_admin_endpoints_require_admin_auth() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-admin-auth").await;

    let resp = harness
        .post_json(&initial_access_path(realm.name.as_ref()), serde_json::json!({"count": 1}))
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = harness.get(&initial_access_path(realm.name.as_ref())).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Registration access token CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_access_token_crud_with_rotation() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-crud").await;
    enable_registration(&harness, &realm).await;

    let json = register_open_ok(&harness, realm.name.as_ref()).await;
    let client_id = json["client_id"].as_str().unwrap().to_string();
    let secret = json["secret"].as_str().unwrap().to_string();
    let token = json["registrationAccessToken"].as_str().unwrap().to_string();

    // Wrong / absent registration access tokens are rejected uniformly.
    let resp = harness
        .get_auth(&registration_client_path(realm.name.as_ref(), &client_id), "wrong-token")
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = harness.get(&registration_client_path(realm.name.as_ref(), &client_id)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // PUT renames the client; the secret is preserved across the update
    // (the body omits it) and the registration access token rotates.
    let resp = put_json_auth(
        &harness,
        &registration_client_path(realm.name.as_ref(), &client_id),
        serde_json::json!({"name": "Renamed App", "redirect_uris": ["http://localhost:8080/cb"]}),
        &token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["name"].as_str().unwrap(), "Renamed App");
    assert_eq!(json["secret"].as_str().unwrap(), secret);
    let new_token = json["registrationAccessToken"].as_str().unwrap().to_string();
    assert_ne!(new_token, token);

    // The old token is dead; the new one works.
    let resp = harness
        .get_auth(&registration_client_path(realm.name.as_ref(), &client_id), &token)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = harness
        .get_auth(&registration_client_path(realm.name.as_ref(), &client_id), &new_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // DELETE burns the client and the token.
    let resp = harness
        .delete_auth(&registration_client_path(realm.name.as_ref(), &client_id), &new_token)
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness
        .get_auth(&registration_client_path(realm.name.as_ref(), &client_id), &new_token)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// End-to-end: a registered client works at the token endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registered_client_can_use_client_credentials_grant() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-e2e").await;
    enable_registration(&harness, &realm).await;

    let json = register_open_ok(&harness, realm.name.as_ref()).await;
    let client_id = json["client_id"].as_str().unwrap();
    let secret = json["secret"].as_str().unwrap();

    let resp = harness
        .post_form(
            &format!("/realms/{}/protocol/openid-connect/token", realm.name),
            &[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", secret),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json["access_token"].as_str().is_some());
}

// ---------------------------------------------------------------------------
// 2026-09 review hardening: mapper fencing, disable containment, audit trail
// ---------------------------------------------------------------------------

/// Registration must not let an anonymous caller attach protocol mappers —
/// an `oidc-audience-mapper` would mint tokens naming any resource server in
/// the realm (no client-registration policy engine exists). Mappers are
/// silently dropped on create AND update; the admin API still accepts them.
#[tokio::test]
async fn registration_strips_caller_supplied_protocol_mappers() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-mappers").await;
    enable_registration(&harness, &realm).await;

    let mapper = serde_json::json!([{
        "id": "mapper-1",
        "name": "borrowed-audience",
        "mapper_type": "oidc-audience-mapper",
        "config": {"included.client.audience": "some-resource-server"}
    }]);
    let resp = harness
        .post_json(
            &registrations_path(realm.name.as_ref(), "default"),
            serde_json::json!({
                "client_id": "mapper-client",
                "redirect_uris": ["http://localhost:8080/cb"],
                "protocol_mappers": mapper,
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    let registration_token = json["registrationAccessToken"].as_str().unwrap().to_string();

    let client = harness
        .storage
        .get_client_by_client_id(
            &realm.id,
            &issuerd_core::ClientIdentifier::new("mapper-client").unwrap(),
        )
        .await
        .unwrap()
        .expect("registered client persisted");
    assert!(
        client.protocol_mappers.is_empty(),
        "caller-supplied mappers must be dropped on create"
    );

    // The update path strips them too.
    let resp = put_json_auth(
        &harness,
        &registration_client_path(realm.name.as_ref(), "mapper-client"),
        serde_json::json!({
            "client_id": "mapper-client",
            "redirect_uris": ["http://localhost:8080/cb"],
            "protocol_mappers": [{
                "id": "mapper-2",
                "name": "borrowed-audience-2",
                "mapper_type": "oidc-audience-mapper",
                "config": {"included.client.audience": "some-resource-server"}
            }],
        }),
        &registration_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let client = harness
        .storage
        .get_client_by_client_id(
            &realm.id,
            &issuerd_core::ClientIdentifier::new("mapper-client").unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        client.protocol_mappers.is_empty(),
        "caller-supplied mappers must be dropped on update"
    );
}

/// An admin's `enabled = false` is containment the registrant cannot undo:
/// the registration access token stops authenticating (uniform 401), and no
/// PUT body can flip enablement back.
#[tokio::test]
async fn disabled_registered_client_loses_registration_access() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-disable").await;
    enable_registration(&harness, &realm).await;

    let json = register_open_ok(&harness, realm.name.as_ref()).await;
    let client_id = json["client_id"].as_str().unwrap().to_string();
    let registration_token = json["registrationAccessToken"].as_str().unwrap().to_string();

    // Admin disables the client.
    let mut client = harness
        .storage
        .get_client_by_client_id(
            &realm.id,
            &issuerd_core::ClientIdentifier::new(&client_id).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    client.enabled = false;
    harness.storage.update_client(&realm.id, &client).await.unwrap();

    // GET / PUT / DELETE with the registration token are all rejected, and a
    // PUT with `"enabled": true` does not re-enable the client.
    let path = registration_client_path(realm.name.as_ref(), &client_id);
    let resp = harness.get_auth(&path, &registration_token).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = put_json_auth(
        &harness,
        &path,
        serde_json::json!({
            "client_id": client_id,
            "enabled": true,
            "redirect_uris": ["http://localhost:8080/cb"],
        }),
        &registration_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let req = axum::http::Request::builder()
        .method("DELETE")
        .uri(&path)
        .header("authorization", format!("Bearer {registration_token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    use tower::ServiceExt;
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let client = harness
        .storage
        .get_client_by_client_id(
            &realm.id,
            &issuerd_core::ClientIdentifier::new(&client_id).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!client.enabled, "registration PUT must never flip enablement");
}

/// Enablement is preserved across legitimate registration updates too: a PUT
/// with `"enabled": false` must not let the registrant disable their own
/// client either (only the admin API manages enablement).
#[tokio::test]
async fn registration_update_cannot_flip_enablement_either_way() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-enabled").await;
    enable_registration(&harness, &realm).await;

    let json = register_open_ok(&harness, realm.name.as_ref()).await;
    let client_id = json["client_id"].as_str().unwrap().to_string();
    let registration_token = json["registrationAccessToken"].as_str().unwrap().to_string();

    let resp = put_json_auth(
        &harness,
        &registration_client_path(realm.name.as_ref(), &client_id),
        serde_json::json!({
            "client_id": client_id,
            "enabled": false,
            "redirect_uris": ["http://localhost:8080/cb"],
        }),
        &registration_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let client = harness
        .storage
        .get_client_by_client_id(
            &realm.id,
            &issuerd_core::ClientIdentifier::new(&client_id).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(client.enabled, "registration PUT must not disable a client");
}

/// The registration lifecycle is audited: create/update/delete through the
/// (unauthenticated) open endpoint must leave an AdminEvent trail.
#[tokio::test]
async fn registration_lifecycle_writes_admin_events() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("dcr-audit").await;
    enable_registration(&harness, &realm).await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    // Create + update + delete via the open endpoint.
    let json = register_open_ok(&harness, realm.name.as_ref()).await;
    let client_id = json["client_id"].as_str().unwrap().to_string();
    let registration_token = json["registrationAccessToken"].as_str().unwrap().to_string();

    let resp = put_json_auth(
        &harness,
        &registration_client_path(realm.name.as_ref(), &client_id),
        serde_json::json!({
            "client_id": client_id,
            "name": "Renamed App",
            "redirect_uris": ["http://localhost:8080/cb"],
        }),
        &registration_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    // The registration token rotates on update (RFC 7592 §3).
    let rotated = json_body(resp).await["registrationAccessToken"].as_str().unwrap().to_string();

    let req = axum::http::Request::builder()
        .method("DELETE")
        .uri(registration_client_path(realm.name.as_ref(), &client_id))
        .header("authorization", format!("Bearer {rotated}"))
        .body(axum::body::Body::empty())
        .unwrap();
    use tower::ServiceExt;
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // CREATE + UPDATE + DELETE client events are all in the admin-event log.
    let resp = harness
        .get_auth(&format!("/admin/realms/{}/admin-events", realm.name), &admin_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let events = json_body(resp).await;
    let events = events.as_array().unwrap();
    for op in ["CREATE", "UPDATE", "DELETE"] {
        assert!(
            events
                .iter()
                .any(|e| e["operation_type"] == op && e["resource_type"] == "CLIENT"),
            "missing {op} client admin event: {events:?}"
        );
    }
}
