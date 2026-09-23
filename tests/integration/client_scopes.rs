// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Client scopes and protocol mappers integration tests (Issuerd-only).

//! Client scopes & protocol mappers integration tests
//! (Issuerd-only; the harness drives storage directly for setup and the
//! real HTTP surface for token/userinfo assertions).
//!
//! Covered: built-in scope seeding (realm + client), realm/client role claims
//! via the `roles` scope, group role mappings, `full_scope_allowed = false`
//! filtering through scope-mappings, custom scopes with user-attribute
//! mappers, assignment removal, service-account client-credentials tokens,
//! and byte-compat of the profile/email claim shapes from before client scopes.

use std::collections::HashMap;

use axum::http::StatusCode;
use base64::Engine;

use issuerd_core::{
    ClientId, ClientProtocol, ClientScope, ClientScopeId, GroupId, GroupName, GroupPath, MapperId,
    MapperType, ProtocolMapper, RealmId, RoleId, RoleName, Scope, ScopeMappings,
};

use crate::harness::TestHarness;

/// Decode the payload segment of a JWT without verifying the signature.
fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Resource owner password grant; asserts HTTP 200 and returns the token
/// response body.
async fn password_grant(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    password: &str,
    scope: &str,
) -> serde_json::Value {
    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/token"),
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
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// GET the userinfo endpoint with a bearer token; asserts HTTP 200.
async fn userinfo(harness: &TestHarness, realm: &str, access_token: &str) -> serde_json::Value {
    let resp = harness
        .get_auth(&format!("/realms/{realm}/protocol/openid-connect/userinfo"), access_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn realm_role(realm_id: &RealmId, name: &str) -> issuerd_core::Role {
    issuerd_core::Role {
        id: RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
        name: RoleName::new(name).unwrap(),
        description: None,
        realm_id: realm_id.clone(),
        client_role: false,
        client_id: None,
        composite: false,
        composites: Vec::new(),
        attributes: HashMap::new(),
    }
}

fn client_role(
    realm_id: &RealmId,
    client: &issuerd_core::Client,
    name: &str,
) -> issuerd_core::Role {
    issuerd_core::Role {
        id: RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
        name: RoleName::new(name).unwrap(),
        description: None,
        realm_id: realm_id.clone(),
        client_role: true,
        client_id: Some(client.id.clone()),
        composite: false,
        composites: Vec::new(),
        attributes: HashMap::new(),
    }
}

/// A custom client scope carrying a single user-attribute mapper that emits
/// the attribute as a claim into ID tokens and userinfo (not access tokens).
fn attribute_scope(realm_id: &RealmId, name: &str, attribute: &str, claim: &str) -> ClientScope {
    let mut config = HashMap::new();
    config.insert(issuerd_core::mapper_config::USER_ATTRIBUTE.to_string(), attribute.to_string());
    config.insert(issuerd_core::mapper_config::CLAIM_NAME.to_string(), claim.to_string());
    config.insert(issuerd_core::mapper_config::ACCESS_TOKEN_CLAIM.to_string(), "false".to_string());
    config.insert(issuerd_core::mapper_config::ID_TOKEN_CLAIM.to_string(), "true".to_string());
    config.insert(
        issuerd_core::mapper_config::USERINFO_TOKEN_CLAIM.to_string(),
        "true".to_string(),
    );
    ClientScope {
        id: ClientScopeId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm_id.clone(),
        name: name.to_string(),
        description: None,
        protocol: ClientProtocol::OpenIdConnect,
        attributes: HashMap::new(),
        protocol_mappers: vec![ProtocolMapper {
            id: MapperId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: format!("{name}-mapper"),
            mapper_type: MapperType::UserAttribute,
            config,
        }],
        scope_mappings: ScopeMappings::default(),
    }
}

/// Attach a scope to a client as an *optional* scope: assignment row plus the
/// client's `optional_scopes` string list (which the token endpoint validates
/// requested scopes against).
async fn assign_optional_scope(
    harness: &TestHarness,
    client: &mut issuerd_core::Client,
    scope: &ClientScope,
) {
    harness
        .storage
        .assign_client_scope(&client.realm_id, &client.id, &scope.id, false)
        .await
        .unwrap();
    let mut names = client.optional_scopes.to_vec();
    names.push(scope.name.clone());
    client.optional_scopes = Scope::from(names);
    harness.storage.update_client(&client.realm_id, client).await.unwrap();
}

#[tokio::test]
async fn realm_creation_seeds_builtin_client_scopes() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("cs-seed-realm").await;

    let scopes = harness
        .storage
        .list_client_scopes(&realm.id, &issuerd_core::Pagination { first: 0, max: 100 })
        .await
        .unwrap();
    let mut names: Vec<&str> = scopes.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "acr",
            "address",
            "email",
            "offline_access",
            "phone",
            "profile",
            "roles",
            "web-origins"
        ]
    );

    let defaults = harness.storage.list_realm_default_client_scopes(&realm.id).await.unwrap();
    let mut default_names = Vec::new();
    let mut optional_names = Vec::new();
    for (scope_id, is_default) in defaults {
        let scope = harness.storage.get_client_scope(&realm.id, &scope_id).await.unwrap().unwrap();
        if is_default {
            default_names.push(scope.name);
        } else {
            optional_names.push(scope.name);
        }
    }
    default_names.sort();
    optional_names.sort();
    assert_eq!(default_names, vec!["email", "profile", "roles"]);
    assert_eq!(optional_names, vec!["acr", "address", "offline_access", "phone", "web-origins"]);
}

#[tokio::test]
async fn client_creation_seeds_scope_assignments() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("cs-seed-client").await;
    // Harness client: default_scopes "openid profile", optional "email".
    let client = harness.create_client("cs-seed-client", false).await;

    let assignments = harness
        .storage
        .list_client_scope_assignments(&realm.id, &client.id)
        .await
        .unwrap();
    let mut defaults = Vec::new();
    let mut optionals = Vec::new();
    for (scope_id, is_default) in assignments {
        let scope = harness.storage.get_client_scope(&realm.id, &scope_id).await.unwrap().unwrap();
        if is_default {
            defaults.push(scope.name);
        } else {
            optionals.push(scope.name);
        }
    }
    defaults.sort();
    optionals.sort();
    // `profile` from the client's default list, `email` from the optional
    // list, and `roles` always as a default (keeps `realm_access` flowing).
    assert_eq!(defaults, vec!["profile", "roles"]);
    assert_eq!(optionals, vec!["email"]);
}

#[tokio::test]
async fn realm_role_flows_to_realm_access_claim() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("cs-realm-role").await;
    let client = harness.create_client("cs-realm-role", false).await;
    let user = harness.create_user("cs-realm-role", "alice", "password123").await;

    let role = realm_role(&realm.id, "admin");
    harness.storage.create_role(&realm.id, &role).await.unwrap();
    harness
        .storage
        .add_user_realm_role(&realm.id, &user.id, &role.id)
        .await
        .unwrap();

    let tokens = password_grant(
        &harness,
        "cs-realm-role",
        &client,
        "alice",
        "password123",
        "openid profile",
    )
    .await;
    let claims = jwt_claims(tokens["access_token"].as_str().unwrap());
    let roles = claims["realm_access"]["roles"].as_array().expect("realm_access.roles");
    assert!(roles.iter().any(|r| r == "admin"), "missing admin in {roles:?}");
}

#[tokio::test]
async fn client_role_flows_to_resource_access_claim() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("cs-client-role").await;
    let client = harness.create_client("cs-client-role", false).await;
    let user = harness.create_user("cs-client-role", "alice", "password123").await;

    let role = client_role(&realm.id, &client, "editor");
    harness.storage.create_role(&realm.id, &role).await.unwrap();
    harness
        .storage
        .add_user_client_role(&realm.id, &user.id, &role.id)
        .await
        .unwrap();

    let tokens = password_grant(
        &harness,
        "cs-client-role",
        &client,
        "alice",
        "password123",
        "openid profile",
    )
    .await;
    let claims = jwt_claims(tokens["access_token"].as_str().unwrap());
    let client_id = client.client_id.to_string();
    let roles = claims["resource_access"][&client_id]["roles"]
        .as_array()
        .expect("resource_access.{client}.roles");
    assert!(roles.iter().any(|r| r == "editor"), "missing editor in {roles:?}");
}

#[tokio::test]
async fn group_client_role_mapping_flows_to_token() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("cs-group-role").await;
    let client = harness.create_client("cs-group-role", false).await;
    let user = harness.create_user("cs-group-role", "alice", "password123").await;

    let role = client_role(&realm.id, &client, "editor");
    harness.storage.create_role(&realm.id, &role).await.unwrap();

    let mut client_roles: HashMap<ClientId, Vec<RoleName>> = HashMap::new();
    client_roles.insert(client.id.clone(), vec![RoleName::new("editor").unwrap()]);
    let group = issuerd_core::Group {
        id: GroupId::new(issuerd_core::utils::generate_id()).unwrap(),
        name: GroupName::new("devs").unwrap(),
        path: GroupPath::new("/devs").unwrap(),
        realm_id: realm.id.clone(),
        parent_id: None,
        sub_groups: Vec::new(),
        attributes: HashMap::new(),
        realm_roles: Vec::new(),
        client_roles,
    };
    harness.storage.create_group(&realm.id, &group).await.unwrap();
    harness.storage.add_user_group(&realm.id, &user.id, &group.id).await.unwrap();

    let tokens = password_grant(
        &harness,
        "cs-group-role",
        &client,
        "alice",
        "password123",
        "openid profile",
    )
    .await;
    let claims = jwt_claims(tokens["access_token"].as_str().unwrap());
    let client_id = client.client_id.to_string();
    let roles = claims["resource_access"][&client_id]["roles"]
        .as_array()
        .expect("resource_access.{client}.roles");
    assert!(roles.iter().any(|r| r == "editor"), "missing editor in {roles:?}");
}

#[tokio::test]
async fn full_scope_allowed_false_filters_token_roles() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("cs-scope-filter").await;
    let mut client = harness.create_client("cs-scope-filter", false).await;
    let user = harness.create_user("cs-scope-filter", "alice", "password123").await;

    let allowed = realm_role(&realm.id, "allowed-role");
    let other = realm_role(&realm.id, "other-role");
    harness.storage.create_role(&realm.id, &allowed).await.unwrap();
    harness.storage.create_role(&realm.id, &other).await.unwrap();
    harness
        .storage
        .add_user_realm_role(&realm.id, &user.id, &allowed.id)
        .await
        .unwrap();
    harness
        .storage
        .add_user_realm_role(&realm.id, &user.id, &other.id)
        .await
        .unwrap();

    client.full_scope_allowed = false;
    client.scope_mappings.realm_roles = vec![allowed.id.clone()];
    harness.storage.update_client(&realm.id, &client).await.unwrap();

    let tokens = password_grant(
        &harness,
        "cs-scope-filter",
        &client,
        "alice",
        "password123",
        "openid profile",
    )
    .await;
    let claims = jwt_claims(tokens["access_token"].as_str().unwrap());
    let roles = claims["realm_access"]["roles"].as_array().expect("realm_access.roles");
    assert!(roles.iter().any(|r| r == "allowed-role"), "missing allowed-role in {roles:?}");
    assert!(
        !roles.iter().any(|r| r == "other-role"),
        "other-role must be filtered out: {roles:?}"
    );
}

#[tokio::test]
async fn custom_scope_mapper_claim_follows_granted_scope() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("cs-custom-scope").await;
    let mut client = harness.create_client("cs-custom-scope", false).await;
    let mut user = harness.create_user("cs-custom-scope", "alice", "password123").await;
    user.attributes
        .insert("department".to_string(), vec!["engineering".to_string()]);
    harness.storage.update_user(&realm.id, &user).await.unwrap();

    let scope = attribute_scope(&realm.id, "department", "department", "dept");
    harness.storage.create_client_scope(&realm.id, &scope).await.unwrap();
    assign_optional_scope(&harness, &mut client, &scope).await;

    // Scope granted -> mapper claim in userinfo.
    let tokens = password_grant(
        &harness,
        "cs-custom-scope",
        &client,
        "alice",
        "password123",
        "openid department",
    )
    .await;
    let info =
        userinfo(&harness, "cs-custom-scope", tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(info["dept"], serde_json::json!("engineering"));
    // The claim is userinfo/ID-token only, not the access token.
    let claims = jwt_claims(tokens["access_token"].as_str().unwrap());
    assert!(claims.get("dept").is_none(), "dept must not leak into the access token");

    // Scope not granted -> no claim.
    let tokens =
        password_grant(&harness, "cs-custom-scope", &client, "alice", "password123", "openid")
            .await;
    let info =
        userinfo(&harness, "cs-custom-scope", tokens["access_token"].as_str().unwrap()).await;
    assert!(info.get("dept").is_none(), "dept without the scope granted: {info:?}");
}

#[tokio::test]
async fn unassigned_scope_is_rejected_by_scope_validation() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("cs-unassign").await;
    let mut client = harness.create_client("cs-unassign", false).await;
    harness.create_user("cs-unassign", "alice", "password123").await;

    let scope = attribute_scope(&realm.id, "department", "department", "dept");
    harness.storage.create_client_scope(&realm.id, &scope).await.unwrap();
    assign_optional_scope(&harness, &mut client, &scope).await;

    // Unassign: drop the assignment row and the name from the client's lists
    // (mirrors what the admin API does on DELETE optional-client-scopes).
    harness
        .storage
        .unassign_client_scope(&realm.id, &client.id, &scope.id)
        .await
        .unwrap();
    client.optional_scopes = Scope::from(
        client
            .optional_scopes
            .iter()
            .filter(|s| s.as_str() != "department")
            .cloned()
            .collect::<Vec<_>>(),
    );
    harness.storage.update_client(&realm.id, &client).await.unwrap();

    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            "/realms/cs-unassign/protocol/openid-connect/token",
            &[
                ("grant_type", "password"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("username", "alice"),
                ("password", "password123"),
                ("scope", "openid department"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], serde_json::json!("invalid_scope"));
}

#[tokio::test]
async fn service_account_backs_client_credentials_grant() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("cs-service-acct").await;
    let mut client = harness.create_client("cs-service-acct", false).await;
    client.service_accounts_enabled = true;
    harness.storage.update_client(&realm.id, &client).await.unwrap();

    // The dedicated service-account user (created lazily by the admin API in
    // production; seeded directly here).
    let sa_username = format!("service-account-{}", client.client_id);
    let sa_user = harness.create_user("cs-service-acct", &sa_username, "unused-password").await;
    let role = realm_role(&realm.id, "svc-role");
    harness.storage.create_role(&realm.id, &role).await.unwrap();
    harness
        .storage
        .add_user_realm_role(&realm.id, &sa_user.id, &role.id)
        .await
        .unwrap();

    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            "/realms/cs-service-acct/protocol/openid-connect/token",
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(claims["sub"], serde_json::json!(sa_user.id.to_string()));
    let roles = claims["realm_access"]["roles"].as_array().expect("realm_access.roles");
    assert!(roles.iter().any(|r| r == "svc-role"), "missing svc-role in {roles:?}");
}

#[tokio::test]
async fn client_credentials_without_service_account_keeps_legacy_shape() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("cs-cc-legacy").await;
    let client = harness.create_client("cs-cc-legacy", false).await;

    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            "/realms/cs-cc-legacy/protocol/openid-connect/token",
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let claims = jwt_claims(json["access_token"].as_str().unwrap());
    // Legacy synthetic shape: sub = client_id, no role claims.
    assert_eq!(claims["sub"], serde_json::json!(client.client_id.to_string()));
    assert!(claims.get("realm_access").is_none());
    assert!(claims.get("resource_access").is_none());
}

#[tokio::test]
async fn builtin_scopes_preserve_legacy_claim_shapes() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("cs-parity").await;
    let client = harness.create_client("cs-parity", false).await;
    let _user = harness.create_user("cs-parity", "alice", "password123").await;

    // Harness client: default "openid profile", optional "email".
    let tokens = password_grant(
        &harness,
        "cs-parity",
        &client,
        "alice",
        "password123",
        "openid profile email",
    )
    .await;
    let access = jwt_claims(tokens["access_token"].as_str().unwrap());
    let info = userinfo(&harness, "cs-parity", tokens["access_token"].as_str().unwrap()).await;

    // Userinfo carries the profile/email claims (pre-client-scopes behavior).
    assert_eq!(info["preferred_username"], serde_json::json!("alice"));
    assert_eq!(info["name"], serde_json::json!("Test User"));
    assert_eq!(info["given_name"], serde_json::json!("Test"));
    assert_eq!(info["family_name"], serde_json::json!("User"));
    assert_eq!(info["email"], serde_json::json!("alice@example.com"));
    assert_eq!(info["email_verified"], serde_json::json!(true));

    // Keycloak parity: preferred_username is the one profile claim that also
    // targets the access token (access-token consumers can show the username).
    assert_eq!(access["preferred_username"], serde_json::json!("alice"));
    // The other profile/email claims stay out of the access token (they were
    // never there before client scopes were introduced either).
    for claim in ["name", "given_name", "family_name", "email"] {
        assert!(access.get(claim).is_none(), "{claim} must not be in the access token");
    }
}

// ---------------------------------------------------------------------------
// Admin API surface (client-scope endpoints through the real HTTP stack)
// ---------------------------------------------------------------------------

/// PUT a JSON body with a bearer token (the harness only ships POST/DELETE).
async fn put_json_auth(
    harness: &TestHarness,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(path)
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    tower::ServiceExt::oneshot(harness.app.clone(), harness.add_connect_info(req))
        .await
        .unwrap()
}

/// DELETE with a JSON body (role-mapping removals take `RoleRepresentation[]`).
async fn delete_json_auth(
    harness: &TestHarness,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    let req = axum::http::Request::builder()
        .method("DELETE")
        .uri(path)
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    tower::ServiceExt::oneshot(harness.app.clone(), harness.add_connect_info(req))
        .await
        .unwrap()
}

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn admin_client_scope_and_assignment_end_to_end() {
    let harness = TestHarness::new().await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let realm = harness.create_realm("cs-admin-scope").await;
    let client = harness.create_client("cs-admin-scope", false).await;
    let mut user = harness.create_user("cs-admin-scope", "alice", "password123").await;
    user.attributes
        .insert("department".to_string(), vec!["engineering".to_string()]);
    harness.storage.update_user(&realm.id, &user).await.unwrap();

    // Create a scope with one user-attribute mapper.
    let resp = harness
        .post_json_auth(
            "/admin/realms/cs-admin-scope/client-scopes",
            &admin,
            serde_json::json!({
                "name": "department",
                "description": "Department claim",
                "protocol": "openid-connect",
                "protocol_mappers": [{
                    "name": "dept",
                    "protocol": "openid-connect",
                    "protocol_mapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "user.attribute": "department",
                        "claim.name": "dept",
                        "access.token.claim": "false",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "true"
                    }
                }]
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = json_body(resp).await;
    let scope_id = created["id"].as_str().unwrap().to_string();
    assert_eq!(
        created["protocol_mappers"][0]["protocol_mapper"],
        "oidc-usermodel-attribute-mapper"
    );

    // List omits mappers; single GET includes them.
    let list =
        json_body(harness.get_auth("/admin/realms/cs-admin-scope/client-scopes", &admin).await)
            .await;
    let listed = list.as_array().unwrap().iter().find(|s| s["name"] == "department").unwrap();
    assert!(listed.get("protocol_mappers").is_none() || listed["protocol_mappers"].is_null());

    // Duplicate name -> 409.
    let dup = harness
        .post_json_auth(
            "/admin/realms/cs-admin-scope/client-scopes",
            &admin,
            serde_json::json!({ "name": "department" }),
        )
        .await;
    assert_eq!(dup.status(), StatusCode::CONFLICT);

    // Assign as optional: assignment row + the client's string list sync.
    let resp = put_json_auth(
        &harness,
        &format!(
            "/admin/realms/cs-admin-scope/clients/{}/optional-client-scopes/{}",
            client.id, scope_id
        ),
        &admin,
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let client_json = json_body(
        harness
            .get_auth(&format!("/admin/realms/cs-admin-scope/clients/{}", client.id), &admin)
            .await,
    )
    .await;
    assert!(client_json["optional_scopes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "department"));

    // The scope is now requestable and drives userinfo claims.
    let tokens = password_grant(
        &harness,
        "cs-admin-scope",
        &client,
        "alice",
        "password123",
        "openid department",
    )
    .await;
    let info = userinfo(&harness, "cs-admin-scope", tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(info["dept"], serde_json::json!("engineering"));

    // Unassign -> removed from the optional list -> requesting it fails.
    let resp = harness
        .delete_auth(
            &format!(
                "/admin/realms/cs-admin-scope/clients/{}/optional-client-scopes/{}",
                client.id, scope_id
            ),
            &admin,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let client_json = json_body(
        harness
            .get_auth(&format!("/admin/realms/cs-admin-scope/clients/{}", client.id), &admin)
            .await,
    )
    .await;
    assert!(!client_json["optional_scopes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "department"));

    // Delete the scope resource.
    let resp = harness
        .delete_auth(&format!("/admin/realms/cs-admin-scope/client-scopes/{scope_id}"), &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn admin_client_roles_and_mappings_end_to_end() {
    let harness = TestHarness::new().await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let _realm = harness.create_realm("cs-admin-roles").await;
    let client = harness.create_client("cs-admin-roles", false).await;
    let user = harness.create_user("cs-admin-roles", "alice", "password123").await;

    // Create a client role.
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/cs-admin-roles/clients/{}/roles", client.id),
            &admin,
            serde_json::json!({ "name": "editor", "description": "Can edit" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // List shows it as a client role owned by this client.
    let roles = json_body(
        harness
            .get_auth(&format!("/admin/realms/cs-admin-roles/clients/{}/roles", client.id), &admin)
            .await,
    )
    .await;
    let editor = roles.as_array().unwrap().iter().find(|r| r["name"] == "editor").unwrap();
    assert_eq!(editor["client_role"], serde_json::json!(true));
    assert_eq!(editor["container_id"], serde_json::json!(client.id.to_string()));
    let editor_id = editor["id"].as_str().unwrap().to_string();

    // Map it to the user via the client role-mappings endpoint (internal UUID).
    let resp = harness
        .post_json_auth(
            &format!(
                "/admin/realms/cs-admin-roles/users/{}/role-mappings/clients/{}",
                user.id, client.id
            ),
            &admin,
            serde_json::json!([{ "id": editor_id, "name": "editor" }]),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The combined mappings view shows the assignment under the client_id key.
    let mappings = json_body(
        harness
            .get_auth(
                &format!("/admin/realms/cs-admin-roles/users/{}/role-mappings", user.id),
                &admin,
            )
            .await,
    )
    .await;
    let cid = client.client_id.to_string();
    let mapped = &mappings["client_mappings"][&cid]["mappings"];
    assert!(mapped.as_array().unwrap().iter().any(|r| r["name"] == "editor"), "{mappings:?}");

    // Composite (effective) view agrees.
    let composite = json_body(
        harness
            .get_auth(
                &format!(
                    "/admin/realms/cs-admin-roles/users/{}/role-mappings/clients/{}/composite",
                    user.id, client.id
                ),
                &admin,
            )
            .await,
    )
    .await;
    assert!(composite.as_array().unwrap().iter().any(|r| r["name"] == "editor"));

    // And it lands in the token.
    let tokens = password_grant(
        &harness,
        "cs-admin-roles",
        &client,
        "alice",
        "password123",
        "openid profile",
    )
    .await;
    let claims = jwt_claims(tokens["access_token"].as_str().unwrap());
    let token_roles = claims["resource_access"][&cid]["roles"].as_array().unwrap();
    assert!(token_roles.iter().any(|r| r == "editor"));

    // Remove the mapping -> gone from the token.
    let resp = delete_json_auth(
        &harness,
        &format!(
            "/admin/realms/cs-admin-roles/users/{}/role-mappings/clients/{}",
            user.id, client.id
        ),
        &admin,
        serde_json::json!([{ "id": editor_id, "name": "editor" }]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let tokens = password_grant(
        &harness,
        "cs-admin-roles",
        &client,
        "alice",
        "password123",
        "openid profile",
    )
    .await;
    let claims = jwt_claims(tokens["access_token"].as_str().unwrap());
    let token_roles =
        claims["resource_access"][&cid]["roles"].as_array().cloned().unwrap_or_default();
    assert!(!token_roles.iter().any(|r| r == "editor"));
}

#[tokio::test]
async fn admin_service_account_user_lifecycle() {
    let harness = TestHarness::new().await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let _realm = harness.create_realm("cs-admin-sa").await;
    let client = harness.create_client("cs-admin-sa", false).await;

    // Disabled -> 400.
    let resp = harness
        .get_auth(
            &format!("/admin/realms/cs-admin-sa/clients/{}/service-account-user", client.id),
            &admin,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Flip the flag via a representation round-trip; update_client must
    // provision the service-account user.
    let mut rep = json_body(
        harness
            .get_auth(&format!("/admin/realms/cs-admin-sa/clients/{}", client.id), &admin)
            .await,
    )
    .await;
    rep["service_accounts_enabled"] = serde_json::json!(true);
    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/cs-admin-sa/clients/{}", client.id),
        &admin,
        rep,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let sa = json_body(
        harness
            .get_auth(
                &format!("/admin/realms/cs-admin-sa/clients/{}/service-account-user", client.id),
                &admin,
            )
            .await,
    )
    .await;
    let expected = format!("service-account-{}", client.client_id);
    assert_eq!(sa["username"], serde_json::json!(expected));
    let sa_id = sa["id"].as_str().unwrap().to_string();

    // Grant the service account a realm role through the admin API.
    let resp = harness
        .post_json_auth(
            "/admin/realms/cs-admin-sa/roles",
            &admin,
            serde_json::json!({ "name": "svc-role" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let roles = json_body(harness.get_auth("/admin/realms/cs-admin-sa/roles", &admin).await).await;
    let role = roles.as_array().unwrap().iter().find(|r| r["name"] == "svc-role").unwrap();
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/cs-admin-sa/users/{sa_id}/role-mappings/realm"),
            &admin,
            serde_json::json!([{ "id": role["id"], "name": "svc-role" }]),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Client-credentials grant: sub is the service-account user, roles flow.
    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            "/realms/cs-admin-sa/protocol/openid-connect/token",
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(claims["sub"], serde_json::json!(sa_id));
    let roles = claims["realm_access"]["roles"].as_array().unwrap();
    assert!(roles.iter().any(|r| r == "svc-role"));
}

#[tokio::test]
async fn admin_mapper_types_enum_and_realm_defaults() {
    let harness = TestHarness::new().await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let _realm = harness.create_realm("cs-admin-enum").await;

    // Mapper types enum endpoint: 9 Keycloak wire ids, each with a description.
    let types = json_body(harness.get_auth("/admin/enums/mapper-types", &admin).await).await;
    let types = types.as_array().unwrap();
    assert_eq!(types.len(), 9);
    assert!(types.iter().any(|t| t["id"] == "oidc-usermodel-attribute-mapper"));
    assert!(types.iter().all(|t| t["description"].is_string()));

    // serverinfo carries the same list.
    let info = json_body(harness.get_auth("/admin/serverinfo", &admin).await).await;
    assert_eq!(info["mapper_types"].as_array().unwrap().len(), 9);

    // Realm default scope tables reflect the built-in scope seeding.
    let defaults = json_body(
        harness
            .get_auth("/admin/realms/cs-admin-enum/default-default-client-scopes", &admin)
            .await,
    )
    .await;
    let mut names: Vec<&str> =
        defaults.as_array().unwrap().iter().filter_map(|s| s["name"].as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, vec!["email", "profile", "roles"]);
    let optionals = json_body(
        harness
            .get_auth("/admin/realms/cs-admin-enum/default-optional-client-scopes", &admin)
            .await,
    )
    .await;
    assert_eq!(optionals.as_array().unwrap().len(), 5);
}
