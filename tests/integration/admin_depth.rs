// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Admin API depth integration tests (Issuerd-only, in-process).
//!
//! Covers the plan's remaining acceptance surface end to end through the HTTP
//! stack: editable authentication flows (guardrails + runtime binding), user
//! credentials CRUD, execute-actions-email roundtrip, impersonation, groups
//! hierarchy/members, role composites, events config/gating/clear, key
//! rotation & disable (incl. cluster propagation on PostgreSQL), realm
//! `not_before`, and partial import/export.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use crate::harness::TestHarness;

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn body_string(resp: axum::response::Response) -> String {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

fn location_header(resp: &axum::response::Response) -> String {
    resp.headers().get("location").unwrap().to_str().unwrap().to_string()
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

/// DELETE with a JSON body (role-composite removal) and a bearer token.
async fn delete_json_auth(
    harness: &TestHarness,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    let req = Request::builder()
        .method("DELETE")
        .uri(path)
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

/// Decode a JWT payload without verifying the signature (test inspection).
fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Decode a JWT header (for `kid` assertions).
fn jwt_header(token: &str) -> serde_json::Value {
    let header = token.split('.').next().expect("jwt header segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Resource-owner password grant (raw response; status varies).
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

/// Start an authorization code flow and return the browser flow id.
async fn start_auth_flow(harness: &TestHarness, realm: &str, client_id: &str) -> String {
    let auth_path = format!(
        "/realms/{realm}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz"
    );
    let resp = harness.get(&auth_path).await;
    if resp.status() != StatusCode::SEE_OTHER {
        let status = resp.status();
        let body = body_string(resp).await;
        panic!("authorize did not redirect: {status} — {body}");
    }
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id")
}

/// POST the JSON login form for a browser flow execution (raw response).
async fn submit_login(
    harness: &TestHarness,
    realm: &str,
    execution_id: &str,
    username: &str,
    password: &str,
) -> axum::response::Response {
    harness
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            serde_json::json!({
                "execution_id": execution_id,
                "username": username,
                "password": password,
            }),
            &TestHarness::flow_cookie(execution_id),
        )
        .await
}

/// GET the realm representation document (for round-trip PUTs).
async fn get_realm_doc(harness: &TestHarness, realm: &str, token: &str) -> serde_json::Value {
    let resp = harness.get_auth(&format!("/admin/realms/{realm}"), token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

/// Round-trip a realm document with one field changed (PUT resets omitted
/// fields to defaults, so the full GET document must be sent back).
async fn put_realm_field(
    harness: &TestHarness,
    realm: &str,
    token: &str,
    field: &str,
    value: serde_json::Value,
) {
    let mut doc = get_realm_doc(harness, realm, token).await;
    doc[field] = value;
    let resp = put_json_auth(harness, &format!("/admin/realms/{realm}"), token, doc).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "realm PUT failed");
}

/// Create a realm role via the admin API.
async fn create_realm_role(harness: &TestHarness, realm: &str, token: &str, name: &str) {
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/{realm}/roles"),
            token,
            serde_json::json!({ "name": name }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "create role {name}");
}

/// Look up a role's representation by name via the admin API.
async fn get_role(
    harness: &TestHarness,
    realm: &str,
    token: &str,
    name: &str,
) -> serde_json::Value {
    let resp = harness.get_auth(&format!("/admin/realms/{realm}/roles/{name}"), token).await;
    assert_eq!(resp.status(), StatusCode::OK, "get role {name}");
    body_json(resp).await
}

// ---------------------------------------------------------------------------
// Recording email sender (same pattern as user_self_service.rs)
// ---------------------------------------------------------------------------

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
async fn harness_with_recorder() -> (TestHarness, Arc<RecordingSender>) {
    use issuerd_server::{config::ServerConfig, state::ServerState};
    let config = ServerConfig::default();
    let mut state = ServerState::from_config(&config).await.unwrap();
    let recorder = Arc::new(RecordingSender::default());
    state.email_sender = recorder.clone();
    let harness = TestHarness::with_state(Arc::new(state));
    (harness, recorder)
}

// ---------------------------------------------------------------------------
// Flows: validation, built-in guardrails, runtime binding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flow_create_rejects_invalid_flows() {
    let harness = TestHarness::new().await;
    harness.create_realm("flow-invalid").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // Unknown authenticator id.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-invalid/authentication/flows",
            &admin,
            serde_json::json!({
                "alias": "bad-auth",
                "stages": [{
                    "id": "s1",
                    "requirement": "required",
                    "authenticator": "nope",
                    "priority": 1,
                }],
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(body.contains("unknown authenticator"), "body: {body}");

    // Unknown sub-flow alias.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-invalid/authentication/flows",
            &admin,
            serde_json::json!({
                "alias": "bad-sub",
                "stages": [{
                    "id": "s1",
                    "requirement": "required",
                    "authenticator": "child",
                    "sub_flow_alias": "child",
                    "priority": 1,
                }],
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(body.contains("unknown sub-flow alias"), "body: {body}");

    // An empty top-level flow is allowed (Keycloak addFlow parity): it is the
    // intermediate state before executions are added.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-invalid/authentication/flows",
            &admin,
            serde_json::json!({ "alias": "empty-flow" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // A top-level flow whose stages are all disabled can never succeed.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-invalid/authentication/flows",
            &admin,
            serde_json::json!({
                "alias": "all-disabled",
                "stages": [{
                    "id": "s1",
                    "requirement": "disabled",
                    "authenticator": "auth-cookie",
                    "priority": 1,
                }],
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(body.contains("no enabled stages"), "body: {body}");

    // Only the empty flow was persisted.
    let resp = harness
        .get_auth("/admin/realms/flow-invalid/authentication/flows", &admin)
        .await;
    let flows = body_json(resp).await;
    let aliases: Vec<&str> =
        flows.as_array().unwrap().iter().filter_map(|f| f["alias"].as_str()).collect();
    assert!(!aliases.contains(&"bad-auth"));
    assert!(!aliases.contains(&"bad-sub"));
    assert!(!aliases.contains(&"all-disabled"));
    assert!(aliases.contains(&"empty-flow"));
    // The seeded built-ins are there.
    assert!(aliases.contains(&"browser"));
    assert!(aliases.contains(&"registration"));
}

#[tokio::test]
async fn builtin_flow_is_read_only_but_its_copy_is_editable() {
    let harness = TestHarness::new().await;
    harness.create_realm("flow-builtin").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // Built-in `browser` rejects updates and deletion.
    let resp = put_json_auth(
        &harness,
        "/admin/realms/flow-builtin/authentication/flows/browser",
        &admin,
        serde_json::json!({ "alias": "browser" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("read-only"));

    let resp = harness
        .delete_auth("/admin/realms/flow-builtin/authentication/flows/browser", &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("read-only"));

    // Copy it — the copy is mutable.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-builtin/authentication/flows/browser/copy",
            &admin,
            serde_json::json!({ "newName": "browser-copy" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let copy = body_json(resp).await;
    assert_eq!(copy["alias"], "browser-copy");
    assert_eq!(copy["built_in"], false);
    assert_eq!(
        copy["stages"].as_array().unwrap().len(),
        7,
        "copy carries the browser flow's stages"
    );

    let resp = put_json_auth(
        &harness,
        "/admin/realms/flow-builtin/authentication/flows/browser-copy",
        &admin,
        serde_json::json!({ "alias": "browser-copy", "provider_id": "basic-flow" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = harness
        .delete_auth("/admin/realms/flow-builtin/authentication/flows/browser-copy", &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn flow_requirement_change_via_binding_drives_runtime_login() {
    let harness = TestHarness::new().await;
    harness.create_realm("flow-bind").await;
    let client = harness.create_client("flow-bind", false).await;
    harness.create_user("flow-bind", "olga", "Password123!").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // Baseline: the default browser flow logs the user in.
    let exec = start_auth_flow(&harness, "flow-bind", client.client_id.as_ref()).await;
    let resp = submit_login(&harness, "flow-bind", &exec, "olga", "Password123!").await;
    assert_eq!(resp.status(), StatusCode::OK, "baseline login must succeed");

    // Copy `browser` and bind the realm to the UNMODIFIED copy first: the
    // stored flow must drive the runtime exactly like the code default.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-bind/authentication/flows/browser/copy",
            &admin,
            serde_json::json!({ "newName": "no-password-browser" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let copy = body_json(resp).await;
    put_realm_field(
        &harness,
        "flow-bind",
        &admin,
        "browserFlow",
        serde_json::json!("no-password-browser"),
    )
    .await;
    let exec = start_auth_flow(&harness, "flow-bind", client.client_id.as_ref()).await;
    let resp = submit_login(&harness, "flow-bind", &exec, "olga", "Password123!").await;
    if resp.status() != StatusCode::OK {
        let status = resp.status();
        let body = body_string(resp).await;
        panic!("bound copy login failed: {status} — {body}");
    }

    // Disable the copy's username-password stage.
    let upw_stage = copy["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["authenticator"] == "auth-username-password")
        .expect("username-password stage in copy")
        .clone();
    let resp = put_json_auth(
        &harness,
        "/admin/realms/flow-bind/authentication/flows/no-password-browser/executions",
        &admin,
        serde_json::json!({ "id": upw_stage["id"], "requirement": "disabled" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The requirement change takes effect at runtime: with no stage left that
    // can challenge the user, the authorize request itself fails instead of
    // rendering the login form.
    let auth_path = format!(
        "/realms/flow-bind/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        client.client_id
    );
    let resp = harness.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "access_denied");

    // Restore the default binding — login works again.
    put_realm_field(&harness, "flow-bind", &admin, "browserFlow", serde_json::Value::Null).await;
    let exec = start_auth_flow(&harness, "flow-bind", client.client_id.as_ref()).await;
    let resp = submit_login(&harness, "flow-bind", &exec, "olga", "Password123!").await;
    assert_eq!(resp.status(), StatusCode::OK, "unbound realm falls back to the default flow");
}

#[tokio::test]
async fn flow_delete_guards_bound_and_referenced_flows() {
    let harness = TestHarness::new().await;
    harness.create_realm("flow-guards").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // A flow referenced by the realm's `browser_flow` binding cannot be deleted.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-guards/authentication/flows",
            &admin,
            serde_json::json!({
                "alias": "custom-bound",
                "stages": [{
                    "id": "s1",
                    "requirement": "required",
                    "authenticator": "auth-cookie",
                    "priority": 1,
                }],
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    put_realm_field(
        &harness,
        "flow-guards",
        &admin,
        "browserFlow",
        serde_json::json!("custom-bound"),
    )
    .await;
    let resp = harness
        .delete_auth("/admin/realms/flow-guards/authentication/flows/custom-bound", &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("browser_flow"));

    // Unbind — deletion now succeeds.
    put_realm_field(&harness, "flow-guards", &admin, "browserFlow", serde_json::Value::Null).await;
    let resp = harness
        .delete_auth("/admin/realms/flow-guards/authentication/flows/custom-bound", &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // A flow matching a DEFAULT binding (`direct grant`) is guarded even with
    // no explicit binding on the realm.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-guards/authentication/flows",
            &admin,
            serde_json::json!({
                "alias": "direct grant",
                "stages": [{
                    "id": "s1",
                    "requirement": "required",
                    "authenticator": "auth-cookie",
                    "priority": 1,
                }],
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = harness
        .delete_auth("/admin/realms/flow-guards/authentication/flows/direct%20grant", &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("direct_grant_flow"));

    // A flow referenced as a sub-flow cannot be deleted.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-guards/authentication/flows",
            &admin,
            serde_json::json!({ "alias": "child-flow", "top_level": false }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-guards/authentication/flows",
            &admin,
            serde_json::json!({
                "alias": "parent-flow",
                "stages": [{
                    "id": "s1",
                    "requirement": "required",
                    "authenticator": "child-flow",
                    "sub_flow_alias": "child-flow",
                    "priority": 1,
                }],
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = harness
        .delete_auth("/admin/realms/flow-guards/authentication/flows/child-flow", &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("references it as a sub-flow"));
}

#[tokio::test]
async fn flow_execution_and_authenticator_config_crud() {
    let harness = TestHarness::new().await;
    harness.create_realm("flow-exec").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // Work on a copy so the built-in guard does not interfere.
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-exec/authentication/flows/browser/copy",
            &admin,
            serde_json::json!({ "newName": "editable" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Add an execution (appended at max priority + 1, default `required`).
    let resp = harness
        .post_json_auth(
            "/admin/realms/flow-exec/authentication/flows/editable/executions/execution",
            &admin,
            serde_json::json!({ "provider": "auth-otp-form" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let stage = body_json(resp).await;
    let stage_id = stage["id"].as_str().unwrap().to_string();
    assert_eq!(stage["authenticator"], "auth-otp-form");
    assert_eq!(stage["requirement"], "required");
    assert_eq!(stage["priority"], 8, "appended after the 7 browser stages");
    assert_eq!(stage["has_config"], false, "no config attached yet");

    // The execution is addressable across flows by id.
    let resp = harness
        .get_auth(&format!("/admin/realms/flow-exec/authentication/executions/{stage_id}"), &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let exec = body_json(resp).await;
    assert_eq!(exec["flow_alias"], "editable");

    // Requirement change.
    let resp = put_json_auth(
        &harness,
        "/admin/realms/flow-exec/authentication/flows/editable/executions",
        &admin,
        serde_json::json!({ "id": stage_id, "requirement": "alternative", "priority": 9 }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness
        .get_auth(&format!("/admin/realms/flow-exec/authentication/executions/{stage_id}"), &admin)
        .await;
    let exec = body_json(resp).await;
    assert_eq!(exec["requirement"], "alternative");
    assert_eq!(exec["priority"], 9);

    // Authenticator config CRUD on the execution.
    let resp = harness
        .get_auth(
            &format!("/admin/realms/flow-exec/authentication/executions/{stage_id}/config"),
            &admin,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "no config yet");

    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/flow-exec/authentication/executions/{stage_id}/config"),
            &admin,
            serde_json::json!({ "alias": "otp-cfg", "config": { "maxAge": "3600" } }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // A stage carries at most one config.
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/flow-exec/authentication/executions/{stage_id}/config"),
            &admin,
            serde_json::json!({ "alias": "second", "config": {} }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = harness
        .get_auth(
            &format!("/admin/realms/flow-exec/authentication/executions/{stage_id}/config"),
            &admin,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cfg = body_json(resp).await;
    assert_eq!(cfg["alias"], "otp-cfg");
    assert_eq!(cfg["config"]["maxAge"], "3600");

    // The stage representation advertises the attached config, so clients can
    // skip the (404-answering) config probe for stages that have none.
    let resp = harness
        .get_auth(&format!("/admin/realms/flow-exec/authentication/executions/{stage_id}"), &admin)
        .await;
    assert_eq!(body_json(resp).await["has_config"], true);

    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/flow-exec/authentication/executions/{stage_id}/config"),
        &admin,
        serde_json::json!({ "alias": "otp-cfg", "config": { "maxAge": "60" } }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness
        .get_auth(
            &format!("/admin/realms/flow-exec/authentication/executions/{stage_id}/config"),
            &admin,
        )
        .await;
    assert_eq!(body_json(resp).await["config"]["maxAge"], "60");

    let resp = harness
        .delete_auth(
            &format!("/admin/realms/flow-exec/authentication/executions/{stage_id}/config"),
            &admin,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = harness
        .get_auth(&format!("/admin/realms/flow-exec/authentication/executions/{stage_id}"), &admin)
        .await;
    assert_eq!(body_json(resp).await["has_config"], false, "config deleted");

    // Delete the execution itself; it is gone.
    let resp = harness
        .delete_auth(
            &format!("/admin/realms/flow-exec/authentication/executions/{stage_id}"),
            &admin,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness
        .get_auth(&format!("/admin/realms/flow-exec/authentication/executions/{stage_id}"), &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// User credentials CRUD
// ---------------------------------------------------------------------------

/// Add a test-only TOTP credential at the given priority.
async fn add_totp_credential(
    harness: &TestHarness,
    realm: &str,
    user: &issuerd_core::User,
    priority: i32,
) -> issuerd_core::Credential {
    let realm_id = issuerd_core::RealmId::new(realm).unwrap();
    let cred = issuerd_core::Credential {
        id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: issuerd_core::CredentialType::Totp,
        user_label: None,
        created_date: chrono::Utc::now(),
        secret_data: b"JBSWY3DPEHPK3PXP".to_vec(),
        credential_data: serde_json::json!({"algorithm": "HmacSHA1", "digits": 6, "period": 30}),
        priority,
    };
    harness.storage.create_credential(&realm_id, &user.id, &cred).await.unwrap();
    cred
}

#[tokio::test]
async fn credentials_crud_redaction_and_last_credential_guard() {
    let harness = TestHarness::new().await;
    harness.create_realm("cred-crud").await;
    let user = harness.create_user("cred-crud", "pavel", "Password123!").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let base = format!("/admin/realms/cred-crud/users/{}/credentials", user.id.0);

    // List: one password credential, fully redacted.
    let resp = harness.get_auth(&base, &admin).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let raw = String::from_utf8_lossy(&body);
    assert!(!raw.contains("$argon2id$"), "secret material must never leave the API: {raw}");
    let creds: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let creds = creds.as_array().unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["type"], "password");
    assert_eq!(creds[0]["user_label"], "Password");
    assert!(creds[0]["secret_data"].is_null());
    assert!(creds[0]["value"].is_null());
    let cred_id = creds[0]["id"].as_str().unwrap().to_string();

    // Label roundtrip.
    let resp = put_json_auth(
        &harness,
        &format!("{base}/{cred_id}"),
        &admin,
        serde_json::json!({ "userLabel": "Work laptop" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth(&base, &admin).await;
    let creds = body_json(resp).await;
    assert_eq!(creds[0]["user_label"], "Work laptop");
    let resp = put_json_auth(
        &harness,
        &format!("{base}/{cred_id}"),
        &admin,
        serde_json::json!({ "userLabel": null }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth(&base, &admin).await;
    assert!(body_json(resp).await[0]["user_label"].is_null());

    // The only credential cannot be deleted.
    let resp = harness.delete_auth(&format!("{base}/{cred_id}"), &admin).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("last credential"));

    // With a second credential, deletion works — until one remains.
    let totp = add_totp_credential(&harness, "cred-crud", &user, 2).await;
    let resp = harness.delete_auth(&format!("{base}/{cred_id}"), &admin).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth(&base, &admin).await;
    let creds = body_json(resp).await;
    assert_eq!(creds.as_array().unwrap().len(), 1);
    assert_eq!(creds[0]["type"], "totp");
    let resp = harness.delete_auth(&format!("{base}/{}", totp.id.0), &admin).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("last credential"));

    // Unknown credential id 404s even when it would be the last one.
    let resp = harness.delete_auth(&format!("{base}/no-such-cred"), &admin).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn credentials_move_after_reorders_priorities() {
    let harness = TestHarness::new().await;
    harness.create_realm("cred-move").await;
    let user = harness.create_user("cred-move", "quinn", "Password123!").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let base = format!("/admin/realms/cred-move/users/{}/credentials", user.id.0);

    // A = password (priority 1 from the harness), B/C = TOTP at 2 and 3.
    let cred_b = add_totp_credential(&harness, "cred-move", &user, 2).await;
    let cred_c = add_totp_credential(&harness, "cred-move", &user, 3).await;
    let resp = harness.get_auth(&base, &admin).await;
    let creds = body_json(resp).await;
    let creds = creds.as_array().unwrap();
    assert_eq!(creds.len(), 3);
    let cred_a = creds[0]["id"].as_str().unwrap().to_string();
    assert_eq!(creds[0]["type"], "password");
    assert_eq!(creds[1]["id"], cred_b.id.0);
    assert_eq!(creds[2]["id"], cred_c.id.0);

    // Move A after C: order becomes B(1), C(2), A(3).
    let resp = put_json_auth(
        &harness,
        &format!("{base}/{cred_a}/moveAfter/{}", cred_c.id.0),
        &admin,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth(&base, &admin).await;
    let creds = body_json(resp).await;
    let creds = creds.as_array().unwrap();
    assert_eq!(creds[0]["id"], cred_b.id.0);
    assert_eq!(creds[1]["id"], cred_c.id.0);
    assert_eq!(creds[2]["id"], cred_a);
    let priorities: Vec<i64> = creds.iter().map(|c| c["priority"].as_i64().unwrap()).collect();
    assert_eq!(priorities, vec![1, 2, 3], "moveAfter renumbers 1..=n");

    // Moving a credential after itself is rejected.
    let resp = put_json_auth(
        &harness,
        &format!("{base}/{cred_a}/moveAfter/{cred_a}"),
        &admin,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Execute-actions email
// ---------------------------------------------------------------------------

/// Extract the action token from the recorded execute-actions email.
fn action_token_from_mail(recorder: &RecordingSender) -> String {
    // Copy the recorded mail out of the lock before any further .await
    // (clippy::await_holding_lock).
    let text = {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "expected exactly one execute-actions email");
        sent[0].2.clone()
    };
    let link = text
        .lines()
        .find(|l| l.contains("/login/execute-actions?token="))
        .expect("execute-actions link in text body")
        .trim()
        .to_string();
    TestHarness::extract_query_param(&link, "token").expect("token in execute-actions link")
}

#[tokio::test]
async fn execute_actions_email_roundtrip() {
    let (harness, recorder) = harness_with_recorder().await;
    harness.create_realm("exec-act").await;
    let client = harness.create_client("exec-act", false).await;
    let user = harness.create_user("exec-act", "nora", "OldPass123!").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // Unknown action ids are rejected before anything is sent.
    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/exec-act/users/{}/execute-actions-email", user.id.0),
        &admin,
        serde_json::json!(["TOTALLY_BOGUS"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("unknown required action"));

    // Users without an email address cannot be mailed.
    let no_mail = harness.create_user("exec-act", "nomail", "Password123!").await;
    let mut no_mail = no_mail;
    no_mail.email = None;
    let realm_id = issuerd_core::RealmId::new("exec-act").unwrap();
    harness.storage.update_user(&realm_id, &no_mail).await.unwrap();
    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/exec-act/users/{}/execute-actions-email", no_mail.id.0),
        &admin,
        serde_json::json!(["UPDATE_PASSWORD"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("no email"));

    // Happy path: mail the UPDATE_PASSWORD action with a redirect target.
    let resp = put_json_auth(
        &harness,
        &format!(
            "/admin/realms/exec-act/users/{}/execute-actions-email?redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcb&lifespan=3600",
            user.id.0
        ),
        &admin,
        serde_json::json!(["UPDATE_PASSWORD"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let token = action_token_from_mail(&recorder);

    // The link drops the browser into the required-action continuation.
    let link_path = format!("/realms/exec-act/login/execute-actions?token={token}");
    let resp = harness.get(&link_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = location_header(&resp);
    assert!(
        location.starts_with("/realms/exec-act/login/required-action/"),
        "expected continuation redirect, got {location}"
    );
    let continuation_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("continuation flow cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(continuation_cookie.starts_with("issuerd_flow_"));

    // The action was merged into the user's assignments.
    let stored = harness.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
    assert_eq!(stored.required_actions, vec!["UPDATE_PASSWORD".to_string()]);

    // Render the password form, then complete it.
    let resp = harness.get(&location).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Update your password"));
    let resp = harness
        .post_form_with_cookie(
            &location,
            &[
                ("new_password", "BrandNew123!"),
                ("confirm_password", "BrandNew123!"),
            ],
            &continuation_cookie,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location_header(&resp),
        "http://localhost:8080/cb",
        "completion honors the admin-chosen redirect_uri"
    );

    // The assignment cleared and the new password works.
    let stored = harness.storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
    assert!(stored.required_actions.is_empty());
    let resp = password_grant(&harness, "exec-act", &client, "nora", "BrandNew123!").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = password_grant(&harness, "exec-act", &client, "nora", "OldPass123!").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The link is single-use.
    let resp = harness.get(&link_path).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("already been used"));
}

// ---------------------------------------------------------------------------
// Impersonation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn impersonation_issues_audited_tokens_and_requires_the_role() {
    let (harness, recorder) = harness_with_recorder().await;
    harness.create_realm("imp-test").await;
    let user = harness.create_user("imp-test", "victim", "Password123!").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    let admin_sub = jwt_claims(&admin)["sub"].as_str().unwrap().to_string();

    // Fresh realms have no `admin-cli` client — impersonation refuses.
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/imp-test/users/{}/impersonation", user.id.0),
            &admin,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("admin-cli"));

    // Create the admin console client in the realm.
    let resp = harness
        .post_json_auth(
            "/admin/realms/imp-test/clients",
            &admin,
            serde_json::json!({ "client_id": "admin-cli", "public_client": true, "enabled": true }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Enable admin events so the impersonation audit is recorded.
    let resp = put_json_auth(
        &harness,
        "/admin/realms/imp-test/events/config",
        &admin,
        serde_json::json!({ "adminEventsEnabled": true }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // A caller with manage-users but WITHOUT the impersonation role is
    // forbidden — prove the token is otherwise valid via execute-actions-email
    // (manage-users), which succeeds.
    let subadmin = harness.create_user("master", "subadmin", "SubPass123!").await;
    let manage_users = get_role(&harness, "master", &admin, "manage-users").await;
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/master/users/{}/role-mappings/realm", subadmin.id.0),
            &admin,
            serde_json::json!([{ "id": manage_users["id"], "name": "manage-users" }]),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let subadmin_token = harness.get_admin_token("master", "subadmin", "SubPass123!").await;
    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/imp-test/users/{}/execute-actions-email", user.id.0),
        &subadmin_token,
        serde_json::json!(["UPDATE_PASSWORD"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "manage-users token works");
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/imp-test/users/{}/impersonation", user.id.0),
            &subadmin_token,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "impersonation role required");

    // An administrator cannot impersonate themselves.
    let admin_user = harness
        .storage
        .get_user_by_username(&issuerd_core::RealmId::new("master").unwrap(), "admin")
        .await
        .unwrap()
        .expect("master admin user");
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/master/users/{}/impersonation", admin_user.id.0),
            &admin,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("themselves"));

    // The real thing: 200 with a token set carrying the impersonator claim.
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/imp-test/users/{}/impersonation", user.id.0),
            &admin,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let tokens = body_json(resp).await;
    assert_eq!(tokens["token_type"], "Bearer");
    let access = tokens["access_token"].as_str().unwrap();
    let claims = jwt_claims(access);
    assert_eq!(claims["sub"].as_str().unwrap(), user.id.0);
    assert_eq!(
        claims["impersonator"].as_str().unwrap(),
        admin_sub,
        "access token carries the impersonator claim"
    );

    // The session record proves who impersonated whom.
    let realm_id = issuerd_core::RealmId::new("imp-test").unwrap();
    let sessions = harness
        .storage
        .list_sessions(&realm_id, Some(user.id.clone()), &issuerd_core::Pagination::default())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].impersonator,
        Some(issuerd_core::UserId::new(admin_sub.clone()).unwrap())
    );

    // Audited: an ACTION admin event on the impersonation resource path...
    let resp = harness.get_auth("/admin/realms/imp-test/admin-events", &admin).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let events = body_json(resp).await;
    let events = events.as_array().unwrap();
    assert!(
        events.iter().any(|e| e["operation_type"] == "ACTION"
            && e["resource_path"].as_str().is_some_and(|p| p.contains("impersonation"))),
        "expected impersonation admin event: {events:?}"
    );

    // ...and a login event that bypasses the (disabled) events gate.
    let resp = harness.get_auth("/admin/realms/imp-test/events", &admin).await;
    let events = body_json(resp).await;
    let events = events.as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["event_type"] == "login" && e["details"]["method"] == "impersonation"),
        "expected impersonation login event: {events:?}"
    );

    // Only the execute-actions mail went out (no mail from impersonation).
    assert_eq!(recorder.sent.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Groups: children, members, move
// ---------------------------------------------------------------------------

/// Create a top-level group via the admin API; returns its id.
async fn create_group(harness: &TestHarness, realm: &str, token: &str, name: &str) -> String {
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/{realm}/groups"),
            token,
            serde_json::json!({ "name": name }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "create group {name}");
    body_json(resp).await["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn groups_children_members_and_move() {
    let harness = TestHarness::new().await;
    harness.create_realm("grp-depth").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // /admins → /admins/ops → /admins/ops/oncall
    let admins = create_group(&harness, "grp-depth", &admin, "admins").await;
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/grp-depth/groups/{admins}/children"),
            &admin,
            serde_json::json!({ "name": "ops" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let child = body_json(resp).await;
    let ops = child["id"].as_str().unwrap().to_string();
    assert_eq!(child["path"], "/admins/ops");
    assert_eq!(child["parent_id"], admins);

    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/grp-depth/groups/{ops}/children"),
            &admin,
            serde_json::json!({ "name": "oncall" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let grandchild = body_json(resp).await;
    let oncall = grandchild["id"].as_str().unwrap().to_string();
    assert_eq!(grandchild["path"], "/admins/ops/oncall");

    // sub_groups in a create body is rejected (use /children instead).
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/grp-depth/groups/{admins}/children"),
            &admin,
            serde_json::json!({ "name": "bad", "sub_groups": [{ "name": "nested" }] }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Cycle: moving /admins under its own grandchild is rejected.
    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/grp-depth/groups/{admins}"),
        &admin,
        serde_json::json!({ "name": "admins", "parent_id": oncall }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("descendants"));

    // Move /admins/ops/oncall to root via explicit null.
    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/grp-depth/groups/{oncall}"),
        &admin,
        serde_json::json!({ "name": "oncall", "parent_id": null }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness
        .get_auth(&format!("/admin/realms/grp-depth/groups/{oncall}"), &admin)
        .await;
    let group = body_json(resp).await;
    assert!(group["parent_id"].is_null());
    assert_eq!(group["path"], "/oncall");

    // Move it back under /admins — paths recompute.
    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/grp-depth/groups/{oncall}"),
        &admin,
        serde_json::json!({ "name": "oncall", "parent_id": admins }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness
        .get_auth(&format!("/admin/realms/grp-depth/groups/{oncall}"), &admin)
        .await;
    let group = body_json(resp).await;
    assert_eq!(group["path"], "/admins/oncall");
    assert_eq!(group["parent_id"], admins);

    // Members: three users in /admins/ops, paginated 2 + 1.
    let realm_id = issuerd_core::RealmId::new("grp-depth").unwrap();
    let mut usernames = Vec::new();
    for name in ["m-a", "m-b", "m-c"] {
        let user = harness.create_user("grp-depth", name, "Password123!").await;
        harness
            .storage
            .add_user_group(&realm_id, &user.id, &issuerd_core::GroupId::new(ops.clone()).unwrap())
            .await
            .unwrap();
        usernames.push(name.to_string());
    }
    usernames.sort();

    let resp = harness
        .get_auth(&format!("/admin/realms/grp-depth/groups/{ops}/members?first=0&max=2"), &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page1 = body_json(resp).await;
    assert_eq!(page1.as_array().unwrap().len(), 2);
    assert!(page1.as_array().unwrap().iter().all(|u| u["credentials"].is_null()));

    let resp = harness
        .get_auth(&format!("/admin/realms/grp-depth/groups/{ops}/members?first=2&max=2"), &admin)
        .await;
    let page2 = body_json(resp).await;
    assert_eq!(page2.as_array().unwrap().len(), 1);

    let mut paged: Vec<String> = page1
        .as_array()
        .unwrap()
        .iter()
        .chain(page2.as_array().unwrap().iter())
        .map(|u| u["username"].as_str().unwrap().to_string())
        .collect();
    paged.sort();
    assert_eq!(paged, usernames, "pages cover all members without overlap");
}

// ---------------------------------------------------------------------------
// Role composites
// ---------------------------------------------------------------------------

#[tokio::test]
async fn role_composites_subresources_roundtrip() {
    let harness = TestHarness::new().await;
    harness.create_realm("comp-test").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;
    create_realm_role(&harness, "comp-test", &admin, "parent-role").await;
    create_realm_role(&harness, "comp-test", &admin, "child-role").await;

    // Add a realm-role child by name.
    let resp = harness
        .post_json_auth(
            "/admin/realms/comp-test/roles/parent-role/composites",
            &admin,
            serde_json::json!([{ "name": "child-role" }]),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness
        .get_auth("/admin/realms/comp-test/roles/parent-role/composites", &admin)
        .await;
    let composites = body_json(resp).await;
    assert_eq!(composites.as_array().unwrap().len(), 1);
    assert_eq!(composites[0]["name"], "child-role");
    let parent = get_role(&harness, "comp-test", &admin, "parent-role").await;
    assert_eq!(parent["composite"], true);

    // A cycle (parent under its own child) is rejected.
    let resp = harness
        .post_json_auth(
            "/admin/realms/comp-test/roles/child-role/composites",
            &admin,
            serde_json::json!([{ "name": "parent-role" }]),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("circular"));

    // A client role can join the composite via its container id.
    let client = harness.create_client("comp-test", false).await;
    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/comp-test/clients/{}/roles", client.id.0),
            &admin,
            serde_json::json!({ "name": "app-admin" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = harness
        .post_json_auth(
            "/admin/realms/comp-test/roles/parent-role/composites",
            &admin,
            serde_json::json!([{
                "name": "app-admin",
                "client_role": true,
                "container_id": client.id.0,
            }]),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness
        .get_auth(
            &format!(
                "/admin/realms/comp-test/roles/parent-role/composites/clients/{}",
                client.id.0
            ),
            &admin,
        )
        .await;
    let client_children = body_json(resp).await;
    assert_eq!(client_children.as_array().unwrap().len(), 1);
    assert_eq!(client_children[0]["name"], "app-admin");

    // Removal is by name; the composite flag flips off when the last child
    // goes away.
    let resp = delete_json_auth(
        &harness,
        "/admin/realms/comp-test/roles/parent-role/composites",
        &admin,
        serde_json::json!([{ "name": "child-role" }]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let parent = get_role(&harness, "comp-test", &admin, "parent-role").await;
    assert_eq!(parent["composite"], true, "app-admin still attached");

    let resp = delete_json_auth(
        &harness,
        "/admin/realms/comp-test/roles/parent-role/composites",
        &admin,
        serde_json::json!([{
            "name": "app-admin",
            "client_role": true,
            "container_id": client.id.0,
        }]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let parent = get_role(&harness, "comp-test", &admin, "parent-role").await;
    assert_eq!(parent["composite"], false);
}

// ---------------------------------------------------------------------------
// Events: config, gating, expiration clamp, clear
// ---------------------------------------------------------------------------

/// Drive a full browser login so a `login` event is (or is not) recorded.
async fn login_once(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
) {
    harness
        .authenticate_user(realm, client.client_id.as_ref(), username, "Password123!")
        .await;
}

#[tokio::test]
async fn events_config_gating_expiration_and_clear() {
    let harness = TestHarness::new().await;
    harness.create_realm("evt-test").await;
    let client = harness.create_client("evt-test", false).await;
    let user = harness.create_user("evt-test", "ruth", "Password123!").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // Defaults: login + admin events on (Issuerd default — Keycloak parity
    // break; Keycloak defaults both off), representations off, `logging`
    // listener only.
    let resp = harness.get_auth("/admin/realms/evt-test/events/config", &admin).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cfg = body_json(resp).await;
    assert_eq!(cfg["eventsEnabled"], true);
    assert_eq!(cfg["eventsExpiration"], 0);
    assert_eq!(cfg["adminEventsEnabled"], true);
    assert_eq!(cfg["adminEventsDetailsEnabled"], false);
    assert_eq!(cfg["eventsListeners"], serde_json::json!(["logging"]));

    // With events disabled, a login records nothing.
    let resp = put_json_auth(
        &harness,
        "/admin/realms/evt-test/events/config",
        &admin,
        serde_json::json!({ "eventsEnabled": false }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    login_once(&harness, "evt-test", &client, "ruth").await;
    let resp = harness.get_auth("/admin/realms/evt-test/events", &admin).await;
    assert!(body_json(resp).await.as_array().unwrap().is_empty());

    // Partial config update flips events on; other fields keep their values.
    let resp = put_json_auth(
        &harness,
        "/admin/realms/evt-test/events/config",
        &admin,
        serde_json::json!({ "eventsEnabled": true }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth("/admin/realms/evt-test/events/config", &admin).await;
    let cfg = body_json(resp).await;
    assert_eq!(cfg["eventsEnabled"], true);
    assert_eq!(cfg["adminEventsEnabled"], true);

    // A login now records a `login` event for the user.
    login_once(&harness, "evt-test", &client, "ruth").await;
    let resp = harness.get_auth("/admin/realms/evt-test/events", &admin).await;
    let events = body_json(resp).await;
    let events = events.as_array().unwrap();
    assert!(
        events.iter().any(|e| e["event_type"] == "login" && e["user_id"] == user.id.0),
        "expected a login event for the user: {events:?}"
    );

    // Expiration clamp: an event older than `eventsExpiration` is excluded
    // from reads even with no date_from filter.
    let realm_id = issuerd_core::RealmId::new("evt-test").unwrap();
    let old = issuerd_core::Event {
        id: issuerd_core::EventId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm_id.clone(),
        event_time: chrono::Utc::now() - chrono::Duration::hours(2),
        event_type: issuerd_core::EventType::Login,
        ip_address: None,
        client_id: None,
        user_id: Some(user.id.clone()),
        session_id: None,
        error: None,
        details: std::collections::HashMap::from([("marker".to_string(), "old".to_string())]),
    };
    harness.storage.save_event(&realm_id, &old).await.unwrap();
    let resp = put_json_auth(
        &harness,
        "/admin/realms/evt-test/events/config",
        &admin,
        serde_json::json!({ "eventsExpiration": 3600 }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth("/admin/realms/evt-test/events", &admin).await;
    let events = body_json(resp).await;
    let events = events.as_array().unwrap();
    assert!(
        events.iter().all(|e| e["details"]["marker"] != "old"),
        "2h-old event must be clamped out: {events:?}"
    );
    assert!(events.iter().any(|e| e["event_type"] == "login"), "recent events stay");

    // Clearing removes every event.
    let resp = harness.delete_auth("/admin/realms/evt-test/events", &admin).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth("/admin/realms/evt-test/events", &admin).await;
    assert!(body_json(resp).await.as_array().unwrap().is_empty());

    // Admin events: enable with representations, then a mutation is audited.
    let resp = put_json_auth(
        &harness,
        "/admin/realms/evt-test/events/config",
        &admin,
        serde_json::json!({ "adminEventsEnabled": true, "adminEventsDetailsEnabled": true }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    create_realm_role(&harness, "evt-test", &admin, "audited-role").await;
    let resp = harness.get_auth("/admin/realms/evt-test/admin-events", &admin).await;
    let admin_events = body_json(resp).await;
    let admin_events = admin_events.as_array().unwrap();
    let role_create = admin_events
        .iter()
        .find(|e| e["operation_type"] == "CREATE" && e["resource_type"] == "ROLE")
        .expect("role-create admin event");
    assert!(
        role_create["representation"]
            .as_str()
            .is_some_and(|r| r.contains("audited-role")),
        "representation captured when details enabled: {role_create:?}"
    );

    // Clearing admin events leaves exactly one fresh event — the wipe itself.
    let resp = harness.delete_auth("/admin/realms/evt-test/admin-events", &admin).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness.get_auth("/admin/realms/evt-test/admin-events", &admin).await;
    let admin_events = body_json(resp).await;
    let admin_events = admin_events.as_array().unwrap();
    assert_eq!(admin_events.len(), 1);
    assert_eq!(admin_events[0]["operation_type"], "DELETE");
}

// ---------------------------------------------------------------------------
// Keys: rotate, disable, cluster propagation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keys_rotate_and_disable() {
    let harness = TestHarness::new().await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // One active RS256 key at boot; the admin token was signed with it.
    let resp = harness.get_auth("/admin/realms/master/keys", &admin).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let keys = body_json(resp).await;
    let kid0 = keys["active"]["RS256"].as_str().unwrap().to_string();
    assert_eq!(jwt_header(&admin)["kid"], kid0);

    // Rotate: a new active key takes over signing; the old one goes passive.
    let resp = harness
        .post_json_auth("/admin/realms/master/keys/rotate", &admin, serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let keys = body_json(resp).await;
    let kid1 = keys["active"]["RS256"].as_str().unwrap().to_string();
    assert_ne!(kid0, kid1, "rotation installs a new active key");
    assert_eq!(keys["passive"][0]["status"], "ACTIVE");
    assert_eq!(keys["passive"][0]["kid"], kid1);

    // New tokens are signed by the new key. The rotation reload hook is
    // asynchronous (fire-and-forget), so poll briefly until this node's
    // keystore has actually reloaded.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let admin2 = loop {
        let token = harness.get_admin_token("master", "admin", "admin").await;
        if jwt_header(&token)["kid"] == kid1 {
            break token;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "keystore did not reload the rotated key within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };

    // ...while tokens signed by the passive key still validate.
    let resp = harness
        .get_auth("/realms/master/protocol/openid-connect/userinfo", &admin)
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "passive key still validates");

    // Disabling the passive key is fine; disabling the only active key is not.
    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/master/keys/{kid0}/disable"),
        &admin2,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = put_json_auth(
        &harness,
        &format!("/admin/realms/master/keys/{kid1}/disable"),
        &admin2,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(resp).await.contains("only active"));

    // Unknown kid 404s.
    let resp = put_json_auth(
        &harness,
        "/admin/realms/master/keys/no-such-kid/disable",
        &admin2,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Seed a minimal master realm (admin/admin, `admin-cli`, and the
/// realm-management roles needed by the keys endpoints) on bare storage —
/// mirrors the dev-backend bootstrap that `ServerState::from_components`
/// skips for PostgreSQL.
async fn seed_master_realm(storage: &Arc<dyn issuerd_core::Storage>) {
    use std::collections::HashMap;

    // PostgreSQL ids are UUIDs (unlike the dev backends' literal ids).
    let realm = issuerd_core::Realm {
        id: issuerd_core::RealmId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
        name: issuerd_core::RealmName::new("master").unwrap(),
        display_name: Some(issuerd_core::DisplayName::new("Master").unwrap()),
        enabled: true,
        ..Default::default()
    };
    storage.create_realm(&realm).await.unwrap();

    let admin_user = issuerd_core::User {
        id: issuerd_core::UserId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
        realm_id: realm.id.clone(),
        username: issuerd_core::Username::new("admin").unwrap(),
        email: Some(issuerd_core::Email::new("admin@localhost.local").unwrap()),
        email_verified: true,
        first_name: Some(issuerd_core::DisplayName::new("Admin").unwrap()),
        last_name: Some(issuerd_core::DisplayName::new("User").unwrap()),
        enabled: true,
        federation_link: None,
        attributes: HashMap::new(),
        required_actions: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    storage.create_user(&realm.id, &admin_user).await.unwrap();

    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password("admin".as_bytes(), &salt).unwrap().to_string();
    let cred = issuerd_core::Credential {
        id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: issuerd_core::CredentialType::Password,
        user_label: Some("Password".to_string()),
        created_date: chrono::Utc::now(),
        secret_data: hash.into_bytes(),
        credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
        priority: 1,
    };
    storage.create_credential(&realm.id, &admin_user.id, &cred).await.unwrap();

    let admin_cli =
        issuerd_admin_api::realms::build_admin_cli_client(&realm.id, "http://localhost:8080")
            .unwrap();
    storage.create_client(&realm.id, &admin_cli).await.unwrap();

    for role_name in ["manage-realm", "view-realm"] {
        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::RoleName::new(role_name.to_string()).unwrap(),
            description: Some(format!("{role_name} role")),
            realm_id: realm.id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        storage.create_role(&realm.id, &role).await.unwrap();
        storage.add_user_realm_role(&realm.id, &admin_user.id, &role.id).await.unwrap();
    }
}

/// Key rotation on one node must reach a peer node within one JWKS refresh
/// interval. Real cross-node propagation only exists on PostgreSQL (the
/// polling task is Postgres-only), so this test boots two in-process nodes
/// over a testcontainers Postgres and skips gracefully without Docker.
#[tokio::test]
async fn keys_rotation_propagates_to_peer_node() {
    let docker = std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker {
        eprintln!("skipping keys_rotation_propagates_to_peer_node: docker unavailable");
        return;
    }

    use issuerd_core::{DistributedCache, Storage};
    use issuerd_server::{config::ServerConfig, state::ServerState};
    use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt};

    let img = GenericImage::new("postgres", "15-alpine")
        .with_wait_for(WaitFor::message_on_stderr("database system is ready to accept connections"))
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_DB", "test");
    let container = img.start().await.expect("postgres container start");
    let host = container.get_host().await.expect("container host");
    let port = container.get_host_port_ipv4(5432).await.expect("container port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/test");

    let pg = issuerd_storage::PostgresStorage::connect(&url).await.expect("postgres connect");
    pg.run_migrations().await.expect("migrations");
    let storage: Arc<dyn Storage> = Arc::new(pg);
    let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());

    // from_components only bootstraps the master realm for the dev backends —
    // on PostgreSQL provisioning owns that, so seed the minimal master realm
    // (admin/admin + admin-cli + the realm-management roles) directly.
    seed_master_realm(&storage).await;

    let config = ServerConfig {
        storage: issuerd_server::config::StorageConfig::Postgres { url: url.clone() },
        cluster: issuerd_server::config::ClusterConfig {
            jwks_refresh_interval_secs: 1,
            ..Default::default()
        },
        ..Default::default()
    };

    // Boot node A (first boot: master realm + shared signing key), then node B
    // (loads the shared key set, starts the JWKS polling task).
    let state_a = ServerState::from_components(&config, Arc::clone(&storage), Arc::clone(&cache))
        .await
        .expect("node A boot");
    let node_a = TestHarness::with_state(Arc::new(state_a));
    let state_b = ServerState::from_components(&config, Arc::clone(&storage), Arc::clone(&cache))
        .await
        .expect("node B boot");
    let node_b = TestHarness::with_state(Arc::new(state_b));

    let admin = node_a.get_admin_token("master", "admin", "admin").await;
    let resp = node_a.get_auth("/admin/realms/master/keys", &admin).await;
    let kid0 = body_json(resp).await["active"]["RS256"].as_str().unwrap().to_string();

    // Rotate on node A: the same-node reload hook fires immediately.
    let resp = node_a
        .post_json_auth("/admin/realms/master/keys/rotate", &admin, serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let kid1 = body_json(resp).await["active"]["RS256"].as_str().unwrap().to_string();
    assert_ne!(kid0, kid1);

    // Node B converges via the JWKS polling task (1 s interval). Generous
    // deadline: fresh TCP connections to testcontainers' randomly published
    // ports can take ~20 s each on degraded Docker Desktop networks, and node
    // B's poll may need a new pool connection after the rotation.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let resp = node_b.get("/realms/master/protocol/openid-connect/certs").await;
        let jwks = body_json(resp).await;
        let has_new = jwks["keys"].as_array().unwrap().iter().any(|k| k["kid"] == kid1);
        if has_new {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "node B did not pick up the rotated key within 120s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Regression test for the rig bug where the account SPA failed with
/// "Unknown or unauthorized client" on PostgreSQL deployments: the built-in
/// `account-console` / `admin-cli` builders used fixed literal internal ids,
/// which PostgreSQL (UUID primary keys) rejected — and the error was
/// swallowed. Realm creation on Postgres must persist both built-ins.
#[tokio::test]
async fn create_realm_on_postgres_persists_builtin_clients() {
    let docker = std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker {
        eprintln!("skipping create_realm_on_postgres_persists_builtin_clients: docker unavailable");
        return;
    }

    use issuerd_core::{DistributedCache, Storage};
    use issuerd_server::{config::ServerConfig, state::ServerState};
    use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt};

    let img = GenericImage::new("postgres", "15-alpine")
        .with_wait_for(WaitFor::message_on_stderr("database system is ready to accept connections"))
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_DB", "test");
    let container = img.start().await.expect("postgres container start");
    let host = container.get_host().await.expect("container host");
    let port = container.get_host_port_ipv4(5432).await.expect("container port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/test");

    let pg = issuerd_storage::PostgresStorage::connect(&url).await.expect("postgres connect");
    pg.run_migrations().await.expect("migrations");
    let storage: Arc<dyn Storage> = Arc::new(pg);
    let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());
    seed_master_realm(&storage).await;

    let config = ServerConfig {
        storage: issuerd_server::config::StorageConfig::Postgres { url: url.clone() },
        ..Default::default()
    };
    let state = ServerState::from_components(&config, Arc::clone(&storage), Arc::clone(&cache))
        .await
        .expect("node boot");
    let node = TestHarness::with_state(Arc::new(state));

    let admin = node.get_admin_token("master", "admin", "admin").await;
    let resp = node
        .post_json_auth("/admin/realms", &admin, serde_json::json!({"realm": "acme"}))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let realm = storage
        .get_realm_by_name("acme")
        .await
        .expect("lookup")
        .expect("acme realm exists");
    for built_in in ["account-console", "admin-cli"] {
        let client = storage
            .get_client_by_client_id(
                &realm.id,
                &issuerd_core::ClientIdentifier::new(built_in).unwrap(),
            )
            .await
            .expect("lookup");
        assert!(client.is_some(), "{built_in} missing on Postgres realm creation");
    }
}

// ---------------------------------------------------------------------------
// Realm not_before
// ---------------------------------------------------------------------------

#[tokio::test]
async fn not_before_rejects_stale_tokens_everywhere() {
    let harness = TestHarness::new().await;
    harness.create_realm("nb-test").await;
    let client = harness.create_client("nb-test", false).await;
    harness.create_user("nb-test", "pete", "Password123!").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    // Baseline: the user token works for userinfo.
    let resp = password_grant(&harness, "nb-test", &client, "pete", "Password123!").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let tokens = body_json(resp).await;
    let access_token = tokens["access_token"].as_str().unwrap().to_string();
    let refresh_token = tokens["refresh_token"].as_str().unwrap().to_string();
    let resp = harness
        .get_auth("/realms/nb-test/protocol/openid-connect/userinfo", &access_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Push the realm's not_before cutoff into the future: every outstanding
    // token predates it.
    let cutoff = chrono::Utc::now().timestamp() + 3600;
    put_realm_field(&harness, "nb-test", &admin, "notBefore", serde_json::json!(cutoff)).await;

    // userinfo rejects the stale access token...
    let resp = harness
        .get_auth("/realms/nb-test/protocol/openid-connect/userinfo", &access_token)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "userinfo must honor not_before");

    // ...the refresh grant rejects the stale refresh token...
    let client_id = client.client_id.to_string();
    let resp = harness
        .post_form(
            "/realms/nb-test/protocol/openid-connect/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
                ("client_id", &client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");

    // ...and the admin middleware rejects master-realm tokens (iat < cutoff)
    // acting on the cutoff realm, while other realms stay reachable.
    let resp = harness.get_auth("/admin/realms/nb-test/users", &admin).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "admin API must honor not_before");
    let resp = harness.get_auth("/admin/realms/master/users", &admin).await;
    assert_eq!(resp.status(), StatusCode::OK, "unaffected realms stay reachable");
}

// ---------------------------------------------------------------------------
// Partial import / export / push-revocation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn partial_import_strategies_export_and_push_revocation() {
    let harness = TestHarness::new().await;
    harness.create_realm("imp-exp").await;
    // A confidential client with a real secret and a user with a password, so
    // the export can be checked for secret leakage.
    let secret_client = harness.create_client("imp-exp", false).await;
    let client_secret = secret_client.secret.clone().expect("confidential client secret");
    harness.create_user("imp-exp", "carl", "Password123!").await;
    let admin = harness.get_admin_token("master", "admin", "admin").await;

    let doc = serde_json::json!({
        "users": [{ "username": "ada", "email": "ada@example.com", "first_name": "Ada", "enabled": true }],
        "groups": [{ "name": "g1" }],
        "clients": [{ "client_id": "imp-client", "enabled": true, "public_client": true }],
        "roles": { "realm": [{ "name": "imp-role" }] },
        "identityProviders": [{
            "alias": "imp-idp",
            "provider_id": "oidc",
            "enabled": true,
            "config": { "issuer": "https://idp.example.com", "clientSecret": "idpsecretvalue" }
        }],
    });

    // Default strategy (FAIL) on a fresh realm imports everything.
    let resp = harness
        .post_json_auth("/admin/realms/imp-exp/partialImport", &admin, doc.clone())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let summary = body_json(resp).await;
    assert_eq!(summary["added"], 5, "user + group + client + role + idp: {summary}");
    assert_eq!(summary["skipped"], 0);
    assert_eq!(summary["updated"], 0);
    assert!(
        summary["results"].as_array().unwrap().iter().all(|r| r["action"] == "added"),
        "all added: {summary}"
    );

    // FAIL on a second run conflicts (409) and keeps what it imported first.
    let conflict_doc = serde_json::json!({
        "users": [{ "username": "newbie", "enabled": true }, { "username": "ada" }],
    });
    let resp = harness
        .post_json_auth("/admin/realms/imp-exp/partialImport", &admin, conflict_doc)
        .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(body_string(resp).await.contains("already exists"));
    let realm_id = issuerd_core::RealmId::new("imp-exp").unwrap();
    assert!(
        harness
            .storage
            .get_user_by_username(&realm_id, "newbie")
            .await
            .unwrap()
            .is_some(),
        "FAIL is not transactional: earlier resources stay imported"
    );

    // SKIP re-imports nothing.
    let resp = harness
        .post_json_auth(
            "/admin/realms/imp-exp/partialImport?ifResourceExists=SKIP",
            &admin,
            doc.clone(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let summary = body_json(resp).await;
    assert_eq!(summary["skipped"], 5);
    assert_eq!(summary["added"], 0);

    // OVERWRITE updates in place.
    let mut overwrite_doc = doc.clone();
    overwrite_doc["users"][0]["first_name"] = serde_json::json!("Ada-Updated");
    let resp = harness
        .post_json_auth(
            "/admin/realms/imp-exp/partialImport?ifResourceExists=OVERWRITE",
            &admin,
            overwrite_doc,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let summary = body_json(resp).await;
    assert_eq!(summary["updated"], 5);
    assert_eq!(summary["added"], 0);
    let realm_id = issuerd_core::RealmId::new("imp-exp").unwrap();
    let ada = harness.storage.get_user_by_username(&realm_id, "ada").await.unwrap().unwrap();
    assert_eq!(ada.first_name.as_deref(), Some("Ada-Updated"));

    // Export: full realm JSON without any secret material.
    let resp = harness
        .post_json_auth("/admin/realms/imp-exp/export", &admin, serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let export = body_string(resp).await;
    assert!(export.contains("\"ada\""), "export contains imported users");
    assert!(export.contains("imp-client"), "export contains clients");
    assert!(!export.contains(&client_secret), "client secrets never export");
    assert!(!export.contains("$argon2id$"), "password hashes never export");
    assert!(!export.contains("idpsecretvalue"), "IdP clientSecret is masked");
    assert!(export.contains("**********"), "mask marker present for the IdP secret");
    let export_json: serde_json::Value = serde_json::from_str(&export).unwrap();
    assert_eq!(export_json["realm"], "imp-exp", "realm fields flatten to top level");

    // push-revocation is a compatibility no-op.
    let resp = harness
        .post_json_auth("/admin/realms/imp-exp/push-revocation", &admin, serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}
