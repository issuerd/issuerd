// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// RAR `authorization_details` (RFC 9396) integration tests (Issuerd-only).

//! RAR: `authorization_details` (RFC 9396) integration tests
//! (Issuerd-only).
//!
//! Covered: parse/structural validation at the authorization endpoint
//! (`invalid_authorization_details` error redirects), the realm type
//! allowlist + discovery advertisement, the full authorize → code → token
//! roundtrip (claim in the access token, echo in the token response,
//! reflection in userinfo and introspection), token-request narrowing
//! (RFC 9396 §6), refresh-token carry-over + narrowing, PAR/JAR
//! pass-through, and rejection for grants without a RAR entitlement.

use axum::http::StatusCode;
use base64::Engine;

use crate::harness::TestHarness;

const REDIRECT_URI: &str = "http://localhost:8080/cb";

/// Two authorization-details elements used across the narrowing tests.
const DETAILS_FULL: &str = r#"[{"type":"account_information","actions":["list_accounts","read_balances"],"locations":["https://example.com/accounts"]},{"type":"payment_initiation","actions":["initiate"]}]"#;
/// The first element of `DETAILS_FULL` alone (a valid narrowing).
const DETAILS_NARROWED: &str = r#"[{"type":"account_information","actions":["list_accounts","read_balances"],"locations":["https://example.com/accounts"]}]"#;

fn auth_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/auth")
}

fn token_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token")
}

/// Percent-encode a query parameter value.
fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Decode the payload segment of a JWT without verifying the signature.
fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Extract a JSON body from a response.
async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// GET the authorization endpoint with raw query params.
async fn authorize(harness: &TestHarness, realm: &str, query: &str) -> axum::response::Response {
    harness.get(&format!("{}?{query}", auth_path(realm))).await
}

/// Drive the browser login for a pending flow; returns the authorization code.
async fn browser_login(
    harness: &TestHarness,
    realm: &str,
    location: &str,
    username: &str,
) -> String {
    assert!(location.contains("/login.html"), "expected login redirect, got: {location}");
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");
    let login_resp = harness
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            serde_json::json!({
                "execution_id": execution_id,
                "username": username,
                "password": "Password123!",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_json = json_body(login_resp).await;
    login_json["code"].as_str().expect("no code issued").to_string()
}

/// Standard code-flow authorize query; `extra_query` is appended verbatim
/// (already encoded).
fn code_flow_query(client: &issuerd_core::Client, extra_query: &str) -> String {
    format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=rar-state{}",
        client.client_id,
        enc(REDIRECT_URI),
        extra_query
    )
}

/// Authorize (expecting the login-page redirect) + log in → authorization code.
async fn run_code_flow(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    extra_query: &str,
) -> String {
    let resp = authorize(harness, realm, &code_flow_query(client, extra_query)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    browser_login(harness, realm, &location, username).await
}

/// Redeem an authorization code; returns (status, body) without asserting.
async fn redeem_code(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    code: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client.client_id.as_ref()),
        ("client_secret", client.secret.as_deref().unwrap_or("")),
    ];
    params.extend_from_slice(extra);
    let resp = harness.post_form(&token_path(realm), &params).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

/// Refresh grant; returns (status, body) without asserting.
async fn refresh(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    refresh_token: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client.client_id.as_ref()),
        ("client_secret", client.secret.as_deref().unwrap_or("")),
    ];
    params.extend_from_slice(extra);
    let resp = harness.post_form(&token_path(realm), &params).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

/// Full roundtrip: authorize with `authorization_details` → code → token.
/// Asserts success and returns the token response JSON.
async fn rar_roundtrip_ok(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    details: &str,
) -> serde_json::Value {
    let code = run_code_flow(
        harness,
        realm,
        client,
        username,
        &format!("&authorization_details={}", enc(details)),
    )
    .await;
    let (status, json) = redeem_code(harness, realm, client, &code, &[]).await;
    assert_eq!(status, StatusCode::OK, "redemption failed: {json}");
    json
}

#[tokio::test]
async fn rar_code_flow_roundtrip() {
    let harness = TestHarness::new().await;
    harness.create_realm("rar-basic").await;
    let client = harness.create_client("rar-basic", false).await;
    harness.create_user("rar-basic", "anna", "Password123!").await;

    let expected: serde_json::Value = serde_json::from_str(DETAILS_NARROWED).unwrap();
    let token_json =
        rar_roundtrip_ok(&harness, "rar-basic", &client, "anna", DETAILS_NARROWED).await;

    // RFC 9396 §7: the token response echoes the granted details.
    assert_eq!(token_json["authorization_details"], expected);

    // §9.1: the access token carries the claim.
    let access_claims = jwt_claims(token_json["access_token"].as_str().unwrap());
    assert_eq!(access_claims["authorization_details"], expected);

    // The refresh token carries the grant's details (durable artifact).
    let refresh_claims = jwt_claims(token_json["refresh_token"].as_str().unwrap());
    assert_eq!(refresh_claims["authorization_details"], expected);

    // Userinfo echoes the details the client is authorized for.
    let userinfo = harness
        .get_auth(
            "/realms/rar-basic/protocol/openid-connect/userinfo",
            token_json["access_token"].as_str().unwrap(),
        )
        .await;
    assert_eq!(userinfo.status(), StatusCode::OK);
    let userinfo_json = json_body(userinfo).await;
    assert_eq!(userinfo_json["authorization_details"], expected);

    // §9.2: introspection reflects the details.
    let introspect = harness
        .post_form(
            "/realms/rar-basic/protocol/openid-connect/token/introspect",
            &[
                ("token", token_json["access_token"].as_str().unwrap()),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(introspect.status(), StatusCode::OK);
    let introspect_json = json_body(introspect).await;
    assert_eq!(introspect_json["active"], true);
    assert_eq!(introspect_json["authorization_details"], expected);
}

#[tokio::test]
async fn rar_token_request_narrowing() {
    let harness = TestHarness::new().await;
    harness.create_realm("rar-narrow").await;
    let client = harness.create_client("rar-narrow", false).await;
    harness.create_user("rar-narrow", "boris", "Password123!").await;

    let full: serde_json::Value = serde_json::from_str(DETAILS_FULL).unwrap();
    let narrowed: serde_json::Value = serde_json::from_str(DETAILS_NARROWED).unwrap();

    let code = run_code_flow(
        &harness,
        "rar-narrow",
        &client,
        "boris",
        &format!("&authorization_details={}", enc(DETAILS_FULL)),
    )
    .await;

    // Narrow at redemption: only the account_information element.
    let (status, json) = redeem_code(
        &harness,
        "rar-narrow",
        &client,
        &code,
        &[("authorization_details", DETAILS_NARROWED)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "narrowed redemption failed: {json}");
    assert_eq!(json["authorization_details"], narrowed);
    let access_claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(access_claims["authorization_details"], narrowed);
    // The resource owner's authorization is unchanged (§6.1): the refresh
    // token keeps the full granted set.
    let refresh_claims = jwt_claims(json["refresh_token"].as_str().unwrap());
    assert_eq!(refresh_claims["authorization_details"], full);
}

#[tokio::test]
async fn rar_token_request_not_subset_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("rar-superset").await;
    let client = harness.create_client("rar-superset", false).await;
    harness.create_user("rar-superset", "carol", "Password123!").await;

    // (a) A type the grant does not carry.
    let code = run_code_flow(
        &harness,
        "rar-superset",
        &client,
        "carol",
        &format!("&authorization_details={}", enc(DETAILS_NARROWED)),
    )
    .await;
    let (status, json) = redeem_code(
        &harness,
        "rar-superset",
        &client,
        &code,
        &[("authorization_details", r#"[{"type":"other_api"}]"#)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_authorization_details");

    // (b) Field-level narrowing is not exact containment → conservatively
    // rejected (see tests/KEYCLOAK_DIFFS.md).
    let code = run_code_flow(
        &harness,
        "rar-superset",
        &client,
        "carol",
        &format!("&authorization_details={}", enc(DETAILS_NARROWED)),
    )
    .await;
    let (status, json) = redeem_code(
        &harness,
        "rar-superset",
        &client,
        &code,
        &[(
            "authorization_details",
            r#"[{"type":"account_information","actions":["list_accounts"]}]"#,
        )],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_authorization_details");

    // (c) The grant carries no details at all.
    let code = run_code_flow(&harness, "rar-superset", &client, "carol", "").await;
    let (status, json) = redeem_code(
        &harness,
        "rar-superset",
        &client,
        &code,
        &[("authorization_details", DETAILS_NARROWED)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_authorization_details");
}

#[tokio::test]
async fn rar_refresh_carries_and_narrows() {
    let harness = TestHarness::new().await;
    harness.create_realm("rar-refresh").await;
    let client = harness.create_client("rar-refresh", false).await;
    harness.create_user("rar-refresh", "dora", "Password123!").await;

    let full: serde_json::Value = serde_json::from_str(DETAILS_FULL).unwrap();
    let narrowed: serde_json::Value = serde_json::from_str(DETAILS_NARROWED).unwrap();

    let token_json = rar_roundtrip_ok(&harness, "rar-refresh", &client, "dora", DETAILS_FULL).await;
    let refresh_token = token_json["refresh_token"].as_str().unwrap().to_string();

    // Plain refresh: the new access token keeps the full granted set.
    let (status, json) = refresh(&harness, "rar-refresh", &client, &refresh_token, &[]).await;
    assert_eq!(status, StatusCode::OK, "refresh failed: {json}");
    assert_eq!(json["authorization_details"], full);
    let access_claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(access_claims["authorization_details"], full);
    let rotated = json["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(jwt_claims(&rotated)["authorization_details"], full);

    // Narrowing refresh: the access token is restricted, the rotated refresh
    // token still carries the original grant.
    let (status, json) = refresh(
        &harness,
        "rar-refresh",
        &client,
        &rotated,
        &[("authorization_details", DETAILS_NARROWED)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "narrowing refresh failed: {json}");
    assert_eq!(json["authorization_details"], narrowed);
    let access_claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(access_claims["authorization_details"], narrowed);
    let rotated = json["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(jwt_claims(&rotated)["authorization_details"], full);

    // Widening refresh: rejected.
    let (status, json) = refresh(
        &harness,
        "rar-refresh",
        &client,
        &rotated,
        &[("authorization_details", r#"[{"type":"medical_record"}]"#)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_authorization_details");
}

#[tokio::test]
async fn rar_rejected_for_other_grants() {
    let harness = TestHarness::new().await;
    harness.create_realm("rar-grants").await;
    let client = harness.create_client("rar-grants", false).await;
    harness.create_user("rar-grants", "erin", "Password123!").await;

    // Password grant.
    let resp = harness
        .post_form(
            &token_path("rar-grants"),
            &[
                ("grant_type", "password"),
                ("username", "erin"),
                ("password", "Password123!"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("scope", "openid"),
                ("authorization_details", DETAILS_NARROWED),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_authorization_details");

    // Client credentials grant.
    let resp = harness
        .post_form(
            &token_path("rar-grants"),
            &[
                ("grant_type", "client_credentials"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("authorization_details", DETAILS_NARROWED),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_authorization_details");
}

#[tokio::test]
async fn rar_authorize_rejects_malformed() {
    let harness = TestHarness::new().await;
    harness.create_realm("rar-malformed").await;
    let client = harness.create_client("rar-malformed", false).await;

    for raw in [
        "not json",
        r#"{"type":"account_information"}"#, // object, not array
        r#"["account_information"]"#,        // element not an object
        r#"[{"actions":["read"]}]"#,         // missing type
        r#"[{"type":42}]"#,                  // non-string type
    ] {
        let resp = authorize(
            &harness,
            "rar-malformed",
            &code_flow_query(&client, &format!("&authorization_details={}", enc(raw))),
        )
        .await;
        // The client + redirect_uri are known-good, so the error is reported
        // via the authorization error redirect (RFC 9396 §5).
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "input: {raw}");
        let location = resp.headers()["location"].to_str().unwrap().to_string();
        assert!(
            location.contains("error=invalid_authorization_details"),
            "input: {raw}, location: {location}"
        );
        assert!(location.contains("state=rar-state"), "state not preserved: {location}");
    }
}

#[tokio::test]
async fn rar_realm_type_allowlist_and_discovery() {
    let harness = TestHarness::new().await;
    let realm = harness.create_realm("rar-allowlist").await;
    let client = harness.create_client("rar-allowlist", false).await;
    harness.create_user("rar-allowlist", "frank", "Password123!").await;

    let discovery_path = "/realms/rar-allowlist/.well-known/openid-configuration";

    // Generic mode: no attribute → the metadata is omitted and any type is
    // accepted.
    let resp = harness.get(discovery_path).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json.get("authorization_details_types_supported").is_none());

    // Pin the realm's supported types.
    let mut realm = realm;
    realm.attributes.insert(
        issuerd_core::Realm::AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE.to_string(),
        "payment_initiation account_information".to_string(),
    );
    harness.storage.update_realm(&realm).await.unwrap();
    // Direct storage writes bypass the admin API's synchronous invalidation
    // of the realm-by-name cache; drop the entry so the next resolution sees
    // the new attributes.
    harness
        .cache
        .delete(&issuerd_cluster::cache_keys::realm_by_name("rar-allowlist"))
        .await
        .unwrap();

    let resp = harness.get(discovery_path).await;
    let json = json_body(resp).await;
    assert_eq!(
        json["authorization_details_types_supported"],
        serde_json::json!(["payment_initiation", "account_information"])
    );

    // Unlisted type → authorization error redirect.
    let resp = authorize(
        &harness,
        "rar-allowlist",
        &code_flow_query(
            &client,
            &format!("&authorization_details={}", enc(r#"[{"type":"medical_record"}]"#)),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains("error=invalid_authorization_details"), "location: {location}");

    // Listed type → the flow proceeds and the claim lands in the token.
    let expected: serde_json::Value =
        serde_json::from_str(r#"[{"type":"payment_initiation","actions":["initiate"]}]"#).unwrap();
    let token_json = rar_roundtrip_ok(
        &harness,
        "rar-allowlist",
        &client,
        "frank",
        r#"[{"type":"payment_initiation","actions":["initiate"]}]"#,
    )
    .await;
    assert_eq!(token_json["authorization_details"], expected);
    let access_claims = jwt_claims(token_json["access_token"].as_str().unwrap());
    assert_eq!(access_claims["authorization_details"], expected);
}

#[tokio::test]
async fn rar_par_roundtrip() {
    let harness = TestHarness::new().await;
    harness.create_realm("rar-par").await;
    let client = harness.create_client("rar-par", false).await;
    harness.create_user("rar-par", "gwen", "Password123!").await;

    // Push the authorization request including authorization_details (PAR
    // stores the parameter verbatim and re-validates at consumption).
    let resp = harness
        .post_form(
            "/realms/rar-par/protocol/openid-connect/ext/par",
            &[
                ("response_type", "code"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", REDIRECT_URI),
                ("scope", "openid"),
                ("state", "rar-par-state"),
                ("client_secret", client.secret.as_deref().unwrap()),
                ("authorization_details", DETAILS_NARROWED),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let request_uri = json_body(resp).await["request_uri"].as_str().unwrap().to_string();

    let resp = authorize(
        &harness,
        "rar-par",
        &format!("client_id={}&request_uri={}", client.client_id, request_uri.replace(':', "%3A")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let code = browser_login(&harness, "rar-par", &location, "gwen").await;

    let (status, json) = redeem_code(&harness, "rar-par", &client, &code, &[]).await;
    assert_eq!(status, StatusCode::OK, "PAR redemption failed: {json}");
    let expected: serde_json::Value = serde_json::from_str(DETAILS_NARROWED).unwrap();
    assert_eq!(json["authorization_details"], expected);
    let access_claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(access_claims["authorization_details"], expected);
}

#[tokio::test]
async fn rar_jar_roundtrip() {
    let harness = TestHarness::new().await;
    harness.create_realm("rar-jar").await;
    let client = harness.create_client("rar-jar", false).await;
    harness.create_user("rar-jar", "henry", "Password123!").await;

    // A signed Request Object (HS256 with the client secret) carrying
    // authorization_details — JAR re-serializes the array into the parameter
    // map, where the standard parse path validates it.
    let request_object = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({
            "iss": client.client_id.as_ref(),
            "aud": "http://localhost:8080/realms/rar-jar".to_string(),
            "exp": chrono::Utc::now().timestamp() + 300,
            "response_type": "code",
            "client_id": client.client_id.as_ref(),
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "rar-jar-state",
            "authorization_details": serde_json::from_str::<serde_json::Value>(DETAILS_NARROWED)
                .unwrap(),
        }),
        &jsonwebtoken::EncodingKey::from_secret(client.secret.as_deref().unwrap().as_bytes()),
    )
    .unwrap();

    let resp = authorize(
        &harness,
        "rar-jar",
        &format!("client_id={}&request={request_object}", client.client_id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let code = browser_login(&harness, "rar-jar", &location, "henry").await;

    let (status, json) = redeem_code(&harness, "rar-jar", &client, &code, &[]).await;
    assert_eq!(status, StatusCode::OK, "JAR redemption failed: {json}");
    let expected: serde_json::Value = serde_json::from_str(DETAILS_NARROWED).unwrap();
    assert_eq!(json["authorization_details"], expected);
    let access_claims = jwt_claims(json["access_token"].as_str().unwrap());
    assert_eq!(access_claims["authorization_details"], expected);
}
