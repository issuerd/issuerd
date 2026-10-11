// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Implicit & hybrid authorization flows (OIDC Core §3.2/§3.3) — integration tests.

//! Implicit and hybrid authorization flows (Issuerd-only).
//!
//! Covered: the response-type acceptance matrix (all six OIDC response types
//! accepted with the right leg set in the fragment; bare `token` rejected),
//! form_post packaging of a multi-value hybrid response, `at_hash`/`c_hash`
//! correctness on authorization-endpoint ID tokens, the nonce requirement for
//! ID-token-bearing response types (incl. the `compat.nonceless_hybrid`
//! escape hatch and the nonce-free `code`/`code token` flows), the per-client
//! `response_types` allowlist, and PAR/JAR sharing the authorization
//! endpoint's acceptance + nonce rules.

use std::collections::HashMap;

use axum::http::StatusCode;
use base64::Engine;

use crate::harness::TestHarness;

const REDIRECT_URI: &str = "http://localhost:8080/cb";
const PASSWORD: &str = "Password123!";

fn auth_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/auth")
}

fn par_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/ext/par")
}

fn token_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token")
}

fn userinfo_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/userinfo")
}

fn introspect_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token/introspect")
}

/// An authorization-request query string for the harness client.
/// `extra` carries the nonce/response_mode tail (`&nonce=…`-style).
fn authz_query(client: &issuerd_core::Client, response_type: &str, extra: &str) -> String {
    format!(
        "response_type={}&client_id={}&redirect_uri={REDIRECT_URI}&scope=openid&state=s-1{extra}",
        response_type.replace(' ', "%20"),
        client.client_id,
    )
}

/// Extract a JSON body from a response.
async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Extract a text (HTML) body from a response.
async fn text_body(resp: axum::response::Response) -> String {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

/// The authorization response's parameter map, from whichever channel the
/// Location carries (query for the code flow, fragment for token-bearing
/// response types).
fn params_of(location: &str) -> HashMap<String, String> {
    let url = url::Url::parse(location).expect("location is a URL");
    let encoded = [url.query(), url.fragment()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("&");
    url::form_urlencoded::parse(encoded.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Whether the response was delivered in the URL fragment.
fn via_fragment(location: &str) -> bool {
    url::Url::parse(location).unwrap().fragment().is_some()
}

/// Decode a JWT's payload segment without verifying the signature.
fn jwt_payload(token: &str) -> serde_json::Value {
    let segment = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(segment).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The `alg` of a JWT's header.
fn jwt_alg(token: &str) -> issuerd_core::Algorithm {
    let segment = token.split('.').next().expect("jwt header segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(segment).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    header["alg"].as_str().unwrap().parse().unwrap()
}

/// Authorize → expect the login-page redirect → form-login (the browser
/// path, so the answer is the packaged authorization response) → return it.
async fn run_flow(
    harness: &TestHarness,
    realm: &str,
    query: &str,
    username: &str,
) -> axum::response::Response {
    let resp = harness.get(&format!("{}?{query}", auth_path(realm))).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains("/login.html"), "expected the login page, got: {location}");
    let execution_id =
        TestHarness::extract_query_param(&location, "execution_id").expect("missing execution_id");
    harness
        .post_form_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            &[
                ("execution_id", &execution_id),
                ("username", username),
                ("password", PASSWORD),
            ],
            &TestHarness::flow_cookie(&execution_id),
        )
        .await
}

/// A fresh realm + confidential client + user on a fresh harness.
async fn fresh_fixture() -> (TestHarness, issuerd_core::Client) {
    let harness = TestHarness::new().await;
    harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    harness.create_user("test", "alice", PASSWORD).await;
    (harness, client)
}

// ---------------------------------------------------------------------------
// Acceptance matrix
// ---------------------------------------------------------------------------

/// Every OIDC response type is accepted and delivers exactly its legs; bare
/// `token` (OAuth2-only) keeps being rejected.
#[tokio::test]
async fn response_type_matrix_delivers_the_right_legs() {
    struct Case {
        response_type: &'static str,
        present: &'static [&'static str],
        absent: &'static [&'static str],
        fragment: bool,
        nonce: bool,
    }
    let cases = [
        Case {
            response_type: "code",
            present: &["code"],
            absent: &["id_token", "access_token", "refresh_token"],
            fragment: false,
            nonce: false,
        },
        Case {
            response_type: "id_token",
            present: &["id_token"],
            absent: &["code", "access_token"],
            fragment: true,
            nonce: true,
        },
        Case {
            response_type: "id_token token",
            present: &["id_token", "access_token", "token_type", "expires_in"],
            absent: &["code", "refresh_token"],
            fragment: true,
            nonce: true,
        },
        Case {
            response_type: "code token",
            present: &["code", "access_token", "token_type", "expires_in"],
            absent: &["id_token", "refresh_token"],
            fragment: true,
            nonce: false,
        },
        Case {
            response_type: "code id_token",
            present: &["code", "id_token"],
            absent: &["access_token"],
            fragment: true,
            nonce: true,
        },
        Case {
            response_type: "code id_token token",
            present: &[
                "code",
                "id_token",
                "access_token",
                "token_type",
                "expires_in",
            ],
            absent: &["refresh_token"],
            fragment: true,
            nonce: true,
        },
    ];
    for case in cases {
        let (harness, client) = fresh_fixture().await;
        let nonce = if case.nonce { "&nonce=n-1" } else { "" };
        let resp =
            run_flow(&harness, "test", &authz_query(&client, case.response_type, nonce), "alice")
                .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{}", case.response_type);
        let location = resp.headers()["location"].to_str().unwrap().to_string();
        assert!(
            location.starts_with(REDIRECT_URI),
            "{}: must deliver to the registered redirect_uri: {location}",
            case.response_type
        );
        assert_eq!(
            via_fragment(&location),
            case.fragment,
            "{}: wrong default response mode: {location}",
            case.response_type
        );
        let params = params_of(&location);
        for key in case.present {
            let value = params
                .get(*key)
                .unwrap_or_else(|| panic!("{}: missing {key} in {location}", case.response_type));
            assert!(!value.is_empty(), "{}: empty {key}", case.response_type);
        }
        for key in case.absent {
            assert!(
                !params.contains_key(*key),
                "{}: unexpected {key} in {location}",
                case.response_type
            );
        }
        assert_eq!(params.get("state").map(String::as_str), Some("s-1"), "{}", case.response_type);
        if case.present.contains(&"token_type") {
            assert_eq!(params.get("token_type").map(String::as_str), Some("Bearer"));
            assert_eq!(params.get("expires_in").map(String::as_str), Some("300"));
        }
    }
}

/// Bare `token` is OAuth2-only: it parses, then fails with
/// `unsupported_response_type` delivered to the registered redirect_uri.
#[tokio::test]
async fn bare_token_response_type_is_rejected() {
    let (harness, client) = fresh_fixture().await;
    let resp = harness
        .get(&format!("{}?{}", auth_path("test"), authz_query(&client, "token", "")))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(REDIRECT_URI), "got: {location}");
    let params = params_of(&location);
    assert_eq!(params.get("error").map(String::as_str), Some("unsupported_response_type"));
    assert_eq!(params.get("state").map(String::as_str), Some("s-1"));
}

/// The per-client `response_types` allowlist (the JSON-array attribute from
/// dynamic registration) gates every response type — including the newly
/// accepted implicit/hybrid ones.
#[tokio::test]
async fn per_client_response_type_allowlist_is_enforced() {
    let (harness, mut client) = fresh_fixture().await;
    client.attributes.insert("response_types".to_string(), "[\"code\"]".to_string());
    harness.storage.update_client(&client.realm_id.clone(), &client).await.unwrap();

    // `id_token token` is not in the allowlist: invalid_request, named rule.
    let resp = harness
        .get(&format!(
            "{}?{}",
            auth_path("test"),
            authz_query(&client, "id_token token", "&nonce=n-1")
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    assert_eq!(params.get("error").map(String::as_str), Some("invalid_request"));
    assert!(
        params
            .get("error_description")
            .map(String::as_str)
            .unwrap_or("")
            .contains("response_type not allowed"),
        "the rule must be named: {location}"
    );

    // The allowlisted type still runs.
    let resp = harness
        .get(&format!("{}?{}", auth_path("test"), authz_query(&client, "code", "")))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains("/login.html"), "code must proceed: {location}");
}

// ---------------------------------------------------------------------------
// form_post packaging
// ---------------------------------------------------------------------------

/// A multi-value hybrid response packages into one auto-submitting form
/// (the Form Post OP shape): every leg a hidden input, POSTed to the exact
/// redirect_uri.
#[tokio::test]
async fn form_post_packages_multi_value_hybrid_response() {
    let (harness, client) = fresh_fixture().await;
    let resp = run_flow(
        &harness,
        "test",
        &authz_query(&client, "code id_token token", "&nonce=n-1&response_mode=form_post"),
        "alice",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = text_body(resp).await;
    assert!(
        html.contains("<form method=\"post\" action=\"http://localhost:8080/cb\">"),
        "{html}"
    );
    for name in [
        "code",
        "id_token",
        "access_token",
        "token_type",
        "expires_in",
        "state",
    ] {
        assert!(html.contains(&format!("name=\"{name}\"")), "missing hidden input {name}");
    }
    assert!(html.contains("name=\"token_type\" value=\"Bearer\""));
    assert!(html.contains("name=\"state\" value=\"s-1\""));
}

// ---------------------------------------------------------------------------
// at_hash / c_hash (OIDC Core §3.3.2.11)
// ---------------------------------------------------------------------------

/// Authorization-endpoint ID tokens carry a correct, alg-aware `at_hash`
/// whenever an access token rides along, and a correct `c_hash` whenever a
/// code does — and no others.
#[tokio::test]
async fn at_hash_and_c_hash_are_correct_on_authorization_endpoint_id_tokens() {
    let (harness, client) = fresh_fixture().await;

    // id_token token: at_hash over the fragment access token, no c_hash.
    let resp =
        run_flow(&harness, "test", &authz_query(&client, "id_token token", "&nonce=n-1"), "alice")
            .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let claims = jwt_payload(&params["id_token"]);
    let alg = jwt_alg(&params["id_token"]);
    assert_eq!(claims["nonce"], "n-1");
    assert_eq!(
        claims["at_hash"].as_str().expect("at_hash present"),
        issuerd_token::hash::compute_at_hash(&params["access_token"], alg).as_str(),
        "at_hash must cover the issued access token"
    );
    assert!(claims.get("c_hash").is_none(), "no code rides along, so no c_hash");

    // code id_token token: both hashes.
    let (harness, client) = fresh_fixture().await;
    let resp = run_flow(
        &harness,
        "test",
        &authz_query(&client, "code id_token token", "&nonce=n-1"),
        "alice",
    )
    .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let claims = jwt_payload(&params["id_token"]);
    let alg = jwt_alg(&params["id_token"]);
    assert_eq!(
        claims["at_hash"].as_str().expect("at_hash present"),
        issuerd_token::hash::compute_at_hash(&params["access_token"], alg).as_str()
    );
    assert_eq!(
        claims["c_hash"].as_str().expect("c_hash present"),
        issuerd_token::hash::compute_c_hash(&params["code"], alg).as_str()
    );

    // code id_token: c_hash only (no access token at the authorization
    // endpoint), as before.
    let (harness, client) = fresh_fixture().await;
    let resp =
        run_flow(&harness, "test", &authz_query(&client, "code id_token", "&nonce=n-1"), "alice")
            .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let claims = jwt_payload(&params["id_token"]);
    let alg = jwt_alg(&params["id_token"]);
    assert_eq!(
        claims["c_hash"].as_str().expect("c_hash present"),
        issuerd_token::hash::compute_c_hash(&params["code"], alg).as_str()
    );
    assert!(claims.get("at_hash").is_none(), "no access token, so no at_hash");
}

// ---------------------------------------------------------------------------
// Nonce rules (OIDC Core §3.2.2.1/§3.3.2.1)
// ---------------------------------------------------------------------------

/// Every ID-token-bearing response type requires `nonce`: a nonce-less
/// request fails at the authorization endpoint with an `invalid_request`
/// error redirect (fragment-delivered per the response type's default mode,
/// state echoed, description naming the nonce) — before any login happens.
#[tokio::test]
async fn nonce_is_required_for_id_token_bearing_response_types() {
    for response_type in [
        "id_token",
        "id_token token",
        "code id_token",
        "code id_token token",
    ] {
        let (harness, client) = fresh_fixture().await;
        let resp = harness
            .get(&format!("{}?{}", auth_path("test"), authz_query(&client, response_type, "")))
            .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{response_type}");
        let location = resp.headers()["location"].to_str().unwrap().to_string();
        assert!(
            location.starts_with(REDIRECT_URI),
            "{response_type}: the error goes to the validated redirect_uri: {location}"
        );
        assert!(
            via_fragment(&location),
            "{response_type}: the error rides the fragment (the type's default mode): {location}"
        );
        let params = params_of(&location);
        assert_eq!(
            params.get("error").map(String::as_str),
            Some("invalid_request"),
            "{response_type}"
        );
        assert!(
            params
                .get("error_description")
                .map(String::as_str)
                .unwrap_or("")
                .contains("nonce"),
            "{response_type}: the description must name the nonce: {location}"
        );
        assert_eq!(params.get("state").map(String::as_str), Some("s-1"), "{response_type}");
    }
}

/// `code` and `code token` carry no authorization-endpoint ID token and stay
/// nonce-optional (the suite asserts the code-flow direction explicitly).
#[tokio::test]
async fn code_and_code_token_stay_nonce_optional() {
    // code without nonce: completes (query-delivered code).
    let (harness, client) = fresh_fixture().await;
    let resp = run_flow(&harness, "test", &authz_query(&client, "code", ""), "alice").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(!via_fragment(&location), "code flow delivers via query: {location}");
    assert!(params_of(&location).contains_key("code"));

    // code token without nonce: completes (fragment-delivered code + token).
    let (harness, client) = fresh_fixture().await;
    let resp = run_flow(&harness, "test", &authz_query(&client, "code token", ""), "alice").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    assert!(params.contains_key("code") && params.contains_key("access_token"), "{location}");
}

/// A nonce-bearing request succeeds and the ID token echoes the nonce.
#[tokio::test]
async fn nonce_is_echoed_into_the_id_token() {
    let (harness, client) = fresh_fixture().await;
    let resp = run_flow(
        &harness,
        "test",
        &authz_query(&client, "code id_token", "&nonce=echo-me"),
        "alice",
    )
    .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    assert_eq!(jwt_payload(&params["id_token"])["nonce"], "echo-me");
}

/// Backward-compat escape hatch: the `compat.nonceless_hybrid` realm
/// attribute restores the pre-tightening behavior for hybrid flows.
#[tokio::test]
async fn compat_nonceless_hybrid_restores_legacy_acceptance() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("test").await;
    realm.attributes.insert(
        issuerd_core::Realm::COMPAT_NONCELESS_HYBRID_ATTRIBUTE.to_string(),
        "true".to_string(),
    );
    harness.storage.update_realm(&realm).await.unwrap();
    let client = harness.create_client("test", false).await;
    harness.create_user("test", "alice", PASSWORD).await;

    // A nonce-less `code id_token` request completes.
    let resp =
        run_flow(&harness, "test", &authz_query(&client, "code id_token", ""), "alice").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    assert!(params.contains_key("code") && params.contains_key("id_token"), "{location}");
}

// ---------------------------------------------------------------------------
// The implicit access token is a real token
// ---------------------------------------------------------------------------

/// The access token minted at the authorization endpoint works at userinfo
/// and introspection, and never comes with a refresh token.
#[tokio::test]
async fn implicit_access_token_works_at_userinfo_and_introspection() {
    let (harness, client) = fresh_fixture().await;
    let resp =
        run_flow(&harness, "test", &authz_query(&client, "id_token token", "&nonce=n-1"), "alice")
            .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    assert!(
        !params.contains_key("refresh_token"),
        "implicit-issued access tokens never carry a refresh token: {location}"
    );
    let access_token = params["access_token"].clone();

    // userinfo accepts it (the SSO session from the login backs it).
    let resp = harness.get_auth(&userinfo_path("test"), &access_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json["sub"].is_string(), "userinfo sub: {json}");

    // Introspection reports it active.
    let resp = harness
        .post_form(
            &introspect_path("test"),
            &[
                ("token", &access_token),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["active"], true, "introspection: {json}");

    // And the hybrid code redeems normally at the token endpoint.
    let (harness, client) = fresh_fixture().await;
    let resp = run_flow(
        &harness,
        "test",
        &authz_query(&client, "code id_token token", "&nonce=n-1"),
        "alice",
    )
    .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let resp = harness
        .post_form(
            &token_path("test"),
            &[
                ("grant_type", "authorization_code"),
                ("code", &params["code"]),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json["access_token"].is_string() && json["id_token"].is_string(), "{json}");
}

// ---------------------------------------------------------------------------
// PAR / JAR share the authorization endpoint's rules
// ---------------------------------------------------------------------------

/// A PAR-resolved request is just an authorization request: the new response
/// types mint their full leg set, and the nonce rule applies identically.
#[tokio::test]
async fn par_shares_response_type_acceptance_and_nonce_rules() {
    let (harness, client) = fresh_fixture().await;

    // Push a hybrid request (with nonce): the full leg set comes back.
    let resp = harness
        .post_form(
            &par_path("test"),
            &[
                ("response_type", "code id_token token"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", REDIRECT_URI),
                ("scope", "openid"),
                ("state", "s-1"),
                ("nonce", "n-1"),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let request_uri = json_body(resp).await["request_uri"].as_str().unwrap().to_string();

    let resp = run_flow(
        &harness,
        "test",
        &format!("client_id={}&request_uri={}", client.client_id, request_uri.replace(':', "%3A")),
        "alice",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    for key in [
        "code",
        "id_token",
        "access_token",
        "token_type",
        "expires_in",
    ] {
        assert!(params.contains_key(key), "PAR flow missing {key}: {location}");
    }

    // Push a nonce-less id_token request: push-time validation passes (the
    // nonce rule is an authorization-endpoint rule), consumption fails with
    // invalid_request.
    let resp = harness
        .post_form(
            &par_path("test"),
            &[
                ("response_type", "id_token"),
                ("client_id", client.client_id.as_ref()),
                ("redirect_uri", REDIRECT_URI),
                ("scope", "openid"),
                ("state", "s-1"),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let request_uri = json_body(resp).await["request_uri"].as_str().unwrap().to_string();
    let resp = harness
        .get(&format!(
            "{}?client_id={}&request_uri={}",
            auth_path("test"),
            client.client_id,
            request_uri.replace(':', "%3A")
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    assert_eq!(params.get("error").map(String::as_str), Some("invalid_request"));
    assert!(
        params
            .get("error_description")
            .map(String::as_str)
            .unwrap_or("")
            .contains("nonce"),
        "{location}"
    );
}

/// Sign a JAR Request Object with the client secret (HS256), the pattern the
/// JAR validator accepts for secret-based clients.
fn sign_request_object(claims: &serde_json::Value, secret: &str) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn jar_claims(client_id: &str, response_type: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": client_id,
        "aud": "http://localhost:8080/realms/test",
        "exp": chrono::Utc::now().timestamp() + 300,
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "s-1",
    })
}

/// A JAR request object likewise funnels into the same parsing: `code token`
/// runs end-to-end, and a nonce-less `id_token` object fails with
/// invalid_request.
#[tokio::test]
async fn jar_shares_response_type_acceptance_and_nonce_rules() {
    let (harness, client) = fresh_fixture().await;
    let secret = client.secret.as_deref().unwrap();

    // code token via a signed request object: no nonce needed, runs to
    // completion with exactly the code + access-token legs.
    let request = sign_request_object(&jar_claims(client.client_id.as_ref(), "code token"), secret);
    let resp = run_flow(
        &harness,
        "test",
        &format!("client_id={}&request={request}", client.client_id),
        "alice",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    assert!(params.contains_key("code") && params.contains_key("access_token"), "{location}");
    assert!(!params.contains_key("id_token"), "code token carries no id_token: {location}");

    // id_token without a nonce inside the object: rejected like a plain
    // request.
    let request = sign_request_object(&jar_claims(client.client_id.as_ref(), "id_token"), secret);
    let resp = harness
        .get(&format!(
            "{}?client_id={}&request={request}",
            auth_path("test"),
            client.client_id
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    assert_eq!(params.get("error").map(String::as_str), Some("invalid_request"));
    assert!(
        params
            .get("error_description")
            .map(String::as_str)
            .unwrap_or("")
            .contains("nonce"),
        "{location}"
    );
}

// ---------------------------------------------------------------------------
// Pure-implicit claim completeness (OIDC Core §5.4)
// ---------------------------------------------------------------------------

/// Give the fixture's `alice` the extended profile attributes the `profile`
/// scope's built-in mappers read.
async fn profiled_user(harness: &TestHarness, realm: &str) {
    let realm_id = issuerd_core::RealmId::new(realm).unwrap();
    let mut user = harness
        .storage
        .get_user_by_username(&realm_id, "alice")
        .await
        .unwrap()
        .expect("alice exists");
    for (key, value) in [
        ("website", "https://alice.example.com"),
        ("zoneinfo", "Europe/Berlin"),
        ("birthdate", "1990-05-15"),
        ("nickname", "ali"),
    ] {
        user.attributes.insert(key.to_string(), vec![value.to_string()]);
    }
    harness.storage.update_user(&realm_id, &user).await.unwrap();
}

/// With `response_type=id_token` no access token is minted, so userinfo is
/// unreachable: the authorization-endpoint ID token must carry the FULL
/// scope claim set — the UserInfo-targeted mapper claims (`website`,
/// `zoneinfo`, `birthdate`, `nickname`, `updated_at`, ...) alongside the
/// IdToken-targeted ones (Keycloak parity; OIDC Core §5.4 permits this when
/// userinfo cannot be reached).
#[tokio::test]
async fn pure_implicit_id_token_carries_the_full_scope_claim_set() {
    let (harness, client) = fresh_fixture().await;
    profiled_user(&harness, "test").await;

    let resp = run_flow(
        &harness,
        "test",
        &format!(
            "response_type=id_token&client_id={}&redirect_uri={REDIRECT_URI}&scope=openid%20profile&state=s-1&nonce=n-1",
            client.client_id
        ),
        "alice",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let claims = jwt_payload(&params["id_token"]);

    // The UserInfo-targeted profile claims are present with their values.
    assert_eq!(claims["website"], "https://alice.example.com");
    assert_eq!(claims["zoneinfo"], "Europe/Berlin");
    assert_eq!(claims["birthdate"], "1990-05-15");
    assert_eq!(claims["nickname"], "ali");
    assert!(claims["updated_at"].is_number(), "updated_at: {claims}");
    // The IdToken-targeted set stays.
    for key in ["preferred_username", "name", "given_name", "family_name"] {
        assert!(claims.get(key).is_some(), "missing claim {key}: {claims}");
    }
}

/// Regression guard for the 0-warning hybrid/code legs: their ID tokens must
/// NOT gain the UserInfo-targeted claims (the userinfo endpoint serves them
/// there).
#[tokio::test]
async fn hybrid_and_code_flows_keep_userinfo_claims_out_of_id_tokens() {
    let (harness, client) = fresh_fixture().await;
    profiled_user(&harness, "test").await;

    // code id_token (hybrid): no userinfo-targeted claims in the ID token.
    let resp = run_flow(
        &harness,
        "test",
        &format!(
            "response_type=code%20id_token&client_id={}&redirect_uri={REDIRECT_URI}&scope=openid%20profile&state=s-1&nonce=n-1",
            client.client_id
        ),
        "alice",
    )
    .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let claims = jwt_payload(&params["id_token"]);
    for key in ["website", "zoneinfo", "birthdate", "nickname", "updated_at"] {
        assert!(claims.get(key).is_none(), "hybrid id_token must not carry {key}: {claims}");
    }

    // code (authorization-code flow): the token-endpoint ID token is
    // likewise lean.
    let resp = run_flow(&harness, "test", &authz_query(&client, "code", ""), "alice").await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let resp = harness
        .post_form(
            &token_path("test"),
            &[
                ("grant_type", "authorization_code"),
                ("code", &params["code"]),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let claims = jwt_payload(json["id_token"].as_str().unwrap());
    for key in ["website", "zoneinfo", "birthdate", "nickname", "updated_at"] {
        assert!(claims.get(key).is_none(), "code-flow id_token must not carry {key}: {claims}");
    }
}

// ---------------------------------------------------------------------------
// The `claims` request parameter in pure-implicit flows (OIDC Core §5.5)
// ---------------------------------------------------------------------------

/// URL-encode an authorization query from pairs (the `claims` JSON needs
/// real percent-encoding).
fn encoded_query(pairs: &[(&str, &str)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

/// Pure implicit with `claims={"userinfo":{...}}`: with no access token
/// minted, userinfo is unreachable, so the requested userinfo-targeted
/// claims must ride the ID token (essential and voluntary entries alike).
#[tokio::test]
async fn claims_parameter_userinfo_entries_ride_the_pure_implicit_id_token() {
    let (harness, client) = fresh_fixture().await;
    profiled_user(&harness, "test").await;

    // scope=openid only: the mapper overlay contributes nothing profile-
    // shaped, so every asserted claim comes from the §5.5 evaluation.
    let claims = serde_json::json!({"userinfo": {
        "name": {"essential": true},
        "nickname": null
    }});
    let query = encoded_query(&[
        ("response_type", "id_token"),
        ("client_id", client.client_id.as_ref()),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid"),
        ("state", "s-1"),
        ("nonce", "n-1"),
        ("claims", &claims.to_string()),
    ]);
    let resp = run_flow(&harness, "test", &query, "alice").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let id_claims = jwt_payload(&params["id_token"]);
    // The harness user is "Test User"; nickname rides from the attributes.
    assert_eq!(id_claims["name"], "Test User", "{id_claims}");
    assert_eq!(id_claims["nickname"], "ali", "{id_claims}");
}

/// Regression guard: the code flow's token-endpoint ID token must NOT gain
/// the `claims.userinfo` entries (the userinfo endpoint serves them — that
/// channel is unchanged).
#[tokio::test]
async fn claims_parameter_userinfo_entries_stay_out_of_code_flow_id_tokens() {
    let (harness, client) = fresh_fixture().await;
    profiled_user(&harness, "test").await;

    let claims = serde_json::json!({"userinfo": {
        "name": {"essential": true},
        "nickname": null
    }});
    let query = encoded_query(&[
        ("response_type", "code"),
        ("client_id", client.client_id.as_ref()),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid"),
        ("state", "s-1"),
        ("claims", &claims.to_string()),
    ]);
    let resp = run_flow(&harness, "test", &query, "alice").await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let params = params_of(&location);
    let resp = harness
        .post_form(
            &token_path("test"),
            &[
                ("grant_type", "authorization_code"),
                ("code", &params["code"]),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let id_claims = jwt_payload(json["id_token"].as_str().unwrap());
    assert!(
        id_claims.get("name").is_none(),
        "code-flow id_token must not gain it: {id_claims}"
    );
    assert!(id_claims.get("nickname").is_none(), "{id_claims}");
}
