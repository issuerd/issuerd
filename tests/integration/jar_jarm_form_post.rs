// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// JAR (RFC 9101), JARM (response_mode=jwt) and form_post integration tests.

//! JAR (RFC 9101) + JARM (response_mode=jwt) + form_post
//! integration tests (Issuerd-only).
//!
//! Covered: signed Request Objects against the client secret (HMAC) and the
//! client JWKS (inline), the rejection matrix (unsigned / wrong key / client
//! binding / response_type mismatch), PAR+JAR combined (a Request Object
//! pushed to the PAR endpoint), the form_post auto-submit page for success
//! and error responses, JARM-wrapped success and error responses in all
//! delivery modes, and truthful discovery advertisement.

use axum::http::StatusCode;

use crate::harness::TestHarness;

const REDIRECT_URI: &str = "http://localhost:8080/cb";

fn auth_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/auth")
}

fn token_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/token")
}

fn par_path(realm: &str) -> String {
    format!("/realms/{realm}/protocol/openid-connect/ext/par")
}

fn issuer(realm: &str) -> String {
    format!("http://localhost:8080/realms/{realm}")
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

/// Sign a Request Object with the client secret (HS256, RFC 9101 §10.2).
fn sign_request_object(claims: &serde_json::Value, secret: &str) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

/// Standard Request Object claims for a code-flow authorization request.
fn jar_claims(client_id: &str, realm: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": client_id,
        "aud": issuer(realm),
        "exp": chrono::Utc::now().timestamp() + 300,
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile",
        "state": "jar-state",
        "nonce": "jar-nonce",
    })
}

/// GET the authorization endpoint with raw query params.
async fn authorize(harness: &TestHarness, realm: &str, query: &str) -> axum::response::Response {
    harness.get(&format!("{}?{query}", auth_path(realm))).await
}

/// Drive a full browser login for the pending flow and return the final
/// authorization response (packaged per the flow's response_mode).
async fn browser_login(
    harness: &TestHarness,
    realm: &str,
    execution_id: &str,
    username: &str,
) -> axum::response::Response {
    harness
        .post_form_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            &[
                ("execution_id", execution_id),
                ("username", username),
                ("password", "Password123!"),
            ],
            &TestHarness::flow_cookie(execution_id),
        )
        .await
}

/// Authorize → expect the login-page redirect → log in → return the final
/// authorization response.
async fn authorize_and_login(
    harness: &TestHarness,
    realm: &str,
    query: &str,
    username: &str,
) -> axum::response::Response {
    let resp = authorize(harness, realm, query).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains("/login.html"), "expected login redirect, got: {location}");
    let execution_id =
        TestHarness::extract_query_param(&location, "execution_id").expect("missing execution_id");
    browser_login(harness, realm, &execution_id, username).await
}

/// Redeem an authorization code; returns the token-endpoint JSON.
async fn redeem_code(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    code: &str,
) -> serde_json::Value {
    let resp = harness
        .post_form(
            &token_path(realm),
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    json_body(resp).await
}

/// Extract the value of a hidden input from a form_post page.
fn hidden_input_value(html: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker)? + marker.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

/// Verify a JARM JWT against the realm's live JWKS and return its claims.
async fn verify_jarm(
    harness: &TestHarness,
    realm: &str,
    client_id: &str,
    jwt: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let resp = harness.get(&format!("/realms/{realm}/protocol/openid-connect/certs")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let jwks = json_body(resp).await;

    let header = jsonwebtoken::decode_header(jwt).unwrap();
    let kid = header.kid.as_deref().expect("JARM JWT carries a kid");
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"].as_str() == Some(kid))
        .expect("realm JWKS covers the JARM kid");
    let key = jsonwebtoken::DecodingKey::from_rsa_components(
        jwk["n"].as_str().unwrap(),
        jwk["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[client_id]);
    jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(jwt, &key, &validation)
        .expect("JARM JWT verifies against the realm JWKS")
        .claims
}

/// Extract the `response` parameter from a redirect Location (query or
/// fragment).
fn extract_response_param(location: &str) -> Option<String> {
    for delimiter in ['?', '#'] {
        if let Some(pos) = location.find(delimiter) {
            for pair in location[pos + 1..].split('&') {
                if let Some(value) = pair.strip_prefix("response=") {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// JAR
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jar_signed_request_object_full_code_flow() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-flow").await;
    let client = harness.create_client("jar-flow", false).await;
    harness.create_user("jar-flow", "anna", "Password123!").await;

    // The query carries ONLY client_id + request; every other parameter lives
    // inside the signed object.
    let secret = client.secret.as_deref().unwrap();
    let request = sign_request_object(&jar_claims(client.client_id.as_str(), "jar-flow"), secret);
    let resp = authorize_and_login(
        &harness,
        "jar-flow",
        &format!("client_id={}&request={}", client.client_id, request),
        "anna",
    )
    .await;

    // Default response mode for code: query redirect with code + state from
    // the object.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(&format!("{REDIRECT_URI}?")), "got: {location}");
    let code = TestHarness::extract_query_param(&location, "code").expect("no code issued");
    assert_eq!(
        TestHarness::extract_query_param(&location, "state").as_deref(),
        Some("jar-state")
    );

    // The code is real: redemption proves the object's redirect_uri was used.
    let tokens = redeem_code(&harness, "jar-flow", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn jar_rs256_request_object_via_inline_jwks() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-rs").await;
    let mut client = harness.create_client("jar-rs", false).await;
    harness.create_user("jar-rs", "anna", "Password123!").await;

    // Client JWKS as inline attributes (Keycloak spellings).
    let crypto = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
        default_alg: issuerd_core::Algorithm::Rs256,
        rsa_key_size: 2048,
    })
    .unwrap();
    let jwks =
        serde_json::to_value(issuerd_core::CryptoProvider::get_public_keys(&crypto).await.unwrap())
            .unwrap();
    let kid = jwks["keys"][0]["kid"].as_str().unwrap().to_string();
    client.attributes.insert("use.jwks.string".to_string(), "true".to_string());
    client
        .attributes
        .insert("jwks.string".to_string(), serde_json::to_string(&jwks).unwrap());
    harness.storage.update_client(&client.realm_id.clone(), &client).await.unwrap();

    let request = issuerd_core::CryptoProvider::sign(
        &crypto,
        &serde_json::to_string(&jar_claims(client.client_id.as_str(), "jar-rs")).unwrap(),
        issuerd_core::Algorithm::Rs256,
        &issuerd_core::KeyId::new(kid).unwrap(),
    )
    .await
    .unwrap();

    let resp = authorize_and_login(
        &harness,
        "jar-rs",
        &format!("client_id={}&request={}", client.client_id, request),
        "anna",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(&format!("{REDIRECT_URI}?")), "got: {location}");
    assert!(
        TestHarness::extract_query_param(&location, "code").is_some(),
        "no code issued: {location}"
    );
}

#[tokio::test]
async fn jar_unsigned_request_object_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-unsigned").await;
    let client = harness.create_client("jar-unsigned", false).await;

    use base64::Engine;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&jar_claims(client.client_id.as_str(), "jar-unsigned"))
            .unwrap()
            .as_bytes(),
    );
    let resp = authorize(
        &harness,
        "jar-unsigned",
        &format!("client_id={}&request={header}.{payload}.", client.client_id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn jar_unsigned_request_object_browser_gets_error_page() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-unsigned-html").await;
    let client = harness.create_client("jar-unsigned-html", false).await;

    use base64::Engine;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&jar_claims(client.client_id.as_str(), "jar-unsigned-html"))
            .unwrap()
            .as_bytes(),
    );
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "{}?client_id={}&request={header}.{payload}.",
            auth_path("jar-unsigned-html"),
            client.client_id
        ))
        .header("accept", "text/html")
        .body(axum::body::Body::empty())
        .unwrap();
    let req = harness.add_connect_info(req);
    let resp = tower::ServiceExt::oneshot(harness.app.clone(), req).await.unwrap();
    // Browsers land on the login page's error surface — never a redirect to
    // the (untrusted) redirect_uri inside the object.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains("/login.html?error=invalid_request"), "got: {location}");
}

#[tokio::test]
async fn jar_wrong_signature_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-wrong-sig").await;
    let client = harness.create_client("jar-wrong-sig", false).await;

    let request =
        sign_request_object(&jar_claims(client.client_id.as_str(), "jar-wrong-sig"), "wrong");
    let resp = authorize(
        &harness,
        "jar-wrong-sig",
        &format!("client_id={}&request={request}", client.client_id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn jar_iss_client_id_mismatch_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-iss").await;
    let client = harness.create_client("jar-iss", false).await;

    // iss names a different client than the query client_id.
    let mut claims = jar_claims(client.client_id.as_str(), "jar-iss");
    claims["iss"] = serde_json::json!("some-other-client");
    let request = sign_request_object(&claims, client.secret.as_deref().unwrap());
    let resp = authorize(
        &harness,
        "jar-iss",
        &format!("client_id={}&request={request}", client.client_id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn jar_client_id_claim_mismatch_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-cid").await;
    let client = harness.create_client("jar-cid", false).await;

    // iss matches the query, but the client_id CLAIM does not (Keycloak's
    // consistency rule).
    let mut claims = jar_claims(client.client_id.as_str(), "jar-cid");
    claims["client_id"] = serde_json::json!("some-other-client");
    let request = sign_request_object(&claims, client.secret.as_deref().unwrap());
    let resp = authorize(
        &harness,
        "jar-cid",
        &format!("client_id={}&request={request}", client.client_id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn jar_response_type_mismatch_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-rt").await;
    let client = harness.create_client("jar-rt", false).await;

    // Query says id_token, the (signed) object says code.
    let request = sign_request_object(
        &jar_claims(client.client_id.as_str(), "jar-rt"),
        client.secret.as_deref().unwrap(),
    );
    let resp = authorize(
        &harness,
        "jar-rt",
        &format!("client_id={}&response_type=id_token&request={request}", client.client_id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn jar_query_params_merged_object_wins() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-merge").await;
    let client = harness.create_client("jar-merge", false).await;
    harness.create_user("jar-merge", "anna", "Password123!").await;

    // Query repeats state/scope with different values: the signed object's
    // values win (Keycloak merge semantics).
    let secret = client.secret.as_deref().unwrap();
    let request = sign_request_object(&jar_claims(client.client_id.as_str(), "jar-merge"), secret);
    let resp = authorize_and_login(
        &harness,
        "jar-merge",
        &format!(
            "client_id={}&request={}&state=query-state&scope=openid",
            client.client_id, request
        ),
        "anna",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(
        TestHarness::extract_query_param(&location, "state").as_deref(),
        Some("jar-state"),
        "object state must win over the query: {location}"
    );
}

#[tokio::test]
async fn jar_par_combined_full_flow() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-par").await;
    let client = harness.create_client("jar-par", false).await;
    harness.create_user("jar-par", "anna", "Password123!").await;

    // Push a Request Object to the PAR endpoint (RFC 9101 via RFC 9126).
    let secret = client.secret.as_deref().unwrap();
    let request = sign_request_object(&jar_claims(client.client_id.as_str(), "jar-par"), secret);
    let resp = harness
        .post_form(
            &par_path("jar-par"),
            &[
                ("client_id", client.client_id.as_ref()),
                ("client_secret", secret),
                ("request", request.as_str()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = json_body(resp).await;
    let request_uri = json["request_uri"].as_str().unwrap();

    // The authorize endpoint consumes the reference; the stored (already
    // validated) claims drive the flow.
    let resp = authorize_and_login(
        &harness,
        "jar-par",
        &format!("client_id={}&request_uri={}", client.client_id, request_uri.replace(':', "%3A")),
        "anna",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let code = TestHarness::extract_query_param(&location, "code").expect("no code issued");
    assert_eq!(
        TestHarness::extract_query_param(&location, "state").as_deref(),
        Some("jar-state")
    );
    let tokens = redeem_code(&harness, "jar-par", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn jar_par_push_rejects_invalid_object() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-par-bad").await;
    let client = harness.create_client("jar-par-bad", false).await;

    let secret = client.secret.as_deref().unwrap();
    let request =
        sign_request_object(&jar_claims(client.client_id.as_str(), "jar-par-bad"), "wrong");
    let resp = harness
        .post_form(
            &par_path("jar-par-bad"),
            &[
                ("client_id", client.client_id.as_ref()),
                ("client_secret", secret),
                ("request", request.as_str()),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

// ---------------------------------------------------------------------------
// form_post
// ---------------------------------------------------------------------------

#[tokio::test]
async fn form_post_code_flow_delivers_html_form() {
    let harness = TestHarness::new().await;
    harness.create_realm("fp-flow").await;
    let client = harness.create_client("fp-flow", false).await;
    harness.create_user("fp-flow", "anna", "Password123!").await;

    let resp = authorize_and_login(
        &harness,
        "fp-flow",
        &format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=fp-state&response_mode=form_post",
            client.client_id,
            REDIRECT_URI.replace(':', "%3A").replace('/', "%2F"),
        ),
        "anna",
    )
    .await;

    // The authorization response is an auto-submitting HTML form — parameters
    // in the body, not the URL.
    assert_eq!(resp.status(), StatusCode::OK);
    let html = text_body(resp).await;
    assert!(html.contains("<body onload=\"document.forms[0].submit()\">"), "got: {html}");
    assert!(
        html.contains(&format!("<form method=\"post\" action=\"{REDIRECT_URI}\">")),
        "got: {html}"
    );
    let code = hidden_input_value(&html, "code").expect("code hidden input missing");
    assert_eq!(hidden_input_value(&html, "state").as_deref(), Some("fp-state"));
    assert!(!html.contains("?code="), "params must not appear in any URL: {html}");

    let tokens = redeem_code(&harness, "fp-flow", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn form_post_error_response_also_posted() {
    let harness = TestHarness::new().await;
    harness.create_realm("fp-error").await;
    let client = harness.create_client("fp-error", false).await;

    // prompt=none without a session → login_required, delivered as form_post.
    let resp = authorize(
        &harness,
        "fp-error",
        &format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=fp-err&prompt=none&response_mode=form_post",
            client.client_id,
            REDIRECT_URI.replace(':', "%3A").replace('/', "%2F"),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = text_body(resp).await;
    assert_eq!(
        hidden_input_value(&html, "error").as_deref(),
        Some("login_required"),
        "got: {html}"
    );
    assert_eq!(hidden_input_value(&html, "state").as_deref(), Some("fp-err"));
}

#[tokio::test]
async fn form_post_error_for_missing_response_type() {
    let harness = TestHarness::new().await;
    harness.create_realm("fp-nort").await;
    let client = harness.create_client("fp-nort", false).await;

    // No response_type at all (a pre-parse error), but response_mode parses:
    // the error must still be POSTed to the client (the Form Post OP module
    // oidcc-response-type-missing requires exactly this).
    let resp = authorize(
        &harness,
        "fp-nort",
        &format!(
            "client_id={}&redirect_uri={}&scope=openid&state=st-1&response_mode=form_post",
            client.client_id,
            REDIRECT_URI.replace(':', "%3A").replace('/', "%2F"),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = text_body(resp).await;
    assert!(
        html.contains(&format!("<form method=\"post\" action=\"{REDIRECT_URI}\">")),
        "got: {html}"
    );
    assert_eq!(
        hidden_input_value(&html, "error").as_deref(),
        Some("invalid_request"),
        "got: {html}"
    );
    assert_eq!(hidden_input_value(&html, "state").as_deref(), Some("st-1"));
    assert!(!html.contains("?error="), "error must not leak into a URL: {html}");
}

// ---------------------------------------------------------------------------
// JARM
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jarm_code_flow_response_jwt() {
    let harness = TestHarness::new().await;
    harness.create_realm("jarm-flow").await;
    let client = harness.create_client("jarm-flow", false).await;
    harness.create_user("jarm-flow", "anna", "Password123!").await;

    let resp = authorize_and_login(
        &harness,
        "jarm-flow",
        &format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=jarm-state&response_mode=jwt",
            client.client_id,
            REDIRECT_URI.replace(':', "%3A").replace('/', "%2F"),
        ),
        "anna",
    )
    .await;

    // `jwt` with a code default resolves to query.jwt.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(&format!("{REDIRECT_URI}?response=")), "got: {location}");
    let jwt = extract_response_param(&location).expect("response parameter missing");

    let claims = verify_jarm(&harness, "jarm-flow", client.client_id.as_str(), &jwt).await;
    assert_eq!(claims["iss"], issuer("jarm-flow"));
    assert_eq!(claims["aud"], client.client_id.as_str());
    assert_eq!(claims["state"], "jarm-state");
    assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
    let code = claims["code"].as_str().expect("code claim missing").to_string();

    let tokens = redeem_code(&harness, "jarm-flow", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn jarm_error_response_also_wrapped() {
    let harness = TestHarness::new().await;
    harness.create_realm("jarm-error").await;
    let client = harness.create_client("jarm-error", false).await;

    let resp = authorize(
        &harness,
        "jarm-error",
        &format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=jarm-err&prompt=none&response_mode=jwt",
            client.client_id,
            REDIRECT_URI.replace(':', "%3A").replace('/', "%2F"),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let jwt = extract_response_param(&location).expect("response parameter missing");
    let claims = verify_jarm(&harness, "jarm-error", client.client_id.as_str(), &jwt).await;
    assert_eq!(claims["error"], "login_required");
    assert_eq!(claims["state"], "jarm-err");
}

#[tokio::test]
async fn jarm_fragment_and_query_variants() {
    let harness = TestHarness::new().await;
    harness.create_realm("jarm-modes").await;
    let client = harness.create_client("jarm-modes", false).await;
    harness.create_user("jarm-modes", "anna", "Password123!").await;

    // fragment.jwt → #response=
    let resp = authorize_and_login(
        &harness,
        "jarm-modes",
        &format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&response_mode=fragment.jwt",
            client.client_id,
            REDIRECT_URI.replace(':', "%3A").replace('/', "%2F"),
        ),
        "anna",
    )
    .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(&format!("{REDIRECT_URI}#response=")), "got: {location}");
    let jwt = extract_response_param(&location).unwrap();
    verify_jarm(&harness, "jarm-modes", client.client_id.as_str(), &jwt).await;

    // query.jwt → ?response=
    let resp = authorize_and_login(
        &harness,
        "jarm-modes",
        &format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&response_mode=query.jwt",
            client.client_id,
            REDIRECT_URI.replace(':', "%3A").replace('/', "%2F"),
        ),
        "anna",
    )
    .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(&format!("{REDIRECT_URI}?response=")), "got: {location}");
}

#[tokio::test]
async fn form_post_jwt_delivers_response_in_form_body() {
    let harness = TestHarness::new().await;
    harness.create_realm("jarm-fp").await;
    let client = harness.create_client("jarm-fp", false).await;
    harness.create_user("jarm-fp", "anna", "Password123!").await;

    let resp = authorize_and_login(
        &harness,
        "jarm-fp",
        &format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&response_mode=form_post.jwt",
            client.client_id,
            REDIRECT_URI.replace(':', "%3A").replace('/', "%2F"),
        ),
        "anna",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = text_body(resp).await;
    assert!(html.contains(&format!("<form method=\"post\" action=\"{REDIRECT_URI}\">")));
    let jwt = hidden_input_value(&html, "response").expect("response hidden input missing");
    // Only the response parameter is posted — the individual params are
    // inside the JWT.
    assert!(!html.contains("name=\"code\""), "got: {html}");
    let claims = verify_jarm(&harness, "jarm-fp", client.client_id.as_str(), &jwt).await;
    assert!(claims["code"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn jarm_implicit_flow_default_fragment() {
    let harness = TestHarness::new().await;
    harness.create_realm("jarm-implicit").await;
    let client = harness.create_client("jarm-implicit", false).await;
    harness.create_user("jarm-implicit", "anna", "Password123!").await;

    // response_type=id_token + response_mode=jwt → fragment.jwt (the
    // response type's default), wrapping the id_token.
    let resp = authorize_and_login(
        &harness,
        "jarm-implicit",
        &format!(
            "response_type=id_token&client_id={}&redirect_uri={}&scope=openid&nonce=n-1&response_mode=jwt",
            client.client_id,
            REDIRECT_URI.replace(':', "%3A").replace('/', "%2F"),
        ),
        "anna",
    )
    .await;
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(&format!("{REDIRECT_URI}#response=")), "got: {location}");
    let jwt = extract_response_param(&location).unwrap();
    let claims = verify_jarm(&harness, "jarm-implicit", client.client_id.as_str(), &jwt).await;
    assert!(claims["id_token"].as_str().unwrap().split('.').count() == 3);
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_advertises_jar_jarm_form_post_truthfully() {
    let harness = TestHarness::new().await;
    harness.create_realm("jar-disc").await;

    let resp = harness.get("/realms/jar-disc/.well-known/openid-configuration").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;

    let modes: Vec<&str> = json["response_modes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for mode in [
        "query",
        "fragment",
        "form_post",
        "jwt",
        "query.jwt",
        "fragment.jwt",
        "form_post.jwt",
    ] {
        assert!(modes.contains(&mode), "response_modes_supported missing {mode}");
    }

    assert_eq!(json["request_parameter_supported"], true);
    assert_eq!(json["request_uri_parameter_supported"], false);

    let jar_algs: Vec<&str> = json["request_object_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for alg in ["RS256", "ES256", "EdDSA", "HS256"] {
        assert!(jar_algs.contains(&alg), "request_object algs missing {alg}");
    }

    let jarm_algs: Vec<&str> = json["authorization_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(jarm_algs.contains(&"RS256"));
}
