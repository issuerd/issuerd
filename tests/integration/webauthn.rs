// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Passkey (WebAuthn) integration tests (Issuerd-only).
//!
//! Covers the account-console registration endpoints (start/finish/list/
//! delete), the browser second-factor challenge (passkey page after a
//! successful password check, rejected-assertion re-render), and the
//! JSON-caller challenge contract.
//!
//! The ceremonies run against a hand-rolled RFC-conformant soft authenticator
//! built on `ring`: registration uses "none" attestation (no attestation
//! signature required), while assertions are genuinely ES256-signed and
//! verified by the real `webauthn-rs` stack server-side. The soft-token crate
//! (`webauthn-authenticator-rs`) was rejected because it would force the same
//! openssl build requirement onto every test host.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use issuerd_core::CredentialType;
use ring::signature::KeyPair as _;
use tower::ServiceExt;

use crate::harness::TestHarness;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The harness issues tokens from `http://localhost:8080`, which makes
/// `localhost` the relying-party id and origin for every ceremony.
const ORIGIN: &str = "http://localhost:8080";

// ---------------------------------------------------------------------------
// Soft authenticator ("none" attestation + real ES256 signatures)
// ---------------------------------------------------------------------------

struct SoftKey {
    pkcs8: Vec<u8>,
    cred_id: Vec<u8>,
    counter: u32,
}

fn new_soft_key() -> SoftKey {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    )
    .unwrap();
    // Distinct, deterministic-enough credential id per key (random would do
    // too, but a derived pattern keeps the test reproducible).
    let cred_id: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(13).wrapping_add(3)).collect();
    SoftKey {
        pkcs8: pkcs8.as_ref().to_vec(),
        cred_id,
        counter: 0,
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
}

fn cose_ec2_key_cbor(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = vec![0xA5]; // map(5)
    out.extend([0x01, 0x02]); // 1: 2 (kty EC2)
    out.extend([0x03, 0x26]); // 3: -7 (ES256)
    out.extend([0x20, 0x01]); // -1: 1 (P-256)
    out.push(0x21); // -2: x
    out.extend([0x58, 0x20]); // bytes(32)
    out.extend_from_slice(x);
    out.push(0x22); // -3: y
    out.extend([0x58, 0x20]);
    out.extend_from_slice(y);
    out
}

fn none_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    assert!(auth_data.len() < 256);
    let mut out = vec![0xA3]; // map(3)
    out.push(0x63); // text(3)
    out.extend(b"fmt");
    out.push(0x64); // text(4)
    out.extend(b"none");
    out.push(0x67); // text(7)
    out.extend(b"attStmt");
    out.push(0xA0); // empty map
    out.push(0x68); // text(8)
    out.extend(b"authData");
    out.extend([0x58, auth_data.len() as u8]); // bytes(n), n < 256
    out.extend_from_slice(auth_data);
    out
}

fn client_data_json(kind: &str, challenge: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": kind,
        "challenge": challenge,
        "origin": ORIGIN,
        "crossOrigin": false,
    }))
    .unwrap()
}

/// Build the registration response (`PublicKeyCredential` JSON) for the
/// server-issued creation options.
fn attestation_response(key: &SoftKey, options: &serde_json::Value) -> serde_json::Value {
    let challenge = options["challenge"].as_str().expect("challenge in options");
    let rp_id = options["rp"]["id"].as_str().expect("rp.id in options");

    let public_key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &key.pkcs8,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap()
    .public_key()
    .as_ref()
    .to_vec();
    assert_eq!(public_key.len(), 65, "expected uncompressed P-256 point");
    let (x, y) = (&public_key[1..33], &public_key[33..65]);

    let mut auth_data = sha256(rp_id.as_bytes());
    auth_data.push(0x45); // user present | user verified | attested data
    auth_data.extend([0, 0, 0, 0]); // counter 0
    auth_data.extend([0u8; 16]); // zero AAGUID
    auth_data.extend([0, 32]); // credential id length (u16 BE)
    auth_data.extend(&key.cred_id);
    auth_data.extend(cose_ec2_key_cbor(x, y));

    let attestation = none_attestation_object(&auth_data);
    let client_data = client_data_json("webauthn.create", challenge);
    serde_json::json!({
        "id": B64.encode(&key.cred_id),
        "rawId": B64.encode(&key.cred_id),
        "response": {
            "attestationObject": B64.encode(&attestation),
            "clientDataJSON": B64.encode(&client_data),
        },
        "type": "public-key",
    })
}

/// Build a genuine ES256-signed assertion for the server-issued request
/// options.
fn assertion_response(key: &mut SoftKey, options: &serde_json::Value) -> serde_json::Value {
    let challenge = options["challenge"].as_str().expect("challenge in options");
    let rp_id = options["rpId"].as_str().expect("rpId in options");
    let client_data = client_data_json("webauthn.get", challenge);
    key.counter += 1;
    let mut auth_data = sha256(rp_id.as_bytes());
    auth_data.push(0x05); // user present | user verified
    auth_data.extend(key.counter.to_be_bytes());
    let mut signed = auth_data.clone();
    signed.extend(sha256(&client_data));

    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &key.pkcs8,
        &rng,
    )
    .unwrap();
    let signature = key_pair.sign(&rng, &signed).unwrap();

    serde_json::json!({
        "id": B64.encode(&key.cred_id),
        "rawId": B64.encode(&key.cred_id),
        "response": {
            "authenticatorData": B64.encode(&auth_data),
            "clientDataJSON": B64.encode(&client_data),
            "signature": B64.encode(signature.as_ref()),
            "userHandle": null,
        },
        "type": "public-key",
    })
}

// ---------------------------------------------------------------------------
// Shared helpers (mirroring the mfa.rs patterns)
// ---------------------------------------------------------------------------

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

/// POST the browser login form (content-type form-urlencoded + flow cookie).
async fn submit_login_form(
    harness: &TestHarness,
    realm: &str,
    execution_id: &str,
    params: &[(&str, &str)],
) -> axum::response::Response {
    let mut all = vec![("execution_id", execution_id)];
    all.extend_from_slice(params);
    harness
        .post_form_with_cookie(
            &format!("/api/v1/auth/login?realm={realm}"),
            &all,
            &TestHarness::flow_cookie(execution_id),
        )
        .await
}

/// Consume the response body as a UTF-8 string.
async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Consume the response body as parsed JSON.
async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
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

/// Extract the code out of a 303 client redirect.
fn code_from_redirect(resp: &axum::response::Response) -> String {
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("http://localhost:8080/cb?"), "unexpected: {location}");
    TestHarness::extract_query_param(location, "code").expect("code in redirect")
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

/// Register `key` through the account-console endpoints with the given label.
async fn register_passkey(
    harness: &TestHarness,
    realm: &str,
    token: &str,
    key: &SoftKey,
    label: &str,
) {
    let resp = harness
        .post_json_auth(
            &format!("/realms/{realm}/account/api/webauthn/register/start"),
            token,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let options = body_json(resp).await;
    assert!(options["challenge"].is_string(), "options must carry a challenge: {options}");
    assert_eq!(options["rp"]["id"], "localhost");

    let credential = attestation_response(key, &options);
    let resp = harness
        .post_json_auth(
            &format!("/realms/{realm}/account/api/webauthn/register/finish"),
            token,
            serde_json::json!({"label": label, "credential": credential}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// Pull the embedded request options out of the passkey challenge page
/// (`const options={...};` in the inline script).
fn extract_page_options(page: &str) -> serde_json::Value {
    const MARKER: &str = "const options=";
    let start = page.find(MARKER).expect("options script marker") + MARKER.len();
    let end = page[start..].find(';').expect("options terminator") + start;
    serde_json::from_str(&page[start..end]).expect("parseable options JSON")
}

// ---------------------------------------------------------------------------
// Account-console registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn account_passkey_registration_e2e() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("wa-acct").await;
    let client = harness.create_client("wa-acct", false).await;
    let _user = harness.create_user("wa-acct", "peter", "Password123!").await;
    let token = harness
        .authenticate_user("wa-acct", client.client_id.as_ref(), "peter", "Password123!")
        .await
        .access_token;

    let key = new_soft_key();
    register_passkey(&harness, "wa-acct", &token, &key, "Work laptop").await;

    // Listed with its label; flagged in the credentials summary.
    let resp = harness
        .get_auth("/realms/wa-acct/account/api/webauthn/credentials", &token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let list = body_json(resp).await;
    let entries = list.as_array().expect("passkey list");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["label"], "Work laptop");
    assert!(entries[0]["id"].as_str().unwrap().len() > 5);
    assert!(entries[0]["createdAt"].as_str().is_some());

    let resp = harness.get_auth("/realms/wa-acct/account/api/credentials", &token).await;
    let summary = body_json(resp).await;
    assert_eq!(summary["webauthn"], true);

    // The credential id is deletable; delete is idempotent.
    let cred_id = entries[0]["id"].as_str().unwrap();
    let resp = delete_auth(
        &harness,
        &format!("/realms/wa-acct/account/api/webauthn/credentials/{cred_id}"),
        &token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = harness
        .get_auth("/realms/wa-acct/account/api/webauthn/credentials", &token)
        .await;
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 0);
    let resp = delete_auth(
        &harness,
        &format!("/realms/wa-acct/account/api/webauthn/credentials/{cred_id}"),
        &token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn account_passkey_finish_without_start_is_rejected() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("wa-nostart").await;
    let client = harness.create_client("wa-nostart", false).await;
    let _user = harness.create_user("wa-nostart", "quinn", "Password123!").await;
    let token = harness
        .authenticate_user("wa-nostart", client.client_id.as_ref(), "quinn", "Password123!")
        .await
        .access_token;

    let resp = harness
        .post_json_auth(
            "/realms/wa-nostart/account/api/webauthn/register/finish",
            &token,
            serde_json::json!({"label": "x", "credential": {"id": "y"}}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn account_passkey_endpoints_require_auth() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("wa-noauth").await;

    let resp = harness
        .post_json("/realms/wa-noauth/account/api/webauthn/register/start", serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = harness
        .post_json(
            "/realms/wa-noauth/account/api/webauthn/register/finish",
            serde_json::json!({"credential": {}}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = harness.get("/realms/wa-noauth/account/api/webauthn/credentials").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let req = Request::builder()
        .method("DELETE")
        .uri("/realms/wa-noauth/account/api/webauthn/credentials/some-id")
        .body(Body::empty())
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn account_passkey_endpoints_reject_foreign_realm_token() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("wa-realm-a").await;
    let _realm = harness.create_realm("wa-realm-b").await;
    let client = harness.create_client("wa-realm-a", false).await;
    let _user = harness.create_user("wa-realm-a", "rachel", "Password123!").await;
    // A token issued by realm A must not manage passkeys in realm B.
    let token = harness
        .authenticate_user("wa-realm-a", client.client_id.as_ref(), "rachel", "Password123!")
        .await
        .access_token;

    let resp = harness
        .post_json_auth(
            "/realms/wa-realm-b/account/api/webauthn/register/start",
            &token,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = harness
        .get_auth("/realms/wa-realm-b/account/api/webauthn/credentials", &token)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Second-factor login challenge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn passkey_login_end_to_end() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("wa-e2e").await;
    let client = harness.create_client("wa-e2e", false).await;
    let user = harness.create_user("wa-e2e", "sam", "Password123!").await;
    let token = harness
        .authenticate_user("wa-e2e", client.client_id.as_ref(), "sam", "Password123!")
        .await
        .access_token;
    let mut key = new_soft_key();
    register_passkey(&harness, "wa-e2e", &token, &key, "YubiKey").await;

    // Password check succeeds, then the flow pauses on the passkey page.
    let exec = start_auth_flow(&harness, "wa-e2e", client.client_id.as_ref()).await;
    let resp = submit_login_form(
        &harness,
        "wa-e2e",
        &exec,
        &[("username", "sam"), ("password", "Password123!")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("passkey"), "expected passkey page: {page}");
    assert!(page.contains("name=\"webauthn_assertion\""), "expected assertion field: {page}");
    assert!(
        page.contains(&format!("value=\"{exec}\"")),
        "expected hidden execution id: {page}"
    );
    let options = extract_page_options(&page);
    assert_eq!(options["rpId"], "localhost");
    let allowed = options["allowCredentials"].as_array().expect("allowCredentials");
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0]["id"], B64.encode(&key.cred_id));

    // A bad assertion re-renders the page with the error banner (never a
    // Failure — a swallowed conditional-stage failure would bypass the
    // factor).
    let bad = serde_json::json!({"id": "broken", "response": {}, "type": "public-key"});
    let resp =
        submit_login_form(&harness, "wa-e2e", &exec, &[("webauthn_assertion", &bad.to_string())])
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Passkey authentication failed"), "expected error banner: {page}");

    // The re-rendered page carries FRESH options; the genuine assertion
    // completes the login with a code redirect.
    let options = extract_page_options(&page);
    let assertion = assertion_response(&mut key, &options);
    let resp = submit_login_form(
        &harness,
        "wa-e2e",
        &exec,
        &[("webauthn_assertion", &assertion.to_string())],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let code = code_from_redirect(&resp);

    let tokens = exchange_code(&harness, "wa-e2e", &client, &code).await;
    assert!(tokens["access_token"].as_str().unwrap().len() > 10);
    assert!(tokens["refresh_token"].as_str().is_some());

    // The authenticator signature counter was persisted on the credential.
    let realm_id = issuerd_core::RealmId::new("wa-e2e").unwrap();
    let creds = harness
        .storage
        .get_credentials(&realm_id, &user.id, CredentialType::WebAuthn)
        .await
        .unwrap();
    assert_eq!(creds.len(), 1);
    let stored: serde_json::Value = serde_json::from_slice(&creds[0].secret_data).unwrap();
    // Passkey serializes nested: {"cred": {..., "counter": n, ...}}.
    assert_eq!(stored["cred"]["counter"], 1, "counter must be persisted: {stored}");
}

#[tokio::test]
async fn passkey_json_caller_gets_challenge_contract() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("wa-json").await;
    let client = harness.create_client("wa-json", false).await;
    let _user = harness.create_user("wa-json", "tara", "Password123!").await;
    let token = harness
        .authenticate_user("wa-json", client.client_id.as_ref(), "tara", "Password123!")
        .await
        .access_token;
    let mut key = new_soft_key();
    register_passkey(&harness, "wa-json", &token, &key, "Phone").await;

    // JSON callers never get the HTML page: 401 + machine-readable challenge
    // carrying the raw request options.
    let exec = start_auth_flow(&harness, "wa-json", client.client_id.as_ref()).await;
    let resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=wa-json",
            serde_json::json!({
                "execution_id": exec,
                "username": "tara",
                "password": "Password123!",
            }),
            &TestHarness::flow_cookie(&exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "authentication_challenge");
    assert_eq!(body["challenge"], "webauthn");
    let options = &body["options"];
    assert!(options["challenge"].is_string(), "options must carry a challenge: {options}");
    assert_eq!(options["allowCredentials"].as_array().unwrap().len(), 1);

    // The same flow completes when the assertion is included in the JSON POST.
    let assertion = assertion_response(&mut key, options);
    let resp = harness
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=wa-json",
            serde_json::json!({
                "execution_id": exec,
                "webauthn_assertion": assertion.to_string(),
            }),
            &TestHarness::flow_cookie(&exec),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["code"].as_str().unwrap().len() > 10);
}
