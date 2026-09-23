// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Docker E2E tests against the running two-node cluster stack.
//!
//! Stack (docker-compose.cluster.yml): nginx LB on `http://localhost:8088`,
//! issuerd nodes on `http://localhost:18081` / `http://localhost:18082`,
//! shared PostgreSQL (realms/users/sessions/signing keys) and Redis (auth
//! codes, revocation blocklist, login-failure counters). cluster/provision.yaml
//! provides realm `demo` with users `demo`/`demo123` and `lockme`/`lockme123`,
//! public client `demo-app`, confidential client `demo-service`/
//! `demo-service-secret`, plus realm `master` with `admin`/`admin` and public
//! client `admin-cli`.
//!
//! All tests skip gracefully unless ISSUERD_CLUSTER_E2E=1:
//!   docker compose -f docker-compose.cluster.yml up -d --build
//!   ISSUERD_CLUSTER_E2E=1 cargo test --test integration cluster_e2e
//!
//! Behavior notes discovered while writing these tests (handler code, not
//! guesses):
//! - The token endpoint answers wrong passwords AND locked accounts with
//!   401 `invalid_grant` (not 400).
//! - `revoke_handler` and `introspect_handler` authenticate the client from
//!   FORM PARAMS ONLY (`authenticate_form_client`); they never read the
//!   Authorization header. Public clients authenticate with `client_id` alone.
//! - Introspection reports `active: true` only to the client the token was
//!   issued to (RFC 7662 §2.2), so cross-client introspection returns inactive.
//! - Provisioned realms get generated UUID ids, but the issuer embeds the
//!   realm NAME (`{issuer_url}/realms/{name}`), so the demo realm's issuer is
//!   `http://localhost:8088/realms/demo` — the LB host:port is the part that
//!   proves correct cluster addressing.

use std::collections::BTreeSet;
use std::time::Duration;

const NODE1_URL: &str = "http://localhost:18081";
const NODE2_URL: &str = "http://localhost:18082";

fn e2e_enabled() -> bool {
    if std::env::var("ISSUERD_CLUSTER_E2E").as_deref() != Ok("1") {
        eprintln!(
            "skipping; set ISSUERD_CLUSTER_E2E=1 (stack: docker compose -f docker-compose.cluster.yml up -d --build)"
        );
        return false;
    }
    true
}

fn lb_url() -> String {
    std::env::var("ISSUERD_LB_URL").unwrap_or_else(|_| "http://localhost:8088".to_string())
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        // Never follow redirects: assertions target raw protocol responses.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .expect("reqwest client build")
}

/// Password grant against `base`. `client_secret` is only required for
/// confidential clients (public clients are not secret-checked).
async fn password_grant(
    client: &reqwest::Client,
    base: &str,
    realm: &str,
    client_id: &str,
    client_secret: Option<&str>,
    username: &str,
    password: &str,
) -> reqwest::Response {
    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", "password"),
        ("client_id", client_id),
        ("username", username),
        ("password", password),
        ("scope", "openid"),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }
    client
        .post(format!("{base}/realms/{realm}/protocol/openid-connect/token"))
        .form(&params)
        .send()
        .await
        .expect("password grant request failed — is the cluster stack up?")
}

async fn response_json(resp: reqwest::Response) -> serde_json::Value {
    resp.json().await.expect("response body must be JSON")
}

async fn jwks_kids(client: &reqwest::Client, base: &str) -> BTreeSet<String> {
    let resp = client
        .get(format!("{base}/realms/demo/protocol/openid-connect/certs"))
        .send()
        .await
        .expect("certs request failed — is the cluster stack up?");
    assert_eq!(resp.status(), 200);
    let json = response_json(resp).await;
    json["keys"]
        .as_array()
        .expect("jwks.keys must be an array")
        .iter()
        .map(|k| k["kid"].as_str().expect("jwk.kid must be a string").to_string())
        .collect()
}

/// The discovery document must advertise the load balancer's public base URL
/// (`issuer_url = http://localhost:8088` in cluster/issuerd.toml), even when
/// a node is queried directly — never a node-internal address.
#[tokio::test]
async fn e2e_discovery_issuer_is_lb_url() {
    if !e2e_enabled() {
        return;
    }
    let client = http_client();
    let lb = lb_url();

    let resp = client
        .get(format!("{lb}/realms/demo/.well-known/openid-configuration"))
        .send()
        .await
        .expect("discovery request failed — is the cluster stack up?");
    assert_eq!(resp.status(), 200);
    let json = response_json(resp).await;

    // Provisioned realms use generated UUID ids but the issuer embeds the
    // realm NAME: exactly `{lb}/realms/demo`.
    let issuer = json["issuer"].as_str().expect("discovery must carry issuer");
    assert_eq!(
        issuer,
        format!("{lb}/realms/demo"),
        "issuer must be the LB URL plus the realm name"
    );
    assert!(
        !issuer.contains("18081") && !issuer.contains("18082"),
        "issuer must not point at an individual node, got: {issuer}"
    );

    // Both nodes queried directly must advertise the exact same issuer.
    for node in [NODE1_URL, NODE2_URL] {
        let resp = client
            .get(format!("{node}/realms/demo/.well-known/openid-configuration"))
            .send()
            .await
            .expect("node discovery request failed");
        assert_eq!(resp.status(), 200);
        let node_json = response_json(resp).await;
        assert_eq!(
            node_json["issuer"].as_str().unwrap(),
            issuer,
            "node {node} must advertise the LB issuer"
        );
    }
}

/// Both nodes must publish the same non-empty JWKS: the first node to boot
/// persisted the shared signing key into PostgreSQL; the other loaded it.
#[tokio::test]
async fn e2e_nodes_share_jwks() {
    if !e2e_enabled() {
        return;
    }
    let client = http_client();

    let kids_1 = jwks_kids(&client, NODE1_URL).await;
    let kids_2 = jwks_kids(&client, NODE2_URL).await;

    assert!(!kids_1.is_empty(), "node 1 JWKS must not be empty");
    assert_eq!(kids_1, kids_2, "both nodes must publish identical kid sets");
}

/// Password grant and userinfo through the LB (round-robins across nodes).
#[tokio::test]
async fn e2e_password_grant_and_userinfo_via_lb() {
    if !e2e_enabled() {
        return;
    }
    let client = http_client();
    let lb = lb_url();

    let resp = password_grant(&client, &lb, "demo", "demo-app", None, "demo", "demo123").await;
    assert_eq!(resp.status(), 200, "password grant via LB must succeed");
    let json = response_json(resp).await;
    let access_token = json["access_token"].as_str().unwrap().to_string();

    let resp = client
        .get(format!("{lb}/realms/demo/protocol/openid-connect/userinfo"))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("userinfo request failed");
    assert_eq!(resp.status(), 200);
    let json = response_json(resp).await;
    assert!(json["sub"].is_string(), "userinfo must contain sub");
}

/// Revocation via the LB: the revoked refresh token lands in the shared Redis
/// blocklist (`revoked_refresh:`), so the refresh grant is rejected no matter
/// which node serves it. Public client `demo-app` revokes with `client_id`
/// only (the revoke endpoint authenticates from form params, not Basic auth).
#[tokio::test]
async fn e2e_revocation_via_lb() {
    if !e2e_enabled() {
        return;
    }
    let client = http_client();
    let lb = lb_url();

    let resp = password_grant(&client, &lb, "demo", "demo-app", None, "demo", "demo123").await;
    assert_eq!(resp.status(), 200);
    let json = response_json(resp).await;
    let refresh_token = json["refresh_token"].as_str().expect("refresh token missing").to_string();

    let resp = client
        .post(format!("{lb}/realms/demo/protocol/openid-connect/revoke"))
        .form(&[
            ("token", refresh_token.as_str()),
            ("token_type_hint", "refresh_token"),
            ("client_id", "demo-app"),
        ])
        .send()
        .await
        .expect("revoke request failed");
    assert_eq!(resp.status(), 200, "revocation must succeed");

    let resp = client
        .post(format!("{lb}/realms/demo/protocol/openid-connect/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", "demo-app"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("refresh grant request failed");
    assert_eq!(resp.status(), 400, "revoked refresh token must be rejected");
    let json = response_json(resp).await;
    assert_eq!(json["error"], "invalid_grant");
}

/// Introspection is served from shared state: revocation performed via the LB
/// is visible to introspection regardless of the node serving the request.
///
/// The token is issued to and introspected by the SAME confidential client
/// (`demo-service`): the introspect handler reports `active: true` only to
/// the client the token was issued to (RFC 7662 §2.2). Client credentials go
/// in the FORM BODY — the introspect/revoke handlers do not read Basic auth.
#[tokio::test]
async fn e2e_introspection_shared() {
    if !e2e_enabled() {
        return;
    }
    let client = http_client();
    let lb = lb_url();

    let resp = password_grant(
        &client,
        &lb,
        "demo",
        "demo-service",
        Some("demo-service-secret"),
        "demo",
        "demo123",
    )
    .await;
    assert_eq!(resp.status(), 200);
    let json = response_json(resp).await;
    let access_token = json["access_token"].as_str().unwrap().to_string();

    let introspect = async |client: &reqwest::Client, lb: &str, token: &str| {
        let resp = client
            .post(format!("{lb}/realms/demo/protocol/openid-connect/token/introspect"))
            .form(&[
                ("token", token),
                ("client_id", "demo-service"),
                ("client_secret", "demo-service-secret"),
            ])
            .send()
            .await
            .expect("introspect request failed");
        assert_eq!(resp.status(), 200);
        response_json(resp).await
    };

    let json = introspect(&client, &lb, &access_token).await;
    assert_eq!(json["active"], true, "fresh token must be active");

    // Revoke the access token via the LB, then introspect again.
    let resp = client
        .post(format!("{lb}/realms/demo/protocol/openid-connect/revoke"))
        .form(&[
            ("token", access_token.as_str()),
            ("token_type_hint", "access_token"),
            ("client_id", "demo-service"),
            ("client_secret", "demo-service-secret"),
        ])
        .send()
        .await
        .expect("revoke request failed");
    assert_eq!(resp.status(), 200);

    let json = introspect(&client, &lb, &access_token).await;
    assert_eq!(json["active"], false, "revoked token must be inactive");
}

/// Brute-force lockout is shared through Redis: the nginx LB (least_conn)
/// round-robins the failing attempts across both nodes, the counter
/// (`login-failure:{realm}:{username}:{ip}`, 300s TTL) aggregates them, and
/// the lock is honored on every node.
///
/// Only the dedicated `lockme` account is touched here — any other account
/// would stay locked for the 300s counter TTL and break other tests.
#[tokio::test]
async fn e2e_bruteforce_lockout_shared() {
    if !e2e_enabled() {
        return;
    }
    let client = http_client();
    let lb = lb_url();

    // Lockout is realm-gated: enable brute-force protection on the
    // demo realm via the admin API. A master-realm token administers every
    // realm; PUT resets omitted fields to defaults, so round-trip via GET.
    let resp = password_grant(&client, &lb, "master", "admin-cli", None, "admin", "admin").await;
    assert_eq!(resp.status(), 200, "admin password grant must succeed");
    let admin_token = response_json(resp).await["access_token"].as_str().unwrap().to_string();
    let resp = client
        .get(format!("{lb}/admin/realms/demo"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("get realm failed");
    assert_eq!(resp.status(), 200, "get demo realm must succeed");
    let mut realm = response_json(resp).await;
    realm["bruteForceProtected"] = serde_json::json!(true);
    let resp = client
        .put(format!("{lb}/admin/realms/demo"))
        .bearer_auth(&admin_token)
        .json(&realm)
        .send()
        .await
        .expect("update realm failed");
    assert_eq!(resp.status(), 204, "enable bruteForceProtected must succeed");

    // 5 failing password grants (wrong password). The token endpoint answers
    // bad credentials with 401 invalid_grant.
    for attempt in 1..=5 {
        let resp =
            password_grant(&client, &lb, "demo", "demo-app", None, "lockme", "wrong-password")
                .await;
        assert_eq!(resp.status(), 401, "failure attempt {attempt} must be rejected");
        let json = response_json(resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    // 6th attempt with the CORRECT password is still rejected: the lock check
    // runs before credential verification.
    let resp = password_grant(&client, &lb, "demo", "demo-app", None, "lockme", "lockme123").await;
    assert_eq!(resp.status(), 401, "locked account must reject even the correct password");
    let json = response_json(resp).await;
    assert_eq!(json["error"], "invalid_grant");

    // And it stays locked — a correct password cannot reset the counter while
    // locked (verification is never reached). The lock clears only when the
    // 300s counter TTL expires; this test deliberately does not wait for it.
    let resp = password_grant(&client, &lb, "demo", "demo-app", None, "lockme", "lockme123").await;
    assert_eq!(resp.status(), 401, "account must stay locked (no self-reset)");
}

/// Admin API through the LB: a token issued by the `master` realm administers
/// every realm (Keycloak model), so the realm-less listing endpoint works.
#[tokio::test]
async fn e2e_admin_api_via_lb() {
    if !e2e_enabled() {
        return;
    }
    let client = http_client();
    let lb = lb_url();

    let resp = password_grant(&client, &lb, "master", "admin-cli", None, "admin", "admin").await;
    assert_eq!(resp.status(), 200, "admin password grant must succeed");
    let json = response_json(resp).await;
    let admin_token = json["access_token"].as_str().unwrap().to_string();

    let resp = client
        .get(format!("{lb}/admin/realms"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("admin realms request failed");
    assert_eq!(resp.status(), 200, "admin realm listing must succeed");
    let json = response_json(resp).await;
    let names: BTreeSet<&str> = json
        .as_array()
        .expect("realm listing must be a JSON array")
        .iter()
        .filter_map(|r| r["realm"].as_str())
        .collect();
    assert!(names.contains("demo"), "realm list must contain demo: {names:?}");
    assert!(names.contains("master"), "realm list must contain master: {names:?}");
}
