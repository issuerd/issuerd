// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// In-process two-node cluster integration tests over shared storage and cache.

//! In-process two-node cluster tests (no Docker).
//!
//! Two full Issuerd instances ("nodes") are booted sequentially in the same
//! process via [`ServerState::from_components`], sharing one
//! [`issuerd_storage::InMemoryStorage`] and one [`issuerd_cluster::InMemoryCache`].
//! Node A performs the first-boot work (persists the shared RS256 signing key
//! into storage, bootstraps the `master` realm with `admin`/`admin` and the
//! public `admin-cli` client); node B then loads the shared key set and
//! publishes the same JWKS.
//!
//! Every test builds its OWN fresh storage+cache pair (`two_node_cluster()`)
//! so sessions, revocation entries and login-failure counters never leak
//! between tests running in parallel in the same process.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{body::Body, extract::ConnectInfo, http::Request, response::Response, Router};
use issuerd_core::{DistributedCache, Storage};
use issuerd_server::{config::ServerConfig, routes::app_router, state::ServerState};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Node boot + request driving (mirrors tests/harness)
// ---------------------------------------------------------------------------

/// Boot one full server node on top of the shared storage/cache pair.
async fn boot_node(
    config: &ServerConfig,
    storage: Arc<dyn Storage>,
    cache: Arc<dyn DistributedCache>,
) -> Router {
    let state = ServerState::from_components(config, storage, cache)
        .await
        .expect("cluster node boot failed");
    app_router(Arc::new(state))
}

/// Two booted nodes plus their shared components.
struct TwoNodeCluster {
    node_a: NodeClient,
    node_b: NodeClient,
    storage: Arc<dyn Storage>,
    cache: Arc<dyn DistributedCache>,
}

/// Boot node A first (shared signing key + master realm bootstrap), then node B.
async fn two_node_cluster() -> TwoNodeCluster {
    let config = ServerConfig::default();
    let storage: Arc<dyn Storage> = Arc::new(issuerd_storage::InMemoryStorage::new());
    let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());
    let node_a = boot_node(&config, Arc::clone(&storage), Arc::clone(&cache)).await;
    let node_b = boot_node(&config, Arc::clone(&storage), Arc::clone(&cache)).await;
    TwoNodeCluster {
        node_a: NodeClient::new(node_a),
        node_b: NodeClient::new(node_b),
        storage,
        cache,
    }
}

/// Minimal request driver for one node — same mechanics as `TestHarness`
/// (ConnectInfo injection, form encoding, flow correlation cookie).
#[derive(Clone)]
struct NodeClient {
    app: Router,
}

impl NodeClient {
    fn new(app: Router) -> Self {
        Self { app }
    }

    fn add_connect_info(&self, mut req: Request<Body>) -> Request<Body> {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        req
    }

    async fn get(&self, path: &str) -> Response {
        let req = Request::builder().method("GET").uri(path).body(Body::empty()).unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    async fn get_auth(&self, path: &str, token: &str) -> Response {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    async fn post_form(&self, path: &str, params: &[(&str, &str)]) -> Response {
        let body = serde_urlencoded::to_string(params).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    async fn post_json_with_cookie(
        &self,
        path: &str,
        body: serde_json::Value,
        cookie: &str,
    ) -> Response {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("cookie", cookie)
            .body(Body::from(body.to_string()))
            .unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    /// Password grant against this node. `client_secret` is only required for
    /// confidential clients (public clients are not secret-checked).
    async fn password_grant(
        &self,
        realm: &str,
        client_id: &str,
        client_secret: Option<&str>,
        username: &str,
        password: &str,
    ) -> Response {
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
        self.post_form(&format!("/realms/{realm}/protocol/openid-connect/token"), &params)
            .await
    }
}

/// Correlation cookie a browser would present when submitting the login form
/// (mirrors `TestHarness::flow_cookie`).
fn flow_cookie(execution_id: &str) -> String {
    format!("issuerd_flow_{execution_id}=1")
}

fn extract_query_param(url_str: &str, key: &str) -> Option<String> {
    let url_parsed = if url_str.starts_with('/') {
        url::Url::parse(&format!("http://localhost{}", url_str)).ok()?
    } else {
        url::Url::parse(url_str).ok()?
    };
    url_parsed.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.to_string())
}

async fn body_json(resp: Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

// ---------------------------------------------------------------------------
// Shared-storage fixture helpers (mirrors tests/harness/mod.rs)
// ---------------------------------------------------------------------------

async fn create_realm(storage: &Arc<dyn Storage>, name: &str) {
    let realm = issuerd_core::Realm {
        id: issuerd_core::RealmId::new(name).unwrap(),
        name: issuerd_core::RealmName::new(name).unwrap(),
        display_name: Some(issuerd_core::DisplayName::new(name).unwrap()),
        enabled: true,
        ..Default::default()
    };
    storage.create_realm(&realm).await.unwrap();
}

/// Create an OIDC client with redirect `http://localhost:8080/cb`.
/// `public = false` generates a confidential client with a random secret.
async fn create_client(
    storage: &Arc<dyn Storage>,
    realm: &str,
    public: bool,
) -> issuerd_core::Client {
    let secret = if public {
        None
    } else {
        Some(issuerd_core::utils::generate_id())
    };
    let client = issuerd_core::Client {
        id: issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: issuerd_core::RealmId::new(realm).unwrap(),
        client_id: issuerd_core::ClientIdentifier::new(format!(
            "client-{}",
            issuerd_core::utils::generate_id()
        ))
        .unwrap(),
        name: Some(issuerd_core::DisplayName::new("Test Client").unwrap()),
        description: None,
        enabled: true,
        protocol: issuerd_core::ClientProtocol::OpenIdConnect,
        public_client: public,
        bearer_only: false,
        client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
        secret: secret.clone(),
        redirect_uris: vec![issuerd_core::RedirectUri::new("http://localhost:8080/cb").unwrap()],
        web_origins: vec![issuerd_core::WebOrigin::new("http://localhost:8080").unwrap()],
        default_scopes: issuerd_core::Scope::parse("openid profile"),
        optional_scopes: issuerd_core::Scope::parse("email"),
        consent_required: false,
        full_scope_allowed: true,
        service_accounts_enabled: false,
        protocol_mappers: Vec::new(),
        scope_mappings: Default::default(),
        attributes: HashMap::new(),
    };
    storage.create_client(&client.realm_id, &client).await.unwrap();
    client
}

async fn create_user(storage: &Arc<dyn Storage>, realm: &str, username: &str, password: &str) {
    let user = issuerd_core::User {
        id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: issuerd_core::RealmId::new(realm).unwrap(),
        username: issuerd_core::Username::new(username).unwrap(),
        email: Some(issuerd_core::Email::new(format!("{}@example.com", username)).unwrap()),
        email_verified: true,
        first_name: Some(issuerd_core::DisplayName::new("Test").unwrap()),
        last_name: Some(issuerd_core::DisplayName::new("User").unwrap()),
        enabled: true,
        federation_link: None,
        attributes: HashMap::new(),
        required_actions: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    storage.create_user(&user.realm_id, &user).await.unwrap();

    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt).unwrap().to_string();

    let cred = issuerd_core::Credential {
        id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: issuerd_core::CredentialType::Password,
        user_label: Some("Password".to_string()),
        created_date: chrono::Utc::now(),
        secret_data: hash.into_bytes(),
        credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
        priority: 1,
    };
    storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Both nodes must publish the same non-empty JWKS: node A generated and
/// persisted the signing key, node B loaded the shared set from storage.
#[tokio::test]
async fn cluster_nodes_share_jwks() {
    let cluster = two_node_cluster().await;

    let resp_a = cluster.node_a.get("/realms/master/protocol/openid-connect/certs").await;
    let resp_b = cluster.node_b.get("/realms/master/protocol/openid-connect/certs").await;
    assert_eq!(resp_a.status(), 200);
    assert_eq!(resp_b.status(), 200);

    let kids = |json: serde_json::Value| -> BTreeSet<String> {
        json["keys"]
            .as_array()
            .expect("jwks.keys must be an array")
            .iter()
            .map(|k| k["kid"].as_str().expect("jwk.kid must be a string").to_string())
            .collect()
    };
    let kids_a = kids(body_json(resp_a).await);
    let kids_b = kids(body_json(resp_b).await);

    assert!(!kids_a.is_empty(), "node A JWKS must not be empty");
    assert_eq!(kids_a, kids_b, "both nodes must publish identical kid sets");
}

/// A token issued by node A must validate on node B (shared signing key +
/// shared session storage). Uses the bootstrapped master realm.
#[tokio::test]
async fn cluster_token_validates_cross_node() {
    let cluster = two_node_cluster().await;

    let resp = cluster
        .node_a
        .password_grant("master", "admin-cli", None, "admin", "admin")
        .await;
    assert_eq!(resp.status(), 200, "password grant on node A must succeed");
    let json = body_json(resp).await;
    let access_token = json["access_token"].as_str().unwrap();

    let userinfo = cluster
        .node_b
        .get_auth("/realms/master/protocol/openid-connect/userinfo", access_token)
        .await;
    assert_eq!(userinfo.status(), 200, "node B must accept a token issued by node A");
    let json = body_json(userinfo).await;
    assert!(json["sub"].is_string(), "userinfo must contain sub");
}

/// Full authorization-code flow: authorize + login on node A, token exchange
/// on node B. The pending-auth entry and the authorization code both live in
/// the shared cache, so node B can redeem a code issued by node A.
#[tokio::test]
async fn cluster_auth_code_redeemable_cross_node() {
    let cluster = two_node_cluster().await;
    create_realm(&cluster.storage, "code-realm").await;
    let client = create_client(&cluster.storage, "code-realm", false).await;
    create_user(&cluster.storage, "code-realm", "alice", "password123").await;

    // Step 1: authorize on node A → redirect to the login page with an execution id.
    let auth_path = format!(
        "/realms/code-realm/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        client.client_id
    );
    let auth_resp = cluster.node_a.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);
    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let execution_id =
        extract_query_param(&location, "execution_id").expect("missing execution_id in redirect");

    // Step 2: login on node A (flow correlation cookie like a browser) → code.
    let login_resp = cluster
        .node_a
        .post_json_with_cookie(
            "/api/v1/auth/login?realm=code-realm",
            serde_json::json!({
                "execution_id": execution_id,
                "username": "alice",
                "password": "password123",
            }),
            &flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(login_resp.status(), axum::http::StatusCode::OK);
    let login_json = body_json(login_resp).await;
    let code = login_json["code"].as_str().expect("login must return a code").to_string();

    // Step 3: redeem the code on node B.
    let token_resp = cluster
        .node_b
        .post_form(
            "/realms/code-realm/protocol/openid-connect/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "http://localhost:8080/cb"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(token_resp.status(), 200, "node B must redeem a code issued by node A");
    let token_json = body_json(token_resp).await;
    assert!(token_json["access_token"].as_str().unwrap().len() > 10);
}

/// Revoking a refresh token on node A must be visible to the refresh grant
/// on node B via the shared `revoked_refresh:` blocklist in the cache.
#[tokio::test]
async fn cluster_revocation_visible_cross_node() {
    let cluster = two_node_cluster().await;
    create_realm(&cluster.storage, "revoke-realm").await;
    let client = create_client(&cluster.storage, "revoke-realm", false).await;
    create_user(&cluster.storage, "revoke-realm", "alice", "password123").await;

    let resp = cluster
        .node_a
        .password_grant(
            "revoke-realm",
            &client.client_id,
            client.secret.as_deref(),
            "alice",
            "password123",
        )
        .await;
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let refresh_token = json["refresh_token"].as_str().expect("refresh token missing").to_string();

    // Revoke on node A. Note: revoke_handler authenticates the client from
    // form params only (client_id + client_secret); the Authorization header
    // is not consulted on this endpoint.
    let revoke_resp = cluster
        .node_a
        .post_form(
            "/realms/revoke-realm/protocol/openid-connect/revoke",
            &[
                ("token", &refresh_token),
                ("token_type_hint", "refresh_token"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(revoke_resp.status(), 200);

    // Refresh grant on node B must reject the revoked token.
    let refresh_resp = cluster
        .node_b
        .post_form(
            "/realms/revoke-realm/protocol/openid-connect/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(refresh_resp.status(), 400);
    let json = body_json(refresh_resp).await;
    assert_eq!(json["error"], "invalid_grant");
}

/// Login-failure lockout is keyed `login-failure:{realm}:{username}:{ip}` in
/// the SHARED cache. Each node has its own `LoginFailureTracker`, but the
/// tracker is stateless — the counter lives in the cache — so failures on
/// different nodes aggregate and the resulting lock is visible on every node.
#[tokio::test]
async fn cluster_login_lockout_shared() {
    let cluster = two_node_cluster().await;
    create_realm(&cluster.storage, "lockout-realm").await;
    // Lockout is realm-gated: enable brute-force protection explicitly.
    let realm_id = issuerd_core::RealmId::new("lockout-realm").unwrap();
    let mut realm = cluster.storage.get_realm(&realm_id).await.unwrap().unwrap();
    realm.brute_force_protected = true;
    cluster.storage.update_realm(&realm).await.unwrap();
    let client = create_client(&cluster.storage, "lockout-realm", false).await;
    create_user(&cluster.storage, "lockout-realm", "victim", "correct-password").await;
    let secret = client.secret.as_deref();

    // 5 failing password grants alternating between nodes (A,B,A,B,A).
    // Wrong credentials → 401 invalid_grant, and each failure increments the
    // shared counter.
    let nodes = [
        &cluster.node_a,
        &cluster.node_b,
        &cluster.node_a,
        &cluster.node_b,
        &cluster.node_a,
    ];
    for (attempt, node) in nodes.iter().enumerate() {
        let resp = node
            .password_grant("lockout-realm", &client.client_id, secret, "victim", "wrong-password")
            .await;
        assert_eq!(resp.status(), 401, "failure attempt {} must be rejected", attempt + 1);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    // Prove the counter aggregated across nodes: 3 failures recorded by node A
    // + 2 by node B must read as a single count of 5 (lock threshold).
    let key = "login-failure:lockout-realm:victim:127.0.0.1";
    let count = cluster
        .cache
        .get(key)
        .await
        .unwrap()
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    assert_eq!(count.as_deref(), Some("5"), "failures must aggregate cross-node");

    // 6th attempt on node B with the CORRECT password is still rejected:
    // is_temporarily_locked is checked before credential verification, so a
    // locked account cannot clear itself with a valid password. Node B only
    // recorded 2 failures itself — rejecting here proves the lock is shared.
    let resp = cluster
        .node_b
        .password_grant("lockout-realm", &client.client_id, secret, "victim", "correct-password")
        .await;
    assert_eq!(resp.status(), 401, "locked account must be rejected on node B");
    let json = body_json(resp).await;
    assert_eq!(json["error"], "invalid_grant");
}
