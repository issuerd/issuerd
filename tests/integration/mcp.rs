// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! MCP Phase-1 integration matrix over real loopback HTTP servers.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

use axum::http::{header, Method, StatusCode};
use base64::Engine as _;
use issuerd_core::{
    Alias, Client, DistributedCache, Group, GroupId, GroupName, GroupPath, IdentityProviderConfig,
    IdentityProviderId, ProviderId, Realm, RealmAccess, Role, RoleId, RoleName, Scope, SessionId,
    Storage, User,
};
use issuerd_protocol::discovery::ProtectedResourceMetadata;
use issuerd_server::{
    config::{DpopNonceMode, ServerConfig},
    routes::app_router,
    state::ServerState,
};
use rmcp::{
    model::{
        CacheScope, CallToolRequestParams, CallToolResult, ClientConfig, ListToolsResult,
        ProtocolVersion, RequestMetaObject, ResultType, ServerPeerInfo,
    },
    service::RunningService,
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig,
        streamable_http_server::{session::never::NeverSessionManager, StreamableHttpService},
        StreamableHttpClientTransport,
    },
    ClientLifecycleMode, ClientServiceExt as _, RoleClient,
};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::harness::{
    dpop::{DpopKey, ProofOpts},
    TestHarness,
};

const PASSWORD: &str = "Password123!";
const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const REDIRECT_URI: &str = "http://localhost:8080/cb";
const LEGACY_VERSIONS: [ProtocolVersion; 2] =
    [ProtocolVersion::V_2025_06_18, ProtocolVersion::V_2025_11_25];
const TOOL_NAMES: [&str; 23] = [
    "attack_detection_status",
    "client_scopes_list",
    "clients_get",
    "clients_list",
    "events_search",
    "flows_list",
    "groups_get",
    "groups_list",
    "groups_members",
    "idp_get",
    "idp_list",
    "keys_list",
    "realm_get",
    "roles_get",
    "roles_list",
    "serverinfo_get",
    "sessions_list",
    "users_get",
    "users_get_credentials",
    "users_get_groups",
    "users_get_role_mappings",
    "users_get_sessions",
    "users_search",
];
const ALL_READ_ROLES: [&str; 6] = [
    "view-realm",
    "manage-realm",
    "view-users",
    "manage-users",
    "view-clients",
    "manage-clients",
];

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

fn unique(label: &str) -> String {
    format!("mcp-{label}-{}", NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed))
}

struct Loopback {
    base_url: String,
    state: Arc<ServerState>,
    http: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct FailSetCache {
    inner: issuerd_cluster::InMemoryCache,
    fail_set: AtomicBool,
    fail_compare_and_delete: AtomicBool,
}

impl FailSetCache {
    fn fail_sets(&self, fail: bool) {
        self.fail_set.store(fail, Ordering::Relaxed);
    }

    fn fail_compare_and_delete(&self, fail: bool) {
        self.fail_compare_and_delete.store(fail, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl DistributedCache for FailSetCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, issuerd_core::IssuerdError> {
        self.inner.get(key).await
    }

    async fn set(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Option<std::time::Duration>,
    ) -> Result<(), issuerd_core::IssuerdError> {
        if self.fail_set.load(Ordering::Relaxed) {
            return Err(issuerd_core::IssuerdError::ServerError("injected set failure".into()));
        }
        self.inner.set(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> Result<(), issuerd_core::IssuerdError> {
        self.inner.delete(key).await
    }

    async fn get_and_delete(
        &self,
        key: &str,
    ) -> Result<Option<Vec<u8>>, issuerd_core::IssuerdError> {
        self.inner.get_and_delete(key).await
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> Result<bool, issuerd_core::IssuerdError> {
        self.inner.compare_and_swap(key, expected, new).await
    }

    async fn compare_and_delete(
        &self,
        key: &str,
        expected: Vec<u8>,
    ) -> Result<bool, issuerd_core::IssuerdError> {
        if self.fail_compare_and_delete.load(Ordering::Relaxed) {
            return Ok(false);
        }
        self.inner.compare_and_delete(key, expected).await
    }

    async fn increment(
        &self,
        key: &str,
        ttl: Option<std::time::Duration>,
    ) -> Result<u64, issuerd_core::IssuerdError> {
        self.inner.increment(key, ttl).await
    }

    async fn publish(
        &self,
        channel: &str,
        message: Vec<u8>,
    ) -> Result<(), issuerd_core::IssuerdError> {
        self.inner.publish(channel, message).await
    }

    async fn subscribe(
        &self,
        channel: &str,
        handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
    ) -> Result<(), issuerd_core::IssuerdError> {
        self.inner.subscribe(channel, handler).await
    }

    async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>, issuerd_core::IssuerdError> {
        self.inner.scan_keys(pattern).await
    }
}

#[derive(Clone)]
struct ServerOptions {
    enabled: bool,
    require_dpop: bool,
    invocation_rate_limit: u32,
    nonce_mode: DpopNonceMode,
    allowed_origins: Vec<String>,
    issuer_url: Option<String>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            require_dpop: false,
            invocation_rate_limit: 10_000,
            nonce_mode: DpopNonceMode::Disabled,
            allowed_origins: Vec::new(),
            issuer_url: None,
        }
    }
}

async fn spawn_server(options: ServerOptions) -> Loopback {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let mut config = crate::harness::test_config();
    config.issuer_url = options.issuer_url.unwrap_or_else(|| base_url.clone());
    config.mcp.enabled = options.enabled;
    config.mcp.require_dpop = options.require_dpop;
    config.mcp.invocation_rate_limit_per_minute = options.invocation_rate_limit;
    config.mcp.allowed_origins = options.allowed_origins;
    config.dpop.nonce.mode = options.nonce_mode;
    spawn_listener(listener, config, None).await
}

async fn spawn_listener(
    listener: tokio::net::TcpListener,
    config: ServerConfig,
    components: Option<(Arc<dyn Storage>, Arc<dyn DistributedCache>)>,
) -> Loopback {
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let state = match components {
        Some((storage, cache)) => ServerState::from_components(&config, storage, cache).await,
        None => ServerState::from_config(&config).await,
    }
    .unwrap();
    let state = Arc::new(state);
    let app = app_router(Arc::clone(&state));
    let task = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    Loopback {
        base_url,
        state,
        http,
        task,
    }
}

impl Loopback {
    fn realm_url(&self, realm: &str, suffix: &[&str], canonical: bool) -> String {
        let base = if canonical {
            &self.state.config.issuer_url
        } else {
            &self.base_url
        };
        issuerd_core::urls::RealmUrlBuilder::new(base, realm)
            .unwrap()
            .path(suffix)
            .to_string()
    }

    fn mcp_url(&self, realm: &str) -> String {
        self.realm_url(realm, &["mcp"], false)
    }

    fn resource(&self, realm: &str) -> String {
        ProtectedResourceMetadata::for_realm(&self.state.config.issuer_url, realm)
            .resource
            .to_string()
    }

    fn metadata_url(&self, realm: &str) -> String {
        ProtectedResourceMetadata::metadata_url_for_realm(&self.state.config.issuer_url, realm)
            .to_string()
    }

    fn host(&self) -> String {
        let url = url::Url::parse(&self.state.config.issuer_url).unwrap();
        let host = url.host_str().unwrap();
        url.port().map_or_else(|| host.to_string(), |port| format!("{host}:{port}"))
    }

    fn request(&self, method: Method, url: impl Into<String>) -> reqwest::RequestBuilder {
        self.http.request(method, url.into()).header(header::HOST, self.host())
    }

    fn get(&self, url: impl Into<String>) -> reqwest::RequestBuilder {
        self.request(Method::GET, url)
    }

    fn post(&self, url: impl Into<String>) -> reqwest::RequestBuilder {
        self.request(Method::POST, url)
    }
}

#[derive(Default)]
struct RequestOptions {
    version: Option<String>,
    method: Option<String>,
    name: Option<String>,
    authorization: Option<String>,
    proofs: Vec<String>,
    origin: Option<String>,
    host: Option<String>,
    last_event_id: Option<String>,
    accepts: Option<Vec<String>>,
    content_type: Option<String>,
}

impl RequestOptions {
    fn legacy() -> Self {
        Self {
            version: Some("2025-11-25".to_string()),
            ..Self::default()
        }
    }

    fn modern(method: &str) -> Self {
        Self {
            version: Some("2026-07-28".to_string()),
            method: Some(method.to_string()),
            ..Self::default()
        }
    }

    fn bearer(token: &str) -> Self {
        Self {
            authorization: Some(format!("Bearer {token}")),
            ..Self::legacy()
        }
    }
}

async fn send_mcp(
    server: &Loopback,
    realm: &str,
    body: impl Into<String>,
    options: RequestOptions,
) -> reqwest::Response {
    let host = options.host.clone().unwrap_or_else(|| server.host());
    let accepts = options
        .accepts
        .clone()
        .unwrap_or_else(|| vec!["application/json, text/event-stream".to_string()]);
    let content_type =
        options.content_type.clone().unwrap_or_else(|| "application/json".to_string());
    let mut request = server
        .http
        .post(server.mcp_url(realm))
        .header(header::HOST, host)
        .body(body.into());
    for accept in accepts {
        request = request.header(header::ACCEPT, accept);
    }
    request = request.header(header::CONTENT_TYPE, content_type);
    if let Some(version) = options.version {
        request = request.header("MCP-Protocol-Version", version);
    }
    if let Some(method) = options.method {
        request = request.header("Mcp-Method", method);
    }
    if let Some(name) = options.name {
        request = request.header("Mcp-Name", name);
    }
    if let Some(authorization) = options.authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    for proof in options.proofs {
        request = request.header("DPoP", proof);
    }
    if let Some(origin) = options.origin {
        request = request.header(header::ORIGIN, origin);
    }
    if let Some(last_event_id) = options.last_event_id {
        request = request.header("Last-Event-ID", last_event_id);
    }
    request.send().await.unwrap()
}

fn legacy_request(method: &str, params: Value) -> String {
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string()
}

fn modern_request(method: &str, mut params: Value) -> String {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name":"integration","version":"1"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    legacy_request(method, params)
}

fn tool_request(tool: &str, arguments: Value, modern: bool) -> String {
    let params = json!({"name":tool,"arguments":arguments});
    if modern {
        modern_request("tools/call", params)
    } else {
        legacy_request("tools/call", params)
    }
}

fn tool_options(tool: &str, token: &str, modern: bool) -> RequestOptions {
    let mut options = if modern {
        RequestOptions::modern("tools/call")
    } else {
        RequestOptions::legacy()
    };
    options.authorization = Some(format!("Bearer {token}"));
    if modern {
        options.name = Some(tool.to_string());
    }
    options
}

async fn response_json(response: reqwest::Response) -> Value {
    let status = response.status();
    let bytes = response.bytes().await.unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("HTTP {status} returned non-JSON body {bytes:?}: {error}"))
}

fn header_values(response: &reqwest::Response, name: header::HeaderName) -> Vec<String> {
    response
        .headers()
        .get_all(name)
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect()
}

fn assert_no_session_id(response: &reqwest::Response) {
    assert!(!response.headers().contains_key("mcp-session-id"));
}

fn assert_no_store(response: &reqwest::Response) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
}

struct Fixture {
    realm: Realm,
    client: Client,
    user: User,
}

async fn add_roles(server: &Loopback, fixture: &Fixture, roles: &[&str]) {
    for name in roles {
        let role =
            match server.state.storage.get_role_by_name(&fixture.realm.id, name).await.unwrap() {
                Some(role) => role,
                None => {
                    let role = Role {
                        id: RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
                        name: RoleName::new(*name).unwrap(),
                        description: None,
                        realm_id: fixture.realm.id.clone(),
                        client_role: false,
                        client_id: None,
                        composite: false,
                        composites: Vec::new(),
                        attributes: HashMap::from([(
                            "password".to_string(),
                            vec!["ROLE-SECRET-CANARY".to_string()],
                        )]),
                    };
                    server.state.storage.create_role(&fixture.realm.id, &role).await.unwrap();
                    role
                }
            };
        server
            .state
            .storage
            .add_user_realm_role(&fixture.realm.id, &fixture.user.id, &role.id)
            .await
            .unwrap();
    }
    issuerd_cluster::invalidate::bump_claims_epoch(server.state.cache.as_ref(), &fixture.realm.id)
        .await;
    issuerd_cluster::invalidate::invalidate_user_claims(
        server.state.cache.as_ref(),
        &fixture.realm.id,
        &fixture.user.id,
    )
    .await;
}

async fn make_fixture(server: &Loopback, label: &str, roles: &[&str]) -> Fixture {
    fixture_named(server, &unique(label), "agent", roles).await
}

async fn fixture_named(
    server: &Loopback,
    realm_name: &str,
    username: &str,
    roles: &[&str],
) -> Fixture {
    let harness = TestHarness::with_state(Arc::clone(&server.state));
    let realm = harness.create_realm(realm_name).await;
    let mut client = harness.create_client(realm_name, false).await;
    client.optional_scopes = Scope::parse("email mcp:read mcp:write");
    server.state.storage.update_client(&client.realm_id, &client).await.unwrap();
    let user = harness.create_user(realm_name, username, PASSWORD).await;
    let fixture = Fixture {
        realm,
        client,
        user,
    };
    add_roles(server, &fixture, roles).await;
    fixture
}

async fn additional_user(server: &Loopback, fixture: &Fixture, username: &str) -> User {
    TestHarness::with_state(Arc::clone(&server.state))
        .create_user(fixture.realm.name.as_str(), username, PASSWORD)
        .await
}

async fn additional_client(server: &Loopback, fixture: &Fixture) -> Client {
    TestHarness::with_state(Arc::clone(&server.state))
        .create_client(fixture.realm.name.as_str(), false)
        .await
}

struct IssuedToken {
    access_token: String,
    claims: Value,
    session_id: String,
}

fn decode_jwt(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn issue_token(
    server: &Loopback,
    fixture: &Fixture,
    scope: &str,
    dpop_key: Option<&DpopKey>,
    include_resource: bool,
) -> IssuedToken {
    let challenge = issuerd_protocol::pkce::PkceVerifier::s256_challenge(CODE_VERIFIER);
    let resource = server.resource(fixture.realm.name.as_str());
    let mut query = vec![
        ("response_type".to_string(), "code".to_string()),
        ("client_id".to_string(), fixture.client.client_id.to_string()),
        ("redirect_uri".to_string(), REDIRECT_URI.to_string()),
        ("scope".to_string(), scope.to_string()),
        ("state".to_string(), "mcp-integration".to_string()),
        ("code_challenge".to_string(), challenge),
        ("code_challenge_method".to_string(), "S256".to_string()),
    ];
    if include_resource {
        query.push(("resource".to_string(), resource));
    }
    let auth_url = format!(
        "{}?{}",
        server.realm_url(
            fixture.realm.name.as_str(),
            &["protocol", "openid-connect", "auth"],
            false,
        ),
        serde_urlencoded::to_string(query).unwrap()
    );
    let response = server.get(auth_url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    let execution_id = TestHarness::extract_query_param(location, "execution_id").unwrap();

    let realm_query =
        serde_urlencoded::to_string([("realm", fixture.realm.name.as_str())]).unwrap();
    let login = server
        .post(format!("{}/api/v1/auth/login?{realm_query}", server.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, TestHarness::flow_cookie(&execution_id))
        .json(&json!({
            "execution_id": execution_id,
            "username": fixture.user.username.as_str(),
            "password": PASSWORD,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login = response_json(login).await;
    let code = login["code"].as_str().unwrap().to_string();

    let token_url = server.realm_url(
        fixture.realm.name.as_str(),
        &["protocol", "openid-connect", "token"],
        false,
    );
    let token_htu = server.realm_url(
        fixture.realm.name.as_str(),
        &["protocol", "openid-connect", "token"],
        true,
    );
    let form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", fixture.client.client_id.as_str()),
        ("client_secret", fixture.client.secret.as_deref().unwrap_or("")),
        ("code_verifier", CODE_VERIFIER),
    ];
    let body = serde_urlencoded::to_string(form).unwrap();
    let mut nonce = None;
    let mut token_response = None;
    for _ in 0..2 {
        let mut request = server
            .post(&token_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.clone());
        if let Some(key) = dpop_key {
            let mut opts = ProofOpts::new("POST", &token_htu);
            opts.nonce = nonce.clone();
            request = request.header("DPoP", key.proof(&opts));
        }
        let response = request.send().await.unwrap();
        if response.status() == StatusCode::OK {
            token_response = Some(response);
            break;
        }
        let next_nonce = response
            .headers()
            .get("dpop-nonce")
            .map(|value| value.to_str().unwrap().to_string());
        let status = response.status();
        let error = response_json(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "token issuance failed: {error}");
        assert_eq!(error["error"], "use_dpop_nonce", "token issuance failed: {error}");
        nonce = Some(next_nonce.expect("nonce challenge must carry a nonce"));
    }
    let response = token_response.expect("DPoP token nonce retry did not succeed");
    let token = response_json(response).await;
    let access_token = token["access_token"].as_str().unwrap().to_string();
    let claims = decode_jwt(&access_token);
    if let Some(key) = dpop_key {
        assert_eq!(token["token_type"], "DPoP");
        assert_eq!(claims["cnf"]["jkt"], key.jkt());
    }
    let session_id = claims["sid"].as_str().expect("interactive token sid").to_string();
    let session = server
        .state
        .storage
        .get_user_session(&fixture.realm.id, &SessionId::new(&session_id).unwrap())
        .await
        .unwrap();
    assert!(session.is_some(), "authorization-code login must persist its session");
    IssuedToken {
        access_token,
        claims,
        session_id,
    }
}

async fn mint_variant(
    server: &Loopback,
    fixture: &Fixture,
    issued: &IssuedToken,
    scope: &str,
    resource: Option<&str>,
    audience: Option<Vec<String>>,
) -> String {
    let roles = issued.claims["realm_access"]["roles"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|role| RoleName::new(role.as_str().unwrap()).unwrap())
        .collect();
    let mut overlay = serde_json::Map::new();
    let audience = audience.unwrap_or_else(|| {
        let mut values = vec![fixture.client.client_id.to_string()];
        if let Some(resource) = resource {
            values.push(resource.to_string());
        }
        values
    });
    overlay.insert("aud".to_string(), json!(audience));
    if let Some(resource) = resource {
        overlay.insert("resource".to_string(), json!(resource));
    }
    server
        .state
        .token_manager
        .issue_access_token_with_roles(
            &fixture.user,
            &fixture.client,
            &fixture.realm,
            &[scope.to_string()],
            &SessionId::new(&issued.session_id).unwrap(),
            Some(RealmAccess { roles }),
            None,
            Some(overlay),
        )
        .await
        .unwrap()
        .token
}

fn dpop_proof(
    server: &Loopback,
    realm: &str,
    access_token: &str,
    key: &DpopKey,
    nonce: Option<&str>,
) -> String {
    let mut opts = ProofOpts::new("POST", server.resource(realm));
    opts.ath = Some(access_token.to_string());
    opts.nonce = nonce.map(str::to_string);
    key.proof(&opts)
}

async fn call_dpop(
    server: &Loopback,
    fixture: &Fixture,
    access_token: &str,
    key: &DpopKey,
    tool: &str,
    arguments: Value,
    nonce: Option<&str>,
) -> reqwest::Response {
    let realm = fixture.realm.name.as_str();
    let proof = dpop_proof(server, realm, access_token, key, nonce);
    let mut options = tool_options(tool, access_token, false);
    options.authorization = Some(format!("DPoP {access_token}"));
    options.proofs = vec![proof];
    send_mcp(server, realm, tool_request(tool, arguments, false), options).await
}

fn modern_meta() -> RequestMetaObject {
    let mut meta = RequestMetaObject::new();
    meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
    meta.set_client_info(rmcp::model::Implementation::new("integration", "1"));
    meta.set_client_capabilities(Default::default());
    meta
}

async fn rmcp_client(
    server: &Loopback,
    fixture: &Fixture,
    token: &str,
    version: ProtocolVersion,
    lifecycle: ClientLifecycleMode,
) -> RunningService<RoleClient, ClientConfig> {
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(server.mcp_url(fixture.realm.name.as_str()))
            .auth_header(token),
    );
    ClientConfig::default()
        .with_protocol_version(version)
        .serve_with_lifecycle(transport, lifecycle)
        .await
        .unwrap()
}

fn assert_peer_info(info: &ServerPeerInfo, version: ProtocolVersion) {
    assert_eq!(info.protocol_version, version);
    let server_info = info.server_info.as_ref().unwrap();
    assert_eq!(server_info.name, "issuerd");
    assert_eq!(server_info.version, env!("CARGO_PKG_VERSION"));
    let tools = info.capabilities.tools.as_ref().unwrap();
    assert_eq!(tools.list_changed, None);
    assert!(info.capabilities.resources.is_none());
    assert!(info.capabilities.prompts.is_none());
}

fn output_schemas(list: &ListToolsResult) -> HashMap<String, Value> {
    list.tools
        .iter()
        .map(|tool| {
            (
                tool.name.to_string(),
                Value::Object(tool.output_schema.as_ref().unwrap().as_ref().clone()),
            )
        })
        .collect()
}

fn assert_tool_result(result: &CallToolResult, schema: &Value, modern: bool) {
    assert_eq!(result.is_error, Some(false));
    if modern {
        assert_eq!(result.result_type, Some(ResultType::COMPLETE));
    } else {
        assert_eq!(result.result_type, None);
    }
    let structured = result.structured_content.as_ref().unwrap();
    assert_schema(schema, schema, structured);
    let mirror = result.content[0].as_text().unwrap();
    let mirrored: Value = serde_json::from_str(&mirror.text).unwrap();
    assert_eq!(&mirrored, structured);
}

async fn exercise_all_tools(
    server: &Loopback,
    client: &RunningService<RoleClient, ClientConfig>,
    fixture: &Fixture,
    modern: bool,
) {
    let list = client.list_tools(None).await.unwrap();
    let names: Vec<_> = list.tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(names, TOOL_NAMES);
    if modern {
        assert_eq!(list.result_type, Some(ResultType::COMPLETE));
        assert_eq!(list.ttl_ms, Some(0));
        assert_eq!(list.cache_scope, Some(CacheScope::Private));
    } else {
        assert_eq!(list.result_type, None);
        assert_eq!(list.ttl_ms, None);
        assert_eq!(list.cache_scope, None);
    }
    let group_id = create_group(server, fixture, &fixture.user, &unique("mcp-group")).await;
    server
        .state
        .storage
        .create_identity_provider(
            &fixture.realm.id,
            &IdentityProviderConfig {
                id: IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap(),
                alias: Alias::new("mcp-idp").unwrap(),
                provider_id: ProviderId::new("oidc"),
                enabled: true,
                config: HashMap::from([
                    ("clientId".to_string(), "public-client".to_string()),
                    ("clientSecret".to_string(), "mcp-secret-canary".to_string()),
                ]),
            },
        )
        .await
        .unwrap();
    let schemas = output_schemas(&list);
    let calls = [
        ("attack_detection_status", json!({"id":fixture.user.id.to_string()})),
        ("client_scopes_list", json!({})),
        ("events_search", json!({})),
        ("events_search", json!({"admin":true})),
        ("flows_list", json!({})),
        ("idp_list", json!({})),
        ("idp_get", json!({"name":"mcp-idp"})),
        ("keys_list", json!({})),
        ("serverinfo_get", json!({})),
        ("sessions_list", json!({})),
        ("realm_get", json!({})),
        ("users_search", json!({"username":fixture.user.username.as_str()})),
        ("users_get", json!({"id":fixture.user.id.to_string()})),
        ("users_get_credentials", json!({"id":fixture.user.id.to_string()})),
        ("users_get_groups", json!({"id":fixture.user.id.to_string()})),
        ("users_get_role_mappings", json!({"id":fixture.user.id.to_string()})),
        ("users_get_sessions", json!({"id":fixture.user.id.to_string()})),
        ("clients_list", json!({"clientId":fixture.client.client_id.as_str()})),
        ("clients_get", json!({"id":fixture.client.id.to_string()})),
        ("groups_list", json!({})),
        ("groups_get", json!({"id":group_id})),
        ("groups_members", json!({"id":group_id})),
        ("roles_list", json!({})),
        ("roles_get", json!({"name":"view-realm"})),
    ];
    for (tool, arguments) in calls {
        let params =
            CallToolRequestParams::new(tool).with_arguments(arguments.as_object().unwrap().clone());
        let result = client.call_tool(params).await.unwrap();
        assert_tool_result(&result, &schemas[tool], modern);
    }
}

fn assert_schema(root: &Value, schema: &Value, value: &Value) {
    if let Some(reference) = schema["$ref"].as_str() {
        let target =
            reference.strip_prefix("#/").unwrap().split('/').fold(root, |current, segment| {
                current
                    .get(segment.replace("~1", "/").replace("~0", "~"))
                    .unwrap_or(&Value::Null)
            });
        assert_schema(root, target, value);
        return;
    }
    if let Some(all_of) = schema["allOf"].as_array() {
        for part in all_of {
            assert_schema(root, part, value);
        }
    }
    if let Some(any_of) = schema["anyOf"].as_array() {
        assert!(
            any_of.iter().any(|part| matches_schema_type(part, value)),
            "{schema} vs {value}"
        );
    }
    if let Some(one_of) = schema["oneOf"].as_array() {
        assert_eq!(one_of.iter().filter(|part| matches_schema_type(part, value)).count(), 1);
    }
    assert!(matches_schema_type(schema, value), "{schema} vs {value}");
    if let Some(object) = value.as_object() {
        for required in schema["required"].as_array().into_iter().flatten() {
            assert!(object.contains_key(required.as_str().unwrap()), "missing {required}");
        }
        if schema["additionalProperties"] == false {
            let properties = schema["properties"].as_object();
            assert!(object
                .keys()
                .all(|key| { properties.is_some_and(|properties| properties.contains_key(key)) }));
        }
        for (key, property_schema) in schema["properties"].as_object().into_iter().flatten() {
            if let Some(property) = object.get(key) {
                assert_schema(root, property_schema, property);
            }
        }
    }
    if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
        for item in array {
            assert_schema(root, items, item);
        }
    }
}

fn matches_schema_type(schema: &Value, value: &Value) -> bool {
    match schema["type"].as_str() {
        Some("object") => value.is_object(),
        Some("array") => value.is_array(),
        Some("string") => value.is_string(),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.is_i64() || value.is_u64(),
        Some("number") => value.is_number(),
        Some("null") => value.is_null(),
        Some(_) => true,
        None => schema["type"].as_array().is_none_or(|types| {
            types.iter().any(|kind| matches_schema_type(&json!({"type":kind}), value))
        }),
    }
}

#[tokio::test]
async fn rmcp_legacy_lifecycles_cover_both_versions_and_all_tools() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "legacy", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;

    for version in LEGACY_VERSIONS {
        let client = rmcp_client(
            &server,
            &fixture,
            &issued.access_token,
            version.clone(),
            ClientLifecycleMode::Initialize,
        )
        .await;
        assert_peer_info(&client.peer_info().unwrap(), version);
        exercise_all_tools(&server, &client, &fixture, false).await;
        client.cancel().await.unwrap();
    }
}

#[tokio::test]
async fn rmcp_modern_discover_covers_versions_hints_and_all_tools() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "modern", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let client = rmcp_client(
        &server,
        &fixture,
        &issued.access_token,
        ProtocolVersion::V_2026_07_28,
        ClientLifecycleMode::Discover {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        },
    )
    .await;
    assert_peer_info(&client.peer_info().unwrap(), ProtocolVersion::V_2026_07_28);

    let discovery = client.discover(modern_meta()).await.unwrap();
    assert_eq!(discovery.result_type, ResultType::COMPLETE);
    assert_eq!(
        discovery.supported_versions,
        [
            ProtocolVersion::V_2025_06_18,
            ProtocolVersion::V_2025_11_25,
            ProtocolVersion::V_2026_07_28,
        ]
    );
    assert_eq!(discovery.ttl_ms, 0);
    assert_eq!(discovery.cache_scope, CacheScope::Private);
    assert_eq!(discovery.server_info().unwrap().name, "issuerd");
    assert_eq!(discovery.capabilities.tools.unwrap().list_changed, None);
    exercise_all_tools(&server, &client, &fixture, true).await;
    client.cancel().await.unwrap();
}

async fn assert_rpc_error(response: reqwest::Response, status: StatusCode, code: i32) -> Value {
    assert_eq!(response.status(), status);
    assert_no_session_id(&response);
    assert_no_store(&response);
    let body = response_json(response).await;
    assert_eq!(body["error"]["code"], code, "{body}");
    body
}

async fn assert_oauth_error(
    response: reqwest::Response,
    status: StatusCode,
    scheme: &str,
    error: &str,
) -> String {
    assert_eq!(response.status(), status);
    assert_no_store(&response);
    let challenges = header_values(&response, header::WWW_AUTHENTICATE);
    assert_eq!(challenges.len(), 1, "{challenges:?}");
    assert!(challenges[0].starts_with(&format!("{scheme} ")), "{challenges:?}");
    assert!(challenges[0].contains(&format!("error=\"{error}\"")), "{challenges:?}");
    let body = response_json(response).await;
    assert_eq!(body["error"], error, "{body}");
    challenges.into_iter().next().unwrap()
}

async fn assert_plain_forbidden(response: reqwest::Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert!(response.bytes().await.unwrap().is_empty());
}

fn dpop_algs() -> String {
    issuerd_core::Algorithm::DPOP_SIGNING_ALG_VALUES_SUPPORTED
        .iter()
        .map(|algorithm| algorithm.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::test]
async fn disabled_feature_is_a_uniform_404() {
    let server = spawn_server(ServerOptions {
        enabled: false,
        ..ServerOptions::default()
    })
    .await;
    let response = send_mcp(
        &server,
        "master",
        legacy_request("tools/list", json!({})),
        RequestOptions::legacy(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_no_session_id(&response);
}

#[tokio::test]
async fn legacy_initialize_and_initialized_have_no_session_ids() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "handshake", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let realm = fixture.realm.name.as_str();

    for version in LEGACY_VERSIONS {
        let initialize = json!({
            "jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":version.as_str(),
                "capabilities":{},
                "clientInfo":{"name":"raw-integration","version":"1"}
            }
        })
        .to_string();
        let mut options = RequestOptions::bearer(&issued.access_token);
        options.version = Some(version.as_str().to_string());
        let response = send_mcp(&server, realm, initialize, options).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_session_id(&response);
        assert!(response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json"));
        let body = response_json(response).await;
        assert_eq!(body["result"]["protocolVersion"], version.as_str());
        assert_eq!(body["result"]["serverInfo"]["name"], "issuerd");
        assert!(body["result"].get("resultType").is_none());

        let mut options = RequestOptions::bearer(&issued.access_token);
        options.version = Some(version.as_str().to_string());
        let response = send_mcp(
            &server,
            realm,
            legacy_request("notifications/initialized", json!({})).replace(r#""id":1,"#, ""),
            options,
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_no_session_id(&response);
        assert!(response.bytes().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn no_credential_challenges_are_exact_and_bodyless() {
    for require_dpop in [true, false] {
        let server = spawn_server(ServerOptions {
            require_dpop,
            ..ServerOptions::default()
        })
        .await;
        let response = send_mcp(
            &server,
            "master",
            legacy_request("tools/list", json!({})),
            RequestOptions::legacy(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_no_store(&response);
        let actual = header_values(&response, header::WWW_AUTHENTICATE);
        let metadata = server.metadata_url("master");
        let bearer = format!("Bearer resource_metadata=\"{metadata}\", scope=\"mcp:read\"");
        let dpop = format!(
            "DPoP resource_metadata=\"{metadata}\", algs=\"{}\", scope=\"mcp:read\"",
            dpop_algs()
        );
        let expected = if require_dpop {
            vec![dpop]
        } else {
            vec![bearer, dpop]
        };
        assert_eq!(actual, expected);
        assert!(response.bytes().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn origin_host_methods_and_last_event_id_follow_stateless_transport() {
    let server = spawn_server(ServerOptions {
        allowed_origins: vec!["https://client.example".to_string()],
        ..ServerOptions::default()
    })
    .await;
    let fixture = make_fixture(&server, "transport", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let realm = fixture.realm.name.as_str();

    let mut options = RequestOptions::legacy();
    options.origin = Some("https://attacker.example".to_string());
    let response = send_mcp(&server, realm, legacy_request("tools/list", json!({})), options).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    for origin in [None, Some("https://client.example")] {
        let mut options = RequestOptions::bearer(&issued.access_token);
        options.origin = origin.map(str::to_string);
        let response =
            send_mcp(&server, realm, legacy_request("tools/list", json!({})), options).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_session_id(&response);
    }

    let mut options = RequestOptions::legacy();
    options.host = Some("attacker.example".to_string());
    let response = send_mcp(&server, realm, legacy_request("tools/list", json!({})), options).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    for method in [Method::GET, Method::DELETE] {
        let response = server
            .request(method, server.mcp_url(realm))
            .header("Last-Event-ID", "not-a-session")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "POST");
        assert_no_session_id(&response);
    }

    let mut options = RequestOptions::bearer(&issued.access_token);
    options.last_event_id = Some("not-a-session".to_string());
    let response = send_mcp(&server, realm, legacy_request("tools/list", json!({})), options).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_session_id(&response);
    let body = response_json(response).await;
    assert_eq!(body["result"]["tools"].as_array().unwrap().len(), 23);
}

#[tokio::test]
async fn host_default_port_accepts_authenticated_requests_with_or_without_explicit_port() {
    let server = spawn_server(ServerOptions {
        issuer_url: Some("http://issuer.example".to_string()),
        ..ServerOptions::default()
    })
    .await;
    let fixture = make_fixture(&server, "default-port", &["view-realm"]).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    for host in ["issuer.example", "issuer.example:80"] {
        let mut options = tool_options("realm_get", &issued.access_token, false);
        options.host = Some(host.to_string());
        let response = send_mcp(
            &server,
            fixture.realm.name.as_str(),
            tool_request("realm_get", json!({}), false),
            options,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "Host: {host}");
        assert_eq!(response_json(response).await["result"]["isError"], false);
    }

    let mut options = RequestOptions::legacy();
    options.host = Some("issuer.example:81".to_string());
    let response = send_mcp(
        &server,
        fixture.realm.name.as_str(),
        legacy_request("tools/list", json!({})),
        options,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn non_default_missing_host_port_precedes_dpop_and_invocation_accounting() {
    let server = spawn_server(ServerOptions {
        issuer_url: Some("http://issuer.example:8080".to_string()),
        require_dpop: true,
        invocation_rate_limit: 1,
        ..ServerOptions::default()
    })
    .await;
    let fixture = make_fixture(&server, "non-default-port", &["view-realm"]).await;
    let key = DpopKey::new();
    let issued = issue_token(&server, &fixture, "openid mcp:read", Some(&key), true).await;
    let realm = fixture.realm.name.as_str();
    let proof = dpop_proof(&server, realm, &issued.access_token, &key, None);

    let mut options = tool_options("realm_get", &issued.access_token, false);
    options.authorization = Some(format!("DPoP {}", issued.access_token));
    options.proofs = vec![proof.clone()];
    options.host = Some("issuer.example".to_string());
    let response =
        send_mcp(&server, realm, tool_request("realm_get", json!({}), false), options).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut options = tool_options("realm_get", &issued.access_token, false);
    options.authorization = Some(format!("DPoP {}", issued.access_token));
    options.proofs = vec![proof];
    options.host = Some("issuer.example:8080".to_string());
    let response =
        send_mcp(&server, realm, tool_request("realm_get", json!({}), false), options).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "early Host rejection must not burn the proof or invocation allowance"
    );
    assert_eq!(response_json(response).await["result"]["isError"], false);
}

#[tokio::test]
async fn case_insensitive_content_type_and_split_accept_succeed_end_to_end() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "media-headers", &["view-realm"]).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let mut options = tool_options("realm_get", &issued.access_token, false);
    options.content_type = Some("Application/JSON".to_string());
    options.accepts = Some(vec![
        "application/json".to_string(),
        "text/event-stream".to_string(),
    ]);
    let response = send_mcp(
        &server,
        fixture.realm.name.as_str(),
        tool_request("realm_get", json!({}), false),
        options,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["result"]["isError"], false);
}

#[tokio::test]
async fn structural_errors_precede_authentication() {
    let server = spawn_server(ServerOptions::default()).await;

    let mut options = RequestOptions::legacy();
    options.version = Some("2025-03-26".to_string());
    let body = assert_rpc_error(
        send_mcp(&server, "master", legacy_request("tools/list", json!({})), options).await,
        StatusCode::BAD_REQUEST,
        -32022,
    )
    .await;
    assert_eq!(body["error"]["data"]["requested"], "2025-03-26");
    assert_eq!(
        body["error"]["data"]["supported"],
        json!(["2025-06-18", "2025-11-25", "2026-07-28"])
    );

    let unsupported = modern_request("tools/list", json!({})).replace("2026-07-28", "2099-01-01");
    let mut options = RequestOptions::modern("tools/list");
    options.version = Some("2099-01-01".to_string());
    assert_rpc_error(
        send_mcp(&server, "master", unsupported, options).await,
        StatusCode::BAD_REQUEST,
        -32022,
    )
    .await;

    let missing_meta = legacy_request("tools/list", json!({}));
    assert_rpc_error(
        send_mcp(&server, "master", missing_meta, RequestOptions::modern("tools/list")).await,
        StatusCode::BAD_REQUEST,
        -32602,
    )
    .await;

    let missing_capabilities = modern_request("tools/list", json!({}))
        .replace(r#""io.modelcontextprotocol/clientCapabilities":{}"#, r#""other":true"#);
    assert_rpc_error(
        send_mcp(&server, "master", missing_capabilities, RequestOptions::modern("tools/list"))
            .await,
        StatusCode::BAD_REQUEST,
        -32602,
    )
    .await;

    let modern_list = modern_request("tools/list", json!({}));
    let modern_call = modern_request("tools/call", json!({"name":"realm_get","arguments":{}}));
    let mut cases = Vec::new();
    let mut missing_version = RequestOptions::modern("tools/list");
    missing_version.version = None;
    cases.push((modern_list.clone(), missing_version));
    let mut missing_method = RequestOptions::modern("tools/list");
    missing_method.method = None;
    cases.push((modern_list.clone(), missing_method));
    cases.push((modern_list, RequestOptions::modern("tools/call")));
    cases.push((modern_call.clone(), RequestOptions::modern("tools/call")));
    let mut wrong_name = RequestOptions::modern("tools/call");
    wrong_name.name = Some("users_get".to_string());
    cases.push((modern_call, wrong_name));
    for (body, options) in cases {
        assert_rpc_error(
            send_mcp(&server, "master", body, options).await,
            StatusCode::BAD_REQUEST,
            -32020,
        )
        .await;
    }

    let duplicate = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"realm_get","arguments":{"nested":{"x":1,"x":2}}}}"#;
    assert_rpc_error(
        send_mcp(&server, "master", duplicate, RequestOptions::legacy()).await,
        StatusCode::BAD_REQUEST,
        -32700,
    )
    .await;
}

#[tokio::test]
async fn modern_malformed_and_unknown_methods_are_method_not_found() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "unknown-methods", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    for method in ["malformed", "unknown/method"] {
        let mut options = RequestOptions::modern(method);
        options.authorization = Some(format!("Bearer {}", issued.access_token));
        assert_rpc_error(
            send_mcp(
                &server,
                fixture.realm.name.as_str(),
                modern_request(method, json!({})),
                options,
            )
            .await,
            StatusCode::NOT_FOUND,
            -32601,
        )
        .await;
    }
}

struct TaskAbortGuard(tokio::task::JoinHandle<()>);

impl Drop for TaskAbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn separate_rmcp_service_emits_real_sse_when_json_mode_is_off() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let cancellation = CancellationToken::new();
    let transport = issuerd_mcp::transport::McpTransportConfig::for_issuer(
        &base_url,
        Vec::new(),
        cancellation.clone(),
    )
    .unwrap();
    let config = issuerd_mcp::transport::streamable_http_config(&transport)
        .with_json_response(false)
        .with_sse_keep_alive(None);
    let storage: Arc<dyn Storage> = Arc::new(issuerd_storage::InMemoryStorage::new());
    let executor = Arc::new(issuerd_mcp::McpToolExecutor::new(
        storage,
        issuerd_mcp::McpRateLimiter::new(Arc::new(issuerd_cluster::InMemoryCache::new()), 60),
    ));
    let service: StreamableHttpService<issuerd_mcp::IssuerdMcpServer, NeverSessionManager> =
        StreamableHttpService::new(
            move || Ok(issuerd_mcp::IssuerdMcpServer::new(Arc::clone(&executor))),
            Arc::new(NeverSessionManager::default()),
            config,
        );
    let app = axum::Router::new().nest_service("/mcp", service);
    let task = TaskAbortGuard(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }));

    let response = reqwest::Client::new()
        .post(format!("{base_url}/mcp"))
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::CONTENT_TYPE, "application/json")
        .header("MCP-Protocol-Version", "2025-11-25")
        .body(
            json!({
                "jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":"2025-11-25",
                    "capabilities":{},
                    "clientInfo":{"name":"sse-integration","version":"1"}
                }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_session_id(&response);
    assert!(response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    let body = response.text().await.unwrap();
    let data = body
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .expect("SSE response must carry a JSON-RPC data event");
    let message: Value = serde_json::from_str(data).unwrap();
    assert_eq!(message["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(message["result"]["serverInfo"]["name"], "issuerd");
    drop(task);
}

#[tokio::test]
async fn rmcp_tools_are_filtered_by_each_role_family_and_scope() {
    let server = spawn_server(ServerOptions::default()).await;
    let realm_tools = &[
        "events_search",
        "flows_list",
        "groups_get",
        "groups_list",
        "idp_get",
        "idp_list",
        "keys_list",
        "realm_get",
        "roles_get",
        "roles_list",
        "serverinfo_get",
        "sessions_list",
    ][..];
    let user_tools = &[
        "groups_members",
        "users_get",
        "users_get_credentials",
        "users_get_groups",
        "users_get_role_mappings",
        "users_get_sessions",
        "users_search",
    ][..];
    let manage_user_tools = &[
        "attack_detection_status",
        "groups_members",
        "users_get",
        "users_get_credentials",
        "users_get_groups",
        "users_get_role_mappings",
        "users_get_sessions",
        "users_search",
    ][..];
    let cases: [(&str, &[&str]); 6] = [
        ("view-realm", realm_tools),
        ("manage-realm", realm_tools),
        ("view-users", user_tools),
        ("manage-users", manage_user_tools),
        ("view-clients", &["client_scopes_list", "clients_get", "clients_list"]),
        ("manage-clients", &["client_scopes_list", "clients_get", "clients_list"]),
    ];
    for (role, expected) in cases {
        let fixture = make_fixture(&server, &unique("filter"), &[role]).await;
        let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
        let client = rmcp_client(
            &server,
            &fixture,
            &issued.access_token,
            ProtocolVersion::V_2025_11_25,
            ClientLifecycleMode::Initialize,
        )
        .await;
        let list = client.list_tools(None).await.unwrap();
        let names: Vec<_> = list.tools.iter().map(|tool| tool.name.as_ref()).collect();
        assert_eq!(names, expected, "role: {role}");
        client.cancel().await.unwrap();
    }

    let fixture = make_fixture(&server, "scope-filter", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &fixture, "openid", None, true).await;
    let client = rmcp_client(
        &server,
        &fixture,
        &issued.access_token,
        ProtocolVersion::V_2025_11_25,
        ClientLifecycleMode::Initialize,
    )
    .await;
    assert!(client.list_tools(None).await.unwrap().tools.is_empty());
    client.cancel().await.unwrap();
}

fn call_arguments(fixture: &Fixture, tool: &str) -> Value {
    match tool {
        "realm_get" => json!({}),
        "users_search" => json!({"username":fixture.user.username.as_str()}),
        "attack_detection_status"
        | "users_get"
        | "users_get_credentials"
        | "users_get_groups"
        | "users_get_role_mappings"
        | "users_get_sessions" => json!({"id":fixture.user.id.to_string()}),
        "clients_list" => json!({"clientId":fixture.client.client_id.as_str()}),
        "clients_get" => json!({"id":fixture.client.id.to_string()}),
        "groups_list" | "roles_list" => json!({}),
        "client_scopes_list" | "events_search" | "flows_list" | "idp_list" | "keys_list"
        | "serverinfo_get" | "sessions_list" => json!({}),
        "idp_get" => json!({"name":"mcp-idp"}),
        "groups_get" | "groups_members" => {
            json!({"id":"00000000-0000-4000-8000-000000000000"})
        }
        "roles_get" => json!({"name":"view-realm"}),
        _ => panic!("unknown tool fixture: {tool}"),
    }
}

#[tokio::test]
async fn every_direct_scope_and_role_denial_has_its_exact_http_mapping() {
    let server = spawn_server(ServerOptions::default()).await;
    let under_scoped = make_fixture(&server, "under-scoped", &ALL_READ_ROLES).await;
    let under_scoped_token = issue_token(&server, &under_scoped, "openid", None, true).await;
    let role_denied = make_fixture(&server, "role-denied", &["unrelated"]).await;
    let role_denied_token = issue_token(&server, &role_denied, "openid mcp:read", None, true).await;

    for tool in TOOL_NAMES {
        let realm = under_scoped.realm.name.as_str();
        let response = send_mcp(
            &server,
            realm,
            tool_request(tool, call_arguments(&under_scoped, tool), false),
            tool_options(tool, &under_scoped_token.access_token, false),
        )
        .await;
        let challenge =
            assert_oauth_error(response, StatusCode::FORBIDDEN, "Bearer", "insufficient_scope")
                .await;
        assert_eq!(
            challenge,
            format!(
                "Bearer error=\"insufficient_scope\", resource_metadata=\"{}\", scope=\"mcp:read\"",
                server.metadata_url(realm)
            ),
            "tool: {tool}"
        );

        let realm = role_denied.realm.name.as_str();
        let response = send_mcp(
            &server,
            realm,
            tool_request(tool, call_arguments(&role_denied, tool), false),
            tool_options(tool, &role_denied_token.access_token, false),
        )
        .await;
        assert_plain_forbidden(response).await;
    }
}

async fn admin_token(server: &Loopback) -> String {
    let response = server
        .post(format!("{}/api/v1/auth/admin-token", server.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&json!({"realm":"master","username":"admin","password":"admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await["access_token"].as_str().unwrap().to_string()
}

async fn admin_json(server: &Loopback, token: &str, path: &str) -> Value {
    let response = server
        .get(format!("{}{path}", server.base_url))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Admin GET {path}");
    response_json(response).await
}

fn assert_selected_fields(actual: &Value, admin: &Value, fields: &[&str]) {
    for field in fields {
        let admin_field = if matches!(
            *field,
            "requiredActions"
                | "internationalizationEnabled"
                | "supportedLocales"
                | "defaultLocale"
                | "registrationEnabled"
                | "resetPasswordAllowed"
                | "rememberMeEnabled"
                | "verifyEmailEnabled"
                | "loginWithEmailAllowed"
                | "duplicateEmailsAllowed"
                | "editUsernameAllowed"
        ) {
            field.to_string()
        } else {
            field.chars().fold(String::new(), |mut output, character| {
                if character.is_uppercase() {
                    output.push('_');
                    output.extend(character.to_lowercase());
                } else {
                    output.push(character);
                }
                output
            })
        };
        assert_eq!(
            actual[*field],
            admin[admin_field.as_str()],
            "selected Admin field {admin_field}"
        );
    }
}

const ROLE_DETAIL_FIELDS: &[&str] = &[
    "id",
    "name",
    "description",
    "composite",
    "composites",
    "clientRole",
    "containerId",
];

fn assert_role_mapping_fields(actual: &Value, expected: &Value) {
    let actual = actual.as_array().unwrap();
    let expected = expected.as_array().unwrap();
    assert_eq!(actual.len(), expected.len());
    for role in actual {
        let admin = expected.iter().find(|candidate| candidate["id"] == role["id"]).unwrap();
        assert_selected_fields(role, admin, ROLE_DETAIL_FIELDS);
    }
}

const REALM_FIELDS: &[&str] = &[
    "displayName",
    "enabled",
    "sslRequired",
    "accessTokenLifespan",
    "refreshTokenLifespan",
    "ssoSessionIdleTimeout",
    "ssoSessionMaxLifespan",
    "offlineSessionIdleTimeout",
    "loginTheme",
    "emailTheme",
    "adminTheme",
    "internationalizationEnabled",
    "supportedLocales",
    "defaultLocale",
    "registrationEnabled",
    "resetPasswordAllowed",
    "rememberMeEnabled",
    "verifyEmailEnabled",
    "loginWithEmailAllowed",
    "duplicateEmailsAllowed",
    "editUsernameAllowed",
];
const USER_FIELDS: &[&str] = &[
    "id",
    "username",
    "email",
    "firstName",
    "lastName",
    "enabled",
    "emailVerified",
    "createdAt",
    "requiredActions",
];
const CLIENT_FIELDS: &[&str] = &[
    "id",
    "clientId",
    "name",
    "description",
    "enabled",
    "protocol",
    "publicClient",
    "bearerOnly",
    "clientAuthenticatorType",
    "redirectUris",
    "webOrigins",
    "defaultScopes",
    "optionalScopes",
    "consentRequired",
    "fullScopeAllowed",
    "serviceAccountsEnabled",
];

async fn create_group(server: &Loopback, fixture: &Fixture, user: &User, name: &str) -> String {
    let id = GroupId::new(issuerd_core::utils::generate_id()).unwrap();
    let group = Group {
        id: id.clone(),
        name: GroupName::new(name).unwrap(),
        path: GroupPath::new(format!("/{name}")).unwrap(),
        realm_id: fixture.realm.id.clone(),
        parent_id: None,
        sub_groups: Vec::new(),
        attributes: HashMap::from([(
            "password".to_string(),
            vec!["GROUP-SECRET-CANARY".to_string()],
        )]),
        realm_roles: Vec::new(),
        client_roles: HashMap::new(),
    };
    server.state.storage.create_group(&fixture.realm.id, &group).await.unwrap();
    server
        .state
        .storage
        .add_user_group(&fixture.realm.id, &user.id, &id)
        .await
        .unwrap();
    id.to_string()
}

#[tokio::test]
async fn all_tools_match_selected_admin_fields_without_secret_channels() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "admin-parity", &ALL_READ_ROLES).await;
    let alice = additional_user(&server, &fixture, "alice").await;
    let alicia = additional_user(&server, &fixture, "alicia").await;
    additional_user(&server, &fixture, "bob").await;
    additional_client(&server, &fixture).await;

    let mut realm = fixture.realm.clone();
    realm.display_name = Some(issuerd_core::DisplayName::new("Curated Realm").unwrap());
    realm.supported_locales = vec!["en".to_string(), "de".to_string()];
    realm.default_locale = Some("en".to_string());
    realm.internationalization_enabled = true;
    realm
        .attributes
        .insert("smtpServer".to_string(), r#"{"password":"SMTP-PASSWORD-CANARY"}"#.to_string());
    realm
        .attributes
        .insert("smtpServer.password".to_string(), "SMTP-PASSWORD-CANARY".to_string());
    realm
        .attributes
        .insert("pairwise_sector_key".to_string(), "PAIRWISE-CANARY".to_string());
    realm
        .attributes
        .insert("customPassword".to_string(), "REALM-CUSTOM-CANARY".to_string());
    server.state.storage.update_realm(&realm).await.unwrap();

    let mut alice_with_secrets = alice.clone();
    alice_with_secrets
        .attributes
        .insert("password".to_string(), vec!["USER-SECRET-CANARY".to_string()]);
    alice_with_secrets
        .attributes
        .insert("custom.secret".to_string(), vec!["USER-SECRET-CANARY".to_string()]);
    server
        .state
        .storage
        .update_user(&alice_with_secrets.realm_id, &alice_with_secrets)
        .await
        .unwrap();
    let alice_roles = Fixture {
        realm: fixture.realm.clone(),
        client: fixture.client.clone(),
        user: alice.clone(),
    };
    add_roles(&server, &alice_roles, &["zeta-role", "alpha-role"]).await;
    for name in ["client-reader", "client-available"] {
        let role = Role {
            id: RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: RoleName::new(name).unwrap(),
            description: Some(format!("{name} description")),
            realm_id: fixture.realm.id.clone(),
            client_role: true,
            client_id: Some(fixture.client.id.clone()),
            composite: false,
            composites: Vec::new(),
            attributes: HashMap::from([(
                "password".to_string(),
                vec!["ROLE-SECRET-CANARY".to_string()],
            )]),
        };
        server.state.storage.create_role(&fixture.realm.id, &role).await.unwrap();
        if name == "client-reader" {
            server
                .state
                .storage
                .add_user_client_role(&fixture.realm.id, &alice.id, &role.id)
                .await
                .unwrap();
        }
    }
    let mut groups = vec![
        create_group(&server, &fixture, &alice, "zeta-group").await,
        create_group(&server, &fixture, &alice, "alpha-group").await,
    ];
    groups.sort();

    let mut client = fixture.client.clone();
    client.secret = Some("CLIENT-SECRET-CANARY".to_string());
    client
        .attributes
        .insert("password".to_string(), "CLIENT-ATTR-CANARY".to_string());
    client
        .attributes
        .insert("custom.secret".to_string(), "CLIENT-ATTR-CANARY".to_string());
    server.state.storage.update_client(&client.realm_id, &client).await.unwrap();
    let fixture = Fixture {
        realm,
        client,
        ..fixture
    };
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let client = rmcp_client(
        &server,
        &fixture,
        &issued.access_token,
        ProtocolVersion::V_2026_07_28,
        ClientLifecycleMode::Discover {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        },
    )
    .await;
    let admin = admin_token(&server).await;
    let realm_name = fixture.realm.name.as_str();
    let mut all_output = Vec::new();

    let result = client.call_tool(CallToolRequestParams::new("realm_get")).await.unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected = admin_json(&server, &admin, &format!("/admin/realms/{realm_name}")).await;
    assert_selected_fields(&output, &expected, REALM_FIELDS);
    assert_eq!(output["id"], fixture.realm.id.to_string());
    assert_eq!(output["realm"], realm_name);
    all_output.push(output);

    let searches = [
        json!({
            "username":format!("  {}  ", alice.username.as_str()),
            "email":"bob@example.com",
            "search":"no-match",
            "first":99,
            "max":0
        }),
        json!({
            "email":format!("  {}  ", alicia.email.as_ref().unwrap()),
            "search":"alice",
            "max":0
        }),
        json!({"search":"ali","first":1,"max":1}),
    ];
    for arguments in searches {
        let result = client
            .call_tool(
                CallToolRequestParams::new("users_search")
                    .with_arguments(arguments.as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        assert_tool_result(
            &result,
            &output_schemas(&client.list_tools(None).await.unwrap())["users_search"],
            true,
        );
        let output = result.structured_content.clone().unwrap();
        let query = serde_urlencoded::to_string(arguments.as_object().unwrap()).unwrap();
        let expected =
            admin_json(&server, &admin, &format!("/admin/realms/{realm_name}/users?{query}")).await;
        let actual_users = output["users"].as_array().unwrap();
        let expected_users = expected.as_array().unwrap();
        assert_eq!(actual_users.len(), expected_users.len(), "arguments: {arguments}");
        for (actual, expected) in actual_users.iter().zip(expected_users) {
            assert_selected_fields(actual, expected, USER_FIELDS);
            assert!(actual.get("realmRoles").is_none());
            assert!(actual.get("groups").is_none());
        }
        all_output.push(output);
    }

    let result = client
        .call_tool(
            CallToolRequestParams::new("users_get")
                .with_arguments(json!({"id":alice.id.to_string()}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected =
        admin_json(&server, &admin, &format!("/admin/realms/{realm_name}/users/{}", alice.id))
            .await;
    assert_selected_fields(&output, &expected, USER_FIELDS);
    let mut actual_roles: Vec<_> = output["realmRoles"].as_array().unwrap().clone();
    actual_roles.sort_by(|left, right| left.as_str().unwrap().cmp(right.as_str().unwrap()));
    let mut expected_roles = expected["realm_roles"].as_array().unwrap().clone();
    expected_roles.sort_by(|left, right| left.as_str().unwrap().cmp(right.as_str().unwrap()));
    assert_eq!(actual_roles, expected_roles);
    assert_eq!(output["groups"], json!(groups));
    all_output.push(output);

    let result = client
        .call_tool(
            CallToolRequestParams::new("users_get_groups")
                .with_arguments(json!({"id":alice.id.to_string()}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected = admin_json(
        &server,
        &admin,
        &format!("/admin/realms/{realm_name}/users/{}/groups", alice.id),
    )
    .await;
    let mut actual_group_ids: Vec<_> = output["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["id"].as_str().unwrap().to_string())
        .collect();
    actual_group_ids.sort();
    let mut expected_group_ids: Vec<_> = expected
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_string())
        .collect();
    expected_group_ids.sort();
    assert_eq!(actual_group_ids, expected_group_ids);
    for group in output["groups"].as_array().unwrap() {
        let expected = admin_json(
            &server,
            &admin,
            &format!("/admin/realms/{realm_name}/groups/{}", group["id"].as_str().unwrap()),
        )
        .await;
        assert_selected_fields(group, &expected, &["id", "name", "path"]);
        assert_eq!(group["parentId"], expected["parent_id"]);
    }
    all_output.push(output);

    let result = client
        .call_tool(
            CallToolRequestParams::new("users_get_role_mappings")
                .with_arguments(json!({"id":alice.id.to_string()}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let output = result.structured_content.clone().unwrap();
    for (field, suffix) in [
        ("realmMappings", "realm"),
        ("availableRealmMappings", "realm/available"),
        ("effectiveRealmMappings", "realm/composite"),
    ] {
        let expected = admin_json(
            &server,
            &admin,
            &format!("/admin/realms/{realm_name}/users/{}/role-mappings/{suffix}", alice.id),
        )
        .await;
        assert_role_mapping_fields(&output[field], &expected);
    }
    let client_mappings = &output["clientMappings"][fixture.client.client_id.as_str()];
    assert_eq!(client_mappings["id"], fixture.client.id.to_string());
    assert_eq!(client_mappings["client"], fixture.client.client_id.to_string());
    for (field, suffix) in [
        ("mappings", ""),
        ("availableMappings", "/available"),
        ("effectiveMappings", "/composite"),
    ] {
        let expected = admin_json(
            &server,
            &admin,
            &format!(
                "/admin/realms/{realm_name}/users/{}/role-mappings/clients/{}{suffix}",
                alice.id, fixture.client.id
            ),
        )
        .await;
        assert_role_mapping_fields(&client_mappings[field], &expected);
    }
    all_output.push(output);

    let result =
        client
            .call_tool(CallToolRequestParams::new("users_get_sessions").with_arguments(
                json!({"id":fixture.user.id.to_string()}).as_object().unwrap().clone(),
            ))
            .await
            .unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected = admin_json(
        &server,
        &admin,
        &format!("/admin/realms/{realm_name}/users/{}/sessions", fixture.user.id),
    )
    .await;
    let sessions = output["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), expected.as_array().unwrap().len());
    assert!(!sessions.is_empty());
    for session in sessions {
        let admin = expected
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["id"] == session["id"])
            .unwrap();
        assert_selected_fields(
            session,
            admin,
            &[
                "id",
                "username",
                "userId",
                "ipAddress",
                "started",
                "lastAccess",
                "offline",
                "clients",
            ],
        );
        for field in [
            "rememberMe",
            "authTime",
            "impersonator",
            "redirectUri",
            "state",
        ] {
            assert!(session.get(field).is_none());
        }
    }
    all_output.push(output);

    let result = client
        .call_tool(
            CallToolRequestParams::new("users_get_credentials")
                .with_arguments(json!({"id":alice.id.to_string()}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected = admin_json(
        &server,
        &admin,
        &format!("/admin/realms/{realm_name}/users/{}/credentials", alice.id),
    )
    .await;
    let credentials = output["credentials"].as_array().unwrap();
    assert_eq!(credentials.len(), expected.as_array().unwrap().len());
    assert!(!credentials.is_empty());
    for credential in credentials {
        let admin = expected
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["id"] == credential["id"])
            .unwrap();
        assert_selected_fields(
            credential,
            admin,
            &[
                "id",
                "type",
                "userLabel",
                "createdDate",
                "priority",
                "temporary",
            ],
        );
        for field in ["secretData", "credentialData", "value"] {
            assert!(credential.get(field).is_none());
        }
    }
    all_output.push(output);

    for (ip, count) in [("192.0.2.1", "4"), ("192.0.2.2", "3")] {
        server
            .state
            .cache
            .set(
                &format!(
                    "login-failure:{}:{}:{ip}",
                    fixture.realm.id,
                    fixture.user.username.as_str()
                ),
                count.as_bytes().to_vec(),
                None,
            )
            .await
            .unwrap();
    }
    server
        .state
        .cache
        .set(
            &format!(
                "login-lockout:{}:{}:192.0.2.1",
                fixture.realm.id,
                fixture.user.username.as_str()
            ),
            b"1".to_vec(),
            None,
        )
        .await
        .unwrap();
    let result =
        client
            .call_tool(CallToolRequestParams::new("attack_detection_status").with_arguments(
                json!({"id":fixture.user.id.to_string()}).as_object().unwrap().clone(),
            ))
            .await
            .unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected = admin_json(
        &server,
        &admin,
        &format!(
            "/admin/realms/{realm_name}/attack-detection/brute-force/users/{}",
            fixture.user.id
        ),
    )
    .await;
    for field in ["userId", "username", "numFailures", "locked"] {
        assert_eq!(output[field], expected[field], "selected Admin field {field}");
    }
    assert_eq!(output["numFailures"], 7);
    assert_eq!(output["locked"], true);
    all_output.push(output);

    let arguments = json!({
        "clientId":format!("  {}  ", fixture.client.client_id.as_str()),
        "first":99,
        "max":0
    });
    let result = client
        .call_tool(
            CallToolRequestParams::new("clients_list")
                .with_arguments(arguments.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let output = result.structured_content.clone().unwrap();
    let query = serde_urlencoded::to_string(arguments.as_object().unwrap()).unwrap();
    let expected =
        admin_json(&server, &admin, &format!("/admin/realms/{realm_name}/clients?{query}")).await;
    assert_eq!(output["clients"].as_array().unwrap().len(), 1);
    assert_eq!(expected.as_array().unwrap().len(), 1);
    assert_selected_fields(&output["clients"][0], &expected[0], CLIENT_FIELDS);
    all_output.push(output);

    let result = client
        .call_tool(CallToolRequestParams::new("clients_get").with_arguments(
            json!({"id":fixture.client.id.to_string()}).as_object().unwrap().clone(),
        ))
        .await
        .unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected = admin_json(
        &server,
        &admin,
        &format!("/admin/realms/{realm_name}/clients/{}", fixture.client.id),
    )
    .await;
    assert_selected_fields(&output, &expected, CLIENT_FIELDS);
    all_output.push(output);

    let result = client.call_tool(CallToolRequestParams::new("groups_list")).await.unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected = admin_json(&server, &admin, &format!("/admin/realms/{realm_name}/groups")).await;
    let actual_groups = output["groups"].as_array().unwrap();
    assert_eq!(actual_groups.len(), expected.as_array().unwrap().len());
    for actual in actual_groups {
        let expected_group = expected
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["id"] == actual["id"])
            .unwrap();
        assert_selected_fields(actual, expected_group, &["id", "name", "path"]);
        assert_eq!(actual["parentId"], expected_group["parent_id"]);
    }
    all_output.push(output);

    let group_id = groups[0].clone();
    let result = client
        .call_tool(
            CallToolRequestParams::new("groups_get")
                .with_arguments(json!({"id":group_id}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected =
        admin_json(&server, &admin, &format!("/admin/realms/{realm_name}/groups/{group_id}")).await;
    assert_selected_fields(&output, &expected, &["id", "name", "path"]);
    assert_eq!(output["parentId"], expected["parent_id"]);
    all_output.push(output);

    let result = client
        .call_tool(
            CallToolRequestParams::new("groups_members")
                .with_arguments(json!({"id":group_id}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected = admin_json(
        &server,
        &admin,
        &format!("/admin/realms/{realm_name}/groups/{group_id}/members"),
    )
    .await;
    let members = output["members"].as_array().unwrap();
    assert_eq!(members.len(), expected.as_array().unwrap().len());
    for (actual, expected) in members.iter().zip(expected.as_array().unwrap()) {
        assert_selected_fields(actual, expected, USER_FIELDS);
    }
    all_output.push(output);

    let result = client.call_tool(CallToolRequestParams::new("roles_list")).await.unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected = admin_json(&server, &admin, &format!("/admin/realms/{realm_name}/roles")).await;
    let actual_roles = output["roles"].as_array().unwrap();
    let expected_roles: Vec<_> = expected
        .as_array()
        .unwrap()
        .iter()
        .filter(|role| role["client_role"] == false)
        .collect();
    assert_eq!(actual_roles.len(), expected_roles.len());
    for actual in actual_roles {
        let expected_role =
            expected_roles.iter().find(|candidate| candidate["id"] == actual["id"]).unwrap();
        assert_selected_fields(
            actual,
            expected_role,
            &["id", "name", "description", "composite", "composites"],
        );
        assert_eq!(actual["clientRole"], expected_role["client_role"]);
        assert_eq!(actual["containerId"], expected_role["container_id"]);
    }
    all_output.push(output);

    let result = client
        .call_tool(
            CallToolRequestParams::new("roles_get")
                .with_arguments(json!({"name":"zeta-role"}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let output = result.structured_content.clone().unwrap();
    let expected =
        admin_json(&server, &admin, &format!("/admin/realms/{realm_name}/roles/zeta-role")).await;
    assert_selected_fields(
        &output,
        &expected,
        &["id", "name", "description", "composite", "composites"],
    );
    assert_eq!(output["clientRole"], expected["client_role"]);
    assert_eq!(output["containerId"], expected["container_id"]);
    all_output.push(output);

    let serialized = Value::Array(all_output).to_string();
    for canary in [
        "SMTP-PASSWORD-CANARY",
        "PAIRWISE-CANARY",
        "REALM-CUSTOM-CANARY",
        "USER-SECRET-CANARY",
        "CLIENT-SECRET-CANARY",
        "CLIENT-ATTR-CANARY",
        "GROUP-SECRET-CANARY",
        "ROLE-SECRET-CANARY",
        "smtpServer",
        "pairwise_sector_key",
        "attributes",
        "protocolMappers",
    ] {
        assert!(!serialized.contains(canary), "MCP leaked {canary}: {serialized}");
    }
    for forbidden_key in [
        "\"secret\":",
        "\"password\":",
        "\"secretData\":",
        "\"credentialData\":",
        "\"secret_data\":",
        "\"credential_data\":",
    ] {
        assert!(
            !serialized.contains(forbidden_key),
            "MCP exposed forbidden key {forbidden_key}: {serialized}"
        );
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn unknown_tool_is_counted_once_before_the_invocation_limit() {
    let server = spawn_server(ServerOptions {
        invocation_rate_limit: 2,
        ..ServerOptions::default()
    })
    .await;
    let fixture = make_fixture(&server, "unknown-count", &["view-realm"]).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let realm = fixture.realm.name.as_str();

    let response = send_mcp(
        &server,
        realm,
        tool_request("not_a_tool", json!({}), false),
        tool_options("not_a_tool", &issued.access_token, false),
    )
    .await;
    assert_rpc_error(response, StatusCode::OK, -32601).await;

    let response = send_mcp(
        &server,
        realm,
        tool_request("realm_get", json!({}), false),
        tool_options("realm_get", &issued.access_token, false),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send_mcp(
        &server,
        realm,
        tool_request("realm_get", json!({}), false),
        tool_options("realm_get", &issued.access_token, false),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key(header::RETRY_AFTER));
    assert_no_store(&response);
}

#[tokio::test]
async fn tool_call_notifications_are_rejected_without_invocation_accounting() {
    for modern in [false, true] {
        let server = spawn_server(ServerOptions {
            invocation_rate_limit: 1,
            ..ServerOptions::default()
        })
        .await;
        let fixture = make_fixture(&server, &unique("tool-notification"), &["view-realm"]).await;
        let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
        let notification = tool_request("realm_get", json!({}), modern).replace(r#""id":1,"#, "");
        let response = send_mcp(
            &server,
            fixture.realm.name.as_str(),
            notification,
            tool_options("realm_get", &issued.access_token, modern),
        )
        .await;
        assert_rpc_error(response, StatusCode::BAD_REQUEST, -32600).await;

        let response = send_mcp(
            &server,
            fixture.realm.name.as_str(),
            tool_request("realm_get", json!({}), modern),
            tool_options("realm_get", &issued.access_token, modern),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "notification consumed the allowance");
        assert_eq!(response_json(response).await["result"]["isError"], false);
    }
}

async fn assert_invalid_bearer_token(server: &Loopback, realm: &str, response: reqwest::Response) {
    let challenge =
        assert_oauth_error(response, StatusCode::UNAUTHORIZED, "Bearer", "invalid_token").await;
    assert_eq!(
        challenge,
        format!(
            "Bearer error=\"invalid_token\", resource_metadata=\"{}\"",
            server.metadata_url(realm)
        )
    );
}

async fn bearer_call(server: &Loopback, fixture: &Fixture, token: &str) -> reqwest::Response {
    send_mcp(
        server,
        fixture.realm.name.as_str(),
        tool_request("realm_get", json!({}), false),
        tool_options("realm_get", token, false),
    )
    .await
}

#[tokio::test]
async fn malformed_revoked_and_session_ended_tokens_are_invalid_token() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "invalid-token", &ALL_READ_ROLES).await;
    assert_invalid_bearer_token(
        &server,
        fixture.realm.name.as_str(),
        bearer_call(&server, &fixture, "not-a-jwt").await,
    )
    .await;

    let revoked_fixture = make_fixture(&server, "revoked-token", &ALL_READ_ROLES).await;
    let revoked = issue_token(&server, &revoked_fixture, "openid mcp:read", None, true).await;
    let revoke_url = server.realm_url(
        revoked_fixture.realm.name.as_str(),
        &["protocol", "openid-connect", "revoke"],
        false,
    );
    let response = server
        .post(revoke_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(
            serde_urlencoded::to_string([
                ("token", revoked.access_token.as_str()),
                ("client_id", revoked_fixture.client.client_id.as_str()),
                ("client_secret", revoked_fixture.client.secret.as_deref().unwrap_or("")),
            ])
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_invalid_bearer_token(
        &server,
        revoked_fixture.realm.name.as_str(),
        bearer_call(&server, &revoked_fixture, &revoked.access_token).await,
    )
    .await;

    let ended_fixture = make_fixture(&server, "ended-session", &ALL_READ_ROLES).await;
    let ended = issue_token(&server, &ended_fixture, "openid mcp:read", None, true).await;
    server
        .state
        .storage
        .delete_user_session(&ended_fixture.realm.id, &SessionId::new(&ended.session_id).unwrap())
        .await
        .unwrap();
    assert_invalid_bearer_token(
        &server,
        ended_fixture.realm.name.as_str(),
        bearer_call(&server, &ended_fixture, &ended.access_token).await,
    )
    .await;
}

#[tokio::test]
async fn audience_resource_and_cross_realm_checks_are_exact() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "audience", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let resource = server.resource(fixture.realm.name.as_str());

    let wrong_audience = mint_variant(
        &server,
        &fixture,
        &issued,
        "openid mcp:read",
        Some(&resource),
        Some(vec![fixture.client.client_id.to_string()]),
    )
    .await;
    assert_invalid_bearer_token(
        &server,
        fixture.realm.name.as_str(),
        bearer_call(&server, &fixture, &wrong_audience).await,
    )
    .await;

    let wrong_resource = format!("{resource}/other");
    let wrong_resource =
        mint_variant(&server, &fixture, &issued, "openid mcp:read", Some(&wrong_resource), None)
            .await;
    assert_invalid_bearer_token(
        &server,
        fixture.realm.name.as_str(),
        bearer_call(&server, &fixture, &wrong_resource).await,
    )
    .await;

    let other = make_fixture(&server, "other-realm", &ALL_READ_ROLES).await;
    let response = send_mcp(
        &server,
        other.realm.name.as_str(),
        tool_request("realm_get", json!({}), false),
        tool_options("realm_get", &issued.access_token, false),
    )
    .await;
    assert_invalid_bearer_token(&server, other.realm.name.as_str(), response).await;
}

#[tokio::test]
async fn mapper_forged_audience_without_trusted_resource_is_invalid_token() {
    let server = spawn_server(ServerOptions::default()).await;
    let mut fixture = make_fixture(&server, "mapper-forged", &ALL_READ_ROLES).await;
    let resource = server.resource(fixture.realm.name.as_str());
    fixture.client.protocol_mappers.push(issuerd_core::ProtocolMapper {
        id: issuerd_core::MapperId::new("mcp-test-audience").unwrap(),
        name: "canonical MCP audience without a resource grant".to_string(),
        mapper_type: issuerd_core::MapperType::Audience,
        config: HashMap::from([(
            issuerd_core::mapper_config::INCLUDED_CUSTOM_AUDIENCE.to_string(),
            resource.clone(),
        )]),
    });
    server
        .state
        .storage
        .update_client(&fixture.client.realm_id, &fixture.client)
        .await
        .unwrap();
    issuerd_cluster::invalidate::invalidate_client_claims(
        server.state.cache.as_ref(),
        &fixture.client.realm_id,
        &fixture.client.id,
        fixture.client.client_id.as_ref(),
    )
    .await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, false).await;
    assert!(issued.claims["aud"]
        .as_array()
        .unwrap()
        .iter()
        .any(|audience| audience == &resource));
    assert!(issued.claims.get("resource").is_none());
    assert_invalid_bearer_token(
        &server,
        fixture.realm.name.as_str(),
        bearer_call(&server, &fixture, &issued.access_token).await,
    )
    .await;
}

#[tokio::test]
async fn disabled_user_and_missing_or_disabled_azp_client_stay_distinct() {
    let server = spawn_server(ServerOptions::default()).await;

    let disabled_user = make_fixture(&server, "disabled-user", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &disabled_user, "openid mcp:read", None, true).await;
    let mut user = disabled_user.user.clone();
    user.enabled = false;
    server.state.storage.update_user(&user.realm_id, &user).await.unwrap();
    assert_plain_forbidden(bearer_call(&server, &disabled_user, &issued.access_token).await).await;

    let missing_client = make_fixture(&server, "missing-client", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &missing_client, "openid mcp:read", None, true).await;
    server
        .state
        .storage
        .delete_client(&missing_client.realm.id, &missing_client.client.id)
        .await
        .unwrap();
    assert_invalid_bearer_token(
        &server,
        missing_client.realm.name.as_str(),
        bearer_call(&server, &missing_client, &issued.access_token).await,
    )
    .await;

    let disabled_client = make_fixture(&server, "disabled-client", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &disabled_client, "openid mcp:read", None, true).await;
    let mut client = disabled_client.client.clone();
    client.enabled = false;
    server.state.storage.update_client(&client.realm_id, &client).await.unwrap();
    assert_plain_forbidden(bearer_call(&server, &disabled_client, &issued.access_token).await)
        .await;
}

#[tokio::test]
async fn unrelated_step_up_scope_has_no_read_authority() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "step-up-only", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let resource = server.resource(fixture.realm.name.as_str());
    let step_up =
        mint_variant(&server, &fixture, &issued, "openid mcp:step_up", Some(&resource), None).await;
    let response = bearer_call(&server, &fixture, &step_up).await;
    let challenge =
        assert_oauth_error(response, StatusCode::FORBIDDEN, "Bearer", "insufficient_scope").await;
    assert_eq!(
        challenge,
        format!(
            "Bearer error=\"insufficient_scope\", resource_metadata=\"{}\", scope=\"mcp:read\"",
            server.metadata_url(fixture.realm.name.as_str())
        )
    );
}

async fn assert_dpop_error(response: reqwest::Response, error: &str) -> String {
    let challenge = assert_oauth_error(response, StatusCode::UNAUTHORIZED, "DPoP", error).await;
    assert!(challenge.contains(&format!("algs=\"{}\"", dpop_algs())), "{challenge}");
    challenge
}

#[tokio::test]
async fn strict_dpop_succeeds_for_every_tool() {
    let server = spawn_server(ServerOptions {
        require_dpop: true,
        ..ServerOptions::default()
    })
    .await;
    let fixture = make_fixture(&server, "strict-tools", &ALL_READ_ROLES).await;
    let key = DpopKey::new();
    let issued = issue_token(&server, &fixture, "openid mcp:read", Some(&key), true).await;
    let group_id = create_group(&server, &fixture, &fixture.user, "strict-tool-group").await;
    server
        .state
        .storage
        .create_identity_provider(
            &fixture.realm.id,
            &IdentityProviderConfig {
                id: IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap(),
                alias: Alias::new("mcp-idp").unwrap(),
                provider_id: ProviderId::new("oidc"),
                enabled: true,
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();

    for tool in TOOL_NAMES {
        let arguments = match tool {
            "groups_get" | "groups_members" => json!({"id":&group_id}),
            _ => call_arguments(&fixture, tool),
        };
        let response =
            call_dpop(&server, &fixture, &issued.access_token, &key, tool, arguments, None).await;
        assert_eq!(response.status(), StatusCode::OK, "tool: {tool}");
        assert_no_session_id(&response);
        assert_no_store(&response);
        assert!(!response.headers().contains_key("dpop-nonce"));
        let body = response_json(response).await;
        assert_eq!(body["result"]["isError"], false, "tool: {tool}: {body}");
    }
}

#[tokio::test]
async fn strict_dpop_rejects_downgrades_bad_proofs_duplicates_and_replay() {
    let server = spawn_server(ServerOptions {
        require_dpop: true,
        ..ServerOptions::default()
    })
    .await;
    let fixture = make_fixture(&server, "strict-negatives", &ALL_READ_ROLES).await;
    let key = DpopKey::new();
    let bound = issue_token(&server, &fixture, "openid mcp:read", Some(&key), true).await;
    let unbound = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let realm = fixture.realm.name.as_str();

    let response = send_mcp(
        &server,
        realm,
        tool_request("realm_get", json!({}), false),
        tool_options("realm_get", &unbound.access_token, false),
    )
    .await;
    assert_dpop_error(response, "invalid_dpop_proof").await;

    let response = send_mcp(
        &server,
        realm,
        tool_request("realm_get", json!({}), false),
        tool_options("realm_get", &bound.access_token, false),
    )
    .await;
    assert_invalid_bearer_token(&server, realm, response).await;

    let mut options = tool_options("realm_get", &unbound.access_token, false);
    options.authorization = Some(format!("DPoP {}", unbound.access_token));
    options.proofs = vec![dpop_proof(
        &server,
        realm,
        &unbound.access_token,
        &key,
        None,
    )];
    let response =
        send_mcp(&server, realm, tool_request("realm_get", json!({}), false), options).await;
    assert_dpop_error(response, "invalid_token").await;

    let mut options = tool_options("realm_get", &bound.access_token, false);
    options.authorization = Some(format!("DPoP {}", bound.access_token));
    let response =
        send_mcp(&server, realm, tool_request("realm_get", json!({}), false), options).await;
    assert_dpop_error(response, "invalid_dpop_proof").await;

    let wrong_key = DpopKey::new();
    let response =
        call_dpop(&server, &fixture, &bound.access_token, &wrong_key, "realm_get", json!({}), None)
            .await;
    assert_dpop_error(response, "invalid_token").await;

    for (htm, htu, ath) in [
        ("GET", server.resource(realm), bound.access_token.clone()),
        (
            "POST",
            server.realm_url(realm, &["protocol", "openid-connect", "token"], true),
            bound.access_token.clone(),
        ),
        ("POST", server.resource(realm), unbound.access_token.clone()),
    ] {
        let mut opts = ProofOpts::new(htm, htu);
        opts.ath = Some(ath);
        let mut options = tool_options("realm_get", &bound.access_token, false);
        options.authorization = Some(format!("DPoP {}", bound.access_token));
        options.proofs = vec![key.proof(&opts)];
        let response =
            send_mcp(&server, realm, tool_request("realm_get", json!({}), false), options).await;
        assert_dpop_error(response, "invalid_dpop_proof").await;
    }

    let proof = dpop_proof(&server, realm, &bound.access_token, &key, None);
    let mut options = tool_options("realm_get", &bound.access_token, false);
    options.authorization = Some(format!("DPoP {}", bound.access_token));
    options.proofs = vec![proof.clone(), proof];
    let response =
        send_mcp(&server, realm, tool_request("realm_get", json!({}), false), options).await;
    assert_dpop_error(response, "invalid_dpop_proof").await;

    let proof = dpop_proof(&server, realm, &bound.access_token, &key, None);
    let mut options = tool_options("realm_get", &bound.access_token, false);
    options.authorization = Some(format!("DPoP {}", bound.access_token));
    options.proofs = vec![proof.clone()];
    let body = tool_request("realm_get", json!({}), false);
    let response = send_mcp(&server, realm, body.clone(), options).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut options = tool_options("realm_get", &bound.access_token, false);
    options.authorization = Some(format!("DPoP {}", bound.access_token));
    options.proofs = vec![proof];
    let response = send_mcp(&server, realm, body, options).await;
    assert_dpop_error(response, "invalid_dpop_proof").await;
}

#[tokio::test]
async fn special_realm_canonical_urls_support_full_dpop_flow() {
    let server = spawn_server(ServerOptions {
        require_dpop: true,
        ..ServerOptions::default()
    })
    .await;
    let fixture = fixture_named(&server, "tenant{one}", "agent", &ALL_READ_ROLES).await;
    let key = DpopKey::new();
    let issued = issue_token(&server, &fixture, "openid mcp:read", Some(&key), true).await;
    let resource = server.resource("tenant{one}");
    assert!(resource.contains("tenant%7Bone%7D"), "{resource}");
    assert!(issued.claims["iss"].as_str().unwrap().contains("tenant%7Bone%7D"));

    let response =
        call_dpop(&server, &fixture, &issued.access_token, &key, "realm_get", json!({}), None)
            .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["result"]["structuredContent"]["realm"], "tenant{one}");
}

#[tokio::test]
async fn dpop_htu_accepts_equivalent_default_port_and_path_encodings() {
    let server = spawn_server(ServerOptions {
        issuer_url: Some("http://issuer.example".to_string()),
        require_dpop: true,
        ..ServerOptions::default()
    })
    .await;
    let fixture = fixture_named(&server, "tenant{one}", "agent", &ALL_READ_ROLES).await;
    let key = DpopKey::new();
    let issued = issue_token(&server, &fixture, "openid mcp:read", Some(&key), true).await;
    for htu in [
        "http://issuer.example:80/realms/tenant%7Bone%7D/mcp",
        "http://issuer.example/realms/tenant{one}/mcp",
        "http://issuer.example/realms/tenant%7bone%7d/mcp",
    ] {
        let mut proof_options = ProofOpts::new("POST", htu);
        proof_options.ath = Some(issued.access_token.to_string());
        let mut options = tool_options("realm_get", &issued.access_token, false);
        options.authorization = Some(format!("DPoP {}", issued.access_token));
        options.proofs = vec![key.proof(&proof_options)];
        let response = send_mcp(
            &server,
            fixture.realm.name.as_str(),
            tool_request("realm_get", json!({}), false),
            options,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "equivalent HTU rejected: {htu}");
        assert_eq!(response_json(response).await["result"]["isError"], false);
    }
}

fn one_nonce(response: &reqwest::Response) -> String {
    let values = header_values(response, header::HeaderName::from_static("dpop-nonce"));
    assert_eq!(values.len(), 1, "expected exactly one DPoP-Nonce: {values:?}");
    values.into_iter().next().unwrap()
}

#[tokio::test]
async fn fresh_nonce_store_failure_is_503_without_tool_accounting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = crate::harness::test_config();
    config.issuer_url = format!("http://{}", listener.local_addr().unwrap());
    config.mcp.enabled = true;
    config.mcp.require_dpop = true;
    config.mcp.invocation_rate_limit_per_minute = 1;
    config.dpop.nonce.mode = DpopNonceMode::Required;
    let storage: Arc<dyn Storage> = Arc::new(issuerd_storage::InMemoryStorage::new());
    let cache = Arc::new(FailSetCache::default());
    let server = spawn_listener(
        listener,
        config,
        Some((storage, cache.clone() as Arc<dyn DistributedCache>)),
    )
    .await;
    let fixture = make_fixture(&server, "nonce-store-failure", &ALL_READ_ROLES).await;
    let key = DpopKey::new();
    let issued = issue_token(&server, &fixture, "openid mcp:read", Some(&key), true).await;

    let response =
        call_dpop(&server, &fixture, &issued.access_token, &key, "realm_get", json!({}), None)
            .await;
    let first_nonce = one_nonce(&response);
    assert_dpop_error(response, "use_dpop_nonce").await;

    cache.fail_sets(true);
    let response = call_dpop(
        &server,
        &fixture,
        &issued.access_token,
        &key,
        "realm_get",
        json!({}),
        Some(&first_nonce),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_store(&response);
    assert!(!response.headers().contains_key("dpop-nonce"));

    cache.fail_sets(false);
    let response =
        call_dpop(&server, &fixture, &issued.access_token, &key, "realm_get", json!({}), None)
            .await;
    let retry_nonce = one_nonce(&response);
    assert_dpop_error(response, "use_dpop_nonce").await;
    let response = call_dpop(
        &server,
        &fixture,
        &issued.access_token,
        &key,
        "realm_get",
        json!({}),
        Some(&retry_nonce),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "503 must not consume the tool allowance");
    assert_eq!(response_json(response).await["result"]["isError"], false);
}

#[tokio::test]
async fn nonce_challenge_store_failures_are_503_without_tool_accounting() {
    for cas_loser in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = crate::harness::test_config();
        config.issuer_url = format!("http://{}", listener.local_addr().unwrap());
        config.mcp.enabled = true;
        config.mcp.require_dpop = true;
        config.mcp.invocation_rate_limit_per_minute = 1;
        config.dpop.nonce.mode = DpopNonceMode::Required;
        let storage: Arc<dyn Storage> = Arc::new(issuerd_storage::InMemoryStorage::new());
        let cache = Arc::new(FailSetCache::default());
        let server = spawn_listener(
            listener,
            config,
            Some((storage, cache.clone() as Arc<dyn DistributedCache>)),
        )
        .await;
        let fixture =
            make_fixture(&server, &unique("nonce-challenge-failure"), &ALL_READ_ROLES).await;
        let key = DpopKey::new();
        let issued = issue_token(&server, &fixture, "openid mcp:read", Some(&key), true).await;

        let nonce = if cas_loser {
            let response = call_dpop(
                &server,
                &fixture,
                &issued.access_token,
                &key,
                "realm_get",
                json!({}),
                None,
            )
            .await;
            let nonce = one_nonce(&response);
            assert_dpop_error(response, "use_dpop_nonce").await;
            Some(nonce)
        } else {
            None
        };
        cache.fail_sets(true);
        cache.fail_compare_and_delete(cas_loser);
        let response = call_dpop(
            &server,
            &fixture,
            &issued.access_token,
            &key,
            "realm_get",
            json!({}),
            nonce.as_deref(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "cas_loser={cas_loser}");
        assert_no_store(&response);
        assert!(!response.headers().contains_key("dpop-nonce"));

        cache.fail_sets(false);
        cache.fail_compare_and_delete(false);
        let response =
            call_dpop(&server, &fixture, &issued.access_token, &key, "realm_get", json!({}), None)
                .await;
        let retry_nonce = one_nonce(&response);
        assert_dpop_error(response, "use_dpop_nonce").await;
        let response = call_dpop(
            &server,
            &fixture,
            &issued.access_token,
            &key,
            "realm_get",
            json!({}),
            Some(&retry_nonce),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "503 consumed the tool allowance");
        assert_eq!(response_json(response).await["result"]["isError"], false);
    }
}

#[tokio::test]
async fn mcp_nonce_supported_and_required_both_require_single_use_nonces() {
    for mode in [DpopNonceMode::Supported, DpopNonceMode::Required] {
        let server = spawn_server(ServerOptions {
            require_dpop: true,
            nonce_mode: mode,
            ..ServerOptions::default()
        })
        .await;
        let fixture = make_fixture(&server, &unique("nonce"), &ALL_READ_ROLES).await;
        let key = DpopKey::new();
        let issued = issue_token(&server, &fixture, "openid mcp:read", Some(&key), true).await;
        let realm = fixture.realm.name.as_str();

        let response =
            call_dpop(&server, &fixture, &issued.access_token, &key, "realm_get", json!({}), None)
                .await;
        let first_nonce = one_nonce(&response);
        assert_no_store(&response);
        assert_dpop_error(response, "use_dpop_nonce").await;

        let proof = dpop_proof(&server, realm, &issued.access_token, &key, Some(&first_nonce));
        let mut options = tool_options("realm_get", &issued.access_token, false);
        options.authorization = Some(format!("DPoP {}", issued.access_token));
        options.proofs = vec![proof.clone()];
        let body = tool_request("realm_get", json!({}), false);
        let response = send_mcp(&server, realm, body.clone(), options).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(&response);
        let second_nonce = one_nonce(&response);
        assert_ne!(second_nonce, first_nonce);
        assert_eq!(response_json(response).await["result"]["isError"], false);

        let response = call_dpop(
            &server,
            &fixture,
            &issued.access_token,
            &key,
            "realm_get",
            json!({"unexpected":true}),
            Some(&second_nonce),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(&response);
        assert!(one_nonce(&response) != second_nonce);
        assert_eq!(response_json(response).await["result"]["isError"], true);

        let response =
            call_dpop(&server, &fixture, &issued.access_token, &key, "realm_get", json!({}), None)
                .await;
        let nonce_after_downgrade = one_nonce(&response);
        assert_ne!(nonce_after_downgrade, second_nonce);
        assert_dpop_error(response, "use_dpop_nonce").await;

        let mut options = tool_options("realm_get", &issued.access_token, false);
        options.authorization = Some(format!("DPoP {}", issued.access_token));
        options.proofs = vec![proof];
        let response = send_mcp(&server, realm, body, options).await;
        assert_dpop_error(response, "use_dpop_nonce").await;

        let response = call_dpop(
            &server,
            &fixture,
            &issued.access_token,
            &key,
            "realm_get",
            json!({}),
            Some(&first_nonce),
        )
        .await;
        let final_nonce = one_nonce(&response);
        assert!(!final_nonce.is_empty());
        assert_no_store(&response);
        assert_dpop_error(response, "use_dpop_nonce").await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alternating_principals_do_not_bleed_through_public_route() {
    let server = spawn_server(ServerOptions::default()).await;
    let realm_fixture = make_fixture(&server, "concurrent-realm", &["view-realm"]).await;
    let realm_token = issue_token(&server, &realm_fixture, "openid mcp:read", None, true).await;
    let reader = additional_user(&server, &realm_fixture, "client-reader").await;
    let client_fixture = Fixture {
        realm: realm_fixture.realm.clone(),
        client: realm_fixture.client.clone(),
        user: reader,
    };
    add_roles(&server, &client_fixture, &["view-clients"]).await;
    let client_token = issue_token(&server, &client_fixture, "openid mcp:read", None, true).await;
    let realm = realm_fixture.realm.name.to_string();
    let exact_client = realm_fixture.client.client_id.to_string();
    assert!(realm_token.claims["realm_access"]["roles"]
        .as_array()
        .unwrap()
        .contains(&json!("view-realm")));
    assert!(client_token.claims["realm_access"]["roles"]
        .as_array()
        .unwrap()
        .contains(&json!("view-clients")));

    let requests = (0..16).map(|index| {
        let server = &server;
        let realm = &realm;
        let realm_token = &realm_token.access_token;
        let client_token = &client_token.access_token;
        let exact_client = &exact_client;
        async move {
            let even = index % 2 == 0;
            let (tool, token, arguments) = if even {
                ("realm_get", realm_token, json!({}))
            } else {
                ("clients_list", client_token, json!({"clientId":exact_client}))
            };
            let body = json!({
                "jsonrpc":"2.0","id":index,"method":"tools/call",
                "params":{"name":tool,"arguments":arguments}
            })
            .to_string();
            let response = send_mcp(server, realm, body, tool_options(tool, token, false)).await;
            let status = response.status();
            if status != StatusCode::OK {
                let bytes = response.bytes().await.unwrap();
                panic!("request {index} (even={even}) returned {status}: {bytes:?}");
            }
            let body = response_json(response).await;
            (index, even, status, body)
        }
    });
    for (index, even, status, body) in futures::future::join_all(requests).await {
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], index);
        assert_eq!(body["result"]["isError"], false, "{body}");
        if even {
            assert_eq!(body["result"]["structuredContent"]["realm"], realm);
        } else {
            assert_eq!(body["result"]["structuredContent"]["clients"][0]["clientId"], exact_client);
        }
    }
}

#[tokio::test]
async fn invocation_limit_is_shared_by_two_real_nodes() {
    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let storage: Arc<dyn Storage> = Arc::new(issuerd_storage::InMemoryStorage::new());
    let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());
    let mut config = crate::harness::test_config();
    config.issuer_url = "http://cluster.example:8080".to_string();
    config.mcp.enabled = true;
    config.mcp.require_dpop = false;
    config.mcp.invocation_rate_limit_per_minute = 1;
    let node_a = spawn_listener(
        listener_a,
        config.clone(),
        Some((Arc::clone(&storage), Arc::clone(&cache))),
    )
    .await;
    let node_b = spawn_listener(listener_b, config, Some((storage, cache))).await;
    let fixture = make_fixture(&node_a, "shared-limit", &["view-realm"]).await;
    let issued = issue_token(&node_a, &fixture, "openid mcp:read", None, true).await;
    let realm = fixture.realm.name.as_str();
    assert!(issued.claims["realm_access"]["roles"]
        .as_array()
        .unwrap()
        .contains(&json!("view-realm")));
    node_b.state.token_service.validate_access_token(&issued.access_token).unwrap();

    let first = send_mcp(
        &node_a,
        realm,
        tool_request("realm_get", json!({}), false),
        tool_options("realm_get", &issued.access_token, false),
    )
    .await;
    if first.status() != StatusCode::OK {
        let status = first.status();
        let bytes = first.bytes().await.unwrap();
        panic!("first node returned {status}: {bytes:?}");
    }
    assert_eq!(response_json(first).await["result"]["isError"], false);

    let second = send_mcp(
        &node_b,
        realm,
        tool_request("realm_get", json!({}), false),
        tool_options("realm_get", &issued.access_token, false),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after =
        second.headers()[header::RETRY_AFTER].to_str().unwrap().parse::<u64>().unwrap();
    assert!(retry_after > 0);
    assert_no_store(&second);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invocation_limit_is_atomic_across_two_nodes_with_redis() {
    let docker_available = std::process::Command::new("docker")
        .arg("info")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !docker_available {
        eprintln!("skipping Redis MCP rate-limit test: Docker unavailable");
        return;
    }
    use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage};

    let image = GenericImage::new("redis", "7-alpine")
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"));
    let container = image.start().await.expect("Redis container start");
    let host = container.get_host().await.expect("Redis container host");
    let port = container.get_host_port_ipv4(6379).await.expect("Redis container port");
    let cache: Arc<dyn DistributedCache> = Arc::new(
        issuerd_cluster::RedisCache::connect(&format!("redis://{host}:{port}"))
            .await
            .expect("Redis connection"),
    );
    let storage: Arc<dyn Storage> = Arc::new(issuerd_storage::InMemoryStorage::new());
    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = crate::harness::test_config();
    config.issuer_url = "http://cluster.example:8080".to_string();
    config.mcp.enabled = true;
    config.mcp.require_dpop = false;
    config.mcp.invocation_rate_limit_per_minute = 1;
    let node_a = spawn_listener(
        listener_a,
        config.clone(),
        Some((Arc::clone(&storage), Arc::clone(&cache))),
    )
    .await;
    let node_b = spawn_listener(listener_b, config, Some((storage, cache))).await;
    let fixture = make_fixture(&node_a, "redis-shared-limit", &["view-realm"]).await;
    let issued = issue_token(&node_a, &fixture, "openid mcp:read", None, true).await;
    let realm = fixture.realm.name.as_str();
    let access_token = issued.access_token.clone();

    // Keep the burst inside one fixed window; the rate_limit unit tests cover
    // intentional window transitions separately.
    let window_second = issuerd_core::utils::now_secs() % 60;
    if window_second > 45 {
        tokio::time::sleep(std::time::Duration::from_secs(61 - window_second)).await;
    }
    let responses = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        futures::future::join_all((0..8).map(|index| {
            let server = if index % 2 == 0 { &node_a } else { &node_b };
            let access_token = access_token.clone();
            async move {
                send_mcp(
                    server,
                    realm,
                    tool_request("realm_get", json!({}), false),
                    tool_options("realm_get", &access_token, false),
                )
                .await
            }
        })),
    )
    .await
    .expect("concurrent burst did not complete within one rate-limit window");
    let mut successes = 0;
    let mut limited = 0;
    for response in responses {
        match response.status() {
            StatusCode::OK => {
                successes += 1;
                assert_eq!(response_json(response).await["result"]["isError"], false);
            }
            StatusCode::TOO_MANY_REQUESTS => {
                limited += 1;
                let retry_after = response.headers()[header::RETRY_AFTER]
                    .to_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap();
                assert!(retry_after > 0);
                assert_no_store(&response);
            }
            status => {
                let body = response.bytes().await.unwrap();
                panic!("unexpected Redis rate-limit response {status}: {body:?}");
            }
        }
    }
    assert_eq!((successes, limited), (1, 7));
}

#[tokio::test]
async fn modern_last_event_id_is_ignored_without_a_session_id() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "modern-last-event", &["view-realm"]).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let mut options = tool_options("realm_get", &issued.access_token, true);
    options.last_event_id = Some("not-a-session".to_string());
    let response = send_mcp(
        &server,
        fixture.realm.name.as_str(),
        tool_request("realm_get", json!({}), true),
        options,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_session_id(&response);
    let body = response_json(response).await;
    assert_eq!(body["result"]["resultType"], "complete");
    assert_eq!(body["result"]["isError"], false);
}

#[tokio::test]
async fn strict_dpop_scope_miss_has_exact_scope_and_algs_challenge() {
    let server = spawn_server(ServerOptions {
        require_dpop: true,
        ..ServerOptions::default()
    })
    .await;
    let fixture = make_fixture(&server, "dpop-scope-miss", &ALL_READ_ROLES).await;
    let key = DpopKey::new();
    let issued = issue_token(&server, &fixture, "openid", Some(&key), true).await;
    let response =
        call_dpop(&server, &fixture, &issued.access_token, &key, "realm_get", json!({}), None)
            .await;
    let challenge =
        assert_oauth_error(response, StatusCode::FORBIDDEN, "DPoP", "insufficient_scope").await;
    assert_eq!(
        challenge,
        format!(
            "DPoP error=\"insufficient_scope\", resource_metadata=\"{}\", algs=\"{}\", scope=\"mcp:read\"",
            server.metadata_url(fixture.realm.name.as_str()),
            dpop_algs()
        )
    );
}

#[tokio::test]
async fn bearer_compatibility_still_rejects_both_dpop_downgrades() {
    let server = spawn_server(ServerOptions {
        require_dpop: false,
        ..ServerOptions::default()
    })
    .await;
    let fixture = make_fixture(&server, "compatibility-downgrades", &ALL_READ_ROLES).await;
    let key = DpopKey::new();
    let bound = issue_token(&server, &fixture, "openid mcp:read", Some(&key), true).await;
    let unbound = issue_token(&server, &fixture, "openid mcp:read", None, true).await;

    assert_invalid_bearer_token(
        &server,
        fixture.realm.name.as_str(),
        bearer_call(&server, &fixture, &bound.access_token).await,
    )
    .await;

    let mut options = tool_options("realm_get", &unbound.access_token, false);
    options.authorization = Some(format!("DPoP {}", unbound.access_token));
    options.proofs = vec![dpop_proof(
        &server,
        fixture.realm.name.as_str(),
        &unbound.access_token,
        &key,
        None,
    )];
    let response = send_mcp(
        &server,
        fixture.realm.name.as_str(),
        tool_request("realm_get", json!({}), false),
        options,
    )
    .await;
    assert_dpop_error(response, "invalid_token").await;
}

async fn expired_variant(server: &Loopback, token: &str) -> String {
    let header = token.split('.').next().unwrap();
    let header: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header).unwrap(),
    )
    .unwrap();
    let mut claims = decode_jwt(token);
    for claim in ["exp", "iat", "nbf"] {
        claims[claim] = json!(1);
    }
    let algorithm: issuerd_core::Algorithm = header["alg"].as_str().unwrap().parse().unwrap();
    let key_id = issuerd_core::KeyId::new(header["kid"].as_str().unwrap()).unwrap();
    server.state.crypto.sign(&claims.to_string(), algorithm, &key_id).await.unwrap()
}

#[tokio::test]
async fn expired_resource_bound_token_is_invalid_token() {
    let server = spawn_server(ServerOptions::default()).await;
    let fixture = make_fixture(&server, "expired-token", &ALL_READ_ROLES).await;
    let issued = issue_token(&server, &fixture, "openid mcp:read", None, true).await;
    let expired = expired_variant(&server, &issued.access_token).await;
    assert_invalid_bearer_token(
        &server,
        fixture.realm.name.as_str(),
        bearer_call(&server, &fixture, &expired).await,
    )
    .await;
}
