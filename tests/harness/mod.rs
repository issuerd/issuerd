// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Shared test harness: target abstraction, legacy in-process harness, AD lab connection config.

pub mod issuerd;
pub mod keycloak;
pub mod target;

// Re-export the trait and helpers for convenient use in tests.
#[allow(unused_imports)]
pub use target::{
    for_each_target, ClientInfo, OidcTestTarget, RealmInfo, TestResponse, TokenBundle, UserInfo,
};

/// Opt-in tracing initialization for tests. Call at the top of a test to see
/// `tracing` output interleaved with the test's own output; a no-op when a
/// subscriber is already installed.
#[allow(dead_code)]
pub fn init_test_tracing() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
}

/// Install `ring` as the process-level rustls `CryptoProvider`. The workspace
/// dependency graph enables both `ring` and `aws-lc-rs` rustls features
/// (the latter via `metrics-exporter-prometheus` → `hyper-rustls`), so
/// `rustls::ClientConfig::builder()` cannot auto-detect a provider and panics.
/// The daemon installs `ring` at startup; test binaries that open LDAPS
/// connections without booting a server must do it themselves. Idempotent.
pub fn ensure_ring_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// Legacy TestHarness is kept for issuerd-only tests that require
// direct storage access or the internal auth-code flow helpers.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{body::Body, extract::ConnectInfo, http::Request, response::Response, Router};
use issuerd_core::{ClientAuthenticatorType, ClientProtocol, RedirectUri, Scope};
use issuerd_server::{config::ServerConfig, routes::app_router, state::ServerState};
use tower::ServiceExt;

#[allow(dead_code)]
pub struct TokenBundleLegacy {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_in: u64,
}

/// Connection details for a real Windows Server Active Directory lab, read
/// from the environment. `from_env` returns `None` when the lab is not
/// configured, and AD-dependent tests skip.
///
/// Required:
/// - `ISSUERD_TEST_AD_HOST` — AD DS host (LDAP on 389, LDAPS on 636)
/// - `ISSUERD_TEST_AD_BIND_CREDENTIAL` — password of the read-bind account
///
/// Optional (defaults mirror the `test.issuerd.local` fixture layout):
/// - `ISSUERD_TEST_AD_BASE_DN` (default `DC=test,DC=issuerd,DC=local`)
/// - `ISSUERD_TEST_AD_USERS_DN` (default `OU=IssuerdUsers,{base}`)
/// - `ISSUERD_TEST_AD_GROUPS_DN` (default `OU=IssuerdGroups,{base}`)
/// - `ISSUERD_TEST_AD_BIND_DN` (default `CN=ldapbind,{users}`)
/// - `ISSUERD_TEST_AD_ADMIN_DN` (default `CN=Administrator,CN=Users,{base}`)
/// - `ISSUERD_TEST_AD_ADMIN_PASSWORD` — required by the load test
/// - `ISSUERD_TEST_AD_VM_NAME` / `ISSUERD_TEST_AD_VM_SNAPSHOT` — Hyper-V
///   reset target for the load test
pub struct AdLab {
    pub host: String,
    pub bind_dn: String,
    pub bind_credential: String,
    pub admin_dn: String,
    pub admin_password: Option<String>,
    pub users_dn: String,
    pub groups_dn: String,
    pub base_dn: String,
    pub vm_name: Option<String>,
    pub vm_snapshot: Option<String>,
}

#[allow(dead_code)]
impl AdLab {
    pub fn from_env() -> Option<Self> {
        ensure_ring_crypto_provider();
        let host = std::env::var("ISSUERD_TEST_AD_HOST").ok()?;
        let base_dn = std::env::var("ISSUERD_TEST_AD_BASE_DN")
            .unwrap_or_else(|_| "DC=test,DC=issuerd,DC=local".to_string());
        let users_dn = std::env::var("ISSUERD_TEST_AD_USERS_DN")
            .unwrap_or_else(|_| format!("OU=IssuerdUsers,{base_dn}"));
        let groups_dn = std::env::var("ISSUERD_TEST_AD_GROUPS_DN")
            .unwrap_or_else(|_| format!("OU=IssuerdGroups,{base_dn}"));
        let bind_dn = std::env::var("ISSUERD_TEST_AD_BIND_DN")
            .unwrap_or_else(|_| format!("CN=ldapbind,{users_dn}"));
        let admin_dn = std::env::var("ISSUERD_TEST_AD_ADMIN_DN")
            .unwrap_or_else(|_| format!("CN=Administrator,CN=Users,{base_dn}"));
        Some(Self {
            host,
            bind_dn,
            bind_credential: std::env::var("ISSUERD_TEST_AD_BIND_CREDENTIAL").ok()?,
            admin_dn,
            admin_password: std::env::var("ISSUERD_TEST_AD_ADMIN_PASSWORD").ok(),
            users_dn,
            groups_dn,
            base_dn,
            vm_name: std::env::var("ISSUERD_TEST_AD_VM_NAME").ok(),
            vm_snapshot: std::env::var("ISSUERD_TEST_AD_VM_SNAPSHOT").ok(),
        })
    }

    pub fn ldap_url(&self) -> String {
        format!("ldap://{}:389", self.host)
    }

    pub fn ldaps_url(&self) -> String {
        format!("ldaps://{}:636", self.host)
    }

    pub fn available(&self) -> bool {
        std::net::TcpStream::connect_timeout(
            &format!("{}:389", self.host).parse().unwrap(),
            std::time::Duration::from_secs(2),
        )
        .is_ok()
    }

    /// Build the LDAP identity-provider config map for this lab.
    pub fn provider_config(&self) -> HashMap<String, String> {
        let mut config = HashMap::new();
        config.insert("connectionUrl".to_string(), self.ldap_url());
        config.insert("bindDn".to_string(), self.bind_dn.clone());
        config.insert("bindCredential".to_string(), self.bind_credential.clone());
        config.insert("usersDn".to_string(), self.users_dn.clone());
        config.insert("baseDn".to_string(), self.base_dn.clone());
        config.insert("usernameLdapAttribute".to_string(), "sAMAccountName".to_string());
        config.insert("rdnLdapAttribute".to_string(), "cn".to_string());
        config.insert("uuidLdapAttribute".to_string(), "objectGUID".to_string());
        config.insert(
            "userObjectClasses".to_string(),
            "person,organizationalPerson,user".to_string(),
        );
        config.insert("vendor".to_string(), "ACTIVE_DIRECTORY".to_string());
        config.insert("searchScope".to_string(), "SUBTREE".to_string());
        config.insert("editMode".to_string(), "WRITABLE".to_string());
        config
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct TestHarness {
    pub app: Router,
    pub storage: Arc<dyn issuerd_core::Storage>,
    pub cache: Arc<dyn issuerd_core::DistributedCache>,
    pub base_url: String,
}

impl TestHarness {
    pub async fn new() -> Self {
        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let storage = Arc::clone(&state.storage);
        let cache = Arc::clone(&state.cache);
        let base_url = config.issuer_url.clone();
        let app = app_router(state);
        Self {
            app,
            storage,
            cache,
            base_url,
        }
    }

    /// Build a harness around a pre-constructed state, so tests can customize
    /// `ServerState` (e.g. swap in a recording `EmailSender`) before the
    /// router captures it.
    pub fn with_state(state: Arc<ServerState>) -> Self {
        let storage = Arc::clone(&state.storage);
        let cache = Arc::clone(&state.cache);
        let base_url = state.config.issuer_url.clone();
        let app = app_router(state);
        Self {
            app,
            storage,
            cache,
            base_url,
        }
    }

    pub fn add_connect_info(&self, mut req: Request<Body>) -> Request<Body> {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        req
    }

    pub async fn get(&self, path: &str) -> Response {
        let req = Request::builder().method("GET").uri(path).body(Body::empty()).unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    pub async fn post_json(&self, path: &str, body: serde_json::Value) -> Response {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    pub async fn post_form(&self, path: &str, params: &[(&str, &str)]) -> Response {
        let body = serde_urlencoded::to_string(params).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    pub async fn post_form_with_cookie(
        &self,
        path: &str,
        params: &[(&str, &str)],
        cookie: &str,
    ) -> Response {
        let body = serde_urlencoded::to_string(params).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", cookie)
            .body(Body::from(body))
            .unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    pub async fn post_json_with_cookie(
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

    /// Correlation cookie a browser would present when submitting the login
    /// form for the given flow (`execution_id`) — mirrors the `Set-Cookie`
    /// issued by the authorize endpoint's redirect to `/login.html`.
    pub fn flow_cookie(execution_id: &str) -> String {
        format!("issuerd_flow_{execution_id}=1")
    }

    pub async fn create_realm(&self, name: &str) -> issuerd_core::Realm {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new(name).unwrap(),
            name: issuerd_core::RealmName::new(name).unwrap(),
            display_name: Some(issuerd_core::DisplayName::new(name).unwrap()),
            enabled: true,
            ..Default::default()
        };
        self.storage.create_realm(&realm).await.unwrap();
        realm
    }

    pub async fn create_client(&self, realm: &str, public: bool) -> issuerd_core::Client {
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
            protocol: ClientProtocol::OpenIdConnect,
            public_client: public,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: secret.clone(),
            redirect_uris: vec![RedirectUri::new("http://localhost:8080/cb").unwrap()],
            web_origins: vec![issuerd_core::WebOrigin::new("http://localhost:8080").unwrap()],
            default_scopes: Scope::parse("openid profile"),
            optional_scopes: Scope::parse("email"),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        self.storage.create_client(&client.realm_id, &client).await.unwrap();
        client
    }

    pub async fn create_user(
        &self,
        realm: &str,
        username: &str,
        password: &str,
    ) -> issuerd_core::User {
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
        self.storage.create_user(&user.realm_id, &user).await.unwrap();

        // Hash password with argon2
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();

        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        self.storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        user
    }

    pub async fn authenticate_user(
        &self,
        realm: &str,
        client_id: &str,
        username: &str,
        password: &str,
    ) -> TokenBundleLegacy {
        // Step 1: Authorization request
        let auth_path = format!(
            "/realms/{realm}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz"
        );
        let auth_resp = self.get(&auth_path).await;
        assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

        // Step 2: Extract execution_id from Location header
        let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
        let execution_id = Self::extract_query_param(location, "execution_id")
            .expect("missing execution_id in redirect");

        // Step 3: POST login (with the flow correlation cookie a browser would send)
        let login_resp = self
            .post_json_with_cookie(
                &format!("/api/v1/auth/login?realm={realm}"),
                serde_json::json!({
                    "execution_id": execution_id,
                    "username": username,
                    "password": password,
                }),
                &Self::flow_cookie(&execution_id),
            )
            .await;
        assert_eq!(login_resp.status(), axum::http::StatusCode::OK);

        // Step 4: Extract code from JSON response
        let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX).await.unwrap();
        let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let code = login_json["code"].as_str().unwrap();

        // Step 5: Get client secret for token request
        let realm_id = issuerd_core::RealmId::new(realm).unwrap();
        let client = self
            .storage
            .get_client_by_client_id(
                &realm_id,
                &issuerd_core::ClientIdentifier::new(client_id).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let secret = client.secret.as_deref().unwrap_or("");

        // Step 6: Token exchange
        let token_resp = self
            .post_form(
                &format!("/realms/{realm}/protocol/openid-connect/token"),
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", "http://localhost:8080/cb"),
                    ("client_id", client_id),
                    ("client_secret", secret),
                ],
            )
            .await;
        assert_eq!(token_resp.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(token_resp.into_body(), usize::MAX).await.unwrap();
        let token_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        TokenBundleLegacy {
            access_token: token_json["access_token"].as_str().unwrap().to_string(),
            refresh_token: token_json["refresh_token"].as_str().map(|s| s.to_string()),
            id_token: token_json["id_token"].as_str().map(|s| s.to_string()),
            expires_in: token_json["expires_in"].as_u64().unwrap(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn authenticate_user_with_pkce(
        &self,
        realm: &str,
        client_id: &str,
        username: &str,
        password: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        code_verifier: &str,
    ) -> TokenBundleLegacy {
        let auth_path = format!(
            "/realms/{realm}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz&code_challenge={code_challenge}&code_challenge_method={code_challenge_method}"
        );
        let auth_resp = self.get(&auth_path).await;
        assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

        let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
        let execution_id = Self::extract_query_param(location, "execution_id")
            .expect("missing execution_id in redirect");

        let login_resp = self
            .post_json_with_cookie(
                &format!("/api/v1/auth/login?realm={realm}"),
                serde_json::json!({
                    "execution_id": execution_id,
                    "username": username,
                    "password": password,
                }),
                &Self::flow_cookie(&execution_id),
            )
            .await;
        assert_eq!(login_resp.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX).await.unwrap();
        let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let code = login_json["code"].as_str().unwrap();

        let realm_id = issuerd_core::RealmId::new(realm).unwrap();
        let client = self
            .storage
            .get_client_by_client_id(
                &realm_id,
                &issuerd_core::ClientIdentifier::new(client_id).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let secret = client.secret.as_deref().unwrap_or("");

        let token_resp = self
            .post_form(
                &format!("/realms/{realm}/protocol/openid-connect/token"),
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", "http://localhost:8080/cb"),
                    ("client_id", client_id),
                    ("client_secret", secret),
                    ("code_verifier", code_verifier),
                ],
            )
            .await;
        assert_eq!(token_resp.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(token_resp.into_body(), usize::MAX).await.unwrap();
        let token_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        TokenBundleLegacy {
            access_token: token_json["access_token"].as_str().unwrap().to_string(),
            refresh_token: token_json["refresh_token"].as_str().map(|s| s.to_string()),
            id_token: token_json["id_token"].as_str().map(|s| s.to_string()),
            expires_in: token_json["expires_in"].as_u64().unwrap(),
        }
    }

    pub async fn get_admin_token(&self, realm: &str, username: &str, password: &str) -> String {
        let resp = self
            .post_json(
                "/api/v1/auth/admin-token",
                serde_json::json!({
                    "realm": realm,
                    "username": username,
                    "password": password,
                }),
            )
            .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        json["access_token"].as_str().unwrap().to_string()
    }

    pub async fn get_auth(&self, path: &str, token: &str) -> Response {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    pub async fn post_json_auth(
        &self,
        path: &str,
        token: &str,
        body: serde_json::Value,
    ) -> Response {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::from(body.to_string()))
            .unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    pub async fn delete_auth(&self, path: &str, token: &str) -> Response {
        let req = Request::builder()
            .method("DELETE")
            .uri(path)
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap()
    }

    pub fn extract_query_param(url: &str, key: &str) -> Option<String> {
        let url_parsed = if url.starts_with('/') {
            url::Url::parse(&format!("http://localhost{}", url)).ok()?
        } else {
            url::Url::parse(url).ok()?
        };
        url_parsed.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.to_string())
    }

    /// Configure a Samba DC LDAP identity provider for the given realm.
    pub async fn configure_samba_ldap_provider(&self, realm: &str) {
        let mut config = HashMap::new();
        config.insert("connectionUrl".to_string(), "ldap://localhost:389".to_string());
        config.insert(
            "bindDn".to_string(),
            "CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local".to_string(),
        );
        config.insert("bindCredential".to_string(), "AdminPass123!".to_string());
        config.insert("usersDn".to_string(), "CN=Users,DC=test,DC=issuerd,DC=local".to_string());
        config.insert("baseDn".to_string(), "DC=test,DC=issuerd,DC=local".to_string());
        config.insert("usernameLdapAttribute".to_string(), "sAMAccountName".to_string());
        config.insert("rdnLdapAttribute".to_string(), "cn".to_string());
        config.insert("uuidLdapAttribute".to_string(), "objectGUID".to_string());
        config.insert(
            "userObjectClasses".to_string(),
            "person,organizationalPerson,user".to_string(),
        );
        config.insert("vendor".to_string(), "ACTIVE_DIRECTORY".to_string());
        config.insert("searchScope".to_string(), "SUBTREE".to_string());
        config.insert("editMode".to_string(), "WRITABLE".to_string());
        config.insert("priority".to_string(), "1".to_string());

        let idp = issuerd_core::IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("samba-ldap").unwrap(),
            alias: issuerd_core::Alias::new("samba-ldap").unwrap(),
            provider_id: issuerd_core::ProviderId::new("ldap"),
            enabled: true,
            config,
        };
        let realm_id = issuerd_core::RealmId::new(realm).unwrap();
        self.storage.create_identity_provider(&realm_id, &idp).await.unwrap();
    }

    /// Configure an OpenLDAP identity provider for the given realm.
    pub async fn configure_openldap_provider(&self, realm: &str) {
        let mut config = HashMap::new();
        config.insert("connectionUrl".to_string(), "ldap://localhost:1389".to_string());
        config.insert("bindDn".to_string(), "cn=admin,dc=test,dc=issuerd,dc=local".to_string());
        config.insert("bindCredential".to_string(), "admin".to_string());
        config.insert("usersDn".to_string(), "ou=users,dc=test,dc=issuerd,dc=local".to_string());
        config.insert("baseDn".to_string(), "dc=test,dc=issuerd,dc=local".to_string());
        config.insert("usernameLdapAttribute".to_string(), "uid".to_string());
        config.insert("rdnLdapAttribute".to_string(), "uid".to_string());
        config.insert("uuidLdapAttribute".to_string(), "entryUUID".to_string());
        config.insert(
            "userObjectClasses".to_string(),
            "inetOrgPerson,organizationalPerson".to_string(),
        );
        config.insert("vendor".to_string(), "GENERIC".to_string());
        config.insert("searchScope".to_string(), "SUBTREE".to_string());
        config.insert("editMode".to_string(), "WRITABLE".to_string());
        config.insert("priority".to_string(), "1".to_string());

        let idp = issuerd_core::IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("openldap").unwrap(),
            alias: issuerd_core::Alias::new("openldap").unwrap(),
            provider_id: issuerd_core::ProviderId::new("ldap"),
            enabled: true,
            config,
        };
        let realm_id = issuerd_core::RealmId::new(realm).unwrap();
        self.storage.create_identity_provider(&realm_id, &idp).await.unwrap();
    }

    /// Configure a real Windows AD LDAP identity provider for the given realm.
    pub async fn configure_ad_provider(&self, realm: &str, lab: &AdLab) {
        let mut config = lab.provider_config();
        config.insert("priority".to_string(), "1".to_string());

        let idp = issuerd_core::IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("ad-ldap").unwrap(),
            alias: issuerd_core::Alias::new("ad-ldap").unwrap(),
            provider_id: issuerd_core::ProviderId::new("ldap"),
            enabled: true,
            config,
        };
        let realm_id = issuerd_core::RealmId::new(realm).unwrap();
        self.storage.create_identity_provider(&realm_id, &idp).await.unwrap();
    }
}
