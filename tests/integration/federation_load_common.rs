// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Shared helpers for the large-scale federation load tests.

//! Shared helpers for large-scale federation load tests.
//!
//! These tests are gated by the `ISSUERD_FEDERATION_LOAD_TEST` environment
//! variable. Set it to `samba`, `openldap`, `ad`, or `all` to enable the
//! corresponding test.
//!
//! Prerequisites:
//!   - PostgreSQL running on localhost:5432
//!     (from docker compose -f docker-compose.integration.yml up -d postgres)
//!   - For Samba: docker compose -f docker-compose.integration.yml up -d samba-dc
//!   - For OpenLDAP: docker compose -f docker-compose.integration.yml up -d openldap
//!   - For AD: a reachable Windows Server AD lab configured via the
//!     ISSUERD_TEST_AD_* environment variables (see `AdLab` in tests/harness)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;

use axum::{body::Body, extract::ConnectInfo, http::Request, response::Response, Router};
use issuerd_core::{
    ClientAuthenticatorType, ClientIdentifier, ClientProtocol, RedirectUri, Scope, Username,
};
use issuerd_server::{config::ServerConfig, routes::app_router, state::ServerState};
use tower::ServiceExt;

use crate::harness::AdLab;

pub fn load_test_enabled(target: &str) -> bool {
    let env = std::env::var("ISSUERD_FEDERATION_LOAD_TEST").unwrap_or_default();
    env == "all" || env == target
}

// ---------------------------------------------------------------------------
// LoadTestHarness (PostgreSQL-backed)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub struct LoadTestHarness {
    pub app: Router,
    pub storage: Arc<dyn issuerd_core::Storage>,
    pub base_url: String,
}

impl LoadTestHarness {
    pub async fn new_with_postgres() -> Self {
        let db_url = std::env::var("ISSUERD_TEST_DB_URL").unwrap_or_else(|_| {
            "postgres://issuerd:issuerd_secret@localhost:5432/issuerd".to_string()
        });
        let config = ServerConfig {
            storage: issuerd_server::config::StorageConfig::Postgres {
                url: db_url.to_string(),
            },
            ..Default::default()
        };

        // Wipe and recreate the public schema to ensure a clean state for every run.
        let wipe_pool = sqlx::postgres::PgPool::connect(&db_url).await.unwrap();
        sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
            .execute(&wipe_pool)
            .await
            .unwrap();
        sqlx::query("CREATE SCHEMA public").execute(&wipe_pool).await.unwrap();
        sqlx::query("GRANT ALL ON SCHEMA public TO issuerd")
            .execute(&wipe_pool)
            .await
            .unwrap();
        drop(wipe_pool);

        // Run migrations first so tables exist.
        let pg = issuerd_storage::PostgresStorage::connect(&db_url).await.unwrap();
        pg.run_migrations().await.unwrap();
        drop(pg);

        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let storage = Arc::clone(&state.storage);
        let app = app_router(state);

        // Bootstrap master realm manually (PostgreSQL is not auto-bootstrapped).
        Self::bootstrap_master(&storage).await;

        Self {
            app,
            storage,
            base_url: config.issuer_url,
        }
    }

    async fn bootstrap_master(storage: &Arc<dyn issuerd_core::Storage>) {
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use chrono::Utc;
        use issuerd_core::{
            Client, ClientId, Credential, CredentialType, Email, Realm, RealmId, Role, User, UserId,
        };
        use rand::rngs::OsRng;

        // PostgreSQL stores realm IDs as UUID, so generate one and keep name = "master".
        let realm_id = RealmId::new(issuerd_core::utils::generate_id()).unwrap();
        if storage.get_realm_by_name("master").await.unwrap().is_some() {
            return; // already bootstrapped
        }

        let realm = Realm {
            id: realm_id.clone(),
            name: issuerd_core::RealmName::new("master").unwrap(),
            display_name: Some(issuerd_core::DisplayName::new("Master").unwrap()),
            enabled: true,
            ..Default::default()
        };
        storage.create_realm(&realm).await.unwrap();

        let admin_user = User {
            id: UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("admin").unwrap(),
            email: Some(Email::new("admin@localhost.local").unwrap()),
            email_verified: true,
            first_name: Some(issuerd_core::DisplayName::new("Admin").unwrap()),
            last_name: Some(issuerd_core::DisplayName::new("User").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        storage.create_user(&realm_id, &admin_user).await.unwrap();

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password("admin".as_bytes(), &salt).unwrap().to_string();
        let cred = Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&realm_id, &admin_user.id, &cred).await.unwrap();

        let client = Client {
            id: ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new("admin-cli").unwrap(),
            name: Some(issuerd_core::DisplayName::new("Admin CLI").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: true,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![
                RedirectUri::new("http://localhost:8080/").unwrap(),
                RedirectUri::new("http://localhost:8080/callback").unwrap(),
                RedirectUri::new("http://localhost:8080/swagger-ui/oauth2-redirect.html").unwrap(),
            ],
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
        storage.create_client(&realm_id, &client).await.unwrap();

        let admin_roles = vec![
            "manage-realm",
            "view-realm",
            "manage-users",
            "view-users",
            "manage-clients",
            "view-clients",
        ];
        for role_name in &admin_roles {
            let role = Role {
                id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
                name: issuerd_core::RoleName::new(role_name.to_string()).unwrap(),
                description: Some(format!("{role_name} role")),
                realm_id: realm_id.clone(),
                client_role: false,
                client_id: None,
                composite: false,
                composites: vec![],
                attributes: HashMap::new(),
            };
            let _ = storage.create_role(&realm_id, &role).await;
            let _ = storage.add_user_realm_role(&realm_id, &admin_user.id, &role.id).await;
        }
    }

    fn add_connect_info(&self, mut req: Request<Body>) -> Request<Body> {
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

    pub async fn create_realm(&self, name: &str) -> issuerd_core::Realm {
        if let Some(existing) = self.storage.get_realm_by_name(name).await.unwrap() {
            return existing;
        }
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::RealmName::new(name).unwrap(),
            display_name: Some(issuerd_core::DisplayName::new(name).unwrap()),
            enabled: true,
            ..Default::default()
        };
        self.storage.create_realm(&realm).await.unwrap();
        realm
    }

    async fn realm_id_by_name(&self, name: &str) -> issuerd_core::RealmId {
        self.storage.get_realm_by_name(name).await.unwrap().unwrap().id
    }

    pub async fn create_client(&self, realm: &str, public: bool) -> issuerd_core::Client {
        let realm_id = self.realm_id_by_name(realm).await;
        let secret = if public {
            None
        } else {
            Some(issuerd_core::utils::generate_id())
        };
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id,
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

    pub async fn authenticate_user(
        &self,
        realm: &str,
        client_id: &str,
        username: &str,
        password: &str,
    ) -> TokenBundleLegacy {
        let realm_id = self.realm_id_by_name(realm).await;
        let auth_path = format!(
            "/realms/{realm}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz"
        );
        let auth_resp = self.get(&auth_path).await;
        assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

        let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
        let execution_id =
            Self::extract_query_param(location, "execution_id").expect("missing execution_id");

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

    pub fn extract_query_param(url: &str, key: &str) -> Option<String> {
        let url_parsed = if url.starts_with('/') {
            url::Url::parse(&format!("http://localhost{}", url)).ok()?
        } else {
            url::Url::parse(url).ok()?
        };
        url_parsed.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.to_string())
    }

    pub async fn trigger_sync(&self, realm: &str, provider_id: &str) -> issuerd_core::SyncResult {
        let admin_token = self.get_admin_token("master", "admin", "admin").await;
        let resp = self
            .post_json_auth(
                // Admin API routes expect the realm *name* in the URL path.
                &format!("/admin/realms/{realm}/user-federation/{provider_id}/sync"),
                &admin_token,
                serde_json::json!({}),
            )
            .await;
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        if status != axum::http::StatusCode::OK {
            let text = String::from_utf8_lossy(&body);
            eprintln!("[load-test] sync returned {status}: {text}");
        }
        assert_eq!(status, axum::http::StatusCode::OK);
        serde_json::from_slice(&body).unwrap()
    }

    // -- provider configuration helpers --

    pub async fn configure_samba_ldap_provider(&self, realm: &str) {
        let realm_id = self.realm_id_by_name(realm).await;
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
            id: issuerd_core::IdentityProviderId::new("a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d")
                .unwrap(),
            alias: issuerd_core::Alias::new("samba-ldap").unwrap(),
            provider_id: issuerd_core::ProviderId::new("ldap"),
            enabled: true,
            config,
        };
        self.storage.create_identity_provider(&realm_id, &idp).await.unwrap();
    }

    pub async fn configure_openldap_provider(&self, realm: &str) {
        let realm_id = self.realm_id_by_name(realm).await;
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
            id: issuerd_core::IdentityProviderId::new("b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e")
                .unwrap(),
            alias: issuerd_core::Alias::new("openldap").unwrap(),
            provider_id: issuerd_core::ProviderId::new("ldap"),
            enabled: true,
            config,
        };
        self.storage.create_identity_provider(&realm_id, &idp).await.unwrap();
    }

    pub async fn configure_ad_provider(&self, realm: &str, lab: &AdLab) {
        let realm_id = self.realm_id_by_name(realm).await;
        let mut config = lab.provider_config();
        config.insert("priority".to_string(), "1".to_string());

        let idp = issuerd_core::IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f")
                .unwrap(),
            alias: issuerd_core::Alias::new("ad-ldap").unwrap(),
            provider_id: issuerd_core::ProviderId::new("ldap"),
            enabled: true,
            config,
        };
        self.storage.create_identity_provider(&realm_id, &idp).await.unwrap();
    }
}

#[allow(dead_code)]
pub struct TokenBundleLegacy {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_in: u64,
}

// ---------------------------------------------------------------------------
// Docker / LDIF helpers
// ---------------------------------------------------------------------------

/// Run `docker compose down -v` for a service and then `up -d`.
///
/// Always targets the integration test stack (`docker-compose.integration.yml`),
/// never the root local-demo compose file.
pub fn reset_docker_service(service: &str) {
    eprintln!("[load-test] Resetting docker service: {service}");
    let down = Command::new("docker")
        .args([
            "compose",
            "-f",
            "docker-compose.integration.yml",
            "down",
            "-v",
            service,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if let Err(e) = down {
        eprintln!("[load-test] docker compose down warning: {e}");
    }
    let up = Command::new("docker")
        .args([
            "compose",
            "-f",
            "docker-compose.integration.yml",
            "up",
            "-d",
            service,
        ])
        .status()
        .unwrap_or_else(|e| panic!("docker compose up -d {service} failed: {e}"));
    if !up.success() {
        panic!("docker compose up -d {service} exited with non-zero status");
    }
}

/// Poll a TCP port until it is open or timeout.
pub fn wait_for_port(host: &str, port: u16, timeout_secs: u64) -> bool {
    let start = std::time::Instant::now();
    let addr = format!("{host}:{port}");
    while start.elapsed().as_secs() < timeout_secs {
        if std::net::TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            std::time::Duration::from_secs(1),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    false
}

/// Poll until an LDAP bind succeeds inside a Docker container.
pub fn wait_for_ldap_ready(
    container: &str,
    bind_dn: &str,
    bind_pw: &str,
    timeout_secs: u64,
) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < timeout_secs {
        let out = Command::new("docker")
            .args([
                "exec",
                container,
                "bash",
                "-c",
                &format!(
                    "ldapsearch -x -H ldap://localhost -D '{}' -w '{}' -b '{}' -s base '(objectClass=*)' 2>/dev/null >/dev/null && echo READY",
                    bind_dn, bind_pw, bind_dn
                ),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        if let Ok(out) = out {
            if out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "READY" {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    false
}

/// Reset a Hyper-V VM to a named snapshot.
pub fn reset_hyperv_vm(vm_name: &str, snapshot: &str) {
    eprintln!("[load-test] Resetting Hyper-V VM {vm_name} to snapshot {snapshot}");
    let out = Command::new("powershell.exe")
        .args([
            "-Command",
            &format!(
                "Get-VMSnapshot -VMName '{}' -Name '{}' | Restore-VMSnapshot -Confirm:$false",
                vm_name, snapshot
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("powershell restore failed: {e}"));
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        panic!("Restore-VMSnapshot failed: {stderr}");
    }
    // Start the VM if it's off
    let _ = Command::new("powershell.exe")
        .args(["-Command", &format!("Start-VM -Name '{}'", vm_name)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Import an LDIF file into a Docker container via `ldapadd`.
pub fn import_ldif_into_container(container: &str, bind_dn: &str, bind_pw: &str, ldif_path: &str) {
    eprintln!("[load-test] Importing {ldif_path} into {container}");
    let out = Command::new("docker")
        .args([
            "exec",
            "-i",
            container,
            "ldapadd",
            "-x",
            "-H",
            "ldap://localhost",
            "-D",
            bind_dn,
            "-w",
            bind_pw,
            "-f",
            ldif_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("ldapadd in {container} failed: {e}"));
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Some entries may already exist; log but don't panic.
        eprintln!("[load-test] ldapadd stderr (may contain non-fatal errors): {stderr}");
    }
}

/// Import an LDIF file directly into the Samba LDB database using `ldbadd`.
/// This bypasses the LDAP server and is orders of magnitude faster for bulk loads.
pub fn import_ldif_samba_ldb(container: &str, ldif_path: &str) {
    eprintln!("[load-test] Importing {ldif_path} into {container} via ldbadd");
    let out = Command::new("docker")
        .args([
            "exec",
            container,
            "ldbadd",
            "-H",
            "/var/lib/samba/private/sam.ldb",
            "--nosync",
            "--relax",
            ldif_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("ldbadd in {container} failed: {e}"));
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // ldbadd may report that some entries already exist on re-runs; log only.
        eprintln!("[load-test] ldbadd stderr (may contain non-fatal errors): {stderr}");
    }
}

/// Import an LDIF modify file directly into the Samba LDB database using `ldbmodify`.
pub fn import_ldif_samba_ldb_modify(container: &str, ldif_path: &str) {
    eprintln!("[load-test] Modifying {ldif_path} in {container} via ldbmodify");
    let out = Command::new("docker")
        .args([
            "exec",
            container,
            "ldbmodify",
            "-H",
            "/var/lib/samba/private/sam.ldb",
            "--nosync",
            "--relax",
            ldif_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("ldbmodify in {container} failed: {e}"));
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("[load-test] ldbmodify stderr (may contain non-fatal errors): {stderr}");
    }
}

/// Copy a file from host into a Docker container.
pub fn docker_cp(host_path: &str, container: &str, container_path: &str) {
    let out = Command::new("docker")
        .args(["cp", host_path, &format!("{container}:{container_path}")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("docker cp failed: {e}"));
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        panic!("docker cp failed: {stderr}");
    }
}

// ---------------------------------------------------------------------------
// LDIF generators
// ---------------------------------------------------------------------------

/// Generate an LDIF chunk for Samba DC users and write it to `path`.
pub fn write_samba_user_ldif_chunk(path: &str, start: usize, count: usize) {
    use std::io::Write;
    let mut file = std::fs::File::create(path).unwrap();
    for i in start..start + count {
        let dn = format!("CN=loaduser_{i},CN=Users,DC=test,DC=issuerd,DC=local");
        writeln!(file, "dn: {dn}").unwrap();
        writeln!(file, "changetype: add").unwrap();
        writeln!(file, "objectClass: top").unwrap();
        writeln!(file, "objectClass: person").unwrap();
        writeln!(file, "objectClass: organizationalPerson").unwrap();
        writeln!(file, "objectClass: user").unwrap();
        writeln!(file, "cn: loaduser_{i}").unwrap();
        writeln!(file, "sAMAccountName: loaduser_{i}").unwrap();
        writeln!(file, "givenName: Load").unwrap();
        writeln!(file, "sn: User{i}").unwrap();
        writeln!(file, "mail: loaduser_{i}@test.issuerd.local").unwrap();
        writeln!(file, "userAccountControl: 512").unwrap();
        writeln!(file).unwrap();
    }
}

/// Generate an LDIF chunk for Samba DC groups and write it to `path`.
pub fn write_samba_group_ldif_chunk(path: &str, start: usize, count: usize) {
    use std::io::Write;
    let mut file = std::fs::File::create(path).unwrap();
    for i in start..start + count {
        let dn = format!("CN=loadgroup_{i},CN=Users,DC=test,DC=issuerd,DC=local");
        writeln!(file, "dn: {dn}").unwrap();
        writeln!(file, "changetype: add").unwrap();
        writeln!(file, "objectClass: top").unwrap();
        writeln!(file, "objectClass: group").unwrap();
        writeln!(file, "cn: loadgroup_{i}").unwrap();
        writeln!(file, "groupType: -2147483646").unwrap();
        writeln!(file).unwrap();
    }
}

/// Generate LDIF modify entries to add members to Samba DC groups.
pub fn write_samba_membership_ldif(path: &str, group_indices: &[usize], users_per_group: usize) {
    use std::io::Write;
    let mut file = std::fs::File::create(path).unwrap();
    for &gi in group_indices {
        let group_dn = format!("CN=loadgroup_{gi},CN=Users,DC=test,DC=issuerd,DC=local");
        writeln!(file, "dn: {group_dn}").unwrap();
        writeln!(file, "changetype: modify").unwrap();
        writeln!(file, "add: member").unwrap();
        for ui in 0..users_per_group {
            let user_dn = format!(
                "CN=loaduser_{},CN=Users,DC=test,DC=issuerd,DC=local",
                gi * users_per_group + ui
            );
            writeln!(file, "member: {user_dn}").unwrap();
        }
        writeln!(file, "-").unwrap();
        writeln!(file).unwrap();
    }
}

/// Generate an LDIF chunk for OpenLDAP users.
pub fn write_openldap_user_ldif_chunk(path: &str, start: usize, count: usize) {
    use std::io::Write;
    let mut file = std::fs::File::create(path).unwrap();
    for i in start..start + count {
        let dn = format!("uid=loaduser_{i},ou=users,dc=test,dc=issuerd,dc=local");
        writeln!(file, "dn: {dn}").unwrap();
        writeln!(file, "changetype: add").unwrap();
        writeln!(file, "objectClass: inetOrgPerson").unwrap();
        writeln!(file, "objectClass: organizationalPerson").unwrap();
        writeln!(file, "objectClass: person").unwrap();
        writeln!(file, "objectClass: top").unwrap();
        writeln!(file, "uid: loaduser_{i}").unwrap();
        writeln!(file, "cn: Load User{i}").unwrap();
        writeln!(file, "sn: User{i}").unwrap();
        writeln!(file, "mail: loaduser_{i}@test.issuerd.local").unwrap();
        writeln!(file, "userPassword: Password123!").unwrap();
        writeln!(file).unwrap();
    }
}

/// Generate an LDIF chunk for OpenLDAP groups.
pub fn write_openldap_group_ldif_chunk(path: &str, start: usize, count: usize) {
    use std::io::Write;
    let mut file = std::fs::File::create(path).unwrap();
    for i in start..start + count {
        let dn = format!("cn=loadgroup_{i},ou=groups,dc=test,dc=issuerd,dc=local");
        let dummy_member = "uid=dummy,ou=users,dc=test,dc=issuerd,dc=local";
        writeln!(file, "dn: {dn}").unwrap();
        writeln!(file, "changetype: add").unwrap();
        writeln!(file, "objectClass: groupOfNames").unwrap();
        writeln!(file, "objectClass: top").unwrap();
        writeln!(file, "cn: loadgroup_{i}").unwrap();
        writeln!(file, "member: {dummy_member}").unwrap();
        writeln!(file).unwrap();
    }
}

/// Generate LDIF modify entries to add members to OpenLDAP groups.
pub fn write_openldap_membership_ldif(path: &str, group_indices: &[usize], users_per_group: usize) {
    use std::io::Write;
    let mut file = std::fs::File::create(path).unwrap();
    for &gi in group_indices {
        let group_dn = format!("cn=loadgroup_{gi},ou=groups,dc=test,dc=issuerd,dc=local");
        writeln!(file, "dn: {group_dn}").unwrap();
        writeln!(file, "changetype: modify").unwrap();
        writeln!(file, "add: member").unwrap();
        for ui in 0..users_per_group {
            let user_dn = format!(
                "uid=loaduser_{},ou=users,dc=test,dc=issuerd,dc=local",
                gi * users_per_group + ui
            );
            writeln!(file, "member: {user_dn}").unwrap();
        }
        writeln!(file, "-").unwrap();
        writeln!(file).unwrap();
    }
}
