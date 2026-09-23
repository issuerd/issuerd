// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Declarative one-shot provisioning configuration model (realms, clients, users, ...).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Declarative configuration used to provision an Issuerd instance once.
///
/// The provisioner applies this config exactly once (tracked by a durable
/// marker in `Storage`). After the marker is written, subsequent server
/// restarts ignore the provision config entirely — admin changes are never
/// overwritten.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvisionConfig {
    /// Marker name used to track whether this provision has been applied.
    /// Defaults to `"default"` if omitted.
    #[serde(default)]
    pub marker: Option<String>,

    /// Realms to create.
    #[serde(default)]
    pub realms: Vec<ProvisionRealm>,

    /// Roles to create (realm-level).
    #[serde(default)]
    pub roles: Vec<ProvisionRole>,

    /// Groups to create.
    #[serde(default)]
    pub groups: Vec<ProvisionGroup>,

    /// Clients to create.
    #[serde(default)]
    pub clients: Vec<ProvisionClient>,

    /// Users to create (with optional credentials, roles and groups).
    #[serde(default)]
    pub users: Vec<ProvisionUser>,

    /// Identity / federation providers to create.
    #[serde(default)]
    pub identity_providers: Vec<ProvisionIdentityProvider>,

    /// Authentication flow configs to create.
    #[serde(default)]
    pub flow_configs: Vec<ProvisionFlowConfig>,
}

impl ProvisionConfig {
    /// Return the effective marker name.
    pub fn marker_name(&self) -> &str {
        self.marker.as_deref().unwrap_or("default")
    }

    /// Generate a fully-populated example config for documentation / CLI usage.
    pub fn generate_example() -> Self {
        let mut realm_attrs = HashMap::new();
        realm_attrs.insert("custom_attr".to_string(), "value".to_string());

        let mut user_attrs = HashMap::new();
        user_attrs.insert("department".to_string(), vec!["engineering".to_string()]);

        let mut idp_config = HashMap::new();
        idp_config.insert("url".to_string(), "ldap://localhost:389".to_string());
        idp_config.insert("users_dn".to_string(), "ou=users,dc=example,dc=com".to_string());
        idp_config.insert("bind_dn".to_string(), "cn=admin,dc=example,dc=com".to_string());

        Self {
            marker: Some("default".to_string()),
            realms: vec![ProvisionRealm {
                name: "myrealm".to_string(),
                display_name: Some("My Realm".to_string()),
                enabled: true,
                ssl_required: Some("external".to_string()),
                login_theme: None,
                email_theme: None,
                admin_theme: None,
                default_role: Some("user".to_string()),
                access_token_lifespan: Some(300),
                refresh_token_lifespan: Some(1800),
                sso_session_idle_timeout: Some(1800),
                sso_session_max_lifespan: Some(36000),
                offline_session_idle_timeout: Some(2592000),
                registration_enabled: Some(true),
                verify_email_enabled: Some(true),
                reset_password_allowed: Some(true),
                remember_me_enabled: Some(true),
                login_with_email_allowed: Some(true),
                browser_flow: Some("browser".to_string()),
                registration_flow: Some("registration".to_string()),
                attributes: realm_attrs,
            }],
            roles: vec![
                ProvisionRole {
                    realm: "myrealm".to_string(),
                    name: "admin".to_string(),
                    description: Some("Administrator role".to_string()),
                },
                ProvisionRole {
                    realm: "myrealm".to_string(),
                    name: "user".to_string(),
                    description: Some("Standard user role".to_string()),
                },
            ],
            groups: vec![
                ProvisionGroup {
                    realm: "myrealm".to_string(),
                    name: "developers".to_string(),
                    path: Some("/developers".to_string()),
                    attributes: HashMap::new(),
                    realm_roles: vec![],
                    client_roles: HashMap::new(),
                },
                ProvisionGroup {
                    realm: "myrealm".to_string(),
                    name: "ops".to_string(),
                    path: None,
                    attributes: HashMap::new(),
                    realm_roles: vec![],
                    client_roles: HashMap::new(),
                },
            ],
            clients: vec![
                ProvisionClient {
                    realm: "myrealm".to_string(),
                    client_id: "my-app".to_string(),
                    name: Some("My Application".to_string()),
                    description: Some("Main web application".to_string()),
                    enabled: true,
                    public_client: false,
                    bearer_only: false,
                    secret: None,
                    redirect_uris: vec![
                        "http://localhost:3000/callback".to_string(),
                        "http://localhost:3000/login".to_string(),
                    ],
                    web_origins: vec!["http://localhost:3000".to_string()],
                    default_scopes: vec!["openid".to_string(), "profile".to_string()],
                    optional_scopes: vec!["email".to_string()],
                    consent_required: false,
                    full_scope_allowed: true,
                },
                ProvisionClient {
                    realm: "myrealm".to_string(),
                    client_id: "public-app".to_string(),
                    name: Some("Public SPA".to_string()),
                    description: Some("Single-page application".to_string()),
                    enabled: true,
                    public_client: true,
                    bearer_only: false,
                    secret: None,
                    redirect_uris: vec!["http://localhost:4000/callback".to_string()],
                    web_origins: vec!["http://localhost:4000".to_string()],
                    default_scopes: vec!["openid".to_string()],
                    optional_scopes: vec![],
                    consent_required: false,
                    full_scope_allowed: true,
                },
            ],
            users: vec![ProvisionUser {
                realm: "myrealm".to_string(),
                username: "alice".to_string(),
                email: Some("alice@example.com".to_string()),
                email_verified: true,
                first_name: Some("Alice".to_string()),
                last_name: Some("Anderson".to_string()),
                enabled: true,
                password: Some("changeme".to_string()),
                realm_roles: vec!["admin".to_string(), "user".to_string()],
                groups: vec!["developers".to_string()],
                attributes: user_attrs,
            }],
            identity_providers: vec![ProvisionIdentityProvider {
                realm: "myrealm".to_string(),
                alias: "corporate-ldap".to_string(),
                provider_id: "ldap".to_string(),
                enabled: true,
                config: idp_config,
            }],
            flow_configs: vec![ProvisionFlowConfig {
                realm: "myrealm".to_string(),
                alias: "browser".to_string(),
                provider_id: Some("basic-flow".to_string()),
                top_level: true,
                built_in: false,
                stages: vec![
                    ProvisionFlowStage {
                        id: "cookie".to_string(),
                        requirement: "alternative".to_string(),
                        authenticator: "auth-cookie".to_string(),
                        priority: 10,
                        sub_flow_alias: None,
                    },
                    ProvisionFlowStage {
                        id: "username-password".to_string(),
                        requirement: "required".to_string(),
                        authenticator: "auth-username-password".to_string(),
                        priority: 20,
                        sub_flow_alias: None,
                    },
                ],
            }],
        }
    }
}

// ---------------------------------------------------------------------------
// Realm
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionRealm {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub ssl_required: Option<String>,
    #[serde(default)]
    pub login_theme: Option<String>,
    #[serde(default)]
    pub email_theme: Option<String>,
    #[serde(default)]
    pub admin_theme: Option<String>,
    #[serde(default)]
    pub default_role: Option<String>,
    #[serde(default)]
    pub access_token_lifespan: Option<u64>,
    #[serde(default)]
    pub refresh_token_lifespan: Option<u64>,
    #[serde(default)]
    pub sso_session_idle_timeout: Option<u64>,
    #[serde(default)]
    pub sso_session_max_lifespan: Option<u64>,
    #[serde(default)]
    pub offline_session_idle_timeout: Option<u64>,
    /// Enable user self-registration (default: realm default `false`).
    #[serde(default)]
    pub registration_enabled: Option<bool>,
    /// Require email verification for the realm (default: realm default `false`).
    #[serde(default)]
    pub verify_email_enabled: Option<bool>,
    /// Allow users to reset their password (default: realm default `false`).
    #[serde(default)]
    pub reset_password_allowed: Option<bool>,
    /// Show the "remember me" checkbox on the login page (default: realm default `false`).
    #[serde(default)]
    pub remember_me_enabled: Option<bool>,
    /// Allow login with the email address as username (default: realm default `true`).
    #[serde(default)]
    pub login_with_email_allowed: Option<bool>,
    /// Alias of the realm's browser login flow binding (`None` = system default).
    #[serde(default)]
    pub browser_flow: Option<String>,
    /// Alias of the realm's registration flow binding (`None` = system default).
    #[serde(default)]
    pub registration_flow: Option<String>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionRole {
    pub realm: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Group
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionGroup {
    pub realm: String,
    pub name: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub attributes: HashMap<String, Vec<String>>,
    /// Realm role names assigned to the group (members inherit them).
    #[serde(default)]
    pub realm_roles: Vec<String>,
    /// Client role names assigned to the group, keyed by `client_id`.
    #[serde(default)]
    pub client_roles: HashMap<String, Vec<String>>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionClient {
    pub realm: String,
    pub client_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub public_client: bool,
    #[serde(default)]
    pub bearer_only: bool,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub web_origins: Vec<String>,
    #[serde(default)]
    pub default_scopes: Vec<String>,
    #[serde(default)]
    pub optional_scopes: Vec<String>,
    #[serde(default)]
    pub consent_required: bool,
    #[serde(default = "default_true")]
    pub full_scope_allowed: bool,
}

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionUser {
    pub realm: String,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default = "default_false")]
    pub email_verified: bool,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Plain-text password. Hashed with Argon2id by the provisioner.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub realm_roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub attributes: HashMap<String, Vec<String>>,
}

// ---------------------------------------------------------------------------
// Identity / Federation Provider
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionIdentityProvider {
    pub realm: String,
    pub alias: String,
    pub provider_id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub config: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Flow Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionFlowConfig {
    pub realm: String,
    pub alias: String,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default = "default_true")]
    pub top_level: bool,
    #[serde(default = "default_false")]
    pub built_in: bool,
    #[serde(default)]
    pub stages: Vec<ProvisionFlowStage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionFlowStage {
    pub id: String,
    pub requirement: String,
    pub authenticator: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub sub_flow_alias: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_roundtrip_yaml() {
        let original = ProvisionConfig::generate_example();
        let yaml = serde_yaml::to_string(&original).unwrap();
        let loaded: ProvisionConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(original.marker, loaded.marker);
        assert_eq!(original.realms.len(), loaded.realms.len());
        assert_eq!(original.realms[0].name, loaded.realms[0].name);
        assert_eq!(original.roles.len(), loaded.roles.len());
        assert_eq!(original.groups.len(), loaded.groups.len());
        assert_eq!(original.clients.len(), loaded.clients.len());
        assert_eq!(original.users.len(), loaded.users.len());
        assert_eq!(original.identity_providers.len(), loaded.identity_providers.len());
        assert_eq!(original.flow_configs.len(), loaded.flow_configs.len());
    }

    #[test]
    fn example_roundtrip_json() {
        let original = ProvisionConfig::generate_example();
        let json = serde_json::to_string_pretty(&original).unwrap();
        let loaded: ProvisionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original.marker, loaded.marker);
        assert_eq!(original.realms.len(), loaded.realms.len());
        assert_eq!(original.users[0].username, loaded.users[0].username);
    }

    #[test]
    fn example_roundtrip_toml() {
        let original = ProvisionConfig::generate_example();
        let toml = toml::to_string_pretty(&original).unwrap();
        let loaded: ProvisionConfig = toml::from_str(&toml).unwrap();
        assert_eq!(original.marker, loaded.marker);
        assert_eq!(original.realms.len(), loaded.realms.len());
        assert_eq!(original.clients[0].client_id, loaded.clients[0].client_id);
    }

    #[test]
    fn realm_login_flags_and_flow_bindings_parse() {
        let yaml = r#"
name: flagged
registration_enabled: true
verify_email_enabled: true
reset_password_allowed: true
remember_me_enabled: false
login_with_email_allowed: false
browser_flow: custom-browser
registration_flow: custom-registration
"#;
        let realm: ProvisionRealm = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(realm.registration_enabled, Some(true));
        assert_eq!(realm.verify_email_enabled, Some(true));
        assert_eq!(realm.reset_password_allowed, Some(true));
        assert_eq!(realm.remember_me_enabled, Some(false));
        assert_eq!(realm.login_with_email_allowed, Some(false));
        assert_eq!(realm.browser_flow.as_deref(), Some("custom-browser"));
        assert_eq!(realm.registration_flow.as_deref(), Some("custom-registration"));
    }

    #[test]
    fn realm_login_flags_and_flow_bindings_default_to_none() {
        let realm: ProvisionRealm = serde_yaml::from_str("name: minimal").unwrap();
        assert!(realm.registration_enabled.is_none());
        assert!(realm.verify_email_enabled.is_none());
        assert!(realm.reset_password_allowed.is_none());
        assert!(realm.remember_me_enabled.is_none());
        assert!(realm.login_with_email_allowed.is_none());
        assert!(realm.browser_flow.is_none());
        assert!(realm.registration_flow.is_none());
    }

    /// Verify the committed `examples/provision.example.yaml` is valid and matches the
    /// generated example struct. If this fails, regenerate with:
    ///   cargo run --bin issuerd -- example provision-config -o examples/provision.example.yaml
    #[test]
    fn committed_example_file_is_valid() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let example_path = manifest
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/provision.example.yaml");
        let yaml = std::fs::read_to_string(&example_path)
            .unwrap_or_else(|e| panic!("failed to read examples/provision.example.yaml: {e}"));
        let loaded: ProvisionConfig = serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("failed to parse examples/provision.example.yaml: {e}"));
        let generated = ProvisionConfig::generate_example();
        assert_eq!(loaded.marker, generated.marker);
        assert_eq!(loaded.realms.len(), generated.realms.len());
        assert_eq!(loaded.realms[0].name, generated.realms[0].name);
        assert_eq!(loaded.roles.len(), generated.roles.len());
        assert_eq!(loaded.groups.len(), generated.groups.len());
        assert_eq!(loaded.clients.len(), generated.clients.len());
        assert_eq!(loaded.users.len(), generated.users.len());
        assert_eq!(loaded.identity_providers.len(), generated.identity_providers.len());
        assert_eq!(loaded.flow_configs.len(), generated.flow_configs.len());
    }
}
