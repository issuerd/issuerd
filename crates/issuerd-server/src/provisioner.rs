// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Loads and applies a ProvisionConfig file (TOML/YAML/JSON) to storage exactly once.

use std::collections::HashMap;
use std::path::Path;

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use issuerd_core::{
    Alias, Client, ClientAuthenticatorType, ClientId, ClientIdentifier, ClientProtocol, Credential,
    CredentialId, CredentialType, DisplayName, Email, FlowConfig, FlowStage, FlowStageId, Group,
    GroupId, GroupName, GroupPath, IdentityProviderConfig, IdentityProviderId, PasswordPolicy,
    ProvisionConfig, Realm, RealmId, RealmName, RedirectUri, Requirement, Role, RoleId, RoleName,
    Scope, SecondsNonZero, SslRequired, Storage, User, UserId, Username, WebOrigin,
};
use rand::rngs::OsRng;
use tracing::{info, warn};

/// Loads and applies a `ProvisionConfig` to `Storage` exactly once.
pub struct Provisioner {
    config: ProvisionConfig,
}

impl Provisioner {
    /// Load a provision config from a file path.
    ///
    /// Supported formats: TOML, YAML, JSON (detected by extension).
    /// Environment variable substitution (`${VAR}`) is performed on all
    /// string values after deserialization.
    pub fn from_file(path: &Path) -> Result<Self, issuerd_core::IssuerdError> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();

        let raw = std::fs::read_to_string(path).map_err(|e| {
            issuerd_core::IssuerdError::ServerError(format!("cannot read provision file: {e}"))
        })?;

        let mut config: ProvisionConfig = match ext.as_str() {
            "yaml" | "yml" => serde_yaml::from_str(&raw).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("provision yaml parse: {e}"))
            })?,
            "json" => serde_json::from_str(&raw).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("provision json parse: {e}"))
            })?,
            _ => toml::from_str(&raw).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("provision toml parse: {e}"))
            })?,
        };

        Self::substitute_env(&mut config)?;
        Ok(Self { config })
    }

    /// Apply the provision config to storage **once**.
    ///
    /// If the provision marker already exists, this is a no-op.
    /// `base_url` (typically the configured issuer URL) is used to build the
    /// redirect URIs of the per-realm built-in clients.
    pub async fn apply_once(
        &self,
        storage: &dyn Storage,
        base_url: &str,
    ) -> Result<(), issuerd_core::IssuerdError> {
        let marker = self.config.marker_name();

        // Claim the marker atomically *before* applying: a concurrent first
        // boot must not run the whole provisioning twice (P3-14).
        if !storage.claim_provision_marker(marker, "applied").await? {
            info!(marker = %marker, "provision already applied; skipping");
            return Ok(());
        }

        info!(marker = %marker, "applying provision config");
        self.apply_realms(storage, base_url).await?;
        self.apply_roles(storage).await?;
        self.apply_clients(storage).await?;
        // Groups after clients: group client-role mappings resolve clients.
        self.apply_groups(storage).await?;
        self.apply_users(storage).await?;
        self.apply_identity_providers(storage).await?;
        self.apply_flow_configs(storage).await?;

        info!(marker = %marker, "provision config applied successfully");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Realms
    // ------------------------------------------------------------------

    async fn apply_realms(
        &self,
        storage: &dyn Storage,
        base_url: &str,
    ) -> Result<(), issuerd_core::IssuerdError> {
        for p in &self.config.realms {
            let name = RealmName::new(&p.name).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("realm '{}': {e}", p.name))
            })?;

            // Use a generated UUID for the realm ID so PostgresStorage is happy.
            let id = RealmId::new(issuerd_core::utils::generate_id()).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("realm '{}': {e}", p.name))
            })?;

            if storage.get_realm_by_name(&p.name).await?.is_some() {
                warn!(realm = %p.name, "realm already exists; skipping");
                continue;
            }

            let defaults = Realm::default();
            let realm = Realm {
                id,
                name,
                display_name: p.display_name.as_ref().and_then(|d| DisplayName::new(d).ok()),
                enabled: p.enabled,
                ssl_required: parse_ssl_required(p.ssl_required.as_deref()),
                password_policy: PasswordPolicy::default(),
                login_theme: p
                    .login_theme
                    .as_ref()
                    .and_then(|t| issuerd_core::ThemeName::new(t).ok()),
                email_theme: p
                    .email_theme
                    .as_ref()
                    .and_then(|t| issuerd_core::ThemeName::new(t).ok()),
                admin_theme: p
                    .admin_theme
                    .as_ref()
                    .and_then(|t| issuerd_core::ThemeName::new(t).ok()),
                default_role: p.default_role.clone(),
                access_token_lifespan: nonzero_lifespan(
                    p.access_token_lifespan,
                    300,
                    "access_token_lifespan",
                    &p.name,
                )?,
                refresh_token_lifespan: nonzero_lifespan(
                    p.refresh_token_lifespan,
                    1800,
                    "refresh_token_lifespan",
                    &p.name,
                )?,
                sso_session_idle_timeout: nonzero_lifespan(
                    p.sso_session_idle_timeout,
                    1800,
                    "sso_session_idle_timeout",
                    &p.name,
                )?,
                sso_session_max_lifespan: nonzero_lifespan(
                    p.sso_session_max_lifespan,
                    36000,
                    "sso_session_max_lifespan",
                    &p.name,
                )?,
                offline_session_idle_timeout: nonzero_lifespan(
                    p.offline_session_idle_timeout,
                    2592000,
                    "offline_session_idle_timeout",
                    &p.name,
                )?,
                // Optional login/registration flags and flow bindings fall back
                // to the `Realm` defaults when the provision file omits them.
                registration_enabled: p
                    .registration_enabled
                    .unwrap_or(defaults.registration_enabled),
                verify_email_enabled: p
                    .verify_email_enabled
                    .unwrap_or(defaults.verify_email_enabled),
                reset_password_allowed: p
                    .reset_password_allowed
                    .unwrap_or(defaults.reset_password_allowed),
                remember_me_enabled: p.remember_me_enabled.unwrap_or(defaults.remember_me_enabled),
                login_with_email_allowed: p
                    .login_with_email_allowed
                    .unwrap_or(defaults.login_with_email_allowed),
                browser_flow: p.browser_flow.clone(),
                registration_flow: p.registration_flow.clone(),
                attributes: p.attributes.clone(),
                ..defaults
            };

            storage.create_realm(&realm).await?;

            // Auto-provision built-in clients (account-console, admin-cli) so
            // the account SPA and admin-style logins work for this realm,
            // matching what the Admin API does on realm creation.
            let account_client = issuerd_admin_api::realms::build_account_console_client(
                &realm.id,
                realm.name.as_str(),
                base_url,
            )?;
            if let Err(e) = storage.create_client(&realm.id, &account_client).await {
                warn!(realm = %p.name, client = "account-console", error = %e, "failed to create built-in client");
            }
            let admin_cli = issuerd_admin_api::realms::build_admin_cli_client(&realm.id, base_url)?;
            if let Err(e) = storage.create_client(&realm.id, &admin_cli).await {
                warn!(realm = %p.name, client = "admin-cli", error = %e, "failed to create built-in client");
            }

            info!(realm = %p.name, "provisioned realm");
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Roles
    // ------------------------------------------------------------------

    async fn apply_roles(&self, storage: &dyn Storage) -> Result<(), issuerd_core::IssuerdError> {
        for p in &self.config.roles {
            let realm_id = self.resolve_realm_id(storage, &p.realm).await?;
            let name = RoleName::new(&p.name).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("role '{}': {e}", p.name))
            })?;

            if storage.get_role_by_name(&realm_id, &p.name).await?.is_some() {
                warn!(realm = %p.realm, role = %p.name, "role already exists; skipping");
                continue;
            }

            let role = Role {
                id: RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
                name,
                description: p.description.clone(),
                realm_id,
                client_role: false,
                client_id: None,
                composite: false,
                composites: vec![],
                attributes: HashMap::new(),
            };

            storage.create_role(&role.realm_id, &role).await?;
            info!(realm = %p.realm, role = %p.name, "provisioned role");
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------

    async fn apply_groups(&self, storage: &dyn Storage) -> Result<(), issuerd_core::IssuerdError> {
        for p in &self.config.groups {
            let realm_id = self.resolve_realm_id(storage, &p.realm).await?;
            let name = GroupName::new(&p.name).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("group '{}': {e}", p.name))
            })?;

            // Dedup by name within realm via a direct lookup — paging through
            // `list_groups` would miss groups past the first page.
            if storage.get_group_by_name(&realm_id, &p.name).await?.is_some() {
                warn!(realm = %p.realm, group = %p.name, "group already exists; skipping");
                continue;
            }

            let path = p
                .path
                .as_ref()
                .and_then(|p| GroupPath::new(p).ok())
                .unwrap_or_else(|| GroupPath::new(format!("/{}", p.name)).unwrap());

            let mut realm_roles = Vec::new();
            for role_name in &p.realm_roles {
                if storage.get_role_by_name(&realm_id, role_name).await?.is_some() {
                    realm_roles.push(RoleName::new(role_name).map_err(|e| {
                        issuerd_core::IssuerdError::ServerError(format!("role '{role_name}': {e}"))
                    })?);
                } else {
                    warn!(realm = %p.realm, group = %p.name, role = %role_name, "role not found; skipping group mapping");
                }
            }

            let mut client_roles = HashMap::new();
            for (client_id, names) in &p.client_roles {
                let Ok(identifier) = ClientIdentifier::new(client_id) else {
                    warn!(realm = %p.realm, group = %p.name, client = %client_id, "invalid client_id; skipping group mapping");
                    continue;
                };
                let Some(client) = storage.get_client_by_client_id(&realm_id, &identifier).await?
                else {
                    warn!(realm = %p.realm, group = %p.name, client = %client_id, "client not found; skipping group mapping");
                    continue;
                };
                let mut resolved = Vec::new();
                for role_name in names {
                    if storage
                        .get_client_role_by_name(&realm_id, &client.id, role_name)
                        .await?
                        .is_some()
                    {
                        resolved.push(RoleName::new(role_name).map_err(|e| {
                            issuerd_core::IssuerdError::ServerError(format!(
                                "role '{role_name}': {e}"
                            ))
                        })?);
                    } else {
                        warn!(realm = %p.realm, group = %p.name, client = %client_id, role = %role_name, "client role not found; skipping group mapping");
                    }
                }
                if !resolved.is_empty() {
                    client_roles.insert(client.id, resolved);
                }
            }

            let group = Group {
                id: GroupId::new(issuerd_core::utils::generate_id()).unwrap(),
                name,
                path,
                realm_id,
                parent_id: None,
                sub_groups: vec![],
                attributes: p.attributes.clone(),
                realm_roles,
                client_roles,
            };

            storage.create_group(&group.realm_id, &group).await?;
            info!(realm = %p.realm, group = %p.name, "provisioned group");
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Clients
    // ------------------------------------------------------------------

    async fn apply_clients(&self, storage: &dyn Storage) -> Result<(), issuerd_core::IssuerdError> {
        for p in &self.config.clients {
            let realm_id = self.resolve_realm_id(storage, &p.realm).await?;
            let client_id = ClientIdentifier::new(&p.client_id).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("client '{}': {e}", p.client_id))
            })?;

            if storage.get_client_by_client_id(&realm_id, &client_id).await?.is_some() {
                warn!(realm = %p.realm, client = %p.client_id, "client already exists; skipping");
                continue;
            }

            let secret = p.secret.clone().or_else(|| {
                if p.public_client {
                    None
                } else {
                    Some(issuerd_core::utils::generate_id())
                }
            });

            let client = Client {
                id: ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
                realm_id,
                client_id,
                name: p.name.as_ref().and_then(|n| DisplayName::new(n).ok()),
                description: p.description.clone(),
                enabled: p.enabled,
                protocol: ClientProtocol::OpenIdConnect,
                public_client: p.public_client,
                bearer_only: p.bearer_only,
                client_authenticator_type: ClientAuthenticatorType::ClientSecret,
                secret,
                redirect_uris: p
                    .redirect_uris
                    .iter()
                    .filter_map(|u| match RedirectUri::new(u) {
                        Ok(uri) => Some(uri),
                        Err(e) => {
                            warn!(realm = %p.realm, client = %p.client_id, uri = %u, error = %e, "invalid redirect URI in provision config; dropping");
                            None
                        }
                    })
                    .collect(),
                web_origins: p
                    .web_origins
                    .iter()
                    .filter_map(|o| match WebOrigin::new(o) {
                        Ok(origin) => Some(origin),
                        Err(e) => {
                            warn!(realm = %p.realm, client = %p.client_id, origin = %o, error = %e, "invalid web origin in provision config; dropping");
                            None
                        }
                    })
                    .collect(),
                default_scopes: if p.default_scopes.is_empty() {
                    Scope::parse("openid profile")
                } else {
                    Scope::parse(&p.default_scopes.join(" "))
                },
                optional_scopes: if p.optional_scopes.is_empty() {
                    Scope::empty()
                } else {
                    Scope::parse(&p.optional_scopes.join(" "))
                },
                consent_required: p.consent_required,
                full_scope_allowed: p.full_scope_allowed,
                service_accounts_enabled: false,
                protocol_mappers: Vec::new(),
                scope_mappings: Default::default(),
                attributes: HashMap::new(),
            };

            storage.create_client(&client.realm_id, &client).await?;
            info!(realm = %p.realm, client = %p.client_id, "provisioned client");
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Users
    // ------------------------------------------------------------------

    async fn apply_users(&self, storage: &dyn Storage) -> Result<(), issuerd_core::IssuerdError> {
        for p in &self.config.users {
            let realm_id = self.resolve_realm_id(storage, &p.realm).await?;
            let username = Username::new(&p.username).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("user '{}': {e}", p.username))
            })?;

            if storage.get_user_by_username(&realm_id, &p.username).await?.is_some() {
                warn!(realm = %p.realm, user = %p.username, "user already exists; skipping");
                continue;
            }

            let user_id = UserId::new(issuerd_core::utils::generate_id()).unwrap();
            let user = User {
                id: user_id.clone(),
                realm_id: realm_id.clone(),
                username,
                email: p.email.as_ref().and_then(|e| Email::new(e).ok()),
                email_verified: p.email_verified,
                first_name: p.first_name.as_ref().and_then(|n| DisplayName::new(n).ok()),
                last_name: p.last_name.as_ref().and_then(|n| DisplayName::new(n).ok()),
                enabled: p.enabled,
                federation_link: None,
                attributes: p.attributes.clone(),
                required_actions: Vec::new(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            storage.create_user(&realm_id, &user).await?;

            // Password
            if let Some(plain) = &p.password {
                let hash = hash_password(plain)?;
                let cred = Credential {
                    id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
                    credential_type: CredentialType::Password,
                    user_label: Some("Password".to_string()),
                    created_date: chrono::Utc::now(),
                    secret_data: hash.into_bytes(),
                    credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
                    priority: 1,
                };
                storage.create_credential(&realm_id, &user_id, &cred).await?;
                info!(realm = %p.realm, user = %p.username, "provisioned user with password");
            } else {
                info!(realm = %p.realm, user = %p.username, "provisioned user without password");
            }

            // Realm roles
            for role_name in &p.realm_roles {
                if let Some(role) = storage.get_role_by_name(&realm_id, role_name).await? {
                    storage.add_user_realm_role(&realm_id, &user_id, &role.id).await?;
                } else {
                    warn!(realm = %p.realm, user = %p.username, role = %role_name, "role not found; skipping assignment");
                }
            }

            // Groups
            for group_name in &p.groups {
                if let Some(group) = storage.get_group_by_name(&realm_id, group_name).await? {
                    storage.add_user_group(&realm_id, &user_id, &group.id).await?;
                } else {
                    warn!(realm = %p.realm, user = %p.username, group = %group_name, "group not found; skipping assignment");
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Identity Providers
    // ------------------------------------------------------------------

    async fn apply_identity_providers(
        &self,
        storage: &dyn Storage,
    ) -> Result<(), issuerd_core::IssuerdError> {
        for p in &self.config.identity_providers {
            let realm_id = self.resolve_realm_id(storage, &p.realm).await?;
            let alias = Alias::new(&p.alias).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("idp '{}': {e}", p.alias))
            })?;

            if storage.get_identity_provider_by_alias(&realm_id, &p.alias).await?.is_some() {
                warn!(realm = %p.realm, alias = %p.alias, "identity provider already exists; skipping");
                continue;
            }

            let idp = IdentityProviderConfig {
                id: IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap(),
                alias,
                provider_id: parse_provider_id(&p.provider_id),
                enabled: p.enabled,
                config: p.config.clone(),
            };

            storage.create_identity_provider(&realm_id, &idp).await?;
            info!(realm = %p.realm, alias = %p.alias, "provisioned identity provider");
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Flow Configs
    // ------------------------------------------------------------------

    async fn apply_flow_configs(
        &self,
        storage: &dyn Storage,
    ) -> Result<(), issuerd_core::IssuerdError> {
        for p in &self.config.flow_configs {
            let realm_id = self.resolve_realm_id(storage, &p.realm).await?;
            let alias = Alias::new(&p.alias).map_err(|e| {
                issuerd_core::IssuerdError::ServerError(format!("flow '{}': {e}", p.alias))
            })?;

            if storage.get_flow_config(&realm_id, &p.alias).await?.is_some() {
                warn!(realm = %p.realm, alias = %p.alias, "flow config already exists; skipping");
                continue;
            }

            let stages: Result<Vec<FlowStage>, issuerd_core::IssuerdError> = p
                .stages
                .iter()
                .map(|s| {
                    Ok(FlowStage {
                        id: FlowStageId::new(&s.id).map_err(|e| {
                            issuerd_core::IssuerdError::ServerError(format!(
                                "flow stage '{}': {e}",
                                s.id
                            ))
                        })?,
                        requirement: parse_requirement(&s.requirement)?,
                        authenticator: Alias::new(&s.authenticator).map_err(|e| {
                            issuerd_core::IssuerdError::ServerError(format!(
                                "authenticator '{}': {e}",
                                s.authenticator
                            ))
                        })?,
                        priority: s.priority,
                        sub_flow_alias: s.sub_flow_alias.as_ref().and_then(|a| Alias::new(a).ok()),
                        authenticator_config: None,
                    })
                })
                .collect();

            let flow = FlowConfig {
                alias,
                realm_id: realm_id.clone(),
                provider_id: p.provider_id.clone().unwrap_or_else(|| "basic-flow".to_string()),
                top_level: p.top_level,
                built_in: p.built_in,
                stages: stages?,
            };

            storage.create_flow_config(&realm_id, &flow).await?;
            info!(realm = %p.realm, alias = %p.alias, "provisioned flow config");
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    async fn resolve_realm_id(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<RealmId, issuerd_core::IssuerdError> {
        storage.get_realm_by_name(name).await?.map(|r| r.id).ok_or_else(|| {
            issuerd_core::IssuerdError::ServerError(format!("realm '{}' not found", name))
        })
    }

    /// Recursively substitute `${VAR}` patterns in all string fields.
    fn substitute_env(config: &mut ProvisionConfig) -> Result<(), issuerd_core::IssuerdError> {
        let mut errors = Vec::new();

        for realm in &mut config.realms {
            realm.name = substitute(&realm.name, &mut errors);
            realm.display_name = realm.display_name.as_ref().map(|s| substitute(s, &mut errors));
            realm.ssl_required = realm.ssl_required.as_ref().map(|s| substitute(s, &mut errors));
            realm.login_theme = realm.login_theme.as_ref().map(|s| substitute(s, &mut errors));
            realm.email_theme = realm.email_theme.as_ref().map(|s| substitute(s, &mut errors));
            realm.admin_theme = realm.admin_theme.as_ref().map(|s| substitute(s, &mut errors));
            realm.default_role = realm.default_role.as_ref().map(|s| substitute(s, &mut errors));
            realm.browser_flow = realm.browser_flow.as_ref().map(|s| substitute(s, &mut errors));
            realm.registration_flow =
                realm.registration_flow.as_ref().map(|s| substitute(s, &mut errors));
            for v in realm.attributes.values_mut() {
                *v = substitute(v, &mut errors);
            }
        }

        for role in &mut config.roles {
            role.realm = substitute(&role.realm, &mut errors);
            role.name = substitute(&role.name, &mut errors);
            role.description = role.description.as_ref().map(|s| substitute(s, &mut errors));
        }

        for group in &mut config.groups {
            group.realm = substitute(&group.realm, &mut errors);
            group.name = substitute(&group.name, &mut errors);
            group.path = group.path.as_ref().map(|s| substitute(s, &mut errors));
        }

        for client in &mut config.clients {
            client.realm = substitute(&client.realm, &mut errors);
            client.client_id = substitute(&client.client_id, &mut errors);
            client.name = client.name.as_ref().map(|s| substitute(s, &mut errors));
            client.description = client.description.as_ref().map(|s| substitute(s, &mut errors));
            client.secret = client.secret.as_ref().map(|s| substitute(s, &mut errors));
            for uri in &mut client.redirect_uris {
                *uri = substitute(uri, &mut errors);
            }
            for origin in &mut client.web_origins {
                *origin = substitute(origin, &mut errors);
            }
        }

        for user in &mut config.users {
            user.realm = substitute(&user.realm, &mut errors);
            user.username = substitute(&user.username, &mut errors);
            user.email = user.email.as_ref().map(|s| substitute(s, &mut errors));
            user.first_name = user.first_name.as_ref().map(|s| substitute(s, &mut errors));
            user.last_name = user.last_name.as_ref().map(|s| substitute(s, &mut errors));
            user.password = user.password.as_ref().map(|s| substitute(s, &mut errors));
            for role in &mut user.realm_roles {
                *role = substitute(role, &mut errors);
            }
            for group in &mut user.groups {
                *group = substitute(group, &mut errors);
            }
        }

        for idp in &mut config.identity_providers {
            idp.realm = substitute(&idp.realm, &mut errors);
            idp.alias = substitute(&idp.alias, &mut errors);
            idp.provider_id = substitute(&idp.provider_id, &mut errors);
            for v in idp.config.values_mut() {
                *v = substitute(v, &mut errors);
            }
        }

        for flow in &mut config.flow_configs {
            flow.realm = substitute(&flow.realm, &mut errors);
            flow.alias = substitute(&flow.alias, &mut errors);
            for stage in &mut flow.stages {
                stage.id = substitute(&stage.id, &mut errors);
                stage.requirement = substitute(&stage.requirement, &mut errors);
                stage.authenticator = substitute(&stage.authenticator, &mut errors);
                stage.sub_flow_alias =
                    stage.sub_flow_alias.as_ref().map(|s| substitute(s, &mut errors));
            }
        }

        if !errors.is_empty() {
            return Err(issuerd_core::IssuerdError::ServerError(format!(
                "environment substitution failed: {}",
                errors.join(", ")
            )));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn hash_password(plain: &str) -> Result<String, issuerd_core::IssuerdError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| issuerd_core::IssuerdError::ServerError(format!("password hash failed: {e}")))
        .map(|h| h.to_string())
}

fn substitute(value: &str, errors: &mut Vec<String>) -> String {
    let mut result = value.to_string();
    let mut pos = 0;
    while let Some(rel) = result[pos..].find("${") {
        let start = pos + rel;
        let Some(end) = result[start..].find('}') else {
            break;
        };
        let var_name = &result[start + 2..start + end];
        match std::env::var(var_name) {
            Ok(v) => {
                result.replace_range(start..start + end + 1, &v);
                // Continue scanning *after* the substituted text: never
                // rescan it, so a self-referential value cannot loop (P3-12).
                pos = start + v.len();
            }
            Err(_) => {
                errors.push(format!("${{{}}}", var_name));
                // Skip past the unresolved placeholder and keep scanning.
                pos = start + end + 1;
            }
        }
    }
    result
}

/// Build a [`SecondsNonZero`] lifespan, rejecting zero values from the
/// provision config instead of panicking (P3-11).
fn nonzero_lifespan(
    value: Option<u64>,
    default: u64,
    field: &str,
    realm: &str,
) -> Result<SecondsNonZero, issuerd_core::IssuerdError> {
    SecondsNonZero::try_from(value.unwrap_or(default)).map_err(|e| {
        issuerd_core::IssuerdError::ServerError(format!("realm '{realm}': invalid {field}: {e}"))
    })
}

fn parse_ssl_required(raw: Option<&str>) -> SslRequired {
    match raw {
        Some("none") => SslRequired::None,
        Some("all") => SslRequired::All,
        _ => SslRequired::External,
    }
}

fn parse_provider_id(raw: &str) -> issuerd_core::ProviderId {
    match raw {
        "ldap" => issuerd_core::ProviderId::Ldap,
        "kerberos" => issuerd_core::ProviderId::Kerberos,
        "oidc" => issuerd_core::ProviderId::Oidc,
        "saml" => issuerd_core::ProviderId::Saml,
        "social" => issuerd_core::ProviderId::Social,
        other => issuerd_core::ProviderId::Custom(other.to_string()),
    }
}

fn parse_requirement(raw: &str) -> Result<Requirement, issuerd_core::IssuerdError> {
    match raw {
        "required" => Ok(Requirement::Required),
        "alternative" => Ok(Requirement::Alternative),
        "optional" => Ok(Requirement::Optional),
        "disabled" => Ok(Requirement::Disabled),
        "conditional" => Ok(Requirement::Conditional),
        other => Err(issuerd_core::IssuerdError::ServerError(format!(
            "unknown requirement '{}'",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{
        CredentialType, Pagination, ProvisionClient, ProvisionFlowConfig, ProvisionFlowStage,
        ProvisionGroup, ProvisionIdentityProvider, ProvisionRealm, ProvisionRole, ProvisionUser,
    };
    use issuerd_storage::InMemoryStorage;
    use std::io::Write;

    fn sample_config() -> ProvisionConfig {
        ProvisionConfig {
            marker: Some("test-marker".to_string()),
            realms: vec![ProvisionRealm {
                name: "testrealm".to_string(),
                display_name: Some("Test Realm".to_string()),
                enabled: true,
                ssl_required: Some("external".to_string()),
                login_theme: None,
                email_theme: None,
                admin_theme: None,
                default_role: None,
                access_token_lifespan: None,
                refresh_token_lifespan: None,
                sso_session_idle_timeout: None,
                sso_session_max_lifespan: None,
                offline_session_idle_timeout: None,
                registration_enabled: None,
                verify_email_enabled: None,
                reset_password_allowed: None,
                remember_me_enabled: None,
                login_with_email_allowed: None,
                browser_flow: None,
                registration_flow: None,
                attributes: HashMap::new(),
            }],
            roles: vec![ProvisionRole {
                realm: "testrealm".to_string(),
                name: "admin".to_string(),
                description: Some("Administrator".to_string()),
            }],
            groups: vec![ProvisionGroup {
                realm: "testrealm".to_string(),
                name: "developers".to_string(),
                path: None,
                attributes: HashMap::new(),
                realm_roles: vec![],
                client_roles: HashMap::new(),
            }],
            clients: vec![
                ProvisionClient {
                    realm: "testrealm".to_string(),
                    client_id: "my-app".to_string(),
                    name: Some("My App".to_string()),
                    description: None,
                    enabled: true,
                    public_client: false,
                    bearer_only: false,
                    secret: None,
                    redirect_uris: vec!["http://localhost:3000/callback".to_string()],
                    web_origins: vec!["http://localhost:3000".to_string()],
                    default_scopes: vec![],
                    optional_scopes: vec![],
                    consent_required: false,
                    full_scope_allowed: true,
                },
                ProvisionClient {
                    realm: "testrealm".to_string(),
                    client_id: "public-app".to_string(),
                    name: Some("Public App".to_string()),
                    description: None,
                    enabled: true,
                    public_client: true,
                    bearer_only: false,
                    secret: None,
                    redirect_uris: vec!["http://localhost:3000/callback".to_string()],
                    web_origins: vec![],
                    default_scopes: vec![],
                    optional_scopes: vec![],
                    consent_required: false,
                    full_scope_allowed: true,
                },
            ],
            users: vec![ProvisionUser {
                realm: "testrealm".to_string(),
                username: "alice".to_string(),
                email: Some("alice@example.com".to_string()),
                email_verified: true,
                first_name: Some("Alice".to_string()),
                last_name: Some("Anderson".to_string()),
                enabled: true,
                password: Some("secret123".to_string()),
                realm_roles: vec!["admin".to_string()],
                groups: vec!["developers".to_string()],
                attributes: HashMap::new(),
            }],
            identity_providers: vec![ProvisionIdentityProvider {
                realm: "testrealm".to_string(),
                alias: "ldap-test".to_string(),
                provider_id: "ldap".to_string(),
                enabled: true,
                config: {
                    let mut m = HashMap::new();
                    m.insert("url".to_string(), "ldap://localhost:389".to_string());
                    m
                },
            }],
            flow_configs: vec![ProvisionFlowConfig {
                realm: "testrealm".to_string(),
                alias: "custom-browser".to_string(),
                provider_id: Some("basic-flow".to_string()),
                top_level: true,
                built_in: false,
                stages: vec![ProvisionFlowStage {
                    id: "cookie".to_string(),
                    requirement: "alternative".to_string(),
                    authenticator: "auth-cookie".to_string(),
                    priority: 10,
                    sub_flow_alias: None,
                }],
            }],
        }
    }

    #[tokio::test]
    async fn groups_get_role_mappings() {
        let storage = InMemoryStorage::new();
        let mut config = sample_config();
        config.groups[0].realm_roles = vec!["admin".to_string(), "ghost".to_string()];
        config.groups[0].client_roles =
            HashMap::from([("my-app".to_string(), vec!["editor".to_string()])]);

        // Pre-seed the realm, the my-app client and its "editor" client role so
        // the group mappings can resolve them (provisioning skips existing
        // entities and never creates client roles itself).
        let realm = Realm {
            id: RealmId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: RealmName::new("testrealm").unwrap(),
            ..Default::default()
        };
        storage.create_realm(&realm).await.unwrap();
        let client = Client {
            id: ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::default(),
            optional_scopes: Scope::default(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: vec![],
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        storage.create_client(&realm.id, &client).await.unwrap();
        let editor = Role {
            id: RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: RoleName::new("editor").unwrap(),
            description: None,
            realm_id: realm.id.clone(),
            client_role: true,
            client_id: Some(client.id.clone()),
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        storage.create_role(&realm.id, &editor).await.unwrap();

        let provisioner = Provisioner { config };
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let group = storage.get_group_by_name(&realm.id, "developers").await.unwrap().unwrap();
        // "ghost" does not exist — skipped with a warning.
        assert_eq!(group.realm_roles, vec![RoleName::new("admin").unwrap()]);
        assert_eq!(
            group.client_roles.get(&client.id),
            Some(&vec![RoleName::new("editor").unwrap()])
        );
    }

    #[tokio::test]
    async fn apply_once_is_idempotent() {
        let storage = InMemoryStorage::new();
        let provisioner = Provisioner {
            config: sample_config(),
        };

        // First call should apply everything.
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage
            .get_realm_by_name("testrealm")
            .await
            .unwrap()
            .expect("realm should exist");
        assert_eq!(realm.name.as_str(), "testrealm");

        // Second call should be a no-op because the marker exists.
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        // Realm should still exist (and not be recreated / duplicated).
        let realms = storage.list_realms(&Pagination::default()).await.unwrap();
        assert_eq!(realms.len(), 1);
    }

    #[tokio::test]
    async fn provisions_all_entity_types() {
        let storage = InMemoryStorage::new();
        let provisioner = Provisioner {
            config: sample_config(),
        };
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage.get_realm_by_name("testrealm").await.unwrap().expect("realm missing");
        assert!(realm.enabled);
        assert_eq!(realm.display_name.as_ref().map(|d| d.as_str()), Some("Test Realm"));

        let role = storage
            .get_role_by_name(&realm.id, "admin")
            .await
            .unwrap()
            .expect("role missing");
        assert_eq!(role.name.as_str(), "admin");
        assert!(!role.client_role);

        let groups = storage.list_groups(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name.as_str(), "developers");
        assert_eq!(groups[0].path.as_str(), "/developers");

        let client = storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("my-app").unwrap())
            .await
            .unwrap()
            .expect("client missing");
        assert_eq!(client.client_id.as_str(), "my-app");
        assert!(!client.public_client);
        assert!(client.secret.is_some());

        let user = storage
            .get_user_by_username(&realm.id, "alice")
            .await
            .unwrap()
            .expect("user missing");
        assert_eq!(user.username.as_str(), "alice");
        assert_eq!(user.email.as_ref().map(|e| e.as_str()), Some("alice@example.com"));
        assert!(user.enabled);

        let creds = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);

        let user_roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert_eq!(user_roles.len(), 1);
        assert_eq!(user_roles[0], role.id);

        let user_groups = storage.list_user_groups(&realm.id, &user.id).await.unwrap();
        assert_eq!(user_groups.len(), 1);
        assert_eq!(user_groups[0], groups[0].id);

        let idp = storage
            .get_identity_provider_by_alias(&realm.id, "ldap-test")
            .await
            .unwrap()
            .expect("idp missing");
        assert_eq!(idp.alias.as_str(), "ldap-test");
        assert_eq!(idp.config.get("url"), Some(&"ldap://localhost:389".to_string()));

        let flow = storage
            .get_flow_config(&realm.id, "custom-browser")
            .await
            .unwrap()
            .expect("flow missing");
        assert_eq!(flow.alias.as_str(), "custom-browser");
        assert!(flow.top_level);
        assert_eq!(flow.stages.len(), 1);
        assert_eq!(flow.stages[0].authenticator.as_str(), "auth-cookie");
    }

    #[tokio::test]
    async fn realm_login_flags_and_flow_bindings_applied() {
        let storage = InMemoryStorage::new();
        let mut config = sample_config();
        {
            let realm = &mut config.realms[0];
            realm.registration_enabled = Some(true);
            realm.verify_email_enabled = Some(true);
            realm.reset_password_allowed = Some(true);
            realm.remember_me_enabled = Some(true);
            realm.login_with_email_allowed = Some(false);
            realm.browser_flow = Some("custom-browser".to_string());
            realm.registration_flow = Some("custom-registration".to_string());
        }
        let provisioner = Provisioner { config };
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage.get_realm_by_name("testrealm").await.unwrap().expect("realm missing");
        assert!(realm.registration_enabled);
        assert!(realm.verify_email_enabled);
        assert!(realm.reset_password_allowed);
        assert!(realm.remember_me_enabled);
        assert!(!realm.login_with_email_allowed);
        assert_eq!(realm.browser_flow.as_deref(), Some("custom-browser"));
        assert_eq!(realm.registration_flow.as_deref(), Some("custom-registration"));
    }

    #[tokio::test]
    async fn realm_login_flags_default_when_unset() {
        let storage = InMemoryStorage::new();
        let provisioner = Provisioner {
            config: sample_config(),
        };
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage.get_realm_by_name("testrealm").await.unwrap().expect("realm missing");
        let defaults = Realm::default();
        assert_eq!(realm.registration_enabled, defaults.registration_enabled);
        assert_eq!(realm.verify_email_enabled, defaults.verify_email_enabled);
        assert_eq!(realm.reset_password_allowed, defaults.reset_password_allowed);
        assert_eq!(realm.remember_me_enabled, defaults.remember_me_enabled);
        assert_eq!(realm.login_with_email_allowed, defaults.login_with_email_allowed);
        assert_eq!(realm.browser_flow, defaults.browser_flow);
        assert_eq!(realm.registration_flow, defaults.registration_flow);
    }

    #[tokio::test]
    async fn password_is_hashed() {
        let storage = InMemoryStorage::new();
        let provisioner = Provisioner {
            config: sample_config(),
        };
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage.get_realm_by_name("testrealm").await.unwrap().unwrap();
        let user = storage.get_user_by_username(&realm.id, "alice").await.unwrap().unwrap();
        let creds = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);

        let secret = std::str::from_utf8(&creds[0].secret_data).unwrap();
        // The hash should be an Argon2id-encoded string, not the raw plaintext.
        assert!(!secret.contains("secret123"), "password must not be stored in plaintext");
        assert!(secret.starts_with("$argon2id$"), "expected argon2id hash prefix");
    }

    #[tokio::test]
    async fn client_secret_auto_generated_for_confidential() {
        let storage = InMemoryStorage::new();
        let provisioner = Provisioner {
            config: sample_config(),
        };
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage.get_realm_by_name("testrealm").await.unwrap().unwrap();
        let client = storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("my-app").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(client.secret.is_some());
        assert!(!client.secret.as_ref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn public_client_has_no_secret() {
        let storage = InMemoryStorage::new();
        let provisioner = Provisioner {
            config: sample_config(),
        };
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage.get_realm_by_name("testrealm").await.unwrap().unwrap();
        let client = storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("public-app").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(client.public_client);
        assert!(client.secret.is_none());
    }

    #[tokio::test]
    async fn env_substitution() {
        std::env::set_var("ISSUERD_TEST_REALM", "envrealm");
        std::env::set_var("ISSUERD_TEST_USER", "envuser");
        std::env::set_var("ISSUERD_TEST_FLOW", "custom-flow");

        let mut config = ProvisionConfig {
            marker: Some("env-marker".to_string()),
            realms: vec![ProvisionRealm {
                name: "${ISSUERD_TEST_REALM}".to_string(),
                display_name: None,
                enabled: true,
                ssl_required: None,
                login_theme: None,
                email_theme: None,
                admin_theme: None,
                default_role: None,
                access_token_lifespan: None,
                refresh_token_lifespan: None,
                sso_session_idle_timeout: None,
                sso_session_max_lifespan: None,
                offline_session_idle_timeout: None,
                registration_enabled: None,
                verify_email_enabled: None,
                reset_password_allowed: None,
                remember_me_enabled: None,
                login_with_email_allowed: None,
                browser_flow: Some("${ISSUERD_TEST_FLOW}".to_string()),
                registration_flow: Some("reg-${ISSUERD_TEST_FLOW}".to_string()),
                attributes: HashMap::new(),
            }],
            roles: vec![],
            groups: vec![],
            clients: vec![],
            users: vec![ProvisionUser {
                realm: "${ISSUERD_TEST_REALM}".to_string(),
                username: "${ISSUERD_TEST_USER}".to_string(),
                email: None,
                email_verified: false,
                first_name: None,
                last_name: None,
                enabled: true,
                password: None,
                realm_roles: vec![],
                groups: vec![],
                attributes: HashMap::new(),
            }],
            identity_providers: vec![],
            flow_configs: vec![],
        };

        Provisioner::substitute_env(&mut config).unwrap();
        let provisioner = Provisioner { config };
        let storage = InMemoryStorage::new();
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage
            .get_realm_by_name("envrealm")
            .await
            .unwrap()
            .expect("envrealm should exist");
        assert_eq!(realm.browser_flow.as_deref(), Some("custom-flow"));
        assert_eq!(realm.registration_flow.as_deref(), Some("reg-custom-flow"));
        let user = storage
            .get_user_by_username(&realm.id, "envuser")
            .await
            .unwrap()
            .expect("envuser should exist");
        assert_eq!(user.username.as_str(), "envuser");

        std::env::remove_var("ISSUERD_TEST_REALM");
        std::env::remove_var("ISSUERD_TEST_USER");
        std::env::remove_var("ISSUERD_TEST_FLOW");
    }

    #[tokio::test]
    async fn load_from_yaml_file() {
        let mut tmp = std::env::temp_dir();
        tmp.push("issuerd_provision_test.yaml");
        let yaml = r#"
marker: file-marker
realms:
  - name: filerealm
    display_name: File Realm
users:
  - realm: filerealm
    username: fileuser
    password: filepass
"#;
        {
            let mut f = std::fs::File::create(&tmp).unwrap();
            f.write_all(yaml.as_bytes()).unwrap();
        }

        let provisioner = Provisioner::from_file(&tmp).unwrap();
        let storage = InMemoryStorage::new();
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage
            .get_realm_by_name("filerealm")
            .await
            .unwrap()
            .expect("filerealm should exist");
        assert_eq!(realm.display_name.as_ref().map(|d| d.as_str()), Some("File Realm"));

        let user = storage
            .get_user_by_username(&realm.id, "fileuser")
            .await
            .unwrap()
            .expect("fileuser should exist");
        assert_eq!(user.username.as_str(), "fileuser");

        std::fs::remove_file(&tmp).ok();
    }

    #[tokio::test]
    async fn skips_existing_entities() {
        let storage = InMemoryStorage::new();
        let provisioner = Provisioner {
            config: sample_config(),
        };
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        // Run again with the same marker — should be a total no-op.
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage.get_realm_by_name("testrealm").await.unwrap().unwrap();
        let users = storage.list_users(&realm.id, "", &Pagination::default()).await.unwrap();
        assert_eq!(users.len(), 1, "user should not be duplicated");

        let roles = storage.list_roles(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(roles.len(), 1, "role should not be duplicated");

        let groups = storage.list_groups(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(groups.len(), 1, "group should not be duplicated");

        let clients = storage.list_clients(&realm.id, &Pagination::default()).await.unwrap();
        // 2 provisioned clients + 2 built-in clients (account-console, admin-cli).
        assert_eq!(clients.len(), 4, "clients should not be duplicated");
    }

    #[tokio::test]
    async fn provisions_builtin_clients_per_realm() {
        let storage = InMemoryStorage::new();
        let provisioner = Provisioner {
            config: sample_config(),
        };
        provisioner.apply_once(&storage, "http://localhost:8080").await.unwrap();

        let realm = storage.get_realm_by_name("testrealm").await.unwrap().unwrap();

        let account = storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("account-console").unwrap())
            .await
            .unwrap()
            .expect("account-console should be provisioned");
        assert!(account.public_client);
        let account_redirects: Vec<String> =
            account.redirect_uris.iter().map(|r| r.to_string()).collect();
        assert!(account_redirects
            .contains(&"http://localhost:8080/realms/testrealm/account".to_string()));

        let admin_cli = storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .expect("admin-cli should be provisioned");
        assert!(admin_cli.public_client);
    }
}
