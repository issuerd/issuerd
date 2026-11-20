// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Keycloak realm-export wire representations and conversion into the
//! endpoint's internal import document.

use std::collections::HashMap;

use issuerd_core::{ClientId, MapperType, RoleName};
use serde::Deserialize;

use crate::{
    dto::{
        ClientRepresentation, ClientScopeRepresentation, CompositeRoleReferences,
        GroupRepresentation, IdentityProviderRepresentation, IfResourceExists,
        PartialImportRepresentation, PartialImportRolesRepresentation,
        ProtocolMapperRepresentation, RoleRepresentation, ScopeMappingRepresentation,
        UserRepresentation,
    },
    error::AdminApiError,
};

#[derive(Debug, Default, Deserialize)]
pub struct KeycloakImportRepresentation {
    #[serde(rename = "ifResourceExists")]
    if_resource_exists: Option<IfResourceExists>,
    users: Option<Vec<KeycloakUserRepresentation>>,
    groups: Option<Vec<KeycloakGroupRepresentation>>,
    clients: Option<Vec<KeycloakClientRepresentation>>,
    roles: Option<KeycloakRolesRepresentation>,
    #[serde(rename = "identityProviders", alias = "identity_providers")]
    identity_providers: Option<Vec<IdentityProviderRepresentation>>,
    #[serde(rename = "clientScopes", alias = "client_scopes")]
    client_scopes: Option<Vec<KeycloakClientScopeRepresentation>>,
    #[serde(rename = "scopeMappings", alias = "scope_mappings")]
    scope_mappings: Option<Vec<ScopeMappingRepresentation>>,
    #[serde(rename = "clientScopeMappings", alias = "client_scope_mappings")]
    client_scope_mappings: Option<HashMap<String, Vec<ScopeMappingRepresentation>>>,
    #[serde(
        rename = "defaultDefaultClientScopes",
        alias = "default_default_client_scopes"
    )]
    default_default_client_scopes: Option<Vec<String>>,
    #[serde(
        rename = "defaultOptionalClientScopes",
        alias = "default_optional_client_scopes"
    )]
    default_optional_client_scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct KeycloakUserRepresentation {
    #[serde(flatten)]
    base: UserRepresentation,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "emailVerified")]
    email_verified: Option<bool>,
    #[serde(rename = "realmRoles")]
    realm_roles: Option<Vec<String>>,
    #[serde(rename = "clientRoles")]
    client_roles: Option<HashMap<String, Vec<String>>>,
}

impl KeycloakUserRepresentation {
    fn into_base(mut self) -> UserRepresentation {
        if self.first_name.is_some() {
            self.base.first_name = self.first_name;
        }
        if self.last_name.is_some() {
            self.base.last_name = self.last_name;
        }
        if self.email_verified.is_some() {
            self.base.email_verified = self.email_verified;
        }
        if self.realm_roles.is_some() {
            self.base.realm_roles = self.realm_roles;
        }
        if self.client_roles.is_some() {
            self.base.client_roles = self.client_roles;
        }
        self.base
    }
}

#[derive(Debug, Deserialize)]
struct KeycloakGroupRepresentation {
    #[serde(flatten)]
    base: GroupRepresentation,
    #[serde(rename = "realmRoles")]
    realm_roles: Option<Vec<RoleName>>,
    #[serde(rename = "clientRoles")]
    client_roles: Option<HashMap<ClientId, Vec<RoleName>>>,
    #[serde(rename = "subGroups")]
    sub_groups: Option<Vec<serde_json::Value>>,
}

impl KeycloakGroupRepresentation {
    fn into_base(mut self) -> Result<GroupRepresentation, AdminApiError> {
        if self.sub_groups.as_ref().is_some_and(|groups| !groups.is_empty()) {
            return Err(AdminApiError::BadRequest(format!(
                "group '{}': nested groups are not supported by this migration",
                self.base.name
            )));
        }
        if self.realm_roles.is_some() {
            self.base.realm_roles = self.realm_roles;
        }
        if self.client_roles.is_some() {
            self.base.client_roles = self.client_roles;
        }
        Ok(self.base)
    }
}

#[derive(Debug, Deserialize)]
struct KeycloakProtocolMapperRepresentation {
    id: Option<String>,
    name: String,
    protocol: Option<String>,
    #[serde(rename = "protocolMapper")]
    protocol_mapper: String,
    config: Option<HashMap<String, String>>,
}

impl KeycloakProtocolMapperRepresentation {
    fn into_base(self, parent: &str) -> Result<ProtocolMapperRepresentation, AdminApiError> {
        let mapper_type = serde_json::from_value::<MapperType>(serde_json::Value::String(
            self.protocol_mapper.clone(),
        ))
        .map_err(|_| {
            AdminApiError::BadRequest(format!(
                "{parent}: unsupported protocol mapper type '{}'",
                self.protocol_mapper
            ))
        })?;
        Ok(ProtocolMapperRepresentation {
            id: self.id,
            name: self.name,
            protocol: self.protocol,
            protocol_mapper: mapper_type,
            config: self.config,
        })
    }
}

#[derive(Debug, Deserialize)]
struct KeycloakClientRepresentation {
    #[serde(flatten)]
    base: ClientRepresentation,
    #[serde(rename = "publicClient")]
    public_client: Option<bool>,
    #[serde(rename = "bearerOnly")]
    bearer_only: Option<bool>,
    #[serde(rename = "clientAuthenticatorType")]
    client_authenticator_type: Option<issuerd_core::ClientAuthenticatorType>,
    #[serde(rename = "redirectUris")]
    redirect_uris: Option<Vec<String>>,
    #[serde(rename = "webOrigins")]
    web_origins: Option<Vec<String>>,
    #[serde(rename = "consentRequired")]
    consent_required: Option<bool>,
    #[serde(rename = "fullScopeAllowed")]
    full_scope_allowed: Option<bool>,
    #[serde(rename = "serviceAccountsEnabled")]
    service_accounts_enabled: Option<bool>,
    #[serde(rename = "defaultClientScopes")]
    default_client_scopes: Option<Vec<String>>,
    #[serde(rename = "optionalClientScopes")]
    optional_client_scopes: Option<Vec<String>>,
    #[serde(rename = "protocolMappers")]
    protocol_mappers: Option<Vec<KeycloakProtocolMapperRepresentation>>,
}

impl KeycloakClientRepresentation {
    fn into_base(mut self) -> Result<ClientRepresentation, AdminApiError> {
        if self.public_client.is_some() {
            self.base.public_client = self.public_client;
        }
        if self.bearer_only.is_some() {
            self.base.bearer_only = self.bearer_only;
        }
        if self.client_authenticator_type.is_some() {
            self.base.client_authenticator_type = self.client_authenticator_type;
        }
        if self.redirect_uris.is_some() {
            self.base.redirect_uris = self.redirect_uris;
        }
        if self.web_origins.is_some() {
            self.base.web_origins = self.web_origins;
        }
        if self.consent_required.is_some() {
            self.base.consent_required = self.consent_required;
        }
        if self.full_scope_allowed.is_some() {
            self.base.full_scope_allowed = self.full_scope_allowed;
        }
        if self.service_accounts_enabled.is_some() {
            self.base.service_accounts_enabled = self.service_accounts_enabled;
        }
        if self.default_client_scopes.is_some() {
            self.base.default_scopes = self.default_client_scopes;
        }
        if self.optional_client_scopes.is_some() {
            self.base.optional_scopes = self.optional_client_scopes;
        }
        if let Some(mappers) = self.protocol_mappers {
            let parent = format!("client '{}'", self.base.client_id);
            self.base.protocol_mappers = Some(
                mappers
                    .into_iter()
                    .map(|mapper| {
                        let converted = mapper.into_base(&parent)?;
                        converted.try_into().map_err(AdminApiError::from)
                    })
                    .collect::<Result<Vec<_>, AdminApiError>>()?,
            );
        }
        Ok(self.base)
    }
}

#[derive(Debug, Deserialize)]
struct KeycloakClientScopeRepresentation {
    #[serde(flatten)]
    base: ClientScopeRepresentation,
    #[serde(rename = "protocolMappers")]
    protocol_mappers: Option<Vec<KeycloakProtocolMapperRepresentation>>,
}

impl KeycloakClientScopeRepresentation {
    fn into_base(mut self) -> Result<ClientScopeRepresentation, AdminApiError> {
        if let Some(mappers) = self.protocol_mappers {
            let parent = format!("client scope '{}'", self.base.name);
            self.base.protocol_mappers = Some(
                mappers
                    .into_iter()
                    .map(|mapper| mapper.into_base(&parent))
                    .collect::<Result<Vec<_>, AdminApiError>>()?,
            );
        }
        Ok(self.base)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum KeycloakComposites {
    Legacy(Vec<RoleName>),
    Detailed {
        realm: Option<Vec<String>>,
        client: Option<HashMap<String, Vec<String>>>,
    },
}

#[derive(Debug, Deserialize)]
struct KeycloakRoleRepresentation {
    #[serde(flatten)]
    base: RoleRepresentation,
    #[serde(rename = "clientRole")]
    client_role: Option<bool>,
    #[serde(rename = "containerId")]
    container_id: Option<String>,
    composites: Option<KeycloakComposites>,
}

impl KeycloakRoleRepresentation {
    fn into_base(
        mut self,
        reference_key: String,
        references: &mut HashMap<String, CompositeRoleReferences>,
    ) -> Result<RoleRepresentation, AdminApiError> {
        if self.client_role.is_some() {
            self.base.client_role = self.client_role;
        }
        if self.container_id.is_some() {
            self.base.container_id = self.container_id;
        }
        match self.composites {
            Some(KeycloakComposites::Legacy(names)) => self.base.composites = Some(names),
            Some(KeycloakComposites::Detailed { realm, client }) => {
                let realm = realm.unwrap_or_default();
                let client = client.unwrap_or_default();
                let mut names = Vec::new();
                for name in &realm {
                    names.push(RoleName::new(name.clone())?);
                }
                for role_names in client.values() {
                    for name in role_names {
                        if !names.iter().any(|existing| existing.as_str() == name) {
                            names.push(RoleName::new(name.clone())?);
                        }
                    }
                }
                self.base.composites = Some(names);
                references.insert(reference_key, CompositeRoleReferences { realm, client });
            }
            None => {}
        }
        Ok(self.base)
    }
}

#[derive(Debug, Deserialize)]
struct KeycloakRolesRepresentation {
    realm: Option<Vec<KeycloakRoleRepresentation>>,
    client: Option<HashMap<String, Vec<KeycloakRoleRepresentation>>>,
}

impl KeycloakImportRepresentation {
    pub fn into_partial(self) -> Result<PartialImportRepresentation, AdminApiError> {
        let mut composite_references = HashMap::new();
        let roles = self
            .roles
            .map(|roles| {
                let realm = roles
                    .realm
                    .unwrap_or_default()
                    .into_iter()
                    .map(|role| {
                        let key = format!("realm:{}", role.base.name);
                        role.into_base(key, &mut composite_references)
                    })
                    .collect::<Result<Vec<_>, AdminApiError>>()?;
                let client = roles
                    .client
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(client_id, roles)| {
                        roles
                            .into_iter()
                            .map(|role| {
                                let key = format!("client:{client_id}:{}", role.base.name);
                                role.into_base(key, &mut composite_references)
                            })
                            .collect::<Result<Vec<_>, AdminApiError>>()
                            .map(|roles| (client_id, roles))
                    })
                    .collect::<Result<HashMap<_, _>, AdminApiError>>()?;
                Ok::<PartialImportRolesRepresentation, AdminApiError>(
                    PartialImportRolesRepresentation {
                        realm: Some(realm),
                        client: Some(client),
                    },
                )
            })
            .transpose()?;
        Ok(PartialImportRepresentation {
            if_resource_exists: self.if_resource_exists,
            users: self.users.map(|users| {
                users.into_iter().map(KeycloakUserRepresentation::into_base).collect()
            }),
            groups: self
                .groups
                .map(|groups| {
                    groups.into_iter().map(KeycloakGroupRepresentation::into_base).collect()
                })
                .transpose()?,
            clients: self
                .clients
                .map(|clients| {
                    clients.into_iter().map(KeycloakClientRepresentation::into_base).collect()
                })
                .transpose()?,
            roles,
            identity_providers: self.identity_providers,
            client_scopes: self
                .client_scopes
                .map(|scopes| {
                    scopes.into_iter().map(KeycloakClientScopeRepresentation::into_base).collect()
                })
                .transpose()?,
            scope_mappings: self.scope_mappings,
            client_scope_mappings: self.client_scope_mappings,
            default_default_client_scopes: self.default_default_client_scopes,
            default_optional_client_scopes: self.default_optional_client_scopes,
            composite_references,
        })
    }
}
