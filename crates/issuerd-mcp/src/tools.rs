// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use issuerd_core::{
    AuthMethod, Client, ClientAuthenticatorType, ClientProtocol, Credential, CredentialType, Group,
    Realm, Role, SslRequired, User, UserSession,
};
use rmcp::model::{Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    policy::ToolName,
    read_inventory::{
        ClientScopesOutput, EventsOutput, EventsSearchArgs, FlowsOutput, IdpsOutput, KeysOutput,
        ServerInfoOutput, SessionsListArgs, SessionsOutput,
    },
};

pub const DEFAULT_PAGE_SIZE: u32 = 20;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_INPUT_STRING_BYTES: usize = 255;

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsersSearchArgs {
    pub username: Option<String>,
    pub email: Option<String>,
    pub search: Option<String>,
    pub first: Option<u32>,
    pub max: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserGetArgs {
    pub id: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientsListArgs {
    pub client_id: Option<String>,
    pub first: Option<u32>,
    pub max: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientGetArgs {
    pub id: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupsListArgs {
    pub first: Option<u32>,
    pub max: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupGetArgs {
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupMembersArgs {
    pub id: String,
    pub first: Option<u32>,
    pub max: Option<u32>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RolesListArgs {
    pub first: Option<u32>,
    pub max: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleGetArgs {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RealmOutput {
    pub id: String,
    pub realm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub enabled: bool,
    pub ssl_required: String,
    pub access_token_lifespan: i64,
    pub refresh_token_lifespan: i64,
    pub sso_session_idle_timeout: i64,
    pub sso_session_max_lifespan: i64,
    pub offline_session_idle_timeout: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_theme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_theme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_theme: Option<String>,
    pub internationalization_enabled: bool,
    pub supported_locales: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_locale: Option<String>,
    pub registration_enabled: bool,
    pub reset_password_allowed: bool,
    pub remember_me_enabled: bool,
    pub verify_email_enabled: bool,
    pub login_with_email_allowed: bool,
    pub duplicate_emails_allowed: bool,
    pub edit_username_allowed: bool,
}

impl From<&Realm> for RealmOutput {
    fn from(realm: &Realm) -> Self {
        Self {
            id: realm.id.to_string(),
            realm: realm.name.to_string(),
            display_name: realm.display_name.as_ref().map(ToString::to_string),
            enabled: realm.enabled,
            ssl_required: match realm.ssl_required {
                SslRequired::None => "none",
                SslRequired::External => "external",
                SslRequired::All => "all",
            }
            .into(),
            access_token_lifespan: realm.access_token_lifespan.get() as i64,
            refresh_token_lifespan: realm.refresh_token_lifespan.get() as i64,
            sso_session_idle_timeout: realm.sso_session_idle_timeout.get() as i64,
            sso_session_max_lifespan: realm.sso_session_max_lifespan.get() as i64,
            offline_session_idle_timeout: realm.offline_session_idle_timeout.get() as i64,
            login_theme: realm.login_theme.as_ref().map(ToString::to_string),
            email_theme: realm.email_theme.as_ref().map(ToString::to_string),
            admin_theme: realm.admin_theme.as_ref().map(ToString::to_string),
            internationalization_enabled: realm.internationalization_enabled,
            supported_locales: realm.supported_locales.clone(),
            default_locale: realm.default_locale.clone(),
            registration_enabled: realm.registration_enabled,
            reset_password_allowed: realm.reset_password_allowed,
            remember_me_enabled: realm.remember_me_enabled,
            verify_email_enabled: realm.verify_email_enabled,
            login_with_email_allowed: realm.login_with_email_allowed,
            duplicate_emails_allowed: realm.duplicate_emails_allowed,
            edit_username_allowed: realm.edit_username_allowed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserOutput {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    pub enabled: bool,
    pub email_verified: bool,
    pub created_at: String,
    pub required_actions: Vec<String>,
}

impl From<&User> for UserOutput {
    fn from(user: &User) -> Self {
        let mut required_actions = user.required_actions.clone();
        required_actions.sort();
        Self {
            id: user.id.to_string(),
            username: user.username.to_string(),
            email: user.email.as_ref().map(ToString::to_string),
            first_name: user.first_name.as_ref().map(ToString::to_string),
            last_name: user.last_name.as_ref().map(ToString::to_string),
            enabled: user.enabled,
            email_verified: user.email_verified,
            created_at: user.created_at.to_rfc3339(),
            required_actions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserDetailsOutput {
    #[serde(flatten)]
    pub user: UserOutput,
    pub realm_roles: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsersOutput {
    pub users: Vec<UserOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientOutput {
    pub id: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub enabled: bool,
    pub protocol: String,
    pub public_client: bool,
    pub bearer_only: bool,
    pub client_authenticator_type: String,
    pub redirect_uris: Vec<String>,
    pub web_origins: Vec<String>,
    pub default_scopes: Vec<String>,
    pub optional_scopes: Vec<String>,
    pub consent_required: bool,
    pub full_scope_allowed: bool,
    pub service_accounts_enabled: bool,
}

impl From<&Client> for ClientOutput {
    fn from(client: &Client) -> Self {
        let mut redirect_uris: Vec<_> =
            client.redirect_uris.iter().map(ToString::to_string).collect();
        redirect_uris.sort();
        let mut web_origins: Vec<_> = client.web_origins.iter().map(ToString::to_string).collect();
        web_origins.sort();
        Self {
            id: client.id.to_string(),
            client_id: client.client_id.to_string(),
            name: client.name.as_ref().map(ToString::to_string),
            description: client.description.clone(),
            enabled: client.enabled,
            protocol: match client.protocol {
                ClientProtocol::OpenIdConnect => "openid-connect",
                ClientProtocol::Saml => "saml",
            }
            .into(),
            public_client: client.public_client,
            bearer_only: client.bearer_only,
            client_authenticator_type: match client.client_authenticator_type {
                ClientAuthenticatorType::ClientSecret => "client-secret",
                ClientAuthenticatorType::ClientJwt => "client-jwt",
                ClientAuthenticatorType::ClientSecretJwt => "client-secret-jwt",
                ClientAuthenticatorType::ClientX509 => "client-x509",
            }
            .into(),
            redirect_uris,
            web_origins,
            default_scopes: client.default_scopes.to_vec(),
            optional_scopes: client.optional_scopes.to_vec(),
            consent_required: client.consent_required,
            full_scope_allowed: client.full_scope_allowed,
            service_accounts_enabled: client.service_accounts_enabled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientsOutput {
    pub clients: Vec<ClientOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupOutput {
    pub id: String,
    pub name: String,
    pub path: String,
    pub parent_id: Option<String>,
}

impl From<&Group> for GroupOutput {
    fn from(group: &Group) -> Self {
        Self {
            id: group.id.to_string(),
            name: group.name.to_string(),
            path: group.path.to_string(),
            parent_id: group.parent_id.as_ref().map(ToString::to_string),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupsOutput {
    pub groups: Vec<GroupOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupMembersOutput {
    pub members: Vec<UserOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleOutput {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub composite: bool,
    pub composites: Vec<String>,
    pub client_role: bool,
    pub container_id: String,
}

impl From<&Role> for RoleOutput {
    fn from(role: &Role) -> Self {
        let mut composites: Vec<_> = role.composites.iter().map(ToString::to_string).collect();
        composites.sort();
        Self {
            id: role.id.to_string(),
            name: role.name.to_string(),
            description: role.description.clone(),
            composite: role.composite,
            composites,
            client_role: role.client_role,
            container_id: if role.client_role {
                role.client_id
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| role.realm_id.to_string())
            } else {
                role.realm_id.to_string()
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolesOutput {
    pub roles: Vec<RoleOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientRoleMappingsOutput {
    pub id: String,
    pub client: String,
    pub mappings: Vec<RoleOutput>,
    pub available_mappings: Vec<RoleOutput>,
    pub effective_mappings: Vec<RoleOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserRoleMappingsOutput {
    pub realm_mappings: Vec<RoleOutput>,
    pub available_realm_mappings: Vec<RoleOutput>,
    pub effective_realm_mappings: Vec<RoleOutput>,
    pub client_mappings: std::collections::BTreeMap<String, ClientRoleMappingsOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserSessionOutput {
    pub id: String,
    pub username: String,
    pub user_id: String,
    pub ip_address: String,
    pub started: i64,
    pub last_access: i64,
    pub offline: bool,
    pub clients: std::collections::BTreeMap<String, String>,
}

impl From<&UserSession> for UserSessionOutput {
    fn from(session: &UserSession) -> Self {
        Self {
            id: session.id.to_string(),
            username: session.login_username.to_string(),
            user_id: session.user_id.to_string(),
            ip_address: session.ip_address.to_string(),
            started: session.started.timestamp(),
            last_access: session.last_session_refresh.timestamp(),
            offline: session.offline,
            clients: session
                .clients
                .iter()
                .map(|client| {
                    let method = match client.auth_method {
                        AuthMethod::Password => "password",
                        AuthMethod::Spnego => "spnego",
                        AuthMethod::Ciba => "ciba",
                        AuthMethod::IdentityProvider => "identity_provider",
                        AuthMethod::Impersonation => "impersonation",
                    };
                    (client.client_id.to_string(), method.to_string())
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserSessionsOutput {
    pub sessions: Vec<UserSessionOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOutput {
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_label: Option<String>,
    pub created_date: i64,
    pub priority: i32,
    pub temporary: bool,
}

impl From<&Credential> for CredentialOutput {
    fn from(credential: &Credential) -> Self {
        let credential_type = match &credential.credential_type {
            CredentialType::Password => "password".into(),
            CredentialType::Totp => "totp".into(),
            CredentialType::Hotp => "hotp".into(),
            CredentialType::WebAuthn => "web_authn".into(),
            CredentialType::WebAuthnPasswordless => "web_authn_passwordless".into(),
            CredentialType::Kerberos => "kerberos".into(),
            CredentialType::SshPublicKey => "ssh_public_key".into(),
            CredentialType::Custom(value) => value.clone(),
        };
        Self {
            id: credential.id.to_string(),
            credential_type,
            user_label: credential.user_label.clone(),
            created_date: credential.created_date.timestamp_millis(),
            priority: credential.priority,
            temporary: credential
                .credential_data
                .get("temporary")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserCredentialsOutput {
    pub credentials: Vec<CredentialOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttackDetectionStatusOutput {
    pub user_id: String,
    pub username: String,
    #[schemars(with = "i64", range(min = 0, max = 4294967295_i64))]
    pub num_failures: u32,
    pub locked: bool,
}

fn read_only_annotations() -> ToolAnnotations {
    ToolAnnotations::from_raw(None, Some(true), Some(false), Some(true), Some(false))
}

pub fn definition(name: ToolName) -> Tool {
    if let Some(tool) = crate::strict_tools::definition(name) {
        return tool;
    }
    if let Some(tool) = crate::account_tools::definition(name) {
        return tool;
    }
    if let Some(tool) = crate::write_tools::definition(name) {
        return tool;
    }
    let description = match name {
        ToolName::AttackDetectionStatus => {
            "Return a user's aggregated brute-force failure count and lockout state."
        }
        ToolName::ClientScopesList => {
            "List client scopes with safe mapper types and claim-target summaries."
        }
        ToolName::EventsSearch => {
            "Search user or admin audit events with filters, retention clamps, and totals."
        }
        ToolName::FlowsList => {
            "List authentication flows and stages without arbitrary authenticator configuration."
        }
        ToolName::IdpGet => {
            "Return an identity provider with credentials and private keys omitted."
        }
        ToolName::IdpList => "List identity providers with credentials and private keys omitted.",
        ToolName::KeysList => "List public signing-key metadata without private key material.",
        ToolName::ServerinfoGet => "Return dynamic server capabilities and enum metadata.",
        ToolName::SessionsList => "List active realm sessions with a matching total count.",
        ToolName::RealmGet => "Return the current realm's curated, non-secret configuration.",
        ToolName::UsersSearch => {
            "Search users by exact username, exact email, or a username/email substring."
        }
        ToolName::UsersGet => {
            "Return a user by internal id, including direct realm roles and groups."
        }
        ToolName::UsersGetGroups => "Return a user's direct group memberships without attributes.",
        ToolName::UsersGetRoleMappings => {
            "Return direct, available, and effective realm and client role mappings for a user."
        }
        ToolName::UsersGetSessions => "Return a user's active sessions with curated fields.",
        ToolName::UsersGetCredentials => {
            "Return credential metadata without secret data or credential payloads."
        }
        ToolName::ClientsList => "List clients or return one exact public client identifier match.",
        ToolName::ClientsGet => {
            "Return a client by its internal UUID without secret or mapper configuration."
        }
        ToolName::GroupsList => "List groups with hierarchy and without arbitrary attributes.",
        ToolName::GroupsGet => "Return a group by internal UUID without arbitrary attributes.",
        ToolName::GroupsMembers => "List a group's members with curated, non-secret user fields.",
        ToolName::RolesList => "List realm roles without arbitrary attributes.",
        ToolName::RolesGet => {
            "Return a role by name using Admin lookup precedence, without arbitrary attributes."
        }
        _ => unreachable!("admin writes have separate definitions"),
    };
    let tool = Tool::new(name.as_str(), description, std::sync::Arc::new(serde_json::Map::new()));
    let tool = match name {
        ToolName::AttackDetectionStatus => tool
            .with_input_schema::<UserGetArgs>()
            .with_output_schema::<AttackDetectionStatusOutput>(),
        ToolName::ClientScopesList => tool
            .with_input_schema::<SessionsListArgs>()
            .with_output_schema::<ClientScopesOutput>(),
        ToolName::EventsSearch => tool
            .with_input_schema::<EventsSearchArgs>()
            .with_output_schema::<EventsOutput>(),
        ToolName::FlowsList => {
            tool.with_input_schema::<NoArgs>().with_output_schema::<FlowsOutput>()
        }
        ToolName::IdpGet => tool
            .with_input_schema::<RoleGetArgs>()
            .with_output_schema::<crate::read_inventory::IdpOutput>(),
        ToolName::IdpList => tool.with_input_schema::<NoArgs>().with_output_schema::<IdpsOutput>(),
        ToolName::KeysList => tool.with_input_schema::<NoArgs>().with_output_schema::<KeysOutput>(),
        ToolName::ServerinfoGet => {
            tool.with_input_schema::<NoArgs>().with_output_schema::<ServerInfoOutput>()
        }
        ToolName::SessionsList => tool
            .with_input_schema::<SessionsListArgs>()
            .with_output_schema::<SessionsOutput>(),
        ToolName::RealmGet => {
            tool.with_input_schema::<NoArgs>().with_output_schema::<RealmOutput>()
        }
        ToolName::UsersSearch => {
            tool.with_input_schema::<UsersSearchArgs>().with_output_schema::<UsersOutput>()
        }
        ToolName::UsersGet => tool
            .with_input_schema::<UserGetArgs>()
            .with_output_schema::<UserDetailsOutput>(),
        ToolName::UsersGetGroups => {
            tool.with_input_schema::<UserGetArgs>().with_output_schema::<GroupsOutput>()
        }
        ToolName::UsersGetRoleMappings => tool
            .with_input_schema::<UserGetArgs>()
            .with_output_schema::<UserRoleMappingsOutput>(),
        ToolName::UsersGetSessions => tool
            .with_input_schema::<UserGetArgs>()
            .with_output_schema::<UserSessionsOutput>(),
        ToolName::UsersGetCredentials => tool
            .with_input_schema::<UserGetArgs>()
            .with_output_schema::<UserCredentialsOutput>(),
        ToolName::ClientsList => tool
            .with_input_schema::<ClientsListArgs>()
            .with_output_schema::<ClientsOutput>(),
        ToolName::ClientsGet => {
            tool.with_input_schema::<ClientGetArgs>().with_output_schema::<ClientOutput>()
        }
        ToolName::GroupsList => {
            tool.with_input_schema::<GroupsListArgs>().with_output_schema::<GroupsOutput>()
        }
        ToolName::GroupsGet => {
            tool.with_input_schema::<GroupGetArgs>().with_output_schema::<GroupOutput>()
        }
        ToolName::GroupsMembers => tool
            .with_input_schema::<GroupMembersArgs>()
            .with_output_schema::<GroupMembersOutput>(),
        ToolName::RolesList => {
            tool.with_input_schema::<RolesListArgs>().with_output_schema::<RolesOutput>()
        }
        ToolName::RolesGet => {
            tool.with_input_schema::<RoleGetArgs>().with_output_schema::<RoleOutput>()
        }
        _ => unreachable!("admin writes have separate definitions"),
    };
    tool.with_annotations(read_only_annotations())
}

pub fn definitions() -> Vec<Tool> {
    ToolName::ALL.into_iter().map(definition).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use issuerd_core::{GroupId, RoleName};

    #[test]
    fn definitions_are_sorted_fully_annotated_and_have_strict_schemas() {
        let definitions = definitions();
        let names: Vec<_> = definitions.iter().map(|tool| tool.name.as_ref()).collect();
        let expected: Vec<_> = ToolName::ALL.iter().map(|tool| tool.as_str()).collect();
        assert_eq!(names, expected);
        for tool in definitions {
            let name = ToolName::parse(tool.name.as_ref()).unwrap();
            let create = matches!(
                name,
                ToolName::UsersCreate
                    | ToolName::GroupsCreate
                    | ToolName::GroupsAddChild
                    | ToolName::RolesCreate
                    | ToolName::ClientsCreate
            );
            let external = name == ToolName::UsersSendActionsEmail;
            let read_only = name.tier() == crate::policy::RiskTier::T0
                || matches!(
                    name,
                    ToolName::MeGetProfile
                        | ToolName::MeSessionsList
                        | ToolName::MeConsentsList
                        | ToolName::MeLinkedAccountsList
                );
            let annotations = tool.annotations.unwrap();
            assert_eq!(annotations.read_only_hint, Some(read_only));
            assert_eq!(
                annotations.destructive_hint,
                Some(name.tier() == crate::policy::RiskTier::T3)
            );
            assert_eq!(
                annotations.idempotent_hint,
                Some(
                    name.tier() != crate::policy::RiskTier::T3
                        && (read_only || (!create && !external))
                )
            );
            assert_eq!(annotations.open_world_hint, Some(external));
            assert_eq!(tool.input_schema["type"], "object");
            assert_eq!(tool.input_schema["additionalProperties"], false);
            assert_eq!(tool.output_schema.as_ref().unwrap()["type"], "object");
        }
        assert!(definition(ToolName::RealmGet).input_schema.get("properties").is_none());
    }

    #[test]
    fn attack_detection_counter_schema_covers_the_full_u32_range() {
        let definition = definition(ToolName::AttackDetectionStatus);
        let schema = definition.output_schema.unwrap();
        let counter = &schema["properties"]["numFailures"];
        assert_eq!(counter["type"], "integer");
        assert_eq!(counter["minimum"], 0);
        assert_eq!(counter["maximum"], serde_json::json!(u32::MAX));
        assert_ne!(counter["format"], "int32");
        assert_ne!(counter["format"], "uint32");
    }

    #[test]
    fn strict_inputs_reject_unknown_fields() {
        let json = r#"{"id":"alice","unexpected":true}"#;
        assert!(serde_json::from_str::<NoArgs>(r#"{"unexpected":true}"#).is_err());
        assert!(serde_json::from_str::<UsersSearchArgs>(json).is_err());
        assert!(serde_json::from_str::<UserGetArgs>(json).is_err());
        assert!(serde_json::from_str::<ClientsListArgs>(json).is_err());
        assert!(serde_json::from_str::<ClientGetArgs>(json).is_err());
        assert!(serde_json::from_str::<GroupsListArgs>(json).is_err());
        assert!(serde_json::from_str::<GroupGetArgs>(json).is_err());
        assert!(serde_json::from_str::<GroupMembersArgs>(json).is_err());
        assert!(serde_json::from_str::<RolesListArgs>(json).is_err());
        assert!(serde_json::from_str::<RoleGetArgs>(json).is_err());
    }

    #[test]
    fn dto_serialization_has_no_secret_or_arbitrary_extension_channels() {
        let values = [
            serde_json::to_value(RealmOutput::from(&realm())).unwrap().to_string(),
            serde_json::to_value(UserOutput::from(&user(ALICE_ID, "alice", "alice@example.com")))
                .unwrap()
                .to_string(),
            serde_json::to_value(ClientOutput::from(&client(ALPHA_CLIENT_ID, "alpha-client")))
                .unwrap()
                .to_string(),
            serde_json::to_value(GroupOutput::from(&group(ALPHA_GROUP_ID, "alpha-group", None)))
                .unwrap()
                .to_string(),
            serde_json::to_value(RoleOutput::from(&role(ALPHA_ROLE_ID, "alpha-role")))
                .unwrap()
                .to_string(),
            serde_json::to_value(CredentialOutput::from(&credential(
                "credential-fixture",
                CredentialType::Password,
                10,
                1_700_000_000,
            )))
            .unwrap()
            .to_string(),
            serde_json::to_value(UserSessionOutput::from(&session(
                "session-fixture",
                ALICE_ID,
                1_700_000_000,
            )))
            .unwrap()
            .to_string(),
        ];
        for value in values {
            for canary in [
                REALM_SECRET,
                PAIRWISE_SECRET,
                USER_SECRET,
                CLIENT_SECRET,
                CLIENT_ATTRIBUTE_SECRET,
                GROUP_SECRET,
                ROLE_SECRET,
                CREDENTIAL_SECRET,
                "attributes",
                "protocolMappers",
                "credentials",
                "federationLink",
            ] {
                assert!(!value.contains(canary), "leaked {canary}: {value}");
            }
        }
    }

    #[test]
    fn selected_fields_match_admin_names_and_values() {
        let realm = serde_json::to_value(RealmOutput::from(&realm())).unwrap();
        assert_eq!(realm["realm"], "demo");
        assert_eq!(realm["displayName"], "Demo Realm");
        assert_eq!(realm["sslRequired"], "external");
        assert_eq!(realm["accessTokenLifespan"], 300);
        assert_eq!(realm["supportedLocales"], serde_json::json!(["en", "de"]));

        let user =
            serde_json::to_value(UserOutput::from(&user(ALICE_ID, "alice", "alice@example.com")))
                .unwrap();
        assert_eq!(user["id"], ALICE_ID);
        assert_eq!(user["username"], "alice");
        assert_eq!(user["emailVerified"], true);
        assert!(user["createdAt"].as_str().unwrap().starts_with("2023-11-14T"));

        let client =
            serde_json::to_value(ClientOutput::from(&client(ALPHA_CLIENT_ID, "alpha-client")))
                .unwrap();
        assert_eq!(client["clientId"], "alpha-client");
        assert_eq!(client["protocol"], "openid-connect");
        assert_eq!(client["clientAuthenticatorType"], "client-secret");
        assert_eq!(client["redirectUris"][0], "https://a.example/callback");
        assert_eq!(client["defaultScopes"], serde_json::json!(["profile", "roles"]));

        let group = serde_json::to_value(GroupOutput::from(&group(
            ZETA_GROUP_ID,
            "zeta-group",
            Some(GroupId::new(ALPHA_GROUP_ID).unwrap()),
        )))
        .unwrap();
        assert_eq!(group["id"], ZETA_GROUP_ID);
        assert_eq!(group["path"], "/alpha-group/zeta-group");
        assert_eq!(group["parentId"], ALPHA_GROUP_ID);

        let mut composite = role(ZETA_ROLE_ID, "zeta-role");
        composite.composite = true;
        composite.composites = vec![
            RoleName::new("zeta-child").unwrap(),
            RoleName::new("alpha-child").unwrap(),
        ];
        let role = serde_json::to_value(RoleOutput::from(&composite)).unwrap();
        assert_eq!(role["containerId"], REALM_ID);
        assert_eq!(role["clientRole"], false);
        assert_eq!(role["composites"], serde_json::json!(["alpha-child", "zeta-child"]));
    }
}
