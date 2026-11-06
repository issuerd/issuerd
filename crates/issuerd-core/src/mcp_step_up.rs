// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Durable operation-bound MCP step-up grants and atomic mutation vocabulary.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    Client, ClientId, ClientIdentifier, FlowConfig, Group, IdentityProviderConfig, JwtId, Realm,
    RealmId, Role, User, UserId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpStepUpExecutionStatus {
    Active,
    Executing,
    Succeeded,
    FailedDefinite,
    OutcomeUnknown,
}

/// Returns whether a credential is a second factor rather than a primary
/// sign-in method that must survive administrative MFA recovery.
pub fn is_second_factor_credential_type(credential_type: &crate::CredentialType) -> bool {
    matches!(
        credential_type,
        crate::CredentialType::Totp | crate::CredentialType::Hotp | crate::CredentialType::WebAuthn
    )
}

/// Returns whether a credential is an active primary sign-in credential.
/// Other credential variants are not consumed by an authentication flow.
pub fn is_primary_sign_in_credential_type(credential_type: &crate::CredentialType) -> bool {
    matches!(credential_type, crate::CredentialType::Password)
}

fn flow_has_email_code<'a>(
    alias: &'a str,
    flows: &'a [crate::FlowConfig],
    visited: &mut Vec<&'a str>,
) -> bool {
    if visited.contains(&alias) {
        return false;
    }
    let Some(flow) = flows.iter().find(|flow| flow.alias.as_str() == alias) else {
        return false;
    };
    visited.push(alias);
    let found = flow.stages.iter().any(|stage| {
        (stage.authenticator.as_str() == "auth-email-code"
            && matches!(
                stage.requirement,
                crate::Requirement::Required | crate::Requirement::Alternative
            ))
            || stage
                .sub_flow_alias
                .as_deref()
                .is_some_and(|sub_flow| flow_has_email_code(sub_flow, flows, visited))
    });
    visited.pop();
    found
}

/// Returns whether a supported primary sign-in method remains after MFA
/// recovery. Provider, link, and flow metadata is inspected without exposing
/// it; external service availability is not probed.
pub fn has_primary_sign_in_method(
    user: &crate::User,
    realm: &crate::Realm,
    credentials: &[crate::Credential],
    identity_providers: &[crate::IdentityProviderConfig],
    identity_provider_links: &[crate::IdentityProviderLink],
    flows: &[crate::FlowConfig],
) -> bool {
    if credentials
        .iter()
        .any(|credential| is_primary_sign_in_credential_type(&credential.credential_type))
    {
        return true;
    }
    if realm.email_code_login()
        && user.email.is_some()
        && realm
            .browser_flow
            .as_deref()
            .is_some_and(|alias| flow_has_email_code(alias, flows, &mut Vec::new()))
    {
        return true;
    }
    let Some(federation_link) = user.federation_link.as_deref() else {
        return false;
    };
    if let Some(alias) = federation_link.strip_prefix("idp:") {
        return identity_providers
            .iter()
            .any(|provider| provider.enabled && provider.alias.as_str() == alias)
            && identity_provider_links
                .iter()
                .any(|link| link.user_id == user.id && link.provider_alias == alias);
    }
    identity_providers.iter().any(|provider| {
        provider.enabled
            && provider.id.as_ref() == federation_link
            && matches!(provider.provider_id.as_str(), "ldap" | "kerberos")
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpStepUpMutation {
    DeleteUser {
        expected: User,
    },
    DeleteGroup {
        expected: Group,
    },
    DeleteRole {
        expected: Role,
    },
    DeleteClient {
        expected: Client,
    },
    UpdateClientSecurity {
        expected: Client,
        updated: Client,
    },
    UpdateRealmSettings {
        expected: Realm,
        updated: Realm,
    },
    UpdateEventsConfig {
        expected: Realm,
        updated: Realm,
    },
    CreateIdentityProvider {
        realm_id: RealmId,
        new: IdentityProviderConfig,
    },
    UpdateIdentityProvider {
        realm_id: RealmId,
        expected: IdentityProviderConfig,
        updated: IdentityProviderConfig,
    },
    DeleteIdentityProvider {
        realm_id: RealmId,
        expected: IdentityProviderConfig,
    },
    UpdateFlow {
        expected: FlowConfig,
        updated: FlowConfig,
    },
    PushNotBefore {
        expected: Realm,
        not_before: i64,
    },
    DeleteRealm {
        expected: Realm,
    },
    DeleteTotp {
        realm_id: RealmId,
        user_id: UserId,
        expected: Vec<crate::Credential>,
    },
    DeleteWebauthn {
        realm_id: RealmId,
        user_id: UserId,
        expected: crate::Credential,
    },
    DeleteUserSecondFactor {
        realm_id: RealmId,
        user_id: UserId,
        expected_user: User,
        expected_realm: Realm,
        expected_credential: crate::Credential,
        expected_credentials: Vec<crate::Credential>,
    },
    UserRoleMapping {
        realm_id: RealmId,
        user_id: UserId,
        expected_role: Role,
        client_role: bool,
        assign: bool,
        expected_present: bool,
    },
    GroupRoleMapping {
        expected: Group,
        expected_role: Role,
        client_id: Option<ClientId>,
        assign: bool,
    },
    UpdateRole {
        expected: Role,
        updated: Role,
    },
    UserGroupMembership {
        realm_id: RealmId,
        user_id: UserId,
        expected_group: Group,
        expected_roles: Vec<Role>,
        assign: bool,
        expected_present: bool,
    },
}

impl McpStepUpMutation {
    pub fn tool(&self) -> &'static str {
        match self {
            Self::DeleteUser { .. } => "users_delete",
            Self::DeleteGroup { .. } => "groups_delete",
            Self::DeleteRole { .. } => "roles_delete",
            Self::DeleteClient { .. } => "clients_delete",
            Self::UpdateClientSecurity { .. } => "clients_update_security",
            Self::UpdateRealmSettings { .. } => "realm_update_settings",
            Self::UpdateEventsConfig { .. } => "events_config_update",
            Self::CreateIdentityProvider { .. } => "idp_create",
            Self::UpdateIdentityProvider { .. } => "idp_update",
            Self::DeleteIdentityProvider { .. } => "idp_delete",
            Self::UpdateFlow { .. } => "flows_update_executions",
            Self::PushNotBefore { .. } => "push_not_before",
            Self::DeleteRealm { .. } => "realm_delete",
            Self::DeleteTotp { .. } => "me_totp_delete",
            Self::DeleteWebauthn { .. } => "me_webauthn_delete",
            Self::DeleteUserSecondFactor { .. } => "users_remove_second_factor",
            Self::UserRoleMapping { assign, .. } => {
                if *assign {
                    "users_assign_role"
                } else {
                    "users_unassign_role"
                }
            }
            Self::GroupRoleMapping { assign, .. } => {
                if *assign {
                    "groups_assign_role"
                } else {
                    "groups_unassign_role"
                }
            }
            Self::UpdateRole { .. } => "roles_update",
            Self::UserGroupMembership { assign, .. } => {
                if *assign {
                    "users_add_to_group"
                } else {
                    "users_remove_from_group"
                }
            }
        }
    }

    /// Canonical secret-free representation used for operation hashes and
    /// durable state. Backends compare current state against the same shape.
    pub fn redacted(&self) -> Self {
        let mut redacted = self.clone();
        match &mut redacted {
            Self::DeleteUser { expected } => redact_user(expected),
            Self::DeleteGroup { expected } => redact_group(expected),
            Self::DeleteRole { expected } => redact_role(expected),
            Self::DeleteClient { expected } => redact_client(expected),
            Self::UpdateClientSecurity { expected, updated } => {
                redact_client(expected);
                redact_client(updated);
            }
            Self::UpdateRealmSettings { expected, updated }
            | Self::UpdateEventsConfig { expected, updated } => {
                redact_realm(expected);
                redact_realm(updated);
            }
            Self::CreateIdentityProvider { new, .. } => redact_idp(new),
            Self::UpdateIdentityProvider {
                expected, updated, ..
            } => {
                redact_idp(expected);
                redact_idp(updated);
            }
            Self::DeleteIdentityProvider { expected, .. } => redact_idp(expected),
            Self::UpdateFlow { expected, updated } => {
                redact_flow(expected);
                redact_flow(updated);
            }
            Self::PushNotBefore { expected, .. } | Self::DeleteRealm { expected } => {
                redact_realm(expected)
            }
            Self::DeleteTotp { expected, .. } => {
                for credential in expected {
                    redact_credential(credential);
                }
            }
            Self::DeleteWebauthn { expected, .. } => redact_credential(expected),
            Self::DeleteUserSecondFactor {
                expected_user,
                expected_realm,
                expected_credential,
                expected_credentials,
                ..
            } => {
                redact_user(expected_user);
                redact_realm(expected_realm);
                redact_credential(expected_credential);
                for credential in expected_credentials {
                    redact_credential(credential);
                }
            }
            Self::UserRoleMapping { expected_role, .. } => redact_role(expected_role),
            Self::GroupRoleMapping {
                expected,
                expected_role,
                ..
            } => {
                redact_group(expected);
                redact_role(expected_role);
            }
            Self::UpdateRole { expected, updated } => {
                redact_role(expected);
                redact_role(updated);
            }
            Self::UserGroupMembership {
                expected_group,
                expected_roles,
                ..
            } => {
                redact_group(expected_group);
                for role in expected_roles {
                    redact_role(role);
                }
            }
        }
        redacted
    }

    pub fn target_id(&self) -> String {
        match self {
            Self::DeleteUser { expected } => expected.id.to_string(),
            Self::DeleteGroup { expected } => expected.id.to_string(),
            Self::DeleteRole { expected } => expected.id.to_string(),
            Self::DeleteClient { expected } => expected.id.to_string(),
            Self::UpdateClientSecurity { updated, .. } => updated.id.to_string(),
            Self::UpdateRealmSettings { updated, .. }
            | Self::UpdateEventsConfig { updated, .. }
            | Self::PushNotBefore {
                expected: updated, ..
            }
            | Self::DeleteRealm { expected: updated } => updated.id.to_string(),
            Self::CreateIdentityProvider { new, .. } => new.id.to_string(),
            Self::UpdateIdentityProvider { updated, .. } => updated.id.to_string(),
            Self::DeleteIdentityProvider { expected, .. } => expected.id.to_string(),
            Self::UpdateFlow { updated, .. } => updated.alias.to_string(),
            Self::DeleteTotp { user_id, .. }
            | Self::DeleteWebauthn { user_id, .. }
            | Self::DeleteUserSecondFactor { user_id, .. } => user_id.to_string(),
            Self::UserRoleMapping { user_id, .. } | Self::UserGroupMembership { user_id, .. } => {
                user_id.to_string()
            }
            Self::GroupRoleMapping { expected, .. } => expected.id.to_string(),
            Self::UpdateRole { expected, .. } => expected.name.to_string(),
        }
    }
}

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "secret",
        "password",
        "credential",
        "privatekey",
        "token",
        "clientassertion",
    ]
    .iter()
    .any(|fragment| normalized.contains(fragment))
}

fn redact_user(user: &mut User) {
    user.attributes.retain(|key, _| !sensitive_key(key));
}

fn redact_group(group: &mut Group) {
    group.attributes.retain(|key, _| !sensitive_key(key));
}

fn redact_role(role: &mut Role) {
    role.attributes.retain(|key, _| !sensitive_key(key));
}

fn redact_client(client: &mut Client) {
    client.secret = None;
    client.attributes.retain(|key, _| !sensitive_key(key));
}

fn redact_realm(realm: &mut Realm) {
    realm.attributes.retain(|key, _| !sensitive_key(key));
}

fn redact_idp(idp: &mut IdentityProviderConfig) {
    idp.config.retain(|key, _| !sensitive_key(key));
}

fn redact_flow(flow: &mut FlowConfig) {
    for stage in &mut flow.stages {
        if let Some(config) = &mut stage.authenticator_config {
            config.config.retain(|key, _| !sensitive_key(key));
        }
    }
}

fn redact_credential(credential: &mut crate::Credential) {
    credential.secret_data.clear();
    credential.credential_data = serde_json::Value::Null;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpStepUpGrant {
    pub version: u32,
    pub operation_id: String,
    pub operation_hash: String,
    pub canonicalization_version: u32,
    pub realm_id: RealmId,
    pub client_id: ClientIdentifier,
    pub subject_user_id: UserId,
    pub resource: String,
    pub tool: String,
    pub mutation: McpStepUpMutation,
    pub origin_access_token_jti: String,
    pub token_jti: JwtId,
    pub dpop_jkt: String,
    pub approval_auth_time: i64,
    pub approval_acr: Option<String>,
    pub approval_amr: Vec<String>,
    pub status: McpStepUpExecutionStatus,
    pub result_json: Option<Value>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpStepUpExecution {
    pub status: McpStepUpExecutionStatus,
    pub result_json: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(realm: &Realm) -> User {
        let now = chrono::Utc::now();
        User {
            id: UserId::new("admin").unwrap(),
            realm_id: realm.id.clone(),
            username: crate::Username::new("admin").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: Default::default(),
            required_actions: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    fn credential(credential_type: crate::CredentialType) -> crate::Credential {
        crate::Credential {
            id: crate::CredentialId::new(crate::utils::generate_id()).unwrap(),
            credential_type,
            user_label: Some("Phone".into()),
            created_date: chrono::Utc::now(),
            secret_data: b"second-factor-secret".to_vec(),
            credential_data: serde_json::json!({"seed": "second-factor-secret"}),
            priority: 0,
        }
    }

    fn provider(alias: &str, provider_id: &str, enabled: bool) -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: crate::IdentityProviderId::new(alias).unwrap(),
            alias: crate::Alias::new(alias).unwrap(),
            provider_id: crate::ProviderId::new(provider_id),
            enabled,
            config: Default::default(),
        }
    }

    fn identity_link(user: &User, alias: &str) -> crate::IdentityProviderLink {
        crate::IdentityProviderLink {
            user_id: user.id.clone(),
            provider_alias: alias.into(),
            external_subject: "external-subject".into(),
            external_username: None,
            stored_refresh_token: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn mutation_tool_names_match_the_public_inventory() {
        let realm = Realm::default();
        assert_eq!(McpStepUpMutation::DeleteRealm { expected: realm }.tool(), "realm_delete");
    }

    #[test]
    fn credential_type_guards_distinguish_primary_secondary_and_unknown_types() {
        assert!(is_primary_sign_in_credential_type(&crate::CredentialType::Password));
        assert!(!is_second_factor_credential_type(&crate::CredentialType::Password));
        for credential_type in [
            crate::CredentialType::Totp,
            crate::CredentialType::Hotp,
            crate::CredentialType::WebAuthn,
        ] {
            assert!(is_second_factor_credential_type(&credential_type));
            assert!(!is_primary_sign_in_credential_type(&credential_type));
        }
        for credential_type in [
            crate::CredentialType::WebAuthnPasswordless,
            crate::CredentialType::Kerberos,
            crate::CredentialType::SshPublicKey,
            crate::CredentialType::Custom("custom-unknown".into()),
        ] {
            assert!(!is_second_factor_credential_type(&credential_type));
            assert!(!is_primary_sign_in_credential_type(&credential_type));
        }
    }

    #[test]
    fn primary_methods_cover_only_supported_credentials_federation_broker_and_email_code() {
        let realm = Realm::default();
        let user = user(&realm);
        assert!(!has_primary_sign_in_method(&user, &realm, &[], &[], &[], &[]));
        for credential_type in [
            crate::CredentialType::WebAuthnPasswordless,
            crate::CredentialType::Kerberos,
            crate::CredentialType::SshPublicKey,
            crate::CredentialType::Custom("custom-unknown".into()),
        ] {
            let credentials = vec![credential(credential_type)];
            assert!(!has_primary_sign_in_method(&user, &realm, &credentials, &[], &[], &[]));
        }
        let password = vec![credential(crate::CredentialType::Password)];
        assert!(has_primary_sign_in_method(&user, &realm, &password, &[], &[], &[]));

        let mut email_user = user.clone();
        email_user.email = Some(crate::Email::new("admin@example.com").unwrap());
        let mut email_realm = realm.clone();
        email_realm
            .attributes
            .insert(Realm::EMAIL_CODE_LOGIN_ATTRIBUTE.into(), "true".into());
        email_realm.browser_flow = Some("browser".into());
        let flows = vec![
            crate::FlowConfig {
                alias: crate::Alias::new("browser").unwrap(),
                realm_id: realm.id.clone(),
                provider_id: "basic-flow".into(),
                top_level: true,
                built_in: false,
                stages: vec![crate::FlowStage {
                    id: crate::FlowStageId::new("parent").unwrap(),
                    requirement: crate::Requirement::Required,
                    authenticator: crate::Alias::new("basic-flow").unwrap(),
                    priority: 1,
                    sub_flow_alias: Some(crate::Alias::new("email-subflow").unwrap()),
                    authenticator_config: None,
                }],
            },
            crate::FlowConfig {
                alias: crate::Alias::new("email-subflow").unwrap(),
                realm_id: realm.id.clone(),
                provider_id: "basic-flow".into(),
                top_level: false,
                built_in: false,
                stages: vec![crate::FlowStage {
                    id: crate::FlowStageId::new("email-code").unwrap(),
                    requirement: crate::Requirement::Required,
                    authenticator: crate::Alias::new("auth-email-code").unwrap(),
                    priority: 1,
                    sub_flow_alias: None,
                    authenticator_config: None,
                }],
            },
        ];
        assert!(has_primary_sign_in_method(&email_user, &email_realm, &[], &[], &[], &flows));
        assert!(!has_primary_sign_in_method(&email_user, &email_realm, &[], &[], &[], &[]));
        assert!(!has_primary_sign_in_method(&user, &email_realm, &[], &[], &[], &flows));
        assert!(!has_primary_sign_in_method(&email_user, &realm, &[], &[], &[], &flows));
        let mut optional_flows = flows.clone();
        optional_flows[1].stages[0].requirement = crate::Requirement::Optional;
        assert!(!has_primary_sign_in_method(
            &email_user,
            &email_realm,
            &[],
            &[],
            &[],
            &optional_flows
        ));

        for provider_type in ["ldap", "kerberos"] {
            let mut federated = user.clone();
            federated.federation_link = Some("directory".into());
            let directory = provider("directory", provider_type, true);
            assert!(has_primary_sign_in_method(
                &federated,
                &realm,
                &[],
                std::slice::from_ref(&directory),
                &[],
                &[]
            ));
            let mut disabled = directory.clone();
            disabled.enabled = false;
            assert!(!has_primary_sign_in_method(&federated, &realm, &[], &[disabled], &[], &[]));
            assert!(!has_primary_sign_in_method(&federated, &realm, &[], &[], &[], &[]));
        }

        let mut broker_user = user.clone();
        broker_user.federation_link = Some("idp:broker".into());
        let broker = provider("broker", "oidc", true);
        let link = identity_link(&broker_user, "broker");
        assert!(has_primary_sign_in_method(
            &broker_user,
            &realm,
            &[],
            std::slice::from_ref(&broker),
            std::slice::from_ref(&link),
            &[]
        ));
        assert!(!has_primary_sign_in_method(
            &broker_user,
            &realm,
            &[],
            std::slice::from_ref(&broker),
            &[],
            &[]
        ));
        let mut disabled = broker;
        disabled.enabled = false;
        assert!(!has_primary_sign_in_method(
            &broker_user,
            &realm,
            &[],
            &[disabled],
            &[link],
            &[]
        ));
    }

    #[test]
    fn second_factor_mutation_is_named_and_fully_redacted() {
        let realm = Realm::default();
        let mut expected_user = user(&realm);
        expected_user.attributes.insert("api_secret".into(), vec!["user-secret".into()]);
        let mut expected_realm = realm.clone();
        expected_realm.attributes.insert("smtp.password".into(), "mail-secret".into());
        let expected_credential = credential(crate::CredentialType::Totp);
        let mutation = McpStepUpMutation::DeleteUserSecondFactor {
            realm_id: realm.id.clone(),
            user_id: expected_user.id.clone(),
            expected_user: expected_user.clone(),
            expected_realm,
            expected_credential: expected_credential.clone(),
            expected_credentials: vec![expected_credential],
        };
        assert_eq!(mutation.tool(), "users_remove_second_factor");
        assert_eq!(mutation.target_id(), expected_user.id.to_string());
        let redacted = mutation.redacted();
        let McpStepUpMutation::DeleteUserSecondFactor {
            expected_user,
            expected_realm,
            expected_credential,
            expected_credentials,
            ..
        } = redacted
        else {
            panic!("mutation changed kind during redaction");
        };
        assert!(!expected_user.attributes.contains_key("api_secret"));
        assert!(!expected_realm.attributes.contains_key("smtp.password"));
        assert!(expected_credential.secret_data.is_empty());
        assert!(expected_credential.credential_data.is_null());
        assert!(expected_credentials[0].secret_data.is_empty());
        assert!(expected_credentials[0].credential_data.is_null());
    }

    #[test]
    fn grant_json_roundtrip_preserves_exact_mutation() {
        let realm = Realm::default();
        let grant = McpStepUpGrant {
            version: 1,
            operation_id: "operation".into(),
            operation_hash: "hash".into(),
            canonicalization_version: 1,
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new("agent").unwrap(),
            subject_user_id: UserId::new("admin").unwrap(),
            resource: "https://issuer.example/realms/master/mcp".into(),
            tool: "realm_delete".into(),
            mutation: McpStepUpMutation::DeleteRealm { expected: realm },
            origin_access_token_jti: "origin".into(),
            token_jti: JwtId::new("token").unwrap(),
            dpop_jkt: "jkt".into(),
            approval_auth_time: 100,
            approval_acr: None,
            approval_amr: vec!["pwd".into()],
            status: McpStepUpExecutionStatus::Active,
            result_json: None,
            issued_at: 100,
            expires_at: 200,
            updated_at: 100,
        };
        let json = serde_json::to_string(&grant).unwrap();
        let decoded: McpStepUpGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, grant);
    }
}
