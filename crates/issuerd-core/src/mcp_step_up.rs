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
            Self::UserRoleMapping { expected_role, .. } => redact_role(expected_role),
            Self::GroupRoleMapping {
                expected,
                expected_role,
                ..
            } => {
                redact_group(expected);
                redact_role(expected_role);
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
            Self::DeleteTotp { user_id, .. } | Self::DeleteWebauthn { user_id, .. } => {
                user_id.to_string()
            }
            Self::UserRoleMapping { user_id, .. } => user_id.to_string(),
            Self::GroupRoleMapping { expected, .. } => expected.id.to_string(),
        }
    }
}

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    ["secret", "password", "credential", "privatekey", "token"]
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

    #[test]
    fn mutation_tool_names_match_the_public_inventory() {
        let realm = Realm::default();
        assert_eq!(McpStepUpMutation::DeleteRealm { expected: realm }.tool(), "realm_delete");
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
