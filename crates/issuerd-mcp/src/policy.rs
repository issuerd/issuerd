// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use issuerd_core::{MCP_SCOPE_READ, MCP_SCOPE_STEP_UP, MCP_SCOPE_WRITE};
use serde::{Deserialize, Serialize};

use crate::auth::McpAuthContext;

const REALM_ROLES: &[&str] = &["view-realm", "manage-realm"];
const USER_ROLES: &[&str] = &["view-users", "manage-users"];
const CLIENT_ROLES: &[&str] = &["view-clients", "manage-clients"];
const MANAGE_REALM: &[&str] = &["manage-realm"];
const MANAGE_USERS: &[&str] = &["manage-users"];
const MANAGE_CLIENTS: &[&str] = &["manage-clients"];
const REVOKE_SESSION_ROLES: &[&str] = &["manage-users", "manage-realm"];
const NO_ROLES: &[&str] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskTier {
    T0,
    T1,
    T2,
    T3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolName {
    AttackDetectionStatus,
    ClientScopesList,
    ClientsCreate,
    ClientsGet,
    ClientsList,
    ClientsSetDefaultScopes,
    ClientsUpdateProfile,
    EventsSearch,
    FlowsList,
    GroupsAddChild,
    GroupsAssignRole,
    GroupsCreate,
    GroupsGet,
    GroupsList,
    GroupsMembers,
    GroupsUnassignRole,
    GroupsUpdate,
    IdpGet,
    IdpList,
    KeysList,
    MeConsentsList,
    MeConsentsRevoke,
    MeGetProfile,
    MeLinkedAccountsList,
    MeLinkedAccountsUnlink,
    MeSessionsList,
    MeSessionsLogout,
    MeTotpEnroll,
    MeUpdateProfile,
    MeWebauthnRegister,
    RealmGet,
    RolesCreate,
    RolesGet,
    RolesList,
    RolesUpdate,
    ServerinfoGet,
    SessionsList,
    UsersAddToGroup,
    UsersAssignRole,
    UsersCreate,
    UsersGet,
    UsersGetCredentials,
    UsersGetGroups,
    UsersGetRoleMappings,
    UsersGetSessions,
    UsersRemoveFromGroup,
    UsersRevokeSessions,
    UsersSearch,
    UsersSendActionsEmail,
    UsersSetEnabled,
    UsersUnassignRole,
    UsersUpdate,
}

impl ToolName {
    pub const ALL: [Self; 52] = [
        Self::AttackDetectionStatus,
        Self::ClientScopesList,
        Self::ClientsCreate,
        Self::ClientsGet,
        Self::ClientsList,
        Self::ClientsSetDefaultScopes,
        Self::ClientsUpdateProfile,
        Self::EventsSearch,
        Self::FlowsList,
        Self::GroupsAddChild,
        Self::GroupsAssignRole,
        Self::GroupsCreate,
        Self::GroupsGet,
        Self::GroupsList,
        Self::GroupsMembers,
        Self::GroupsUnassignRole,
        Self::GroupsUpdate,
        Self::IdpGet,
        Self::IdpList,
        Self::KeysList,
        Self::MeConsentsList,
        Self::MeConsentsRevoke,
        Self::MeGetProfile,
        Self::MeLinkedAccountsList,
        Self::MeLinkedAccountsUnlink,
        Self::MeSessionsList,
        Self::MeSessionsLogout,
        Self::MeTotpEnroll,
        Self::MeUpdateProfile,
        Self::MeWebauthnRegister,
        Self::RealmGet,
        Self::RolesCreate,
        Self::RolesGet,
        Self::RolesList,
        Self::RolesUpdate,
        Self::ServerinfoGet,
        Self::SessionsList,
        Self::UsersAddToGroup,
        Self::UsersAssignRole,
        Self::UsersCreate,
        Self::UsersGet,
        Self::UsersGetCredentials,
        Self::UsersGetGroups,
        Self::UsersGetRoleMappings,
        Self::UsersGetSessions,
        Self::UsersRemoveFromGroup,
        Self::UsersRevokeSessions,
        Self::UsersSearch,
        Self::UsersSendActionsEmail,
        Self::UsersSetEnabled,
        Self::UsersUnassignRole,
        Self::UsersUpdate,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttackDetectionStatus => "attack_detection_status",
            Self::ClientScopesList => "client_scopes_list",
            Self::ClientsCreate => "clients_create",
            Self::ClientsGet => "clients_get",
            Self::ClientsList => "clients_list",
            Self::ClientsSetDefaultScopes => "clients_set_default_scopes",
            Self::ClientsUpdateProfile => "clients_update_profile",
            Self::EventsSearch => "events_search",
            Self::FlowsList => "flows_list",
            Self::GroupsAddChild => "groups_add_child",
            Self::GroupsAssignRole => "groups_assign_role",
            Self::GroupsCreate => "groups_create",
            Self::GroupsGet => "groups_get",
            Self::GroupsList => "groups_list",
            Self::GroupsMembers => "groups_members",
            Self::GroupsUnassignRole => "groups_unassign_role",
            Self::GroupsUpdate => "groups_update",
            Self::IdpGet => "idp_get",
            Self::IdpList => "idp_list",
            Self::KeysList => "keys_list",
            Self::MeConsentsList => "me_consents_list",
            Self::MeConsentsRevoke => "me_consents_revoke",
            Self::MeGetProfile => "me_get_profile",
            Self::MeLinkedAccountsList => "me_linked_accounts_list",
            Self::MeLinkedAccountsUnlink => "me_linked_accounts_unlink",
            Self::MeSessionsList => "me_sessions_list",
            Self::MeSessionsLogout => "me_sessions_logout",
            Self::MeTotpEnroll => "me_totp_enroll",
            Self::MeUpdateProfile => "me_update_profile",
            Self::MeWebauthnRegister => "me_webauthn_register",
            Self::RealmGet => "realm_get",
            Self::RolesCreate => "roles_create",
            Self::RolesGet => "roles_get",
            Self::RolesList => "roles_list",
            Self::RolesUpdate => "roles_update",
            Self::ServerinfoGet => "serverinfo_get",
            Self::SessionsList => "sessions_list",
            Self::UsersAddToGroup => "users_add_to_group",
            Self::UsersAssignRole => "users_assign_role",
            Self::UsersCreate => "users_create",
            Self::UsersGet => "users_get",
            Self::UsersGetCredentials => "users_get_credentials",
            Self::UsersGetGroups => "users_get_groups",
            Self::UsersGetRoleMappings => "users_get_role_mappings",
            Self::UsersGetSessions => "users_get_sessions",
            Self::UsersRemoveFromGroup => "users_remove_from_group",
            Self::UsersRevokeSessions => "users_revoke_sessions",
            Self::UsersSearch => "users_search",
            Self::UsersSendActionsEmail => "users_send_actions_email",
            Self::UsersSetEnabled => "users_set_enabled",
            Self::UsersUnassignRole => "users_unassign_role",
            Self::UsersUpdate => "users_update",
        }
    }

    pub const fn tier(self) -> RiskTier {
        match self {
            Self::AttackDetectionStatus
            | Self::ClientScopesList
            | Self::ClientsGet
            | Self::ClientsList
            | Self::EventsSearch
            | Self::FlowsList
            | Self::GroupsGet
            | Self::GroupsList
            | Self::GroupsMembers
            | Self::IdpGet
            | Self::IdpList
            | Self::KeysList
            | Self::RealmGet
            | Self::RolesGet
            | Self::RolesList
            | Self::ServerinfoGet
            | Self::SessionsList
            | Self::UsersGet
            | Self::UsersGetCredentials
            | Self::UsersGetGroups
            | Self::UsersGetRoleMappings
            | Self::UsersGetSessions
            | Self::UsersSearch => RiskTier::T0,
            Self::MeConsentsList
            | Self::MeConsentsRevoke
            | Self::MeGetProfile
            | Self::MeLinkedAccountsList
            | Self::MeLinkedAccountsUnlink
            | Self::MeSessionsList
            | Self::MeSessionsLogout
            | Self::MeTotpEnroll
            | Self::MeUpdateProfile
            | Self::MeWebauthnRegister => RiskTier::T1,
            _ => RiskTier::T2,
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.as_str() == name)
    }
}

impl std::fmt::Display for ToolName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolPolicy {
    pub tool: ToolName,
    pub required_scope: &'static str,
    pub any_realm_roles: &'static [&'static str],
}

macro_rules! policy {
    ($tool:ident, $scope:expr, $roles:expr) => {
        ToolPolicy {
            tool: ToolName::$tool,
            required_scope: $scope,
            any_realm_roles: $roles,
        }
    };
}

pub const POLICIES: [ToolPolicy; 52] = [
    policy!(AttackDetectionStatus, MCP_SCOPE_READ, MANAGE_USERS),
    policy!(ClientScopesList, MCP_SCOPE_READ, CLIENT_ROLES),
    policy!(ClientsCreate, MCP_SCOPE_WRITE, MANAGE_CLIENTS),
    policy!(ClientsGet, MCP_SCOPE_READ, CLIENT_ROLES),
    policy!(ClientsList, MCP_SCOPE_READ, CLIENT_ROLES),
    policy!(ClientsSetDefaultScopes, MCP_SCOPE_WRITE, MANAGE_CLIENTS),
    policy!(ClientsUpdateProfile, MCP_SCOPE_WRITE, MANAGE_CLIENTS),
    policy!(EventsSearch, MCP_SCOPE_READ, REALM_ROLES),
    policy!(FlowsList, MCP_SCOPE_READ, REALM_ROLES),
    policy!(GroupsAddChild, MCP_SCOPE_WRITE, MANAGE_REALM),
    policy!(GroupsAssignRole, MCP_SCOPE_WRITE, MANAGE_REALM),
    policy!(GroupsCreate, MCP_SCOPE_WRITE, MANAGE_REALM),
    policy!(GroupsGet, MCP_SCOPE_READ, REALM_ROLES),
    policy!(GroupsList, MCP_SCOPE_READ, REALM_ROLES),
    policy!(GroupsMembers, MCP_SCOPE_READ, USER_ROLES),
    policy!(GroupsUnassignRole, MCP_SCOPE_WRITE, MANAGE_REALM),
    policy!(GroupsUpdate, MCP_SCOPE_WRITE, MANAGE_REALM),
    policy!(IdpGet, MCP_SCOPE_READ, REALM_ROLES),
    policy!(IdpList, MCP_SCOPE_READ, REALM_ROLES),
    policy!(KeysList, MCP_SCOPE_READ, REALM_ROLES),
    policy!(MeConsentsList, "openid", NO_ROLES),
    policy!(MeConsentsRevoke, "openid", NO_ROLES),
    policy!(MeGetProfile, "openid", NO_ROLES),
    policy!(MeLinkedAccountsList, "openid", NO_ROLES),
    policy!(MeLinkedAccountsUnlink, "openid", NO_ROLES),
    policy!(MeSessionsList, "openid", NO_ROLES),
    policy!(MeSessionsLogout, "openid", NO_ROLES),
    policy!(MeTotpEnroll, "openid", NO_ROLES),
    policy!(MeUpdateProfile, "openid", NO_ROLES),
    policy!(MeWebauthnRegister, "openid", NO_ROLES),
    policy!(RealmGet, MCP_SCOPE_READ, REALM_ROLES),
    policy!(RolesCreate, MCP_SCOPE_WRITE, MANAGE_REALM),
    policy!(RolesGet, MCP_SCOPE_READ, REALM_ROLES),
    policy!(RolesList, MCP_SCOPE_READ, REALM_ROLES),
    policy!(RolesUpdate, MCP_SCOPE_WRITE, MANAGE_REALM),
    policy!(ServerinfoGet, MCP_SCOPE_READ, REALM_ROLES),
    policy!(SessionsList, MCP_SCOPE_READ, REALM_ROLES),
    policy!(UsersAddToGroup, MCP_SCOPE_WRITE, MANAGE_USERS),
    policy!(UsersAssignRole, MCP_SCOPE_WRITE, MANAGE_USERS),
    policy!(UsersCreate, MCP_SCOPE_WRITE, MANAGE_USERS),
    policy!(UsersGet, MCP_SCOPE_READ, USER_ROLES),
    policy!(UsersGetCredentials, MCP_SCOPE_READ, USER_ROLES),
    policy!(UsersGetGroups, MCP_SCOPE_READ, USER_ROLES),
    policy!(UsersGetRoleMappings, MCP_SCOPE_READ, USER_ROLES),
    policy!(UsersGetSessions, MCP_SCOPE_READ, USER_ROLES),
    policy!(UsersRemoveFromGroup, MCP_SCOPE_WRITE, MANAGE_USERS),
    policy!(UsersRevokeSessions, MCP_SCOPE_WRITE, REVOKE_SESSION_ROLES),
    policy!(UsersSearch, MCP_SCOPE_READ, USER_ROLES),
    policy!(UsersSendActionsEmail, MCP_SCOPE_WRITE, MANAGE_USERS),
    policy!(UsersSetEnabled, MCP_SCOPE_WRITE, MANAGE_USERS),
    policy!(UsersUnassignRole, MCP_SCOPE_WRITE, MANAGE_USERS),
    policy!(UsersUpdate, MCP_SCOPE_WRITE, MANAGE_USERS),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDeny {
    MissingScope(&'static str),
    MissingRole {
        tool: ToolName,
        roles: &'static [&'static str],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny(PolicyDeny),
}

impl PolicyDecision {
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

pub fn policies() -> &'static [ToolPolicy; 52] {
    &POLICIES
}

pub fn policy_for(tool: ToolName) -> &'static ToolPolicy {
    let index = ToolName::ALL
        .iter()
        .position(|candidate| *candidate == tool)
        .expect("every tool has a static policy");
    &POLICIES[index]
}

pub fn decide(policy: &ToolPolicy, auth: &McpAuthContext) -> PolicyDecision {
    if auth.has_scope(MCP_SCOPE_STEP_UP) && policy.tool.tier() != RiskTier::T3 {
        return PolicyDecision::Deny(PolicyDeny::MissingScope(policy.required_scope));
    }
    if !auth.has_scope(policy.required_scope) {
        return PolicyDecision::Deny(PolicyDeny::MissingScope(policy.required_scope));
    }
    if policy.tool.tier() == RiskTier::T1 {
        return PolicyDecision::Allow;
    }
    let role_allowed = if policy.tool == ToolName::UsersRevokeSessions {
        auth.has_realm_role("manage-users") && auth.has_realm_role("manage-realm")
    } else {
        auth.has_any_realm_role(policy.any_realm_roles)
    };
    if !role_allowed {
        return PolicyDecision::Deny(PolicyDeny::MissingRole {
            tool: policy.tool,
            roles: policy.any_realm_roles,
        });
    }
    PolicyDecision::Allow
}

pub fn decide_for(tool: ToolName, auth: &McpAuthContext) -> PolicyDecision {
    decide(policy_for(tool), auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{
        AccessTokenClaims, Audience, ClientIdentifier, Issuer, JwtId, JwtType, RealmAccess,
        RealmId, RealmName, RoleName, Scope, UserId,
    };
    use std::collections::BTreeSet;

    fn auth(scope: &str, roles: &[&str]) -> McpAuthContext {
        McpAuthContext {
            realm_id: RealmId::new("realm").unwrap(),
            realm_name: RealmName::new("demo").unwrap(),
            user_id: UserId::new("user").unwrap(),
            azp: ClientIdentifier::new("agent").unwrap(),
            claims: AccessTokenClaims {
                jti: JwtId::new("jti").unwrap(),
                iss: Issuer::new("https://issuer.example/realms/demo").unwrap(),
                sub: UserId::new("subject").unwrap(),
                aud: Audience::new("agent").unwrap(),
                exp: 100,
                iat: 1,
                nbf: 1,
                scope: Scope::parse(scope),
                typ: JwtType::Bearer,
                azp: Some("agent".into()),
                session_state: None,
                realm_access: Some(RealmAccess {
                    roles: roles.iter().map(|role| RoleName::new(*role).unwrap()).collect(),
                }),
                resource_access: None,
                sid: None,
                claims: None,
                cnf: None,
                authorization_details: None,
                resource: None,
            },
        }
    }

    #[test]
    fn policies_are_unique_complete_and_sorted() {
        let names: Vec<_> = policies().iter().map(|policy| policy.tool.as_str()).collect();
        let unique: BTreeSet<_> = names.iter().copied().collect();
        assert_eq!(unique.len(), 52);
        assert_eq!(unique, ToolName::ALL.iter().map(|tool| tool.as_str()).collect());
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        for tool in ToolName::ALL {
            assert_eq!(policy_for(tool).tool, tool);
            assert_eq!(ToolName::parse(tool.as_str()), Some(tool));
        }
        assert_eq!(ToolName::parse("realm_delete"), None);
    }

    #[test]
    fn every_policy_enforces_its_scope_and_either_accepted_role() {
        for policy in policies() {
            let scope = match policy.tool.tier() {
                RiskTier::T0 => "mcp:read",
                RiskTier::T1 => "openid",
                _ => "mcp:write",
            };
            if policy.any_realm_roles.is_empty() {
                assert!(decide(policy, &auth(scope, &[])).is_allowed());
            }
            for role in policy.any_realm_roles {
                let roles = if policy.tool == ToolName::UsersRevokeSessions {
                    vec![
                        *role,
                        if *role == "manage-users" {
                            "manage-realm"
                        } else {
                            "manage-users"
                        },
                    ]
                } else {
                    vec![*role]
                };
                assert!(decide(policy, &auth(scope, &roles)).is_allowed());
            }
            let without_scope = if policy.tool.tier() == RiskTier::T1 {
                "profile"
            } else {
                "openid"
            };
            assert_eq!(
                decide(policy, &auth(without_scope, policy.any_realm_roles)),
                PolicyDecision::Deny(PolicyDeny::MissingScope(scope))
            );
            if policy.tool.tier() == RiskTier::T1 {
                assert!(decide(policy, &auth(scope, &["unrelated"])).is_allowed());
            } else {
                assert_eq!(
                    decide(policy, &auth(scope, &["unrelated"])),
                    PolicyDecision::Deny(PolicyDeny::MissingRole {
                        tool: policy.tool,
                        roles: policy.any_realm_roles,
                    })
                );
            }
            assert_eq!(
                decide(policy, &auth(without_scope, &["unrelated"])),
                PolicyDecision::Deny(PolicyDeny::MissingScope(scope)),
                "scope denial precedes role denial"
            );
        }
    }

    #[test]
    fn no_other_scope_grants_read_authority() {
        for scope in ["mcp:write", "mcp:step_up", "openid mcp:write", "admin"] {
            for policy in policies().iter().filter(|policy| policy.tool.tier() == RiskTier::T0) {
                assert!(!decide(policy, &auth(scope, policy.any_realm_roles)).is_allowed());
            }
        }
    }

    #[test]
    fn session_revocation_requires_both_manage_roles() {
        let policy = policy_for(ToolName::UsersRevokeSessions);
        for roles in [
            &["manage-users"][..],
            &["manage-realm"][..],
            &["unrelated"][..],
        ] {
            assert!(!decide(policy, &auth("mcp:write", roles)).is_allowed());
        }
        assert!(decide(policy, &auth("mcp:write", &["manage-users", "manage-realm"])).is_allowed());
    }

    #[test]
    fn roles_are_not_interchangeable_between_tools() {
        let cases = [
            (ToolName::AttackDetectionStatus, "view-users"),
            (ToolName::RealmGet, "view-users"),
            (ToolName::UsersGet, "view-clients"),
            (ToolName::UsersGetCredentials, "view-realm"),
            (ToolName::UsersGetGroups, "manage-realm"),
            (ToolName::UsersGetRoleMappings, "view-clients"),
            (ToolName::UsersGetSessions, "manage-clients"),
            (ToolName::UsersSearch, "manage-realm"),
            (ToolName::ClientsGet, "manage-users"),
            (ToolName::ClientsList, "view-realm"),
            (ToolName::GroupsGet, "view-users"),
            (ToolName::GroupsList, "view-clients"),
            (ToolName::GroupsMembers, "view-realm"),
            (ToolName::RolesGet, "manage-users"),
            (ToolName::RolesList, "manage-clients"),
        ];
        for (tool, wrong_role) in cases {
            assert!(!decide_for(tool, &auth("mcp:read", &[wrong_role])).is_allowed());
        }
    }

    #[test]
    fn group_members_require_user_read_roles_like_the_admin_api() {
        for role in ["view-users", "manage-users"] {
            assert!(decide_for(ToolName::GroupsMembers, &auth("mcp:read", &[role])).is_allowed());
        }
        for role in ["view-realm", "manage-realm", "view-clients"] {
            assert!(!decide_for(ToolName::GroupsMembers, &auth("mcp:read", &[role])).is_allowed());
        }
    }
}
