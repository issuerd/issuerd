// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use issuerd_core::MCP_SCOPE_READ;
use serde::{Deserialize, Serialize};

use crate::auth::McpAuthContext;

const REALM_ROLES: &[&str] = &["view-realm", "manage-realm"];
const USER_ROLES: &[&str] = &["view-users", "manage-users"];
const CLIENT_ROLES: &[&str] = &["view-clients", "manage-clients"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolName {
    AttackDetectionStatus,
    ClientsGet,
    ClientsList,
    GroupsGet,
    GroupsList,
    GroupsMembers,
    RealmGet,
    RolesGet,
    RolesList,
    UsersGet,
    UsersGetCredentials,
    UsersGetGroups,
    UsersGetRoleMappings,
    UsersGetSessions,
    UsersSearch,
}

impl ToolName {
    pub const ALL: [Self; 15] = [
        Self::AttackDetectionStatus,
        Self::ClientsGet,
        Self::ClientsList,
        Self::GroupsGet,
        Self::GroupsList,
        Self::GroupsMembers,
        Self::RealmGet,
        Self::RolesGet,
        Self::RolesList,
        Self::UsersGet,
        Self::UsersGetCredentials,
        Self::UsersGetGroups,
        Self::UsersGetRoleMappings,
        Self::UsersGetSessions,
        Self::UsersSearch,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttackDetectionStatus => "attack_detection_status",
            Self::ClientsGet => "clients_get",
            Self::ClientsList => "clients_list",
            Self::GroupsGet => "groups_get",
            Self::GroupsList => "groups_list",
            Self::GroupsMembers => "groups_members",
            Self::RealmGet => "realm_get",
            Self::RolesGet => "roles_get",
            Self::RolesList => "roles_list",
            Self::UsersGet => "users_get",
            Self::UsersGetCredentials => "users_get_credentials",
            Self::UsersGetGroups => "users_get_groups",
            Self::UsersGetRoleMappings => "users_get_role_mappings",
            Self::UsersGetSessions => "users_get_sessions",
            Self::UsersSearch => "users_search",
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

pub const POLICIES: [ToolPolicy; 15] = [
    ToolPolicy {
        tool: ToolName::AttackDetectionStatus,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: &["manage-users"],
    },
    ToolPolicy {
        tool: ToolName::ClientsGet,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: CLIENT_ROLES,
    },
    ToolPolicy {
        tool: ToolName::ClientsList,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: CLIENT_ROLES,
    },
    ToolPolicy {
        tool: ToolName::GroupsGet,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: REALM_ROLES,
    },
    ToolPolicy {
        tool: ToolName::GroupsList,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: REALM_ROLES,
    },
    ToolPolicy {
        tool: ToolName::GroupsMembers,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: USER_ROLES,
    },
    ToolPolicy {
        tool: ToolName::RealmGet,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: REALM_ROLES,
    },
    ToolPolicy {
        tool: ToolName::RolesGet,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: REALM_ROLES,
    },
    ToolPolicy {
        tool: ToolName::RolesList,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: REALM_ROLES,
    },
    ToolPolicy {
        tool: ToolName::UsersGet,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: USER_ROLES,
    },
    ToolPolicy {
        tool: ToolName::UsersGetCredentials,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: USER_ROLES,
    },
    ToolPolicy {
        tool: ToolName::UsersGetGroups,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: USER_ROLES,
    },
    ToolPolicy {
        tool: ToolName::UsersGetRoleMappings,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: USER_ROLES,
    },
    ToolPolicy {
        tool: ToolName::UsersGetSessions,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: USER_ROLES,
    },
    ToolPolicy {
        tool: ToolName::UsersSearch,
        required_scope: MCP_SCOPE_READ,
        any_realm_roles: USER_ROLES,
    },
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

pub fn policies() -> &'static [ToolPolicy; 15] {
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
    if !auth.has_scope(policy.required_scope) {
        return PolicyDecision::Deny(PolicyDeny::MissingScope(policy.required_scope));
    }
    if !auth.has_any_realm_role(policy.any_realm_roles) {
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
        assert_eq!(unique.len(), 15);
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
            for role in policy.any_realm_roles {
                assert!(decide(policy, &auth("mcp:read", &[*role])).is_allowed());
            }
            assert_eq!(
                decide(policy, &auth("openid", policy.any_realm_roles)),
                PolicyDecision::Deny(PolicyDeny::MissingScope("mcp:read"))
            );
            assert_eq!(
                decide(policy, &auth("mcp:read", &["unrelated"])),
                PolicyDecision::Deny(PolicyDeny::MissingRole {
                    tool: policy.tool,
                    roles: policy.any_realm_roles,
                })
            );
            assert_eq!(
                decide(policy, &auth("openid", &["unrelated"])),
                PolicyDecision::Deny(PolicyDeny::MissingScope("mcp:read")),
                "scope denial precedes role denial"
            );
        }
    }

    #[test]
    fn no_other_scope_grants_read_authority() {
        for scope in ["mcp:write", "mcp:step_up", "openid mcp:write", "admin"] {
            for policy in policies() {
                assert!(!decide(policy, &auth(scope, policy.any_realm_roles)).is_allowed());
            }
        }
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
