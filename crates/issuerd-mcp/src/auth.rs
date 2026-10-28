// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use issuerd_core::{AccessTokenClaims, ClientIdentifier, RealmId, RealmName, UserId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAuthContext {
    pub realm_id: RealmId,
    pub realm_name: RealmName,
    pub user_id: UserId,
    pub azp: ClientIdentifier,
    pub claims: AccessTokenClaims,
}

impl McpAuthContext {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.claims.scope.contains(scope)
    }

    pub fn has_realm_role(&self, role: &str) -> bool {
        self.claims
            .realm_access
            .as_ref()
            .is_some_and(|access| access.roles.iter().any(|candidate| candidate.as_ref() == role))
    }

    pub fn has_any_realm_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|role| self.has_realm_role(role))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{Audience, Issuer, JwtId, JwtType, RealmAccess, RoleName, Scope};

    fn auth(scope: &str, roles: &[&str]) -> McpAuthContext {
        let realm_id = RealmId::new("realm-uuid").unwrap();
        let user_id = UserId::new("user-uuid").unwrap();
        let azp = ClientIdentifier::new("agent").unwrap();
        let claims = AccessTokenClaims {
            jti: JwtId::new("token-id").unwrap(),
            iss: Issuer::new("https://issuer.example/realms/demo").unwrap(),
            sub: UserId::new("pairwise-subject").unwrap(),
            aud: Audience::new("agent").unwrap(),
            exp: 100,
            iat: 1,
            nbf: 1,
            scope: Scope::parse(scope),
            typ: JwtType::Bearer,
            azp: Some(azp.to_string()),
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
        };
        McpAuthContext {
            realm_id,
            realm_name: RealmName::new("demo").unwrap(),
            user_id,
            azp,
            claims,
        }
    }

    #[test]
    fn scope_and_realm_role_checks_are_exact() {
        let context = auth("openid mcp:read", &["view-users"]);
        assert!(context.has_scope("mcp:read"));
        assert!(!context.has_scope("mcp:write"));
        assert!(!context.has_scope("read"));
        assert!(context.has_realm_role("view-users"));
        assert!(context.has_any_realm_role(&["manage-users", "view-users"]));
        assert!(!context.has_any_realm_role(&["manage-users", "view-clients"]));
    }

    #[test]
    fn write_and_step_up_scopes_do_not_imply_read() {
        for scope in ["mcp:write", "mcp:step_up", "openid"] {
            assert!(!auth(scope, &["view-realm"]).has_scope("mcp:read"));
        }
    }
}
