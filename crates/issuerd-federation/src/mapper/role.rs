// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Maps LDAP role memberships to Issuerd role names.

use std::collections::HashMap;

use issuerd_core::{FederatedUser, FederationError};

use crate::mapper::LdapMapper;

/// Maps LDAP role memberships to Issuerd role names.
#[derive(Debug, Clone)]
pub struct RoleMapper {
    pub roles_dn: String,
    pub role_name_attribute: String,
    pub client_id: Option<String>, // None = realm roles
}

impl RoleMapper {
    fn extract_role_name(&self, dn: &str) -> Option<String> {
        // Same logic as GroupMapper
        dn.split(',').next()?.split_once('=').map(|(_, name)| name.to_string())
    }
}

impl LdapMapper for RoleMapper {
    fn id(&self) -> &str {
        "role-ldap-mapper"
    }

    fn map_user(
        &self,
        _ldap_attrs: &HashMap<String, Vec<String>>,
        _user: &mut FederatedUser,
    ) -> Result<(), FederationError> {
        Ok(())
    }

    fn map_memberships(&self, ldap_attrs: &HashMap<String, Vec<String>>) -> Vec<String> {
        ldap_attrs
            .get("memberOf")
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|dn| self.extract_role_name(&dn))
            .collect()
    }
}
