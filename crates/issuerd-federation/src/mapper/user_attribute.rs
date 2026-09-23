// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Maps a single LDAP attribute to a user model field.

use std::collections::HashMap;

use issuerd_core::{FederatedUser, FederationError};

use crate::mapper::LdapMapper;

/// Maps a single LDAP attribute to a user model field.
#[derive(Debug, Clone)]
pub struct UserAttributeMapper {
    pub user_attribute: String,
    pub ldap_attribute: String,
    pub read_only: bool,
    pub always_read_from_ldap: bool,
    pub is_mandatory_in_ldap: bool,
    pub default_value: Option<String>,
}

impl LdapMapper for UserAttributeMapper {
    fn id(&self) -> &str {
        "user-attribute-ldap-mapper"
    }

    fn map_user(
        &self,
        ldap_attrs: &HashMap<String, Vec<String>>,
        user: &mut FederatedUser,
    ) -> Result<(), FederationError> {
        let values = ldap_attrs.get(&self.ldap_attribute);
        if values.is_none() && self.is_mandatory_in_ldap {
            return Err(FederationError::SchemaMismatch(format!(
                "mandatory attribute {} missing",
                self.ldap_attribute
            )));
        }
        let value = values.and_then(|v| v.first()).cloned().or_else(|| self.default_value.clone());

        match self.user_attribute.as_str() {
            "username" => { /* skip — set from DN/username search */ }
            "email" => user.email = value,
            "firstName" => {
                user.first_name = value.and_then(|s| issuerd_core::DisplayName::new(&s).ok())
            }
            "lastName" => {
                user.last_name = value.and_then(|s| issuerd_core::DisplayName::new(&s).ok())
            }
            other => {
                if let Some(v) = value {
                    user.attributes.insert(other.to_string(), vec![v]);
                }
            }
        }
        Ok(())
    }
}
