// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Splits a single LDAP attribute (e.g. cn) into first and last name.

use std::collections::HashMap;

use issuerd_core::{FederatedUser, FederationError};

use crate::mapper::LdapMapper;

/// Splits a single LDAP attribute (e.g. `cn`) into first/last name.
#[derive(Debug, Clone)]
pub struct FullNameMapper {
    pub ldap_attribute: String,
}

impl LdapMapper for FullNameMapper {
    fn id(&self) -> &str {
        "full-name-ldap-mapper"
    }

    fn map_user(
        &self,
        ldap_attrs: &HashMap<String, Vec<String>>,
        user: &mut FederatedUser,
    ) -> Result<(), FederationError> {
        if let Some(full) = ldap_attrs.get(&self.ldap_attribute).and_then(|v| v.first()) {
            // Split on first space: "John Doe" -> first_name="John", last_name="Doe"
            if let Some(idx) = full.find(' ') {
                user.first_name = issuerd_core::DisplayName::new(&full[..idx]).ok();
                user.last_name = issuerd_core::DisplayName::new(&full[idx + 1..]).ok();
            } else {
                user.first_name = issuerd_core::DisplayName::new(full).ok();
            }
        }
        Ok(())
    }
}
