// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Interprets MSAD userAccountControl and pwdLastSet attributes.

use std::collections::HashMap;

use issuerd_core::{FederatedUser, FederationError};

use crate::mapper::LdapMapper;

/// Interprets MSAD `userAccountControl` and `pwdLastSet` attributes.
#[derive(Debug, Clone, Copy)]
pub struct MsadAccountControlMapper;

impl LdapMapper for MsadAccountControlMapper {
    fn id(&self) -> &str {
        "msad-user-account-control-mapper"
    }

    fn map_enabled(&self, ldap_attrs: &HashMap<String, Vec<String>>) -> Option<bool> {
        let uac = ldap_attrs.get("userAccountControl")?.first()?.parse::<u32>().ok()?;
        // ACCOUNTDISABLE bit = 0x0002
        Some((uac & 0x0002) == 0)
    }

    fn map_user(
        &self,
        ldap_attrs: &HashMap<String, Vec<String>>,
        user: &mut FederatedUser,
    ) -> Result<(), FederationError> {
        if let Some(enabled) = self.map_enabled(ldap_attrs) {
            user.enabled = enabled;
        }
        // pwdLastSet == 0 means "must change password at next logon"
        if let Some(pwd_last_set) = ldap_attrs.get("pwdLastSet").and_then(|v| v.first()) {
            if pwd_last_set == "0" {
                user.attributes.insert("UPDATE_PASSWORD".to_string(), vec!["true".to_string()]);
            }
        }
        Ok(())
    }
}
