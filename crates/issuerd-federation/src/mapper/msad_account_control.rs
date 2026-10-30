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
        let uac = crate::mapper::get_attr(ldap_attrs, "userAccountControl")?
            .first()?
            .parse::<u32>()
            .ok()?;
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
        if let Some(pwd_last_set) =
            crate::mapper::get_attr(ldap_attrs, "pwdLastSet").and_then(|v| v.first())
        {
            if pwd_last_set == "0" {
                user.attributes.insert("UPDATE_PASSWORD".to_string(), vec!["true".to_string()]);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(name: &str, values: &[&str]) -> HashMap<String, Vec<String>> {
        HashMap::from([(
            name.to_string(),
            values.iter().map(|value| (*value).to_string()).collect(),
        )])
    }

    #[test]
    fn pwd_last_set_zero_requires_password_update() {
        let mapper = MsadAccountControlMapper;
        let mut user = FederatedUser::default();
        let mut ldap_attrs = attrs("pwdLastSet", &["0"]);
        ldap_attrs.extend(attrs("userAccountControl", &["514"]));

        mapper.map_user(&ldap_attrs, &mut user).unwrap();

        assert!(!user.enabled);
        assert_eq!(user.attributes.get("UPDATE_PASSWORD"), Some(&vec!["true".to_string()]));
    }

    #[test]
    fn malformed_account_control_values_return_none() {
        let mapper = MsadAccountControlMapper;
        for value in ["", "not-a-number", "-1", "512.0", " 512", "4294967296"] {
            assert_eq!(mapper.map_enabled(&attrs("userAccountControl", &[value])), None, "{value}");
        }
        assert_eq!(mapper.map_enabled(&attrs("userAccountControl", &[])), None);
        assert_eq!(mapper.map_enabled(&HashMap::new()), None);
    }

    #[test]
    fn account_control_uses_the_first_value() {
        let mapper = MsadAccountControlMapper;
        assert_eq!(mapper.map_enabled(&attrs("userAccountControl", &["514", "512"])), Some(false));
        assert_eq!(mapper.map_enabled(&attrs("userAccountControl", &["512", "514"])), Some(true));
    }

    #[test]
    fn known_account_control_flags_keep_their_enabled_state() {
        let mapper = MsadAccountControlMapper;
        for (value, expected) in [
            ("512", true),
            ("514", false),
            ("544", true),
            ("66048", true),
        ] {
            assert_eq!(
                mapper.map_enabled(&attrs("userAccountControl", &[value])),
                Some(expected),
                "{value}"
            );
        }
    }
}
