// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Splits a single LDAP attribute (e.g. cn) into first and last name.

use std::collections::HashMap;

use issuerd_core::{FederatedUser, FederationError};

use crate::mapper::user_attribute::config_value;
use crate::mapper::LdapMapper;

/// Splits a single LDAP attribute (e.g. `cn`) into first/last name.
#[derive(Debug, Clone)]
pub struct FullNameMapper {
    pub ldap_attribute: String,
}

impl FullNameMapper {
    /// Build from a `full-name-ldap-mapper` entry of the IdP `mappers` list:
    /// `ldap.full.name.attribute`, defaulting to `cn` (Keycloak parity).
    pub fn from_config(config: &HashMap<String, String>) -> Self {
        Self {
            ldap_attribute: config_value(config, "ldap.full.name.attribute")
                .unwrap_or_else(|| "cn".to_string()),
        }
    }
}

impl LdapMapper for FullNameMapper {
    fn id(&self) -> &str {
        "full-name-ldap-mapper"
    }

    fn requested_attributes(&self) -> Vec<String> {
        vec![self.ldap_attribute.clone()]
    }

    fn map_user(
        &self,
        ldap_attrs: &HashMap<String, Vec<String>>,
        user: &mut FederatedUser,
    ) -> Result<(), FederationError> {
        if let Some(full) =
            crate::mapper::get_attr(ldap_attrs, &self.ldap_attribute).and_then(|v| v.first())
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(value: &str) -> HashMap<String, Vec<String>> {
        HashMap::from([("cn".to_string(), vec![value.to_string()])])
    }

    fn user() -> FederatedUser {
        FederatedUser {
            username: "jdoe".to_string(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            attributes: HashMap::new(),
            federation_link: "f1".to_string(),
            external_id: None,
            groups: None,
        }
    }

    #[test]
    fn splits_on_first_space_and_trims_last_name() {
        let mapper = FullNameMapper {
            ldap_attribute: "cn".to_string(),
        };
        let mut u = user();
        mapper.map_user(&attrs("John Doe"), &mut u).unwrap();
        assert_eq!(u.first_name.as_deref(), Some("John"));
        // `idx + 1` must skip the space: the `*` mutant yields " Doe".
        assert_eq!(u.last_name.as_deref(), Some("Doe"));
    }

    #[test]
    fn single_word_sets_only_first_name() {
        let mapper = FullNameMapper {
            ldap_attribute: "cn".to_string(),
        };
        let mut u = user();
        mapper.map_user(&attrs("John"), &mut u).unwrap();
        assert_eq!(u.first_name.as_deref(), Some("John"));
        assert_eq!(u.last_name, None);
    }
}
