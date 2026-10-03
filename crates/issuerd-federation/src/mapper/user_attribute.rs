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

/// Parse a Keycloak-style boolean config value (`"true"`, case-insensitive).
pub(crate) fn config_bool(config: &HashMap<String, String>, key: &str) -> bool {
    config.get(key).is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// Fetch a trimmed, non-empty config value.
pub(crate) fn config_value(config: &HashMap<String, String>, key: &str) -> Option<String> {
    config.get(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

impl UserAttributeMapper {
    /// Build from a `user-attribute-ldap-mapper` entry of the IdP `mappers`
    /// list (Keycloak config keys, so exported Keycloak configs translate
    /// 1:1): `user.attribute` + `ldap.attribute` are required; optional
    /// `read.only`, `always.read.value.from.ldap`, `is.mandatory.in.ldap`,
    /// `attribute.default.value`. Returns `None` when a required key is
    /// missing/blank.
    pub fn from_config(config: &HashMap<String, String>) -> Option<Self> {
        Some(Self {
            user_attribute: config_value(config, "user.attribute")?,
            ldap_attribute: config_value(config, "ldap.attribute")?,
            read_only: config_bool(config, "read.only"),
            always_read_from_ldap: config_bool(config, "always.read.value.from.ldap"),
            is_mandatory_in_ldap: config_bool(config, "is.mandatory.in.ldap"),
            default_value: config_value(config, "attribute.default.value"),
        })
    }
}

impl LdapMapper for UserAttributeMapper {
    fn id(&self) -> &str {
        "user-attribute-ldap-mapper"
    }

    fn requested_attributes(&self) -> Vec<String> {
        vec![self.ldap_attribute.clone()]
    }

    fn map_user(
        &self,
        ldap_attrs: &HashMap<String, Vec<String>>,
        user: &mut FederatedUser,
    ) -> Result<(), FederationError> {
        let values = crate::mapper::get_attr(ldap_attrs, &self.ldap_attribute);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_requires_both_attributes() {
        assert!(UserAttributeMapper::from_config(&HashMap::new()).is_none());
        assert!(UserAttributeMapper::from_config(&HashMap::from([(
            "user.attribute".to_string(),
            "email".to_string()
        )]))
        .is_none());
        // Blank values count as missing.
        assert!(UserAttributeMapper::from_config(&HashMap::from([
            ("user.attribute".to_string(), "email".to_string()),
            ("ldap.attribute".to_string(), "  ".to_string()),
        ]))
        .is_none());
    }

    #[test]
    fn from_config_parses_flags_and_default() {
        let m = UserAttributeMapper::from_config(&HashMap::from([
            ("user.attribute".to_string(), "email".to_string()),
            ("ldap.attribute".to_string(), "mail".to_string()),
            ("read.only".to_string(), "TRUE".to_string()),
            ("is.mandatory.in.ldap".to_string(), "true".to_string()),
            ("attribute.default.value".to_string(), "none@example.com".to_string()),
        ]))
        .unwrap();
        assert_eq!(m.user_attribute, "email");
        assert_eq!(m.ldap_attribute, "mail");
        assert!(m.read_only);
        assert!(!m.always_read_from_ldap);
        assert!(m.is_mandatory_in_ldap);
        assert_eq!(m.default_value.as_deref(), Some("none@example.com"));
    }

    #[test]
    fn mapper_requests_its_ldap_attribute() {
        let m = UserAttributeMapper::from_config(&HashMap::from([
            ("user.attribute".to_string(), "email".to_string()),
            ("ldap.attribute".to_string(), "mail".to_string()),
        ]))
        .unwrap();
        assert_eq!(m.requested_attributes(), vec!["mail".to_string()]);
    }

    #[test]
    fn maps_email_and_custom_attribute() {
        let email = UserAttributeMapper::from_config(&HashMap::from([
            ("user.attribute".to_string(), "email".to_string()),
            ("ldap.attribute".to_string(), "mail".to_string()),
        ]))
        .unwrap();
        let custom = UserAttributeMapper::from_config(&HashMap::from([
            ("user.attribute".to_string(), "department".to_string()),
            ("ldap.attribute".to_string(), "ou".to_string()),
        ]))
        .unwrap();
        let attrs = HashMap::from([
            ("mail".to_string(), vec!["a@ex.com".to_string()]),
            ("ou".to_string(), vec!["eng".to_string()]),
        ]);
        let mut user = FederatedUser {
            username: "alice".to_string(),
            federation_link: "f1".to_string(),
            ..Default::default()
        };
        email.map_user(&attrs, &mut user).unwrap();
        custom.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.email.as_deref(), Some("a@ex.com"));
        assert_eq!(user.attributes.get("department").unwrap(), &vec!["eng".to_string()]);
    }

    #[test]
    fn mandatory_attribute_missing_errors() {
        let m = UserAttributeMapper::from_config(&HashMap::from([
            ("user.attribute".to_string(), "email".to_string()),
            ("ldap.attribute".to_string(), "mail".to_string()),
            ("is.mandatory.in.ldap".to_string(), "true".to_string()),
        ]))
        .unwrap();
        let mut user = FederatedUser {
            username: "alice".to_string(),
            federation_link: "f1".to_string(),
            ..Default::default()
        };
        assert!(m.map_user(&HashMap::new(), &mut user).is_err());
    }
}

#[cfg(test)]
mod case_tests {
    use super::*;

    #[test]
    fn ldap_attribute_lookup_is_case_insensitive() {
        // LLDAP's "*" expansion returns schema attributes lowercased
        // (`givenname`), AD preserves its schema case (`givenName`) — both
        // must match the configured `givenName` (RFC 4512 §2.5).
        let m = UserAttributeMapper::from_config(&HashMap::from([
            ("user.attribute".to_string(), "firstName".to_string()),
            ("ldap.attribute".to_string(), "givenName".to_string()),
        ]))
        .unwrap();
        let attrs = HashMap::from([("givenname".to_string(), vec!["Test".to_string()])]);
        let mut user = FederatedUser {
            username: "alice".to_string(),
            federation_link: "f1".to_string(),
            ..Default::default()
        };
        m.map_user(&attrs, &mut user).unwrap();
        assert_eq!(user.first_name.as_deref(), Some("Test"));
    }
}
