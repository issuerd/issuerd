// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// LDAP federation provider configuration (vendor, search scope, TLS options).

use std::collections::HashMap;

use issuerd_core::{EditMode, FederationError};

/// Configuration for an LDAP federation provider.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub connection_url: String,
    pub bind_dn: String,
    pub bind_credential: String,
    pub users_dn: String,
    pub base_dn: String,
    pub username_attribute: String,
    pub rdn_attribute: String,
    pub uuid_attribute: String,
    pub user_object_classes: Vec<String>,
    pub edit_mode: EditMode,
    pub custom_user_search_filter: Option<String>,
    pub search_scope: LdapSearchScope,
    pub use_starttls: bool,
    /// Skip TLS certificate verification for `ldaps://`/StartTLS connections.
    /// INSECURE — lab/dev only (self-signed directory certs); defaults to false.
    pub no_tls_verify: bool,
    pub pagination: bool,
    pub batch_size: i32,
    pub max_conditions: i32,
    pub vendor: LdapVendor,
}

/// LDAP server vendor — drives defaults and special-cased behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapVendor {
    Generic,
    ActiveDirectory,
    Samba,
}

/// LDAP search scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapSearchScope {
    Subtree,
    OneLevel,
    Base,
}

impl LdapConfig {
    /// Build an `LdapConfig` from the raw `HashMap<String,String>` stored in
    /// `FederationProviderConfig.config`.
    pub fn from_hashmap(config: &HashMap<String, String>) -> Result<Self, FederationError> {
        let vendor = config
            .get("vendor")
            .map(|v| match v.as_str() {
                "ACTIVE_DIRECTORY" => LdapVendor::ActiveDirectory,
                "SAMBA" => LdapVendor::Samba,
                _ => LdapVendor::Generic,
            })
            .unwrap_or(LdapVendor::Generic);

        let connection_url = config
            .get("connectionUrl")
            .ok_or_else(|| FederationError::ConfigError("missing connectionUrl".into()))?
            .clone();

        let username_attribute =
            config.get("usernameLdapAttribute").cloned().unwrap_or_else(|| match vendor {
                LdapVendor::ActiveDirectory | LdapVendor::Samba => "sAMAccountName".to_string(),
                LdapVendor::Generic => "uid".to_string(),
            });

        let uuid_attribute =
            config.get("uuidLdapAttribute").cloned().unwrap_or_else(|| match vendor {
                LdapVendor::ActiveDirectory | LdapVendor::Samba => "objectGUID".to_string(),
                LdapVendor::Generic => "entryUUID".to_string(),
            });

        let user_object_classes = config
            .get("userObjectClasses")
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|| {
                vec![
                    "inetOrgPerson".to_string(),
                    "organizationalPerson".to_string(),
                ]
            });

        let search_scope = config
            .get("searchScope")
            .map(|s| match s.as_str() {
                "ONELEVEL" => LdapSearchScope::OneLevel,
                "BASE" => LdapSearchScope::Base,
                _ => LdapSearchScope::Subtree,
            })
            .unwrap_or(LdapSearchScope::Subtree);

        let edit_mode = config
            .get("editMode")
            .map(|s| match s.as_str() {
                "WRITABLE" => EditMode::Writable,
                "UNSYNCED" => EditMode::Unsynced,
                _ => EditMode::ReadOnly,
            })
            .unwrap_or(EditMode::ReadOnly);

        Ok(Self {
            connection_url,
            bind_dn: config.get("bindDn").cloned().unwrap_or_default(),
            bind_credential: config.get("bindCredential").cloned().unwrap_or_default(),
            users_dn: config.get("usersDn").cloned().unwrap_or_default(),
            base_dn: config.get("baseDn").cloned().unwrap_or_default(),
            rdn_attribute: config
                .get("rdnLdapAttribute")
                .cloned()
                .unwrap_or_else(|| username_attribute.clone()),
            username_attribute,
            uuid_attribute,
            user_object_classes,
            edit_mode,
            custom_user_search_filter: config.get("customUserSearchFilter").cloned(),
            search_scope,
            use_starttls: config
                .get("useStartTls")
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            no_tls_verify: config
                .get("noTlsVerify")
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            pagination: config
                .get("pagination")
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            batch_size: config.get("batchSize").and_then(|s| s.parse().ok()).unwrap_or(1000),
            max_conditions: config
                .get("maxConditions")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000),
            vendor,
        })
    }

    /// Build an RFC-4515 search filter for a single username.
    pub fn user_search_filter(&self, username: &str) -> String {
        let object_classes = self
            .user_object_classes
            .iter()
            .map(|c| format!("(objectClass={})", esc_ldap_filter(c)))
            .collect::<String>();

        let user_filter = format!(
            "({}={})",
            esc_ldap_filter(&self.username_attribute),
            esc_ldap_filter(username)
        );

        if let Some(custom) = &self.custom_user_search_filter {
            format!("(&{}({}))", user_filter, custom.trim_start_matches('(').trim_end_matches(')'))
        } else {
            format!("(&{}{})", object_classes, user_filter)
        }
    }

    /// Build a search filter for a single email address.
    pub fn email_search_filter(&self, email: &str) -> String {
        let object_classes = self
            .user_object_classes
            .iter()
            .map(|c| format!("(objectClass={})", esc_ldap_filter(c)))
            .collect::<String>();
        format!("(&{}(mail={}))", object_classes, esc_ldap_filter(email))
    }

    /// Build a filter that matches all user objects.
    pub fn all_users_filter(&self) -> String {
        let object_classes = self
            .user_object_classes
            .iter()
            .map(|c| format!("(objectClass={})", esc_ldap_filter(c)))
            .collect::<String>();
        format!("(&{})", object_classes)
    }
}

/// Minimal LDAP filter escaping per RFC 4515.
fn esc_ldap_filter(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\\' => "\\5c".to_string(),
            '*' => "\\2a".to_string(),
            '(' => "\\28".to_string(),
            ')' => "\\29".to_string(),
            '\0' => "\\00".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldap_config_defaults_for_ad() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://dc.example.com".to_string());
        m.insert("vendor".to_string(), "ACTIVE_DIRECTORY".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.username_attribute, "sAMAccountName");
        assert_eq!(cfg.uuid_attribute, "objectGUID");
        assert_eq!(cfg.rdn_attribute, "sAMAccountName");
    }

    #[test]
    fn ldap_config_defaults_for_generic() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.username_attribute, "uid");
        assert_eq!(cfg.uuid_attribute, "entryUUID");
        assert_eq!(cfg.rdn_attribute, "uid");
    }

    #[test]
    fn ldap_config_user_search_filter() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        m.insert(
            "userObjectClasses".to_string(),
            "inetOrgPerson,organizationalPerson".to_string(),
        );
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        let filter = cfg.user_search_filter("alice");
        assert!(filter.contains("(objectClass=inetOrgPerson)"));
        assert!(filter.contains("(objectClass=organizationalPerson)"));
        assert!(filter.contains("(uid=alice)"));
        assert!(filter.starts_with("(&"));
    }

    #[test]
    fn ldap_config_custom_search_filter() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        m.insert("customUserSearchFilter".to_string(), "(employeeType=internal)".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        let filter = cfg.user_search_filter("alice");
        assert!(filter.contains("(uid=alice)"));
        assert!(filter.contains("employeeType=internal"));
    }

    #[test]
    fn ldap_config_from_hashmap_missing_url() {
        let m = HashMap::new();
        let err = LdapConfig::from_hashmap(&m).unwrap_err();
        assert!(matches!(err, FederationError::ConfigError(_)));
    }

    #[test]
    fn ldap_config_escaping() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        let filter = cfg.user_search_filter("user(name)");
        assert!(filter.contains(r"(uid=user\28name\29)"));
    }

    #[test]
    fn ldap_config_samba_defaults() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://samba.example.com".to_string());
        m.insert("vendor".to_string(), "SAMBA".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.username_attribute, "sAMAccountName");
        assert_eq!(cfg.uuid_attribute, "objectGUID");
        assert_eq!(cfg.vendor, LdapVendor::Samba);
    }

    #[test]
    fn ldap_config_onelevel_scope() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        m.insert("searchScope".to_string(), "ONELEVEL".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.search_scope, LdapSearchScope::OneLevel);
    }

    #[test]
    fn ldap_config_base_scope() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        m.insert("searchScope".to_string(), "BASE".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.search_scope, LdapSearchScope::Base);
    }

    #[test]
    fn ldap_config_writable_mode() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        m.insert("editMode".to_string(), "WRITABLE".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.edit_mode, EditMode::Writable);
    }

    #[test]
    fn ldap_config_unsynced_mode() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        m.insert("editMode".to_string(), "UNSYNCED".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.edit_mode, EditMode::Unsynced);
    }

    #[test]
    fn ldap_config_starttls_and_pagination() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        m.insert("useStartTls".to_string(), "true".to_string());
        m.insert("pagination".to_string(), "true".to_string());
        m.insert("batchSize".to_string(), "500".to_string());
        m.insert("maxConditions".to_string(), "50".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert!(cfg.use_starttls);
        assert!(cfg.pagination);
        assert_eq!(cfg.batch_size, 500);
        assert_eq!(cfg.max_conditions, 50);
    }

    #[test]
    fn ldap_config_no_tls_verify() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldaps://ldap.example.com".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert!(!cfg.no_tls_verify, "default must verify certificates");

        m.insert("noTlsVerify".to_string(), "true".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert!(cfg.no_tls_verify);
    }

    #[test]
    fn ldap_config_email_search_filter() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        let filter = cfg.email_search_filter("alice@example.com");
        assert!(filter.contains("(mail=alice@example.com)"));
        assert!(filter.starts_with("(&"));
    }

    #[test]
    fn ldap_config_all_users_filter() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        m.insert(
            "userObjectClasses".to_string(),
            "inetOrgPerson,organizationalPerson".to_string(),
        );
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        let filter = cfg.all_users_filter();
        assert!(filter.contains("(objectClass=inetOrgPerson)"));
        assert!(filter.contains("(objectClass=organizationalPerson)"));
        assert!(filter.starts_with("(&"));
    }

    #[test]
    fn ldap_config_rdn_override() {
        let mut m = HashMap::new();
        m.insert("connectionUrl".to_string(), "ldap://ldap.example.com".to_string());
        m.insert("rdnLdapAttribute".to_string(), "cn".to_string());
        let cfg = LdapConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.rdn_attribute, "cn");
    }
}
