// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Kerberos federation provider configuration.

use std::collections::HashMap;

use issuerd_core::FederationError;

/// Configuration for a Kerberos federation provider.
#[derive(Debug, Clone)]
pub struct KerberosConfig {
    pub kerberos_realm: String,
    pub server_principal: String,
    pub keytab_path: String,
    pub allow_password_authentication: bool,
    pub allow_kerberos_authentication: bool,
    pub update_profile_first_login: bool,
    pub debug: bool,
}

impl KerberosConfig {
    /// Parse from a raw `HashMap<String,String>`.
    pub fn from_hashmap(config: &HashMap<String, String>) -> Result<Self, FederationError> {
        let kerberos_realm = config
            .get("kerberosRealm")
            .ok_or_else(|| FederationError::ConfigError("missing kerberosRealm".into()))?
            .clone();
        Ok(Self {
            kerberos_realm,
            server_principal: config.get("serverPrincipal").cloned().unwrap_or_default(),
            keytab_path: config.get("keyTab").cloned().unwrap_or_default(),
            allow_password_authentication: config
                .get("allowPasswordAuthentication")
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            allow_kerberos_authentication: config
                .get("allowKerberosAuthentication")
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            update_profile_first_login: config
                .get("updateProfileFirstLogin")
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            debug: config.get("debug").map(|s| s.eq_ignore_ascii_case("true")).unwrap_or(false),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kerberos_config_parsing() {
        let mut m = HashMap::new();
        m.insert("kerberosRealm".to_string(), "TEST.ISSUERD.LOCAL".to_string());
        m.insert("allowPasswordAuthentication".to_string(), "true".to_string());
        let cfg = KerberosConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.kerberos_realm, "TEST.ISSUERD.LOCAL");
        assert!(cfg.allow_password_authentication);
        assert!(cfg.allow_kerberos_authentication); // default
    }

    #[test]
    fn kerberos_config_missing_realm() {
        let m = HashMap::new();
        let err = KerberosConfig::from_hashmap(&m).unwrap_err();
        assert!(matches!(err, FederationError::ConfigError(_)));
    }

    #[test]
    fn kerberos_config_all_fields_parsed() {
        let mut m = HashMap::new();
        m.insert("kerberosRealm".to_string(), "TEST.ISSUERD.LOCAL".to_string());
        m.insert("serverPrincipal".to_string(), "HTTP/test@TEST.ISSUERD.LOCAL".to_string());
        m.insert("keyTab".to_string(), "/etc/keytab".to_string());
        m.insert("allowPasswordAuthentication".to_string(), "true".to_string());
        m.insert("allowKerberosAuthentication".to_string(), "false".to_string());
        m.insert("updateProfileFirstLogin".to_string(), "false".to_string());
        m.insert("debug".to_string(), "true".to_string());
        let cfg = KerberosConfig::from_hashmap(&m).unwrap();
        assert_eq!(cfg.kerberos_realm, "TEST.ISSUERD.LOCAL");
        assert_eq!(cfg.server_principal, "HTTP/test@TEST.ISSUERD.LOCAL");
        assert_eq!(cfg.keytab_path, "/etc/keytab");
        assert!(cfg.allow_password_authentication);
        assert!(!cfg.allow_kerberos_authentication);
        assert!(!cfg.update_profile_first_login);
        assert!(cfg.debug);
    }
}
