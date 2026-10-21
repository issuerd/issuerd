// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Kerberos-backed federation provider.

use std::collections::HashMap;

use issuerd_core::{
    FederatedUser, FederationError, FederationProvider, FederationProviderType, SpnegoAuthResult,
};

use crate::kerberos::config::KerberosConfig;

/// Kerberos-backed federation provider.
pub struct KerberosFederationProvider {
    id: String,
    config: KerberosConfig,
}

impl KerberosFederationProvider {
    pub fn new(id: String, config: KerberosConfig) -> Result<Self, FederationError> {
        if config.allow_kerberos_authentication
            && !std::path::Path::new(&config.keytab_path).is_file()
        {
            return Err(FederationError::ConfigError("keytab missing".into()));
        }
        Ok(Self { id, config })
    }

    /// Refuses a SPNEGO result whose principal (`name@REALM`) is not in the
    /// configured realm.
    ///
    /// Callers map the part before the first `@` onto a local username, so a
    /// principal from any other realm the KDC trusts must be refused here.
    /// No configured realm means no principal is accepted.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn require_configured_realm(
        &self,
        result: SpnegoAuthResult,
    ) -> Result<SpnegoAuthResult, FederationError> {
        let Some(principal) = result.principal.as_deref() else {
            return Ok(result);
        };
        let realm = &self.config.kerberos_realm;
        if !realm.is_empty()
            && principal.split_once('@').is_some_and(|(_, r)| r.eq_ignore_ascii_case(realm))
        {
            return Ok(result);
        }
        tracing::warn!(
            provider_id = %self.id,
            principal = %issuerd_core::utils::sanitize_log_str(principal),
            "SPNEGO principal is outside the configured Kerberos realm"
        );
        Err(FederationError::InvalidCredentials)
    }
}

#[async_trait::async_trait]
impl FederationProvider for KerberosFederationProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn provider_type(&self) -> FederationProviderType {
        FederationProviderType::Kerberos
    }

    async fn find_user(&self, username: &str) -> Result<Option<FederatedUser>, FederationError> {
        let principal = format!("{}@{}", username, self.config.kerberos_realm);
        Ok(Some(FederatedUser {
            username: username.to_string(),
            federation_link: self.id.clone(),
            enabled: true,
            attributes: {
                let mut m = HashMap::new();
                m.insert("KERBEROS_PRINCIPAL".to_string(), vec![principal]);
                m
            },
            ..Default::default()
        }))
    }

    async fn find_user_by_email(
        &self,
        _email: &str,
    ) -> Result<Option<FederatedUser>, FederationError> {
        Ok(None)
    }

    async fn validate_password(
        &self,
        _username: &str,
        _password: &str,
    ) -> Result<bool, FederationError> {
        if !self.config.allow_password_authentication {
            return Err(FederationError::NotSupported);
        }
        // Kerberos password validation requires a KDC connection.
        // On Unix this could use libgssapi client credentials or krb5 crate.
        // For MVP, password validation via Kerberos is a platform-specific
        // integration test feature.
        Err(FederationError::NotSupported)
    }

    async fn update_password(
        &self,
        _username: &str,
        _password: &str,
    ) -> Result<(), FederationError> {
        Err(FederationError::NotSupported)
    }

    async fn authenticate_spnego(&self, token: &str) -> Result<SpnegoAuthResult, FederationError> {
        #[cfg(unix)]
        {
            if !self.config.allow_kerberos_authentication {
                return Err(FederationError::NotSupported);
            }
            let config = self.config.clone();
            let token = token.to_string();
            let result = tokio::task::spawn_blocking(move || -> Result<_, FederationError> {
                let mut auth = crate::kerberos::spnego::SpnegoAuthenticator::new(config)?;
                let result = auth.authenticate(&token)?;
                Ok(SpnegoAuthResult {
                    principal: auth.authenticated_principal().map(|s| s.to_string()),
                    response_token: auth.response_token().map(|s| s.to_string()),
                    status: match result {
                        crate::kerberos::spnego::SpnegoResult::Authenticated => {
                            issuerd_core::SpnegoStatus::Authenticated
                        }
                        crate::kerberos::spnego::SpnegoResult::Continue => {
                            issuerd_core::SpnegoStatus::Continue
                        }
                        crate::kerberos::spnego::SpnegoResult::Failed => {
                            issuerd_core::SpnegoStatus::Failed
                        }
                    },
                })
            })
            .await
            .map_err(|e| FederationError::NetworkError(e.to_string()))??;
            self.require_configured_realm(result)
        }
        #[cfg(not(unix))]
        {
            let _ = token;
            Err(FederationError::NotSupported)
        }
    }

    async fn stream_users(&self) -> Result<Vec<FederatedUser>, FederationError> {
        Err(FederationError::NotSupported)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use issuerd_core::SpnegoStatus;

    use super::*;

    fn test_config() -> KerberosConfig {
        KerberosConfig {
            kerberos_realm: "TEST.ISSUERD.LOCAL".to_string(),
            server_principal: "HTTP/issuerd.test.issuerd.local@TEST.ISSUERD.LOCAL".to_string(),
            keytab_path: "/dev/null".to_string(),
            allow_password_authentication: false,
            allow_kerberos_authentication: false,
            update_profile_first_login: true,
            debug: false,
        }
    }

    #[test]
    fn kerberos_provider_find_user() {
        let provider =
            KerberosFederationProvider::new("krb-test".to_string(), test_config()).unwrap();
        let user = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(provider.find_user("alice"))
            .unwrap()
            .unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.federation_link, "krb-test");
        assert!(user.enabled);
        assert_eq!(
            user.attributes.get("KERBEROS_PRINCIPAL"),
            Some(&vec!["alice@TEST.ISSUERD.LOCAL".to_string()])
        );
    }

    #[test]
    fn kerberos_provider_id_and_type() {
        let provider =
            KerberosFederationProvider::new("krb-test".to_string(), test_config()).unwrap();
        assert_eq!(provider.id(), "krb-test");
        assert_eq!(provider.provider_type(), FederationProviderType::Kerberos);
    }

    #[test]
    fn kerberos_provider_validate_password_disabled() {
        let provider =
            KerberosFederationProvider::new("krb-test".to_string(), test_config()).unwrap();
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(provider.validate_password("alice", "secret"))
            .unwrap_err();
        assert!(matches!(err, FederationError::NotSupported));
    }

    fn spnego_result(principal: Option<&str>, status: SpnegoStatus) -> SpnegoAuthResult {
        SpnegoAuthResult {
            principal: principal.map(str::to_string),
            response_token: Some("cmVzcA==".to_string()),
            status,
        }
    }

    fn provider_for_realm(realm: &str) -> KerberosFederationProvider {
        let mut config = test_config();
        config.kerberos_realm = realm.to_string();
        KerberosFederationProvider::new("krb-test".to_string(), config).unwrap()
    }

    #[test]
    fn kerberos_provider_accepts_principal_in_configured_realm() {
        let provider = provider_for_realm("EXAMPLE.COM");
        for principal in ["user@EXAMPLE.COM", "user@example.com"] {
            let result = provider
                .require_configured_realm(spnego_result(
                    Some(principal),
                    SpnegoStatus::Authenticated,
                ))
                .unwrap();
            assert_eq!(result.principal.as_deref(), Some(principal));
            assert_eq!(result.status, SpnegoStatus::Authenticated);
            assert_eq!(result.response_token.as_deref(), Some("cmVzcA=="));
        }
    }

    #[test]
    fn kerberos_provider_rejects_principal_outside_configured_realm() {
        let provider = provider_for_realm("EXAMPLE.COM");
        for principal in [
            "user@OTHER.COM",
            "user@PARTNER.EXAMPLE.COM",
            "user@EXAMPLE.COM.EVIL",
            "user@EXAMPLE.COM@PARTNER.CORP",
            "user\\@EXAMPLE.COM@PARTNER.CORP",
            "user",
            "user@",
        ] {
            let err = provider
                .require_configured_realm(spnego_result(
                    Some(principal),
                    SpnegoStatus::Authenticated,
                ))
                .unwrap_err();
            assert_eq!(err, FederationError::InvalidCredentials, "{principal}");
        }
    }

    #[test]
    fn kerberos_provider_without_realm_rejects_every_principal() {
        let provider = provider_for_realm("");
        for principal in ["user@EXAMPLE.COM", "user@", "user"] {
            let err = provider
                .require_configured_realm(spnego_result(
                    Some(principal),
                    SpnegoStatus::Authenticated,
                ))
                .unwrap_err();
            assert_eq!(err, FederationError::InvalidCredentials, "{principal}");
        }
    }

    #[test]
    fn kerberos_provider_passes_through_results_without_principal() {
        let provider = provider_for_realm("EXAMPLE.COM");
        let result = provider
            .require_configured_realm(spnego_result(None, SpnegoStatus::Continue))
            .unwrap();
        assert_eq!(result.status, SpnegoStatus::Continue);
        assert_eq!(result.response_token.as_deref(), Some("cmVzcA=="));
    }

    #[test]
    fn kerberos_provider_find_user_by_email_returns_none() {
        let provider =
            KerberosFederationProvider::new("krb-test".to_string(), test_config()).unwrap();
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(provider.find_user_by_email("alice@example.com"));
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn kerberos_provider_validate_password_enabled_returns_not_supported() {
        let mut config = test_config();
        config.allow_password_authentication = true;
        let provider = KerberosFederationProvider::new("krb-test".to_string(), config).unwrap();
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(provider.validate_password("alice", "secret"))
            .unwrap_err();
        assert!(matches!(err, FederationError::NotSupported));
    }

    #[test]
    fn kerberos_provider_update_password_returns_not_supported() {
        let provider =
            KerberosFederationProvider::new("krb-test".to_string(), test_config()).unwrap();
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(provider.update_password("alice", "new"))
            .unwrap_err();
        assert!(matches!(err, FederationError::NotSupported));
    }

    #[test]
    fn kerberos_provider_authenticate_spnego_not_supported_on_non_unix() {
        let provider =
            KerberosFederationProvider::new("krb-test".to_string(), test_config()).unwrap();
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(provider.authenticate_spnego("dG9rZW4="))
            .unwrap_err();
        assert!(matches!(err, FederationError::NotSupported));
    }

    #[test]
    fn kerberos_provider_stream_users_returns_not_supported() {
        let provider =
            KerberosFederationProvider::new("krb-test".to_string(), test_config()).unwrap();
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(provider.stream_users())
            .unwrap_err();
        assert!(matches!(err, FederationError::NotSupported));
    }
}
