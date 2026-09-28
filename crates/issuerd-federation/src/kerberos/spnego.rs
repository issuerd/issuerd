// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// SPNEGO / GSSAPI acceptor for Kerberos authentication.

use issuerd_core::FederationError;

use crate::kerberos::config::KerberosConfig;

/// Result of a single SPNEGO step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpnegoResult {
    Authenticated,
    Continue,
    Failed,
}

/// SPNEGO / GSSAPI acceptor for Kerberos authentication.
pub struct SpnegoAuthenticator {
    config: KerberosConfig,
    server_ctx: Option<libgssapi::context::ServerCtx>,
    response_token: Option<String>,
    authenticated_principal: Option<String>,
}

impl SpnegoAuthenticator {
    pub fn new(config: KerberosConfig) -> Result<Self, FederationError> {
        if !std::path::Path::new(&config.keytab_path).is_file() {
            return Err(FederationError::ConfigError(format!(
                "keytab not found: {}",
                config.keytab_path
            )));
        }
        Ok(Self {
            config,
            server_ctx: None,
            response_token: None,
            authenticated_principal: None,
        })
    }

    pub fn authenticate(&mut self, token: &str) -> Result<SpnegoResult, FederationError> {
        use base64::Engine;
        use libgssapi::context::SecurityContext;

        let input = base64::engine::general_purpose::STANDARD
            .decode(token)
            .map_err(|_| FederationError::InvalidCredentials)?;

        let mut ctx = if let Some(ctx) = self.server_ctx.take() {
            ctx
        } else {
            let name = libgssapi::name::Name::new(
                self.config.server_principal.as_bytes(),
                Some(libgssapi::oid::GSS_NT_HOSTBASED_SERVICE),
            )
            .map_err(|e| FederationError::NetworkError(e.to_string()))?;
            let cname = name
                .canonicalize(Some(libgssapi::oid::GSS_MECH_SPNEGO))
                .map_err(|e| FederationError::NetworkError(e.to_string()))?;
            let cred = libgssapi::credential::Cred::acquire(
                Some(&cname),
                None,
                libgssapi::credential::CredUsage::Accept,
                None,
            )
            .map_err(|e| FederationError::NetworkError(e.to_string()))?;
            libgssapi::context::ServerCtx::new(Some(cred))
        };

        match ctx.step(&input, None) {
            Ok(Some(output)) => {
                self.response_token =
                    Some(base64::engine::general_purpose::STANDARD.encode(&*output));
                if ctx.is_complete() {
                    let src = ctx
                        .source_name()
                        .map_err(|e| FederationError::NetworkError(e.to_string()))?;
                    self.authenticated_principal = Some(src.to_string());
                    self.server_ctx = Some(ctx);
                    Ok(SpnegoResult::Authenticated)
                } else {
                    self.server_ctx = Some(ctx);
                    Ok(SpnegoResult::Continue)
                }
            }
            Ok(None) => {
                if ctx.is_complete() {
                    let src = ctx
                        .source_name()
                        .map_err(|e| FederationError::NetworkError(e.to_string()))?;
                    self.authenticated_principal = Some(src.to_string());
                    self.server_ctx = Some(ctx);
                    Ok(SpnegoResult::Authenticated)
                } else {
                    self.server_ctx = Some(ctx);
                    Ok(SpnegoResult::Continue)
                }
            }
            Err(_) => {
                self.server_ctx = Some(ctx);
                Err(FederationError::InvalidCredentials)
            }
        }
    }

    pub fn authenticated_principal(&self) -> Option<&str> {
        self.authenticated_principal.as_deref()
    }

    pub fn response_token(&self) -> Option<&str> {
        self.response_token.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> KerberosConfig {
        KerberosConfig {
            kerberos_realm: "TEST.ISSUERD.LOCAL".to_string(),
            server_principal: "HTTP/issuerd.test.issuerd.local@TEST.ISSUERD.LOCAL".to_string(),
            // Any existing regular file satisfies the keytab presence check.
            keytab_path: concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml").to_string(),
            allow_password_authentication: false,
            allow_kerberos_authentication: true,
            update_profile_first_login: true,
            debug: false,
        }
    }

    #[test]
    fn fresh_authenticator_has_no_principal_or_response_token() {
        let auth = SpnegoAuthenticator::new(test_config()).unwrap();
        assert_eq!(auth.authenticated_principal(), None);
        assert_eq!(auth.response_token(), None);
    }

    #[test]
    fn new_rejects_missing_keytab() {
        let mut config = test_config();
        config.keytab_path = "/nonexistent/issuerd.keytab".to_string();
        assert!(matches!(SpnegoAuthenticator::new(config), Err(FederationError::ConfigError(_))));
    }
}
