// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// CIBA backchannel authentication request parsing (OpenID Connect CIBA Core).

use std::collections::HashMap;

use issuerd_core::{IssuerdError, Scope};

use crate::utils::{parse_opt_u64, parse_scope, parse_space_separated};

#[derive(Debug, Clone)]
pub struct CibaRequest {
    pub scope: Scope,
    pub client_notification_token: Option<String>,
    pub acr_values: Vec<String>,
    pub login_hint_token: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub binding_message: Option<String>,
    pub user_code: Option<String>,
    pub requested_expiry: Option<u64>,
    /// Reserved for the validated operation-bound CIBA profile.
    pub operation_id: Option<String>,
    /// Reserved for the same operation-bound profile, never generic CIBA
    /// resource issuance.
    pub resource: Option<String>,
}

impl CibaRequest {
    /// Parse and validate a CIBA form body.
    ///
    /// # Examples
    ///
    /// ```
    /// use issuerd_core::IssuerdError;
    /// use issuerd_protocol::ciba::CibaRequest;
    /// use std::collections::HashMap;
    ///
    /// let body = HashMap::from([
    ///     ("login_hint".into(), "user@example.com".into()),
    ///     ("scope".into(), "openid profile".into()),
    /// ]);
    /// let request = CibaRequest::parse(&body)?;
    /// assert_eq!(request.login_hint.as_deref(), Some("user@example.com"));
    /// assert!(request.scope.contains("profile"));
    ///
    /// let error = CibaRequest::parse(&HashMap::new()).unwrap_err();
    /// assert_eq!(
    ///     error,
    ///     IssuerdError::InvalidRequest("exactly one hint must be provided".into())
    /// );
    /// # Ok::<(), IssuerdError>(())
    /// ```
    pub fn parse(body: &HashMap<String, String>) -> Result<Self, IssuerdError> {
        let scope = parse_scope(body.get("scope"));

        let login_hint = body.get("login_hint").cloned();
        let login_hint_token = body.get("login_hint_token").cloned();
        let id_token_hint = body.get("id_token_hint").cloned();

        let requested_expiry = parse_opt_u64(body, "requested_expiry")?;

        let req = Self {
            scope,
            client_notification_token: body.get("client_notification_token").cloned(),
            acr_values: parse_space_separated(body.get("acr_values")),
            login_hint_token,
            id_token_hint,
            login_hint,
            binding_message: body.get("binding_message").cloned(),
            user_code: body.get("user_code").cloned(),
            requested_expiry,
            operation_id: body.get("operation_id").cloned(),
            resource: body.get("resource").cloned(),
        };

        req.validate()?;
        Ok(req)
    }

    pub fn validate(&self) -> Result<(), IssuerdError> {
        let hints = usize::from(self.login_hint.is_some())
            + usize::from(self.login_hint_token.is_some())
            + usize::from(self.id_token_hint.is_some());
        if hints != 1 {
            return Err(IssuerdError::InvalidRequest("exactly one hint must be provided".into()));
        }

        if let Some(binding_message) = &self.binding_message {
            if binding_message.is_empty()
                || binding_message.chars().count() > 100
                || binding_message.chars().any(char::is_control)
                || binding_message.trim() != binding_message
            {
                return Err(IssuerdError::InvalidBindingMessage(
                    "binding_message must be 1..=100 Unicode scalar values of plain text without controls".into(),
                ));
            }
        }

        if self.operation_id.is_some()
            && (self.scope.len() != 2
                || !self.scope.contains("openid")
                || !self.scope.contains(issuerd_core::MCP_SCOPE_STEP_UP))
        {
            return Err(IssuerdError::InvalidScope);
        }
        if let Some(requested_expiry) = self.requested_expiry {
            if requested_expiry == 0 {
                return Err(IssuerdError::InvalidRequest("requested_expiry must be > 0".into()));
            }
        }

        Ok(())
    }

    /// Scope rule for a validated operation-bound request. Ordinary CIBA uses
    /// `validate_scope_with_mcp`, which deliberately rejects this scope.
    pub fn validate_step_up_scope(
        &self,
        client: &issuerd_core::Client,
    ) -> Result<(), IssuerdError> {
        if client.public_client
            || client.default_scopes.contains(issuerd_core::MCP_SCOPE_STEP_UP)
            || !client.optional_scopes.contains(issuerd_core::MCP_SCOPE_STEP_UP)
        {
            return Err(IssuerdError::UnauthorizedClient);
        }
        Ok(())
    }

    /// RFC 6749 §3.3: every requested scope must be assigned to the client
    /// (same rule as the authorization and token endpoints) — otherwise a
    /// client could pick up scopes such as `offline_access` that the admin
    /// deliberately left unassigned. Separate from `validate` because the
    /// client is only known to the handler, not to `parse`.
    pub fn validate_scope(&self, client: &issuerd_core::Client) -> Result<(), IssuerdError> {
        self.validate_scope_with_mcp(client, false)
    }

    pub fn validate_scope_with_mcp(
        &self,
        client: &issuerd_core::Client,
        mcp_enabled: bool,
    ) -> Result<(), IssuerdError> {
        if self.scope.iter().any(|scope| {
            !issuerd_core::client_scope_request_permitted_with_mcp(client, scope, mcp_enabled)
        }) {
            return Err(IssuerdError::InvalidScope);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciba_parse_with_login_hint() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("scope".to_string(), "openid".to_string());

        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.login_hint, Some("user@example.com".to_string()));
    }

    #[test]
    fn ciba_parse_with_login_hint_token() {
        let mut body = HashMap::new();
        body.insert("login_hint_token".to_string(), "jwt_token".to_string());
        body.insert("scope".to_string(), "openid".to_string());

        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.login_hint_token, Some("jwt_token".to_string()));
    }

    #[test]
    fn ciba_parse_with_id_token_hint() {
        let mut body = HashMap::new();
        body.insert("id_token_hint".to_string(), "id_jwt".to_string());
        body.insert("scope".to_string(), "openid".to_string());

        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.id_token_hint, Some("id_jwt".to_string()));
    }

    #[test]
    fn ciba_parse_with_multiple_hints() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("scope".to_string(), "openid".to_string());
        body.insert("id_token_hint".to_string(), "id_jwt".to_string());
        body.insert("scope".to_string(), "openid profile".to_string());
        body.insert("acr_values".to_string(), "1 2".to_string());

        assert!(CibaRequest::parse(&body).is_err());
    }

    #[test]
    fn ciba_parse_missing_all_hints() {
        let body = HashMap::new();
        assert!(CibaRequest::parse(&body).is_err());
    }

    #[test]
    fn ciba_binding_message_too_long() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("scope".to_string(), "openid".to_string());
        body.insert("binding_message".to_string(), "a".repeat(101));

        assert!(CibaRequest::parse(&body).is_err());
    }

    #[test]
    fn ciba_binding_message_exactly_100() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("scope".to_string(), "openid".to_string());
        body.insert("binding_message".to_string(), "a".repeat(100));

        assert!(CibaRequest::parse(&body).is_ok());
    }

    #[test]
    fn ciba_requested_expiry_zero() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("scope".to_string(), "openid".to_string());
        body.insert("requested_expiry".to_string(), "0".to_string());

        assert!(CibaRequest::parse(&body).is_err());
    }

    #[test]
    fn ciba_requested_expiry_malformed() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("scope".to_string(), "openid".to_string());
        body.insert("requested_expiry".to_string(), "abc".to_string());

        assert!(CibaRequest::parse(&body).is_err());
    }

    #[test]
    fn ciba_requested_expiry_valid() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("scope".to_string(), "openid".to_string());
        body.insert("requested_expiry".to_string(), "3600".to_string());

        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.requested_expiry, Some(3600));
    }

    #[test]
    fn operation_fields_are_captured_for_server_side_profile_validation() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("scope".to_string(), "openid mcp:step_up".to_string());
        body.insert("operation_id".to_string(), "op-1".to_string());
        body.insert(
            "resource".to_string(),
            "https://issuer.example.com/realms/demo/mcp".to_string(),
        );
        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.operation_id.as_deref(), Some("op-1"));
        assert_eq!(req.resource.as_deref(), Some("https://issuer.example.com/realms/demo/mcp"));

        body.insert("scope".to_string(), "openid".to_string());
        assert_eq!(CibaRequest::parse(&body).unwrap_err(), IssuerdError::InvalidScope);
    }

    #[test]
    fn openid_is_required_only_for_operation_bound_requests() {
        let mut legacy = HashMap::new();
        legacy.insert("login_hint".to_string(), "user@example.com".to_string());
        legacy.insert("scope".to_string(), "mcp:read".to_string());
        assert!(CibaRequest::parse(&legacy).is_ok());

        legacy.insert("operation_id".to_string(), "op-1".to_string());
        assert_eq!(CibaRequest::parse(&legacy).unwrap_err(), IssuerdError::InvalidScope);
    }

    fn make_test_client() -> issuerd_core::Client {
        issuerd_core::Client {
            id: issuerd_core::ClientId::new("client-1").unwrap(),
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            client_id: issuerd_core::ClientIdentifier::new("client1").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: issuerd_core::ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn ciba_validate_scope_availability() {
        let client = make_test_client();
        let parse = |scope: &str| {
            let mut body = HashMap::new();
            body.insert("login_hint".to_string(), "user@example.com".to_string());
            body.insert("scope".to_string(), "openid".to_string());
            body.insert("scope".to_string(), scope.to_string());
            CibaRequest::parse(&body).unwrap()
        };

        // RFC 6749 §3.3: a scope assigned to the client is accepted.
        assert!(parse("openid").validate_scope(&client).is_ok());

        // A scope the client does not have assigned is rejected.
        assert!(matches!(
            parse("openid admin").validate_scope(&client),
            Err(IssuerdError::InvalidScope)
        ));

        let mut legacy = client;
        legacy.default_scopes = Scope::parse(issuerd_core::MCP_SCOPE_STEP_UP);
        legacy.optional_scopes = Scope::parse(issuerd_core::MCP_SCOPE_STEP_UP);
        for mcp_enabled in [false, true] {
            assert!(matches!(
                parse(&format!("openid {}", issuerd_core::MCP_SCOPE_STEP_UP))
                    .validate_scope_with_mcp(&legacy, mcp_enabled),
                Err(IssuerdError::InvalidScope)
            ));
        }
    }
}
