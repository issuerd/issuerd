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
}

impl CibaRequest {
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
        };

        req.validate()?;
        Ok(req)
    }

    pub fn validate(&self) -> Result<(), IssuerdError> {
        if self.login_hint.is_none()
            && self.login_hint_token.is_none()
            && self.id_token_hint.is_none()
        {
            return Err(IssuerdError::InvalidRequest("at least one hint must be provided".into()));
        }

        if let Some(binding_message) = &self.binding_message {
            if binding_message.len() > 100 {
                return Err(IssuerdError::InvalidRequest(
                    "binding_message must be <= 100 characters".into(),
                ));
            }
        }

        if let Some(requested_expiry) = self.requested_expiry {
            if requested_expiry == 0 {
                return Err(IssuerdError::InvalidRequest("requested_expiry must be > 0".into()));
            }
        }

        Ok(())
    }

    /// RFC 6749 §3.3: every requested scope must be assigned to the client
    /// (same rule as the authorization and token endpoints) — otherwise a
    /// client could pick up scopes such as `offline_access` that the admin
    /// deliberately left unassigned. Separate from `validate` because the
    /// client is only known to the handler, not to `parse`.
    pub fn validate_scope(&self, client: &issuerd_core::Client) -> Result<(), IssuerdError> {
        let available: std::collections::HashSet<&str> = client
            .default_scopes
            .iter()
            .chain(client.optional_scopes.iter())
            .map(String::as_str)
            .collect();
        if self.scope.iter().any(|s| !available.contains(s.as_str())) {
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

        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.login_hint, Some("user@example.com".to_string()));
    }

    #[test]
    fn ciba_parse_with_login_hint_token() {
        let mut body = HashMap::new();
        body.insert("login_hint_token".to_string(), "jwt_token".to_string());

        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.login_hint_token, Some("jwt_token".to_string()));
    }

    #[test]
    fn ciba_parse_with_id_token_hint() {
        let mut body = HashMap::new();
        body.insert("id_token_hint".to_string(), "id_jwt".to_string());

        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.id_token_hint, Some("id_jwt".to_string()));
    }

    #[test]
    fn ciba_parse_with_multiple_hints() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("id_token_hint".to_string(), "id_jwt".to_string());
        body.insert("scope".to_string(), "openid profile".to_string());
        body.insert("acr_values".to_string(), "1 2".to_string());

        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.scope, Scope::parse("openid profile"));
        assert_eq!(req.acr_values, vec!["1", "2"]);
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
        body.insert("binding_message".to_string(), "a".repeat(101));

        assert!(CibaRequest::parse(&body).is_err());
    }

    #[test]
    fn ciba_binding_message_exactly_100() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("binding_message".to_string(), "a".repeat(100));

        assert!(CibaRequest::parse(&body).is_ok());
    }

    #[test]
    fn ciba_requested_expiry_zero() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("requested_expiry".to_string(), "0".to_string());

        assert!(CibaRequest::parse(&body).is_err());
    }

    #[test]
    fn ciba_requested_expiry_malformed() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("requested_expiry".to_string(), "abc".to_string());

        assert!(CibaRequest::parse(&body).is_err());
    }

    #[test]
    fn ciba_requested_expiry_valid() {
        let mut body = HashMap::new();
        body.insert("login_hint".to_string(), "user@example.com".to_string());
        body.insert("requested_expiry".to_string(), "3600".to_string());

        let req = CibaRequest::parse(&body).unwrap();
        assert_eq!(req.requested_expiry, Some(3600));
    }
}
