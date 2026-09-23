// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Token introspection and revocation request parsing (RFC 7662 / RFC 7009).

use std::collections::HashMap;

use issuerd_core::{IssuerdError, TokenTypeHint};

#[derive(Debug, Clone)]
pub struct IntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<TokenTypeHint>,
}

impl IntrospectionRequest {
    pub fn parse(body: &HashMap<String, String>) -> Result<Self, IssuerdError> {
        let token = body
            .get("token")
            .ok_or_else(|| IssuerdError::InvalidRequest("missing token".into()))?
            .clone();

        let token_type_hint = body
            .get("token_type_hint")
            .map(|s| {
                serde_json::from_value(serde_json::Value::String(s.clone())).map_err(|e| {
                    IssuerdError::InvalidRequest(format!("invalid token_type_hint: {e}"))
                })
            })
            .transpose()?;

        Ok(Self {
            token,
            token_type_hint,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RevocationRequest {
    pub token: String,
    pub token_type_hint: Option<TokenTypeHint>,
}

impl RevocationRequest {
    pub fn parse(body: &HashMap<String, String>) -> Result<Self, IssuerdError> {
        let token = body
            .get("token")
            .ok_or_else(|| IssuerdError::InvalidRequest("missing token".into()))?
            .clone();

        let token_type_hint = body
            .get("token_type_hint")
            .map(|s| {
                serde_json::from_value(serde_json::Value::String(s.clone())).map_err(|e| {
                    IssuerdError::InvalidRequest(format!("invalid token_type_hint: {e}"))
                })
            })
            .transpose()?;

        Ok(Self {
            token,
            token_type_hint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn introspection_parse_valid() {
        let mut body = HashMap::new();
        body.insert("token".to_string(), "abc123".to_string());
        let req = IntrospectionRequest::parse(&body).unwrap();
        assert_eq!(req.token, "abc123");
        assert_eq!(req.token_type_hint, None);
    }

    #[test]
    fn introspection_parse_with_access_token_hint() {
        let mut body = HashMap::new();
        body.insert("token".to_string(), "abc123".to_string());
        body.insert("token_type_hint".to_string(), "access_token".to_string());
        let req = IntrospectionRequest::parse(&body).unwrap();
        assert_eq!(req.token_type_hint, Some(TokenTypeHint::AccessToken));
    }

    #[test]
    fn introspection_parse_with_refresh_token_hint() {
        let mut body = HashMap::new();
        body.insert("token".to_string(), "abc123".to_string());
        body.insert("token_type_hint".to_string(), "refresh_token".to_string());
        let req = IntrospectionRequest::parse(&body).unwrap();
        assert_eq!(req.token_type_hint, Some(TokenTypeHint::RefreshToken));
    }

    #[test]
    fn introspection_parse_invalid_hint() {
        let mut body = HashMap::new();
        body.insert("token".to_string(), "abc123".to_string());
        body.insert("token_type_hint".to_string(), "id_token".to_string());
        assert!(IntrospectionRequest::parse(&body).is_err());
    }

    #[test]
    fn introspection_parse_missing_token() {
        let body = HashMap::new();
        assert!(IntrospectionRequest::parse(&body).is_err());
    }

    #[test]
    fn revocation_parse_valid() {
        let mut body = HashMap::new();
        body.insert("token".to_string(), "abc123".to_string());
        let req = RevocationRequest::parse(&body).unwrap();
        assert_eq!(req.token, "abc123");
    }

    #[test]
    fn revocation_parse_missing_token() {
        let body = HashMap::new();
        assert!(RevocationRequest::parse(&body).is_err());
    }

    #[test]
    fn revocation_parse_invalid_hint() {
        let mut body = HashMap::new();
        body.insert("token".to_string(), "abc123".to_string());
        body.insert("token_type_hint".to_string(), "unknown".to_string());
        assert!(RevocationRequest::parse(&body).is_err());
    }
}
