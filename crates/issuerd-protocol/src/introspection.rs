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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    const NEAR_MISS_KEYS: &[&str] = &[
        "Token", "TOKEN", "token ", " token", "token\0", "tokens",
        "access_token", "refresh_token", "Token_Type_Hint", "token_type_hint ",
    ];

    fn extra_fields() -> impl Strategy<Value = HashMap<String, String>> {
        let key = prop_oneof![
            prop::sample::select(NEAR_MISS_KEYS).prop_map(str::to_string),
            any::<String>(),
        ]
        // prevent the possiblity og any::<String>() generating "token"
        .prop_filter("not a real parameter", |k| k != "token" && k != "token_type_hint");

        prop::collection::hash_map(key, any::<String>(), 0..8)
    }

    /// Both parsers' output in one comparable shape. The request structs don't
    /// derive `PartialEq`, so they're reduced to `(token, hint)` here.
    type Parsed = Result<(String, Option<TokenTypeHint>), IssuerdError>;

    /// Runs the identical introspection and revocation parsers on the same body,
    /// so every property checks both.
    fn parse_both(body: &HashMap<String, String>) -> [Parsed; 2] {
        [
            IntrospectionRequest::parse(body).map(|r| (r.token, r.token_type_hint)),
            RevocationRequest::parse(body).map(|r| (r.token, r.token_type_hint)),
        ]
    }

    proptest! {
        #[test]
        fn missing_token_is_rejected(extras in extra_fields()) {
            let body = extras;

            for result in parse_both(&body) {
                let err = result.expect_err("a body without `token` must not parse");
                prop_assert_eq!(err, IssuerdError::InvalidRequest("missing token".into()));
            }
        }
    }
}
