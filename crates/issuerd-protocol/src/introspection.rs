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

/// Property-based tests for the RFC 7662 introspection and RFC 7009
/// revocation form parsers.
///
/// Both parsers are identical, so every property runs against both through
/// `parse_both` and also pins that they agree. The generators lean
/// adversarial: empty, whitespace-only, over-long (4–16 KiB), non-ASCII and
/// control-character values; near-miss keys (`Token`, `token `, `token\0`)
/// and near-miss hints (`Access_Token`, `access_token `, `id_token`, `""`).
///
/// Deliberate behavior pinned here: the token is opaque. Any value, including
/// empty or whitespace, is accepted and returned byte-for-byte; an unknown
/// token yields `active: false` (RFC 7662 §2.2) or a 200 (RFC 7009 §2.2)
/// downstream, not a 400. Only a missing `token` key or a `token_type_hint`
/// outside the two registered values is rejected, always as `invalid_request`.
#[cfg(test)]
mod proptests {
    use super::*;
    use issuerd_core::OAuth2ErrorCode;
    use proptest::prelude::*;

    /// The two registered hint values and the variants they must parse to.
    const VALID_HINTS: &[(&str, TokenTypeHint)] = &[
        ("access_token", TokenTypeHint::AccessToken),
        ("refresh_token", TokenTypeHint::RefreshToken),
    ];

    /// Hints that look valid but must be rejected.
    const NEAR_MISS_HINTS: &[&str] = &[
        "Access_Token",
        "ACCESS_TOKEN",
        "access_token ",
        " access_token",
        "access-token",
        "accesstoken",
        "access_token\0",
        "\"access_token\"",
        "refresh_token\n",
        "id_token",
        "token",
        "",
    ];

    /// Keys that look like the real parameters but must not be read as them.
    const NEAR_MISS_KEYS: &[&str] = &[
        "Token",
        "TOKEN",
        "token ",
        " token",
        "token\0",
        "tokens",
        "access_token",
        "refresh_token",
        "Token_Type_Hint",
        "token_type_hint ",
    ];

    /// Any Unicode text of 0–64 chars. `any::<String>()` excludes control
    /// characters (`\PC*`), so this builds from `any::<char>()` instead.
    fn arbitrary_text() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<char>(), 0..64).prop_map(|c| c.into_iter().collect())
    }

    /// Token values the parsers must accept and return unchanged. Empty comes
    /// first so failures shrink toward it; long values repeat a short seed
    /// (4–16 KiB) so they shrink quickly instead of char by char.
    fn token_value() -> impl Strategy<Value = String> {
        prop_oneof![
            1 => Just(String::new()),
            3 => "[A-Za-z0-9_-]{1,64}\\.[A-Za-z0-9_-]{1,64}\\.[A-Za-z0-9_-]{0,86}",
            1 => "[ \t\r\n]{1,8}",
            1 => "[\\x00-\\x1F\\x7F]{1,16}",
            1 => ("[A-Za-z0-9]{16}", 256..1024usize).prop_map(|(seed, n)| seed.repeat(n)),
            3 => arbitrary_text(),
        ]
    }

    /// An absent or registered hint, paired with the variant it parses to.
    fn valid_hint() -> impl Strategy<Value = Option<(&'static str, TokenTypeHint)>> {
        proptest::option::of(prop::sample::select(VALID_HINTS))
    }

    /// A present hint that must be rejected.
    fn invalid_hint() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(NEAR_MISS_HINTS).prop_map(str::to_string),
            arbitrary_text(),
        ]
        .prop_filter("not a registered hint", |h| !VALID_HINTS.iter().any(|(valid, _)| valid == h))
    }

    /// Any hint a client might send: absent, valid, near-miss, or garbage.
    fn any_hint() -> impl Strategy<Value = Option<String>> {
        proptest::option::of(prop_oneof![
            prop::sample::select(VALID_HINTS).prop_map(|(h, _)| h.to_string()),
            invalid_hint(),
        ])
    }

    /// Unknown form fields, including near-miss keys.
    fn extra_fields() -> impl Strategy<Value = HashMap<String, String>> {
        let key = prop_oneof![
            prop::sample::select(NEAR_MISS_KEYS).prop_map(str::to_string),
            arbitrary_text(),
        ]
        // `arbitrary_text()` could otherwise generate a real parameter name.
        .prop_filter("not a real parameter", |k| k != "token" && k != "token_type_hint");

        prop::collection::hash_map(key, arbitrary_text(), 0..8)
    }

    /// A fully arbitrary form body whose keys and values sometimes hit the
    /// real parameter names and hint values.
    fn arbitrary_body() -> impl Strategy<Value = HashMap<String, String>> {
        let key = prop_oneof![
            Just("token".to_string()),
            Just("token_type_hint".to_string()),
            prop::sample::select(NEAR_MISS_KEYS).prop_map(str::to_string),
            arbitrary_text(),
        ];
        let value = prop_oneof![
            prop::sample::select(VALID_HINTS).prop_map(|(h, _)| h.to_string()),
            prop::sample::select(NEAR_MISS_HINTS).prop_map(str::to_string),
            token_value(),
        ];
        prop::collection::hash_map(key, value, 0..6)
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

    fn is_invalid_hint_error(err: &IssuerdError) -> bool {
        matches!(err, IssuerdError::InvalidRequest(m) if m.starts_with("invalid token_type_hint"))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Well-formed body → `Ok`, the token comes back byte-for-byte, the
        /// hint parses to its variant and serializes back to the sent string,
        /// and unknown fields have no effect.
        #[test]
        fn well_formed_body_parses_and_roundtrips(
            token in token_value(),
            hint in valid_hint(),
            extras in extra_fields(),
        ) {
            let mut body = extras;
            body.insert("token".to_string(), token.clone());
            if let Some((raw, _)) = hint {
                body.insert("token_type_hint".to_string(), raw.to_string());
            }

            for result in parse_both(&body) {
                let (parsed_token, parsed_hint) =
                    result.expect("a body with a token and a valid hint must parse");
                prop_assert_eq!(&parsed_token, &token);
                prop_assert_eq!(parsed_hint, hint.map(|(_, variant)| variant));
                if let (Some(variant), Some((raw, _))) = (parsed_hint, hint) {
                    prop_assert_eq!(
                        serde_json::to_value(variant).expect("hint serializes"),
                        serde_json::Value::String(raw.to_string())
                    );
                }
            }
        }

        /// Missing token → `invalid_request: missing token`, whatever
        /// else the body carries: near-miss keys, junk fields, or any hint
        /// value (the token check runs before hint parsing).
        #[test]
        fn missing_token_is_rejected(
            hint in any_hint(),
            extras in extra_fields(),
        ) {
            let mut body = extras;
            if let Some(hint) = hint {
                body.insert("token_type_hint".to_string(), hint);
            }
            // No "token" key is ever inserted — that is the property.

            for result in parse_both(&body) {
                let err = result.expect_err("a body without `token` must not parse");
                prop_assert_eq!(err.oauth_error_code(), OAuth2ErrorCode::InvalidRequest);
                prop_assert_eq!(err.http_status(), 400);
                prop_assert_eq!(err, IssuerdError::InvalidRequest("missing token".into()));
            }
        }

        /// Token present + a hint outside the two registered values →
        /// `invalid_request: invalid token_type_hint`, whatever the token.
        #[test]
        fn invalid_hint_is_rejected(
            token in token_value(),
            hint in invalid_hint(),
            extras in extra_fields(),
        ) {
            let mut body = extras;
            body.insert("token".to_string(), token);
            body.insert("token_type_hint".to_string(), hint);

            for result in parse_both(&body) {
                let err = result.expect_err("an unregistered hint must be rejected");
                prop_assert_eq!(err.oauth_error_code(), OAuth2ErrorCode::InvalidRequest);
                prop_assert_eq!(err.http_status(), 400);
                prop_assert!(is_invalid_hint_error(&err), "expected the hint message, got {err:?}");
            }
        }

        /// Any body at all → no panic, both parsers agree, and the outcome is
        /// exactly one of: `Ok` echoing the `token` value, `missing token`, or
        /// `invalid token_type_hint`.
        #[test]
        fn arbitrary_body_never_panics_and_parsers_agree(body in arbitrary_body()) {
            let [introspection, revocation] = parse_both(&body);
            prop_assert_eq!(&introspection, &revocation);

            match introspection {
                Ok((token, _)) => prop_assert_eq!(Some(&token), body.get("token")),
                Err(err) if !body.contains_key("token") => {
                    prop_assert_eq!(err, IssuerdError::InvalidRequest("missing token".into()));
                }
                Err(err) => {
                    prop_assert!(is_invalid_hint_error(&err), "unexpected error {err:?}");
                }
            }
        }
    }
}
