// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// RFC 8707 Resource Indicators for OAuth 2.0: `resource` parameter
// structural validation.

use issuerd_core::IssuerdError;

/// Parse and structurally validate an RFC 8707 `resource` parameter value.
///
/// §2: the value MUST be an absolute URI and MUST NOT include a fragment
/// component (a query component is allowed). This is a pure shape check —
/// whether the resource is recognized at all is the server's allowlist
/// decision (§2.1, same `invalid_target` error code). The validated value is
/// returned unchanged: no normalization, so the downstream allowlist
/// comparison stays an exact string match.
///
/// `None` (parameter absent) passes through as `None`. A present-but-empty
/// value is rejected rather than silently dropped: an empty string is not an
/// absolute URI, and ignoring it would let a client believe a resource was
/// requested when none was honored.
pub fn parse_resource_indicator(raw: Option<&String>) -> Result<Option<String>, IssuerdError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let parsed = url::Url::parse(raw)
        .map_err(|_| IssuerdError::InvalidTarget("resource must be an absolute URI".into()))?;
    if parsed.fragment().is_some() {
        return Err(IssuerdError::InvalidTarget("resource must not contain a fragment".into()));
    }
    Ok(Some(raw.clone()))
}

/// Count `resource` occurrences in an URL-encoded query or form body before
/// deserialization can collapse repeated keys.
pub fn resource_parameter_count(encoded: &str) -> usize {
    url::form_urlencoded::parse(encoded.as_bytes())
        .filter(|(name, _)| name == "resource")
        .count()
}

/// Enforce this server's single-resource profile (RFC 8707 §2).
pub fn validate_resource_parameter_count(count: usize) -> Result<(), IssuerdError> {
    if count > 1 {
        return Err(IssuerdError::InvalidTarget("resource must appear at most once".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("https://issuer.example.com/realms/demo/mcp")]
    // A query component is allowed (§2).
    #[case("https://api.example.com/resource?query=1")]
    // Non-hierarchical absolute URIs are valid; the allowlist decides.
    #[case("urn:example:resource")]
    fn valid_resource_indicators(#[case] raw: &str) {
        let parsed = parse_resource_indicator(Some(&raw.to_string())).unwrap();
        assert_eq!(parsed.as_deref(), Some(raw));
    }

    #[test]
    fn absent_resource_is_none() {
        assert_eq!(parse_resource_indicator(None).unwrap(), None);
    }

    #[test]
    fn repeated_resource_parameters_are_counted_and_rejected() {
        for encoded in [
            "resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example",
            "resource=https%3A%2F%2Fa.example&x=1&resource=https%3A%2F%2Fa.example",
        ] {
            assert_eq!(resource_parameter_count(encoded), 2);
            assert!(matches!(
                validate_resource_parameter_count(resource_parameter_count(encoded)),
                Err(IssuerdError::InvalidTarget(_))
            ));
        }
        assert_eq!(resource_parameter_count("resource=https%3A%2F%2Fa.example"), 1);
        assert!(validate_resource_parameter_count(0).is_ok());
        assert!(validate_resource_parameter_count(1).is_ok());
    }

    #[rstest]
    // No scheme — not absolute.
    #[case("not-a-uri")]
    // Relative reference.
    #[case("/relative/path")]
    // Fragment components are forbidden (§2) — even an empty one.
    #[case("https://example.com/mcp#frag")]
    #[case("https://example.com/mcp#")]
    // An empty value is not an absolute URI.
    #[case("")]
    fn invalid_resource_indicators(#[case] raw: &str) {
        let err = parse_resource_indicator(Some(&raw.to_string())).unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidTarget(_)), "got {err}");
        assert_eq!(err.oauth_error_code().as_ref(), "invalid_target");
        assert_eq!(err.http_status(), 400);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Arbitrary values never panic; anything `url::Url` rejects or
            /// that carries a fragment is an `invalid_target` error
            /// (RFC 8707 §2); accepted values pass through unchanged.
            #[test]
            fn parse_never_panics_and_rejects_fragments(raw in any::<String>()) {
                match parse_resource_indicator(Some(&raw)) {
                    Ok(parsed) => {
                        let parsed = parsed.expect("present input yields present output");
                        prop_assert_eq!(&parsed, &raw);
                        let url = url::Url::parse(&raw).expect("accepted input is a URL");
                        prop_assert!(url.fragment().is_none());
                    }
                    Err(err) => {
                        prop_assert!(matches!(err, IssuerdError::InvalidTarget(_)));
                    }
                }
            }
        }
    }
}
