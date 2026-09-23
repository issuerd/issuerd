// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Shared query/form parameter parsing helpers for the protocol endpoints.

use std::collections::HashMap;

use issuerd_core::{IssuerdError, Scope};

/// Parse an optional space-separated scope string into a normalized `Scope`.
pub fn parse_scope(input: Option<&String>) -> Scope {
    input.map(|s| Scope::parse(s)).unwrap_or_default()
}

/// Parse an optional space-separated string into a deduplicated, filtered Vec.
pub fn parse_space_separated(input: Option<&String>) -> Vec<String> {
    input
        .map(|s| {
            let mut seen = std::collections::HashSet::new();
            s.split_whitespace()
                .map(|v| v.to_string())
                .filter(|v| seen.insert(v.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Parse an optional u64 from query parameters, returning an error on malformed values.
pub fn parse_opt_u64(
    params: &HashMap<String, String>,
    key: &str,
) -> Result<Option<u64>, IssuerdError> {
    match params.get(key) {
        Some(v) => v.parse::<u64>().map(Some).map_err(|_| {
            IssuerdError::InvalidRequest(format!("invalid numeric value for {}", key))
        }),
        None => Ok(None),
    }
}

/// Parse a required URL from query parameters.
pub fn parse_required_url(
    params: &HashMap<String, String>,
    key: &str,
) -> Result<url::Url, IssuerdError> {
    params
        .get(key)
        .ok_or_else(|| IssuerdError::InvalidRequest(format!("missing {}", key)))?
        .parse::<url::Url>()
        .map_err(|_| IssuerdError::InvalidRequest(format!("invalid {}", key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_space_separated_basic() {
        let input = Some("openid profile email".to_string());
        let result = parse_space_separated(input.as_ref());
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"openid".to_string()));
        assert!(result.contains(&"profile".to_string()));
        assert!(result.contains(&"email".to_string()));
    }

    #[test]
    fn parse_space_separated_deduplicates() {
        let input = Some("openid openid profile".to_string());
        let result = parse_space_separated(input.as_ref());
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn parse_space_separated_empty() {
        let input = Some("".to_string());
        let result = parse_space_separated(input.as_ref());
        assert!(result.is_empty());
    }

    #[test]
    fn parse_space_separated_none() {
        let result = parse_space_separated(None);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_opt_u64_valid() {
        let mut params = HashMap::new();
        params.insert("max_age".to_string(), "3600".to_string());
        assert_eq!(parse_opt_u64(&params, "max_age").unwrap(), Some(3600));
    }

    #[test]
    fn parse_opt_u64_missing() {
        let params = HashMap::new();
        assert_eq!(parse_opt_u64(&params, "max_age").unwrap(), None);
    }

    #[test]
    fn parse_opt_u64_invalid() {
        let mut params = HashMap::new();
        params.insert("max_age".to_string(), "abc".to_string());
        assert!(parse_opt_u64(&params, "max_age").is_err());
    }

    #[test]
    fn parse_required_url_valid() {
        let mut params = HashMap::new();
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        assert!(parse_required_url(&params, "redirect_uri").is_ok());
    }

    #[test]
    fn parse_required_url_missing() {
        let params = HashMap::new();
        assert!(parse_required_url(&params, "redirect_uri").is_err());
    }

    #[test]
    fn parse_required_url_invalid() {
        let mut params = HashMap::new();
        params.insert("redirect_uri".to_string(), "not a url".to_string());
        assert!(parse_required_url(&params, "redirect_uri").is_err());
    }
}
