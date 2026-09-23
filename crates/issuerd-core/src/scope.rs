// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Normalized OAuth2/OIDC scope set with sorted, deduplicated tokens.

use serde::{Deserialize, Serialize};

/// The `offline_access` scope token (OIDC Core §11). When granted, the token
/// set includes an offline refresh token (`typ: Offline`) bound to an offline
/// session that outlives the SSO session.
pub const OFFLINE_ACCESS_SCOPE: &str = "offline_access";

/// Normalized OAuth2/OIDC scope.
///
/// Invariant: tokens are sorted, deduplicated, and whitespace-trimmed. Once
/// constructed, `Scope` cannot contain duplicate tokens or empty tokens.
/// This makes scope comparison and set intersection deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default, Hash)]
pub struct Scope(Vec<String>);

/// Manual `Deserialize` that re-applies the sorted/deduplicated invariant.
///
/// The derived implementation would accept any JSON array verbatim, bypassing
/// normalization (see `Scope::parse`). Deserialization is a construction
/// boundary, so it must uphold the same invariant.
impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tokens = Vec::<String>::deserialize(deserializer)?;
        Ok(Scope::from(tokens))
    }
}

impl Scope {
    /// Parse a space-delimited scope string into a normalized `Scope`.
    ///
    /// # Examples
    ///
    /// ```
    /// use issuerd_core::Scope;
    ///
    /// let scope = Scope::parse("openid profile email");
    /// assert!(scope.contains("openid"));
    /// assert!(scope.contains("email"));
    /// assert!(!scope.contains("offline_access"));
    /// ```
    pub fn parse(raw: &str) -> Self {
        let mut tokens: Vec<String> = raw.split_whitespace().map(|s| s.to_string()).collect();
        tokens.sort();
        tokens.dedup();
        Self(tokens)
    }

    /// Construct an empty scope.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns `true` if there are no scope tokens.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of distinct scope tokens.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the scope contains the given token.
    pub fn contains(&self, token: &str) -> bool {
        self.0.iter().any(|s| s == token)
    }

    /// Iterate over scope tokens.
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }

    /// View the underlying tokens as a slice.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Convert into a raw `Vec<String>`.
    pub fn into_vec(self) -> Vec<String> {
        self.0
    }

    /// Convert to a raw `Vec<String>` by cloning.
    pub fn to_vec(&self) -> Vec<String> {
        self.0.clone()
    }

    /// Serialize to a space-delimited scope string.
    pub fn to_space_separated(&self) -> String {
        self.0.join(" ")
    }

    /// Join scope tokens with the given separator.
    pub fn join(&self, sep: &str) -> String {
        self.0.join(sep)
    }
}

impl From<Vec<String>> for Scope {
    fn from(mut tokens: Vec<String>) -> Self {
        tokens.sort();
        tokens.dedup();
        Self(tokens)
    }
}

impl From<Scope> for Vec<String> {
    fn from(scope: Scope) -> Self {
        scope.0
    }
}

impl<'a> IntoIterator for &'a Scope {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for Scope {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Serde helper module for `Option<Scope>` as a space-separated string.
///
/// Use with `#[serde(with = "space_separated_opt")]` on a field of type
/// `Option<Scope>`. Serializes to `"openid profile"` and deserializes from
/// the same format, matching OAuth2 introspection wire format.
pub mod space_separated_opt {
    use super::Scope;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(scope: &Option<Scope>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match scope {
            Some(s) => serializer.serialize_some(&s.to_space_separated()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Scope>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        Ok(opt.map(|s| Scope::parse(&s)))
    }
}

/// Serde helper module for `Scope` as a space-separated string.
///
/// Use with `#[serde(with = "space_separated")]` on a field of type `Scope`.
/// JWT `scope` claims are space-delimited strings per RFC 9068 §2.2.3, not
/// JSON arrays.
pub mod space_separated {
    use super::Scope;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(scope: &Scope, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&scope.to_space_separated())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scope, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Scope::parse(&s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normalizes_order_and_dedupes() {
        let scope = Scope::parse("profile openid email openid");
        assert_eq!(scope.to_vec(), vec!["email", "openid", "profile"]);
    }

    #[test]
    fn parse_empty_string_is_empty() {
        let scope = Scope::parse("");
        assert!(scope.is_empty());
        assert_eq!(scope.len(), 0);
    }

    #[test]
    fn parse_whitespace_only_is_empty() {
        let scope = Scope::parse("   \t\n  ");
        assert!(scope.is_empty());
    }

    #[test]
    fn contains_works() {
        let scope = Scope::parse("openid profile");
        assert!(scope.contains("openid"));
        assert!(scope.contains("profile"));
        assert!(!scope.contains("email"));
    }

    #[test]
    fn from_vec_normalizes() {
        let scope = Scope::from(vec![
            "profile".to_string(),
            "openid".to_string(),
            "profile".to_string(),
        ]);
        assert_eq!(scope.to_vec(), vec!["openid", "profile"]);
    }

    #[test]
    fn into_vec_roundtrip() {
        let scope = Scope::parse("openid profile email");
        let vec: Vec<String> = scope.into();
        assert_eq!(vec, vec!["email", "openid", "profile"]);
    }

    #[test]
    fn iter_yields_sorted_tokens() {
        let scope = Scope::parse("profile openid");
        let collected: Vec<&String> = scope.iter().collect();
        assert_eq!(collected, vec!["openid", "profile"]);
    }

    #[test]
    fn into_iter_yields_sorted_tokens() {
        let scope = Scope::parse("profile openid");
        let collected: Vec<String> = scope.into_iter().collect();
        assert_eq!(collected, vec!["openid", "profile"]);
    }

    #[test]
    fn to_space_separated_roundtrip() {
        let scope = Scope::parse("profile openid email");
        assert_eq!(scope.to_space_separated(), "email openid profile");
    }

    #[test]
    fn serde_roundtrip_as_array() {
        let scope = Scope::parse("profile openid");
        let json = serde_json::to_string(&scope).unwrap();
        assert_eq!(json, r#"["openid","profile"]"#);
        let back: Scope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }

    #[test]
    fn deserialize_normalizes_invariant() {
        let scope: Scope = serde_json::from_str(r#"["profile","openid","profile"]"#).unwrap();
        assert_eq!(scope.to_vec(), vec!["openid", "profile"]);
    }
}
