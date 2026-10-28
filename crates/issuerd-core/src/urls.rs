// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Canonical realm URL construction and inbound path-segment decoding.

use url::Url;

use crate::{IssuerdError, RealmName};

/// Parsed deployment origin and base path shared by canonical realm URLs.
#[derive(Debug, Clone)]
pub struct RealmIssuerBase {
    origin: Url,
    base_segments: Vec<String>,
}

impl RealmIssuerBase {
    pub fn new(base_url: &str) -> Result<Self, IssuerdError> {
        let (origin, base_segments) = parse_base(base_url)?;
        Ok(Self {
            origin,
            base_segments,
        })
    }

    /// Parse a realm issuer against this deployment and return its decoded
    /// realm name. No UUID fallback is implied here.
    pub fn realm_name(&self, issuer: &str) -> Option<RealmName> {
        let url = Url::parse(issuer).ok()?;
        if url.scheme() != self.origin.scheme()
            || url.host_str() != self.origin.host_str()
            || url.port_or_known_default() != self.origin.port_or_known_default()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        let segments: Vec<&str> = url.path_segments()?.collect();
        if segments.len() != self.base_segments.len() + 2
            || segments.get(self.base_segments.len()) != Some(&"realms")
        {
            return None;
        }
        for (actual, expected) in segments.iter().zip(&self.base_segments) {
            if decode_path_segment(actual).ok()?.as_str() != expected {
                return None;
            }
        }
        decode_realm_segment(segments.last()?).ok()
    }
}

/// Builder for a realm's issuer and endpoint URLs.
#[derive(Debug, Clone)]
pub struct RealmUrlBuilder {
    base: RealmIssuerBase,
    realm: RealmName,
}

impl RealmUrlBuilder {
    /// Validate the configured base URL and logical realm name.
    pub fn new(base_url: &str, realm: &str) -> Result<Self, IssuerdError> {
        Self::with_base(&RealmIssuerBase::new(base_url)?, realm)
    }

    /// Build from an already parsed deployment base.
    pub fn with_base(base: &RealmIssuerBase, realm: &str) -> Result<Self, IssuerdError> {
        let realm = RealmName::new(realm)?;
        reject_dot_only(&realm)?;
        Ok(Self {
            base: base.clone(),
            realm,
        })
    }

    /// The canonical realm issuer URL.
    pub fn issuer(&self) -> Url {
        self.path(&[])
    }

    /// A canonical URL below the realm issuer, built from literal path segments.
    pub fn path(&self, suffix: &[&str]) -> Url {
        self.build(&[], suffix)
    }

    /// A canonical URL with segments inserted before the issuer base path.
    /// This is used by well-known metadata formats such as RFC 9728.
    pub fn with_prefix(&self, prefix: &[&str], suffix: &[&str]) -> Url {
        self.build(prefix, suffix)
    }

    fn build(&self, prefix: &[&str], suffix: &[&str]) -> Url {
        let segments: Vec<String> = prefix
            .iter()
            .copied()
            .chain(self.base.base_segments.iter().map(String::as_str))
            .chain(["realms", self.realm.as_str()])
            .chain(suffix.iter().copied())
            .map(encode_path_segment)
            .collect();
        let mut url = self.base.origin.clone();
        url.set_path(&format!("/{}", segments.join("/")));
        url
    }
}

fn encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for &byte in segment.as_bytes() {
        let escape = !byte.is_ascii()
            || byte <= 0x20
            || byte == 0x7f
            || matches!(
                byte,
                b'"' | b'<' | b'>' | b'`' | b'#' | b'?' | b'{' | b'}' | b'/' | b'%' | b'\\'
            );
        if escape {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        } else {
            encoded.push(byte as char);
        }
    }
    match encoded.as_str() {
        "." => "%2E".to_string(),
        ".." => "%2E%2E".to_string(),
        _ => encoded,
    }
}

fn reject_dot_only(realm: &RealmName) -> Result<(), IssuerdError> {
    if matches!(realm.as_str(), "." | "..") {
        return Err(IssuerdError::InvalidRequest(
            "dot-only realm names have no canonical URL path representation".into(),
        ));
    }
    Ok(())
}

/// Decode one inbound URL path segment and validate the resulting realm name.
/// A second encoded `%` remains in the decoded value and is rejected by
/// `RealmName`, so nested encoding never becomes another decoding pass.
pub fn decode_realm_segment(segment: &str) -> Result<RealmName, IssuerdError> {
    let decoded = decode_path_segment(segment)?;
    let realm = RealmName::new(&decoded)?;
    if realm.as_str() != decoded {
        return Err(IssuerdError::InvalidRequest(
            "realm path segment must not have surrounding whitespace".into(),
        ));
    }
    reject_dot_only(&realm)?;
    Ok(realm)
}

/// Parse a realm issuer against this deployment's configured base URL and
/// return its decoded realm name. No UUID fallback is implied here.
pub fn realm_name_from_issuer(base_url: &str, issuer: &str) -> Option<RealmName> {
    RealmIssuerBase::new(base_url).ok()?.realm_name(issuer)
}

fn parse_base(base_url: &str) -> Result<(Url, Vec<String>), IssuerdError> {
    let mut origin = Url::parse(base_url)
        .map_err(|_| IssuerdError::InvalidRequest("issuer base URL is invalid".into()))?;
    if origin.cannot_be_a_base() {
        return Err(IssuerdError::InvalidRequest("issuer base URL must be hierarchical".into()));
    }
    let mut base_segments: Vec<String> = origin
        .path_segments()
        .ok_or_else(|| IssuerdError::InvalidRequest("issuer base URL must be hierarchical".into()))?
        .map(decode_path_segment)
        .collect::<Result<_, _>>()?;
    while base_segments.last().is_some_and(String::is_empty) {
        base_segments.pop();
    }
    origin.set_query(None);
    origin.set_fragment(None);
    origin.set_path("");
    Ok((origin, base_segments))
}

fn decode_path_segment(segment: &str) -> Result<String, IssuerdError> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(IssuerdError::InvalidRequest(
                    "invalid percent encoding in URL path segment".into(),
                ));
            }
            let high = hex(bytes[index + 1]).ok_or_else(|| {
                IssuerdError::InvalidRequest("invalid percent encoding in URL path segment".into())
            })?;
            let low = hex(bytes[index + 2]).ok_or_else(|| {
                IssuerdError::InvalidRequest("invalid percent encoding in URL path segment".into())
            })?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| IssuerdError::InvalidRequest("URL path segment is not UTF-8".into()))
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_uses_one_canonical_segment_encoding() {
        let urls = RealmUrlBuilder::new("https://auth.example/iam/", "tenant{one}").unwrap();
        assert_eq!(urls.issuer().as_str(), "https://auth.example/iam/realms/tenant%7Bone%7D");
        assert_eq!(
            urls.path(&["mcp"]).as_str(),
            "https://auth.example/iam/realms/tenant%7Bone%7D/mcp"
        );
        assert_eq!(
            urls.with_prefix(&[".well-known", "oauth-protected-resource"], &["mcp"])
                .as_str(),
            "https://auth.example/.well-known/oauth-protected-resource/iam/realms/tenant%7Bone%7D/mcp"
        );
    }

    #[test]
    fn ambiguous_dot_realm_names_are_rejected_without_normalization() {
        for name in [".", ".."] {
            assert!(RealmUrlBuilder::new("https://auth.example", name).is_err());
            assert!(decode_realm_segment("%2E").is_err());
            assert_eq!(
                realm_name_from_issuer(
                    "https://auth.example",
                    &format!("https://auth.example/realms/{name}")
                ),
                None
            );
        }

        for name in ["a.b", ".realm", "realm."] {
            let urls = RealmUrlBuilder::new("https://auth.example", name).unwrap();
            assert_eq!(
                urls.path(&["mcp"]).as_str(),
                format!("https://auth.example/realms/{name}/mcp")
            );
            assert_eq!(
                realm_name_from_issuer("https://auth.example", urls.issuer().as_str()),
                Some(RealmName::new(name).unwrap())
            );
        }
    }

    #[test]
    fn inbound_realm_segment_decodes_exactly_once() {
        assert_eq!(decode_realm_segment("tenant%7Bone%7D").unwrap().as_str(), "tenant{one}");
        assert!(decode_realm_segment("tenant%257Bone%257D").is_err());
        assert!(decode_realm_segment("a%2Fb").is_err());
        assert!(decode_realm_segment("%20master%20").is_err());
        assert!(decode_realm_segment(" master ").is_err());
        assert!(decode_realm_segment("%").is_err());
        assert!(decode_realm_segment("%FF").is_err());
    }

    #[test]
    fn issuer_parser_preserves_base_path_and_rejects_aliases() {
        assert_eq!(
            realm_name_from_issuer(
                "https://auth.example/iam/",
                "https://auth.example/iam/realms/tenant%7Bone%7D"
            ),
            Some(RealmName::new("tenant{one}").unwrap())
        );
        for issuer in [
            "https://auth.example/realms/demo",
            "https://auth.example/iam/realms/demo/",
            "https://auth.example/iam/realms/demo/mcp",
            "https://auth.example/iam/realms/a%2Fb",
        ] {
            assert_eq!(realm_name_from_issuer("https://auth.example/iam", issuer), None);
        }
    }

    #[test]
    fn builder_validates_realm_names() {
        assert!(RealmUrlBuilder::new("https://auth.example", "a/b").is_err());
        assert!(RealmUrlBuilder::new("https://auth.example", "my realm").is_err());
    }
}
