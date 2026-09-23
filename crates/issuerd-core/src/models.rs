// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Core domain models: realms, users, clients, roles, groups, sessions, and credentials.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::IssuerdError;
use crate::ids::{
    ClientId, ClientSessionId, CredentialId, FlowStageId, GroupId, IdentityProviderId, JwtId,
    KeyId, RealmId, RoleId, SessionId, UserId,
};
use crate::scope::Scope;
use crate::traits::Algorithm;

// ---------------------------------------------------------------------------
// SecondsNonZero
// ---------------------------------------------------------------------------

/// A positive non-zero duration in seconds.
///
/// Used for token lifespans and session timeouts so that a zero or negative
/// value is unrepresentable.
///
/// Flux: the refinement annotations let `cargo flux` (scripts/flux.sh) prove
/// that `new`/`get` preserve the stored value. They come from the `flux-rs`
/// proc-macro shim, which expands to nothing in normal builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
#[flux_rs::refined_by(seconds: int)]
pub struct SecondsNonZero(#[flux_rs::field(u64[seconds])] u64);

impl SecondsNonZero {
    /// Construct a `SecondsNonZero` value.
    ///
    /// # Panics
    ///
    /// Panics if `seconds` is zero.
    #[flux_rs::spec(fn(seconds: u64) -> SecondsNonZero[seconds])]
    pub const fn new(seconds: u64) -> Self {
        assert!(seconds > 0, "SecondsNonZero must be > 0");
        Self(seconds)
    }

    /// Return the underlying `u64` value.
    #[flux_rs::spec(fn(self: SecondsNonZero[@seconds]) -> u64[seconds])]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<SecondsNonZero> for u64 {
    fn from(s: SecondsNonZero) -> Self {
        s.0
    }
}

impl TryFrom<u64> for SecondsNonZero {
    type Error = &'static str;

    fn try_from(seconds: u64) -> Result<Self, Self::Error> {
        if seconds > 0 {
            Ok(Self(seconds))
        } else {
            Err("SecondsNonZero must be > 0")
        }
    }
}

impl TryFrom<i64> for SecondsNonZero {
    type Error = &'static str;

    fn try_from(seconds: i64) -> Result<Self, Self::Error> {
        if seconds > 0 {
            Ok(Self(seconds as u64))
        } else {
            Err("SecondsNonZero must be > 0")
        }
    }
}

impl std::ops::Deref for SecondsNonZero {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<u64> for SecondsNonZero {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<SecondsNonZero> for u64 {
    fn eq(&self, other: &SecondsNonZero) -> bool {
        *self == other.0
    }
}

// ---------------------------------------------------------------------------
// Username
// ---------------------------------------------------------------------------

/// A validated username.
///
/// Rules (v1):
/// * non-empty after trimming
/// * no control characters
/// * maximum length 255
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Username(String);

impl Username {
    /// Maximum allowed username length.
    pub const MAX_LEN: usize = 255;

    /// Create a new `Username`, validating the input.
    pub fn new(name: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = name.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("username must not be empty".into()));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "username must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "username must not contain control characters".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the username as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Username {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Username {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for Username {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Username {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<Username> for str {
    fn eq(&self, other: &Username) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for Username {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

/// A validated email address.
///
/// Rules (v1):
/// * non-empty
/// * contains exactly one `@`
/// * local part (before `@`) is non-empty
/// * domain part (after `@`) contains at least one `.`
/// * maximum length 254
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Email(String);

impl Email {
    /// Maximum allowed email length.
    pub const MAX_LEN: usize = 254;

    /// Create a new `Email`, validating the input.
    pub fn new(email: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = email.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("email must not be empty".into()));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(IssuerdError::InvalidRequest(
                "email must not contain control characters".into(),
            ));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "email must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        let parts: Vec<&str> = trimmed.split('@').collect();
        if parts.len() != 2 {
            return Err(IssuerdError::InvalidRequest("email must contain exactly one @".into()));
        }
        let (local, domain) = (parts[0], parts[1]);
        if local.is_empty() {
            return Err(IssuerdError::InvalidRequest("email local part must not be empty".into()));
        }
        if domain.is_empty() || !domain.contains('.') {
            return Err(IssuerdError::InvalidRequest("email domain must contain a dot".into()));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the email as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Email {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Email {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for Email {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Email {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<Email> for str {
    fn eq(&self, other: &Email) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for Email {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// ClientIdentifier
// ---------------------------------------------------------------------------

/// A validated OAuth2/OIDC client identifier.
///
/// This is the human-readable identifier used in OAuth2 protocol requests
/// (e.g. `client_id` parameter), distinct from the internal `ClientId` UUID.
///
/// Rules (v1):
/// * non-empty after trimming
/// * no control characters
/// * maximum length 255
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ClientIdentifier(String);

impl ClientIdentifier {
    /// Maximum allowed client identifier length.
    pub const MAX_LEN: usize = 255;

    /// Create a new `ClientIdentifier`, validating the input.
    pub fn new(id: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = id.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("client_identifier must not be empty".into()));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "client_identifier must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "client_identifier must not contain control characters".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClientIdentifier {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for ClientIdentifier {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for ClientIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for ClientIdentifier {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for ClientIdentifier {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for ClientIdentifier {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<ClientIdentifier> for str {
    fn eq(&self, other: &ClientIdentifier) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for ClientIdentifier {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// RedirectUri
// ---------------------------------------------------------------------------

/// A validated OAuth2/OIDC redirect URI.
///
/// The value is stored in its normalized `url::Url` serialization so it
/// compares equal to the (parsed, normalized) request-side redirect URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RedirectUri(String);

impl RedirectUri {
    /// Create a new `RedirectUri`, validating that it is a parseable URL.
    pub fn new(uri: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = uri.into();
        // `Url::parse` silently strips tabs/newlines per WHATWG; reject them
        // instead so stored values never differ invisibly from admin input.
        if s.chars().any(char::is_control) {
            return Err(IssuerdError::InvalidRequest(
                "redirect_uri must not contain control characters".into(),
            ));
        }
        let parsed = Url::parse(&s)
            .map_err(|e| IssuerdError::InvalidRequest(format!("invalid redirect_uri: {e}")))?;
        Ok(Self(parsed.to_string()))
    }

    /// Borrow the URI as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Keycloak-compatible redirect-URI matching: exact equality, or — when
    /// the REGISTERED URI ends in a trailing `*` — a byte-prefix match on the
    /// part before it (`https://host/app/*` matches `https://host/app/cb`).
    /// The wildcard is only honored at the very end; an interior `*` is
    /// literal. The requested side is expected to be normalized already (a
    /// parsed `url::Url` / a `RedirectUri`). Note the prefix is matched
    /// bytewise, so a registration like `https://host*` (no path separator
    /// before `*`) would also match `https://host.evil.example` — same
    /// caveat as Keycloak; registrations are administrator-controlled.
    pub fn matches(&self, requested: &str) -> bool {
        if self.0 == requested {
            return true;
        }
        match self.0.strip_suffix('*') {
            Some(prefix) => !prefix.is_empty() && requested.starts_with(prefix),
            None => false,
        }
    }
}

impl TryFrom<String> for RedirectUri {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for RedirectUri {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for RedirectUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for RedirectUri {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for RedirectUri {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for RedirectUri {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<RedirectUri> for str {
    fn eq(&self, other: &RedirectUri) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for RedirectUri {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// RealmName
// ---------------------------------------------------------------------------

/// A validated realm name.
///
/// Rules (v1):
/// * non-empty
/// * ASCII only
/// * no control characters
/// * no whitespace
/// * no URL-reserved or query-significant characters (`/ \ ? # % + & =`)
/// * maximum length 255
///
/// A valid name is always a safe single URL path segment: realm names appear
/// verbatim in issuer URLs (`{issuer}/realms/{name}`), and discovery runs
/// `Url::parse` on the issuer (which percent-encodes non-ASCII), so spaces,
/// query separators, or non-ASCII characters would make the advertised issuer
/// diverge from the byte-exact `iss` claim in tokens.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RealmName(String);

impl RealmName {
    /// Maximum allowed realm name length.
    pub const MAX_LEN: usize = 255;

    /// Create a new `RealmName`, validating the input.
    pub fn new(name: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = name.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("realm name must not be empty".into()));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "realm name must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "realm name must not contain control characters".into(),
            ));
        }
        // Realm names appear verbatim in URL path segments and issuer URLs
        // (`/realms/{name}/...`): whitespace or URL-reserved characters would
        // make the realm unreachable, break `Url::parse` on the issuer, or
        // make its URLs ambiguous.
        if trimmed.chars().any(|c| c.is_whitespace()) {
            return Err(IssuerdError::InvalidRequest(
                "realm name must not contain whitespace".into(),
            ));
        }
        if trimmed
            .chars()
            .any(|c| matches!(c, '/' | '\\' | '?' | '#' | '%' | '+' | '&' | '='))
        {
            return Err(IssuerdError::InvalidRequest(
                "realm name must not contain URL-reserved characters (/ \\ ? # % + & =)".into(),
            ));
        }
        // Non-ASCII names would be percent-encoded by `Url::parse` in
        // discovery but embedded raw in token `iss`, breaking the OIDC
        // Discovery §4.2 byte-exact issuer match.
        if !trimmed.is_ascii() {
            return Err(IssuerdError::InvalidRequest(
                "realm name must be ASCII (it is embedded verbatim in issuer URLs)".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the realm name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RealmName {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for RealmName {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for RealmName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for RealmName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for RealmName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<RealmName> for str {
    fn eq(&self, other: &RealmName) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for RealmName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// Acr
// ---------------------------------------------------------------------------

/// Authentication Context Class Reference per OIDC Core 1.0 Section 2.
///
/// Standard values include `"0"`, `"1"`, `"2"`, `"3"` (NIST 800-63 AAL levels)
/// and custom URIs.  Only rule enforced here is non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Acr(String);

impl Acr {
    /// Create a new `Acr`, validating that it is non-empty.
    pub fn new(acr: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = acr.into();
        if s.trim().is_empty() {
            return Err(IssuerdError::InvalidRequest("acr must not be empty".into()));
        }
        Ok(Self(s))
    }

    /// Borrow the ACR value as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Acr {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Acr {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for Acr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Acr {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Amr
// ---------------------------------------------------------------------------

/// Authentication Methods References per RFC 8176.
///
/// Common standardized values are represented as variants; unknown values
/// are captured by the `Custom` variant and round-trip through serde.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Amr {
    #[serde(rename = "pwd")]
    Password,
    #[serde(rename = "otp")]
    Otp,
    #[serde(rename = "sms")]
    Sms,
    #[serde(rename = "tel")]
    Tel,
    #[serde(rename = "swk")]
    SoftwareKey,
    #[serde(rename = "hwk")]
    HardwareKey,
    #[serde(rename = "mfa")]
    Mfa,
    #[serde(rename = "sc")]
    SmartCard,
    #[serde(rename = "ba")]
    Biometric,
    #[serde(rename = "user")]
    UserPresence,
    #[serde(rename = "pin")]
    Pin,
    #[serde(rename = "fpt")]
    Fingerprint,
    #[serde(rename = "face")]
    Face,
    #[serde(rename = "fido")]
    Fido,
    #[serde(rename = "rk")]
    RecoveryKey,
    #[serde(untagged)]
    Custom(String),
}

impl Amr {
    /// Return the wire-format string for this AMR value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Password => "pwd",
            Self::Otp => "otp",
            Self::Sms => "sms",
            Self::Tel => "tel",
            Self::SoftwareKey => "swk",
            Self::HardwareKey => "hwk",
            Self::Mfa => "mfa",
            Self::SmartCard => "sc",
            Self::Biometric => "ba",
            Self::UserPresence => "user",
            Self::Pin => "pin",
            Self::Fingerprint => "fpt",
            Self::Face => "face",
            Self::Fido => "fido",
            Self::RecoveryKey => "rk",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for Amr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// WebOrigin
// ---------------------------------------------------------------------------

/// A validated web origin for CORS / OAuth2 redirect validation.
///
/// Rules:
/// * non-empty
/// * either the literal string `*` (wildcard)
/// * or a parseable URL with a scheme
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WebOrigin(String);

impl WebOrigin {
    /// Create a new `WebOrigin`.
    pub fn new(origin: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = origin.into();
        if s.trim().is_empty() {
            return Err(IssuerdError::InvalidRequest("web origin must not be empty".into()));
        }
        if s.chars().any(char::is_control) {
            return Err(IssuerdError::InvalidRequest(
                "web origin must not contain control characters".into(),
            ));
        }
        if s == "*" {
            return Ok(Self(s));
        }
        let _ = Url::parse(&s)
            .map_err(|e| IssuerdError::InvalidRequest(format!("invalid web origin: {e}")))?;
        Ok(Self(s))
    }

    /// Borrow the origin as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for WebOrigin {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for WebOrigin {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for WebOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for WebOrigin {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// GroupPath
// ---------------------------------------------------------------------------

/// A validated group path.
///
/// Rules:
/// * non-empty
/// * must start with `/`
/// * must not contain control characters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupPath(String);

impl GroupPath {
    /// Create a new `GroupPath`.
    pub fn new(path: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = path.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("group path must not be empty".into()));
        }
        if !trimmed.starts_with('/') {
            return Err(IssuerdError::InvalidRequest("group path must start with '/'".into()));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "group path must not contain control characters".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the path as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GroupPath {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for GroupPath {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for GroupPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for GroupPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// ThemeName
// ---------------------------------------------------------------------------

/// A validated theme name.
///
/// Rules (v1):
/// * non-empty after trimming
/// * no control characters
/// * no path separators (`/` or `\\`)
/// * maximum length 255
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ThemeName(String);

impl ThemeName {
    /// Maximum allowed theme name length.
    pub const MAX_LEN: usize = 255;

    /// Create a new `ThemeName`, validating the input.
    pub fn new(name: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = name.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("theme name must not be empty".into()));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "theme name must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "theme name must not contain control characters".into(),
            ));
        }
        if trimmed.contains('/') || trimmed.contains('\\') {
            return Err(IssuerdError::InvalidRequest(
                "theme name must not contain path separators".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the theme name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ThemeName {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for ThemeName {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for ThemeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for ThemeName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for ThemeName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for ThemeName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<ThemeName> for str {
    fn eq(&self, other: &ThemeName) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for ThemeName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// DisplayName
// ---------------------------------------------------------------------------

/// A validated human-readable display name.
///
/// Rules (v1):
/// * non-empty after trimming
/// * no control characters
/// * maximum length 255
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct DisplayName(String);

impl DisplayName {
    /// Maximum allowed display name length.
    pub const MAX_LEN: usize = 255;

    /// Create a new `DisplayName`, validating the input.
    pub fn new(name: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = name.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("display name must not be empty".into()));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "display name must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "display name must not contain control characters".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the display name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DisplayName {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for DisplayName {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for DisplayName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for DisplayName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for DisplayName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for DisplayName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<DisplayName> for str {
    fn eq(&self, other: &DisplayName) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for DisplayName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// AuthorizationCode
// ---------------------------------------------------------------------------

/// A validated OAuth2 authorization code.
///
/// Rules (v1):
/// * non-empty
/// * maximum length 2048
/// * no control characters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct AuthorizationCode(String);

impl AuthorizationCode {
    pub const MAX_LEN: usize = 2048;

    pub fn new(code: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = code.into();
        if s.is_empty() {
            return Err(IssuerdError::InvalidRequest(
                "authorization code must not be empty".into(),
            ));
        }
        if s.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "authorization code must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "authorization code must not contain control characters".into(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AuthorizationCode {
    type Error = IssuerdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for AuthorizationCode {
    type Error = IssuerdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for AuthorizationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for AuthorizationCode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for AuthorizationCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// ClientSecret
// ---------------------------------------------------------------------------

/// A validated OAuth2 client secret.
///
/// Rules (v1):
/// * non-empty
/// * maximum length 2048
/// * no control characters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ClientSecret(String);

impl ClientSecret {
    pub const MAX_LEN: usize = 2048;

    pub fn new(secret: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = secret.into();
        if s.is_empty() {
            return Err(IssuerdError::InvalidRequest("client secret must not be empty".into()));
        }
        if s.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "client secret must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "client secret must not contain control characters".into(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClientSecret {
    type Error = IssuerdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for ClientSecret {
    type Error = IssuerdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for ClientSecret {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for ClientSecret {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// RefreshToken
// ---------------------------------------------------------------------------

/// A validated OAuth2 refresh token.
///
/// Rules (v1):
/// * non-empty
/// * maximum length 8192
/// * no control characters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RefreshToken(String);

impl RefreshToken {
    pub const MAX_LEN: usize = 8192;

    pub fn new(token: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = token.into();
        if s.is_empty() {
            return Err(IssuerdError::InvalidRequest("refresh token must not be empty".into()));
        }
        if s.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "refresh token must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "refresh token must not contain control characters".into(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RefreshToken {
    type Error = IssuerdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for RefreshToken {
    type Error = IssuerdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for RefreshToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for RefreshToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Password
// ---------------------------------------------------------------------------

/// A validated user password.
///
/// Rules (v1):
/// * non-empty (not trimmed — leading/trailing spaces are intentional)
/// * maximum length 4096
/// * no control characters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Password(String);

impl Password {
    pub const MAX_LEN: usize = 4096;

    pub fn new(password: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = password.into();
        if s.is_empty() {
            return Err(IssuerdError::InvalidRequest("password must not be empty".into()));
        }
        if s.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "password must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "password must not contain control characters".into(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Password {
    type Error = IssuerdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Password {
    type Error = IssuerdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for Password {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Assertion
// ---------------------------------------------------------------------------

/// A validated OAuth2 assertion (JWT or SAML).
///
/// Rules (v1):
/// * non-empty
/// * maximum length 65536
/// * no control characters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Assertion(String);

impl Assertion {
    pub const MAX_LEN: usize = 65536;

    pub fn new(assertion: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = assertion.into();
        if s.is_empty() {
            return Err(IssuerdError::InvalidRequest("assertion must not be empty".into()));
        }
        if s.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "assertion must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "assertion must not contain control characters".into(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Assertion {
    type Error = IssuerdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Assertion {
    type Error = IssuerdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for Assertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Assertion {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for Assertion {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// ClaimName
// ---------------------------------------------------------------------------

/// A validated OIDC claim name.
///
/// Rules (v1):
/// * non-empty after trimming
/// * no control characters
/// * maximum length 255
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ClaimName(String);

impl ClaimName {
    /// Maximum allowed claim name length.
    pub const MAX_LEN: usize = 255;

    /// Create a new `ClaimName`, validating the input.
    pub fn new(name: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = name.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("claim name must not be empty".into()));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "claim name must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "claim name must not contain control characters".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the claim name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClaimName {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for ClaimName {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for ClaimName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for ClaimName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for ClaimName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for ClaimName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<ClaimName> for str {
    fn eq(&self, other: &ClaimName) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for ClaimName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// Alias
// ---------------------------------------------------------------------------

/// A validated alias for identity providers, flows, and authenticators.
///
/// Rules (v1):
/// * non-empty after trimming
/// * no control characters
/// * maximum length 255
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(try_from = "String")]
pub struct Alias(String);

impl Alias {
    /// Maximum allowed alias length.
    pub const MAX_LEN: usize = 255;

    /// Create a new `Alias`, validating the input.
    pub fn new(alias: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = alias.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("alias must not be empty".into()));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "alias must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "alias must not contain control characters".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the alias as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Alias {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Alias {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for Alias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for Alias {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for Alias {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Alias {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<Alias> for str {
    fn eq(&self, other: &Alias) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for Alias {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// Nonce
// ---------------------------------------------------------------------------

/// A validated OIDC nonce value.
///
/// Rules (v1):
/// * non-empty after trimming
/// * no control characters
/// * maximum length 255
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Nonce(String);

impl Nonce {
    /// Maximum allowed nonce length.
    pub const MAX_LEN: usize = 255;

    /// Create a new `Nonce`, validating the input.
    pub fn new(nonce: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = nonce.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("nonce must not be empty".into()));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "nonce must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "nonce must not contain control characters".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the nonce as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Nonce {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Nonce {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for Nonce {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for Nonce {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Nonce {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<Nonce> for str {
    fn eq(&self, other: &Nonce) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for Nonce {
    fn eq(&self, other: &&str) -> bool {
        self.0 == **other
    }
}

// ---------------------------------------------------------------------------
// RoleName
// ---------------------------------------------------------------------------

/// A validated role or group name.
///
/// Rules:
/// * non-empty
/// * must not contain control characters
/// * max 255 characters
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, utoipa::ToSchema,
)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    /// Maximum allowed name length.
    pub const MAX_LEN: usize = 255;

    /// Create a new `RoleName`, validating the input.
    pub fn new(name: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = name.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(IssuerdError::InvalidRequest("name must not be empty".into()));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(IssuerdError::InvalidRequest(format!(
                "name must not exceed {} characters",
                Self::MAX_LEN
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "name must not contain control characters".into(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RoleName {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for RoleName {
    type Error = IssuerdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl std::fmt::Display for RoleName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for RoleName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Alias for `RoleName` — group names follow the same validation rules.
pub type GroupName = RoleName;

// ---------------------------------------------------------------------------
// Realm
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Realm {
    pub id: RealmId,
    pub name: RealmName,
    pub display_name: Option<DisplayName>,
    pub enabled: bool,
    pub ssl_required: SslRequired,
    pub password_policy: PasswordPolicy,
    pub login_theme: Option<ThemeName>,
    pub email_theme: Option<ThemeName>,
    pub admin_theme: Option<ThemeName>,
    // --- Internationalization ---
    /// Master toggle: when `true`, login and email pages may be localized.
    #[serde(default)]
    pub internationalization_enabled: bool,
    /// Locale tags (BCP 47) this realm can render.
    #[serde(default)]
    pub supported_locales: Vec<String>,
    /// Fallback locale used when the client does not negotiate one.
    #[serde(default)]
    pub default_locale: Option<String>,
    pub default_role: Option<String>,
    pub access_token_lifespan: SecondsNonZero,
    pub refresh_token_lifespan: SecondsNonZero,
    pub sso_session_idle_timeout: SecondsNonZero,
    pub sso_session_max_lifespan: SecondsNonZero,
    pub offline_session_idle_timeout: SecondsNonZero,
    // --- Brute-force detection ---
    /// Master toggle: when `false`, no login-failure tracking or lockout is
    /// applied for this realm.
    #[serde(default)]
    pub brute_force_protected: bool,
    /// Number of consecutive failures before the account+IP is locked.
    #[serde(default = "default_max_login_failures")]
    pub max_login_failures: u32,
    /// Progressive wait increment in seconds (0 = fixed lockout duration).
    #[serde(default = "default_wait_increment_secs")]
    pub wait_increment_secs: u32,
    /// Upper bound for the progressive wait, in seconds.
    #[serde(default = "default_max_failure_wait_secs")]
    pub max_failure_wait_secs: u32,
    /// Fixed lockout duration in seconds (used when `wait_increment_secs` is 0).
    #[serde(default = "default_lockout_duration_secs")]
    pub lockout_duration_secs: u32,
    // --- Login settings toggles ---
    #[serde(default)]
    pub registration_enabled: bool,
    #[serde(default)]
    pub reset_password_allowed: bool,
    #[serde(default)]
    pub remember_me_enabled: bool,
    #[serde(default)]
    pub verify_email_enabled: bool,
    #[serde(default = "default_true")]
    pub login_with_email_allowed: bool,
    #[serde(default)]
    pub duplicate_emails_allowed: bool,
    #[serde(default = "default_true")]
    pub edit_username_allowed: bool,
    /// Idle timeout in seconds for sessions established via "remember me".
    /// Separate from `sso_session_idle_timeout` so remembered
    /// sessions can live longer than interactive SSO sessions.
    #[serde(default = "default_remember_me_session_idle_secs")]
    pub remember_me_session_idle_secs: SecondsNonZero,
    /// TOTP policy for one-time-password credentials.
    #[serde(default)]
    pub otp_policy: OtpPolicy,
    // --- Events configuration ---
    /// Master toggle for login/user event recording. Issuerd default: `true`
    /// (Keycloak parity break — Keycloak defaults to off).
    #[serde(default = "default_true")]
    pub events_enabled: bool,
    /// How long events are retained, in seconds (0 = never expire).
    #[serde(default)]
    pub events_expiration_secs: i64,
    /// Master toggle for admin (audit) event recording. Issuerd default:
    /// `true` (Keycloak parity break — Keycloak defaults to off).
    #[serde(default = "default_true")]
    pub admin_events_enabled: bool,
    /// When `true`, admin events store the request body representation.
    #[serde(default)]
    pub include_representations: bool,
    /// Event listener ids active for this realm (default: `["logging"]`).
    #[serde(default = "default_events_listeners")]
    pub events_listeners: Vec<String>,
    /// Revocation cutoff: tokens issued before this Unix timestamp are
    /// rejected (0 = no cutoff).
    #[serde(default)]
    pub not_before: i64,
    /// Group paths assigned to every new user on creation.
    #[serde(default)]
    pub default_groups: Vec<String>,
    // --- Flow bindings ---
    /// Alias of the browser login flow (`None` = system default `"browser"`).
    #[serde(default)]
    pub browser_flow: Option<String>,
    /// Alias of the direct grant flow (`None` = system default `"direct grant"`).
    #[serde(default)]
    pub direct_grant_flow: Option<String>,
    /// Alias of the reset credentials flow (`None` = system default
    /// `"reset credentials"`).
    #[serde(default)]
    pub reset_credentials_flow: Option<String>,
    /// Alias of the first broker login flow (`None` = system default
    /// `"first broker login"`).
    #[serde(default)]
    pub first_broker_login_flow: Option<String>,
    /// Alias of the registration flow (`None` = system default `"registration"`).
    #[serde(default)]
    pub registration_flow: Option<String>,
    pub attributes: HashMap<String, String>,
}

fn default_max_login_failures() -> u32 {
    5
}

fn default_wait_increment_secs() -> u32 {
    60
}

fn default_max_failure_wait_secs() -> u32 {
    900
}

fn default_lockout_duration_secs() -> u32 {
    900
}

fn default_true() -> bool {
    true
}

fn default_remember_me_session_idle_secs() -> SecondsNonZero {
    SecondsNonZero::new(604_800)
}

fn default_events_listeners() -> Vec<String> {
    vec!["logging".to_string()]
}

impl Default for Realm {
    fn default() -> Self {
        Self {
            id: RealmId::new("default").unwrap(),
            name: RealmName::new("default").unwrap(),
            display_name: None,
            enabled: true,
            ssl_required: SslRequired::External,
            password_policy: PasswordPolicy::default(),
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            internationalization_enabled: false,
            supported_locales: Vec::new(),
            default_locale: None,
            default_role: None,
            access_token_lifespan: SecondsNonZero::new(300),
            refresh_token_lifespan: SecondsNonZero::new(1800),
            sso_session_idle_timeout: SecondsNonZero::new(1800),
            sso_session_max_lifespan: SecondsNonZero::new(36000),
            offline_session_idle_timeout: SecondsNonZero::new(2592000),
            brute_force_protected: false,
            max_login_failures: default_max_login_failures(),
            wait_increment_secs: default_wait_increment_secs(),
            max_failure_wait_secs: default_max_failure_wait_secs(),
            lockout_duration_secs: default_lockout_duration_secs(),
            registration_enabled: false,
            reset_password_allowed: false,
            remember_me_enabled: false,
            verify_email_enabled: false,
            login_with_email_allowed: true,
            duplicate_emails_allowed: false,
            edit_username_allowed: true,
            remember_me_session_idle_secs: default_remember_me_session_idle_secs(),
            otp_policy: OtpPolicy::default(),
            events_enabled: true,
            events_expiration_secs: 0,
            admin_events_enabled: true,
            include_representations: false,
            events_listeners: default_events_listeners(),
            not_before: 0,
            default_groups: Vec::new(),
            browser_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: None,
            attributes: HashMap::new(),
        }
    }
}

impl Realm {
    /// Realm attribute naming the JWS algorithm used to sign this realm's
    /// tokens. Signing keys are server-global (the `signing_keys`
    /// table); the attribute selects which active global key signs
    /// this realm's tokens. Absent/invalid values fall back to the default
    /// (newest active) signing key.
    pub const DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE: &'static str = "default_signature_algorithm";

    /// The realm's configured token-signing algorithm, if the attribute is
    /// present, names a known algorithm, and is **asymmetric**. Symmetric
    /// (HMAC) values are ignored: HS* keys publish no usable public material
    /// (the JWKS exposure boundary strips `k`), so a realm signed with one
    /// could not even validate its own tokens from the JWKS snapshot.
    pub fn default_signature_algorithm(&self) -> Option<crate::Algorithm> {
        self.attributes
            .get(Self::DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE)
            .and_then(|v| v.parse::<crate::Algorithm>().ok())
            .filter(|alg| !alg.is_symmetric())
    }

    /// Realm attribute listing the authorization-details types (RFC 9396)
    /// this realm supports, space-separated. Deployments define
    /// their types per RFC 9396 §11.1; when the attribute is set, the
    /// authorization endpoint rejects requests carrying an unlisted type
    /// (`invalid_authorization_details`) and discovery advertises the list as
    /// `authorization_details_types_supported`. When absent, any type is
    /// accepted (unknown types are extensible per RFC 9396 §2.1) and
    /// discovery omits the metadata.
    pub const AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE: &'static str = "authorization_details_types";

    /// The realm's supported authorization-details types, or `None` when the
    /// attribute is unset/empty (generic mode: any type is accepted).
    pub fn authorization_details_types(&self) -> Option<Vec<String>> {
        let types: Vec<String> = self
            .attributes
            .get(Self::AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE)
            .map(|v| v.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        if types.is_empty() {
            None
        } else {
            Some(types)
        }
    }

    /// Realm attribute (`"true"`) enabling dynamic client registration
    /// (RFC 7591/7592): the public
    /// `/realms/{realm}/clients-registrations/*` endpoints answer 404 and the
    /// discovery `registration_endpoint` stays unadvertised unless this is
    /// set. Default off — registration is a public attack surface and must
    /// be opted into per realm.
    pub const DYNAMIC_CLIENT_REGISTRATION_ATTRIBUTE: &'static str =
        "dynamic_client_registration_enabled";

    /// Whether dynamic client registration is enabled for this realm
    /// (default `false`).
    pub fn dynamic_client_registration_enabled(&self) -> bool {
        self.attributes
            .get(Self::DYNAMIC_CLIENT_REGISTRATION_ATTRIBUTE)
            .is_some_and(|v| v == "true")
    }

    /// Realm attribute (`"true"`) making first and last name mandatory on
    /// the self-registration form. Default off — names stay optional.
    pub const REGISTRATION_REQUIRE_NAMES_ATTRIBUTE: &'static str = "registration_require_names";

    /// Whether self-registration requires a first and last name
    /// (default `false`).
    pub fn registration_require_names(&self) -> bool {
        self.attributes
            .get(Self::REGISTRATION_REQUIRE_NAMES_ATTRIBUTE)
            .is_some_and(|v| v == "true")
    }

    /// Realm attribute (`"true"`) for passwordless self-registration: the
    /// form collects no password and the account is created without a
    /// password credential. Default off.
    pub const REGISTRATION_PASSWORDLESS_ATTRIBUTE: &'static str = "registration_passwordless";

    /// Whether self-registration skips password collection (default
    /// `false`).
    pub fn registration_passwordless(&self) -> bool {
        self.attributes
            .get(Self::REGISTRATION_PASSWORDLESS_ATTRIBUTE)
            .is_some_and(|v| v == "true")
    }

    /// Realm attribute (`"true"`) for strict `UPDATE_PROFILE`: a submitted
    /// form with a blank/absent first or last name re-presents the form with
    /// an error instead of clearing the stored names. Default off (blank
    /// clears the field).
    pub const UPDATE_PROFILE_REQUIRE_NAMES_ATTRIBUTE: &'static str = "update_profile_require_names";

    /// Whether `UPDATE_PROFILE` requires non-blank first and last names
    /// (default `false`).
    pub fn update_profile_require_names(&self) -> bool {
        self.attributes
            .get(Self::UPDATE_PROFILE_REQUIRE_NAMES_ATTRIBUTE)
            .is_some_and(|v| v == "true")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SslRequired {
    None,
    External,
    All,
}

/// Hash algorithm used for password hashing.
///
/// Supports the two built-in algorithms (`argon2id`, `pbkdf2`) and a
/// forward-compatible `Custom` fallback for algorithms added in the future.
#[derive(Debug, Clone, PartialEq, Eq, utoipa::ToSchema)]
pub enum HashAlgorithm {
    Argon2id,
    Pbkdf2,
    Custom(String),
}

impl HashAlgorithm {
    /// Returns the wire-format string for this algorithm.
    pub fn as_str(&self) -> &str {
        match self {
            HashAlgorithm::Argon2id => "argon2id",
            HashAlgorithm::Pbkdf2 => "pbkdf2",
            HashAlgorithm::Custom(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for HashAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HashAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "argon2id" => Ok(HashAlgorithm::Argon2id),
            "pbkdf2" => Ok(HashAlgorithm::Pbkdf2),
            _ => Ok(HashAlgorithm::Custom(s)),
        }
    }
}

// ---------------------------------------------------------------------------
// PasswordLength
// ---------------------------------------------------------------------------

/// A password length value in the range 1..=128.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct PasswordLength(u32);

impl PasswordLength {
    /// Minimum allowed password length.
    pub const MIN: u32 = 1;
    /// Maximum allowed password length.
    pub const MAX: u32 = 128;

    /// Construct a `PasswordLength` value.
    ///
    /// # Panics
    ///
    /// Panics if `length` is outside the range 1..=128.
    pub const fn new(length: u32) -> Self {
        assert!(length >= Self::MIN && length <= Self::MAX, "PasswordLength out of range");
        Self(length)
    }

    /// Return the underlying `u32` value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<PasswordLength> for u32 {
    fn from(p: PasswordLength) -> Self {
        p.0
    }
}

impl TryFrom<u32> for PasswordLength {
    type Error = IssuerdError;

    fn try_from(length: u32) -> Result<Self, Self::Error> {
        if !(Self::MIN..=Self::MAX).contains(&length) {
            return Err(IssuerdError::InvalidRequest(format!(
                "password length must be between {} and {}",
                Self::MIN,
                Self::MAX
            )));
        }
        Ok(Self(length))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: PasswordLength,
    pub max_length: Option<PasswordLength>,
    pub require_digits: bool,
    pub require_lower: bool,
    pub require_upper: bool,
    pub require_special: bool,
    pub not_username: bool,
    pub not_email: bool,
    pub history_size: u32,
    pub hash_algorithm: HashAlgorithm,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: PasswordLength::new(8),
            max_length: None,
            require_digits: false,
            require_lower: false,
            require_upper: false,
            require_special: false,
            not_username: false,
            not_email: false,
            history_size: 0,
            hash_algorithm: HashAlgorithm::Argon2id,
        }
    }
}

// ---------------------------------------------------------------------------
// OTP (TOTP) policy
// ---------------------------------------------------------------------------

/// HMAC hash algorithm used for TOTP code generation (RFC 6238).
///
/// The serde renames use Keycloak's wire spelling (`HmacSHA1` etc.) so the
/// same mapping serves the admin API, stored realm JSON, and the database
/// column — there is exactly one string representation everywhere.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema,
)]
pub enum OtpHashAlgorithm {
    #[default]
    #[serde(rename = "HmacSHA1")]
    HmacSha1,
    #[serde(rename = "HmacSHA256")]
    HmacSha256,
    #[serde(rename = "HmacSHA512")]
    HmacSha512,
}

impl OtpHashAlgorithm {
    /// Returns the wire-format string for this algorithm (Keycloak spelling).
    pub fn as_str(&self) -> &'static str {
        match self {
            OtpHashAlgorithm::HmacSha1 => "HmacSHA1",
            OtpHashAlgorithm::HmacSha256 => "HmacSHA256",
            OtpHashAlgorithm::HmacSha512 => "HmacSHA512",
        }
    }
}

impl std::str::FromStr for OtpHashAlgorithm {
    type Err = IssuerdError;

    /// Parse the wire-format string (Keycloak spelling).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HmacSHA1" => Ok(OtpHashAlgorithm::HmacSha1),
            "HmacSHA256" => Ok(OtpHashAlgorithm::HmacSha256),
            "HmacSHA512" => Ok(OtpHashAlgorithm::HmacSha512),
            _ => Err(IssuerdError::InvalidRequest(format!("unsupported OTP hash algorithm: {s}"))),
        }
    }
}

impl std::fmt::Display for OtpHashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Realm-level TOTP policy (Keycloak parity: algorithm, digits, period,
/// look-ahead window).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OtpPolicy {
    pub algorithm: OtpHashAlgorithm,
    pub digits: u32,
    pub period_secs: u32,
    pub look_ahead_window: u32,
}

impl Default for OtpPolicy {
    /// Keycloak defaults: HmacSHA1, 6 digits, 30-second period, 1-step
    /// look-ahead window.
    fn default() -> Self {
        Self {
            algorithm: OtpHashAlgorithm::HmacSha1,
            digits: 6,
            period_secs: 30,
            look_ahead_window: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub realm_id: RealmId,
    pub username: Username,
    pub email: Option<Email>,
    pub email_verified: bool,
    pub first_name: Option<DisplayName>,
    pub last_name: Option<DisplayName>,
    pub enabled: bool,
    /// If set, the user is federated from an external provider identified by
    /// this string (e.g. `"ldap-my-ad"`). Users created by identity brokering
    /// are stamped `idp:{alias}` and additionally carry an
    /// [`crate::IdentityProviderLink`] row per linked provider.
    pub federation_link: Option<String>,
    pub attributes: HashMap<String, Vec<String>>,
    /// Required actions assigned to this user (e.g. `"UPDATE_PASSWORD"`,
    /// `"VERIFY_EMAIL"`). Evaluated by the auth flow after successful
    /// authentication; each action is removed once completed.
    #[serde(default)]
    pub required_actions: Vec<String>,
    pub created_at: DateTime<Utc>,
    /// Last modification time. Set equal to `created_at` on creation and
    /// bumped to `Utc::now()` by every storage `update_user` call.
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client protocol per Keycloak domain model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum ClientProtocol {
    #[serde(rename = "openid-connect")]
    OpenIdConnect,
    #[serde(rename = "saml")]
    Saml,
}

/// Client authenticator type per Keycloak domain model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum ClientAuthenticatorType {
    #[serde(rename = "client-secret")]
    ClientSecret,
    #[serde(rename = "client-jwt")]
    ClientJwt,
    #[serde(rename = "client-secret-jwt")]
    ClientSecretJwt,
    #[serde(rename = "client-x509")]
    ClientX509,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    pub id: ClientId,
    pub realm_id: RealmId,
    pub client_id: ClientIdentifier,
    pub name: Option<DisplayName>,
    pub description: Option<String>,
    pub enabled: bool,
    pub protocol: ClientProtocol,
    pub public_client: bool,
    pub bearer_only: bool,
    pub client_authenticator_type: ClientAuthenticatorType,
    pub secret: Option<String>,
    pub redirect_uris: Vec<RedirectUri>,
    pub web_origins: Vec<WebOrigin>,
    pub default_scopes: Scope,
    pub optional_scopes: Scope,
    pub consent_required: bool,
    pub full_scope_allowed: bool,
    /// Whether the client credentials grant is backed by a dedicated
    /// service-account user (`service-account-{client_id}`) that can hold
    /// role mappings. When disabled the grant keeps the legacy synthetic
    /// token (`sub = client_id`, no role claims).
    #[serde(default)]
    pub service_accounts_enabled: bool,
    /// Client-local protocol mappers (Keycloak "dedicated scope" mappers).
    #[serde(default)]
    pub protocol_mappers: Vec<crate::client_scope::ProtocolMapper>,
    /// Per-client role subsetting applied when `full_scope_allowed` is false.
    #[serde(default)]
    pub scope_mappings: crate::client_scope::ScopeMappings,
    pub attributes: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: RoleName,
    pub description: Option<String>,
    pub realm_id: RealmId,
    pub client_role: bool,
    pub client_id: Option<ClientId>,
    pub composite: bool,
    pub composites: Vec<RoleName>,
    pub attributes: HashMap<String, Vec<String>>,
}

// ---------------------------------------------------------------------------
// Group
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub name: GroupName,
    pub path: GroupPath,
    pub realm_id: RealmId,
    pub parent_id: Option<GroupId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_groups: Vec<Group>,
    pub attributes: HashMap<String, Vec<String>>,
    pub realm_roles: Vec<RoleName>,
    pub client_roles: HashMap<ClientId, Vec<RoleName>>,
}

// ---------------------------------------------------------------------------
// Credential
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub id: CredentialId,
    pub credential_type: CredentialType,
    pub user_label: Option<String>,
    pub created_date: DateTime<Utc>,
    pub secret_data: Vec<u8>,
    pub credential_data: serde_json::Value,
    pub priority: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    Password,
    Totp,
    Hotp,
    WebAuthn,
    WebAuthnPasswordless,
    Kerberos,
    SshPublicKey,
    #[serde(untagged)]
    Custom(String),
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Authentication method used to establish a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    Spnego,
    Ciba,
    /// Session established via identity brokering (external OIDC/social IdP).
    IdentityProvider,
    /// Session established by an administrator impersonating the user.
    /// Tokens issued from such sessions carry the impersonator.
    Impersonation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSession {
    pub id: SessionId,
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub login_username: Username,
    pub ip_address: std::net::IpAddr,
    pub auth_method: AuthMethod,
    pub remember_me: bool,
    /// Offline session: created when the granted scopes include
    /// `offline_access`. Offline sessions back `typ: Offline` refresh tokens,
    /// use `Realm.offline_session_idle_timeout` instead of the SSO idle
    /// windows, and survive SSO session expiry/logout.
    #[serde(default)]
    pub offline: bool,
    pub started: DateTime<Utc>,
    pub last_session_refresh: DateTime<Utc>,
    pub auth_time: DateTime<Utc>,
    /// Administrator who impersonated this session; `None` for
    /// regular user logins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonator: Option<UserId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<ClientSession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSession {
    pub id: ClientSessionId,
    pub client_id: ClientId,
    pub session_id: SessionId,
    pub redirect_uri: Option<RedirectUri>,
    pub state: Option<String>,
    pub auth_method: AuthMethod,
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Access / Consent helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmAccess {
    pub roles: Vec<RoleName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAccess {
    pub roles: Vec<RoleName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consent {
    pub client_id: ClientId,
    pub user_id: UserId,
    pub granted_scopes: Scope,
    pub granted_realm_roles: Vec<RoleName>,
    pub granted_client_roles: HashMap<ClientId, Vec<RoleName>>,
    pub created_at: DateTime<Utc>,
    pub last_updated_at: DateTime<Utc>,
}

/// Identity-provider type identifier.
///
/// Covers the built-in provider families (`ldap`, `kerberos`, `oidc`, `saml`,
/// `social`) and a forward-compatible `Custom` fallback.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
pub enum ProviderId {
    #[serde(rename = "ldap")]
    Ldap,
    #[serde(rename = "kerberos")]
    Kerberos,
    #[serde(rename = "oidc")]
    Oidc,
    #[serde(rename = "saml")]
    Saml,
    #[serde(rename = "social")]
    Social,
    #[serde(untagged)]
    Custom(String),
}

impl ProviderId {
    /// Construct a `ProviderId` from a raw string, mapping known values to
    /// their enum variants.
    pub fn new(id: impl Into<String>) -> Self {
        let s = id.into();
        match s.as_str() {
            "ldap" => Self::Ldap,
            "kerberos" => Self::Kerberos,
            "oidc" => Self::Oidc,
            "saml" => Self::Saml,
            "social" => Self::Social,
            _ => Self::Custom(s),
        }
    }

    /// Return the wire-format string for this provider id.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ldap => "ldap",
            Self::Kerberos => "kerberos",
            Self::Oidc => "oidc",
            Self::Saml => "saml",
            Self::Social => "social",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityProviderConfig {
    pub id: IdentityProviderId,
    pub alias: Alias,
    pub provider_id: ProviderId,
    pub enabled: bool,
    pub config: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowConfig {
    pub alias: Alias,
    pub realm_id: RealmId,
    pub provider_id: String,
    pub top_level: bool,
    pub built_in: bool,
    pub stages: Vec<FlowStage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStage {
    pub id: FlowStageId,
    pub requirement: Requirement,
    pub authenticator: Alias,
    pub priority: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_flow_alias: Option<Alias>,
    /// Per-stage authenticator configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_config: Option<AuthenticatorConfig>,
}

/// Configuration attached to a flow stage's authenticator,
/// mirroring Keycloak's `AuthenticatorConfig`: a named alias plus a free-form
/// key/value map consumed by the authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthenticatorConfig {
    pub alias: Alias,
    pub config: serde_json::Map<String, serde_json::Value>,
}

impl Default for AuthenticatorConfig {
    fn default() -> Self {
        Self {
            alias: Alias::new("config").expect("static alias is valid"),
            config: serde_json::Map::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    Required,
    Alternative,
    Optional,
    Disabled,
    Conditional,
}

// ---------------------------------------------------------------------------
// Token / Introspection
// ---------------------------------------------------------------------------

/// OAuth2 token type per RFC 6750.
///
/// Only `Bearer` is standardized; the enum prevents arbitrary strings from
/// appearing in introspection responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    #[serde(rename = "Bearer")]
    Bearer,
    /// DPoP sender-constrained token (RFC 9449) — introspection
    /// responses report this when the access token carries a `cnf.jkt`.
    #[serde(rename = "DPoP")]
    Dpop,
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenType::Bearer => f.write_str("Bearer"),
            TokenType::Dpop => f.write_str("DPoP"),
        }
    }
}

/// JWT token type claim used in access and refresh token payloads.
///
/// Keycloak uses `"Bearer"` for access tokens, `"Refresh"` for online refresh
/// tokens, and `"Offline"` for offline refresh tokens (tokens
/// bound to an offline session rather than the SSO session). The enum
/// prevents arbitrary strings from appearing in token claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum JwtType {
    #[serde(rename = "Bearer")]
    Bearer,
    #[serde(rename = "Refresh")]
    Refresh,
    #[serde(rename = "Offline")]
    Offline,
}

impl std::fmt::Display for JwtType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtType::Bearer => f.write_str("Bearer"),
            JwtType::Refresh => f.write_str("Refresh"),
            JwtType::Offline => f.write_str("Offline"),
        }
    }
}

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

/// An issuer identifier, validated as a non-empty URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Issuer(String);

impl Issuer {
    /// Create a new `Issuer`, validating the input.
    pub fn new(issuer: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = issuer.into();
        if s.is_empty() {
            return Err(IssuerdError::InvalidRequest("issuer must not be empty".into()));
        }
        if Url::parse(&s).is_err() {
            return Err(IssuerdError::InvalidRequest("issuer must be a valid URL".into()));
        }
        Ok(Self(s))
    }

    /// Return the issuer as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Issuer {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl AsRef<str> for Issuer {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Audience
// ---------------------------------------------------------------------------

/// An audience identifier, validated as non-empty.
///
/// Serialization is always a plain string. Deserialization additionally
/// tolerates the JWT multi-audience form (`"aud": ["a", "b"]`), taking the
/// first entry: tokens whose `aud` was extended by an Audience protocol
/// mapper must still deserialize into the claims structs for
/// stateless validation. Audience *checks* never rely on this field alone —
/// `decode_token` enforces a pinned audience via the library, and callers
/// otherwise verify audience themselves.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Audience(String);

impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Single(String),
            Many(Vec<String>),
        }
        let first = match Repr::deserialize(deserializer)? {
            Repr::Single(s) => s,
            Repr::Many(mut v) if !v.is_empty() => v.remove(0),
            Repr::Many(_) => {
                return Err(serde::de::Error::custom("audience must not be empty"));
            }
        };
        Audience::new(first).map_err(serde::de::Error::custom)
    }
}

impl Audience {
    /// Create a new `Audience`, validating the input.
    pub fn new(audience: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = audience.into();
        if s.is_empty() {
            return Err(IssuerdError::InvalidRequest("audience must not be empty".into()));
        }
        Ok(Self(s))
    }

    /// Return the audience as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Audience {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl AsRef<str> for Audience {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::scope::space_separated_opt")]
    pub scope: Option<Scope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<ClientIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<Username>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<TokenType>,
    /// DPoP confirmation claim passthrough (RFC 9449 §6.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaim>,
    /// RAR authorization details assigned to the token (RFC 9396 §9.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<Issuer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<JwtId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutToken {
    pub token: String,
    pub claims: LogoutTokenClaims,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    pub iss: Issuer,
    pub sub: UserId,
    pub aud: Audience,
    pub iat: i64,
    pub jti: JwtId,
    pub events: serde_json::Value,
    pub sid: SessionId,
}

/// RFC 7800 `cnf` (confirmation) claim — the sender-constraining material of
/// a token. Currently only the DPoP JWK thumbprint method (`jkt`, RFC 9449
/// §6.1) is produced; the struct leaves room for further members (e.g.
/// `x5t#S256` for mTLS, RFC 8705).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmationClaim {
    /// RFC 7638 SHA-256 thumbprint of the DPoP public key the token is bound to.
    pub jkt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub jti: JwtId,
    pub iss: Issuer,
    pub sub: UserId,
    pub aud: Audience,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    #[serde(with = "crate::scope::space_separated")]
    pub scope: Scope,
    pub typ: JwtType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_access: Option<RealmAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_access: Option<HashMap<String, ClientAccess>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<SessionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    /// DPoP key binding. Set via the claims overlay at issuance
    /// (the token endpoint merges it after mapper evaluation); typed here so
    /// the validation surface (userinfo, introspection) can read it back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaim>,
    /// RAR authorization details (RFC 9396 §9.1). Injected via
    /// the claims overlay at issuance (same mechanics as `cnf`); typed here so
    /// userinfo and introspection can reflect the granted details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub jti: JwtId,
    pub iss: Issuer,
    pub sub: UserId,
    pub aud: Audience,
    pub exp: i64,
    pub iat: i64,
    pub typ: JwtType,
    pub sid: SessionId,
    #[serde(with = "crate::scope::space_separated")]
    pub scope: Scope,
    /// DPoP key binding (RFC 9449 §5.1): a bound refresh token may
    /// only be redeemed together with a DPoP proof from the same key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaim>,
    /// RAR authorization details of the underlying grant (RFC 9396 §6). The
    /// refresh token is the durable artifact of the grant, so
    /// it carries the granted details; a refresh request may narrow them for
    /// the new access token, but the rotated refresh token keeps this set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<serde_json::Value>>,
}

/// Purpose value for reset-credentials action tokens.
pub const ACTION_TOKEN_PURPOSE_RESET_CREDENTIALS: &str = "reset-credentials";
/// Purpose value for remember-me cookie tokens.
pub const ACTION_TOKEN_PURPOSE_REMEMBER_ME: &str = "remember-me";
/// Purpose value for broker account-linking tokens: authorizes
/// linking an external IdP identity to the user named by `sub`.
pub const ACTION_TOKEN_PURPOSE_BROKER_LINK: &str = "broker-link";
/// Purpose value for execute-actions-email tokens: authorizes
/// running the listed required actions for the user named by `sub`.
pub const ACTION_TOKEN_PURPOSE_EXECUTE_ACTIONS: &str = "execute-actions";

/// Claims for short-lived, single-purpose signed action tokens.
///
/// Action tokens are compact JWS payloads signed with the realm signing key
/// (via `CryptoProvider`) for out-of-band flows such as reset-credentials
/// links and the remember-me cookie. They deliberately do **not** use
/// `AccessTokenClaims`: verification is manual — check the signature,
/// `purpose`, `realm`, and `exp`, and (for single-use flows) consume the
/// `jti` via the distributed cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionTokenClaims {
    /// User id the token acts on.
    pub sub: String,
    /// Realm id the token is bound to.
    pub realm: String,
    /// What the token authorizes (see `ACTION_TOKEN_PURPOSE_*`).
    pub purpose: String,
    pub exp: i64,
    pub iat: i64,
    /// Unique token id; single-use flows track it in the cache.
    pub jti: String,
    /// Original authentication time (remember-me tokens only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: Issuer,
    pub sub: UserId,
    pub aud: Audience,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<Acr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<Amr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<SessionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<Base64Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<Base64Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<DisplayName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<DisplayName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<DisplayName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<Username>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_access: Option<RealmAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_access: Option<HashMap<String, ClientAccess>>,
}

/// JWS header type per RFC 7515.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwsType {
    #[serde(rename = "JWT")]
    Jwt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwsHeader {
    pub alg: Algorithm,
    pub typ: Option<JwsType>,
    pub kid: KeyId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// JWK use value per RFC 7517 Section 4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum JwkUse {
    #[serde(rename = "sig")]
    Sig,
    #[serde(rename = "enc")]
    Enc,
}

/// Key status for key metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum KeyStatus {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "PASSIVE")]
    Passive,
}

/// JWK cryptographic curve per RFC 7518 / RFC 8037.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum JwkCurve {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[serde(rename = "Ed448")]
    Ed448,
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

impl JwkCurve {
    /// Return the wire-name for this curve.
    pub fn as_str(&self) -> &'static str {
        match self {
            JwkCurve::P256 => "P-256",
            JwkCurve::P384 => "P-384",
            JwkCurve::P521 => "P-521",
            JwkCurve::Ed25519 => "Ed25519",
            JwkCurve::Ed448 => "Ed448",
            JwkCurve::Secp256k1 => "secp256k1",
        }
    }
}

impl std::fmt::Display for JwkCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for JwkCurve {
    type Err = IssuerdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "P-256" => Ok(JwkCurve::P256),
            "P-384" => Ok(JwkCurve::P384),
            "P-521" => Ok(JwkCurve::P521),
            "Ed25519" => Ok(JwkCurve::Ed25519),
            "Ed448" => Ok(JwkCurve::Ed448),
            "secp256k1" => Ok(JwkCurve::Secp256k1),
            _ => Err(IssuerdError::InvalidRequest(format!("unsupported JWK curve: {s}"))),
        }
    }
}

/// JWK key type per RFC 7518 Section 6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum JwkKty {
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "EC")]
    Ec,
    #[serde(rename = "oct")]
    Oct,
    #[serde(rename = "OKP")]
    Okp,
}

/// Token type hint for introspection and revocation per RFC 7009 / RFC 7662.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenTypeHint {
    #[serde(rename = "access_token")]
    AccessToken,
    #[serde(rename = "refresh_token")]
    RefreshToken,
}

/// PKCE code challenge method per RFC 7636.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PkceCodeChallengeMethod {
    S256,
    #[serde(rename = "plain")]
    Plain,
}

// ---------------------------------------------------------------------------
// Base64Url
// ---------------------------------------------------------------------------

/// A base64url-encoded string value per RFC 4648 Section 5.
///
/// Validates that the string contains only base64url characters
/// (`A–Z`, `a–z`, `0–9`, `-`, `_`) and optional padding (`=`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(try_from = "String")]
pub struct Base64Url(String);

impl Base64Url {
    /// Create a new `Base64Url`, validating the input.
    pub fn new(value: impl Into<String>) -> Result<Self, IssuerdError> {
        let s = value.into();
        if s.is_empty() {
            return Err(IssuerdError::InvalidRequest("base64url value must not be empty".into()));
        }
        if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=') {
            return Err(IssuerdError::InvalidRequest(
                "base64url value contains invalid characters".into(),
            ));
        }
        Ok(Self(s))
    }

    /// Return the value as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Base64Url {
    type Error = IssuerdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl AsRef<str> for Base64Url {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: JwkKty,
    pub kid: KeyId,
    pub alg: Algorithm,
    #[serde(rename = "use")]
    pub use_: JwkUse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<Base64Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<Base64Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<Base64Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<Base64Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<JwkCurve>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<Base64Url>,
}

/// A signing key persisted in shared storage.
///
/// Contains the **private** key material (PKCS#8 DER). This type must never be
/// exposed through any public API response; only `public_jwk` may leave the
/// server. Multi-node clusters load the shared key set at boot so every node
/// signs with the same active key and validates tokens issued by its peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSigningKey {
    pub kid: KeyId,
    pub alg: Algorithm,
    pub created_at: DateTime<Utc>,
    /// PKCS#8 DER-encoded private key (raw secret bytes for HMAC keys).
    pub private_der: Vec<u8>,
    /// Public half of the key as a JWK (published via JWKS).
    pub public_jwk: Jwk,
    /// Whether the key may be selected for signing. Inactive keys remain
    /// published for validation until tokens signed with them have expired.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn redirect_uri_matches_exact() {
        let registered = RedirectUri::new("https://app.example.com/cb").unwrap();
        assert!(registered.matches("https://app.example.com/cb"));
        assert!(!registered.matches("https://app.example.com/other"));
        assert!(!registered.matches("https://other.example.com/cb"));
    }

    #[test]
    fn redirect_uri_matches_trailing_wildcard() {
        let registered = RedirectUri::new("https://app.example.com/*").unwrap();
        assert!(registered.matches("https://app.example.com/cb"));
        assert!(registered.matches("https://app.example.com/a/b/c?x=1"));
        // …but not a different host or a sibling path — the `/` before `*`
        // anchors the boundary.
        assert!(!registered.matches("https://evil.example.com/cb"));
        assert!(!registered.matches("https://app.example.com.evil.example/cb"));
        assert!(!registered.matches("https://app.example.com"));
    }

    #[test]
    fn redirect_uri_wildcard_only_honored_trailing() {
        // An interior `*` is literal, not a wildcard.
        let registered = RedirectUri::new("https://app.example.com/*/cb").unwrap();
        assert!(!registered.matches("https://app.example.com/a/cb"));
        assert!(registered.matches("https://app.example.com/*/cb"));
    }

    // ------------------------------------------------------------------
    // Serde roundtrip helpers
    // ------------------------------------------------------------------
    fn roundtrip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
        value: &T,
    ) {
        let json = serde_json::to_string(value).unwrap();
        let back: T = serde_json::from_str(&json).unwrap();
        assert_eq!(*value, back);
    }

    // ------------------------------------------------------------------
    // Realm
    // ------------------------------------------------------------------
    #[test]
    fn realm_roundtrip() {
        let r = Realm {
            id: RealmId::new("realm-1").unwrap(),
            name: RealmName::new("test").unwrap(),
            display_name: Some(DisplayName::new("Test Realm").unwrap()),
            enabled: true,
            ssl_required: SslRequired::External,
            password_policy: PasswordPolicy::default(),
            login_theme: None,
            email_theme: Some(ThemeName::new("keycloak").unwrap()),
            admin_theme: None,
            internationalization_enabled: true,
            supported_locales: vec!["en".to_string(), "de".to_string()],
            default_locale: Some("en".to_string()),
            default_role: Some("default-roles-test".to_string()),
            access_token_lifespan: SecondsNonZero::new(300),
            refresh_token_lifespan: SecondsNonZero::new(1800),
            sso_session_idle_timeout: SecondsNonZero::new(1800),
            sso_session_max_lifespan: SecondsNonZero::new(36000),
            offline_session_idle_timeout: SecondsNonZero::new(2592000),
            brute_force_protected: true,
            max_login_failures: 7,
            wait_increment_secs: 30,
            max_failure_wait_secs: 600,
            lockout_duration_secs: 1200,
            registration_enabled: true,
            reset_password_allowed: true,
            remember_me_enabled: true,
            verify_email_enabled: true,
            login_with_email_allowed: false,
            duplicate_emails_allowed: true,
            edit_username_allowed: false,
            remember_me_session_idle_secs: SecondsNonZero::new(604_800),
            otp_policy: OtpPolicy {
                algorithm: OtpHashAlgorithm::HmacSha256,
                digits: 8,
                period_secs: 60,
                look_ahead_window: 2,
            },
            events_enabled: true,
            events_expiration_secs: 3600,
            admin_events_enabled: true,
            include_representations: true,
            events_listeners: vec!["logging".to_string(), "audit".to_string()],
            not_before: 1_700_000_000,
            default_groups: vec!["/newcomers".to_string()],
            browser_flow: Some("custom-browser".to_string()),
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: Some("custom-registration".to_string()),
            attributes: {
                let mut m = HashMap::new();
                m.insert("key".to_string(), "value".to_string());
                m
            },
        };
        roundtrip(&r);
    }

    #[test]
    fn realm_default() {
        let r = Realm::default();
        assert!(r.enabled);
        assert_eq!(r.access_token_lifespan, 300);
    }

    #[test]
    fn realm_known_good_json() {
        let json = r#"{
            "id": "realm-1",
            "name": "test",
            "display_name": "Test Realm",
            "enabled": true,
            "ssl_required": "external",
            "password_policy": {
                "min_length": 8,
                "max_length": null,
                "require_digits": false,
                "require_lower": false,
                "require_upper": false,
                "require_special": false,
                "not_username": false,
                "not_email": false,
                "history_size": 0,
                "hash_algorithm": "argon2id"
            },
            "login_theme": null,
            "email_theme": "keycloak",
            "admin_theme": null,
            "default_role": "default-roles-test",
            "access_token_lifespan": 300,
            "refresh_token_lifespan": 1800,
            "sso_session_idle_timeout": 1800,
            "sso_session_max_lifespan": 36000,
            "offline_session_idle_timeout": 2592000,
            "attributes": {"key": "value"}
        }"#;
        let r: Realm = serde_json::from_str(json).unwrap();
        assert_eq!(r.id, RealmId::new("realm-1").unwrap());
        assert_eq!(r.name, "test");
        assert_eq!(r.display_name, Some(DisplayName::new("Test Realm").unwrap()));
        assert!(r.enabled);
        assert_eq!(r.ssl_required, SslRequired::External);
        assert_eq!(r.default_role, Some("default-roles-test".to_string()));
        assert_eq!(r.attributes.get("key"), Some(&"value".to_string()));
    }

    // ------------------------------------------------------------------
    // OtpPolicy / OtpHashAlgorithm
    // ------------------------------------------------------------------
    #[test]
    fn otp_policy_defaults_match_keycloak() {
        let p = OtpPolicy::default();
        assert_eq!(p.algorithm, OtpHashAlgorithm::HmacSha1);
        assert_eq!(p.digits, 6);
        assert_eq!(p.period_secs, 30);
        assert_eq!(p.look_ahead_window, 1);
    }

    #[test]
    fn otp_hash_algorithm_uses_keycloak_wire_spelling() {
        assert_eq!(OtpHashAlgorithm::HmacSha1.as_str(), "HmacSHA1");
        assert_eq!(OtpHashAlgorithm::HmacSha256.as_str(), "HmacSHA256");
        assert_eq!(OtpHashAlgorithm::HmacSha512.as_str(), "HmacSHA512");
        assert_eq!("HmacSHA1".parse::<OtpHashAlgorithm>(), Ok(OtpHashAlgorithm::HmacSha1));
        assert_eq!("HmacSHA256".parse::<OtpHashAlgorithm>(), Ok(OtpHashAlgorithm::HmacSha256));
        assert_eq!("HmacSHA512".parse::<OtpHashAlgorithm>(), Ok(OtpHashAlgorithm::HmacSha512));
        assert!("SHA1".parse::<OtpHashAlgorithm>().is_err());
        assert!("hmacsha1".parse::<OtpHashAlgorithm>().is_err());
        assert_eq!(OtpHashAlgorithm::default(), OtpHashAlgorithm::HmacSha1);
        assert_eq!(OtpHashAlgorithm::HmacSha256.to_string(), "HmacSHA256");
    }

    #[test]
    fn otp_hash_algorithm_serde_roundtrip() {
        for variant in [
            OtpHashAlgorithm::HmacSha1,
            OtpHashAlgorithm::HmacSha256,
            OtpHashAlgorithm::HmacSha512,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, format!("\"{}\"", variant.as_str()));
            let back: OtpHashAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn otp_policy_serde_roundtrip() {
        let p = OtpPolicy {
            algorithm: OtpHashAlgorithm::HmacSha512,
            digits: 8,
            period_secs: 45,
            look_ahead_window: 3,
        };
        roundtrip(&p);
    }

    #[test]
    fn realm_without_otp_policy_deserializes_to_default() {
        // Older stored realms (and the known-good JSON above) carry no
        // otp_policy field; the serde default must fill it in.
        let json = r#"{
            "id": "realm-1",
            "name": "test",
            "enabled": true,
            "ssl_required": "external",
            "password_policy": {
                "min_length": 8,
                "max_length": null,
                "require_digits": false,
                "require_lower": false,
                "require_upper": false,
                "require_special": false,
                "not_username": false,
                "not_email": false,
                "history_size": 0,
                "hash_algorithm": "argon2id"
            },
            "access_token_lifespan": 300,
            "refresh_token_lifespan": 1800,
            "sso_session_idle_timeout": 1800,
            "sso_session_max_lifespan": 36000,
            "offline_session_idle_timeout": 2592000,
            "attributes": {}
        }"#;
        let r: Realm = serde_json::from_str(json).unwrap();
        assert_eq!(r.otp_policy, OtpPolicy::default());
    }

    #[test]
    fn realm_without_i18n_fields_deserializes_to_defaults() {
        // Older stored realms (pre-internationalization) carry no i18n
        // fields; the serde defaults must fill them in.
        let json = r#"{
            "id": "realm-1",
            "name": "test",
            "enabled": true,
            "ssl_required": "external",
            "password_policy": {
                "min_length": 8,
                "max_length": null,
                "require_digits": false,
                "require_lower": false,
                "require_upper": false,
                "require_special": false,
                "not_username": false,
                "not_email": false,
                "history_size": 0,
                "hash_algorithm": "argon2id"
            },
            "access_token_lifespan": 300,
            "refresh_token_lifespan": 1800,
            "sso_session_idle_timeout": 1800,
            "sso_session_max_lifespan": 36000,
            "offline_session_idle_timeout": 2592000,
            "attributes": {}
        }"#;
        let r: Realm = serde_json::from_str(json).unwrap();
        assert!(!r.internationalization_enabled);
        assert!(r.supported_locales.is_empty());
        assert_eq!(r.default_locale, None);
    }

    #[test]
    fn realm_without_admin_depth_fields_deserializes_to_defaults() {
        // Older stored realms (pre-events-config) carry no events config,
        // not-before, default groups, or flow bindings; the serde defaults
        // must fill them in with the model defaults.
        let json = r#"{
            "id": "realm-1",
            "name": "test",
            "enabled": true,
            "ssl_required": "external",
            "password_policy": {
                "min_length": 8,
                "max_length": null,
                "require_digits": false,
                "require_lower": false,
                "require_upper": false,
                "require_special": false,
                "not_username": false,
                "not_email": false,
                "history_size": 0,
                "hash_algorithm": "argon2id"
            },
            "access_token_lifespan": 300,
            "refresh_token_lifespan": 1800,
            "sso_session_idle_timeout": 1800,
            "sso_session_max_lifespan": 36000,
            "offline_session_idle_timeout": 2592000,
            "attributes": {}
        }"#;
        let r: Realm = serde_json::from_str(json).unwrap();
        assert!(r.events_enabled);
        assert_eq!(r.events_expiration_secs, 0);
        assert!(r.admin_events_enabled);
        assert!(!r.include_representations);
        assert_eq!(r.events_listeners, vec!["logging".to_string()]);
        assert_eq!(r.not_before, 0);
        assert!(r.default_groups.is_empty());
        assert_eq!(r.browser_flow, None);
        assert_eq!(r.direct_grant_flow, None);
        assert_eq!(r.reset_credentials_flow, None);
        assert_eq!(r.first_broker_login_flow, None);
        assert_eq!(r.registration_flow, None);
    }

    // ------------------------------------------------------------------
    // HashAlgorithm
    // ------------------------------------------------------------------
    #[test]
    fn hash_algorithm_roundtrip() {
        for variant in [
            HashAlgorithm::Argon2id,
            HashAlgorithm::Pbkdf2,
            HashAlgorithm::Custom("future-algo".to_string()),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: HashAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn hash_algorithm_custom_fallback() {
        let back: HashAlgorithm = serde_json::from_str("\"scrypt\"").unwrap();
        assert_eq!(back, HashAlgorithm::Custom("scrypt".to_string()));
    }

    #[test]
    fn hash_algorithm_display() {
        assert_eq!(HashAlgorithm::Argon2id.to_string(), "argon2id");
        assert_eq!(HashAlgorithm::Pbkdf2.to_string(), "pbkdf2");
        assert_eq!(HashAlgorithm::Custom("scrypt".to_string()).to_string(), "scrypt");
    }

    // ------------------------------------------------------------------
    // PasswordPolicy
    // ------------------------------------------------------------------
    #[test]
    fn password_policy_roundtrip() {
        roundtrip(&PasswordPolicy::default());
    }

    // ------------------------------------------------------------------
    // User
    // ------------------------------------------------------------------
    #[test]
    fn user_roundtrip() {
        let u = User {
            id: UserId::new("user-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: Some(DisplayName::new("Smith").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: {
                let mut m = HashMap::new();
                m.insert("locale".to_string(), vec!["en".to_string()]);
                m
            },
            required_actions: vec!["VERIFY_EMAIL".to_string()],
            created_at: now(),
            updated_at: now(),
        };
        roundtrip(&u);
    }

    #[test]
    fn user_known_good_json() {
        let json = r#"{
            "id": "user-1",
            "realm_id": "realm-1",
            "username": "alice",
            "email": "alice@example.com",
            "email_verified": true,
            "first_name": "Alice",
            "last_name": "Smith",
            "enabled": true,
            "federation_link": null,
            "attributes": {"locale": ["en"]},
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-16T11:45:00Z"
        }"#;
        let u: User = serde_json::from_str(json).unwrap();
        assert_eq!(u.id, UserId::new("user-1").unwrap());
        assert_eq!(u.username, "alice");
        assert_eq!(u.email, Some(Email::new("alice@example.com").unwrap()));
        assert!(u.email_verified);
    }

    // ------------------------------------------------------------------
    // Client
    // ------------------------------------------------------------------
    #[test]
    fn client_roundtrip() {
        let c = Client {
            id: ClientId::new("client-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: Some(DisplayName::new("My App").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![RedirectUri::new("https://app.example.com/callback").unwrap()],
            web_origins: vec![WebOrigin::new("https://app.example.com").unwrap()],
            default_scopes: Scope::from(vec!["openid".to_string(), "profile".to_string()]),
            optional_scopes: Scope::from(vec!["email".to_string()]),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        roundtrip(&c);
    }

    // ------------------------------------------------------------------
    // Role
    // ------------------------------------------------------------------
    #[test]
    fn role_roundtrip() {
        let r = Role {
            id: RoleId::new("role-1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: Some("Administrator".to_string()),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: true,
            composites: vec![RoleName::new("role-2").unwrap()],
            attributes: HashMap::new(),
        };
        roundtrip(&r);
    }

    // ------------------------------------------------------------------
    // Group
    // ------------------------------------------------------------------
    #[test]
    fn group_roundtrip() {
        let g = Group {
            id: GroupId::new("group-1").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: GroupPath::new("/admins").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![RoleName::new("admin").unwrap()],
            client_roles: HashMap::new(),
        };
        roundtrip(&g);
    }

    #[test]
    fn group_with_nested_subgroups() {
        let g = Group {
            id: GroupId::new("group-1").unwrap(),
            name: GroupName::new("org").unwrap(),
            path: GroupPath::new("/org").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            parent_id: None,
            sub_groups: vec![Group {
                id: GroupId::new("group-2").unwrap(),
                name: GroupName::new("engineering").unwrap(),
                path: GroupPath::new("/org/engineering").unwrap(),
                realm_id: RealmId::new("realm-1").unwrap(),
                parent_id: Some(GroupId::new("group-1").unwrap()),
                sub_groups: vec![],
                attributes: HashMap::new(),
                realm_roles: vec![],
                client_roles: HashMap::new(),
            }],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        roundtrip(&g);
    }

    // ------------------------------------------------------------------
    // Credential
    // ------------------------------------------------------------------
    #[test]
    fn credential_roundtrip() {
        let c = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: Some("My password".to_string()),
            created_date: now(),
            secret_data: vec![1, 2, 3],
            credential_data: serde_json::json!({"hash": "abc123"}),
            priority: 1,
        };
        roundtrip(&c);
    }

    // ------------------------------------------------------------------
    // CredentialType
    // ------------------------------------------------------------------
    #[test]
    fn credential_type_builtin_variants_serialize_to_snake_case() {
        assert_eq!(serde_json::to_string(&CredentialType::Password).unwrap(), "\"password\"");
        assert_eq!(serde_json::to_string(&CredentialType::Totp).unwrap(), "\"totp\"");
        assert_eq!(serde_json::to_string(&CredentialType::Hotp).unwrap(), "\"hotp\"");
        assert_eq!(serde_json::to_string(&CredentialType::WebAuthn).unwrap(), "\"web_authn\"");
        assert_eq!(
            serde_json::to_string(&CredentialType::WebAuthnPasswordless).unwrap(),
            "\"web_authn_passwordless\""
        );
        assert_eq!(serde_json::to_string(&CredentialType::Kerberos).unwrap(), "\"kerberos\"");
        assert_eq!(
            serde_json::to_string(&CredentialType::SshPublicKey).unwrap(),
            "\"ssh_public_key\""
        );
    }

    #[test]
    fn credential_type_custom_roundtrip() {
        let ct = CredentialType::Custom("yubikey".to_string());
        let json = serde_json::to_string(&ct).unwrap();
        let back: CredentialType = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, back);
    }

    // ------------------------------------------------------------------
    // UserSession & ClientSession
    // ------------------------------------------------------------------
    #[test]
    fn user_session_roundtrip() {
        let s = UserSession {
            id: SessionId::new("session-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            user_id: UserId::new("user-1").unwrap(),
            login_username: Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: now(),
            last_session_refresh: now(),
            auth_time: now(),
            impersonator: None,
            clients: vec![],
        };
        roundtrip(&s);
    }

    #[test]
    fn client_session_roundtrip() {
        let cs = ClientSession {
            id: ClientSessionId::new("cs-1").unwrap(),
            client_id: ClientId::new("client-1").unwrap(),
            session_id: SessionId::new("session-1").unwrap(),
            redirect_uri: Some(RedirectUri::new("https://app.example.com").unwrap()),
            state: Some("xyz".to_string()),
            auth_method: AuthMethod::Password,
            timestamp: now(),
        };
        roundtrip(&cs);
    }

    // ------------------------------------------------------------------
    // RealmAccess & ClientAccess
    // ------------------------------------------------------------------
    #[test]
    fn realm_access_roundtrip() {
        roundtrip(&RealmAccess {
            roles: vec![
                RoleName::new("admin").unwrap(),
                RoleName::new("user").unwrap(),
            ],
        });
    }

    #[test]
    fn client_access_roundtrip() {
        roundtrip(&ClientAccess {
            roles: vec![RoleName::new("read").unwrap()],
        });
    }

    // ------------------------------------------------------------------
    // Consent
    // ------------------------------------------------------------------
    #[test]
    fn consent_roundtrip() {
        let c = Consent {
            client_id: ClientId::new("client-1").unwrap(),
            user_id: UserId::new("user-1").unwrap(),
            granted_scopes: Scope::from(vec!["openid".to_string(), "profile".to_string()]),
            granted_realm_roles: vec![RoleName::new("user").unwrap()],
            granted_client_roles: {
                let mut m = HashMap::new();
                m.insert(ClientId::new("client-1").unwrap(), vec![RoleName::new("read").unwrap()]);
                m
            },
            created_at: now(),
            last_updated_at: now(),
        };
        roundtrip(&c);
    }

    // ------------------------------------------------------------------
    // IdentityProviderConfig
    // ------------------------------------------------------------------
    #[test]
    fn identity_provider_config_roundtrip() {
        let idp = IdentityProviderConfig {
            id: IdentityProviderId::new("idp-1").unwrap(),
            alias: Alias::new("google").unwrap(),
            provider_id: ProviderId::new("google"),
            enabled: true,
            config: {
                let mut m = HashMap::new();
                m.insert("clientId".to_string(), "123".to_string());
                m
            },
        };
        roundtrip(&idp);
    }

    // ------------------------------------------------------------------
    // FlowConfig & FlowStage
    // ------------------------------------------------------------------
    #[test]
    fn flow_config_roundtrip() {
        let fc = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                FlowStage {
                    id: FlowStageId::new("stage-1").unwrap(),
                    requirement: Requirement::Required,
                    authenticator: Alias::new("auth-cookie").unwrap(),
                    priority: 1,
                    sub_flow_alias: None,
                    authenticator_config: None,
                },
                FlowStage {
                    id: FlowStageId::new("stage-2").unwrap(),
                    requirement: Requirement::Required,
                    authenticator: Alias::new("sub-flow").unwrap(),
                    priority: 2,
                    sub_flow_alias: Some(Alias::new("nested").unwrap()),
                    authenticator_config: None,
                },
            ],
        };
        roundtrip(&fc);
    }

    #[test]
    fn requirement_roundtrip() {
        roundtrip(&Requirement::Required);
        roundtrip(&Requirement::Alternative);
        roundtrip(&Requirement::Optional);
        roundtrip(&Requirement::Disabled);
        roundtrip(&Requirement::Conditional);
    }

    // ------------------------------------------------------------------
    // IntrospectionResponse
    // ------------------------------------------------------------------
    #[test]
    fn introspection_response_roundtrip() {
        let ir = IntrospectionResponse {
            active: true,
            scope: Some(Scope::parse("openid profile")),
            client_id: Some(ClientIdentifier::new("client-1").unwrap()),
            username: Some(Username::new("alice").unwrap()),
            token_type: Some(TokenType::Bearer),
            cnf: Some(ConfirmationClaim {
                jkt: "dpop-thumbprint".to_string(),
            }),
            exp: Some(1234567890),
            iat: Some(1234567800),
            nbf: Some(1234567800),
            sub: Some("user-1".to_string()),
            aud: Some(Audience::new("client-1").unwrap()),
            iss: Some(Issuer::new("https://auth.example.com").unwrap()),
            jti: Some(JwtId::new("token-1").unwrap()),
            authorization_details: Some(vec![serde_json::json!({
                "type": "payment_initiation",
                "actions": ["initiate"]
            })]),
        };
        roundtrip(&ir);
    }

    #[test]
    fn token_type_bearer_serializes_to_title_case() {
        let json = serde_json::to_string(&TokenType::Bearer).unwrap();
        assert_eq!(json, "\"Bearer\"");
        let back: TokenType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TokenType::Bearer);
    }

    #[test]
    fn token_type_display_matches_wire_name() {
        assert_eq!(TokenType::Bearer.to_string(), "Bearer");
    }

    // ------------------------------------------------------------------
    // LogoutTokenClaims
    // ------------------------------------------------------------------
    #[test]
    fn logout_token_claims_roundtrip() {
        let ltc = LogoutTokenClaims {
            iss: Issuer::new("https://auth.example.com").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("client-1").unwrap(),
            iat: 1234567890,
            jti: JwtId::new("jti-1").unwrap(),
            events: serde_json::json!({"http://schemas.openid.net/event/backchannel-logout": {}}),
            sid: SessionId::new("session-1").unwrap(),
        };
        roundtrip(&ltc);
    }

    // ------------------------------------------------------------------
    // AccessTokenClaims
    // ------------------------------------------------------------------
    #[test]
    fn access_token_claims_roundtrip() {
        let atc = AccessTokenClaims {
            jti: JwtId::new("jti-1").unwrap(),
            iss: Issuer::new("https://auth.example.com").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("client-1").unwrap(),
            exp: 1234567890,
            iat: 1234567800,
            nbf: 1234567800,
            scope: Scope::parse("openid profile"),
            typ: JwtType::Bearer,
            azp: Some("client-1".to_string()),
            session_state: Some("state-1".to_string()),
            realm_access: Some(RealmAccess {
                roles: vec![RoleName::new("user").unwrap()],
            }),
            resource_access: Some({
                let mut m = HashMap::new();
                m.insert(
                    "client-1".to_string(),
                    ClientAccess {
                        roles: vec![RoleName::new("read").unwrap()],
                    },
                );
                m
            }),
            sid: Some(SessionId::new("session-1").unwrap()),
            claims: None,
            cnf: Some(ConfirmationClaim {
                jkt: "dpop-thumbprint".to_string(),
            }),
            authorization_details: Some(vec![serde_json::json!({
                "type": "account_information",
                "actions": ["list_accounts"]
            })]),
        };
        roundtrip(&atc);
    }

    // ------------------------------------------------------------------
    // IdTokenClaims
    // ------------------------------------------------------------------
    #[test]
    fn id_token_claims_roundtrip() {
        let idtc = IdTokenClaims {
            iss: Issuer::new("https://auth.example.com").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("client-1").unwrap(),
            exp: 1234567890,
            iat: 1234567800,
            auth_time: Some(1234567800),
            nonce: Some(Nonce::new("nonce-1").unwrap()),
            acr: Some(Acr::new("1").unwrap()),
            amr: Some(vec![Amr::Password]),
            azp: Some("client-1".to_string()),
            sid: Some(SessionId::new("session-1").unwrap()),
            at_hash: Some(Base64Url::new("at_hash").unwrap()),
            c_hash: Some(Base64Url::new("c_hash").unwrap()),
            name: Some(DisplayName::new("Alice Smith").unwrap()),
            given_name: Some(DisplayName::new("Alice").unwrap()),
            family_name: Some(DisplayName::new("Smith").unwrap()),
            preferred_username: Some(Username::new("alice").unwrap()),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: Some(true),
            address: Some(AddressClaim {
                formatted: Some("123 Main St".to_string()),
                street_address: Some("123 Main St".to_string()),
                locality: Some("Springfield".to_string()),
                region: Some("IL".to_string()),
                postal_code: Some("62701".to_string()),
                country: Some("USA".to_string()),
            }),
            phone_number: Some("+1-555-123-4567".to_string()),
            phone_number_verified: Some(true),
            realm_access: Some(RealmAccess {
                roles: vec![RoleName::new("user").unwrap()],
            }),
            resource_access: Some({
                let mut m = HashMap::new();
                m.insert(
                    "client-1".to_string(),
                    ClientAccess {
                        roles: vec![RoleName::new("read").unwrap()],
                    },
                );
                m
            }),
        };
        roundtrip(&idtc);
    }

    // ------------------------------------------------------------------
    // JwsHeader, JwkSet, Jwk
    // ------------------------------------------------------------------
    #[test]
    fn jws_header_roundtrip() {
        roundtrip(&JwsHeader {
            alg: Algorithm::Rs256,
            typ: Some(JwsType::Jwt),
            kid: KeyId::new("key-1").unwrap(),
        });
    }

    #[test]
    fn jwk_set_roundtrip() {
        let jwk = Jwk {
            kty: JwkKty::Rsa,
            kid: KeyId::new("key-1").unwrap(),
            alg: Algorithm::Rs256,
            use_: JwkUse::Sig,
            n: Some(Base64Url::new("bW9kdWx1cw").unwrap()),
            e: Some(Base64Url::new("AQAB").unwrap()),
            x: None,
            y: None,
            crv: None,
            k: None,
        };
        roundtrip(&JwkSet { keys: vec![jwk] });
    }

    #[test]
    fn jwk_ec_roundtrip() {
        let jwk = Jwk {
            kty: JwkKty::Ec,
            kid: KeyId::new("key-ec").unwrap(),
            alg: Algorithm::Es256,
            use_: JwkUse::Sig,
            n: None,
            e: None,
            x: Some(Base64Url::new("x-val").unwrap()),
            y: Some(Base64Url::new("y-val").unwrap()),
            crv: Some(JwkCurve::P256),
            k: None,
        };
        roundtrip(&jwk);
    }

    #[test]
    fn jwk_serializes_alg_as_jwt_string() {
        let jwk = Jwk {
            kty: JwkKty::Rsa,
            kid: KeyId::new("key-1").unwrap(),
            alg: Algorithm::EdDsa,
            use_: JwkUse::Sig,
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
            k: None,
        };
        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("\"alg\":\"EdDSA\""));
    }

    // ------------------------------------------------------------------
    // SecondsNonZero
    // ------------------------------------------------------------------
    #[test]
    fn seconds_non_zero_try_from_zero_fails() {
        assert!(SecondsNonZero::try_from(0u64).is_err());
    }

    #[test]
    fn seconds_non_zero_try_from_negative_i64_fails() {
        assert!(SecondsNonZero::try_from(-1i64).is_err());
    }

    #[test]
    fn seconds_non_zero_deref_and_eq() {
        let s = SecondsNonZero::new(300);
        assert_eq!(*s, 300u64);
        assert_eq!(s, 300u64);
        assert_eq!(300u64, s);
    }

    #[test]
    fn seconds_non_zero_into_u64() {
        let s = SecondsNonZero::new(60);
        let n: u64 = s.into();
        assert_eq!(n, 60);
    }

    // ------------------------------------------------------------------
    // Username validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn username_empty_fails() {
        assert!(Username::new("").is_err());
        assert!(Username::new("   ").is_err());
    }

    #[test]
    fn username_too_long_fails() {
        let long = "a".repeat(256);
        assert!(Username::new(&long).is_err());
    }

    #[test]
    fn username_control_char_fails() {
        assert!(Username::new("user\x00name").is_err());
    }

    #[test]
    fn username_success_and_traits() {
        let u = Username::new("  alice  ").unwrap();
        assert_eq!(u.as_str(), "alice");
        assert_eq!(u.to_string(), "alice");
        assert_eq!(&*u, "alice");
        assert_eq!(u.as_ref(), "alice");
        assert_eq!(u, "alice");
        // reverse partial_eq not implemented
        assert_eq!(u.as_str(), "alice");
        assert_eq!(Username::try_from("alice".to_string()).unwrap(), u);
        assert_eq!(Username::try_from("alice").unwrap(), u);
    }

    // ------------------------------------------------------------------
    // Email validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn email_empty_fails() {
        assert!(Email::new("").is_err());
    }

    #[test]
    fn email_too_long_fails() {
        let local = "a".repeat(250);
        assert!(Email::new(format!("{}@b.com", local)).is_err());
    }

    #[test]
    fn email_no_at_fails() {
        assert!(Email::new("alice.example.com").is_err());
    }

    #[test]
    fn email_multiple_at_fails() {
        assert!(Email::new("a@b@c.com").is_err());
    }

    #[test]
    fn email_empty_local_fails() {
        assert!(Email::new("@example.com").is_err());
    }

    #[test]
    fn email_no_dot_in_domain_fails() {
        assert!(Email::new("alice@example").is_err());
    }

    #[test]
    fn email_success_and_traits() {
        let e = Email::new("alice@example.com").unwrap();
        assert_eq!(e.as_str(), "alice@example.com");
        assert_eq!(e.to_string(), "alice@example.com");
        assert_eq!(&*e, "alice@example.com");
        assert_eq!(e.as_ref(), "alice@example.com");
        assert_eq!(e, "alice@example.com");
        // reverse partial_eq not implemented
        assert_eq!(Email::try_from("alice@example.com".to_string()).unwrap(), e);
    }

    // ------------------------------------------------------------------
    // ClientIdentifier validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn client_identifier_empty_fails() {
        assert!(ClientIdentifier::new("").is_err());
    }

    #[test]
    fn client_identifier_too_long_fails() {
        assert!(ClientIdentifier::new("a".repeat(256)).is_err());
    }

    #[test]
    fn client_identifier_control_char_fails() {
        assert!(ClientIdentifier::new("id\x01").is_err());
    }

    #[test]
    fn client_identifier_success_and_traits() {
        let c = ClientIdentifier::new("my-app").unwrap();
        assert_eq!(c.as_str(), "my-app");
        assert_eq!(c.to_string(), "my-app");
        assert_eq!(&*c, "my-app");
        assert_eq!(c.as_ref(), "my-app");
        assert_eq!(c, "my-app");
        // reverse partial_eq not implemented
    }

    // ------------------------------------------------------------------
    // RedirectUri validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn redirect_uri_invalid_url_fails() {
        assert!(RedirectUri::new("not-a-url").is_err());
    }

    #[test]
    fn redirect_uri_success_and_traits() {
        let r = RedirectUri::new("https://app.example.com/cb").unwrap();
        assert_eq!(r.as_str(), "https://app.example.com/cb");
        assert_eq!(r.to_string(), "https://app.example.com/cb");
        assert_eq!(&*r, "https://app.example.com/cb");
        assert_eq!(r.as_ref(), "https://app.example.com/cb");
        assert_eq!(r, "https://app.example.com/cb");
        // reverse partial_eq not implemented
    }

    // ------------------------------------------------------------------
    // RealmName validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn realm_name_empty_fails() {
        assert!(RealmName::new("").is_err());
    }

    #[test]
    fn realm_name_too_long_fails() {
        assert!(RealmName::new("a".repeat(256)).is_err());
    }

    #[test]
    fn realm_name_control_char_fails() {
        assert!(RealmName::new("r\x00").is_err());
    }

    #[test]
    fn realm_name_whitespace_fails() {
        assert!(RealmName::new("my realm").is_err());
        assert!(RealmName::new("my\trealm").is_err());
        assert!(RealmName::new("my\nrealm").is_err());
    }

    #[test]
    fn realm_name_non_ascii_fails() {
        // Discovery percent-encodes non-ASCII via `Url::parse` while token
        // `iss` embeds the name raw — the two would diverge.
        assert!(RealmName::new("rëalm").is_err());
        assert!(RealmName::new("领域").is_err());
    }

    #[test]
    fn realm_name_url_reserved_fails() {
        for bad in ["a/b", "a\\b", "a?b", "a#b", "a%b", "a+b", "a&b", "a=b"] {
            assert!(RealmName::new(bad).is_err(), "expected {bad:?} to fail");
        }
    }

    #[test]
    fn realm_name_valid_url_segment_passes() {
        for good in ["master", "demo", "tenant-1", "acme_corp", "realm.dev"] {
            assert!(RealmName::new(good).is_ok(), "expected {good:?} to pass");
        }
    }

    #[test]
    fn realm_name_success_and_traits() {
        let r = RealmName::new("master").unwrap();
        assert_eq!(r.as_str(), "master");
        assert_eq!(r.to_string(), "master");
        assert_eq!(r.as_ref(), "master");
        assert_eq!(r, "master");
        // reverse partial_eq not implemented
        assert_eq!(RealmName::try_from("master".to_string()).unwrap(), r);
    }

    // ------------------------------------------------------------------
    // Acr validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn acr_empty_fails() {
        assert!(Acr::new("").is_err());
        assert!(Acr::new("   ").is_err());
    }

    #[test]
    fn acr_success_and_traits() {
        let a = Acr::new("1").unwrap();
        assert_eq!(a.as_str(), "1");
        assert_eq!(a.to_string(), "1");
        assert_eq!(a.as_ref(), "1");
        assert_eq!(Acr::try_from("1".to_string()).unwrap(), a);
    }

    // ------------------------------------------------------------------
    // WebOrigin validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn web_origin_empty_fails() {
        assert!(WebOrigin::new("").is_err());
    }

    #[test]
    fn web_origin_invalid_url_fails() {
        assert!(WebOrigin::new("://bad").is_err());
    }

    #[test]
    fn web_origin_wildcard_succeeds() {
        let w = WebOrigin::new("*").unwrap();
        assert_eq!(w.as_str(), "*");
    }

    #[test]
    fn web_origin_success_and_traits() {
        let o = WebOrigin::new("https://app.example.com").unwrap();
        assert_eq!(o.as_str(), "https://app.example.com");
        assert_eq!(o.to_string(), "https://app.example.com");
        assert_eq!(o.as_ref(), "https://app.example.com");
        assert_eq!(WebOrigin::try_from("https://app.example.com".to_string()).unwrap(), o);
    }

    // ------------------------------------------------------------------
    // GroupPath validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn group_path_empty_fails() {
        assert!(GroupPath::new("").is_err());
    }

    #[test]
    fn group_path_no_leading_slash_fails() {
        assert!(GroupPath::new("admins").is_err());
    }

    #[test]
    fn group_path_control_char_fails() {
        assert!(GroupPath::new("/adm\x00ins").is_err());
    }

    #[test]
    fn group_path_success_and_traits() {
        let p = GroupPath::new("/admins").unwrap();
        assert_eq!(p.as_str(), "/admins");
        assert_eq!(p.to_string(), "/admins");
        assert_eq!(p.as_ref(), "/admins");
        assert_eq!(GroupPath::try_from("/admins".to_string()).unwrap(), p);
    }

    // ------------------------------------------------------------------
    // ThemeName validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn theme_name_empty_fails() {
        assert!(ThemeName::new("").is_err());
    }

    #[test]
    fn theme_name_too_long_fails() {
        assert!(ThemeName::new("a".repeat(256)).is_err());
    }

    #[test]
    fn theme_name_control_char_fails() {
        assert!(ThemeName::new("t\x00").is_err());
    }

    #[test]
    fn theme_name_path_separator_fails() {
        assert!(ThemeName::new("a/b").is_err());
        assert!(ThemeName::new("a\\b").is_err());
    }

    #[test]
    fn theme_name_success_and_traits() {
        let t = ThemeName::new("keycloak").unwrap();
        assert_eq!(t.as_str(), "keycloak");
        assert_eq!(t.to_string(), "keycloak");
        assert_eq!(&*t, "keycloak");
        assert_eq!(t.as_ref(), "keycloak");
        assert_eq!(t, "keycloak");
        // reverse partial_eq not implemented
    }

    // ------------------------------------------------------------------
    // DisplayName validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn display_name_empty_fails() {
        assert!(DisplayName::new("").is_err());
    }

    #[test]
    fn display_name_too_long_fails() {
        assert!(DisplayName::new("a".repeat(256)).is_err());
    }

    #[test]
    fn display_name_control_char_fails() {
        assert!(DisplayName::new("n\x00").is_err());
    }

    #[test]
    fn display_name_success_and_traits() {
        let d = DisplayName::new("Alice").unwrap();
        assert_eq!(d.as_str(), "Alice");
        assert_eq!(d.to_string(), "Alice");
        assert_eq!(&*d, "Alice");
        assert_eq!(d.as_ref(), "Alice");
        assert_eq!(d, "Alice");
        // reverse partial_eq not implemented
    }

    // ------------------------------------------------------------------
    // AuthorizationCode validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn authorization_code_empty_fails() {
        assert!(AuthorizationCode::new("").is_err());
    }

    #[test]
    fn authorization_code_too_long_fails() {
        assert!(AuthorizationCode::new("a".repeat(2049)).is_err());
    }

    #[test]
    fn authorization_code_control_char_fails() {
        assert!(AuthorizationCode::new("c\x00").is_err());
    }

    #[test]
    fn authorization_code_success_and_traits() {
        let c = AuthorizationCode::new("code-123").unwrap();
        assert_eq!(c.as_str(), "code-123");
        assert_eq!(c.to_string(), "code-123");
        assert_eq!(&*c, "code-123");
        assert_eq!(c.as_ref(), "code-123");
    }

    // ------------------------------------------------------------------
    // ClientSecret validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn client_secret_empty_fails() {
        assert!(ClientSecret::new("").is_err());
    }

    #[test]
    fn client_secret_too_long_fails() {
        assert!(ClientSecret::new("a".repeat(2049)).is_err());
    }

    #[test]
    fn client_secret_control_char_fails() {
        assert!(ClientSecret::new("s\x00").is_err());
    }

    #[test]
    fn client_secret_success_and_traits() {
        let s = ClientSecret::new("secret").unwrap();
        assert_eq!(s.as_str(), "secret");
        assert_eq!(s.to_string(), "secret");
        assert_eq!(&*s, "secret");
        assert_eq!(s.as_ref(), "secret");
    }

    // ------------------------------------------------------------------
    // RefreshToken validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn refresh_token_empty_fails() {
        assert!(RefreshToken::new("").is_err());
    }

    #[test]
    fn refresh_token_too_long_fails() {
        assert!(RefreshToken::new("a".repeat(8193)).is_err());
    }

    #[test]
    fn refresh_token_control_char_fails() {
        assert!(RefreshToken::new("t\x00").is_err());
    }

    #[test]
    fn refresh_token_success_and_traits() {
        let t = RefreshToken::new("rt-123").unwrap();
        assert_eq!(t.as_str(), "rt-123");
        assert_eq!(t.to_string(), "rt-123");
        assert_eq!(&*t, "rt-123");
        assert_eq!(t.as_ref(), "rt-123");
    }

    // ------------------------------------------------------------------
    // Password validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn password_empty_fails() {
        assert!(Password::new("").is_err());
    }

    #[test]
    fn password_too_long_fails() {
        assert!(Password::new("a".repeat(4097)).is_err());
    }

    #[test]
    fn password_control_char_fails() {
        assert!(Password::new("p\x00").is_err());
    }

    #[test]
    fn password_success_and_traits() {
        let p = Password::new("hunter2").unwrap();
        assert_eq!(p.as_str(), "hunter2");
        assert_eq!(p.to_string(), "hunter2");
        assert_eq!(&*p, "hunter2");
        assert_eq!(p.as_ref(), "hunter2");
    }

    // ------------------------------------------------------------------
    // Assertion validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn assertion_empty_fails() {
        assert!(Assertion::new("").is_err());
    }

    #[test]
    fn assertion_too_long_fails() {
        assert!(Assertion::new("a".repeat(65537)).is_err());
    }

    #[test]
    fn assertion_control_char_fails() {
        assert!(Assertion::new("a\x00").is_err());
    }

    #[test]
    fn assertion_success_and_traits() {
        let a = Assertion::new("assertion-123").unwrap();
        assert_eq!(a.as_str(), "assertion-123");
        assert_eq!(a.to_string(), "assertion-123");
        assert_eq!(&*a, "assertion-123");
        assert_eq!(a.as_ref(), "assertion-123");
    }

    // ------------------------------------------------------------------
    // ClaimName validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn claim_name_empty_fails() {
        assert!(ClaimName::new("").is_err());
    }

    #[test]
    fn claim_name_too_long_fails() {
        assert!(ClaimName::new("a".repeat(256)).is_err());
    }

    #[test]
    fn claim_name_control_char_fails() {
        assert!(ClaimName::new("c\x00").is_err());
    }

    #[test]
    fn claim_name_success_and_traits() {
        let c = ClaimName::new("email").unwrap();
        assert_eq!(c.as_str(), "email");
        assert_eq!(c.to_string(), "email");
        assert_eq!(&*c, "email");
        assert_eq!(c.as_ref(), "email");
        assert_eq!(c, "email");
        // reverse partial_eq not implemented
    }

    // ------------------------------------------------------------------
    // Alias validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn alias_empty_fails() {
        assert!(Alias::new("").is_err());
    }

    #[test]
    fn alias_too_long_fails() {
        assert!(Alias::new("a".repeat(256)).is_err());
    }

    #[test]
    fn alias_control_char_fails() {
        assert!(Alias::new("a\x00").is_err());
    }

    #[test]
    fn alias_success_and_traits() {
        let a = Alias::new("browser").unwrap();
        assert_eq!(a.as_str(), "browser");
        assert_eq!(a.to_string(), "browser");
        assert_eq!(&*a, "browser");
        assert_eq!(a.as_ref(), "browser");
        assert_eq!(a, "browser");
    }

    // ------------------------------------------------------------------
    // Nonce validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn nonce_empty_fails() {
        assert!(Nonce::new("").is_err());
    }

    #[test]
    fn nonce_too_long_fails() {
        assert!(Nonce::new("a".repeat(256)).is_err());
    }

    #[test]
    fn nonce_control_char_fails() {
        assert!(Nonce::new("n\x00").is_err());
    }

    #[test]
    fn nonce_success_and_traits() {
        let n = Nonce::new("nonce-123").unwrap();
        assert_eq!(n.as_str(), "nonce-123");
        assert_eq!(n.to_string(), "nonce-123");
        assert_eq!(&*n, "nonce-123");
        assert_eq!(n.as_ref(), "nonce-123");
        assert_eq!(n, "nonce-123");
    }

    // ------------------------------------------------------------------
    // RoleName validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn role_name_empty_fails() {
        assert!(RoleName::new("").is_err());
    }

    #[test]
    fn role_name_too_long_fails() {
        assert!(RoleName::new("a".repeat(256)).is_err());
    }

    #[test]
    fn role_name_control_char_fails() {
        assert!(RoleName::new("r\x00").is_err());
    }

    #[test]
    fn role_name_success_and_traits() {
        let r = RoleName::new("admin").unwrap();
        assert_eq!(r.as_str(), "admin");
        assert_eq!(r.to_string(), "admin");
        assert_eq!(r.as_ref(), "admin");
        assert_eq!(r.as_str(), "admin");
    }

    // ------------------------------------------------------------------
    // PasswordLength
    // ------------------------------------------------------------------
    #[test]
    fn password_length_try_from_zero_fails() {
        assert!(PasswordLength::try_from(0u32).is_err());
    }

    #[test]
    fn password_length_try_from_too_large_fails() {
        assert!(PasswordLength::try_from(129u32).is_err());
    }

    #[test]
    fn password_length_success_and_traits() {
        let p = PasswordLength::new(12);
        assert_eq!(p.get(), 12);
        assert_eq!(u32::from(p), 12);
        assert_eq!(PasswordLength::try_from(12u32).unwrap(), p);
    }

    // ------------------------------------------------------------------
    // Amr
    // ------------------------------------------------------------------
    #[test]
    fn amr_all_variants_as_str() {
        let cases = [
            (Amr::Password, "pwd"),
            (Amr::Otp, "otp"),
            (Amr::Sms, "sms"),
            (Amr::Tel, "tel"),
            (Amr::SoftwareKey, "swk"),
            (Amr::HardwareKey, "hwk"),
            (Amr::Mfa, "mfa"),
            (Amr::SmartCard, "sc"),
            (Amr::Biometric, "ba"),
            (Amr::UserPresence, "user"),
            (Amr::Pin, "pin"),
            (Amr::Fingerprint, "fpt"),
            (Amr::Face, "face"),
            (Amr::Fido, "fido"),
            (Amr::RecoveryKey, "rk"),
            (Amr::Custom("x".to_string()), "x"),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.as_str(), expected);
            assert_eq!(variant.to_string(), expected);
        }
    }

    // ------------------------------------------------------------------
    // SslRequired
    // ------------------------------------------------------------------
    #[test]
    fn ssl_required_serde_roundtrip() {
        for variant in [SslRequired::None, SslRequired::External, SslRequired::All] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: SslRequired = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ------------------------------------------------------------------
    // HashAlgorithm as_str
    // ------------------------------------------------------------------
    #[test]
    fn hash_algorithm_as_str() {
        assert_eq!(HashAlgorithm::Argon2id.as_str(), "argon2id");
        assert_eq!(HashAlgorithm::Pbkdf2.as_str(), "pbkdf2");
        assert_eq!(HashAlgorithm::Custom("scrypt".to_string()).as_str(), "scrypt");
    }

    // ------------------------------------------------------------------
    // Issuer validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn issuer_empty_fails() {
        assert!(Issuer::new("").is_err());
    }

    #[test]
    fn issuer_invalid_url_fails() {
        assert!(Issuer::new("not a url").is_err());
    }

    #[test]
    fn issuer_success_and_traits() {
        let i = Issuer::new("https://auth.example.com").unwrap();
        assert_eq!(i.as_str(), "https://auth.example.com");
        assert_eq!(i.as_ref(), "https://auth.example.com");
        assert_eq!(Issuer::try_from("https://auth.example.com".to_string()).unwrap(), i);
    }

    // ------------------------------------------------------------------
    // Audience validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn audience_empty_fails() {
        assert!(Audience::new("").is_err());
    }

    #[test]
    fn audience_success_and_traits() {
        let a = Audience::new("client-1").unwrap();
        assert_eq!(a.as_str(), "client-1");
        assert_eq!(a.as_ref(), "client-1");
        assert_eq!(Audience::try_from("client-1".to_string()).unwrap(), a);
    }

    // ------------------------------------------------------------------
    // Base64Url validation & traits
    // ------------------------------------------------------------------
    #[test]
    fn base64_url_empty_fails() {
        assert!(Base64Url::new("").is_err());
    }

    #[test]
    fn base64_url_invalid_char_fails() {
        assert!(Base64Url::new("bad@chars").is_err());
        assert!(Base64Url::new("bad+chars").is_err());
    }

    #[test]
    fn base64_url_success_and_traits() {
        let b = Base64Url::new("abc123-_").unwrap();
        assert_eq!(b.as_str(), "abc123-_");
        assert_eq!(b.as_ref(), "abc123-_");
        assert_eq!(Base64Url::try_from("abc123-_".to_string()).unwrap(), b);
    }

    // ------------------------------------------------------------------
    // JwkCurve
    // ------------------------------------------------------------------
    #[test]
    fn jwk_curve_from_str_error() {
        assert!("unknown".parse::<JwkCurve>().is_err());
    }

    #[test]
    fn jwk_curve_display_all() {
        assert_eq!(JwkCurve::P256.to_string(), "P-256");
        assert_eq!(JwkCurve::P384.to_string(), "P-384");
        assert_eq!(JwkCurve::P521.to_string(), "P-521");
        assert_eq!(JwkCurve::Ed25519.to_string(), "Ed25519");
        assert_eq!(JwkCurve::Ed448.to_string(), "Ed448");
        assert_eq!(JwkCurve::Secp256k1.to_string(), "secp256k1");
    }

    // ------------------------------------------------------------------
    // ProviderId
    // ------------------------------------------------------------------
    #[test]
    fn provider_id_builtin_and_custom() {
        assert_eq!(ProviderId::new("ldap"), ProviderId::Ldap);
        assert_eq!(ProviderId::new("kerberos"), ProviderId::Kerberos);
        assert_eq!(ProviderId::new("oidc"), ProviderId::Oidc);
        assert_eq!(ProviderId::new("saml"), ProviderId::Saml);
        assert_eq!(ProviderId::new("social"), ProviderId::Social);
        assert_eq!(ProviderId::new("custom"), ProviderId::Custom("custom".to_string()));
    }

    #[test]
    fn provider_id_as_str_and_display() {
        assert_eq!(ProviderId::Ldap.as_str(), "ldap");
        assert_eq!(ProviderId::Kerberos.as_str(), "kerberos");
        assert_eq!(ProviderId::Oidc.as_str(), "oidc");
        assert_eq!(ProviderId::Saml.as_str(), "saml");
        assert_eq!(ProviderId::Social.as_str(), "social");
        assert_eq!(ProviderId::Custom("x".to_string()).as_str(), "x");
        assert_eq!(ProviderId::new("ldap").to_string(), "ldap");
    }

    // ------------------------------------------------------------------
    // Enum serde roundtrips
    // ------------------------------------------------------------------
    #[test]
    fn client_protocol_roundtrip() {
        roundtrip(&ClientProtocol::OpenIdConnect);
        roundtrip(&ClientProtocol::Saml);
    }

    #[test]
    fn client_authenticator_type_roundtrip() {
        roundtrip(&ClientAuthenticatorType::ClientSecret);
        roundtrip(&ClientAuthenticatorType::ClientJwt);
        roundtrip(&ClientAuthenticatorType::ClientSecretJwt);
        roundtrip(&ClientAuthenticatorType::ClientX509);
    }

    #[test]
    fn requirement_roundtrip_all() {
        roundtrip(&Requirement::Required);
        roundtrip(&Requirement::Alternative);
        roundtrip(&Requirement::Optional);
        roundtrip(&Requirement::Disabled);
        roundtrip(&Requirement::Conditional);
    }

    #[test]
    fn token_type_roundtrip() {
        roundtrip(&TokenType::Bearer);
    }

    #[test]
    fn jwt_type_display_and_roundtrip() {
        assert_eq!(JwtType::Bearer.to_string(), "Bearer");
        assert_eq!(JwtType::Refresh.to_string(), "Refresh");
        roundtrip(&JwtType::Bearer);
        roundtrip(&JwtType::Refresh);
    }

    #[test]
    fn pkce_code_challenge_method_roundtrip() {
        roundtrip(&PkceCodeChallengeMethod::S256);
        roundtrip(&PkceCodeChallengeMethod::Plain);
    }

    #[test]
    fn token_type_hint_roundtrip() {
        roundtrip(&TokenTypeHint::AccessToken);
        roundtrip(&TokenTypeHint::RefreshToken);
    }

    #[test]
    fn jwk_use_roundtrip() {
        roundtrip(&JwkUse::Sig);
        roundtrip(&JwkUse::Enc);
    }

    #[test]
    fn key_status_roundtrip() {
        roundtrip(&KeyStatus::Active);
        roundtrip(&KeyStatus::Passive);
    }

    // ------------------------------------------------------------------
    // Deref for types that have it but weren't tested
    // ------------------------------------------------------------------
    #[test]
    fn authorization_code_deref() {
        let c = AuthorizationCode::new("code").unwrap();
        assert_eq!(&*c, "code");
    }

    #[test]
    fn client_secret_deref() {
        let s = ClientSecret::new("secret").unwrap();
        assert_eq!(&*s, "secret");
    }

    #[test]
    fn refresh_token_deref() {
        let t = RefreshToken::new("rt").unwrap();
        assert_eq!(&*t, "rt");
    }

    #[test]
    fn assertion_deref() {
        let a = Assertion::new("assert").unwrap();
        assert_eq!(&*a, "assert");
    }

    #[test]
    fn claim_name_deref() {
        let c = ClaimName::new("email").unwrap();
        assert_eq!(&*c, "email");
    }

    // ------------------------------------------------------------------
    // Reverse PartialEq via AsRef<str>
    // ------------------------------------------------------------------
    #[test]
    fn username_reverse_eq() {
        let u = Username::new("alice").unwrap();
        assert!(u.as_ref() == "alice");
    }

    #[test]
    fn email_reverse_eq() {
        let e = Email::new("a@b.com").unwrap();
        assert!(e.as_ref() == "a@b.com");
    }

    #[test]
    fn client_identifier_reverse_eq() {
        let c = ClientIdentifier::new("app").unwrap();
        assert!(c.as_ref() == "app");
    }

    #[test]
    fn realm_name_reverse_eq() {
        let r = RealmName::new("master").unwrap();
        assert!(r.as_ref() == "master");
    }

    #[test]
    fn display_name_reverse_eq() {
        let d = DisplayName::new("Alice").unwrap();
        assert!(d.as_ref() == "Alice");
    }

    #[test]
    fn theme_name_reverse_eq() {
        let t = ThemeName::new("keycloak").unwrap();
        assert!(t.as_ref() == "keycloak");
    }

    #[test]
    fn acr_reverse_eq() {
        let a = Acr::new("1").unwrap();
        assert!(a.as_ref() == "1");
    }

    #[test]
    fn web_origin_reverse_eq() {
        let o = WebOrigin::new("https://app.example.com").unwrap();
        assert!(o.as_ref() == "https://app.example.com");
    }

    #[test]
    fn group_path_reverse_eq() {
        let p = GroupPath::new("/admins").unwrap();
        assert!(p.as_ref() == "/admins");
    }

    #[test]
    fn alias_reverse_eq() {
        let a = Alias::new("browser").unwrap();
        assert!(a.as_ref() == "browser");
    }

    #[test]
    fn nonce_reverse_eq() {
        let n = Nonce::new("nonce").unwrap();
        assert!(n.as_ref() == "nonce");
    }

    #[test]
    fn role_name_reverse_eq() {
        let r = RoleName::new("admin").unwrap();
        assert!(r.as_ref() == "admin");
    }

    #[test]
    fn password_length_from_u32() {
        let p = PasswordLength::new(12);
        let n: u32 = p.into();
        assert_eq!(n, 12);
    }

    #[test]
    fn seconds_non_zero_partial_eq_u64_reverse() {
        let s = SecondsNonZero::new(300);
        assert_eq!(300u64, s);
    }

    #[test]
    fn redirect_uri_reverse_eq() {
        // Stored value is the normalized URL serialization (trailing slash).
        let r = RedirectUri::new("https://app.example.com").unwrap();
        assert!(r.as_ref() == "https://app.example.com/");
    }

    #[test]
    fn realm_ssl_required_none_json() {
        let json = r#"{"id":"r","name":"test","enabled":true,"ssl_required":"none","password_policy":{"min_length":8,"max_length":null,"require_digits":false,"require_lower":false,"require_upper":false,"require_special":false,"not_username":false,"not_email":false,"history_size":0,"hash_algorithm":"argon2id"},"access_token_lifespan":300,"refresh_token_lifespan":1800,"sso_session_idle_timeout":1800,"sso_session_max_lifespan":36000,"offline_session_idle_timeout":2592000,"attributes":{}}"#;
        let r: Realm = serde_json::from_str(json).unwrap();
        assert!(matches!(r.ssl_required, SslRequired::None));
    }

    #[test]
    fn realm_ssl_required_all_json() {
        let json = r#"{"id":"r","name":"test","enabled":true,"ssl_required":"all","password_policy":{"min_length":8,"max_length":null,"require_digits":false,"require_lower":false,"require_upper":false,"require_special":false,"not_username":false,"not_email":false,"history_size":0,"hash_algorithm":"argon2id"},"access_token_lifespan":300,"refresh_token_lifespan":1800,"sso_session_idle_timeout":1800,"sso_session_max_lifespan":36000,"offline_session_idle_timeout":2592000,"attributes":{}}"#;
        let r: Realm = serde_json::from_str(json).unwrap();
        assert!(matches!(r.ssl_required, SslRequired::All));
    }

    #[test]
    fn realm_authorization_details_types_attribute() {
        let mut realm = Realm::default();
        assert_eq!(realm.authorization_details_types(), None);

        realm.attributes.insert(
            Realm::AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE.to_string(),
            "payment_initiation account_information".to_string(),
        );
        assert_eq!(
            realm.authorization_details_types(),
            Some(vec![
                "payment_initiation".to_string(),
                "account_information".to_string()
            ])
        );

        // Empty/whitespace-only values behave like an unset attribute.
        realm
            .attributes
            .insert(Realm::AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE.to_string(), "  ".to_string());
        assert_eq!(realm.authorization_details_types(), None);
    }

    #[test]
    fn realm_dynamic_client_registration_attribute() {
        let mut realm = Realm::default();
        assert!(!realm.dynamic_client_registration_enabled());

        realm
            .attributes
            .insert(Realm::DYNAMIC_CLIENT_REGISTRATION_ATTRIBUTE.to_string(), "true".to_string());
        assert!(realm.dynamic_client_registration_enabled());

        // Anything other than the exact string "true" is off.
        realm
            .attributes
            .insert(Realm::DYNAMIC_CLIENT_REGISTRATION_ATTRIBUTE.to_string(), "yes".to_string());
        assert!(!realm.dynamic_client_registration_enabled());
    }

    #[test]
    fn realm_form_requirement_attributes() {
        let mut realm = Realm::default();
        assert!(!realm.registration_require_names());
        assert!(!realm.registration_passwordless());
        assert!(!realm.update_profile_require_names());

        let cases: [(&'static str, fn(&Realm) -> bool); 3] = [
            (Realm::REGISTRATION_REQUIRE_NAMES_ATTRIBUTE, Realm::registration_require_names),
            (Realm::REGISTRATION_PASSWORDLESS_ATTRIBUTE, Realm::registration_passwordless),
            (
                Realm::UPDATE_PROFILE_REQUIRE_NAMES_ATTRIBUTE,
                Realm::update_profile_require_names,
            ),
        ];
        for (key, check) in cases {
            realm.attributes.insert(key.to_string(), "true".to_string());
            assert!(check(&realm), "{key} = true must enable the flag");
            // Anything other than the exact string "true" is off.
            realm.attributes.insert(key.to_string(), "yes".to_string());
            assert!(!check(&realm), "{key} = yes must not enable the flag");
            realm.attributes.remove(key);
        }
    }

    #[test]
    fn realm_default_signature_algorithm_attribute() {
        let mut realm = Realm::default();
        assert_eq!(realm.default_signature_algorithm(), None);

        realm
            .attributes
            .insert(Realm::DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE.to_string(), "ES256".to_string());
        assert_eq!(realm.default_signature_algorithm(), Some(crate::Algorithm::Es256));

        // Unknown values are ignored (fall back to the default signing key).
        realm
            .attributes
            .insert(Realm::DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE.to_string(), "FOOBAR".to_string());
        assert_eq!(realm.default_signature_algorithm(), None);

        // Symmetric (HMAC) values are ignored: HS* keys publish no usable
        // public material, so realm token signing never selects them.
        realm
            .attributes
            .insert(Realm::DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE.to_string(), "HS256".to_string());
        assert_eq!(realm.default_signature_algorithm(), None);
    }

    #[test]
    fn client_saml_protocol_roundtrip() {
        let c = Client {
            id: ClientId::new("client-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::Saml,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientX509,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        roundtrip(&c);
    }

    #[test]
    fn password_policy_custom_values() {
        let pp = PasswordPolicy {
            min_length: PasswordLength::new(12),
            max_length: Some(PasswordLength::new(64)),
            require_digits: true,
            require_lower: true,
            require_upper: true,
            require_special: true,
            not_username: true,
            not_email: true,
            history_size: 5,
            hash_algorithm: HashAlgorithm::Pbkdf2,
        };
        roundtrip(&pp);
    }

    #[test]
    fn user_with_federation_link_roundtrip() {
        let u = User {
            id: UserId::new("user-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            username: Username::new("alice").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: Some("ldap-ad".to_string()),
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: now(),
            updated_at: now(),
        };
        roundtrip(&u);
    }

    #[test]
    fn id_token_claims_minimal_roundtrip() {
        let idtc = IdTokenClaims {
            iss: Issuer::new("https://auth.example.com").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("client-1").unwrap(),
            exp: 1234567890,
            iat: 1234567800,
            auth_time: None,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            sid: None,
            at_hash: None,
            c_hash: None,
            name: None,
            given_name: None,
            family_name: None,
            preferred_username: None,
            email: None,
            email_verified: None,
            address: None,
            phone_number: None,
            phone_number_verified: None,
            realm_access: None,
            resource_access: None,
        };
        roundtrip(&idtc);
    }

    #[test]
    fn access_token_claims_minimal_roundtrip() {
        let atc = AccessTokenClaims {
            jti: JwtId::new("jti-1").unwrap(),
            iss: Issuer::new("https://auth.example.com").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("client-1").unwrap(),
            exp: 1234567890,
            iat: 1234567800,
            nbf: 1234567800,
            scope: Scope::parse("openid"),
            typ: JwtType::Bearer,
            azp: None,
            session_state: None,
            realm_access: None,
            resource_access: None,
            sid: None,
            claims: None,
            cnf: None,
            authorization_details: None,
        };
        roundtrip(&atc);
    }

    #[test]
    fn refresh_token_claims_roundtrip() {
        let rtc = RefreshTokenClaims {
            jti: JwtId::new("jti-1").unwrap(),
            iss: Issuer::new("https://auth.example.com").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("client-1").unwrap(),
            exp: 1234567890,
            iat: 1234567800,
            typ: JwtType::Refresh,
            sid: SessionId::new("session-1").unwrap(),
            scope: Scope::parse("openid"),
            cnf: Some(ConfirmationClaim {
                jkt: "dpop-thumbprint".to_string(),
            }),
            authorization_details: Some(vec![serde_json::json!({"type": "payment_initiation"})]),
        };
        roundtrip(&rtc);
    }

    #[test]
    fn logout_token_roundtrip() {
        let lt = LogoutToken {
            token: "jwt".to_string(),
            claims: LogoutTokenClaims {
                iss: Issuer::new("https://auth.example.com").unwrap(),
                sub: UserId::new("user-1").unwrap(),
                aud: Audience::new("client-1").unwrap(),
                iat: 1234567890,
                jti: JwtId::new("jti-1").unwrap(),
                events: serde_json::json!({"http://schemas.openid.net/event/backchannel-logout": {}}),
                sid: SessionId::new("session-1").unwrap(),
            },
        };
        roundtrip(&lt);
    }

    // ------------------------------------------------------------------
    // Validation type TryFrom<&str> and PartialEq<str> coverage
    // ------------------------------------------------------------------

    #[test]
    fn validation_type_try_from_str_and_partial_eq() {
        let u = Username::new("alice").unwrap();
        assert_eq!(Username::try_from("alice").unwrap(), u);
        assert_eq!(Username::try_from("alice".to_string()).unwrap(), u);
        assert_eq!(u, "alice");
        assert!(PartialEq::<str>::eq(&u, "alice"));
        assert!(PartialEq::<Username>::eq("alice", &u));

        let e = Email::new("a@b.com").unwrap();
        assert_eq!(Email::try_from("a@b.com").unwrap(), e);
        assert_eq!(Email::try_from("a@b.com".to_string()).unwrap(), e);
        assert_eq!(e, "a@b.com");
        assert!(PartialEq::<str>::eq(&e, "a@b.com"));
        assert!(PartialEq::<Email>::eq("a@b.com", &e));

        let c = ClientIdentifier::new("my-app").unwrap();
        assert_eq!(ClientIdentifier::try_from("my-app").unwrap(), c);
        assert_eq!(ClientIdentifier::try_from("my-app".to_string()).unwrap(), c);
        assert_eq!(c, "my-app");
        assert!(PartialEq::<str>::eq(&c, "my-app"));
        assert!(PartialEq::<ClientIdentifier>::eq("my-app", &c));

        let r = RedirectUri::new("https://app.example.com").unwrap();
        assert_eq!(RedirectUri::try_from("https://app.example.com").unwrap(), r);
        assert_eq!(RedirectUri::try_from("https://app.example.com".to_string()).unwrap(), r);
        assert_eq!(r, "https://app.example.com/");
        assert!(PartialEq::<str>::eq(&r, "https://app.example.com/"));
        assert!(PartialEq::<RedirectUri>::eq("https://app.example.com/", &r));

        let rn = RealmName::new("test").unwrap();
        assert_eq!(RealmName::try_from("test").unwrap(), rn);
        assert_eq!(RealmName::try_from("test".to_string()).unwrap(), rn);
        assert_eq!(rn, "test");
        assert!(PartialEq::<str>::eq(&rn, "test"));
        assert!(PartialEq::<RealmName>::eq("test", &rn));

        let a = Acr::new("1").unwrap();
        assert_eq!(Acr::try_from("1").unwrap(), a);
        assert_eq!(Acr::try_from("1".to_string()).unwrap(), a);

        let wo = WebOrigin::new("https://app.example.com").unwrap();
        assert_eq!(WebOrigin::try_from("https://app.example.com").unwrap(), wo);
        assert_eq!(WebOrigin::try_from("https://app.example.com".to_string()).unwrap(), wo);

        let gp = GroupPath::new("/admins").unwrap();
        assert_eq!(GroupPath::try_from("/admins").unwrap(), gp);
        assert_eq!(GroupPath::try_from("/admins".to_string()).unwrap(), gp);

        let tn = ThemeName::new("keycloak").unwrap();
        assert_eq!(ThemeName::try_from("keycloak").unwrap(), tn);
        assert_eq!(ThemeName::try_from("keycloak".to_string()).unwrap(), tn);
        assert_eq!(tn, "keycloak");
        assert!(PartialEq::<str>::eq(&tn, "keycloak"));
        assert!(PartialEq::<ThemeName>::eq("keycloak", &tn));

        let dn = DisplayName::new("Test").unwrap();
        assert_eq!(DisplayName::try_from("Test").unwrap(), dn);
        assert_eq!(DisplayName::try_from("Test".to_string()).unwrap(), dn);
        assert_eq!(dn, "Test");
        assert!(PartialEq::<str>::eq(&dn, "Test"));
        assert!(PartialEq::<DisplayName>::eq("Test", &dn));

        let ac = AuthorizationCode::new("code").unwrap();
        assert_eq!(AuthorizationCode::try_from("code").unwrap(), ac);
        assert_eq!(AuthorizationCode::try_from("code".to_string()).unwrap(), ac);

        let cs = ClientSecret::new("secret").unwrap();
        assert_eq!(ClientSecret::try_from("secret").unwrap(), cs);
        assert_eq!(ClientSecret::try_from("secret".to_string()).unwrap(), cs);

        let rt = RefreshToken::new("rt").unwrap();
        assert_eq!(RefreshToken::try_from("rt").unwrap(), rt);
        assert_eq!(RefreshToken::try_from("rt".to_string()).unwrap(), rt);

        let pw = Password::new("pw").unwrap();
        assert_eq!(Password::try_from("pw").unwrap(), pw);
        assert_eq!(Password::try_from("pw".to_string()).unwrap(), pw);

        let asr = Assertion::new("assert").unwrap();
        assert_eq!(Assertion::try_from("assert").unwrap(), asr);
        assert_eq!(Assertion::try_from("assert".to_string()).unwrap(), asr);

        let cn = ClaimName::new("claim").unwrap();
        assert_eq!(ClaimName::try_from("claim").unwrap(), cn);
        assert_eq!(ClaimName::try_from("claim".to_string()).unwrap(), cn);
        assert_eq!(cn, "claim");
        assert!(PartialEq::<str>::eq(&cn, "claim"));
        assert!(PartialEq::<ClaimName>::eq("claim", &cn));

        let al = Alias::new("alias").unwrap();
        assert_eq!(Alias::try_from("alias").unwrap(), al);
        assert_eq!(Alias::try_from("alias".to_string()).unwrap(), al);
        assert_eq!(al, "alias");
        assert!(PartialEq::<str>::eq(&al, "alias"));
        assert!(PartialEq::<Alias>::eq("alias", &al));

        let n = Nonce::new("nonce").unwrap();
        assert_eq!(Nonce::try_from("nonce").unwrap(), n);
        assert_eq!(Nonce::try_from("nonce".to_string()).unwrap(), n);
        assert_eq!(n, "nonce");
        assert!(PartialEq::<str>::eq(&n, "nonce"));
        assert!(PartialEq::<Nonce>::eq("nonce", &n));

        let ro = RoleName::new("admin").unwrap();
        assert_eq!(RoleName::try_from("admin").unwrap(), ro);
        assert_eq!(RoleName::try_from("admin".to_string()).unwrap(), ro);
    }
}
