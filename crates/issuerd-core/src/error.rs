// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Error types: IssuerdError, OAuth2Error, and OAuth2/OIDC error codes with protocol mapping.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Standard OAuth2 / OIDC error code per RFC 6749 / RFC 6750 / OIDC Core.
///
/// Using an enum makes invalid error codes unrepresentable: the compiler rejects
/// `OAuth2ErrorCode::new("totally_invalid")` at compile time, and serde can only
/// deserialize known variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2ErrorCode {
    /// RFC 6749 Section 5.2
    InvalidRequest,
    /// RFC 6749 Section 5.2
    UnauthorizedClient,
    /// RFC 6749 Section 5.2
    AccessDenied,
    /// RFC 6749 Section 4.1.2.1
    UnsupportedResponseType,
    /// RFC 6749 Section 5.2
    InvalidScope,
    /// RFC 6749 Section 5.2
    ServerError,
    /// RFC 6749 Section 4.1.2.1
    TemporarilyUnavailable,
    /// RFC 6749 Section 5.2
    InvalidGrant,
    /// RFC 6750 Section 3.1
    InvalidToken,
    /// RFC 6750 Section 3.1
    InsufficientScope,
    /// Custom Issuerd extension for operations that are not supported.
    UnsupportedOperation,
    /// OIDC Core Section 3.1.2.6
    LoginRequired,
    /// OIDC Core Section 3.1.2.6 — user consent is required but cannot be
    /// requested (e.g. `prompt=none`).
    ConsentRequired,
    /// OIDC Core Section 3.3.2.6
    RequestNotSupported,
    /// RFC 9449 Section 5.1 — the DPoP proof JWT is invalid (bad signature,
    /// `htm`/`htu` mismatch, stale `iat`, replayed `jti`, ...).
    InvalidDpopProof,
    /// RFC 9396 Sections 5/8 — the `authorization_details` parameter is
    /// malformed, carries an authorization-details type the realm does not
    /// support, or is not covered by the underlying grant.
    InvalidAuthorizationDetails,
}

impl std::fmt::Display for OAuth2ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // serde serializes to snake_case, which is exactly the wire representation.
        let s = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        // serde_json produces a quoted string; strip the quotes for Display.
        write!(f, "{}", s.trim_matches('"'))
    }
}

impl AsRef<str> for OAuth2ErrorCode {
    fn as_ref(&self) -> &str {
        match self {
            OAuth2ErrorCode::InvalidRequest => "invalid_request",
            OAuth2ErrorCode::UnauthorizedClient => "unauthorized_client",
            OAuth2ErrorCode::AccessDenied => "access_denied",
            OAuth2ErrorCode::UnsupportedResponseType => "unsupported_response_type",
            OAuth2ErrorCode::InvalidScope => "invalid_scope",
            OAuth2ErrorCode::ServerError => "server_error",
            OAuth2ErrorCode::TemporarilyUnavailable => "temporarily_unavailable",
            OAuth2ErrorCode::InvalidGrant => "invalid_grant",
            OAuth2ErrorCode::InvalidToken => "invalid_token",
            OAuth2ErrorCode::InsufficientScope => "insufficient_scope",
            OAuth2ErrorCode::UnsupportedOperation => "unsupported_operation",
            OAuth2ErrorCode::LoginRequired => "login_required",
            OAuth2ErrorCode::ConsentRequired => "consent_required",
            OAuth2ErrorCode::RequestNotSupported => "request_not_supported",
            OAuth2ErrorCode::InvalidDpopProof => "invalid_dpop_proof",
            OAuth2ErrorCode::InvalidAuthorizationDetails => "invalid_authorization_details",
        }
    }
}

/// OAuth2 error response per RFC 6749 Section 5.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuth2Error {
    pub error: OAuth2ErrorCode,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
    pub extra_params: HashMap<String, String>,
}

impl OAuth2Error {
    pub fn new(error: OAuth2ErrorCode) -> Self {
        Self {
            error,
            error_description: None,
            error_uri: None,
            extra_params: HashMap::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.error_description = Some(desc.into());
        self
    }
}

/// Core error type for Issuerd.
///
/// # Design note: `ServerError` stores `String` instead of `anyhow::Error`
///
/// Storing `anyhow::Error` directly would prevent `IssuerdError` from deriving `Clone`,
/// `PartialEq`, and `Eq` — all of which are required for error comparison in tests
/// and for cheap error propagation across async boundaries. The string representation
/// is sufficient for diagnostic purposes; callers that need structured error sources
/// can wrap `IssuerdError` in an `anyhow::Result` at the application boundary.
///
/// # OAuth2 coverage (RFC 6749 Section 5.2)
///
/// | OAuth2 error code        | `IssuerdError` variant(s)                 |
/// |--------------------------|---------------------------------------|
/// | `invalid_request`        | `InvalidRequest`                      |
/// | `unauthorized_client`    | `UnauthorizedClient`                  |
/// | `access_denied`          | `AccessDenied`                        |
/// | `unsupported_response_type` | `UnsupportedResponseType`        |
/// | `invalid_scope`          | `InvalidScope`                        |
/// | `server_error`           | `ServerError`, `NotFound`, `Conflict` |
///
/// The following RFC 6749 codes are **intentionally omitted** because they do not
/// arise in this architecture:
/// - `temporarily_unavailable` — handled at the infrastructure / load-balancer layer.
///
/// Additional variants (`InvalidGrant`, `InvalidToken`, `InsufficientScope`) map to
/// Bearer Token usage errors defined in RFC 6750.
///
/// # Examples
///
/// ```
/// use issuerd_core::{IssuerdError, OAuth2ErrorCode};
///
/// let err = IssuerdError::InvalidRequest("missing scope".into());
/// assert_eq!(err.oauth_error_code(), OAuth2ErrorCode::InvalidRequest);
/// assert_eq!(err.http_status(), 400);
/// ```
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum IssuerdError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("unauthorized client")]
    UnauthorizedClient,
    #[error("access denied")]
    AccessDenied,
    #[error("unsupported response type")]
    UnsupportedResponseType,
    #[error("invalid grant")]
    InvalidGrant,
    #[error("invalid scope")]
    InvalidScope,
    #[error("invalid token")]
    InvalidToken,
    #[error("insufficient scope")]
    InsufficientScope,
    #[error("server error: {0}")]
    ServerError(String),
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("unsupported operation")]
    UnsupportedOperation,
    #[error("login required")]
    LoginRequired,
    #[error("consent required")]
    ConsentRequired,
    #[error("request not supported")]
    RequestNotSupported,
    #[error("invalid DPoP proof")]
    InvalidDpopProof,
    #[error("invalid authorization details: {0}")]
    InvalidAuthorizationDetails(String),
}

impl IssuerdError {
    /// Maps to OAuth2 error code enum variant.
    pub fn oauth_error_code(&self) -> OAuth2ErrorCode {
        match self {
            IssuerdError::InvalidRequest(_) => OAuth2ErrorCode::InvalidRequest,
            IssuerdError::UnauthorizedClient => OAuth2ErrorCode::UnauthorizedClient,
            IssuerdError::AccessDenied => OAuth2ErrorCode::AccessDenied,
            IssuerdError::UnsupportedResponseType => OAuth2ErrorCode::UnsupportedResponseType,
            IssuerdError::InvalidGrant => OAuth2ErrorCode::InvalidGrant,
            IssuerdError::InvalidScope => OAuth2ErrorCode::InvalidScope,
            IssuerdError::InvalidToken => OAuth2ErrorCode::InvalidToken,
            IssuerdError::InsufficientScope => OAuth2ErrorCode::InsufficientScope,
            IssuerdError::ServerError(_) => OAuth2ErrorCode::ServerError,
            IssuerdError::NotFound => OAuth2ErrorCode::ServerError,
            IssuerdError::Conflict => OAuth2ErrorCode::ServerError,
            IssuerdError::UnsupportedOperation => OAuth2ErrorCode::UnsupportedOperation,
            IssuerdError::LoginRequired => OAuth2ErrorCode::LoginRequired,
            IssuerdError::ConsentRequired => OAuth2ErrorCode::ConsentRequired,
            IssuerdError::RequestNotSupported => OAuth2ErrorCode::RequestNotSupported,
            IssuerdError::InvalidDpopProof => OAuth2ErrorCode::InvalidDpopProof,
            IssuerdError::InvalidAuthorizationDetails(_) => {
                OAuth2ErrorCode::InvalidAuthorizationDetails
            }
        }
    }

    /// Maps to HTTP status code.
    pub fn http_status(&self) -> u16 {
        match self {
            IssuerdError::InvalidRequest(_) => 400,
            IssuerdError::UnauthorizedClient => 400,
            IssuerdError::AccessDenied => 403,
            IssuerdError::UnsupportedResponseType => 400,
            IssuerdError::InvalidGrant => 400,
            IssuerdError::InvalidScope => 400,
            IssuerdError::InvalidToken => 401,
            IssuerdError::InsufficientScope => 403,
            IssuerdError::ServerError(_) => 500,
            IssuerdError::NotFound => 404,
            IssuerdError::Conflict => 409,
            IssuerdError::LoginRequired => 400,
            IssuerdError::ConsentRequired => 400,
            IssuerdError::UnsupportedOperation => 501,
            IssuerdError::RequestNotSupported => 400,
            IssuerdError::InvalidDpopProof => 400,
            IssuerdError::InvalidAuthorizationDetails(_) => 400,
        }
    }

    /// Convert to an OAuth2 error response.
    pub fn to_oauth2_error(&self) -> OAuth2Error {
        OAuth2Error::new(self.oauth_error_code()).with_description(self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(IssuerdError::InvalidRequest("bad scope".into()), OAuth2ErrorCode::InvalidRequest, 400)]
    #[case(
        IssuerdError::UnauthorizedClient,
        OAuth2ErrorCode::UnauthorizedClient,
        400
    )]
    #[case(IssuerdError::AccessDenied, OAuth2ErrorCode::AccessDenied, 403)]
    #[case(
        IssuerdError::UnsupportedResponseType,
        OAuth2ErrorCode::UnsupportedResponseType,
        400
    )]
    #[case(IssuerdError::InvalidGrant, OAuth2ErrorCode::InvalidGrant, 400)]
    #[case(IssuerdError::InvalidScope, OAuth2ErrorCode::InvalidScope, 400)]
    #[case(IssuerdError::InvalidToken, OAuth2ErrorCode::InvalidToken, 401)]
    #[case(
        IssuerdError::InsufficientScope,
        OAuth2ErrorCode::InsufficientScope,
        403
    )]
    #[case(IssuerdError::ServerError("boom".into()), OAuth2ErrorCode::ServerError, 500)]
    #[case(IssuerdError::NotFound, OAuth2ErrorCode::ServerError, 404)]
    #[case(IssuerdError::Conflict, OAuth2ErrorCode::ServerError, 409)]
    #[case(
        IssuerdError::UnsupportedOperation,
        OAuth2ErrorCode::UnsupportedOperation,
        501
    )]
    fn error_mapping(
        #[case] err: IssuerdError,
        #[case] code: OAuth2ErrorCode,
        #[case] status: u16,
    ) {
        assert_eq!(err.oauth_error_code(), code);
        assert_eq!(err.http_status(), status);
    }

    #[test]
    fn to_oauth2_error_populates_fields() {
        let err = IssuerdError::InvalidRequest("missing redirect_uri".into());
        let oe = err.to_oauth2_error();
        assert_eq!(oe.error, OAuth2ErrorCode::InvalidRequest);
        assert_eq!(oe.error_description, Some("invalid request: missing redirect_uri".to_string()));
    }

    #[test]
    fn to_oauth2_error_matches_code_for_all_variants() {
        let variants = vec![
            IssuerdError::InvalidRequest("x".into()),
            IssuerdError::UnauthorizedClient,
            IssuerdError::AccessDenied,
            IssuerdError::UnsupportedResponseType,
            IssuerdError::InvalidGrant,
            IssuerdError::InvalidScope,
            IssuerdError::InvalidToken,
            IssuerdError::InsufficientScope,
            IssuerdError::ServerError("x".into()),
            IssuerdError::NotFound,
            IssuerdError::Conflict,
            IssuerdError::LoginRequired,
            IssuerdError::UnsupportedOperation,
            IssuerdError::RequestNotSupported,
            IssuerdError::InvalidDpopProof,
            IssuerdError::InvalidAuthorizationDetails("x".into()),
        ];
        for err in variants {
            let oe = err.to_oauth2_error();
            assert_eq!(oe.error, err.oauth_error_code());
            assert!(oe.error_description.is_some());
        }
    }

    #[test]
    fn oauth2_error_with_description_chaining() {
        let oe = OAuth2Error::new(OAuth2ErrorCode::InvalidRequest).with_description("bad scope");
        assert_eq!(oe.error, OAuth2ErrorCode::InvalidRequest);
        assert_eq!(oe.error_description, Some("bad scope".to_string()));
    }

    #[test]
    fn issuerd_error_clone_and_eq() {
        let e1 = IssuerdError::ServerError("db timeout".into());
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn oauth2_error_code_serde_roundtrip() {
        for code in [
            OAuth2ErrorCode::InvalidRequest,
            OAuth2ErrorCode::UnauthorizedClient,
            OAuth2ErrorCode::AccessDenied,
            OAuth2ErrorCode::UnsupportedResponseType,
            OAuth2ErrorCode::InvalidScope,
            OAuth2ErrorCode::ServerError,
            OAuth2ErrorCode::TemporarilyUnavailable,
            OAuth2ErrorCode::InvalidGrant,
            OAuth2ErrorCode::InvalidToken,
            OAuth2ErrorCode::InsufficientScope,
            OAuth2ErrorCode::UnsupportedOperation,
            OAuth2ErrorCode::LoginRequired,
            OAuth2ErrorCode::RequestNotSupported,
            OAuth2ErrorCode::InvalidDpopProof,
            OAuth2ErrorCode::InvalidAuthorizationDetails,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let back: OAuth2ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, back);
            assert_eq!(code.as_ref(), json.trim_matches('"'));
        }
    }

    #[test]
    fn oauth2_error_code_display_matches_serde() {
        let code = OAuth2ErrorCode::InvalidRequest;
        assert_eq!(code.to_string(), "invalid_request");
        assert_eq!(code.as_ref(), "invalid_request");
    }

    #[test]
    fn oauth2_error_code_deserialize_rejects_unknown() {
        let err = serde_json::from_str::<OAuth2ErrorCode>("\"totally_invalid\"").unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }
}
