// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OAuth2 error response structure for JSON serialization (RFC 6749 §5.2).

use issuerd_core::{IssuerdError, OAuth2ErrorCode};
use serde::Serialize;

/// OAuth2 error response structure for JSON serialization per RFC 6749 Section 5.2.
#[derive(Debug, Clone, Serialize)]
pub struct OAuth2ErrorResponse {
    pub error: OAuth2ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl From<IssuerdError> for OAuth2ErrorResponse {
    fn from(err: IssuerdError) -> Self {
        Self {
            error: err.oauth_error_code(),
            error_description: Some(err.to_string()),
            error_uri: None,
            state: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth2_error_response_from_invalid_request() {
        let err = IssuerdError::InvalidRequest("missing redirect_uri".into());
        let resp: OAuth2ErrorResponse = err.into();
        assert_eq!(resp.error, OAuth2ErrorCode::InvalidRequest);
        assert_eq!(
            resp.error_description,
            Some("invalid request: missing redirect_uri".to_string())
        );
    }

    #[test]
    fn oauth2_error_response_serialization() {
        let resp = OAuth2ErrorResponse {
            error: OAuth2ErrorCode::InvalidGrant,
            error_description: Some("code is invalid".to_string()),
            error_uri: None,
            state: Some("xyz".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("invalid_grant"));
        assert!(json.contains("code is invalid"));
        assert!(json.contains("xyz"));
    }

    #[test]
    fn oauth2_error_response_skips_none() {
        let resp = OAuth2ErrorResponse {
            error: OAuth2ErrorCode::InvalidRequest,
            error_description: None,
            error_uri: None,
            state: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"error":"invalid_request"}"#);
    }
}
