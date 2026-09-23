// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Admin API error type and its Keycloak-style JSON wire format.

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;
use utoipa::ToSchema;

use issuerd_core::PasswordPolicyError;

/// Standard error response returned by the Admin API.
///
/// Serialized with camelCase keys (`errorMessage`, `policyViolations`) to
/// match Keycloak's wire format — see [`AdminApiError`]'s `IntoResponse`.
#[derive(ToSchema, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AdminApiErrorResponse {
    /// Human-readable error message describing what went wrong.
    pub error_message: String,
    /// Machine-readable password-policy violations; present only on 400
    /// responses from password-setting endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_violations: Option<Vec<issuerd_core::PasswordPolicyViolation>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AdminApiError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    /// A 409 conflict whose body names the colliding resource (partial
    /// import under the FAIL strategy, Keycloak-style duplicate errors).
    #[error("conflict: {0}")]
    ConflictWithMessage(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("{0}")]
    PasswordPolicy(PasswordPolicyError),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("internal server error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AdminApiError {
    fn into_response(self) -> axum::response::Response {
        // Password-policy failures carry the structured violation list so API
        // clients can render every failed rule without parsing the message.
        if let AdminApiError::PasswordPolicy(err) = &self {
            let body = Json(json!({
                "errorMessage": err.to_string(),
                "policyViolations": err.violations,
            }));
            return (StatusCode::BAD_REQUEST, body).into_response();
        }
        let status = match &self {
            AdminApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            AdminApiError::Forbidden => StatusCode::FORBIDDEN,
            AdminApiError::NotFound => StatusCode::NOT_FOUND,
            AdminApiError::Conflict => StatusCode::CONFLICT,
            AdminApiError::ConflictWithMessage(_) => StatusCode::CONFLICT,
            AdminApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AdminApiError::PasswordPolicy(_) => unreachable!("handled above"),
            AdminApiError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            AdminApiError::Internal(err) => {
                // 500s reach here with no log anywhere else in the crate —
                // record the full anyhow chain (`?` prints the causes).
                error!(error = ?err, "admin API internal error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let body = Json(json!({ "errorMessage": self.to_string() }));
        (status, body).into_response()
    }
}

impl From<PasswordPolicyError> for AdminApiError {
    fn from(e: PasswordPolicyError) -> Self {
        AdminApiError::PasswordPolicy(e)
    }
}

impl From<issuerd_core::IssuerdError> for AdminApiError {
    fn from(e: issuerd_core::IssuerdError) -> Self {
        match e {
            issuerd_core::IssuerdError::NotFound => AdminApiError::NotFound,
            issuerd_core::IssuerdError::Conflict => AdminApiError::Conflict,
            issuerd_core::IssuerdError::InvalidRequest(msg) => AdminApiError::BadRequest(msg),
            issuerd_core::IssuerdError::UnsupportedOperation => {
                AdminApiError::NotImplemented("operation not supported".to_string())
            }
            _ => AdminApiError::Internal(anyhow::Error::new(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn error_status_codes() {
        let cases = [
            (AdminApiError::Unauthorized, StatusCode::UNAUTHORIZED),
            (AdminApiError::Forbidden, StatusCode::FORBIDDEN),
            (AdminApiError::NotFound, StatusCode::NOT_FOUND),
            (AdminApiError::Conflict, StatusCode::CONFLICT),
            (
                AdminApiError::ConflictWithMessage("user 'alice' already exists".to_string()),
                StatusCode::CONFLICT,
            ),
            (AdminApiError::BadRequest("bad".to_string()), StatusCode::BAD_REQUEST),
            (
                AdminApiError::Internal(anyhow::anyhow!("err")),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, expected) in cases {
            let resp = err.into_response();
            assert_eq!(resp.status(), expected);
        }
    }

    #[test]
    fn from_issuerd_error() {
        assert!(matches!(
            AdminApiError::from(issuerd_core::IssuerdError::NotFound),
            AdminApiError::NotFound
        ));
        assert!(matches!(
            AdminApiError::from(issuerd_core::IssuerdError::Conflict),
            AdminApiError::Conflict
        ));
        assert!(matches!(
            AdminApiError::from(issuerd_core::IssuerdError::InvalidRequest("msg".to_string())),
            AdminApiError::BadRequest(_)
        ));
        assert!(matches!(
            AdminApiError::from(issuerd_core::IssuerdError::UnauthorizedClient),
            AdminApiError::Internal(_)
        ));
    }

    #[tokio::test]
    async fn password_policy_error_response_body() {
        let err = AdminApiError::PasswordPolicy(PasswordPolicyError {
            violations: vec![issuerd_core::PasswordPolicyViolation {
                code: "min_length".to_string(),
                message: "too short".to_string(),
            }],
        });
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json
            .get("errorMessage")
            .and_then(|m| m.as_str())
            .is_some_and(|m| m.contains("min_length")));
        let violations = json.get("policyViolations").and_then(|v| v.as_array()).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].get("code").and_then(|c| c.as_str()), Some("min_length"));
        assert_eq!(violations[0].get("message").and_then(|m| m.as_str()), Some("too short"));
    }
}
