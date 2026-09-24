// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OpenAPI assembly for issuerd-server-owned endpoints, merged into the admin API document.

//! OpenAPI assembly for endpoints owned by `issuerd-server`: the account console
//! API, the public protocol helpers (login context, token endpoint), and the
//! internal first-party SPA auth API. [`full_openapi`] merges these into the
//! admin API document so the emitted spec covers every endpoint the web
//! clients call.

use utoipa::OpenApi;

/// Account endpoints report failures as `{"error": "..."}`; password-policy
/// failures additionally carry `policyViolations`.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AccountErrorResponse {
    pub error: String,
    #[serde(rename = "policyViolations", skip_serializing_if = "Option::is_none")]
    pub policy_violations: Option<Vec<PolicyViolation>>,
}

/// One password-policy violation (machine-readable code + human message).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct PolicyViolation {
    pub code: String,
    pub message: String,
}

/// RFC 6749 §5.2 OAuth2 error response (token endpoint).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct OAuth2ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Form fields of the token endpoint used by the first-party web clients
/// (`application/x-www-form-urlencoded`). Every field is optional; the
/// `grant_type` drives which ones a given grant requires.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct TokenEndpointForm {
    /// e.g. `authorization_code` or `refresh_token`.
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    /// Second-factor OTP code for the password grant (Keycloak direct-grant
    /// parity): required when the user has OTP credentials enrolled.
    pub totp: Option<String>,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::account::account_me_handler,
        crate::routes::account::account_sessions_handler,
        crate::routes::account::account_logout_session_handler,
        crate::routes::account::account_update_me_handler,
        crate::routes::account::account_change_password_handler,
        crate::routes::account::account_totp_start_handler,
        crate::routes::account::account_totp_verify_handler,
        crate::routes::account::account_totp_delete_handler,
        crate::routes::account::account_webauthn_register_start_handler,
        crate::routes::account::account_webauthn_register_finish_handler,
        crate::routes::account::account_webauthn_credentials_handler,
        crate::routes::account::account_webauthn_delete_handler,
        crate::routes::account::account_credentials_handler,
        crate::routes::account::account_consents_handler,
        crate::routes::account::account_delete_consent_handler,
        crate::routes::account::account_linked_accounts_handler,
        crate::routes::account::account_link_identity_handler,
        crate::routes::account::account_unlink_identity_handler,
        crate::routes::login_api::login_context_handler,
        crate::routes::login_api::logout_api_handler,
        crate::routes::oidc::token_handler,
    ),
    components(schemas(
        AccountErrorResponse,
        PolicyViolation,
        OAuth2ErrorResponse,
        TokenEndpointForm,
        crate::routes::account::AccountMeResponse,
        crate::routes::account::AccountSession,
        crate::routes::account::UpdateMeRequest,
        crate::routes::account::ChangePasswordRequest,
        crate::routes::account::TotpStartResponse,
        crate::routes::account::TotpVerifyRequest,
        crate::routes::account::AccountCredentialsResponse,
        crate::routes::account::AccountConsentResponse,
        crate::routes::account::WebAuthnRegisterFinishRequest,
        crate::routes::account::AccountPasskeyResponse,
        crate::routes::account::LinkedAccountResponse,
        crate::routes::account::LinkAccountResponse,
        crate::routes::login_api::LoginContextResponse,
        crate::routes::login_api::LoginContextIdp,
        crate::routes::oidc::TokenResponse,
    )),
    tags(
        (name = "Account", description = "Self-service account console endpoints (the user's own bearer token)"),
        (name = "Protocol", description = "Public OIDC/OAuth2 protocol helpers"),
        (name = "Internal", description = "Internal first-party SPA auth API"),
    )
)]
pub struct ServerApiDoc;

/// The full OpenAPI document: Admin API plus the account-console, public
/// protocol, and internal SPA endpoints served by the Issuerd daemon.
pub fn full_openapi() -> utoipa::openapi::OpenApi {
    let mut doc =
        issuerd_admin_api::openapi::AdminApiDoc::openapi().merge_from(ServerApiDoc::openapi());
    doc.info.title = "Issuerd API".to_string();
    doc.info.description = Some("REST Admin API plus the account-console, public protocol, and internal SPA endpoints served by the Issuerd daemon.".to_string());
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_openapi_covers_account_protocol_and_internal_paths() {
        let doc = full_openapi();
        for path in [
            "/realms/{realm}/account/api/me",
            "/realms/{realm}/account/api/linked-accounts",
            "/realms/{realm}/login/context",
            "/realms/{realm}/protocol/openid-connect/token",
            "/api/v1/auth/logout",
            "/admin/serverinfo",
        ] {
            assert!(doc.paths.paths.contains_key(path), "missing path {path}");
        }
    }
}
