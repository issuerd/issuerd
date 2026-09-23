// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Account console REST API: profile, credentials, sessions, consents, and linked accounts.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use issuerd_auth_flow::{
    built_in::{federated_password_provider, set_user_password, verify_password_hash},
    totp,
};
use issuerd_core::{
    typestate::{AccountSessionGuard, RealmBound},
    BrokerIdpSettings, ClientIdentifier, Credential, CredentialId, CredentialType, DisplayName,
    Email, IssuerdError, Pagination, PasswordPolicyError, Realm, RealmId, SessionId, User, UserId,
    Username, ACTION_TOKEN_PURPOSE_BROKER_LINK,
};
use issuerd_token::action_tokens::{action_token_claims, issue_action_token};
use tracing::{debug, error, instrument, warn};

use super::required_actions::send_verification_email;
use crate::{
    middleware::{proxy_ip::ClientIp, realm::ResolvedRealm},
    state::ServerState,
};

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AccountMeResponse {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email_verified: bool,
    pub enabled: bool,
    pub roles: Vec<String>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AccountSession {
    pub id: String,
    pub ip_address: String,
    pub started: String,
    pub last_session_refresh: String,
    pub clients: Vec<String>,
}

/// Serde helper for tri-state optional fields: absent = `None` (leave
/// unchanged), explicit `null` = `Some(None)` (clear), value = `Some(Some(v))`.
/// With `#[serde(default)]` the function runs only when the field is present.
mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Ok(Some(Option::<T>::deserialize(deserializer)?))
    }
}

/// Profile update body: a field that is absent stays unchanged, an explicit
/// `null` clears it (first/last name and email only — username is never
/// cleared).
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct UpdateMeRequest {
    #[serde(default, deserialize_with = "double_option::deserialize")]
    pub first_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    pub last_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    pub email: Option<Option<String>>,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Response of the TOTP enrollment start endpoint: the base32 secret, the
/// `otpauth://` provisioning URI, and the same URI rendered as an inline SVG
/// QR code (generated locally — the secret never leaves the server).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct TotpStartResponse {
    pub secret: String,
    #[serde(rename = "otpauthUrl")]
    pub otpauth_url: String,
    #[serde(rename = "qrSvg")]
    pub qr_svg: String,
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AccountCredentialsResponse {
    pub password: bool,
    pub totp: bool,
    pub webauthn: bool,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AccountConsentResponse {
    pub client_id: String,
    pub granted_scopes: Vec<String>,
    pub created_at: String,
    pub last_updated_at: String,
}

#[utoipa::path(
    get,
    path = "/realms/{realm}/account/api/me",
    tag = "Account",
    summary = "Get the authenticated user's profile",
    operation_id = "account_get_me",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "Account profile", body = AccountMeResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_me_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let user = match load_user(&state, &guard).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    match build_me_response(&state, &guard.realm_id, &user).await {
        Ok(me) => Json(me).into_response(),
        Err(resp) => resp,
    }
}

#[utoipa::path(
    get,
    path = "/realms/{realm}/account/api/sessions",
    tag = "Account",
    summary = "List the authenticated user's sessions",
    operation_id = "account_list_sessions",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "Active sessions", body = Vec<AccountSession>),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_sessions_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let sessions = match state
        .storage
        .list_sessions(&guard.realm_id, Some(guard.user_id), &Pagination::default())
        .await
    {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to list sessions"})),
            )
                .into_response()
        }
    };

    let result: Vec<AccountSession> = sessions
        .into_iter()
        .map(|s| AccountSession {
            id: s.id.0,
            ip_address: s.ip_address.to_string(),
            started: s.started.to_rfc3339(),
            last_session_refresh: s.last_session_refresh.to_rfc3339(),
            clients: s.clients.into_iter().map(|c| c.client_id.0).collect(),
        })
        .collect();

    Json(result).into_response()
}

#[utoipa::path(
    post,
    path = "/realms/{realm}/account/api/sessions/{id}/logout",
    tag = "Account",
    summary = "Log out (delete) one of the user's own sessions",
    operation_id = "account_logout_session",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Session or credential id"),
    ),
    responses(
        (status = 204, description = "Session deleted (idempotent)"),
        (status = 400, description = "Bad request", body = crate::openapi::AccountErrorResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers, _realm, session_id))]
pub async fn account_logout_session_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    // The realm segment is resolved by middleware; only the session id is used.
    Path((_realm, session_id)): Path<(String, String)>,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let sid = match SessionId::new(session_id.clone()) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid session id"})),
            )
                .into_response()
        }
    };

    // Verify the session belongs to the current user. A storage error must
    // fail closed: skipping the ownership check would let a caller delete
    // another user's session during a backend outage (P3-15).
    let session = match state.storage.get_user_session(&guard.realm_id, &sid).await {
        Ok(Some(session)) => {
            if session.user_id != guard.user_id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "cannot logout another user's session"})),
                )
                    .into_response();
            }
            session
        }
        Ok(None) => {
            // Already gone — logout is idempotent, nothing to delete.
            return StatusCode::NO_CONTENT.into_response();
        }
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account logout: failed to load session");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to load session"})),
            )
                .into_response();
        }
    };

    if let Err(e) = state.storage.delete_user_session(&guard.realm_id, &sid).await {
        error!(realm = %guard.realm_id, error = %e, "account logout: failed to delete session");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to delete session"})),
        )
            .into_response();
    }
    crate::session_cache::invalidate_session(&state, &guard.realm_id, &sid).await;
    // Back-channel logout: notify clients with a `backchannel_logout_uri`
    // (fire-and-forget).
    if let Ok(Some(realm)) = state.storage.get_realm(&guard.realm_id).await {
        state.logout_notifier.notify_session_destroyed(&realm, &session).await;
    }
    StatusCode::NO_CONTENT.into_response()
}

#[utoipa::path(
    put,
    path = "/realms/{realm}/account/api/me",
    tag = "Account",
    summary = "Update the authenticated user's profile",
    operation_id = "account_update_me",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    request_body = UpdateMeRequest,
    responses(
        (status = 200, description = "Updated account profile", body = AccountMeResponse),
        (status = 400, description = "Bad request", body = crate::openapi::AccountErrorResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers, body))]
pub async fn account_update_me_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    Json(body): Json<UpdateMeRequest>,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let realm_model = match load_realm(&state, &guard).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let mut user = match load_user(&state, &guard).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // Resending the current username is a no-op, not a change attempt.
    if let Some(new_username) = body.username {
        if new_username != user.username.as_str() {
            if !realm_model.edit_username_allowed {
                return bad_request("username changes are not allowed in this realm");
            }
            match Username::new(new_username) {
                Ok(username) => user.username = username,
                Err(e) => return bad_request(&e.to_string()),
            }
        }
    }

    if let Some(first_name) = body.first_name {
        match parse_optional_name(first_name) {
            Ok(name) => user.first_name = name,
            Err(msg) => return bad_request(&msg),
        }
    }
    if let Some(last_name) = body.last_name {
        match parse_optional_name(last_name) {
            Ok(name) => user.last_name = name,
            Err(msg) => return bad_request(&msg),
        }
    }

    let mut send_verification = false;
    if let Some(email) = body.email {
        match apply_email_change(&state, &guard, &realm_model, &mut user, email).await {
            Ok(v) => send_verification = v,
            Err(resp) => return resp,
        }
    }

    if let Err(e) = state.storage.update_user(&guard.realm_id, &user).await {
        // Username uniqueness on rename is enforced by the storage backend.
        if matches!(e, IssuerdError::Conflict)
            || matches!(&e, IssuerdError::InvalidRequest(m) if m.contains("username already exists"))
        {
            return bad_request("username already in use");
        }
        error!(realm = %guard.realm_id, error = %e, "account update me: failed to update user");
        return internal_error("failed to update user");
    }
    issuerd_cluster::invalidate::invalidate_user_claims(
        state.cache.as_ref(),
        &guard.realm_id,
        &user.id,
    )
    .await;

    // Deliver after persisting so the VERIFY_EMAIL assignment survives a
    // delivery failure (the user can retrigger it from the login flow).
    if send_verification {
        if let Err(e) = send_verification_email(
            &state,
            &realm_model,
            realm_model.name.as_ref(),
            &user,
            None,
            None,
        )
        .await
        {
            error!(realm = %guard.realm_id, error = %e, "account update me: verification email failed");
        }
    }

    match build_me_response(&state, &guard.realm_id, &user).await {
        Ok(me) => Json(me).into_response(),
        Err(resp) => resp,
    }
}

#[utoipa::path(
    post,
    path = "/realms/{realm}/account/api/credentials/password",
    tag = "Account",
    summary = "Change the account password (verifies the current one, enforces the realm policy)",
    operation_id = "account_change_password",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed"),
        (status = 400, description = "Bad request", body = crate::openapi::AccountErrorResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers, body, ip))]
pub async fn account_change_password_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let realm_model = match load_realm(&state, &guard).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let user = match load_user(&state, &guard).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // Federated user with a live provider: the external directory is the
    // source of truth for both the current-password check and the write.
    let federation = match federated_password_provider(
        state.storage.as_ref(),
        state.federation_manager.as_ref(),
        &guard.realm_id,
        &guard.user_id,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account change password: federation lookup failed");
            return internal_error("failed to resolve federation provider");
        }
    };
    if let Some((provider, username)) = federation {
        let current_ok = match provider.validate_password(&username, &body.current_password).await {
            Ok(v) => v,
            Err(e) => {
                error!(realm = %guard.realm_id, error = %e, "account change password: federation validation failed");
                return internal_error("failed to verify current password");
            }
        };
        if !current_ok {
            warn!(realm = %guard.realm_id, username = %issuerd_core::utils::sanitize_log_str(user.username.as_str()), ip = %ip, "account change password: wrong current password");
            return bad_request("current password is incorrect");
        }
        if let Err(policy_err) = realm_model.password_policy.validate(&body.new_password, &user) {
            return policy_error_response(policy_err);
        }
        return match provider.update_password(&username, &body.new_password).await {
            Ok(()) => {
                // Drop stale local credentials: login only consults them when
                // the provider errors, where they would act as a dormant
                // fallback password.
                match state
                    .storage
                    .get_credentials(&guard.realm_id, &guard.user_id, CredentialType::Password)
                    .await
                {
                    Ok(stale) => {
                        for cred in stale {
                            if let Err(e) = state
                                .storage
                                .delete_credential(&guard.realm_id, &guard.user_id, &cred.id)
                                .await
                            {
                                warn!(realm = %guard.realm_id, error = %e, "account change password: stale credential cleanup failed");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(realm = %guard.realm_id, error = %e, "account change password: stale credential cleanup failed");
                    }
                }
                StatusCode::NO_CONTENT.into_response()
            }
            Err(issuerd_core::FederationError::NotSupported) => bad_request(
                "the external directory for this account does not accept password changes",
            ),
            Err(e) => {
                error!(realm = %guard.realm_id, error = %e, "account change password: directory write failed");
                internal_error("failed to update password")
            }
        };
    }

    let credentials = match state
        .storage
        .get_credentials(&guard.realm_id, &guard.user_id, CredentialType::Password)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account change password: load failed");
            return internal_error("failed to load credentials");
        }
    };
    // Identical message whether the account has no password credential or the
    // current password does not match — the response must not reveal which.
    let current_ok = credentials.iter().any(|c| verify_password_hash(&body.current_password, c));
    if !current_ok {
        warn!(realm = %guard.realm_id, username = %issuerd_core::utils::sanitize_log_str(user.username.as_str()), ip = %ip, "account change password: wrong current password");
        return bad_request("current password is incorrect");
    }

    // Policy gate before any stored credential is touched.
    if let Err(policy_err) = realm_model.password_policy.validate(&body.new_password, &user) {
        return policy_error_response(policy_err);
    }

    match set_user_password(
        state.storage.as_ref(),
        &guard.realm_id,
        &guard.user_id,
        &body.new_password,
        realm_model.password_policy.history_size,
        false,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            let msg = e.to_string();
            // set_user_password enforces password history; a reuse rejection
            // surfaces in the same 400 + policyViolations shape.
            if msg.contains("password_history") {
                let violations = vec![issuerd_core::PasswordPolicyViolation {
                    code: "password_history".to_string(),
                    message: msg.clone(),
                }];
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": msg, "policyViolations": violations})),
                )
                    .into_response();
            }
            error!(realm = %guard.realm_id, error = %e, "account change password: failed");
            internal_error("failed to update password")
        }
    }
}

/// Cache TTL for a pending TOTP enrollment secret.
const TOTP_ENROLL_TTL_SECS: u64 = 600;

/// Cache key holding a user's not-yet-verified enrollment secret.
fn totp_enrollment_key(realm_id: &RealmId, user_id: &UserId) -> String {
    format!("totp-enroll:{realm_id}:{user_id}")
}

#[utoipa::path(
    post,
    path = "/realms/{realm}/account/api/credentials/totp/start",
    tag = "Account",
    summary = "Start TOTP enrollment (returns secret + otpauth URL + QR SVG)",
    operation_id = "account_totp_start",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "Pending enrollment", body = TotpStartResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_totp_start_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let realm_model = match load_realm(&state, &guard).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let user = match load_user(&state, &guard).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let secret = totp::generate_secret();
    let key = totp_enrollment_key(&guard.realm_id, &guard.user_id);
    if let Err(e) = state
        .cache
        .set(
            &key,
            secret.clone().into_bytes(),
            Some(Duration::from_secs(TOTP_ENROLL_TTL_SECS)),
        )
        .await
    {
        error!(realm = %guard.realm_id, error = %e, "account TOTP start: cache write failed");
        return internal_error("failed to start authenticator enrollment");
    }

    let issuer = realm_model
        .display_name
        .as_ref()
        .map(|d| d.as_str())
        .unwrap_or(realm_model.name.as_str());
    let otpauth_url =
        totp::otpauth_url(issuer, user.username.as_str(), &secret, &realm_model.otp_policy);
    let qr_svg = match crate::qr::qr_svg(&otpauth_url) {
        Ok(svg) => svg,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account TOTP start: QR render failed");
            return internal_error("failed to render QR code");
        }
    };

    Json(TotpStartResponse {
        secret,
        otpauth_url,
        qr_svg,
    })
    .into_response()
}

#[utoipa::path(
    post,
    path = "/realms/{realm}/account/api/credentials/totp/verify",
    tag = "Account",
    summary = "Verify a TOTP code and persist the authenticator credential",
    operation_id = "account_totp_verify",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    request_body = TotpVerifyRequest,
    responses(
        (status = 204, description = "TOTP credential created"),
        (status = 400, description = "Bad request", body = crate::openapi::AccountErrorResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers, body))]
pub async fn account_totp_verify_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    Json(body): Json<TotpVerifyRequest>,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let realm_model = match load_realm(&state, &guard).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let key = totp_enrollment_key(&guard.realm_id, &guard.user_id);
    // A wrong code must NOT consume the pending secret — the user may simply
    // have mistyped, and deleting here would force a restart of enrollment.
    let secret = match state.cache.get(&key).await {
        Ok(Some(bytes)) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return internal_error("corrupt enrollment state"),
        },
        Ok(None) => return bad_request("enrollment not started or expired"),
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account TOTP verify: cache read failed");
            return internal_error("failed to load enrollment state");
        }
    };

    let now = issuerd_core::utils::now_secs();
    let Some(matched_step) = totp::verify(&secret, &body.code, now, &realm_model.otp_policy, None)
    else {
        return bad_request("invalid code");
    };

    let cred = Credential {
        id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: CredentialType::Totp,
        user_label: None,
        created_date: chrono::Utc::now(),
        secret_data: secret.into_bytes(),
        credential_data: serde_json::json!({
            "algorithm": realm_model.otp_policy.algorithm,
            "digits": realm_model.otp_policy.digits,
            "period": realm_model.otp_policy.period_secs,
            "last_used_step": matched_step,
        }),
        priority: 0,
    };
    if let Err(e) = state.storage.create_credential(&guard.realm_id, &guard.user_id, &cred).await {
        error!(realm = %guard.realm_id, error = %e, "account TOTP verify: store failed");
        return internal_error("failed to store authenticator");
    }
    // Enrollment consumed — clear the pending secret. A cleanup failure is
    // harmless (the entry expires on its own), so only log it.
    if let Err(e) = state.cache.delete(&key).await {
        warn!(realm = %guard.realm_id, error = %e, "account TOTP verify: cleanup failed");
    }
    StatusCode::NO_CONTENT.into_response()
}

#[utoipa::path(
    delete,
    path = "/realms/{realm}/account/api/credentials/totp",
    tag = "Account",
    summary = "Delete the account's TOTP credential",
    operation_id = "account_totp_delete",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 204, description = "TOTP credential deleted (idempotent)"),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_totp_delete_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Idempotent: 204 whether or not a TOTP credential existed.
    let credentials = match state
        .storage
        .get_credentials(&guard.realm_id, &guard.user_id, CredentialType::Totp)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account TOTP delete: load failed");
            return internal_error("failed to load credentials");
        }
    };
    for cred in credentials {
        if let Err(e) =
            state.storage.delete_credential(&guard.realm_id, &guard.user_id, &cred.id).await
        {
            error!(realm = %guard.realm_id, error = %e, "account TOTP delete: failed");
            return internal_error("failed to delete authenticator");
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

// --- WebAuthn / passkey management -----------------------------------------

/// Cache TTL for an in-flight passkey registration ceremony.
const WEBAUTHN_REG_TTL_SECS: u64 = 600;

/// Cache key holding a user's in-flight passkey registration state.
fn webauthn_registration_key(realm_id: &RealmId, user_id: &UserId) -> String {
    format!("webauthn-reg:{realm_id}:{user_id}")
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct WebAuthnRegisterFinishRequest {
    /// Optional user-facing label ("Work laptop") stored on the credential.
    #[serde(default)]
    pub label: Option<String>,
    /// The serialized `PublicKeyCredential` produced by the browser ceremony.
    pub credential: serde_json::Value,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AccountPasskeyResponse {
    pub id: String,
    pub label: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Build the relying-party instance for the configured issuer, logging and
/// returning `None` on failure. The issuer is validated at boot, so a failure
/// here indicates a configuration regression.
fn webauthn_rp(state: &ServerState, realm: &Realm) -> Option<webauthn_rs::prelude::Webauthn> {
    let (rp_id, rp_origin) =
        match issuerd_auth_flow::webauthn::relying_party_from_issuer(&state.config.issuer_url) {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "account WebAuthn: invalid relying-party configuration");
                return None;
            }
        };
    let rp_name = realm.display_name.as_ref().map(|d| d.as_str()).unwrap_or(realm.name.as_str());
    match issuerd_auth_flow::webauthn::build_webauthn(&rp_id, &rp_origin, rp_name) {
        Ok(w) => Some(w),
        Err(e) => {
            error!(error = %e, "account WebAuthn: failed to build relying party");
            None
        }
    }
}

/// Ceremony display name: "First Last" when present, else the username.
fn passkey_display_name(user: &User) -> String {
    match (&user.first_name, &user.last_name) {
        (Some(first), Some(last)) => format!("{first} {last}"),
        (Some(first), None) => first.to_string(),
        (None, Some(last)) => last.to_string(),
        (None, None) => user.username.to_string(),
    }
}

#[utoipa::path(
    post,
    path = "/realms/{realm}/account/api/webauthn/register/start",
    tag = "Account",
    summary = "Start a passkey registration ceremony",
    operation_id = "account_webauthn_register_start",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "WebAuthn creation options (PublicKeyCredentialCreationOptions JSON)", body = serde_json::Value),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_webauthn_register_start_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let realm_model = match load_realm(&state, &guard).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let user = match load_user(&state, &guard).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let Some(webauthn) = webauthn_rp(&state, &realm_model) else {
        return internal_error("invalid relying-party configuration");
    };

    // Exclude already-registered passkeys so the browser refuses duplicates.
    let existing = match state
        .storage
        .get_credentials(&guard.realm_id, &guard.user_id, CredentialType::WebAuthn)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account WebAuthn start: load failed");
            return internal_error("failed to load credentials");
        }
    };
    let mut exclude = Vec::with_capacity(existing.len());
    for cred in &existing {
        match issuerd_auth_flow::webauthn::passkey_from_bytes(&cred.secret_data) {
            Ok(passkey) => exclude.push(passkey.cred_id().clone()),
            Err(e) => {
                warn!(realm = %guard.realm_id, error = %e, "account WebAuthn start: skipping undecodable passkey");
            }
        }
    }

    let display_name = passkey_display_name(&user);
    let (ccr, reg_state) = match webauthn.start_passkey_registration(
        issuerd_auth_flow::webauthn::user_handle(&guard.user_id),
        user.username.as_str(),
        &display_name,
        Some(exclude),
    ) {
        Ok(v) => v,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account WebAuthn start: ceremony init failed");
            return internal_error("failed to start passkey registration");
        }
    };

    let state_bytes = match serde_json::to_vec(&reg_state) {
        Ok(b) => b,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account WebAuthn start: state serialization failed");
            return internal_error("failed to start passkey registration");
        }
    };
    let key = webauthn_registration_key(&guard.realm_id, &guard.user_id);
    if let Err(e) = state
        .cache
        .set(&key, state_bytes, Some(Duration::from_secs(WEBAUTHN_REG_TTL_SECS)))
        .await
    {
        error!(realm = %guard.realm_id, error = %e, "account WebAuthn start: cache write failed");
        return internal_error("failed to start passkey registration");
    }

    Json(ccr.public_key).into_response()
}

#[utoipa::path(
    post,
    path = "/realms/{realm}/account/api/webauthn/register/finish",
    tag = "Account",
    summary = "Finish a passkey registration ceremony and store the credential",
    operation_id = "account_webauthn_register_finish",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    request_body = WebAuthnRegisterFinishRequest,
    responses(
        (status = 204, description = "Passkey registered"),
        (status = 400, description = "Bad request", body = crate::openapi::AccountErrorResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers, body))]
pub async fn account_webauthn_register_finish_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    Json(body): Json<WebAuthnRegisterFinishRequest>,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let realm_model = match load_realm(&state, &guard).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(webauthn) = webauthn_rp(&state, &realm_model) else {
        return internal_error("invalid relying-party configuration");
    };

    let key = webauthn_registration_key(&guard.realm_id, &guard.user_id);
    // A failed finish keeps the pending state: the user may retry the
    // ceremony (e.g. after cancelling the browser prompt) until the TTL
    // expires.
    let state_bytes = match state.cache.get(&key).await {
        Ok(Some(b)) => b,
        Ok(None) => return bad_request("registration not started or expired"),
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account WebAuthn finish: cache read failed");
            return internal_error("failed to load registration state");
        }
    };
    let reg_state: webauthn_rs::prelude::PasskeyRegistration = match serde_json::from_slice(
        &state_bytes,
    ) {
        Ok(s) => s,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account WebAuthn finish: corrupt state");
            return internal_error("corrupt registration state");
        }
    };
    let credential: webauthn_rs::prelude::RegisterPublicKeyCredential =
        match serde_json::from_value(body.credential) {
            Ok(c) => c,
            Err(_) => return bad_request("malformed credential"),
        };
    let passkey = match webauthn.finish_passkey_registration(&credential, &reg_state) {
        Ok(p) => p,
        Err(e) => {
            warn!(realm = %guard.realm_id, error = %e, "account WebAuthn finish: passkey verification failed");
            return bad_request("passkey verification failed");
        }
    };

    let label = body
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let secret_data = match issuerd_auth_flow::webauthn::passkey_to_bytes(&passkey) {
        Ok(b) => b,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account WebAuthn finish: serialization failed");
            return internal_error("failed to store passkey");
        }
    };
    let cred = Credential {
        id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: CredentialType::WebAuthn,
        user_label: label,
        created_date: chrono::Utc::now(),
        secret_data,
        credential_data: serde_json::json!({
            "cred_id": base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &**passkey.cred_id(),
            ),
        }),
        priority: 0,
    };
    if let Err(e) = state.storage.create_credential(&guard.realm_id, &guard.user_id, &cred).await {
        error!(realm = %guard.realm_id, error = %e, "account WebAuthn finish: store failed");
        return internal_error("failed to store passkey");
    }
    // Registration consumed — clear the pending state. A cleanup failure is
    // harmless (the entry expires on its own), so only log it.
    if let Err(e) = state.cache.delete(&key).await {
        warn!(realm = %guard.realm_id, error = %e, "account WebAuthn finish: cleanup failed");
    }
    StatusCode::NO_CONTENT.into_response()
}

#[utoipa::path(
    get,
    path = "/realms/{realm}/account/api/webauthn/credentials",
    tag = "Account",
    summary = "List the account's registered passkeys",
    operation_id = "account_webauthn_list_credentials",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "Registered passkeys", body = Vec<AccountPasskeyResponse>),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_webauthn_credentials_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let credentials = match state
        .storage
        .get_credentials(&guard.realm_id, &guard.user_id, CredentialType::WebAuthn)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account WebAuthn list: load failed");
            return internal_error("failed to load credentials");
        }
    };
    let result: Vec<AccountPasskeyResponse> = credentials
        .iter()
        .map(|cred| AccountPasskeyResponse {
            id: cred.id.0.clone(),
            label: cred.user_label.clone().unwrap_or_default(),
            created_at: cred.created_date.to_rfc3339(),
        })
        .collect();
    Json(result).into_response()
}

#[utoipa::path(
    delete,
    path = "/realms/{realm}/account/api/webauthn/credentials/{id}",
    tag = "Account",
    summary = "Delete one of the account's passkeys",
    operation_id = "account_webauthn_delete_credential",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Session or credential id"),
    ),
    responses(
        (status = 204, description = "Passkey deleted (idempotent; only WebAuthn credentials are deletable)"),
        (status = 400, description = "Bad request", body = crate::openapi::AccountErrorResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers, _realm, credential_id))]
pub async fn account_webauthn_delete_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    // The realm segment is resolved by middleware; only the credential id is used.
    Path((_realm, credential_id)): Path<(String, String)>,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let cred_id = match CredentialId::new(credential_id) {
        Ok(id) => id,
        Err(e) => return bad_request(&e.to_string()),
    };
    let credentials = match state
        .storage
        .get_credentials(&guard.realm_id, &guard.user_id, CredentialType::WebAuthn)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account WebAuthn delete: load failed");
            return internal_error("failed to load credentials");
        }
    };
    // Only WebAuthn credentials of this user are deletable through this
    // endpoint; anything else (including unknown ids) is an idempotent 204.
    if let Some(cred) = credentials.iter().find(|c| c.id == cred_id) {
        if let Err(e) =
            state.storage.delete_credential(&guard.realm_id, &guard.user_id, &cred.id).await
        {
            error!(realm = %guard.realm_id, error = %e, "account WebAuthn delete: failed");
            return internal_error("failed to delete passkey");
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

#[utoipa::path(
    get,
    path = "/realms/{realm}/account/api/credentials",
    tag = "Account",
    summary = "Presence flags for the account's enrolled credentials",
    operation_id = "account_get_credentials",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "Credential presence flags", body = AccountCredentialsResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_credentials_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let password = match has_credential(&state, &guard, CredentialType::Password).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // Federated users keep their password in the external directory; report
    // it as set when the linked provider accepts password writes so the
    // account console offers the change form.
    let password = if password {
        true
    } else {
        matches!(
            federated_password_provider(
                state.storage.as_ref(),
                state.federation_manager.as_ref(),
                &guard.realm_id,
                &guard.user_id,
            )
            .await,
            Ok(Some((provider, _))) if provider.supports_password_update()
        )
    };
    let totp = match has_credential(&state, &guard, CredentialType::Totp).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let webauthn = match has_credential(&state, &guard, CredentialType::WebAuthn).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let webauthn_passwordless =
        match has_credential(&state, &guard, CredentialType::WebAuthnPasswordless).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    Json(AccountCredentialsResponse {
        password,
        totp,
        webauthn: webauthn || webauthn_passwordless,
    })
    .into_response()
}

#[utoipa::path(
    get,
    path = "/realms/{realm}/account/api/consents",
    tag = "Account",
    summary = "List the account's granted consents",
    operation_id = "account_list_consents",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "Granted consents", body = Vec<AccountConsentResponse>),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_consents_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let consents = match state.storage.get_consents(&guard.realm_id, &guard.user_id).await {
        Ok(c) => c,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account consents: failed to list");
            return internal_error("failed to list consents");
        }
    };

    let mut result = Vec::new();
    for consent in consents {
        // The consent stores the internal client UUID; the API exposes the
        // human client_id string. Skip consents whose client row vanished.
        let client = match state.storage.get_client(&guard.realm_id, &consent.client_id).await {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(e) => {
                error!(realm = %guard.realm_id, error = %e, "account consents: resolve failed");
                return internal_error("failed to resolve consent client");
            }
        };
        result.push(AccountConsentResponse {
            client_id: client.client_id.to_string(),
            granted_scopes: consent.granted_scopes.to_vec(),
            created_at: consent.created_at.to_rfc3339(),
            last_updated_at: consent.last_updated_at.to_rfc3339(),
        });
    }
    Json(result).into_response()
}

#[utoipa::path(
    delete,
    path = "/realms/{realm}/account/api/consents/{client_id}",
    tag = "Account",
    summary = "Revoke the account's consent for a client",
    operation_id = "account_delete_consent",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("client_id" = String, Path, description = "Human client_id string"),
    ),
    responses(
        (status = 204, description = "Consent revoked (idempotent)"),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
        (status = 404, description = "Not found", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_delete_consent_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    // The realm segment is resolved by middleware; only the client id is used.
    Path((_realm, client_id)): Path<(String, String)>,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // The path param is the human client_id string, not the internal UUID.
    let identifier = match ClientIdentifier::new(client_id) {
        Ok(id) => id,
        Err(e) => return bad_request(&e.to_string()),
    };
    let client = match state.storage.get_client_by_client_id(&guard.realm_id, &identifier).await {
        Ok(Some(c)) => c,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "client not found"),
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "account delete consent: load failed");
            return internal_error("failed to load client");
        }
    };

    // Deleting a missing consent is a no-op in every backend, so revocation
    // is idempotent: 204 whether or not a consent row existed.
    if let Err(e) = state.storage.delete_consent(&guard.realm_id, &guard.user_id, &client.id).await
    {
        error!(realm = %guard.realm_id, error = %e, "account delete consent: failed");
        return internal_error("failed to delete consent");
    }
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Linked accounts (identity brokering)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct LinkedAccountResponse {
    pub alias: String,
    pub provider_id: String,
    pub display_name: String,
    pub external_username: Option<String>,
    pub created_at: String,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct LinkAccountResponse {
    pub redirect_url: String,
}

/// `GET /realms/{realm}/account/api/linked-accounts` — the user's IdP links,
/// joined with the provider configuration for display purposes.
#[utoipa::path(
    get,
    path = "/realms/{realm}/account/api/linked-accounts",
    tag = "Account",
    summary = "List the account's linked external identities",
    operation_id = "account_list_linked_accounts",
    params(
        ("realm" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "Linked accounts", body = Vec<LinkedAccountResponse>),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_linked_accounts_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let links = match state
        .storage
        .list_identity_provider_links(&guard.realm_id, &guard.user_id)
        .await
    {
        Ok(l) => l,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "linked accounts: failed to list");
            return internal_error("failed to list linked accounts");
        }
    };
    let idps = match state.storage.list_identity_providers(&guard.realm_id).await {
        Ok(l) => l,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "linked accounts: failed to list IdPs");
            return internal_error("failed to list identity providers");
        }
    };

    let result = links
        .into_iter()
        .map(|link| {
            // A link can outlive its IdP config row only until the cascade
            // delete runs; if it is gone, fall back to the bare alias.
            let (provider_id, display_name) =
                match idps.iter().find(|i| i.alias.as_ref() == link.provider_alias) {
                    Some(cfg) => (
                        cfg.provider_id.as_str().to_string(),
                        BrokerIdpSettings::new(cfg).display_name(),
                    ),
                    None => (String::new(), link.provider_alias.clone()),
                };
            LinkedAccountResponse {
                alias: link.provider_alias.clone(),
                provider_id,
                display_name,
                external_username: link.external_username.clone(),
                created_at: link.created_at.to_rfc3339(),
            }
        })
        .collect::<Vec<_>>();
    Json(result).into_response()
}

/// `POST /realms/{realm}/account/api/linked-accounts/{alias}` — start the
/// linking ceremony: returns the broker login URL carrying a short-lived
/// `link` action token that binds the callback to this authenticated user.
#[utoipa::path(
    post,
    path = "/realms/{realm}/account/api/linked-accounts/{alias}",
    tag = "Account",
    summary = "Start the IdP account-linking ceremony (returns the broker redirect URL)",
    operation_id = "account_link_identity",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "Identity provider alias"),
    ),
    responses(
        (status = 200, description = "Link ceremony start", body = LinkAccountResponse),
        (status = 400, description = "Bad request", body = crate::openapi::AccountErrorResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
        (status = 404, description = "Not found", body = crate::openapi::AccountErrorResponse),
        (status = 409, description = "Conflict", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_link_identity_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    // The realm segment is resolved by middleware; only the alias is used.
    Path((_realm, alias)): Path<(String, String)>,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // extract_auth has already rejected a missing realm segment.
    let realm_name = realm.as_deref().unwrap_or_default();

    if let Err(e) = issuerd_core::Alias::new(alias.clone()) {
        return bad_request(&e.to_string());
    }
    let idp = match state.storage.get_identity_provider_by_alias(&guard.realm_id, &alias).await {
        Ok(Some(i)) => i,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "identity provider not found"),
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "link account: IdP load failed");
            return internal_error("failed to load identity provider");
        }
    };
    if !idp.enabled || !BrokerIdpSettings::new(&idp).is_broker_provider() {
        return bad_request("identity provider is not available for linking");
    }

    // One link per (user, alias); re-linking is a delete-then-link cycle.
    match state
        .storage
        .get_identity_provider_link_for_user(&guard.realm_id, &guard.user_id, &alias)
        .await
    {
        Ok(Some(_)) => {
            return error_response(StatusCode::CONFLICT, "identity provider already linked")
        }
        Ok(None) => {}
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "link account: link check failed");
            return internal_error("failed to check existing link");
        }
    }

    // The link token is deliberately NOT single-use: the guard is the
    // BrokerState entry plus the issuerd_session cookie match at the callback, so
    // a browser restart during the ceremony does not strand the user.
    let claims = action_token_claims(
        &guard.user_id,
        &guard.realm_id,
        ACTION_TOKEN_PURPOSE_BROKER_LINK,
        super::broker::LINK_TOKEN_TTL_SECS,
    );
    let token = match issue_action_token(state.crypto.as_ref(), &claims).await {
        Ok(t) => t,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "link account: token issue failed");
            return internal_error("failed to issue link token");
        }
    };
    Json(LinkAccountResponse {
        redirect_url: format!("/realms/{realm_name}/broker/{alias}/login?link={token}"),
    })
    .into_response()
}

/// `DELETE /realms/{realm}/account/api/linked-accounts/{alias}` — unlink.
/// Idempotent (204 whether or not the link existed), but refuses to remove
/// the account's last sign-in method.
#[utoipa::path(
    delete,
    path = "/realms/{realm}/account/api/linked-accounts/{alias}",
    tag = "Account",
    summary = "Unlink an external identity (refuses to remove the last sign-in method)",
    operation_id = "account_unlink_identity",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "Identity provider alias"),
    ),
    responses(
        (status = 204, description = "Unlinked (idempotent)"),
        (status = 400, description = "Bad request", body = crate::openapi::AccountErrorResponse),
        (status = 401, description = "Missing or invalid access token", body = crate::openapi::AccountErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
#[instrument(skip(state, headers))]
pub async fn account_unlink_identity_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    // The realm segment is resolved by middleware; only the alias is used.
    Path((_realm, alias)): Path<(String, String)>,
) -> Response {
    let guard = match extract_auth(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let links = match state
        .storage
        .list_identity_provider_links(&guard.realm_id, &guard.user_id)
        .await
    {
        Ok(l) => l,
        Err(e) => {
            error!(realm = %guard.realm_id, error = %e, "unlink account: failed to list");
            return internal_error("failed to list linked accounts");
        }
    };
    if !links.iter().any(|l| l.provider_alias == alias) {
        return StatusCode::NO_CONTENT.into_response();
    }

    // Last sign-in method guard: without a password credential, unlinking the
    // only IdP link would leave the account with no way to sign in at all.
    if links.len() == 1 {
        match has_credential(&state, &guard, CredentialType::Password).await {
            Ok(true) => {}
            Ok(false) => {
                return bad_request("cannot unlink the only sign-in method; set a password first")
            }
            Err(resp) => return resp,
        }
    }

    if let Err(e) = state
        .storage
        .delete_identity_provider_link(&guard.realm_id, &guard.user_id, &alias)
        .await
    {
        error!(realm = %guard.realm_id, error = %e, "unlink account: delete failed");
        return internal_error("failed to unlink identity provider");
    }
    StatusCode::NO_CONTENT.into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({"error": message}))).into_response()
}

fn bad_request(message: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, message)
}

fn internal_error(message: &str) -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
}

/// 400 with the machine-readable violation list the account console renders.
fn policy_error_response(err: PasswordPolicyError) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": err.to_string(),
            "policyViolations": err.violations,
        })),
    )
        .into_response()
}

/// Load the authenticated user, mapping storage failures to error responses.
#[allow(clippy::result_large_err)]
async fn load_user(
    state: &Arc<ServerState>,
    guard: &AccountSessionGuard,
) -> Result<User, Response> {
    state
        .storage
        .get_user(&guard.realm_id, &guard.user_id)
        .await
        .map_err(|e| {
            error!(realm = %guard.realm_id, error = %e, "account API: failed to load user");
            internal_error("failed to load user")
        })?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "user not found"))
}

/// Load the realm the guard is bound to (login flags, password policy).
#[allow(clippy::result_large_err)]
async fn load_realm(
    state: &Arc<ServerState>,
    guard: &AccountSessionGuard,
) -> Result<Realm, Response> {
    state
        .storage
        .get_realm(&guard.realm_id)
        .await
        .map_err(|e| {
            error!(realm = %guard.realm_id, error = %e, "account API: failed to load realm");
            internal_error("failed to load realm")
        })?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "realm not found"))
}

/// Resolve the user's realm-role names and build the `me` response object.
/// Shared by GET and PUT so both return the identical shape.
#[allow(clippy::result_large_err)]
async fn build_me_response(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    user: &User,
) -> Result<AccountMeResponse, Response> {
    let role_ids = state.storage.list_user_realm_roles(realm_id, &user.id).await.map_err(|e| {
        error!(realm = %realm_id, error = %e, "account me: failed to list roles");
        internal_error("failed to list roles")
    })?;
    let mut roles = vec![];
    for role_id in &role_ids {
        if let Ok(Some(role)) = state.storage.get_role(realm_id, role_id).await {
            roles.push(role.name.to_string());
        }
    }
    Ok(AccountMeResponse {
        id: user.id.0.clone(),
        username: user.username.to_string(),
        email: user.email.as_ref().map(|e| e.to_string()),
        first_name: user.first_name.as_ref().map(|n| n.to_string()),
        last_name: user.last_name.as_ref().map(|n| n.to_string()),
        email_verified: user.email_verified,
        enabled: user.enabled,
        roles,
    })
}

/// `true` when the user has at least one credential of the given type.
/// Password-history credentials use a custom type and are never counted here.
#[allow(clippy::result_large_err)]
async fn has_credential(
    state: &Arc<ServerState>,
    guard: &AccountSessionGuard,
    cred_type: CredentialType,
) -> Result<bool, Response> {
    state
        .storage
        .get_credentials(&guard.realm_id, &guard.user_id, cred_type)
        .await
        .map(|creds| !creds.is_empty())
        .map_err(|e| {
            error!(realm = %guard.realm_id, error = %e, "account credentials: load failed");
            internal_error("failed to load credentials")
        })
}

/// Validate an optional display-name update: explicit null clears the field,
/// a value is validated through the `DisplayName` newtype. The `Err` variant
/// carries the validation message for the 400 response.
fn parse_optional_name(value: Option<String>) -> Result<Option<DisplayName>, String> {
    value.map(|v| DisplayName::new(v).map_err(|e| e.to_string())).transpose()
}

/// Apply an email change to `user`, enforcing uniqueness and verification
/// rules. Returns `true` when a verification email must be sent after the
/// update has been persisted.
#[allow(clippy::result_large_err)]
async fn apply_email_change(
    state: &Arc<ServerState>,
    guard: &AccountSessionGuard,
    realm: &Realm,
    user: &mut User,
    new_email: Option<String>,
) -> Result<bool, Response> {
    let new_email: Option<Email> = match new_email {
        Some(v) => Some(Email::new(v).map_err(|e| bad_request(&e.to_string()))?),
        None => None,
    };
    let changed = new_email.as_ref().map(|e| e.as_str()) != user.email.as_ref().map(|e| e.as_str());
    if !changed {
        return Ok(false);
    }
    if let Some(email) = &new_email {
        // Email uniqueness is not enforced by the storage backends, so it is
        // checked here unless the realm explicitly allows duplicate emails.
        if !realm.duplicate_emails_allowed {
            let existing = state
                .storage
                .get_user_by_email(&guard.realm_id, email.as_str())
                .await
                .map_err(|e| {
                    error!(realm = %guard.realm_id, error = %e, "account update me: email lookup failed");
                    internal_error("failed to update user")
                })?;
            if existing.is_some_and(|other| other.id != user.id) {
                return Err(bad_request("email already in use"));
            }
        }
    }
    user.email = new_email;
    // Any email change invalidates the previous verification.
    user.email_verified = false;
    if user.email.is_none() || !realm.verify_email_enabled {
        return Ok(false);
    }
    if !user.required_actions.iter().any(|a| a == "VERIFY_EMAIL") {
        user.required_actions.push("VERIFY_EMAIL".to_string());
    }
    Ok(true)
}

/// Peek at the JWT payload's `exp` claim without validating the token. Used
/// only to pick the log level for an already-rejected token — never for an
/// authorization decision.
fn token_is_expired(token: &str) -> bool {
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(bytes) =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
    else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .is_some_and(|exp| exp < chrono::Utc::now().timestamp())
}

#[allow(clippy::result_large_err)]
async fn extract_auth(
    state: &Arc<ServerState>,
    realm: &Option<String>,
    headers: &axum::http::HeaderMap,
) -> Result<AccountSessionGuard, Response> {
    let realm_name = match realm.as_deref() {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing realm"})),
            )
                .into_response())
        }
    };

    // The URL carries the realm name and token issuers embed the realm name;
    // storage is keyed by realm id, which differs for admin-created
    // (UUID-id) realms.
    let realm = match state.resolve_realm(realm_name).await {
        Ok(Some(realm)) => realm,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid realm"})),
            )
                .into_response())
        }
    };
    let realm_id = realm.id.clone();

    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_token"})))
                .into_response()
        })?;

    let validated = state.token_service.validate_access_token(token).map_err(|e| {
        // A routinely expired token is client noise (the SPA refreshes and
        // retries); anything else (bad signature, wrong issuer, malformed)
        // is security-relevant and stays at WARN.
        if token_is_expired(token) {
            debug!(realm = %realm_id, error = %e, "account API authentication failed: token expired");
        } else {
            warn!(realm = %realm_id, error = %e, "account API authentication failed");
        }
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_token"})))
            .into_response()
    })?;

    // Verify the token's issuer belongs to this realm. The issuer embeds the
    // realm name.
    let token_realm =
        issuerd_core::typestate::extract_realm_from_issuer(validated.claims.iss.as_str());
    if token_realm != Some(realm.name.as_str()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
            .into_response());
    }

    // Wrap the validated user id in a realm-bound value and then produce the
    // compile-time proof required by account handlers. A token
    // minted for a pairwise client carries an irreversible `sub` — resolve
    // the real user through the token's session (the account-console client
    // is public by default, so this only matters when an admin opts a
    // first-party client into pairwise).
    let user_id =
        match super::oidc::resolve_token_user(state, &realm_id, &validated.claims, None).await {
            Some(user) => user.id,
            None => validated.claims.sub,
        };
    let bound = RealmBound::new(realm_id, user_id);
    Ok(AccountSessionGuard::bind(bound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::ServerConfig, state::ServerState};

    async fn test_state() -> Arc<ServerState> {
        let cfg = ServerConfig::default();
        Arc::new(ServerState::from_config(&cfg).await.unwrap())
    }

    fn master_realm() -> axum::extract::Extension<ResolvedRealm> {
        axum::extract::Extension(ResolvedRealm(Some("master".to_string())))
    }

    #[tokio::test]
    async fn account_me_requires_auth() {
        let response = account_me_handler(
            State(test_state().await),
            master_realm(),
            axum::http::HeaderMap::new(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_update_me_requires_auth() {
        let response = account_update_me_handler(
            State(test_state().await),
            master_realm(),
            axum::http::HeaderMap::new(),
            Json(UpdateMeRequest {
                first_name: None,
                last_name: None,
                email: None,
                username: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_change_password_requires_auth() {
        let response = account_change_password_handler(
            State(test_state().await),
            master_realm(),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            Json(ChangePasswordRequest {
                current_password: "old".to_string(),
                new_password: "new".to_string(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_credentials_requires_auth() {
        let response = account_credentials_handler(
            State(test_state().await),
            master_realm(),
            axum::http::HeaderMap::new(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_consents_requires_auth() {
        let response = account_consents_handler(
            State(test_state().await),
            master_realm(),
            axum::http::HeaderMap::new(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_delete_consent_requires_auth() {
        let response = account_delete_consent_handler(
            State(test_state().await),
            master_realm(),
            axum::http::HeaderMap::new(),
            Path(("master".to_string(), "some-client".to_string())),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_webauthn_register_start_requires_auth() {
        let response = account_webauthn_register_start_handler(
            State(test_state().await),
            master_realm(),
            axum::http::HeaderMap::new(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_webauthn_register_finish_requires_auth() {
        let response = account_webauthn_register_finish_handler(
            State(test_state().await),
            master_realm(),
            axum::http::HeaderMap::new(),
            Json(WebAuthnRegisterFinishRequest {
                label: None,
                credential: serde_json::json!({}),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_webauthn_credentials_requires_auth() {
        let response = account_webauthn_credentials_handler(
            State(test_state().await),
            master_realm(),
            axum::http::HeaderMap::new(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_webauthn_delete_requires_auth() {
        let response = account_webauthn_delete_handler(
            State(test_state().await),
            master_realm(),
            axum::http::HeaderMap::new(),
            Path(("master".to_string(), "some-credential".to_string())),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn update_me_request_distinguishes_absent_from_explicit_null() {
        let parsed: UpdateMeRequest = serde_json::from_str("{}").unwrap();
        assert!(parsed.first_name.is_none());
        assert!(parsed.last_name.is_none());
        assert!(parsed.email.is_none());
        assert!(parsed.username.is_none());

        let parsed: UpdateMeRequest = serde_json::from_str(
            r#"{"first_name": null, "email": "a@example.com", "username": "newname"}"#,
        )
        .unwrap();
        assert_eq!(parsed.first_name, Some(None));
        assert!(parsed.last_name.is_none());
        assert_eq!(parsed.email, Some(Some("a@example.com".to_string())));
        assert_eq!(parsed.username, Some("newname".to_string()));
    }

    #[test]
    fn parse_optional_name_maps_clear_value_and_validation() {
        assert_eq!(parse_optional_name(None).unwrap(), None);
        assert_eq!(
            parse_optional_name(Some("Ada".to_string())).unwrap(),
            Some(DisplayName::new("Ada").unwrap())
        );
        // Empty values are rejected by the newtype with a message for the 400.
        assert!(!parse_optional_name(Some(String::new())).unwrap_err().is_empty());
    }

    #[test]
    fn account_credentials_response_serializes_contract_shape() {
        let json = serde_json::to_value(AccountCredentialsResponse {
            password: true,
            totp: false,
            webauthn: true,
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({"password": true, "totp": false, "webauthn": true}));
    }

    #[test]
    fn account_consent_response_serializes_contract_shape() {
        let json = serde_json::to_value(AccountConsentResponse {
            client_id: "my-client".to_string(),
            granted_scopes: vec!["openid".to_string(), "profile".to_string()],
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            last_updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "client_id": "my-client",
                "granted_scopes": ["openid", "profile"],
                "created_at": "2026-01-01T00:00:00+00:00",
                "last_updated_at": "2026-01-02T00:00:00+00:00",
            })
        );
    }
}
