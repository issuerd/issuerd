// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Browser login endpoints: password login POST, SPA auth API, login page, and login context.

use std::sync::Arc;

use argon2::PasswordVerifier;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use issuerd_auth_flow::typestate::{ChallengeClassification, ChallengeExt, FlowOutput};
use issuerd_core::{AuthMethod, ClientIdentifier, EventType, FlowStageId, RealmId};

use crate::{
    middleware::{proxy_ip::ClientIp, realm::ResolvedRealm},
    state::{default_browser_flow, ServerState},
};

use super::oidc::{emit_oidc_event, PendingAuthData};
use tracing::{error, info, instrument, warn};

/// Maximum number of failed login attempts for a single pending auth flow
/// before the server breaks the redirect loop and returns an error to the
/// client application.
const MAX_LOGIN_ATTEMPTS: u8 = 3;

/// Process-wide argon2id hash for timing-equalizing dummy verifies (P3-6).
/// Generated once on first use so it is always a valid PHC string.
fn dummy_password_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        use argon2::PasswordHasher;
        let salt = argon2::password_hash::SaltString::generate(
            &mut argon2::password_hash::rand_core::OsRng,
        );
        argon2::Argon2::default()
            .hash_password(b"dummy-password", &salt)
            .map(|h| h.to_string())
            .unwrap_or_default()
    })
}

/// Mask an email address for the email-code challenge page: the first
/// character of the local part and of the domain survive, plus the final
/// domain suffix — `alice@example.com` → `a***@e***.com`.
fn mask_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "***".to_string();
    };
    let head = |s: &str| s.chars().next().map(|c| c.to_string()).unwrap_or_default();
    let suffix = domain.rfind('.').map(|i| &domain[i..]).unwrap_or("");
    format!("{}***@{}***{suffix}", head(local), head(domain))
}

/// Load the paused flow's bound user and mask their email address for the
/// email-code challenge page. `None` when no user is bound (the entered
/// address resolved to no account) or the user has no email — the page then
/// renders generic copy so account existence is not leaked.
async fn masked_email_for_pending(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    user_id: Option<&str>,
) -> Option<String> {
    let id = issuerd_core::UserId::new(user_id?).ok()?;
    let user = state.storage.get_user(realm_id, &id).await.ok()??;
    user.email.map(|e| mask_email(e.as_str()))
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct LoginRequest {
    pub execution_id: FlowStageId,
    /// Optional so the OTP challenge page can POST only `execution_id` + `otp`.
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    pub otp: Option<String>,
    /// Serialized WebAuthn assertion JSON posted by the passkey challenge page
    /// (or a JSON client answering a `webauthn` challenge).
    #[serde(default)]
    pub webauthn_assertion: Option<String>,
    /// "Resend code" submission from the email-code challenge page
    /// (`resend=1`/`true`); only meaningful to the `auth-email-code` stage.
    #[serde(default)]
    pub resend: Option<String>,
    /// Remember-me checkbox state; only honored when the realm enables it.
    pub remember_me: Option<bool>,
}

#[derive(Debug, serde::Serialize)]
pub struct LoginResponse {
    pub redirect_uri: String,
    pub code: Option<String>,
    pub id_token: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct AdminTokenRequest {
    pub realm: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, serde::Serialize)]
pub struct AdminTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[instrument(skip(state, query, headers, body_bytes), fields(realm = ?realm))]
pub async fn login_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let body: LoginRequest = if content_type.starts_with("application/x-www-form-urlencoded") {
        let form: std::collections::HashMap<String, String> =
            serde_urlencoded::from_bytes(&body_bytes).unwrap_or_default();
        LoginRequest {
            execution_id: form
                .get("execution_id")
                .map(|s| FlowStageId(s.clone()))
                .unwrap_or(FlowStageId("".into())),
            username: form.get("username").cloned().unwrap_or_default(),
            password: form.get("password").cloned().unwrap_or_default(),
            otp: form.get("otp").cloned(),
            webauthn_assertion: form.get("webauthn_assertion").cloned(),
            resend: form.get("resend").cloned(),
            // Checkbox semantics: only the usual truthy form values count.
            remember_me: form.get("remember_me").map(|v| matches!(v.as_str(), "on" | "true" | "1")),
        }
    } else {
        match serde_json::from_slice(&body_bytes) {
            Ok(req) => req,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid request body"})),
                )
                    .into_response();
            }
        }
    };

    let is_browser_form = content_type.starts_with("application/x-www-form-urlencoded");

    let realm_name = match realm.or_else(|| query.get("realm").cloned()) {
        Some(r) => r,
        None => {
            if is_browser_form {
                return Redirect::to("/login.html?error=missing_realm").into_response();
            }
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing realm"})))
                .into_response();
        }
    };

    // Look up realm by name so we have the correct realm ID for storage queries.
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            if is_browser_form {
                let mut redirect = url::form_urlencoded::Serializer::new(String::new());
                redirect.append_pair("realm", &realm_name);
                redirect.append_pair("error", "realm_not_found");
                return Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response();
            }
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "realm not found"})))
                .into_response();
        }
        Err(e) => {
            if is_browser_form {
                let mut redirect = url::form_urlencoded::Serializer::new(String::new());
                redirect.append_pair("realm", &realm_name);
                redirect.append_pair("error", "server_error");
                return Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response();
            }
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()})))
                .into_response();
        }
    };
    let realm_id = realm.id.clone();

    // The login POST must carry the correlation cookie set by the authorize
    // endpoint. Without it, an attacker could complete their own pending flow
    // with a victim's credentials (login CSRF).
    if !super::oidc::has_flow_cookie(&headers, &body.execution_id.0) {
        if is_browser_form {
            let mut redirect = url::form_urlencoded::Serializer::new(String::new());
            redirect.append_pair("realm", &realm_name);
            redirect.append_pair("error", "invalid_grant");
            return Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response();
        }
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
            .into_response();
    }

    // Look up pending auth data from cache. The entry is consumed atomically
    // (single-use); failure paths below re-store it so the user can retry.
    let cache_key = super::oidc::pending_auth_cache_key(&realm_id, &body.execution_id.0);
    let pending: Option<PendingAuthData> = match state.cache.get_and_delete(&cache_key).await {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
        _ => None,
    };

    let mut pending = match pending {
        Some(p) => p,
        None => {
            if is_browser_form {
                let mut redirect = url::form_urlencoded::Serializer::new(String::new());
                redirect.append_pair("execution_id", &body.execution_id.0);
                redirect.append_pair("realm", &realm_name);
                redirect.append_pair("error", "invalid_grant");
                return Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response();
            }
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    };

    // Validate the pending auth data belongs to the requested realm. With the
    // realm-scoped cache key this is defense-in-depth; never delete the entry
    // here (an unauthenticated POST must not wipe another realm's flow).
    if pending.realm_id != realm_id.as_ref() {
        if is_browser_form {
            let mut redirect = url::form_urlencoded::Serializer::new(String::new());
            redirect.append_pair("realm", &realm_name);
            redirect.append_pair("error", "invalid_grant");
            return Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response();
        }
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
            .into_response();
    }

    // Record the remember-me choice on the pending entry so it survives the
    // required-action continuation and reaches `complete_login`. The realm
    // toggle wins over the checkbox. Only overwrite when the checkbox was
    // part of this submission: the second-factor OTP page re-POSTs without
    // it and must not clobber the choice made on the password form.
    if let Some(remember_me) = body.remember_me {
        pending.remember_me = remember_me && realm.remember_me_enabled;
    }

    // Build typed auth context with credentials
    let pending_client_id = match issuerd_core::ClientId::new(&pending.client_id) {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    };
    let mut ctx = issuerd_core::typestate::TypedAuthContext::new_anonymous(realm_id.clone());
    ctx.client_id = Some(pending_client_id);
    ctx.ip_address = pending.ip_address;
    // Re-bind the already-authenticated user when resuming a paused
    // second-factor challenge (the OTP page posts only execution_id + otp,
    // and the OTP stage requires the user in context).
    if let Some(ref uid) = pending.user_id {
        if let Ok(id) = issuerd_core::UserId::new(uid.clone()) {
            ctx.user_id = Some(id);
        }
    }
    if realm.verify_email_enabled {
        ctx.attributes
            .insert("realm_verify_email_enabled".to_string(), "true".to_string());
    }

    let login_username = body.username.clone();
    ctx.parameters.insert("username".to_string(), vec![body.username]);
    ctx.parameters.insert("password".to_string(), vec![body.password]);
    if let Some(ref otp) = body.otp {
        ctx.parameters.insert("otp".to_string(), vec![otp.clone()]);
    }
    if let Some(ref assertion) = body.webauthn_assertion {
        ctx.parameters.insert("webauthn_assertion".to_string(), vec![assertion.clone()]);
    }
    if let Some(ref resend) = body.resend {
        ctx.parameters.insert("resend".to_string(), vec![resend.clone()]);
    }

    // Also re-inject original auth request params
    ctx.parameters
        .insert("response_type".to_string(), vec![pending.response_type.clone()]);
    ctx.parameters.insert("client_id".to_string(), vec![pending.client_id.clone()]);
    ctx.parameters
        .insert("redirect_uri".to_string(), vec![pending.redirect_uri.clone()]);
    if !pending.scope.is_empty() {
        ctx.parameters.insert("scope".to_string(), pending.scope.clone());
    }
    if let Some(ref s) = pending.state {
        ctx.parameters.insert("state".to_string(), vec![s.clone()]);
    }
    if let Some(ref n) = pending.nonce {
        ctx.parameters.insert("nonce".to_string(), vec![n.to_string()]);
    }

    // Run flow. The resume position is the flow stage id stored inside the
    // pending entry — not the browser-facing random flow id. The
    // realm's browser-flow binding selects the top-level flow from storage
    // (code default as fallback); the executor sees the full stored flow set
    // so sub-flow stages resolve.
    let (flow, executor) = state
        .bound_flow_executor(&realm, realm.browser_flow.as_deref(), "browser", default_browser_flow)
        .await;

    let outcome = match executor.continue_flow(&flow, &pending.execution_id, ctx).await {
        Ok(o) => o,
        Err(e) => {
            if is_browser_form {
                let mut redirect = url::form_urlencoded::Serializer::new(String::new());
                redirect.append_pair("execution_id", &body.execution_id.0);
                redirect.append_pair("realm", &realm_name);
                redirect.append_pair("error", e.oauth_error_code().as_ref());
                return Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response();
            }
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()})))
                .into_response();
        }
    };

    match outcome {
        FlowOutput::Success { ctx, result } => {
            info!(username = %issuerd_core::utils::sanitize_log_str(&login_username), "login succeeded");
            // The pending entry was already consumed atomically at lookup.

            // Required actions pending: hand off to the action continuation
            // (verify email, update password, ...) before any code/token is
            // minted. The continuation completes the login afterwards.
            if !result.required_actions.is_empty() {
                return super::required_actions::begin_actions_continuation(
                    &state,
                    &realm_name,
                    pending,
                    *result,
                    is_browser_form,
                )
                .await;
            }

            // Typestate proof: clear required actions before authorization
            let user_id = ctx.user_id.clone();
            let session_id = result.session_id.clone();
            let result_auth_time = result.auth_time;
            let _cleared = result.into_cleared();
            complete_login(
                &state,
                &realm_id,
                &pending,
                &user_id,
                &session_id,
                result_auth_time,
                is_browser_form,
            )
            .await
        }
        FlowOutput::Challenge { paused } => {
            // Advance the resume position to the stage that issued the
            // challenge (the OTP stage runs after a successful password
            // check) and remember the authenticated user so the resumed flow
            // re-enters with the user bound.
            pending.execution_id = paused.execution_id().clone();
            pending.user_id = paused.user_id().map(|u| u.0.clone());
            // Re-store the consumed entry so the user can answer the
            // challenge (e.g. OTP) with the same browser flow id.
            let cache_value = serde_json::to_vec(&pending).unwrap();
            let _ = state
                .cache
                .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
                .await;
            match paused.challenge().clone().classify() {
                ChallengeClassification::OtpForm(_) => {
                    // The passwordless email-code stage challenges with the
                    // same OtpForm kind as the TOTP second factor; tell them
                    // apart by the paused stage's authenticator. Sub-flow
                    // stages are not reachable here: `continue_flow` only
                    // resolves top-level stage ids as resume positions.
                    let is_email_code =
                        flow.stages.iter().find(|s| s.id == pending.execution_id).is_some_and(
                            |s| {
                                s.authenticator.as_str()
                                    == issuerd_auth_flow::email_code::AUTHENTICATOR_ID
                            },
                        );
                    if is_email_code {
                        if is_browser_form {
                            // A resubmitted code that still challenges was
                            // wrong or expired; a resend re-renders cleanly.
                            let error = if body.resend.is_some() {
                                None
                            } else {
                                body.otp.as_ref().map(|_| "Invalid or expired code.")
                            };
                            let masked = masked_email_for_pending(
                                &state,
                                &realm_id,
                                pending.user_id.as_deref(),
                            )
                            .await;
                            super::required_actions::email_code_challenge_page(
                                &realm_name,
                                &body.execution_id.0,
                                masked.as_deref(),
                                error,
                                issuerd_auth_flow::email_code::code_length(&realm),
                            )
                        } else {
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(serde_json::json!({
                                    "error": "authentication_challenge",
                                    "challenge": "email_code",
                                })),
                            )
                                .into_response()
                        }
                    } else if is_browser_form {
                        // A resubmitted code that still challenges was wrong.
                        let error = body.otp.as_ref().map(|_| "Invalid one-time code.");
                        super::required_actions::otp_challenge_page(
                            &realm_name,
                            &body.execution_id.0,
                            error,
                        )
                    } else {
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(serde_json::json!({
                                "error": "authentication_challenge",
                                "challenge": "otp",
                            })),
                        )
                            .into_response()
                    }
                }
                ChallengeClassification::WebAuthn(ch) => {
                    if is_browser_form {
                        // A resubmitted assertion that still challenges failed
                        // verification; re-render the page with an error.
                        let error = body
                            .webauthn_assertion
                            .as_ref()
                            .map(|_| "Passkey authentication failed. Try again.");
                        super::required_actions::webauthn_challenge_page(
                            &realm_name,
                            &body.execution_id.0,
                            ch.challenge(),
                            error,
                        )
                    } else {
                        // JSON clients get the raw request options to drive
                        // navigator.credentials.get() themselves.
                        let options: serde_json::Value =
                            serde_json::from_str(ch.challenge()).unwrap_or(serde_json::Value::Null);
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(serde_json::json!({
                                "error": "authentication_challenge",
                                "challenge": "webauthn",
                                "options": options,
                            })),
                        )
                            .into_response()
                    }
                }
                _ => {
                    if is_browser_form {
                        let mut redirect = url::form_urlencoded::Serializer::new(String::new());
                        redirect.append_pair("execution_id", &body.execution_id.0);
                        redirect.append_pair("realm", &realm_name);
                        redirect.append_pair("error", "authentication_challenge");
                        Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response()
                    } else {
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(serde_json::json!({"error": "authentication_challenge"})),
                        )
                            .into_response()
                    }
                }
            }
        }
        FlowOutput::Failure(e) => {
            warn!(username = %issuerd_core::utils::sanitize_log_str(&login_username), error = %e, "login failed");
            let mut details = std::collections::HashMap::new();
            details.insert("username".to_string(), login_username.clone());
            details.insert("error".to_string(), e.to_string());
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::LoginError,
                &pending.ip_address.unwrap_or("127.0.0.1".parse().unwrap()),
                issuerd_core::ClientId::new(&pending.client_id).ok(),
                None,
                None,
                Some(e.to_string()),
                details,
            )
            .await;
            if is_browser_form {
                // Increment attempt counter and store it back so repeated
                // failures do not bounce the browser forever.
                pending.attempt_count += 1;
                if pending.attempt_count >= MAX_LOGIN_ATTEMPTS {
                    // Entry already consumed at lookup; not re-storing it ends
                    // the flow.
                    let mut url = pending.redirect_uri.clone();
                    let sep = if url.contains('?') { "&" } else { "?" };
                    url.push_str(sep);
                    url.push_str("error=login_required");
                    if let Some(ref s) = pending.state {
                        url.push_str("&state=");
                        url.extend(url::form_urlencoded::byte_serialize(s.as_bytes()));
                    }
                    return Redirect::to(&url).into_response();
                }
                let cache_value = serde_json::to_vec(&pending).unwrap();
                let _ = state
                    .cache
                    .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
                    .await;

                let error_code = e.oauth_error_code();
                let mut redirect = url::form_urlencoded::Serializer::new(String::new());
                redirect.append_pair("execution_id", &body.execution_id.0);
                redirect.append_pair("realm", &realm_name);
                redirect.append_pair("error", error_code.as_ref());
                Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response()
            } else {
                (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": e.to_string()})))
                    .into_response()
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "Internal",
    summary = "Log out the first-party SPA session",
    description = "Destroys every SSO session referenced by the browser's per-realm `issuerd_session_{realm}` cookies (with back-channel logout) and clears those plus the `issuerd_remember_{realm}` cookies; the pre-realm-scoping `issuerd_session`/`issuerd_remember` names are honored and cleared as well.",
    operation_id = "auth_logout",
    responses(
        (status = 204, description = "Logged out; session cookies cleared"),
    ),
)]
#[instrument(skip(state, headers))]
pub async fn logout_api_handler(
    State(state): State<Arc<ServerState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Every cookie the browser carries for us, by name: the per-realm names
    // tell us which Set-Cookie clears to emit (the browser only echoes names
    // it actually holds), the legacy single names are always cleared too.
    let mut clear_names: Vec<String> = vec![
        "issuerd_session".to_string(),
        "issuerd_remember".to_string(),
    ];
    for cookie in headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|h| h.split(';'))
    {
        let Some((name, value)) = cookie.trim().split_once('=') else {
            continue;
        };
        if name == "issuerd_session" || name.starts_with("issuerd_session_") {
            clear_names.push(name.to_string());
            // Validate and destroy the referenced session (resolving the
            // realm from the realm-NAME based issuer), then fan out the
            // back-channel logout to its clients.
            if let Ok(validated) = state.token_service.validate_access_token(value) {
                let realm =
                    state.resolve_issuer_realm(validated.claims.iss.as_str()).await.ok().flatten();
                if let Some(realm) = realm {
                    if let Some(ref sid) = validated.claims.sid {
                        // Fetch before delete so the back-channel logout
                        // dispatcher can still see the client sessions.
                        let destroyed =
                            state.storage.get_user_session(&realm.id, sid).await.ok().flatten();
                        let _ = state.storage.delete_user_session(&realm.id, sid).await;
                        crate::session_cache::invalidate_session(&state, &realm.id, sid).await;
                        if let Some(destroyed) = destroyed {
                            state
                                .logout_notifier
                                .notify_session_destroyed(&realm, &destroyed)
                                .await;
                        }
                    }
                }
            }
        } else if name == "issuerd_remember" || name.starts_with("issuerd_remember_") {
            clear_names.push(name.to_string());
        }
    }

    clear_names.sort();
    clear_names.dedup();
    let mut resp = StatusCode::NO_CONTENT.into_response();
    for name in clear_names {
        if let Ok(v) = axum::http::HeaderValue::from_str(&format!(
            "{name}=; Max-Age=0; Path=/; Secure; SameSite=Lax; HttpOnly"
        )) {
            resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
        }
    }
    resp
}

/// Browser-form authorization response: package the parameter set per the
/// pending entry's `response_mode` (query/fragment redirect or a
/// form_post/JARM page) and attach the SSO session cookie to whatever
/// response shape comes back.
async fn browser_auth_response(
    state: &Arc<ServerState>,
    realm: &issuerd_core::Realm,
    pending: &super::oidc::PendingAuthData,
    params: &[(&str, &str)],
    cookie_value: &str,
) -> Response {
    let mut resp = crate::routes::auth_response::authorization_response(
        state,
        &pending.redirect_uri,
        params,
        &crate::routes::auth_response::ResponsePackaging::from_pending(realm, pending),
    )
    .await;
    if let Ok(v) = axum::http::HeaderValue::from_str(cookie_value) {
        resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
    }
    resp
}

/// Shared post-authentication completion: persist the SSO session, emit the
/// login event, set the session cookie, and mint the authorization code and/or
/// id_token per the requested response type.
///
/// Used by the password login handler and by the required-action continuation
/// once the last action clears. `result_auth_time` is the original
/// authentication time so tokens issued after a continuation keep it.
pub(crate) async fn complete_login(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    pending: &super::oidc::PendingAuthData,
    user_id: &issuerd_core::UserId,
    session_id: &issuerd_core::SessionId,
    result_auth_time: chrono::DateTime<chrono::Utc>,
    is_browser_form: bool,
) -> Response {
    complete_login_with_method(
        state,
        realm_id,
        pending,
        user_id,
        session_id,
        result_auth_time,
        is_browser_form,
        AuthMethod::Password,
        "password",
    )
    .await
}

/// Assemble the authorization-response parameter set for form-based browser
/// submissions (state first, then code, then id_token — the pre-24.7 order).
/// Delivery (query/fragment/form_post/JARM) is decided from the pending
/// entry's response_mode at response time.
fn response_params<'a>(
    pending: &'a super::oidc::PendingAuthData,
    code: Option<&'a str>,
    id_token: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut params: Vec<(&str, &str)> = Vec::new();
    if let Some(ref s) = pending.state {
        params.push(("state", s.as_str()));
    }
    if let Some(c) = code {
        params.push(("code", c));
    }
    if let Some(t) = id_token {
        params.push(("id_token", t));
    }
    params
}

/// [`complete_login`] with an explicit authentication method: identity
/// brokering completes logins with `AuthMethod::IdentityProvider`,
/// stamped on the session and the login event.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn complete_login_with_method(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    pending: &super::oidc::PendingAuthData,
    user_id: &issuerd_core::UserId,
    session_id: &issuerd_core::SessionId,
    result_auth_time: chrono::DateTime<chrono::Utc>,
    is_browser_form: bool,
    auth_method: AuthMethod,
    method_label: &str,
) -> Response {
    let realm_id = realm_id.clone();
    let user_id = user_id.clone();
    let session_id = session_id.clone();
    let pending = pending.clone();

    // Look up the authenticated user; provides the canonical username for the session.
    let user = match state.storage.get_user(&realm_id, &user_id).await {
        Ok(Some(u)) => u,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    };

    let pending_redirect_uri = match issuerd_core::RedirectUri::new(pending.redirect_uri.clone()) {
        Ok(uri) => Some(uri),
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    };

    let pending_client_identifier = match ClientIdentifier::new(&pending.client_id) {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    };
    let client = match state
        .storage
        .get_client_by_client_id(&realm_id, &pending_client_identifier)
        .await
    {
        Ok(Some(c)) => c,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"})))
                .into_response();
        }
    };

    let realm = match state.storage.get_realm(&realm_id).await {
        Ok(Some(r)) => r,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_realm"})))
                .into_response();
        }
    };

    // Consent gate: a consent-required client (or prompt=consent
    // carried in the pending entry) pauses here — after authentication,
    // before session/code issuance — until the user grants the scopes.
    if super::consent::consent_needed(
        state,
        &realm_id,
        &client,
        &user_id,
        &pending.scope,
        pending.prompt_consent,
    )
    .await
    {
        let entry = super::consent::PendingConsentData {
            user_id: user_id.0.clone(),
            session_id: session_id.0.clone(),
            result_auth_time,
            auth_time: result_auth_time,
            is_browser_form,
            sso_resume: false,
            auth_method,
            method_label: method_label.to_string(),
            error: None,
            _typestate_tag: "consent".to_string(),
            pending: pending.clone(),
        };
        return super::consent::begin_consent(state, realm.name.as_str(), entry).await;
    }

    // Create session (common to all response types)
    let session = issuerd_core::UserSession {
        id: session_id.clone(),
        realm_id: realm_id.clone(),
        user_id: user_id.clone(),
        login_username: user.username.clone(),
        auth_method,
        remember_me: pending.remember_me,
        offline: false,
        ip_address: pending.ip_address.unwrap_or("127.0.0.1".parse().unwrap()),
        started: result_auth_time,
        last_session_refresh: result_auth_time,
        auth_time: result_auth_time,
        impersonator: None,
        clients: vec![issuerd_core::ClientSession {
            id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id()).unwrap(),
            // The internal client id, NOT `pending.client_id` (the public
            // client_id name): PostgreSQL session rows are UUID-typed, and
            // every other construction site stores the internal id too.
            client_id: client.id.clone(),
            session_id: session_id.clone(),
            redirect_uri: pending_redirect_uri,
            state: pending.state.clone(),
            auth_method,
            timestamp: result_auth_time,
        }],
    };
    if let Err(e) = state.storage.create_user_session(&realm_id, &session).await {
        error!(realm = %realm_id, error = %e, "failed to persist user session");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error"})),
        )
            .into_response();
    }

    let mut details = std::collections::HashMap::new();
    details.insert("method".to_string(), method_label.to_string());
    details.insert("username".to_string(), user.username.to_string());
    emit_oidc_event(
        state,
        &realm_id,
        EventType::Login,
        &pending.ip_address.unwrap_or("127.0.0.1".parse().unwrap()),
        Some(client.id.clone()),
        Some(user.id.clone()),
        Some(session.id.clone()),
        None,
        details,
    )
    .await;

    // Issue a session cookie for SSO (claims via protocol mappers)
    let mut overlay = crate::claims::build_claims_overlay(
        state,
        &realm_id,
        Some(&client),
        &user,
        &pending.scope,
        issuerd_core::ClaimTarget::AccessToken,
    )
    .await
    .unwrap_or_default();

    // An impersonated session keeps the `impersonator` claim on the
    // SSO cookie token. (Sessions created by this path are never impersonated
    // today — impersonation issues tokens directly from the admin API — but
    // the guard keeps the claim if a session with an impersonator ever
    // completes through here.)
    if let Some(ref impersonator) = session.impersonator {
        overlay.insert(
            "impersonator".to_string(),
            serde_json::Value::String(impersonator.to_string()),
        );
    }

    let sso_token = match state
        .token_manager
        .issue_access_token_with_roles(
            &user,
            &client,
            &realm,
            &pending.scope,
            &session_id,
            None,
            pending.claims.clone(),
            Some(overlay),
        )
        .await
    {
        Ok(t) => t,
        Err(e) => {
            error!(realm = %realm_id, error = %e, "failed to issue SSO session token");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let cookie_value = format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/",
        super::oidc::session_cookie_name(&realm_id),
        sso_token.token
    );
    let cookie_header = [(axum::http::header::SET_COOKIE, cookie_value.clone())];

    // Remember-me: alongside the SSO cookie, issue the long-lived
    // realm-bound remember cookie (a signed action token) that can silently
    // re-establish a session after SSO idle expiry.
    let remember_cookie = if pending.remember_me {
        let mut claims = issuerd_token::action_tokens::action_token_claims(
            &user_id,
            &realm_id,
            issuerd_core::ACTION_TOKEN_PURPOSE_REMEMBER_ME,
            realm.remember_me_session_idle_secs.get() as i64,
        );
        claims.auth_time = Some(result_auth_time.timestamp());
        match issuerd_token::action_tokens::issue_action_token(state.crypto.as_ref(), &claims).await
        {
            Ok(token) => Some(format!(
                "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
                super::oidc::remember_cookie_name(&realm_id),
                token,
                realm.remember_me_session_idle_secs.get()
            )),
            Err(e) => {
                error!(realm = %realm_id, error = %e, "failed to issue remember-me token");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    } else {
        None
    };
    // Append the remember cookie (when present) as a second Set-Cookie header.
    let with_remember_cookie = |resp: Response| -> Response {
        let mut resp = resp;
        if let Some(ref cookie) = remember_cookie {
            if let Ok(v) = axum::http::HeaderValue::from_str(cookie) {
                resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
            }
        }
        resp
    };

    let resp = match pending.response_type.as_str() {
        "id_token" => {
            // Implicit flow: issue id_token directly; scope claims embed via
            // the mapper overlay (no access token is issued alongside).
            let overlay = crate::claims::build_claims_overlay(
                state,
                &realm_id,
                Some(&client),
                &user,
                &pending.scope,
                issuerd_core::ClaimTarget::IdToken,
            )
            .await
            .unwrap_or_default();
            let id_token = match state
                .token_manager
                .issue_id_token(
                    &user,
                    &client,
                    &realm,
                    pending.nonce.as_deref(),
                    result_auth_time,
                    &session_id,
                    None,
                    None,
                    Some(&pending.acr_values),
                    Some(overlay),
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    error!(realm = %realm_id, error = %e, "failed to issue ID token");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response();
                }
            };

            if is_browser_form {
                browser_auth_response(
                    state,
                    &realm,
                    &pending,
                    &response_params(&pending, None, Some(&id_token.token)),
                    &cookie_value,
                )
                .await
            } else {
                (
                    cookie_header,
                    Json(LoginResponse {
                        redirect_uri: pending.redirect_uri,
                        code: None,
                        id_token: Some(id_token.token),
                        state: pending.state,
                    }),
                )
                    .into_response()
            }
        }
        "code id_token" => {
            // Hybrid flow: issue both code and id_token
            let code = issuerd_core::utils::generate_id();
            let code_data = super::oidc::AuthCodeData::from_pending(
                &pending,
                &user_id,
                &session_id,
                result_auth_time,
            );
            super::oidc::store_auth_code(&state.cache, &code, &code_data).await;

            let id_token = match state
                .token_manager
                .issue_id_token(
                    &user,
                    &client,
                    &realm,
                    pending.nonce.as_deref(),
                    result_auth_time,
                    &session_id,
                    None,
                    Some(&code),
                    Some(&pending.acr_values),
                    // Hybrid flow: userinfo claims via the userinfo endpoint.
                    None,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    error!(realm = %realm_id, error = %e, "failed to issue ID token");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response();
                }
            };

            if is_browser_form {
                browser_auth_response(
                    state,
                    &realm,
                    &pending,
                    &response_params(&pending, Some(&code), Some(&id_token.token)),
                    &cookie_value,
                )
                .await
            } else {
                (
                    cookie_header,
                    Json(LoginResponse {
                        redirect_uri: pending.redirect_uri,
                        code: Some(code),
                        id_token: Some(id_token.token),
                        state: pending.state,
                    }),
                )
                    .into_response()
            }
        }
        _ => {
            // Authorization code flow
            let code = issuerd_core::utils::generate_id();
            let code_data = super::oidc::AuthCodeData::from_pending(
                &pending,
                &user_id,
                &session_id,
                result_auth_time,
            );
            super::oidc::store_auth_code(&state.cache, &code, &code_data).await;

            if is_browser_form {
                browser_auth_response(
                    state,
                    &realm,
                    &pending,
                    &response_params(&pending, Some(&code), None),
                    &cookie_value,
                )
                .await
            } else {
                (
                    cookie_header,
                    Json(LoginResponse {
                        redirect_uri: pending.redirect_uri,
                        code: Some(code),
                        id_token: None,
                        state: pending.state,
                    }),
                )
                    .into_response()
            }
        }
    };
    with_remember_cookie(resp)
}

#[instrument(skip(state, body, ip), fields(realm = %body.realm, username = %issuerd_core::utils::sanitize_log_str(&body.username)))]
pub async fn admin_token_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    Json(body): Json<AdminTokenRequest>,
) -> Response {
    // Verify realm exists by name (the `realm` field is the realm name, not ID)
    let realm = match state.resolve_realm(&body.realm).await {
        Ok(Some(r)) => r,
        _ => {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    };
    let realm_id = realm.id.clone();

    // Find user
    let user = match state.storage.get_user_by_username(&realm_id, &body.username).await {
        Ok(Some(u)) if u.enabled => u,
        _ => {
            // Run a dummy argon2 verify so unknown/disabled usernames cost the
            // same as a wrong password — otherwise the response time leaks
            // which usernames exist (P3-6).
            let parsed = argon2::PasswordHash::new(dummy_password_hash());
            if let Ok(parsed) = parsed {
                let _ =
                    argon2::Argon2::default().verify_password(body.password.as_bytes(), &parsed);
            }
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    };

    // Brute-force lockout, keyed like the browser login flow (canonical
    // username + source IP). Realms without brute-force protection skip
    // failure tracking entirely.
    let brute_force = realm
        .brute_force_protected
        .then(|| issuerd_auth_flow::login_failures::LoginFailureConfig::from_realm(&realm));
    let ip_key = ip.to_string();
    if brute_force.is_some() {
        let locked = state
            .login_failure_tracker
            .is_temporarily_locked(&realm_id, user.username.as_str(), &ip_key, state.cache.as_ref())
            .await
            .unwrap_or(false);
        if locked {
            warn!(realm = %body.realm, username = %issuerd_core::utils::sanitize_log_str(&body.username), "admin token request rejected: account temporarily locked");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    }

    // Verify password
    let creds = match state
        .storage
        .get_credentials(&realm_id, &user.id, issuerd_core::CredentialType::Password)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(realm = %realm_id, error = %e, "failed to load user credentials");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    };

    let mut matched = false;
    for cred in &creds {
        let hash_str = match String::from_utf8(cred.secret_data.clone()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let parsed = match argon2::PasswordHash::new(&hash_str) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if argon2::Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed)
            .is_ok()
        {
            matched = true;
            break;
        }
    }

    if !matched {
        warn!(realm = %body.realm, username = %issuerd_core::utils::sanitize_log_str(&body.username), "admin token request failed: invalid password");
        if let Some(ref config) = brute_force {
            let _ = state
                .login_failure_tracker
                .record_failure(
                    &realm_id,
                    user.username.as_str(),
                    &ip_key,
                    state.cache.as_ref(),
                    config,
                )
                .await;
        }
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_grant"})))
            .into_response();
    }

    // Successful authentication clears the failure counter.
    if brute_force.is_some() {
        let _ = state
            .login_failure_tracker
            .reset_failures(&realm_id, user.username.as_str(), &ip_key, state.cache.as_ref())
            .await;
    }

    // Get admin-cli client
    let client = match state
        .storage
        .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            error!(realm = %realm_id, "admin-cli client not found");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "client_not_found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!(realm = %realm_id, error = %e, "failed to load admin-cli client");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "client_not_found"})),
            )
                .into_response();
        }
    };

    // Roles and scope claims flow through protocol mappers. The
    // hardcoded scope list below is kept verbatim; default-assigned client
    // scopes (notably `roles`) still apply to the access token.
    let admin_scope = ["openid".to_string(), "profile".to_string()];
    let overlay = crate::claims::build_claims_overlay(
        &state,
        &realm_id,
        Some(&client),
        &user,
        &admin_scope,
        issuerd_core::ClaimTarget::AccessToken,
    )
    .await
    .unwrap_or_default();

    // Create session
    let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
    let now = chrono::Utc::now();
    let session = issuerd_core::UserSession {
        id: session_id.clone(),
        realm_id: realm_id.clone(),
        user_id: user.id.clone(),
        login_username: user.username.clone(),
        auth_method: AuthMethod::Password,
        remember_me: false,
        offline: false,
        ip_address: ip,
        started: now,
        last_session_refresh: now,
        auth_time: now,
        impersonator: None,
        clients: vec![issuerd_core::ClientSession {
            id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id()).unwrap(),
            client_id: client.id.clone(),
            session_id: session_id.clone(),
            redirect_uri: None,
            state: None,
            auth_method: AuthMethod::Password,
            timestamp: now,
        }],
    };
    if let Err(e) = state.storage.create_user_session(&realm_id, &session).await {
        error!(realm = %realm_id, error = %e, "failed to persist user session");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error"})),
        )
            .into_response();
    }

    // Issue access token with roles (via the mapper overlay)
    let access_token = match state
        .token_manager
        .issue_access_token_with_roles(
            &user,
            &client,
            &realm,
            &admin_scope,
            &session_id,
            None,
            None,
            Some(overlay),
        )
        .await
    {
        Ok(t) => t,
        Err(e) => {
            error!(realm = %realm_id, error = %e, "failed to issue admin access token");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    info!(realm = %body.realm, username = %issuerd_core::utils::sanitize_log_str(&body.username), "admin token issued");
    Json(AdminTokenResponse {
        access_token: access_token.token,
        token_type: "Bearer".to_string(),
        expires_in: realm.access_token_lifespan.get() as i64,
    })
    .into_response()
}

/// Redirect `/realms/{realm}/login` to the static login page with realm context.
/// This provides a Keycloak-compatible convenience URL for direct realm login.
pub async fn realm_login_page_handler(
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
) -> Response {
    let realm_name = realm.unwrap_or_else(|| "master".to_string());
    Redirect::to(&super::oidc::build_redirect_url(
        "/login.html",
        &[("realm", realm_name.as_str())],
        false,
    ))
    .into_response()
}

/// Public login-page bootstrap payload.
///
/// Exposes only the non-sensitive realm login flags the static `login.html`
/// needs to render its conditional elements (register link, forgot-password
/// link, remember-me checkbox). Unauthenticated by design — these flags are
/// UI hints, not enforcement (the enforcing endpoints re-check the realm).
/// An identity provider offered on the login page. Only enabled
/// broker providers are listed; the alias is the `{alias}` path segment of
/// the broker login route.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct LoginContextIdp {
    pub alias: String,
    pub display_name: String,
    pub provider_id: String,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct LoginContextResponse {
    pub registration_enabled: bool,
    pub reset_password_allowed: bool,
    pub remember_me_enabled: bool,
    pub login_with_email_allowed: bool,
    pub duplicate_emails_allowed: bool,
    pub edit_username_allowed: bool,
    pub verify_email_enabled: bool,
    /// Passwordless email-code login: the realm attribute
    /// `email_code_login == "true"` switches the login page to a single
    /// email field (no password) whose submission mails a one-time code.
    pub email_code_login: bool,
    pub identity_providers: Vec<LoginContextIdp>,
    /// Resolved UI locale for this request: pinned by the paused
    /// flow when `execution_id` is passed, else resolved from
    /// `Accept-Language` and the realm defaults.
    pub locale: String,
    /// Locale tags the realm allows (empty = unrestricted).
    pub supported_locales: Vec<String>,
    /// Login theme name when the realm overrides the built-in default.
    pub login_theme: Option<String>,
    /// Message bundle for `locale` (per-key English fallback applied).
    pub messages: std::collections::HashMap<String, String>,
}

/// Query parameters for [`login_context_handler`].
#[derive(Debug, serde::Deserialize)]
pub struct LoginContextQuery {
    /// Paused login flow whose pinned locale should be reused.
    pub execution_id: Option<String>,
}

#[utoipa::path(
    get,
    path = "/realms/{realm}/login/context",
    tag = "Protocol",
    summary = "Public realm login configuration for the login page",
    operation_id = "login_context",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("execution_id" = Option<String>, Query, description = "Paused login flow whose pinned locale should be reused"),
    ),
    responses(
        (status = 200, description = "Realm login flags", body = LoginContextResponse),
        (status = 400, description = "Missing or invalid realm", body = crate::openapi::AccountErrorResponse),
    ),
    security(()),
)]
/// `GET /realms/{realm}/login/context` — realm login flags for the login page.
pub async fn login_context_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    Query(query): Query<LoginContextQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(realm_name) = realm else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing realm"})))
            .into_response();
    };
    match state.resolve_realm(&realm_name).await {
        Ok(Some(realm)) => {
            let idps = match state.storage.list_identity_providers(&realm.id).await {
                Ok(list) => list,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response()
                }
            };
            let identity_providers = idps
                .iter()
                .filter(|i| {
                    i.enabled && issuerd_core::BrokerIdpSettings::new(i).is_broker_provider()
                })
                .map(|i| LoginContextIdp {
                    alias: i.alias.to_string(),
                    display_name: issuerd_core::BrokerIdpSettings::new(i).display_name(),
                    provider_id: i.provider_id.as_str().to_string(),
                })
                .collect();
            // A paused flow pins its locale at the authorize
            // endpoint; reuse it when the login page passes its flow id.
            let pending_locale = match &query.execution_id {
                Some(execution) => {
                    let key = super::oidc::pending_auth_cache_key(&realm.id, execution);
                    match state.cache.get(&key).await {
                        Ok(Some(bytes)) => serde_json::from_slice::<PendingAuthData>(&bytes)
                            .ok()
                            .and_then(|p| p.locale),
                        _ => None,
                    }
                }
                None => None,
            };
            let locale = pending_locale.unwrap_or_else(|| {
                crate::i18n::resolve_locale(
                    &realm,
                    &[],
                    headers.get(axum::http::header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()),
                )
            });
            let bundle = crate::i18n::message_bundle(
                Some(state.config.themes.dir.as_path()),
                realm.login_theme.as_ref().map(|t| t.as_str()),
                &locale,
            );
            Json(LoginContextResponse {
                registration_enabled: realm.registration_enabled,
                reset_password_allowed: realm.reset_password_allowed,
                remember_me_enabled: realm.remember_me_enabled,
                login_with_email_allowed: realm.login_with_email_allowed,
                duplicate_emails_allowed: realm.duplicate_emails_allowed,
                edit_username_allowed: realm.edit_username_allowed,
                verify_email_enabled: realm.verify_email_enabled,
                email_code_login: realm
                    .attributes
                    .get(issuerd_auth_flow::email_code::REALM_ATTR_EMAIL_CODE_LOGIN)
                    .map(String::as_str)
                    == Some("true"),
                identity_providers,
                locale,
                supported_locales: realm.supported_locales.clone(),
                login_theme: realm.login_theme.as_ref().map(|t| t.as_str().to_string()),
                messages: bundle,
            })
            .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "realm not found"})))
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use issuerd_core::{
        AuthContext, AuthMethod, Authenticator, ClientAuthenticatorType, ClientProtocol, Scope,
        Storage,
    };

    #[test]
    fn mask_email_hides_local_part_and_domain() {
        assert_eq!(mask_email("alice@example.com"), "a***@e***.com");
        assert_eq!(mask_email("b@sub.domain.org"), "b***@s***.org");
        // Degenerate inputs never panic and never echo the full address.
        assert_eq!(mask_email("no-at-sign"), "***");
        assert_eq!(mask_email("@example.com"), "***@e***.com");
        assert_eq!(mask_email("a@localhost"), "a***@l***");
    }

    #[tokio::test]
    async fn masked_email_for_pending_requires_bound_user_with_email() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm_id = RealmId::new("master").unwrap();

        // No bound user → nothing to show.
        assert!(masked_email_for_pending(&state, &realm_id, None).await.is_none());
        // Unknown user id → nothing to show.
        assert!(masked_email_for_pending(&state, &realm_id, Some("no-such-user"))
            .await
            .is_none());
        // The bootstrapped admin user has an email address.
        let masked = masked_email_for_pending(&state, &realm_id, Some("admin"))
            .await
            .expect("admin email masked");
        assert_eq!(masked, "a***@l***.local");
    }

    #[tokio::test]
    async fn admin_token_success() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "admin".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["access_token"].as_str().unwrap().len() > 10);
        assert_eq!(json["token_type"], "Bearer");
        assert!(json["expires_in"].as_i64().unwrap() > 0);
    }

    #[tokio::test]
    async fn admin_token_wrong_password() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "admin".to_string(),
                password: "wrong".to_string(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_token_disabled_user_rejected() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let mut user =
            state.storage.get_user_by_username(&realm_id, "admin").await.unwrap().unwrap();
        user.enabled = false;
        state.storage.update_user(&realm_id, &user).await.unwrap();

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "admin".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;

        // Same generic error as bad credentials: no account-state oracle.
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    async fn extract_json(resp: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn setup_state() -> Arc<ServerState> {
        Arc::new(ServerState::from_config(&ServerConfig::default()).await.unwrap())
    }

    /// Request headers carrying the flow correlation cookie that the authorize
    /// endpoint sets alongside the `execution_id` redirect.
    fn headers_with_flow_cookie(flow_id: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(axum::http::header::COOKIE, format!("issuerd_flow_{flow_id}=1").parse().unwrap());
        h
    }

    #[tokio::test]
    async fn login_success() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("xyz".to_string()),
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let response = login_handler(
            State(state.clone()),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        // The SSO cookie is realm-scoped so one realm's login cannot clobber
        // another realm's SSO session.
        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.starts_with("issuerd_session_master="), "cookie: {set_cookie}");
        let json = extract_json(response).await;
        assert!(json["code"].as_str().unwrap().len() > 5);
        assert!(json["id_token"].is_null());
        assert_eq!(json["redirect_uri"], "http://localhost:8080/cb");
    }

    #[tokio::test]
    async fn login_requires_flow_correlation_cookie() {
        let state = setup_state().await;
        // Browser-facing flow id is random and distinct from the resume stage id.
        let flow_id = issuerd_core::utils::generate_id();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("xyz".to_string()),
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: FlowStageId::new("username-password").unwrap(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &flow_id,
        );
        state
            .cache
            .set(
                &cache_key,
                serde_json::to_vec(&pending).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let login = |headers: axum::http::HeaderMap, flow_id: String| {
            let state = state.clone();
            async move {
                login_handler(
                    State(state),
                    axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                        "master".to_string(),
                    ))),
                    Query(std::collections::HashMap::new()),
                    headers,
                    axum::body::Bytes::from(
                        serde_json::to_vec(&LoginRequest {
                            execution_id: FlowStageId::new(flow_id).unwrap(),
                            username: "admin".to_string(),
                            password: "admin".to_string(),
                            otp: None,
                            remember_me: None,
                            webauthn_assertion: None,
                            resend: None,
                        })
                        .unwrap(),
                    ),
                )
                .await
            }
        };

        // 1. No correlation cookie: rejected even though the entry exists.
        let resp = login(axum::http::HeaderMap::new(), flow_id.clone()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 2. Wrong cookie (attacker's flow id): rejected.
        let resp = login(headers_with_flow_cookie("attacker-flow"), flow_id.clone()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 3. Correct cookie: succeeds and consumes the entry (single-use).
        let resp = login(headers_with_flow_cookie(&flow_id), flow_id.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let leftover = state.cache.get(&cache_key).await.unwrap();
        assert!(leftover.is_none(), "pending entry must be consumed");

        // 4. Replay with the same flow id + cookie: rejected.
        let resp = login(headers_with_flow_cookie(&flow_id), flow_id).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_success_implicit_flow() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("xyz".to_string()),
            nonce: Some(issuerd_core::Nonce::new("abc").unwrap()),
            response_type: "id_token".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let response = login_handler(
            State(state.clone()),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert!(json["id_token"].is_string());
        assert!(json["id_token"].as_str().unwrap().len() > 10);
        assert!(json["code"].is_null());
        assert_eq!(json["redirect_uri"], "http://localhost:8080/cb");
        assert_eq!(json["state"], "xyz");
    }

    #[tokio::test]
    async fn login_success_hybrid_flow_code_id_token() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("xyz".to_string()),
            nonce: Some(issuerd_core::Nonce::new("abc").unwrap()),
            response_type: "code id_token".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let response = login_handler(
            State(state.clone()),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert!(json["code"].is_string());
        assert!(json["code"].as_str().unwrap().len() > 5);
        assert!(json["id_token"].is_string());
        assert!(json["id_token"].as_str().unwrap().len() > 10);
        assert_eq!(json["redirect_uri"], "http://localhost:8080/cb");
        assert_eq!(json["state"], "xyz");
    }

    #[tokio::test]
    async fn login_missing_realm() {
        let state = setup_state().await;
        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(None)),
            Query(std::collections::HashMap::new()),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id: FlowStageId::new("test").unwrap(),
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_pending_not_found() {
        let state = setup_state().await;
        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id: FlowStageId::new("does-not-exist").unwrap(),
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_wrong_password() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "wrong".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_form_urlencoded_wrong_password_redirects() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_flow_{}=1", execution_id.0).parse().unwrap(),
        );

        let form_body = serde_urlencoded::to_string([
            ("execution_id", execution_id.0.as_str()),
            ("username", "admin"),
            ("password", "wrong"),
        ])
        .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers,
            axum::body::Bytes::from(form_body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location =
            response.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap();
        assert!(location.starts_with("/login.html"));
        assert!(location.contains("error=invalid_grant"));
        assert!(location.contains("execution_id="));
    }

    #[tokio::test]
    async fn logout_api_returns_no_content() {
        let state = setup_state().await;
        let response = logout_api_handler(State(state), axum::http::HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn logout_api_clears_cookie() {
        let state = setup_state().await;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, "issuerd_session=dummy".parse().unwrap());
        let response = logout_api_handler(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let set_cookie = response.headers().get(axum::http::header::SET_COOKIE).unwrap();
        assert!(set_cookie.to_str().unwrap().contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn admin_token_missing_realm() {
        let state = setup_state().await;
        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "nonexistent".to_string(),
                username: "admin".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_token_missing_user() {
        let state = setup_state().await;
        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "nobody".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_token_missing_credentials() {
        let state = setup_state().await;
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("nocreds").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            username: issuerd_core::Username::new("nocreds").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: std::collections::HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&user.realm_id, &user).await.unwrap();

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "nocreds".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_token_missing_client() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        state.storage.delete_client(&realm_id, &client.id).await.unwrap();

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "admin".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn login_form_urlencoded_code_flow() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("xyz".to_string()),
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_flow_{}=1", execution_id.0).parse().unwrap(),
        );
        let body = format!("execution_id={}&username=admin&password=admin", execution_id);

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers,
            axum::body::Bytes::from(body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="));
        assert!(location.contains("state=xyz"));
    }

    #[tokio::test]
    async fn login_form_urlencoded_implicit_flow() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("xyz".to_string()),
            nonce: Some(issuerd_core::Nonce::new("abc").unwrap()),
            response_type: "id_token".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_flow_{}=1", execution_id.0).parse().unwrap(),
        );
        let body = format!("execution_id={}&username=admin&password=admin", execution_id);

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers,
            axum::body::Bytes::from(body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("id_token="));
        assert!(location.contains("state=xyz"));
    }

    #[tokio::test]
    async fn login_form_urlencoded_hybrid_flow() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("xyz".to_string()),
            nonce: Some(issuerd_core::Nonce::new("abc").unwrap()),
            response_type: "code id_token".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_flow_{}=1", execution_id.0).parse().unwrap(),
        );
        let body = format!("execution_id={}&username=admin&password=admin", execution_id);

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers,
            axum::body::Bytes::from(body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="));
        assert!(location.contains("id_token="));
        assert!(location.contains("state=xyz"));
    }

    #[tokio::test]
    async fn login_invalid_json_body() {
        let state = setup_state().await;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::CONTENT_TYPE, "application/json".parse().unwrap());

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers,
            axum::body::Bytes::from("not json"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_with_otp() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: Some("123456".to_string()),
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logout_api_with_valid_token_realm_extraction() {
        let state = setup_state().await;
        // Issue a token so we can pass it as a cookie
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = crate::routes::oidc::token_handler(
            State(state.clone()),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_session={}", access_token).parse().unwrap(),
        );
        let response = logout_api_handler(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn admin_token_invalid_utf8_cred() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("badutf8").unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new("badutf8").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: std::collections::HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: vec![0x80, 0x81, 0x82], // invalid UTF-8
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&realm_id, &user.id, &cred).await.unwrap();

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "badutf8".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_token_invalid_hash_cred() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("badhash").unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new("badhash").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: std::collections::HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: b"not-a-valid-hash".to_vec(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&realm_id, &user.id, &cred).await.unwrap();

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "badhash".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_success_user_with_no_roles() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();

        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("noroles").unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new("noroles").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: std::collections::HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();

        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default().hash_password("pass".as_bytes(), &salt).unwrap().to_string();
        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&realm_id, &user.id, &cred).await.unwrap();

        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let pending_json = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(
                &crate::routes::oidc::pending_auth_cache_key(&realm_id, &execution_id.0),
                pending_json,
                Some(std::time::Duration::from_secs(300)),
            )
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "noroles".to_string(),
                    password: "pass".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logout_api_handler_clears_cookie() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user_id = issuerd_core::UserId::new("admin").unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();

        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user_id.clone(),
            ip_address: "127.0.0.1".parse().unwrap(),
            login_username: issuerd_core::Username::new("admin").unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: chrono::Utc::now(),
            last_session_refresh: chrono::Utc::now(),
            auth_time: chrono::Utc::now(),
            impersonator: None,
            clients: vec![],
        };
        state.storage.create_user_session(&realm_id, &session).await.unwrap();

        let user = state.storage.get_user(&realm_id, &user_id).await.unwrap().unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let access_token = state
            .token_manager
            .issue_access_token_with_roles(
                &user,
                &client,
                &realm,
                &["openid".to_string()],
                &session_id,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_session={}", access_token.token).parse().unwrap(),
        );

        let response = logout_api_handler(State(state), headers).await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let set_cookie = response.headers().get(axum::http::header::SET_COOKIE);
        assert!(set_cookie.is_some());
        let cookie_str = set_cookie.unwrap().to_str().unwrap();
        assert!(
            cookie_str.contains("Max-Age=0") || cookie_str.contains("Expires="),
            "cookie: {}",
            cookie_str
        );
    }

    #[tokio::test]
    async fn logout_api_destroys_session_via_per_realm_cookie_and_clears_all_names() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user_id = issuerd_core::UserId::new("admin").unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();

        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user_id.clone(),
            ip_address: "127.0.0.1".parse().unwrap(),
            login_username: issuerd_core::Username::new("admin").unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: chrono::Utc::now(),
            last_session_refresh: chrono::Utc::now(),
            auth_time: chrono::Utc::now(),
            impersonator: None,
            clients: vec![],
        };
        state.storage.create_user_session(&realm_id, &session).await.unwrap();

        let user = state.storage.get_user(&realm_id, &user_id).await.unwrap().unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let access_token = state
            .token_manager
            .issue_access_token_with_roles(
                &user,
                &client,
                &realm,
                &["openid".to_string()],
                &session_id,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_session_master={}; issuerd_remember_master=xyz", access_token.token)
                .parse()
                .unwrap(),
        );

        let response = logout_api_handler(State(state.clone()), headers).await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        // The referenced session is gone.
        assert!(
            state.storage.get_user_session(&realm_id, &session_id).await.unwrap().is_none(),
            "session must be destroyed"
        );
        // Every echoed cookie name is cleared, plus the legacy single names.
        let cleared: Vec<String> = response
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        for expected in [
            "issuerd_session_master",
            "issuerd_remember_master",
            "issuerd_session",
            "issuerd_remember",
        ] {
            assert!(
                cleared.iter().any(|c| c.starts_with(&format!("{expected}=; Max-Age=0"))),
                "missing clear for {expected}; got: {cleared:?}"
            );
        }
    }

    #[tokio::test]
    async fn login_continue_flow_unknown_execution_id() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("unknown-stage").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_client_deleted_after_pending_auth() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        // Delete the client so get_client_by_client_id returns None
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        state.storage.delete_client(&realm_id, &client.id).await.unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn admin_token_get_credentials_error() {
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage.expect_get_realm_by_name().returning(|_| {
            Ok(Some(issuerd_core::Realm {
                id: issuerd_core::RealmId::new("master").unwrap(),
                name: issuerd_core::RealmName::new("master").unwrap(),
                display_name: None,
                enabled: true,
                access_token_lifespan: issuerd_core::SecondsNonZero::new(300),
                ..Default::default()
            }))
        });
        mock_storage.expect_get_user_by_username().returning(|_, username| {
            Ok(Some(issuerd_core::User {
                id: issuerd_core::UserId::new("admin").unwrap(),
                realm_id: issuerd_core::RealmId::new("master").unwrap(),
                username: issuerd_core::Username::new(username)
                    .expect("login username must be valid"),
                email: None,
                email_verified: false,
                first_name: None,
                last_name: None,
                enabled: true,
                federation_link: None,
                attributes: std::collections::HashMap::new(),
                required_actions: Vec::new(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }))
        });
        mock_storage.expect_get_credentials().returning(|_, _, _| {
            Err(issuerd_core::IssuerdError::ServerError("db fail".to_string()))
        });

        let state = Arc::new(ServerState {
            config: ServerConfig::default(),
            storage: Arc::new(mock_storage),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            crypto: Arc::new(
                issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                    .unwrap(),
            ),
            token_service: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            token_manager: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            plugin_registry: Arc::new(crate::state::SimplePluginRegistry::new()),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            login_failure_tracker: Arc::new(
                issuerd_auth_flow::login_failures::LoginFailureTracker::new(),
            ),
            email_sender: Arc::new(crate::email::NoOpEmailSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            signing_key_reload: Arc::new(|| {}),
            keyset_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            event_listeners: std::collections::HashMap::new(),
        });

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "admin".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_browser_form_redirects_to_callback() {
        let state = setup_state().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/callback".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("test-state-123".to_string()),
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        let cache_value = serde_json::to_vec(&pending).unwrap();
        state
            .cache
            .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
            .await
            .unwrap();

        let form_body = "execution_id=username-password&username=admin&password=admin";
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_flow_{}=1", execution_id.0).parse().unwrap(),
        );

        let response = login_handler(
            State(state.clone()),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers,
            axum::body::Bytes::from(form_body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("http://localhost:8080/callback"));
        assert!(location.contains("state=test-state-123"));
        assert!(location.contains("code="));
    }

    // Authenticator that returns Success with a hardcoded user_id without touching storage.
    struct HardcodedUserAuthenticator {
        user_id: issuerd_core::UserId,
    }

    #[async_trait::async_trait]
    impl issuerd_core::Authenticator for HardcodedUserAuthenticator {
        fn id(&self) -> &str {
            "auth-username-password"
        }
        fn display_name(&self) -> &str {
            "Hardcoded"
        }
        fn requires_user(&self) -> bool {
            false
        }
        fn configured_for(&self, _context: &AuthContext) -> bool {
            true
        }
        async fn authenticate(&self, context: &mut AuthContext) -> issuerd_core::AuthStepResult {
            context.user_id = Some(self.user_id.clone());
            issuerd_core::AuthStepResult::Success
        }
    }

    // Authenticator that returns Challenge so the flow executor yields FlowOutcome::Challenge.
    struct ChallengeAuthenticator;

    #[async_trait::async_trait]
    impl issuerd_core::Authenticator for ChallengeAuthenticator {
        fn id(&self) -> &str {
            "auth-cookie"
        }
        fn display_name(&self) -> &str {
            "Challenge"
        }
        fn requires_user(&self) -> bool {
            false
        }
        fn configured_for(&self, _context: &AuthContext) -> bool {
            true
        }
        async fn authenticate(&self, _context: &mut AuthContext) -> issuerd_core::AuthStepResult {
            issuerd_core::AuthStepResult::Challenge(issuerd_core::Challenge::LoginForm {
                action_url: "http://test".to_string(),
            })
        }
    }

    async fn state_with_empty_jwks() -> Arc<ServerState> {
        let mut state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        let crypto = Arc::new(
            issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default()).unwrap(),
        );
        let token_manager = Arc::new(issuerd_token::token_manager::TokenManager::new(
            crypto,
            state.config.issuer_url.clone(),
            std::time::Duration::from_secs(60),
            issuerd_core::JwkSet { keys: vec![] },
        ));
        state.token_manager = token_manager.clone();
        state.token_service = token_manager;
        Arc::new(state)
    }

    pub async fn state_for_mock_token(access_ok: bool, id_ok: bool) -> Arc<ServerState> {
        let mut state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        state.token_manager = mock_token_manager(access_ok, id_ok);
        Arc::new(state)
    }

    pub fn mock_token_manager(access_ok: bool, id_ok: bool) -> Arc<dyn issuerd_token::TokenIssuer> {
        let access_token = issuerd_token::AccessToken {
            token: "mock_access".to_string(),
            claims: issuerd_core::AccessTokenClaims {
                jti: issuerd_core::JwtId::new("jti").unwrap(),
                iss: issuerd_core::Issuer::new("https://iss").unwrap(),
                sub: issuerd_core::UserId::new("u1").unwrap(),
                aud: issuerd_core::Audience::new("aud").unwrap(),
                exp: 9999999999,
                iat: 0,
                nbf: 0,
                scope: issuerd_core::Scope::parse("openid"),
                typ: issuerd_core::JwtType::Bearer,
                azp: None,
                session_state: None,
                realm_access: None,
                resource_access: None,
                sid: Some(issuerd_core::SessionId::new("sess-1").unwrap()),
                claims: None,
                cnf: None,
                authorization_details: None,
            },
        };
        let id_token = issuerd_token::IdToken {
            token: "mock_id".to_string(),
            claims: issuerd_core::IdTokenClaims {
                iss: issuerd_core::Issuer::new("https://iss").unwrap(),
                sub: issuerd_core::UserId::new("u1").unwrap(),
                aud: issuerd_core::Audience::new("aud").unwrap(),
                exp: 9999999999,
                iat: 0,
                auth_time: Some(0),
                nonce: None,
                azp: None,
                amr: None,
                acr: None,
                sid: Some(issuerd_core::SessionId::new("sess-1").unwrap()),
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
            },
        };
        let refresh_token = issuerd_token::RefreshToken {
            token: "mock_refresh".to_string(),
            claims: issuerd_core::RefreshTokenClaims {
                jti: issuerd_core::JwtId::new("jti").unwrap(),
                iss: issuerd_core::Issuer::new("https://iss").unwrap(),
                sub: issuerd_core::UserId::new("u1").unwrap(),
                aud: issuerd_core::Audience::new("aud").unwrap(),
                exp: 9999999999,
                iat: 0,
                typ: issuerd_core::JwtType::Refresh,
                sid: issuerd_core::SessionId::new("sess-1").unwrap(),
                scope: issuerd_core::Scope::parse("openid"),
                cnf: None,
                authorization_details: None,
            },
        };
        Arc::new(MockTokenIssuer {
            access_token_result: Some(if access_ok {
                Ok(access_token)
            } else {
                Err(issuerd_core::IssuerdError::ServerError("no active signing keys".into()))
            }),
            id_token_result: Some(if id_ok {
                Ok(id_token)
            } else {
                Err(issuerd_core::IssuerdError::ServerError("no active signing keys".into()))
            }),
            refresh_token_result: Some(if access_ok {
                Ok(refresh_token)
            } else {
                Err(issuerd_core::IssuerdError::ServerError("mock".into()))
            }),
        })
    }

    #[tokio::test]
    async fn login_user_not_found_after_flow_success() {
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage.expect_get_realm_by_name().returning(|_| {
            Ok(Some(issuerd_core::Realm {
                id: issuerd_core::RealmId::new("master").unwrap(),
                name: issuerd_core::RealmName::new("master").unwrap(),
                display_name: None,
                enabled: true,
                ..Default::default()
            }))
        });
        mock_storage.expect_create_user_session().returning(|_, _| Ok(()));
        mock_storage.expect_get_user().returning(|_, _| Ok(None));
        // No stored flows: the runtime falls back to the code default flow.
        mock_storage.expect_list_flow_configs().returning(|_| Ok(vec![]));

        let mut reg = crate::state::SimplePluginRegistry::new();
        reg.register_authenticator(Arc::new(HardcodedUserAuthenticator {
            user_id: issuerd_core::UserId::new("ghost").unwrap(),
        }));

        let state = Arc::new(ServerState {
            config: ServerConfig::default(),
            storage: Arc::new(mock_storage),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            crypto: Arc::new(
                issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                    .unwrap(),
            ),
            token_service: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            token_manager: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            plugin_registry: Arc::new(reg),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            login_failure_tracker: Arc::new(
                issuerd_auth_flow::login_failures::LoginFailureTracker::new(),
            ),
            email_sender: Arc::new(crate::email::NoOpEmailSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            signing_key_reload: Arc::new(|| {}),
            keyset_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            event_listeners: std::collections::HashMap::new(),
        });

        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        state
            .cache
            .set(
                &cache_key,
                serde_json::to_vec(&pending).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_realm_not_found_after_flow_success() {
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage.expect_get_realm_by_name().returning(|_| {
            Ok(Some(issuerd_core::Realm {
                id: issuerd_core::RealmId::new("master").unwrap(),
                name: issuerd_core::RealmName::new("master").unwrap(),
                display_name: None,
                enabled: true,
                ..Default::default()
            }))
        });
        mock_storage.expect_create_user_session().returning(|_, _| Ok(()));
        mock_storage.expect_get_user().returning(|_, _| {
            Ok(Some(issuerd_core::User {
                id: issuerd_core::UserId::new("u1").unwrap(),
                realm_id: issuerd_core::RealmId::new("master").unwrap(),
                username: issuerd_core::Username::new("admin").unwrap(),
                email: None,
                email_verified: false,
                first_name: None,
                last_name: None,
                enabled: true,
                federation_link: None,
                attributes: std::collections::HashMap::new(),
                required_actions: Vec::new(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }))
        });
        mock_storage.expect_get_client_by_client_id().returning(|_, _| {
            Ok(Some(issuerd_core::Client {
                id: issuerd_core::ClientId::new("admin-cli").unwrap(),
                realm_id: issuerd_core::RealmId::new("master").unwrap(),
                client_id: ClientIdentifier::new("admin-cli").unwrap(),
                name: None,
                description: None,
                enabled: true,
                protocol: ClientProtocol::OpenIdConnect,
                public_client: true,
                bearer_only: false,
                client_authenticator_type: ClientAuthenticatorType::ClientSecret,
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
                attributes: std::collections::HashMap::new(),
            }))
        });
        mock_storage.expect_get_realm().returning(|_| Ok(None));
        // No stored flows: the runtime falls back to the code default flow.
        mock_storage.expect_list_flow_configs().returning(|_| Ok(vec![]));

        let mut reg = crate::state::SimplePluginRegistry::new();
        reg.register_authenticator(Arc::new(HardcodedUserAuthenticator {
            user_id: issuerd_core::UserId::new("u1").unwrap(),
        }));

        let state = Arc::new(ServerState {
            config: ServerConfig::default(),
            storage: Arc::new(mock_storage),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            crypto: Arc::new(
                issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                    .unwrap(),
            ),
            token_service: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            token_manager: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            plugin_registry: Arc::new(reg),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            login_failure_tracker: Arc::new(
                issuerd_auth_flow::login_failures::LoginFailureTracker::new(),
            ),
            email_sender: Arc::new(crate::email::NoOpEmailSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            signing_key_reload: Arc::new(|| {}),
            keyset_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            event_listeners: std::collections::HashMap::new(),
        });

        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        state
            .cache
            .set(
                &cache_key,
                serde_json::to_vec(&pending).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_flow_challenge_response() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let master_realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("master").unwrap(),
            name: issuerd_core::RealmName::new("master").unwrap(),
            display_name: None,
            enabled: true,
            ..Default::default()
        };
        storage.create_realm(&master_realm).await.unwrap();

        let mut reg = crate::state::SimplePluginRegistry::new();
        reg.register_authenticator(Arc::new(ChallengeAuthenticator));

        let state = Arc::new(ServerState {
            config: ServerConfig::default(),
            storage,
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            crypto: Arc::new(
                issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                    .unwrap(),
            ),
            token_service: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            token_manager: Arc::new(issuerd_token::token_manager::TokenManager::new(
                Arc::new(
                    issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default())
                        .unwrap(),
                ),
                "http://localhost:8080".to_string(),
                std::time::Duration::from_secs(60),
                issuerd_core::JwkSet { keys: vec![] },
            )),
            plugin_registry: Arc::new(reg),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            login_failure_tracker: Arc::new(
                issuerd_auth_flow::login_failures::LoginFailureTracker::new(),
            ),
            email_sender: Arc::new(crate::email::NoOpEmailSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            signing_key_reload: Arc::new(|| {}),
            keyset_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            event_listeners: std::collections::HashMap::new(),
        });

        let execution_id = FlowStageId::new("cookie-auth").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        state
            .cache
            .set(
                &cache_key,
                serde_json::to_vec(&pending).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_access_token_issuance_error() {
        let state = state_with_empty_jwks().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        state
            .cache
            .set(
                &cache_key,
                serde_json::to_vec(&pending).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn login_implicit_id_token_issuance_error() {
        let state = state_with_empty_jwks().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "id_token".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        state
            .cache
            .set(
                &cache_key,
                serde_json::to_vec(&pending).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn login_hybrid_id_token_issuance_error() {
        let state = state_with_empty_jwks().await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code id_token".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        state
            .cache
            .set(
                &cache_key,
                serde_json::to_vec(&pending).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn admin_token_user_with_no_roles() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("norole").unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new("norole").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: std::collections::HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();

        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password("secret".as_bytes(), &salt).unwrap().to_string();
        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&realm_id, &user.id, &cred).await.unwrap();

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "norole".to_string(),
                password: "secret".to_string(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn hardcoded_user_authenticator_trait_methods() {
        let auth = HardcodedUserAuthenticator {
            user_id: issuerd_core::UserId::new("u1").unwrap(),
        };
        assert_eq!(auth.id(), "auth-username-password");
        assert_eq!(auth.display_name(), "Hardcoded");
        assert!(!auth.requires_user());
        assert!(auth.configured_for(&issuerd_core::AuthContext {
            realm_id: issuerd_core::RealmId::new("test").unwrap(),
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: std::collections::HashMap::new(),
            attributes: std::collections::HashMap::new(),
            current_challenge: None,
        }));
    }

    #[tokio::test]
    async fn challenge_authenticator_trait_methods() {
        let auth = ChallengeAuthenticator;
        assert_eq!(auth.id(), "auth-cookie");
        assert_eq!(auth.display_name(), "Challenge");
        assert!(!auth.requires_user());
        assert!(auth.configured_for(&issuerd_core::AuthContext {
            realm_id: issuerd_core::RealmId::new("test").unwrap(),
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: std::collections::HashMap::new(),
            attributes: std::collections::HashMap::new(),
            current_challenge: None,
        }));
        let mut ctx = issuerd_core::AuthContext {
            realm_id: issuerd_core::RealmId::new("test").unwrap(),
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: std::collections::HashMap::new(),
            attributes: std::collections::HashMap::new(),
            current_challenge: None,
        };
        let result = auth.authenticate(&mut ctx).await;
        assert!(matches!(result, issuerd_core::AuthStepResult::Challenge(_)));
    }

    #[tokio::test]
    async fn admin_token_issuance_error() {
        let state = state_with_empty_jwks().await;

        let response = admin_token_handler(
            State(state),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            Json(AdminTokenRequest {
                realm: "master".to_string(),
                username: "admin".to_string(),
                password: "admin".to_string(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn login_implicit_flow_id_token_issuance_error() {
        let state = state_for_mock_token(true, false).await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "id_token".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        state
            .cache
            .set(
                &cache_key,
                serde_json::to_vec(&pending).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn login_hybrid_flow_id_token_issuance_error() {
        let state = state_for_mock_token(true, false).await;
        let execution_id = FlowStageId::new("username-password").unwrap();
        let pending = crate::routes::oidc::PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code id_token".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: execution_id.clone(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        };
        let cache_key = crate::routes::oidc::pending_auth_cache_key(
            &issuerd_core::RealmId::new("master").unwrap(),
            &execution_id.0,
        );
        state
            .cache
            .set(
                &cache_key,
                serde_json::to_vec(&pending).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = login_handler(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            Query(std::collections::HashMap::new()),
            headers_with_flow_cookie(&execution_id.0),
            axum::body::Bytes::from(
                serde_json::to_vec(&LoginRequest {
                    execution_id,
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                    otp: None,
                    remember_me: None,
                    webauthn_assertion: None,
                    resend: None,
                })
                .unwrap(),
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn mock_token_issuer_exercises_all_methods() {
        let tm = mock_token_manager(true, true);
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("u1").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            username: issuerd_core::Username::new("u1").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: std::collections::HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("c1").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("c1").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: true,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
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
            attributes: std::collections::HashMap::new(),
        };
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("master").unwrap(),
            name: issuerd_core::RealmName::new("master").unwrap(),
            display_name: None,
            enabled: true,
            ..Default::default()
        };
        let session_id = issuerd_core::SessionId::new("s1").unwrap();
        tm.issue_access_token(&user, &client, &realm, &[], &session_id).await.unwrap();
        tm.issue_access_token_with_roles(
            &user,
            &client,
            &realm,
            &[],
            &session_id,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        tm.issue_refresh_token(&user, &client, &realm, &session_id, &[], false, None, None)
            .await
            .unwrap();
        tm.issue_id_token(
            &user,
            &client,
            &realm,
            None,
            chrono::Utc::now(),
            &session_id,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    }

    // -----------------------------------------------------------------------
    // MockTokenIssuer
    // -----------------------------------------------------------------------

    use issuerd_token::TokenIssuer;

    pub struct MockTokenIssuer {
        access_token_result: Option<Result<issuerd_token::AccessToken, issuerd_core::IssuerdError>>,
        id_token_result: Option<Result<issuerd_token::IdToken, issuerd_core::IssuerdError>>,
        refresh_token_result:
            Option<Result<issuerd_token::RefreshToken, issuerd_core::IssuerdError>>,
    }

    #[async_trait::async_trait]
    impl TokenIssuer for MockTokenIssuer {
        async fn issue_access_token(
            &self,
            _user: &issuerd_core::User,
            _client: &issuerd_core::Client,
            _realm: &issuerd_core::Realm,
            _scope: &[String],
            _session_id: &issuerd_core::SessionId,
        ) -> Result<issuerd_token::AccessToken, issuerd_core::IssuerdError> {
            self.access_token_result
                .clone()
                .unwrap_or_else(|| Err(issuerd_core::IssuerdError::ServerError("mock".into())))
        }

        async fn issue_access_token_with_roles(
            &self,
            _user: &issuerd_core::User,
            _client: &issuerd_core::Client,
            _realm: &issuerd_core::Realm,
            _scope: &[String],
            _session_id: &issuerd_core::SessionId,
            _realm_access: Option<issuerd_core::RealmAccess>,
            _claims: Option<serde_json::Value>,
            _claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<issuerd_token::AccessToken, issuerd_core::IssuerdError> {
            self.access_token_result
                .clone()
                .unwrap_or_else(|| Err(issuerd_core::IssuerdError::ServerError("mock".into())))
        }

        async fn issue_refresh_token(
            &self,
            _user: &issuerd_core::User,
            _client: &issuerd_core::Client,
            _realm: &issuerd_core::Realm,
            _session_id: &issuerd_core::SessionId,
            _scope: &[String],
            _offline: bool,
            _dpop_jkt: Option<&str>,
            _authorization_details: Option<&[serde_json::Value]>,
        ) -> Result<issuerd_token::RefreshToken, issuerd_core::IssuerdError> {
            self.refresh_token_result
                .clone()
                .unwrap_or_else(|| Err(issuerd_core::IssuerdError::ServerError("mock".into())))
        }

        async fn issue_id_token(
            &self,
            _user: &issuerd_core::User,
            _client: &issuerd_core::Client,
            _realm: &issuerd_core::Realm,
            _nonce: Option<&str>,
            _auth_time: chrono::DateTime<chrono::Utc>,
            _session_id: &issuerd_core::SessionId,
            _access_token: Option<&issuerd_token::AccessToken>,
            _code: Option<&str>,
            _acr_values: Option<&[String]>,
            _claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<issuerd_token::IdToken, issuerd_core::IssuerdError> {
            self.id_token_result
                .clone()
                .unwrap_or_else(|| Err(issuerd_core::IssuerdError::ServerError("mock".into())))
        }

        async fn issue_logout_token(
            &self,
            _user: &issuerd_core::User,
            _client: &issuerd_core::Client,
            _realm: &issuerd_core::Realm,
            _session_id: &issuerd_core::SessionId,
        ) -> Result<issuerd_core::LogoutToken, issuerd_core::IssuerdError> {
            Err(issuerd_core::IssuerdError::ServerError("mock".into()))
        }

        async fn sign_authorization_response(
            &self,
            _realm: &issuerd_core::Realm,
            _client_id: &str,
            _params: &[(String, String)],
        ) -> Result<String, issuerd_core::IssuerdError> {
            Err(issuerd_core::IssuerdError::ServerError("mock".into()))
        }
    }

    #[tokio::test]
    async fn realm_login_page_redirects_with_realm() {
        let response = realm_login_page_handler(axum::extract::Extension(
            crate::middleware::realm::ResolvedRealm(Some("conformance".to_string())),
        ))
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(location, "/login.html?realm=conformance");
    }

    #[tokio::test]
    async fn realm_login_page_defaults_to_master() {
        let response = realm_login_page_handler(axum::extract::Extension(
            crate::middleware::realm::ResolvedRealm(None),
        ))
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(location, "/login.html?realm=master");
    }
}
