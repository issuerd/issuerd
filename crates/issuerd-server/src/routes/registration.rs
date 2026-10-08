// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Self-registration flow.

//! Self-registration.
//!
//! A flat single-stage flow executed through the standard flow engine: the
//! `RegistrationAuthenticator` validates the whole form
//! (username/email/first/last/password) and creates the user in one POST —
//! the originally planned "profile form → password form → optional
//! verify-email" chain deliberately collapses into this one stage. Email verification rides the
//! existing required-action machinery instead: the account is created with
//! `VERIFY_EMAIL` assigned when the realm enables it, and the verification
//! email is sent immediately after the flow succeeds.
//!
//! State lives in the distributed cache under
//! `pending_registration:{realm}:{flow}` (10-minute TTL), so any cluster node
//! can serve the POST. POSTs require the per-flow correlation cookie minted
//! by the GET (login-CSRF protection, same model as the password login).
//!
//! When the registration was started from a browser login flow (the login
//! page's Register link carries the flow's `execution_id`), a successful POST
//! resumes that paused flow with the just-registered credentials, so the user
//! is signed in and lands on the originating app (via the required-action
//! continuation when the realm verifies emails). Standalone registration
//! creates no session — the user signs in through the normal login flow.
//!
//! Realm attributes gate two form behaviors: `registration_require_names`
//! makes first/last name mandatory, and `registration_passwordless` drops
//! password collection (the account is created without a password
//! credential).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use tracing::{error, info, instrument, warn};

use issuerd_auth_flow::typestate::FlowOutput;
use issuerd_core::typestate::TypedAuthContext;
use issuerd_core::{EventType, FlowStageId, IssuerdError, RealmId};

use crate::email::html_escape;
use crate::middleware::proxy_ip::ClientIp;
use crate::state::{default_browser_flow, registration_flow, ServerState};

use super::oidc::{emit_oidc_event, flow_cookie_header, has_flow_cookie};
use super::required_actions::{
    accept_language, error_banner, error_response, page, send_verification_email, url_path_segment,
    PageCopy,
};

/// Cache TTL for an in-flight registration flow (matches the pending auth TTL).
const PENDING_REGISTRATION_TTL_SECS: u64 = 600;

/// Cache key for an in-flight registration flow.
fn pending_registration_cache_key(realm_id: &RealmId, flow_id: &str) -> String {
    format!("pending_registration:{}:{}", realm_id.0, flow_id)
}

/// State of an in-flight self-registration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingRegistration {
    pub realm_id: String,
    /// Resume position inside the registration flow (the flow stage id).
    pub execution_id: FlowStageId,
    pub ip_address: Option<std::net::IpAddr>,
    /// Paused browser-login execution this registration was started from (the
    /// login page's Register link threads it here). A successful POST resumes
    /// it so the user lands on the originating app, not the account console.
    #[serde(default)]
    pub login_execution_id: Option<String>,
    /// UI locale pinned by the GET (Accept-Language + realm default); the POST
    /// re-renders reuse it so the flow does not change language mid-way.
    #[serde(default)]
    pub locale: Option<String>,
}

/// Form fields forwarded to the authenticator as flow parameters.
const FORM_FIELDS: [&str; 6] = [
    "username",
    "email",
    "first_name",
    "last_name",
    "password",
    "confirm_password",
];

// ---------------------------------------------------------------------------
// HTML pages (shared required-actions chrome; every dynamic value is escaped)
// ---------------------------------------------------------------------------

/// Render the registration form, optionally with an error banner and the
/// previously entered non-secret values prefilled.
///
/// Realm-attribute gates: `require_names` marks the name inputs `required`
/// (with a visible `*` marker in the label); `passwordless` omits the
/// password/confirm inputs entirely.
fn render_register_page(
    copy: &PageCopy,
    realm_name: &str,
    flow_id: &str,
    error: Option<&str>,
    prefill: &HashMap<String, String>,
    require_names: bool,
    passwordless: bool,
) -> Response {
    let url = format!("/realms/{}/login/register", url_path_segment(realm_name));
    let banner = error_banner(error);
    let field = |key: &str| html_escape(prefill.get(key).map(String::as_str).unwrap_or(""));
    let name_marker = if require_names { " *" } else { "" };
    let name_required = if require_names { " required" } else { "" };
    let password_fields = if passwordless {
        String::new()
    } else {
        format!(
            "<label for=\"password\">{}</label>\
             <input type=\"password\" id=\"password\" name=\"password\" \
             autocomplete=\"new-password\" required>\
             <label for=\"confirm_password\">{}</label>\
             <input type=\"password\" id=\"confirm_password\" name=\"confirm_password\" \
             autocomplete=\"new-password\" required>",
            copy.msg("register.passwordLabel", "Password"),
            copy.msg("register.confirmPasswordLabel", "Confirm password"),
        )
    };
    let heading = copy.msg("register.heading", "Create your account");
    let username_label = copy.msg("register.usernameLabel", "Username");
    let email_label = copy.msg("register.emailLabel", "Email");
    let first_label = copy.msg("register.firstNameLabel", "First name");
    let last_label = copy.msg("register.lastNameLabel", "Last name");
    let submit = copy.msg("register.submit", "Register");
    let body = format!(
        "<h1>{heading}</h1>\
         {banner}\
         <form method=\"post\" action=\"{url}\">\
         <input type=\"hidden\" name=\"flow\" value=\"{}\">\
         <label for=\"username\">{username_label}</label>\
         <input type=\"text\" id=\"username\" name=\"username\" value=\"{}\" \
         autocomplete=\"username\" required>\
         <label for=\"email\">{email_label}</label>\
         <input type=\"email\" id=\"email\" name=\"email\" value=\"{}\" \
         autocomplete=\"email\" required>\
         <label for=\"first_name\">{first_label}{name_marker}</label>\
         <input type=\"text\" id=\"first_name\" name=\"first_name\" value=\"{}\" \
         autocomplete=\"given-name\"{name_required}>\
         <label for=\"last_name\">{last_label}{name_marker}</label>\
         <input type=\"text\" id=\"last_name\" name=\"last_name\" value=\"{}\" \
         autocomplete=\"family-name\"{name_required}>\
         {password_fields}\
         <button type=\"submit\">{submit}</button>\
         </form>",
        html_escape(flow_id),
        field("username"),
        field("email"),
        field("first_name"),
        field("last_name"),
    );
    page(&copy.msg("register.title", "Register"), &body, &copy.lang).into_response()
}

/// Absolute-path link to the login page for the realm. `execution_id` points
/// the page at the paused browser-login flow the registration started from,
/// so a manual sign-in still lands on the originating app.
fn login_page_url(realm_name: &str, execution_id: Option<&str>) -> String {
    let mut login = url::form_urlencoded::Serializer::new(String::new());
    login.append_pair("realm", realm_name);
    if let Some(execution_id) = execution_id {
        login.append_pair("execution_id", execution_id);
    }
    format!("/login.html?{}", login.finish())
}

/// Confirmation page after a successful registration.
fn registration_success_page(
    copy: &PageCopy,
    realm_name: &str,
    verify_email: bool,
    execution_id: Option<&str>,
) -> Response {
    let login_url = login_page_url(realm_name, execution_id);
    let hint = if verify_email {
        copy.msg(
            "register.successHintVerify",
            "We sent you an email with a verification link &mdash; open it to \
             verify your address, then sign in.",
        )
    } else {
        copy.msg("register.successHint", "You can now sign in.")
    };
    let title = copy.msg("register.successTitle", "Registration successful");
    page(
        &title,
        &format!(
            "<h1>{title}</h1>\
             <p>{} {hint}</p>\
             <p><a href=\"{login_url}\">{}</a></p>",
            copy.msg("register.successLead", "Your account has been created."),
            copy.msg("register.continueToLogin", "Continue to sign-in"),
        ),
        &copy.lang,
    )
    .into_response()
}

/// Re-store the consumed pending entry (fresh TTL) and re-render the form.
#[allow(clippy::too_many_arguments)]
async fn restore_and_render(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    flow_id: &str,
    pending: &PendingRegistration,
    copy: &PageCopy,
    realm_name: &str,
    error: Option<&str>,
    form: &HashMap<String, String>,
    require_names: bool,
    passwordless: bool,
) -> Response {
    // Serialization cannot fail: every field is a plain String/Option.
    let bytes = serde_json::to_vec(pending).unwrap();
    let _ = state
        .cache
        .set(
            &pending_registration_cache_key(realm_id, flow_id),
            bytes,
            Some(Duration::from_secs(PENDING_REGISTRATION_TTL_SECS)),
        )
        .await;
    render_register_page(copy, realm_name, flow_id, error, form, require_names, passwordless)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Query parameters for [`register_page`].
#[derive(Debug, serde::Deserialize)]
pub struct RegisterPageQuery {
    /// Paused browser-login execution the registration was started from.
    execution_id: Option<String>,
}

/// GET `/realms/{realm}/login/register` — start a registration flow and
/// render the form. 404 unless the realm exists and enables registration.
pub async fn register_page(
    State(state): State<Arc<ServerState>>,
    Path(realm_name): Path<String>,
    axum::extract::Query(query): axum::extract::Query<RegisterPageQuery>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: HeaderMap,
) -> Response {
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => {
            let copy = PageCopy::fallback(&state);
            return error_response(
                &copy,
                StatusCode::NOT_FOUND,
                &copy.msg("error.realmNotFound", "Realm not found."),
            );
        }
    };
    let copy = PageCopy::for_realm(&state, &realm, None, accept_language(&headers));
    if !realm.registration_enabled {
        return error_response(
            &copy,
            StatusCode::NOT_FOUND,
            &copy.msg("register.notEnabled", "Registration is not enabled for this realm."),
        );
    }
    let realm_id = realm.id.clone();

    // Keep the originating login execution only while it is still live. It is
    // single-use, so peek without consuming; an expired one degrades the
    // registration to standalone.
    let login_execution_id = match query.execution_id {
        Some(exec) => {
            let key = super::oidc::pending_auth_cache_key(&realm_id, &exec);
            match state.cache.get(&key).await {
                Ok(Some(_)) => Some(exec),
                _ => None,
            }
        }
        None => None,
    };

    // With no form parameters the authenticator challenges; the challenge's
    // stage id is the resume position stored for the POST. The
    // realm's registration-flow binding selects the flow from storage (code
    // default as fallback).
    let mut ctx = TypedAuthContext::new_anonymous(realm_id.clone());
    ctx.ip_address = Some(ip);
    let (flow, executor) = state
        .bound_flow_executor(
            &realm,
            realm.registration_flow.as_deref(),
            "registration",
            registration_flow,
        )
        .await;
    let outcome = match executor.execute(&flow, ctx).await {
        Ok(o) => o,
        Err(e) => {
            error!(realm = %realm_id, error = %e, "registration flow execution failed");
            return error_response(
                &copy,
                StatusCode::INTERNAL_SERVER_ERROR,
                &copy.msg(
                    "register.internalError",
                    "Registration failed due to an internal error. Please try again later.",
                ),
            );
        }
    };
    let FlowOutput::Challenge { paused } = outcome else {
        return error_response(
            &copy,
            StatusCode::INTERNAL_SERVER_ERROR,
            &copy.msg("register.misconfigured", "Registration flow is misconfigured."),
        );
    };

    let flow_id = issuerd_core::utils::generate_id();
    let entry = PendingRegistration {
        realm_id: realm_id.0.clone(),
        execution_id: paused.execution_id().clone(),
        ip_address: Some(ip),
        login_execution_id,
        locale: Some(copy.lang.clone()),
    };
    // Serialization cannot fail: every field is a plain String/Option.
    let bytes = serde_json::to_vec(&entry).unwrap();
    let _ = state
        .cache
        .set(
            &pending_registration_cache_key(&realm_id, &flow_id),
            bytes,
            Some(Duration::from_secs(PENDING_REGISTRATION_TTL_SECS)),
        )
        .await;

    let mut resp = render_register_page(
        &copy,
        &realm_name,
        &flow_id,
        None,
        &HashMap::new(),
        realm.registration_require_names(),
        realm.registration_passwordless(),
    );
    if let Ok(v) =
        HeaderValue::from_str(&flow_cookie_header(&flow_id, state.config.secure_cookies()))
    {
        resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
    }
    resp
}

/// POST `/realms/{realm}/login/register` — validate the submitted form
/// through the registration flow and create the account.
#[instrument(skip(state, ip, headers, body), fields(realm = %realm_name))]
pub async fn register_submit(
    State(state): State<Arc<ServerState>>,
    Path(realm_name): Path<String>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form: HashMap<String, String> = serde_urlencoded::from_bytes(&body).unwrap_or_default();
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => {
            let copy = PageCopy::fallback(&state);
            return error_response(
                &copy,
                StatusCode::NOT_FOUND,
                &copy.msg("error.realmNotFound", "Realm not found."),
            );
        }
    };
    if !realm.registration_enabled {
        let copy = PageCopy::for_realm(&state, &realm, None, accept_language(&headers));
        return error_response(
            &copy,
            StatusCode::NOT_FOUND,
            &copy.msg("register.notEnabled", "Registration is not enabled for this realm."),
        );
    }
    let realm_id = realm.id.clone();
    let require_names = realm.registration_require_names();
    let passwordless = realm.registration_passwordless();

    // The POST must carry the correlation cookie minted by the GET (CSRF).
    let flow_id = form.get("flow").cloned().unwrap_or_default();
    if flow_id.is_empty() || !has_flow_cookie(&headers, &flow_id) {
        let copy = PageCopy::for_realm(&state, &realm, None, accept_language(&headers));
        return error_response(
            &copy,
            StatusCode::BAD_REQUEST,
            &copy.msg("register.flowInvalid", "Invalid or expired registration flow."),
        );
    }

    // Consume the entry atomically; failure paths below re-store it so the
    // user can correct and resubmit the form.
    let key = pending_registration_cache_key(&realm_id, &flow_id);
    let pending: Option<PendingRegistration> = match state.cache.get_and_delete(&key).await {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
        _ => None,
    };
    // Realm binding is defense-in-depth on top of the realm-scoped cache key.
    let pending = match pending {
        Some(p) if p.realm_id == realm_id.0 => p,
        _ => {
            let copy = PageCopy::for_realm(&state, &realm, None, accept_language(&headers));
            return error_response(
                &copy,
                StatusCode::BAD_REQUEST,
                &copy.msg(
                    "register.sessionExpired",
                    "Your registration session has expired. Please start again.",
                ),
            );
        }
    };
    // The GET pinned the locale; the POST re-renders in the same language.
    let copy =
        PageCopy::for_realm(&state, &realm, pending.locale.as_deref(), accept_language(&headers));

    let mut ctx = TypedAuthContext::new_anonymous(realm_id.clone());
    ctx.ip_address = pending.ip_address.or(Some(ip));
    for field in FORM_FIELDS {
        if let Some(value) = form.get(field) {
            ctx.parameters.insert(field.to_string(), vec![value.clone()]);
        }
    }

    let (flow, executor) = state
        .bound_flow_executor(
            &realm,
            realm.registration_flow.as_deref(),
            "registration",
            registration_flow,
        )
        .await;
    let outcome = match executor.continue_flow(&flow, &pending.execution_id, ctx).await {
        Ok(o) => o,
        Err(e) => {
            error!(realm = %realm_id, error = %e, "registration flow execution failed");
            return error_response(
                &copy,
                StatusCode::INTERNAL_SERVER_ERROR,
                &copy.msg(
                    "register.internalError",
                    "Registration failed due to an internal error. Please try again later.",
                ),
            );
        }
    };

    match outcome {
        FlowOutput::Success { ctx, .. } => {
            let user_id = ctx.user_id.clone();
            info!(realm = %realm_id, user_id = %user_id, "user registered");
            let mut details = HashMap::new();
            if let Some(username) = form.get("username") {
                details.insert("username".to_string(), username.clone());
            }
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::Custom("register".to_string()),
                &pending.ip_address.unwrap_or(ip),
                None,
                Some(user_id.clone()),
                None,
                None,
                details,
            )
            .await;

            // The authenticator just created the account; a missing row would
            // be a storage bug, not user error.
            let user = match state.storage.get_user(&realm_id, &user_id).await {
                Ok(Some(u)) => u,
                _ => {
                    return error_response(
                        &copy,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &copy.msg(
                            "register.accountNotLoaded",
                            "Your account was created but could not be loaded.",
                        ),
                    );
                }
            };

            // Realm default groups apply to interactive user
            // creation (registration, broker first login) — not to
            // admin-created users.
            crate::groups::assign_default_groups(&state, &realm, &user.id).await;

            // Registration started from a browser login flow: resume it with
            // the fresh credentials so the user lands on the originating app.
            // `None` means the resume was not possible (expired execution,
            // passwordless realm, flow challenge) — fall through to the
            // success page, whose link keeps the sign-in inside the app flow.
            if let Some(exec) = pending.login_execution_id.as_deref() {
                if let Some(resp) = try_resume_login_flow(
                    &state,
                    &realm,
                    &realm_name,
                    &realm_id,
                    exec,
                    &form,
                    &headers,
                )
                .await
                {
                    return resp;
                }
            }

            if realm.verify_email_enabled {
                // A delivery failure must not fail the registration: the user
                // can have the mail resent at first login. When the
                // registration started from an app's login flow, the link
                // threads that execution so the verified user returns to the
                // app, not the account console.
                if let Err(e) = send_verification_email(
                    &state,
                    &realm,
                    &realm_name,
                    &user,
                    None,
                    pending.login_execution_id.as_deref(),
                )
                .await
                {
                    error!(realm = %realm_id, error = %e, "failed to send verification email");
                }
            }
            registration_success_page(
                &copy,
                &realm_name,
                realm.verify_email_enabled,
                pending.login_execution_id.as_deref(),
            )
        }
        FlowOutput::Failure(e) => {
            // `register()` renders user-facing validation failures as
            // `InvalidRequest` with form-safe messages; anything else
            // (storage/server errors) is internal text and must not reach
            // the page.
            let form_error = match &e {
                IssuerdError::InvalidRequest(msg) => {
                    warn!(realm = %realm_id, error = %e, "registration failed");
                    crate::i18n::localize_error(&copy.bundle, msg)
                }
                _ => {
                    error!(realm = %realm_id, error = %e, "registration failed with internal error");
                    copy.msg(
                        "register.internalError",
                        "Registration failed due to an internal error. Please try again later.",
                    )
                }
            };
            let mut details = HashMap::new();
            if let Some(username) = form.get("username") {
                details.insert("username".to_string(), username.clone());
            }
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::Custom("register_error".to_string()),
                &pending.ip_address.unwrap_or(ip),
                None,
                None,
                None,
                Some(e.to_string()),
                details,
            )
            .await;
            restore_and_render(
                &state,
                &realm_id,
                &flow_id,
                &pending,
                &copy,
                &realm_name,
                Some(&form_error),
                &form,
                require_names,
                passwordless,
            )
            .await
        }
        // Not expected from the flat registration form (all input arrives in
        // one POST), but re-rendering the form is the only sane answer.
        FlowOutput::Challenge { .. } => {
            restore_and_render(
                &state,
                &realm_id,
                &flow_id,
                &pending,
                &copy,
                &realm_name,
                None,
                &form,
                require_names,
                passwordless,
            )
            .await
        }
    }
}

/// Resume the paused browser-login flow a registration was started from,
/// authenticating with the credentials the user just registered with.
/// Returns the login response (the app redirect, or the required-action
/// continuation when actions such as VERIFY_EMAIL are pending). `None` means
/// the resume was not possible; the paused entry is then re-stored so the
/// normal login page can still complete it, and the caller renders the
/// standalone success page instead.
async fn try_resume_login_flow(
    state: &Arc<ServerState>,
    realm: &issuerd_core::Realm,
    realm_name: &str,
    realm_id: &RealmId,
    execution_id: &str,
    form: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Option<Response> {
    // Same login-CSRF posture as the password login handler: the browser must
    // present the correlation cookie the authorize endpoint minted.
    if !has_flow_cookie(headers, execution_id) {
        return None;
    }
    // Passwordless registrations collect no password; there is nothing to
    // authenticate with yet (the email-code flow starts from the login page).
    let password = form.get("password")?.clone();
    let username = form.get("username")?.clone();

    // Consume the paused login atomically (single-use); every decline path
    // below re-stores it so the user can still sign in manually.
    let cache_key = super::oidc::pending_auth_cache_key(realm_id, execution_id);
    let pending: Option<super::oidc::PendingAuthData> =
        match state.cache.get_and_delete(&cache_key).await {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            _ => None,
        };
    let mut pending = match pending {
        Some(p) if p.realm_id == realm_id.as_ref() => p,
        Some(p) => {
            // Realm mismatch is defense-in-depth (the key is realm-scoped);
            // restore the entry and decline.
            let bytes = serde_json::to_vec(&p).unwrap();
            let _ = state.cache.set(&cache_key, bytes, Some(Duration::from_secs(600))).await;
            return None;
        }
        None => return None,
    };

    let Some(pending_client_id) = issuerd_core::ClientId::new(&pending.client_id).ok() else {
        let bytes = serde_json::to_vec(&pending).unwrap();
        let _ = state.cache.set(&cache_key, bytes, Some(Duration::from_secs(600))).await;
        return None;
    };
    let mut ctx = TypedAuthContext::new_anonymous(realm_id.clone());
    ctx.client_id = Some(pending_client_id);
    ctx.ip_address = pending.ip_address;
    if realm.verify_email_enabled {
        ctx.attributes
            .insert("realm_verify_email_enabled".to_string(), "true".to_string());
    }
    ctx.parameters.insert("username".to_string(), vec![username]);
    ctx.parameters.insert("password".to_string(), vec![password]);
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

    let (flow, executor) = state
        .bound_flow_executor(realm, realm.browser_flow.as_deref(), "browser", default_browser_flow)
        .await;
    let outcome = match executor.continue_flow(&flow, &pending.execution_id, ctx).await {
        Ok(o) => o,
        Err(_) => {
            let bytes = serde_json::to_vec(&pending).unwrap();
            let _ = state.cache.set(&cache_key, bytes, Some(Duration::from_secs(600))).await;
            return None;
        }
    };

    match outcome {
        FlowOutput::Success { ctx, result } => {
            if !result.required_actions.is_empty() {
                // VERIFY_EMAIL & co: the continuation mails the verification
                // link itself; resuming it completes the login into the app.
                return Some(
                    super::required_actions::begin_actions_continuation(
                        state, realm_name, pending, *result, true,
                    )
                    .await,
                );
            }
            let user_id = ctx.user_id.clone();
            let session_id = result.session_id.clone();
            let result_auth_time = result.auth_time;
            let _cleared = result.into_cleared();
            Some(
                super::login_api::complete_login(
                    state,
                    realm_id,
                    &pending,
                    &user_id,
                    &session_id,
                    result_auth_time,
                    true,
                )
                .await,
            )
        }
        FlowOutput::Challenge { paused } => {
            // A second-factor stage answered with parameters it does not
            // understand: advance the resume position like the login handler
            // does and let the user answer from the normal login page.
            pending.execution_id = paused.execution_id().clone();
            pending.user_id = paused.user_id().map(|u| u.0.clone());
            let bytes = serde_json::to_vec(&pending).unwrap();
            let _ = state.cache.set(&cache_key, bytes, Some(Duration::from_secs(600))).await;
            None
        }
        FlowOutput::Failure(_) => {
            let bytes = serde_json::to_vec(&pending).unwrap();
            let _ = state.cache.set(&cache_key, bytes, Some(Duration::from_secs(600))).await;
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::routes::oidc::{pending_auth_cache_key, PendingAuthData};
    use issuerd_core::{CredentialType, DistributedCache, Realm, Storage};

    type TestStorage = Arc<issuerd_storage::InMemoryStorage>;
    type TestCache = Arc<issuerd_cluster::InMemoryCache>;

    async fn test_state() -> (Arc<ServerState>, TestStorage, TestCache) {
        let cfg = ServerConfig::default();
        let storage: TestStorage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let cache: TestCache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let state = ServerState::from_components(&cfg, storage.clone(), cache.clone())
            .await
            .unwrap();
        (Arc::new(state), storage, cache)
    }

    fn master_realm_id() -> RealmId {
        RealmId::new("master").unwrap()
    }

    /// Flip `registration_enabled` on the master realm and make sure the
    /// by-name resolution cache cannot serve a stale pre-update row.
    async fn enable_registration(state: &Arc<ServerState>) -> Realm {
        let mut realm = state
            .storage
            .get_realm(&master_realm_id())
            .await
            .unwrap()
            .expect("master realm bootstrapped");
        realm.registration_enabled = true;
        state.storage.update_realm(&realm).await.unwrap();
        let _ = state.cache.delete(&issuerd_cluster::cache_keys::realm_by_name("master")).await;
        realm
    }

    fn client_ip() -> axum::extract::Extension<ClientIp> {
        axum::extract::Extension(ClientIp(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
    }

    /// A paused browser-login entry as the authorize endpoint stores it.
    fn pending_login(realm_id: &RealmId, execution_id: &str) -> PendingAuthData {
        PendingAuthData {
            realm_id: realm_id.0.clone(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: Some("xyz".to_string()),
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: None,
            execution_id: FlowStageId::new(execution_id).unwrap(),
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
        }
    }

    async fn seed_pending_login(cache: &TestCache, realm_id: &RealmId, execution_id: &str) {
        cache
            .set(
                &pending_auth_cache_key(realm_id, execution_id),
                serde_json::to_vec(&pending_login(realm_id, "username-password")).unwrap(),
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();
    }

    /// GET the registration page; returns the minted flow id and the response.
    async fn start_registration(
        state: &Arc<ServerState>,
        login_execution_id: Option<&str>,
    ) -> (String, Response) {
        let resp = register_page(
            State(state.clone()),
            Path("master".to_string()),
            axum::extract::Query(RegisterPageQuery {
                execution_id: login_execution_id.map(str::to_string),
            }),
            client_ip(),
            HeaderMap::new(),
        )
        .await;
        let set_cookie = resp
            .headers()
            .get("set-cookie")
            .expect("flow cookie")
            .to_str()
            .unwrap()
            .to_string();
        let flow_id = set_cookie
            .strip_prefix("issuerd_flow_")
            .and_then(|rest| rest.split('=').next())
            .expect("issuerd_flow_<id>=1 cookie")
            .to_string();
        (flow_id, resp)
    }

    async fn submit_registration(
        state: &Arc<ServerState>,
        flow_id: &str,
        cookies: &[String],
        fields: &[(&str, &str)],
    ) -> Response {
        let mut form: Vec<(String, String)> =
            fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        form.push(("flow".to_string(), flow_id.to_string()));
        let body = serde_urlencoded::to_string(form).unwrap();
        let mut headers = HeaderMap::new();
        if !cookies.is_empty() {
            headers.insert(axum::http::header::COOKIE, cookies.join("; ").parse().unwrap());
        }
        register_submit(
            State(state.clone()),
            Path("master".to_string()),
            client_ip(),
            headers,
            Bytes::from(body),
        )
        .await
    }

    fn flow_cookie(flow_id: &str) -> String {
        format!("issuerd_flow_{flow_id}=1")
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn pending_entry(
        cache: &TestCache,
        realm_id: &RealmId,
        flow_id: &str,
    ) -> Option<PendingRegistration> {
        cache
            .get(&pending_registration_cache_key(realm_id, flow_id))
            .await
            .unwrap()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }

    fn valid_form() -> Vec<(&'static str, &'static str)> {
        vec![
            ("username", "newbie"),
            ("email", "newbie@example.com"),
            ("first_name", "New"),
            ("last_name", "User"),
            ("password", "password-123"),
            ("confirm_password", "password-123"),
        ]
    }

    #[test]
    fn cache_key_is_realm_scoped() {
        let realm = RealmId::new("master").unwrap();
        assert_eq!(
            pending_registration_cache_key(&realm, "flow-1"),
            "pending_registration:master:flow-1"
        );
    }

    #[tokio::test]
    async fn form_renders_escaped_prefill_and_flow() {
        let mut prefill = HashMap::new();
        prefill.insert("username".to_string(), "<script>alert(1)</script>".to_string());
        prefill.insert("email".to_string(), "a@b.example".to_string());
        let resp = render_register_page(
            &PageCopy::builtin("en"),
            "master",
            "flow-\"x\"",
            Some("bad & worse"),
            &prefill,
            false,
            false,
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("value=\"&lt;script&gt;alert(1)&lt;/script&gt;\""));
        assert!(body.contains("value=\"flow-&quot;x&quot;\""));
        assert!(body.contains("bad &amp; worse"));
        assert!(!body.contains("<script>alert"));
        assert!(body.contains("action=\"/realms/master/login/register\""));
    }

    #[tokio::test]
    async fn form_localizes_labels_and_lang() {
        let mut bundle = crate::i18n::message_bundle(None, None, "en");
        bundle.insert("register.heading".to_string(), "Konto erstellen".to_string());
        bundle.insert("register.usernameLabel".to_string(), "Benutzername".to_string());
        let copy = PageCopy {
            lang: "de".to_string(),
            bundle,
        };
        let resp =
            render_register_page(&copy, "master", "flow-1", None, &HashMap::new(), false, false);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("<html lang=\"de\">"), "body: {body}");
        assert!(body.contains("<h1>Konto erstellen</h1>"), "body: {body}");
        assert!(body.contains("<label for=\"username\">Benutzername</label>"), "body: {body}");
        // Untouched keys keep the English default.
        assert!(body.contains("<label for=\"email\">Email</label>"), "body: {body}");
    }

    #[tokio::test]
    async fn form_marks_names_required_when_realm_requires_them() {
        let resp = render_register_page(
            &PageCopy::builtin("en"),
            "master",
            "flow-1",
            None,
            &HashMap::new(),
            true,
            false,
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        // Visible marker plus the HTML required attribute on both name inputs.
        assert!(body.contains("<label for=\"first_name\">First name *</label>"));
        assert!(body.contains("<label for=\"last_name\">Last name *</label>"));
        assert!(
            body.contains("name=\"first_name\" value=\"\" autocomplete=\"given-name\" required>")
        );
        assert!(
            body.contains("name=\"last_name\" value=\"\" autocomplete=\"family-name\" required>")
        );
        // Password collection is untouched by this flag.
        assert!(body.contains("name=\"password\""));
        assert!(body.contains("name=\"confirm_password\""));
    }

    #[tokio::test]
    async fn form_omits_password_fields_when_passwordless() {
        let resp = render_register_page(
            &PageCopy::builtin("en"),
            "master",
            "flow-1",
            None,
            &HashMap::new(),
            false,
            true,
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!body.contains("name=\"password\""));
        assert!(!body.contains("name=\"confirm_password\""));
        // Name inputs stay optional under this flag alone.
        assert!(body.contains("<label for=\"first_name\">First name</label>"));
        assert!(body.contains("name=\"first_name\" value=\"\" autocomplete=\"given-name\">"));
    }

    #[tokio::test]
    async fn success_pages_link_to_login() {
        let resp = registration_success_page(&PageCopy::builtin("en"), "my realm", true, None);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("verification link"));
        assert!(body.contains("/login.html?realm=my+realm"));

        let resp = registration_success_page(&PageCopy::builtin("en"), "my realm", false, None);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!body.contains("verification link"));
        assert!(body.contains("/login.html?realm=my+realm"));
    }

    #[tokio::test]
    async fn success_page_threads_login_execution_into_link() {
        let resp =
            registration_success_page(&PageCopy::builtin("en"), "my realm", false, Some("exec 1"));
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("/login.html?realm=my+realm&execution_id=exec+1"));
    }

    #[test]
    fn pending_registration_deserializes_without_login_execution() {
        // Cache entries written before the field existed must still load.
        let legacy = serde_json::json!({
            "realm_id": "r1",
            "execution_id": "stage-1",
            "ip_address": null,
        });
        let entry: PendingRegistration = serde_json::from_value(legacy).unwrap();
        assert_eq!(entry.login_execution_id, None);
    }

    // -- register_page -----------------------------------------------------------

    #[tokio::test]
    async fn page_renders_form_and_mints_flow_cookie() {
        let (state, _storage, cache) = test_state().await;

        // Disabled by default: a 404 page, not the form.
        let resp = register_page(
            State(state.clone()),
            Path("master".to_string()),
            axum::extract::Query(RegisterPageQuery { execution_id: None }),
            client_ip(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(body_string(resp).await.contains("Registration is not enabled"));

        enable_registration(&state).await;
        let (flow_id, resp) = start_registration(&state, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Create your account"));
        assert!(body.contains(&format!("name=\"flow\" value=\"{flow_id}\"")));
        assert!(body.contains("action=\"/realms/master/login/register\""));

        // The pending entry exists under the exact schema key.
        let realm_id = master_realm_id();
        let entry = pending_entry(&cache, &realm_id, &flow_id)
            .await
            .expect("pending registration cached");
        assert_eq!(entry.realm_id, realm_id.0);
        assert_eq!(entry.login_execution_id, None);
    }

    #[tokio::test]
    async fn page_keeps_only_live_login_execution_link() {
        let (state, _storage, cache) = test_state().await;
        enable_registration(&state).await;
        let realm_id = master_realm_id();
        seed_pending_login(&cache, &realm_id, "login-exec-1").await;

        // A live pending login flow is threaded into the registration.
        let (flow_id, resp) = start_registration(&state, Some("login-exec-1")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let entry = pending_entry(&cache, &realm_id, &flow_id).await.unwrap();
        assert_eq!(entry.login_execution_id.as_deref(), Some("login-exec-1"));

        // An expired/unknown execution degrades the registration to standalone.
        let (flow_id, resp) = start_registration(&state, Some("gone-exec")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let entry = pending_entry(&cache, &realm_id, &flow_id).await.unwrap();
        assert_eq!(entry.login_execution_id, None);
    }

    // -- register_submit -----------------------------------------------------------

    #[tokio::test]
    async fn submit_creates_account_and_success_page() {
        let (state, storage, cache) = test_state().await;
        enable_registration(&state).await;
        let realm_id = master_realm_id();
        let (flow_id, resp) = start_registration(&state, None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp =
            submit_registration(&state, &flow_id, &[flow_cookie(&flow_id)], &valid_form()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Registration successful"));
        assert!(body.contains("Continue to sign-in"));

        // The account exists with a working password credential.
        let user = storage
            .get_user_by_username(&realm_id, "newbie")
            .await
            .unwrap()
            .expect("registered user persisted");
        assert_eq!(user.email.as_ref().map(|e| e.as_str()), Some("newbie@example.com"));
        assert!(user.enabled);
        let creds = storage
            .get_credentials(&realm_id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert!(
            creds
                .iter()
                .any(|c| issuerd_auth_flow::built_in::verify_password_hash("password-123", c)),
            "password credential stored"
        );
        // The pending entry is single-use.
        assert!(pending_entry(&cache, &realm_id, &flow_id).await.is_none());
    }

    #[tokio::test]
    async fn submit_without_flow_cookie_rejected() {
        let (state, storage, cache) = test_state().await;
        enable_registration(&state).await;
        let realm_id = master_realm_id();
        let (flow_id, resp) = start_registration(&state, None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // The correlation cookie is missing: reject before touching the entry.
        let resp = submit_registration(&state, &flow_id, &[], &valid_form()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("Invalid or expired registration flow."));
        assert!(pending_entry(&cache, &realm_id, &flow_id).await.is_some());
        assert!(storage.get_user_by_username(&realm_id, "newbie").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn submit_rejects_entry_from_another_realm() {
        let (state, storage, cache) = test_state().await;
        enable_registration(&state).await;
        let realm_id = master_realm_id();
        let (flow_id, resp) = start_registration(&state, None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Overwrite the entry with one bound to a different realm (the cache
        // key is realm-scoped, so this is defense-in-depth).
        let foreign = PendingRegistration {
            realm_id: "other-realm".to_string(),
            execution_id: FlowStageId::new("registration").unwrap(),
            ip_address: None,
            login_execution_id: None,
            locale: None,
        };
        cache
            .set(
                &pending_registration_cache_key(&realm_id, &flow_id),
                serde_json::to_vec(&foreign).unwrap(),
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let resp =
            submit_registration(&state, &flow_id, &[flow_cookie(&flow_id)], &valid_form()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("registration session has expired"));
        assert!(storage.get_user_by_username(&realm_id, "newbie").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn submit_validation_failure_rerenders_form_with_message() {
        let (state, storage, cache) = test_state().await;
        enable_registration(&state).await;
        let realm_id = master_realm_id();
        let (flow_id, resp) = start_registration(&state, None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // "admin" exists in the bootstrapped master realm.
        let mut form = valid_form();
        form[0] = ("username", "admin");
        let resp = submit_registration(&state, &flow_id, &[flow_cookie(&flow_id)], &form).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        // The authenticator's user-facing message — never the generic
        // internal-error text — lands in the banner.
        assert!(body.contains("username already in use"), "body: {body}");
        assert!(!body.contains("internal error"), "body: {body}");
        // The form re-renders with the non-secret values prefilled.
        assert!(body.contains("value=\"admin\""));
        assert!(body.contains("value=\"newbie@example.com\""));
        // …and the entry is re-stored so the user can correct and resubmit.
        assert!(pending_entry(&cache, &realm_id, &flow_id).await.is_some());
        assert!(storage.get_user_by_username(&realm_id, "newbie").await.unwrap().is_none());
    }

    // -- login-flow resume ---------------------------------------------------------

    #[tokio::test]
    async fn submit_resumes_originating_login_flow() {
        let (state, storage, cache) = test_state().await;
        enable_registration(&state).await;
        let realm_id = master_realm_id();
        seed_pending_login(&cache, &realm_id, "login-exec-1").await;

        let (flow_id, resp) = start_registration(&state, Some("login-exec-1")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = submit_registration(
            &state,
            &flow_id,
            &[flow_cookie(&flow_id), flow_cookie("login-exec-1")],
            &valid_form(),
        )
        .await;

        // The paused browser login resumes with the fresh credentials and
        // lands the user on the originating app with an authorization code.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
        assert!(location.starts_with("http://localhost:8080/cb?"), "{location}");
        assert!(location.contains("code="), "{location}");
        assert!(location.contains("state=xyz"), "{location}");

        // The login flow entry was consumed by the resume.
        assert!(cache
            .get(&pending_auth_cache_key(&realm_id, "login-exec-1"))
            .await
            .unwrap()
            .is_none());
        assert!(storage.get_user_by_username(&realm_id, "newbie").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn submit_without_login_cookie_falls_back_to_success_page() {
        let (state, _storage, cache) = test_state().await;
        enable_registration(&state).await;
        let realm_id = master_realm_id();
        seed_pending_login(&cache, &realm_id, "login-exec-2").await;

        let (flow_id, resp) = start_registration(&state, Some("login-exec-2")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Only the registration cookie — the login flow's correlation cookie
        // is missing, so the resume must NOT run.
        let resp =
            submit_registration(&state, &flow_id, &[flow_cookie(&flow_id)], &valid_form()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Registration successful"));
        // The success page keeps the sign-in inside the app flow.
        assert!(body.contains("execution_id=login-exec-2"), "body: {body}");
        // The paused login flow is untouched: the user can still sign in.
        assert!(cache
            .get(&pending_auth_cache_key(&realm_id, "login-exec-2"))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn resume_declines_cross_realm_pending_and_restores_it() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();

        // A registered user whose credentials the resumed flow would accept.
        let now = chrono::Utc::now();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new("flowuser").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        storage.create_user(&realm_id, &user).await.unwrap();
        issuerd_auth_flow::built_in::set_user_password(
            storage.as_ref(),
            &realm_id,
            &user.id,
            "password-123",
            0,
            false,
        )
        .await
        .unwrap();

        // The pending entry claims a different realm (defense-in-depth: the
        // cache key is already realm-scoped).
        let mut foreign = pending_login(&realm_id, "username-password");
        foreign.realm_id = "other-realm".to_string();
        let cache_key = pending_auth_cache_key(&realm_id, "login-exec-x");
        cache
            .set(
                &cache_key,
                serde_json::to_vec(&foreign).unwrap(),
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let form: HashMap<String, String> = HashMap::from([
            ("username".to_string(), "flowuser".to_string()),
            ("password".to_string(), "password-123".to_string()),
        ]);
        let headers = HeaderMap::from_iter([(
            axum::http::header::COOKIE,
            flow_cookie("login-exec-x").parse().unwrap(),
        )]);

        let resp = try_resume_login_flow(
            &state,
            &realm,
            "master",
            &realm_id,
            "login-exec-x",
            &form,
            &headers,
        )
        .await;

        assert!(resp.is_none(), "cross-realm pending entry must not resume");
        // The entry is restored so the user can still sign in manually.
        assert!(cache.get(&cache_key).await.unwrap().is_some());
    }
}
