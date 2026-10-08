// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// User-initiated forgot/reset password flow backed by single-use action tokens.

//! User-initiated forgot/reset password.
//!
//! Unlike registration, this flow carries no flow cookie: the signed action
//! token minted into the email link **is** the credential. The token
//! (purpose `reset-credentials`, 15-minute TTL) proves ownership of the
//! account's email address; the `jti` is tracked in the distributed cache
//! (`reset-credentials:{realm}:{jti}` → user id) and consumed atomically when
//! the new password is written, making every link single-use and safe to serve
//! from any cluster node.
//!
//! The request endpoint always answers 204 — whether the account exists, is
//! enabled, or has an email address — so the flow cannot be used for account
//! enumeration. The pages only ever mutate state via POST.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use tracing::{debug, error, info, instrument};

use crate::email::{
    html_escape, render_reset_credentials_email_localized, RESET_CREDENTIALS_LINK_TTL_SECS,
};
use crate::middleware::proxy_ip::ClientIp;
use crate::state::ServerState;
use issuerd_auth_flow::built_in::{
    set_user_password, write_through_federated_password, FederationWriteThrough,
};
use issuerd_core::{EventType, Realm, RealmId, UserId, ACTION_TOKEN_PURPOSE_RESET_CREDENTIALS};
use issuerd_token::action_tokens::{action_token_claims, issue_action_token, verify_action_token};

use super::oidc::emit_oidc_event;
use super::required_actions::{
    accept_language, error_banner, error_response, js_string_literal, page, url_path_segment,
    PageCopy,
};

/// Cache key for a pending (not yet consumed) reset-credentials token id.
fn reset_credentials_cache_key(realm_id: &RealmId, jti: &str) -> String {
    format!("reset-credentials:{}:{}", realm_id.0, jti)
}

/// Neutral confirmation shown after requesting a reset — identical whether or
/// not the account exists (no enumeration).
const CONFIRMATION: &str = "If an account exists for the details you entered, an email with \
     reset instructions is on its way.";

/// Error shown when the action token fails verification (bad signature,
/// wrong purpose/realm, or expired).
const INVALID_LINK: &str = "This password reset link is invalid or has expired.";

/// Error shown when the token verifies but its `jti` was already consumed.
const USED_LINK: &str = "This password reset link has already been used.";

// ---------------------------------------------------------------------------
// HTML pages (shared required-actions chrome; every dynamic value is escaped)
// ---------------------------------------------------------------------------

/// Inline script that posts the request form via `fetch` and swaps the card
/// to the neutral confirmation — the POST answers 204 with no body, so a
/// native submit would land the browser on a blank page. Without JavaScript
/// the form still posts (blank 204 page; acceptable). Assembled from
/// `RESET_FORM_SCRIPT_PRE` + the localized confirmation heading/body (as
/// JS string literals via [`js_string_literal`]) + `RESET_FORM_SCRIPT_MID` +
/// `RESET_FORM_SCRIPT_POST`.
const RESET_FORM_SCRIPT_PRE: &str = "\
<script>\
(function(){\
var form=document.getElementById(\"issuerd-reset-form\");\
form.addEventListener(\"submit\",function(event){\
event.preventDefault();\
var data=new URLSearchParams(new FormData(form));\
fetch(form.action,{method:\"POST\",\
headers:{\"Content-Type\":\"application/x-www-form-urlencoded\"},body:data})\
.then(function(){\
document.querySelector(\"main.card\").innerHTML=\"<h1>\"+";

const RESET_FORM_SCRIPT_MID: &str = "+\"</h1><p>\"+";

const RESET_FORM_SCRIPT_POST: &str = "+\"</p>\";});});})();</script>";

/// Render the "request a reset link" form (single `username` field).
fn render_reset_request_page(copy: &PageCopy, realm_name: &str) -> Response {
    let url = format!("/realms/{}/login/reset-credentials", url_path_segment(realm_name));
    let heading = copy.msg("reset.requestHeading", "Forgot your password?");
    let lead = copy.msg(
        "reset.requestLead",
        "Enter your username or email address and we will send you a link to reset \
         your password.",
    );
    let username_label = copy.msg("reset.usernameLabel", "Username or email");
    let submit = copy.msg("reset.requestSubmit", "Send reset email");
    let mut body = format!(
        "<h1>{heading}</h1>\
         <p>{lead}</p>\
         <form method=\"post\" action=\"{url}\" id=\"issuerd-reset-form\">\
         <label for=\"username\">{username_label}</label>\
         <input type=\"text\" id=\"username\" name=\"username\" \
         autocomplete=\"username\" required>\
         <button type=\"submit\">{submit}</button>\
         </form>"
    );
    body.push_str(RESET_FORM_SCRIPT_PRE);
    body.push_str(&js_string_literal(&copy.msg("reset.confirmationHeading", "Check your email")));
    body.push_str(RESET_FORM_SCRIPT_MID);
    body.push_str(&js_string_literal(&copy.msg("reset.confirmation", CONFIRMATION)));
    body.push_str(RESET_FORM_SCRIPT_POST);
    page(&copy.msg("reset.requestTitle", "Reset password"), &body, &copy.lang).into_response()
}

/// Render the new-password form the emailed link opens. `token` is round-
/// tripped through a hidden field so the POST can re-verify it.
fn render_update_credentials_page(
    copy: &PageCopy,
    realm_name: &str,
    token: &str,
    error: Option<&str>,
) -> Response {
    let url = format!("/realms/{}/login/update-credentials", url_path_segment(realm_name));
    let banner = error_banner(error);
    let heading = copy.msg("reset.updateHeading", "Choose a new password");
    let new_label = copy.msg("reset.newPasswordLabel", "New password");
    let confirm_label = copy.msg("reset.confirmPasswordLabel", "Confirm password");
    let submit = copy.msg("reset.updateSubmit", "Update password");
    let body = format!(
        "<h1>{heading}</h1>\
         {banner}\
         <form method=\"post\" action=\"{url}\">\
         <input type=\"hidden\" name=\"token\" value=\"{}\">\
         <label for=\"new_password\">{new_label}</label>\
         <input type=\"password\" id=\"new_password\" name=\"new_password\" \
         autocomplete=\"new-password\" required>\
         <label for=\"confirm_password\">{confirm_label}</label>\
         <input type=\"password\" id=\"confirm_password\" name=\"confirm_password\" \
         autocomplete=\"new-password\" required>\
         <button type=\"submit\">{submit}</button>\
         </form>",
        html_escape(token),
    );
    page(&copy.msg("reset.updateTitle", "Update password"), &body, &copy.lang).into_response()
}

/// Error page for dead links (invalid/expired/already used), with a way back
/// to the request form.
fn link_error_page(copy: &PageCopy, realm_name: &str, msg: &str) -> Response {
    let url = format!("/realms/{}/login/reset-credentials", url_path_segment(realm_name));
    let title = copy.msg("reset.requestTitle", "Reset password");
    (
        StatusCode::BAD_REQUEST,
        page(
            &title,
            &format!(
                "<h1>{title}</h1>\
                 <p class=\"error\">{}</p>\
                 <p><a href=\"{url}\">{}</a></p>",
                html_escape(msg),
                copy.msg("reset.requestNewLink", "Request a new reset link"),
            ),
            &copy.lang,
        ),
    )
        .into_response()
}

/// Success page after the password was changed.
fn update_success_page(copy: &PageCopy, realm_name: &str) -> Response {
    let mut login = url::form_urlencoded::Serializer::new(String::new());
    login.append_pair("realm", realm_name);
    let login_url = format!("/login.html?{}", login.finish());
    let title = copy.msg("reset.successTitle", "Password updated");
    page(
        &title,
        &format!(
            "<h1>{title}</h1>\
             <p>{}</p>\
             <p><a href=\"{login_url}\">{}</a></p>",
            copy.msg("reset.successLead", "Your password has been changed."),
            copy.msg("reset.successContinue", "Continue to sign in"),
        ),
        &copy.lang,
    )
    .into_response()
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

/// Extract the `username` field from a urlencoded or JSON request body.
fn parse_username(headers: &HeaderMap, body: &Bytes) -> Option<String> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type.contains("application/json") {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;
        json.get("username")?.as_str().map(str::to_string)
    } else {
        let form: HashMap<String, String> = serde_urlencoded::from_bytes(body).ok()?;
        form.get("username").cloned()
    }
}

/// Resolve the account, mint the action token, track its `jti`, and send the
/// reset email. Unknown/disabled/address-less accounts silently return `Ok(())`
/// without sending — the caller always answers 204 regardless.
async fn send_reset_email(
    state: &Arc<ServerState>,
    realm: &Realm,
    realm_name: &str,
    username: &str,
) -> Result<(), issuerd_core::IssuerdError> {
    let user = state.storage.get_user_by_username(&realm.id, username).await?;
    let user = match user {
        Some(u) => Some(u),
        // Email login disabled: do not probe addresses either.
        None if realm.login_with_email_allowed => {
            state.storage.get_user_by_email(&realm.id, username).await?
        }
        None => None,
    };
    let Some(user) = user.filter(|u| u.enabled) else {
        return Ok(());
    };
    let Some(email) = user.email.clone() else {
        return Ok(());
    };

    let claims = action_token_claims(
        &user.id,
        &realm.id,
        ACTION_TOKEN_PURPOSE_RESET_CREDENTIALS,
        RESET_CREDENTIALS_LINK_TTL_SECS,
    );
    let token = issue_action_token(state.crypto.as_ref(), &claims).await?;
    state
        .cache
        .set(
            &reset_credentials_cache_key(&realm.id, &claims.jti),
            user.id.0.clone().into_bytes(),
            Some(Duration::from_secs(RESET_CREDENTIALS_LINK_TTL_SECS as u64)),
        )
        .await?;

    let issuer = state.config.issuer_url.trim_end_matches('/');
    let link = format!(
        "{issuer}/realms/{}/login/update-credentials?token={token}",
        url_path_segment(realm_name)
    );
    let realm_display =
        realm.display_name.as_ref().map(|d| d.as_str()).unwrap_or(realm.name.as_str());
    let user_display =
        user.first_name.as_ref().map(|n| n.as_str()).unwrap_or(user.username.as_str());
    let locale = crate::i18n::user_locale(realm, &user);
    let bundle = crate::i18n::message_bundle(
        Some(state.config.themes.dir.as_path()),
        realm.email_theme.as_ref().map(|t| t.as_str()),
        &locale,
    );
    let rendered = render_reset_credentials_email_localized(
        realm_display,
        user_display,
        &link,
        RESET_CREDENTIALS_LINK_TTL_SECS / 60,
        &bundle,
    );
    state
        .email_sender
        .send(realm, email.as_str(), &rendered.subject, &rendered.text, Some(rendered.html))
        .await
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET `/realms/{realm}/login/reset-credentials` — render the request form.
/// 404 unless the realm exists and allows password reset.
pub async fn reset_credentials_page(
    State(state): State<Arc<ServerState>>,
    Path(realm_name): Path<String>,
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
    if !realm.reset_password_allowed {
        return error_response(
            &copy,
            StatusCode::NOT_FOUND,
            &copy.msg("reset.notEnabled", "Password reset is not enabled for this realm."),
        );
    }
    render_reset_request_page(&copy, &realm_name)
}

/// POST `/realms/{realm}/login/reset-credentials` — accept the request and,
/// when the account exists and has an email address, send the reset link.
/// Always 204: the response must not reveal whether an account exists.
#[instrument(skip(state, headers, body), fields(realm = %realm_name))]
pub async fn reset_credentials_submit(
    State(state): State<Arc<ServerState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
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
    if !realm.reset_password_allowed {
        let copy = PageCopy::for_realm(&state, &realm, None, accept_language(&headers));
        return error_response(
            &copy,
            StatusCode::NOT_FOUND,
            &copy.msg("reset.notEnabled", "Password reset is not enabled for this realm."),
        );
    }

    if let Some(username) = parse_username(&headers, &body) {
        // A delivery failure must not leak through the response either.
        if let Err(e) = send_reset_email(&state, &realm, &realm_name, &username).await {
            error!(realm = %realm.id, error = %e, "failed to send reset-credentials email");
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// GET `/realms/{realm}/login/update-credentials?token=...` — the link target
/// from the reset email. Verifies the action token and renders the
/// new-password form; dead links get an error page instead.
pub async fn update_credentials_page(
    State(state): State<Arc<ServerState>>,
    Path(realm_name): Path<String>,
    Query(query): Query<HashMap<String, String>>,
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
    if !realm.reset_password_allowed {
        return error_response(
            &copy,
            StatusCode::NOT_FOUND,
            &copy.msg("reset.notEnabled", "Password reset is not enabled for this realm."),
        );
    }
    let realm_id = realm.id.clone();

    let Some(token) = query.get("token") else {
        return link_error_page(&copy, &realm_name, &copy.msg("reset.invalidLink", INVALID_LINK));
    };
    let claims = match verify_action_token(
        state.crypto.as_ref(),
        token,
        ACTION_TOKEN_PURPOSE_RESET_CREDENTIALS,
        &realm_id,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "reset-credentials link rejected: invalid or expired token");
            return link_error_page(
                &copy,
                &realm_name,
                &copy.msg("reset.invalidLink", INVALID_LINK),
            );
        }
    };
    // Single-use: the jti must still be pending in the cache.
    match state.cache.get(&reset_credentials_cache_key(&realm_id, &claims.jti)).await {
        Ok(Some(_)) => render_update_credentials_page(&copy, &realm_name, token, None),
        _ => link_error_page(&copy, &realm_name, &copy.msg("reset.usedLink", USED_LINK)),
    }
}

/// POST `/realms/{realm}/login/update-credentials` — validate the form,
/// consume the token atomically, and set the new password through the
/// canonical policy/history-enforcing writer.
#[instrument(skip(state, ip, headers, body), fields(realm = %realm_name))]
pub async fn update_credentials_submit(
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
    let copy = PageCopy::for_realm(&state, &realm, None, accept_language(&headers));
    if !realm.reset_password_allowed {
        return error_response(
            &copy,
            StatusCode::NOT_FOUND,
            &copy.msg("reset.notEnabled", "Password reset is not enabled for this realm."),
        );
    }
    let realm_id = realm.id.clone();

    let token = form.get("token").cloned().unwrap_or_default();
    let claims = match verify_action_token(
        state.crypto.as_ref(),
        &token,
        ACTION_TOKEN_PURPOSE_RESET_CREDENTIALS,
        &realm_id,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "reset-credentials link rejected: invalid or expired token");
            return link_error_page(
                &copy,
                &realm_name,
                &copy.msg("reset.invalidLink", INVALID_LINK),
            );
        }
    };
    let key = reset_credentials_cache_key(&realm_id, &claims.jti);
    // The token must be unused before the form is even considered; the
    // actual consumption below is the atomic point of no return.
    match state.cache.get(&key).await {
        Ok(Some(_)) => {}
        _ => return link_error_page(&copy, &realm_name, &copy.msg("reset.usedLink", USED_LINK)),
    }

    let new_password = form.get("new_password").cloned().unwrap_or_default();
    let confirm_password = form.get("confirm_password").cloned().unwrap_or_default();
    if new_password != confirm_password {
        return render_update_credentials_page(
            &copy,
            &realm_name,
            &token,
            Some(&copy.msg("reset.passwordsDoNotMatch", "The passwords do not match.")),
        );
    }

    let user_id = match UserId::new(claims.sub.clone()) {
        Ok(id) => id,
        Err(_) => {
            return link_error_page(
                &copy,
                &realm_name,
                &copy.msg("reset.invalidLink", INVALID_LINK),
            )
        }
    };
    let mut user = match state.storage.get_user(&realm_id, &user_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => {
            return link_error_page(
                &copy,
                &realm_name,
                &copy.msg("error.accountUnavailable", "This account is no longer available."),
            )
        }
    };

    if let Err(err) = realm.password_policy.validate(&new_password, &user) {
        // Best-effort localization of the known policy messages; unknown
        // texts pass through unchanged.
        let message = err
            .violations
            .iter()
            .map(|v| crate::i18n::localize_error(&copy.bundle, &v.message))
            .collect::<Vec<_>>()
            .join(" ");
        // The token is deliberately NOT consumed: the user may correct the
        // password and resubmit with the same link.
        return render_update_credentials_page(&copy, &realm_name, &token, Some(&message));
    }

    // All checks passed — consume the jti atomically. A concurrent replay of
    // the same link loses the race here.
    match state.cache.get_and_delete(&key).await {
        Ok(Some(_)) => {}
        _ => return link_error_page(&copy, &realm_name, &copy.msg("reset.usedLink", USED_LINK)),
    }

    // Federated user: write the new password through to the external
    // directory; only a non-federated user (or a dead link) keeps the local
    // credential write.
    let written_to_directory = match write_through_federated_password(
        state.storage.as_ref(),
        Some(state.federation_manager.as_ref()),
        &realm_id,
        &user_id,
        &new_password,
    )
    .await
    {
        Ok(FederationWriteThrough::WrittenToDirectory) => true,
        Ok(FederationWriteThrough::NotApplicable) => false,
        Err(e) => {
            error!(realm = %realm_id, user_id = %user_id, error = %e, "password reset failed");
            return link_error_page(
                &copy,
                &realm_name,
                &copy.msg(
                    "reset.updateFailed",
                    "Could not update the password. Please request a new reset link.",
                ),
            );
        }
    };

    if !written_to_directory {
        if let Err(e) = set_user_password(
            state.storage.as_ref(),
            &realm_id,
            &user_id,
            &new_password,
            realm.password_policy.history_size,
            false,
        )
        .await
        {
            error!(realm = %realm_id, user_id = %user_id, error = %e, "password reset failed");
            return link_error_page(
                &copy,
                &realm_name,
                &copy.msg(
                    "reset.updateFailed",
                    "Could not update the password. Please request a new reset link.",
                ),
            );
        }
    }

    // A successful reset satisfies the UPDATE_PASSWORD required action.
    if user.required_actions.iter().any(|a| a == "UPDATE_PASSWORD") {
        user.required_actions.retain(|a| a != "UPDATE_PASSWORD");
        let _ = state.storage.update_user(&realm_id, &user).await;
        issuerd_cluster::invalidate::invalidate_user_claims(
            state.cache.as_ref(),
            &realm_id,
            &user.id,
        )
        .await;
    }

    info!(realm = %realm_id, user_id = %user_id, "password reset via email link");
    let mut details = HashMap::new();
    details.insert("username".to_string(), user.username.to_string());
    emit_oidc_event(
        &state,
        &realm_id,
        EventType::Custom("reset_password".to_string()),
        &ip,
        None,
        Some(user_id),
        None,
        None,
        details,
    )
    .await;

    update_success_page(&copy, &realm_name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use issuerd_core::{CredentialType, DistributedCache, Email, Storage, User, Username};

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

    /// (to, subject, text body) of every mail the mock sender was asked to send.
    type SentMails = Arc<std::sync::Mutex<Vec<(String, String, String)>>>;
    type MockSender = Arc<issuerd_core::MockEmailSender>;

    /// A recording [`EmailSender`] mock plus the shared capture buffer.
    fn recording_state() -> (SentMails, MockSender) {
        let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = sent.clone();
        let mut mock = issuerd_core::MockEmailSender::new();
        mock.expect_send().returning(move |_realm, to, subject, text, _html| {
            captured
                .lock()
                .unwrap()
                .push((to.to_string(), subject.to_string(), text.to_string()));
            Ok(())
        });
        (sent, Arc::new(mock))
    }

    async fn state_with_sender(sender: MockSender) -> (Arc<ServerState>, TestStorage, TestCache) {
        let cfg = ServerConfig::default();
        let storage: TestStorage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let cache: TestCache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let state = ServerState::from_components_with_email_sender(
            &cfg,
            storage.clone(),
            cache.clone(),
            sender,
        )
        .await
        .unwrap();
        (Arc::new(state), storage, cache)
    }

    fn master_realm_id() -> RealmId {
        RealmId::new("master").unwrap()
    }

    /// Flip `reset_password_allowed` on the master realm and make sure the
    /// by-name resolution cache cannot serve a stale pre-update row.
    async fn enable_reset_password(state: &Arc<ServerState>) -> Realm {
        let mut realm = state
            .storage
            .get_realm(&master_realm_id())
            .await
            .unwrap()
            .expect("master realm bootstrapped");
        realm.reset_password_allowed = true;
        state.storage.update_realm(&realm).await.unwrap();
        let _ = state.cache.delete(&issuerd_cluster::cache_keys::realm_by_name("master")).await;
        realm
    }

    async fn seed_user(
        storage: &TestStorage,
        realm_id: &RealmId,
        username: &str,
        email: Option<&str>,
        enabled: bool,
        required_actions: &[&str],
    ) -> User {
        let now = chrono::Utc::now();
        let user = User {
            id: UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new(username).unwrap(),
            email: email.map(|e| Email::new(e).unwrap()),
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: required_actions.iter().map(|a| a.to_string()).collect(),
            created_at: now,
            updated_at: now,
        };
        storage.create_user(realm_id, &user).await.unwrap();
        user
    }

    /// Mint a reset-credentials action token and return it with its `jti`.
    async fn mint_reset_token(
        state: &Arc<ServerState>,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> (String, String) {
        let claims = action_token_claims(
            user_id,
            realm_id,
            ACTION_TOKEN_PURPOSE_RESET_CREDENTIALS,
            RESET_CREDENTIALS_LINK_TTL_SECS,
        );
        let jti = claims.jti.clone();
        let token = issue_action_token(state.crypto.as_ref(), &claims).await.unwrap();
        (token, jti)
    }

    async fn seed_pending_jti(cache: &TestCache, realm_id: &RealmId, jti: &str, user_id: &UserId) {
        cache
            .set(
                &reset_credentials_cache_key(realm_id, jti),
                user_id.0.clone().into_bytes(),
                Some(Duration::from_secs(RESET_CREDENTIALS_LINK_TTL_SECS as u64)),
            )
            .await
            .unwrap();
    }

    fn client_ip() -> axum::extract::Extension<ClientIp> {
        axum::extract::Extension(ClientIp(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
    }

    async fn call_update_submit(state: &Arc<ServerState>, form: &[(&str, &str)]) -> Response {
        let body = serde_urlencoded::to_string(form).unwrap();
        update_credentials_submit(
            State(state.clone()),
            Path("master".to_string()),
            client_ip(),
            HeaderMap::new(),
            Bytes::from(body),
        )
        .await
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn cache_key_is_realm_scoped() {
        let realm = RealmId::new("master").unwrap();
        assert_eq!(reset_credentials_cache_key(&realm, "jti-1"), "reset-credentials:master:jti-1");
    }

    #[tokio::test]
    async fn request_page_renders_form_and_js_confirmation() {
        let resp = render_reset_request_page(&PageCopy::builtin("en"), "my realm");
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("action=\"/realms/my+realm/login/reset-credentials\""));
        assert!(body.contains("Username or email"));
        assert!(body.contains("name=\"username\""));
        // The fetch-based confirmation swap is what keeps the 204 UX sane.
        assert!(body.contains("<script>"));
        assert!(body.contains(CONFIRMATION));
    }

    #[tokio::test]
    async fn request_page_localizes_copy_and_js_confirmation() {
        let mut bundle = crate::i18n::message_bundle(None, None, "en");
        bundle.insert("reset.requestHeading".to_string(), "Passwort vergessen?".to_string());
        bundle.insert("reset.confirmation".to_string(), "E-Mail unterwegs.".to_string());
        let copy = PageCopy {
            lang: "de".to_string(),
            bundle,
        };
        let resp = render_reset_request_page(&copy, "master");
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("<html lang=\"de\">"), "body: {body}");
        assert!(body.contains("<h1>Passwort vergessen?</h1>"), "body: {body}");
        // The JS swap text lands as a quoted, escaped string literal.
        assert!(body.contains("+\"E-Mail unterwegs.\"+"), "body: {body}");
        assert!(!body.contains(CONFIRMATION), "body: {body}");
    }

    #[tokio::test]
    async fn update_page_escapes_token_and_shows_error() {
        let resp = render_update_credentials_page(
            &PageCopy::builtin("en"),
            "master",
            "tok-\"<script>",
            Some("passwords do not match & more"),
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("value=\"tok-&quot;&lt;script&gt;\""));
        assert!(!body.contains("tok-\"<script>"));
        assert!(body.contains("passwords do not match &amp; more"));
        assert!(body.contains("action=\"/realms/master/login/update-credentials\""));
        assert!(body.contains("name=\"new_password\""));
        assert!(body.contains("name=\"confirm_password\""));
    }

    #[tokio::test]
    async fn link_error_page_points_back_to_request_form() {
        let resp = link_error_page(&PageCopy::builtin("en"), "master", USED_LINK);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("already been used"));
        assert!(body.contains("href=\"/realms/master/login/reset-credentials\""));
    }

    #[tokio::test]
    async fn success_page_links_to_login() {
        let resp = update_success_page(&PageCopy::builtin("en"), "my realm");
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Password updated"));
        assert!(body.contains("/login.html?realm=my+realm"));
    }

    #[test]
    fn parse_username_supports_form_and_json() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        let body = Bytes::from("username=alice&ignored=1");
        assert_eq!(parse_username(&headers, &body).as_deref(), Some("alice"));

        headers.insert(axum::http::header::CONTENT_TYPE, "application/json".parse().unwrap());
        let body = Bytes::from(r#"{"username":"bob"}"#);
        assert_eq!(parse_username(&headers, &body).as_deref(), Some("bob"));

        // Malformed bodies yield None (the handler still answers 204).
        let body = Bytes::from("not json");
        assert_eq!(parse_username(&headers, &body), None);
        let body = Bytes::from(r#"{"other":"x"}"#);
        assert_eq!(parse_username(&headers, &body), None);
    }

    // -- reset_credentials_page ------------------------------------------------

    #[tokio::test]
    async fn page_renders_form_only_when_reset_enabled() {
        let (state, _storage, _cache) = test_state().await;

        // Disabled by default: a 404 page, not the form.
        let resp = reset_credentials_page(
            State(state.clone()),
            Path("master".to_string()),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(body_string(resp).await.contains("not enabled"));

        enable_reset_password(&state).await;
        let resp =
            reset_credentials_page(State(state), Path("master".to_string()), HeaderMap::new())
                .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Forgot your password?"));
        assert!(body.contains("action=\"/realms/master/login/reset-credentials\""));
        assert!(body.contains("name=\"username\""));
    }

    // -- reset_credentials_submit ----------------------------------------------

    #[tokio::test]
    async fn submit_answers_204_regardless_of_account_existence() {
        let (state, storage, _cache) = test_state().await;
        enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        seed_user(&storage, &realm_id, "alice", Some("alice@example.com"), true, &[]).await;

        // The default state wires the loud NoOpEmailSender: even a delivery
        // failure for an existing account must surface as the same 204.
        for username in ["alice", "no-such-user"] {
            let resp = reset_credentials_submit(
                State(state.clone()),
                Path("master".to_string()),
                HeaderMap::new(),
                Bytes::from(format!("username={username}")),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::NO_CONTENT, "username {username}");
            assert!(body_string(resp).await.is_empty(), "204 carries no body");
        }
    }

    #[tokio::test]
    async fn submit_requires_realm_flag() {
        let (state, _storage, _cache) = test_state().await;
        let resp = reset_credentials_submit(
            State(state),
            Path("master".to_string()),
            HeaderMap::new(),
            Bytes::from("username=alice"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(body_string(resp).await.contains("not enabled"));
    }

    // -- send_reset_email --------------------------------------------------------

    #[tokio::test]
    async fn send_reset_email_delivers_token_link_with_expiry_minutes() {
        let (sent, sender) = recording_state();
        let (state, storage, cache) = state_with_sender(sender).await;
        let realm = enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        let user =
            seed_user(&storage, &realm_id, "alice", Some("alice@example.com"), true, &[]).await;

        send_reset_email(&state, &realm, "master", "alice")
            .await
            .expect("send succeeds");

        // Snapshot the recording and drop the lock guard before any await.
        let (to, subject, text) = {
            let sent = sent.lock().unwrap();
            assert_eq!(sent.len(), 1, "exactly one reset email sent");
            sent[0].clone()
        };
        assert_eq!(to, "alice@example.com");
        assert_eq!(subject, "Reset your password");
        // The 900 s TTL is rendered in minutes (`TTL / 60` — not `% 60` = 0,
        // not `* 60` = 54000).
        assert!(text.contains("15 minutes"), "text: {text}");
        let link = text
            .lines()
            .map(str::trim)
            .find(|l| l.contains("/login/update-credentials?token="))
            .expect("reset link in the text body");
        assert!(
            link.starts_with("http://localhost:8080/realms/master/login/update-credentials?token="),
            "link: {link}"
        );
        // The embedded token verifies and its jti is tracked for single-use.
        let token = link.rsplit("token=").next().unwrap();
        let claims = verify_action_token(
            state.crypto.as_ref(),
            token,
            ACTION_TOKEN_PURPOSE_RESET_CREDENTIALS,
            &realm_id,
        )
        .await
        .unwrap();
        assert_eq!(claims.sub, user.id.0);
        let cached = cache
            .get(&reset_credentials_cache_key(&realm_id, &claims.jti))
            .await
            .unwrap()
            .expect("jti tracked in the cache");
        assert_eq!(cached, user.id.0.clone().into_bytes());
    }

    #[tokio::test]
    async fn send_reset_email_probes_addresses_only_when_email_login_allowed() {
        let (sent, sender) = recording_state();
        let (state, storage, _cache) = state_with_sender(sender).await;
        let realm = enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        // Findable only by email — the username lookup misses.
        seed_user(&storage, &realm_id, "bob", Some("bob@example.com"), true, &[]).await;

        // Default realms allow email login: the address probe runs.
        send_reset_email(&state, &realm, "master", "bob@example.com").await.unwrap();
        assert_eq!(sent.lock().unwrap().len(), 1, "email login allowed → probe sends");

        // With email login disabled the address is never probed.
        let mut realm = realm;
        realm.login_with_email_allowed = false;
        send_reset_email(&state, &realm, "master", "bob@example.com").await.unwrap();
        assert_eq!(sent.lock().unwrap().len(), 1, "email login disabled → no probe, no mail");
    }

    #[tokio::test]
    async fn send_reset_email_silently_skips_unusable_accounts() {
        let (sent, sender) = recording_state();
        let (state, storage, _cache) = state_with_sender(sender).await;
        let realm = enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        seed_user(&storage, &realm_id, "disabled", Some("d@example.com"), false, &[]).await;
        seed_user(&storage, &realm_id, "no-email", None, true, &[]).await;

        for username in ["no-such-user", "disabled", "no-email"] {
            send_reset_email(&state, &realm, "master", username).await.unwrap();
        }
        assert!(
            sent.lock().unwrap().is_empty(),
            "no mail for unknown/disabled/address-less accounts"
        );
    }

    // -- update_credentials_page -------------------------------------------------

    #[tokio::test]
    async fn update_page_renders_form_for_pending_token() {
        let (state, storage, cache) = test_state().await;
        enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        let user =
            seed_user(&storage, &realm_id, "alice", Some("alice@example.com"), true, &[]).await;
        let (token, jti) = mint_reset_token(&state, &realm_id, &user.id).await;
        seed_pending_jti(&cache, &realm_id, &jti, &user.id).await;

        let resp = update_credentials_page(
            State(state),
            Path("master".to_string()),
            Query(HashMap::from([("token".to_string(), token.clone())])),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Choose a new password"));
        assert!(body.contains("name=\"new_password\""));
        assert!(body.contains("name=\"confirm_password\""));
        assert!(body.contains(&format!("value=\"{token}\"")));
    }

    #[tokio::test]
    async fn update_page_rejects_invalid_and_consumed_links() {
        let (state, storage, _cache) = test_state().await;
        enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        let user =
            seed_user(&storage, &realm_id, "alice", Some("alice@example.com"), true, &[]).await;

        // Garbage token → invalid-link page.
        let resp = update_credentials_page(
            State(state.clone()),
            Path("master".to_string()),
            Query(HashMap::from([("token".to_string(), "garbage".to_string())])),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("invalid or has expired"));

        // Valid token whose jti is not pending → single-use page.
        let (token, _jti) = mint_reset_token(&state, &realm_id, &user.id).await;
        let resp = update_credentials_page(
            State(state),
            Path("master".to_string()),
            Query(HashMap::from([("token".to_string(), token)])),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("already been used"));
    }

    // -- update_credentials_submit -----------------------------------------------

    #[tokio::test]
    async fn update_submit_sets_password_consumes_token_and_clears_required_action() {
        let (state, storage, cache) = test_state().await;
        enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        let user = seed_user(
            &storage,
            &realm_id,
            "alice",
            Some("alice@example.com"),
            true,
            &["UPDATE_PASSWORD"],
        )
        .await;
        let (token, jti) = mint_reset_token(&state, &realm_id, &user.id).await;
        seed_pending_jti(&cache, &realm_id, &jti, &user.id).await;

        let resp = call_update_submit(
            &state,
            &[
                ("token", token.as_str()),
                ("new_password", "new-secret-123"),
                ("confirm_password", "new-secret-123"),
            ],
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("Password updated"));

        // The new password credential was actually written…
        let creds = storage
            .get_credentials(&realm_id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert!(
            creds
                .iter()
                .any(|c| issuerd_auth_flow::built_in::verify_password_hash("new-secret-123", c)),
            "new password verifies against the stored credential"
        );
        // …the jti was consumed (single-use)…
        assert!(
            cache
                .get(&reset_credentials_cache_key(&realm_id, &jti))
                .await
                .unwrap()
                .is_none(),
            "jti consumed after success"
        );
        // …and a successful reset satisfies the UPDATE_PASSWORD required action.
        let user = storage.get_user(&realm_id, &user.id).await.unwrap().unwrap();
        assert!(
            !user.required_actions.iter().any(|a| a == "UPDATE_PASSWORD"),
            "UPDATE_PASSWORD cleared: {:?}",
            user.required_actions
        );
    }

    #[tokio::test]
    async fn update_submit_rejects_disabled_account() {
        let (state, storage, cache) = test_state().await;
        enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        let user =
            seed_user(&storage, &realm_id, "alice", Some("alice@example.com"), false, &[]).await;
        let (token, jti) = mint_reset_token(&state, &realm_id, &user.id).await;
        seed_pending_jti(&cache, &realm_id, &jti, &user.id).await;

        let resp = call_update_submit(
            &state,
            &[
                ("token", token.as_str()),
                ("new_password", "new-secret-123"),
                ("confirm_password", "new-secret-123"),
            ],
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("no longer available"));
        assert!(
            storage
                .get_credentials(&realm_id, &user.id, CredentialType::Password)
                .await
                .unwrap()
                .is_empty(),
            "no password written for a disabled account"
        );
    }

    #[tokio::test]
    async fn update_submit_mismatched_passwords_rerender_without_consuming() {
        let (state, storage, cache) = test_state().await;
        enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        let user =
            seed_user(&storage, &realm_id, "alice", Some("alice@example.com"), true, &[]).await;
        let (token, jti) = mint_reset_token(&state, &realm_id, &user.id).await;
        seed_pending_jti(&cache, &realm_id, &jti, &user.id).await;

        let resp = call_update_submit(
            &state,
            &[
                ("token", token.as_str()),
                ("new_password", "new-secret-123"),
                ("confirm_password", "something-else"),
            ],
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("The passwords do not match."));
        // The token stays pending so the user can correct and resubmit.
        assert!(
            cache
                .get(&reset_credentials_cache_key(&realm_id, &jti))
                .await
                .unwrap()
                .is_some(),
            "jti not consumed on a form error"
        );
        assert!(storage
            .get_credentials(&realm_id, &user.id, CredentialType::Password)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn update_submit_replay_after_success_is_rejected() {
        let (state, storage, cache) = test_state().await;
        enable_reset_password(&state).await;
        let realm_id = master_realm_id();
        let user =
            seed_user(&storage, &realm_id, "alice", Some("alice@example.com"), true, &[]).await;
        let (token, jti) = mint_reset_token(&state, &realm_id, &user.id).await;
        seed_pending_jti(&cache, &realm_id, &jti, &user.id).await;

        let form = [
            ("token", token.as_str()),
            ("new_password", "new-secret-123"),
            ("confirm_password", "new-secret-123"),
        ];
        let first = call_update_submit(&state, &form).await;
        assert_eq!(first.status(), StatusCode::OK);

        let resp = call_update_submit(&state, &form).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("already been used"));
    }

    #[tokio::test]
    async fn update_submit_rejects_garbage_token() {
        let (state, _storage, _cache) = test_state().await;
        enable_reset_password(&state).await;

        let resp = call_update_submit(
            &state,
            &[
                ("token", "garbage"),
                ("new_password", "new-secret-123"),
                ("confirm_password", "new-secret-123"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("invalid or has expired"));
    }
}
