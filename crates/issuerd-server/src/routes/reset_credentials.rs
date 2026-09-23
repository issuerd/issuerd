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
use super::required_actions::{error_banner, error_response, page, url_path_segment};

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
/// `RESET_FORM_SCRIPT_PRE` + [`CONFIRMATION`] + `RESET_FORM_SCRIPT_POST`.
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
document.querySelector(\"main.card\").innerHTML=\"<h1>Check your email</h1><p>";

const RESET_FORM_SCRIPT_POST: &str = "</p>\";});});})();</script>";

/// Render the "request a reset link" form (single `username` field).
fn render_reset_request_page(realm_name: &str) -> Response {
    let url = format!("/realms/{}/login/reset-credentials", url_path_segment(realm_name));
    let mut body = format!(
        "<h1>Forgot your password?</h1>\
         <p>Enter your username or email address and we will send you a link to reset \
         your password.</p>\
         <form method=\"post\" action=\"{url}\" id=\"issuerd-reset-form\">\
         <label for=\"username\">Username or email</label>\
         <input type=\"text\" id=\"username\" name=\"username\" \
         autocomplete=\"username\" required>\
         <button type=\"submit\">Send reset email</button>\
         </form>"
    );
    body.push_str(RESET_FORM_SCRIPT_PRE);
    body.push_str(CONFIRMATION);
    body.push_str(RESET_FORM_SCRIPT_POST);
    page("Reset password", &body).into_response()
}

/// Render the new-password form the emailed link opens. `token` is round-
/// tripped through a hidden field so the POST can re-verify it.
fn render_update_credentials_page(realm_name: &str, token: &str, error: Option<&str>) -> Response {
    let url = format!("/realms/{}/login/update-credentials", url_path_segment(realm_name));
    let banner = error_banner(error);
    let body = format!(
        "<h1>Choose a new password</h1>\
         {banner}\
         <form method=\"post\" action=\"{url}\">\
         <input type=\"hidden\" name=\"token\" value=\"{}\">\
         <label for=\"new_password\">New password</label>\
         <input type=\"password\" id=\"new_password\" name=\"new_password\" \
         autocomplete=\"new-password\" required>\
         <label for=\"confirm_password\">Confirm password</label>\
         <input type=\"password\" id=\"confirm_password\" name=\"confirm_password\" \
         autocomplete=\"new-password\" required>\
         <button type=\"submit\">Update password</button>\
         </form>",
        html_escape(token),
    );
    page("Update password", &body).into_response()
}

/// Error page for dead links (invalid/expired/already used), with a way back
/// to the request form.
fn link_error_page(realm_name: &str, msg: &str) -> Response {
    let url = format!("/realms/{}/login/reset-credentials", url_path_segment(realm_name));
    (
        StatusCode::BAD_REQUEST,
        page(
            "Reset password",
            &format!(
                "<h1>Reset password</h1>\
                 <p class=\"error\">{}</p>\
                 <p><a href=\"{url}\">Request a new reset link</a></p>",
                html_escape(msg)
            ),
        ),
    )
        .into_response()
}

/// Success page after the password was changed.
fn update_success_page(realm_name: &str) -> Response {
    let mut login = url::form_urlencoded::Serializer::new(String::new());
    login.append_pair("realm", realm_name);
    let login_url = format!("/login.html?{}", login.finish());
    page(
        "Password updated",
        &format!(
            "<h1>Password updated</h1>\
             <p>Your password has been changed.</p>\
             <p><a href=\"{login_url}\">Continue to sign in</a></p>"
        ),
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
) -> Response {
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::NOT_FOUND, "Realm not found."),
    };
    if !realm.reset_password_allowed {
        return error_response(
            StatusCode::NOT_FOUND,
            "Password reset is not enabled for this realm.",
        );
    }
    render_reset_request_page(&realm_name)
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
        _ => return error_response(StatusCode::NOT_FOUND, "Realm not found."),
    };
    if !realm.reset_password_allowed {
        return error_response(
            StatusCode::NOT_FOUND,
            "Password reset is not enabled for this realm.",
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
) -> Response {
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::NOT_FOUND, "Realm not found."),
    };
    if !realm.reset_password_allowed {
        return error_response(
            StatusCode::NOT_FOUND,
            "Password reset is not enabled for this realm.",
        );
    }
    let realm_id = realm.id.clone();

    let Some(token) = query.get("token") else {
        return link_error_page(&realm_name, INVALID_LINK);
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
            return link_error_page(&realm_name, INVALID_LINK);
        }
    };
    // Single-use: the jti must still be pending in the cache.
    match state.cache.get(&reset_credentials_cache_key(&realm_id, &claims.jti)).await {
        Ok(Some(_)) => render_update_credentials_page(&realm_name, token, None),
        _ => link_error_page(&realm_name, USED_LINK),
    }
}

/// POST `/realms/{realm}/login/update-credentials` — validate the form,
/// consume the token atomically, and set the new password through the
/// canonical policy/history-enforcing writer.
#[instrument(skip(state, ip, body), fields(realm = %realm_name))]
pub async fn update_credentials_submit(
    State(state): State<Arc<ServerState>>,
    Path(realm_name): Path<String>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    body: Bytes,
) -> Response {
    let form: HashMap<String, String> = serde_urlencoded::from_bytes(&body).unwrap_or_default();
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::NOT_FOUND, "Realm not found."),
    };
    if !realm.reset_password_allowed {
        return error_response(
            StatusCode::NOT_FOUND,
            "Password reset is not enabled for this realm.",
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
            return link_error_page(&realm_name, INVALID_LINK);
        }
    };
    let key = reset_credentials_cache_key(&realm_id, &claims.jti);
    // The token must be unused before the form is even considered; the
    // actual consumption below is the atomic point of no return.
    match state.cache.get(&key).await {
        Ok(Some(_)) => {}
        _ => return link_error_page(&realm_name, USED_LINK),
    }

    let new_password = form.get("new_password").cloned().unwrap_or_default();
    let confirm_password = form.get("confirm_password").cloned().unwrap_or_default();
    if new_password != confirm_password {
        return render_update_credentials_page(
            &realm_name,
            &token,
            Some("The passwords do not match."),
        );
    }

    let user_id = match UserId::new(claims.sub.clone()) {
        Ok(id) => id,
        Err(_) => return link_error_page(&realm_name, INVALID_LINK),
    };
    let mut user = match state.storage.get_user(&realm_id, &user_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => return link_error_page(&realm_name, "This account is no longer available."),
    };

    if let Err(err) = realm.password_policy.validate(&new_password, &user) {
        let message =
            err.violations.iter().map(|v| v.message.as_str()).collect::<Vec<_>>().join(" ");
        // The token is deliberately NOT consumed: the user may correct the
        // password and resubmit with the same link.
        return render_update_credentials_page(&realm_name, &token, Some(&message));
    }

    // All checks passed — consume the jti atomically. A concurrent replay of
    // the same link loses the race here.
    match state.cache.get_and_delete(&key).await {
        Ok(Some(_)) => {}
        _ => return link_error_page(&realm_name, USED_LINK),
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
                &realm_name,
                "Could not update the password. Please request a new reset link.",
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
                &realm_name,
                "Could not update the password. Please request a new reset link.",
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

    update_success_page(&realm_name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_realm_scoped() {
        let realm = RealmId::new("master").unwrap();
        assert_eq!(reset_credentials_cache_key(&realm, "jti-1"), "reset-credentials:master:jti-1");
    }

    #[tokio::test]
    async fn request_page_renders_form_and_js_confirmation() {
        let resp = render_reset_request_page("my realm");
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
    async fn update_page_escapes_token_and_shows_error() {
        let resp = render_update_credentials_page(
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
        let resp = link_error_page("master", USED_LINK);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("already been used"));
        assert!(body.contains("href=\"/realms/master/login/reset-credentials\""));
    }

    #[tokio::test]
    async fn success_page_links_to_login() {
        let resp = update_success_page("my realm");
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
}
