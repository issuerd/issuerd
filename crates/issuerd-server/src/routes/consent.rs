// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Consent screen: scope-grant page and stored-consent checks.

//! Consent screen.
//!
//! After successful authentication (and after any required actions), a client
//! with `consent_required = true` receives an authorization response only
//! once the user has granted the requested scopes on a consent page. The
//! grant is persisted as a `Consent` record (upsert semantics) and consulted
//! on later logins: the page is skipped while the stored grant covers the
//! requested scope set. `prompt=consent` forces the page regardless, and
//! revoking the grant (account-console consents API) re-triggers
//! it. Denial redirects `access_denied` to the client's registered redirect
//! URI (already validated at authorization-request parse time).
//!
//! State lives in the distributed cache under
//! `pending_consent:{realm}:{execution}` (10-minute TTL) so any cluster node
//! can render and continue the page; POSTs require the per-flow correlation
//! cookie (same login-CSRF model as the required-action continuation).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use tracing::{error, info, warn};

use issuerd_core::{AuthMethod, Client, Realm, RealmId, SessionId, User, UserId};

use crate::email::html_escape;
use crate::state::ServerState;

use super::login_api::LoginResponse;
use super::oidc::{flow_cookie_header, has_flow_cookie, PendingAuthData};
use super::required_actions::{error_banner, error_response, page, url_path_segment};

/// Cache TTL for a paused consent continuation (matches pending auth).
const PENDING_CONSENT_TTL_SECS: u64 = 600;

/// Cache key for a paused consent continuation.
pub(crate) fn pending_consent_cache_key(realm_id: &RealmId, execution: &str) -> String {
    format!("pending_consent:{}:{}", realm_id.0, execution)
}

fn consent_tag() -> String {
    "consent".to_string()
}

/// State of a paused login waiting for the user's consent decision.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingConsentData {
    /// The original authorization request; replayed on approval.
    pub pending: PendingAuthData,
    pub user_id: String,
    pub session_id: String,
    /// Flow-result time (session start/refresh timestamps).
    pub result_auth_time: chrono::DateTime<chrono::Utc>,
    /// Final `auth_time` stamped on sessions/tokens (the SSO path preserves
    /// the original authentication time).
    pub auth_time: chrono::DateTime<chrono::Utc>,
    pub is_browser_form: bool,
    /// `true` = resume by merging into the (possibly pre-existing) SSO
    /// session via [`super::oidc::finish_sso_login`]; `false` = fresh session
    /// via [`super::login_api::complete_login_with_method`].
    pub sso_resume: bool,
    /// Authentication method stamped on fresh sessions (non-SSO resume).
    pub auth_method: AuthMethod,
    /// Login-event method label (non-SSO resume).
    pub method_label: String,
    /// One-shot error banner carried across a POST→redirect (PRG pattern).
    #[serde(default)]
    pub error: Option<String>,
    /// Typestate marker for cache round-trips.
    #[serde(default = "consent_tag")]
    pub _typestate_tag: String,
}

fn continuation_url(realm_name: &str, execution: &str) -> String {
    format!("/realms/{}/login/consent/{execution}", url_path_segment(realm_name))
}

/// Does this login need a consent-page stop?
///
/// The page is shown when `prompt=consent` was requested (regardless of
/// stored grants), or when the client requires consent and no stored grant
/// covers the full requested scope set. A consent-store failure fails open
/// (log + skip) so a backend hiccup cannot take down logins — the same
/// policy the claims overlay uses.
pub(crate) async fn consent_needed(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    client: &Client,
    user_id: &UserId,
    granted_scopes: &[String],
    prompt_consent: bool,
) -> bool {
    if !client.consent_required && !prompt_consent {
        return false;
    }
    if prompt_consent {
        return true;
    }
    match state.storage.get_consents(realm_id, user_id).await {
        Ok(consents) => match consents.iter().find(|c| c.client_id == client.id) {
            Some(grant) => !granted_scopes.iter().all(|s| grant.granted_scopes.contains(s)),
            None => true,
        },
        Err(e) => {
            warn!(realm = %realm_id, error = %e, "consent lookup failed; skipping consent screen");
            false
        }
    }
}

/// Store the paused login and route the user agent to the consent page.
pub(crate) async fn begin_consent(
    state: &Arc<ServerState>,
    realm_name: &str,
    entry: PendingConsentData,
) -> Response {
    let realm_id = match RealmId::new(entry.pending.realm_id.clone()) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "invalid_grant"})),
            )
                .into_response();
        }
    };
    let execution = issuerd_core::utils::generate_id();
    // Serialization cannot fail: every field is a plain String/Option/Vec.
    let bytes = serde_json::to_vec(&entry).unwrap();
    let _ = state
        .cache
        .set(
            &pending_consent_cache_key(&realm_id, &execution),
            bytes,
            Some(Duration::from_secs(PENDING_CONSENT_TTL_SECS)),
        )
        .await;

    let url = continuation_url(realm_name, &execution);
    let cookie = flow_cookie_header(&execution);
    if entry.is_browser_form {
        let mut resp = axum::response::Redirect::to(&url).into_response();
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
        }
        resp
    } else {
        // SPA login: the client navigates to `redirect_uri` itself.
        (
            [(axum::http::header::SET_COOKIE, cookie)],
            axum::Json(LoginResponse {
                redirect_uri: url,
                code: None,
                id_token: None,
                state: entry.pending.state.clone(),
            }),
        )
            .into_response()
    }
}

async fn store_entry(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    execution: &str,
    entry: &PendingConsentData,
) {
    let bytes = serde_json::to_vec(entry).unwrap();
    let _ = state
        .cache
        .set(
            &pending_consent_cache_key(realm_id, execution),
            bytes,
            Some(Duration::from_secs(PENDING_CONSENT_TTL_SECS)),
        )
        .await;
}

/// Load the paused consent entry, the realm, and the client — shared by the
/// GET page and the POST submit handler.
async fn load_consent_context(
    state: &Arc<ServerState>,
    realm_name: &str,
    execution: &str,
) -> Result<(Realm, PendingConsentData, Client), Response> {
    let realm = match state.resolve_realm(realm_name).await {
        Ok(Some(r)) => r,
        _ => {
            return Err(error_response(StatusCode::NOT_FOUND, "realm not found"));
        }
    };
    let key = pending_consent_cache_key(&realm.id, execution);
    let entry: PendingConsentData = match state.cache.get(&key).await {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(_) => {
                return Err(error_response(StatusCode::BAD_REQUEST, "invalid consent state"));
            }
        },
        _ => {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "consent request expired — please restart the login",
            ));
        }
    };
    let identifier = match issuerd_core::ClientIdentifier::new(&entry.pending.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Err(error_response(StatusCode::BAD_REQUEST, "invalid client"));
        }
    };
    let client = match state.storage.get_client_by_client_id(&realm.id, &identifier).await {
        Ok(Some(c)) => c,
        _ => {
            return Err(error_response(StatusCode::BAD_REQUEST, "unknown client"));
        }
    };
    Ok((realm, entry, client))
}

/// `GET /realms/{realm}/login/consent/{execution}` — render the consent page.
pub async fn consent_page(
    State(state): State<Arc<ServerState>>,
    Path((realm_name, execution)): Path<(String, String)>,
) -> Response {
    let (realm, entry, client) = match load_consent_context(&state, &realm_name, &execution).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    render_consent_page(&state, &realm, &realm_name, &execution, &entry, &client).await
}

async fn render_consent_page(
    state: &Arc<ServerState>,
    realm: &Realm,
    realm_name: &str,
    execution: &str,
    entry: &PendingConsentData,
    client: &Client,
) -> Response {
    // Scope display list: client-scope description when seeded, otherwise the
    // bare scope name.
    let mut items = String::new();
    for scope in &entry.pending.scope {
        let description =
            match state.storage.get_client_scope_by_name(&client.realm_id, scope).await {
                Ok(Some(cs)) => cs.description,
                _ => None,
            };
        let label = match description.as_deref().map(str::trim) {
            Some(d) if !d.is_empty() => {
                format!("{} — {}", html_escape(scope), html_escape(d))
            }
            _ => html_escape(scope),
        };
        items.push_str(&format!("<li>{label}</li>"));
    }

    let client_display = client
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| client.client_id.as_ref());
    // Page copy follows the locale pinned at the authorize endpoint; the
    // bundle falls back to English per key.
    let locale = entry
        .pending
        .locale
        .clone()
        .unwrap_or_else(|| crate::i18n::resolve_locale(realm, &[], None));
    let bundle = crate::i18n::message_bundle(
        Some(state.config.themes.dir.as_path()),
        realm.login_theme.as_ref().map(|t| t.as_str()),
        &locale,
    );
    let title = crate::i18n::msg(&bundle, "consent.title", "Grant access");
    let lead = crate::i18n::msg(&bundle, "consent.lead", "requests permission to:");
    let allow = crate::i18n::msg(&bundle, "consent.allow", "Allow");
    let deny = crate::i18n::msg(&bundle, "consent.deny", "Deny");
    let banner = error_banner(entry.error.as_deref());
    let action = continuation_url(realm_name, execution);
    let body = format!(
        "<h1>{title}</h1>\
         <p><strong>{}</strong> {}</p>\
         <ul>{items}</ul>\
         {banner}\
         <form method=\"post\" action=\"{action}\">\
         <button type=\"submit\" name=\"decision\" value=\"allow\">{allow}</button>\
         <button type=\"submit\" name=\"decision\" value=\"deny\" class=\"secondary\">{deny}</button>\
         </form>",
        html_escape(client_display),
        html_escape(&lead),
    );
    page(&title, &body).into_response()
}

/// `POST /realms/{realm}/login/consent/{execution}` — apply the decision.
pub async fn consent_submit(
    State(state): State<Arc<ServerState>>,
    Path((realm_name, execution)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Login-CSRF: the correlation cookie minted by `begin_consent` must be
    // present (same model as the required-action POST).
    if !has_flow_cookie(&headers, &execution) {
        return error_response(StatusCode::FORBIDDEN, "missing flow correlation cookie");
    }

    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::NOT_FOUND, "realm not found"),
    };
    let realm_id = realm.id.clone();

    // Consume the entry atomically so a double-submit cannot complete twice.
    let key = pending_consent_cache_key(&realm_id, &execution);
    let mut entry: PendingConsentData = match state.cache.get_and_delete(&key).await {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid consent state");
            }
        },
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "consent request expired — please restart the login",
            );
        }
    };

    let form: std::collections::HashMap<String, String> =
        serde_urlencoded::from_bytes(&body).unwrap_or_default();

    if form.get("decision").map(String::as_str) != Some("allow") {
        // Denial: per OIDC Core the error returns to the (already validated)
        // registered redirect URI, packaged per the requested response_mode.
        info!(realm = %realm_id, client_id = %entry.pending.client_id, "user denied consent");
        return super::auth_response::oauth_error_redirect(
            &state,
            &entry.pending.redirect_uri,
            &issuerd_core::IssuerdError::AccessDenied,
            entry.pending.state.as_deref(),
            &super::auth_response::ResponsePackaging::from_pending(&realm, &entry.pending),
        )
        .await;
    }

    // Approval: persist the grant (upsert), then resume the paused login. The
    // Consent record keys on the client's INTERNAL id.
    let (_user, client) = match load_user_and_client(&state, &realm_id, &entry).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let user_id = match UserId::new(entry.user_id.clone()) {
        Ok(id) => id,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid user"),
    };
    let now = chrono::Utc::now();
    let consent = issuerd_core::Consent {
        client_id: client.id.clone(),
        user_id,
        granted_scopes: issuerd_core::Scope::parse(&entry.pending.scope.join(" ")),
        granted_realm_roles: Vec::new(),
        granted_client_roles: std::collections::HashMap::new(),
        created_at: now,
        last_updated_at: now,
    };
    if let Err(e) = state.storage.create_consent(&realm_id, &consent).await {
        error!(realm = %realm_id, error = %e, "failed to persist consent grant");
        entry.error = Some("could not record your choice — please try again".to_string());
        store_entry(&state, &realm_id, &execution, &entry).await;
        return axum::response::Redirect::to(&continuation_url(&realm_name, &execution))
            .into_response();
    }

    info!(realm = %realm_id, client_id = %client.client_id, user_id = %consent.user_id, "user granted consent");
    resume_after_consent(&state, &realm, entry).await
}

/// Continue the paused login after an approved grant. The stored consent now
/// covers the scope set, and `prompt_consent` is cleared so the gate in
/// `complete_login_with_method` / the SSO branch passes.
async fn resume_after_consent(
    state: &Arc<ServerState>,
    realm: &Realm,
    mut entry: PendingConsentData,
) -> Response {
    entry.pending.prompt_consent = false;
    let realm_id = realm.id.clone();
    let (user_id, session_id) =
        match (UserId::new(entry.user_id.clone()), SessionId::new(entry.session_id.clone())) {
            (Ok(u), Ok(s)) => (u, s),
            _ => return error_response(StatusCode::BAD_REQUEST, "invalid consent state"),
        };

    if !entry.sso_resume {
        return super::login_api::complete_login_with_method(
            state,
            &realm_id,
            &entry.pending,
            &user_id,
            &session_id,
            entry.result_auth_time,
            entry.is_browser_form,
            entry.auth_method,
            &entry.method_label,
        )
        .await;
    }

    // SSO resume: merge into the (possibly still live) SSO session. If the
    // session expired while the user was deciding, `finish_sso_login` simply
    // creates a fresh one.
    let (user, client) = match load_user_and_client(state, &realm_id, &entry).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let existing = state.storage.get_user_session(&realm_id, &session_id).await.ok().flatten();
    super::oidc::finish_sso_login(
        state,
        realm,
        &client,
        &user,
        &entry.pending,
        existing,
        &session_id,
        entry.result_auth_time,
        entry.auth_time,
        entry.pending.ip_address.unwrap_or("127.0.0.1".parse().unwrap()),
        false,
    )
    .await
}

async fn load_user_and_client(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    entry: &PendingConsentData,
) -> Result<(User, Client), Response> {
    let user_id = match UserId::new(entry.user_id.clone()) {
        Ok(id) => id,
        Err(_) => return Err(error_response(StatusCode::BAD_REQUEST, "invalid user")),
    };
    let user = match state.storage.get_user(realm_id, &user_id).await {
        Ok(Some(u)) => u,
        _ => return Err(error_response(StatusCode::BAD_REQUEST, "invalid user")),
    };
    let identifier = match issuerd_core::ClientIdentifier::new(&entry.pending.client_id) {
        Ok(id) => id,
        Err(_) => return Err(error_response(StatusCode::BAD_REQUEST, "invalid client")),
    };
    let client = match state.storage.get_client_by_client_id(realm_id, &identifier).await {
        Ok(Some(c)) => c,
        _ => return Err(error_response(StatusCode::BAD_REQUEST, "unknown client")),
    };
    Ok((user, client))
}
