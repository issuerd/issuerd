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
use super::required_actions::{error_banner, error_response, page, url_path_segment, PageCopy};

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
    let cookie = flow_cookie_header(&execution, state.config.secure_cookies());
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
#[allow(clippy::result_large_err)]
async fn load_consent_context(
    state: &Arc<ServerState>,
    realm_name: &str,
    execution: &str,
    accept_language: Option<&str>,
) -> Result<(Realm, PendingConsentData, Client), Response> {
    let realm = match state.resolve_realm(realm_name).await {
        Ok(Some(r)) => r,
        _ => {
            let copy = PageCopy::fallback(state);
            return Err(error_response(
                &copy,
                StatusCode::NOT_FOUND,
                &copy.msg("consent.error.realmNotFound", "realm not found"),
            ));
        }
    };
    let key = pending_consent_cache_key(&realm.id, execution);
    let entry: PendingConsentData = match state.cache.get(&key).await {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(_) => {
                let copy = PageCopy::for_realm(state, &realm, None, accept_language);
                return Err(error_response(
                    &copy,
                    StatusCode::BAD_REQUEST,
                    &copy.msg("consent.error.invalidState", "invalid consent state"),
                ));
            }
        },
        _ => {
            let copy = PageCopy::for_realm(state, &realm, None, accept_language);
            return Err(error_response(
                &copy,
                StatusCode::BAD_REQUEST,
                &copy.msg(
                    "consent.error.expired",
                    "consent request expired — please restart the login",
                ),
            ));
        }
    };
    let identifier = match issuerd_core::ClientIdentifier::new(&entry.pending.client_id) {
        Ok(id) => id,
        Err(_) => {
            let copy = PageCopy::for_realm(state, &realm, entry.pending.locale.as_deref(), None);
            return Err(error_response(
                &copy,
                StatusCode::BAD_REQUEST,
                &copy.msg("consent.error.invalidClient", "invalid client"),
            ));
        }
    };
    let client = match state.storage.get_client_by_client_id(&realm.id, &identifier).await {
        Ok(Some(c)) => c,
        _ => {
            let copy = PageCopy::for_realm(state, &realm, entry.pending.locale.as_deref(), None);
            return Err(error_response(
                &copy,
                StatusCode::BAD_REQUEST,
                &copy.msg("consent.error.unknownClient", "unknown client"),
            ));
        }
    };
    Ok((realm, entry, client))
}

/// `GET /realms/{realm}/login/consent/{execution}` — render the consent page.
pub async fn consent_page(
    State(state): State<Arc<ServerState>>,
    Path((realm_name, execution)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let (realm, entry, client) = match load_consent_context(
        &state,
        &realm_name,
        &execution,
        super::required_actions::accept_language(&headers),
    )
    .await
    {
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
    page(&title, &body, &locale).into_response()
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
        let copy = PageCopy::fallback(&state);
        return error_response(
            &copy,
            StatusCode::FORBIDDEN,
            &copy.msg("consent.error.missingFlowCookie", "missing flow correlation cookie"),
        );
    }

    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => {
            let copy = PageCopy::fallback(&state);
            return error_response(
                &copy,
                StatusCode::NOT_FOUND,
                &copy.msg("consent.error.realmNotFound", "realm not found"),
            );
        }
    };
    let realm_id = realm.id.clone();

    // Consume the entry atomically so a double-submit cannot complete twice.
    let key = pending_consent_cache_key(&realm_id, &execution);
    let mut entry: PendingConsentData = match state.cache.get_and_delete(&key).await {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(_) => {
                let copy = PageCopy::for_realm(&state, &realm, None, None);
                return error_response(
                    &copy,
                    StatusCode::BAD_REQUEST,
                    &copy.msg("consent.error.invalidState", "invalid consent state"),
                );
            }
        },
        _ => {
            let copy = PageCopy::for_realm(&state, &realm, None, None);
            return error_response(
                &copy,
                StatusCode::BAD_REQUEST,
                &copy.msg(
                    "consent.error.expired",
                    "consent request expired — please restart the login",
                ),
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
    let copy = PageCopy::for_realm(
        &state,
        &realm,
        entry.pending.locale.as_deref(),
        super::required_actions::accept_language(&headers),
    );
    let (_user, client) = match load_user_and_client(&state, &realm_id, &entry, &copy).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let user_id = match UserId::new(entry.user_id.clone()) {
        Ok(id) => id,
        Err(_) => {
            return error_response(
                &copy,
                StatusCode::BAD_REQUEST,
                &copy.msg("consent.error.invalidUser", "invalid user"),
            )
        }
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
        entry.error =
            Some(copy.msg(
                "consent.error.persistFailed",
                "could not record your choice — please try again",
            ));
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
    let copy = PageCopy::for_realm(state, realm, entry.pending.locale.as_deref(), None);
    let (user_id, session_id) =
        match (UserId::new(entry.user_id.clone()), SessionId::new(entry.session_id.clone())) {
            (Ok(u), Ok(s)) => (u, s),
            _ => {
                return error_response(
                    &copy,
                    StatusCode::BAD_REQUEST,
                    &copy.msg("consent.error.invalidState", "invalid consent state"),
                )
            }
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
    let (user, client) = match load_user_and_client(state, &realm_id, &entry, &copy).await {
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

#[allow(clippy::result_large_err)]
async fn load_user_and_client(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    entry: &PendingConsentData,
    copy: &PageCopy,
) -> Result<(User, Client), Response> {
    let user_id = match UserId::new(entry.user_id.clone()) {
        Ok(id) => id,
        Err(_) => {
            return Err(error_response(
                copy,
                StatusCode::BAD_REQUEST,
                &copy.msg("consent.error.invalidUser", "invalid user"),
            ))
        }
    };
    let user = match state.storage.get_user(realm_id, &user_id).await {
        Ok(Some(u)) => u,
        _ => {
            return Err(error_response(
                copy,
                StatusCode::BAD_REQUEST,
                &copy.msg("consent.error.invalidUser", "invalid user"),
            ))
        }
    };
    let identifier = match issuerd_core::ClientIdentifier::new(&entry.pending.client_id) {
        Ok(id) => id,
        Err(_) => {
            return Err(error_response(
                copy,
                StatusCode::BAD_REQUEST,
                &copy.msg("consent.error.invalidClient", "invalid client"),
            ))
        }
    };
    let client = match state.storage.get_client_by_client_id(realm_id, &identifier).await {
        Ok(Some(c)) => c,
        _ => {
            return Err(error_response(
                copy,
                StatusCode::BAD_REQUEST,
                &copy.msg("consent.error.unknownClient", "unknown client"),
            ))
        }
    };
    Ok((user, client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use issuerd_core::{
        ClientAuthenticatorType, ClientId, ClientIdentifier, ClientProtocol, Consent, RoleName,
        Scope,
    };
    use std::collections::HashMap;

    async fn setup() -> (Arc<ServerState>, RealmId, UserId) {
        let state = Arc::new(ServerState::from_config(&ServerConfig::default()).await.unwrap());
        (state, RealmId::new("master").unwrap(), UserId::new("admin").unwrap())
    }

    /// The built-in admin-cli client (`consent_required = false`).
    async fn admin_cli(state: &Arc<ServerState>, realm_id: &RealmId) -> Client {
        state
            .storage
            .get_client_by_client_id(realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap()
    }

    /// A fresh client with `consent_required = true`.
    async fn consenting_client(state: &Arc<ServerState>, realm_id: &RealmId) -> Client {
        let client = Client {
            id: ClientId::new("consent-client-uuid").unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new("consent-client").unwrap(),
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
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: true,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        state.storage.create_client(realm_id, &client).await.unwrap();
        client
    }

    #[tokio::test]
    async fn no_consent_when_client_does_not_require_it() {
        let (state, realm_id, user_id) = setup().await;
        let client = admin_cli(&state, &realm_id).await;
        assert!(
            !consent_needed(&state, &realm_id, &client, &user_id, &["openid".to_string()], false)
                .await,
            "a client without consent_required must never pause for consent"
        );
    }

    #[tokio::test]
    async fn prompt_consent_forces_the_screen() {
        let (state, realm_id, user_id) = setup().await;
        let client = admin_cli(&state, &realm_id).await;
        assert!(
            consent_needed(&state, &realm_id, &client, &user_id, &["openid".to_string()], true)
                .await,
            "prompt=consent forces the page regardless of client settings or stored grants"
        );
    }

    #[tokio::test]
    async fn consent_required_client_without_grant_needs_consent() {
        let (state, realm_id, user_id) = setup().await;
        let client = consenting_client(&state, &realm_id).await;
        assert!(
            consent_needed(&state, &realm_id, &client, &user_id, &["openid".to_string()], false)
                .await,
            "no stored grant -> consent page"
        );
    }

    #[tokio::test]
    async fn stored_grant_skips_consent_only_when_covering_requested_scopes() {
        let (state, realm_id, user_id) = setup().await;
        let client = consenting_client(&state, &realm_id).await;
        let consent = Consent {
            client_id: client.id.clone(),
            user_id: user_id.clone(),
            granted_scopes: Scope::parse("openid profile"),
            granted_realm_roles: Vec::<RoleName>::new(),
            granted_client_roles: HashMap::new(),
            created_at: chrono::Utc::now(),
            last_updated_at: chrono::Utc::now(),
        };
        state.storage.create_consent(&realm_id, &consent).await.unwrap();

        // Covered set -> skip the page.
        assert!(
            !consent_needed(&state, &realm_id, &client, &user_id, &["openid".to_string()], false)
                .await,
            "a stored grant covering the requested scopes skips the page"
        );
        // Anything beyond the grant -> page again.
        assert!(
            consent_needed(
                &state,
                &realm_id,
                &client,
                &user_id,
                &["openid".to_string(), "email".to_string()],
                false
            )
            .await,
            "a scope outside the stored grant re-triggers the page"
        );
    }

    // -----------------------------------------------------------------------
    // Continuation state: cache-key schema, page rendering, submit handling.
    // -----------------------------------------------------------------------

    fn test_pending_auth(client_id: &str, redirect_uri: &str, scope: &[&str]) -> PendingAuthData {
        PendingAuthData {
            realm_id: "master".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.iter().map(|s| s.to_string()).collect(),
            state: Some("state-xyz".to_string()),
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            execution_id: issuerd_core::FlowStageId::new("username-password").unwrap(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "challenged".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: true,
            locale: None,
            response_mode: None,
            authorization_details: None,
        }
    }

    fn consent_entry(pending: PendingAuthData) -> PendingConsentData {
        PendingConsentData {
            pending,
            user_id: "admin".to_string(),
            session_id: issuerd_core::utils::generate_id(),
            // Distinct timestamps: the non-SSO resume must stamp the session
            // with the flow-result time, not the SSO-preserved auth_time.
            result_auth_time: chrono::Utc::now() - chrono::Duration::hours(1),
            auth_time: chrono::Utc::now(),
            is_browser_form: true,
            sso_resume: false,
            auth_method: AuthMethod::Spnego,
            method_label: "password".to_string(),
            error: None,
            _typestate_tag: consent_tag(),
        }
    }

    /// Seed the pending-consent entry under its cache key; returns the key.
    async fn seed_entry(
        state: &Arc<ServerState>,
        execution: &str,
        entry: &PendingConsentData,
    ) -> String {
        let key = pending_consent_cache_key(&RealmId::new("master").unwrap(), execution);
        state
            .cache
            .set(&key, serde_json::to_vec(entry).unwrap(), Some(Duration::from_secs(600)))
            .await
            .unwrap();
        key
    }

    fn cookie_headers(state: &Arc<ServerState>, execution: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let cookie = flow_cookie_header(execution, state.config.secure_cookies());
        headers.insert(axum::http::header::COOKIE, cookie.parse().unwrap());
        headers
    }

    /// The consent-required test client: display name for the page, a
    /// registered redirect URI for the submit paths.
    fn named_client_model(realm_id: &RealmId) -> Client {
        Client {
            id: ClientId::new("named-client-uuid").unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new("named-client").unwrap(),
            name: Some(issuerd_core::DisplayName::new("My App").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: true,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![issuerd_core::RedirectUri::new(
                "https://app.example.com/callback".to_string(),
            )
            .unwrap()],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: true,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    async fn named_client(state: &Arc<ServerState>, realm_id: &RealmId) -> Client {
        let client = named_client_model(realm_id);
        state.storage.create_client(realm_id, &client).await.unwrap();
        client
    }

    fn admin_user_model(realm_id: &RealmId) -> User {
        User {
            id: UserId::new("admin").unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new("admin").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    async fn seed_scope(
        state: &Arc<ServerState>,
        realm_id: &RealmId,
        name: &str,
        description: Option<&str>,
    ) {
        let scope = issuerd_core::ClientScope {
            id: issuerd_core::ClientScopeId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            name: name.to_string(),
            description: description.map(str::to_string),
            protocol: ClientProtocol::OpenIdConnect,
            attributes: HashMap::new(),
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
        };
        state.storage.create_client_scope(realm_id, &scope).await.unwrap();
    }

    #[test]
    fn pending_consent_cache_key_scopes_realm_and_execution() {
        let realm = RealmId::new("master").unwrap();
        assert_eq!(pending_consent_cache_key(&realm, "exec-1"), "pending_consent:master:exec-1");
        assert_ne!(
            pending_consent_cache_key(&realm, "exec-1"),
            pending_consent_cache_key(&RealmId::new("other").unwrap(), "exec-1")
        );
        assert_ne!(
            pending_consent_cache_key(&realm, "exec-1"),
            pending_consent_cache_key(&realm, "exec-2")
        );
    }

    #[test]
    fn consent_tag_is_the_stable_typestate_marker() {
        assert_eq!(consent_tag(), "consent");
        // Entries written before the tag field existed still deserialize,
        // tagged as consent entries by the serde default.
        let entry = consent_entry(test_pending_auth(
            "named-client",
            "https://app.example.com/callback",
            &["openid"],
        ));
        let mut json = serde_json::to_value(&entry).unwrap();
        json.as_object_mut().unwrap().remove("_typestate_tag");
        let parsed: PendingConsentData = serde_json::from_value(json).unwrap();
        assert_eq!(parsed._typestate_tag, "consent");
    }

    #[test]
    fn continuation_url_points_at_the_consent_endpoint() {
        assert_eq!(continuation_url("master", "exec-1"), "/realms/master/login/consent/exec-1");
    }

    #[tokio::test]
    async fn begin_consent_redirects_browser_and_stores_entry() {
        let (state, realm_id, _user_id) = setup().await;
        let entry = consent_entry(test_pending_auth(
            "named-client",
            "https://app.example.com/callback",
            &["openid"],
        ));
        let resp = begin_consent(&state, "master", entry.clone()).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers()["location"].to_str().unwrap();
        let prefix = "/realms/master/login/consent/";
        assert!(location.starts_with(prefix), "location: {location}");
        let execution = &location[prefix.len()..];
        let set_cookie = resp.headers()["set-cookie"].to_str().unwrap();
        assert!(
            set_cookie.contains(&format!("issuerd_flow_{execution}=1")),
            "cookie: {set_cookie}"
        );

        // The paused login waits in the cache under the execution key.
        let bytes = state
            .cache
            .get(&pending_consent_cache_key(&realm_id, execution))
            .await
            .unwrap()
            .expect("pending consent entry");
        let stored: PendingConsentData = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(stored.user_id, entry.user_id);
        assert_eq!(stored.pending.client_id, "named-client");
    }

    #[tokio::test]
    async fn consent_page_renders_client_name_and_scope_labels() {
        let (state, realm_id, _user_id) = setup().await;
        named_client(&state, &realm_id).await;
        // A scope with a real description renders "name — description"; a
        // whitespace-only description falls back to the bare scope name.
        seed_scope(&state, &realm_id, "read:files", Some("Read your files")).await;
        seed_scope(&state, &realm_id, "reports", Some("   ")).await;

        let execution = "exec-page";
        let entry = consent_entry(test_pending_auth(
            "named-client",
            "https://app.example.com/callback",
            &["openid", "read:files", "reports"],
        ));
        seed_entry(&state, execution, &entry).await;

        let resp = consent_page(
            State(state.clone()),
            Path(("master".to_string(), execution.to_string())),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("<strong>My App</strong>"), "body: {body}");
        assert!(body.contains("<li>read:files — Read your files</li>"), "body: {body}");
        assert!(body.contains("<li>reports</li>"), "body: {body}");
        assert!(!body.contains("reports —"), "body: {body}");
        assert!(
            body.contains("action=\"/realms/master/login/consent/exec-page\""),
            "body: {body}"
        );
        assert!(body.contains("Grant access"), "body: {body}");
    }

    #[tokio::test]
    async fn consent_submit_without_flow_cookie_is_forbidden() {
        let (state, _realm_id, _user_id) = setup().await;
        let resp = consent_submit(
            State(state),
            Path(("master".to_string(), "exec-1".to_string())),
            HeaderMap::new(),
            Bytes::from_static(b"decision=allow"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn consent_submit_denial_redirects_access_denied_and_consumes_entry() {
        let (state, realm_id, user_id) = setup().await;
        named_client(&state, &realm_id).await;
        let execution = "exec-deny";
        let entry = consent_entry(test_pending_auth(
            "named-client",
            "https://app.example.com/callback",
            &["openid"],
        ));
        let key = seed_entry(&state, execution, &entry).await;

        let resp = consent_submit(
            State(state.clone()),
            Path(("master".to_string(), execution.to_string())),
            cookie_headers(&state, execution),
            Bytes::from_static(b"decision=deny"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers()["location"].to_str().unwrap();
        assert!(
            location.starts_with("https://app.example.com/callback?"),
            "location: {location}"
        );
        assert!(location.contains("error=access_denied"), "location: {location}");
        assert!(location.contains("state=state-xyz"), "location: {location}");

        // No grant is persisted, and the entry is consumed (single-submit).
        assert!(state.storage.get_consents(&realm_id, &user_id).await.unwrap().is_empty());
        assert!(state.cache.get(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn consent_submit_approval_persists_grant_and_resumes_login() {
        let (state, realm_id, user_id) = setup().await;
        let client = named_client(&state, &realm_id).await;
        let execution = "exec-allow";
        let entry = consent_entry(test_pending_auth(
            "named-client",
            "https://app.example.com/callback",
            &["openid"],
        ));
        let session_id = entry.session_id.clone();
        let result_auth_time = entry.result_auth_time;
        let key = seed_entry(&state, execution, &entry).await;

        let resp = consent_submit(
            State(state.clone()),
            Path(("master".to_string(), execution.to_string())),
            cookie_headers(&state, execution),
            Bytes::from_static(b"decision=allow"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers()["location"].to_str().unwrap();
        assert!(
            location.starts_with("https://app.example.com/callback?"),
            "location: {location}"
        );
        assert!(location.contains("code="), "location: {location}");
        assert!(location.contains("state=state-xyz"), "location: {location}");

        // The grant is persisted, keyed on the client's internal id.
        let consents = state.storage.get_consents(&realm_id, &user_id).await.unwrap();
        assert_eq!(consents.len(), 1);
        assert_eq!(consents[0].client_id, client.id);
        assert!(consents[0].granted_scopes.contains("openid"));

        // The login resumed on the non-SSO path: a fresh session stamped with
        // the flow-result time and the entry's auth method.
        let session = state
            .storage
            .get_user_session(&realm_id, &SessionId::new(session_id).unwrap())
            .await
            .unwrap()
            .expect("resumed session");
        assert_eq!(session.auth_method, AuthMethod::Spnego);
        assert_eq!(session.auth_time, result_auth_time);

        // Single-submit: the entry is gone.
        assert!(state.cache.get(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn consent_submit_restores_entry_and_redirects_when_grant_persist_fails() {
        let realm_id = RealmId::new("master").unwrap();
        let realm = Realm {
            id: realm_id.clone(),
            name: issuerd_core::RealmName::new("master").unwrap(),
            display_name: None,
            enabled: true,
            ..Default::default()
        };
        let user = admin_user_model(&realm_id);
        let client = named_client_model(&realm_id);

        let mut storage = issuerd_core::MockStorage::new();
        storage
            .expect_get_realm_by_name()
            .returning(move |name| Ok((name == "master").then(|| realm.clone())));
        storage.expect_get_user().returning(move |_, _| Ok(Some(user.clone())));
        storage
            .expect_get_client_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        storage
            .expect_create_consent()
            .returning(|_, _| Err(issuerd_core::IssuerdError::ServerError("db down".to_string())));

        let mut state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        state.storage = Arc::new(storage);
        let state = Arc::new(state);

        let execution = "exec-persist-fail";
        let entry = consent_entry(test_pending_auth(
            "named-client",
            "https://app.example.com/callback",
            &["openid"],
        ));
        let key = seed_entry(&state, execution, &entry).await;

        let resp = consent_submit(
            State(state.clone()),
            Path(("master".to_string(), execution.to_string())),
            cookie_headers(&state, execution),
            Bytes::from_static(b"decision=allow"),
        )
        .await;
        // PRG: back to the consent page, with the entry (and the one-shot
        // error banner) restored for the retry.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()["location"].to_str().unwrap(),
            format!("/realms/master/login/consent/{execution}")
        );
        let bytes = state.cache.get(&key).await.unwrap().expect("entry restored after failure");
        let restored: PendingConsentData = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            restored.error.as_deref(),
            Some("could not record your choice — please try again")
        );
    }
}
