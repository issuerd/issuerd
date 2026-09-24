// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OIDC/OAuth2 protocol endpoints: authorize, token, discovery, userinfo, logout, device, CIBA.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use issuerd_auth_flow::typestate::FlowOutput;
use issuerd_core::{
    AccessTokenClaims, AuthMethod, Challenge, ClientIdentifier, EventType, FlowStageId,
    IssuerdError, PkceCodeChallengeMethod, Realm, RealmId, SessionId, UserId, Username,
};
use issuerd_protocol::{
    authorization::{AuthorizationRequest, Prompt, ResponseMode, ResponseType},
    device::{DeviceAuthorizationRequest, DeviceAuthorizationResponse},
    discovery::DiscoveryResponse,
    introspection::{IntrospectionRequest, RevocationRequest},
    token::{GrantType, TokenRequest},
};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    middleware::{proxy_ip::ClientIp, realm::ResolvedRealm},
    state::{default_browser_flow, ServerState},
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn emit_oidc_event(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    event_type: issuerd_core::EventType,
    ip: &std::net::IpAddr,
    client_id: Option<issuerd_core::ClientId>,
    user_id: Option<issuerd_core::UserId>,
    session_id: Option<issuerd_core::SessionId>,
    error: Option<String>,
    details: std::collections::HashMap<String, String>,
) {
    // Realm event gating: events are only recorded when the realm has
    // `events_enabled` (Issuerd default: on — Keycloak parity break; Keycloak
    // defaults to off). A realm re-read failure fails
    // OPEN — the event is still written; an outage of the realm table must
    // not blind the audit trail — but listener dispatch is skipped because
    // the realm's listener list is then unknown.
    let realm = match state.storage.get_realm(realm_id).await {
        Ok(realm) => realm,
        Err(e) => {
            warn!(realm = %realm_id, error = %e, "event gating: realm reload failed; recording event anyway");
            None
        }
    };
    if realm.as_ref().is_some_and(|r| !r.events_enabled) {
        return;
    }
    let event = issuerd_core::Event {
        id: issuerd_core::EventId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm_id.clone(),
        event_time: chrono::Utc::now(),
        event_type,
        ip_address: Some(*ip),
        client_id,
        user_id,
        session_id,
        error,
        details,
    };
    if let Err(e) = state.storage.save_event(realm_id, &event).await {
        warn!(realm = %realm_id, error = %e, "audit event write failed");
    }
    if let Some(realm) = realm {
        for name in &realm.events_listeners {
            match state.event_listeners.get(name) {
                Some(listener) => {
                    if let Err(e) = listener.on_event(&event).await {
                        warn!(realm = %realm_id, listener = %name, error = %e, "event listener dispatch failed");
                    }
                }
                None => {
                    warn!(realm = %realm_id, listener = %name, "unknown event listener ignored")
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery & JWKS
// ---------------------------------------------------------------------------

pub async fn discovery_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
) -> Response {
    let realm_name = realm.unwrap_or_else(|| "master".to_string());
    // Tokens are issued with `iss = {issuer_url}/realms/{realm.name}` (see
    // TokenManager::issuer_for_realm), so discovery must advertise the same
    // issuer.
    match state.resolve_realm(&realm_name).await {
        Ok(Some(realm)) => {
            // Pre-rendered body cache: the document is a pure function of
            // the realm row + the active signing-key set (see
            // `discovery_cache`); validated per request, so realm edits and
            // key rotations take effect immediately.
            let keyset_gen = state.keyset_generation.load(std::sync::atomic::Ordering::Relaxed);
            if let Some(body) = crate::discovery_cache::read(&state, &realm, keyset_gen).await {
                return raw_json_response(body);
            }
            let mut discovery =
                DiscoveryResponse::for_realm(&state.config.issuer_url, realm.name.as_str());
            // RFC 9126 §5: advertise the realm's PAR policy (default false).
            discovery.require_pushed_authorization_requests =
                crate::routes::par::realm_requires_par(&realm);
            // RFC 9396 §10: advertise the realm's supported
            // authorization-details types when the deployment pins them via
            // the `authorization_details_types` attribute. Unset = generic
            // mode (any type accepted) and the metadata stays omitted.
            if let Some(types) = realm.authorization_details_types() {
                discovery.authorization_details_types_supported = types;
            }
            // RFC 7591 §3: the registration endpoint is
            // advertised only for realms that opted in via the
            // `dynamic_client_registration_enabled` attribute.
            if realm.dynamic_client_registration_enabled() {
                discovery.registration_endpoint = Some(
                    url::Url::parse(&format!(
                        "{}/clients-registrations/openid-connect",
                        discovery.issuer
                    ))
                    .unwrap(),
                );
            }
            // Advertise exactly the algorithms of the active
            // (server-global) signing keys. Any of them may sign this realm's
            // tokens depending on its `default_signature_algorithm` attribute.
            match state.crypto.active_signing_algorithms().await {
                Ok(algs) if !algs.is_empty() => {
                    discovery.id_token_signing_alg_values_supported = algs.clone();
                    // JARM responses sign with the same key set.
                    discovery.authorization_signing_alg_values_supported = algs;
                }
                _ => {}
            }
            match serde_json::to_vec(&discovery) {
                Ok(body) => {
                    crate::discovery_cache::write(&state, &realm, keyset_gen, &body).await;
                    raw_json_response(body)
                }
                Err(e) => {
                    error!(realm = %realm.id, error = %e, "discovery serialization failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "serialization_failed"})),
                    )
                        .into_response()
                }
            }
        }
        _ => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "realm_not_found"})))
            .into_response(),
    }
}

pub async fn certs_handler(State(state): State<Arc<ServerState>>) -> Response {
    match state.crypto.get_public_keys().await {
        Ok(jwks) => Json(jwks).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

fn default_anonymous_tag() -> String {
    "anonymous".to_string()
}

/// Cache key for a pending (in-flight) browser login flow.
///
/// Keyed by realm id and a cryptographically random per-flow id so concurrent
/// logins — in the same realm or across realms — can never share a slot.
pub(crate) fn pending_auth_cache_key(realm_id: &RealmId, flow_id: &str) -> String {
    format!("pending_auth:{}:{}", realm_id.0, flow_id)
}

/// Name of the correlation cookie that binds a pending login flow to the
/// browser that started it. One cookie per flow keeps multi-tab logins working.
pub(crate) fn flow_cookie_name(flow_id: &str) -> String {
    format!("issuerd_flow_{flow_id}")
}

/// `Set-Cookie` value for the flow correlation cookie (matches the pending
/// entry's 10-minute TTL). `secure` appends the `Secure` attribute — pass
/// [`crate::config::ServerConfig::secure_cookies`] so TLS deployments get it
/// while plain-HTTP development rigs keep working.
///
/// Deliberately NOT renamed to a `__Host-` prefix: that would harden against
/// cookie injection from sibling domains, but renaming any cookie breaks
/// in-flight login flows on upgrade unless a compat read path accepts both
/// names — deferred as follow-up work (same conclusion for the SSO and
/// remember-me cookies).
pub(crate) fn flow_cookie_header(flow_id: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{}=1; Path=/; HttpOnly; SameSite=Lax; Max-Age=600{secure_attr}",
        flow_cookie_name(flow_id)
    )
}

/// Check whether the request carries the correlation cookie for `flow_id`.
pub(crate) fn has_flow_cookie(headers: &axum::http::HeaderMap, flow_id: &str) -> bool {
    let name = flow_cookie_name(flow_id);
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|h| h.split(';'))
        .any(|cookie| cookie.trim().split_once('=').is_some_and(|(n, _)| n == name))
}

/// Name of the per-realm SSO session cookie. Realm-ID scoped (UUIDs are
/// always cookie-name safe), so logging into one realm no longer clobbers
/// another realm's SSO session. Reads fall back to the legacy single
/// `issuerd_session` name for cookies minted before the switch.
pub(crate) fn session_cookie_name(realm_id: &RealmId) -> String {
    format!("issuerd_session_{realm_id}")
}

/// Name of the per-realm remember-me cookie (see [`session_cookie_name`]).
pub(crate) fn remember_cookie_name(realm_id: &RealmId) -> String {
    format!("issuerd_remember_{realm_id}")
}

/// Look up a realm-scoped cookie value: the per-realm name first, then the
/// legacy single-name variant used before the switch.
pub(crate) fn find_realm_cookie(
    headers: &axum::http::HeaderMap,
    realm_id: &RealmId,
    legacy_name: &str,
) -> Option<String> {
    let per_realm = format!("{legacy_name}_{realm_id}");
    let mut legacy = None;
    for cookie in headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|h| h.split(';'))
    {
        let Some((name, value)) = cookie.trim().split_once('=') else {
            continue;
        };
        if name == per_realm {
            return Some(value.to_string());
        }
        if name == legacy_name {
            legacy = Some(value.to_string());
        }
    }
    legacy
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingAuthData {
    pub realm_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<issuerd_core::Nonce>,
    pub response_type: String,
    pub code_challenge: Option<issuerd_core::Base64Url>,
    pub code_challenge_method: Option<issuerd_core::PkceCodeChallengeMethod>,
    pub ip_address: Option<std::net::IpAddr>,
    pub execution_id: FlowStageId,
    pub acr_values: Vec<String>,
    pub claims: Option<serde_json::Value>,
    #[serde(default = "default_anonymous_tag")]
    pub _typestate_tag: String,
    /// Number of failed login attempts for this pending auth flow. Used to
    /// break redirect loops when the same error repeats.
    #[serde(default)]
    pub attempt_count: u8,
    /// Remember-me checkbox state captured at the login POST (already ANDed
    /// with the realm toggle), or the remember-cookie provenance flag on the
    /// SSO re-authentication path.
    #[serde(default)]
    pub remember_me: bool,
    /// User bound to the paused flow when a second-factor challenge pauses
    /// AFTER a successful first factor. `None` while the flow is
    /// still anonymous (initial login-form challenge).
    #[serde(default)]
    pub user_id: Option<String>,
    /// `prompt=consent` from the original authorization request:
    /// forces the consent page even when a stored grant already covers the
    /// requested scopes.
    #[serde(default)]
    pub prompt_consent: bool,
    /// UI locale resolved from `ui_locales` / `Accept-Language` / the realm
    /// default at the start of the flow; `None` = not resolved
    /// (legacy cache entries, non-browser callers).
    #[serde(default)]
    pub locale: Option<String>,
    /// `response_mode` requested by the client; `None` = the
    /// spec default for the response type applies. Drives the final
    /// authorization-response packaging (query/fragment/form_post/JARM) on
    /// every continuation path.
    #[serde(default)]
    pub response_mode: Option<ResponseMode>,
    /// RAR authorization details granted by this authorization request (RFC
    /// 9396 §2); carried verbatim through every continuation into
    /// the authorization code.
    #[serde(default)]
    pub authorization_details: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthCodeData {
    pub user_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<issuerd_core::Nonce>,
    pub code_challenge: Option<issuerd_core::Base64Url>,
    pub code_challenge_method: Option<issuerd_core::PkceCodeChallengeMethod>,
    pub session_id: Option<String>,
    pub auth_time: Option<chrono::DateTime<chrono::Utc>>,
    pub acr_values: Vec<String>,
    pub claims: Option<serde_json::Value>,
    /// RAR authorization details attached to the grant.
    /// `#[serde(default)]` keeps codes minted before a rolling upgrade
    /// (auth-code TTL window) deserializable.
    #[serde(default)]
    pub authorization_details: Option<Vec<serde_json::Value>>,
}

impl AuthCodeData {
    /// Build from a paused/resumed login flow after successful authentication.
    pub(crate) fn from_pending(
        pending: &PendingAuthData,
        user_id: &issuerd_core::UserId,
        session_id: &issuerd_core::SessionId,
        auth_time: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            user_id: user_id.0.clone(),
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            scope: pending.scope.clone(),
            state: pending.state.clone(),
            nonce: pending.nonce.clone(),
            code_challenge: pending.code_challenge.clone(),
            code_challenge_method: pending.code_challenge_method,
            session_id: Some(session_id.0.clone()),
            auth_time: Some(auth_time),
            acr_values: pending.acr_values.clone(),
            claims: pending.claims.clone(),
            authorization_details: pending.authorization_details.clone(),
        }
    }
}

/// Persist an authorization code for the token endpoint (`auth_code:{code}`).
///
/// `ttl` is the code's redemption window — callers pass
/// [`crate::config::OAuthConfig::auth_code_ttl`] (`[oauth]
/// auth_code_ttl_secs`, optionally overridden per realm).
///
/// Fail-closed: the cache write must be confirmed before the code leaves the
/// server — a code that was never persisted can never be exchanged, so the
/// caller must surface the error instead of emitting the code.
pub(crate) async fn store_auth_code(
    cache: &Arc<dyn issuerd_core::DistributedCache>,
    code: &str,
    data: &AuthCodeData,
    ttl: std::time::Duration,
) -> Result<(), IssuerdError> {
    // Serialization cannot fail: every field is a plain String/Option/Vec.
    let value = serde_json::to_vec(data).unwrap();
    cache.set(&format!("auth_code:{code}"), value, Some(ttl)).await
}

/// Fail-closed surface for a failed [`store_auth_code`] write on the
/// redirect-based login paths: ERROR log plus `login_error` event, then
/// package `temporarily_unavailable` as an authorization error redirect
/// (RFC 6749 §4.1.2.1 — the redirect URI was validated when the flow
/// started). The authorization code is never emitted.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn auth_code_store_failure(
    state: &Arc<ServerState>,
    realm: &issuerd_core::Realm,
    client: &issuerd_core::Client,
    user_id: &issuerd_core::UserId,
    session_id: &issuerd_core::SessionId,
    ip: &std::net::IpAddr,
    pending: &PendingAuthData,
    error: &IssuerdError,
) -> Response {
    error!(realm = %realm.id, client_id = %client.client_id, error = %error, "failed to persist authorization code");
    let mut details = std::collections::HashMap::new();
    details.insert("error".to_string(), "temporarily_unavailable".to_string());
    emit_oidc_event(
        state,
        &realm.id,
        EventType::LoginError,
        ip,
        Some(client.id.clone()),
        Some(user_id.clone()),
        Some(session_id.clone()),
        Some("temporarily_unavailable".to_string()),
        details,
    )
    .await;
    crate::routes::auth_response::oauth_error_redirect(
        state,
        &pending.redirect_uri,
        &IssuerdError::TemporarilyUnavailable,
        pending.state.as_deref(),
        &crate::routes::auth_response::ResponsePackaging::from_pending(realm, pending),
    )
    .await
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UsedAuthCode {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix expiry of the issued access token — sizes the revocation TTL so
    /// the marker cannot expire before the token it invalidates.
    pub access_exp: u64,
    /// Unix expiry of the issued refresh token, if one was issued.
    pub refresh_exp: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceCodeData {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub realm_id: String,
    pub scope: Vec<String>,
    pub user_id: Option<String>,
    pub authorized: bool,
    pub last_polled_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Absolute expiry; polling must not extend it.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CibaAuthReqData {
    pub auth_req_id: String,
    pub client_id: String,
    pub realm_id: String,
    pub scope: Vec<String>,
    pub user_id: Option<String>,
    pub authorized: bool,
    pub denied: bool,
    pub binding_message: Option<String>,
    pub client_notification_token: Option<String>,
    pub last_polled_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Absolute expiry; polling/approval must not extend it.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Remaining TTL for a device/CIBA cache entry, or `None` once expired.
fn remaining_ttl(expires_at: chrono::DateTime<chrono::Utc>) -> Option<std::time::Duration> {
    (expires_at - chrono::Utc::now()).to_std().ok()
}

/// Registration-page counterpart of the login-page challenge redirect: when
/// the authorize request carries the `registration=true` hint and the realm
/// allows self-registration, the browser is sent to the registration form
/// with the paused flow's execution id instead of the login page. The
/// registration POST resumes the flow afterwards (see `registration.rs`).
fn register_challenge_location(realm_name: &str, flow_id: &str) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    ser.append_pair("execution_id", flow_id);
    format!("/realms/{realm_name}/login/register?{}", ser.finish())
}

/// Build a redirect URL appending parameters either in the query string or fragment.
pub(crate) fn build_redirect_url(
    base: &str,
    params: &[(&str, &str)],
    use_fragment: bool,
) -> String {
    let mut url = base.to_string();
    let mut pairs = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        pairs.append_pair(k, v);
    }
    let encoded = pairs.finish();
    if use_fragment {
        url.push('#');
        url.push_str(&encoded);
    } else if url.contains('?') {
        url.push('&');
        url.push_str(&encoded);
    } else {
        url.push('?');
        url.push_str(&encoded);
    }
    url
}

/// Try to look up the client and validate the redirect URI so we can redirect safely.
/// Per RFC 6749 §4.1.2.1, an error MUST NOT be redirected to a missing or
/// unregistered redirect_uri — and the OIDC conformance suite explicitly rejects
/// falling back to a default/registered redirect_uri in that case
/// (`oidcc-ensure-request-object-with-redirect-uri`), so we return `None` and let
/// the caller render an error page instead.
///
/// Even on this pre-parse error path an explicitly requested (and parseable)
/// `response_mode` is honored: a request missing `response_type`
/// but carrying `response_mode=form_post` gets its error POSTed to the client —
/// the Form Post OP conformance module (`oidcc-response-type-missing`) requires
/// exactly that. JARM works here too: the realm and the client's redirect_uri
/// are both validated by this point.
async fn try_auth_error_redirect(
    state: &Arc<ServerState>,
    realm_name: &str,
    params: &HashMap<String, String>,
    error: &IssuerdError,
) -> Option<Response> {
    let client_id = params.get("client_id")?;
    let redirect_uri = params.get("redirect_uri")?;
    let redirect_uri = redirect_uri.parse::<url::Url>().ok()?;
    let realm = state.resolve_realm(realm_name).await.ok()??;
    let client_identifier = match ClientIdentifier::new(client_id) {
        Ok(id) => id,
        Err(_) => return None,
    };
    let client = match state.storage.get_client_by_client_id(&realm.id, &client_identifier).await {
        Ok(Some(c)) => c,
        _ => return None,
    };
    if !client.redirect_uris.iter().any(|r| r.matches(redirect_uri.as_str())) {
        return None;
    }
    let requested_mode = params.get("response_mode").and_then(|s| s.parse::<ResponseMode>().ok());
    let default_fragment = params
        .get("response_type")
        .and_then(|s| s.parse::<ResponseType>().ok())
        .is_some_and(|rt| rt.has_id_token());
    let packaging = crate::routes::auth_response::ResponsePackaging {
        realm: &realm,
        client_id: client.client_id.as_str(),
        requested_mode,
        default_fragment,
    };
    Some(
        crate::routes::auth_response::oauth_error_redirect(
            state,
            redirect_uri.as_ref(),
            error,
            params.get("state").map(|s| s.as_str()),
            &packaging,
        )
        .await,
    )
}

/// Check whether the request appears to come from a browser (Accept: text/html).
pub(crate) fn wants_html(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html"))
        .unwrap_or(false)
}

async fn resolve_session_from_cookie(
    state: &Arc<ServerState>,
    headers: &axum::http::HeaderMap,
    realm: &issuerd_core::Realm,
) -> Option<issuerd_core::UserSession> {
    let realm_id = &realm.id;
    let cookie_value = find_realm_cookie(headers, realm_id, "issuerd_session")?;
    tracing::debug!("resolve_session_from_cookie: found issuerd_session cookie");

    let validated = match state.token_service.validate_access_token(&cookie_value) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, "resolve_session_from_cookie: token validation failed");
            return None;
        }
    };

    // Verify the cookie belongs to the requested realm. Issuers are
    // realm-NAME based, so compare against the realm name.
    let issuer_realm =
        issuerd_core::typestate::extract_realm_from_issuer(validated.claims.iss.as_str());
    if issuer_realm != Some(realm.name.as_str()) {
        tracing::debug!(
            issuer_realm = ?issuer_realm,
            realm = %realm.name,
            "resolve_session_from_cookie: cookie issuer realm does not match requested realm"
        );
        return None;
    }

    tracing::debug!(session_id = ?validated.claims.sid, "resolve_session_from_cookie: token validated");
    let sid = validated.claims.sid?;
    let session = state.storage.get_user_session(realm_id, &sid).await.ok().flatten()?;
    tracing::debug!("resolve_session_from_cookie: session lookup succeeded");

    // Offline sessions are not SSO sessions: they back offline
    // refresh tokens only. Never resolve them from a browser cookie — and in
    // particular never delete them via the SSO idle check below.
    if session.offline {
        return None;
    }

    // SSO idle-timeout enforcement: remembered sessions get the realm's
    // (longer) remember-me idle window, plain sessions the SSO idle window.
    let idle_secs = if session.remember_me {
        realm.remember_me_session_idle_secs.get()
    } else {
        realm.sso_session_idle_timeout.get()
    };
    let idle = chrono::Duration::seconds(idle_secs as i64);
    if chrono::Utc::now() - session.last_session_refresh > idle {
        debug!(realm = %realm_id, session_id = %session.id, "SSO session idle timeout exceeded; deleting session");
        let _ = state.storage.delete_user_session(realm_id, &session.id).await;
        crate::session_cache::invalidate_session(state, realm_id, &session.id).await;
        return None;
    }
    Some(session)
}

pub async fn auth_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    handle_auth_request(state, realm, ip, headers, params).await
}

pub async fn auth_handler_post(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: axum::http::HeaderMap,
    Query(query_params): Query<HashMap<String, String>>,
    body: String,
) -> Response {
    let mut params: HashMap<String, String> = match serde_urlencoded::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_form_data"})),
            )
                .into_response();
        }
    };
    // Merge query parameters; body parameters take precedence.
    for (k, v) in query_params {
        params.entry(k).or_insert(v);
    }
    handle_auth_request(state, realm, ip, headers, params).await
}

#[instrument(skip(state, headers, params, ip), fields(realm = ?realm))]
async fn handle_auth_request(
    state: Arc<ServerState>,
    realm: Option<String>,
    ip: std::net::IpAddr,
    headers: axum::http::HeaderMap,
    params: HashMap<String, String>,
) -> Response {
    let realm_name = match realm {
        Some(r) => r,
        None => {
            if wants_html(&headers) {
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
            if wants_html(&headers) {
                let mut redirect = url::form_urlencoded::Serializer::new(String::new());
                redirect.append_pair("error", "realm_not_found");
                redirect.append_pair("realm", &realm_name);
                return Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response();
            }
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "realm not found"})))
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    };
    let realm_id = realm.id.clone();

    // PAR (RFC 9126): a `request_uri` reference resolves into the
    // stored pushed authorization request before normal parsing; the realm's
    // require-PAR policy is enforced when no `request_uri` is present.
    let (params, used_par) = match crate::routes::par::resolve_par_params(
        &state,
        &realm,
        &realm_name,
        &ip,
        &headers,
        params,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // JAR (RFC 9101): a signed `request` object carries the
    // authorization request. Validate it against the client's verification
    // material and merge its claims (they win per-key over the query
    // parameters) before normal parsing. Failures render an error page/JSON —
    // nothing inside an unvalidated object (including redirect_uri) may be
    // trusted, so no client redirect is possible.
    let params = if params.contains_key("request") {
        let jar_result = async {
            let client_id_str = params.get("client_id").cloned().ok_or_else(|| {
                IssuerdError::InvalidRequest(
                    "client_id is required with the request parameter".into(),
                )
            })?;
            let identifier = ClientIdentifier::new(&client_id_str)?;
            let client = state
                .storage
                .get_client_by_client_id(&realm_id, &identifier)
                .await?
                .ok_or_else(|| IssuerdError::InvalidRequest("unknown client".into()))?;
            crate::routes::jar::extract_request_object_params(&state, &realm, &client, &params)
                .await
        }
        .await;
        match jar_result {
            Ok(p) => p,
            Err(e) => {
                return crate::routes::jar::jar_resolution_error(
                    &state,
                    &realm,
                    &realm_name,
                    &ip,
                    &headers,
                    &params,
                    e,
                )
                .await;
            }
        }
    } else {
        params
    };

    let auth_req = match AuthorizationRequest::parse(&params) {
        Ok(r) => r,
        Err(e) => {
            if let Some(resp) = try_auth_error_redirect(&state, &realm_name, &params, &e).await {
                let mut details = std::collections::HashMap::new();
                details.insert("error".to_string(), e.to_string());
                emit_oidc_event(
                    &state,
                    &realm_id,
                    EventType::LoginError,
                    &ip,
                    params.get("client_id").and_then(|s| issuerd_core::ClientId::new(s).ok()),
                    None,
                    None,
                    Some(e.to_string()),
                    details,
                )
                .await;
                return resp;
            }
            if wants_html(&headers) {
                let mut redirect = url::form_urlencoded::Serializer::new(String::new());
                redirect.append_pair("error", e.oauth_error_code().as_ref());
                redirect.append_pair("realm", &realm_name);
                if let Some(desc) = params.get("error_description") {
                    redirect.append_pair("error_description", desc);
                }
                return Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response();
            }
            return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
        }
    };

    // Resolve the UI locale once per flow (`ui_locales` beats
    // `Accept-Language` beats the realm default) and pin it on every pending
    // entry this request creates so continuation pages render in the same
    // language.
    let resolved_locale = crate::i18n::resolve_locale(
        &realm,
        &auth_req.ui_locales,
        headers.get(axum::http::header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()),
    );

    let client = match state.storage.get_client_by_client_id(&realm_id, &auth_req.client_id).await {
        // Disabled clients are rejected exactly like unknown ones (Keycloak
        // blocks disabled clients at every endpoint).
        Ok(Some(c)) if c.enabled => c,
        Ok(_) => {
            if wants_html(&headers) {
                let mut redirect = url::form_urlencoded::Serializer::new(String::new());
                redirect.append_pair("error", "invalid_client");
                redirect.append_pair("realm", &realm_name);
                return Redirect::to(&format!("/login.html?{}", redirect.finish())).into_response();
            }
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid client"})))
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    };

    if let Err(e) = auth_req.validate(&realm, &client) {
        warn!(realm = %realm_id, client_id = %auth_req.client_id, error = %e, "authorization request validation failed");
        let mut details = std::collections::HashMap::new();
        details.insert("error".to_string(), e.to_string());
        emit_oidc_event(
            &state,
            &realm_id,
            EventType::LoginError,
            &ip,
            Some(client.id.clone()),
            None,
            None,
            Some(e.to_string()),
            details,
        )
        .await;
        // Per RFC 6749 §4.1.2.1 / OIDC Core 3.1.2.1, when the redirect_uri is not
        // registered for the client the error MUST NOT be sent via redirect — not to
        // the requested URI, and not to a default registered URI either (the OIDC
        // conformance suite rejects both: oidcc-ensure-registered-redirect-uri and
        // oidcc-ensure-request-object-with-redirect-uri). Render an error instead.
        // Other validation failures (scope, response_type, ...) still redirect to the
        // requested redirect_uri, which is known to be registered at that point.
        if !client.redirect_uris.iter().any(|r| r.matches(auth_req.redirect_uri.as_str())) {
            return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
        }
        return crate::routes::auth_response::oauth_error_redirect(
            &state,
            auth_req.redirect_uri.as_ref(),
            &e,
            auth_req.state.as_deref(),
            &crate::routes::auth_response::ResponsePackaging::from_request(
                &realm,
                client.client_id.as_str(),
                &auth_req,
            ),
        )
        .await;
    }

    // Reject response types that parse but are not implemented (implicit/hybrid
    // variants involving `token`) instead of silently falling through to the
    // code flow. The redirect target is safe here: `validate` already verified
    // the redirect_uri is registered on this client.
    match &auth_req.response_type {
        ResponseType::Code | ResponseType::IdToken | ResponseType::CodeIdToken => {}
        unsupported => {
            let e = IssuerdError::UnsupportedResponseType;
            warn!(realm = %realm_id, client_id = %auth_req.client_id, response_type = %unsupported.as_str(), "unsupported response_type requested");
            let mut details = std::collections::HashMap::new();
            details.insert("error".to_string(), e.to_string());
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::LoginError,
                &ip,
                Some(client.id.clone()),
                None,
                None,
                Some(e.to_string()),
                details,
            )
            .await;
            return crate::routes::auth_response::oauth_error_redirect(
                &state,
                auth_req.redirect_uri.as_ref(),
                &e,
                auth_req.state.as_deref(),
                &crate::routes::auth_response::ResponsePackaging::from_request(
                    &realm,
                    client.client_id.as_str(),
                    &auth_req,
                ),
            )
            .await;
        }
    }

    // RFC 9126 §6: a client pinned to PAR may not start a plain authorization
    // request. `validate` already verified the redirect_uri is registered, so
    // the error can be safely redirected.
    if !used_par && crate::routes::par::client_requires_par(&client) {
        let e = IssuerdError::InvalidRequest(
            "client is required to use pushed authorization requests".into(),
        );
        warn!(realm = %realm_id, client_id = %auth_req.client_id, "client requires PAR but sent a plain authorization request");
        let mut details = std::collections::HashMap::new();
        details.insert("error".to_string(), e.to_string());
        emit_oidc_event(
            &state,
            &realm_id,
            EventType::LoginError,
            &ip,
            Some(client.id.clone()),
            None,
            None,
            Some(e.to_string()),
            details,
        )
        .await;
        return crate::routes::auth_response::oauth_error_redirect(
            &state,
            auth_req.redirect_uri.as_ref(),
            &e,
            auth_req.state.as_deref(),
            &crate::routes::auth_response::ResponsePackaging::from_request(
                &realm,
                client.client_id.as_str(),
                &auth_req,
            ),
        )
        .await;
    }

    // Resolve existing session for prompt/max_age checks
    let existing_session = resolve_session_from_cookie(&state, &headers, &realm).await;
    debug!(
        prompt = ?auth_req.prompt,
        max_age = ?auth_req.max_age,
        existing_session = existing_session.is_some(),
        "auth request state"
    );

    // prompt=none handling: if no valid session or max_age exceeded, return login_required
    if auth_req.prompt.contains(&Prompt::None) {
        let max_age_exceeded = auth_req.max_age.is_some_and(|max_age| {
            existing_session.as_ref().is_some_and(|sess| {
                // Clamp at zero: a future auth_time (clock skew) must not wrap
                // into a huge elapsed value and force spurious re-auth.
                let elapsed = (chrono::Utc::now() - sess.auth_time).num_seconds().max(0) as u64;
                elapsed > max_age
            })
        });
        debug!(
            existing_session = existing_session.is_some(),
            max_age_exceeded, "prompt=none handling"
        );
        if existing_session.is_none() || max_age_exceeded {
            let redirect = crate::routes::auth_response::oauth_error_redirect(
                &state,
                auth_req.redirect_uri.as_ref(),
                &IssuerdError::LoginRequired,
                auth_req.state.as_deref(),
                &crate::routes::auth_response::ResponsePackaging::from_request(
                    &realm,
                    client.client_id.as_str(),
                    &auth_req,
                ),
            )
            .await;
            let mut details = std::collections::HashMap::new();
            details.insert("error".to_string(), "login_required".to_string());
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::LoginError,
                &ip,
                Some(client.id.clone()),
                existing_session.as_ref().map(|s| s.user_id.clone()),
                existing_session.as_ref().map(|s| s.id.clone()),
                Some("login_required".to_string()),
                details,
            )
            .await;
            debug!("returning login_required redirect");
            return redirect;
        }
    }

    // Determine if we should force re-authentication
    let force_reauth = auth_req.prompt.contains(&Prompt::Login)
        || auth_req.max_age.is_some_and(|max_age| {
            existing_session.as_ref().is_some_and(|sess| {
                let elapsed = (chrono::Utc::now() - sess.auth_time).num_seconds().max(0) as u64;
                elapsed > max_age
            })
        });
    debug!(force_reauth, "auth request re-authentication decision");

    // Build typed auth context
    let mut ctx = issuerd_core::typestate::TypedAuthContext::new_anonymous(realm_id.clone());
    ctx.client_id = Some(client.id.clone());
    ctx.ip_address = Some(ip);
    if realm.verify_email_enabled {
        ctx.attributes
            .insert("realm_verify_email_enabled".to_string(), "true".to_string());
    }

    // Extract session cookie for SSO (only if not forcing re-auth).
    // Validate the cookie's issuer realm first so that a cookie issued by
    // another realm is never injected into the auth context.
    if !force_reauth {
        if let Some(value) = find_realm_cookie(&headers, &realm_id, "issuerd_session") {
            if let Ok(validated) = state.token_service.validate_access_token(&value) {
                let issuer_realm = issuerd_core::typestate::extract_realm_from_issuer(
                    validated.claims.iss.as_str(),
                );
                // Issuers are realm-NAME based: the segment is
                // the realm name, not the id.
                if issuer_realm != Some(realm.name.as_str()) {
                    tracing::debug!(
                        "auth_handler: ignoring cross-realm issuerd_session cookie for realm {:?}",
                        issuer_realm
                    );
                } else {
                    // W2: SSO via cookie only when the cookie's sid
                    // maps to a live stored session — otherwise a
                    // logged-out (deleted) session would keep
                    // re-authenticating until the cookie JWT expires.
                    let live = match (&existing_session, &validated.claims.sid) {
                        (Some(sess), Some(sid)) => sess.id == *sid,
                        _ => false,
                    };
                    if live {
                        ctx.attributes.insert("session_cookie".to_string(), value.to_string());
                    } else {
                        tracing::debug!(
                            "auth_handler: ignoring issuerd_session cookie without a live session"
                        );
                    }
                }
            }
        }
    }

    // Remember-me re-authentication: no live SSO session, but a valid
    // long-lived `issuerd_remember` cookie re-establishes the user silently. Any
    // failure (missing/invalid/expired token, unknown or disabled user) is
    // silent — the flow simply falls through to the login form.
    if !force_reauth && existing_session.is_none() && realm.remember_me_enabled {
        if let Some(value) = find_realm_cookie(&headers, &realm_id, "issuerd_remember") {
            let verified = issuerd_token::action_tokens::verify_action_token(
                state.crypto.as_ref(),
                &value,
                issuerd_core::ACTION_TOKEN_PURPOSE_REMEMBER_ME,
                &realm_id,
            )
            .await;
            if let Ok(claims) = verified {
                let user = match issuerd_core::UserId::new(claims.sub.clone()) {
                    Ok(id) => state.storage.get_user(&realm_id, &id).await.ok().flatten(),
                    Err(_) => None,
                };
                if let Some(user) = user.filter(|u| u.enabled) {
                    debug!(realm = %realm_id, user_id = %user.id, "re-authenticating via remember-me cookie");
                    ctx.attributes.insert("remember_me_user".to_string(), claims.sub);
                    ctx.attributes.insert(
                        "remember_me_auth_time".to_string(),
                        claims.auth_time.unwrap_or(claims.iat).to_string(),
                    );
                }
            }
        }
    }

    // Extract Authorization header for SPNEGO
    if let Some(authz) =
        headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok())
    {
        ctx.attributes.insert("Authorization".to_string(), authz.to_string());
    }

    // Copy auth request params into context.parameters as Vec<String>
    ctx.parameters
        .insert("response_type".to_string(), vec![auth_req.response_type.as_str().to_string()]);
    ctx.parameters
        .insert("client_id".to_string(), vec![auth_req.client_id.to_string()]);
    ctx.parameters
        .insert("redirect_uri".to_string(), vec![auth_req.redirect_uri.to_string()]);
    if !auth_req.scope.is_empty() {
        ctx.parameters.insert("scope".to_string(), auth_req.scope.to_vec());
    }
    if let Some(ref s) = auth_req.state {
        ctx.parameters.insert("state".to_string(), vec![s.clone()]);
    }
    if let Some(ref n) = auth_req.nonce {
        ctx.parameters.insert("nonce".to_string(), vec![n.to_string()]);
    }
    if let Some(ref cc) = auth_req.code_challenge {
        ctx.parameters
            .insert("code_challenge".to_string(), vec![cc.as_str().to_string()]);
    }
    if let Some(ccm) = auth_req.code_challenge_method {
        ctx.parameters.insert(
            "code_challenge_method".to_string(),
            vec![serde_json::to_string(&ccm).unwrap().trim_matches('"').to_string()],
        );
    }

    // `kc_idp_hint` arms the identity-provider redirect stage of the
    // browser flow (the hint travels in the context, not the parameters, so a
    // resumed flow without the hint degrades gracefully to the login form).
    if let Some(hint) = params.get("kc_idp_hint") {
        ctx.attributes.insert("identity_provider_hint".to_string(), hint.clone());
    }

    // Run flow. The realm's browser-flow binding selects the
    // top-level flow from storage (code default as fallback); the executor is
    // built over the realm's full stored flow set so sub-flow stages resolve.
    // The direct-grant / reset-credentials / first-broker-login bindings are
    // intentionally not consumed at runtime — see `ServerState::bound_flow_executor`.
    let (flow, executor) = state
        .bound_flow_executor(&realm, realm.browser_flow.as_deref(), "browser", default_browser_flow)
        .await;

    match executor.execute(&flow, ctx).await {
        Ok(FlowOutput::Success { ctx, result }) => {
            info!(realm = %realm_id, user_id = %ctx.user_id, "authentication flow succeeded");

            // Remember-me re-authentication provenance, injected into the
            // context before the flow ran (only after the remember cookie
            // passed full server-side verification).
            let remember_me_reauth = ctx.attributes.contains_key("remember_me_user");
            let remember_me_auth_time = ctx
                .attributes
                .get("remember_me_auth_time")
                .and_then(|s| s.parse::<i64>().ok())
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

            // Required actions pending (temporary password, unverified email,
            // admin-assigned actions detected during SSO/cookie auth): pause
            // into the required-action continuation before issuing anything.
            if !result.required_actions.is_empty() {
                let pending = PendingAuthData {
                    realm_id: realm_id.0.clone(),
                    client_id: auth_req.client_id.to_string(),
                    redirect_uri: auth_req.redirect_uri.to_string(),
                    scope: auth_req.scope.to_vec(),
                    state: auth_req.state.clone(),
                    nonce: auth_req.nonce.clone(),
                    response_type: auth_req.response_type.as_str().to_string(),
                    code_challenge: auth_req.code_challenge.clone(),
                    code_challenge_method: auth_req.code_challenge_method,
                    ip_address: Some(ip),
                    execution_id: FlowStageId::new("required-actions").unwrap(),
                    acr_values: auth_req.acr_values.clone(),
                    claims: auth_req.claims.clone(),
                    _typestate_tag: "action_required".to_string(),
                    attempt_count: 0,
                    remember_me: remember_me_reauth,
                    user_id: None,
                    prompt_consent: auth_req.prompt.contains(&Prompt::Consent),
                    locale: Some(resolved_locale.clone()),
                    response_mode: auth_req.response_mode,
                    authorization_details: auth_req.authorization_details.clone(),
                };
                return super::required_actions::begin_actions_continuation(
                    &state,
                    &realm_name,
                    pending,
                    *result,
                    true,
                )
                .await;
            }

            // Look up user (needed for id_token flow)
            let user = match state.storage.get_user(&realm_id, &ctx.user_id).await {
                Ok(Some(u)) => u,
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            // Typestate proof: clear required actions before authorization
            let user_id = ctx.user_id.clone();
            let session_id = result.session_id.clone();
            let result_auth_time = result.auth_time;
            let _cleared = result.into_cleared();

            // Preserve original auth_time when not forcing re-authentication:
            // from the live SSO session, or from the remember cookie's record
            // of the original authentication time.
            let auth_time = if force_reauth {
                result_auth_time
            } else if let Some(existing) = &existing_session {
                existing.auth_time
            } else {
                remember_me_auth_time.unwrap_or(result_auth_time)
            };

            // Consent gate: a consent-required client (or an explicit
            // prompt=consent) pauses here — after authentication but before
            // any session/code issuance — until the user grants the scopes.
            let prompt_consent = auth_req.prompt.contains(&Prompt::Consent);
            let pending = PendingAuthData {
                realm_id: realm_id.0.clone(),
                client_id: auth_req.client_id.to_string(),
                redirect_uri: auth_req.redirect_uri.to_string(),
                scope: auth_req.scope.to_vec(),
                state: auth_req.state.clone(),
                nonce: auth_req.nonce.clone(),
                response_type: auth_req.response_type.as_str().to_string(),
                code_challenge: auth_req.code_challenge.clone(),
                code_challenge_method: auth_req.code_challenge_method,
                ip_address: Some(ip),
                // Resume position is inert on this completed flow; the pending
                // entry only materializes inside the consent continuation.
                execution_id: FlowStageId::new("consent").unwrap(),
                acr_values: auth_req.acr_values.clone(),
                claims: auth_req.claims.clone(),
                _typestate_tag: "challenged".to_string(),
                attempt_count: 0,
                remember_me: remember_me_reauth,
                user_id: Some(user_id.0.clone()),
                prompt_consent,
                locale: Some(resolved_locale.clone()),
                response_mode: auth_req.response_mode,
                authorization_details: auth_req.authorization_details.clone(),
            };
            if super::consent::consent_needed(
                &state,
                &realm_id,
                &client,
                &user_id,
                auth_req.scope.as_slice(),
                prompt_consent,
            )
            .await
            {
                // prompt=none must never render an interactive page (OIDC Core
                // 3.1.2.6): report consent_required to the client instead.
                if auth_req.prompt.contains(&Prompt::None) {
                    return crate::routes::auth_response::oauth_error_redirect(
                        &state,
                        auth_req.redirect_uri.as_ref(),
                        &IssuerdError::ConsentRequired,
                        auth_req.state.as_deref(),
                        &crate::routes::auth_response::ResponsePackaging::from_request(
                            &realm,
                            client.client_id.as_str(),
                            &auth_req,
                        ),
                    )
                    .await;
                }
                let entry = super::consent::PendingConsentData {
                    pending,
                    user_id: user_id.0.clone(),
                    session_id: session_id.0.clone(),
                    result_auth_time,
                    auth_time,
                    is_browser_form: true,
                    sso_resume: true,
                    // Unused on the SSO resume path; the session merge there
                    // keeps its own method semantics.
                    auth_method: AuthMethod::Password,
                    method_label: "cookie".to_string(),
                    error: None,
                    _typestate_tag: "consent".to_string(),
                };
                return super::consent::begin_consent(&state, realm_name.as_str(), entry).await;
            }

            finish_sso_login(
                &state,
                &realm,
                &client,
                &user,
                &pending,
                existing_session,
                &session_id,
                result_auth_time,
                auth_time,
                ip,
                remember_me_reauth,
            )
            .await
        }
        Ok(FlowOutput::Challenge { paused }) => {
            let execution_id = paused.execution_id().clone();
            // Browser-facing flow id is a fresh random value; the flow stage id
            // stays inside the stored entry as the resume position only.
            let flow_id = issuerd_core::utils::generate_id();
            let pending = PendingAuthData {
                realm_id: realm_id.0.clone(),
                client_id: auth_req.client_id.to_string(),
                redirect_uri: auth_req.redirect_uri.to_string(),
                scope: auth_req.scope.to_vec(),
                state: auth_req.state.clone(),
                nonce: auth_req.nonce.clone(),
                response_type: auth_req.response_type.as_str().to_string(),
                code_challenge: auth_req.code_challenge.clone(),
                code_challenge_method: auth_req.code_challenge_method,
                ip_address: Some(ip),
                execution_id: execution_id.clone(),
                acr_values: auth_req.acr_values.clone(),
                claims: auth_req.claims.clone(),
                _typestate_tag: "challenged".to_string(),
                attempt_count: 0,
                remember_me: false,
                user_id: paused.user_id().map(|u| u.0.clone()),
                prompt_consent: auth_req.prompt.contains(&Prompt::Consent),
                locale: Some(resolved_locale.clone()),
                response_mode: auth_req.response_mode,
                authorization_details: auth_req.authorization_details.clone(),
            };
            let cache_key = pending_auth_cache_key(&realm_id, &flow_id);
            let cache_value = serde_json::to_vec(&pending).unwrap();
            let _ = state
                .cache
                .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
                .await;

            let mut redirect_params: Vec<(&str, &str)> = vec![
                ("execution_id", flow_id.as_ref()),
                ("realm", realm_name.as_ref()),
            ];
            if let Some(ref s) = auth_req.state {
                redirect_params.push(("state", s.as_str()));
            }
            // An identity-provider redirect challenge goes straight
            // to the broker login route (realm-relative challenge URL anchored
            // under /realms/{realm}) instead of the login page. The pending
            // entry stored above plus the flow cookie authorize the broker
            // kickoff; the callback consumes the entry and finalizes the login.
            let location = match paused.challenge() {
                Challenge::Redirect { url } if url.starts_with("/broker/") => {
                    let mut ser = url::form_urlencoded::Serializer::new(String::new());
                    ser.append_pair("flow", &flow_id);
                    format!("/realms/{}{}?{}", realm_name, url, ser.finish())
                }
                // The `registration=true` hint sends the browser to the
                // registration form instead of the login page; the pending
                // entry and flow cookie above let the registration POST
                // resume this flow afterwards.
                _ if auth_req.registration && realm.registration_enabled => {
                    register_challenge_location(&realm_name, &flow_id)
                }
                _ => build_redirect_url("/login.html", &redirect_params, false),
            };
            let mut resp = Redirect::to(&location).into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str(&flow_cookie_header(
                &flow_id,
                state.config.secure_cookies(),
            )) {
                resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
            }
            resp
        }
        Ok(FlowOutput::Failure(IssuerdError::InvalidGrant)) => {
            // Treat missing credentials as a login challenge. The resume
            // position is the flow's username-password stage — resolved from
            // the loaded flow, not hardcoded, because copied/custom flows
            // carry their own stage ids (the literal only survives as a
            // fallback for flows without a password stage).
            let execution_id = flow
                .stages
                .iter()
                .find(|s| {
                    s.sub_flow_alias.is_none()
                        && s.authenticator.as_str() == "auth-username-password"
                        && !matches!(s.requirement, issuerd_core::Requirement::Disabled)
                })
                .map(|s| s.id.clone())
                .unwrap_or_else(|| FlowStageId::new("username-password").unwrap());
            let flow_id = issuerd_core::utils::generate_id();
            let pending = PendingAuthData {
                realm_id: realm_id.0.clone(),
                client_id: auth_req.client_id.to_string(),
                redirect_uri: auth_req.redirect_uri.to_string(),
                scope: auth_req.scope.to_vec(),
                state: auth_req.state.clone(),
                nonce: auth_req.nonce.clone(),
                response_type: auth_req.response_type.as_str().to_string(),
                code_challenge: auth_req.code_challenge.clone(),
                code_challenge_method: auth_req.code_challenge_method,
                ip_address: Some(ip),
                execution_id: execution_id.clone(),
                acr_values: auth_req.acr_values.clone(),
                claims: auth_req.claims.clone(),
                _typestate_tag: "anonymous".to_string(),
                attempt_count: 0,
                remember_me: false,
                user_id: None,
                prompt_consent: auth_req.prompt.contains(&Prompt::Consent),
                locale: Some(resolved_locale.clone()),
                response_mode: auth_req.response_mode,
                authorization_details: auth_req.authorization_details.clone(),
            };
            let cache_key = pending_auth_cache_key(&realm_id, &flow_id);
            let cache_value = serde_json::to_vec(&pending).unwrap();
            let _ = state
                .cache
                .set(&cache_key, cache_value, Some(std::time::Duration::from_secs(600)))
                .await;

            let mut redirect_params: Vec<(&str, &str)> = vec![
                ("execution_id", flow_id.as_ref()),
                ("realm", realm_name.as_ref()),
            ];
            if let Some(ref s) = auth_req.state {
                redirect_params.push(("state", s.as_str()));
            }
            let location = if auth_req.registration && realm.registration_enabled {
                // Same `registration=true` hint as the challenge branch above.
                register_challenge_location(&realm_name, &flow_id)
            } else {
                build_redirect_url("/login.html", &redirect_params, false)
            };
            let mut resp = Redirect::to(&location).into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str(&flow_cookie_header(
                &flow_id,
                state.config.secure_cookies(),
            )) {
                resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
            }
            resp
        }
        Ok(FlowOutput::Failure(e)) => {
            (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    }
}

/// SSO/cookie-path login completion: merge the client session into the
/// (possibly pre-existing) SSO session, persist it, emit the login event, and
/// mint the response per the requested response type.
///
/// Extracted from `handle_auth_request` so the consent continuation
/// resumes into the exact same tail once the user approves.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn finish_sso_login(
    state: &Arc<ServerState>,
    realm: &issuerd_core::Realm,
    client: &issuerd_core::Client,
    user: &issuerd_core::User,
    pending: &PendingAuthData,
    existing_session: Option<issuerd_core::UserSession>,
    session_id: &issuerd_core::SessionId,
    result_auth_time: chrono::DateTime<chrono::Utc>,
    auth_time: chrono::DateTime<chrono::Utc>,
    ip: std::net::IpAddr,
    remember_me_reauth: bool,
) -> Response {
    let realm_id = realm.id.clone();
    let user_id = user.id.clone();
    // Create session (common to all response types)
    let client_redirect_uri = match issuerd_core::RedirectUri::new(pending.redirect_uri.clone()) {
        Ok(u) => u,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e))).into_response();
        }
    };
    let client_session = issuerd_core::ClientSession {
        id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id()).unwrap(),
        client_id: client.id.clone(),
        session_id: session_id.clone(),
        redirect_uri: Some(client_redirect_uri),
        state: pending.state.clone(),
        auth_method: AuthMethod::Password,
        timestamp: result_auth_time,
    };
    // SSO login over an existing session must merge the client
    // sessions, not overwrite them (P3-3): other clients already
    // registered on this SSO session keep their entries.
    let (session, update_existing) = match &existing_session {
        Some(existing) if existing.id == *session_id => {
            let mut merged = existing.clone();
            merged.ip_address = ip;
            merged.login_username = user.username.clone();
            merged.last_session_refresh = result_auth_time;
            merged.auth_time = auth_time;
            match merged.clients.iter_mut().find(|cs| cs.client_id == client.id) {
                Some(cs) => *cs = client_session,
                None => merged.clients.push(client_session),
            }
            (merged, true)
        }
        _ => (
            issuerd_core::UserSession {
                id: session_id.clone(),
                realm_id: realm_id.clone(),
                user_id: user_id.clone(),
                ip_address: ip,
                login_username: user.username.clone(),
                auth_method: AuthMethod::Password,
                remember_me: remember_me_reauth,
                offline: false,
                started: result_auth_time,
                last_session_refresh: result_auth_time,
                auth_time,
                impersonator: None,
                clients: vec![client_session],
            },
            false,
        ),
    };
    if let Err(resp) = persist_session(state, &realm_id, &session, update_existing).await {
        return resp;
    }

    if existing_session.is_some() {
        let mut details = std::collections::HashMap::new();
        details.insert("method".to_string(), "cookie".to_string());
        emit_oidc_event(
            state,
            &realm_id,
            EventType::Login,
            &ip,
            Some(client.id.clone()),
            Some(session.user_id.clone()),
            Some(session.id.clone()),
            None,
            details,
        )
        .await;
    } else {
        let mut details = std::collections::HashMap::new();
        let method = if remember_me_reauth {
            "remember_me"
        } else {
            "password"
        };
        details.insert("method".to_string(), method.to_string());
        details.insert("username".to_string(), user.username.to_string());
        emit_oidc_event(
            state,
            &realm_id,
            EventType::Login,
            &ip,
            Some(client.id.clone()),
            Some(user.id.clone()),
            Some(session.id.clone()),
            None,
            details,
        )
        .await;
    }

    match pending.response_type.as_str() {
        "id_token" => {
            // Pure implicit flow: no access token is issued, so scope
            // claims ride in the ID token (OIDC Core §5.4) via the
            // protocol-mapper overlay.
            let overlay = crate::claims::build_claims_overlay(
                state,
                &realm_id,
                Some(client),
                user,
                pending.scope.as_slice(),
                issuerd_core::ClaimTarget::IdToken,
            )
            .await
            .unwrap_or_default();
            let id_token = match state
                .token_manager
                .issue_id_token(
                    user,
                    client,
                    realm,
                    pending.nonce.as_deref(),
                    auth_time,
                    session_id,
                    None,
                    None,
                    Some(&pending.acr_values),
                    Some(overlay),
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    error!(realm = %realm_id, client_id = %client.client_id, error = %e, "failed to issue ID token");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e)))
                        .into_response();
                }
            };

            let mut redirect_params: Vec<(&str, &str)> = vec![("id_token", &id_token.token)];
            if let Some(ref s) = pending.state {
                redirect_params.push(("state", s));
            }
            // Packaged per the requested response_mode (the
            // fragment is the default for pure implicit).
            crate::routes::auth_response::authorization_response(
                state,
                &pending.redirect_uri,
                &redirect_params,
                &crate::routes::auth_response::ResponsePackaging::from_pending(realm, pending),
            )
            .await
        }
        "code id_token" => {
            let code = issuerd_core::utils::generate_id();
            let code_data = AuthCodeData::from_pending(pending, &user_id, session_id, auth_time);
            if let Err(e) = store_auth_code(
                &state.cache,
                &code,
                &code_data,
                state.config.oauth.auth_code_ttl(realm),
            )
            .await
            {
                return auth_code_store_failure(
                    state, realm, client, &user_id, session_id, &ip, pending, &e,
                )
                .await;
            }

            let id_token = match state
                .token_manager
                .issue_id_token(
                    user,
                    client,
                    realm,
                    pending.nonce.as_deref(),
                    auth_time,
                    session_id,
                    None,
                    Some(&code),
                    Some(&pending.acr_values),
                    // Hybrid flow: userinfo claims are served by the
                    // userinfo endpoint, not embedded in the ID token.
                    None,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    error!(realm = %realm_id, client_id = %client.client_id, error = %e, "failed to issue ID token");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e)))
                        .into_response();
                }
            };

            let mut redirect_params: Vec<(&str, &str)> =
                vec![("code", &code), ("id_token", &id_token.token)];
            if let Some(ref s) = pending.state {
                redirect_params.push(("state", s));
            }
            // Packaged per the requested response_mode (the
            // fragment is the default for hybrid with id_token).
            crate::routes::auth_response::authorization_response(
                state,
                &pending.redirect_uri,
                &redirect_params,
                &crate::routes::auth_response::ResponsePackaging::from_pending(realm, pending),
            )
            .await
        }
        _ => {
            let code = issuerd_core::utils::generate_id();
            let code_data = AuthCodeData::from_pending(pending, &user_id, session_id, auth_time);
            if let Err(e) = store_auth_code(
                &state.cache,
                &code,
                &code_data,
                state.config.oauth.auth_code_ttl(realm),
            )
            .await
            {
                return auth_code_store_failure(
                    state, realm, client, &user_id, session_id, &ip, pending, &e,
                )
                .await;
            }

            let mut redirect_params: Vec<(&str, &str)> = vec![("code", &code)];
            if let Some(ref s) = pending.state {
                redirect_params.push(("state", s));
            }
            // Packaged per the requested response_mode (the query
            // is the default for the code flow).
            crate::routes::auth_response::authorization_response(
                state,
                &pending.redirect_uri,
                &redirect_params,
                &crate::routes::auth_response::ResponsePackaging::from_pending(realm, pending),
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Device authorization endpoint
// ---------------------------------------------------------------------------

fn generate_user_code() -> String {
    // User-friendly code: 8 chars, uppercase, no ambiguous characters
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let chars: String = (0..8)
        .map(|_| {
            let idx = rand::Rng::gen_range(&mut rng, 0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    format!("{}-{}", &chars[0..4], &chars[4..8])
}

#[instrument(skip(state, body), fields(realm = ?realm))]
pub async fn device_auth_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    body: String,
) -> Response {
    let realm_name = match realm {
        Some(r) => r,
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing realm"})))
                .into_response();
        }
    };

    // Resolve the realm by name so storage queries use the canonical realm ID.
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "realm not found"})))
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    };
    let realm_id = realm.id.clone();

    let body_params: HashMap<String, String> = match serde_urlencoded::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_form_data"})),
            )
                .into_response();
        }
    };

    let device_req = match DeviceAuthorizationRequest::parse(&body_params) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
        }
    };

    let client = match state.storage.get_client_by_client_id(&realm_id, &device_req.client_id).await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"})))
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    };

    if let Err(e) = device_req.validate(&client) {
        return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
    }

    let device_code = issuerd_core::utils::generate_id();
    let user_code = generate_user_code();
    let expires_in: u64 = 600;
    let interval: u64 = 5;

    let code_data = DeviceCodeData {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        client_id: device_req.client_id.to_string(),
        realm_id: realm_id.0.clone(),
        scope: device_req.scope.to_vec(),
        user_id: None,
        authorized: false,
        last_polled_at: None,
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64),
    };

    let cache_value = serde_json::to_vec(&code_data).unwrap();
    let ttl = Some(std::time::Duration::from_secs(expires_in));

    let _ = state
        .cache
        .set(
            &issuerd_cluster::cache_keys::device_code(&device_code),
            cache_value.clone(),
            ttl,
        )
        .await;
    let _ = state
        .cache
        .set(&issuerd_cluster::cache_keys::user_code(&user_code), cache_value, ttl)
        .await;

    let issuer = format!(
        "{}/realms/{}",
        state.config.issuer_url.trim_end_matches('/'),
        realm.name.as_str()
    );
    let verification_uri = format!("{}/protocol/openid-connect/auth/device-verify", issuer);
    let verification_uri_complete = Some(format!("{}?user_code={}", verification_uri, user_code));

    let resp = DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in,
        interval,
    };

    Json(resp).into_response()
}

// ---------------------------------------------------------------------------
// Device verification endpoint
// ---------------------------------------------------------------------------

#[instrument(skip(state, body, ip), fields(realm = ?realm))]
pub async fn device_verify_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    body: String,
) -> Response {
    let realm_name = match realm {
        Some(r) => r,
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing realm"})))
                .into_response();
        }
    };
    // Resolve by name so the storage realm ID is used (URLs carry the name).
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_realm"})))
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    };
    let realm_id = realm.id.clone();

    let body_params: HashMap<String, String> = match serde_urlencoded::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_form_data"})),
            )
                .into_response();
        }
    };

    let user_code = body_params
        .get("user_code")
        .map(|s| s.trim().to_uppercase())
        .unwrap_or_default();
    let username = body_params.get("username").map(|s| s.as_str()).unwrap_or("");
    let password = body_params.get("password").map(|s| s.as_str()).unwrap_or("");

    if user_code.is_empty() || username.is_empty() || password.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_request"})))
            .into_response();
    }

    // Look up device request by user_code
    let cache_key = issuerd_cluster::cache_keys::user_code(&user_code);
    let mut code_data: DeviceCodeData = match state.cache.get(&cache_key).await {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "expired_token"})),
                )
                    .into_response();
            }
        },
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "expired_token"})))
                .into_response();
        }
    };

    if code_data.realm_id != realm_id.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "expired_token"})))
            .into_response();
    }

    // Authenticate user with username/password
    let user = match state.storage.get_user_by_username(&realm_id, username).await {
        Ok(Some(u)) if u.enabled => u,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant"})))
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
            warn!(realm = %realm_id, username = %user.username, ip = %ip, "device verification rejected: account temporarily locked");
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    }

    let creds = match state
        .storage
        .get_credentials(&realm_id, &user.id, issuerd_core::CredentialType::Password)
        .await
    {
        Ok(c) => c,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
    };

    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let mut matched = false;
    for cred in &creds {
        let hash_str = match String::from_utf8(cred.secret_data.clone()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let parsed = match PasswordHash::new(&hash_str) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok() {
            matched = true;
            break;
        }
    }

    if !matched {
        warn!(realm = %realm_id, username = %issuerd_core::utils::sanitize_log_str(username), ip = %ip, "device verification failed: invalid user credentials");
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
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant"})))
            .into_response();
    }

    // Successful authentication clears the failure counter.
    if brute_force.is_some() {
        let _ = state
            .login_failure_tracker
            .reset_failures(&realm_id, user.username.as_str(), &ip_key, state.cache.as_ref())
            .await;
    }

    // Update cache entry with authorization
    code_data.user_id = Some(user.id.0.clone());
    code_data.authorized = true;
    code_data.last_polled_at = None;

    let cache_value = serde_json::to_vec(&code_data).unwrap();
    let device_key = issuerd_cluster::cache_keys::device_code(&code_data.device_code);
    let user_key = issuerd_cluster::cache_keys::user_code(&code_data.user_code);

    // Re-set with the remaining TTL — approval must not extend the lifetime.
    let Some(ttl) = remaining_ttl(code_data.expires_at) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "expired_token"})))
            .into_response();
    };
    let _ = state.cache.set(&device_key, cache_value.clone(), Some(ttl)).await;
    let _ = state.cache.set(&user_key, cache_value, Some(ttl)).await;

    info!(realm = %realm_id, client_id = %code_data.client_id, "device authorization approved");

    Json(serde_json::json!({"status": "ok"})).into_response()
}

// ---------------------------------------------------------------------------
// CIBA backchannel authentication endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
struct CibaAuthResponse {
    auth_req_id: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[instrument(skip(state, body, ip), fields(realm = ?realm))]
pub async fn ciba_auth_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    body: String,
) -> Response {
    let realm_name = match realm {
        Some(r) => r,
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing realm"})))
                .into_response();
        }
    };

    // Resolve the realm by name so storage queries use the canonical realm ID.
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "realm not found"})))
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    };
    let realm_id = realm.id.clone();

    let body_params: HashMap<String, String> = match serde_urlencoded::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                None,
                None,
                None,
                Some("invalid_form_data".to_string()),
                HashMap::new(),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_form_data"})),
            )
                .into_response();
        }
    };

    let ciba_req = match issuerd_protocol::ciba::CibaRequest::parse(&body_params) {
        Ok(r) => r,
        Err(e) => {
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                None,
                None,
                None,
                Some(e.oauth_error_code().to_string()),
                HashMap::new(),
            )
            .await;
            return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
        }
    };

    let client_id = body_params.get("client_id").map(|s| s.as_str()).unwrap_or("");
    let client_identifier = match ClientIdentifier::new(client_id) {
        Ok(id) => id,
        Err(_) => {
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                None,
                None,
                None,
                Some("invalid_client".to_string()),
                HashMap::new(),
            )
            .await;
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"})))
                .into_response();
        }
    };
    let client = match state.storage.get_client_by_client_id(&realm_id, &client_identifier).await {
        Ok(Some(c)) if c.enabled => c,
        // A disabled client must not start backchannel authentication either.
        Ok(c) => {
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                c.as_ref().map(|c| c.id.clone()),
                None,
                None,
                Some("invalid_client".to_string()),
                HashMap::new(),
            )
            .await;
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"})))
                .into_response();
        }
        Err(e) => {
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                None,
                None,
                None,
                Some(e.oauth_error_code().to_string()),
                HashMap::new(),
            )
            .await;
            return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
        }
    };

    // CIBA requires a confidential client
    if client.public_client {
        emit_oidc_event(
            &state,
            &realm_id,
            EventType::CibaAuthError,
            &ip,
            Some(client.id.clone()),
            None,
            None,
            Some("unauthorized_client".to_string()),
            HashMap::new(),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unauthorized_client"})),
        )
            .into_response();
    }

    // Authenticate client with secret
    let provided_secret = body_params.get("client_secret").map(|s| s.as_str()).unwrap_or("");
    let expected_secret = client.secret.as_deref().unwrap_or("");
    let secrets_match: bool =
        subtle::ConstantTimeEq::ct_eq(provided_secret.as_bytes(), expected_secret.as_bytes())
            .into();
    if provided_secret.is_empty() || !secrets_match {
        emit_oidc_event(
            &state,
            &realm_id,
            EventType::CibaAuthError,
            &ip,
            Some(client.id.clone()),
            None,
            None,
            Some("invalid_client".to_string()),
            HashMap::new(),
        )
        .await;
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"})))
            .into_response();
    }

    // The requested scope must be assigned to the client — otherwise CIBA
    // would be a side channel around the authorize-endpoint scope check
    // (e.g. picking up an unassigned `offline_access`).
    if let Err(e) = ciba_req.validate_scope(&client) {
        emit_oidc_event(
            &state,
            &realm_id,
            EventType::CibaAuthError,
            &ip,
            Some(client.id.clone()),
            None,
            None,
            Some(e.oauth_error_code().to_string()),
            HashMap::new(),
        )
        .await;
        return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
    }

    // Resolve user from login_hint (simple username lookup for MVP)
    let login_hint = ciba_req.login_hint.as_deref().unwrap_or("");
    let user = match state.storage.get_user_by_username(&realm_id, login_hint).await {
        Ok(Some(u)) if u.enabled => u,
        _ => {
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                Some(client.id.clone()),
                None,
                None,
                Some("unknown_user_id".to_string()),
                HashMap::new(),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "unknown_user_id"})),
            )
                .into_response();
        }
    };

    let auth_req_id = issuerd_core::utils::generate_id();
    let expires_in: u64 = ciba_req.requested_expiry.unwrap_or(120);
    let interval: u64 = 5;

    let req_data = CibaAuthReqData {
        auth_req_id: auth_req_id.clone(),
        client_id: client.client_id.to_string(),
        realm_id: realm_id.0.clone(),
        scope: ciba_req.scope.to_vec(),
        user_id: Some(user.id.0.clone()),
        authorized: false,
        denied: false,
        binding_message: ciba_req.binding_message.clone(),
        client_notification_token: ciba_req.client_notification_token.clone(),
        last_polled_at: None,
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64),
    };

    let cache_key = issuerd_cluster::cache_keys::ciba_auth_req(&auth_req_id);
    let cache_value = serde_json::to_vec(&req_data).unwrap();
    let ttl = Some(std::time::Duration::from_secs(expires_in));
    let _ = state.cache.set(&cache_key, cache_value, ttl).await;

    let mut details = HashMap::new();
    details.insert("scope".to_string(), ciba_req.scope.to_vec().join(" "));
    details.insert("expires_in".to_string(), expires_in.to_string());
    // The binding message is user-facing free text that can carry PII or
    // business data ("Refund $150 for order #123") — record only its
    // presence and length, never the text itself.
    if let Some(binding_message) = &ciba_req.binding_message {
        details.insert("binding_message_len".to_string(), binding_message.len().to_string());
    }
    emit_oidc_event(
        &state,
        &realm_id,
        EventType::CibaAuth,
        &ip,
        Some(client.id.clone()),
        Some(user.id.clone()),
        None,
        None,
        details,
    )
    .await;

    let resp = CibaAuthResponse {
        auth_req_id,
        expires_in,
        interval: Some(interval),
    };

    Json(resp).into_response()
}

// ---------------------------------------------------------------------------
// CIBA approval endpoint
//
// Approves or denies a CIBA request on behalf of the user identified by the
// request's login_hint, so it requires an SSO session (`issuerd_session` cookie)
// for exactly that user.
// ---------------------------------------------------------------------------

#[instrument(skip(state, headers, body, ip), fields(realm = ?realm))]
pub async fn ciba_approve_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let realm_name = match realm {
        Some(r) => r,
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing realm"})))
                .into_response();
        }
    };
    // Resolve by name so the storage realm ID is used (URLs carry the name).
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_realm"})))
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    };
    let realm_id = realm.id.clone();

    let body_params: HashMap<String, String> = match serde_urlencoded::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                None,
                None,
                None,
                Some("invalid_form_data".to_string()),
                HashMap::new(),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_form_data"})),
            )
                .into_response();
        }
    };

    let auth_req_id = body_params.get("auth_req_id").map(|s| s.as_str()).unwrap_or("");
    let action = body_params.get("action").map(|s| s.as_str()).unwrap_or("");

    if auth_req_id.is_empty() || action.is_empty() {
        emit_oidc_event(
            &state,
            &realm_id,
            EventType::CibaAuthError,
            &ip,
            None,
            None,
            None,
            Some("invalid_request".to_string()),
            HashMap::new(),
        )
        .await;
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_request"})))
            .into_response();
    }

    let cache_key = issuerd_cluster::cache_keys::ciba_auth_req(auth_req_id);
    let mut req_data: CibaAuthReqData = match state.cache.get(&cache_key).await {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(_) => {
                emit_oidc_event(
                    &state,
                    &realm_id,
                    EventType::CibaAuthError,
                    &ip,
                    None,
                    None,
                    None,
                    Some("expired_token".to_string()),
                    HashMap::new(),
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "expired_token"})),
                )
                    .into_response();
            }
        },
        _ => {
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                None,
                None,
                None,
                Some("expired_token".to_string()),
                HashMap::new(),
            )
            .await;
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "expired_token"})))
                .into_response();
        }
    };

    if req_data.realm_id != realm_id.0 {
        emit_oidc_event(
            &state,
            &realm_id,
            EventType::CibaAuthError,
            &ip,
            None,
            None,
            None,
            Some("expired_token".to_string()),
            HashMap::new(),
        )
        .await;
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "expired_token"})))
            .into_response();
    }

    // Approving or denying grants the client access as the bound user, so the
    // caller must hold an SSO session for exactly that user.
    let session = resolve_session_from_cookie(&state, &headers, &realm).await;
    let session_user = session.as_ref().map(|s| s.user_id.0.as_str());
    match (&req_data.user_id, session_user) {
        (Some(bound), Some(actual)) if bound == actual => {}
        _ => {
            // A valid SSO session deciding another user's request (or no
            // session at all) is security-relevant — audit it.
            let event_client_id =
                resolve_ciba_client_uuid(&state, &realm_id, &req_data.client_id).await;
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                event_client_id,
                session.as_ref().map(|s| s.user_id.clone()),
                session.as_ref().map(|s| s.id.clone()),
                Some("unauthorized".to_string()),
                HashMap::new(),
            )
            .await;
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"})))
                .into_response();
        }
    }

    let event_type = match action {
        "approve" => {
            req_data.authorized = true;
            req_data.last_polled_at = None;
            EventType::CibaApprove
        }
        "deny" => {
            req_data.denied = true;
            req_data.last_polled_at = None;
            EventType::CibaDeny
        }
        _ => {
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CibaAuthError,
                &ip,
                None,
                session.as_ref().map(|s| s.user_id.clone()),
                session.as_ref().map(|s| s.id.clone()),
                Some("invalid_request".to_string()),
                HashMap::new(),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_request"})),
            )
                .into_response();
        }
    };

    let cache_value = serde_json::to_vec(&req_data).unwrap();
    // Approval must not extend the request's lifetime.
    let Some(ttl) = remaining_ttl(req_data.expires_at) else {
        emit_oidc_event(
            &state,
            &realm_id,
            EventType::CibaAuthError,
            &ip,
            None,
            session.as_ref().map(|s| s.user_id.clone()),
            session.as_ref().map(|s| s.id.clone()),
            Some("expired_token".to_string()),
            HashMap::new(),
        )
        .await;
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "expired_token"})))
            .into_response();
    };
    let _ = state.cache.set(&cache_key, cache_value, Some(ttl)).await;

    let event_client_id = resolve_ciba_client_uuid(&state, &realm_id, &req_data.client_id).await;
    let mut details = HashMap::new();
    details.insert("scope".to_string(), req_data.scope.join(" "));
    emit_oidc_event(
        &state,
        &realm_id,
        event_type,
        &ip,
        event_client_id,
        session.as_ref().map(|s| s.user_id.clone()),
        session.as_ref().map(|s| s.id.clone()),
        None,
        details,
    )
    .await;

    Json(serde_json::json!({"status": "ok"})).into_response()
}

/// Resolve the internal client UUID for an audit event from the client
/// identifier stored on a pending CIBA request. `None` when the client is
/// gone or the lookup fails — the event is still recorded without it.
async fn resolve_ciba_client_uuid(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    client_id: &str,
) -> Option<issuerd_core::ClientId> {
    let identifier = ClientIdentifier::new(client_id).ok()?;
    state
        .storage
        .get_client_by_client_id(realm_id, &identifier)
        .await
        .ok()
        .flatten()
        .map(|c| c.id)
}

/// Emit a `login_error` event for a failed CIBA poll (`expired_token`,
/// `access_denied`, cross-client `invalid_grant`). `authorization_pending`
/// and `slow_down` are protocol chatter and never reach this helper.
async fn emit_ciba_poll_error(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    ip: &std::net::IpAddr,
    client: &issuerd_core::Client,
    user_id: Option<&str>,
    error: &str,
) {
    let mut details = HashMap::new();
    details.insert("method".to_string(), "ciba".to_string());
    emit_oidc_event(
        state,
        realm_id,
        EventType::LoginError,
        ip,
        Some(client.id.clone()),
        user_id.and_then(|uid| UserId::new(uid).ok()),
        None,
        Some(error.to_string()),
        details,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub(crate) struct TokenResponse {
    pub(crate) access_token: String,
    pub(crate) token_type: String,
    pub(crate) expires_in: u64,
    pub(crate) refresh_token: Option<String>,
    pub(crate) id_token: Option<String>,
    pub(crate) scope: Option<String>,
    /// RFC 8693 §2.2 `issued_token_type` — only set by the token-exchange
    /// grant; skipped everywhere else so the other grants'
    /// response shape is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issued_token_type: Option<String>,
    /// RFC 9396 §7 `authorization_details` echo — the details assigned to the
    /// issued access token, set by the authorization_code and refresh_token
    /// grants when the grant carries RAR authorization details;
    /// skipped everywhere else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authorization_details: Option<Vec<serde_json::Value>>,
}

pub(crate) fn token_response(resp: TokenResponse) -> Response {
    let mut response = Json(resp).into_response();
    let headers = response.headers_mut();
    headers.insert(axum::http::header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(axum::http::header::PRAGMA, "no-cache".parse().unwrap());
    response
}

pub(crate) fn extract_basic_auth(headers: &axum::http::HeaderMap) -> Option<(String, String)> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let creds = auth.strip_prefix("Basic ")?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, creds).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let mut parts = decoded_str.splitn(2, ':');
    let client_id = parts.next()?.to_string();
    let client_secret = parts.next()?.to_string();
    Some((client_id, client_secret))
}

/// Merge HTTP Basic client credentials into the form params (RFC 6749
/// §2.3.1). A body `client_id` alongside the Basic header is legal — the
/// header authenticates and the parameter merely identifies the client
/// (RFC 9126 §1.1's own example pushes with Basic auth AND a body
/// `client_id`) — but a mismatched body `client_id`, or a contradicting body
/// `client_secret`, is rejected as `invalid_client` with a 401 and a
/// `WWW-Authenticate` challenge (RFC 6749 §5.2).
///
/// The `Err` payload is a ready-made response; `Response` is large, but this
/// helper is called at most once per request, so the lint's performance
/// concern does not apply.
#[allow(clippy::result_large_err)]
pub(crate) fn fold_basic_auth(
    headers: &axum::http::HeaderMap,
    params: &mut HashMap<String, String>,
) -> Result<(), Response> {
    let Some((basic_id, basic_secret)) = extract_basic_auth(headers) else {
        return Ok(());
    };
    let mismatch = params.get("client_id").is_some_and(|id| *id != basic_id)
        || params.get("client_secret").is_some_and(|s| *s != basic_secret);
    if mismatch {
        return Err((
            StatusCode::UNAUTHORIZED,
            [(axum::http::header::WWW_AUTHENTICATE, "Basic realm=\"issuerd\"")],
            Json(serde_json::json!({"error": "invalid_client"})),
        )
            .into_response());
    }
    params.insert("client_id".to_string(), basic_id);
    params.insert("client_secret".to_string(), basic_secret);
    Ok(())
}

#[utoipa::path(
    post,
    path = "/realms/{realm}/protocol/openid-connect/token",
    tag = "Protocol",
    summary = "OAuth2/OIDC token endpoint",
    description = "Exchanges an authorization code (with PKCE verifier) or a refresh token for tokens. Content type is `application/x-www-form-urlencoded`.",
    operation_id = "token_endpoint",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(content = crate::openapi::TokenEndpointForm, content_type = "application/x-www-form-urlencoded", description = "Grant-specific form fields (all optional; the grant_type drives which are required)"),
    responses(
        (status = 200, description = "Issued tokens", body = TokenResponse),
        (status = 400, description = "OAuth2 error response", body = crate::openapi::OAuth2ErrorResponse),
    ),
    security(()),
)]
#[instrument(skip(state, headers, body, ip), fields(realm = ?realm))]
pub async fn token_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let realm_name = match realm {
        Some(r) => r,
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing realm"})))
                .into_response();
        }
    };

    // Look up realm by name so we have the correct realm ID for storage queries.
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "realm not found"})))
                .into_response();
        }
    };
    let realm_id = realm.id.clone();

    let mut body_params: HashMap<String, String> = match serde_urlencoded::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_form_data"})),
            )
                .into_response();
        }
    };

    // Extract client credentials from the Basic Auth header, folding them
    // into the form params. A body `client_id` next to Basic auth is legal
    // and common; contradictions are rejected as `invalid_client`.
    if let Err(resp) = fold_basic_auth(&headers, &mut body_params) {
        return resp;
    }

    let token_req = match TokenRequest::parse(&body_params) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
        }
    };

    let client_id = token_req.client_id.as_deref().unwrap_or("");
    let client_identifier = match ClientIdentifier::new(client_id) {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"})))
                .into_response();
        }
    };
    let client = match state.storage.get_client_by_client_id(&realm_id, &client_identifier).await {
        // A disabled client must not redeem codes, passwords, or refresh
        // tokens — disabling is the administrative containment action.
        Ok(Some(c)) if c.enabled => c,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"})))
                .into_response();
        }
    };

    // Authenticate confidential clients per their configured
    // `client_authenticator_type`: shared secret (default) or a JWT client
    // assertion (`private_key_jwt` / `client_secret_jwt`).
    if !client.public_client {
        if let Err(e) = crate::client_assertion::verify_client_auth(
            &state,
            &realm_id,
            realm.name.as_str(),
            &client,
            &body_params,
        )
        .await
        {
            warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "token endpoint client authentication failed");
            // RFC 6749 §5.2: a client that attempted HTTP Basic
            // authentication gets a 401 with a WWW-Authenticate challenge.
            if extract_basic_auth(&headers).is_some() {
                return (
                    StatusCode::UNAUTHORIZED,
                    [(axum::http::header::WWW_AUTHENTICATE, "Basic realm=\"issuerd\"")],
                    Json(serde_json::json!({"error": "invalid_client"})),
                )
                    .into_response();
            }
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"})))
                .into_response();
        }
    }

    // DPoP (RFC 9449): when the request carries a `DPoP` proof
    // header, verify it (htm/htu/iat/jti single-use, plus the server-nonce
    // gate when `[dpop.nonce]` is enabled) — tokens issued below are
    // then bound to the proof key via `cnf.jkt`. No header: plain Bearer flow.
    let dpop = match crate::dpop::verify_proof_header(
        &state,
        &realm_id,
        Some(realm.name.as_ref()),
        &headers,
        "POST",
        "token",
        None,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(crate::dpop::DpopRejection::UseDpopNonce(nonce)) => {
            debug!(realm = %realm_id, client_id = %client.client_id, "DPoP proof without a live server nonce at token endpoint — challenging");
            return crate::dpop::use_dpop_nonce_response(&nonce);
        }
        Err(crate::dpop::DpopRejection::InvalidProof) => {
            warn!(realm = %realm_id, client_id = %client.client_id, "DPoP proof rejected at token endpoint");
            return (
                StatusCode::BAD_REQUEST,
                Json(error_response(&IssuerdError::InvalidDpopProof)),
            )
                .into_response();
        }
    };
    let dpop_jkt: Option<String> = dpop.proof.map(|p| p.jkt);
    let dpop_response_nonce = dpop.response_nonce;

    if let Err(e) = token_req.validate(&realm, &client) {
        warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "token request validation failed");
        return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
    }

    // RFC 9396 §6: `authorization_details` in the token request
    // narrows the details of the underlying grant — only the
    // authorization_code and refresh_token grants carry a RAR grant to narrow.
    // Every other grant has no RAR entitlement, so the parameter is refused
    // (like `invalid_scope`) rather than silently ignored.
    if token_req.authorization_details.is_some()
        && !matches!(token_req.grant_type, GrantType::AuthorizationCode | GrantType::RefreshToken)
    {
        let e = IssuerdError::InvalidAuthorizationDetails(
            "authorization_details is only supported for the authorization_code and refresh_token grants"
                .into(),
        );
        return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
    }

    let response = match token_req.grant_type {
        GrantType::AuthorizationCode => {
            let code = token_req.code.as_deref().unwrap_or("");
            let cache_key = format!("auth_code:{code}");
            // Atomic consume: an authorization code is single-use, so any
            // exchange attempt — successful or not — burns it.
            let code_data: Option<AuthCodeData> = match state.cache.get_and_delete(&cache_key).await
            {
                Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
                _ => None,
            };

            let code_data = match code_data {
                Some(d) => d,
                None => {
                    // Check if this code was previously used — if so, revoke the issued tokens
                    if let Ok(Some(bytes)) =
                        state.cache.get(&format!("used_auth_code:{code}")).await
                    {
                        if let Ok(used) = serde_json::from_slice::<UsedAuthCode>(&bytes) {
                            let now_secs = chrono::Utc::now().timestamp().max(0) as u64;
                            let access_ttl = used.access_exp.saturating_sub(now_secs);
                            if access_ttl > 0 {
                                let _ = state
                                    .cache
                                    .set(
                                        &format!("revoked:{}", used.access_token),
                                        vec![1],
                                        Some(std::time::Duration::from_secs(access_ttl)),
                                    )
                                    .await;
                            }
                            if let (Some(rt), Some(refresh_exp)) =
                                (used.refresh_token.as_ref(), used.refresh_exp)
                            {
                                let refresh_ttl = refresh_exp.saturating_sub(now_secs);
                                if refresh_ttl > 0 {
                                    let _ = state
                                        .cache
                                        .set(
                                            &format!("revoked_refresh:{rt}"),
                                            vec![1],
                                            Some(std::time::Duration::from_secs(refresh_ttl)),
                                        )
                                        .await;
                                }
                            }
                        }
                    }
                    warn!(realm = %realm_id, client_id = %client.client_id, "authorization code reuse detected — revoking previously issued tokens");
                    let mut details = std::collections::HashMap::new();
                    details.insert("grant_type".to_string(), "authorization_code".to_string());
                    emit_oidc_event(
                        &state,
                        &realm_id,
                        EventType::CodeToTokenError,
                        &ip,
                        Some(client.id.clone()),
                        None,
                        None,
                        Some("invalid_grant".to_string()),
                        details,
                    )
                    .await;
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            // RFC 6749 §4.1.3 / OIDC Core 3.1.3.3: the code must have been
            // issued to the client that is redeeming it.
            if code_data.client_id != client.client_id.to_string() {
                warn!(realm = %realm_id, client_id = %client.client_id, "authorization code presented by wrong client");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }

            // Verify redirect_uri matches
            if let Some(ref redirect_uri) = token_req.redirect_uri {
                if redirect_uri.to_string() != code_data.redirect_uri {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            }

            // Verify PKCE if code_challenge was present
            if let Some(ref challenge) = code_data.code_challenge {
                let verifier = token_req.code_verifier.as_deref().unwrap_or("");
                if !verify_pkce(verifier, challenge.as_str(), code_data.code_challenge_method) {
                    warn!(realm = %realm_id, client_id = %client.client_id, "PKCE verification failed");
                    let mut details = std::collections::HashMap::new();
                    details.insert("grant_type".to_string(), "authorization_code".to_string());
                    let user_id = UserId::new(&code_data.user_id).ok();
                    let session_id =
                        code_data.session_id.as_deref().and_then(|s| SessionId::new(s).ok());
                    emit_oidc_event(
                        &state,
                        &realm_id,
                        EventType::CodeToTokenError,
                        &ip,
                        Some(client.id.clone()),
                        user_id,
                        session_id,
                        Some("invalid_grant".to_string()),
                        details,
                    )
                    .await;
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            }

            // Look up user
            let user_id = match UserId::new(&code_data.user_id) {
                Ok(id) => id,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };
            let user = match state.storage.get_user(&realm_id, &user_id).await {
                Ok(Some(u)) if u.enabled => u,
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            let session_id = code_data
                .session_id
                .as_deref()
                .and_then(|s| SessionId::new(s).ok())
                .unwrap_or_else(|| SessionId::new(issuerd_core::utils::generate_id()).unwrap());
            let auth_time = code_data.auth_time.unwrap_or_else(chrono::Utc::now);
            let scope = code_data.scope.clone();

            // RFC 9396 §6: the token request may narrow the
            // authorization details granted with the code; without it, the
            // granted set applies. Narrowing is exact element containment
            // (no type-specific comparison logic exists).
            let authorization_details = match &token_req.authorization_details {
                None => code_data.authorization_details.clone(),
                Some(requested) => {
                    let granted = code_data.authorization_details.clone().unwrap_or_default();
                    if issuerd_protocol::authorization::authorization_details_is_subset(
                        requested, &granted,
                    ) {
                        Some(requested.clone())
                    } else {
                        let e = IssuerdError::InvalidAuthorizationDetails(
                            "requested authorization_details exceed the details granted with the code"
                                .into(),
                        );
                        return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
                    }
                }
            };

            // Create and store session for auth code grant
            let redirect_uri = match issuerd_core::RedirectUri::new(code_data.redirect_uri.clone())
            {
                Ok(uri) => Some(uri),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };
            let new_client_session = issuerd_core::ClientSession {
                id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id()).unwrap(),
                client_id: client.id.clone(),
                session_id: session_id.clone(),
                redirect_uri,
                state: code_data.state.clone(),
                auth_method: AuthMethod::Password,
                timestamp: chrono::Utc::now(),
            };
            // The login ceremony (password form, remember-cookie re-auth,
            // SSO resume) already persisted the session this code points at,
            // with its fields (remember-me, login IP, auth time) set there.
            // Redemption must attach/refresh, never re-create: a blind create
            // clobbers those fields, drops previously attached client
            // sessions, and violates the sessions table's primary key on
            // PostgreSQL.
            let session = match state.storage.get_user_session(&realm_id, &session_id).await {
                Ok(Some(mut session)) => {
                    if !session.clients.iter().any(|cs| cs.client_id == client.id) {
                        session.clients.push(new_client_session);
                    }
                    session.last_session_refresh = chrono::Utc::now();
                    if let Err(resp) = persist_session(&state, &realm_id, &session, true).await {
                        return resp;
                    }
                    session
                }
                _ => {
                    // No ceremony session (direct code issuance paths): create
                    // it fresh.
                    let session = issuerd_core::UserSession {
                        id: session_id.clone(),
                        realm_id: realm_id.clone(),
                        user_id: user.id.clone(),
                        login_username: user.username.clone(),
                        auth_method: AuthMethod::Password,
                        remember_me: false,
                        offline: false,
                        ip_address: ip,
                        started: chrono::Utc::now(),
                        last_session_refresh: chrono::Utc::now(),
                        auth_time,
                        impersonator: None,
                        clients: vec![new_client_session],
                    };
                    if let Err(resp) = persist_session(&state, &realm_id, &session, false).await {
                        return resp;
                    }
                    session
                }
            };

            // An `offline_access` grant additionally mints a
            // separate offline session (Keycloak's `createOrUpdateOfflineSession`
            // parity) that backs the offline refresh token. It is a distinct
            // session row (Keycloak reuses the online session's id in a
            // separate store; we key all sessions in one table, so the
            // offline session gets its own id) and it survives SSO session
            // expiry and browser logout. The issued tokens point at it.
            let offline = scope.iter().any(|s| s == issuerd_core::OFFLINE_ACCESS_SCOPE);
            let token_session_id = if offline {
                let offline_session_id =
                    SessionId::new(issuerd_core::utils::generate_id()).unwrap();
                let offline_session = issuerd_core::UserSession {
                    id: offline_session_id.clone(),
                    realm_id: realm_id.clone(),
                    user_id: user.id.clone(),
                    login_username: user.username.clone(),
                    auth_method: AuthMethod::Password,
                    remember_me: session.remember_me,
                    offline: true,
                    ip_address: ip,
                    started: chrono::Utc::now(),
                    last_session_refresh: chrono::Utc::now(),
                    auth_time,
                    impersonator: None,
                    clients: session
                        .clients
                        .iter()
                        .map(|cs| issuerd_core::ClientSession {
                            id: issuerd_core::ClientSessionId::new(
                                issuerd_core::utils::generate_id(),
                            )
                            .unwrap(),
                            session_id: offline_session_id.clone(),
                            ..cs.clone()
                        })
                        .collect(),
                };
                if let Err(resp) = persist_session(&state, &realm_id, &offline_session, false).await
                {
                    return resp;
                }
                offline_session_id
            } else {
                session_id.clone()
            };

            let overlay = crate::claims::build_claims_overlay(
                &state,
                &realm_id,
                Some(&client),
                &user,
                &scope,
                issuerd_core::ClaimTarget::AccessToken,
            )
            .await
            .unwrap_or_default();
            // Bind the issued tokens to the DPoP proof key.
            let overlay = crate::dpop::bind_cnf_overlay(Some(overlay), dpop_jkt.as_deref());
            // Attach the granted (or narrowed) RAR authorization
            // details to the access token.
            let overlay = crate::claims::bind_authorization_details_overlay(
                overlay,
                authorization_details.as_deref(),
            );

            let access_token = match state
                .token_manager
                .issue_access_token_with_roles(
                    &user,
                    &client,
                    &realm,
                    &scope,
                    &token_session_id,
                    None,
                    code_data.claims.clone(),
                    overlay,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    error!(realm = %realm_id, user_id = %user.id, error = %e, "failed to issue access token");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e)))
                        .into_response();
                }
            };

            let refresh_token = match state
                .token_manager
                .issue_refresh_token(
                    &user,
                    &client,
                    &realm,
                    &token_session_id,
                    scope.as_slice(),
                    offline,
                    dpop_jkt.as_deref(),
                    // The refresh token carries the granted (not narrowed)
                    // details: narrowing at redemption only restricts the
                    // access token (RFC 9396 §6.1).
                    code_data.authorization_details.as_deref(),
                )
                .await
            {
                Ok(t) => Some(t.token),
                Err(e) => {
                    warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "refresh token issuance failed; omitting from response");
                    None
                }
            };

            let id_token = if scope.contains(&"openid".to_string()) {
                match state
                    .token_manager
                    .issue_id_token(
                        &user,
                        &client,
                        &realm,
                        code_data.nonce.as_deref(),
                        auth_time,
                        &token_session_id,
                        Some(&access_token),
                        Some(code),
                        Some(&code_data.acr_values),
                        // Code flow: userinfo claims via the userinfo endpoint.
                        None,
                    )
                    .await
                {
                    Ok(t) => Some(t.token),
                    Err(e) => {
                        warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "ID token issuance failed; omitting from response");
                        None
                    }
                }
            } else {
                None
            };

            let resp = TokenResponse {
                access_token: access_token.token.clone(),
                token_type: crate::dpop::token_type(dpop_jkt.is_some()),
                expires_in: realm.access_token_lifespan.get(),
                refresh_token: refresh_token.clone(),
                id_token,
                scope: Some(scope.join(" ")),
                issued_token_type: None,
                // RFC 9396 §7: echo the details assigned to the access token.
                authorization_details: authorization_details.clone(),
            };

            // Store mapping so we can revoke tokens if the code is reused.
            // The entry (and the revocation markers derived from it) must
            // outlive the issued tokens, so the TTL is sized from token
            // expiry rather than a fixed window.
            let now_secs = chrono::Utc::now().timestamp().max(0) as u64;
            let access_exp = now_secs + realm.access_token_lifespan.get();
            let refresh_lifespan = if offline {
                realm.offline_session_idle_timeout.get()
            } else {
                realm.refresh_token_lifespan.get()
            };
            let refresh_exp = refresh_token.as_ref().map(|_| now_secs + refresh_lifespan);
            let used_code_data = UsedAuthCode {
                access_token: access_token.token,
                refresh_token,
                access_exp,
                refresh_exp,
            };
            let used_code_ttl = std::cmp::max(access_exp, refresh_exp.unwrap_or(0)) - now_secs;
            let _ = state
                .cache
                .set(
                    &format!("used_auth_code:{code}"),
                    serde_json::to_vec(&used_code_data).unwrap(),
                    Some(std::time::Duration::from_secs(used_code_ttl)),
                )
                .await;

            info!(realm = %realm_id, client_id = %client.client_id, user_id = %user.id, grant_type = "authorization_code", "token issued");
            let mut details = std::collections::HashMap::new();
            details.insert("grant_type".to_string(), "authorization_code".to_string());
            details.insert("username".to_string(), user.username.to_string());
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CodeToToken,
                &ip,
                Some(client.id.clone()),
                Some(user.id.clone()),
                Some(token_session_id.clone()),
                None,
                details,
            )
            .await;

            token_response(resp)
        }
        GrantType::Password => {
            // Resource Owner Password Credentials grant
            let username = token_req.username.as_deref().unwrap_or("");
            let password = token_req.password.as_deref().unwrap_or("");

            let user = match state.storage.get_user_by_username(&realm_id, username).await {
                Ok(Some(u)) if u.enabled => u,
                _ => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            // Brute-force lockout, keyed like the browser login flow
            // (canonical username + source IP). Realms without brute-force
            // protection skip failure tracking entirely.
            let brute_force = realm
                .brute_force_protected
                .then(|| issuerd_auth_flow::login_failures::LoginFailureConfig::from_realm(&realm));
            let ip_key = ip.to_string();
            if brute_force.is_some() {
                let locked = state
                    .login_failure_tracker
                    .is_temporarily_locked(
                        &realm_id,
                        user.username.as_str(),
                        &ip_key,
                        state.cache.as_ref(),
                    )
                    .await
                    .unwrap_or(false);
                if locked {
                    warn!(realm = %realm_id, username = %user.username, "password grant rejected: account temporarily locked");
                    emit_oidc_event(
                        &state,
                        &realm_id,
                        EventType::LoginError,
                        &ip,
                        Some(client.id.clone()),
                        Some(user.id.clone()),
                        None,
                        Some("temporarily_locked".to_string()),
                        std::collections::HashMap::new(),
                    )
                    .await;
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            }

            // Verify password using built-in authenticator logic
            let creds = match state
                .storage
                .get_credentials(&realm_id, &user.id, issuerd_core::CredentialType::Password)
                .await
            {
                Ok(c) => c,
                _ => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            // Federated user: validate against the external directory first,
            // mirroring the browser flow (UsernamePasswordAuthenticator): an
            // active rejection is final (no local fallback), while a provider
            // error or a dead link falls back to local credentials.
            let mut matched = false;
            let mut federated_rejected = false;
            if let Some(ref link) = user.federation_link {
                match state.federation_manager.providers_for_realm(&realm_id).await {
                    Ok(providers) => {
                        for provider in providers {
                            if provider.id() == *link {
                                match provider.validate_password(username, password).await {
                                    Ok(true) => matched = true,
                                    Ok(false) => federated_rejected = true,
                                    Err(e) => {
                                        warn!(realm = %realm_id, username = %user.username, error = %e, "password grant: federation validation error; falling back to local password");
                                    }
                                }
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(realm = %realm_id, username = %user.username, error = %e, "password grant: federation manager error; falling back to local password");
                    }
                }
            }

            if !matched && !federated_rejected {
                use argon2::{Argon2, PasswordHash, PasswordVerifier};
                for cred in &creds {
                    let hash_str = match String::from_utf8(cred.secret_data.clone()) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let parsed = match PasswordHash::new(&hash_str) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok() {
                        matched = true;
                        break;
                    }
                }
            }

            if !matched {
                warn!(realm = %realm_id, username = %issuerd_core::utils::sanitize_log_str(username), ip = %ip, "password grant failed: invalid user credentials");
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
                emit_oidc_event(
                    &state,
                    &realm_id,
                    EventType::LoginError,
                    &ip,
                    Some(client.id.clone()),
                    Some(user.id.clone()),
                    None,
                    Some("invalid_user_credentials".to_string()),
                    std::collections::HashMap::new(),
                )
                .await;
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }

            // Successful authentication clears the failure counter.
            if brute_force.is_some() {
                let _ = state
                    .login_failure_tracker
                    .reset_failures(
                        &realm_id,
                        user.username.as_str(),
                        &ip_key,
                        state.cache.as_ref(),
                    )
                    .await;
            }

            // ROPC cannot render required-action pages: an account with
            // pending actions (e.g. temporary password, unverified email) is
            // rejected so the user is pushed through the browser flow, which
            // can. Keycloak parity: invalid_grant "Account is not fully set up".
            if !user.required_actions.is_empty() {
                warn!(realm = %realm_id, username = %user.username, actions = ?user.required_actions, "password grant rejected: required actions pending");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "Account is not fully set up",
                    })),
                )
                    .into_response();
            }

            let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
            let scope = token_req.scope.clone();
            // `offline_access` in the granted scopes makes this an
            // offline session backing an offline (`typ: Offline`) refresh
            // token with its own idle window.
            let offline = scope.contains(issuerd_core::OFFLINE_ACCESS_SCOPE);

            // Create and store session for password grant
            let session = issuerd_core::UserSession {
                id: session_id.clone(),
                realm_id: realm_id.clone(),
                user_id: user.id.clone(),
                login_username: user.username.clone(),
                auth_method: AuthMethod::Password,
                remember_me: false,
                offline,
                ip_address: ip,
                started: chrono::Utc::now(),
                last_session_refresh: chrono::Utc::now(),
                auth_time: chrono::Utc::now(),
                impersonator: None,
                clients: vec![issuerd_core::ClientSession {
                    id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id())
                        .unwrap(),
                    client_id: client.id.clone(),
                    session_id: session_id.clone(),
                    redirect_uri: None,
                    state: None,
                    auth_method: AuthMethod::Password,
                    timestamp: chrono::Utc::now(),
                }],
            };
            if let Err(resp) = persist_session(&state, &realm_id, &session, false).await {
                return resp;
            }

            let overlay = crate::claims::build_claims_overlay(
                &state,
                &realm_id,
                Some(&client),
                &user,
                scope.as_slice(),
                issuerd_core::ClaimTarget::AccessToken,
            )
            .await
            .unwrap_or_default();
            // Bind the issued tokens to the DPoP proof key.
            let overlay = crate::dpop::bind_cnf_overlay(Some(overlay), dpop_jkt.as_deref());

            let access_token = match state
                .token_manager
                .issue_access_token_with_roles(
                    &user,
                    &client,
                    &realm,
                    scope.as_slice(),
                    &session_id,
                    None,
                    None,
                    overlay,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    error!(realm = %realm_id, user_id = %user.id, error = %e, "failed to issue access token");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e)))
                        .into_response();
                }
            };

            let refresh_token = match state
                .token_manager
                .issue_refresh_token(
                    &user,
                    &client,
                    &realm,
                    &session_id,
                    scope.as_slice(),
                    offline,
                    dpop_jkt.as_deref(),
                    None,
                )
                .await
            {
                Ok(t) => Some(t.token),
                Err(e) => {
                    warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "refresh token issuance failed; omitting from response");
                    None
                }
            };

            let id_token = if scope.contains("openid") {
                match state
                    .token_manager
                    .issue_id_token(
                        &user,
                        &client,
                        &realm,
                        None,
                        chrono::Utc::now(),
                        &session_id,
                        Some(&access_token),
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    Ok(t) => Some(t.token),
                    Err(e) => {
                        warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "ID token issuance failed; omitting from response");
                        None
                    }
                }
            } else {
                None
            };

            let resp = TokenResponse {
                access_token: access_token.token,
                token_type: crate::dpop::token_type(dpop_jkt.is_some()),
                expires_in: realm.access_token_lifespan.get(),
                refresh_token,
                id_token,
                scope: Some(scope.join(" ")),
                issued_token_type: None,
                authorization_details: None,
            };

            info!(realm = %realm_id, client_id = %client.client_id, user_id = %user.id, grant_type = "password", "token issued");
            let mut details = std::collections::HashMap::new();
            details.insert("grant_type".to_string(), "password".to_string());
            details.insert("username".to_string(), user.username.to_string());
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::CodeToToken,
                &ip,
                Some(client.id.clone()),
                Some(user.id.clone()),
                Some(session_id.clone()),
                None,
                details,
            )
            .await;

            token_response(resp)
        }
        GrantType::RefreshToken => {
            let refresh_token = token_req.refresh_token.as_deref().unwrap_or("");

            // Check revocation list
            let revoked = matches!(
                state.cache.get(&format!("revoked_refresh:{refresh_token}")).await,
                Ok(Some(_))
            );
            if revoked {
                warn!(realm = %realm_id, client_id = %client.client_id, "revoked refresh token presented");
                let mut details = std::collections::HashMap::new();
                details.insert("grant_type".to_string(), "refresh_token".to_string());
                emit_oidc_event(
                    &state,
                    &realm_id,
                    EventType::RefreshTokenError,
                    &ip,
                    Some(client.id.clone()),
                    None,
                    None,
                    Some("invalid_grant".to_string()),
                    details,
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }

            let validated = match state.token_service.validate_refresh_token(refresh_token) {
                Ok(v) => v,
                Err(e) => {
                    warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "refresh token validation failed");
                    let mut details = std::collections::HashMap::new();
                    details.insert("grant_type".to_string(), "refresh_token".to_string());
                    emit_oidc_event(
                        &state,
                        &realm_id,
                        EventType::RefreshTokenError,
                        &ip,
                        Some(client.id.clone()),
                        None,
                        None,
                        Some("invalid_grant".to_string()),
                        details,
                    )
                    .await;
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            // Refresh token client binding: reject if presented by a different client
            if validated.claims.aud.as_str() != client.client_id.as_str() {
                warn!(realm = %realm_id, client_id = %client.client_id, expected_aud = %validated.claims.aud.as_str(), "refresh token client binding mismatch");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }

            // DPoP (RFC 9449 §5.1): a bound refresh token may only
            // be redeemed together with a proof from the same key, and the
            // rotated tokens keep the binding ("slide"). An unbound token
            // presented with a valid proof becomes bound going forward.
            let dpop_jkt: Option<String> = match (
                validated.claims.cnf.as_ref().map(|c| &c.jkt),
                dpop_jkt,
            ) {
                (Some(bound), Some(proof)) if bound == &proof => Some(proof),
                (Some(_), Some(_)) => {
                    warn!(realm = %realm_id, client_id = %client.client_id, "DPoP proof key does not match the refresh token binding");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
                (Some(_), None) => {
                    warn!(realm = %realm_id, client_id = %client.client_id, "DPoP-bound refresh token presented without a proof");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
                (None, proof) => proof,
            };

            // Realm not_before: tokens issued before the realm's cutoff are
            // revoked wholesale (0 = no cutoff).
            if realm.not_before > 0 && validated.claims.iat < realm.not_before {
                warn!(realm = %realm_id, client_id = %client.client_id, "refresh token predates realm not_before cutoff");
                let mut details = std::collections::HashMap::new();
                details.insert("grant_type".to_string(), "refresh_token".to_string());
                emit_oidc_event(
                    &state,
                    &realm_id,
                    EventType::RefreshTokenError,
                    &ip,
                    Some(client.id.clone()),
                    None,
                    None,
                    Some("invalid_grant".to_string()),
                    details,
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }

            // Verify session still exists. Resolution is session-first:
            // pairwise refresh tokens carry a sector-scoped
            // `sub` that cannot be reversed to a user id, so the user is
            // loaded through the session (public `sub` values resolve to the
            // same user either way).
            let mut session =
                match state.storage.get_user_session(&realm_id, &validated.claims.sid).await {
                    Ok(Some(s)) => s,
                    _ => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "invalid_grant"})),
                        )
                            .into_response();
                    }
                };

            let user = match state.storage.get_user(&realm_id, &session.user_id).await {
                Ok(Some(u)) if u.enabled => u,
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            // Idle-timeout enforcement: offline sessions get the
            // realm's offline idle window — this is what lets an offline
            // refresh token outlive the SSO session it was born from.
            // Otherwise remembered sessions get the (longer) remember-me idle
            // window and plain sessions the SSO idle window. An idle-expired
            // session is deleted and rejected exactly like a missing one.
            let idle_secs = if session.offline {
                realm.offline_session_idle_timeout.get()
            } else if session.remember_me {
                realm.remember_me_session_idle_secs.get()
            } else {
                realm.sso_session_idle_timeout.get()
            };
            let idle = chrono::Duration::seconds(idle_secs as i64);
            if chrono::Utc::now() - session.last_session_refresh > idle {
                warn!(realm = %realm_id, session_id = %session.id, offline = session.offline, "refresh rejected: session idle timeout exceeded");
                let _ = state.storage.delete_user_session(&realm_id, &session.id).await;
                crate::session_cache::invalidate_session(&state, &realm_id, &session.id).await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }

            // A valid refresh extends the SSO idle window.
            session.last_session_refresh = chrono::Utc::now();
            let _ = state.storage.update_user_session(&realm_id, &session).await;

            let scope = if token_req.scope.is_empty() {
                validated.claims.scope.clone()
            } else {
                // RFC 6749 §6: the requested scope must not exceed the scope
                // originally granted with this refresh token.
                let granted = &validated.claims.scope;
                if token_req.scope.iter().any(|s| !granted.contains(s)) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_scope"})),
                    )
                        .into_response();
                }
                token_req.scope.clone()
            };

            // RFC 9396 §6: like scope, the refresh request may
            // narrow the grant's authorization details for the new access
            // token. The resource owner's authorization is unchanged (§6.1),
            // so the rotated refresh token keeps the original set.
            let granted_details = validated.claims.authorization_details.clone();
            let authorization_details = match &token_req.authorization_details {
                None => granted_details.clone(),
                Some(requested) => {
                    let granted = granted_details.clone().unwrap_or_default();
                    if issuerd_protocol::authorization::authorization_details_is_subset(
                        requested, &granted,
                    ) {
                        Some(requested.clone())
                    } else {
                        let e = IssuerdError::InvalidAuthorizationDetails(
                            "requested authorization_details exceed the granted details".into(),
                        );
                        return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response();
                    }
                }
            };

            // Rotate: the presented refresh token is revoked on successful
            // refresh (TTL = its remaining lifetime).
            {
                let now = issuerd_core::utils::now_secs() as i64;
                let remaining = validated.claims.exp.saturating_sub(now).max(0) as u64;
                let _ = state
                    .cache
                    .set(
                        &format!("revoked_refresh:{refresh_token}"),
                        vec![1],
                        Some(std::time::Duration::from_secs(remaining.max(1))),
                    )
                    .await;
            }

            let mut overlay = crate::claims::build_claims_overlay(
                &state,
                &realm_id,
                Some(&client),
                &user,
                scope.as_slice(),
                issuerd_core::ClaimTarget::AccessToken,
            )
            .await
            .unwrap_or_default();

            // An impersonated session keeps the `impersonator`
            // claim on refreshed tokens (the overlay is rebuilt from scratch,
            // so re-inject it from the persisted session).
            if let Some(ref impersonator) = session.impersonator {
                overlay.insert(
                    "impersonator".to_string(),
                    serde_json::Value::String(impersonator.to_string()),
                );
            }

            // Keep the DPoP binding on the rotated tokens.
            let overlay = crate::dpop::bind_cnf_overlay(Some(overlay), dpop_jkt.as_deref());
            // The (possibly narrowed) RAR authorization details.
            let overlay = crate::claims::bind_authorization_details_overlay(
                overlay,
                authorization_details.as_deref(),
            );

            let access_token = match state
                .token_manager
                .issue_access_token_with_roles(
                    &user,
                    &client,
                    &realm,
                    scope.as_slice(),
                    &session.id,
                    None,
                    None,
                    overlay,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    error!(realm = %realm_id, client_id = %client.client_id, error = %e, "failed to issue access token");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e)))
                        .into_response();
                }
            };

            // Issue new refresh token (rotation); the offline class of the
            // session is preserved on the rotated token. The
            // grant's original scope and authorization details are carried
            // over unchanged (RFC 6749 §6 / RFC 9396 §6.1: narrowing a
            // refresh request restricts only the new access token — the
            // rotated refresh token keeps the original grant, so narrowing
            // does not accumulate across rotations).
            let new_refresh_token = match state
                .token_manager
                .issue_refresh_token(
                    &user,
                    &client,
                    &realm,
                    &session.id,
                    validated.claims.scope.as_slice(),
                    session.offline,
                    dpop_jkt.as_deref(),
                    granted_details.as_deref(),
                )
                .await
            {
                Ok(t) => Some(t.token),
                Err(e) => {
                    warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "refresh token issuance failed; omitting from response");
                    None
                }
            };

            let id_token = if scope.contains("openid") {
                match state
                    .token_manager
                    .issue_id_token(
                        &user,
                        &client,
                        &realm,
                        None,
                        session.auth_time,
                        &session.id,
                        Some(&access_token),
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    Ok(t) => Some(t.token),
                    Err(e) => {
                        warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "ID token issuance failed; omitting from response");
                        None
                    }
                }
            } else {
                None
            };

            let resp = TokenResponse {
                access_token: access_token.token,
                token_type: crate::dpop::token_type(dpop_jkt.is_some()),
                expires_in: realm.access_token_lifespan.get(),
                refresh_token: new_refresh_token,
                id_token,
                scope: Some(scope.join(" ")),
                issued_token_type: None,
                // RFC 9396 §7: echo the details assigned to the access token.
                authorization_details: authorization_details.clone(),
            };

            debug!(realm = %realm_id, client_id = %client.client_id, user_id = %user.id, grant_type = "refresh_token", "token refreshed");
            let mut details = std::collections::HashMap::new();
            details.insert("grant_type".to_string(), "refresh_token".to_string());
            details.insert("username".to_string(), user.username.to_string());
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::RefreshToken,
                &ip,
                Some(client.id.clone()),
                Some(user.id.clone()),
                Some(session.id.clone()),
                None,
                details,
            )
            .await;

            token_response(resp)
        }
        GrantType::ClientCredentials => {
            // Public clients may not use this grant. Confidential clients were already
            // authenticated by the shared secret check before grant dispatch.
            if client.public_client {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "unauthorized_client"})),
                )
                    .into_response();
            }

            let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
            let scope = token_req.scope.clone();

            // Service accounts: when enabled on the client, the
            // grant is backed by the dedicated `service-account-{client_id}`
            // user — its role mappings flow into the token via the claims
            // overlay, and `sub` is that user's id (Keycloak behavior).
            // Otherwise the legacy synthetic shape is kept (sub = client_id,
            // no role claims).
            let service_account = if client.service_accounts_enabled {
                let username = crate::claims::service_account_username(&client);
                match state.storage.get_user_by_username(&realm_id, &username).await {
                    Ok(Some(user)) => Some(user),
                    Ok(None) => {
                        warn!(realm = %realm_id, client_id = %client.client_id, "service accounts enabled but no service-account user found; falling back to synthetic token");
                        None
                    }
                    Err(e) => {
                        error!(realm = %realm_id, error = %e, "service-account lookup failed");
                        None
                    }
                }
            } else {
                None
            };

            // Synthetic user for client credentials (sub = client_id)
            let synthetic_user = issuerd_core::User {
                id: issuerd_core::UserId::new(client.client_id.as_str()).unwrap(),
                realm_id: realm_id.clone(),
                username: Username::new(client.client_id.as_str())
                    .expect("client client_id must be valid"),
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
            let (token_user, overlay) = match &service_account {
                Some(sa_user) => {
                    let overlay = crate::claims::build_claims_overlay(
                        &state,
                        &realm_id,
                        Some(&client),
                        sa_user,
                        scope.as_slice(),
                        issuerd_core::ClaimTarget::AccessToken,
                    )
                    .await
                    .unwrap_or_default();
                    (sa_user.clone(), Some(overlay))
                }
                None => (synthetic_user, None),
            };
            // Bind the issued token to the DPoP proof key (the
            // synthetic-user arm has no mapper overlay; binding creates one).
            let overlay = crate::dpop::bind_cnf_overlay(overlay, dpop_jkt.as_deref());

            let access_token = match state
                .token_manager
                .issue_access_token_with_roles(
                    &token_user,
                    &client,
                    &realm,
                    scope.as_slice(),
                    &session_id,
                    None,
                    None,
                    overlay,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    error!(realm = %realm_id, client_id = %client.client_id, error = %e, "failed to issue access token");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e)))
                        .into_response();
                }
            };

            let resp = TokenResponse {
                access_token: access_token.token,
                token_type: crate::dpop::token_type(dpop_jkt.is_some()),
                expires_in: realm.access_token_lifespan.get(),
                refresh_token: None,
                id_token: None,
                scope: Some(scope.join(" ")),
                issued_token_type: None,
                authorization_details: None,
            };

            debug!(realm = %realm_id, client_id = %client.client_id, user_id = %token_user.id, grant_type = "client_credentials", "token issued");
            let mut details = std::collections::HashMap::new();
            details.insert("grant_type".to_string(), "client_credentials".to_string());
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::ClientLogin,
                &ip,
                Some(client.id.clone()),
                Some(token_user.id.clone()),
                Some(session_id.clone()),
                None,
                details,
            )
            .await;

            token_response(resp)
        }
        GrantType::DeviceCode => {
            let device_code = token_req.device_code.as_deref().unwrap_or("");
            let cache_key = issuerd_cluster::cache_keys::device_code(device_code);

            let mut code_data: DeviceCodeData = match state.cache.get(&cache_key).await {
                Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
                    Ok(d) => d,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "expired_token"})),
                        )
                            .into_response();
                    }
                },
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "expired_token"})),
                    )
                        .into_response();
                }
            };

            // Slow-down check: if polled too recently, return slow_down
            let now = chrono::Utc::now();
            if let Some(last_polled) = code_data.last_polled_at {
                let interval = chrono::Duration::seconds(5);
                if now - last_polled < interval {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "slow_down"})),
                    )
                        .into_response();
                }
            }
            code_data.last_polled_at = Some(now);

            // Absolute expiry: polling must not extend the code's lifetime.
            let Some(remaining) = remaining_ttl(code_data.expires_at) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "expired_token"})),
                )
                    .into_response();
            };

            // RFC 8628 §3.4: only the client that initiated the device flow
            // may redeem its device code.
            if code_data.client_id != client.client_id.to_string() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }

            // Update last_polled_at in cache, preserving the remaining TTL
            let cache_value = serde_json::to_vec(&code_data).unwrap();
            let _ = state.cache.set(&cache_key, cache_value.clone(), Some(remaining)).await;
            let _ = state
                .cache
                .set(
                    &issuerd_cluster::cache_keys::user_code(&code_data.user_code),
                    cache_value,
                    Some(remaining),
                )
                .await;

            if !code_data.authorized {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "authorization_pending"})),
                )
                    .into_response();
            }

            // User authorized — issue tokens
            let user_id = match code_data.user_id {
                Some(ref uid) => match UserId::new(uid) {
                    Ok(id) => id,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "invalid_grant"})),
                        )
                            .into_response();
                    }
                },
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            let user = match state.storage.get_user(&realm_id, &user_id).await {
                Ok(Some(u)) if u.enabled => u,
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            let device_client_id = match ClientIdentifier::new(&code_data.client_id) {
                Ok(id) => id,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };
            let device_client =
                match state.storage.get_client_by_client_id(&realm_id, &device_client_id).await {
                    Ok(Some(c)) => c,
                    _ => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "invalid_grant"})),
                        )
                            .into_response();
                    }
                };

            // Atomic consume: an approved device code is single-use, so any
            // poll that reaches this point burns it. Only the first
            // concurrent consumer observes the entry; the rest get
            // `expired_token`, matching an unknown/expired device code.
            let consumed: Option<DeviceCodeData> =
                match state.cache.get_and_delete(&cache_key).await {
                    Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
                    _ => None,
                };
            let Some(consumed) = consumed else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "expired_token"})),
                )
                    .into_response();
            };
            // The consumed entry may not be the exact write this poller read
            // (a concurrent approval/pacing write can land between the read
            // and the consume) — re-validate the payload before issuing:
            // client binding, user binding, still authorized, not expired.
            if consumed.client_id != client.client_id.to_string()
                || consumed.user_id != code_data.user_id
                || !consumed.authorized
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }
            if remaining_ttl(consumed.expires_at).is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "expired_token"})),
                )
                    .into_response();
            }
            // Burn the user-code mirror entry too (best effort — the device
            // code entry above was the redeemable one).
            let _ = state
                .cache
                .delete(&issuerd_cluster::cache_keys::user_code(&consumed.user_code))
                .await;

            let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
            let scope = consumed.scope.clone();
            let offline = scope.iter().any(|s| s == issuerd_core::OFFLINE_ACCESS_SCOPE);

            let session = issuerd_core::UserSession {
                id: session_id.clone(),
                realm_id: realm_id.clone(),
                user_id: user.id.clone(),
                login_username: user.username.clone(),
                auth_method: AuthMethod::Password,
                remember_me: false,
                offline,
                ip_address: ip,
                started: chrono::Utc::now(),
                last_session_refresh: chrono::Utc::now(),
                auth_time: chrono::Utc::now(),
                impersonator: None,
                clients: vec![issuerd_core::ClientSession {
                    id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id())
                        .unwrap(),
                    client_id: device_client.id.clone(),
                    session_id: session_id.clone(),
                    redirect_uri: None,
                    state: None,
                    auth_method: AuthMethod::Password,
                    timestamp: chrono::Utc::now(),
                }],
            };
            if let Err(resp) = persist_session(&state, &realm_id, &session, false).await {
                return resp;
            }

            let overlay = crate::claims::build_claims_overlay(
                &state,
                &realm_id,
                Some(&device_client),
                &user,
                scope.as_slice(),
                issuerd_core::ClaimTarget::AccessToken,
            )
            .await
            .unwrap_or_default();
            // Bind the issued tokens to the DPoP proof key.
            let overlay = crate::dpop::bind_cnf_overlay(Some(overlay), dpop_jkt.as_deref());

            let access_token = match state
                .token_manager
                .issue_access_token_with_roles(
                    &user,
                    &device_client,
                    &realm,
                    scope.as_slice(),
                    &session_id,
                    None,
                    None,
                    overlay,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e)))
                        .into_response();
                }
            };

            let refresh_token = match state
                .token_manager
                .issue_refresh_token(
                    &user,
                    &device_client,
                    &realm,
                    &session_id,
                    &scope,
                    offline,
                    dpop_jkt.as_deref(),
                    None,
                )
                .await
            {
                Ok(t) => Some(t.token),
                Err(e) => {
                    warn!(realm = %realm_id, client_id = %device_client.client_id, error = %e, "refresh token issuance failed; omitting from response");
                    None
                }
            };

            let id_token = if scope.contains(&"openid".to_string()) {
                match state
                    .token_manager
                    .issue_id_token(
                        &user,
                        &device_client,
                        &realm,
                        None,
                        chrono::Utc::now(),
                        &session_id,
                        Some(&access_token),
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    Ok(t) => Some(t.token),
                    Err(e) => {
                        warn!(realm = %realm_id, client_id = %device_client.client_id, error = %e, "ID token issuance failed; omitting from response");
                        None
                    }
                }
            } else {
                None
            };

            let resp = TokenResponse {
                access_token: access_token.token,
                token_type: crate::dpop::token_type(dpop_jkt.is_some()),
                expires_in: realm.access_token_lifespan.get(),
                refresh_token,
                id_token,
                scope: Some(scope.join(" ")),
                issued_token_type: None,
                authorization_details: None,
            };

            token_response(resp)
        }
        GrantType::Ciba => {
            let auth_req_id = token_req.auth_req_id.as_deref().unwrap_or("");
            let cache_key = issuerd_cluster::cache_keys::ciba_auth_req(auth_req_id);

            let mut req_data: CibaAuthReqData = match state.cache.get(&cache_key).await {
                Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
                    Ok(d) => d,
                    Err(_) => {
                        emit_ciba_poll_error(
                            &state,
                            &realm_id,
                            &ip,
                            &client,
                            None,
                            "expired_token",
                        )
                        .await;
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "expired_token"})),
                        )
                            .into_response();
                    }
                },
                _ => {
                    emit_ciba_poll_error(&state, &realm_id, &ip, &client, None, "expired_token")
                        .await;
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "expired_token"})),
                    )
                        .into_response();
                }
            };

            // Slow-down check: if polled too recently, return slow_down
            let now = chrono::Utc::now();
            if let Some(last_polled) = req_data.last_polled_at {
                let interval = chrono::Duration::seconds(5);
                if now - last_polled < interval {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "slow_down"})),
                    )
                        .into_response();
                }
            }
            req_data.last_polled_at = Some(now);

            // Absolute expiry: polling must not extend the request's lifetime.
            let Some(remaining) = remaining_ttl(req_data.expires_at) else {
                emit_ciba_poll_error(
                    &state,
                    &realm_id,
                    &ip,
                    &client,
                    req_data.user_id.as_deref(),
                    "expired_token",
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "expired_token"})),
                )
                    .into_response();
            };

            // CIBA §7.1: only the client that initiated the backchannel
            // request may redeem its auth_req_id.
            if req_data.client_id != client.client_id.to_string() {
                emit_ciba_poll_error(
                    &state,
                    &realm_id,
                    &ip,
                    &client,
                    req_data.user_id.as_deref(),
                    "invalid_grant",
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }

            // Update last_polled_at in cache, preserving the remaining TTL
            let cache_value = serde_json::to_vec(&req_data).unwrap();
            let _ = state.cache.set(&cache_key, cache_value, Some(remaining)).await;

            if req_data.denied {
                emit_ciba_poll_error(
                    &state,
                    &realm_id,
                    &ip,
                    &client,
                    req_data.user_id.as_deref(),
                    "access_denied",
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "access_denied"})),
                )
                    .into_response();
            }

            // authorization_pending is normal protocol chatter, not an audit
            // event — the decision was already recorded at the approve
            // endpoint.
            if !req_data.authorized {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "authorization_pending"})),
                )
                    .into_response();
            }

            // User authorized — issue tokens
            let user_id = match req_data.user_id {
                Some(ref uid) => match UserId::new(uid) {
                    Ok(id) => id,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "invalid_grant"})),
                        )
                            .into_response();
                    }
                },
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            let user = match state.storage.get_user(&realm_id, &user_id).await {
                Ok(Some(u)) if u.enabled => u,
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };

            let ciba_client_id = match ClientIdentifier::new(&req_data.client_id) {
                Ok(id) => id,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_grant"})),
                    )
                        .into_response();
                }
            };
            let ciba_client =
                match state.storage.get_client_by_client_id(&realm_id, &ciba_client_id).await {
                    Ok(Some(c)) => c,
                    _ => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "invalid_grant"})),
                        )
                            .into_response();
                    }
                };

            // Atomic consume: an approved auth_req_id is single-use, so any
            // poll that reaches this point burns it. Only the first
            // concurrent consumer observes the entry; the rest get
            // `expired_token`, matching an unknown/expired auth_req_id.
            let consumed: Option<CibaAuthReqData> =
                match state.cache.get_and_delete(&cache_key).await {
                    Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
                    _ => None,
                };
            let Some(consumed) = consumed else {
                emit_ciba_poll_error(
                    &state,
                    &realm_id,
                    &ip,
                    &client,
                    req_data.user_id.as_deref(),
                    "expired_token",
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "expired_token"})),
                )
                    .into_response();
            };
            // The consumed entry may not be the exact write this poller read
            // (a concurrent approve/deny or pacing write can land between the
            // read and the consume) — re-validate the payload before issuing:
            // client binding, user binding, still authorized, not expired.
            if consumed.client_id != client.client_id.to_string()
                || consumed.user_id != req_data.user_id
                || !consumed.authorized
                || consumed.denied
            {
                emit_ciba_poll_error(
                    &state,
                    &realm_id,
                    &ip,
                    &client,
                    req_data.user_id.as_deref(),
                    "invalid_grant",
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }
            if remaining_ttl(consumed.expires_at).is_none() {
                emit_ciba_poll_error(
                    &state,
                    &realm_id,
                    &ip,
                    &client,
                    req_data.user_id.as_deref(),
                    "expired_token",
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "expired_token"})),
                )
                    .into_response();
            }

            let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
            let scope = consumed.scope.clone();
            let offline = scope.iter().any(|s| s == issuerd_core::OFFLINE_ACCESS_SCOPE);

            let session = issuerd_core::UserSession {
                id: session_id.clone(),
                realm_id: realm_id.clone(),
                user_id: user.id.clone(),
                login_username: user.username.clone(),
                auth_method: AuthMethod::Ciba,
                remember_me: false,
                offline,
                ip_address: ip,
                started: chrono::Utc::now(),
                last_session_refresh: chrono::Utc::now(),
                auth_time: chrono::Utc::now(),
                impersonator: None,
                clients: vec![issuerd_core::ClientSession {
                    id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id())
                        .unwrap(),
                    client_id: ciba_client.id.clone(),
                    session_id: session_id.clone(),
                    redirect_uri: None,
                    state: None,
                    auth_method: AuthMethod::Ciba,
                    timestamp: chrono::Utc::now(),
                }],
            };
            if let Err(resp) = persist_session(&state, &realm_id, &session, false).await {
                return resp;
            }

            let overlay = crate::claims::build_claims_overlay(
                &state,
                &realm_id,
                Some(&ciba_client),
                &user,
                scope.as_slice(),
                issuerd_core::ClaimTarget::AccessToken,
            )
            .await
            .unwrap_or_default();
            // Bind the issued tokens to the DPoP proof key.
            let overlay = crate::dpop::bind_cnf_overlay(Some(overlay), dpop_jkt.as_deref());

            let access_token = match state
                .token_manager
                .issue_access_token_with_roles(
                    &user,
                    &ciba_client,
                    &realm,
                    scope.as_slice(),
                    &session_id,
                    None,
                    None,
                    overlay,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e)))
                        .into_response();
                }
            };

            let refresh_token = match state
                .token_manager
                .issue_refresh_token(
                    &user,
                    &ciba_client,
                    &realm,
                    &session_id,
                    &scope,
                    offline,
                    dpop_jkt.as_deref(),
                    None,
                )
                .await
            {
                Ok(t) => Some(t.token),
                Err(e) => {
                    warn!(realm = %realm_id, client_id = %ciba_client.client_id, error = %e, "refresh token issuance failed; omitting from response");
                    None
                }
            };

            let id_token = if scope.contains(&"openid".to_string()) {
                match state
                    .token_manager
                    .issue_id_token(
                        &user,
                        &ciba_client,
                        &realm,
                        None,
                        chrono::Utc::now(),
                        &session_id,
                        Some(&access_token),
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    Ok(t) => Some(t.token),
                    Err(e) => {
                        warn!(realm = %realm_id, client_id = %ciba_client.client_id, error = %e, "ID token issuance failed; omitting from response");
                        None
                    }
                }
            } else {
                None
            };

            let resp = TokenResponse {
                access_token: access_token.token,
                token_type: crate::dpop::token_type(dpop_jkt.is_some()),
                expires_in: realm.access_token_lifespan.get(),
                refresh_token,
                id_token,
                scope: Some(scope.join(" ")),
                issued_token_type: None,
                authorization_details: None,
            };

            // The user's out-of-band approval materializes into a session and
            // tokens here — the same audit weight as a browser login.
            let mut details = std::collections::HashMap::new();
            details.insert("method".to_string(), "ciba".to_string());
            details.insert("username".to_string(), user.username.to_string());
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::Login,
                &ip,
                Some(ciba_client.id.clone()),
                Some(user.id.clone()),
                Some(session_id.clone()),
                None,
                details,
            )
            .await;

            token_response(resp)
        }
        GrantType::TokenExchange => {
            crate::routes::token_exchange::token_exchange_grant(
                &state,
                &realm,
                &client,
                &token_req,
                &ip,
                dpop_jkt.as_deref(),
            )
            .await
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unsupported_grant_type"})),
        )
            .into_response(),
    };
    // RFC 9449 §8/§9: when the nonce mode issued a fresh server nonce for a
    // proof-carrying request, advertise it on the response so the client
    // echoes it in its next proof. (Early error returns above skip the
    // header — RFC-required only on `use_dpop_nonce` responses, which carry
    // it at the verification site.)
    crate::dpop::with_nonce_header(response, dpop_response_nonce.as_deref())
}

fn verify_pkce(verifier: &str, challenge: &str, method: Option<PkceCodeChallengeMethod>) -> bool {
    issuerd_protocol::pkce::PkceVerifier::verify(verifier, challenge, method).is_ok()
}

/// Check whether an access token's underlying user session has been deleted.
///
/// Returns `true` if the token should be treated as invalid because the session
/// no longer exists in storage. Returns `false` if the session is still present,
/// or if the token is not bound to a user session (e.g. client credentials).
///
/// The existence check goes through the session-validity cache
/// (`crate::session_cache::session_snapshot`); invalidation on session
/// delete keeps revocation immediate, and the positive TTL bounds the rest.
pub(crate) async fn session_invalidated(
    state: &Arc<ServerState>,
    claims: &AccessTokenClaims,
) -> bool {
    let Some(ref sid) = claims.sid else {
        return false;
    };
    // Issuers are realm-NAME based: resolve the segment as a name, then use
    // the realm id for storage. An unresolvable segment (deleted realm, or a
    // pre-switch id-spelled issuer) invalidates the token; storage errors
    // fail closed.
    let realm = match state.resolve_issuer_realm(claims.iss.as_str()).await {
        Ok(Some(r)) => r,
        Ok(None) | Err(_) => return true,
    };
    let realm_id = realm.id;

    match crate::session_cache::session_snapshot(state, &realm_id, sid).await {
        Some(_) => false,
        None => {
            // Session missing or unreadable. A session-bearing user token
            // whose session is gone IS invalidated — logout, admin teardown,
            // idle cleanup. The exception is session-less client-credentials
            // tokens, which carry a synthetic, never-persisted sid; those are
            // recognized by shape (sub = client_id, or sub = the client's
            // service-account user), NOT by user resolution — pairwise subs
            // are keyed HMACs that never resolve to a user, and
            // must not slip through as "not invalidated".
            !is_sessionless_client_token(state, &realm_id, claims).await
        }
    }
}

/// Recognize session-less client-credentials tokens by shape: `sub` equals
/// the requesting client's own `client_id` (legacy synthetic shape), or the
/// id of the client's `service-account-{client_id}` user.
async fn is_sessionless_client_token(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    claims: &AccessTokenClaims,
) -> bool {
    let client_name = claims.azp.clone().unwrap_or_else(|| claims.aud.as_str().to_string());
    if claims.sub.as_ref() == client_name {
        return true;
    }
    let Ok(identifier) = ClientIdentifier::new(&client_name) else {
        return false;
    };
    let client = match crate::claims_cache::ClaimsReader::new(state, realm_id)
        .client(&identifier)
        .await
    {
        Some(c) if c.service_accounts_enabled => c,
        _ => return false,
    };
    let username = crate::claims::service_account_username(&client);
    matches!(
        state.storage.get_user_by_username(realm_id, &username).await,
        Ok(Some(u)) if u.id == claims.sub
    )
}

/// Resolve the user behind access-token claims. Pairwise subjects are keyed
/// HMACs that cannot be reversed to a user id, so
/// the user is resolved through the token's session; public subjects
/// (including session-less client-credentials tokens) resolve directly.
///
/// `session` is the already-fetched validity snapshot when the caller ran the
/// session check first (userinfo); other callers pass `None` and the snapshot
/// is loaded here — through the session-validity cache either way. The user
/// row itself comes from the claims read-model cache (a miss or storage
/// error falls through to the public-sub lookup, as before).
pub(crate) async fn resolve_token_user(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    claims: &AccessTokenClaims,
    session: Option<crate::session_cache::SessionSnapshot>,
) -> Option<issuerd_core::User> {
    let session = match (session, claims.sid.as_ref()) {
        (Some(s), _) => Some(s),
        (None, Some(sid)) => crate::session_cache::session_snapshot(state, realm_id, sid).await,
        (None, None) => None,
    };
    let reader = crate::claims_cache::ClaimsReader::new(state, realm_id);
    if let Some(session) = session {
        if let Some(bundle) = reader.user_claims(&session.user_id).await {
            return Some(bundle.user);
        }
    }
    reader.user_claims(&claims.sub).await.map(|bundle| bundle.user)
}

// ---------------------------------------------------------------------------
// Userinfo endpoint
// ---------------------------------------------------------------------------

async fn userinfo_handler_inner(
    state: Arc<ServerState>,
    realm_name: Option<String>,
    headers: axum::http::HeaderMap,
    body: Option<String>,
    method: &'static str,
) -> Response {
    // The access token arrives as `Authorization: Bearer|DPoP <token>` or
    // (form-body fallback) as `access_token`. Values without a recognized
    // scheme keyword are treated as the bare token (pre-24.6 leniency).
    let (dpop_scheme, token) = if let Some(auth_header) = headers.get("authorization") {
        match auth_header.to_str() {
            Ok(s) => match s.split_once(' ') {
                Some((scheme, credentials)) if scheme.eq_ignore_ascii_case("dpop") => {
                    (true, credentials.to_string())
                }
                Some((scheme, credentials)) if scheme.eq_ignore_ascii_case("bearer") => {
                    (false, credentials.to_string())
                }
                _ => (false, s.to_string()),
            },
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "invalid_token"})),
                )
                    .into_response();
            }
        }
    } else if let Some(body_str) = body {
        // Check for access_token in POST body (form-encoded)
        let params: HashMap<String, String> =
            serde_urlencoded::from_str(&body_str).unwrap_or_default();
        (false, params.get("access_token").cloned().unwrap_or_default())
    } else {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_token"})))
            .into_response();
    };

    if token.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_token"})))
            .into_response();
    }

    // Check revocation list first
    let revoked = matches!(state.cache.get(&format!("revoked:{token}")).await, Ok(Some(_)));
    if revoked {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_token"})))
            .into_response();
    }

    match state.token_service.validate_access_token(&token) {
        Ok(validated) => {
            let claims = validated.claims;

            // Resolve the token's issuing realm once per request — the DPoP
            // replay cache, the session-validity check, and claims assembly
            // all need it (each use site below applies its own failure
            // policy; the lookup itself is cached).
            let issuer_realm = state.resolve_issuer_realm(claims.iss.as_str()).await.ok().flatten();

            // DPoP (RFC 9449 §7.1): a token carrying `cnf.jkt`
            // must be presented with the `DPoP` scheme plus a fresh proof
            // whose key thumbprint matches the binding (`ath` ties the proof
            // to this very token). The DPoP scheme on an unbound token is
            // equally rejected.
            let mut dpop_response_nonce: Option<String> = None;
            if dpop_scheme || claims.cnf.is_some() {
                // Issuers are realm-NAME based: resolve the segment as a
                // realm name, then use the realm id for the replay cache.
                let Some(realm) = issuer_realm.as_ref() else {
                    return crate::dpop::challenge_response(
                        "invalid_token",
                        "token issuer is not a realm",
                        None,
                    );
                };
                let realm_id = realm.id.clone();
                let dpop = match crate::dpop::verify_proof_header(
                    &state,
                    &realm_id,
                    realm_name.as_deref(),
                    &headers,
                    method,
                    "userinfo",
                    Some(&token),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    // RFC 9449 §9: the nonce challenge carries the fresh
                    // nonce in the `DPoP-Nonce` header.
                    Err(crate::dpop::DpopRejection::UseDpopNonce(nonce)) => {
                        return crate::dpop::challenge_response(
                            "use_dpop_nonce",
                            "Resource server requires nonce in DPoP proof",
                            Some(&nonce),
                        );
                    }
                    Err(crate::dpop::DpopRejection::InvalidProof) => {
                        return crate::dpop::challenge_response(
                            "invalid_dpop_proof",
                            "the DPoP proof is invalid",
                            None,
                        );
                    }
                };
                let proof = match dpop.proof {
                    Some(proof) => proof,
                    None if dpop_scheme => {
                        return crate::dpop::challenge_response(
                            "invalid_dpop_proof",
                            "DPoP proof required",
                            None,
                        );
                    }
                    // Bearer presentation of a bound token (downgrade).
                    None => {
                        return crate::dpop::challenge_response(
                            "invalid_token",
                            "the token is DPoP-bound; present it with the DPoP scheme and a proof",
                            None,
                        );
                    }
                };
                dpop_response_nonce = dpop.response_nonce;
                if claims.cnf.as_ref().map(|c| c.jkt.as_str()) != Some(proof.jkt.as_str()) {
                    return crate::dpop::challenge_response(
                        "invalid_token",
                        "the token is not bound to the proof key",
                        None,
                    );
                }
            }

            // Verify the underlying user session still exists. The realm and
            // the session snapshot resolved here are reused for user
            // resolution below — one fetch each per request.
            let session = match (claims.sid.as_ref(), issuer_realm.as_ref()) {
                (Some(sid), Some(realm)) => {
                    crate::session_cache::session_snapshot(&state, &realm.id, sid).await
                }
                _ => None,
            };
            if claims.sid.is_some() {
                // An unresolvable issuer (deleted realm, pre-switch id-spelled
                // issuer, storage error) fails closed; a missing session
                // invalidates too — except session-less client-credentials
                // tokens (synthetic, never-persisted sid), recognized by shape.
                let invalidated = match issuer_realm.as_ref() {
                    None => true,
                    Some(realm) => match session.as_ref() {
                        Some(_) => false,
                        None => !is_sessionless_client_token(&state, &realm.id, &claims).await,
                    },
                };
                if invalidated {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "invalid_token"})),
                    )
                        .into_response();
                }
            }

            // Realm not_before: tokens issued before the realm's cutoff are
            // revoked wholesale (0 = no cutoff). A validity gate — it must
            // run per request, ahead of the rendered-response cache below.
            if let Some(realm) = issuer_realm.as_ref() {
                if realm.not_before > 0 && claims.iat < realm.not_before {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "invalid_token"})),
                    )
                        .into_response();
                }
            }

            // Rendered-response cache: the body built below is a pure
            // function of the resolved user, the issuing client, the token's
            // scope set, and its claims/authz parameters (see
            // `userinfo_cache`). The read is consulted only after every
            // validity gate above has passed, so a logged-out, revoked, or
            // expired token never reaches it.
            let cache_ctx = issuer_realm.as_ref().map(|realm| {
                let user_id = session
                    .as_ref()
                    .map(|s| s.user_id.clone())
                    .unwrap_or_else(|| claims.sub.clone());
                (
                    realm.id.clone(),
                    user_id,
                    claims.aud.as_str().to_string(),
                    crate::userinfo_cache::fingerprint(&claims),
                )
            });
            if let Some((realm_id, user_id, client_id, fp)) = &cache_ctx {
                if let Some(body) =
                    crate::userinfo_cache::read(&state, realm_id, user_id, client_id, fp).await
                {
                    return crate::dpop::with_nonce_header(
                        raw_json_response(body),
                        dpop_response_nonce.as_deref(),
                    );
                }
            }

            // Build base response with required sub claim
            let mut resp = serde_json::Map::new();
            resp.insert("sub".to_string(), serde_json::json!(claims.sub.0));
            // Set when the full user path ran — only then is the body cached
            // (a `{sub}`-only body of an unresolvable user is never cached).
            let mut cacheable = false;

            // RFC 9396 §9: echo the token's authorization details
            // (the client was authorized for them by the underlying grant).
            if let Some(ref details) = claims.authorization_details {
                resp.insert(
                    "authorization_details".to_string(),
                    serde_json::Value::Array(details.clone()),
                );
            }

            // Look up user to return scope-based claims. Issuers are
            // realm-NAME based: resolve the segment as a realm name. A
            // lookup failure fails open (serving userinfo must not depend on
            // this storage read).
            if let Some(realm) = issuer_realm {
                let realm_id = realm.id.clone();
                // Pairwise `sub` values cannot be reversed to a
                // user id — resolve the user through the token's session,
                // falling back to the public-sub lookup (client-credentials).
                if let Some(user) = resolve_token_user(&state, &realm_id, &claims, session).await {
                    cacheable = true;
                    // Scope claims are produced by protocol mappers
                    // on the client scopes matching the token's granted scope
                    // names (+ client-local mappers). The issuing client is
                    // resolved from `aud`; if it was deleted since issuance,
                    // scope-resource mappers still apply.
                    let client = match ClientIdentifier::new(claims.aud.as_str()) {
                        Ok(cid) => {
                            crate::claims_cache::ClaimsReader::new(&state, &realm_id)
                                .client(&cid)
                                .await
                        }
                        Err(_) => None,
                    };
                    let scope_names = claims.scope.to_vec();
                    let overlay = crate::claims::build_claims_overlay(
                        &state,
                        &realm_id,
                        client.as_ref(),
                        &user,
                        &scope_names,
                        issuerd_core::ClaimTarget::UserInfo,
                    )
                    .await
                    .unwrap_or_default();
                    resp.extend(overlay);

                    // Include claims requested via the `claims` parameter
                    if let Some(ref claims_value) = claims.claims {
                        if let Some(userinfo_claims) =
                            claims_value.get("userinfo").and_then(|v| v.as_object())
                        {
                            for (claim_name, _) in userinfo_claims {
                                if resp.contains_key(claim_name) {
                                    continue;
                                }
                                match claim_name.as_str() {
                                    "name" => {
                                        let name = match (&user.first_name, &user.last_name) {
                                            (Some(f), Some(l)) => format!("{f} {l}"),
                                            (Some(f), None) => f.to_string(),
                                            (None, Some(l)) => l.to_string(),
                                            (None, None) => user.username.to_string(),
                                        };
                                        resp.insert(claim_name.clone(), serde_json::json!(name));
                                    }
                                    "given_name" => {
                                        resp.insert(
                                            claim_name.clone(),
                                            serde_json::json!(user.first_name.as_deref()),
                                        );
                                    }
                                    "family_name" => {
                                        resp.insert(
                                            claim_name.clone(),
                                            serde_json::json!(user.last_name.as_deref()),
                                        );
                                    }
                                    "middle_name" => {
                                        let v = user
                                            .attributes
                                            .get("middle_name")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "nickname" => {
                                        let v = user
                                            .attributes
                                            .get("nickname")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "preferred_username" => {
                                        resp.insert(
                                            claim_name.clone(),
                                            serde_json::json!(user.username),
                                        );
                                    }
                                    "profile" => {
                                        let v = user
                                            .attributes
                                            .get("profile")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "picture" => {
                                        let v = user
                                            .attributes
                                            .get("picture")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "website" => {
                                        let v = user
                                            .attributes
                                            .get("website")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "gender" => {
                                        let v = user
                                            .attributes
                                            .get("gender")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "birthdate" => {
                                        let v = user
                                            .attributes
                                            .get("birthdate")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "zoneinfo" => {
                                        let v = user
                                            .attributes
                                            .get("zoneinfo")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "locale" => {
                                        let v = user
                                            .attributes
                                            .get("locale")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "updated_at" => {
                                        // Truthful source: the User model now
                                        // tracks modification time (P3-1).
                                        resp.insert(
                                            claim_name.clone(),
                                            serde_json::json!(user.updated_at.timestamp()),
                                        );
                                    }
                                    "email" => {
                                        resp.insert(
                                            claim_name.clone(),
                                            serde_json::json!(user.email.as_deref()),
                                        );
                                    }
                                    "email_verified" => {
                                        resp.insert(
                                            claim_name.clone(),
                                            serde_json::json!(user.email_verified),
                                        );
                                    }
                                    "phone_number" => {
                                        let v = user
                                            .attributes
                                            .get("phone_number")
                                            .and_then(|vals| vals.first().cloned());
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "phone_number_verified" => {
                                        let v = user
                                            .attributes
                                            .get("phone_number_verified")
                                            .and_then(|vals| vals.first())
                                            .map(|v| v.parse::<bool>().unwrap_or(false));
                                        resp.insert(claim_name.clone(), serde_json::json!(v));
                                    }
                                    "address" => {
                                        let mut address = serde_json::Map::new();
                                        for (field, attr_key) in [
                                            ("formatted", "address_formatted"),
                                            ("street_address", "address_street"),
                                            ("locality", "address_locality"),
                                            ("region", "address_region"),
                                            ("postal_code", "address_postal_code"),
                                            ("country", "address_country"),
                                        ] {
                                            let value = user
                                                .attributes
                                                .get(attr_key)
                                                .and_then(|vals| vals.first().cloned());
                                            address.insert(
                                                field.to_string(),
                                                serde_json::json!(value),
                                            );
                                        }
                                        resp.insert(
                                            claim_name.clone(),
                                            serde_json::Value::Object(address),
                                        );
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }

            let value = serde_json::Value::Object(resp);
            if cacheable {
                if let Some((realm_id, user_id, client_id, fp)) = &cache_ctx {
                    if let Ok(body) = serde_json::to_vec(&value) {
                        crate::userinfo_cache::write(
                            &state, realm_id, user_id, client_id, fp, &body,
                        )
                        .await;
                        return crate::dpop::with_nonce_header(
                            raw_json_response(body),
                            dpop_response_nonce.as_deref(),
                        );
                    }
                }
            }
            crate::dpop::with_nonce_header(
                Json(value).into_response(),
                dpop_response_nonce.as_deref(),
            )
        }
        Err(e) => (StatusCode::UNAUTHORIZED, Json(error_response(&e))).into_response(),
    }
}

#[instrument(skip(state, headers))]
pub async fn userinfo_handler_get(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
) -> Response {
    userinfo_handler_inner(state, realm, headers, None, "GET").await
}

#[instrument(skip(state, headers, body))]
pub async fn userinfo_handler_post(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    userinfo_handler_inner(state, realm, headers, Some(body), "POST").await
}

// ---------------------------------------------------------------------------
// Logout endpoint (OIDC RP-Initiated Logout + Keycloak-compatible POST)
// ---------------------------------------------------------------------------

/// POST variant: parameters arrive as `application/x-www-form-urlencoded` body.
#[instrument(skip(state, headers, body, ip), fields(realm = ?realm))]
pub async fn logout_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let params: HashMap<String, String> = serde_urlencoded::from_str(&body).unwrap_or_default();
    logout_inner(state, realm, ip, headers, params).await
}

/// GET variant per OIDC RP-Initiated Logout: parameters arrive as query params.
#[instrument(skip(state, headers, params, ip), fields(realm = ?realm))]
pub async fn logout_handler_get(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    logout_inner(state, realm, ip, headers, params).await
}

async fn logout_inner(
    state: Arc<ServerState>,
    realm: Option<String>,
    ip: std::net::IpAddr,
    headers: axum::http::HeaderMap,
    params: HashMap<String, String>,
) -> Response {
    // The URL carries the human-readable realm name; storage is keyed by
    // realm id, which differs for admin-created (UUID-id) realms.
    let realm = match realm.as_deref() {
        Some(r) => match state.resolve_realm(r).await {
            Ok(Some(realm)) => realm,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_realm"})),
                )
                    .into_response();
            }
        },
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing realm"})))
                .into_response();
        }
    };
    let realm_id = realm.id.clone();

    let mut session_id: Option<issuerd_core::SessionId> = None;
    let mut user_id: Option<issuerd_core::UserId> = None;
    let mut client: Option<issuerd_core::Client> = None;
    // Tracks whether `session_id` came from an explicitly presented refresh
    // token (vs. an `id_token_hint`): only the former may destroy an offline
    // session.
    let mut session_from_refresh_token = false;

    // Blacklist the presented refresh token. The entry only needs to outlive
    // the token itself, so size the TTL from its exp claim instead of a fixed
    // 24h window.
    if let Some(refresh_token) = params.get("refresh_token") {
        if let Ok(validated) = state.token_service.validate_refresh_token(refresh_token) {
            let now = chrono::Utc::now().timestamp();
            let remaining = validated.claims.exp - now;
            if remaining > 0 {
                let _ = state
                    .cache
                    .set(
                        &format!("revoked_refresh:{refresh_token}"),
                        vec![1],
                        Some(std::time::Duration::from_secs(remaining as u64)),
                    )
                    .await;
            }
            session_id = Some(validated.claims.sid.clone());
            user_id = Some(validated.claims.sub.clone());
            session_from_refresh_token = true;
        }
    }

    // id_token_hint (RP-Initiated Logout): identifies the session and the
    // client used to validate post_logout_redirect_uri.
    if let Some(hint) = params.get("id_token_hint") {
        if let Ok(validated) = state.token_service.validate_access_token(hint) {
            if session_id.is_none() {
                session_id = validated.claims.sid.clone();
            }
            if user_id.is_none() {
                user_id = Some(validated.claims.sub.clone());
            }
            let aud = validated
                .claims
                .azp
                .clone()
                .unwrap_or_else(|| validated.claims.aud.as_str().to_string());
            if let Ok(identifier) = ClientIdentifier::new(&aud) {
                client = state
                    .storage
                    .get_client_by_client_id(&realm_id, &identifier)
                    .await
                    .ok()
                    .flatten();
            }
        } else if let Ok(id_claims) = state.token_service.validate_id_token_hint(hint) {
            // A genuine ID token: cryptographically validated (signature, exp,
            // issuer family); aud/azp are only read after validation succeeds.
            if session_id.is_none() {
                session_id = id_claims.sid.clone();
            }
            if user_id.is_none() {
                user_id = Some(id_claims.sub.clone());
            }
            let aud = id_claims.azp.clone().unwrap_or_else(|| id_claims.aud.as_str().to_string());
            if let Ok(identifier) = ClientIdentifier::new(&aud) {
                client = state
                    .storage
                    .get_client_by_client_id(&realm_id, &identifier)
                    .await
                    .ok()
                    .flatten();
            }
        }
    }

    // Fall back to an explicit client_id parameter for redirect validation.
    if client.is_none() {
        if let Some(client_id) = params.get("client_id") {
            if let Ok(identifier) = ClientIdentifier::new(client_id) {
                client = state
                    .storage
                    .get_client_by_client_id(&realm_id, &identifier)
                    .await
                    .ok()
                    .flatten();
            }
        }
    }

    // Invalidate sessions so subsequent userinfo / refresh attempts fail
    // rather than only the presented token being blacklisted. Fetch each
    // session first: the back-channel dispatcher and the front-channel
    // interstitial both need its client sessions.
    //
    // Offline-session semantics: an explicitly presented refresh token destroys
    // its own session, including an offline one (grant termination). An
    // `id_token_hint` alone never destroys an offline session — in the
    // offline_access flow the issued tokens point at the OFFLINE session
    // while the browser's `issuerd_session` cookie points at the ONLINE SSO
    // session, and a browser logout must end the online session while
    // leaving offline refresh tokens alive. Offline sessions otherwise end
    // via the revocation endpoint, admin action, or their own expiry.
    let mut destroyed_sessions: Vec<issuerd_core::UserSession> = Vec::new();
    if let Some(ref sid) = session_id {
        let session = state.storage.get_user_session(&realm_id, sid).await.ok().flatten();
        let destroy = session_from_refresh_token || session.as_ref().is_some_and(|s| !s.offline);
        if destroy {
            let _ = state.storage.delete_user_session(&realm_id, sid).await;
            crate::session_cache::invalidate_session(&state, &realm_id, sid).await;
            if let Some(s) = session {
                destroyed_sessions.push(s);
            }
        }
    }

    // The browser SSO session from the `issuerd_session` cookie — the session a
    // browser-driven logout is actually meant to terminate.
    // `resolve_session_from_cookie` never returns offline sessions.
    if let Some(cookie_session) = resolve_session_from_cookie(&state, &headers, &realm).await {
        if !destroyed_sessions.iter().any(|s| s.id == cookie_session.id) {
            let _ = state.storage.delete_user_session(&realm_id, &cookie_session.id).await;
            crate::session_cache::invalidate_session(&state, &realm_id, &cookie_session.id).await;
            destroyed_sessions.push(cookie_session);
        }
    }

    // Back-channel logout: notify every client with a `backchannel_logout_uri`
    // (fire-and-forget; never blocks this response).
    for destroyed in &destroyed_sessions {
        state.logout_notifier.notify_session_destroyed(&realm, destroyed).await;
    }

    // Front-channel logout: one hidden iframe per client session whose client
    // configured a `frontchannel_logout_uri`.
    let mut frontchannel_urls: Vec<String> = Vec::new();
    for destroyed in &destroyed_sessions {
        frontchannel_urls.extend(
            crate::routes::logout::frontchannel_logout_urls(
                &state.storage,
                &realm_id,
                &crate::routes::logout::issuer_for_realm(
                    &state.config.issuer_url,
                    realm.name.as_str(),
                ),
                destroyed,
            )
            .await,
        );
    }

    let mut details = std::collections::HashMap::new();
    if let Some(ref c) = client {
        details.insert("client_id".to_string(), c.client_id.to_string());
    }
    // The event records the internal user id: token-derived `user_id` may be
    // a pairwise subject, so a destroyed session — which
    // always knows the real user — wins when present.
    let event_user_id = destroyed_sessions.first().map(|s| s.user_id.clone()).or(user_id);
    emit_oidc_event(
        &state,
        &realm_id,
        EventType::Logout,
        &ip,
        client.as_ref().map(|c| c.id.clone()),
        event_user_id,
        session_id,
        None,
        details,
    )
    .await;

    // Optional post-logout redirect, validated against the client's registered
    // redirect URIs. Without a recognized client we cannot validate the target,
    // so we refuse the redirect rather than acting as an open redirector.
    if let Some(target) = params.get("post_logout_redirect_uri") {
        let registered = client
            .as_ref()
            .map(|c| {
                // Same Keycloak-compatible matching as the authorization
                // endpoint (exact or trailing-`*` wildcard); an unparseable
                // target never matches.
                issuerd_core::RedirectUri::new(target)
                    .ok()
                    .is_some_and(|t| c.redirect_uris.iter().any(|u| u.matches(t.as_str())))
            })
            .unwrap_or(false);
        if !registered {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "invalid post_logout_redirect_uri"
                })),
            )
                .into_response();
        }
        let mut redirect_params: Vec<(&str, &str)> = Vec::new();
        if let Some(s) = params.get("state") {
            redirect_params.push(("state", s.as_str()));
        }
        let url = build_redirect_url(target, &redirect_params, false);
        // Front-channel logout: give the client iframes a chance to run before
        // the browser continues to the post-logout target.
        if !frontchannel_urls.is_empty() {
            return crate::routes::logout::frontchannel_logout_page(Some(&url), &frontchannel_urls);
        }
        return Redirect::to(&url).into_response();
    }

    if !frontchannel_urls.is_empty() {
        return crate::routes::logout::frontchannel_logout_page(None, &frontchannel_urls);
    }

    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Revoke endpoint
// ---------------------------------------------------------------------------

#[instrument(skip(state, headers, body, ip), fields(realm = ?realm))]
pub async fn revoke_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let realm_name = match realm {
        Some(r) => r,
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing realm"})))
                .into_response();
        }
    };
    // Resolve by name so the storage realm ID is used (URLs carry the name).
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_realm"})))
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    };
    let realm_id = realm.id.clone();

    let mut body_params: HashMap<String, String> = match serde_urlencoded::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_form_data"})),
            )
                .into_response();
        }
    };

    // RFC 7009 §2.1 allows the client to authenticate with HTTP Basic, like
    // at the token endpoint.
    let basic_present = extract_basic_auth(&headers).is_some();
    if let Err(resp) = fold_basic_auth(&headers, &mut body_params) {
        return resp;
    }

    // RFC 7009 §2.1: the revoking party must authenticate as a client.
    let client = match authenticate_form_client(&state, &realm, &body_params, basic_present).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    match RevocationRequest::parse(&body_params) {
        Ok(req) => {
            // Resolve the token type: honor the hint, otherwise probe whether
            // the token validates as a refresh token. Refresh tokens land in
            // `revoked_refresh:` (checked by the refresh grant), access tokens
            // in `revoked:` (checked by introspection); TTL = remaining
            // token lifetime so revocation cannot expire before the token.
            let now = issuerd_core::utils::now_secs() as i64;
            let default_ttl = std::time::Duration::from_secs(86400);
            let as_refresh = match req.token_type_hint {
                Some(issuerd_core::TokenTypeHint::AccessToken) => None,
                _ => state.token_service.validate_refresh_token(&req.token).ok(),
            };
            let (cache_key, ttl) = match as_refresh {
                Some(validated) => {
                    let remaining = validated.claims.exp.saturating_sub(now).max(1) as u64;
                    (
                        format!("revoked_refresh:{}", req.token),
                        std::time::Duration::from_secs(remaining),
                    )
                }
                None => {
                    let ttl = state
                        .token_service
                        .validate_access_token(&req.token)
                        .ok()
                        .map(|v| v.claims.exp.saturating_sub(now).max(1) as u64)
                        .map(std::time::Duration::from_secs)
                        .unwrap_or(default_ttl);
                    (format!("revoked:{}", req.token), ttl)
                }
            };
            let _ = state.cache.set(&cache_key, vec![1], Some(ttl)).await;
            let mut details = std::collections::HashMap::new();
            if let Some(hint) = req.token_type_hint {
                details.insert(
                    "token_type_hint".to_string(),
                    serde_json::to_string(&hint).unwrap().trim_matches('"').to_string(),
                );
            }
            emit_oidc_event(
                &state,
                &realm_id,
                EventType::Logout,
                &ip,
                Some(client.id.clone()),
                None,
                None,
                None,
                details,
            )
            .await;
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Introspect endpoint
// ---------------------------------------------------------------------------

#[instrument(skip(state, headers, body))]
pub async fn introspect_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let mut body_params: HashMap<String, String> = match serde_urlencoded::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_form_data"})),
            )
                .into_response();
        }
    };

    // RFC 7662 §2.1 allows the client to authenticate with HTTP Basic, like
    // at the token endpoint.
    let basic_present = extract_basic_auth(&headers).is_some();
    if let Err(resp) = fold_basic_auth(&headers, &mut body_params) {
        return resp;
    }

    let realm = match realm.as_deref() {
        Some(name) => match state.resolve_realm(name).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_realm"})),
                )
                    .into_response();
            }
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e)))
                    .into_response();
            }
        },
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_realm"})))
                .into_response();
        }
    };

    // RFC 7662 §2.1: the introspecting party must authenticate as a client.
    let client = match authenticate_form_client(&state, &realm, &body_params, basic_present).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    match IntrospectionRequest::parse(&body_params) {
        Ok(req) => {
            let inactive = || issuerd_core::IntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                cnf: None,
                authorization_details: None,
                exp: None,
                iat: None,
                nbf: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            };

            // Check revocation list first
            let revoked =
                matches!(state.cache.get(&format!("revoked:{}", req.token)).await, Ok(Some(_)));

            let response = if revoked {
                inactive()
            } else {
                match state.token_service.validate_access_token(&req.token) {
                    Ok(validated) => {
                        let claims = validated.claims;
                        // RFC 7662 §2.2: disclose token details only to the
                        // client the token was issued to, within this realm.
                        // Realm not_before: tokens issued before the realm's
                        // cutoff report inactive (0 = no cutoff).
                        let token_realm =
                            issuerd_core::typestate::extract_realm_from_issuer(claims.iss.as_str());
                        let token_client =
                            claims.azp.clone().unwrap_or_else(|| claims.aud.as_str().to_string());
                        // The token's issuer segment is a realm NAME;
                        // compare it against the introspecting realm's name.
                        if token_realm != Some(realm.name.as_str())
                            || token_client != client.client_id.as_str()
                            || (realm.not_before > 0 && claims.iat < realm.not_before)
                            || session_invalidated(&state, &claims).await
                        {
                            inactive()
                        } else {
                            issuerd_core::IntrospectionResponse {
                                active: true,
                                scope: Some(claims.scope.clone()),
                                client_id: ClientIdentifier::new(claims.aud.as_str().to_string())
                                    .ok(),
                                username: None,
                                // RFC 9449 §6.1: DPoP-bound tokens introspect
                                // as `DPoP` and disclose their `cnf`.
                                token_type: Some(if claims.cnf.is_some() {
                                    issuerd_core::TokenType::Dpop
                                } else {
                                    issuerd_core::TokenType::Bearer
                                }),
                                cnf: claims.cnf.clone(),
                                // RFC 9396 §9.2: reflect the
                                // granted authorization details.
                                authorization_details: claims.authorization_details.clone(),
                                exp: Some(claims.exp),
                                iat: Some(claims.iat),
                                nbf: Some(claims.iat),
                                sub: Some(claims.sub.0.clone()),
                                aud: Some(claims.aud.clone()),
                                iss: Some(claims.iss.clone()),
                                jti: Some(claims.jti),
                            }
                        }
                    }
                    Err(_) => inactive(),
                }
            };
            Json(response).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(error_response(&e))).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn error_response(error: &IssuerdError) -> serde_json::Value {
    serde_json::json!({"error": error.oauth_error_code()})
}

/// Serve a pre-serialized JSON body with the same content type axum's
/// `Json` responder sets (rendered-response cache hits).
pub(crate) fn raw_json_response(bytes: Vec<u8>) -> Response {
    ([(axum::http::header::CONTENT_TYPE, "application/json")], bytes).into_response()
}

/// Persist a user session on a login-success path.
///
/// Failure must not be swallowed (P3-4): an untracked session would keep
/// issuing tokens while being invisible to logout and admin session views.
#[allow(clippy::result_large_err)]
pub(crate) async fn persist_session(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    session: &issuerd_core::UserSession,
    update_existing: bool,
) -> Result<(), Response> {
    let result = if update_existing {
        state.storage.update_user_session(realm_id, session).await
    } else {
        state.storage.create_user_session(realm_id, session).await
    };
    result.map_err(|e| {
        error!(realm = %realm_id, session_id = %session.id, error = %e, "failed to persist user session");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_response(&IssuerdError::ServerError(e.to_string()))),
        )
            .into_response()
    })
}

/// Authenticate the calling client for RFC 7009/7662 endpoints: `client_id`
/// is required, and confidential clients authenticate per their configured
/// `client_authenticator_type` — shared secret (constant-time compared) or a
/// JWT client assertion (`private_key_jwt` / `client_secret_jwt`).
///
/// `basic_present` records whether the client attempted HTTP Basic
/// authentication: per RFC 6749 §5.2 those responses carry a
/// `WWW-Authenticate` challenge. The status stays 401 either way (Keycloak
/// parity; the conformance suite pins it).
#[allow(clippy::result_large_err)]
pub(crate) async fn authenticate_form_client(
    state: &Arc<ServerState>,
    realm: &Realm,
    params: &HashMap<String, String>,
    basic_present: bool,
) -> Result<issuerd_core::Client, Response> {
    let invalid_client = || {
        let mut resp =
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_client"})))
                .into_response();
        if basic_present {
            resp.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Basic realm=\"issuerd\""),
            );
        }
        resp
    };
    let raw = params.get("client_id").filter(|s| !s.is_empty()).ok_or_else(invalid_client)?;
    let identifier = ClientIdentifier::new(raw).map_err(|_| invalid_client())?;
    // The claims read-model cache answers warm lookups without a storage
    // round trip (client updates precise-delete the entry, so secret
    // rotation and disable take effect on the next request). On a miss —
    // unknown client, or a cache/storage degradation — fall back to the
    // direct storage read to preserve the 401-vs-500 distinction.
    let cached = crate::claims_cache::ClaimsReader::new(state, &realm.id)
        .client(&identifier)
        .await;
    let client = match cached {
        Some(c) if c.enabled => c,
        _ => match state.storage.get_client_by_client_id(&realm.id, &identifier).await {
            Ok(Some(c)) if c.enabled => c,
            Ok(_) => return Err(invalid_client()),
            Err(e) => {
                error!(realm = %realm.id, client_id = %identifier, error = %e, "client lookup failed");
                return Err(
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e))).into_response()
                );
            }
        },
    };
    if !client.public_client {
        if let Err(e) = crate::client_assertion::verify_client_auth(
            state,
            &realm.id,
            realm.name.as_str(),
            &client,
            params,
        )
        .await
        {
            warn!(realm = %realm.id, client_id = %client.client_id, error = %e, "client authentication failed");
            return Err(invalid_client());
        }
    }
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::middleware::realm::ResolvedRealm;
    use argon2::PasswordHasher;
    use issuerd_core::{
        AuthMethod, ClientAuthenticatorType, ClientProtocol, Email, PkceCodeChallengeMethod,
        RedirectUri, Scope,
    };

    async fn extract_json(resp: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn cookie_headers(value: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, value.parse().unwrap());
        headers
    }

    #[test]
    fn find_realm_cookie_prefers_per_realm_name() {
        let realm_id = RealmId::new("master").unwrap();
        let headers =
            cookie_headers("issuerd_session=legacy-tok; issuerd_session_master=realm-tok");
        assert_eq!(
            find_realm_cookie(&headers, &realm_id, "issuerd_session").as_deref(),
            Some("realm-tok")
        );
    }

    #[test]
    fn find_realm_cookie_falls_back_to_legacy_name() {
        let realm_id = RealmId::new("master").unwrap();
        let headers = cookie_headers("issuerd_session=legacy-tok");
        assert_eq!(
            find_realm_cookie(&headers, &realm_id, "issuerd_session").as_deref(),
            Some("legacy-tok")
        );
    }

    #[test]
    fn find_realm_cookie_ignores_other_realms_cookies() {
        let realm_id = RealmId::new("master").unwrap();
        // Another realm's scoped cookie must be invisible here.
        let headers = cookie_headers("issuerd_session_other-realm-id=other-tok");
        assert_eq!(find_realm_cookie(&headers, &realm_id, "issuerd_session"), None);
        // Multiple Cookie headers are all inspected.
        let mut headers = cookie_headers("issuerd_remember=legacy-rem");
        headers.append(
            axum::http::header::COOKIE,
            "issuerd_remember_master=realm-rem".parse().unwrap(),
        );
        assert_eq!(
            find_realm_cookie(&headers, &realm_id, "issuerd_remember").as_deref(),
            Some("realm-rem")
        );
    }

    #[tokio::test]
    async fn refresh_token_grant_success() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        // Step 1: obtain refresh token via password grant
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let refresh_token = json["refresh_token"].as_str().unwrap();

        // Step 2: exchange refresh token
        let refresh_body = format!(
            "grant_type=refresh_token&refresh_token={}&client_id=admin-cli&scope=openid",
            refresh_token
        );
        let refresh_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            refresh_body,
        )
        .await;
        assert_eq!(refresh_resp.status(), StatusCode::OK);
        let json = extract_json(refresh_resp).await;
        assert!(json["access_token"].as_str().unwrap().len() > 10);
        assert!(json["refresh_token"].as_str().is_some());
    }

    #[tokio::test]
    async fn client_credentials_grant_success() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        // Create a confidential client with a secret
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("confidential-1").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("confidential-client").unwrap(),
            name: Some(issuerd_core::DisplayName::new("Confidential").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let body = "grant_type=client_credentials&client_id=confidential-client&client_secret=s3cr3t&scope=openid".to_string();
        let resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = extract_json(resp).await;
        assert!(json["access_token"].as_str().unwrap().len() > 10);
        assert!(json["refresh_token"].is_null());
        assert!(json["id_token"].is_null());
    }

    #[tokio::test]
    async fn client_credentials_public_client_rejected() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        // admin-cli is a public client bootstrapped by default
        let body =
            "grant_type=client_credentials&client_id=admin-cli&client_secret=anything&scope=openid"
                .to_string();
        let resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = extract_json(resp).await;
        assert_eq!(json["error"], "unauthorized_client");
    }

    async fn setup_state() -> Arc<ServerState> {
        Arc::new(ServerState::from_config(&ServerConfig::default()).await.unwrap())
    }

    /// Seed a realm whose storage id is a UUID that differs from its
    /// human-readable name (`uuid-realm`), plus one user and one public
    /// client inside it. Returns the realm id. Exercises the name→id
    /// resolution every endpoint must perform.
    async fn seed_uuid_realm(state: &Arc<ServerState>) -> issuerd_core::RealmId {
        let realm_id = issuerd_core::RealmId::new(issuerd_core::utils::generate_id()).unwrap();
        let realm = issuerd_core::Realm {
            id: realm_id.clone(),
            name: issuerd_core::RealmName::new("uuid-realm").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let user = issuerd_core::User {
            id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new("uuid-user").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new("uuid-client").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: true,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![RedirectUri::new("http://localhost/callback").unwrap()],
            web_origins: vec![],
            default_scopes: Scope::parse("openid profile"),
            optional_scopes: Scope::default(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        state.storage.create_client(&realm_id, &client).await.unwrap();
        realm_id
    }

    /// Extract a query parameter from a relative or absolute URL.
    fn extract_query_param(url: &str, key: &str) -> Option<String> {
        let query = url.split_once('?')?.1;
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    /// Create an SSO session for `username` and return headers carrying a valid
    /// `issuerd_session` cookie for it.
    async fn session_cookie_headers(
        state: &Arc<ServerState>,
        username: &str,
    ) -> axum::http::HeaderMap {
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = state.storage.get_user_by_username(&realm_id, username).await.unwrap().unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let now = chrono::Utc::now();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: issuerd_core::AuthMethod::Password,
            remember_me: false,
            offline: false,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: vec![],
        };
        state.storage.create_user_session(&realm_id, &session).await.unwrap();
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
        headers
    }

    #[tokio::test]
    async fn discovery_returns_json() {
        let state = setup_state().await;
        let response = discovery_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn discovery_defaults_to_master() {
        let state = setup_state().await;
        let response =
            discovery_handler(State(state), axum::extract::Extension(ResolvedRealm(None))).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn discovery_lists_active_signing_algorithms() {
        let state = setup_state().await;

        // Fresh boot key set: EdDSA (default) + the OIDC Core MTI RS256 key,
        // newest first. RS256 MUST be advertised (OIDC Core §3 + §15.1).
        let response = discovery_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
        )
        .await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let boot_algs = serde_json::json!(["EdDSA", "RS256"]);
        assert_eq!(json["id_token_signing_alg_values_supported"], boot_algs);
        assert_eq!(json["authorization_signing_alg_values_supported"], boot_algs);

        // Add an active ES256 key to the shared set (as a per-algorithm
        // rotation would) and reload this node's keystore.
        let es256 = issuerd_token::KeyStore::generate_key(issuerd_core::Algorithm::Es256, 2048)
            .unwrap()
            .to_stored(true);
        state.storage.create_signing_key(&es256).await.unwrap();
        (state.signing_key_reload)();

        // The reload hook is asynchronous; poll until the keystore converges.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let algs = loop {
            let response = discovery_handler(
                State(state.clone()),
                axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            )
            .await;
            let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let algs = json["id_token_signing_alg_values_supported"].clone();
            if algs != boot_algs {
                break algs;
            }
            assert!(std::time::Instant::now() < deadline, "keystore did not reload in time");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        // Exactly the active algorithms, newest first.
        assert_eq!(algs, serde_json::json!(["ES256", "EdDSA", "RS256"]));
    }

    #[tokio::test]
    async fn certs_returns_jwks() {
        let state = setup_state().await;
        let response = certs_handler(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_missing_realm() {
        let state = setup_state().await;
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(None)),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn auth_invalid_request() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("client_id".to_string(), "admin-cli".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn auth_missing_response_type_redirects() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("state".to_string(), "xyz".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"), "location: {}", location);
        assert!(location.contains("state=xyz"), "location: {}", location);
    }

    fn valid_code_auth_params() -> std::collections::HashMap<String, String> {
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert(
            "code_challenge".to_string(),
            "E9Melhoa2OwvFrEMTJguCHAoBKt5ubiT2xK87fCYVwI".to_string(),
        );
        params.insert("code_challenge_method".to_string(), "S256".to_string());
        params
    }

    async fn auth_location(
        state: Arc<ServerState>,
        params: std::collections::HashMap<String, String>,
    ) -> String {
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        response.headers().get("location").unwrap().to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn auth_registration_hint_redirects_to_register_page() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        realm.registration_enabled = true;
        state.storage.update_realm(&realm).await.unwrap();

        let mut params = valid_code_auth_params();
        params.insert("registration".to_string(), "true".to_string());
        let location = auth_location(state, params).await;
        assert!(
            location.starts_with("/realms/master/login/register?execution_id="),
            "location: {location}"
        );
    }

    #[tokio::test]
    async fn auth_registration_hint_ignored_when_registration_disabled() {
        let state = setup_state().await;
        // The default realm does not allow self-registration: the hint must
        // not divert the browser from the login page.
        let mut params = valid_code_auth_params();
        params.insert("registration".to_string(), "true".to_string());
        let location = auth_location(state, params).await;
        assert!(location.starts_with("/login.html"), "location: {location}");
    }

    #[tokio::test]
    async fn auth_without_registration_hint_goes_to_login_page() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        realm.registration_enabled = true;
        state.storage.update_realm(&realm).await.unwrap();

        let location = auth_location(state, valid_code_auth_params()).await;
        assert!(location.starts_with("/login.html"), "location: {location}");
    }

    #[tokio::test]
    async fn auth_unsupported_response_type_redirects() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "unknown".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_unregistered_redirect_uri_stays_400() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert("redirect_uri".to_string(), "http://evil.com/cb".to_string());
        params.insert("scope".to_string(), "openid".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn auth_validate_error_unregistered_redirect_uri_returns_400() {
        // Parseable request, but validation fails because the redirect_uri is not
        // registered: the error MUST NOT be sent via redirect (RFC 6749 §4.1.2.1) —
        // neither to the unregistered URI nor to a default registered one.
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert("redirect_uri".to_string(), "http://evil.com/cb".to_string());
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("state".to_string(), "xyz".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("location").is_none());
    }

    #[tokio::test]
    async fn auth_unimplemented_response_type_redirects_unsupported_response_type() {
        // `token` parses and is allowed by the client's default response_types, but is
        // not implemented; it must be rejected with unsupported_response_type instead
        // of silently falling through to the code flow.
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "token".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("state".to_string(), "xyz".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.starts_with("http://localhost:8080/admin/console/callback?"),
            "location: {}",
            location
        );
        assert!(location.contains("error=unsupported_response_type"), "location: {}", location);
        assert!(location.contains("state=xyz"), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_realm_not_found() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert("redirect_uri".to_string(), "http://localhost:8080/cb".to_string());
        params.insert("scope".to_string(), "openid".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("nonexistent".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn auth_invalid_client() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "no-such-client".to_string());
        params.insert("redirect_uri".to_string(), "http://localhost:8080/cb".to_string());
        params.insert("scope".to_string(), "openid".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn auth_redirects_to_login_on_missing_credentials() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        let response = auth_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let headers = response.headers();
        let location = headers.get("location").unwrap().to_str().unwrap();
        let flow_id =
            extract_query_param(location, "execution_id").expect("execution_id in login redirect");
        // Browser-facing id must be a random per-flow value, not the stage id.
        assert_ne!(flow_id, "username-password");
        // Correlation cookie binds the flow to this browser.
        let set_cookie = headers
            .get(axum::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            set_cookie.contains(&format!("issuerd_flow_{flow_id}=1")),
            "set-cookie: {set_cookie}"
        );
        // Pending entry is keyed by realm id + flow id.
        let entry = state
            .cache
            .get(&pending_auth_cache_key(&RealmId::new("master").unwrap(), &flow_id))
            .await
            .unwrap();
        assert!(entry.is_some(), "pending entry must exist for the flow");
    }

    #[test]
    fn flow_cookie_header_secure_flag() {
        let secure = flow_cookie_header("flow-1", true);
        assert!(secure.contains("issuerd_flow_flow-1=1"), "cookie: {secure}");
        assert!(secure.contains("HttpOnly"), "cookie: {secure}");
        assert!(secure.contains("SameSite=Lax"), "cookie: {secure}");
        assert!(secure.contains("; Secure"), "cookie: {secure}");

        let plain = flow_cookie_header("flow-1", false);
        assert!(plain.contains("issuerd_flow_flow-1=1"), "cookie: {plain}");
        assert!(!plain.contains("Secure"), "http rigs must not get the flag: {plain}");
    }

    /// Run the authorize endpoint against `state` and return the flow
    /// correlation `Set-Cookie` header value. `redirect_uri` must be one the
    /// bootstrapped `admin-cli` client registered — the master-realm
    /// bootstrap derives it from the configured `issuer_url`.
    async fn authorize_flow_set_cookie(state: Arc<ServerState>, redirect_uri: &str) -> String {
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert("redirect_uri".to_string(), redirect_uri.to_string());
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok().map(str::to_string))
            .expect("authorize redirect sets the flow correlation cookie")
    }

    #[tokio::test]
    async fn auth_flow_cookie_secure_flag_follows_issuer_scheme() {
        // HTTPS issuer: the flow correlation cookie carries `Secure`.
        let config = ServerConfig {
            issuer_url: "https://issuerd.test.internal".to_string(),
            ..Default::default()
        };
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let set_cookie = authorize_flow_set_cookie(
            state,
            "https://issuerd.test.internal/admin/console/callback",
        )
        .await;
        assert!(set_cookie.contains("issuerd_flow_"), "set-cookie: {set_cookie}");
        assert!(set_cookie.contains("; Secure"), "set-cookie: {set_cookie}");

        // Plain-HTTP issuer (development rigs): no `Secure`, so the browser
        // still stores the cookie.
        let state = setup_state().await;
        let set_cookie =
            authorize_flow_set_cookie(state, "http://localhost:8080/admin/console/callback").await;
        assert!(set_cookie.contains("issuerd_flow_"), "set-cookie: {set_cookie}");
        assert!(!set_cookie.contains("Secure"), "set-cookie: {set_cookie}");
    }

    #[tokio::test]
    async fn auth_handler_post_succeeds() {
        let state = setup_state().await;
        let body = "response_type=code&client_id=admin-cli&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fadmin%2Fconsole%2Fcallback&scope=openid&code_challenge=challenge";
        let response = auth_handler_post(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            axum::extract::Query(std::collections::HashMap::new()),
            body.to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let headers = response.headers();
        let location = headers.get("location").unwrap().to_str().unwrap();
        let flow_id =
            extract_query_param(location, "execution_id").expect("execution_id in login redirect");
        assert_ne!(flow_id, "username-password");
        let set_cookie = headers
            .get(axum::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            set_cookie.contains(&format!("issuerd_flow_{flow_id}=1")),
            "set-cookie: {set_cookie}"
        );
    }

    #[tokio::test]
    async fn auth_handler_post_with_query_params_merge() {
        let state = setup_state().await;
        // Body overrides query params; query provides fallback for missing body keys
        let mut query = std::collections::HashMap::new();
        query.insert("client_id".to_string(), "admin-cli".to_string());
        query.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        query.insert("scope".to_string(), "openid".to_string());
        query.insert("state".to_string(), "from_query".to_string());

        let body =
            "response_type=code&client_id=admin-cli&state=from_body&code_challenge=challenge";
        let response = auth_handler_post(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            axum::extract::Query(query),
            body.to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let headers = response.headers();
        let location = headers.get("location").unwrap().to_str().unwrap();
        assert!(location.contains("execution_id="));
        assert!(!location.contains("execution_id=username-password"));
        // state from body should take precedence
        assert!(location.contains("state=from_body"), "location: {}", location);
    }

    #[tokio::test]
    async fn token_missing_realm() {
        let state = setup_state().await;
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(None)),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "grant_type=password&username=admin&password=admin".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_invalid_form_data() {
        let state = setup_state().await;
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "not_valid_form".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_invalid_grant_type() {
        let state = setup_state().await;
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "grant_type=invalid&client_id=admin-cli".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_device_code_expired() {
        let state = setup_state().await;
        let body = "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=admin-cli&device_code=xyz".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "expired_token");
    }

    #[tokio::test]
    async fn token_password_grant_success() {
        let state = setup_state().await;
        let body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert!(json["access_token"].as_str().unwrap().len() > 10);
        assert!(json["refresh_token"].is_string());
        assert!(json["id_token"].is_string());
    }

    #[tokio::test]
    async fn token_password_grant_user_not_found() {
        let state = setup_state().await;
        let body =
            "grant_type=password&username=nobody&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_password_grant_wrong_password() {
        let state = setup_state().await;
        let body =
            "grant_type=password&username=admin&password=wrong&client_id=admin-cli&scope=openid"
                .to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    // -----------------------------------------------------------------------
    // ROPC federation validation (parity with the browser flow)
    // -----------------------------------------------------------------------

    /// Stub provider with a programmable validation outcome.
    struct RopcStubProvider {
        id: String,
        validate_result: std::sync::Mutex<Result<bool, issuerd_core::FederationError>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationProvider for RopcStubProvider {
        fn id(&self) -> &str {
            &self.id
        }

        fn provider_type(&self) -> issuerd_core::FederationProviderType {
            issuerd_core::FederationProviderType::Ldap
        }

        async fn find_user(
            &self,
            _username: &str,
        ) -> Result<Option<issuerd_core::FederatedUser>, issuerd_core::FederationError> {
            Ok(None)
        }

        async fn find_user_by_email(
            &self,
            _email: &str,
        ) -> Result<Option<issuerd_core::FederatedUser>, issuerd_core::FederationError> {
            Ok(None)
        }

        async fn validate_password(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<bool, issuerd_core::FederationError> {
            let guard = self.validate_result.lock().unwrap();
            match &*guard {
                Ok(v) => Ok(*v),
                Err(issuerd_core::FederationError::NotSupported) => {
                    Err(issuerd_core::FederationError::NotSupported)
                }
                Err(_) => Err(issuerd_core::FederationError::NetworkError("stub".into())),
            }
        }
    }

    struct RopcStubManager {
        providers: Vec<Arc<dyn issuerd_core::FederationProvider>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationManager for RopcStubManager {
        async fn providers_for_realm(
            &self,
            _realm_id: &issuerd_core::RealmId,
        ) -> Result<Vec<Arc<dyn issuerd_core::FederationProvider>>, IssuerdError> {
            Ok(self.providers.clone())
        }

        async fn find_user(
            &self,
            _realm_id: &issuerd_core::RealmId,
            _username: &str,
        ) -> Result<
            Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
            IssuerdError,
        > {
            Ok(None)
        }

        async fn find_user_by_email(
            &self,
            _realm_id: &issuerd_core::RealmId,
            _email: &str,
        ) -> Result<
            Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
            IssuerdError,
        > {
            Ok(None)
        }
    }

    /// Seed a federated user (link `ldap-1`) in master with a local password
    /// credential, and swap in the stub manager.
    async fn setup_federated_ropc_state(
        validate_result: Result<bool, issuerd_core::FederationError>,
    ) -> Arc<ServerState> {
        let mut state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        state.federation_manager = Arc::new(RopcStubManager {
            providers: vec![Arc::new(RopcStubProvider {
                id: "ldap-1".to_string(),
                validate_result: std::sync::Mutex::new(validate_result),
            })],
        });
        let state = Arc::new(state);

        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new("feduser").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: Some("ldap-1".to_string()),
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();
        // A local credential must only ever be consulted when the provider
        // errors (or is gone) — never when it actively rejects.
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        let hash = Argon2::default().hash_password(b"localpass123", &salt).unwrap().to_string();
        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&realm_id, &user.id, &cred).await.unwrap();
        state
    }

    async fn ropc_grant(state: &Arc<ServerState>, password: &str) -> StatusCode {
        token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!(
                "grant_type=password&username=feduser&password={password}&client_id=admin-cli&scope=openid"
            ),
        )
        .await
        .status()
    }

    #[tokio::test]
    async fn token_password_grant_federated_directory_accepts() {
        let state = setup_federated_ropc_state(Ok(true)).await;
        assert_eq!(ropc_grant(&state, "directorypass").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn token_password_grant_federated_rejection_has_no_local_fallback() {
        // The directory actively rejects: even a matching local credential
        // must not authenticate (browser-flow parity).
        let state = setup_federated_ropc_state(Ok(false)).await;
        assert_eq!(ropc_grant(&state, "localpass123").await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_password_grant_federated_error_falls_back_to_local() {
        let state = setup_federated_ropc_state(Err(issuerd_core::FederationError::NetworkError(
            "down".into(),
        )))
        .await;
        assert_eq!(ropc_grant(&state, "localpass123").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn token_password_grant_dead_federation_link_falls_back_to_local() {
        // No provider matches the link: local credentials decide.
        let state = setup_federated_ropc_state(Ok(false)).await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let mut user =
            state.storage.get_user_by_username(&realm_id, "feduser").await.unwrap().unwrap();
        user.federation_link = Some("no-such-provider".to_string());
        state.storage.update_user(&realm_id, &user).await.unwrap();
        assert_eq!(ropc_grant(&state, "localpass123").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn token_auth_code_invalid_code() {
        let state = setup_state().await;
        let body = "grant_type=authorization_code&code=bogus&redirect_uri=http://localhost:8080/cb&client_id=admin-cli&code_verifier=xyz".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_auth_code_success() {
        let state = setup_state().await;
        let code = issuerd_core::utils::generate_id();
        let code_data = AuthCodeData {
            user_id: "admin".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: None,
            authorization_details: None,
        };
        state
            .cache
            .set(
                &format!("auth_code:{code}"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://localhost:8080/cb&client_id=admin-cli&code_verifier=xyz"
        );
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert!(json["access_token"].as_str().unwrap().len() > 10);
    }

    #[tokio::test]
    async fn token_auth_code_reuse_revokes_access_token() {
        let state = setup_state().await;
        let code = issuerd_core::utils::generate_id();
        let code_data = AuthCodeData {
            user_id: "admin".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: None,
            authorization_details: None,
        };
        state
            .cache
            .set(
                &format!("auth_code:{code}"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://localhost:8080/cb&client_id=admin-cli&code_verifier=xyz"
        );
        let first_response = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body.clone(),
        )
        .await;
        assert_eq!(first_response.status(), StatusCode::OK);
        let first_json = extract_json(first_response).await;
        let access_token = first_json["access_token"].as_str().unwrap().to_string();

        // Reuse the same code — should return invalid_grant and revoke the access token
        let second_response = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(second_response.status(), StatusCode::BAD_REQUEST);
        let second_json = extract_json(second_response).await;
        assert_eq!(second_json["error"], "invalid_grant");

        // The previously issued access token should now be revoked
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {access_token}").parse().unwrap(),
        );
        let userinfo_response = userinfo_handler_get(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(userinfo_response.status(), StatusCode::UNAUTHORIZED);
        let userinfo_json = extract_json(userinfo_response).await;
        assert_eq!(userinfo_json["error"], "invalid_token");
    }

    #[tokio::test]
    async fn token_auth_code_redirect_uri_mismatch() {
        let state = setup_state().await;
        let code = issuerd_core::utils::generate_id();
        let code_data = AuthCodeData {
            user_id: "admin".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: None,
            authorization_details: None,
        };
        state
            .cache
            .set(
                &format!("auth_code:{code}"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://evil.com/cb&client_id=admin-cli&code_verifier=xyz"
        );
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_auth_code_pkce_failure() {
        let state = setup_state().await;
        let code = issuerd_core::utils::generate_id();
        let code_data = AuthCodeData {
            user_id: "admin".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: Some(issuerd_core::Base64Url::new("challenge").unwrap()),
            code_challenge_method: Some(PkceCodeChallengeMethod::S256),
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: None,
            authorization_details: None,
        };
        state
            .cache
            .set(
                &format!("auth_code:{code}"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://localhost:8080/cb&client_id=admin-cli&code_verifier=wrong"
        );
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_refresh_token_revoked() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let refresh_token = json["refresh_token"].as_str().unwrap();

        state
            .cache
            .set(
                &format!("revoked_refresh:{refresh_token}"),
                vec![1],
                Some(std::time::Duration::from_secs(86400)),
            )
            .await
            .unwrap();

        let refresh_body =
            format!("grant_type=refresh_token&refresh_token={refresh_token}&client_id=admin-cli");
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            refresh_body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_refresh_token_invalid() {
        let state = setup_state().await;
        let body = "grant_type=refresh_token&refresh_token=invalid.token.here&client_id=admin-cli"
            .to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_refresh_token_wrong_client_binding() {
        let state = setup_state().await;

        // Create two confidential clients
        let client_a = issuerd_core::Client {
            id: issuerd_core::ClientId::new("client-a").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("client-a").unwrap(),
            name: Some(issuerd_core::DisplayName::new("Client A").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("secret-a".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        let client_b = issuerd_core::Client {
            id: issuerd_core::ClientId::new("client-b").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("client-b").unwrap(),
            name: Some(issuerd_core::DisplayName::new("Client B").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("secret-b".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client_a.realm_id, &client_a).await.unwrap();
        state.storage.create_client(&client_b.realm_id, &client_b).await.unwrap();

        // Obtain refresh token using client A
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=client-a&client_secret=secret-a&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let refresh_token = json["refresh_token"].as_str().unwrap();

        // Attempt to exchange refresh token using client B's credentials
        let refresh_body = format!(
            "grant_type=refresh_token&refresh_token={}&client_id=client-b&client_secret=secret-b&scope=openid",
            refresh_token
        );
        let refresh_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            refresh_body,
        )
        .await;
        assert_eq!(refresh_resp.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(refresh_resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_client_credentials_wrong_secret() {
        let state = setup_state().await;
        // Create a confidential client
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("conf-client-1").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("confidential-test").unwrap(),
            name: Some(issuerd_core::DisplayName::new("Test").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let body = "grant_type=client_credentials&client_id=confidential-test&client_secret=wrong&scope=openid".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn userinfo_success() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        let json = extract_json(password_resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {}", access_token).parse().unwrap());

        let response = userinfo_handler_get(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["sub"], "admin");
    }

    #[tokio::test]
    async fn userinfo_deleted_session() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        let json = extract_json(password_resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        // Extract session id from the token and delete it (simulates admin action)
        let validated = state.token_service.validate_access_token(access_token).unwrap();
        let sid = validated.claims.sid.unwrap();
        state
            .storage
            .delete_user_session(&RealmId::new("master").unwrap(), &sid)
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {}", access_token).parse().unwrap());

        let response = userinfo_handler_get(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_token");
    }

    /// Password grant against the default master realm; returns
    /// `(access_token, refresh_token)`.
    async fn password_grant_pair(state: &Arc<ServerState>) -> (String, String) {
        let json = password_grant_tokens(state).await;
        (
            json["access_token"].as_str().unwrap().to_string(),
            json["refresh_token"].as_str().unwrap().to_string(),
        )
    }

    async fn userinfo_with_token(state: &Arc<ServerState>, access_token: &str) -> Response {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {access_token}").parse().unwrap());
        userinfo_handler_get(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await
    }

    #[tokio::test]
    async fn userinfo_cached_session_revoked_immediately_by_logout() {
        let state = setup_state().await;
        let (access_token, refresh_token) = password_grant_pair(&state).await;

        let response = userinfo_with_token(&state, &access_token).await;
        assert_eq!(response.status(), StatusCode::OK);

        // The validity check populated the session cache.
        let validated = state.token_service.validate_access_token(&access_token).unwrap();
        let sid = validated.claims.sid.unwrap();
        let key = issuerd_cluster::cache_keys::session("master", sid.as_ref());
        assert!(
            state.cache.get(&key).await.unwrap().is_some(),
            "userinfo cached the session snapshot"
        );

        // Logout deletes the session AND invalidates the cache synchronously.
        let logout_resp = logout_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!("refresh_token={refresh_token}"),
        )
        .await;
        assert_eq!(logout_resp.status(), StatusCode::NO_CONTENT);
        assert!(
            state.cache.get(&key).await.unwrap().is_none(),
            "logout invalidated the cached snapshot"
        );

        let response = userinfo_with_token(&state, &access_token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn userinfo_negative_cache_absorbs_deleted_session_replay() {
        let state = setup_state().await;
        let (access_token, _) = password_grant_pair(&state).await;
        let validated = state.token_service.validate_access_token(&access_token).unwrap();
        let sid = validated.claims.sid.unwrap();
        let realm_id = RealmId::new("master").unwrap();
        let session =
            state.storage.get_user_session(&realm_id, &sid).await.unwrap().expect("session");
        let key = issuerd_cluster::cache_keys::session("master", sid.as_ref());

        // Direct storage delete (simulates a path that bypasses invalidation).
        state.storage.delete_user_session(&realm_id, &sid).await.unwrap();
        let response = userinfo_with_token(&state, &access_token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            state.cache.get(&key).await.unwrap().is_some(),
            "first miss cached the negative marker"
        );

        // A session resurrected under the same sid within the negative window
        // is still rejected (replay absorption).
        state.storage.create_user_session(&realm_id, &session).await.unwrap();
        let response = userinfo_with_token(&state, &access_token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Once the marker is gone, the live session resolves again.
        state.cache.delete(&key).await.unwrap();
        let response = userinfo_with_token(&state, &access_token).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn userinfo_session_cache_disabled_falls_back_to_db() {
        let mut cfg = ServerConfig::default();
        cfg.cache.read_cache_ttl_secs = 0;
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let (access_token, _) = password_grant_pair(&state).await;
        let validated = state.token_service.validate_access_token(&access_token).unwrap();
        let sid = validated.claims.sid.unwrap();
        let key = issuerd_cluster::cache_keys::session("master", sid.as_ref());

        let response = userinfo_with_token(&state, &access_token).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.cache.get(&key).await.unwrap().is_none(), "disabled cache stores nothing");

        // Direct delete is seen immediately (no TTL window).
        state
            .storage
            .delete_user_session(&RealmId::new("master").unwrap(), &sid)
            .await
            .unwrap();
        let response = userinfo_with_token(&state, &access_token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Password grant with an explicit scope list; returns the access token.
    async fn password_grant_scoped(state: &Arc<ServerState>, scope: &str) -> String {
        let resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!(
                "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope={scope}"
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        extract_json(resp).await["access_token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn userinfo_user_update_reflected_after_precise_invalidation() {
        let state = setup_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user_id = issuerd_core::UserId::new("admin").unwrap();
        let access_token = password_grant_scoped(&state, "openid+profile").await;

        let response = userinfo_with_token(&state, &access_token).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["given_name"], "Admin");
        let key = issuerd_cluster::cache_keys::user_claims("master", "admin");
        assert!(
            state.cache.get(&key).await.unwrap().is_some(),
            "userinfo cached the claims bundle"
        );

        // Direct storage mutation is hidden by the cache (bounded staleness).
        let mut user = state.storage.get_user(&realm_id, &user_id).await.unwrap().unwrap();
        user.first_name = Some(issuerd_core::DisplayName::new("Grace").unwrap());
        state.storage.update_user(&realm_id, &user).await.unwrap();
        let response = userinfo_with_token(&state, &access_token).await;
        let json = extract_json(response).await;
        assert_eq!(json["given_name"], "Admin", "stale bundle still served");

        // The admin write path deletes the user's claims key synchronously;
        // the next userinfo reflects the change immediately.
        issuerd_cluster::invalidate::invalidate_user_claims(
            state.cache.as_ref(),
            &realm_id,
            &user_id,
        )
        .await;
        let response = userinfo_with_token(&state, &access_token).await;
        let json = extract_json(response).await;
        assert_eq!(json["given_name"], "Grace");
    }

    #[tokio::test]
    async fn claims_overlay_role_change_hidden_until_epoch_bump() {
        let state = setup_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user_id = issuerd_core::UserId::new("admin").unwrap();

        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::RoleName::new("epoch-role").unwrap(),
            description: None,
            realm_id: realm_id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_role(&realm_id, &role).await.unwrap();
        state.storage.add_user_realm_role(&realm_id, &user_id, &role.id).await.unwrap();

        let user = state.storage.get_user(&realm_id, &user_id).await.unwrap().unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let scope_names = vec!["openid".to_string()];
        let build = || {
            crate::claims::build_claims_overlay(
                &state,
                &realm_id,
                Some(&client),
                &user,
                &scope_names,
                issuerd_core::ClaimTarget::AccessToken,
            )
        };
        let role_names = |overlay: &serde_json::Map<String, serde_json::Value>| {
            overlay["realm_access"]["roles"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|r| r.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        };
        let names = role_names(&build().await.unwrap());
        assert!(names.iter().any(|r| r == "epoch-role"));
        let catalog_key = issuerd_cluster::cache_keys::realm_catalog("master");
        assert!(
            state.cache.get(&catalog_key).await.unwrap().is_some(),
            "assembly cached the realm catalog"
        );

        // Rename the role definition directly in storage: the cached catalog
        // keeps serving the old definition.
        let mut renamed = role.clone();
        renamed.name = issuerd_core::RoleName::new("epoch-role-v2").unwrap();
        state.storage.update_role(&realm_id, &renamed).await.unwrap();
        let names = role_names(&build().await.unwrap());
        assert!(names.iter().any(|r| r == "epoch-role"), "stale catalog still served");
        assert!(!names.iter().any(|r| r == "epoch-role-v2"));

        // Role-definition CRUD bumps the realm claims epoch; every cached
        // entry misses on its next read and reloads.
        issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
        let names = role_names(&build().await.unwrap());
        assert!(names.iter().any(|r| r == "epoch-role-v2"));
        assert!(!names.iter().any(|r| r == "epoch-role"));
    }

    #[tokio::test]
    async fn userinfo_scope_mapper_change_hidden_until_epoch_bump() {
        let state = setup_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let user_id = issuerd_core::UserId::new("admin").unwrap();

        // The attribute exists on the user before the cache warms; only the
        // mapper that would surface it is added later.
        let mut user = state.storage.get_user(&realm_id, &user_id).await.unwrap().unwrap();
        user.attributes
            .insert("department".to_string(), vec!["engineering".to_string()]);
        state.storage.update_user(&realm_id, &user).await.unwrap();

        let access_token = password_grant_scoped(&state, "openid+profile").await;
        let response = userinfo_with_token(&state, &access_token).await;
        let json = extract_json(response).await;
        assert!(json.get("dept").is_none());
        let catalog_key = issuerd_cluster::cache_keys::realm_catalog("master");
        assert!(state.cache.get(&catalog_key).await.unwrap().is_some());

        // Add a UserAttribute mapper to the profile scope directly in storage.
        let mut profile = state
            .storage
            .list_client_scopes(&realm_id, &issuerd_core::Pagination { first: 0, max: 100 })
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.name == "profile")
            .expect("profile scope seeded");
        profile.protocol_mappers.push(issuerd_core::ProtocolMapper {
            id: issuerd_core::MapperId::new("m-dept").unwrap(),
            name: "dept".to_string(),
            mapper_type: issuerd_core::MapperType::UserAttribute,
            config: std::collections::HashMap::from([
                ("user.attribute".to_string(), "department".to_string()),
                ("claim.name".to_string(), "dept".to_string()),
            ]),
        });
        state.storage.update_client_scope(&realm_id, &profile).await.unwrap();

        // The cached catalog predates the mapper: still no claim.
        let response = userinfo_with_token(&state, &access_token).await;
        let json = extract_json(response).await;
        assert!(json.get("dept").is_none(), "stale catalog still served");

        // Scope/mapper CRUD bumps the epoch; the next userinfo evaluates the
        // new mapper.
        issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
        let response = userinfo_with_token(&state, &access_token).await;
        let json = extract_json(response).await;
        assert_eq!(json["dept"], "engineering");
    }

    #[tokio::test]
    async fn userinfo_missing_auth() {
        let state = setup_state().await;
        let headers = axum::http::HeaderMap::new();
        let response = userinfo_handler_get(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn userinfo_invalid_token() {
        let state = setup_state().await;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer invalid.token".parse().unwrap());
        let response = userinfo_handler_get(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_success() {
        let state = setup_state().await;
        let response = logout_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "refresh_token=some_token".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn logout_missing_realm() {
        let state = setup_state().await;
        let response = logout_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(None)),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn revoke_success() {
        let state = setup_state().await;
        let response = revoke_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "token=some_token&client_id=admin-cli".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn revoke_requires_client_auth() {
        let state = setup_state().await;
        // No client_id at all.
        let response = revoke_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "token=some_token".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Unknown client.
        let response = revoke_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "token=some_token&client_id=nosuch".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_refresh_token_blocks_subsequent_refresh() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let refresh_token = json["refresh_token"].as_str().unwrap().to_string();

        let revoke_resp = revoke_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!("token={refresh_token}&token_type_hint=refresh_token&client_id=admin-cli"),
        )
        .await;
        assert_eq!(revoke_resp.status(), StatusCode::OK);

        // The revoked refresh token must no longer be redeemable.
        let refresh_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!("grant_type=refresh_token&refresh_token={refresh_token}&client_id=admin-cli"),
        )
        .await;
        assert_eq!(refresh_resp.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(refresh_resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn revoke_invalid_form() {
        let state = setup_state().await;
        // Valid client auth but missing the `token` parameter.
        let response = revoke_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "client_id=admin-cli".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn introspect_active_token() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        let json = extract_json(password_resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        let response = introspect_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            format!("token={access_token}&client_id=admin-cli"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["active"], true);
    }

    #[tokio::test]
    async fn introspect_deleted_session() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        let json = extract_json(password_resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        // Extract session id from the token and delete it (simulates admin action)
        let validated = state.token_service.validate_access_token(access_token).unwrap();
        let sid = validated.claims.sid.unwrap();
        state
            .storage
            .delete_user_session(&RealmId::new("master").unwrap(), &sid)
            .await
            .unwrap();

        let response = introspect_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            format!("token={access_token}&client_id=admin-cli"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["active"], false);
    }

    #[tokio::test]
    async fn introspect_client_credentials_active() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("confidential-1").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("confidential-client").unwrap(),
            name: Some(issuerd_core::DisplayName::new("Confidential").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let body = "grant_type=client_credentials&client_id=confidential-client&client_secret=s3cr3t&scope=openid".to_string();
        let resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = extract_json(resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        // Client credentials tokens have no persisted session, but introspection
        // should still report active because the `sub` does not resolve to a user.
        let response = introspect_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            format!("token={access_token}&client_id=confidential-client&client_secret=s3cr3t"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["active"], true);
    }

    #[tokio::test]
    async fn introspect_revoked_token() {
        let state = setup_state().await;
        let token = "my_test_token";
        state
            .cache
            .set(
                &format!("revoked:{token}"),
                vec![1],
                Some(std::time::Duration::from_secs(86400)),
            )
            .await
            .unwrap();

        let response = introspect_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            format!("token={token}&client_id=admin-cli"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["active"], false);
    }

    #[tokio::test]
    async fn introspect_invalid_form() {
        let state = setup_state().await;
        // Valid client auth but no `token` parameter.
        let response = introspect_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            "client_id=admin-cli".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_auth_code_user_not_found() {
        let state = setup_state().await;
        let code = issuerd_core::utils::generate_id();
        let code_data = AuthCodeData {
            user_id: "nonexistent-user".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: None,
            authorization_details: None,
        };
        state
            .cache
            .set(
                &format!("auth_code:{code}"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://localhost:8080/cb&client_id=admin-cli&code_verifier=xyz"
        );
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_refresh_user_not_found() {
        let state = setup_state().await;
        // Create a temporary user
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("tempuser").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            username: Username::new("tempuser").unwrap(),
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

        // Hash password with argon2
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password("temppass".as_bytes(), &salt).unwrap().to_string();

        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        // Obtain refresh token
        let password_body = "grant_type=password&username=tempuser&password=temppass&client_id=admin-cli&scope=openid".to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let refresh_token = json["refresh_token"].as_str().unwrap();

        // Delete the user
        state.storage.delete_user(&user.realm_id, &user.id).await.unwrap();

        let refresh_body =
            format!("grant_type=refresh_token&refresh_token={refresh_token}&client_id=admin-cli");
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            refresh_body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_refresh_client_not_found() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();

        // Create a temporary client for token issuance
        let temp_client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("temp-client-1").unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new("temp-client").unwrap(),
            name: Some(issuerd_core::DisplayName::new("Temp").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("secret".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&realm_id, &temp_client).await.unwrap();

        // Obtain refresh token using temp-client
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=temp-client&client_secret=secret&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let refresh_token = json["refresh_token"].as_str().unwrap();

        // Delete temp-client so the aud claim in the refresh token no longer resolves
        state.storage.delete_client(&realm_id, &temp_client.id).await.unwrap();

        // Use admin-cli (which still exists) as the request client_id so early lookup passes
        let refresh_body =
            format!("grant_type=refresh_token&refresh_token={refresh_token}&client_id=admin-cli");
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            refresh_body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_refresh_session_not_found() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let refresh_token = json["refresh_token"].as_str().unwrap();

        // Get session id from refresh token and delete it
        let validated = state.token_service.validate_refresh_token(refresh_token).unwrap();
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        state
            .storage
            .delete_user_session(&realm_id, &validated.claims.sid)
            .await
            .unwrap();

        let refresh_body =
            format!("grant_type=refresh_token&refresh_token={refresh_token}&client_id=admin-cli");
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            refresh_body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn device_auth_handler_success() {
        let state = setup_state().await;
        let body = "client_id=admin-cli&scope=openid".to_string();
        let response = device_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert!(json["device_code"].as_str().unwrap().len() > 10);
        assert!(json["user_code"].as_str().unwrap().len() > 4);
        assert!(json["verification_uri"].as_str().unwrap().contains("auth/device-verify"));
        assert_eq!(json["expires_in"], 600);
        assert_eq!(json["interval"], 5);
    }

    #[tokio::test]
    async fn device_auth_handler_invalid_client() {
        let state = setup_state().await;
        let body = "client_id=no-such-client&scope=openid".to_string();
        let response = device_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn device_verify_handler_wrong_password() {
        let state = setup_state().await;

        // Seed a device code entry
        let user_code = "ABCD-EFGH".to_string();
        let code_data = DeviceCodeData {
            device_code: "device-123".to_string(),
            user_code: user_code.clone(),
            client_id: "admin-cli".to_string(),
            realm_id: "master".to_string(),
            scope: vec!["openid".to_string()],
            user_id: None,
            authorized: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::user_code(&user_code),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = "user_code=ABCD-EFGH&username=admin&password=wrong".to_string();
        let response = device_verify_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn device_verify_handler_brute_force_lockout() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        realm.brute_force_protected = true;
        realm.max_login_failures = 2;
        state.storage.update_realm(&realm).await.unwrap();

        // Seed a device code entry
        let user_code = "ABCD-EFGH".to_string();
        let code_data = DeviceCodeData {
            device_code: "device-123".to_string(),
            user_code: user_code.clone(),
            client_id: "admin-cli".to_string(),
            realm_id: "master".to_string(),
            scope: vec!["openid".to_string()],
            user_id: None,
            authorized: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::user_code(&user_code),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        // Wrong-password attempts are counted by the login-failure tracker.
        for _ in 0..2 {
            let response = device_verify_handler(
                State(state.clone()),
                axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
                axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
                "user_code=ABCD-EFGH&username=admin&password=wrong".to_string(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        // Locked out: even the correct password is now rejected.
        let response = device_verify_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "user_code=ABCD-EFGH&username=admin&password=admin".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");

        // The device code must not have been authorized while locked.
        let cached: DeviceCodeData = serde_json::from_slice(
            &state
                .cache
                .get(&issuerd_cluster::cache_keys::user_code(&user_code))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(!cached.authorized);
    }

    #[tokio::test]
    async fn device_token_flow_pending_then_success() {
        let state = setup_state().await;

        // Step 1: Initiate device authorization
        let auth_body = "client_id=admin-cli&scope=openid".to_string();
        let auth_resp = device_auth_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            auth_body,
        )
        .await;
        assert_eq!(auth_resp.status(), StatusCode::OK);
        let auth_json = extract_json(auth_resp).await;
        let device_code = auth_json["device_code"].as_str().unwrap();
        let user_code = auth_json["user_code"].as_str().unwrap();

        // Step 2: Poll token endpoint — should be authorization_pending
        let token_body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=admin-cli&device_code={}",
            device_code
        );
        let pending_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            token_body.clone(),
        )
        .await;
        assert_eq!(pending_resp.status(), StatusCode::BAD_REQUEST);
        let pending_json = extract_json(pending_resp).await;
        assert_eq!(pending_json["error"], "authorization_pending");

        // Step 3: User verifies with user_code
        let verify_body = format!("user_code={}&username=admin&password=admin", user_code);
        let verify_resp = device_verify_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            verify_body,
        )
        .await;
        assert_eq!(verify_resp.status(), StatusCode::OK);

        // Step 4: Poll token endpoint again — should succeed
        let success_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            token_body,
        )
        .await;
        let success_json = extract_json(success_resp).await;
        assert!(
            success_json["access_token"].is_string(),
            "expected access_token but got error: {}",
            success_json["error"]
        );

        // Step 5: Poll token endpoint a third time — code should be consumed
        let consumed_body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=admin-cli&device_code={}",
            device_code
        );
        let consumed_resp = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            consumed_body,
        )
        .await;
        assert_eq!(consumed_resp.status(), StatusCode::BAD_REQUEST);
        let consumed_json = extract_json(consumed_resp).await;
        assert_eq!(consumed_json["error"], "expired_token");
    }

    #[tokio::test]
    async fn device_token_flow_slow_down() {
        let state = setup_state().await;

        // Initiate device authorization
        let auth_body = "client_id=admin-cli&scope=openid".to_string();
        let auth_resp = device_auth_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            auth_body,
        )
        .await;
        assert_eq!(auth_resp.status(), StatusCode::OK);
        let auth_json = extract_json(auth_resp).await;
        let device_code = auth_json["device_code"].as_str().unwrap();

        // First poll — sets last_polled_at
        let token_body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=admin-cli&device_code={}",
            device_code
        );
        let first_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            token_body.clone(),
        )
        .await;
        assert_eq!(first_resp.status(), StatusCode::BAD_REQUEST);
        let first_json = extract_json(first_resp).await;
        assert_eq!(first_json["error"], "authorization_pending");

        // Immediate second poll — should trigger slow_down
        let second_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            token_body,
        )
        .await;
        assert_eq!(second_resp.status(), StatusCode::BAD_REQUEST);
        let second_json = extract_json(second_resp).await;
        assert_eq!(second_json["error"], "slow_down");
    }

    #[tokio::test]
    async fn ciba_auth_handler_public_client_rejected() {
        let state = setup_state().await;
        let body = "client_id=admin-cli&login_hint=admin&scope=openid".to_string();
        let response = ciba_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "unauthorized_client");
    }

    #[tokio::test]
    async fn ciba_auth_handler_invalid_client_secret() {
        let state = setup_state().await;
        // Create a confidential client
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("ciba-conf-1").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("ciba-conf-client").unwrap(),
            name: Some(issuerd_core::DisplayName::new("CIBA Conf").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let body = "client_id=ciba-conf-client&client_secret=wrong&login_hint=admin&scope=openid"
            .to_string();
        let response = ciba_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn ciba_auth_handler_success() {
        let state = setup_state().await;
        // Create a confidential client
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("ciba-conf-2").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("ciba-conf-client-2").unwrap(),
            name: Some(issuerd_core::DisplayName::new("CIBA Conf").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let body = "client_id=ciba-conf-client-2&client_secret=s3cr3t&login_hint=admin&scope=openid&binding_message=Login%20now".to_string();
        let response = ciba_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert!(json["auth_req_id"].as_str().unwrap().len() > 10);
        assert!(json["expires_in"].is_number());
    }

    #[tokio::test]
    async fn ciba_token_flow_pending_approve_success() {
        let state = setup_state().await;
        // Create a confidential client
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("ciba-conf-3").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("ciba-conf-client-3").unwrap(),
            name: Some(issuerd_core::DisplayName::new("CIBA Conf").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        // Step 1: Initiate CIBA auth request
        let auth_body =
            "client_id=ciba-conf-client-3&client_secret=s3cr3t&login_hint=admin&scope=openid"
                .to_string();
        let auth_resp = ciba_auth_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            auth_body,
        )
        .await;
        assert_eq!(auth_resp.status(), StatusCode::OK);
        let auth_json = extract_json(auth_resp).await;
        let auth_req_id = auth_json["auth_req_id"].as_str().unwrap();

        // Step 2: Poll token endpoint — should be authorization_pending
        let token_body = format!(
            "grant_type=urn:openid:params:grant-type:ciba&client_id=ciba-conf-client-3&client_secret=s3cr3t&auth_req_id={}",
            auth_req_id
        );
        let pending_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            token_body.clone(),
        )
        .await;
        assert_eq!(pending_resp.status(), StatusCode::BAD_REQUEST);
        let pending_json = extract_json(pending_resp).await;
        assert_eq!(pending_json["error"], "authorization_pending");

        // Step 3: Approve via approval endpoint (authenticated as the bound user)
        let approve_headers = session_cookie_headers(&state, "admin").await;
        let approve_body = format!("auth_req_id={}&action=approve", auth_req_id);
        let approve_resp = ciba_approve_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            approve_headers,
            approve_body,
        )
        .await;
        assert_eq!(approve_resp.status(), StatusCode::OK);

        // Step 4: Poll token endpoint again — should succeed
        let success_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            token_body.clone(),
        )
        .await;
        assert_eq!(success_resp.status(), StatusCode::OK);
        let success_json = extract_json(success_resp).await;
        assert!(success_json["access_token"].is_string());
        assert!(success_json["refresh_token"].is_string());
        assert!(success_json["id_token"].is_string());

        // Step 5: Poll token endpoint a third time — auth_req_id should be consumed
        let consumed_resp = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            token_body,
        )
        .await;
        assert_eq!(consumed_resp.status(), StatusCode::BAD_REQUEST);
        let consumed_json = extract_json(consumed_resp).await;
        assert_eq!(consumed_json["error"], "expired_token");
    }

    #[tokio::test]
    async fn ciba_token_flow_denied() {
        let state = setup_state().await;
        // Create a confidential client
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("ciba-conf-4").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("ciba-conf-client-4").unwrap(),
            name: Some(issuerd_core::DisplayName::new("CIBA Conf").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        // Initiate CIBA auth request
        let auth_body =
            "client_id=ciba-conf-client-4&client_secret=s3cr3t&login_hint=admin&scope=openid"
                .to_string();
        let auth_resp = ciba_auth_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            auth_body,
        )
        .await;
        assert_eq!(auth_resp.status(), StatusCode::OK);
        let auth_json = extract_json(auth_resp).await;
        let auth_req_id = auth_json["auth_req_id"].as_str().unwrap();

        // Deny via approval endpoint (authenticated as the bound user)
        let deny_headers = session_cookie_headers(&state, "admin").await;
        let deny_body = format!("auth_req_id={}&action=deny", auth_req_id);
        let deny_resp = ciba_approve_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            deny_headers,
            deny_body,
        )
        .await;
        assert_eq!(deny_resp.status(), StatusCode::OK);

        // Poll token endpoint — should get access_denied
        let token_body = format!(
            "grant_type=urn:openid:params:grant-type:ciba&client_id=ciba-conf-client-4&client_secret=s3cr3t&auth_req_id={}",
            auth_req_id
        );
        let token_resp = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            token_body,
        )
        .await;
        assert_eq!(token_resp.status(), StatusCode::BAD_REQUEST);
        let token_json = extract_json(token_resp).await;
        assert_eq!(token_json["error"], "access_denied");
    }

    #[tokio::test]
    async fn auth_handler_valid_cookie_success_code() {
        let state = setup_state().await;
        // Issue an access token for the admin user
        let user = state
            .storage
            .get_user(
                &issuerd_core::RealmId::new("master").unwrap(),
                &issuerd_core::UserId::new("admin").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(
                &issuerd_core::RealmId::new("master").unwrap(),
                &ClientIdentifier::new("admin-cli").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let realm = state
            .storage
            .get_realm(&issuerd_core::RealmId::new("master").unwrap())
            .await
            .unwrap()
            .unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: issuerd_core::UserId::new("admin").unwrap(),
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

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("state".to_string(), "my_state".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="), "location: {}", location);
        assert!(location.contains("state=my_state"), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_handler_deleted_session_cookie_no_sso() {
        let state = setup_state().await;
        // Issue an access token for the admin user
        let user = state
            .storage
            .get_user(
                &issuerd_core::RealmId::new("master").unwrap(),
                &issuerd_core::UserId::new("admin").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(
                &issuerd_core::RealmId::new("master").unwrap(),
                &ClientIdentifier::new("admin-cli").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let realm = state
            .storage
            .get_realm(&issuerd_core::RealmId::new("master").unwrap())
            .await
            .unwrap()
            .unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: issuerd_core::UserId::new("admin").unwrap(),
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

        // The session is deleted (e.g. logout or admin action) — the cookie
        // still cryptographically validates but must NOT trigger SSO.
        state.storage.delete_user_session(&realm_id, &session_id).await.unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_session={}", access_token.token).parse().unwrap(),
        );

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("execution_id="), "location: {}", location);
        assert!(!location.contains("code="), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_handler_valid_cookie_success_id_token() {
        let state = setup_state().await;
        let user = state
            .storage
            .get_user(
                &issuerd_core::RealmId::new("master").unwrap(),
                &issuerd_core::UserId::new("admin").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(
                &issuerd_core::RealmId::new("master").unwrap(),
                &ClientIdentifier::new("admin-cli").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let realm = state
            .storage
            .get_realm(&issuerd_core::RealmId::new("master").unwrap())
            .await
            .unwrap()
            .unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: issuerd_core::UserId::new("admin").unwrap(),
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

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "id_token".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("nonce".to_string(), "abc".to_string());
        params.insert("state".to_string(), "xyz".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("id_token="), "location: {}", location);
        assert!(location.contains("state="), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_handler_prompt_none_no_session() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("prompt".to_string(), "none".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=login_required"), "location: {}", location);
    }

    /// Cache double that fails only authorization-code persistence — every
    /// other operation delegates to an in-memory cache, so a login flow runs
    /// normally until the code write.
    struct FailAuthCodeSet {
        inner: issuerd_cluster::InMemoryCache,
    }

    #[async_trait::async_trait]
    impl issuerd_core::DistributedCache for FailAuthCodeSet {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<std::time::Duration>,
        ) -> Result<(), IssuerdError> {
            if key.starts_with("auth_code:") {
                return Err(IssuerdError::ServerError("cache down".to_string()));
            }
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), IssuerdError> {
            self.inner.delete(key).await
        }
        async fn get_and_delete(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
            self.inner.get_and_delete(key).await
        }
        async fn compare_and_swap(
            &self,
            key: &str,
            expected: Option<Vec<u8>>,
            new: Vec<u8>,
        ) -> Result<bool, IssuerdError> {
            self.inner.compare_and_swap(key, expected, new).await
        }
        async fn publish(&self, channel: &str, message: Vec<u8>) -> Result<(), IssuerdError> {
            self.inner.publish(channel, message).await
        }
        async fn subscribe(
            &self,
            channel: &str,
            handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
        ) -> Result<(), IssuerdError> {
            self.inner.subscribe(channel, handler).await
        }
    }

    fn sample_auth_code_data() -> AuthCodeData {
        AuthCodeData {
            user_id: "user-1".to_string(),
            client_id: "client-1".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: None,
            authorization_details: None,
        }
    }

    #[tokio::test]
    async fn store_auth_code_surfaces_cache_errors() {
        let data = sample_auth_code_data();

        // A failed write propagates — the caller must not emit the code.
        let failing: Arc<dyn issuerd_core::DistributedCache> = Arc::new(FailAuthCodeSet {
            inner: issuerd_cluster::InMemoryCache::new(),
        });
        let ttl = std::time::Duration::from_secs(crate::config::AUTH_CODE_TTL_DEFAULT_SECS);
        let result = store_auth_code(&failing, "code-1", &data, ttl).await;
        assert!(result.is_err(), "cache failure must propagate");

        // A confirmed write returns Ok and the entry is readable back.
        let cache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let as_dyn: Arc<dyn issuerd_core::DistributedCache> = cache.clone();
        store_auth_code(&as_dyn, "code-2", &data, ttl).await.unwrap();
        let stored = issuerd_core::DistributedCache::get(cache.as_ref(), "auth_code:code-2")
            .await
            .unwrap();
        assert!(stored.is_some(), "persisted code must be readable");
    }

    #[tokio::test]
    async fn auth_handler_code_persistence_failure_redirects_temporarily_unavailable() {
        let cache: Arc<dyn issuerd_core::DistributedCache> = Arc::new(FailAuthCodeSet {
            inner: issuerd_cluster::InMemoryCache::new(),
        });
        let config = ServerConfig::default();
        let storage: Arc<dyn issuerd_core::Storage> =
            Arc::new(issuerd_storage::InMemoryStorage::new());
        let state = Arc::new(ServerState::from_components(&config, storage, cache).await.unwrap());

        // Establish an SSO session for admin (same rig as the prompt=login test).
        let user = state
            .storage
            .get_user(
                &issuerd_core::RealmId::new("master").unwrap(),
                &issuerd_core::UserId::new("admin").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(
                &issuerd_core::RealmId::new("master").unwrap(),
                &ClientIdentifier::new("admin-cli").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let realm = state
            .storage
            .get_realm(&issuerd_core::RealmId::new("master").unwrap())
            .await
            .unwrap()
            .unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: issuerd_core::UserId::new("admin").unwrap(),
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

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("state".to_string(), "xyz".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        // Fail-closed: the client is told to retry later; no code is emitted.
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=temporarily_unavailable"), "location: {}", location);
        assert!(location.contains("state=xyz"), "location: {}", location);
        assert!(
            !location.contains("?code=") && !location.contains("&code="),
            "no authorization code may leak: {}",
            location
        );
    }

    #[tokio::test]
    async fn auth_handler_prompt_login() {
        let state = setup_state().await;
        let user = state
            .storage
            .get_user(
                &issuerd_core::RealmId::new("master").unwrap(),
                &issuerd_core::UserId::new("admin").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(
                &issuerd_core::RealmId::new("master").unwrap(),
                &ClientIdentifier::new("admin-cli").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let realm = state
            .storage
            .get_realm(&issuerd_core::RealmId::new("master").unwrap())
            .await
            .unwrap()
            .unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: issuerd_core::UserId::new("admin").unwrap(),
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

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("prompt".to_string(), "login".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        // prompt=login forces re-auth, so cookie is ignored and user is redirected to login
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("execution_id="), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_handler_with_state_nonce_ccm() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("state".to_string(), "my_state".to_string());
        params.insert("nonce".to_string(), "my_nonce".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "S256".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("execution_id="), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_error_redirect_missing_client() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("client_id".to_string(), "no-such-client".to_string());
        params.insert("redirect_uri".to_string(), "http://localhost:8080/cb".to_string());
        params.insert("scope".to_string(), "openid".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_handler_basic_auth() {
        let state = setup_state().await;
        // Create a confidential client
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("basic-auth-client").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("basic-auth-client").unwrap(),
            name: Some(issuerd_core::DisplayName::new("Basic Auth").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let mut headers = axum::http::HeaderMap::new();
        let creds = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "basic-auth-client:s3cr3t",
        );
        headers.insert("authorization", format!("Basic {}", creds).parse().unwrap());

        let body = "grant_type=client_credentials&scope=openid".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers,
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert!(json["access_token"].as_str().unwrap().len() > 10);
    }

    #[tokio::test]
    async fn token_handler_client_secret_post() {
        let state = setup_state().await;
        // Create a confidential client
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("post-auth-client").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("post-auth-client").unwrap(),
            name: Some(issuerd_core::DisplayName::new("Client Secret Post").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let headers = axum::http::HeaderMap::new();
        let body = "grant_type=client_credentials&client_id=post-auth-client&client_secret=s3cr3t&scope=openid".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers,
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert!(json["access_token"].as_str().unwrap().len() > 10);
    }

    #[tokio::test]
    async fn userinfo_post_success() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        let json = extract_json(password_resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        let response = super::userinfo_handler_post(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            format!("access_token={}", access_token),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["sub"], "admin");
    }

    #[tokio::test]
    async fn device_auth_handler_invalid_form() {
        let state = setup_state().await;
        let response = device_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            "not_valid_form".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ciba_auth_handler_invalid_form() {
        let state = setup_state().await;
        let response = ciba_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "not_valid_form".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ciba_auth_handler_unknown_user() {
        let state = setup_state().await;
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("ciba-unknown").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("ciba-unknown-client").unwrap(),
            name: Some(issuerd_core::DisplayName::new("CIBA").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let body =
            "client_id=ciba-unknown-client&client_secret=s3cr3t&login_hint=nobody&scope=openid"
                .to_string();
        let response = ciba_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "unknown_user_id");
    }

    #[tokio::test]
    async fn claims_overlay_includes_realm_access_with_roles() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user_id = issuerd_core::UserId::new("admin").unwrap();

        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::RoleName::new("test-role-unique").unwrap(),
            description: None,
            realm_id: realm_id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_role(&realm_id, &role).await.unwrap();
        state.storage.add_user_realm_role(&realm_id, &user_id, &role.id).await.unwrap();

        let user = state.storage.get_user(&realm_id, &user_id).await.unwrap().unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let overlay = crate::claims::build_claims_overlay(
            &state,
            &realm_id,
            Some(&client),
            &user,
            &["openid".to_string()],
            issuerd_core::ClaimTarget::AccessToken,
        )
        .await
        .unwrap();
        let roles = overlay
            .get("realm_access")
            .and_then(|v| v.get("roles"))
            .and_then(|v| v.as_array())
            .expect("realm_access.roles must be present");
        assert!(roles.iter().any(|r| r.as_str() == Some("test-role-unique")));
    }

    #[tokio::test]
    async fn auth_handler_valid_cookie_success_hybrid() {
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

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code id_token".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("nonce".to_string(), "abc123".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="), "location: {}", location);
        assert!(location.contains("id_token="), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_handler_invalid_cookie_token() {
        let state = setup_state().await;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "issuerd_session=invalid.token.value".parse().unwrap(),
        );

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("execution_id="), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_handler_prompt_none_max_age_exceeded() {
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
            auth_time: chrono::Utc::now() - chrono::Duration::seconds(2),
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

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("prompt".to_string(), "none".to_string());
        params.insert("max_age".to_string(), "1".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=login_required"), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_handler_max_age_exceeded_force_reauth() {
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
            auth_time: chrono::Utc::now() - chrono::Duration::seconds(2),
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

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("max_age".to_string(), "1".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("execution_id="), "location: {}", location);
    }

    #[tokio::test]
    async fn auth_handler_code_redirect_uri_with_query() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();

        let mut client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        client.redirect_uris.push(
            RedirectUri::new("http://localhost:8080/admin/console/callback?foo=bar").unwrap(),
        );
        state.storage.update_client(&realm_id, &client).await.unwrap();

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

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback?foo=bar".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("code_challenge".to_string(), "challenge".to_string());
        params.insert("code_challenge_method".to_string(), "plain".to_string());

        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="), "location: {}", location);
        assert!(location.contains("foo=bar"), "location: {}", location);
    }

    #[tokio::test]
    async fn device_auth_handler_missing_realm() {
        let state = setup_state().await;
        let response = device_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(None)),
            "client_id=admin-cli".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ciba_auth_handler_missing_realm() {
        let state = setup_state().await;
        let response = ciba_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(None)),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "client_id=admin-cli".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn certs_handler_crypto_error() {
        use crate::config::ServerConfig;
        use crate::state::ServerState;
        use issuerd_token::token_manager::TokenManager;

        let mut mock_crypto = issuerd_core::MockCryptoProvider::new();
        mock_crypto
            .expect_get_public_keys()
            .returning(|| Err(issuerd_core::IssuerdError::ServerError("crypto fail".to_string())));

        let real_crypto = Arc::new(
            issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default()).unwrap(),
        );
        let token_manager = Arc::new(TokenManager::new(
            real_crypto.clone(),
            "http://localhost:8080".to_string(),
            std::time::Duration::from_secs(60),
            issuerd_core::JwkSet { keys: vec![] },
        ));
        let token_service: Arc<dyn issuerd_core::TokenService> = token_manager.clone();

        let state = Arc::new(ServerState {
            config: ServerConfig::default(),
            storage: Arc::new(issuerd_storage::InMemoryStorage::new()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            crypto: Arc::new(mock_crypto),
            token_service,
            token_manager,
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

        let response = certs_handler(State(state)).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn userinfo_profile_scope_admin_user() {
        let state = setup_state().await;
        let body = "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid%20profile".to_string();
        let resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = extract_json(resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {access_token}").parse().unwrap());
        let userinfo = userinfo_handler_get(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(userinfo.status(), StatusCode::OK);
        let info = extract_json(userinfo).await;
        assert_eq!(info["name"], "Admin User");
        assert_eq!(info["given_name"], "Admin");
        assert_eq!(info["family_name"], "User");
    }

    #[tokio::test]
    async fn userinfo_profile_scope_all_branches() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();

        // Create users to cover all name branches
        for (fname, lname, uname, expected_name) in [
            (Some("John"), None, "john_no_last", "John"),
            (None, Some("Doe"), "doe_no_first", "Doe"),
            (None, None::<&str>, "noname", "noname"),
        ] {
            let user = issuerd_core::User {
                id: issuerd_core::UserId::new(uname).unwrap(),
                realm_id: realm_id.clone(),
                username: Username::new(uname).unwrap(),
                email: None,
                email_verified: false,
                first_name: fname.map(|s| issuerd_core::DisplayName::new(s).unwrap()),
                last_name: lname.map(|s| issuerd_core::DisplayName::new(s).unwrap()),
                enabled: true,
                federation_link: None,
                attributes: [
                    ("middle_name", vec!["Mid"]),
                    ("nickname", vec!["Nick"]),
                    ("profile", vec!["https://example.com/profile"]),
                    ("picture", vec!["https://example.com/pic"]),
                    ("website", vec!["https://example.com"]),
                    ("gender", vec!["male"]),
                    ("birthdate", vec!["1990-01-01"]),
                    ("zoneinfo", vec!["UTC"]),
                    ("locale", vec!["en-US"]),
                ]
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
                required_actions: Vec::new(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            state.storage.create_user(&realm_id, &user).await.unwrap();

            let salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
            let hash = argon2::Argon2::default()
                .hash_password("pass".as_bytes(), &salt)
                .unwrap()
                .to_string();
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

            let body = format!(
                "grant_type=password&username={uname}&password=pass&client_id=admin-cli&scope=openid%20profile"
            );
            let resp = token_handler(
                State(state.clone()),
                axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
                axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
                axum::http::HeaderMap::new(),
                body,
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "failed for user {uname}");
            let json = extract_json(resp).await;
            let access_token = json["access_token"].as_str().unwrap();

            let mut headers = axum::http::HeaderMap::new();
            headers.insert("authorization", format!("Bearer {access_token}").parse().unwrap());
            let userinfo = userinfo_handler_get(
                State(state.clone()),
                axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
                headers,
            )
            .await;
            assert_eq!(userinfo.status(), StatusCode::OK);
            let info = extract_json(userinfo).await;
            assert_eq!(info["name"], expected_name, "name mismatch for {uname}");
            assert_eq!(info["preferred_username"], uname);
            // Memory storage sets updated_at = created_at on user creation.
            assert_eq!(info["updated_at"], user.created_at.timestamp());
            assert_eq!(info["middle_name"], "Mid");
            assert_eq!(info["nickname"], "Nick");
            assert_eq!(info["profile"], "https://example.com/profile");
            assert_eq!(info["picture"], "https://example.com/pic");
            assert_eq!(info["website"], "https://example.com");
            assert_eq!(info["gender"], "male");
            assert_eq!(info["birthdate"], "1990-01-01");
            assert_eq!(info["zoneinfo"], "UTC");
            assert_eq!(info["locale"], "en-US");
        }
    }

    #[tokio::test]
    async fn userinfo_email_address_phone_scopes() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();

        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("contactuser").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("contactuser").unwrap(),
            email: Some(Email::new("user@example.com").unwrap()),
            email_verified: true,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: [
                ("address_formatted", vec!["123 Main St"]),
                ("address_street", vec!["Main St"]),
                ("address_locality", vec!["Springfield"]),
                ("address_region", vec!["IL"]),
                ("address_postal_code", vec!["62701"]),
                ("address_country", vec!["US"]),
                ("phone_number", vec!["+1-555-1234"]),
                ("phone_number_verified", vec!["true"]),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
        let hash = argon2::Argon2::default()
            .hash_password("pass".as_bytes(), &salt)
            .unwrap()
            .to_string();
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

        // Client with the contact scopes registered (token endpoint validates
        // requested scopes against the client's scopes now).
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("contact-cli").unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new("contact-cli").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: issuerd_core::ClientProtocol::OpenIdConnect,
            public_client: true,
            bearer_only: false,
            client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid email address phone"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let body = "grant_type=password&username=contactuser&password=pass&client_id=contact-cli&scope=openid%20email%20address%20phone".to_string();
        let resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = extract_json(resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {access_token}").parse().unwrap());
        let userinfo = userinfo_handler_get(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(userinfo.status(), StatusCode::OK);
        let info = extract_json(userinfo).await;

        assert_eq!(info["email"], "user@example.com");
        assert_eq!(info["email_verified"], true);
        assert_eq!(info["address"]["formatted"], "123 Main St");
        assert_eq!(info["address"]["street_address"], "Main St");
        assert_eq!(info["address"]["locality"], "Springfield");
        assert_eq!(info["address"]["region"], "IL");
        assert_eq!(info["address"]["postal_code"], "62701");
        assert_eq!(info["address"]["country"], "US");
        assert_eq!(info["phone_number"], "+1-555-1234");
        assert_eq!(info["phone_number_verified"], true);
    }

    #[tokio::test]
    async fn userinfo_claims_parameter() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();

        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("claimsuser").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("claimsuser").unwrap(),
            email: Some(Email::new("claims@example.com").unwrap()),
            email_verified: false,
            first_name: Some(issuerd_core::DisplayName::new("First").unwrap()),
            last_name: Some(issuerd_core::DisplayName::new("Last").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: [
                ("middle_name", vec!["Middle"]),
                ("nickname", vec!["Nick"]),
                ("profile", vec!["prof"]),
                ("picture", vec!["pic"]),
                ("website", vec!["web"]),
                ("gender", vec!["other"]),
                ("birthdate", vec!["2000-01-01"]),
                ("zoneinfo", vec!["EST"]),
                ("locale", vec!["en"]),
                ("address_formatted", vec!["123 Main St"]),
                ("address_street", vec!["Main St"]),
                ("address_locality", vec!["Springfield"]),
                ("address_region", vec!["IL"]),
                ("address_postal_code", vec!["62701"]),
                ("address_country", vec!["US"]),
                ("phone_number", vec!["+123"]),
                ("phone_number_verified", vec!["false"]),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
        let hash = argon2::Argon2::default()
            .hash_password("pass".as_bytes(), &salt)
            .unwrap()
            .to_string();
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

        // Create an auth code with claims data so the token carries the claims request
        let code = issuerd_core::utils::generate_id();
        let claims_json = serde_json::json!({"userinfo": {
            "name": null, "given_name": null, "family_name": null,
            "middle_name": null, "nickname": null, "preferred_username": null,
            "profile": null, "picture": null, "website": null,
            "gender": null, "birthdate": null, "zoneinfo": null, "locale": null,
            "updated_at": null, "email": null, "email_verified": null,
            "phone_number": null, "phone_number_verified": null, "address": null
        }});
        let code_data = AuthCodeData {
            user_id: "claimsuser".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: Some(claims_json),
            authorization_details: None,
        };
        state
            .cache
            .set(
                &format!("auth_code:{code}"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://localhost:8080/cb&client_id=admin-cli&code_verifier=dummy"
        );
        let resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = extract_json(resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {access_token}").parse().unwrap());
        let userinfo = userinfo_handler_get(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(userinfo.status(), StatusCode::OK);
        let info = extract_json(userinfo).await;

        assert_eq!(info["name"], "First Last");
        assert_eq!(info["given_name"], "First");
        assert_eq!(info["family_name"], "Last");
        assert_eq!(info["middle_name"], "Middle");
        assert_eq!(info["nickname"], "Nick");
        assert_eq!(info["preferred_username"], "claimsuser");
        assert_eq!(info["profile"], "prof");
        assert_eq!(info["picture"], "pic");
        assert_eq!(info["website"], "web");
        assert_eq!(info["gender"], "other");
        assert_eq!(info["birthdate"], "2000-01-01");
        assert_eq!(info["zoneinfo"], "EST");
        assert_eq!(info["locale"], "en");
        // Memory storage sets updated_at = created_at on user creation.
        assert_eq!(info["updated_at"], user.created_at.timestamp());
        assert_eq!(info["email"], "claims@example.com");
        assert_eq!(info["email_verified"], false);
        assert_eq!(info["phone_number"], "+123");
        assert_eq!(info["phone_number_verified"], false);
        assert_eq!(info["address"]["formatted"], "123 Main St");
    }

    #[tokio::test]
    async fn userinfo_claims_parameter_name_partial() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();

        // User with only first_name
        let user1 = issuerd_core::User {
            id: issuerd_core::UserId::new("firstonly").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("firstonly").unwrap(),
            email: None,
            email_verified: false,
            first_name: Some(issuerd_core::DisplayName::new("Alice").unwrap()),
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: Default::default(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user1).await.unwrap();
        let salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
        let hash = argon2::Argon2::default()
            .hash_password("pass".as_bytes(), &salt)
            .unwrap()
            .to_string();
        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&realm_id, &user1.id, &cred).await.unwrap();

        // User with only last_name
        let user2 = issuerd_core::User {
            id: issuerd_core::UserId::new("lastonly").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("lastonly").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: Some(issuerd_core::DisplayName::new("Bob").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: Default::default(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user2).await.unwrap();
        let salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
        let hash = argon2::Argon2::default()
            .hash_password("pass".as_bytes(), &salt)
            .unwrap()
            .to_string();
        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&realm_id, &user2.id, &cred).await.unwrap();

        for (user_id, expected_name) in [("firstonly", "Alice"), ("lastonly", "Bob")] {
            let code = issuerd_core::utils::generate_id();
            let claims_json = serde_json::json!({"userinfo": {"name": null}});
            let code_data = AuthCodeData {
                user_id: user_id.to_string(),
                client_id: "admin-cli".to_string(),
                redirect_uri: "http://localhost:8080/cb".to_string(),
                scope: vec!["openid".to_string()],
                state: None,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                session_id: None,
                auth_time: None,
                acr_values: vec![],
                claims: Some(claims_json),
                authorization_details: None,
            };
            state
                .cache
                .set(
                    &format!("auth_code:{code}"),
                    serde_json::to_vec(&code_data).unwrap(),
                    Some(std::time::Duration::from_secs(600)),
                )
                .await
                .unwrap();

            let body = format!(
                "grant_type=authorization_code&code={code}&redirect_uri=http://localhost:8080/cb&client_id=admin-cli&code_verifier=dummy"
            );
            let resp = token_handler(
                State(state.clone()),
                axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
                axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
                axum::http::HeaderMap::new(),
                body,
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let json = extract_json(resp).await;
            let access_token = json["access_token"].as_str().unwrap();

            let mut headers = axum::http::HeaderMap::new();
            headers.insert("authorization", format!("Bearer {access_token}").parse().unwrap());
            let userinfo = userinfo_handler_get(
                State(state.clone()),
                axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
                headers,
            )
            .await;
            assert_eq!(userinfo.status(), StatusCode::OK);
            let info = extract_json(userinfo).await;
            assert_eq!(info["name"], expected_name, "mismatch for user {user_id}");
        }
    }

    #[tokio::test]
    async fn userinfo_invalid_auth_header_utf8() {
        let state = setup_state().await;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            axum::http::HeaderValue::from_bytes(&[0x80, 0x81, 0x82]).unwrap(),
        );
        let resp = userinfo_handler_get(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn userinfo_post_empty_token() {
        let state = setup_state().await;
        let resp = userinfo_handler_post(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            "".to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_handler_disabled_client() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let mut client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        client.enabled = false;
        state.storage.update_client(&realm_id, &client).await.unwrap();

        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());

        // Browser requests (Accept: text/html) get the login-page error
        // redirect, exactly like an unknown client.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::ACCEPT, "text/html".parse().unwrap());
        let resp = auth_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            headers,
            Query(params.clone()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(loc.contains("error=invalid_client"), "location: {loc}");

        // Non-HTML callers get a plain 400.
        let resp = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_password_grant_missing_username() {
        let state = setup_state().await;
        let body =
            "grant_type=password&password=admin&client_id=admin-cli&scope=openid".to_string();
        let resp = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_password_grant_public_client_no_secret() {
        let state = setup_state().await;
        // admin-cli is public; password grant should work without client_secret
        let body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let resp = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = extract_json(resp).await;
        assert!(json["access_token"].as_str().unwrap().len() > 10);
    }

    #[tokio::test]
    async fn device_auth_missing_client_id() {
        let state = setup_state().await;
        let body = "scope=openid".to_string();
        let resp = device_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(resp).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn ciba_approve_invalid_action() {
        let state = setup_state().await;
        let _realm_id = issuerd_core::RealmId::new("master").unwrap();

        // Seed a valid CIBA auth req in cache
        let auth_req_id = "test-ciba-req-1".to_string();
        let req_data = CibaAuthReqData {
            auth_req_id: auth_req_id.clone(),
            client_id: "admin-cli".to_string(),
            realm_id: "master".to_string(),
            user_id: Some("admin".to_string()),
            scope: vec!["openid".to_string()],
            binding_message: None,
            client_notification_token: None,
            authorized: false,
            denied: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::ciba_auth_req(&auth_req_id),
                serde_json::to_vec(&req_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let headers = session_cookie_headers(&state, "admin").await;
        let body = format!("auth_req_id={auth_req_id}&action=unknown");
        let resp = ciba_approve_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers,
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(resp).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn auth_code_pkce_plain_success() {
        let state = setup_state().await;
        let code = issuerd_core::utils::generate_id();
        let verifier = "a".repeat(43);
        let code_data = AuthCodeData {
            user_id: "admin".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: Some(issuerd_core::Base64Url::new(&verifier).unwrap()),
            code_challenge_method: Some(PkceCodeChallengeMethod::Plain),
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: None,
            authorization_details: None,
        };
        state
            .cache
            .set(
                &format!("auth_code:{code}"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://localhost:8080/cb&client_id=admin-cli&code_verifier={verifier}"
        );
        let resp = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = extract_json(resp).await;
        assert!(json["access_token"].as_str().unwrap().len() > 10);
    }

    #[tokio::test]
    async fn token_auth_code_missing_verifier() {
        let state = setup_state().await;
        let code = issuerd_core::utils::generate_id();
        let code_data = AuthCodeData {
            user_id: "admin".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: Some(issuerd_core::Base64Url::new("challenge").unwrap()),
            code_challenge_method: Some(PkceCodeChallengeMethod::S256),
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: None,
            authorization_details: None,
        };
        state
            .cache
            .set(
                &format!("auth_code:{code}"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://localhost:8080/cb&client_id=admin-cli"
        );
        let resp = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn auth_handler_post_invalid_form() {
        let state = setup_state().await;
        let response = auth_handler_post(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            axum::extract::Query(std::collections::HashMap::new()),
            "foo=%ZZ".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn device_verify_handler_missing_realm() {
        let state = setup_state().await;
        let response = device_verify_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(None)),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "user_code=ABCD-EFGH&username=admin&password=admin".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn device_verify_handler_invalid_form() {
        let state = setup_state().await;
        let response = device_verify_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "foo=%ZZ".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn device_verify_handler_empty_fields() {
        let state = setup_state().await;
        let response = device_verify_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "user_code=&username=&password=".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn device_verify_handler_expired_token() {
        let state = setup_state().await;
        let response = device_verify_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "user_code=NOEXIST&username=admin&password=admin".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "expired_token");
    }

    #[tokio::test]
    async fn device_verify_handler_realm_mismatch() {
        let state = setup_state().await;
        let code_data = DeviceCodeData {
            device_code: "device-123".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            client_id: "admin-cli".to_string(),
            realm_id: "other-realm".to_string(),
            scope: vec!["openid".to_string()],
            user_id: None,
            authorized: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::user_code("ABCD-EFGH"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = device_verify_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "user_code=ABCD-EFGH&username=admin&password=admin".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "expired_token");
    }

    #[tokio::test]
    async fn device_verify_handler_user_not_found() {
        let state = setup_state().await;
        let code_data = DeviceCodeData {
            device_code: "device-123".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            client_id: "admin-cli".to_string(),
            realm_id: "master".to_string(),
            scope: vec!["openid".to_string()],
            user_id: None,
            authorized: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::user_code("ABCD-EFGH"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = device_verify_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "user_code=ABCD-EFGH&username=nobody&password=admin".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn device_verify_handler_no_credentials() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("nocreds").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("nocreds").unwrap(),
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

        let code_data = DeviceCodeData {
            device_code: "device-123".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            client_id: "admin-cli".to_string(),
            realm_id: "master".to_string(),
            scope: vec!["openid".to_string()],
            user_id: None,
            authorized: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::user_code("ABCD-EFGH"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = device_verify_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "user_code=ABCD-EFGH&username=nocreds&password=admin".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn device_verify_handler_malformed_hash() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("badhash").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("badhash").unwrap(),
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
            secret_data: b"not_valid_utf8_\xff".to_vec(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&realm_id, &user.id, &cred).await.unwrap();

        let cred2 = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password2".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: b"not_a_valid_hash".to_vec(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 2,
        };
        state.storage.create_credential(&realm_id, &user.id, &cred2).await.unwrap();

        let code_data = DeviceCodeData {
            device_code: "device-123".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            client_id: "admin-cli".to_string(),
            realm_id: "master".to_string(),
            scope: vec!["openid".to_string()],
            user_id: None,
            authorized: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::user_code("ABCD-EFGH"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = device_verify_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            "user_code=ABCD-EFGH&username=badhash&password=admin".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn ciba_auth_handler_client_not_found() {
        let state = setup_state().await;
        let body = "client_id=no-such-client&login_hint=admin&scope=openid".to_string();
        let response = ciba_auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn ciba_approve_handler_invalid_form() {
        let state = setup_state().await;
        let response = ciba_approve_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "foo=%ZZ".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn ciba_approve_handler_empty_fields() {
        let state = setup_state().await;
        let response = ciba_approve_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "auth_req_id=&action=".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn ciba_approve_handler_expired() {
        let state = setup_state().await;
        let response = ciba_approve_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "auth_req_id=nonexistent&action=approve".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "expired_token");
    }

    #[tokio::test]
    async fn ciba_approve_handler_realm_mismatch() {
        let state = setup_state().await;
        let auth_req_id = "test-req-mismatch".to_string();
        let req_data = CibaAuthReqData {
            auth_req_id: auth_req_id.clone(),
            client_id: "admin-cli".to_string(),
            realm_id: "other-realm".to_string(),
            user_id: Some("admin".to_string()),
            scope: vec!["openid".to_string()],
            binding_message: None,
            client_notification_token: None,
            authorized: false,
            denied: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::ciba_auth_req(&auth_req_id),
                serde_json::to_vec(&req_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = ciba_approve_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!("auth_req_id={auth_req_id}&action=approve"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "expired_token");
    }

    #[tokio::test]
    async fn ciba_approve_without_session_returns_401() {
        let state = setup_state().await;
        let auth_req_id = "test-ciba-no-session".to_string();
        let req_data = CibaAuthReqData {
            auth_req_id: auth_req_id.clone(),
            client_id: "admin-cli".to_string(),
            realm_id: "master".to_string(),
            user_id: Some("admin".to_string()),
            scope: vec!["openid".to_string()],
            binding_message: None,
            client_notification_token: None,
            authorized: false,
            denied: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::ciba_auth_req(&auth_req_id),
                serde_json::to_vec(&req_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let response = ciba_approve_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!("auth_req_id={auth_req_id}&action=approve"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ciba_approve_other_user_session_returns_401() {
        let state = setup_state().await;
        // A second user whose session must not authorize approval of admin's request.
        let mallory = issuerd_core::User {
            id: issuerd_core::UserId::new("mallory").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            username: issuerd_core::Username::new("mallory").unwrap(),
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
        state.storage.create_user(&mallory.realm_id, &mallory).await.unwrap();

        let auth_req_id = "test-ciba-wrong-user".to_string();
        let req_data = CibaAuthReqData {
            auth_req_id: auth_req_id.clone(),
            client_id: "admin-cli".to_string(),
            realm_id: "master".to_string(),
            user_id: Some("admin".to_string()),
            scope: vec!["openid".to_string()],
            binding_message: None,
            client_notification_token: None,
            authorized: false,
            denied: false,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::ciba_auth_req(&auth_req_id),
                serde_json::to_vec(&req_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let headers = session_cookie_headers(&state, "mallory").await;
        let response = ciba_approve_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers,
            format!("auth_req_id={auth_req_id}&action=approve"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_handler_realm_not_found() {
        let state = setup_state().await;
        let body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("nonexistent".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "realm not found");
    }

    #[tokio::test]
    async fn token_handler_client_not_found() {
        let state = setup_state().await;
        let body = "grant_type=password&username=admin&password=admin&client_id=no-such-client"
            .to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn token_auth_code_reuse_revokes_refresh_token() {
        let state = setup_state().await;
        let code = issuerd_core::utils::generate_id();
        let code_data = AuthCodeData {
            user_id: "admin".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost:8080/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            session_id: None,
            auth_time: None,
            acr_values: vec![],
            claims: None,
            authorization_details: None,
        };
        state
            .cache
            .set(
                &format!("auth_code:{code}"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://localhost:8080/cb&client_id=admin-cli&code_verifier=xyz"
        );
        let first_response = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body.clone(),
        )
        .await;
        assert_eq!(first_response.status(), StatusCode::OK);
        let first_json = extract_json(first_response).await;
        let refresh_token = first_json["refresh_token"].as_str().unwrap().to_string();

        // Reuse the same code
        let second_response = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(second_response.status(), StatusCode::BAD_REQUEST);

        // The previously issued refresh token should now be revoked
        let refresh_body =
            format!("grant_type=refresh_token&refresh_token={refresh_token}&client_id=admin-cli");
        let refresh_resp = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            refresh_body,
        )
        .await;
        assert_eq!(refresh_resp.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(refresh_resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_password_grant_no_credentials() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("nocreduser").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("nocreduser").unwrap(),
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

        let body = "grant_type=password&username=nocreduser&password=admin&client_id=admin-cli&scope=openid".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn token_password_grant_malformed_hash() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("badhashuser").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("badhashuser").unwrap(),
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
            secret_data: b"not_a_valid_hash_string".to_vec(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        state.storage.create_credential(&realm_id, &user.id, &cred).await.unwrap();

        let body = "grant_type=password&username=badhashuser&password=admin&client_id=admin-cli&scope=openid".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn unsupported_grant_type() {
        let state = setup_state().await;
        let body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&client_id=admin-cli&assertion=dummy&assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn userinfo_revoked_token() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        let json = extract_json(password_resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        state
            .cache
            .set(
                &format!("revoked:{access_token}"),
                vec![1],
                Some(std::time::Duration::from_secs(86400)),
            )
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {access_token}").parse().unwrap());

        let response = userinfo_handler_get(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_token");
    }

    #[tokio::test]
    async fn introspect_invalid_token() {
        let state = setup_state().await;
        let response = introspect_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            "token=invalid.token.value&client_id=admin-cli".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["active"], false);
    }

    #[tokio::test]
    async fn introspect_requires_client_auth() {
        let state = setup_state().await;
        let response = introspect_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            "token=anything".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn introspect_foreign_client_token_reports_inactive() {
        let state = setup_state().await;
        // A second client in the same realm.
        let other = issuerd_core::Client {
            id: issuerd_core::ClientId::new("other-1").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("other-client").unwrap(),
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
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&other.realm_id, &other).await.unwrap();

        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        let json = extract_json(password_resp).await;
        let access_token = json["access_token"].as_str().unwrap();

        // The token was issued to admin-cli; introspecting as other-client
        // must not disclose anything beyond active:false.
        let response = introspect_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            format!("token={access_token}&client_id=other-client"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["active"], false);
    }

    #[tokio::test]
    async fn logout_without_refresh_token() {
        let state = setup_state().await;
        let response = logout_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn logout_deletes_session_and_blacklists_refresh_token() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = state
            .storage
            .get_user(&realm_id, &issuerd_core::UserId::new("admin").unwrap())
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let now = chrono::Utc::now();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: issuerd_core::AuthMethod::Password,
            remember_me: false,
            offline: false,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: vec![],
        };
        state.storage.create_user_session(&realm_id, &session).await.unwrap();
        let refresh = state
            .token_manager
            .issue_refresh_token(
                &user,
                &client,
                &realm,
                &session_id,
                &["openid".to_string()],
                false,
                None,
                None,
            )
            .await
            .unwrap();

        let response = logout_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!("refresh_token={}", refresh.token),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // The SSO session must be gone, not just the token blacklisted.
        assert!(state.storage.get_user_session(&realm_id, &session_id).await.unwrap().is_none());
        let blacklisted =
            state.cache.get(&format!("revoked_refresh:{}", refresh.token)).await.unwrap();
        assert!(blacklisted.is_some());
    }

    /// Offline-session logout semantics: an `id_token_hint` that points at the
    /// OFFLINE session must not destroy it (the offline refresh token
    /// survives browser logout), while the ONLINE SSO session referenced by
    /// the `issuerd_session` cookie — the session the user is actually logging
    /// out of — must be deleted.
    #[tokio::test]
    async fn logout_id_token_hint_preserves_offline_session_but_ends_cookie_sso_session() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = state
            .storage
            .get_user(&realm_id, &issuerd_core::UserId::new("admin").unwrap())
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let now = chrono::Utc::now();
        let mk_session = |offline: bool| issuerd_core::UserSession {
            id: issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: issuerd_core::AuthMethod::Password,
            remember_me: false,
            offline,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: vec![],
        };
        // In the offline_access flow the issued tokens point at the offline
        // session; the browser cookie keeps pointing at the online session.
        let offline_session = mk_session(true);
        let online_session = mk_session(false);
        let offline_id = offline_session.id.clone();
        let online_id = online_session.id.clone();
        state.storage.create_user_session(&realm_id, &offline_session).await.unwrap();
        state.storage.create_user_session(&realm_id, &online_session).await.unwrap();

        let id_hint = state
            .token_manager
            .issue_access_token_with_roles(
                &user,
                &client,
                &realm,
                &["openid".to_string()],
                &offline_id,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let cookie_token = state
            .token_manager
            .issue_access_token_with_roles(
                &user,
                &client,
                &realm,
                &["openid".to_string()],
                &online_id,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("issuerd_session={}", cookie_token.token).parse().unwrap(),
        );
        let mut params = std::collections::HashMap::new();
        params.insert("id_token_hint".to_string(), id_hint.token);

        let response = logout_handler_get(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            headers,
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // The offline session (and thus the offline refresh token) survives…
        assert!(state.storage.get_user_session(&realm_id, &offline_id).await.unwrap().is_some());
        // …while the online SSO session is gone.
        assert!(state.storage.get_user_session(&realm_id, &online_id).await.unwrap().is_none());
    }

    /// An explicitly presented refresh token terminates its own grant — even
    /// when that grant is an offline session (RFC 7009-style revocation via
    /// the logout endpoint).
    #[tokio::test]
    async fn logout_with_refresh_token_destroys_offline_session() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = state
            .storage
            .get_user(&realm_id, &issuerd_core::UserId::new("admin").unwrap())
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let now = chrono::Utc::now();
        let offline_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let session = issuerd_core::UserSession {
            id: offline_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: issuerd_core::AuthMethod::Password,
            remember_me: false,
            offline: true,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: vec![],
        };
        state.storage.create_user_session(&realm_id, &session).await.unwrap();
        let refresh = state
            .token_manager
            .issue_refresh_token(
                &user,
                &client,
                &realm,
                &offline_id,
                &["openid".to_string(), "offline_access".to_string()],
                true,
                None,
                None,
            )
            .await
            .unwrap();

        let response = logout_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!("refresh_token={}", refresh.token),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(state.storage.get_user_session(&realm_id, &offline_id).await.unwrap().is_none());
    }

    #[test]
    fn fold_basic_auth_absent_header_is_noop() {
        let headers = axum::http::HeaderMap::new();
        let mut params = HashMap::from([("client_id".to_string(), "app".to_string())]);
        assert!(fold_basic_auth(&headers, &mut params).is_ok());
        assert!(!params.contains_key("client_secret"));
        assert_eq!(params.get("client_id").unwrap(), "app");
    }

    #[test]
    fn fold_basic_auth_fills_params_from_header() {
        let mut headers = axum::http::HeaderMap::new();
        let creds =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "app:s3cret");
        headers.insert("authorization", format!("Basic {creds}").parse().unwrap());
        let mut params = HashMap::new();
        assert!(fold_basic_auth(&headers, &mut params).is_ok());
        assert_eq!(params.get("client_id").unwrap(), "app");
        assert_eq!(params.get("client_secret").unwrap(), "s3cret");
    }

    #[test]
    fn fold_basic_auth_accepts_matching_body_client_id() {
        // RFC 9126 §1.1's own example shape: Basic header AND body client_id.
        let mut headers = axum::http::HeaderMap::new();
        let creds =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "app:s3cret");
        headers.insert("authorization", format!("Basic {creds}").parse().unwrap());
        let mut params = HashMap::from([("client_id".to_string(), "app".to_string())]);
        assert!(fold_basic_auth(&headers, &mut params).is_ok());
        assert_eq!(params.get("client_secret").unwrap(), "s3cret");
    }

    #[test]
    fn fold_basic_auth_rejects_mismatched_client_id_with_challenge() {
        let mut headers = axum::http::HeaderMap::new();
        let creds =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "app:s3cret");
        headers.insert("authorization", format!("Basic {creds}").parse().unwrap());
        let mut params = HashMap::from([("client_id".to_string(), "other".to_string())]);
        let resp = fold_basic_auth(&headers, &mut params).unwrap_err();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().contains_key(axum::http::header::WWW_AUTHENTICATE));
        assert!(!params.contains_key("client_secret"));
    }

    #[test]
    fn fold_basic_auth_rejects_contradicting_client_secret() {
        let mut headers = axum::http::HeaderMap::new();
        let creds =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "app:s3cret");
        headers.insert("authorization", format!("Basic {creds}").parse().unwrap());
        let mut params = HashMap::from([
            ("client_id".to_string(), "app".to_string()),
            ("client_secret".to_string(), "different".to_string()),
        ]);
        let resp = fold_basic_auth(&headers, &mut params).unwrap_err();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    fn access_claims(
        sub: &str,
        sid: Option<issuerd_core::SessionId>,
        azp: &str,
    ) -> AccessTokenClaims {
        AccessTokenClaims {
            jti: issuerd_core::JwtId::new("jti").unwrap(),
            iss: issuerd_core::Issuer::new("http://localhost:8080/realms/master").unwrap(),
            sub: issuerd_core::UserId::new(sub).unwrap(),
            aud: issuerd_core::Audience::new(azp).unwrap(),
            exp: chrono::Utc::now().timestamp() + 300,
            iat: chrono::Utc::now().timestamp(),
            nbf: chrono::Utc::now().timestamp(),
            scope: Scope::parse("openid"),
            typ: issuerd_core::JwtType::Bearer,
            azp: Some(azp.to_string()),
            session_state: None,
            realm_access: None,
            resource_access: None,
            sid,
            claims: None,
            cnf: None,
            authorization_details: None,
        }
    }

    /// Regression test: a pairwise subject can never resolve to a
    /// stored user, so the destroyed-session check must not key on user
    /// resolution — a pairwise token whose session is gone is invalidated.
    #[tokio::test]
    async fn session_invalidated_pairwise_sub_with_destroyed_session_is_invalidated() {
        let state = setup_state().await;
        let sid = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let claims = access_claims("pairwise-hmac-sub", Some(sid), "admin-cli");
        assert!(session_invalidated(&state, &claims).await);
    }

    /// Session-less client-credentials tokens (synthetic sid, `sub` =
    /// `client_id`) must keep working — they never had a stored session.
    #[tokio::test]
    async fn session_invalidated_synthetic_client_credentials_token_is_not_invalidated() {
        let state = setup_state().await;
        let sid = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let claims = access_claims("admin-cli", Some(sid), "admin-cli");
        assert!(!session_invalidated(&state, &claims).await);
    }

    #[tokio::test]
    async fn logout_get_with_id_token_hint_redirects_and_deletes_session() {
        let state = setup_state().await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = state
            .storage
            .get_user(&realm_id, &issuerd_core::UserId::new("admin").unwrap())
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let now = chrono::Utc::now();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: issuerd_core::AuthMethod::Password,
            remember_me: false,
            offline: false,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: vec![],
        };
        state.storage.create_user_session(&realm_id, &session).await.unwrap();
        let id_token_hint = state
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

        let mut params = std::collections::HashMap::new();
        params.insert("id_token_hint".to_string(), id_token_hint.token);
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "post_logout_redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("state".to_string(), "xyz".to_string());

        let response = logout_handler_get(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(location, "http://localhost:8080/admin/console/callback?state=xyz");
        assert!(state.storage.get_user_session(&realm_id, &session_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn logout_post_logout_redirect_uri_unregistered_returns_400() {
        let state = setup_state().await;
        let mut params = std::collections::HashMap::new();
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "post_logout_redirect_uri".to_string(),
            "https://evil.example/steal".to_string(),
        );

        let response = logout_handler_get(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn discovery_advertises_realm_name_issuer_and_404s_unknown_realm() {
        let state = setup_state().await;
        seed_uuid_realm(&state).await;

        let response = discovery_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("uuid-realm".to_string()))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        // Tokens carry `iss = {issuer_url}/realms/{realm.name}`; discovery must
        // advertise the same issuer or conforming clients reject every token.
        // The seeded realm's storage id is a UUID — the advertised issuer must
        // carry the NAME, not the id.
        let expected = format!("{}/realms/uuid-realm", state.config.issuer_url);
        assert_eq!(json["issuer"], expected);

        let response = discovery_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("no-such-realm".to_string()))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn name_issuer_token_roundtrips_through_userinfo() {
        let state = setup_state().await;
        let realm_id = seed_uuid_realm(&state).await;
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let user = state
            .storage
            .get_user_by_username(&realm_id, "uuid-user")
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("uuid-client").unwrap())
            .await
            .unwrap()
            .unwrap();

        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let now = chrono::Utc::now();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: issuerd_core::AuthMethod::Password,
            remember_me: false,
            offline: false,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: vec![],
        };
        state.storage.create_user_session(&realm_id, &session).await.unwrap();

        let access = state
            .token_manager
            .issue_access_token(&user, &client, &realm, &["openid".to_string()], &session_id)
            .await
            .unwrap();

        // The issuer embeds the realm NAME, never the UUID storage id.
        let validated = state.token_service.validate_access_token(&access.token).unwrap();
        let expected_iss = format!("{}/realms/uuid-realm", state.config.issuer_url);
        assert_eq!(validated.claims.iss.as_str(), expected_iss);

        // userinfo resolves the issuer name back to the realm: the session
        // check and the user lookup both key off the resolved realm id.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {}", access.token).parse().unwrap());
        let response = userinfo_handler_get(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("uuid-realm".to_string()))),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert_eq!(json["sub"], user.id.as_ref());
    }

    #[tokio::test]
    async fn logout_resolves_realm_name_to_id() {
        let state = setup_state().await;
        let realm_id = seed_uuid_realm(&state).await;
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let user = state
            .storage
            .get_user_by_username(&realm_id, "uuid-user")
            .await
            .unwrap()
            .unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("uuid-client").unwrap())
            .await
            .unwrap()
            .unwrap();

        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let now = chrono::Utc::now();
        let session = issuerd_core::UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: issuerd_core::AuthMethod::Password,
            remember_me: false,
            offline: false,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: vec![],
        };
        state.storage.create_user_session(&realm_id, &session).await.unwrap();
        let refresh = state
            .token_manager
            .issue_refresh_token(
                &user,
                &client,
                &realm,
                &session_id,
                &["openid".to_string()],
                false,
                None,
                None,
            )
            .await
            .unwrap();

        // Logout addressed by realm *name* must still delete the session
        // stored under the realm *id*, and a registered
        // post_logout_redirect_uri must be accepted for UUID-id realms.
        let body = format!(
            "refresh_token={}&client_id=uuid-client&post_logout_redirect_uri=http%3A%2F%2Flocalhost%2Fcallback",
            refresh.token
        );
        let response = logout_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("uuid-realm".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        assert!(state.storage.get_user_session(&realm_id, &session_id).await.unwrap().is_none());
        let blacklisted =
            state.cache.get(&format!("revoked_refresh:{}", refresh.token)).await.unwrap();
        assert!(blacklisted.is_some());
    }

    #[tokio::test]
    async fn device_token_flow_user_not_found() {
        let state = setup_state().await;
        let code_data = DeviceCodeData {
            device_code: "device-123".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            client_id: "admin-cli".to_string(),
            realm_id: "master".to_string(),
            scope: vec!["openid".to_string()],
            user_id: Some("nonexistent-user".to_string()),
            authorized: true,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::device_code("device-123"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let body = "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=admin-cli&device_code=device-123".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn device_token_flow_client_not_found() {
        let state = setup_state().await;
        let code_data = DeviceCodeData {
            device_code: "device-123".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            client_id: "no-such-client".to_string(),
            realm_id: "master".to_string(),
            scope: vec!["openid".to_string()],
            user_id: Some("admin".to_string()),
            authorized: true,
            last_polled_at: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        };
        state
            .cache
            .set(
                &issuerd_cluster::cache_keys::device_code("device-123"),
                serde_json::to_vec(&code_data).unwrap(),
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();

        // Use a valid request client_id so early lookup passes; code_data client_id is invalid
        let body = "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=admin-cli&device_code=device-123".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn auth_handler_realm_lookup_error() {
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage
            .expect_get_realm_by_name()
            .returning(|_| Err(issuerd_core::IssuerdError::ServerError("db fail".to_string())));
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
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn auth_handler_client_lookup_error() {
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
        mock_storage
            .expect_get_client_by_client_id()
            .returning(|_, _| Err(issuerd_core::IssuerdError::ServerError("db fail".to_string())));
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
        let mut params = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "http://localhost:8080/admin/console/callback".to_string(),
        );
        params.insert("scope".to_string(), "openid".to_string());
        let response = auth_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            Query(params),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_handler_invalid_grant_type() {
        let state = setup_state().await;
        let body = "grant_type=unknown_grant&client_id=admin-cli".to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(response).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn password_grant_token_issuance_error() {
        let state = crate::routes::login_api::tests::state_for_mock_token(false, false).await;
        let body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn password_grant_without_openid_scope() {
        let state = setup_state().await;
        let body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=profile"
                .to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = extract_json(response).await;
        assert!(json["access_token"].as_str().is_some());
        assert!(json["id_token"].is_null());
    }

    #[tokio::test]
    async fn refresh_token_grant_without_openid_scope() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid%20profile"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let refresh_token = json["refresh_token"].as_str().unwrap();

        // Narrowing to a granted subset scope is allowed (RFC 6749 §6).
        let refresh_body = format!(
            "grant_type=refresh_token&refresh_token={}&client_id=admin-cli&scope=profile",
            refresh_token
        );
        let refresh_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            refresh_body,
        )
        .await;
        assert_eq!(refresh_resp.status(), StatusCode::OK);
        let json = extract_json(refresh_resp).await;
        assert!(json["access_token"].as_str().is_some());
        assert!(json["id_token"].is_null());
    }

    #[tokio::test]
    async fn refresh_token_grant_scope_escalation_rejected() {
        let state = setup_state().await;
        let password_body =
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string();
        let password_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            password_body,
        )
        .await;
        assert_eq!(password_resp.status(), StatusCode::OK);
        let json = extract_json(password_resp).await;
        let refresh_token = json["refresh_token"].as_str().unwrap();

        // "profile" was not granted with this refresh token: must be rejected.
        let refresh_body = format!(
            "grant_type=refresh_token&refresh_token={}&client_id=admin-cli&scope=openid%20profile",
            refresh_token
        );
        let refresh_resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            refresh_body,
        )
        .await;
        assert_eq!(refresh_resp.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(refresh_resp).await;
        assert_eq!(json["error"], "invalid_scope");
    }

    #[tokio::test]
    async fn client_credentials_token_issuance_error() {
        let mut state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        state.token_manager = crate::routes::login_api::tests::mock_token_manager(false, false);
        let state = Arc::new(state);

        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("conf-cc").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("conf-cc").unwrap(),
            name: Some(issuerd_core::DisplayName::new("CC").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();

        let body =
            "grant_type=client_credentials&client_id=conf-cc&client_secret=s3cr3t&scope=openid"
                .to_string();
        let response = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn build_redirect_url_encodes_special_chars() {
        let url = build_redirect_url(
            "https://client.example/cb",
            &[("code", "abc"), ("state", "a&b=c#d e")],
            false,
        );
        assert_eq!(url, "https://client.example/cb?code=abc&state=a%26b%3Dc%23d+e");
    }

    #[test]
    fn build_redirect_url_appends_to_existing_query() {
        let url =
            build_redirect_url("https://client.example/cb?foo=bar", &[("code", "abc")], false);
        assert_eq!(url, "https://client.example/cb?foo=bar&code=abc");
    }

    #[test]
    fn build_redirect_url_fragment_mode() {
        let url = build_redirect_url("https://client.example/cb", &[("id_token", "t.ok.en")], true);
        assert_eq!(url, "https://client.example/cb#id_token=t.ok.en");
    }

    // -- Realm not_before ----------------------------------------------------

    /// Password grant against the bootstrap master realm; fails on non-200.
    async fn password_grant_tokens(state: &Arc<ServerState>) -> serde_json::Value {
        let resp = token_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            "grant_type=password&username=admin&password=admin&client_id=admin-cli&scope=openid"
                .to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        extract_json(resp).await
    }

    /// Move the master realm's not_before cutoff one hour into the future so
    /// every token issued so far predates it.
    async fn bump_master_not_before(state: &Arc<ServerState>) {
        let realm_id = RealmId::new("master").unwrap();
        let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        realm.not_before = chrono::Utc::now().timestamp() + 3600;
        state.storage.update_realm(&realm).await.unwrap();
        // Mirrors the admin route's synchronous invalidation of the
        // realm-by-name cache (`resolve_issuer_realm`); a direct storage
        // write would otherwise stay hidden for the cache TTL.
        state
            .cache
            .delete(&issuerd_cluster::cache_keys::realm_by_name("master"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn not_before_rejects_userinfo_and_introspection() {
        let state = setup_state().await;
        let json = password_grant_tokens(&state).await;
        let access_token = json["access_token"].as_str().unwrap().to_string();

        // Sanity: the token is usable before the cutoff moves.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {access_token}").parse().unwrap());
        let resp = userinfo_handler_get(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers.clone(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        bump_master_not_before(&state).await;

        let resp = userinfo_handler_get(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            headers,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = extract_json(resp).await;
        assert_eq!(json["error"], "invalid_token");

        let resp = introspect_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::http::HeaderMap::new(),
            format!("token={access_token}&client_id=admin-cli"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = extract_json(resp).await;
        assert_eq!(json["active"], false);
    }

    #[tokio::test]
    async fn not_before_rejects_refresh_grant() {
        let state = setup_state().await;
        let json = password_grant_tokens(&state).await;
        let refresh_token = json["refresh_token"].as_str().unwrap().to_string();

        bump_master_not_before(&state).await;

        let resp = token_handler(
            State(state),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!("grant_type=refresh_token&refresh_token={refresh_token}&client_id=admin-cli"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = extract_json(resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    // -- User-event gating + listener dispatch --------------------------------

    /// Test listener recording every dispatched user event.
    #[derive(Default)]
    struct RecordingListener {
        events: std::sync::Mutex<Vec<issuerd_core::EventType>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::EventListener for RecordingListener {
        async fn on_event(
            &self,
            event: &issuerd_core::Event,
        ) -> Result<(), issuerd_core::IssuerdError> {
            self.events.lock().unwrap().push(event.event_type.clone());
            Ok(())
        }

        async fn on_admin_event(
            &self,
            _event: &issuerd_core::AdminEvent,
        ) -> Result<(), issuerd_core::IssuerdError> {
            Ok(())
        }
    }

    async fn query_all_events(state: &Arc<ServerState>, realm: &str) -> Vec<issuerd_core::Event> {
        state
            .storage
            .query_events(
                &RealmId::new(realm).unwrap(),
                &issuerd_core::EventQuery {
                    event_type: None,
                    client_id: None,
                    user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: issuerd_core::Pagination::default(),
                },
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn emit_oidc_event_skipped_when_realm_events_disabled() {
        let state = setup_state().await;
        // Issuerd defaults to events_enabled=true; disable explicitly to
        // exercise the gate.
        let realm_id = RealmId::new("master").unwrap();
        let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        realm.events_enabled = false;
        state.storage.update_realm(&realm).await.unwrap();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        emit_oidc_event(
            &state,
            &realm_id,
            issuerd_core::EventType::Login,
            &ip,
            None,
            None,
            None,
            None,
            HashMap::new(),
        )
        .await;
        assert!(
            query_all_events(&state, "master").await.is_empty(),
            "events_enabled=false — nothing may be stored"
        );
    }

    #[tokio::test]
    async fn emit_oidc_event_recorded_and_dispatched_when_enabled() {
        let mut state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        let recorder = Arc::new(RecordingListener::default());
        state.event_listeners.insert("recording".to_string(), recorder.clone());
        let state = Arc::new(state);

        let realm_id = RealmId::new("master").unwrap();
        let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        realm.events_enabled = true;
        // One real listener plus an unknown name (ignored, debug-logged).
        realm.events_listeners = vec!["recording".to_string(), "no-such-listener".to_string()];
        state.storage.update_realm(&realm).await.unwrap();

        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        emit_oidc_event(
            &state,
            &realm_id,
            issuerd_core::EventType::Login,
            &ip,
            None,
            None,
            None,
            None,
            HashMap::new(),
        )
        .await;

        let events = query_all_events(&state, "master").await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, issuerd_core::EventType::Login);
        let recorded = recorder.events.lock().unwrap().clone();
        assert_eq!(recorded, vec![issuerd_core::EventType::Login]);
    }

    #[tokio::test]
    async fn emit_oidc_event_unknown_realm_still_recorded() {
        // Fail-open: a realm row that cannot be loaded must not blind the
        // audit trail (listener dispatch is skipped — the list is unknown).
        let state = setup_state().await;
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        emit_oidc_event(
            &state,
            &RealmId::new("ghost").unwrap(),
            issuerd_core::EventType::Custom("test".to_string()),
            &ip,
            None,
            None,
            None,
            Some("boom".to_string()),
            HashMap::new(),
        )
        .await;
        let events = query_all_events(&state, "ghost").await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].error.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn emit_oidc_event_fails_open_on_realm_fetch_error() {
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage
            .expect_get_realm()
            .returning(|_| Err(issuerd_core::IssuerdError::ServerError("db fail".to_string())));
        mock_storage.expect_save_event().times(1).returning(|_, _| Ok(()));
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

        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        emit_oidc_event(
            &state,
            &RealmId::new("master").unwrap(),
            issuerd_core::EventType::Login,
            &ip,
            None,
            None,
            None,
            None,
            HashMap::new(),
        )
        .await;
        // The `.times(1)` save_event expectation is verified when the mock
        // drops at the end of the test.
    }
}
