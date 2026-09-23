// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Identity brokering endpoints: login kickoff, external IdP callback, and first-broker-login.

//! Identity brokering endpoints: login kickoff, external IdP
//! callback, and the first-broker-login continuation pages.
//!
//! ## Flow (login mode)
//!
//! 1. The login page button (or a `kc_idp_hint` authorize request) lands the
//!    browser on `GET /realms/{realm}/broker/{alias}/login?flow={id}` where
//!    `id` is the pending browser-flow entry created by the authorize
//!    endpoint. The handler stores a single-use [`BrokerState`] (nonce, PKCE
//!    verifier we hold, the flow id) and 302s to the external IdP's
//!    authorization endpoint.
//! 2. The IdP returns the browser to `/broker/{alias}/endpoint?code&state`.
//!    The callback exchanges the code server-to-server
//!    ([`crate::broker::exchange_code_for_identity`]), then:
//!    - a known [`IdentityProviderLink`] → straight to login completion;
//!    - an unknown identity → first-broker-login decision
//!      ([`issuerd_core::decide_first_broker_login`]): auto-link / auto-create /
//!      the review-profile / link-via-password pages below.
//! 3. Completion reuses [`super::login_api::complete_login_with_method`] so a
//!    brokered login ends in a normal Issuerd session + authorization code,
//!    stamped `AuthMethod::IdentityProvider`. Pending required actions ride
//!    the required-action continuation machinery.
//!
//! ## Link mode
//!
//! `POST /account/api/linked-accounts/{alias}` (account console) returns a
//! `?link={action-token}` kickoff URL; the callback then links the external
//! identity to the **currently signed-in** user (the `issuerd_session` cookie must
//! match the token's subject — this blocks login-CSRF link injection) and
//! redirects back to the account console instead of issuing a session.
//!
//! ## Deviation from the plan
//!
//! The plan sketched first-broker-login as a flow-engine flow. The production
//! executor cannot resume sub-flow stages and the broker continuation state
//! (external identity, IdP alias) does not fit `PendingAuthData`, so the
//! continuation uses the required-actions idiom instead (cache entry +
//! server-rendered pages + PRG), as the other paused-flow pages do.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Form, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use issuerd_auth_flow::built_in::verify_password_hash;
use issuerd_core::{
    apply_mappers, decide_first_broker_login, AuthMethod, BrokerIdpSettings, BrokeredIdentity,
    CredentialType, DisplayName, Email, FirstBrokerLoginDecision, IdentityProviderConfig,
    IdentityProviderLink, IssuerdError, Realm, RealmId, SessionId, TypedFlowResult, User, UserId,
    Username,
};
use tracing::{info, instrument, warn};

use super::login_api::complete_login_with_method;
use super::oidc::{flow_cookie_header, has_flow_cookie, pending_auth_cache_key, PendingAuthData};
use super::required_actions::{error_banner, error_response, page, url_path_segment};
use crate::broker::{exchange_code_for_identity, resolve_idp_endpoints};
use crate::middleware::realm::ResolvedRealm;
use crate::state::ServerState;

const BROKER_STATE_TTL_SECS: u64 = 600;
const FIRST_LOGIN_TTL_SECS: u64 = 600;
/// TTL of the account-linking kickoff token minted by the account console.
pub(crate) const LINK_TOKEN_TTL_SECS: i64 = 300;

fn broker_state_cache_key(realm_id: &RealmId, state: &str) -> String {
    format!("broker_state:{}:{state}", realm_id.0)
}

fn first_login_cache_key(realm_id: &RealmId, execution: &str) -> String {
    format!("broker_fbl:{}:{execution}", realm_id.0)
}

/// State held while the browser is away at the external IdP.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BrokerState {
    /// Nonce sent to the IdP; verified against the ID token.
    nonce: String,
    /// PKCE S256 verifier we hold for the code exchange (when enabled).
    pkce_verifier: Option<String>,
    /// Login mode: the pending browser-flow entry from the authorize request.
    #[serde(default)]
    flow_id: Option<String>,
    /// Link mode: the local user being linked (from the action token).
    #[serde(default)]
    linking_user: Option<String>,
}

/// Paused first-broker-login state (review-profile / link-via-password).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BrokerFirstLoginData {
    /// The original authorization request; replayed on completion.
    pending: PendingAuthData,
    alias: String,
    identity: BrokeredIdentity,
    suggested_username: String,
    /// "review" (create a new account) or "link" (email conflict).
    mode: String,
    /// Link mode: the existing user whose email matched.
    #[serde(default)]
    existing_user_id: Option<String>,
    /// External refresh token, carried only when the IdP stores tokens.
    #[serde(default)]
    external_refresh_token: Option<String>,
    /// One-shot error banner carried across a POST→redirect (PRG pattern).
    #[serde(default)]
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The URL the external IdP redirects back to. Uses the URL path segment the
/// request arrived on (a realm name in practice) so the IdP's redirect matches
/// the registered client exactly.
fn callback_url(state: &ServerState, realm_segment: &str, alias: &str) -> String {
    format!(
        "{}/realms/{}/broker/{}/endpoint",
        state.config.issuer_url.trim_end_matches('/'),
        url_path_segment(realm_segment),
        url_path_segment(alias)
    )
}

/// Resolve the realm + IdP config for a broker request, with all the
/// precondition failures rendered as sign-in error pages.
async fn load_broker_target(
    state: &Arc<ServerState>,
    realm_segment: &Option<String>,
    alias: &str,
) -> Result<(Realm, IdentityProviderConfig), Response> {
    let realm_name = match realm_segment.as_deref() {
        Some(r) => r,
        None => return Err(error_response(StatusCode::BAD_REQUEST, "missing realm")),
    };
    let realm = match state.resolve_realm(realm_name).await {
        Ok(Some(r)) if r.enabled => r,
        _ => return Err(error_response(StatusCode::BAD_REQUEST, "unknown realm")),
    };
    let idp = match state.storage.get_identity_provider_by_alias(&realm.id, alias).await {
        Ok(Some(idp)) => idp,
        _ => return Err(error_response(StatusCode::NOT_FOUND, "unknown identity provider")),
    };
    let settings = BrokerIdpSettings::new(&idp);
    if !idp.enabled || !settings.is_broker_provider() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "this identity provider is not available for sign-in",
        ));
    }
    let problems = settings.validate();
    if !problems.is_empty() {
        warn!(realm = %realm.id, alias, problems = ?problems, "identity provider is misconfigured");
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "this identity provider is not configured correctly",
        ));
    }
    Ok((realm, idp))
}

fn error_redirect_to_login(realm_segment: &str, flow_id: Option<&str>, error: &str) -> Response {
    if let Some(flow) = flow_id {
        let url = format!(
            "/login.html?execution_id={}&realm={}&error={}",
            url_path_segment(flow),
            url_path_segment(realm_segment),
            url_path_segment(error)
        );
        return Redirect::to(&url).into_response();
    }
    error_response(StatusCode::BAD_REQUEST, error)
}

// ---------------------------------------------------------------------------
// GET /realms/{realm}/broker/{alias}/login — kickoff
// ---------------------------------------------------------------------------

#[instrument(skip(state, params, headers), fields(alias = %alias))]
pub async fn broker_login_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm_segment)): axum::extract::Extension<ResolvedRealm>,
    Path((_realm, alias)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let (realm, idp) = match load_broker_target(&state, &realm_segment, &alias).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let realm_segment = realm_segment.unwrap_or_default();

    // Mode selection: pending login flow, or an account-linking token.
    let flow_id = params.get("flow").cloned();
    let linking_user = match params.get("link") {
        Some(token) => {
            match issuerd_token::action_tokens::verify_action_token(
                state.crypto.as_ref(),
                token,
                issuerd_core::ACTION_TOKEN_PURPOSE_BROKER_LINK,
                &realm.id,
            )
            .await
            {
                Ok(claims) => Some(claims.sub),
                Err(_) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "the account-linking link is invalid or has expired",
                    )
                }
            }
        }
        None => None,
    };
    if linking_user.is_none() {
        match &flow_id {
            Some(flow) => {
                // The pending entry must exist and the browser must carry the
                // correlation cookie set when the flow was paused (CSRF).
                let key = pending_auth_cache_key(&realm.id, flow);
                let exists = matches!(state.cache.get(&key).await, Ok(Some(_)));
                if !exists || !has_flow_cookie(&headers, flow) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "the sign-in session has expired — please start again",
                    );
                }
            }
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "missing sign-in session (flow) or linking token (link)",
                );
            }
        }
    }

    let endpoints = match resolve_idp_endpoints(&state, &realm.id, &idp).await {
        Ok(e) => e,
        Err(e) => {
            warn!(realm = %realm.id, alias, error = %e, "cannot resolve IdP endpoints");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the identity provider could not be reached",
            );
        }
    };

    let settings = BrokerIdpSettings::new(&idp);
    let state_key = issuerd_core::utils::generate_id();
    let nonce = issuerd_core::utils::generate_id();
    let pkce_verifier = settings.pkce_enabled().then(|| {
        format!("{}{}", issuerd_core::utils::generate_id(), issuerd_core::utils::generate_id())
    });
    let entry = BrokerState {
        nonce: nonce.clone(),
        pkce_verifier: pkce_verifier.clone(),
        flow_id,
        linking_user,
    };
    let bytes = serde_json::to_vec(&entry).unwrap();
    if let Err(e) = state
        .cache
        .set(
            &broker_state_cache_key(&realm.id, &state_key),
            bytes,
            Some(Duration::from_secs(BROKER_STATE_TTL_SECS)),
        )
        .await
    {
        warn!(realm = %realm.id, alias, error = %e, "broker state cache write failed");
    }

    let mut url = match url::Url::parse(&endpoints.authorization_url) {
        Ok(u) => u,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the identity provider is misconfigured",
            );
        }
    };
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", settings.client_id().expect("validated by load_broker_target"));
        q.append_pair("redirect_uri", &callback_url(&state, &realm_segment, &alias));
        q.append_pair("scope", &settings.default_scope());
        q.append_pair("state", &state_key);
        q.append_pair("nonce", &nonce);
        if let Some(ref verifier) = pkce_verifier {
            q.append_pair(
                "code_challenge",
                &issuerd_protocol::pkce::PkceVerifier::s256_challenge(verifier),
            );
            q.append_pair("code_challenge_method", "S256");
        }
    }
    Redirect::to(url.as_str()).into_response()
}

// ---------------------------------------------------------------------------
// GET|POST /realms/{realm}/broker/{alias}/endpoint — the IdP callback
// ---------------------------------------------------------------------------

pub async fn broker_endpoint_handler_get(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm_segment)): axum::extract::Extension<ResolvedRealm>,
    Path((_realm, alias)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    endpoint_inner(state, realm_segment, alias, params, headers).await
}

/// POST variant: IdPs using `response_mode=form_post` deliver the code in the
/// body instead of the query string.
pub async fn broker_endpoint_handler_post(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm_segment)): axum::extract::Extension<ResolvedRealm>,
    Path((_realm, alias)): Path<(String, String)>,
    headers: HeaderMap,
    Form(params): Form<HashMap<String, String>>,
) -> Response {
    endpoint_inner(state, realm_segment, alias, params, headers).await
}

#[instrument(skip(state, params, headers), fields(alias = %alias))]
async fn endpoint_inner(
    state: Arc<ServerState>,
    realm_segment: Option<String>,
    alias: String,
    params: HashMap<String, String>,
    headers: HeaderMap,
) -> Response {
    let (realm, idp) = match load_broker_target(&state, &realm_segment, &alias).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let realm_segment = realm_segment.unwrap_or_default();

    // The state key identifies (and authenticates) the round-trip. It is
    // single-use: consumed here regardless of outcome.
    let state_key = params.get("state").cloned().unwrap_or_default();
    let broker_state: Option<BrokerState> =
        match state.cache.get_and_delete(&broker_state_cache_key(&realm.id, &state_key)).await {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            _ => None,
        };
    let Some(broker_state) = broker_state else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "the sign-in session is invalid or has expired — please start again",
        );
    };

    // IdP-side failure (user cancelled, access_denied, ...).
    if let Some(error) = params.get("error") {
        let description = params.get("error_description").cloned().unwrap_or_else(|| error.clone());
        info!(realm = %realm.id, alias, error = %issuerd_core::utils::sanitize_log_str(&description), "identity provider returned an error");
        return error_redirect_to_login(
            &realm_segment,
            broker_state.flow_id.as_deref(),
            "identity_provider_error",
        );
    }

    let Some(code) = params.get("code").cloned().filter(|c| !c.is_empty()) else {
        return error_response(StatusCode::BAD_REQUEST, "the provider sent no authorization code");
    };

    let endpoints = match resolve_idp_endpoints(&state, &realm.id, &idp).await {
        Ok(e) => e,
        Err(e) => {
            warn!(realm = %realm.id, alias, error = %e, "cannot resolve IdP endpoints");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the identity provider could not be reached",
            );
        }
    };

    let exchange = exchange_code_for_identity(
        &state,
        &realm.id,
        &idp,
        &endpoints,
        &code,
        &callback_url(&state, &realm_segment, &alias),
        broker_state.pkce_verifier.as_deref(),
        Some(broker_state.nonce.as_str()),
    )
    .await;
    let (identity, external_refresh_token) = match exchange {
        Ok(v) => v,
        Err(e) => {
            warn!(realm = %realm.id, alias, error = %e, "brokered code exchange failed");
            return error_redirect_to_login(
                &realm_segment,
                broker_state.flow_id.as_deref(),
                "identity_provider_error",
            );
        }
    };

    if let Some(linking_user) = broker_state.linking_user.clone() {
        return finish_linking(
            &state,
            &realm,
            &idp,
            &headers,
            &realm_segment,
            linking_user,
            identity,
            external_refresh_token,
        )
        .await;
    }

    finish_login(
        &state,
        &realm,
        &idp,
        &realm_segment,
        broker_state,
        identity,
        external_refresh_token,
    )
    .await
}

// ---------------------------------------------------------------------------
// Link mode completion
// ---------------------------------------------------------------------------

/// Extract the signed-in user from the realm's SSO session cookie, verifying
/// the cookie's realm (the issuer segment is a realm NAME) and (for linking)
/// that it belongs to `expect_user`.
async fn session_cookie_user(
    state: &Arc<ServerState>,
    realm: &Realm,
    headers: &HeaderMap,
) -> Option<UserId> {
    let token = super::oidc::find_realm_cookie(headers, &realm.id, "issuerd_session")?;
    let validated = state.token_service.validate_access_token(&token).ok()?;
    let token_realm =
        issuerd_core::typestate::extract_realm_from_issuer(validated.claims.iss.as_str());
    if token_realm != Some(realm.name.as_str()) {
        return None;
    }
    Some(validated.claims.sub)
}

#[allow(clippy::too_many_arguments)]
async fn finish_linking(
    state: &Arc<ServerState>,
    realm: &Realm,
    idp: &IdentityProviderConfig,
    headers: &HeaderMap,
    realm_segment: &str,
    linking_user: String,
    identity: BrokeredIdentity,
    external_refresh_token: Option<String>,
) -> Response {
    let account_url = |query: &str| {
        format!("/realms/{}/account/linked-accounts?{query}", url_path_segment(realm_segment))
    };

    // The browser must hold a live session for the user the link token was
    // issued to — otherwise anyone could steer a victim's external identity
    // onto an attacker's account (login CSRF).
    let session_user = session_cookie_user(state, realm, headers).await;
    let Ok(linking_user_id) = UserId::new(linking_user) else {
        return Redirect::to(&account_url("error=link-failed")).into_response();
    };
    if session_user.as_ref() != Some(&linking_user_id) {
        return Redirect::to(&account_url("error=link-session-mismatch")).into_response();
    }

    let alias = idp.alias.to_string();
    match state
        .storage
        .get_identity_provider_link(&realm.id, &alias, &identity.subject)
        .await
    {
        // Idempotent: already linked to this same account.
        Ok(Some(link)) if link.user_id == linking_user_id => {
            return Redirect::to(&account_url(&format!("linked={alias}"))).into_response();
        }
        // The external account belongs to somebody else.
        Ok(Some(_)) => {
            return Redirect::to(&account_url("error=already-linked")).into_response();
        }
        Ok(None) => {}
        Err(e) => {
            warn!(error = %e, "link lookup failed");
            return Redirect::to(&account_url("error=link-failed")).into_response();
        }
    }

    let settings = BrokerIdpSettings::new(idp);
    let link = IdentityProviderLink {
        user_id: linking_user_id,
        provider_alias: alias.clone(),
        external_subject: identity.subject.clone(),
        external_username: identity.username.clone().or(identity.email.clone()),
        stored_refresh_token: settings.store_tokens().then_some(external_refresh_token).flatten(),
        created_at: chrono::Utc::now(),
    };
    match state.storage.create_identity_provider_link(&realm.id, &link).await {
        Ok(()) => Redirect::to(&account_url(&format!("linked={alias}"))).into_response(),
        Err(IssuerdError::Conflict) => {
            Redirect::to(&account_url("error=already-linked")).into_response()
        }
        Err(e) => {
            warn!(error = %e, "link creation failed");
            Redirect::to(&account_url("error=link-failed")).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Login mode completion
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn finish_login(
    state: &Arc<ServerState>,
    realm: &Realm,
    idp: &IdentityProviderConfig,
    realm_segment: &str,
    broker_state: BrokerState,
    identity: BrokeredIdentity,
    external_refresh_token: Option<String>,
) -> Response {
    let Some(flow_id) = broker_state.flow_id.clone() else {
        return error_response(StatusCode::BAD_REQUEST, "missing sign-in session");
    };
    // Consume the pending browser flow: a completed broker callback ends it.
    let key = pending_auth_cache_key(&realm.id, &flow_id);
    let pending: Option<PendingAuthData> = match state.cache.get_and_delete(&key).await {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
        _ => None,
    };
    let Some(pending) = pending else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "the sign-in session has expired — please start again",
        );
    };
    let alias = idp.alias.to_string();

    // Known link → straight to completion.
    let existing_link = state
        .storage
        .get_identity_provider_link(&realm.id, &alias, &identity.subject)
        .await;
    match existing_link {
        Ok(Some(link)) => {
            let user = match state.storage.get_user(&realm.id, &link.user_id).await {
                Ok(Some(u)) => u,
                _ => {
                    warn!(realm = %realm.id, alias, "identity provider link points at a missing user");
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "account link is broken — please contact an administrator",
                    );
                }
            };
            if !user.enabled {
                return error_response(StatusCode::FORBIDDEN, "this account is disabled");
            }
            // Mappers re-apply per the sync mode; the stored token (if any)
            // is written at link-creation time only.
            let settings = BrokerIdpSettings::new(idp);
            let apply = settings.sync_mode() == issuerd_core::BrokerSyncMode::Force;
            return finalize_brokered_login(state, realm, idp, pending, user, &identity, apply)
                .await;
        }
        Ok(None) => {}
        Err(e) => {
            warn!(error = %e, "link lookup failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed");
        }
    }

    // First broker login: conflict on email?
    let conflicting_user = match identity.email.as_deref() {
        Some(email) => match state.storage.get_user_by_email(&realm.id, email).await {
            Ok(u) => u,
            Err(e) => {
                warn!(error = %e, "email lookup failed");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed");
            }
        },
        None => None,
    };
    let settings = BrokerIdpSettings::new(idp);
    let decision = decide_first_broker_login(
        conflicting_user.is_some(),
        settings.trust_email(),
        identity.email_verified,
    );
    let store_tokens = settings.store_tokens();

    match decision {
        FirstBrokerLoginDecision::AutoLink => {
            let existing = conflicting_user.expect("conflict implies an existing user");
            if !existing.enabled {
                return error_response(StatusCode::FORBIDDEN, "this account is disabled");
            }
            let link = IdentityProviderLink {
                user_id: existing.id.clone(),
                provider_alias: alias.clone(),
                external_subject: identity.subject.clone(),
                external_username: identity.username.clone().or(identity.email.clone()),
                stored_refresh_token: store_tokens.then_some(external_refresh_token).flatten(),
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = state.storage.create_identity_provider_link(&realm.id, &link).await {
                warn!(error = %e, "auto-link failed");
                return error_response(StatusCode::CONFLICT, "account link failed");
            }
            finalize_brokered_login(state, realm, idp, pending, existing, &identity, true).await
        }
        FirstBrokerLoginDecision::AutoCreate => {
            let username = find_available_username(
                state,
                &realm.id,
                &identity.suggested_username(&alias),
                &alias,
                &identity.subject,
            )
            .await;
            let user = match create_brokered_user(
                state, realm, idp, &identity, username, None, None, None,
            )
            .await
            {
                Ok(u) => u,
                Err(e) => {
                    warn!(error = %e, "brokered user creation failed");
                    return error_response(StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed");
                }
            };
            let stored_token = store_tokens.then_some(external_refresh_token).flatten();
            match create_link_for_new_user(state, realm, &alias, &identity, &user, stored_token)
                .await
            {
                Ok(()) => {
                    finalize_brokered_login(state, realm, idp, pending, user, &identity, false)
                        .await
                }
                Err(resp) => resp,
            }
        }
        FirstBrokerLoginDecision::ReviewProfile | FirstBrokerLoginDecision::LinkOrCreate => {
            let execution = issuerd_core::utils::generate_id();
            let entry = BrokerFirstLoginData {
                pending,
                alias: alias.clone(),
                suggested_username: identity.suggested_username(&alias),
                mode: if decision == FirstBrokerLoginDecision::ReviewProfile {
                    "review".to_string()
                } else {
                    "link".to_string()
                },
                existing_user_id: conflicting_user.map(|u| u.id.to_string()),
                identity,
                external_refresh_token: store_tokens.then_some(external_refresh_token).flatten(),
                error: None,
            };
            let bytes = serde_json::to_vec(&entry).unwrap();
            if let Err(e) = state
                .cache
                .set(
                    &first_login_cache_key(&realm.id, &execution),
                    bytes,
                    Some(Duration::from_secs(FIRST_LOGIN_TTL_SECS)),
                )
                .await
            {
                warn!(realm = %realm.id, alias, error = %e, "first-broker-login cache write failed");
            }
            let url = format!(
                "/realms/{}/broker/first-login/{execution}",
                url_path_segment(realm_segment)
            );
            let mut resp = Redirect::to(&url).into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str(&flow_cookie_header(&execution)) {
                resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
            }
            resp
        }
    }
}

/// The user is authenticated; apply mappers when due, run pending required
/// actions through the required-action continuation, or complete the login outright.
async fn finalize_brokered_login(
    state: &Arc<ServerState>,
    realm: &Realm,
    idp: &IdentityProviderConfig,
    pending: PendingAuthData,
    mut user: User,
    identity: &BrokeredIdentity,
    apply_mappers_now: bool,
) -> Response {
    if apply_mappers_now {
        let settings = BrokerIdpSettings::new(idp);
        let effects =
            apply_mappers(&settings.mappers(), idp.alias.as_ref(), &identity.claims, &mut user);
        if let Err(e) = state.storage.update_user(&realm.id, &user).await {
            warn!(error = %e, "mapper attribute sync failed");
        }
        assign_mapped_roles(state, &realm.id, &user.id, &effects.roles).await;
        issuerd_cluster::invalidate::invalidate_user_claims(
            state.cache.as_ref(),
            &realm.id,
            &user.id,
        )
        .await;
    }

    // Required actions assigned to this user (VERIFY_EMAIL, TERMS, ...) are
    // enforced exactly like after a password login.
    let mut ctx = issuerd_core::AuthContext {
        realm_id: realm.id.clone(),
        client_id: None,
        user_id: Some(user.id.clone()),
        session_id: None,
        ip_address: pending.ip_address,
        parameters: HashMap::new(),
        attributes: HashMap::new(),
        current_challenge: None,
    };
    if realm.verify_email_enabled {
        ctx.attributes
            .insert("realm_verify_email_enabled".to_string(), "true".to_string());
    }
    let mut actions = Vec::new();
    for action_id in state.plugin_registry.list_required_action_ids() {
        // A brokered user's sign-in method IS the external IdP, so they
        // legitimately have no local password: the "no password →
        // UPDATE_PASSWORD" auto-rule must not fire on broker logins (Keycloak
        // behaves the same). An explicit admin assignment is still honored.
        if action_id == "UPDATE_PASSWORD"
            && !user.required_actions.iter().any(|a| a == "UPDATE_PASSWORD")
        {
            continue;
        }
        match state.plugin_registry.get_required_action(&action_id).await {
            Ok(Some(action)) if action.evaluate(&ctx).await => actions.push(action_id),
            Ok(_) => {}
            Err(e) => warn!(error = %e, action = %action_id, "required action evaluation failed"),
        }
    }

    let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
    if !actions.is_empty() {
        let result = TypedFlowResult::new_pending(user.id.clone(), session_id, actions);
        return super::required_actions::begin_actions_continuation(
            state,
            realm.name.as_ref(),
            pending,
            result,
            true,
        )
        .await;
    }
    complete_login_with_method(
        state,
        &realm.id,
        &pending,
        &user.id,
        &session_id,
        chrono::Utc::now(),
        true,
        AuthMethod::IdentityProvider,
        "identity_provider",
    )
    .await
}

/// Assign realm roles named by mapper effects; unknown roles are skipped
/// (mappers reference roles by name and must not conjure them into being).
async fn assign_mapped_roles(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    user_id: &UserId,
    role_names: &[String],
) {
    for name in role_names {
        match state.storage.get_role_by_name(realm_id, name).await {
            Ok(Some(role)) => {
                if let Err(e) = state.storage.add_user_realm_role(realm_id, user_id, &role.id).await
                {
                    warn!(error = %e, role = %name, "mapped role assignment failed");
                }
            }
            Ok(None) => warn!(role = %name, "IdP mapper references an unknown role"),
            Err(e) => warn!(error = %e, role = %name, "role lookup failed"),
        }
    }
}

/// Pick a unique username: the suggestion, then `{alias}.{subject}` (Keycloak's
/// collision shape), then a random suffix as the last resort.
async fn find_available_username(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    suggested: &str,
    alias: &str,
    subject: &str,
) -> String {
    if Username::new(suggested).is_ok() && !username_taken(state, realm_id, suggested).await {
        return suggested.to_string();
    }
    let fallback = format!("{alias}.{subject}");
    if Username::new(&fallback).is_ok() && !username_taken(state, realm_id, &fallback).await {
        return fallback;
    }
    format!("{alias}.{}", issuerd_core::utils::generate_id())
}

async fn username_taken(state: &Arc<ServerState>, realm_id: &RealmId, name: &str) -> bool {
    matches!(state.storage.get_user_by_username(realm_id, name).await, Ok(Some(_)))
}

/// Create the local user for a brokered identity. `form_*` overrides come
/// from the review-profile page; absent values fall back to mapped claims.
#[allow(clippy::too_many_arguments)]
async fn create_brokered_user(
    state: &Arc<ServerState>,
    realm: &Realm,
    idp: &IdentityProviderConfig,
    identity: &BrokeredIdentity,
    username: String,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
) -> Result<User, IssuerdError> {
    let alias = idp.alias.to_string();
    let email = email.or_else(|| identity.email.clone());
    let first_name = first_name.or_else(|| identity.first_name.clone());
    let last_name = last_name.or_else(|| identity.last_name.clone());

    // The email is verified only when the IdP said so AND it survived the
    // review form unedited.
    let email_verified = identity.email_verified && email == identity.email;
    let username = Username::new(username.clone())
        .map_err(|e| IssuerdError::InvalidRequest(format!("invalid username: {e}")))?;
    let email_typed = match email {
        Some(e) => {
            Some(Email::new(e).map_err(|err| IssuerdError::InvalidRequest(err.to_string()))?)
        }
        None => None,
    };

    let mut required_actions = Vec::new();
    if realm.verify_email_enabled && !email_verified && email_typed.is_some() {
        required_actions.push("VERIFY_EMAIL".to_string());
    }

    let now = chrono::Utc::now();
    let mut user = User {
        id: UserId::new(issuerd_core::utils::generate_id())?,
        realm_id: realm.id.clone(),
        username,
        email: email_typed,
        email_verified,
        first_name: first_name.and_then(|n| DisplayName::new(n).ok()),
        last_name: last_name.and_then(|n| DisplayName::new(n).ok()),
        enabled: true,
        federation_link: Some(format!("idp:{alias}")),
        attributes: HashMap::new(),
        required_actions,
        created_at: now,
        updated_at: now,
    };

    // Import-mode mapper application at creation time.
    let settings = BrokerIdpSettings::new(idp);
    let effects = apply_mappers(&settings.mappers(), &alias, &identity.claims, &mut user);
    state.storage.create_user(&realm.id, &user).await?;

    // Realm default role + mapped roles.
    if let Some(ref default_role) = realm.default_role {
        if let Ok(Some(role)) = state.storage.get_role_by_name(&realm.id, default_role).await {
            if let Err(e) = state.storage.add_user_realm_role(&realm.id, &user.id, &role.id).await {
                warn!(realm = %realm.id, error = %e, "default role assignment failed");
            }
        }
    }
    assign_mapped_roles(state, &realm.id, &user.id, &effects.roles).await;
    // Realm default groups apply to interactive user creation
    // (registration, broker first login) — not to admin-created users.
    crate::groups::assign_default_groups(state, realm, &user.id).await;
    Ok(user)
}

/// Create the link row for a freshly created user; failures roll back the
/// user so a retry does not hit username-uniqueness ghosts. The
/// `external_refresh_token` argument must already have the `storeTokens`
/// config applied by the caller (None = not stored).
async fn create_link_for_new_user(
    state: &Arc<ServerState>,
    realm: &Realm,
    alias: &str,
    identity: &BrokeredIdentity,
    user: &User,
    external_refresh_token: Option<String>,
) -> Result<(), Response> {
    let link = IdentityProviderLink {
        user_id: user.id.clone(),
        provider_alias: alias.to_string(),
        external_subject: identity.subject.clone(),
        external_username: identity.username.clone().or(identity.email.clone()),
        stored_refresh_token: external_refresh_token,
        created_at: chrono::Utc::now(),
    };
    match state.storage.create_identity_provider_link(&realm.id, &link).await {
        Ok(()) => Ok(()),
        Err(e) => {
            warn!(error = %e, "link creation for new user failed; rolling back user");
            let _ = state.storage.delete_user(&realm.id, &user.id).await;
            Err(error_response(StatusCode::CONFLICT, "this external account is already linked"))
        }
    }
}

// ---------------------------------------------------------------------------
// First-broker-login pages
// ---------------------------------------------------------------------------

fn first_login_url(realm_segment: &str, execution: &str) -> String {
    format!("/realms/{}/broker/first-login/{execution}", url_path_segment(realm_segment))
}

async fn load_first_login_entry(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    execution: &str,
) -> Option<BrokerFirstLoginData> {
    match state.cache.get(&first_login_cache_key(realm_id, execution)).await {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
        _ => None,
    }
}

async fn store_first_login_entry(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    execution: &str,
    entry: &BrokerFirstLoginData,
) {
    let bytes = serde_json::to_vec(entry).unwrap();
    if let Err(e) = state
        .cache
        .set(
            &first_login_cache_key(realm_id, execution),
            bytes,
            Some(Duration::from_secs(FIRST_LOGIN_TTL_SECS)),
        )
        .await
    {
        warn!(realm = %realm_id, error = %e, "first-broker-login cache write failed");
    }
}

/// GET /realms/{realm}/broker/first-login/{execution}
pub async fn first_broker_login_page(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm_segment)): axum::extract::Extension<ResolvedRealm>,
    Path((_realm, execution)): Path<(String, String)>,
) -> Response {
    let Some(realm_segment) = realm_segment else {
        return error_response(StatusCode::BAD_REQUEST, "missing realm");
    };
    let realm = match state.resolve_realm(&realm_segment).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::BAD_REQUEST, "unknown realm"),
    };
    let Some(entry) = load_first_login_entry(&state, &realm.id, &execution).await else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "the sign-in session has expired — please start again",
        );
    };
    let banner = error_banner(entry.error.as_deref());
    let action = first_login_url(&realm_segment, &execution);
    let id = &entry.identity;

    if entry.mode == "link" {
        let email = crate::email::html_escape(id.email.as_deref().unwrap_or_default());
        let body = format!(
            "<h1>Link your account</h1>\
             <p>An account with the email address <b>{email}</b> already exists. \
             To link your <b>{}</b> identity to it, confirm the account password.</p>\
             {banner}\
             <form method=\"post\" action=\"{action}\">\
             <label for=\"password\">Password</label>\
             <input type=\"password\" id=\"password\" name=\"password\" required autofocus>\
             <button type=\"submit\" name=\"action\" value=\"link\">Link account</button>\
             </form>\
             <form method=\"post\" action=\"{action}\">\
             <button type=\"submit\" name=\"action\" value=\"create\" class=\"secondary\">\
             Create a separate account instead</button>\
             </form>",
            crate::email::html_escape(&entry.alias),
        );
        return page("Link your account", &body).into_response();
    }

    // Review mode: prefilled, editable profile.
    let username = crate::email::html_escape(&entry.suggested_username);
    let email = crate::email::html_escape(id.email.as_deref().unwrap_or_default());
    let first = crate::email::html_escape(id.first_name.as_deref().unwrap_or_default());
    let last = crate::email::html_escape(id.last_name.as_deref().unwrap_or_default());
    let body = format!(
        "<h1>Review your profile</h1>\
         <p>You are signing in via <b>{}</b>. Review and complete your profile to finish.</p>\
         {banner}\
         <form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"action\" value=\"review\">\
         <label for=\"username\">Username</label>\
         <input type=\"text\" id=\"username\" name=\"username\" value=\"{username}\" required>\
         <label for=\"email\">Email</label>\
         <input type=\"email\" id=\"email\" name=\"email\" value=\"{email}\">\
         <label for=\"first_name\">First name</label>\
         <input type=\"text\" id=\"first_name\" name=\"first_name\" value=\"{first}\">\
         <label for=\"last_name\">Last name</label>\
         <input type=\"text\" id=\"last_name\" name=\"last_name\" value=\"{last}\">\
         <button type=\"submit\">Continue</button>\
         </form>",
        crate::email::html_escape(&entry.alias),
    );
    page("Review your profile", &body).into_response()
}

/// POST /realms/{realm}/broker/first-login/{execution}
pub async fn first_broker_login_submit(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm_segment)): axum::extract::Extension<ResolvedRealm>,
    Path((_realm, execution)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Some(realm_segment) = realm_segment else {
        return error_response(StatusCode::BAD_REQUEST, "missing realm");
    };
    let realm = match state.resolve_realm(&realm_segment).await {
        Ok(Some(r)) => r,
        _ => return error_response(StatusCode::BAD_REQUEST, "unknown realm"),
    };
    if !has_flow_cookie(&headers, &execution) {
        return error_response(StatusCode::BAD_REQUEST, "invalid sign-in session");
    }
    // Consume atomically; any retryable failure re-stores the entry.
    let entry: Option<BrokerFirstLoginData> =
        match state.cache.get_and_delete(&first_login_cache_key(&realm.id, &execution)).await {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            _ => None,
        };
    let Some(mut entry) = entry else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "the sign-in session has expired — please start again",
        );
    };

    let idp = match state.storage.get_identity_provider_by_alias(&realm.id, &entry.alias).await {
        Ok(Some(idp)) if idp.enabled => idp,
        _ => return error_response(StatusCode::BAD_REQUEST, "unknown identity provider"),
    };

    /// Retry: re-store the entry with an error banner and PRG back to GET.
    macro_rules! retry {
        ($entry:expr, $msg:expr) => {{
            let mut e = $entry;
            e.error = Some($msg.to_string());
            store_first_login_entry(&state, &realm.id, &execution, &e).await;
            return Redirect::to(&first_login_url(&realm_segment, &execution)).into_response();
        }};
    }

    match form.get("action").map(String::as_str) {
        // Link mode: prove ownership of the existing account with its password.
        Some("link") => {
            let Some(existing_id) = entry.existing_user_id.clone() else {
                return error_response(StatusCode::BAD_REQUEST, "invalid link state");
            };
            let password = form.get("password").cloned().unwrap_or_default();
            let existing_id_typed = match UserId::new(existing_id) {
                Ok(id) => id,
                Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid link state"),
            };
            let user = match state.storage.get_user(&realm.id, &existing_id_typed).await {
                Ok(Some(u)) if u.enabled => u,
                Ok(Some(_)) => {
                    return error_response(StatusCode::FORBIDDEN, "this account is disabled")
                }
                _ => return error_response(StatusCode::BAD_REQUEST, "account not found"),
            };
            let credentials = state
                .storage
                .get_credentials(&realm.id, &user.id, CredentialType::Password)
                .await
                .unwrap_or_default();
            let verified = credentials.iter().any(|cred| verify_password_hash(&password, cred));
            if !verified {
                retry!(entry, "invalid password");
            }
            let link = IdentityProviderLink {
                user_id: user.id.clone(),
                provider_alias: entry.alias.clone(),
                external_subject: entry.identity.subject.clone(),
                external_username: entry.identity.username.clone().or(entry.identity.email.clone()),
                stored_refresh_token: entry.external_refresh_token.clone(),
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = state.storage.create_identity_provider_link(&realm.id, &link).await {
                warn!(error = %e, "link-via-password failed");
                return error_response(
                    StatusCode::CONFLICT,
                    "this external account is already linked",
                );
            }
            finalize_brokered_login(
                &state,
                &realm,
                &idp,
                entry.pending,
                user,
                &entry.identity,
                true,
            )
            .await
        }
        // Link mode, alternate button: switch to review mode (create distinct).
        Some("create") => {
            entry.mode = "review".to_string();
            entry.error = None;
            store_first_login_entry(&state, &realm.id, &execution, &entry).await;
            Redirect::to(&first_login_url(&realm_segment, &execution)).into_response()
        }
        // Review mode: validate the edited profile and create the account.
        _ => {
            let username = form.get("username").cloned().unwrap_or_default();
            let username = username.trim().to_string();
            if Username::new(&username).is_err() {
                retry!(entry, "a valid username is required");
            }
            if matches!(state.storage.get_user_by_username(&realm.id, &username).await, Ok(Some(_)))
            {
                retry!(entry, "that username is already taken");
            }
            let email = form.get("email").map(|e| e.trim().to_string()).filter(|e| !e.is_empty());
            if let Some(ref email) = email {
                if Email::new(email).is_err() {
                    retry!(entry, "a valid email address is required");
                }
                if !realm.duplicate_emails_allowed
                    && matches!(
                        state.storage.get_user_by_email(&realm.id, email).await,
                        Ok(Some(_))
                    )
                {
                    retry!(entry, "that email address is already in use");
                }
            }
            let user = match create_brokered_user(
                &state,
                &realm,
                &idp,
                &entry.identity,
                username,
                email,
                form.get("first_name").cloned().filter(|s| !s.is_empty()),
                form.get("last_name").cloned().filter(|s| !s.is_empty()),
            )
            .await
            {
                Ok(u) => u,
                Err(e) => {
                    warn!(error = %e, "brokered user creation failed");
                    return error_response(StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed");
                }
            };
            // The entry's token already encodes the storeTokens decision.
            match create_link_for_new_user(
                &state,
                &realm,
                &entry.alias,
                &entry.identity,
                &user,
                entry.external_refresh_token.clone(),
            )
            .await
            {
                Ok(()) => {
                    finalize_brokered_login(
                        &state,
                        &realm,
                        &idp,
                        entry.pending,
                        user,
                        &entry.identity,
                        false,
                    )
                    .await
                }
                Err(resp) => resp,
            }
        }
    }
}
