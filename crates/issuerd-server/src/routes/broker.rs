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
#[allow(clippy::result_large_err)]
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
            if let Ok(v) = axum::http::HeaderValue::from_str(&flow_cookie_header(
                &execution,
                state.config.secure_cookies(),
            )) {
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
#[allow(clippy::result_large_err)]
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use issuerd_core::{
        Alias, DistributedCache, FlowStageId, IdentityProviderId, ProviderId, RealmName, Storage,
    };

    const MASTER: &str = "master";
    const IDP_ALIAS: &str = "ext";

    type TestStorage = Arc<issuerd_storage::InMemoryStorage>;
    type TestCache = Arc<issuerd_cluster::InMemoryCache>;

    /// Bootstrapped in-memory state (master realm + admin user + admin-cli client).
    async fn test_state() -> (Arc<ServerState>, TestStorage, TestCache) {
        let cfg = ServerConfig::default();
        let storage: TestStorage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let cache: TestCache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let state = ServerState::from_components(&cfg, storage.clone(), cache.clone())
            .await
            .unwrap();
        (Arc::new(state), storage, cache)
    }

    /// [`test_state`] with the external IdP HTTP client stubbed out.
    async fn test_state_with_broker_client(
        client: issuerd_core::MockBrokerClient,
    ) -> (Arc<ServerState>, TestStorage, TestCache) {
        let cfg = ServerConfig::default();
        let storage: TestStorage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let cache: TestCache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let mut state = ServerState::from_components(&cfg, storage.clone(), cache.clone())
            .await
            .unwrap();
        state.broker_client = Arc::new(client);
        (Arc::new(state), storage, cache)
    }

    fn master_realm_id() -> RealmId {
        RealmId::new(MASTER).unwrap()
    }

    /// A valid, enabled generic-OIDC broker config with explicit endpoints
    /// (no discovery → endpoint resolution makes no HTTP calls).
    fn broker_idp_config(alias: &str) -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap(),
            alias: Alias::new(alias).unwrap(),
            provider_id: ProviderId::Oidc,
            enabled: true,
            config: HashMap::from([
                ("clientId".to_string(), "broker-client".to_string()),
                ("clientSecret".to_string(), "broker-secret".to_string()),
                ("authorizationUrl".to_string(), "https://idp.example.com/authorize".to_string()),
                ("tokenUrl".to_string(), "https://idp.example.com/token".to_string()),
                ("userInfoUrl".to_string(), "https://idp.example.com/userinfo".to_string()),
            ]),
        }
    }

    async fn seed_broker_idp(storage: &TestStorage, realm_id: &RealmId) {
        storage
            .create_identity_provider(realm_id, &broker_idp_config(IDP_ALIAS))
            .await
            .unwrap();
    }

    fn broker_identity() -> BrokeredIdentity {
        BrokeredIdentity {
            subject: "ext-sub-1".to_string(),
            username: Some("extuser".to_string()),
            email: Some("ext@example.com".to_string()),
            email_verified: true,
            first_name: None,
            last_name: None,
            display_name: None,
            claims: serde_json::json!({"sub": "ext-sub-1"}),
        }
    }

    fn broker_user(realm_id: &RealmId, username: &str, enabled: bool) -> User {
        let now = chrono::Utc::now();
        User {
            id: UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new(username).unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    fn pending_auth_data(realm_id: &RealmId, flow_id: &str) -> PendingAuthData {
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
            execution_id: FlowStageId::new(flow_id).unwrap(),
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

    fn first_login_entry(
        realm_id: &RealmId,
        mode: &str,
        existing_user_id: Option<String>,
    ) -> BrokerFirstLoginData {
        BrokerFirstLoginData {
            pending: pending_auth_data(realm_id, "fbl-flow"),
            alias: IDP_ALIAS.to_string(),
            identity: broker_identity(),
            suggested_username: "extuser".to_string(),
            mode: mode.to_string(),
            existing_user_id,
            external_refresh_token: None,
            error: None,
        }
    }

    async fn seed_first_login_entry(
        cache: &TestCache,
        realm_id: &RealmId,
        execution: &str,
        entry: &BrokerFirstLoginData,
    ) {
        cache
            .set(
                &first_login_cache_key(realm_id, execution),
                serde_json::to_vec(entry).unwrap(),
                None,
            )
            .await
            .unwrap();
    }

    async fn seed_broker_state(
        cache: &TestCache,
        realm_id: &RealmId,
        state_key: &str,
        entry: &BrokerState,
    ) {
        cache
            .set(
                &broker_state_cache_key(realm_id, state_key),
                serde_json::to_vec(entry).unwrap(),
                None,
            )
            .await
            .unwrap();
    }

    fn login_broker_state(flow_id: Option<&str>) -> BrokerState {
        BrokerState {
            nonce: "nonce-1".to_string(),
            pkce_verifier: None,
            flow_id: flow_id.map(str::to_string),
            linking_user: None,
        }
    }

    /// Token endpoint answers an access token only → userinfo fallback yields
    /// the external identity.
    fn successful_userinfo_client() -> issuerd_core::MockBrokerClient {
        let mut client = issuerd_core::MockBrokerClient::new();
        client.expect_post_form().returning(|_, _, _| {
            Ok(serde_json::json!({
                "access_token": "ext-at",
                "token_type": "Bearer",
                "refresh_token": "ext-rt",
            }))
        });
        client.expect_get_json_bearer().returning(|_, _| {
            Ok(serde_json::json!({
                "sub": "ext-sub-1",
                "preferred_username": "extuser",
                "email": "ext@example.com",
                "email_verified": true,
            }))
        });
        client
    }

    fn flow_cookie_headers(flow_id: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::COOKIE, format!("issuerd_flow_{flow_id}=1").parse().unwrap());
        h
    }

    fn resolved(segment: &str) -> axum::extract::Extension<ResolvedRealm> {
        axum::extract::Extension(ResolvedRealm(Some(segment.to_string())))
    }

    fn location(resp: &Response) -> String {
        resp.headers().get("location").unwrap().to_str().unwrap().to_string()
    }

    async fn body_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    async fn submit_first_login(
        state: &Arc<ServerState>,
        execution: &str,
        form: HashMap<String, String>,
        with_cookie: bool,
    ) -> Response {
        let headers = if with_cookie {
            flow_cookie_headers(execution)
        } else {
            HeaderMap::new()
        };
        first_broker_login_submit(
            State(state.clone()),
            resolved(MASTER),
            Path((MASTER.to_string(), execution.to_string())),
            headers,
            Form(form),
        )
        .await
    }

    // -- cache key schema ----------------------------------------------------

    #[test]
    fn broker_cache_keys_have_exact_schema_and_are_distinct() {
        let realm_a = RealmId::new("realm-a").unwrap();
        let realm_b = RealmId::new("realm-b").unwrap();

        assert_eq!(broker_state_cache_key(&realm_a, "state-1"), "broker_state:realm-a:state-1");
        assert_eq!(first_login_cache_key(&realm_a, "exec-1"), "broker_fbl:realm-a:exec-1");

        // Distinct per realm, per round-trip identifier, and across the two schemas.
        assert_ne!(
            broker_state_cache_key(&realm_a, "state-1"),
            broker_state_cache_key(&realm_b, "state-1")
        );
        assert_ne!(
            broker_state_cache_key(&realm_a, "state-1"),
            broker_state_cache_key(&realm_a, "state-2")
        );
        assert_ne!(
            first_login_cache_key(&realm_a, "exec-1"),
            first_login_cache_key(&realm_b, "exec-1")
        );
        assert_ne!(
            first_login_cache_key(&realm_a, "exec-1"),
            first_login_cache_key(&realm_a, "exec-2")
        );
        assert_ne!(
            broker_state_cache_key(&realm_a, "same"),
            first_login_cache_key(&realm_a, "same")
        );
    }

    // -- load_broker_target guards --------------------------------------------

    #[tokio::test]
    async fn load_broker_target_returns_realm_and_idp() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let (realm, idp) = load_broker_target(&state, &Some(MASTER.to_string()), IDP_ALIAS)
            .await
            .expect("enabled realm + enabled broker IdP must load");
        assert_eq!(realm.name.as_str(), MASTER);
        assert_eq!(idp.alias.as_str(), IDP_ALIAS);
    }

    #[tokio::test]
    async fn load_broker_target_missing_realm_segment_rejected() {
        let (state, _storage, _cache) = test_state().await;
        let err = load_broker_target(&state, &None, IDP_ALIAS)
            .await
            .expect_err("missing realm segment must fail");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(err).await.contains("missing realm"));
    }

    #[tokio::test]
    async fn load_broker_target_unknown_realm_rejected() {
        let (state, _storage, _cache) = test_state().await;
        let err = load_broker_target(&state, &Some("no-such-realm".to_string()), IDP_ALIAS)
            .await
            .expect_err("unknown realm must fail");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(err).await.contains("unknown realm"));
    }

    #[tokio::test]
    async fn load_broker_target_disabled_realm_rejected() {
        let (state, storage, _cache) = test_state().await;
        let locked = Realm {
            id: RealmId::new("locked").unwrap(),
            name: RealmName::new("locked").unwrap(),
            display_name: None,
            enabled: false,
            ..Default::default()
        };
        storage.create_realm(&locked).await.unwrap();

        let err = load_broker_target(&state, &Some("locked".to_string()), IDP_ALIAS)
            .await
            .expect_err("disabled realm must fail");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(err).await.contains("unknown realm"));
    }

    #[tokio::test]
    async fn load_broker_target_unknown_alias_rejected() {
        let (state, _storage, _cache) = test_state().await;
        let err = load_broker_target(&state, &Some(MASTER.to_string()), "no-such-idp")
            .await
            .expect_err("unknown alias must fail");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert!(body_text(err).await.contains("unknown identity provider"));
    }

    #[tokio::test]
    async fn load_broker_target_disabled_idp_rejected() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let mut idp = broker_idp_config(IDP_ALIAS);
        idp.enabled = false;
        storage.create_identity_provider(&realm_id, &idp).await.unwrap();

        let err = load_broker_target(&state, &Some(MASTER.to_string()), IDP_ALIAS)
            .await
            .expect_err("disabled IdP must fail");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(err).await.contains("not available for sign-in"));
    }

    #[tokio::test]
    async fn load_broker_target_non_broker_provider_rejected() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let mut idp = broker_idp_config(IDP_ALIAS);
        idp.provider_id = ProviderId::Ldap;
        storage.create_identity_provider(&realm_id, &idp).await.unwrap();

        let err = load_broker_target(&state, &Some(MASTER.to_string()), IDP_ALIAS)
            .await
            .expect_err("user-federation provider must fail as a broker target");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(err).await.contains("not available for sign-in"));
    }

    #[tokio::test]
    async fn load_broker_target_misconfigured_idp_rejected() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let mut idp = broker_idp_config(IDP_ALIAS);
        idp.config.remove("clientSecret");
        storage.create_identity_provider(&realm_id, &idp).await.unwrap();

        let err = load_broker_target(&state, &Some(MASTER.to_string()), IDP_ALIAS)
            .await
            .expect_err("invalid IdP config must fail");
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body_text(err).await.contains("not configured correctly"));
    }

    // -- broker_login_handler -------------------------------------------------

    #[tokio::test]
    async fn broker_login_redirects_to_idp_and_stores_state() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let flow = "flow-123";
        let pending = pending_auth_data(&realm_id, flow);
        cache
            .set(
                &pending_auth_cache_key(&realm_id, flow),
                serde_json::to_vec(&pending).unwrap(),
                None,
            )
            .await
            .unwrap();

        let resp = broker_login_handler(
            State(state.clone()),
            resolved(MASTER),
            Path((MASTER.to_string(), IDP_ALIAS.to_string())),
            Query(HashMap::from([("flow".to_string(), flow.to_string())])),
            flow_cookie_headers(flow),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = location(&resp);
        assert!(location.starts_with("https://idp.example.com/authorize?"), "{location}");
        assert!(location.contains("response_type=code"), "{location}");
        assert!(location.contains("client_id=broker-client"), "{location}");
        assert!(location.contains("nonce="), "{location}");
        assert!(location.contains("code_challenge="), "{location}");
        assert!(location.contains("code_challenge_method=S256"), "{location}");

        let url = url::Url::parse(&location).unwrap();
        let param =
            |name: &str| url.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned());
        // The redirect URI is this realm's broker callback.
        assert_eq!(
            param("redirect_uri").as_deref(),
            Some("http://localhost:8080/realms/master/broker/ext/endpoint")
        );
        // The broker state round-trip entry is stored under the exact schema key.
        let state_key = param("state").expect("state param present");
        let stored = cache
            .get(&broker_state_cache_key(&realm_id, &state_key))
            .await
            .unwrap()
            .expect("broker state cached under broker_state:{realm}:{state}");
        let stored: BrokerState = serde_json::from_slice(&stored).unwrap();
        assert_eq!(stored.flow_id.as_deref(), Some(flow));
        assert!(stored.linking_user.is_none());
        assert!(stored.pkce_verifier.is_some(), "PKCE defaults to enabled");
    }

    #[tokio::test]
    async fn broker_login_missing_pending_entry_rejected() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        // The flow correlation cookie is present but the pending entry is gone.
        let resp = broker_login_handler(
            State(state.clone()),
            resolved(MASTER),
            Path((MASTER.to_string(), IDP_ALIAS.to_string())),
            Query(HashMap::from([("flow".to_string(), "gone-flow".to_string())])),
            flow_cookie_headers("gone-flow"),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("has expired"));
    }

    #[tokio::test]
    async fn broker_login_missing_flow_cookie_rejected() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let flow = "flow-no-cookie";
        let pending = pending_auth_data(&realm_id, flow);
        cache
            .set(
                &pending_auth_cache_key(&realm_id, flow),
                serde_json::to_vec(&pending).unwrap(),
                None,
            )
            .await
            .unwrap();

        let resp = broker_login_handler(
            State(state.clone()),
            resolved(MASTER),
            Path((MASTER.to_string(), IDP_ALIAS.to_string())),
            Query(HashMap::from([("flow".to_string(), flow.to_string())])),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("has expired"));
    }

    #[tokio::test]
    async fn broker_login_without_flow_or_link_rejected() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let resp = broker_login_handler(
            State(state.clone()),
            resolved(MASTER),
            Path((MASTER.to_string(), IDP_ALIAS.to_string())),
            Query(HashMap::new()),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("missing sign-in session"));
    }

    // -- endpoint_inner -------------------------------------------------------

    #[tokio::test]
    async fn endpoint_unknown_state_rejected() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let resp = endpoint_inner(
            state,
            Some(MASTER.to_string()),
            IDP_ALIAS.to_string(),
            HashMap::from([("state".to_string(), "no-such-state".to_string())]),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("is invalid or has expired"));
    }

    #[tokio::test]
    async fn endpoint_idp_error_redirects_back_to_login() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        seed_broker_state(&cache, &realm_id, "st-1", &login_broker_state(Some("flow-9"))).await;

        let resp = endpoint_inner(
            state,
            Some(MASTER.to_string()),
            IDP_ALIAS.to_string(),
            HashMap::from([
                ("state".to_string(), "st-1".to_string()),
                ("error".to_string(), "access_denied".to_string()),
            ]),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            location(&resp),
            "/login.html?execution_id=flow-9&realm=master&error=identity_provider_error"
        );
        // The state entry is single-use: consumed even on an IdP-side error.
        assert!(cache.get(&broker_state_cache_key(&realm_id, "st-1")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn endpoint_missing_code_rejected() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        seed_broker_state(&cache, &realm_id, "st-2", &login_broker_state(Some("flow-9"))).await;

        let resp = endpoint_inner(
            state,
            Some(MASTER.to_string()),
            IDP_ALIAS.to_string(),
            HashMap::from([("state".to_string(), "st-2".to_string())]),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("no authorization code"));
    }

    #[tokio::test]
    async fn endpoint_empty_code_rejected() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        seed_broker_state(&cache, &realm_id, "st-3", &login_broker_state(Some("flow-9"))).await;

        let resp = endpoint_inner(
            state,
            Some(MASTER.to_string()),
            IDP_ALIAS.to_string(),
            HashMap::from([
                ("state".to_string(), "st-3".to_string()),
                ("code".to_string(), String::new()),
            ]),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("no authorization code"));
    }

    #[tokio::test]
    async fn endpoint_exchange_failure_redirects_to_login() {
        let mut client = issuerd_core::MockBrokerClient::new();
        client
            .expect_post_form()
            .returning(|_, _, _| Err(IssuerdError::ServerError("idp down".to_string())));
        let (state, storage, cache) = test_state_with_broker_client(client).await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        seed_broker_state(&cache, &realm_id, "st-4", &login_broker_state(Some("flow-11"))).await;

        let resp = endpoint_inner(
            state,
            Some(MASTER.to_string()),
            IDP_ALIAS.to_string(),
            HashMap::from([
                ("state".to_string(), "st-4".to_string()),
                ("code".to_string(), "real-code".to_string()),
            ]),
            HeaderMap::new(),
        )
        .await;

        // A non-empty code proceeds to the exchange; its failure bounces the
        // browser back to the login page (not a 400 "no code" error).
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            location(&resp),
            "/login.html?execution_id=flow-11&realm=master&error=identity_provider_error"
        );
    }

    #[tokio::test]
    async fn endpoint_missing_flow_session_rejected() {
        let (state, storage, cache) =
            test_state_with_broker_client(successful_userinfo_client()).await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        // A link-mode-less state without a flow id cannot complete a login.
        seed_broker_state(&cache, &realm_id, "st-5", &login_broker_state(None)).await;

        let resp = endpoint_inner(
            state,
            Some(MASTER.to_string()),
            IDP_ALIAS.to_string(),
            HashMap::from([
                ("state".to_string(), "st-5".to_string()),
                ("code".to_string(), "real-code".to_string()),
            ]),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("missing sign-in session"));
    }

    #[tokio::test]
    async fn endpoint_new_identity_redirects_to_first_login() {
        let (state, storage, cache) =
            test_state_with_broker_client(successful_userinfo_client()).await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let flow = "flow-77";
        let pending = pending_auth_data(&realm_id, flow);
        cache
            .set(
                &pending_auth_cache_key(&realm_id, flow),
                serde_json::to_vec(&pending).unwrap(),
                None,
            )
            .await
            .unwrap();
        seed_broker_state(&cache, &realm_id, "st-6", &login_broker_state(Some(flow))).await;

        let resp = endpoint_inner(
            state,
            Some(MASTER.to_string()),
            IDP_ALIAS.to_string(),
            HashMap::from([
                ("state".to_string(), "st-6".to_string()),
                ("code".to_string(), "real-code".to_string()),
            ]),
            HeaderMap::new(),
        )
        .await;

        // Unknown identity + untrusted email → review-profile continuation.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = location(&resp);
        assert!(location.starts_with("/realms/master/broker/first-login/"), "{location}");
        let execution = location.rsplit('/').next().unwrap().to_string();

        let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap().to_string();
        assert!(
            set_cookie.contains(&format!("issuerd_flow_{execution}=1")),
            "set-cookie: {set_cookie}"
        );

        // The continuation entry is cached under the exact schema key…
        let stored = cache
            .get(&first_login_cache_key(&realm_id, &execution))
            .await
            .unwrap()
            .expect("first-login entry cached under broker_fbl:{realm}:{execution}");
        let entry: BrokerFirstLoginData = serde_json::from_slice(&stored).unwrap();
        assert_eq!(entry.mode, "review");
        assert_eq!(entry.alias, IDP_ALIAS);
        assert_eq!(entry.suggested_username, "extuser");

        // …and both round-trip entries were consumed.
        assert!(cache.get(&broker_state_cache_key(&realm_id, "st-6")).await.unwrap().is_none());
        assert!(cache.get(&pending_auth_cache_key(&realm_id, flow)).await.unwrap().is_none());
    }

    // -- finalize_brokered_login ----------------------------------------------

    #[tokio::test]
    async fn finalize_without_pending_actions_completes_login() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.resolve_realm(MASTER).await.unwrap().unwrap();
        let user = broker_user(&realm_id, "brokered-user", true);
        storage.create_user(&realm_id, &user).await.unwrap();
        let idp = broker_idp_config(IDP_ALIAS);
        let identity = broker_identity();

        let resp = finalize_brokered_login(
            &state,
            &realm,
            &idp,
            pending_auth_data(&realm_id, "flow-fin-1"),
            user,
            &identity,
            false,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = location(&resp);
        assert!(location.starts_with("http://localhost:8080/cb?"), "{location}");
        assert!(location.contains("code="), "{location}");
    }

    #[tokio::test]
    async fn finalize_with_pending_actions_starts_continuation() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.resolve_realm(MASTER).await.unwrap().unwrap();
        let mut user = broker_user(&realm_id, "brokered-user", true);
        user.required_actions = vec!["UPDATE_PASSWORD".to_string()];
        storage.create_user(&realm_id, &user).await.unwrap();
        let idp = broker_idp_config(IDP_ALIAS);
        let identity = broker_identity();

        let resp = finalize_brokered_login(
            &state,
            &realm,
            &idp,
            pending_auth_data(&realm_id, "flow-fin-2"),
            user,
            &identity,
            false,
        )
        .await;

        // An explicitly assigned required action pauses the login instead of
        // issuing the authorization code.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = location(&resp);
        assert!(location.starts_with("/realms/master/login/required-action/"), "{location}");
    }

    // -- find_available_username ----------------------------------------------

    #[tokio::test]
    async fn find_available_username_returns_suggestion_when_free() {
        let (state, _storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let picked =
            find_available_username(&state, &realm_id, "free-name", IDP_ALIAS, "sub-1").await;
        assert_eq!(picked, "free-name");
    }

    #[tokio::test]
    async fn find_available_username_falls_back_to_alias_subject_on_conflict() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        storage
            .create_user(&realm_id, &broker_user(&realm_id, "taken-name", true))
            .await
            .unwrap();

        let picked =
            find_available_username(&state, &realm_id, "taken-name", IDP_ALIAS, "sub-9").await;
        assert_eq!(picked, "ext.sub-9");
    }

    #[tokio::test]
    async fn find_available_username_random_suffix_when_suggestion_and_fallback_taken() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        storage
            .create_user(&realm_id, &broker_user(&realm_id, "taken-name", true))
            .await
            .unwrap();
        storage
            .create_user(&realm_id, &broker_user(&realm_id, "ext.sub-9", true))
            .await
            .unwrap();

        let picked =
            find_available_username(&state, &realm_id, "taken-name", IDP_ALIAS, "sub-9").await;
        assert!(picked.starts_with("ext."), "{picked}");
        assert_ne!(picked, "ext.sub-9");
        assert!(Username::new(&picked).is_ok(), "{picked}");
    }

    // -- first_broker_login_submit --------------------------------------------

    #[tokio::test]
    async fn submit_without_flow_cookie_rejected() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        let execution = "exec-no-cookie";
        let entry = first_login_entry(&realm_id, "link", None);
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([("action".to_string(), "link".to_string())]),
            false,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("invalid sign-in session"));
        // The entry is NOT consumed when the correlation cookie is missing.
        assert!(load_first_login_entry(&state, &realm_id, execution).await.is_some());
    }

    #[tokio::test]
    async fn submit_unknown_execution_rejected() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let resp = submit_first_login(
            &state,
            "exec-gone",
            HashMap::from([("action".to_string(), "link".to_string())]),
            true,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("has expired"));
    }

    #[tokio::test]
    async fn submit_link_wrong_password_retries_with_banner() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        let user = broker_user(&realm_id, "existing-user", true);
        storage.create_user(&realm_id, &user).await.unwrap();
        issuerd_auth_flow::built_in::set_user_password(
            storage.as_ref(),
            &realm_id,
            &user.id,
            "correct-horse",
            0,
            false,
        )
        .await
        .unwrap();

        let execution = "exec-link-wrong";
        let entry = first_login_entry(&realm_id, "link", Some(user.id.to_string()));
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([
                ("action".to_string(), "link".to_string()),
                ("password".to_string(), "wrong-password".to_string()),
            ]),
            true,
        )
        .await;

        // PRG back to the page with the banner; no link may be created.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), format!("/realms/master/broker/first-login/{execution}"));
        let stored = load_first_login_entry(&state, &realm_id, execution)
            .await
            .expect("entry re-stored for the retry");
        assert_eq!(stored.error.as_deref(), Some("invalid password"));
        assert_eq!(stored.mode, "link");
        assert!(storage
            .get_identity_provider_link(&realm_id, IDP_ALIAS, "ext-sub-1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn submit_link_correct_password_links_and_completes() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        let user = broker_user(&realm_id, "existing-user", true);
        storage.create_user(&realm_id, &user).await.unwrap();
        issuerd_auth_flow::built_in::set_user_password(
            storage.as_ref(),
            &realm_id,
            &user.id,
            "correct-horse",
            0,
            false,
        )
        .await
        .unwrap();

        let execution = "exec-link-ok";
        let entry = first_login_entry(&realm_id, "link", Some(user.id.to_string()));
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([
                ("action".to_string(), "link".to_string()),
                ("password".to_string(), "correct-horse".to_string()),
            ]),
            true,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = location(&resp);
        assert!(location.starts_with("http://localhost:8080/cb?"), "{location}");
        assert!(location.contains("code="), "{location}");

        let link = storage
            .get_identity_provider_link(&realm_id, IDP_ALIAS, "ext-sub-1")
            .await
            .unwrap()
            .expect("identity provider link created");
        assert_eq!(link.user_id, user.id);
        assert_eq!(link.external_username.as_deref(), Some("extuser"));
        // The continuation entry was consumed by the successful submit.
        assert!(load_first_login_entry(&state, &realm_id, execution).await.is_none());
    }

    #[tokio::test]
    async fn submit_link_disabled_user_rejected() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        let user = broker_user(&realm_id, "disabled-user", false);
        storage.create_user(&realm_id, &user).await.unwrap();

        let execution = "exec-link-disabled";
        let entry = first_login_entry(&realm_id, "link", Some(user.id.to_string()));
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([
                ("action".to_string(), "link".to_string()),
                ("password".to_string(), "whatever".to_string()),
            ]),
            true,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_text(resp).await.contains("this account is disabled"));
        assert!(storage
            .get_identity_provider_link(&realm_id, IDP_ALIAS, "ext-sub-1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn submit_link_unknown_account_rejected() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let execution = "exec-link-missing-user";
        let missing = UserId::new(issuerd_core::utils::generate_id()).unwrap();
        let entry = first_login_entry(&realm_id, "link", Some(missing.to_string()));
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([
                ("action".to_string(), "link".to_string()),
                ("password".to_string(), "whatever".to_string()),
            ]),
            true,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("account not found"));
    }

    #[tokio::test]
    async fn submit_create_switches_to_review_mode() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let execution = "exec-switch-to-review";
        let entry = first_login_entry(&realm_id, "link", None);
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([("action".to_string(), "create".to_string())]),
            true,
        )
        .await;

        // PRG back to the same page, now in review mode and without a banner —
        // the "create" button must NOT fall through to the review-submit arm.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), format!("/realms/master/broker/first-login/{execution}"));
        let stored = load_first_login_entry(&state, &realm_id, execution)
            .await
            .expect("entry re-stored in review mode");
        assert_eq!(stored.mode, "review");
        assert!(stored.error.is_none());
    }

    #[tokio::test]
    async fn submit_review_creates_user_and_completes() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let execution = "exec-review-ok";
        let entry = first_login_entry(&realm_id, "review", None);
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([
                ("action".to_string(), "review".to_string()),
                ("username".to_string(), "newbie".to_string()),
                ("email".to_string(), "newbie@example.com".to_string()),
            ]),
            true,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = location(&resp);
        assert!(location.starts_with("http://localhost:8080/cb?"), "{location}");
        assert!(location.contains("code="), "{location}");

        let created = storage
            .get_user_by_username(&realm_id, "newbie")
            .await
            .unwrap()
            .expect("review submit creates the local user");
        assert_eq!(created.federation_link.as_deref(), Some("idp:ext"));
        assert!(storage
            .get_identity_provider_link(&realm_id, IDP_ALIAS, "ext-sub-1")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn submit_review_duplicate_username_retries() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        storage
            .create_user(&realm_id, &broker_user(&realm_id, "taken-name", true))
            .await
            .unwrap();

        let execution = "exec-review-taken";
        let entry = first_login_entry(&realm_id, "review", None);
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([
                ("action".to_string(), "review".to_string()),
                ("username".to_string(), "taken-name".to_string()),
            ]),
            true,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), format!("/realms/master/broker/first-login/{execution}"));
        let stored = load_first_login_entry(&state, &realm_id, execution)
            .await
            .expect("entry re-stored for the retry");
        assert_eq!(stored.error.as_deref(), Some("that username is already taken"));
    }

    // -- endpoint handler wrappers (GET/POST) --------------------------------

    #[tokio::test]
    async fn endpoint_get_and_post_reject_unknown_state() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let params = HashMap::from([("state".to_string(), "no-such-state".to_string())]);

        let resp = broker_endpoint_handler_get(
            State(state.clone()),
            resolved(MASTER),
            Path((MASTER.to_string(), IDP_ALIAS.to_string())),
            Query(params.clone()),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("is invalid or has expired"));

        let resp = broker_endpoint_handler_post(
            State(state.clone()),
            resolved(MASTER),
            Path((MASTER.to_string(), IDP_ALIAS.to_string())),
            HeaderMap::new(),
            Form(params),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("is invalid or has expired"));
    }

    // -- session_cookie_user / finish_linking ---------------------------------

    /// Mint a realm-bound SSO access token for `user` (the cookie payload).
    async fn mint_sso_token(state: &Arc<ServerState>, realm: &Realm, user: &User) -> String {
        // The token's `iss` is realm-derived; the client only feeds claims, so
        // the master realm's built-in admin-cli serves for any realm.
        let client = state
            .storage
            .get_client_by_client_id(
                &master_realm_id(),
                &issuerd_core::ClientIdentifier::new("admin-cli").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        state
            .token_manager
            .issue_access_token_with_roles(
                user,
                &client,
                realm,
                &["openid".to_string()],
                &session_id,
                None,
                None,
                None,
            )
            .await
            .unwrap()
            .token
    }

    fn cookie_headers(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::COOKIE, cookie.parse().unwrap());
        h
    }

    #[tokio::test]
    async fn session_cookie_user_validates_realm_and_signature() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let user = broker_user(&realm_id, "cookie-user", true);
        storage.create_user(&realm_id, &user).await.unwrap();

        // No cookie → nobody.
        assert_eq!(session_cookie_user(&state, &realm, &HeaderMap::new()).await, None);
        // A garbage token → nobody.
        let bad = cookie_headers("issuerd_session_master=garbage");
        assert_eq!(session_cookie_user(&state, &realm, &bad).await, None);

        // A valid realm-bound SSO cookie → the signed-in user.
        let token = mint_sso_token(&state, &realm, &user).await;
        let headers = cookie_headers(&format!("issuerd_session_master={token}"));
        assert_eq!(session_cookie_user(&state, &realm, &headers).await, Some(user.id.clone()));

        // A token minted for ANOTHER realm must not match this realm.
        let other = Realm {
            id: RealmId::new("other").unwrap(),
            name: RealmName::new("other").unwrap(),
            display_name: None,
            enabled: true,
            ..Default::default()
        };
        storage.create_realm(&other).await.unwrap();
        let foreign = mint_sso_token(&state, &other, &user).await;
        let headers = cookie_headers(&format!("issuerd_session_master={foreign}"));
        assert_eq!(session_cookie_user(&state, &realm, &headers).await, None);
    }

    #[tokio::test]
    async fn finish_linking_links_external_identity_to_signed_in_user() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let idp = broker_idp_config(IDP_ALIAS);
        let user = broker_user(&realm_id, "linked-user", true);
        storage.create_user(&realm_id, &user).await.unwrap();

        let token = mint_sso_token(&state, &realm, &user).await;
        let headers = cookie_headers(&format!("issuerd_session_master={token}"));

        let resp = finish_linking(
            &state,
            &realm,
            &idp,
            &headers,
            MASTER,
            user.id.to_string(),
            broker_identity(),
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), "/realms/master/account/linked-accounts?linked=ext");
        let link = storage
            .get_identity_provider_link(&realm_id, IDP_ALIAS, "ext-sub-1")
            .await
            .unwrap()
            .expect("link created");
        assert_eq!(link.user_id, user.id);
        assert_eq!(link.external_username.as_deref(), Some("extuser"));
    }

    #[tokio::test]
    async fn finish_linking_requires_session_for_the_link_token_subject() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let idp = broker_idp_config(IDP_ALIAS);
        let user = broker_user(&realm_id, "signed-in-user", true);
        let other = broker_user(&realm_id, "token-subject", true);
        storage.create_user(&realm_id, &user).await.unwrap();
        storage.create_user(&realm_id, &other).await.unwrap();

        // The SSO cookie belongs to `user`, but the link token was issued to
        // `other` — a login-CSRF link injection must be refused.
        let token = mint_sso_token(&state, &realm, &user).await;
        let headers = cookie_headers(&format!("issuerd_session_master={token}"));
        let resp = finish_linking(
            &state,
            &realm,
            &idp,
            &headers,
            MASTER,
            other.id.to_string(),
            broker_identity(),
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            location(&resp),
            "/realms/master/account/linked-accounts?error=link-session-mismatch"
        );

        // No session cookie at all → same refusal.
        let resp = finish_linking(
            &state,
            &realm,
            &idp,
            &HeaderMap::new(),
            MASTER,
            other.id.to_string(),
            broker_identity(),
            None,
        )
        .await;
        assert_eq!(
            location(&resp),
            "/realms/master/account/linked-accounts?error=link-session-mismatch"
        );

        assert!(storage
            .get_identity_provider_link(&realm_id, IDP_ALIAS, "ext-sub-1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn finish_linking_idempotent_when_already_linked_to_same_user() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let idp = broker_idp_config(IDP_ALIAS);
        let user = broker_user(&realm_id, "linked-user", true);
        storage.create_user(&realm_id, &user).await.unwrap();
        storage
            .create_identity_provider_link(
                &realm_id,
                &IdentityProviderLink {
                    user_id: user.id.clone(),
                    provider_alias: IDP_ALIAS.to_string(),
                    external_subject: "ext-sub-1".to_string(),
                    external_username: None,
                    stored_refresh_token: None,
                    created_at: chrono::Utc::now(),
                },
            )
            .await
            .unwrap();

        let token = mint_sso_token(&state, &realm, &user).await;
        let headers = cookie_headers(&format!("issuerd_session_master={token}"));

        let resp = finish_linking(
            &state,
            &realm,
            &idp,
            &headers,
            MASTER,
            user.id.to_string(),
            broker_identity(),
            None,
        )
        .await;

        // Already linked to THIS account: a success, not an error.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), "/realms/master/account/linked-accounts?linked=ext");
    }

    #[tokio::test]
    async fn finish_linking_refuses_identity_linked_to_another_user() {
        let (state, storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let idp = broker_idp_config(IDP_ALIAS);
        let user = broker_user(&realm_id, "signed-in-user", true);
        let other = broker_user(&realm_id, "other-user", true);
        storage.create_user(&realm_id, &user).await.unwrap();
        storage.create_user(&realm_id, &other).await.unwrap();
        // The external identity belongs to `other`.
        storage
            .create_identity_provider_link(
                &realm_id,
                &IdentityProviderLink {
                    user_id: other.id.clone(),
                    provider_alias: IDP_ALIAS.to_string(),
                    external_subject: "ext-sub-1".to_string(),
                    external_username: None,
                    stored_refresh_token: None,
                    created_at: chrono::Utc::now(),
                },
            )
            .await
            .unwrap();

        let token = mint_sso_token(&state, &realm, &user).await;
        let headers = cookie_headers(&format!("issuerd_session_master={token}"));

        let resp = finish_linking(
            &state,
            &realm,
            &idp,
            &headers,
            MASTER,
            user.id.to_string(),
            broker_identity(),
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), "/realms/master/account/linked-accounts?error=already-linked");
        // The link still points at the original owner.
        let link = storage
            .get_identity_provider_link(&realm_id, IDP_ALIAS, "ext-sub-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(link.user_id, other.id);
    }

    // -- finish_login -----------------------------------------------------------

    async fn seed_pending_auth(cache: &TestCache, realm_id: &RealmId, flow_id: &str) {
        cache
            .set(
                &pending_auth_cache_key(realm_id, flow_id),
                serde_json::to_vec(&pending_auth_data(realm_id, flow_id)).unwrap(),
                None,
            )
            .await
            .unwrap();
    }

    fn realm_role(realm_id: &RealmId, name: &str) -> issuerd_core::Role {
        issuerd_core::Role {
            id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::RoleName::new(name).unwrap(),
            description: None,
            realm_id: realm_id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        }
    }

    fn existing_link(user_id: &UserId) -> IdentityProviderLink {
        IdentityProviderLink {
            user_id: user_id.clone(),
            provider_alias: IDP_ALIAS.to_string(),
            external_subject: "ext-sub-1".to_string(),
            external_username: None,
            stored_refresh_token: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn finish_login_known_link_disabled_user_rejected() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let idp = broker_idp_config(IDP_ALIAS);
        let user = broker_user(&realm_id, "linked-user", false);
        storage.create_user(&realm_id, &user).await.unwrap();
        storage
            .create_identity_provider_link(&realm_id, &existing_link(&user.id))
            .await
            .unwrap();
        seed_pending_auth(&cache, &realm_id, "flow-disabled").await;

        let resp = finish_login(
            &state,
            &realm,
            &idp,
            MASTER,
            login_broker_state(Some("flow-disabled")),
            broker_identity(),
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_text(resp).await.contains("this account is disabled"));
    }

    #[tokio::test]
    async fn finish_login_force_sync_applies_mapped_roles() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let mut idp = broker_idp_config(IDP_ALIAS);
        idp.config.insert("syncMode".to_string(), "force".to_string());
        idp.config.insert(
            "mappers".to_string(),
            r#"[{"name":"grant-admins","mapper_type":"role","config":{"claim":"groups","claim_value":"admins","role":"broker-mapped-role"}}]"#
                .to_string(),
        );
        let role = realm_role(&realm_id, "broker-mapped-role");
        storage.create_role(&realm_id, &role).await.unwrap();
        let user = broker_user(&realm_id, "linked-user", true);
        storage.create_user(&realm_id, &user).await.unwrap();
        storage
            .create_identity_provider_link(&realm_id, &existing_link(&user.id))
            .await
            .unwrap();
        seed_pending_auth(&cache, &realm_id, "flow-force").await;

        let mut identity = broker_identity();
        identity.claims = serde_json::json!({"sub": "ext-sub-1", "groups": ["admins"]});

        let resp = finish_login(
            &state,
            &realm,
            &idp,
            MASTER,
            login_broker_state(Some("flow-force")),
            identity,
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(location(&resp).starts_with("http://localhost:8080/cb?"));
        // syncMode=force re-applies mappers on every login: the role the
        // mapper grants must actually be assigned.
        let roles = storage.list_user_realm_roles(&realm_id, &user.id).await.unwrap();
        assert!(roles.contains(&role.id), "mapped role assigned on force-sync login");
    }

    #[tokio::test]
    async fn finish_login_autolink_rejects_disabled_account() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let mut idp = broker_idp_config(IDP_ALIAS);
        idp.config.insert("trustEmail".to_string(), "true".to_string());
        let mut existing = broker_user(&realm_id, "existing-user", false);
        existing.email = Some(Email::new("ext@example.com").unwrap());
        storage.create_user(&realm_id, &existing).await.unwrap();
        seed_pending_auth(&cache, &realm_id, "flow-autolink-disabled").await;

        let resp = finish_login(
            &state,
            &realm,
            &idp,
            MASTER,
            login_broker_state(Some("flow-autolink-disabled")),
            broker_identity(),
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_text(resp).await.contains("this account is disabled"));
        assert!(storage
            .get_identity_provider_link(&realm_id, IDP_ALIAS, "ext-sub-1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn finish_login_autolink_links_enabled_account_and_completes() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let mut idp = broker_idp_config(IDP_ALIAS);
        idp.config.insert("trustEmail".to_string(), "true".to_string());
        let mut existing = broker_user(&realm_id, "existing-user", true);
        existing.email = Some(Email::new("ext@example.com").unwrap());
        storage.create_user(&realm_id, &existing).await.unwrap();
        seed_pending_auth(&cache, &realm_id, "flow-autolink-ok").await;

        let resp = finish_login(
            &state,
            &realm,
            &idp,
            MASTER,
            login_broker_state(Some("flow-autolink-ok")),
            broker_identity(),
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(location(&resp).starts_with("http://localhost:8080/cb?"));
        let link = storage
            .get_identity_provider_link(&realm_id, IDP_ALIAS, "ext-sub-1")
            .await
            .unwrap()
            .expect("auto-link created");
        assert_eq!(link.user_id, existing.id);
    }

    // -- create_brokered_user -----------------------------------------------------

    #[tokio::test]
    async fn create_brokered_user_marks_email_verified_only_when_unedited() {
        let (state, _storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let idp = broker_idp_config(IDP_ALIAS);

        // IdP-verified email, passed through unedited → verified.
        let user = create_brokered_user(
            &state,
            &realm,
            &idp,
            &broker_identity(),
            "user-one".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(user.email_verified, "IdP-verified email, unedited → verified");
        assert_eq!(user.email.as_ref().map(|e| e.as_str()), Some("ext@example.com"));

        // Edited on the review form → NOT verified, even though the IdP
        // verified the original address.
        let user = create_brokered_user(
            &state,
            &realm,
            &idp,
            &broker_identity(),
            "user-two".to_string(),
            Some("edited@example.com".to_string()),
            None,
            None,
        )
        .await
        .unwrap();
        assert!(!user.email_verified, "edited email must not be marked verified");
        assert_eq!(user.email.as_ref().map(|e| e.as_str()), Some("edited@example.com"));

        // Not IdP-verified → not verified even when unedited.
        let mut identity = broker_identity();
        identity.email_verified = false;
        let user = create_brokered_user(
            &state,
            &realm,
            &idp,
            &identity,
            "user-three".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(!user.email_verified);
    }

    #[tokio::test]
    async fn create_brokered_user_assigns_verify_email_only_for_unverified_email() {
        let (state, _storage, _cache) = test_state().await;
        let realm_id = master_realm_id();
        let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        realm.verify_email_enabled = true;
        let idp = broker_idp_config(IDP_ALIAS);

        // Unverified email + verify-email realm → VERIFY_EMAIL assigned.
        let mut identity = broker_identity();
        identity.email_verified = false;
        let user = create_brokered_user(
            &state,
            &realm,
            &idp,
            &identity,
            "user-v1".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(
            user.required_actions.iter().any(|a| a == "VERIFY_EMAIL"),
            "unverified email → VERIFY_EMAIL: {:?}",
            user.required_actions
        );

        // IdP-verified email surviving unedited → no VERIFY_EMAIL.
        let user = create_brokered_user(
            &state,
            &realm,
            &idp,
            &broker_identity(),
            "user-v2".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(
            !user.required_actions.iter().any(|a| a == "VERIFY_EMAIL"),
            "verified email → no VERIFY_EMAIL: {:?}",
            user.required_actions
        );
    }

    // -- first_broker_login_page ----------------------------------------------------

    #[tokio::test]
    async fn first_login_page_renders_review_and_link_modes() {
        let (state, _storage, cache) = test_state().await;
        let realm_id = master_realm_id();

        // Review mode: prefilled, editable profile form.
        let entry = first_login_entry(&realm_id, "review", None);
        seed_first_login_entry(&cache, &realm_id, "exec-page-review", &entry).await;
        let resp = first_broker_login_page(
            State(state.clone()),
            resolved(MASTER),
            Path((MASTER.to_string(), "exec-page-review".to_string())),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_text(resp).await;
        assert!(body.contains("Review your profile"), "body: {body}");
        assert!(body.contains("value=\"extuser\""));
        assert!(body.contains("value=\"ext@example.com\""));
        assert!(body.contains("value=\"review\""));
        assert!(body.contains("/realms/master/broker/first-login/exec-page-review"));

        // Link mode: password confirmation form.
        let entry = first_login_entry(&realm_id, "link", Some("some-user".to_string()));
        seed_first_login_entry(&cache, &realm_id, "exec-page-link", &entry).await;
        let resp = first_broker_login_page(
            State(state.clone()),
            resolved(MASTER),
            Path((MASTER.to_string(), "exec-page-link".to_string())),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_text(resp).await;
        assert!(body.contains("Link your account"), "body: {body}");
        assert!(body.contains("ext@example.com"));
        assert!(body.contains("value=\"link\""));
        assert!(body.contains("value=\"create\""));

        // Unknown execution → error page, not a form.
        let resp = first_broker_login_page(
            State(state),
            resolved(MASTER),
            Path((MASTER.to_string(), "gone".to_string())),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("has expired"));
    }

    #[tokio::test]
    async fn submit_with_disabled_idp_rejected() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        let mut idp = broker_idp_config(IDP_ALIAS);
        idp.enabled = false;
        storage.create_identity_provider(&realm_id, &idp).await.unwrap();

        let execution = "exec-idp-disabled";
        let entry = first_login_entry(&realm_id, "review", None);
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([
                ("action".to_string(), "review".to_string()),
                ("username".to_string(), "newbie".to_string()),
                ("email".to_string(), "newbie@example.com".to_string()),
            ]),
            true,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("unknown identity provider"));
        assert!(storage.get_user_by_username(&realm_id, "newbie").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn submit_review_maps_profile_fields() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;

        let execution = "exec-review-fields";
        let entry = first_login_entry(&realm_id, "review", None);
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([
                ("action".to_string(), "review".to_string()),
                ("username".to_string(), "mapped-user".to_string()),
                ("email".to_string(), "mapped@example.com".to_string()),
                ("first_name".to_string(), "Mapped".to_string()),
                ("last_name".to_string(), "Person".to_string()),
            ]),
            true,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(location(&resp).starts_with("http://localhost:8080/cb?"));
        let created = storage
            .get_user_by_username(&realm_id, "mapped-user")
            .await
            .unwrap()
            .expect("review submit creates the local user");
        // The form values win over the identity fallback: a dropped non-empty
        // filter would silently fall back to the IdP claims instead.
        assert_eq!(created.email.as_ref().map(|e| e.as_str()), Some("mapped@example.com"));
        assert_eq!(created.first_name.as_ref().map(|n| n.as_str()), Some("Mapped"));
        assert_eq!(created.last_name.as_ref().map(|n| n.as_str()), Some("Person"));
    }

    #[tokio::test]
    async fn submit_review_duplicate_email_retries() {
        let (state, storage, cache) = test_state().await;
        let realm_id = master_realm_id();
        seed_broker_idp(&storage, &realm_id).await;
        let mut existing = broker_user(&realm_id, "existing-user", true);
        existing.email = Some(Email::new("dup@example.com").unwrap());
        storage.create_user(&realm_id, &existing).await.unwrap();

        let execution = "exec-review-dup";
        let entry = first_login_entry(&realm_id, "review", None);
        seed_first_login_entry(&cache, &realm_id, execution, &entry).await;

        let resp = submit_first_login(
            &state,
            execution,
            HashMap::from([
                ("action".to_string(), "review".to_string()),
                ("username".to_string(), "unique-name".to_string()),
                ("email".to_string(), "dup@example.com".to_string()),
            ]),
            true,
        )
        .await;

        // The realm forbids duplicate emails: PRG back with the banner.
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), format!("/realms/master/broker/first-login/{execution}"));
        let stored = load_first_login_entry(&state, &realm_id, execution)
            .await
            .expect("entry re-stored for the retry");
        assert_eq!(stored.error.as_deref(), Some("that email address is already in use"));
        assert!(storage.get_user_by_username(&realm_id, "unique-name").await.unwrap().is_none());
    }
}
