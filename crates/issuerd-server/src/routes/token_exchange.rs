// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// RFC 8693 token exchange: internal audience exchange and impersonation.

//! RFC 8693 token exchange.
//!
//! Two modes are implemented:
//!
//! - **Internal exchange**: the `subject_token` is an access token issued by
//!   this realm; the minted token is scoped to the `audience` client (or the
//!   requesting client itself when `audience` is omitted). The target client
//!   must carry the `token.exchange.enabled=true` attribute, otherwise the
//!   exchange is rejected with `invalid_grant`.
//! - **Impersonation exchange**: `requested_subject` names a target user; the
//!   subject token's owner must hold the realm `impersonation` role (parity
//!   with the admin impersonation endpoint). The minted token carries
//!   the `impersonator` claim and the same audit treatment applies (admin
//!   event + gate-bypassing login event).
//!
//! Out of scope (rejected at protocol validation): delegation
//! (`actor_token`), non-access-token subject/requested token types.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use issuerd_core::{
    AccessTokenClaims, Client, ClientIdentifier, EventType, Realm, RealmId, SessionId, User, UserId,
};
use issuerd_protocol::token::{GrantType, TokenRequest, TOKEN_TYPE_ACCESS_TOKEN};
use tracing::{debug, info, warn};

use super::oidc::{
    emit_oidc_event, error_response, persist_session, resolve_token_user, session_invalidated,
    token_response, TokenResponse,
};
use crate::state::ServerState;

/// Client attribute gating internal token exchange to this client as the
/// target audience.
pub(crate) const CLIENT_TOKEN_EXCHANGE_ATTRIBUTE: &str = "token.exchange.enabled";

/// Realm role the subject-token owner must hold to run an impersonation
/// exchange — the same role the admin impersonation endpoint checks.
const IMPERSONATION_ROLE: &str = "impersonation";

/// Token-endpoint entry point for `urn:ietf:params:oauth:grant-type:token-exchange`.
///
/// The requesting client is already authenticated by `token_handler`, and the
/// request has passed `TokenRequest::validate` (subject token present, token
/// type URNs checked). Everything here fails with `400 invalid_grant` unless
/// noted otherwise — RFC 6749 §5.2 has no more specific code for these
/// failures.
pub(crate) async fn token_exchange_grant(
    state: &Arc<ServerState>,
    realm: &Realm,
    client: &Client,
    token_req: &TokenRequest,
    ip: &std::net::IpAddr,
    dpop_jkt: Option<&str>,
) -> Response {
    let realm_id = &realm.id;
    let subject_token = token_req.subject_token.as_deref().unwrap_or("");

    // RFC 7009 revocation blocklist — the same key the userinfo and
    // introspection paths check.
    if matches!(state.cache.get(&format!("revoked:{subject_token}")).await, Ok(Some(_))) {
        warn!(realm = %realm_id, client_id = %client.client_id, "token exchange: revoked subject token presented");
        return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
    }

    // Stateless validation: signature, expiry, issuer family. `aud` is
    // deliberately not checked — the subject token only needs to be a valid
    // token of this realm, regardless of which client it was minted for.
    let subject_claims = match state.token_service.validate_access_token(subject_token) {
        Ok(v) => v.claims,
        Err(e) => {
            debug!(realm = %realm_id, client_id = %client.client_id, error = %e, "token exchange: subject token validation failed");
            return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
        }
    };

    // Realm binding: the stateless validator accepts any realm of this issuer
    // base URL, so the issuer realm must be compared explicitly. The issuer
    // segment is a realm NAME. Cross-realm exchange is not supported.
    if issuerd_core::typestate::extract_realm_from_issuer(subject_claims.iss.as_str())
        != Some(realm.name.as_str())
    {
        warn!(realm = %realm_id, client_id = %client.client_id, iss = %subject_claims.iss.as_str(), "token exchange: subject token from another realm");
        return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
    }

    // Realm not_before: tokens issued before the realm's cutoff are
    // revoked wholesale (0 = no cutoff).
    if realm.not_before > 0 && subject_claims.iat < realm.not_before {
        return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
    }

    // The underlying user session must still be alive (logout, admin session
    // teardown).
    if session_invalidated(state, &subject_claims).await {
        return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
    }

    // The subject user must still exist and be enabled. Pairwise subject
    // tokens resolve through their session; public ones
    // resolve directly.
    let subject_user = match resolve_token_user(state, realm_id, &subject_claims, None).await {
        Some(u) if u.enabled => u,
        _ => {
            warn!(realm = %realm_id, client_id = %client.client_id, sub = %subject_claims.sub, "token exchange: subject user missing or disabled");
            return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
        }
    };

    // RFC 9449 §7.1: a DPoP-bound subject token may only be
    // exchanged by its key holder. Without this check a stolen bound token
    // could be laundered into a plain bearer token (or re-bound to the
    // attacker's key), defeating sender-constraining. The request's proof was
    // already verified by the token handler, so matching thumbprints also
    // propagates the binding to the minted token via `bind_cnf_overlay`.
    if let Some(cnf) = &subject_claims.cnf {
        if dpop_jkt != Some(cnf.jkt.as_str()) {
            warn!(realm = %realm_id, client_id = %client.client_id, "token exchange: subject token is DPoP-bound but the request proof is missing or carries a different key");
            return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
        }
    }

    if let Some(requested_subject) = token_req.requested_subject.as_deref() {
        impersonation_exchange(
            state,
            realm,
            client,
            token_req,
            ip,
            &subject_claims,
            &subject_user,
            requested_subject,
            dpop_jkt,
        )
        .await
    } else {
        internal_exchange(
            state,
            realm,
            client,
            token_req,
            ip,
            &subject_claims,
            &subject_user,
            dpop_jkt,
        )
        .await
    }
}

/// Internal exchange: re-scope the subject token's grant to the target
/// client, narrowed by the exchange permission flag and the requested scope.
#[allow(clippy::too_many_arguments)]
async fn internal_exchange(
    state: &Arc<ServerState>,
    realm: &Realm,
    client: &Client,
    token_req: &TokenRequest,
    ip: &std::net::IpAddr,
    subject_claims: &AccessTokenClaims,
    subject_user: &User,
    dpop_jkt: Option<&str>,
) -> Response {
    let realm_id = &realm.id;

    // Target client: `audience` names the client the exchanged token is
    // minted for; without it the token is re-scoped for the requesting
    // client itself.
    let target_client =
        match resolve_target_client(state, realm_id, token_req.audience.as_deref()).await {
            Some(c) => c,
            None => {
                return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
            }
        };
    let target_client = target_client.unwrap_or_else(|| client.clone());

    // Exchange permission: the target client must opt in via the
    // `token.exchange.enabled` attribute.
    let permitted = target_client
        .attributes
        .get(CLIENT_TOKEN_EXCHANGE_ATTRIBUTE)
        .is_some_and(|v| v == "true");
    if !permitted {
        warn!(realm = %realm_id, client_id = %client.client_id, target = %target_client.client_id, "token exchange: target client has not opted in");
        return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
    }

    // Scope narrowing (RFC 8693 §2.1): the requested scope must not exceed
    // the subject token's grant; an omitted scope keeps it.
    let scope = if token_req.scope.is_empty() {
        subject_claims.scope.clone()
    } else {
        let granted = &subject_claims.scope;
        if token_req.scope.iter().any(|s| !granted.contains(s)) {
            return exchange_error(state, realm_id, client, ip, "invalid_scope").await;
        }
        token_req.scope.clone()
    };
    // The claims pipeline resolves scope names realm-wide, so
    // intersect with the TARGET client's assignments — otherwise a
    // requesting client could smuggle its own assigned scopes (and their
    // protocol mappers / role filters) into the target's audience. RFC 6749
    // §3.3 permits issuing a narrower scope than requested; the response
    // carries the issued set.
    let scope = intersect_client_scopes(scope, &target_client);

    // The exchanged token stays bound to the subject's session; subject
    // tokens without a user session (client credentials) get a fresh,
    // unpersisted session id — same shape as the client-credentials grant.
    let subject_session = match &subject_claims.sid {
        Some(sid) => match state.storage.get_user_session(realm_id, sid).await {
            Ok(session) => session,
            Err(e) => {
                warn!(realm = %realm_id, client_id = %client.client_id, error = %e, "token exchange: subject session lookup failed; impersonator audit claim may be dropped");
                None
            }
        },
        None => None,
    };
    let session_id = subject_claims
        .sid
        .clone()
        .unwrap_or_else(|| SessionId::new(issuerd_core::utils::generate_id()).unwrap());

    // The claims pipeline resolves scope names to client scopes and
    // evaluates mappers for the TARGET client, so audience/scope narrowing is
    // automatic.
    let mut overlay = crate::claims::build_claims_overlay(
        state,
        realm_id,
        Some(&target_client),
        subject_user,
        scope.as_slice(),
        issuerd_core::ClaimTarget::AccessToken,
    )
    .await
    .unwrap_or_default();

    // An impersonated subject session keeps the `impersonator` audit claim on
    // exchanged tokens (parity with the refresh grant) — otherwise
    // an exchange would launder the impersonation trail.
    if let Some(impersonator) = subject_session.and_then(|s| s.impersonator) {
        overlay.insert(
            "impersonator".to_string(),
            serde_json::Value::String(impersonator.to_string()),
        );
    }

    // Bind the exchanged token to the request's DPoP proof key.
    let overlay = crate::dpop::bind_cnf_overlay(Some(overlay), dpop_jkt);

    let access_token = match state
        .token_manager
        .issue_access_token_with_roles(
            subject_user,
            &target_client,
            realm,
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
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e))).into_response();
        }
    };

    info!(realm = %realm_id, client_id = %client.client_id, target = %target_client.client_id, user_id = %subject_user.id, "token exchanged");
    let mut details = HashMap::new();
    details.insert("grant_type".to_string(), GrantType::TokenExchange.as_str().to_string());
    details.insert("audience".to_string(), target_client.client_id.to_string());
    emit_oidc_event(
        state,
        realm_id,
        EventType::TokenExchange,
        ip,
        Some(client.id.clone()),
        Some(subject_user.id.clone()),
        Some(session_id),
        None,
        details,
    )
    .await;

    token_response(TokenResponse {
        access_token: access_token.token,
        token_type: crate::dpop::token_type(dpop_jkt.is_some()),
        expires_in: realm.access_token_lifespan.get(),
        refresh_token: None,
        id_token: None,
        scope: Some(scope.join(" ")),
        issued_token_type: Some(TOKEN_TYPE_ACCESS_TOKEN.to_string()),
        authorization_details: None,
    })
}

/// Impersonation exchange: mint a token for `requested_subject` on behalf of
/// the subject token's owner, who must hold the realm `impersonation` role.
#[allow(clippy::too_many_arguments)]
async fn impersonation_exchange(
    state: &Arc<ServerState>,
    realm: &Realm,
    client: &Client,
    token_req: &TokenRequest,
    ip: &std::net::IpAddr,
    subject_claims: &AccessTokenClaims,
    subject_user: &User,
    requested_subject: &str,
    dpop_jkt: Option<&str>,
) -> Response {
    let realm_id = &realm.id;

    // The caller must hold the realm `impersonation` role, matching the admin
    // impersonation endpoint: it evaluates the token's `realm_access` claim,
    // and so does the exchange.
    let permitted = subject_claims
        .realm_access
        .as_ref()
        .is_some_and(|ra| ra.roles.iter().any(|r| r.as_ref() == IMPERSONATION_ROLE));
    if !permitted {
        warn!(realm = %realm_id, client_id = %client.client_id, user_id = %subject_user.id, "impersonation exchange: caller lacks the impersonation role");
        return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
    }

    let target_id = match UserId::new(requested_subject) {
        Ok(id) => id,
        Err(_) => return exchange_error(state, realm_id, client, ip, "invalid_grant").await,
    };
    let target_user = match state.storage.get_user(realm_id, &target_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => {
            return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
        }
    };
    // Admin-API parity: an administrator cannot impersonate themselves.
    if target_user.id == subject_user.id {
        return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
    }

    // The impersonation role is the gate; `audience` merely re-targets the
    // minted token (default: the requesting client). The
    // `token.exchange.enabled` flag is not required in this mode.
    let target_client =
        match resolve_target_client(state, realm_id, token_req.audience.as_deref()).await {
            Some(c) => c,
            None => {
                return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
            }
        };
    let target_client = target_client.unwrap_or_else(|| client.clone());

    // Persist an impersonation session (the admin-impersonation shape) so
    // logout, session administration, and refresh-time `impersonator`
    // re-injection all work.
    let now = chrono::Utc::now();
    let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
    let session = issuerd_core::UserSession {
        id: session_id.clone(),
        realm_id: realm_id.clone(),
        user_id: target_user.id.clone(),
        login_username: target_user.username.clone(),
        ip_address: *ip,
        auth_method: issuerd_core::AuthMethod::Impersonation,
        remember_me: false,
        offline: false,
        started: now,
        last_session_refresh: now,
        auth_time: now,
        impersonator: Some(subject_user.id.clone()),
        clients: vec![issuerd_core::ClientSession {
            id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id()).unwrap(),
            client_id: target_client.id.clone(),
            session_id: session_id.clone(),
            redirect_uri: None,
            state: None,
            auth_method: issuerd_core::AuthMethod::Impersonation,
            timestamp: now,
        }],
    };
    if let Err(resp) = persist_session(state, realm_id, &session, false).await {
        return resp;
    }

    // Requested scope if given (already validated against the requesting
    // client's vocabulary), else the impersonation default set.
    // Intersected with the target client's assignments (see
    // `intersect_client_scopes`).
    let scope = if token_req.scope.is_empty() {
        issuerd_core::Scope::parse("openid profile email")
    } else {
        token_req.scope.clone()
    };
    let scope = intersect_client_scopes(scope, &target_client);

    let mut overlay = crate::claims::build_claims_overlay(
        state,
        realm_id,
        Some(&target_client),
        &target_user,
        scope.as_slice(),
        issuerd_core::ClaimTarget::AccessToken,
    )
    .await
    .unwrap_or_default();
    overlay.insert(
        "impersonator".to_string(),
        serde_json::Value::String(subject_user.id.to_string()),
    );
    // Bind the exchanged token to the request's DPoP proof key.
    let overlay = crate::dpop::bind_cnf_overlay(Some(overlay), dpop_jkt);

    let access_token = match state
        .token_manager
        .issue_access_token_with_roles(
            &target_user,
            &target_client,
            realm,
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
            // Issuance failed after the session was persisted — remove it so
            // no token-less impersonation session lingers in storage.
            let _ = state.storage.delete_user_session(realm_id, &session_id).await;
            crate::session_cache::invalidate_session(state, realm_id, &session_id).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response(&e))).into_response();
        }
    };

    // Audit: an admin event (gated on the realm's admin-events config,
    // representation stripped unless opted in — realm gating rules) ...
    if realm.admin_events_enabled {
        let representation = if realm.include_representations {
            serde_json::to_string(&serde_json::json!({
                "impersonator": subject_user.id.to_string(),
                "impersonated_user": target_user.id.to_string(),
                "via": "token-exchange",
            }))
            .ok()
        } else {
            None
        };
        let event = issuerd_core::AdminEvent {
            id: issuerd_core::EventId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            auth_realm_id: Some(realm_id.clone()),
            auth_client_id: Some(client.id.clone()),
            auth_user_id: Some(subject_user.id.clone()),
            operation_type: issuerd_core::OperationType::Action,
            resource_type: issuerd_core::ResourceType::User,
            resource_path: format!("users/{}/impersonation", target_user.id),
            representation,
            error: None,
            event_time: now,
        };
        if let Err(e) = state.storage.save_admin_event(&event).await {
            warn!(realm = %realm_id, impersonator = %subject_user.id, impersonated = %target_user.id, error = %e, "impersonation admin event write failed");
        }
    }

    // ... plus a login event that deliberately bypasses the `events_enabled`
    // gate (parity with admin impersonation: impersonation must always be
    // visible in the audit trail).
    let mut details = HashMap::new();
    details.insert("method".to_string(), "impersonation".to_string());
    details.insert("impersonator".to_string(), subject_user.id.to_string());
    details.insert("username".to_string(), target_user.username.to_string());
    details.insert("grant_type".to_string(), GrantType::TokenExchange.as_str().to_string());
    let event = issuerd_core::Event {
        id: issuerd_core::EventId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm_id.clone(),
        event_time: now,
        event_type: EventType::Login,
        ip_address: Some(*ip),
        client_id: Some(target_client.id.clone()),
        user_id: Some(target_user.id.clone()),
        session_id: Some(session_id.clone()),
        error: None,
        details,
    };
    if let Err(e) = state.storage.save_event(realm_id, &event).await {
        warn!(realm = %realm_id, impersonator = %subject_user.id, impersonated = %target_user.id, error = %e, "impersonation login event write failed");
    }

    info!(realm = %realm_id, client_id = %client.client_id, user_id = %target_user.id, impersonator = %subject_user.id, "impersonation token exchange");

    token_response(TokenResponse {
        access_token: access_token.token,
        token_type: crate::dpop::token_type(dpop_jkt.is_some()),
        expires_in: realm.access_token_lifespan.get(),
        refresh_token: None,
        id_token: None,
        scope: Some(scope.join(" ")),
        issued_token_type: Some(TOKEN_TYPE_ACCESS_TOKEN.to_string()),
        authorization_details: None,
    })
}

/// Intersect a scope with the target client's assigned scope names
/// (`default_scopes ∪ optional_scopes`). The claims pipeline resolves scope
/// names realm-wide, so without this an exchanged token could carry scopes —
/// and their mappers and scope-derived role filters — that the target client
/// was never assigned.
fn intersect_client_scopes(scope: issuerd_core::Scope, client: &Client) -> issuerd_core::Scope {
    issuerd_core::Scope::from(
        scope
            .iter()
            .filter(|s| client.default_scopes.contains(s) || client.optional_scopes.contains(s))
            .cloned()
            .collect::<Vec<_>>(),
    )
}

/// Resolve the `audience` parameter to an enabled client of this realm.
///
/// Returns `Some(None)` when `audience` is absent (caller substitutes the
/// requesting client), `Some(Some(client))` on resolution, and `None` when
/// the named client does not exist or is disabled.
async fn resolve_target_client(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    audience: Option<&str>,
) -> Option<Option<Client>> {
    let Some(audience) = audience else {
        return Some(None);
    };
    let identifier = ClientIdentifier::new(audience).ok()?;
    match state.storage.get_client_by_client_id(realm_id, &identifier).await {
        Ok(Some(c)) if c.enabled => Some(Some(c)),
        Err(e) => {
            warn!(realm = %realm_id, client_id = %identifier, error = %e, "token exchange: target client lookup failed");
            None
        }
        _ => None,
    }
}

/// Emit a `token_exchange_error` event and return the OAuth2 error response.
async fn exchange_error(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    client: &Client,
    ip: &std::net::IpAddr,
    error: &str,
) -> Response {
    let mut details = HashMap::new();
    details.insert("grant_type".to_string(), GrantType::TokenExchange.as_str().to_string());
    emit_oidc_event(
        state,
        realm_id,
        EventType::TokenExchangeError,
        ip,
        Some(client.id.clone()),
        None,
        None,
        Some(error.to_string()),
        details,
    )
    .await;
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": error }))).into_response()
}
