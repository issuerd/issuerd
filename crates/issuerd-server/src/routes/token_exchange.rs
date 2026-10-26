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
//! The subject token's `aud` MUST contain the requesting client (Keycloak's
//! semantics, unconditional since the security-review remediation): a client
//! may only exchange a token that was issued for it, in both modes — see
//! `token_exchange_grant`. (The former opt-in
//! `require_requester_in_subject_aud` realm/client attribute was removed;
//! leftover attributes in stored realms/clients are inert.)
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
    cache_failure_response, emit_oidc_event, error_response, persist_session, resolve_token_user,
    session_invalidated, token_response, TokenResponse,
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
    match state.cache.get(&format!("revoked:{subject_token}")).await {
        Ok(Some(_)) => {
            warn!(realm = %realm_id, client_id = %client.client_id, "token exchange: revoked subject token presented");
            return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
        }
        Ok(None) => {}
        Err(e) => return cache_failure_response(&e),
    }

    // Stateless validation: signature, expiry, issuer family. `aud` is not
    // checked here — the mandatory requester-in-audience check below handles
    // it against the raw claim (the typed claims keep only its first entry).
    let subject_claims = match state.token_service.validate_access_token(subject_token) {
        Ok(v) => v.claims,
        Err(e) => {
            debug!(realm = %realm_id, client_id = %client.client_id, error = %e, "token exchange: subject token validation failed");
            return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
        }
    };

    // The reserved operation-bound scope can never enter an ordinary exchange,
    // including by inheritance from legacy subject-token data.
    if subject_claims.scope.contains(issuerd_core::MCP_SCOPE_STEP_UP) {
        return exchange_error(state, realm_id, client, ip, "invalid_scope").await;
    }

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

    // Mandatory audience check (Keycloak's semantics; security review
    // remediation): the requesting client must be an audience of the subject
    // token. Without it, a client that was handed a token addressed to
    // someone else could re-scope it.
    if !subject_claims.aud.contains(client.client_id.as_ref()) {
        warn!(realm = %realm_id, client_id = %client.client_id, "token exchange: requesting client not in the subject token's audience");
        return exchange_error(state, realm_id, client, ip, "invalid_grant").await;
    }

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
    let scope = intersect_client_scopes(scope, &target_client, state.config.mcp.enabled);

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
    let scope = intersect_client_scopes(scope, &target_client, state.config.mcp.enabled);

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
fn intersect_client_scopes(
    scope: issuerd_core::Scope,
    client: &Client,
    mcp_enabled: bool,
) -> issuerd_core::Scope {
    issuerd_core::Scope::from(
        scope
            .iter()
            .filter(|scope| {
                issuerd_core::client_scope_request_permitted_with_mcp(client, scope, mcp_enabled)
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::middleware::{proxy_ip::ClientIp, realm::ResolvedRealm};
    use issuerd_core::IssuerdError;

    /// Master-realm state where admin-cli has opted into token exchange and
    /// admin holds a session-backed access token issued for admin-cli.
    struct ExchangeFixture {
        state: Arc<ServerState>,
        subject_token: String,
    }

    #[derive(Default)]
    struct RevocationFailureCache {
        inner: issuerd_cluster::InMemoryCache,
    }

    #[async_trait::async_trait]
    impl issuerd_core::DistributedCache for RevocationFailureCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
            if key.starts_with("revoked:") {
                return Err(IssuerdError::ServerError("cache down".to_string()));
            }
            self.inner.get(key).await
        }

        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<std::time::Duration>,
        ) -> Result<(), IssuerdError> {
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

    async fn exchange_fixture() -> ExchangeFixture {
        exchange_fixture_with_cache(Arc::new(issuerd_cluster::InMemoryCache::new())).await
    }

    async fn exchange_fixture_with_cache(
        cache: Arc<dyn issuerd_core::DistributedCache>,
    ) -> ExchangeFixture {
        let storage: Arc<dyn issuerd_core::Storage> =
            Arc::new(issuerd_storage::InMemoryStorage::new());
        let state = Arc::new(
            ServerState::from_components(&ServerConfig::default(), storage, cache)
                .await
                .unwrap(),
        );
        let realm_id = RealmId::new("master").unwrap();
        let user = state.storage.get_user_by_username(&realm_id, "admin").await.unwrap().unwrap();
        let mut client = state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        client
            .attributes
            .insert(CLIENT_TOKEN_EXCHANGE_ATTRIBUTE.to_string(), "true".to_string());
        state.storage.update_client(&realm_id, &client).await.unwrap();
        // Mirrors the admin route's claims-cache invalidation for client
        // mutations (direct storage writes would otherwise stay hidden).
        issuerd_cluster::invalidate::invalidate_client_claims(
            state.cache.as_ref(),
            &realm_id,
            &client.id,
            client.client_id.as_ref(),
        )
        .await;

        let realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
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
        let token = state
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
        ExchangeFixture {
            state,
            subject_token: token.token,
        }
    }

    /// Post an internal token-exchange request for the given subject token.
    async fn exchange(state: &Arc<ServerState>, subject_token: &str) -> Response {
        crate::routes::oidc::token_handler(
            axum::extract::State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            axum::extract::Extension(ClientIp("127.0.0.1".parse().unwrap())),
            axum::http::HeaderMap::new(),
            format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=admin-cli&subject_token={subject_token}&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
            ),
        )
        .await
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn exchange_succeeds_for_opted_in_client() {
        let fixture = exchange_fixture().await;
        let resp = exchange(&fixture.state, &fixture.subject_token).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = json_body(resp).await;
        assert!(json["access_token"].as_str().unwrap().len() > 10);
        assert_eq!(
            json["issued_token_type"].as_str().unwrap(),
            "urn:ietf:params:oauth:token-type:access_token"
        );
    }

    #[tokio::test]
    async fn exchange_revocation_lookup_failure_is_temporarily_unavailable() {
        let fixture =
            exchange_fixture_with_cache(Arc::new(RevocationFailureCache::default())).await;
        let resp = exchange(&fixture.state, &fixture.subject_token).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json_body(resp).await["error"], "temporarily_unavailable");
    }

    #[tokio::test]
    async fn exchange_rejects_disabled_subject_user() {
        let fixture = exchange_fixture().await;
        let realm_id = RealmId::new("master").unwrap();
        let mut user = fixture
            .state
            .storage
            .get_user_by_username(&realm_id, "admin")
            .await
            .unwrap()
            .unwrap();
        user.enabled = false;
        fixture.state.storage.update_user(&realm_id, &user).await.unwrap();
        // Mirrors the admin route's claims-cache invalidation for user
        // mutations (direct storage writes would otherwise stay hidden).
        issuerd_cluster::invalidate::invalidate_user_claims(
            fixture.state.cache.as_ref(),
            &realm_id,
            &user.id,
        )
        .await;

        let resp = exchange(&fixture.state, &fixture.subject_token).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn exchange_rejects_inherited_step_up_scope() {
        let fixture = exchange_fixture().await;
        let subject = fixture
            .state
            .token_service
            .validate_access_token(&fixture.subject_token)
            .unwrap()
            .claims;
        let realm_id = RealmId::new("master").unwrap();
        let realm = fixture.state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        let user = fixture
            .state
            .storage
            .get_user_by_username(&realm_id, "admin")
            .await
            .unwrap()
            .unwrap();
        let client = fixture
            .state
            .storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap()
            .unwrap();
        let legacy_token = fixture
            .state
            .token_manager
            .issue_access_token_with_roles(
                &user,
                &client,
                &realm,
                &[
                    "openid".to_string(),
                    issuerd_core::MCP_SCOPE_STEP_UP.to_string(),
                ],
                subject.sid.as_ref().unwrap(),
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let resp = exchange(&fixture.state, &legacy_token.token).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_scope");
    }

    #[tokio::test]
    async fn exchange_honors_realm_not_before_boundary() {
        let fixture = exchange_fixture().await;
        let realm_id = RealmId::new("master").unwrap();
        let iat = fixture
            .state
            .token_service
            .validate_access_token(&fixture.subject_token)
            .unwrap()
            .claims
            .iat;

        let set_not_before = |cutoff: i64| {
            let state = fixture.state.clone();
            let realm_id = realm_id.clone();
            async move {
                let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
                realm.not_before = cutoff;
                state.storage.update_realm(&realm).await.unwrap();
                // Mirrors the admin route's synchronous realm-by-name
                // invalidation.
                state
                    .cache
                    .delete(&issuerd_cluster::cache_keys::realm_by_name("master"))
                    .await
                    .unwrap();
            }
        };

        // Boundary: a token issued exactly AT the cutoff is still valid
        // (the revocation is strictly `iat < not_before`).
        set_not_before(iat).await;
        let resp = exchange(&fixture.state, &fixture.subject_token).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // One second past the token's issue time: revoked wholesale.
        set_not_before(iat + 1).await;
        let resp = exchange(&fixture.state, &fixture.subject_token).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["error"], "invalid_grant");
    }

    #[test]
    fn audience_string_form_matches_exactly() {
        let aud: issuerd_core::Audience =
            serde_json::from_value(serde_json::json!("requester")).unwrap();
        assert!(aud.contains("requester"));
        assert!(!aud.contains("other-client"));
        assert!(!aud.contains("request"));
        assert!(!aud.contains("Requester"));
    }

    #[test]
    fn audience_array_form_matches_any_entry() {
        let aud: issuerd_core::Audience =
            serde_json::from_value(serde_json::json!(["frontend", "requester"])).unwrap();
        assert!(aud.contains("requester"));
        assert!(aud.contains("frontend"));
        assert!(!aud.contains("absent"));
    }

    #[test]
    fn audience_missing_or_malformed_fails_closed() {
        for value in [
            serde_json::Value::Null,
            serde_json::json!(42),
            serde_json::json!([]),
        ] {
            assert!(serde_json::from_value::<issuerd_core::Audience>(value).is_err());
        }
    }
}
