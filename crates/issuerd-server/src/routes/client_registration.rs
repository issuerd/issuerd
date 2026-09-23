// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Dynamic client registration (RFC 7591/7592), Keycloak's clients-registrations paths.

//! Dynamic client registration (RFC 7591/7592), Keycloak's
//! `clients-registrations` paths.
//!
//! Three endpoint families, all gated on the realm's
//! `dynamic_client_registration_enabled` attribute (default off → 404):
//!
//! - `POST /realms/{realm}/clients-registrations/default` — open
//!   registration (per-IP rate-limited).
//! - `POST /realms/{realm}/clients-registrations/openid-connect` —
//!   registration gated by an admin-minted initial access token
//!   (`Authorization: Bearer`, see `issuerd_admin_api::initial_access`).
//! - `GET/PUT/DELETE .../clients-registrations/openid-connect/{client_id}` —
//!   client configuration management with the **registration access token**
//!   issued at registration time (rotated on every PUT).
//!
//! Client payloads are the admin API's `ClientRepresentation` and run through
//! the exact validation of the admin create/update paths (extracted helpers
//! in `issuerd_admin_api::clients`), so registered and admin-managed clients are
//! indistinguishable afterwards.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use issuerd_admin_api::{
    clients::{ensure_client_id_available, seed_client_scopes_from_realm_defaults},
    dto::ClientRepresentation,
    initial_access::{sha256_hex, verify_and_consume_initial_access_token},
};
use issuerd_core::{
    AdminEvent, Client, EventId, IssuerdError, OperationType, Realm, RealmId, ResourceType,
};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    middleware::{proxy_ip::ClientIp, realm::ResolvedRealm},
    state::ServerState,
};

/// Per-IP registration allowance for the open endpoint (fixed 1-hour
/// window, tracked in the distributed cache).
pub(crate) const REGISTRATION_RATE_LIMIT_PER_HOUR: u64 = 50;

/// Cache key of a client's registration access token (hex SHA-256 of the
/// raw token; keyed by the client's internal id so renames keep working).
pub(crate) fn registration_access_cache_key(realm_id: &RealmId, client_id: &str) -> String {
    format!("registration-access:{}:{client_id}", realm_id.0)
}

/// The registration response: the client representation (secret visible —
/// this is the one channel that returns it) plus the registration access
/// token (RFC 7591 §3.2.1 `registration_access_token`; Keycloak spells it
/// `registrationAccessToken`).
#[derive(Debug, Serialize)]
struct ClientRegistrationResponse {
    #[serde(flatten)]
    client: ClientRepresentation,
    #[serde(rename = "registrationAccessToken")]
    registration_access_token: String,
}

/// RFC 7591 §3.2.2 error body.
fn registration_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

/// 401 for a missing/invalid bearer token (RFC 6750).
fn invalid_token_response(description: &str) -> Response {
    let mut response = registration_error(StatusCode::UNAUTHORIZED, "invalid_token", description);
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        "Bearer realm=\"client-registration\", error=\"invalid_token\"".parse().unwrap(),
    );
    response
}

/// Resolve the realm from the path segment and enforce the registration toggle.
/// Everything else (unknown realm, disabled toggle) is a uniform 404 — a
/// disabled realm must not reveal whether the realm exists.
async fn resolve_enabled_realm(
    state: &Arc<ServerState>,
    realm_segment: Option<&str>,
) -> Result<Realm, Response> {
    let Some(segment) = realm_segment else {
        return Err(registration_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing realm",
        ));
    };
    match state.resolve_realm(segment).await {
        Ok(Some(realm)) if realm.dynamic_client_registration_enabled() => Ok(realm),
        Ok(_) => Err(registration_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "dynamic client registration is not available",
        )),
        Err(e) => {
            warn!(error = %e, "realm resolution failed");
            Err(registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "realm lookup failed",
            ))
        }
    }
}

/// Extract a `Bearer` token from the Authorization header (case-insensitive
/// scheme, RFC 6750 §2.1).
fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Parse the registration request body as a [`ClientRepresentation`],
/// auto-generating `client_id` when the caller omitted it (RFC 7591 allows
/// server-assigned client ids). The `Err` payload is the
/// `error_description` for an `invalid_client_metadata` 400.
fn parse_client_representation(body: &serde_json::Value) -> Result<ClientRepresentation, String> {
    if !body.is_object() {
        return Err("request body must be a JSON object".to_string());
    }
    let mut value = body.clone();
    let missing_id = value.get("client_id").is_none_or(|v| v.is_null());
    if missing_id {
        value["client_id"] = serde_json::Value::String(issuerd_core::utils::generate_id());
    }
    serde_json::from_value(value).map_err(|e| format!("invalid client metadata: {e}"))
}

/// Create the client described by `body` in `realm`, mint its registration
/// access token, and render the 201 response. Shared by the open and the
/// token-gated registration endpoints.
async fn register_client(
    state: &Arc<ServerState>,
    realm: &Realm,
    body: serde_json::Value,
) -> Response {
    let mut rep = match parse_client_representation(&body) {
        Ok(rep) => rep,
        Err(description) => {
            return registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &description,
            );
        }
    };
    // There is no client-registration policy engine (Keycloak's
    // ClientRegistrationPolicy) to vet caller-supplied protocol mappers — an
    // audience mapper would let an anonymous registrant mint tokens naming
    // any resource server in the realm. Mapper attachment is admin-only
    // (the admin API still accepts them); drop them here.
    if rep.protocol_mappers.is_some() {
        debug!(
            realm = %realm.id,
            client_id = %rep.client_id,
            "dropping caller-supplied protocol mappers on registration"
        );
        rep.protocol_mappers = None;
    }
    if let Err(e) =
        seed_client_scopes_from_realm_defaults(&state.storage, &realm.id, &mut rep).await
    {
        warn!(realm = %realm.id, error = %e, "client scope seeding failed");
        return registration_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "client scope lookup failed",
        );
    }
    // Split the error code precisely per RFC 7591 §3.2.2: redirect-URI
    // syntax errors are `invalid_redirect_uri`, everything else is
    // `invalid_client_metadata`.
    if let Some(uris) = &rep.redirect_uris {
        for uri in uris {
            if let Err(e) = issuerd_core::RedirectUri::new(uri) {
                return registration_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_redirect_uri",
                    &format!("invalid redirect_uri: {e}"),
                );
            }
        }
    }
    let mut client: Client = match rep.clone().try_into() {
        Ok(c) => c,
        Err(e) => {
            return registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &e.to_string(),
            );
        }
    };
    match ensure_client_id_available(&state.storage, &realm.id, &client.client_id, None).await {
        Ok(()) => {}
        Err(IssuerdError::Conflict) => {
            return registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "client_id is already registered",
            );
        }
        Err(e) => {
            warn!(realm = %realm.id, error = %e, "client_id availability check failed");
            return registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "client lookup failed",
            );
        }
    }
    client.realm_id = realm.id.clone();
    // OIDC Core §8.1: pairwise clients must resolve to an
    // unambiguous sector; a configured `sector_identifier_uri` is fetched
    // and validated against the registered redirect URIs.
    if let Err(e) = issuerd_core::pairwise::validate_pairwise_subject_config(
        &client,
        state.broker_client.as_ref(),
    )
    .await
    {
        return registration_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            &e.to_string(),
        );
    }
    // Confidential by default: a registered client without an explicit
    // public flag or secret gets a generated one (Keycloak behaviour).
    if !client.public_client && client.secret.is_none() {
        client.secret = Some(issuerd_core::utils::generate_id());
    }
    if let Err(e) = state.storage.create_client(&realm.id, &client).await {
        error!(realm = %realm.id, error = %e, "client registration failed");
        return registration_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "client creation failed",
        );
    }
    audit_registration_event(state, realm, OperationType::Create, &client).await;
    let registration_access_token =
        match mint_registration_access_token(state, &realm.id, &client).await {
            Ok(t) => t,
            Err(resp) => return resp,
        };
    info!(realm = %realm.id, client_id = %client.client_id, "client registered");
    build_registration_response(client, registration_access_token, StatusCode::CREATED)
}

/// Mint and store a fresh registration access token for `client`.
async fn mint_registration_access_token(
    state: &Arc<ServerState>,
    realm_id: &RealmId,
    client: &Client,
) -> Result<String, Response> {
    let token = issuerd_core::utils::generate_id();
    let key = registration_access_cache_key(realm_id, client.id.as_ref());
    if let Err(e) = state.cache.set(&key, sha256_hex(&token).into_bytes(), None).await {
        error!(realm = %realm_id, error = %e, "registration access token store failed");
        return Err(registration_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "registration access token store failed",
        ));
    }
    Ok(token)
}

/// Record a client-registration lifecycle event in the admin-event audit log
/// (security invariant: administrative mutations are audited; self-registered
/// client abuse must leave a trace). The representation is never stored — it
/// would carry the client secret. The gate uses the already-loaded realm, and
/// a save failure is logged and swallowed: auditing must never fail the
/// request.
async fn audit_registration_event(
    state: &Arc<ServerState>,
    realm: &Realm,
    operation_type: OperationType,
    client: &Client,
) {
    if !realm.admin_events_enabled {
        return;
    }
    let event = AdminEvent {
        id: EventId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm.id.clone(),
        auth_realm_id: Some(realm.id.clone()),
        auth_client_id: None,
        auth_user_id: None,
        operation_type,
        resource_type: ResourceType::Client,
        // Same resource-path convention as the admin API's clients.rs.
        resource_path: format!("clients/{}", client.id),
        representation: None,
        error: None,
        event_time: chrono::Utc::now(),
    };
    if let Err(e) = state.storage.save_admin_event(&event).await {
        warn!(realm = %realm.id, error = %e, "registration admin event write failed");
    }
}

/// Render the registration/CRUD response with the secret visible.
fn build_registration_response(
    client: Client,
    registration_access_token: String,
    status: StatusCode,
) -> Response {
    let mut rep = ClientRepresentation::from(client.clone());
    rep.secret = client.secret.clone();
    (
        status,
        Json(ClientRegistrationResponse {
            client: rep,
            registration_access_token,
        }),
    )
        .into_response()
}

/// Authenticate a client-configuration request: resolve the client by its
/// public `client_id` path segment and verify the bearer registration access
/// token against the stored hash in constant time. Unknown clients, bad
/// tokens, and disabled clients are a uniform 401.
async fn authenticate_registration_access(
    state: &Arc<ServerState>,
    realm: &Realm,
    client_id: &str,
    headers: &axum::http::HeaderMap,
) -> Result<(Client, String), Response> {
    let Some(token) = extract_bearer(headers) else {
        return Err(invalid_token_response("missing registration access token"));
    };
    let client_id = issuerd_core::ClientIdentifier::new(client_id)
        .map_err(|_| invalid_token_response("invalid registration access token"))?;
    let client = state
        .storage
        .get_client_by_client_id(&realm.id, &client_id)
        .await
        .map_err(|e| {
            warn!(realm = %realm.id, error = %e, "client lookup failed");
            registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "client lookup failed",
            )
        })?
        .ok_or_else(|| invalid_token_response("invalid registration access token"))?;
    let key = registration_access_cache_key(&realm.id, client.id.as_ref());
    let stored = state.cache.get(&key).await.map_err(|e| {
        warn!(realm = %realm.id, error = %e, "registration access token lookup failed");
        registration_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "token lookup failed")
    })?;
    let provided_hash = sha256_hex(&token);
    let valid =
        stored.is_some_and(|hash| bool::from(provided_hash.as_bytes().ct_eq(hash.as_slice())));
    if !valid {
        debug!(realm = %realm.id, client_id = %client.client_id, "registration access token mismatch");
        return Err(invalid_token_response("invalid registration access token"));
    }
    // An admin-disabled client's registration access token stops working too:
    // these endpoints are not a backdoor around an admin disable. Same
    // uniform 401 — do not reveal which check failed.
    if !client.enabled {
        debug!(realm = %realm.id, client_id = %client.client_id, "registration access token presented for disabled client");
        return Err(invalid_token_response("invalid registration access token"));
    }
    Ok((client, token))
}

/// `POST /realms/{realm}/clients-registrations/default` — open registration.
/// Rate-limited per source IP; no other authentication.
#[instrument(skip(state, ip, body), fields(realm = ?realm))]
pub async fn register_open_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    body: String,
) -> Response {
    let realm = match resolve_enabled_realm(&state, realm.as_deref()).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let rate_key = format!("registration-rate:{}:{ip}", realm.id.0);
    match state
        .cache
        .increment(&rate_key, Some(std::time::Duration::from_secs(3600)))
        .await
    {
        Ok(n) if n > REGISTRATION_RATE_LIMIT_PER_HOUR => {
            return registration_error(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many client registrations from this address",
            );
        }
        Ok(_) => {}
        Err(e) => {
            warn!(realm = %realm.id, error = %e, "registration rate limiter failed");
            return registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "rate limiter unavailable",
            );
        }
    }
    let body: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("invalid JSON: {e}"),
            );
        }
    };
    register_client(&state, &realm, body).await
}

/// `POST /realms/{realm}/clients-registrations/openid-connect` —
/// registration gated by an initial access token (`Authorization: Bearer`).
#[instrument(skip(state, headers, body), fields(realm = ?realm))]
pub async fn register_token_gated_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let realm = match resolve_enabled_realm(&state, realm.as_deref()).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(token) = extract_bearer(&headers) else {
        return invalid_token_response("missing initial access token");
    };
    match verify_and_consume_initial_access_token(&state.cache, &realm.id, &token).await {
        Ok(true) => {}
        Ok(false) => {
            return invalid_token_response("invalid, expired, or exhausted initial access token")
        }
        Err(e) => {
            warn!(realm = %realm.id, error = %e, "initial access token verification failed");
            return registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "initial access token verification failed",
            );
        }
    }
    let body: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("invalid JSON: {e}"),
            );
        }
    };
    register_client(&state, &realm, body).await
}

/// `GET /realms/{realm}/clients-registrations/openid-connect/{client_id}` —
/// read the client's own configuration (RFC 7592 §3). The registration
/// access token is echoed, not rotated.
#[instrument(skip(state, headers), fields(realm = ?realm))]
pub async fn read_registered_client_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Path((_realm_segment, client_id)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Response {
    let realm = match resolve_enabled_realm(&state, realm.as_deref()).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match authenticate_registration_access(&state, &realm, &client_id, &headers).await {
        Ok((client, token)) => build_registration_response(client, token, StatusCode::OK),
        Err(resp) => resp,
    }
}

/// `PUT /realms/{realm}/clients-registrations/openid-connect/{client_id}` —
/// replace the client's configuration (RFC 7592 §3, Keycloak semantics: a
/// full representation). Rotates the registration access token.
#[instrument(skip(state, headers, body), fields(realm = ?realm))]
pub async fn update_registered_client_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Path((_realm_segment, client_id)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let realm = match resolve_enabled_realm(&state, realm.as_deref()).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (existing, _old_token) =
        match authenticate_registration_access(&state, &realm, &client_id, &headers).await {
            Ok(ok) => ok,
            Err(resp) => return resp,
        };
    let body: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("invalid JSON: {e}"),
            );
        }
    };
    // The path identifies the client; an omitted `client_id` in the body is
    // not a rename.
    let mut body = body;
    if body.is_object() && body.get("client_id").is_none_or(|v| v.is_null()) {
        body["client_id"] = serde_json::Value::String(client_id.clone());
    }
    let mut rep: ClientRepresentation = match serde_json::from_value(body) {
        Ok(rep) => rep,
        Err(e) => {
            return registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("invalid client metadata: {e}"),
            );
        }
    };
    // Same as registration (see register_client): without a
    // client-registration policy engine, mapper attachment is admin-only.
    if rep.protocol_mappers.is_some() {
        debug!(
            realm = %realm.id,
            client_id = %rep.client_id,
            "dropping caller-supplied protocol mappers on registration update"
        );
        rep.protocol_mappers = None;
    }
    if let Some(uris) = &rep.redirect_uris {
        for uri in uris {
            if let Err(e) = issuerd_core::RedirectUri::new(uri) {
                return registration_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_redirect_uri",
                    &format!("invalid redirect_uri: {e}"),
                );
            }
        }
    }
    let mut updated: Client = match rep.try_into() {
        Ok(c) => c,
        Err(e) => {
            return registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &e.to_string(),
            );
        }
    };
    updated.id = existing.id.clone();
    updated.realm_id = existing.realm_id.clone();
    // Enablement is admin-only: a registration access token must never
    // re-enable a client an admin disabled (nor disable an enabled one).
    updated.enabled = existing.enabled;
    // OIDC Core §8.1: re-validate the pairwise configuration —
    // redirect URIs may have changed under an existing sector setup.
    if let Err(e) = issuerd_core::pairwise::validate_pairwise_subject_config(
        &updated,
        state.broker_client.as_ref(),
    )
    .await
    {
        return registration_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            &e.to_string(),
        );
    }
    // A secret-less update body means "leave the secret unchanged" (the
    // representation never round-trips secrets on read; admin parity).
    if updated.secret.is_none() {
        updated.secret = existing.secret.clone();
    }
    // Scope mappings live behind the admin `/scope-mappings` sub-resources —
    // preserve them across updates (admin parity).
    updated.scope_mappings = existing.scope_mappings.clone();
    match ensure_client_id_available(
        &state.storage,
        &realm.id,
        &updated.client_id,
        Some(&updated.id),
    )
    .await
    {
        Ok(()) => {}
        Err(IssuerdError::Conflict) => {
            return registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "client_id is already registered",
            );
        }
        Err(e) => {
            warn!(realm = %realm.id, error = %e, "client_id availability check failed");
            return registration_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "client lookup failed",
            );
        }
    }
    if let Err(e) = state.storage.update_client(&realm.id, &updated).await {
        error!(realm = %realm.id, error = %e, "registered client update failed");
        return registration_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "client update failed",
        );
    }
    // The claims-cache client key embeds the public identifier: on rename the
    // OLD identifier's key is the stale one; drop the new one defensively.
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm.id,
        &updated.id,
        existing.client_id.as_ref(),
    )
    .await;
    if updated.client_id != existing.client_id {
        issuerd_cluster::invalidate::delete_best_effort(
            state.cache.as_ref(),
            &realm.id,
            &issuerd_cluster::cache_keys::client(realm.id.as_ref(), updated.client_id.as_ref()),
        )
        .await;
    }
    audit_registration_event(&state, &realm, OperationType::Update, &updated).await;
    // RFC 7592 §3 / Keycloak: the registration access token rotates on every
    // configuration update; the old one stops working immediately.
    let new_token = match mint_registration_access_token(&state, &realm.id, &updated).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    info!(realm = %realm.id, client_id = %updated.client_id, "registered client updated");
    build_registration_response(updated, new_token, StatusCode::OK)
}

/// `DELETE /realms/{realm}/clients-registrations/openid-connect/{client_id}`
/// — delete the client (RFC 7592 §3). Burns the registration access token.
#[instrument(skip(state, headers), fields(realm = ?realm))]
pub async fn delete_registered_client_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Path((_realm_segment, client_id)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Response {
    let realm = match resolve_enabled_realm(&state, realm.as_deref()).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (client, _token) =
        match authenticate_registration_access(&state, &realm, &client_id, &headers).await {
            Ok(ok) => ok,
            Err(resp) => return resp,
        };
    if let Err(e) = state.storage.delete_client(&realm.id, &client.id).await {
        error!(realm = %realm.id, error = %e, "registered client delete failed");
        return registration_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "client deletion failed",
        );
    }
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm.id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    audit_registration_event(&state, &realm, OperationType::Delete, &client).await;
    let _ = state
        .cache
        .delete(&registration_access_cache_key(&realm.id, client.id.as_ref()))
        .await;
    info!(realm = %realm.id, client_id = %client.client_id, "registered client deleted");
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_layout() {
        let realm_id = RealmId::new("realm-1").unwrap();
        assert_eq!(
            registration_access_cache_key(&realm_id, "client-1"),
            "registration-access:realm-1:client-1"
        );
    }

    #[test]
    fn bearer_extraction() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(extract_bearer(&headers).is_none());
        headers.insert(axum::http::header::AUTHORIZATION, "Bearer abc123".parse().unwrap());
        assert_eq!(extract_bearer(&headers), Some("abc123".to_string()));
        headers.insert(axum::http::header::AUTHORIZATION, "bearer abc".parse().unwrap());
        assert_eq!(extract_bearer(&headers), Some("abc".to_string()));
        headers.insert(axum::http::header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(extract_bearer(&headers).is_none());
        headers.insert(axum::http::header::AUTHORIZATION, "Bearer".parse().unwrap());
        assert!(extract_bearer(&headers).is_none());
    }

    #[test]
    fn parse_fills_missing_client_id() {
        let rep = parse_client_representation(&serde_json::json!({
            "name": "My App",
            "redirect_uris": ["http://localhost/cb"],
        }))
        .unwrap();
        assert!(!rep.client_id.is_empty());
        assert_eq!(rep.name.as_deref(), Some("My App"));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_client_representation(&serde_json::json!({"redirect_uris": "nope"})).is_err());
        assert!(parse_client_representation(&serde_json::json!(["nope"])).is_err());
    }

    #[tokio::test]
    async fn toggle_gates_registration() {
        let config = crate::config::ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        // Default realm attributes: registration disabled → 404.
        let resp = resolve_enabled_realm(&state, Some("master")).await;
        let Err(resp) = resp else {
            panic!("master realm must not have registration enabled by default");
        };
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Unknown realm is the same 404 (no existence leak).
        let resp = resolve_enabled_realm(&state, Some("no-such-realm")).await;
        let Err(resp) = resp else {
            panic!("unknown realm must 404");
        };
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Enable the toggle on master and the realm resolves.
        let mut realm = state.resolve_realm("master").await.unwrap().unwrap();
        realm
            .attributes
            .insert(Realm::DYNAMIC_CLIENT_REGISTRATION_ATTRIBUTE.to_string(), "true".to_string());
        update_realm_and_invalidate(&state, &realm).await;
        let resolved = resolve_enabled_realm(&state, Some("master")).await.unwrap();
        assert_eq!(resolved.name.as_ref(), "master");
    }

    /// In-memory state with the master realm's dynamic-registration toggle
    /// on, plus the resolved realm.
    async fn registration_state() -> (Arc<ServerState>, Realm) {
        let config = crate::config::ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let mut realm = state.resolve_realm("master").await.unwrap().unwrap();
        realm
            .attributes
            .insert(Realm::DYNAMIC_CLIENT_REGISTRATION_ATTRIBUTE.to_string(), "true".to_string());
        update_realm_and_invalidate(&state, &realm).await;
        let realm = resolve_enabled_realm(&state, Some("master")).await.unwrap();
        (state, realm)
    }

    /// Direct realm mutation bypasses the admin API's synchronous
    /// invalidation of the realm-by-name cache; drop the entry so subsequent
    /// resolutions see the new row.
    async fn update_realm_and_invalidate(state: &Arc<ServerState>, realm: &Realm) {
        state.storage.update_realm(realm).await.unwrap();
        state
            .cache
            .delete(&issuerd_cluster::cache_keys::realm_by_name(realm.name.as_ref()))
            .await
            .unwrap();
    }

    /// An audience mapper naming an unrelated resource server — the Bug 1
    /// attack payload.
    fn audience_mapper_body(client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "client_id": client_id,
            "redirect_uris": ["http://localhost/cb"],
            "protocol_mappers": [{
                "id": "mapper-1",
                "name": "borrowed-audience",
                "mapper_type": "oidc-audience-mapper",
                "config": {"included.client.audience": "some-resource-server"}
            }]
        })
    }

    /// Register a client through the shared create path; returns the stored
    /// client and its registration access token.
    async fn register_test_client(
        state: &Arc<ServerState>,
        realm: &Realm,
        body: serde_json::Value,
    ) -> (Client, String) {
        let resp = register_client(state, realm, body).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = json["registrationAccessToken"].as_str().unwrap().to_string();
        let client_id =
            issuerd_core::ClientIdentifier::new(json["client_id"].as_str().unwrap()).unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm.id, &client_id)
            .await
            .unwrap()
            .unwrap();
        (client, token)
    }

    fn bearer_headers(token: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers
            .insert(axum::http::header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        headers
    }

    fn master_path(client_id: &str) -> axum::extract::Path<(String, String)> {
        axum::extract::Path(("master".to_string(), client_id.to_string()))
    }

    async fn recorded_admin_events(
        state: &Arc<ServerState>,
        realm_id: &RealmId,
    ) -> Vec<issuerd_core::AdminEvent> {
        state
            .storage
            .query_admin_events(
                realm_id,
                &issuerd_core::AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: issuerd_core::Pagination::default(),
                },
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn registration_strips_caller_supplied_protocol_mappers() {
        let (state, realm) = registration_state().await;
        let (client, _token) =
            register_test_client(&state, &realm, audience_mapper_body("dcr-mapper-create")).await;
        // Registration succeeds, but the mapper never reaches storage.
        assert!(client.protocol_mappers.is_empty());
    }

    #[tokio::test]
    async fn registration_update_strips_caller_supplied_protocol_mappers() {
        let (state, realm) = registration_state().await;
        let (client, token) = register_test_client(
            &state,
            &realm,
            serde_json::json!({"client_id": "dcr-mapper-update"}),
        )
        .await;
        let resp = update_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-mapper-update"),
            bearer_headers(&token),
            audience_mapper_body("dcr-mapper-update").to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let stored = state.storage.get_client(&realm.id, &client.id).await.unwrap().unwrap();
        assert!(stored.protocol_mappers.is_empty());
    }

    #[tokio::test]
    async fn disabled_client_registration_token_is_rejected() {
        let (state, realm) = registration_state().await;
        let (client, token) =
            register_test_client(&state, &realm, serde_json::json!({"client_id": "dcr-disabled"}))
                .await;
        // An admin disables the client.
        let mut stored = state.storage.get_client(&realm.id, &client.id).await.unwrap().unwrap();
        stored.enabled = false;
        state.storage.update_client(&realm.id, &stored).await.unwrap();

        let resp = read_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-disabled"),
            bearer_headers(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Even a PUT trying to re-enable itself is refused before parsing.
        let resp = update_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-disabled"),
            bearer_headers(&token),
            serde_json::json!({"client_id": "dcr-disabled", "enabled": true}).to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = delete_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-disabled"),
            bearer_headers(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // The refused PUT must not have flipped enablement.
        let stored = state.storage.get_client(&realm.id, &client.id).await.unwrap().unwrap();
        assert!(!stored.enabled);
    }

    #[tokio::test]
    async fn registration_update_cannot_flip_enablement() {
        let (state, realm) = registration_state().await;
        let (client, token) =
            register_test_client(&state, &realm, serde_json::json!({"client_id": "dcr-enabled"}))
                .await;
        assert!(client.enabled);
        let resp = update_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-enabled"),
            bearer_headers(&token),
            serde_json::json!({"client_id": "dcr-enabled", "enabled": false}).to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let stored = state.storage.get_client(&realm.id, &client.id).await.unwrap().unwrap();
        assert!(stored.enabled);
    }

    #[tokio::test]
    async fn registration_lifecycle_records_admin_events() {
        let (state, realm) = registration_state().await;
        let (client, token) =
            register_test_client(&state, &realm, serde_json::json!({"client_id": "dcr-audit"}))
                .await;
        // Update (rotates the registration access token).
        let resp = update_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-audit"),
            bearer_headers(&token),
            serde_json::json!({"client_id": "dcr-audit", "description": "rotated"}).to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let rotated_token = json["registrationAccessToken"].as_str().unwrap().to_string();
        // Delete.
        let resp = delete_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-audit"),
            bearer_headers(&rotated_token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let events = recorded_admin_events(&state, &realm.id).await;
        assert_eq!(events.len(), 3);
        let expected_path = format!("clients/{}", client.id);
        for op in [
            OperationType::Create,
            OperationType::Update,
            OperationType::Delete,
        ] {
            let event = events
                .iter()
                .find(|e| e.operation_type == op)
                .unwrap_or_else(|| panic!("missing {op:?} event"));
            assert_eq!(event.resource_type, ResourceType::Client);
            assert_eq!(event.resource_path, expected_path);
            assert_eq!(event.realm_id, realm.id);
            assert_eq!(event.auth_realm_id, Some(realm.id.clone()));
            assert_eq!(event.auth_client_id, None);
            assert_eq!(event.auth_user_id, None);
            // The representation must never carry the client secret.
            assert_eq!(event.representation, None);
        }
    }

    #[tokio::test]
    async fn registration_admin_events_respect_realm_toggle() {
        let (state, mut realm) = registration_state().await;
        realm.admin_events_enabled = false;
        update_realm_and_invalidate(&state, &realm).await;
        let realm = resolve_enabled_realm(&state, Some("master")).await.unwrap();

        let (_client, token) =
            register_test_client(&state, &realm, serde_json::json!({"client_id": "dcr-no-audit"}))
                .await;
        let resp = delete_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-no-audit"),
            bearer_headers(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        assert!(recorded_admin_events(&state, &realm.id).await.is_empty());
    }
}
