// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Pushed Authorization Requests (PAR, RFC 9126).
//!
//! The PAR endpoint lets a client push the payload of an authorization
//! request directly to the server (client-authenticated, like the token
//! endpoint) and receive a `request_uri` reference in exchange. The
//! authorization endpoint then resolves that reference into the stored
//! parameters and runs the unchanged authorization pipeline on them.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use issuerd_core::{Client, EventType, IssuerdError, Realm, RealmId};
use issuerd_protocol::authorization::{AuthorizationRequest, ResponseType};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, instrument, warn};

use crate::{middleware::realm::ResolvedRealm, routes::oidc, state::ServerState};

/// URN prefix of request URIs minted by this server (RFC 9126 §2.2).
pub(crate) const PAR_REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Lifetime of a pushed authorization request (RFC 9126 suggests 5–600 s).
pub(crate) const PAR_TTL_SECS: u64 = 90;

/// Realm attribute (`"true"`) that refuses any authorization request not made
/// via PAR (RFC 9126 §4/§5). Keycloak-compatible name.
pub(crate) const REALM_REQUIRE_PAR_ATTRIBUTE: &str = "require_pushed_authorization_requests";

/// Client attribute (`"true"`) pinning a single client to PAR (RFC 9126 §6).
/// Keycloak spelling (`ParConfig.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS`).
pub(crate) const CLIENT_REQUIRE_PAR_ATTRIBUTE: &str = "require.pushed.authorization.requests";

/// A stored pushed authorization request: the full parameter set (with
/// client-authentication parameters stripped) bound to the pushing client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ParData {
    pub client_id: String,
    pub params: HashMap<String, String>,
}

/// Cache key for a pushed authorization request.
pub(crate) fn par_cache_key(realm_id: &RealmId, request_id: &str) -> String {
    format!("par:{}:{request_id}", realm_id.0)
}

/// Whether the realm refuses non-PAR authorization requests (default false).
pub(crate) fn realm_requires_par(realm: &Realm) -> bool {
    realm.attributes.get(REALM_REQUIRE_PAR_ATTRIBUTE).is_some_and(|v| v == "true")
}

/// Whether the client is pinned to PAR (default false).
pub(crate) fn client_requires_par(client: &Client) -> bool {
    client.attributes.get(CLIENT_REQUIRE_PAR_ATTRIBUTE).is_some_and(|v| v == "true")
}

/// `true` when `request_uri` is a PAR reference minted by this server (and not
/// a JAR-by-reference URL, which stays unsupported — JAR implements
/// only the `request` parameter).
pub(crate) fn is_par_request_uri(request_uri: &str) -> bool {
    request_uri.starts_with(PAR_REQUEST_URI_PREFIX)
}

// ---------------------------------------------------------------------------
// PAR endpoint
// ---------------------------------------------------------------------------

/// `POST /realms/{realm}/protocol/openid-connect/ext/par` (RFC 9126 §2).
///
/// Authenticates the client exactly like the token endpoint, validates the
/// pushed payload as an authorization request (§2.1 rule 3), stores it in the
/// distributed cache (90 s, single-use), and answers `201` with the
/// `request_uri` reference.
#[instrument(skip(state, headers, body), fields(realm = ?realm))]
pub async fn par_handler(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
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

    // Client credentials may arrive via Basic auth instead of the form body
    // (same rules as the token endpoint, RFC 9126 §2). A body `client_id`
    // next to the Basic header is legal (RFC 9126 §1.1's example); a
    // contradicting one is rejected inside `fold_basic_auth`.
    let basic_present = oidc::extract_basic_auth(&headers).is_some();
    if let Err(resp) = oidc::fold_basic_auth(&headers, &mut params) {
        return resp;
    }

    // RFC 9126 §2.1 rule 1: authenticate the client as at the token endpoint.
    let client = match oidc::authenticate_form_client(&state, &realm, &params, basic_present).await
    {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // RFC 9126 §2.1 rule 2: a pushed request MUST NOT contain request_uri.
    if params.contains_key("request_uri") {
        return par_endpoint_error(&IssuerdError::InvalidRequest(
            "request_uri must not be present in a pushed authorization request".into(),
        ));
    }

    // JAR over PAR: a pushed `request` object is validated NOW —
    // the client is authenticated and its verification material is at hand —
    // and its claims are stored instead of the JWT, so the authorize endpoint
    // consumes a plain parameter map either way.
    let mut params = if params.contains_key("request") {
        match crate::routes::jar::extract_request_object_params(&state, &realm, &client, &params)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!(realm = %realm_id, error = %e, "pushed request object validation failed");
                return par_endpoint_error(&IssuerdError::InvalidRequest(
                    "invalid request object".into(),
                ));
            }
        }
    } else {
        params
    };

    // RFC 9126 §2.1 rule 3: validate the pushed request as an authorization
    // request. It is validated again when consumed (§7.4), so a policy change
    // in the 90 s window cannot smuggle anything through.
    let auth_req = match AuthorizationRequest::parse(&params) {
        Ok(r) => r,
        Err(e) => return par_endpoint_error(&e),
    };
    if let Err(e) = auth_req.validate(&realm, &client) {
        return par_endpoint_error(&e);
    }
    // Reject unimplemented response types at push time, mirroring the
    // authorization endpoint.
    match &auth_req.response_type {
        ResponseType::Code | ResponseType::IdToken | ResponseType::CodeIdToken => {}
        _ => return par_endpoint_error(&IssuerdError::UnsupportedResponseType),
    }

    // Client-authentication parameters are relied upon only for the
    // authentication above (RFC 9126 §2.1) and are never stored.
    params.remove("client_secret");
    params.remove("client_assertion");
    params.remove("client_assertion_type");

    let request_id = issuerd_core::utils::generate_id();
    let data = ParData {
        client_id: client.client_id.to_string(),
        params,
    };
    let bytes = match serde_json::to_vec(&data) {
        Ok(b) => b,
        Err(e) => {
            error!(realm = %realm_id, error = %e, "failed to serialize pushed authorization request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(oidc::error_response(&IssuerdError::ServerError(e.to_string()))),
            )
                .into_response();
        }
    };
    if let Err(e) = state
        .cache
        .set(
            &par_cache_key(&realm_id, &request_id),
            bytes,
            Some(std::time::Duration::from_secs(PAR_TTL_SECS)),
        )
        .await
    {
        error!(realm = %realm_id, error = %e, "failed to store pushed authorization request");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(oidc::error_response(&IssuerdError::ServerError(e.to_string()))),
        )
            .into_response();
    }

    debug!(realm = %realm_id, client_id = %client.client_id, "pushed authorization request stored");
    let mut response = (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "request_uri": format!("{PAR_REQUEST_URI_PREFIX}{request_id}"),
            "expires_in": PAR_TTL_SECS,
        })),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(axum::http::header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(axum::http::header::PRAGMA, "no-cache".parse().unwrap());
    response
}

/// Token-endpoint-style error body (RFC 9126 §2.3 → RFC 6749 §5.2).
fn par_endpoint_error(error: &IssuerdError) -> Response {
    let status = StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut response = (status, Json(oidc::error_response(error))).into_response();
    let headers = response.headers_mut();
    headers.insert(axum::http::header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(axum::http::header::PRAGMA, "no-cache".parse().unwrap());
    response
}

// ---------------------------------------------------------------------------
// Authorization endpoint consumption
// ---------------------------------------------------------------------------

/// Resolve a PAR `request_uri` into the stored authorization request
/// parameters, or enforce the realm-wide require-PAR policy when the request
/// carries no `request_uri`.
///
/// Returns the (possibly replaced) parameter map plus a flag telling the
/// caller whether the request came through PAR (the per-client require-PAR
/// check needs it after client validation). Errors are rendered like the
/// other pre-validation authorization-endpoint errors (error page for
/// browsers, JSON otherwise) — no client redirect is possible at this point
/// because no redirect_uri has been validated yet.
pub(crate) async fn resolve_par_params(
    state: &Arc<ServerState>,
    realm: &Realm,
    realm_name: &str,
    ip: &std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    params: HashMap<String, String>,
) -> Result<(HashMap<String, String>, bool), Response> {
    let Some(request_uri) = params.get("request_uri").cloned() else {
        // RFC 9126 §4: realm policy may dictate PAR for every request.
        if realm_requires_par(realm) {
            let e = IssuerdError::InvalidRequest(
                "pushed authorization request required (request_uri missing)".into(),
            );
            return Err(
                par_resolution_error(state, realm, realm_name, ip, headers, &params, e).await
            );
        }
        return Ok((params, false));
    };

    macro_rules! reject {
        ($e:expr) => {
            return Err(
                par_resolution_error(state, realm, realm_name, ip, headers, &params, $e).await
            )
        };
    }

    if params.contains_key("request") {
        reject!(IssuerdError::InvalidRequest(
            "request and request_uri parameters must not be combined".into(),
        ));
    }
    if !is_par_request_uri(&request_uri) {
        // A non-PAR request_uri is JAR-by-reference — not implemented (24.7
        // implements only the `request` parameter).
        reject!(IssuerdError::RequestNotSupported);
    }
    // Only client_id may accompany a PAR reference; the stored request is the
    // complete authorization request (stricter than Keycloak, which merges —
    // recorded in tests/KEYCLOAK_DIFFS.md).
    if params.keys().any(|k| k != "client_id" && k != "request_uri") {
        reject!(IssuerdError::InvalidRequest("only client_id may accompany request_uri".into()));
    }
    let client_id = match params.get("client_id") {
        Some(c) if !c.is_empty() => c,
        _ => reject!(IssuerdError::InvalidRequest("client_id is required with request_uri".into())),
    };
    let request_id = &request_uri[PAR_REQUEST_URI_PREFIX.len()..];
    if request_id.is_empty() {
        reject!(IssuerdError::InvalidRequest("malformed request_uri".into()));
    }

    // Atomic consume: a request_uri is single-use (RFC 9126 §7.3; stricter
    // than the RFC's browser-reload allowance — FAPI requires reuse
    // rejection). Unknown, expired, and already-used references are
    // indistinguishable: all are invalid (an expired request_uri MUST be
    // rejected, §4).
    let entry = match state.cache.get_and_delete(&par_cache_key(&realm.id, request_id)).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            reject!(IssuerdError::InvalidRequest(
                "request_uri is unknown, expired, or already used".into(),
            ));
        }
        Err(e) => {
            warn!(realm = %realm.id, error = %e, "PAR cache lookup failed");
            reject!(IssuerdError::InvalidRequest("request_uri lookup failed".into()));
        }
    };
    let data: ParData = match serde_json::from_slice(&entry) {
        Ok(d) => d,
        Err(e) => {
            warn!(realm = %realm.id, error = %e, "corrupt PAR cache entry");
            reject!(IssuerdError::InvalidRequest("corrupt request_uri entry".into()));
        }
    };

    // RFC 9126 §2.2: the request_uri is bound to the client that posted it.
    if data.client_id != *client_id {
        warn!(realm = %realm.id, client_id = %client_id, "PAR request_uri presented by a different client");
        reject!(IssuerdError::InvalidRequest("request_uri was not issued to this client".into()));
    }

    debug!(realm = %realm.id, client_id = %client_id, "pushed authorization request consumed");
    Ok((data.params, true))
}

/// Render a PAR resolution failure like the other pre-validation
/// authorization-endpoint errors: an error-page redirect for browsers, a JSON
/// OAuth2 error otherwise. Also records a login-error event.
async fn par_resolution_error(
    state: &Arc<ServerState>,
    realm: &Realm,
    realm_name: &str,
    ip: &std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    params: &HashMap<String, String>,
    error: IssuerdError,
) -> Response {
    warn!(realm = %realm.id, error = %error, "PAR resolution failed");
    let mut details = HashMap::new();
    details.insert("error".to_string(), error.to_string());
    oidc::emit_oidc_event(
        state,
        &realm.id,
        EventType::LoginError,
        ip,
        params.get("client_id").and_then(|s| issuerd_core::ClientId::new(s).ok()),
        None,
        None,
        Some(error.to_string()),
        details,
    )
    .await;
    if oidc::wants_html(headers) {
        let mut redirect = url::form_urlencoded::Serializer::new(String::new());
        redirect.append_pair("error", error.oauth_error_code().as_ref());
        redirect.append_pair("realm", realm_name);
        return axum::response::Redirect::to(&format!("/login.html?{}", redirect.finish()))
            .into_response();
    }
    (StatusCode::BAD_REQUEST, Json(oidc::error_response(&error))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    #[test]
    fn par_request_uri_prefix_detection() {
        assert!(is_par_request_uri("urn:ietf:params:oauth:request_uri:abc-123"));
        assert!(!is_par_request_uri("https://example.com/request.jwt"));
        assert!(!is_par_request_uri("urn:ietf:params:oauth:other:abc"));
        // Prefix-only value: recognized as PAR, rejected later as malformed.
        assert!(is_par_request_uri("urn:ietf:params:oauth:request_uri:"));
    }

    fn make_client() -> Client {
        Client {
            id: issuerd_core::ClientId::new("client-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: issuerd_core::ClientIdentifier::new("client1").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: issuerd_core::ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: issuerd_core::Scope::empty(),
            optional_scopes: issuerd_core::Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    #[test]
    fn realm_and_client_require_par_flags() {
        let mut realm = Realm::default();
        assert!(!realm_requires_par(&realm));
        realm
            .attributes
            .insert(REALM_REQUIRE_PAR_ATTRIBUTE.to_string(), "true".to_string());
        assert!(realm_requires_par(&realm));
        realm
            .attributes
            .insert(REALM_REQUIRE_PAR_ATTRIBUTE.to_string(), "false".to_string());
        assert!(!realm_requires_par(&realm));

        let mut client = make_client();
        assert!(!client_requires_par(&client));
        client
            .attributes
            .insert(CLIENT_REQUIRE_PAR_ATTRIBUTE.to_string(), "true".to_string());
        assert!(client_requires_par(&client));
    }

    #[test]
    fn par_data_roundtrip() {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("redirect_uri".to_string(), "http://localhost:8080/cb".to_string());
        let data = ParData {
            client_id: "client1".to_string(),
            params,
        };
        let bytes = serde_json::to_vec(&data).unwrap();
        let back: ParData = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.client_id, "client1");
        assert_eq!(back.params["response_type"], "code");
    }

    #[tokio::test]
    async fn expired_request_uri_is_rejected() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm = state.resolve_realm("master").await.unwrap().unwrap();

        // Insert an entry that expires almost immediately, then consume it
        // after expiry — the resolution must fail with invalid_request.
        let request_id = "expired-entry";
        let data = ParData {
            client_id: "admin-cli".to_string(),
            params: HashMap::new(),
        };
        state
            .cache
            .set(
                &par_cache_key(&realm.id, request_id),
                serde_json::to_vec(&data).unwrap(),
                Some(std::time::Duration::from_millis(1)),
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut params = HashMap::new();
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert("request_uri".to_string(), format!("{PAR_REQUEST_URI_PREFIX}{request_id}"));
        let result = resolve_par_params(
            &state,
            &realm,
            "master",
            &std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            &axum::http::HeaderMap::new(),
            params,
        )
        .await;
        let Err(resp) = result else {
            panic!("expired request_uri must be rejected");
        };
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn realm_require_par_rejects_plain_request() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let mut realm = state.resolve_realm("master").await.unwrap().unwrap();
        realm
            .attributes
            .insert(REALM_REQUIRE_PAR_ATTRIBUTE.to_string(), "true".to_string());

        let params = HashMap::new();
        let result = resolve_par_params(
            &state,
            &realm,
            "master",
            &std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            &axum::http::HeaderMap::new(),
            params,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn plain_request_passes_through_when_par_not_required() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm = state.resolve_realm("master").await.unwrap().unwrap();

        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        let (out, used_par) = resolve_par_params(
            &state,
            &realm,
            "master",
            &std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            &axum::http::HeaderMap::new(),
            params,
        )
        .await
        .unwrap();
        assert!(!used_par);
        assert_eq!(out["response_type"], "code");
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm = state.resolve_realm("master").await.unwrap().unwrap();

        let request_id = "once-only";
        let mut stored = HashMap::new();
        stored.insert("response_type".to_string(), "code".to_string());
        let data = ParData {
            client_id: "admin-cli".to_string(),
            params: stored,
        };
        state
            .cache
            .set(
                &par_cache_key(&realm.id, request_id),
                serde_json::to_vec(&data).unwrap(),
                Some(std::time::Duration::from_secs(PAR_TTL_SECS)),
            )
            .await
            .unwrap();

        let make_params = || {
            let mut p = HashMap::new();
            p.insert("client_id".to_string(), "admin-cli".to_string());
            p.insert("request_uri".to_string(), format!("{PAR_REQUEST_URI_PREFIX}{request_id}"));
            p
        };
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let first = resolve_par_params(
            &state,
            &realm,
            "master",
            &ip,
            &axum::http::HeaderMap::new(),
            make_params(),
        )
        .await;
        let (stored_params, used_par) = first.unwrap();
        assert!(used_par);
        assert_eq!(stored_params["response_type"], "code");

        let second = resolve_par_params(
            &state,
            &realm,
            "master",
            &ip,
            &axum::http::HeaderMap::new(),
            make_params(),
        )
        .await;
        assert!(second.is_err());
    }

    #[tokio::test]
    async fn client_id_mismatch_is_rejected() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm = state.resolve_realm("master").await.unwrap().unwrap();

        let request_id = "bound-to-other-client";
        let data = ParData {
            client_id: "other-client".to_string(),
            params: HashMap::new(),
        };
        state
            .cache
            .set(
                &par_cache_key(&realm.id, request_id),
                serde_json::to_vec(&data).unwrap(),
                Some(std::time::Duration::from_secs(PAR_TTL_SECS)),
            )
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert("request_uri".to_string(), format!("{PAR_REQUEST_URI_PREFIX}{request_id}"));
        let result = resolve_par_params(
            &state,
            &realm,
            "master",
            &std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            &axum::http::HeaderMap::new(),
            params,
        )
        .await;
        assert!(result.is_err());
    }
}
