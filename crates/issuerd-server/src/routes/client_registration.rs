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
//! indistinguishable afterwards. The open endpoint additionally vets the
//! payload first (`enforce_open_registration_policy`): caller-controlled JWKS
//! and logout-URI attributes are stripped, service accounts are forced off,
//! redirect-URI schemes are allowlisted, and the `"*"` web origin is
//! rejected. Open-endpoint clients carry the `dcr.policy=open` marker
//! attribute, so an RFC 7592 update with the registration access token
//! re-applies the same policy (and re-stamps the marker) — the token can
//! never resurrect a stripped attribute. The token-gated path trusts its
//! admin-minted initial access token and honors every field.
//!
//! RFC 7591 request metadata (`client_name`, `grant_types`, `response_types`,
//! `token_endpoint_auth_method`, `jwks`/`jwks_uri`, the logout metadata, …)
//! is accepted alongside the Keycloak shape: [`translate_rfc7591_request`]
//! folds it into the `ClientRepresentation` shape before parsing, so both
//! spellings of a registration land in the same model (the RFC fields map
//! onto client attributes — see [`crate::client_metadata`]). Responses carry
//! the RFC 7591 §3.2.1 / RFC 7592 fields (`registration_access_token`,
//! `registration_client_uri`, `client_id_issued_at`,
//! `client_secret_expires_at`) next to the Keycloak spelling, plus an echo of
//! every registered metadata field.

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
    client_metadata,
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
/// this is the one channel that returns it), the registration access token
/// under both spellings (Keycloak's `registrationAccessToken` and RFC 7591
/// §3.2.1's `registration_access_token`), the RFC 7592
/// `registration_client_uri`, and the RFC 7591 metadata echo. Only fields
/// that are actually set on the client are echoed.
#[derive(Debug, Serialize)]
struct ClientRegistrationResponse {
    #[serde(flatten)]
    client: ClientRepresentation,
    #[serde(rename = "registrationAccessToken")]
    registration_access_token: String,
    /// RFC 7591 §3.2.1 spelling — same value as `registrationAccessToken`.
    #[serde(rename = "registration_access_token")]
    registration_access_token_rfc: String,
    /// RFC 7592 §3: the client configuration URL (the management endpoint).
    registration_client_uri: String,
    /// RFC 7591 §3.2.1: unix seconds at which the client identifier was
    /// issued (DCR creation stamp; `None` for clients that predate it).
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id_issued_at: Option<i64>,
    /// RFC 7591 §3.2.1 spelling of the client secret (alongside Keycloak's
    /// `secret`); both are present only when the client has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    /// RFC 7591 §3.2.1: `0` — issued secrets never expire.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret_expires_at: Option<i64>,
    // --- RFC 7591 §2 metadata echo (stored client attributes) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    /// OIDC registration §2: defaults to `["authorization_code", "implicit"]`.
    grant_types: Vec<String>,
    /// OIDC registration §2: defaults to `["code"]`.
    response_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sector_identifier_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    initiate_login_uri: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    post_logout_redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frontchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frontchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token_signed_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userinfo_signed_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_object_signing_alg: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_uris: Vec<String>,
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
#[allow(clippy::result_large_err)]
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

// ---------------------------------------------------------------------------
// RFC 7591 request metadata
// ---------------------------------------------------------------------------

/// RFC 7591 request field names the translation layer consumes. A body
/// carrying none of them takes the pre-existing (Keycloak-shaped) path
/// bit-for-bit.
const RFC7591_REQUEST_FIELDS: [&str; 23] = [
    "client_name",
    "grant_types",
    "response_types",
    "token_endpoint_auth_method",
    "scope",
    "subject_type",
    "sector_identifier_uri",
    "jwks",
    "jwks_uri",
    "initiate_login_uri",
    "post_logout_redirect_uris",
    "frontchannel_logout_uri",
    "backchannel_logout_uri",
    "frontchannel_logout_session_required",
    "backchannel_logout_session_required",
    "logo_uri",
    "policy_uri",
    "tos_uri",
    "id_token_signed_response_alg",
    "userinfo_signed_response_alg",
    "request_object_signing_alg",
    "request_uris",
    "client_secret",
];

/// RFC 7591 `grant_types` values Issuerd accepts at registration
/// (bookkeeping — the token endpoint's own grant checks stay the runtime
/// authority).
const RFC7591_GRANT_TYPES: [&str; 8] = [
    "authorization_code",
    "implicit",
    "refresh_token",
    "client_credentials",
    "password",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:openid:params:grant-type:ciba",
];

/// RFC 7591 `token_endpoint_auth_method` values Issuerd implements.
const RFC7591_TOKEN_ENDPOINT_AUTH_METHODS: [&str; 5] = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "none",
];

/// `invalid_client_metadata` 400 (RFC 7591 §3.2.2).
#[allow(clippy::result_large_err)]
fn invalid_metadata(description: String) -> Response {
    registration_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", &description)
}

/// `invalid_redirect_uri` 400 (RFC 7591 §3.2.2).
#[allow(clippy::result_large_err)]
fn invalid_redirect_uri(description: String) -> Response {
    registration_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", &description)
}

/// Insert `key = value` into the `attributes` object of a
/// ClientRepresentation-shaped JSON body (created when absent). An existing
/// attribute of the same key is left untouched: a caller that mixes the
/// Keycloak spelling (explicit `attributes`) and the RFC spelling of one
/// concept gets the Keycloak value, matching the `name`-over-`client_name`
/// precedence.
#[allow(clippy::result_large_err)]
fn insert_body_attribute(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: serde_json::Value,
) -> Result<(), Response> {
    let attributes = obj
        .entry("attributes".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(attributes) = attributes.as_object_mut() else {
        return Err(invalid_metadata("`attributes` must be an object".to_string()));
    };
    attributes.entry(key.to_string()).or_insert(value);
    Ok(())
}

/// An RFC 7591 URL metadata field that must be an https URL
/// (`initiate_login_uri`, `jwks_uri`, the logout URIs, `logo_uri`,
/// `policy_uri`, `tos_uri`).
#[allow(clippy::result_large_err)]
fn require_https_uri(field: &str, value: &str) -> Result<(), Response> {
    match url::Url::parse(value) {
        Ok(parsed) if parsed.scheme() == "https" => Ok(()),
        _ => Err(invalid_metadata(format!("{field} must be an https URL: {value:?}"))),
    }
}

/// A post-logout redirect target must be a syntactically valid URL
/// (`invalid_redirect_uri` otherwise) and use https, loopback http, or a
/// custom (non-scriptable) scheme (`invalid_client_metadata` otherwise) —
/// the same scheme rules as the open-registration redirect-URI policy.
#[allow(clippy::result_large_err)]
fn validate_post_logout_redirect_uri(uri: &str) -> Result<(), Response> {
    if uri.chars().any(char::is_control) {
        return Err(invalid_redirect_uri(format!(
            "invalid post_logout_redirect_uris entry {uri:?}: control characters are not allowed"
        )));
    }
    let parsed = url::Url::parse(uri).map_err(|e| {
        invalid_redirect_uri(format!("invalid post_logout_redirect_uris entry {uri:?}: {e}"))
    })?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_redirect_host(&parsed) => Ok(()),
        "http" => Err(invalid_metadata(format!(
            "post_logout_redirect_uris entry {uri:?} is not allowed: \
             plain http is only accepted for loopback hosts"
        ))),
        "javascript" | "data" | "vbscript" => Err(invalid_metadata(format!(
            "post_logout_redirect_uris entry {uri:?} is not allowed: \
             the {} scheme is forbidden",
            parsed.scheme()
        ))),
        // Custom schemes (`myapp://…`) — OIDC native-app practice.
        _ => Ok(()),
    }
}

/// Registration redirect_uris must be syntactically valid URLs
/// (`RedirectUri::new`) and — per RFC 6749 §3.1.2 / OIDC Core §3.1.2 — must
/// NOT carry a fragment component (the redirection endpoint's response must
/// never inherit one). Rejected with `invalid_redirect_uri`.
#[allow(clippy::result_large_err)]
fn validate_registration_redirect_uri(uri: &str) -> Result<(), Response> {
    let parsed = issuerd_core::RedirectUri::new(uri).map_err(|e| {
        registration_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!("invalid redirect_uri: {e}"),
        )
    })?;
    if url::Url::parse(parsed.as_str()).is_ok_and(|u| u.fragment().is_some()) {
        return Err(registration_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uri must not contain a fragment component",
        ));
    }
    Ok(())
}

/// `id_token_signed_response_alg` / `userinfo_signed_response_alg` must name
/// an asymmetric JWS algorithm Issuerd signs tokens with; `none` and the
/// symmetric HS* family are rejected outright.
#[allow(clippy::result_large_err)]
fn validate_signed_response_alg(field: &str, value: &str) -> Result<(), Response> {
    match value.parse::<issuerd_core::Algorithm>() {
        Ok(alg) if !alg.is_symmetric() => Ok(()),
        _ => Err(invalid_metadata(format!(
            "{field} value {value:?} is not an algorithm Issuerd signs tokens with"
        ))),
    }
}

/// Fold RFC 7591 request metadata into the `ClientRepresentation` shape, in
/// place on the raw JSON body. Runs before parsing — and therefore before
/// `enforce_open_registration_policy`, so RFC-spelled JWKS/logout attributes
/// on the open endpoint are stripped by the existing policy exactly like
/// Keycloak-spelled ones. Validation failures map to the RFC 7591 §3.2.2
/// error codes.
#[allow(clippy::result_large_err)]
fn translate_rfc7591_request(mut body: serde_json::Value) -> Result<serde_json::Value, Response> {
    {
        let Some(obj) = body.as_object() else {
            return Ok(body);
        };
        if !obj.keys().any(|k| RFC7591_REQUEST_FIELDS.contains(&k.as_str())) {
            return Ok(body);
        }
    }
    let obj = body.as_object_mut().expect("checked to be an object above");

    // client_name → name (the Keycloak `name` wins when both are present).
    if let Some(value) = obj.remove("client_name") {
        let Some(name) = value.as_str() else {
            return Err(invalid_metadata("client_name must be a string".to_string()));
        };
        obj.entry("name".to_string())
            .or_insert(serde_json::Value::String(name.to_string()));
    }

    // grant_types: validated and stored as registration bookkeeping
    // (`dcr.grant_types`, JSON array).
    if let Some(value) = obj.remove("grant_types") {
        let Some(list) = value.as_array() else {
            return Err(invalid_metadata(
                "grant_types must be an array of grant-type strings".to_string(),
            ));
        };
        let mut grants = Vec::with_capacity(list.len());
        for entry in list {
            let Some(grant) = entry.as_str() else {
                return Err(invalid_metadata("grant_types entries must be strings".to_string()));
            };
            if !RFC7591_GRANT_TYPES.contains(&grant) {
                return Err(invalid_metadata(format!(
                    "grant_types value {grant:?} is not supported"
                )));
            }
            grants.push(grant);
        }
        // Re-serializing a Vec<&str> of validated strings cannot fail.
        let encoded = serde_json::to_string(&grants).expect("grant list serialization");
        insert_body_attribute(
            obj,
            client_metadata::ATTR_DCR_GRANT_TYPES,
            serde_json::Value::String(encoded),
        )?;
    }

    // response_types: validated and stored as the client's response-type
    // allowlist (JSON array — the space-separated legacy encoding cannot
    // represent multi-token combinations like `code id_token`).
    if let Some(value) = obj.remove("response_types") {
        let Some(list) = value.as_array() else {
            return Err(invalid_metadata(
                "response_types must be an array of response-type strings".to_string(),
            ));
        };
        let mut types: Vec<&'static str> = Vec::with_capacity(list.len());
        for entry in list {
            let Some(response_type) = entry.as_str() else {
                return Err(invalid_metadata("response_types entries must be strings".to_string()));
            };
            // Both token/id_token orderings parse (normalized to the
            // canonical `as_str` spelling — discovery advertises both). Bare
            // `token` parses but is OAuth2-only: the authorization endpoint
            // always rejects it, so it is not registrable metadata.
            let parsed = response_type
                .parse::<issuerd_protocol::authorization::ResponseType>()
                .map_err(|_| {
                    invalid_metadata(format!(
                        "response_types value {response_type:?} is not a supported OIDC response type"
                    ))
                })?;
            if parsed == issuerd_protocol::authorization::ResponseType::Token {
                return Err(invalid_metadata(
                    "response_types value \"token\" is OAuth2-only and never accepted by the authorization endpoint"
                        .to_string(),
                ));
            }
            types.push(parsed.as_str());
        }
        let encoded = serde_json::to_string(&types).expect("response type list serialization");
        insert_body_attribute(
            obj,
            issuerd_core::Client::RESPONSE_TYPES_ATTRIBUTE,
            serde_json::Value::String(encoded),
        )?;
    }

    // token_endpoint_auth_method: stored + mapped onto the Keycloak-shaped
    // authenticator fields (`none` forces a public client).
    if let Some(value) = obj.remove("token_endpoint_auth_method") {
        let Some(method) = value.as_str() else {
            return Err(invalid_metadata(
                "token_endpoint_auth_method must be a string".to_string(),
            ));
        };
        if !RFC7591_TOKEN_ENDPOINT_AUTH_METHODS.contains(&method) {
            return Err(invalid_metadata(format!(
                "token_endpoint_auth_method value {method:?} is not supported"
            )));
        }
        insert_body_attribute(
            obj,
            client_metadata::ATTR_TOKEN_ENDPOINT_AUTH_METHOD,
            serde_json::Value::String(method.to_string()),
        )?;
        let authenticator = match method {
            "client_secret_basic" | "client_secret_post" => Some("client-secret"),
            "client_secret_jwt" => Some("client-secret-jwt"),
            "private_key_jwt" => Some("client-jwt"),
            _ => None,
        };
        match authenticator {
            Some(authenticator) => {
                obj.entry("client_authenticator_type".to_string())
                    .or_insert(serde_json::Value::String(authenticator.to_string()));
            }
            // `none`: no credential — force the public-client shape so no
            // secret is generated for it.
            None => {
                obj.insert("public_client".to_string(), serde_json::Value::Bool(true));
            }
        }
    }

    // scope (space-separated string): merged into default_scopes.
    if let Some(value) = obj.remove("scope") {
        let Some(scope) = value.as_str() else {
            return Err(invalid_metadata("scope must be a space-separated string".to_string()));
        };
        let requested: Vec<&str> = scope.split_whitespace().collect();
        if !requested.is_empty() {
            let entry = obj
                .entry("default_scopes".to_string())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            let Some(existing) = entry.as_array_mut() else {
                return Err(invalid_metadata(
                    "default_scopes must be an array of strings".to_string(),
                ));
            };
            for scope in requested {
                if !existing.iter().any(|v| v.as_str() == Some(scope)) {
                    existing.push(serde_json::Value::String(scope.to_string()));
                }
            }
        }
    }

    // subject_type: `public` (default) or `pairwise`.
    if let Some(value) = obj.remove("subject_type") {
        let Some(subject_type) = value.as_str() else {
            return Err(invalid_metadata("subject_type must be a string".to_string()));
        };
        if subject_type != "public" && subject_type != "pairwise" {
            return Err(invalid_metadata(format!(
                "subject_type value {subject_type:?} must be \"public\" or \"pairwise\""
            )));
        }
        insert_body_attribute(
            obj,
            issuerd_core::Client::SUBJECT_TYPE_ATTRIBUTE,
            serde_json::Value::String(subject_type.to_string()),
        )?;
    }

    // sector_identifier_uri: stored; the pairwise validation later in the
    // pipeline fetches and checks it (and fails the registration with
    // `invalid_client_metadata` when it cannot).
    if let Some(value) = obj.remove("sector_identifier_uri") {
        let Some(uri) = value.as_str() else {
            return Err(invalid_metadata("sector_identifier_uri must be a string".to_string()));
        };
        insert_body_attribute(
            obj,
            issuerd_core::Client::SECTOR_IDENTIFIER_URI_ATTRIBUTE,
            serde_json::Value::String(uri.to_string()),
        )?;
    }

    // jwks (inline JWK Set) / jwks_uri: the client's `private_key_jwt`
    // key material. Inline wins when both are present.
    let jwks_inline = obj.remove("jwks");
    let jwks_uri = obj.remove("jwks_uri");
    if let Some(value) = jwks_inline {
        if !value.is_object() {
            return Err(invalid_metadata("jwks must be a JSON object (a JWK Set)".to_string()));
        }
        let compact = serde_json::to_string(&value).expect("jwks re-serialization");
        insert_body_attribute(
            obj,
            crate::client_assertion::ATTR_USE_JWKS_STRING,
            serde_json::Value::String("true".to_string()),
        )?;
        insert_body_attribute(
            obj,
            crate::client_assertion::ATTR_JWKS_STRING,
            serde_json::Value::String(compact),
        )?;
    } else if let Some(value) = jwks_uri {
        let Some(uri) = value.as_str() else {
            return Err(invalid_metadata("jwks_uri must be a string".to_string()));
        };
        require_https_uri("jwks_uri", uri)?;
        insert_body_attribute(
            obj,
            crate::client_assertion::ATTR_USE_JWKS_URL,
            serde_json::Value::String("true".to_string()),
        )?;
        insert_body_attribute(
            obj,
            crate::client_assertion::ATTR_JWKS_URL,
            serde_json::Value::String(uri.to_string()),
        )?;
    }

    // initiate_login_uri (OIDC Third-Party-Initiated Login): https only.
    if let Some(value) = obj.remove("initiate_login_uri") {
        let Some(uri) = value.as_str() else {
            return Err(invalid_metadata("initiate_login_uri must be a string".to_string()));
        };
        require_https_uri("initiate_login_uri", uri)?;
        insert_body_attribute(
            obj,
            client_metadata::ATTR_INITIATE_LOGIN_URI,
            serde_json::Value::String(uri.to_string()),
        )?;
    }

    // post_logout_redirect_uris: the per-client list the logout endpoint
    // validates `post_logout_redirect_uri` against (stored as JSON).
    if let Some(value) = obj.remove("post_logout_redirect_uris") {
        let Some(list) = value.as_array() else {
            return Err(invalid_metadata(
                "post_logout_redirect_uris must be an array of URI strings".to_string(),
            ));
        };
        let mut uris = Vec::with_capacity(list.len());
        for entry in list {
            let Some(uri) = entry.as_str() else {
                return Err(invalid_metadata(
                    "post_logout_redirect_uris entries must be strings".to_string(),
                ));
            };
            validate_post_logout_redirect_uri(uri)?;
            uris.push(uri.to_string());
        }
        let encoded = serde_json::to_string(&uris).expect("uri list serialization");
        insert_body_attribute(
            obj,
            client_metadata::ATTR_POST_LOGOUT_REDIRECT_URIS,
            serde_json::Value::String(encoded),
        )?;
    }

    // front-/back-channel logout URIs: https only.
    for (field, attribute) in [
        (
            "frontchannel_logout_uri",
            crate::routes::logout::CLIENT_ATTR_FRONTCHANNEL_LOGOUT_URI,
        ),
        (
            "backchannel_logout_uri",
            crate::routes::logout::CLIENT_ATTR_BACKCHANNEL_LOGOUT_URI,
        ),
    ] {
        if let Some(value) = obj.remove(field) {
            let Some(uri) = value.as_str() else {
                return Err(invalid_metadata(format!("{field} must be a string")));
            };
            require_https_uri(field, uri)?;
            insert_body_attribute(obj, attribute, serde_json::Value::String(uri.to_string()))?;
        }
    }

    // The logout `*_session_required` flags: JSON booleans stored as
    // "true"/"false" attribute strings.
    for (field, attribute) in [
        (
            "frontchannel_logout_session_required",
            client_metadata::ATTR_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED,
        ),
        (
            "backchannel_logout_session_required",
            client_metadata::ATTR_BACKCHANNEL_LOGOUT_SESSION_REQUIRED,
        ),
    ] {
        if let Some(value) = obj.remove(field) {
            let Some(required) = value.as_bool() else {
                return Err(invalid_metadata(format!("{field} must be a boolean")));
            };
            insert_body_attribute(obj, attribute, serde_json::Value::String(required.to_string()))?;
        }
    }

    // logo/policy/tos URLs: https only.
    for (field, attribute) in [
        ("logo_uri", client_metadata::ATTR_LOGO_URI),
        ("policy_uri", client_metadata::ATTR_POLICY_URI),
        ("tos_uri", client_metadata::ATTR_TOS_URI),
    ] {
        if let Some(value) = obj.remove(field) {
            let Some(uri) = value.as_str() else {
                return Err(invalid_metadata(format!("{field} must be a string")));
            };
            require_https_uri(field, uri)?;
            insert_body_attribute(obj, attribute, serde_json::Value::String(uri.to_string()))?;
        }
    }

    // Signed-response algorithm preferences: stored and echoed (signing
    // enforcement is a separate feature).
    for (field, attribute) in [
        (
            "id_token_signed_response_alg",
            client_metadata::ATTR_ID_TOKEN_SIGNED_RESPONSE_ALG,
        ),
        (
            "userinfo_signed_response_alg",
            client_metadata::ATTR_USERINFO_SIGNED_RESPONSE_ALG,
        ),
        ("request_object_signing_alg", client_metadata::ATTR_REQUEST_OBJECT_SIGNING_ALG),
    ] {
        if let Some(value) = obj.remove(field) {
            let Some(alg) = value.as_str() else {
                return Err(invalid_metadata(format!("{field} must be a string")));
            };
            validate_signed_response_alg(field, alg)?;
            insert_body_attribute(obj, attribute, serde_json::Value::String(alg.to_string()))?;
        }
    }

    // request_uris (OIDC registration; JAR-by-reference): the URIs the
    // authorization endpoint may fetch a request object from. https-only
    // (the SSRF-guarded fetch never dials anything else), stored as JSON.
    if let Some(value) = obj.remove("request_uris") {
        let Some(list) = value.as_array() else {
            return Err(invalid_metadata(
                "request_uris must be an array of URI strings".to_string(),
            ));
        };
        let mut uris = Vec::with_capacity(list.len());
        for entry in list {
            let Some(uri) = entry.as_str() else {
                return Err(invalid_metadata("request_uris entries must be strings".to_string()));
            };
            require_https_uri("request_uris", uri)?;
            uris.push(uri.to_string());
        }
        let encoded = serde_json::to_string(&uris).expect("uri list serialization");
        insert_body_attribute(
            obj,
            client_metadata::ATTR_REQUEST_URIS,
            serde_json::Value::String(encoded),
        )?;
    }

    // client_secret: the registrant-suggested secret (RFC 7591 allows the
    // server to override it; Issuerd honors it, keeping auto-generation when
    // absent). The Keycloak-shaped `secret` wins when both are sent.
    if let Some(value) = obj.remove("client_secret") {
        let Some(secret) = value.as_str() else {
            return Err(invalid_metadata("client_secret must be a string".to_string()));
        };
        obj.entry("secret".to_string())
            .or_insert(serde_json::Value::String(secret.to_string()));
    }

    Ok(body)
}

/// Payload vetting for registration creates. The open (unauthenticated)
/// endpoint applies [`RegistrationPolicy::Open`]; the initial-access-token
/// gated endpoint trusts the caller (an admin minted the token) and keeps
/// honoring every field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationPolicy {
    Open,
    Trusted,
}

/// Client attribute keys an anonymous registrant must never set, stripped by
/// the open-registration policy. The JWKS quartet selects the client's
/// `private_key_jwt` key material: `jwks.url` points the token endpoint's
/// outbound JWKS fetch at a caller-controlled URL, and the inline
/// `jwks.string` would make the registrant its own key authority — anonymous
/// clients authenticate with `client_secret`. The logout URIs are
/// server-initiated POST/redirect targets dispatched at session teardown, and
/// `request_uris` names URLs the authorization endpoint fetches (all
/// SSRF-guarded fetches, but the open endpoint takes no caller-controlled
/// fetch targets).
const OPEN_REGISTRATION_STRIPPED_ATTRIBUTES: [&str; 8] = [
    issuerd_core::Client::ADMIN_API_ACCESS_ATTRIBUTE,
    crate::client_assertion::ATTR_JWKS_URL,
    crate::client_assertion::ATTR_USE_JWKS_URL,
    crate::client_assertion::ATTR_JWKS_STRING,
    crate::client_assertion::ATTR_USE_JWKS_STRING,
    crate::routes::logout::CLIENT_ATTR_BACKCHANNEL_LOGOUT_URI,
    crate::routes::logout::CLIENT_ATTR_FRONTCHANNEL_LOGOUT_URI,
    client_metadata::ATTR_REQUEST_URIS,
];

/// Apply the payload policy of the open (unauthenticated) client
/// registration endpoint to a parsed representation.
///
/// THIS IS THE CLIENT-REGISTRATION POLICY FOR THE ANONYMOUS ENDPOINT
/// (`POST /realms/{realm}/clients-registrations/default`). Keycloak gates
/// the same decisions behind its ClientRegistrationPolicy SPI; this is
/// Issuerd's fixed equivalent. Write-path only: clients that already exist
/// are unaffected, and the token-gated and admin registration paths keep
/// honoring every field.
///
/// - the attributes in [`OPEN_REGISTRATION_STRIPPED_ATTRIBUTES`] are
///   STRIPPED — and a logout-URI attribute spelling a scriptable or
///   plain-remote-http scheme is REJECTED outright
///   ([`validate_open_registration_logout_uri`]);
/// - `service_accounts_enabled` is FORCED to false (Keycloak anonymous
///   registration parity: no service account without admin approval);
/// - `redirect_uris` are scheme-vetted (see
///   [`validate_open_registration_redirect_uri`]); a forbidden URI REJECTS
///   the whole registration with `invalid_redirect_uri` naming the URI — no
///   partial filtering that would silently register a different client than
///   the caller sent;
/// - `web_origins` REJECTS the literal `"*"` (CORS wildcard) with
///   `invalid_client_metadata`.
///
/// Runs on open-endpoint creates AND on RFC 7592 updates of clients carrying
/// the `dcr.policy=open` marker ([`client_metadata::ATTR_DCR_POLICY`]), so a
/// registration access token can never resurrect a stripped attribute.
#[allow(clippy::result_large_err)]
fn enforce_open_registration_policy(
    realm_id: &RealmId,
    rep: &mut ClientRepresentation,
) -> Result<(), Response> {
    if let Some(attributes) = &mut rep.attributes {
        // The logout URIs arrive free-form through the Keycloak-shaped
        // `attributes` map (the RFC-spelled top-level fields are
        // https-validated during translation). They are stripped below
        // either way, but a scriptable or plain-remote-http spelling is
        // rejected loudly instead of silently dropped — the same scheme
        // rules as `validate_post_logout_redirect_uri`.
        for key in [
            crate::routes::logout::CLIENT_ATTR_FRONTCHANNEL_LOGOUT_URI,
            crate::routes::logout::CLIENT_ATTR_BACKCHANNEL_LOGOUT_URI,
        ] {
            if let Some(uri) = attributes.get(key) {
                validate_open_registration_logout_uri(key, uri)?;
            }
        }
        let before = attributes.len();
        for key in OPEN_REGISTRATION_STRIPPED_ATTRIBUTES {
            attributes.remove(key);
        }
        if attributes.len() != before {
            debug!(
                realm = %realm_id,
                client_id = %rep.client_id,
                "stripped JWKS/logout attributes on open registration"
            );
        }
    }
    if rep.service_accounts_enabled == Some(true) {
        debug!(
            realm = %realm_id,
            client_id = %rep.client_id,
            "forcing service_accounts_enabled off on open registration"
        );
    }
    rep.service_accounts_enabled = Some(false);
    if let Some(uris) = &rep.redirect_uris {
        for uri in uris {
            validate_open_registration_redirect_uri(uri)?;
        }
    }
    if let Some(origins) = &rep.web_origins {
        if origins.iter().any(|origin| origin == "*") {
            return Err(registration_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "web_origins value \"*\" is not allowed on open registration",
            ));
        }
    }
    Ok(())
}

/// The open-registration redirect-URI scheme allowlist. `https` is always
/// allowed; plain `http` only for loopback/localhost hosts (local
/// development and the RFC 8252 native-app loopback flow); custom schemes
/// (`myapp://…`) are allowed as OIDC native-app practice requires.
/// `javascript:`, `data:` and `vbscript:` are REJECTED explicitly — they
/// parse as valid URLs (so `RedirectUri::new` accepts them), but a stored
/// scriptable scheme would execute in the end user's browser whenever the
/// authorization endpoint redirects to it.
#[allow(clippy::result_large_err)]
fn validate_open_registration_redirect_uri(uri: &str) -> Result<(), Response> {
    let reject = |description: String| {
        registration_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", &description)
    };
    let parsed = match url::Url::parse(uri) {
        Ok(parsed) => parsed,
        Err(e) => return Err(reject(format!("invalid redirect_uri {uri:?}: {e}"))),
    };
    // `Url::parse` ASCII-lowercases the scheme, so `JAVASCRIPT:…` arrives
    // here as `javascript`.
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_redirect_host(&parsed) => Ok(()),
        "http" => Err(reject(format!(
            "redirect_uri {uri:?} is not allowed on open registration: \
             plain http is only accepted for loopback hosts"
        ))),
        "javascript" | "data" | "vbscript" => Err(reject(format!(
            "redirect_uri {uri:?} is not allowed on open registration: \
             the {} scheme is forbidden",
            parsed.scheme()
        ))),
        // Custom schemes (`myapp://…`) — OIDC native-app practice.
        _ => Ok(()),
    }
}

/// Whether `url`'s host is `localhost` or a loopback IP literal — the only
/// hosts allowed on plain-http redirect URIs from open registration.
fn is_loopback_redirect_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// The open-policy scheme check for the logout-URI attributes (the same
/// acceptance shape as [`validate_post_logout_redirect_uri`]): https,
/// loopback http, and custom (non-scriptable) schemes pass;
/// `javascript:`/`data:`/`vbscript:` and non-loopback plain http are
/// rejected with `invalid_client_metadata`. The open policy strips the
/// attributes regardless — this makes the dangerous spellings loud instead
/// of silently dropped.
#[allow(clippy::result_large_err)]
fn validate_open_registration_logout_uri(field: &str, uri: &str) -> Result<(), Response> {
    match url::Url::parse(uri) {
        Ok(parsed) => match parsed.scheme() {
            "https" => Ok(()),
            "http" if is_loopback_redirect_host(&parsed) => Ok(()),
            "http" => Err(invalid_metadata(format!(
                "{field} {uri:?} is not allowed on open registration: \
                 plain http is only accepted for loopback hosts"
            ))),
            "javascript" | "data" | "vbscript" => Err(invalid_metadata(format!(
                "{field} {uri:?} is not allowed on open registration: \
                 the {} scheme is forbidden",
                parsed.scheme()
            ))),
            // Custom schemes (`myapp://…`) — OIDC native-app practice.
            _ => Ok(()),
        },
        Err(e) => Err(invalid_metadata(format!("{field} {uri:?} is not a valid URL: {e}"))),
    }
}

/// Create the client described by `body` in `realm`, mint its registration
/// access token, and render the 201 response. Shared by the open and the
/// token-gated registration endpoints; `policy` selects how much of the
/// caller-supplied payload is honored (see [`RegistrationPolicy`]).
async fn register_client(
    state: &Arc<ServerState>,
    realm: &Realm,
    body: serde_json::Value,
    policy: RegistrationPolicy,
) -> Response {
    // RFC 7591 metadata is folded into the ClientRepresentation shape first,
    // so the open-registration policy below strips what it must strip from
    // RFC-spelled input exactly like Keycloak-spelled input.
    let body = match translate_rfc7591_request(body) {
        Ok(body) => body,
        Err(resp) => return resp,
    };
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
    // The client-registration policy for the anonymous endpoint lives in
    // `enforce_open_registration_policy` — it strips/forces/rejects the
    // fields an unauthenticated registrant must not control. The
    // token-gated path is Trusted and skips it entirely.
    if policy == RegistrationPolicy::Open {
        if let Err(resp) = enforce_open_registration_policy(&realm.id, &mut rep) {
            return resp;
        }
    }
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
            if let Err(resp) = validate_registration_redirect_uri(uri) {
                return resp;
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
    // Stamp the DCR creation time (RFC 7591 §3.2.1 `client_id_issued_at`);
    // updates carry the original forward.
    client
        .attributes
        .entry(client_metadata::ATTR_DCR_CLIENT_ID_ISSUED_AT.to_string())
        .or_insert_with(|| issuerd_core::utils::now_secs().to_string());
    // Clients created through the open endpoint carry the policy marker:
    // RFC 7592 updates re-apply the open payload policy (see
    // update_registered_client_handler). Stamped post-conversion so a
    // caller-supplied `dcr.policy` attribute never survives.
    if policy == RegistrationPolicy::Open {
        client.attributes.insert(
            client_metadata::ATTR_DCR_POLICY.to_string(),
            client_metadata::DCR_POLICY_OPEN.to_string(),
        );
    }
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
    build_registration_response(
        &state.config.issuer_url,
        realm.name.as_str(),
        client,
        registration_access_token,
        StatusCode::CREATED,
    )
}

/// Mint and store a fresh registration access token for `client`.
#[allow(clippy::result_large_err)]
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
    issuer_base_url: &str,
    realm_name: &str,
    client: Client,
    registration_access_token: String,
    status: StatusCode,
) -> Response {
    let secret = client.secret.clone();
    let mut rep = ClientRepresentation::from(client.clone());
    rep.secret = secret.clone();

    // RFC 7591 §2 / OIDC registration §2 defaults: `grant_types` defaults to
    // ["authorization_code", "implicit"] and `response_types` to ["code"] —
    // both are always present in the response; every other metadata field is
    // echoed only when registered.
    let grant_types = client_metadata::dcr_grant_types(&client)
        .unwrap_or_else(|| vec!["authorization_code".to_string(), "implicit".to_string()]);
    let response_types =
        client.allowed_response_types().unwrap_or_else(|| vec!["code".to_string()]);
    let scope =
        (!client.default_scopes.is_empty()).then(|| client.default_scopes.to_space_separated());
    let registration_client_uri = format!(
        "{}/realms/{}/clients-registrations/openid-connect/{}",
        issuer_base_url.trim_end_matches('/'),
        realm_name,
        client.client_id
    );
    let attribute_bool = |key: &str| client.attributes.get(key).map(|v| v == "true");
    let attribute_str = |key: &str| client.attributes.get(key).filter(|v| !v.is_empty()).cloned();
    let mut response = (
        status,
        Json(ClientRegistrationResponse {
            client: rep,
            registration_access_token: registration_access_token.clone(),
            registration_access_token_rfc: registration_access_token,
            registration_client_uri,
            client_id_issued_at: client_metadata::dcr_client_id_issued_at(&client),
            client_secret: secret.clone(),
            client_secret_expires_at: secret.map(|_| 0),
            client_name: client.name.as_ref().map(|n| n.to_string()),
            grant_types,
            response_types,
            token_endpoint_auth_method: client_metadata::token_endpoint_auth_method(&client)
                .map(str::to_string),
            scope,
            subject_type: attribute_str(Client::SUBJECT_TYPE_ATTRIBUTE),
            sector_identifier_uri: client.sector_identifier_uri().map(str::to_string),
            initiate_login_uri: client_metadata::initiate_login_uri(&client).map(str::to_string),
            post_logout_redirect_uris: client_metadata::post_logout_redirect_uris(&client),
            frontchannel_logout_uri: attribute_str(
                crate::routes::logout::CLIENT_ATTR_FRONTCHANNEL_LOGOUT_URI,
            ),
            frontchannel_logout_session_required: attribute_bool(
                client_metadata::ATTR_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED,
            ),
            backchannel_logout_uri: attribute_str(
                crate::routes::logout::CLIENT_ATTR_BACKCHANNEL_LOGOUT_URI,
            ),
            backchannel_logout_session_required: attribute_bool(
                client_metadata::ATTR_BACKCHANNEL_LOGOUT_SESSION_REQUIRED,
            ),
            logo_uri: client_metadata::logo_uri(&client).map(str::to_string),
            policy_uri: client_metadata::policy_uri(&client).map(str::to_string),
            tos_uri: client_metadata::tos_uri(&client).map(str::to_string),
            jwks_uri: crate::client_assertion::client_jwks_url(&client).ok().flatten(),
            jwks: crate::client_assertion::inline_client_jwks(&client).ok().flatten(),
            id_token_signed_response_alg: client_metadata::id_token_signed_response_alg(&client)
                .map(str::to_string),
            userinfo_signed_response_alg: client_metadata::userinfo_signed_response_alg(&client)
                .map(str::to_string),
            request_object_signing_alg: client_metadata::request_object_signing_alg(&client)
                .map(str::to_string),
            request_uris: client_metadata::request_uris(&client),
        }),
    )
        .into_response();
    // The body echoes the client secret and the registration access token:
    // never cacheable (RFC 6749 §5.1's token-response rule, applied to the
    // management API).
    let headers = response.headers_mut();
    headers.insert(axum::http::header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(axum::http::header::PRAGMA, "no-cache".parse().unwrap());
    response
}

/// Authenticate a client-configuration request: resolve the client by its
/// public `client_id` path segment and verify the bearer registration access
/// token against the stored hash in constant time. Unknown clients, bad
/// tokens, and disabled clients are a uniform 401.
#[allow(clippy::result_large_err)]
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
    register_client(&state, &realm, body, RegistrationPolicy::Open).await
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
    register_client(&state, &realm, body, RegistrationPolicy::Trusted).await
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
        Ok((client, token)) => build_registration_response(
            &state.config.issuer_url,
            realm.name.as_str(),
            client,
            token,
            StatusCode::OK,
        ),
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
    // RFC 7591 metadata fields fold into the ClientRepresentation shape
    // before parsing, same as on the create paths.
    let body = match translate_rfc7591_request(body) {
        Ok(body) => body,
        Err(resp) => return resp,
    };
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
    // A client created through the open endpoint stays under the open
    // payload policy on update: the registration access token must not
    // resurrect the stripped attributes (JWKS sources, logout URIs,
    // `request_uris`) or flip `service_accounts_enabled` back on.
    let open_registered =
        existing.attributes.get(client_metadata::ATTR_DCR_POLICY).map(String::as_str)
            == Some(client_metadata::DCR_POLICY_OPEN);
    if open_registered {
        if let Err(resp) = enforce_open_registration_policy(&realm.id, &mut rep) {
            return resp;
        }
    }
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
            if let Err(resp) = validate_registration_redirect_uri(uri) {
                return resp;
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
    // The DCR creation stamp (`client_id_issued_at`) describes issuance, not
    // the last modification: carry the original forward across updates.
    if !updated.attributes.contains_key(client_metadata::ATTR_DCR_CLIENT_ID_ISSUED_AT) {
        if let Some(stamp) = existing.attributes.get(client_metadata::ATTR_DCR_CLIENT_ID_ISSUED_AT)
        {
            updated
                .attributes
                .insert(client_metadata::ATTR_DCR_CLIENT_ID_ISSUED_AT.to_string(), stamp.clone());
        }
    }
    // The open-policy marker survives updates untouched — the registrant can
    // neither shed it nor rewrite it through the free-form attributes map.
    if open_registered {
        updated.attributes.insert(
            client_metadata::ATTR_DCR_POLICY.to_string(),
            client_metadata::DCR_POLICY_OPEN.to_string(),
        );
    }
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
    build_registration_response(
        &state.config.issuer_url,
        realm.name.as_str(),
        updated,
        new_token,
        StatusCode::OK,
    )
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

    /// Register a client through the shared create path with the open
    /// endpoint's policy; returns the stored client and its registration
    /// access token.
    async fn register_test_client(
        state: &Arc<ServerState>,
        realm: &Realm,
        body: serde_json::Value,
    ) -> (Client, String) {
        register_test_client_with_policy(state, realm, body, RegistrationPolicy::Open).await
    }

    /// Same as [`register_test_client`] with an explicit policy, to exercise
    /// the token-gated (trusted) create path.
    async fn register_test_client_with_policy(
        state: &Arc<ServerState>,
        realm: &Realm,
        body: serde_json::Value,
        policy: RegistrationPolicy,
    ) -> (Client, String) {
        let resp = register_client(state, realm, body, policy).await;
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

    #[test]
    fn open_policy_redirect_uri_scheme_allowlist() {
        // https is always allowed.
        assert!(validate_open_registration_redirect_uri("https://app.example.com/cb").is_ok());
        // Plain http only on loopback hosts (dev + RFC 8252 native apps).
        assert!(validate_open_registration_redirect_uri("http://localhost:8080/cb").is_ok());
        assert!(validate_open_registration_redirect_uri("http://127.0.0.1:3000/cb").is_ok());
        assert!(validate_open_registration_redirect_uri("http://[::1]:3000/cb").is_ok());
        assert!(validate_open_registration_redirect_uri("http://app.example.com/cb").is_err());
        assert!(validate_open_registration_redirect_uri("http://192.168.1.10/cb").is_err());
        assert!(
            validate_open_registration_redirect_uri("http://localhost.evil.example/cb").is_err()
        );
        // Scriptable schemes are rejected; Url::parse lowercases the scheme.
        for uri in [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "vbscript:msgbox(1)",
        ] {
            assert!(validate_open_registration_redirect_uri(uri).is_err(), "{uri}");
        }
        // Custom schemes are OIDC native-app practice.
        assert!(validate_open_registration_redirect_uri("myapp://callback").is_ok());
        assert!(validate_open_registration_redirect_uri("com.example.app:/oauth2redirect").is_ok());
    }

    #[test]
    fn open_policy_strips_attributes_and_forces_no_service_account() {
        let realm_id = RealmId::new("policy-test").unwrap();
        let mut rep: ClientRepresentation = serde_json::from_value(serde_json::json!({
            "client_id": "policy-test",
            "redirect_uris": ["https://app.example.com/cb"],
            "service_accounts_enabled": true,
            "attributes": {
                "jwks.url": "http://169.254.169.254/latest/meta-data",
                "use.jwks.url": "true",
                "jwks.string": "{\"keys\":[]}",
                "use.jwks.string": "true",
                "backchannel_logout_uri": "https://attacker.example.com/hook",
                "frontchannel_logout_uri": "https://attacker.example.com/logout",
                "admin_api_access": "true",
                "custom": "kept"
            }
        }))
        .unwrap();
        enforce_open_registration_policy(&realm_id, &mut rep).unwrap();
        let attributes = rep.attributes.unwrap();
        assert_eq!(
            attributes.len(),
            1,
            "all JWKS/logout attributes stripped, only the custom one kept: {attributes:?}"
        );
        assert_eq!(attributes.get("custom").map(String::as_str), Some("kept"));
        assert_eq!(rep.service_accounts_enabled, Some(false));
    }

    #[test]
    fn open_policy_rejects_wildcard_web_origin() {
        let realm_id = RealmId::new("policy-test").unwrap();
        let mut rep: ClientRepresentation = serde_json::from_value(serde_json::json!({
            "client_id": "policy-test",
            "web_origins": ["https://app.example.com", "*"]
        }))
        .unwrap();
        assert!(enforce_open_registration_policy(&realm_id, &mut rep).is_err());
        // Non-wildcard origins pass untouched.
        let mut rep: ClientRepresentation = serde_json::from_value(serde_json::json!({
            "client_id": "policy-test",
            "web_origins": ["https://app.example.com"]
        }))
        .unwrap();
        enforce_open_registration_policy(&realm_id, &mut rep).unwrap();
        assert_eq!(rep.web_origins.unwrap(), vec!["https://app.example.com".to_string()]);
    }

    #[tokio::test]
    async fn open_registration_applies_payload_policy() {
        let (state, realm) = registration_state().await;
        let (client, _token) = register_test_client(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-open-policy",
                "redirect_uris": ["http://localhost/cb"],
                "service_accounts_enabled": true,
                "web_origins": ["https://app.example.com"],
                "attributes": {
                    "jwks.url": "http://169.254.169.254/jwks.json",
                    "use.jwks.url": "true",
                    "jwks.string": "{\"keys\":[]}",
                    "use.jwks.string": "true",
                    "backchannel_logout_uri": "https://attacker.example.com/hook",
                    "frontchannel_logout_uri": "https://attacker.example.com/logout",
                    "custom": "kept"
                }
            }),
        )
        .await;
        assert!(!client.service_accounts_enabled);
        for key in [
            "jwks.url",
            "use.jwks.url",
            "jwks.string",
            "use.jwks.string",
            "backchannel_logout_uri",
            "frontchannel_logout_uri",
        ] {
            assert!(!client.attributes.contains_key(key), "{key} must be stripped");
        }
        assert_eq!(client.attributes.get("custom").map(String::as_str), Some("kept"));
        assert!(client.web_origins.iter().any(|o| o.as_str() == "https://app.example.com"));
    }

    #[tokio::test]
    async fn open_client_update_reapplies_the_open_policy() {
        let (state, realm) = registration_state().await;
        let (client, token) = register_test_client(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-open-put",
                "redirect_uris": ["http://localhost/cb"],
            }),
        )
        .await;
        // The open create stamped the policy marker.
        assert_eq!(
            client.attributes.get(client_metadata::ATTR_DCR_POLICY).map(String::as_str),
            Some(client_metadata::DCR_POLICY_OPEN)
        );

        // PUT back everything the create stripped — plus a marker overwrite
        // attempt and the service-account flip.
        let resp = update_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-open-put"),
            bearer_headers(&token),
            serde_json::json!({
                "client_id": "dcr-open-put",
                "redirect_uris": ["http://localhost/cb"],
                "service_accounts_enabled": true,
                "attributes": {
                    "jwks.url": "https://attacker.example.com/jwks",
                    "use.jwks.url": "true",
                    "backchannel_logout_uri": "https://attacker.example.com/hook",
                    "frontchannel_logout_uri": "https://attacker.example.com/logout",
                    "request_uris": "[\"https://attacker.example.com/obj.jwt\"]",
                    "dcr.policy": "trusted"
                }
            })
            .to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = state.storage.get_client(&realm.id, &client.id).await.unwrap().unwrap();
        for key in [
            "jwks.url",
            "use.jwks.url",
            "backchannel_logout_uri",
            "frontchannel_logout_uri",
            "request_uris",
        ] {
            assert!(!stored.attributes.contains_key(key), "{key} must be re-stripped on update");
        }
        assert!(!stored.service_accounts_enabled, "the service-account flip is refused");
        assert_eq!(
            stored.attributes.get(client_metadata::ATTR_DCR_POLICY).map(String::as_str),
            Some(client_metadata::DCR_POLICY_OPEN),
            "the marker is re-stamped, never registrant-controlled"
        );
    }

    #[tokio::test]
    async fn trusted_client_update_keeps_every_field() {
        let (state, realm) = registration_state().await;
        let (client, token) = register_test_client_with_policy(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-trusted-put",
                "redirect_uris": ["http://localhost/cb"],
                "attributes": {"backchannel_logout_uri": "https://app.example.com/hook"}
            }),
            RegistrationPolicy::Trusted,
        )
        .await;
        // No marker on the trusted path.
        assert!(!client.attributes.contains_key(client_metadata::ATTR_DCR_POLICY));
        assert_eq!(
            client.attributes.get("backchannel_logout_uri").map(String::as_str),
            Some("https://app.example.com/hook")
        );

        let resp = update_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-trusted-put"),
            bearer_headers(&token),
            serde_json::json!({
                "client_id": "dcr-trusted-put",
                "redirect_uris": ["http://localhost/cb"],
                "service_accounts_enabled": true,
                "attributes": {"backchannel_logout_uri": "https://app.example.com/hook"}
            })
            .to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = state.storage.get_client(&realm.id, &client.id).await.unwrap().unwrap();
        assert_eq!(
            stored.attributes.get("backchannel_logout_uri").map(String::as_str),
            Some("https://app.example.com/hook"),
            "the trusted path honors every field"
        );
        assert!(stored.service_accounts_enabled);
    }

    /// Create (201) and read (200) responses echo the client secret and the
    /// registration access token: both carry no-store/no-cache.
    #[tokio::test]
    async fn registration_responses_carry_no_store_headers() {
        let (state, realm) = registration_state().await;
        let resp = register_client(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-cache-hdr",
                "redirect_uris": ["http://localhost/cb"]
            }),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(resp.headers()[axum::http::header::CACHE_CONTROL], "no-store");
        assert_eq!(resp.headers()[axum::http::header::PRAGMA], "no-cache");
        let json = response_json(resp).await;
        let token = json["registrationAccessToken"].as_str().unwrap().to_string();

        let resp = read_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-cache-hdr"),
            bearer_headers(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[axum::http::header::CACHE_CONTROL], "no-store");
        assert_eq!(resp.headers()[axum::http::header::PRAGMA], "no-cache");
    }

    #[test]
    fn open_policy_rejects_dangerous_logout_uri_schemes() {
        let realm_id = RealmId::new("policy-test").unwrap();
        // Scriptable schemes and non-loopback plain http are loud errors.
        for uri in [
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "http://169.254.169.254/latest/meta-data",
        ] {
            let mut rep: ClientRepresentation = serde_json::from_value(serde_json::json!({
                "client_id": "policy-test",
                "redirect_uris": ["https://app.example.com/cb"],
                "attributes": {"backchannel_logout_uri": uri}
            }))
            .unwrap();
            assert!(enforce_open_registration_policy(&realm_id, &mut rep).is_err(), "{uri}");
        }
        // https, loopback http and custom schemes validate (and are still
        // stripped — the open endpoint never stores logout URIs).
        for uri in [
            "https://app.example.com/hook",
            "http://localhost:8080/hook",
            "myapp://logout",
        ] {
            let mut rep: ClientRepresentation = serde_json::from_value(serde_json::json!({
                "client_id": "policy-test",
                "redirect_uris": ["https://app.example.com/cb"],
                "attributes": {"backchannel_logout_uri": uri}
            }))
            .unwrap();
            enforce_open_registration_policy(&realm_id, &mut rep).unwrap();
            assert!(!rep.attributes.unwrap().contains_key("backchannel_logout_uri"), "{uri}");
        }
    }

    #[tokio::test]
    async fn open_registration_rejects_forbidden_redirect_scheme() {
        let (state, realm) = registration_state().await;
        let resp = register_client(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-js-uri",
                "redirect_uris": ["https://app.example.com/cb", "javascript:alert(1)"],
            }),
            RegistrationPolicy::Open,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "invalid_redirect_uri");
        assert!(
            json["error_description"].as_str().unwrap().contains("javascript:alert(1)"),
            "the offending URI must be named: {json}"
        );
        // The whole registration is rejected: no client was created.
        let client_id = issuerd_core::ClientIdentifier::new("dcr-js-uri").unwrap();
        let stored = state.storage.get_client_by_client_id(&realm.id, &client_id).await.unwrap();
        assert!(stored.is_none(), "no partial registration on policy rejection");
    }

    #[tokio::test]
    async fn registration_rejects_fragment_in_redirect_uri() {
        let (state, realm) = registration_state().await;
        // RFC 6749 §3.1.2 / OIDC Core §3.1.2: no fragment component, on both
        // the open and the token-gated paths (the conformance suite's
        // oidcc-redirect-uri-regfrag module drives the trusted path).
        for policy in [RegistrationPolicy::Open, RegistrationPolicy::Trusted] {
            let resp = register_client(
                &state,
                &realm,
                serde_json::json!({
                    "client_id": format!("dcr-frag-{policy:?}"),
                    "redirect_uris": ["https://app.example.com/cb#frag"],
                }),
                policy,
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["error"], "invalid_redirect_uri");
        }
    }

    #[tokio::test]
    async fn trusted_registration_honors_full_payload() {
        let (state, realm) = registration_state().await;
        let (client, _token) = register_test_client_with_policy(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-trusted",
                "redirect_uris": ["http://dev.internal.example/cb"],
                "service_accounts_enabled": true,
                "web_origins": ["*"],
                "attributes": {
                    "jwks.url": "https://idp.example.com/jwks.json",
                    "use.jwks.url": "true",
                    "backchannel_logout_uri": "https://app.example.com/logout/backchannel",
                    "frontchannel_logout_uri": "https://app.example.com/logout/frontchannel"
                }
            }),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert!(client.service_accounts_enabled);
        assert_eq!(
            client.attributes.get("jwks.url").map(String::as_str),
            Some("https://idp.example.com/jwks.json")
        );
        assert_eq!(
            client.attributes.get("backchannel_logout_uri").map(String::as_str),
            Some("https://app.example.com/logout/backchannel")
        );
        assert!(client.web_origins.iter().any(|o| o.as_str() == "*"));
        assert!(client
            .redirect_uris
            .iter()
            .any(|u| u.as_str() == "http://dev.internal.example/cb"));
    }

    // ------------------------------------------------------------------
    // RFC 7591/7592 request translation and response shape
    // ------------------------------------------------------------------

    /// A full RFC 7591 registration body (all supported metadata fields).
    fn rfc7591_body() -> serde_json::Value {
        serde_json::json!({
            "client_name": "RFC App",
            "redirect_uris": ["https://app.example.com/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code", "code id_token"],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "openid profile",
            "subject_type": "public",
            "jwks": {"keys": [{"kty": "RSA", "kid": "r1", "n": "0vx7agoe", "e": "AQAB"}]},
            "initiate_login_uri": "https://app.example.com/login",
            "post_logout_redirect_uris": ["https://app.example.com/logout-done"],
            "frontchannel_logout_uri": "https://app.example.com/fc-logout",
            "frontchannel_logout_session_required": true,
            "backchannel_logout_uri": "https://app.example.com/bc-logout",
            "backchannel_logout_session_required": false,
            "logo_uri": "https://app.example.com/logo.png",
            "policy_uri": "https://app.example.com/policy",
            "tos_uri": "https://app.example.com/tos",
            "id_token_signed_response_alg": "ES256",
            "userinfo_signed_response_alg": "RS256",
            "client_secret": "registrant-chosen-secret"
        })
    }

    /// Read a response body as JSON.
    async fn response_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn translate_passes_through_bodies_without_rfc_fields() {
        let body = serde_json::json!({"client_id": "x", "name": "App"});
        let out = translate_rfc7591_request(body.clone()).unwrap();
        assert_eq!(out, body, "Keycloak-shaped bodies must be untouched");
        // Non-object bodies pass through for the parser to reject.
        let out = translate_rfc7591_request(serde_json::json!(["nope"])).unwrap();
        assert_eq!(out, serde_json::json!(["nope"]));
    }

    #[test]
    fn translate_keycloak_spelling_wins_over_rfc_twin() {
        let out = translate_rfc7591_request(serde_json::json!({
            "name": "KC Name",
            "client_name": "RFC Name",
            "secret": "kc-secret",
            "client_secret": "rfc-secret",
            "client_authenticator_type": "client-secret-jwt",
            "token_endpoint_auth_method": "client_secret_basic"
        }))
        .unwrap();
        assert_eq!(out["name"], "KC Name");
        assert_eq!(out["secret"], "kc-secret");
        assert_eq!(out["client_authenticator_type"], "client-secret-jwt");
        // The RFC twins are consumed, the metadata attribute is still stored.
        assert!(out.get("client_name").is_none());
        assert!(out.get("client_secret").is_none());
        assert_eq!(out["attributes"]["token_endpoint_auth_method"], "client_secret_basic");
    }

    #[test]
    fn translate_scope_merges_into_default_scopes() {
        let out = translate_rfc7591_request(serde_json::json!({
            "default_scopes": ["openid"],
            "scope": "profile email profile"
        }))
        .unwrap();
        assert_eq!(
            out["default_scopes"],
            serde_json::json!(["openid", "profile", "email"]),
            "union, deduplicated, request order preserved"
        );
    }

    #[tokio::test]
    async fn rfc7591_full_registration_roundtrip() {
        let (state, realm) = registration_state().await;
        let resp =
            register_client(&state, &realm, rfc7591_body(), RegistrationPolicy::Trusted).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = response_json(resp).await;

        // RFC 7591 §3.2.1 / RFC 7592 response fields.
        let client_id = json["client_id"].as_str().unwrap().to_string();
        assert_eq!(
            json["registration_client_uri"].as_str().unwrap(),
            format!(
                "{}/realms/master/clients-registrations/openid-connect/{client_id}",
                state.config.issuer_url
            )
        );
        assert_eq!(
            json["registration_access_token"].as_str().unwrap(),
            json["registrationAccessToken"].as_str().unwrap(),
            "both token spellings carry the same value"
        );
        assert!(json["client_id_issued_at"].as_i64().unwrap() > 0);
        assert_eq!(json["client_secret_expires_at"].as_i64().unwrap(), 0);
        // The registrant-suggested secret is honored under both spellings.
        assert_eq!(json["client_secret"].as_str().unwrap(), "registrant-chosen-secret");
        assert_eq!(json["secret"].as_str().unwrap(), "registrant-chosen-secret");

        // Metadata echo.
        assert_eq!(json["client_name"], "RFC App");
        assert_eq!(json["grant_types"], serde_json::json!(["authorization_code", "refresh_token"]));
        assert_eq!(json["response_types"], serde_json::json!(["code", "code id_token"]));
        assert_eq!(json["token_endpoint_auth_method"], "client_secret_basic");
        assert_eq!(json["scope"], "openid profile");
        assert_eq!(json["subject_type"], "public");
        assert_eq!(json["initiate_login_uri"], "https://app.example.com/login");
        assert_eq!(
            json["post_logout_redirect_uris"],
            serde_json::json!(["https://app.example.com/logout-done"])
        );
        assert_eq!(json["frontchannel_logout_uri"], "https://app.example.com/fc-logout");
        assert_eq!(json["frontchannel_logout_session_required"], true);
        assert_eq!(json["backchannel_logout_uri"], "https://app.example.com/bc-logout");
        assert_eq!(json["backchannel_logout_session_required"], false);
        assert_eq!(json["logo_uri"], "https://app.example.com/logo.png");
        assert_eq!(json["policy_uri"], "https://app.example.com/policy");
        assert_eq!(json["tos_uri"], "https://app.example.com/tos");
        assert_eq!(json["id_token_signed_response_alg"], "ES256");
        assert_eq!(json["userinfo_signed_response_alg"], "RS256");
        assert_eq!(json["jwks"]["keys"][0]["kid"], "r1");

        // Stored model: the RFC fields landed as client attributes.
        let identifier = issuerd_core::ClientIdentifier::new(&client_id).unwrap();
        let stored = state
            .storage
            .get_client_by_client_id(&realm.id, &identifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.name.as_ref().map(|n| n.to_string()).as_deref(), Some("RFC App"));
        assert_eq!(stored.secret.as_deref(), Some("registrant-chosen-secret"));
        assert_eq!(stored.attributes.get("subject_type").map(String::as_str), Some("public"));
        assert_eq!(stored.attributes.get("use.jwks.string").map(String::as_str), Some("true"));
        assert!(stored.attributes.contains_key(client_metadata::ATTR_DCR_CLIENT_ID_ISSUED_AT));

        // RFC 7592 read: GET echoes everything (incl. initiate_login_uri and
        // the creation stamp).
        let token = json["registration_access_token"].as_str().unwrap().to_string();
        let resp = read_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path(&client_id),
            bearer_headers(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let read = response_json(resp).await;
        assert_eq!(read["initiate_login_uri"], "https://app.example.com/login");
        assert_eq!(read["client_id_issued_at"], json["client_id_issued_at"]);
        assert_eq!(read["registration_client_uri"], json["registration_client_uri"]);
        assert_eq!(read["grant_types"], json["grant_types"]);
        assert_eq!(read["response_types"], json["response_types"]);
        assert_eq!(read["jwks"]["keys"][0]["kid"], "r1");
    }

    #[tokio::test]
    async fn rfc7591_rejects_non_https_url_metadata() {
        let (state, realm) = registration_state().await;
        for (field, value) in [
            ("initiate_login_uri", "http://app.example.com/login"),
            ("jwks_uri", "http://app.example.com/jwks.json"),
            ("frontchannel_logout_uri", "http://app.example.com/fc"),
            ("backchannel_logout_uri", "http://app.example.com/bc"),
            ("logo_uri", "http://app.example.com/logo.png"),
            ("policy_uri", "http://app.example.com/policy"),
            ("tos_uri", "http://app.example.com/tos"),
        ] {
            let resp = register_client(
                &state,
                &realm,
                serde_json::json!({
                    "redirect_uris": ["https://app.example.com/cb"],
                    field: value,
                }),
                RegistrationPolicy::Trusted,
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{field}");
            let json = response_json(resp).await;
            assert_eq!(json["error"], "invalid_client_metadata", "{field}");
        }
    }

    #[tokio::test]
    async fn rfc7591_rejects_unknown_grant_and_response_types() {
        let (state, realm) = registration_state().await;
        for body in [
            serde_json::json!({"grant_types": ["authorization_code", "made-up-grant"]}),
            serde_json::json!({"response_types": ["code", "token token"]}),
            // Bare `token` parses but is OAuth2-only: never accepted by the
            // authorization endpoint, so it is not registrable metadata.
            serde_json::json!({"response_types": ["token"]}),
            serde_json::json!({"response_types": "code"}),
            serde_json::json!({"grant_types": {"authorization_code": true}}),
        ] {
            let resp = register_client(&state, &realm, body, RegistrationPolicy::Trusted).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let json = response_json(resp).await;
            assert_eq!(json["error"], "invalid_client_metadata");
        }
    }

    /// The discovery-advertised `token id_token` spelling (OIDCD-3) registers
    /// and normalizes to the canonical `id_token token`.
    #[tokio::test]
    async fn rfc7591_response_types_accept_and_normalize_token_id_token() {
        let (state, realm) = registration_state().await;
        let resp = register_client(
            &state,
            &realm,
            serde_json::json!({"response_types": ["token id_token", "code"]}),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = response_json(resp).await;
        assert_eq!(json["response_types"], serde_json::json!(["id_token token", "code"]));
    }

    #[tokio::test]
    async fn rfc7591_rejects_none_and_symmetric_signing_algs() {
        let (state, realm) = registration_state().await;
        for alg in ["none", "HS256", "HS512", "PS256", "not-an-alg"] {
            for field in [
                "id_token_signed_response_alg",
                "userinfo_signed_response_alg",
            ] {
                let resp = register_client(
                    &state,
                    &realm,
                    serde_json::json!({field: alg}),
                    RegistrationPolicy::Trusted,
                )
                .await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{field}={alg}");
                let json = response_json(resp).await;
                assert_eq!(json["error"], "invalid_client_metadata", "{field}={alg}");
            }
        }
        // A supported asymmetric alg registers fine.
        let (client, _token) = register_test_client_with_policy(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-alg-ok",
                "id_token_signed_response_alg": "EdDSA",
                "userinfo_signed_response_alg": "ES384"
            }),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert_eq!(
            client.attributes.get("id_token_signed_response_alg").map(String::as_str),
            Some("EdDSA")
        );
    }

    #[tokio::test]
    async fn rfc7591_post_logout_redirect_uri_validation() {
        let (state, realm) = registration_state().await;

        // Syntactically invalid → invalid_redirect_uri.
        let resp = register_client(
            &state,
            &realm,
            serde_json::json!({"post_logout_redirect_uris": ["not a url at all"]}),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "invalid_redirect_uri");

        // Scheme violations → invalid_client_metadata.
        for uri in ["http://app.example.com/done", "javascript:alert(1)"] {
            let resp = register_client(
                &state,
                &realm,
                serde_json::json!({"post_logout_redirect_uris": [uri]}),
                RegistrationPolicy::Trusted,
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
            let json = response_json(resp).await;
            assert_eq!(json["error"], "invalid_client_metadata", "{uri}");
        }

        // https, loopback http and custom schemes are accepted.
        let (client, _token) = register_test_client_with_policy(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-plru-ok",
                "post_logout_redirect_uris": [
                    "https://app.example.com/done",
                    "http://localhost:8080/done",
                    "myapp://logout-done"
                ]
            }),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert_eq!(
            client_metadata::post_logout_redirect_uris(&client),
            vec![
                "https://app.example.com/done".to_string(),
                "http://localhost:8080/done".to_string(),
                "myapp://logout-done".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn rfc7591_token_endpoint_auth_method_mapping() {
        let (state, realm) = registration_state().await;

        // `none` forces a public client and no secret is generated.
        let resp = register_client(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-auth-none",
                "token_endpoint_auth_method": "none",
                "redirect_uris": ["https://app.example.com/cb"]
            }),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = response_json(resp).await;
        assert!(json.get("client_secret").is_none(), "no secret for a public client");
        assert!(json["secret"].is_null());
        let identifier = issuerd_core::ClientIdentifier::new("dcr-auth-none").unwrap();
        let stored = state
            .storage
            .get_client_by_client_id(&realm.id, &identifier)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.public_client);
        assert!(stored.secret.is_none());
        assert_eq!(
            stored.attributes.get("token_endpoint_auth_method").map(String::as_str),
            Some("none")
        );

        // private_key_jwt maps onto the client-jwt authenticator.
        let (client, _token) = register_test_client_with_policy(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-auth-jwt",
                "token_endpoint_auth_method": "private_key_jwt"
            }),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert_eq!(
            client.client_authenticator_type,
            issuerd_core::ClientAuthenticatorType::ClientJwt
        );
        // client_secret_jwt → client-secret-jwt; basic/post → client-secret.
        for (method, expected) in [
            ("client_secret_jwt", issuerd_core::ClientAuthenticatorType::ClientSecretJwt),
            ("client_secret_basic", issuerd_core::ClientAuthenticatorType::ClientSecret),
            ("client_secret_post", issuerd_core::ClientAuthenticatorType::ClientSecret),
        ] {
            let (client, _token) = register_test_client_with_policy(
                &state,
                &realm,
                serde_json::json!({
                    "client_id": format!("dcr-auth-{}", method.replace('_', "-")),
                    "token_endpoint_auth_method": method
                }),
                RegistrationPolicy::Trusted,
            )
            .await;
            assert_eq!(client.client_authenticator_type, expected, "{method}");
        }

        // An unknown method is rejected.
        let resp = register_client(
            &state,
            &realm,
            serde_json::json!({"token_endpoint_auth_method": "tls_client_auth"}),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "invalid_client_metadata");
    }

    #[tokio::test]
    async fn rfc7591_subject_type_and_jwks_shape_validation() {
        let (state, realm) = registration_state().await;
        for body in [
            serde_json::json!({"subject_type": "weird"}),
            serde_json::json!({"jwks": "not-an-object"}),
            serde_json::json!({"frontchannel_logout_session_required": "yes"}),
            serde_json::json!({"sector_identifier_uri": 42}),
        ] {
            let resp = register_client(&state, &realm, body, RegistrationPolicy::Trusted).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let json = response_json(resp).await;
            assert_eq!(json["error"], "invalid_client_metadata");
        }
    }

    /// RFC fields on the OPEN endpoint translate into attributes first and
    /// are then stripped by the existing open-registration policy, exactly
    /// like Keycloak-spelled attributes.
    #[tokio::test]
    async fn open_policy_strips_rfc_spelled_jwks_and_logout_attributes() {
        let (state, realm) = registration_state().await;
        let (client, _token) = register_test_client(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-rfc-strip",
                "redirect_uris": ["https://app.example.com/cb"],
                "jwks": {"keys": []},
                "jwks_uri": "https://idp.example.com/jwks",
                "frontchannel_logout_uri": "https://attacker.example.com/logout",
                "backchannel_logout_uri": "https://attacker.example.com/hook",
                "initiate_login_uri": "https://app.example.com/login",
                "post_logout_redirect_uris": ["https://app.example.com/done"],
                "response_types": ["code"]
            }),
        )
        .await;
        for key in [
            "use.jwks.string",
            "jwks.string",
            "use.jwks.url",
            "jwks.url",
            "frontchannel_logout_uri",
            "backchannel_logout_uri",
        ] {
            assert!(!client.attributes.contains_key(key), "{key} must be stripped");
        }
        // Benign RFC metadata survives the open policy.
        assert_eq!(
            client.attributes.get("initiate_login_uri").map(String::as_str),
            Some("https://app.example.com/login")
        );
        assert_eq!(client.attributes.get("response_types").map(String::as_str), Some("[\"code\"]"));
        assert!(client.attributes.contains_key(client_metadata::ATTR_POST_LOGOUT_REDIRECT_URIS));
    }

    /// The RFC 7591 creation stamp is written once at registration and
    /// survives RFC 7592 updates (which rotate only the registration access
    /// token).
    #[tokio::test]
    async fn update_preserves_client_id_issued_at() {
        let (state, realm) = registration_state().await;
        let (client, token) = register_test_client(
            &state,
            &realm,
            serde_json::json!({"client_id": "dcr-iat", "client_name": "Original"}),
        )
        .await;
        let issued_at = client_metadata::dcr_client_id_issued_at(&client).expect("stamped");

        let resp = update_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-iat"),
            bearer_headers(&token),
            serde_json::json!({
                "client_name": "Renamed",
                "initiate_login_uri": "https://app.example.com/login"
            })
            .to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(json["client_id_issued_at"].as_i64().unwrap(), issued_at);
        assert_eq!(json["client_name"], "Renamed");
        assert_eq!(json["initiate_login_uri"], "https://app.example.com/login");

        // The RFC 7592 read reports the original stamp as well.
        let rotated = json["registration_access_token"].as_str().unwrap().to_string();
        let resp = read_registered_client_handler(
            State(state.clone()),
            axum::extract::Extension(ResolvedRealm(Some("master".to_string()))),
            master_path("dcr-iat"),
            bearer_headers(&rotated),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(json["client_id_issued_at"].as_i64().unwrap(), issued_at);
    }

    /// A body without any RFC 7591 field takes the legacy path: no
    /// RFC-translated attributes appear (the `client_id_issued_at` stamp is
    /// the only addition — it marks every DCR-created client).
    #[tokio::test]
    async fn keycloak_shaped_body_stores_no_rfc_attributes() {
        let (state, realm) = registration_state().await;
        let (client, _token) = register_test_client(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-kc-shape",
                "name": "KC App",
                "redirect_uris": ["http://localhost/cb"]
            }),
        )
        .await;
        assert!(!client.attributes.contains_key(client_metadata::ATTR_DCR_GRANT_TYPES));
        assert!(!client.attributes.contains_key(client_metadata::ATTR_INITIATE_LOGIN_URI));
        assert!(client.attributes.contains_key(client_metadata::ATTR_DCR_CLIENT_ID_ISSUED_AT));
    }

    /// `request_uris` (OIDC registration, JAR-by-reference): https-only at
    /// registration, stored as JSON, echoed in responses.
    #[tokio::test]
    async fn request_uris_registration_roundtrip() {
        let (state, realm) = registration_state().await;
        let resp = register_client(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-request-uris",
                "request_uris": ["https://rp.example.com/object.jwt"],
                "request_object_signing_alg": "RS256"
            }),
            RegistrationPolicy::Trusted,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = response_json(resp).await;
        assert_eq!(json["request_uris"], serde_json::json!(["https://rp.example.com/object.jwt"]));
        assert_eq!(json["request_object_signing_alg"], "RS256");

        let identifier = issuerd_core::ClientIdentifier::new("dcr-request-uris").unwrap();
        let stored = state
            .storage
            .get_client_by_client_id(&realm.id, &identifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            client_metadata::request_uris(&stored),
            vec!["https://rp.example.com/object.jwt".to_string()]
        );
        assert_eq!(client_metadata::request_object_signing_alg(&stored), Some("RS256"));
    }

    /// `request_uris` entries must be https; non-https and non-array shapes
    /// are `invalid_client_metadata`.
    #[tokio::test]
    async fn request_uris_rejects_non_https_and_bad_shapes() {
        let (state, realm) = registration_state().await;
        for body in [
            serde_json::json!({"request_uris": ["http://rp.example.com/object.jwt"]}),
            serde_json::json!({"request_uris": ["not a url"]}),
            serde_json::json!({"request_uris": "https://rp.example.com/object.jwt"}),
            serde_json::json!({"request_uris": [42]}),
        ] {
            let desc = body.to_string();
            let resp = register_client(&state, &realm, body, RegistrationPolicy::Trusted).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{desc}");
            let json = response_json(resp).await;
            assert_eq!(json["error"], "invalid_client_metadata", "{desc}");
        }
    }

    /// The open endpoint strips `request_uris` (a caller-controlled fetch
    /// target), like the JWKS/logout attributes.
    #[tokio::test]
    async fn open_policy_strips_request_uris() {
        let (state, realm) = registration_state().await;
        let (client, _token) = register_test_client(
            &state,
            &realm,
            serde_json::json!({
                "client_id": "dcr-open-request-uris",
                "redirect_uris": ["https://app.example.com/cb"],
                "request_uris": ["https://attacker.example.com/object.jwt"]
            }),
        )
        .await;
        assert!(!client.attributes.contains_key(client_metadata::ATTR_REQUEST_URIS));
    }
}
