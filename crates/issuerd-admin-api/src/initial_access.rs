// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Initial access tokens for dynamic client registration.

//! Initial access tokens for dynamic client registration (Keycloak's
//! `clients-initial-access` admin API).
//!
//! An initial access token gates the public
//! `POST /realms/{realm}/clients-registrations/openid-connect` endpoint.
//! Tokens are opaque (not JWTs), cache-backed (multi-node safe via the
//! shared `DistributedCache`), optionally expiring, and count-limited.
//!
//! Storage layout (distributed cache):
//!
//! - `initial-access:{realm_id}:{id}` → JSON [`InitialAccessTokenData`]
//!   (cache TTL mirrors `expiration` when non-zero)
//! - `initial-access-used:{realm_id}:{id}` → atomic use counter via
//!   [`issuerd_core::DistributedCache::increment`], compared against `count`
//!
//! The token presented by clients has the form `{id}.{secret}`: the `id`
//! segment addresses the cache entry directly, and the whole token is
//! verified against the stored SHA-256 hash in constant time.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{DistributedCache, IssuerdError, OperationType, RealmId, ResourceType};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{InitialAccessTokenCreateRequest, InitialAccessTokenRepresentation},
    error::AdminApiError,
    state::AdminApiState,
};

/// Cache key of an initial access token entry.
pub fn initial_access_cache_key(realm_id: &RealmId, id: &str) -> String {
    format!("initial-access:{}:{id}", realm_id.0)
}

/// Cache key of the atomic use counter for an initial access token.
fn initial_access_used_cache_key(realm_id: &RealmId, id: &str) -> String {
    format!("initial-access-used:{}:{id}", realm_id.0)
}

/// Hex-encoded SHA-256 of a bearer token. Also used by the registration
/// access token machinery in issuerd-server.
pub fn sha256_hex(token: &str) -> String {
    let digest = sha2::Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// An initial access token as stored in the distributed cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialAccessTokenData {
    /// Hex-encoded SHA-256 of the full `{id}.{secret}` token.
    pub token_hash: String,
    /// Requested lifetime in seconds from minting (`0` = never expires).
    pub expiration: u64,
    /// Maximum number of registrations (`0` = unlimited).
    pub count: u32,
}

/// Mint a new initial access token and store it in the distributed cache.
///
/// Returns the admin-facing id, the raw `{id}.{secret}` token (shown to the
/// caller exactly once), and the stored data.
pub async fn mint_initial_access_token(
    cache: &Arc<dyn DistributedCache>,
    realm_id: &RealmId,
    expiration: u64,
    count: u32,
) -> Result<(String, String, InitialAccessTokenData), IssuerdError> {
    let id = issuerd_core::utils::generate_id();
    let token = format!("{id}.{}", issuerd_core::utils::generate_id());
    let data = InitialAccessTokenData {
        token_hash: sha256_hex(&token),
        expiration,
        count,
    };
    let bytes = serde_json::to_vec(&data)
        .map_err(|e| IssuerdError::ServerError(format!("serialize initial access token: {e}")))?;
    let ttl = (expiration > 0).then(|| std::time::Duration::from_secs(expiration));
    cache.set(&initial_access_cache_key(realm_id, &id), bytes, ttl).await?;
    Ok((id, token, data))
}

/// TTL for the use counter: it must outlive the token entry it counts uses
/// for (small grace), and must never expire when the token never expires —
/// otherwise the count window would silently reset.
fn used_counter_ttl(expiration: u64) -> Option<std::time::Duration> {
    (expiration > 0).then(|| std::time::Duration::from_secs(expiration + 60))
}

/// Verify a raw initial access token and, when valid, atomically consume one
/// of its uses. Returns `Ok(false)` for malformed, unknown, expired,
/// hash-mismatched, or exhausted tokens (all indistinguishable to the
/// caller).
///
/// A use is consumed at verification time, so a registration that fails
/// afterwards (e.g. invalid client metadata) still decrements the count —
/// deliberately abuse-resistant.
pub async fn verify_and_consume_initial_access_token(
    cache: &Arc<dyn DistributedCache>,
    realm_id: &RealmId,
    token: &str,
) -> Result<bool, IssuerdError> {
    use subtle::ConstantTimeEq;
    let Some((id, _)) = token.split_once('.') else {
        return Ok(false);
    };
    let Some(bytes) = cache.get(&initial_access_cache_key(realm_id, id)).await? else {
        return Ok(false);
    };
    let data: InitialAccessTokenData = match serde_json::from_slice(&bytes) {
        Ok(d) => d,
        Err(_) => return Ok(false),
    };
    let provided_hash = sha256_hex(token);
    if !bool::from(provided_hash.as_bytes().ct_eq(data.token_hash.as_bytes())) {
        return Ok(false);
    }
    // The cache TTL is the real expiration mechanism (PAR precedent): an
    // expired entry is indistinguishable from an unknown one.
    if data.count == 0 {
        return Ok(true);
    }
    let used = cache
        .increment(&initial_access_used_cache_key(realm_id, id), used_counter_ttl(data.expiration))
        .await?;
    Ok(used <= u64::from(data.count))
}

/// Revoke an initial access token and its use counter. Idempotent.
pub async fn revoke_initial_access_token(
    cache: &Arc<dyn DistributedCache>,
    realm_id: &RealmId,
    id: &str,
) -> Result<(), IssuerdError> {
    cache.delete(&initial_access_cache_key(realm_id, id)).await?;
    cache.delete(&initial_access_used_cache_key(realm_id, id)).await?;
    Ok(())
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/clients-initial-access",
    tag = "Clients",
    summary = "Mint an initial access token",
    description = "Creates an initial access token that gates dynamic client registration at `POST /realms/{realm}/clients-registrations/openid-connect`. The raw token is returned only in this response. Requires `manage-clients` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Token parameters", content = InitialAccessTokenCreateRequest),
    responses(
        (status = 200, description = "Token created", body = InitialAccessTokenRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_initial_access_token(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<InitialAccessTokenCreateRequest>,
) -> Result<Json<InitialAccessTokenRepresentation>, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let expiration = body.expiration.unwrap_or(0);
    let count = body.count.unwrap_or(0);
    let (id, token, data) =
        mint_initial_access_token(&state.cache, &realm_id, expiration, count).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::InitialAccessToken,
        &format!("clients-initial-access/{id}"),
        None,
    )
    .await;
    Ok(Json(InitialAccessTokenRepresentation {
        id,
        token: Some(token),
        expiration: data.expiration,
        count: data.count,
        remaining_count: data.count,
    }))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients-initial-access",
    tag = "Clients",
    summary = "List initial access tokens",
    description = "Lists the realm's live initial access tokens (without token material). Requires `view-clients` or `manage-clients` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Initial access tokens", body = Vec<InitialAccessTokenRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_initial_access_tokens(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<Vec<InitialAccessTokenRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let prefix = format!("initial-access:{}:", realm_id);
    let mut tokens = Vec::new();
    for key in state.cache.scan_keys(&format!("{prefix}*")).await? {
        let Some(id) = key.strip_prefix(&prefix) else {
            continue;
        };
        let Some(bytes) = state.cache.get(&key).await? else {
            continue;
        };
        let Ok(data) = serde_json::from_slice::<InitialAccessTokenData>(&bytes) else {
            continue;
        };
        let used_raw = state.cache.get(&initial_access_used_cache_key(&realm_id, id)).await?;
        let used = used_raw
            .and_then(|raw| std::str::from_utf8(&raw).ok()?.parse::<u64>().ok())
            .unwrap_or(0);
        let remaining = if data.count == 0 {
            0
        } else {
            u64::from(data.count).saturating_sub(used) as u32
        };
        tokens.push(InitialAccessTokenRepresentation {
            id: id.to_string(),
            token: None,
            expiration: data.expiration,
            count: data.count,
            remaining_count: remaining,
        });
    }
    // Deterministic output for UI tables: cache iteration order is undefined.
    tokens.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Json(tokens))
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/clients-initial-access/{id}",
    tag = "Clients",
    summary = "Revoke an initial access token",
    description = "Revokes an initial access token so it can no longer be used for dynamic client registration. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Token ID")
    ),
    responses(
        (status = 204, description = "Token revoked"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_initial_access_token(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    revoke_initial_access_token(&state.cache, &realm_id, &id).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::InitialAccessToken,
        &format!("clients-initial-access/{id}"),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::Request,
        routing::{delete, get},
        Router,
    };
    use tower::ServiceExt;

    fn realm_id() -> RealmId {
        RealmId::new("realm-1").unwrap()
    }

    /// Router mirroring the `clients-initial-access` registrations in
    /// `routes.rs`, behind the real admin auth middleware.
    fn initial_access_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/clients-initial-access",
                get(list_initial_access_tokens).post(create_initial_access_token),
            )
            .route(
                "/admin/realms/{realm}/clients-initial-access/{id}",
                delete(delete_initial_access_token),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    async fn seed_test_realm(state: &AdminApiState) {
        let realm = issuerd_core::Realm {
            id: realm_id(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
    }

    fn request(method: &str, uri: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", "Bearer valid-token")
            .header("Content-Type", "application/json")
            .body(body)
            .unwrap()
    }

    async fn json_body<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn cache_key_layout() {
        assert_eq!(initial_access_cache_key(&realm_id(), "abc"), "initial-access:realm-1:abc");
        assert_eq!(
            initial_access_used_cache_key(&realm_id(), "abc"),
            "initial-access-used:realm-1:abc"
        );
    }

    #[test]
    fn used_counter_ttl_outlives_only_expiring_tokens() {
        // A never-expiring token (expiration 0) must get a never-expiring use
        // counter — otherwise the count window would silently reset.
        assert_eq!(used_counter_ttl(0), None);
        // An expiring token's counter outlives the token entry by a 60-second
        // grace so a registration racing the expiry still counts correctly.
        assert_eq!(used_counter_ttl(60), Some(std::time::Duration::from_secs(120)));
        assert_eq!(used_counter_ttl(3600), Some(std::time::Duration::from_secs(3660)));
    }

    #[test]
    fn sha256_hex_is_stable() {
        // RFC 6234-style check: SHA-256 of the empty string.
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256_hex("tok").len(), 64);
    }

    #[tokio::test]
    async fn mint_verify_consume_revoke_roundtrip() {
        let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());
        let (id, token, data) =
            mint_initial_access_token(&cache, &realm_id(), 3600, 2).await.unwrap();
        assert!(token.starts_with(&format!("{id}.")));
        assert_eq!(data.count, 2);

        // Malformed / wrong-secret tokens are rejected without consuming uses.
        assert!(!verify_and_consume_initial_access_token(&cache, &realm_id(), "no-dot")
            .await
            .unwrap());
        let wrong = format!("{id}.{}", issuerd_core::utils::generate_id());
        assert!(!verify_and_consume_initial_access_token(&cache, &realm_id(), &wrong)
            .await
            .unwrap());

        // Exactly `count` uses succeed.
        assert!(verify_and_consume_initial_access_token(&cache, &realm_id(), &token)
            .await
            .unwrap());
        assert!(verify_and_consume_initial_access_token(&cache, &realm_id(), &token)
            .await
            .unwrap());
        assert!(!verify_and_consume_initial_access_token(&cache, &realm_id(), &token)
            .await
            .unwrap());

        revoke_initial_access_token(&cache, &realm_id(), &id).await.unwrap();
        assert!(!verify_and_consume_initial_access_token(&cache, &realm_id(), &token)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn unlimited_count_never_exhausts() {
        let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());
        let (_id, token, _data) =
            mint_initial_access_token(&cache, &realm_id(), 0, 0).await.unwrap();
        for _ in 0..5 {
            assert!(verify_and_consume_initial_access_token(&cache, &realm_id(), &token)
                .await
                .unwrap());
        }
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());
        // Mint with a 1-second TTL, then wait out the cache entry.
        let (_id, token, _data) =
            mint_initial_access_token(&cache, &realm_id(), 1, 0).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(!verify_and_consume_initial_access_token(&cache, &realm_id(), &token)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn create_list_consume_list_roundtrip_handler() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = initial_access_routes(state.clone());
        seed_test_realm(&state).await;

        // Mint via the admin endpoint: the raw token is returned exactly once.
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/realms/test/clients-initial-access",
                Body::from(r#"{"expiration":3600,"count":2}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created: InitialAccessTokenRepresentation = json_body(response).await;
        assert!(!created.id.is_empty());
        let raw = created.token.clone().expect("mint response carries the raw token");
        assert!(raw.starts_with(&format!("{}.", created.id)));
        assert_eq!(created.expiration, 3600);
        assert_eq!(created.count, 2);
        assert_eq!(created.remaining_count, 2);

        // The list shows the token without token material.
        let response = app
            .clone()
            .oneshot(request("GET", "/admin/realms/test/clients-initial-access", Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed: Vec<InitialAccessTokenRepresentation> = json_body(response).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.id);
        assert!(listed[0].token.is_none());
        assert_eq!(listed[0].expiration, 3600);
        assert_eq!(listed[0].count, 2);
        assert_eq!(listed[0].remaining_count, 2);

        // Consuming a use via the registration-side verifier decrements the
        // remaining count reported by the list handler.
        assert!(verify_and_consume_initial_access_token(&state.cache, &realm_id(), &raw)
            .await
            .unwrap());
        let response = app
            .clone()
            .oneshot(request("GET", "/admin/realms/test/clients-initial-access", Body::empty()))
            .await
            .unwrap();
        let listed: Vec<InitialAccessTokenRepresentation> = json_body(response).await;
        assert_eq!(listed[0].remaining_count, 1);

        assert!(verify_and_consume_initial_access_token(&state.cache, &realm_id(), &raw)
            .await
            .unwrap());
        let response = app
            .oneshot(request("GET", "/admin/realms/test/clients-initial-access", Body::empty()))
            .await
            .unwrap();
        let listed: Vec<InitialAccessTokenRepresentation> = json_body(response).await;
        assert_eq!(listed[0].remaining_count, 0);
        assert!(!verify_and_consume_initial_access_token(&state.cache, &realm_id(), &raw)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn create_defaults_to_unlimited_and_delete_revokes_idempotently() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = initial_access_routes(state.clone());
        seed_test_realm(&state).await;

        // Omitted expiration/count default to 0: never expires, unlimited uses.
        let response = app
            .clone()
            .oneshot(request("POST", "/admin/realms/test/clients-initial-access", Body::from("{}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created: InitialAccessTokenRepresentation = json_body(response).await;
        assert_eq!(created.expiration, 0);
        assert_eq!(created.count, 0);
        assert_eq!(created.remaining_count, 0);
        let raw = created.token.clone().unwrap();

        let response = app
            .clone()
            .oneshot(request(
                "DELETE",
                &format!("/admin/realms/test/clients-initial-access/{}", created.id),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Revoked: gone from the list and no longer verifiable.
        let response = app
            .clone()
            .oneshot(request("GET", "/admin/realms/test/clients-initial-access", Body::empty()))
            .await
            .unwrap();
        let listed: Vec<InitialAccessTokenRepresentation> = json_body(response).await;
        assert!(listed.is_empty());
        assert!(!verify_and_consume_initial_access_token(&state.cache, &realm_id(), &raw)
            .await
            .unwrap());

        // Revocation is deliberately idempotent (unlike Keycloak's 404):
        // re-deleting an unknown id still returns 204.
        let response = app
            .oneshot(request(
                "DELETE",
                &format!("/admin/realms/test/clients-initial-access/{}", created.id),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn handlers_return_404_for_unknown_realm() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = initial_access_routes(state);

        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/realms/ghost/clients-initial-access",
                Body::from("{}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .clone()
            .oneshot(request("GET", "/admin/realms/ghost/clients-initial-access", Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .oneshot(request(
                "DELETE",
                "/admin/realms/ghost/clients-initial-access/some-id",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn handlers_enforce_client_role_guards() {
        // view-clients may list but not mint or revoke.
        let viewer =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let app = initial_access_routes(viewer.clone());
        seed_test_realm(&viewer).await;

        let response = app
            .clone()
            .oneshot(request("GET", "/admin/realms/test/clients-initial-access", Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request("POST", "/admin/realms/test/clients-initial-access", Body::from("{}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(request(
                "DELETE",
                "/admin/realms/test/clients-initial-access/some-id",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // An unrelated admin role (manage-realm) grants no client access.
        let other =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = initial_access_routes(other.clone());
        seed_test_realm(&other).await;

        let response = app
            .clone()
            .oneshot(request("GET", "/admin/realms/test/clients-initial-access", Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(request("POST", "/admin/realms/test/clients-initial-access", Body::from("{}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn handlers_require_authentication() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = initial_access_routes(state.clone());
        seed_test_realm(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/clients-initial-access")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
