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

    fn realm_id() -> RealmId {
        RealmId::new("realm-1").unwrap()
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
}
