// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Brute-force attack-detection endpoints: lockout status and reset.

//! Brute-force attack-detection endpoints (Keycloak's `attack-detection` API).
//!
//! Login-failure tracking (`issuerd-auth-flow`'s `LoginFailureTracker`) stores two
//! key families in the distributed cache:
//!
//! - `login-failure:{realm_id}:{username}:{ip}` — consecutive failure counter
//! - `login-lockout:{realm_id}:{username}:{ip}` — lockout marker (TTL-bound)
//!
//! Key parsing caveat: the format is colon-delimited and the IP is recovered
//! with `rsplit_once(':')`, so usernames containing `:` still parse correctly,
//! but IPv6 addresses do not (their colons are indistinguishable from the
//! field separators).

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{OperationType, RealmId, ResourceType, UserId};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{BruteForceLockoutRepresentation, BruteForceUserStatusRepresentation},
    error::AdminApiError,
    state::AdminApiState,
};

/// Counter key prefix (without realm/username/ip segments).
const FAILURE_PREFIX: &str = "login-failure";
/// Lockout-marker key prefix (without realm/username/ip segments).
const LOCKOUT_PREFIX: &str = "login-lockout";

/// Read the consecutive-failure counter for one (username, IP) pair; a
/// missing or unparsable counter reads as 0.
async fn failure_count(
    state: &AdminApiState,
    realm_id: &RealmId,
    username: &str,
    ip: &str,
) -> Result<u32, AdminApiError> {
    let key = format!("{FAILURE_PREFIX}:{realm_id}:{username}:{ip}");
    let count = state
        .cache
        .get(&key)
        .await?
        .and_then(|raw| std::str::from_utf8(&raw).ok()?.parse::<u32>().ok())
        .unwrap_or(0);
    Ok(count)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/attack-detection/brute-force/users",
    tag = "Attack Detection",
    summary = "List locked-out users",
    description = "Returns every (username, IP) pair currently locked out by brute-force detection, with its consecutive failure count. Requires `manage-users` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Locked-out (username, IP) pairs", body = Vec<BruteForceLockoutRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_locked_users(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<Vec<BruteForceLockoutRepresentation>>, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let prefix = format!("{LOCKOUT_PREFIX}:{}:", realm.id);
    let mut locked = Vec::new();
    for key in state.cache.scan_keys(&format!("{prefix}*")).await? {
        let Some((username, ip)) = key.strip_prefix(&prefix).and_then(|s| s.rsplit_once(':'))
        else {
            continue;
        };
        // Resolve the username to a user id so the UI can unlock directly;
        // `None` when the user no longer exists in the realm.
        let user_id = state
            .storage
            .get_user_by_username(&realm.id, username)
            .await?
            .map(|u| u.id.to_string());
        locked.push(BruteForceLockoutRepresentation {
            username: username.to_string(),
            ip: ip.to_string(),
            num_failures: failure_count(&state, &realm.id, username, ip).await?,
            user_id,
        });
    }
    // Deterministic output for UI tables: cache iteration order is undefined.
    locked.sort_by(|a, b| a.username.cmp(&b.username).then_with(|| a.ip.cmp(&b.ip)));
    Ok(Json(locked))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/attack-detection/brute-force/users/{id}",
    tag = "Attack Detection",
    summary = "Get brute-force status for a user",
    description = "Returns the aggregated login-failure count (across all source IPs) and lockout state for the given user. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Brute-force status", body = BruteForceUserStatusRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_user_brute_force_status(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<BruteForceUserStatusRepresentation>, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let user = state
        .storage
        .get_user(&realm.id, &user_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    let username = user.username.to_string();

    let mut num_failures = 0u32;
    let failure_pattern = format!("{FAILURE_PREFIX}:{}:{username}:*", realm.id);
    for key in state.cache.scan_keys(&failure_pattern).await? {
        if let Some(raw) = state.cache.get(&key).await? {
            let count =
                std::str::from_utf8(&raw).ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            num_failures = num_failures.saturating_add(count);
        }
    }
    let lockout_pattern = format!("{LOCKOUT_PREFIX}:{}:{username}:*", realm.id);
    let locked = !state.cache.scan_keys(&lockout_pattern).await?.is_empty();

    Ok(Json(BruteForceUserStatusRepresentation {
        user_id: user.id.to_string(),
        username,
        num_failures,
        locked,
    }))
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/attack-detection/brute-force/users/{id}",
    tag = "Attack Detection",
    summary = "Clear brute-force state for a user",
    description = "Deletes all login-failure counters and lockout markers for the given user across every source IP, unlocking the account. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 204, description = "Brute-force state cleared"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn clear_user_brute_force_state(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let user = state
        .storage
        .get_user(&realm.id, &user_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    let username = user.username.to_string();

    for prefix in [FAILURE_PREFIX, LOCKOUT_PREFIX] {
        let pattern = format!("{prefix}:{}:{username}:*", realm.id);
        for key in state.cache.scan_keys(&pattern).await? {
            state.cache.delete(&key).await?;
        }
    }
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{id}"),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use issuerd_core::DistributedCache;
    use std::collections::HashMap;
    use tower::ServiceExt;

    /// Build a state whose cache the test seeds directly, plus a handle to
    /// that same cache for assertions.
    fn test_state_with_cache(
        roles: Vec<issuerd_core::RoleName>,
        cache: Arc<issuerd_cluster::InMemoryCache>,
    ) -> Arc<AdminApiState> {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));
        Arc::new(AdminApiState {
            storage: crate::test_utils::tests::storage_with_master_realm(),
            token_service: Arc::new(crate::test_utils::tests::MockTokenService { roles }),
            crypto: Arc::new(mock),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache,
            email_sender: Arc::new(issuerd_core::MockEmailSender::new()),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            base_url: "http://localhost:8080".to_string(),
        })
    }

    fn attack_detection_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/attack-detection/brute-force/users",
                get(list_locked_users),
            )
            .route(
                "/admin/realms/{realm}/attack-detection/brute-force/users/{id}",
                get(get_user_brute_force_status).delete(clear_user_brute_force_state),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    /// Seed the `test` realm (id `realm-1`) with user `alice` (id `user-1`).
    async fn create_test_realm_and_user(state: &Arc<AdminApiState>) {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("user-1").unwrap(),
            realm_id: realm.id.clone(),
            username: issuerd_core::Username::new("alice").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm.id, &user).await.unwrap();
    }

    /// Seed lockout + counter keys for alice from two source IPs.
    async fn seed_lockout_keys(cache: &Arc<issuerd_cluster::InMemoryCache>) {
        cache
            .set("login-failure:realm-1:alice:10.0.0.1", b"3".to_vec(), None)
            .await
            .unwrap();
        cache
            .set("login-failure:realm-1:alice:10.0.0.2", b"2".to_vec(), None)
            .await
            .unwrap();
        cache
            .set("login-lockout:realm-1:alice:10.0.0.1", b"1".to_vec(), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_locked_users_shows_lockout() {
        let cache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let state = test_state_with_cache(
            vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            cache.clone(),
        );
        create_test_realm_and_user(&state).await;
        seed_lockout_keys(&cache).await;
        let app = attack_detection_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/attack-detection/brute-force/users")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let locked: Vec<BruteForceLockoutRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            locked,
            vec![BruteForceLockoutRepresentation {
                username: "alice".to_string(),
                ip: "10.0.0.1".to_string(),
                num_failures: 3,
                user_id: Some("user-1".to_string()),
            }]
        );
    }

    #[tokio::test]
    async fn get_user_status_aggregates_failures_and_lockout() {
        let cache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let state = test_state_with_cache(
            vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            cache.clone(),
        );
        create_test_realm_and_user(&state).await;
        seed_lockout_keys(&cache).await;
        let app = attack_detection_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/attack-detection/brute-force/users/user-1")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let status: BruteForceUserStatusRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            status,
            BruteForceUserStatusRepresentation {
                user_id: "user-1".to_string(),
                username: "alice".to_string(),
                num_failures: 5,
                locked: true,
            }
        );
    }

    #[tokio::test]
    async fn delete_user_status_unlocks_and_clears_counters() {
        let cache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let state = test_state_with_cache(
            vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            cache.clone(),
        );
        create_test_realm_and_user(&state).await;
        seed_lockout_keys(&cache).await;
        let app = attack_detection_routes(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/realms/test/attack-detection/brute-force/users/user-1")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(cache.scan_keys("login-failure:realm-1:alice:*").await.unwrap().is_empty());
        assert!(cache.scan_keys("login-lockout:realm-1:alice:*").await.unwrap().is_empty());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/attack-detection/brute-force/users/user-1")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let status: BruteForceUserStatusRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.num_failures, 0);
        assert!(!status.locked);
    }

    #[tokio::test]
    async fn get_user_status_unknown_user_is_404() {
        let cache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let state = test_state_with_cache(
            vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            cache,
        );
        create_test_realm_and_user(&state).await;
        let app = attack_detection_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/attack-detection/brute-force/users/nope")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn attack_detection_requires_manage_users() {
        let cache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let state =
            test_state_with_cache(vec![issuerd_core::RoleName::new("view-realm").unwrap()], cache);
        create_test_realm_and_user(&state).await;
        let app = attack_detection_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/attack-detection/brute-force/users")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
