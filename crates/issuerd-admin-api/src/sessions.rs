// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Session administration endpoints: list and revoke active user sessions.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{OperationType, Pagination, ResourceType, SessionId};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{CountRepresentation, PaginationQueryParams, UserSessionRepresentation},
    error::AdminApiError,
    state::AdminApiState,
};

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/sessions",
    tag = "Sessions",
    summary = "List active sessions",
    description = "Returns a paginated list of active user sessions in the realm. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        PaginationQueryParams
    ),
    responses(
        (status = 200, description = "List of active sessions", body = Vec<UserSessionRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_sessions(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<PaginationQueryParams>,
) -> Result<Json<Vec<UserSessionRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let sessions = state
        .storage
        .list_sessions(&realm_id, None, &Pagination::new(params.first, params.max))
        .await?;
    Ok(Json(sessions.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/sessions/count",
    tag = "Sessions",
    summary = "Count active sessions",
    description = "Returns the total number of active user sessions in the realm. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Session count", body = CountRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn count_sessions(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<CountRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let count = state.storage.count_sessions(&realm_id, None).await?;
    Ok(Json(CountRepresentation { count }))
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/sessions/{session}",
    tag = "Sessions",
    summary = "Revoke a session",
    description = "Deletes a user session, effectively logging the user out. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("session" = String, Path, description = "Session ID")
    ),
    responses(
        (status = 204, description = "Session revoked successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or session not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_session(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, session)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let realm_id = realm.id.clone();
    let session_id =
        SessionId::new(&session).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    // Fetch before delete so the back-channel logout dispatcher can still see
    // the session's client sessions. Best-effort: if the session
    // is already gone there is nothing to notify about.
    let existing = state.storage.get_user_session(&realm_id, &session_id).await?;
    state.storage.delete_user_session(&realm_id, &session_id).await?;
    // Drop the session-validity cache entry so userinfo/introspect see the
    // revocation immediately instead of after the snapshot TTL (best-effort:
    // the TTL bounds staleness if the cache is down).
    if let Err(e) = state
        .cache
        .delete(&issuerd_cluster::cache_keys::session(realm_id.as_ref(), session_id.as_ref()))
        .await
    {
        tracing::warn!(realm = %realm_id, error = %e, "session cache invalidation failed");
    }
    if let Some(existing) = existing {
        state.logout_notifier.notify_session_destroyed(&realm, &existing).await;
    }
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::Session,
        &format!("sessions/{}", session),
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
        http::{Request, StatusCode},
        routing::{delete, get},
        Router,
    };
    use chrono::Utc;
    use issuerd_core::AuthMethod;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn session_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/sessions", get(list_sessions))
            .route("/admin/realms/{realm}/sessions/{session}", delete(delete_session))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    async fn seed_realm_user_session(state: &Arc<AdminApiState>) {
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
            attributes: std::collections::HashMap::new(),
            required_actions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        state.storage.create_user(&realm.id, &user).await.unwrap();

        let session = issuerd_core::UserSession {
            id: issuerd_core::SessionId::new("session-1").unwrap(),
            realm_id: realm.id.clone(),
            user_id: user.id.clone(),
            login_username: issuerd_core::Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
            clients: vec![],
        };
        state.storage.create_user_session(&realm.id, &session).await.unwrap();
    }

    #[tokio::test]
    async fn session_list_and_delete() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = session_routes(state.clone());
        seed_realm_user_session(&state).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/sessions")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/realms/test/sessions/session-1")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_session_invalidates_session_cache() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = session_routes(state.clone());
        seed_realm_user_session(&state).await;

        // Seed the session-validity cache entry userinfo/introspect populate.
        let key = issuerd_cluster::cache_keys::session("realm-1", "session-1");
        state.cache.set(&key, br#"{"u":"user-1","v":0}"#.to_vec(), None).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/realms/test/sessions/session-1")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            state.cache.get(&key).await.unwrap().is_none(),
            "admin session revoke dropped the cached validity snapshot"
        );
    }
}
