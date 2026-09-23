// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Login and admin event query endpoints plus realm events configuration.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use issuerd_core::{
    AdminEventQuery, EventQuery, OperationType, Pagination, RealmId, ResourceType, UserId,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{
        AdminEventQueryParams, AdminEventRepresentation, CountRepresentation, EventQueryParams,
        EventRepresentation, RealmEventsConfigRepresentation,
    },
    error::AdminApiError,
    state::AdminApiState,
};

/// Clamp the requested lower bound of an event query to the realm's retention
/// window: with `events_expiration_secs > 0`, events older than
/// `now - expiration` count as expired even when the caller requested an
/// earlier start.
fn clamp_date_from(
    requested: Option<chrono::DateTime<Utc>>,
    expiration_secs: i64,
) -> Option<chrono::DateTime<Utc>> {
    if expiration_secs <= 0 {
        return requested;
    }
    let cutoff = Utc::now() - chrono::Duration::seconds(expiration_secs);
    Some(requested.map_or(cutoff, |from| from.max(cutoff)))
}

fn build_event_query(params: EventQueryParams, expiration_secs: i64) -> EventQuery {
    EventQuery {
        event_type: params.event_type,
        client_id: None,
        user_id: None,
        date_from: clamp_date_from(
            params
                .date_from
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            expiration_secs,
        ),
        date_to: params
            .date_to
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc)),
        pagination: Pagination::new(params.first, params.max),
    }
}

fn build_admin_event_query(params: AdminEventQueryParams, expiration_secs: i64) -> AdminEventQuery {
    AdminEventQuery {
        operation_type: params.operation_type,
        resource_type: params.resource_type,
        auth_user_id: None,
        date_from: clamp_date_from(
            params
                .date_from
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            expiration_secs,
        ),
        date_to: params
            .date_to
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc)),
        pagination: Pagination::new(params.first, params.max),
    }
}

/// Resolve `(realm, user)` pairs to current usernames for display. Subjects
/// whose user no longer exists (deleted, or a federated user never imported)
/// are skipped — callers fall back to the ID or a recorded `username` detail.
async fn resolve_usernames(
    state: &AdminApiState,
    subjects: HashSet<(RealmId, UserId)>,
) -> HashMap<(RealmId, UserId), String> {
    let mut map = HashMap::with_capacity(subjects.len());
    for (realm, user_id) in subjects {
        if let Ok(Some(user)) = state.storage.get_user(&realm, &user_id).await {
            map.insert((realm, user_id), user.username.as_str().to_string());
        }
    }
    map
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/events",
    tag = "Events",
    summary = "Query audit events",
    description = "Queries authentication and admin audit events with optional filters. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        EventQueryParams
    ),
    responses(
        (status = 200, description = "List of matching events", body = Vec<EventRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn query_events(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<EventQueryParams>,
) -> Result<Json<Vec<EventRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let query = build_event_query(params, realm.events_expiration_secs);
    let events = state.storage.query_events(&realm.id, &query).await?;
    let subjects: HashSet<(RealmId, UserId)> = events
        .iter()
        .filter_map(|e| e.user_id.as_ref().map(|u| (realm.id.clone(), u.clone())))
        .collect();
    let usernames = resolve_usernames(&state, subjects).await;
    let reps = events
        .into_iter()
        .map(|e| {
            let username = e
                .user_id
                .as_ref()
                .and_then(|u| usernames.get(&(realm.id.clone(), u.clone())).cloned())
                .or_else(|| e.details.get("username").cloned());
            let mut rep = EventRepresentation::from(e);
            rep.username = username;
            rep
        })
        .collect();
    Ok(Json(reps))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/events/count",
    tag = "Events",
    summary = "Count audit events",
    description = "Counts authentication and admin audit events matching the given filters (pagination parameters are ignored), so list pages can render a total. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        EventQueryParams
    ),
    responses(
        (status = 200, description = "Number of matching events", body = CountRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn count_events(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<EventQueryParams>,
) -> Result<Json<CountRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let query = build_event_query(params, realm.events_expiration_secs);
    let count = state.storage.count_events(&realm.id, &query).await?;
    Ok(Json(CountRepresentation { count }))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/admin-events",
    tag = "Events",
    summary = "Query admin audit events",
    description = "Queries admin audit events with optional filters. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        AdminEventQueryParams
    ),
    responses(
        (status = 200, description = "List of matching admin events", body = Vec<AdminEventRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn query_admin_events(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<AdminEventQueryParams>,
) -> Result<Json<Vec<AdminEventRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let query = build_admin_event_query(params, realm.events_expiration_secs);
    let events = state.storage.query_admin_events(&realm.id, &query).await?;
    // The acting admin may belong to a different realm than the event (a
    // master-realm token can administer any realm).
    let subjects: HashSet<(RealmId, UserId)> = events
        .iter()
        .filter_map(|e| {
            e.auth_user_id
                .as_ref()
                .map(|u| (e.auth_realm_id.clone().unwrap_or_else(|| realm.id.clone()), u.clone()))
        })
        .collect();
    let usernames = resolve_usernames(&state, subjects).await;
    let reps = events
        .into_iter()
        .map(|e| {
            let auth_username = e.auth_user_id.as_ref().and_then(|u| {
                usernames
                    .get(&(e.auth_realm_id.clone().unwrap_or_else(|| realm.id.clone()), u.clone()))
                    .cloned()
            });
            let mut rep = AdminEventRepresentation::from(e);
            rep.auth_username = auth_username;
            rep
        })
        .collect();
    Ok(Json(reps))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/admin-events/count",
    tag = "Events",
    summary = "Count admin audit events",
    description = "Counts admin audit events matching the given filters (pagination parameters are ignored), so list pages can render a total. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        AdminEventQueryParams
    ),
    responses(
        (status = 200, description = "Number of matching admin events", body = CountRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn count_admin_events(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<AdminEventQueryParams>,
) -> Result<Json<CountRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let query = build_admin_event_query(params, realm.events_expiration_secs);
    let count = state.storage.count_admin_events(&realm.id, &query).await?;
    Ok(Json(CountRepresentation { count }))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/events/config",
    tag = "Events",
    summary = "Get realm events configuration",
    description = "Returns the realm's audit event configuration (recording toggles, retention, listeners). Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Events configuration", body = RealmEventsConfigRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_events_config(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<RealmEventsConfigRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    Ok(Json(RealmEventsConfigRepresentation::from(&realm)))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/events/config",
    tag = "Events",
    summary = "Update realm events configuration",
    description = "Partially updates the realm's audit event configuration; absent fields keep their current values. Listener ids are free-form (only `logging` is built in). Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Events configuration update", content = RealmEventsConfigRepresentation),
    responses(
        (status = 204, description = "Configuration updated"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_events_config(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<RealmEventsConfigRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let mut realm =
        state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    if let Some(enabled) = body.events_enabled {
        realm.events_enabled = enabled;
    }
    if let Some(expiration) = body.events_expiration {
        realm.events_expiration_secs = expiration;
    }
    if let Some(enabled) = body.admin_events_enabled {
        realm.admin_events_enabled = enabled;
    }
    if let Some(details) = body.admin_events_details_enabled {
        realm.include_representations = details;
    }
    if let Some(listeners) = &body.events_listeners {
        realm.events_listeners = listeners.clone();
    }
    state.storage.update_realm(&realm).await?;
    // The realm row changed; invalidate the cached realm-by-name entry
    // (best-effort — the 60 s TTL bounds staleness if the cache is down).
    if let Err(e) = state
        .cache
        .delete(&issuerd_cluster::cache_keys::realm_by_name(realm.name.as_str()))
        .await
    {
        tracing::warn!(realm = %realm.id, error = %e, "realm-by-name cache invalidation failed");
    }
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Update,
        ResourceType::Realm,
        &format!("realms/{}/events/config", realm.name),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/events",
    tag = "Events",
    summary = "Clear all login/user events",
    description = "Deletes every stored login/user event of the realm, then records the wipe itself as a fresh admin event so the audit log keeps the fact of the clear. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 204, description = "Events cleared"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn clear_events(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    state.storage.delete_events(&realm.id).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Delete,
        ResourceType::Realm,
        &format!("realms/{}/events", realm.name),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/admin-events",
    tag = "Events",
    summary = "Clear all admin events",
    description = "Deletes every stored admin audit event of the realm, then records the wipe itself as a fresh admin event so the audit log keeps the fact of the clear. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 204, description = "Admin events cleared"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn clear_admin_events(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    state.storage.delete_admin_events(&realm.id).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Delete,
        ResourceType::Realm,
        &format!("realms/{}/admin-events", realm.name),
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
        routing::get,
        Router,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    fn event_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/events", get(query_events))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn event_query_by_type() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = event_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let ev = issuerd_core::Event {
            id: issuerd_core::EventId::new("event-1").unwrap(),
            realm_id: realm.id.clone(),
            event_time: Utc::now(),
            event_type: issuerd_core::EventType::Login,
            ip_address: None,
            client_id: None,
            user_id: None,
            session_id: None,
            error: None,
            details: std::collections::HashMap::new(),
        };
        state.storage.save_event(&realm.id, &ev).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/events?event_type=login")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<EventRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
    }

    #[tokio::test]
    async fn event_query_with_date_range() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = event_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let now = Utc::now();
        let ev = issuerd_core::Event {
            id: issuerd_core::EventId::new("event-1").unwrap(),
            realm_id: realm.id.clone(),
            event_time: now,
            event_type: issuerd_core::EventType::Login,
            ip_address: None,
            client_id: None,
            user_id: None,
            session_id: None,
            error: None,
            details: std::collections::HashMap::new(),
        };
        state.storage.save_event(&realm.id, &ev).await.unwrap();

        let from = (now - chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let to = (now + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let uri = format!("/admin/realms/test/events?date_from={from}&date_to={to}");

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<EventRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
    }

    fn admin_event_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/admin-events", get(query_admin_events))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn admin_event_query_by_operation_type() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = admin_event_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let ev = issuerd_core::AdminEvent {
            id: issuerd_core::EventId::new("ae-1").unwrap(),
            realm_id: realm.id.clone(),
            auth_realm_id: Some(issuerd_core::RealmId::new("master").unwrap()),
            auth_client_id: Some(issuerd_core::ClientId::new("admin-cli").unwrap()),
            auth_user_id: Some(issuerd_core::UserId::new("admin").unwrap()),
            operation_type: issuerd_core::OperationType::Create,
            resource_type: issuerd_core::ResourceType::User,
            resource_path: "users/user-1".to_string(),
            representation: None,
            error: None,
            event_time: Utc::now(),
        };
        state.storage.save_admin_event(&ev).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/admin-events?operation_type=CREATE")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<AdminEventRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
        assert_eq!(reps[0].operation_type, issuerd_core::OperationType::Create);
    }

    #[tokio::test]
    async fn admin_event_query_by_resource_type() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = admin_event_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let ev1 = issuerd_core::AdminEvent {
            id: issuerd_core::EventId::new("ae-1").unwrap(),
            realm_id: realm.id.clone(),
            auth_realm_id: Some(issuerd_core::RealmId::new("master").unwrap()),
            auth_client_id: Some(issuerd_core::ClientId::new("admin-cli").unwrap()),
            auth_user_id: Some(issuerd_core::UserId::new("admin").unwrap()),
            operation_type: issuerd_core::OperationType::Create,
            resource_type: issuerd_core::ResourceType::User,
            resource_path: "users/user-1".to_string(),
            representation: None,
            error: None,
            event_time: Utc::now(),
        };
        let ev2 = issuerd_core::AdminEvent {
            id: issuerd_core::EventId::new("ae-2").unwrap(),
            realm_id: realm.id.clone(),
            auth_realm_id: Some(issuerd_core::RealmId::new("master").unwrap()),
            auth_client_id: Some(issuerd_core::ClientId::new("admin-cli").unwrap()),
            auth_user_id: Some(issuerd_core::UserId::new("admin").unwrap()),
            operation_type: issuerd_core::OperationType::Create,
            resource_type: issuerd_core::ResourceType::Client,
            resource_path: "clients/client-1".to_string(),
            representation: None,
            error: None,
            event_time: Utc::now(),
        };
        state.storage.save_admin_event(&ev1).await.unwrap();
        state.storage.save_admin_event(&ev2).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/admin-events?resource_type=CLIENT")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<AdminEventRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
        assert_eq!(reps[0].resource_type, issuerd_core::ResourceType::Client);
    }

    // ------------------------------------------------------------------
    // Events config + clear + expiration clamping
    // ------------------------------------------------------------------

    fn config_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/events/config",
                get(get_events_config).put(update_events_config),
            )
            .route("/admin/realms/{realm}/events", get(query_events).delete(clear_events))
            .route("/admin/realms/{realm}/events/count", get(count_events))
            .route(
                "/admin/realms/{realm}/admin-events",
                get(query_admin_events).delete(clear_admin_events),
            )
            .route("/admin/realms/{realm}/admin-events/count", get(count_admin_events))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    async fn create_test_realm(state: &Arc<AdminApiState>, realm: issuerd_core::Realm) {
        state.storage.create_realm(&realm).await.unwrap();
    }

    fn test_realm() -> issuerd_core::Realm {
        issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        }
    }

    fn sample_event(
        id: &str,
        realm_id: &issuerd_core::RealmId,
        event_time: chrono::DateTime<Utc>,
    ) -> issuerd_core::Event {
        issuerd_core::Event {
            id: issuerd_core::EventId::new(id).unwrap(),
            realm_id: realm_id.clone(),
            event_time,
            event_type: issuerd_core::EventType::Login,
            ip_address: None,
            client_id: None,
            user_id: None,
            session_id: None,
            error: None,
            details: std::collections::HashMap::new(),
        }
    }

    fn sample_admin_event(id: &str, realm_id: &issuerd_core::RealmId) -> issuerd_core::AdminEvent {
        issuerd_core::AdminEvent {
            id: issuerd_core::EventId::new(id).unwrap(),
            realm_id: realm_id.clone(),
            auth_realm_id: Some(issuerd_core::RealmId::new("master").unwrap()),
            auth_client_id: Some(issuerd_core::ClientId::new("admin-cli").unwrap()),
            auth_user_id: Some(issuerd_core::UserId::new("admin").unwrap()),
            operation_type: issuerd_core::OperationType::Create,
            resource_type: issuerd_core::ResourceType::User,
            resource_path: "users/user-1".to_string(),
            representation: None,
            error: None,
            event_time: Utc::now(),
        }
    }

    async fn call(
        app: Router,
        method: &str,
        uri: &str,
        body: Option<String>,
    ) -> (StatusCode, Vec<u8>) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", "Bearer valid-token");
        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }
        let response = app
            .oneshot(builder.body(Body::from(body.unwrap_or_default())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, bytes.to_vec())
    }

    #[tokio::test]
    async fn events_config_get_returns_defaults() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        create_test_realm(&state, test_realm()).await;

        let (status, body) = call(app, "GET", "/admin/realms/test/events/config", None).await;
        assert_eq!(status, StatusCode::OK);
        let config: RealmEventsConfigRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(config.events_enabled, Some(true));
        assert_eq!(config.events_expiration, Some(0));
        assert_eq!(config.admin_events_enabled, Some(true));
        assert_eq!(config.admin_events_details_enabled, Some(false));
        assert_eq!(config.events_listeners, Some(vec!["logging".to_string()]));
    }

    #[tokio::test]
    async fn events_config_put_applies_partial_update() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        create_test_realm(&state, test_realm()).await;

        let (status, _) = call(
            app.clone(),
            "PUT",
            "/admin/realms/test/events/config",
            Some(r#"{"eventsEnabled":true,"eventsExpiration":3600}"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, body) =
            call(app.clone(), "GET", "/admin/realms/test/events/config", None).await;
        assert_eq!(status, StatusCode::OK);
        let config: RealmEventsConfigRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(config.events_enabled, Some(true));
        assert_eq!(config.events_expiration, Some(3600));
        // Untouched fields keep their current values.
        assert_eq!(config.admin_events_enabled, Some(true));
        assert_eq!(config.admin_events_details_enabled, Some(false));
        assert_eq!(config.events_listeners, Some(vec!["logging".to_string()]));

        // Unknown listener ids are accepted (custom SPIs); the value round-trips.
        let (status, _) = call(
            app,
            "PUT",
            "/admin/realms/test/events/config",
            Some(r#"{"eventsListeners":["logging","acme-audit"]}"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let realm = state
            .storage
            .get_realm(&issuerd_core::RealmId::new("realm-1").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(realm.events_listeners, vec!["logging".to_string(), "acme-audit".to_string()]);
    }

    #[tokio::test]
    async fn events_config_put_invalidates_realm_by_name_cache() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        create_test_realm(&state, test_realm()).await;

        // Seed the realm-by-name entry `resolve_issuer_realm` populates.
        let key = issuerd_cluster::cache_keys::realm_by_name("test");
        let realm = state.storage.get_realm_by_name("test").await.unwrap().unwrap();
        state.cache.set(&key, serde_json::to_vec(&realm).unwrap(), None).await.unwrap();

        let (status, _) = call(
            app,
            "PUT",
            "/admin/realms/test/events/config",
            Some(r#"{"eventsEnabled":false}"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            state.cache.get(&key).await.unwrap().is_none(),
            "events-config save invalidated the realm-by-name cache entry"
        );
    }

    #[tokio::test]
    async fn query_events_clamps_date_from_to_retention_window() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        let mut realm = test_realm();
        realm.events_expiration_secs = 3600;
        create_test_realm(&state, realm.clone()).await;

        let now = Utc::now();
        state
            .storage
            .save_event(
                &realm.id,
                &sample_event("ev-old", &realm.id, now - chrono::Duration::days(2)),
            )
            .await
            .unwrap();
        state
            .storage
            .save_event(&realm.id, &sample_event("ev-fresh", &realm.id, now))
            .await
            .unwrap();

        // No explicit date_from: the retention window still excludes the old event.
        let (status, body) =
            call(app.clone(), "GET", "/admin/realms/test/events?max=50", None).await;
        assert_eq!(status, StatusCode::OK);
        let reps: Vec<EventRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
        assert_eq!(reps[0].id.as_deref(), Some("ev-fresh"));

        // An explicit date_from older than the cutoff is clamped to the cutoff.
        let from = (now - chrono::Duration::days(3)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let (status, body) =
            call(app, "GET", &format!("/admin/realms/test/events?date_from={from}&max=50"), None)
                .await;
        assert_eq!(status, StatusCode::OK);
        let reps: Vec<EventRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
        assert_eq!(reps[0].id.as_deref(), Some("ev-fresh"));
    }

    #[tokio::test]
    async fn query_events_without_expiration_returns_old_events() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        let realm = test_realm();
        create_test_realm(&state, realm.clone()).await;

        let now = Utc::now();
        state
            .storage
            .save_event(
                &realm.id,
                &sample_event("ev-old", &realm.id, now - chrono::Duration::days(2)),
            )
            .await
            .unwrap();
        state
            .storage
            .save_event(&realm.id, &sample_event("ev-fresh", &realm.id, now))
            .await
            .unwrap();

        let (status, body) = call(app, "GET", "/admin/realms/test/events?max=50", None).await;
        assert_eq!(status, StatusCode::OK);
        let reps: Vec<EventRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 2);
    }

    #[tokio::test]
    async fn clear_events_removes_rows_and_records_the_wipe() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        let mut realm = test_realm();
        realm.admin_events_enabled = true;
        create_test_realm(&state, realm.clone()).await;
        state
            .storage
            .save_event(&realm.id, &sample_event("ev-1", &realm.id, Utc::now()))
            .await
            .unwrap();

        let (status, _) = call(app, "DELETE", "/admin/realms/test/events", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let remaining = state
            .storage
            .query_events(
                &realm.id,
                &EventQuery {
                    event_type: None,
                    client_id: None,
                    user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert!(remaining.is_empty());

        // The wipe itself is preserved as one fresh admin event.
        let admin_events = state
            .storage
            .query_admin_events(
                &realm.id,
                &AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(admin_events.len(), 1);
        assert_eq!(admin_events[0].operation_type, issuerd_core::OperationType::Delete);
        assert_eq!(admin_events[0].resource_path, "realms/test/events");
    }

    #[tokio::test]
    async fn clear_admin_events_removes_rows_and_records_the_wipe() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        let mut realm = test_realm();
        realm.admin_events_enabled = true;
        create_test_realm(&state, realm.clone()).await;
        state
            .storage
            .save_admin_event(&sample_admin_event("ae-1", &realm.id))
            .await
            .unwrap();
        state
            .storage
            .save_admin_event(&sample_admin_event("ae-2", &realm.id))
            .await
            .unwrap();

        let (status, _) = call(app, "DELETE", "/admin/realms/test/admin-events", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Only the fresh "wipe" record remains.
        let admin_events = state
            .storage
            .query_admin_events(
                &realm.id,
                &AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(admin_events.len(), 1);
        assert_eq!(admin_events[0].operation_type, issuerd_core::OperationType::Delete);
        assert_eq!(admin_events[0].resource_path, "realms/test/admin-events");
    }

    #[tokio::test]
    async fn events_config_requires_manage_realm_for_put() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        create_test_realm(&state, test_realm()).await;

        let (status, _) = call(
            app,
            "PUT",
            "/admin/realms/test/events/config",
            Some(r#"{"eventsEnabled":true}"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn events_config_unknown_realm_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state);

        let (status, _) = call(app, "GET", "/admin/realms/nope/events/config", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ------------------------------------------------------------------
    // Count endpoints + username resolution
    // ------------------------------------------------------------------

    async fn create_test_user(
        state: &Arc<AdminApiState>,
        realm_id: &issuerd_core::RealmId,
        id: &str,
        username: &str,
    ) {
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new(id).unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new(username).unwrap(),
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
        state.storage.create_user(realm_id, &user).await.unwrap();
    }

    #[tokio::test]
    async fn count_events_matches_filtered_total() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        create_test_realm(&state, test_realm()).await;

        let realm = test_realm();
        let now = Utc::now();
        state
            .storage
            .save_event(&realm.id, &sample_event("ev-1", &realm.id, now))
            .await
            .unwrap();
        state
            .storage
            .save_event(&realm.id, &sample_event("ev-2", &realm.id, now))
            .await
            .unwrap();
        let mut logout = sample_event("ev-3", &realm.id, now);
        logout.event_type = issuerd_core::EventType::Logout;
        state.storage.save_event(&realm.id, &logout).await.unwrap();

        let (status, body) =
            call(app.clone(), "GET", "/admin/realms/test/events/count", None).await;
        assert_eq!(status, StatusCode::OK);
        let count: crate::dto::CountRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(count.count, 3);

        // The count honors the same filters as the list endpoint.
        let (status, body) =
            call(app, "GET", "/admin/realms/test/events/count?event_type=logout", None).await;
        assert_eq!(status, StatusCode::OK);
        let count: crate::dto::CountRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(count.count, 1);
    }

    #[tokio::test]
    async fn count_events_applies_retention_clamp() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        let mut realm = test_realm();
        realm.events_expiration_secs = 3600;
        create_test_realm(&state, realm.clone()).await;

        let now = Utc::now();
        state
            .storage
            .save_event(
                &realm.id,
                &sample_event("ev-old", &realm.id, now - chrono::Duration::days(2)),
            )
            .await
            .unwrap();
        state
            .storage
            .save_event(&realm.id, &sample_event("ev-fresh", &realm.id, now))
            .await
            .unwrap();

        let (status, body) = call(app, "GET", "/admin/realms/test/events/count", None).await;
        assert_eq!(status, StatusCode::OK);
        let count: crate::dto::CountRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(count.count, 1);
    }

    #[tokio::test]
    async fn count_admin_events_matches_filtered_total() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        create_test_realm(&state, test_realm()).await;

        let realm = test_realm();
        state
            .storage
            .save_admin_event(&sample_admin_event("ae-1", &realm.id))
            .await
            .unwrap();
        state
            .storage
            .save_admin_event(&sample_admin_event("ae-2", &realm.id))
            .await
            .unwrap();

        let (status, body) =
            call(app.clone(), "GET", "/admin/realms/test/admin-events/count", None).await;
        assert_eq!(status, StatusCode::OK);
        let count: crate::dto::CountRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(count.count, 2);

        let (status, body) =
            call(app, "GET", "/admin/realms/test/admin-events/count?operation_type=DELETE", None)
                .await;
        assert_eq!(status, StatusCode::OK);
        let count: crate::dto::CountRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(count.count, 0);
    }

    #[tokio::test]
    async fn query_events_resolves_username_and_falls_back_to_details() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        let realm = test_realm();
        create_test_realm(&state, realm.clone()).await;
        create_test_user(&state, &realm.id, "user-1", "alice").await;

        let now = Utc::now();
        // Existing user: username resolved from storage; session id exposed.
        let mut ev1 = sample_event("ev-1", &realm.id, now);
        ev1.user_id = Some(issuerd_core::UserId::new("user-1").unwrap());
        ev1.session_id = Some(issuerd_core::SessionId::new("session-1").unwrap());
        state.storage.save_event(&realm.id, &ev1).await.unwrap();

        // Deleted / never-imported user: fall back to the recorded detail.
        let mut ev2 = sample_event("ev-2", &realm.id, now);
        ev2.user_id = Some(issuerd_core::UserId::new("ghost").unwrap());
        ev2.details.insert("username".to_string(), "ghosty".to_string());
        state.storage.save_event(&realm.id, &ev2).await.unwrap();

        // No user attached at all.
        let ev3 = sample_event("ev-3", &realm.id, now);
        state.storage.save_event(&realm.id, &ev3).await.unwrap();

        let (status, body) = call(app, "GET", "/admin/realms/test/events", None).await;
        assert_eq!(status, StatusCode::OK);
        let reps: Vec<EventRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 3);

        let by_id = |id: &str| reps.iter().find(|r| r.id.as_deref() == Some(id)).unwrap();
        assert_eq!(by_id("ev-1").username.as_deref(), Some("alice"));
        assert_eq!(by_id("ev-1").session_id.as_deref(), Some("session-1"));
        assert_eq!(by_id("ev-2").username.as_deref(), Some("ghosty"));
        assert_eq!(by_id("ev-3").username, None);
    }

    #[tokio::test]
    async fn query_admin_events_resolves_auth_username() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = config_routes(state.clone());
        let realm = test_realm();
        create_test_realm(&state, realm.clone()).await;
        create_test_user(&state, &realm.id, "admin-1", "root").await;

        let mut ev = sample_admin_event("ae-1", &realm.id);
        ev.auth_realm_id = Some(realm.id.clone());
        ev.auth_user_id = Some(issuerd_core::UserId::new("admin-1").unwrap());
        state.storage.save_admin_event(&ev).await.unwrap();

        // Unresolvable auth user: auth_username stays absent.
        let mut ev2 = sample_admin_event("ae-2", &realm.id);
        ev2.auth_realm_id = Some(realm.id.clone());
        ev2.auth_user_id = Some(issuerd_core::UserId::new("gone").unwrap());
        state.storage.save_admin_event(&ev2).await.unwrap();

        let (status, body) = call(app, "GET", "/admin/realms/test/admin-events", None).await;
        assert_eq!(status, StatusCode::OK);
        let reps: Vec<AdminEventRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 2);

        let by_id = |id: &str| reps.iter().find(|r| r.id.as_deref() == Some(id)).unwrap();
        assert_eq!(by_id("ae-1").auth_username.as_deref(), Some("root"));
        assert_eq!(by_id("ae-2").auth_username, None);
    }
}
