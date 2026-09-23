// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Realm role CRUD endpoints and shared role-mapping resolution helpers.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
#[cfg(test)]
use issuerd_core::RoleName;
use issuerd_core::{OperationType, Pagination, ResourceType};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{
        ClientMappingsRepresentation, CountRepresentation, MappingsRepresentation,
        PaginationQueryParams, RoleRepresentation,
    },
    error::AdminApiError,
    state::AdminApiState,
};

// ---------------------------------------------------------------------------
// Shared role-mapping helpers (users / groups / client scope-mappings)
// ---------------------------------------------------------------------------

/// Resolve a `Vec<RoleRepresentation>` request body into stored roles by id.
/// A body entry without an id is a 400; an unknown id is a 404 (Keycloak
/// behavior for the role-mapping endpoints).
pub(crate) async fn resolve_role_representations(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    reps: Vec<RoleRepresentation>,
) -> Result<Vec<issuerd_core::Role>, AdminApiError> {
    let mut roles = Vec::with_capacity(reps.len());
    for rep in reps {
        let id = rep
            .id
            .ok_or_else(|| AdminApiError::BadRequest("role id is required".to_string()))?;
        let role = state
            .storage
            .get_role(realm_id, &issuerd_core::RoleId::new(&id)?)
            .await?
            .ok_or(AdminApiError::NotFound)?;
        roles.push(role);
    }
    Ok(roles)
}

/// Resolve role ids to stored roles, silently skipping dangling references —
/// a role deleted through another path must not break mapping reads.
pub(crate) async fn roles_by_ids(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    ids: Vec<issuerd_core::RoleId>,
) -> Result<Vec<issuerd_core::Role>, AdminApiError> {
    let mut roles = Vec::with_capacity(ids.len());
    for id in &ids {
        if let Some(role) = state.storage.get_role(realm_id, id).await? {
            roles.push(role);
        }
    }
    Ok(roles)
}

/// Build the combined [`MappingsRepresentation`] from already-resolved roles:
/// realm roles go to `realm_mappings`, client roles are grouped under
/// `client_mappings` keyed by the owning client's `client_id` string.
pub(crate) async fn build_mappings_representation(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    roles: Vec<issuerd_core::Role>,
) -> Result<MappingsRepresentation, AdminApiError> {
    let mut realm_mappings: Vec<RoleRepresentation> = Vec::new();
    let mut by_client: std::collections::HashMap<issuerd_core::ClientId, Vec<issuerd_core::Role>> =
        std::collections::HashMap::new();
    for role in roles {
        if role.client_role {
            if let Some(owner) = &role.client_id {
                by_client.entry(owner.clone()).or_default().push(role);
            }
        } else {
            realm_mappings.push(role.into());
        }
    }
    let mut client_mappings = std::collections::HashMap::new();
    for (owner_id, roles) in by_client {
        if let Some(client) = state.storage.get_client(realm_id, &owner_id).await? {
            client_mappings.insert(
                client.client_id.to_string(),
                ClientMappingsRepresentation {
                    id: client.id.to_string(),
                    client: client.client_id.to_string(),
                    mappings: roles.into_iter().map(Into::into).collect(),
                },
            );
        }
    }
    Ok(MappingsRepresentation {
        realm_mappings: (!realm_mappings.is_empty()).then_some(realm_mappings),
        client_mappings: (!client_mappings.is_empty()).then_some(client_mappings),
    })
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/roles",
    tag = "Roles",
    summary = "List realm roles",
    description = "Returns a paginated list of realm-level roles. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        PaginationQueryParams
    ),
    responses(
        (status = 200, description = "List of realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<PaginationQueryParams>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let roles = state
        .storage
        .list_roles(&realm_id, &Pagination::new(params.first, params.max))
        .await?;
    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/roles/count",
    tag = "Roles",
    summary = "Count realm roles",
    description = "Returns the total number of realm-level roles. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Role count", body = CountRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn count_realm_roles(
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
    let count = state.storage.count_roles(&realm_id).await?;
    Ok(Json(CountRepresentation { count }))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/roles",
    tag = "Roles",
    summary = "Create a realm role",
    description = "Creates a new realm-level role. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Role representation", content = RoleRepresentation),
    responses(
        (status = 201, description = "Role created successfully", body = RoleRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - role already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_realm_role(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<RoleRepresentation>,
) -> Result<(StatusCode, Json<RoleRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let mut role: issuerd_core::Role = body.clone().try_into()?;
    role.realm_id = realm_id.clone();
    state.storage.create_role(&role.realm_id, &role).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Role,
        &format!("roles/{}", role.name),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(role.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/roles/{role_name}",
    tag = "Roles",
    summary = "Get a realm role by name",
    description = "Returns the role representation. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("role_name" = String, Path, description = "Role name")
    ),
    responses(
        (status = 200, description = "Role found", body = RoleRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_realm_role(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, role_name)): axum::extract::Path<(String, String)>,
) -> Result<Json<RoleRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let role = state
        .storage
        .get_role_by_name(&realm_id, &role_name)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(role.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/roles/{role_name}",
    tag = "Roles",
    summary = "Update a realm role",
    description = "Updates an existing realm-level role. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("role_name" = String, Path, description = "Role name")
    ),
    request_body(description = "Updated role representation", content = RoleRepresentation),
    responses(
        (status = 204, description = "Role updated successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_realm_role(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, role_name)): axum::extract::Path<(String, String)>,
    Json(body): Json<RoleRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let existing = state
        .storage
        .get_role_by_name(&realm_id, &role_name)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    let mut updated: issuerd_core::Role = body.clone().try_into()?;
    updated.id = existing.id.clone();
    updated.realm_id = existing.realm_id;
    // Fields omitted from the update body mean "leave unchanged", not
    // "clear" — otherwise a plain rename wipes composites and attributes.
    if body.composites.is_none() {
        updated.composites = existing.composites;
    }
    if body.attributes.is_none() {
        updated.attributes = existing.attributes;
    }
    state.storage.update_role(&realm_id, &updated).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::Role,
        &format!("roles/{}", role_name),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/roles/{role_name}",
    tag = "Roles",
    summary = "Delete a realm role",
    description = "Permanently deletes a realm-level role. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("role_name" = String, Path, description = "Role name")
    ),
    responses(
        (status = 204, description = "Role deleted successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_realm_role(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, role_name)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let existing = state
        .storage
        .get_role_by_name(&realm_id, &role_name)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    state.storage.delete_role(&realm_id, &existing.id).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::Role,
        &format!("roles/{}", role_name),
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

    fn role_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/roles", get(list_realm_roles).post(create_realm_role))
            .route(
                "/admin/realms/{realm}/roles/{role_name}",
                get(get_realm_role).put(update_realm_role).delete(delete_realm_role),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn role_crud() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = role_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        // Create
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/test/roles")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"admin"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Get
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/roles/admin")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Update
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/realms/test/roles/admin")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"admin","description":"Updated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Delete
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/realms/test/roles/admin")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn list_realm_roles_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = role_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new("role-1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: None,
            realm_id: realm.id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_role(&realm.id, &role).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/roles")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<RoleRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
    }

    #[tokio::test]
    async fn get_realm_role_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = role_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new("role-1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: Some("Admin role".to_string()),
            realm_id: realm.id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_role(&realm.id, &role).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/roles/admin")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: RoleRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.name, "admin");
    }

    #[tokio::test]
    async fn update_realm_role_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = role_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/realms/test/roles/nonexistent")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"nonexistent"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_realm_role_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = role_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/realms/test/roles/nonexistent")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
