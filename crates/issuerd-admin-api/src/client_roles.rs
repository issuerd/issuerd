// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Client role endpoints: roles owned by a client, addressed by name.

//! Client role endpoints: roles owned by a client, addressed by
//! name under `/admin/realms/{realm}/clients/{id}/roles[/{role-name}]`.
//!
//! Client roles are `Role` rows with `client_role = true` and `client_id` set
//! to the owning client's internal id; `containerId` on the wire is that
//! client id (Keycloak convention).

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{OperationType, Pagination, ResourceType};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    clients::load_client,
    dto::{PaginationQueryParams, RoleRepresentation},
    error::AdminApiError,
    state::AdminApiState,
};

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/roles",
    tag = "Client Roles",
    summary = "List client roles",
    description = "Returns the roles owned by the client. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        PaginationQueryParams
    ),
    responses(
        (status = 200, description = "List of client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<PaginationQueryParams>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let roles = state
        .storage
        .list_client_roles(&realm_id, &client.id, &Pagination::new(params.first, params.max))
        .await?;
    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/clients/{id}/roles",
    tag = "Client Roles",
    summary = "Create a client role",
    description = "Creates a new role owned by the client. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    request_body(description = "Role representation", content = RoleRepresentation),
    responses(
        (status = 201, description = "Role created successfully", body = RoleRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - role name already exists on this client", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_client_role(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<RoleRepresentation>,
) -> Result<(StatusCode, Json<RoleRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    // Name uniqueness is per owning client; pre-check so a duplicate surfaces
    // as 409 rather than a backend-specific error.
    if state
        .storage
        .get_client_role_by_name(&realm_id, &client.id, &body.name)
        .await?
        .is_some()
    {
        return Err(AdminApiError::Conflict);
    }
    let mut role: issuerd_core::Role = body.clone().try_into()?;
    role.realm_id = realm_id.clone();
    role.client_role = true;
    role.client_id = Some(client.id.clone());
    state.storage.create_role(&realm_id, &role).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Role,
        &format!("clients/{}/roles/{}", client.id, role.name),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(role.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/roles/{role_name}",
    tag = "Client Roles",
    summary = "Get a client role by name",
    description = "Returns the client role representation. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("role_name" = String, Path, description = "Role name")
    ),
    responses(
        (status = 200, description = "Role found", body = RoleRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_client_role(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, role_name)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<RoleRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let role = state
        .storage
        .get_client_role_by_name(&realm_id, &client.id, &role_name)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(role.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/clients/{id}/roles/{role_name}",
    tag = "Client Roles",
    summary = "Update a client role",
    description = "Updates an existing client role. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("role_name" = String, Path, description = "Role name")
    ),
    request_body(description = "Updated role representation", content = RoleRepresentation),
    responses(
        (status = 204, description = "Role updated successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - renamed role collides on this client", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_client_role(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, role_name)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<RoleRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let existing = state
        .storage
        .get_client_role_by_name(&realm_id, &client.id, &role_name)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    // Renaming onto another role of the same client must be a conflict, not a
    // silent duplicate.
    if body.name != role_name {
        if let Some(other) =
            state.storage.get_client_role_by_name(&realm_id, &client.id, &body.name).await?
        {
            if other.id != existing.id {
                return Err(AdminApiError::Conflict);
            }
        }
    }
    let mut updated: issuerd_core::Role = body.clone().try_into()?;
    updated.id = existing.id.clone();
    updated.realm_id = existing.realm_id;
    updated.client_role = true;
    updated.client_id = Some(client.id.clone());
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
        &format!("clients/{}/roles/{}", client.id, role_name),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/clients/{id}/roles/{role_name}",
    tag = "Client Roles",
    summary = "Delete a client role",
    description = "Permanently deletes a client role. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("role_name" = String, Path, description = "Role name")
    ),
    responses(
        (status = 204, description = "Role deleted successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_client_role(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, role_name)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let existing = state
        .storage
        .get_client_role_by_name(&realm_id, &client.id, &role_name)
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
        &format!("clients/{}/roles/{}", client.id, role_name),
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

    fn client_role_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/clients/{id}/roles",
                get(list_client_roles).post(create_client_role),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/roles/{role_name}",
                get(get_client_role).put(update_client_role).delete(delete_client_role),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    async fn realm_and_client(state: &Arc<AdminApiState>) -> (String, String) {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("client-1").unwrap(),
            realm_id: realm.id.clone(),
            client_id: issuerd_core::ClientIdentifier::new("my-app").unwrap(),
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
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&realm.id, &client).await.unwrap();
        (realm.name.to_string(), client.id.to_string())
    }

    #[tokio::test]
    async fn client_role_crud() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_role_routes(state.clone());
        let (realm_name, client_id) = realm_and_client(&state).await;

        // Create
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"app-admin"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: RoleRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.client_role, Some(true));
        assert_eq!(rep.container_id, Some(client_id.clone()));

        // Duplicate name -> 409
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"app-admin"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // Get
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles/app-admin"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: RoleRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.name, "app-admin");
        assert_eq!(rep.client_role, Some(true));

        // List
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles"))
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

        // Update
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles/app-admin"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"app-admin","description":"Updated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let role = state
            .storage
            .get_client_role_by_name(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::ClientId::new(&client_id).unwrap(),
                "app-admin",
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(role.description.as_deref(), Some("Updated"));
        assert!(role.client_role);

        // Delete
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles/app-admin"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles/app-admin"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn client_role_update_rename_collision_returns_409() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_role_routes(state.clone());
        let (realm_name, client_id) = realm_and_client(&state).await;

        for name in ["role-a", "role-b"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles"))
                        .header("Authorization", "Bearer valid-token")
                        .header("Content-Type", "application/json")
                        .body(Body::from(format!(r#"{{"name":"{name}"}}"#)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles/role-a"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"role-b"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn client_role_unknown_client_returns_404() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_role_routes(state.clone());
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/test/clients/no-such-client/roles")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"app-admin"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn client_role_insufficient_roles_returns_403() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let app = client_role_routes(state.clone());
        let (realm_name, client_id) = realm_and_client(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"app-admin"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn realm_role_and_client_role_may_share_a_name() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_role_routes(state.clone());
        let (realm_name, client_id) = realm_and_client(&state).await;

        // A realm role named "shared" exists...
        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new("role-1").unwrap(),
            name: issuerd_core::RoleName::new("shared").unwrap(),
            description: None,
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_role(&role.realm_id, &role).await.unwrap();

        // ...and a client role with the same name on this client is fine.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/roles"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"shared"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }
}
