// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Client scope-mappings endpoints: per-client realm/client role allow-lists.

//! Client scope-mappings endpoints, Keycloak paths under
//! `/admin/realms/{realm}/clients/{id}/scope-mappings`:
//!
//! - `GET /scope-mappings` — combined realm + client mappings
//! - `GET|POST|DELETE /scope-mappings/realm` plus `/realm/available` and
//!   `/realm/composite` — realm-role allow-list of the client
//! - `GET|POST|DELETE /scope-mappings/clients/{client_id}` plus
//!   `/clients/{client_id}/available` and `/clients/{client_id}/composite` —
//!   client-role allow-list entries
//!
//! Scope mappings bound the roles a client may contribute to tokens when full
//! scope is not allowed; they are stored on the client row
//! (`Client::scope_mappings`).

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{ClientId, OperationType, Pagination, ResourceType, Role, RoleId};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    clients::load_client,
    dto::{MappingsRepresentation, RoleRepresentation},
    error::AdminApiError,
    roles::{build_mappings_representation, resolve_role_representations, roles_by_ids},
    state::AdminApiState,
};

/// Resolve the `{client_id}` path segment (internal UUID of the client that
/// owns the roles) to a stored client in the same realm.
async fn load_target_client(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    client_id: &str,
) -> Result<issuerd_core::Client, AdminApiError> {
    let id = ClientId::new(client_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    state.storage.get_client(realm_id, &id).await?.ok_or(AdminApiError::NotFound)
}

/// Resolve the request body to stored roles and reject any role not owned by
/// `container` (realm roles for the realm side, client roles of `client_id`
/// for the client side) with 404 — Keycloak hides cross-container roles.
async fn resolve_container_roles(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    reps: Vec<RoleRepresentation>,
    owner: Option<&ClientId>,
) -> Result<Vec<Role>, AdminApiError> {
    let roles = resolve_role_representations(state, realm_id, reps).await?;
    for role in &roles {
        let in_container = match owner {
            None => !role.client_role,
            Some(client_id) => role.client_id.as_ref() == Some(client_id),
        };
        if !in_container {
            return Err(AdminApiError::NotFound);
        }
    }
    Ok(roles)
}

fn push_unique(ids: &mut Vec<RoleId>, id: RoleId) {
    if !ids.contains(&id) {
        ids.push(id);
    }
}

async fn emit_mapping_event(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm_id: &issuerd_core::RealmId,
    op: OperationType,
    path: String,
    body: Option<String>,
) {
    crate::audit::emit_admin_event(state, auth, realm_id, op, ResourceType::Client, &path, body)
        .await;
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings",
    tag = "Scope Mappings",
    summary = "Get all scope mappings of a client",
    description = "Returns the combined realm-level and client-level scope mappings of the client. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Combined scope mappings", body = MappingsRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_client_scope_mappings(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<MappingsRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let mut ids = client.scope_mappings.realm_roles.clone();
    for roles in client.scope_mappings.client_roles.values() {
        ids.extend(roles.iter().cloned());
    }
    let roles = roles_by_ids(&state, &realm_id, ids).await?;
    Ok(Json(build_mappings_representation(&state, &realm_id, roles).await?))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/realm",
    tag = "Scope Mappings",
    summary = "Get realm-level scope mappings of a client",
    description = "Returns the realm roles on the client's scope-mapping allow-list. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Assigned realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_scope_mapping_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let roles = roles_by_ids(&state, &realm_id, client.scope_mappings.realm_roles).await?;
    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/realm",
    tag = "Scope Mappings",
    summary = "Add realm-level scope mappings to a client",
    description = "Adds realm roles to the client's scope-mapping allow-list. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    request_body(description = "Roles to add (id is required on each entry)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Mappings added"),
        (status = 400, description = "Role id missing from a body entry", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_scope_mapping_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut client) = load_client(&state, &realm, &id).await?;
    let roles = resolve_container_roles(&state, &realm_id, body.clone(), None).await?;
    for role in roles {
        push_unique(&mut client.scope_mappings.realm_roles, role.id);
    }
    state.storage.update_client(&realm_id, &client).await?;
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    emit_mapping_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        format!("clients/{id}/scope-mappings/realm"),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/realm",
    tag = "Scope Mappings",
    summary = "Remove realm-level scope mappings from a client",
    description = "Removes realm roles from the client's scope-mapping allow-list. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    request_body(description = "Roles to remove (id is required on each entry)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Mappings removed"),
        (status = 400, description = "Role id missing from a body entry", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_scope_mapping_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut client) = load_client(&state, &realm, &id).await?;
    let roles = resolve_container_roles(&state, &realm_id, body.clone(), None).await?;
    let removed: Vec<&RoleId> = roles.iter().map(|r| &r.id).collect();
    client.scope_mappings.realm_roles.retain(|rid| !removed.contains(&rid));
    state.storage.update_client(&realm_id, &client).await?;
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    emit_mapping_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        format!("clients/{id}/scope-mappings/realm"),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/realm/available",
    tag = "Scope Mappings",
    summary = "List realm roles available for scope mapping",
    description = "Returns the realm roles not yet on the client's scope-mapping allow-list. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Available realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_available_scope_mapping_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let all = issuerd_core::list_all_roles(state.storage.as_ref(), &realm_id).await?;
    let reps = all
        .into_iter()
        .filter(|r| !r.client_role && !client.scope_mappings.realm_roles.contains(&r.id))
        .map(Into::into)
        .collect();
    Ok(Json(reps))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/realm/composite",
    tag = "Scope Mappings",
    summary = "Get effective realm-level scope mappings of a client",
    description = "Returns the effective realm roles of the client's scope-mapping allow-list. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Effective realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_effective_scope_mapping_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    // Simplification: for a client's scope-mapping allow-list the stored
    // mapping IS the effective set — no composite expansion.
    let roles = roles_by_ids(&state, &realm_id, client.scope_mappings.realm_roles).await?;
    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}",
    tag = "Scope Mappings",
    summary = "Get client-level scope mappings of a client",
    description = "Returns the roles of the target client on this client's scope-mapping allow-list. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("client_id" = String, Path, description = "Internal UUID of the client that owns the roles")
    ),
    responses(
        (status = 200, description = "Assigned client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_scope_mapping_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let target = load_target_client(&state, &realm_id, &client_id).await?;
    let ids = client.scope_mappings.client_roles.get(&target.id).cloned().unwrap_or_default();
    let roles = roles_by_ids(&state, &realm_id, ids).await?;
    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}",
    tag = "Scope Mappings",
    summary = "Add client-level scope mappings to a client",
    description = "Adds roles of the target client to this client's scope-mapping allow-list. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("client_id" = String, Path, description = "Internal UUID of the client that owns the roles")
    ),
    request_body(description = "Roles to add (id is required on each entry)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Mappings added"),
        (status = 400, description = "Role id missing from a body entry", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_scope_mapping_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut client) = load_client(&state, &realm, &id).await?;
    let target = load_target_client(&state, &realm_id, &client_id).await?;
    let roles = resolve_container_roles(&state, &realm_id, body.clone(), Some(&target.id)).await?;
    let entry = client.scope_mappings.client_roles.entry(target.id).or_default();
    for role in roles {
        push_unique(entry, role.id);
    }
    state.storage.update_client(&realm_id, &client).await?;
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    emit_mapping_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        format!("clients/{id}/scope-mappings/clients/{client_id}"),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}",
    tag = "Scope Mappings",
    summary = "Remove client-level scope mappings from a client",
    description = "Removes roles of the target client from this client's scope-mapping allow-list. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("client_id" = String, Path, description = "Internal UUID of the client that owns the roles")
    ),
    request_body(description = "Roles to remove (id is required on each entry)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Mappings removed"),
        (status = 400, description = "Role id missing from a body entry", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_scope_mapping_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut client) = load_client(&state, &realm, &id).await?;
    let target = load_target_client(&state, &realm_id, &client_id).await?;
    let roles = resolve_container_roles(&state, &realm_id, body.clone(), Some(&target.id)).await?;
    let removed: Vec<&RoleId> = roles.iter().map(|r| &r.id).collect();
    if let Some(entry) = client.scope_mappings.client_roles.get_mut(&target.id) {
        entry.retain(|rid| !removed.contains(&rid));
        if entry.is_empty() {
            client.scope_mappings.client_roles.remove(&target.id);
        }
    }
    state.storage.update_client(&realm_id, &client).await?;
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    emit_mapping_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        format!("clients/{id}/scope-mappings/clients/{client_id}"),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}/available",
    tag = "Scope Mappings",
    summary = "List client roles available for scope mapping",
    description = "Returns the roles of the target client not yet on this client's scope-mapping allow-list. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("client_id" = String, Path, description = "Internal UUID of the client that owns the roles")
    ),
    responses(
        (status = 200, description = "Available client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_available_scope_mapping_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let target = load_target_client(&state, &realm_id, &client_id).await?;
    let assigned = client.scope_mappings.client_roles.get(&target.id).cloned().unwrap_or_default();
    let all = state
        .storage
        .list_client_roles(
            &realm_id,
            &target.id,
            &Pagination {
                first: 0,
                max: i32::MAX,
            },
        )
        .await?;
    let reps = all.into_iter().filter(|r| !assigned.contains(&r.id)).map(Into::into).collect();
    Ok(Json(reps))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}/composite",
    tag = "Scope Mappings",
    summary = "Get effective client-level scope mappings of a client",
    description = "Returns the effective roles of the target client on this client's scope-mapping allow-list. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("client_id" = String, Path, description = "Internal UUID of the client that owns the roles")
    ),
    responses(
        (status = 200, description = "Effective client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_effective_scope_mapping_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    let target = load_target_client(&state, &realm_id, &client_id).await?;
    // Simplification: the stored mapping IS the effective set — no composite
    // expansion for scope mappings.
    let ids = client.scope_mappings.client_roles.get(&target.id).cloned().unwrap_or_default();
    let roles = roles_by_ids(&state, &realm_id, ids).await?;
    Ok(Json(roles.into_iter().map(Into::into).collect()))
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
    use tower::ServiceExt;

    fn scope_mapping_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/clients/{id}/scope-mappings",
                get(get_client_scope_mappings),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/scope-mappings/realm",
                get(get_scope_mapping_realm_roles)
                    .post(add_scope_mapping_realm_roles)
                    .delete(remove_scope_mapping_realm_roles),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/scope-mappings/realm/available",
                get(get_available_scope_mapping_realm_roles),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/scope-mappings/realm/composite",
                get(get_effective_scope_mapping_realm_roles),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}",
                get(get_scope_mapping_client_roles)
                    .post(add_scope_mapping_client_roles)
                    .delete(remove_scope_mapping_client_roles),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}/available",
                get(get_available_scope_mapping_client_roles),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/scope-mappings/clients/{client_id}/composite",
                get(get_effective_scope_mapping_client_roles),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    fn manage_state() -> Arc<AdminApiState> {
        crate::test_utils::tests::test_state(vec![
            issuerd_core::RoleName::new("manage-clients").unwrap()
        ])
    }

    /// Seed realm, owning client, target client, one realm role and one client
    /// role on the target client.
    async fn fixture(
        state: &Arc<AdminApiState>,
    ) -> (String, String, String, issuerd_core::Role, issuerd_core::Role) {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        let mk_client = |id: &str, client_id: &str| issuerd_core::Client {
            id: ClientId::new(id).unwrap(),
            realm_id: realm.id.clone(),
            client_id: issuerd_core::ClientIdentifier::new(client_id).unwrap(),
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
            attributes: Default::default(),
        };
        let client = mk_client("client-1", "my-app");
        state.storage.create_client(&realm.id, &client).await.unwrap();
        let target = mk_client("client-2", "other-app");
        state.storage.create_client(&realm.id, &target).await.unwrap();
        let realm_role = issuerd_core::Role {
            id: RoleId::new("role-1").unwrap(),
            name: issuerd_core::RoleName::new("realm-role").unwrap(),
            description: None,
            realm_id: realm.id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: Default::default(),
        };
        state.storage.create_role(&realm.id, &realm_role).await.unwrap();
        let client_role = issuerd_core::Role {
            id: RoleId::new("role-2").unwrap(),
            name: issuerd_core::RoleName::new("target-role").unwrap(),
            description: None,
            realm_id: realm.id.clone(),
            client_role: true,
            client_id: Some(target.id.clone()),
            composite: false,
            composites: vec![],
            attributes: Default::default(),
        };
        state.storage.create_role(&realm.id, &client_role).await.unwrap();
        (
            realm.name.to_string(),
            client.id.to_string(),
            target.id.to_string(),
            realm_role,
            client_role,
        )
    }

    fn authed(method: &str, uri: String, body: Option<String>) -> Request<Body> {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", "Bearer valid-token");
        match body {
            Some(json) => builder
                .header("Content-Type", "application/json")
                .body(Body::from(json))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn role_ref(role: &Role) -> String {
        format!(r#"{{"id":"{}","name":"{}"}}"#, role.id, role.name)
    }

    #[tokio::test]
    async fn realm_scope_mappings_roundtrip() {
        let state = manage_state();
        let app = scope_mapping_routes(state.clone());
        let (realm, client_id, _, realm_role, _) = fixture(&state).await;
        let base = format!("/admin/realms/{realm}/clients/{client_id}/scope-mappings/realm");

        // Initially empty; the realm role shows up as available.
        let response = app.clone().oneshot(authed("GET", base.clone(), None)).await.unwrap();
        assert_eq!(body_json(response).await.as_array().unwrap().len(), 0);
        let response = app
            .clone()
            .oneshot(authed("GET", format!("{base}/available"), None))
            .await
            .unwrap();
        let available = body_json(response).await;
        assert!(available
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.get("name").and_then(|n| n.as_str()) == Some("realm-role")));

        // Add.
        let response = app
            .clone()
            .oneshot(authed("POST", base.clone(), Some(format!("[{}]", role_ref(&realm_role)))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Assigned + effective now carry it, available no longer does.
        let response = app.clone().oneshot(authed("GET", base.clone(), None)).await.unwrap();
        assert_eq!(body_json(response).await.as_array().unwrap().len(), 1);
        let response = app
            .clone()
            .oneshot(authed("GET", format!("{base}/composite"), None))
            .await
            .unwrap();
        assert_eq!(body_json(response).await.as_array().unwrap().len(), 1);
        let response = app
            .clone()
            .oneshot(authed("GET", format!("{base}/available"), None))
            .await
            .unwrap();
        assert!(body_json(response).await.as_array().unwrap().is_empty());

        // Combined view reports the mapping.
        let response = app
            .clone()
            .oneshot(authed(
                "GET",
                format!("/admin/realms/{realm}/clients/{client_id}/scope-mappings"),
                None,
            ))
            .await
            .unwrap();
        let mappings = body_json(response).await;
        assert_eq!(
            mappings
                .get("realm_mappings")
                .and_then(|m| m.as_array())
                .map(std::vec::Vec::len),
            Some(1)
        );

        // Remove.
        let response = app
            .clone()
            .oneshot(authed("DELETE", base.clone(), Some(format!("[{}]", role_ref(&realm_role)))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app.oneshot(authed("GET", base, None)).await.unwrap();
        assert!(body_json(response).await.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn client_scope_mappings_roundtrip() {
        let state = manage_state();
        let app = scope_mapping_routes(state.clone());
        let (realm, client_id, target_id, _, client_role) = fixture(&state).await;
        let base =
            format!("/admin/realms/{realm}/clients/{client_id}/scope-mappings/clients/{target_id}");

        let response = app.clone().oneshot(authed("GET", base.clone(), None)).await.unwrap();
        assert!(body_json(response).await.as_array().unwrap().is_empty());

        let response = app
            .clone()
            .oneshot(authed("POST", base.clone(), Some(format!("[{}]", role_ref(&client_role)))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app.clone().oneshot(authed("GET", base.clone(), None)).await.unwrap();
        assert_eq!(body_json(response).await.as_array().unwrap().len(), 1);
        let response = app
            .clone()
            .oneshot(authed("GET", format!("{base}/composite"), None))
            .await
            .unwrap();
        assert_eq!(body_json(response).await.as_array().unwrap().len(), 1);
        let response = app
            .clone()
            .oneshot(authed("GET", format!("{base}/available"), None))
            .await
            .unwrap();
        assert!(body_json(response).await.as_array().unwrap().is_empty());

        // Combined view groups the role under the owning client's client_id.
        let response = app
            .clone()
            .oneshot(authed(
                "GET",
                format!("/admin/realms/{realm}/clients/{client_id}/scope-mappings"),
                None,
            ))
            .await
            .unwrap();
        let mappings = body_json(response).await;
        let entry = mappings.get("client_mappings").and_then(|m| m.get("other-app")).unwrap();
        assert_eq!(
            entry.get("mappings").and_then(|m| m.as_array()).map(std::vec::Vec::len),
            Some(1)
        );

        let response = app
            .clone()
            .oneshot(authed("DELETE", base.clone(), Some(format!("[{}]", role_ref(&client_role)))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // The empty container entry is dropped from the stored map.
        let client = state
            .storage
            .get_client(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &ClientId::new(&client_id).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(client.scope_mappings.client_roles.is_empty());
    }

    #[tokio::test]
    async fn cross_container_role_returns_404() {
        let state = manage_state();
        let app = scope_mapping_routes(state.clone());
        let (realm, client_id, target_id, realm_role, client_role) = fixture(&state).await;

        // A client role is not valid on the realm side...
        let response = app
            .clone()
            .oneshot(authed(
                "POST",
                format!("/admin/realms/{realm}/clients/{client_id}/scope-mappings/realm"),
                Some(format!("[{}]", role_ref(&client_role))),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // ...and a realm role is not valid on a client side.
        let response = app
            .oneshot(authed(
                "POST",
                format!(
                    "/admin/realms/{realm}/clients/{client_id}/scope-mappings/clients/{target_id}"
                ),
                Some(format!("[{}]", role_ref(&realm_role))),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_ids_return_404() {
        let state = manage_state();
        let app = scope_mapping_routes(state.clone());
        let (realm, client_id, _target_id, realm_role, _) = fixture(&state).await;

        // Unknown owning client.
        let response = app
            .clone()
            .oneshot(authed(
                "GET",
                format!("/admin/realms/{realm}/clients/nope/scope-mappings"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Unknown target client.
        let response = app
            .clone()
            .oneshot(authed(
                "GET",
                format!("/admin/realms/{realm}/clients/{client_id}/scope-mappings/clients/nope"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Unknown role id in the body.
        let response = app
            .clone()
            .oneshot(authed(
                "POST",
                format!("/admin/realms/{realm}/clients/{client_id}/scope-mappings/realm"),
                Some(r#"[{"id":"nope","name":"ghost"}]"#.to_string()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Missing role id in a body entry → 400.
        let response = app
            .clone()
            .oneshot(authed(
                "POST",
                format!("/admin/realms/{realm}/clients/{client_id}/scope-mappings/realm"),
                Some(r#"[{"name":"no-id"}]"#.to_string()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Valid-but-foreign-container handled in the sibling test; keep a
        // sanity POST happy-path here for the target client as well.
        let response = app
            .oneshot(authed(
                "POST",
                format!("/admin/realms/{realm}/clients/{client_id}/scope-mappings/realm"),
                Some(format!("[{}]", role_ref(&realm_role))),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
