// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Client scope CRUD, protocol mappers, and scope assignment endpoints.

//! Client scope endpoints, Keycloak paths:
//!
//! - `/admin/realms/{realm}/client-scopes[/{id}]` — scope CRUD
//! - `/admin/realms/{realm}/client-scopes/{id}/protocol-mappers/models[...]` —
//!   protocol mapper sub-resources of a scope
//! - `/admin/realms/{realm}/clients/{id}/protocol-mappers/models[...]` — the
//!   client-local ("dedicated scope") mappers, same shapes
//! - `/admin/realms/{realm}/clients/{id}/default-client-scopes[...]` and
//!   `.../optional-client-scopes[...]` — client ↔ scope assignments
//! - `/admin/realms/{realm}/default-default-client-scopes[...]` and
//!   `.../default-optional-client-scopes[...]` — realm-level defaults applied
//!   to newly created clients

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{
    ClientScope, ClientScopeId, MapperId, OperationType, Pagination, ProtocolMapper, RealmId,
    ResourceType,
};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    clients::load_client,
    dto::{ClientScopeRepresentation, PaginationQueryParams, ProtocolMapperRepresentation},
    error::AdminApiError,
    state::AdminApiState,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Resolve the path realm and load a client scope by id (404 on either).
async fn load_scope(
    state: &Arc<AdminApiState>,
    realm: &str,
    id: &str,
) -> Result<(RealmId, ClientScope), AdminApiError> {
    let realm_id = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?.id;
    let scope_id = ClientScopeId::new(id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let scope = state
        .storage
        .get_client_scope(&realm_id, &scope_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok((realm_id, scope))
}

/// Convert a mapper body, surfacing the DTO validation (OIDC-only protocol) as
/// a 400.
fn mapper_from_rep(rep: &ProtocolMapperRepresentation) -> Result<ProtocolMapper, AdminApiError> {
    rep.clone().try_into().map_err(AdminApiError::from)
}

/// Append a mapper, rejecting a duplicate name within the same parent.
fn add_mapper(
    mappers: &mut Vec<ProtocolMapper>,
    rep: &ProtocolMapperRepresentation,
) -> Result<ProtocolMapper, AdminApiError> {
    let mapper = mapper_from_rep(rep)?;
    if mappers.iter().any(|m| m.name == mapper.name) {
        return Err(AdminApiError::Conflict);
    }
    mappers.push(mapper.clone());
    Ok(mapper)
}

/// Replace the mapper with the given id; the path id wins over the body id,
/// and a rename must not collide with a sibling mapper.
fn replace_mapper(
    mappers: &mut [ProtocolMapper],
    id: &MapperId,
    rep: &ProtocolMapperRepresentation,
) -> Result<(), AdminApiError> {
    let Some(pos) = mappers.iter().position(|m| m.id == *id) else {
        return Err(AdminApiError::NotFound);
    };
    let mut mapper = mapper_from_rep(rep)?;
    if mapper.name != mappers[pos].name && mappers.iter().any(|m| m.name == mapper.name) {
        return Err(AdminApiError::Conflict);
    }
    mapper.id = id.clone();
    mappers[pos] = mapper;
    Ok(())
}

/// Remove the mapper with the given id (404 when unknown).
fn remove_mapper(mappers: &mut Vec<ProtocolMapper>, id: &MapperId) -> Result<(), AdminApiError> {
    let before = mappers.len();
    mappers.retain(|m| m.id != *id);
    if mappers.len() == before {
        return Err(AdminApiError::NotFound);
    }
    Ok(())
}

/// Add a scope token to a `Scope` list (sorted/dedup on rebuild).
fn scope_list_add(scope: &issuerd_core::Scope, name: &str) -> issuerd_core::Scope {
    let mut tokens = scope.to_vec();
    if !tokens.iter().any(|t| t == name) {
        tokens.push(name.to_string());
    }
    issuerd_core::Scope::from(tokens)
}

/// Remove a scope token from a `Scope` list.
fn scope_list_remove(scope: &issuerd_core::Scope, name: &str) -> issuerd_core::Scope {
    issuerd_core::Scope::from(scope.to_vec().into_iter().filter(|t| t != name).collect::<Vec<_>>())
}

// ---------------------------------------------------------------------------
// Client scope CRUD
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/client-scopes",
    tag = "Client Scopes",
    summary = "List client scopes",
    description = "Returns the client scopes of the realm. Protocol mappers are omitted on list responses (Keycloak behavior). Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        PaginationQueryParams
    ),
    responses(
        (status = 200, description = "List of client scopes", body = Vec<ClientScopeRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_client_scopes(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<PaginationQueryParams>,
) -> Result<Json<Vec<ClientScopeRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let scopes = state
        .storage
        .list_client_scopes(&realm_id, &Pagination::new(params.first, params.max))
        .await?;
    Ok(Json(
        scopes.into_iter().map(ClientScopeRepresentation::without_mappers).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/client-scopes",
    tag = "Client Scopes",
    summary = "Create a client scope",
    description = "Creates a new client scope. Requires `manage-clients` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Client scope representation", content = ClientScopeRepresentation),
    responses(
        (status = 201, description = "Client scope created", body = ClientScopeRepresentation),
        (status = 400, description = "Invalid scope (empty name, non-OIDC mapper protocol)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - scope name already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<ClientScopeRepresentation>,
) -> Result<(StatusCode, Json<ClientScopeRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    if body.name.trim().is_empty() {
        return Err(AdminApiError::BadRequest("scope name is required".to_string()));
    }
    // Pre-check so a duplicate name surfaces as 409 on every backend.
    if state.storage.get_client_scope_by_name(&realm_id, &body.name).await?.is_some() {
        return Err(AdminApiError::Conflict);
    }
    let mut scope: ClientScope = body.clone().try_into()?;
    scope.realm_id = realm_id.clone();
    state.storage.create_client_scope(&realm_id, &scope).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::ClientScope,
        &format!("client-scopes/{}", scope.id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(scope.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/client-scopes/{id}",
    tag = "Client Scopes",
    summary = "Get a client scope by ID",
    description = "Returns the client scope representation including protocol mappers. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 200, description = "Client scope found", body = ClientScopeRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<ClientScopeRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (_realm_id, scope) = load_scope(&state, &realm, &id).await?;
    Ok(Json(scope.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/client-scopes/{id}",
    tag = "Client Scopes",
    summary = "Update a client scope",
    description = "Updates an existing client scope. Omitted `protocol_mappers` leave the stored mappers unchanged. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client scope ID")
    ),
    request_body(description = "Updated client scope representation", content = ClientScopeRepresentation),
    responses(
        (status = 204, description = "Client scope updated"),
        (status = 400, description = "Invalid scope (non-OIDC mapper protocol)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - renamed scope collides", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<ClientScopeRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, existing) = load_scope(&state, &realm, &id).await?;
    if body.name.trim().is_empty() {
        return Err(AdminApiError::BadRequest("scope name is required".to_string()));
    }
    // Renaming onto another scope must be a conflict, not a silent duplicate.
    if body.name != existing.name {
        if let Some(other) = state.storage.get_client_scope_by_name(&realm_id, &body.name).await? {
            if other.id != existing.id {
                return Err(AdminApiError::Conflict);
            }
        }
    }
    let mut updated: ClientScope = body.clone().try_into()?;
    updated.id = existing.id.clone();
    updated.realm_id = existing.realm_id;
    // Omitted fields mean "leave unchanged": mappers are stripped from list
    // responses, so a list-driven PUT must not wipe them; scope mappings live
    // behind their own sub-resources.
    if body.protocol_mappers.is_none() {
        updated.protocol_mappers = existing.protocol_mappers;
    }
    if body.attributes.is_none() {
        updated.attributes = existing.attributes;
    }
    if body.protocol.is_none() {
        updated.protocol = existing.protocol;
    }
    updated.scope_mappings = existing.scope_mappings;
    state.storage.update_client_scope(&realm_id, &updated).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::ClientScope,
        &format!("client-scopes/{}", id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/client-scopes/{id}",
    tag = "Client Scopes",
    summary = "Delete a client scope",
    description = "Permanently deletes a client scope, including its assignments and realm-default rows. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 204, description = "Client scope deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, scope) = load_scope(&state, &realm, &id).await?;
    state.storage.delete_client_scope(&realm_id, &scope.id).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::ClientScope,
        &format!("client-scopes/{}", id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Protocol mapper sub-resources (client scope parent)
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/client-scopes/{id}/protocol-mappers/models",
    tag = "Client Scopes",
    summary = "List protocol mappers of a client scope",
    description = "Returns the protocol mappers bundled in the client scope. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 200, description = "List of protocol mappers", body = Vec<ProtocolMapperRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_scope_mappers(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<ProtocolMapperRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (_realm_id, scope) = load_scope(&state, &realm, &id).await?;
    Ok(Json(scope.protocol_mappers.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/client-scopes/{id}/protocol-mappers/models",
    tag = "Client Scopes",
    summary = "Add a protocol mapper to a client scope",
    description = "Adds a protocol mapper to the client scope. Mapper names are unique per scope. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client scope ID")
    ),
    request_body(description = "Protocol mapper definition", content = ProtocolMapperRepresentation),
    responses(
        (status = 201, description = "Mapper created", body = ProtocolMapperRepresentation),
        (status = 400, description = "Invalid mapper (non-OIDC protocol)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - mapper name already exists on this scope", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_scope_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<ProtocolMapperRepresentation>,
) -> Result<(StatusCode, Json<ProtocolMapperRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut scope) = load_scope(&state, &realm, &id).await?;
    let mapper = add_mapper(&mut scope.protocol_mappers, &body)?;
    state.storage.update_client_scope(&realm_id, &scope).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::ClientScope,
        &format!("client-scopes/{}/protocol-mappers/models/{}", scope.id, mapper.name),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(mapper.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/client-scopes/{id}/protocol-mappers/models/{mapper_id}",
    tag = "Client Scopes",
    summary = "Get a protocol mapper of a client scope",
    description = "Returns the protocol mapper with the given id. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client scope ID"),
        ("mapper_id" = String, Path, description = "Protocol mapper ID")
    ),
    responses(
        (status = 200, description = "Mapper found", body = ProtocolMapperRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client scope, or mapper not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_scope_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, mapper_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<ProtocolMapperRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (_realm_id, scope) = load_scope(&state, &realm, &id).await?;
    let mapper_id =
        MapperId::new(&mapper_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let mapper = scope
        .protocol_mappers
        .into_iter()
        .find(|m| m.id == mapper_id)
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(mapper.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/client-scopes/{id}/protocol-mappers/models/{mapper_id}",
    tag = "Client Scopes",
    summary = "Update a protocol mapper of a client scope",
    description = "Replaces the protocol mapper with the given id. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client scope ID"),
        ("mapper_id" = String, Path, description = "Protocol mapper ID")
    ),
    request_body(description = "Updated protocol mapper definition", content = ProtocolMapperRepresentation),
    responses(
        (status = 204, description = "Mapper updated"),
        (status = 400, description = "Invalid mapper (non-OIDC protocol)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client scope, or mapper not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - renamed mapper collides", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_scope_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, mapper_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<ProtocolMapperRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut scope) = load_scope(&state, &realm, &id).await?;
    let mapper_id =
        MapperId::new(&mapper_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    replace_mapper(&mut scope.protocol_mappers, &mapper_id, &body)?;
    state.storage.update_client_scope(&realm_id, &scope).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::ClientScope,
        &format!("client-scopes/{}/protocol-mappers/models/{}", scope.id, mapper_id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/client-scopes/{id}/protocol-mappers/models/{mapper_id}",
    tag = "Client Scopes",
    summary = "Delete a protocol mapper of a client scope",
    description = "Removes the protocol mapper with the given id from the client scope. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client scope ID"),
        ("mapper_id" = String, Path, description = "Protocol mapper ID")
    ),
    responses(
        (status = 204, description = "Mapper deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client scope, or mapper not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_scope_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, mapper_id)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut scope) = load_scope(&state, &realm, &id).await?;
    let mapper_id =
        MapperId::new(&mapper_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    remove_mapper(&mut scope.protocol_mappers, &mapper_id)?;
    state.storage.update_client_scope(&realm_id, &scope).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::ClientScope,
        &format!("client-scopes/{}/protocol-mappers/models/{}", scope.id, mapper_id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Protocol mapper sub-resources (client parent — Keycloak "dedicated scope")
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/protocol-mappers/models",
    tag = "Clients",
    summary = "List protocol mappers of a client",
    description = "Returns the client-local protocol mappers (Keycloak dedicated scope). Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "List of protocol mappers", body = Vec<ProtocolMapperRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_client_mappers(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<ProtocolMapperRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (_realm_id, client) = load_client(&state, &realm, &id).await?;
    Ok(Json(client.protocol_mappers.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/clients/{id}/protocol-mappers/models",
    tag = "Clients",
    summary = "Add a protocol mapper to a client",
    description = "Adds a client-local protocol mapper. Mapper names are unique per client. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    request_body(description = "Protocol mapper definition", content = ProtocolMapperRepresentation),
    responses(
        (status = 201, description = "Mapper created", body = ProtocolMapperRepresentation),
        (status = 400, description = "Invalid mapper (non-OIDC protocol)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - mapper name already exists on this client", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_client_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<ProtocolMapperRepresentation>,
) -> Result<(StatusCode, Json<ProtocolMapperRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut client) = load_client(&state, &realm, &id).await?;
    let mapper = add_mapper(&mut client.protocol_mappers, &body)?;
    state.storage.update_client(&realm_id, &client).await?;
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Client,
        &format!("clients/{}/protocol-mappers/models/{}", client.id, mapper.name),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(mapper.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/protocol-mappers/models/{mapper_id}",
    tag = "Clients",
    summary = "Get a protocol mapper of a client",
    description = "Returns the client-local protocol mapper with the given id. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("mapper_id" = String, Path, description = "Protocol mapper ID")
    ),
    responses(
        (status = 200, description = "Mapper found", body = ProtocolMapperRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or mapper not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_client_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, mapper_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<ProtocolMapperRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (_realm_id, client) = load_client(&state, &realm, &id).await?;
    let mapper_id =
        MapperId::new(&mapper_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let mapper = client
        .protocol_mappers
        .into_iter()
        .find(|m| m.id == mapper_id)
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(mapper.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/clients/{id}/protocol-mappers/models/{mapper_id}",
    tag = "Clients",
    summary = "Update a protocol mapper of a client",
    description = "Replaces the client-local protocol mapper with the given id. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("mapper_id" = String, Path, description = "Protocol mapper ID")
    ),
    request_body(description = "Updated protocol mapper definition", content = ProtocolMapperRepresentation),
    responses(
        (status = 204, description = "Mapper updated"),
        (status = 400, description = "Invalid mapper (non-OIDC protocol)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or mapper not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - renamed mapper collides", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_client_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, mapper_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<ProtocolMapperRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut client) = load_client(&state, &realm, &id).await?;
    let mapper_id =
        MapperId::new(&mapper_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    replace_mapper(&mut client.protocol_mappers, &mapper_id, &body)?;
    state.storage.update_client(&realm_id, &client).await?;
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::Client,
        &format!("clients/{}/protocol-mappers/models/{}", client.id, mapper_id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/clients/{id}/protocol-mappers/models/{mapper_id}",
    tag = "Clients",
    summary = "Delete a protocol mapper of a client",
    description = "Removes the client-local protocol mapper with the given id. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("mapper_id" = String, Path, description = "Protocol mapper ID")
    ),
    responses(
        (status = 204, description = "Mapper deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or mapper not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_client_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, mapper_id)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, mut client) = load_client(&state, &realm, &id).await?;
    let mapper_id =
        MapperId::new(&mapper_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    remove_mapper(&mut client.protocol_mappers, &mapper_id)?;
    state.storage.update_client(&realm_id, &client).await?;
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::Client,
        &format!("clients/{}/protocol-mappers/models/{}", client.id, mapper_id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Client ↔ scope assignments (default-client-scopes / optional-client-scopes)
// ---------------------------------------------------------------------------

/// List the scopes assigned to a client with the given defaultness, resolving
/// each assignment to its representation (dangling references are skipped).
async fn list_assigned_scopes(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    client_id: &issuerd_core::ClientId,
    is_default: bool,
) -> Result<Json<Vec<ClientScopeRepresentation>>, AdminApiError> {
    let assignments = state.storage.list_client_scope_assignments(realm_id, client_id).await?;
    let mut reps = Vec::new();
    for (scope_id, assigned_default) in assignments {
        if assigned_default != is_default {
            continue;
        }
        if let Some(scope) = state.storage.get_client_scope(realm_id, &scope_id).await? {
            reps.push(ClientScopeRepresentation::without_mappers(scope));
        }
    }
    Ok(Json(reps))
}

/// Shared body of the PUT assignment handlers: upsert the assignment row and
/// keep the client's legacy scope string lists in sync with it.
async fn assign_scope_to_client(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm: &str,
    id: &str,
    scope_id: &str,
    is_default: bool,
    audit_path: &str,
) -> Result<StatusCode, AdminApiError> {
    require_roles(auth, &["manage-clients"])?;
    let (realm_id, mut client) = load_client(state, realm, id).await?;
    let scope_id =
        ClientScopeId::new(scope_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let scope = state
        .storage
        .get_client_scope(&realm_id, &scope_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    state
        .storage
        .assign_client_scope(&realm_id, &client.id, &scope_id, is_default)
        .await?;
    if is_default {
        client.default_scopes = scope_list_add(&client.default_scopes, &scope.name);
        client.optional_scopes = scope_list_remove(&client.optional_scopes, &scope.name);
    } else {
        client.optional_scopes = scope_list_add(&client.optional_scopes, &scope.name);
        client.default_scopes = scope_list_remove(&client.default_scopes, &scope.name);
    }
    state.storage.update_client(&realm_id, &client).await?;
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    crate::audit::emit_admin_event(
        state,
        auth,
        &realm_id,
        OperationType::Update,
        ResourceType::Client,
        audit_path,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Shared body of the DELETE assignment handlers: drop the assignment row and
/// scrub the scope name from both legacy string lists.
async fn unassign_scope_from_client(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm: &str,
    id: &str,
    scope_id: &str,
    audit_path: &str,
) -> Result<StatusCode, AdminApiError> {
    require_roles(auth, &["manage-clients"])?;
    let (realm_id, mut client) = load_client(state, realm, id).await?;
    let scope_id =
        ClientScopeId::new(scope_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let scope = state
        .storage
        .get_client_scope(&realm_id, &scope_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    state.storage.unassign_client_scope(&realm_id, &client.id, &scope_id).await?;
    client.default_scopes = scope_list_remove(&client.default_scopes, &scope.name);
    client.optional_scopes = scope_list_remove(&client.optional_scopes, &scope.name);
    state.storage.update_client(&realm_id, &client).await?;
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &client.id,
        client.client_id.as_ref(),
    )
    .await;
    crate::audit::emit_admin_event(
        state,
        auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::Client,
        audit_path,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/default-client-scopes",
    tag = "Clients",
    summary = "List a client's default client scopes",
    description = "Returns the client scopes assigned to the client as defaults. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Assigned default client scopes", body = Vec<ClientScopeRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_default_client_scopes(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<ClientScopeRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    list_assigned_scopes(&state, &realm_id, &client.id, true).await
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/clients/{id}/default-client-scopes/{scope_id}",
    tag = "Clients",
    summary = "Assign a default client scope to a client",
    description = "Adds the client scope as a default assignment on the client. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("scope_id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 204, description = "Scope assigned"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn assign_default_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, scope_id)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    assign_scope_to_client(
        &state,
        &auth,
        &realm,
        &id,
        &scope_id,
        true,
        &format!("clients/{id}/default-client-scopes/{scope_id}"),
    )
    .await
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/clients/{id}/default-client-scopes/{scope_id}",
    tag = "Clients",
    summary = "Unassign a default client scope from a client",
    description = "Removes the client scope assignment from the client. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("scope_id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 204, description = "Scope unassigned"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn unassign_default_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, scope_id)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    unassign_scope_from_client(
        &state,
        &auth,
        &realm,
        &id,
        &scope_id,
        &format!("clients/{id}/default-client-scopes/{scope_id}"),
    )
    .await
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/optional-client-scopes",
    tag = "Clients",
    summary = "List a client's optional client scopes",
    description = "Returns the client scopes assigned to the client as optional. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Assigned optional client scopes", body = Vec<ClientScopeRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_optional_client_scopes(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<ClientScopeRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    list_assigned_scopes(&state, &realm_id, &client.id, false).await
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/clients/{id}/optional-client-scopes/{scope_id}",
    tag = "Clients",
    summary = "Assign an optional client scope to a client",
    description = "Adds the client scope as an optional assignment on the client. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("scope_id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 204, description = "Scope assigned"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn assign_optional_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, scope_id)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    assign_scope_to_client(
        &state,
        &auth,
        &realm,
        &id,
        &scope_id,
        false,
        &format!("clients/{id}/optional-client-scopes/{scope_id}"),
    )
    .await
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/clients/{id}/optional-client-scopes/{scope_id}",
    tag = "Clients",
    summary = "Unassign an optional client scope from a client",
    description = "Removes the client scope assignment from the client. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("scope_id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 204, description = "Scope unassigned"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn unassign_optional_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, scope_id)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    unassign_scope_from_client(
        &state,
        &auth,
        &realm,
        &id,
        &scope_id,
        &format!("clients/{id}/optional-client-scopes/{scope_id}"),
    )
    .await
}

// ---------------------------------------------------------------------------
// Realm-level default client-scope tables
// ---------------------------------------------------------------------------

/// List the realm's default-scope table entries of the given defaultness.
async fn list_realm_default_scopes(
    state: &Arc<AdminApiState>,
    realm: &str,
    is_default: bool,
) -> Result<Json<Vec<ClientScopeRepresentation>>, AdminApiError> {
    let realm_id = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?.id;
    let entries = state.storage.list_realm_default_client_scopes(&realm_id).await?;
    let mut reps = Vec::new();
    for (scope_id, entry_default) in entries {
        if entry_default != is_default {
            continue;
        }
        if let Some(scope) = state.storage.get_client_scope(&realm_id, &scope_id).await? {
            reps.push(ClientScopeRepresentation::without_mappers(scope));
        }
    }
    Ok(Json(reps))
}

/// Shared body of the realm-defaults PUT handlers.
async fn add_realm_default_scope(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm: &str,
    scope_id: &str,
    is_default: bool,
    audit_path: &str,
) -> Result<StatusCode, AdminApiError> {
    require_roles(auth, &["manage-realm"])?;
    let realm_id = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?.id;
    let scope_id =
        ClientScopeId::new(scope_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    state
        .storage
        .get_client_scope(&realm_id, &scope_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    state
        .storage
        .add_realm_default_client_scope(&realm_id, &scope_id, is_default)
        .await?;
    crate::audit::emit_admin_event(
        state,
        auth,
        &realm_id,
        OperationType::Update,
        ResourceType::ClientScope,
        audit_path,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Shared body of the realm-defaults DELETE handlers.
async fn remove_realm_default_scope(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm: &str,
    scope_id: &str,
    audit_path: &str,
) -> Result<StatusCode, AdminApiError> {
    require_roles(auth, &["manage-realm"])?;
    let realm_id = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?.id;
    let scope_id =
        ClientScopeId::new(scope_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    state
        .storage
        .get_client_scope(&realm_id, &scope_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    state.storage.remove_realm_default_client_scope(&realm_id, &scope_id).await?;
    crate::audit::emit_admin_event(
        state,
        auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::ClientScope,
        audit_path,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/default-default-client-scopes",
    tag = "Client Scopes",
    summary = "List the realm's default client scopes",
    description = "Returns the client scopes every newly created client receives as default assignments. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Realm default client scopes", body = Vec<ClientScopeRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_default_default_client_scopes(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<Vec<ClientScopeRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    list_realm_default_scopes(&state, &realm, true).await
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/default-default-client-scopes/{scope_id}",
    tag = "Client Scopes",
    summary = "Add a realm default client scope",
    description = "Marks the client scope as a realm-level default, assigned to every newly created client. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("scope_id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 204, description = "Realm default added"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_default_default_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, scope_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    add_realm_default_scope(
        &state,
        &auth,
        &realm,
        &scope_id,
        true,
        &format!("default-default-client-scopes/{scope_id}"),
    )
    .await
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/default-default-client-scopes/{scope_id}",
    tag = "Client Scopes",
    summary = "Remove a realm default client scope",
    description = "Removes the client scope from the realm-level default table. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("scope_id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 204, description = "Realm default removed"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_default_default_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, scope_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    remove_realm_default_scope(
        &state,
        &auth,
        &realm,
        &scope_id,
        &format!("default-default-client-scopes/{scope_id}"),
    )
    .await
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/default-optional-client-scopes",
    tag = "Client Scopes",
    summary = "List the realm's default optional client scopes",
    description = "Returns the client scopes every newly created client receives as optional assignments. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Realm default optional client scopes", body = Vec<ClientScopeRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_default_optional_client_scopes(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<Vec<ClientScopeRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    list_realm_default_scopes(&state, &realm, false).await
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/default-optional-client-scopes/{scope_id}",
    tag = "Client Scopes",
    summary = "Add a realm default optional client scope",
    description = "Marks the client scope as a realm-level optional assignment, granted to every newly created client. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("scope_id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 204, description = "Realm default added"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_default_optional_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, scope_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    add_realm_default_scope(
        &state,
        &auth,
        &realm,
        &scope_id,
        false,
        &format!("default-optional-client-scopes/{scope_id}"),
    )
    .await
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/default-optional-client-scopes/{scope_id}",
    tag = "Client Scopes",
    summary = "Remove a realm default optional client scope",
    description = "Removes the client scope from the realm-level optional table. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("scope_id" = String, Path, description = "Client scope ID")
    ),
    responses(
        (status = 204, description = "Realm default removed"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client scope not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_default_optional_client_scope(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, scope_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    remove_realm_default_scope(
        &state,
        &auth,
        &realm,
        &scope_id,
        &format!("default-optional-client-scopes/{scope_id}"),
    )
    .await
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

    fn client_scope_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/client-scopes",
                get(list_client_scopes).post(create_client_scope),
            )
            .route(
                "/admin/realms/{realm}/client-scopes/{id}",
                get(get_client_scope).put(update_client_scope).delete(delete_client_scope),
            )
            .route(
                "/admin/realms/{realm}/client-scopes/{id}/protocol-mappers/models",
                get(list_scope_mappers).post(create_scope_mapper),
            )
            .route(
                "/admin/realms/{realm}/client-scopes/{id}/protocol-mappers/models/{mapper_id}",
                get(get_scope_mapper).put(update_scope_mapper).delete(delete_scope_mapper),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/protocol-mappers/models",
                get(list_client_mappers).post(create_client_mapper),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/protocol-mappers/models/{mapper_id}",
                get(get_client_mapper).put(update_client_mapper).delete(delete_client_mapper),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/default-client-scopes",
                get(get_default_client_scopes),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/default-client-scopes/{scope_id}",
                axum::routing::put(assign_default_client_scope)
                    .delete(unassign_default_client_scope),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/optional-client-scopes",
                get(get_optional_client_scopes),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/optional-client-scopes/{scope_id}",
                axum::routing::put(assign_optional_client_scope)
                    .delete(unassign_optional_client_scope),
            )
            .route(
                "/admin/realms/{realm}/default-default-client-scopes",
                get(list_default_default_client_scopes),
            )
            .route(
                "/admin/realms/{realm}/default-default-client-scopes/{scope_id}",
                axum::routing::put(add_default_default_client_scope)
                    .delete(remove_default_default_client_scope),
            )
            .route(
                "/admin/realms/{realm}/default-optional-client-scopes",
                get(list_default_optional_client_scopes),
            )
            .route(
                "/admin/realms/{realm}/default-optional-client-scopes/{scope_id}",
                axum::routing::put(add_default_optional_client_scope)
                    .delete(remove_default_optional_client_scope),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    /// Seed a realm (built-in scopes + realm default tables) and one client.
    async fn fixture(state: &Arc<AdminApiState>) -> (String, String) {
        let realm = issuerd_core::Realm {
            id: RealmId::new("realm-1").unwrap(),
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
            attributes: Default::default(),
        };
        state.storage.create_client(&realm.id, &client).await.unwrap();
        (realm.name.to_string(), client.id.to_string())
    }

    async fn scope_id_by_name(state: &Arc<AdminApiState>, name: &str) -> String {
        state
            .storage
            .get_client_scope_by_name(&RealmId::new("realm-1").unwrap(), name)
            .await
            .unwrap()
            .unwrap()
            .id
            .to_string()
    }

    fn authed(method: &str, uri: String, body: Option<&str>) -> Request<Body> {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", "Bearer valid-token");
        match body {
            Some(json) => builder
                .header("Content-Type", "application/json")
                .body(Body::from(json.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn manage_state() -> Arc<AdminApiState> {
        crate::test_utils::tests::test_state(vec![
            issuerd_core::RoleName::new("manage-clients").unwrap(),
            issuerd_core::RoleName::new("manage-realm").unwrap(),
        ])
    }

    #[tokio::test]
    async fn client_scope_crud_roundtrip() {
        let state = manage_state();
        let app = client_scope_routes(state.clone());
        let (realm, _) = fixture(&state).await;

        // Create
        let response = app
            .clone()
            .oneshot(authed(
                "POST",
                format!("/admin/realms/{realm}/client-scopes"),
                Some(
                    r#"{"name":"custom","description":"Custom scope","protocol":"openid-connect"}"#,
                ),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        let id = created.get("id").and_then(|v| v.as_str()).unwrap().to_string();

        // List omits protocol_mappers (Keycloak behavior).
        let response = app
            .clone()
            .oneshot(authed("GET", format!("/admin/realms/{realm}/client-scopes"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        let entry = list
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s.get("name").and_then(|n| n.as_str()) == Some("custom"))
            .unwrap();
        assert!(entry.get("protocol_mappers").is_none());

        // Single GET includes the (empty) mapper list.
        let response = app
            .clone()
            .oneshot(authed("GET", format!("/admin/realms/{realm}/client-scopes/{id}"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let single = body_json(response).await;
        assert!(single.get("protocol_mappers").is_some());

        // Update
        let response = app
            .clone()
            .oneshot(authed(
                "PUT",
                format!("/admin/realms/{realm}/client-scopes/{id}"),
                Some(r#"{"name":"custom","description":"Renamed description"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Delete
        let response = app
            .clone()
            .oneshot(authed("DELETE", format!("/admin/realms/{realm}/client-scopes/{id}"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(authed("GET", format!("/admin/realms/{realm}/client-scopes/{id}"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_scope_duplicate_name_returns_409() {
        let state = manage_state();
        let app = client_scope_routes(state.clone());
        let (realm, _) = fixture(&state).await;

        // "profile" is one of the built-in scopes seeded with the realm.
        let response = app
            .oneshot(authed(
                "POST",
                format!("/admin/realms/{realm}/client-scopes"),
                Some(r#"{"name":"profile"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn unknown_scope_returns_404() {
        let state = manage_state();
        let app = client_scope_routes(state.clone());
        let (realm, _) = fixture(&state).await;

        for (method, body) in [
            ("GET", None),
            ("PUT", Some(r#"{"name":"whatever"}"#)),
            ("DELETE", None),
        ] {
            let response = app
                .clone()
                .oneshot(authed(method, format!("/admin/realms/{realm}/client-scopes/nope"), body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method}");
        }
    }

    #[tokio::test]
    async fn scope_mapper_crud() {
        let state = manage_state();
        let app = client_scope_routes(state.clone());
        let (realm, _) = fixture(&state).await;
        let scope_id = scope_id_by_name(&state, "profile").await;
        let models =
            format!("/admin/realms/{realm}/client-scopes/{scope_id}/protocol-mappers/models");

        // The built-in profile scope ships mappers already.
        let response = app.clone().oneshot(authed("GET", models.clone(), None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        assert!(!list.as_array().unwrap().is_empty());

        // Create
        let response = app
            .clone()
            .oneshot(authed(
                "POST",
                models.clone(),
                Some(r#"{"name":"my-mapper","protocol":"openid-connect","protocol_mapper":"oidc-full-name-mapper","config":{"a":"b"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let mapper = body_json(response).await;
        let mapper_id = mapper.get("id").and_then(|v| v.as_str()).unwrap().to_string();

        // Duplicate name → 409
        let response = app
            .clone()
            .oneshot(authed(
                "POST",
                models.clone(),
                Some(r#"{"name":"my-mapper","protocol_mapper":"oidc-full-name-mapper"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // Non-OIDC protocol → 400
        let response = app
            .clone()
            .oneshot(authed(
                "POST",
                models.clone(),
                Some(r#"{"name":"saml-m","protocol":"saml","protocol_mapper":"oidc-full-name-mapper"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Get / update / delete
        let response = app
            .clone()
            .oneshot(authed("GET", format!("{models}/{mapper_id}"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(authed(
                "PUT",
                format!("{models}/{mapper_id}"),
                Some(r#"{"name":"my-mapper","protocol_mapper":"oidc-full-name-mapper","config":{"a":"c"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app
            .clone()
            .oneshot(authed("DELETE", format!("{models}/{mapper_id}"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response =
            app.oneshot(authed("GET", format!("{models}/{mapper_id}"), None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_mapper_returns_404() {
        let state = manage_state();
        let app = client_scope_routes(state.clone());
        let (realm, _) = fixture(&state).await;
        let scope_id = scope_id_by_name(&state, "profile").await;
        let models =
            format!("/admin/realms/{realm}/client-scopes/{scope_id}/protocol-mappers/models/nope");

        for (method, body) in [
            ("GET", None),
            ("PUT", Some(r#"{"name":"x","protocol_mapper":"oidc-full-name-mapper"}"#)),
            ("DELETE", None),
        ] {
            let response = app.clone().oneshot(authed(method, models.clone(), body)).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method}");
        }
    }

    #[tokio::test]
    async fn client_mapper_crud() {
        let state = manage_state();
        let app = client_scope_routes(state.clone());
        let (realm, client_id) = fixture(&state).await;
        let models = format!("/admin/realms/{realm}/clients/{client_id}/protocol-mappers/models");

        let response = app
            .clone()
            .oneshot(authed(
                "POST",
                models.clone(),
                Some(r#"{"name":"cm","protocol_mapper":"oidc-full-name-mapper"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let mapper = body_json(response).await;
        let mapper_id = mapper.get("id").and_then(|v| v.as_str()).unwrap().to_string();

        let response = app.clone().oneshot(authed("GET", models.clone(), None)).await.unwrap();
        let list = body_json(response).await;
        assert_eq!(list.as_array().unwrap().len(), 1);

        let response = app
            .clone()
            .oneshot(authed(
                "PUT",
                format!("{models}/{mapper_id}"),
                Some(r#"{"name":"cm2","protocol_mapper":"oidc-full-name-mapper"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .clone()
            .oneshot(authed("DELETE", format!("{models}/{mapper_id}"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app.oneshot(authed("GET", models, None)).await.unwrap();
        let list = body_json(response).await;
        assert!(list.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn default_and_optional_scope_assignments() {
        let state = manage_state();
        let app = client_scope_routes(state.clone());
        let (realm, client_id) = fixture(&state).await;
        let email_id = scope_id_by_name(&state, "email").await;
        let address_id = scope_id_by_name(&state, "address").await;

        // Seeded assignments: "roles" is always default on a new client.
        let response = app
            .clone()
            .oneshot(authed(
                "GET",
                format!("/admin/realms/{realm}/clients/{client_id}/default-client-scopes"),
                None,
            ))
            .await
            .unwrap();
        let list = body_json(response).await;
        assert!(list
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("roles")));

        // Assign "email" as default.
        let response = app
            .clone()
            .oneshot(authed(
                "PUT",
                format!(
                    "/admin/realms/{realm}/clients/{client_id}/default-client-scopes/{email_id}"
                ),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Legacy string lists track the assignment.
        let client = state
            .storage
            .get_client(
                &RealmId::new("realm-1").unwrap(),
                &issuerd_core::ClientId::new(&client_id).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(client.default_scopes.contains("email"));
        assert!(!client.optional_scopes.contains("email"));

        // Assign "address" as optional, then unassign it again.
        let response = app
            .clone()
            .oneshot(authed(
                "PUT",
                format!(
                    "/admin/realms/{realm}/clients/{client_id}/optional-client-scopes/{address_id}"
                ),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app
            .clone()
            .oneshot(authed(
                "GET",
                format!("/admin/realms/{realm}/clients/{client_id}/optional-client-scopes"),
                None,
            ))
            .await
            .unwrap();
        let list = body_json(response).await;
        assert!(list
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("address")));
        let response = app
            .clone()
            .oneshot(authed(
                "DELETE",
                format!(
                    "/admin/realms/{realm}/clients/{client_id}/optional-client-scopes/{address_id}"
                ),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Unassign "email" from defaults — both lists drop the name.
        let response = app
            .clone()
            .oneshot(authed(
                "DELETE",
                format!(
                    "/admin/realms/{realm}/clients/{client_id}/default-client-scopes/{email_id}"
                ),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let client = state
            .storage
            .get_client(
                &RealmId::new("realm-1").unwrap(),
                &issuerd_core::ClientId::new(&client_id).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(!client.default_scopes.contains("email"));
        assert!(!client.optional_scopes.contains("email"));

        // Unknown scope id → 404 on assign/unassign.
        let response = app
            .oneshot(authed(
                "PUT",
                format!("/admin/realms/{realm}/clients/{client_id}/default-client-scopes/nope"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn realm_default_scope_tables() {
        let state = manage_state();
        let app = client_scope_routes(state.clone());
        let (realm, _) = fixture(&state).await;

        // Seeded realm defaults.
        let response = app
            .clone()
            .oneshot(authed(
                "GET",
                format!("/admin/realms/{realm}/default-default-client-scopes"),
                None,
            ))
            .await
            .unwrap();
        let list = body_json(response).await;
        let names: Vec<&str> = list
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s.get("name").and_then(|n| n.as_str()))
            .collect();
        for expected in ["profile", "email", "roles"] {
            assert!(names.contains(&expected), "missing default {expected}");
        }

        let response = app
            .clone()
            .oneshot(authed(
                "GET",
                format!("/admin/realms/{realm}/default-optional-client-scopes"),
                None,
            ))
            .await
            .unwrap();
        let list = body_json(response).await;
        let names: Vec<&str> = list
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s.get("name").and_then(|n| n.as_str()))
            .collect();
        for expected in ["address", "phone", "offline_access", "web-origins", "acr"] {
            assert!(names.contains(&expected), "missing optional {expected}");
        }

        // Add a custom scope to the optional table, then remove it.
        let response = app
            .clone()
            .oneshot(authed(
                "POST",
                format!("/admin/realms/{realm}/client-scopes"),
                Some(r#"{"name":"custom-opt"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let custom_id = scope_id_by_name(&state, "custom-opt").await;

        let response = app
            .clone()
            .oneshot(authed(
                "PUT",
                format!("/admin/realms/{realm}/default-optional-client-scopes/{custom_id}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app
            .clone()
            .oneshot(authed(
                "GET",
                format!("/admin/realms/{realm}/default-optional-client-scopes"),
                None,
            ))
            .await
            .unwrap();
        let list = body_json(response).await;
        assert!(list
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("custom-opt")));

        let response = app
            .clone()
            .oneshot(authed(
                "DELETE",
                format!("/admin/realms/{realm}/default-optional-client-scopes/{custom_id}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Unknown scope → 404.
        let response = app
            .oneshot(authed(
                "PUT",
                format!("/admin/realms/{realm}/default-default-client-scopes/nope"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
