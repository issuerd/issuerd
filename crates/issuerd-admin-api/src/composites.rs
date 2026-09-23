// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Composite role sub-resources for realm and client roles.

//! Role composite sub-resources: the `/composites` trees under
//! both realm roles (`/roles/{role_name}/composites…`) and client roles
//! (`/clients/{id}/roles/{role_name}/composites…`).
//!
//! Composites are stored as role NAMES on the parent role row
//! (`Role.composites`); name resolution mirrors `issuerd_core::expand_composites`:
//! a client role's children resolve in the same client first, then realm
//! roles; a realm role's children resolve realm roles first, then any client
//! role with that name. Composite references in request bodies resolve by id
//! when present, otherwise by name — entries carrying `client_role: true` +
//! `container_id` resolve against that client's roles, which is how a realm
//! role can gain a client-role child (Keycloak allows cross-container
//! composites). Because storage is name-based, a child whose name collides
//! across containers resolves by the rules above at expansion time regardless
//! of which concrete role was added — a model-level limitation shared with
//! the full-role update path.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{OperationType, ResourceType, Role};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    clients::load_client,
    dto::RoleRepresentation,
    error::AdminApiError,
    state::AdminApiState,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Load the path realm and the realm role `role_name` (404 on either). Uses
/// the same lookup as the parent `/roles/{role_name}` resource.
async fn load_realm_role(
    state: &Arc<AdminApiState>,
    realm: &str,
    role_name: &str,
) -> Result<(issuerd_core::RealmId, Role), AdminApiError> {
    let realm_id = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?.id;
    let role = state
        .storage
        .get_role_by_name(&realm_id, role_name)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok((realm_id, role))
}

/// Load the path realm, client, and the client's role `role_name` (404 on
/// any of them).
async fn load_client_role(
    state: &Arc<AdminApiState>,
    realm: &str,
    id: &str,
    role_name: &str,
) -> Result<(issuerd_core::RealmId, issuerd_core::Client, Role), AdminApiError> {
    let (realm_id, client) = load_client(state, realm, id).await?;
    let role = state
        .storage
        .get_client_role_by_name(&realm_id, &client.id, role_name)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok((realm_id, client, role))
}

/// Resolve one stored composite name using `expand_composites`' rules.
fn resolve_child_name(parent: &Role, name: &str, all: &[Role]) -> Option<Role> {
    let resolved = if parent.client_role {
        all.iter()
            .find(|r| {
                r.client_role
                    && r.client_id.as_ref() == parent.client_id.as_ref()
                    && r.name.as_str() == name
            })
            .or_else(|| all.iter().find(|r| !r.client_role && r.name.as_str() == name))
    } else {
        all.iter()
            .find(|r| !r.client_role && r.name.as_str() == name)
            .or_else(|| all.iter().find(|r| r.client_role && r.name.as_str() == name))
    };
    resolved.cloned()
}

/// The direct composite children of `parent` (stored names resolved against
/// the realm's roles; dangling names left behind by a deleted role are
/// skipped).
fn direct_children(parent: &Role, all: &[Role]) -> Vec<Role> {
    parent
        .composites
        .iter()
        .filter_map(|name| resolve_child_name(parent, name.as_str(), all))
        .collect()
}

/// Resolve a composite request body into stored roles. Entries with an `id`
/// resolve by id; name-only entries resolve by name (realm role preferred,
/// client-role fallback — the storage `get_role_by_name` rule); entries with
/// `client_role: true` resolve against the roles of the client named by
/// `container_id`. Unresolvable references are a 404 (Keycloak behavior).
async fn resolve_composite_refs(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    reps: Vec<RoleRepresentation>,
) -> Result<Vec<Role>, AdminApiError> {
    let mut roles = Vec::with_capacity(reps.len());
    for rep in reps {
        let role = match rep.id {
            Some(id) => state
                .storage
                .get_role(realm_id, &issuerd_core::RoleId::new(&id)?)
                .await?
                .ok_or(AdminApiError::NotFound)?,
            None => {
                if rep.client_role.unwrap_or(false) {
                    let container = rep.container_id.ok_or_else(|| {
                        AdminApiError::BadRequest(
                            "container_id is required for client-role composite references"
                                .to_string(),
                        )
                    })?;
                    state
                        .storage
                        .get_client_role_by_name(
                            realm_id,
                            &issuerd_core::ClientId::new(&container)?,
                            &rep.name,
                        )
                        .await?
                        .ok_or(AdminApiError::NotFound)?
                } else {
                    state
                        .storage
                        .get_role_by_name(realm_id, &rep.name)
                        .await?
                        .ok_or(AdminApiError::NotFound)?
                }
            }
        };
        roles.push(role);
    }
    Ok(roles)
}

/// The parent's direct children as representations, for the GET endpoints.
async fn composite_children(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    parent: &Role,
) -> Result<Vec<Role>, AdminApiError> {
    let all = issuerd_core::list_all_roles(state.storage.as_ref(), realm_id).await?;
    Ok(direct_children(parent, &all))
}

/// Union-add composite children with dedupe; rejects the write when the
/// candidate set's expanded closure would contain the parent role itself
/// (circular reference).
async fn add_composites(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm_id: &issuerd_core::RealmId,
    parent: &Role,
    resource_path: &str,
    body: Vec<RoleRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    let additions = resolve_composite_refs(state, realm_id, body.clone()).await?;
    let all = issuerd_core::list_all_roles(state.storage.as_ref(), realm_id).await?;
    let mut children = direct_children(parent, &all);
    for addition in additions {
        if !children.iter().any(|c| c.id == addition.id) {
            children.push(addition);
        }
    }
    // Cycle prevention: the transitive closure of the candidate children must
    // not contain the parent (also catches adding the parent to itself).
    if issuerd_core::expand_composites(children.clone(), &all)
        .iter()
        .any(|r| r.id == parent.id)
    {
        return Err(AdminApiError::BadRequest(format!(
            "composite set would make role '{}' its own ancestor (circular reference)",
            parent.name
        )));
    }
    let mut seen = std::collections::HashSet::new();
    let mut updated = parent.clone();
    updated.composites = children
        .iter()
        .filter(|c| seen.insert(c.name.clone()))
        .map(|c| c.name.clone())
        .collect();
    updated.composite = !updated.composites.is_empty();
    state.storage.update_role(realm_id, &updated).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), realm_id).await;
    crate::audit::emit_admin_event(
        state,
        auth,
        realm_id,
        OperationType::Action,
        ResourceType::Role,
        resource_path,
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Remove composite children by name; removing a role that is not a child is
/// a no-op (idempotent).
async fn remove_composites(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm_id: &issuerd_core::RealmId,
    parent: &Role,
    resource_path: &str,
    body: Vec<RoleRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    let removals = resolve_composite_refs(state, realm_id, body.clone()).await?;
    let names: std::collections::HashSet<&str> = removals.iter().map(|r| r.name.as_str()).collect();
    let mut updated = parent.clone();
    updated.composites.retain(|n| !names.contains(n.as_str()));
    updated.composite = !updated.composites.is_empty();
    state.storage.update_role(realm_id, &updated).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), realm_id).await;
    crate::audit::emit_admin_event(
        state,
        auth,
        realm_id,
        OperationType::Action,
        ResourceType::Role,
        resource_path,
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Load the client addressed by a `composites/clients/{client_uuid}` path
/// segment (the client's internal UUID, Keycloak convention).
async fn load_listing_client(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    client_uuid: &str,
) -> Result<issuerd_core::Client, AdminApiError> {
    let client_id = issuerd_core::ClientId::new(client_uuid)
        .map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    state
        .storage
        .get_client(realm_id, &client_id)
        .await?
        .ok_or(AdminApiError::NotFound)
}

// ---------------------------------------------------------------------------
// Realm role composites (`/roles/{role_name}/composites…`)
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/roles/{role_name}/composites",
    tag = "Roles",
    summary = "Get composite children of a realm role",
    description = "Returns the direct composite children of the realm role. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("role_name" = String, Path, description = "Role name")
    ),
    responses(
        (status = 200, description = "Composite children", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_realm_role_composites(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, role_name)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, parent) = load_realm_role(&state, &realm, &role_name).await?;
    let children = composite_children(&state, &realm_id, &parent).await?;
    Ok(Json(children.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/roles/{role_name}/composites",
    tag = "Roles",
    summary = "Add composite children to a realm role",
    description = "Adds one or more roles as composite children of the realm role (union-add with dedupe). Entries resolve by `id`, or by `name` plus optional `client_role`/`container_id` client context, so client roles can be added too. Rejected with 400 when the result would be circular. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("role_name" = String, Path, description = "Role name")
    ),
    request_body(description = "Role representations to add as composites", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Composites added successfully"),
        (status = 400, description = "Circular reference or invalid reference", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, role, or referenced role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_realm_role_composites(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, role_name)): axum::extract::Path<(String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let (realm_id, parent) = load_realm_role(&state, &realm, &role_name).await?;
    add_composites(
        &state,
        &auth,
        &realm_id,
        &parent,
        &format!("roles/{role_name}/composites"),
        body,
    )
    .await
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/roles/{role_name}/composites",
    tag = "Roles",
    summary = "Remove composite children from a realm role",
    description = "Removes the listed roles from the realm role's composite children (idempotent). Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("role_name" = String, Path, description = "Role name")
    ),
    request_body(description = "Role representations to remove", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Composites removed successfully"),
        (status = 400, description = "Invalid reference", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, role, or referenced role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_realm_role_composites(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, role_name)): axum::extract::Path<(String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let (realm_id, parent) = load_realm_role(&state, &realm, &role_name).await?;
    remove_composites(
        &state,
        &auth,
        &realm_id,
        &parent,
        &format!("roles/{role_name}/composites"),
        body,
    )
    .await
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/roles/{role_name}/composites/realm",
    tag = "Roles",
    summary = "Get realm-level composite children of a realm role",
    description = "Returns only the realm-level direct composite children of the realm role. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("role_name" = String, Path, description = "Role name")
    ),
    responses(
        (status = 200, description = "Realm-level composite children", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_realm_role_composites_realm(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, role_name)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, parent) = load_realm_role(&state, &realm, &role_name).await?;
    let children = composite_children(&state, &realm_id, &parent).await?;
    Ok(Json(children.into_iter().filter(|r| !r.client_role).map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/roles/{role_name}/composites/clients/{client_uuid}",
    tag = "Roles",
    summary = "Get client composite children of a realm role",
    description = "Returns only the direct composite children of the realm role that belong to the given client. `{client_uuid}` is the client's internal UUID. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("role_name" = String, Path, description = "Role name"),
        ("client_uuid" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Client composite children", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, role, or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_realm_role_composites_clients(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, role_name, client_uuid)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, parent) = load_realm_role(&state, &realm, &role_name).await?;
    let client = load_listing_client(&state, &realm_id, &client_uuid).await?;
    let children = composite_children(&state, &realm_id, &parent).await?;
    Ok(Json(
        children
            .into_iter()
            .filter(|r| r.client_role && r.client_id.as_ref() == Some(&client.id))
            .map(Into::into)
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// Client role composites (`/clients/{id}/roles/{role_name}/composites…`)
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/roles/{role_name}/composites",
    tag = "Client Roles",
    summary = "Get composite children of a client role",
    description = "Returns the direct composite children of the client role. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("role_name" = String, Path, description = "Role name")
    ),
    responses(
        (status = 200, description = "Composite children", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_client_role_composites(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, role_name)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, _client, parent) = load_client_role(&state, &realm, &id, &role_name).await?;
    let children = composite_children(&state, &realm_id, &parent).await?;
    Ok(Json(children.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/clients/{id}/roles/{role_name}/composites",
    tag = "Client Roles",
    summary = "Add composite children to a client role",
    description = "Adds one or more roles as composite children of the client role (union-add with dedupe). Entries resolve by `id`, or by `name` plus optional `client_role`/`container_id` client context; realm roles may be added to a client role. Rejected with 400 when the result would be circular. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("role_name" = String, Path, description = "Role name")
    ),
    request_body(description = "Role representations to add as composites", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Composites added successfully"),
        (status = 400, description = "Circular reference or invalid reference", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, role, or referenced role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_client_role_composites(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, role_name)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, client, parent) = load_client_role(&state, &realm, &id, &role_name).await?;
    add_composites(
        &state,
        &auth,
        &realm_id,
        &parent,
        &format!("clients/{}/roles/{role_name}/composites", client.id),
        body,
    )
    .await
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/clients/{id}/roles/{role_name}/composites",
    tag = "Client Roles",
    summary = "Remove composite children from a client role",
    description = "Removes the listed roles from the client role's composite children (idempotent). Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("role_name" = String, Path, description = "Role name")
    ),
    request_body(description = "Role representations to remove", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Composites removed successfully"),
        (status = 400, description = "Invalid reference", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, role, or referenced role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_client_role_composites(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, role_name)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let (realm_id, client, parent) = load_client_role(&state, &realm, &id, &role_name).await?;
    remove_composites(
        &state,
        &auth,
        &realm_id,
        &parent,
        &format!("clients/{}/roles/{role_name}/composites", client.id),
        body,
    )
    .await
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/roles/{role_name}/composites/realm",
    tag = "Client Roles",
    summary = "Get realm-level composite children of a client role",
    description = "Returns only the realm-level direct composite children of the client role. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("role_name" = String, Path, description = "Role name")
    ),
    responses(
        (status = 200, description = "Realm-level composite children", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_client_role_composites_realm(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, role_name)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, _client, parent) = load_client_role(&state, &realm, &id, &role_name).await?;
    let children = composite_children(&state, &realm_id, &parent).await?;
    Ok(Json(children.into_iter().filter(|r| !r.client_role).map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/roles/{role_name}/composites/clients/{client_uuid}",
    tag = "Client Roles",
    summary = "Get client composite children of a client role",
    description = "Returns only the direct composite children of the client role that belong to the given client. `{client_uuid}` is the listing client's internal UUID. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("role_name" = String, Path, description = "Role name"),
        ("client_uuid" = String, Path, description = "Listing client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Client composite children", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, role, or listing client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_client_role_composites_clients(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, role_name, client_uuid)): axum::extract::Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, _client, parent) = load_client_role(&state, &realm, &id, &role_name).await?;
    let listing = load_listing_client(&state, &realm_id, &client_uuid).await?;
    let children = composite_children(&state, &realm_id, &parent).await?;
    Ok(Json(
        children
            .into_iter()
            .filter(|r| r.client_role && r.client_id.as_ref() == Some(&listing.id))
            .map(Into::into)
            .collect(),
    ))
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

    fn composite_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/roles/{role_name}/composites",
                get(get_realm_role_composites)
                    .post(add_realm_role_composites)
                    .delete(remove_realm_role_composites),
            )
            .route(
                "/admin/realms/{realm}/roles/{role_name}/composites/realm",
                get(get_realm_role_composites_realm),
            )
            .route(
                "/admin/realms/{realm}/roles/{role_name}/composites/clients/{client_uuid}",
                get(get_realm_role_composites_clients),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/roles/{role_name}/composites",
                get(get_client_role_composites)
                    .post(add_client_role_composites)
                    .delete(remove_client_role_composites),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/roles/{role_name}/composites/realm",
                get(get_client_role_composites_realm),
            )
            .route(
                "/admin/realms/{realm}/clients/{id}/roles/{role_name}/composites/clients/{client_uuid}",
                get(get_client_role_composites_clients),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    fn manager_state() -> Arc<AdminApiState> {
        crate::test_utils::tests::test_state(vec![
            issuerd_core::RoleName::new("manage-realm").unwrap(),
            issuerd_core::RoleName::new("manage-clients").unwrap(),
        ])
    }

    async fn create_realm(state: &Arc<AdminApiState>) -> issuerd_core::Realm {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        realm
    }

    async fn create_role(
        state: &Arc<AdminApiState>,
        realm_id: &issuerd_core::RealmId,
        id: &str,
        name: &str,
        client: Option<&issuerd_core::Client>,
    ) -> Role {
        let role = Role {
            id: issuerd_core::RoleId::new(id).unwrap(),
            name: issuerd_core::RoleName::new(name).unwrap(),
            description: None,
            realm_id: realm_id.clone(),
            client_role: client.is_some(),
            client_id: client.map(|c| c.id.clone()),
            composite: false,
            composites: vec![],
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_role(realm_id, &role).await.unwrap();
        role
    }

    async fn create_client(
        state: &Arc<AdminApiState>,
        realm_id: &issuerd_core::RealmId,
    ) -> issuerd_core::Client {
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("client-1").unwrap(),
            realm_id: realm_id.clone(),
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
        state.storage.create_client(realm_id, &client).await.unwrap();
        client
    }

    async fn get_names(app: &Router, uri: String) -> (StatusCode, Vec<String>) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let names = serde_json::from_slice::<Vec<RoleRepresentation>>(&body)
            .map(|reps| reps.into_iter().map(|r| r.name).collect())
            .unwrap_or_default();
        (status, names)
    }

    async fn send_reps(app: &Router, method: &str, uri: String, body: &str) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn realm_role_composites_roundtrip_and_dedupe() {
        let state = manager_state();
        let app = composite_routes(state.clone());
        let realm = create_realm(&state).await;
        create_role(&state, &realm.id, "role-a", "parent", None).await;
        create_role(&state, &realm.id, "role-b", "child", None).await;

        // Add by name; the parent's composite flag flips on.
        let status = send_reps(
            &app,
            "POST",
            "/admin/realms/test/roles/parent/composites".to_string(),
            r#"[{"name":"child"}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let stored = state.storage.get_role_by_name(&realm.id, "parent").await.unwrap().unwrap();
        assert!(stored.composite);
        assert_eq!(stored.composites, vec![issuerd_core::RoleName::new("child").unwrap()]);

        // GET lists the child; the realm sub-listing shows it too.
        let (status, names) =
            get_names(&app, "/admin/realms/test/roles/parent/composites".to_string()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(names, vec!["child"]);
        let (_, names) =
            get_names(&app, "/admin/realms/test/roles/parent/composites/realm".to_string()).await;
        assert_eq!(names, vec!["child"]);

        // Adding the same role again is a deduped no-op.
        let status = send_reps(
            &app,
            "POST",
            "/admin/realms/test/roles/parent/composites".to_string(),
            r#"[{"name":"child"}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let stored = state.storage.get_role_by_name(&realm.id, "parent").await.unwrap().unwrap();
        assert_eq!(stored.composites.len(), 1);

        // Remove; the composite flag flips off.
        let status = send_reps(
            &app,
            "DELETE",
            "/admin/realms/test/roles/parent/composites".to_string(),
            r#"[{"name":"child"}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let stored = state.storage.get_role_by_name(&realm.id, "parent").await.unwrap().unwrap();
        assert!(!stored.composite);
        assert!(stored.composites.is_empty());

        // Removing again is idempotent.
        let status = send_reps(
            &app,
            "DELETE",
            "/admin/realms/test/roles/parent/composites".to_string(),
            r#"[{"name":"child"}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn realm_role_composites_cycle_rejected() {
        let state = manager_state();
        let app = composite_routes(state.clone());
        let realm = create_realm(&state).await;
        create_role(&state, &realm.id, "role-a", "a", None).await;
        create_role(&state, &realm.id, "role-b", "b", None).await;
        create_role(&state, &realm.id, "role-c", "c", None).await;

        // a composites b, b composites c.
        let status = send_reps(
            &app,
            "POST",
            "/admin/realms/test/roles/a/composites".to_string(),
            r#"[{"name":"b"}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let status = send_reps(
            &app,
            "POST",
            "/admin/realms/test/roles/b/composites".to_string(),
            r#"[{"name":"c"}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // c composites a would close a cycle a -> b -> c -> a.
        let status = send_reps(
            &app,
            "POST",
            "/admin/realms/test/roles/c/composites".to_string(),
            r#"[{"name":"a"}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Direct self-reference is rejected too.
        let status = send_reps(
            &app,
            "POST",
            "/admin/realms/test/roles/a/composites".to_string(),
            r#"[{"name":"a"}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Nothing was persisted.
        let stored = state.storage.get_role_by_name(&realm.id, "c").await.unwrap().unwrap();
        assert!(stored.composites.is_empty());
    }

    #[tokio::test]
    async fn realm_role_can_composite_a_client_role() {
        let state = manager_state();
        let app = composite_routes(state.clone());
        let realm = create_realm(&state).await;
        let client = create_client(&state, &realm.id).await;
        create_role(&state, &realm.id, "role-a", "parent", None).await;
        create_role(&state, &realm.id, "role-r", "realm-child", None).await;
        create_role(&state, &realm.id, "role-c", "app-admin", Some(&client)).await;

        // Add both a realm child and a client child (client context in body).
        let status = send_reps(
            &app,
            "POST",
            "/admin/realms/test/roles/parent/composites".to_string(),
            &format!(
                r#"[{{"name":"realm-child"}},{{"name":"app-admin","client_role":true,"container_id":"{}"}}]"#,
                client.id
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Full listing has both; sub-listings filter.
        let (_, names) =
            get_names(&app, "/admin/realms/test/roles/parent/composites".to_string()).await;
        assert_eq!(names.len(), 2);
        let (_, names) =
            get_names(&app, "/admin/realms/test/roles/parent/composites/realm".to_string()).await;
        assert_eq!(names, vec!["realm-child"]);
        let (_, names) = get_names(
            &app,
            format!("/admin/realms/test/roles/parent/composites/clients/{}", client.id),
        )
        .await;
        assert_eq!(names, vec!["app-admin"]);
    }

    #[tokio::test]
    async fn client_role_composites_roundtrip() {
        let state = manager_state();
        let app = composite_routes(state.clone());
        let realm = create_realm(&state).await;
        let client = create_client(&state, &realm.id).await;
        create_role(&state, &realm.id, "role-p", "app-parent", Some(&client)).await;
        create_role(&state, &realm.id, "role-ch", "app-child", Some(&client)).await;
        create_role(&state, &realm.id, "role-r", "realm-child", None).await;

        let base = format!("/admin/realms/test/clients/{}/roles/app-parent/composites", client.id);

        // Add a same-client child by name and a realm child by id (the
        // representation still carries `name` — it is a required field).
        let realm_child =
            state.storage.get_role_by_name(&realm.id, "realm-child").await.unwrap().unwrap();
        let status = send_reps(
            &app,
            "POST",
            base.clone(),
            &format!(
                r#"[{{"name":"app-child"}},{{"id":"{}","name":"realm-child"}}]"#,
                realm_child.id
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, names) = get_names(&app, base.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(names.len(), 2);
        let (_, names) = get_names(&app, format!("{base}/realm")).await;
        assert_eq!(names, vec!["realm-child"]);
        let (_, names) = get_names(&app, format!("{base}/clients/{}", client.id)).await;
        assert_eq!(names, vec!["app-child"]);

        // Remove the client child.
        let status = send_reps(&app, "DELETE", base.clone(), r#"[{"name":"app-child"}]"#).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, names) = get_names(&app, base).await;
        assert_eq!(names, vec!["realm-child"]);
    }

    #[tokio::test]
    async fn client_role_composites_cycle_rejected() {
        let state = manager_state();
        let app = composite_routes(state.clone());
        let realm = create_realm(&state).await;
        let client = create_client(&state, &realm.id).await;
        create_role(&state, &realm.id, "role-a", "a", Some(&client)).await;
        create_role(&state, &realm.id, "role-b", "b", Some(&client)).await;

        let uri_a = format!("/admin/realms/test/clients/{}/roles/a/composites", client.id);
        let uri_b = format!("/admin/realms/test/clients/{}/roles/b/composites", client.id);

        let status = send_reps(&app, "POST", uri_a, r#"[{"name":"b"}]"#).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        // b -> a would close the cycle.
        let status = send_reps(&app, "POST", uri_b, r#"[{"name":"a"}]"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn composites_unknown_targets_return_404() {
        let state = manager_state();
        let app = composite_routes(state.clone());
        let realm = create_realm(&state).await;
        let client = create_client(&state, &realm.id).await;
        create_role(&state, &realm.id, "role-a", "a", None).await;

        // Unknown parent role.
        let (status, _) =
            get_names(&app, "/admin/realms/test/roles/ghost/composites".to_string()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Unknown referenced role in the body.
        let status = send_reps(
            &app,
            "POST",
            "/admin/realms/test/roles/a/composites".to_string(),
            r#"[{"name":"ghost"}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Unknown client on the client-role tree.
        let (status, _) = get_names(
            &app,
            "/admin/realms/test/clients/no-such-client/roles/a/composites".to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Unknown client role name on a real client.
        let (status, _) = get_names(
            &app,
            format!("/admin/realms/test/clients/{}/roles/ghost/composites", client.id),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Unknown listing client on the filtered sub-resource.
        let (status, _) = get_names(
            &app,
            "/admin/realms/test/roles/a/composites/clients/no-such-client".to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
