// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Group management endpoints: CRUD, hierarchy, membership, and role mappings.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{GroupId, OperationType, Pagination, RealmId, ResourceType};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{
        CountRepresentation, GroupRepresentation, MappingsRepresentation, PaginationQueryParams,
        RoleRepresentation, UserRepresentation,
    },
    error::AdminApiError,
    state::AdminApiState,
};

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups",
    tag = "Groups",
    summary = "List groups in a realm",
    description = "Returns a paginated list of groups in the realm. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        PaginationQueryParams
    ),
    responses(
        (status = 200, description = "List of groups", body = Vec<GroupRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_groups(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<PaginationQueryParams>,
) -> Result<Json<Vec<GroupRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let groups = state
        .storage
        .list_groups(&realm_id, &Pagination::new(params.first, params.max))
        .await?;
    Ok(Json(groups.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/count",
    tag = "Groups",
    summary = "Count groups in a realm",
    description = "Returns the total number of groups in the realm. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Group count", body = CountRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn count_groups(
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
    let count = state.storage.count_groups(&realm_id).await?;
    Ok(Json(CountRepresentation { count }))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/groups",
    tag = "Groups",
    summary = "Create a new group",
    description = "Creates a group in the specified realm. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Group representation", content = GroupRepresentation),
    responses(
        (status = 201, description = "Group created successfully", body = GroupRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - group already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_group(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<GroupRepresentation>,
) -> Result<(StatusCode, Json<GroupRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    // Sub-groups are not persisted through the create body; the hierarchy is
    // built through the dedicated children endpoint.
    if body.sub_groups.as_ref().is_some_and(|s| !s.is_empty()) {
        return Err(AdminApiError::BadRequest(
            "sub_groups in the create body are not supported; create subgroups via POST /groups/{id}/children"
                .to_string(),
        ));
    }
    let mut group: issuerd_core::Group = body.clone().try_into()?;
    group.realm_id = realm_id.clone();
    state.storage.create_group(&group.realm_id, &group).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Group,
        &format!("groups/{}", group.id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(group.into())))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/groups/{id}/children",
    tag = "Groups",
    summary = "Create a sub-group",
    description = "Creates a child group under the group addressed by `{id}`. The child's path is computed as `{parent.path}/{name}` and its parent is the addressed group; `path`/`parent_id` in the body are ignored. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Parent group ID")
    ),
    request_body(description = "Group representation (`name` is required)", content = GroupRepresentation),
    responses(
        (status = 201, description = "Sub-group created successfully", body = GroupRepresentation),
        (status = 400, description = "Invalid request (e.g. nested sub_groups in the body)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or parent group not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - group name already exists in the realm", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_child_group(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<GroupRepresentation>,
) -> Result<(StatusCode, Json<GroupRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let (realm_id, parent) = load_group(&state, &realm, &id).await?;
    // Nest one level at a time; grandchildren get their own POST against the
    // freshly created child.
    if body.sub_groups.as_ref().is_some_and(|s| !s.is_empty()) {
        return Err(AdminApiError::BadRequest(
            "sub_groups in the create body are not supported; create subgroups via POST /groups/{id}/children"
                .to_string(),
        ));
    }
    let mut group: issuerd_core::Group = body.clone().try_into()?;
    group.realm_id = realm_id.clone();
    group.parent_id = Some(parent.id.clone());
    group.path = issuerd_core::GroupPath::new(format!("{}/{}", parent.path, group.name))?;
    state.storage.create_group(&realm_id, &group).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Group,
        &format!("groups/{}", group.id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(group.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/{id}",
    tag = "Groups",
    summary = "Get a group by ID",
    description = "Returns the group representation. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "Group found", body = GroupRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or group not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_group(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<GroupRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let group_id = GroupId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let group = state
        .storage
        .get_group(&realm_id, &group_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(group.into()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/{id}/members",
    tag = "Groups",
    summary = "List group members",
    description = "Returns the users that are members of the group, paginated. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID"),
        PaginationQueryParams
    ),
    responses(
        (status = 200, description = "Group members", body = Vec<UserRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or group not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_group_members(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<PaginationQueryParams>,
) -> Result<Json<Vec<UserRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, group) = load_group(&state, &realm, &id).await?;
    let members = state
        .storage
        .list_group_members(&realm_id, &group.id, params.first, params.max)
        .await?;
    // `From<User>` never populates `credentials` — the member list carries no
    // credential data by construction.
    Ok(Json(members.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/groups/{id}",
    tag = "Groups",
    summary = "Update a group",
    description = "Updates an existing group. `parent_id` is tri-state: omit it to keep the current parent, send `null` to move the group to the root, or send a group id to move it under that parent (paths of the moved group and its descendants are recomputed). Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID")
    ),
    request_body(description = "Updated group representation", content = GroupRepresentation),
    responses(
        (status = 204, description = "Group updated successfully"),
        (status = 400, description = "Invalid move (cycle) or invalid field", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, group, or target parent not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_group(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<GroupRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let group_id = GroupId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let existing = state
        .storage
        .get_group(&realm_id, &group_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    let mut updated: issuerd_core::Group = body.clone().try_into()?;
    updated.id = existing.id.clone();
    updated.realm_id = existing.realm_id;
    // Fields omitted from the update body mean "leave unchanged", not
    // "clear" — otherwise a plain rename wipes role grants and attributes.
    if body.realm_roles.is_none() {
        updated.realm_roles = existing.realm_roles;
    }
    if body.client_roles.is_none() {
        updated.client_roles = existing.client_roles;
    }
    if body.attributes.is_none() {
        updated.attributes = existing.attributes;
    }
    // Tri-state parent_id: absent = keep the stored parent (a routine update
    // must not sever the hierarchy); present = move (explicit null = root).
    let moved = match &body.parent_id {
        None => {
            updated.parent_id = existing.parent_id.clone();
            false
        }
        Some(target) => {
            if *target == existing.parent_id {
                false
            } else {
                let (parent_id, path) =
                    move_target(&state, &realm_id, &updated, target.clone()).await?;
                updated.parent_id = parent_id;
                updated.path = path;
                true
            }
        }
    };
    state.storage.update_group(&realm_id, &updated).await?;
    if moved {
        repath_descendants(&state, &realm_id, &updated).await?;
    }
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::Group,
        &format!("groups/{}", id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Validate a group move and compute the moved group's new `parent_id` and
/// `path`. `target` of `None` moves the group to the root.
async fn move_target(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    group: &issuerd_core::Group,
    target: Option<GroupId>,
) -> Result<(Option<GroupId>, issuerd_core::GroupPath), AdminApiError> {
    let Some(parent_id) = target else {
        return Ok((None, issuerd_core::GroupPath::new(format!("/{}", group.name))?));
    };
    let parent = state
        .storage
        .get_group(realm_id, &parent_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    // The target's ancestor chain must never reach the moved group — that
    // would make the group its own ancestor.
    let mut visited = std::collections::HashSet::new();
    let mut cursor = Some(parent.clone());
    while let Some(current) = cursor {
        if current.id == group.id {
            return Err(AdminApiError::BadRequest(
                "cannot move a group under itself or one of its descendants".to_string(),
            ));
        }
        if !visited.insert(current.id.clone()) {
            break; // pre-existing cycle in stored data; stop walking
        }
        cursor = match &current.parent_id {
            Some(pid) => state.storage.get_group(realm_id, pid).await?,
            None => None,
        };
    }
    Ok((
        Some(parent.id.clone()),
        issuerd_core::GroupPath::new(format!("{}/{}", parent.path, group.name))?,
    ))
}

/// Recompute and persist the paths of every descendant of `group` after a
/// move (the moved group's own path is set by the caller). Children are
/// discovered via `parent_id` over the full group list, not the transient
/// `sub_groups` field, which no backend populates on read.
async fn repath_descendants(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    group: &issuerd_core::Group,
) -> Result<(), AdminApiError> {
    let all = state
        .storage
        .list_groups(
            realm_id,
            &Pagination {
                first: 0,
                max: i32::MAX,
            },
        )
        .await?;
    let mut children_of: std::collections::HashMap<GroupId, Vec<issuerd_core::Group>> =
        std::collections::HashMap::new();
    for g in all {
        if let Some(pid) = &g.parent_id {
            children_of.entry(pid.clone()).or_default().push(g);
        }
    }
    let mut stack = vec![group.clone()];
    while let Some(ancestor) = stack.pop() {
        // `remove` consumes each child list once, so even a pre-existing
        // parent cycle in stored data terminates.
        for mut child in children_of.remove(&ancestor.id).unwrap_or_default() {
            child.path = issuerd_core::GroupPath::new(format!("{}/{}", ancestor.path, child.name))?;
            state.storage.update_group(realm_id, &child).await?;
            stack.push(child);
        }
    }
    Ok(())
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/groups/{id}",
    tag = "Groups",
    summary = "Delete a group",
    description = "Permanently deletes a group. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 204, description = "Group deleted successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or group not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_group(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let group_id = GroupId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    // Deleting a missing group must be a 404 (and must not emit an audit event).
    state
        .storage
        .get_group(&realm_id, &group_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    state.storage.delete_group(&realm_id, &group_id).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::Group,
        &format!("groups/{}", id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Role mappings (Keycloak `/groups/{id}/role-mappings/...`)
//
// Group mappings are stored as role NAMES on the group row
// (`group.realm_roles`, `group.client_roles`) — POST bodies resolve
// RoleRepresentation ids to roles and the names are persisted via
// `update_group`.
// ---------------------------------------------------------------------------

/// Resolve the path realm and load the target group (404 on either).
async fn load_group(
    state: &Arc<AdminApiState>,
    realm: &str,
    id: &str,
) -> Result<(RealmId, issuerd_core::Group), AdminApiError> {
    let realm_id = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?.id;
    let group_id = GroupId::new(id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let group = state
        .storage
        .get_group(&realm_id, &group_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok((realm_id, group))
}

/// Resolve the group's stored realm-role names against the realm's roles.
async fn group_realm_roles(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    group: &issuerd_core::Group,
) -> Result<Vec<issuerd_core::Role>, AdminApiError> {
    let all = issuerd_core::list_all_roles(state.storage.as_ref(), realm_id).await?;
    Ok(group
        .realm_roles
        .iter()
        .filter_map(|name| {
            all.iter().find(|r| !r.client_role && r.name.as_str() == name.as_str()).cloned()
        })
        .collect())
}

/// Resolve the group's stored role names for one client against the realm's
/// roles.
async fn group_client_roles(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    group: &issuerd_core::Group,
    client_id: &issuerd_core::ClientId,
) -> Result<Vec<issuerd_core::Role>, AdminApiError> {
    let all = issuerd_core::list_all_roles(state.storage.as_ref(), realm_id).await?;
    let names = group.client_roles.get(client_id);
    Ok(names
        .into_iter()
        .flatten()
        .filter_map(|name| {
            all.iter()
                .find(|r| {
                    r.client_role
                        && r.client_id.as_ref() == Some(client_id)
                        && r.name.as_str() == name.as_str()
                })
                .cloned()
        })
        .collect())
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings",
    tag = "Groups",
    summary = "Get all role mappings of a group",
    description = "Returns the combined realm and client role mappings of the group. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "Combined role mappings", body = MappingsRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or group not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_group_role_mappings(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<MappingsRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, group) = load_group(&state, &realm, &id).await?;
    let mut roles = group_realm_roles(&state, &realm_id, &group).await?;
    let owners: Vec<issuerd_core::ClientId> = group.client_roles.keys().cloned().collect();
    for owner in owners {
        roles.extend(group_client_roles(&state, &realm_id, &group, &owner).await?);
    }
    let mappings = crate::roles::build_mappings_representation(&state, &realm_id, roles).await?;
    Ok(Json(mappings))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/realm",
    tag = "Groups",
    summary = "Get group realm roles",
    description = "Returns the realm roles assigned to the group. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "Assigned realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or group not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_group_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, group) = load_group(&state, &realm, &id).await?;
    let roles = group_realm_roles(&state, &realm_id, &group).await?;
    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/realm",
    tag = "Groups",
    summary = "Add realm roles to a group",
    description = "Assigns one or more realm roles to the group. Roles are addressed by id; an unknown id or a client role yields 404. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID")
    ),
    request_body(description = "Role representations to assign (id required)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Roles added successfully"),
        (status = 400, description = "Role representation without id", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, group, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_group_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let (realm_id, mut group) = load_group(&state, &realm, &id).await?;
    let roles = crate::roles::resolve_role_representations(&state, &realm_id, body.clone()).await?;
    for role in roles {
        if role.client_role {
            return Err(AdminApiError::NotFound);
        }
        if !group.realm_roles.contains(&role.name) {
            group.realm_roles.push(role.name.clone());
        }
    }
    state.storage.update_group(&realm_id, &group).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::Group,
        &format!("groups/{}/role-mappings/realm", id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/realm",
    tag = "Groups",
    summary = "Remove realm roles from a group",
    description = "Removes one or more realm roles from the group. Roles are addressed by id. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID")
    ),
    request_body(description = "Role representations to remove (id required)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Roles removed successfully"),
        (status = 400, description = "Role representation without id", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, group, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_group_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let (realm_id, mut group) = load_group(&state, &realm, &id).await?;
    let roles = crate::roles::resolve_role_representations(&state, &realm_id, body.clone()).await?;
    for role in &roles {
        if role.client_role {
            return Err(AdminApiError::NotFound);
        }
    }
    let names: std::collections::HashSet<_> = roles.iter().map(|r| &r.name).collect();
    group.realm_roles.retain(|n| !names.contains(n));
    state.storage.update_group(&realm_id, &group).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::Group,
        &format!("groups/{}/role-mappings/realm", id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/realm/available",
    tag = "Groups",
    summary = "Get available realm roles for a group",
    description = "Returns the realm roles that are not part of the group's effective role set. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "Available realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or group not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_available_group_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, group) = load_group(&state, &realm, &id).await?;
    let effective =
        issuerd_core::effective_group_roles(state.storage.as_ref(), &realm_id, &group.id).await?;
    let effective_ids: std::collections::HashSet<_> =
        effective.iter().map(|r| r.id.clone()).collect();
    let all = issuerd_core::list_all_roles(state.storage.as_ref(), &realm_id).await?;
    let available = all
        .into_iter()
        .filter(|r| !r.client_role && !effective_ids.contains(&r.id))
        .map(Into::into)
        .collect();
    Ok(Json(available))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/realm/composite",
    tag = "Groups",
    summary = "Get effective realm roles of a group",
    description = "Returns the group's effective realm roles with composite expansion. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "Effective realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or group not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_effective_group_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, group) = load_group(&state, &realm, &id).await?;
    let effective =
        issuerd_core::effective_group_roles(state.storage.as_ref(), &realm_id, &group.id).await?;
    Ok(Json(effective.into_iter().filter(|r| !r.client_role).map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}",
    tag = "Groups",
    summary = "Get group client roles",
    description = "Returns the roles of the given client assigned to the group. `{client_id}` is the client's internal UUID. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Assigned client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, group, or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_group_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, group) = load_group(&state, &realm, &id).await?;
    let client = load_group_mapping_client(&state, &realm_id, &client_id).await?;
    let roles = group_client_roles(&state, &realm_id, &group, &client.id).await?;
    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

/// Load the client a `role-mappings/clients/{client_id}` path addresses (the
/// path segment is the client's internal UUID, Keycloak convention).
async fn load_group_mapping_client(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    client_id: &str,
) -> Result<issuerd_core::Client, AdminApiError> {
    let client_id = issuerd_core::ClientId::new(client_id)
        .map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    state
        .storage
        .get_client(realm_id, &client_id)
        .await?
        .ok_or(AdminApiError::NotFound)
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}",
    tag = "Groups",
    summary = "Add client roles to a group",
    description = "Assigns one or more roles of the given client to the group. Roles are addressed by id; an unknown id or a role of another container yields 404. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    request_body(description = "Role representations to assign (id required)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Roles added successfully"),
        (status = 400, description = "Role representation without id", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, group, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_group_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let (realm_id, mut group) = load_group(&state, &realm, &id).await?;
    let client = load_group_mapping_client(&state, &realm_id, &client_id).await?;
    let roles = crate::roles::resolve_role_representations(&state, &realm_id, body.clone()).await?;
    let names = group.client_roles.entry(client.id.clone()).or_default();
    for role in roles {
        if !role.client_role || role.client_id.as_ref() != Some(&client.id) {
            return Err(AdminApiError::NotFound);
        }
        if !names.contains(&role.name) {
            names.push(role.name.clone());
        }
    }
    state.storage.update_group(&realm_id, &group).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::Group,
        &format!("groups/{}/role-mappings/clients/{}", id, client.id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}",
    tag = "Groups",
    summary = "Remove client roles from a group",
    description = "Removes one or more roles of the given client from the group. Roles are addressed by id. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    request_body(description = "Role representations to remove (id required)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Roles removed successfully"),
        (status = 400, description = "Role representation without id", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, group, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_group_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let (realm_id, mut group) = load_group(&state, &realm, &id).await?;
    let client = load_group_mapping_client(&state, &realm_id, &client_id).await?;
    let roles = crate::roles::resolve_role_representations(&state, &realm_id, body.clone()).await?;
    for role in &roles {
        if !role.client_role || role.client_id.as_ref() != Some(&client.id) {
            return Err(AdminApiError::NotFound);
        }
    }
    let names: std::collections::HashSet<_> = roles.iter().map(|r| &r.name).collect();
    let empty = {
        let entry = group.client_roles.entry(client.id.clone()).or_default();
        entry.retain(|n| !names.contains(n));
        entry.is_empty()
    };
    if empty {
        group.client_roles.remove(&client.id);
    }
    state.storage.update_group(&realm_id, &group).await?;
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::Group,
        &format!("groups/{}/role-mappings/clients/{}", id, client.id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}/available",
    tag = "Groups",
    summary = "Get available client roles for a group",
    description = "Returns the roles of the given client that are not part of the group's effective role set. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Available client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, group, or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_available_group_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, group) = load_group(&state, &realm, &id).await?;
    let client = load_group_mapping_client(&state, &realm_id, &client_id).await?;
    let effective =
        issuerd_core::effective_group_roles(state.storage.as_ref(), &realm_id, &group.id).await?;
    let effective_ids: std::collections::HashSet<_> = effective
        .iter()
        .filter(|r| r.client_id.as_ref() == Some(&client.id))
        .map(|r| r.id.clone())
        .collect();
    let all = state
        .storage
        .list_client_roles(
            &realm_id,
            &client.id,
            &Pagination {
                first: 0,
                max: i32::MAX,
            },
        )
        .await?;
    let available = all
        .into_iter()
        .filter(|r| !effective_ids.contains(&r.id))
        .map(Into::into)
        .collect();
    Ok(Json(available))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}/composite",
    tag = "Groups",
    summary = "Get effective client roles of a group",
    description = "Returns the group's effective roles of the given client with composite expansion. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Group ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Effective client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, group, or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_effective_group_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (realm_id, group) = load_group(&state, &realm, &id).await?;
    let client = load_group_mapping_client(&state, &realm_id, &client_id).await?;
    let effective =
        issuerd_core::effective_group_roles(state.storage.as_ref(), &realm_id, &group.id).await?;
    let roles = effective
        .into_iter()
        .filter(|r| r.client_role && r.client_id.as_ref() == Some(&client.id))
        .map(Into::into)
        .collect();
    Ok(Json(roles))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    fn group_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/groups", get(list_groups).post(create_group))
            .route(
                "/admin/realms/{realm}/groups/{id}",
                get(get_group).put(update_group).delete(delete_group),
            )
            .route("/admin/realms/{realm}/groups/{id}/children", post(create_child_group))
            .route("/admin/realms/{realm}/groups/{id}/members", get(get_group_members))
            .route("/admin/realms/{realm}/groups/{id}/role-mappings", get(get_group_role_mappings))
            .route(
                "/admin/realms/{realm}/groups/{id}/role-mappings/realm",
                get(get_group_realm_roles)
                    .post(add_group_realm_roles)
                    .delete(remove_group_realm_roles),
            )
            .route(
                "/admin/realms/{realm}/groups/{id}/role-mappings/realm/available",
                get(get_available_group_realm_roles),
            )
            .route(
                "/admin/realms/{realm}/groups/{id}/role-mappings/realm/composite",
                get(get_effective_group_realm_roles),
            )
            .route(
                "/admin/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}",
                get(get_group_client_roles)
                    .post(add_group_client_roles)
                    .delete(remove_group_client_roles),
            )
            .route(
                "/admin/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}/available",
                get(get_available_group_client_roles),
            )
            .route(
                "/admin/realms/{realm}/groups/{id}/role-mappings/clients/{client_id}/composite",
                get(get_effective_group_client_roles),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn group_crud() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/test/groups")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"admins","path":"/admins"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/groups")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let group = state
            .storage
            .get_group_by_name(&realm.id, "admins")
            .await
            .unwrap()
            .expect("group created above");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/realms/test/groups/{}", group.id.as_ref()))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            state.storage.get_group(&realm.id, &group.id).await.unwrap().is_none(),
            "group must be gone after delete"
        );
    }

    #[tokio::test]
    async fn delete_missing_group_returns_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());

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
                    .uri("/admin/realms/test/groups/no-such-group")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_group_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = group_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let group = issuerd_core::Group {
            id: issuerd_core::GroupId::new("group-1").unwrap(),
            name: issuerd_core::GroupName::new("admins").unwrap(),
            path: issuerd_core::GroupPath::new("/admins").unwrap(),
            realm_id: realm.id.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: std::collections::HashMap::new(),
            realm_roles: vec![],
            client_roles: std::collections::HashMap::new(),
        };
        state.storage.create_group(&realm.id, &group).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/groups/group-1")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: GroupRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.name, "admins");
    }

    #[tokio::test]
    async fn update_group_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let group = issuerd_core::Group {
            id: issuerd_core::GroupId::new("group-1").unwrap(),
            name: issuerd_core::GroupName::new("admins").unwrap(),
            path: issuerd_core::GroupPath::new("/admins").unwrap(),
            realm_id: realm.id.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: std::collections::HashMap::new(),
            realm_roles: vec![],
            client_roles: std::collections::HashMap::new(),
        };
        state.storage.create_group(&realm.id, &group).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/realms/test/groups/group-1")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"admins","path":"/admins"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn create_group_realm_not_found() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/nonexistent/groups")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"admins","path":"/admins"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -- Role mappings --------------------------------------------------------

    async fn role_mapping_fixture(state: &Arc<AdminApiState>) -> (String, issuerd_core::Group) {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        let group = issuerd_core::Group {
            id: issuerd_core::GroupId::new("group-1").unwrap(),
            name: issuerd_core::GroupName::new("admins").unwrap(),
            path: issuerd_core::GroupPath::new("/admins").unwrap(),
            realm_id: realm.id.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: std::collections::HashMap::new(),
            realm_roles: vec![],
            client_roles: std::collections::HashMap::new(),
        };
        state.storage.create_group(&realm.id, &group).await.unwrap();
        (realm.name.to_string(), group)
    }

    async fn create_role(
        state: &Arc<AdminApiState>,
        id: &str,
        name: &str,
        client: Option<&issuerd_core::Client>,
    ) -> issuerd_core::Role {
        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new(id).unwrap(),
            name: issuerd_core::RoleName::new(name).unwrap(),
            description: None,
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            client_role: client.is_some(),
            client_id: client.map(|c| c.id.clone()),
            composite: false,
            composites: vec![],
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_role(&role.realm_id, &role).await.unwrap();
        role
    }

    async fn create_client(
        state: &Arc<AdminApiState>,
        id: &str,
        client_id: &str,
    ) -> issuerd_core::Client {
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new(id).unwrap(),
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
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
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_client(&client.realm_id, &client).await.unwrap();
        client
    }

    #[tokio::test]
    async fn group_realm_role_mappings_roundtrip() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());
        let (realm_name, group) = role_mapping_fixture(&state).await;
        create_role(&state, "role-1", "assigned", None).await;
        create_role(&state, "role-2", "free", None).await;

        // Assign by representation id.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/admin/realms/{realm_name}/groups/{}/role-mappings/realm",
                        group.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"role-1","name":"assigned"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Names land on the group row.
        let stored = state
            .storage
            .get_group(&issuerd_core::RealmId::new("realm-1").unwrap(), &group.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.realm_roles,
            vec![issuerd_core::RoleName::new("assigned").unwrap()],
            "group mappings are stored as role names"
        );

        // GET assigned.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/groups/{}/role-mappings/realm",
                        group.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let roles: Vec<RoleRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["assigned"]);

        // Available / effective.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/groups/{}/role-mappings/realm/available",
                        group.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let roles: Vec<RoleRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["free"]);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/groups/{}/role-mappings/realm/composite",
                        group.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let roles: Vec<RoleRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["assigned"]);

        // Remove.
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/admin/realms/{realm_name}/groups/{}/role-mappings/realm",
                        group.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"role-1","name":"assigned"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let stored = state
            .storage
            .get_group(&issuerd_core::RealmId::new("realm-1").unwrap(), &group.id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.realm_roles.is_empty());
    }

    #[tokio::test]
    async fn group_client_role_mappings_roundtrip() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());
        let (realm_name, group) = role_mapping_fixture(&state).await;
        let client = create_client(&state, "client-1", "my-app").await;
        create_role(&state, "role-a", "app-admin", Some(&client)).await;
        create_role(&state, "role-b", "app-viewer", Some(&client)).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/admin/realms/{realm_name}/groups/{}/role-mappings/clients/client-1",
                        group.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"role-a","name":"app-admin"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Combined mappings representation groups client roles by client_id.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/groups/{}/role-mappings", group.id))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let mappings: crate::dto::MappingsRepresentation = serde_json::from_slice(&body).unwrap();
        assert!(mappings.realm_mappings.is_none());
        let client_mappings = mappings.client_mappings.unwrap();
        let entry = client_mappings.get("my-app").expect("keyed by client_id string");
        assert_eq!(entry.mappings.len(), 1);
        assert_eq!(entry.mappings[0].name, "app-admin");

        // Available lists the unmapped client role.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/groups/{}/role-mappings/clients/client-1/available",
                        group.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let roles: Vec<RoleRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["app-viewer"]);

        // Delete leaves no empty client entry behind.
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/admin/realms/{realm_name}/groups/{}/role-mappings/clients/client-1",
                        group.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"role-a","name":"app-admin"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let stored = state
            .storage
            .get_group(&issuerd_core::RealmId::new("realm-1").unwrap(), &group.id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.client_roles.is_empty());
    }

    #[tokio::test]
    async fn group_role_mappings_unknown_ids_return_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());
        let (realm_name, group) = role_mapping_fixture(&state).await;

        // Unknown group.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/groups/no-such-group/role-mappings"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Unknown role id in the body.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/admin/realms/{realm_name}/groups/{}/role-mappings/realm",
                        group.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"ghost","name":"ghost"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -- Hierarchy ------------------------------------------------------------

    fn realm_fixture() -> issuerd_core::Realm {
        issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        }
    }

    fn group_fixture(
        realm_id: &issuerd_core::RealmId,
        id: &str,
        name: &str,
        path: &str,
        parent_id: Option<issuerd_core::GroupId>,
    ) -> issuerd_core::Group {
        issuerd_core::Group {
            id: issuerd_core::GroupId::new(id).unwrap(),
            name: issuerd_core::GroupName::new(name).unwrap(),
            path: issuerd_core::GroupPath::new(path).unwrap(),
            realm_id: realm_id.clone(),
            parent_id,
            sub_groups: vec![],
            attributes: std::collections::HashMap::new(),
            realm_roles: vec![],
            client_roles: std::collections::HashMap::new(),
        }
    }

    async fn stored_group(state: &Arc<AdminApiState>, id: &str) -> issuerd_core::Group {
        state
            .storage
            .get_group(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::GroupId::new(id).unwrap(),
            )
            .await
            .unwrap()
            .expect("group exists")
    }

    async fn put_group(app: &Router, id: &str, body: String) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/test/groups/{id}"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn create_child_group_sets_parent_and_path() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());
        let realm = realm_fixture();
        state.storage.create_realm(&realm).await.unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/test/groups")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"admins"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let parent = state.storage.get_group_by_name(&realm.id, "admins").await.unwrap().unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/test/groups/{}/children", parent.id))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"ops"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: GroupRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.path.as_deref(), Some("/admins/ops"));
        assert_eq!(rep.parent_id, Some(Some(parent.id.clone())));

        let stored = stored_group(&state, rep.id.as_deref().unwrap()).await;
        assert_eq!(stored.parent_id, Some(parent.id.clone()));
        assert_eq!(stored.path, issuerd_core::GroupPath::new("/admins/ops").unwrap());

        // Unknown parent -> 404.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/test/groups/no-such-group/children")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Name conflict (the backend enforces realm-wide name uniqueness) -> 409.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/test/groups/{}/children", parent.id))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"ops"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // Nested sub_groups in the body are still rejected.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/test/groups/{}/children", parent.id))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"nested","sub_groups":[{"name":"deep"}]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn group_members_paginate() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = group_routes(state.clone());
        let realm = realm_fixture();
        state.storage.create_realm(&realm).await.unwrap();
        let group = group_fixture(&realm.id, "group-1", "team", "/team", None);
        state.storage.create_group(&realm.id, &group).await.unwrap();

        for (id, name) in [("user-1", "alice"), ("user-2", "bob"), ("user-3", "carol")] {
            let user = issuerd_core::User {
                id: issuerd_core::UserId::new(id).unwrap(),
                realm_id: realm.id.clone(),
                username: issuerd_core::Username::new(name).unwrap(),
                email: None,
                email_verified: false,
                first_name: None,
                last_name: None,
                enabled: true,
                federation_link: None,
                attributes: std::collections::HashMap::new(),
                required_actions: vec![],
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            state.storage.create_user(&realm.id, &user).await.unwrap();
            if name != "carol" {
                state.storage.add_user_group(&realm.id, &user.id, &group.id).await.unwrap();
            }
        }

        async fn member_names(app: &Router, uri: String) -> (StatusCode, Vec<String>) {
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
            let names = serde_json::from_slice::<Vec<crate::dto::UserRepresentation>>(&body)
                .map(|users| {
                    assert!(users.iter().all(|u| u.credentials.is_none()));
                    users.into_iter().map(|u| u.username).collect()
                })
                .unwrap_or_default();
            (status, names)
        }

        let (status, names) =
            member_names(&app, "/admin/realms/test/groups/group-1/members".to_string()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(names, vec!["alice", "bob"]);

        let (_, names) = member_names(
            &app,
            "/admin/realms/test/groups/group-1/members?first=1&max=1".to_string(),
        )
        .await;
        assert_eq!(names, vec!["bob"]);

        let (status, _) =
            member_names(&app, "/admin/realms/test/groups/no-such-group/members".to_string()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn move_group_updates_descendant_paths() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());
        let realm = realm_fixture();
        state.storage.create_realm(&realm).await.unwrap();
        // Tree: /a/b/c plus an unrelated root /z.
        for (id, name, path, parent) in [
            ("g-a", "a", "/a", None),
            ("g-b", "b", "/a/b", Some("g-a")),
            ("g-c", "c", "/a/b/c", Some("g-b")),
            ("g-z", "z", "/z", None),
        ] {
            let group = group_fixture(
                &realm.id,
                id,
                name,
                path,
                parent.map(|p| issuerd_core::GroupId::new(p).unwrap()),
            );
            state.storage.create_group(&realm.id, &group).await.unwrap();
        }

        // Move b under z; the whole subtree is repathed.
        let status = put_group(&app, "g-b", r#"{"name":"b","parent_id":"g-z"}"#.to_string()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let moved = stored_group(&state, "g-b").await;
        assert_eq!(moved.parent_id, Some(issuerd_core::GroupId::new("g-z").unwrap()));
        assert_eq!(moved.path, issuerd_core::GroupPath::new("/z/b").unwrap());
        let child = stored_group(&state, "g-c").await;
        assert_eq!(child.path, issuerd_core::GroupPath::new("/z/b/c").unwrap());
        // The old parent is untouched.
        let a = stored_group(&state, "g-a").await;
        assert_eq!(a.path, issuerd_core::GroupPath::new("/a").unwrap());

        // Unknown target parent -> 404.
        let status =
            put_group(&app, "g-c", r#"{"name":"c","parent_id":"ghost"}"#.to_string()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn move_group_cycle_rejected() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());
        let realm = realm_fixture();
        state.storage.create_realm(&realm).await.unwrap();
        for (id, name, path, parent) in
            [("g-a", "a", "/a", None), ("g-b", "b", "/a/b", Some("g-a"))]
        {
            let group = group_fixture(
                &realm.id,
                id,
                name,
                path,
                parent.map(|p| issuerd_core::GroupId::new(p).unwrap()),
            );
            state.storage.create_group(&realm.id, &group).await.unwrap();
        }

        // Moving a under its own child b would create a cycle.
        let status = put_group(&app, "g-a", r#"{"name":"a","parent_id":"g-b"}"#.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Moving a under itself is rejected too.
        let status = put_group(&app, "g-a", r#"{"name":"a","parent_id":"g-a"}"#.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Nothing moved.
        let a = stored_group(&state, "g-a").await;
        assert_eq!(a.parent_id, None);
        assert_eq!(a.path, issuerd_core::GroupPath::new("/a").unwrap());
    }

    #[tokio::test]
    async fn move_group_to_root_with_explicit_null_parent() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());
        let realm = realm_fixture();
        state.storage.create_realm(&realm).await.unwrap();
        for (id, name, path, parent) in [
            ("g-a", "a", "/a", None),
            ("g-b", "b", "/a/b", Some("g-a")),
            ("g-c", "c", "/a/b/c", Some("g-b")),
        ] {
            let group = group_fixture(
                &realm.id,
                id,
                name,
                path,
                parent.map(|p| issuerd_core::GroupId::new(p).unwrap()),
            );
            state.storage.create_group(&realm.id, &group).await.unwrap();
        }

        let status = put_group(&app, "g-b", r#"{"name":"b","parent_id":null}"#.to_string()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let moved = stored_group(&state, "g-b").await;
        assert_eq!(moved.parent_id, None);
        assert_eq!(moved.path, issuerd_core::GroupPath::new("/b").unwrap());
        let child = stored_group(&state, "g-c").await;
        assert_eq!(child.path, issuerd_core::GroupPath::new("/b/c").unwrap());
    }

    #[tokio::test]
    async fn update_group_without_parent_id_preserves_hierarchy() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = group_routes(state.clone());
        let realm = realm_fixture();
        state.storage.create_realm(&realm).await.unwrap();
        for (id, name, path, parent) in
            [("g-a", "a", "/a", None), ("g-b", "b", "/a/b", Some("g-a"))]
        {
            let group = group_fixture(
                &realm.id,
                id,
                name,
                path,
                parent.map(|p| issuerd_core::GroupId::new(p).unwrap()),
            );
            state.storage.create_group(&realm.id, &group).await.unwrap();
        }

        // An update that omits parent_id must not sever the hierarchy.
        let status = put_group(&app, "g-b", r#"{"name":"b","path":"/a/b"}"#.to_string()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let stored = stored_group(&state, "g-b").await;
        assert_eq!(stored.parent_id, Some(issuerd_core::GroupId::new("g-a").unwrap()));
        assert_eq!(stored.path, issuerd_core::GroupPath::new("/a/b").unwrap());
    }
}
