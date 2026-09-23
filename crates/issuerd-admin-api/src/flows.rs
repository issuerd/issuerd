// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Authentication flow management: flows, executions, and authenticator configs.

//! Authentication flow management: list/get plus editable-flow
//! endpoints — create, copy, update, delete, execution (stage) CRUD, and
//! per-stage authenticator configuration. Every structural mutation validates
//! the realm's *post-mutation* flow set with [`validate_flows`] and persists
//! nothing when validation fails; built-in flows are read-only (copy first).

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use issuerd_auth_flow::validation::validate_flows;
use issuerd_core::{
    Alias, AuthenticatorConfig, FlowConfig, FlowStage, FlowStageId, OperationType, Realm, RealmId,
    Requirement, ResourceType,
};

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{
        flow_config_from_representation, AddExecutionRequest, AddFlowExecutionRequest,
        AuthenticatorConfigRepresentation, AuthenticatorConfigRequest, CopyFlowRequest,
        FlowRepresentation, FlowStageRepresentation, UpdateExecutionRequest,
    },
    error::AdminApiError,
    state::AdminApiState,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fetch the realm by name or 404.
async fn load_realm(state: &AdminApiState, realm: &str) -> Result<Realm, AdminApiError> {
    state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)
}

/// Built-in flows are read-only (Keycloak rule): edit a copy instead.
fn ensure_not_built_in(flow: &FlowConfig) -> Result<(), AdminApiError> {
    if flow.built_in {
        return Err(AdminApiError::BadRequest(format!(
            "flow '{}' is built-in: built-in flows are read-only; copy first",
            flow.alias
        )));
    }
    Ok(())
}

/// Validate the realm's flow set as it would look *after* a mutation,
/// returning a 400 that lists every problem found. Callers run this before
/// persisting, so a failed validation leaves storage untouched.
fn validate_post_mutation_set(
    state: &AdminApiState,
    flows: &[FlowConfig],
) -> Result<(), AdminApiError> {
    validate_flows(flows, state.plugin_registry.as_ref())
        .map_err(|errors| AdminApiError::BadRequest(errors.join("; ")))
}

/// Locate a stage by id across the realm's flows, returning the owning flow's
/// index in `flows` and the stage's index within it.
fn find_stage(flows: &[FlowConfig], execution_id: &str) -> Option<(usize, usize)> {
    flows.iter().enumerate().find_map(|(flow_idx, flow)| {
        flow.stages
            .iter()
            .position(|s| s.id.as_ref() == execution_id)
            .map(|stage_idx| (flow_idx, stage_idx))
    })
}

/// Load the flow owning stage `execution_id`: the full flow list, the owning
/// flow's index, and the stage index within it. 404 when no stage matches.
async fn load_stage_owner(
    state: &AdminApiState,
    realm_id: &RealmId,
    execution_id: &str,
) -> Result<(Vec<FlowConfig>, usize, usize), AdminApiError> {
    let flows = state.storage.list_flow_configs(realm_id).await?;
    find_stage(&flows, execution_id)
        .map(|(flow_idx, stage_idx)| (flows, flow_idx, stage_idx))
        .ok_or(AdminApiError::NotFound)
}

/// Return a copy of `flows` with `flow` (matched by alias) replacing the
/// stored entry.
fn replace_flow(flows: &[FlowConfig], flow: &FlowConfig) -> Vec<FlowConfig> {
    flows
        .iter()
        .map(|f| {
            if f.alias == flow.alias {
                flow.clone()
            } else {
                f.clone()
            }
        })
        .collect()
}

/// Replace `flow` in the realm's stored set: validate the resulting set, then
/// persist. Nothing is written when validation fails.
async fn save_flow_update(
    state: &AdminApiState,
    realm_id: &RealmId,
    flow: &FlowConfig,
) -> Result<(), AdminApiError> {
    let flows = state.storage.list_flow_configs(realm_id).await?;
    let candidate = replace_flow(&flows, flow);
    validate_post_mutation_set(state, &candidate)?;
    state.storage.update_flow_config(realm_id, flow).await?;
    Ok(())
}

/// Next stage priority for an appended stage (seeded flows count from 1).
fn next_priority(flow: &FlowConfig) -> i32 {
    flow.stages.iter().map(|s| s.priority).max().unwrap_or(0) + 1
}

// ---------------------------------------------------------------------------
// Flow endpoints
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/authentication/flows",
    tag = "Authentication Flows",
    summary = "List authentication flows",
    description = "Returns all authentication and authorization flows configured in the realm. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "List of authentication flows", body = Vec<FlowRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_flows(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<Vec<FlowRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let flows = state.storage.list_flow_configs(&realm_id).await?;
    Ok(Json(flows.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/authentication/flows",
    tag = "Authentication Flows",
    summary = "Create an authentication flow",
    description = "Creates a new flow. The realm's post-mutation flow set is validated first; a 400 listing every problem is returned and nothing is persisted on failure. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Flow representation", content = FlowRepresentation),
    responses(
        (status = 201, description = "Flow created", body = FlowRepresentation),
        (status = 400, description = "Invalid flow definition (validation errors listed)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "A flow with this alias already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_flow(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<FlowRepresentation>,
) -> Result<(StatusCode, Json<FlowRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let flows = state.storage.list_flow_configs(&realm_id).await?;
    if flows.iter().any(|f| f.alias == body.alias) {
        return Err(AdminApiError::Conflict);
    }
    let representation = serde_json::to_string(&body).ok();
    // A flow created through the admin API is never built-in, whatever the
    // client sent; an omitted `top_level` defaults to true (a new standalone
    // flow), matching Keycloak's `addFlow`.
    let top_level_omitted = body.top_level.is_none();
    let mut flow = flow_config_from_representation(&realm_id, body)?;
    flow.built_in = false;
    if top_level_omitted {
        flow.top_level = true;
    }
    let mut candidate = flows;
    candidate.push(flow.clone());
    validate_post_mutation_set(&state, &candidate)?;
    state.storage.create_flow_config(&realm_id, &flow).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        // No `ResourceType::AuthFlow` exists yet; flows are realm-level
        // configuration, so Realm is the closest resource type.
        ResourceType::Realm,
        &format!("authentication/flows/{}", flow.alias),
        representation,
    )
    .await;
    Ok((StatusCode::CREATED, Json(flow.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/authentication/flows/{flow_alias}",
    tag = "Authentication Flows",
    summary = "Get an authentication flow",
    description = "Returns a single authentication flow with its stages. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("flow_alias" = String, Path, description = "Flow alias")
    ),
    responses(
        (status = 200, description = "Authentication flow found", body = FlowRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or flow not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_flow(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, flow_alias)): axum::extract::Path<(String, String)>,
) -> Result<Json<FlowRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let flow = state
        .storage
        .get_flow_config(&realm_id, &flow_alias)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(flow.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/authentication/flows/{flow_alias}",
    tag = "Authentication Flows",
    summary = "Update an authentication flow",
    description = "Replaces the flow's provider id, top-level flag, and stages. The path alias wins (flows cannot be renamed via PUT), built-in status never changes, and omitted fields keep their stored values. Built-in flows are read-only. The post-mutation flow set is validated before persisting. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("flow_alias" = String, Path, description = "Flow alias")
    ),
    request_body(description = "Flow representation", content = FlowRepresentation),
    responses(
        (status = 204, description = "Flow updated"),
        (status = 400, description = "Built-in flow or invalid flow definition", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or flow not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_flow(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, flow_alias)): axum::extract::Path<(String, String)>,
    Json(body): Json<FlowRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let stored = state
        .storage
        .get_flow_config(&realm_id, &flow_alias)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    ensure_not_built_in(&stored)?;
    let representation = serde_json::to_string(&body).ok();
    let keep_provider_id = body.provider_id.is_none();
    let keep_top_level = body.top_level.is_none();
    let keep_stages = body.stages.is_none();
    let mut updated = flow_config_from_representation(&realm_id, body)?;
    updated.alias = stored.alias.clone();
    updated.built_in = stored.built_in;
    if keep_provider_id {
        updated.provider_id = stored.provider_id.clone();
    }
    if keep_top_level {
        updated.top_level = stored.top_level;
    }
    if keep_stages {
        updated.stages = stored.stages.clone();
    }
    save_flow_update(&state, &realm_id, &updated).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::Realm,
        &format!("authentication/flows/{}", updated.alias),
        representation,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/authentication/flows/{flow_alias}",
    tag = "Authentication Flows",
    summary = "Delete an authentication flow",
    description = "Deletes a flow. Built-in flows cannot be deleted, nor flows referenced by a realm flow binding (browser/direct-grant/reset-credentials/first-broker-login/registration) or by another flow as a sub-flow. The post-delete flow set is validated before persisting. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("flow_alias" = String, Path, description = "Flow alias")
    ),
    responses(
        (status = 204, description = "Flow deleted"),
        (status = 400, description = "Flow is built-in, bound, referenced as a sub-flow, or the post-delete set is invalid", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or flow not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_flow(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, flow_alias)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let flows = state.storage.list_flow_configs(&realm_id).await?;
    let flow = flows
        .iter()
        .find(|f| f.alias.as_str() == flow_alias)
        .ok_or(AdminApiError::NotFound)?;
    ensure_not_built_in(flow)?;

    // Binding guard: an unset binding resolves to its system default alias
    // before comparing, so the default-bound flow is protected too.
    let bindings = [
        ("browser_flow", realm.browser_flow.as_deref().unwrap_or("browser")),
        (
            "direct_grant_flow",
            realm.direct_grant_flow.as_deref().unwrap_or("direct grant"),
        ),
        (
            "reset_credentials_flow",
            realm.reset_credentials_flow.as_deref().unwrap_or("reset credentials"),
        ),
        (
            "first_broker_login_flow",
            realm.first_broker_login_flow.as_deref().unwrap_or("first broker login"),
        ),
        (
            "registration_flow",
            realm.registration_flow.as_deref().unwrap_or("registration"),
        ),
    ];
    for (binding, bound_alias) in bindings {
        if bound_alias == flow_alias {
            return Err(AdminApiError::BadRequest(format!(
                "flow '{flow_alias}' cannot be deleted: it is referenced by the realm's '{binding}' binding"
            )));
        }
    }

    // Sub-flow reference guard.
    for other in &flows {
        if other.alias.as_str() == flow_alias {
            continue;
        }
        if other
            .stages
            .iter()
            .any(|s| s.sub_flow_alias.as_ref().is_some_and(|a| a.as_str() == flow_alias))
        {
            return Err(AdminApiError::BadRequest(format!(
                "flow '{flow_alias}' cannot be deleted: flow '{}' references it as a sub-flow",
                other.alias
            )));
        }
    }

    let candidate: Vec<FlowConfig> =
        flows.iter().filter(|f| f.alias.as_str() != flow_alias).cloned().collect();
    validate_post_mutation_set(&state, &candidate)?;
    state.storage.delete_flow_config(&realm_id, &flow_alias).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::Realm,
        &format!("authentication/flows/{flow_alias}"),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/authentication/flows/{flow_alias}/copy",
    tag = "Authentication Flows",
    summary = "Copy an authentication flow",
    description = "Creates a deep copy of the flow under a new alias: stages are cloned with fresh stage ids, the copy is never built-in, and the top-level flag is preserved. This is how a built-in flow becomes editable. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("flow_alias" = String, Path, description = "Alias of the flow to copy")
    ),
    request_body(description = "Copy request with the new flow alias", content = CopyFlowRequest),
    responses(
        (status = 201, description = "Flow copied", body = FlowRepresentation),
        (status = 400, description = "Invalid new alias or flow definition", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or source flow not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "A flow with the new alias already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn copy_flow(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, flow_alias)): axum::extract::Path<(String, String)>,
    Json(body): Json<CopyFlowRequest>,
) -> Result<(StatusCode, Json<FlowRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let flows = state.storage.list_flow_configs(&realm_id).await?;
    let source = flows
        .iter()
        .find(|f| f.alias.as_str() == flow_alias)
        .ok_or(AdminApiError::NotFound)?;
    let new_alias =
        Alias::new(&body.new_name).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    if flows.iter().any(|f| f.alias == new_alias) {
        return Err(AdminApiError::Conflict);
    }
    let mut copy = source.clone();
    copy.alias = new_alias;
    copy.built_in = false;
    // Deep copy: fresh stage ids so the copy shares nothing with the source.
    for stage in &mut copy.stages {
        stage.id = FlowStageId::new(issuerd_core::utils::generate_id())
            .map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    }
    let mut candidate = flows;
    candidate.push(copy.clone());
    validate_post_mutation_set(&state, &candidate)?;
    state.storage.create_flow_config(&realm_id, &copy).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Realm,
        &format!("authentication/flows/{}", copy.alias),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(copy.into())))
}

// ---------------------------------------------------------------------------
// Execution (stage) endpoints
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/authentication/flows/{flow_alias}/executions/execution",
    tag = "Authentication Flows",
    summary = "Add an authenticator execution to a flow",
    description = "Appends a stage running the given authenticator provider at the next priority. Unknown providers are rejected by flow-set validation. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("flow_alias" = String, Path, description = "Flow alias")
    ),
    request_body(description = "Provider id and optional requirement", content = AddExecutionRequest),
    responses(
        (status = 201, description = "Execution added", body = FlowStageRepresentation),
        (status = 400, description = "Built-in flow, invalid provider, or invalid resulting flow set", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or flow not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_execution(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, flow_alias)): axum::extract::Path<(String, String)>,
    Json(body): Json<AddExecutionRequest>,
) -> Result<(StatusCode, Json<FlowStageRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let mut flow = state
        .storage
        .get_flow_config(&realm_id, &flow_alias)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    ensure_not_built_in(&flow)?;
    let representation = serde_json::to_string(&body).ok();
    let stage = FlowStage {
        id: FlowStageId::new(issuerd_core::utils::generate_id())
            .map_err(|e| AdminApiError::BadRequest(e.to_string()))?,
        requirement: body.requirement.unwrap_or(Requirement::Required),
        authenticator: Alias::new(&body.provider)
            .map_err(|e| AdminApiError::BadRequest(e.to_string()))?,
        priority: next_priority(&flow),
        sub_flow_alias: None,
        authenticator_config: None,
    };
    let stage_id = stage.id.to_string();
    let stage_rep = FlowStageRepresentation::from(stage.clone());
    flow.stages.push(stage);
    save_flow_update(&state, &realm_id, &flow).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Realm,
        &format!("authentication/flows/{flow_alias}/executions/{stage_id}"),
        representation,
    )
    .await;
    Ok((StatusCode::CREATED, Json(stage_rep)))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/authentication/flows/{flow_alias}/executions/flow",
    tag = "Authentication Flows",
    summary = "Add a sub-flow execution to a flow",
    description = "Creates a new non-top-level flow and appends a stage referencing it to the parent flow. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("flow_alias" = String, Path, description = "Parent flow alias")
    ),
    request_body(description = "New sub-flow alias and optional requirement", content = AddFlowExecutionRequest),
    responses(
        (status = 201, description = "Sub-flow created and execution added", body = FlowStageRepresentation),
        (status = 400, description = "Built-in parent flow, invalid alias, or invalid resulting flow set", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or parent flow not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "A flow with the sub-flow alias already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_flow_execution(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, flow_alias)): axum::extract::Path<(String, String)>,
    Json(body): Json<AddFlowExecutionRequest>,
) -> Result<(StatusCode, Json<FlowStageRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let flows = state.storage.list_flow_configs(&realm_id).await?;
    let mut parent = flows
        .iter()
        .find(|f| f.alias.as_str() == flow_alias)
        .cloned()
        .ok_or(AdminApiError::NotFound)?;
    ensure_not_built_in(&parent)?;
    let representation = serde_json::to_string(&body).ok();
    let new_alias =
        Alias::new(&body.alias).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    if flows.iter().any(|f| f.alias == new_alias) {
        return Err(AdminApiError::Conflict);
    }
    let sub_flow = FlowConfig {
        alias: new_alias.clone(),
        realm_id: realm_id.clone(),
        // Keycloak's provider spelling for sub-flows ("basic-flow" is the
        // top-level flow provider); the executor ignores it either way.
        provider_id: "form-flow".to_string(),
        top_level: false,
        built_in: false,
        stages: vec![],
    };
    let stage = FlowStage {
        id: FlowStageId::new(issuerd_core::utils::generate_id())
            .map_err(|e| AdminApiError::BadRequest(e.to_string()))?,
        requirement: body.requirement.unwrap_or(Requirement::Required),
        // The executor ignores `authenticator` while `sub_flow_alias` is
        // `Some`; store the alias string itself for readability.
        authenticator: new_alias.clone(),
        priority: next_priority(&parent),
        sub_flow_alias: Some(new_alias),
        authenticator_config: None,
    };
    let stage_id = stage.id.to_string();
    let stage_rep = FlowStageRepresentation::from(stage.clone());
    parent.stages.push(stage);
    let mut candidate = replace_flow(&flows, &parent);
    candidate.push(sub_flow.clone());
    validate_post_mutation_set(&state, &candidate)?;
    state.storage.create_flow_config(&realm_id, &sub_flow).await?;
    state.storage.update_flow_config(&realm_id, &parent).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Realm,
        &format!("authentication/flows/{flow_alias}/executions/{stage_id}"),
        representation,
    )
    .await;
    Ok((StatusCode::CREATED, Json(stage_rep)))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/authentication/flows/{flow_alias}/executions",
    tag = "Authentication Flows",
    summary = "Update an execution's requirement or priority",
    description = "Updates a single stage within the flow, identified by its stage id. Omitted fields keep their stored values. The post-mutation flow set is validated before persisting. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("flow_alias" = String, Path, description = "Flow alias")
    ),
    request_body(description = "Stage id plus new requirement and/or priority", content = UpdateExecutionRequest),
    responses(
        (status = 204, description = "Execution updated"),
        (status = 400, description = "Built-in flow or invalid resulting flow set", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, flow, or stage not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_execution(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, flow_alias)): axum::extract::Path<(String, String)>,
    Json(body): Json<UpdateExecutionRequest>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let mut flow = state
        .storage
        .get_flow_config(&realm_id, &flow_alias)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    ensure_not_built_in(&flow)?;
    let representation = serde_json::to_string(&body).ok();
    let stage = flow
        .stages
        .iter_mut()
        .find(|s| s.id.as_ref() == body.id)
        .ok_or(AdminApiError::NotFound)?;
    if let Some(requirement) = body.requirement {
        stage.requirement = requirement;
    }
    if let Some(priority) = body.priority {
        stage.priority = priority;
    }
    save_flow_update(&state, &realm_id, &flow).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::Realm,
        &format!("authentication/flows/{flow_alias}/executions/{}", body.id),
        representation,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/authentication/executions/{execution_id}",
    tag = "Authentication Flows",
    summary = "Get an execution by id",
    description = "Finds a stage across all of the realm's flows and returns it, including the alias of the owning flow. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("execution_id" = String, Path, description = "Stage (execution) identifier")
    ),
    responses(
        (status = 200, description = "Execution found", body = FlowStageRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or execution not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_execution(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, execution_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<FlowStageRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let (flows, flow_idx, stage_idx) = load_stage_owner(&state, &realm.id, &execution_id).await?;
    let mut rep = FlowStageRepresentation::from(flows[flow_idx].stages[stage_idx].clone());
    rep.flow_alias = Some(flows[flow_idx].alias.to_string());
    Ok(Json(rep))
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/authentication/executions/{execution_id}",
    tag = "Authentication Flows",
    summary = "Delete an execution",
    description = "Removes the stage from its owning flow. Built-in flows are read-only. The post-delete flow set is validated before persisting. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("execution_id" = String, Path, description = "Stage (execution) identifier")
    ),
    responses(
        (status = 204, description = "Execution deleted"),
        (status = 400, description = "Owning flow is built-in or the post-delete set is invalid", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or execution not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_execution(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, execution_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let (flows, flow_idx, stage_idx) = load_stage_owner(&state, &realm_id, &execution_id).await?;
    let mut flow = flows[flow_idx].clone();
    ensure_not_built_in(&flow)?;
    flow.stages.remove(stage_idx);
    let candidate = replace_flow(&flows, &flow);
    validate_post_mutation_set(&state, &candidate)?;
    state.storage.update_flow_config(&realm_id, &flow).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::Realm,
        &format!("authentication/executions/{execution_id}"),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Per-stage authenticator configuration endpoints
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/authentication/executions/{execution_id}/config",
    tag = "Authentication Flows",
    summary = "Get an execution's authenticator configuration",
    description = "Returns the stage's embedded authenticator configuration. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("execution_id" = String, Path, description = "Stage (execution) identifier")
    ),
    responses(
        (status = 200, description = "Authenticator configuration", body = AuthenticatorConfigRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, execution, or configuration not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_execution_config(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, execution_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<AuthenticatorConfigRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let (flows, flow_idx, stage_idx) = load_stage_owner(&state, &realm.id, &execution_id).await?;
    let config = flows[flow_idx].stages[stage_idx]
        .authenticator_config
        .clone()
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(config.into()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/authentication/executions/{execution_id}/config",
    tag = "Authentication Flows",
    summary = "Create an execution's authenticator configuration",
    description = "Attaches an authenticator configuration to the stage; a stage carries at most one. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("execution_id" = String, Path, description = "Stage (execution) identifier")
    ),
    request_body(description = "Configuration alias and key/value map", content = AuthenticatorConfigRequest),
    responses(
        (status = 201, description = "Configuration created", body = AuthenticatorConfigRepresentation),
        (status = 400, description = "Configuration already exists or owning flow is built-in", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or execution not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_execution_config(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, execution_id)): axum::extract::Path<(String, String)>,
    Json(body): Json<AuthenticatorConfigRequest>,
) -> Result<(StatusCode, Json<AuthenticatorConfigRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let (flows, flow_idx, stage_idx) = load_stage_owner(&state, &realm_id, &execution_id).await?;
    let mut flow = flows[flow_idx].clone();
    ensure_not_built_in(&flow)?;
    if flow.stages[stage_idx].authenticator_config.is_some() {
        return Err(AdminApiError::BadRequest(format!(
            "execution '{execution_id}' already has an authenticator configuration"
        )));
    }
    let representation = serde_json::to_string(&body).ok();
    let config = AuthenticatorConfig {
        alias: Alias::new(&body.alias).map_err(|e| AdminApiError::BadRequest(e.to_string()))?,
        config: body.config.into_iter().collect(),
    };
    let rep = AuthenticatorConfigRepresentation::from(config.clone());
    flow.stages[stage_idx].authenticator_config = Some(config);
    // The config does not affect flow structure, so no flow-set validation
    // runs here.
    state.storage.update_flow_config(&realm_id, &flow).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Realm,
        &format!("authentication/executions/{execution_id}/config"),
        representation,
    )
    .await;
    Ok((StatusCode::CREATED, Json(rep)))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/authentication/executions/{execution_id}/config",
    tag = "Authentication Flows",
    summary = "Replace an execution's authenticator configuration",
    description = "Replaces the stage's existing authenticator configuration. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("execution_id" = String, Path, description = "Stage (execution) identifier")
    ),
    request_body(description = "Configuration alias and key/value map", content = AuthenticatorConfigRequest),
    responses(
        (status = 204, description = "Configuration updated"),
        (status = 400, description = "Owning flow is built-in", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, execution, or configuration not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_execution_config(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, execution_id)): axum::extract::Path<(String, String)>,
    Json(body): Json<AuthenticatorConfigRequest>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let (flows, flow_idx, stage_idx) = load_stage_owner(&state, &realm_id, &execution_id).await?;
    let mut flow = flows[flow_idx].clone();
    ensure_not_built_in(&flow)?;
    if flow.stages[stage_idx].authenticator_config.is_none() {
        return Err(AdminApiError::NotFound);
    }
    let representation = serde_json::to_string(&body).ok();
    flow.stages[stage_idx].authenticator_config = Some(AuthenticatorConfig {
        alias: Alias::new(&body.alias).map_err(|e| AdminApiError::BadRequest(e.to_string()))?,
        config: body.config.into_iter().collect(),
    });
    state.storage.update_flow_config(&realm_id, &flow).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::Realm,
        &format!("authentication/executions/{execution_id}/config"),
        representation,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/authentication/executions/{execution_id}/config",
    tag = "Authentication Flows",
    summary = "Delete an execution's authenticator configuration",
    description = "Removes the stage's authenticator configuration. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("execution_id" = String, Path, description = "Stage (execution) identifier")
    ),
    responses(
        (status = 204, description = "Configuration deleted"),
        (status = 400, description = "Owning flow is built-in", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, execution, or configuration not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_execution_config(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, execution_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let realm_id = realm.id.clone();
    let (flows, flow_idx, stage_idx) = load_stage_owner(&state, &realm_id, &execution_id).await?;
    let mut flow = flows[flow_idx].clone();
    ensure_not_built_in(&flow)?;
    if flow.stages[stage_idx].authenticator_config.is_none() {
        return Err(AdminApiError::NotFound);
    }
    flow.stages[stage_idx].authenticator_config = None;
    state.storage.update_flow_config(&realm_id, &flow).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::Realm,
        &format!("authentication/executions/{execution_id}/config"),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post, put},
        Router,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    fn flow_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/authentication/flows", get(list_flows).post(create_flow))
            .route(
                "/admin/realms/{realm}/authentication/flows/{flow_alias}",
                get(get_flow).put(update_flow).delete(delete_flow),
            )
            .route("/admin/realms/{realm}/authentication/flows/{flow_alias}/copy", post(copy_flow))
            .route(
                "/admin/realms/{realm}/authentication/flows/{flow_alias}/executions",
                put(update_execution),
            )
            .route(
                "/admin/realms/{realm}/authentication/flows/{flow_alias}/executions/execution",
                post(add_execution),
            )
            .route(
                "/admin/realms/{realm}/authentication/flows/{flow_alias}/executions/flow",
                post(add_flow_execution),
            )
            .route(
                "/admin/realms/{realm}/authentication/executions/{execution_id}",
                get(get_execution).delete(delete_execution),
            )
            .route(
                "/admin/realms/{realm}/authentication/executions/{execution_id}/config",
                get(get_execution_config)
                    .post(create_execution_config)
                    .put(update_execution_config)
                    .delete(delete_execution_config),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    fn manage_state() -> Arc<AdminApiState> {
        crate::test_utils::tests::test_state(vec![
            issuerd_core::RoleName::new("manage-realm").unwrap()
        ])
    }

    /// Create the `test` realm; creation seeds the built-in `browser` and
    /// `registration` flows.
    async fn seeded_realm(state: &Arc<AdminApiState>) -> issuerd_core::Realm {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        realm
    }

    fn authed_request(method: &str, uri: &str, body: Option<serde_json::Value>) -> Request<Body> {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", "Bearer valid-token");
        match body {
            Some(json) => builder
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&json).unwrap()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Create a plain top-level flow with one required `auth-cookie` stage.
    async fn create_custom_flow(app: &Router, alias: &str) {
        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows",
                Some(serde_json::json!({
                    "alias": alias,
                    "stages": [{
                        "id": "s1",
                        "requirement": "required",
                        "authenticator": "auth-cookie",
                        "priority": 1
                    }]
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED, "create flow '{alias}'");
    }

    #[tokio::test]
    async fn get_flow_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = flow_routes(state.clone());
        seeded_realm(&state).await;

        let response = app
            .oneshot(authed_request("GET", "/admin/realms/test/authentication/flows/browser", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_flows_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = flow_routes(state.clone());
        seeded_realm(&state).await;

        let response = app
            .oneshot(authed_request("GET", "/admin/realms/test/authentication/flows", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let aliases: Vec<&str> =
            json.as_array().unwrap().iter().filter_map(|f| f["alias"].as_str()).collect();
        assert!(aliases.contains(&"browser"));
        assert!(aliases.contains(&"registration"));
    }

    #[tokio::test]
    async fn create_flow_and_duplicate_conflict() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        let realm = seeded_realm(&state).await;

        create_custom_flow(&app, "custom").await;
        let stored = state.storage.get_flow_config(&realm.id, "custom").await.unwrap().unwrap();
        assert!(!stored.built_in);
        assert!(stored.top_level);

        let response = app
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows",
                Some(serde_json::json!({"alias": "custom"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn create_flow_validation_failure_persists_nothing() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        let realm = seeded_realm(&state).await;

        let response = app
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows",
                Some(serde_json::json!({
                    "alias": "bad",
                    "stages": [{
                        "id": "s1",
                        "requirement": "required",
                        "authenticator": "nope",
                        "priority": 1
                    }]
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert!(json["errorMessage"].as_str().unwrap().contains("unknown authenticator"));
        assert!(state.storage.get_flow_config(&realm.id, "bad").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn copy_flow_produces_editable_flow() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        let realm = seeded_realm(&state).await;
        let source = state.storage.get_flow_config(&realm.id, "browser").await.unwrap().unwrap();
        assert!(source.built_in);

        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows/browser/copy",
                Some(serde_json::json!({"newName": "browser-copy"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let copy = state.storage.get_flow_config(&realm.id, "browser-copy").await.unwrap().unwrap();
        assert!(!copy.built_in);
        assert_eq!(copy.top_level, source.top_level);
        assert_eq!(copy.stages.len(), source.stages.len());
        // Deep copy: fresh stage ids, same authenticators in the same order.
        for (new_stage, old_stage) in copy.stages.iter().zip(source.stages.iter()) {
            assert_ne!(new_stage.id, old_stage.id);
            assert_eq!(new_stage.authenticator, old_stage.authenticator);
        }

        // The copy — unlike its built-in source — is editable.
        let rep = FlowRepresentation::from(copy);
        let response = app
            .clone()
            .oneshot(authed_request(
                "PUT",
                "/admin/realms/test/authentication/flows/browser-copy",
                Some(serde_json::to_value(&rep).unwrap()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Copying to an existing alias conflicts.
        let response = app
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows/browser/copy",
                Some(serde_json::json!({"newName": "browser-copy"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn update_and_delete_builtin_flow_rejected() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        seeded_realm(&state).await;

        let put = app
            .clone()
            .oneshot(authed_request(
                "PUT",
                "/admin/realms/test/authentication/flows/browser",
                Some(serde_json::json!({"alias": "browser"})),
            ))
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::BAD_REQUEST);
        let json = body_json(put).await;
        assert!(json["errorMessage"].as_str().unwrap().contains("read-only"));

        let delete = app
            .oneshot(authed_request(
                "DELETE",
                "/admin/realms/test/authentication/flows/browser",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::BAD_REQUEST);
        let json = body_json(delete).await;
        assert!(json["errorMessage"].as_str().unwrap().contains("read-only"));
    }

    #[tokio::test]
    async fn delete_flow_rejected_when_bound_explicitly() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        let realm = seeded_realm(&state).await;

        create_custom_flow(&app, "custom-browser").await;
        let mut bound_realm = realm.clone();
        bound_realm.browser_flow = Some("custom-browser".to_string());
        state.storage.update_realm(&bound_realm).await.unwrap();

        let response = app
            .oneshot(authed_request(
                "DELETE",
                "/admin/realms/test/authentication/flows/custom-browser",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert!(json["errorMessage"].as_str().unwrap().contains("browser_flow"));
    }

    #[tokio::test]
    async fn delete_flow_rejected_when_bound_implicitly_by_default() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        seeded_realm(&state).await;

        // The realm's `direct_grant_flow` is None, which resolves to the
        // system default alias "direct grant" — occupied by this custom flow.
        create_custom_flow(&app, "direct grant").await;

        let response = app
            .oneshot(authed_request(
                "DELETE",
                "/admin/realms/test/authentication/flows/direct%20grant",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert!(json["errorMessage"].as_str().unwrap().contains("direct_grant_flow"));
    }

    #[tokio::test]
    async fn delete_flow_rejected_when_referenced_as_sub_flow() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        seeded_realm(&state).await;

        // Non-top-level child flow (no stages is valid for a sub-flow).
        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows",
                Some(serde_json::json!({"alias": "child", "top_level": false})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Parent referencing the child as a sub-flow stage.
        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows",
                Some(serde_json::json!({
                    "alias": "parent",
                    "stages": [{
                        "id": "s1",
                        "requirement": "required",
                        "authenticator": "child",
                        "sub_flow_alias": "child",
                        "priority": 1
                    }]
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = app
            .oneshot(authed_request(
                "DELETE",
                "/admin/realms/test/authentication/flows/child",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert!(json["errorMessage"].as_str().unwrap().contains("parent"));
    }

    #[tokio::test]
    async fn delete_flow_success() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        let realm = seeded_realm(&state).await;

        create_custom_flow(&app, "custom").await;
        let response = app
            .clone()
            .oneshot(authed_request(
                "DELETE",
                "/admin/realms/test/authentication/flows/custom",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(state.storage.get_flow_config(&realm.id, "custom").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn add_execution_appends_stage_and_invalid_provider_rejected() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        let realm = seeded_realm(&state).await;
        create_custom_flow(&app, "custom").await;

        // Known provider: appended at max priority + 1 with default requirement.
        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows/custom/executions/execution",
                Some(serde_json::json!({"provider": "auth-otp-form"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let stored = state.storage.get_flow_config(&realm.id, "custom").await.unwrap().unwrap();
        assert_eq!(stored.stages.len(), 2);
        assert_eq!(stored.stages[1].authenticator.as_str(), "auth-otp-form");
        assert_eq!(stored.stages[1].priority, 2);
        assert_eq!(stored.stages[1].requirement, Requirement::Required);

        // Unknown provider: rejected by flow-set validation, nothing persisted.
        let response = app
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows/custom/executions/execution",
                Some(serde_json::json!({"provider": "nope"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert!(json["errorMessage"].as_str().unwrap().contains("unknown authenticator"));
        let stored = state.storage.get_flow_config(&realm.id, "custom").await.unwrap().unwrap();
        assert_eq!(stored.stages.len(), 2);
    }

    #[tokio::test]
    async fn add_flow_execution_creates_sub_flow_and_stage() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        let realm = seeded_realm(&state).await;
        create_custom_flow(&app, "custom").await;

        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows/custom/executions/flow",
                Some(serde_json::json!({"alias": "custom-sub"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let sub = state.storage.get_flow_config(&realm.id, "custom-sub").await.unwrap().unwrap();
        assert!(!sub.top_level);
        assert!(!sub.built_in);
        assert!(sub.stages.is_empty());

        let parent = state.storage.get_flow_config(&realm.id, "custom").await.unwrap().unwrap();
        assert_eq!(parent.stages.len(), 2);
        let stage = &parent.stages[1];
        assert_eq!(stage.sub_flow_alias.as_ref().map(|a| a.as_str()), Some("custom-sub"));
        assert_eq!(stage.authenticator.as_str(), "custom-sub");
        assert_eq!(stage.priority, 2);

        // Reusing an existing flow alias conflicts.
        let response = app
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows/custom/executions/flow",
                Some(serde_json::json!({"alias": "custom-sub"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn update_execution_changes_requirement_and_priority() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        let realm = seeded_realm(&state).await;
        create_custom_flow(&app, "custom").await;
        // A second stage so the flow still has an enabled stage afterwards.
        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows/custom/executions/execution",
                Some(serde_json::json!({"provider": "auth-otp-form"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = app
            .clone()
            .oneshot(authed_request(
                "PUT",
                "/admin/realms/test/authentication/flows/custom/executions",
                Some(serde_json::json!({
                    "id": "s1",
                    "requirement": "optional",
                    "priority": 5
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let stored = state.storage.get_flow_config(&realm.id, "custom").await.unwrap().unwrap();
        let stage = stored.stages.iter().find(|s| s.id.as_ref() == "s1").unwrap();
        assert_eq!(stage.requirement, Requirement::Optional);
        assert_eq!(stage.priority, 5);

        // Unknown stage id → 404.
        let response = app
            .oneshot(authed_request(
                "PUT",
                "/admin/realms/test/authentication/flows/custom/executions",
                Some(serde_json::json!({"id": "missing", "requirement": "optional"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_and_delete_execution_by_id() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        let realm = seeded_realm(&state).await;
        create_custom_flow(&app, "custom").await;
        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/flows/custom/executions/execution",
                Some(serde_json::json!({"provider": "auth-otp-form"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        let new_id = created["id"].as_str().unwrap().to_string();

        // Cross-flow lookup returns the stage and names its owning flow.
        let response = app
            .clone()
            .oneshot(authed_request(
                "GET",
                &format!("/admin/realms/test/authentication/executions/{new_id}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["flow_alias"], "custom");
        assert_eq!(json["authenticator"], "auth-otp-form");

        let response = app
            .clone()
            .oneshot(authed_request(
                "GET",
                "/admin/realms/test/authentication/executions/missing",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .clone()
            .oneshot(authed_request(
                "DELETE",
                &format!("/admin/realms/test/authentication/executions/{new_id}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let stored = state.storage.get_flow_config(&realm.id, "custom").await.unwrap().unwrap();
        assert_eq!(stored.stages.len(), 1);

        let response = app
            .oneshot(authed_request(
                "DELETE",
                &format!("/admin/realms/test/authentication/executions/{new_id}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_execution_on_builtin_flow_rejected() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        seeded_realm(&state).await;

        // `cookie-auth` is a stage of the seeded built-in browser flow.
        let response = app
            .oneshot(authed_request(
                "DELETE",
                "/admin/realms/test/authentication/executions/cookie-auth",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn execution_config_crud_roundtrip() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        seeded_realm(&state).await;
        create_custom_flow(&app, "custom").await;

        let config_uri = "/admin/realms/test/authentication/executions/s1/config";

        // No config yet → 404.
        let response = app.clone().oneshot(authed_request("GET", config_uri, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Create.
        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                config_uri,
                Some(serde_json::json!({"alias": "cookie-cfg", "config": {"maxAge": "3600"}})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Read back.
        let response = app.clone().oneshot(authed_request("GET", config_uri, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["alias"], "cookie-cfg");
        assert_eq!(json["config"]["maxAge"], "3600");

        // Second create → 400.
        let response = app
            .clone()
            .oneshot(authed_request(
                "POST",
                config_uri,
                Some(serde_json::json!({"alias": "other", "config": {}})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Update.
        let response = app
            .clone()
            .oneshot(authed_request(
                "PUT",
                config_uri,
                Some(serde_json::json!({"alias": "cookie-cfg-2", "config": {"maxAge": "60"}})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app.clone().oneshot(authed_request("GET", config_uri, None)).await.unwrap();
        let json = body_json(response).await;
        assert_eq!(json["alias"], "cookie-cfg-2");
        assert_eq!(json["config"]["maxAge"], "60");

        // Delete, then both read and delete → 404.
        let response =
            app.clone().oneshot(authed_request("DELETE", config_uri, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app.clone().oneshot(authed_request("GET", config_uri, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = app.oneshot(authed_request("DELETE", config_uri, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn execution_config_on_builtin_flow_rejected() {
        let state = manage_state();
        let app = flow_routes(state.clone());
        seeded_realm(&state).await;

        let response = app
            .oneshot(authed_request(
                "POST",
                "/admin/realms/test/authentication/executions/cookie-auth/config",
                Some(serde_json::json!({"alias": "cfg", "config": {}})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
