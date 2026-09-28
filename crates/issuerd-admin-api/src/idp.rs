// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Identity provider (brokering) management: instance CRUD and mappers.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{IdpMapper, OperationType, ResourceType};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::IdentityProviderRepresentation,
    error::AdminApiError,
    state::AdminApiState,
};

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/identity-provider/instances",
    tag = "Identity Providers",
    summary = "List identity providers",
    description = "Returns all external identity provider configurations for the realm. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "List of identity providers", body = Vec<IdentityProviderRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_idps(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<Vec<IdentityProviderRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let idps = state.storage.list_identity_providers(&realm_id).await?;
    Ok(Json(idps.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/identity-provider/instances",
    tag = "Identity Providers",
    summary = "Create an identity provider",
    description = "Registers a new external identity provider (e.g. Google, GitHub, SAML). Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Identity provider representation", content = IdentityProviderRepresentation),
    responses(
        (status = 201, description = "Identity provider created successfully", body = IdentityProviderRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - alias already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_idp(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<IdentityProviderRepresentation>,
) -> Result<(StatusCode, Json<IdentityProviderRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let mut idp: issuerd_core::IdentityProviderConfig = body.clone().try_into()?;
    idp.id = issuerd_core::IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap();
    state.storage.create_identity_provider(&realm_id, &idp).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::IdentityProvider,
        &format!("identity-provider/instances/{}", idp.alias),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(idp.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/identity-provider/instances/{alias}",
    tag = "Identity Providers",
    summary = "Get an identity provider",
    description = "Returns the identity provider configuration. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "IdP alias")
    ),
    responses(
        (status = 200, description = "Identity provider found", body = IdentityProviderRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or identity provider not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_idp(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, alias)): axum::extract::Path<(String, String)>,
) -> Result<Json<IdentityProviderRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let idp = state
        .storage
        .get_identity_provider_by_alias(&realm_id, &alias)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(idp.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/identity-provider/instances/{alias}",
    tag = "Identity Providers",
    summary = "Update an identity provider",
    description = "Updates an existing identity provider configuration. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "IdP alias")
    ),
    request_body(description = "Updated identity provider representation", content = IdentityProviderRepresentation),
    responses(
        (status = 204, description = "Identity provider updated successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or identity provider not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_idp(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, alias)): axum::extract::Path<(String, String)>,
    Json(body): Json<IdentityProviderRepresentation>,
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
        .get_identity_provider_by_alias(&realm_id, &alias)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    let mut updated: issuerd_core::IdentityProviderConfig = body.clone().try_into()?;
    updated.id = existing.id;
    state.storage.update_identity_provider(&realm_id, &updated).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::IdentityProvider,
        &format!("identity-provider/instances/{}", alias),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/identity-provider/instances/{alias}",
    tag = "Identity Providers",
    summary = "Delete an identity provider",
    description = "Removes an external identity provider from the realm. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "IdP alias")
    ),
    responses(
        (status = 204, description = "Identity provider deleted successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or identity provider not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_idp(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, alias)): axum::extract::Path<(String, String)>,
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
        .get_identity_provider_by_alias(&realm_id, &alias)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    state.storage.delete_identity_provider(&realm_id, &existing.id).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::IdentityProvider,
        &format!("identity-provider/instances/{}", alias),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// IdP mappers + connection test
// ---------------------------------------------------------------------------

/// Mappers live in the `mappers` config key as a JSON array of [`IdpMapper`].
fn read_mappers(
    idp: &issuerd_core::IdentityProviderConfig,
) -> Result<Vec<IdpMapper>, AdminApiError> {
    match idp.config.get("mappers") {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(raw).map_err(|e| {
            AdminApiError::Internal(anyhow::anyhow!("stored mapper config is malformed: {e}"))
        }),
    }
}

/// Persist the mapper list back into the IdP config (empty list removes the
/// key entirely) and update the IdP row.
async fn write_mappers(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    idp: &issuerd_core::IdentityProviderConfig,
    mappers: &[IdpMapper],
) -> Result<(), AdminApiError> {
    let mut updated = idp.clone();
    if mappers.is_empty() {
        updated.config.remove("mappers");
    } else {
        let raw = serde_json::to_string(mappers).map_err(|e| {
            AdminApiError::Internal(anyhow::anyhow!("mapper serialization failed: {e}"))
        })?;
        updated.config.insert("mappers".to_string(), raw);
    }
    state.storage.update_identity_provider(realm_id, &updated).await?;
    Ok(())
}

/// Shared loader for the mapper sub-resource: realm by name + IdP by alias.
async fn load_idp(
    state: &Arc<AdminApiState>,
    realm: &str,
    alias: &str,
) -> Result<(issuerd_core::RealmId, issuerd_core::IdentityProviderConfig), AdminApiError> {
    let realm_id = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?.id;
    let idp = state
        .storage
        .get_identity_provider_by_alias(&realm_id, alias)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok((realm_id, idp))
}

/// Validate a mapper name: non-empty and free of characters that would break
/// the sub-resource path.
fn validate_mapper(mapper: &IdpMapper) -> Result<(), AdminApiError> {
    if mapper.name.trim().is_empty() {
        return Err(AdminApiError::BadRequest("mapper name is required".to_string()));
    }
    if mapper.name.contains('/') {
        return Err(AdminApiError::BadRequest("mapper name must not contain '/'".to_string()));
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers",
    tag = "Identity Providers",
    summary = "List identity provider mappers",
    description = "Returns the claim-mapping rules of an identity provider. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "IdP alias")
    ),
    responses(
        (status = 200, description = "List of mappers", body = Vec<IdpMapper>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or identity provider not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_idp_mappers(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, alias)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<IdpMapper>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let (_realm_id, idp) = load_idp(&state, &realm, &alias).await?;
    Ok(Json(read_mappers(&idp)?))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers",
    tag = "Identity Providers",
    summary = "Add an identity provider mapper",
    description = "Adds a claim-mapping rule to an identity provider. Mapper names are unique per provider. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "IdP alias")
    ),
    request_body(description = "Mapper definition", content = IdpMapper),
    responses(
        (status = 201, description = "Mapper created", body = IdpMapper),
        (status = 400, description = "Invalid mapper", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or identity provider not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - mapper name already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_idp_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, alias)): axum::extract::Path<(String, String)>,
    Json(body): Json<IdpMapper>,
) -> Result<(StatusCode, Json<IdpMapper>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    validate_mapper(&body)?;
    let (realm_id, idp) = load_idp(&state, &realm, &alias).await?;
    let mut mappers = read_mappers(&idp)?;
    if mappers.iter().any(|m| m.name == body.name) {
        return Err(AdminApiError::Conflict);
    }
    mappers.push(body.clone());
    write_mappers(&state, &realm_id, &idp, &mappers).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::IdentityProvider,
        &format!("identity-provider/instances/{alias}/mappers/{}", body.name),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(body)))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{name}",
    tag = "Identity Providers",
    summary = "Update an identity provider mapper",
    description = "Replaces the mapper stored under `{name}`. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "IdP alias"),
        ("name" = String, Path, description = "Mapper name")
    ),
    request_body(description = "Updated mapper definition", content = IdpMapper),
    responses(
        (status = 204, description = "Mapper updated"),
        (status = 400, description = "Invalid mapper", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, identity provider, or mapper not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - renamed mapper collides", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_idp_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, alias, name)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<IdpMapper>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    validate_mapper(&body)?;
    let (realm_id, idp) = load_idp(&state, &realm, &alias).await?;
    let mut mappers = read_mappers(&idp)?;
    let Some(pos) = mappers.iter().position(|m| m.name == name) else {
        return Err(AdminApiError::NotFound);
    };
    // A rename must not collide with a different existing mapper.
    if body.name != name && mappers.iter().any(|m| m.name == body.name) {
        return Err(AdminApiError::Conflict);
    }
    mappers[pos] = body.clone();
    write_mappers(&state, &realm_id, &idp, &mappers).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::IdentityProvider,
        &format!("identity-provider/instances/{alias}/mappers/{name}"),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{name}",
    tag = "Identity Providers",
    summary = "Delete an identity provider mapper",
    description = "Removes a claim-mapping rule from an identity provider. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "IdP alias"),
        ("name" = String, Path, description = "Mapper name")
    ),
    responses(
        (status = 204, description = "Mapper deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, identity provider, or mapper not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_idp_mapper(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, alias, name)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let (realm_id, idp) = load_idp(&state, &realm, &alias).await?;
    let mut mappers = read_mappers(&idp)?;
    let before = mappers.len();
    mappers.retain(|m| m.name != name);
    if mappers.len() == before {
        return Err(AdminApiError::NotFound);
    }
    write_mappers(&state, &realm_id, &idp, &mappers).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::IdentityProvider,
        &format!("identity-provider/instances/{alias}/mappers/{name}"),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Result of the IdP test-connection endpoint.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct IdpTestConnectionResponse {
    /// `"ok"` when the configuration is usable, `"error"` otherwise.
    pub status: String,
    /// Human-readable problems found (empty when `status == "ok"`).
    pub problems: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/identity-provider/instances/{alias}/test-connection",
    tag = "Identity Providers",
    summary = "Test an identity provider configuration",
    description = "Validates the broker configuration and, when OIDC discovery is enabled, fetches and parses the discovery document. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "IdP alias")
    ),
    responses(
        (status = 200, description = "Configuration is usable", body = IdpTestConnectionResponse),
        (status = 400, description = "Configuration problems found", body = IdpTestConnectionResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or identity provider not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn test_idp_connection(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, alias)): axum::extract::Path<(String, String)>,
) -> Result<(StatusCode, Json<IdpTestConnectionResponse>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let (_realm_id, idp) = load_idp(&state, &realm, &alias).await?;

    let settings = issuerd_core::BrokerIdpSettings::new(&idp);
    let mut problems = settings.validate();
    if !settings.is_broker_provider() {
        problems.push(format!(
            "provider_id '{}' is not a broker-capable provider",
            idp.provider_id.as_str()
        ));
    }
    if !problems.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(IdpTestConnectionResponse {
                status: "error".to_string(),
                problems,
            }),
        ));
    }

    // With discovery enabled, prove the issuer actually serves a parseable
    // discovery document; explicit-URL configs are validated statically only.
    if settings.use_discovery() {
        let issuer = settings.issuer().unwrap_or_default();
        let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let outcome = match state.broker_client.get_json(&url).await {
            Ok(doc) => issuerd_core::BrokerDiscoveryDocument::parse(&doc)
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        if let Err(problem) = outcome {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(IdpTestConnectionResponse {
                    status: "error".to_string(),
                    problems: vec![format!("discovery fetch failed: {problem}")],
                }),
            ));
        }
    }

    Ok((
        StatusCode::OK,
        Json(IdpTestConnectionResponse {
            status: "ok".to_string(),
            problems: vec![],
        }),
    ))
}

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

    fn idp_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/identity-provider/instances",
                get(list_idps).post(create_idp),
            )
            .route(
                "/admin/realms/{realm}/identity-provider/instances/{alias}",
                get(get_idp).put(update_idp).delete(delete_idp),
            )
            .route(
                "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers",
                get(list_idp_mappers).post(create_idp_mapper),
            )
            .route(
                "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{name}",
                put(update_idp_mapper).delete(delete_idp_mapper),
            )
            .route(
                "/admin/realms/{realm}/identity-provider/instances/{alias}/test-connection",
                post(test_idp_connection),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn idp_crud() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = idp_routes(state.clone());

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
                    .uri("/admin/realms/test/identity-provider/instances")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"alias":"google","provider_id":"google"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/identity-provider/instances/google")
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
                    .uri("/admin/realms/test/identity-provider/instances/google")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn list_idps_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = idp_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let idp = issuerd_core::IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("idp-1").unwrap(),
            alias: issuerd_core::Alias::new("google").unwrap(),
            provider_id: issuerd_core::ProviderId::new("google"),
            enabled: true,
            config: std::collections::HashMap::new(),
        };
        state.storage.create_identity_provider(&realm.id, &idp).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/identity-provider/instances")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<IdentityProviderRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
    }

    #[tokio::test]
    async fn update_idp_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = idp_routes(state.clone());

        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();

        let idp = issuerd_core::IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("idp-1").unwrap(),
            alias: issuerd_core::Alias::new("google").unwrap(),
            provider_id: issuerd_core::ProviderId::new("google"),
            enabled: true,
            config: std::collections::HashMap::new(),
        };
        state.storage.create_identity_provider(&realm.id, &idp).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/realms/test/identity-provider/instances/google")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"alias":"google","provider_id":"github"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    // ------------------------------------------------------------------
    // IdP mapper sub-resources + test-connection
    // ------------------------------------------------------------------

    const MAPPERS_URI: &str = "/admin/realms/test/identity-provider/instances/corpidp/mappers";
    const TEST_CONNECTION_URI: &str =
        "/admin/realms/test/identity-provider/instances/corpidp/test-connection";

    fn manage_realm_state() -> Arc<AdminApiState> {
        crate::test_utils::tests::test_state(vec![
            issuerd_core::RoleName::new("manage-realm").unwrap()
        ])
    }

    async fn seed_realm(state: &Arc<AdminApiState>) -> issuerd_core::RealmId {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        realm.id
    }

    async fn seed_idp(
        state: &Arc<AdminApiState>,
        realm_id: &issuerd_core::RealmId,
        provider_id: &str,
        config: std::collections::HashMap<String, String>,
    ) {
        let idp = issuerd_core::IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("idp-1").unwrap(),
            alias: issuerd_core::Alias::new("corpidp").unwrap(),
            provider_id: issuerd_core::ProviderId::new(provider_id),
            enabled: true,
            config,
        };
        state.storage.create_identity_provider(realm_id, &idp).await.unwrap();
    }

    fn idp_config(entries: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        entries.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn req(method: &str, uri: &str, body: Option<&str>) -> Request<Body> {
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
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn list_mappers(app: &Router) -> Vec<IdpMapper> {
        let response = app.clone().oneshot(req("GET", MAPPERS_URI, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_value(body_json(response).await).unwrap()
    }

    #[tokio::test]
    async fn idp_mapper_crud_roundtrip() {
        let state = manage_realm_state();
        let app = idp_routes(state.clone());
        let realm_id = seed_realm(&state).await;
        seed_idp(&state, &realm_id, "oidc", std::collections::HashMap::new()).await;

        // Create: 201, and the mapper shows up in the list.
        let response = app
            .clone()
            .oneshot(req(
                "POST",
                MAPPERS_URI,
                Some(r#"{"name":"org","mapper_type":"attribute","config":{"claim":"org","attribute":"organization"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let mappers = list_mappers(&app).await;
        assert_eq!(mappers.len(), 1);
        assert_eq!(mappers[0].name, "org");

        // A distinct second name is accepted ...
        let response = app
            .clone()
            .oneshot(req(
                "POST",
                MAPPERS_URI,
                Some(r#"{"name":"admins","mapper_type":"role","config":{"claim":"groups","claim_value":"admins","role":"realm-admin"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        // ... while an exact duplicate conflicts.
        let response = app
            .clone()
            .oneshot(req(
                "POST",
                MAPPERS_URI,
                Some(r#"{"name":"org","mapper_type":"attribute","config":{"claim":"x","attribute":"y"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // In-place update (same name) succeeds and persists.
        let response = app
            .clone()
            .oneshot(req(
                "PUT",
                &format!("{MAPPERS_URI}/org"),
                Some(r#"{"name":"org","mapper_type":"attribute","config":{"claim":"department","attribute":"dept"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let mappers = list_mappers(&app).await;
        assert_eq!(mappers.len(), 2);
        let orgs: Vec<&IdpMapper> = mappers.iter().filter(|m| m.name == "org").collect();
        assert_eq!(orgs.len(), 1, "in-place update must not touch the other mapper");
        assert_eq!(orgs[0].config.get("claim").map(String::as_str), Some("department"));

        // Renaming onto an existing mapper name conflicts ...
        let response = app
            .clone()
            .oneshot(req(
                "PUT",
                &format!("{MAPPERS_URI}/org"),
                Some(r#"{"name":"admins","mapper_type":"attribute","config":{}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        // ... renaming to a fresh name succeeds ...
        let response = app
            .clone()
            .oneshot(req(
                "PUT",
                &format!("{MAPPERS_URI}/org"),
                Some(r#"{"name":"org-renamed","mapper_type":"attribute","config":{"claim":"department","attribute":"dept"}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        // ... and updating a mapper that does not exist is a 404.
        let response = app
            .clone()
            .oneshot(req(
                "PUT",
                &format!("{MAPPERS_URI}/missing"),
                Some(r#"{"name":"missing","mapper_type":"attribute","config":{}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Delete removes exactly the named mapper.
        let response = app
            .clone()
            .oneshot(req("DELETE", &format!("{MAPPERS_URI}/admins"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let mappers = list_mappers(&app).await;
        assert_eq!(mappers.len(), 1);
        assert_eq!(mappers[0].name, "org-renamed");

        // Deleting it again is a 404.
        let response = app
            .clone()
            .oneshot(req("DELETE", &format!("{MAPPERS_URI}/admins"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Deleting the last mapper empties the list.
        let response = app
            .clone()
            .oneshot(req("DELETE", &format!("{MAPPERS_URI}/org-renamed"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(list_mappers(&app).await.is_empty());
    }

    #[tokio::test]
    async fn idp_mapper_validation_rejects_bad_names() {
        let state = manage_realm_state();
        let app = idp_routes(state.clone());
        let realm_id = seed_realm(&state).await;
        seed_idp(&state, &realm_id, "oidc", std::collections::HashMap::new()).await;

        for name in ["", "   ", "a/b"] {
            let body = format!(r#"{{"name":"{name}","mapper_type":"attribute","config":{{}}}}"#);
            let response =
                app.clone().oneshot(req("POST", MAPPERS_URI, Some(&body))).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "name {name:?}");
        }
        // Rejected mappers were not stored.
        assert!(list_mappers(&app).await.is_empty());
    }

    #[tokio::test]
    async fn idp_mapper_subresources_404_for_unknown_idp() {
        let state = manage_realm_state();
        let app = idp_routes(state.clone());
        seed_realm(&state).await;

        let base = "/admin/realms/test/identity-provider/instances/nope";
        let response =
            app.clone().oneshot(req("GET", &format!("{base}/mappers"), None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = app
            .clone()
            .oneshot(req("POST", &format!("{base}/test-connection"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn idp_mapper_writes_require_manage_realm() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let app = idp_routes(state.clone());
        let realm_id = seed_realm(&state).await;
        seed_idp(&state, &realm_id, "oidc", std::collections::HashMap::new()).await;

        // The read-only role may list ...
        let response = app.clone().oneshot(req("GET", MAPPERS_URI, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // ... but every mutation is forbidden.
        let mapper =
            r#"{"name":"org","mapper_type":"attribute","config":{"claim":"c","attribute":"a"}}"#;
        let instance = r#"{"alias":"corp2","provider_id":"oidc"}"#;
        let instances_uri = "/admin/realms/test/identity-provider/instances";
        let instance_uri = format!("{instances_uri}/corpidp");
        for (method, uri, body) in [
            ("POST", MAPPERS_URI.to_string(), Some(mapper)),
            ("PUT", format!("{MAPPERS_URI}/org"), Some(mapper)),
            ("DELETE", format!("{MAPPERS_URI}/org"), None),
            ("POST", TEST_CONNECTION_URI.to_string(), None),
            ("POST", instances_uri.to_string(), Some(instance)),
            ("PUT", instance_uri.clone(), Some(instance)),
            ("DELETE", instance_uri, None),
        ] {
            let response = app.clone().oneshot(req(method, &uri, body)).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
        }
    }

    #[test]
    fn validate_mapper_rejects_empty_and_slash_names() {
        let mapper = |name: &str| IdpMapper {
            name: name.to_string(),
            mapper_type: issuerd_core::IdpMapperType::Attribute,
            config: std::collections::HashMap::new(),
        };
        assert!(matches!(validate_mapper(&mapper("")), Err(AdminApiError::BadRequest(_))));
        assert!(matches!(validate_mapper(&mapper("   ")), Err(AdminApiError::BadRequest(_))));
        assert!(matches!(validate_mapper(&mapper("a/b")), Err(AdminApiError::BadRequest(_))));
        assert!(validate_mapper(&mapper("org")).is_ok());
    }

    #[test]
    fn read_mappers_parses_stored_config_and_rejects_malformed() {
        let idp = |config: std::collections::HashMap<String, String>| {
            issuerd_core::IdentityProviderConfig {
                id: issuerd_core::IdentityProviderId::new("idp-1").unwrap(),
                alias: issuerd_core::Alias::new("corpidp").unwrap(),
                provider_id: issuerd_core::ProviderId::new("oidc"),
                enabled: true,
                config,
            }
        };
        // No `mappers` key: empty list.
        assert!(read_mappers(&idp(std::collections::HashMap::new())).unwrap().is_empty());
        // Well-formed JSON: parsed.
        let stored = idp_config(&[(
            "mappers",
            r#"[{"name":"m","mapper_type":"attribute","config":{"claim":"c","attribute":"a"}}]"#,
        )]);
        let mappers = read_mappers(&idp(stored)).unwrap();
        assert_eq!(mappers.len(), 1);
        assert_eq!(mappers[0].name, "m");
        // Malformed JSON is a 500, never silently an empty list.
        let broken = idp_config(&[("mappers", "not-json")]);
        assert!(matches!(read_mappers(&idp(broken)), Err(AdminApiError::Internal(_))));
    }

    #[tokio::test]
    async fn test_connection_static_config_ok() {
        // The default mock broker client has no expectations: any discovery
        // fetch would panic, pinning that a static config is never fetched.
        let state = manage_realm_state();
        let app = idp_routes(state.clone());
        let realm_id = seed_realm(&state).await;
        seed_idp(
            &state,
            &realm_id,
            "oidc",
            idp_config(&[
                ("clientId", "cid"),
                ("clientSecret", "sec"),
                ("useDiscovery", "false"),
                ("authorizationUrl", "https://idp.example.com/auth"),
                ("tokenUrl", "https://idp.example.com/token"),
            ]),
        )
        .await;

        let response = app.oneshot(req("POST", TEST_CONNECTION_URI, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["problems"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_connection_reports_static_config_problems() {
        let state = manage_realm_state();
        let app = idp_routes(state.clone());
        let realm_id = seed_realm(&state).await;
        // Empty config: discovery defaults off (no issuer), so both explicit
        // endpoint URLs are required too.
        seed_idp(&state, &realm_id, "oidc", std::collections::HashMap::new()).await;

        let response = app.oneshot(req("POST", TEST_CONNECTION_URI, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["status"], "error");
        let problems = body["problems"].as_array().unwrap();
        assert_eq!(problems.len(), 4, "{problems:?}");
        for expected in ["clientId", "clientSecret", "authorizationUrl", "tokenUrl"] {
            assert!(
                problems.iter().any(|p| p.as_str().is_some_and(|s| s.contains(expected))),
                "missing problem for {expected}: {problems:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_connection_rejects_non_broker_provider() {
        let state = manage_realm_state();
        let app = idp_routes(state.clone());
        let realm_id = seed_realm(&state).await;
        // Statically valid, but ldap is a federation provider, not a broker.
        seed_idp(
            &state,
            &realm_id,
            "ldap",
            idp_config(&[
                ("clientId", "cid"),
                ("clientSecret", "sec"),
                ("useDiscovery", "false"),
                ("authorizationUrl", "https://idp.example.com/auth"),
                ("tokenUrl", "https://idp.example.com/token"),
            ]),
        )
        .await;

        let response = app.oneshot(req("POST", TEST_CONNECTION_URI, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["status"], "error");
        let problems = body["problems"].as_array().unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0]
            .as_str()
            .is_some_and(|s| s.contains("not a broker-capable provider")));
    }

    #[tokio::test]
    async fn test_connection_discovery_success() {
        let mut broker = issuerd_core::MockBrokerClient::new();
        broker
            .expect_get_json()
            // The seeded issuer has a trailing slash: the fetch URL must not
            // end up with a doubled path separator.
            .withf(|url| {
                url.starts_with("https://idp.example.com/.well-known/openid-configuration")
                    && !url.contains("//.well-known")
            })
            .times(1)
            .returning(|_| {
                Ok(serde_json::json!({
                    "issuer": "https://idp.example.com",
                    "authorization_endpoint": "https://idp.example.com/auth",
                    "token_endpoint": "https://idp.example.com/token"
                }))
            });
        let state = crate::test_utils::tests::test_state_with_broker_client(
            vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
            Arc::new(broker),
        );
        let app = idp_routes(state.clone());
        let realm_id = seed_realm(&state).await;
        seed_idp(
            &state,
            &realm_id,
            "oidc",
            idp_config(&[
                ("clientId", "cid"),
                ("clientSecret", "sec"),
                ("issuer", "https://idp.example.com/"),
            ]),
        )
        .await;

        let response = app.oneshot(req("POST", TEST_CONNECTION_URI, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["problems"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_connection_discovery_fetch_failure() {
        let mut broker = issuerd_core::MockBrokerClient::new();
        broker.expect_get_json().times(1).returning(|_| {
            Err(issuerd_core::IssuerdError::ServerError("connection refused".to_string()))
        });
        let state = crate::test_utils::tests::test_state_with_broker_client(
            vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
            Arc::new(broker),
        );
        let app = idp_routes(state.clone());
        let realm_id = seed_realm(&state).await;
        seed_idp(
            &state,
            &realm_id,
            "oidc",
            idp_config(&[
                ("clientId", "cid"),
                ("clientSecret", "sec"),
                ("issuer", "https://idp.example.com"),
            ]),
        )
        .await;

        let response = app.oneshot(req("POST", TEST_CONNECTION_URI, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["status"], "error");
        let problems = body["problems"].as_array().unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        let problem = problems[0].as_str().unwrap();
        assert!(problem.contains("discovery fetch failed"), "{problem}");
        assert!(problem.contains("connection refused"), "{problem}");
    }

    #[tokio::test]
    async fn test_connection_discovery_unparseable_document() {
        let mut broker = issuerd_core::MockBrokerClient::new();
        // Missing both endpoints the brokering flow cannot live without.
        broker
            .expect_get_json()
            .times(1)
            .returning(|_| Ok(serde_json::json!({"issuer": "https://idp.example.com"})));
        let state = crate::test_utils::tests::test_state_with_broker_client(
            vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
            Arc::new(broker),
        );
        let app = idp_routes(state.clone());
        let realm_id = seed_realm(&state).await;
        seed_idp(
            &state,
            &realm_id,
            "oidc",
            idp_config(&[
                ("clientId", "cid"),
                ("clientSecret", "sec"),
                ("issuer", "https://idp.example.com"),
            ]),
        )
        .await;

        let response = app.oneshot(req("POST", TEST_CONNECTION_URI, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["status"], "error");
        let problems = body["problems"].as_array().unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        let problem = problems[0].as_str().unwrap();
        assert!(problem.contains("discovery fetch failed"), "{problem}");
        assert!(problem.contains("missing"), "{problem}");
    }
}
