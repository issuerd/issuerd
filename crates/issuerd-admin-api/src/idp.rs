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
        routing::get,
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
}
