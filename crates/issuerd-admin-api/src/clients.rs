// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Client management endpoints: CRUD, secrets, and service-account users.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{ClientId, OperationType, Pagination, ResourceType};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{
        ClientRepresentation, ClientSecret, CountRepresentation, PaginationQueryParams,
        UserRepresentation,
    },
    error::AdminApiError,
    state::AdminApiState,
};

/// Resolve a realm by name and load a client by its internal id.
///
/// Shared by the client sub-resource modules (`client_roles`,
/// `client_scopes`, `scope_mappings`) so every handler applies the same
/// 404/400 mapping.
pub(crate) async fn load_client(
    state: &Arc<AdminApiState>,
    realm: &str,
    id: &str,
) -> Result<(issuerd_core::RealmId, issuerd_core::Client), AdminApiError> {
    let realm_id = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?.id;
    let client_id = ClientId::new(id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let client = state
        .storage
        .get_client(&realm_id, &client_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok((realm_id, client))
}

/// Username of a client's service-account user.
///
/// Mirrors `issuerd_server::claims::service_account_username`; issuerd-admin-api must
/// not depend on issuerd-server, so the formula is duplicated here and the two
/// must be kept in sync.
pub(crate) fn service_account_username(client: &issuerd_core::Client) -> String {
    format!("service-account-{}", client.client_id)
}

/// Return the service-account user for `client`, creating it on first use.
///
/// The user is a plain realm user with no credentials; it exists so the
/// client-credentials grant and admin role-mapping screens have a subject to
/// attach roles to.
pub(crate) async fn ensure_service_account_user(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    client: &issuerd_core::Client,
) -> Result<issuerd_core::User, AdminApiError> {
    let username = service_account_username(client);
    if let Some(user) = state.storage.get_user_by_username(realm_id, &username).await? {
        return Ok(user);
    }
    let now = chrono::Utc::now();
    let user = issuerd_core::User {
        id: issuerd_core::UserId::new(issuerd_core::utils::generate_id())
            .map_err(|e| AdminApiError::BadRequest(e.to_string()))?,
        realm_id: realm_id.clone(),
        username: issuerd_core::Username::new(&username)
            .map_err(|e| AdminApiError::BadRequest(e.to_string()))?,
        email: None,
        email_verified: false,
        first_name: None,
        last_name: None,
        enabled: true,
        federation_link: None,
        attributes: std::collections::HashMap::new(),
        required_actions: Vec::new(),
        created_at: now,
        updated_at: now,
    };
    state.storage.create_user(realm_id, &user).await?;
    Ok(user)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients",
    tag = "Clients",
    summary = "List clients in a realm",
    description = "Returns a paginated list of OIDC/OAuth2 clients in the realm. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        PaginationQueryParams
    ),
    responses(
        (status = 200, description = "List of clients", body = Vec<ClientRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_clients(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<PaginationQueryParams>,
) -> Result<Json<Vec<ClientRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let clients = state
        .storage
        .list_clients(&realm_id, &Pagination::new(params.first, params.max))
        .await?;
    Ok(Json(clients.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/count",
    tag = "Clients",
    summary = "Count clients in a realm",
    description = "Returns the total number of clients in the realm. Requires `view-clients` or `manage-clients` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Client count", body = CountRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn count_clients(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<CountRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let count = state.storage.count_clients(&realm_id).await?;
    Ok(Json(CountRepresentation { count }))
}

/// Seed a client representation's scope lists from the realm's
/// default/optional client-scope tables when the caller omitted them
/// (Keycloak behaviour; an explicit `[]` is respected as "no scopes").
///
/// Shared with the dynamic client registration endpoints so admin-created
/// and self-registered clients validate identically.
pub async fn seed_client_scopes_from_realm_defaults(
    storage: &Arc<dyn issuerd_core::Storage>,
    realm_id: &issuerd_core::RealmId,
    rep: &mut ClientRepresentation,
) -> Result<(), issuerd_core::IssuerdError> {
    if rep.default_scopes.is_some() && rep.optional_scopes.is_some() {
        return Ok(());
    }
    let defaults = storage.list_realm_default_client_scopes(realm_id).await?;
    let mut default_scopes = Vec::new();
    let mut optional_scopes = Vec::new();
    for (scope_id, is_default) in defaults {
        if let Some(scope) = storage.get_client_scope(realm_id, &scope_id).await? {
            if is_default {
                default_scopes.push(scope.name);
            } else {
                optional_scopes.push(scope.name);
            }
        }
    }
    if rep.default_scopes.is_none() {
        rep.default_scopes = Some(default_scopes);
    }
    if rep.optional_scopes.is_none() {
        rep.optional_scopes = Some(optional_scopes);
    }
    Ok(())
}

/// Reject with [`issuerd_core::IssuerdError::Conflict`] when `client_id` is already
/// taken by another client in the realm (`own_id` identifies the client
/// being updated, if any). Without a pre-check a create/rename onto an
/// existing client_id becomes a silent duplicate (InMemory) or a 500
/// (Postgres unique violation).
///
/// Shared with the dynamic client registration endpoints.
pub async fn ensure_client_id_available(
    storage: &Arc<dyn issuerd_core::Storage>,
    realm_id: &issuerd_core::RealmId,
    client_id: &issuerd_core::ClientIdentifier,
    own_id: Option<&ClientId>,
) -> Result<(), issuerd_core::IssuerdError> {
    if let Some(other) = storage.get_client_by_client_id(realm_id, client_id).await? {
        if own_id != Some(&other.id) {
            return Err(issuerd_core::IssuerdError::Conflict);
        }
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/clients",
    tag = "Clients",
    summary = "Create a new client",
    description = "Registers a new OIDC/OAuth2 client in the realm. Requires `manage-clients` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Client representation", content = ClientRepresentation),
    responses(
        (status = 201, description = "Client created successfully", body = ClientRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - client already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_client(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<ClientRepresentation>,
) -> Result<(StatusCode, Json<ClientRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let mut rep = body;
    seed_client_scopes_from_realm_defaults(&state.storage, &realm_id, &mut rep).await?;
    let mut client: issuerd_core::Client = rep.clone().try_into()?;
    ensure_client_id_available(&state.storage, &realm_id, &client.client_id, None).await?;
    client.realm_id = realm_id.clone();
    // OIDC Core §8.1: pairwise clients must resolve to an
    // unambiguous sector; a configured `sector_identifier_uri` is fetched
    // and validated against the registered redirect URIs.
    issuerd_core::pairwise::validate_pairwise_subject_config(&client, state.broker_client.as_ref())
        .await?;
    state.storage.create_client(&client.realm_id, &client).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::Client,
        &format!("clients/{}", client.id),
        serde_json::to_string(&rep.redacted_for_audit()).ok(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(client.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}",
    tag = "Clients",
    summary = "Get a client by ID",
    description = "Returns the client representation. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID")
    ),
    responses(
        (status = 200, description = "Client found", body = ClientRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_client(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<ClientRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let client_id = ClientId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let client = state
        .storage
        .get_client(&realm_id, &client_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(client.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/clients/{id}",
    tag = "Clients",
    summary = "Update a client",
    description = "Updates an existing client configuration. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID")
    ),
    request_body(description = "Updated client representation", content = ClientRepresentation),
    responses(
        (status = 204, description = "Client updated successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_client(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<ClientRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let client_id = ClientId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let existing = state
        .storage
        .get_client(&realm_id, &client_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    let mut updated: issuerd_core::Client = body.clone().try_into()?;
    updated.id = existing.id;
    updated.realm_id = existing.realm_id;
    // A secret-less update body means "leave the secret unchanged", not
    // "clear it" — the representation never round-trips secrets on read.
    if updated.secret.is_none() {
        updated.secret = existing.secret;
    }
    // Scope mappings live behind the `/scope-mappings` sub-resources and are
    // not part of the representation — preserve them across client updates.
    updated.scope_mappings = existing.scope_mappings.clone();
    ensure_client_id_available(&state.storage, &realm_id, &updated.client_id, Some(&updated.id))
        .await?;
    // OIDC Core §8.1: re-validate the pairwise configuration —
    // redirect URIs may have changed under an existing sector setup.
    issuerd_core::pairwise::validate_pairwise_subject_config(
        &updated,
        state.broker_client.as_ref(),
    )
    .await?;
    state.storage.update_client(&realm_id, &updated).await?;
    // The claims-cache client key embeds the public identifier: on rename the
    // OLD identifier's key is the stale one; drop the new one defensively.
    issuerd_cluster::invalidate::invalidate_client_claims(
        state.cache.as_ref(),
        &realm_id,
        &updated.id,
        existing.client_id.as_ref(),
    )
    .await;
    if updated.client_id != existing.client_id {
        issuerd_cluster::invalidate::delete_best_effort(
            state.cache.as_ref(),
            &realm_id,
            &issuerd_cluster::cache_keys::client(realm_id.as_ref(), updated.client_id.as_ref()),
        )
        .await;
    }
    // Flipping service accounts on provisions the backing user immediately so
    // the grant and the role-mapping screens can rely on it existing.
    if updated.service_accounts_enabled {
        ensure_service_account_user(&state, &realm_id, &updated).await?;
    }
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::Client,
        &format!("clients/{}", id),
        serde_json::to_string(&body.redacted_for_audit()).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/clients/{id}",
    tag = "Clients",
    summary = "Delete a client",
    description = "Permanently removes a client from the realm. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID")
    ),
    responses(
        (status = 204, description = "Client deleted successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_client(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let client_id = ClientId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    // Read the row first: the claims-cache client key embeds the public
    // identifier, which the path id (uuid) does not give us.
    let existing = state.storage.get_client(&realm_id, &client_id).await?;
    state.storage.delete_client(&realm_id, &client_id).await?;
    if let Some(client) = existing {
        issuerd_cluster::invalidate::invalidate_client_claims(
            state.cache.as_ref(),
            &realm_id,
            &client_id,
            client.client_id.as_ref(),
        )
        .await;
    }
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::Client,
        &format!("clients/{}", id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/secret",
    tag = "Clients",
    summary = "Get client secret",
    description = "Returns the current client secret. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID")
    ),
    responses(
        (status = 200, description = "Client secret", body = ClientSecret),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_client_secret(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<ClientSecret>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let client_id = ClientId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let client = state
        .storage
        .get_client(&realm_id, &client_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(ClientSecret {
        secret_type: "client-secret".to_string(),
        value: client.secret.unwrap_or_default(),
    }))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/clients/{id}/client-secret",
    tag = "Clients",
    summary = "Rotate client secret",
    description = "Generates a new random client secret and returns it. Requires `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID")
    ),
    responses(
        (status = 200, description = "New client secret", body = ClientSecret),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn rotate_client_secret(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<ClientSecret>, AdminApiError> {
    require_roles(&auth, &["manage-clients"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let client_id = ClientId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let mut client = state
        .storage
        .get_client(&realm_id, &client_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    let new_secret = issuerd_core::utils::generate_id();
    client.secret = Some(new_secret.clone());
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
        OperationType::Action,
        ResourceType::Client,
        &format!("clients/{}", id),
        None,
    )
    .await;
    Ok(Json(ClientSecret {
        secret_type: "client-secret".to_string(),
        value: new_secret,
    }))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/service-account-user",
    tag = "Clients",
    summary = "Get the service-account user of a client",
    description = "Returns the user backing the client's service account, creating it on first use. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID")
    ),
    responses(
        (status = 200, description = "Service-account user", body = UserRepresentation),
        (status = 400, description = "Service accounts are not enabled on this client", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_service_account_user(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<UserRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let (realm_id, client) = load_client(&state, &realm, &id).await?;
    if !client.service_accounts_enabled {
        return Err(AdminApiError::BadRequest(
            "service accounts are not enabled on this client".to_string(),
        ));
    }
    let user = ensure_service_account_user(&state, &realm_id, &client).await?;
    Ok(Json(user.into()))
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
    use issuerd_core::{ClientAuthenticatorType, ClientProtocol};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn client_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/clients", get(list_clients).post(create_client))
            .route(
                "/admin/realms/{realm}/clients/{id}",
                get(get_client).put(update_client).delete(delete_client),
            )
            .route("/admin/realms/{realm}/clients/{id}/secret", get(get_client_secret))
            .route("/admin/realms/{realm}/clients/{id}/client-secret", post(rotate_client_secret))
            .route(
                "/admin/realms/{realm}/clients/{id}/service-account-user",
                get(get_service_account_user),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    async fn create_test_realm_and_client(state: &Arc<AdminApiState>) -> (String, String) {
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
            name: Some(issuerd_core::DisplayName::new("My App").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("old-secret".to_string()),
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
    async fn client_crud() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_routes(state.clone());
        let (realm_name, client_id) = create_test_realm_and_client(&state).await;

        // Get
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}"))
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
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"client_id":"my-app","name":"Updated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // A secret-less update body must leave the stored secret untouched.
        let stored = state
            .storage
            .get_client(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::ClientId::new(&client_id).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.secret.as_deref(), Some("old-secret"));

        // Delete
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rotate_secret_changes_value() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_routes(state.clone());
        let (realm_name, client_id) = create_test_realm_and_client(&state).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/secret"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let old: ClientSecret = serde_json::from_slice(&body).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/client-secret"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let new: ClientSecret = serde_json::from_slice(&body).unwrap();

        assert_ne!(old.value, new.value);
    }

    #[tokio::test]
    async fn list_clients_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let app = client_routes(state.clone());
        let (realm_name, _) = create_test_realm_and_client(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/clients"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<ClientRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
    }

    #[tokio::test]
    async fn get_client_secret_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let app = client_routes(state.clone());
        let (realm_name, client_id) = create_test_realm_and_client(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}/secret"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let secret: ClientSecret = serde_json::from_slice(&body).unwrap();
        assert_eq!(secret.value, "old-secret");
    }

    #[tokio::test]
    async fn update_and_delete_client() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_routes(state.clone());
        let (realm_name, client_id) = create_test_realm_and_client(&state).await;

        // Update
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"client_id":"my-app","name":"Updated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Delete
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify deleted
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_client_realm_not_found() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/nonexistent/clients")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"client_id":"app"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn service_account_user_requires_enabled_client() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let app = client_routes(state.clone());
        let (realm_name, client_id) = create_test_realm_and_client(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/clients/{client_id}/service-account-user"
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn service_account_user_provisioned_on_enable() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_routes(state.clone());
        let (realm_name, client_id) = create_test_realm_and_client(&state).await;

        // Flip service accounts on; the update handler provisions the user.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/clients/{client_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"client_id":"my-app","service_accounts_enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/clients/{client_id}/service-account-user"
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let user: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(user.get("username").and_then(|u| u.as_str()), Some("service-account-my-app"));

        // A second fetch returns the same user rather than creating a new one.
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/clients/{client_id}/service-account-user"
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let user2: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(user.get("id"), user2.get("id"));
    }

    #[tokio::test]
    async fn create_client_fills_realm_default_scopes() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_routes(state.clone());
        let (realm_name, _) = create_test_realm_and_client(&state).await;

        // No scope lists in the body → seeded from the realm default tables.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/clients"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"client_id":"scoped-app"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let defaults: Vec<&str> = rep
            .get("default_scopes")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|s| s.as_str())
            .collect();
        for expected in ["profile", "email", "roles"] {
            assert!(defaults.contains(&expected), "missing default scope {expected}");
        }
        let optionals: Vec<&str> = rep
            .get("optional_scopes")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|s| s.as_str())
            .collect();
        for expected in ["address", "phone", "offline_access", "web-origins", "acr"] {
            assert!(optionals.contains(&expected), "missing optional scope {expected}");
        }
    }

    #[tokio::test]
    async fn create_client_explicit_empty_scope_lists_stay_empty() {
        let state = crate::test_utils::tests::test_state(vec![issuerd_core::RoleName::new(
            "manage-clients",
        )
        .unwrap()]);
        let app = client_routes(state.clone());
        let (realm_name, _) = create_test_realm_and_client(&state).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/clients"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"client_id":"bare-app","default_scopes":[],"optional_scopes":[]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.get("default_scopes").and_then(|v| v.as_array()).map(Vec::len), Some(0));
        assert_eq!(rep.get("optional_scopes").and_then(|v| v.as_array()).map(Vec::len), Some(0));
    }
}
