// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Partial realm import, full realm export, and the push-revocation stub.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{OperationType, Pagination, ResourceType};
use std::{collections::HashMap, sync::Arc};

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{
        ClientRepresentation, ClientScopeRepresentation, ExportRolesRepresentation,
        GroupRepresentation, IdentityProviderRepresentation, IfResourceExists, ImportAction,
        PartialImportParams, PartialImportRepresentation, PartialImportResultEntry,
        PartialImportResultRepresentation, RealmExportRepresentation, RoleRepresentation,
        UserRepresentation,
    },
    error::AdminApiError,
    state::AdminApiState,
};
use tracing::instrument;

/// Record one per-resource outcome in the import summary.
fn record(
    summary: &mut PartialImportResultRepresentation,
    resource_type: ResourceType,
    resource_name: String,
    action: ImportAction,
) {
    match action {
        ImportAction::Added => summary.added += 1,
        ImportAction::Skipped => summary.skipped += 1,
        ImportAction::Updated => summary.updated += 1,
    }
    summary.results.push(PartialImportResultEntry {
        resource_type,
        resource_name,
        action,
    });
}

/// 409 naming the colliding resource (Keycloak partial-import FAIL semantics).
fn conflict(resource: &str, name: &str) -> AdminApiError {
    AdminApiError::ConflictWithMessage(format!(
        "{resource} '{name}' already exists (ifResourceExists=FAIL)"
    ))
}

/// Import one user, matched by username.
///
/// Users are imported **without credentials**: the [`issuerd_core::User`] model
/// carries no credential fields, so converting the representation drops
/// `credentials` (and the `realm_roles`/`client_roles`/`groups` assignment
/// lists, which stay the job of the role-mappings/groups endpoints) entirely.
/// Realm default groups are intentionally not resolved — they belong to
/// interactive user creation.
async fn import_user(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    strategy: IfResourceExists,
    rep: UserRepresentation,
    summary: &mut PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    let name = rep.username.clone();
    let existing = state.storage.get_user_by_username(realm_id, &rep.username).await?;
    match (existing, strategy) {
        (None, _) => {
            let mut user: issuerd_core::User = rep.try_into()?;
            user.realm_id = realm_id.clone();
            state.storage.create_user(realm_id, &user).await?;
            record(summary, ResourceType::User, name, ImportAction::Added);
        }
        (Some(_), IfResourceExists::Fail) => return Err(conflict("user", &name)),
        (Some(_), IfResourceExists::Skip) => {
            record(summary, ResourceType::User, name, ImportAction::Skipped);
        }
        (Some(existing), IfResourceExists::Overwrite) => {
            // Same preserve rules as `PUT /users/{id}`: identity, creation
            // timestamp, and federation link survive the overwrite.
            let mut updated: issuerd_core::User = rep.try_into()?;
            updated.id = existing.id;
            updated.realm_id = existing.realm_id;
            updated.created_at = existing.created_at;
            updated.federation_link = existing.federation_link;
            state.storage.update_user(realm_id, &updated).await?;
            record(summary, ResourceType::User, name, ImportAction::Updated);
        }
    }
    Ok(())
}

/// Import one top-level group, matched by name (storage enforces
/// realm-wide group-name uniqueness).
async fn import_group(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    strategy: IfResourceExists,
    rep: GroupRepresentation,
    summary: &mut PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    let name = rep.name.clone();
    if rep.sub_groups.as_ref().is_some_and(|s| !s.is_empty()) {
        return Err(AdminApiError::BadRequest(
            "sub_groups in the import document are not supported; import top-level groups and create subgroups via POST /groups/{id}/children"
                .to_string(),
        ));
    }
    let existing = state.storage.get_group_by_name(realm_id, &rep.name).await?;
    match (existing, strategy) {
        (None, _) => {
            let mut group: issuerd_core::Group = rep.try_into()?;
            group.realm_id = realm_id.clone();
            // Imports create top-level groups only; the path is derived from
            // the name (a document path like "/parent/child" would lie about
            // the stored hierarchy).
            group.parent_id = None;
            group.path = issuerd_core::GroupPath::new(format!("/{}", group.name))?;
            state.storage.create_group(realm_id, &group).await?;
            record(summary, ResourceType::Group, name, ImportAction::Added);
        }
        (Some(_), IfResourceExists::Fail) => return Err(conflict("group", &name)),
        (Some(_), IfResourceExists::Skip) => {
            record(summary, ResourceType::Group, name, ImportAction::Skipped);
        }
        (Some(existing), IfResourceExists::Overwrite) => {
            // Same omitted-means-keep rules as `PUT /groups/{id}`; import
            // never re-parents or re-paths an existing group.
            let keep_realm_roles = rep.realm_roles.is_none();
            let keep_client_roles = rep.client_roles.is_none();
            let keep_attributes = rep.attributes.is_none();
            let mut updated: issuerd_core::Group = rep.try_into()?;
            updated.id = existing.id;
            updated.realm_id = existing.realm_id;
            updated.parent_id = existing.parent_id;
            updated.path = existing.path;
            updated.sub_groups = existing.sub_groups;
            if keep_realm_roles {
                updated.realm_roles = existing.realm_roles;
            }
            if keep_client_roles {
                updated.client_roles = existing.client_roles;
            }
            if keep_attributes {
                updated.attributes = existing.attributes;
            }
            state.storage.update_group(realm_id, &updated).await?;
            record(summary, ResourceType::Group, name, ImportAction::Updated);
        }
    }
    Ok(())
}

/// Import one client, matched by `client_id`.
async fn import_client(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    strategy: IfResourceExists,
    rep: ClientRepresentation,
    summary: &mut PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    let name = rep.client_id.clone();
    let identifier = issuerd_core::ClientIdentifier::new(rep.client_id.clone())?;
    let existing = state.storage.get_client_by_client_id(realm_id, &identifier).await?;
    match (existing, strategy) {
        (None, _) => {
            // Unlike `POST /clients`, omitted scope lists are not seeded from
            // the realm default-scope tables: import stores the document
            // verbatim.
            let mut client: issuerd_core::Client = rep.try_into()?;
            client.realm_id = realm_id.clone();
            state.storage.create_client(realm_id, &client).await?;
            record(summary, ResourceType::Client, name, ImportAction::Added);
        }
        (Some(_), IfResourceExists::Fail) => return Err(conflict("client", &name)),
        (Some(_), IfResourceExists::Skip) => {
            record(summary, ResourceType::Client, name, ImportAction::Skipped);
        }
        (Some(existing), IfResourceExists::Overwrite) => {
            // Same preserve rules as `PUT /clients/{id}`: an omitted secret
            // and the scope mappings survive the overwrite.
            let mut updated: issuerd_core::Client = rep.try_into()?;
            updated.id = existing.id;
            updated.realm_id = existing.realm_id;
            if updated.secret.is_none() {
                updated.secret = existing.secret;
            }
            updated.scope_mappings = existing.scope_mappings;
            state.storage.update_client(realm_id, &updated).await?;
            record(summary, ResourceType::Client, name, ImportAction::Updated);
        }
    }
    Ok(())
}

/// Import one role. Realm roles (`client == None`) match by name; client
/// roles match by (owning client, name).
async fn import_role(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    strategy: IfResourceExists,
    client: Option<&issuerd_core::Client>,
    rep: RoleRepresentation,
    summary: &mut PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    let resource_name = match client {
        Some(c) => format!("{}/{}", c.client_id, rep.name),
        None => rep.name.clone(),
    };
    let keep_composites = rep.composites.is_none();
    let keep_attributes = rep.attributes.is_none();
    let existing = match client {
        Some(c) => state.storage.get_client_role_by_name(realm_id, &c.id, &rep.name).await?,
        // `get_role_by_name` prefers realm roles but falls back to a
        // same-named client role; that fallback is NOT a realm-role identity
        // match (a realm role and a client role may share a name).
        None => state
            .storage
            .get_role_by_name(realm_id, &rep.name)
            .await?
            .filter(|r| !r.client_role),
    };
    match (existing, strategy) {
        (None, _) => {
            let mut role: issuerd_core::Role = rep.try_into()?;
            role.realm_id = realm_id.clone();
            role.client_role = client.is_some();
            role.client_id = client.map(|c| c.id.clone());
            state.storage.create_role(realm_id, &role).await?;
            record(summary, ResourceType::Role, resource_name, ImportAction::Added);
        }
        (Some(_), IfResourceExists::Fail) => return Err(conflict("role", &resource_name)),
        (Some(_), IfResourceExists::Skip) => {
            record(summary, ResourceType::Role, resource_name, ImportAction::Skipped);
        }
        (Some(existing), IfResourceExists::Overwrite) => {
            // Same omitted-means-keep rules as the role update endpoints;
            // the owning container (realm vs client) is never reassigned.
            let mut updated: issuerd_core::Role = rep.try_into()?;
            updated.id = existing.id;
            updated.realm_id = existing.realm_id;
            updated.client_role = existing.client_role;
            updated.client_id = existing.client_id;
            if keep_composites {
                updated.composites = existing.composites;
            }
            if keep_attributes {
                updated.attributes = existing.attributes;
            }
            state.storage.update_role(realm_id, &updated).await?;
            record(summary, ResourceType::Role, resource_name, ImportAction::Updated);
        }
    }
    Ok(())
}

/// Import one identity provider, matched by alias.
async fn import_idp(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    strategy: IfResourceExists,
    rep: IdentityProviderRepresentation,
    summary: &mut PartialImportResultRepresentation,
) -> Result<(), AdminApiError> {
    let name = rep.alias.as_str().to_string();
    let existing = state.storage.get_identity_provider_by_alias(realm_id, &name).await?;
    match (existing, strategy) {
        (None, _) => {
            // The conversion mints a fresh internal id.
            let idp: issuerd_core::IdentityProviderConfig = rep.try_into()?;
            state.storage.create_identity_provider(realm_id, &idp).await?;
            record(summary, ResourceType::IdentityProvider, name, ImportAction::Added);
        }
        (Some(_), IfResourceExists::Fail) => {
            return Err(conflict("identity provider", &name));
        }
        (Some(_), IfResourceExists::Skip) => {
            record(summary, ResourceType::IdentityProvider, name, ImportAction::Skipped);
        }
        (Some(existing), IfResourceExists::Overwrite) => {
            // Same preserve rule as `PUT /identity-provider/instances/{alias}`.
            let mut updated: issuerd_core::IdentityProviderConfig = rep.try_into()?;
            updated.id = existing.id;
            state.storage.update_identity_provider(realm_id, &updated).await?;
            record(summary, ResourceType::IdentityProvider, name, ImportAction::Updated);
        }
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/partialImport",
    tag = "Realms",
    summary = "Partially import realm resources",
    description = "Imports users, groups, clients, roles, and identity providers from a realm-partial document. `ifResourceExists` (query parameter, or the same field in the body) selects the conflict strategy: `FAIL` (default) stops at the first already-existing resource with 409 naming it — resources imported before the conflict stay imported, there is no transactional rollback; `SKIP` leaves existing resources untouched and imports the rest; `OVERWRITE` updates existing resources with the document's fields. Identity matching: users by username, clients by clientId, realm roles by name, client roles by (clientId, name), groups by name, identity providers by alias. Users are imported WITHOUT credentials — credential fields in the document are ignored entirely and password hashes are never accepted through this endpoint; user role/group assignments and realm default groups are not applied. Groups are imported as top-level only (`sub_groups` is rejected). Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        PartialImportParams
    ),
    request_body(description = "Realm-partial document", content = PartialImportRepresentation),
    responses(
        (status = 200, description = "Import summary", body = PartialImportResultRepresentation),
        (status = 400, description = "Invalid document (e.g. nested sub_groups, dangling client reference in roles.client)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict under the FAIL strategy; the message names the existing resource", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth, body), fields(realm = %realm))]
pub async fn partial_import(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<PartialImportParams>,
    Json(body): Json<PartialImportRepresentation>,
) -> Result<Json<PartialImportResultRepresentation>, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let realm_id = realm.id.clone();
    // The query parameter (Keycloak's spelling) wins over the body field.
    let strategy = params.if_resource_exists.or(body.if_resource_exists).unwrap_or_default();

    let mut summary = PartialImportResultRepresentation {
        added: 0,
        skipped: 0,
        updated: 0,
        results: Vec::new(),
    };
    // Fixed processing order: users, groups, clients, realm roles, client
    // roles (their owning clients must exist first), identity providers.
    // Under FAIL the first conflict aborts the run; resources imported before
    // it stay imported.
    for rep in body.users.unwrap_or_default() {
        import_user(&state, &realm_id, strategy, rep, &mut summary).await?;
    }
    for rep in body.groups.unwrap_or_default() {
        import_group(&state, &realm_id, strategy, rep, &mut summary).await?;
    }
    for rep in body.clients.unwrap_or_default() {
        import_client(&state, &realm_id, strategy, rep, &mut summary).await?;
    }
    if let Some(roles) = body.roles {
        for rep in roles.realm.unwrap_or_default() {
            import_role(&state, &realm_id, strategy, None, rep, &mut summary).await?;
        }
        for (client_id, reps) in roles.client.unwrap_or_default() {
            let identifier = issuerd_core::ClientIdentifier::new(client_id.clone())?;
            let client = state
                .storage
                .get_client_by_client_id(&realm_id, &identifier)
                .await?
                .ok_or_else(|| {
                    AdminApiError::BadRequest(format!(
                        "roles.client references unknown client '{client_id}'"
                    ))
                })?;
            for rep in reps {
                import_role(&state, &realm_id, strategy, Some(&client), rep, &mut summary).await?;
            }
        }
    }
    for rep in body.identity_providers.unwrap_or_default() {
        import_idp(&state, &realm_id, strategy, rep, &mut summary).await?;
    }

    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;

    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::Realm,
        &format!("realms/{}/partialImport", realm.name),
        // Audit the outcome summary, never the request body: the document may
        // legitimately carry client secrets.
        serde_json::to_string(&summary).ok(),
    )
    .await;
    Ok(Json(summary))
}

/// Placeholder written into exported IdP client secrets (Keycloak's spelling).
const EXPORT_SECRET_MASK: &str = "**********";

/// Mask broker client secrets in an exported IdP configuration.
fn mask_idp_secrets(
    mut idp: issuerd_core::IdentityProviderConfig,
) -> issuerd_core::IdentityProviderConfig {
    if idp.config.contains_key("clientSecret") {
        idp.config.insert("clientSecret".to_string(), EXPORT_SECRET_MASK.to_string());
    }
    idp
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/export",
    tag = "Realms",
    summary = "Export the full realm",
    description = "Returns the realm as a single JSON document: realm fields at the top level (Keycloak-compatible where fields overlap) plus users, clients, groups, roles, identity providers, and client scopes. The document carries no secret material: users never include credentials, client secrets are omitted, and identity-provider `clientSecret` values are masked as `**********`. Groups are a flat list with hierarchy carried by `parent_id`. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Realm export document", body = RealmExportRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn export_realm(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<RealmExportRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let realm_id = realm.id.clone();
    let all = Pagination {
        first: 0,
        max: i32::MAX,
    };

    // `From<User>` never populates credentials — no secret material.
    let users = state
        .storage
        .list_users(&realm_id, "", &all)
        .await?
        .into_iter()
        .map(UserRepresentation::from)
        .collect();
    let client_models = state.storage.list_clients(&realm_id, &all).await?;
    let mut client_roles: HashMap<String, Vec<RoleRepresentation>> = HashMap::new();
    for client in &client_models {
        let roles = state.storage.list_client_roles(&realm_id, &client.id, &all).await?;
        if !roles.is_empty() {
            client_roles.insert(
                client.client_id.to_string(),
                roles.into_iter().map(RoleRepresentation::from).collect(),
            );
        }
    }
    // `From<Client>` never populates the secret.
    let clients = client_models.into_iter().map(ClientRepresentation::from).collect();
    let groups = state
        .storage
        .list_groups(&realm_id, &all)
        .await?
        .into_iter()
        .map(GroupRepresentation::from)
        .collect();
    let realm_roles = state
        .storage
        .list_roles(&realm_id, &all)
        .await?
        .into_iter()
        .filter(|r| !r.client_role)
        .map(RoleRepresentation::from)
        .collect();
    let identity_providers = state
        .storage
        .list_identity_providers(&realm_id)
        .await?
        .into_iter()
        .map(mask_idp_secrets)
        .map(IdentityProviderRepresentation::from)
        .collect();
    let client_scopes = state
        .storage
        .list_client_scopes(&realm_id, &all)
        .await?
        .into_iter()
        .map(ClientScopeRepresentation::from)
        .collect();

    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::Realm,
        &format!("realms/{}/export", realm.name),
        None,
    )
    .await;
    Ok(Json(RealmExportRepresentation {
        realm: realm.into(),
        users,
        clients,
        groups,
        roles: ExportRolesRepresentation {
            realm: realm_roles,
            client: client_roles,
        },
        identity_providers,
        client_scopes,
    }))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/push-revocation",
    tag = "Realms",
    summary = "Push revocation (compatibility stub)",
    description = "Keycloak pushes revocation to registered clients; Issuerd has no client push channel. Revocation is enforced server-side instead: session invalidation, the token-revocation blocklist, and the realm `notBefore` cutoff (tokens with `iat` before it are rejected by this API's middleware). This endpoint exists for API compatibility: it records an admin event and returns 204 without other side effects. Set `notBefore` via `PUT /admin/realms/{realm}` to revoke previously issued tokens. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 204, description = "Revocation noted (no push channel exists)"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn push_revocation(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Action,
        ResourceType::Realm,
        &format!("realms/{}/push-revocation", realm.name),
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
        routing::post,
        Router,
    };
    use issuerd_core::{AdminEventQuery, RealmId, RoleName};
    use tower::ServiceExt;

    fn test_app(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/partialImport", post(partial_import))
            .route("/admin/realms/{realm}/export", post(export_realm))
            .route("/admin/realms/{realm}/push-revocation", post(push_revocation))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    fn manage_realm_state() -> Arc<AdminApiState> {
        crate::test_utils::tests::test_state(vec![RoleName::new("manage-realm").unwrap()])
    }

    fn master_realm_id() -> RealmId {
        RealmId::new("master").unwrap()
    }

    async fn post_json(
        app: &Router,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", "Bearer valid-token");
        let body = match body {
            Some(json) => {
                builder = builder.header("Content-Type", "application/json");
                Body::from(serde_json::to_vec(&json).unwrap())
            }
            None => Body::empty(),
        };
        let response = app.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, json)
    }

    async fn seed_user(
        state: &Arc<AdminApiState>,
        realm_id: &RealmId,
        username: &str,
        email: Option<&str>,
    ) -> issuerd_core::User {
        let now = chrono::Utc::now();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new(username).unwrap(),
            email: email.map(|e| issuerd_core::Email::new(e).unwrap()),
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: now,
            updated_at: now,
        };
        state.storage.create_user(realm_id, &user).await.unwrap();
        user
    }

    async fn seed_client(
        state: &Arc<AdminApiState>,
        realm_id: &RealmId,
        client_id: &str,
        secret: Option<&str>,
    ) -> issuerd_core::Client {
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            client_id: issuerd_core::ClientIdentifier::new(client_id).unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: issuerd_core::ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
            secret: secret.map(str::to_string),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: issuerd_core::Scope::parse("openid"),
            optional_scopes: issuerd_core::Scope::parse("email"),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: vec![],
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        state.storage.create_client(realm_id, &client).await.unwrap();
        client
    }

    async fn seed_realm_role(
        state: &Arc<AdminApiState>,
        realm_id: &RealmId,
        name: &str,
        description: Option<&str>,
    ) -> issuerd_core::Role {
        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::RoleName::new(name).unwrap(),
            description: description.map(str::to_string),
            realm_id: realm_id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        state.storage.create_role(realm_id, &role).await.unwrap();
        role
    }

    async fn seed_client_role(
        state: &Arc<AdminApiState>,
        realm_id: &RealmId,
        client: &issuerd_core::Client,
        name: &str,
    ) -> issuerd_core::Role {
        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::RoleName::new(name).unwrap(),
            description: None,
            realm_id: realm_id.clone(),
            client_role: true,
            client_id: Some(client.id.clone()),
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        state.storage.create_role(realm_id, &role).await.unwrap();
        role
    }

    async fn seed_group(
        state: &Arc<AdminApiState>,
        realm_id: &RealmId,
        name: &str,
    ) -> issuerd_core::Group {
        let group = issuerd_core::Group {
            id: issuerd_core::GroupId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::GroupName::new(name).unwrap(),
            path: issuerd_core::GroupPath::new(format!("/{name}")).unwrap(),
            realm_id: realm_id.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        state.storage.create_group(realm_id, &group).await.unwrap();
        group
    }

    async fn seed_idp(
        state: &Arc<AdminApiState>,
        realm_id: &RealmId,
        alias: &str,
        client_secret: Option<&str>,
    ) -> issuerd_core::IdentityProviderConfig {
        let mut config = HashMap::new();
        config.insert("clientId".to_string(), "idp-client".to_string());
        if let Some(secret) = client_secret {
            config.insert("clientSecret".to_string(), secret.to_string());
        }
        let idp = issuerd_core::IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap(),
            alias: issuerd_core::Alias::new(alias).unwrap(),
            provider_id: issuerd_core::ProviderId::new("oidc"),
            enabled: true,
            config,
        };
        state.storage.create_identity_provider(realm_id, &idp).await.unwrap();
        idp
    }

    async fn enable_admin_events(state: &Arc<AdminApiState>, realm_id: &RealmId) {
        let mut realm = state.storage.get_realm(realm_id).await.unwrap().unwrap();
        realm.admin_events_enabled = true;
        realm.include_representations = true;
        state.storage.update_realm(&realm).await.unwrap();
    }

    async fn recorded_admin_events(
        state: &Arc<AdminApiState>,
        realm_id: &RealmId,
    ) -> Vec<issuerd_core::AdminEvent> {
        state
            .storage
            .query_admin_events(
                realm_id,
                &AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap()
    }

    // -- partialImport --------------------------------------------------------

    #[tokio::test]
    async fn fail_stops_at_first_conflict_and_keeps_earlier_imports() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();
        seed_user(&state, &realm_id, "existing", None).await;

        // No ifResourceExists: FAIL is the default.
        let doc = serde_json::json!({
            "users": [
                {"username": "newuser"},
                {"username": "existing"},
                {"username": "never-imported"}
            ]
        });
        let (status, body) = post_json(&app, "/admin/realms/master/partialImport", Some(doc)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let message = body["errorMessage"].as_str().unwrap();
        assert!(
            message.contains("user 'existing'"),
            "409 names the conflicting resource: {message}"
        );
        // Sequential processing: resources before the conflict stay imported,
        // resources after it are not (no transactional rollback).
        assert!(state
            .storage
            .get_user_by_username(&realm_id, "newuser")
            .await
            .unwrap()
            .is_some());
        assert!(state
            .storage
            .get_user_by_username(&realm_id, "never-imported")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn fail_strategy_is_not_idempotent() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let doc = serde_json::json!({"users": [{"username": "alice"}]});

        let (status, body) = post_json(
            &app,
            "/admin/realms/master/partialImport?ifResourceExists=FAIL",
            Some(doc.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["added"], 1);

        let (status, body) =
            post_json(&app, "/admin/realms/master/partialImport?ifResourceExists=FAIL", Some(doc))
                .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["errorMessage"].as_str().unwrap().contains("user 'alice'"));
    }

    #[tokio::test]
    async fn skip_skips_conflicts_and_is_stable_on_rerun() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();
        seed_user(&state, &realm_id, "existing", Some("old@example.com")).await;

        let doc = serde_json::json!({
            "users": [
                {"username": "existing", "email": "new@example.com"},
                {"username": "fresh"}
            ],
            "groups": [{"name": "g1"}]
        });
        let (status, body) = post_json(
            &app,
            "/admin/realms/master/partialImport?ifResourceExists=SKIP",
            Some(doc.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["added"], 2);
        assert_eq!(body["skipped"], 1);
        assert_eq!(body["updated"], 0);
        // The conflicting user is left untouched.
        let existing = state
            .storage
            .get_user_by_username(&realm_id, "existing")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(existing.email.unwrap().as_str(), "old@example.com");

        // Second run: everything conflicts, everything is skipped.
        let (status, body) =
            post_json(&app, "/admin/realms/master/partialImport?ifResourceExists=SKIP", Some(doc))
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["added"], 0);
        assert_eq!(body["skipped"], 3);
        assert_eq!(body["updated"], 0);
    }

    #[tokio::test]
    async fn overwrite_updates_existing_and_is_stable_on_rerun() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();
        seed_user(&state, &realm_id, "existing", Some("old@example.com")).await;
        let client = seed_client(&state, &realm_id, "c1", None).await;
        seed_realm_role(&state, &realm_id, "r1", Some("old description")).await;
        seed_group(&state, &realm_id, "g1").await;
        seed_idp(&state, &realm_id, "idp1", None).await;

        let doc = serde_json::json!({
            "users": [{"username": "existing", "email": "new@example.com"}],
            "groups": [{"name": "g1", "attributes": {"k": ["v"]}}],
            "clients": [{"client_id": "c1", "description": "new client description"}],
            "roles": {
                "realm": [{"name": "r1", "description": "new description"}],
                "client": {"c1": [{"name": "cr1"}]}
            },
            "identityProviders": [{"alias": "idp1", "provider_id": "oidc", "enabled": false}]
        });
        let (status, body) = post_json(
            &app,
            "/admin/realms/master/partialImport?ifResourceExists=OVERWRITE",
            Some(doc.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        // user + group + client + realm role + IdP updated; the client role is new.
        assert_eq!(body["updated"], 5);
        assert_eq!(body["added"], 1);
        assert_eq!(body["skipped"], 0);
        assert_eq!(body["results"][0]["resourceType"], "USER");
        assert_eq!(body["results"][0]["resourceName"], "existing");
        assert_eq!(body["results"][0]["action"], "updated");

        let user = state
            .storage
            .get_user_by_username(&realm_id, "existing")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.email.unwrap().as_str(), "new@example.com");
        let role = state.storage.get_role_by_name(&realm_id, "r1").await.unwrap().unwrap();
        assert_eq!(role.description.as_deref(), Some("new description"));
        let client_after = state.storage.get_client(&realm_id, &client.id).await.unwrap().unwrap();
        assert_eq!(client_after.description.as_deref(), Some("new client description"));
        let group = state.storage.get_group_by_name(&realm_id, "g1").await.unwrap().unwrap();
        assert_eq!(group.attributes.get("k").unwrap(), &vec!["v".to_string()]);
        // Import never re-paths an existing group.
        assert_eq!(group.path.as_str(), "/g1");
        let idp = state
            .storage
            .get_identity_provider_by_alias(&realm_id, "idp1")
            .await
            .unwrap()
            .unwrap();
        assert!(!idp.enabled);
        let client_role = state
            .storage
            .get_client_role_by_name(&realm_id, &client.id, "cr1")
            .await
            .unwrap()
            .unwrap();
        assert!(client_role.client_role);
        assert_eq!(client_role.client_id, Some(client.id.clone()));

        // Second run: everything exists, everything is overwritten again.
        let (status, body) = post_json(
            &app,
            "/admin/realms/master/partialImport?ifResourceExists=OVERWRITE",
            Some(doc),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["added"], 0);
        assert_eq!(body["updated"], 6);
        assert_eq!(body["skipped"], 0);
    }

    #[tokio::test]
    async fn body_strategy_accepted_and_query_param_wins() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();
        seed_user(&state, &realm_id, "existing", None).await;

        // Strategy in the body (Keycloak also accepts it there).
        let doc = serde_json::json!({
            "ifResourceExists": "SKIP",
            "users": [{"username": "existing"}, {"username": "fresh"}]
        });
        let (status, body) = post_json(&app, "/admin/realms/master/partialImport", Some(doc)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["skipped"], 1);
        assert_eq!(body["added"], 1);

        // The query parameter wins when both are set.
        let doc = serde_json::json!({
            "ifResourceExists": "SKIP",
            "users": [{"username": "existing"}]
        });
        let (status, _) =
            post_json(&app, "/admin/realms/master/partialImport?ifResourceExists=FAIL", Some(doc))
                .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn unknown_fields_are_ignored() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let doc = serde_json::json!({
            "unknownTopLevel": {"anything": true},
            "users": [{"username": "u1", "someUnknownField": 123}]
        });
        let (status, body) = post_json(&app, "/admin/realms/master/partialImport", Some(doc)).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["added"], 1);
    }

    #[tokio::test]
    async fn users_are_imported_without_credentials() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();

        let doc = serde_json::json!({
            "users": [{
                "username": "u1",
                "credentials": [{
                    "type": "password",
                    "value": "plaintext-pw",
                    "secret_data": "pretend-hash"
                }]
            }]
        });
        let (status, body) = post_json(&app, "/admin/realms/master/partialImport", Some(doc)).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let user = state.storage.get_user_by_username(&realm_id, "u1").await.unwrap().unwrap();
        // No credential of any type was stored for the imported user.
        assert!(state.storage.list_credentials(&realm_id, &user.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn client_roles_reference_must_resolve() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let doc = serde_json::json!({
            "roles": {"client": {"no-such-client": [{"name": "r"}]}}
        });
        // A dangling reference is a document error (400), not a conflict.
        let (status, body) = post_json(&app, "/admin/realms/master/partialImport", Some(doc)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["errorMessage"].as_str().unwrap().contains("no-such-client"));
    }

    #[tokio::test]
    async fn realm_role_sharing_a_client_role_name_is_not_a_conflict() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();
        let client = seed_client(&state, &realm_id, "c1", None).await;
        seed_client_role(&state, &realm_id, &client, "shared").await;

        let doc = serde_json::json!({"roles": {"realm": [{"name": "shared"}]}});
        // Default FAIL: the client role named "shared" does not collide with
        // a new realm role of the same name.
        let (status, body) = post_json(&app, "/admin/realms/master/partialImport", Some(doc)).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["added"], 1);
        let realm_role =
            state.storage.get_role_by_name(&realm_id, "shared").await.unwrap().unwrap();
        assert!(!realm_role.client_role);
        assert!(state
            .storage
            .get_client_role_by_name(&realm_id, &client.id, "shared")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn nested_groups_are_rejected() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let doc = serde_json::json!({
            "groups": [{"name": "g1", "sub_groups": [{"name": "sub"}]}]
        });
        let (status, _) = post_json(&app, "/admin/realms/master/partialImport", Some(doc)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn partial_import_requires_manage_realm() {
        let state =
            crate::test_utils::tests::test_state(vec![RoleName::new("view-realm").unwrap()]);
        let app = test_app(state);
        let (status, _) =
            post_json(&app, "/admin/realms/master/partialImport", Some(serde_json::json!({})))
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn partial_import_writes_admin_event_with_summary() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();
        enable_admin_events(&state, &realm_id).await;

        let doc = serde_json::json!({"users": [{"username": "audited"}]});
        let (status, _) = post_json(&app, "/admin/realms/master/partialImport", Some(doc)).await;
        assert_eq!(status, StatusCode::OK);

        let events = recorded_admin_events(&state, &realm_id).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, OperationType::Action);
        assert_eq!(events[0].resource_type, ResourceType::Realm);
        assert_eq!(events[0].resource_path, "realms/master/partialImport");
        let representation = events[0].representation.as_deref().unwrap();
        // The audit representation is the outcome summary, not the document.
        assert!(representation.contains("\"added\":1"), "representation: {representation}");
    }

    // -- export ---------------------------------------------------------------

    #[tokio::test]
    async fn export_returns_full_document_without_secret_material() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();

        let user = seed_user(&state, &realm_id, "alice", Some("alice@example.com")).await;
        // A stored password credential: must never appear in the export.
        let credential = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new("cred-1").unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: b"argon2id-user-hash".to_vec(),
            credential_data: serde_json::json!({}),
            priority: 0,
        };
        state.storage.create_credential(&realm_id, &user.id, &credential).await.unwrap();
        let client = seed_client(&state, &realm_id, "c1", Some("topsecret-client-value")).await;
        seed_client_role(&state, &realm_id, &client, "cr1").await;
        seed_realm_role(&state, &realm_id, "r1", Some("realm role")).await;
        seed_group(&state, &realm_id, "g1").await;
        seed_idp(&state, &realm_id, "idp1", Some("idp-secret-value")).await;

        let (status, body) = post_json(&app, "/admin/realms/master/export", None).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        // Realm fields are flattened at the top level.
        assert_eq!(body["realm"], "master");
        assert!(body["users"].as_array().unwrap().iter().any(|u| u["username"] == "alice"));
        let exported_client = body["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["client_id"] == "c1")
            .unwrap();
        assert!(exported_client["secret"].is_null());
        assert!(body["roles"]["realm"].as_array().unwrap().iter().any(|r| r["name"] == "r1"));
        assert_eq!(body["roles"]["client"]["c1"][0]["name"], "cr1");
        assert!(body["groups"].as_array().unwrap().iter().any(|g| g["name"] == "g1"));
        let exported_idp = &body["identityProviders"][0];
        assert_eq!(exported_idp["alias"], "idp1");
        assert_eq!(exported_idp["config"]["clientSecret"], "**********");
        // Built-in client scopes are seeded on realm creation.
        assert!(!body["clientScopes"].as_array().unwrap().is_empty());

        // No known secret value appears anywhere in the serialized document.
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("topsecret-client-value"));
        assert!(!serialized.contains("idp-secret-value"));
        assert!(!serialized.contains("argon2id-user-hash"));

        // Round-trip: the document deserializes back into the export shape.
        let parsed: RealmExportRepresentation = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.realm.realm, "master");
        assert_eq!(parsed.users.len(), 1);
        assert!(parsed.users[0].credentials.is_none());
        assert_eq!(parsed.roles.realm.iter().filter(|r| r.name == "r1").count(), 1);
        assert_eq!(parsed.roles.client["c1"][0].name, "cr1");
    }

    #[tokio::test]
    async fn export_allows_view_role() {
        let state =
            crate::test_utils::tests::test_state(vec![RoleName::new("view-realm").unwrap()]);
        let app = test_app(state);
        let (status, _) = post_json(&app, "/admin/realms/master/export", None).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn export_writes_admin_event() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();
        enable_admin_events(&state, &realm_id).await;

        let (status, _) = post_json(&app, "/admin/realms/master/export", None).await;
        assert_eq!(status, StatusCode::OK);

        let events = recorded_admin_events(&state, &realm_id).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, OperationType::Action);
        assert_eq!(events[0].resource_type, ResourceType::Realm);
        assert_eq!(events[0].resource_path, "realms/master/export");
    }

    // -- push-revocation ------------------------------------------------------

    #[tokio::test]
    async fn push_revocation_returns_204_and_writes_admin_event() {
        let state = manage_realm_state();
        let app = test_app(state.clone());
        let realm_id = master_realm_id();
        enable_admin_events(&state, &realm_id).await;

        let (status, _) = post_json(&app, "/admin/realms/master/push-revocation", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let events = recorded_admin_events(&state, &realm_id).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, OperationType::Action);
        assert_eq!(events[0].resource_type, ResourceType::Realm);
        assert_eq!(events[0].resource_path, "realms/master/push-revocation");
    }

    #[tokio::test]
    async fn push_revocation_requires_manage_realm() {
        let state =
            crate::test_utils::tests::test_state(vec![RoleName::new("view-realm").unwrap()]);
        let app = test_app(state);
        let (status, _) = post_json(&app, "/admin/realms/master/push-revocation", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn push_revocation_unknown_realm_is_404() {
        let state = manage_realm_state();
        let app = test_app(state);
        let (status, _) = post_json(&app, "/admin/realms/ghost/push-revocation", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
