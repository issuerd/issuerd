// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// User management endpoints: CRUD, password reset, and role mappings.

use argon2::{
    password_hash::rand_core::OsRng, password_hash::PasswordHash, password_hash::SaltString,
    Argon2, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{
    Credential, CredentialType, GroupId, OperationType, Pagination, RealmId, ResourceType, RoleId,
    Storage, UserId,
};
#[cfg(test)]
use issuerd_core::{GroupName, RoleName};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{
        CountRepresentation, CredentialRepresentation, MappingsRepresentation, RoleRepresentation,
        UserCountQueryParams, UserQueryParams, UserRepresentation,
    },
    error::AdminApiError,
    state::AdminApiState,
};
use tracing::{info, instrument};

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users",
    tag = "Users",
    summary = "List users in a realm",
    description = "Returns a paginated list of users. Supports searching by username, email, first name, or last name. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        UserQueryParams
    ),
    responses(
        (status = 200, description = "List of users", body = Vec<UserRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_users(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<UserQueryParams>,
) -> Result<Json<Vec<UserRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let users = state
        .storage
        .list_users(
            &realm_id,
            &params.search.unwrap_or_default(),
            &Pagination::new(params.first, params.max),
        )
        .await?;
    Ok(Json(users.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users/count",
    tag = "Users",
    summary = "Count users in a realm",
    description = "Returns the total number of users matching the optional search filter. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        UserCountQueryParams
    ),
    responses(
        (status = 200, description = "User count", body = CountRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn count_users(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<UserCountQueryParams>,
) -> Result<Json<CountRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let count = state.storage.count_users(&realm_id, &params.search.unwrap_or_default()).await?;
    Ok(Json(CountRepresentation { count }))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/users",
    tag = "Users",
    summary = "Create a new user",
    description = "Creates a user account in the specified realm. Initial password credentials are validated against the realm password policy. Requires `manage-users` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "User representation", content = UserRepresentation),
    responses(
        (status = 201, description = "User created successfully", body = UserRepresentation),
        (status = 400, description = "Password policy violation (machine-readable `policyViolations`)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - user already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_user(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<UserRepresentation>,
) -> Result<(StatusCode, Json<UserRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let realm_id = realm.id.clone();

    // Validate the assignable parts of the body up front so a bad request
    // cannot leave a half-created user behind.
    if body.client_roles.as_ref().is_some_and(|m| !m.is_empty()) {
        return Err(AdminApiError::BadRequest(
            "client_roles in the create body are not supported".to_string(),
        ));
    }
    let mut realm_role_ids: Vec<RoleId> = Vec::new();
    for name in body.realm_roles.as_deref().unwrap_or_default() {
        let role = state
            .storage
            .get_role_by_name(&realm_id, name)
            .await?
            .ok_or_else(|| AdminApiError::BadRequest(format!("unknown realm role: {name}")))?;
        realm_role_ids.push(role.id);
    }
    let mut group_ids: Vec<GroupId> = Vec::new();
    for gid in body.groups.as_deref().unwrap_or_default() {
        let group_id = GroupId::new(gid).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
        state
            .storage
            .get_group(&realm_id, &group_id)
            .await?
            .ok_or_else(|| AdminApiError::BadRequest(format!("unknown group: {gid}")))?;
        group_ids.push(group_id);
    }
    let mut user: issuerd_core::User = body.clone().try_into()?;
    user.realm_id = realm_id.clone();
    // Hash password credentials exactly like the reset-password endpoint so
    // onboarding with an initial password actually works. The realm password
    // policy applies to password credentials; the user is new, so there is no
    // password history to check against.
    let mut credentials: Vec<Credential> = Vec::new();
    for cred_rep in body.credentials.as_deref().unwrap_or_default() {
        let mut cred: Credential = cred_rep.clone().try_into()?;
        if let Some(value) = cred_rep.value.clone() {
            if cred.credential_type == CredentialType::Password {
                realm
                    .password_policy
                    .validate(&value, &user)
                    .map_err(AdminApiError::PasswordPolicy)?;
            }
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2.hash_password(value.as_bytes(), &salt).map_err(|e| {
                AdminApiError::Internal(anyhow::anyhow!("password hashing failed: {e}"))
            })?;
            cred.secret_data = password_hash.to_string().into_bytes();
        }
        credentials.push(cred);
    }

    state.storage.create_user(&user.realm_id, &user).await?;
    for cred in &credentials {
        state.storage.create_credential(&realm_id, &user.id, cred).await?;
    }
    for role_id in &realm_role_ids {
        state.storage.add_user_realm_role(&realm_id, &user.id, role_id).await?;
    }
    for group_id in &group_ids {
        state.storage.add_user_group(&realm_id, &user.id, group_id).await?;
    }
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Create,
        ResourceType::User,
        &format!("users/{}", user.id),
        serde_json::to_string(&body.redacted_for_audit()).ok(),
    )
    .await;
    info!(realm = %realm_id, user_id = %user.id, admin = %auth.claims.sub, "user created");
    Ok((StatusCode::CREATED, Json(user.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users/{id}",
    tag = "Users",
    summary = "Get a user by ID",
    description = "Returns the user representation including realm roles and groups. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User found", body = UserRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_user(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<UserRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let user = state
        .storage
        .get_user(&realm_id, &user_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    let mut rep: UserRepresentation = user.into();
    // The representation contract is role *names*; storage returns IDs (P3-18).
    let role_ids = state.storage.list_user_realm_roles(&realm_id, &user_id).await?;
    let mut role_names = Vec::with_capacity(role_ids.len());
    for role_id in &role_ids {
        if let Some(role) = state.storage.get_role(&realm_id, role_id).await? {
            role_names.push(role.name.to_string());
        }
    }
    rep.realm_roles = Some(role_names);
    let groups = state.storage.list_user_groups(&realm_id, &user_id).await?;
    rep.groups = Some(groups.into_iter().map(|g| g.to_string()).collect());
    Ok(Json(rep))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/users/{id}",
    tag = "Users",
    summary = "Update a user",
    description = "Updates an existing user account. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    request_body(description = "Updated user representation", content = UserRepresentation),
    responses(
        (status = 204, description = "User updated successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_user(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<UserRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let existing = state
        .storage
        .get_user(&realm_id, &user_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    let mut updated: issuerd_core::User = body.clone().try_into()?;
    updated.id = existing.id;
    updated.realm_id = existing.realm_id;
    updated.created_at = existing.created_at;
    // The admin representation has no federation_link field; preserve the
    // stored value so a routine edit does not detach federated users.
    updated.federation_link = existing.federation_link;
    // Renaming onto an existing username must be a conflict, not a silent
    // duplicate (InMemory) or a 500 (Postgres unique violation).
    if updated.username != existing.username {
        if let Some(other) =
            state.storage.get_user_by_username(&realm_id, updated.username.as_ref()).await?
        {
            if other.id != updated.id {
                return Err(AdminApiError::Conflict);
            }
        }
    }
    state.storage.update_user(&realm_id, &updated).await?;
    issuerd_cluster::invalidate::invalidate_user_claims(
        state.cache.as_ref(),
        &realm_id,
        &updated.id,
    )
    .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::User,
        &format!("users/{}", id),
        serde_json::to_string(&body.redacted_for_audit()).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/users/{id}",
    tag = "Users",
    summary = "Delete a user",
    description = "Permanently deletes a user account. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 204, description = "User deleted successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth), fields(realm = %realm, user_id = %id))]
pub async fn delete_user(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    state.storage.delete_user(&realm_id, &user_id).await?;
    // The DB cascade removes the user's sessions without touching Rust; bump
    // the per-user session-version counter so cached session-validity
    // snapshots of this user miss on their next read (best-effort — the
    // snapshot TTL bounds staleness if the cache is down).
    if let Err(e) = state
        .cache
        .increment(
            &issuerd_cluster::cache_keys::session_version(realm_id.as_ref(), user_id.as_ref()),
            None,
        )
        .await
    {
        tracing::warn!(realm = %realm_id, error = %e, "session version bump failed");
    }
    issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm_id, &user_id)
        .await;
    info!(realm = %realm_id, user_id = %id, admin = %auth.claims.sub, "user deleted");
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::User,
        &format!("users/{}", id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users/{id}/sessions",
    tag = "Users",
    summary = "Get user sessions",
    description = "Returns all active sessions for the given user. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "List of user sessions", body = Vec<crate::dto::UserSessionRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_user_sessions(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<crate::dto::UserSessionRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let sessions = state
        .storage
        .list_sessions(&realm_id, Some(user_id), &Pagination::default())
        .await?;
    Ok(Json(sessions.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/users/{id}/reset-password",
    tag = "Users",
    summary = "Reset user password",
    description = "Sets or resets the user's password credential. The plain-text value is validated against the realm password policy (including password-history reuse) and hashed with Argon2id before storage; superseded passwords are retained as inert history entries per the policy `history_size`. A temporary password also assigns the `UPDATE_PASSWORD` required action. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    request_body(description = "Password credential representation", content = CredentialRepresentation),
    responses(
        (status = 204, description = "Password reset successfully"),
        (status = 400, description = "Password policy violation (machine-readable `policyViolations`)", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth, body), fields(realm = %realm, user_id = %id))]
pub async fn reset_password(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<CredentialRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let realm_id = realm.id.clone();
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    // The documented 404: resetting a password for a missing user must not
    // succeed and leave an orphaned credential behind (P3-17).
    let user = state
        .storage
        .get_user(&realm_id, &user_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;

    let temporary = body.temporary == Some(true);
    if let Some(value) = body.value.clone() {
        // Policy gate first: a violating password must be rejected before any
        // stored credential is touched.
        realm
            .password_policy
            .validate(&value, &user)
            .map_err(AdminApiError::PasswordPolicy)?;
        // Federated user: write the new password through to the external
        // directory; only a non-federated user (or a dead link) keeps the
        // local credential write. Error mapping: read-only directory → 400,
        // directory failure → 500.
        match issuerd_auth_flow::built_in::write_through_federated_password(
            state.storage.as_ref(),
            Some(state.federation_manager.as_ref()),
            &realm_id,
            &user_id,
            &value,
        )
        .await?
        {
            issuerd_auth_flow::built_in::FederationWriteThrough::WrittenToDirectory => {}
            issuerd_auth_flow::built_in::FederationWriteThrough::NotApplicable => {
                set_user_password(
                    state.storage.as_ref(),
                    &realm_id,
                    &user_id,
                    &value,
                    realm.password_policy.history_size,
                    temporary,
                )
                .await?;
            }
        }
        // Keycloak parity: a new *temporary* password forces an UPDATE_PASSWORD
        // required action so the user picks their own password at next login.
        // An explicit non-temporary reset leaves required_actions untouched.
        if temporary && !user.required_actions.iter().any(|a| a == "UPDATE_PASSWORD") {
            let mut user = user;
            user.required_actions.push("UPDATE_PASSWORD".to_string());
            state.storage.update_user(&realm_id, &user).await?;
        }
    } else {
        // No plain-text value: store the representation-derived credential
        // as-is (legacy path — no policy/history handling applies).
        let mut cred: Credential = body.try_into()?;
        cred.credential_type = CredentialType::Password;
        // Reset replaces, not appends: remove existing password credentials so
        // the old password stops working (the verify loops accept ANY matching
        // password credential).
        for old in state
            .storage
            .get_credentials(&realm_id, &user_id, CredentialType::Password)
            .await?
        {
            state.storage.delete_credential(&realm_id, &user_id, &old.id).await?;
        }
        state.storage.create_credential(&realm_id, &user_id, &cred).await?;
    }
    issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm_id, &user_id)
        .await;
    info!(realm = %realm_id, user_id = %id, admin = %auth.claims.sub, "user password reset");
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{}", id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Password history helpers
// ---------------------------------------------------------------------------

/// Credential type used to retain superseded password hashes for history
/// checks. Credentials of this type are never accepted for login (only
/// [`CredentialType::Password`] is), mirroring Keycloak's hidden
/// `password-history` credential type.
///
/// Ported from `issuerd_auth_flow::built_in::set_user_password` (see the doc on
/// [`set_user_password`] below) — the crate does depend on issuerd-auth-flow; the
/// copy stays because history-reuse rejections must surface as the
/// machine-readable [`AdminApiError::PasswordPolicy`] 400 rather than a
/// flattened `IssuerdError`.
const PASSWORD_HISTORY_CREDENTIAL_TYPE: &str = "password-history";

/// Verify a candidate password against a stored credential's hash.
///
/// Only argon2id PHC strings are verified; unknown or foreign hash formats
/// return `false` (they simply cannot match for history-reuse purposes).
fn verify_password_hash(candidate: &str, cred: &Credential) -> bool {
    let hash_str = match std::str::from_utf8(&cred.secret_data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let parsed = match PasswordHash::new(hash_str) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default().verify_password(candidate.as_bytes(), &parsed).is_ok()
}

/// Set a user's password with password-history handling.
///
/// Ported from `issuerd_auth_flow::built_in::set_user_password`; the only semantic
/// difference is that history-reuse rejections surface as a machine-readable
/// [`AdminApiError::PasswordPolicy`] 400 instead of a flattened
/// `IssuerdError::InvalidRequest`. Behavior:
///
/// 1. When `history_size > 0`, the candidate is verified against the current
///    password and all retained history entries; a match is rejected with a
///    `password_history` policy violation.
/// 2. Current `Password` credentials become inert `password-history`
///    credentials (or are deleted when history is disabled).
/// 3. History is pruned to the newest `history_size - 1` entries.
/// 4. The new argon2id hash is stored as the sole `Password` credential,
///    honoring the request's `temporary` flag.
async fn set_user_password(
    storage: &dyn Storage,
    realm_id: &RealmId,
    user_id: &UserId,
    new_password: &str,
    history_size: u32,
    temporary: bool,
) -> Result<(), AdminApiError> {
    let history_type = CredentialType::Custom(PASSWORD_HISTORY_CREDENTIAL_TYPE.to_string());
    let current = storage.get_credentials(realm_id, user_id, CredentialType::Password).await?;
    let mut history = storage.get_credentials(realm_id, user_id, history_type).await?;

    if history_size > 0 {
        for cred in current.iter().chain(history.iter()) {
            if verify_password_hash(new_password, cred) {
                return Err(AdminApiError::PasswordPolicy(issuerd_core::PasswordPolicyError {
                    violations: vec![issuerd_core::PasswordPolicyViolation {
                        code: "password_history".to_string(),
                        message: format!(
                            "password must not match any of the last {history_size} passwords"
                        ),
                    }],
                }));
            }
        }
    }

    for cred in current {
        // Delete-then-recreate (not update) so the type change is portable:
        // some backends key credentials by `(realm, user, type)`, where an
        // in-place type mutation would be a silent no-op.
        storage.delete_credential(realm_id, user_id, &cred.id).await?;
        if history_size > 0 {
            let mut history_cred = cred;
            history_cred.credential_type =
                CredentialType::Custom(PASSWORD_HISTORY_CREDENTIAL_TYPE.to_string());
            if let Some(obj) = history_cred.credential_data.as_object_mut() {
                obj.remove("temporary");
            }
            storage.create_credential(realm_id, user_id, &history_cred).await?;
            history.push(history_cred);
        }
    }

    // Prune history to the newest `history_size - 1` entries; when history is
    // disabled this deletes every stale entry from a previous policy era.
    let keep = issuerd_core::password::credentials_to_retain(&history, history_size);
    for cred in history.iter().filter(|c| !keep.contains(&c.id)) {
        storage.delete_credential(realm_id, user_id, &cred.id).await?;
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|e| AdminApiError::Internal(anyhow::anyhow!("password hashing failed: {e}")))?
        .to_string();
    let credential_data = if temporary {
        serde_json::json!({"hash_algorithm": "argon2id", "temporary": true})
    } else {
        serde_json::json!({"hash_algorithm": "argon2id"})
    };
    let cred = Credential {
        id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: CredentialType::Password,
        user_label: Some("Password".to_string()),
        created_date: chrono::Utc::now(),
        secret_data: hash.into_bytes(),
        credential_data,
        priority: 1,
    };
    storage.create_credential(realm_id, user_id, &cred).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Role mappings (Keycloak `/users/{id}/role-mappings/...`)
// ---------------------------------------------------------------------------

/// Resolve the path realm and load the target user (404 on either).
async fn load_user(
    state: &Arc<AdminApiState>,
    realm: &str,
    id: &str,
) -> Result<(RealmId, issuerd_core::User), AdminApiError> {
    let realm_id = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?.id;
    let user_id = UserId::new(id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let user = state
        .storage
        .get_user(&realm_id, &user_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok((realm_id, user))
}

/// Load the client a `role-mappings/clients/{clientId}` path addresses; the
/// path segment is the client's internal UUID (Keycloak convention).
async fn load_mapping_client(
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
    get,
    path = "/admin/realms/{realm}/users/{id}/role-mappings",
    tag = "Users",
    summary = "Get all role mappings of a user",
    description = "Returns the combined realm and client role mappings of the user. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Combined role mappings", body = crate::dto::MappingsRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_user_role_mappings(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<MappingsRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let realm_ids = state.storage.list_user_realm_roles(&realm_id, &user.id).await?;
    let client_ids = state.storage.list_user_client_roles(&realm_id, &user.id).await?;
    let roles =
        crate::roles::roles_by_ids(&state, &realm_id, [realm_ids, client_ids].concat()).await?;
    let mappings = crate::roles::build_mappings_representation(&state, &realm_id, roles).await?;
    Ok(Json(mappings))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users/{id}/role-mappings/realm",
    tag = "Users",
    summary = "Get user realm roles",
    description = "Returns the realm roles assigned to the user. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Assigned realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_user_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let ids = state.storage.list_user_realm_roles(&realm_id, &user.id).await?;
    let roles = crate::roles::roles_by_ids(&state, &realm_id, ids).await?;
    Ok(Json(roles.into_iter().filter(|r| !r.client_role).map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/users/{id}/role-mappings/realm",
    tag = "Users",
    summary = "Add realm roles to a user",
    description = "Assigns one or more realm roles to the user. Roles are addressed by id; an unknown id or a client role yields 404. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    request_body(description = "Role representations to assign (id required)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Roles added successfully"),
        (status = 400, description = "Role representation without id", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_user_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let roles = crate::roles::resolve_role_representations(&state, &realm_id, body.clone()).await?;
    for role in &roles {
        // A client role id posted to the realm endpoint is "not found" here —
        // client roles live under `role-mappings/clients/{clientId}`.
        if role.client_role {
            return Err(AdminApiError::NotFound);
        }
        state.storage.add_user_realm_role(&realm_id, &user.id, &role.id).await?;
    }
    issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm_id, &user.id)
        .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{}/role-mappings/realm", id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/users/{id}/role-mappings/realm",
    tag = "Users",
    summary = "Remove realm roles from a user",
    description = "Removes one or more realm roles from the user. Roles are addressed by id. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    request_body(description = "Role representations to remove (id required)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Roles removed successfully"),
        (status = 400, description = "Role representation without id", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_user_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let roles = crate::roles::resolve_role_representations(&state, &realm_id, body.clone()).await?;
    for role in &roles {
        if role.client_role {
            return Err(AdminApiError::NotFound);
        }
        state.storage.remove_user_realm_role(&realm_id, &user.id, &role.id).await?;
    }
    issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm_id, &user.id)
        .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{}/role-mappings/realm", id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users/{id}/role-mappings/realm/available",
    tag = "Users",
    summary = "Get available realm roles for a user",
    description = "Returns the realm roles that are not part of the user's effective role set. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Available realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_available_user_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let effective =
        issuerd_core::effective_user_roles(state.storage.as_ref(), &realm_id, &user.id).await?;
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
    path = "/admin/realms/{realm}/users/{id}/role-mappings/realm/composite",
    tag = "Users",
    summary = "Get effective realm roles of a user",
    description = "Returns the user's effective realm roles: direct mappings plus group mappings, with composite expansion. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Effective realm roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_effective_user_realm_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let effective =
        issuerd_core::effective_user_roles(state.storage.as_ref(), &realm_id, &user.id).await?;
    Ok(Json(effective.into_iter().filter(|r| !r.client_role).map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users/{id}/role-mappings/clients/{client_id}",
    tag = "Users",
    summary = "Get user client roles",
    description = "Returns the roles of the given client assigned to the user. `{client_id}` is the client's internal UUID. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Assigned client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_user_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let client = load_mapping_client(&state, &realm_id, &client_id).await?;
    let ids = state.storage.list_user_client_roles(&realm_id, &user.id).await?;
    let roles = crate::roles::roles_by_ids(&state, &realm_id, ids).await?;
    let assigned = roles
        .into_iter()
        .filter(|r| r.client_role && r.client_id.as_ref() == Some(&client.id))
        .map(Into::into)
        .collect();
    Ok(Json(assigned))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/users/{id}/role-mappings/clients/{client_id}",
    tag = "Users",
    summary = "Add client roles to a user",
    description = "Assigns one or more roles of the given client to the user. Roles are addressed by id; an unknown id or a role of another container yields 404. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    request_body(description = "Role representations to assign (id required)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Roles added successfully"),
        (status = 400, description = "Role representation without id", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_user_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let client = load_mapping_client(&state, &realm_id, &client_id).await?;
    let roles = crate::roles::resolve_role_representations(&state, &realm_id, body.clone()).await?;
    for role in &roles {
        if !role.client_role || role.client_id.as_ref() != Some(&client.id) {
            return Err(AdminApiError::NotFound);
        }
        state.storage.add_user_client_role(&realm_id, &user.id, &role.id).await?;
    }
    issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm_id, &user.id)
        .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{}/role-mappings/clients/{}", id, client.id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/users/{id}/role-mappings/clients/{client_id}",
    tag = "Users",
    summary = "Remove client roles from a user",
    description = "Removes one or more roles of the given client from the user. Roles are addressed by id. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    request_body(description = "Role representations to remove (id required)", content = Vec<RoleRepresentation>),
    responses(
        (status = 204, description = "Roles removed successfully"),
        (status = 400, description = "Role representation without id", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, client, or role not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_user_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Vec<RoleRepresentation>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let client = load_mapping_client(&state, &realm_id, &client_id).await?;
    let roles = crate::roles::resolve_role_representations(&state, &realm_id, body.clone()).await?;
    for role in &roles {
        if !role.client_role || role.client_id.as_ref() != Some(&client.id) {
            return Err(AdminApiError::NotFound);
        }
        state.storage.remove_user_client_role(&realm_id, &user.id, &role.id).await?;
    }
    issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm_id, &user.id)
        .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{}/role-mappings/clients/{}", id, client.id),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users/{id}/role-mappings/clients/{client_id}/available",
    tag = "Users",
    summary = "Get available client roles for a user",
    description = "Returns the roles of the given client that are not part of the user's effective role set. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Available client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_available_user_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let client = load_mapping_client(&state, &realm_id, &client_id).await?;
    let effective =
        issuerd_core::effective_user_roles(state.storage.as_ref(), &realm_id, &user.id).await?;
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
    path = "/admin/realms/{realm}/users/{id}/role-mappings/clients/{client_id}/composite",
    tag = "Users",
    summary = "Get effective client roles of a user",
    description = "Returns the user's effective roles of the given client: direct mappings plus group mappings, with composite expansion. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("client_id" = String, Path, description = "Client ID (internal UUID)")
    ),
    responses(
        (status = 200, description = "Effective client roles", body = Vec<RoleRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or client not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_effective_user_client_roles(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, client_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Vec<RoleRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let client = load_mapping_client(&state, &realm_id, &client_id).await?;
    let effective =
        issuerd_core::effective_user_roles(state.storage.as_ref(), &realm_id, &user.id).await?;
    let roles = effective
        .into_iter()
        .filter(|r| r.client_role && r.client_id.as_ref() == Some(&client.id))
        .map(Into::into)
        .collect();
    Ok(Json(roles))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users/{id}/groups",
    tag = "Users",
    summary = "Get user groups",
    description = "Returns the group IDs the user belongs to. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "List of group IDs", body = Vec<String>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_user_groups(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<String>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let groups = state.storage.list_user_groups(&realm_id, &user_id).await?;
    Ok(Json(groups.into_iter().map(|g| g.to_string()).collect()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/users/{id}/groups/{group_id}",
    tag = "Users",
    summary = "Add user to a group",
    description = "Assigns the user to the specified group. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("group_id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 204, description = "User added to group successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or group not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn add_user_group(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, group_id)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let group_id = GroupId::new(&group_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    state.storage.add_user_group(&realm_id, &user_id, &group_id).await?;
    issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm_id, &user_id)
        .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{}", id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/users/{id}/groups/{group_id}",
    tag = "Users",
    summary = "Remove user from a group",
    description = "Removes the user from the specified group. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("group_id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 204, description = "User removed from group successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or group not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn remove_user_group(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, group_id)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;
    let user_id = UserId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let group_id = GroupId::new(&group_id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    state.storage.remove_user_group(&realm_id, &user_id, &group_id).await?;
    issuerd_cluster::invalidate::invalidate_user_claims(state.cache.as_ref(), &realm_id, &user_id)
        .await;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{}", id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, put},
        Router,
    };
    use issuerd_core::{
        AccessTokenClaims, Algorithm, AuthMethod, Client, Email, IdTokenClaims, IssuerdError,
        JwsType, JwtType, KeyId, RealmAccess, ValidatedAccessToken,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use tower::ServiceExt;

    struct MockTokenService {
        roles: Vec<issuerd_core::RoleName>,
    }

    impl issuerd_core::TokenService for MockTokenService {
        fn validate_access_token(
            &self,
            _token: &str,
        ) -> Result<ValidatedAccessToken, IssuerdError> {
            Ok(ValidatedAccessToken {
                claims: AccessTokenClaims {
                    jti: issuerd_core::JwtId::new("jti").unwrap(),
                    iss: issuerd_core::Issuer::new("http://localhost:8080/realms/master").unwrap(),
                    sub: issuerd_core::UserId::new("admin").unwrap(),
                    aud: issuerd_core::Audience::new("aud").unwrap(),
                    exp: 9999999999,
                    iat: 0,
                    nbf: 0,
                    scope: issuerd_core::Scope::parse("openid"),
                    typ: JwtType::Bearer,
                    azp: None,
                    session_state: None,
                    realm_access: Some(RealmAccess {
                        roles: self.roles.clone(),
                    }),
                    resource_access: None,
                    sid: None,
                    claims: None,
                    cnf: None,
                    authorization_details: None,
                },
                header: issuerd_core::JwsHeader {
                    alg: Algorithm::Rs256,
                    typ: Some(JwsType::Jwt),
                    kid: KeyId::new("key-1").unwrap(),
                },
            })
        }

        fn validate_id_token(
            &self,
            _token: &str,
            _client: &Client,
            _nonce: Option<&str>,
        ) -> Result<IdTokenClaims, IssuerdError> {
            unimplemented!()
        }

        fn validate_refresh_token(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::ValidatedRefreshToken, IssuerdError> {
            unimplemented!()
        }

        fn validate_id_token_hint(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::IdTokenClaims, IssuerdError> {
            unimplemented!()
        }
    }

    fn test_state(roles: Vec<issuerd_core::RoleName>) -> Arc<AdminApiState> {
        Arc::new(AdminApiState {
            storage: crate::test_utils::tests::storage_with_master_realm(),
            token_service: Arc::new(MockTokenService { roles }),
            crypto: {
                let mut mock = issuerd_core::MockCryptoProvider::new();
                mock.expect_get_public_keys()
                    .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));
                Arc::new(mock)
            },
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender: Arc::new(issuerd_core::MockEmailSender::new()),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            base_url: "http://localhost:8080".to_string(),
        })
    }

    fn user_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/users", get(list_users).post(create_user))
            .route(
                "/admin/realms/{realm}/users/{id}",
                get(get_user).put(update_user).delete(delete_user),
            )
            .route("/admin/realms/{realm}/users/{id}/sessions", get(get_user_sessions))
            .route("/admin/realms/{realm}/users/{id}/reset-password", put(reset_password))
            .route("/admin/realms/{realm}/users/{id}/role-mappings", get(get_user_role_mappings))
            .route(
                "/admin/realms/{realm}/users/{id}/role-mappings/realm",
                get(get_user_realm_roles)
                    .post(add_user_realm_roles)
                    .delete(remove_user_realm_roles),
            )
            .route(
                "/admin/realms/{realm}/users/{id}/role-mappings/realm/available",
                get(get_available_user_realm_roles),
            )
            .route(
                "/admin/realms/{realm}/users/{id}/role-mappings/realm/composite",
                get(get_effective_user_realm_roles),
            )
            .route(
                "/admin/realms/{realm}/users/{id}/role-mappings/clients/{client_id}",
                get(get_user_client_roles)
                    .post(add_user_client_roles)
                    .delete(remove_user_client_roles),
            )
            .route(
                "/admin/realms/{realm}/users/{id}/role-mappings/clients/{client_id}/available",
                get(get_available_user_client_roles),
            )
            .route(
                "/admin/realms/{realm}/users/{id}/role-mappings/clients/{client_id}/composite",
                get(get_effective_user_client_roles),
            )
            .route("/admin/realms/{realm}/users/{id}/groups", get(get_user_groups))
            .route(
                "/admin/realms/{realm}/users/{id}/groups/{group_id}",
                put(add_user_group).delete(remove_user_group),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    async fn create_test_realm_and_user(state: &Arc<AdminApiState>) -> (String, String) {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("user-1").unwrap(),
            realm_id: realm.id.clone(),
            username: issuerd_core::Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(issuerd_core::DisplayName::new("Alice").unwrap()),
            last_name: Some(issuerd_core::DisplayName::new("Smith").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm.id, &user).await.unwrap();
        (realm.name.to_string(), user.id.to_string())
    }

    async fn create_test_client(
        state: &Arc<AdminApiState>,
        realm_id: &issuerd_core::RealmId,
        id: &str,
        client_id: &str,
    ) -> Client {
        let client = Client {
            id: issuerd_core::ClientId::new(id).unwrap(),
            realm_id: realm_id.clone(),
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
            attributes: HashMap::new(),
        };
        state.storage.create_client(realm_id, &client).await.unwrap();
        client
    }

    async fn create_test_role(
        state: &Arc<AdminApiState>,
        realm_id: &issuerd_core::RealmId,
        id: &str,
        name: &str,
        client: Option<&Client>,
    ) -> issuerd_core::Role {
        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new(id).unwrap(),
            name: RoleName::new(name).unwrap(),
            description: None,
            realm_id: realm_id.clone(),
            client_role: client.is_some(),
            client_id: client.map(|c| c.id.clone()),
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        state.storage.create_role(realm_id, &role).await.unwrap();
        role
    }

    #[tokio::test]
    async fn create_user_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());

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
                    .uri("/admin/realms/test/users")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"username":"bob","email":"bob@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_user_with_required_actions_persists() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());

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
                    .uri("/admin/realms/test/users")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"username":"bob","email":"bob@example.com","requiredActions":["VERIFY_EMAIL","UPDATE_PROFILE"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: UserRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            rep.required_actions,
            Some(vec!["VERIFY_EMAIL".to_string(), "UPDATE_PROFILE".to_string()])
        );

        // The actions are persisted on the stored user, not just echoed back.
        let stored = state
            .storage
            .get_user_by_username(&issuerd_core::RealmId::new("realm-1").unwrap(), "bob")
            .await
            .unwrap()
            .expect("user should be stored");
        assert_eq!(
            stored.required_actions,
            vec!["VERIFY_EMAIL".to_string(), "UPDATE_PROFILE".to_string()]
        );
    }

    #[tokio::test]
    async fn get_user_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn update_user_email() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"username":"alice","email":"new@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: UserRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.email, Some("new@example.com".to_string()));
    }

    #[tokio::test]
    async fn update_user_drops_claims_cache_key() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        // Seed the claims read-model entry the userinfo path would have written.
        let key = issuerd_cluster::cache_keys::user_claims("realm-1", &user_id);
        state.cache.set(&key, b"{}".to_vec(), None).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"username":"alice","email":"new@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            state.cache.get(&key).await.unwrap().is_none(),
            "update_user invalidated the claims cache entry"
        );
    }

    #[tokio::test]
    async fn delete_user_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
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
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_user_bumps_session_version_counter() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // The DB cascade removed the user's sessions without touching Rust;
        // the version bump makes every cached session-validity snapshot of
        // this user miss on its next read.
        let v = state
            .cache
            .get(&issuerd_cluster::cache_keys::session_version("realm-1", &user_id))
            .await
            .unwrap()
            .expect("session version counter bumped");
        assert_eq!(std::str::from_utf8(&v).unwrap(), "1");
    }

    #[tokio::test]
    async fn delete_user_malformed_id_returns_bad_request() {
        // Route matching never yields an empty `{id}` segment, but the
        // handler must still surface newtype validation failures as a clean
        // 400 instead of panicking on untrusted input.
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let auth = AdminAuth {
            claims: AccessTokenClaims {
                jti: issuerd_core::JwtId::new("jti").unwrap(),
                iss: issuerd_core::Issuer::new("http://localhost:8080/realms/master").unwrap(),
                sub: issuerd_core::UserId::new("admin").unwrap(),
                aud: issuerd_core::Audience::new("aud").unwrap(),
                exp: 9999999999,
                iat: 0,
                nbf: 0,
                scope: issuerd_core::Scope::parse("openid"),
                typ: JwtType::Bearer,
                azp: None,
                session_state: None,
                realm_access: Some(RealmAccess {
                    roles: vec![issuerd_core::RoleName::new("manage-users").unwrap()],
                }),
                resource_access: None,
                sid: None,
                claims: None,
                cnf: None,
                authorization_details: None,
            },
        };
        let result = delete_user(
            State(state),
            Extension(auth),
            axum::extract::Path(("master".to_string(), String::new())),
        )
        .await;
        assert!(matches!(result, Err(AdminApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn search_users_by_username() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, _) = create_test_realm_and_user(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users?search=alice"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<UserRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
    }

    #[tokio::test]
    async fn reset_password_creates_credential() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/reset-password"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"type":"password","value":"secret123"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let creds = state
            .storage
            .get_credentials(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::UserId::new(&user_id).unwrap(),
                CredentialType::Password,
            )
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
    }

    #[tokio::test]
    async fn assign_realm_role_to_user() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new("role-1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: None,
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        state.storage.create_role(&role.realm_id, &role).await.unwrap();

        // Keycloak payload: role representations addressed by id.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/role-mappings/realm"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"role-1","name":"admin"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: UserRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.realm_roles, Some(vec!["admin".to_string()]));
    }

    #[tokio::test]
    async fn assign_unknown_role_id_returns_404() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/role-mappings/realm"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"no-such-role","name":"ghost"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn add_user_to_group() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let group = issuerd_core::Group {
            id: issuerd_core::GroupId::new("group-1").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: issuerd_core::GroupPath::new("/admins").unwrap(),
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        state.storage.create_group(&group.realm_id, &group).await.unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/groups/group-1"))
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
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: UserRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.groups, Some(vec!["group-1".to_string()]));
    }

    #[tokio::test]
    async fn insufficient_roles_returns_403() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-realm").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, _) = create_test_realm_and_user(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/realms/{realm_name}/users"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"username":"bob"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_users_without_search() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, _) = create_test_realm_and_user(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<UserRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
    }

    #[tokio::test]
    async fn get_user_sessions_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let session = issuerd_core::UserSession {
            id: issuerd_core::SessionId::new("session-1").unwrap(),
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            user_id: issuerd_core::UserId::new(&user_id).unwrap(),
            login_username: issuerd_core::Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: chrono::Utc::now(),
            last_session_refresh: chrono::Utc::now(),
            auth_time: chrono::Utc::now(),
            impersonator: None,
            clients: vec![],
        };
        state
            .storage
            .create_user_session(&issuerd_core::RealmId::new("realm-1").unwrap(), &session)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/sessions"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<crate::dto::UserSessionRepresentation> =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 1);
    }

    #[tokio::test]
    async fn get_user_realm_roles_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new("role-1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: None,
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        state.storage.create_role(&role.realm_id, &role).await.unwrap();
        state
            .storage
            .add_user_realm_role(
                &role.realm_id,
                &issuerd_core::UserId::new(&user_id).unwrap(),
                &role.id,
            )
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/role-mappings/realm"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let roles: Vec<RoleRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, Some("role-1".to_string()));
        assert_eq!(roles[0].name, "admin");
    }

    #[tokio::test]
    async fn remove_user_realm_roles_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new("role-1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: None,
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        state.storage.create_role(&role.realm_id, &role).await.unwrap();
        state
            .storage
            .add_user_realm_role(
                &role.realm_id,
                &issuerd_core::UserId::new(&user_id).unwrap(),
                &role.id,
            )
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/role-mappings/realm"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"role-1","name":"admin"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let roles = state
            .storage
            .list_user_realm_roles(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::UserId::new(&user_id).unwrap(),
            )
            .await
            .unwrap();
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn get_user_groups_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let group = issuerd_core::Group {
            id: issuerd_core::GroupId::new("group-1").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: issuerd_core::GroupPath::new("/admins").unwrap(),
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        state.storage.create_group(&group.realm_id, &group).await.unwrap();
        state
            .storage
            .add_user_group(
                &group.realm_id,
                &issuerd_core::UserId::new(&user_id).unwrap(),
                &group.id,
            )
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/groups"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let groups: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert_eq!(groups, vec!["group-1"]);
    }

    #[tokio::test]
    async fn remove_user_group_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let group = issuerd_core::Group {
            id: issuerd_core::GroupId::new("group-1").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: issuerd_core::GroupPath::new("/admins").unwrap(),
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        state.storage.create_group(&group.realm_id, &group).await.unwrap();
        state
            .storage
            .add_user_group(
                &group.realm_id,
                &issuerd_core::UserId::new(&user_id).unwrap(),
                &group.id,
            )
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/groups/group-1"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let groups = state
            .storage
            .list_user_groups(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::UserId::new(&user_id).unwrap(),
            )
            .await
            .unwrap();
        assert!(groups.is_empty());
    }

    #[tokio::test]
    async fn create_user_realm_not_found() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/nonexistent/users")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"username":"bob"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_user_404() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, _) = create_test_realm_and_user(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/users/nonexistent"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"username":"bob"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// PUT a reset-password request body, returning the raw response.
    async fn do_reset_password(
        app: &Router,
        realm_name: &str,
        user_id: &str,
        body: &str,
    ) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/reset-password"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn reset_password_policy_violation_returns_400() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;
        let mut realm = state.storage.get_realm_by_name(&realm_name).await.unwrap().unwrap();
        realm.password_policy.require_digits = true;
        state.storage.update_realm(&realm).await.unwrap();

        let response = do_reset_password(
            &app,
            &realm_name,
            &user_id,
            r#"{"type":"password","value":"onlylowercase"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("errorMessage").and_then(|m| m.as_str()).is_some());
        let violations = json.get("policyViolations").and_then(|v| v.as_array()).unwrap();
        assert!(violations
            .iter()
            .any(|v| v.get("code").and_then(|c| c.as_str()) == Some("require_digits")));
        // Rejected before storage: no password credential may have been created.
        let creds = state
            .storage
            .get_credentials(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::UserId::new(&user_id).unwrap(),
                CredentialType::Password,
            )
            .await
            .unwrap();
        assert!(creds.is_empty());
    }

    #[tokio::test]
    async fn reset_password_history_reuse_returns_400() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;
        let mut realm = state.storage.get_realm_by_name(&realm_name).await.unwrap().unwrap();
        realm.password_policy.history_size = 3;
        state.storage.update_realm(&realm).await.unwrap();

        let response = do_reset_password(
            &app,
            &realm_name,
            &user_id,
            r#"{"type":"password","value":"First!pass1"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = do_reset_password(
            &app,
            &realm_name,
            &user_id,
            r#"{"type":"password","value":"Sec0nd!pass"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // The superseded first password is retained as an inert history entry
        // with the temporary flag stripped.
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();
        let uid = issuerd_core::UserId::new(&user_id).unwrap();
        let history = state
            .storage
            .get_credentials(
                &realm_id,
                &uid,
                CredentialType::Custom(PASSWORD_HISTORY_CREDENTIAL_TYPE.to_string()),
            )
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].credential_data.get("temporary").is_none());

        // Reusing the first password is now a history violation.
        let response = do_reset_password(
            &app,
            &realm_name,
            &user_id,
            r#"{"type":"password","value":"First!pass1"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let violations = json.get("policyViolations").and_then(|v| v.as_array()).unwrap();
        assert!(violations
            .iter()
            .any(|v| v.get("code").and_then(|c| c.as_str()) == Some("password_history")));
    }

    #[tokio::test]
    async fn reset_password_temporary_adds_update_password_action() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();
        let uid = issuerd_core::UserId::new(&user_id).unwrap();

        let response = do_reset_password(
            &app,
            &realm_name,
            &user_id,
            r#"{"type":"password","value":"Temp!pass1","temporary":true}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let user = state.storage.get_user(&realm_id, &uid).await.unwrap().unwrap();
        assert_eq!(
            user.required_actions.iter().filter(|a| *a == "UPDATE_PASSWORD").count(),
            1,
            "temporary reset must add UPDATE_PASSWORD exactly once"
        );

        // A non-temporary reset leaves required_actions untouched.
        let response = do_reset_password(
            &app,
            &realm_name,
            &user_id,
            r#"{"type":"password","value":"An0ther!pass","temporary":false}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let user = state.storage.get_user(&realm_id, &uid).await.unwrap().unwrap();
        assert_eq!(
            user.required_actions.iter().filter(|a| *a == "UPDATE_PASSWORD").count(),
            1,
            "non-temporary reset must not add or remove UPDATE_PASSWORD"
        );
    }

    // -----------------------------------------------------------------------
    // Federation password write-through
    // -----------------------------------------------------------------------

    /// Stub provider recording password writes.
    struct StubFederationProvider {
        id: String,
        update_result: std::sync::Mutex<Result<(), issuerd_core::FederationError>>,
        written: std::sync::Mutex<Vec<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationProvider for StubFederationProvider {
        fn id(&self) -> &str {
            &self.id
        }

        fn provider_type(&self) -> issuerd_core::FederationProviderType {
            issuerd_core::FederationProviderType::Ldap
        }

        async fn find_user(
            &self,
            _username: &str,
        ) -> Result<Option<issuerd_core::FederatedUser>, issuerd_core::FederationError> {
            Ok(None)
        }

        async fn find_user_by_email(
            &self,
            _email: &str,
        ) -> Result<Option<issuerd_core::FederatedUser>, issuerd_core::FederationError> {
            Ok(None)
        }

        async fn validate_password(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<bool, issuerd_core::FederationError> {
            Ok(true)
        }

        async fn update_password(
            &self,
            username: &str,
            password: &str,
        ) -> Result<(), issuerd_core::FederationError> {
            self.written.lock().unwrap().push((username.to_string(), password.to_string()));
            let guard = self.update_result.lock().unwrap();
            match &*guard {
                Ok(()) => Ok(()),
                Err(issuerd_core::FederationError::NotSupported) => {
                    Err(issuerd_core::FederationError::NotSupported)
                }
                Err(_) => Err(issuerd_core::FederationError::NetworkError("stub".into())),
            }
        }

        fn supports_password_update(&self) -> bool {
            true
        }
    }

    struct StubFederationManager {
        providers: Vec<Arc<dyn issuerd_core::FederationProvider>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationManager for StubFederationManager {
        async fn providers_for_realm(
            &self,
            _realm_id: &issuerd_core::RealmId,
        ) -> Result<Vec<Arc<dyn issuerd_core::FederationProvider>>, issuerd_core::IssuerdError>
        {
            Ok(self.providers.clone())
        }

        async fn find_user(
            &self,
            _realm_id: &issuerd_core::RealmId,
            _username: &str,
        ) -> Result<
            Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
            issuerd_core::IssuerdError,
        > {
            Ok(None)
        }

        async fn find_user_by_email(
            &self,
            _realm_id: &issuerd_core::RealmId,
            _email: &str,
        ) -> Result<
            Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
            issuerd_core::IssuerdError,
        > {
            Ok(None)
        }
    }

    /// `test_state` with the federation manager swapped for the stub.
    fn test_state_with_federation(
        roles: Vec<issuerd_core::RoleName>,
        fm: Arc<dyn issuerd_core::FederationManager>,
    ) -> Arc<AdminApiState> {
        let base = test_state(roles);
        Arc::new(AdminApiState {
            storage: base.storage.clone(),
            token_service: base.token_service.clone(),
            crypto: base.crypto.clone(),
            federation_manager: fm,
            plugin_registry: base.plugin_registry.clone(),
            cache: base.cache.clone(),
            email_sender: base.email_sender.clone(),
            broker_client: base.broker_client.clone(),
            logout_notifier: base.logout_notifier.clone(),
            available_themes: base.available_themes.clone(),
            token_issuer: base.token_issuer.clone(),
            signing_key_reload: base.signing_key_reload.clone(),
            base_url: base.base_url.clone(),
        })
    }

    #[tokio::test]
    async fn reset_password_federated_writes_through_to_directory() {
        let provider = Arc::new(StubFederationProvider {
            id: "ldap-1".to_string(),
            update_result: std::sync::Mutex::new(Ok(())),
            written: std::sync::Mutex::new(vec![]),
        });
        let state = test_state_with_federation(
            vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            Arc::new(StubFederationManager {
                providers: vec![provider.clone()],
            }),
        );
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();
        let uid = issuerd_core::UserId::new(&user_id).unwrap();
        let mut user = state.storage.get_user(&realm_id, &uid).await.unwrap().unwrap();
        user.federation_link = Some("ldap-1".to_string());
        state.storage.update_user(&realm_id, &user).await.unwrap();

        let response = do_reset_password(
            &app,
            &realm_name,
            &user_id,
            r#"{"type":"password","value":"New!pass123","temporary":true}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // The directory received the password; no local credential exists.
        assert_eq!(
            provider.written.lock().unwrap().as_slice(),
            [("alice".to_string(), "New!pass123".to_string())]
        );
        let creds = state
            .storage
            .get_credentials(&realm_id, &uid, CredentialType::Password)
            .await
            .unwrap();
        assert!(creds.is_empty(), "write-through must not create a local credential");
        // The temporary flag still drives the UPDATE_PASSWORD required action.
        let user = state.storage.get_user(&realm_id, &uid).await.unwrap().unwrap();
        assert!(user.required_actions.iter().any(|a| a == "UPDATE_PASSWORD"));
    }

    #[tokio::test]
    async fn reset_password_federated_readonly_directory_returns_400() {
        let provider = Arc::new(StubFederationProvider {
            id: "ldap-1".to_string(),
            update_result: std::sync::Mutex::new(Err(issuerd_core::FederationError::NotSupported)),
            written: std::sync::Mutex::new(vec![]),
        });
        let state = test_state_with_federation(
            vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            Arc::new(StubFederationManager {
                providers: vec![provider.clone()],
            }),
        );
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();
        let uid = issuerd_core::UserId::new(&user_id).unwrap();
        let mut user = state.storage.get_user(&realm_id, &uid).await.unwrap().unwrap();
        user.federation_link = Some("ldap-1".to_string());
        state.storage.update_user(&realm_id, &user).await.unwrap();

        let response = do_reset_password(
            &app,
            &realm_name,
            &user_id,
            r#"{"type":"password","value":"New!pass123"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let creds = state
            .storage
            .get_credentials(&realm_id, &uid, CredentialType::Password)
            .await
            .unwrap();
        assert!(creds.is_empty(), "a rejected directory write must not fall back to local");
    }

    #[tokio::test]
    async fn update_user_required_actions_roundtrip() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"username":"alice","requiredActions":["VERIFY_EMAIL"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rep: UserRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(rep.required_actions, Some(vec!["VERIFY_EMAIL".to_string()]));
    }

    #[tokio::test]
    async fn get_user_role_mappings_combines_realm_and_client() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();
        let uid = issuerd_core::UserId::new(&user_id).unwrap();

        let realm_role = create_test_role(&state, &realm_id, "role-1", "admin", None).await;
        let client = create_test_client(&state, &realm_id, "client-1", "my-app").await;
        let client_role =
            create_test_role(&state, &realm_id, "role-2", "app-admin", Some(&client)).await;
        state
            .storage
            .add_user_realm_role(&realm_id, &uid, &realm_role.id)
            .await
            .unwrap();
        state
            .storage
            .add_user_client_role(&realm_id, &uid, &client_role.id)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users/{user_id}/role-mappings"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let mappings: crate::dto::MappingsRepresentation = serde_json::from_slice(&body).unwrap();
        let realm_mappings = mappings.realm_mappings.unwrap();
        assert_eq!(realm_mappings.len(), 1);
        assert_eq!(realm_mappings[0].name, "admin");
        let client_mappings = mappings.client_mappings.unwrap();
        let entry = client_mappings.get("my-app").expect("keyed by client_id string");
        assert_eq!(entry.id, "client-1");
        assert_eq!(entry.client, "my-app");
        assert_eq!(entry.mappings.len(), 1);
        assert_eq!(entry.mappings[0].name, "app-admin");
    }

    #[tokio::test]
    async fn user_realm_roles_available_and_effective() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();
        let uid = issuerd_core::UserId::new(&user_id).unwrap();

        let assigned = create_test_role(&state, &realm_id, "role-1", "assigned", None).await;
        create_test_role(&state, &realm_id, "role-2", "free", None).await;
        state.storage.add_user_realm_role(&realm_id, &uid, &assigned.id).await.unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/users/{user_id}/role-mappings/realm/composite"
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

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/users/{user_id}/role-mappings/realm/available"
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
        assert_eq!(roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["free"]);
    }

    #[tokio::test]
    async fn user_client_role_mappings_roundtrip() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();

        let client = create_test_client(&state, &realm_id, "client-1", "my-app").await;
        create_test_role(&state, &realm_id, "role-a", "app-admin", Some(&client)).await;
        create_test_role(&state, &realm_id, "role-b", "app-viewer", Some(&client)).await;

        // Assign role-a by id.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/client-1"
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"role-a","name":"app-admin"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Assigned list.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/client-1"
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
        assert_eq!(roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["app-admin"]);
        assert_eq!(roles[0].container_id, Some("client-1".to_string()));

        // Available = the other client role; effective = the assigned one.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/client-1/available"
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

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/client-1/composite"
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let roles: Vec<RoleRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["app-admin"]);

        // Remove.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/client-1"
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"role-a","name":"app-admin"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let roles = state
            .storage
            .list_user_client_roles(&realm_id, &issuerd_core::UserId::new(&user_id).unwrap())
            .await
            .unwrap();
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn user_client_roles_reject_foreign_container() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, user_id) = create_test_realm_and_user(&state).await;
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();

        let client = create_test_client(&state, &realm_id, "client-1", "my-app").await;
        let other = create_test_client(&state, &realm_id, "client-2", "other-app").await;
        create_test_role(&state, &realm_id, "role-x", "other-role", Some(&other)).await;

        // Posting a role of `other-app` to `my-app`'s mapping endpoint is a 404.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/{}",
                        client.id
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"[{"id":"role-x","name":"other-role"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Unknown client in the path is a 404 too.
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/no-such-client"
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn role_mappings_unknown_user_returns_404() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        let app = user_routes(state.clone());
        let (realm_name, _) = create_test_realm_and_user(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/admin/realms/{realm_name}/users/no-such-user/role-mappings"))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
