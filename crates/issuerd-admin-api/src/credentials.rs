// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// User credentials CRUD: list, relabel, delete, and reorder (secrets redacted).

//! User credentials CRUD: list, relabel, delete, and reorder a
//! user's credentials. Secret material never leaves the API — every response
//! goes through [`CredentialRepresentation::redacted_from`].

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{Credential, OperationType, RealmId, ResourceType, UserId};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{CredentialRepresentation, UpdateCredentialLabelRequest},
    error::AdminApiError,
    state::AdminApiState,
};
use tracing::instrument;

// ---------------------------------------------------------------------------
// Helpers
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

/// All credentials of the user, deterministically ordered.
///
/// Credentials are consumed lowest-`priority`-first (both storage backends
/// sort ascending on read; see `InMemoryStorage::list_credentials`), with
/// `created_date` as the tiebreak for equal priorities.
async fn sorted_credentials(
    state: &Arc<AdminApiState>,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Result<Vec<Credential>, AdminApiError> {
    let mut creds = state.storage.list_credentials(realm_id, user_id).await?;
    creds.sort_by_key(|c| (c.priority, c.created_date));
    Ok(creds)
}

/// Find one credential of the user by id (404 when unknown).
fn find_credentials(
    creds: &[Credential],
    credential_id: &str,
) -> Result<Credential, AdminApiError> {
    creds
        .iter()
        .find(|c| c.id.as_ref() == credential_id)
        .cloned()
        .ok_or(AdminApiError::NotFound)
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/users/{id}/credentials",
    tag = "Users",
    summary = "List user credentials",
    description = "Returns all credentials of the user (all types), ordered by priority. Secret data is never included — the representations carry metadata only. Requires `view-users` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "List of credentials (redacted)", body = Vec<CredentialRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_user_credentials(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<CredentialRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-users", "manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let creds = sorted_credentials(&state, &realm_id, &user.id).await?;
    Ok(Json(creds.iter().map(CredentialRepresentation::redacted_from).collect()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/users/{id}/credentials/{credential_id}",
    tag = "Users",
    summary = "Update a credential's user label",
    description = "Updates the user-facing label of the credential (e.g. \"My laptop\"). Only the label is mutable through this endpoint. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("credential_id" = String, Path, description = "Credential ID")
    ),
    request_body(description = "New label (`null` clears it)", content = UpdateCredentialLabelRequest),
    responses(
        (status = 204, description = "Credential label updated"),
        (status = 400, description = "Invalid request", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or credential not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth, body), fields(realm = %realm, user_id = %id))]
pub async fn update_credential_label(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, credential_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<UpdateCredentialLabelRequest>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let creds = sorted_credentials(&state, &realm_id, &user.id).await?;
    let mut cred = find_credentials(&creds, &credential_id)?;
    cred.user_label = body.user_label.clone();
    state.storage.update_credential(&realm_id, &user.id, &cred).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Update,
        ResourceType::User,
        &format!("users/{id}/credentials/{credential_id}"),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/users/{id}/credentials/{credential_id}",
    tag = "Users",
    summary = "Delete a user credential",
    description = "Deletes the credential. The user's last remaining credential cannot be deleted (400) — reset the password or add a credential first. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("credential_id" = String, Path, description = "Credential ID")
    ),
    responses(
        (status = 204, description = "Credential deleted"),
        (status = 400, description = "Cannot delete the user's last credential", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or credential not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth), fields(realm = %realm, user_id = %id))]
pub async fn delete_credential(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, credential_id)): axum::extract::Path<(String, String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let creds = sorted_credentials(&state, &realm_id, &user.id).await?;
    let cred = find_credentials(&creds, &credential_id)?;
    if creds.len() == 1 {
        return Err(AdminApiError::BadRequest(
            "cannot delete the user's last credential".to_string(),
        ));
    }
    state.storage.delete_credential(&realm_id, &user.id, &cred.id).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Delete,
        ResourceType::User,
        &format!("users/{id}/credentials/{credential_id}"),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/users/{id}/credentials/{credential_id}/moveAfter/{new_previous_credential_id}",
    tag = "Users",
    summary = "Move a credential after another",
    description = "Reorders the user's credentials so the addressed credential sits immediately after `new_previous_credential_id`. Ordering scheme: credentials are consumed lowest-`priority`-first; after the move the full list is renumbered to sequential priorities (1..n) in the new order, so only the priorities that actually change are persisted. Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ("credential_id" = String, Path, description = "Credential to move"),
        ("new_previous_credential_id" = String, Path, description = "Credential after which to place it")
    ),
    responses(
        (status = 204, description = "Credential moved"),
        (status = 400, description = "Cannot move a credential after itself", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, user, or credential not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth), fields(realm = %realm, user_id = %id))]
pub async fn move_credential_after(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, credential_id, new_previous_credential_id)): axum::extract::Path<
        (String, String, String, String),
    >,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let (realm_id, user) = load_user(&state, &realm, &id).await?;
    let mut creds = sorted_credentials(&state, &realm_id, &user.id).await?;
    let moved_idx = creds
        .iter()
        .position(|c| c.id.as_ref() == credential_id.as_str())
        .ok_or(AdminApiError::NotFound)?;
    let target_idx = creds
        .iter()
        .position(|c| c.id.as_ref() == new_previous_credential_id.as_str())
        .ok_or(AdminApiError::NotFound)?;
    if moved_idx == target_idx {
        return Err(AdminApiError::BadRequest("cannot move a credential after itself".to_string()));
    }
    let moved = creds.remove(moved_idx);
    let insert_idx = creds
        .iter()
        .position(|c| c.id.as_ref() == new_previous_credential_id.as_str())
        .expect("target credential still present")
        + 1;
    creds.insert(insert_idx, moved);
    // Renumber sequentially in the new order; only persist actual changes.
    for (idx, cred) in creds.iter_mut().enumerate() {
        let new_priority = (idx + 1) as i32;
        if cred.priority != new_priority {
            cred.priority = new_priority;
            state.storage.update_credential(&realm_id, &user.id, cred).await?;
        }
    }
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{id}/credentials/{credential_id}/moveAfter/{new_previous_credential_id}"),
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
        routing::{get, put},
        Router,
    };
    use issuerd_core::{CredentialId, CredentialType, Email};
    use tower::ServiceExt;

    fn credential_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/users/{id}/credentials",
                get(list_user_credentials),
            )
            .route(
                "/admin/realms/{realm}/users/{id}/credentials/{credential_id}",
                put(update_credential_label).delete(delete_credential),
            )
            .route(
                "/admin/realms/{realm}/users/{id}/credentials/{credential_id}/moveAfter/{new_previous_credential_id}",
                put(move_credential_after),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    async fn realm_and_user(state: &Arc<AdminApiState>) -> (String, String) {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            // Admin-event recording is opt-in per realm; these tests assert
            // on the emitted audit events.
            admin_events_enabled: true,
            include_representations: true,
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("user-1").unwrap(),
            realm_id: realm.id.clone(),
            username: issuerd_core::Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: Default::default(),
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm.id, &user).await.unwrap();
        (realm.name.to_string(), user.id.to_string())
    }

    async fn add_credential(
        state: &Arc<AdminApiState>,
        user_id: &str,
        id: &str,
        cred_type: CredentialType,
        priority: i32,
        secret: &str,
    ) {
        let cred = Credential {
            id: CredentialId::new(id).unwrap(),
            credential_type: cred_type,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: secret.as_bytes().to_vec(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority,
        };
        state
            .storage
            .create_credential(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &UserId::new(user_id).unwrap(),
                &cred,
            )
            .await
            .unwrap();
    }

    async fn call(
        app: Router,
        method: &str,
        uri: String,
        body: Option<String>,
    ) -> (StatusCode, axum::body::Bytes) {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", "Bearer valid-token");
        let builder = if body.is_some() {
            builder.header("Content-Type", "application/json")
        } else {
            builder
        };
        let response = app
            .oneshot(builder.body(Body::from(body.unwrap_or_default())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, bytes)
    }

    #[tokio::test]
    async fn list_credentials_redacted_and_sorted() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        // Insert out of priority order; the endpoint must sort ascending.
        add_credential(&state, &user_id, "cred-totp", CredentialType::Totp, 2, "totp-secret").await;
        add_credential(&state, &user_id, "cred-pw", CredentialType::Password, 1, "pw-secret").await;

        let (status, body) =
            call(app, "GET", format!("/admin/realms/{realm}/users/{user_id}/credentials"), None)
                .await;
        assert_eq!(status, StatusCode::OK);
        let reps: Vec<CredentialRepresentation> = serde_json::from_slice(&body).unwrap();
        assert_eq!(reps.len(), 2);
        assert_eq!(reps[0].id.as_deref(), Some("cred-pw"));
        assert_eq!(reps[0].credential_type, CredentialType::Password);
        assert_eq!(reps[1].id.as_deref(), Some("cred-totp"));
        // No secret material anywhere in the response body.
        let raw = String::from_utf8(body.to_vec()).unwrap();
        assert!(!raw.contains("pw-secret"));
        assert!(!raw.contains("totp-secret"));
        assert!(reps.iter().all(|r| r.secret_data.is_none() && r.value.is_none()));
        assert!(reps.iter().all(|r| r.created_date.is_some()));
    }

    #[tokio::test]
    async fn list_credentials_unknown_user_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, _) = realm_and_user(&state).await;
        let (status, _) = call(
            app,
            "GET",
            format!("/admin/realms/{realm}/users/no-such-user/credentials"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_credential_label_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        add_credential(&state, &user_id, "cred-totp", CredentialType::Totp, 1, "secret").await;
        add_credential(&state, &user_id, "cred-pw", CredentialType::Password, 2, "secret2").await;

        let (status, _) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/cred-totp"),
            Some(r#"{"userLabel":"My phone"}"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let creds = state
            .storage
            .get_credentials(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &UserId::new(&user_id).unwrap(),
                CredentialType::Totp,
            )
            .await
            .unwrap();
        assert_eq!(creds[0].user_label, Some("My phone".to_string()));

        // Audit event recorded.
        let events = state
            .storage
            .query_admin_events(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: issuerd_core::Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, OperationType::Update);
        assert_eq!(events[0].resource_path, format!("users/{user_id}/credentials/cred-totp"));
    }

    #[tokio::test]
    async fn update_credential_label_unknown_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        add_credential(&state, &user_id, "cred-pw", CredentialType::Password, 1, "s").await;

        let (status, _) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/nope"),
            Some(r#"{"userLabel":"x"}"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_credential_label_requires_manage_users() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        add_credential(&state, &user_id, "cred-pw", CredentialType::Password, 1, "s").await;

        let (status, _) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/cred-pw"),
            Some(r#"{"userLabel":"x"}"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_credential_success() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        add_credential(&state, &user_id, "cred-pw", CredentialType::Password, 1, "s1").await;
        add_credential(&state, &user_id, "cred-totp", CredentialType::Totp, 2, "s2").await;

        let (status, _) = call(
            app,
            "DELETE",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/cred-totp"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let remaining = state
            .storage
            .list_credentials(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &UserId::new(&user_id).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id.as_ref(), "cred-pw");
    }

    #[tokio::test]
    async fn delete_last_credential_rejected() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        add_credential(&state, &user_id, "cred-pw", CredentialType::Password, 1, "s1").await;

        let (status, body) = call(
            app,
            "DELETE",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/cred-pw"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let raw = String::from_utf8(body.to_vec()).unwrap();
        assert!(raw.contains("last credential"));
        // The credential survives.
        let remaining = state
            .storage
            .list_credentials(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &UserId::new(&user_id).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn delete_unknown_credential_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        add_credential(&state, &user_id, "cred-pw", CredentialType::Password, 1, "s1").await;

        let (status, _) = call(
            app,
            "DELETE",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/nope"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn move_credential_after_reorders() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        add_credential(&state, &user_id, "cred-a", CredentialType::Password, 1, "s").await;
        add_credential(&state, &user_id, "cred-b", CredentialType::Totp, 2, "s").await;
        add_credential(&state, &user_id, "cred-c", CredentialType::WebAuthn, 3, "s").await;

        // Move A after C: expected order B, C, A.
        let (status, _) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/cred-a/moveAfter/cred-c"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let creds = state
            .storage
            .list_credentials(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &UserId::new(&user_id).unwrap(),
            )
            .await
            .unwrap();
        let mut ordered: Vec<(&str, i32)> =
            creds.iter().map(|c| (c.id.as_ref(), c.priority)).collect();
        ordered.sort_by_key(|(_, p)| *p);
        assert_eq!(ordered, [("cred-b", 1), ("cred-c", 2), ("cred-a", 3)]);
    }

    #[tokio::test]
    async fn move_credential_after_unknown_ids_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        add_credential(&state, &user_id, "cred-a", CredentialType::Password, 1, "s").await;
        add_credential(&state, &user_id, "cred-b", CredentialType::Totp, 2, "s").await;

        let (status, _) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/nope/moveAfter/cred-b"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = call(
            credential_routes(state.clone()),
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/cred-a/moveAfter/nope"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn move_credential_after_itself_400() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-users").unwrap()
            ]);
        let app = credential_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state).await;
        add_credential(&state, &user_id, "cred-a", CredentialType::Password, 1, "s").await;
        add_credential(&state, &user_id, "cred-b", CredentialType::Totp, 2, "s").await;

        let (status, _) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/credentials/cred-a/moveAfter/cred-a"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
