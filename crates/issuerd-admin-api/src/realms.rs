// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Realm management endpoints: CRUD, built-in client seeding, and SMTP test.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use issuerd_core::{
    Client, ClientAuthenticatorType, ClientId, ClientIdentifier, ClientProtocol, DisplayName,
    OperationType, Pagination, RedirectUri, ResourceType, Scope, WebOrigin,
};
use std::{collections::HashMap, sync::Arc};

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{
        CountRepresentation, PaginationQueryParams, RealmRepresentation, TestSmtpConnectionRequest,
    },
    error::AdminApiError,
    state::AdminApiState,
};
use tracing::{info, instrument, warn};

/// Build the default `admin-cli` client for a realm.
///
/// Every realm gets this built-in public client (Keycloak parity); it is used
/// by the admin console, Swagger UI and CLI-style logins.
pub fn build_admin_cli_client(
    realm_id: &issuerd_core::RealmId,
    base_url: &str,
) -> Result<Client, issuerd_core::IssuerdError> {
    let base_url = base_url.trim_end_matches('/');
    Ok(Client {
        id: ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm_id.clone(),
        client_id: ClientIdentifier::new("admin-cli").unwrap(),
        name: Some(DisplayName::new("Admin CLI").unwrap()),
        description: None,
        enabled: true,
        protocol: ClientProtocol::OpenIdConnect,
        public_client: true,
        bearer_only: false,
        client_authenticator_type: ClientAuthenticatorType::ClientSecret,
        secret: None,
        redirect_uris: vec![
            RedirectUri::new(format!("{base_url}/"))?,
            RedirectUri::new(format!("{base_url}/admin/console/callback"))?,
            RedirectUri::new(format!("{base_url}/swagger-ui/oauth2-redirect.html"))?,
        ],
        web_origins: vec![WebOrigin::new(base_url.to_string())?],
        default_scopes: Scope::parse("openid profile"),
        optional_scopes: Scope::parse("email"),
        consent_required: false,
        full_scope_allowed: true,
        service_accounts_enabled: false,
        protocol_mappers: Vec::new(),
        scope_mappings: Default::default(),
        attributes: HashMap::new(),
    })
}

/// Build the default `account-console` client for a realm.
pub fn build_account_console_client(
    realm_id: &issuerd_core::RealmId,
    realm_name: &str,
    base_url: &str,
) -> Result<Client, issuerd_core::IssuerdError> {
    // Normalize the base URL so a trailing slash does not produce double slashes
    // in the generated redirect URIs.
    let base_url = base_url.trim_end_matches('/');
    Ok(Client {
        id: ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm_id.clone(),
        client_id: ClientIdentifier::new("account-console").unwrap(),
        name: Some(DisplayName::new("Account Console").unwrap()),
        description: None,
        enabled: true,
        protocol: ClientProtocol::OpenIdConnect,
        public_client: true,
        bearer_only: false,
        client_authenticator_type: ClientAuthenticatorType::ClientSecret,
        secret: None,
        redirect_uris: vec![
            RedirectUri::new(format!("{base_url}/"))?,
            RedirectUri::new(format!("{base_url}/realms/{realm_name}/account"))?,
        ],
        web_origins: vec![WebOrigin::new(base_url.to_string())?],
        default_scopes: Scope::parse("openid profile"),
        optional_scopes: Scope::parse("email"),
        consent_required: false,
        full_scope_allowed: true,
        service_accounts_enabled: false,
        protocol_mappers: Vec::new(),
        scope_mappings: Default::default(),
        attributes: HashMap::new(),
    })
}

#[utoipa::path(
    get,
    path = "/admin/realms",
    tag = "Realms",
    summary = "List all realms",
    description = "Returns a paginated list of realms visible to the caller. Requires `view-realm` or `manage-realm` role.",
    params(PaginationQueryParams),
    responses(
        (status = 200, description = "List of realms", body = Vec<RealmRepresentation>),
        (status = 401, description = "Unauthorized - missing or invalid bearer token", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden - insufficient realm-management roles", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_realms(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Query(params): axum::extract::Query<PaginationQueryParams>,
) -> Result<Json<Vec<RealmRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realms = state.storage.list_realms(&Pagination::new(params.first, params.max)).await?;
    Ok(Json(realms.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/admin/realms/count",
    tag = "Realms",
    summary = "Count realms",
    description = "Returns the total number of realms. Requires `view-realm` or `manage-realm` role.",
    responses(
        (status = 200, description = "Realm count", body = CountRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn count_realms(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<CountRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let count = state.storage.count_realms().await?;
    Ok(Json(CountRepresentation { count }))
}

#[utoipa::path(
    post,
    path = "/admin/realms",
    tag = "Realms",
    summary = "Create a new realm",
    description = "Creates a realm from the given representation. Requires `manage-realm` role.",
    request_body(description = "Realm representation", content = RealmRepresentation),
    responses(
        (status = 201, description = "Realm created successfully", body = RealmRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Conflict - realm already exists", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth, body), fields(realm = %body.realm))]
pub async fn create_realm(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    Json(body): Json<RealmRepresentation>,
) -> Result<(StatusCode, Json<RealmRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm: issuerd_core::Realm = body.clone().try_into()?;
    state.storage.create_realm(&realm).await?;

    // Auto-provision built-in clients so the account SPA and admin-style
    // logins work for this realm (Keycloak parity).
    let account_client =
        build_account_console_client(&realm.id, realm.name.as_str(), &state.base_url)?;
    if let Err(e) = state.storage.create_client(&realm.id, &account_client).await {
        warn!(realm = %realm.name, client = "account-console", error = %e, "failed to create built-in client");
    }
    let admin_cli = build_admin_cli_client(&realm.id, &state.base_url)?;
    if let Err(e) = state.storage.create_client(&realm.id, &admin_cli).await {
        warn!(realm = %realm.name, client = "admin-cli", error = %e, "failed to create built-in client");
    }

    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Create,
        ResourceType::Realm,
        &format!("realms/{}", realm.name),
        serde_json::to_string(&body).ok(),
    )
    .await;
    info!(realm = %realm.name, "realm created");
    Ok((StatusCode::CREATED, Json(realm.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}",
    tag = "Realms",
    summary = "Get a realm by name",
    description = "Returns the realm representation. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Realm found", body = RealmRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_realm(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<Json<RealmRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    Ok(Json(realm.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}",
    tag = "Realms",
    summary = "Update a realm",
    description = "Updates an existing realm. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Updated realm representation", content = RealmRepresentation),
    responses(
        (status = 204, description = "Realm updated successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_realm(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<RealmRepresentation>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let existing = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let mut updated: issuerd_core::Realm = body.clone().try_into()?;
    updated.id = existing.id.clone();
    // Renaming via PUT is not supported: realm names appear in every URL and
    // issuer. Force the stored name; reject an explicit mismatch (P3-20).
    if updated.name != existing.name {
        return Err(AdminApiError::BadRequest(format!(
            "realm rename is not supported (path realm '{}' != body realm '{}')",
            existing.name, updated.name
        )));
    }
    // The pairwise sector key is server-generated by storage seeding and must
    // survive a full-realm PUT that omits it: losing it hard-fails pairwise
    // issuance until the boot backfill generates a NEW key, silently rotating
    // every pairwise sub in the realm. An explicit value in the
    // body still wins (deliberate rotation). Runs before the name move below —
    // `pairwise_sector_key` borrows all of `existing`.
    if let Some(sector_key) = existing.pairwise_sector_key() {
        updated
            .attributes
            .entry(issuerd_core::Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE.to_string())
            .or_insert_with(|| sector_key.to_string());
    }
    updated.name = existing.name;
    state.storage.update_realm(&updated).await?;
    // Invalidate the cached realm-by-name entry so token endpoints
    // (`resolve_issuer_realm`) see the update immediately (best-effort — the
    // 60 s TTL bounds staleness if the cache is down).
    if let Err(e) = state
        .cache
        .delete(&issuerd_cluster::cache_keys::realm_by_name(updated.name.as_str()))
        .await
    {
        tracing::warn!(realm = %updated.id, error = %e, "realm-by-name cache invalidation failed");
    }
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &existing.id,
        OperationType::Update,
        ResourceType::Realm,
        &format!("realms/{}", realm),
        serde_json::to_string(&body).ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}",
    tag = "Realms",
    summary = "Delete a realm",
    description = "Permanently deletes a realm and all associated data. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 204, description = "Realm deleted successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth), fields(realm = %realm))]
pub async fn delete_realm(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let existing = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    state.storage.delete_realm(&existing.id).await?;
    // Invalidate the cached realm-by-name entry: with the realm gone the
    // issuer must stop resolving so its tokens are immediately invalidated.
    if let Err(e) = state
        .cache
        .delete(&issuerd_cluster::cache_keys::realm_by_name(existing.name.as_str()))
        .await
    {
        tracing::warn!(realm = %existing.id, error = %e, "realm-by-name cache invalidation failed");
    }
    info!(realm = %existing.id, "realm deleted");
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &existing.id,
        OperationType::Delete,
        ResourceType::Realm,
        &format!("realms/{}", realm),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/test-smtp-connection",
    tag = "Realms",
    summary = "Test SMTP connection",
    description = "Sends a test email through the realm's SMTP configuration to the given address, verifying connectivity end to end. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Test email recipient", content = TestSmtpConnectionRequest),
    responses(
        (status = 204, description = "Test email sent successfully"),
        (status = 400, description = "SMTP delivery failed", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn test_smtp_connection(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Json(body): Json<TestSmtpConnectionRequest>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    state
        .email_sender
        .send(
            &realm,
            &body.email,
            "Issuerd SMTP test",
            "plain body",
            Some("<p>html body</p>".to_string()),
        )
        .await
        .map_err(|e| AdminApiError::BadRequest(format!("SMTP test failed: {e}")))?;
    info!(realm = %realm.name, to = %body.email, "SMTP test email sent");
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
        routing::{get, post},
        Router,
    };
    use issuerd_core::{
        AccessTokenClaims, Algorithm, Client, IdTokenClaims, IssuerdError, JwsType, JwtType, KeyId,
        RealmAccess, ValidatedAccessToken,
    };
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

    fn mock_crypto() -> Arc<dyn issuerd_core::CryptoProvider> {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));
        Arc::new(mock)
    }

    fn test_state(roles: Vec<issuerd_core::RoleName>) -> Arc<AdminApiState> {
        test_state_with_email_sender(roles, Arc::new(issuerd_core::MockEmailSender::new()))
    }

    fn test_state_with_email_sender(
        roles: Vec<issuerd_core::RoleName>,
        email_sender: Arc<dyn issuerd_core::EmailSender>,
    ) -> Arc<AdminApiState> {
        Arc::new(AdminApiState {
            storage: crate::test_utils::tests::storage_with_master_realm(),
            token_service: Arc::new(MockTokenService { roles }),
            crypto: mock_crypto(),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender,
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            base_url: "http://localhost:8080".to_string(),
        })
    }

    fn admin_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms", get(list_realms).post(create_realm))
            .route("/admin/realms/{realm}", get(get_realm).put(update_realm).delete(delete_realm))
            .route("/admin/realms/{realm}/test-smtp-connection", post(test_smtp_connection))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn list_realms_requires_auth() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-realm").unwrap()]);
        let app = admin_routes(state);

        // No token → 401
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/admin/realms").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Valid token → 200
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_realm_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"realm":"test","display_name":"Test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[test]
    fn build_account_console_client_normalizes_trailing_slash() {
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();
        let client =
            build_account_console_client(&realm_id, "acme", "http://localhost:8080/").unwrap();
        let redirect_uris: Vec<String> =
            client.redirect_uris.iter().map(|r| r.to_string()).collect();
        assert!(redirect_uris.contains(&"http://localhost:8080/".to_string()));
        assert!(redirect_uris.contains(&"http://localhost:8080/realms/acme/account".to_string()));
        // No double slashes in the path component.
        assert!(!redirect_uris.iter().any(|u| u.replace("://", "").contains("//")));
        assert_eq!(client.web_origins[0].as_str(), "http://localhost:8080");
    }

    #[tokio::test]
    async fn create_realm_creates_account_console_client() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"realm":"acme","display_name":"Acme"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let realm = state.storage.get_realm_by_name("acme").await.unwrap().unwrap();
        let client = state
            .storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("account-console").unwrap())
            .await
            .unwrap();
        assert!(client.is_some(), "account-console client should be auto-created");
        let client = client.unwrap();
        assert!(client.public_client);
        assert_eq!(client.client_id.as_str(), "account-console");
        let redirect_uris: Vec<String> =
            client.redirect_uris.iter().map(|r| r.to_string()).collect();
        assert!(redirect_uris.contains(&"http://localhost:8080/realms/acme/account".to_string()));

        let admin_cli = state
            .storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("admin-cli").unwrap())
            .await
            .unwrap();
        assert!(admin_cli.is_some(), "admin-cli client should be auto-created");
        let admin_cli = admin_cli.unwrap();
        assert!(admin_cli.public_client);
        let redirect_uris: Vec<String> =
            admin_cli.redirect_uris.iter().map(|r| r.to_string()).collect();
        assert!(redirect_uris
            .contains(&"http://localhost:8080/swagger-ui/oauth2-redirect.html".to_string()));
    }

    #[tokio::test]
    async fn get_realm_404() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-realm").unwrap()]);
        let app = admin_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/nonexistent")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_realm_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state.clone());

        // Create realm first
        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                ..Default::default()
            })
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/realms/test")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"realm":"test","display_name":"Updated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn update_realm_preserves_pairwise_sector_key() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state.clone());

        let mut attributes = HashMap::new();
        attributes.insert(
            issuerd_core::Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE.to_string(),
            "sector-key-1".to_string(),
        );
        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                attributes,
                ..Default::default()
            })
            .await
            .unwrap();

        // A full PUT whose body carries no attributes must not drop the
        // server-generated sector key (that would silently rotate every
        // pairwise sub at the next boot backfill).
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/realms/test")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"realm":"test","display_name":"Updated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let realm = state
            .storage
            .get_realm(&issuerd_core::RealmId::new("realm-1").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(realm.pairwise_sector_key(), Some("sector-key-1"));
    }

    #[tokio::test]
    async fn update_realm_explicit_pairwise_sector_key_wins() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state.clone());

        let mut attributes = HashMap::new();
        attributes.insert(
            issuerd_core::Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE.to_string(),
            "sector-key-1".to_string(),
        );
        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                attributes,
                ..Default::default()
            })
            .await
            .unwrap();

        // An explicit value in the PUT body is a deliberate rotation and is
        // kept as-is — the carry-over only fills in a MISSING attribute.
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/realms/test")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"realm":"test","attributes":{"pairwise_sector_key":"rotated-key"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let realm = state
            .storage
            .get_realm(&issuerd_core::RealmId::new("realm-1").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(realm.pairwise_sector_key(), Some("rotated-key"));
    }

    #[tokio::test]
    async fn delete_realm_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state.clone());

        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                ..Default::default()
            })
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/realms/test")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn update_realm_invalidates_realm_by_name_cache() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state.clone());

        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                ..Default::default()
            })
            .await
            .unwrap();

        // Seed the realm-by-name entry `resolve_issuer_realm` populates.
        let key = issuerd_cluster::cache_keys::realm_by_name("test");
        let realm = state.storage.get_realm_by_name("test").await.unwrap().unwrap();
        state.cache.set(&key, serde_json::to_vec(&realm).unwrap(), None).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/realms/test")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"realm":"test","display_name":"Updated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            state.cache.get(&key).await.unwrap().is_none(),
            "realm update invalidated the realm-by-name cache entry"
        );
    }

    #[tokio::test]
    async fn delete_realm_invalidates_realm_by_name_cache() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state.clone());

        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                ..Default::default()
            })
            .await
            .unwrap();

        let key = issuerd_cluster::cache_keys::realm_by_name("test");
        let realm = state.storage.get_realm_by_name("test").await.unwrap().unwrap();
        state.cache.set(&key, serde_json::to_vec(&realm).unwrap(), None).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/realms/test")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            state.cache.get(&key).await.unwrap().is_none(),
            "realm delete invalidated the realm-by-name cache entry"
        );
    }

    #[tokio::test]
    async fn list_realms_returns_data() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-realm").unwrap()]);
        let app = admin_routes(state.clone());

        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                display_name: Some(issuerd_core::DisplayName::new("Test Realm").unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let reps: Vec<RealmRepresentation> = serde_json::from_slice(&body).unwrap();
        // The seeded master realm is listed alongside the test realm.
        assert!(reps.iter().any(|r| r.realm == "master"));
        let test = reps.iter().find(|r| r.realm == "test").expect("test realm listed");
        assert_eq!(test.display_name.as_deref(), Some("Test Realm"));
    }

    #[tokio::test]
    async fn get_realm_success() {
        let state = test_state(vec![issuerd_core::RoleName::new("view-realm").unwrap()]);
        let app = admin_routes(state.clone());

        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                ..Default::default()
            })
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn update_realm_404() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/realms/nonexistent")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"realm":"nonexistent"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_realm_bad_request() {
        let state = test_state(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        let app = admin_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"realm":"test","ssl_required":"invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_smtp_connection_success() {
        let mut sender = issuerd_core::MockEmailSender::new();
        sender
            .expect_send()
            .withf(|_realm, to, subject, text, html| {
                to == "admin@example.com"
                    && subject == "Issuerd SMTP test"
                    && !text.is_empty()
                    && html.is_some()
            })
            .returning(|_, _, _, _, _| Ok(()));
        let state = test_state_with_email_sender(
            vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
            Arc::new(sender),
        );
        let app = admin_routes(state.clone());
        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                ..Default::default()
            })
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/test/test-smtp-connection")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"email":"admin@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_smtp_connection_failure_is_400() {
        let mut sender = issuerd_core::MockEmailSender::new();
        sender.expect_send().returning(|_, _, _, _, _| {
            Err(issuerd_core::IssuerdError::ServerError("connection refused".to_string()))
        });
        let state = test_state_with_email_sender(
            vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
            Arc::new(sender),
        );
        let app = admin_routes(state.clone());
        state
            .storage
            .create_realm(&issuerd_core::Realm {
                id: issuerd_core::RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test").unwrap(),
                ..Default::default()
            })
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/realms/test/test-smtp-connection")
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"email":"admin@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json
            .get("errorMessage")
            .and_then(|m| m.as_str())
            .is_some_and(|m| m.contains("SMTP test failed")));
    }
}
