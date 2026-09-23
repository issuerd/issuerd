// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// User federation endpoints: trigger synchronization from external providers.

use axum::{
    extract::{Extension, State},
    Json,
};
use chrono::Utc;
use issuerd_core::{OperationType, ResourceType};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    error::AdminApiError,
    state::AdminApiState,
};

/// `IdentityProviderConfig.config` key holding the RFC 3339 watermark of the
/// last successful federation sync (same key name Keycloak uses).
const LAST_SYNC_CONFIG_KEY: &str = "lastSyncTime";

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/user-federation/{provider_id}/sync",
    tag = "User Federation",
    summary = "Trigger user federation sync",
    description = "Synchronises users from an external federation provider into local storage. Requires `manage-realm` or `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("provider_id" = String, Path, description = "Federation provider alias or id"),
        ("strategy" = Option<String>, Query, description = "Sync strategy: `full` (default) or `incremental`"),
    ),
    responses(
        (status = 200, description = "Sync result", body = crate::dto::SyncResultRepresentation),
        (status = 400, description = "Bad request", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or provider not found", body = crate::error::AdminApiErrorResponse),
        (status = 501, description = "Provider does not support incremental sync", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn sync_users(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, provider_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<crate::dto::SyncResultRepresentation>, AdminApiError> {
    require_roles(&auth, &["manage-realm", "manage-users"])?;

    let realm_id = state
        .storage
        .get_realm_by_name(&realm)
        .await?
        .ok_or(AdminApiError::NotFound)?
        .id;

    // Resolve provider by id or alias (API accepts either).
    let idps = state
        .storage
        .list_identity_providers(&realm_id)
        .await
        .map_err(|e| AdminApiError::Internal(anyhow::anyhow!("{e}")))?;
    let matched_config = idps
        .into_iter()
        .find(|idp| idp.id.as_ref() == provider_id || idp.alias.as_ref() == provider_id.as_str())
        .ok_or(AdminApiError::NotFound)?;

    let providers = state
        .federation_manager
        .providers_for_realm(&realm_id)
        .await
        .map_err(|e| AdminApiError::Internal(anyhow::anyhow!("{e}")))?;

    let provider = providers
        .into_iter()
        .find(|p| p.id() == matched_config.id.as_ref())
        .ok_or(AdminApiError::NotFound)?;

    let synchronizer = issuerd_federation::sync::UserSynchronizer::new(
        provider.as_ref(),
        state.storage.clone(),
        realm_id.clone(),
    );

    let result = if params.get("strategy").map(|s| s.as_str()) == Some("incremental") {
        // Use the watermark persisted by the previous successful sync; a
        // missing watermark means "never synced", so sync since the epoch.
        let since = matched_config
            .config
            .get(LAST_SYNC_CONFIG_KEY)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map_or_else(chrono::DateTime::<Utc>::default, |dt| dt.with_timezone(&Utc));
        synchronizer.sync_since(since).await?
    } else {
        synchronizer.sync_all().await?
    };
    issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;

    // Persist the sync watermark so the next incremental run resumes from it.
    let mut updated_config = matched_config.clone();
    updated_config
        .config
        .insert(LAST_SYNC_CONFIG_KEY.to_string(), result.last_sync.to_rfc3339());
    state.storage.update_identity_provider(&realm_id, &updated_config).await?;

    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm_id,
        OperationType::Action,
        ResourceType::UserFederation,
        &format!("user-federation/{provider_id}/sync"),
        None,
    )
    .await;

    Ok(Json(result.into()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::MockTokenService;
    use axum::extract::{Extension, Query, State};
    use issuerd_core::{
        AccessTokenClaims, Audience, DisplayName, FederatedUser, FederationError,
        FederationProvider, FederationProviderType, IdentityProviderConfig, Issuer, JwtId, JwtType,
        Realm, RealmAccess, RealmId, RealmName, RoleName, Storage, SyncResult, UserId,
    };
    use std::sync::Arc;

    struct MockProvider {
        pub id: String,
    }

    #[async_trait::async_trait]
    impl FederationProvider for MockProvider {
        fn id(&self) -> &str {
            &self.id
        }
        fn provider_type(&self) -> FederationProviderType {
            FederationProviderType::Ldap
        }
        async fn find_user(
            &self,
            _username: &str,
        ) -> Result<Option<FederatedUser>, FederationError> {
            Ok(None)
        }
        async fn find_user_by_email(
            &self,
            _email: &str,
        ) -> Result<Option<FederatedUser>, FederationError> {
            Ok(None)
        }
        async fn validate_password(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<bool, FederationError> {
            Ok(false)
        }
        async fn stream_users(&self) -> Result<Vec<FederatedUser>, FederationError> {
            Ok(vec![FederatedUser {
                username: "fed-user".to_string(),
                email: Some("fed@example.com".to_string()),
                email_verified: true,
                first_name: DisplayName::new("Fed").ok(),
                last_name: DisplayName::new("User").ok(),
                enabled: true,
                federation_link: "mock-ldap".to_string(),
                attributes: std::collections::HashMap::new(),
                external_id: None,
                groups: None,
            }])
        }
        async fn sync_users_since(
            &self,
            _since: chrono::DateTime<Utc>,
        ) -> Result<SyncResult, FederationError> {
            Ok(SyncResult {
                added: 2,
                updated: 1,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })
        }
    }

    /// Provider without an incremental-sync override (default: `NotSupported`).
    struct FullOnlyProvider;

    #[async_trait::async_trait]
    impl FederationProvider for FullOnlyProvider {
        fn id(&self) -> &str {
            "idp-1"
        }
        fn provider_type(&self) -> FederationProviderType {
            FederationProviderType::Ldap
        }
        async fn find_user(
            &self,
            _username: &str,
        ) -> Result<Option<FederatedUser>, FederationError> {
            Ok(None)
        }
        async fn find_user_by_email(
            &self,
            _email: &str,
        ) -> Result<Option<FederatedUser>, FederationError> {
            Ok(None)
        }
        async fn validate_password(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<bool, FederationError> {
            Ok(false)
        }
        async fn stream_users(&self) -> Result<Vec<FederatedUser>, FederationError> {
            Ok(vec![])
        }
    }

    struct MockFederationManager {
        provider: Arc<dyn FederationProvider>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationManager for MockFederationManager {
        async fn providers_for_realm(
            &self,
            _realm_id: &RealmId,
        ) -> Result<Vec<Arc<dyn FederationProvider>>, issuerd_core::IssuerdError> {
            Ok(vec![self.provider.clone()])
        }
        async fn find_user(
            &self,
            _realm_id: &RealmId,
            _username: &str,
        ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, issuerd_core::IssuerdError>
        {
            Ok(None)
        }
        async fn find_user_by_email(
            &self,
            _realm_id: &RealmId,
            _email: &str,
        ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, issuerd_core::IssuerdError>
        {
            Ok(None)
        }
    }

    fn admin_auth() -> AdminAuth {
        AdminAuth {
            claims: AccessTokenClaims {
                jti: JwtId::new("jti").unwrap(),
                iss: Issuer::new("https://iss").unwrap(),
                sub: UserId::new("admin").unwrap(),
                aud: Audience::new("aud").unwrap(),
                exp: 9999999999,
                iat: 0,
                nbf: 0,
                scope: issuerd_core::Scope::parse("openid"),
                typ: JwtType::Bearer,
                azp: Some("admin-cli".to_string()),
                session_state: None,
                realm_access: Some(RealmAccess {
                    roles: vec![RoleName::new("manage-realm").unwrap()],
                }),
                resource_access: None,
                sid: None,
                claims: None,
                cnf: None,
                authorization_details: None,
            },
        }
    }

    async fn state_with_mock_federation() -> Arc<AdminApiState> {
        state_with_provider(Arc::new(MockProvider {
            id: "idp-1".to_string(),
        }))
        .await
    }

    async fn state_with_provider(provider: Arc<dyn FederationProvider>) -> Arc<AdminApiState> {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));

        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let realm = Realm {
            id: RealmId::new("realm-1").unwrap(),
            name: RealmName::new("test").unwrap(),
            display_name: None,
            enabled: true,
            ssl_required: issuerd_core::SslRequired::External,
            password_policy: issuerd_core::PasswordPolicy::default(),
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            default_role: None,
            access_token_lifespan: issuerd_core::SecondsNonZero::new(300),
            refresh_token_lifespan: issuerd_core::SecondsNonZero::new(1800),
            sso_session_idle_timeout: issuerd_core::SecondsNonZero::new(1800),
            sso_session_max_lifespan: issuerd_core::SecondsNonZero::new(36000),
            offline_session_idle_timeout: issuerd_core::SecondsNonZero::new(2592000),
            attributes: std::collections::HashMap::new(),
            ..Default::default()
        };
        storage.create_realm(&realm).await.unwrap();

        let idp = IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("idp-1").unwrap(),
            alias: issuerd_core::Alias::new("mock-ldap").unwrap(),
            provider_id: issuerd_core::ProviderId::new("ldap"),
            enabled: true,
            config: std::collections::HashMap::new(),
        };
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();

        Arc::new(AdminApiState {
            storage,
            token_service: Arc::new(MockTokenService {
                roles: vec![RoleName::new("manage-realm").unwrap()],
            }),
            crypto: Arc::new(mock),
            federation_manager: Arc::new(MockFederationManager { provider }),
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

    #[tokio::test]
    async fn sync_users_full_success() {
        let state = state_with_mock_federation().await;
        let result = sync_users(
            State(state.clone()),
            Extension(admin_auth()),
            axum::extract::Path(("test".to_string(), "mock-ldap".to_string())),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert!(result.is_ok());
        let json = result.unwrap().0;
        assert_eq!(json.added, 1);
    }

    #[tokio::test]
    async fn sync_users_incremental_success() {
        let state = state_with_mock_federation().await;

        // A full sync establishes the persisted watermark.
        let full = sync_users(
            State(state.clone()),
            Extension(admin_auth()),
            axum::extract::Path(("test".to_string(), "mock-ldap".to_string())),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert!(full.is_ok());
        let stored = state
            .storage
            .get_identity_provider(
                &RealmId::new("realm-1").unwrap(),
                &issuerd_core::IdentityProviderId::new("idp-1").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(stored.config.contains_key(LAST_SYNC_CONFIG_KEY));

        // The incremental sync resumes from the persisted watermark.
        let mut params = std::collections::HashMap::new();
        params.insert("strategy".to_string(), "incremental".to_string());
        let result = sync_users(
            State(state.clone()),
            Extension(admin_auth()),
            axum::extract::Path(("test".to_string(), "mock-ldap".to_string())),
            Query(params),
        )
        .await;
        let json = result.expect("incremental sync should succeed").0;
        assert_eq!(json.added, 2);
        assert_eq!(json.updated, 1);
    }

    #[tokio::test]
    async fn sync_users_incremental_unsupported_returns_501() {
        let state = state_with_provider(Arc::new(FullOnlyProvider)).await;
        let mut params = std::collections::HashMap::new();
        params.insert("strategy".to_string(), "incremental".to_string());
        let result = sync_users(
            State(state),
            Extension(admin_auth()),
            axum::extract::Path(("test".to_string(), "mock-ldap".to_string())),
            Query(params),
        )
        .await;
        assert!(matches!(result, Err(AdminApiError::NotImplemented(_))));
    }

    fn auth_with_roles(roles: Vec<RoleName>) -> AdminAuth {
        AdminAuth {
            claims: AccessTokenClaims {
                jti: JwtId::new("jti").unwrap(),
                iss: Issuer::new("https://iss").unwrap(),
                sub: UserId::new("admin").unwrap(),
                aud: Audience::new("aud").unwrap(),
                exp: 9999999999,
                iat: 0,
                nbf: 0,
                scope: issuerd_core::Scope::parse("openid"),
                typ: JwtType::Bearer,
                azp: Some("admin-cli".to_string()),
                session_state: None,
                realm_access: Some(RealmAccess { roles }),
                resource_access: None,
                sid: None,
                claims: None,
                cnf: None,
                authorization_details: None,
            },
        }
    }

    #[tokio::test]
    async fn sync_users_forbidden_without_role() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));
        let state = Arc::new(AdminApiState {
            storage: Arc::new(issuerd_storage::InMemoryStorage::new()),
            token_service: Arc::new(MockTokenService { roles: vec![] }),
            crypto: Arc::new(mock),
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
        });
        let result = sync_users(
            State(state),
            Extension(auth_with_roles(vec![])),
            axum::extract::Path(("test".to_string(), "mock-ldap".to_string())),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert!(matches!(result, Err(AdminApiError::Forbidden)));
    }

    #[tokio::test]
    async fn sync_users_realm_not_found() {
        let state = state_with_mock_federation().await;
        let result = sync_users(
            State(state.clone()),
            Extension(admin_auth()),
            axum::extract::Path(("nonexistent".to_string(), "mock-ldap".to_string())),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert!(matches!(result, Err(AdminApiError::NotFound)));
    }

    #[tokio::test]
    async fn sync_users_provider_not_found() {
        let state = state_with_mock_federation().await;
        let result = sync_users(
            State(state.clone()),
            Extension(admin_auth()),
            axum::extract::Path(("test".to_string(), "nonexistent".to_string())),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert!(matches!(result, Err(AdminApiError::NotFound)));
    }

    #[tokio::test]
    async fn sync_users_list_identity_providers_error() {
        let mut mock_storage = issuerd_core::MockStorage::new();
        mock_storage.expect_get_realm_by_name().returning(|name| {
            Ok(Some(Realm {
                id: RealmId::new("realm-1").unwrap(),
                name: RealmName::new(name).unwrap(),
                display_name: None,
                enabled: true,
                ssl_required: issuerd_core::SslRequired::External,
                password_policy: issuerd_core::PasswordPolicy::default(),
                login_theme: None,
                email_theme: None,
                admin_theme: None,
                default_role: None,
                access_token_lifespan: issuerd_core::SecondsNonZero::new(300),
                refresh_token_lifespan: issuerd_core::SecondsNonZero::new(1800),
                sso_session_idle_timeout: issuerd_core::SecondsNonZero::new(1800),
                sso_session_max_lifespan: issuerd_core::SecondsNonZero::new(36000),
                offline_session_idle_timeout: issuerd_core::SecondsNonZero::new(2592000),
                attributes: std::collections::HashMap::new(),
                ..Default::default()
            }))
        });
        mock_storage
            .expect_list_identity_providers()
            .returning(|_| Err(issuerd_core::IssuerdError::ServerError("db down".into())));

        let mut mock_crypto = issuerd_core::MockCryptoProvider::new();
        mock_crypto
            .expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));

        let state = Arc::new(AdminApiState {
            storage: Arc::new(mock_storage),
            token_service: Arc::new(MockTokenService {
                roles: vec![RoleName::new("manage-realm").unwrap()],
            }),
            crypto: Arc::new(mock_crypto),
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
        });

        let result = sync_users(
            State(state),
            Extension(admin_auth()),
            axum::extract::Path(("test".to_string(), "mock-ldap".to_string())),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert!(matches!(result, Err(AdminApiError::Internal(_))));
    }

    struct ErrorFederationManager;

    #[async_trait::async_trait]
    impl issuerd_core::FederationManager for ErrorFederationManager {
        async fn providers_for_realm(
            &self,
            _realm_id: &RealmId,
        ) -> Result<Vec<Arc<dyn FederationProvider>>, issuerd_core::IssuerdError> {
            Err(issuerd_core::IssuerdError::ServerError("fed down".into()))
        }
        async fn find_user(
            &self,
            _realm_id: &RealmId,
            _username: &str,
        ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, issuerd_core::IssuerdError>
        {
            Ok(None)
        }
        async fn find_user_by_email(
            &self,
            _realm_id: &RealmId,
            _email: &str,
        ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, issuerd_core::IssuerdError>
        {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn sync_users_providers_for_realm_error() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let realm = Realm {
            id: RealmId::new("realm-1").unwrap(),
            name: RealmName::new("test").unwrap(),
            display_name: None,
            enabled: true,
            ssl_required: issuerd_core::SslRequired::External,
            password_policy: issuerd_core::PasswordPolicy::default(),
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            default_role: None,
            access_token_lifespan: issuerd_core::SecondsNonZero::new(300),
            refresh_token_lifespan: issuerd_core::SecondsNonZero::new(1800),
            sso_session_idle_timeout: issuerd_core::SecondsNonZero::new(1800),
            sso_session_max_lifespan: issuerd_core::SecondsNonZero::new(36000),
            offline_session_idle_timeout: issuerd_core::SecondsNonZero::new(2592000),
            attributes: std::collections::HashMap::new(),
            ..Default::default()
        };
        storage.create_realm(&realm).await.unwrap();

        let idp = IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("idp-1").unwrap(),
            alias: issuerd_core::Alias::new("mock-ldap").unwrap(),
            provider_id: issuerd_core::ProviderId::new("ldap"),
            enabled: true,
            config: std::collections::HashMap::new(),
        };
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();

        let mut mock_crypto = issuerd_core::MockCryptoProvider::new();
        mock_crypto
            .expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));

        let state = Arc::new(AdminApiState {
            storage,
            token_service: Arc::new(MockTokenService {
                roles: vec![RoleName::new("manage-realm").unwrap()],
            }),
            crypto: Arc::new(mock_crypto),
            federation_manager: Arc::new(ErrorFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender: Arc::new(issuerd_core::MockEmailSender::new()),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            base_url: "http://localhost:8080".to_string(),
        });

        let result = sync_users(
            State(state),
            Extension(admin_auth()),
            axum::extract::Path(("test".to_string(), "mock-ldap".to_string())),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert!(matches!(result, Err(AdminApiError::Internal(_))));
    }
}
