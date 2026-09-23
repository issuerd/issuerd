// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// User synchronisation from a federation provider into local storage.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use issuerd_core::{
    DisplayName, Email, FederationError, FederationProvider, IssuerdError, Pagination, RealmId,
    Storage, SyncResult, User, UserId, Username,
};

/// Cap on per-record WARN lines emitted during a sync run: the first
/// failures are logged with full detail, the rest only count toward the
/// end-of-sync summary (one systematic failure must not produce 100k lines).
const MAX_DETAILED_FAILURE_LOGS: usize = 10;

/// Orchestrates user synchronisation from a federation provider into local
/// `Storage`.
pub struct UserSynchronizer<'a> {
    provider: &'a dyn FederationProvider,
    storage: Arc<dyn Storage>,
    realm_id: RealmId,
}

impl<'a> UserSynchronizer<'a> {
    pub fn new(
        provider: &'a dyn FederationProvider,
        storage: Arc<dyn Storage>,
        realm_id: RealmId,
    ) -> Self {
        Self {
            provider,
            storage,
            realm_id,
        }
    }

    /// Trigger a full synchronisation.
    pub async fn sync_all(&self) -> Result<SyncResult, IssuerdError> {
        tracing::info!(realm = %self.realm_id, "federation user sync started");
        let users = self
            .provider
            .stream_users()
            .await
            .map_err(|e| IssuerdError::ServerError(e.to_string()))?;
        let mut result = SyncResult {
            added: 0,
            updated: 0,
            removed: 0,
            failed: 0,
            last_sync: Utc::now(),
        };
        let mut detailed_failure_logs = 0usize;

        // Pre-fetch existing users to avoid N+1 SELECT queries.
        let existing = self.load_existing_users().await?;
        let mut to_add: Vec<(User, Option<Vec<String>>)> = Vec::new();
        let mut to_update: Vec<(User, Option<Vec<String>>)> = Vec::new();

        for fed in users {
            if let Some(local) = existing.get(&fed.username) {
                if local.federation_link.as_deref() == Some(&fed.federation_link) {
                    let mut updated = local.clone();
                    updated.email =
                        fed.email.as_deref().map(Email::new).transpose().unwrap_or(None);
                    updated.email_verified = fed.email_verified;
                    updated.first_name =
                        fed.first_name.as_deref().and_then(|s| DisplayName::new(s).ok());
                    updated.last_name =
                        fed.last_name.as_deref().and_then(|s| DisplayName::new(s).ok());
                    updated.enabled = fed.enabled;
                    updated.attributes = fed.attributes.clone();
                    to_update.push((updated, fed.groups));
                } else {
                    result.failed += 1;
                    if detailed_failure_logs < MAX_DETAILED_FAILURE_LOGS {
                        detailed_failure_logs += 1;
                        tracing::warn!(
                            username = %issuerd_core::utils::sanitize_log_str(&fed.username),
                            "sync upsert failed: username conflicts with non-federated user"
                        );
                    }
                }
            } else {
                to_add.push((
                    User {
                        id: UserId::new(issuerd_core::utils::generate_id()).unwrap(),
                        realm_id: self.realm_id.clone(),
                        username: Username::new(&fed.username)
                            .expect("federated username must be valid"),
                        email: fed.email.as_deref().map(Email::new).transpose().unwrap_or(None),
                        email_verified: fed.email_verified,
                        first_name: fed
                            .first_name
                            .as_deref()
                            .and_then(|s| DisplayName::new(s).ok()),
                        last_name: fed.last_name.as_deref().and_then(|s| DisplayName::new(s).ok()),
                        enabled: fed.enabled,
                        federation_link: Some(fed.federation_link.clone()),
                        attributes: fed.attributes.clone(),
                        required_actions: Vec::new(),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    },
                    fed.groups,
                ));
            }
        }

        // Batch insert new users.
        const BATCH_SIZE: usize = 1000;
        let mut synced: Vec<(UserId, Option<Vec<String>>)> = Vec::new();
        for chunk in to_add.chunks(BATCH_SIZE) {
            let chunk_users: Vec<User> = chunk.iter().map(|(u, _)| u.clone()).collect();
            if let Err(e) = self.storage.bulk_create_users(&self.realm_id, &chunk_users).await {
                tracing::warn!(error = %e, "bulk_create_users failed for batch");
                // Fall back to individual inserts for this batch.
                for (user, groups) in chunk {
                    if let Err(e) = self.storage.create_user(&self.realm_id, user).await {
                        result.failed += 1;
                        if detailed_failure_logs < MAX_DETAILED_FAILURE_LOGS {
                            detailed_failure_logs += 1;
                            tracing::warn!(
                                username = %user.username,
                                error = %e,
                                "sync create failed"
                            );
                        }
                    } else {
                        result.added += 1;
                        synced.push((user.id.clone(), groups.clone()));
                    }
                }
            } else {
                result.added += chunk.len();
                synced.extend(chunk.iter().map(|(u, g)| (u.id.clone(), g.clone())));
            }
        }

        // Update existing users.
        for (user, groups) in to_update {
            if let Err(e) = self.storage.update_user(&self.realm_id, &user).await {
                result.failed += 1;
                if detailed_failure_logs < MAX_DETAILED_FAILURE_LOGS {
                    detailed_failure_logs += 1;
                    tracing::warn!(username = %user.username, error = %e, "sync update failed");
                }
            } else {
                result.updated += 1;
                synced.push((user.id.clone(), groups));
            }
        }

        // Reconcile external (LDAP) group memberships for every synced user.
        self.reconcile_groups(&synced).await;

        result.last_sync = Utc::now();
        tracing::info!(
            realm = %self.realm_id,
            added = result.added,
            updated = result.updated,
            removed = result.removed,
            failed = result.failed,
            "federation user sync completed"
        );
        Ok(result)
    }

    /// Apply `FederatedUser.groups` to local group memberships via
    /// [`issuerd_core::roles::reconcile_group_memberships_indexed`]. Users whose
    /// provider does not report groups (`None`) are skipped — "not reported"
    /// must never wipe memberships. Failures are logged and counted, never
    /// abort the sync run.
    async fn reconcile_groups(&self, synced: &[(UserId, Option<Vec<String>>)]) {
        if synced.iter().all(|(_, groups)| groups.is_none()) {
            return;
        }
        // Shared realm-group index: avoids per-user lookups for the same
        // groups (the N+1 the batching above was designed to avoid).
        let mut index = match issuerd_core::roles::GroupIndex::load(
            self.storage.as_ref(),
            &self.realm_id,
        )
        .await
        {
            Ok(index) => index,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "group index preload failed; per-user lookups instead"
                );
                issuerd_core::roles::GroupIndex::default()
            }
        };
        let mut totals = issuerd_core::roles::GroupReconcileResult::default();
        let mut failed = 0usize;
        let mut detailed_failure_logs = 0usize;
        for (user_id, groups) in synced {
            let Some(groups) = groups else {
                continue;
            };
            match issuerd_core::roles::reconcile_group_memberships_indexed(
                self.storage.as_ref(),
                &self.realm_id,
                user_id,
                groups,
                &mut index,
            )
            .await
            {
                Ok(r) => {
                    totals.added += r.added;
                    totals.removed += r.removed;
                    totals.created_groups += r.created_groups;
                    totals.adopted_groups += r.adopted_groups;
                    totals.skipped += r.skipped;
                }
                Err(e) => {
                    failed += 1;
                    if detailed_failure_logs < MAX_DETAILED_FAILURE_LOGS {
                        detailed_failure_logs += 1;
                        tracing::warn!(
                            user_id = %user_id,
                            error = %e,
                            "group membership reconcile failed"
                        );
                    }
                }
            }
        }
        if totals.added > 0
            || totals.removed > 0
            || totals.created_groups > 0
            || totals.adopted_groups > 0
            || totals.skipped > 0
            || failed > 0
        {
            tracing::info!(
                memberships_added = totals.added,
                memberships_removed = totals.removed,
                groups_created = totals.created_groups,
                groups_adopted = totals.adopted_groups,
                names_skipped = totals.skipped,
                reconcile_failed = failed,
                "LDAP group sync reconciled"
            );
        }
    }

    /// Trigger an incremental synchronisation.
    ///
    /// Providers that do not implement incremental sync yield
    /// [`IssuerdError::UnsupportedOperation`] instead of a generic server error.
    pub async fn sync_since(&self, since: DateTime<Utc>) -> Result<SyncResult, IssuerdError> {
        self.provider.sync_users_since(since).await.map_err(|e| match e {
            FederationError::NotSupported => IssuerdError::UnsupportedOperation,
            other => IssuerdError::ServerError(other.to_string()),
        })
    }

    async fn load_existing_users(&self) -> Result<HashMap<String, User>, IssuerdError> {
        let mut map = HashMap::new();
        let mut page = Pagination {
            first: 0,
            max: 1000,
        };
        loop {
            let batch = self.storage.list_users(&self.realm_id, "", &page).await?;
            if batch.is_empty() {
                break;
            }
            for user in batch {
                map.insert(user.username.to_string(), user);
            }
            page.first += page.max;
        }
        Ok(map)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use issuerd_core::{
        FederatedUser, FederationError, FederationProviderType, RealmId, SyncResult,
    };
    use std::collections::HashMap;

    struct MockProvider {
        users: Mutex<Vec<FederatedUser>>,
        sync_since_result: Mutex<Result<SyncResult, FederationError>>,
    }

    #[async_trait::async_trait]
    impl FederationProvider for MockProvider {
        fn id(&self) -> &str {
            "mock"
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
            Ok(self.users.lock().unwrap().clone())
        }
        async fn sync_users_since(
            &self,
            _since: DateTime<Utc>,
        ) -> Result<SyncResult, FederationError> {
            self.sync_since_result.lock().unwrap().clone()
        }
    }

    fn mock_storage() -> Arc<dyn Storage> {
        Arc::new(issuerd_storage::InMemoryStorage::default())
    }

    #[tokio::test]
    async fn sync_all_empty() {
        let provider = MockProvider {
            users: Mutex::new(vec![]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let sync = UserSynchronizer::new(&provider, mock_storage(), RealmId::new("test").unwrap());
        let result = sync.sync_all().await.unwrap();
        assert_eq!(result.added, 0);
    }

    #[tokio::test]
    async fn sync_all_counts() {
        let provider = MockProvider {
            users: Mutex::new(vec![
                FederatedUser {
                    username: "alice".to_string(),
                    federation_link: "mock".to_string(),
                    enabled: true,
                    ..Default::default()
                },
                FederatedUser {
                    username: "bob".to_string(),
                    federation_link: "mock".to_string(),
                    enabled: true,
                    ..Default::default()
                },
            ]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let sync = UserSynchronizer::new(&provider, mock_storage(), RealmId::new("test").unwrap());
        let result = sync.sync_all().await.unwrap();
        assert_eq!(result.added, 2);
        assert_eq!(result.updated, 0);
        assert_eq!(result.removed, 0);
    }

    #[tokio::test]
    async fn sync_since_not_supported() {
        let provider = MockProvider {
            users: Mutex::new(vec![]),
            sync_since_result: Mutex::new(Err(FederationError::NotSupported)),
        };
        let sync = UserSynchronizer::new(&provider, mock_storage(), RealmId::new("test").unwrap());
        let err = sync.sync_since(Utc::now()).await.unwrap_err();
        assert!(matches!(err, IssuerdError::UnsupportedOperation));
    }

    #[tokio::test]
    async fn sync_since_success() {
        let provider = MockProvider {
            users: Mutex::new(vec![]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 5,
                updated: 3,
                removed: 1,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let sync = UserSynchronizer::new(&provider, mock_storage(), RealmId::new("test").unwrap());
        let result = sync.sync_since(Utc::now()).await.unwrap();
        assert_eq!(result.added, 5);
        assert_eq!(result.updated, 3);
        assert_eq!(result.removed, 1);
    }

    #[tokio::test]
    async fn sync_all_updates_existing_user() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let realm = RealmId::new("test").unwrap();
        let existing = User {
            id: UserId::new("u1").unwrap(),
            realm_id: realm.clone(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("old@example.com").unwrap()),
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: Some("mock".to_string()),
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        storage.create_user(&realm, &existing).await.unwrap();

        let provider = MockProvider {
            users: Mutex::new(vec![FederatedUser {
                username: "alice".to_string(),
                federation_link: "mock".to_string(),
                email: Some("new@example.com".to_string()),
                email_verified: true,
                first_name: Some(issuerd_core::DisplayName::new("Alice").unwrap()),
                last_name: Some(issuerd_core::DisplayName::new("Smith").unwrap()),
                enabled: true,
                external_id: None,
                attributes: HashMap::new(),
                groups: None,
            }]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let sync = UserSynchronizer::new(&provider, storage.clone(), realm.clone());
        let result = sync.sync_all().await.unwrap();
        assert_eq!(result.updated, 1);
        assert_eq!(result.added, 0);

        let user = storage.get_user_by_username(&realm, "alice").await.unwrap().unwrap();
        assert_eq!(user.email, Some(Email::new("new@example.com").unwrap()));
        assert_eq!(user.first_name, Some(DisplayName::new("Alice").unwrap()));
    }

    #[tokio::test]
    async fn sync_all_skips_conflict() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let realm = RealmId::new("test").unwrap();
        let existing = User {
            id: UserId::new("u1").unwrap(),
            realm_id: realm.clone(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("old@example.com").unwrap()),
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None, // local user, not federated
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        storage.create_user(&realm, &existing).await.unwrap();

        let provider = MockProvider {
            users: Mutex::new(vec![FederatedUser {
                username: "alice".to_string(),
                federation_link: "mock".to_string(),
                email: Some("new@example.com".to_string()),
                email_verified: true,
                first_name: None,
                last_name: None,
                enabled: true,
                external_id: None,
                attributes: HashMap::new(),
                groups: None,
            }]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let sync = UserSynchronizer::new(&provider, storage.clone(), realm.clone());
        let result = sync.sync_all().await.unwrap();
        assert_eq!(result.failed, 1);
        assert_eq!(result.added, 0);
        assert_eq!(result.updated, 0);
    }

    #[tokio::test]
    async fn sync_all_bulk_create_fallback_and_individual_failures() {
        let realm = RealmId::new("test").unwrap();
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_list_users().returning(|_, _, _| Ok(vec![]));
        mock.expect_list_user_groups().returning(|_, _| Ok(vec![]));
        // bulk_create_users always fails.
        mock.expect_bulk_create_users()
            .returning(|_, _| Err(issuerd_core::IssuerdError::ServerError("batch fail".into())));
        // create_user succeeds for alice, fails for bob.
        mock.expect_create_user().times(2).returning(|_, user| {
            if user.username == "alice" {
                Ok(())
            } else {
                Err(issuerd_core::IssuerdError::ServerError("create fail".into()))
            }
        });

        let provider = MockProvider {
            users: Mutex::new(vec![
                FederatedUser {
                    username: "alice".to_string(),
                    federation_link: "mock".to_string(),
                    enabled: true,
                    ..Default::default()
                },
                FederatedUser {
                    username: "bob".to_string(),
                    federation_link: "mock".to_string(),
                    enabled: true,
                    ..Default::default()
                },
            ]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let sync = UserSynchronizer::new(&provider, Arc::new(mock), realm.clone());
        let result = sync.sync_all().await.unwrap();
        assert_eq!(result.added, 1);
        assert_eq!(result.failed, 1);
    }

    #[tokio::test]
    async fn sync_all_update_user_failure_counts_as_failed() {
        let realm = RealmId::new("test").unwrap();
        let mut mock = issuerd_core::MockStorage::new();
        // list_users returns the existing user once, then empty.
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cc = call_count.clone();
        mock.expect_list_users().returning(move |_, _, _| {
            if cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok(vec![User {
                    id: UserId::new("u1").unwrap(),
                    realm_id: RealmId::new("test").unwrap(),
                    username: Username::new("alice").unwrap(),
                    email: None,
                    email_verified: false,
                    first_name: None,
                    last_name: None,
                    enabled: true,
                    federation_link: Some("mock".to_string()),
                    attributes: HashMap::new(),
                    required_actions: Vec::new(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }])
            } else {
                Ok(vec![])
            }
        });
        // update_user fails.
        mock.expect_update_user()
            .returning(|_, _| Err(issuerd_core::IssuerdError::ServerError("update fail".into())));

        let provider = MockProvider {
            users: Mutex::new(vec![FederatedUser {
                username: "alice".to_string(),
                federation_link: "mock".to_string(),
                email: Some("new@example.com".to_string()),
                email_verified: true,
                first_name: None,
                last_name: None,
                enabled: true,
                external_id: None,
                attributes: HashMap::new(),
                groups: None,
            }]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let sync = UserSynchronizer::new(&provider, Arc::new(mock), realm.clone());
        let result = sync.sync_all().await.unwrap();
        assert_eq!(result.updated, 0);
        assert_eq!(result.failed, 1);
    }

    #[tokio::test]
    async fn sync_all_stream_users_error() {
        struct FailingProvider;
        #[async_trait::async_trait]
        impl FederationProvider for FailingProvider {
            fn id(&self) -> &str {
                "fail"
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
                Err(FederationError::NetworkError("ldap down".into()))
            }
            async fn sync_users_since(
                &self,
                _since: DateTime<Utc>,
            ) -> Result<SyncResult, FederationError> {
                Ok(SyncResult {
                    added: 0,
                    updated: 0,
                    removed: 0,
                    failed: 0,
                    last_sync: Utc::now(),
                })
            }
        }
        let provider = FailingProvider;
        let sync = UserSynchronizer::new(&provider, mock_storage(), RealmId::new("test").unwrap());
        let err = sync.sync_all().await.unwrap_err();
        assert!(matches!(err, IssuerdError::ServerError(_)));
    }

    #[tokio::test]
    async fn sync_all_add_user_with_all_fields() {
        let provider = MockProvider {
            users: Mutex::new(vec![FederatedUser {
                username: "alice".to_string(),
                federation_link: "mock".to_string(),
                email: Some("alice@example.com".to_string()),
                email_verified: true,
                first_name: Some(DisplayName::new("Alice").unwrap()),
                last_name: Some(DisplayName::new("Smith").unwrap()),
                enabled: true,
                external_id: Some("ext-123".to_string()),
                attributes: {
                    let mut m = HashMap::new();
                    m.insert("dept".to_string(), vec!["engineering".to_string()]);
                    m
                },
                groups: None,
            }]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let storage = mock_storage();
        let realm = RealmId::new("test").unwrap();
        let sync = UserSynchronizer::new(&provider, storage.clone(), realm.clone());
        let result = sync.sync_all().await.unwrap();
        assert_eq!(result.added, 1);
        assert_eq!(result.failed, 0);

        let user = storage.get_user_by_username(&realm, "alice").await.unwrap().unwrap();
        assert_eq!(user.email, Some(Email::new("alice@example.com").unwrap()));
        assert_eq!(user.first_name, Some(DisplayName::new("Alice").unwrap()));
        assert_eq!(user.last_name, Some(DisplayName::new("Smith").unwrap()));
        assert!(user.email_verified);
        assert_eq!(user.attributes.get("dept"), Some(&vec!["engineering".to_string()]));
    }

    #[tokio::test]
    async fn sync_all_invalid_email_ignored() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let realm = RealmId::new("test").unwrap();
        let existing = User {
            id: UserId::new("u1").unwrap(),
            realm_id: realm.clone(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("old@example.com").unwrap()),
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: Some("mock".to_string()),
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        storage.create_user(&realm, &existing).await.unwrap();

        let provider = MockProvider {
            users: Mutex::new(vec![FederatedUser {
                username: "alice".to_string(),
                federation_link: "mock".to_string(),
                email: Some("not-an-email".to_string()),
                email_verified: true,
                first_name: None,
                last_name: None,
                enabled: true,
                external_id: None,
                attributes: HashMap::new(),
                groups: None,
            }]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let sync = UserSynchronizer::new(&provider, storage.clone(), realm.clone());
        let result = sync.sync_all().await.unwrap();
        assert_eq!(result.updated, 1);
        // Invalid email should be silently dropped (None).
        let user = storage.get_user_by_username(&realm, "alice").await.unwrap().unwrap();
        assert_eq!(user.email, None);
    }

    #[tokio::test]
    async fn sync_all_load_existing_users_error() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_list_users()
            .returning(|_, _, _| Err(issuerd_core::IssuerdError::ServerError("db down".into())));
        let provider = MockProvider {
            users: Mutex::new(vec![FederatedUser {
                username: "alice".to_string(),
                federation_link: "mock".to_string(),
                enabled: true,
                ..Default::default()
            }]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        };
        let sync = UserSynchronizer::new(&provider, Arc::new(mock), RealmId::new("test").unwrap());
        let err = sync.sync_all().await.unwrap_err();
        assert!(matches!(err, IssuerdError::ServerError(_)));
    }

    // ------------------------------------------------------------------
    // Group membership reconciliation
    // ------------------------------------------------------------------

    async fn realm_storage() -> (Arc<issuerd_storage::InMemoryStorage>, RealmId) {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let realm = issuerd_core::Realm {
            id: RealmId::new("test").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        storage.create_realm(&realm).await.unwrap();
        (storage, realm.id)
    }

    fn provider_with_groups(groups: Vec<String>) -> MockProvider {
        MockProvider {
            users: Mutex::new(vec![FederatedUser {
                username: "alice".to_string(),
                federation_link: "mock".to_string(),
                enabled: true,
                groups: Some(groups),
                ..Default::default()
            }]),
            sync_since_result: Mutex::new(Ok(SyncResult {
                added: 0,
                updated: 0,
                removed: 0,
                failed: 0,
                last_sync: Utc::now(),
            })),
        }
    }

    async fn group_names_of(
        storage: &Arc<issuerd_storage::InMemoryStorage>,
        realm: &RealmId,
        username: &str,
    ) -> Vec<String> {
        let user = storage.get_user_by_username(realm, username).await.unwrap().unwrap();
        let ids = storage.list_user_groups(realm, &user.id).await.unwrap();
        let mut names = Vec::new();
        for id in ids {
            names.push(storage.get_group(realm, &id).await.unwrap().unwrap().name.to_string());
        }
        names.sort();
        names
    }

    #[tokio::test]
    async fn sync_all_creates_groups_and_memberships() {
        let (storage, realm) = realm_storage().await;
        let provider = provider_with_groups(vec!["developers".to_string()]);
        let sync = UserSynchronizer::new(&provider, storage.clone(), realm.clone());
        let result = sync.sync_all().await.unwrap();
        assert_eq!(result.added, 1);

        assert_eq!(group_names_of(&storage, &realm, "alice").await, ["developers"]);
        let group = storage
            .get_group_by_name(&realm, "developers")
            .await
            .unwrap()
            .expect("group created on demand");
        assert_eq!(
            group.attributes.get(issuerd_core::roles::LDAP_SYNC_MARKER_ATTRIBUTE),
            Some(&vec!["true".to_string()])
        );
    }

    #[tokio::test]
    async fn sync_all_removes_stale_memberships_on_next_run() {
        let (storage, realm) = realm_storage().await;
        let provider = provider_with_groups(vec!["developers".to_string()]);
        let sync = UserSynchronizer::new(&provider, storage.clone(), realm.clone());
        sync.sync_all().await.unwrap();
        assert_eq!(group_names_of(&storage, &realm, "alice").await, ["developers"]);

        // AD membership removed → next sync drops the local membership.
        provider.users.lock().unwrap()[0].groups = Some(vec![]);
        sync.sync_all().await.unwrap();
        assert!(group_names_of(&storage, &realm, "alice").await.is_empty());
    }

    #[tokio::test]
    async fn sync_all_adopts_preexisting_group_and_keeps_manual_groups() {
        let (storage, realm) = realm_storage().await;
        // Pre-existing (e.g. provisioned) group without the sync marker…
        let group = issuerd_core::Group {
            id: issuerd_core::GroupId::new("g1").unwrap(),
            name: issuerd_core::GroupName::new("developers").unwrap(),
            path: issuerd_core::GroupPath::new("/developers").unwrap(),
            realm_id: realm.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        storage.create_group(&realm, &group).await.unwrap();
        // …and a manual group the user belongs to (must survive reconciliation).
        let manual = issuerd_core::Group {
            id: issuerd_core::GroupId::new("g2").unwrap(),
            name: issuerd_core::GroupName::new("manual").unwrap(),
            path: issuerd_core::GroupPath::new("/manual").unwrap(),
            realm_id: realm.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        storage.create_group(&realm, &manual).await.unwrap();

        let provider = provider_with_groups(vec!["developers".to_string()]);
        let sync = UserSynchronizer::new(&provider, storage.clone(), realm.clone());
        sync.sync_all().await.unwrap();

        let user = storage.get_user_by_username(&realm, "alice").await.unwrap().unwrap();
        storage
            .add_user_group(&realm, &user.id, &issuerd_core::GroupId::new("g2").unwrap())
            .await
            .unwrap();

        // Second run: developers adopted (marker set), manual group untouched.
        sync.sync_all().await.unwrap();
        let adopted = storage.get_group_by_name(&realm, "developers").await.unwrap().unwrap();
        assert!(adopted.attributes.contains_key(issuerd_core::roles::LDAP_SYNC_MARKER_ATTRIBUTE));
        let names = group_names_of(&storage, &realm, "alice").await;
        assert_eq!(names, ["developers", "manual"]);
    }

    #[tokio::test]
    async fn sync_without_group_reporting_never_wipes_memberships() {
        let (storage, realm) = realm_storage().await;
        // First run with groups: creates the marked membership.
        let provider = provider_with_groups(vec!["developers".to_string()]);
        let sync = UserSynchronizer::new(&provider, storage.clone(), realm.clone());
        sync.sync_all().await.unwrap();
        assert_eq!(group_names_of(&storage, &realm, "alice").await, ["developers"]);

        // The provider loses its group mapper (admin removed groupsDn):
        // groups become "not reported" (None) — memberships must survive,
        // unlike an authoritative Some(vec![]) which would remove them.
        provider.users.lock().unwrap()[0].groups = None;
        sync.sync_all().await.unwrap();
        assert_eq!(group_names_of(&storage, &realm, "alice").await, ["developers"]);
    }
}
