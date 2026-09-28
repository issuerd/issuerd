// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Slow, file-backed JSON storage intended for manual testing only.

use async_trait::async_trait;
use issuerd_core::*;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::memory::InMemoryStorage;

/// Slow, file-backed JSON storage intended for manual testing only.
///
/// Every write operation updates the in-memory state and then locks a
/// global mutex while re-serializing the entire database to JSON on
/// disk.  Reads are served directly from the in-memory copy without
/// locking.
pub struct JsonFileStorage {
    inner: InMemoryStorage,
    path: PathBuf,
    lock: Mutex<()>,
}

impl JsonFileStorage {
    /// Create or load a `JsonFileStorage` backed by `path`.
    ///
    /// If the file already exists it is parsed and loaded into memory.
    /// If it does not exist an empty storage is created; the file will
    /// be written on the first mutating operation.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, IssuerdError> {
        let path = path.as_ref().to_path_buf();
        let inner = InMemoryStorage::new();

        let mut loaded = false;
        if path.exists() {
            let data = std::fs::read_to_string(&path).map_err(|e| {
                IssuerdError::ServerError(format!("failed to read json storage: {e}"))
            })?;
            let snapshot = serde_json::from_str(&data).map_err(|e| {
                IssuerdError::ServerError(format!("failed to parse json storage: {e}"))
            })?;
            inner.load_snapshot(snapshot);
            loaded = true;
        }

        let storage = Self {
            inner,
            path,
            lock: Mutex::new(()),
        };

        if loaded {
            // Data migration: snapshots written before client
            // scopes existed contain none — seed the built-ins and the
            // clients' assignments into every loaded realm, then persist so
            // the migration is durable. The in-memory backend performs no
            // I/O, so the async seed helpers can be driven to completion
            // synchronously.
            storage.seed_loaded_realms()?;
            storage.persist()?;
        }

        Ok(storage)
    }

    /// Seed built-in client scopes and per-client assignments into every
    /// realm loaded from disk (idempotent).
    fn seed_loaded_realms(&self) -> Result<(), IssuerdError> {
        let realms =
            crate::seed::block_on_ready(self.inner.list_realms(&Pagination::new(0, i32::MAX)))?;
        for realm in realms {
            crate::seed::block_on_ready(crate::seed::seed_builtin_client_scopes(
                &self.inner,
                &realm.id,
            ))?;
            // Snapshots written before flow seeding get the
            // built-in browser + registration flows backfilled.
            crate::seed::block_on_ready(crate::seed::seed_builtin_flows(&self.inner, &realm.id))?;
            // Snapshots written before pairwise subjects get the
            // sector key backfilled.
            crate::seed::block_on_ready(crate::seed::backfill_pairwise_sector_key(
                &self.inner,
                &realm.id,
            ))?;
            let clients = crate::seed::block_on_ready(
                self.inner.list_clients(&realm.id, &Pagination::new(0, i32::MAX)),
            )?;
            for client in clients {
                crate::seed::block_on_ready(crate::seed::seed_client_scope_assignments(
                    &self.inner,
                    &realm.id,
                    &client,
                ))?;
            }
        }
        Ok(())
    }

    /// Persist the current in-memory state to disk.
    fn persist(&self) -> Result<(), IssuerdError> {
        let _guard = self.lock.lock().unwrap();
        let snapshot = self.inner.to_snapshot();
        let data = serde_json::to_string_pretty(&snapshot).map_err(|e| {
            IssuerdError::ServerError(format!("failed to serialize json storage: {e}"))
        })?;
        std::fs::write(&self.path, data)
            .map_err(|e| IssuerdError::ServerError(format!("failed to write json storage: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl Storage for JsonFileStorage {
    // ------------------------------------------------------------------
    // Realm
    // ------------------------------------------------------------------
    async fn get_realm(&self, id: &RealmId) -> Result<Option<Realm>, IssuerdError> {
        self.inner.get_realm(id).await
    }

    async fn get_realm_by_name(&self, name: &str) -> Result<Option<Realm>, IssuerdError> {
        self.inner.get_realm_by_name(name).await
    }

    async fn list_realms(&self, pagination: &Pagination) -> Result<Vec<Realm>, IssuerdError> {
        self.inner.list_realms(pagination).await
    }

    async fn count_realms(&self) -> Result<i64, IssuerdError> {
        self.inner.count_realms().await
    }

    async fn create_realm(&self, realm: &Realm) -> Result<(), IssuerdError> {
        self.inner.create_realm(realm).await?;
        self.persist()
    }

    async fn update_realm(&self, realm: &Realm) -> Result<(), IssuerdError> {
        self.inner.update_realm(realm).await?;
        self.persist()
    }

    async fn delete_realm(&self, id: &RealmId) -> Result<(), IssuerdError> {
        self.inner.delete_realm(id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // User
    // ------------------------------------------------------------------
    async fn get_user(&self, realm: &RealmId, id: &UserId) -> Result<Option<User>, IssuerdError> {
        self.inner.get_user(realm, id).await
    }

    async fn get_user_by_username(
        &self,
        realm: &RealmId,
        username: &str,
    ) -> Result<Option<User>, IssuerdError> {
        self.inner.get_user_by_username(realm, username).await
    }

    async fn get_user_by_email(
        &self,
        realm: &RealmId,
        email: &str,
    ) -> Result<Option<User>, IssuerdError> {
        self.inner.get_user_by_email(realm, email).await
    }

    async fn get_user_by_federation_link(
        &self,
        realm: &RealmId,
        link: &str,
    ) -> Result<Vec<User>, IssuerdError> {
        self.inner.get_user_by_federation_link(realm, link).await
    }

    async fn list_users(
        &self,
        realm: &RealmId,
        query: &str,
        pagination: &Pagination,
    ) -> Result<Vec<User>, IssuerdError> {
        self.inner.list_users(realm, query, pagination).await
    }

    async fn count_users(&self, realm: &RealmId, query: &str) -> Result<i64, IssuerdError> {
        self.inner.count_users(realm, query).await
    }

    async fn create_user(&self, realm: &RealmId, user: &User) -> Result<(), IssuerdError> {
        self.inner.create_user(realm, user).await?;
        self.persist()
    }

    async fn bulk_create_users(&self, realm: &RealmId, users: &[User]) -> Result<(), IssuerdError> {
        self.inner.bulk_create_users(realm, users).await?;
        self.persist()
    }

    async fn update_user(&self, realm: &RealmId, user: &User) -> Result<(), IssuerdError> {
        self.inner.update_user(realm, user).await?;
        self.persist()
    }

    async fn delete_user(&self, realm: &RealmId, id: &UserId) -> Result<(), IssuerdError> {
        self.inner.delete_user(realm, id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Client
    // ------------------------------------------------------------------
    async fn get_client(
        &self,
        realm: &RealmId,
        id: &ClientId,
    ) -> Result<Option<Client>, IssuerdError> {
        self.inner.get_client(realm, id).await
    }

    async fn get_client_by_client_id(
        &self,
        realm: &RealmId,
        client_id: &ClientIdentifier,
    ) -> Result<Option<Client>, IssuerdError> {
        self.inner.get_client_by_client_id(realm, client_id).await
    }

    async fn list_clients(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Client>, IssuerdError> {
        self.inner.list_clients(realm, pagination).await
    }

    async fn count_clients(&self, realm: &RealmId) -> Result<i64, IssuerdError> {
        self.inner.count_clients(realm).await
    }

    async fn create_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError> {
        self.inner.create_client(realm, client).await?;
        self.persist()
    }

    async fn update_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError> {
        self.inner.update_client(realm, client).await?;
        self.persist()
    }

    async fn delete_client(&self, realm: &RealmId, id: &ClientId) -> Result<(), IssuerdError> {
        self.inner.delete_client(realm, id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Credentials
    // ------------------------------------------------------------------
    async fn get_credentials(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred_type: CredentialType,
    ) -> Result<Vec<Credential>, IssuerdError> {
        self.inner.get_credentials(realm, user, cred_type).await
    }

    async fn list_credentials(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<Credential>, IssuerdError> {
        self.inner.list_credentials(realm, user).await
    }

    async fn create_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred: &Credential,
    ) -> Result<(), IssuerdError> {
        self.inner.create_credential(realm, user, cred).await?;
        self.persist()
    }

    async fn update_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred: &Credential,
    ) -> Result<(), IssuerdError> {
        self.inner.update_credential(realm, user, cred).await?;
        self.persist()
    }

    async fn delete_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred_id: &CredentialId,
    ) -> Result<(), IssuerdError> {
        self.inner.delete_credential(realm, user, cred_id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------
    async fn get_user_session(
        &self,
        realm: &RealmId,
        id: &SessionId,
    ) -> Result<Option<UserSession>, IssuerdError> {
        self.inner.get_user_session(realm, id).await
    }

    async fn list_sessions(
        &self,
        realm: &RealmId,
        user: Option<UserId>,
        pagination: &Pagination,
    ) -> Result<Vec<UserSession>, IssuerdError> {
        self.inner.list_sessions(realm, user, pagination).await
    }

    async fn count_sessions(
        &self,
        realm: &RealmId,
        user: Option<UserId>,
    ) -> Result<i64, IssuerdError> {
        self.inner.count_sessions(realm, user).await
    }

    async fn create_user_session(
        &self,
        realm: &RealmId,
        session: &UserSession,
    ) -> Result<(), IssuerdError> {
        self.inner.create_user_session(realm, session).await?;
        self.persist()
    }

    async fn update_user_session(
        &self,
        realm: &RealmId,
        session: &UserSession,
    ) -> Result<(), IssuerdError> {
        self.inner.update_user_session(realm, session).await?;
        self.persist()
    }

    async fn delete_user_session(
        &self,
        realm: &RealmId,
        id: &SessionId,
    ) -> Result<(), IssuerdError> {
        self.inner.delete_user_session(realm, id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Roles
    // ------------------------------------------------------------------
    async fn get_role(&self, realm: &RealmId, id: &RoleId) -> Result<Option<Role>, IssuerdError> {
        self.inner.get_role(realm, id).await
    }

    async fn get_role_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<Role>, IssuerdError> {
        self.inner.get_role_by_name(realm, name).await
    }

    async fn list_roles(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Role>, IssuerdError> {
        self.inner.list_roles(realm, pagination).await
    }

    async fn count_roles(&self, realm: &RealmId) -> Result<i64, IssuerdError> {
        self.inner.count_roles(realm).await
    }

    async fn create_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError> {
        self.inner.create_role(realm, role).await?;
        self.persist()
    }

    async fn update_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError> {
        self.inner.update_role(realm, role).await?;
        self.persist()
    }

    async fn delete_role(&self, realm: &RealmId, id: &RoleId) -> Result<(), IssuerdError> {
        self.inner.delete_role(realm, id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Client roles
    // ------------------------------------------------------------------
    async fn get_client_role_by_name(
        &self,
        realm: &RealmId,
        client: &ClientId,
        name: &str,
    ) -> Result<Option<Role>, IssuerdError> {
        self.inner.get_client_role_by_name(realm, client, name).await
    }

    async fn list_client_roles(
        &self,
        realm: &RealmId,
        client: &ClientId,
        pagination: &Pagination,
    ) -> Result<Vec<Role>, IssuerdError> {
        self.inner.list_client_roles(realm, client, pagination).await
    }

    // ------------------------------------------------------------------
    // Client scopes
    // ------------------------------------------------------------------
    async fn get_client_scope(
        &self,
        realm: &RealmId,
        id: &ClientScopeId,
    ) -> Result<Option<ClientScope>, IssuerdError> {
        self.inner.get_client_scope(realm, id).await
    }

    async fn get_client_scope_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<ClientScope>, IssuerdError> {
        self.inner.get_client_scope_by_name(realm, name).await
    }

    async fn list_client_scopes(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<ClientScope>, IssuerdError> {
        self.inner.list_client_scopes(realm, pagination).await
    }

    async fn create_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScope,
    ) -> Result<(), IssuerdError> {
        self.inner.create_client_scope(realm, scope).await?;
        self.persist()
    }

    async fn update_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScope,
    ) -> Result<(), IssuerdError> {
        self.inner.update_client_scope(realm, scope).await?;
        self.persist()
    }

    async fn delete_client_scope(
        &self,
        realm: &RealmId,
        id: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        self.inner.delete_client_scope(realm, id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Client <-> client-scope assignments
    // ------------------------------------------------------------------
    async fn assign_client_scope(
        &self,
        realm: &RealmId,
        client: &ClientId,
        scope: &ClientScopeId,
        is_default: bool,
    ) -> Result<(), IssuerdError> {
        self.inner.assign_client_scope(realm, client, scope, is_default).await?;
        self.persist()
    }

    async fn unassign_client_scope(
        &self,
        realm: &RealmId,
        client: &ClientId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        self.inner.unassign_client_scope(realm, client, scope).await?;
        self.persist()
    }

    async fn list_client_scope_assignments(
        &self,
        realm: &RealmId,
        client: &ClientId,
    ) -> Result<Vec<(ClientScopeId, bool)>, IssuerdError> {
        self.inner.list_client_scope_assignments(realm, client).await
    }

    // ------------------------------------------------------------------
    // Realm default client scopes
    // ------------------------------------------------------------------
    async fn list_realm_default_client_scopes(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<(ClientScopeId, bool)>, IssuerdError> {
        self.inner.list_realm_default_client_scopes(realm).await
    }

    async fn add_realm_default_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScopeId,
        is_default: bool,
    ) -> Result<(), IssuerdError> {
        self.inner.add_realm_default_client_scope(realm, scope, is_default).await?;
        self.persist()
    }

    async fn remove_realm_default_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        self.inner.remove_realm_default_client_scope(realm, scope).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------
    async fn get_group(
        &self,
        realm: &RealmId,
        id: &GroupId,
    ) -> Result<Option<Group>, IssuerdError> {
        self.inner.get_group(realm, id).await
    }

    async fn get_group_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<Group>, IssuerdError> {
        self.inner.get_group_by_name(realm, name).await
    }

    async fn list_groups(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Group>, IssuerdError> {
        self.inner.list_groups(realm, pagination).await
    }

    async fn count_groups(&self, realm: &RealmId) -> Result<i64, IssuerdError> {
        self.inner.count_groups(realm).await
    }

    async fn create_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError> {
        self.inner.create_group(realm, group).await?;
        self.persist()
    }

    async fn update_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError> {
        self.inner.update_group(realm, group).await?;
        self.persist()
    }

    async fn delete_group(&self, realm: &RealmId, id: &GroupId) -> Result<(), IssuerdError> {
        self.inner.delete_group(realm, id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // User realm roles
    // ------------------------------------------------------------------
    async fn add_user_realm_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        self.inner.add_user_realm_role(realm, user, role_id).await?;
        self.persist()
    }

    async fn remove_user_realm_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        self.inner.remove_user_realm_role(realm, user, role_id).await?;
        self.persist()
    }

    async fn list_user_realm_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError> {
        self.inner.list_user_realm_roles(realm, user).await
    }

    // ------------------------------------------------------------------
    // User client roles
    // ------------------------------------------------------------------
    async fn add_user_client_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        self.inner.add_user_client_role(realm, user, role_id).await?;
        self.persist()
    }

    async fn remove_user_client_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        self.inner.remove_user_client_role(realm, user, role_id).await?;
        self.persist()
    }

    async fn list_user_client_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError> {
        self.inner.list_user_client_roles(realm, user).await
    }

    // ------------------------------------------------------------------
    // User groups
    // ------------------------------------------------------------------
    async fn add_user_group(
        &self,
        realm: &RealmId,
        user: &UserId,
        group_id: &GroupId,
    ) -> Result<(), IssuerdError> {
        self.inner.add_user_group(realm, user, group_id).await?;
        self.persist()
    }

    async fn remove_user_group(
        &self,
        realm: &RealmId,
        user: &UserId,
        group_id: &GroupId,
    ) -> Result<(), IssuerdError> {
        self.inner.remove_user_group(realm, user, group_id).await?;
        self.persist()
    }

    async fn list_user_groups(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<GroupId>, IssuerdError> {
        self.inner.list_user_groups(realm, user).await
    }

    async fn list_group_members(
        &self,
        realm: &RealmId,
        group: &GroupId,
        first: i32,
        max: i32,
    ) -> Result<Vec<User>, IssuerdError> {
        self.inner.list_group_members(realm, group, first, max).await
    }

    // ------------------------------------------------------------------
    // Consent
    // ------------------------------------------------------------------
    async fn get_consents(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<Consent>, IssuerdError> {
        self.inner.get_consents(realm, user).await
    }

    async fn create_consent(&self, realm: &RealmId, consent: &Consent) -> Result<(), IssuerdError> {
        self.inner.create_consent(realm, consent).await?;
        self.persist()
    }

    async fn delete_consent(
        &self,
        realm: &RealmId,
        user: &UserId,
        client_id: &ClientId,
    ) -> Result<(), IssuerdError> {
        self.inner.delete_consent(realm, user, client_id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Identity Providers
    // ------------------------------------------------------------------
    async fn get_identity_provider(
        &self,
        realm: &RealmId,
        id: &IdentityProviderId,
    ) -> Result<Option<IdentityProviderConfig>, IssuerdError> {
        self.inner.get_identity_provider(realm, id).await
    }

    async fn get_identity_provider_by_alias(
        &self,
        realm: &RealmId,
        alias: &str,
    ) -> Result<Option<IdentityProviderConfig>, IssuerdError> {
        self.inner.get_identity_provider_by_alias(realm, alias).await
    }

    async fn list_identity_providers(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<IdentityProviderConfig>, IssuerdError> {
        self.inner.list_identity_providers(realm).await
    }

    async fn create_identity_provider(
        &self,
        realm: &RealmId,
        idp: &IdentityProviderConfig,
    ) -> Result<(), IssuerdError> {
        self.inner.create_identity_provider(realm, idp).await?;
        self.persist()
    }

    async fn update_identity_provider(
        &self,
        realm: &RealmId,
        idp: &IdentityProviderConfig,
    ) -> Result<(), IssuerdError> {
        self.inner.update_identity_provider(realm, idp).await?;
        self.persist()
    }

    async fn delete_identity_provider(
        &self,
        realm: &RealmId,
        id: &IdentityProviderId,
    ) -> Result<(), IssuerdError> {
        self.inner.delete_identity_provider(realm, id).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Identity Provider Links
    // ------------------------------------------------------------------
    async fn get_identity_provider_link(
        &self,
        realm: &RealmId,
        alias: &str,
        external_subject: &str,
    ) -> Result<Option<IdentityProviderLink>, IssuerdError> {
        self.inner.get_identity_provider_link(realm, alias, external_subject).await
    }

    async fn get_identity_provider_link_for_user(
        &self,
        realm: &RealmId,
        user: &UserId,
        alias: &str,
    ) -> Result<Option<IdentityProviderLink>, IssuerdError> {
        self.inner.get_identity_provider_link_for_user(realm, user, alias).await
    }

    async fn list_identity_provider_links(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<IdentityProviderLink>, IssuerdError> {
        self.inner.list_identity_provider_links(realm, user).await
    }

    async fn create_identity_provider_link(
        &self,
        realm: &RealmId,
        link: &IdentityProviderLink,
    ) -> Result<(), IssuerdError> {
        self.inner.create_identity_provider_link(realm, link).await?;
        self.persist()
    }

    async fn delete_identity_provider_link(
        &self,
        realm: &RealmId,
        user: &UserId,
        alias: &str,
    ) -> Result<(), IssuerdError> {
        self.inner.delete_identity_provider_link(realm, user, alias).await?;
        self.persist()
    }

    // ------------------------------------------------------------------
    // Flow Config
    // ------------------------------------------------------------------
    async fn get_flow_config(
        &self,
        realm: &RealmId,
        alias: &str,
    ) -> Result<Option<FlowConfig>, IssuerdError> {
        self.inner.get_flow_config(realm, alias).await
    }

    async fn create_flow_config(
        &self,
        realm: &RealmId,
        config: &FlowConfig,
    ) -> Result<(), IssuerdError> {
        self.inner.create_flow_config(realm, config).await?;
        self.persist()
    }

    async fn update_flow_config(
        &self,
        realm: &RealmId,
        config: &FlowConfig,
    ) -> Result<(), IssuerdError> {
        self.inner.update_flow_config(realm, config).await?;
        self.persist()
    }

    async fn delete_flow_config(&self, realm: &RealmId, alias: &str) -> Result<(), IssuerdError> {
        self.inner.delete_flow_config(realm, alias).await?;
        self.persist()
    }

    async fn list_flow_configs(&self, realm: &RealmId) -> Result<Vec<FlowConfig>, IssuerdError> {
        self.inner.list_flow_configs(realm).await
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------
    async fn save_event(&self, realm: &RealmId, event: &Event) -> Result<(), IssuerdError> {
        self.inner.save_event(realm, event).await?;
        self.persist()
    }

    async fn query_events(
        &self,
        realm: &RealmId,
        query: &EventQuery,
    ) -> Result<Vec<Event>, IssuerdError> {
        self.inner.query_events(realm, query).await
    }

    async fn count_events(&self, realm: &RealmId, query: &EventQuery) -> Result<i64, IssuerdError> {
        self.inner.count_events(realm, query).await
    }

    async fn delete_events(&self, realm: &RealmId) -> Result<(), IssuerdError> {
        self.inner.delete_events(realm).await?;
        self.persist()
    }

    async fn save_admin_event(&self, event: &AdminEvent) -> Result<(), IssuerdError> {
        self.inner.save_admin_event(event).await?;
        self.persist()
    }

    async fn query_admin_events(
        &self,
        realm: &RealmId,
        query: &AdminEventQuery,
    ) -> Result<Vec<AdminEvent>, IssuerdError> {
        self.inner.query_admin_events(realm, query).await
    }

    async fn count_admin_events(
        &self,
        realm: &RealmId,
        query: &AdminEventQuery,
    ) -> Result<i64, IssuerdError> {
        self.inner.count_admin_events(realm, query).await
    }

    async fn delete_admin_events(&self, realm: &RealmId) -> Result<(), IssuerdError> {
        self.inner.delete_admin_events(realm).await?;
        self.persist()
    }

    async fn get_provision_marker(&self, name: &str) -> Result<Option<String>, IssuerdError> {
        self.inner.get_provision_marker(name).await
    }

    async fn set_provision_marker(&self, name: &str, value: &str) -> Result<(), IssuerdError> {
        self.inner.set_provision_marker(name, value).await?;
        self.persist()?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Signing keys
    // ------------------------------------------------------------------
    async fn list_signing_keys(&self) -> Result<Vec<StoredSigningKey>, IssuerdError> {
        self.inner.list_signing_keys().await
    }

    async fn create_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError> {
        self.inner.create_signing_key(key).await?;
        self.persist()
    }

    async fn update_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError> {
        self.inner.update_signing_key(key).await?;
        self.persist()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_realm() -> Realm {
        Realm {
            id: RealmId::new("realm-1").unwrap(),
            name: RealmName::new("test-realm").unwrap(),
            display_name: Some(DisplayName::new("Test Realm").unwrap()),
            enabled: true,
            ssl_required: SslRequired::External,
            password_policy: PasswordPolicy::default(),
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            default_role: None,
            access_token_lifespan: SecondsNonZero::new(300),
            refresh_token_lifespan: SecondsNonZero::new(1800),
            sso_session_idle_timeout: SecondsNonZero::new(1800),
            sso_session_max_lifespan: SecondsNonZero::new(36000),
            offline_session_idle_timeout: SecondsNonZero::new(2592000),
            brute_force_protected: false,
            max_login_failures: 5,
            wait_increment_secs: 60,
            max_failure_wait_secs: 900,
            lockout_duration_secs: 900,
            registration_enabled: false,
            reset_password_allowed: false,
            remember_me_enabled: false,
            verify_email_enabled: false,
            login_with_email_allowed: true,
            duplicate_emails_allowed: false,
            edit_username_allowed: true,
            remember_me_session_idle_secs: SecondsNonZero::new(604_800),
            otp_policy: OtpPolicy::default(),
            internationalization_enabled: false,
            supported_locales: Vec::new(),
            default_locale: None,
            events_enabled: false,
            events_expiration_secs: 0,
            admin_events_enabled: false,
            include_representations: false,
            events_listeners: vec!["logging".to_string()],
            not_before: 0,
            default_groups: Vec::new(),
            browser_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: None,
            attributes: HashMap::new(),
        }
    }

    fn test_user() -> User {
        User {
            id: UserId::new("user-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: Some(DisplayName::new("Smith").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn json_storage_persists_and_reloads() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("issuerd-json-test-{}.json", uuid::Uuid::new_v4()));

        // Create storage and write data
        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let realm = test_realm();
            let user = test_user();
            storage.create_realm(&realm).await.unwrap();
            storage.create_user(&realm.id, &user).await.unwrap();

            let fetched = storage.get_realm(&realm.id).await.unwrap().unwrap();
            assert_eq!(fetched.name, "test-realm");
        }

        // Reload from file and verify
        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let realm =
                storage.get_realm(&RealmId::new("realm-1").unwrap()).await.unwrap().unwrap();
            assert_eq!(realm.name, "test-realm");

            let user = storage
                .get_user(&RealmId::new("realm-1").unwrap(), &UserId::new("user-1").unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(user.username, "alice");
        }

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn json_storage_update_and_delete_persist() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("issuerd-json-test-{}.json", uuid::Uuid::new_v4()));

        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let realm = test_realm();
            storage.create_realm(&realm).await.unwrap();
        }

        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let mut realm =
                storage.get_realm(&RealmId::new("realm-1").unwrap()).await.unwrap().unwrap();
            realm.name = RealmName::new("updated-realm").unwrap();
            storage.update_realm(&realm).await.unwrap();
        }

        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let realm =
                storage.get_realm(&RealmId::new("realm-1").unwrap()).await.unwrap().unwrap();
            assert_eq!(realm.name, "updated-realm");
            storage.delete_realm(&realm.id).await.unwrap();
        }

        {
            let storage = JsonFileStorage::new(&path).unwrap();
            assert!(storage.get_realm(&RealmId::new("realm-1").unwrap()).await.unwrap().is_none());
        }

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn json_storage_creates_file_on_first_write() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("issuerd-json-test-{}.json", uuid::Uuid::new_v4()));

        assert!(!path.exists());
        let storage = JsonFileStorage::new(&path).unwrap();
        assert!(!path.exists()); // still not created before first write

        storage.create_realm(&test_realm()).await.unwrap();
        assert!(path.exists());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn json_storage_all_operations() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("issuerd-json-all-{}.json", uuid::Uuid::new_v4()));

        let storage = JsonFileStorage::new(&path).unwrap();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        // User operations
        let user = test_user();
        storage.create_user(&realm.id, &user).await.unwrap();
        assert!(storage.get_user(&realm.id, &user.id).await.unwrap().is_some());
        assert!(storage.get_user_by_username(&realm.id, "alice").await.unwrap().is_some());
        assert!(storage
            .get_user_by_email(&realm.id, "alice@example.com")
            .await
            .unwrap()
            .is_some());
        let users = storage.list_users(&realm.id, "", &Pagination::default()).await.unwrap();
        assert_eq!(users.len(), 1);

        // Client operations
        let client = Client {
            id: ClientId::new("client-1").unwrap(),
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        storage.create_client(&realm.id, &client).await.unwrap();
        assert!(storage.get_client(&realm.id, &client.id).await.unwrap().is_some());
        assert!(storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("my-app").unwrap())
            .await
            .unwrap()
            .is_some());
        let clients = storage.list_clients(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(clients.len(), 1);

        // Credential operations
        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: vec![],
            credential_data: serde_json::json!(null),
            priority: 0,
        };
        storage.create_credential(&realm.id, &user.id, &cred).await.unwrap();
        let creds = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
        storage.update_credential(&realm.id, &user.id, &cred).await.unwrap();
        storage.delete_credential(&realm.id, &user.id, &cred.id).await.unwrap();

        // Session operations
        let session = UserSession {
            id: SessionId::new("session-1").unwrap(),
            realm_id: realm.id.clone(),
            user_id: user.id.clone(),
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
        storage.create_user_session(&realm.id, &session).await.unwrap();
        assert!(storage.get_user_session(&realm.id, &session.id).await.unwrap().is_some());
        let sessions = storage
            .list_sessions(&realm.id, Some(user.id.clone()), &Pagination::default())
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1);
        storage.update_user_session(&realm.id, &session).await.unwrap();
        storage.delete_user_session(&realm.id, &session.id).await.unwrap();

        // Role operations
        let role = Role {
            id: RoleId::new("role-1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: None,
            realm_id: realm.id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        storage.create_role(&realm.id, &role).await.unwrap();
        assert!(storage.get_role(&realm.id, &role.id).await.unwrap().is_some());
        assert!(storage.get_role_by_name(&realm.id, "admin").await.unwrap().is_some());
        let roles = storage.list_roles(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(roles.len(), 1);
        storage.update_role(&realm.id, &role).await.unwrap();
        storage.delete_role(&realm.id, &role.id).await.unwrap();

        // Group operations
        let group = Group {
            id: GroupId::new("group-1").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: GroupPath::new("/admins").unwrap(),
            realm_id: realm.id.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        storage.create_group(&realm.id, &group).await.unwrap();
        assert!(storage.get_group(&realm.id, &group.id).await.unwrap().is_some());
        let groups = storage.list_groups(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(groups.len(), 1);
        storage.update_group(&realm.id, &group).await.unwrap();
        storage.delete_group(&realm.id, &group.id).await.unwrap();

        // User realm roles
        storage.add_user_realm_role(&realm.id, &user.id, &role.id).await.unwrap();
        let user_roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert_eq!(user_roles.len(), 1);
        storage.remove_user_realm_role(&realm.id, &user.id, &role.id).await.unwrap();

        // User groups
        storage.add_user_group(&realm.id, &user.id, &group.id).await.unwrap();
        let user_groups = storage.list_user_groups(&realm.id, &user.id).await.unwrap();
        assert_eq!(user_groups.len(), 1);
        storage.remove_user_group(&realm.id, &user.id, &group.id).await.unwrap();

        // Consent operations
        let consent = Consent {
            client_id: ClientId::new("client-1").unwrap(),
            user_id: user.id.clone(),
            granted_scopes: Scope::empty(),
            granted_realm_roles: vec![],
            granted_client_roles: HashMap::new(),
            created_at: chrono::Utc::now(),
            last_updated_at: chrono::Utc::now(),
        };
        storage.create_consent(&realm.id, &consent).await.unwrap();
        let consents = storage.get_consents(&realm.id, &user.id).await.unwrap();
        assert_eq!(consents.len(), 1);
        storage.delete_consent(&realm.id, &user.id, &consent.client_id).await.unwrap();

        // Identity provider operations
        let idp = IdentityProviderConfig {
            id: IdentityProviderId::new("idp-1").unwrap(),
            alias: Alias::new("google").unwrap(),
            provider_id: ProviderId::new("google"),
            enabled: true,
            config: HashMap::new(),
        };
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();
        assert!(storage.get_identity_provider(&realm.id, &idp.id).await.unwrap().is_some());
        assert!(storage
            .get_identity_provider_by_alias(&realm.id, "google")
            .await
            .unwrap()
            .is_some());
        let idps = storage.list_identity_providers(&realm.id).await.unwrap();
        assert_eq!(idps.len(), 1);
        storage.update_identity_provider(&realm.id, &idp).await.unwrap();
        storage.delete_identity_provider(&realm.id, &idp.id).await.unwrap();

        // Flow config operations
        let flow = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: realm.id.clone(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![],
        };
        storage.create_flow_config(&realm.id, &flow).await.unwrap();
        assert!(storage.get_flow_config(&realm.id, "browser").await.unwrap().is_some());
        let flows = storage.list_flow_configs(&realm.id).await.unwrap();
        // The realm also carries the seeded built-in flows.
        assert!(flows.iter().any(|f| f.alias == flow.alias));
        storage.update_flow_config(&realm.id, &flow).await.unwrap();
        storage.delete_flow_config(&realm.id, "browser").await.unwrap();

        // Event operations
        let event = Event {
            id: EventId::new("event-1").unwrap(),
            realm_id: realm.id.clone(),
            event_time: chrono::Utc::now(),
            event_type: EventType::Login,
            ip_address: None,
            client_id: None,
            user_id: None,
            session_id: None,
            error: None,
            details: HashMap::new(),
        };
        storage.save_event(&realm.id, &event).await.unwrap();
        let events = storage
            .query_events(
                &realm.id,
                &EventQuery {
                    event_type: None,
                    client_id: None,
                    user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(events.len(), 1);

        // Realm list
        let realms = storage.list_realms(&Pagination::default()).await.unwrap();
        assert_eq!(realms.len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn json_storage_new_with_malformed_json() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("issuerd-json-bad-{}.json", uuid::Uuid::new_v4()));

        std::fs::write(&path, "not valid json").unwrap();
        let result = JsonFileStorage::new(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn json_storage_remaining_operations() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("issuerd-json-rem-{}.json", uuid::Uuid::new_v4()));

        let storage = JsonFileStorage::new(&path).unwrap();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        // get_realm_by_name
        assert!(storage.get_realm_by_name("test-realm").await.unwrap().is_some());

        // bulk_create_users
        let user1 = test_user();
        let mut user2 = test_user();
        user2.id = UserId::new("user-2").unwrap();
        user2.username = Username::new("bob").unwrap();
        storage
            .bulk_create_users(&realm.id, &[user1.clone(), user2.clone()])
            .await
            .unwrap();
        assert!(storage.get_user(&realm.id, &user1.id).await.unwrap().is_some());
        assert!(storage.get_user(&realm.id, &user2.id).await.unwrap().is_some());

        // update_user
        let mut updated_user = user1.clone();
        updated_user.email = Some(Email::new("new@example.com").unwrap());
        storage.update_user(&realm.id, &updated_user).await.unwrap();
        let fetched = storage.get_user(&realm.id, &user1.id).await.unwrap().unwrap();
        assert_eq!(fetched.email, Some(Email::new("new@example.com").unwrap()));

        // delete_user
        storage.delete_user(&realm.id, &user2.id).await.unwrap();
        assert!(storage.get_user(&realm.id, &user2.id).await.unwrap().is_none());

        // get_user_by_federation_link
        let mut fed_user = test_user();
        fed_user.id = UserId::new("user-fed").unwrap();
        fed_user.username = Username::new("fed").unwrap();
        fed_user.federation_link = Some("ldap-1".to_string());
        storage.create_user(&realm.id, &fed_user).await.unwrap();
        let fed = storage.get_user_by_federation_link(&realm.id, "ldap-1").await.unwrap();
        assert_eq!(fed.len(), 1);

        // update_client + delete_client
        let client = Client {
            id: ClientId::new("client-1").unwrap(),
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        storage.create_client(&realm.id, &client).await.unwrap();
        let mut updated_client = client.clone();
        updated_client.name = Some(DisplayName::new("Updated").unwrap());
        storage.update_client(&realm.id, &updated_client).await.unwrap();
        let fetched = storage.get_client(&realm.id, &client.id).await.unwrap().unwrap();
        assert_eq!(fetched.name, Some(DisplayName::new("Updated").unwrap()));
        storage.delete_client(&realm.id, &client.id).await.unwrap();
        assert!(storage.get_client(&realm.id, &client.id).await.unwrap().is_none());

        // save_admin_event + query_admin_events
        let admin_event = AdminEvent {
            id: EventId::new("admin-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            auth_realm_id: None,
            auth_client_id: None,
            auth_user_id: None,
            operation_type: OperationType::Create,
            resource_type: ResourceType::Realm,
            resource_path: "/realms/test".to_string(),
            representation: None,
            error: None,
            event_time: chrono::Utc::now(),
        };
        storage.save_admin_event(&admin_event).await.unwrap();
        let admin_events = storage
            .query_admin_events(
                &realm.id,
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
            .unwrap();
        assert_eq!(admin_events.len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn json_storage_seeds_scopes_when_loading_old_snapshot() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("issuerd-json-old-{}.json", uuid::Uuid::new_v4()));

        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let realm = test_realm();
            storage.create_realm(&realm).await.unwrap();
            let client = Client {
                id: ClientId::new("client-1").unwrap(),
                realm_id: realm.id.clone(),
                client_id: ClientIdentifier::new("my-app").unwrap(),
                name: None,
                description: None,
                enabled: true,
                protocol: ClientProtocol::OpenIdConnect,
                public_client: false,
                bearer_only: false,
                client_authenticator_type: ClientAuthenticatorType::ClientSecret,
                secret: None,
                redirect_uris: vec![],
                web_origins: vec![],
                default_scopes: Scope::empty(),
                optional_scopes: Scope::empty(),
                consent_required: false,
                full_scope_allowed: true,
                service_accounts_enabled: false,
                protocol_mappers: Vec::new(),
                scope_mappings: Default::default(),
                attributes: HashMap::new(),
            };
            storage.create_client(&realm.id, &client).await.unwrap();
        }

        // Rewrite the file as a snapshot from before client scopes existed
        // would look: no client scope collections at all.
        let data = std::fs::read_to_string(&path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&data).unwrap();
        let obj = json.as_object_mut().unwrap();
        obj.remove("client_scopes");
        obj.remove("client_scope_assignments");
        obj.remove("realm_default_client_scopes");
        obj.remove("user_client_roles");
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        // Loading the old snapshot seeds built-in scopes, realm defaults and
        // the client's assignments (`roles` default via the carve-out).
        let storage = JsonFileStorage::new(&path).unwrap();
        let realm_id = RealmId::new("realm-1").unwrap();
        assert_eq!(
            storage
                .list_client_scopes(&realm_id, &Pagination::default())
                .await
                .unwrap()
                .len(),
            8
        );
        assert_eq!(storage.list_realm_default_client_scopes(&realm_id).await.unwrap().len(), 8);
        let client = storage
            .get_client_by_client_id(&realm_id, &ClientIdentifier::new("my-app").unwrap())
            .await
            .unwrap()
            .unwrap();
        let assignments =
            storage.list_client_scope_assignments(&realm_id, &client.id).await.unwrap();
        assert_eq!(assignments.len(), 1);
        let roles_scope =
            storage.get_client_scope_by_name(&realm_id, "roles").await.unwrap().unwrap();
        assert_eq!(assignments, vec![(roles_scope.id, true)]);

        // The migration was persisted: reloading shows the same state.
        let storage = JsonFileStorage::new(&path).unwrap();
        assert_eq!(
            storage
                .list_client_scopes(&realm_id, &Pagination::default())
                .await
                .unwrap()
                .len(),
            8
        );

        let _ = std::fs::remove_file(&path);
    }

    // ------------------------------------------------------------------
    // Full-entity persist + reload roundtrip
    // ------------------------------------------------------------------

    fn unique_test_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("issuerd-{tag}-{}.json", uuid::Uuid::new_v4()))
    }

    fn full_realm() -> Realm {
        let mut r = test_realm();
        r.login_theme = Some(ThemeName::new("issuerd").unwrap());
        r.email_theme = Some(ThemeName::new("custom-email").unwrap());
        r.admin_theme = Some(ThemeName::new("custom-admin").unwrap());
        r.default_role = Some("default-roles".to_string());
        r.brute_force_protected = true;
        r.registration_enabled = true;
        r.reset_password_allowed = true;
        r.remember_me_enabled = true;
        r.verify_email_enabled = true;
        r.duplicate_emails_allowed = true;
        r.edit_username_allowed = false;
        r.internationalization_enabled = true;
        r.supported_locales = vec!["en".to_string(), "de".to_string()];
        r.default_locale = Some("en".to_string());
        r.events_enabled = true;
        r.events_expiration_secs = 86_400;
        r.admin_events_enabled = true;
        r.include_representations = true;
        r.events_listeners = vec!["logging".to_string(), "metrics".to_string()];
        r.not_before = 1_700_000_000;
        r.default_groups = vec!["/admins".to_string()];
        r.browser_flow = Some("browser".to_string());
        r.direct_grant_flow = Some("direct grant".to_string());
        r.reset_credentials_flow = Some("reset credentials".to_string());
        r.first_broker_login_flow = Some("first broker login".to_string());
        r.registration_flow = Some("registration".to_string());
        r.attributes.insert("custom".to_string(), "value".to_string());
        r
    }

    fn full_user(realm_id: &RealmId) -> User {
        let now = chrono::Utc::now();
        User {
            id: UserId::new("user-1").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: Some(DisplayName::new("Smith").unwrap()),
            enabled: true,
            federation_link: Some("ldap-1".to_string()),
            attributes: HashMap::from([(
                "department".to_string(),
                vec!["engineering".to_string(), "ops".to_string()],
            )]),
            required_actions: vec!["UPDATE_PASSWORD".to_string()],
            created_at: now,
            updated_at: now,
        }
    }

    fn full_client(realm_id: &RealmId) -> Client {
        Client {
            id: ClientId::new("client-1").unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: Some(DisplayName::new("My App").unwrap()),
            description: Some("test client".to_string()),
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![RedirectUri::new("https://app.example.com/callback").unwrap()],
            web_origins: vec![WebOrigin::new("https://app.example.com").unwrap()],
            default_scopes: Scope::parse("openid profile email"),
            optional_scopes: Scope::parse("offline_access"),
            consent_required: true,
            full_scope_allowed: false,
            service_accounts_enabled: true,
            protocol_mappers: vec![ProtocolMapper {
                id: MapperId::new("mapper-1").unwrap(),
                name: "username".to_string(),
                mapper_type: MapperType::UserProperty,
                config: HashMap::from([(
                    "claim.name".to_string(),
                    "preferred_username".to_string(),
                )]),
            }],
            scope_mappings: ScopeMappings {
                realm_roles: vec![RoleId::new("role-realm").unwrap()],
                client_roles: HashMap::from([(
                    ClientId::new("client-1").unwrap(),
                    vec![RoleId::new("role-client").unwrap()],
                )]),
            },
            attributes: HashMap::from([("pkce.required".to_string(), "true".to_string())]),
        }
    }

    fn realm_role() -> Role {
        Role {
            id: RoleId::new("role-realm").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: Some("Realm administrator".to_string()),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: true,
            composites: vec![RoleName::new("base").unwrap()],
            attributes: HashMap::from([("tag".to_string(), vec!["a".to_string()])]),
        }
    }

    fn client_role() -> Role {
        Role {
            id: RoleId::new("role-client").unwrap(),
            name: RoleName::new("app-admin").unwrap(),
            description: Some("Application administrator".to_string()),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_role: true,
            client_id: Some(ClientId::new("client-1").unwrap()),
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        }
    }

    fn parent_group() -> Group {
        Group {
            id: GroupId::new("group-parent").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: GroupPath::new("/admins").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        }
    }

    fn child_group() -> Group {
        Group {
            id: GroupId::new("group-child").unwrap(),
            name: GroupName::new("ops").unwrap(),
            path: GroupPath::new("/admins/ops").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            parent_id: Some(GroupId::new("group-parent").unwrap()),
            sub_groups: vec![],
            attributes: HashMap::from([("ldap_sync".to_string(), vec!["true".to_string()])]),
            realm_roles: vec![RoleName::new("admin").unwrap()],
            client_roles: HashMap::from([(
                ClientId::new("client-1").unwrap(),
                vec![RoleName::new("app-admin").unwrap()],
            )]),
        }
    }

    fn custom_scope() -> ClientScope {
        ClientScope {
            id: ClientScopeId::new("scope-custom").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            name: "custom-scope".to_string(),
            description: Some("custom scope".to_string()),
            protocol: ClientProtocol::OpenIdConnect,
            attributes: HashMap::from([(
                "display.on.consent.screen".to_string(),
                "true".to_string(),
            )]),
            protocol_mappers: vec![ProtocolMapper {
                id: MapperId::new("mapper-custom").unwrap(),
                name: "department".to_string(),
                mapper_type: MapperType::UserAttribute,
                config: HashMap::from([
                    ("user.attribute".to_string(), "department".to_string()),
                    ("claim.name".to_string(), "department".to_string()),
                ]),
            }],
            scope_mappings: ScopeMappings {
                realm_roles: vec![RoleId::new("role-realm").unwrap()],
                client_roles: HashMap::from([(
                    ClientId::new("client-1").unwrap(),
                    vec![RoleId::new("role-client").unwrap()],
                )]),
            },
        }
    }

    fn sample_credential(id: &str, cred_type: CredentialType, priority: i32) -> Credential {
        Credential {
            id: CredentialId::new(id).unwrap(),
            credential_type: cred_type,
            user_label: Some(format!("{id}-label")),
            created_date: chrono::Utc::now(),
            secret_data: format!("{id}-secret").into_bytes(),
            credential_data: serde_json::json!({"id": id}),
            priority,
        }
    }

    fn sample_session(id: &str, realm_id: &RealmId, user_id: &UserId) -> UserSession {
        let now = chrono::Utc::now();
        UserSession {
            id: SessionId::new(id).unwrap(),
            realm_id: realm_id.clone(),
            user_id: user_id.clone(),
            login_username: Username::new("alice").unwrap(),
            ip_address: "192.168.1.10".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: vec![],
        }
    }

    fn sample_idp(id: &str, alias: &str) -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: IdentityProviderId::new(id).unwrap(),
            alias: Alias::new(alias).unwrap(),
            provider_id: ProviderId::new("oidc"),
            enabled: true,
            config: HashMap::from([
                ("clientId".to_string(), "abc".to_string()),
                ("clientSecret".to_string(), "shh".to_string()),
            ]),
        }
    }

    fn sample_flow(alias: &str, realm_id: &RealmId) -> FlowConfig {
        FlowConfig {
            alias: Alias::new(alias).unwrap(),
            realm_id: realm_id.clone(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: false,
            stages: vec![FlowStage {
                id: FlowStageId::new("stage-1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("auth-username-password-form").unwrap(),
                priority: 10,
                sub_flow_alias: None,
                authenticator_config: Some(AuthenticatorConfig {
                    alias: Alias::new("cfg").unwrap(),
                    config: serde_json::Map::from_iter([(
                        "key".to_string(),
                        serde_json::json!("value"),
                    )]),
                }),
            }],
        }
    }

    fn sample_signing_key(kid: &str) -> StoredSigningKey {
        StoredSigningKey {
            kid: KeyId::new(kid).unwrap(),
            alg: Algorithm::EdDsa,
            created_at: chrono::Utc::now(),
            private_der: vec![1, 2, 3, 4],
            public_jwk: Jwk {
                kty: JwkKty::Okp,
                kid: KeyId::new(kid).unwrap(),
                alg: Algorithm::EdDsa,
                use_: JwkUse::Sig,
                n: None,
                e: None,
                x: Some(Base64Url::new("dGVzdA").unwrap()),
                y: None,
                crv: Some(JwkCurve::Ed25519),
                k: None,
            },
            active: true,
        }
    }

    #[tokio::test]
    async fn json_storage_full_entity_roundtrip() {
        let path = unique_test_path("json-roundtrip");
        let realm_id = RealmId::new("realm-1").unwrap();
        let user_id = UserId::new("user-1").unwrap();
        let client_id = ClientId::new("client-1").unwrap();
        let now = chrono::Utc::now();

        let user = full_user(&realm_id);
        let client = full_client(&realm_id);
        let password_cred = sample_credential("cred-pw", CredentialType::Password, 1);
        let totp_cred = sample_credential("cred-totp", CredentialType::Totp, 2);
        let webauthn_cred = sample_credential("cred-webauthn", CredentialType::WebAuthn, 3);
        let mut session = sample_session("session-1", &realm_id, &user_id);
        session.remember_me = true;
        session.offline = true;
        session.impersonator = Some(UserId::new("admin-1").unwrap());
        session.clients = vec![ClientSession {
            id: ClientSessionId::new("csess-1").unwrap(),
            client_id: client_id.clone(),
            session_id: session.id.clone(),
            redirect_uri: Some(RedirectUri::new("https://app.example.com/callback").unwrap()),
            state: Some("state-123".to_string()),
            auth_method: AuthMethod::Password,
            timestamp: now,
        }];
        let realm_role = realm_role();
        let client_role = client_role();
        let parent_group = parent_group();
        let child_group = child_group();
        let consent = Consent {
            client_id: client_id.clone(),
            user_id: user_id.clone(),
            granted_scopes: Scope::parse("openid profile"),
            granted_realm_roles: vec![RoleName::new("admin").unwrap()],
            granted_client_roles: HashMap::from([(
                client_id.clone(),
                vec![RoleName::new("app-admin").unwrap()],
            )]),
            created_at: now,
            last_updated_at: now,
        };
        let idp = sample_idp("idp-1", "google");
        let idp_link = IdentityProviderLink {
            user_id: user_id.clone(),
            provider_alias: "google".to_string(),
            external_subject: "ext-sub-1".to_string(),
            external_username: Some("alice@gmail.com".to_string()),
            stored_refresh_token: Some("external-refresh-token".to_string()),
            created_at: now,
        };
        let flow = sample_flow("my-flow", &realm_id);
        let event = Event {
            id: EventId::new("event-1").unwrap(),
            realm_id: realm_id.clone(),
            event_time: now,
            event_type: EventType::Login,
            ip_address: Some("10.0.0.1".parse().unwrap()),
            client_id: Some(client_id.clone()),
            user_id: Some(user_id.clone()),
            session_id: Some(session.id.clone()),
            error: None,
            details: HashMap::from([("auth_method".to_string(), "password".to_string())]),
        };
        let admin_event = AdminEvent {
            id: EventId::new("admin-event-1").unwrap(),
            realm_id: realm_id.clone(),
            auth_realm_id: Some(realm_id.clone()),
            auth_client_id: Some(ClientId::new("admin-cli").unwrap()),
            auth_user_id: Some(UserId::new("admin-1").unwrap()),
            operation_type: OperationType::Update,
            resource_type: ResourceType::User,
            resource_path: "/realms/test-realm/users/user-1".to_string(),
            representation: Some("{\"enabled\":true}".to_string()),
            error: None,
            event_time: now,
        };
        let custom_scope = custom_scope();
        let signing_key = sample_signing_key("key-1");

        // Phase 1: populate every entity kind and persist.
        let expected_realm = {
            let storage = JsonFileStorage::new(&path).unwrap();
            storage.create_realm(&full_realm()).await.unwrap();
            storage.create_user(&realm_id, &user).await.unwrap();
            storage.create_client(&realm_id, &client).await.unwrap();
            for cred in [&password_cred, &totp_cred, &webauthn_cred] {
                storage.create_credential(&realm_id, &user_id, cred).await.unwrap();
            }
            storage.create_user_session(&realm_id, &session).await.unwrap();
            storage.create_role(&realm_id, &realm_role).await.unwrap();
            storage.create_role(&realm_id, &client_role).await.unwrap();
            storage.create_group(&realm_id, &parent_group).await.unwrap();
            storage.create_group(&realm_id, &child_group).await.unwrap();
            storage.add_user_realm_role(&realm_id, &user_id, &realm_role.id).await.unwrap();
            storage
                .add_user_client_role(&realm_id, &user_id, &client_role.id)
                .await
                .unwrap();
            storage.add_user_group(&realm_id, &user_id, &child_group.id).await.unwrap();
            storage.create_consent(&realm_id, &consent).await.unwrap();
            storage.create_identity_provider(&realm_id, &idp).await.unwrap();
            storage.create_identity_provider_link(&realm_id, &idp_link).await.unwrap();
            storage.create_flow_config(&realm_id, &flow).await.unwrap();
            storage.save_event(&realm_id, &event).await.unwrap();
            storage.save_admin_event(&admin_event).await.unwrap();
            storage.create_client_scope(&realm_id, &custom_scope).await.unwrap();
            storage
                .add_realm_default_client_scope(&realm_id, &custom_scope.id, false)
                .await
                .unwrap();
            storage.set_provision_marker("demo-seed", "v1").await.unwrap();
            storage.create_signing_key(&signing_key).await.unwrap();
            // The realm as stored (create_realm adds the pairwise sector key).
            storage.get_realm(&realm_id).await.unwrap().unwrap()
        };

        // Phase 2: reload from disk and assert every entity roundtrips.
        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let page = Pagination::default();

            // Realm
            assert!(expected_realm.pairwise_sector_key().is_some());
            assert_eq!(storage.count_realms().await.unwrap(), 1);
            assert_eq!(storage.get_realm(&realm_id).await.unwrap().unwrap(), expected_realm);
            assert_eq!(
                storage.get_realm_by_name("test-realm").await.unwrap().unwrap(),
                expected_realm
            );
            assert_eq!(storage.list_realms(&page).await.unwrap(), vec![expected_realm.clone()]);

            // User
            assert_eq!(storage.count_users(&realm_id, "").await.unwrap(), 1);
            assert_eq!(storage.get_user(&realm_id, &user_id).await.unwrap().unwrap(), user);
            assert_eq!(
                storage.get_user_by_username(&realm_id, "alice").await.unwrap().unwrap(),
                user
            );
            assert_eq!(
                storage
                    .get_user_by_email(&realm_id, "alice@example.com")
                    .await
                    .unwrap()
                    .unwrap(),
                user
            );
            assert_eq!(
                storage.get_user_by_federation_link(&realm_id, "ldap-1").await.unwrap(),
                vec![user.clone()]
            );
            assert_eq!(storage.list_users(&realm_id, "", &page).await.unwrap(), vec![user.clone()]);

            // Client
            assert_eq!(storage.count_clients(&realm_id).await.unwrap(), 1);
            assert_eq!(storage.get_client(&realm_id, &client_id).await.unwrap().unwrap(), client);
            assert_eq!(
                storage
                    .get_client_by_client_id(&realm_id, &ClientIdentifier::new("my-app").unwrap())
                    .await
                    .unwrap()
                    .unwrap(),
                client
            );
            assert_eq!(storage.list_clients(&realm_id, &page).await.unwrap(), vec![client.clone()]);

            // Credentials (list_credentials sorts by priority)
            assert_eq!(
                storage
                    .get_credentials(&realm_id, &user_id, CredentialType::Password)
                    .await
                    .unwrap(),
                vec![password_cred.clone()]
            );
            assert_eq!(
                storage
                    .get_credentials(&realm_id, &user_id, CredentialType::Totp)
                    .await
                    .unwrap(),
                vec![totp_cred.clone()]
            );
            assert_eq!(
                storage
                    .get_credentials(&realm_id, &user_id, CredentialType::WebAuthn)
                    .await
                    .unwrap(),
                vec![webauthn_cred.clone()]
            );
            assert_eq!(
                storage.list_credentials(&realm_id, &user_id).await.unwrap(),
                vec![
                    password_cred.clone(),
                    totp_cred.clone(),
                    webauthn_cred.clone()
                ]
            );

            // Sessions (incl. the client session inside the user session)
            assert_eq!(storage.count_sessions(&realm_id, None).await.unwrap(), 1);
            assert_eq!(storage.count_sessions(&realm_id, Some(user_id.clone())).await.unwrap(), 1);
            assert_eq!(
                storage.get_user_session(&realm_id, &session.id).await.unwrap().unwrap(),
                session
            );
            assert_eq!(
                storage.list_sessions(&realm_id, None, &page).await.unwrap(),
                vec![session.clone()]
            );
            assert_eq!(
                storage.list_sessions(&realm_id, Some(user_id.clone()), &page).await.unwrap(),
                vec![session.clone()]
            );

            // Roles (list_roles sorts by name: admin < app-admin)
            assert_eq!(storage.count_roles(&realm_id).await.unwrap(), 2);
            assert_eq!(
                storage.get_role(&realm_id, &realm_role.id).await.unwrap().unwrap(),
                realm_role
            );
            assert_eq!(
                storage.get_role_by_name(&realm_id, "admin").await.unwrap().unwrap(),
                realm_role
            );
            assert_eq!(
                storage.list_roles(&realm_id, &page).await.unwrap(),
                vec![realm_role.clone(), client_role.clone()]
            );
            assert_eq!(
                storage
                    .get_client_role_by_name(&realm_id, &client_id, "app-admin")
                    .await
                    .unwrap()
                    .unwrap(),
                client_role
            );
            assert_eq!(
                storage.list_client_roles(&realm_id, &client_id, &page).await.unwrap(),
                vec![client_role.clone()]
            );

            // Groups
            assert_eq!(storage.count_groups(&realm_id).await.unwrap(), 2);
            assert_eq!(
                storage.get_group(&realm_id, &parent_group.id).await.unwrap().unwrap(),
                parent_group
            );
            assert_eq!(
                storage.get_group(&realm_id, &child_group.id).await.unwrap().unwrap(),
                child_group
            );
            assert_eq!(
                storage.get_group_by_name(&realm_id, "admins").await.unwrap().unwrap(),
                parent_group
            );
            let mut groups = storage.list_groups(&realm_id, &page).await.unwrap();
            groups.sort_by(|a, b| a.id.as_ref().cmp(b.id.as_ref()));
            let mut expected_groups = vec![parent_group.clone(), child_group.clone()];
            expected_groups.sort_by(|a, b| a.id.as_ref().cmp(b.id.as_ref()));
            assert_eq!(groups, expected_groups);

            // Role & group memberships
            assert_eq!(
                storage.list_user_realm_roles(&realm_id, &user_id).await.unwrap(),
                vec![realm_role.id.clone()]
            );
            assert_eq!(
                storage.list_user_client_roles(&realm_id, &user_id).await.unwrap(),
                vec![client_role.id.clone()]
            );
            assert_eq!(
                storage.list_user_groups(&realm_id, &user_id).await.unwrap(),
                vec![child_group.id.clone()]
            );
            assert_eq!(
                storage.list_group_members(&realm_id, &child_group.id, 0, 10).await.unwrap(),
                vec![user.clone()]
            );

            // Consent
            assert_eq!(
                storage.get_consents(&realm_id, &user_id).await.unwrap(),
                vec![consent.clone()]
            );

            // Identity providers + links
            assert_eq!(
                storage.get_identity_provider(&realm_id, &idp.id).await.unwrap().unwrap(),
                idp
            );
            assert_eq!(
                storage
                    .get_identity_provider_by_alias(&realm_id, "google")
                    .await
                    .unwrap()
                    .unwrap(),
                idp
            );
            assert_eq!(
                storage.list_identity_providers(&realm_id).await.unwrap(),
                vec![idp.clone()]
            );
            assert_eq!(
                storage
                    .get_identity_provider_link(&realm_id, "google", "ext-sub-1")
                    .await
                    .unwrap()
                    .unwrap(),
                idp_link
            );
            assert_eq!(
                storage
                    .get_identity_provider_link_for_user(&realm_id, &user_id, "google")
                    .await
                    .unwrap()
                    .unwrap(),
                idp_link
            );
            assert_eq!(
                storage.list_identity_provider_links(&realm_id, &user_id).await.unwrap(),
                vec![idp_link.clone()]
            );

            // Flows (two built-ins seeded at realm creation + the custom one)
            assert_eq!(storage.get_flow_config(&realm_id, "my-flow").await.unwrap().unwrap(), flow);
            let flow_aliases: Vec<String> = storage
                .list_flow_configs(&realm_id)
                .await
                .unwrap()
                .iter()
                .map(|f| f.alias.to_string())
                .collect();
            assert_eq!(
                flow_aliases,
                vec![
                    "browser".to_string(),
                    "my-flow".to_string(),
                    "registration".to_string()
                ]
            );

            // Events + admin events
            let event_query = EventQuery {
                event_type: None,
                client_id: None,
                user_id: None,
                date_from: None,
                date_to: None,
                pagination: Pagination::default(),
            };
            assert_eq!(
                storage.query_events(&realm_id, &event_query).await.unwrap(),
                vec![event.clone()]
            );
            assert_eq!(storage.count_events(&realm_id, &event_query).await.unwrap(), 1);
            let admin_query = AdminEventQuery {
                operation_type: None,
                resource_type: None,
                auth_user_id: None,
                date_from: None,
                date_to: None,
                pagination: Pagination::default(),
            };
            assert_eq!(
                storage.query_admin_events(&realm_id, &admin_query).await.unwrap(),
                vec![admin_event.clone()]
            );
            assert_eq!(storage.count_admin_events(&realm_id, &admin_query).await.unwrap(), 1);

            // Provision markers
            assert_eq!(
                storage.get_provision_marker("demo-seed").await.unwrap(),
                Some("v1".to_string())
            );
            assert_eq!(storage.get_provision_marker("never-set").await.unwrap(), None);

            // Signing keys
            assert_eq!(storage.list_signing_keys().await.unwrap(), vec![signing_key.clone()]);

            // Client scopes: 8 built-ins + the custom one
            let scopes = storage.list_client_scopes(&realm_id, &page).await.unwrap();
            assert_eq!(scopes.len(), 9);
            assert_eq!(
                storage.get_client_scope(&realm_id, &custom_scope.id).await.unwrap().unwrap(),
                custom_scope
            );
            assert_eq!(
                storage
                    .get_client_scope_by_name(&realm_id, "custom-scope")
                    .await
                    .unwrap()
                    .unwrap(),
                custom_scope
            );

            // Scope assignments seeded from the client's scope lists plus the
            // `roles` carve-out: profile+email default, offline_access
            // optional, roles default.
            let id_of = |name: &str| scopes.iter().find(|s| s.name == name).unwrap().id.clone();
            let mut assignments =
                storage.list_client_scope_assignments(&realm_id, &client_id).await.unwrap();
            assignments.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
            let mut expected_assignments = vec![
                (id_of("profile"), true),
                (id_of("email"), true),
                (id_of("offline_access"), false),
                (id_of("roles"), true),
            ];
            expected_assignments.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
            assert_eq!(assignments, expected_assignments);

            // Realm default scopes: 8 built-ins + the custom optional one.
            let defaults = storage.list_realm_default_client_scopes(&realm_id).await.unwrap();
            assert_eq!(defaults.len(), 9);
            assert!(defaults.contains(&(custom_scope.id.clone(), false)));
        }

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn json_storage_updates_and_deletes_survive_reload() {
        let path = unique_test_path("json-update-delete");
        let realm_id = RealmId::new("realm-1").unwrap();
        let user_id = UserId::new("user-1").unwrap();
        let client_id = ClientId::new("client-1").unwrap();
        let now = chrono::Utc::now();

        // Updated entities (constructed values asserted after reload).
        let mut updated_client = full_client(&realm_id);
        updated_client.name = Some(DisplayName::new("Renamed App").unwrap());
        updated_client.consent_required = false;
        let mut updated_cred = sample_credential("cred-1", CredentialType::Password, 1);
        updated_cred.priority = 42;
        updated_cred.user_label = Some("renamed".to_string());
        let mut updated_session = sample_session("session-1", &realm_id, &user_id);
        updated_session.remember_me = true;
        updated_session.offline = true;
        let mut updated_role = realm_role();
        updated_role.description = Some("updated description".to_string());
        updated_role.composites = vec![RoleName::new("base").unwrap(), RoleName::new("x").unwrap()];
        let mut updated_group = parent_group();
        updated_group.attributes = HashMap::from([("k".to_string(), vec!["v".to_string()])]);
        updated_group.realm_roles = vec![RoleName::new("admin").unwrap()];
        let mut updated_idp = sample_idp("idp-1", "google");
        updated_idp.enabled = false;
        updated_idp.config = HashMap::from([("k".to_string(), "v".to_string())]);
        let mut updated_flow = sample_flow("upd-flow", &realm_id);
        updated_flow.top_level = false;
        updated_flow.provider_id = "custom-flow".to_string();
        let mut updated_scope = custom_scope();
        updated_scope.description = Some("v2".to_string());
        let signing_key = sample_signing_key("key-1");
        let mut updated_key = signing_key.clone();
        updated_key.active = false;

        let expected_realm = {
            let storage = JsonFileStorage::new(&path).unwrap();
            storage.create_realm(&full_realm()).await.unwrap();
            storage.create_user(&realm_id, &full_user(&realm_id)).await.unwrap();
            storage.create_client(&realm_id, &full_client(&realm_id)).await.unwrap();

            // ---------------------- update paths ----------------------
            let mut realm = storage.get_realm(&realm_id).await.unwrap().unwrap();
            realm.display_name = Some(DisplayName::new("Updated Realm").unwrap());
            storage.update_realm(&realm).await.unwrap();

            let mut user = full_user(&realm_id);
            user.first_name = Some(DisplayName::new("Updated").unwrap());
            storage.update_user(&realm_id, &user).await.unwrap();

            storage.update_client(&realm_id, &updated_client).await.unwrap();

            let cred = sample_credential("cred-1", CredentialType::Password, 1);
            storage.create_credential(&realm_id, &user_id, &cred).await.unwrap();
            storage.update_credential(&realm_id, &user_id, &updated_cred).await.unwrap();

            let session = sample_session("session-1", &realm_id, &user_id);
            storage.create_user_session(&realm_id, &session).await.unwrap();
            storage.update_user_session(&realm_id, &updated_session).await.unwrap();

            storage.create_role(&realm_id, &realm_role()).await.unwrap();
            storage.create_role(&realm_id, &client_role()).await.unwrap();
            storage.update_role(&realm_id, &updated_role).await.unwrap();

            storage.create_group(&realm_id, &parent_group()).await.unwrap();
            storage.update_group(&realm_id, &updated_group).await.unwrap();

            storage
                .create_identity_provider(&realm_id, &sample_idp("idp-1", "google"))
                .await
                .unwrap();
            storage.update_identity_provider(&realm_id, &updated_idp).await.unwrap();

            storage
                .create_flow_config(&realm_id, &sample_flow("upd-flow", &realm_id))
                .await
                .unwrap();
            storage.update_flow_config(&realm_id, &updated_flow).await.unwrap();

            storage.create_client_scope(&realm_id, &custom_scope()).await.unwrap();
            storage.update_client_scope(&realm_id, &updated_scope).await.unwrap();

            storage.create_signing_key(&signing_key).await.unwrap();
            storage.update_signing_key(&updated_key).await.unwrap();

            // ---------------------- delete paths ----------------------
            let mut user2 = full_user(&realm_id);
            user2.id = UserId::new("user-2").unwrap();
            user2.username = Username::new("bob").unwrap();
            user2.email = None;
            storage.create_user(&realm_id, &user2).await.unwrap();
            storage.delete_user(&realm_id, &user2.id).await.unwrap();

            let mut client2 = full_client(&realm_id);
            client2.id = ClientId::new("client-2").unwrap();
            client2.client_id = ClientIdentifier::new("temp-app").unwrap();
            storage.create_client(&realm_id, &client2).await.unwrap();
            storage.delete_client(&realm_id, &client2.id).await.unwrap();

            let cred2 = sample_credential("cred-2", CredentialType::Totp, 9);
            storage.create_credential(&realm_id, &user_id, &cred2).await.unwrap();
            storage.delete_credential(&realm_id, &user_id, &cred2.id).await.unwrap();

            let session2 = sample_session("session-2", &realm_id, &user_id);
            storage.create_user_session(&realm_id, &session2).await.unwrap();
            storage.delete_user_session(&realm_id, &session2.id).await.unwrap();

            let role2 = Role {
                id: RoleId::new("role-temp").unwrap(),
                name: RoleName::new("temprole").unwrap(),
                description: None,
                realm_id: realm_id.clone(),
                client_role: false,
                client_id: None,
                composite: false,
                composites: vec![],
                attributes: HashMap::new(),
            };
            storage.create_role(&realm_id, &role2).await.unwrap();
            storage.delete_role(&realm_id, &role2.id).await.unwrap();

            let group2 = Group {
                id: GroupId::new("group-temp").unwrap(),
                name: GroupName::new("tempgroup").unwrap(),
                path: GroupPath::new("/tempgroup").unwrap(),
                realm_id: realm_id.clone(),
                parent_id: None,
                sub_groups: vec![],
                attributes: HashMap::new(),
                realm_roles: vec![],
                client_roles: HashMap::new(),
            };
            storage.create_group(&realm_id, &group2).await.unwrap();
            storage.delete_group(&realm_id, &group2.id).await.unwrap();

            let consent = Consent {
                client_id: client_id.clone(),
                user_id: user_id.clone(),
                granted_scopes: Scope::parse("openid"),
                granted_realm_roles: vec![],
                granted_client_roles: HashMap::new(),
                created_at: now,
                last_updated_at: now,
            };
            storage.create_consent(&realm_id, &consent).await.unwrap();
            storage.delete_consent(&realm_id, &user_id, &consent.client_id).await.unwrap();

            let idp_link = IdentityProviderLink {
                user_id: user_id.clone(),
                provider_alias: "google".to_string(),
                external_subject: "ext-sub-1".to_string(),
                external_username: None,
                stored_refresh_token: None,
                created_at: now,
            };
            storage.create_identity_provider_link(&realm_id, &idp_link).await.unwrap();
            storage
                .delete_identity_provider_link(&realm_id, &user_id, "google")
                .await
                .unwrap();

            storage
                .create_identity_provider(&realm_id, &sample_idp("idp-temp", "temp-idp"))
                .await
                .unwrap();
            storage
                .delete_identity_provider(&realm_id, &IdentityProviderId::new("idp-temp").unwrap())
                .await
                .unwrap();

            storage
                .create_flow_config(&realm_id, &sample_flow("temp-flow", &realm_id))
                .await
                .unwrap();
            storage.delete_flow_config(&realm_id, "temp-flow").await.unwrap();

            let event = Event {
                id: EventId::new("event-1").unwrap(),
                realm_id: realm_id.clone(),
                event_time: now,
                event_type: EventType::Login,
                ip_address: None,
                client_id: None,
                user_id: None,
                session_id: None,
                error: None,
                details: HashMap::new(),
            };
            storage.save_event(&realm_id, &event).await.unwrap();
            storage.delete_events(&realm_id).await.unwrap();
            let admin_event = AdminEvent {
                id: EventId::new("admin-1").unwrap(),
                realm_id: realm_id.clone(),
                auth_realm_id: None,
                auth_client_id: None,
                auth_user_id: None,
                operation_type: OperationType::Create,
                resource_type: ResourceType::Realm,
                resource_path: "/".to_string(),
                representation: None,
                error: None,
                event_time: now,
            };
            storage.save_admin_event(&admin_event).await.unwrap();
            storage.delete_admin_events(&realm_id).await.unwrap();

            let temp_scope = ClientScope {
                id: ClientScopeId::new("scope-temp").unwrap(),
                realm_id: realm_id.clone(),
                name: "temp-scope".to_string(),
                description: None,
                protocol: ClientProtocol::OpenIdConnect,
                attributes: HashMap::new(),
                protocol_mappers: vec![],
                scope_mappings: ScopeMappings::default(),
            };
            storage.create_client_scope(&realm_id, &temp_scope).await.unwrap();
            storage.delete_client_scope(&realm_id, &temp_scope.id).await.unwrap();

            // Assign then unassign a scope that is NOT in the client's string
            // lists (those would be re-seeded on load by design).
            storage
                .assign_client_scope(&realm_id, &client_id, &updated_scope.id, true)
                .await
                .unwrap();
            storage
                .unassign_client_scope(&realm_id, &client_id, &updated_scope.id)
                .await
                .unwrap();

            // Add then remove a realm default (custom scopes are not re-seeded).
            storage
                .add_realm_default_client_scope(&realm_id, &updated_scope.id, false)
                .await
                .unwrap();
            storage
                .remove_realm_default_client_scope(&realm_id, &updated_scope.id)
                .await
                .unwrap();

            // Add then remove memberships.
            storage
                .add_user_realm_role(&realm_id, &user_id, &updated_role.id)
                .await
                .unwrap();
            storage
                .remove_user_realm_role(&realm_id, &user_id, &updated_role.id)
                .await
                .unwrap();
            let client_role = client_role();
            storage
                .add_user_client_role(&realm_id, &user_id, &client_role.id)
                .await
                .unwrap();
            storage
                .remove_user_client_role(&realm_id, &user_id, &client_role.id)
                .await
                .unwrap();
            storage.add_user_group(&realm_id, &user_id, &updated_group.id).await.unwrap();
            storage.remove_user_group(&realm_id, &user_id, &updated_group.id).await.unwrap();

            realm
        };

        // Phase 2: reload from disk and assert.
        {
            let storage = JsonFileStorage::new(&path).unwrap();

            // Updated entities survived the reload.
            assert_eq!(storage.get_realm(&realm_id).await.unwrap().unwrap(), expected_realm);
            let user = storage.get_user(&realm_id, &user_id).await.unwrap().unwrap();
            assert_eq!(user.first_name, Some(DisplayName::new("Updated").unwrap()));
            assert_eq!(user.last_name, Some(DisplayName::new("Smith").unwrap()));
            assert_eq!(
                storage.get_client(&realm_id, &client_id).await.unwrap().unwrap(),
                updated_client
            );
            assert_eq!(
                storage
                    .get_credentials(&realm_id, &user_id, CredentialType::Password)
                    .await
                    .unwrap(),
                vec![updated_cred.clone()]
            );
            assert_eq!(
                storage.get_user_session(&realm_id, &updated_session.id).await.unwrap().unwrap(),
                updated_session
            );
            assert_eq!(
                storage.get_role(&realm_id, &updated_role.id).await.unwrap().unwrap(),
                updated_role
            );
            assert_eq!(
                storage.get_group(&realm_id, &updated_group.id).await.unwrap().unwrap(),
                updated_group
            );
            assert_eq!(
                storage
                    .get_identity_provider(&realm_id, &updated_idp.id)
                    .await
                    .unwrap()
                    .unwrap(),
                updated_idp
            );
            assert_eq!(
                storage.get_flow_config(&realm_id, "upd-flow").await.unwrap().unwrap(),
                updated_flow
            );
            assert_eq!(
                storage.get_client_scope(&realm_id, &updated_scope.id).await.unwrap().unwrap(),
                updated_scope
            );
            assert_eq!(storage.list_signing_keys().await.unwrap(), vec![updated_key.clone()]);

            // Deleted entities stayed deleted.
            assert_eq!(storage.count_users(&realm_id, "").await.unwrap(), 1);
            assert!(storage
                .get_user(&realm_id, &UserId::new("user-2").unwrap())
                .await
                .unwrap()
                .is_none());
            assert_eq!(storage.count_clients(&realm_id).await.unwrap(), 1);
            assert!(storage
                .get_client(&realm_id, &ClientId::new("client-2").unwrap())
                .await
                .unwrap()
                .is_none());
            assert!(storage
                .get_credentials(&realm_id, &user_id, CredentialType::Totp)
                .await
                .unwrap()
                .is_empty());
            assert!(storage
                .get_user_session(&realm_id, &SessionId::new("session-2").unwrap())
                .await
                .unwrap()
                .is_none());
            assert!(storage
                .get_role(&realm_id, &RoleId::new("role-temp").unwrap())
                .await
                .unwrap()
                .is_none());
            assert!(storage
                .get_group(&realm_id, &GroupId::new("group-temp").unwrap())
                .await
                .unwrap()
                .is_none());
            assert!(storage.get_consents(&realm_id, &user_id).await.unwrap().is_empty());
            assert!(storage
                .get_identity_provider_link(&realm_id, "google", "ext-sub-1")
                .await
                .unwrap()
                .is_none());
            assert!(storage
                .get_identity_provider_by_alias(&realm_id, "temp-idp")
                .await
                .unwrap()
                .is_none());
            assert!(storage.get_flow_config(&realm_id, "temp-flow").await.unwrap().is_none());
            let event_query = EventQuery {
                event_type: None,
                client_id: None,
                user_id: None,
                date_from: None,
                date_to: None,
                pagination: Pagination::default(),
            };
            assert!(storage.query_events(&realm_id, &event_query).await.unwrap().is_empty());
            assert_eq!(storage.count_events(&realm_id, &event_query).await.unwrap(), 0);
            let admin_query = AdminEventQuery {
                operation_type: None,
                resource_type: None,
                auth_user_id: None,
                date_from: None,
                date_to: None,
                pagination: Pagination::default(),
            };
            assert!(storage.query_admin_events(&realm_id, &admin_query).await.unwrap().is_empty());
            assert_eq!(storage.count_admin_events(&realm_id, &admin_query).await.unwrap(), 0);
            assert!(storage
                .get_client_scope_by_name(&realm_id, "temp-scope")
                .await
                .unwrap()
                .is_none());

            // The unassigned scope did not come back; the seeded assignments
            // from the client's scope lists (+ `roles` carve-out) remain.
            let assignments =
                storage.list_client_scope_assignments(&realm_id, &client_id).await.unwrap();
            assert!(!assignments.iter().any(|(id, _)| id == &updated_scope.id));
            assert_eq!(assignments.len(), 4);

            // The removed realm default stayed removed (8 built-ins remain).
            let defaults = storage.list_realm_default_client_scopes(&realm_id).await.unwrap();
            assert_eq!(defaults.len(), 8);
            assert!(!defaults.iter().any(|(id, _)| id == &updated_scope.id));

            // Removed memberships stayed removed.
            assert!(storage.list_user_realm_roles(&realm_id, &user_id).await.unwrap().is_empty());
            assert!(storage.list_user_client_roles(&realm_id, &user_id).await.unwrap().is_empty());
            assert!(storage.list_user_groups(&realm_id, &user_id).await.unwrap().is_empty());

            // Flow list: 2 built-ins + the updated custom flow; roles: realm
            // role + client role (the temp role was deleted).
            assert_eq!(storage.list_flow_configs(&realm_id).await.unwrap().len(), 3);
            assert_eq!(storage.count_roles(&realm_id).await.unwrap(), 2);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn json_storage_counts_track_actual_entities() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("issuerd-json-test-{}.json", uuid::Uuid::new_v4()));

        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let realm_id = RealmId::new("realm-1").unwrap();
            let realm2_id = RealmId::new("realm-2").unwrap();

            // Empty storage: every count is zero.
            assert_eq!(storage.count_realms().await.unwrap(), 0);
            assert_eq!(storage.count_users(&realm_id, "").await.unwrap(), 0);
            assert_eq!(storage.count_clients(&realm_id).await.unwrap(), 0);
            assert_eq!(storage.count_sessions(&realm_id, None).await.unwrap(), 0);

            let mut realm2 = test_realm();
            realm2.id = realm2_id.clone();
            realm2.name = RealmName::new("test-realm-2").unwrap();
            storage.create_realm(&test_realm()).await.unwrap();
            storage.create_realm(&realm2).await.unwrap();
            assert_eq!(storage.count_realms().await.unwrap(), 2);

            let user1 = test_user();
            let mut user2 = test_user();
            user2.id = UserId::new("user-2").unwrap();
            user2.username = Username::new("bob").unwrap();
            storage.create_user(&realm_id, &user1).await.unwrap();
            storage.create_user(&realm_id, &user2).await.unwrap();
            assert_eq!(storage.count_users(&realm_id, "").await.unwrap(), 2);
            assert_eq!(storage.count_users(&realm2_id, "").await.unwrap(), 0);

            let client1 = full_client(&realm_id);
            let mut client2 = full_client(&realm_id);
            client2.id = ClientId::new("client-2").unwrap();
            client2.client_id = ClientIdentifier::new("second-app").unwrap();
            storage.create_client(&realm_id, &client1).await.unwrap();
            storage.create_client(&realm_id, &client2).await.unwrap();
            assert_eq!(storage.count_clients(&realm_id).await.unwrap(), 2);
            assert_eq!(storage.count_clients(&realm2_id).await.unwrap(), 0);

            let session1 = sample_session("session-1", &realm_id, &user1.id);
            let session2 = sample_session("session-2", &realm_id, &user2.id);
            storage.create_user_session(&realm_id, &session1).await.unwrap();
            storage.create_user_session(&realm_id, &session2).await.unwrap();
            assert_eq!(storage.count_sessions(&realm_id, None).await.unwrap(), 2);
            assert_eq!(storage.count_sessions(&realm_id, Some(user1.id.clone())).await.unwrap(), 1);
            assert_eq!(storage.count_sessions(&realm2_id, None).await.unwrap(), 0);
        }

        // The counts agree after a reload from disk.
        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let realm_id = RealmId::new("realm-1").unwrap();
            assert_eq!(storage.count_realms().await.unwrap(), 2);
            assert_eq!(storage.count_users(&realm_id, "").await.unwrap(), 2);
            assert_eq!(storage.count_clients(&realm_id).await.unwrap(), 2);
            assert_eq!(storage.count_sessions(&realm_id, None).await.unwrap(), 2);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn json_storage_assign_client_scope_persists() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("issuerd-json-test-{}.json", uuid::Uuid::new_v4()));
        let realm_id = RealmId::new("realm-1").unwrap();
        let client_id = ClientId::new("client-1").unwrap();
        let scope = custom_scope();

        {
            let storage = JsonFileStorage::new(&path).unwrap();
            storage.create_realm(&test_realm()).await.unwrap();
            storage.create_client(&realm_id, &full_client(&realm_id)).await.unwrap();
            storage.create_client_scope(&realm_id, &scope).await.unwrap();

            storage
                .assign_client_scope(&realm_id, &client_id, &scope.id, false)
                .await
                .unwrap();
            let assignments =
                storage.list_client_scope_assignments(&realm_id, &client_id).await.unwrap();
            assert!(assignments.contains(&(scope.id.clone(), false)));
        }

        // The assignment survives a reload from disk.
        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let assignments =
                storage.list_client_scope_assignments(&realm_id, &client_id).await.unwrap();
            assert!(assignments.contains(&(scope.id.clone(), false)));
        }

        let _ = std::fs::remove_file(&path);
    }
}
