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
}
