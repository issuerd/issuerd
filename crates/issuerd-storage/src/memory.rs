// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// In-memory DashMap-backed Storage implementation for tests and dev.

use async_trait::async_trait;
use dashmap::DashMap;
use issuerd_core::*;
use serde::{Deserialize, Serialize};

/// In-memory storage implementation for testing.
pub struct InMemoryStorage {
    realms: DashMap<RealmId, Realm>,
    users: DashMap<(RealmId, UserId), User>,
    clients: DashMap<(RealmId, ClientId), Client>,
    credentials: DashMap<(RealmId, UserId, String), Vec<Credential>>,
    sessions: DashMap<(RealmId, SessionId), UserSession>,
    roles: DashMap<(RealmId, RoleId), Role>,
    groups: DashMap<(RealmId, GroupId), Group>,
    consents: DashMap<(RealmId, UserId, ClientId), Consent>,
    identity_providers: DashMap<(RealmId, IdentityProviderId), IdentityProviderConfig>,
    /// Brokered-login account links, keyed by (realm, alias, external subject).
    identity_provider_links: DashMap<(RealmId, String, String), IdentityProviderLink>,
    flow_configs: DashMap<(RealmId, Alias), FlowConfig>,
    events: std::sync::RwLock<Vec<Event>>,
    #[allow(dead_code)]
    admin_events: std::sync::RwLock<Vec<AdminEvent>>,
    user_realm_roles: DashMap<(RealmId, UserId), Vec<RoleId>>,
    user_client_roles: DashMap<(RealmId, UserId), Vec<RoleId>>,
    user_groups: DashMap<(RealmId, UserId), Vec<GroupId>>,
    client_scopes: DashMap<(RealmId, ClientScopeId), ClientScope>,
    /// Per-client scope assignments as `(scope_id, is_default)` pairs.
    client_scope_assignments: DashMap<(RealmId, ClientId), Vec<(ClientScopeId, bool)>>,
    /// Realm default scopes as `(scope_id, is_default)` pairs.
    realm_default_client_scopes: DashMap<RealmId, Vec<(ClientScopeId, bool)>>,
    provision_markers: DashMap<String, String>,
    signing_keys: DashMap<String, StoredSigningKey>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            realms: DashMap::new(),
            users: DashMap::new(),
            clients: DashMap::new(),
            credentials: DashMap::new(),
            sessions: DashMap::new(),
            roles: DashMap::new(),
            groups: DashMap::new(),
            consents: DashMap::new(),
            identity_providers: DashMap::new(),
            identity_provider_links: DashMap::new(),
            flow_configs: DashMap::new(),
            events: std::sync::RwLock::new(Vec::new()),
            admin_events: std::sync::RwLock::new(Vec::new()),
            user_realm_roles: DashMap::new(),
            user_client_roles: DashMap::new(),
            user_groups: DashMap::new(),
            client_scopes: DashMap::new(),
            client_scope_assignments: DashMap::new(),
            realm_default_client_scopes: DashMap::new(),
            provision_markers: DashMap::new(),
            signing_keys: DashMap::new(),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JSON snapshot (used by JsonFileStorage)
// ---------------------------------------------------------------------------

/// Snapshot entry for per-client scope assignments: `(realm, client)` mapped
/// to its `(scope, is_default)` pairs.
type ClientScopeAssignmentEntry = ((RealmId, ClientId), Vec<(ClientScopeId, bool)>);

#[derive(Serialize, Deserialize)]
pub(crate) struct StorageSnapshot {
    pub realms: Vec<Realm>,
    pub users: Vec<User>,
    pub clients: Vec<Client>,
    pub credentials: Vec<((RealmId, UserId, String), Vec<Credential>)>,
    pub sessions: Vec<UserSession>,
    pub roles: Vec<Role>,
    pub groups: Vec<Group>,
    pub consents: Vec<((RealmId, UserId, ClientId), Consent)>,
    pub identity_providers: Vec<((RealmId, IdentityProviderId), IdentityProviderConfig)>,
    /// Keyed by (realm, alias, external subject). `default` keeps snapshots
    /// written before identity-provider links existed loadable.
    #[serde(default)]
    pub identity_provider_links: Vec<((RealmId, String, String), IdentityProviderLink)>,
    pub flow_configs: Vec<FlowConfig>,
    pub events: Vec<Event>,
    pub admin_events: Vec<AdminEvent>,
    pub user_realm_roles: Vec<((RealmId, UserId), Vec<RoleId>)>,
    pub user_groups: Vec<((RealmId, UserId), Vec<GroupId>)>,
    /// The `default`s keep snapshots written before client scopes existed loadable.
    #[serde(default)]
    pub client_scopes: Vec<ClientScope>,
    #[serde(default)]
    pub client_scope_assignments: Vec<ClientScopeAssignmentEntry>,
    #[serde(default)]
    pub realm_default_client_scopes: Vec<(RealmId, Vec<(ClientScopeId, bool)>)>,
    #[serde(default)]
    pub user_client_roles: Vec<((RealmId, UserId), Vec<RoleId>)>,
    pub provision_markers: Vec<(String, String)>,
    pub signing_keys: Vec<StoredSigningKey>,
}

impl InMemoryStorage {
    pub(crate) fn to_snapshot(&self) -> StorageSnapshot {
        StorageSnapshot {
            realms: self.realms.iter().map(|r| r.clone()).collect(),
            users: self.users.iter().map(|u| u.clone()).collect(),
            clients: self.clients.iter().map(|c| c.clone()).collect(),
            credentials: self
                .credentials
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            sessions: self.sessions.iter().map(|s| s.clone()).collect(),
            roles: self.roles.iter().map(|r| r.clone()).collect(),
            groups: self.groups.iter().map(|g| g.clone()).collect(),
            consents: self.consents.iter().map(|e| (e.key().clone(), e.value().clone())).collect(),
            identity_providers: self
                .identity_providers
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            identity_provider_links: self
                .identity_provider_links
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            flow_configs: self.flow_configs.iter().map(|f| f.clone()).collect(),
            events: self.events.read().unwrap().clone(),
            admin_events: self.admin_events.read().unwrap().clone(),
            user_realm_roles: self
                .user_realm_roles
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            user_groups: self
                .user_groups
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            client_scopes: self.client_scopes.iter().map(|s| s.clone()).collect(),
            client_scope_assignments: self
                .client_scope_assignments
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            realm_default_client_scopes: self
                .realm_default_client_scopes
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            user_client_roles: self
                .user_client_roles
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            provision_markers: self
                .provision_markers
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            signing_keys: self.signing_keys.iter().map(|k| k.clone()).collect(),
        }
    }

    pub(crate) fn load_snapshot(&self, snapshot: StorageSnapshot) {
        self.realms.clear();
        for r in snapshot.realms {
            self.realms.insert(r.id.clone(), r);
        }

        self.users.clear();
        for u in snapshot.users {
            self.users.insert((u.realm_id.clone(), u.id.clone()), u);
        }

        self.clients.clear();
        for c in snapshot.clients {
            self.clients.insert((c.realm_id.clone(), c.id.clone()), c);
        }

        self.credentials.clear();
        for (k, v) in snapshot.credentials {
            self.credentials.insert(k, v);
        }

        self.sessions.clear();
        for s in snapshot.sessions {
            self.sessions.insert((s.realm_id.clone(), s.id.clone()), s);
        }

        self.roles.clear();
        for r in snapshot.roles {
            self.roles.insert((r.realm_id.clone(), r.id.clone()), r);
        }

        self.groups.clear();
        for g in snapshot.groups {
            self.groups.insert((g.realm_id.clone(), g.id.clone()), g);
        }

        self.consents.clear();
        for (k, v) in snapshot.consents {
            self.consents.insert(k, v);
        }

        self.identity_providers.clear();
        for (k, v) in snapshot.identity_providers {
            self.identity_providers.insert(k, v);
        }

        self.identity_provider_links.clear();
        for (k, v) in snapshot.identity_provider_links {
            self.identity_provider_links.insert(k, v);
        }

        self.flow_configs.clear();
        for f in snapshot.flow_configs {
            self.flow_configs.insert((f.realm_id.clone(), f.alias.clone()), f);
        }

        *self.events.write().unwrap() = snapshot.events;
        *self.admin_events.write().unwrap() = snapshot.admin_events;

        self.user_realm_roles.clear();
        for (k, v) in snapshot.user_realm_roles {
            self.user_realm_roles.insert(k, v);
        }

        self.user_groups.clear();
        for (k, v) in snapshot.user_groups {
            self.user_groups.insert(k, v);
        }

        self.client_scopes.clear();
        for s in snapshot.client_scopes {
            self.client_scopes.insert((s.realm_id.clone(), s.id.clone()), s);
        }

        self.client_scope_assignments.clear();
        for (k, v) in snapshot.client_scope_assignments {
            self.client_scope_assignments.insert(k, v);
        }

        self.realm_default_client_scopes.clear();
        for (k, v) in snapshot.realm_default_client_scopes {
            self.realm_default_client_scopes.insert(k, v);
        }

        self.user_client_roles.clear();
        for (k, v) in snapshot.user_client_roles {
            self.user_client_roles.insert(k, v);
        }

        self.provision_markers.clear();
        for (k, v) in snapshot.provision_markers {
            self.provision_markers.insert(k, v);
        }

        self.signing_keys.clear();
        for k in snapshot.signing_keys {
            self.signing_keys.insert(k.kid.to_string(), k);
        }
    }
}

/// Shared event filter predicate used by both `query_events` and
/// `count_events` so the total always matches the filtered list.
fn event_matches(e: &Event, realm: &RealmId, query: &EventQuery) -> bool {
    e.realm_id == *realm
        && query.event_type.as_ref().is_none_or(|et| e.event_type == *et)
        && query.date_from.is_none_or(|from| e.event_time >= from)
        && query.date_to.is_none_or(|to| e.event_time <= to)
        && query.client_id.as_ref().is_none_or(|cid| e.client_id.as_ref() == Some(cid))
        && query.user_id.as_ref().is_none_or(|uid| e.user_id.as_ref() == Some(uid))
}

/// Shared admin-event filter predicate used by both `query_admin_events` and
/// `count_admin_events` so the total always matches the filtered list.
fn admin_event_matches(e: &AdminEvent, realm: &RealmId, query: &AdminEventQuery) -> bool {
    e.realm_id == *realm
        && query.operation_type.as_ref().is_none_or(|ot| e.operation_type == *ot)
        && query.resource_type.as_ref().is_none_or(|rt| e.resource_type == *rt)
        && query
            .auth_user_id
            .as_ref()
            .is_none_or(|uid| e.auth_user_id.as_ref() == Some(uid))
        && query.date_from.is_none_or(|from| e.event_time >= from)
        && query.date_to.is_none_or(|to| e.event_time <= to)
}

#[async_trait]
impl Storage for InMemoryStorage {
    // ------------------------------------------------------------------
    // Realm
    // ------------------------------------------------------------------
    async fn get_realm(&self, id: &RealmId) -> Result<Option<Realm>, IssuerdError> {
        Ok(self.realms.get(id).map(|r| r.clone()))
    }

    async fn get_realm_by_name(&self, name: &str) -> Result<Option<Realm>, IssuerdError> {
        Ok(self.realms.iter().find(|r| r.value().name == name).map(|r| r.clone()))
    }

    async fn list_realms(&self, pagination: &Pagination) -> Result<Vec<Realm>, IssuerdError> {
        let mut list: Vec<Realm> = self.realms.iter().map(|r| r.clone()).collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        let start = pagination.first.max(0) as usize;
        let page_size = pagination.max.max(0) as usize;
        Ok(list.into_iter().skip(start).take(page_size).collect())
    }

    async fn count_realms(&self) -> Result<i64, IssuerdError> {
        Ok(self.realms.len() as i64)
    }

    async fn create_realm(&self, realm: &Realm) -> Result<(), IssuerdError> {
        if self
            .realms
            .iter()
            .any(|r| r.value().name == realm.name && r.value().id != realm.id)
        {
            return Err(IssuerdError::InvalidRequest("realm name already exists".into()));
        }
        let mut realm = realm.clone();
        // Every realm carries a pairwise sector key from birth.
        crate::seed::ensure_realm_pairwise_sector_key(&mut realm);
        self.realms.insert(realm.id.clone(), realm.clone());
        // Every realm carries the built-in client scopes (and the
        // realm default scope sets) from birth, on every backend.
        crate::seed::seed_builtin_client_scopes(self, &realm.id).await?;
        // Every realm also carries the built-in browser and
        // registration flows from birth (idempotent).
        crate::seed::seed_builtin_flows(self, &realm.id).await?;
        Ok(())
    }

    async fn update_realm(&self, realm: &Realm) -> Result<(), IssuerdError> {
        if !self.realms.contains_key(&realm.id) {
            return Err(IssuerdError::NotFound);
        }
        self.realms.insert(realm.id.clone(), realm.clone());
        Ok(())
    }

    async fn delete_realm(&self, id: &RealmId) -> Result<(), IssuerdError> {
        self.realms.remove(id);

        // Cascade: remove all realm-scoped entities.
        self.users.retain(|k, _| k.0 != *id);
        self.clients.retain(|k, _| k.0 != *id);
        self.credentials.retain(|k, _| k.0 != *id);
        self.sessions.retain(|k, _| k.0 != *id);
        self.roles.retain(|k, _| k.0 != *id);
        self.groups.retain(|k, _| k.0 != *id);
        self.consents.retain(|k, _| k.0 != *id);
        self.identity_providers.retain(|k, _| k.0 != *id);
        self.identity_provider_links.retain(|k, _| k.0 != *id);
        self.flow_configs.retain(|k, _| k.0 != *id);
        self.user_realm_roles.retain(|k, _| k.0 != *id);
        self.user_client_roles.retain(|k, _| k.0 != *id);
        self.user_groups.retain(|k, _| k.0 != *id);
        self.client_scopes.retain(|k, _| k.0 != *id);
        self.client_scope_assignments.retain(|k, _| k.0 != *id);
        self.realm_default_client_scopes.retain(|k, _| k != id);

        // Keep events/admin_events for audit; filter them at query time.
        Ok(())
    }

    // ------------------------------------------------------------------
    // User
    // ------------------------------------------------------------------
    async fn get_user(&self, realm: &RealmId, id: &UserId) -> Result<Option<User>, IssuerdError> {
        Ok(self.users.get(&(realm.clone(), id.clone())).map(|u| u.clone()))
    }

    async fn get_user_by_username(
        &self,
        realm: &RealmId,
        username: &str,
    ) -> Result<Option<User>, IssuerdError> {
        Ok(self
            .users
            .iter()
            .find(|u| u.value().realm_id == *realm && u.value().username == username)
            .map(|u| u.clone()))
    }

    async fn get_user_by_email(
        &self,
        realm: &RealmId,
        email: &str,
    ) -> Result<Option<User>, IssuerdError> {
        Ok(self
            .users
            .iter()
            .find(|u| u.value().realm_id == *realm && u.value().email.as_deref() == Some(email))
            .map(|u| u.clone()))
    }

    async fn get_user_by_federation_link(
        &self,
        realm: &RealmId,
        link: &str,
    ) -> Result<Vec<User>, IssuerdError> {
        Ok(self
            .users
            .iter()
            .filter(|u| {
                u.value().realm_id == *realm && u.value().federation_link.as_deref() == Some(link)
            })
            .map(|u| u.clone())
            .collect())
    }

    async fn list_users(
        &self,
        realm: &RealmId,
        query: &str,
        pagination: &Pagination,
    ) -> Result<Vec<User>, IssuerdError> {
        let q = query.to_lowercase();
        let mut list: Vec<User> = self
            .users
            .iter()
            .filter(|u| {
                u.value().realm_id == *realm
                    && (q.is_empty()
                        || u.value().username.to_lowercase().contains(&q)
                        || u.value()
                            .email
                            .as_ref()
                            .map(|e| e.to_lowercase().contains(&q))
                            .unwrap_or(false))
            })
            .map(|u| u.clone())
            .collect();
        list.sort_by(|a, b| a.username.cmp(&b.username));
        let start = pagination.first.max(0) as usize;
        let page_size = pagination.max.max(0) as usize;
        Ok(list.into_iter().skip(start).take(page_size).collect())
    }

    async fn count_users(&self, realm: &RealmId, query: &str) -> Result<i64, IssuerdError> {
        let q = query.to_lowercase();
        Ok(self
            .users
            .iter()
            .filter(|u| {
                u.value().realm_id == *realm
                    && (q.is_empty()
                        || u.value().username.to_lowercase().contains(&q)
                        || u.value()
                            .email
                            .as_ref()
                            .map(|e| e.to_lowercase().contains(&q))
                            .unwrap_or(false))
            })
            .count() as i64)
    }

    async fn create_user(&self, realm: &RealmId, user: &User) -> Result<(), IssuerdError> {
        if self
            .users
            .iter()
            .any(|u| u.value().realm_id == *realm && u.value().username == user.username)
        {
            return Err(IssuerdError::InvalidRequest("username already exists in realm".into()));
        }
        let mut user = user.clone();
        user.updated_at = user.created_at;
        self.users.insert((realm.clone(), user.id.clone()), user);
        Ok(())
    }

    async fn update_user(&self, realm: &RealmId, user: &User) -> Result<(), IssuerdError> {
        if !self.users.contains_key(&(realm.clone(), user.id.clone())) {
            return Err(IssuerdError::NotFound);
        }
        let mut user = user.clone();
        user.updated_at = chrono::Utc::now();
        self.users.insert((realm.clone(), user.id.clone()), user);
        Ok(())
    }

    async fn delete_user(&self, realm: &RealmId, id: &UserId) -> Result<(), IssuerdError> {
        self.users.remove(&(realm.clone(), id.clone()));
        // Cascade: delete credentials and sessions for this user.
        self.credentials.retain(|k, _| k.0 != *realm || k.1 != *id);
        self.sessions.retain(|k, v| k.0 != *realm || v.user_id != *id);
        self.consents.retain(|k, _| k.0 != *realm || k.1 != *id);
        self.identity_provider_links.retain(|k, v| k.0 != *realm || v.user_id != *id);
        self.user_realm_roles.remove(&(realm.clone(), id.clone()));
        self.user_client_roles.remove(&(realm.clone(), id.clone()));
        self.user_groups.remove(&(realm.clone(), id.clone()));
        Ok(())
    }

    // ------------------------------------------------------------------
    // Client
    // ------------------------------------------------------------------
    async fn get_client(
        &self,
        realm: &RealmId,
        id: &ClientId,
    ) -> Result<Option<Client>, IssuerdError> {
        Ok(self.clients.get(&(realm.clone(), id.clone())).map(|c| c.clone()))
    }

    async fn get_client_by_client_id(
        &self,
        realm: &RealmId,
        client_id: &ClientIdentifier,
    ) -> Result<Option<Client>, IssuerdError> {
        Ok(self
            .clients
            .iter()
            .find(|c| c.value().realm_id == *realm && c.value().client_id == *client_id)
            .map(|c| c.clone()))
    }

    async fn list_clients(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Client>, IssuerdError> {
        let mut list: Vec<Client> = self
            .clients
            .iter()
            .filter(|c| c.value().realm_id == *realm)
            .map(|c| c.clone())
            .collect();
        list.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        let start = pagination.first.max(0) as usize;
        let page_size = pagination.max.max(0) as usize;
        Ok(list.into_iter().skip(start).take(page_size).collect())
    }

    async fn count_clients(&self, realm: &RealmId) -> Result<i64, IssuerdError> {
        Ok(self.clients.iter().filter(|c| c.value().realm_id == *realm).count() as i64)
    }

    async fn create_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError> {
        if self
            .clients
            .iter()
            .any(|c| c.value().realm_id == *realm && c.value().client_id == client.client_id)
        {
            return Err(IssuerdError::InvalidRequest("client_id already exists in realm".into()));
        }
        self.clients.insert((realm.clone(), client.id.clone()), client.clone());
        // Seed scope assignments from the client's legacy
        // default/optional scope string lists (plus the `roles` carve-out).
        crate::seed::seed_client_scope_assignments(self, realm, client).await?;
        Ok(())
    }

    async fn update_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError> {
        if !self.clients.contains_key(&(realm.clone(), client.id.clone())) {
            return Err(IssuerdError::NotFound);
        }
        self.clients.insert((realm.clone(), client.id.clone()), client.clone());
        Ok(())
    }

    async fn delete_client(&self, realm: &RealmId, id: &ClientId) -> Result<(), IssuerdError> {
        self.clients.remove(&(realm.clone(), id.clone()));
        // Cascade (mirrors the Postgres ON DELETE CASCADE FKs): the client's
        // scope assignments, its own roles, and those roles' user mappings.
        self.client_scope_assignments.remove(&(realm.clone(), id.clone()));
        let role_ids: Vec<RoleId> = self
            .roles
            .iter()
            .filter(|r| r.key().0 == *realm && r.value().client_id.as_ref() == Some(id))
            .map(|r| r.value().id.clone())
            .collect();
        self.roles.retain(|k, _| !(k.0 == *realm && role_ids.contains(&k.1)));
        for mut entry in self.user_realm_roles.iter_mut() {
            if entry.key().0 == *realm {
                entry.value_mut().retain(|r| !role_ids.contains(r));
            }
        }
        for mut entry in self.user_client_roles.iter_mut() {
            if entry.key().0 == *realm {
                entry.value_mut().retain(|r| !role_ids.contains(r));
            }
        }
        Ok(())
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
        let key = (
            realm.clone(),
            user.clone(),
            serde_json::to_string(&cred_type).unwrap_or_default(),
        );
        Ok(self.credentials.get(&key).map(|list| list.clone()).unwrap_or_default())
    }

    async fn list_credentials(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<Credential>, IssuerdError> {
        let mut all: Vec<Credential> = self
            .credentials
            .iter()
            .filter(|e| e.key().0 == *realm && e.key().1 == *user)
            .flat_map(|e| e.value().clone())
            .collect();
        all.sort_by_key(|c| c.priority);
        Ok(all)
    }

    async fn create_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred: &Credential,
    ) -> Result<(), IssuerdError> {
        let type_key = serde_json::to_string(&cred.credential_type).unwrap_or_default();
        let key = (realm.clone(), user.clone(), type_key);
        let mut entry = self.credentials.entry(key).or_default();
        entry.push(cred.clone());
        Ok(())
    }

    async fn update_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred: &Credential,
    ) -> Result<(), IssuerdError> {
        let type_key = serde_json::to_string(&cred.credential_type).unwrap_or_default();
        let key = (realm.clone(), user.clone(), type_key);
        if let Some(mut list) = self.credentials.get_mut(&key) {
            if let Some(existing) = list.iter_mut().find(|c| c.id == cred.id) {
                *existing = cred.clone();
            }
        }
        Ok(())
    }

    async fn delete_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred_id: &CredentialId,
    ) -> Result<(), IssuerdError> {
        for mut entry in self.credentials.iter_mut() {
            let key = entry.key();
            if key.0 == *realm && key.1 == *user {
                entry.value_mut().retain(|c| c.id != *cred_id);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------
    async fn get_user_session(
        &self,
        realm: &RealmId,
        id: &SessionId,
    ) -> Result<Option<UserSession>, IssuerdError> {
        Ok(self.sessions.get(&(realm.clone(), id.clone())).map(|s| s.clone()))
    }

    async fn list_sessions(
        &self,
        realm: &RealmId,
        user: Option<UserId>,
        pagination: &Pagination,
    ) -> Result<Vec<UserSession>, IssuerdError> {
        let mut list: Vec<UserSession> = self
            .sessions
            .iter()
            .filter(|s| {
                s.value().realm_id == *realm
                    && user.as_ref().is_none_or(|u| &s.value().user_id == u)
            })
            .map(|s| s.clone())
            .collect();
        list.sort_by_key(|b| std::cmp::Reverse(b.last_session_refresh));
        let start = pagination.first.max(0) as usize;
        let page_size = pagination.max.max(0) as usize;
        Ok(list.into_iter().skip(start).take(page_size).collect())
    }

    async fn count_sessions(
        &self,
        realm: &RealmId,
        user: Option<UserId>,
    ) -> Result<i64, IssuerdError> {
        Ok(self
            .sessions
            .iter()
            .filter(|s| {
                s.value().realm_id == *realm
                    && user.as_ref().is_none_or(|u| &s.value().user_id == u)
            })
            .count() as i64)
    }

    async fn create_user_session(
        &self,
        realm: &RealmId,
        session: &UserSession,
    ) -> Result<(), IssuerdError> {
        self.sessions.insert((realm.clone(), session.id.clone()), session.clone());
        Ok(())
    }

    async fn update_user_session(
        &self,
        realm: &RealmId,
        session: &UserSession,
    ) -> Result<(), IssuerdError> {
        if !self.sessions.contains_key(&(realm.clone(), session.id.clone())) {
            return Err(IssuerdError::NotFound);
        }
        self.sessions.insert((realm.clone(), session.id.clone()), session.clone());
        Ok(())
    }

    async fn delete_user_session(
        &self,
        realm: &RealmId,
        id: &SessionId,
    ) -> Result<(), IssuerdError> {
        self.sessions.remove(&(realm.clone(), id.clone()));
        Ok(())
    }

    // ------------------------------------------------------------------
    // Roles
    // ------------------------------------------------------------------
    async fn get_role(&self, realm: &RealmId, id: &RoleId) -> Result<Option<Role>, IssuerdError> {
        Ok(self.roles.get(&(realm.clone(), id.clone())).map(|r| r.clone()))
    }

    async fn get_role_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<Role>, IssuerdError> {
        // A realm role wins over same-named client roles (client roles are
        // addressed via `get_client_role_by_name`); DashMap iteration order
        // is nondeterministic, so scan the whole shard set.
        let mut client_match = None;
        for r in self.roles.iter() {
            if r.value().realm_id == *realm && r.value().name.as_ref() == name {
                if !r.value().client_role {
                    return Ok(Some(r.value().clone()));
                }
                if client_match.is_none() {
                    client_match = Some(r.value().clone());
                }
            }
        }
        Ok(client_match)
    }

    async fn list_roles(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Role>, IssuerdError> {
        let mut list: Vec<Role> = self
            .roles
            .iter()
            .filter(|r| r.value().realm_id == *realm)
            .map(|r| r.clone())
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        let start = pagination.first.max(0) as usize;
        let page_size = pagination.max.max(0) as usize;
        Ok(list.into_iter().skip(start).take(page_size).collect())
    }

    async fn count_roles(&self, realm: &RealmId) -> Result<i64, IssuerdError> {
        Ok(self.roles.iter().filter(|r| r.value().realm_id == *realm).count() as i64)
    }

    async fn create_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError> {
        // Uniqueness is per owning client (realm roles have `client_id =
        // None`), mirroring the `roles_realm_client_name_key` index: a realm
        // role and a client role (or roles of two different clients) may
        // share a name.
        if self.roles.iter().any(|r| {
            r.value().realm_id == *realm
                && r.value().name == role.name
                && r.value().client_id == role.client_id
        }) {
            return Err(IssuerdError::InvalidRequest("role name already exists in realm".into()));
        }
        self.roles.insert((realm.clone(), role.id.clone()), role.clone());
        Ok(())
    }

    async fn update_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError> {
        if !self.roles.contains_key(&(realm.clone(), role.id.clone())) {
            return Err(IssuerdError::NotFound);
        }
        self.roles.insert((realm.clone(), role.id.clone()), role.clone());
        Ok(())
    }

    async fn delete_role(&self, realm: &RealmId, id: &RoleId) -> Result<(), IssuerdError> {
        self.roles.remove(&(realm.clone(), id.clone()));
        // Remove role from all users
        for mut entry in self.user_realm_roles.iter_mut() {
            if entry.key().0 == *realm {
                entry.value_mut().retain(|r| r != id);
            }
        }
        for mut entry in self.user_client_roles.iter_mut() {
            if entry.key().0 == *realm {
                entry.value_mut().retain(|r| r != id);
            }
        }
        Ok(())
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
        Ok(self
            .roles
            .iter()
            .find(|r| {
                r.value().realm_id == *realm
                    && r.value().client_id.as_ref() == Some(client)
                    && r.value().name.as_ref() == name
            })
            .map(|r| r.clone()))
    }

    async fn list_client_roles(
        &self,
        realm: &RealmId,
        client: &ClientId,
        pagination: &Pagination,
    ) -> Result<Vec<Role>, IssuerdError> {
        let mut list: Vec<Role> = self
            .roles
            .iter()
            .filter(|r| {
                r.value().realm_id == *realm && r.value().client_id.as_ref() == Some(client)
            })
            .map(|r| r.clone())
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        let start = pagination.first.max(0) as usize;
        let page_size = pagination.max.max(0) as usize;
        Ok(list.into_iter().skip(start).take(page_size).collect())
    }

    // ------------------------------------------------------------------
    // Client scopes
    // ------------------------------------------------------------------
    async fn get_client_scope(
        &self,
        realm: &RealmId,
        id: &ClientScopeId,
    ) -> Result<Option<ClientScope>, IssuerdError> {
        Ok(self.client_scopes.get(&(realm.clone(), id.clone())).map(|s| s.clone()))
    }

    async fn get_client_scope_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<ClientScope>, IssuerdError> {
        Ok(self
            .client_scopes
            .iter()
            .find(|s| s.key().0 == *realm && s.value().name == name)
            .map(|s| s.value().clone()))
    }

    async fn list_client_scopes(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<ClientScope>, IssuerdError> {
        let mut list: Vec<ClientScope> = self
            .client_scopes
            .iter()
            .filter(|s| s.key().0 == *realm)
            .map(|s| s.value().clone())
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        let start = pagination.first.max(0) as usize;
        let page_size = pagination.max.max(0) as usize;
        Ok(list.into_iter().skip(start).take(page_size).collect())
    }

    async fn create_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScope,
    ) -> Result<(), IssuerdError> {
        // UNIQUE(realm_id, name) in Postgres; Conflict mirrors sqlx_err.
        if self
            .client_scopes
            .iter()
            .any(|s| s.key().0 == *realm && s.value().name == scope.name)
        {
            return Err(IssuerdError::Conflict);
        }
        self.client_scopes.insert((realm.clone(), scope.id.clone()), scope.clone());
        Ok(())
    }

    async fn update_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScope,
    ) -> Result<(), IssuerdError> {
        if !self.client_scopes.contains_key(&(realm.clone(), scope.id.clone())) {
            return Err(IssuerdError::NotFound);
        }
        self.client_scopes.insert((realm.clone(), scope.id.clone()), scope.clone());
        Ok(())
    }

    async fn delete_client_scope(
        &self,
        realm: &RealmId,
        id: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        self.client_scopes.remove(&(realm.clone(), id.clone()));
        // Cascade (mirrors the Postgres ON DELETE CASCADE FKs): client
        // assignments and realm-default rows referencing the scope.
        for mut entry in self.client_scope_assignments.iter_mut() {
            if entry.key().0 == *realm {
                entry.value_mut().retain(|(s, _)| s != id);
            }
        }
        if let Some(mut entry) = self.realm_default_client_scopes.get_mut(realm) {
            entry.value_mut().retain(|(s, _)| s != id);
        }
        Ok(())
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
        let mut entry = self
            .client_scope_assignments
            .entry((realm.clone(), client.clone()))
            .or_default();
        if let Some(existing) = entry.iter_mut().find(|(s, _)| s == scope) {
            existing.1 = is_default;
        } else {
            entry.push((scope.clone(), is_default));
        }
        Ok(())
    }

    async fn unassign_client_scope(
        &self,
        realm: &RealmId,
        client: &ClientId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        if let Some(mut entry) =
            self.client_scope_assignments.get_mut(&(realm.clone(), client.clone()))
        {
            entry.retain(|(s, _)| s != scope);
        }
        Ok(())
    }

    async fn list_client_scope_assignments(
        &self,
        realm: &RealmId,
        client: &ClientId,
    ) -> Result<Vec<(ClientScopeId, bool)>, IssuerdError> {
        Ok(self
            .client_scope_assignments
            .get(&(realm.clone(), client.clone()))
            .map(|v| v.clone())
            .unwrap_or_default())
    }

    // ------------------------------------------------------------------
    // Realm default client scopes
    // ------------------------------------------------------------------
    async fn list_realm_default_client_scopes(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<(ClientScopeId, bool)>, IssuerdError> {
        Ok(self
            .realm_default_client_scopes
            .get(realm)
            .map(|v| v.clone())
            .unwrap_or_default())
    }

    async fn add_realm_default_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScopeId,
        is_default: bool,
    ) -> Result<(), IssuerdError> {
        let mut entry = self.realm_default_client_scopes.entry(realm.clone()).or_default();
        if let Some(existing) = entry.iter_mut().find(|(s, _)| s == scope) {
            existing.1 = is_default;
        } else {
            entry.push((scope.clone(), is_default));
        }
        Ok(())
    }

    async fn remove_realm_default_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        if let Some(mut entry) = self.realm_default_client_scopes.get_mut(realm) {
            entry.retain(|(s, _)| s != scope);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------
    async fn get_group(
        &self,
        realm: &RealmId,
        id: &GroupId,
    ) -> Result<Option<Group>, IssuerdError> {
        Ok(self.groups.get(&(realm.clone(), id.clone())).map(|g| g.clone()))
    }

    async fn get_group_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<Group>, IssuerdError> {
        Ok(self
            .groups
            .iter()
            .find(|g| g.key().0 == *realm && g.value().name.as_str() == name)
            .map(|g| g.value().clone()))
    }

    async fn list_groups(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Group>, IssuerdError> {
        let mut list: Vec<Group> = self
            .groups
            .iter()
            .filter(|g| g.value().realm_id == *realm)
            .map(|g| g.clone())
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        let start = pagination.first.max(0) as usize;
        let page_size = pagination.max.max(0) as usize;
        Ok(list.into_iter().skip(start).take(page_size).collect())
    }

    async fn count_groups(&self, realm: &RealmId) -> Result<i64, IssuerdError> {
        Ok(self.groups.iter().filter(|g| g.value().realm_id == *realm).count() as i64)
    }

    async fn create_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError> {
        if self
            .groups
            .iter()
            .any(|g| g.value().realm_id == *realm && g.value().name == group.name)
        {
            return Err(IssuerdError::Conflict);
        }
        self.groups.insert((realm.clone(), group.id.clone()), group.clone());
        Ok(())
    }

    async fn update_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError> {
        if !self.groups.contains_key(&(realm.clone(), group.id.clone())) {
            return Err(IssuerdError::NotFound);
        }
        self.groups.insert((realm.clone(), group.id.clone()), group.clone());
        Ok(())
    }

    async fn delete_group(&self, realm: &RealmId, id: &GroupId) -> Result<(), IssuerdError> {
        self.groups.remove(&(realm.clone(), id.clone()));
        // Remove group from all users
        for mut entry in self.user_groups.iter_mut() {
            if entry.key().0 == *realm {
                entry.value_mut().retain(|g| g != id);
            }
        }
        Ok(())
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
        let mut entry = self.user_realm_roles.entry((realm.clone(), user.clone())).or_default();
        if !entry.contains(role_id) {
            entry.push(role_id.clone());
        }
        Ok(())
    }

    async fn remove_user_realm_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        if let Some(mut entry) = self.user_realm_roles.get_mut(&(realm.clone(), user.clone())) {
            entry.retain(|r| r != role_id);
        }
        Ok(())
    }

    async fn list_user_realm_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError> {
        Ok(self
            .user_realm_roles
            .get(&(realm.clone(), user.clone()))
            .map(|v| v.clone())
            .unwrap_or_default())
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
        let mut entry = self.user_client_roles.entry((realm.clone(), user.clone())).or_default();
        if !entry.contains(role_id) {
            entry.push(role_id.clone());
        }
        Ok(())
    }

    async fn remove_user_client_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        if let Some(mut entry) = self.user_client_roles.get_mut(&(realm.clone(), user.clone())) {
            entry.retain(|r| r != role_id);
        }
        Ok(())
    }

    async fn list_user_client_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError> {
        Ok(self
            .user_client_roles
            .get(&(realm.clone(), user.clone()))
            .map(|v| v.clone())
            .unwrap_or_default())
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
        let mut entry = self.user_groups.entry((realm.clone(), user.clone())).or_default();
        if !entry.contains(group_id) {
            entry.push(group_id.clone());
        }
        Ok(())
    }

    async fn remove_user_group(
        &self,
        realm: &RealmId,
        user: &UserId,
        group_id: &GroupId,
    ) -> Result<(), IssuerdError> {
        if let Some(mut entry) = self.user_groups.get_mut(&(realm.clone(), user.clone())) {
            entry.retain(|g| g != group_id);
        }
        Ok(())
    }

    async fn list_user_groups(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<GroupId>, IssuerdError> {
        Ok(self
            .user_groups
            .get(&(realm.clone(), user.clone()))
            .map(|v| v.clone())
            .unwrap_or_default())
    }

    async fn list_group_members(
        &self,
        realm: &RealmId,
        group: &GroupId,
        first: i32,
        max: i32,
    ) -> Result<Vec<User>, IssuerdError> {
        // Reverse membership lookup: user_groups is keyed by user, so invert
        // it and resolve each member's User record. Sorted by username for a
        // deterministic pagination order.
        let mut members: Vec<User> = self
            .user_groups
            .iter()
            .filter(|e| e.key().0 == *realm && e.value().contains(group))
            .filter_map(|e| self.users.get(e.key()).map(|u| u.clone()))
            .collect();
        members.sort_by(|a, b| a.username.as_ref().cmp(b.username.as_ref()));
        let start = first.max(0) as usize;
        let page_size = max.max(0) as usize;
        Ok(members.into_iter().skip(start).take(page_size).collect())
    }

    // ------------------------------------------------------------------
    // Consent
    // ------------------------------------------------------------------
    async fn get_consents(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<Consent>, IssuerdError> {
        Ok(self
            .consents
            .iter()
            .filter(|c| c.key().0 == *realm && c.key().1 == *user)
            .map(|c| c.clone())
            .collect())
    }

    async fn create_consent(&self, realm: &RealmId, consent: &Consent) -> Result<(), IssuerdError> {
        self.consents.insert(
            (realm.clone(), consent.user_id.clone(), consent.client_id.clone()),
            consent.clone(),
        );
        Ok(())
    }

    async fn delete_consent(
        &self,
        realm: &RealmId,
        user: &UserId,
        client_id: &ClientId,
    ) -> Result<(), IssuerdError> {
        self.consents.remove(&(realm.clone(), user.clone(), client_id.clone()));
        Ok(())
    }

    // ------------------------------------------------------------------
    // Identity Providers
    // ------------------------------------------------------------------
    async fn get_identity_provider(
        &self,
        realm: &RealmId,
        id: &IdentityProviderId,
    ) -> Result<Option<IdentityProviderConfig>, IssuerdError> {
        Ok(self.identity_providers.get(&(realm.clone(), id.clone())).map(|i| i.clone()))
    }

    async fn get_identity_provider_by_alias(
        &self,
        realm: &RealmId,
        alias: &str,
    ) -> Result<Option<IdentityProviderConfig>, IssuerdError> {
        let result = self
            .identity_providers
            .iter()
            .find(|entry| entry.key().0 == *realm && entry.value().alias == alias)
            .map(|entry| entry.value().clone());
        Ok(result)
    }

    async fn list_identity_providers(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<IdentityProviderConfig>, IssuerdError> {
        Ok(self
            .identity_providers
            .iter()
            .filter(|i| i.key().0 == *realm)
            .map(|i| i.clone())
            .collect())
    }

    async fn create_identity_provider(
        &self,
        realm: &RealmId,
        idp: &IdentityProviderConfig,
    ) -> Result<(), IssuerdError> {
        self.identity_providers.insert((realm.clone(), idp.id.clone()), idp.clone());
        Ok(())
    }

    async fn update_identity_provider(
        &self,
        realm: &RealmId,
        idp: &IdentityProviderConfig,
    ) -> Result<(), IssuerdError> {
        if !self.identity_providers.contains_key(&(realm.clone(), idp.id.clone())) {
            return Err(IssuerdError::NotFound);
        }
        self.identity_providers.insert((realm.clone(), idp.id.clone()), idp.clone());
        Ok(())
    }

    async fn delete_identity_provider(
        &self,
        realm: &RealmId,
        id: &IdentityProviderId,
    ) -> Result<(), IssuerdError> {
        if let Some(idp) = self.identity_providers.get(&(realm.clone(), id.clone())) {
            // Cascade: account links into the deleted provider go with it.
            let alias = idp.alias.to_string();
            drop(idp);
            self.identity_provider_links.retain(|k, _| k.0 != *realm || k.1 != alias);
        }
        self.identity_providers.remove(&(realm.clone(), id.clone()));
        Ok(())
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
        Ok(self
            .identity_provider_links
            .get(&(realm.clone(), alias.to_string(), external_subject.to_string()))
            .map(|l| l.clone()))
    }

    async fn get_identity_provider_link_for_user(
        &self,
        realm: &RealmId,
        user: &UserId,
        alias: &str,
    ) -> Result<Option<IdentityProviderLink>, IssuerdError> {
        Ok(self
            .identity_provider_links
            .iter()
            .find(|e| e.key().0 == *realm && e.key().1 == alias && e.value().user_id == *user)
            .map(|e| e.value().clone()))
    }

    async fn list_identity_provider_links(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<IdentityProviderLink>, IssuerdError> {
        Ok(self
            .identity_provider_links
            .iter()
            .filter(|e| e.key().0 == *realm && e.value().user_id == *user)
            .map(|e| e.value().clone())
            .collect())
    }

    async fn create_identity_provider_link(
        &self,
        realm: &RealmId,
        link: &IdentityProviderLink,
    ) -> Result<(), IssuerdError> {
        // One external subject maps to exactly one local user; one user holds
        // at most one link per provider alias.
        let clash = self.identity_provider_links.iter().any(|e| {
            e.key().0 == *realm
                && e.key().1 == link.provider_alias
                && (e.key().2 == link.external_subject || e.value().user_id == link.user_id)
        });
        if clash {
            return Err(IssuerdError::Conflict);
        }
        self.identity_provider_links.insert(
            (realm.clone(), link.provider_alias.clone(), link.external_subject.clone()),
            link.clone(),
        );
        Ok(())
    }

    async fn delete_identity_provider_link(
        &self,
        realm: &RealmId,
        user: &UserId,
        alias: &str,
    ) -> Result<(), IssuerdError> {
        self.identity_provider_links
            .retain(|k, v| !(k.0 == *realm && k.1 == alias && v.user_id == *user));
        Ok(())
    }

    // ------------------------------------------------------------------
    // Flow Config
    // ------------------------------------------------------------------
    async fn get_flow_config(
        &self,
        realm: &RealmId,
        alias: &str,
    ) -> Result<Option<FlowConfig>, IssuerdError> {
        Ok(self.flow_configs.get(&(realm.clone(), Alias::new(alias)?)).map(|f| f.clone()))
    }

    async fn create_flow_config(
        &self,
        realm: &RealmId,
        config: &FlowConfig,
    ) -> Result<(), IssuerdError> {
        self.flow_configs.insert((realm.clone(), config.alias.clone()), config.clone());
        Ok(())
    }

    async fn update_flow_config(
        &self,
        realm: &RealmId,
        config: &FlowConfig,
    ) -> Result<(), IssuerdError> {
        if !self.flow_configs.contains_key(&(realm.clone(), config.alias.clone())) {
            return Err(IssuerdError::NotFound);
        }
        self.flow_configs.insert((realm.clone(), config.alias.clone()), config.clone());
        Ok(())
    }

    async fn delete_flow_config(&self, realm: &RealmId, alias: &str) -> Result<(), IssuerdError> {
        self.flow_configs.remove(&(realm.clone(), Alias::new(alias).unwrap()));
        Ok(())
    }

    async fn list_flow_configs(&self, realm: &RealmId) -> Result<Vec<FlowConfig>, IssuerdError> {
        let mut result: Vec<FlowConfig> = self
            .flow_configs
            .iter()
            .filter(|entry| entry.key().0 == *realm)
            .map(|entry| entry.value().clone())
            .collect();
        result.sort_by(|a, b| a.alias.cmp(&b.alias));
        Ok(result)
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------
    async fn save_event(&self, _realm: &RealmId, event: &Event) -> Result<(), IssuerdError> {
        self.events.write().unwrap().push(event.clone());
        Ok(())
    }

    async fn query_events(
        &self,
        realm: &RealmId,
        query: &EventQuery,
    ) -> Result<Vec<Event>, IssuerdError> {
        let events = self.events.read().unwrap();
        let mut filtered: Vec<Event> =
            events.iter().filter(|e| event_matches(e, realm, query)).cloned().collect();
        filtered.sort_by_key(|b| std::cmp::Reverse(b.event_time));
        let start = query.pagination.first.max(0) as usize;
        let page_size = query.pagination.max.max(0) as usize;
        Ok(filtered.into_iter().skip(start).take(page_size).collect())
    }

    async fn count_events(&self, realm: &RealmId, query: &EventQuery) -> Result<i64, IssuerdError> {
        let events = self.events.read().unwrap();
        let count = events.iter().filter(|e| event_matches(e, realm, query)).count();
        Ok(count as i64)
    }

    async fn delete_events(&self, realm: &RealmId) -> Result<(), IssuerdError> {
        self.events.write().unwrap().retain(|e| e.realm_id != *realm);
        Ok(())
    }

    async fn save_admin_event(&self, event: &AdminEvent) -> Result<(), IssuerdError> {
        self.admin_events.write().unwrap().push(event.clone());
        Ok(())
    }

    async fn query_admin_events(
        &self,
        realm: &RealmId,
        query: &AdminEventQuery,
    ) -> Result<Vec<AdminEvent>, IssuerdError> {
        let events = self.admin_events.read().unwrap();
        let mut filtered: Vec<AdminEvent> = events
            .iter()
            .filter(|e| admin_event_matches(e, realm, query))
            .cloned()
            .collect();
        filtered.sort_by_key(|b| std::cmp::Reverse(b.event_time));
        let start = query.pagination.first.max(0) as usize;
        let page_size = query.pagination.max.max(0) as usize;
        Ok(filtered.into_iter().skip(start).take(page_size).collect())
    }

    async fn count_admin_events(
        &self,
        realm: &RealmId,
        query: &AdminEventQuery,
    ) -> Result<i64, IssuerdError> {
        let events = self.admin_events.read().unwrap();
        let count = events.iter().filter(|e| admin_event_matches(e, realm, query)).count();
        Ok(count as i64)
    }

    async fn delete_admin_events(&self, realm: &RealmId) -> Result<(), IssuerdError> {
        self.admin_events.write().unwrap().retain(|e| e.realm_id != *realm);
        Ok(())
    }

    async fn get_provision_marker(&self, name: &str) -> Result<Option<String>, IssuerdError> {
        Ok(self.provision_markers.get(name).map(|v| v.clone()))
    }

    async fn set_provision_marker(&self, name: &str, value: &str) -> Result<(), IssuerdError> {
        self.provision_markers.insert(name.to_string(), value.to_string());
        Ok(())
    }

    async fn claim_provision_marker(&self, name: &str, value: &str) -> Result<bool, IssuerdError> {
        match self.provision_markers.entry(name.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(_) => Ok(false),
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                slot.insert(value.to_string());
                Ok(true)
            }
        }
    }

    // ------------------------------------------------------------------
    // Signing keys
    // ------------------------------------------------------------------
    async fn list_signing_keys(&self) -> Result<Vec<StoredSigningKey>, IssuerdError> {
        let mut keys: Vec<StoredSigningKey> = self.signing_keys.iter().map(|k| k.clone()).collect();
        keys.sort_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.kid.cmp(&b.kid)));
        Ok(keys)
    }

    async fn create_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError> {
        match self.signing_keys.entry(key.kid.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(IssuerdError::InvalidRequest("signing key kid already exists".into()))
            }
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                slot.insert(key.clone());
                Ok(())
            }
        }
    }

    async fn update_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError> {
        match self.signing_keys.get_mut(&key.kid.to_string()) {
            Some(mut slot) => {
                slot.active = key.active;
                Ok(())
            }
            None => Err(IssuerdError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
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

    fn test_realm_2() -> Realm {
        Realm {
            id: RealmId::new("realm-2").unwrap(),
            name: RealmName::new("test-realm-2").unwrap(),
            display_name: Some(DisplayName::new("Test Realm 2").unwrap()),
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

    fn test_user(realm_id: &str) -> User {
        User {
            id: UserId::new("user-1").unwrap(),
            realm_id: RealmId::new(realm_id).unwrap(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: Some(DisplayName::new("Smith").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn test_client(realm_id: &str) -> Client {
        Client {
            id: ClientId::new("client-1").unwrap(),
            realm_id: RealmId::new(realm_id).unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: Some(issuerd_core::DisplayName::new("My App").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![RedirectUri::new("https://app.example.com/callback").unwrap()],
            web_origins: vec![WebOrigin::new("https://app.example.com").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::parse("email"),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    fn test_credential() -> Credential {
        Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: Some("My password".to_string()),
            created_date: Utc::now(),
            secret_data: vec![1, 2, 3],
            credential_data: serde_json::json!({"hash": "abc123"}),
            priority: 1,
        }
    }

    fn test_session(realm_id: &str) -> UserSession {
        UserSession {
            id: SessionId::new("session-1").unwrap(),
            realm_id: RealmId::new(realm_id).unwrap(),
            user_id: UserId::new("user-1").unwrap(),
            login_username: issuerd_core::Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
            clients: vec![],
        }
    }

    fn test_role(realm_id: &str) -> Role {
        Role {
            id: RoleId::new("role-1").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: Some("Admin role".to_string()),
            realm_id: RealmId::new(realm_id).unwrap(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        }
    }

    fn test_group(realm_id: &str) -> Group {
        Group {
            id: GroupId::new("group-1").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: GroupPath::new("/admins").unwrap(),
            realm_id: RealmId::new(realm_id).unwrap(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![issuerd_core::RoleName::new("admin").unwrap()],
            client_roles: HashMap::new(),
        }
    }

    fn test_consent() -> Consent {
        Consent {
            client_id: ClientId::new("client-1").unwrap(),
            user_id: UserId::new("user-1").unwrap(),
            granted_scopes: Scope::parse("openid"),
            granted_realm_roles: vec![],
            granted_client_roles: HashMap::new(),
            created_at: Utc::now(),
            last_updated_at: Utc::now(),
        }
    }

    fn test_idp() -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: IdentityProviderId::new("idp-1").unwrap(),
            alias: Alias::new("google").unwrap(),
            provider_id: ProviderId::new("google"),
            enabled: true,
            config: {
                let mut m = HashMap::new();
                m.insert("clientId".to_string(), "123".to_string());
                m
            },
        }
    }

    fn test_flow_config(realm_id: &str) -> FlowConfig {
        FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new(realm_id).unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![],
        }
    }

    fn test_event(realm_id: &str, event_type: EventType) -> Event {
        Event {
            id: EventId::new("event-1").unwrap(),
            realm_id: RealmId::new(realm_id).unwrap(),
            event_time: Utc::now(),
            event_type,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            client_id: Some(ClientId::new("client-1").unwrap()),
            user_id: Some(UserId::new("user-1").unwrap()),
            session_id: Some(SessionId::new("session-1").unwrap()),
            error: None,
            details: {
                let mut m = HashMap::new();
                m.insert("method".to_string(), "password".to_string());
                m
            },
        }
    }

    // ------------------------------------------------------------------
    // Realm CRUD
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn realm_crud_and_uniqueness() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        let realm2 = test_realm_2();

        storage.create_realm(&realm).await.unwrap();
        storage.create_realm(&realm2).await.unwrap();

        assert_eq!(storage.get_realm(&realm.id).await.unwrap().unwrap().name, "test-realm");
        assert_eq!(storage.get_realm_by_name("test-realm-2").await.unwrap().unwrap().id, realm2.id);

        // Duplicate name
        let mut dup = realm.clone();
        dup.id = RealmId::new("realm-dup").unwrap();
        assert!(storage.create_realm(&dup).await.is_err());

        storage.delete_realm(&realm.id).await.unwrap();
        assert!(storage.get_realm(&realm.id).await.unwrap().is_none());
        assert!(storage.get_realm(&realm2.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn realm_update_and_not_found() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let mut updated = realm.clone();
        updated.name = RealmName::new("updated").unwrap();
        storage.update_realm(&updated).await.unwrap();
        assert_eq!(storage.get_realm(&realm.id).await.unwrap().unwrap().name, "updated");

        let unknown = Realm {
            id: RealmId::new("unknown").unwrap(),
            ..realm.clone()
        };
        assert_eq!(storage.update_realm(&unknown).await.unwrap_err(), IssuerdError::NotFound);
    }

    #[tokio::test]
    async fn realm_list_pagination() {
        let storage = InMemoryStorage::new();
        for i in 0..5 {
            let mut r = test_realm();
            r.id = RealmId::new(format!("realm-{i}")).unwrap();
            r.name = RealmName::new(format!("realm-{i:02}")).unwrap();
            storage.create_realm(&r).await.unwrap();
        }
        let all = storage.list_realms(&Pagination { first: 0, max: 100 }).await.unwrap();
        assert_eq!(all.len(), 5);

        let page = storage.list_realms(&Pagination { first: 2, max: 2 }).await.unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].name, "realm-02");
    }

    // ------------------------------------------------------------------
    // User CRUD
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn user_crud_and_uniqueness_per_realm() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        let realm2 = test_realm_2();
        storage.create_realm(&realm).await.unwrap();
        storage.create_realm(&realm2).await.unwrap();

        let user = test_user("realm-1");
        let mut user2 = user.clone();
        user2.id = UserId::new("user-2").unwrap();
        user2.realm_id = realm2.id.clone();

        storage.create_user(&realm.id, &user).await.unwrap();
        storage.create_user(&realm2.id, &user2).await.unwrap();

        assert_eq!(
            storage.get_user_by_username(&realm.id, "alice").await.unwrap().unwrap().id,
            user.id
        );

        // Same username in same realm should fail.
        let mut dup = user.clone();
        dup.id = UserId::new("user-dup").unwrap();
        assert!(storage.create_user(&realm.id, &dup).await.is_err());

        storage.delete_user(&realm.id, &user.id).await.unwrap();
        assert!(storage.get_user(&realm.id, &user.id).await.unwrap().is_none());
        assert!(storage.get_user(&realm2.id, &user2.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn user_email_lookup() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();

        let found = storage.get_user_by_email(&realm.id, "alice@example.com").await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn user_list_and_search() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        for i in 0..5 {
            let mut u = test_user("realm-1");
            u.id = UserId::new(format!("user-{i}")).unwrap();
            u.username = Username::new(format!("user-{i:02}")).unwrap();
            storage.create_user(&realm.id, &u).await.unwrap();
        }

        let all = storage.list_users(&realm.id, "", &Pagination::default()).await.unwrap();
        assert_eq!(all.len(), 5);

        let searched =
            storage.list_users(&realm.id, "user-02", &Pagination::default()).await.unwrap();
        assert_eq!(searched.len(), 1);
    }

    // ------------------------------------------------------------------
    // Client CRUD
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn client_crud_and_uniqueness() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();

        assert_eq!(
            storage
                .get_client_by_client_id(&realm.id, &ClientIdentifier::new("my-app").unwrap())
                .await
                .unwrap()
                .unwrap()
                .id,
            client.id
        );

        let mut dup = client.clone();
        dup.id = ClientId::new("client-dup").unwrap();
        assert!(storage.create_client(&realm.id, &dup).await.is_err());

        storage.delete_client(&realm.id, &client.id).await.unwrap();
        assert!(storage.get_client(&realm.id, &client.id).await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Credentials
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn credential_crud() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        let user = test_user("realm-1");
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();

        let cred = test_credential();
        storage.create_credential(&realm.id, &user.id, &cred).await.unwrap();

        let list = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(list.len(), 1);

        let mut updated = cred.clone();
        updated.priority = 5;
        storage.update_credential(&realm.id, &user.id, &updated).await.unwrap();
        let list = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(list[0].priority, 5);

        storage.delete_credential(&realm.id, &user.id, &cred.id).await.unwrap();
        let list = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert!(list.is_empty());
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn session_lifecycle() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        let user = test_user("realm-1");
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();

        let session = test_session("realm-1");
        storage.create_user_session(&realm.id, &session).await.unwrap();

        let found = storage.get_user_session(&realm.id, &session.id).await.unwrap();
        assert!(found.is_some());

        let mut updated = session.clone();
        updated.last_session_refresh = Utc::now();
        storage.update_user_session(&realm.id, &updated).await.unwrap();

        let list = storage
            .list_sessions(&realm.id, Some(user.id.clone()), &Pagination::default())
            .await
            .unwrap();
        assert_eq!(list.len(), 1);

        storage.delete_user_session(&realm.id, &session.id).await.unwrap();
        assert!(storage.get_user_session(&realm.id, &session.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn session_cascade_on_user_delete() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        let user = test_user("realm-1");
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();

        let session = test_session("realm-1");
        storage.create_user_session(&realm.id, &session).await.unwrap();

        storage.delete_user(&realm.id, &user.id).await.unwrap();
        assert!(storage.get_user_session(&realm.id, &session.id).await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Roles
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn role_crud() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let role = test_role("realm-1");
        storage.create_role(&realm.id, &role).await.unwrap();

        assert_eq!(
            storage.get_role_by_name(&realm.id, "admin").await.unwrap().unwrap().id,
            role.id
        );

        storage.delete_role(&realm.id, &role.id).await.unwrap();
        assert!(storage.get_role(&realm.id, &role.id).await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn group_crud() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let group = test_group("realm-1");
        storage.create_group(&realm.id, &group).await.unwrap();

        assert_eq!(
            storage.get_group(&realm.id, &group.id).await.unwrap().unwrap().name,
            GroupName::new("admins").unwrap()
        );
    }

    // ------------------------------------------------------------------
    // Consents
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn consent_lifecycle() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let consent = test_consent();
        storage.create_consent(&realm.id, &consent).await.unwrap();

        let list = storage.get_consents(&realm.id, &consent.user_id).await.unwrap();
        assert_eq!(list.len(), 1);

        storage
            .delete_consent(&realm.id, &consent.user_id, &consent.client_id)
            .await
            .unwrap();
        let list = storage.get_consents(&realm.id, &consent.user_id).await.unwrap();
        assert!(list.is_empty());
    }

    // ------------------------------------------------------------------
    // Identity Providers
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn idp_lifecycle() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let idp = test_idp();
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();

        let list = storage.list_identity_providers(&realm.id).await.unwrap();
        assert_eq!(list.len(), 1);

        let mut updated = idp.clone();
        updated.enabled = false;
        storage.update_identity_provider(&realm.id, &updated).await.unwrap();
        assert!(
            !storage
                .get_identity_provider(&realm.id, &idp.id)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );

        storage.delete_identity_provider(&realm.id, &idp.id).await.unwrap();
        assert!(storage.get_identity_provider(&realm.id, &idp.id).await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Flow Configs
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn flow_config_lifecycle() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let flow = test_flow_config("realm-1");
        storage.create_flow_config(&realm.id, &flow).await.unwrap();

        let found = storage.get_flow_config(&realm.id, "browser").await.unwrap();
        assert!(found.is_some());

        let mut updated = flow.clone();
        updated.provider_id = "updated".to_string();
        storage.update_flow_config(&realm.id, &updated).await.unwrap();
        assert_eq!(
            storage
                .get_flow_config(&realm.id, "browser")
                .await
                .unwrap()
                .unwrap()
                .provider_id,
            "updated"
        );

        storage.delete_flow_config(&realm.id, "browser").await.unwrap();
        assert!(storage.get_flow_config(&realm.id, "browser").await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn event_save_and_query() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        for i in 0..10 {
            let mut ev = test_event("realm-1", EventType::Login);
            ev.id = EventId::new(format!("event-{i}")).unwrap();
            ev.event_time = Utc::now() + chrono::Duration::milliseconds(i as i64 * 10);
            storage.save_event(&realm.id, &ev).await.unwrap();
        }

        let all = storage
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
        assert_eq!(all.len(), 10);

        let paginated = storage
            .query_events(
                &realm.id,
                &EventQuery {
                    event_type: None,
                    client_id: None,
                    user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination { first: 2, max: 3 },
                },
            )
            .await
            .unwrap();
        assert_eq!(paginated.len(), 3);
    }

    #[tokio::test]
    async fn event_query_by_type() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let mut ev1 = test_event("realm-1", EventType::Login);
        ev1.id = EventId::new("event-login").unwrap();
        storage.save_event(&realm.id, &ev1).await.unwrap();

        let mut ev2 = test_event("realm-1", EventType::Logout);
        ev2.id = EventId::new("event-logout").unwrap();
        storage.save_event(&realm.id, &ev2).await.unwrap();

        let query = EventQuery {
            event_type: Some(EventType::Login),
            client_id: None,
            user_id: None,
            date_from: None,
            date_to: None,
            pagination: Pagination::default(),
        };
        let results = storage.query_events(&realm.id, &query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].event_type, EventType::Login));
    }

    // ------------------------------------------------------------------
    // Admin Events
    // ------------------------------------------------------------------
    fn test_admin_event(
        realm_id: &str,
        operation_type: OperationType,
        resource_type: ResourceType,
    ) -> AdminEvent {
        let rt_str =
            serde_json::to_string(&resource_type).unwrap().trim_matches('"').to_lowercase();
        AdminEvent {
            id: EventId::new("ae-1").unwrap(),
            realm_id: RealmId::new(realm_id).unwrap(),
            auth_realm_id: Some(RealmId::new("master").unwrap()),
            auth_client_id: Some(ClientId::new("admin-cli").unwrap()),
            auth_user_id: Some(UserId::new("admin").unwrap()),
            operation_type,
            resource_type,
            resource_path: format!("{rt_str}/test-1"),
            representation: None,
            error: None,
            event_time: Utc::now(),
        }
    }

    #[tokio::test]
    async fn admin_event_save_and_query() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        for i in 0..5 {
            let mut ev = test_admin_event("realm-1", OperationType::Create, ResourceType::User);
            ev.id = EventId::new(format!("ae-{i}")).unwrap();
            ev.event_time = Utc::now() + chrono::Duration::milliseconds(i as i64 * 10);
            storage.save_admin_event(&ev).await.unwrap();
        }

        let all = storage
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
        assert_eq!(all.len(), 5);
    }

    #[tokio::test]
    async fn admin_event_query_filters() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let mut ev1 = test_admin_event("realm-1", OperationType::Create, ResourceType::User);
        ev1.id = EventId::new("ae-create-user").unwrap();
        storage.save_admin_event(&ev1).await.unwrap();

        let mut ev2 = test_admin_event("realm-1", OperationType::Delete, ResourceType::User);
        ev2.id = EventId::new("ae-delete-user").unwrap();
        storage.save_admin_event(&ev2).await.unwrap();

        let mut ev3 = test_admin_event("realm-1", OperationType::Update, ResourceType::Client);
        ev3.id = EventId::new("ae-update-client").unwrap();
        storage.save_admin_event(&ev3).await.unwrap();

        let by_op = storage
            .query_admin_events(
                &realm.id,
                &AdminEventQuery {
                    operation_type: Some(OperationType::Create),
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(by_op.len(), 1);
        assert!(matches!(by_op[0].operation_type, OperationType::Create));

        let by_resource = storage
            .query_admin_events(
                &realm.id,
                &AdminEventQuery {
                    operation_type: None,
                    resource_type: Some(ResourceType::User),
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(by_resource.len(), 2);

        let by_both = storage
            .query_admin_events(
                &realm.id,
                &AdminEventQuery {
                    operation_type: Some(OperationType::Delete),
                    resource_type: Some(ResourceType::User),
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(by_both.len(), 1);
        assert!(matches!(by_both[0].operation_type, OperationType::Delete));
    }

    // ------------------------------------------------------------------
    // Cascade
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn cascade_delete_realm() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();

        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();

        let cred = test_credential();
        storage.create_credential(&realm.id, &user.id, &cred).await.unwrap();

        let session = test_session("realm-1");
        storage.create_user_session(&realm.id, &session).await.unwrap();

        let role = test_role("realm-1");
        storage.create_role(&realm.id, &role).await.unwrap();

        let group = test_group("realm-1");
        storage.create_group(&realm.id, &group).await.unwrap();

        let consent = test_consent();
        storage.create_consent(&realm.id, &consent).await.unwrap();

        let idp = test_idp();
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();

        let flow = test_flow_config("realm-1");
        storage.create_flow_config(&realm.id, &flow).await.unwrap();

        storage.delete_realm(&realm.id).await.unwrap();

        assert!(storage.get_realm(&realm.id).await.unwrap().is_none());
        assert!(storage.get_user(&realm.id, &user.id).await.unwrap().is_none());
        assert!(storage.get_client(&realm.id, &client.id).await.unwrap().is_none());
        assert!(storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap()
            .is_empty());
        assert!(storage.get_user_session(&realm.id, &session.id).await.unwrap().is_none());
        assert!(storage.get_role(&realm.id, &role.id).await.unwrap().is_none());
        assert!(storage.get_group(&realm.id, &group.id).await.unwrap().is_none());
        assert!(storage.get_consents(&realm.id, &user.id).await.unwrap().is_empty());
        assert!(storage.get_identity_provider(&realm.id, &idp.id).await.unwrap().is_none());
        assert!(storage.get_flow_config(&realm.id, "browser").await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // User realm roles
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn user_realm_role_membership() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();

        let role1 = test_role("realm-1");
        let mut role2 = role1.clone();
        role2.id = RoleId::new("role-2").unwrap();
        role2.name = RoleName::new("user").unwrap();
        storage.create_role(&realm.id, &role1).await.unwrap();
        storage.create_role(&realm.id, &role2).await.unwrap();

        storage.add_user_realm_role(&realm.id, &user.id, &role1.id).await.unwrap();
        storage.add_user_realm_role(&realm.id, &user.id, &role2.id).await.unwrap();

        let roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert_eq!(roles.len(), 2);

        storage.remove_user_realm_role(&realm.id, &user.id, &role1.id).await.unwrap();
        let roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0], role2.id);
    }

    #[tokio::test]
    async fn user_group_membership() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();

        let group1 = test_group("realm-1");
        let mut group2 = group1.clone();
        group2.id = GroupId::new("group-2").unwrap();
        group2.name = GroupName::new("users").unwrap();
        storage.create_group(&realm.id, &group1).await.unwrap();
        storage.create_group(&realm.id, &group2).await.unwrap();

        storage.add_user_group(&realm.id, &user.id, &group1.id).await.unwrap();
        storage.add_user_group(&realm.id, &user.id, &group2.id).await.unwrap();

        let groups = storage.list_user_groups(&realm.id, &user.id).await.unwrap();
        assert_eq!(groups.len(), 2);

        storage.remove_user_group(&realm.id, &user.id, &group1.id).await.unwrap();
        let groups = storage.list_user_groups(&realm.id, &user.id).await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], group2.id);
    }

    #[tokio::test]
    async fn membership_cascade_delete_user() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();

        let role = test_role("realm-1");
        storage.create_role(&realm.id, &role).await.unwrap();

        let group = test_group("realm-1");
        storage.create_group(&realm.id, &group).await.unwrap();

        storage.add_user_realm_role(&realm.id, &user.id, &role.id).await.unwrap();
        storage.add_user_group(&realm.id, &user.id, &group.id).await.unwrap();

        storage.delete_user(&realm.id, &user.id).await.unwrap();

        let roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert!(roles.is_empty());
        let groups = storage.list_user_groups(&realm.id, &user.id).await.unwrap();
        assert!(groups.is_empty());
    }

    #[tokio::test]
    async fn membership_cascade_delete_role() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();

        let role = test_role("realm-1");
        storage.create_role(&realm.id, &role).await.unwrap();

        storage.add_user_realm_role(&realm.id, &user.id, &role.id).await.unwrap();
        storage.delete_role(&realm.id, &role.id).await.unwrap();

        let roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert!(roles.is_empty());
    }

    // ------------------------------------------------------------------
    // Edge cases & error paths
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn user_not_found_and_update_not_found() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        assert!(storage
            .get_user(&realm.id, &UserId::new("missing").unwrap())
            .await
            .unwrap()
            .is_none());
        assert!(storage.get_user_by_username(&realm.id, "nobody").await.unwrap().is_none());
        assert!(storage
            .get_user_by_email(&realm.id, "nobody@example.com")
            .await
            .unwrap()
            .is_none());

        let user = User {
            id: UserId::new("missing").unwrap(),
            realm_id: realm.id.clone(),
            username: Username::new("nobody").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(
            storage.update_user(&realm.id, &user).await.unwrap_err(),
            IssuerdError::NotFound
        );
    }

    #[tokio::test]
    async fn user_list_email_search_and_pagination() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let mut u = test_user("realm-1");
        u.email = Some(Email::new("bob@example.com").unwrap());
        u.username = Username::new("bob").unwrap();
        storage.create_user(&realm.id, &u).await.unwrap();

        let by_email = storage
            .list_users(&realm.id, "bob@example", &Pagination::default())
            .await
            .unwrap();
        assert_eq!(by_email.len(), 1);

        let page = storage
            .list_users(&realm.id, "", &Pagination { first: 0, max: 1 })
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
    }

    #[tokio::test]
    async fn client_not_found_and_update_not_found() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        assert!(storage
            .get_client(&realm.id, &ClientId::new("missing").unwrap())
            .await
            .unwrap()
            .is_none());
        assert!(storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("nobody").unwrap())
            .await
            .unwrap()
            .is_none());

        let client = Client {
            id: ClientId::new("missing").unwrap(),
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new("nobody").unwrap(),
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
        assert_eq!(
            storage.update_client(&realm.id, &client).await.unwrap_err(),
            IssuerdError::NotFound
        );
    }

    #[tokio::test]
    async fn credential_wrong_type_and_update_not_found() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        let user = test_user("realm-1");
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();

        let cred = test_credential();
        storage.create_credential(&realm.id, &user.id, &cred).await.unwrap();

        let wrong = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Totp)
            .await
            .unwrap();
        assert!(wrong.is_empty());

        let mut updated = cred.clone();
        updated.id = CredentialId::new("missing").unwrap();
        storage.update_credential(&realm.id, &user.id, &updated).await.unwrap();
        // update_credential silently does nothing when not found
    }

    #[tokio::test]
    async fn session_not_found_and_update_not_found() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        assert!(storage
            .get_user_session(&realm.id, &SessionId::new("missing").unwrap())
            .await
            .unwrap()
            .is_none());

        let session = UserSession {
            id: SessionId::new("missing").unwrap(),
            realm_id: realm.id.clone(),
            user_id: UserId::new("user-1").unwrap(),
            login_username: issuerd_core::Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
            clients: vec![],
        };
        assert_eq!(
            storage.update_user_session(&realm.id, &session).await.unwrap_err(),
            IssuerdError::NotFound
        );
    }

    #[tokio::test]
    async fn session_list_without_user_filter_and_pagination() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        let user = test_user("realm-1");
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();

        let session = test_session("realm-1");
        storage.create_user_session(&realm.id, &session).await.unwrap();

        let all = storage.list_sessions(&realm.id, None, &Pagination::default()).await.unwrap();
        assert_eq!(all.len(), 1);

        let empty = storage
            .list_sessions(&realm.id, None, &Pagination { first: 10, max: 10 })
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn role_not_found_and_update_not_found() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        assert!(storage
            .get_role(&realm.id, &RoleId::new("missing").unwrap())
            .await
            .unwrap()
            .is_none());
        assert!(storage.get_role_by_name(&realm.id, "nobody").await.unwrap().is_none());

        let role = Role {
            id: RoleId::new("missing").unwrap(),
            name: RoleName::new("nobody").unwrap(),
            description: None,
            realm_id: realm.id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        assert_eq!(
            storage.update_role(&realm.id, &role).await.unwrap_err(),
            IssuerdError::NotFound
        );
    }

    #[tokio::test]
    async fn role_list_pagination_and_delete_cascade() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        for i in 0..3 {
            let mut r = test_role("realm-1");
            r.id = RoleId::new(format!("role-{i}")).unwrap();
            r.name = RoleName::new(format!("role-{i:02}")).unwrap();
            storage.create_role(&realm.id, &r).await.unwrap();
        }

        let page = storage.list_roles(&realm.id, &Pagination { first: 1, max: 1 }).await.unwrap();
        assert_eq!(page.len(), 1);

        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();
        storage
            .add_user_realm_role(&realm.id, &user.id, &RoleId::new("role-0").unwrap())
            .await
            .unwrap();
        storage.delete_role(&realm.id, &RoleId::new("role-0").unwrap()).await.unwrap();
        let roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn group_not_found_and_update_not_found_and_delete_cascade() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        assert!(storage
            .get_group(&realm.id, &GroupId::new("missing").unwrap())
            .await
            .unwrap()
            .is_none());

        let group = Group {
            id: GroupId::new("missing").unwrap(),
            name: GroupName::new("nobody").unwrap(),
            path: GroupPath::new("/nobody").unwrap(),
            realm_id: realm.id.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        assert_eq!(
            storage.update_group(&realm.id, &group).await.unwrap_err(),
            IssuerdError::NotFound
        );

        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();
        let g = test_group("realm-1");
        storage.create_group(&realm.id, &g).await.unwrap();
        storage.add_user_group(&realm.id, &user.id, &g.id).await.unwrap();
        storage.delete_group(&realm.id, &g.id).await.unwrap();
        let groups = storage.list_user_groups(&realm.id, &user.id).await.unwrap();
        assert!(groups.is_empty());
    }

    #[tokio::test]
    async fn group_list_pagination() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        for i in 0..3 {
            let mut g = test_group("realm-1");
            g.id = GroupId::new(format!("group-{i}")).unwrap();
            g.name = GroupName::new(format!("group-{i:02}")).unwrap();
            storage.create_group(&realm.id, &g).await.unwrap();
        }

        let page = storage.list_groups(&realm.id, &Pagination { first: 1, max: 1 }).await.unwrap();
        assert_eq!(page.len(), 1);
    }

    #[tokio::test]
    async fn membership_edge_cases() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();

        assert!(storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap().is_empty());
        assert!(storage.list_user_groups(&realm.id, &user.id).await.unwrap().is_empty());

        // Duplicate add should be idempotent
        storage
            .add_user_realm_role(&realm.id, &user.id, &RoleId::new("role-1").unwrap())
            .await
            .unwrap();
        storage
            .add_user_realm_role(&realm.id, &user.id, &RoleId::new("role-1").unwrap())
            .await
            .unwrap();
        let roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert_eq!(roles.len(), 1);

        storage
            .add_user_group(&realm.id, &user.id, &GroupId::new("group-1").unwrap())
            .await
            .unwrap();
        storage
            .add_user_group(&realm.id, &user.id, &GroupId::new("group-1").unwrap())
            .await
            .unwrap();
        let groups = storage.list_user_groups(&realm.id, &user.id).await.unwrap();
        assert_eq!(groups.len(), 1);

        // Remove non-existent should not error
        storage
            .remove_user_realm_role(&realm.id, &user.id, &RoleId::new("missing").unwrap())
            .await
            .unwrap();
        storage
            .remove_user_group(&realm.id, &user.id, &GroupId::new("missing").unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn event_query_filters() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let mut ev1 = test_event("realm-1", EventType::Login);
        ev1.id = EventId::new("event-1").unwrap();
        ev1.event_time = Utc::now() - chrono::Duration::hours(1);
        ev1.client_id = Some(ClientId::new("client-a").unwrap());
        ev1.user_id = Some(UserId::new("user-a").unwrap());
        storage.save_event(&realm.id, &ev1).await.unwrap();

        let mut ev2 = test_event("realm-1", EventType::Logout);
        ev2.id = EventId::new("event-2").unwrap();
        ev2.event_time = Utc::now();
        ev2.client_id = Some(ClientId::new("client-b").unwrap());
        ev2.user_id = Some(UserId::new("user-b").unwrap());
        storage.save_event(&realm.id, &ev2).await.unwrap();

        // Filter by date_from
        let query = EventQuery {
            event_type: None,
            client_id: None,
            user_id: None,
            date_from: Some(Utc::now() - chrono::Duration::minutes(30)),
            date_to: None,
            pagination: Pagination::default(),
        };
        let results = storage.query_events(&realm.id, &query).await.unwrap();
        assert_eq!(results.len(), 1);

        // Filter by date_to
        let query = EventQuery {
            event_type: None,
            client_id: None,
            user_id: None,
            date_from: None,
            date_to: Some(Utc::now() - chrono::Duration::minutes(30)),
            pagination: Pagination::default(),
        };
        let results = storage.query_events(&realm.id, &query).await.unwrap();
        assert_eq!(results.len(), 1);

        // Filter by client_id
        let query = EventQuery {
            event_type: None,
            client_id: Some(ClientId::new("client-a").unwrap()),
            user_id: None,
            date_from: None,
            date_to: None,
            pagination: Pagination::default(),
        };
        let results = storage.query_events(&realm.id, &query).await.unwrap();
        assert_eq!(results.len(), 1);

        // Filter by user_id
        let query = EventQuery {
            event_type: None,
            client_id: None,
            user_id: Some(UserId::new("user-b").unwrap()),
            date_from: None,
            date_to: None,
            pagination: Pagination::default(),
        };
        let results = storage.query_events(&realm.id, &query).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn idp_alias_lookup_and_list() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let idp = test_idp();
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();

        let by_alias = storage.get_identity_provider_by_alias(&realm.id, "google").await.unwrap();
        assert!(by_alias.is_some());
        assert!(storage
            .get_identity_provider_by_alias(&realm.id, "missing")
            .await
            .unwrap()
            .is_none());

        let list = storage.list_identity_providers(&realm.id).await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn idp_update_not_found() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let idp = test_idp();
        assert_eq!(
            storage.update_identity_provider(&realm.id, &idp).await.unwrap_err(),
            IssuerdError::NotFound
        );
    }

    fn test_link(user_id: &str, alias: &str, subject: &str) -> IdentityProviderLink {
        IdentityProviderLink {
            user_id: UserId::new(user_id).unwrap(),
            provider_alias: alias.to_string(),
            external_subject: subject.to_string(),
            external_username: Some("ext-user".to_string()),
            stored_refresh_token: None,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn idp_link_crud_and_uniqueness() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let link = test_link("user-1", "google", "sub-1");
        storage.create_identity_provider_link(&realm.id, &link).await.unwrap();

        // Lookup by external subject and by user+alias.
        let found = storage.get_identity_provider_link(&realm.id, "google", "sub-1").await.unwrap();
        assert_eq!(found.as_ref().map(|l| &l.user_id), Some(&link.user_id));
        let for_user = storage
            .get_identity_provider_link_for_user(&realm.id, &link.user_id, "google")
            .await
            .unwrap();
        assert_eq!(for_user.as_ref().map(|l| &l.external_subject), Some(&"sub-1".to_string()));

        let list = storage.list_identity_provider_links(&realm.id, &link.user_id).await.unwrap();
        assert_eq!(list.len(), 1);

        // Same external subject again -> conflict.
        let dup_subject = test_link("user-2", "google", "sub-1");
        assert_eq!(
            storage
                .create_identity_provider_link(&realm.id, &dup_subject)
                .await
                .unwrap_err(),
            IssuerdError::Conflict
        );
        // Same user + provider again -> conflict.
        let dup_user = test_link("user-1", "google", "sub-9");
        assert_eq!(
            storage.create_identity_provider_link(&realm.id, &dup_user).await.unwrap_err(),
            IssuerdError::Conflict
        );
        // Different provider alias for the same user is fine.
        storage
            .create_identity_provider_link(&realm.id, &test_link("user-1", "github", "sub-1"))
            .await
            .unwrap();

        storage
            .delete_identity_provider_link(&realm.id, &link.user_id, "google")
            .await
            .unwrap();
        assert!(storage
            .get_identity_provider_link(&realm.id, "google", "sub-1")
            .await
            .unwrap()
            .is_none());
        // The github link survives.
        assert_eq!(
            storage
                .list_identity_provider_links(&realm.id, &link.user_id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn idp_link_cascades_on_user_and_realm_delete() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();
        storage
            .create_identity_provider_link(&realm.id, &test_link("user-1", "google", "sub-1"))
            .await
            .unwrap();

        storage.delete_user(&realm.id, &user.id).await.unwrap();
        assert!(storage
            .get_identity_provider_link(&realm.id, "google", "sub-1")
            .await
            .unwrap()
            .is_none());

        // Realm delete cascades too.
        storage.create_user(&realm.id, &user).await.unwrap();
        storage
            .create_identity_provider_link(&realm.id, &test_link("user-1", "google", "sub-2"))
            .await
            .unwrap();
        storage.delete_realm(&realm.id).await.unwrap();
        assert!(storage
            .get_identity_provider_link(&realm.id, "google", "sub-2")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn idp_link_cascades_on_provider_delete() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let idp = test_idp();
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();
        storage
            .create_identity_provider_link(&realm.id, &test_link("user-1", "google", "sub-1"))
            .await
            .unwrap();

        storage.delete_identity_provider(&realm.id, &idp.id).await.unwrap();
        assert!(storage
            .get_identity_provider_link(&realm.id, "google", "sub-1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn idp_link_survives_snapshot_roundtrip() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        storage
            .create_identity_provider_link(&realm.id, &test_link("user-1", "google", "sub-1"))
            .await
            .unwrap();

        let snapshot = storage.to_snapshot();
        let storage2 = InMemoryStorage::new();
        storage2.load_snapshot(snapshot);
        let found =
            storage2.get_identity_provider_link(&realm.id, "google", "sub-1").await.unwrap();
        assert_eq!(found.map(|l| l.user_id), Some(UserId::new("user-1").unwrap()));
    }

    #[tokio::test]
    async fn flow_config_list_and_not_found() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let flow = test_flow_config("realm-1");
        storage.create_flow_config(&realm.id, &flow).await.unwrap();

        let list = storage.list_flow_configs(&realm.id).await.unwrap();
        // The realm also carries the seeded built-in flows.
        assert!(list.iter().any(|f| f.alias == flow.alias));

        assert!(storage.get_flow_config(&realm.id, "missing").await.unwrap().is_none());

        let mut updated = flow.clone();
        updated.alias = Alias::new("missing").unwrap();
        assert_eq!(
            storage.update_flow_config(&realm.id, &updated).await.unwrap_err(),
            IssuerdError::NotFound
        );
    }

    #[tokio::test]
    async fn default_creates_empty_storage() {
        let storage: InMemoryStorage = Default::default();
        assert!(storage.list_realms(&Pagination::default()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn snapshot_roundtrip_preserves_all_data() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();

        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();

        let cred = test_credential();
        storage.create_credential(&realm.id, &user.id, &cred).await.unwrap();

        let session = test_session("realm-1");
        storage.create_user_session(&realm.id, &session).await.unwrap();

        let role = test_role("realm-1");
        storage.create_role(&realm.id, &role).await.unwrap();

        let group = test_group("realm-1");
        storage.create_group(&realm.id, &group).await.unwrap();

        let consent = test_consent();
        storage.create_consent(&realm.id, &consent).await.unwrap();

        let idp = test_idp();
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();

        let flow = test_flow_config("realm-1");
        storage.create_flow_config(&realm.id, &flow).await.unwrap();

        let event = test_event("realm-1", EventType::Login);
        storage.save_event(&realm.id, &event).await.unwrap();

        let signing_key = test_signing_key("key-1", Utc::now());
        storage.create_signing_key(&signing_key).await.unwrap();

        let admin_event = AdminEvent {
            id: EventId::new("ae-1").unwrap(),
            realm_id: realm.id.clone(),
            event_time: Utc::now(),
            operation_type: OperationType::Create,
            resource_type: ResourceType::Realm,
            resource_path: "realms/realm-1".to_string(),
            representation: None,
            error: None,
            auth_realm_id: Some(realm.id.clone()),
            auth_client_id: None,
            auth_user_id: Some(UserId::new("admin").unwrap()),
        };
        storage.save_admin_event(&admin_event).await.unwrap();

        storage.add_user_realm_role(&realm.id, &user.id, &role.id).await.unwrap();
        storage.add_user_group(&realm.id, &user.id, &group.id).await.unwrap();

        let snapshot = storage.to_snapshot();
        let storage2 = InMemoryStorage::new();
        storage2.load_snapshot(snapshot);

        assert_eq!(storage2.list_realms(&Pagination::default()).await.unwrap().len(), 1);
        assert_eq!(
            storage2.list_users(&realm.id, "", &Pagination::default()).await.unwrap().len(),
            1
        );
        assert_eq!(
            storage2.list_clients(&realm.id, &Pagination::default()).await.unwrap().len(),
            1
        );
        assert_eq!(
            storage2
                .list_sessions(&realm.id, None, &Pagination::default())
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(storage2.list_roles(&realm.id, &Pagination::default()).await.unwrap().len(), 1);
        assert_eq!(storage2.list_groups(&realm.id, &Pagination::default()).await.unwrap().len(), 1);
        assert_eq!(storage2.list_identity_providers(&realm.id).await.unwrap().len(), 1);
        // The test flow plus the seeded built-in browser + registration flows.
        assert_eq!(storage2.list_flow_configs(&realm.id).await.unwrap().len(), 2);
        assert_eq!(
            storage2
                .query_events(
                    &realm.id,
                    &EventQuery {
                        event_type: None,
                        client_id: None,
                        user_id: None,
                        date_from: None,
                        date_to: None,
                        pagination: Pagination::default()
                    }
                )
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            storage2
                .query_admin_events(
                    &realm.id,
                    &AdminEventQuery {
                        operation_type: None,
                        resource_type: None,
                        auth_user_id: None,
                        date_from: None,
                        date_to: None,
                        pagination: Pagination::default()
                    }
                )
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            storage2.list_user_realm_roles(&realm.id, &user.id).await.unwrap(),
            vec![role.id]
        );
        assert_eq!(storage2.list_user_groups(&realm.id, &user.id).await.unwrap(), vec![group.id]);
        assert_eq!(storage2.list_signing_keys().await.unwrap(), vec![signing_key]);
    }

    // ------------------------------------------------------------------
    // Signing keys
    // ------------------------------------------------------------------
    fn test_signing_key(kid: &str, created_at: chrono::DateTime<Utc>) -> StoredSigningKey {
        StoredSigningKey {
            kid: KeyId::new(kid).unwrap(),
            alg: Algorithm::Rs256,
            created_at,
            private_der: vec![1, 2, 3, 4],
            public_jwk: Jwk {
                kty: JwkKty::Rsa,
                kid: KeyId::new(kid).unwrap(),
                alg: Algorithm::Rs256,
                use_: JwkUse::Sig,
                n: Some(Base64Url::new("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2").unwrap()),
                e: Some(Base64Url::new("AQAB").unwrap()),
                x: None,
                y: None,
                crv: None,
                k: None,
            },
            active: true,
        }
    }

    #[tokio::test]
    async fn signing_key_create_and_list_roundtrip() {
        let storage = InMemoryStorage::new();
        let key = test_signing_key("key-1", Utc::now());

        storage.create_signing_key(&key).await.unwrap();

        let keys = storage.list_signing_keys().await.unwrap();
        assert_eq!(keys, vec![key]);
    }

    #[tokio::test]
    async fn signing_key_duplicate_kid_rejected() {
        let storage = InMemoryStorage::new();
        let key = test_signing_key("key-1", Utc::now());

        storage.create_signing_key(&key).await.unwrap();
        assert_eq!(
            storage.create_signing_key(&key).await.unwrap_err(),
            IssuerdError::InvalidRequest("signing key kid already exists".into())
        );
        assert_eq!(storage.list_signing_keys().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn signing_key_list_ordered_by_created_at() {
        let storage = InMemoryStorage::new();
        let base = Utc::now();
        let key1 = test_signing_key("key-1", base + chrono::Duration::seconds(20));
        let key2 = test_signing_key("key-2", base);
        let key3 = test_signing_key("key-3", base + chrono::Duration::seconds(10));

        // Insert out of order; list must come back oldest first.
        storage.create_signing_key(&key1).await.unwrap();
        storage.create_signing_key(&key3).await.unwrap();
        storage.create_signing_key(&key2).await.unwrap();

        let keys = storage.list_signing_keys().await.unwrap();
        assert_eq!(keys, vec![key2, key3, key1]);
    }

    #[tokio::test]
    async fn signing_key_update_active_flag() {
        let storage = InMemoryStorage::new();
        let key = test_signing_key("key-1", Utc::now());
        storage.create_signing_key(&key).await.unwrap();

        let mut disabled = key.clone();
        disabled.active = false;
        storage.update_signing_key(&disabled).await.unwrap();

        let keys = storage.list_signing_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(!keys[0].active);
        // Only the active flag is updated, nothing else.
        assert_eq!(keys[0].kid, key.kid);
        assert_eq!(keys[0].private_der, key.private_der);

        let unknown = test_signing_key("missing", Utc::now());
        assert_eq!(storage.update_signing_key(&unknown).await.unwrap_err(), IssuerdError::NotFound);
    }

    // ------------------------------------------------------------------
    // Credentials listing, events clearing, group members
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn list_credentials_returns_all_types() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();

        let password = test_credential();
        let mut totp = test_credential();
        totp.id = CredentialId::new("cred-2").unwrap();
        totp.credential_type = CredentialType::Totp;
        totp.priority = 2;
        storage.create_credential(&realm.id, &user.id, &password).await.unwrap();
        storage.create_credential(&realm.id, &user.id, &totp).await.unwrap();

        let all = storage.list_credentials(&realm.id, &user.id).await.unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|c| c.credential_type == CredentialType::Password));
        assert!(all.iter().any(|c| c.credential_type == CredentialType::Totp));

        // Scoped per user: a different user has no credentials.
        let other = UserId::new("user-2").unwrap();
        assert!(storage.list_credentials(&realm.id, &other).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_events_clears_only_the_realm() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        let realm2 = test_realm_2();
        storage.create_realm(&realm).await.unwrap();
        storage.create_realm(&realm2).await.unwrap();

        storage
            .save_event(&realm.id, &test_event("realm-1", EventType::Login))
            .await
            .unwrap();
        storage
            .save_event(&realm2.id, &test_event("realm-2", EventType::Login))
            .await
            .unwrap();

        storage.delete_events(&realm.id).await.unwrap();

        let query = EventQuery {
            event_type: None,
            client_id: None,
            user_id: None,
            date_from: None,
            date_to: None,
            pagination: Pagination::default(),
        };
        assert!(storage.query_events(&realm.id, &query).await.unwrap().is_empty());
        assert_eq!(storage.query_events(&realm2.id, &query).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn delete_admin_events_clears_only_the_realm() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        let realm2 = test_realm_2();
        storage.create_realm(&realm).await.unwrap();
        storage.create_realm(&realm2).await.unwrap();

        let admin_event = |id: &str, realm_id: RealmId| AdminEvent {
            id: EventId::new(id).unwrap(),
            realm_id,
            event_time: Utc::now(),
            operation_type: OperationType::Create,
            resource_type: ResourceType::Realm,
            resource_path: "realms/x".to_string(),
            representation: None,
            error: None,
            auth_realm_id: None,
            auth_client_id: None,
            auth_user_id: None,
        };
        storage.save_admin_event(&admin_event("ae-1", realm.id.clone())).await.unwrap();
        storage.save_admin_event(&admin_event("ae-2", realm2.id.clone())).await.unwrap();

        storage.delete_admin_events(&realm.id).await.unwrap();

        let query = AdminEventQuery {
            operation_type: None,
            resource_type: None,
            auth_user_id: None,
            date_from: None,
            date_to: None,
            pagination: Pagination::default(),
        };
        assert!(storage.query_admin_events(&realm.id, &query).await.unwrap().is_empty());
        assert_eq!(storage.query_admin_events(&realm2.id, &query).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn list_group_members_reverse_lookup_paginates() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let group = test_group("realm-1");
        let other_group = Group {
            id: GroupId::new("group-2").unwrap(),
            name: GroupName::new("other".to_string()).unwrap(),
            path: GroupPath::new("/other").unwrap(),
            realm_id: realm.id.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        storage.create_group(&realm.id, &group).await.unwrap();
        storage.create_group(&realm.id, &other_group).await.unwrap();

        for (n, name) in ["alice", "bob", "carol"].into_iter().enumerate() {
            let mut user = test_user("realm-1");
            user.id = UserId::new(format!("user-{n}")).unwrap();
            user.username = Username::new(name).unwrap();
            storage.create_user(&realm.id, &user).await.unwrap();
            storage.add_user_group(&realm.id, &user.id, &group.id).await.unwrap();
        }
        // dave belongs to the other group only.
        let mut dave = test_user("realm-1");
        dave.id = UserId::new("user-3").unwrap();
        dave.username = Username::new("dave").unwrap();
        storage.create_user(&realm.id, &dave).await.unwrap();
        storage.add_user_group(&realm.id, &dave.id, &other_group.id).await.unwrap();

        let members = storage.list_group_members(&realm.id, &group.id, 0, 100).await.unwrap();
        let names: Vec<&str> = members.iter().map(|u| u.username.as_ref()).collect();
        assert_eq!(names, vec!["alice", "bob", "carol"]);

        // Pagination: skip the first, take one.
        let page = storage.list_group_members(&realm.id, &group.id, 1, 1).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].username, "bob");

        // The other group only has dave.
        let other_members =
            storage.list_group_members(&realm.id, &other_group.id, 0, 100).await.unwrap();
        assert_eq!(other_members.len(), 1);
        assert_eq!(other_members[0].username, "dave");
    }

    // ------------------------------------------------------------------
    // Flow seeding
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn realm_creation_seeds_builtin_flows_idempotently() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let browser = storage.get_flow_config(&realm.id, "browser").await.unwrap().unwrap();
        assert_eq!(browser.stages.len(), 7);
        assert!(browser.built_in);
        let registration =
            storage.get_flow_config(&realm.id, "registration").await.unwrap().unwrap();
        assert_eq!(registration.stages.len(), 1);
        assert_eq!(storage.list_flow_configs(&realm.id).await.unwrap().len(), 2);

        // Seeding is idempotent: a second run changes nothing.
        crate::seed::seed_builtin_flows(&storage, &realm.id).await.unwrap();
        let flows = storage.list_flow_configs(&realm.id).await.unwrap();
        assert_eq!(flows.len(), 2);
        assert!(flows.contains(&browser));
        assert!(flows.contains(&registration));
    }

    // ------------------------------------------------------------------
    // Client scopes
    // ------------------------------------------------------------------
    fn test_client_scope(realm_id: &str, name: &str) -> ClientScope {
        ClientScope {
            id: ClientScopeId::new(format!("scope-{name}")).unwrap(),
            realm_id: RealmId::new(realm_id).unwrap(),
            name: name.to_string(),
            description: Some(format!("desc {name}")),
            protocol: ClientProtocol::OpenIdConnect,
            attributes: HashMap::new(),
            protocol_mappers: vec![],
            scope_mappings: ScopeMappings::default(),
        }
    }

    fn test_client_role(realm_id: &str, client: &ClientId, id: &str, name: &str) -> Role {
        Role {
            id: RoleId::new(id).unwrap(),
            name: RoleName::new(name).unwrap(),
            description: None,
            realm_id: RealmId::new(realm_id).unwrap(),
            client_role: true,
            client_id: Some(client.clone()),
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn client_scope_crud_roundtrip() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        // Realm creation seeded the 8 built-ins.
        assert_eq!(
            storage
                .list_client_scopes(&realm.id, &Pagination::default())
                .await
                .unwrap()
                .len(),
            8
        );

        let scope = test_client_scope("realm-1", "custom");
        storage.create_client_scope(&realm.id, &scope).await.unwrap();
        assert_eq!(
            storage.get_client_scope(&realm.id, &scope.id).await.unwrap(),
            Some(scope.clone())
        );
        assert_eq!(
            storage
                .get_client_scope_by_name(&realm.id, "custom")
                .await
                .unwrap()
                .map(|s| s.id),
            Some(scope.id.clone())
        );
        assert!(storage.get_client_scope_by_name(&realm.id, "missing").await.unwrap().is_none());

        let mut updated = scope.clone();
        updated.description = Some("updated".to_string());
        storage.update_client_scope(&realm.id, &updated).await.unwrap();
        assert_eq!(
            storage
                .get_client_scope(&realm.id, &scope.id)
                .await
                .unwrap()
                .unwrap()
                .description,
            Some("updated".to_string())
        );

        // Update of a missing scope is NotFound.
        let mut missing = scope.clone();
        missing.id = ClientScopeId::new("missing").unwrap();
        assert_eq!(
            storage.update_client_scope(&realm.id, &missing).await.unwrap_err(),
            IssuerdError::NotFound
        );

        // Sorted listing: acr, address, custom, email, ... — "custom" at index 2.
        let page = storage
            .list_client_scopes(&realm.id, &Pagination { first: 2, max: 1 })
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].name, "custom");

        storage.delete_client_scope(&realm.id, &scope.id).await.unwrap();
        assert!(storage.get_client_scope(&realm.id, &scope.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn client_scope_duplicate_name_rejected() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let scope = test_client_scope("realm-1", "custom");
        storage.create_client_scope(&realm.id, &scope).await.unwrap();
        let mut dup = scope.clone();
        dup.id = ClientScopeId::new("scope-dup").unwrap();
        assert_eq!(
            storage.create_client_scope(&realm.id, &dup).await.unwrap_err(),
            IssuerdError::Conflict
        );

        // Same name in another realm is fine.
        let realm2 = test_realm_2();
        storage.create_realm(&realm2).await.unwrap();
        let mut other = scope.clone();
        other.realm_id = realm2.id.clone();
        storage.create_client_scope(&realm2.id, &other).await.unwrap();
    }

    #[tokio::test]
    async fn realm_creation_seeds_builtin_scopes() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let scopes = storage.list_client_scopes(&realm.id, &Pagination::default()).await.unwrap();
        let names: Vec<&str> = scopes.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "acr",
                "address",
                "email",
                "offline_access",
                "phone",
                "profile",
                "roles",
                "web-origins"
            ]
        );
        // The roles scope carries the two role-list mappers.
        let roles = scopes.iter().find(|s| s.name == "roles").unwrap();
        assert_eq!(roles.protocol_mappers.len(), 2);

        // Realm defaults: profile/email/roles default, the rest optional.
        let defaults = storage.list_realm_default_client_scopes(&realm.id).await.unwrap();
        assert_eq!(defaults.len(), 8);
        for (id, is_default) in &defaults {
            let name = &scopes.iter().find(|s| s.id == *id).unwrap().name;
            if DEFAULT_DEFAULT_SCOPES.contains(&name.as_str()) {
                assert!(is_default);
            } else {
                assert!(!is_default);
                assert!(DEFAULT_OPTIONAL_SCOPES.contains(&name.as_str()));
            }
        }

        // Seeding is idempotent: a second run changes nothing.
        crate::seed::seed_builtin_client_scopes(&storage, &realm.id).await.unwrap();
        let again = storage.list_client_scopes(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(scopes, again);
        assert_eq!(storage.list_realm_default_client_scopes(&realm.id).await.unwrap().len(), 8);
    }

    #[tokio::test]
    async fn client_creation_seeds_scope_assignments() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let mut client = test_client("realm-1");
        client.default_scopes = Scope::parse("openid profile email");
        client.optional_scopes = Scope::parse("phone");
        storage.create_client(&realm.id, &client).await.unwrap();

        let scopes = storage.list_client_scopes(&realm.id, &Pagination::default()).await.unwrap();
        let id_of = |name: &str| scopes.iter().find(|s| s.name == name).unwrap().id.clone();
        let assignments =
            storage.list_client_scope_assignments(&realm.id, &client.id).await.unwrap();
        assert_eq!(assignments.len(), 4);
        assert!(assignments.contains(&(id_of("profile"), true)));
        assert!(assignments.contains(&(id_of("email"), true)));
        assert!(assignments.contains(&(id_of("phone"), false)));
        // `roles` carve-out: default even though the string lists omit it.
        assert!(assignments.contains(&(id_of("roles"), true)));

        // Seeding is idempotent.
        crate::seed::seed_client_scope_assignments(&storage, &realm.id, &client)
            .await
            .unwrap();
        let again = storage.list_client_scope_assignments(&realm.id, &client.id).await.unwrap();
        assert_eq!(again.len(), 4);

        // A client with empty scope lists still gets `roles` as default.
        let mut bare = test_client("realm-1");
        bare.id = ClientId::new("client-bare").unwrap();
        bare.client_id = ClientIdentifier::new("bare").unwrap();
        bare.default_scopes = Scope::empty();
        bare.optional_scopes = Scope::empty();
        storage.create_client(&realm.id, &bare).await.unwrap();
        let bare_assignments =
            storage.list_client_scope_assignments(&realm.id, &bare.id).await.unwrap();
        assert_eq!(bare_assignments, vec![(id_of("roles"), true)]);
    }

    #[tokio::test]
    async fn client_scope_assignment_lifecycle() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();

        let profile =
            storage.get_client_scope_by_name(&realm.id, "profile").await.unwrap().unwrap();
        let phone = storage.get_client_scope_by_name(&realm.id, "phone").await.unwrap().unwrap();

        storage
            .assign_client_scope(&realm.id, &client.id, &profile.id, true)
            .await
            .unwrap();
        storage
            .assign_client_scope(&realm.id, &client.id, &phone.id, false)
            .await
            .unwrap();

        // Seeded (email optional + roles default) plus the two above.
        let assignments =
            storage.list_client_scope_assignments(&realm.id, &client.id).await.unwrap();
        assert_eq!(assignments.len(), 4);
        assert!(assignments.contains(&(profile.id.clone(), true)));
        assert!(assignments.contains(&(phone.id.clone(), false)));

        // Re-assigning flips is_default without duplicating the row.
        storage
            .assign_client_scope(&realm.id, &client.id, &phone.id, true)
            .await
            .unwrap();
        let assignments =
            storage.list_client_scope_assignments(&realm.id, &client.id).await.unwrap();
        assert_eq!(assignments.len(), 4);
        assert!(assignments.contains(&(phone.id.clone(), true)));

        storage.unassign_client_scope(&realm.id, &client.id, &profile.id).await.unwrap();
        let assignments =
            storage.list_client_scope_assignments(&realm.id, &client.id).await.unwrap();
        assert!(!assignments.iter().any(|(s, _)| s == &profile.id));
        // Unassigning something not assigned is a no-op.
        storage.unassign_client_scope(&realm.id, &client.id, &profile.id).await.unwrap();
        assert_eq!(
            storage
                .list_client_scope_assignments(&realm.id, &client.id)
                .await
                .unwrap()
                .len(),
            3
        );
    }

    #[tokio::test]
    async fn realm_default_client_scopes_lifecycle() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let scopes = storage.list_client_scopes(&realm.id, &Pagination::default()).await.unwrap();
        let profile = scopes.iter().find(|s| s.name == "profile").unwrap();

        // Re-add is idempotent (upsert semantics).
        storage
            .add_realm_default_client_scope(&realm.id, &profile.id, true)
            .await
            .unwrap();
        assert_eq!(storage.list_realm_default_client_scopes(&realm.id).await.unwrap().len(), 8);

        // Adding with the flipped flag updates the row.
        storage
            .add_realm_default_client_scope(&realm.id, &profile.id, false)
            .await
            .unwrap();
        let defaults = storage.list_realm_default_client_scopes(&realm.id).await.unwrap();
        assert_eq!(defaults.len(), 8);
        assert!(defaults.contains(&(profile.id.clone(), false)));

        // Remove (twice: the second is a no-op).
        storage.remove_realm_default_client_scope(&realm.id, &profile.id).await.unwrap();
        storage.remove_realm_default_client_scope(&realm.id, &profile.id).await.unwrap();
        let defaults = storage.list_realm_default_client_scopes(&realm.id).await.unwrap();
        assert_eq!(defaults.len(), 7);
        assert!(!defaults.iter().any(|(s, _)| s == &profile.id));
    }

    #[tokio::test]
    async fn user_client_role_membership() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();
        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();

        let role1 = test_client_role("realm-1", &client.id, "cr-1", "viewer");
        let role2 = test_client_role("realm-1", &client.id, "cr-2", "editor");
        storage.create_role(&realm.id, &role1).await.unwrap();
        storage.create_role(&realm.id, &role2).await.unwrap();

        storage.add_user_client_role(&realm.id, &user.id, &role1.id).await.unwrap();
        storage.add_user_client_role(&realm.id, &user.id, &role2.id).await.unwrap();
        // Duplicate add dedupes.
        storage.add_user_client_role(&realm.id, &user.id, &role1.id).await.unwrap();
        let roles = storage.list_user_client_roles(&realm.id, &user.id).await.unwrap();
        assert_eq!(roles.len(), 2);

        storage.remove_user_client_role(&realm.id, &user.id, &role1.id).await.unwrap();
        assert_eq!(
            storage.list_user_client_roles(&realm.id, &user.id).await.unwrap(),
            vec![role2.id.clone()]
        );
        // Removing a missing mapping is a no-op.
        storage.remove_user_client_role(&realm.id, &user.id, &role1.id).await.unwrap();

        // Deleting the role purges the mapping.
        storage.delete_role(&realm.id, &role2.id).await.unwrap();
        assert!(storage.list_user_client_roles(&realm.id, &user.id).await.unwrap().is_empty());

        // Deleting the user purges too.
        storage.add_user_client_role(&realm.id, &user.id, &role1.id).await.unwrap();
        storage.delete_user(&realm.id, &user.id).await.unwrap();
        assert!(storage.list_user_client_roles(&realm.id, &user.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_role_by_name_prefers_realm_role() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();
        let mut client2 = test_client("realm-1");
        client2.id = ClientId::new("client-2").unwrap();
        client2.client_id = ClientIdentifier::new("other-app").unwrap();
        storage.create_client(&realm.id, &client2).await.unwrap();

        // A realm role and two client roles (different clients) share a name.
        let mut realm_role = test_role("realm-1");
        realm_role.id = RoleId::new("realm-role-shared").unwrap();
        realm_role.name = RoleName::new("shared").unwrap();
        storage.create_role(&realm.id, &realm_role).await.unwrap();
        let cr1 = test_client_role("realm-1", &client.id, "client-role-1", "shared");
        let cr2 = test_client_role("realm-1", &client2.id, "client-role-2", "shared");
        storage.create_role(&realm.id, &cr1).await.unwrap();
        storage.create_role(&realm.id, &cr2).await.unwrap();

        // Same name within the same client is rejected.
        let dup = test_client_role("realm-1", &client.id, "client-role-dup", "shared");
        assert!(storage.create_role(&realm.id, &dup).await.is_err());
        // A second realm role with the name is rejected too.
        let mut dup_realm = realm_role.clone();
        dup_realm.id = RoleId::new("realm-role-dup").unwrap();
        assert!(storage.create_role(&realm.id, &dup_realm).await.is_err());

        // The realm role wins the unqualified lookup...
        let found = storage.get_role_by_name(&realm.id, "shared").await.unwrap().unwrap();
        assert_eq!(found.id, realm_role.id);
        assert!(!found.client_role);
        // ...while client lookups stay client-scoped.
        assert_eq!(
            storage
                .get_client_role_by_name(&realm.id, &client.id, "shared")
                .await
                .unwrap()
                .unwrap()
                .id,
            cr1.id
        );
        assert_eq!(
            storage
                .get_client_role_by_name(&realm.id, &client2.id, "shared")
                .await
                .unwrap()
                .unwrap()
                .id,
            cr2.id
        );
        assert!(storage
            .get_client_role_by_name(&realm.id, &client.id, "missing")
            .await
            .unwrap()
            .is_none());

        let client_roles = storage
            .list_client_roles(&realm.id, &client.id, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(client_roles.len(), 1);
        assert_eq!(client_roles[0].id, cr1.id);

        // With no realm role present the client role is returned.
        storage.delete_role(&realm.id, &realm_role.id).await.unwrap();
        let found = storage.get_role_by_name(&realm.id, "shared").await.unwrap().unwrap();
        assert!(found.client_role);
    }

    #[tokio::test]
    async fn delete_client_scope_cascades_assignments_and_realm_defaults() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();

        // Seeding assigned `email` (optional) to the client and made it a
        // realm default.
        let email = storage.get_client_scope_by_name(&realm.id, "email").await.unwrap().unwrap();
        assert!(storage
            .list_client_scope_assignments(&realm.id, &client.id)
            .await
            .unwrap()
            .iter()
            .any(|(s, _)| s == &email.id));
        assert!(storage
            .list_realm_default_client_scopes(&realm.id)
            .await
            .unwrap()
            .iter()
            .any(|(s, _)| s == &email.id));

        storage.delete_client_scope(&realm.id, &email.id).await.unwrap();
        assert!(storage.get_client_scope(&realm.id, &email.id).await.unwrap().is_none());
        assert!(!storage
            .list_client_scope_assignments(&realm.id, &client.id)
            .await
            .unwrap()
            .iter()
            .any(|(s, _)| s == &email.id));
        assert!(!storage
            .list_realm_default_client_scopes(&realm.id)
            .await
            .unwrap()
            .iter()
            .any(|(s, _)| s == &email.id));
    }

    #[tokio::test]
    async fn delete_client_cascades_assignments_and_client_roles() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();
        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();
        let role = test_client_role("realm-1", &client.id, "cr-1", "viewer");
        storage.create_role(&realm.id, &role).await.unwrap();
        storage.add_user_client_role(&realm.id, &user.id, &role.id).await.unwrap();

        storage.delete_client(&realm.id, &client.id).await.unwrap();
        assert!(storage
            .list_client_scope_assignments(&realm.id, &client.id)
            .await
            .unwrap()
            .is_empty());
        assert!(storage.get_role(&realm.id, &role.id).await.unwrap().is_none());
        assert!(storage.list_user_client_roles(&realm.id, &user.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_realm_wipes_client_scope_state() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();
        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();
        let role = test_client_role("realm-1", &client.id, "cr-1", "viewer");
        storage.create_role(&realm.id, &role).await.unwrap();
        storage.add_user_client_role(&realm.id, &user.id, &role.id).await.unwrap();

        storage.delete_realm(&realm.id).await.unwrap();

        assert!(storage
            .list_client_scopes(&realm.id, &Pagination::default())
            .await
            .unwrap()
            .is_empty());
        assert!(storage
            .list_client_scope_assignments(&realm.id, &client.id)
            .await
            .unwrap()
            .is_empty());
        assert!(storage.list_realm_default_client_scopes(&realm.id).await.unwrap().is_empty());
        assert!(storage.list_user_client_roles(&realm.id, &user.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn snapshot_preserves_client_scope_state() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();
        let user = test_user("realm-1");
        storage.create_user(&realm.id, &user).await.unwrap();
        let role = test_client_role("realm-1", &client.id, "cr-1", "viewer");
        storage.create_role(&realm.id, &role).await.unwrap();
        storage.add_user_client_role(&realm.id, &user.id, &role.id).await.unwrap();

        let snapshot = storage.to_snapshot();
        let storage2 = InMemoryStorage::new();
        storage2.load_snapshot(snapshot);

        assert_eq!(
            storage2
                .list_client_scopes(&realm.id, &Pagination::default())
                .await
                .unwrap()
                .len(),
            8
        );
        assert_eq!(storage2.list_realm_default_client_scopes(&realm.id).await.unwrap().len(), 8);
        // email (optional) + roles (default) from the creation seeding.
        assert_eq!(
            storage2
                .list_client_scope_assignments(&realm.id, &client.id)
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            storage2.list_user_client_roles(&realm.id, &user.id).await.unwrap(),
            vec![role.id]
        );
    }

    #[tokio::test]
    async fn old_snapshot_without_client_scope_fields_still_loads() {
        let storage = InMemoryStorage::new();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let client = test_client("realm-1");
        storage.create_client(&realm.id, &client).await.unwrap();

        // Simulate a snapshot written before client scopes existed: strip the
        // new keys.
        let mut json = serde_json::to_value(storage.to_snapshot()).unwrap();
        let obj = json.as_object_mut().unwrap();
        obj.remove("client_scopes");
        obj.remove("client_scope_assignments");
        obj.remove("realm_default_client_scopes");
        obj.remove("user_client_roles");

        let snapshot: StorageSnapshot = serde_json::from_value(json).unwrap();
        let storage2 = InMemoryStorage::new();
        storage2.load_snapshot(snapshot);
        assert!(storage2.get_realm(&realm.id).await.unwrap().is_some());
        assert!(storage2
            .list_client_scopes(&realm.id, &Pagination::default())
            .await
            .unwrap()
            .is_empty());
        assert!(storage2
            .list_client_scope_assignments(&realm.id, &client.id)
            .await
            .unwrap()
            .is_empty());

        // The migration path restores scopes, defaults and assignments.
        crate::seed::seed_builtin_client_scopes(&storage2, &realm.id).await.unwrap();
        crate::seed::seed_client_scope_assignments(&storage2, &realm.id, &client)
            .await
            .unwrap();
        assert_eq!(
            storage2
                .list_client_scopes(&realm.id, &Pagination::default())
                .await
                .unwrap()
                .len(),
            8
        );
        assert_eq!(storage2.list_realm_default_client_scopes(&realm.id).await.unwrap().len(), 8);
        assert_eq!(
            storage2
                .list_client_scope_assignments(&realm.id, &client.id)
                .await
                .unwrap()
                .len(),
            2
        );
    }
}
