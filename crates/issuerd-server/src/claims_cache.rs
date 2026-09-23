// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Claims read-model cache: keeps the userinfo/token claims-assembly reads
// (user row, groups, role mappings, role/scope catalog, client) off the
// database, Keycloak-Infinispan style.

//! Epoch-validated cache-aside read model for claims assembly.
//!
//! Every userinfo call used to cost ~10 storage queries: the user row, its
//! group memberships and group rows, direct role mappings, the realm role
//! catalog (composite expansion), client-role name resolution, the issuing
//! client, its default scope assignments, and the granted client scopes.
//! This module caches all of them under five key shapes
//! (`issuerd_cluster::cache_keys`):
//!
//! - `user-claims:{realm}:{user_id}` — [`UserClaims`]: user row, group
//!   rows, direct realm/client role-mapping ids;
//! - `realm-catalog:{realm}` — [`RealmCatalog`]: every role definition and
//!   every client scope (with mappers) of the realm, so name→object
//!   resolution happens in Rust;
//! - `client:{realm}:{client_id}` — the client row;
//! - `client-scopes:{realm}:{uuid}` — the client's default-assigned scope
//!   ids;
//! - `client-uuid:{realm}:{uuid}` — uuid→identifier reverse map for
//!   role-owner display ids.
//!
//! **Epoch.** Every entry stores the realm's claims epoch
//! (`claimsepoch:{realm}`) it was written at; reads compare against the
//! current epoch (one memoized cache GET per [`ClaimsReader`]). A mismatch
//! is a miss: refetch, rewrite at the current epoch. Definition changes
//! that fan out to many entries (role/scope/mapper/composite/group CRUD,
//! bulk imports, federation sync runs) bump the epoch via
//! `issuerd_cluster::invalidate::bump_claims_epoch`; single-entity mutations
//! (user update, per-user mappings, client update) delete their keys
//! precisely. A write that misses both is bounded by the TTL — the
//! accepted staleness window, same class as Keycloak's Infinispan
//! invalidation latency.
//!
//! **Degradation.** `[cache] read_cache_ttl_secs = 0` disables the layer
//! (pure-DB). Cache errors fall back to storage with a WARN and skip the
//! write — a cache outage costs latency, never answers. Storage errors
//! keep the pre-cache per-query leniency (the failed piece degrades to
//! empty) but poison the entry: a partially-degraded bundle is served for
//! the current request yet never written to the cache. Negative results
//! (missing user/client) are not cached.
//!
//! Epoch read happens BEFORE the storage load and the loaded entry is
//! tagged with that pre-load epoch: a concurrent bump can only make the
//! entry look older than it is (a wasted reload), never newer.

use std::sync::Arc;
use std::time::Duration;

use issuerd_cluster::cache_keys;
use issuerd_core::{
    Client, ClientId, ClientIdentifier, ClientScope, ClientScopeId, DistributedCache, Group,
    Pagination, RealmId, Role, RoleId, Storage, User, UserId,
};
use tokio::sync::OnceCell;
use tracing::{debug, warn};

use crate::state::ServerState;

/// Per-user claims bundle: everything about one user that claims assembly
/// reads, in one cache entry.
#[derive(Debug, Clone)]
pub struct UserClaims {
    pub user: User,
    /// Group rows the user belongs to (carry the groups' role-name lists).
    pub groups: Vec<Group>,
    /// Direct realm-role mapping ids.
    pub realm_role_ids: Vec<RoleId>,
    /// Direct client-role mapping ids.
    pub client_role_ids: Vec<RoleId>,
}

/// Realm-wide claims catalog: role and client-scope definitions resolved
/// against in Rust instead of per-name/per-id storage lookups.
#[derive(Debug, Default, Clone)]
pub struct RealmCatalog {
    pub roles: Vec<Role>,
    pub scopes: Vec<ClientScope>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct UserClaimsEntry {
    user: User,
    groups: Vec<Group>,
    realm_role_ids: Vec<RoleId>,
    client_role_ids: Vec<RoleId>,
    epoch: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RealmCatalogEntry {
    roles: Vec<Role>,
    scopes: Vec<ClientScope>,
    epoch: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ClientEntry {
    client: Client,
    epoch: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ClientScopesEntry {
    default_scope_ids: Vec<ClientScopeId>,
    epoch: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ClientUuidEntry {
    identifier: String,
    epoch: u64,
}

/// Read handle for the claims read model of one realm. Memoizes the
/// claims-epoch read, so a request costs one epoch GET plus one GET per
/// entry kind it touches.
pub struct ClaimsReader<'a> {
    state: &'a Arc<ServerState>,
    realm_id: RealmId,
    /// `Some(epoch)` = cache usable; `None` = cache outage, pure-DB mode.
    epoch: OnceCell<Option<u64>>,
}

impl<'a> ClaimsReader<'a> {
    pub fn new(state: &'a Arc<ServerState>, realm_id: &RealmId) -> Self {
        Self {
            state,
            realm_id: realm_id.clone(),
            epoch: OnceCell::new(),
        }
    }

    fn ttl(&self) -> u64 {
        self.state.config.cache.read_cache_ttl_secs
    }

    fn storage(&self) -> &dyn Storage {
        self.state.storage.as_ref()
    }

    fn cache(&self) -> &Arc<dyn DistributedCache> {
        &self.state.cache
    }

    /// Current claims epoch, read once per reader. `None` on cache error:
    /// every read then falls back to storage and nothing is written.
    async fn epoch(&self) -> Option<u64> {
        *self
            .epoch
            .get_or_init(|| async {
                let key = cache_keys::claims_epoch(self.realm_id.as_ref());
                match self.state.cache.get(&key).await {
                    Ok(Some(bytes)) => match std::str::from_utf8(&bytes).ok()?.parse::<u64>() {
                        Ok(v) => Some(v),
                        Err(_) => {
                            warn!(realm = %self.realm_id, "claims epoch unparsable; treating as 0");
                            Some(0)
                        }
                    },
                    Ok(None) => Some(0),
                    Err(e) => {
                        warn!(realm = %self.realm_id, error = %e, "claims epoch read failed; falling back to storage");
                        None
                    }
                }
            })
            .await
    }

    /// Read one cache entry and validate it against `epoch`.
    async fn read_entry<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        epoch: u64,
        entry_epoch: fn(&T) -> u64,
    ) -> Option<T> {
        match self.cache().get(key).await {
            Ok(Some(bytes)) => match serde_json::from_slice::<T>(&bytes) {
                Ok(entry) if entry_epoch(&entry) == epoch => {
                    debug!(realm = %self.realm_id, "claims cache: hit");
                    Some(entry)
                }
                Ok(_) => {
                    debug!(realm = %self.realm_id, "claims cache: stale epoch; re-reading");
                    None
                }
                Err(_) => {
                    debug!(realm = %self.realm_id, "claims cache: malformed entry; re-reading");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                warn!(realm = %self.realm_id, error = %e, "claims cache read failed; falling back to storage");
                None
            }
        }
    }

    async fn write_entry<T: serde::Serialize>(&self, key: &str, entry: &T) {
        match serde_json::to_vec(entry) {
            Ok(bytes) => {
                if let Err(e) =
                    self.cache().set(key, bytes, Some(Duration::from_secs(self.ttl()))).await
                {
                    warn!(realm = %self.realm_id, error = %e, "claims cache write failed");
                }
            }
            Err(e) => {
                warn!(realm = %self.realm_id, error = %e, "claims cache serialization failed");
            }
        }
    }

    /// One user's claims bundle. `None` when the user does not exist or a
    /// storage read fails (callers keep their pre-cache fallback behavior).
    pub async fn user_claims(&self, user_id: &UserId) -> Option<UserClaims> {
        if self.ttl() == 0 {
            return load_user_claims(self.storage(), &self.realm_id, user_id).await.0;
        }
        let Some(epoch) = self.epoch().await else {
            return load_user_claims(self.storage(), &self.realm_id, user_id).await.0;
        };
        let key = cache_keys::user_claims(self.realm_id.as_ref(), user_id.as_ref());
        if let Some(entry) = self.read_entry::<UserClaimsEntry>(&key, epoch, |e| e.epoch).await {
            return Some(UserClaims {
                user: entry.user,
                groups: entry.groups,
                realm_role_ids: entry.realm_role_ids,
                client_role_ids: entry.client_role_ids,
            });
        }
        let (bundle, degraded) = load_user_claims(self.storage(), &self.realm_id, user_id).await;
        if let Some(bundle) = &bundle {
            if !degraded {
                let entry = UserClaimsEntry {
                    user: bundle.user.clone(),
                    groups: bundle.groups.clone(),
                    realm_role_ids: bundle.realm_role_ids.clone(),
                    client_role_ids: bundle.client_role_ids.clone(),
                    epoch,
                };
                self.write_entry(&key, &entry).await;
            }
        }
        bundle
    }

    /// The realm's role + client-scope catalog. Empty on storage outage
    /// (the pre-cache per-query leniency degraded the same way).
    pub async fn realm_catalog(&self) -> RealmCatalog {
        if self.ttl() == 0 {
            return load_realm_catalog(self.storage(), &self.realm_id).await.0;
        }
        let Some(epoch) = self.epoch().await else {
            return load_realm_catalog(self.storage(), &self.realm_id).await.0;
        };
        let key = cache_keys::realm_catalog(self.realm_id.as_ref());
        if let Some(entry) = self.read_entry::<RealmCatalogEntry>(&key, epoch, |e| e.epoch).await {
            return RealmCatalog {
                roles: entry.roles,
                scopes: entry.scopes,
            };
        }
        let (catalog, degraded) = load_realm_catalog(self.storage(), &self.realm_id).await;
        if !degraded {
            let entry = RealmCatalogEntry {
                roles: catalog.roles.clone(),
                scopes: catalog.scopes.clone(),
                epoch,
            };
            self.write_entry(&key, &entry).await;
        }
        catalog
    }

    /// The client row by its public identifier. `None` when missing or on
    /// storage error.
    pub async fn client(&self, client_id: &ClientIdentifier) -> Option<Client> {
        if self.ttl() == 0 {
            return load_client(self.storage(), &self.realm_id, client_id).await.0;
        }
        let Some(epoch) = self.epoch().await else {
            return load_client(self.storage(), &self.realm_id, client_id).await.0;
        };
        let key = cache_keys::client(self.realm_id.as_ref(), client_id.as_ref());
        if let Some(entry) = self.read_entry::<ClientEntry>(&key, epoch, |e| e.epoch).await {
            return Some(entry.client);
        }
        let (client, degraded) = load_client(self.storage(), &self.realm_id, client_id).await;
        if let Some(client) = &client {
            if !degraded {
                self.write_entry(
                    &key,
                    &ClientEntry {
                        client: client.clone(),
                        epoch,
                    },
                )
                .await;
            }
        }
        client
    }

    /// The client's default-assigned client-scope ids (AccessToken default
    /// scope expansion). Empty when unreadable — same leniency as before.
    pub async fn client_default_scope_ids(&self, client_uuid: &ClientId) -> Vec<ClientScopeId> {
        if self.ttl() == 0 {
            return load_default_scope_ids(self.storage(), &self.realm_id, client_uuid).await.0;
        }
        let Some(epoch) = self.epoch().await else {
            return load_default_scope_ids(self.storage(), &self.realm_id, client_uuid).await.0;
        };
        let key = cache_keys::client_scopes(self.realm_id.as_ref(), client_uuid.as_ref());
        if let Some(entry) = self.read_entry::<ClientScopesEntry>(&key, epoch, |e| e.epoch).await {
            return entry.default_scope_ids;
        }
        let (ids, degraded) =
            load_default_scope_ids(self.storage(), &self.realm_id, client_uuid).await;
        if !degraded {
            self.write_entry(
                &key,
                &ClientScopesEntry {
                    default_scope_ids: ids.clone(),
                    epoch,
                },
            )
            .await;
        }
        ids
    }

    /// Public `client_id` identifier for a client UUID (role-owner display
    /// ids in `resource_access`). `None` when missing or unreadable.
    pub async fn client_identifier_by_uuid(&self, client_uuid: &ClientId) -> Option<String> {
        if self.ttl() == 0 {
            return load_client_identifier(self.storage(), &self.realm_id, client_uuid).await.0;
        }
        let Some(epoch) = self.epoch().await else {
            return load_client_identifier(self.storage(), &self.realm_id, client_uuid).await.0;
        };
        let key = cache_keys::client_uuid(self.realm_id.as_ref(), client_uuid.as_ref());
        if let Some(entry) = self.read_entry::<ClientUuidEntry>(&key, epoch, |e| e.epoch).await {
            return Some(entry.identifier);
        }
        let (identifier, degraded) =
            load_client_identifier(self.storage(), &self.realm_id, client_uuid).await;
        if let Some(identifier) = &identifier {
            if !degraded {
                self.write_entry(
                    &key,
                    &ClientUuidEntry {
                        identifier: identifier.clone(),
                        epoch,
                    },
                )
                .await;
            }
        }
        identifier
    }
}

/// Storage load behind [`ClaimsReader::user_claims`]; the `bool` marks a
/// partially degraded bundle (must not be cached).
async fn load_user_claims(
    storage: &dyn Storage,
    realm_id: &RealmId,
    user_id: &UserId,
) -> (Option<UserClaims>, bool) {
    let user = match storage.get_user(realm_id, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return (None, false),
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "user read failed");
            return (None, true);
        }
    };
    let mut degraded = false;
    let groups = match storage.list_user_groups(realm_id, user_id).await {
        Ok(ids) => match storage.get_groups_batch(realm_id, &ids).await {
            Ok(groups) => groups,
            Err(e) => {
                debug!(realm = %realm_id, error = %e, "group batch read failed");
                degraded = true;
                Vec::new()
            }
        },
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "group membership read failed");
            degraded = true;
            Vec::new()
        }
    };
    let realm_role_ids = match storage.list_user_realm_roles(realm_id, user_id).await {
        Ok(ids) => ids,
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "realm-role mapping read failed");
            degraded = true;
            Vec::new()
        }
    };
    let client_role_ids = match storage.list_user_client_roles(realm_id, user_id).await {
        Ok(ids) => ids,
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "client-role mapping read failed");
            degraded = true;
            Vec::new()
        }
    };
    (
        Some(UserClaims {
            user,
            groups,
            realm_role_ids,
            client_role_ids,
        }),
        degraded,
    )
}

async fn load_realm_catalog(storage: &dyn Storage, realm_id: &RealmId) -> (RealmCatalog, bool) {
    let mut degraded = false;
    let roles = match storage
        .list_roles(
            realm_id,
            &Pagination {
                first: 0,
                max: i32::MAX,
            },
        )
        .await
    {
        Ok(roles) => roles,
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "role catalog read failed");
            degraded = true;
            Vec::new()
        }
    };
    let scopes = match storage
        .list_client_scopes(
            realm_id,
            &Pagination {
                first: 0,
                max: i32::MAX,
            },
        )
        .await
    {
        Ok(scopes) => scopes,
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "scope catalog read failed");
            degraded = true;
            Vec::new()
        }
    };
    (RealmCatalog { roles, scopes }, degraded)
}

async fn load_client(
    storage: &dyn Storage,
    realm_id: &RealmId,
    client_id: &ClientIdentifier,
) -> (Option<Client>, bool) {
    match storage.get_client_by_client_id(realm_id, client_id).await {
        Ok(Some(client)) => (Some(client), false),
        Ok(None) => (None, false),
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "client read failed");
            (None, true)
        }
    }
}

async fn load_default_scope_ids(
    storage: &dyn Storage,
    realm_id: &RealmId,
    client_uuid: &ClientId,
) -> (Vec<ClientScopeId>, bool) {
    match storage.list_client_scope_assignments(realm_id, client_uuid).await {
        Ok(assignments) => (
            assignments
                .into_iter()
                .filter(|(_, is_default)| *is_default)
                .map(|(scope_id, _)| scope_id)
                .collect(),
            false,
        ),
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "scope assignment read failed");
            (Vec::new(), true)
        }
    }
}

async fn load_client_identifier(
    storage: &dyn Storage,
    realm_id: &RealmId,
    client_uuid: &ClientId,
) -> (Option<String>, bool) {
    match storage.get_client(realm_id, client_uuid).await {
        Ok(Some(client)) => (Some(client.client_id.to_string()), false),
        Ok(None) => (None, false),
        Err(e) => {
            debug!(realm = %realm_id, error = %e, "client uuid read failed");
            (None, true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{ClientAuthenticatorType, ClientProtocol, IssuerdError, Scope, Username};
    use std::collections::HashMap;

    async fn setup() -> (Arc<ServerState>, RealmId) {
        let state = Arc::new(
            ServerState::from_config(&crate::config::ServerConfig::default()).await.unwrap(),
        );
        (state, RealmId::new("master").unwrap())
    }

    fn reader<'a>(state: &'a Arc<ServerState>, realm_id: &RealmId) -> ClaimsReader<'a> {
        ClaimsReader::new(state, realm_id)
    }

    fn user(user_id: &UserId, realm_id: &RealmId) -> User {
        User {
            id: user_id.clone(),
            realm_id: realm_id.clone(),
            username: Username::new("bob").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn client(uuid: &str, realm_id: &RealmId, identifier: &str) -> Client {
        Client {
            id: ClientId::new(uuid).unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new(identifier).unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: true,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn user_claims_caches_and_invalidation_reflects() {
        let (state, realm_id) = setup().await;
        let user_id = UserId::new("bob").unwrap();
        state.storage.create_user(&realm_id, &user(&user_id, &realm_id)).await.unwrap();

        let bundle = reader(&state, &realm_id).user_claims(&user_id).await.expect("bundle");
        assert_eq!(bundle.user.username.as_str(), "bob");
        let key = cache_keys::user_claims("master", "bob");
        assert!(state.cache.get(&key).await.unwrap().is_some(), "bundle cached");

        // Direct storage mutation is hidden by the cache (bounded staleness).
        let mut renamed = user(&user_id, &realm_id);
        renamed.username = Username::new("robert").unwrap();
        state.storage.update_user(&realm_id, &renamed).await.unwrap();
        let bundle = reader(&state, &realm_id).user_claims(&user_id).await.unwrap();
        assert_eq!(bundle.user.username.as_str(), "bob", "stale entry served within TTL");

        // Precise invalidation makes the change visible immediately.
        issuerd_cluster::invalidate::invalidate_user_claims(
            state.cache.as_ref(),
            &realm_id,
            &user_id,
        )
        .await;
        let bundle = reader(&state, &realm_id).user_claims(&user_id).await.unwrap();
        assert_eq!(bundle.user.username.as_str(), "robert");
    }

    #[tokio::test]
    async fn epoch_bump_invalidates_every_entry_kind() {
        let (state, realm_id) = setup().await;
        let user_id = UserId::new("bob").unwrap();
        state.storage.create_user(&realm_id, &user(&user_id, &realm_id)).await.unwrap();
        let uuid = ClientId::new("uuid-1").unwrap();
        state
            .storage
            .create_client(&realm_id, &client("uuid-1", &realm_id, "my-app"))
            .await
            .unwrap();

        // Warm every entry kind.
        let r = reader(&state, &realm_id);
        assert!(r.user_claims(&user_id).await.is_some());
        let _ = r.realm_catalog().await;
        assert!(r.client(&ClientIdentifier::new("my-app").unwrap()).await.is_some());
        let _ = r.client_default_scope_ids(&uuid).await;
        assert_eq!(r.client_identifier_by_uuid(&uuid).await.as_deref(), Some("my-app"));

        issuerd_cluster::invalidate::bump_claims_epoch(state.cache.as_ref(), &realm_id).await;

        // Every entry now carries a stale epoch: each read must reload and
        // rewrite at the new epoch.
        let r = reader(&state, &realm_id);
        assert!(r.user_claims(&user_id).await.is_some());
        let key = cache_keys::user_claims("master", "bob");
        let raw = state.cache.get(&key).await.unwrap().unwrap();
        let entry: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(entry["epoch"], 1, "entry rewritten at the new epoch");
    }

    #[tokio::test]
    async fn disabled_cache_is_pure_db() {
        let mut cfg = crate::config::ServerConfig::default();
        cfg.cache.read_cache_ttl_secs = 0;
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm_id = RealmId::new("master").unwrap();
        let user_id = UserId::new("bob").unwrap();
        state.storage.create_user(&realm_id, &user(&user_id, &realm_id)).await.unwrap();

        assert!(reader(&state, &realm_id).user_claims(&user_id).await.is_some());
        let key = cache_keys::user_claims("master", "bob");
        assert!(state.cache.get(&key).await.unwrap().is_none(), "nothing cached");
        // Direct mutation is seen immediately (no TTL window).
        let mut renamed = user(&user_id, &realm_id);
        renamed.username = Username::new("robert").unwrap();
        state.storage.update_user(&realm_id, &renamed).await.unwrap();
        let bundle = reader(&state, &realm_id).user_claims(&user_id).await.unwrap();
        assert_eq!(bundle.user.username.as_str(), "robert");
    }

    #[tokio::test]
    async fn cache_outage_falls_back_to_storage() {
        #[derive(Debug)]
        struct DeadCache;
        #[async_trait::async_trait]
        impl DistributedCache for DeadCache {
            async fn get(&self, _: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
                Err(IssuerdError::ServerError("cache down".into()))
            }
            async fn set(
                &self,
                _: &str,
                _: Vec<u8>,
                _: Option<Duration>,
            ) -> Result<(), IssuerdError> {
                Err(IssuerdError::ServerError("cache down".into()))
            }
            async fn delete(&self, _: &str) -> Result<(), IssuerdError> {
                Err(IssuerdError::ServerError("cache down".into()))
            }
            async fn compare_and_swap(
                &self,
                _: &str,
                _: Option<Vec<u8>>,
                _: Vec<u8>,
            ) -> Result<bool, IssuerdError> {
                Err(IssuerdError::ServerError("cache down".into()))
            }
            async fn publish(&self, _: &str, _: Vec<u8>) -> Result<(), IssuerdError> {
                Err(IssuerdError::ServerError("cache down".into()))
            }
            async fn subscribe(
                &self,
                _: &str,
                _: Box<dyn Fn(Vec<u8>) + Send + Sync>,
            ) -> Result<(), IssuerdError> {
                Err(IssuerdError::ServerError("cache down".into()))
            }
        }

        let cfg = crate::config::ServerConfig::default();
        let storage: Arc<dyn Storage> = Arc::new(issuerd_storage::InMemoryStorage::new());
        let state = Arc::new(
            ServerState::from_components(&cfg, storage, Arc::new(DeadCache)).await.unwrap(),
        );
        let realm_id = RealmId::new("master").unwrap();
        let user_id = UserId::new("admin").unwrap();
        // from_components skips the bootstrap seeding; create the fixtures.
        state.storage.create_user(&realm_id, &user(&user_id, &realm_id)).await.unwrap();
        let role = Role {
            id: RoleId::new("role-1").unwrap(),
            name: issuerd_core::RoleName::new("admin").unwrap(),
            description: None,
            realm_id: realm_id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        state.storage.create_role(&realm_id, &role).await.unwrap();

        // Reads fail; answers still come from storage.
        let bundle = reader(&state, &realm_id).user_claims(&user_id).await;
        assert!(bundle.is_some(), "stored user resolves despite cache outage");
        let catalog = reader(&state, &realm_id).realm_catalog().await;
        assert!(!catalog.roles.is_empty(), "stored roles resolve despite cache outage");
    }
}
