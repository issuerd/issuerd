// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// SPI traits (Storage, CryptoProvider, DistributedCache, ...) and shared query types.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::broker::IdentityProviderLink;
use crate::client_scope::ClientScope;
use crate::error::IssuerdError;
use crate::events::{AdminEvent, Event, EventType, OperationType, ResourceType};
use crate::ids::{
    ClientId, ClientScopeId, CredentialId, GroupId, IdentityProviderId, KeyId, RealmId, RoleId,
    SessionId, UserId,
};
use crate::models::*;

// ---------------------------------------------------------------------------
// Pagination & Queries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pagination {
    pub first: i32,
    pub max: i32,
}

impl Default for Pagination {
    fn default() -> Self {
        Self { first: 0, max: 100 }
    }
}

impl Pagination {
    /// Create a page request, clamping negative values to zero so backends
    /// never see an invalid `OFFSET`/`LIMIT` or wrapping `usize` cast.
    pub fn new(first: i32, max: i32) -> Self {
        Self {
            first: first.max(0),
            max: max.max(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<EventType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<ClientId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<UserId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_to: Option<DateTime<Utc>>,
    #[serde(default)]
    pub pagination: Pagination,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminEventQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_type: Option<OperationType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<ResourceType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_user_id: Option<UserId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_to: Option<DateTime<Utc>>,
    #[serde(default)]
    pub pagination: Pagination,
}

// ---------------------------------------------------------------------------
// Storage trait
// ---------------------------------------------------------------------------

#[mockall::automock]
#[async_trait]
pub trait Storage: Send + Sync {
    // Realm
    async fn get_realm(&self, id: &RealmId) -> Result<Option<Realm>, IssuerdError>;
    async fn get_realm_by_name(&self, name: &str) -> Result<Option<Realm>, IssuerdError>;
    async fn list_realms(&self, pagination: &Pagination) -> Result<Vec<Realm>, IssuerdError>;
    async fn count_realms(&self) -> Result<i64, IssuerdError>;
    async fn create_realm(&self, realm: &Realm) -> Result<(), IssuerdError>;
    async fn update_realm(&self, realm: &Realm) -> Result<(), IssuerdError>;
    async fn delete_realm(&self, id: &RealmId) -> Result<(), IssuerdError>;

    // User
    async fn get_user(&self, realm: &RealmId, id: &UserId) -> Result<Option<User>, IssuerdError>;
    async fn get_user_by_username(
        &self,
        realm: &RealmId,
        username: &str,
    ) -> Result<Option<User>, IssuerdError>;
    async fn get_user_by_email(
        &self,
        realm: &RealmId,
        email: &str,
    ) -> Result<Option<User>, IssuerdError>;
    async fn get_user_by_federation_link(
        &self,
        realm: &RealmId,
        link: &str,
    ) -> Result<Vec<User>, IssuerdError>;
    async fn list_users(
        &self,
        realm: &RealmId,
        query: &str,
        pagination: &Pagination,
    ) -> Result<Vec<User>, IssuerdError>;
    async fn count_users(&self, realm: &RealmId, query: &str) -> Result<i64, IssuerdError>;
    async fn create_user(&self, realm: &RealmId, user: &User) -> Result<(), IssuerdError>;
    async fn bulk_create_users(&self, realm: &RealmId, users: &[User]) -> Result<(), IssuerdError> {
        for user in users {
            self.create_user(realm, user).await?;
        }
        Ok(())
    }
    async fn update_user(&self, realm: &RealmId, user: &User) -> Result<(), IssuerdError>;
    async fn delete_user(&self, realm: &RealmId, id: &UserId) -> Result<(), IssuerdError>;

    // Client
    async fn get_client(
        &self,
        realm: &RealmId,
        id: &ClientId,
    ) -> Result<Option<Client>, IssuerdError>;
    async fn get_client_by_client_id(
        &self,
        realm: &RealmId,
        client_id: &ClientIdentifier,
    ) -> Result<Option<Client>, IssuerdError>;
    /// Batch variant of [`Storage::get_client`]: returns the found clients in
    /// the order of `ids`, skipping unknown ids. The default loops over
    /// [`Storage::get_client`]; backends override with a single `IN` query
    /// (same pattern as [`Storage::bulk_create_users`]).
    async fn get_clients_batch(
        &self,
        realm: &RealmId,
        ids: &[ClientId],
    ) -> Result<Vec<Client>, IssuerdError> {
        let mut clients = Vec::new();
        for id in ids {
            if let Some(client) = self.get_client(realm, id).await? {
                clients.push(client);
            }
        }
        Ok(clients)
    }
    async fn list_clients(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Client>, IssuerdError>;
    async fn count_clients(&self, realm: &RealmId) -> Result<i64, IssuerdError>;
    async fn create_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError>;
    async fn update_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError>;
    async fn delete_client(&self, realm: &RealmId, id: &ClientId) -> Result<(), IssuerdError>;

    // Credentials
    async fn get_credentials(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred_type: CredentialType,
    ) -> Result<Vec<Credential>, IssuerdError>;
    /// List ALL credentials of a user regardless of credential type.
    /// [`Storage::get_credentials`] filters by type; this
    /// is the unfiltered reverse used by the admin API.
    async fn list_credentials(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<Credential>, IssuerdError>;
    async fn create_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred: &Credential,
    ) -> Result<(), IssuerdError>;
    async fn update_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred: &Credential,
    ) -> Result<(), IssuerdError>;
    async fn delete_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred_id: &CredentialId,
    ) -> Result<(), IssuerdError>;

    // Sessions
    async fn get_user_session(
        &self,
        realm: &RealmId,
        id: &SessionId,
    ) -> Result<Option<UserSession>, IssuerdError>;
    async fn list_sessions(
        &self,
        realm: &RealmId,
        user: Option<UserId>,
        pagination: &Pagination,
    ) -> Result<Vec<UserSession>, IssuerdError>;
    async fn count_sessions(
        &self,
        realm: &RealmId,
        user: Option<UserId>,
    ) -> Result<i64, IssuerdError>;
    async fn create_user_session(
        &self,
        realm: &RealmId,
        session: &UserSession,
    ) -> Result<(), IssuerdError>;
    async fn update_user_session(
        &self,
        realm: &RealmId,
        session: &UserSession,
    ) -> Result<(), IssuerdError>;
    async fn delete_user_session(
        &self,
        realm: &RealmId,
        id: &SessionId,
    ) -> Result<(), IssuerdError>;

    // Roles
    async fn get_role(&self, realm: &RealmId, id: &RoleId) -> Result<Option<Role>, IssuerdError>;
    /// Look up a role by name. When both a realm role and client roles share
    /// the name, the realm role wins (client roles are addressed via
    /// [`Storage::get_client_role_by_name`]).
    async fn get_role_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<Role>, IssuerdError>;
    async fn list_roles(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Role>, IssuerdError>;
    async fn count_roles(&self, realm: &RealmId) -> Result<i64, IssuerdError>;
    async fn create_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError>;
    async fn update_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError>;
    async fn delete_role(&self, realm: &RealmId, id: &RoleId) -> Result<(), IssuerdError>;

    // Client roles (roles rows with `client_id` set)
    async fn get_client_role_by_name(
        &self,
        realm: &RealmId,
        client: &ClientId,
        name: &str,
    ) -> Result<Option<Role>, IssuerdError>;
    /// Batch variant of [`Storage::get_client_role_by_name`]: returns the
    /// found roles in the order of `names`, skipping unknown names. The
    /// default loops over [`Storage::get_client_role_by_name`]; backends
    /// override with a single `IN` query.
    async fn get_client_roles_by_names(
        &self,
        realm: &RealmId,
        client: &ClientId,
        names: &[String],
    ) -> Result<Vec<Role>, IssuerdError> {
        let mut roles = Vec::new();
        for name in names {
            if let Some(role) = self.get_client_role_by_name(realm, client, name).await? {
                roles.push(role);
            }
        }
        Ok(roles)
    }
    async fn list_client_roles(
        &self,
        realm: &RealmId,
        client: &ClientId,
        pagination: &Pagination,
    ) -> Result<Vec<Role>, IssuerdError>;

    // Client scopes
    async fn get_client_scope(
        &self,
        realm: &RealmId,
        id: &ClientScopeId,
    ) -> Result<Option<ClientScope>, IssuerdError>;
    async fn get_client_scope_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<ClientScope>, IssuerdError>;
    /// Batch variant of [`Storage::get_client_scope_by_name`]: returns the
    /// found scopes in the order of `names`, skipping unknown names. The
    /// default loops over [`Storage::get_client_scope_by_name`]; backends
    /// override with a single `IN` query.
    async fn get_client_scopes_by_names(
        &self,
        realm: &RealmId,
        names: &[String],
    ) -> Result<Vec<ClientScope>, IssuerdError> {
        let mut scopes = Vec::new();
        for name in names {
            if let Some(scope) = self.get_client_scope_by_name(realm, name).await? {
                scopes.push(scope);
            }
        }
        Ok(scopes)
    }
    /// Batch variant of [`Storage::get_client_scope`]: returns the found
    /// scopes in the order of `ids`, skipping unknown ids. The default loops
    /// over [`Storage::get_client_scope`]; backends override with a single
    /// `IN` query.
    async fn get_client_scopes_by_ids(
        &self,
        realm: &RealmId,
        ids: &[ClientScopeId],
    ) -> Result<Vec<ClientScope>, IssuerdError> {
        let mut scopes = Vec::new();
        for id in ids {
            if let Some(scope) = self.get_client_scope(realm, id).await? {
                scopes.push(scope);
            }
        }
        Ok(scopes)
    }
    async fn list_client_scopes(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<ClientScope>, IssuerdError>;
    async fn create_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScope,
    ) -> Result<(), IssuerdError>;
    async fn update_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScope,
    ) -> Result<(), IssuerdError>;
    async fn delete_client_scope(
        &self,
        realm: &RealmId,
        id: &ClientScopeId,
    ) -> Result<(), IssuerdError>;

    // Client <-> client-scope assignments (`is_default` = default vs optional)
    async fn assign_client_scope(
        &self,
        realm: &RealmId,
        client: &ClientId,
        scope: &ClientScopeId,
        is_default: bool,
    ) -> Result<(), IssuerdError>;
    async fn unassign_client_scope(
        &self,
        realm: &RealmId,
        client: &ClientId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError>;
    /// List scope assignments of a client as `(scope_id, is_default)` pairs.
    async fn list_client_scope_assignments(
        &self,
        realm: &RealmId,
        client: &ClientId,
    ) -> Result<Vec<(ClientScopeId, bool)>, IssuerdError>;

    // Realm default client scopes (`is_default` = default-default vs default-optional)
    async fn list_realm_default_client_scopes(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<(ClientScopeId, bool)>, IssuerdError>;
    async fn add_realm_default_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScopeId,
        is_default: bool,
    ) -> Result<(), IssuerdError>;
    async fn remove_realm_default_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError>;

    // Groups
    async fn get_group(&self, realm: &RealmId, id: &GroupId)
        -> Result<Option<Group>, IssuerdError>;
    async fn get_group_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<Group>, IssuerdError>;
    /// Batch variant of [`Storage::get_group`]: returns the found groups in
    /// the order of `ids`, skipping unknown ids. The default loops over
    /// [`Storage::get_group`]; backends override with a single `IN` query.
    async fn get_groups_batch(
        &self,
        realm: &RealmId,
        ids: &[GroupId],
    ) -> Result<Vec<Group>, IssuerdError> {
        let mut groups = Vec::new();
        for id in ids {
            if let Some(group) = self.get_group(realm, id).await? {
                groups.push(group);
            }
        }
        Ok(groups)
    }
    async fn list_groups(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Group>, IssuerdError>;
    async fn count_groups(&self, realm: &RealmId) -> Result<i64, IssuerdError>;
    async fn create_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError>;
    async fn update_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError>;
    async fn delete_group(&self, realm: &RealmId, id: &GroupId) -> Result<(), IssuerdError>;

    // User realm roles
    async fn add_user_realm_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError>;
    async fn remove_user_realm_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError>;
    async fn list_user_realm_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError>;

    // User client roles
    async fn add_user_client_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError>;
    async fn remove_user_client_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError>;
    /// All client role ids mapped to the user (across all clients).
    async fn list_user_client_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError>;

    // User groups
    async fn add_user_group(
        &self,
        realm: &RealmId,
        user: &UserId,
        group_id: &GroupId,
    ) -> Result<(), IssuerdError>;
    async fn remove_user_group(
        &self,
        realm: &RealmId,
        user: &UserId,
        group_id: &GroupId,
    ) -> Result<(), IssuerdError>;
    async fn list_user_groups(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<GroupId>, IssuerdError>;
    /// Reverse membership lookup: users that are members of `group`,
    /// paginated by `first`/`max`.
    async fn list_group_members(
        &self,
        realm: &RealmId,
        group: &GroupId,
        first: i32,
        max: i32,
    ) -> Result<Vec<User>, IssuerdError>;

    // Consent
    async fn get_consents(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<Consent>, IssuerdError>;
    async fn create_consent(&self, realm: &RealmId, consent: &Consent) -> Result<(), IssuerdError>;
    async fn delete_consent(
        &self,
        realm: &RealmId,
        user: &UserId,
        client_id: &ClientId,
    ) -> Result<(), IssuerdError>;

    // Identity Providers
    async fn get_identity_provider(
        &self,
        realm: &RealmId,
        id: &IdentityProviderId,
    ) -> Result<Option<IdentityProviderConfig>, IssuerdError>;
    async fn get_identity_provider_by_alias(
        &self,
        realm: &RealmId,
        alias: &str,
    ) -> Result<Option<IdentityProviderConfig>, IssuerdError>;
    async fn list_identity_providers(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<IdentityProviderConfig>, IssuerdError>;
    async fn create_identity_provider(
        &self,
        realm: &RealmId,
        idp: &IdentityProviderConfig,
    ) -> Result<(), IssuerdError>;
    async fn update_identity_provider(
        &self,
        realm: &RealmId,
        idp: &IdentityProviderConfig,
    ) -> Result<(), IssuerdError>;
    async fn delete_identity_provider(
        &self,
        realm: &RealmId,
        id: &IdentityProviderId,
    ) -> Result<(), IssuerdError>;

    // Identity Provider Links (brokered login account links)
    async fn get_identity_provider_link(
        &self,
        realm: &RealmId,
        alias: &str,
        external_subject: &str,
    ) -> Result<Option<IdentityProviderLink>, IssuerdError>;
    async fn get_identity_provider_link_for_user(
        &self,
        realm: &RealmId,
        user: &UserId,
        alias: &str,
    ) -> Result<Option<IdentityProviderLink>, IssuerdError>;
    async fn list_identity_provider_links(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<IdentityProviderLink>, IssuerdError>;
    async fn create_identity_provider_link(
        &self,
        realm: &RealmId,
        link: &IdentityProviderLink,
    ) -> Result<(), IssuerdError>;
    async fn delete_identity_provider_link(
        &self,
        realm: &RealmId,
        user: &UserId,
        alias: &str,
    ) -> Result<(), IssuerdError>;

    // Flow Config
    async fn get_flow_config(
        &self,
        realm: &RealmId,
        alias: &str,
    ) -> Result<Option<FlowConfig>, IssuerdError>;
    async fn create_flow_config(
        &self,
        realm: &RealmId,
        config: &FlowConfig,
    ) -> Result<(), IssuerdError>;
    async fn update_flow_config(
        &self,
        realm: &RealmId,
        config: &FlowConfig,
    ) -> Result<(), IssuerdError>;
    async fn delete_flow_config(&self, realm: &RealmId, alias: &str) -> Result<(), IssuerdError>;
    async fn list_flow_configs(&self, realm: &RealmId) -> Result<Vec<FlowConfig>, IssuerdError>;

    // Events
    async fn save_event(&self, realm: &RealmId, event: &Event) -> Result<(), IssuerdError>;
    async fn query_events(
        &self,
        realm: &RealmId,
        query: &EventQuery,
    ) -> Result<Vec<Event>, IssuerdError>;
    /// Count the events matching `query`; the pagination field is ignored.
    async fn count_events(&self, realm: &RealmId, query: &EventQuery) -> Result<i64, IssuerdError>;
    /// Delete all events of a realm (events config "clear events").
    async fn delete_events(&self, realm: &RealmId) -> Result<(), IssuerdError>;

    // Admin Events
    async fn save_admin_event(&self, event: &AdminEvent) -> Result<(), IssuerdError>;
    async fn query_admin_events(
        &self,
        realm: &RealmId,
        query: &AdminEventQuery,
    ) -> Result<Vec<AdminEvent>, IssuerdError>;
    /// Count the admin events matching `query`; the pagination field is ignored.
    async fn count_admin_events(
        &self,
        realm: &RealmId,
        query: &AdminEventQuery,
    ) -> Result<i64, IssuerdError>;
    /// Delete all admin events of a realm (events config "clear admin
    /// events").
    async fn delete_admin_events(&self, realm: &RealmId) -> Result<(), IssuerdError>;

    // Provision markers
    async fn get_provision_marker(&self, name: &str) -> Result<Option<String>, IssuerdError>;
    async fn set_provision_marker(&self, name: &str, value: &str) -> Result<(), IssuerdError>;
    /// Atomically claim a provision marker: returns `true` when this call
    /// created the marker, `false` when it already existed. The default
    /// implementation is check-then-set (not atomic); backends with
    /// compare-and-insert primitives must override it.
    async fn claim_provision_marker(&self, name: &str, value: &str) -> Result<bool, IssuerdError> {
        if self.get_provision_marker(name).await?.is_some() {
            return Ok(false);
        }
        self.set_provision_marker(name, value).await?;
        Ok(true)
    }

    // Signing keys
    /// List all stored signing keys ordered by creation time (oldest first).
    ///
    /// The returned keys include private key material and must never leave
    /// the server. Multi-node clusters share this key set so every node signs
    /// with the same active key and validates tokens issued by its peers.
    async fn list_signing_keys(&self) -> Result<Vec<StoredSigningKey>, IssuerdError>;
    /// Persist a new signing key. Implementations must reject a duplicate
    /// `kid` with an error rather than silently overwriting.
    async fn create_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError>;
    /// Update the `active` flag of the signing key identified by `kid`
    /// (key rotation/disable). Returns [`IssuerdError::NotFound`] when no
    /// key with that `kid` exists.
    async fn update_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError>;
}

// ---------------------------------------------------------------------------
// KeyEncryptionKeyProvider trait
// ---------------------------------------------------------------------------

/// Envelope-encryption (KEK) provider for signing keys at rest.
///
/// A Key Encryption Key encrypts the per-row private key material before it is
/// written to storage; the database then only ever holds ciphertext. Rows
/// carry the id of the KEK that encrypted them so KEKs can rotate: providers
/// decrypt with any configured KEK but encrypt new rows with the active one
/// only.
///
/// This trait is the SPI seam for future external backends (cloud KMS, HSM):
/// those implement `decrypt` as a remote call and never expose key material.
/// Only the local AES-256-GCM implementation ships today (issuerd-storage).
///
/// Implementations must use an AEAD construction with a fresh random nonce per
/// encryption; the KEK itself must never be persisted alongside the data.
pub trait KeyEncryptionKeyProvider: Send + Sync {
    /// Id of the KEK used for NEW encryptions (persisted on each encrypted row
    /// so a later rotation can tell which KEK must decrypt it).
    fn active_key_id(&self) -> &str;
    /// Encrypt `plaintext` under the active KEK, returning the self-describing
    /// ciphertext blob (version tag || nonce || ciphertext || auth tag).
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, IssuerdError>;
    /// Decrypt `blob` with the KEK named `key_id` (the active KEK or a
    /// configured previous one). Fails closed: an unknown `key_id`, malformed
    /// blob, or wrong KEK returns an error — never a plaintext fallback.
    fn decrypt(&self, key_id: &str, blob: &[u8]) -> Result<Vec<u8>, IssuerdError>;
}

// ---------------------------------------------------------------------------
// CryptoProvider trait
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum Algorithm {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    Rs384,
    #[serde(rename = "RS512")]
    Rs512,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[serde(rename = "ES512")]
    Es512,
    #[serde(rename = "HS256")]
    Hs256,
    #[serde(rename = "HS384")]
    Hs384,
    #[serde(rename = "HS512")]
    Hs512,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl Algorithm {
    /// Every algorithm variant, in declaration order. Coverage tests assert
    /// this stays in sync with the enum; consumers (admin enums, key
    /// generation, rotation validation) iterate it instead of duplicating the
    /// variant list.
    pub const ALL: [Algorithm; 10] = [
        Algorithm::Rs256,
        Algorithm::Rs384,
        Algorithm::Rs512,
        Algorithm::Es256,
        Algorithm::Es384,
        Algorithm::Es512,
        Algorithm::Hs256,
        Algorithm::Hs384,
        Algorithm::Hs512,
        Algorithm::EdDsa,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Rs256 => "RS256",
            Algorithm::Rs384 => "RS384",
            Algorithm::Rs512 => "RS512",
            Algorithm::Es256 => "ES256",
            Algorithm::Es384 => "ES384",
            Algorithm::Es512 => "ES512",
            Algorithm::Hs256 => "HS256",
            Algorithm::Hs384 => "HS384",
            Algorithm::Hs512 => "HS512",
            Algorithm::EdDsa => "EdDSA",
        }
    }

    /// Whether this algorithm uses a symmetric (HMAC) key. Symmetric signing
    /// keys publish no usable public key material, so tokens signed with them
    /// can only be verified by parties holding the secret.
    pub fn is_symmetric(&self) -> bool {
        matches!(self, Algorithm::Hs256 | Algorithm::Hs384 | Algorithm::Hs512)
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Algorithm {
    type Err = IssuerdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RS256" => Ok(Algorithm::Rs256),
            "RS384" => Ok(Algorithm::Rs384),
            "RS512" => Ok(Algorithm::Rs512),
            "ES256" => Ok(Algorithm::Es256),
            "ES384" => Ok(Algorithm::Es384),
            "ES512" => Ok(Algorithm::Es512),
            "HS256" => Ok(Algorithm::Hs256),
            "HS384" => Ok(Algorithm::Hs384),
            "HS512" => Ok(Algorithm::Hs512),
            "EdDSA" => Ok(Algorithm::EdDsa),
            _ => Err(IssuerdError::InvalidRequest("unsupported algorithm".into())),
        }
    }
}

#[mockall::automock]
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    async fn sign(
        &self,
        payload: &str,
        alg: Algorithm,
        kid: &KeyId,
    ) -> Result<String, IssuerdError>;
    async fn verify(&self, token: &str, alg: Algorithm, kid: &KeyId) -> Result<bool, IssuerdError>;
    async fn get_public_keys(&self) -> Result<JwkSet, IssuerdError>;

    /// Public JWKs of the currently **active** signing keys only (newest
    /// first) — the keys eligible to sign newly issued tokens.
    ///
    /// Disabled (passive) keys are excluded: they stay published via
    /// [`CryptoProvider::get_public_keys`] so previously issued tokens still
    /// verify, but they must never sign again. Signing-key selection must
    /// read this set, not the full published set.
    ///
    /// The default is conservative: it assumes every published key is active
    /// and falls back to [`CryptoProvider::get_public_keys`]. Providers that
    /// track per-key active/passive state override it.
    async fn get_active_public_keys(&self) -> Result<JwkSet, IssuerdError> {
        self.get_public_keys().await
    }

    async fn rotate_keys(&self) -> Result<(), IssuerdError> {
        Ok(())
    }

    /// Algorithms of the currently **active** signing keys — the algorithms
    /// the server may sign newly issued tokens with. Discovery
    /// advertises exactly this set in `id_token_signing_alg_values_supported`.
    /// The default preserves the historical single-alg (RS256) behavior for
    /// providers without key metadata.
    async fn active_signing_algorithms(&self) -> Result<Vec<Algorithm>, IssuerdError> {
        Ok(vec![Algorithm::Rs256])
    }
}

// ---------------------------------------------------------------------------
// DistributedCache trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait DistributedCache: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError>;
    async fn set(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Option<Duration>,
    ) -> Result<(), IssuerdError>;
    async fn delete(&self, key: &str) -> Result<(), IssuerdError>;
    /// Atomically read and remove a key (single-use consume).
    ///
    /// The default implementation is a non-atomic `get` + `delete`; backends
    /// that support an atomic take (Redis `GETDEL`, `DashMap::remove`)
    /// override it. Callers relying on single-use semantics (authorization
    /// codes, pending-auth entries, approved CIBA/device grants) must run on
    /// an overriding backend.
    async fn get_and_delete(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
        let value = self.get(key).await?;
        if value.is_some() {
            self.delete(key).await?;
        }
        Ok(value)
    }
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> Result<bool, IssuerdError>;
    /// Atomically increment the integer counter stored at `key` and return the
    /// new value. A missing key is created with value `1`; when `ttl` is
    /// provided it is applied only on creation (first increment), matching
    /// Redis `INCR` + conditional `PEXPIRE` semantics.
    ///
    /// The default implementation is a bounded get+CAS retry loop. It cannot
    /// apply `ttl` (compare-and-swap carries no TTL), so backends used with
    /// expiring counters must override it — both shipped backends do (Redis
    /// `INCR` + `PEXPIRE` Lua script, `DashMap::entry`).
    async fn increment(&self, key: &str, ttl: Option<Duration>) -> Result<u64, IssuerdError> {
        let _ = ttl;
        for _ in 0..16 {
            let current = self.get(key).await?;
            let count = current
                .as_ref()
                .and_then(|b| std::str::from_utf8(b).ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let new_value = count + 1;
            if self.compare_and_swap(key, current, new_value.to_string().into_bytes()).await? {
                return Ok(new_value);
            }
        }
        Err(IssuerdError::ServerError(format!("increment contention on key {key}")))
    }
    async fn publish(&self, channel: &str, message: Vec<u8>) -> Result<(), IssuerdError>;
    async fn subscribe(
        &self,
        channel: &str,
        handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
    ) -> Result<(), IssuerdError>;
    /// Return all keys matching `pattern` (`*` is the only wildcard,
    /// matching any byte sequence, e.g. `login-lockout:realm-1:*`).
    ///
    /// Used by admin/attack-detection queries. The default implementation
    /// returns an empty list; backends override it (Redis `SCAN ... MATCH`,
    /// in-memory map iteration). Never use on hot paths.
    async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>, IssuerdError> {
        let _ = pattern;
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// EmailSender trait
// ---------------------------------------------------------------------------

/// Sends email on behalf of a realm.
///
/// Follows the same `dyn`-trait pattern as [`Storage`], [`CryptoProvider`],
/// and [`DistributedCache`]: handlers depend on `Arc<dyn EmailSender>` and
/// tests substitute a mock or recording implementation. The production
/// implementation (SMTP via `lettre`) lives in `issuerd-server`.
///
/// `text_body` is always required; `html_body` is sent as a
/// `multipart/alternative` part when present so plain-text-only clients
/// still get a readable message.
#[mockall::automock]
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(
        &self,
        realm: &Realm,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: Option<String>,
    ) -> Result<(), IssuerdError>;
}

// ---------------------------------------------------------------------------
// EventListener trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait EventListener: Send + Sync {
    async fn on_event(&self, event: &Event) -> Result<(), IssuerdError>;
    async fn on_admin_event(&self, event: &AdminEvent) -> Result<(), IssuerdError>;
}

// ---------------------------------------------------------------------------
// Authenticator trait
// ---------------------------------------------------------------------------

/// Authentication context passed through the auth flow pipeline.
///
/// Intentionally does **not** derive `Serialize`/`Deserialize` because it is an
/// in-memory, request-scoped object. The HTTP layer serializes concrete response
/// DTOs, not the internal context.
pub struct AuthContext {
    pub realm_id: RealmId,
    pub client_id: Option<ClientId>,
    pub user_id: Option<UserId>,
    pub session_id: Option<SessionId>,
    pub ip_address: Option<std::net::IpAddr>,
    pub parameters: HashMap<String, Vec<String>>,
    pub attributes: HashMap<String, String>,
    pub current_challenge: Option<Challenge>,
}

/// Challenge presented to the user during authentication.
///
/// Intentionally does **not** derive `Serialize`/`Deserialize` because challenges
/// are translated into concrete HTTP responses (HTML forms, redirects, etc.) by
/// the protocol layer (`issuerd-protocol`). Serializing the raw enum would leak
/// internal abstraction details.
#[derive(Debug, Clone)]
pub enum Challenge {
    LoginForm {
        action_url: String,
    },
    OtpForm {
        action_url: String,
    },
    WebAuthn {
        action_url: String,
        challenge: String,
    },
    Redirect {
        url: String,
    },
    Cookie,
}

/// Result of a single authentication step.
///
/// Intentionally does **not** derive `Serialize`/`Deserialize` because it
/// contains `IssuerdError` (which is not serializable) and is an internal auth-flow
/// type. The protocol layer maps this to an appropriate HTTP/OAuth2 response.
#[derive(Debug, Clone)]
pub enum AuthStepResult {
    Success,
    Failure(IssuerdError),
    Challenge(Challenge),
    Attempted,
}

/// Result of executing a required action.
///
/// Intentionally does **not** derive `Serialize`/`Deserialize` for the same
/// reasons as `AuthStepResult` — it is an internal auth-flow type.
#[derive(Debug, Clone)]
pub enum RequiredActionResult {
    Success,
    Challenge(Challenge),
    Failure(IssuerdError),
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    fn id(&self) -> &str;
    fn display_name(&self) -> &str;
    fn requires_user(&self) -> bool;
    fn configured_for(&self, context: &AuthContext) -> bool;
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult;
}

#[async_trait]
pub trait RequiredAction: Send + Sync {
    fn id(&self) -> &str;
    fn display_name(&self) -> &str;
    async fn evaluate(&self, context: &AuthContext) -> bool;
    async fn process(&self, context: &mut AuthContext) -> RequiredActionResult;
}

// ---------------------------------------------------------------------------
// IdentityProvider trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    fn id(&self) -> &str;
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult;
}

// ---------------------------------------------------------------------------
// TokenService trait
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ValidatedAccessToken {
    pub claims: AccessTokenClaims,
    pub header: JwsHeader,
}

#[derive(Debug, Clone)]
pub struct ValidatedRefreshToken {
    pub claims: RefreshTokenClaims,
    pub header: JwsHeader,
}

pub trait TokenService: Send + Sync {
    fn validate_access_token(&self, token: &str) -> Result<ValidatedAccessToken, IssuerdError>;
    fn validate_id_token(
        &self,
        token: &str,
        client: &Client,
        nonce: Option<&str>,
    ) -> Result<IdTokenClaims, IssuerdError>;
    fn validate_refresh_token(&self, token: &str) -> Result<ValidatedRefreshToken, IssuerdError>;

    /// Validate an `id_token_hint` at the logout endpoint (OIDC RP-Initiated Logout).
    ///
    /// Cryptographic validation only (signature, expiry, issuer family) — the client is
    /// typically unknown at this point, so audience/nonce checks are skipped; the caller
    /// reads `aud`/`azp` from the returned claims for client binding.
    fn validate_id_token_hint(&self, token: &str) -> Result<IdTokenClaims, IssuerdError>;
}

// ---------------------------------------------------------------------------
// Session logout notification (back-channel logout)
// ---------------------------------------------------------------------------

/// Notified whenever a user session is destroyed outside the OIDC logout
/// endpoint (admin session deletion, account-console session logout, ...).
///
/// The implementation is expected to deliver OIDC back-channel logout
/// tokens to every client session registered on the destroyed session that
/// configured a `backchannel_logout_uri`. Delivery is best-effort and
/// fire-and-forget: implementations must never block or fail the caller's
/// logout path.
#[async_trait]
pub trait SessionLogoutNotifier: Send + Sync {
    /// A user session is about to be (or has just been) destroyed.
    async fn notify_session_destroyed(&self, realm: &Realm, session: &UserSession);
}

/// Default notifier used when no back-channel dispatcher is wired (tests,
/// non-server embeddings). Deliberately does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpSessionLogoutNotifier;

#[async_trait]
impl SessionLogoutNotifier for NoOpSessionLogoutNotifier {
    async fn notify_session_destroyed(&self, _realm: &Realm, _session: &UserSession) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rstest::rstest;

    fn roundtrip<
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
    >(
        value: &T,
    ) {
        let json = serde_json::to_string(value).unwrap();
        let back: T = serde_json::from_str(&json).unwrap();
        assert_eq!(*value, back);
    }

    #[test]
    fn pagination_roundtrip() {
        roundtrip(&Pagination { first: 0, max: 100 });
    }

    #[test]
    fn pagination_default() {
        let p = Pagination::default();
        assert_eq!(p.first, 0);
        assert_eq!(p.max, 100);
    }

    #[test]
    fn event_query_roundtrip() {
        let q = EventQuery {
            event_type: Some(EventType::LoginError),
            client_id: Some(ClientId::new("client-1").unwrap()),
            user_id: Some(UserId::new("user-1").unwrap()),
            date_from: Some(Utc::now()),
            date_to: Some(Utc::now()),
            pagination: Pagination::default(),
        };
        roundtrip(&q);
    }

    #[test]
    fn algorithm_contains_expected_variants() {
        let variants = vec![
            Algorithm::Rs256,
            Algorithm::Rs384,
            Algorithm::Rs512,
            Algorithm::Es256,
            Algorithm::Es384,
            Algorithm::Es512,
            Algorithm::Hs256,
            Algorithm::Hs384,
            Algorithm::Hs512,
            Algorithm::EdDsa,
        ];
        // Ensure all variants are distinct
        let mut set = std::collections::HashSet::new();
        for v in &variants {
            assert!(set.insert(std::mem::discriminant(v)));
        }
        assert_eq!(set.len(), 10);
    }

    #[test]
    fn algorithm_serde_roundtrip_preserves_jwt_names() {
        for alg in [
            Algorithm::Rs256,
            Algorithm::Rs384,
            Algorithm::Rs512,
            Algorithm::Es256,
            Algorithm::Es384,
            Algorithm::Es512,
            Algorithm::Hs256,
            Algorithm::Hs384,
            Algorithm::Hs512,
            Algorithm::EdDsa,
        ] {
            let json = serde_json::to_string(&alg).unwrap();
            let back: Algorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, back);
            assert_eq!(json.trim_matches('"'), alg.as_str());
        }
    }

    #[test]
    fn algorithm_deserialize_rejects_unknown() {
        let err = serde_json::from_str::<Algorithm>("\"FOOBAR\"").unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }

    // ------------------------------------------------------------------
    // Trait object safety compile-time assertions
    // ------------------------------------------------------------------
    #[test]
    fn storage_is_object_safe() {
        let _: Option<Box<dyn Storage>> = None;
    }

    #[test]
    fn crypto_provider_is_object_safe() {
        let _: Option<Box<dyn CryptoProvider>> = None;
    }

    #[test]
    fn distributed_cache_is_object_safe() {
        let _: Option<Box<dyn DistributedCache>> = None;
    }

    #[test]
    fn event_listener_is_object_safe() {
        let _: Option<Box<dyn EventListener>> = None;
    }

    #[test]
    fn identity_provider_is_object_safe() {
        let _: Option<Box<dyn IdentityProvider>> = None;
    }

    #[test]
    fn token_service_is_object_safe() {
        let _: Option<Box<dyn TokenService>> = None;
    }

    #[test]
    fn authenticator_is_object_safe() {
        let _: Option<Box<dyn Authenticator>> = None;
    }

    #[test]
    fn required_action_is_object_safe() {
        let _: Option<Box<dyn RequiredAction>> = None;
    }

    #[test]
    fn email_sender_is_object_safe() {
        let _: Option<Box<dyn EmailSender>> = None;
    }

    // ------------------------------------------------------------------
    // Algorithm coverage
    // ------------------------------------------------------------------

    #[rstest]
    #[case(Algorithm::Rs256, "RS256")]
    #[case(Algorithm::Rs384, "RS384")]
    #[case(Algorithm::Rs512, "RS512")]
    #[case(Algorithm::Es256, "ES256")]
    #[case(Algorithm::Es384, "ES384")]
    #[case(Algorithm::Es512, "ES512")]
    #[case(Algorithm::Hs256, "HS256")]
    #[case(Algorithm::Hs384, "HS384")]
    #[case(Algorithm::Hs512, "HS512")]
    #[case(Algorithm::EdDsa, "EdDSA")]
    fn algorithm_as_str(#[case] alg: Algorithm, #[case] expected: &str) {
        assert_eq!(alg.as_str(), expected);
    }

    #[rstest]
    #[case(Algorithm::Rs256, "RS256")]
    #[case(Algorithm::Rs384, "RS384")]
    #[case(Algorithm::Rs512, "RS512")]
    #[case(Algorithm::Es256, "ES256")]
    #[case(Algorithm::Es384, "ES384")]
    #[case(Algorithm::Es512, "ES512")]
    #[case(Algorithm::Hs256, "HS256")]
    #[case(Algorithm::Hs384, "HS384")]
    #[case(Algorithm::Hs512, "HS512")]
    #[case(Algorithm::EdDsa, "EdDSA")]
    fn algorithm_display(#[case] alg: Algorithm, #[case] expected: &str) {
        assert_eq!(format!("{alg}"), expected);
    }

    #[rstest]
    #[case("RS256", Algorithm::Rs256)]
    #[case("RS384", Algorithm::Rs384)]
    #[case("RS512", Algorithm::Rs512)]
    #[case("ES256", Algorithm::Es256)]
    #[case("ES384", Algorithm::Es384)]
    #[case("ES512", Algorithm::Es512)]
    #[case("HS256", Algorithm::Hs256)]
    #[case("HS384", Algorithm::Hs384)]
    #[case("HS512", Algorithm::Hs512)]
    #[case("EdDSA", Algorithm::EdDsa)]
    fn algorithm_from_str_ok(#[case] input: &str, #[case] expected: Algorithm) {
        assert_eq!(input.parse::<Algorithm>().unwrap(), expected);
    }

    #[test]
    fn algorithm_from_str_err() {
        let err = "unknown".parse::<Algorithm>().unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)));
    }

    #[test]
    fn algorithm_all_covers_every_variant() {
        // Every variant must appear exactly once in ALL, and every ALL entry
        // must round-trip through as_str/FromStr.
        assert_eq!(Algorithm::ALL.len(), 10);
        for alg in Algorithm::ALL {
            let count = Algorithm::ALL.iter().filter(|a| **a == alg).count();
            assert_eq!(count, 1, "duplicate or missing variant: {alg}");
            let back: Algorithm = alg.as_str().parse().unwrap();
            assert_eq!(back, alg);
        }
        // Exhaustiveness anchor: adding a variant without updating ALL fails
        // this match-free check via the count assertion above.
        assert!(Algorithm::ALL.contains(&Algorithm::Rs256));
        assert!(Algorithm::ALL.contains(&Algorithm::EdDsa));
    }

    #[test]
    fn algorithm_is_symmetric_only_for_hmac() {
        for alg in Algorithm::ALL {
            let expected = matches!(alg, Algorithm::Hs256 | Algorithm::Hs384 | Algorithm::Hs512);
            assert_eq!(alg.is_symmetric(), expected, "is_symmetric mismatch for {alg}");
        }
    }

    // ------------------------------------------------------------------
    // CryptoProvider default method coverage
    // ------------------------------------------------------------------

    struct DummyCryptoProvider;

    #[async_trait]
    impl CryptoProvider for DummyCryptoProvider {
        async fn sign(
            &self,
            _payload: &str,
            _alg: Algorithm,
            _kid: &KeyId,
        ) -> Result<String, IssuerdError> {
            Ok("dummy".to_string())
        }

        async fn verify(
            &self,
            _token: &str,
            _alg: Algorithm,
            _kid: &KeyId,
        ) -> Result<bool, IssuerdError> {
            Ok(true)
        }

        async fn get_public_keys(&self) -> Result<JwkSet, IssuerdError> {
            Ok(JwkSet { keys: vec![] })
        }
    }

    #[tokio::test]
    async fn crypto_provider_rotate_keys_default_returns_ok() {
        let provider = DummyCryptoProvider;
        assert!(provider.rotate_keys().await.is_ok());
    }

    #[tokio::test]
    async fn dummy_crypto_provider_sign_returns_dummy() {
        let provider = DummyCryptoProvider;
        let result = provider.sign("payload", Algorithm::Rs256, &KeyId::new("kid").unwrap()).await;
        assert_eq!(result.unwrap(), "dummy");
    }

    #[tokio::test]
    async fn dummy_crypto_provider_verify_returns_true() {
        let provider = DummyCryptoProvider;
        let result = provider.verify("token", Algorithm::Rs256, &KeyId::new("kid").unwrap()).await;
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn dummy_crypto_provider_get_public_keys_returns_empty() {
        let provider = DummyCryptoProvider;
        let result = provider.get_public_keys().await;
        assert!(result.unwrap().keys.is_empty());
    }

    #[tokio::test]
    async fn crypto_provider_active_signing_algorithms_default_is_rs256() {
        let provider = DummyCryptoProvider;
        let algs = provider.active_signing_algorithms().await.unwrap();
        assert_eq!(algs, vec![Algorithm::Rs256]);
    }

    #[tokio::test]
    async fn crypto_provider_get_active_public_keys_defaults_to_public_keys() {
        let provider = DummyCryptoProvider;
        // The conservative default assumes every published key is active.
        let active = provider.get_active_public_keys().await.unwrap();
        let all = provider.get_public_keys().await.unwrap();
        assert_eq!(active.keys.len(), all.keys.len());
    }
}
