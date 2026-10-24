// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Built-in client scope and authentication flow seeding.
//!
//! Shared helpers so every storage backend seeds the same built-in client
//! scopes ([`issuerd_core::builtin_client_scopes`]) when a realm is created and
//! the same default/optional scope assignments when a client is created,
//! regardless of which creation path (admin API, provisioning, tests) was
//! taken, and so every realm carries the built-in browser + registration
//! flows ([`issuerd_core::flows`]). All helpers are idempotent: re-running them is
//! a no-op.

use issuerd_core::*;
use tracing::debug;

/// Page request used when a helper genuinely needs every row of a
/// collection. Seeding runs at realm/client creation and at migration time,
/// never on a request hot path.
const ALL: Pagination = Pagination {
    first: 0,
    max: i32::MAX,
};

/// Seed the ten built-in client scopes into `realm_id` and wire the realm
/// default scope sets ([`DEFAULT_DEFAULT_SCOPES`] / [`DEFAULT_OPTIONAL_SCOPES`]).
///
/// Scopes that already exist (matched by name) are left untouched; realm
/// default rows are upserts, so re-running this helper is a no-op.
pub async fn seed_builtin_client_scopes(
    storage: &(impl Storage + ?Sized),
    realm_id: &RealmId,
) -> Result<(), IssuerdError> {
    debug!(realm = %realm_id, "seeding built-in client scopes");
    let existing = storage.list_client_scopes(realm_id, &ALL).await?;
    for scope in builtin_client_scopes(realm_id) {
        if !existing.iter().any(|s| s.name == scope.name) {
            match storage.create_client_scope(realm_id, &scope).await {
                Ok(()) | Err(IssuerdError::Conflict) => {}
                Err(e) => return Err(e),
            }
        }
    }

    // Re-list to learn the ids of the scopes just created, then ensure the
    // realm default sets.
    let scopes = storage.list_client_scopes(realm_id, &ALL).await?;
    for (names, is_default) in [
        (DEFAULT_DEFAULT_SCOPES, true),
        (DEFAULT_OPTIONAL_SCOPES, false),
    ] {
        for name in names {
            if let Some(scope) = scopes.iter().find(|s| s.name == *name) {
                storage.add_realm_default_client_scope(realm_id, &scope.id, is_default).await?;
            }
        }
    }
    Ok(())
}

/// Assign realm client scopes to a freshly created client, mirroring its
/// legacy string lists: scopes named in `client.default_scopes` become
/// *default* assignments, scopes named in `client.optional_scopes` become
/// *optional* assignments. This preserves legacy behavior; the MCP-enabled
/// startup validator rejects unsafe MCP configurations separately.
///
/// Carve-out: a scope named `roles` is always assigned as *default* when the
/// client has no assignment for it. Before client scopes were introduced the
/// `realm_access` claim was populated unconditionally; keeping `roles`
/// assigned preserves that
/// behavior for clients whose string lists do not mention it.
pub async fn seed_client_scope_assignments(
    storage: &(impl Storage + ?Sized),
    realm_id: &RealmId,
    client: &Client,
) -> Result<(), IssuerdError> {
    debug!(realm = %realm_id, client = %client.id, "seeding client scope assignments");
    let scopes = storage.list_client_scopes(realm_id, &ALL).await?;
    for scope in &scopes {
        if client.default_scopes.contains(&scope.name) {
            storage.assign_client_scope(realm_id, &client.id, &scope.id, true).await?;
        } else if client.optional_scopes.contains(&scope.name) {
            storage.assign_client_scope(realm_id, &client.id, &scope.id, false).await?;
        }
    }

    let assigned = storage.list_client_scope_assignments(realm_id, &client.id).await?;
    if let Some(roles) = scopes.iter().find(|s| s.name == "roles") {
        if !assigned.iter().any(|(id, _)| id == &roles.id) {
            storage.assign_client_scope(realm_id, &client.id, &roles.id, true).await?;
        }
    }
    Ok(())
}

/// Validate legacy MCP scope definitions and assignments before the MCP
/// surface is enabled. MCP-disabled deployments deliberately skip this check
/// so previously valid custom scopes keep booting unchanged.
pub async fn validate_mcp_scope_policy(
    storage: &(impl Storage + ?Sized),
) -> Result<(), IssuerdError> {
    fn collision(realm: &Realm, detail: String) -> IssuerdError {
        IssuerdError::InvalidRequest(format!(
            "MCP scope collision in realm '{}': {detail}; reconcile it before enabling MCP",
            realm.name
        ))
    }

    let realms = storage.list_realms(&ALL).await?;
    for realm in realms {
        let scopes = storage.list_client_scopes(&realm.id, &ALL).await?;
        let mcp_scopes: Vec<&ClientScope> =
            scopes.iter().filter(|scope| is_mcp_scope_name(&scope.name)).collect();
        for scope in &mcp_scopes {
            if !scope.protocol_mappers.is_empty()
                || !scope.scope_mappings.realm_roles.is_empty()
                || !scope.scope_mappings.client_roles.is_empty()
            {
                return Err(collision(
                    &realm,
                    format!(
                        "custom scope '{}' carries protocol mappers or role mappings",
                        scope.name
                    ),
                ));
            }
        }

        let realm_defaults = storage.list_realm_default_client_scopes(&realm.id).await?;
        if realm_defaults
            .iter()
            .any(|(scope_id, _)| mcp_scopes.iter().any(|scope| scope.id == *scope_id))
        {
            return Err(collision(
                &realm,
                "an MCP scope is assigned as a realm default".to_string(),
            ));
        }

        let clients = storage.list_clients(&realm.id, &ALL).await?;
        for client in clients {
            if let Some(scope) = client.default_scopes.iter().find(|scope| is_mcp_scope_name(scope))
            {
                return Err(collision(
                    &realm,
                    format!(
                        "client '{}' has MCP scope '{scope}' in its default list",
                        client.client_id
                    ),
                ));
            }
            let open_registered =
                client.attributes.get(ATTR_DCR_POLICY).map(String::as_str) == Some(DCR_POLICY_OPEN);
            if open_registered
                && client
                    .default_scopes
                    .iter()
                    .chain(client.optional_scopes.iter())
                    .any(|scope| is_mcp_scope_name(scope))
            {
                return Err(collision(
                    &realm,
                    format!("open-registered client '{}' carries an MCP scope", client.client_id),
                ));
            }
            let assignments = storage.list_client_scope_assignments(&realm.id, &client.id).await?;
            if assignments.iter().any(|(scope_id, is_default)| {
                *is_default && mcp_scopes.iter().any(|scope| scope.id == *scope_id)
            }) {
                return Err(collision(
                    &realm,
                    format!("client '{}' has a default MCP assignment", client.client_id),
                ));
            }
        }
    }
    Ok(())
}

/// Seed the built-in authentication flows (browser + registration, defined in
/// [`issuerd_core::flows`]) into `realm_id`.
///
/// Flows that already exist (matched by alias) are left untouched, so
/// re-running this helper is a no-op.
pub async fn seed_builtin_flows(
    storage: &(impl Storage + ?Sized),
    realm_id: &RealmId,
) -> Result<(), IssuerdError> {
    debug!(realm = %realm_id, "seeding built-in authentication flows");
    for flow in [
        issuerd_core::flows::default_browser_flow(realm_id.clone()),
        issuerd_core::flows::registration_flow(realm_id.clone()),
    ] {
        if storage.get_flow_config(realm_id, flow.alias.as_ref()).await?.is_none() {
            storage.create_flow_config(realm_id, &flow).await?;
        }
    }
    Ok(())
}

/// Ensure `realm` carries a pairwise sector key: the secret
/// HMAC key feeding pairwise `sub` derivation. Generated once at realm
/// creation; two random ids give ~244 bits of key material. Existing values
/// are preserved, so re-running this helper is a no-op.
pub fn ensure_realm_pairwise_sector_key(realm: &mut Realm) {
    realm
        .attributes
        .entry(Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE.to_string())
        .or_insert_with(|| {
            format!("{}{}", issuerd_core::utils::generate_id(), issuerd_core::utils::generate_id())
        });
}

/// Backfill the pairwise sector key for a realm that predates
/// the seeding (migration / snapshot-load path). No-op when the attribute is
/// already present.
pub async fn backfill_pairwise_sector_key(
    storage: &(impl Storage + ?Sized),
    realm_id: &RealmId,
) -> Result<(), IssuerdError> {
    debug!(realm = %realm_id, "backfilling pairwise sector key");
    if let Some(mut realm) = storage.get_realm(realm_id).await? {
        if realm.pairwise_sector_key().is_none() {
            ensure_realm_pairwise_sector_key(&mut realm);
            storage.update_realm(&realm).await?;
        }
    }
    Ok(())
}

/// Drive a future that is guaranteed to be immediately ready (the in-memory
/// backend performs no I/O) from synchronous code. Used by the
/// `JsonFileStorage` constructor to seed realms loaded from a snapshot that
/// predates client scopes; mirrors `issuerd_admin_api::test_utils::block_on_ready`.
pub(crate) fn block_on_ready<F: std::future::Future>(future: F) -> F::Output {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("seed future unexpectedly pended"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::InMemoryStorage;
    use std::collections::HashMap;

    fn realm_id() -> RealmId {
        RealmId::new("seed-realm").unwrap()
    }

    fn test_client(id: &str, identifier: &str, default: &str, optional: &str) -> Client {
        Client {
            id: ClientId::new(id).unwrap(),
            realm_id: realm_id(),
            client_id: ClientIdentifier::new(identifier).unwrap(),
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
            default_scopes: Scope::parse(default),
            optional_scopes: Scope::parse(optional),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: ScopeMappings::default(),
            attributes: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn seed_builtin_client_scopes_creates_all_ten_with_realm_defaults() {
        let storage = InMemoryStorage::new();
        let realm = realm_id();
        seed_builtin_client_scopes(&storage, &realm).await.unwrap();

        let scopes = storage.list_client_scopes(&realm, &ALL).await.unwrap();
        assert_eq!(scopes.len(), 10);
        for expected in builtin_client_scopes(&realm) {
            assert!(
                scopes.iter().any(|s| s.name == expected.name),
                "missing built-in scope {}",
                expected.name
            );
        }

        let defaults = storage.list_realm_default_client_scopes(&realm).await.unwrap();
        assert_eq!(defaults.len(), 8);
        for (names, is_default) in [
            (DEFAULT_DEFAULT_SCOPES, true),
            (DEFAULT_OPTIONAL_SCOPES, false),
        ] {
            for name in names {
                let scope = scopes.iter().find(|s| s.name == *name).unwrap();
                assert!(
                    defaults.contains(&(scope.id.clone(), is_default)),
                    "realm default missing {name} (is_default={is_default})"
                );
            }
        }
        // The MCP authorization gates are seeded but never join the realm
        // default sets — administrators assign them to agent clients
        // explicitly.
        for name in ["mcp:read", "mcp:write"] {
            let scope = scopes.iter().find(|s| s.name == name).unwrap();
            assert!(!defaults.iter().any(|(id, _)| id == &scope.id));
        }
    }

    #[tokio::test]
    async fn seed_builtin_client_scopes_rerun_is_a_no_op() {
        let storage = InMemoryStorage::new();
        let realm = realm_id();
        seed_builtin_client_scopes(&storage, &realm).await.unwrap();
        let scopes = storage.list_client_scopes(&realm, &ALL).await.unwrap();
        let defaults = storage.list_realm_default_client_scopes(&realm).await.unwrap();

        seed_builtin_client_scopes(&storage, &realm).await.unwrap();
        seed_builtin_client_scopes(&storage, &realm).await.unwrap();

        assert_eq!(storage.list_client_scopes(&realm, &ALL).await.unwrap(), scopes);
        assert_eq!(storage.list_realm_default_client_scopes(&realm).await.unwrap(), defaults);
    }

    #[tokio::test]
    async fn seed_builtin_client_scopes_tolerates_concurrent_creation() {
        let storage = std::sync::Arc::new(InMemoryStorage::new());
        let realm = realm_id();
        let (first, second) = tokio::join!(
            seed_builtin_client_scopes(storage.as_ref(), &realm),
            seed_builtin_client_scopes(storage.as_ref(), &realm),
        );
        first.unwrap();
        second.unwrap();
        assert_eq!(storage.list_client_scopes(&realm, &ALL).await.unwrap().len(), 10);
    }

    #[tokio::test]
    async fn seed_builtin_client_scopes_preserves_preexisting_scope() {
        // A realm that already carries one of the built-in scopes (created
        // before seeding existed): the pre-existing row must be preserved
        // (not recreated) and the remaining nine scopes filled in.
        let storage = InMemoryStorage::new();
        let realm = realm_id();
        let preexisting = ClientScope {
            id: ClientScopeId::new("scope-pre").unwrap(),
            realm_id: realm.clone(),
            name: "profile".to_string(),
            description: Some("pre-existing".to_string()),
            protocol: ClientProtocol::OpenIdConnect,
            attributes: HashMap::new(),
            protocol_mappers: Vec::new(),
            scope_mappings: ScopeMappings::default(),
        };
        storage.create_client_scope(&realm, &preexisting).await.unwrap();

        seed_builtin_client_scopes(&storage, &realm).await.unwrap();

        let scopes = storage.list_client_scopes(&realm, &ALL).await.unwrap();
        assert_eq!(scopes.len(), 10);
        let profile = scopes.iter().find(|s| s.name == "profile").unwrap();
        assert_eq!(profile.id, preexisting.id);
        assert_eq!(profile.description, preexisting.description);
    }

    #[tokio::test]
    async fn seed_client_scope_assignments_mirrors_lists_plus_roles_carve_out() {
        let storage = InMemoryStorage::new();
        let realm = realm_id();
        seed_builtin_client_scopes(&storage, &realm).await.unwrap();
        let client = test_client("client-1", "my-app", "openid profile email", "offline_access");

        seed_client_scope_assignments(&storage, &realm, &client).await.unwrap();

        let scopes = storage.list_client_scopes(&realm, &ALL).await.unwrap();
        let id_of = |name: &str| scopes.iter().find(|s| s.name == name).unwrap().id.clone();
        let mut assignments =
            storage.list_client_scope_assignments(&realm, &client.id).await.unwrap();
        assignments.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
        let mut expected = vec![
            (id_of("profile"), true),
            (id_of("email"), true),
            (id_of("offline_access"), false),
            // The carve-out always assigns `roles` as default.
            (id_of("roles"), true),
        ];
        expected.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
        assert_eq!(assignments, expected);

        // Re-running is a no-op.
        let before = storage.list_client_scope_assignments(&realm, &client.id).await.unwrap();
        seed_client_scope_assignments(&storage, &realm, &client).await.unwrap();
        assert_eq!(
            storage.list_client_scope_assignments(&realm, &client.id).await.unwrap(),
            before
        );
    }

    async fn seeded_storage() -> (InMemoryStorage, RealmId) {
        let storage = InMemoryStorage::new();
        let realm = realm_id();
        storage
            .create_realm(&Realm {
                id: realm.clone(),
                name: RealmName::new("seed-realm").unwrap(),
                ..Default::default()
            })
            .await
            .unwrap();
        (storage, realm)
    }

    #[tokio::test]
    async fn seed_client_scope_assignments_preserves_legacy_mcp_assignments() {
        let (storage, realm) = seeded_storage().await;
        let client = test_client("client-1", "my-app", "openid mcp:write", "mcp:read");
        seed_client_scope_assignments(&storage, &realm, &client).await.unwrap();

        let scopes = storage.list_client_scopes(&realm, &ALL).await.unwrap();
        let read = scopes.iter().find(|scope| scope.name == MCP_SCOPE_READ).unwrap();
        let write = scopes.iter().find(|scope| scope.name == MCP_SCOPE_WRITE).unwrap();
        let assignments = storage.list_client_scope_assignments(&realm, &client.id).await.unwrap();
        assert!(assignments.contains(&(read.id.clone(), false)));
        assert!(assignments.contains(&(write.id.clone(), true)));
    }

    #[tokio::test]
    async fn mcp_policy_accepts_valid_legacy_optional_assignment() {
        let (storage, realm) = seeded_storage().await;
        let client = test_client("client-1", "my-app", "openid", "mcp:write");
        storage.create_client(&realm, &client).await.unwrap();
        validate_mcp_scope_policy(&storage).await.unwrap();
    }

    #[tokio::test]
    async fn mcp_policy_rejects_unsafe_legacy_client_assignments() {
        let (storage, realm) = seeded_storage().await;
        let client = test_client("client-1", "my-app", "openid mcp:write", "");
        storage.create_client(&realm, &client).await.unwrap();
        assert!(validate_mcp_scope_policy(&storage).await.is_err());

        let (storage, realm) = seeded_storage().await;
        let mut client = test_client("client-1", "my-app", "openid", "mcp:read");
        client
            .attributes
            .insert(ATTR_DCR_POLICY.to_string(), DCR_POLICY_OPEN.to_string());
        storage.create_client(&realm, &client).await.unwrap();
        assert!(validate_mcp_scope_policy(&storage).await.is_err());

        let (storage, realm) = seeded_storage().await;
        let client = test_client("client-1", "my-app", "openid", "");
        storage.create_client(&realm, &client).await.unwrap();
        let scope =
            storage.get_client_scope_by_name(&realm, MCP_SCOPE_READ).await.unwrap().unwrap();
        storage.assign_client_scope(&realm, &client.id, &scope.id, true).await.unwrap();
        assert!(validate_mcp_scope_policy(&storage).await.is_err());
    }

    #[tokio::test]
    async fn mcp_policy_rejects_realm_defaults_and_custom_definitions() {
        let (storage, realm) = seeded_storage().await;
        let scope =
            storage.get_client_scope_by_name(&realm, MCP_SCOPE_READ).await.unwrap().unwrap();
        storage.add_realm_default_client_scope(&realm, &scope.id, false).await.unwrap();
        assert!(validate_mcp_scope_policy(&storage).await.is_err());

        let (storage, realm) = seeded_storage().await;
        let mut scope = storage
            .get_client_scope_by_name(&realm, MCP_SCOPE_WRITE)
            .await
            .unwrap()
            .unwrap();
        let profile_mapper = builtin_client_scopes(&realm)
            .into_iter()
            .find(|scope| scope.name == "profile")
            .unwrap()
            .protocol_mappers
            .into_iter()
            .next()
            .unwrap();
        scope.protocol_mappers.push(profile_mapper);
        storage.update_client_scope(&realm, &scope).await.unwrap();
        assert!(validate_mcp_scope_policy(&storage).await.is_err());
    }

    #[tokio::test]
    async fn seed_client_scope_assignments_does_not_duplicate_explicit_roles() {
        let storage = InMemoryStorage::new();
        let realm = realm_id();
        seed_builtin_client_scopes(&storage, &realm).await.unwrap();
        // `roles` named explicitly in the default list: assigned exactly once.
        let client = test_client("client-1", "my-app", "openid roles", "");

        seed_client_scope_assignments(&storage, &realm, &client).await.unwrap();
        seed_client_scope_assignments(&storage, &realm, &client).await.unwrap();

        let scopes = storage.list_client_scopes(&realm, &ALL).await.unwrap();
        let roles = scopes.iter().find(|s| s.name == "roles").unwrap();
        let assignments = storage.list_client_scope_assignments(&realm, &client.id).await.unwrap();
        assert_eq!(assignments, vec![(roles.id.clone(), true)]);
    }

    #[tokio::test]
    async fn seed_builtin_flows_creates_browser_and_registration_once() {
        let storage = InMemoryStorage::new();
        let realm = realm_id();

        seed_builtin_flows(&storage, &realm).await.unwrap();
        assert_eq!(
            storage.get_flow_config(&realm, "browser").await.unwrap().unwrap(),
            issuerd_core::flows::default_browser_flow(realm.clone())
        );
        assert_eq!(
            storage.get_flow_config(&realm, "registration").await.unwrap().unwrap(),
            issuerd_core::flows::registration_flow(realm.clone())
        );
        assert_eq!(storage.list_flow_configs(&realm).await.unwrap().len(), 2);

        seed_builtin_flows(&storage, &realm).await.unwrap();
        assert_eq!(storage.list_flow_configs(&realm).await.unwrap().len(), 2);
    }

    #[test]
    fn ensure_realm_pairwise_sector_key_generates_then_preserves() {
        let mut realm = Realm::default();
        assert!(realm.pairwise_sector_key().is_none());
        ensure_realm_pairwise_sector_key(&mut realm);
        let key = realm.pairwise_sector_key().unwrap().to_string();
        assert!(!key.is_empty());

        // A second call keeps the generated value.
        ensure_realm_pairwise_sector_key(&mut realm);
        assert_eq!(realm.pairwise_sector_key(), Some(key.as_str()));

        // A pre-populated realm is never overwritten.
        let mut existing = Realm::default();
        existing
            .attributes
            .insert(Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE.to_string(), "fixed".to_string());
        ensure_realm_pairwise_sector_key(&mut existing);
        assert_eq!(existing.pairwise_sector_key(), Some("fixed"));
    }

    #[tokio::test]
    async fn backfill_pairwise_sector_key_adds_only_when_missing() {
        let storage = InMemoryStorage::new();
        let realm = realm_id();
        // `create_realm` ensures the key from birth; strip it to simulate a
        // realm written before pairwise subjects existed.
        let template = Realm {
            id: realm.clone(),
            name: RealmName::new("seed-realm").unwrap(),
            ..Realm::default()
        };
        storage.create_realm(&template).await.unwrap();
        let mut stripped = storage.get_realm(&realm).await.unwrap().unwrap();
        stripped.attributes.remove(Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE);
        storage.update_realm(&stripped).await.unwrap();
        assert!(storage
            .get_realm(&realm)
            .await
            .unwrap()
            .unwrap()
            .pairwise_sector_key()
            .is_none());

        backfill_pairwise_sector_key(&storage, &realm).await.unwrap();
        let key = storage
            .get_realm(&realm)
            .await
            .unwrap()
            .unwrap()
            .pairwise_sector_key()
            .expect("backfill adds the key")
            .to_string();
        assert!(!key.is_empty());

        // Re-running preserves the generated key.
        backfill_pairwise_sector_key(&storage, &realm).await.unwrap();
        assert_eq!(
            storage.get_realm(&realm).await.unwrap().unwrap().pairwise_sector_key(),
            Some(key.as_str())
        );

        // Unknown realm: no-op, no error.
        backfill_pairwise_sector_key(&storage, &RealmId::new("missing").unwrap())
            .await
            .unwrap();
    }
}
