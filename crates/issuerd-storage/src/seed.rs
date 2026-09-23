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

/// Seed the eight built-in client scopes into `realm_id` and wire the realm
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
            storage.create_client_scope(realm_id, &scope).await?;
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
/// *optional* assignments.
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
