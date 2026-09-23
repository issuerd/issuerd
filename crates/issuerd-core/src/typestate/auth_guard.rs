// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Compile-time proof of realm-authenticated account sessions (AccountSessionGuard).

//! Compile-time proof of realm-authenticated account sessions.
//!
//! Handlers that serve personal/account pages can require an
//! [`AccountSessionGuard`] parameter. This type can only be constructed from
//! a [`RealmBound<UserId>`] whose realm has already been verified against the
//! request, making it a compile-time error to serve the page without a
//! realm-validated authentication step.

use crate::{RealmId, UserId};

use super::realm_bound::RealmBound;

/// Proof that the current request has been authenticated for a specific realm.
///
/// The private `_seal` field prevents construction from outside this module,
/// so the only way to obtain a guard is through [`AccountSessionGuard::bind`],
/// which consumes a [`RealmBound<UserId>`]. That in turn forces the caller to
/// have validated the user's realm before serving the personal page.
#[derive(Debug, Clone)]
#[allow(clippy::manual_non_exhaustive)]
pub struct AccountSessionGuard {
    pub realm_id: RealmId,
    pub user_id: UserId,
    _seal: (),
}

impl AccountSessionGuard {
    /// Construct a guard from a realm-bound user id.
    ///
    /// The [`RealmBound`] wrapper is the proof that `user_id` has already been
    /// validated against `realm_id` (e.g., by checking the JWT issuer claim).
    /// This makes it impossible to create an `AccountSessionGuard` for a user
    /// from realm A while processing a request for realm B without explicitly
    /// handling the mismatch.
    pub fn bind(bound: RealmBound<UserId>) -> Self {
        Self {
            realm_id: bound.realm_id,
            user_id: bound.inner,
            _seal: (),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_session_guard_binds_user_to_realm() {
        let bound = RealmBound::new(RealmId::new("master").unwrap(), UserId::new("alice").unwrap());
        let guard = AccountSessionGuard::bind(bound);
        assert_eq!(guard.realm_id, RealmId::new("master").unwrap());
        assert_eq!(guard.user_id, UserId::new("alice").unwrap());
    }
}
