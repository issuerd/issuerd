// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Realm-bound values: proofs that a value belongs to a specific realm.

//! Realm-bound values.
//!
//! A value (token, session id, user id, etc.) that has been proven to belong
//! to a specific realm. The proof is created at runtime, but the wrapper
//! prevents accidental use of the value in a handler for a different realm
//! without an explicit verification call.

use crate::{IssuerdError, RealmId};

/// Extract the realm name from an OIDC issuer URL of the form
/// `https://host/realms/{realm}` or `https://host/realms/{realm}/`.
///
/// Returns `None` if the URL does not contain a `/realms/` segment or if the
/// realm name is empty. This prevents a bare host such as
/// `https://id.example.com/` from being misinterpreted as a realm.
pub fn extract_realm_from_issuer(issuer: &str) -> Option<&str> {
    let issuer = issuer.trim_end_matches('/');
    let mut parts = issuer.rsplit('/');
    let realm = parts.next()?;
    let prefix = parts.next()?;
    if prefix != "realms" || realm.is_empty() {
        return None;
    }
    Some(realm)
}

/// A value `T` that has been bound to a specific realm.
///
/// The binding is a proof that `inner` belongs to `realm_id`. It is the
/// caller's responsibility to create the binding only after validating the
/// value (for example by checking the `iss` claim of a JWT).
#[derive(Debug, Clone)]
pub struct RealmBound<T> {
    pub realm_id: RealmId,
    pub inner: T,
}

impl<T> RealmBound<T> {
    /// Bind a value to a realm.
    ///
    /// # Safety / correctness
    ///
    /// Callers must only call this after validating that `inner` genuinely
    /// belongs to `realm_id`. The type system cannot enforce the validation
    /// itself; it only enforces that any code that wants the unwrapped value
    /// must pass a realm check via [`Self::verify`].
    pub fn new(realm_id: RealmId, inner: T) -> Self {
        Self { realm_id, inner }
    }

    /// Consume the binding and verify it matches the expected realm.
    ///
    /// This is the only way to obtain ownership of the inner value, making it
    /// impossible to accidentally use a cross-realm value without an explicit
    /// realm check.
    pub fn verify(self, expected: &RealmId) -> Result<T, IssuerdError> {
        if &self.realm_id == expected {
            Ok(self.inner)
        } else {
            Err(IssuerdError::InvalidRequest(format!(
                "realm mismatch: value is bound to {} but expected {}",
                self.realm_id.0, expected.0
            )))
        }
    }

    /// Borrow the inner value without consuming the binding.
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_realm_from_issuer_url() {
        assert_eq!(
            extract_realm_from_issuer("https://id.example.com/realms/master"),
            Some("master")
        );
        assert_eq!(
            extract_realm_from_issuer("https://id.example.com/realms/master/"),
            Some("master")
        );
        assert_eq!(
            extract_realm_from_issuer("https://id.example.com/realms/test-realm"),
            Some("test-realm")
        );
        assert_eq!(extract_realm_from_issuer("https://id.example.com/"), None);
        assert_eq!(extract_realm_from_issuer("https://id.example.com"), None);
        assert_eq!(extract_realm_from_issuer("https://evil.com/"), None);
        assert_eq!(extract_realm_from_issuer(""), None);
    }

    #[test]
    fn realm_bound_verify_matches() {
        let bound = RealmBound::new(RealmId::new("master").unwrap(), "secret");
        assert_eq!(bound.verify(&RealmId::new("master").unwrap()).unwrap(), "secret");
    }

    #[test]
    fn realm_bound_verify_mismatch_fails() {
        let bound = RealmBound::new(RealmId::new("master").unwrap(), "secret");
        assert!(bound.verify(&RealmId::new("other").unwrap()).is_err());
    }

    #[test]
    fn realm_bound_borrows_inner() {
        let bound = RealmBound::new(RealmId::new("master").unwrap(), 42u32);
        assert_eq!(*bound.inner(), 42);
    }
}
