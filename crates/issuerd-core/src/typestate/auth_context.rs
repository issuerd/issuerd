// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// TypedAuthContext: authentication context with state encoded in the type parameter.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::IpAddr;

use crate::error::IssuerdError;
use crate::ids::{ClientId, RealmId, SessionId, UserId};
use crate::traits::{AuthContext, Challenge};

use super::{AnonymousState, AuthState, AuthenticatedState};

/// Authentication context with state encoded in the type parameter.
#[derive(Debug, Clone)]
pub struct TypedAuthContext<S: AuthState> {
    pub realm_id: RealmId,
    pub client_id: Option<ClientId>,
    pub user_id: S::UserIdType,
    pub session_id: Option<SessionId>,
    pub ip_address: Option<IpAddr>,
    pub parameters: HashMap<String, Vec<String>>,
    pub attributes: HashMap<String, String>,
    pub current_challenge: Option<Challenge>,
    _state: PhantomData<fn() -> S>,
}

impl TypedAuthContext<AnonymousState> {
    /// Create a new anonymous context for the given realm.
    pub fn new_anonymous(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: HashMap::new(),
            attributes: HashMap::new(),
            current_challenge: None,
            _state: PhantomData,
        }
    }

    /// Transition from anonymous to authenticated.
    pub fn authenticate(self, user_id: UserId) -> TypedAuthContext<AuthenticatedState> {
        TypedAuthContext {
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id,
            session_id: self.session_id,
            ip_address: self.ip_address,
            parameters: self.parameters,
            attributes: self.attributes,
            current_challenge: None,
            _state: PhantomData,
        }
    }

    /// Build from an untyped `AuthContext`.
    pub fn from_untyped(ctx: AuthContext) -> Self {
        Self {
            realm_id: ctx.realm_id,
            client_id: ctx.client_id,
            user_id: ctx.user_id,
            session_id: ctx.session_id,
            ip_address: ctx.ip_address,
            parameters: ctx.parameters,
            attributes: ctx.attributes,
            current_challenge: ctx.current_challenge,
            _state: PhantomData,
        }
    }

    /// Convert to the untyped `AuthContext`.
    pub fn into_untyped(self) -> AuthContext {
        AuthContext {
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id: self.user_id,
            session_id: self.session_id,
            ip_address: self.ip_address,
            parameters: self.parameters,
            attributes: self.attributes,
            current_challenge: self.current_challenge,
        }
    }

    /// Clone into an untyped `AuthContext`.
    pub fn as_untyped(&self) -> AuthContext {
        AuthContext {
            realm_id: self.realm_id.clone(),
            client_id: self.client_id.clone(),
            user_id: self.user_id.clone(),
            session_id: self.session_id.clone(),
            ip_address: self.ip_address,
            parameters: self.parameters.clone(),
            attributes: self.attributes.clone(),
            current_challenge: self.current_challenge.clone(),
        }
    }
}

impl TypedAuthContext<AuthenticatedState> {
    /// Try to build from an untyped `AuthContext` — fails if `user_id` is missing.
    pub fn try_from_untyped(ctx: AuthContext) -> Result<Self, IssuerdError> {
        let user_id = ctx.user_id.clone().ok_or_else(|| {
            IssuerdError::InvalidRequest("cannot create AuthenticatedState without user_id".into())
        })?;
        Ok(Self {
            realm_id: ctx.realm_id,
            client_id: ctx.client_id,
            user_id,
            session_id: ctx.session_id,
            ip_address: ctx.ip_address,
            parameters: ctx.parameters,
            attributes: ctx.attributes,
            current_challenge: ctx.current_challenge,
            _state: PhantomData,
        })
    }

    /// Convert to the untyped `AuthContext`.
    pub fn into_untyped(self) -> AuthContext {
        AuthContext {
            realm_id: self.realm_id,
            client_id: self.client_id,
            user_id: Some(self.user_id),
            session_id: self.session_id,
            ip_address: self.ip_address,
            parameters: self.parameters,
            attributes: self.attributes,
            current_challenge: self.current_challenge,
        }
    }

    /// Clone into an untyped `AuthContext`.
    pub fn as_untyped(&self) -> AuthContext {
        AuthContext {
            realm_id: self.realm_id.clone(),
            client_id: self.client_id.clone(),
            user_id: Some(self.user_id.clone()),
            session_id: self.session_id.clone(),
            ip_address: self.ip_address,
            parameters: self.parameters.clone(),
            attributes: self.attributes.clone(),
            current_challenge: self.current_challenge.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealmId;

    #[test]
    fn anonymous_context_has_optional_user_id() {
        let ctx = TypedAuthContext::<AnonymousState>::new_anonymous(RealmId::new("r1").unwrap());
        let opt: Option<UserId> = ctx.user_id;
        assert!(opt.is_none());
    }

    #[test]
    fn authenticated_context_has_required_user_id() {
        let ctx = TypedAuthContext::<AnonymousState>::new_anonymous(RealmId::new("r1").unwrap())
            .authenticate(UserId::new("alice").unwrap());
        let uid: UserId = ctx.user_id;
        assert_eq!(uid, UserId::new("alice").unwrap());
    }

    #[test]
    fn authenticate_transition_changes_type() {
        let anon = TypedAuthContext::<AnonymousState>::new_anonymous(RealmId::new("r1").unwrap());
        let auth = anon.authenticate(UserId::new("alice").unwrap());
        assert_eq!(auth.user_id, UserId::new("alice").unwrap());
    }

    #[test]
    fn from_untyped_fails_when_user_missing() {
        let untyped = AuthContext {
            realm_id: RealmId::new("r1").unwrap(),
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: HashMap::new(),
            attributes: HashMap::new(),
            current_challenge: None,
        };
        assert!(TypedAuthContext::<AuthenticatedState>::try_from_untyped(untyped).is_err());
    }

    #[test]
    fn from_untyped_succeeds_when_user_present() {
        let untyped = AuthContext {
            realm_id: RealmId::new("r1").unwrap(),
            client_id: None,
            user_id: Some(UserId::new("alice").unwrap()),
            session_id: None,
            ip_address: None,
            parameters: HashMap::new(),
            attributes: HashMap::new(),
            current_challenge: None,
        };
        let typed = TypedAuthContext::<AuthenticatedState>::try_from_untyped(untyped).unwrap();
        assert_eq!(typed.user_id, UserId::new("alice").unwrap());
    }

    #[test]
    fn into_untyped_roundtrip() {
        let ctx = TypedAuthContext::<AnonymousState>::new_anonymous(RealmId::new("r1").unwrap())
            .authenticate(UserId::new("alice").unwrap());
        let untyped = ctx.into_untyped();
        assert_eq!(untyped.user_id, Some(UserId::new("alice").unwrap()));
    }

    #[test]
    fn as_untyped_anonymous_copies_all_fields() {
        let mut ctx =
            TypedAuthContext::<AnonymousState>::new_anonymous(RealmId::new("r1").unwrap());
        ctx.client_id = Some(ClientId::new("c1").unwrap());
        ctx.session_id = Some(SessionId::new("s1").unwrap());
        ctx.ip_address = Some("127.0.0.1".parse().unwrap());
        ctx.parameters.insert("key".to_string(), vec!["val".to_string()]);
        ctx.attributes.insert("attr".to_string(), "v".to_string());
        ctx.current_challenge = Some(Challenge::Cookie);

        let untyped = ctx.as_untyped();
        assert_eq!(untyped.realm_id, RealmId::new("r1").unwrap());
        assert_eq!(untyped.client_id, Some(ClientId::new("c1").unwrap()));
        assert_eq!(untyped.user_id, None);
        assert_eq!(untyped.session_id, Some(SessionId::new("s1").unwrap()));
        assert_eq!(untyped.ip_address, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(untyped.parameters.get("key").unwrap()[0], "val");
        assert_eq!(untyped.attributes.get("attr").unwrap(), "v");
        assert!(matches!(untyped.current_challenge, Some(Challenge::Cookie)));
    }

    #[test]
    fn as_untyped_authenticated_copies_all_fields() {
        let mut anon =
            TypedAuthContext::<AnonymousState>::new_anonymous(RealmId::new("r1").unwrap());
        anon.client_id = Some(ClientId::new("c1").unwrap());
        anon.session_id = Some(SessionId::new("s1").unwrap());
        anon.ip_address = Some("127.0.0.1".parse().unwrap());
        let ctx = anon.authenticate(UserId::new("alice").unwrap());

        let untyped = ctx.as_untyped();
        assert_eq!(untyped.user_id, Some(UserId::new("alice").unwrap()));
        assert_eq!(untyped.client_id, Some(ClientId::new("c1").unwrap()));
        assert_eq!(untyped.session_id, Some(SessionId::new("s1").unwrap()));
    }

    #[test]
    fn from_untyped_anonymous_with_populated_fields() {
        let untyped = AuthContext {
            realm_id: RealmId::new("r1").unwrap(),
            client_id: Some(ClientId::new("c1").unwrap()),
            user_id: Some(UserId::new("alice").unwrap()),
            session_id: Some(SessionId::new("s1").unwrap()),
            ip_address: Some("127.0.0.1".parse().unwrap()),
            parameters: {
                let mut m = HashMap::new();
                m.insert("k".to_string(), vec!["v".to_string()]);
                m
            },
            attributes: {
                let mut m = HashMap::new();
                m.insert("a".to_string(), "b".to_string());
                m
            },
            current_challenge: Some(Challenge::Cookie),
        };
        let typed = TypedAuthContext::<AnonymousState>::from_untyped(untyped);
        assert_eq!(typed.realm_id, RealmId::new("r1").unwrap());
        assert_eq!(typed.user_id, Some(UserId::new("alice").unwrap()));
        assert_eq!(typed.client_id, Some(ClientId::new("c1").unwrap()));
    }

    #[test]
    fn into_untyped_anonymous_roundtrip() {
        let mut ctx =
            TypedAuthContext::<AnonymousState>::new_anonymous(RealmId::new("r1").unwrap());
        ctx.client_id = Some(ClientId::new("c1").unwrap());
        let untyped = ctx.into_untyped();
        assert_eq!(untyped.realm_id, RealmId::new("r1").unwrap());
        assert_eq!(untyped.client_id, Some(ClientId::new("c1").unwrap()));
    }

    #[test]
    fn try_from_untyped_authenticated_with_all_fields() {
        let untyped = AuthContext {
            realm_id: RealmId::new("r1").unwrap(),
            client_id: Some(ClientId::new("c1").unwrap()),
            user_id: Some(UserId::new("alice").unwrap()),
            session_id: Some(SessionId::new("s1").unwrap()),
            ip_address: Some("127.0.0.1".parse().unwrap()),
            parameters: HashMap::new(),
            attributes: HashMap::new(),
            current_challenge: None,
        };
        let typed = TypedAuthContext::<AuthenticatedState>::try_from_untyped(untyped).unwrap();
        assert_eq!(typed.user_id, UserId::new("alice").unwrap());
        assert_eq!(typed.realm_id, RealmId::new("r1").unwrap());
        assert_eq!(typed.client_id, Some(ClientId::new("c1").unwrap()));
    }

    /// ```compile_fail
    /// use issuerd_core::typestate::TypedAuthContext;
    /// use issuerd_core::typestate::AuthenticatedState;
    /// use issuerd_core::UserId;
    /// fn f(ctx: TypedAuthContext<AuthenticatedState>) {
    ///     ctx.authenticate(UserId::new("x").unwrap());
    /// }
    /// ```
    #[allow(dead_code)]
    fn compile_fail_authenticate_on_authenticated() {}
}
