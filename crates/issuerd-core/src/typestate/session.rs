// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// TypedSession: user session with lifecycle state encoded in the type parameter.

use std::marker::PhantomData;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::error::IssuerdError;
use crate::ids::{ClientId, ClientSessionId, SessionId, UserId};
use crate::models::{AuthMethod, ClientSession, UserSession};

use super::{
    SessionAnonymous, SessionAuthenticated, SessionAuthorized, SessionConsentRequired,
    SessionExpired, SessionState,
};

/// User session with lifecycle state encoded in the type parameter.
#[derive(Debug, Clone)]
pub struct TypedSession<State: SessionState> {
    pub user_id: UserId,
    pub client_id: ClientId,
    pub session_id: SessionId,
    pub auth_time: DateTime<Utc>,
    pub auth_method: AuthMethod,
    pub remember_me: bool,
    pub ip_address: IpAddr,
    pub(crate) _state: PhantomData<fn() -> State>,
}

impl TypedSession<SessionAnonymous> {
    /// Create a new anonymous session skeleton.
    pub fn new_anonymous(user_id: UserId, client_id: ClientId, ip: IpAddr) -> Self {
        Self {
            user_id,
            client_id,
            session_id: SessionId::new(crate::utils::generate_id()).unwrap(),
            auth_time: Utc::now(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            ip_address: ip,
            _state: PhantomData,
        }
    }

    /// Transition to authenticated by providing auth method and explicit session id.
    pub fn authenticate(
        self,
        method: AuthMethod,
        session_id: SessionId,
    ) -> TypedSession<SessionAuthenticated> {
        TypedSession {
            user_id: self.user_id,
            client_id: self.client_id,
            session_id,
            auth_time: self.auth_time,
            auth_method: method,
            remember_me: self.remember_me,
            ip_address: self.ip_address,
            _state: PhantomData,
        }
    }
}

impl TypedSession<SessionAuthenticated> {
    /// Transition to consent-required state.
    pub fn require_consent(
        self,
        _client: &crate::Client,
        _scopes: crate::Scope,
    ) -> TypedSession<SessionConsentRequired> {
        TypedSession {
            user_id: self.user_id,
            client_id: self.client_id,
            session_id: self.session_id,
            auth_time: self.auth_time,
            auth_method: self.auth_method,
            remember_me: self.remember_me,
            ip_address: self.ip_address,
            _state: PhantomData,
        }
    }

    /// Convert to a plain `UserSession` for storage.
    ///
    /// `realm_id` and `login_username` are not tracked by the typestate
    /// wrapper, so the caller — which always knows the realm it operates
    /// in — must supply them explicitly.
    pub fn into_user_session(
        self,
        realm_id: crate::RealmId,
        login_username: crate::Username,
    ) -> UserSession {
        UserSession {
            id: self.session_id.clone(),
            realm_id,
            user_id: self.user_id,
            login_username,
            ip_address: self.ip_address,
            auth_method: self.auth_method,
            remember_me: self.remember_me,
            offline: false,
            started: self.auth_time,
            last_session_refresh: self.auth_time,
            auth_time: self.auth_time,
            impersonator: None,
            clients: vec![],
        }
    }

    /// Build from an existing `UserSession`.
    pub fn from_user_session(session: UserSession) -> Self {
        Self {
            user_id: session.user_id,
            client_id: session
                .clients
                .first()
                .map(|c| c.client_id.clone())
                .unwrap_or_else(|| crate::ClientId::new(crate::utils::generate_id()).unwrap()),
            session_id: session.id,
            auth_time: session.auth_time,
            auth_method: session.auth_method,
            remember_me: session.remember_me,
            ip_address: session.ip_address,
            _state: PhantomData,
        }
    }
}

impl TypedSession<SessionConsentRequired> {
    /// Grant or deny authorization.
    pub fn authorize(self, granted: bool) -> Result<TypedSession<SessionAuthorized>, IssuerdError> {
        if granted {
            Ok(TypedSession {
                user_id: self.user_id,
                client_id: self.client_id,
                session_id: self.session_id,
                auth_time: self.auth_time,
                auth_method: self.auth_method,
                remember_me: self.remember_me,
                ip_address: self.ip_address,
                _state: PhantomData,
            })
        } else {
            Err(IssuerdError::AccessDenied)
        }
    }
}

impl TypedSession<SessionAuthorized> {
    /// Issue tokens, consuming the authorized session and returning an expired proof.
    ///
    /// The `TokenSet` is not actually produced here — this method is a type-level
    /// proof that the caller has the right to issue. The real token issuance is
    /// performed by `TokenManager` in `issuerd-token`.
    pub fn issue_token(self) -> TypedSession<SessionExpired> {
        TypedSession {
            user_id: self.user_id,
            client_id: self.client_id,
            session_id: self.session_id,
            auth_time: self.auth_time,
            auth_method: self.auth_method,
            remember_me: self.remember_me,
            ip_address: self.ip_address,
            _state: PhantomData,
        }
    }

    /// Convert to a plain `UserSession` for storage.
    ///
    /// `realm_id` and `login_username` are not tracked by the typestate
    /// wrapper, so the caller — which always knows the realm it operates
    /// in — must supply them explicitly.
    pub fn into_user_session(
        self,
        realm_id: crate::RealmId,
        login_username: crate::Username,
    ) -> UserSession {
        UserSession {
            id: self.session_id.clone(),
            realm_id,
            user_id: self.user_id,
            login_username,
            ip_address: self.ip_address,
            auth_method: self.auth_method,
            remember_me: self.remember_me,
            offline: false,
            started: self.auth_time,
            last_session_refresh: self.auth_time,
            auth_time: self.auth_time,
            impersonator: None,
            clients: vec![ClientSession {
                id: ClientSessionId::new(crate::utils::generate_id()).unwrap(),
                client_id: self.client_id,
                session_id: self.session_id,
                redirect_uri: None,
                state: None,
                auth_method: self.auth_method,
                timestamp: self.auth_time,
            }],
        }
    }

    /// Build from an existing `UserSession` (e.g. when loading from storage).
    pub fn from_user_session(session: UserSession) -> Self {
        Self {
            user_id: session.user_id,
            client_id: session
                .clients
                .first()
                .map(|c| c.client_id.clone())
                .unwrap_or_else(|| crate::ClientId::new(crate::utils::generate_id()).unwrap()),
            session_id: session.id,
            auth_time: session.auth_time,
            auth_method: session.auth_method,
            remember_me: session.remember_me,
            ip_address: session.ip_address,
            _state: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ClientId, UserId};

    #[test]
    fn session_lifecycle_full_chain() {
        let anon = TypedSession::<SessionAnonymous>::new_anonymous(
            UserId::new("alice").unwrap(),
            ClientId::new("client-1").unwrap(),
            "127.0.0.1".parse().unwrap(),
        );
        let auth = anon.authenticate(AuthMethod::Password, SessionId::new("s1").unwrap());
        let consent = auth.require_consent(
            &crate::Client {
                id: ClientId::new("client-1").unwrap(),
                realm_id: crate::RealmId::new("r1").unwrap(),
                client_id: crate::ClientIdentifier::new("c1").unwrap(),
                name: None,
                description: None,
                enabled: true,
                protocol: crate::ClientProtocol::OpenIdConnect,
                public_client: true,
                bearer_only: false,
                client_authenticator_type: crate::ClientAuthenticatorType::ClientSecret,
                secret: None,
                redirect_uris: vec![],
                web_origins: vec![],
                default_scopes: crate::Scope::default(),
                optional_scopes: crate::Scope::default(),
                consent_required: false,
                full_scope_allowed: true,
                service_accounts_enabled: false,
                protocol_mappers: Vec::new(),
                scope_mappings: Default::default(),
                attributes: std::collections::HashMap::new(),
            },
            crate::Scope::parse("openid"),
        );
        let authorized = consent.authorize(true).unwrap();
        let _expired = authorized.issue_token();
    }

    #[test]
    fn authorize_denied_returns_error() {
        let anon = TypedSession::<SessionAnonymous>::new_anonymous(
            UserId::new("alice").unwrap(),
            ClientId::new("client-1").unwrap(),
            "127.0.0.1".parse().unwrap(),
        );
        let auth = anon.authenticate(AuthMethod::Password, SessionId::new("s1").unwrap());
        let consent = auth.require_consent(
            &crate::Client {
                id: ClientId::new("client-1").unwrap(),
                realm_id: crate::RealmId::new("r1").unwrap(),
                client_id: crate::ClientIdentifier::new("c1").unwrap(),
                name: None,
                description: None,
                enabled: true,
                protocol: crate::ClientProtocol::OpenIdConnect,
                public_client: true,
                bearer_only: false,
                client_authenticator_type: crate::ClientAuthenticatorType::ClientSecret,
                secret: None,
                redirect_uris: vec![],
                web_origins: vec![],
                default_scopes: crate::Scope::default(),
                optional_scopes: crate::Scope::default(),
                consent_required: false,
                full_scope_allowed: true,
                service_accounts_enabled: false,
                protocol_mappers: Vec::new(),
                scope_mappings: Default::default(),
                attributes: std::collections::HashMap::new(),
            },
            crate::Scope::parse("openid"),
        );
        assert_eq!(consent.authorize(false).unwrap_err(), IssuerdError::AccessDenied);
    }

    #[test]
    fn new_anonymous_sets_fields() {
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let anon = TypedSession::<SessionAnonymous>::new_anonymous(
            UserId::new("bob").unwrap(),
            ClientId::new("client-2").unwrap(),
            ip,
        );
        assert_eq!(anon.user_id, UserId::new("bob").unwrap());
        assert_eq!(anon.client_id, ClientId::new("client-2").unwrap());
        assert_eq!(anon.ip_address, ip);
        assert_eq!(anon.auth_method, AuthMethod::Password);
        assert!(!anon.remember_me);
    }

    #[test]
    fn authenticated_from_user_session_with_client() {
        let session = UserSession {
            id: SessionId::new("s1").unwrap(),
            realm_id: crate::RealmId::new("r1").unwrap(),
            user_id: UserId::new("alice").unwrap(),
            login_username: crate::Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Spnego,
            remember_me: true,
            offline: false,
            started: chrono::Utc::now(),
            last_session_refresh: chrono::Utc::now(),
            auth_time: chrono::Utc::now(),
            impersonator: None,
            clients: vec![ClientSession {
                id: ClientSessionId::new("cs1").unwrap(),
                client_id: ClientId::new("client-1").unwrap(),
                session_id: SessionId::new("s1").unwrap(),
                redirect_uri: None,
                state: None,
                auth_method: AuthMethod::Spnego,
                timestamp: chrono::Utc::now(),
            }],
        };
        let typed = TypedSession::<SessionAuthenticated>::from_user_session(session);
        assert_eq!(typed.user_id, UserId::new("alice").unwrap());
        assert_eq!(typed.client_id, ClientId::new("client-1").unwrap());
        assert_eq!(typed.auth_method, AuthMethod::Spnego);
        assert!(typed.remember_me);
    }

    #[test]
    fn authenticated_from_user_session_without_client_falls_back() {
        let session = UserSession {
            id: SessionId::new("s1").unwrap(),
            realm_id: crate::RealmId::new("r1").unwrap(),
            user_id: UserId::new("alice").unwrap(),
            login_username: crate::Username::new("alice").unwrap(),
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
        let typed = TypedSession::<SessionAuthenticated>::from_user_session(session);
        assert_eq!(typed.user_id, UserId::new("alice").unwrap());
        // client_id falls back to a generated id, just verify it parses
        assert!(ClientId::new(typed.client_id.0.as_str()).is_ok());
    }

    #[test]
    fn authenticated_into_user_session() {
        let anon = TypedSession::<SessionAnonymous>::new_anonymous(
            UserId::new("alice").unwrap(),
            ClientId::new("client-1").unwrap(),
            "127.0.0.1".parse().unwrap(),
        );
        let auth = anon.authenticate(AuthMethod::Password, SessionId::new("s1").unwrap());
        let session = auth.into_user_session(
            crate::RealmId::new("r1").unwrap(),
            crate::Username::new("alice").unwrap(),
        );
        assert_eq!(session.id, SessionId::new("s1").unwrap());
        assert_eq!(session.user_id, UserId::new("alice").unwrap());
        assert_eq!(session.realm_id, crate::RealmId::new("r1").unwrap());
        assert_eq!(session.login_username, crate::Username::new("alice").unwrap());
        assert!(session.clients.is_empty());
    }

    #[test]
    fn authorized_from_user_session_with_client() {
        let session = UserSession {
            id: SessionId::new("s2").unwrap(),
            realm_id: crate::RealmId::new("r1").unwrap(),
            user_id: UserId::new("bob").unwrap(),
            login_username: crate::Username::new("bob").unwrap(),
            ip_address: "10.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: chrono::Utc::now(),
            last_session_refresh: chrono::Utc::now(),
            auth_time: chrono::Utc::now(),
            impersonator: None,
            clients: vec![ClientSession {
                id: ClientSessionId::new("cs2").unwrap(),
                client_id: ClientId::new("client-2").unwrap(),
                session_id: SessionId::new("s2").unwrap(),
                redirect_uri: None,
                state: None,
                auth_method: AuthMethod::Password,
                timestamp: chrono::Utc::now(),
            }],
        };
        let typed = TypedSession::<SessionAuthorized>::from_user_session(session);
        assert_eq!(typed.user_id, UserId::new("bob").unwrap());
        assert_eq!(typed.client_id, ClientId::new("client-2").unwrap());
    }

    #[test]
    fn authorized_into_user_session_has_client() {
        let anon = TypedSession::<SessionAnonymous>::new_anonymous(
            UserId::new("alice").unwrap(),
            ClientId::new("client-1").unwrap(),
            "127.0.0.1".parse().unwrap(),
        );
        let auth = anon.authenticate(AuthMethod::Password, SessionId::new("s1").unwrap());
        let consent = auth.require_consent(
            &crate::Client {
                id: ClientId::new("client-1").unwrap(),
                realm_id: crate::RealmId::new("r1").unwrap(),
                client_id: crate::ClientIdentifier::new("c1").unwrap(),
                name: None,
                description: None,
                enabled: true,
                protocol: crate::ClientProtocol::OpenIdConnect,
                public_client: true,
                bearer_only: false,
                client_authenticator_type: crate::ClientAuthenticatorType::ClientSecret,
                secret: None,
                redirect_uris: vec![],
                web_origins: vec![],
                default_scopes: crate::Scope::default(),
                optional_scopes: crate::Scope::default(),
                consent_required: false,
                full_scope_allowed: true,
                service_accounts_enabled: false,
                protocol_mappers: Vec::new(),
                scope_mappings: Default::default(),
                attributes: std::collections::HashMap::new(),
            },
            crate::Scope::parse("openid"),
        );
        let authorized = consent.authorize(true).unwrap();
        let session = authorized.into_user_session(
            crate::RealmId::new("r1").unwrap(),
            crate::Username::new("alice").unwrap(),
        );
        assert_eq!(session.id, SessionId::new("s1").unwrap());
        assert_eq!(session.user_id, UserId::new("alice").unwrap());
        assert_eq!(session.clients.len(), 1);
        assert_eq!(session.clients[0].client_id, ClientId::new("client-1").unwrap());
    }

    /// ```compile_fail
    /// use issuerd_core::typestate::{TypedSession, SessionAuthenticated};
    /// fn f(s: TypedSession<SessionAuthenticated>) {
    ///     let _ = s.issue_token();
    /// }
    /// ```
    #[allow(dead_code)]
    fn compile_fail_issue_token_on_authenticated() {}

    /// ```compile_fail
    /// use issuerd_core::typestate::{TypedSession, SessionExpired};
    /// fn f(s: TypedSession<SessionExpired>) {
    ///     let _ = s.issue_token();
    /// }
    /// ```
    #[allow(dead_code)]
    fn compile_fail_issue_token_on_expired() {}
}
