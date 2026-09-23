// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OIDC authorization request with lifecycle state encoded in the type parameter.

use chrono::{DateTime, Utc};
use std::marker::PhantomData;

use issuerd_core::{
    typestate::{AuthAuthenticated, AuthAuthorized, AuthConsented, AuthInit, AuthRequestState},
    Client, Consent, Realm, RedirectUri, Scope, User, UserSession,
};

/// OIDC authorization request with lifecycle state encoded in the type parameter.
#[derive(Debug, Clone)]
pub struct AuthRequest<State: AuthRequestState> {
    pub realm: Realm,
    pub client: Client,
    pub redirect_uri: RedirectUri,
    pub scope: Scope,
    pub state: Option<String>,
    pub nonce: Option<issuerd_core::Nonce>,
    pub user: State::UserType,
    pub session: State::SessionType,
    pub auth_time: Option<DateTime<Utc>>,
    pub code_challenge: Option<issuerd_core::Base64Url>,
    pub code_challenge_method: Option<issuerd_core::PkceCodeChallengeMethod>,
    pub acr_values: Vec<String>,
    pub claims: Option<serde_json::Value>,
    _state: PhantomData<fn() -> State>,
}

impl AuthRequest<AuthInit> {
    /// Create a new initial auth request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        realm: Realm,
        client: Client,
        redirect_uri: RedirectUri,
        scope: Scope,
        state: Option<String>,
        nonce: Option<issuerd_core::Nonce>,
        code_challenge: Option<issuerd_core::Base64Url>,
        code_challenge_method: Option<issuerd_core::PkceCodeChallengeMethod>,
        acr_values: Vec<String>,
        claims: Option<serde_json::Value>,
    ) -> Self {
        Self {
            realm,
            client,
            redirect_uri,
            scope,
            state,
            nonce,
            user: (),
            session: (),
            auth_time: None,
            code_challenge,
            code_challenge_method,
            acr_values,
            claims,
            _state: PhantomData,
        }
    }

    /// Transition to authenticated after flow success.
    pub fn with_authenticated_user(
        self,
        user: User,
        session: UserSession,
        auth_time: DateTime<Utc>,
    ) -> AuthRequest<AuthAuthenticated> {
        AuthRequest {
            realm: self.realm,
            client: self.client,
            redirect_uri: self.redirect_uri,
            scope: self.scope,
            state: self.state,
            nonce: self.nonce,
            user,
            session,
            auth_time: Some(auth_time),
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            acr_values: self.acr_values,
            claims: self.claims,
            _state: PhantomData,
        }
    }
}

impl AuthRequest<AuthAuthenticated> {
    /// Transition to consented after consent check.
    pub fn with_consent(self, _consent: Option<Consent>) -> AuthRequest<AuthConsented> {
        AuthRequest {
            realm: self.realm,
            client: self.client,
            redirect_uri: self.redirect_uri,
            scope: self.scope,
            state: self.state,
            nonce: self.nonce,
            user: self.user,
            session: self.session,
            auth_time: self.auth_time,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            acr_values: self.acr_values,
            claims: self.claims,
            _state: PhantomData,
        }
    }
}

impl AuthRequest<AuthConsented> {
    /// Transition to authorized after tokens issued.
    pub fn authorize(self) -> AuthRequest<AuthAuthorized> {
        AuthRequest {
            realm: self.realm,
            client: self.client,
            redirect_uri: self.redirect_uri,
            scope: self.scope,
            state: self.state,
            nonce: self.nonce,
            user: self.user,
            session: self.session,
            auth_time: self.auth_time,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            acr_values: self.acr_values,
            claims: self.claims,
            _state: PhantomData,
        }
    }
}

impl AuthRequest<AuthAuthorized> {
    /// Build a redirect response with an authorization code.
    pub fn into_redirect_response(self, code: String) -> RedirectResponse {
        RedirectResponse {
            redirect_uri: self.redirect_uri.to_string(),
            code: Some(code),
            id_token: None,
            state: self.state,
        }
    }
}

/// Simple redirect response DTO.
#[derive(Debug, serde::Serialize)]
pub struct RedirectResponse {
    pub redirect_uri: String,
    pub code: Option<String>,
    pub id_token: Option<String>,
    pub state: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{
        ClientId, ClientIdentifier, ClientProtocol, RealmId, RealmName, RedirectUri, Scope, UserId,
        Username,
    };
    use std::collections::HashMap;

    fn test_realm() -> Realm {
        Realm {
            id: RealmId::new("r1").unwrap(),
            name: RealmName::new("realm-1").unwrap(),
            display_name: None,
            enabled: true,
            ..Default::default()
        }
    }

    fn test_client() -> Client {
        Client {
            id: ClientId::new("client-1").unwrap(),
            realm_id: RealmId::new("r1").unwrap(),
            client_id: ClientIdentifier::new("c1").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: true,
            bearer_only: false,
            client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::default(),
            optional_scopes: Scope::default(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    fn test_user() -> User {
        User {
            id: UserId::new("alice").unwrap(),
            realm_id: RealmId::new("r1").unwrap(),
            username: Username::new("alice").unwrap(),
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
        }
    }

    fn test_session() -> UserSession {
        UserSession {
            id: issuerd_core::SessionId::new("s1").unwrap(),
            realm_id: RealmId::new("r1").unwrap(),
            user_id: UserId::new("alice").unwrap(),
            login_username: Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: issuerd_core::AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
            clients: vec![],
        }
    }

    #[test]
    fn auth_request_new_sets_fields() {
        let realm = test_realm();
        let client = test_client();
        let redirect = RedirectUri::new("http://localhost/cb").unwrap();
        let scope = Scope::parse("openid");
        let req = AuthRequest::<AuthInit>::new(
            realm.clone(),
            client.clone(),
            redirect.clone(),
            scope.clone(),
            Some("state-1".to_string()),
            None,
            None,
            None,
            vec!["1".to_string()],
            None,
        );
        assert_eq!(req.realm.id, realm.id);
        assert_eq!(req.client.id, client.id);
        assert_eq!(req.redirect_uri, redirect);
        assert_eq!(req.scope, scope);
        assert_eq!(req.state, Some("state-1".to_string()));
        assert_eq!(req.acr_values, vec!["1".to_string()]);
        assert!(req.auth_time.is_none());
    }

    #[test]
    fn auth_request_with_authenticated_user_transitions() {
        let req = AuthRequest::<AuthInit>::new(
            test_realm(),
            test_client(),
            RedirectUri::new("http://localhost/cb").unwrap(),
            Scope::parse("openid"),
            Some("state-1".to_string()),
            None,
            None,
            None,
            vec![],
            None,
        );
        let auth_time = Utc::now();
        let authed = req.with_authenticated_user(test_user(), test_session(), auth_time);
        assert_eq!(authed.user.id, UserId::new("alice").unwrap());
        assert_eq!(authed.auth_time, Some(auth_time));
    }

    #[test]
    fn auth_request_with_consent_transitions() {
        let req = AuthRequest::<AuthInit>::new(
            test_realm(),
            test_client(),
            RedirectUri::new("http://localhost/cb").unwrap(),
            Scope::parse("openid"),
            None,
            None,
            None,
            None,
            vec![],
            None,
        );
        let authed = req.with_authenticated_user(test_user(), test_session(), Utc::now());
        let consented = authed.with_consent(None);
        assert_eq!(consented.user.id, UserId::new("alice").unwrap());
    }

    #[test]
    fn auth_request_authorize_transitions() {
        let req = AuthRequest::<AuthInit>::new(
            test_realm(),
            test_client(),
            RedirectUri::new("http://localhost/cb").unwrap(),
            Scope::parse("openid"),
            Some("state-2".to_string()),
            None,
            None,
            None,
            vec![],
            None,
        );
        let authed = req.with_authenticated_user(test_user(), test_session(), Utc::now());
        let consented = authed.with_consent(None);
        let authorized = consented.authorize();
        assert_eq!(authorized.user.id, UserId::new("alice").unwrap());
        assert_eq!(authorized.state, Some("state-2".to_string()));
    }

    #[test]
    fn auth_request_into_redirect_response() {
        let req = AuthRequest::<AuthInit>::new(
            test_realm(),
            test_client(),
            RedirectUri::new("http://localhost/cb").unwrap(),
            Scope::parse("openid"),
            Some("state-3".to_string()),
            None,
            None,
            None,
            vec![],
            None,
        );
        let authed = req.with_authenticated_user(test_user(), test_session(), Utc::now());
        let consented = authed.with_consent(None);
        let authorized = consented.authorize();
        let resp = authorized.into_redirect_response("code-123".to_string());
        assert_eq!(resp.redirect_uri, "http://localhost/cb");
        assert_eq!(resp.code, Some("code-123".to_string()));
        assert_eq!(resp.state, Some("state-3".to_string()));
        assert!(resp.id_token.is_none());
    }
}
