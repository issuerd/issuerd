// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Test fixtures: mock token service for Admin API handler tests.

#[cfg(test)]
pub mod tests {
    use issuerd_core::{
        AccessTokenClaims, Algorithm, Audience, Client, IdTokenClaims, Issuer, IssuerdError,
        JwsType, JwtId, JwtType, KeyId, RealmAccess, ValidatedAccessToken,
    };
    use std::sync::Arc;

    use crate::state::AdminApiState;

    pub struct MockTokenService {
        pub roles: Vec<issuerd_core::RoleName>,
    }

    impl issuerd_core::TokenService for MockTokenService {
        fn validate_access_token(
            &self,
            _token: &str,
        ) -> Result<ValidatedAccessToken, IssuerdError> {
            Ok(ValidatedAccessToken {
                claims: AccessTokenClaims {
                    jti: JwtId::new("jti").unwrap(),
                    iss: Issuer::new("http://localhost:8080/realms/master").unwrap(),
                    sub: issuerd_core::UserId::new("admin").unwrap(),
                    aud: Audience::new("aud").unwrap(),
                    exp: 9999999999,
                    iat: 0,
                    nbf: 0,
                    scope: issuerd_core::Scope::parse("openid"),
                    typ: JwtType::Bearer,
                    azp: None,
                    session_state: None,
                    realm_access: Some(RealmAccess {
                        roles: self.roles.clone(),
                    }),
                    resource_access: None,
                    sid: None,
                    claims: None,
                    cnf: None,
                    authorization_details: None,
                },
                header: issuerd_core::JwsHeader {
                    alg: Algorithm::Rs256,
                    typ: Some(JwsType::Jwt),
                    kid: KeyId::new("key-1").unwrap(),
                },
            })
        }

        fn validate_id_token(
            &self,
            _token: &str,
            _client: &Client,
            _nonce: Option<&str>,
        ) -> Result<IdTokenClaims, IssuerdError> {
            unimplemented!()
        }

        fn validate_refresh_token(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::ValidatedRefreshToken, IssuerdError> {
            unimplemented!()
        }

        fn validate_id_token_hint(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::IdTokenClaims, IssuerdError> {
            unimplemented!()
        }
    }

    /// Drive a future that is guaranteed to be immediately ready (in-memory
    /// storage performs no I/O) from synchronous test setup code.
    pub fn block_on_ready<F: std::future::Future>(future: F) -> F::Output {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => panic!("test setup future unexpectedly pended"),
        }
    }

    /// The bootstrap `master` realm (id == name, as in the test harness).
    pub fn master_realm() -> issuerd_core::Realm {
        issuerd_core::Realm {
            id: issuerd_core::RealmId::new("master").unwrap(),
            name: issuerd_core::RealmName::new("master").unwrap(),
            ..Default::default()
        }
    }

    /// Fresh in-memory storage pre-seeded with the `master` realm so that
    /// mock master-realm tokens pass admin realm binding.
    pub fn storage_with_master_realm() -> Arc<issuerd_storage::InMemoryStorage> {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        block_on_ready(issuerd_core::Storage::create_realm(storage.as_ref(), &master_realm()))
            .unwrap();
        storage
    }

    pub fn test_state(roles: Vec<issuerd_core::RoleName>) -> Arc<AdminApiState> {
        test_state_with_storage(storage_with_master_realm(), roles)
    }

    /// Same as [`test_state`] but over caller-supplied storage, so tests can
    /// inject a `MockStorage` primed to fail specific calls.
    pub fn test_state_with_storage(
        storage: Arc<dyn issuerd_core::Storage>,
        roles: Vec<issuerd_core::RoleName>,
    ) -> Arc<AdminApiState> {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));
        Arc::new(AdminApiState {
            storage,
            token_service: Arc::new(MockTokenService { roles }),
            crypto: Arc::new(mock),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender: Arc::new(issuerd_core::MockEmailSender::new()),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            base_url: "http://localhost:8080".to_string(),
        })
    }

    /// Stub authenticator resolved by [`StubPluginRegistry`]; the id doubles as
    /// the display name so tests can assert on either.
    pub struct StubAuthenticator(&'static str);

    #[async_trait::async_trait]
    impl issuerd_core::Authenticator for StubAuthenticator {
        fn id(&self) -> &str {
            self.0
        }
        fn display_name(&self) -> &str {
            self.0
        }
        fn requires_user(&self) -> bool {
            false
        }
        fn configured_for(&self, _ctx: &issuerd_core::AuthContext) -> bool {
            true
        }
        async fn authenticate(
            &self,
            _ctx: &mut issuerd_core::AuthContext,
        ) -> issuerd_core::AuthStepResult {
            issuerd_core::AuthStepResult::Attempted
        }
    }

    /// Stub plugin registry whose known authenticator ids cover every stage of
    /// the seeded built-in flows (`issuerd_core::flows`), so `validate_flows`
    /// accepts a freshly seeded realm's flow set in flow-mutation tests, and
    /// whose required-action ids cover the five built-in actions so the
    /// execute-actions-email endpoint accepts them.
    pub struct StubPluginRegistry {
        authenticators: std::collections::HashSet<&'static str>,
        required_actions: std::collections::HashSet<&'static str>,
    }

    pub fn stub_plugin_registry() -> StubPluginRegistry {
        StubPluginRegistry {
            authenticators: [
                "auth-cookie",
                "auth-spnego",
                "auth-idp-redirect",
                "auth-username-password",
                "conditional-user-configured",
                "auth-otp-form",
                "auth-webauthn",
                "auth-registration",
            ]
            .into_iter()
            .collect(),
            required_actions: [
                "VERIFY_EMAIL",
                "UPDATE_PASSWORD",
                "UPDATE_PROFILE",
                "CONFIGURE_TOTP",
                "TERMS_AND_CONDITIONS",
            ]
            .into_iter()
            .collect(),
        }
    }

    #[async_trait::async_trait]
    impl issuerd_auth_flow::plugin_registry::PluginRegistry for StubPluginRegistry {
        async fn get_authenticator(
            &self,
            id: &str,
        ) -> Result<Option<Arc<dyn issuerd_core::Authenticator>>, issuerd_core::IssuerdError>
        {
            Ok(self.authenticators.get(id).map(|known| {
                Arc::new(StubAuthenticator(known)) as Arc<dyn issuerd_core::Authenticator>
            }))
        }

        async fn get_required_action(
            &self,
            _id: &str,
        ) -> Result<Option<Arc<dyn issuerd_core::RequiredAction>>, issuerd_core::IssuerdError>
        {
            Ok(None)
        }

        fn list_authenticator_ids(&self) -> Vec<String> {
            let mut ids: Vec<String> =
                self.authenticators.iter().map(|s| (*s).to_string()).collect();
            ids.sort();
            ids
        }

        fn list_required_action_ids(&self) -> Vec<String> {
            let mut ids: Vec<String> =
                self.required_actions.iter().map(|s| (*s).to_string()).collect();
            ids.sort();
            ids
        }
    }

    /// Recording stub for `issuerd_token::TokenIssuer`: captures the
    /// claims overlay and realm roles of the last issued access token so
    /// tests can assert what would have been signed, and returns
    /// deterministic (unsigned) token strings.
    pub struct StubTokenIssuer {
        pub last_access_overlay:
            std::sync::Mutex<Option<serde_json::Map<String, serde_json::Value>>>,
        pub last_realm_access: std::sync::Mutex<Option<issuerd_core::RealmAccess>>,
    }

    impl StubTokenIssuer {
        pub fn new() -> Self {
            Self {
                last_access_overlay: std::sync::Mutex::new(None),
                last_realm_access: std::sync::Mutex::new(None),
            }
        }

        fn canned_access_claims(
            user: &issuerd_core::User,
            client: &Client,
            realm: &issuerd_core::Realm,
        ) -> AccessTokenClaims {
            AccessTokenClaims {
                jti: JwtId::new("stub-jti").unwrap(),
                iss: Issuer::new(format!("http://localhost:8080/realms/{}", realm.name.as_str()))
                    .unwrap(),
                sub: user.id.clone(),
                aud: Audience::new(client.client_id.to_string()).unwrap(),
                exp: 9999999999,
                iat: 0,
                nbf: 0,
                scope: issuerd_core::Scope::parse("openid"),
                typ: JwtType::Bearer,
                azp: Some(client.client_id.to_string()),
                session_state: None,
                realm_access: None,
                resource_access: None,
                sid: None,
                claims: None,
                cnf: None,
                authorization_details: None,
            }
        }
    }

    impl Default for StubTokenIssuer {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl issuerd_token::TokenIssuer for StubTokenIssuer {
        async fn issue_access_token(
            &self,
            user: &issuerd_core::User,
            client: &Client,
            realm: &issuerd_core::Realm,
            _scope: &[String],
            _session_id: &issuerd_core::SessionId,
        ) -> Result<issuerd_token::AccessToken, issuerd_core::IssuerdError> {
            Ok(issuerd_token::AccessToken {
                token: "stub-access-token".to_string(),
                claims: Self::canned_access_claims(user, client, realm),
            })
        }

        async fn issue_access_token_with_roles(
            &self,
            user: &issuerd_core::User,
            client: &Client,
            realm: &issuerd_core::Realm,
            _scope: &[String],
            _session_id: &issuerd_core::SessionId,
            realm_access: Option<issuerd_core::RealmAccess>,
            _claims: Option<serde_json::Value>,
            claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<issuerd_token::AccessToken, issuerd_core::IssuerdError> {
            *self.last_access_overlay.lock().unwrap() = claims_overlay;
            *self.last_realm_access.lock().unwrap() = realm_access;
            self.issue_access_token(user, client, realm, _scope, _session_id).await
        }

        async fn issue_refresh_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &issuerd_core::Realm,
            _session_id: &issuerd_core::SessionId,
            _scope: &[String],
            _offline: bool,
            _dpop_jkt: Option<&str>,
            authorization_details: Option<&[serde_json::Value]>,
        ) -> Result<issuerd_token::RefreshToken, issuerd_core::IssuerdError> {
            Ok(issuerd_token::RefreshToken {
                token: "stub-refresh-token".to_string(),
                claims: issuerd_core::RefreshTokenClaims {
                    jti: JwtId::new("stub-jti").unwrap(),
                    iss: Issuer::new("http://localhost:8080/realms/master").unwrap(),
                    sub: issuerd_core::UserId::new("stub-user").unwrap(),
                    aud: Audience::new("aud").unwrap(),
                    exp: 9999999999,
                    iat: 0,
                    typ: JwtType::Refresh,
                    sid: issuerd_core::SessionId::new("stub-session").unwrap(),
                    scope: issuerd_core::Scope::parse("openid"),
                    cnf: None,
                    authorization_details: authorization_details.map(<[serde_json::Value]>::to_vec),
                },
            })
        }

        async fn issue_id_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &issuerd_core::Realm,
            _nonce: Option<&str>,
            auth_time: chrono::DateTime<chrono::Utc>,
            _session_id: &issuerd_core::SessionId,
            _access_token: Option<&issuerd_token::AccessToken>,
            _code: Option<&str>,
            _acr_values: Option<&[String]>,
            _claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<issuerd_token::IdToken, issuerd_core::IssuerdError> {
            Ok(issuerd_token::IdToken {
                token: "stub-id-token".to_string(),
                claims: issuerd_core::IdTokenClaims {
                    iss: Issuer::new("http://localhost:8080/realms/master").unwrap(),
                    sub: issuerd_core::UserId::new("stub-user").unwrap(),
                    aud: Audience::new("aud").unwrap(),
                    exp: 9999999999,
                    iat: 0,
                    auth_time: Some(auth_time.timestamp()),
                    nonce: None,
                    acr: None,
                    amr: None,
                    azp: None,
                    sid: None,
                    at_hash: None,
                    c_hash: None,
                    name: None,
                    given_name: None,
                    family_name: None,
                    preferred_username: None,
                    email: None,
                    email_verified: None,
                    address: None,
                    phone_number: None,
                    phone_number_verified: None,
                    realm_access: None,
                    resource_access: None,
                },
            })
        }

        async fn issue_logout_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &issuerd_core::Realm,
            _session_id: &issuerd_core::SessionId,
        ) -> Result<issuerd_core::LogoutToken, issuerd_core::IssuerdError> {
            unimplemented!("stub does not issue logout tokens")
        }

        async fn sign_authorization_response(
            &self,
            _realm: &issuerd_core::Realm,
            _client_id: &str,
            _params: &[(String, String)],
        ) -> Result<String, issuerd_core::IssuerdError> {
            unimplemented!("stub does not sign authorization responses")
        }
    }
}
