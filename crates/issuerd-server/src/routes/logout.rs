// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! OIDC back-channel and front-channel logout.
//!
//! **Back-channel:** whenever a user session is destroyed — the RP-initiated
//! logout endpoint, the SPA logout API, the account-console session logout,
//! or an admin session deletion — every client session registered on that
//! session whose client configured a `backchannel_logout_uri` attribute
//! receives a signed logout token (`logout_token=<jwt>`,
//! `application/x-www-form-urlencoded`). Delivery is fire-and-forget with a
//! short timeout and one retry; it never blocks or fails the user's logout.
//! Calls require HTTPS and publicly routable addresses, with redirects disabled
//! and DNS validation pinned to the connection. The operator can explicitly
//! allow private callbacks with `[outbound_http] allow_private_addresses`.
//! Each delivery (success or failure) is recorded as an admin event.
//!
//! **Front-channel:** the RP-initiated logout endpoint renders an
//! interstitial page embedding a hidden iframe per client session whose
//! client configured a `frontchannel_logout_uri` attribute (called with the
//! `iss` and `sid` query parameters per OIDC Front-Channel Logout 1.0, unless
//! the client registered `frontchannel_logout_session_required = false`), then
//! continues to the validated `post_logout_redirect_uri`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::response::{IntoResponse, Response};
use tracing::{debug, error, warn};

use issuerd_core::{
    AdminEvent, EventId, IssuerdError, OperationType, Realm, RealmId, ResourceType, SessionId,
    SessionLogoutNotifier, Storage, UserSession,
};
use issuerd_token::token_manager::TokenIssuer;

/// Client attribute carrying the back-channel logout URI.
pub const CLIENT_ATTR_BACKCHANNEL_LOGOUT_URI: &str = "backchannel_logout_uri";

/// Client attribute carrying the front-channel logout URI.
pub const CLIENT_ATTR_FRONTCHANNEL_LOGOUT_URI: &str = "frontchannel_logout_uri";

/// Per-attempt HTTP timeout for back-channel delivery.
const BACKCHANNEL_TIMEOUT_SECS: u64 = 5;

/// Delivers back-channel logout tokens to clients on session teardown.
///
/// Held behind `Arc<dyn SessionLogoutNotifier>` in `ServerState` (and injected
/// into the admin API) so every session-teardown path shares one dispatcher.
pub struct BackchannelLogoutDispatcher {
    storage: Arc<dyn Storage>,
    token_manager: Arc<dyn TokenIssuer>,
    http: crate::broker::SsrfGuardedClient,
}

impl BackchannelLogoutDispatcher {
    pub fn new(
        storage: Arc<dyn Storage>,
        token_manager: Arc<dyn TokenIssuer>,
        extra_roots: &[reqwest::Certificate],
    ) -> Result<Self, IssuerdError> {
        Self::new_with_policy(storage, token_manager, extra_roots, false)
    }

    /// Build the dispatcher with an explicit guarded-address policy. HTTPS and
    /// redirect rejection always apply; non-public addresses require the
    /// explicit `[outbound_http] allow_private_addresses` opt-in.
    pub fn new_with_policy(
        storage: Arc<dyn Storage>,
        token_manager: Arc<dyn TokenIssuer>,
        extra_roots: &[reqwest::Certificate],
        allow_private_addresses: bool,
    ) -> Result<Self, IssuerdError> {
        let http = crate::broker::SsrfGuardedClient::new(
            extra_roots,
            allow_private_addresses,
            Duration::from_secs(BACKCHANNEL_TIMEOUT_SECS),
        )
        .map_err(|e| IssuerdError::ServerError(format!("backchannel logout http client: {e}")))?;
        Ok(Self {
            storage,
            token_manager,
            http,
        })
    }

    /// POST the logout token with one retry; returns the final error, if any.
    async fn post_logout_token(&self, uri: &str, token: &str) -> Result<(), String> {
        for attempt in 1..=2 {
            match self.http.post_form(uri, &[("logout_token", token)]).await {
                Ok(status) if status.is_success() => return Ok(()),
                Ok(status) => {
                    debug!(
                        attempt,
                        %status,
                        uri, "backchannel logout delivery rejected"
                    );
                    if attempt == 2 {
                        return Err(format!("http status {status}"));
                    }
                }
                Err(e) => {
                    debug!(attempt, error = %e, uri, "backchannel logout delivery failed");
                    if attempt == 2 {
                        return Err(e.to_string());
                    }
                }
            }
        }
        unreachable!("loop returns on the final attempt")
    }

    /// Record the delivery outcome as a system-initiated admin event.
    ///
    /// Admin-event gating: skipped entirely when the realm has
    /// `admin_events_enabled = false` (Issuerd default: on — Keycloak parity
    /// break; Keycloak defaults to off). The realm is always
    /// already loaded on the wired dispatch paths, so there is no fetch to
    /// fail open on.
    async fn record(
        &self,
        realm: &Realm,
        session_id: &SessionId,
        client_name: &str,
        error: Option<String>,
    ) {
        if !realm.admin_events_enabled {
            return;
        }
        let event = AdminEvent {
            id: EventId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm.id.clone(),
            auth_realm_id: None,
            auth_client_id: None,
            auth_user_id: None,
            operation_type: OperationType::Action,
            resource_type: ResourceType::Session,
            resource_path: format!("backchannel-logout/{client_name}"),
            representation: Some(format!("session={session_id}")),
            error,
            event_time: chrono::Utc::now(),
        };
        let _ = self.storage.save_admin_event(&event).await;
    }

    /// Deliver back-channel logout tokens for every client session of
    /// `session`. Best-effort: individual failures are logged and recorded
    /// but never propagated.
    pub async fn dispatch(&self, realm: &Realm, session: &UserSession) {
        // The logout token carries `sub`, so the user row must still exist
        // (it always does on the wired teardown paths; user deletion cascades
        // sessions before any notification could be sent).
        let user = match self.storage.get_user(&realm.id, &session.user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                debug!(
                    realm = %realm.id,
                    session_id = %session.id,
                    "backchannel logout skipped: user no longer exists"
                );
                return;
            }
            Err(e) => {
                warn!(realm = %realm.id, error = %e, "backchannel logout: user lookup failed");
                return;
            }
        };

        for client_session in &session.clients {
            let client = match self.storage.get_client(&realm.id, &client_session.client_id).await {
                Ok(Some(c)) => c,
                Ok(None) => continue,
                Err(e) => {
                    warn!(realm = %realm.id, error = %e, "backchannel logout: client lookup failed");
                    continue;
                }
            };
            let Some(uri) = client
                .attributes
                .get(CLIENT_ATTR_BACKCHANNEL_LOGOUT_URI)
                .filter(|u| !u.is_empty())
            else {
                continue;
            };
            // OIDC Back-Channel Logout 1.0 §2.4: clients registered with
            // `backchannel_logout_session_required = false` get a logout
            // token WITHOUT `sid` (it correlates by `sub` alone, which is
            // always present).
            let include_sid = crate::client_metadata::backchannel_logout_session_required(&client);
            let token = match self
                .token_manager
                .issue_logout_token(&user, &client, realm, include_sid.then_some(&session.id))
                .await
            {
                Ok(t) => t.token,
                Err(e) => {
                    error!(realm = %realm.id, client_id = %client.client_id, error = %e, "backchannel logout: token issuance failed");
                    self.record(
                        realm,
                        &session.id,
                        client.client_id.as_ref(),
                        Some(format!("token issuance failed: {e}")),
                    )
                    .await;
                    continue;
                }
            };
            let result = self.post_logout_token(uri, &token).await;
            if let Err(ref e) = result {
                warn!(
                    realm = %realm.id,
                    client_id = %client.client_id,
                    uri,
                    error = %e,
                    "backchannel logout delivery failed"
                );
            }
            self.record(realm, &session.id, client.client_id.as_ref(), result.err()).await;
        }
    }
}

#[async_trait]
impl SessionLogoutNotifier for BackchannelLogoutDispatcher {
    /// Fire-and-forget: the caller's logout path never waits on delivery.
    async fn notify_session_destroyed(&self, realm: &Realm, session: &UserSession) {
        if session.clients.is_empty() {
            return;
        }
        let dispatcher = Self {
            storage: self.storage.clone(),
            token_manager: self.token_manager.clone(),
            http: self.http.clone(),
        };
        let realm = realm.clone();
        let session = session.clone();
        tokio::spawn(async move { dispatcher.dispatch(&realm, &session).await });
    }
}

/// Collect the front-channel logout iframe URLs for a session being torn
/// down: one per client session whose client configured
/// `frontchannel_logout_uri`. The URL is called with the `iss` + `sid` query
/// parameters unless the client registered
/// `frontchannel_logout_session_required = false` (OIDC Front-Channel Logout
/// 1.0 §2), in which case the bare URI is used.
///
/// `issuer` must be the token issuer URL for the realm
/// (`{issuer_url}/realms/{realm_name}`) so RPs can match it against token
/// `iss`.
pub async fn frontchannel_logout_urls(
    storage: &Arc<dyn Storage>,
    realm_id: &RealmId,
    issuer: &str,
    session: &UserSession,
) -> Vec<String> {
    let mut urls = Vec::new();
    for client_session in &session.clients {
        let client = match storage.get_client(realm_id, &client_session.client_id).await {
            Ok(Some(c)) => c,
            _ => continue,
        };
        if let Some(uri) = client
            .attributes
            .get(CLIENT_ATTR_FRONTCHANNEL_LOGOUT_URI)
            .filter(|u| !u.is_empty())
        {
            if crate::client_metadata::frontchannel_logout_session_required(&client) {
                urls.push(super::oidc::build_redirect_url(
                    uri,
                    &[("iss", issuer), ("sid", &session.id.0)],
                    false,
                ));
            } else {
                urls.push(uri.clone());
            }
        }
    }
    urls
}

/// Render the front-channel logout interstitial: a hidden iframe per client
/// session, then an automatic continuation to `continue_url` (the validated
/// post-logout redirect target) once the iframes had a moment to load. When
/// there is no redirect target the page itself confirms the sign-out.
pub fn frontchannel_logout_page(continue_url: Option<&str>, iframe_urls: &[String]) -> Response {
    let mut body = String::from("<h1>Signing you out</h1>");
    body.push_str("<p>You have been signed out.</p>");
    for url in iframe_urls {
        body.push_str(&format!(
            "<iframe src=\"{}\" style=\"display:none\" title=\"logout\"></iframe>",
            crate::email::html_escape(url)
        ));
    }
    if let Some(target) = continue_url {
        // The JSON string literal doubles as a safe JS string; `<` is escaped
        // so a crafted URL cannot break out of the inline script.
        let js_target = serde_json::to_string(target)
            .unwrap_or_else(|_| "\"\"".to_string())
            .replace('<', "\\u003c");
        let escaped = crate::email::html_escape(target);
        body.push_str(&format!(
            "<p><a href=\"{escaped}\">Continue</a></p>\
             <script>setTimeout(function(){{window.location.replace({js_target});}},1500);</script>\
             <noscript><meta http-equiv=\"refresh\" content=\"3;url={escaped}\"></noscript>"
        ));
    }
    super::required_actions::page("Sign-out", &body, crate::i18n::DEFAULT_LOCALE).into_response()
}

/// The token issuer URL for a realm — must match `iss` in issued tokens
/// (`TokenManager::issuer_for_realm`). Issuers are realm-NAME based.
pub fn issuer_for_realm(issuer_base: &str, realm_name: &str) -> String {
    issuerd_core::urls::RealmUrlBuilder::new(issuer_base, realm_name)
        .expect("the configured base URL and a valid realm name form a canonical issuer")
        .issuer()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{
        AdminEventQuery, AuthMethod, Client, ClientAuthenticatorType, ClientId, ClientIdentifier,
        ClientProtocol, ClientSession, ClientSessionId, Pagination, Scope, User, UserId, Username,
    };
    use issuerd_storage::InMemoryStorage;
    use issuerd_token::{AccessToken, IdToken, RefreshToken, TokenIssuer};
    use std::collections::HashMap;

    /// TokenIssuer double whose every method fails: `dispatch` then records
    /// the token-issuance failure for each client it selects, so the test
    /// observes the client-selection decision without any network I/O.
    struct FailingTokenIssuer;

    #[async_trait]
    impl TokenIssuer for FailingTokenIssuer {
        async fn issue_access_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            _scope: &[String],
            _session_id: &SessionId,
        ) -> Result<AccessToken, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn issue_access_token_with_roles(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            _scope: &[String],
            _session_id: &SessionId,
            _realm_access: Option<issuerd_core::RealmAccess>,
            _claims: Option<serde_json::Value>,
            _claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<AccessToken, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn issue_refresh_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            _session_id: &SessionId,
            _scope: &[String],
            _offline: bool,
            _dpop_jkt: Option<&str>,
            _authorization_details: Option<&[serde_json::Value]>,
        ) -> Result<RefreshToken, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn issue_id_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            _nonce: Option<&str>,
            _auth_time: chrono::DateTime<chrono::Utc>,
            _session_id: &SessionId,
            _access_token: Option<&AccessToken>,
            _code: Option<&str>,
            _acr_values: Option<&[String]>,
            _claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<IdToken, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn issue_logout_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            _session_id: Option<&SessionId>,
        ) -> Result<issuerd_core::LogoutToken, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn sign_authorization_response(
            &self,
            _realm: &Realm,
            _client_id: &str,
            _params: &[(String, String)],
        ) -> Result<String, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn sign_userinfo_response(
            &self,
            _client: &Client,
            _realm: &Realm,
            _claims: &serde_json::Map<String, serde_json::Value>,
            _alg: issuerd_core::Algorithm,
        ) -> Result<String, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }
    }

    fn client(uuid: &str, identifier: &str, backchannel_uri: Option<&str>) -> Client {
        let mut attributes = HashMap::new();
        if let Some(uri) = backchannel_uri {
            attributes.insert(CLIENT_ATTR_BACKCHANNEL_LOGOUT_URI.to_string(), uri.to_string());
        }
        Client {
            id: ClientId::new(uuid).unwrap(),
            realm_id: RealmId::new("master").unwrap(),
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
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes,
        }
    }

    #[tokio::test]
    async fn dispatch_skips_clients_without_a_configured_backchannel_uri() {
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
        let realm = Realm {
            id: RealmId::new("master").unwrap(),
            ..Default::default()
        };
        let user = User {
            id: UserId::new("u-1").unwrap(),
            realm_id: realm.id.clone(),
            username: Username::new("alice").unwrap(),
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
        };
        storage.create_user(&realm.id, &user).await.unwrap();

        let empty_uri = client("c-empty", "empty-uri-client", Some(""));
        let configured =
            client("c-conf", "configured-client", Some("http://client.example.com/logout"));
        let unset = client("c-unset", "unset-client", None);
        for c in [&empty_uri, &configured, &unset] {
            storage.create_client(&realm.id, c).await.unwrap();
        }

        let session_id = SessionId::new("sess-1").unwrap();
        let client_session = |c: &Client| ClientSession {
            id: ClientSessionId::new(issuerd_core::utils::generate_id()).unwrap(),
            client_id: c.id.clone(),
            session_id: session_id.clone(),
            redirect_uri: None,
            state: None,
            auth_method: AuthMethod::Password,
            timestamp: chrono::Utc::now(),
        };
        let session = UserSession {
            id: session_id.clone(),
            realm_id: realm.id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: chrono::Utc::now(),
            last_session_refresh: chrono::Utc::now(),
            auth_time: chrono::Utc::now(),
            impersonator: None,
            clients: vec![
                client_session(&empty_uri),
                client_session(&configured),
                client_session(&unset),
            ],
        };

        let dispatcher =
            BackchannelLogoutDispatcher::new(storage.clone(), Arc::new(FailingTokenIssuer), &[])
                .unwrap();
        dispatcher.dispatch(&realm, &session).await;

        let events = storage
            .query_admin_events(
                &realm.id,
                &AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            events.len(),
            1,
            "only the client with a non-empty backchannel_logout_uri may be dispatched to: {events:?}"
        );
        assert_eq!(events[0].resource_path, "backchannel-logout/configured-client");
        assert!(
            events[0].error.as_deref().unwrap_or("").contains("token issuance failed"),
            "the configured client must reach logout-token issuance: {events:?}"
        );
    }

    /// TokenIssuer double recording whether each `issue_logout_token` call
    /// carried a session id, so tests can assert the
    /// `backchannel_logout_session_required` wiring without network I/O.
    struct SidRecordingTokenIssuer {
        calls: Arc<std::sync::Mutex<Vec<bool>>>,
    }

    #[async_trait]
    impl TokenIssuer for SidRecordingTokenIssuer {
        async fn issue_access_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            _scope: &[String],
            _session_id: &SessionId,
        ) -> Result<AccessToken, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn issue_access_token_with_roles(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            _scope: &[String],
            _session_id: &SessionId,
            _realm_access: Option<issuerd_core::RealmAccess>,
            _claims: Option<serde_json::Value>,
            _claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<AccessToken, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn issue_refresh_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            _session_id: &SessionId,
            _scope: &[String],
            _offline: bool,
            _dpop_jkt: Option<&str>,
            _authorization_details: Option<&[serde_json::Value]>,
        ) -> Result<RefreshToken, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn issue_id_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            _nonce: Option<&str>,
            _auth_time: chrono::DateTime<chrono::Utc>,
            _session_id: &SessionId,
            _access_token: Option<&AccessToken>,
            _code: Option<&str>,
            _acr_values: Option<&[String]>,
            _claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<IdToken, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn issue_logout_token(
            &self,
            _user: &issuerd_core::User,
            _client: &Client,
            _realm: &Realm,
            session_id: Option<&SessionId>,
        ) -> Result<issuerd_core::LogoutToken, IssuerdError> {
            self.calls.lock().unwrap().push(session_id.is_some());
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn sign_authorization_response(
            &self,
            _realm: &Realm,
            _client_id: &str,
            _params: &[(String, String)],
        ) -> Result<String, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }

        async fn sign_userinfo_response(
            &self,
            _client: &Client,
            _realm: &Realm,
            _claims: &serde_json::Map<String, serde_json::Value>,
            _alg: issuerd_core::Algorithm,
        ) -> Result<String, IssuerdError> {
            Err(IssuerdError::ServerError("mock".into()))
        }
    }

    fn user(realm_id: &RealmId) -> User {
        User {
            id: UserId::new("u-1").unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("alice").unwrap(),
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

    fn session_for(realm_id: &RealmId, user: &User, clients: &[&Client]) -> UserSession {
        let session_id = SessionId::new("sess-1").unwrap();
        UserSession {
            id: session_id.clone(),
            realm_id: realm_id.clone(),
            user_id: user.id.clone(),
            login_username: user.username.clone(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            ip_address: "127.0.0.1".parse().unwrap(),
            started: chrono::Utc::now(),
            last_session_refresh: chrono::Utc::now(),
            auth_time: chrono::Utc::now(),
            impersonator: None,
            clients: clients
                .iter()
                .map(|c| ClientSession {
                    id: ClientSessionId::new(issuerd_core::utils::generate_id()).unwrap(),
                    client_id: c.id.clone(),
                    session_id: session_id.clone(),
                    redirect_uri: None,
                    state: None,
                    auth_method: AuthMethod::Password,
                    timestamp: chrono::Utc::now(),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn dispatch_omits_sid_when_backchannel_session_not_required() {
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
        let realm = Realm {
            id: RealmId::new("master").unwrap(),
            ..Default::default()
        };
        let user = user(&realm.id);
        storage.create_user(&realm.id, &user).await.unwrap();

        let default_client =
            client("c-default", "default-client", Some("http://client.example.com/logout"));
        let mut opted_out =
            client("c-opted-out", "opted-out-client", Some("http://client.example.com/logout"));
        opted_out.attributes.insert(
            crate::client_metadata::ATTR_BACKCHANNEL_LOGOUT_SESSION_REQUIRED.to_string(),
            "false".to_string(),
        );
        for c in [&default_client, &opted_out] {
            storage.create_client(&realm.id, c).await.unwrap();
        }
        let session = session_for(&realm.id, &user, &[&default_client, &opted_out]);

        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let issuer = SidRecordingTokenIssuer {
            calls: Arc::clone(&calls),
        };
        let dispatcher =
            BackchannelLogoutDispatcher::new(storage.clone(), Arc::new(issuer), &[]).unwrap();
        dispatcher.dispatch(&realm, &session).await;

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 2, "both configured clients are dispatched to");
        let default_call = recorded[0];
        let opted_out_call = recorded[1];
        assert!(default_call, "default client keeps the sid claim");
        assert!(!opted_out_call, "opted-out client's logout token omits sid");
    }

    #[tokio::test]
    async fn frontchannel_urls_omit_iss_and_sid_when_session_not_required() {
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
        let realm_id = RealmId::new("master").unwrap();

        let mut default_client = client("c-fc-default", "fc-default-client", None);
        default_client.attributes.insert(
            CLIENT_ATTR_FRONTCHANNEL_LOGOUT_URI.to_string(),
            "https://client.example.com/fc-logout".to_string(),
        );
        let mut opted_out = client("c-fc-opted-out", "fc-opted-out-client", None);
        opted_out.attributes.insert(
            CLIENT_ATTR_FRONTCHANNEL_LOGOUT_URI.to_string(),
            "https://client.example.com/fc-plain".to_string(),
        );
        opted_out.attributes.insert(
            crate::client_metadata::ATTR_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED.to_string(),
            "false".to_string(),
        );
        for c in [&default_client, &opted_out] {
            storage.create_client(&realm_id, c).await.unwrap();
        }
        let user = user(&realm_id);
        let session = session_for(&realm_id, &user, &[&default_client, &opted_out]);

        let urls = frontchannel_logout_urls(
            &storage,
            &realm_id,
            "https://issuer.example.com/realms/master",
            &session,
        )
        .await;

        assert_eq!(urls.len(), 2);
        let with_session = urls
            .iter()
            .find(|u| u.starts_with("https://client.example.com/fc-logout"))
            .expect("default client URL");
        assert!(
            with_session.starts_with("https://client.example.com/fc-logout?iss="),
            "default client keeps iss+sid: {with_session}"
        );
        assert!(with_session.contains("&sid=sess-1"), "sid appended: {with_session}");
        let bare = urls
            .iter()
            .find(|u| u.starts_with("https://client.example.com/fc-plain"))
            .expect("opted-out client URL");
        assert_eq!(
            bare, "https://client.example.com/fc-plain",
            "opted-out client is called with the bare URI"
        );
    }

    #[derive(Clone, Debug)]
    struct RecordedLogoutRequest {
        method: String,
        path: String,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    #[derive(Clone, Default)]
    struct LogoutRecorder {
        requests: Arc<std::sync::Mutex<Vec<RecordedLogoutRequest>>>,
    }

    impl LogoutRecorder {
        fn snapshot(&self) -> Vec<RecordedLogoutRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    async fn record_logout_request(
        axum::extract::State(recorder): axum::extract::State<LogoutRecorder>,
        request: axum::extract::Request,
    ) -> Response {
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let content_type = request
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = axum::body::to_bytes(request.into_body(), 64 * 1024).await.unwrap().to_vec();
        recorder.requests.lock().unwrap().push(RecordedLogoutRequest {
            method,
            path: path.clone(),
            content_type,
            body,
        });
        if path == "/redirect" {
            (
                axum::http::StatusCode::TEMPORARY_REDIRECT,
                [(axum::http::header::LOCATION, "/target")],
            )
                .into_response()
        } else {
            axum::http::StatusCode::NO_CONTENT.into_response()
        }
    }

    async fn start_loopback_tls_logout() -> (String, reqwest::Certificate, LogoutRecorder) {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "issuerd logout test CA");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_cert =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
                .unwrap()
                .signed_by(&server_key, &ca_cert)
                .unwrap();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            server_cert.pem().into_bytes(),
            server_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();

        let recorder = LogoutRecorder::default();
        let app = axum::Router::new().fallback(record_logout_request).with_state(recorder.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        let root = reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).unwrap();
        (format!("https://127.0.0.1:{port}"), root, recorder)
    }

    fn delivery_dispatcher(
        roots: Vec<reqwest::Certificate>,
        allow_private_addresses: bool,
    ) -> BackchannelLogoutDispatcher {
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
        BackchannelLogoutDispatcher::new_with_policy(
            storage,
            Arc::new(FailingTokenIssuer),
            &roots,
            allow_private_addresses,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn backchannel_rejects_plain_http_even_with_private_opt_in() {
        let (base, root, recorder) = start_loopback_tls_logout().await;
        let uri = format!("{}/logout", base.replacen("https:", "http:", 1));
        let dispatcher = delivery_dispatcher(vec![root], true);

        let err = dispatcher.post_logout_token(&uri, "token").await.unwrap_err();

        assert!(err.contains("untrusted URL"), "{err}");
        assert!(recorder.snapshot().is_empty(), "plain HTTP must not be dialed");
    }

    #[tokio::test]
    async fn backchannel_rejects_loopback_before_connecting_by_default() {
        let (base, root, recorder) = start_loopback_tls_logout().await;
        let dispatcher = delivery_dispatcher(vec![root], false);

        let err = dispatcher
            .post_logout_token(&format!("{base}/logout"), "token")
            .await
            .unwrap_err();

        assert!(err.contains("untrusted URL"), "{err}");
        assert!(recorder.snapshot().is_empty(), "loopback must not be dialed");
    }

    #[tokio::test]
    async fn backchannel_rejects_loopback_hostnames_before_connecting() {
        let (base, root, recorder) = start_loopback_tls_logout().await;
        let dispatcher = delivery_dispatcher(vec![root], false);
        let uri = format!("{}/logout", base.replace("127.0.0.1", "localhost"));

        let err = dispatcher.post_logout_token(&uri, "token").await.unwrap_err();

        assert!(err.contains("untrusted URL"), "{err}");
        assert!(
            recorder.snapshot().is_empty(),
            "a hostname resolving to loopback must not be dialed"
        );
    }

    #[tokio::test]
    async fn backchannel_rejects_private_and_link_local_literals() {
        let dispatcher = delivery_dispatcher(Vec::new(), false);
        for uri in [
            "https://10.0.0.5/logout",
            "https://192.168.1.10/logout",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/logout",
        ] {
            let err = dispatcher.post_logout_token(uri, "token").await.unwrap_err();
            assert!(err.contains("untrusted URL"), "{uri}: {err}");
        }
    }

    #[tokio::test]
    async fn backchannel_does_not_follow_redirects() {
        let (base, root, recorder) = start_loopback_tls_logout().await;
        let dispatcher = delivery_dispatcher(vec![root], true);

        let err = dispatcher
            .post_logout_token(&format!("{base}/redirect"), "token")
            .await
            .unwrap_err();

        assert!(err.contains("untrusted URL"), "{err}");
        let requests = recorder.snapshot();
        assert_eq!(requests.len(), 2, "the original request keeps its one retry");
        assert!(requests.iter().all(|request| request.path == "/redirect"));
    }

    #[tokio::test]
    async fn backchannel_private_opt_in_delivers_form_over_https() {
        let (base, root, recorder) = start_loopback_tls_logout().await;
        let dispatcher = delivery_dispatcher(vec![root], true);
        let token = "header.payload+/=&";

        dispatcher.post_logout_token(&format!("{base}/logout"), token).await.unwrap();

        let requests = recorder.snapshot();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/logout");
        assert_eq!(request.content_type.as_deref(), Some("application/x-www-form-urlencoded"));
        let form: HashMap<String, String> = serde_urlencoded::from_bytes(&request.body).unwrap();
        assert_eq!(form.get("logout_token").map(String::as_str), Some(token));
    }
}
