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
//! Each delivery (success or failure) is recorded as an admin event.
//!
//! **Front-channel:** the RP-initiated logout endpoint renders an
//! interstitial page embedding a hidden iframe per client session whose
//! client configured a `frontchannel_logout_uri` attribute (called with the
//! `iss` and `sid` query parameters per OIDC Front-Channel Logout 1.0), then
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
    http: reqwest::Client,
}

impl BackchannelLogoutDispatcher {
    pub fn new(
        storage: Arc<dyn Storage>,
        token_manager: Arc<dyn TokenIssuer>,
    ) -> Result<Self, IssuerdError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(BACKCHANNEL_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                IssuerdError::ServerError(format!("backchannel logout http client: {e}"))
            })?;
        Ok(Self {
            storage,
            token_manager,
            http,
        })
    }

    /// POST the logout token with one retry; returns the final error, if any.
    async fn post_logout_token(&self, uri: &str, token: &str) -> Result<(), String> {
        for attempt in 1..=2 {
            match self.http.post(uri).form(&[("logout_token", token)]).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    debug!(
                        attempt,
                        status = %resp.status(),
                        uri, "backchannel logout delivery rejected"
                    );
                    if attempt == 2 {
                        return Err(format!("http status {}", resp.status()));
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
            let token = match self
                .token_manager
                .issue_logout_token(&user, &client, realm, &session.id)
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
/// `frontchannel_logout_uri`, called with `iss` + `sid` query parameters.
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
            urls.push(super::oidc::build_redirect_url(
                uri,
                &[("iss", issuer), ("sid", &session.id.0)],
                false,
            ));
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
    format!("{}/realms/{}", issuer_base.trim_end_matches('/'), realm_name)
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
            _session_id: &SessionId,
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
            BackchannelLogoutDispatcher::new(storage.clone(), Arc::new(FailingTokenIssuer))
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
}
