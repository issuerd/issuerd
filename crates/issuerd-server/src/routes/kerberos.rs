// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// SPNEGO / Kerberos negotiate endpoint.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use issuerd_core::{AuthMethod, EventType, User, UserId, Username};

use crate::{
    middleware::{proxy_ip::ClientIp, realm::ResolvedRealm},
    state::ServerState,
};

use super::oidc::emit_oidc_event;

/// SPNEGO / Kerberos endpoint.
///
/// Returns:
/// - `401` + `WWW-Authenticate: Negotiate` when no `Authorization` header is present.
/// - `401` + `WWW-Authenticate: Negotiate {token}` when SPNEGO requires another round-trip.
/// - Redirect with auth code on successful authentication.
#[tracing::instrument(skip(state, ip, headers, params))]
pub async fn handle_spnego(
    State(state): State<Arc<ServerState>>,
    axum::extract::Extension(ResolvedRealm(realm)): axum::extract::Extension<ResolvedRealm>,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let realm_name = match realm.as_deref() {
        Some(r) => r,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "missing realm"})),
            )
                .into_response();
        }
    };
    // Resolve the realm by name so storage queries use the canonical realm ID
    // (realm IDs may be UUIDs while URLs carry the human-readable name).
    let realm = match state.resolve_realm(realm_name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "invalid_realm"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "kerberos realm resolution failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "server_error"})),
            )
                .into_response();
        }
    };
    let realm_id = realm.id.clone();

    let token = match headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Negotiate "))
    {
        Some(t) if !t.is_empty() => t,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Negotiate")],
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };

    let providers = match state.federation_manager.providers_for_realm(&realm_id).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "federation manager error");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({"error": "temporarily_unavailable"})),
            )
                .into_response();
        }
    };

    for provider in providers {
        if provider.provider_type() != issuerd_core::FederationProviderType::Kerberos {
            continue;
        }

        match provider.authenticate_spnego(token).await {
            Ok(issuerd_core::SpnegoAuthResult {
                status: issuerd_core::SpnegoStatus::Authenticated,
                principal: Some(principal),
                ..
            }) => {
                let principal_clone = principal.clone();
                let username_raw = principal
                    .split_once('@')
                    .map(|(u, _)| u.to_string())
                    .unwrap_or_else(|| principal.clone());
                let username = match Username::new(&username_raw) {
                    Ok(u) => u,
                    Err(_) => {
                        tracing::warn!(
                            username = %issuerd_core::utils::sanitize_log_str(&username_raw),
                            "kerberos principal maps to invalid username"
                        );
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({"error": "invalid_principal"})),
                        )
                            .into_response();
                    }
                };

                // Validate client + redirect target BEFORE touching the user
                // store: an unvalidated redirect_uri would turn this
                // interaction-free endpoint into a code-delivery oracle.
                let client_id_str = match params.get("client_id").filter(|s| !s.is_empty()) {
                    Some(c) => c.clone(),
                    None => {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({
                                "error": "invalid_request",
                                "error_description": "missing client_id"
                            })),
                        )
                            .into_response();
                    }
                };
                let client_identifier = match issuerd_core::ClientIdentifier::new(&client_id_str) {
                    Ok(c) => c,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({
                                "error": "invalid_request",
                                "error_description": "invalid client_id"
                            })),
                        )
                            .into_response();
                    }
                };
                let client = match state
                    .storage
                    .get_client_by_client_id(&realm_id, &client_identifier)
                    .await
                {
                    Ok(Some(c)) if c.enabled => c,
                    Ok(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({
                                "error": "invalid_client",
                                "error_description": "unknown or disabled client"
                            })),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(serde_json::json!({"error": e.to_string()})),
                        )
                            .into_response();
                    }
                };
                let redirect_uri_str = match params.get("redirect_uri").filter(|s| !s.is_empty()) {
                    Some(r) => r.clone(),
                    None => {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({
                                "error": "invalid_request",
                                "error_description": "missing redirect_uri"
                            })),
                        )
                            .into_response();
                    }
                };
                let redirect_uri = match issuerd_core::RedirectUri::new(&redirect_uri_str) {
                    Ok(r) => r,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({
                                "error": "invalid_request",
                                "error_description": "invalid redirect_uri"
                            })),
                        )
                            .into_response();
                    }
                };
                // Same redirect-URI matching rule as the authorization
                // endpoint (exact or trailing-`*` wildcard), plus no fragment.
                let has_fragment = url::Url::parse(redirect_uri.as_str())
                    .map(|u| u.fragment().is_some())
                    .unwrap_or(true);
                if !client.redirect_uris.iter().any(|r| r.matches(&redirect_uri)) || has_fragment {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({
                            "error": "invalid_request",
                            "error_description": "redirect_uri not registered"
                        })),
                    )
                        .into_response();
                }
                // Scope: every requested scope must be available to the client.
                let scope = params.get("scope").cloned().unwrap_or_else(|| "openid".to_string());
                let requested_scopes: Vec<String> =
                    scope.split_whitespace().map(str::to_string).collect();
                let available_scopes: std::collections::HashSet<&String> =
                    client.default_scopes.iter().chain(client.optional_scopes.iter()).collect();
                if requested_scopes.iter().any(|s| !available_scopes.contains(s)) {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({
                            "error": "invalid_scope",
                            "error_description": "requested scope not available for client"
                        })),
                    )
                        .into_response();
                }
                // Public clients must bind the code with PKCE, same as /auth.
                if client.public_client && !params.contains_key("code_challenge") {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({
                            "error": "invalid_request",
                            "error_description": "code_challenge required for public clients"
                        })),
                    )
                        .into_response();
                }

                // Find or create user
                let user = match state
                    .storage
                    .get_user_by_username(&realm_id, username.as_str())
                    .await
                {
                    Ok(Some(u)) => u,
                    Ok(None) => {
                        let new_user = User {
                            id: UserId::new(issuerd_core::utils::generate_id()).unwrap(),
                            realm_id: realm_id.clone(),
                            username: username.clone(),
                            email: None,
                            email_verified: false,
                            first_name: None,
                            last_name: None,
                            enabled: true,
                            federation_link: Some(provider.id().to_string()),
                            attributes: {
                                let mut m = HashMap::new();
                                m.insert("KERBEROS_PRINCIPAL".to_string(), vec![principal_clone]);
                                m
                            },
                            required_actions: Vec::new(),
                            created_at: chrono::Utc::now(),
                            updated_at: chrono::Utc::now(),
                        };
                        if let Err(e) = state.storage.create_user(&realm_id, &new_user).await {
                            tracing::error!(error = %e, "failed to create kerberos user");
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({"error": "user_creation_failed"})),
                            )
                                .into_response();
                        }
                        new_user
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "storage error");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(serde_json::json!({"error": "server_error"})),
                        )
                            .into_response();
                    }
                };

                // Disabled users must not receive sessions or codes.
                if !user.enabled {
                    return (
                        StatusCode::UNAUTHORIZED,
                        [("WWW-Authenticate", "Negotiate")],
                        axum::Json(serde_json::json!({"error": "invalid_credentials"})),
                    )
                        .into_response();
                }

                let client_id = client.id.clone();
                let session_id =
                    issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
                let now = chrono::Utc::now();
                let session = issuerd_core::UserSession {
                    id: session_id.clone(),
                    realm_id: realm_id.clone(),
                    user_id: user.id.clone(),
                    login_username: user.username.clone(),
                    auth_method: AuthMethod::Spnego,
                    remember_me: false,
                    offline: false,
                    ip_address: ip,
                    started: now,
                    last_session_refresh: now,
                    auth_time: now,
                    impersonator: None,
                    clients: vec![issuerd_core::ClientSession {
                        id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id())
                            .unwrap(),
                        client_id: client_id.clone(),
                        session_id: session_id.clone(),
                        redirect_uri: Some(redirect_uri),
                        state: params.get("state").cloned(),
                        auth_method: AuthMethod::Spnego,
                        timestamp: now,
                    }],
                };
                if let Err(e) = state.storage.create_user_session(&realm_id, &session).await {
                    tracing::error!(error = %e, "failed to persist kerberos session");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(serde_json::json!({"error": "session_persistence_failed"})),
                    )
                        .into_response();
                }

                let code = issuerd_core::utils::generate_id();
                let code_data = super::oidc::AuthCodeData {
                    user_id: user.id.0.clone(),
                    client_id: client.client_id.to_string(),
                    redirect_uri: redirect_uri_str.clone(),
                    scope: requested_scopes.clone(),
                    state: params.get("state").cloned(),
                    nonce: params
                        .get("nonce")
                        .map(|s| issuerd_core::Nonce::new(s.clone()))
                        .transpose()
                        .ok()
                        .flatten(),
                    code_challenge: params
                        .get("code_challenge")
                        .map(|s| issuerd_core::Base64Url::new(s.clone()))
                        .transpose()
                        .ok()
                        .flatten(),
                    code_challenge_method: params
                        .get("code_challenge_method")
                        .map(|s| serde_json::from_value(serde_json::Value::String(s.clone())))
                        .transpose()
                        .ok()
                        .flatten(),
                    session_id: Some(session_id.0.clone()),
                    auth_time: Some(now),
                    acr_values: vec![],
                    claims: None,
                    authorization_details: None,
                };
                if let Err(e) = super::oidc::store_auth_code(
                    &state.cache,
                    &code,
                    &code_data,
                    state.config.oauth.auth_code_ttl(&realm),
                )
                .await
                {
                    tracing::error!(realm = %realm_id, client_id = %client.client_id, error = %e, "failed to persist authorization code");
                    let mut details = HashMap::new();
                    details.insert("error".to_string(), "temporarily_unavailable".to_string());
                    emit_oidc_event(
                        &state,
                        &realm_id,
                        EventType::LoginError,
                        &ip,
                        Some(client_id.clone()),
                        Some(user.id.clone()),
                        Some(session_id.clone()),
                        Some("temporarily_unavailable".to_string()),
                        details,
                    )
                    .await;
                    // Same response_mode handling as the success redirect
                    // below (RFC 6749 §4.1.2.1 — the redirect URI was
                    // validated above); JARM wraps error responses exactly
                    // like success responses.
                    let requested_mode = params.get("response_mode").and_then(|m| {
                        m.parse::<issuerd_protocol::authorization::ResponseMode>().ok()
                    });
                    if let Some(mode) = requested_mode {
                        if let Ok(Some(realm)) = state.storage.get_realm(&realm_id).await {
                            let packaging = super::auth_response::ResponsePackaging {
                                realm: &realm,
                                client_id: client.client_id.as_str(),
                                requested_mode: Some(mode),
                                default_fragment: false,
                            };
                            return super::auth_response::oauth_error_redirect(
                                &state,
                                &redirect_uri_str,
                                &issuerd_core::IssuerdError::TemporarilyUnavailable,
                                params.get("state").map(|s| s.as_str()),
                                &packaging,
                            )
                            .await;
                        }
                    }
                    let mut redirect_params: Vec<(&str, &str)> =
                        vec![("error", "temporarily_unavailable")];
                    if let Some(s) = params.get("state") {
                        redirect_params.push(("state", s.as_str()));
                    }
                    let url =
                        super::oidc::build_redirect_url(&redirect_uri_str, &redirect_params, false);
                    return (StatusCode::FOUND, [("Location", url)]).into_response();
                }

                let mut redirect_params: Vec<(&str, &str)> = vec![("code", code.as_str())];
                if let Some(s) = params.get("state") {
                    redirect_params.push(("state", s.as_str()));
                }

                let mut details = HashMap::new();
                details.insert("method".to_string(), "spnego".to_string());
                details.insert("username".to_string(), user.username.to_string());
                emit_oidc_event(
                    &state,
                    &realm_id,
                    EventType::Login,
                    &ip,
                    Some(client_id.clone()),
                    Some(user.id.clone()),
                    Some(session_id),
                    None,
                    details,
                )
                .await;

                // Honor an explicitly requested response_mode
                // (form_post / JARM); without one the code delivery stays a
                // plain query redirect. JARM signing needs the realm — on a
                // lookup failure fall back to the plain redirect rather than
                // failing the completed authentication.
                let requested_mode = params
                    .get("response_mode")
                    .and_then(|m| m.parse::<issuerd_protocol::authorization::ResponseMode>().ok());
                if let Some(mode) = requested_mode {
                    if let Ok(Some(realm)) = state.storage.get_realm(&realm_id).await {
                        let packaging = super::auth_response::ResponsePackaging {
                            realm: &realm,
                            client_id: client.client_id.as_str(),
                            requested_mode: Some(mode),
                            default_fragment: false,
                        };
                        return super::auth_response::authorization_response(
                            &state,
                            &redirect_uri_str,
                            &redirect_params,
                            &packaging,
                        )
                        .await;
                    }
                }

                let url =
                    super::oidc::build_redirect_url(&redirect_uri_str, &redirect_params, false);

                return (StatusCode::FOUND, [("Location", url)]).into_response();
            }
            Ok(issuerd_core::SpnegoAuthResult {
                status: issuerd_core::SpnegoStatus::Continue,
                response_token: Some(resp),
                ..
            }) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    [("WWW-Authenticate", format!("Negotiate {}", resp))],
                    axum::Json(serde_json::json!({"error": "authentication_challenge"})),
                )
                    .into_response();
            }
            Ok(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    [("WWW-Authenticate", "Negotiate")],
                    axum::Json(serde_json::json!({"error": "invalid_credentials"})),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::warn!(error = %e, "spnego provider error");
                continue;
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Negotiate")],
        axum::Json(serde_json::json!({"error": "invalid_credentials"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;

    struct MockKerberosProvider {
        result: Result<issuerd_core::SpnegoAuthResult, issuerd_core::FederationError>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationProvider for MockKerberosProvider {
        fn id(&self) -> &str {
            "mock-krb"
        }
        fn provider_type(&self) -> issuerd_core::FederationProviderType {
            issuerd_core::FederationProviderType::Kerberos
        }
        async fn find_user(
            &self,
            _username: &str,
        ) -> Result<Option<issuerd_core::FederatedUser>, issuerd_core::FederationError> {
            Ok(None)
        }
        async fn find_user_by_email(
            &self,
            _email: &str,
        ) -> Result<Option<issuerd_core::FederatedUser>, issuerd_core::FederationError> {
            Ok(None)
        }
        async fn validate_password(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<bool, issuerd_core::FederationError> {
            Ok(false)
        }
        async fn authenticate_spnego(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::SpnegoAuthResult, issuerd_core::FederationError> {
            self.result.clone()
        }
    }

    struct MockFederationManager {
        providers:
            Result<Vec<Arc<dyn issuerd_core::FederationProvider>>, issuerd_core::IssuerdError>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationManager for MockFederationManager {
        async fn providers_for_realm(
            &self,
            _realm_id: &issuerd_core::RealmId,
        ) -> Result<Vec<Arc<dyn issuerd_core::FederationProvider>>, issuerd_core::IssuerdError>
        {
            self.providers.clone()
        }
        async fn find_user(
            &self,
            _realm_id: &issuerd_core::RealmId,
            _username: &str,
        ) -> Result<
            Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
            issuerd_core::IssuerdError,
        > {
            Ok(None)
        }
        async fn find_user_by_email(
            &self,
            _realm_id: &issuerd_core::RealmId,
            _email: &str,
        ) -> Result<
            Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
            issuerd_core::IssuerdError,
        > {
            Ok(None)
        }
    }

    fn negotiate_headers(token: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Negotiate {token}")).unwrap(),
        );
        headers
    }

    fn query_with_redirect() -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("client_id".to_string(), "test-client".to_string());
        params.insert("redirect_uri".to_string(), "http://localhost/callback".to_string());
        params.insert("scope".to_string(), "openid".to_string());
        params.insert("state".to_string(), "xyz".to_string());
        params
    }

    async fn test_state_with_manager(
        mgr: Arc<dyn issuerd_core::FederationManager>,
    ) -> Arc<ServerState> {
        let cfg = crate::config::ServerConfig::default();
        let base = ServerState::from_config(&cfg).await.unwrap();
        Arc::new(ServerState {
            federation_manager: mgr,
            ..base.clone()
        })
    }

    /// Register the `test-client` used by `query_with_redirect` in the master
    /// realm, with its redirect URI and `openid` scope.
    async fn seed_test_client(state: &Arc<ServerState>) {
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            client_id: issuerd_core::ClientIdentifier::new("test-client").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: issuerd_core::ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
            secret: Some("test-secret".to_string()),
            redirect_uris: vec![
                issuerd_core::RedirectUri::new("http://localhost/callback").unwrap()
            ],
            web_origins: vec![],
            default_scopes: issuerd_core::Scope::parse("openid profile"),
            optional_scopes: issuerd_core::Scope::default(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        state.storage.create_client(&realm_id, &client).await.unwrap();
    }

    #[tokio::test]
    async fn spnego_endpoint_no_header_returns_401() {
        let cfg = crate::config::ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            axum::http::HeaderMap::new(),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let www_auth = response.headers().get("WWW-Authenticate").unwrap();
        assert_eq!(www_auth, "Negotiate");
    }

    #[tokio::test]
    async fn spnego_endpoint_bad_token_returns_401() {
        let cfg = crate::config::ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("badtoken"),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn spnego_endpoint_missing_realm_returns_400() {
        let cfg = crate::config::ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(None)),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn spnego_endpoint_federation_manager_error_returns_503() {
        let mgr = Arc::new(MockFederationManager {
            providers: Err(issuerd_core::IssuerdError::ServerError("federation down".into())),
        });
        let state = test_state_with_manager(mgr).await;

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn spnego_endpoint_authenticated_redirect() {
        let mgr = Arc::new(MockFederationManager {
            providers: Ok(vec![Arc::new(MockKerberosProvider {
                result: Ok(issuerd_core::SpnegoAuthResult {
                    status: issuerd_core::SpnegoStatus::Authenticated,
                    principal: Some("alice@EXAMPLE.COM".to_string()),
                    response_token: None,
                }),
            })]),
        });
        let state = test_state_with_manager(mgr).await;
        seed_test_client(&state).await;

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(query_with_redirect()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response.headers().get("Location").unwrap().to_str().unwrap();
        assert!(location.starts_with("http://localhost/callback?code="));
        assert!(location.contains("&state=xyz"));
    }

    #[tokio::test]
    async fn spnego_endpoint_continue_challenge() {
        let mgr = Arc::new(MockFederationManager {
            providers: Ok(vec![Arc::new(MockKerberosProvider {
                result: Ok(issuerd_core::SpnegoAuthResult {
                    status: issuerd_core::SpnegoStatus::Continue,
                    principal: None,
                    response_token: Some("resp123".to_string()),
                }),
            })]),
        });
        let state = test_state_with_manager(mgr).await;

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let www_auth = response.headers().get("WWW-Authenticate").unwrap().to_str().unwrap();
        assert_eq!(www_auth, "Negotiate resp123");
    }

    #[tokio::test]
    async fn spnego_endpoint_failed_status() {
        let mgr = Arc::new(MockFederationManager {
            providers: Ok(vec![Arc::new(MockKerberosProvider {
                result: Ok(issuerd_core::SpnegoAuthResult {
                    status: issuerd_core::SpnegoStatus::Failed,
                    principal: None,
                    response_token: None,
                }),
            })]),
        });
        let state = test_state_with_manager(mgr).await;

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn spnego_endpoint_provider_error_falls_through() {
        let mgr = Arc::new(MockFederationManager {
            providers: Ok(vec![Arc::new(MockKerberosProvider {
                result: Err(issuerd_core::FederationError::NetworkError("kdc down".into())),
            })]),
        });
        let state = test_state_with_manager(mgr).await;

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn spnego_endpoint_existing_user_redirect() {
        let cfg = crate::config::ServerConfig::default();
        let base = ServerState::from_config(&cfg).await.unwrap();
        // Pre-create the user so lookup succeeds.
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            username: issuerd_core::Username::new("alice").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: Some("mock-krb".to_string()),
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        base.storage.create_user(&user.realm_id, &user).await.unwrap();

        let mgr = Arc::new(MockFederationManager {
            providers: Ok(vec![Arc::new(MockKerberosProvider {
                result: Ok(issuerd_core::SpnegoAuthResult {
                    status: issuerd_core::SpnegoStatus::Authenticated,
                    principal: Some("alice@EXAMPLE.COM".to_string()),
                    response_token: None,
                }),
            })]),
        });
        let state = Arc::new(ServerState {
            federation_manager: mgr,
            ..base.clone()
        });
        seed_test_client(&state).await;

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(query_with_redirect()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FOUND);
    }

    #[tokio::test]
    async fn spnego_endpoint_missing_client_id_returns_400() {
        let mgr = Arc::new(MockFederationManager {
            providers: Ok(vec![Arc::new(MockKerberosProvider {
                result: Ok(issuerd_core::SpnegoAuthResult {
                    status: issuerd_core::SpnegoStatus::Authenticated,
                    principal: Some("alice@EXAMPLE.COM".to_string()),
                    response_token: None,
                }),
            })]),
        });
        let state = test_state_with_manager(mgr).await;

        let mut params = HashMap::new();
        params.insert("redirect_uri".to_string(), "http://localhost/callback".to_string());

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(params),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn spnego_endpoint_missing_redirect_uri_returns_400() {
        let mgr = Arc::new(MockFederationManager {
            providers: Ok(vec![Arc::new(MockKerberosProvider {
                result: Ok(issuerd_core::SpnegoAuthResult {
                    status: issuerd_core::SpnegoStatus::Authenticated,
                    principal: Some("alice@EXAMPLE.COM".to_string()),
                    response_token: None,
                }),
            })]),
        });
        let state = test_state_with_manager(mgr).await;

        let mut params = HashMap::new();
        params.insert("client_id".to_string(), "test-client".to_string());

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(params),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn spnego_endpoint_state_is_url_encoded() {
        let mgr = Arc::new(MockFederationManager {
            providers: Ok(vec![Arc::new(MockKerberosProvider {
                result: Ok(issuerd_core::SpnegoAuthResult {
                    status: issuerd_core::SpnegoStatus::Authenticated,
                    principal: Some("alice@EXAMPLE.COM".to_string()),
                    response_token: None,
                }),
            })]),
        });
        let state = test_state_with_manager(mgr).await;
        seed_test_client(&state).await;

        let mut params = query_with_redirect();
        params.insert("state".to_string(), "a&b=c#d".to_string());

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(params),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response.headers().get("Location").unwrap().to_str().unwrap();
        assert!(location.contains("state=a%26b%3Dc%23d"), "location: {location}");
    }

    fn authenticated_manager() -> Arc<MockFederationManager> {
        Arc::new(MockFederationManager {
            providers: Ok(vec![Arc::new(MockKerberosProvider {
                result: Ok(issuerd_core::SpnegoAuthResult {
                    status: issuerd_core::SpnegoStatus::Authenticated,
                    principal: Some("alice@EXAMPLE.COM".to_string()),
                    response_token: None,
                }),
            })]),
        })
    }

    #[tokio::test]
    async fn spnego_endpoint_unregistered_redirect_uri_returns_400() {
        let state = test_state_with_manager(authenticated_manager()).await;
        seed_test_client(&state).await;

        let mut params = query_with_redirect();
        params.insert("redirect_uri".to_string(), "https://attacker.example/cb".to_string());

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(params),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error_description"], "redirect_uri not registered");
    }

    #[tokio::test]
    async fn spnego_endpoint_unknown_client_returns_400() {
        let state = test_state_with_manager(authenticated_manager()).await;
        // No seed_test_client: the client does not exist.

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(query_with_redirect()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn spnego_endpoint_unavailable_scope_returns_400() {
        let state = test_state_with_manager(authenticated_manager()).await;
        seed_test_client(&state).await;

        let mut params = query_with_redirect();
        params.insert("scope".to_string(), "openid admin".to_string());

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(params),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn spnego_endpoint_disabled_user_gets_no_code() {
        let state = test_state_with_manager(authenticated_manager()).await;
        seed_test_client(&state).await;
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new("alice").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: false,
            federation_link: Some("mock-krb".to_string()),
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();

        let response = handle_spnego(
            State(state),
            axum::extract::Extension(crate::middleware::realm::ResolvedRealm(Some(
                "master".to_string(),
            ))),
            axum::extract::Extension(crate::middleware::proxy_ip::ClientIp(
                "127.0.0.1".parse().unwrap(),
            )),
            negotiate_headers("token"),
            axum::extract::Query(query_with_redirect()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
