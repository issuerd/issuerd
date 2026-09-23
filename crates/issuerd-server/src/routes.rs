// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Route tree assembly: mounts all route modules and the middleware stack onto the app router.

use std::sync::Arc;

use axum::{
    middleware,
    response::Redirect,
    routing::{delete, get, post},
    Router,
};
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use tracing::Level;

use crate::{
    middleware::{
        proxy_ip::proxy_ip_middleware, realm::realm_resolution_middleware,
        request_id::request_id_middleware,
    },
    state::ServerState,
};

pub(crate) mod account;
mod auth_response;
mod broker;
mod client_registration;
pub mod consent;
mod jar;
mod kerberos;
pub(crate) mod login_api;
pub mod logout;
pub(crate) mod oidc;
mod par;
mod registration;
mod required_actions;
mod reset_credentials;
mod system;
mod theme;
mod token_exchange;
mod web_ui;

pub use oidc::PendingAuthData;
pub use system::init_metrics;

/// Returns `true` for "noisy" paths whose successful responses should be logged at
/// DEBUG instead of INFO (static files, discovery, JWKS, health, readiness, metrics).
fn is_noisy_path(path: &str) -> bool {
    if path.starts_with("/assets/")
        || path.starts_with("/.well-known")
        // The JWKS endpoint is the highest-frequency polled path in production.
        || path.ends_with("/protocol/openid-connect/certs")
        || path == "/"
        || path == "/config.js"
        || path == "/favicon.ico"
        || path == "/robots.txt"
        || path == "/site.webmanifest"
        || path == "/health"
        || path == "/ready"
        || path == "/health/ready"
        || path == "/metrics"
    {
        return true;
    }
    // Treat common static file extensions as noisy (e.g. /main.js, /index.css, /login.html).
    // HTML files are static SPA assets; the actual API calls (auth, login, admin) never
    // use .html endpoints, so suppressing them does not hide security-relevant events.
    path.rsplit_once('.')
        .map(|(_, ext)| {
            matches!(
                ext,
                "js" | "mjs"
                    | "css"
                    | "png"
                    | "jpg"
                    | "jpeg"
                    | "gif"
                    | "svg"
                    | "ico"
                    | "woff"
                    | "woff2"
                    | "ttf"
                    | "eot"
                    | "map"
                    | "webmanifest"
                    | "html"
            )
        })
        .unwrap_or(false)
}

/// Build the CORS layer from configuration.
///
/// With no configured origins the layer emits no CORS headers, effectively
/// denying all cross-origin browser requests (same-origin SPA and non-browser
/// clients are unaffected). Invalid origin strings are skipped with a warning.
fn cors_layer(config: &crate::config::CorsConfig) -> CorsLayer {
    use axum::http::{header, HeaderValue, Method};

    let origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .filter_map(|origin| match HeaderValue::from_str(origin) {
            Ok(value) => Some(value),
            Err(e) => {
                tracing::warn!(origin = %origin, error = %e, "ignoring invalid cors.allowed_origins entry");
                None
            }
        })
        .collect();

    CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
}

/// Build the complete application router.
pub fn app_router(state: Arc<ServerState>) -> Router {
    let cors = cors_layer(&state.config.cors);
    let admin_state = Arc::new(issuerd_admin_api::state::AdminApiState {
        storage: state.storage.clone(),
        token_service: state.token_service.clone(),
        crypto: state.crypto.clone(),
        federation_manager: state.federation_manager.clone(),
        plugin_registry: state.plugin_registry.clone(),
        cache: state.cache.clone(),
        email_sender: state.email_sender.clone(),
        broker_client: state.broker_client.clone(),
        logout_notifier: state.logout_notifier.clone(),
        available_themes: theme::available_themes(&state.config.themes.dir),
        token_issuer: state.token_manager.clone(),
        signing_key_reload: state.signing_key_reload.clone(),
        base_url: state.config.issuer_url.trim_end_matches('/').to_string(),
    });
    let admin_routes = issuerd_admin_api::routes::admin_routes(admin_state)
        .fallback(web_ui::admin_console_handler);

    // `/admin` serves two things: the REST Admin API (explicit routes) and,
    // via the nested router's fallback, the admin console SPA under
    // `/admin/console/*` — see `web_ui::admin_console_handler`.
    let admin_nested = Router::new().nest_service("/admin", admin_routes).with_state(state.clone());

    let swagger = utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
        .url("/openapi.json", crate::openapi::full_openapi())
        .oauth(
            utoipa_swagger_ui::oauth::Config::new()
                .client_id("admin-cli")
                .scopes(vec!["openid".to_string(), "profile".to_string()])
                .use_pkce_with_authorization_code_grant(true),
        );

    Router::new()
        .route("/health", get(system::health_handler))
        .route("/ready", get(system::ready_handler))
        .route("/health/ready", get(system::ready_handler))
        .route("/metrics", get(system::metrics_handler))
        .route("/.well-known/openid-configuration", get(oidc::discovery_handler))
        .route("/realms/{realm}/.well-known/openid-configuration", get(oidc::discovery_handler))
        .route("/realms/{realm}/protocol/openid-connect/certs", get(oidc::certs_handler))
        .route(
            "/realms/{realm}/protocol/openid-connect/auth",
            get(oidc::auth_handler).post(oidc::auth_handler_post),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/auth/device",
            post(oidc::device_auth_handler),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/auth/device-verify",
            post(oidc::device_verify_handler),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/ext/ciba/auth",
            post(oidc::ciba_auth_handler),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/ext/ciba/approve",
            post(oidc::ciba_approve_handler),
        )
        .route("/realms/{realm}/protocol/openid-connect/ext/par", post(par::par_handler))
        .route(
            "/realms/{realm}/clients-registrations/default",
            post(client_registration::register_open_handler),
        )
        .route(
            "/realms/{realm}/clients-registrations/openid-connect",
            post(client_registration::register_token_gated_handler),
        )
        .route(
            "/realms/{realm}/clients-registrations/openid-connect/{client_id}",
            get(client_registration::read_registered_client_handler)
                .put(client_registration::update_registered_client_handler)
                .delete(client_registration::delete_registered_client_handler),
        )
        .route("/realms/{realm}/protocol/openid-connect/token", post(oidc::token_handler))
        .route(
            "/realms/{realm}/protocol/openid-connect/userinfo",
            get(oidc::userinfo_handler_get).post(oidc::userinfo_handler_post),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/logout",
            post(oidc::logout_handler).get(oidc::logout_handler_get),
        )
        .route("/realms/{realm}/protocol/openid-connect/revoke", post(oidc::revoke_handler))
        .route(
            "/realms/{realm}/protocol/openid-connect/token/introspect",
            post(oidc::introspect_handler),
        )
        .route("/realms/{realm}/kerberos", get(kerberos::handle_spnego))
        .route("/realms/{realm}/broker/{alias}/login", get(broker::broker_login_handler))
        .route(
            "/realms/{realm}/broker/{alias}/endpoint",
            get(broker::broker_endpoint_handler_get).post(broker::broker_endpoint_handler_post),
        )
        .route(
            "/realms/{realm}/broker/first-login/{execution}",
            get(broker::first_broker_login_page).post(broker::first_broker_login_submit),
        )
        .route("/realms/{realm}/login", get(login_api::realm_login_page_handler))
        .route("/realms/{realm}/login/context", get(login_api::login_context_handler))
        .route("/realms/{realm}/theme/{*path}", get(theme::theme_asset_handler))
        .route(
            "/realms/{realm}/login/register",
            get(registration::register_page).post(registration::register_submit),
        )
        .route(
            "/realms/{realm}/login/required-action/{execution}",
            get(required_actions::required_action_page)
                .post(required_actions::required_action_submit),
        )
        .route(
            "/realms/{realm}/login/consent/{execution}",
            get(consent::consent_page).post(consent::consent_submit),
        )
        .route(
            "/realms/{realm}/login/verify-email",
            get(required_actions::verify_email_handler),
        )
        .route(
            "/realms/{realm}/login/execute-actions",
            get(required_actions::execute_actions_handler),
        )
        .route(
            "/realms/{realm}/login/reset-credentials",
            get(reset_credentials::reset_credentials_page)
                .post(reset_credentials::reset_credentials_submit),
        )
        .route(
            "/realms/{realm}/login/update-credentials",
            get(reset_credentials::update_credentials_page)
                .post(reset_credentials::update_credentials_submit),
        )
        .route("/api/v1/auth/login", post(login_api::login_handler))
        .route("/api/v1/auth/logout", post(login_api::logout_api_handler))
        .route("/api/v1/auth/admin-token", post(login_api::admin_token_handler))
        .route(
            "/realms/{realm}/account/api/me",
            get(account::account_me_handler).put(account::account_update_me_handler),
        )
        .route("/realms/{realm}/account/api/sessions", get(account::account_sessions_handler))
        .route(
            "/realms/{realm}/account/api/sessions/{id}/logout",
            post(account::account_logout_session_handler),
        )
        .route(
            "/realms/{realm}/account/api/credentials",
            get(account::account_credentials_handler),
        )
        .route(
            "/realms/{realm}/account/api/credentials/password",
            post(account::account_change_password_handler),
        )
        .route(
            "/realms/{realm}/account/api/credentials/totp/start",
            post(account::account_totp_start_handler),
        )
        .route(
            "/realms/{realm}/account/api/credentials/totp/verify",
            post(account::account_totp_verify_handler),
        )
        .route(
            "/realms/{realm}/account/api/credentials/totp",
            delete(account::account_totp_delete_handler),
        )
        .route(
            "/realms/{realm}/account/api/webauthn/register/start",
            post(account::account_webauthn_register_start_handler),
        )
        .route(
            "/realms/{realm}/account/api/webauthn/register/finish",
            post(account::account_webauthn_register_finish_handler),
        )
        .route(
            "/realms/{realm}/account/api/webauthn/credentials",
            get(account::account_webauthn_credentials_handler),
        )
        .route(
            "/realms/{realm}/account/api/webauthn/credentials/{id}",
            delete(account::account_webauthn_delete_handler),
        )
        .route("/realms/{realm}/account/api/consents", get(account::account_consents_handler))
        .route(
            "/realms/{realm}/account/api/consents/{client_id}",
            delete(account::account_delete_consent_handler),
        )
        .route(
            "/realms/{realm}/account/api/linked-accounts",
            get(account::account_linked_accounts_handler),
        )
        .route(
            "/realms/{realm}/account/api/linked-accounts/{alias}",
            post(account::account_link_identity_handler)
                .delete(account::account_unlink_identity_handler),
        )
        .merge(admin_nested)
        .merge(swagger)
        .route("/{*path}", get(web_ui::static_handler))
        .route("/", get(|| async { Redirect::temporary(web_ui::ADMIN_CONSOLE_PREFIX) }))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::extract::Request| {
                    let path = request.uri().path();
                    let request_id = request
                        .extensions()
                        .get::<crate::middleware::request_id::RequestId>()
                        .map(|r| r.0.clone())
                        .unwrap_or_default();
                    if is_noisy_path(path) {
                        // Keep the span at INFO so its fields are available when a
                        // quiet path returns 4xx/5xx; the on_response hook demotes
                        // successful responses on these paths to DEBUG events.
                        tracing::info_span!(
                            "http_request_quiet",
                            method = %request.method(),
                            path = %path,
                            status = tracing::field::Empty,
                            request_id = %request_id,
                        )
                    } else {
                        // Only the path is recorded — query strings can carry live
                        // credentials (authorization codes, action tokens, JAR
                        // request objects, id_token_hint JWTs).
                        tracing::info_span!(
                            "http_request",
                            method = %request.method(),
                            path = %path,
                            status = tracing::field::Empty,
                            request_id = %request_id,
                        )
                    }
                })
                .on_response(
                    |response: &axum::response::Response,
                     latency: std::time::Duration,
                     span: &tracing::Span| {
                        let is_quiet =
                            span.metadata().map(|m| m.name()) == Some("http_request_quiet");
                        let status = response.status().as_u16();
                        span.record("status", status);
                        let latency_ms = latency.as_millis() as u64;
                        if status >= 500 {
                            tracing::event!(parent: span, Level::ERROR, latency_ms, "response");
                        } else if status >= 400 {
                            tracing::event!(parent: span, Level::WARN, latency_ms, "response");
                        } else if is_quiet {
                            tracing::event!(parent: span, Level::DEBUG, latency_ms, "response");
                        } else {
                            tracing::event!(parent: span, Level::INFO, latency_ms, "response");
                        }
                    },
                ),
        )
        .layer(cors)
        .layer(CompressionLayer::new())
        .layer(middleware::from_fn(request_id_middleware))
        .layer(middleware::from_fn(realm_resolution_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), proxy_ip_middleware))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::ServerConfig, state::ServerState};
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[test]
    fn noisy_path_classification() {
        assert!(is_noisy_path("/health"));
        assert!(is_noisy_path("/.well-known/openid-configuration"));
        assert!(is_noisy_path("/realms/master/protocol/openid-connect/certs"));
        assert!(is_noisy_path("/realms/demo/protocol/openid-connect/certs"));
        assert!(is_noisy_path("/assets/main.js"));
        assert!(is_noisy_path("/login.html"));
        assert!(!is_noisy_path("/realms/master/protocol/openid-connect/token"));
        assert!(!is_noisy_path("/admin/realms"));
    }

    #[tokio::test]
    async fn app_router_builds_and_responds() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        let mut req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn cors_preflight_denied_when_no_origins_configured() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        let mut req = Request::builder()
            .method(axum::http::Method::OPTIONS)
            .uri("/health")
            .header("origin", "https://attacker.example")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert!(
            response.headers().get("access-control-allow-origin").is_none(),
            "no CORS headers may be emitted without configured origins"
        );
    }

    #[tokio::test]
    async fn cors_preflight_allowed_for_configured_origin() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let mut config = ServerConfig::default();
        config.cors.allowed_origins = vec!["https://app.example.com".to_string()];
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        let mut req = Request::builder()
            .method(axum::http::Method::OPTIONS)
            .uri("/health")
            .header("origin", "https://app.example.com")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(
            response.headers().get("access-control-allow-origin").unwrap(),
            "https://app.example.com"
        );
    }

    #[tokio::test]
    async fn app_router_has_oidc_discovery() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        let mut req = Request::builder()
            .uri("/.well-known/openid-configuration")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn app_router_health_ready_returns_json() {
        use axum::body::to_bytes;
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        let mut req = Request::builder().uri("/health/ready").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ready");
    }

    #[tokio::test]
    async fn app_router_traces_4xx_response() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        // Request a path with an extension that does not exist in the embedded
        // web UI — static_handler returns 404 for concrete missing files.
        let mut req = Request::builder().uri("/missing.css").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn app_router_traces_5xx_response() {
        use axum::extract::ConnectInfo;
        use issuerd_token::token_manager::TokenManager;
        use std::net::SocketAddr;

        let mut mock_crypto = issuerd_core::MockCryptoProvider::new();
        mock_crypto
            .expect_get_public_keys()
            .returning(|| Err(issuerd_core::IssuerdError::ServerError("crypto fail".to_string())));

        let real_crypto = Arc::new(
            issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default()).unwrap(),
        );
        let token_manager = Arc::new(TokenManager::new(
            real_crypto.clone(),
            "http://localhost:8080".to_string(),
            std::time::Duration::from_secs(60),
            issuerd_core::JwkSet { keys: vec![] },
        ));
        let token_service: Arc<dyn issuerd_core::TokenService> = token_manager.clone();

        let state = Arc::new(ServerState {
            config: ServerConfig::default(),
            storage: Arc::new(issuerd_storage::InMemoryStorage::new()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            crypto: Arc::new(mock_crypto),
            token_service,
            token_manager,
            plugin_registry: Arc::new(crate::state::SimplePluginRegistry::new()),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            login_failure_tracker: Arc::new(
                issuerd_auth_flow::login_failures::LoginFailureTracker::new(),
            ),
            email_sender: Arc::new(crate::email::NoOpEmailSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            signing_key_reload: Arc::new(|| {}),
            keyset_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            event_listeners: std::collections::HashMap::new(),
        });

        let app = app_router(state);

        let mut req = Request::builder()
            .uri("/realms/master/protocol/openid-connect/certs")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn admin_console_serves_spa_shell_for_client_routes() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        for uri in ["/admin/console", "/admin/console/users/some-id"] {
            let mut req = Request::builder()
                .uri(uri)
                .header("Accept", "text/html")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
            let response = app.clone().oneshot(req).await.unwrap();
            #[cfg(webclient_present)]
            {
                assert_eq!(response.status(), axum::http::StatusCode::OK, "uri: {uri}");
                let content_type =
                    response.headers().get("content-type").unwrap().to_str().unwrap();
                assert_eq!(content_type, "text/html");
            }
            #[cfg(not(webclient_present))]
            assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND, "uri: {uri}");
        }
    }

    #[tokio::test]
    async fn admin_console_missing_asset_is_404() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        let mut req = Request::builder()
            .uri("/admin/console/missing-asset.css")
            .header("Accept", "text/html")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_api_typo_is_json_404_even_for_browsers() {
        use axum::body::to_bytes;
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        let mut req = Request::builder()
            .uri("/admin/no-such-api-path")
            .header("Accept", "text/html")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "not found");
    }

    #[tokio::test]
    async fn admin_api_unauthorized_stays_json_for_browsers() {
        use axum::body::to_bytes;
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        let mut req = Request::builder()
            .uri("/admin/realms")
            .header("Accept", "text/html")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errorMessage"], "unauthorized");
    }

    #[tokio::test]
    async fn bare_admin_and_root_redirect_to_console() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        for uri in ["/", "/admin"] {
            let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
            let response = app.clone().oneshot(req).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::TEMPORARY_REDIRECT, "uri: {uri}");
            assert_eq!(
                response.headers().get("location").unwrap().to_str().unwrap(),
                "/admin/console"
            );
        }
    }

    #[tokio::test]
    async fn unknown_api_and_top_level_paths_are_json_404() {
        use axum::body::to_bytes;
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        for uri in ["/api/v1/bogus", "/totally-unknown"] {
            let mut req = Request::builder()
                .uri(uri)
                .header("Accept", "text/html")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
            let response = app.clone().oneshot(req).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND, "uri: {uri}");

            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "not found", "uri: {uri}");
        }
    }

    #[tokio::test]
    async fn admin_spa_no_fallback_on_401_with_json_accept() {
        use axum::body::to_bytes;
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let config = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = app_router(state);

        let mut req = Request::builder()
            .uri("/admin/realms")
            .header("Accept", "application/json")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errorMessage"], "unauthorized");
    }
}
