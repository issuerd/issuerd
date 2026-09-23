// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Admin-initiated user operations: execute-actions-email and impersonation.

//! Admin-initiated user account operations: execute-actions-email
//! (send the user a signed link to complete required actions) and
//! impersonation (issue a session as the target user, fully audited).

use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use issuerd_core::{
    AuthMethod, EventType, OperationType, Realm, ResourceType, UserId,
    ACTION_TOKEN_PURPOSE_EXECUTE_ACTIONS,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{ExecuteActionsEmailParams, ImpersonationResponse},
    error::AdminApiError,
    state::AdminApiState,
};
use tracing::{info, instrument};

/// Default execute-actions link validity: 12 hours (Keycloak default).
const DEFAULT_EXECUTE_ACTIONS_LIFESPAN_SECS: i64 = 43_200;

/// Client id of the admin console SPA (`webclientsrc` `CONFIG.CLIENT_ID`);
/// impersonation tokens are issued for this client so the admin can open the
/// console as the target user.
const ADMIN_CONSOLE_CLIENT_ID: &str = "admin-cli";

/// Continuation payload stored under `execute-actions:{realm_name}:{jti}`
/// (realm **name**, matching the login-route keying convention) with the
/// action token's TTL. The login-side continuation endpoint (issuerd-server, later
/// slice) reads this entry after verifying the token; keep the shape exactly
/// in sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteActionsContinuation {
    pub user_id: String,
    pub actions: Vec<String>,
    pub redirect_uri: Option<String>,
}

/// Resolve the path realm (404) and load the target user (404).
async fn load_realm_and_user(
    state: &Arc<AdminApiState>,
    realm: &str,
    id: &str,
) -> Result<(Realm, issuerd_core::User), AdminApiError> {
    let realm = state.storage.get_realm_by_name(realm).await?.ok_or(AdminApiError::NotFound)?;
    let user_id = UserId::new(id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let user = state
        .storage
        .get_user(&realm.id, &user_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok((realm, user))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/users/{id}/execute-actions-email",
    tag = "Users",
    summary = "Send an execute-actions email",
    description = "Emails the user a signed, single-purpose action link that opens the required-action continuation for the listed actions. Every action id must be registered in the plugin registry (400 naming the unknown ids otherwise). The user must have an email address (400 otherwise). Requires `manage-users` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID"),
        ExecuteActionsEmailParams
    ),
    request_body(description = "Required-action ids to execute (e.g. `[\"UPDATE_PASSWORD\", \"VERIFY_EMAIL\"]`)", content = Vec<String>),
    responses(
        (status = 204, description = "Email sent"),
        (status = 400, description = "Unknown action ids, user has no email, or invalid lifespan", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Email delivery failed", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth, actions), fields(realm = %realm, user_id = %id))]
pub async fn execute_actions_email(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
    Query(params): Query<ExecuteActionsEmailParams>,
    Json(actions): Json<Vec<String>>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-users"])?;
    let (realm, user) = load_realm_and_user(&state, &realm, &id).await?;

    let known = state.plugin_registry.list_required_action_ids();
    let mut unknown: Vec<&str> = actions
        .iter()
        .map(String::as_str)
        .filter(|a| !known.contains(&a.to_string()))
        .collect();
    unknown.sort_unstable();
    unknown.dedup();
    if !unknown.is_empty() {
        return Err(AdminApiError::BadRequest(format!(
            "unknown required action ids: {}",
            unknown.join(", ")
        )));
    }

    let email = user
        .email
        .as_ref()
        .map(|e| e.to_string())
        .ok_or_else(|| AdminApiError::BadRequest("user has no email address".to_string()))?;

    let lifespan = params.lifespan.unwrap_or(DEFAULT_EXECUTE_ACTIONS_LIFESPAN_SECS);
    if lifespan <= 0 {
        return Err(AdminApiError::BadRequest("lifespan must be positive".to_string()));
    }

    let claims = issuerd_token::action_token_claims(
        &user.id,
        &realm.id,
        ACTION_TOKEN_PURPOSE_EXECUTE_ACTIONS,
        lifespan,
    );
    let jti = claims.jti.clone();
    let token = issuerd_token::issue_action_token(state.crypto.as_ref(), &claims).await?;

    // Continuation entry consumed by `GET /realms/{realm}/login/execute-actions`
    // (issuerd-server slice): keyed by realm NAME + token jti, TTL = lifespan.
    let continuation = ExecuteActionsContinuation {
        user_id: user.id.to_string(),
        actions: actions.clone(),
        redirect_uri: params.redirect_uri.clone(),
    };
    let value = serde_json::to_vec(&continuation)
        .map_err(|e| AdminApiError::Internal(anyhow::anyhow!("continuation JSON: {e}")))?;
    state
        .cache
        .set(
            &format!("execute-actions:{}:{}", realm.name, jti),
            value,
            Some(std::time::Duration::from_secs(lifespan as u64)),
        )
        .await?;

    let link =
        format!("{}/realms/{}/login/execute-actions?token={}", state.base_url, realm.name, token);
    let realm_display = realm
        .display_name
        .as_ref()
        .map(|d| d.to_string())
        .unwrap_or_else(|| realm.name.to_string());
    let rendered = crate::email::render_execute_actions_email(
        &realm_display,
        user.username.as_ref(),
        &link,
        lifespan / 60,
    );
    state
        .email_sender
        .send(&realm, &email, &rendered.subject, &rendered.text, Some(rendered.html))
        .await
        .map_err(|e| {
            AdminApiError::Internal(anyhow::anyhow!("failed to send execute-actions email: {e}"))
        })?;

    info!(realm = %realm.id, user_id = %user.id, actions = ?actions, "execute-actions email sent");
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{id}/execute-actions-email"),
        serde_json::to_string(&serde_json::json!({
            "actions": actions,
            "lifespan": lifespan,
            "redirect_uri": params.redirect_uri,
        }))
        .ok(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/users/{id}/impersonation",
    tag = "Users",
    summary = "Impersonate a user",
    description = "Creates a session as the target user and returns its tokens. The issued tokens carry an `impersonator` claim naming the calling administrator; the session is persisted with the impersonator recorded and both an admin event and a login event are written. An administrator cannot impersonate themselves or a disabled user (400). Tokens are issued for the realm's `admin-cli` client (400 when absent). Requires the `impersonation` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "User ID to impersonate")
    ),
    responses(
        (status = 200, description = "Impersonated session tokens", body = ImpersonationResponse),
        (status = 400, description = "Self-impersonation, disabled user, or missing admin-cli client", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Missing `impersonation` role", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or user not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
#[instrument(skip(state, auth), fields(realm = %realm, user_id = %id))]
pub async fn impersonate_user(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id)): axum::extract::Path<(String, String)>,
) -> Result<(StatusCode, Json<ImpersonationResponse>), AdminApiError> {
    require_roles(&auth, &["impersonation"])?;
    let (realm, user) = load_realm_and_user(&state, &realm, &id).await?;

    if auth.claims.sub == user.id {
        return Err(AdminApiError::BadRequest(
            "an administrator cannot impersonate themselves".to_string(),
        ));
    }
    if !user.enabled {
        return Err(AdminApiError::BadRequest("cannot impersonate a disabled user".to_string()));
    }

    let client_identifier = issuerd_core::ClientIdentifier::new(ADMIN_CONSOLE_CLIENT_ID)
        .map_err(|e| AdminApiError::Internal(anyhow::anyhow!(e.to_string())))?;
    let client = state
        .storage
        .get_client_by_client_id(&realm.id, &client_identifier)
        .await?
        .ok_or_else(|| {
            AdminApiError::BadRequest(format!(
                "realm '{realm_name}' has no '{ADMIN_CONSOLE_CLIENT_ID}' client; impersonation \
                 issues tokens for the admin console client",
                realm_name = realm.name
            ))
        })?;

    let now = Utc::now();
    let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id())
        .map_err(|e| AdminApiError::Internal(anyhow::anyhow!(e.to_string())))?;
    let session = issuerd_core::UserSession {
        id: session_id.clone(),
        realm_id: realm.id.clone(),
        user_id: user.id.clone(),
        login_username: user.username.clone(),
        // The admin API does not observe the browser's connection info; the
        // impersonator's network address is not meaningful for the target
        // user's session, so the loopback placeholder matches the login flow's
        // fallback convention.
        ip_address: "127.0.0.1".parse().unwrap(),
        auth_method: AuthMethod::Impersonation,
        remember_me: false,
        offline: false,
        started: now,
        last_session_refresh: now,
        auth_time: now,
        impersonator: Some(auth.claims.sub.clone()),
        clients: vec![issuerd_core::ClientSession {
            id: issuerd_core::ClientSessionId::new(issuerd_core::utils::generate_id())
                .map_err(|e| AdminApiError::Internal(anyhow::anyhow!(e.to_string())))?,
            client_id: client.id.clone(),
            session_id: session_id.clone(),
            redirect_uri: None,
            state: None,
            auth_method: AuthMethod::Impersonation,
            timestamp: now,
        }],
    };
    state.storage.create_user_session(&realm.id, &session).await?;

    // Effective realm roles of the target user (direct + group + composite);
    // client roles are not embedded (the token's `resource_access` would need
    // the claims assembly in issuerd-server, which the admin API cannot
    // reach).
    let effective =
        issuerd_core::effective_user_roles(state.storage.as_ref(), &realm.id, &user.id).await?;
    let realm_roles: Vec<issuerd_core::RoleName> =
        effective.into_iter().filter(|r| !r.client_role).map(|r| r.name).collect();

    let mut overlay = serde_json::Map::new();
    overlay.insert(
        "impersonator".to_string(),
        serde_json::Value::String(auth.claims.sub.to_string()),
    );
    let scope = vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ];

    let access = state
        .token_issuer
        .issue_access_token_with_roles(
            &user,
            &client,
            &realm,
            &scope,
            &session_id,
            Some(issuerd_core::RealmAccess { roles: realm_roles }),
            None,
            Some(overlay.clone()),
        )
        .await?;
    let refresh = state
        .token_issuer
        .issue_refresh_token(&user, &client, &realm, &session_id, &scope, false, None, None)
        .await?;
    let id_token = state
        .token_issuer
        .issue_id_token(
            &user,
            &client,
            &realm,
            None,
            now,
            &session_id,
            Some(&access),
            None,
            None,
            Some(overlay),
        )
        .await?;

    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Action,
        ResourceType::User,
        &format!("users/{id}/impersonation"),
        serde_json::to_string(&serde_json::json!({
            "impersonator": auth.claims.sub.to_string(),
            "impersonated_user": user.id.to_string(),
        }))
        .ok(),
    )
    .await;

    let mut details = std::collections::HashMap::new();
    details.insert("method".to_string(), "impersonation".to_string());
    details.insert("impersonator".to_string(), auth.claims.sub.to_string());
    details.insert("username".to_string(), user.username.to_string());
    let event = issuerd_core::Event {
        id: issuerd_core::EventId::new(issuerd_core::utils::generate_id())
            .map_err(|e| AdminApiError::Internal(anyhow::anyhow!(e.to_string())))?,
        realm_id: realm.id.clone(),
        event_time: Utc::now(),
        event_type: EventType::Login,
        ip_address: None,
        client_id: Some(client.id.clone()),
        user_id: Some(user.id.clone()),
        session_id: Some(session_id),
        error: None,
        details,
    };
    state.storage.save_event(&realm.id, &event).await?;

    info!(realm = %realm.id, user_id = %user.id, impersonator = %auth.claims.sub, "user impersonated");
    Ok((
        StatusCode::OK,
        Json(ImpersonationResponse {
            access_token: access.token,
            refresh_token: refresh.token,
            id_token: Some(id_token.token),
            expires_in: realm.access_token_lifespan.get() as i64,
            token_type: "Bearer".to_string(),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{post, put},
        Router,
    };
    use issuerd_core::{Client, Email, IssuerdError};
    use std::sync::Mutex;
    use tower::ServiceExt;

    fn action_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/users/{id}/execute-actions-email",
                put(execute_actions_email),
            )
            .route("/admin/realms/{realm}/users/{id}/impersonation", post(impersonate_user))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    /// Email sender capturing every message for assertions.
    struct RecordingEmailSender {
        sent: Mutex<Vec<(String, String, String, Option<String>)>>,
    }

    impl RecordingEmailSender {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl issuerd_core::EmailSender for RecordingEmailSender {
        async fn send(
            &self,
            _realm: &Realm,
            to: &str,
            subject: &str,
            text_body: &str,
            html_body: Option<String>,
        ) -> Result<(), IssuerdError> {
            self.sent.lock().unwrap().push((
                to.to_string(),
                subject.to_string(),
                text_body.to_string(),
                html_body,
            ));
            Ok(())
        }
    }

    fn real_crypto() -> Arc<issuerd_token::RingCryptoProvider> {
        Arc::new(
            issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig::default()).unwrap(),
        )
    }

    /// Admin state backed by a real signing provider (execute-actions tokens
    /// must verify) and the recording email sender.
    fn email_test_state(
        roles: Vec<issuerd_core::RoleName>,
        email_sender: Arc<RecordingEmailSender>,
    ) -> Arc<AdminApiState> {
        Arc::new(AdminApiState {
            storage: crate::test_utils::tests::storage_with_master_realm(),
            token_service: Arc::new(crate::test_utils::tests::MockTokenService { roles }),
            crypto: real_crypto(),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender,
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            base_url: "http://localhost:8080".to_string(),
        })
    }

    async fn realm_and_user(state: &Arc<AdminApiState>, email: Option<&str>) -> (String, String) {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            // Admin-event recording is opt-in per realm; the impersonation
            // test asserts on the emitted audit event.
            admin_events_enabled: true,
            include_representations: true,
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new("user-1").unwrap(),
            realm_id: realm.id.clone(),
            username: issuerd_core::Username::new("alice").unwrap(),
            email: email.map(|e| Email::new(e).unwrap()),
            email_verified: true,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: Default::default(),
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&realm.id, &user).await.unwrap();
        (realm.name.to_string(), user.id.to_string())
    }

    async fn create_admin_cli_client(state: &Arc<AdminApiState>) {
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();
        let client = Client {
            id: issuerd_core::ClientId::new("client-1").unwrap(),
            realm_id: realm_id.clone(),
            client_id: issuerd_core::ClientIdentifier::new(ADMIN_CONSOLE_CLIENT_ID).unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: issuerd_core::ClientProtocol::OpenIdConnect,
            public_client: true,
            bearer_only: false,
            client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: issuerd_core::Scope::empty(),
            optional_scopes: issuerd_core::Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: Default::default(),
        };
        state.storage.create_client(&realm_id, &client).await.unwrap();
    }

    async fn call(
        app: Router,
        method: &str,
        uri: String,
        body: Option<String>,
    ) -> (StatusCode, axum::body::Bytes) {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", "Bearer valid-token");
        let builder = if body.is_some() {
            builder.header("Content-Type", "application/json")
        } else {
            builder
        };
        let response = app
            .oneshot(builder.body(Body::from(body.unwrap_or_default())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, bytes)
    }

    // -- execute-actions-email -----------------------------------------------

    #[tokio::test]
    async fn execute_actions_email_unknown_action_400() {
        let sender = Arc::new(RecordingEmailSender::new());
        let state = email_test_state(
            vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            sender.clone(),
        );
        let app = action_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state, Some("alice@example.com")).await;

        let (status, body) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/execute-actions-email"),
            Some(r#"["UPDATE_PASSWORD","NOPE"]"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let raw = String::from_utf8(body.to_vec()).unwrap();
        assert!(raw.contains("NOPE"), "error names the unknown id: {raw}");
        assert!(sender.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn execute_actions_email_no_email_400() {
        let sender = Arc::new(RecordingEmailSender::new());
        let state = email_test_state(
            vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            sender.clone(),
        );
        let app = action_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state, None).await;

        let (status, body) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/execute-actions-email"),
            Some(r#"["UPDATE_PASSWORD"]"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let raw = String::from_utf8(body.to_vec()).unwrap();
        assert!(raw.contains("no email"), "{raw}");
        assert!(sender.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn execute_actions_email_happy_path_roundtrip() {
        let sender = Arc::new(RecordingEmailSender::new());
        let state = email_test_state(
            vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            sender.clone(),
        );
        let app = action_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state, Some("alice@example.com")).await;

        let (status, _) = call(
            app,
            "PUT",
            format!(
                "/admin/realms/{realm}/users/{user_id}/execute-actions-email?redirect_uri=https://app.example.com/after&lifespan=3600"
            ),
            Some(r#"["VERIFY_EMAIL","UPDATE_PROFILE","UPDATE_PASSWORD"]"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Email captured with the absolute execute-actions link. Clone out of the
        // guard so no std MutexGuard is held across the awaits below.
        let (to, subject, text, html) = {
            let sent = sender.sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            sent[0].clone()
        };
        assert_eq!(to, "alice@example.com");
        assert_eq!(subject, "Complete required actions for your account");
        let marker = "http://localhost:8080/realms/test/login/execute-actions?token=";
        let start = text.find(marker).expect("text body carries the link");
        let token: String = text[start + marker.len()..]
            .chars()
            .take_while(|c| *c != '\n' && !c.is_whitespace())
            .collect();
        assert!(html.as_ref().unwrap().contains(&token));

        // Token verifies against the realm signing key and carries the 1h TTL.
        let claims = issuerd_token::verify_action_token(
            state.crypto.as_ref(),
            &token,
            ACTION_TOKEN_PURPOSE_EXECUTE_ACTIONS,
            &issuerd_core::RealmId::new("realm-1").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.exp - claims.iat, 3600);

        // Cache entry keyed by realm NAME + jti holds the continuation payload.
        let key = format!("execute-actions:{realm}:{}", claims.jti);
        let entry = state.cache.get(&key).await.unwrap().expect("cache entry present");
        let entry: ExecuteActionsContinuation = serde_json::from_slice(&entry).unwrap();
        assert_eq!(entry.user_id, user_id);
        // The continuation preserves the exact order of the admin request body.
        assert_eq!(
            entry.actions,
            vec![
                "VERIFY_EMAIL".to_string(),
                "UPDATE_PROFILE".to_string(),
                "UPDATE_PASSWORD".to_string()
            ]
        );
        assert_eq!(entry.redirect_uri, Some("https://app.example.com/after".to_string()));
    }

    #[tokio::test]
    async fn execute_actions_email_send_failure_is_500() {
        struct FailingSender;
        #[async_trait::async_trait]
        impl issuerd_core::EmailSender for FailingSender {
            async fn send(
                &self,
                _realm: &Realm,
                _to: &str,
                _subject: &str,
                _text_body: &str,
                _html_body: Option<String>,
            ) -> Result<(), IssuerdError> {
                Err(IssuerdError::ServerError("smtp down".to_string()))
            }
        }
        let state = Arc::new(AdminApiState {
            storage: crate::test_utils::tests::storage_with_master_realm(),
            token_service: Arc::new(crate::test_utils::tests::MockTokenService {
                roles: vec![issuerd_core::RoleName::new("manage-users").unwrap()],
            }),
            crypto: real_crypto(),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender: Arc::new(FailingSender),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            base_url: "http://localhost:8080".to_string(),
        });
        let app = action_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state, Some("alice@example.com")).await;

        let (status, _) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/execute-actions-email"),
            Some(r#"["UPDATE_PASSWORD"]"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn execute_actions_email_requires_manage_users() {
        let sender = Arc::new(RecordingEmailSender::new());
        let state =
            email_test_state(vec![issuerd_core::RoleName::new("view-users").unwrap()], sender);
        let app = action_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state, Some("alice@example.com")).await;

        let (status, _) = call(
            app,
            "PUT",
            format!("/admin/realms/{realm}/users/{user_id}/execute-actions-email"),
            Some(r#"["UPDATE_PASSWORD"]"#.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // -- impersonation ---------------------------------------------------------

    /// State whose token issuer records the issued-token inputs (the stub
    /// token issuer is shared through the state's `token_issuer`).
    fn impersonation_state(
        roles: Vec<issuerd_core::RoleName>,
    ) -> (Arc<AdminApiState>, Arc<crate::test_utils::tests::StubTokenIssuer>) {
        let issuer = Arc::new(crate::test_utils::tests::StubTokenIssuer::new());
        let state = Arc::new(AdminApiState {
            storage: crate::test_utils::tests::storage_with_master_realm(),
            token_service: Arc::new(crate::test_utils::tests::MockTokenService { roles }),
            crypto: real_crypto(),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender: Arc::new(issuerd_core::MockEmailSender::new()),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: issuer.clone(),
            signing_key_reload: Arc::new(|| {}),
            base_url: "http://localhost:8080".to_string(),
        });
        (state, issuer)
    }

    #[tokio::test]
    async fn impersonation_requires_impersonation_role() {
        let (state, _) =
            impersonation_state(vec![issuerd_core::RoleName::new("manage-users").unwrap()]);
        let app = action_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state, Some("alice@example.com")).await;

        let (status, _) = call(
            app,
            "POST",
            format!("/admin/realms/{realm}/users/{user_id}/impersonation"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn impersonation_self_400() {
        let (state, _) =
            impersonation_state(vec![issuerd_core::RoleName::new("impersonation").unwrap()]);
        let app = action_routes(state.clone());
        let (realm, _) = realm_and_user(&state, Some("alice@example.com")).await;
        // The test token's subject is the user id "admin" (MockTokenService).
        let admin_user = issuerd_core::User {
            id: issuerd_core::UserId::new("admin").unwrap(),
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            username: issuerd_core::Username::new("admin").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: Default::default(),
            required_actions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.storage.create_user(&admin_user.realm_id, &admin_user).await.unwrap();

        let (status, body) =
            call(app, "POST", format!("/admin/realms/{realm}/users/admin/impersonation"), None)
                .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8(body.to_vec()).unwrap().contains("themselves"));
    }

    #[tokio::test]
    async fn impersonation_disabled_user_400() {
        let (state, _) =
            impersonation_state(vec![issuerd_core::RoleName::new("impersonation").unwrap()]);
        let app = action_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state, Some("alice@example.com")).await;
        let mut user = state
            .storage
            .get_user(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::UserId::new(&user_id).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        user.enabled = false;
        state.storage.update_user(&user.realm_id, &user).await.unwrap();

        let (status, body) = call(
            app,
            "POST",
            format!("/admin/realms/{realm}/users/{user_id}/impersonation"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8(body.to_vec()).unwrap().contains("disabled"));
    }

    #[tokio::test]
    async fn impersonation_missing_admin_client_400() {
        let (state, _) =
            impersonation_state(vec![issuerd_core::RoleName::new("impersonation").unwrap()]);
        let app = action_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state, Some("alice@example.com")).await;

        let (status, body) = call(
            app,
            "POST",
            format!("/admin/realms/{realm}/users/{user_id}/impersonation"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8(body.to_vec()).unwrap().contains(ADMIN_CONSOLE_CLIENT_ID));
    }

    #[tokio::test]
    async fn impersonation_happy_path() {
        let (state, issuer) =
            impersonation_state(vec![issuerd_core::RoleName::new("impersonation").unwrap()]);
        let app = action_routes(state.clone());
        let (realm, user_id) = realm_and_user(&state, Some("alice@example.com")).await;
        create_admin_cli_client(&state).await;
        // A realm role so the issued realm_access is exercised.
        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new("role-1").unwrap(),
            name: issuerd_core::RoleName::new("reader").unwrap(),
            description: None,
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: Default::default(),
        };
        state.storage.create_role(&role.realm_id, &role).await.unwrap();
        state
            .storage
            .add_user_realm_role(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::UserId::new(&user_id).unwrap(),
                &role.id,
            )
            .await
            .unwrap();

        let (status, body) = call(
            app,
            "POST",
            format!("/admin/realms/{realm}/users/{user_id}/impersonation"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let tokens: ImpersonationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(tokens.access_token, "stub-access-token");
        assert_eq!(tokens.refresh_token, "stub-refresh-token");
        assert_eq!(tokens.id_token.as_deref(), Some("stub-id-token"));
        assert_eq!(tokens.token_type, "Bearer");
        assert!(tokens.expires_in > 0);

        // The overlay passed to the issuer carries exactly the impersonator.
        let overlay = issuer.last_access_overlay.lock().unwrap().clone().unwrap();
        assert_eq!(overlay.len(), 1);
        assert_eq!(
            overlay.get("impersonator"),
            Some(&serde_json::Value::String("admin".to_string()))
        );
        // Effective roles ride the realm_access argument.
        let realm_access = issuer.last_realm_access.lock().unwrap().clone().unwrap();
        assert_eq!(realm_access.roles, vec![issuerd_core::RoleName::new("reader").unwrap()]);

        // Session persisted with the impersonator recorded.
        let sessions = state
            .storage
            .list_sessions(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                Some(issuerd_core::UserId::new(&user_id).unwrap()),
                &issuerd_core::Pagination::default(),
            )
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].impersonator, Some(issuerd_core::UserId::new("admin").unwrap()));
        assert_eq!(sessions[0].auth_method, AuthMethod::Impersonation);
        assert!(!sessions[0].remember_me);

        // Login event + admin event recorded.
        let events = state
            .storage
            .query_events(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::EventQuery {
                    event_type: None,
                    client_id: None,
                    user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: issuerd_core::Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::Login);
        assert_eq!(events[0].details.get("impersonator").map(String::as_str), Some("admin"));

        let admin_events = state
            .storage
            .query_admin_events(
                &issuerd_core::RealmId::new("realm-1").unwrap(),
                &issuerd_core::AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: issuerd_core::Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(admin_events.len(), 1);
        assert_eq!(admin_events[0].operation_type, OperationType::Action);
        assert_eq!(admin_events[0].resource_path, format!("users/{user_id}/impersonation"));
        assert!(admin_events[0].representation.as_ref().unwrap().contains("impersonator"));
    }
}
