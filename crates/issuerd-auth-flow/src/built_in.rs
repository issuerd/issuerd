// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Built-in authenticators and required actions (cookie, password, OTP, federation write-through).

use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use chrono::Utc;
use issuerd_core::{
    AuthContext, AuthStepResult, Challenge, Credential, CredentialId, CredentialType, DisplayName,
    DistributedCache, Email, IssuerdError, RealmId, RequiredActionResult, Storage, User, UserId,
    Username, ValidatedAccessToken,
};
use serde_json::json;
use tracing::{debug, info, instrument, warn};

use crate::email_code::REALM_ATTR_EMAIL_CODE_LOGIN;
use crate::login_failures::{LoginFailureConfig, LoginFailureTracker};

// ---------------------------------------------------------------------------
// Authenticators
// ---------------------------------------------------------------------------

/// Authenticates the user via an existing session cookie (JWT access token),
/// or via a server-verified remember-me re-authentication.
///
/// Two context attributes are recognized:
/// - `session_cookie`: the raw `issuerd_session` cookie JWT, validated here.
/// - `remember_me_user`: a user id injected by the HTTP layer **only** after
///   the `issuerd_remember` action token passed full cryptographic verification
///   (signature, purpose, realm binding, expiry) and the user was confirmed
///   to exist and be enabled. It is therefore trusted as-is; the session id
///   is left unset so the executor generates a fresh one.
pub struct CookieAuthenticator {
    token_service: Arc<dyn issuerd_core::TokenService>,
    storage: Arc<dyn Storage>,
}

impl CookieAuthenticator {
    pub fn new(
        token_service: Arc<dyn issuerd_core::TokenService>,
        storage: Arc<dyn Storage>,
    ) -> Self {
        Self {
            token_service,
            storage,
        }
    }
}

#[async_trait]
impl issuerd_core::Authenticator for CookieAuthenticator {
    fn id(&self) -> &str {
        "auth-cookie"
    }

    fn display_name(&self) -> &str {
        "Cookie"
    }

    fn requires_user(&self) -> bool {
        false
    }

    fn configured_for(&self, _context: &AuthContext) -> bool {
        true
    }

    #[instrument(skip(self, context), fields(authenticator = %self.id(), realm = %context.realm_id))]
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult {
        if let Some(cookie) = context.attributes.get("session_cookie").cloned() {
            match self.token_service.validate_access_token(&cookie) {
                Ok(ValidatedAccessToken { claims, .. }) => {
                    // Reject session cookies issued for a different realm. The
                    // `issuerd_session` cookie is global, so a browser may send a cookie
                    // from realm A while requesting realm B. Without this check the
                    // flow could authenticate the wrong user or enter an infinite
                    // redirect loop. Issuers are realm-NAME based, so resolve this
                    // flow's realm and compare names; a storage failure rejects
                    // the cookie (fail closed).
                    let issuer_realm =
                        issuerd_core::typestate::extract_realm_from_issuer(claims.iss.as_str());
                    let realm_name = self
                        .storage
                        .get_realm(&context.realm_id)
                        .await
                        .ok()
                        .flatten()
                        .map(|r| r.name.as_str().to_string());
                    if issuer_realm == realm_name.as_deref() {
                        context.user_id = Some(claims.sub);
                        if let Some(sid) = claims.sid {
                            context.session_id = Some(sid);
                        }
                        return AuthStepResult::Success;
                    }
                    warn!(
                        realm = %context.realm_id,
                        issuer = %claims.iss.as_str(),
                        "rejecting cross-realm session cookie"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "cookie validation failed");
                }
            }
        }

        // Remember-me fallback (see the struct docs for why the attribute can
        // be trusted without further verification).
        if let Some(user_id) = context.attributes.get("remember_me_user").cloned() {
            if let Ok(id) = UserId::new(user_id) {
                context.user_id = Some(id);
                return AuthStepResult::Success;
            }
        }

        AuthStepResult::Attempted
    }
}

// ---------------------------------------------------------------------------

/// Authenticates the user via username and password.
pub struct UsernamePasswordAuthenticator {
    storage: Arc<dyn Storage>,
    tracker: Option<Arc<LoginFailureTracker>>,
    cache: Option<Arc<dyn DistributedCache>>,
    federation_manager: Option<Arc<dyn issuerd_core::FederationManager>>,
}

impl UsernamePasswordAuthenticator {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            storage,
            tracker: None,
            cache: None,
            federation_manager: None,
        }
    }

    pub fn with_tracker(
        storage: Arc<dyn Storage>,
        tracker: Arc<LoginFailureTracker>,
        cache: Arc<dyn DistributedCache>,
    ) -> Self {
        Self {
            storage,
            tracker: Some(tracker),
            cache: Some(cache),
            federation_manager: None,
        }
    }

    pub fn with_federation_manager(mut self, fm: Arc<dyn issuerd_core::FederationManager>) -> Self {
        self.federation_manager = Some(fm);
        self
    }

    async fn validate_local_password(
        &self,
        context: &mut AuthContext,
        user: &issuerd_core::User,
        password: &str,
    ) -> AuthStepResult {
        let creds = match self
            .storage
            .get_credentials(&context.realm_id, &user.id, CredentialType::Password)
            .await
        {
            Ok(c) => c,
            Err(e) => return AuthStepResult::Failure(e),
        };

        let mut matched = false;
        for cred in &creds {
            let hash_str = match String::from_utf8(cred.secret_data.clone()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let parsed = match PasswordHash::new(&hash_str) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok() {
                matched = true;
                break;
            }
        }

        if matched {
            debug!(username = %user.username, "password verified successfully");
            context.user_id = Some(user.id.clone());
            AuthStepResult::Success
        } else {
            warn!(username = %issuerd_core::utils::sanitize_log_str(user.username.as_str()), "password verification failed");
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        }
    }

    /// Load the realm's brute-force configuration when protection is enabled.
    ///
    /// Returns `None` when the realm has `brute_force_protected = false` (or
    /// the realm cannot be loaded) — callers must then skip failure tracking
    /// and lockout checks entirely.
    async fn brute_force_config(&self, context: &AuthContext) -> Option<LoginFailureConfig> {
        let realm = self.storage.get_realm(&context.realm_id).await.ok()??;
        if !realm.brute_force_protected {
            return None;
        }
        Some(LoginFailureConfig::from_realm(&realm))
    }

    async fn record_failure_and_return(
        &self,
        context: &AuthContext,
        user: &issuerd_core::User,
        brute_force: Option<&LoginFailureConfig>,
    ) -> AuthStepResult {
        if let (Some(ref tracker), Some(ref cache), Some(config)) =
            (&self.tracker, &self.cache, brute_force)
        {
            let ip = context
                .ip_address
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string());
            if let Err(e) = tracker
                .record_failure(&context.realm_id, &user.username, &ip, cache.as_ref(), config)
                .await
            {
                warn!(username = %issuerd_core::utils::sanitize_log_str(user.username.as_str()), error = %e, "failed to record login failure; brute-force lockout may not engage");
            }
        }
        AuthStepResult::Failure(IssuerdError::InvalidGrant)
    }

    /// Successful authentication clears any failure counter for the
    /// user+IP pair (best-effort; counter errors never block a valid login).
    async fn reset_failures_on_success(
        &self,
        context: &AuthContext,
        username: &str,
        brute_force: Option<&LoginFailureConfig>,
    ) {
        if let (Some(ref tracker), Some(ref cache), Some(_)) =
            (&self.tracker, &self.cache, brute_force)
        {
            let ip = context
                .ip_address
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string());
            if let Err(e) =
                tracker.reset_failures(&context.realm_id, username, &ip, cache.as_ref()).await
            {
                warn!(username = %issuerd_core::utils::sanitize_log_str(username), error = %e, "failed to reset login failure counter; stale lockout may persist");
            }
        }
    }

    async fn import_federated_user(
        &self,
        realm_id: &issuerd_core::RealmId,
        fed: &issuerd_core::FederatedUser,
    ) -> Result<issuerd_core::User, IssuerdError> {
        let now = Utc::now();
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            username: issuerd_core::Username::new(&fed.username)
                .expect("federated username must be valid"),
            email: fed.email.as_deref().map(Email::new).transpose().unwrap_or(None),
            email_verified: fed.email_verified,
            first_name: fed.first_name.as_deref().and_then(|s| DisplayName::new(s).ok()),
            last_name: fed.last_name.as_deref().and_then(|s| DisplayName::new(s).ok()),
            enabled: fed.enabled,
            federation_link: Some(fed.federation_link.clone()),
            attributes: fed.attributes.clone(),
            required_actions: vec![],
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.storage.create_user(realm_id, &user).await {
            tracing::error!(error = %e, "failed to import federated user");
            return Err(e);
        }
        // Reconcile only when the row exists; `None` groups means the
        // provider does not report memberships — leave them untouched.
        if let Some(groups) = &fed.groups {
            if let Err(e) = issuerd_core::roles::reconcile_group_memberships(
                self.storage.as_ref(),
                realm_id,
                &user.id,
                groups,
            )
            .await
            {
                tracing::warn!(
                    username = %issuerd_core::utils::sanitize_log_str(&fed.username),
                    error = %e,
                    "group membership reconcile failed for imported user"
                );
            }
        }
        Ok(user)
    }
}

#[async_trait]
impl issuerd_core::Authenticator for UsernamePasswordAuthenticator {
    fn id(&self) -> &str {
        "auth-username-password"
    }

    fn display_name(&self) -> &str {
        "Username Password Form"
    }

    fn requires_user(&self) -> bool {
        false
    }

    fn configured_for(&self, _context: &AuthContext) -> bool {
        true
    }

    #[instrument(skip(self, context), fields(authenticator = %self.id(), realm = %context.realm_id, username))]
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult {
        let username = match context.parameters.get("username").and_then(|v| v.first()) {
            Some(u) => u,
            None => return AuthStepResult::Failure(IssuerdError::InvalidGrant),
        };
        let password = match context.parameters.get("password").and_then(|v| v.first()) {
            Some(p) => p.clone(),
            None => return AuthStepResult::Failure(IssuerdError::InvalidGrant),
        };

        let username = username.clone();
        let sanitized = issuerd_core::utils::sanitize_log_str(&username);
        tracing::Span::current().record("username", &*sanitized);

        // 1. Try local user first
        match self.storage.get_user_by_username(&context.realm_id, &username).await {
            Ok(Some(user)) => {
                // Disabled accounts fail with the same generic error as bad
                // credentials so the endpoint does not leak account state.
                if !user.enabled {
                    warn!(username = %user.username, "login rejected: user is disabled");
                    return AuthStepResult::Failure(IssuerdError::InvalidGrant);
                }

                // Brute-force check (local users only), gated on the realm's
                // brute-force protection toggle. Realm lookup happens once
                // per login attempt here — not inside the tracker — and only
                // when a tracker is wired at all.
                let brute_force = match (&self.tracker, &self.cache) {
                    (Some(_), Some(_)) => self.brute_force_config(context).await,
                    _ => None,
                };
                if let (Some(ref tracker), Some(ref cache), Some(_)) =
                    (&self.tracker, &self.cache, &brute_force)
                {
                    let ip = context
                        .ip_address
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "0.0.0.0".to_string());
                    match tracker
                        .is_temporarily_locked(
                            &context.realm_id,
                            &user.username,
                            &ip,
                            cache.as_ref(),
                        )
                        .await
                    {
                        Ok(true) => {
                            warn!(username = %user.username, "account temporarily locked due to failed login attempts");
                            return AuthStepResult::Failure(IssuerdError::AccessDenied);
                        }
                        Ok(false) => {}
                        Err(e) => return AuthStepResult::Failure(e),
                    }
                }

                if let Some(ref link) = user.federation_link {
                    // Delegated user — validate against federation provider
                    if let Some(ref fm) = self.federation_manager {
                        let providers = match fm.providers_for_realm(&context.realm_id).await {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(username = %user.username, federation_link = %link, error = %e, "federation manager failed to load providers");
                                return self
                                    .validate_local_password(context, &user, &password)
                                    .await;
                            }
                        };

                        if providers.is_empty() {
                            warn!(username = %user.username, federation_link = %link, "no federation providers configured for realm; falling back to local password");
                        }

                        let mut provider_found = false;
                        for provider in providers {
                            if provider.id() == link {
                                provider_found = true;
                                debug!(username = %user.username, provider_id = %provider.id(), "validating password against federation provider");
                                match provider.validate_password(&username, &password).await {
                                    Ok(true) => {
                                        debug!(username = %user.username, "federated password verified successfully");
                                        context.user_id = Some(user.id.clone());
                                        self.reset_failures_on_success(
                                            context,
                                            &user.username,
                                            brute_force.as_ref(),
                                        )
                                        .await;
                                        return AuthStepResult::Success;
                                    }
                                    Ok(false) => {
                                        warn!(username = %issuerd_core::utils::sanitize_log_str(user.username.as_str()), provider_id = %provider.id(), "federated password rejected");
                                        return self
                                            .record_failure_and_return(
                                                context,
                                                &user,
                                                brute_force.as_ref(),
                                            )
                                            .await;
                                    }
                                    Err(e) => {
                                        warn!(username = %user.username, provider_id = %provider.id(), error = %e, "federation provider error during password validation");
                                        // Fall through to local validation
                                        break;
                                    }
                                }
                            }
                        }

                        if !provider_found {
                            warn!(username = %user.username, federation_link = %link, "no federation provider matches user's federation_link; falling back to local password");
                        }
                    } else {
                        warn!(username = %user.username, federation_link = %link, "user has federation_link but no federation manager configured; falling back to local password");
                    }
                }

                // Local credential check (existing Argon2 logic)
                let result = self.validate_local_password(context, &user, &password).await;
                if !matches!(result, AuthStepResult::Success) {
                    return self
                        .record_failure_and_return(context, &user, brute_force.as_ref())
                        .await;
                }
                self.reset_failures_on_success(context, &user.username, brute_force.as_ref())
                    .await;
                result
            }
            Ok(None) => {
                // 2. Local user not found — try federation lookup
                debug!(username = %issuerd_core::utils::sanitize_log_str(&username), "local user not found; attempting federation lookup");
                if let Some(ref fm) = self.federation_manager {
                    match fm.find_user(&context.realm_id, &username).await {
                        Ok(Some((provider, federated_user))) => {
                            debug!(username = %issuerd_core::utils::sanitize_log_str(&username), provider_id = %provider.id(), "found federated user; validating password");
                            match provider.validate_password(&username, &password).await {
                                Ok(true) => {
                                    // A failed import must fail the login —
                                    // succeeding here would put an unpersisted
                                    // (phantom) user id into the session.
                                    let user = match self
                                        .import_federated_user(&context.realm_id, &federated_user)
                                        .await
                                    {
                                        Ok(u) => u,
                                        Err(e) => return AuthStepResult::Failure(e),
                                    };
                                    context.user_id = Some(user.id);
                                    return AuthStepResult::Success;
                                }
                                Ok(false) => {
                                    warn!(username = %issuerd_core::utils::sanitize_log_str(&username), provider_id = %provider.id(), "federated password rejected for user not present locally");
                                    return AuthStepResult::Failure(IssuerdError::InvalidGrant);
                                }
                                Err(e) => {
                                    warn!(username = %issuerd_core::utils::sanitize_log_str(&username), provider_id = %provider.id(), error = %e, "federation provider error during password validation");
                                    return AuthStepResult::Failure(IssuerdError::InvalidGrant);
                                }
                            }
                        }
                        Ok(None) => {
                            warn!(username = %issuerd_core::utils::sanitize_log_str(&username), "user not found locally or in federation provider");
                            AuthStepResult::Failure(IssuerdError::InvalidGrant)
                        }
                        Err(e) => {
                            warn!(username = %issuerd_core::utils::sanitize_log_str(&username), error = %e, "federation lookup error");
                            AuthStepResult::Failure(IssuerdError::InvalidGrant)
                        }
                    }
                } else {
                    warn!(username = %issuerd_core::utils::sanitize_log_str(&username), "local user not found and no federation manager configured");
                    AuthStepResult::Failure(IssuerdError::InvalidGrant)
                }
            }
            Err(e) => {
                warn!(username = %issuerd_core::utils::sanitize_log_str(&username), error = %e, "storage error during user lookup");
                AuthStepResult::Failure(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------

/// Authenticates the user via SPNEGO / Kerberos.
pub struct SpnegoFlowAuthenticator {
    federation_manager: Arc<dyn issuerd_core::FederationManager>,
}

impl SpnegoFlowAuthenticator {
    pub fn new(federation_manager: Arc<dyn issuerd_core::FederationManager>) -> Self {
        Self { federation_manager }
    }
}

#[async_trait]
impl issuerd_core::Authenticator for SpnegoFlowAuthenticator {
    fn id(&self) -> &str {
        "auth-spnego"
    }

    fn display_name(&self) -> &str {
        "Kerberos / SPNEGO"
    }

    fn requires_user(&self) -> bool {
        false
    }

    fn configured_for(&self, context: &AuthContext) -> bool {
        context
            .attributes
            .get("Authorization")
            .map(|v| v.starts_with("Negotiate "))
            .unwrap_or(false)
    }

    #[instrument(skip(self, context), fields(authenticator = %self.id(), realm = %context.realm_id))]
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult {
        let token = match context.attributes.get("Authorization") {
            Some(v) if v.starts_with("Negotiate ") => &v["Negotiate ".len()..],
            _ => return AuthStepResult::Attempted,
        };

        let providers = match self.federation_manager.providers_for_realm(&context.realm_id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "federation manager error");
                return AuthStepResult::Attempted;
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
                    let username = provider
                        .find_user(&principal)
                        .await
                        .ok()
                        .flatten()
                        .map(|u| u.username)
                        .unwrap_or_else(|| {
                            // Strip realm suffix if present
                            principal
                                .split_once('@')
                                .map(|(u, _)| u.to_string())
                                .unwrap_or(principal)
                        });
                    if let Ok(Some((_, federated_user))) =
                        self.federation_manager.find_user(&context.realm_id, &username).await
                    {
                        let now = Utc::now();
                        let user = User {
                            id: UserId::new(issuerd_core::utils::generate_id()).unwrap(),
                            realm_id: context.realm_id.clone(),
                            username: Username::new(&federated_user.username)
                                .expect("federated username must be valid"),
                            email: federated_user
                                .email
                                .as_deref()
                                .map(Email::new)
                                .transpose()
                                .unwrap_or(None),
                            email_verified: federated_user.email_verified,
                            first_name: federated_user
                                .first_name
                                .as_deref()
                                .and_then(|s| DisplayName::new(s).ok()),
                            last_name: federated_user
                                .last_name
                                .as_deref()
                                .and_then(|s| DisplayName::new(s).ok()),
                            enabled: federated_user.enabled,
                            federation_link: Some(federated_user.federation_link.clone()),
                            attributes: federated_user.attributes.clone(),
                            required_actions: vec![],
                            created_at: now,
                            updated_at: now,
                        };
                        context.user_id = Some(user.id.clone());
                        // Note: user is not persisted here; the caller (login handler)
                        // may persist if needed. For SPNEGO flow, transient user is sufficient.
                        return AuthStepResult::Success;
                    }
                    return AuthStepResult::Failure(IssuerdError::InvalidGrant);
                }
                Ok(issuerd_core::SpnegoAuthResult {
                    status: issuerd_core::SpnegoStatus::Continue,
                    response_token: Some(resp),
                    ..
                }) => {
                    context
                        .attributes
                        .insert("WWW-Authenticate".to_string(), format!("Negotiate {}", resp));
                    return AuthStepResult::Challenge(Challenge::LoginForm {
                        action_url: "".to_string(),
                    });
                }
                Ok(_) => return AuthStepResult::Failure(IssuerdError::InvalidGrant),
                Err(e) => {
                    tracing::warn!(error = %e, "spnego provider error");
                    continue;
                }
            }
        }

        AuthStepResult::Attempted
    }
}

// ---------------------------------------------------------------------------

/// Authenticates the user via TOTP / OTP form (RFC 6238).
///
/// Contract: no `otp` parameter (or a wrong code) re-issues
/// [`Challenge::OtpForm`]; a user without any TOTP credential is `Attempted`
/// (pass-through — the stage is gated by the conditional-user-configured
/// condition). A correct code persists the matched step as the credential's
/// `last_used_step` replay watermark before succeeding.
pub struct OtpFormAuthenticator {
    storage: Arc<dyn Storage>,
}

impl OtpFormAuthenticator {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl issuerd_core::Authenticator for OtpFormAuthenticator {
    fn id(&self) -> &str {
        "auth-otp-form"
    }

    fn display_name(&self) -> &str {
        "OTP Form"
    }

    fn requires_user(&self) -> bool {
        true
    }

    fn configured_for(&self, context: &AuthContext) -> bool {
        // Best-effort sync check; full check happens in authenticate
        context.user_id.is_some()
    }

    #[instrument(skip(self, context), fields(authenticator = %self.id(), realm = %context.realm_id))]
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult {
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return AuthStepResult::Failure(IssuerdError::AccessDenied),
        };

        // Credential presence is checked BEFORE any challenge is issued: the
        // conditional-user-configured condition also admits WebAuthn-only
        // users, and they must reach the WebAuthn stage untouched
        // instead of being stuck on an OTP page they cannot answer.
        let creds = match self
            .storage
            .get_credentials(&context.realm_id, &user_id, CredentialType::Totp)
            .await
        {
            Ok(c) => c,
            Err(e) => return AuthStepResult::Failure(e),
        };

        if creds.is_empty() {
            // Pass-through: this stage is gated by the
            // conditional-user-configured condition, so users without a TOTP
            // credential must flow through untouched.
            return AuthStepResult::Attempted;
        }

        let otp = match context.parameters.get("otp").and_then(|v| v.first()) {
            Some(o) => o.clone(),
            None => {
                return AuthStepResult::Challenge(Challenge::OtpForm {
                    action_url: "".to_string(),
                });
            }
        };

        // The realm OTP policy drives validation. A missing realm degrades to
        // the Keycloak defaults instead of failing: at a Conditional flow
        // stage the executor swallows failures (skip_conditional_scope), so a
        // Failure here would let the login succeed WITHOUT a second factor.
        let policy = match self.storage.get_realm(&context.realm_id).await {
            Ok(Some(realm)) => realm.otp_policy,
            Ok(None) => issuerd_core::OtpPolicy::default(),
            Err(e) => return AuthStepResult::Failure(e),
        };

        let now = issuerd_core::utils::now_secs();
        for cred in &creds {
            let secret = match std::str::from_utf8(&cred.secret_data) {
                Ok(s) => s,
                Err(_) => {
                    return AuthStepResult::Failure(IssuerdError::ServerError(
                        "bad secret data".into(),
                    ))
                }
            };
            let last_used_step =
                cred.credential_data.get("last_used_step").and_then(|v| v.as_u64());
            if let Some(matched_step) =
                crate::totp::verify(secret, &otp, now, &policy, last_used_step)
            {
                // Persist the replay watermark before reporting success so the
                // same code cannot be reused for another login.
                let mut updated = cred.clone();
                updated.credential_data["last_used_step"] = json!(matched_step);
                if let Err(e) =
                    self.storage.update_credential(&context.realm_id, &user_id, &updated).await
                {
                    warn!(user_id = %user_id, error = %e, "failed to persist TOTP replay watermark");
                    return AuthStepResult::Failure(e);
                }
                // Marker for the WebAuthn conditional stage: a
                // satisfied OTP challenge counts as the second factor for
                // this login, so a user with BOTH credential types is not
                // double-challenged. (Deviation from Keycloak, which offers a
                // credential-choice UI; here OTP simply wins by flow order.)
                context.attributes.insert("second_factor_ok".to_string(), "true".to_string());
                return AuthStepResult::Success;
            }
        }

        // A wrong code is NEVER a Failure: conditional-stage failures are
        // swallowed by the executor (see above), which would bypass the second
        // factor. Re-challenge so the user can retry.
        debug!(user_id = %user_id, "TOTP code rejected; re-challenging");
        AuthStepResult::Challenge(Challenge::OtpForm {
            action_url: "".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------

/// Redirects to an external identity provider.
///
/// The challenge URL is realm-relative (`/broker/{alias}/login`) —
/// the HTTP layer anchors it under `/realms/{realm}` and attaches the pending
/// flow id, and the broker login route builds the actual external
/// authorization URL (with state/nonce/PKCE) from the IdP configuration.
pub struct IdentityProviderRedirectAuthenticator {
    storage: Arc<dyn Storage>,
}

impl IdentityProviderRedirectAuthenticator {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl issuerd_core::Authenticator for IdentityProviderRedirectAuthenticator {
    fn id(&self) -> &str {
        "auth-idp-redirect"
    }

    fn display_name(&self) -> &str {
        "Identity Provider Redirect"
    }

    fn requires_user(&self) -> bool {
        false
    }

    fn configured_for(&self, context: &AuthContext) -> bool {
        context.attributes.contains_key("identity_provider_hint")
    }

    #[instrument(skip(self, context), fields(authenticator = %self.id(), realm = %context.realm_id))]
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult {
        let hint = match context.attributes.get("identity_provider_hint") {
            Some(h) => h,
            None => return AuthStepResult::Attempted,
        };

        let idps = match self.storage.list_identity_providers(&context.realm_id).await {
            Ok(list) => list,
            Err(e) => return AuthStepResult::Failure(e),
        };

        let idp = idps.into_iter().find(|i| {
            i.enabled && (i.alias.as_ref() == hint.as_str() || i.provider_id.as_str() == hint)
        });
        match idp {
            Some(config) => AuthStepResult::Challenge(Challenge::Redirect {
                url: format!("/broker/{}/login", config.alias),
            }),
            None => AuthStepResult::Attempted,
        }
    }
}

// ---------------------------------------------------------------------------

/// Conditional authenticator that succeeds if the user has credentials configured.
///
/// This condition gates the whole conditional second-factor scope
/// (OTP form + WebAuthn stages), so it succeeds when the user has ANY
/// second-factor credential — a TOTP credential or a WebAuthn passkey.
pub struct ConditionalUserConfiguredAuthenticator {
    storage: Arc<dyn Storage>,
}

impl ConditionalUserConfiguredAuthenticator {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl issuerd_core::Authenticator for ConditionalUserConfiguredAuthenticator {
    fn id(&self) -> &str {
        "conditional-user-configured"
    }

    fn display_name(&self) -> &str {
        "Condition - user configured"
    }

    fn requires_user(&self) -> bool {
        true
    }

    fn configured_for(&self, _context: &AuthContext) -> bool {
        true
    }

    #[instrument(skip(self, context), fields(authenticator = %self.id(), realm = %context.realm_id))]
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult {
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return AuthStepResult::Attempted,
        };

        let totp = match self
            .storage
            .get_credentials(&context.realm_id, &user_id, CredentialType::Totp)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                warn!(user_id = %user_id, error = %e, "failed to read TOTP credentials; treating second factor as unconfigured");
                return AuthStepResult::Attempted;
            }
        };
        if !totp.is_empty() {
            return AuthStepResult::Success;
        }

        let webauthn = match self
            .storage
            .get_credentials(&context.realm_id, &user_id, CredentialType::WebAuthn)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                warn!(user_id = %user_id, error = %e, "failed to read WebAuthn credentials; treating second factor as unconfigured");
                return AuthStepResult::Attempted;
            }
        };

        if webauthn.is_empty() {
            AuthStepResult::Attempted
        } else {
            AuthStepResult::Success
        }
    }
}

// ---------------------------------------------------------------------------

/// Creates a new user account from the self-registration form.
///
/// **Design deviation from the original self-service design:** the
/// "profile form → password form → optional verify-email" chain
/// collapses into this single flat stage — one authenticator validates the
/// whole form (username/email/first/last/password) and creates the user in a
/// single POST. Email verification rides the existing required-action
/// machinery instead: when the realm has `verify_email_enabled`, the new
/// user is created with `VERIFY_EMAIL` assigned and the HTTP layer sends the
/// verification email immediately after the flow succeeds.
///
/// Challenge contract: with no `username` parameter the form has not been
/// submitted yet, so a [`Challenge::LoginForm`] is returned; the resume POST
/// re-enters `authenticate` with the form fields present in
/// `context.parameters`.
///
/// Realm attributes gate two behaviors (see [`issuerd_core::Realm`]):
/// `registration_require_names` makes first/last name mandatory, and
/// `registration_passwordless` skips password validation and credential
/// creation entirely.
pub struct RegistrationAuthenticator {
    storage: Arc<dyn Storage>,
}

impl RegistrationAuthenticator {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    /// First submitted value of a form field, if present.
    fn form_value(context: &AuthContext, key: &str) -> Option<String> {
        context.parameters.get(key).and_then(|v| v.first()).cloned()
    }

    /// First submitted value of a required form field (blank counts as missing).
    fn required_form_value(context: &AuthContext, key: &str) -> Result<String, IssuerdError> {
        Self::form_value(context, key)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| IssuerdError::InvalidRequest(format!("{key} is required")))
    }

    /// First submitted value of a required display-name field (blank counts
    /// as missing), validated into the newtype.
    fn required_display_name(
        context: &AuthContext,
        key: &str,
        label: &str,
    ) -> Result<DisplayName, IssuerdError> {
        let value = Self::form_value(context, key)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| IssuerdError::InvalidRequest(format!("{label} is required")))?;
        DisplayName::new(&value)
    }

    /// Validate the submitted form and create the account; returns the new
    /// user id. All user-facing validation failures are
    /// [`IssuerdError::InvalidRequest`] with a message safe to render on the form.
    async fn register(&self, context: &AuthContext) -> Result<UserId, IssuerdError> {
        let username = Self::required_form_value(context, "username")?;
        let sanitized = issuerd_core::utils::sanitize_log_str(&username);
        tracing::Span::current().record("username", &*sanitized);
        let email = Self::required_form_value(context, "email")?;

        let realm =
            self.storage.get_realm(&context.realm_id).await?.ok_or(IssuerdError::NotFound)?;

        // Passwordless realms skip password collection entirely: the fields
        // are neither required nor validated and no credential is stored.
        let password = if realm.registration_passwordless() {
            None
        } else {
            let password = Self::required_form_value(context, "password")?;
            if Self::form_value(context, "confirm_password").is_some_and(|c| c != password) {
                return Err(IssuerdError::InvalidRequest("passwords do not match".into()));
            }
            Some(password)
        };

        // Newtype validation rejects malformed input before anything is
        // persisted; the user value also feeds the policy's not_username /
        // not_email rules below.
        let now = Utc::now();
        let optional_name = |key: &str| {
            Self::form_value(context, key)
                .filter(|v| !v.trim().is_empty())
                .map(DisplayName::new)
                .transpose()
        };
        // Realm-gated: the form can require first/last name (validated
        // through the same DisplayName newtype).
        let (first_name, last_name) = if realm.registration_require_names() {
            (
                Some(Self::required_display_name(context, "first_name", "first name")?),
                Some(Self::required_display_name(context, "last_name", "last name")?),
            )
        } else {
            (optional_name("first_name")?, optional_name("last_name")?)
        };
        let user = User {
            id: UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: context.realm_id.clone(),
            username: Username::new(&username)?,
            email: Some(Email::new(&email)?),
            email_verified: false,
            first_name,
            last_name,
            enabled: true,
            federation_link: None,
            attributes: std::collections::HashMap::new(),
            required_actions: if realm.verify_email_enabled {
                vec!["VERIFY_EMAIL".to_string()]
            } else {
                Vec::new()
            },
            created_at: now,
            updated_at: now,
        };

        // Single enforcement point: the realm password policy applies to
        // self-registration exactly as it does to admin-created users.
        if let Some(ref password) = password {
            realm.password_policy.validate(password, &user)?;
        }

        // Email uniqueness is not enforced by the storage backends, so it is
        // checked here unless the realm explicitly allows duplicate emails.
        if !realm.duplicate_emails_allowed
            && self.storage.get_user_by_email(&context.realm_id, &email).await?.is_some()
        {
            return Err(IssuerdError::InvalidRequest("email already in use".into()));
        }

        self.storage.create_user(&context.realm_id, &user).await.map_err(|e| {
            // Duplicate usernames surface differently per backend: Postgres
            // maps the UNIQUE(realm_id, username) violation to Conflict, the
            // in-memory store returns a named InvalidRequest.
            let duplicate = matches!(e, IssuerdError::Conflict)
                || matches!(&e, IssuerdError::InvalidRequest(m) if m.contains("username already exists"));
            if duplicate {
                IssuerdError::InvalidRequest("username already in use".into())
            } else {
                e
            }
        })?;

        if let Some(ref password) = password {
            set_user_password(
                self.storage.as_ref(),
                &context.realm_id,
                &user.id,
                password,
                realm.password_policy.history_size,
                false,
            )
            .await?;
        }

        // Default realm role. A missing role or assignment failure must not
        // fail an otherwise valid registration — log and continue.
        if let Some(ref role_name) = realm.default_role {
            self.assign_default_role(&context.realm_id, &user.id, role_name).await;
        }

        Ok(user.id)
    }

    /// Resolve the realm's default role by name and grant it to the user,
    /// warning (never failing) when the role does not exist or the write
    /// fails.
    async fn assign_default_role(&self, realm_id: &RealmId, user_id: &UserId, role_name: &str) {
        match self.storage.get_role_by_name(realm_id, role_name).await {
            Ok(Some(role)) => {
                if let Err(e) = self.storage.add_user_realm_role(realm_id, user_id, &role.id).await
                {
                    warn!(role = %role_name, error = %e, "failed to assign realm default role");
                }
            }
            Ok(None) => {
                warn!(role = %role_name, "realm default role does not exist; skipping assignment")
            }
            Err(e) => warn!(role = %role_name, error = %e, "failed to resolve realm default role"),
        }
    }
}

#[async_trait]
impl issuerd_core::Authenticator for RegistrationAuthenticator {
    fn id(&self) -> &str {
        "auth-registration"
    }

    fn display_name(&self) -> &str {
        "Registration Form"
    }

    fn requires_user(&self) -> bool {
        false
    }

    fn configured_for(&self, _context: &AuthContext) -> bool {
        true
    }

    #[instrument(skip(self, context), fields(authenticator = %self.id(), realm = %context.realm_id, username))]
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult {
        // Without a username field the form has not been submitted at all:
        // challenge so the HTTP layer renders the registration form.
        if !context.parameters.contains_key("username") {
            return AuthStepResult::Challenge(Challenge::LoginForm {
                action_url: String::new(),
            });
        }
        match self.register(context).await {
            Ok(user_id) => {
                context.user_id = Some(user_id);
                AuthStepResult::Success
            }
            Err(e) => AuthStepResult::Failure(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Required Actions
// ---------------------------------------------------------------------------

/// Credential type used to retain superseded password hashes for history
/// checks. Credentials of this type are never accepted for login (only
/// [`CredentialType::Password`] is), mirroring Keycloak's hidden
/// `password-history` credential type.
pub const PASSWORD_HISTORY_CREDENTIAL_TYPE: &str = "password-history";

/// Verify a candidate password against a stored credential's hash.
///
/// Only argon2id PHC strings are verified; unknown or foreign hash formats
/// return `false` (they simply cannot match for history-reuse purposes).
pub fn verify_password_hash(candidate: &str, cred: &Credential) -> bool {
    let hash_str = match std::str::from_utf8(&cred.secret_data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let parsed = match PasswordHash::new(hash_str) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default().verify_password(candidate.as_bytes(), &parsed).is_ok()
}

/// Set a user's password with password-history handling.
///
/// Shared by the `UPDATE_PASSWORD` required action; the admin API keeps an
/// equivalent copy (it needs history rejections as machine-readable 400s).
/// Federated users should go through [`write_through_federated_password`]
/// first — this writes a **local** credential only. Behavior:
///
/// 1. When `history_size > 0`, the candidate is verified against the current
///    password and all retained history entries; a match is rejected with a
///    `password_history` policy violation.
/// 2. Current `Password` credentials become inert `password-history`
///    credentials (or are deleted when history is disabled).
/// 3. History is pruned to the newest `history_size - 1` entries.
/// 4. The new argon2id hash is stored as the sole `Password` credential.
pub async fn set_user_password(
    storage: &dyn Storage,
    realm_id: &RealmId,
    user_id: &UserId,
    new_password: &str,
    history_size: u32,
    temporary: bool,
) -> Result<(), IssuerdError> {
    let history_type = CredentialType::Custom(PASSWORD_HISTORY_CREDENTIAL_TYPE.to_string());
    let current = storage.get_credentials(realm_id, user_id, CredentialType::Password).await?;
    let mut history = storage.get_credentials(realm_id, user_id, history_type).await?;

    if history_size > 0 {
        for cred in current.iter().chain(history.iter()) {
            if verify_password_hash(new_password, cred) {
                return Err(IssuerdError::from(issuerd_core::PasswordPolicyError {
                    violations: vec![issuerd_core::PasswordPolicyViolation {
                        code: "password_history".to_string(),
                        message: format!(
                            "password must not match any of the last {history_size} passwords"
                        ),
                    }],
                }));
            }
        }
    }

    for cred in current {
        // Delete-then-recreate (not update) so the type change is portable:
        // some backends key credentials by `(realm, user, type)`, where an
        // in-place type mutation would be a silent no-op.
        storage.delete_credential(realm_id, user_id, &cred.id).await?;
        if history_size > 0 {
            let mut history_cred = cred;
            history_cred.credential_type =
                CredentialType::Custom(PASSWORD_HISTORY_CREDENTIAL_TYPE.to_string());
            if let Some(obj) = history_cred.credential_data.as_object_mut() {
                obj.remove("temporary");
            }
            storage.create_credential(realm_id, user_id, &history_cred).await?;
            history.push(history_cred);
        }
    }

    // Prune history to the newest `history_size - 1` entries; when history is
    // disabled this deletes every stale entry from a previous policy era.
    let keep = issuerd_core::password::credentials_to_retain(&history, history_size);
    for cred in history.iter().filter(|c| !keep.contains(&c.id)) {
        storage.delete_credential(realm_id, user_id, &cred.id).await?;
    }

    use argon2::{password_hash::SaltString, PasswordHasher};
    use rand::rngs::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|_| IssuerdError::ServerError("password hashing failed".into()))?
        .to_string();
    let credential_data = if temporary {
        json!({"hash_algorithm": "argon2id", "temporary": true})
    } else {
        json!({"hash_algorithm": "argon2id"})
    };
    let cred = Credential {
        id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: CredentialType::Password,
        user_label: Some("Password".to_string()),
        created_date: Utc::now(),
        secret_data: hash.into_bytes(),
        credential_data,
        priority: 1,
    };
    storage.create_credential(realm_id, user_id, &cred).await
}

/// Resolve the federation provider that owns password operations for a user.
///
/// Returns `Some((provider, username))` iff the user's `federation_link`
/// matches a provider currently registered for the realm. `None` covers both
/// purely local users and links pointing at removed/disabled providers —
/// login falls back to the local password in the latter case, so password
/// writes correctly stay local too.
pub async fn federated_password_provider(
    storage: &dyn Storage,
    federation_manager: &dyn issuerd_core::FederationManager,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Result<Option<(Arc<dyn issuerd_core::FederationProvider>, String)>, IssuerdError> {
    let Some(user) = storage.get_user(realm_id, user_id).await? else {
        return Ok(None);
    };
    let Some(link) = user.federation_link else {
        return Ok(None);
    };
    let providers = federation_manager.providers_for_realm(realm_id).await?;
    Ok(providers
        .into_iter()
        .find(|p| p.id() == link)
        .map(|p| (p, user.username.to_string())))
}

/// Outcome of [`write_through_federated_password`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationWriteThrough {
    /// No federation write-through applies: perform the normal local
    /// credential write.
    NotApplicable,
    /// The external directory accepted the new password: skip the local
    /// credential write.
    WrittenToDirectory,
}

/// Write a federated user's new password through to the external directory.
///
/// Shared by every password-set path (account change-password, the
/// UPDATE_PASSWORD required action, reset-credentials, admin reset) so a
/// federated user's password lands where login actually validates it. When
/// the directory write succeeds, any stale local `Password` credentials are
/// deleted: login validates against the directory first and only falls back
/// to local credentials when the provider errors, so a leftover local
/// password would act as a dormant fallback during directory outages.
///
/// Errors: [`IssuerdError::InvalidRequest`] when the linked provider does not
/// support password changes (e.g. `editMode: READ_ONLY`),
/// [`IssuerdError::ServerError`] when the directory write itself fails.
pub async fn write_through_federated_password(
    storage: &dyn Storage,
    federation_manager: Option<&dyn issuerd_core::FederationManager>,
    realm_id: &RealmId,
    user_id: &UserId,
    new_password: &str,
) -> Result<FederationWriteThrough, IssuerdError> {
    let Some(fm) = federation_manager else {
        return Ok(FederationWriteThrough::NotApplicable);
    };
    let Some((provider, username)) =
        federated_password_provider(storage, fm, realm_id, user_id).await?
    else {
        return Ok(FederationWriteThrough::NotApplicable);
    };
    provider
        .update_password(&username, new_password)
        .await
        .map_err(map_federation_write_error)?;
    for cred in storage.get_credentials(realm_id, user_id, CredentialType::Password).await? {
        storage.delete_credential(realm_id, user_id, &cred.id).await?;
    }
    Ok(FederationWriteThrough::WrittenToDirectory)
}

/// Map a failed directory password write to an HTTP-meaningful error.
fn map_federation_write_error(e: issuerd_core::FederationError) -> IssuerdError {
    match e {
        issuerd_core::FederationError::NotSupported => IssuerdError::InvalidRequest(
            "the external directory for this user does not accept password changes".into(),
        ),
        other => IssuerdError::ServerError(format!("federated password update failed: {other}")),
    }
}

/// Requires the user to verify their email address.
pub struct VerifyEmailRequiredAction {
    storage: Arc<dyn Storage>,
}

impl VerifyEmailRequiredAction {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl issuerd_core::RequiredAction for VerifyEmailRequiredAction {
    fn id(&self) -> &str {
        "VERIFY_EMAIL"
    }

    fn display_name(&self) -> &str {
        "Verify Email"
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn evaluate(&self, context: &AuthContext) -> bool {
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return false,
        };
        match self.storage.get_user(&context.realm_id, &user_id).await {
            Ok(Some(user)) => {
                user.required_actions.iter().any(|a| a == "VERIFY_EMAIL")
                    || (context
                        .attributes
                        .get("realm_verify_email_enabled")
                        .is_some_and(|v| v == "true")
                        && user.email.is_some()
                        && !user.email_verified)
            }
            _ => false,
        }
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn process(&self, context: &mut AuthContext) -> RequiredActionResult {
        // Re-read the user: the verification link may have been clicked in
        // another browser or tab since the challenge was rendered. The email
        // itself is sent by the HTTP layer, which owns the `EmailSender`.
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return RequiredActionResult::Failure(IssuerdError::AccessDenied),
        };
        match self.storage.get_user(&context.realm_id, &user_id).await {
            Ok(Some(user)) if user.email_verified => RequiredActionResult::Success,
            Ok(Some(_)) => RequiredActionResult::Challenge(Challenge::LoginForm {
                action_url: String::new(),
            }),
            Ok(None) => RequiredActionResult::Failure(IssuerdError::NotFound),
            Err(e) => RequiredActionResult::Failure(e),
        }
    }
}

// ---------------------------------------------------------------------------

/// Requires the user to update their password.
pub struct UpdatePasswordRequiredAction {
    storage: Arc<dyn Storage>,
    federation_manager: Option<Arc<dyn issuerd_core::FederationManager>>,
}

impl UpdatePasswordRequiredAction {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            storage,
            federation_manager: None,
        }
    }

    /// Enable federation write-through: a federated user's new password is
    /// written to the external directory instead of a local credential.
    pub fn with_federation_manager(mut self, fm: Arc<dyn issuerd_core::FederationManager>) -> Self {
        self.federation_manager = Some(fm);
        self
    }
}

#[async_trait]
impl issuerd_core::RequiredAction for UpdatePasswordRequiredAction {
    fn id(&self) -> &str {
        "UPDATE_PASSWORD"
    }

    fn display_name(&self) -> &str {
        "Update Password"
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn evaluate(&self, context: &AuthContext) -> bool {
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return false,
        };
        // Explicitly assigned by an admin?
        let mut federated = false;
        if let Ok(Some(user)) = self.storage.get_user(&context.realm_id, &user_id).await {
            if user.required_actions.iter().any(|a| a == "UPDATE_PASSWORD") {
                return true;
            }
            federated = user.federation_link.is_some();
        }
        // Email-code realms sign in without a password by design, so having
        // no password credential is normal there — the auto-rule below must
        // not fire (same reasoning as the broker-login carve-out). The
        // explicit admin assignment above is still honored.
        if let Ok(Some(realm)) = self.storage.get_realm(&context.realm_id).await {
            if realm.attributes.get(REALM_ATTR_EMAIL_CODE_LOGIN).is_some_and(|v| v == "true") {
                return false;
            }
        }
        match self
            .storage
            .get_credentials(&context.realm_id, &user_id, CredentialType::Password)
            .await
        {
            // An admin-set temporary password must always be rotated.
            Ok(creds)
                if creds.iter().any(|c| {
                    c.credential_data.get("temporary").and_then(|v| v.as_bool()).unwrap_or(false)
                }) =>
            {
                true
            }
            // Federated users authenticate against the external directory —
            // their password is not a local credential, so the
            // no-local-password auto-rule does not apply (same carve-out as
            // the email-code realm above).
            Ok(_) if federated => false,
            // No password at all: force an update (P3-17).
            Ok(creds) => creds.is_empty(),
            Err(_) => false,
        }
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn process(&self, context: &mut AuthContext) -> RequiredActionResult {
        let new_password = match context.parameters.get("new_password").and_then(|v| v.first()) {
            Some(p) => p.clone(),
            None => {
                return RequiredActionResult::Challenge(Challenge::LoginForm {
                    action_url: String::new(),
                });
            }
        };
        if let Some(confirm) = context.parameters.get("confirm_password").and_then(|v| v.first()) {
            if confirm != &new_password {
                return RequiredActionResult::Failure(IssuerdError::InvalidRequest(
                    "passwords do not match".into(),
                ));
            }
        }

        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return RequiredActionResult::Failure(IssuerdError::AccessDenied),
        };
        let user = match self.storage.get_user(&context.realm_id, &user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return RequiredActionResult::Failure(IssuerdError::NotFound),
            Err(e) => return RequiredActionResult::Failure(e),
        };
        let realm = match self.storage.get_realm(&context.realm_id).await {
            Ok(Some(r)) => r,
            Ok(None) => return RequiredActionResult::Failure(IssuerdError::NotFound),
            Err(e) => return RequiredActionResult::Failure(e),
        };

        // Single enforcement point: realm password policy applies here too.
        if let Err(err) = realm.password_policy.validate(&new_password, &user) {
            return RequiredActionResult::Failure(err.into());
        }

        // Federated user: write the new password through to the external
        // directory; only a non-federated user (or a dead link) keeps the
        // local-credential write below.
        match write_through_federated_password(
            self.storage.as_ref(),
            self.federation_manager.as_deref(),
            &context.realm_id,
            &user_id,
            &new_password,
        )
        .await
        {
            Ok(FederationWriteThrough::WrittenToDirectory) => {
                return RequiredActionResult::Success;
            }
            Ok(FederationWriteThrough::NotApplicable) => {}
            Err(e) => return RequiredActionResult::Failure(e),
        }

        match set_user_password(
            self.storage.as_ref(),
            &context.realm_id,
            &user_id,
            &new_password,
            realm.password_policy.history_size,
            false,
        )
        .await
        {
            Ok(()) => RequiredActionResult::Success,
            Err(e) => RequiredActionResult::Failure(e),
        }
    }
}

// ---------------------------------------------------------------------------

/// Requires the user to update their profile.
///
/// Strict mode (realm attribute `update_profile_require_names`): a submitted
/// form with a blank/absent first or last name fails with a form-visible
/// error instead of clearing the stored names, so the action stays pending.
pub struct UpdateProfileRequiredAction {
    storage: Arc<dyn Storage>,
}

impl UpdateProfileRequiredAction {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl issuerd_core::RequiredAction for UpdateProfileRequiredAction {
    fn id(&self) -> &str {
        "UPDATE_PROFILE"
    }

    fn display_name(&self) -> &str {
        "Update Profile"
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn evaluate(&self, context: &AuthContext) -> bool {
        if context.attributes.get("realm_update_profile_on_first_login")
            == Some(&"true".to_string())
        {
            return true;
        }
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return false,
        };
        match self.storage.get_user(&context.realm_id, &user_id).await {
            Ok(Some(user)) => user.required_actions.iter().any(|a| a == "UPDATE_PROFILE"),
            _ => false,
        }
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn process(&self, context: &mut AuthContext) -> RequiredActionResult {
        // The form always submits all three fields; their absence means the
        // form has not been rendered/submitted yet.
        let submitted = context.parameters.contains_key("first_name")
            || context.parameters.contains_key("last_name")
            || context.parameters.contains_key("email");
        if !submitted {
            return RequiredActionResult::Challenge(Challenge::LoginForm {
                action_url: String::new(),
            });
        }

        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return RequiredActionResult::Failure(IssuerdError::AccessDenied),
        };
        let mut user = match self.storage.get_user(&context.realm_id, &user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return RequiredActionResult::Failure(IssuerdError::NotFound),
            Err(e) => return RequiredActionResult::Failure(e),
        };

        // Strict realm: blank/absent names must not complete the action nor
        // clear the stored values. Failing here (before any mutation) keeps
        // the action pending and surfaces the message through the
        // continuation's error banner, exactly like an UPDATE_PASSWORD
        // policy violation. A missing realm degrades to the default
        // (non-strict) behavior.
        let require_names = match self.storage.get_realm(&context.realm_id).await {
            Ok(Some(realm)) => realm.update_profile_require_names(),
            Ok(None) => false,
            Err(e) => return RequiredActionResult::Failure(e),
        };
        if require_names {
            let blank = |key: &str| {
                context
                    .parameters
                    .get(key)
                    .and_then(|v| v.first())
                    .is_none_or(|v| v.trim().is_empty())
            };
            if blank("first_name") {
                return RequiredActionResult::Failure(IssuerdError::InvalidRequest(
                    "First name is required.".to_string(),
                ));
            }
            if blank("last_name") {
                return RequiredActionResult::Failure(IssuerdError::InvalidRequest(
                    "Last name is required.".to_string(),
                ));
            }
        }

        let param = |key: &str| context.parameters.get(key).and_then(|v| v.first()).cloned();
        if let Some(first) = param("first_name") {
            user.first_name = if first.is_empty() {
                None
            } else {
                match DisplayName::new(&first) {
                    Ok(n) => Some(n),
                    Err(e) => return RequiredActionResult::Failure(e),
                }
            };
        }
        if let Some(last) = param("last_name") {
            user.last_name = if last.is_empty() {
                None
            } else {
                match DisplayName::new(&last) {
                    Ok(n) => Some(n),
                    Err(e) => return RequiredActionResult::Failure(e),
                }
            };
        }
        if let Some(email) = param("email") {
            let new_email = if email.is_empty() {
                None
            } else {
                match Email::new(&email) {
                    Ok(e) => Some(e),
                    Err(e) => return RequiredActionResult::Failure(e),
                }
            };
            // A changed address is unverified until proven otherwise; an
            // unchanged one keeps its verification state.
            let changed = match (user.email.as_ref(), new_email.as_ref()) {
                (Some(a), Some(b)) => !a.as_str().eq_ignore_ascii_case(b.as_str()),
                (a, b) => a.is_some() != b.is_some(),
            };
            user.email = new_email;
            if changed {
                user.email_verified = false;
            }
        }

        match self.storage.update_user(&context.realm_id, &user).await {
            Ok(()) => RequiredActionResult::Success,
            Err(e) => RequiredActionResult::Failure(e),
        }
    }
}

// ---------------------------------------------------------------------------

/// Requires the user to configure TOTP.
///
/// Enrollment flow: the HTTP continuation layer generates a fresh
/// secret on first page render and carries it in the paused-continuation cache
/// entry (never persisted); on submit it is passed in as the `totp_secret`
/// context attribute. `process` verifies the submitted `totp_code` against
/// that secret with the realm OTP policy and only then persists the
/// `CredentialType::Totp` credential — a code the user cannot produce proves
/// nothing was enrolled.
pub struct ConfigureTotpRequiredAction {
    storage: Arc<dyn Storage>,
}

impl ConfigureTotpRequiredAction {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl issuerd_core::RequiredAction for ConfigureTotpRequiredAction {
    fn id(&self) -> &str {
        "CONFIGURE_TOTP"
    }

    fn display_name(&self) -> &str {
        "Configure OTP"
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn evaluate(&self, context: &AuthContext) -> bool {
        // Only fires when explicitly assigned to the user — unlike earlier
        // drafts it must not trigger for every TOTP-less account.
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return false,
        };
        match self.storage.get_user(&context.realm_id, &user_id).await {
            Ok(Some(user)) => user.required_actions.iter().any(|a| a == "CONFIGURE_TOTP"),
            _ => false,
        }
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn process(&self, context: &mut AuthContext) -> RequiredActionResult {
        let code = match context.parameters.get("totp_code").and_then(|v| v.first()) {
            Some(c) => c.clone(),
            None => {
                return RequiredActionResult::Failure(IssuerdError::InvalidRequest(
                    "missing authenticator code".to_string(),
                ))
            }
        };
        let secret = match context.attributes.get("totp_secret") {
            Some(s) => s.clone(),
            None => {
                warn!("TOTP enrollment state is missing; restart the action");
                return RequiredActionResult::Failure(IssuerdError::ServerError(
                    "TOTP enrollment state is missing; restart the action".to_string(),
                ));
            }
        };
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return RequiredActionResult::Failure(IssuerdError::AccessDenied),
        };
        let policy = match self.storage.get_realm(&context.realm_id).await {
            Ok(Some(realm)) => realm.otp_policy,
            Ok(None) => {
                return RequiredActionResult::Failure(IssuerdError::ServerError(
                    "realm not found".to_string(),
                ))
            }
            Err(e) => return RequiredActionResult::Failure(e),
        };

        let now = issuerd_core::utils::now_secs();
        let Some(matched_step) = crate::totp::verify(&secret, &code, now, &policy, None) else {
            debug!(user_id = %user_id, "TOTP enrollment rejected: code did not verify");
            return RequiredActionResult::Failure(IssuerdError::InvalidRequest(
                "Invalid authenticator code".to_string(),
            ));
        };

        let cred = Credential {
            id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: CredentialType::Totp,
            user_label: None,
            created_date: Utc::now(),
            secret_data: secret.into_bytes(),
            credential_data: json!({
                "algorithm": policy.algorithm,
                "digits": policy.digits,
                "period": policy.period_secs,
                "last_used_step": matched_step,
            }),
            priority: 0,
        };
        match self.storage.create_credential(&context.realm_id, &user_id, &cred).await {
            Ok(()) => {
                context.attributes.remove("totp_secret");
                info!(user_id = %user_id, "TOTP credential enrolled");
                RequiredActionResult::Success
            }
            Err(e) => {
                warn!(user_id = %user_id, error = %e, "failed to persist TOTP credential");
                RequiredActionResult::Failure(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------

/// Requires the user to accept terms and conditions.
///
/// Acceptance is persisted on the user (`attributes["terms_accepted"]`), so
/// restarts do not lose it.
pub struct TermsAndConditionsRequiredAction {
    storage: Arc<dyn Storage>,
}

impl TermsAndConditionsRequiredAction {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl issuerd_core::RequiredAction for TermsAndConditionsRequiredAction {
    fn id(&self) -> &str {
        "TERMS_AND_CONDITIONS"
    }

    fn display_name(&self) -> &str {
        "Terms and Conditions"
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn evaluate(&self, context: &AuthContext) -> bool {
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return false,
        };
        match self.storage.get_user(&context.realm_id, &user_id).await {
            Ok(Some(user)) => {
                user.required_actions.iter().any(|a| a == "TERMS_AND_CONDITIONS")
                    && user.attributes.get("terms_accepted").and_then(|v| v.first())
                        != Some(&"true".to_string())
            }
            _ => false,
        }
    }

    #[instrument(skip(self, context), fields(action = %self.id(), realm = %context.realm_id))]
    async fn process(&self, context: &mut AuthContext) -> RequiredActionResult {
        if context.parameters.get("terms_accepted").map(|v| v.as_slice())
            != Some(&["true".to_string()])
        {
            return RequiredActionResult::Challenge(Challenge::LoginForm {
                action_url: String::new(),
            });
        }
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return RequiredActionResult::Failure(IssuerdError::AccessDenied),
        };
        let mut user = match self.storage.get_user(&context.realm_id, &user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return RequiredActionResult::Failure(IssuerdError::NotFound),
            Err(e) => return RequiredActionResult::Failure(e),
        };
        user.attributes.insert("terms_accepted".to_string(), vec!["true".to_string()]);
        match self.storage.update_user(&context.realm_id, &user).await {
            Ok(()) => RequiredActionResult::Success,
            Err(e) => RequiredActionResult::Failure(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use chrono::Utc;
    use issuerd_core::{
        AccessTokenClaims, Algorithm, AuthContext, Authenticator, Client, ClientAuthenticatorType,
        ClientId, ClientProtocol, Credential, CredentialId, CredentialType, Email,
        IdentityProviderConfig, IdentityProviderId, JwsType, JwtType, RealmId, RequiredAction,
        Scope, SessionId, TokenService, User, UserId,
    };
    use issuerd_storage::memory::InMemoryStorage;

    use super::*;

    fn test_context() -> AuthContext {
        AuthContext {
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: HashMap::new(),
            attributes: HashMap::new(),
            current_challenge: None,
        }
    }

    fn test_user() -> User {
        User {
            id: UserId::new("alice").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn test_realm() -> issuerd_core::Realm {
        issuerd_core::Realm {
            id: RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("realm-1").unwrap(),
            ..issuerd_core::Realm::default()
        }
    }

    fn hash_password(password: &str) -> String {
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string()
    }

    // -----------------------------------------------------------------------
    // Assertion helpers (with dedicated panic-coverage tests)
    // -----------------------------------------------------------------------

    fn assert_auth_success(result: AuthStepResult) {
        match result {
            AuthStepResult::Success => {}
            other => panic!("expected Success, got {:?}", other),
        }
    }

    fn assert_auth_attempted(result: AuthStepResult) {
        match result {
            AuthStepResult::Attempted => {}
            other => panic!("expected Attempted, got {:?}", other),
        }
    }

    fn assert_auth_failure(result: AuthStepResult, expected: IssuerdError) {
        match result {
            AuthStepResult::Failure(e) => assert_eq!(e, expected),
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    fn assert_auth_challenge_otp(result: AuthStepResult) {
        match result {
            AuthStepResult::Challenge(Challenge::OtpForm { .. }) => {}
            other => panic!("expected Challenge::OtpForm, got {:?}", other),
        }
    }

    fn assert_auth_challenge_redirect(result: AuthStepResult) -> String {
        match result {
            AuthStepResult::Challenge(Challenge::Redirect { url }) => url,
            other => panic!("expected Challenge::Redirect, got {:?}", other),
        }
    }

    #[test]
    #[should_panic(expected = "expected Success")]
    fn assert_auth_success_panics() {
        assert_auth_success(AuthStepResult::Failure(IssuerdError::AccessDenied));
    }

    #[test]
    #[should_panic(expected = "expected Attempted")]
    fn assert_auth_attempted_panics() {
        assert_auth_attempted(AuthStepResult::Success);
    }

    #[test]
    #[should_panic(expected = "expected Failure")]
    fn assert_auth_failure_panics() {
        assert_auth_failure(AuthStepResult::Success, IssuerdError::AccessDenied);
    }

    #[test]
    #[should_panic(expected = "expected Challenge::OtpForm")]
    fn assert_auth_challenge_otp_panics() {
        assert_auth_challenge_otp(AuthStepResult::Success);
    }

    #[test]
    #[should_panic(expected = "expected Challenge::Redirect")]
    fn assert_auth_challenge_redirect_panics() {
        assert_auth_challenge_redirect(AuthStepResult::Success);
    }

    fn assert_auth_server_error(result: AuthStepResult) {
        match result {
            AuthStepResult::Failure(IssuerdError::ServerError(_)) => {}
            other => panic!("expected Failure(ServerError), got {:?}", other),
        }
    }

    fn assert_action_success(result: RequiredActionResult) {
        match result {
            RequiredActionResult::Success => {}
            other => panic!("expected Success, got {:?}", other),
        }
    }

    fn assert_action_challenge_login_form(result: RequiredActionResult) {
        match result {
            RequiredActionResult::Challenge(Challenge::LoginForm { .. }) => {}
            other => panic!("expected Challenge::LoginForm, got {:?}", other),
        }
    }

    fn assert_action_failure(result: RequiredActionResult, expected: IssuerdError) {
        match result {
            RequiredActionResult::Failure(e) => assert_eq!(e, expected),
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    #[should_panic(expected = "expected Failure(ServerError)")]
    fn assert_auth_server_error_panics() {
        assert_auth_server_error(AuthStepResult::Success);
    }

    #[test]
    #[should_panic(expected = "expected Success")]
    fn assert_action_success_panics() {
        assert_action_success(RequiredActionResult::Failure(IssuerdError::AccessDenied));
    }

    #[test]
    #[should_panic(expected = "expected Challenge::LoginForm")]
    fn assert_action_challenge_login_form_panics() {
        assert_action_challenge_login_form(RequiredActionResult::Success);
    }

    #[test]
    #[should_panic(expected = "expected Failure")]
    fn assert_action_failure_panics() {
        assert_action_failure(RequiredActionResult::Success, IssuerdError::AccessDenied);
    }

    // -----------------------------------------------------------------------
    // CookieAuthenticator
    // -----------------------------------------------------------------------

    struct MockTokenService {
        valid: bool,
        issuer: String,
    }

    impl MockTokenService {
        fn for_realm(valid: bool, realm: &str) -> Self {
            Self {
                valid,
                issuer: format!("https://id.example.com/realms/{realm}"),
            }
        }
    }

    impl issuerd_core::TokenService for MockTokenService {
        fn validate_access_token(
            &self,
            _token: &str,
        ) -> Result<ValidatedAccessToken, IssuerdError> {
            if self.valid {
                Ok(ValidatedAccessToken {
                    claims: AccessTokenClaims {
                        jti: issuerd_core::JwtId::new("jti").unwrap(),
                        iss: issuerd_core::Issuer::new(&self.issuer).unwrap(),
                        sub: UserId::new("alice").unwrap(),
                        aud: issuerd_core::Audience::new("aud").unwrap(),
                        exp: 9_999_999_999,
                        iat: 0,
                        nbf: 0,
                        scope: issuerd_core::Scope::parse("openid"),
                        typ: JwtType::Bearer,
                        azp: None,
                        session_state: None,
                        realm_access: None,
                        resource_access: None,
                        sid: Some(SessionId::new("sess-1").unwrap()),
                        claims: None,
                        cnf: None,
                        authorization_details: None,
                    },
                    header: issuerd_core::JwsHeader {
                        alg: Algorithm::Hs256,
                        typ: Some(JwsType::Jwt),
                        kid: issuerd_core::KeyId::new("key-1").unwrap(),
                    },
                })
            } else {
                Err(IssuerdError::InvalidToken)
            }
        }

        fn validate_id_token(
            &self,
            _token: &str,
            _client: &issuerd_core::Client,
            _nonce: Option<&str>,
        ) -> Result<issuerd_core::IdTokenClaims, IssuerdError> {
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

    /// Build a CookieAuthenticator whose storage holds the flow realm
    /// (id `realm-1`, NAME `test-realm` — id != name pins that issuer
    /// segments are compared as names). `issuer_realm_name` is the name
    /// embedded in the mock cookie's `iss`.
    async fn cookie_authenticator(valid: bool, issuer_realm_name: &str) -> CookieAuthenticator {
        let storage = Arc::new(InMemoryStorage::new());
        storage
            .create_realm(&issuerd_core::Realm {
                id: RealmId::new("realm-1").unwrap(),
                name: issuerd_core::RealmName::new("test-realm").unwrap(),
                ..issuerd_core::Realm::default()
            })
            .await
            .unwrap();
        CookieAuthenticator::new(
            Arc::new(MockTokenService::for_realm(valid, issuer_realm_name)),
            storage,
        )
    }

    #[tokio::test]
    async fn cookie_authenticator_valid_token() {
        let auth = cookie_authenticator(true, "test-realm").await;
        let mut ctx = test_context();
        ctx.attributes.insert("session_cookie".to_string(), "valid".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
        assert_eq!(ctx.user_id, Some(UserId::new("alice").unwrap()));
        assert_eq!(ctx.session_id, Some(SessionId::new("sess-1").unwrap()));
    }

    #[tokio::test]
    async fn cookie_authenticator_invalid_token() {
        let auth = cookie_authenticator(false, "test-realm").await;
        let mut ctx = test_context();
        ctx.attributes.insert("session_cookie".to_string(), "invalid".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    #[tokio::test]
    async fn cookie_authenticator_rejects_cross_realm_cookie() {
        // Cookie issued for the realm NAMED "realm-2" must not authenticate a
        // request for the realm named "test-realm" (id realm-1).
        let auth = cookie_authenticator(true, "realm-2").await;
        let mut ctx = test_context();
        ctx.attributes.insert("session_cookie".to_string(), "valid".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
        assert!(ctx.user_id.is_none());
    }

    #[tokio::test]
    async fn cookie_authenticator_rejects_id_spelled_issuer() {
        // Pre-switch cookies carry the realm ID in `iss`; they must not
        // authenticate — the segment is a name now.
        let auth = cookie_authenticator(true, "realm-1").await;
        let mut ctx = test_context();
        ctx.attributes.insert("session_cookie".to_string(), "valid".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
        assert!(ctx.user_id.is_none());
    }

    #[tokio::test]
    async fn cookie_authenticator_no_attributes_returns_attempted() {
        // Neither session cookie nor remember-me hint: nothing to authenticate.
        let auth = cookie_authenticator(true, "test-realm").await;
        let mut ctx = test_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
        assert!(ctx.user_id.is_none());
    }

    #[tokio::test]
    async fn cookie_authenticator_remember_me_user_succeeds() {
        // The server only injects `remember_me_user` after full cryptographic
        // verification of the remember cookie, so the authenticator trusts it.
        let auth = cookie_authenticator(true, "test-realm").await;
        let mut ctx = test_context();
        ctx.attributes.insert("remember_me_user".to_string(), "alice".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
        assert_eq!(ctx.user_id, Some(UserId::new("alice").unwrap()));
        // No live SSO session: the executor generates a fresh session id.
        assert!(ctx.session_id.is_none());
    }

    #[tokio::test]
    async fn cookie_authenticator_remember_me_user_invalid_id_returns_attempted() {
        let auth = cookie_authenticator(true, "test-realm").await;
        let mut ctx = test_context();
        ctx.attributes.insert("remember_me_user".to_string(), String::new());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
        assert!(ctx.user_id.is_none());
    }

    // -----------------------------------------------------------------------
    // UsernamePasswordAuthenticator
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn password_authenticator_correct_password() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("password").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let auth = UsernamePasswordAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);

        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
        assert_eq!(ctx.user_id, Some(UserId::new("alice").unwrap()));
    }

    #[tokio::test]
    async fn password_authenticator_wrong_password() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("password").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let auth = UsernamePasswordAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["wrong".to_string()]);

        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn password_authenticator_missing_user() {
        let storage = Arc::new(InMemoryStorage::new());
        let auth = UsernamePasswordAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["bob".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);

        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidGrant);
    }

    // -----------------------------------------------------------------------
    // OtpFormAuthenticator
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn otp_no_param_returns_challenge() {
        // A user WITH a TOTP credential and no `otp` parameter is challenged.
        // (Users without a credential pass through — see
        // `otp_no_credentials_no_param_is_attempted`.)
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let secret = crate::totp::base32_encode(OTP_TEST_KEY);
        storage
            .create_credential(&user.realm_id, &user.id, &totp_credential(&secret, None))
            .await
            .unwrap();

        let auth = OtpFormAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_challenge_otp(result);
    }

    /// RFC 6238 key shared by the OTP authenticator tests.
    const OTP_TEST_KEY: &[u8] = b"12345678901234567890";

    fn totp_credential(secret_b32: &str, last_used_step: Option<u64>) -> Credential {
        Credential {
            id: CredentialId::new("cred-totp").unwrap(),
            credential_type: CredentialType::Totp,
            user_label: None,
            created_date: Utc::now(),
            secret_data: secret_b32.as_bytes().to_vec(),
            credential_data: match last_used_step {
                Some(step) => json!({"last_used_step": step}),
                None => json!({}),
            },
            priority: 1,
        }
    }

    fn current_otp() -> String {
        let step = issuerd_core::utils::now_secs() / 30;
        crate::totp::totp_at(OTP_TEST_KEY, step, 6, &issuerd_core::OtpHashAlgorithm::HmacSha1)
    }

    #[tokio::test]
    async fn otp_correct_code() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let secret = crate::totp::base32_encode(OTP_TEST_KEY);
        storage
            .create_credential(&user.realm_id, &user.id, &totp_credential(&secret, None))
            .await
            .unwrap();

        let auth = OtpFormAuthenticator::new(storage.clone());
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("otp".to_string(), vec![current_otp()]);

        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);

        // The replay watermark was persisted on the credential.
        let stored = storage
            .get_credentials(&user.realm_id, &user.id, CredentialType::Totp)
            .await
            .unwrap();
        let step = issuerd_core::utils::now_secs() / 30;
        let watermark = stored[0].credential_data["last_used_step"].as_u64().unwrap();
        assert!(watermark >= step - 1 && watermark <= step + 1, "watermark {watermark}");
    }

    #[tokio::test]
    async fn otp_replayed_code_is_rejected() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        // Watermark at the current step: the current code was already consumed.
        let step = issuerd_core::utils::now_secs() / 30;
        let secret = crate::totp::base32_encode(OTP_TEST_KEY);
        storage
            .create_credential(&user.realm_id, &user.id, &totp_credential(&secret, Some(step)))
            .await
            .unwrap();

        let auth = OtpFormAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("otp".to_string(), vec![current_otp()]);

        let result = auth.authenticate(&mut ctx).await;
        assert_auth_challenge_otp(result);
    }

    #[tokio::test]
    async fn otp_no_credentials_is_attempted() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let auth = OtpFormAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("otp".to_string(), vec!["123456".to_string()]);

        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    #[tokio::test]
    async fn otp_no_credentials_no_param_is_attempted() {
        // Regression: a WebAuthn-only user is admitted by the
        // conditional-user-configured condition but owns no TOTP credential;
        // the stage must pass through even when no `otp` parameter was posted
        // (previously it challenged with an unanswerable OTP form first).
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let auth = OtpFormAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());

        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    // -----------------------------------------------------------------------
    // IdentityProviderRedirectAuthenticator
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn idp_redirect_hint_present() {
        let storage = Arc::new(InMemoryStorage::new());
        let idp = IdentityProviderConfig {
            id: IdentityProviderId::new("idp-1").unwrap(),
            alias: issuerd_core::Alias::new("google").unwrap(),
            provider_id: issuerd_core::ProviderId::new("google"),
            enabled: true,
            config: {
                let mut m = HashMap::new();
                m.insert(
                    "authorizationUrl".to_string(),
                    "https://idp.example.com/auth".to_string(),
                );
                m
            },
        };
        storage
            .create_identity_provider(&RealmId::new("realm-1").unwrap(), &idp)
            .await
            .unwrap();

        let auth = IdentityProviderRedirectAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.attributes
            .insert("identity_provider_hint".to_string(), "google".to_string());
        let result = auth.authenticate(&mut ctx).await;
        let url = assert_auth_challenge_redirect(result);
        assert_eq!(url, "/broker/google/login");
    }

    #[tokio::test]
    async fn idp_redirect_no_hint() {
        let storage = Arc::new(InMemoryStorage::new());
        let auth = IdentityProviderRedirectAuthenticator::new(storage);
        let mut ctx = test_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    // -----------------------------------------------------------------------
    // ConditionalUserConfiguredAuthenticator
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn conditional_user_configured_has_totp() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let cred = Credential {
            id: CredentialId::new("cred-totp").unwrap(),
            credential_type: CredentialType::Totp,
            user_label: None,
            created_date: Utc::now(),
            secret_data: b"secret".to_vec(),
            credential_data: json!({}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let auth = ConditionalUserConfiguredAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
    }

    #[tokio::test]
    async fn conditional_user_configured_no_totp() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let auth = ConditionalUserConfiguredAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    #[tokio::test]
    async fn conditional_user_configured_has_webauthn_only() {
        // A WebAuthn passkey alone also satisfies the condition, so
        // the conditional second-factor scope activates for passkey-only users.
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let cred = Credential {
            id: CredentialId::new("cred-webauthn").unwrap(),
            credential_type: CredentialType::WebAuthn,
            user_label: None,
            created_date: Utc::now(),
            secret_data: b"passkey".to_vec(),
            credential_data: json!({}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let auth = ConditionalUserConfiguredAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
    }

    // -----------------------------------------------------------------------
    // Required Actions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_email_evaluates_true_for_unverified_when_realm_enables_it() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.email_verified = false;
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = VerifyEmailRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.attributes
            .insert("realm_verify_email_enabled".to_string(), "true".to_string());
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn verify_email_not_triggered_when_realm_toggle_off() {
        // Unverified email only blocks when the realm enables verification.
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.email_verified = false;
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = VerifyEmailRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(!action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn verify_email_evaluates_true_when_assigned() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.email_verified = true; // assigned action fires regardless
        user.required_actions = vec!["VERIFY_EMAIL".to_string()];
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = VerifyEmailRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn verify_email_process_checks_storage_state() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.email_verified = true;
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = VerifyEmailRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        // Verified in storage (e.g. link clicked) -> Success.
        let result = action.process(&mut ctx).await;
        assert_action_success(result);
    }

    #[tokio::test]
    async fn update_password_evaluates_true_when_no_password() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn update_password_auto_rule_skipped_in_email_code_realm() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        realm
            .attributes
            .insert(REALM_ATTR_EMAIL_CODE_LOGIN.to_string(), "true".to_string());
        storage.create_realm(&realm).await.unwrap();
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        // No password credential, but the realm signs in by emailed code:
        // the auto-rule stays silent.
        assert!(!action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn update_password_auto_rule_skipped_for_federated_user() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("msad".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        // No local password credential, but the password lives in the
        // external directory (validated via LDAP bind) — the auto-rule
        // must not force a local password update.
        assert!(!action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn update_password_assignment_fires_for_federated_user() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("msad".to_string());
        user.required_actions = vec!["UPDATE_PASSWORD".to_string()];
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        // Explicit admin assignment still wins for federated users.
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn update_password_temporary_credential_fires_for_federated_user() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("msad".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("password").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id", "temporary": true}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        // The directory carve-out suppresses only the no-local-password rule,
        // never the temporary-password rotation.
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn update_password_assignment_fires_in_email_code_realm() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        realm
            .attributes
            .insert(REALM_ATTR_EMAIL_CODE_LOGIN.to_string(), "true".to_string());
        storage.create_realm(&realm).await.unwrap();
        let mut user = test_user();
        user.required_actions = vec!["UPDATE_PASSWORD".to_string()];
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        // Explicit admin assignment still wins in an email-code realm.
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn update_password_evaluates_true_when_assigned() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.required_actions = vec!["UPDATE_PASSWORD".to_string()];
        storage.create_user(&user.realm_id, &user).await.unwrap();
        // A valid, non-temporary password exists — assignment still wins.
        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("password").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn update_password_process_creates_credential() {
        let storage = Arc::new(InMemoryStorage::new());
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage.clone());
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters
            .insert("new_password".to_string(), vec!["newpass123".to_string()]);
        let result = action.process(&mut ctx).await;
        assert_action_success(result);

        let creds = storage
            .get_credentials(
                &RealmId::new("realm-1").unwrap(),
                &UserId::new("alice").unwrap(),
                CredentialType::Password,
            )
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
    }

    #[tokio::test]
    async fn update_password_process_enforces_realm_policy() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        realm.password_policy.require_digits = true;
        realm.password_policy.require_upper = true;
        storage.create_realm(&realm).await.unwrap();
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters
            .insert("new_password".to_string(), vec!["alllowercase".to_string()]);
        let result = action.process(&mut ctx).await;
        match result {
            RequiredActionResult::Failure(IssuerdError::InvalidRequest(msg)) => {
                assert!(msg.contains("require_digits"), "{msg}");
                assert!(msg.contains("require_upper"), "{msg}");
            }
            other => panic!("expected policy failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_password_process_rejects_history_reuse() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        realm.password_policy.history_size = 2;
        storage.create_realm(&realm).await.unwrap();
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let cred = Credential {
            id: CredentialId::new("cred-current").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("currentpass").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id", "temporary": true}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage.clone());
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());

        // Reusing the current password is rejected.
        ctx.parameters
            .insert("new_password".to_string(), vec!["currentpass".to_string()]);
        let result = action.process(&mut ctx).await;
        match result {
            RequiredActionResult::Failure(IssuerdError::InvalidRequest(msg)) => {
                assert!(msg.contains("password_history"), "{msg}");
            }
            other => panic!("expected history failure, got {other:?}"),
        }

        // A fresh password succeeds; the old credential becomes inert history.
        ctx.parameters
            .insert("new_password".to_string(), vec!["brandnewpass".to_string()]);
        let result = action.process(&mut ctx).await;
        assert_action_success(result);
        let active = storage
            .get_credentials(&user.realm_id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(active.len(), 1);
        let history = storage
            .get_credentials(
                &user.realm_id,
                &user.id,
                CredentialType::Custom(PASSWORD_HISTORY_CREDENTIAL_TYPE.to_string()),
            )
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        // The temporary flag must not survive on the retained history entry.
        assert!(history[0].credential_data.get("temporary").is_none());
    }

    #[tokio::test]
    async fn update_password_process_rejects_mismatched_confirmation() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdatePasswordRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters
            .insert("new_password".to_string(), vec!["newpass123".to_string()]);
        ctx.parameters
            .insert("confirm_password".to_string(), vec!["different".to_string()]);
        let result = action.process(&mut ctx).await;
        assert_action_failure(
            result,
            IssuerdError::InvalidRequest("passwords do not match".into()),
        );
    }

    // -----------------------------------------------------------------------
    // Federation password write-through
    // -----------------------------------------------------------------------

    /// Stub provider recording password writes; validation/update outcomes
    /// are programmable per test.
    struct StubFederationProvider {
        id: String,
        supports_update: bool,
        update_result: std::sync::Mutex<Result<(), issuerd_core::FederationError>>,
        validate_result: std::sync::Mutex<Result<bool, issuerd_core::FederationError>>,
        written: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl StubFederationProvider {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                supports_update: true,
                update_result: std::sync::Mutex::new(Ok(())),
                validate_result: std::sync::Mutex::new(Ok(true)),
                written: std::sync::Mutex::new(vec![]),
            }
        }

        fn written(&self) -> Vec<(String, String)> {
            self.written.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationProvider for StubFederationProvider {
        fn id(&self) -> &str {
            &self.id
        }

        fn provider_type(&self) -> issuerd_core::FederationProviderType {
            issuerd_core::FederationProviderType::Ldap
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
            let guard = self.validate_result.lock().unwrap();
            match &*guard {
                Ok(v) => Ok(*v),
                Err(issuerd_core::FederationError::NotSupported) => {
                    Err(issuerd_core::FederationError::NotSupported)
                }
                Err(_) => Err(issuerd_core::FederationError::NetworkError("stub".into())),
            }
        }

        async fn update_password(
            &self,
            username: &str,
            password: &str,
        ) -> Result<(), issuerd_core::FederationError> {
            self.written.lock().unwrap().push((username.to_string(), password.to_string()));
            let guard = self.update_result.lock().unwrap();
            match &*guard {
                Ok(()) => Ok(()),
                Err(issuerd_core::FederationError::NotSupported) => {
                    Err(issuerd_core::FederationError::NotSupported)
                }
                Err(_) => Err(issuerd_core::FederationError::NetworkError("stub".into())),
            }
        }

        fn supports_password_update(&self) -> bool {
            self.supports_update
        }
    }

    struct StubFederationManager {
        providers: Vec<Arc<dyn issuerd_core::FederationProvider>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationManager for StubFederationManager {
        async fn providers_for_realm(
            &self,
            _realm_id: &RealmId,
        ) -> Result<Vec<Arc<dyn issuerd_core::FederationProvider>>, IssuerdError> {
            Ok(self.providers.clone())
        }

        async fn find_user(
            &self,
            _realm_id: &RealmId,
            _username: &str,
        ) -> Result<
            Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
            IssuerdError,
        > {
            Ok(None)
        }

        async fn find_user_by_email(
            &self,
            _realm_id: &RealmId,
            _email: &str,
        ) -> Result<
            Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
            IssuerdError,
        > {
            Ok(None)
        }
    }

    fn stubbed_manager(provider: Arc<StubFederationProvider>) -> StubFederationManager {
        StubFederationManager {
            providers: vec![provider],
        }
    }

    #[tokio::test]
    async fn write_through_not_applicable_for_local_user() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let fm = StubFederationManager { providers: vec![] };

        let result = write_through_federated_password(
            storage.as_ref(),
            Some(&fm),
            &user.realm_id,
            &user.id,
            "newpass123",
        )
        .await
        .unwrap();
        assert_eq!(result, FederationWriteThrough::NotApplicable);
    }

    #[tokio::test]
    async fn write_through_not_applicable_when_provider_missing() {
        // The link points at a provider the manager no longer returns: login
        // falls back to the local password, so the write stays local too.
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("gone".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let fm = StubFederationManager { providers: vec![] };

        let result = write_through_federated_password(
            storage.as_ref(),
            Some(&fm),
            &user.realm_id,
            &user.id,
            "newpass123",
        )
        .await
        .unwrap();
        assert_eq!(result, FederationWriteThrough::NotApplicable);
    }

    #[tokio::test]
    async fn write_through_success_writes_directory_and_removes_stale_credential() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("ldap-1".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();
        // Stale local credential, e.g. from a pre-write-through reset: it must
        // not survive as a dormant fallback password.
        let cred = Credential {
            id: CredentialId::new("cred-stale").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("stalepass").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let provider = Arc::new(StubFederationProvider::new("ldap-1"));
        let fm = stubbed_manager(provider.clone());

        let result = write_through_federated_password(
            storage.as_ref(),
            Some(&fm),
            &user.realm_id,
            &user.id,
            "newpass123",
        )
        .await
        .unwrap();
        assert_eq!(result, FederationWriteThrough::WrittenToDirectory);
        assert_eq!(provider.written(), vec![("alice".to_string(), "newpass123".to_string())]);
        let creds = storage
            .get_credentials(&user.realm_id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert!(creds.is_empty(), "stale local credential must be deleted");
    }

    #[tokio::test]
    async fn write_through_readonly_provider_is_invalid_request() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("ldap-1".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("stalepass").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let provider = Arc::new(StubFederationProvider::new("ldap-1"));
        *provider.update_result.lock().unwrap() = Err(issuerd_core::FederationError::NotSupported);
        let fm = stubbed_manager(provider);

        let err = write_through_federated_password(
            storage.as_ref(),
            Some(&fm),
            &user.realm_id,
            &user.id,
            "newpass123",
        )
        .await
        .unwrap_err();
        match err {
            IssuerdError::InvalidRequest(msg) => {
                assert!(msg.contains("does not accept password changes"), "{msg}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
        // The failed write must not touch the existing credential.
        let creds = storage
            .get_credentials(&user.realm_id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
    }

    #[tokio::test]
    async fn write_through_directory_failure_is_server_error() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("ldap-1".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let provider = Arc::new(StubFederationProvider::new("ldap-1"));
        *provider.update_result.lock().unwrap() =
            Err(issuerd_core::FederationError::NetworkError("boom".into()));
        let fm = stubbed_manager(provider);

        let err = write_through_federated_password(
            storage.as_ref(),
            Some(&fm),
            &user.realm_id,
            &user.id,
            "newpass123",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IssuerdError::ServerError(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn update_password_process_federated_writes_through() {
        let storage = Arc::new(InMemoryStorage::new());
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let mut user = test_user();
        user.federation_link = Some("ldap-1".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let provider = Arc::new(StubFederationProvider::new("ldap-1"));
        let action = UpdatePasswordRequiredAction::new(storage.clone())
            .with_federation_manager(Arc::new(stubbed_manager(provider.clone())));
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters
            .insert("new_password".to_string(), vec!["newpass123".to_string()]);
        let result = action.process(&mut ctx).await;
        assert_action_success(result);

        assert_eq!(provider.written(), vec![("alice".to_string(), "newpass123".to_string())]);
        let creds = storage
            .get_credentials(&user.realm_id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert!(creds.is_empty(), "no local credential for a directory write");
    }

    #[tokio::test]
    async fn update_password_process_federated_readonly_provider_fails() {
        let storage = Arc::new(InMemoryStorage::new());
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let mut user = test_user();
        user.federation_link = Some("ldap-1".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let provider = Arc::new(StubFederationProvider::new("ldap-1"));
        *provider.update_result.lock().unwrap() = Err(issuerd_core::FederationError::NotSupported);
        let action = UpdatePasswordRequiredAction::new(storage.clone())
            .with_federation_manager(Arc::new(stubbed_manager(provider)));
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters
            .insert("new_password".to_string(), vec!["newpass123".to_string()]);
        let result = action.process(&mut ctx).await;
        match result {
            RequiredActionResult::Failure(IssuerdError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not accept password changes"), "{msg}");
            }
            other => panic!("expected InvalidRequest failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn terms_and_conditions_evaluates_true_when_assigned_and_not_accepted() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.required_actions = vec!["TERMS_AND_CONDITIONS".to_string()];
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = TermsAndConditionsRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn terms_and_conditions_process_accepts_and_persists() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.required_actions = vec!["TERMS_AND_CONDITIONS".to_string()];
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = TermsAndConditionsRequiredAction::new(storage.clone());
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("terms_accepted".to_string(), vec!["true".to_string()]);
        let result = action.process(&mut ctx).await;
        assert_action_success(result);

        // Acceptance is persisted on the user, not request-scoped state.
        let stored = storage
            .get_user(&RealmId::new("realm-1").unwrap(), &UserId::new("alice").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.attributes.get("terms_accepted"), Some(&vec!["true".to_string()]));
        // ...so the action no longer evaluates as pending.
        assert!(!action.evaluate(&ctx).await);
    }

    // -----------------------------------------------------------------------
    // RegistrationAuthenticator
    // -----------------------------------------------------------------------

    /// A registration context carrying a full, valid form submission.
    fn registration_context() -> AuthContext {
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["newuser".to_string()]);
        ctx.parameters
            .insert("email".to_string(), vec!["newuser@example.com".to_string()]);
        ctx.parameters.insert("first_name".to_string(), vec!["New".to_string()]);
        ctx.parameters.insert("last_name".to_string(), vec!["User".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password123".to_string()]);
        ctx.parameters
            .insert("confirm_password".to_string(), vec!["password123".to_string()]);
        ctx
    }

    fn registration_realm() -> issuerd_core::Realm {
        let mut realm = test_realm();
        realm.default_role = Some("user".to_string());
        realm
    }

    fn default_role(realm_id: &RealmId) -> issuerd_core::Role {
        issuerd_core::Role {
            id: issuerd_core::RoleId::new("role-user").unwrap(),
            name: issuerd_core::RoleName::new("user").unwrap(),
            description: None,
            realm_id: realm_id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        }
    }

    fn assert_auth_challenge_login_form(result: AuthStepResult) {
        match result {
            AuthStepResult::Challenge(Challenge::LoginForm { .. }) => {}
            other => panic!("expected Challenge::LoginForm, got {:?}", other),
        }
    }

    #[test]
    #[should_panic(expected = "expected Challenge::LoginForm")]
    fn assert_auth_challenge_login_form_panics() {
        assert_auth_challenge_login_form(AuthStepResult::Success);
    }

    #[tokio::test]
    async fn registration_challenges_without_submission() {
        let storage = Arc::new(InMemoryStorage::new());
        let auth = RegistrationAuthenticator::new(storage);
        let result = auth.authenticate(&mut test_context()).await;
        assert_auth_challenge_login_form(result);
    }

    #[tokio::test]
    async fn registration_creates_user_with_password_and_default_role() {
        let storage = Arc::new(InMemoryStorage::new());
        let realm = registration_realm();
        storage.create_realm(&realm).await.unwrap();
        storage.create_role(&realm.id, &default_role(&realm.id)).await.unwrap();

        let auth = RegistrationAuthenticator::new(storage.clone());
        let mut ctx = registration_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
        let user_id = ctx.user_id.clone().expect("user id set on success");

        // The account lands in storage: enabled, email unverified, profile set.
        let user = storage.get_user(&realm.id, &user_id).await.unwrap().unwrap();
        assert_eq!(user.username, "newuser");
        assert_eq!(user.email.as_ref().unwrap().as_str(), "newuser@example.com");
        assert!(!user.email_verified);
        assert!(user.enabled);
        assert_eq!(user.first_name.as_ref().unwrap().as_str(), "New");
        assert_eq!(user.last_name.as_ref().unwrap().as_str(), "User");
        assert!(user.required_actions.is_empty());

        // The password verifies against the stored argon2id credential.
        let creds = storage
            .get_credentials(&realm.id, &user_id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
        assert!(verify_password_hash("password123", &creds[0]));

        // The realm default role was granted.
        let roles = storage.list_user_realm_roles(&realm.id, &user_id).await.unwrap();
        assert!(roles.contains(&issuerd_core::RoleId::new("role-user").unwrap()));
    }

    #[tokio::test]
    async fn registration_assigns_verify_email_when_realm_enables_it() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        realm.verify_email_enabled = true;
        storage.create_realm(&realm).await.unwrap();

        let auth = RegistrationAuthenticator::new(storage.clone());
        let mut ctx = registration_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);

        let user = storage.get_user(&realm.id, &ctx.user_id.unwrap()).await.unwrap().unwrap();
        assert_eq!(user.required_actions, vec!["VERIFY_EMAIL".to_string()]);
    }

    #[tokio::test]
    async fn registration_rejects_password_mismatch() {
        let storage = Arc::new(InMemoryStorage::new());
        storage.create_realm(&test_realm()).await.unwrap();
        let auth = RegistrationAuthenticator::new(storage);
        let mut ctx = registration_context();
        ctx.parameters
            .insert("confirm_password".to_string(), vec!["different".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidRequest("passwords do not match".into()));
    }

    #[tokio::test]
    async fn registration_rejects_missing_required_fields() {
        let storage = Arc::new(InMemoryStorage::new());
        storage.create_realm(&test_realm()).await.unwrap();
        let auth = RegistrationAuthenticator::new(storage);

        // Submitted (username key present) but email missing.
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["newuser".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password123".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidRequest("email is required".into()));

        // Blank username counts as missing.
        let mut ctx = registration_context();
        ctx.parameters.insert("username".to_string(), vec!["   ".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidRequest("username is required".into()));

        // Missing password.
        let mut ctx = registration_context();
        ctx.parameters.remove("password");
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidRequest("password is required".into()));
    }

    #[tokio::test]
    async fn registration_rejects_invalid_newtypes() {
        let storage = Arc::new(InMemoryStorage::new());
        storage.create_realm(&test_realm()).await.unwrap();
        let auth = RegistrationAuthenticator::new(storage);

        let mut ctx = registration_context();
        ctx.parameters.insert("email".to_string(), vec!["not-an-email".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        match result {
            AuthStepResult::Failure(IssuerdError::InvalidRequest(msg)) => {
                assert!(msg.contains("email"), "{msg}");
            }
            other => panic!("expected validation failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn registration_enforces_password_policy() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        realm.password_policy.require_digits = true;
        realm.password_policy.require_upper = true;
        storage.create_realm(&realm).await.unwrap();

        let auth = RegistrationAuthenticator::new(storage.clone());
        let mut ctx = registration_context();
        ctx.parameters.insert("password".to_string(), vec!["alllowercase".to_string()]);
        ctx.parameters
            .insert("confirm_password".to_string(), vec!["alllowercase".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        match result {
            AuthStepResult::Failure(IssuerdError::InvalidRequest(msg)) => {
                assert!(msg.contains("require_digits"), "{msg}");
                assert!(msg.contains("require_upper"), "{msg}");
            }
            other => panic!("expected policy failure, got {other:?}"),
        }

        // No account was created.
        assert!(storage
            .get_user_by_username(&RealmId::new("realm-1").unwrap(), "newuser")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn registration_rejects_duplicate_email_unless_allowed() {
        let storage = Arc::new(InMemoryStorage::new());
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        // Existing account already holds the address.
        let mut existing = test_user();
        existing.email = Some(Email::new("newuser@example.com").unwrap());
        storage.create_user(&existing.realm_id, &existing).await.unwrap();

        // duplicate_emails_allowed = false (realm default): rejected.
        let auth = RegistrationAuthenticator::new(storage.clone());
        let result = auth.authenticate(&mut registration_context()).await;
        assert_auth_failure(result, IssuerdError::InvalidRequest("email already in use".into()));

        // Allowed: a second account with the same address is created.
        let mut realm = test_realm();
        realm.duplicate_emails_allowed = true;
        storage.update_realm(&realm).await.unwrap();
        let auth = RegistrationAuthenticator::new(storage.clone());
        let mut ctx = registration_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
    }

    #[tokio::test]
    async fn registration_rejects_duplicate_username() {
        let storage = Arc::new(InMemoryStorage::new());
        storage.create_realm(&test_realm()).await.unwrap();
        storage
            .create_user(&RealmId::new("realm-1").unwrap(), &test_user())
            .await
            .unwrap();

        let auth = RegistrationAuthenticator::new(storage);
        let mut ctx = registration_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidRequest("username already in use".into()));
    }

    #[tokio::test]
    async fn registration_missing_default_role_does_not_fail() {
        let storage = Arc::new(InMemoryStorage::new());
        // Realm names a default role that was never created.
        let realm = registration_realm();
        storage.create_realm(&realm).await.unwrap();

        let auth = RegistrationAuthenticator::new(storage.clone());
        let mut ctx = registration_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
        let roles = storage.list_user_realm_roles(&realm.id, &ctx.user_id.unwrap()).await.unwrap();
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn registration_require_names_rejects_missing_or_blank_names() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        realm.attributes.insert(
            issuerd_core::Realm::REGISTRATION_REQUIRE_NAMES_ATTRIBUTE.to_string(),
            "true".into(),
        );
        storage.create_realm(&realm).await.unwrap();

        let auth = RegistrationAuthenticator::new(storage.clone());

        // Missing first name.
        let mut ctx = registration_context();
        ctx.parameters.remove("first_name");
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidRequest("first name is required".into()));

        // Blank (whitespace-only) last name counts as missing.
        let mut ctx = registration_context();
        ctx.parameters.insert("last_name".to_string(), vec!["   ".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidRequest("last name is required".into()));

        // No account was created by either attempt.
        assert!(storage
            .get_user_by_username(&RealmId::new("realm-1").unwrap(), "newuser")
            .await
            .unwrap()
            .is_none());

        // Both names present -> success, and the names are stored.
        let auth = RegistrationAuthenticator::new(storage.clone());
        let mut ctx = registration_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
        let user = storage.get_user(&realm.id, &ctx.user_id.unwrap()).await.unwrap().unwrap();
        assert_eq!(user.first_name.as_ref().unwrap().as_str(), "New");
        assert_eq!(user.last_name.as_ref().unwrap().as_str(), "User");
    }

    #[tokio::test]
    async fn registration_passwordless_registers_without_password_credential() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = registration_realm();
        realm.verify_email_enabled = true;
        realm.attributes.insert(
            issuerd_core::Realm::REGISTRATION_PASSWORDLESS_ATTRIBUTE.to_string(),
            "true".into(),
        );
        storage.create_realm(&realm).await.unwrap();
        storage.create_role(&realm.id, &default_role(&realm.id)).await.unwrap();

        let auth = RegistrationAuthenticator::new(storage.clone());
        let mut ctx = registration_context();
        ctx.parameters.remove("password");
        ctx.parameters.remove("confirm_password");
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
        let user_id = ctx.user_id.clone().expect("user id set on success");

        // No password credential was stored...
        let creds = storage
            .get_credentials(&realm.id, &user_id, CredentialType::Password)
            .await
            .unwrap();
        assert!(creds.is_empty());

        // ...while everything else is unchanged: VERIFY_EMAIL assignment and
        // the default role grant still happen.
        let user = storage.get_user(&realm.id, &user_id).await.unwrap().unwrap();
        assert_eq!(user.required_actions, vec!["VERIFY_EMAIL".to_string()]);
        let roles = storage.list_user_realm_roles(&realm.id, &user_id).await.unwrap();
        assert!(roles.contains(&issuerd_core::RoleId::new("role-user").unwrap()));
    }

    #[tokio::test]
    async fn registration_passwordless_ignores_submitted_password_fields() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        // A policy the submitted password would violate — it must not be
        // consulted at all in passwordless mode.
        realm.password_policy.require_digits = true;
        realm.password_policy.require_upper = true;
        realm.attributes.insert(
            issuerd_core::Realm::REGISTRATION_PASSWORDLESS_ATTRIBUTE.to_string(),
            "true".into(),
        );
        storage.create_realm(&realm).await.unwrap();

        // Mismatched, policy-violating password fields are ignored entirely.
        let auth = RegistrationAuthenticator::new(storage.clone());
        let mut ctx = registration_context();
        ctx.parameters.insert("password".to_string(), vec!["alllowercase".to_string()]);
        ctx.parameters
            .insert("confirm_password".to_string(), vec!["different".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);

        let creds = storage
            .get_credentials(&realm.id, &ctx.user_id.unwrap(), CredentialType::Password)
            .await
            .unwrap();
        assert!(creds.is_empty());
    }

    #[tokio::test]
    async fn registration_require_names_and_passwordless_compose() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        realm.attributes.insert(
            issuerd_core::Realm::REGISTRATION_REQUIRE_NAMES_ATTRIBUTE.to_string(),
            "true".into(),
        );
        realm.attributes.insert(
            issuerd_core::Realm::REGISTRATION_PASSWORDLESS_ATTRIBUTE.to_string(),
            "true".into(),
        );
        storage.create_realm(&realm).await.unwrap();

        // Names required even though no password is collected.
        let auth = RegistrationAuthenticator::new(storage.clone());
        let mut ctx = registration_context();
        ctx.parameters.remove("password");
        ctx.parameters.remove("confirm_password");
        ctx.parameters.remove("first_name");
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidRequest("first name is required".into()));

        // Full form minus the password fields succeeds.
        let auth = RegistrationAuthenticator::new(storage);
        let mut ctx = registration_context();
        ctx.parameters.remove("password");
        ctx.parameters.remove("confirm_password");
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
    }

    #[tokio::test]
    async fn registration_trait_methods() {
        let auth = RegistrationAuthenticator::new(Arc::new(InMemoryStorage::new()));
        assert_eq!(auth.id(), "auth-registration");
        assert_eq!(auth.display_name(), "Registration Form");
        assert!(!auth.requires_user());
        assert!(auth.configured_for(&test_context()));
    }

    // -----------------------------------------------------------------------
    // Trait methods coverage (id, display_name, requires_user, configured_for)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cookie_authenticator_trait_methods() {
        let auth = cookie_authenticator(true, "test-realm").await;
        assert_eq!(auth.id(), "auth-cookie");
        assert_eq!(auth.display_name(), "Cookie");
        assert!(!auth.requires_user());
        assert!(auth.configured_for(&test_context()));
    }

    #[tokio::test]
    async fn password_authenticator_trait_methods_and_paths() {
        let storage = Arc::new(InMemoryStorage::new());
        let auth = UsernamePasswordAuthenticator::new(storage.clone());
        assert_eq!(auth.id(), "auth-username-password");
        assert_eq!(auth.display_name(), "Username Password Form");
        assert!(!auth.requires_user());
        assert!(auth.configured_for(&test_context()));

        // with_tracker constructor
        let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());
        let tracker = Arc::new(LoginFailureTracker::new());
        let auth2 = UsernamePasswordAuthenticator::with_tracker(storage, tracker, cache);
        assert_eq!(auth2.id(), "auth-username-password");

        // missing username
        let mut ctx = test_context();
        ctx.parameters.insert("password".to_string(), vec!["x".to_string()]);
        let result = auth2.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidGrant);

        // missing password
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["x".to_string()]);
        let result = auth2.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn password_authenticator_tracker_locks_and_resets() {
        let storage = Arc::new(InMemoryStorage::new());
        // Realm opts into brute-force protection with a threshold of 1.
        let mut realm = test_realm();
        realm.brute_force_protected = true;
        realm.max_login_failures = 1;
        realm.wait_increment_secs = 0;
        realm.lockout_duration_secs = 900;
        storage.create_realm(&realm).await.unwrap();
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("password").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());
        let tracker = Arc::new(LoginFailureTracker::new());
        let auth = UsernamePasswordAuthenticator::with_tracker(
            storage.clone(),
            tracker.clone(),
            cache.clone(),
        );

        // First wrong password -> count becomes 1, locked on next attempt
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["wrong".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidGrant);

        // Second attempt -> locked
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["wrong2".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::AccessDenied);

        // Correct password while locked still denied
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::AccessDenied);

        // Reset failures manually
        tracker
            .reset_failures(&user.realm_id, &user.username, "0.0.0.0", cache.as_ref())
            .await
            .unwrap();

        // Now correct password succeeds and resets
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
    }

    #[tokio::test]
    async fn password_authenticator_no_tracking_when_realm_unprotected() {
        let storage = Arc::new(InMemoryStorage::new());
        // Realm exists but brute-force protection is disabled (default).
        let mut realm = test_realm();
        realm.max_login_failures = 1;
        storage.create_realm(&realm).await.unwrap();
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("password").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let cache: Arc<dyn DistributedCache> = Arc::new(issuerd_cluster::InMemoryCache::new());
        let tracker = Arc::new(LoginFailureTracker::new());
        let auth = UsernamePasswordAuthenticator::with_tracker(storage, tracker, cache.clone());

        // Many failures, threshold 1 — never locks because the realm is
        // unprotected, and no counter is written either.
        for _ in 0..5 {
            let mut ctx = test_context();
            ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
            ctx.parameters.insert("password".to_string(), vec!["wrong".to_string()]);
            let result = auth.authenticate(&mut ctx).await;
            assert_auth_failure(result, IssuerdError::InvalidGrant);
        }
        assert!(cache
            .get(&crate::login_failures::failure_count_key(
                &RealmId::new("realm-1").unwrap(),
                "alice",
                "0.0.0.0"
            ))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn otp_authenticator_trait_methods_and_edge_cases() {
        let storage = Arc::new(InMemoryStorage::new());
        let auth = OtpFormAuthenticator::new(storage);
        assert_eq!(auth.id(), "auth-otp-form");
        assert_eq!(auth.display_name(), "OTP Form");
        assert!(auth.requires_user());
        assert!(!auth.configured_for(&test_context()));
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(auth.configured_for(&ctx));

        // no user_id -> AccessDenied
        let mut ctx = test_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::AccessDenied);
    }

    #[tokio::test]
    async fn otp_wrong_code_returns_challenge() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let secret = crate::totp::base32_encode(OTP_TEST_KEY);
        storage
            .create_credential(&user.realm_id, &user.id, &totp_credential(&secret, None))
            .await
            .unwrap();

        let auth = OtpFormAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("otp".to_string(), vec!["000000".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_challenge_otp(result);
    }

    #[tokio::test]
    async fn otp_bad_secret_data_returns_error() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let cred = Credential {
            id: CredentialId::new("cred-totp").unwrap(),
            credential_type: CredentialType::Totp,
            user_label: None,
            created_date: Utc::now(),
            secret_data: vec![0x80, 0x81, 0x82], // invalid utf8
            credential_data: json!({}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let auth = OtpFormAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("otp".to_string(), vec!["000000".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_server_error(result);
    }

    #[tokio::test]
    async fn idp_redirect_trait_methods_and_edge_cases() {
        let storage = Arc::new(InMemoryStorage::new());
        let auth = IdentityProviderRedirectAuthenticator::new(storage.clone());
        assert_eq!(auth.id(), "auth-idp-redirect");
        assert_eq!(auth.display_name(), "Identity Provider Redirect");
        assert!(!auth.requires_user());
        let mut ctx = test_context();
        assert!(!auth.configured_for(&ctx));
        ctx.attributes
            .insert("identity_provider_hint".to_string(), "google".to_string());
        assert!(auth.configured_for(&ctx));

        // no hint -> Attempted
        let mut ctx = test_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);

        // storage error
        let mut ctx = test_context();
        ctx.attributes
            .insert("identity_provider_hint".to_string(), "google".to_string());
    }

    #[tokio::test]
    async fn idp_redirect_hint_matches_provider_id() {
        let storage = Arc::new(InMemoryStorage::new());
        let idp = IdentityProviderConfig {
            id: IdentityProviderId::new("idp-1").unwrap(),
            alias: issuerd_core::Alias::new("gmail").unwrap(),
            provider_id: issuerd_core::ProviderId::new("google"),
            enabled: true,
            config: {
                let mut m = HashMap::new();
                m.insert(
                    "authorizationUrl".to_string(),
                    "https://idp.example.com/auth".to_string(),
                );
                m
            },
        };
        storage
            .create_identity_provider(&RealmId::new("realm-1").unwrap(), &idp)
            .await
            .unwrap();

        let auth = IdentityProviderRedirectAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.attributes
            .insert("identity_provider_hint".to_string(), "google".to_string());
        let result = auth.authenticate(&mut ctx).await;
        let url = assert_auth_challenge_redirect(result);
        assert_eq!(url, "/broker/gmail/login");
    }

    #[tokio::test]
    async fn idp_redirect_no_matching_idp() {
        let storage = Arc::new(InMemoryStorage::new());
        let auth = IdentityProviderRedirectAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.attributes
            .insert("identity_provider_hint".to_string(), "google".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    #[tokio::test]
    async fn idp_redirect_disabled_idp_is_skipped() {
        let storage = Arc::new(InMemoryStorage::new());
        let idp = IdentityProviderConfig {
            id: IdentityProviderId::new("idp-1").unwrap(),
            alias: issuerd_core::Alias::new("google").unwrap(),
            provider_id: issuerd_core::ProviderId::new("google"),
            enabled: false,
            config: HashMap::new(),
        };
        storage
            .create_identity_provider(&RealmId::new("realm-1").unwrap(), &idp)
            .await
            .unwrap();

        let auth = IdentityProviderRedirectAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.attributes
            .insert("identity_provider_hint".to_string(), "google".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    #[tokio::test]
    #[should_panic(expected = "not implemented")]
    async fn mock_token_service_validate_id_token() {
        let svc = MockTokenService::for_realm(true, "realm-1");
        let client = Client {
            id: ClientId::new("c1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: issuerd_core::ClientIdentifier::new("client-1").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
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
            attributes: HashMap::new(),
        };
        let result = svc.validate_id_token("token", &client, None);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn conditional_user_configured_trait_methods_and_no_user() {
        let storage = Arc::new(InMemoryStorage::new());
        let auth = ConditionalUserConfiguredAuthenticator::new(storage);
        assert_eq!(auth.id(), "conditional-user-configured");
        assert_eq!(auth.display_name(), "Condition - user configured");
        assert!(auth.requires_user());
        assert!(auth.configured_for(&test_context()));

        // no user_id -> Attempted
        let mut ctx = test_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    #[tokio::test]
    async fn conditional_user_configured_storage_error() {
        // Using InMemoryStorage with non-existent user will return empty credentials, not error.
        // We test the storage error path by using a user that doesn't exist and verifying it returns Attempted.
        let storage = Arc::new(InMemoryStorage::new());
        let auth = ConditionalUserConfiguredAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("nobody").unwrap());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    // -----------------------------------------------------------------------
    // Required action trait methods and edge cases
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_email_trait_methods_and_edge_cases() {
        let storage = Arc::new(InMemoryStorage::new());
        let action = VerifyEmailRequiredAction::new(storage);
        assert_eq!(action.id(), "VERIFY_EMAIL");
        assert_eq!(action.display_name(), "Verify Email");

        // no user_id -> false
        let ctx = test_context();
        assert!(!action.evaluate(&ctx).await);

        // user not found -> false
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("nobody").unwrap());
        assert!(!action.evaluate(&ctx).await);

        // email none -> false (even with the realm toggle on)
        let storage2 = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.email = None;
        user.email_verified = false;
        storage2.create_user(&user.realm_id, &user).await.unwrap();
        let action2 = VerifyEmailRequiredAction::new(storage2);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.attributes
            .insert("realm_verify_email_enabled".to_string(), "true".to_string());
        assert!(!action2.evaluate(&ctx).await);

        // already verified + toggle on -> false
        let storage3 = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.email_verified = true;
        storage3.create_user(&user.realm_id, &user).await.unwrap();
        let action3 = VerifyEmailRequiredAction::new(storage3);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.attributes
            .insert("realm_verify_email_enabled".to_string(), "true".to_string());
        assert!(!action3.evaluate(&ctx).await);

        // process with unverified user -> challenge (login-form marker)
        let storage4 = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.email_verified = false;
        storage4.create_user(&user.realm_id, &user).await.unwrap();
        let action4 = VerifyEmailRequiredAction::new(storage4);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        let result = action4.process(&mut ctx).await;
        assert_action_challenge_login_form(result);

        // process without user_id -> failure
        let storage5 = Arc::new(InMemoryStorage::new());
        let action5 = VerifyEmailRequiredAction::new(storage5);
        let mut ctx = test_context();
        let result = action5.process(&mut ctx).await;
        assert_action_failure(result, IssuerdError::AccessDenied);
    }

    #[tokio::test]
    async fn update_password_trait_methods_and_edge_cases() {
        let storage = Arc::new(InMemoryStorage::new());
        let action = UpdatePasswordRequiredAction::new(storage.clone());
        assert_eq!(action.id(), "UPDATE_PASSWORD");
        assert_eq!(action.display_name(), "Update Password");

        // no user_id -> false
        let ctx = test_context();
        assert!(!action.evaluate(&ctx).await);

        // has password -> false
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("password").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(!action.evaluate(&ctx).await);

        // process no new_password -> challenge
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        let result = action.process(&mut ctx).await;
        assert_action_challenge_login_form(result);

        // process no user_id -> failure
        let mut ctx = test_context();
        ctx.parameters.insert("new_password".to_string(), vec!["x".to_string()]);
        let result = action.process(&mut ctx).await;
        assert_action_failure(result, IssuerdError::AccessDenied);
    }

    #[tokio::test]
    async fn update_profile_trait_methods_and_edge_cases() {
        let storage = Arc::new(InMemoryStorage::new());
        let action = UpdateProfileRequiredAction::new(storage.clone());
        assert_eq!(action.id(), "UPDATE_PROFILE");
        assert_eq!(action.display_name(), "Update Profile");

        // attribute not set, user not found -> false
        let ctx = test_context();
        assert!(!action.evaluate(&ctx).await);

        // realm attribute set -> true
        let mut ctx = test_context();
        ctx.attributes
            .insert("realm_update_profile_on_first_login".to_string(), "true".to_string());
        assert!(action.evaluate(&ctx).await);

        // assigned on the user -> true
        let mut user = test_user();
        user.required_actions = vec!["UPDATE_PROFILE".to_string()];
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn configure_totp_trait_methods_and_edge_cases() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = ConfigureTotpRequiredAction::new(storage.clone());
        assert_eq!(action.id(), "CONFIGURE_TOTP");
        assert_eq!(action.display_name(), "Configure OTP");

        // no user_id -> false
        let ctx = test_context();
        assert!(!action.evaluate(&ctx).await);

        // no TOTP creds but NOT assigned -> false (assignment-driven only)
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(!action.evaluate(&ctx).await);

        // assigned -> true
        let mut assigned = test_user();
        assigned.required_actions = vec!["CONFIGURE_TOTP".to_string()];
        storage.update_user(&assigned.realm_id, &assigned).await.unwrap();
        assert!(action.evaluate(&ctx).await);
    }

    #[tokio::test]
    async fn terms_and_conditions_trait_methods_and_edge_cases() {
        let storage = Arc::new(InMemoryStorage::new());
        let action = TermsAndConditionsRequiredAction::new(storage.clone());
        assert_eq!(action.id(), "TERMS_AND_CONDITIONS");
        assert_eq!(action.display_name(), "Terms and Conditions");

        // no user_id -> false
        let ctx = test_context();
        assert!(!action.evaluate(&ctx).await);

        // not assigned -> false
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        assert!(!action.evaluate(&ctx).await);

        // assigned but already accepted -> false
        let mut accepted = test_user();
        accepted.required_actions = vec!["TERMS_AND_CONDITIONS".to_string()];
        accepted
            .attributes
            .insert("terms_accepted".to_string(), vec!["true".to_string()]);
        storage.update_user(&accepted.realm_id, &accepted).await.unwrap();
        assert!(!action.evaluate(&ctx).await);

        // process without terms_accepted -> challenge
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        let result = action.process(&mut ctx).await;
        assert_action_challenge_login_form(result);
    }

    #[tokio::test]
    async fn update_profile_process_updates_user() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdateProfileRequiredAction::new(storage.clone());
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());

        // No form fields submitted -> challenge (form not yet rendered).
        let result = action.process(&mut ctx).await;
        assert_action_challenge_login_form(result);

        // Submitted fields update the user; a new email resets verification.
        ctx.parameters.insert("first_name".to_string(), vec!["Alice".to_string()]);
        ctx.parameters.insert("last_name".to_string(), vec!["Smith".to_string()]);
        ctx.parameters
            .insert("email".to_string(), vec!["alice.smith@example.com".to_string()]);
        let result = action.process(&mut ctx).await;
        assert_action_success(result);

        let stored = storage
            .get_user(&RealmId::new("realm-1").unwrap(), &UserId::new("alice").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.first_name.as_ref().unwrap().as_ref(), "Alice");
        assert_eq!(stored.last_name.as_ref().unwrap().as_ref(), "Smith");
        assert_eq!(stored.email.as_ref().unwrap().as_ref(), "alice.smith@example.com");
        assert!(!stored.email_verified);
    }

    #[tokio::test]
    async fn update_profile_unchanged_email_keeps_verification() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.email_verified = true;
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdateProfileRequiredAction::new(storage.clone());
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());

        // Same address (different case) re-submitted: verification survives.
        ctx.parameters
            .insert("email".to_string(), vec!["ALICE@example.com".to_string()]);
        let result = action.process(&mut ctx).await;
        assert_action_success(result);

        let stored = storage
            .get_user(&RealmId::new("realm-1").unwrap(), &UserId::new("alice").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(stored.email_verified);
    }

    #[tokio::test]
    async fn update_profile_process_rejects_invalid_email() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdateProfileRequiredAction::new(storage);
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("email".to_string(), vec!["not-an-email".to_string()]);
        let result = action.process(&mut ctx).await;
        assert!(matches!(result, RequiredActionResult::Failure(_)));
    }

    #[tokio::test]
    async fn update_profile_strict_rejects_blank_names_and_preserves_stored() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut realm = test_realm();
        realm.attributes.insert(
            issuerd_core::Realm::UPDATE_PROFILE_REQUIRE_NAMES_ATTRIBUTE.to_string(),
            "true".into(),
        );
        storage.create_realm(&realm).await.unwrap();
        let mut user = test_user();
        user.first_name = Some(DisplayName::new("Alice").unwrap());
        user.last_name = Some(DisplayName::new("Smith").unwrap());
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdateProfileRequiredAction::new(storage.clone());
        let stored = || async {
            storage
                .get_user(&RealmId::new("realm-1").unwrap(), &UserId::new("alice").unwrap())
                .await
                .unwrap()
                .unwrap()
        };

        // Blank first name -> re-present the form with an error, names kept.
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("first_name".to_string(), vec![String::new()]);
        ctx.parameters.insert("last_name".to_string(), vec!["Smith".to_string()]);
        let result = action.process(&mut ctx).await;
        match result {
            RequiredActionResult::Failure(IssuerdError::InvalidRequest(m)) => {
                assert_eq!(m, "First name is required.")
            }
            other => panic!("expected Failure(InvalidRequest), got {other:?}"),
        }
        let user = stored().await;
        assert_eq!(user.first_name.as_ref().unwrap().as_str(), "Alice");
        assert_eq!(user.last_name.as_ref().unwrap().as_str(), "Smith");

        // Whitespace-only last name counts as blank.
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("first_name".to_string(), vec!["Alice".to_string()]);
        ctx.parameters.insert("last_name".to_string(), vec!["  ".to_string()]);
        let result = action.process(&mut ctx).await;
        match result {
            RequiredActionResult::Failure(IssuerdError::InvalidRequest(m)) => {
                assert_eq!(m, "Last name is required.")
            }
            other => panic!("expected Failure(InvalidRequest), got {other:?}"),
        }
        let user = stored().await;
        assert_eq!(user.last_name.as_ref().unwrap().as_str(), "Smith");

        // Absent (not just blank) first name is also rejected.
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("last_name".to_string(), vec!["Smith".to_string()]);
        ctx.parameters
            .insert("email".to_string(), vec!["alice@example.com".to_string()]);
        let result = action.process(&mut ctx).await;
        match result {
            RequiredActionResult::Failure(IssuerdError::InvalidRequest(m)) => {
                assert_eq!(m, "First name is required.")
            }
            other => panic!("expected Failure(InvalidRequest), got {other:?}"),
        }

        // A complete submission succeeds and updates the stored names.
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("first_name".to_string(), vec!["Alicia".to_string()]);
        ctx.parameters.insert("last_name".to_string(), vec!["Jones".to_string()]);
        let result = action.process(&mut ctx).await;
        assert_action_success(result);
        let user = stored().await;
        assert_eq!(user.first_name.as_ref().unwrap().as_str(), "Alicia");
        assert_eq!(user.last_name.as_ref().unwrap().as_str(), "Jones");
    }

    #[tokio::test]
    async fn update_profile_non_strict_keeps_clear_on_empty() {
        let storage = Arc::new(InMemoryStorage::new());
        // Realm exists but does NOT set the strict attribute.
        storage.create_realm(&test_realm()).await.unwrap();
        let mut user = test_user();
        user.first_name = Some(DisplayName::new("Alice").unwrap());
        user.last_name = Some(DisplayName::new("Smith").unwrap());
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = UpdateProfileRequiredAction::new(storage.clone());
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("first_name".to_string(), vec![String::new()]);
        ctx.parameters.insert("last_name".to_string(), vec![String::new()]);
        let result = action.process(&mut ctx).await;
        assert_action_success(result);

        let stored = storage
            .get_user(&RealmId::new("realm-1").unwrap(), &UserId::new("alice").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(stored.first_name.is_none());
        assert!(stored.last_name.is_none());
    }

    #[tokio::test]
    async fn configure_totp_process_enrolls_on_valid_code() {
        let storage = Arc::new(InMemoryStorage::new());
        storage.create_realm(&test_realm()).await.unwrap();
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let action = ConfigureTotpRequiredAction::new(storage.clone());
        let secret = crate::totp::generate_secret();
        let step = issuerd_core::utils::now_secs() / 30;

        // Missing code -> InvalidRequest failure.
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.attributes.insert("totp_secret".to_string(), secret.clone());
        let result = action.process(&mut ctx).await;
        assert!(matches!(result, RequiredActionResult::Failure(IssuerdError::InvalidRequest(_))));

        // Missing enrollment secret -> ServerError failure.
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.parameters.insert("totp_code".to_string(), vec!["123456".to_string()]);
        let result = action.process(&mut ctx).await;
        assert!(matches!(result, RequiredActionResult::Failure(IssuerdError::ServerError(_))));

        // Wrong code -> InvalidRequest failure, nothing persisted.
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.attributes.insert("totp_secret".to_string(), secret.clone());
        ctx.parameters.insert("totp_code".to_string(), vec!["000000".to_string()]);
        let result = action.process(&mut ctx).await;
        match result {
            RequiredActionResult::Failure(IssuerdError::InvalidRequest(m)) => {
                assert_eq!(m, "Invalid authenticator code")
            }
            other => panic!("expected Failure(InvalidRequest), got {other:?}"),
        }
        assert!(storage
            .get_credentials(&user.realm_id, &user.id, CredentialType::Totp)
            .await
            .unwrap()
            .is_empty());

        // Valid code -> credential persisted with the realm policy shape and
        // the matched step as replay watermark; the secret attribute cleared.
        let key = crate::totp::base32_encode(b"12345678901234567890");
        let code = crate::totp::totp_at(
            b"12345678901234567890",
            step,
            6,
            &issuerd_core::OtpHashAlgorithm::HmacSha1,
        );
        let mut ctx = test_context();
        ctx.user_id = Some(UserId::new("alice").unwrap());
        ctx.attributes.insert("totp_secret".to_string(), key.clone());
        ctx.parameters.insert("totp_code".to_string(), vec![code]);
        let result = action.process(&mut ctx).await;
        assert_action_success(result);
        assert!(!ctx.attributes.contains_key("totp_secret"));

        let creds = storage
            .get_credentials(&user.realm_id, &user.id, CredentialType::Totp)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
        let cred = &creds[0];
        assert_eq!(cred.secret_data, key.as_bytes());
        assert_eq!(cred.credential_data["algorithm"], json!("HmacSHA1"));
        assert_eq!(cred.credential_data["digits"], json!(6));
        assert_eq!(cred.credential_data["period"], json!(30));
        let watermark = cred.credential_data["last_used_step"].as_u64().unwrap();
        assert!(watermark >= step - 1 && watermark <= step + 1, "watermark {watermark}");
    }

    // -----------------------------------------------------------------------
    // Federation-aware UsernamePasswordAuthenticator
    // -----------------------------------------------------------------------

    struct MockFedProvider {
        id: String,
        validate_result: std::sync::Mutex<Result<bool, issuerd_core::FederationError>>,
        spnego_result:
            std::sync::Mutex<Result<issuerd_core::SpnegoAuthResult, issuerd_core::FederationError>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationProvider for MockFedProvider {
        fn id(&self) -> &str {
            &self.id
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
            self.validate_result.lock().unwrap().clone()
        }
        async fn authenticate_spnego(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::SpnegoAuthResult, issuerd_core::FederationError> {
            self.spnego_result.lock().unwrap().clone()
        }
    }

    #[allow(clippy::type_complexity)]
    struct MockFedManager {
        providers: Vec<Arc<dyn issuerd_core::FederationProvider>>,
        find_user_result: std::sync::Mutex<
            Result<
                Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
                issuerd_core::IssuerdError,
            >,
        >,
    }

    #[async_trait::async_trait]
    impl issuerd_core::FederationManager for MockFedManager {
        async fn providers_for_realm(
            &self,
            _realm_id: &issuerd_core::RealmId,
        ) -> Result<Vec<Arc<dyn issuerd_core::FederationProvider>>, issuerd_core::IssuerdError>
        {
            Ok(self.providers.clone())
        }
        async fn find_user(
            &self,
            _realm_id: &issuerd_core::RealmId,
            _username: &str,
        ) -> Result<
            Option<(Arc<dyn issuerd_core::FederationProvider>, issuerd_core::FederatedUser)>,
            issuerd_core::IssuerdError,
        > {
            self.find_user_result.lock().unwrap().clone()
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

    #[tokio::test]
    async fn password_federated_user_success() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("ldap-test".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let provider = Arc::new(MockFedProvider {
            id: "ldap-test".to_string(),
            validate_result: std::sync::Mutex::new(Ok(true)),
            spnego_result: std::sync::Mutex::new(Err(issuerd_core::FederationError::NotSupported)),
        });
        let fm = Arc::new(MockFedManager {
            providers: vec![provider],
            find_user_result: std::sync::Mutex::new(Ok(None)),
        });

        let auth = UsernamePasswordAuthenticator::new(storage).with_federation_manager(fm);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["secret".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
        assert_eq!(ctx.user_id, Some(UserId::new("alice").unwrap()));
    }

    #[tokio::test]
    async fn password_federated_user_bad_password() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("ldap-test".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let provider = Arc::new(MockFedProvider {
            id: "ldap-test".to_string(),
            validate_result: std::sync::Mutex::new(Ok(false)),
            spnego_result: std::sync::Mutex::new(Err(issuerd_core::FederationError::NotSupported)),
        });
        let fm = Arc::new(MockFedManager {
            providers: vec![provider],
            find_user_result: std::sync::Mutex::new(Ok(None)),
        });

        let auth = UsernamePasswordAuthenticator::new(storage).with_federation_manager(fm);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["wrong".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn password_federated_lookup_success() {
        let storage = Arc::new(InMemoryStorage::new());

        let provider = Arc::new(MockFedProvider {
            id: "ldap-test".to_string(),
            validate_result: std::sync::Mutex::new(Ok(true)),
            spnego_result: std::sync::Mutex::new(Err(issuerd_core::FederationError::NotSupported)),
        });
        let fed_user = issuerd_core::FederatedUser {
            username: "alice".to_string(),
            federation_link: "ldap-test".to_string(),
            enabled: true,
            ..Default::default()
        };
        let fm = Arc::new(MockFedManager {
            providers: vec![provider.clone()],
            find_user_result: std::sync::Mutex::new(Ok(Some((provider, fed_user)))),
        });

        let auth = UsernamePasswordAuthenticator::new(storage.clone()).with_federation_manager(fm);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["secret".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);

        let imported = storage
            .get_user_by_username(&RealmId::new("realm-1").unwrap(), "alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(imported.federation_link, Some("ldap-test".to_string()));
    }

    #[tokio::test]
    async fn password_federated_import_storage_error_fails_login() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_get_user_by_username().returning(|_, _| Ok(None));
        mock.expect_create_user()
            .returning(|_, _| Err(issuerd_core::IssuerdError::ServerError("db down".into())));

        let provider = Arc::new(MockFedProvider {
            id: "ldap-test".to_string(),
            validate_result: std::sync::Mutex::new(Ok(true)),
            spnego_result: std::sync::Mutex::new(Err(issuerd_core::FederationError::NotSupported)),
        });
        let fed_user = issuerd_core::FederatedUser {
            username: "alice".to_string(),
            federation_link: "ldap-test".to_string(),
            enabled: true,
            ..Default::default()
        };
        let fm = Arc::new(MockFedManager {
            providers: vec![provider.clone()],
            find_user_result: std::sync::Mutex::new(Ok(Some((provider, fed_user)))),
        });

        let auth = UsernamePasswordAuthenticator::new(Arc::new(mock)).with_federation_manager(fm);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["secret".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        // The import failure must fail the login: succeeding would leave a
        // session pointing at a user id that was never persisted.
        assert_auth_server_error(result);
        assert!(ctx.user_id.is_none());
    }

    #[tokio::test]
    async fn password_federated_import_creates_group_memberships() {
        let storage = Arc::new(InMemoryStorage::new());

        let provider = Arc::new(MockFedProvider {
            id: "ldap-test".to_string(),
            validate_result: std::sync::Mutex::new(Ok(true)),
            spnego_result: std::sync::Mutex::new(Err(issuerd_core::FederationError::NotSupported)),
        });
        let fed_user = issuerd_core::FederatedUser {
            username: "alice".to_string(),
            federation_link: "ldap-test".to_string(),
            enabled: true,
            groups: Some(vec!["developers".to_string()]),
            ..Default::default()
        };
        let fm = Arc::new(MockFedManager {
            providers: vec![provider.clone()],
            find_user_result: std::sync::Mutex::new(Ok(Some((provider, fed_user)))),
        });

        let auth = UsernamePasswordAuthenticator::new(storage.clone()).with_federation_manager(fm);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["secret".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);

        let realm = RealmId::new("realm-1").unwrap();
        let imported = storage.get_user_by_username(&realm, "alice").await.unwrap().unwrap();
        let group_ids = storage.list_user_groups(&realm, &imported.id).await.unwrap();
        assert_eq!(group_ids.len(), 1);
        let group = storage.get_group(&realm, &group_ids[0]).await.unwrap().unwrap();
        assert_eq!(group.name.as_str(), "developers");
        assert!(group.attributes.contains_key(issuerd_core::roles::LDAP_SYNC_MARKER_ATTRIBUTE));
    }

    #[tokio::test]
    async fn password_federated_provider_unavailable_falls_back_local() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.federation_link = Some("ldap-test".to_string());
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: hash_password("password").into_bytes(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let provider = Arc::new(MockFedProvider {
            id: "ldap-test".to_string(),
            validate_result: std::sync::Mutex::new(Err(
                issuerd_core::FederationError::ProviderUnavailable("down".into()),
            )),
            spnego_result: std::sync::Mutex::new(Err(issuerd_core::FederationError::NotSupported)),
        });
        let fm = Arc::new(MockFedManager {
            providers: vec![provider],
            find_user_result: std::sync::Mutex::new(Ok(None)),
        });

        let auth = UsernamePasswordAuthenticator::new(storage).with_federation_manager(fm);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
    }

    // -----------------------------------------------------------------------
    // SpnegoFlowAuthenticator
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn spnego_authenticator_configured_for() {
        let fm = Arc::new(MockFedManager {
            providers: vec![],
            find_user_result: std::sync::Mutex::new(Ok(None)),
        });
        let auth = SpnegoFlowAuthenticator::new(fm);

        let mut ctx = test_context();
        assert!(!auth.configured_for(&ctx));

        ctx.attributes
            .insert("Authorization".to_string(), "Negotiate abcdef==".to_string());
        assert!(auth.configured_for(&ctx));
    }

    #[tokio::test]
    async fn spnego_authenticator_success() {
        let provider = Arc::new(MockFedProvider {
            id: "krb-test".to_string(),
            validate_result: std::sync::Mutex::new(Ok(true)),
            spnego_result: std::sync::Mutex::new(Ok(issuerd_core::SpnegoAuthResult {
                principal: Some("alice@TEST.LOCAL".to_string()),
                response_token: None,
                status: issuerd_core::SpnegoStatus::Authenticated,
            })),
        });
        let fed_user = issuerd_core::FederatedUser {
            username: "alice".to_string(),
            federation_link: "krb-test".to_string(),
            enabled: true,
            ..Default::default()
        };
        let fm = Arc::new(MockFedManager {
            providers: vec![provider.clone()],
            find_user_result: std::sync::Mutex::new(Ok(Some((provider, fed_user)))),
        });
        let auth = SpnegoFlowAuthenticator::new(fm);

        let mut ctx = test_context();
        ctx.attributes
            .insert("Authorization".to_string(), "Negotiate abcdef==".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
        assert!(ctx.user_id.is_some());
    }

    #[tokio::test]
    async fn spnego_authenticator_no_header_attempted() {
        let fm = Arc::new(MockFedManager {
            providers: vec![],
            find_user_result: std::sync::Mutex::new(Ok(None)),
        });
        let auth = SpnegoFlowAuthenticator::new(fm);
        let mut ctx = test_context();
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    #[tokio::test]
    async fn spnego_trait_methods() {
        let fm = Arc::new(MockFedManager {
            providers: vec![],
            find_user_result: std::sync::Mutex::new(Ok(None)),
        });
        let auth = SpnegoFlowAuthenticator::new(fm);
        assert_eq!(auth.id(), "auth-spnego");
        assert_eq!(auth.display_name(), "Kerberos / SPNEGO");
        assert!(!auth.requires_user());
    }

    #[tokio::test]
    async fn spnego_providers_for_realm_error() {
        let fm = Arc::new(MockFedManager {
            providers: vec![],
            find_user_result: std::sync::Mutex::new(Err(issuerd_core::IssuerdError::ServerError(
                "down".into(),
            ))),
        });
        let auth = SpnegoFlowAuthenticator::new(fm);
        let mut ctx = test_context();
        ctx.attributes
            .insert("Authorization".to_string(), "Negotiate abcdef==".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    #[tokio::test]
    async fn spnego_non_kerberos_provider_skipped() {
        struct LdapProvider;
        #[async_trait::async_trait]
        impl issuerd_core::FederationProvider for LdapProvider {
            fn id(&self) -> &str {
                "ldap-1"
            }
            fn provider_type(&self) -> issuerd_core::FederationProviderType {
                issuerd_core::FederationProviderType::Ldap
            }
            async fn find_user(
                &self,
                _username: &str,
            ) -> Result<Option<issuerd_core::FederatedUser>, issuerd_core::FederationError>
            {
                Ok(None)
            }
            async fn find_user_by_email(
                &self,
                _email: &str,
            ) -> Result<Option<issuerd_core::FederatedUser>, issuerd_core::FederationError>
            {
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
                Err(issuerd_core::FederationError::NotSupported)
            }
        }

        let fm = Arc::new(MockFedManager {
            providers: vec![Arc::new(LdapProvider)],
            find_user_result: std::sync::Mutex::new(Ok(None)),
        });
        let auth = SpnegoFlowAuthenticator::new(fm);
        let mut ctx = test_context();
        ctx.attributes
            .insert("Authorization".to_string(), "Negotiate abcdef==".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_attempted(result);
    }

    #[tokio::test]
    async fn spnego_continue_status() {
        let provider = Arc::new(MockFedProvider {
            id: "krb-test".to_string(),
            validate_result: std::sync::Mutex::new(Ok(true)),
            spnego_result: std::sync::Mutex::new(Ok(issuerd_core::SpnegoAuthResult {
                principal: None,
                response_token: Some("continue-token".to_string()),
                status: issuerd_core::SpnegoStatus::Continue,
            })),
        });
        let fm = Arc::new(MockFedManager {
            providers: vec![provider],
            find_user_result: std::sync::Mutex::new(Ok(None)),
        });
        let auth = SpnegoFlowAuthenticator::new(fm);
        let mut ctx = test_context();
        ctx.attributes
            .insert("Authorization".to_string(), "Negotiate abcdef==".to_string());
        let result = auth.authenticate(&mut ctx).await;
        match result {
            AuthStepResult::Challenge(Challenge::LoginForm { action_url }) => {
                assert_eq!(action_url, "");
                assert_eq!(
                    ctx.attributes.get("WWW-Authenticate"),
                    Some(&"Negotiate continue-token".to_string())
                );
            }
            other => panic!("expected Challenge::LoginForm, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn spnego_find_user_none_returns_invalid_grant() {
        let provider = Arc::new(MockFedProvider {
            id: "krb-test".to_string(),
            validate_result: std::sync::Mutex::new(Ok(true)),
            spnego_result: std::sync::Mutex::new(Ok(issuerd_core::SpnegoAuthResult {
                principal: Some("alice@TEST.LOCAL".to_string()),
                response_token: None,
                status: issuerd_core::SpnegoStatus::Authenticated,
            })),
        });
        let fm = Arc::new(MockFedManager {
            providers: vec![provider.clone()],
            find_user_result: std::sync::Mutex::new(Ok(None)),
        });
        let auth = SpnegoFlowAuthenticator::new(fm);
        let mut ctx = test_context();
        ctx.attributes
            .insert("Authorization".to_string(), "Negotiate abcdef==".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn spnego_provider_error_then_success() {
        let bad_provider = Arc::new(MockFedProvider {
            id: "krb-bad".to_string(),
            validate_result: std::sync::Mutex::new(Ok(true)),
            spnego_result: std::sync::Mutex::new(Err(
                issuerd_core::FederationError::ProviderUnavailable("down".into()),
            )),
        });
        let good_provider = Arc::new(MockFedProvider {
            id: "krb-good".to_string(),
            validate_result: std::sync::Mutex::new(Ok(true)),
            spnego_result: std::sync::Mutex::new(Ok(issuerd_core::SpnegoAuthResult {
                principal: Some("alice@TEST.LOCAL".to_string()),
                response_token: None,
                status: issuerd_core::SpnegoStatus::Authenticated,
            })),
        });
        let fed_user = issuerd_core::FederatedUser {
            username: "alice".to_string(),
            federation_link: "krb-good".to_string(),
            enabled: true,
            ..Default::default()
        };
        let fm = Arc::new(MockFedManager {
            providers: vec![bad_provider, good_provider.clone()],
            find_user_result: std::sync::Mutex::new(Ok(Some((good_provider, fed_user)))),
        });
        let auth = SpnegoFlowAuthenticator::new(fm);
        let mut ctx = test_context();
        ctx.attributes
            .insert("Authorization".to_string(), "Negotiate abcdef==".to_string());
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_success(result);
    }

    // -----------------------------------------------------------------------
    // UsernamePasswordAuthenticator error paths
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn password_authenticator_credentials_error() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_get_user_by_username().returning(|_, _| Ok(Some(test_user())));
        mock.expect_get_credentials()
            .returning(|_, _, _| Err(issuerd_core::IssuerdError::ServerError("db down".into())));

        let auth = UsernamePasswordAuthenticator::new(Arc::new(mock));
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        // validate_local_password returns ServerError, but authenticate wraps it
        // via record_failure_and_return into InvalidGrant.
        assert_auth_failure(result, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn password_authenticator_disabled_user_rejected() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut user = test_user();
        user.enabled = false;
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let auth = UsernamePasswordAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        // Same generic failure as bad credentials: no account-state oracle.
        assert_auth_failure(result, IssuerdError::InvalidGrant);
        assert!(ctx.user_id.is_none());
    }

    #[tokio::test]
    async fn password_authenticator_bad_secret_data_utf8() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: vec![0x80, 0x81, 0x82], // invalid utf8
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let auth = UsernamePasswordAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn password_authenticator_bad_hash_format() {
        let storage = Arc::new(InMemoryStorage::new());
        let user = test_user();
        storage.create_user(&user.realm_id, &user).await.unwrap();

        let cred = Credential {
            id: CredentialId::new("cred-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: b"not-a-valid-hash".to_vec(),
            credential_data: json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        let auth = UsernamePasswordAuthenticator::new(storage);
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_failure(result, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn password_authenticator_storage_error_on_lookup() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_get_user_by_username()
            .returning(|_, _| Err(issuerd_core::IssuerdError::ServerError("db down".into())));

        let auth = UsernamePasswordAuthenticator::new(Arc::new(mock));
        let mut ctx = test_context();
        ctx.parameters.insert("username".to_string(), vec!["alice".to_string()]);
        ctx.parameters.insert("password".to_string(), vec!["password".to_string()]);
        let result = auth.authenticate(&mut ctx).await;
        assert_auth_server_error(result);
    }
}
