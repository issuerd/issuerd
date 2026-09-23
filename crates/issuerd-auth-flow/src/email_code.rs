// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Passwordless email one-time-code authenticator.
//!
//! `auth-email-code` is a browser-flow stage that authenticates the user with
//! a short numeric code emailed to their address — intended as the **only**
//! factor in passwordless realms (no password check anywhere in the flow).
//!
//! Stage contract:
//!
//! - No parameters → [`Challenge::LoginForm`]: the login page renders and
//!   posts the user's email address as `username` (no password field).
//! - `username` present → resolve the user (by email, then by username),
//!   mint a code, persist it in the distributed cache under
//!   `email-code:{realm}:{user_id}`, send it via [`EmailCodeSender`], and
//!   challenge with [`Challenge::OtpForm`]. Unknown/disabled/no-email users
//!   get the same challenge without a mail and without binding
//!   `context.user_id`, so the endpoint does not leak account existence.
//! - `otp` present → verify the submitted code against the cache entry.
//!   Codes are single-use and expire with the cache entry's TTL. A wrong
//!   code is NEVER a `Failure` — the stage re-challenges instead (same
//!   reasoning as [`crate::built_in::OtpFormAuthenticator`]: at a
//!   conditional stage the executor swallows failures, which would bypass
//!   the factor).
//! - `resend=1`/`resend=true` → mint and send a fresh code for the already
//!   bound user, subject to the per-entry send limit.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use issuerd_core::{
    AuthContext, AuthStepResult, Challenge, DistributedCache, IssuerdError, Realm, RealmId,
    Storage, User, UserId,
};
use ring::rand::SecureRandom;
use subtle::ConstantTimeEq;
use tracing::{debug, instrument, warn};

/// Authenticator id referenced by flow stages and the plugin registry.
pub const AUTHENTICATOR_ID: &str = "auth-email-code";

/// Realm attribute (`"true"`) that switches the login page into email-code
/// mode (email field instead of username+password).
pub const REALM_ATTR_EMAIL_CODE_LOGIN: &str = "email_code_login";
/// Realm attribute overriding the generated code length.
pub const REALM_ATTR_CODE_LENGTH: &str = "email_code_length";
/// Realm attribute overriding the code entry TTL (seconds).
pub const REALM_ATTR_TTL_SECS: &str = "email_code_ttl_secs";

/// Default generated code length (digits).
pub const DEFAULT_CODE_LENGTH: usize = 6;
/// Default cache-entry TTL (seconds): the code expires with the entry.
pub const DEFAULT_TTL_SECS: u64 = 300;
/// Wrong-code submissions after which the entry is burned.
pub const MAX_VERIFY_ATTEMPTS: u32 = 5;
/// Number of codes that may be emailed per entry lifetime.
pub const MAX_SENDS: u32 = 5;

/// Largest code length accepted from the realm attribute — guards against
/// pathological values (and against length 0, which would compare equal to
/// an empty submission).
const MAX_CODE_LENGTH: usize = 32;

/// Sends a freshly minted login code to the user's email address.
///
/// Same `dyn`-trait pattern as the other injected services: the
/// authenticator depends on the trait, `issuerd-server` provides the SMTP-backed
/// implementation, and tests substitute a recording one.
#[async_trait]
pub trait EmailCodeSender: Send + Sync {
    async fn send_login_code(
        &self,
        realm: &Realm,
        to: &str,
        code: &str,
        ttl_secs: u64,
    ) -> Result<(), IssuerdError>;
}

/// State tracked per (realm, user) while a code is in flight. The cache
/// entry's TTL enforces code expiry; a missing entry means "expired or never
/// issued".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EmailCodeEntry {
    code: String,
    /// Failed verification attempts since the current code was issued.
    attempts: u32,
    /// Codes emailed within this entry's lifetime (resends included).
    sends: u32,
}

/// Cache key holding the in-flight code entry for a user.
fn entry_key(realm_id: &RealmId, user_id: &UserId) -> String {
    format!("email-code:{realm_id}:{user_id}")
}

fn otp_challenge() -> AuthStepResult {
    AuthStepResult::Challenge(Challenge::OtpForm {
        action_url: String::new(),
    })
}

/// First value of a form parameter, if present.
fn param(context: &AuthContext, key: &str) -> Option<String> {
    context.parameters.get(key).and_then(|v| v.first()).cloned()
}

/// Generate a `digits`-long numeric code via rejection sampling so every
/// digit is uniform (no modulo bias).
fn generate_code(digits: usize) -> Result<String, IssuerdError> {
    let rng = ring::rand::SystemRandom::new();
    let mut code = String::with_capacity(digits);
    let mut buf = [0u8; 32];
    while code.len() < digits {
        rng.fill(&mut buf)
            .map_err(|_| IssuerdError::ServerError("secure RNG unavailable".to_string()))?;
        for &b in &buf {
            // 250 is the largest multiple of 10 representable in a u8;
            // rejecting 250..=255 keeps every digit equally likely.
            if b >= 250 {
                continue;
            }
            code.push(char::from(b'0' + (b % 10)));
            if code.len() == digits {
                break;
            }
        }
    }
    Ok(code)
}

/// Code length from the realm attributes, falling back to the default for
/// missing/invalid/out-of-range values. Public so the login UI can render the
/// matching number of digit boxes.
pub fn code_length(realm: &Realm) -> usize {
    realm
        .attributes
        .get(REALM_ATTR_CODE_LENGTH)
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| (1..=MAX_CODE_LENGTH).contains(&n))
        .unwrap_or(DEFAULT_CODE_LENGTH)
}

/// Code-entry TTL from the realm attributes, falling back to the default.
fn ttl_secs(realm: &Realm) -> u64 {
    realm
        .attributes
        .get(REALM_ATTR_TTL_SECS)
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_TTL_SECS)
}

/// Passwordless browser authenticator: emails a one-time code as the only
/// login factor. See the module docs for the stage contract.
pub struct EmailCodeAuthenticator {
    storage: Arc<dyn Storage>,
    cache: Arc<dyn DistributedCache>,
    mailer: Arc<dyn EmailCodeSender>,
}

impl EmailCodeAuthenticator {
    pub fn new(
        storage: Arc<dyn Storage>,
        cache: Arc<dyn DistributedCache>,
        mailer: Arc<dyn EmailCodeSender>,
    ) -> Self {
        Self {
            storage,
            cache,
            mailer,
        }
    }

    async fn load_entry(&self, key: &str) -> Result<Option<EmailCodeEntry>, IssuerdError> {
        match self.cache.get(key).await? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| IssuerdError::ServerError(format!("corrupt email-code entry: {e}"))),
            None => Ok(None),
        }
    }

    async fn store_entry(
        &self,
        key: &str,
        entry: &EmailCodeEntry,
        ttl: u64,
    ) -> Result<(), IssuerdError> {
        let bytes = serde_json::to_vec(entry).map_err(|e| {
            IssuerdError::ServerError(format!("failed to encode email-code entry: {e}"))
        })?;
        self.cache.set(key, bytes, Some(Duration::from_secs(ttl))).await
    }

    /// Resolve the login-page identifier to a user: email address first
    /// (the page posts the email as `username`), username as fallback.
    async fn resolve_user(
        &self,
        realm_id: &RealmId,
        login: &str,
    ) -> Result<Option<User>, IssuerdError> {
        if let Some(user) = self.storage.get_user_by_email(realm_id, login).await? {
            return Ok(Some(user));
        }
        self.storage.get_user_by_username(realm_id, login).await
    }

    /// Mint a fresh code for `user`, persist the entry, and email it. Shared
    /// by the login-page submission and the resend button. Binds
    /// `context.user_id` so the resumed flow can verify/resend.
    async fn issue_code(
        &self,
        context: &mut AuthContext,
        realm: &Realm,
        user: &User,
        email: &str,
    ) -> AuthStepResult {
        context.user_id = Some(user.id.clone());
        let key = entry_key(&context.realm_id, &user.id);
        let prior_sends = match self.load_entry(&key).await {
            Ok(Some(entry)) => entry.sends,
            Ok(None) => 0,
            Err(e) => return AuthStepResult::Failure(e),
        };
        if prior_sends >= MAX_SENDS {
            // TODO: signal "too many codes sent" to the page instead of a
            // bare re-challenge (the last mailed code stays valid).
            debug!(user_id = %user.id, sends = prior_sends, "email-code send limit reached; not sending");
            return otp_challenge();
        }
        let ttl = ttl_secs(realm);
        let code = match generate_code(code_length(realm)) {
            Ok(code) => code,
            Err(e) => return AuthStepResult::Failure(e),
        };
        let entry = EmailCodeEntry {
            code: code.clone(),
            attempts: 0,
            sends: prior_sends + 1,
        };
        if let Err(e) = self.store_entry(&key, &entry, ttl).await {
            warn!(user_id = %user.id, error = %e, "failed to store email login code entry");
            return AuthStepResult::Failure(e);
        }
        if let Err(e) = self.mailer.send_login_code(realm, email, &code, ttl).await {
            warn!(user_id = %user.id, error = %e, "failed to send email login code");
            return AuthStepResult::Failure(e);
        }
        otp_challenge()
    }

    /// Login-page submission: the email address arrives as `username`.
    async fn mint_and_send(&self, context: &mut AuthContext, login: &str) -> AuthStepResult {
        let user = match self.resolve_user(&context.realm_id, login).await {
            Ok(user) => user,
            Err(e) => return AuthStepResult::Failure(e),
        };
        let eligible = user.filter(|u| u.enabled && u.email.is_some());
        let Some(user) = eligible else {
            // Indistinguishable from "no such user": no mail is sent and the
            // user stays unbound so a later code submission cannot verify.
            debug!(login = %login, "no eligible user for the submitted identifier; not sending a code");
            return otp_challenge();
        };
        let realm = match self.storage.get_realm(&context.realm_id).await {
            Ok(Some(realm)) => realm,
            Err(e) => return AuthStepResult::Failure(e),
            // Realm row gone mid-flow: cannot render or send the mail, so
            // degrade to the no-leak challenge without binding the user.
            Ok(None) => return otp_challenge(),
        };
        let email = user.email.as_ref().expect("eligibility checked above").as_str().to_string();
        self.issue_code(context, &realm, &user, &email).await
    }

    /// Resend button on the code page: mint and mail a fresh code for the
    /// already bound user, subject to the send limit.
    async fn resend(&self, context: &mut AuthContext) -> AuthStepResult {
        let Some(user_id) = context.user_id.clone() else {
            // Nobody to send to (the login page submitted an unknown email):
            // stay on the code page, indistinguishable from a real send.
            debug!("resend requested without a bound user; not sending a code");
            return otp_challenge();
        };
        let user = match self.storage.get_user(&context.realm_id, &user_id).await {
            Ok(Some(user)) => user,
            Ok(None) => return otp_challenge(),
            Err(e) => return AuthStepResult::Failure(e),
        };
        let realm = match self.storage.get_realm(&context.realm_id).await {
            Ok(Some(realm)) => realm,
            Ok(None) => return otp_challenge(),
            Err(e) => return AuthStepResult::Failure(e),
        };
        let Some(email) = user.email.clone() else {
            return otp_challenge();
        };
        if !user.enabled {
            return otp_challenge();
        }
        self.issue_code(context, &realm, &user, email.as_str()).await
    }

    /// Code submission: verify against the cache entry. Single-use on
    /// success; burned after [`MAX_VERIFY_ATTEMPTS`] failures; any other
    /// outcome re-challenges (never `Failure` — see the module docs).
    async fn verify(&self, context: &mut AuthContext, submitted: &str) -> AuthStepResult {
        let Some(user_id) = context.user_id.clone() else {
            // No bound user (the entered email resolved to nobody): any code
            // submission just re-renders the page.
            return otp_challenge();
        };
        let key = entry_key(&context.realm_id, &user_id);
        let entry = match self.load_entry(&key).await {
            Ok(Some(entry)) => entry,
            // Expired (cache TTL) or never issued.
            Ok(None) => return otp_challenge(),
            Err(e) => return AuthStepResult::Failure(e),
        };
        let matches: bool = submitted.as_bytes().ct_eq(entry.code.as_bytes()).into();
        if matches {
            // Single-use: consume the entry before reporting success.
            if let Err(e) = self.cache.delete(&key).await {
                return AuthStepResult::Failure(e);
            }
            context.attributes.insert("auth_method".to_string(), "email_code".to_string());
            return AuthStepResult::Success;
        }

        let attempts = entry.attempts + 1;
        if attempts >= MAX_VERIFY_ATTEMPTS {
            // Burn the code: further submissions hit the missing-entry path.
            if let Err(e) = self.cache.delete(&key).await {
                return AuthStepResult::Failure(e);
            }
            warn!(user_id = %user_id, attempts = attempts, "email login code burned after repeated failed attempts");
        } else {
            // The cache API has no keep-TTL set, so the entry TTL restarts on
            // each failed attempt — bounded by MAX_VERIFY_ATTEMPTS.
            let ttl = match self.storage.get_realm(&context.realm_id).await {
                Ok(Some(realm)) => ttl_secs(&realm),
                Ok(None) => DEFAULT_TTL_SECS,
                Err(e) => return AuthStepResult::Failure(e),
            };
            let updated = EmailCodeEntry { attempts, ..entry };
            if let Err(e) = self.store_entry(&key, &updated, ttl).await {
                return AuthStepResult::Failure(e);
            }
            debug!(user_id = %user_id, attempts = attempts, "email login code rejected; re-challenging");
        }
        otp_challenge()
    }
}

#[async_trait]
impl issuerd_core::Authenticator for EmailCodeAuthenticator {
    fn id(&self) -> &str {
        AUTHENTICATOR_ID
    }

    fn display_name(&self) -> &str {
        "Email Code"
    }

    /// The stage itself identifies the user (from the posted email address),
    /// so no prior stage has to.
    fn requires_user(&self) -> bool {
        false
    }

    fn configured_for(&self, _context: &AuthContext) -> bool {
        true
    }

    #[instrument(skip(self, context), fields(authenticator = %self.id(), realm = %context.realm_id))]
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult {
        // Explicit resend request from the code page.
        if matches!(param(context, "resend").as_deref(), Some("1" | "true")) {
            return self.resend(context).await;
        }
        // Code submission.
        if let Some(otp) = param(context, "otp") {
            return self.verify(context, &otp).await;
        }
        // Login-page submission (the page posts the email as `username`).
        if let Some(login) = param(context, "username").filter(|v| !v.is_empty()) {
            return self.mint_and_send(context, &login).await;
        }
        // Initial page render.
        AuthStepResult::Challenge(Challenge::LoginForm {
            action_url: String::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use issuerd_core::{Authenticator, Email, RealmName, Username};

    use super::*;

    const REALM: &str = "realm-1";

    #[derive(Default)]
    struct RecordingMailer {
        sent: std::sync::Mutex<Vec<(String, String, u64)>>,
    }

    #[async_trait]
    impl EmailCodeSender for RecordingMailer {
        async fn send_login_code(
            &self,
            _realm: &Realm,
            to: &str,
            code: &str,
            ttl_secs: u64,
        ) -> Result<(), IssuerdError> {
            self.sent.lock().unwrap().push((to.to_string(), code.to_string(), ttl_secs));
            Ok(())
        }
    }

    impl RecordingMailer {
        fn sent(&self) -> Vec<(String, String, u64)> {
            self.sent.lock().unwrap().clone()
        }
    }

    struct FailingMailer;

    #[async_trait]
    impl EmailCodeSender for FailingMailer {
        async fn send_login_code(
            &self,
            _realm: &Realm,
            _to: &str,
            _code: &str,
            _ttl_secs: u64,
        ) -> Result<(), IssuerdError> {
            Err(IssuerdError::ServerError("smtp down".to_string()))
        }
    }

    struct Fixture {
        storage: Arc<issuerd_storage::InMemoryStorage>,
        cache: Arc<issuerd_cluster::InMemoryCache>,
        mailer: Arc<RecordingMailer>,
        authenticator: EmailCodeAuthenticator,
    }

    async fn fixture() -> Fixture {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let cache = Arc::new(issuerd_cluster::InMemoryCache::new());
        let mailer = Arc::new(RecordingMailer::default());
        storage.create_realm(&test_realm()).await.unwrap();
        let authenticator =
            EmailCodeAuthenticator::new(storage.clone(), cache.clone(), mailer.clone());
        Fixture {
            storage,
            cache,
            mailer,
            authenticator,
        }
    }

    fn test_realm() -> Realm {
        Realm {
            id: RealmId::new(REALM).unwrap(),
            name: RealmName::new(REALM).unwrap(),
            display_name: None,
            enabled: true,
            ..Default::default()
        }
    }

    fn test_user(id: &str, username: &str, email: Option<&str>) -> User {
        User {
            id: UserId::new(id).unwrap(),
            realm_id: RealmId::new(REALM).unwrap(),
            username: Username::new(username).unwrap(),
            email: email.map(|e| Email::new(e).unwrap()),
            email_verified: true,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn context() -> AuthContext {
        AuthContext {
            realm_id: RealmId::new(REALM).unwrap(),
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: HashMap::new(),
            attributes: HashMap::new(),
            current_challenge: None,
        }
    }

    fn with_param(mut ctx: AuthContext, key: &str, value: &str) -> AuthContext {
        ctx.parameters.insert(key.to_string(), vec![value.to_string()]);
        ctx
    }

    fn assert_otp_challenge(result: AuthStepResult) {
        assert!(
            matches!(result, AuthStepResult::Challenge(Challenge::OtpForm { .. })),
            "expected OtpForm challenge, got {result:?}"
        );
    }

    /// Mint a code for `login` and return the code captured by the mailer.
    async fn mint(f: &Fixture, login: &str) -> (AuthStepResult, String) {
        let mut ctx = with_param(context(), "username", login);
        let result = f.authenticator.authenticate(&mut ctx).await;
        let sent = f.mailer.sent();
        assert_eq!(sent.len(), 1, "expected exactly one mail: {sent:?}");
        (result, sent[0].1.clone())
    }

    async fn submit_otp(
        f: &Fixture,
        user_id: Option<&str>,
        otp: &str,
    ) -> (AuthStepResult, AuthContext) {
        let mut ctx = with_param(context(), "otp", otp);
        ctx.user_id = user_id.map(|u| UserId::new(u).unwrap());
        let result = f.authenticator.authenticate(&mut ctx).await;
        (result, ctx)
    }

    #[test]
    fn trait_metadata() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let auth = EmailCodeAuthenticator::new(
            storage,
            Arc::new(issuerd_cluster::InMemoryCache::new()),
            Arc::new(RecordingMailer::default()),
        );
        assert_eq!(auth.id(), "auth-email-code");
        assert_eq!(auth.display_name(), "Email Code");
        assert!(!auth.requires_user());
        assert!(auth.configured_for(&context()));
    }

    #[tokio::test]
    async fn no_params_challenges_with_login_form() {
        let f = fixture().await;
        let mut ctx = context();
        let result = f.authenticator.authenticate(&mut ctx).await;
        assert!(
            matches!(result, AuthStepResult::Challenge(Challenge::LoginForm { .. })),
            "expected LoginForm challenge, got {result:?}"
        );
        assert!(f.mailer.sent().is_empty());
    }

    #[tokio::test]
    async fn mint_then_verify_happy_path() {
        let f = fixture().await;
        let user = test_user("u-1", "alice", Some("alice@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();

        let (result, code) = mint(&f, "alice@example.com").await;
        assert_otp_challenge(result);
        let sent = f.mailer.sent();
        assert_eq!(sent[0].0, "alice@example.com");
        assert_eq!(code.len(), DEFAULT_CODE_LENGTH);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(sent[0].2, DEFAULT_TTL_SECS);

        let (result, ctx) = submit_otp(&f, Some("u-1"), &code).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
        assert_eq!(ctx.attributes.get("auth_method").map(String::as_str), Some("email_code"));
    }

    #[tokio::test]
    async fn username_fallback_lookup() {
        let f = fixture().await;
        let user = test_user("u-2", "bob", Some("bob@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();

        // Logging in with the username (not the email) still sends the code
        // to the user's email address.
        let (result, code) = mint(&f, "bob").await;
        assert_otp_challenge(result);
        assert_eq!(f.mailer.sent()[0].0, "bob@example.com");

        let (result, _) = submit_otp(&f, Some("u-2"), &code).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
    }

    #[tokio::test]
    async fn wrong_code_rechallenges_and_counts_attempts() {
        let f = fixture().await;
        let user = test_user("u-3", "carol", Some("carol@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let (_, code) = mint(&f, "carol@example.com").await;
        let wrong = if code == "000000" { "000001" } else { "000000" };

        let (result, _) = submit_otp(&f, Some("u-3"), wrong).await;
        assert_otp_challenge(result);

        // The entry survived with one recorded attempt; the right code still works.
        let key = entry_key(&RealmId::new(REALM).unwrap(), &UserId::new("u-3").unwrap());
        let entry: EmailCodeEntry =
            serde_json::from_slice(&f.cache.get(&key).await.unwrap().unwrap()).unwrap();
        assert_eq!(entry.attempts, 1);
        let (result, _) = submit_otp(&f, Some("u-3"), &code).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
    }

    #[tokio::test]
    async fn five_wrong_attempts_invalidate_the_code() {
        let f = fixture().await;
        let user = test_user("u-4", "dave", Some("dave@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let (_, code) = mint(&f, "dave@example.com").await;
        let wrong = if code == "000000" { "000001" } else { "000000" };

        for _ in 0..MAX_VERIFY_ATTEMPTS {
            let (result, _) = submit_otp(&f, Some("u-4"), wrong).await;
            assert_otp_challenge(result);
        }
        // Entry burned: even the correct code no longer verifies.
        let (result, _) = submit_otp(&f, Some("u-4"), &code).await;
        assert_otp_challenge(result);
    }

    #[tokio::test]
    async fn cache_ttl_expires_the_code() {
        let f = fixture().await;
        let user = test_user("u-5", "erin", Some("erin@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();

        // Simulate an entry minted with a tiny TTL (realm attribute drives
        // this in production); after expiry the code no longer verifies.
        let key = entry_key(&RealmId::new(REALM).unwrap(), &UserId::new("u-5").unwrap());
        let entry = EmailCodeEntry {
            code: "123456".to_string(),
            attempts: 0,
            sends: 1,
        };
        f.cache
            .set(&key, serde_json::to_vec(&entry).unwrap(), Some(Duration::from_millis(50)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(f.cache.get(&key).await.unwrap().is_none(), "entry must expire");

        let (result, _) = submit_otp(&f, Some("u-5"), "123456").await;
        assert_otp_challenge(result);
    }

    #[tokio::test]
    async fn unknown_user_challenges_without_binding_or_sending() {
        let f = fixture().await;
        let mut ctx = with_param(context(), "username", "ghost@example.com");
        let result = f.authenticator.authenticate(&mut ctx).await;
        assert_otp_challenge(result);
        assert!(ctx.user_id.is_none(), "unknown user must not be bound");
        assert!(f.mailer.sent().is_empty(), "no mail for unknown users");

        // A code submission without a bound user just re-challenges.
        let (result, _) = submit_otp(&f, None, "123456").await;
        assert_otp_challenge(result);
    }

    #[tokio::test]
    async fn disabled_user_is_indistinguishable_from_unknown() {
        let f = fixture().await;
        let mut user = test_user("u-6", "frank", Some("frank@example.com"));
        user.enabled = false;
        f.storage.create_user(&user.realm_id, &user).await.unwrap();

        let mut ctx = with_param(context(), "username", "frank@example.com");
        let result = f.authenticator.authenticate(&mut ctx).await;
        assert_otp_challenge(result);
        assert!(ctx.user_id.is_none());
        assert!(f.mailer.sent().is_empty());
    }

    #[tokio::test]
    async fn user_without_email_is_indistinguishable_from_unknown() {
        let f = fixture().await;
        let user = test_user("u-7", "grace", None);
        f.storage.create_user(&user.realm_id, &user).await.unwrap();

        let mut ctx = with_param(context(), "username", "grace");
        let result = f.authenticator.authenticate(&mut ctx).await;
        assert_otp_challenge(result);
        assert!(ctx.user_id.is_none());
        assert!(f.mailer.sent().is_empty());
    }

    #[tokio::test]
    async fn resend_regenerates_and_counts_sends() {
        let f = fixture().await;
        let user = test_user("u-8", "heidi", Some("heidi@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let (_, first_code) = mint(&f, "heidi@example.com").await;

        let mut ctx = with_param(context(), "resend", "1");
        ctx.user_id = Some(UserId::new("u-8").unwrap());
        let result = f.authenticator.authenticate(&mut ctx).await;
        assert_otp_challenge(result);

        let sent = f.mailer.sent();
        assert_eq!(sent.len(), 2, "resend must mail a fresh code");
        let second_code = sent[1].1.clone();
        assert_eq!(second_code.len(), DEFAULT_CODE_LENGTH);

        // The regenerated entry replaced the old code (in the astronomically
        // likely case of a distinct code).
        if first_code != second_code {
            let (result, _) = submit_otp(&f, Some("u-8"), &first_code).await;
            assert_otp_challenge(result);
        }

        // The fresh code verifies; the entry tracks both sends.
        let (result, _) = submit_otp(&f, Some("u-8"), &second_code).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");

        // Resend without a bound user is a no-op challenge.
        let mut ctx = with_param(context(), "resend", "true");
        let result = f.authenticator.authenticate(&mut ctx).await;
        assert_otp_challenge(result);
        assert_eq!(f.mailer.sent().len(), 2, "no mail without a bound user");
    }

    #[tokio::test]
    async fn send_limit_stops_further_mails() {
        let f = fixture().await;
        let user = test_user("u-9", "ivan", Some("ivan@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        mint(&f, "ivan@example.com").await;

        for expected_sends in 2..=MAX_SENDS {
            let mut ctx = with_param(context(), "resend", "1");
            ctx.user_id = Some(UserId::new("u-9").unwrap());
            let result = f.authenticator.authenticate(&mut ctx).await;
            assert_otp_challenge(result);
            assert_eq!(f.mailer.sent().len() as u32, expected_sends);
        }

        // The sixth resend hits the limit: challenge, no mail.
        let mut ctx = with_param(context(), "resend", "1");
        ctx.user_id = Some(UserId::new("u-9").unwrap());
        let result = f.authenticator.authenticate(&mut ctx).await;
        assert_otp_challenge(result);
        assert_eq!(f.mailer.sent().len() as u32, MAX_SENDS);

        // The last mailed code is still valid.
        let code = f.mailer.sent().last().unwrap().1.clone();
        let (result, _) = submit_otp(&f, Some("u-9"), &code).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
    }

    #[tokio::test]
    async fn codes_are_single_use() {
        let f = fixture().await;
        let user = test_user("u-10", "judy", Some("judy@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let (_, code) = mint(&f, "judy@example.com").await;

        let (result, _) = submit_otp(&f, Some("u-10"), &code).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
        // Second use of the same code fails (entry consumed).
        let (result, _) = submit_otp(&f, Some("u-10"), &code).await;
        assert_otp_challenge(result);
    }

    #[tokio::test]
    async fn mailer_failure_fails_the_stage() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        storage.create_realm(&test_realm()).await.unwrap();
        let user = test_user("u-11", "karl", Some("karl@example.com"));
        storage.create_user(&user.realm_id, &user).await.unwrap();
        let auth = EmailCodeAuthenticator::new(
            storage,
            Arc::new(issuerd_cluster::InMemoryCache::new()),
            Arc::new(FailingMailer),
        );

        let mut ctx = with_param(context(), "username", "karl@example.com");
        let result = auth.authenticate(&mut ctx).await;
        assert!(matches!(result, AuthStepResult::Failure(_)), "got {result:?}");
    }

    #[tokio::test]
    async fn realm_attributes_override_length_and_ttl() {
        let f = fixture().await;
        let mut realm = test_realm();
        realm.attributes.insert(REALM_ATTR_CODE_LENGTH.to_string(), "8".to_string());
        realm.attributes.insert(REALM_ATTR_TTL_SECS.to_string(), "60".to_string());
        f.storage.update_realm(&realm).await.unwrap();
        let user = test_user("u-12", "lena", Some("lena@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();

        let (_, code) = mint(&f, "lena@example.com").await;
        assert_eq!(code.len(), 8);
        assert_eq!(f.mailer.sent()[0].2, 60);

        // Invalid attribute values fall back to the defaults.
        assert_eq!(code_length(&test_realm()), DEFAULT_CODE_LENGTH);
        assert_eq!(ttl_secs(&test_realm()), DEFAULT_TTL_SECS);
        let mut weird = test_realm();
        weird.attributes.insert(REALM_ATTR_CODE_LENGTH.to_string(), "0".to_string());
        weird.attributes.insert(REALM_ATTR_TTL_SECS.to_string(), "-5".to_string());
        assert_eq!(code_length(&weird), DEFAULT_CODE_LENGTH);
        assert_eq!(ttl_secs(&weird), DEFAULT_TTL_SECS);
    }

    #[test]
    fn generated_codes_are_uniform_digits() {
        for _ in 0..200 {
            let code = generate_code(DEFAULT_CODE_LENGTH).unwrap();
            assert_eq!(code.len(), DEFAULT_CODE_LENGTH);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
