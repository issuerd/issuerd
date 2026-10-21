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
//!   bound user, subject to per-user and per-source send limits.
//!
//! Rate limits use atomic cache counters with fixed (never sliding) TTLs:
//! submissions are counted per issued code and source before comparison, and
//! mailed codes per (realm, user) and source within a code-TTL window. Burning
//! or replacing a code does not reset the send budget; a successful login does.
//! Consumption and burning use atomic compare-and-delete, so a stale flow
//! cannot consume or burn a newer code.

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
/// Submissions allowed per issued code; reaching it without a match burns
/// the code.
pub const MAX_VERIFY_ATTEMPTS: u32 = 5;
/// Number of codes that may be emailed per user within one window of one
/// code TTL, counted from the first mail. Burning a code does not reset it.
pub const MAX_SENDS: u32 = 5;
/// Per-source caps leave one code and its attempts available from another
/// source, so a single attacker cannot exhaust a victim's whole login window.
const MAX_SENDS_PER_IP: u32 = MAX_SENDS - 1;
const MAX_VERIFY_ATTEMPTS_PER_IP: u32 = MAX_SENDS_PER_IP * MAX_VERIFY_ATTEMPTS;

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

/// The code in flight for a (realm, user). The cache entry's TTL enforces
/// code expiry; a missing entry means "expired, burned, used, or never
/// issued". The rate-limit counters live under separate keys so deleting or
/// replacing this entry never resets the send budget.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EmailCodeEntry {
    code: String,
    /// Names this code's attempt counter. Absent in entries written by
    /// nodes predating the atomic counters.
    #[serde(default)]
    nonce: Option<String>,
    /// Code TTL in seconds at issue time; sizes this code's attempt-counter
    /// window. Absent in entries written by nodes predating the atomic
    /// counters ([`DEFAULT_TTL_SECS`] applies).
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// Attempts recorded in the entry itself: written as 0 and never updated
    /// here; nodes predating the atomic counters count in it.
    attempts: u32,
    /// Copy of the per-user send count, kept so nodes predating the atomic
    /// counters still enforce the send limit during a rolling upgrade.
    sends: u32,
}

/// Cache key holding the in-flight code entry for a user.
fn entry_key(realm_id: &RealmId, user_id: &UserId) -> String {
    format!("email-code:{realm_id}:{user_id}")
}

/// Atomic counter of submissions against one issued code (see
/// [`MAX_VERIFY_ATTEMPTS`]). Entries without a nonce share a `legacy` slot.
fn attempts_key(realm_id: &RealmId, user_id: &UserId, nonce: Option<&str>) -> String {
    let nonce = nonce.unwrap_or("legacy");
    format!("email-code-attempts:{realm_id}:{user_id}:{nonce}")
}

/// Atomic counter of codes mailed to a user (see [`MAX_SENDS`]).
fn sends_key(realm_id: &RealmId, user_id: &UserId) -> String {
    format!("email-code-sends:{realm_id}:{user_id}")
}

fn sends_ip_key(realm_id: &RealmId, user_id: &UserId, ip: std::net::IpAddr) -> String {
    format!("email-code-sends-ip:{realm_id}:{user_id}:{ip}")
}

fn attempts_ip_key(realm_id: &RealmId, user_id: &UserId, ip: std::net::IpAddr) -> String {
    format!("email-code-attempts-ip:{realm_id}:{user_id}:{ip}")
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

    async fn load_entry(
        &self,
        key: &str,
    ) -> Result<Option<(EmailCodeEntry, Vec<u8>)>, IssuerdError> {
        match self.cache.get(key).await? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(|entry| Some((entry, bytes)))
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

    /// Charge one mail against the user's send budget and return the new
    /// count, or `None` once the limit is reached. The increment is atomic,
    /// so concurrent requests each get a distinct count, and its TTL applies
    /// only when the counter is created, so the window never slides.
    async fn charge_send(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        ip_address: Option<std::net::IpAddr>,
        ttl: u64,
    ) -> Result<Option<u32>, IssuerdError> {
        let window = Some(Duration::from_secs(ttl));
        if let Some(ip) = ip_address {
            let key = sends_ip_key(realm_id, user_id, ip);
            let source_sends = self.cache.increment(&key, window).await?;
            if source_sends > u64::from(MAX_SENDS_PER_IP) {
                debug!(user_id = %user_id, sends = source_sends,
                    "email-code per-source send limit reached; not sending");
                return Ok(None);
            }
        }
        let sends = self.cache.increment(&sends_key(realm_id, user_id), window).await?;
        match u32::try_from(sends) {
            Ok(n) if n <= MAX_SENDS => Ok(Some(n)),
            _ => {
                debug!(user_id = %user_id, sends = sends, "email-code send limit reached; not sending");
                Ok(None)
            }
        }
    }

    /// A successful login clears the send budget. Best effort: a failed
    /// delete only leaves the counter to expire with its window.
    async fn clear_send_budget(&self, realm_id: &RealmId, user_id: &UserId) {
        if let Err(e) = self.cache.delete(&sends_key(realm_id, user_id)).await {
            warn!(user_id = %user_id, error = %e, "failed to clear email-code send counter");
        }
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
        let ttl = ttl_secs(realm);
        let sends =
            match self.charge_send(&context.realm_id, &user.id, context.ip_address, ttl).await {
                Ok(Some(sends)) => sends,
                // TODO: signal "too many codes sent" to the page instead of a
                // bare re-challenge (the last mailed code stays valid).
                Ok(None) => return otp_challenge(),
                Err(e) => return AuthStepResult::Failure(e),
            };
        let code = match generate_code(code_length(realm)) {
            Ok(code) => code,
            Err(e) => return AuthStepResult::Failure(e),
        };
        let key = entry_key(&context.realm_id, &user.id);
        let entry = EmailCodeEntry {
            code: code.clone(),
            nonce: Some(uuid::Uuid::new_v4().simple().to_string()),
            ttl_secs: Some(ttl),
            attempts: 0,
            sends,
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
    /// success; burned once its submissions reach [`MAX_VERIFY_ATTEMPTS`];
    /// any other outcome re-challenges (never `Failure` — see the module
    /// docs).
    async fn verify(&self, context: &mut AuthContext, submitted: &str) -> AuthStepResult {
        let Some(user_id) = context.user_id.clone() else {
            // No bound user (the entered email resolved to nobody): any code
            // submission just re-renders the page.
            return otp_challenge();
        };
        let key = entry_key(&context.realm_id, &user_id);
        let (entry, raw_entry) = match self.load_entry(&key).await {
            Ok(Some(entry)) => entry,
            // Expired (cache TTL), burned, used, or never issued.
            Ok(None) => return otp_challenge(),
            Err(e) => return AuthStepResult::Failure(e),
        };
        if let Some(ip) = context.ip_address {
            let ttl = entry.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
            let window = ttl.saturating_mul(u64::from(MAX_VERIFY_ATTEMPTS));
            let source_attempts = match self
                .cache
                .increment(
                    &attempts_ip_key(&context.realm_id, &user_id, ip),
                    Some(Duration::from_secs(window)),
                )
                .await
            {
                Ok(count) => count,
                Err(e) => return AuthStepResult::Failure(e),
            };
            if source_attempts > u64::from(MAX_VERIFY_ATTEMPTS_PER_IP) {
                return otp_challenge();
            }
        }
        // Count the submission against this code atomically BEFORE comparing:
        // concurrent submissions from any number of flows bound to this user
        // each get a distinct count, so at most MAX_VERIFY_ATTEMPTS are ever
        // compared per code.
        let attempts = match self.count_attempt(&context.realm_id, &user_id, &entry).await {
            Ok(n) => n,
            Err(e) => return AuthStepResult::Failure(e),
        };
        let max = u64::from(MAX_VERIFY_ATTEMPTS);
        let matches =
            attempts <= max && bool::from(submitted.as_bytes().ct_eq(entry.code.as_bytes()));
        if matches {
            match self.cache.compare_and_delete(&key, raw_entry).await {
                Ok(true) => {}
                Ok(false) => return otp_challenge(),
                Err(e) => return AuthStepResult::Failure(e),
            }
            self.clear_send_budget(&context.realm_id, &user_id).await;
            context.attributes.insert("auth_method".to_string(), "email_code".to_string());
            return AuthStepResult::Success;
        }
        if attempts >= max {
            // A stale flow must never burn a newer code issued for the user.
            match self.cache.compare_and_delete(&key, raw_entry).await {
                Ok(true) => {
                    warn!(user_id = %user_id, attempts = attempts, "email login code burned after repeated failed attempts");
                }
                Ok(false) => {}
                Err(e) => return AuthStepResult::Failure(e),
            }
        } else {
            debug!(user_id = %user_id, attempts = attempts, "email login code rejected; re-challenging");
        }
        otp_challenge()
    }

    /// Count one submission against `entry`'s code and return the total,
    /// including attempts an older node recorded in the entry itself. The
    /// counter's TTL (MAX_VERIFY_ATTEMPTS × the issue-time code TTL) is set
    /// once at creation and comfortably outlives the code itself, so it cannot
    /// expire and restart at 1 while the code is alive.
    async fn count_attempt(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        entry: &EmailCodeEntry,
    ) -> Result<u64, IssuerdError> {
        let key = attempts_key(realm_id, user_id, entry.nonce.as_deref());
        let ttl = entry.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
        let window = Duration::from_secs(ttl.saturating_mul(u64::from(MAX_VERIFY_ATTEMPTS)));
        let counted = self.cache.increment(&key, Some(window)).await?;
        Ok(counted.saturating_add(u64::from(entry.attempts)))
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

    async fn mint_from(f: &Fixture, login: &str, ip: std::net::IpAddr) -> String {
        let mut ctx = with_param(context(), "username", login);
        ctx.ip_address = Some(ip);
        assert_otp_challenge(f.authenticator.authenticate(&mut ctx).await);
        f.mailer.sent().last().unwrap().1.clone()
    }

    async fn submit_otp_from(
        f: &Fixture,
        user_id: &str,
        otp: &str,
        ip: std::net::IpAddr,
    ) -> AuthStepResult {
        let mut ctx = with_param(context(), "otp", otp);
        ctx.user_id = Some(UserId::new(user_id).unwrap());
        ctx.ip_address = Some(ip);
        f.authenticator.authenticate(&mut ctx).await
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

        // One attempt is recorded and the entry survived: the right code still works.
        assert_eq!(code_attempts(&f, "u-3").await, 1);
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
            nonce: None,
            ttl_secs: None,
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

    #[test]
    fn entry_key_is_scoped_per_realm_and_user() {
        let realm = RealmId::new("realm-1").unwrap();
        let other_realm = RealmId::new("realm-2").unwrap();
        let user = UserId::new("u-1").unwrap();
        let other_user = UserId::new("u-2").unwrap();

        assert_eq!(entry_key(&realm, &user), "email-code:realm-1:u-1");
        // Keys must not collide across realms or users: a constant key would
        // let one user's minted code overwrite another's.
        assert_ne!(entry_key(&realm, &user), entry_key(&other_realm, &user));
        assert_ne!(entry_key(&realm, &user), entry_key(&realm, &other_user));
    }

    #[test]
    fn ttl_secs_rejects_zero_and_falls_back_to_default() {
        let mut realm = test_realm();
        realm.attributes.insert(REALM_ATTR_TTL_SECS.to_string(), "0".to_string());
        // A zero TTL would burn the entry instantly; it falls back to the
        // default like any other invalid value.
        assert_eq!(ttl_secs(&realm), DEFAULT_TTL_SECS);

        let mut realm = test_realm();
        realm.attributes.insert(REALM_ATTR_TTL_SECS.to_string(), "120".to_string());
        assert_eq!(ttl_secs(&realm), 120);
    }

    #[test]
    fn generated_code_uses_the_full_digit_alphabet() {
        // Rejection sampling accepts bytes 0..250, so every digit 0-9 must
        // be reachable. Over 512 digits the original produces a digit >= 6
        // with probability 1 - 0.6^512; a sampler rejecting the wrong byte
        // range (only 250..=255 accepted) can only emit digits 0-5.
        let code = generate_code(512).unwrap();
        assert_eq!(code.len(), 512);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(
            code.chars().any(|c| c >= '6'),
            "512 samples without a digit >= 6: the acceptance range is wrong"
        );
    }

    #[tokio::test]
    async fn codes_are_scoped_per_user() {
        let f = fixture().await;
        let alice = test_user("u-20", "alice", Some("alice@example.com"));
        let bob = test_user("u-21", "bob", Some("bob@example.com"));
        f.storage.create_user(&alice.realm_id, &alice).await.unwrap();
        f.storage.create_user(&bob.realm_id, &bob).await.unwrap();

        // Mint codes for both users; alice's entry must survive bob's mint.
        let mut ctx = with_param(context(), "username", "alice@example.com");
        assert_otp_challenge(f.authenticator.authenticate(&mut ctx).await);
        let mut ctx = with_param(context(), "username", "bob@example.com");
        assert_otp_challenge(f.authenticator.authenticate(&mut ctx).await);
        let sent = f.mailer.sent();
        assert_eq!(sent.len(), 2);
        let alice_code = sent[0].1.clone();

        let (result, _) = submit_otp(&f, Some("u-20"), &alice_code).await;
        assert!(
            matches!(result, AuthStepResult::Success),
            "alice's code must verify after bob's mint: {result:?}"
        );
    }

    async fn resend(f: &Fixture, user_id: &str) -> AuthStepResult {
        let mut ctx = with_param(context(), "resend", "1");
        ctx.user_id = Some(UserId::new(user_id).unwrap());
        f.authenticator.authenticate(&mut ctx).await
    }

    fn wrong_for(code: &str) -> &'static str {
        if code == "000000" {
            "000001"
        } else {
            "000000"
        }
    }

    async fn counter(cache: &dyn DistributedCache, key: &str) -> u64 {
        let value = cache.get(key).await.unwrap();
        value.map_or(0, |b| String::from_utf8(b).unwrap().parse().unwrap())
    }

    async fn stored_entry(cache: &dyn DistributedCache, user_id: &str) -> Option<EmailCodeEntry> {
        let key = entry_key(&RealmId::new(REALM).unwrap(), &UserId::new(user_id).unwrap());
        let value = cache.get(&key).await.unwrap();
        value.map(|b| serde_json::from_slice(&b).unwrap())
    }

    fn code_attempts_key(entry: &EmailCodeEntry, user_id: &str) -> String {
        let user = UserId::new(user_id).unwrap();
        attempts_key(&RealmId::new(REALM).unwrap(), &user, entry.nonce.as_deref())
    }

    /// Submissions counted against the user's current code.
    async fn code_attempts(f: &Fixture, user_id: &str) -> u64 {
        let entry = stored_entry(f.cache.as_ref(), user_id).await.expect("a code in flight");
        counter(f.cache.as_ref(), &code_attempts_key(&entry, user_id)).await
    }

    async fn sends(f: &Fixture, user_id: &str) -> u64 {
        let key = sends_key(&RealmId::new(REALM).unwrap(), &UserId::new(user_id).unwrap());
        counter(f.cache.as_ref(), &key).await
    }

    #[tokio::test]
    async fn burning_a_code_does_not_reset_the_send_budget() {
        let f = fixture().await;
        let user = test_user("u-30", "mona", Some("mona@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();

        // Restart from the login page after every burn: each burned code is
        // replaced while the send budget lasts.
        for expected_sends in 1..=MAX_SENDS {
            let mut ctx = with_param(context(), "username", "mona@example.com");
            assert_otp_challenge(f.authenticator.authenticate(&mut ctx).await);
            let mails = f.mailer.sent();
            assert_eq!(mails.len() as u32, expected_sends);
            let wrong = wrong_for(&mails.last().unwrap().1);
            for _ in 0..MAX_VERIFY_ATTEMPTS {
                assert_otp_challenge(submit_otp(&f, Some("u-30"), wrong).await.0);
            }
        }

        // The burn used to delete the send count with the code, so this
        // restarted at zero and mailed again.
        let mut ctx = with_param(context(), "username", "mona@example.com");
        assert_otp_challenge(f.authenticator.authenticate(&mut ctx).await);
        assert!(ctx.user_id.is_some(), "the user is still bound (no existence leak)");
        assert_otp_challenge(resend(&f, "u-30").await);
        assert_eq!(f.mailer.sent().len() as u32, MAX_SENDS, "send limit survives burns");
    }

    #[tokio::test]
    async fn reissued_code_gets_fresh_attempts() {
        let f = fixture().await;
        let user = test_user("u-31", "nils", Some("nils@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let (_, first) = mint(&f, "nils@example.com").await;
        for _ in 0..MAX_VERIFY_ATTEMPTS {
            assert_otp_challenge(submit_otp(&f, Some("u-31"), wrong_for(&first)).await.0);
        }

        // After a burn the legitimate user gets a new code with its own
        // MAX_VERIFY_ATTEMPTS tries.
        assert_otp_challenge(resend(&f, "u-31").await);
        let second = f.mailer.sent()[1].1.clone();
        for _ in 1..MAX_VERIFY_ATTEMPTS {
            assert_otp_challenge(submit_otp(&f, Some("u-31"), wrong_for(&second)).await.0);
        }
        assert_eq!(code_attempts(&f, "u-31").await, u64::from(MAX_VERIFY_ATTEMPTS) - 1);
        let (result, _) = submit_otp(&f, Some("u-31"), &second).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
    }

    #[tokio::test]
    async fn spent_attempt_budget_refuses_even_the_correct_code() {
        let f = fixture().await;
        let user = test_user("u-35", "sven", Some("sven@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let (_, code) = mint(&f, "sven@example.com").await;

        // The state concurrent submissions leave behind when they loaded the
        // entry before the burn: budget spent, code still present. The next
        // submission is counted before it is compared, so it is refused.
        let entry = stored_entry(f.cache.as_ref(), "u-35").await.unwrap();
        let key = code_attempts_key(&entry, "u-35");
        for _ in 0..MAX_VERIFY_ATTEMPTS {
            f.cache.increment(&key, None).await.unwrap();
        }
        assert_otp_challenge(submit_otp(&f, Some("u-35"), &code).await.0);
        assert!(stored_entry(f.cache.as_ref(), "u-35").await.is_none(), "the code is burned");
    }

    #[tokio::test]
    async fn successful_login_clears_the_send_budget() {
        let f = fixture().await;
        let user = test_user("u-32", "olga", Some("olga@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        mint(&f, "olga@example.com").await;
        assert_otp_challenge(resend(&f, "u-32").await);
        assert_eq!(sends(&f, "u-32").await, 2);

        let code = f.mailer.sent()[1].1.clone();
        let (result, _) = submit_otp(&f, Some("u-32"), &code).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
        assert_eq!(sends(&f, "u-32").await, 0);
    }

    #[tokio::test]
    async fn send_budget_recovers_when_the_window_expires() {
        let f = fixture().await;
        let mut realm = test_realm();
        realm.attributes.insert(REALM_ATTR_TTL_SECS.to_string(), "1".to_string());
        f.storage.update_realm(&realm).await.unwrap();
        let user = test_user("u-33", "pavel", Some("pavel@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        mint(&f, "pavel@example.com").await;
        for _ in 0..MAX_SENDS {
            assert_otp_challenge(resend(&f, "u-33").await);
        }
        assert_eq!(f.mailer.sent().len() as u32, MAX_SENDS);

        // The window is fixed from the first mail, so it ends even though
        // resends kept arriving.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_otp_challenge(resend(&f, "u-33").await);
        let sent = f.mailer.sent();
        assert_eq!(sent.len() as u32, MAX_SENDS + 1, "a fresh code once the window has expired");
        let (result, _) = submit_otp(&f, Some("u-33"), &sent.last().unwrap().1).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
    }

    /// The entry shape nodes predating the atomic counters deserialize.
    #[derive(serde::Deserialize)]
    struct LegacyEntry {
        code: String,
        attempts: u32,
        sends: u32,
    }

    #[tokio::test]
    async fn new_entries_still_parse_as_the_legacy_shape() {
        let f = fixture().await;
        let user = test_user("u-36", "tara", Some("tara@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let (_, code) = mint(&f, "tara@example.com").await;
        let key = entry_key(&RealmId::new(REALM).unwrap(), &UserId::new("u-36").unwrap());
        let raw = f.cache.get(&key).await.unwrap().unwrap();
        let legacy: LegacyEntry = serde_json::from_slice(&raw).unwrap();
        assert_eq!((legacy.code, legacy.attempts, legacy.sends), (code, 0, 1));
    }

    #[tokio::test]
    async fn legacy_entries_verify_and_keep_their_recorded_attempts() {
        let f = fixture().await;
        let user = test_user("u-37", "uwe", Some("uwe@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let key = entry_key(&RealmId::new(REALM).unwrap(), &UserId::new("u-37").unwrap());
        let legacy = br#"{"code":"123456","attempts":3,"sends":1}"#.to_vec();
        let ttl = Some(Duration::from_secs(DEFAULT_TTL_SECS));
        f.cache.set(&key, legacy, ttl).await.unwrap();

        // A wrong attempt leaves the legacy entry unchanged; 3 recorded + 2
        // counted reaches the cap and burns it.
        assert_otp_challenge(submit_otp(&f, Some("u-37"), "000000").await.0);
        let stored = stored_entry(f.cache.as_ref(), "u-37").await.unwrap();
        assert_eq!((stored.nonce, stored.ttl_secs, stored.attempts), (None, None, 3));
        assert_otp_challenge(submit_otp(&f, Some("u-37"), "000000").await.0);
        assert!(stored_entry(f.cache.as_ref(), "u-37").await.is_none(), "the code is burned");
        assert_otp_challenge(submit_otp(&f, Some("u-37"), "123456").await.0);

        // A fresh legacy entry still verifies with the right code.
        let legacy = br#"{"code":"654321","attempts":0,"sends":1}"#.to_vec();
        let user = test_user("u-38", "vera", Some("vera@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let key = entry_key(&RealmId::new(REALM).unwrap(), &UserId::new("u-38").unwrap());
        f.cache.set(&key, legacy, ttl).await.unwrap();
        let (result, _) = submit_otp(&f, Some("u-38"), "654321").await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
    }

    /// Fixture whose realm issues codes with a 1-second TTL.
    async fn short_ttl_fixture(user: &User) -> Fixture {
        let f = fixture().await;
        let mut realm = test_realm();
        realm.attributes.insert(REALM_ATTR_TTL_SECS.to_string(), "1".to_string());
        f.storage.update_realm(&realm).await.unwrap();
        f.storage.create_user(&user.realm_id, user).await.unwrap();
        f
    }

    #[tokio::test]
    async fn wrong_attempt_does_not_extend_code_ttl() {
        let f = short_ttl_fixture(&test_user("u-50", "wanda", Some("wanda@example.com"))).await;
        let (_, code) = mint(&f, "wanda@example.com").await;

        // Issued at t=0 with TTL 1 s, wrong at t=0.7, correct at t=1.4.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_otp_challenge(submit_otp(&f, Some("u-50"), wrong_for(&code)).await.0);
        let entry = stored_entry(f.cache.as_ref(), "u-50").await.unwrap();
        let attempts_key = code_attempts_key(&entry, "u-50");
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(
            counter(f.cache.as_ref(), &attempts_key).await,
            1,
            "the counter outlives the original TTL"
        );
        assert_otp_challenge(submit_otp(&f, Some("u-50"), &code).await.0);
    }

    #[tokio::test]
    async fn stale_wrong_attempt_does_not_overwrite_reissued_code() {
        let f = fixture().await;
        let user = test_user("u-53", "olivia", Some("olivia@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let (_, old_code) = mint(&f, "olivia@example.com").await;
        assert_otp_challenge(resend(&f, "u-53").await);
        let new_code = f.mailer.sent()[1].1.clone();

        assert_otp_challenge(submit_otp(&f, Some("u-53"), wrong_for(&old_code)).await.0);
        let (result, _) = submit_otp(&f, Some("u-53"), &new_code).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
    }

    /// Cache that, while armed, holds every `get` result at a barrier until
    /// all parties have read, so concurrent requests act on the same state
    /// before any of them writes — the interleaving under which a
    /// read-modify-write counter loses updates.
    #[derive(Default)]
    struct GatedCache {
        inner: issuerd_cluster::InMemoryCache,
        gate: std::sync::Mutex<Option<Arc<tokio::sync::Barrier>>>,
    }

    impl GatedCache {
        fn arm(&self, parties: usize) {
            *self.gate.lock().unwrap() = Some(Arc::new(tokio::sync::Barrier::new(parties)));
        }

        fn disarm(&self) {
            *self.gate.lock().unwrap() = None;
        }
    }

    #[async_trait]
    impl DistributedCache for GatedCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
            let value = self.inner.get(key).await;
            let gate = self.gate.lock().unwrap().clone();
            if let Some(barrier) = gate {
                barrier.wait().await;
            }
            value
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<Duration>,
        ) -> Result<(), IssuerdError> {
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), IssuerdError> {
            self.inner.delete(key).await
        }
        async fn get_and_delete(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
            self.inner.get_and_delete(key).await
        }
        async fn compare_and_swap(
            &self,
            key: &str,
            expected: Option<Vec<u8>>,
            new: Vec<u8>,
        ) -> Result<bool, IssuerdError> {
            self.inner.compare_and_swap(key, expected, new).await
        }
        async fn increment(&self, key: &str, ttl: Option<Duration>) -> Result<u64, IssuerdError> {
            self.inner.increment(key, ttl).await
        }
        async fn publish(&self, channel: &str, message: Vec<u8>) -> Result<(), IssuerdError> {
            self.inner.publish(channel, message).await
        }
        async fn subscribe(
            &self,
            channel: &str,
            handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
        ) -> Result<(), IssuerdError> {
            self.inner.subscribe(channel, handler).await
        }
    }

    struct GatedFixture {
        cache: Arc<GatedCache>,
        mailer: Arc<RecordingMailer>,
        authenticator: Arc<EmailCodeAuthenticator>,
    }

    async fn gated_fixture(user: &User) -> GatedFixture {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        storage.create_realm(&test_realm()).await.unwrap();
        storage.create_user(&user.realm_id, user).await.unwrap();
        let cache = Arc::new(GatedCache::default());
        let mailer = Arc::new(RecordingMailer::default());
        let authenticator =
            Arc::new(EmailCodeAuthenticator::new(storage, cache.clone(), mailer.clone()));
        GatedFixture {
            cache,
            mailer,
            authenticator,
        }
    }

    /// Run `parallel` copies of a bound-user submission with every cache
    /// read held at the barrier; returns once all have finished.
    async fn run_gated(g: &GatedFixture, parallel: usize, user_id: &str, key: &str, value: &str) {
        g.cache.arm(parallel);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..parallel {
            let auth = g.authenticator.clone();
            let mut ctx = with_param(context(), key, value);
            ctx.user_id = Some(UserId::new(user_id).unwrap());
            tasks.spawn(async move { auth.authenticate(&mut ctx).await });
        }
        while let Some(result) = tasks.join_next().await {
            assert_otp_challenge(result.unwrap());
        }
        g.cache.disarm();
    }

    #[tokio::test]
    async fn concurrent_wrong_codes_cannot_exceed_the_attempt_cap() {
        const PARALLEL: usize = 20;
        let g = gated_fixture(&test_user("u-40", "quinn", Some("quinn@example.com"))).await;
        let mut ctx = with_param(context(), "username", "quinn@example.com");
        assert_otp_challenge(g.authenticator.authenticate(&mut ctx).await);
        let code = g.mailer.sent()[0].1.clone();
        let entry = stored_entry(&g.cache.inner, "u-40").await.unwrap();

        run_gated(&g, PARALLEL, "u-40", "otp", wrong_for(&code)).await;

        // Every submission was counted against the code, so it is burned; a
        // lost-update counter would have left it alive at one attempt.
        let key = code_attempts_key(&entry, "u-40");
        assert_eq!(counter(&g.cache.inner, &key).await, PARALLEL as u64);
        let mut ctx = with_param(context(), "otp", &code);
        ctx.user_id = Some(UserId::new("u-40").unwrap());
        assert_otp_challenge(g.authenticator.authenticate(&mut ctx).await);

        // The burn does not lock the user out: a reissued code verifies.
        let mut ctx = with_param(context(), "resend", "1");
        ctx.user_id = Some(UserId::new("u-40").unwrap());
        assert_otp_challenge(g.authenticator.authenticate(&mut ctx).await);
        let mut ctx = with_param(context(), "otp", &g.mailer.sent()[1].1);
        ctx.user_id = Some(UserId::new("u-40").unwrap());
        let result = g.authenticator.authenticate(&mut ctx).await;
        assert!(matches!(result, AuthStepResult::Success), "got {result:?}");
    }

    #[tokio::test]
    async fn concurrent_sends_cannot_exceed_the_send_cap() {
        let g = gated_fixture(&test_user("u-41", "rosa", Some("rosa@example.com"))).await;
        run_gated(&g, 12, "u-41", "resend", "1").await;
        assert_eq!(g.mailer.sent().len(), MAX_SENDS as usize);
    }

    #[tokio::test]
    async fn concurrent_correct_codes_have_exactly_one_success() {
        let g = gated_fixture(&test_user("u-42", "sam", Some("sam@example.com"))).await;
        let mut ctx = with_param(context(), "username", "sam@example.com");
        assert_otp_challenge(g.authenticator.authenticate(&mut ctx).await);
        let code = g.mailer.sent()[0].1.clone();
        g.cache.arm(2);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let auth = g.authenticator.clone();
            let mut ctx = with_param(context(), "otp", &code);
            ctx.user_id = Some(UserId::new("u-42").unwrap());
            tasks.spawn(async move { auth.authenticate(&mut ctx).await });
        }
        let mut results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            results.push(result.unwrap());
        }
        g.cache.disarm();
        assert_eq!(results.iter().filter(|r| matches!(r, AuthStepResult::Success)).count(), 1);
        assert_eq!(results.iter().filter(|r| matches!(r, AuthStepResult::Challenge(_))).count(), 1);
        assert!(stored_entry(&g.cache.inner, "u-42").await.is_none());
    }

    #[tokio::test]
    async fn stale_burn_cannot_delete_a_reissued_code() {
        let f = fixture().await;
        let key = entry_key(&RealmId::new(REALM).unwrap(), &UserId::new("u-43").unwrap());
        let old = EmailCodeEntry {
            code: "111111".to_string(),
            nonce: Some("old".to_string()),
            ttl_secs: Some(DEFAULT_TTL_SECS),
            attempts: 0,
            sends: 1,
        };
        f.cache
            .set(&key, serde_json::to_vec(&old).unwrap(), Some(Duration::from_secs(60)))
            .await
            .unwrap();
        let old_raw = f.cache.get(&key).await.unwrap().unwrap();
        let new = EmailCodeEntry {
            code: "222222".to_string(),
            nonce: Some("new".to_string()),
            ..old
        };
        f.cache
            .set(&key, serde_json::to_vec(&new).unwrap(), Some(Duration::from_secs(60)))
            .await
            .unwrap();

        assert!(!f.cache.compare_and_delete(&key, old_raw).await.unwrap());
        let current = f.cache.get(&key).await.unwrap().unwrap();
        assert_eq!(serde_json::from_slice::<EmailCodeEntry>(&current).unwrap().code, "222222");
    }

    #[tokio::test]
    async fn one_source_cannot_burn_the_code_reserved_for_another_source() {
        let f = fixture().await;
        let user = test_user("u-44", "victim", Some("victim@example.com"));
        f.storage.create_user(&user.realm_id, &user).await.unwrap();
        let attacker = "192.0.2.10".parse().unwrap();
        let victim = "198.51.100.20".parse().unwrap();

        for _ in 0..MAX_SENDS_PER_IP {
            let code = mint_from(&f, "victim@example.com", attacker).await;
            for _ in 0..MAX_VERIFY_ATTEMPTS {
                assert_otp_challenge(submit_otp_from(&f, "u-44", wrong_for(&code), attacker).await);
            }
        }

        let victim_code = mint_from(&f, "victim@example.com", victim).await;
        assert_eq!(f.mailer.sent().len(), MAX_SENDS as usize);
        assert_otp_challenge(submit_otp_from(&f, "u-44", wrong_for(&victim_code), attacker).await);
        assert!(matches!(
            submit_otp_from(&f, "u-44", &victim_code, victim).await,
            AuthStepResult::Success
        ));
    }
}
