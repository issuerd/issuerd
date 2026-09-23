// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Outbound email: compile-time embedded templates and lettre SMTP sender.

//! Outbound email: compile-time embedded templates + lettre SMTP sender.
//!
//! Templates live in `templates/email/` and are baked into the binary via
//! [`include_str!`], so the released executable is fully self-contained (no
//! template directory lookup at runtime). The HTML templates are written for
//! maximum mail-client compatibility: XHTML 1.0 Transitional doctype, table
//! layout, inline CSS, MSO conditional comments, and a VML bulletproof button
//! for Outlook on Windows.
//!
//! Rendering is a deliberately tiny `{{placeholder}}` substitution engine —
//! no external templating dependency. Every dynamic value substituted into
//! HTML is passed through [`html_escape`] first.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use issuerd_core::{EmailSender, IssuerdError, Realm};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use tracing::{debug, instrument};

use crate::config::SmtpConfig;
use crate::i18n::{self, MessageBundle};

/// Email templates embedded into the binary at compile time.
pub mod templates {
    /// HTML body for the email-address verification message.
    pub const VERIFY_EMAIL_HTML: &str = include_str!("../templates/email/verify-email.html");
    /// Plain-text body for the email-address verification message.
    pub const VERIFY_EMAIL_TXT: &str = include_str!("../templates/email/verify-email.txt");
    /// HTML body for the reset-credentials (forgot password) message.
    pub const RESET_CREDENTIALS_HTML: &str =
        include_str!("../templates/email/reset-credentials.html");
    /// Plain-text body for the reset-credentials (forgot password) message.
    pub const RESET_CREDENTIALS_TXT: &str =
        include_str!("../templates/email/reset-credentials.txt");
    /// HTML body for the passwordless login one-time-code message.
    pub const LOGIN_CODE_HTML: &str = include_str!("../templates/email/login-code.html");
    /// Plain-text body for the passwordless login one-time-code message.
    pub const LOGIN_CODE_TXT: &str = include_str!("../templates/email/login-code.txt");
}

/// How long a verify-email link stays valid (24 hours, Keycloak default).
pub const VERIFY_EMAIL_LINK_TTL_SECS: i64 = 86_400;

/// How long a reset-credentials link stays valid (15 minutes, Keycloak's
/// `resetCredentials` action-token lifespan). The signed action token and the
/// single-use cache entry share this TTL.
pub const RESET_CREDENTIALS_LINK_TTL_SECS: i64 = 900;

/// A fully rendered email ready to hand to [`EmailSender::send`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedEmail {
    /// Subject line.
    pub subject: String,
    /// Plain-text body (always present).
    pub text: String,
    /// HTML body (sent as `multipart/alternative`).
    pub html: String,
}

/// Escape the five HTML-significant characters in a dynamic template value.
///
/// Applied to every value substituted into an HTML template so a crafted
/// username or realm display name cannot inject markup into outgoing mail.
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Substitute `{{key}}` placeholders in `template` with the given values.
///
/// Placeholders without a matching entry are left untouched; unknown keys in
/// `vars` are ignored. Callers are responsible for escaping values when the
/// template is HTML.
fn render_template(template: &str, vars: &[(&str, String)]) -> String {
    let mut out = template.to_string();
    for (key, value) in vars {
        out = out.replace(&format!("{{{{{key}}}}}"), value);
    }
    out
}

/// English fallback copy, kept identical to `i18n/messages_en.json`: a missing
/// bundle key must never change the default (English) output.
mod en_fallback {
    pub const GREETING: &str = "Hi {user},";
    pub const EXPIRY_NOTE: &str = "This link expires in {minutes} minutes.";
    pub const FALLBACK_NOTE: &str =
        "If the button does not work, copy and paste this link into your browser:";
    pub const FOOTER: &str = "This is an automated message from {realm}. Please do not reply.";
    pub const REALM_LABEL: &str = "Realm: {realm}";
    pub const VERIFY_SUBJECT: &str = "Verify your email address";
    pub const VERIFY_HEADING: &str = "Verify your email address";
    pub const VERIFY_PREHEADER: &str =
        "Confirm your email address for {realm} — this link expires in {minutes} minutes.";
    pub const VERIFY_INTRO: &str = "Please confirm this email address for your {realm} account.";
    pub const VERIFY_BUTTON: &str = "Verify email address";
    pub const VERIFY_IGNORE: &str = "If you did not create an account with {realm}, you can safely ignore this email — no changes will be made.";
    pub const RESET_SUBJECT: &str = "Reset your password";
    pub const RESET_HEADING: &str = "Reset your password";
    pub const RESET_PREHEADER: &str =
        "Reset the password for your {realm} account — this link expires in {minutes} minutes.";
    pub const RESET_INTRO: &str =
        "We received a request to reset the password for your {realm} account.";
    pub const RESET_BUTTON: &str = "Reset password";
    pub const RESET_IGNORE: &str = "If you did not request a password reset for {realm}, you can safely ignore this email — your password will not change.";
    pub const LOGIN_CODE_SUBJECT: &str = "Your sign-in code";
    pub const LOGIN_CODE_HEADING: &str = "Your sign-in code";
    pub const LOGIN_CODE_PREHEADER: &str =
        "Your {realm} sign-in code — the code expires in {minutes} minutes.";
    pub const LOGIN_CODE_INTRO: &str = "Use this one-time code to sign in to your {realm} account:";
    pub const LOGIN_CODE_EXPIRY_NOTE: &str = "The code expires in {minutes} minutes.";
    pub const LOGIN_CODE_IGNORE: &str = "If you did not try to sign in to {realm}, you can safely ignore this email — nobody can sign in without this code.";
}

/// The six strings that differ between the two mail types (defaults used when
/// the bundle has no entry for the key).
struct MailCopy {
    subject: &'static str,
    heading: &'static str,
    preheader: &'static str,
    intro: &'static str,
    button: &'static str,
    ignore_note: &'static str,
}

const VERIFY_COPY: MailCopy = MailCopy {
    subject: en_fallback::VERIFY_SUBJECT,
    heading: en_fallback::VERIFY_HEADING,
    preheader: en_fallback::VERIFY_PREHEADER,
    intro: en_fallback::VERIFY_INTRO,
    button: en_fallback::VERIFY_BUTTON,
    ignore_note: en_fallback::VERIFY_IGNORE,
};

const RESET_COPY: MailCopy = MailCopy {
    subject: en_fallback::RESET_SUBJECT,
    heading: en_fallback::RESET_HEADING,
    preheader: en_fallback::RESET_PREHEADER,
    intro: en_fallback::RESET_INTRO,
    button: en_fallback::RESET_BUTTON,
    ignore_note: en_fallback::RESET_IGNORE,
};

/// The strings that make up the login-code mail (defaults used when the
/// bundle has no entry for the key). Unlike the link-based mails there is no
/// button/fallback copy — the code itself is the payload.
struct LoginCodeCopy {
    subject: &'static str,
    heading: &'static str,
    preheader: &'static str,
    intro: &'static str,
    expiry_note: &'static str,
    ignore_note: &'static str,
}

const LOGIN_CODE_COPY: LoginCodeCopy = LoginCodeCopy {
    subject: en_fallback::LOGIN_CODE_SUBJECT,
    heading: en_fallback::LOGIN_CODE_HEADING,
    preheader: en_fallback::LOGIN_CODE_PREHEADER,
    intro: en_fallback::LOGIN_CODE_INTRO,
    expiry_note: en_fallback::LOGIN_CODE_EXPIRY_NOTE,
    ignore_note: en_fallback::LOGIN_CODE_IGNORE,
};

/// The built-in English bundle backing the non-localized renderers.
fn english_bundle() -> &'static MessageBundle {
    static BUNDLE: OnceLock<MessageBundle> = OnceLock::new();
    BUNDLE.get_or_init(|| i18n::message_bundle(None, None, i18n::DEFAULT_LOCALE))
}

/// All translatable strings of one outbound email, resolved from a bundle.
struct EmailStrings {
    subject: String,
    heading: String,
    preheader: String,
    greeting: String,
    intro: String,
    expiry_note: String,
    button_label: String,
    fallback_note: String,
    ignore_note: String,
    footer: String,
    realm_label: String,
}

impl EmailStrings {
    /// Resolve every string from `bundle`, substituting
    /// `{realm}`/`{user}`/`{minutes}`. Bundle text is trusted theme content
    /// and inserted verbatim; the dynamic values are HTML-escaped when
    /// `escape` is set (HTML body) and raw otherwise (plain-text body).
    fn resolve(
        bundle: &MessageBundle,
        prefix: &str,
        copy: &MailCopy,
        realm: &str,
        user: &str,
        minutes: &str,
        escape: bool,
    ) -> Self {
        let (realm, user) = if escape {
            (html_escape(realm), html_escape(user))
        } else {
            (realm.to_string(), user.to_string())
        };
        let lookup = |key: &str, default: &str| -> String {
            i18n::msg(bundle, key, default)
                .replace("{realm}", &realm)
                .replace("{user}", &user)
                .replace("{minutes}", minutes)
        };
        Self {
            subject: lookup(&format!("{prefix}subject"), copy.subject),
            heading: lookup(&format!("{prefix}heading"), copy.heading),
            preheader: lookup(&format!("{prefix}preheader"), copy.preheader),
            greeting: lookup("email.greeting", en_fallback::GREETING),
            intro: lookup(&format!("{prefix}intro"), copy.intro),
            expiry_note: lookup("email.expiryNote", en_fallback::EXPIRY_NOTE),
            button_label: lookup(&format!("{prefix}button"), copy.button),
            fallback_note: lookup("email.fallbackNote", en_fallback::FALLBACK_NOTE),
            ignore_note: lookup(&format!("{prefix}ignoreNote"), copy.ignore_note),
            footer: lookup("email.footer", en_fallback::FOOTER),
            realm_label: lookup("email.realmLabel", en_fallback::REALM_LABEL),
        }
    }
}

/// Shared renderer for both mail types: resolves the copy from `bundle` and
/// substitutes it into the plain-text and HTML templates.
#[allow(clippy::too_many_arguments)]
fn render_mail(
    bundle: &MessageBundle,
    prefix: &str,
    copy: &MailCopy,
    realm_display: &str,
    user_display: &str,
    link: &str,
    link_expiration_minutes: i64,
    txt_template: &str,
    html_template: &str,
) -> RenderedEmail {
    let minutes = link_expiration_minutes.to_string();
    let html =
        EmailStrings::resolve(bundle, prefix, copy, realm_display, user_display, &minutes, true);
    let text =
        EmailStrings::resolve(bundle, prefix, copy, realm_display, user_display, &minutes, false);
    let heading_underline = "=".repeat(text.heading.chars().count());
    let html_vars = [
        ("realm", html_escape(realm_display)),
        ("realm_label", html.realm_label),
        ("link", html_escape(link)),
        ("heading", html.heading),
        ("preheader", html.preheader),
        ("greeting", html.greeting),
        ("intro", html.intro),
        ("expiry_note", html.expiry_note),
        ("button_label", html.button_label),
        ("fallback_note", html.fallback_note),
        ("ignore_note", html.ignore_note),
        ("footer", html.footer),
    ];
    let text_vars = [
        ("realm_label", text.realm_label),
        ("heading", text.heading),
        ("heading_underline", heading_underline),
        ("greeting", text.greeting),
        ("intro", text.intro),
        ("link", link.to_string()),
        ("expiry_note", text.expiry_note),
        ("ignore_note", text.ignore_note),
        ("footer", text.footer),
    ];
    RenderedEmail {
        subject: text.subject,
        text: render_template(txt_template, &text_vars),
        html: render_template(html_template, &html_vars),
    }
}

/// Render the verify-email message for `user_display` in `realm_display`
/// with the built-in English copy.
///
/// `link` is the absolute verification URL; `link_expiration_minutes` is the
/// human-facing validity window. Dynamic values are HTML-escaped for the HTML
/// body and used verbatim for the plain-text body.
pub fn render_verify_email(
    realm_display: &str,
    user_display: &str,
    link: &str,
    link_expiration_minutes: i64,
) -> RenderedEmail {
    render_verify_email_localized(
        realm_display,
        user_display,
        link,
        link_expiration_minutes,
        english_bundle(),
    )
}

/// [`render_verify_email`] with the copy taken from `bundle` (locale already
/// resolved by the caller); missing keys fall back to English per key.
pub fn render_verify_email_localized(
    realm_display: &str,
    user_display: &str,
    link: &str,
    link_expiration_minutes: i64,
    bundle: &MessageBundle,
) -> RenderedEmail {
    render_mail(
        bundle,
        "email.verify.",
        &VERIFY_COPY,
        realm_display,
        user_display,
        link,
        link_expiration_minutes,
        templates::VERIFY_EMAIL_TXT,
        templates::VERIFY_EMAIL_HTML,
    )
}

/// Render the reset-credentials (forgot password) message with the built-in
/// English copy.
///
/// Same contract as [`render_verify_email`]: `link` is the absolute
/// update-credentials URL carrying the signed action token, dynamic values are
/// HTML-escaped for the HTML body and verbatim in the plain-text body.
pub fn render_reset_credentials_email(
    realm_display: &str,
    user_display: &str,
    link: &str,
    link_expiration_minutes: i64,
) -> RenderedEmail {
    render_reset_credentials_email_localized(
        realm_display,
        user_display,
        link,
        link_expiration_minutes,
        english_bundle(),
    )
}

/// [`render_reset_credentials_email`] with the copy taken from `bundle`.
pub fn render_reset_credentials_email_localized(
    realm_display: &str,
    user_display: &str,
    link: &str,
    link_expiration_minutes: i64,
    bundle: &MessageBundle,
) -> RenderedEmail {
    render_mail(
        bundle,
        "email.reset.",
        &RESET_COPY,
        realm_display,
        user_display,
        link,
        link_expiration_minutes,
        templates::RESET_CREDENTIALS_TXT,
        templates::RESET_CREDENTIALS_HTML,
    )
}

/// All translatable strings of the login-code email, resolved from a bundle.
struct LoginCodeStrings {
    subject: String,
    heading: String,
    preheader: String,
    greeting: String,
    intro: String,
    expiry_note: String,
    ignore_note: String,
    footer: String,
    realm_label: String,
}

impl LoginCodeStrings {
    /// Resolve every string from `bundle`, substituting
    /// `{realm}`/`{user}`/`{minutes}`. Same escape contract as
    /// [`EmailStrings::resolve`].
    fn resolve(
        bundle: &MessageBundle,
        copy: &LoginCodeCopy,
        realm: &str,
        user: &str,
        minutes: &str,
        escape: bool,
    ) -> Self {
        let (realm, user) = if escape {
            (html_escape(realm), html_escape(user))
        } else {
            (realm.to_string(), user.to_string())
        };
        let lookup = |key: &str, default: &str| -> String {
            i18n::msg(bundle, key, default)
                .replace("{realm}", &realm)
                .replace("{user}", &user)
                .replace("{minutes}", minutes)
        };
        Self {
            subject: lookup("email.loginCode.subject", copy.subject),
            heading: lookup("email.loginCode.heading", copy.heading),
            preheader: lookup("email.loginCode.preheader", copy.preheader),
            greeting: lookup("email.greeting", en_fallback::GREETING),
            intro: lookup("email.loginCode.intro", copy.intro),
            expiry_note: lookup("email.loginCode.expiryNote", copy.expiry_note),
            ignore_note: lookup("email.loginCode.ignoreNote", copy.ignore_note),
            footer: lookup("email.footer", en_fallback::FOOTER),
            realm_label: lookup("email.realmLabel", en_fallback::REALM_LABEL),
        }
    }
}

/// Shared renderer for the login-code mail: resolves the copy from `bundle`
/// and substitutes it into the plain-text and HTML templates.
fn render_login_code_mail(
    bundle: &MessageBundle,
    copy: &LoginCodeCopy,
    realm_display: &str,
    user_display: &str,
    code: &str,
    code_expiration_minutes: u64,
) -> RenderedEmail {
    let minutes = code_expiration_minutes.to_string();
    let html = LoginCodeStrings::resolve(bundle, copy, realm_display, user_display, &minutes, true);
    let text =
        LoginCodeStrings::resolve(bundle, copy, realm_display, user_display, &minutes, false);
    let heading_underline = "=".repeat(text.heading.chars().count());
    let html_vars = [
        ("realm_label", html.realm_label),
        ("heading", html.heading),
        ("preheader", html.preheader),
        ("greeting", html.greeting),
        ("intro", html.intro),
        ("code", html_escape(code)),
        ("expiry_note", html.expiry_note),
        ("ignore_note", html.ignore_note),
        ("footer", html.footer),
    ];
    let text_vars = [
        ("realm_label", text.realm_label),
        ("heading", text.heading),
        ("heading_underline", heading_underline),
        ("greeting", text.greeting),
        ("intro", text.intro),
        ("code", code.to_string()),
        ("expiry_note", text.expiry_note),
        ("ignore_note", text.ignore_note),
        ("footer", text.footer),
    ];
    RenderedEmail {
        subject: text.subject,
        text: render_template(templates::LOGIN_CODE_TXT, &text_vars),
        html: render_template(templates::LOGIN_CODE_HTML, &html_vars),
    }
}

/// Render the passwordless login one-time-code message with the built-in
/// English copy.
///
/// `code` is the minted numeric code; `code_expiration_minutes` is the
/// human-facing validity window. Dynamic values are HTML-escaped for the HTML
/// body and used verbatim for the plain-text body.
pub fn render_login_code_email(
    realm_display: &str,
    user_display: &str,
    code: &str,
    code_expiration_minutes: u64,
) -> RenderedEmail {
    render_login_code_email_localized(
        realm_display,
        user_display,
        code,
        code_expiration_minutes,
        english_bundle(),
    )
}

/// [`render_login_code_email`] with the copy taken from `bundle` (locale
/// already resolved by the caller); missing keys fall back to English per key.
pub fn render_login_code_email_localized(
    realm_display: &str,
    user_display: &str,
    code: &str,
    code_expiration_minutes: u64,
    bundle: &MessageBundle,
) -> RenderedEmail {
    render_login_code_mail(
        bundle,
        &LOGIN_CODE_COPY,
        realm_display,
        user_display,
        code,
        code_expiration_minutes,
    )
}

/// Build a `Mailbox` from an address and optional display name.
fn mailbox(address: &str, display: Option<&str>) -> Result<Mailbox, IssuerdError> {
    let address = address.parse().map_err(|e| {
        IssuerdError::ServerError(format!("invalid email address '{address}': {e}"))
    })?;
    Ok(Mailbox::new(display.map(str::to_string), address))
}

fn server_err(context: &str, e: impl std::fmt::Display) -> IssuerdError {
    IssuerdError::ServerError(format!("{context}: {e}"))
}

/// Production [`EmailSender`] backed by SMTP via `lettre`.
///
/// A fresh transport is built per message from the realm-merged
/// configuration ([`SmtpConfig::for_realm`]); SMTP connections are therefore
/// never shared across realms with divergent settings.
pub struct SmtpEmailSender {
    config: SmtpConfig,
}

impl SmtpEmailSender {
    /// Create a sender from the global `[smtp]` configuration.
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }

    fn transport(
        &self,
        cfg: &SmtpConfig,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, IssuerdError> {
        let builder = if cfg.ssl {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
                .map_err(|e| server_err("smtp relay config", e))?
        } else if cfg.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
                .map_err(|e| server_err("smtp starttls config", e))?
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(cfg.host.clone())
        };
        let builder = builder.port(cfg.port).timeout(Some(Duration::from_secs(10)));
        let builder = match (&cfg.username, &cfg.password) {
            (Some(user), Some(pass)) => {
                builder.credentials(Credentials::new(user.clone(), pass.clone()))
            }
            _ => builder,
        };
        Ok(builder.build())
    }

    fn build_message(
        cfg: &SmtpConfig,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: Option<String>,
    ) -> Result<Message, IssuerdError> {
        let mut builder = Message::builder()
            .from(mailbox(&cfg.from, cfg.from_display.as_deref())?)
            .to(mailbox(to, None)?)
            .subject(subject.to_string());
        if let Some(reply_to) = &cfg.reply_to {
            builder = builder.reply_to(mailbox(reply_to, None)?);
        }
        match html_body {
            Some(html) => builder
                .multipart(
                    MultiPart::alternative()
                        .singlepart(SinglePart::plain(text_body.to_string()))
                        .singlepart(SinglePart::html(html)),
                )
                .map_err(|e| server_err("build email", e)),
            None => builder.body(text_body.to_string()).map_err(|e| server_err("build email", e)),
        }
    }
}

#[async_trait]
impl EmailSender for SmtpEmailSender {
    #[instrument(skip_all, fields(realm = %realm.name.as_str(), to = %to))]
    async fn send(
        &self,
        realm: &Realm,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: Option<String>,
    ) -> Result<(), IssuerdError> {
        let cfg = self.config.for_realm(realm);
        debug!(
            host = %cfg.host,
            port = cfg.port,
            subject = %subject,
            "sending email"
        );
        let message = Self::build_message(&cfg, to, subject, text_body, html_body)?;
        let transport = self.transport(&cfg)?;
        transport.send(message).await.map_err(|e| server_err("smtp send", e))?;
        debug!(host = %cfg.host, port = cfg.port, "email sent");
        Ok(())
    }
}

/// Sender wired when `[smtp] enabled = false`.
///
/// Fails loudly instead of silently dropping mail: an admin who flips on
/// `verify_email` without configuring SMTP must see the misconfiguration
/// rather than have users wait for messages that never arrive.
pub struct NoOpEmailSender;

#[async_trait]
impl EmailSender for NoOpEmailSender {
    async fn send(
        &self,
        _realm: &Realm,
        _to: &str,
        _subject: &str,
        _text_body: &str,
        _html_body: Option<String>,
    ) -> Result<(), IssuerdError> {
        Err(IssuerdError::ServerError(
            "SMTP is not configured: set [smtp] enabled = true (and host/port/from) \
             before enabling email flows"
                .to_string(),
        ))
    }
}

/// Production [`issuerd_auth_flow::email_code::EmailCodeSender`]: renders the
/// login-code templates and hands the result to the wrapped [`EmailSender`]
/// (which applies the realm-merged SMTP configuration). With SMTP disabled
/// the wrapped no-op sender fails loudly, so a passwordless realm without
/// mail configuration surfaces the misconfiguration on the first login.
pub struct SmtpEmailCodeSender {
    sender: Arc<dyn EmailSender>,
}

impl SmtpEmailCodeSender {
    pub fn new(sender: Arc<dyn EmailSender>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl issuerd_auth_flow::email_code::EmailCodeSender for SmtpEmailCodeSender {
    #[instrument(skip_all, fields(realm = %realm.name.as_str(), to = %to))]
    async fn send_login_code(
        &self,
        realm: &Realm,
        to: &str,
        code: &str,
        ttl_secs: u64,
    ) -> Result<(), IssuerdError> {
        let realm_display =
            realm.display_name.as_ref().map(|d| d.as_str()).unwrap_or(realm.name.as_str());
        let rendered = render_login_code_email(realm_display, to, code, ttl_secs.div_ceil(60));
        self.sender
            .send(realm, to, &rendered.subject, &rendered.text, Some(rendered.html))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Placeholders shared by the two link-based mail types (i18n contract:
    /// the translatable copy arrives as `{{heading}}`/`{{greeting}}`/…
    /// strings; only `{{link}}` is a raw dynamic value in those templates).
    const PLACEHOLDERS: [&str; 7] = [
        "{{heading}}",
        "{{greeting}}",
        "{{intro}}",
        "{{link}}",
        "{{expiry_note}}",
        "{{ignore_note}}",
        "{{footer}}",
    ];

    /// Placeholders of the login-code mail: the code replaces the link.
    const LOGIN_CODE_PLACEHOLDERS: [&str; 8] = [
        "{{heading}}",
        "{{greeting}}",
        "{{intro}}",
        "{{code}}",
        "{{expiry_note}}",
        "{{ignore_note}}",
        "{{footer}}",
        "{{realm_label}}",
    ];

    #[test]
    fn login_code_templates_are_present_and_outlook_compatible() {
        for template in [templates::LOGIN_CODE_HTML, templates::LOGIN_CODE_TXT] {
            assert!(!template.is_empty());
            for placeholder in LOGIN_CODE_PLACEHOLDERS {
                assert!(
                    template.contains(placeholder),
                    "template missing placeholder {placeholder}"
                );
            }
        }
        assert!(templates::LOGIN_CODE_TXT.contains("{{heading_underline}}"));
        let html = templates::LOGIN_CODE_HTML;
        assert!(html.contains("{{preheader}}"));
        // XHTML 1.0 Transitional doctype: the safest baseline for Outlook.
        assert!(html.contains("XHTML 1.0 Transitional"));
        assert!(html.contains("urn:schemas-microsoft-com:vml"));
        assert!(html.contains("<!--[if mso]>"));
        // Table-based layout (no flexbox/grid — unsupported in Outlook).
        assert!(html.contains("role=\"presentation\""));
        assert!(!html.contains("display:flex"));
        assert!(!html.contains("display:grid"));
    }

    #[test]
    fn render_login_code_email_substitutes_all_placeholders() {
        let rendered = render_login_code_email("Demo Realm", "alice@example.com", "123456", 5);
        assert_eq!(rendered.subject, "Your sign-in code");
        for body in [&rendered.text, &rendered.html] {
            assert!(!body.contains("{{"), "unsubstituted placeholder in: {body}");
            assert!(body.contains("Demo Realm"), "realm missing in: {body}");
            assert!(body.contains("alice@example.com"), "user missing in: {body}");
            assert!(body.contains("123456"), "code missing in: {body}");
            assert!(body.contains("5 minutes"), "expiry missing in: {body}");
        }
    }

    #[test]
    fn render_login_code_email_localizes_via_bundle() {
        let bundle = i18n::message_bundle(None, None, "de");
        let rendered = render_login_code_email_localized(
            "Demo Realm",
            "alice@example.com",
            "123456",
            5,
            &bundle,
        );
        assert_ne!(rendered.subject, "Your sign-in code", "german subject expected");
        assert!(rendered.text.contains("123456"));
        assert!(!rendered.text.contains("{{"));
    }

    #[test]
    fn login_code_html_body_escapes_injected_markup() {
        let rendered = render_login_code_email(
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "42<b>17",
            5,
        );
        assert!(!rendered.html.contains("<script>"));
        assert!(rendered.html.contains("&lt;script&gt;"));
        assert!(rendered.html.contains("42&lt;b&gt;17"));
        // Plain-text body keeps values verbatim (no HTML entities).
        assert!(rendered.text.contains("<script>alert(1)</script>"));
        assert!(rendered.text.contains("42<b>17"));
    }

    #[tokio::test]
    async fn smtp_email_code_sender_renders_and_forwards() {
        use issuerd_auth_flow::email_code::EmailCodeSender as _;

        let mut mock = issuerd_core::MockEmailSender::new();
        mock.expect_send()
            .withf(|_realm, to, subject, text, html| {
                to == "alice@example.com"
                    && subject == "Your sign-in code"
                    && text.contains("654321")
                    && html.as_deref().is_some_and(|h| h.contains("654321"))
            })
            .returning(|_, _, _, _, _| Ok(()));
        let sender = SmtpEmailCodeSender::new(Arc::new(mock));
        let realm = Realm::default();
        sender
            .send_login_code(&realm, "alice@example.com", "654321", 300)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn smtp_email_code_sender_propagates_transport_failure() {
        use issuerd_auth_flow::email_code::EmailCodeSender as _;

        let sender = SmtpEmailCodeSender::new(Arc::new(NoOpEmailSender));
        let realm = Realm::default();
        let err = sender
            .send_login_code(&realm, "alice@example.com", "654321", 300)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("SMTP is not configured"));
    }

    #[test]
    fn embedded_templates_are_present_and_outlook_compatible() {
        for template in [
            templates::VERIFY_EMAIL_HTML,
            templates::VERIFY_EMAIL_TXT,
            templates::RESET_CREDENTIALS_HTML,
            templates::RESET_CREDENTIALS_TXT,
        ] {
            assert!(!template.is_empty());
            for placeholder in PLACEHOLDERS {
                assert!(
                    template.contains(placeholder),
                    "template missing placeholder {placeholder}"
                );
            }
        }
        for html in [
            templates::VERIFY_EMAIL_HTML,
            templates::RESET_CREDENTIALS_HTML,
        ] {
            for placeholder in ["{{preheader}}", "{{button_label}}", "{{fallback_note}}"] {
                assert!(html.contains(placeholder), "HTML missing placeholder {placeholder}");
            }
        }
        for txt in [
            templates::VERIFY_EMAIL_TXT,
            templates::RESET_CREDENTIALS_TXT,
        ] {
            assert!(txt.contains("{{heading_underline}}"), "TXT missing heading underline");
        }
        for html in [
            templates::VERIFY_EMAIL_HTML,
            templates::RESET_CREDENTIALS_HTML,
        ] {
            // XHTML 1.0 Transitional doctype: the safest baseline for Outlook.
            assert!(html.contains("XHTML 1.0 Transitional"));
            // VML namespace + bulletproof button for Outlook on Windows.
            assert!(html.contains("urn:schemas-microsoft-com:vml"));
            assert!(html.contains("v:roundrect"));
            assert!(html.contains("<!--[if mso]>"));
            // Table-based layout (no flexbox/grid — unsupported in Outlook).
            assert!(html.contains("role=\"presentation\""));
            assert!(!html.contains("display:flex"));
            assert!(!html.contains("display:grid"));
        }
    }

    #[test]
    fn render_verify_email_substitutes_all_placeholders() {
        let rendered = render_verify_email(
            "Demo Realm",
            "alice",
            "https://id.example.com/realms/demo/login/verify-email?token=abc",
            1440,
        );
        assert_eq!(rendered.subject, "Verify your email address");
        for body in [&rendered.text, &rendered.html] {
            assert!(!body.contains("{{"), "unsubstituted placeholder in: {body}");
            assert!(body.contains("Demo Realm"));
            assert!(body.contains("alice"));
            assert!(body.contains("1440"));
        }
        assert!(rendered
            .html
            .contains("https://id.example.com/realms/demo/login/verify-email?token=abc"));
        assert!(rendered
            .text
            .contains("https://id.example.com/realms/demo/login/verify-email?token=abc"));
    }

    #[test]
    fn render_reset_credentials_email_substitutes_all_placeholders() {
        let rendered = render_reset_credentials_email(
            "Demo Realm",
            "alice",
            "https://id.example.com/realms/demo/login/update-credentials?token=abc",
            15,
        );
        assert_eq!(rendered.subject, "Reset your password");
        for body in [&rendered.text, &rendered.html] {
            assert!(!body.contains("{{"), "unsubstituted placeholder in: {body}");
            assert!(body.contains("Demo Realm"));
            assert!(body.contains("alice"));
            assert!(body.contains("15"));
            assert!(body.contains("Reset your password"), "heading missing in: {body}");
        }
        // Bulletproof button label appears in the HTML body.
        assert!(rendered.html.contains(">Reset password</a>"));
        let link = "https://id.example.com/realms/demo/login/update-credentials?token=abc";
        assert!(rendered.html.contains(link));
        assert!(rendered.text.contains(link));
        // Ignore-if-not-you notice is part of the anti-hijack messaging.
        assert!(rendered.text.contains("did not request a password reset"));
        assert!(rendered.html.contains("did not request a password reset"));
    }

    #[test]
    fn reset_credentials_html_body_escapes_injected_markup() {
        let rendered = render_reset_credentials_email(
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "https://id.example.com/u?token=a.x_y-z",
            15,
        );
        assert!(!rendered.html.contains("<script>"));
        assert!(rendered.html.contains("&lt;script&gt;"));
        assert!(rendered.html.contains("&quot;&gt;&lt;img"));
        assert!(rendered.text.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn html_body_escapes_injected_markup() {
        let rendered = render_verify_email(
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "https://id.example.com/v?token=a&execution=b",
            60,
        );
        assert!(!rendered.html.contains("<script>"));
        assert!(rendered.html.contains("&lt;script&gt;"));
        assert!(rendered.html.contains("&quot;&gt;&lt;img"));
        // `&` in the URL must be entity-escaped in HTML, raw in text.
        assert!(rendered.html.contains("token=a&amp;execution=b"));
        assert!(rendered.text.contains("token=a&execution=b"));
        // Plain-text body keeps values verbatim (no HTML entities).
        assert!(rendered.text.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn html_escape_covers_all_five_characters() {
        assert_eq!(html_escape("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
        assert_eq!(html_escape("plain"), "plain");
    }

    #[test]
    fn build_message_rejects_invalid_addresses() {
        let cfg = SmtpConfig {
            from: "not-an-address".to_string(),
            ..SmtpConfig::default()
        };
        assert!(SmtpEmailSender::build_message(&cfg, "a@b.c", "s", "t", None).is_err());
        let cfg = SmtpConfig::default();
        assert!(SmtpEmailSender::build_message(&cfg, "nope", "s", "t", None).is_err());
    }

    #[tokio::test]
    async fn noop_sender_fails_loudly() {
        let realm = Realm::default();
        let err = NoOpEmailSender.send(&realm, "a@b.c", "s", "t", None).await.unwrap_err();
        assert!(matches!(err, IssuerdError::ServerError(_)));
        assert!(err.to_string().contains("SMTP is not configured"));
    }
}
