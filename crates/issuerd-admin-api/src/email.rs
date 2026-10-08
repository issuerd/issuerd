// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Outbound email rendering: embedded templates with placeholder substitution.

//! Outbound email rendering for the admin API: compile-time
//! embedded templates via `include_str!` plus a minimal `{{placeholder}}`
//! substitution engine.
//!
//! This is a deliberately small port of `issuerd-server`'s email machinery
//! (`crates/issuerd-server/src/email.rs`): the markup idiom (XHTML 1.0
//! Transitional, table layout, MSO conditionals, VML bulletproof button) and
//! the i18n message-bundle contract are shared, but the bundle loader itself
//! is **not** reachable from this crate (issuerd-server depends on
//! issuerd-admin-api, never the reverse). The resolved bundle therefore
//! arrives as a plain `HashMap<String, String>` — the composition root wires
//! it through `AdminApiState::email_bundle`. Missing keys fall back to the
//! English defaults per key, so an empty bundle reproduces the built-in copy
//! byte-for-byte.

use std::collections::HashMap;

/// Email templates embedded into the binary at compile time.
pub mod templates {
    /// HTML body for the execute-actions (admin-initiated required actions)
    /// message.
    pub const EXECUTE_ACTIONS_HTML: &str = include_str!("../templates/email/execute-actions.html");
    /// Plain-text body for the execute-actions message.
    pub const EXECUTE_ACTIONS_TXT: &str = include_str!("../templates/email/execute-actions.txt");
}

/// One fully rendered outbound email.
pub struct RenderedEmail {
    pub subject: String,
    pub text: String,
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

/// English fallback copy, kept identical to the copy previously baked into
/// the templates: a missing bundle key must never change the default
/// (English) output. The shared fragments (`email.greeting`, …) mirror
/// issuerd-server's `i18n/messages_en.json` so a partially translated theme
/// bundle mixes cleanly with these defaults.
mod en_fallback {
    pub const GREETING: &str = "Hi {user},";
    pub const EXPIRY_NOTE: &str = "This link expires in {minutes} minutes.";
    pub const FALLBACK_NOTE: &str =
        "If the button does not work, copy and paste this link into your browser:";
    pub const FOOTER: &str = "This is an automated message from {realm}. Please do not reply.";
    pub const SUBJECT: &str = "Complete required actions for your account";
    pub const HEADING: &str = "Complete required actions for your account";
    pub const PREHEADER: &str =
        "Action required for your {realm} account — this link expires in {minutes} minutes.";
    pub const INTRO: &str =
        "An administrator has asked you to complete required actions for your {realm} account.";
    pub const BUTTON: &str = "Complete required actions";
    pub const IGNORE_NOTE: &str = "If you were not expecting this message, you can safely ignore it — no changes will be made to your account until you open the link.";
}

/// All translatable strings of the execute-actions email, resolved from a
/// bundle (the server's key scheme: `email.executeActions.*` for the
/// mail-specific copy plus the shared `email.*` fragments).
struct ExecuteActionsStrings {
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
}

impl ExecuteActionsStrings {
    /// Resolve every string from `bundle`, substituting
    /// `{realm}`/`{user}`/`{minutes}`. Bundle text is trusted theme content
    /// and inserted verbatim; the dynamic values are HTML-escaped when
    /// `escape` is set (HTML body) and raw otherwise (plain-text body).
    fn resolve(
        bundle: &HashMap<String, String>,
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
            bundle
                .get(key)
                .cloned()
                .unwrap_or_else(|| default.to_string())
                .replace("{realm}", &realm)
                .replace("{user}", &user)
                .replace("{minutes}", minutes)
        };
        Self {
            subject: lookup("email.executeActions.subject", en_fallback::SUBJECT),
            heading: lookup("email.executeActions.heading", en_fallback::HEADING),
            preheader: lookup("email.executeActions.preheader", en_fallback::PREHEADER),
            greeting: lookup("email.greeting", en_fallback::GREETING),
            intro: lookup("email.executeActions.intro", en_fallback::INTRO),
            expiry_note: lookup("email.expiryNote", en_fallback::EXPIRY_NOTE),
            button_label: lookup("email.executeActions.button", en_fallback::BUTTON),
            fallback_note: lookup("email.fallbackNote", en_fallback::FALLBACK_NOTE),
            ignore_note: lookup("email.executeActions.ignoreNote", en_fallback::IGNORE_NOTE),
            footer: lookup("email.footer", en_fallback::FOOTER),
        }
    }
}

/// Render the execute-actions email for `user_display` in `realm_display`
/// with the built-in English copy.
///
/// `link` is the absolute execute-actions URL carrying the signed action
/// token; `link_expiration_minutes` is the human-facing validity window.
/// Dynamic values are HTML-escaped for the HTML body and used verbatim for
/// the plain-text body.
pub fn render_execute_actions_email(
    realm_display: &str,
    user_display: &str,
    link: &str,
    link_expiration_minutes: i64,
) -> RenderedEmail {
    render_execute_actions_email_localized(
        realm_display,
        user_display,
        link,
        link_expiration_minutes,
        &HashMap::new(),
    )
}

/// [`render_execute_actions_email`] with the copy taken from `bundle` (locale
/// already resolved by the caller); missing keys fall back to English per key.
pub fn render_execute_actions_email_localized(
    realm_display: &str,
    user_display: &str,
    link: &str,
    link_expiration_minutes: i64,
    bundle: &HashMap<String, String>,
) -> RenderedEmail {
    let minutes = link_expiration_minutes.to_string();
    let html = ExecuteActionsStrings::resolve(bundle, realm_display, user_display, &minutes, true);
    let text = ExecuteActionsStrings::resolve(bundle, realm_display, user_display, &minutes, false);
    let html_vars = [
        ("realm", html_escape(realm_display)),
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
        ("heading", text.heading),
        ("greeting", text.greeting),
        ("intro", text.intro),
        ("link", link.to_string()),
        ("expiry_note", text.expiry_note),
        ("ignore_note", text.ignore_note),
        ("footer", text.footer),
    ];
    RenderedEmail {
        subject: text.subject,
        text: render_template(templates::EXECUTE_ACTIONS_TXT, &text_vars),
        html: render_template(templates::EXECUTE_ACTIONS_HTML, &html_vars),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_covers_all_five_characters() {
        assert_eq!(html_escape("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
        assert_eq!(html_escape("plain"), "plain");
    }

    #[test]
    fn render_execute_actions_email_substitutes_all_placeholders() {
        let rendered = render_execute_actions_email(
            "Demo Realm",
            "alice",
            "https://id.example.com/realms/demo/login/execute-actions?token=abc",
            720,
        );
        for body in [&rendered.text, &rendered.html] {
            assert!(!body.contains("{{"), "unsubstituted placeholder in body");
            assert!(body.contains("Demo Realm"));
            assert!(body.contains("alice"));
            assert!(
                body.contains("https://id.example.com/realms/demo/login/execute-actions?token=abc")
            );
            assert!(body.contains("720 minutes"));
        }
        assert_eq!(rendered.subject, "Complete required actions for your account");
    }

    #[test]
    fn render_execute_actions_email_default_text_body_is_byte_identical() {
        // The empty-bundle render must reproduce the legacy English mail
        // byte-for-byte, including the plain-text layout (the heading
        // underline stays a fixed decoration line of the template).
        let rendered = render_execute_actions_email("Demo Realm", "alice", "https://link", 720);
        let expected = "Complete required actions for your account\n\
            ===========================================\n\
            \n\
            Hi alice,\n\
            \n\
            An administrator has asked you to complete required actions for your Demo Realm account.\n\
            \n\
            https://link\n\
            \n\
            This link expires in 720 minutes.\n\
            \n\
            If you were not expecting this message, you can safely ignore it — no changes will be made to your account until you open the link.\n\
            \n\
            --\n\
            This is an automated message from Demo Realm. Please do not reply.\n";
        assert_eq!(rendered.text, expected);
        // The HTML body must likewise stay byte-stable: pin the hidden
        // preheader padding run (exactly 9 `&#8199;&#847;` pairs, as the
        // legacy template had) and assert full placeholder substitution.
        assert!(
            rendered.html.contains(&"&#8199;&#847;".repeat(9)),
            "legacy preheader padding run must survive"
        );
        assert!(!rendered.html.contains("{{"), "unsubstituted placeholder in html body");
    }

    #[test]
    fn render_execute_actions_email_localizes_via_bundle() {
        let bundle = HashMap::from([
            (
                "email.executeActions.subject".to_string(),
                "Erforderliche Aktionen für Ihr Konto".to_string(),
            ),
            ("email.greeting".to_string(), "Hallo {user},".to_string()),
        ]);
        let rendered = render_execute_actions_email_localized(
            "Demo Realm",
            "alice",
            "https://id.example.com/x?token=abc",
            60,
            &bundle,
        );
        assert_eq!(rendered.subject, "Erforderliche Aktionen für Ihr Konto");
        for body in [&rendered.text, &rendered.html] {
            assert!(!body.contains("{{"), "unsubstituted placeholder in body");
            assert!(body.contains("Hallo alice,"), "greeting from bundle in: {body}");
        }
        // Keys missing from the bundle keep the English defaults per key.
        assert!(rendered.text.contains("This link expires in 60 minutes."));
        assert!(rendered.html.contains("Complete required actions for your account"));
    }

    #[test]
    fn render_execute_actions_email_escapes_html_values() {
        let rendered = render_execute_actions_email(
            "<script>alert(1)</script>",
            "alice<b>",
            "https://id.example.com/?a=1&b=2",
            15,
        );
        assert!(rendered.html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(rendered.html.contains("alice&lt;b&gt;"));
        assert!(rendered.html.contains("?a=1&amp;b=2"));
        assert!(!rendered.html.contains("<script>"));
        // Plain-text body keeps values verbatim (no HTML entities).
        assert!(rendered.text.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn render_execute_actions_email_localized_escapes_dynamic_values() {
        // A translated greeting still gets the HTML-escaped username; the
        // bundle text itself is trusted and inserted verbatim.
        let bundle =
            HashMap::from([("email.greeting".to_string(), "<em>Hallo</em> {user},".to_string())]);
        let rendered = render_execute_actions_email_localized(
            "Demo Realm",
            "alice<b>",
            "https://l",
            5,
            &bundle,
        );
        assert!(rendered.html.contains("<em>Hallo</em> alice&lt;b&gt;,"));
        assert!(rendered.text.contains("<em>Hallo</em> alice<b>,"));
    }

    #[test]
    fn html_template_uses_outlook_compatible_markup() {
        let html = templates::EXECUTE_ACTIONS_HTML;
        assert!(html.contains("XHTML 1.0 Transitional"));
        assert!(html.contains("<!--[if mso]>"));
        assert!(html.contains("v:roundrect"));
        assert!(!html.contains("display:flex"));
        assert!(!html.contains("display:grid"));
    }
}
