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
//! Transitional, table layout, MSO conditionals, VML bulletproof button) is
//! shared, but the i18n message-bundle resolution is **not** reachable from
//! this crate (issuerd-server depends on issuerd-admin-api, never the reverse), so the
//! execute-actions email ships English-only copy with the
//! `{{realm}}`/`{{user}}`/`{{link}}`/`{{link_expiration_minutes}}`
//! placeholder set.

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

/// Render the execute-actions email for `user_display` in `realm_display`.
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
    let minutes = link_expiration_minutes.to_string();
    let html_vars = [
        ("realm", html_escape(realm_display)),
        ("user", html_escape(user_display)),
        ("link", html_escape(link)),
        ("link_expiration_minutes", minutes.clone()),
    ];
    let text_vars = [
        ("realm", realm_display.to_string()),
        ("user", user_display.to_string()),
        ("link", link.to_string()),
        ("link_expiration_minutes", minutes),
    ];
    RenderedEmail {
        subject: "Complete required actions for your account".to_string(),
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
    fn html_template_uses_outlook_compatible_markup() {
        let html = templates::EXECUTE_ACTIONS_HTML;
        assert!(html.contains("XHTML 1.0 Transitional"));
        assert!(html.contains("<!--[if mso]>"));
        assert!(html.contains("v:roundrect"));
        assert!(!html.contains("display:flex"));
        assert!(!html.contains("display:grid"));
    }
}
