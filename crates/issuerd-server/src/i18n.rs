// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// UI internationalization: locale resolution and layered message-bundle loading.

//! UI internationalization.
//!
//! Locale resolution follows the Keycloak precedence chain:
//! `ui_locales` authorization parameter → `Accept-Language` header → realm
//! `default_locale` → `en`. The whole chain is gated on the realm's
//! `internationalization_enabled` flag; when off, every resolution is `en`.
//!
//! Message bundles are flat JSON key→text maps. Loading is layered with
//! per-key fallback, so a partial custom bundle only overrides the keys it
//! defines:
//!
//! 1. built-in `en` (embedded, always complete)
//! 2. built-in `{locale}` (embedded; shipped locales: [`SHIPPED_LOCALES`])
//! 3. theme `en` override (`{themes_dir}/{theme}/messages_en.json`)
//! 4. theme `{locale}` override (`{themes_dir}/{theme}/messages_{locale}.json`)
//!
//! Locale strings are request-controlled (`ui_locales`, `Accept-Language`,
//! the user `locale` attribute); only strict ASCII-alphanumeric language
//! subtags may become filesystem path components (see [`safe_layer_name`]).
//!
//! A `None` theme falls back to the default theme
//! ([`crate::routes::theme::DEFAULT_THEME`]), matching the theme asset
//! handler: operators can drop `messages_<locale>.json` into the default
//! theme directory without setting `login_theme`/`email_theme` on the realm.
//!
//! The login page receives its resolved bundle through the (unauthenticated)
//! login-context endpoint; server-rendered pages and emails consume the same
//! bundles server-side.

use std::collections::HashMap;
use std::path::Path;

use tracing::warn;

use issuerd_core::{Realm, User};

/// Locales with a built-in message bundle (embedded at compile time).
pub use issuerd_core::i18n::SHIPPED_LOCALES;

/// The fallback locale — always shipped, always complete.
pub const DEFAULT_LOCALE: &str = "en";

mod bundles {
    /// Built-in English bundle (canonical, complete).
    pub const EN: &str = include_str!("../i18n/messages_en.json");
    /// Built-in German bundle.
    pub const DE: &str = include_str!("../i18n/messages_de.json");
}

/// A flat message key → text map.
pub type MessageBundle = HashMap<String, String>;

fn parse_bundle(json: &str) -> MessageBundle {
    serde_json::from_str(json).unwrap_or_default()
}

fn builtin_bundle(locale: &str) -> Option<MessageBundle> {
    match locale {
        "en" => Some(parse_bundle(bundles::EN)),
        "de" => Some(parse_bundle(bundles::DE)),
        _ => None,
    }
}

/// Primary language subtag of a BCP-47 tag (`de-DE` → `de`).
fn language_subtag(tag: &str) -> &str {
    tag.split(['-', '_']).next().unwrap_or(tag)
}

/// A language tag that is safe to use as a filesystem path component:
/// non-empty and strictly ASCII alphanumeric (what a BCP-47 primary subtag
/// looks like once split on `-`/`_`). Locale strings are request-controlled
/// (`ui_locales`, `Accept-Language`, the user `locale` attribute), so
/// anything containing separators, dots, or other bytes must never reach the
/// filesystem — it is rejected here, at the sink.
fn safe_layer_name(tag: &str) -> Option<&str> {
    if !tag.is_empty() && tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
        Some(tag)
    } else {
        None
    }
}

/// Parse an `Accept-Language` header value into quality-ordered tags.
/// (`de, en-US;q=0.9, en;q=0.8` → `["de", "en-US", "en"]`.)
pub fn parse_accept_language(header: &str) -> Vec<String> {
    let mut parsed: Vec<(f32, usize, String)> = header
        .split(',')
        .enumerate()
        .filter_map(|(idx, part)| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let (tag, q) = match part.split_once(';') {
                Some((tag, params)) => {
                    let q = params
                        .trim()
                        .strip_prefix("q=")
                        .and_then(|v| v.parse::<f32>().ok())
                        .unwrap_or(1.0);
                    (tag.trim(), q)
                }
                None => (part, 1.0),
            };
            if tag.is_empty() {
                return None;
            }
            Some((q, idx, tag.to_string()))
        })
        .collect();
    // Higher quality first; stable by position for ties.
    parsed.sort_by(|a, b| {
        b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1))
    });
    parsed.into_iter().map(|(_, _, tag)| tag).collect()
}

/// Resolve the UI locale for a request.
///
/// Gated on `realm.internationalization_enabled` (off ⇒ always `en`). A
/// candidate is admissible when the realm's `supported_locales` is empty
/// (unrestricted) or contains the candidate's primary language subtag. The
/// result is not clamped to [`SHIPPED_LOCALES`]: custom themes can ship
/// additional bundle files, and the bundle loader falls back to English
/// per-key for anything missing.
pub fn resolve_locale(
    realm: &Realm,
    ui_locales: &[String],
    accept_language: Option<&str>,
) -> String {
    if !realm.internationalization_enabled {
        return DEFAULT_LOCALE.to_string();
    }
    let allowed = |tag: &str| {
        realm.supported_locales.is_empty()
            || realm
                .supported_locales
                .iter()
                .any(|s| language_subtag(s) == language_subtag(tag) || s == tag)
    };
    for candidate in ui_locales {
        if allowed(candidate) {
            return candidate.clone();
        }
    }
    if let Some(header) = accept_language {
        for candidate in parse_accept_language(header) {
            if candidate == "*" {
                continue;
            }
            if allowed(&candidate) {
                return candidate;
            }
        }
    }
    realm.default_locale.clone().unwrap_or_else(|| DEFAULT_LOCALE.to_string())
}

/// Resolve the locale for outbound email to `user`: the user's `locale`
/// attribute wins (Keycloak semantics), then the realm default.
pub fn user_locale(realm: &Realm, user: &User) -> String {
    if !realm.internationalization_enabled {
        return DEFAULT_LOCALE.to_string();
    }
    if let Some(loc) = user
        .attributes
        .get("locale")
        .and_then(|v| v.first())
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let allowed = realm.supported_locales.is_empty()
            || realm
                .supported_locales
                .iter()
                .any(|s| language_subtag(s) == language_subtag(loc) || s == loc);
        if allowed {
            return loc.to_string();
        }
    }
    realm.default_locale.clone().unwrap_or_else(|| DEFAULT_LOCALE.to_string())
}

/// Load the layered message bundle for `locale` (with per-key English
/// fallback). `themes_dir`/`theme` add the theme override layers when the
/// files exist on disk; a `None` theme reads the default theme
/// ([`crate::routes::theme::DEFAULT_THEME`]), the same fallback the theme
/// asset handler applies.
pub fn message_bundle(
    themes_dir: Option<&Path>,
    theme: Option<&str>,
    locale: &str,
) -> MessageBundle {
    let mut bundle = builtin_bundle(DEFAULT_LOCALE).unwrap_or_default();
    let lang = language_subtag(locale);
    if lang != DEFAULT_LOCALE {
        if let Some(overlay) = builtin_bundle(lang) {
            bundle.extend(overlay);
        }
    }
    if let Some(dir) = themes_dir {
        // A malformed stored theme name must never become a path component
        // (same guard as the theme asset handler).
        let theme_name = match theme {
            Some(t) if !t.contains('/') && !t.contains('\\') && t != ".." => t,
            Some(_) => crate::routes::theme::DEFAULT_THEME,
            None => crate::routes::theme::DEFAULT_THEME,
        };
        for layer in [DEFAULT_LOCALE, lang] {
            // The locale string is request-controlled; only a strict
            // alphanumeric subtag may become a path component. An unsafe
            // layer is skipped — the built-in English layer is already
            // loaded, so the bundle simply stays at the fallback.
            let Some(layer) = safe_layer_name(layer) else {
                continue;
            };
            let path = dir.join(theme_name).join(format!("messages_{layer}.json"));
            // A missing override file for a layer is normal; malformed JSON is not.
            if let Ok(content) = std::fs::read_to_string(&path) {
                match serde_json::from_str::<MessageBundle>(&content) {
                    Ok(overlay) => bundle.extend(overlay),
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "ignoring malformed theme message bundle")
                    }
                }
            }
        }
    }
    bundle
}

/// Look up `key` in the bundle, falling back to `default` when absent.
pub fn msg<'a>(bundle: &'a MessageBundle, key: &str, default: &'a str) -> String {
    bundle.get(key).cloned().unwrap_or_else(|| default.to_string())
}

/// Prefix of the `Display` rendering of
/// [`issuerd_core::PasswordPolicyError`], which wraps every violation as
/// `[code] message` segments joined by `"; "`.
const POLICY_ENVELOPE_PREFIX: &str = "password policy violation: ";

/// Localize one password-policy violation message, identified by its stable
/// machine-readable `code` when the caller has it (the `[code] message`
/// envelope segments), or by the bare message shape otherwise. Unknown codes
/// and shapes pass through unchanged.
fn localize_policy_text(bundle: &MessageBundle, code: Option<&str>, message: &str) -> String {
    let key = match code {
        Some("min_length") => Some("error.passwordMinLength"),
        Some("max_length") => Some("error.passwordMaxLength"),
        Some("require_digits") => Some("error.passwordRequireDigits"),
        Some("require_lower") => Some("error.passwordRequireLower"),
        Some("require_upper") => Some("error.passwordRequireUpper"),
        Some("require_special") => Some("error.passwordRequireSpecial"),
        Some("not_username") => Some("error.passwordNotUsername"),
        Some("not_email") => Some("error.passwordNotEmail"),
        Some(_) => None,
        None => match message {
            "password must contain at least one digit" => Some("error.passwordRequireDigits"),
            "password must contain at least one lowercase letter" => {
                Some("error.passwordRequireLower")
            }
            "password must contain at least one uppercase letter" => {
                Some("error.passwordRequireUpper")
            }
            "password must contain at least one special character" => {
                Some("error.passwordRequireSpecial")
            }
            "password must not be equal to the username" => Some("error.passwordNotUsername"),
            "password must not be equal to the email address" => Some("error.passwordNotEmail"),
            _ if message.starts_with("password must be at least ")
                && message.ends_with(" characters long") =>
            {
                Some("error.passwordMinLength")
            }
            _ if message.starts_with("password must be at most ")
                && message.ends_with(" characters long") =>
            {
                Some("error.passwordMaxLength")
            }
            _ => None,
        },
    };
    match key {
        Some("error.passwordMinLength") => {
            // Off-shape message with a known code (cannot happen with today's
            // policy): never substitute an empty count — fall back to raw.
            match message
                .strip_prefix("password must be at least ")
                .and_then(|s| s.strip_suffix(" characters long"))
            {
                Some(count) => msg(
                    bundle,
                    "error.passwordMinLength",
                    "password must be at least {count} characters long",
                )
                .replace("{count}", count),
                None => message.to_string(),
            }
        }
        Some("error.passwordMaxLength") => {
            match message
                .strip_prefix("password must be at most ")
                .and_then(|s| s.strip_suffix(" characters long"))
            {
                Some(count) => msg(
                    bundle,
                    "error.passwordMaxLength",
                    "password must be at most {count} characters long",
                )
                .replace("{count}", count),
                None => message.to_string(),
            }
        }
        Some(key) => msg(bundle, key, message),
        None => message.to_string(),
    }
}

/// Map a known, stable error string produced by the flow engine
/// (`issuerd-auth-flow`: registration validation, required-action failures)
/// or by password-policy validation to its localized bundle equivalent.
///
/// Known strings map to `error.*` keys; the `{field}`/`{count}`-style
/// placeholders carry through the dynamic parts of the source string.
/// Password-policy errors arrive either as bare violation messages or wrapped
/// in the `password policy violation: [code] message; ...` display envelope —
/// both shapes are handled. Unknown strings pass through unchanged.
pub fn localize_error(bundle: &MessageBundle, raw: &str) -> String {
    let key = match raw {
        "passwords do not match" => Some("error.passwordsDoNotMatch"),
        "email already in use" => Some("error.emailInUse"),
        "username already in use" => Some("error.usernameInUse"),
        "First name is required." => Some("error.firstNameRequired"),
        "Last name is required." => Some("error.lastNameRequired"),
        "missing authenticator code" => Some("error.missingAuthenticatorCode"),
        "Invalid authenticator code" => Some("error.invalidAuthenticatorCode"),
        "the external directory for this user does not accept password changes" => {
            Some("error.directoryReadOnly")
        }
        _ => None,
    };
    if let Some(key) = key {
        return msg(bundle, key, raw);
    }
    // Registration form fields embed the field name: "{field} is required".
    if let Some(field) = raw.strip_suffix(" is required") {
        if !field.is_empty() {
            return msg(bundle, "error.fieldRequired", "{field} is required")
                .replace("{field}", field);
        }
    }
    if let Some(envelope) = raw.strip_prefix(POLICY_ENVELOPE_PREFIX) {
        return envelope
            .split("; ")
            .map(|segment| match segment.split_once(']') {
                Some((code, message)) if code.starts_with('[') => {
                    localize_policy_text(bundle, Some(code[1..].trim()), message.trim())
                }
                _ => segment.to_string(),
            })
            .collect::<Vec<_>>()
            .join("; ");
    }
    localize_policy_text(bundle, None, raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm_with(i18n: bool, supported: &[&str], default: Option<&str>) -> Realm {
        Realm {
            internationalization_enabled: i18n,
            supported_locales: supported.iter().map(|s| s.to_string()).collect(),
            default_locale: default.map(|s| s.to_string()),
            ..Realm::default()
        }
    }

    #[test]
    fn accept_language_parsing_orders_by_quality() {
        assert_eq!(parse_accept_language("de, en-US;q=0.9, en;q=0.8"), vec!["de", "en-US", "en"]);
        assert_eq!(parse_accept_language("en-US"), vec!["en-US"]);
        assert!(parse_accept_language("").is_empty());
        assert_eq!(parse_accept_language("en;q=0.5, de;q=0.9"), vec!["de", "en"]);
    }

    #[test]
    fn i18n_disabled_always_resolves_en() {
        let realm = realm_with(false, &["de"], Some("de"));
        assert_eq!(resolve_locale(&realm, &["de".to_string()], Some("de")), "en");
    }

    #[test]
    fn ui_locales_win_over_header_and_default() {
        let realm = realm_with(true, &["en", "de"], Some("en"));
        assert_eq!(resolve_locale(&realm, &["de".to_string()], Some("fr"),), "de");
    }

    #[test]
    fn accept_language_beats_realm_default() {
        let realm = realm_with(true, &["en", "de"], Some("de"));
        assert_eq!(resolve_locale(&realm, &[], Some("en-US, en;q=0.9")), "en-US");
    }

    #[test]
    fn unsupported_candidates_fall_through_to_default() {
        let realm = realm_with(true, &["en"], Some("en"));
        assert_eq!(resolve_locale(&realm, &["de".to_string()], Some("de")), "en");
    }

    #[test]
    fn no_candidates_uses_realm_default_then_en() {
        let with_default = realm_with(true, &["de"], Some("de"));
        assert_eq!(resolve_locale(&with_default, &[], None), "de");
        let without_default = realm_with(true, &[], None);
        assert_eq!(resolve_locale(&without_default, &[], None), "en");
    }

    #[test]
    fn region_subtag_matches_supported_language() {
        let realm = realm_with(true, &["de"], None);
        assert_eq!(resolve_locale(&realm, &["de-DE".to_string()], None), "de-DE");
    }

    #[test]
    fn wildcard_accept_language_is_skipped() {
        // A bare wildcard is not a locale: it must never be returned, even
        // with unrestricted supported_locales.
        let realm = realm_with(true, &[], Some("de"));
        assert_eq!(resolve_locale(&realm, &[], Some("*")), "de");
        // Real candidates around a wildcard still resolve.
        assert_eq!(resolve_locale(&realm, &[], Some("*, fr;q=0.5, de;q=0.9")), "de");
    }

    #[test]
    fn builtin_bundles_cover_same_keys() {
        let en = builtin_bundle("en").unwrap();
        let de = builtin_bundle("de").unwrap();
        let missing: Vec<_> = en.keys().filter(|k| !de.contains_key(*k)).collect();
        assert!(missing.is_empty(), "de bundle missing keys: {missing:?}");
    }

    #[test]
    fn unknown_locale_falls_back_to_english_bundle() {
        let bundle = message_bundle(None, None, "fr-FR");
        assert_eq!(bundle.get("login.title").map(String::as_str), Some("Sign In"));
    }

    #[test]
    fn message_bundle_without_theme_reads_default_theme_dir() {
        // A `None` theme falls back to the default theme directory, matching
        // the theme asset handler: `themes/issuerd/messages_fr.json` applies
        // without any realm theme setting.
        let dir = std::env::temp_dir()
            .join(format!("issuerd-i18n-test-{}", issuerd_core::utils::generate_id()));
        let theme_dir = dir.join(crate::routes::theme::DEFAULT_THEME);
        std::fs::create_dir_all(&theme_dir).unwrap();
        std::fs::write(theme_dir.join("messages_fr.json"), r#"{"login.title":"Connexion FR"}"#)
            .unwrap();

        let bundle = message_bundle(Some(&dir), None, "fr");
        assert_eq!(bundle.get("login.title").map(String::as_str), Some("Connexion FR"));
        // Untouched keys still fall back to the built-in English text.
        assert_eq!(bundle.get("consent.allow").map(String::as_str), Some("Allow"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn message_bundle_named_theme_still_wins() {
        let dir = std::env::temp_dir()
            .join(format!("issuerd-i18n-test-{}", issuerd_core::utils::generate_id()));
        let default_dir = dir.join(crate::routes::theme::DEFAULT_THEME);
        let custom_dir = dir.join("custom");
        std::fs::create_dir_all(&default_dir).unwrap();
        std::fs::create_dir_all(&custom_dir).unwrap();
        std::fs::write(default_dir.join("messages_en.json"), r#"{"login.title":"Default"}"#)
            .unwrap();
        std::fs::write(custom_dir.join("messages_en.json"), r#"{"login.title":"Custom"}"#).unwrap();

        let bundle = message_bundle(Some(&dir), Some("custom"), "en");
        assert_eq!(bundle.get("login.title").map(String::as_str), Some("Custom"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn message_bundle_rejects_request_controlled_path_traversal() {
        // A crafted locale with separators must never become a path
        // component. The `messages_x` directory is created on purpose: the OS
        // resolves path components sequentially, so `../` traversal only
        // resolves when the prefix directory exists — with it present, the
        // naive join `messages_x/../../evil.json` would read
        // `{themes_dir}/evil.json`, one level above the theme directory.
        let dir = std::env::temp_dir()
            .join(format!("issuerd-i18n-test-{}", issuerd_core::utils::generate_id()));
        let theme_dir = dir.join(crate::routes::theme::DEFAULT_THEME);
        std::fs::create_dir_all(theme_dir.join("messages_x")).unwrap();
        std::fs::write(dir.join("evil.json"), r#"{"login.title":"PWNED"}"#).unwrap();

        let bundle = message_bundle(Some(&dir), None, "x/../../evil");
        // The unsafe layer is skipped; only the built-in English text remains.
        assert_eq!(bundle.get("login.title").map(String::as_str), Some("Sign In"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn safe_layer_name_accepts_only_strict_subtags() {
        assert_eq!(safe_layer_name("de"), Some("de"));
        assert_eq!(safe_layer_name("zh419"), Some("zh419"));
        assert_eq!(safe_layer_name(""), None);
        assert_eq!(safe_layer_name("../evil"), None);
        assert_eq!(safe_layer_name("x/../../evil"), None);
        // Already subtag-split by `language_subtag`; a raw tag must not pass.
        assert_eq!(safe_layer_name("de-DE"), None);
        assert_eq!(safe_layer_name("evil.json"), None);
    }

    #[test]
    fn localize_error_maps_known_flow_engine_strings() {
        let mut bundle = MessageBundle::new();
        bundle.insert("error.passwordsDoNotMatch".to_string(), "PASS-MISMATCH".to_string());
        bundle.insert("error.fieldRequired".to_string(), "{field} fehlt".to_string());

        assert_eq!(localize_error(&bundle, "passwords do not match"), "PASS-MISMATCH");
        // Placeholder: the dynamic field name is carried into the template.
        assert_eq!(localize_error(&bundle, "username is required"), "username fehlt");
        assert_eq!(localize_error(&bundle, "first name is required"), "first name fehlt");
        // Unknown strings pass through unchanged.
        assert_eq!(localize_error(&bundle, "something else entirely"), "something else entirely");
    }

    #[test]
    fn localize_error_defaults_to_the_english_text() {
        // Without a bundle override the known English text comes back as-is.
        let bundle = builtin_bundle("en").unwrap();
        assert_eq!(localize_error(&bundle, "passwords do not match"), "passwords do not match");
        assert_eq!(localize_error(&bundle, "email already in use"), "email already in use");
        assert_eq!(localize_error(&bundle, "username is required"), "username is required");
    }

    #[test]
    fn localize_error_maps_password_policy_messages() {
        let mut bundle = MessageBundle::new();
        bundle.insert("error.passwordRequireDigits".to_string(), "DIGITS".to_string());
        bundle.insert(
            "error.passwordMinLength".to_string(),
            "mindestens {count} Zeichen".to_string(),
        );

        // Bare violation messages (the reset page joins them directly).
        assert_eq!(localize_error(&bundle, "password must contain at least one digit"), "DIGITS");
        assert_eq!(
            localize_error(&bundle, "password must be at least 8 characters long"),
            "mindestens 8 Zeichen"
        );

        // The PasswordPolicyError display envelope keeps its shape, with each
        // `[code] message` segment localized; unknown segments pass through.
        let wrapped = "password policy violation: [min_length] password must be at least 12 \
                       characters long; [require_digits] password must contain at least one digit";
        assert_eq!(localize_error(&bundle, wrapped), "mindestens 12 Zeichen; DIGITS");
        let mixed = "password policy violation: [custom_rule] bespoke rule text";
        assert_eq!(localize_error(&bundle, mixed), "bespoke rule text");
    }

    #[test]
    fn german_bundle_overrides_english_keys() {
        let bundle = message_bundle(None, None, "de-DE");
        let title = bundle.get("login.title").unwrap();
        assert_ne!(title, "Sign In");
        // Keys missing from de (if any) fall back to en.
        assert!(bundle.contains_key("consent.allow"));
    }
}
