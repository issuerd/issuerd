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
/// realm has a login theme and the files exist on disk.
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
    if let (Some(dir), Some(theme_name)) = (themes_dir, theme) {
        for layer in [DEFAULT_LOCALE, lang] {
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
    fn german_bundle_overrides_english_keys() {
        let bundle = message_bundle(None, None, "de-DE");
        let title = bundle.get("login.title").unwrap();
        assert_ne!(title, "Sign In");
        // Keys missing from de (if any) fall back to en.
        assert!(bundle.contains_key("consent.allow"));
    }
}
