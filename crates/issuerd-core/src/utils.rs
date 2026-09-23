// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Small shared utilities: ID generation, timestamps, and input validation helpers.

use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

/// Generate a new v4 UUID string.
///
/// # Examples
///
/// ```
/// use issuerd_core::utils::generate_id;
///
/// let id = generate_id();
/// assert_eq!(id.len(), 36); // standard UUID string length
/// ```
pub fn generate_id() -> String {
    Uuid::new_v4().to_string()
}

/// Current Unix timestamp in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

/// Current Unix timestamp in milliseconds.
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as u64
}

/// Validate that a string is a valid email address (basic check).
pub fn is_valid_email(email: &str) -> bool {
    email.contains('@') && !email.starts_with('@') && !email.ends_with('@')
}

/// Validate that a username contains only allowed characters.
pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Split a space-delimited scope string into unique, sorted tokens.
pub fn parse_scopes(scope: &str) -> Vec<String> {
    let mut scopes: Vec<String> = scope.split_whitespace().map(|s| s.to_string()).collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

/// Sanitize an untrusted string for single-line log output.
///
/// Replaces ASCII control characters (including `\r` and `\n`) with `?` so
/// attacker-controlled values (usernames, IdP error descriptions, …) cannot
/// forge log lines or inject terminal escape sequences. Returns the original
/// string untouched when it contains no control characters.
pub fn sanitize_log_str(value: &str) -> std::borrow::Cow<'_, str> {
    if value.chars().any(char::is_control) {
        std::borrow::Cow::Owned(
            value.chars().map(|c| if c.is_control() { '?' } else { c }).collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_id_format() {
        let id = generate_id();
        assert_eq!(id.len(), 36);
        // UUID v4 format: 8-4-4-4-12 with hyphens at positions 8, 13, 18, 23
        assert_eq!(id.chars().nth(8), Some('-'));
        assert_eq!(id.chars().nth(13), Some('-'));
        assert_eq!(id.chars().nth(18), Some('-'));
        assert_eq!(id.chars().nth(23), Some('-'));
        // Version nibble should be 4
        assert_eq!(id.chars().nth(14), Some('4'));
    }

    #[test]
    fn now_secs_monotonic_and_magnitude() {
        let t1 = now_secs();
        let t2 = now_secs();
        assert!(t2 >= t1);
        // Rough magnitude check: should be after 2020-01-01 (1577836800)
        assert!(t1 > 1_577_836_800);
        // And before 2040-01-01 (2208988800)
        assert!(t1 < 2_208_988_800);
    }

    #[test]
    fn now_millis_monotonic_and_magnitude() {
        let t1 = now_millis();
        let t2 = now_millis();
        assert!(t2 >= t1);
        // Should be after 2020-01-01 in millis
        assert!(t1 > 1_577_836_800_000);
        // And before 2040-01-01 in millis
        assert!(t1 < 2_208_988_800_000);
    }

    #[test]
    fn is_valid_email_positive() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("a@b.co"));
        assert!(is_valid_email("user.name+tag@example.co.uk"));
    }

    #[test]
    fn is_valid_email_negative() {
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("notanemail"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("user@"));
        assert!(!is_valid_email("@"));
    }

    #[test]
    fn is_valid_username_positive() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("user_123"));
        assert!(is_valid_username("bob.smith"));
        assert!(is_valid_username("charlie-jones"));
        assert!(is_valid_username("A1"));
    }

    #[test]
    fn is_valid_username_negative() {
        assert!(!is_valid_username(""));
        assert!(!is_valid_username(" user"));
        assert!(!is_valid_username("user "));
        assert!(!is_valid_username("user@name"));
        assert!(!is_valid_username("user/name"));
    }

    #[test]
    fn parse_scopes_ordering_and_dedup() {
        assert_eq!(parse_scopes("openid profile email"), vec!["email", "openid", "profile"]);
    }

    #[test]
    fn parse_scopes_deduplicates() {
        assert_eq!(parse_scopes("openid openid profile"), vec!["openid", "profile"]);
    }

    #[test]
    fn parse_scopes_whitespace_handling() {
        assert_eq!(parse_scopes("  openid   profile  email  "), vec!["email", "openid", "profile"]);
    }

    #[test]
    fn parse_scopes_empty() {
        assert!(parse_scopes("").is_empty());
        assert!(parse_scopes("   ").is_empty());
    }

    #[test]
    fn sanitize_log_str_clean_input_borrowed() {
        let clean = sanitize_log_str("alice.smith");
        assert_eq!(clean, "alice.smith");
        assert!(matches!(clean, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn sanitize_log_str_strips_newlines_and_controls() {
        assert_eq!(sanitize_log_str("alice\nINFO forged"), "alice?INFO forged");
        assert_eq!(sanitize_log_str("a\rb\rc"), "a?b?c");
        assert_eq!(sanitize_log_str("tab\there"), "tab?here");
        assert_eq!(sanitize_log_str("esc\u{1b}[31m"), "esc?[31m");
        assert_eq!(sanitize_log_str("nul\u{0}x"), "nul?x");
    }

    #[test]
    fn sanitize_log_str_preserves_unicode() {
        assert_eq!(sanitize_log_str("用户名字"), "用户名字");
    }
}
