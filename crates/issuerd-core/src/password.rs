// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Password policy validation and password-credential history helpers.
//!
//! [`PasswordPolicy::validate`] is a **pure function**: it performs no I/O and
//! only inspects the candidate password string and the [`User`] value. Hash
//! verification for history-reuse checks happens at the set-password call
//! sites (admin API, required action), which own the password hasher; this
//! module provides the pure retention-selection helper
//! [`credentials_to_retain`].

use serde::{Deserialize, Serialize};

use crate::ids::CredentialId;
use crate::models::{Credential, PasswordPolicy, User};

/// A single password-policy violation, machine-readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PasswordPolicyViolation {
    /// Stable machine-readable code, e.g. `"min_length"`, `"not_username"`.
    pub code: String,
    /// Human-readable description of the violated rule.
    pub message: String,
}

/// Error returned when a password violates the realm [`PasswordPolicy`].
///
/// Carries **all** violations (not just the first) so API clients can render
/// the complete rule set to the user in one round trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PasswordPolicyError {
    /// Every rule the candidate password failed.
    pub violations: Vec<PasswordPolicyViolation>,
}

impl std::fmt::Display for PasswordPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let joined = self
            .violations
            .iter()
            .map(|v| format!("[{}] {}", v.code, v.message))
            .collect::<Vec<_>>()
            .join("; ");
        write!(f, "password policy violation: {joined}")
    }
}

impl std::error::Error for PasswordPolicyError {}

impl From<PasswordPolicyError> for crate::error::IssuerdError {
    fn from(err: PasswordPolicyError) -> Self {
        crate::error::IssuerdError::InvalidRequest(err.to_string())
    }
}

impl PasswordPolicy {
    /// Validate a candidate password against this policy.
    ///
    /// Pure function — no I/O, no hashing. Checks length bounds, character
    /// classes (digit/lower/upper/special), `not_username`, and `not_email`.
    /// Password-history reuse is **not** checked here (it requires hash
    /// verification); call sites enforce it against retained credentials.
    pub fn validate(&self, password: &str, user: &User) -> Result<(), PasswordPolicyError> {
        let mut violations = Vec::new();
        let len = password.chars().count() as u32;

        if len < self.min_length.get() {
            violations.push(PasswordPolicyViolation {
                code: "min_length".to_string(),
                message: format!(
                    "password must be at least {} characters long",
                    self.min_length.get()
                ),
            });
        }
        if let Some(max) = self.max_length {
            if len > max.get() {
                violations.push(PasswordPolicyViolation {
                    code: "max_length".to_string(),
                    message: format!("password must be at most {} characters long", max.get()),
                });
            }
        }
        if self.require_digits && !password.chars().any(|c| c.is_ascii_digit()) {
            violations.push(PasswordPolicyViolation {
                code: "require_digits".to_string(),
                message: "password must contain at least one digit".to_string(),
            });
        }
        if self.require_lower && !password.chars().any(|c| c.is_lowercase()) {
            violations.push(PasswordPolicyViolation {
                code: "require_lower".to_string(),
                message: "password must contain at least one lowercase letter".to_string(),
            });
        }
        if self.require_upper && !password.chars().any(|c| c.is_uppercase()) {
            violations.push(PasswordPolicyViolation {
                code: "require_upper".to_string(),
                message: "password must contain at least one uppercase letter".to_string(),
            });
        }
        // "Special" means any non-alphanumeric character (Unicode-aware):
        // punctuation, symbols, whitespace-free separators, etc.
        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            violations.push(PasswordPolicyViolation {
                code: "require_special".to_string(),
                message: "password must contain at least one special character".to_string(),
            });
        }
        if self.not_username && password.eq_ignore_ascii_case(user.username.as_ref()) {
            violations.push(PasswordPolicyViolation {
                code: "not_username".to_string(),
                message: "password must not be equal to the username".to_string(),
            });
        }
        if self.not_email {
            if let Some(email) = &user.email {
                if password.eq_ignore_ascii_case(email.as_ref()) {
                    violations.push(PasswordPolicyViolation {
                        code: "not_email".to_string(),
                        message: "password must not be equal to the email address".to_string(),
                    });
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(PasswordPolicyError { violations })
        }
    }
}

/// Select which existing password credentials to **retain** when a new
/// password is set, given a policy `history_size`.
///
/// Keycloak semantics: with `history_size = N`, the new password plus the
/// `N - 1` most recent previous passwords are kept (and checked against);
/// anything older is deleted. A `history_size` of `0` disables history —
/// all previous credentials are replaced.
///
/// Pure function: callers pass the user's current password-type credentials
/// and delete every credential whose id is **not** in the returned set.
pub fn credentials_to_retain(existing: &[Credential], history_size: u32) -> Vec<CredentialId> {
    if history_size == 0 {
        return Vec::new();
    }
    let keep = (history_size - 1) as usize;
    let mut sorted: Vec<&Credential> = existing.iter().collect();
    // Newest first; stable sort keeps a deterministic order for identical
    // timestamps.
    sorted.sort_by_key(|c| std::cmp::Reverse(c.created_date));
    sorted.into_iter().take(keep).map(|c| c.id.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HashAlgorithm, PasswordLength};
    use rstest::rstest;

    fn user() -> User {
        User {
            id: crate::ids::UserId::new("u-1").unwrap(),
            realm_id: crate::ids::RealmId::new("r-1").unwrap(),
            username: crate::models::Username::new("alice").unwrap(),
            email: Some(crate::models::Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: std::collections::HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            required_actions: vec![],
        }
    }

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            min_length: PasswordLength::new(8),
            max_length: None,
            require_digits: true,
            require_lower: true,
            require_upper: true,
            require_special: true,
            not_username: true,
            not_email: true,
            history_size: 0,
            hash_algorithm: HashAlgorithm::Argon2id,
        }
    }

    fn codes(err: &PasswordPolicyError) -> Vec<&str> {
        err.violations.iter().map(|v| v.code.as_str()).collect()
    }

    #[rstest]
    #[case("Str0ng!pass", true, &[])]
    // min_length
    #[case("S1!abcd", false, &["min_length"])]
    // max_length
    #[case("Aa1!aaaaaaaaaaaaaaaa", true, &[])]
    // digits
    #[case("Strong!pass", false, &["require_digits"])]
    // lower
    #[case("STR0NG!PASS", false, &["require_lower"])]
    // upper
    #[case("str0ng!pass", false, &["require_upper"])]
    // special
    #[case("Str0ngpass1", false, &["require_special"])]
    // not_username (case-insensitive)
    #[case("ALICE", false, &["min_length", "require_digits", "require_lower", "require_special", "not_username"])]
    #[case("alice", false, &["min_length", "require_digits", "require_upper", "require_special", "not_username"])]
    // not_email (case-insensitive); `@` satisfies the special-char rule
    #[case("Alice@Example.com", false, &["require_digits", "not_email"])]
    // multiple violations at once
    #[case("short", false, &["min_length", "require_digits", "require_upper", "require_special"])]
    fn validate_table(#[case] password: &str, #[case] ok: bool, #[case] expected: &[&str]) {
        let result = policy().validate(password, &user());
        assert_eq!(result.is_ok(), ok, "password {password:?}");
        if let Err(err) = result {
            assert_eq!(codes(&err), expected, "password {password:?}");
        }
    }

    #[test]
    fn validate_max_length_enforced_when_set() {
        let p = PasswordPolicy {
            max_length: Some(PasswordLength::new(10)),
            ..PasswordPolicy::default()
        };
        let err = p.validate("abcdefghijklmnop", &user()).unwrap_err();
        assert_eq!(codes(&err), vec!["max_length"]);
    }

    #[test]
    fn default_policy_accepts_any_8_plus_chars() {
        let p = PasswordPolicy::default();
        assert!(p.validate("12345678", &user()).is_ok());
        assert!(p.validate("username-free", &user()).is_ok());
        assert!(p.validate("short", &user()).is_err());
    }

    #[test]
    fn unicode_length_counts_chars_not_bytes() {
        // 8 Unicode scalar values, 24 UTF-8 bytes — must pass min_length 8.
        let p = PasswordPolicy::default();
        assert!(p.validate("пароль123", &user()).is_ok());
    }

    #[test]
    fn error_display_contains_all_codes() {
        let err = policy().validate("x", &user()).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("min_length"));
        assert!(s.contains("require_digits"));
    }

    #[test]
    fn converts_into_issuerd_error_invalid_request() {
        let err = policy().validate("x", &user()).unwrap_err();
        let issuerd_err: crate::error::IssuerdError = err.into();
        assert!(matches!(issuerd_err, crate::error::IssuerdError::InvalidRequest(_)));
    }

    #[test]
    fn violation_serde_roundtrip() {
        let err = policy().validate("x", &user()).unwrap_err();
        let json = serde_json::to_string(&err).unwrap();
        let back: PasswordPolicyError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // ------------------------------------------------------------------
    // credentials_to_retain
    // ------------------------------------------------------------------

    fn cred(id: &str, days_ago: i64) -> Credential {
        Credential {
            id: CredentialId::new(id).unwrap(),
            credential_type: crate::models::CredentialType::Password,
            user_label: None,
            created_date: chrono::Utc::now() - chrono::Duration::days(days_ago),
            secret_data: b"hash".to_vec(),
            credential_data: serde_json::json!({}),
            priority: 1,
        }
    }

    #[test]
    fn retain_none_when_history_disabled() {
        let existing = vec![cred("a", 1), cred("b", 2)];
        assert!(credentials_to_retain(&existing, 0).is_empty());
    }

    #[test]
    fn retain_newest_n_minus_1() {
        // history_size 3 → keep the 2 newest previous passwords.
        let existing = vec![cred("oldest", 30), cred("newest", 1), cred("middle", 10)];
        let keep = credentials_to_retain(&existing, 3);
        let keep: Vec<&str> = keep.iter().map(|c| c.0.as_str()).collect();
        assert_eq!(keep, vec!["newest", "middle"]);
    }

    #[test]
    fn retain_all_when_fewer_than_history() {
        let existing = vec![cred("only", 5)];
        let keep = credentials_to_retain(&existing, 5);
        assert_eq!(keep.len(), 1);
    }

    #[test]
    fn retain_history_size_1_keeps_nothing() {
        // history_size 1 means "only the current password is remembered" —
        // the new password replaces everything.
        let existing = vec![cred("a", 1)];
        assert!(credentials_to_retain(&existing, 1).is_empty());
    }
}
