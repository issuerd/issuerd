// `unsanitized_username_in_log`: a `username` field carrying raw text must be
// a sanitize_log_str(...) call (or the validated Username newtype), at INFO+
// and in span fields.

#![allow(dead_code)]

pub mod utils {
    use std::borrow::Cow;
    pub fn sanitize_log_str(value: &str) -> Cow<'_, str> {
        Cow::Borrowed(value)
    }
}

pub mod models {
    pub struct Username(pub String);
    impl std::fmt::Display for Username {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
}

#[tracing::instrument(fields(username = %raw))]
fn span_raw(raw: &str) {}

#[tracing::instrument(fields(username = %utils::sanitize_log_str(raw)))]
fn span_sanitized(raw: &str) {}

fn main() {
    let raw: &str = "alice\r\nadmin";
    let owned: String = raw.to_string();
    let username = models::Username("alice".to_string());
    let cow = utils::sanitize_log_str(raw);

    // Violations: raw text at INFO+.
    tracing::warn!(username = %raw, "bad");
    tracing::warn!(username = %owned, "bad");
    tracing::warn!(username = raw, "plain form, still bad");
    tracing::info!(username = %raw, user_id = 3, "with another field");
    tracing::warn!(username = %raw);
    tracing::warn!(username = %cow, "stored Cow is not a sanitizer call");

    // OK: sanitized, validated newtype, DEBUG level.
    tracing::warn!(username = %utils::sanitize_log_str(raw), "sanitized");
    tracing::warn!(username = %username, "validated newtype");
    tracing::debug!(username = %raw, "debug is exempt");
    tracing::warn!(user_id = 3, "other fields untouched");

    span_raw(raw);
    span_sanitized(raw);
}
