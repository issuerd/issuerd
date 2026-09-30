// edition:2024
// `secret_field_in_log`: secret-named fields are forbidden at any level,
// including `#[instrument(fields(...))]` span fields.

#![feature(register_tool)]
#![register_tool(tracing)]
#![allow(dead_code)]

macro_rules! trace { ($($tt:tt)*) => {} }
macro_rules! debug { ($($tt:tt)*) => {} }
macro_rules! info { ($($tt:tt)*) => {} }
macro_rules! warn { ($($tt:tt)*) => {} }
macro_rules! error { ($($tt:tt)*) => {} }

fn main() {
    let password = "hunter2";
    let token = "tok";

    // Violations (any level).
    info!(password = %password, "login");
    warn!(client_secret = "s3cr3t", "client");
    debug!(token = %token, "issued");
    trace!(code = "123456", "mailed");
    error!(?password, "failed");
    warn!(password, "shorthand");
    info!(dpop_proof = "proof", "bound");
    info!(authorization = "Basic x", "header");
    info!(cookie = "session=..", "header");

    // OK: metadata about secrets carries the exempt suffixes, and the
    // OAuth-vocabulary compounds of `token`/`code`/`authorization` are not
    // secrets.
    info!(token_type = "Bearer", "issued");
    info!(token_hash = "h", "stored");
    info!(token_roles = "admin", "not a secret");
    info!(code_challenge = "ch", "PKCE challenge is public");
    info!(authorization_details = "[]", "RAR echo");
    info!(password_len = 8, "policy");
    info!(otp_count = 2, "attempts");
    info!(session_id = "s", "not a secret-name rule");
    info!(user_id = "u", "fine");
}

// Violations in span fields.
#[tracing::instrument(fields(secret = "x"))]
fn span_secret() {}

#[tracing::instrument(fields(token = %token))]
fn span_token(token: &str) {
    let _ = token;
}

// OK: exempt suffix in a span field.
#[tracing::instrument(skip_all, fields(access_token_hash = "h"))]
fn span_ok() {}
