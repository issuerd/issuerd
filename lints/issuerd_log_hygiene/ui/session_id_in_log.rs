// edition:2024
// `session_id_in_log`: session identifiers are DEBUG/TRACE at most, and
// never appear in `#[instrument(fields(...))]` span fields.

#![feature(register_tool)]
#![register_tool(tracing)]
#![allow(dead_code)]

macro_rules! trace { ($($tt:tt)*) => {} }
macro_rules! debug { ($($tt:tt)*) => {} }
macro_rules! info { ($($tt:tt)*) => {} }
macro_rules! warn { ($($tt:tt)*) => {} }
macro_rules! error { ($($tt:tt)*) => {} }

fn main() {
    let sid = "s1";

    // Violations at INFO and above.
    info!(session_id = "abc", "login");
    warn!(sid = %sid, "refresh");
    error!(session_id = ?sid, "lookup failed");

    // OK at DEBUG/TRACE.
    debug!(session_id = %sid, "validated");
    trace!(sid = "s1", "validated");
    info!(session_count = 3, "metadata suffix is exempt");
}

// Violations: span fields never carry session identifiers, at any level.
#[tracing::instrument(fields(session_id = "abc"))]
fn span_session() {}

#[tracing::instrument(skip_all, fields(sid = "s1"))]
fn span_sid() {}

// OK: no session identifier in the span fields.
#[tracing::instrument(skip_all, fields(realm = "r"))]
fn span_clean() {}
