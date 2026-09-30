// edition:2024
// `tracing_error_debug`: error/err fields must use the `%` (Display) sigil.

// Dummy no-op level macros: the lints are syntax-only and never expand these.
macro_rules! trace { ($($tt:tt)*) => {} }
macro_rules! debug { ($($tt:tt)*) => {} }
macro_rules! info { ($($tt:tt)*) => {} }
macro_rules! warn { ($($tt:tt)*) => {} }
macro_rules! error { ($($tt:tt)*) => {} }

fn main() {
    let e = std::io::Error::other("boom");
    let err = std::io::Error::other("boom");

    // Violations (any level).
    error!(error = ?e, "failed");
    error!(err = ?e, "failed");
    warn!(error = ?e, "failed");
    debug!(err = ?e, "failed");
    trace!(error = ?e);
    error!(target: "issuerd", error = ?e, "failed");
    error!(?err, "failed");

    // OK: the Display sigil, `?` on fields not named error/err, plain
    // messages, shorthand without an error name.
    error!(error = %e, "failed");
    error!(err = %e, error = %e, "failed");
    warn!(roles = ?["a", "b"], "roles");
    debug!(?e, "shorthand is not named error");
    info!("just a message");
    error!(count = 3, "counted");
}
