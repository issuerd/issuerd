// `secret_typed_value_in_log`: secret-typed values must never be recorded,
// under any field name, at any level. (Field names here are deliberately
// neutral — name-based rules are the early-pass lints' job.)

#![allow(dead_code)]

pub mod models {
    #[derive(Debug)]
    pub struct Password(pub String);
    impl std::fmt::Display for Password {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Password(..)")
        }
    }

    #[derive(Debug)]
    pub struct Credential {
        pub secret_data: Vec<u8>,
    }

    #[derive(Debug)]
    pub struct SessionId(pub String);
    impl std::fmt::Display for SessionId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
}

fn main() {
    let password = models::Password("hunter2".to_string());
    let credential = models::Credential {
        secret_data: vec![1, 2, 3],
    };
    let session = models::SessionId("s1".to_string());
    let password_ref = &password;

    // Violations: the value's type is on the secret list, under any name.
    tracing::info!(field = %password, "display form");
    tracing::info!(field = ?credential, "debug form");
    tracing::warn!(field = %password_ref, "through a reference");
    tracing::debug!(field = %password, "any level");

    // OK: metadata and non-secret types.
    tracing::warn!(field = %password.0.len(), "a length, not the secret");
    tracing::info!(field = %session, "not on the secret list");
    tracing::info!(field = "static string", "plain text");
    tracing::info!("message only");
}
