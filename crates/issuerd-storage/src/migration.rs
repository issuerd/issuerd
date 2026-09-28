// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Embedded SQLx migration runner.

use issuerd_core::IssuerdError;
use tracing::info;

/// Run embedded SQLx migrations.
pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), IssuerdError> {
    info!("running database schema migrations");
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| IssuerdError::ServerError(format!("migration failed: {e}")))?;
    info!("database schema migrations completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_migrations_surfaces_connection_failures() {
        // Nothing listens on 127.0.0.1:1 and the pool connects lazily, so the
        // connection error must surface as an Err here — never be swallowed
        // as a fake Ok (a silent no-op migration run boots against an
        // unmigrated schema). The pool retries failed connects until
        // acquire_timeout — bound it so the refusal surfaces fast.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect_lazy("postgres://issuerd:issuerd@127.0.0.1:1/issuerd")
            .expect("lazy pool construction does not connect");
        let err = run_migrations(&pool).await.unwrap_err();
        assert!(matches!(err, IssuerdError::ServerError(_)));
    }
}
