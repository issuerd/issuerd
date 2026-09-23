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
