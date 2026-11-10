// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// SQLite storage adapter (sqlx).

use async_trait::async_trait;
use issuerd_core::*;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    QueryBuilder, Sqlite, SqlitePool, Transaction,
};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{error, info, instrument};

use crate::db_types::*;
use crate::migration::SQLITE_BUSY;
use crate::sqlite_types::{SqliteConsent, SqliteUserSession};

#[cfg(unix)]
fn secure_owner_only(path: &Path) -> Result<(), IssuerdError> {
    use std::os::unix::fs::PermissionsExt;

    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            IssuerdError::ServerError(format!(
                "SQLite file metadata failed for {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(IssuerdError::InvalidRequest(format!(
                "SQLite path is not a regular file: {}",
                path.display()
            )));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                IssuerdError::ServerError(format!(
                    "SQLite permission hardening failed for {}: {error}",
                    path.display()
                ))
            },
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_owner_only(_path: &Path) -> Result<(), IssuerdError> {
    Ok(())
}

fn prepare_sqlite_file(path: &Path) -> Result<(), IssuerdError> {
    if !path.exists() {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if let Err(error) = options.open(path) {
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(IssuerdError::ServerError(format!(
                    "SQLite file creation failed for {}: {error}",
                    path.display()
                )));
            }
        }
    }
    secure_owner_only(path)
}

fn secure_sqlite_files(path: &Path) -> Result<(), IssuerdError> {
    secure_owner_only(path)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        secure_owner_only(Path::new(&sidecar))?;
    }
    Ok(())
}

macro_rules! retry_execute {
    ($pool:expr, $query:expr) => {{
        let mut failed_attempts = 0;
        loop {
            match $query.execute($pool).await.map_err(sqlx_err) {
                Err(error) if is_busy(&error) => {
                    failed_attempts += 1;
                    if failed_attempts == MAX_BUSY_ATTEMPTS {
                        break Err(IssuerdError::TemporarilyUnavailable);
                    }
                    tokio::time::sleep(Duration::from_millis(25_u64 << failed_attempts)).await;
                }
                result => break result,
            }
        }
    }};
}

macro_rules! retry_execute_tx {
    ($tx:expr, $query:expr) => {{
        let mut failed_attempts = 0;
        loop {
            match $query.execute(&mut *$tx).await.map_err(sqlx_err) {
                Err(error) if is_busy(&error) => {
                    failed_attempts += 1;
                    if failed_attempts == MAX_BUSY_ATTEMPTS {
                        break Err(IssuerdError::TemporarilyUnavailable);
                    }
                    tokio::time::sleep(Duration::from_millis(25_u64 << failed_attempts)).await;
                }
                result => break result,
            }
        }
    }};
}

/// Embedded, durable, single-node SQLite storage adapter.
pub struct SqliteStorage {
    pool: SqlitePool,
    path: PathBuf,
}

impl SqliteStorage {
    #[instrument(skip_all)]
    pub async fn connect(path: &Path) -> Result<Self, IssuerdError> {
        info!("connecting to SQLite");
        prepare_sqlite_file(path)?;
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        // WAL readers run concurrently; BEGIN IMMEDIATE and the busy timeout
        // serialize the single-writer paths without routine lock failures.
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(30))
            .connect_with(options)
            .await
            .map_err(|e| {
                error!(error = %e, "SQLite connection failed");
                IssuerdError::ServerError(format!("db connect failed: {e}"))
            })?;
        secure_sqlite_files(path)?;
        Ok(Self {
            pool,
            path: path.to_path_buf(),
        })
    }

    pub async fn run_migrations(&self) -> Result<(), IssuerdError> {
        with_busy_retry(|| crate::migration::run_sqlite_migrations(&self.pool)).await?;
        self.backfill_user_search_columns().await?;
        secure_sqlite_files(&self.path)?;
        let realms = self.list_realms(&Pagination::new(0, i32::MAX)).await?;
        for realm in realms {
            crate::seed::seed_builtin_client_scopes(self, &realm.id).await?;
            crate::seed::seed_builtin_flows(self, &realm.id).await?;
            crate::seed::backfill_pairwise_sector_key(self, &realm.id).await?;
            let clients = self.list_clients(&realm.id, &Pagination::new(0, i32::MAX)).await?;
            for client in clients {
                crate::seed::seed_client_scope_assignments(self, &realm.id, &client).await?;
            }
        }
        Ok(())
    }

    async fn backfill_user_search_columns(&self) -> Result<(), IssuerdError> {
        let users: Vec<(uuid::Uuid, uuid::Uuid, String, Option<String>)> =
            sqlx::query_as("SELECT id, realm_id, username, email FROM users")
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        for (id, realm_id, username, email) in users {
            retry_execute!(
                self.pool(),
                sqlx::query(
                    "UPDATE users SET username_search = ?2, email_search = ?3 \
                     WHERE id = ?1 AND realm_id = ?4 \
                       AND (username_search IS NOT ?2 OR email_search IS NOT ?3)",
                )
                .bind(id)
                .bind(username.to_lowercase())
                .bind(email.as_ref().map(|value| value.to_lowercase()))
                .bind(realm_id)
            )?;
        }
        Ok(())
    }

    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

const MAX_BUSY_ATTEMPTS: usize = 4;

fn is_busy(error: &IssuerdError) -> bool {
    matches!(error, IssuerdError::ServerError(message) if message == SQLITE_BUSY)
}

pub(crate) async fn with_busy_retry<F, Fut, T>(mut operation: F) -> Result<T, IssuerdError>
where
    F: FnMut() -> Fut + Send,
    Fut: std::future::Future<Output = Result<T, IssuerdError>> + Send,
{
    let mut failed_attempts = 0;
    loop {
        match operation().await {
            Err(error) if is_busy(&error) => {
                failed_attempts += 1;
                if failed_attempts == MAX_BUSY_ATTEMPTS {
                    return Err(IssuerdError::TemporarilyUnavailable);
                }
                tokio::time::sleep(Duration::from_millis(25_u64 << failed_attempts)).await;
            }
            result => return result,
        }
    }
}

pub(crate) async fn begin_immediate_with_retry(
    pool: &SqlitePool,
) -> Result<Transaction<'static, Sqlite>, IssuerdError> {
    with_busy_retry(|| async { pool.begin_with("BEGIN IMMEDIATE").await.map_err(sqlx_err) }).await
}

pub(crate) fn sqlx_err(e: sqlx::Error) -> IssuerdError {
    match e {
        sqlx::Error::Database(_) if crate::migration::is_sqlite_busy_error(&e) => {
            IssuerdError::ServerError(SQLITE_BUSY.into())
        }
        sqlx::Error::Database(ref db)
            if matches!(db.kind(), sqlx::error::ErrorKind::UniqueViolation) =>
        {
            IssuerdError::Conflict
        }
        sqlx::Error::Database(ref db)
            if matches!(
                db.kind(),
                sqlx::error::ErrorKind::ForeignKeyViolation
                    | sqlx::error::ErrorKind::NotNullViolation
                    | sqlx::error::ErrorKind::CheckViolation
            ) =>
        {
            IssuerdError::InvalidRequest(format!("database constraint violation: {db}"))
        }
        sqlx::Error::RowNotFound => IssuerdError::NotFound,
        _ => IssuerdError::ServerError(e.to_string()),
    }
}

fn to_uuid(id: &str) -> Result<uuid::Uuid, IssuerdError> {
    uuid::Uuid::parse_str(id)
        .map_err(|e| IssuerdError::InvalidRequest(format!("invalid uuid: {e}")))
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn close(&self) {
        self.pool.close().await;
    }

    // ------------------------------------------------------------------
    // Realm
    // ------------------------------------------------------------------
    async fn get_realm(&self, id: &RealmId) -> Result<Option<Realm>, IssuerdError> {
        let pg: Option<PgRealm> = sqlx::query_as("SELECT * FROM realms WHERE id = ?1")
            .bind(to_uuid(id.as_ref())?)
            .fetch_optional(self.pool())
            .await
            .map_err(sqlx_err)?;
        pg.map(|r| r.try_into()).transpose()
    }

    async fn get_realm_by_name(&self, name: &str) -> Result<Option<Realm>, IssuerdError> {
        let pg: Option<PgRealm> = sqlx::query_as("SELECT * FROM realms WHERE name = ?1")
            .bind(name)
            .fetch_optional(self.pool())
            .await
            .map_err(sqlx_err)?;
        pg.map(|r| r.try_into()).transpose()
    }

    async fn list_realms(&self, pagination: &Pagination) -> Result<Vec<Realm>, IssuerdError> {
        let rows: Vec<PgRealm> =
            sqlx::query_as("SELECT * FROM realms ORDER BY name LIMIT ?1 OFFSET ?2")
                .bind(pagination.max as i64)
                .bind(pagination.first as i64)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn count_realms(&self) -> Result<i64, IssuerdError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM realms")
            .fetch_one(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(count)
    }

    async fn create_realm(&self, realm: &Realm) -> Result<(), IssuerdError> {
        let mut realm = realm.clone();
        // Every realm carries a pairwise sector key from birth.
        crate::seed::ensure_realm_pairwise_sector_key(&mut realm);
        let pg: PgRealm = (&realm).try_into()?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO realms (
                id, name, display_name, enabled, ssl_required, password_policy,
                login_theme, email_theme, admin_theme, default_role,
                access_token_lifespan, refresh_token_lifespan,
                sso_session_idle_timeout, sso_session_max_lifespan,
                offline_session_idle_timeout,
                brute_force_protected, max_login_failures, wait_increment_secs,
                max_failure_wait_secs, lockout_duration_secs,
                registration_enabled, reset_password_allowed, remember_me_enabled,
                verify_email_enabled, login_with_email_allowed,
                duplicate_emails_allowed, edit_username_allowed,
                remember_me_session_idle_secs,
                otp_algorithm, otp_digits, otp_period_secs, otp_look_ahead_window,
                attributes,
                internationalization_enabled, supported_locales, default_locale,
                events_enabled, events_expiration_secs, admin_events_enabled,
                include_representations, events_listeners, not_before, default_groups,
                browser_flow, direct_grant_flow, reset_credentials_flow,
                first_broker_login_flow, registration_flow
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38,
                ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48
            )"#,
            )
            .bind(pg.id)
            .bind(&pg.name)
            .bind(&pg.display_name)
            .bind(pg.enabled)
            .bind(&pg.ssl_required)
            .bind(&pg.password_policy)
            .bind(&pg.login_theme)
            .bind(&pg.email_theme)
            .bind(&pg.admin_theme)
            .bind(&pg.default_role)
            .bind(pg.access_token_lifespan)
            .bind(pg.refresh_token_lifespan)
            .bind(pg.sso_session_idle_timeout)
            .bind(pg.sso_session_max_lifespan)
            .bind(pg.offline_session_idle_timeout)
            .bind(pg.brute_force_protected)
            .bind(pg.max_login_failures)
            .bind(pg.wait_increment_secs)
            .bind(pg.max_failure_wait_secs)
            .bind(pg.lockout_duration_secs)
            .bind(pg.registration_enabled)
            .bind(pg.reset_password_allowed)
            .bind(pg.remember_me_enabled)
            .bind(pg.verify_email_enabled)
            .bind(pg.login_with_email_allowed)
            .bind(pg.duplicate_emails_allowed)
            .bind(pg.edit_username_allowed)
            .bind(pg.remember_me_session_idle_secs)
            .bind(&pg.otp_algorithm)
            .bind(pg.otp_digits)
            .bind(pg.otp_period_secs)
            .bind(pg.otp_look_ahead_window)
            .bind(&pg.attributes)
            .bind(pg.internationalization_enabled)
            .bind(&pg.supported_locales)
            .bind(&pg.default_locale)
            .bind(pg.events_enabled)
            .bind(pg.events_expiration_secs)
            .bind(pg.admin_events_enabled)
            .bind(pg.include_representations)
            .bind(&pg.events_listeners)
            .bind(pg.not_before)
            .bind(&pg.default_groups)
            .bind(&pg.browser_flow)
            .bind(&pg.direct_grant_flow)
            .bind(&pg.reset_credentials_flow)
            .bind(&pg.first_broker_login_flow)
            .bind(&pg.registration_flow)
        )?;
        // Every realm carries the built-in client scopes (and the
        // realm default scope sets) from birth, on every backend.
        crate::seed::seed_builtin_client_scopes(self, &realm.id).await?;
        // Every realm also carries the built-in browser and
        // registration flows from birth (idempotent).
        crate::seed::seed_builtin_flows(self, &realm.id).await?;
        Ok(())
    }

    async fn update_realm(&self, realm: &Realm) -> Result<(), IssuerdError> {
        let pg: PgRealm = realm.try_into()?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE realms SET
                name = ?2, display_name = ?3, enabled = ?4, ssl_required = ?5,
                password_policy = ?6, login_theme = ?7, email_theme = ?8,
                admin_theme = ?9, default_role = ?10,
                access_token_lifespan = ?11, refresh_token_lifespan = ?12,
                sso_session_idle_timeout = ?13, sso_session_max_lifespan = ?14,
                offline_session_idle_timeout = ?15,
                brute_force_protected = ?16, max_login_failures = ?17,
                wait_increment_secs = ?18, max_failure_wait_secs = ?19,
                lockout_duration_secs = ?20,
                registration_enabled = ?21, reset_password_allowed = ?22,
                remember_me_enabled = ?23, verify_email_enabled = ?24,
                login_with_email_allowed = ?25, duplicate_emails_allowed = ?26,
                edit_username_allowed = ?27,
                remember_me_session_idle_secs = ?28,
                otp_algorithm = ?29, otp_digits = ?30,
                otp_period_secs = ?31, otp_look_ahead_window = ?32,
                attributes = ?33,
                internationalization_enabled = ?34, supported_locales = ?35,
                default_locale = ?36,
                events_enabled = ?37, events_expiration_secs = ?38,
                admin_events_enabled = ?39, include_representations = ?40,
                events_listeners = ?41, not_before = ?42, default_groups = ?43,
                browser_flow = ?44, direct_grant_flow = ?45,
                reset_credentials_flow = ?46, first_broker_login_flow = ?47,
                registration_flow = ?48,
                updated_at = strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')
            WHERE id = ?1"#,
            )
            .bind(pg.id)
            .bind(&pg.name)
            .bind(&pg.display_name)
            .bind(pg.enabled)
            .bind(&pg.ssl_required)
            .bind(&pg.password_policy)
            .bind(&pg.login_theme)
            .bind(&pg.email_theme)
            .bind(&pg.admin_theme)
            .bind(&pg.default_role)
            .bind(pg.access_token_lifespan)
            .bind(pg.refresh_token_lifespan)
            .bind(pg.sso_session_idle_timeout)
            .bind(pg.sso_session_max_lifespan)
            .bind(pg.offline_session_idle_timeout)
            .bind(pg.brute_force_protected)
            .bind(pg.max_login_failures)
            .bind(pg.wait_increment_secs)
            .bind(pg.max_failure_wait_secs)
            .bind(pg.lockout_duration_secs)
            .bind(pg.registration_enabled)
            .bind(pg.reset_password_allowed)
            .bind(pg.remember_me_enabled)
            .bind(pg.verify_email_enabled)
            .bind(pg.login_with_email_allowed)
            .bind(pg.duplicate_emails_allowed)
            .bind(pg.edit_username_allowed)
            .bind(pg.remember_me_session_idle_secs)
            .bind(&pg.otp_algorithm)
            .bind(pg.otp_digits)
            .bind(pg.otp_period_secs)
            .bind(pg.otp_look_ahead_window)
            .bind(&pg.attributes)
            .bind(pg.internationalization_enabled)
            .bind(&pg.supported_locales)
            .bind(&pg.default_locale)
            .bind(pg.events_enabled)
            .bind(pg.events_expiration_secs)
            .bind(pg.admin_events_enabled)
            .bind(pg.include_representations)
            .bind(&pg.events_listeners)
            .bind(pg.not_before)
            .bind(&pg.default_groups)
            .bind(&pg.browser_flow)
            .bind(&pg.direct_grant_flow)
            .bind(&pg.reset_credentials_flow)
            .bind(&pg.first_broker_login_flow)
            .bind(&pg.registration_flow)
        )?;

        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_realm(&self, id: &RealmId) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM realms WHERE id = ?1").bind(to_uuid(id.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // User
    // ------------------------------------------------------------------
    async fn get_user(&self, realm: &RealmId, id: &UserId) -> Result<Option<User>, IssuerdError> {
        let pg: Option<PgUser> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|u| u.try_into()).transpose()
    }

    async fn get_user_by_username(
        &self,
        realm: &RealmId,
        username: &str,
    ) -> Result<Option<User>, IssuerdError> {
        let pg: Option<PgUser> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = ?1 AND username = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(username)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|u| u.try_into()).transpose()
    }

    async fn get_user_by_email(
        &self,
        realm: &RealmId,
        email: &str,
    ) -> Result<Option<User>, IssuerdError> {
        let pg: Option<PgUser> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = ?1 AND email = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(email)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|u| u.try_into()).transpose()
    }

    async fn get_user_by_federation_link(
        &self,
        realm: &RealmId,
        link: &str,
    ) -> Result<Vec<User>, IssuerdError> {
        let rows: Vec<PgUser> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = ?1 AND federation_link = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(link)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        rows.into_iter().map(|u| u.try_into()).collect()
    }

    async fn list_users(
        &self,
        realm: &RealmId,
        query: &str,
        pagination: &Pagination,
    ) -> Result<Vec<User>, IssuerdError> {
        let pattern = if query.is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.to_lowercase())
        };
        let rows: Vec<PgUser> = sqlx::query_as(
            "SELECT * FROM users WHERE realm_id = ?1 AND (username_search LIKE ?2 OR email_search LIKE ?2) ORDER BY username LIMIT ?3 OFFSET ?4",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(&pattern)
        .bind(pagination.max as i64)
        .bind(pagination.first as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|u| u.try_into()).collect()
    }

    async fn count_users(&self, realm: &RealmId, query: &str) -> Result<i64, IssuerdError> {
        let pattern = if query.is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.to_lowercase())
        };
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE realm_id = ?1 AND (username_search LIKE ?2 OR email_search LIKE ?2)",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(&pattern)
        .fetch_one(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(count)
    }

    async fn create_user(&self, realm: &RealmId, user: &User) -> Result<(), IssuerdError> {
        let mut pg: PgUser = user.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO users (
                id, realm_id, username, email, email_verified,
                first_name, last_name, enabled, federation_link, attributes,
                required_actions, updated_at, username_search, email_search
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"#,
            )
            .bind(pg.id)
            .bind(pg.realm_id)
            .bind(&pg.username)
            .bind(&pg.email)
            .bind(pg.email_verified)
            .bind(&pg.first_name)
            .bind(&pg.last_name)
            .bind(pg.enabled)
            .bind(&pg.federation_link)
            .bind(&pg.attributes)
            .bind(&pg.required_actions)
            .bind(pg.created_at)
            .bind(pg.username.to_lowercase())
            .bind(pg.email.as_ref().map(|value| value.to_lowercase()))
        )?;
        Ok(())
    }

    async fn bulk_create_users(&self, realm: &RealmId, users: &[User]) -> Result<(), IssuerdError> {
        if users.is_empty() {
            return Ok(());
        }
        let realm_uuid = to_uuid(realm.as_ref())?;
        let mut rows = Vec::with_capacity(users.len());
        for user in users {
            let mut pg: PgUser = user.try_into()?;
            pg.realm_id = realm_uuid;
            rows.push(pg);
        }

        let mut tx = begin_immediate_with_retry(self.pool()).await?;
        for chunk in rows.chunks(50) {
            let mut query = QueryBuilder::<Sqlite>::new(
                "INSERT INTO users (\
                    id, realm_id, username, email, email_verified, first_name, last_name, \
                    enabled, federation_link, attributes, required_actions, updated_at, \
                    username_search, email_search\
                ) ",
            );
            query.push_values(chunk, |mut values, pg| {
                values
                    .push_bind(pg.id)
                    .push_bind(pg.realm_id)
                    .push_bind(&pg.username)
                    .push_bind(&pg.email)
                    .push_bind(pg.email_verified)
                    .push_bind(&pg.first_name)
                    .push_bind(&pg.last_name)
                    .push_bind(pg.enabled)
                    .push_bind(&pg.federation_link)
                    .push_bind(&pg.attributes)
                    .push_bind(&pg.required_actions)
                    .push_bind(pg.created_at)
                    .push_bind(pg.username.to_lowercase())
                    .push_bind(pg.email.as_ref().map(|value| value.to_lowercase()));
            });
            retry_execute_tx!(tx, query.build())?;
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_user(&self, realm: &RealmId, user: &User) -> Result<(), IssuerdError> {
        let pg: PgUser = user.try_into()?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE users SET
                username = ?3, email = ?4, email_verified = ?5,
                first_name = ?6, last_name = ?7, enabled = ?8,
                federation_link = ?9, attributes = ?10, required_actions = ?11,
                updated_at = strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now'),
                username_search = ?12, email_search = ?13
            WHERE realm_id = ?1 AND id = ?2"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(pg.id)
            .bind(&pg.username)
            .bind(&pg.email)
            .bind(pg.email_verified)
            .bind(&pg.first_name)
            .bind(&pg.last_name)
            .bind(pg.enabled)
            .bind(&pg.federation_link)
            .bind(&pg.attributes)
            .bind(&pg.required_actions)
            .bind(pg.username.to_lowercase())
            .bind(pg.email.as_ref().map(|value| value.to_lowercase()))
        )?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_user(&self, realm: &RealmId, id: &UserId) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM users WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Client
    // ------------------------------------------------------------------
    async fn get_client(
        &self,
        realm: &RealmId,
        id: &ClientId,
    ) -> Result<Option<Client>, IssuerdError> {
        let pg: Option<PgClient> =
            sqlx::query_as("SELECT * FROM clients WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|c| c.try_into()).transpose()
    }

    async fn get_client_by_client_id(
        &self,
        realm: &RealmId,
        client_id: &ClientIdentifier,
    ) -> Result<Option<Client>, IssuerdError> {
        let pg: Option<PgClient> =
            sqlx::query_as("SELECT * FROM clients WHERE realm_id = ?1 AND client_id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(client_id.as_str())
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|c| c.try_into()).transpose()
    }

    async fn get_clients_batch(
        &self,
        realm: &RealmId,
        ids: &[ClientId],
    ) -> Result<Vec<Client>, IssuerdError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let realm_uuid = to_uuid(realm.as_ref())?;
        let uuids = ids.iter().map(|id| to_uuid(id.as_ref())).collect::<Result<Vec<_>, _>>()?;
        let mut rows = Vec::new();
        for chunk in uuids.chunks(500) {
            let mut query = QueryBuilder::<Sqlite>::new("SELECT * FROM clients WHERE realm_id = ");
            query.push_bind(realm_uuid).push(" AND id IN (");
            let mut values = query.separated(", ");
            for id in chunk {
                values.push_bind(id);
            }
            values.push_unseparated(")");
            rows.extend(
                query
                    .build_query_as::<PgClient>()
                    .fetch_all(self.pool())
                    .await
                    .map_err(sqlx_err)?,
            );
        }
        let clients: Vec<Client> =
            rows.into_iter().map(|c| c.try_into()).collect::<Result<_, _>>()?;
        // IN does not preserve input order; restore it in Rust (unknown ids
        // are absent from the result set and get skipped).
        let by_id: std::collections::HashMap<String, Client> =
            clients.into_iter().map(|c| (c.id.to_string(), c)).collect();
        Ok(ids.iter().filter_map(|id| by_id.get(id.as_ref()).cloned()).collect())
    }

    async fn list_clients(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Client>, IssuerdError> {
        let rows: Vec<PgClient> = sqlx::query_as(
            "SELECT * FROM clients WHERE realm_id = ?1 ORDER BY client_id LIMIT ?2 OFFSET ?3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(pagination.max as i64)
        .bind(pagination.first as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|c| c.try_into()).collect()
    }

    async fn count_clients(&self, realm: &RealmId) -> Result<i64, IssuerdError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM clients WHERE realm_id = ?1")
            .bind(to_uuid(realm.as_ref())?)
            .fetch_one(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(count)
    }

    async fn create_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError> {
        let mut pg: PgClient = client.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        retry_execute!(self.pool(), sqlx::query(
            r#"INSERT INTO clients (
                id, realm_id, client_id, name, description, enabled, protocol,
                public_client, bearer_only, client_authenticator_type, secret,
                redirect_uris, web_origins, default_scopes, optional_scopes,
                consent_required, full_scope_allowed, service_accounts_enabled,
                protocol_mappers, scope_mappings, attributes
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)"#,
        )
        .bind(pg.id)
        .bind(pg.realm_id)
        .bind(&pg.client_id)
        .bind(&pg.name)
        .bind(&pg.description)
        .bind(pg.enabled)
        .bind(&pg.protocol)
        .bind(pg.public_client)
        .bind(pg.bearer_only)
        .bind(&pg.client_authenticator_type)
        .bind(&pg.secret)
        .bind(&pg.redirect_uris)
        .bind(&pg.web_origins)
        .bind(&pg.default_scopes)
        .bind(&pg.optional_scopes)
        .bind(pg.consent_required)
        .bind(pg.full_scope_allowed)
        .bind(pg.service_accounts_enabled)
        .bind(&pg.protocol_mappers)
        .bind(&pg.scope_mappings)
        .bind(&pg.attributes)
        )?;
        // Seed scope assignments from the client's legacy
        // default/optional scope string lists (plus the `roles` carve-out).
        crate::seed::seed_client_scope_assignments(self, realm, client).await?;
        Ok(())
    }

    async fn update_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError> {
        let pg: PgClient = client.try_into()?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE clients SET
                client_id = ?3, name = ?4, description = ?5, enabled = ?6,
                protocol = ?7, public_client = ?8, bearer_only = ?9,
                client_authenticator_type = ?10, secret = ?11,
                redirect_uris = ?12, web_origins = ?13, default_scopes = ?14,
                optional_scopes = ?15, consent_required = ?16,
                full_scope_allowed = ?17, service_accounts_enabled = ?18,
                protocol_mappers = ?19, scope_mappings = ?20, attributes = ?21
            WHERE realm_id = ?1 AND id = ?2"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(pg.id)
            .bind(&pg.client_id)
            .bind(&pg.name)
            .bind(&pg.description)
            .bind(pg.enabled)
            .bind(&pg.protocol)
            .bind(pg.public_client)
            .bind(pg.bearer_only)
            .bind(&pg.client_authenticator_type)
            .bind(&pg.secret)
            .bind(&pg.redirect_uris)
            .bind(&pg.web_origins)
            .bind(&pg.default_scopes)
            .bind(&pg.optional_scopes)
            .bind(pg.consent_required)
            .bind(pg.full_scope_allowed)
            .bind(pg.service_accounts_enabled)
            .bind(&pg.protocol_mappers)
            .bind(&pg.scope_mappings)
            .bind(&pg.attributes)
        )?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_client(&self, realm: &RealmId, id: &ClientId) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM clients WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Credentials
    // ------------------------------------------------------------------
    async fn get_credentials(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred_type: CredentialType,
    ) -> Result<Vec<Credential>, IssuerdError> {
        let type_str = serde_json::to_string(&cred_type)
            .map_err(|e| IssuerdError::ServerError(format!("json error: {e}")))?
            .trim_matches('"')
            .to_string();
        let rows: Vec<PgCredential> = sqlx::query_as(
            "SELECT * FROM credentials WHERE realm_id = ?1 AND user_id = ?2 AND credential_type = ?3 ORDER BY priority",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(&type_str)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|c| c.try_into()).collect()
    }

    async fn list_credentials(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<Credential>, IssuerdError> {
        let rows: Vec<PgCredential> = sqlx::query_as(
            "SELECT * FROM credentials WHERE realm_id = ?1 AND user_id = ?2 ORDER BY credential_type, priority",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|c| c.try_into()).collect()
    }

    async fn create_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred: &Credential,
    ) -> Result<(), IssuerdError> {
        let mut pg: PgCredential = cred.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        pg.user_id = to_uuid(user.as_ref())?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO credentials (
                id, realm_id, user_id, credential_type, user_label, created_date,
                secret_data, credential_data, priority
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
            )
            .bind(pg.id)
            .bind(pg.realm_id)
            .bind(pg.user_id)
            .bind(&pg.credential_type)
            .bind(&pg.user_label)
            .bind(pg.created_date)
            .bind(&pg.secret_data)
            .bind(&pg.credential_data)
            .bind(pg.priority)
        )?;
        Ok(())
    }

    async fn update_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred: &Credential,
    ) -> Result<(), IssuerdError> {
        let pg: PgCredential = cred.try_into()?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE credentials SET
                credential_type = ?4, user_label = ?5, created_date = ?6,
                secret_data = ?7, credential_data = ?8, priority = ?9
            WHERE realm_id = ?1 AND user_id = ?2 AND id = ?3"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(user.as_ref())?)
            .bind(pg.id)
            .bind(&pg.credential_type)
            .bind(&pg.user_label)
            .bind(pg.created_date)
            .bind(&pg.secret_data)
            .bind(&pg.credential_data)
            .bind(pg.priority)
        )?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn consume_totp_step(
        &self,
        realm: &RealmId,
        user: &UserId,
        credential_id: &CredentialId,
        matched_step: u64,
    ) -> Result<bool, IssuerdError> {
        let matched_step = i64::try_from(matched_step)
            .map_err(|_| IssuerdError::InvalidRequest("TOTP step is out of range".into()))?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE credentials
            SET credential_data = json_set(
                COALESCE(credential_data, '{}'), '$.last_used_step', ?
            )
            WHERE realm_id = ? AND user_id = ? AND id = ?
                AND credential_type = 'totp'
                AND COALESCE(
                    CAST(json_extract(credential_data, '$.last_used_step') AS INTEGER), 0
                ) < ?"#,
            )
            .bind(matched_step)
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(user.as_ref())?)
            .bind(to_uuid(credential_id.as_ref())?)
            .bind(matched_step)
        )?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred_id: &CredentialId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM credentials WHERE realm_id = ?1 AND user_id = ?2 AND id = ?3")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(user.as_ref())?)
                .bind(to_uuid(cred_id.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------
    async fn get_user_session(
        &self,
        realm: &RealmId,
        id: &SessionId,
    ) -> Result<Option<UserSession>, IssuerdError> {
        let pg: Option<SqliteUserSession> =
            sqlx::query_as("SELECT * FROM user_sessions WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;

        let mut session: UserSession = match pg {
            Some(s) => s.try_into()?,
            None => return Ok(None),
        };

        let clients: Vec<PgClientSession> =
            sqlx::query_as("SELECT * FROM client_sessions WHERE session_id = ?1")
                .bind(to_uuid(id.as_ref())?)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        session.clients =
            clients.into_iter().map(|c| c.try_into()).collect::<Result<Vec<_>, _>>()?;
        Ok(Some(session))
    }

    async fn list_sessions(
        &self,
        realm: &RealmId,
        user: Option<UserId>,
        pagination: &Pagination,
    ) -> Result<Vec<UserSession>, IssuerdError> {
        let user_id_opt = user.map(|u| to_uuid(u.as_ref())).transpose()?;
        let rows: Vec<SqliteUserSession> = sqlx::query_as(
            r#"SELECT * FROM user_sessions
               WHERE realm_id = ?1
                 AND (?2 IS NULL OR user_id = ?2)
               ORDER BY last_session_refresh DESC
               LIMIT ?3 OFFSET ?4"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(user_id_opt)
        .bind(pagination.max as i64)
        .bind(pagination.first as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;

        let mut sessions: Vec<UserSession> = Vec::new();
        let mut session_ids = Vec::new();
        for pg in rows {
            let id = pg.id;
            sessions.push(pg.try_into()?);
            session_ids.push(id);
        }

        if !session_ids.is_empty() {
            let mut clients = Vec::new();
            for chunk in session_ids.chunks(500) {
                let mut query = QueryBuilder::<Sqlite>::new(
                    "SELECT * FROM client_sessions WHERE session_id IN (",
                );
                let mut values = query.separated(", ");
                for id in chunk {
                    values.push_bind(id);
                }
                values.push_unseparated(")");
                clients.extend(
                    query
                        .build_query_as::<PgClientSession>()
                        .fetch_all(self.pool())
                        .await
                        .map_err(sqlx_err)?,
                );
            }

            for client_pg in clients {
                let cs: ClientSession = client_pg.try_into()?;
                if let Some(session) = sessions.iter_mut().find(|s| s.id == cs.session_id) {
                    session.clients.push(cs);
                }
            }
        }

        Ok(sessions)
    }

    async fn count_sessions(
        &self,
        realm: &RealmId,
        user: Option<UserId>,
    ) -> Result<i64, IssuerdError> {
        let user_id_opt = user.map(|u| to_uuid(u.as_ref())).transpose()?;
        let count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM user_sessions
               WHERE realm_id = ?1
                 AND (?2 IS NULL OR user_id = ?2)"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(user_id_opt)
        .fetch_one(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(count)
    }

    async fn create_user_session(
        &self,
        realm: &RealmId,
        session: &UserSession,
    ) -> Result<(), IssuerdError> {
        let mut txn = begin_immediate_with_retry(self.pool()).await?;
        let pg: SqliteUserSession = session.try_into()?;

        retry_execute_tx!(
            txn,
            sqlx::query(
                r#"INSERT INTO user_sessions (
                id, realm_id, user_id, login_username, ip_address,
                auth_method, remember_me, offline, started, last_session_refresh, auth_time,
                impersonator
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
            )
            .bind(pg.id)
            .bind(to_uuid(realm.as_ref())?)
            .bind(pg.user_id)
            .bind(&pg.login_username)
            .bind(&pg.ip_address)
            .bind(&pg.auth_method)
            .bind(pg.remember_me)
            .bind(pg.offline)
            .bind(pg.started)
            .bind(pg.last_session_refresh)
            .bind(pg.auth_time)
            .bind(pg.impersonator)
        )?;

        for client_session in &session.clients {
            let cs: PgClientSession = client_session.try_into()?;
            retry_execute_tx!(
                txn,
                sqlx::query(
                    r#"INSERT INTO client_sessions (
                    id, client_id, session_id, redirect_uri, state, auth_method, timestamp
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                )
                .bind(cs.id)
                .bind(cs.client_id)
                .bind(cs.session_id)
                .bind(&cs.redirect_uri)
                .bind(&cs.state)
                .bind(&cs.auth_method)
                .bind(cs.timestamp)
            )?;
        }

        txn.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_user_session(
        &self,
        realm: &RealmId,
        session: &UserSession,
    ) -> Result<(), IssuerdError> {
        let mut txn = begin_immediate_with_retry(self.pool()).await?;
        let pg: SqliteUserSession = session.try_into()?;

        let result = retry_execute_tx!(
            txn,
            sqlx::query(
                r#"UPDATE user_sessions SET
                user_id = ?3, login_username = ?4, ip_address = ?5,
                auth_method = ?6, remember_me = ?7, offline = ?8,
                started = ?9, last_session_refresh = ?10, auth_time = ?11,
                impersonator = ?12
            WHERE realm_id = ?1 AND id = ?2"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(pg.id)
            .bind(pg.user_id)
            .bind(&pg.login_username)
            .bind(&pg.ip_address)
            .bind(&pg.auth_method)
            .bind(pg.remember_me)
            .bind(pg.offline)
            .bind(pg.started)
            .bind(pg.last_session_refresh)
            .bind(pg.auth_time)
            .bind(pg.impersonator)
        )?;

        if result.rows_affected() == 0 {
            txn.rollback().await.map_err(sqlx_err)?;
            return Err(IssuerdError::NotFound);
        }

        retry_execute_tx!(
            txn,
            sqlx::query("DELETE FROM client_sessions WHERE session_id = ?1").bind(pg.id)
        )?;

        for client_session in &session.clients {
            let cs: PgClientSession = client_session.try_into()?;
            retry_execute_tx!(
                txn,
                sqlx::query(
                    r#"INSERT INTO client_sessions (
                    id, client_id, session_id, redirect_uri, state, auth_method, timestamp
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                )
                .bind(cs.id)
                .bind(cs.client_id)
                .bind(cs.session_id)
                .bind(&cs.redirect_uri)
                .bind(&cs.state)
                .bind(&cs.auth_method)
                .bind(cs.timestamp)
            )?;
        }

        txn.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_user_session(
        &self,
        realm: &RealmId,
        id: &SessionId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM user_sessions WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Roles
    // ------------------------------------------------------------------
    async fn get_role(&self, realm: &RealmId, id: &RoleId) -> Result<Option<Role>, IssuerdError> {
        let pg: Option<PgRole> =
            sqlx::query_as("SELECT * FROM roles WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|r| r.try_into()).transpose()
    }

    async fn get_role_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<Role>, IssuerdError> {
        // A realm role (client_role = false) wins over same-named client
        // roles; client roles are addressed via `get_client_role_by_name`.
        let pg: Option<PgRole> = sqlx::query_as(
            "SELECT * FROM roles WHERE realm_id = ?1 AND name = ?2 \
             ORDER BY client_role ASC, id LIMIT 1",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(name)
        .fetch_optional(self.pool())
        .await
        .map_err(sqlx_err)?;
        pg.map(|r| r.try_into()).transpose()
    }

    async fn list_roles(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Role>, IssuerdError> {
        let rows: Vec<PgRole> = sqlx::query_as(
            "SELECT * FROM roles WHERE realm_id = ?1 ORDER BY name LIMIT ?2 OFFSET ?3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(pagination.max as i64)
        .bind(pagination.first as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn count_roles(&self, realm: &RealmId) -> Result<i64, IssuerdError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE realm_id = ?1")
            .bind(to_uuid(realm.as_ref())?)
            .fetch_one(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(count)
    }

    async fn create_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError> {
        let mut pg: PgRole = role.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO roles (
                id, name, description, realm_id, client_role, client_id,
                composite, composites, attributes
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
            )
            .bind(pg.id)
            .bind(&pg.name)
            .bind(&pg.description)
            .bind(pg.realm_id)
            .bind(pg.client_role)
            .bind(pg.client_id)
            .bind(pg.composite)
            .bind(&pg.composites)
            .bind(&pg.attributes)
        )?;
        Ok(())
    }

    async fn update_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError> {
        let pg: PgRole = role.try_into()?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE roles SET
                name = ?3, description = ?4, client_role = ?5, client_id = ?6,
                composite = ?7, composites = ?8, attributes = ?9
            WHERE realm_id = ?1 AND id = ?2"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(pg.id)
            .bind(&pg.name)
            .bind(&pg.description)
            .bind(pg.client_role)
            .bind(pg.client_id)
            .bind(pg.composite)
            .bind(&pg.composites)
            .bind(&pg.attributes)
        )?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_role(&self, realm: &RealmId, id: &RoleId) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM roles WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Client roles (roles rows with `client_id` set)
    // ------------------------------------------------------------------
    async fn get_client_role_by_name(
        &self,
        realm: &RealmId,
        client: &ClientId,
        name: &str,
    ) -> Result<Option<Role>, IssuerdError> {
        let pg: Option<PgRole> = sqlx::query_as(
            "SELECT * FROM roles WHERE realm_id = ?1 AND client_id = ?2 AND name = ?3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(client.as_ref())?)
        .bind(name)
        .fetch_optional(self.pool())
        .await
        .map_err(sqlx_err)?;
        pg.map(|r| r.try_into()).transpose()
    }

    async fn get_client_roles_by_names(
        &self,
        realm: &RealmId,
        client: &ClientId,
        names: &[String],
    ) -> Result<Vec<Role>, IssuerdError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let realm_uuid = to_uuid(realm.as_ref())?;
        let client_uuid = to_uuid(client.as_ref())?;
        let mut rows = Vec::new();
        for chunk in names.chunks(500) {
            let mut query = QueryBuilder::<Sqlite>::new("SELECT * FROM roles WHERE realm_id = ");
            query.push_bind(realm_uuid).push(" AND client_id = ");
            query.push_bind(client_uuid).push(" AND name IN (");
            let mut values = query.separated(", ");
            for name in chunk {
                values.push_bind(name);
            }
            values.push_unseparated(")");
            rows.extend(
                query
                    .build_query_as::<PgRole>()
                    .fetch_all(self.pool())
                    .await
                    .map_err(sqlx_err)?,
            );
        }
        let roles: Vec<Role> = rows.into_iter().map(|r| r.try_into()).collect::<Result<_, _>>()?;
        let by_name: std::collections::HashMap<String, Role> =
            roles.into_iter().map(|r| (r.name.to_string(), r)).collect();
        Ok(names.iter().filter_map(|n| by_name.get(n).cloned()).collect())
    }

    async fn list_client_roles(
        &self,
        realm: &RealmId,
        client: &ClientId,
        pagination: &Pagination,
    ) -> Result<Vec<Role>, IssuerdError> {
        let rows: Vec<PgRole> = sqlx::query_as(
            "SELECT * FROM roles WHERE realm_id = ?1 AND client_id = ?2 \
             ORDER BY name LIMIT ?3 OFFSET ?4",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(client.as_ref())?)
        .bind(pagination.max as i64)
        .bind(pagination.first as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    // ------------------------------------------------------------------
    // Client scopes
    // ------------------------------------------------------------------
    async fn get_client_scope(
        &self,
        realm: &RealmId,
        id: &ClientScopeId,
    ) -> Result<Option<ClientScope>, IssuerdError> {
        let pg: Option<PgClientScope> =
            sqlx::query_as("SELECT * FROM client_scopes WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|s| s.try_into()).transpose()
    }

    async fn get_client_scope_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<ClientScope>, IssuerdError> {
        let pg: Option<PgClientScope> =
            sqlx::query_as("SELECT * FROM client_scopes WHERE realm_id = ?1 AND name = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(name)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|s| s.try_into()).transpose()
    }

    async fn get_client_scopes_by_names(
        &self,
        realm: &RealmId,
        names: &[String],
    ) -> Result<Vec<ClientScope>, IssuerdError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let realm_uuid = to_uuid(realm.as_ref())?;
        let mut rows = Vec::new();
        for chunk in names.chunks(500) {
            let mut query =
                QueryBuilder::<Sqlite>::new("SELECT * FROM client_scopes WHERE realm_id = ");
            query.push_bind(realm_uuid).push(" AND name IN (");
            let mut values = query.separated(", ");
            for name in chunk {
                values.push_bind(name);
            }
            values.push_unseparated(")");
            rows.extend(
                query
                    .build_query_as::<PgClientScope>()
                    .fetch_all(self.pool())
                    .await
                    .map_err(sqlx_err)?,
            );
        }
        let scopes: Vec<ClientScope> =
            rows.into_iter().map(|s| s.try_into()).collect::<Result<_, _>>()?;
        let by_name: std::collections::HashMap<String, ClientScope> =
            scopes.into_iter().map(|s| (s.name.clone(), s)).collect();
        Ok(names.iter().filter_map(|n| by_name.get(n).cloned()).collect())
    }

    async fn get_client_scopes_by_ids(
        &self,
        realm: &RealmId,
        ids: &[ClientScopeId],
    ) -> Result<Vec<ClientScope>, IssuerdError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let realm_uuid = to_uuid(realm.as_ref())?;
        let uuids = ids.iter().map(|id| to_uuid(id.as_ref())).collect::<Result<Vec<_>, _>>()?;
        let mut rows = Vec::new();
        for chunk in uuids.chunks(500) {
            let mut query =
                QueryBuilder::<Sqlite>::new("SELECT * FROM client_scopes WHERE realm_id = ");
            query.push_bind(realm_uuid).push(" AND id IN (");
            let mut values = query.separated(", ");
            for id in chunk {
                values.push_bind(id);
            }
            values.push_unseparated(")");
            rows.extend(
                query
                    .build_query_as::<PgClientScope>()
                    .fetch_all(self.pool())
                    .await
                    .map_err(sqlx_err)?,
            );
        }
        let scopes: Vec<ClientScope> =
            rows.into_iter().map(|s| s.try_into()).collect::<Result<_, _>>()?;
        let by_id: std::collections::HashMap<String, ClientScope> =
            scopes.into_iter().map(|s| (s.id.to_string(), s)).collect();
        Ok(ids.iter().filter_map(|id| by_id.get(id.as_ref()).cloned()).collect())
    }

    async fn list_client_scopes(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<ClientScope>, IssuerdError> {
        let rows: Vec<PgClientScope> = sqlx::query_as(
            "SELECT * FROM client_scopes WHERE realm_id = ?1 ORDER BY name LIMIT ?2 OFFSET ?3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(pagination.max as i64)
        .bind(pagination.first as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|s| s.try_into()).collect()
    }

    async fn create_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScope,
    ) -> Result<(), IssuerdError> {
        let mut pg: PgClientScope = scope.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO client_scopes (
                id, realm_id, name, description, protocol,
                attributes, protocol_mappers, scope_mappings
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            )
            .bind(pg.id)
            .bind(pg.realm_id)
            .bind(&pg.name)
            .bind(&pg.description)
            .bind(&pg.protocol)
            .bind(&pg.attributes)
            .bind(&pg.protocol_mappers)
            .bind(&pg.scope_mappings)
        )?;
        Ok(())
    }

    async fn update_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScope,
    ) -> Result<(), IssuerdError> {
        let pg: PgClientScope = scope.try_into()?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE client_scopes SET
                name = ?3, description = ?4, protocol = ?5,
                attributes = ?6, protocol_mappers = ?7, scope_mappings = ?8
            WHERE realm_id = ?1 AND id = ?2"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(pg.id)
            .bind(&pg.name)
            .bind(&pg.description)
            .bind(&pg.protocol)
            .bind(&pg.attributes)
            .bind(&pg.protocol_mappers)
            .bind(&pg.scope_mappings)
        )?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_client_scope(
        &self,
        realm: &RealmId,
        id: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        // client_client_scopes / realm_default_client_scopes rows cascade
        // via their scope_id FKs.
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM client_scopes WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Client <-> client-scope assignments
    // ------------------------------------------------------------------
    async fn assign_client_scope(
        &self,
        realm: &RealmId,
        client: &ClientId,
        scope: &ClientScopeId,
        is_default: bool,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO client_client_scopes (realm_id, client_id, scope_id, is_default)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT (client_id, scope_id) DO UPDATE SET is_default = EXCLUDED.is_default"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(client.as_ref())?)
            .bind(to_uuid(scope.as_ref())?)
            .bind(is_default)
        )?;
        Ok(())
    }

    async fn unassign_client_scope(
        &self,
        realm: &RealmId,
        client: &ClientId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query(
                "DELETE FROM client_client_scopes \
             WHERE realm_id = ?1 AND client_id = ?2 AND scope_id = ?3",
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(client.as_ref())?)
            .bind(to_uuid(scope.as_ref())?)
        )?;
        Ok(())
    }

    async fn list_client_scope_assignments(
        &self,
        realm: &RealmId,
        client: &ClientId,
    ) -> Result<Vec<(ClientScopeId, bool)>, IssuerdError> {
        let rows: Vec<(uuid::Uuid, bool)> = sqlx::query_as(
            "SELECT scope_id, is_default FROM client_client_scopes \
             WHERE realm_id = ?1 AND client_id = ?2 ORDER BY scope_id",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(client.as_ref())?)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter()
            .map(|(id, is_default)| ClientScopeId::new(id.to_string()).map(|s| (s, is_default)))
            .collect::<Result<Vec<_>, _>>()
    }

    // ------------------------------------------------------------------
    // Realm default client scopes
    // ------------------------------------------------------------------
    async fn list_realm_default_client_scopes(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<(ClientScopeId, bool)>, IssuerdError> {
        let rows: Vec<(uuid::Uuid, bool)> = sqlx::query_as(
            "SELECT scope_id, is_default FROM realm_default_client_scopes \
             WHERE realm_id = ?1 ORDER BY scope_id",
        )
        .bind(to_uuid(realm.as_ref())?)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter()
            .map(|(id, is_default)| ClientScopeId::new(id.to_string()).map(|s| (s, is_default)))
            .collect::<Result<Vec<_>, _>>()
    }

    async fn add_realm_default_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScopeId,
        is_default: bool,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO realm_default_client_scopes (realm_id, scope_id, is_default)
               VALUES (?1, ?2, ?3)
               ON CONFLICT (realm_id, scope_id) DO UPDATE SET is_default = EXCLUDED.is_default"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(scope.as_ref())?)
            .bind(is_default)
        )?;
        Ok(())
    }

    async fn remove_realm_default_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query(
                "DELETE FROM realm_default_client_scopes WHERE realm_id = ?1 AND scope_id = ?2",
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(scope.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------
    async fn get_group(
        &self,
        realm: &RealmId,
        id: &GroupId,
    ) -> Result<Option<Group>, IssuerdError> {
        let pg: Option<PgGroup> =
            sqlx::query_as("SELECT * FROM groups WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|g| g.try_into()).transpose()
    }

    async fn get_group_by_name(
        &self,
        realm: &RealmId,
        name: &str,
    ) -> Result<Option<Group>, IssuerdError> {
        let pg: Option<PgGroup> =
            sqlx::query_as("SELECT * FROM groups WHERE realm_id = ?1 AND name = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(name)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|g| g.try_into()).transpose()
    }

    async fn get_groups_batch(
        &self,
        realm: &RealmId,
        ids: &[GroupId],
    ) -> Result<Vec<Group>, IssuerdError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let realm_uuid = to_uuid(realm.as_ref())?;
        let uuids = ids.iter().map(|id| to_uuid(id.as_ref())).collect::<Result<Vec<_>, _>>()?;
        let mut rows = Vec::new();
        for chunk in uuids.chunks(500) {
            let mut query = QueryBuilder::<Sqlite>::new("SELECT * FROM groups WHERE realm_id = ");
            query.push_bind(realm_uuid).push(" AND id IN (");
            let mut values = query.separated(", ");
            for id in chunk {
                values.push_bind(id);
            }
            values.push_unseparated(")");
            rows.extend(
                query
                    .build_query_as::<PgGroup>()
                    .fetch_all(self.pool())
                    .await
                    .map_err(sqlx_err)?,
            );
        }
        let groups: Vec<Group> =
            rows.into_iter().map(|g| g.try_into()).collect::<Result<_, _>>()?;
        // IN does not preserve input order; restore it in Rust.
        let by_id: std::collections::HashMap<String, Group> =
            groups.into_iter().map(|g| (g.id.to_string(), g)).collect();
        Ok(ids.iter().filter_map(|id| by_id.get(id.as_ref()).cloned()).collect())
    }

    async fn list_groups(
        &self,
        realm: &RealmId,
        pagination: &Pagination,
    ) -> Result<Vec<Group>, IssuerdError> {
        let rows: Vec<PgGroup> = sqlx::query_as(
            "SELECT * FROM groups WHERE realm_id = ?1 ORDER BY name LIMIT ?2 OFFSET ?3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(pagination.max as i64)
        .bind(pagination.first as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|g| g.try_into()).collect()
    }

    async fn count_groups(&self, realm: &RealmId) -> Result<i64, IssuerdError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE realm_id = ?1")
            .bind(to_uuid(realm.as_ref())?)
            .fetch_one(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(count)
    }

    async fn create_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError> {
        let mut pg: PgGroup = group.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO groups (
                id, name, path, realm_id, parent_id, attributes, realm_roles, client_roles
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            )
            .bind(pg.id)
            .bind(&pg.name)
            .bind(&pg.path)
            .bind(pg.realm_id)
            .bind(pg.parent_id)
            .bind(&pg.attributes)
            .bind(&pg.realm_roles)
            .bind(&pg.client_roles)
        )?;
        Ok(())
    }

    async fn update_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError> {
        let pg: PgGroup = group.try_into()?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE groups SET
                name = ?3, path = ?4, parent_id = ?5, attributes = ?6,
                realm_roles = ?7, client_roles = ?8
            WHERE realm_id = ?1 AND id = ?2"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(pg.id)
            .bind(&pg.name)
            .bind(&pg.path)
            .bind(pg.parent_id)
            .bind(&pg.attributes)
            .bind(&pg.realm_roles)
            .bind(&pg.client_roles)
        )?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_group(&self, realm: &RealmId, id: &GroupId) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM groups WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // User realm roles
    // ------------------------------------------------------------------
    async fn add_user_realm_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(self.pool(), sqlx::query(
            "INSERT INTO user_realm_roles (realm_id, user_id, role_id) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING"
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(role_id.as_ref())?)
        )?;
        Ok(())
    }

    async fn remove_user_realm_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(self.pool(), sqlx::query(
            "DELETE FROM user_realm_roles WHERE realm_id = ?1 AND user_id = ?2 AND role_id = ?3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(role_id.as_ref())?)
        )?;
        Ok(())
    }

    async fn list_user_realm_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError> {
        let rows: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT role_id FROM user_realm_roles WHERE realm_id = ?1 AND user_id = ?2",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter()
            .map(|r| RoleId::new(r.0.to_string()))
            .collect::<Result<Vec<_>, _>>()
    }

    // ------------------------------------------------------------------
    // User client roles
    // ------------------------------------------------------------------
    async fn add_user_client_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(self.pool(), sqlx::query(
            "INSERT INTO user_client_roles (realm_id, user_id, role_id) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING"
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(role_id.as_ref())?)
        )?;
        Ok(())
    }

    async fn remove_user_client_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(self.pool(), sqlx::query(
            "DELETE FROM user_client_roles WHERE realm_id = ?1 AND user_id = ?2 AND role_id = ?3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(role_id.as_ref())?)
        )?;
        Ok(())
    }

    async fn list_user_client_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError> {
        let rows: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT role_id FROM user_client_roles WHERE realm_id = ?1 AND user_id = ?2",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter()
            .map(|r| RoleId::new(r.0.to_string()))
            .collect::<Result<Vec<_>, _>>()
    }

    // ------------------------------------------------------------------
    // User groups
    // ------------------------------------------------------------------
    async fn add_user_group(
        &self,
        realm: &RealmId,
        user: &UserId,
        group_id: &GroupId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(self.pool(), sqlx::query(
            "INSERT INTO user_groups (realm_id, user_id, group_id) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING"
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(group_id.as_ref())?)
        )?;
        Ok(())
    }

    async fn remove_user_group(
        &self,
        realm: &RealmId,
        user: &UserId,
        group_id: &GroupId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query(
                "DELETE FROM user_groups WHERE realm_id = ?1 AND user_id = ?2 AND group_id = ?3",
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(user.as_ref())?)
            .bind(to_uuid(group_id.as_ref())?)
        )?;
        Ok(())
    }

    async fn list_user_groups(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<GroupId>, IssuerdError> {
        let rows: Vec<(uuid::Uuid,)> =
            sqlx::query_as("SELECT group_id FROM user_groups WHERE realm_id = ?1 AND user_id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(user.as_ref())?)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        rows.into_iter()
            .map(|r| GroupId::new(r.0.to_string()))
            .collect::<Result<Vec<_>, _>>()
    }

    async fn list_group_members(
        &self,
        realm: &RealmId,
        group: &GroupId,
        first: i32,
        max: i32,
    ) -> Result<Vec<User>, IssuerdError> {
        let rows: Vec<PgUser> = sqlx::query_as(
            r#"SELECT u.* FROM users u
               JOIN user_groups ug
                 ON ug.realm_id = u.realm_id AND ug.user_id = u.id
               WHERE ug.realm_id = ?1 AND ug.group_id = ?2
               ORDER BY u.username
               LIMIT ?3 OFFSET ?4"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(group.as_ref())?)
        .bind(max.max(0) as i64)
        .bind(first.max(0) as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|u| u.try_into()).collect()
    }

    // ------------------------------------------------------------------
    // Consent
    // ------------------------------------------------------------------
    async fn get_consents(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<Consent>, IssuerdError> {
        let rows: Vec<SqliteConsent> =
            sqlx::query_as("SELECT * FROM consents WHERE realm_id = ?1 AND user_id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(user.as_ref())?)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        rows.into_iter().map(|c| c.try_into()).collect()
    }

    async fn create_consent(&self, realm: &RealmId, consent: &Consent) -> Result<(), IssuerdError> {
        let mut pg: SqliteConsent = consent.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO consents (
                realm_id, user_id, client_id, granted_scopes,
                granted_realm_roles, granted_client_roles, created_at, last_updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT (realm_id, user_id, client_id) DO UPDATE SET
                granted_scopes = EXCLUDED.granted_scopes,
                granted_realm_roles = EXCLUDED.granted_realm_roles,
                granted_client_roles = EXCLUDED.granted_client_roles,
                last_updated_at = EXCLUDED.last_updated_at"#,
            )
            .bind(pg.realm_id)
            .bind(pg.user_id)
            .bind(pg.client_id)
            .bind(&pg.granted_scopes)
            .bind(&pg.granted_realm_roles)
            .bind(&pg.granted_client_roles)
            .bind(pg.created_at)
            .bind(pg.last_updated_at)
        )?;
        Ok(())
    }

    async fn delete_consent(
        &self,
        realm: &RealmId,
        user: &UserId,
        client_id: &ClientId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query(
                "DELETE FROM consents WHERE realm_id = ?1 AND user_id = ?2 AND client_id = ?3"
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(user.as_ref())?)
            .bind(to_uuid(client_id.as_ref())?)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Identity Providers
    // ------------------------------------------------------------------
    async fn get_identity_provider(
        &self,
        realm: &RealmId,
        id: &IdentityProviderId,
    ) -> Result<Option<IdentityProviderConfig>, IssuerdError> {
        let pg: Option<PgIdentityProvider> =
            sqlx::query_as("SELECT * FROM identity_providers WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|i| i.try_into()).transpose()
    }

    async fn get_identity_provider_by_alias(
        &self,
        realm: &RealmId,
        alias: &str,
    ) -> Result<Option<IdentityProviderConfig>, IssuerdError> {
        let realm_uuid = uuid::Uuid::parse_str(realm.as_ref())
            .map_err(|e| IssuerdError::InvalidRequest(format!("invalid realm id: {e}")))?;
        let row = sqlx::query_as::<_, crate::db_types::PgIdentityProvider>(
            "SELECT * FROM identity_providers WHERE realm_id = ?1 AND alias = ?2",
        )
        .bind(realm_uuid)
        .bind(alias)
        .fetch_optional(&self.pool)
        .await
        .map_err(sqlx_err)?;
        row.map(|r| r.try_into()).transpose()
    }

    async fn list_identity_providers(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<IdentityProviderConfig>, IssuerdError> {
        let rows: Vec<PgIdentityProvider> =
            sqlx::query_as("SELECT * FROM identity_providers WHERE realm_id = ?1")
                .bind(to_uuid(realm.as_ref())?)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        rows.into_iter().map(|i| i.try_into()).collect()
    }

    async fn create_identity_provider(
        &self,
        realm: &RealmId,
        idp: &IdentityProviderConfig,
    ) -> Result<(), IssuerdError> {
        let mut pg: PgIdentityProvider = idp.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        retry_execute!(self.pool(), sqlx::query(
            r#"INSERT INTO identity_providers (id, realm_id, alias, provider_id, enabled, config)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
        )
        .bind(pg.id)
        .bind(pg.realm_id)
        .bind(&pg.alias)
        .bind(&pg.provider_id)
        .bind(pg.enabled)
        .bind(&pg.config)
        )?;
        Ok(())
    }

    async fn update_identity_provider(
        &self,
        realm: &RealmId,
        idp: &IdentityProviderConfig,
    ) -> Result<(), IssuerdError> {
        let pg: PgIdentityProvider = idp.try_into()?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE identity_providers SET
                alias = ?3, provider_id = ?4, enabled = ?5, config = ?6
            WHERE realm_id = ?1 AND id = ?2"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(pg.id)
            .bind(&pg.alias)
            .bind(&pg.provider_id)
            .bind(pg.enabled)
            .bind(&pg.config)
        )?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_identity_provider(
        &self,
        realm: &RealmId,
        id: &IdentityProviderId,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM identity_providers WHERE realm_id = ?1 AND id = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(id.as_ref())?)
        )?;
        // identity_provider_links rows cascade via fk_idp_links_provider.
        Ok(())
    }

    // ------------------------------------------------------------------
    // Identity Provider Links
    // ------------------------------------------------------------------
    async fn get_identity_provider_link(
        &self,
        realm: &RealmId,
        alias: &str,
        external_subject: &str,
    ) -> Result<Option<IdentityProviderLink>, IssuerdError> {
        let row: Option<PgIdentityProviderLink> = sqlx::query_as(
            "SELECT * FROM identity_provider_links \
             WHERE realm_id = ?1 AND provider_alias = ?2 AND external_subject = ?3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(alias)
        .bind(external_subject)
        .fetch_optional(self.pool())
        .await
        .map_err(sqlx_err)?;
        row.map(|r| r.try_into()).transpose()
    }

    async fn get_identity_provider_link_for_user(
        &self,
        realm: &RealmId,
        user: &UserId,
        alias: &str,
    ) -> Result<Option<IdentityProviderLink>, IssuerdError> {
        let row: Option<PgIdentityProviderLink> = sqlx::query_as(
            "SELECT * FROM identity_provider_links \
             WHERE realm_id = ?1 AND user_id = ?2 AND provider_alias = ?3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(alias)
        .fetch_optional(self.pool())
        .await
        .map_err(sqlx_err)?;
        row.map(|r| r.try_into()).transpose()
    }

    async fn list_identity_provider_links(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<IdentityProviderLink>, IssuerdError> {
        let rows: Vec<PgIdentityProviderLink> = sqlx::query_as(
            "SELECT * FROM identity_provider_links WHERE realm_id = ?1 AND user_id = ?2 \
             ORDER BY provider_alias",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn create_identity_provider_link(
        &self,
        realm: &RealmId,
        link: &IdentityProviderLink,
    ) -> Result<(), IssuerdError> {
        // Unique violations (duplicate external subject, or a second link for
        // the same user+provider) surface as IssuerdError::Conflict via sqlx_err.
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO identity_provider_links (
                realm_id, user_id, provider_alias, external_subject,
                external_username, stored_refresh_token, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(link.user_id.as_ref())?)
            .bind(&link.provider_alias)
            .bind(&link.external_subject)
            .bind(&link.external_username)
            .bind(&link.stored_refresh_token)
            .bind(link.created_at)
        )?;
        Ok(())
    }

    async fn delete_identity_provider_link(
        &self,
        realm: &RealmId,
        user: &UserId,
        alias: &str,
    ) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query(
                "DELETE FROM identity_provider_links \
             WHERE realm_id = ?1 AND user_id = ?2 AND provider_alias = ?3",
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(user.as_ref())?)
            .bind(alias)
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Flow Config
    // ------------------------------------------------------------------
    async fn get_flow_config(
        &self,
        realm: &RealmId,
        alias: &str,
    ) -> Result<Option<FlowConfig>, IssuerdError> {
        let pg: Option<PgFlowConfig> =
            sqlx::query_as("SELECT * FROM flow_configs WHERE realm_id = ?1 AND alias = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(alias)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        pg.map(|f| f.try_into()).transpose()
    }

    async fn create_flow_config(
        &self,
        realm: &RealmId,
        config: &FlowConfig,
    ) -> Result<(), IssuerdError> {
        let mut pg: PgFlowConfig = config.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        retry_execute!(self.pool(), sqlx::query(
            r#"INSERT INTO flow_configs (alias, realm_id, provider_id, top_level, built_in, stages)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
        )
        .bind(&pg.alias)
        .bind(pg.realm_id)
        .bind(&pg.provider_id)
        .bind(pg.top_level)
        .bind(pg.built_in)
        .bind(&pg.stages)
        )?;
        Ok(())
    }

    async fn update_flow_config(
        &self,
        realm: &RealmId,
        config: &FlowConfig,
    ) -> Result<(), IssuerdError> {
        let pg: PgFlowConfig = config.try_into()?;
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"UPDATE flow_configs SET
                provider_id = ?3, top_level = ?4, built_in = ?5, stages = ?6
            WHERE realm_id = ?1 AND alias = ?2"#,
            )
            .bind(to_uuid(realm.as_ref())?)
            .bind(&pg.alias)
            .bind(&pg.provider_id)
            .bind(pg.top_level)
            .bind(pg.built_in)
            .bind(&pg.stages)
        )?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_flow_config(&self, realm: &RealmId, alias: &str) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM flow_configs WHERE realm_id = ?1 AND alias = ?2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(alias)
        )?;
        Ok(())
    }

    async fn list_flow_configs(&self, realm: &RealmId) -> Result<Vec<FlowConfig>, IssuerdError> {
        let realm_uuid = uuid::Uuid::parse_str(realm.as_ref())
            .map_err(|e| IssuerdError::InvalidRequest(format!("invalid realm id: {e}")))?;
        let rows = sqlx::query_as::<_, crate::db_types::PgFlowConfig>(
            "SELECT * FROM flow_configs WHERE realm_id = ?1 ORDER BY alias",
        )
        .bind(realm_uuid)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------
    async fn save_event(&self, _realm: &RealmId, event: &Event) -> Result<(), IssuerdError> {
        let pg: PgEvent = event.try_into()?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO events (
                id, realm_id, event_time, event_type, ip_address,
                client_id, user_id, session_id, error, details
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            )
            .bind(pg.id)
            .bind(pg.realm_id)
            .bind(pg.event_time)
            .bind(&pg.event_type)
            .bind(&pg.ip_address)
            .bind(pg.client_id)
            .bind(pg.user_id)
            .bind(pg.session_id)
            .bind(&pg.error)
            .bind(&pg.details)
        )?;
        Ok(())
    }

    async fn query_events(
        &self,
        realm: &RealmId,
        query: &EventQuery,
    ) -> Result<Vec<Event>, IssuerdError> {
        let event_type_opt = query
            .event_type
            .as_ref()
            .map(|et| serde_json::to_string(et).unwrap_or_default().trim_matches('"').to_string());
        let client_id_opt = query.client_id.as_ref().map(|c| to_uuid(c.as_ref())).transpose()?;
        let user_id_opt = query.user_id.as_ref().map(|u| to_uuid(u.as_ref())).transpose()?;

        let rows: Vec<PgEvent> = sqlx::query_as(
            r#"SELECT * FROM events
               WHERE realm_id = ?1
                 AND (?2 IS NULL OR event_type = ?2)
                 AND (?3 IS NULL OR event_time >= ?3)
                 AND (?4 IS NULL OR event_time <= ?4)
                 AND (?5 IS NULL OR client_id = ?5)
                 AND (?6 IS NULL OR user_id = ?6)
               ORDER BY event_time DESC
               LIMIT ?7 OFFSET ?8"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(event_type_opt)
        .bind(query.date_from)
        .bind(query.date_to)
        .bind(client_id_opt)
        .bind(user_id_opt)
        .bind(query.pagination.max as i64)
        .bind(query.pagination.first as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|e| e.try_into()).collect()
    }

    async fn count_events(&self, realm: &RealmId, query: &EventQuery) -> Result<i64, IssuerdError> {
        let event_type_opt = query
            .event_type
            .as_ref()
            .map(|et| serde_json::to_string(et).unwrap_or_default().trim_matches('"').to_string());
        let client_id_opt = query.client_id.as_ref().map(|c| to_uuid(c.as_ref())).transpose()?;
        let user_id_opt = query.user_id.as_ref().map(|u| to_uuid(u.as_ref())).transpose()?;

        let row: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(*) FROM events
               WHERE realm_id = ?1
                 AND (?2 IS NULL OR event_type = ?2)
                 AND (?3 IS NULL OR event_time >= ?3)
                 AND (?4 IS NULL OR event_time <= ?4)
                 AND (?5 IS NULL OR client_id = ?5)
                 AND (?6 IS NULL OR user_id = ?6)"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(event_type_opt)
        .bind(query.date_from)
        .bind(query.date_to)
        .bind(client_id_opt)
        .bind(user_id_opt)
        .fetch_one(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(row.0)
    }

    async fn delete_events(&self, realm: &RealmId) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM events WHERE realm_id = ?1").bind(to_uuid(realm.as_ref())?)
        )?;
        Ok(())
    }

    async fn save_admin_event(&self, event: &AdminEvent) -> Result<(), IssuerdError> {
        let pg: PgAdminEvent = event.try_into()?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO admin_events (
                id, realm_id, auth_realm_id, auth_client_id, auth_user_id,
                operation_type, resource_type, resource_path, representation, error, event_time
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
            )
            .bind(pg.id)
            .bind(pg.realm_id)
            .bind(pg.auth_realm_id)
            .bind(&pg.auth_client_id)
            .bind(pg.auth_user_id)
            .bind(&pg.operation_type)
            .bind(&pg.resource_type)
            .bind(&pg.resource_path)
            .bind(&pg.representation)
            .bind(&pg.error)
            .bind(pg.event_time)
        )?;
        Ok(())
    }

    async fn query_admin_events(
        &self,
        realm: &RealmId,
        query: &AdminEventQuery,
    ) -> Result<Vec<AdminEvent>, IssuerdError> {
        let operation_type_opt = query
            .operation_type
            .as_ref()
            .map(|ot| serde_json::to_string(ot).unwrap_or_default().trim_matches('"').to_string());
        let resource_type_opt = query
            .resource_type
            .as_ref()
            .map(|rt| serde_json::to_string(rt).unwrap_or_default().trim_matches('"').to_string());
        let auth_user_id_opt =
            query.auth_user_id.as_ref().map(|u| to_uuid(u.as_ref())).transpose()?;

        let rows: Vec<PgAdminEvent> = sqlx::query_as(
            r#"SELECT * FROM admin_events
               WHERE realm_id = ?1
                 AND (?2 IS NULL OR operation_type = ?2)
                 AND (?3 IS NULL OR resource_type = ?3)
                 AND (?4 IS NULL OR event_time >= ?4)
                 AND (?5 IS NULL OR event_time <= ?5)
                 AND (?6 IS NULL OR auth_user_id = ?6)
               ORDER BY event_time DESC
               LIMIT ?7 OFFSET ?8"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(operation_type_opt)
        .bind(resource_type_opt)
        .bind(query.date_from)
        .bind(query.date_to)
        .bind(auth_user_id_opt)
        .bind(query.pagination.max as i64)
        .bind(query.pagination.first as i64)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        rows.into_iter().map(|e| e.try_into()).collect()
    }

    async fn count_admin_events(
        &self,
        realm: &RealmId,
        query: &AdminEventQuery,
    ) -> Result<i64, IssuerdError> {
        let operation_type_opt = query
            .operation_type
            .as_ref()
            .map(|ot| serde_json::to_string(ot).unwrap_or_default().trim_matches('"').to_string());
        let resource_type_opt = query
            .resource_type
            .as_ref()
            .map(|rt| serde_json::to_string(rt).unwrap_or_default().trim_matches('"').to_string());
        let auth_user_id_opt =
            query.auth_user_id.as_ref().map(|u| to_uuid(u.as_ref())).transpose()?;

        let row: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(*) FROM admin_events
               WHERE realm_id = ?1
                 AND (?2 IS NULL OR operation_type = ?2)
                 AND (?3 IS NULL OR resource_type = ?3)
                 AND (?4 IS NULL OR event_time >= ?4)
                 AND (?5 IS NULL OR event_time <= ?5)
                 AND (?6 IS NULL OR auth_user_id = ?6)"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(operation_type_opt)
        .bind(resource_type_opt)
        .bind(query.date_from)
        .bind(query.date_to)
        .bind(auth_user_id_opt)
        .fetch_one(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(row.0)
    }

    async fn delete_admin_events(&self, realm: &RealmId) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM admin_events WHERE realm_id = ?1")
                .bind(to_uuid(realm.as_ref())?)
        )?;
        Ok(())
    }

    async fn create_webhook_subscription(
        &self,
        realm: &RealmId,
        subscription: &WebhookSubscription,
    ) -> Result<(), IssuerdError> {
        SqliteStorage::create_webhook_subscription(self, realm, subscription).await
    }
    async fn get_webhook_subscription(
        &self,
        realm: &RealmId,
        id: &WebhookSubscriptionId,
    ) -> Result<Option<WebhookSubscription>, IssuerdError> {
        SqliteStorage::get_webhook_subscription(self, realm, id).await
    }
    async fn list_webhook_subscriptions(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<WebhookSubscription>, IssuerdError> {
        SqliteStorage::list_webhook_subscriptions(self, realm).await
    }
    async fn update_webhook_subscription(
        &self,
        realm: &RealmId,
        subscription: &WebhookSubscription,
    ) -> Result<(), IssuerdError> {
        SqliteStorage::update_webhook_subscription(self, realm, subscription).await
    }
    async fn delete_webhook_subscription(
        &self,
        realm: &RealmId,
        id: &WebhookSubscriptionId,
    ) -> Result<(), IssuerdError> {
        SqliteStorage::delete_webhook_subscription(self, realm, id).await
    }
    async fn enqueue_webhook_delivery(
        &self,
        realm: &RealmId,
        subscription_id: &WebhookSubscriptionId,
        event: &WebhookEvent,
    ) -> Result<bool, IssuerdError> {
        SqliteStorage::enqueue_webhook_delivery(self, realm, subscription_id, event).await
    }
    async fn claim_webhook_deliveries(
        &self,
        worker_id: &str,
        limit: u32,
        lease_duration: std::time::Duration,
    ) -> Result<Vec<WebhookDeliveryTask>, IssuerdError> {
        SqliteStorage::claim_webhook_deliveries(self, worker_id, limit, lease_duration).await
    }
    async fn complete_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
        lease_owner: &str,
    ) -> Result<(), IssuerdError> {
        SqliteStorage::complete_webhook_delivery(self, realm, id, lease_owner).await
    }
    async fn fail_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
        lease_owner: &str,
        error: &str,
        next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), IssuerdError> {
        SqliteStorage::fail_webhook_delivery(self, realm, id, lease_owner, error, next_attempt_at)
            .await
    }
    async fn get_webhook_delivery(
        &self,
        realm: &RealmId,
        subscription_id: &WebhookSubscriptionId,
        id: &WebhookDeliveryId,
    ) -> Result<Option<WebhookDelivery>, IssuerdError> {
        SqliteStorage::get_webhook_delivery(self, realm, subscription_id, id).await
    }
    async fn replay_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
    ) -> Result<(), IssuerdError> {
        SqliteStorage::replay_webhook_delivery(self, realm, id).await
    }
    async fn list_webhook_deliveries(
        &self,
        realm: &RealmId,
        subscription_id: Option<WebhookSubscriptionId>,
        pagination: &Pagination,
    ) -> Result<Vec<WebhookDelivery>, IssuerdError> {
        SqliteStorage::list_webhook_deliveries(self, realm, subscription_id, pagination).await
    }

    async fn get_provision_marker(&self, name: &str) -> Result<Option<String>, IssuerdError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM provision_markers WHERE name = ?1")
                .bind(name)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        Ok(row.map(|r| r.0))
    }

    async fn set_provision_marker(&self, name: &str, value: &str) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO provision_markers (name, value)
               VALUES (?1, ?2)
               ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value"#,
            )
            .bind(name)
            .bind(value)
        )?;
        Ok(())
    }

    async fn delete_provision_marker(&self, name: &str) -> Result<(), IssuerdError> {
        retry_execute!(
            self.pool(),
            sqlx::query("DELETE FROM provision_markers WHERE name = ?1").bind(name)
        )?;
        Ok(())
    }

    async fn claim_provision_marker(&self, name: &str, value: &str) -> Result<bool, IssuerdError> {
        let result = retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO provision_markers (name, value)
               VALUES (?1, ?2)
               ON CONFLICT (name) DO NOTHING"#,
            )
            .bind(name)
            .bind(value)
        )?;
        Ok(result.rows_affected() == 1)
    }

    // ------------------------------------------------------------------
    // Signing keys
    // ------------------------------------------------------------------
    async fn list_signing_keys(&self) -> Result<Vec<StoredSigningKey>, IssuerdError> {
        let rows: Vec<PgSigningKey> =
            sqlx::query_as("SELECT * FROM signing_keys ORDER BY created_at ASC, kid ASC")
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        rows.into_iter().map(|row| row.try_into()).collect()
    }

    async fn create_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError> {
        let pg: PgSigningKey = key.try_into()?;
        retry_execute!(
            self.pool(),
            sqlx::query(
                r#"INSERT INTO signing_keys (
                kid, alg, created_at, private_der, public_jwk, active
            ) VALUES (?, ?, ?, ?, ?, ?)"#,
            )
            .bind(&pg.kid)
            .bind(&pg.alg)
            .bind(pg.created_at)
            .bind(&pg.private_der)
            .bind(&pg.public_jwk)
            .bind(pg.active)
        )?;
        Ok(())
    }

    async fn update_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError> {
        let result = retry_execute!(
            self.pool(),
            sqlx::query("UPDATE signing_keys SET active = ?2 WHERE kid = ?1")
                .bind(key.kid.to_string())
                .bind(key.active)
        )?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn get_mcp_step_up_grant(
        &self,
        token_jti: &JwtId,
    ) -> Result<Option<McpStepUpGrant>, IssuerdError> {
        crate::step_up_sqlite::get_grant(self, token_jti).await
    }

    async fn create_mcp_step_up_grant(&self, grant: &McpStepUpGrant) -> Result<(), IssuerdError> {
        crate::step_up_sqlite::create_grant(self, grant).await
    }

    async fn execute_mcp_step_up(
        &self,
        token_jti: &JwtId,
        operation_hash: &str,
        mutation: &McpStepUpMutation,
        result_json: serde_json::Value,
    ) -> Result<McpStepUpExecution, IssuerdError> {
        crate::step_up_sqlite::execute_grant(self, token_jti, operation_hash, mutation, result_json)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    async fn setup_sqlite() -> (SqliteStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temporary SQLite directory");
        let path = dir.path().join("issuerd.db");
        let storage = SqliteStorage::connect(&path).await.expect("connect");
        storage.run_migrations().await.expect("migrations");
        (storage, dir)
    }

    fn test_realm() -> Realm {
        Realm {
            id: RealmId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            name: RealmName::new("test-realm").unwrap(),
            display_name: Some(DisplayName::new("Test Realm").unwrap()),
            enabled: true,
            ssl_required: SslRequired::External,
            password_policy: PasswordPolicy::default(),
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            default_role: None,
            access_token_lifespan: SecondsNonZero::new(300),
            refresh_token_lifespan: SecondsNonZero::new(1800),
            sso_session_idle_timeout: SecondsNonZero::new(1800),
            sso_session_max_lifespan: SecondsNonZero::new(36000),
            offline_session_idle_timeout: SecondsNonZero::new(2592000),
            brute_force_protected: false,
            max_login_failures: 5,
            wait_increment_secs: 60,
            max_failure_wait_secs: 900,
            lockout_duration_secs: 900,
            registration_enabled: false,
            reset_password_allowed: false,
            remember_me_enabled: false,
            verify_email_enabled: false,
            login_with_email_allowed: true,
            duplicate_emails_allowed: false,
            edit_username_allowed: true,
            remember_me_session_idle_secs: SecondsNonZero::new(604_800),
            otp_policy: OtpPolicy::default(),
            internationalization_enabled: false,
            supported_locales: Vec::new(),
            default_locale: None,
            events_enabled: false,
            events_expiration_secs: 0,
            admin_events_enabled: false,
            include_representations: false,
            events_listeners: vec!["logging".to_string()],
            not_before: 0,
            default_groups: Vec::new(),
            browser_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: None,
            attributes: HashMap::new(),
        }
    }

    fn test_user(realm_id: &RealmId) -> User {
        User {
            id: UserId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm_id.clone(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: Some(DisplayName::new("Smith").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn test_client(realm_id: &RealmId) -> Client {
        Client {
            id: ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: Some(issuerd_core::DisplayName::new("My App").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![RedirectUri::new("https://app.example.com/callback").unwrap()],
            web_origins: vec![WebOrigin::new("https://app.example.com").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::parse("email"),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    fn test_credential() -> Credential {
        Credential {
            id: CredentialId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            credential_type: CredentialType::Password,
            user_label: Some("My password".to_string()),
            created_date: Utc::now(),
            secret_data: vec![1, 2, 3],
            credential_data: serde_json::json!({"hash": "abc123"}),
            priority: 1,
        }
    }

    fn test_session(realm_id: &RealmId, user_id: &UserId) -> UserSession {
        UserSession {
            id: SessionId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm_id.clone(),
            user_id: user_id.clone(),
            login_username: issuerd_core::Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
            clients: vec![],
        }
    }

    fn test_role(realm_id: &RealmId) -> Role {
        Role {
            id: RoleId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: Some("Admin role".to_string()),
            realm_id: realm_id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        }
    }

    fn test_group(realm_id: &RealmId) -> Group {
        Group {
            id: GroupId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: GroupPath::new("/admins").unwrap(),
            realm_id: realm_id.clone(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![issuerd_core::RoleName::new("admin").unwrap()],
            client_roles: HashMap::new(),
        }
    }

    fn test_consent() -> Consent {
        Consent {
            client_id: ClientId::new("client-1").unwrap(),
            user_id: UserId::new("user-1").unwrap(),
            granted_scopes: Scope::parse("openid"),
            granted_realm_roles: vec![],
            granted_client_roles: HashMap::new(),
            created_at: Utc::now(),
            last_updated_at: Utc::now(),
        }
    }

    fn test_idp() -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: IdentityProviderId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            alias: Alias::new("google").unwrap(),
            provider_id: ProviderId::new("google"),
            enabled: true,
            config: {
                let mut m = HashMap::new();
                m.insert("clientId".to_string(), "123".to_string());
                m
            },
        }
    }

    fn test_flow_config(realm_id: &RealmId) -> FlowConfig {
        FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: realm_id.clone(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![],
        }
    }

    fn test_event(realm_id: &RealmId, event_type: EventType) -> Event {
        Event {
            id: EventId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm_id.clone(),
            event_time: Utc::now(),
            event_type,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            client_id: Some(ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap()),
            user_id: Some(UserId::new(uuid::Uuid::new_v4().to_string()).unwrap()),
            session_id: Some(SessionId::new(uuid::Uuid::new_v4().to_string()).unwrap()),
            error: None,
            details: {
                let mut m = HashMap::new();
                m.insert("method".to_string(), "password".to_string());
                m
            },
        }
    }

    fn test_signing_key(kid: &str, created_at: chrono::DateTime<Utc>) -> StoredSigningKey {
        StoredSigningKey {
            kid: KeyId::new(kid).unwrap(),
            alg: Algorithm::Rs256,
            created_at,
            private_der: vec![1, 2, 3, 4],
            public_jwk: Jwk {
                kty: JwkKty::Rsa,
                kid: KeyId::new(kid).unwrap(),
                alg: Algorithm::Rs256,
                use_: JwkUse::Sig,
                n: Some(Base64Url::new("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2").unwrap()),
                e: Some(Base64Url::new("AQAB").unwrap()),
                x: None,
                y: None,
                crv: None,
                k: None,
            },
            active: true,
        }
    }

    // ------------------------------------------------------------------
    // Realm CRUD
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_realm_crud_and_uniqueness() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let found = storage.get_realm(&realm.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "test-realm");

        let by_name = storage.get_realm_by_name("test-realm").await.unwrap();
        assert!(by_name.is_some());

        // Duplicate name
        let mut dup = realm.clone();
        dup.id = RealmId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert!(storage.create_realm(&dup).await.is_err());

        storage.delete_realm(&realm.id).await.unwrap();
        assert!(storage.get_realm(&realm.id).await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // User CRUD
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_user_crud_and_uniqueness() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user(&realm.id);
        storage.create_user(&realm.id, &user).await.unwrap();

        let found = storage.get_user(&realm.id, &user.id).await.unwrap();
        assert!(found.is_some());

        let by_username = storage.get_user_by_username(&realm.id, "alice").await.unwrap();
        assert!(by_username.is_some());

        let by_email = storage.get_user_by_email(&realm.id, "alice@example.com").await.unwrap();
        assert!(by_email.is_some());

        // Duplicate username in same realm
        let mut dup = user.clone();
        dup.id = UserId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert!(storage.create_user(&realm.id, &dup).await.is_err());

        storage.delete_user(&realm.id, &user.id).await.unwrap();
        assert!(storage.get_user(&realm.id, &user.id).await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Client CRUD
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_client_crud_and_uniqueness() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let client = test_client(&realm.id);
        storage.create_client(&realm.id, &client).await.unwrap();

        let found = storage.get_client(&realm.id, &client.id).await.unwrap();
        assert!(found.is_some());

        let by_client_id = storage
            .get_client_by_client_id(&realm.id, &ClientIdentifier::new("my-app").unwrap())
            .await
            .unwrap();
        assert!(by_client_id.is_some());

        // Duplicate client_id
        let mut dup = client.clone();
        dup.id = ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert!(storage.create_client(&realm.id, &dup).await.is_err());

        storage.delete_client(&realm.id, &client.id).await.unwrap();
        assert!(storage.get_client(&realm.id, &client.id).await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Role / Group
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_role_and_group_crud() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let role = test_role(&realm.id);
        storage.create_role(&realm.id, &role).await.unwrap();

        let found = storage.get_role(&realm.id, &role.id).await.unwrap();
        assert!(found.is_some());

        let by_name = storage.get_role_by_name(&realm.id, "admin").await.unwrap();
        assert!(by_name.is_some());

        storage.delete_role(&realm.id, &role.id).await.unwrap();
        assert!(storage.get_role(&realm.id, &role.id).await.unwrap().is_none());

        let group = test_group(&realm.id);
        storage.create_group(&realm.id, &group).await.unwrap();
        let g = storage.get_group(&realm.id, &group.id).await.unwrap();
        assert!(g.is_some());
    }

    // ------------------------------------------------------------------
    // Credentials
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_credential_crud() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        let user = test_user(&realm.id);
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();

        let cred = test_credential();
        storage.create_credential(&realm.id, &user.id, &cred).await.unwrap();

        let list = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(list.len(), 1);

        let mut updated = cred.clone();
        updated.priority = 5;
        storage.update_credential(&realm.id, &user.id, &updated).await.unwrap();
        let list = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(list[0].priority, 5);

        storage.delete_credential(&realm.id, &user.id, &cred.id).await.unwrap();
        let list = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn sqlite_consume_totp_step_is_atomic_and_monotonic() {
        const BURST: usize = 64;

        let (storage, _tempdir) = setup_sqlite().await;
        let storage = std::sync::Arc::new(storage);
        let realm = test_realm();
        let user = test_user(&realm.id);
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();

        let password = test_credential();
        let mut totp = test_credential();
        totp.credential_type = CredentialType::Totp;
        totp.credential_data = serde_json::json!({
            "algorithm": "HmacSHA1",
            "digits": 6,
            "last_used_step": null
        });
        storage.create_credential(&realm.id, &user.id, &password).await.unwrap();
        storage.create_credential(&realm.id, &user.id, &totp).await.unwrap();

        let missing = CredentialId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert!(!storage.consume_totp_step(&realm.id, &user.id, &missing, 100).await.unwrap());
        assert!(!storage.consume_totp_step(&realm.id, &user.id, &password.id, 100).await.unwrap());
        assert!(storage.consume_totp_step(&realm.id, &user.id, &totp.id, 100).await.unwrap());
        assert!(!storage.consume_totp_step(&realm.id, &user.id, &totp.id, 100).await.unwrap());
        assert!(!storage.consume_totp_step(&realm.id, &user.id, &totp.id, 99).await.unwrap());

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(BURST));
        let mut tasks = Vec::with_capacity(BURST);
        for _ in 0..BURST {
            let storage = std::sync::Arc::clone(&storage);
            let barrier = std::sync::Arc::clone(&barrier);
            let realm_id = realm.id.clone();
            let user_id = user.id.clone();
            let credential_id = totp.id.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                storage
                    .consume_totp_step(&realm_id, &user_id, &credential_id, 101)
                    .await
                    .unwrap()
            }));
        }
        let mut successes = 0;
        for task in tasks {
            if task.await.unwrap() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1);
        assert!(storage.consume_totp_step(&realm.id, &user.id, &totp.id, 102).await.unwrap());

        let mut expected = totp.clone();
        expected.credential_data["last_used_step"] = serde_json::json!(102);
        let stored = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Totp)
            .await
            .unwrap();
        assert_eq!(stored, vec![expected]);
        let stored_password = storage
            .get_credentials(&realm.id, &user.id, CredentialType::Password)
            .await
            .unwrap();
        assert_eq!(stored_password, vec![password]);
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_session_lifecycle() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        let user = test_user(&realm.id);
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();

        let client = test_client(&realm.id);
        storage.create_client(&realm.id, &client).await.unwrap();

        let mut session = test_session(&realm.id, &user.id);
        session.clients.push(ClientSession {
            id: ClientSessionId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            client_id: client.id.clone(),
            session_id: session.id.clone(),
            redirect_uri: Some(issuerd_core::RedirectUri::new("https://app.example.com").unwrap()),
            state: Some("xyz".to_string()),
            auth_method: AuthMethod::Password,
            timestamp: Utc::now(),
        });

        storage.create_user_session(&realm.id, &session).await.unwrap();

        let found = storage.get_user_session(&realm.id, &session.id).await.unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.clients.len(), 1);
        assert_eq!(
            found.clients[0].redirect_uri,
            Some(issuerd_core::RedirectUri::new("https://app.example.com").unwrap())
        );

        let list = storage
            .list_sessions(&realm.id, Some(user.id.clone()), &Pagination::default())
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].clients.len(), 1);

        storage.delete_user_session(&realm.id, &session.id).await.unwrap();
        assert!(storage.get_user_session(&realm.id, &session.id).await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Consent
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_consent_lifecycle() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user(&realm.id);
        storage.create_user(&realm.id, &user).await.unwrap();

        let mut consent = test_consent();
        consent.user_id = user.id.clone();
        consent.client_id = ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap();

        storage.create_consent(&realm.id, &consent).await.unwrap();

        let list = storage.get_consents(&realm.id, &consent.user_id).await.unwrap();
        assert_eq!(list.len(), 1);

        storage
            .delete_consent(&realm.id, &consent.user_id, &consent.client_id)
            .await
            .unwrap();
        let list = storage.get_consents(&realm.id, &consent.user_id).await.unwrap();
        assert!(list.is_empty());
    }

    // ------------------------------------------------------------------
    // Identity Providers
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_idp_lifecycle() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let idp = test_idp();
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();

        let list = storage.list_identity_providers(&realm.id).await.unwrap();
        assert_eq!(list.len(), 1);

        let mut updated = idp.clone();
        updated.enabled = false;
        storage.update_identity_provider(&realm.id, &updated).await.unwrap();
        let found = storage.get_identity_provider(&realm.id, &idp.id).await.unwrap();
        assert!(!found.unwrap().enabled);

        storage.delete_identity_provider(&realm.id, &idp.id).await.unwrap();
        assert!(storage.get_identity_provider(&realm.id, &idp.id).await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Flow Configs
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_flow_config_lifecycle() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        // A fresh alias: `create_realm` already seeded the built-in `browser`
        // and `registration` flows.
        let mut flow = test_flow_config(&realm.id);
        flow.alias = Alias::new("custom-flow").unwrap();
        storage.create_flow_config(&realm.id, &flow).await.unwrap();

        let found = storage.get_flow_config(&realm.id, "custom-flow").await.unwrap();
        assert!(found.is_some());

        let mut updated = flow.clone();
        updated.provider_id = "updated".to_string();
        storage.update_flow_config(&realm.id, &updated).await.unwrap();
        let found = storage.get_flow_config(&realm.id, "custom-flow").await.unwrap();
        assert_eq!(found.unwrap().provider_id, "updated");

        storage.delete_flow_config(&realm.id, "custom-flow").await.unwrap();
        assert!(storage.get_flow_config(&realm.id, "custom-flow").await.unwrap().is_none());
    }

    // ------------------------------------------------------------------
    // Signing keys
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_signing_key_roundtrip() {
        let (storage, _tempdir) = setup_sqlite().await;

        let older =
            test_signing_key("key-1", chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap());
        let newer =
            test_signing_key("key-2", chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap());

        // Insert newest first to prove list ordering is not insertion order.
        storage.create_signing_key(&newer).await.unwrap();
        storage.create_signing_key(&older).await.unwrap();

        let keys = storage.list_signing_keys().await.unwrap();
        assert_eq!(keys, vec![older.clone(), newer.clone()]);

        // Duplicate kid is rejected with a primary-key violation.
        assert!(storage.create_signing_key(&older).await.is_err());
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_event_save_and_query() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        for i in 0..10 {
            let mut ev = test_event(&realm.id, EventType::Login);
            ev.id = EventId::new(uuid::Uuid::new_v4().to_string()).unwrap();
            ev.event_time = Utc::now() + chrono::Duration::milliseconds(i as i64 * 10);
            storage.save_event(&realm.id, &ev).await.unwrap();
        }

        let all = storage
            .query_events(
                &realm.id,
                &EventQuery {
                    event_type: None,
                    client_id: None,
                    user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(all.len(), 10);

        let query = EventQuery {
            event_type: Some(EventType::Login),
            client_id: None,
            user_id: None,
            date_from: None,
            date_to: None,
            pagination: Pagination { first: 0, max: 5 },
        };
        let results = storage.query_events(&realm.id, &query).await.unwrap();
        assert_eq!(results.len(), 5);
    }

    // ------------------------------------------------------------------
    // Transaction rollback on error
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn sqlite_transaction_rollback_on_invalid_session() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        // Create a session for a non-existent user - should fail at FK level
        let session =
            test_session(&realm.id, &UserId::new(uuid::Uuid::new_v4().to_string()).unwrap());
        assert!(storage.create_user_session(&realm.id, &session).await.is_err());
    }

    #[tokio::test]
    async fn sqlite_provision_marker_delete_allows_reclaim() {
        let (storage, _tempdir) = setup_sqlite().await;
        assert!(storage.claim_provision_marker("retry", "in_progress").await.unwrap());
        assert!(!storage.claim_provision_marker("retry", "in_progress").await.unwrap());
        storage.delete_provision_marker("retry").await.unwrap();
        assert_eq!(storage.get_provision_marker("retry").await.unwrap(), None);
        assert!(storage.claim_provision_marker("retry", "in_progress").await.unwrap());
    }

    #[tokio::test]
    async fn sqlite_list_and_update_operations() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        // list_realms
        let realms = storage.list_realms(&Pagination::default()).await.unwrap();
        assert_eq!(realms.len(), 1);

        // update_realm
        let mut updated_realm = realm.clone();
        updated_realm.name = RealmName::new("updated-realm").unwrap();
        storage.update_realm(&updated_realm).await.unwrap();
        let fetched = storage.get_realm(&realm.id).await.unwrap().unwrap();
        assert_eq!(fetched.name, "updated-realm");

        // User list and update
        let user = test_user(&realm.id);
        storage.create_user(&realm.id, &user).await.unwrap();
        let users = storage.list_users(&realm.id, "", &Pagination::default()).await.unwrap();
        assert_eq!(users.len(), 1);

        let mut updated_user = user.clone();
        updated_user.first_name = Some(DisplayName::new("Updated").unwrap());
        storage.update_user(&realm.id, &updated_user).await.unwrap();

        // Client list and update
        let client = test_client(&realm.id);
        storage.create_client(&realm.id, &client).await.unwrap();
        let clients = storage.list_clients(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(clients.len(), 1);

        let mut updated_client = client.clone();
        updated_client.name = Some(issuerd_core::DisplayName::new("Updated App").unwrap());
        storage.update_client(&realm.id, &updated_client).await.unwrap();

        // Role list and update
        let role = test_role(&realm.id);
        storage.create_role(&realm.id, &role).await.unwrap();
        let roles = storage.list_roles(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(roles.len(), 1);

        let mut updated_role = role.clone();
        updated_role.description = Some("Updated".to_string());
        storage.update_role(&realm.id, &updated_role).await.unwrap();

        // Group list and update
        let group = test_group(&realm.id);
        storage.create_group(&realm.id, &group).await.unwrap();
        let groups = storage.list_groups(&realm.id, &Pagination::default()).await.unwrap();
        assert_eq!(groups.len(), 1);

        let mut updated_group = group.clone();
        updated_group.path = GroupPath::new("/updated").unwrap();
        storage.update_group(&realm.id, &updated_group).await.unwrap();

        // update_user_session
        let session = test_session(&realm.id, &user.id);
        storage.create_user_session(&realm.id, &session).await.unwrap();
        let mut updated_session = session.clone();
        updated_session.ip_address = "10.0.0.1".parse().unwrap();
        storage.update_user_session(&realm.id, &updated_session).await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_user_membership_and_idp_alias() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let user = test_user(&realm.id);
        storage.create_user(&realm.id, &user).await.unwrap();

        let role = test_role(&realm.id);
        storage.create_role(&realm.id, &role).await.unwrap();

        storage.add_user_realm_role(&realm.id, &user.id, &role.id).await.unwrap();
        let roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert_eq!(roles.len(), 1);
        storage.remove_user_realm_role(&realm.id, &user.id, &role.id).await.unwrap();
        let roles = storage.list_user_realm_roles(&realm.id, &user.id).await.unwrap();
        assert!(roles.is_empty());

        let group = test_group(&realm.id);
        storage.create_group(&realm.id, &group).await.unwrap();

        storage.add_user_group(&realm.id, &user.id, &group.id).await.unwrap();
        let groups = storage.list_user_groups(&realm.id, &user.id).await.unwrap();
        assert_eq!(groups.len(), 1);
        storage.remove_user_group(&realm.id, &user.id, &group.id).await.unwrap();
        let groups = storage.list_user_groups(&realm.id, &user.id).await.unwrap();
        assert!(groups.is_empty());

        let idp = test_idp();
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();
        let by_alias = storage.get_identity_provider_by_alias(&realm.id, "google").await.unwrap();
        assert!(by_alias.is_some());

        let flows = storage.list_flow_configs(&realm.id).await.unwrap();
        // create_realm seeds the built-in browser + registration flows.
        let aliases: Vec<&str> = flows.iter().map(|f| f.alias.as_str()).collect();
        assert_eq!(aliases.len(), 2);
        assert!(aliases.contains(&"browser"));
        assert!(aliases.contains(&"registration"));
    }

    #[tokio::test]
    async fn sqlite_event_query_filters() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let client = test_client(&realm.id);
        storage.create_client(&realm.id, &client).await.unwrap();

        let user = test_user(&realm.id);
        storage.create_user(&realm.id, &user).await.unwrap();

        let mut ev1 = test_event(&realm.id, EventType::Login);
        ev1.id = EventId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        ev1.event_time = Utc::now() - chrono::Duration::hours(1);
        ev1.client_id = Some(client.id.clone());
        ev1.user_id = Some(user.id.clone());
        storage.save_event(&realm.id, &ev1).await.unwrap();

        let mut ev2 = test_event(&realm.id, EventType::Logout);
        ev2.id = EventId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        ev2.event_time = Utc::now();
        storage.save_event(&realm.id, &ev2).await.unwrap();

        let query = EventQuery {
            event_type: Some(EventType::Login),
            client_id: Some(client.id.clone()),
            user_id: Some(user.id.clone()),
            date_from: Some(Utc::now() - chrono::Duration::minutes(90)),
            date_to: Some(Utc::now() - chrono::Duration::minutes(30)),
            pagination: Pagination::default(),
        };
        let results = storage.query_events(&realm.id, &query).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_update_not_found_errors() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        let mut realm_unknown = realm.clone();
        realm_unknown.id = RealmId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert_eq!(storage.update_realm(&realm_unknown).await.unwrap_err(), IssuerdError::NotFound);

        let user = test_user(&realm.id);
        let mut user_unknown = user.clone();
        user_unknown.id = UserId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert_eq!(
            storage.update_user(&realm.id, &user_unknown).await.unwrap_err(),
            IssuerdError::NotFound
        );

        let client = test_client(&realm.id);
        let mut client_unknown = client.clone();
        client_unknown.id = ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert_eq!(
            storage.update_client(&realm.id, &client_unknown).await.unwrap_err(),
            IssuerdError::NotFound
        );

        let role = test_role(&realm.id);
        let mut role_unknown = role.clone();
        role_unknown.id = RoleId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert_eq!(
            storage.update_role(&realm.id, &role_unknown).await.unwrap_err(),
            IssuerdError::NotFound
        );

        let group = test_group(&realm.id);
        let mut group_unknown = group.clone();
        group_unknown.id = GroupId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert_eq!(
            storage.update_group(&realm.id, &group_unknown).await.unwrap_err(),
            IssuerdError::NotFound
        );

        let session = test_session(&realm.id, &user.id);
        let mut session_unknown = session.clone();
        session_unknown.id = SessionId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert_eq!(
            storage.update_user_session(&realm.id, &session_unknown).await.unwrap_err(),
            IssuerdError::NotFound
        );

        let idp = test_idp();
        let mut idp_unknown = idp.clone();
        idp_unknown.id = IdentityProviderId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert_eq!(
            storage.update_identity_provider(&realm.id, &idp_unknown).await.unwrap_err(),
            IssuerdError::NotFound
        );

        let flow = test_flow_config(&realm.id);
        let mut flow_unknown = flow.clone();
        flow_unknown.alias = Alias::new("unknown").unwrap();
        assert_eq!(
            storage.update_flow_config(&realm.id, &flow_unknown).await.unwrap_err(),
            IssuerdError::NotFound
        );
    }

    #[test]
    fn to_uuid_valid() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        assert!(to_uuid(uuid_str).is_ok());
    }

    #[test]
    fn to_uuid_invalid() {
        let result = to_uuid("not-a-uuid");
        assert!(result.is_err());
    }

    #[test]
    fn sqlx_err_row_not_found() {
        let err = sqlx_err(sqlx::Error::RowNotFound);
        assert_eq!(err, IssuerdError::NotFound);
    }

    #[test]
    fn sqlx_err_generic() {
        let io_err = std::io::Error::other("test error");
        let err = sqlx_err(sqlx::Error::Io(io_err));
        assert!(matches!(err, IssuerdError::ServerError(_)));
    }

    #[tokio::test]
    async fn sqlite_uuid_bindings_are_blob_and_survive_reconnect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuerd.db");
        let realm = test_realm();
        let user = test_user(&realm.id);
        {
            let storage = SqliteStorage::connect(&path).await.unwrap();
            storage.run_migrations().await.unwrap();
            storage.create_realm(&realm).await.unwrap();
            storage.create_user(&realm.id, &user).await.unwrap();

            let (id_type, id_len, realm_type): (String, i64, String) = sqlx::query_as(
                "SELECT typeof(u.id), length(u.id), typeof(u.realm_id) \
                 FROM users u WHERE u.id = ? AND u.realm_id = ?",
            )
            .bind(to_uuid(user.id.as_ref()).unwrap())
            .bind(to_uuid(realm.id.as_ref()).unwrap())
            .fetch_one(storage.pool())
            .await
            .unwrap();
            assert_eq!(id_type, "blob");
            assert_eq!(id_len, 16);
            assert_eq!(realm_type, "blob");
            storage.pool().close().await;
        }
        {
            let storage = SqliteStorage::connect(&path).await.unwrap();
            let persisted = storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
            assert_eq!(persisted.id, user.id);
            assert_eq!(persisted.realm_id, realm.id);
        }
    }

    #[tokio::test]
    async fn sqlite_invalid_uuid_is_rejected_before_query_execution() {
        let (storage, _tempdir) = setup_sqlite().await;
        let error = storage.get_realm(&RealmId::new("not-a-uuid").unwrap()).await.unwrap_err();
        assert!(matches!(error, IssuerdError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn sqlite_provision_claim_has_one_winner_across_connections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuerd.db");
        let first = std::sync::Arc::new(SqliteStorage::connect(&path).await.unwrap());
        first.run_migrations().await.unwrap();
        let second = std::sync::Arc::new(SqliteStorage::connect(&path).await.unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        for attempt in 0..16 {
            let storage = if attempt % 2 == 0 {
                std::sync::Arc::clone(&first)
            } else {
                std::sync::Arc::clone(&second)
            };
            tasks.spawn(async move {
                storage.claim_provision_marker("shared", "completed").await.unwrap()
            });
        }
        let mut winners = 0;
        while let Some(result) = tasks.join_next().await {
            winners += usize::from(result.unwrap());
        }
        assert_eq!(winners, 1);
        assert_eq!(
            first.get_provision_marker("shared").await.unwrap().as_deref(),
            Some("completed")
        );
    }

    #[tokio::test]
    async fn sqlite_concurrent_builtin_scope_backfill_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuerd.db");
        let first = SqliteStorage::connect(&path).await.unwrap();
        first.run_migrations().await.unwrap();
        let second = SqliteStorage::connect(&path).await.unwrap();
        let realm = test_realm();
        first.create_realm(&realm).await.unwrap();
        for name in [MCP_SCOPE_READ, MCP_SCOPE_WRITE] {
            let scope = first.get_client_scope_by_name(&realm.id, name).await.unwrap().unwrap();
            first.delete_client_scope(&realm.id, &scope.id).await.unwrap();
        }

        let (a, b) = tokio::join!(
            crate::seed::seed_builtin_client_scopes(&first, &realm.id),
            crate::seed::seed_builtin_client_scopes(&second, &realm.id),
        );
        a.unwrap();
        b.unwrap();
        let scopes = first
            .list_client_scopes(&realm.id, &Pagination::new(0, i32::MAX))
            .await
            .unwrap();
        assert_eq!(scopes.len(), 11);
    }

    #[tokio::test]
    async fn sqlite_mcp_backfill_rejects_legacy_default_assignment() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let mut client = test_client(&realm.id);
        client.default_scopes = Scope::parse("openid mcp:write");
        storage.create_client(&realm.id, &client).await.unwrap();
        storage.run_migrations().await.unwrap();

        let err = crate::seed::validate_mcp_scope_policy(&storage).await.unwrap_err();
        assert!(err.to_string().contains("default list"));
    }

    #[tokio::test]
    async fn sqlite_connect_rejects_a_directory_path() {
        let dir = tempfile::tempdir().unwrap();
        let result = SqliteStorage::connect(dir.path()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sqlite_bulk_users_are_chunked_searchable_and_atomic() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        assert_eq!(storage.count_realms().await.unwrap(), 1);

        let template = test_user(&realm.id);
        let users: Vec<User> = (0..125)
            .map(|index| {
                let mut user = template.clone();
                user.id = UserId::new(uuid::Uuid::new_v4().to_string()).unwrap();
                user.username = Username::new(format!("alice-{index:03}")).unwrap();
                user.email = Some(Email::new(format!("alice-{index:03}@example.com")).unwrap());
                if index == 0 {
                    user.federation_link = Some("ldap-directory".into());
                }
                user
            })
            .collect();
        storage.bulk_create_users(&realm.id, &users).await.unwrap();
        assert_eq!(storage.count_users(&realm.id, "").await.unwrap(), 125);
        assert_eq!(storage.count_users(&realm.id, "ALICE-01").await.unwrap(), 10);
        assert_eq!(
            storage
                .get_user_by_federation_link(&realm.id, "ldap-directory")
                .await
                .unwrap()
                .len(),
            1
        );

        let mut new_user = template.clone();
        new_user.id = UserId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        new_user.username = Username::new("must-rollback").unwrap();
        let new_id = new_user.id.clone();
        let error = storage
            .bulk_create_users(&realm.id, &[new_user, users[0].clone()])
            .await
            .unwrap_err();
        assert_eq!(error, IssuerdError::Conflict);
        assert_eq!(storage.count_users(&realm.id, "").await.unwrap(), 125);
        assert!(storage.get_user(&realm.id, &new_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sqlite_client_role_and_scope_batch_contract() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let template = test_client(&realm.id);
        let clients: Vec<Client> = (0..3)
            .map(|index| {
                let mut client = template.clone();
                client.id = ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap();
                client.client_id = ClientIdentifier::new(format!("app-{index}")).unwrap();
                client
            })
            .collect();
        for client in &clients {
            storage.create_client(&realm.id, client).await.unwrap();
        }
        assert_eq!(storage.count_clients(&realm.id).await.unwrap(), 3);

        let unknown_client = ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        let requested = vec![
            clients[2].id.clone(),
            clients[0].id.clone(),
            unknown_client,
            clients[2].id.clone(),
        ];
        let found = storage.get_clients_batch(&realm.id, &requested).await.unwrap();
        let found_ids: Vec<ClientId> = found.into_iter().map(|client| client.id).collect();
        assert_eq!(
            found_ids,
            vec![
                clients[2].id.clone(),
                clients[0].id.clone(),
                clients[2].id.clone()
            ]
        );

        let mut roles = Vec::new();
        for name in ["writer", "reader"] {
            let mut role = test_role(&realm.id);
            role.id = RoleId::new(uuid::Uuid::new_v4().to_string()).unwrap();
            role.name = RoleName::new(name).unwrap();
            role.client_role = true;
            role.client_id = Some(clients[0].id.clone());
            storage.create_role(&realm.id, &role).await.unwrap();
            roles.push(role);
        }
        assert_eq!(storage.count_roles(&realm.id).await.unwrap(), 2);
        assert_eq!(
            storage
                .get_client_role_by_name(&realm.id, &clients[0].id, "reader")
                .await
                .unwrap()
                .unwrap()
                .id,
            roles[1].id
        );
        let names = vec![
            "writer".to_string(),
            "missing".to_string(),
            "reader".to_string(),
        ];
        let found = storage
            .get_client_roles_by_names(&realm.id, &clients[0].id, &names)
            .await
            .unwrap();
        let found_names: Vec<String> =
            found.into_iter().map(|role| role.name.to_string()).collect();
        assert_eq!(found_names, vec!["writer", "reader"]);
        assert_eq!(
            storage
                .list_client_roles(&realm.id, &clients[0].id, &Pagination::default())
                .await
                .unwrap()
                .len(),
            2
        );

        let scope = ClientScope {
            id: ClientScopeId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm.id.clone(),
            name: "custom".into(),
            description: Some("before".into()),
            protocol: ClientProtocol::OpenIdConnect,
            attributes: HashMap::new(),
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
        };
        storage.create_client_scope(&realm.id, &scope).await.unwrap();
        let mut updated_scope = scope.clone();
        updated_scope.description = Some("after".into());
        storage.update_client_scope(&realm.id, &updated_scope).await.unwrap();
        assert_eq!(
            storage
                .get_client_scope(&realm.id, &scope.id)
                .await
                .unwrap()
                .unwrap()
                .description
                .as_deref(),
            Some("after")
        );
        assert_eq!(
            storage
                .get_client_scopes_by_names(&realm.id, &["custom".into(), "missing".into()])
                .await
                .unwrap()
                .len(),
            1
        );
        let unknown_scope = ClientScopeId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        let found = storage
            .get_client_scopes_by_ids(&realm.id, &[scope.id.clone(), unknown_scope])
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, scope.id);

        storage
            .assign_client_scope(&realm.id, &clients[0].id, &scope.id, true)
            .await
            .unwrap();
        storage
            .assign_client_scope(&realm.id, &clients[0].id, &scope.id, false)
            .await
            .unwrap();
        let assignments =
            storage.list_client_scope_assignments(&realm.id, &clients[0].id).await.unwrap();
        assert!(assignments.contains(&(scope.id.clone(), false)));
        storage
            .add_realm_default_client_scope(&realm.id, &scope.id, true)
            .await
            .unwrap();
        assert!(storage
            .list_realm_default_client_scopes(&realm.id)
            .await
            .unwrap()
            .contains(&(scope.id.clone(), true)));
        storage.delete_client_scope(&realm.id, &scope.id).await.unwrap();
        assert!(!storage
            .list_client_scope_assignments(&realm.id, &clients[0].id)
            .await
            .unwrap()
            .iter()
            .any(|(id, _)| id == &scope.id));
        assert!(!storage
            .list_realm_default_client_scopes(&realm.id)
            .await
            .unwrap()
            .iter()
            .any(|(id, _)| id == &scope.id));
        storage
            .unassign_client_scope(&realm.id, &clients[0].id, &scope.id)
            .await
            .unwrap();
        storage.remove_realm_default_client_scope(&realm.id, &scope.id).await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_group_batch_chunks_and_reverse_membership() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let template = test_group(&realm.id);
        let mut ids = Vec::new();
        for index in 0..501 {
            let mut group = template.clone();
            group.id = GroupId::new(uuid::Uuid::new_v4().to_string()).unwrap();
            group.name = GroupName::new(format!("group-{index:03}")).unwrap();
            group.path = GroupPath::new(format!("/group-{index:03}")).unwrap();
            storage.create_group(&realm.id, &group).await.unwrap();
            ids.push(group.id);
        }
        assert_eq!(storage.count_groups(&realm.id).await.unwrap(), 501);
        assert_eq!(
            storage.list_groups(&realm.id, &Pagination::new(0, 10)).await.unwrap().len(),
            10
        );
        assert!(storage.get_group_by_name(&realm.id, "group-250").await.unwrap().is_some());

        let mut requested: Vec<GroupId> = ids.iter().rev().cloned().collect();
        requested.push(GroupId::new(uuid::Uuid::new_v4().to_string()).unwrap());
        let found = storage.get_groups_batch(&realm.id, &requested).await.unwrap();
        assert_eq!(found.len(), 501);
        assert_eq!(found[0].id, ids[500]);
        assert_eq!(found[500].id, ids[0]);

        let user = test_user(&realm.id);
        storage.create_user(&realm.id, &user).await.unwrap();
        storage.add_user_group(&realm.id, &user.id, &ids[0]).await.unwrap();
        let members = storage.list_group_members(&realm.id, &ids[0], 0, 1).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].id, user.id);
        assert!(storage.list_group_members(&realm.id, &ids[0], 1, 1).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn sqlite_links_events_sessions_and_signing_key_updates() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let user = test_user(&realm.id);
        storage.create_user(&realm.id, &user).await.unwrap();
        let idp = test_idp();
        storage.create_identity_provider(&realm.id, &idp).await.unwrap();
        let link = IdentityProviderLink {
            user_id: user.id.clone(),
            provider_alias: idp.alias.to_string(),
            external_subject: "external-subject".into(),
            external_username: Some("external-user".into()),
            stored_refresh_token: None,
            created_at: Utc::now(),
        };
        storage.create_identity_provider_link(&realm.id, &link).await.unwrap();
        assert!(storage
            .get_identity_provider_link(&realm.id, idp.alias.as_ref(), "external-subject")
            .await
            .unwrap()
            .is_some());
        assert!(storage
            .get_identity_provider_link_for_user(&realm.id, &user.id, idp.alias.as_ref())
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            storage.list_identity_provider_links(&realm.id, &user.id).await.unwrap().len(),
            1
        );
        storage
            .delete_identity_provider_link(&realm.id, &user.id, idp.alias.as_ref())
            .await
            .unwrap();
        assert!(storage
            .list_identity_provider_links(&realm.id, &user.id)
            .await
            .unwrap()
            .is_empty());

        let credential = test_credential();
        storage.create_credential(&realm.id, &user.id, &credential).await.unwrap();
        assert_eq!(storage.list_credentials(&realm.id, &user.id).await.unwrap().len(), 1);

        let session = test_session(&realm.id, &user.id);
        storage.create_user_session(&realm.id, &session).await.unwrap();
        assert_eq!(storage.count_sessions(&realm.id, None).await.unwrap(), 1);
        assert_eq!(storage.count_sessions(&realm.id, Some(user.id.clone())).await.unwrap(), 1);
        let other_user = UserId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        assert_eq!(storage.count_sessions(&realm.id, Some(other_user)).await.unwrap(), 0);
        assert_eq!(
            storage
                .list_sessions(&realm.id, None, &Pagination::default())
                .await
                .unwrap()
                .len(),
            1
        );

        let event = test_event(&realm.id, EventType::Login);
        storage.save_event(&realm.id, &event).await.unwrap();
        let event_query = EventQuery {
            event_type: None,
            client_id: None,
            user_id: None,
            date_from: None,
            date_to: None,
            pagination: Pagination::default(),
        };
        assert_eq!(storage.count_events(&realm.id, &event_query).await.unwrap(), 1);
        storage.delete_events(&realm.id).await.unwrap();
        assert_eq!(storage.count_events(&realm.id, &event_query).await.unwrap(), 0);

        let admin_event = AdminEvent {
            id: EventId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm.id.clone(),
            auth_realm_id: Some(realm.id.clone()),
            auth_client_id: Some(ClientId::new("admin-cli").unwrap()),
            auth_user_id: Some(user.id.clone()),
            operation_type: OperationType::Create,
            resource_type: ResourceType::User,
            resource_path: format!("users/{}", user.id),
            representation: None,
            error: None,
            event_time: Utc::now(),
        };
        storage.save_admin_event(&admin_event).await.unwrap();
        let admin_query = AdminEventQuery {
            operation_type: Some(OperationType::Create),
            resource_type: Some(ResourceType::User),
            auth_user_id: Some(user.id.clone()),
            date_from: Some(Utc::now() - chrono::Duration::minutes(1)),
            date_to: Some(Utc::now() + chrono::Duration::minutes(1)),
            pagination: Pagination::default(),
        };
        assert_eq!(storage.query_admin_events(&realm.id, &admin_query).await.unwrap().len(), 1);
        assert_eq!(storage.count_admin_events(&realm.id, &admin_query).await.unwrap(), 1);
        let (client_id_type, client_id): (String, String) = sqlx::query_as(
            "SELECT typeof(auth_client_id), auth_client_id FROM admin_events WHERE id = ?1",
        )
        .bind(to_uuid(admin_event.id.as_ref()).unwrap())
        .fetch_one(storage.pool())
        .await
        .unwrap();
        assert_eq!(client_id_type, "text");
        assert_eq!(client_id, "admin-cli");
        storage.delete_admin_events(&realm.id).await.unwrap();
        let all_admin_events = AdminEventQuery {
            operation_type: None,
            resource_type: None,
            auth_user_id: None,
            date_from: None,
            date_to: None,
            pagination: Pagination::default(),
        };
        assert_eq!(storage.count_admin_events(&realm.id, &all_admin_events).await.unwrap(), 0);

        let mut key = test_signing_key("rotation", Utc::now());
        storage.create_signing_key(&key).await.unwrap();
        key.active = false;
        storage.update_signing_key(&key).await.unwrap();
        assert!(!storage.list_signing_keys().await.unwrap()[0].active);
        key.kid = KeyId::new("missing").unwrap();
        assert_eq!(storage.update_signing_key(&key).await.unwrap_err(), IssuerdError::NotFound);
    }

    #[tokio::test]
    async fn sqlite_internal_ids_use_typed_blob_columns() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        let user = test_user(&realm.id);
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();

        let mut consent = test_consent();
        consent.user_id = user.id.clone();
        consent.client_id = ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        storage.create_consent(&realm.id, &consent).await.unwrap();
        let (client_type,): (String,) = sqlx::query_as(
            "SELECT typeof(client_id) FROM consents WHERE realm_id = ?1 AND user_id = ?2",
        )
        .bind(to_uuid(realm.id.as_ref()).unwrap())
        .bind(to_uuid(user.id.as_ref()).unwrap())
        .fetch_one(storage.pool())
        .await
        .unwrap();
        assert_eq!(client_type, "blob");
        let mut invalid_consent = consent.clone();
        invalid_consent.client_id = ClientId::new("not-a-uuid").unwrap();
        assert!(matches!(
            storage.create_consent(&realm.id, &invalid_consent).await,
            Err(IssuerdError::ServerError(_))
        ));

        let impersonator = UserId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        let mut session = test_session(&realm.id, &user.id);
        session.impersonator = Some(impersonator.clone());
        storage.create_user_session(&realm.id, &session).await.unwrap();
        assert_eq!(
            storage
                .get_user_session(&realm.id, &session.id)
                .await
                .unwrap()
                .unwrap()
                .impersonator,
            Some(impersonator)
        );
        let (impersonator_type,): (String,) =
            sqlx::query_as("SELECT typeof(impersonator) FROM user_sessions WHERE id = ?1")
                .bind(to_uuid(session.id.as_ref()).unwrap())
                .fetch_one(storage.pool())
                .await
                .unwrap();
        assert_eq!(impersonator_type, "blob");

        let mut invalid_session = test_session(&realm.id, &user.id);
        invalid_session.impersonator = Some(UserId::new("not-a-uuid").unwrap());
        assert!(matches!(
            storage.create_user_session(&realm.id, &invalid_session).await,
            Err(IssuerdError::ServerError(_))
        ));
        assert!(storage
            .get_user_session(&realm.id, &invalid_session.id)
            .await
            .unwrap()
            .is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sqlite_files_are_owner_only_on_create_and_reopen() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuerd.db");
        let storage = SqliteStorage::connect(&path).await.unwrap();
        storage.run_migrations().await.unwrap();

        let sidecar = |suffix: &str| {
            let mut value = path.as_os_str().to_os_string();
            value.push(suffix);
            PathBuf::from(value)
        };
        let assert_owner_only = |path: &Path| {
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "unexpected mode for {path:?}");
        };
        for file in [&path, &sidecar("-wal"), &sidecar("-shm")] {
            assert_owner_only(file);
        }

        for file in [&path, &sidecar("-wal"), &sidecar("-shm")] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        storage.run_migrations().await.unwrap();
        for file in [&path, &sidecar("-wal"), &sidecar("-shm")] {
            assert_owner_only(file);
        }
    }

    #[tokio::test]
    async fn sqlite_unicode_search_covers_all_write_paths_and_backfill() {
        let (storage, _tempdir) = setup_sqlite().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let mut user = test_user(&realm.id);
        user.username = Username::new("Алиса").unwrap();
        user.email = Some(Email::new("Mixed@Example.COM").unwrap());
        storage.create_user(&realm.id, &user).await.unwrap();
        assert_eq!(storage.count_users(&realm.id, "алиса").await.unwrap(), 1);
        assert_eq!(storage.count_users(&realm.id, "MIXED@example.com").await.unwrap(), 1);
        assert_eq!(
            storage
                .list_users(&realm.id, "АЛИСА", &Pagination::default())
                .await
                .unwrap()
                .len(),
            1
        );

        sqlx::query("UPDATE users SET username_search = '', email_search = NULL WHERE id = ?1")
            .bind(to_uuid(user.id.as_ref()).unwrap())
            .execute(storage.pool())
            .await
            .unwrap();
        assert_eq!(storage.count_users(&realm.id, "алиса").await.unwrap(), 0);
        storage.run_migrations().await.unwrap();
        assert_eq!(storage.count_users(&realm.id, "алиса").await.unwrap(), 1);
        assert_eq!(storage.count_users(&realm.id, "MIXED@example.com").await.unwrap(), 1);

        let mut renamed = user.clone();
        renamed.username = Username::new("Другая").unwrap();
        storage.update_user(&realm.id, &renamed).await.unwrap();
        assert_eq!(storage.count_users(&realm.id, "ДРУГАЯ").await.unwrap(), 1);

        let mut bulk = test_user(&realm.id);
        bulk.id = UserId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        bulk.username = Username::new("Борис").unwrap();
        storage.bulk_create_users(&realm.id, &[bulk]).await.unwrap();
        assert_eq!(storage.count_users(&realm.id, "БОРИС").await.unwrap(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sqlite_write_retries_after_external_lock_is_released() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuerd.db");
        let storage = SqliteStorage::connect(&path).await.unwrap();
        storage.run_migrations().await.unwrap();
        let options = SqliteConnectOptions::new().filename(&path);
        let lock_pool =
            SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        let lock = lock_pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(7)).await;
            lock.commit().await.unwrap();
        });

        let started = std::time::Instant::now();
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(5),
            "first lock timeout was not exercised: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(20), "retry budget was not bounded: {elapsed:?}");
        release.await.unwrap();
        assert!(storage.get_realm(&realm.id).await.unwrap().is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sqlite_non_regular_paths_are_rejected_without_chmod() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let original_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        let result = SqliteStorage::connect(dir.path()).await;
        assert!(matches!(result, Err(IssuerdError::InvalidRequest(_))));
        assert_eq!(std::fs::metadata(dir.path()).unwrap().permissions().mode(), original_mode);

        let target = dir.path().join("target.db");
        std::fs::write(&target, b"not a database").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("linked.db");
        symlink(&target, &link).unwrap();
        let result = SqliteStorage::connect(&link).await;
        assert!(matches!(result, Err(IssuerdError::InvalidRequest(_))));
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o644);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sqlite_schema_migrations_retry_after_external_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuerd.db");
        let storage = SqliteStorage::connect(&path).await.unwrap();
        let options = SqliteConnectOptions::new().filename(&path);
        let lock_pool =
            SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        let lock = lock_pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(7)).await;
            lock.commit().await.unwrap();
        });

        storage.run_migrations().await.unwrap();
        release.await.unwrap();
        let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
            .fetch_one(storage.pool())
            .await
            .unwrap();
        assert_eq!(version, 20);
    }

    #[tokio::test]
    async fn sqlite_busy_retry_exhaustion_is_temporarily_unavailable() {
        let error = with_busy_retry(|| async {
            Err::<(), _>(IssuerdError::ServerError(SQLITE_BUSY.into()))
        })
        .await
        .unwrap_err();
        assert_eq!(error, IssuerdError::TemporarilyUnavailable);
    }
}
