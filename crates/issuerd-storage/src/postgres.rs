// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// PostgreSQL storage adapter (sqlx).

use async_trait::async_trait;
// chrono unused at top level; used via db_types
use issuerd_core::*;
use sqlx::PgPool;
use tracing::{error, info, instrument};

use crate::db_types::*;

/// PostgreSQL storage adapter.
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    #[instrument(skip_all)]
    pub async fn connect(database_url: &str) -> Result<Self, IssuerdError> {
        info!("connecting to PostgreSQL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await
            .map_err(|e| {
                error!(error = %e, "PostgreSQL connection failed");
                IssuerdError::ServerError(format!("db connect failed: {e}"))
            })?;
        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<(), IssuerdError> {
        crate::migration::run_migrations(&self.pool).await?;
        // Data migration: realms/clients that predate the
        // client_scopes tables get the built-in scopes and per-client
        // assignments seeded (idempotent — also covers a plain restart).
        let realms = self.list_realms(&Pagination::new(0, i32::MAX)).await?;
        for realm in realms {
            crate::seed::seed_builtin_client_scopes(self, &realm.id).await?;
            // Realms that predate flow seeding get the built-in
            // browser + registration flows backfilled (idempotent).
            crate::seed::seed_builtin_flows(self, &realm.id).await?;
            // Realms that predate pairwise subjects get the
            // sector key backfilled (idempotent).
            crate::seed::backfill_pairwise_sector_key(self, &realm.id).await?;
            let clients = self.list_clients(&realm.id, &Pagination::new(0, i32::MAX)).await?;
            for client in clients {
                crate::seed::seed_client_scope_assignments(self, &realm.id, &client).await?;
            }
        }
        Ok(())
    }

    fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn sqlx_err(e: sqlx::Error) -> IssuerdError {
    match e {
        // SQLSTATE 23505: unique_violation.
        sqlx::Error::Database(ref db) if db.code().as_deref() == Some("23505") => {
            IssuerdError::Conflict
        }
        sqlx::Error::Database(ref db) if db.constraint().is_some() => {
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
impl Storage for PostgresStorage {
    // ------------------------------------------------------------------
    // Realm
    // ------------------------------------------------------------------
    async fn get_realm(&self, id: &RealmId) -> Result<Option<Realm>, IssuerdError> {
        let pg: Option<PgRealm> = sqlx::query_as("SELECT * FROM realms WHERE id = $1")
            .bind(to_uuid(id.as_ref())?)
            .fetch_optional(self.pool())
            .await
            .map_err(sqlx_err)?;
        pg.map(|r| r.try_into()).transpose()
    }

    async fn get_realm_by_name(&self, name: &str) -> Result<Option<Realm>, IssuerdError> {
        let pg: Option<PgRealm> = sqlx::query_as("SELECT * FROM realms WHERE name = $1")
            .bind(name)
            .fetch_optional(self.pool())
            .await
            .map_err(sqlx_err)?;
        pg.map(|r| r.try_into()).transpose()
    }

    async fn list_realms(&self, pagination: &Pagination) -> Result<Vec<Realm>, IssuerdError> {
        let rows: Vec<PgRealm> =
            sqlx::query_as("SELECT * FROM realms ORDER BY name LIMIT $1 OFFSET $2")
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
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
                $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38,
                $39, $40, $41, $42, $43, $44, $45, $46, $47, $48
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
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
        let result = sqlx::query(
            r#"UPDATE realms SET
                name = $2, display_name = $3, enabled = $4, ssl_required = $5,
                password_policy = $6, login_theme = $7, email_theme = $8,
                admin_theme = $9, default_role = $10,
                access_token_lifespan = $11, refresh_token_lifespan = $12,
                sso_session_idle_timeout = $13, sso_session_max_lifespan = $14,
                offline_session_idle_timeout = $15,
                brute_force_protected = $16, max_login_failures = $17,
                wait_increment_secs = $18, max_failure_wait_secs = $19,
                lockout_duration_secs = $20,
                registration_enabled = $21, reset_password_allowed = $22,
                remember_me_enabled = $23, verify_email_enabled = $24,
                login_with_email_allowed = $25, duplicate_emails_allowed = $26,
                edit_username_allowed = $27,
                remember_me_session_idle_secs = $28,
                otp_algorithm = $29, otp_digits = $30,
                otp_period_secs = $31, otp_look_ahead_window = $32,
                attributes = $33,
                internationalization_enabled = $34, supported_locales = $35,
                default_locale = $36,
                events_enabled = $37, events_expiration_secs = $38,
                admin_events_enabled = $39, include_representations = $40,
                events_listeners = $41, not_before = $42, default_groups = $43,
                browser_flow = $44, direct_grant_flow = $45,
                reset_credentials_flow = $46, first_broker_login_flow = $47,
                registration_flow = $48,
                updated_at = now()
            WHERE id = $1"#,
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;

        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_realm(&self, id: &RealmId) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM realms WHERE id = $1")
            .bind(to_uuid(id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // User
    // ------------------------------------------------------------------
    async fn get_user(&self, realm: &RealmId, id: &UserId) -> Result<Option<User>, IssuerdError> {
        let pg: Option<PgUser> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = $1 AND id = $2")
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
            sqlx::query_as("SELECT * FROM users WHERE realm_id = $1 AND username = $2")
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
            sqlx::query_as("SELECT * FROM users WHERE realm_id = $1 AND email = $2")
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
            sqlx::query_as("SELECT * FROM users WHERE realm_id = $1 AND federation_link = $2")
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
            format!("%{query}%")
        };
        let rows: Vec<PgUser> = sqlx::query_as(
            "SELECT * FROM users WHERE realm_id = $1 AND (username ILIKE $2 OR email ILIKE $2) ORDER BY username LIMIT $3 OFFSET $4",
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
            format!("%{query}%")
        };
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE realm_id = $1 AND (username ILIKE $2 OR email ILIKE $2)",
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
        sqlx::query(
            r#"INSERT INTO users (
                id, realm_id, username, email, email_verified,
                first_name, last_name, enabled, federation_link, attributes,
                required_actions, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn bulk_create_users(&self, realm: &RealmId, users: &[User]) -> Result<(), IssuerdError> {
        if users.is_empty() {
            return Ok(());
        }
        let realm_uuid = to_uuid(realm.as_ref())?;
        let mut ids = Vec::with_capacity(users.len());
        let mut realm_ids = Vec::with_capacity(users.len());
        let mut usernames = Vec::with_capacity(users.len());
        let mut emails = Vec::with_capacity(users.len());
        let mut email_verified = Vec::with_capacity(users.len());
        let mut first_names = Vec::with_capacity(users.len());
        let mut last_names = Vec::with_capacity(users.len());
        let mut enabled = Vec::with_capacity(users.len());
        let mut federation_links = Vec::with_capacity(users.len());
        let mut attributes = Vec::with_capacity(users.len());
        let mut required_actions = Vec::with_capacity(users.len());
        let mut updated_ats = Vec::with_capacity(users.len());
        for user in users {
            let pg: PgUser = user.try_into()?;
            ids.push(pg.id);
            realm_ids.push(realm_uuid);
            usernames.push(pg.username);
            emails.push(pg.email);
            email_verified.push(pg.email_verified);
            first_names.push(pg.first_name);
            last_names.push(pg.last_name);
            enabled.push(pg.enabled);
            federation_links.push(pg.federation_link);
            attributes.push(pg.attributes);
            required_actions.push(pg.required_actions);
            updated_ats.push(pg.created_at);
        }
        sqlx::query(
            r#"INSERT INTO users (
                id, realm_id, username, email, email_verified,
                first_name, last_name, enabled, federation_link, attributes,
                required_actions, updated_at
            )
            SELECT * FROM UNNEST($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
        )
        .bind(&ids)
        .bind(&realm_ids)
        .bind(&usernames)
        .bind(&emails)
        .bind(&email_verified)
        .bind(&first_names)
        .bind(&last_names)
        .bind(&enabled)
        .bind(&federation_links)
        .bind(&attributes)
        .bind(&required_actions)
        .bind(&updated_ats)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_user(&self, realm: &RealmId, user: &User) -> Result<(), IssuerdError> {
        let pg: PgUser = user.try_into()?;
        let result = sqlx::query(
            r#"UPDATE users SET
                username = $3, email = $4, email_verified = $5,
                first_name = $6, last_name = $7, enabled = $8,
                federation_link = $9, attributes = $10, required_actions = $11,
                updated_at = now()
            WHERE realm_id = $1 AND id = $2"#,
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_user(&self, realm: &RealmId, id: &UserId) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM users WHERE realm_id = $1 AND id = $2")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
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
            sqlx::query_as("SELECT * FROM clients WHERE realm_id = $1 AND id = $2")
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
            sqlx::query_as("SELECT * FROM clients WHERE realm_id = $1 AND client_id = $2")
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
        let uuids = ids.iter().map(|id| to_uuid(id.as_ref())).collect::<Result<Vec<_>, _>>()?;
        let rows: Vec<PgClient> =
            sqlx::query_as("SELECT * FROM clients WHERE realm_id = $1 AND id = ANY($2)")
                .bind(to_uuid(realm.as_ref())?)
                .bind(&uuids)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        let clients: Vec<Client> =
            rows.into_iter().map(|c| c.try_into()).collect::<Result<_, _>>()?;
        // ANY() does not preserve input order; restore it in Rust (unknown
        // ids are absent from the result set and get skipped).
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
            "SELECT * FROM clients WHERE realm_id = $1 ORDER BY client_id LIMIT $2 OFFSET $3",
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
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM clients WHERE realm_id = $1")
            .bind(to_uuid(realm.as_ref())?)
            .fetch_one(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(count)
    }

    async fn create_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError> {
        let mut pg: PgClient = client.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        sqlx::query(
            r#"INSERT INTO clients (
                id, realm_id, client_id, name, description, enabled, protocol,
                public_client, bearer_only, client_authenticator_type, secret,
                redirect_uris, web_origins, default_scopes, optional_scopes,
                consent_required, full_scope_allowed, service_accounts_enabled,
                protocol_mappers, scope_mappings, attributes
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)"#,
        )
        .bind(pg.id)
        .bind(pg.realm_id)
        .bind(pg.client_id)
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        // Seed scope assignments from the client's legacy
        // default/optional scope string lists (plus the `roles` carve-out).
        crate::seed::seed_client_scope_assignments(self, realm, client).await?;
        Ok(())
    }

    async fn update_client(&self, realm: &RealmId, client: &Client) -> Result<(), IssuerdError> {
        let pg: PgClient = client.try_into()?;
        let result = sqlx::query(
            r#"UPDATE clients SET
                client_id = $3, name = $4, description = $5, enabled = $6,
                protocol = $7, public_client = $8, bearer_only = $9,
                client_authenticator_type = $10, secret = $11,
                redirect_uris = $12, web_origins = $13, default_scopes = $14,
                optional_scopes = $15, consent_required = $16,
                full_scope_allowed = $17, service_accounts_enabled = $18,
                protocol_mappers = $19, scope_mappings = $20, attributes = $21
            WHERE realm_id = $1 AND id = $2"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(pg.id)
        .bind(pg.client_id)
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_client(&self, realm: &RealmId, id: &ClientId) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM clients WHERE realm_id = $1 AND id = $2")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
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
            "SELECT * FROM credentials WHERE realm_id = $1 AND user_id = $2 AND credential_type = $3 ORDER BY priority",
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
            "SELECT * FROM credentials WHERE realm_id = $1 AND user_id = $2 ORDER BY credential_type, priority",
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
        sqlx::query(
            r#"INSERT INTO credentials (
                id, realm_id, user_id, credential_type, user_label, created_date,
                secret_data, credential_data, priority
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred: &Credential,
    ) -> Result<(), IssuerdError> {
        let pg: PgCredential = cred.try_into()?;
        let result = sqlx::query(
            r#"UPDATE credentials SET
                credential_type = $4, user_label = $5, created_date = $6,
                secret_data = $7, credential_data = $8, priority = $9
            WHERE realm_id = $1 AND user_id = $2 AND id = $3"#,
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_credential(
        &self,
        realm: &RealmId,
        user: &UserId,
        cred_id: &CredentialId,
    ) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND id = $3")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(user.as_ref())?)
            .bind(to_uuid(cred_id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
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
        let pg: Option<PgUserSession> =
            sqlx::query_as("SELECT * FROM user_sessions WHERE realm_id = $1 AND id = $2")
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
            sqlx::query_as("SELECT * FROM client_sessions WHERE session_id = $1")
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
        let rows: Vec<PgUserSession> = sqlx::query_as(
            r#"SELECT * FROM user_sessions
               WHERE realm_id = $1
                 AND ($2::uuid IS NULL OR user_id = $2)
               ORDER BY last_session_refresh DESC
               LIMIT $3 OFFSET $4"#,
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
            let clients: Vec<PgClientSession> =
                sqlx::query_as("SELECT * FROM client_sessions WHERE session_id = ANY($1)")
                    .bind(&session_ids)
                    .fetch_all(self.pool())
                    .await
                    .map_err(sqlx_err)?;

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
               WHERE realm_id = $1
                 AND ($2::uuid IS NULL OR user_id = $2)"#,
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
        let mut txn = self.pool().begin().await.map_err(sqlx_err)?;
        let pg: PgUserSession = session.try_into()?;

        sqlx::query(
            r#"INSERT INTO user_sessions (
                id, realm_id, user_id, login_username, ip_address,
                auth_method, remember_me, offline, started, last_session_refresh, auth_time,
                impersonator
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
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
        .bind(&pg.impersonator)
        .execute(&mut *txn)
        .await
        .map_err(sqlx_err)?;

        for client_session in &session.clients {
            let cs: PgClientSession = client_session.try_into()?;
            sqlx::query(
                r#"INSERT INTO client_sessions (
                    id, client_id, session_id, redirect_uri, state, auth_method, timestamp
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            )
            .bind(cs.id)
            .bind(cs.client_id)
            .bind(cs.session_id)
            .bind(&cs.redirect_uri)
            .bind(&cs.state)
            .bind(&cs.auth_method)
            .bind(cs.timestamp)
            .execute(&mut *txn)
            .await
            .map_err(sqlx_err)?;
        }

        txn.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_user_session(
        &self,
        realm: &RealmId,
        session: &UserSession,
    ) -> Result<(), IssuerdError> {
        let mut txn = self.pool().begin().await.map_err(sqlx_err)?;
        let pg: PgUserSession = session.try_into()?;

        let result = sqlx::query(
            r#"UPDATE user_sessions SET
                user_id = $3, login_username = $4, ip_address = $5,
                auth_method = $6, remember_me = $7, offline = $8,
                started = $9, last_session_refresh = $10, auth_time = $11,
                impersonator = $12
            WHERE realm_id = $1 AND id = $2"#,
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
        .bind(&pg.impersonator)
        .execute(&mut *txn)
        .await
        .map_err(sqlx_err)?;

        if result.rows_affected() == 0 {
            txn.rollback().await.map_err(sqlx_err)?;
            return Err(IssuerdError::NotFound);
        }

        sqlx::query("DELETE FROM client_sessions WHERE session_id = $1")
            .bind(pg.id)
            .execute(&mut *txn)
            .await
            .map_err(sqlx_err)?;

        for client_session in &session.clients {
            let cs: PgClientSession = client_session.try_into()?;
            sqlx::query(
                r#"INSERT INTO client_sessions (
                    id, client_id, session_id, redirect_uri, state, auth_method, timestamp
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            )
            .bind(cs.id)
            .bind(cs.client_id)
            .bind(cs.session_id)
            .bind(&cs.redirect_uri)
            .bind(&cs.state)
            .bind(&cs.auth_method)
            .bind(cs.timestamp)
            .execute(&mut *txn)
            .await
            .map_err(sqlx_err)?;
        }

        txn.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_user_session(
        &self,
        realm: &RealmId,
        id: &SessionId,
    ) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM user_sessions WHERE realm_id = $1 AND id = $2")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Roles
    // ------------------------------------------------------------------
    async fn get_role(&self, realm: &RealmId, id: &RoleId) -> Result<Option<Role>, IssuerdError> {
        let pg: Option<PgRole> =
            sqlx::query_as("SELECT * FROM roles WHERE realm_id = $1 AND id = $2")
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
            "SELECT * FROM roles WHERE realm_id = $1 AND name = $2 \
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
            "SELECT * FROM roles WHERE realm_id = $1 ORDER BY name LIMIT $2 OFFSET $3",
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
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE realm_id = $1")
            .bind(to_uuid(realm.as_ref())?)
            .fetch_one(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(count)
    }

    async fn create_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError> {
        let mut pg: PgRole = role.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        sqlx::query(
            r#"INSERT INTO roles (
                id, name, description, realm_id, client_role, client_id,
                composite, composites, attributes
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_role(&self, realm: &RealmId, role: &Role) -> Result<(), IssuerdError> {
        let pg: PgRole = role.try_into()?;
        let result = sqlx::query(
            r#"UPDATE roles SET
                name = $3, description = $4, client_role = $5, client_id = $6,
                composite = $7, composites = $8, attributes = $9
            WHERE realm_id = $1 AND id = $2"#,
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_role(&self, realm: &RealmId, id: &RoleId) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM roles WHERE realm_id = $1 AND id = $2")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
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
            "SELECT * FROM roles WHERE realm_id = $1 AND client_id = $2 AND name = $3",
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
        let rows: Vec<PgRole> = sqlx::query_as(
            "SELECT * FROM roles WHERE realm_id = $1 AND client_id = $2 AND name = ANY($3)",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(client.as_ref())?)
        .bind(names)
        .fetch_all(self.pool())
        .await
        .map_err(sqlx_err)?;
        let roles: Vec<Role> = rows.into_iter().map(|r| r.try_into()).collect::<Result<_, _>>()?;
        // ANY() does not preserve input order; restore it in Rust.
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
            "SELECT * FROM roles WHERE realm_id = $1 AND client_id = $2 \
             ORDER BY name LIMIT $3 OFFSET $4",
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
            sqlx::query_as("SELECT * FROM client_scopes WHERE realm_id = $1 AND id = $2")
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
            sqlx::query_as("SELECT * FROM client_scopes WHERE realm_id = $1 AND name = $2")
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
        let rows: Vec<PgClientScope> =
            sqlx::query_as("SELECT * FROM client_scopes WHERE realm_id = $1 AND name = ANY($2)")
                .bind(to_uuid(realm.as_ref())?)
                .bind(names)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        let scopes: Vec<ClientScope> =
            rows.into_iter().map(|s| s.try_into()).collect::<Result<_, _>>()?;
        // ANY() does not preserve input order; restore it in Rust.
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
        let uuids = ids.iter().map(|id| to_uuid(id.as_ref())).collect::<Result<Vec<_>, _>>()?;
        let rows: Vec<PgClientScope> =
            sqlx::query_as("SELECT * FROM client_scopes WHERE realm_id = $1 AND id = ANY($2)")
                .bind(to_uuid(realm.as_ref())?)
                .bind(&uuids)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        let scopes: Vec<ClientScope> =
            rows.into_iter().map(|s| s.try_into()).collect::<Result<_, _>>()?;
        // ANY() does not preserve input order; restore it in Rust.
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
            "SELECT * FROM client_scopes WHERE realm_id = $1 ORDER BY name LIMIT $2 OFFSET $3",
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
        sqlx::query(
            r#"INSERT INTO client_scopes (
                id, realm_id, name, description, protocol,
                attributes, protocol_mappers, scope_mappings
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(pg.id)
        .bind(pg.realm_id)
        .bind(&pg.name)
        .bind(&pg.description)
        .bind(&pg.protocol)
        .bind(&pg.attributes)
        .bind(&pg.protocol_mappers)
        .bind(&pg.scope_mappings)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScope,
    ) -> Result<(), IssuerdError> {
        let pg: PgClientScope = scope.try_into()?;
        let result = sqlx::query(
            r#"UPDATE client_scopes SET
                name = $3, description = $4, protocol = $5,
                attributes = $6, protocol_mappers = $7, scope_mappings = $8
            WHERE realm_id = $1 AND id = $2"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(pg.id)
        .bind(&pg.name)
        .bind(&pg.description)
        .bind(&pg.protocol)
        .bind(&pg.attributes)
        .bind(&pg.protocol_mappers)
        .bind(&pg.scope_mappings)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
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
        sqlx::query("DELETE FROM client_scopes WHERE realm_id = $1 AND id = $2")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
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
        sqlx::query(
            r#"INSERT INTO client_client_scopes (realm_id, client_id, scope_id, is_default)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (client_id, scope_id) DO UPDATE SET is_default = EXCLUDED.is_default"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(client.as_ref())?)
        .bind(to_uuid(scope.as_ref())?)
        .bind(is_default)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn unassign_client_scope(
        &self,
        realm: &RealmId,
        client: &ClientId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        sqlx::query(
            "DELETE FROM client_client_scopes \
             WHERE realm_id = $1 AND client_id = $2 AND scope_id = $3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(client.as_ref())?)
        .bind(to_uuid(scope.as_ref())?)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_client_scope_assignments(
        &self,
        realm: &RealmId,
        client: &ClientId,
    ) -> Result<Vec<(ClientScopeId, bool)>, IssuerdError> {
        let rows: Vec<(uuid::Uuid, bool)> = sqlx::query_as(
            "SELECT scope_id, is_default FROM client_client_scopes \
             WHERE realm_id = $1 AND client_id = $2 ORDER BY scope_id",
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
             WHERE realm_id = $1 ORDER BY scope_id",
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
        sqlx::query(
            r#"INSERT INTO realm_default_client_scopes (realm_id, scope_id, is_default)
               VALUES ($1, $2, $3)
               ON CONFLICT (realm_id, scope_id) DO UPDATE SET is_default = EXCLUDED.is_default"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(scope.as_ref())?)
        .bind(is_default)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn remove_realm_default_client_scope(
        &self,
        realm: &RealmId,
        scope: &ClientScopeId,
    ) -> Result<(), IssuerdError> {
        sqlx::query(
            "DELETE FROM realm_default_client_scopes WHERE realm_id = $1 AND scope_id = $2",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(scope.as_ref())?)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
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
            sqlx::query_as("SELECT * FROM groups WHERE realm_id = $1 AND id = $2")
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
            sqlx::query_as("SELECT * FROM groups WHERE realm_id = $1 AND name = $2")
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
        let uuids = ids.iter().map(|id| to_uuid(id.as_ref())).collect::<Result<Vec<_>, _>>()?;
        let rows: Vec<PgGroup> =
            sqlx::query_as("SELECT * FROM groups WHERE realm_id = $1 AND id = ANY($2)")
                .bind(to_uuid(realm.as_ref())?)
                .bind(&uuids)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        let groups: Vec<Group> =
            rows.into_iter().map(|g| g.try_into()).collect::<Result<_, _>>()?;
        // ANY() does not preserve input order; restore it in Rust.
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
            "SELECT * FROM groups WHERE realm_id = $1 ORDER BY name LIMIT $2 OFFSET $3",
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
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE realm_id = $1")
            .bind(to_uuid(realm.as_ref())?)
            .fetch_one(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(count)
    }

    async fn create_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError> {
        let mut pg: PgGroup = group.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        sqlx::query(
            r#"INSERT INTO groups (
                id, name, path, realm_id, parent_id, attributes, realm_roles, client_roles
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(pg.id)
        .bind(&pg.name)
        .bind(&pg.path)
        .bind(pg.realm_id)
        .bind(pg.parent_id)
        .bind(&pg.attributes)
        .bind(&pg.realm_roles)
        .bind(&pg.client_roles)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_group(&self, realm: &RealmId, group: &Group) -> Result<(), IssuerdError> {
        let pg: PgGroup = group.try_into()?;
        let result = sqlx::query(
            r#"UPDATE groups SET
                name = $3, path = $4, parent_id = $5, attributes = $6,
                realm_roles = $7, client_roles = $8
            WHERE realm_id = $1 AND id = $2"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(pg.id)
        .bind(&pg.name)
        .bind(&pg.path)
        .bind(pg.parent_id)
        .bind(&pg.attributes)
        .bind(&pg.realm_roles)
        .bind(&pg.client_roles)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_group(&self, realm: &RealmId, id: &GroupId) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM groups WHERE realm_id = $1 AND id = $2")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
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
        sqlx::query(
            "INSERT INTO user_realm_roles (realm_id, user_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(role_id.as_ref())?)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn remove_user_realm_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        sqlx::query(
            "DELETE FROM user_realm_roles WHERE realm_id = $1 AND user_id = $2 AND role_id = $3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(role_id.as_ref())?)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_user_realm_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError> {
        let rows: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT role_id::uuid FROM user_realm_roles WHERE realm_id = $1 AND user_id = $2",
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
        sqlx::query(
            "INSERT INTO user_client_roles (realm_id, user_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(role_id.as_ref())?)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn remove_user_client_role(
        &self,
        realm: &RealmId,
        user: &UserId,
        role_id: &RoleId,
    ) -> Result<(), IssuerdError> {
        sqlx::query(
            "DELETE FROM user_client_roles WHERE realm_id = $1 AND user_id = $2 AND role_id = $3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(role_id.as_ref())?)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_user_client_roles(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<RoleId>, IssuerdError> {
        let rows: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT role_id::uuid FROM user_client_roles WHERE realm_id = $1 AND user_id = $2",
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
        sqlx::query(
            "INSERT INTO user_groups (realm_id, user_id, group_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(group_id.as_ref())?)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn remove_user_group(
        &self,
        realm: &RealmId,
        user: &UserId,
        group_id: &GroupId,
    ) -> Result<(), IssuerdError> {
        sqlx::query(
            "DELETE FROM user_groups WHERE realm_id = $1 AND user_id = $2 AND group_id = $3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(to_uuid(group_id.as_ref())?)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_user_groups(
        &self,
        realm: &RealmId,
        user: &UserId,
    ) -> Result<Vec<GroupId>, IssuerdError> {
        let rows: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT group_id::uuid FROM user_groups WHERE realm_id = $1 AND user_id = $2",
        )
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
               WHERE ug.realm_id = $1 AND ug.group_id = $2
               ORDER BY u.username
               LIMIT $3 OFFSET $4"#,
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
        let rows: Vec<PgConsent> =
            sqlx::query_as("SELECT * FROM consents WHERE realm_id = $1 AND user_id = $2")
                .bind(to_uuid(realm.as_ref())?)
                .bind(to_uuid(user.as_ref())?)
                .fetch_all(self.pool())
                .await
                .map_err(sqlx_err)?;
        rows.into_iter().map(|c| c.try_into()).collect()
    }

    async fn create_consent(&self, realm: &RealmId, consent: &Consent) -> Result<(), IssuerdError> {
        let mut pg: PgConsent = consent.try_into()?;
        pg.realm_id = to_uuid(realm.as_ref())?;
        sqlx::query(
            r#"INSERT INTO consents (
                realm_id, user_id, client_id, granted_scopes,
                granted_realm_roles, granted_client_roles, created_at, last_updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_consent(
        &self,
        realm: &RealmId,
        user: &UserId,
        client_id: &ClientId,
    ) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM consents WHERE realm_id = $1 AND user_id = $2 AND client_id = $3")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(user.as_ref())?)
            .bind(client_id.to_string())
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
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
            sqlx::query_as("SELECT * FROM identity_providers WHERE realm_id = $1 AND id = $2")
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
            "SELECT * FROM identity_providers WHERE realm_id = $1 AND alias = $2",
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
            sqlx::query_as("SELECT * FROM identity_providers WHERE realm_id = $1")
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
        sqlx::query(
            r#"INSERT INTO identity_providers (id, realm_id, alias, provider_id, enabled, config)
            VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(pg.id)
        .bind(pg.realm_id)
        .bind(&pg.alias)
        .bind(&pg.provider_id)
        .bind(pg.enabled)
        .bind(&pg.config)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_identity_provider(
        &self,
        realm: &RealmId,
        idp: &IdentityProviderConfig,
    ) -> Result<(), IssuerdError> {
        let pg: PgIdentityProvider = idp.try_into()?;
        let result = sqlx::query(
            r#"UPDATE identity_providers SET
                alias = $3, provider_id = $4, enabled = $5, config = $6
            WHERE realm_id = $1 AND id = $2"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(pg.id)
        .bind(&pg.alias)
        .bind(&pg.provider_id)
        .bind(pg.enabled)
        .bind(&pg.config)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
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
        sqlx::query("DELETE FROM identity_providers WHERE realm_id = $1 AND id = $2")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
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
             WHERE realm_id = $1 AND provider_alias = $2 AND external_subject = $3",
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
             WHERE realm_id = $1 AND user_id = $2 AND provider_alias = $3",
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
            "SELECT * FROM identity_provider_links WHERE realm_id = $1 AND user_id = $2 \
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
        sqlx::query(
            r#"INSERT INTO identity_provider_links (
                realm_id, user_id, provider_alias, external_subject,
                external_username, stored_refresh_token, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(link.user_id.as_ref())?)
        .bind(&link.provider_alias)
        .bind(&link.external_subject)
        .bind(&link.external_username)
        .bind(&link.stored_refresh_token)
        .bind(link.created_at)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_identity_provider_link(
        &self,
        realm: &RealmId,
        user: &UserId,
        alias: &str,
    ) -> Result<(), IssuerdError> {
        sqlx::query(
            "DELETE FROM identity_provider_links \
             WHERE realm_id = $1 AND user_id = $2 AND provider_alias = $3",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(user.as_ref())?)
        .bind(alias)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
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
            sqlx::query_as("SELECT * FROM flow_configs WHERE realm_id = $1 AND alias = $2")
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
        sqlx::query(
            r#"INSERT INTO flow_configs (alias, realm_id, provider_id, top_level, built_in, stages)
            VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(&pg.alias)
        .bind(pg.realm_id)
        .bind(&pg.provider_id)
        .bind(pg.top_level)
        .bind(pg.built_in)
        .bind(&pg.stages)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_flow_config(
        &self,
        realm: &RealmId,
        config: &FlowConfig,
    ) -> Result<(), IssuerdError> {
        let pg: PgFlowConfig = config.try_into()?;
        let result = sqlx::query(
            r#"UPDATE flow_configs SET
                provider_id = $3, top_level = $4, built_in = $5, stages = $6
            WHERE realm_id = $1 AND alias = $2"#,
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(&pg.alias)
        .bind(&pg.provider_id)
        .bind(pg.top_level)
        .bind(pg.built_in)
        .bind(&pg.stages)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    async fn delete_flow_config(&self, realm: &RealmId, alias: &str) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM flow_configs WHERE realm_id = $1 AND alias = $2")
            .bind(to_uuid(realm.as_ref())?)
            .bind(alias)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_flow_configs(&self, realm: &RealmId) -> Result<Vec<FlowConfig>, IssuerdError> {
        let realm_uuid = uuid::Uuid::parse_str(realm.as_ref())
            .map_err(|e| IssuerdError::InvalidRequest(format!("invalid realm id: {e}")))?;
        let rows = sqlx::query_as::<_, crate::db_types::PgFlowConfig>(
            "SELECT * FROM flow_configs WHERE realm_id = $1 ORDER BY alias",
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
        sqlx::query(
            r#"INSERT INTO events (
                id, realm_id, event_time, event_type, ip_address,
                client_id, user_id, session_id, error, details
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
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
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
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
               WHERE realm_id = $1
                 AND ($2::text IS NULL OR event_type = $2)
                 AND ($3::timestamptz IS NULL OR event_time >= $3)
                 AND ($4::timestamptz IS NULL OR event_time <= $4)
                 AND ($5::uuid IS NULL OR client_id = $5)
                 AND ($6::uuid IS NULL OR user_id = $6)
               ORDER BY event_time DESC
               LIMIT $7 OFFSET $8"#,
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
               WHERE realm_id = $1
                 AND ($2::text IS NULL OR event_type = $2)
                 AND ($3::timestamptz IS NULL OR event_time >= $3)
                 AND ($4::timestamptz IS NULL OR event_time <= $4)
                 AND ($5::uuid IS NULL OR client_id = $5)
                 AND ($6::uuid IS NULL OR user_id = $6)"#,
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
        sqlx::query("DELETE FROM events WHERE realm_id = $1")
            .bind(to_uuid(realm.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(())
    }

    async fn save_admin_event(&self, event: &AdminEvent) -> Result<(), IssuerdError> {
        let pg: PgAdminEvent = event.try_into()?;
        sqlx::query(
            r#"INSERT INTO admin_events (
                id, realm_id, auth_realm_id, auth_client_id, auth_user_id,
                operation_type, resource_type, resource_path, representation, error, event_time
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(pg.id)
        .bind(pg.realm_id)
        .bind(pg.auth_realm_id)
        .bind(pg.auth_client_id)
        .bind(pg.auth_user_id)
        .bind(&pg.operation_type)
        .bind(&pg.resource_type)
        .bind(&pg.resource_path)
        .bind(&pg.representation)
        .bind(&pg.error)
        .bind(pg.event_time)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
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
               WHERE realm_id = $1
                 AND ($2::text IS NULL OR operation_type = $2)
                 AND ($3::text IS NULL OR resource_type = $3)
                 AND ($4::timestamptz IS NULL OR event_time >= $4)
                 AND ($5::timestamptz IS NULL OR event_time <= $5)
                 AND ($6::uuid IS NULL OR auth_user_id = $6)
               ORDER BY event_time DESC
               LIMIT $7 OFFSET $8"#,
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
               WHERE realm_id = $1
                 AND ($2::text IS NULL OR operation_type = $2)
                 AND ($3::text IS NULL OR resource_type = $3)
                 AND ($4::timestamptz IS NULL OR event_time >= $4)
                 AND ($5::timestamptz IS NULL OR event_time <= $5)
                 AND ($6::uuid IS NULL OR auth_user_id = $6)"#,
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
        sqlx::query("DELETE FROM admin_events WHERE realm_id = $1")
            .bind(to_uuid(realm.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_provision_marker(&self, name: &str) -> Result<Option<String>, IssuerdError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM provision_markers WHERE name = $1")
                .bind(name)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
        Ok(row.map(|r| r.0))
    }

    async fn set_provision_marker(&self, name: &str, value: &str) -> Result<(), IssuerdError> {
        sqlx::query(
            r#"INSERT INTO provision_markers (name, value)
               VALUES ($1, $2)
               ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value"#,
        )
        .bind(name)
        .bind(value)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn claim_provision_marker(&self, name: &str, value: &str) -> Result<bool, IssuerdError> {
        let result = sqlx::query(
            r#"INSERT INTO provision_markers (name, value)
               VALUES ($1, $2)
               ON CONFLICT (name) DO NOTHING"#,
        )
        .bind(name)
        .bind(value)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
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
        rows.into_iter().map(|k| k.try_into()).collect()
    }

    async fn create_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError> {
        let pg: PgSigningKey = key.try_into()?;
        sqlx::query(
            r#"INSERT INTO signing_keys (
                kid, alg, created_at, private_der, public_jwk, active
            ) VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(&pg.kid)
        .bind(&pg.alg)
        .bind(pg.created_at)
        .bind(&pg.private_der)
        .bind(&pg.public_jwk)
        .bind(pg.active)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn update_signing_key(&self, key: &StoredSigningKey) -> Result<(), IssuerdError> {
        let result = sqlx::query("UPDATE signing_keys SET active = $2 WHERE kid = $1")
            .bind(key.kid.to_string())
            .bind(key.active)
            .execute(self.pool())
            .await
            .map_err(sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt};

    async fn setup_pg() -> (PostgresStorage, testcontainers::ContainerAsync<GenericImage>) {
        let img = GenericImage::new("postgres", "15-alpine")
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_DB", "test");
        let container = img.start().await.expect("postgres container start");
        let host = container.get_host().await.expect("host");
        let port = container.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgres://postgres:postgres@{host}:{port}/test");
        let storage = PostgresStorage::connect(&url).await.expect("connect");
        storage.run_migrations().await.expect("migrations");
        (storage, container)
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
    #[ignore = "requires Docker"]
    async fn pg_realm_crud_and_uniqueness() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_user_crud_and_uniqueness() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_client_crud_and_uniqueness() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_role_and_group_crud() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_credential_crud() {
        let (storage, _container) = setup_pg().await;
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

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------
    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn pg_session_lifecycle() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_consent_lifecycle() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_idp_lifecycle() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_flow_config_lifecycle() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_signing_key_roundtrip() {
        let (storage, _container) = setup_pg().await;

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
    #[ignore = "requires Docker"]
    async fn pg_event_save_and_query() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_transaction_rollback_on_invalid_session() {
        let (storage, _container) = setup_pg().await;
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();

        // Create a session for a non-existent user - should fail at FK level
        let session =
            test_session(&realm.id, &UserId::new(uuid::Uuid::new_v4().to_string()).unwrap());
        assert!(storage.create_user_session(&realm.id, &session).await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn pg_list_and_update_operations() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_user_membership_and_idp_alias() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_event_query_filters() {
        let (storage, _container) = setup_pg().await;
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
    #[ignore = "requires Docker"]
    async fn pg_update_not_found_errors() {
        let (storage, _container) = setup_pg().await;
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

    // ------------------------------------------------------------------
    // Helper unit tests (no Docker required)
    // ------------------------------------------------------------------
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
    async fn connect_invalid_url() {
        let result = PostgresStorage::connect("not-a-valid-url").await;
        assert!(result.is_err());
    }

    #[test]
    fn sqlx_err_pool_timed_out() {
        let err = sqlx_err(sqlx::Error::PoolTimedOut);
        assert!(matches!(err, IssuerdError::ServerError(_)));
    }

    #[test]
    fn sqlx_err_pool_closed() {
        let err = sqlx_err(sqlx::Error::PoolClosed);
        assert!(matches!(err, IssuerdError::ServerError(_)));
    }
}
