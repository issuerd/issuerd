// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Durable operation-bound MCP grants and serialized SQLite execution.

use issuerd_core::*;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{Sqlite, Transaction};

use crate::{db_types::*, sqlite::SqliteStorage};

fn json_error(error: serde_json::Error) -> IssuerdError {
    IssuerdError::ServerError(format!("invalid step-up grant serialization: {error}"))
}

fn from_json<T: DeserializeOwned>(value: Value) -> Result<T, IssuerdError> {
    serde_json::from_value(value).map_err(json_error)
}

#[derive(Debug, sqlx::FromRow)]
struct SqliteStepUpGrant {
    version: i32,
    operation_id: String,
    operation_hash: String,
    canonicalization_version: i32,
    realm_id: uuid::Uuid,
    client_id: String,
    subject_user_id: uuid::Uuid,
    resource: String,
    tool: String,
    mutation_json: Value,
    origin_access_token_jti: String,
    token_jti: String,
    dpop_jkt: String,
    approval_auth_time: i64,
    approval_acr: Option<String>,
    approval_amr: Value,
    status: String,
    result_json: Option<Value>,
    issued_at: i64,
    expires_at: i64,
    updated_at: i64,
}

impl SqliteStepUpGrant {
    fn into_grant(self) -> Result<McpStepUpGrant, IssuerdError> {
        Ok(McpStepUpGrant {
            version: u32::try_from(self.version)
                .map_err(|_| IssuerdError::ServerError("invalid step-up grant version".into()))?,
            operation_id: self.operation_id,
            operation_hash: self.operation_hash,
            canonicalization_version: u32::try_from(self.canonicalization_version).map_err(
                |_| IssuerdError::ServerError("invalid step-up canonicalization version".into()),
            )?,
            realm_id: RealmId::new(self.realm_id.to_string())?,
            client_id: ClientIdentifier::new(self.client_id)?,
            subject_user_id: UserId::new(self.subject_user_id.to_string())?,
            resource: self.resource,
            tool: self.tool,
            mutation: from_json(self.mutation_json)?,
            origin_access_token_jti: self.origin_access_token_jti,
            token_jti: JwtId::new(self.token_jti)?,
            dpop_jkt: self.dpop_jkt,
            approval_auth_time: self.approval_auth_time,
            approval_acr: self.approval_acr,
            approval_amr: from_json(self.approval_amr)?,
            status: match self.status.as_str() {
                "active" => McpStepUpExecutionStatus::Active,
                "executing" => McpStepUpExecutionStatus::Executing,
                "succeeded" => McpStepUpExecutionStatus::Succeeded,
                "failed_definite" => McpStepUpExecutionStatus::FailedDefinite,
                "outcome_unknown" => McpStepUpExecutionStatus::OutcomeUnknown,
                _ => return Err(IssuerdError::ServerError("invalid grant status".into())),
            },
            result_json: self.result_json,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            updated_at: self.updated_at,
        })
    }
}

fn status_name(status: McpStepUpExecutionStatus) -> &'static str {
    match status {
        McpStepUpExecutionStatus::Active => "active",
        McpStepUpExecutionStatus::Executing => "executing",
        McpStepUpExecutionStatus::Succeeded => "succeeded",
        McpStepUpExecutionStatus::FailedDefinite => "failed_definite",
        McpStepUpExecutionStatus::OutcomeUnknown => "outcome_unknown",
    }
}

pub(crate) async fn get_grant(
    storage: &SqliteStorage,
    token_jti: &JwtId,
) -> Result<Option<McpStepUpGrant>, IssuerdError> {
    let row: Option<SqliteStepUpGrant> =
        sqlx::query_as("SELECT * FROM mcp_step_up_grants WHERE token_jti = ?1")
            .bind(token_jti.as_ref())
            .fetch_optional(storage.pool())
            .await
            .map_err(sqlx_error)?;
    row.map(SqliteStepUpGrant::into_grant).transpose()
}

pub(crate) async fn create_grant(
    storage: &SqliteStorage,
    grant: &McpStepUpGrant,
) -> Result<(), IssuerdError> {
    let mut grant = grant.clone();
    grant.mutation = grant.mutation.redacted();
    let version = i32::try_from(grant.version)
        .map_err(|_| IssuerdError::InvalidRequest("invalid grant version".into()))?;
    let canonicalization_version = i32::try_from(grant.canonicalization_version)
        .map_err(|_| IssuerdError::InvalidRequest("invalid canonicalization version".into()))?;
    let mutation_json = serde_json::to_value(&grant.mutation).map_err(json_error)?;
    let approval_amr = serde_json::to_value(&grant.approval_amr).map_err(json_error)?;
    let mut failed_attempts = 0;
    loop {
        match sqlx::query(
            r#"INSERT INTO mcp_step_up_grants (
                token_jti, version, operation_id, operation_hash, canonicalization_version,
                realm_id, client_id, subject_user_id, resource, tool, mutation_json,
                origin_access_token_jti, dpop_jkt, approval_auth_time, approval_acr,
                approval_amr, status, result_json, issued_at, expires_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21
            )"#,
        )
        .bind(grant.token_jti.as_ref())
        .bind(version)
        .bind(&grant.operation_id)
        .bind(&grant.operation_hash)
        .bind(canonicalization_version)
        .bind(uuid(grant.realm_id.as_ref())?)
        .bind(grant.client_id.as_str())
        .bind(uuid(grant.subject_user_id.as_ref())?)
        .bind(&grant.resource)
        .bind(&grant.tool)
        .bind(&mutation_json)
        .bind(&grant.origin_access_token_jti)
        .bind(&grant.dpop_jkt)
        .bind(grant.approval_auth_time)
        .bind(&grant.approval_acr)
        .bind(&approval_amr)
        .bind(status_name(grant.status))
        .bind(&grant.result_json)
        .bind(grant.issued_at)
        .bind(grant.expires_at)
        .bind(grant.updated_at)
        .execute(storage.pool())
        .await
        .map_err(sqlx_error)
        {
            Err(error) if is_busy(&error) => {
                failed_attempts += 1;
                if failed_attempts == 8 {
                    return Err(IssuerdError::TemporarilyUnavailable);
                }
                tokio::time::sleep(std::time::Duration::from_millis(10 * failed_attempts as u64))
                    .await;
            }
            result => {
                result?;
                return Ok(());
            }
        }
    }
}

pub(crate) async fn execute_grant(
    storage: &SqliteStorage,
    token_jti: &JwtId,
    operation_hash: &str,
    mutation: &McpStepUpMutation,
    result_json: Value,
) -> Result<McpStepUpExecution, IssuerdError> {
    const MAX_BUSY_ATTEMPTS: usize = 8;

    for attempt in 0..MAX_BUSY_ATTEMPTS {
        match execute_grant_once(storage, token_jti, operation_hash, mutation, result_json.clone())
            .await
        {
            Err(error) if is_busy(&error) => {
                tokio::time::sleep(std::time::Duration::from_millis(10 * (attempt as u64 + 1)))
                    .await;
            }
            result => return result,
        }
    }
    Err(IssuerdError::TemporarilyUnavailable)
}

async fn execute_grant_once(
    storage: &SqliteStorage,
    token_jti: &JwtId,
    operation_hash: &str,
    mutation: &McpStepUpMutation,
    result_json: Value,
) -> Result<McpStepUpExecution, IssuerdError> {
    let mut tx = storage.pool().begin_with("BEGIN IMMEDIATE").await.map_err(sqlx_error)?;
    let row: Option<SqliteStepUpGrant> =
        sqlx::query_as("SELECT * FROM mcp_step_up_grants WHERE token_jti = ?1")
            .bind(token_jti.as_ref())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_error)?;
    let Some(row) = row else {
        tx.rollback().await.map_err(sqlx_error)?;
        return Err(IssuerdError::InvalidGrant);
    };
    let mut grant = row.into_grant()?;
    if grant.operation_hash != operation_hash || grant.mutation != mutation.redacted() {
        tx.rollback().await.map_err(sqlx_error)?;
        return Err(IssuerdError::AccessDenied);
    }
    match grant.status {
        McpStepUpExecutionStatus::Succeeded => {
            let execution = McpStepUpExecution {
                status: grant.status,
                result_json: grant.result_json,
            };
            tx.commit().await.map_err(sqlx_error)?;
            return Ok(execution);
        }
        McpStepUpExecutionStatus::FailedDefinite => {
            tx.rollback().await.map_err(sqlx_error)?;
            return Err(IssuerdError::Conflict);
        }
        McpStepUpExecutionStatus::Executing | McpStepUpExecutionStatus::OutcomeUnknown => {
            tx.rollback().await.map_err(sqlx_error)?;
            return Err(IssuerdError::TemporarilyUnavailable);
        }
        McpStepUpExecutionStatus::Active => {}
    }
    if grant.expires_at <= chrono::Utc::now().timestamp() {
        tx.rollback().await.map_err(sqlx_error)?;
        return Err(IssuerdError::InvalidGrant);
    }
    let now = chrono::Utc::now().timestamp();
    let transition = sqlx::query(
        "UPDATE mcp_step_up_grants SET status = 'executing', updated_at = ?2 WHERE token_jti = ?1 AND status = 'active'",
    )
    .bind(token_jti.as_ref())
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(sqlx_error)?;
    if transition.rows_affected() != 1 {
        tx.rollback().await.map_err(sqlx_error)?;
        return Err(IssuerdError::TemporarilyUnavailable);
    }

    let mutation_result = apply_mutation(&mut tx, mutation).await;
    if let Err(error) = mutation_result {
        if error == IssuerdError::Conflict {
            sqlx::query(
                "UPDATE mcp_step_up_grants SET status = 'failed_definite', updated_at = ?2 WHERE token_jti = ?1",
            )
            .bind(token_jti.as_ref())
            .bind(chrono::Utc::now().timestamp())
            .execute(&mut *tx)
            .await
            .map_err(sqlx_error)?;
            tx.commit().await.map_err(sqlx_error)?;
        } else {
            tx.rollback().await.map_err(sqlx_error)?;
        }
        return Err(error);
    }

    let completed = sqlx::query(
        "UPDATE mcp_step_up_grants SET status = 'succeeded', result_json = ?2, updated_at = ?3 WHERE token_jti = ?1",
    )
    .bind(token_jti.as_ref())
    .bind(&result_json)
    .bind(chrono::Utc::now().timestamp())
    .execute(&mut *tx)
    .await
    .map_err(sqlx_error)?;
    if completed.rows_affected() != 1 {
        tx.rollback().await.map_err(sqlx_error)?;
        return Err(IssuerdError::TemporarilyUnavailable);
    }
    grant.status = McpStepUpExecutionStatus::Succeeded;
    grant.result_json = Some(result_json);
    tx.commit().await.map_err(sqlx_error)?;
    Ok(McpStepUpExecution {
        status: grant.status,
        result_json: grant.result_json,
    })
}

async fn apply_mutation(
    tx: &mut Transaction<'_, Sqlite>,
    mutation: &McpStepUpMutation,
) -> Result<(), IssuerdError> {
    let mutation = mutation.redacted();
    match mutation {
        McpStepUpMutation::DeleteUser { expected } => {
            let current: Option<PgUser> =
                sqlx::query_as("SELECT * FROM users WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_user(current.try_into()?) != expected {
                return Err(IssuerdError::Conflict);
            }
            expect_one(
                sqlx::query("DELETE FROM users WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::DeleteGroup { expected } => {
            let current: Option<PgGroup> =
                sqlx::query_as("SELECT * FROM groups WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_group(current.try_into()?) != expected {
                return Err(IssuerdError::Conflict);
            }
            expect_one(
                sqlx::query("DELETE FROM groups WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::DeleteRole { expected } => {
            let current: Option<PgRole> =
                sqlx::query_as("SELECT * FROM roles WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_role(current.try_into()?) != expected {
                return Err(IssuerdError::Conflict);
            }
            expect_one(
                sqlx::query("DELETE FROM roles WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::DeleteClient { expected } => {
            let current: Option<PgClient> =
                sqlx::query_as("SELECT * FROM clients WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_client(current.try_into()?) != expected {
                return Err(IssuerdError::Conflict);
            }
            expect_one(
                sqlx::query("DELETE FROM clients WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::UpdateClientSecurity { expected, updated } => {
            let current: Option<PgClient> =
                sqlx::query_as("SELECT * FROM clients WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            let current: Client = current.try_into()?;
            if redacted_client(current.clone()) != expected {
                return Err(IssuerdError::Conflict);
            }
            let mut effective = updated;
            effective.secret = current.secret;
            for (key, value) in current.attributes {
                if sensitive_key(&key) {
                    effective.attributes.entry(key).or_insert(value);
                }
            }
            let pg: PgClient = (&effective).try_into()?;
            expect_one(
                sqlx::query(
                    r#"UPDATE clients SET redirect_uris = ?3, web_origins = ?4, attributes = ?5,
                        public_client = ?6, bearer_only = ?7, consent_required = ?8,
                        full_scope_allowed = ?9, service_accounts_enabled = ?10
                        WHERE realm_id = ?1 AND id = ?2"#,
                )
                .bind(uuid(expected.realm_id.as_ref())?)
                .bind(pg.id)
                .bind(&pg.redirect_uris)
                .bind(&pg.web_origins)
                .bind(&pg.attributes)
                .bind(pg.public_client)
                .bind(pg.bearer_only)
                .bind(pg.consent_required)
                .bind(pg.full_scope_allowed)
                .bind(pg.service_accounts_enabled)
                .execute(&mut **tx)
                .await
                .map_err(sqlx_error)?
                .rows_affected(),
            )
        }
        McpStepUpMutation::UpdateRealmSettings { expected, updated } => {
            let current: Option<PgRealm> = sqlx::query_as("SELECT * FROM realms WHERE id = ?1")
                .bind(uuid(expected.id.as_ref())?)
                .fetch_optional(&mut **tx)
                .await
                .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            let current: Realm = current.try_into()?;
            if redacted_realm(current.clone()) != expected {
                return Err(IssuerdError::Conflict);
            }
            let mut effective = updated;
            for (key, value) in current.attributes {
                if sensitive_key(&key) {
                    effective.attributes.entry(key).or_insert(value);
                }
            }
            let pg: PgRealm = (&effective).try_into()?;
            expect_one(
                sqlx::query(
                    r#"UPDATE realms SET display_name = ?2, enabled = ?3, ssl_required = ?4,
                        access_token_lifespan = ?5, refresh_token_lifespan = ?6,
                        sso_session_idle_timeout = ?7, sso_session_max_lifespan = ?8,
                        offline_session_idle_timeout = ?9, login_theme = ?10, email_theme = ?11,
                        admin_theme = ?12, registration_enabled = ?13, reset_password_allowed = ?14,
                        remember_me_enabled = ?15, verify_email_enabled = ?16,
                        login_with_email_allowed = ?17, duplicate_emails_allowed = ?18,
                        edit_username_allowed = ?19, updated_at = strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now') WHERE id = ?1"#,
                )
                .bind(pg.id)
                .bind(&pg.display_name)
                .bind(pg.enabled)
                .bind(&pg.ssl_required)
                .bind(pg.access_token_lifespan)
                .bind(pg.refresh_token_lifespan)
                .bind(pg.sso_session_idle_timeout)
                .bind(pg.sso_session_max_lifespan)
                .bind(pg.offline_session_idle_timeout)
                .bind(&pg.login_theme)
                .bind(&pg.email_theme)
                .bind(&pg.admin_theme)
                .bind(pg.registration_enabled)
                .bind(pg.reset_password_allowed)
                .bind(pg.remember_me_enabled)
                .bind(pg.verify_email_enabled)
                .bind(pg.login_with_email_allowed)
                .bind(pg.duplicate_emails_allowed)
                .bind(pg.edit_username_allowed)
                .execute(&mut **tx)
                .await
                .map_err(sqlx_error)?
                .rows_affected(),
            )
        }
        McpStepUpMutation::UpdateEventsConfig { expected, updated } => {
            let current: Option<PgRealm> = sqlx::query_as("SELECT * FROM realms WHERE id = ?1")
                .bind(uuid(expected.id.as_ref())?)
                .fetch_optional(&mut **tx)
                .await
                .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            let current: Realm = current.try_into()?;
            if redacted_realm(current.clone()) != expected {
                return Err(IssuerdError::Conflict);
            }
            let pg: PgRealm = (&updated).try_into()?;
            expect_one(
                sqlx::query(
                    "UPDATE realms SET events_enabled = ?2, events_expiration_secs = ?3, admin_events_enabled = ?4, include_representations = ?5, events_listeners = ?6, updated_at = strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now') WHERE id = ?1",
                )
                .bind(pg.id)
                .bind(pg.events_enabled)
                .bind(pg.events_expiration_secs)
                .bind(pg.admin_events_enabled)
                .bind(pg.include_representations)
                .bind(&pg.events_listeners)
                .execute(&mut **tx)
                .await
                .map_err(sqlx_error)?
                .rows_affected(),
            )
        }
        McpStepUpMutation::CreateIdentityProvider { realm_id, new } => {
            let pg: PgIdentityProvider = (&new).try_into()?;
            sqlx::query(
                "INSERT INTO identity_providers (id, realm_id, alias, provider_id, enabled, config) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(pg.id)
            .bind(uuid(realm_id.as_ref())?)
            .bind(&pg.alias)
            .bind(&pg.provider_id)
            .bind(pg.enabled)
            .bind(&pg.config)
            .execute(&mut **tx)
            .await
            .map_err(sqlx_error)?;
            Ok(())
        }
        McpStepUpMutation::UpdateIdentityProvider {
            realm_id,
            expected,
            updated,
        } => {
            let current: Option<PgIdentityProvider> =
                sqlx::query_as("SELECT * FROM identity_providers WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            let current: IdentityProviderConfig = current.try_into()?;
            if redacted_idp(current.clone()) != expected {
                return Err(IssuerdError::Conflict);
            }
            let mut effective = updated;
            for (key, value) in current.config {
                if sensitive_key(&key) {
                    effective.config.entry(key).or_insert(value);
                }
            }
            let pg: PgIdentityProvider = (&effective).try_into()?;
            expect_one(
                sqlx::query(
                    "UPDATE identity_providers SET alias = ?3, provider_id = ?4, enabled = ?5, config = ?6 WHERE realm_id = ?1 AND id = ?2",
                )
                .bind(uuid(realm_id.as_ref())?)
                .bind(pg.id)
                .bind(&pg.alias)
                .bind(&pg.provider_id)
                .bind(pg.enabled)
                .bind(&pg.config)
                .execute(&mut **tx)
                .await
                .map_err(sqlx_error)?
                .rows_affected(),
            )
        }
        McpStepUpMutation::DeleteIdentityProvider { realm_id, expected } => {
            let current: Option<PgIdentityProvider> =
                sqlx::query_as("SELECT * FROM identity_providers WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_idp(current.try_into()?) != expected {
                return Err(IssuerdError::Conflict);
            }
            expect_one(
                sqlx::query("DELETE FROM identity_providers WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::UpdateFlow { expected, updated } => {
            let current: Option<PgFlowConfig> =
                sqlx::query_as("SELECT * FROM flow_configs WHERE realm_id = ?1 AND alias = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(expected.alias.as_str())
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            let current: FlowConfig = current.try_into()?;
            if redacted_flow(current.clone()) != expected {
                return Err(IssuerdError::Conflict);
            }
            let mut effective = updated;
            for current_stage in current.stages {
                let Some(current_config) = current_stage.authenticator_config else {
                    continue;
                };
                let Some(updated_stage) =
                    effective.stages.iter_mut().find(|stage| stage.id == current_stage.id)
                else {
                    continue;
                };
                let updated_config =
                    updated_stage.authenticator_config.get_or_insert_with(|| AuthenticatorConfig {
                        alias: current_config.alias.clone(),
                        config: serde_json::Map::new(),
                    });
                for (key, value) in current_config.config {
                    if sensitive_key(&key) {
                        updated_config.config.entry(key).or_insert(value);
                    }
                }
            }
            let pg: PgFlowConfig = (&effective).try_into()?;
            expect_one(
                sqlx::query(
                    "UPDATE flow_configs SET stages = ?3 WHERE realm_id = ?1 AND alias = ?2",
                )
                .bind(uuid(expected.realm_id.as_ref())?)
                .bind(expected.alias.as_str())
                .bind(&pg.stages)
                .execute(&mut **tx)
                .await
                .map_err(sqlx_error)?
                .rows_affected(),
            )
        }
        McpStepUpMutation::PushNotBefore {
            expected,
            not_before,
        } => {
            let current: Option<PgRealm> = sqlx::query_as("SELECT * FROM realms WHERE id = ?1")
                .bind(uuid(expected.id.as_ref())?)
                .fetch_optional(&mut **tx)
                .await
                .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_realm(current.try_into()?) != expected {
                return Err(IssuerdError::Conflict);
            }
            expect_one(
                sqlx::query("UPDATE realms SET not_before = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now') WHERE id = ?1")
                    .bind(uuid(expected.id.as_ref())?)
                    .bind(not_before)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::DeleteRealm { expected } => {
            let current: Option<PgRealm> = sqlx::query_as("SELECT * FROM realms WHERE id = ?1")
                .bind(uuid(expected.id.as_ref())?)
                .fetch_optional(&mut **tx)
                .await
                .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_realm(current.try_into()?) != expected {
                return Err(IssuerdError::Conflict);
            }
            expect_one(
                sqlx::query("DELETE FROM realms WHERE id = ?1")
                    .bind(uuid(expected.id.as_ref())?)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::DeleteTotp {
            realm_id,
            user_id,
            expected,
        } => {
            let current: Vec<PgCredential> = sqlx::query_as(
                "SELECT * FROM credentials WHERE realm_id = ?1 AND user_id = ?2 AND credential_type = 'totp'",
            )
            .bind(uuid(realm_id.as_ref())?)
            .bind(uuid(user_id.as_ref())?)
            .fetch_all(&mut **tx)
            .await
            .map_err(sqlx_error)?;
            let current: Vec<Credential> =
                current.into_iter().map(TryInto::try_into).collect::<Result<_, _>>()?;
            if !same_credentials(current, expected.clone()) {
                return Err(IssuerdError::Conflict);
            }
            for credential in expected {
                expect_one(
                    sqlx::query(
                        "DELETE FROM credentials WHERE realm_id = ?1 AND user_id = ?2 AND id = ?3",
                    )
                    .bind(uuid(realm_id.as_ref())?)
                    .bind(uuid(user_id.as_ref())?)
                    .bind(uuid(credential.id.as_ref())?)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
                )?;
            }
            Ok(())
        }
        McpStepUpMutation::DeleteWebauthn {
            realm_id,
            user_id,
            expected,
        } => {
            let current: Option<PgCredential> = sqlx::query_as(
                "SELECT * FROM credentials WHERE realm_id = ?1 AND user_id = ?2 AND id = ?3",
            )
            .bind(uuid(realm_id.as_ref())?)
            .bind(uuid(user_id.as_ref())?)
            .bind(uuid(expected.id.as_ref())?)
            .fetch_optional(&mut **tx)
            .await
            .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_credential(current.try_into()?) != expected {
                return Err(IssuerdError::Conflict);
            }
            expect_one(
                sqlx::query(
                    "DELETE FROM credentials WHERE realm_id = ?1 AND user_id = ?2 AND id = ?3",
                )
                .bind(uuid(realm_id.as_ref())?)
                .bind(uuid(user_id.as_ref())?)
                .bind(uuid(expected.id.as_ref())?)
                .execute(&mut **tx)
                .await
                .map_err(sqlx_error)?
                .rows_affected(),
            )
        }
        McpStepUpMutation::UserRoleMapping {
            realm_id,
            user_id,
            expected_role,
            client_role,
            assign,
            expected_present,
        } => {
            let current_role: Option<PgRole> =
                sqlx::query_as("SELECT * FROM roles WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(realm_id.as_ref())?)
                    .bind(uuid(expected_role.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current_role) = current_role else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_role(current_role.try_into()?) != expected_role {
                return Err(IssuerdError::Conflict);
            }
            let present: bool = if client_role {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM user_client_roles WHERE realm_id = ?1 AND user_id = ?2 AND role_id = ?3)",
                )
            } else {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM user_realm_roles WHERE realm_id = ?1 AND user_id = ?2 AND role_id = ?3)",
                )
            }
            .bind(uuid(realm_id.as_ref())?)
            .bind(uuid(user_id.as_ref())?)
            .bind(uuid(expected_role.id.as_ref())?)
            .fetch_one(&mut **tx)
            .await
            .map_err(sqlx_error)?;
            if present != expected_present {
                return Err(IssuerdError::Conflict);
            }
            match (client_role, assign) {
                (true, true) => {
                    sqlx::query(
                        "INSERT INTO user_client_roles (realm_id, user_id, role_id) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
                    )
                }
                (true, false) => {
                    sqlx::query(
                        "DELETE FROM user_client_roles WHERE realm_id = ?1 AND user_id = ?2 AND role_id = ?3",
                    )
                }
                (false, true) => {
                    sqlx::query(
                        "INSERT INTO user_realm_roles (realm_id, user_id, role_id) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
                    )
                }
                (false, false) => {
                    sqlx::query(
                        "DELETE FROM user_realm_roles WHERE realm_id = ?1 AND user_id = ?2 AND role_id = ?3",
                    )
                }
            }
            .bind(uuid(realm_id.as_ref())?)
            .bind(uuid(user_id.as_ref())?)
            .bind(uuid(expected_role.id.as_ref())?)
            .execute(&mut **tx)
            .await
            .map_err(sqlx_error)?;
            Ok(())
        }
        McpStepUpMutation::GroupRoleMapping {
            expected,
            expected_role,
            client_id,
            assign,
        } => {
            let current: Option<PgGroup> =
                sqlx::query_as("SELECT * FROM groups WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            let current: Group = current.try_into()?;
            if redacted_group(current.clone()) != expected {
                return Err(IssuerdError::Conflict);
            }
            let current_role: Option<PgRole> =
                sqlx::query_as("SELECT * FROM roles WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected_role.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current_role) = current_role else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_role(current_role.try_into()?) != expected_role {
                return Err(IssuerdError::Conflict);
            }
            let mut updated = expected;
            if let Some(client_id) = client_id {
                let names = updated.client_roles.entry(client_id).or_default();
                if assign && !names.contains(&expected_role.name) {
                    names.push(expected_role.name.clone());
                } else if !assign {
                    names.retain(|name| name != &expected_role.name);
                }
            } else if assign && !updated.realm_roles.contains(&expected_role.name) {
                updated.realm_roles.push(expected_role.name.clone());
            } else if !assign {
                updated.realm_roles.retain(|name| name != &expected_role.name);
            }
            for (key, value) in current.attributes {
                if sensitive_key(&key) {
                    updated.attributes.entry(key).or_insert(value);
                }
            }
            let pg: PgGroup = (&updated).try_into()?;
            expect_one(
                sqlx::query("UPDATE groups SET realm_roles = ?3, client_roles = ?4 WHERE realm_id = ?1 AND id = ?2")
                    .bind(pg.realm_id)
                    .bind(pg.id)
                    .bind(&pg.realm_roles)
                    .bind(&pg.client_roles)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::UpdateRole { expected, updated } => {
            let current: Option<PgRole> =
                sqlx::query_as("SELECT * FROM roles WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(expected.realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            let current: Role = current.try_into()?;
            if redacted_role(current.clone()) != expected {
                return Err(IssuerdError::Conflict);
            }
            let mut effective = updated;
            for (key, value) in current.attributes {
                if sensitive_key(&key) {
                    effective.attributes.entry(key).or_insert(value);
                }
            }
            let pg: PgRole = (&effective).try_into()?;
            expect_one(
                sqlx::query(
                    r#"UPDATE roles SET name = ?3, description = ?4, client_role = ?5,
                        client_id = ?6, composite = ?7, composites = ?8, attributes = ?9
                        WHERE realm_id = ?1 AND id = ?2"#,
                )
                .bind(pg.realm_id)
                .bind(pg.id)
                .bind(&pg.name)
                .bind(&pg.description)
                .bind(pg.client_role)
                .bind(pg.client_id)
                .bind(pg.composite)
                .bind(&pg.composites)
                .bind(&pg.attributes)
                .execute(&mut **tx)
                .await
                .map_err(sqlx_error)?
                .rows_affected(),
            )
        }
        McpStepUpMutation::UserGroupMembership {
            realm_id,
            user_id,
            expected_group,
            expected_roles,
            assign,
            expected_present,
        } => {
            sqlx::query("SELECT id FROM users WHERE realm_id = ?1 AND id = ?2")
                .bind(uuid(realm_id.as_ref())?)
                .bind(uuid(user_id.as_ref())?)
                .fetch_optional(&mut **tx)
                .await
                .map_err(sqlx_error)?
                .ok_or(IssuerdError::Conflict)?;
            let current: Option<PgGroup> =
                sqlx::query_as("SELECT * FROM groups WHERE realm_id = ?1 AND id = ?2")
                    .bind(uuid(realm_id.as_ref())?)
                    .bind(uuid(expected_group.id.as_ref())?)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sqlx_error)?;
            let Some(current) = current else {
                return Err(IssuerdError::Conflict);
            };
            if redacted_group(current.try_into()?) != expected_group {
                return Err(IssuerdError::Conflict);
            }
            for expected_role in expected_roles {
                let current: Option<PgRole> =
                    sqlx::query_as("SELECT * FROM roles WHERE realm_id = ?1 AND id = ?2")
                        .bind(uuid(realm_id.as_ref())?)
                        .bind(uuid(expected_role.id.as_ref())?)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(sqlx_error)?;
                let Some(current) = current else {
                    return Err(IssuerdError::Conflict);
                };
                if redacted_role(current.try_into()?) != expected_role {
                    return Err(IssuerdError::Conflict);
                }
            }
            let present: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM user_groups WHERE realm_id = ?1 AND user_id = ?2 AND group_id = ?3)",
            )
            .bind(uuid(realm_id.as_ref())?)
            .bind(uuid(user_id.as_ref())?)
            .bind(uuid(expected_group.id.as_ref())?)
            .fetch_one(&mut **tx)
            .await
            .map_err(sqlx_error)?;
            if present != expected_present {
                return Err(IssuerdError::Conflict);
            }
            if assign {
                sqlx::query(
                    "INSERT INTO user_groups (realm_id, user_id, group_id) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
                )
            } else {
                sqlx::query("DELETE FROM user_groups WHERE realm_id = ?1 AND user_id = ?2 AND group_id = ?3")
            }
            .bind(uuid(realm_id.as_ref())?)
            .bind(uuid(user_id.as_ref())?)
            .bind(uuid(expected_group.id.as_ref())?)
            .execute(&mut **tx)
            .await
            .map_err(sqlx_error)?;
            Ok(())
        }
    }
}

fn expect_one(rows: u64) -> Result<(), IssuerdError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(IssuerdError::Conflict)
    }
}

fn uuid(value: &str) -> Result<uuid::Uuid, IssuerdError> {
    uuid::Uuid::parse_str(value).map_err(|error| IssuerdError::InvalidRequest(error.to_string()))
}

const SQLITE_BUSY: &str = "SQLite database is locked";

fn is_busy(error: &IssuerdError) -> bool {
    matches!(error, IssuerdError::ServerError(message) if message == SQLITE_BUSY)
}

fn sqlx_error(error: sqlx::Error) -> IssuerdError {
    match error {
        sqlx::Error::Database(ref db)
            if db
                .code()
                .and_then(|code| code.parse::<i32>().ok())
                .is_some_and(|code| matches!(code & 0xff, 5 | 6)) =>
        {
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
        _ => IssuerdError::ServerError(error.to_string()),
    }
}

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "secret",
        "password",
        "credential",
        "privatekey",
        "token",
        "clientassertion",
    ]
    .iter()
    .any(|fragment| normalized.contains(fragment))
}

fn redacted_user(mut value: User) -> User {
    value.attributes.retain(|key, _| !sensitive_key(key));
    value
}

fn redacted_client(mut value: Client) -> Client {
    value.secret = None;
    value.attributes.retain(|key, _| !sensitive_key(key));
    value
}

fn redacted_realm(mut value: Realm) -> Realm {
    value.attributes.retain(|key, _| !sensitive_key(key));
    value
}

fn redacted_group(mut value: Group) -> Group {
    value.attributes.retain(|key, _| !sensitive_key(key));
    value
}

fn redacted_role(mut value: Role) -> Role {
    value.attributes.retain(|key, _| !sensitive_key(key));
    value
}

fn redacted_idp(mut value: IdentityProviderConfig) -> IdentityProviderConfig {
    value.config.retain(|key, _| !sensitive_key(key));
    value
}

fn redacted_flow(mut value: FlowConfig) -> FlowConfig {
    for stage in &mut value.stages {
        if let Some(config) = &mut stage.authenticator_config {
            config.config.retain(|key, _| !sensitive_key(key));
        }
    }
    value
}

fn redacted_credential(mut value: Credential) -> Credential {
    value.secret_data.clear();
    value.credential_data = Value::Null;
    value
}

fn same_credentials(mut left: Vec<Credential>, mut right: Vec<Credential>) -> bool {
    left = left.into_iter().map(redacted_credential).collect();
    right = right.into_iter().map(redacted_credential).collect();
    left.sort_by(|a, b| a.id.cmp(&b.id));
    right.sort_by(|a, b| a.id.cmp(&b.id));
    left == right
}
