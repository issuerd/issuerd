// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Durable operation-bound MCP grants and serializable PostgreSQL execution.

use issuerd_core::*;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{Postgres, Transaction};

use crate::{db_types::*, postgres::PostgresStorage};

fn json_error(error: serde_json::Error) -> IssuerdError {
    IssuerdError::ServerError(format!("invalid step-up grant serialization: {error}"))
}

fn from_json<T: DeserializeOwned>(value: Value) -> Result<T, IssuerdError> {
    serde_json::from_value(value).map_err(json_error)
}

#[derive(Debug, sqlx::FromRow)]
struct PgStepUpGrant {
    version: i32,
    operation_id: String,
    operation_hash: String,
    canonicalization_version: i32,
    realm_id: uuid::Uuid,
    client_id: String,
    subject_user_id: String,
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

impl PgStepUpGrant {
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
            subject_user_id: UserId::new(self.subject_user_id)?,
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
    storage: &PostgresStorage,
    token_jti: &JwtId,
) -> Result<Option<McpStepUpGrant>, IssuerdError> {
    let row: Option<PgStepUpGrant> =
        sqlx::query_as("SELECT * FROM mcp_step_up_grants WHERE token_jti = $1")
            .bind(token_jti.as_ref())
            .fetch_optional(storage.pool())
            .await
            .map_err(sqlx_error)?;
    row.map(PgStepUpGrant::into_grant).transpose()
}

pub(crate) async fn create_grant(
    storage: &PostgresStorage,
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
    sqlx::query(
        r#"INSERT INTO mcp_step_up_grants (
            token_jti, version, operation_id, operation_hash, canonicalization_version,
            realm_id, client_id, subject_user_id, resource, tool, mutation_json,
            origin_access_token_jti, dpop_jkt, approval_auth_time, approval_acr,
            approval_amr, status, result_json, issued_at, expires_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21
        )"#,
    )
    .bind(grant.token_jti.as_ref())
    .bind(version)
    .bind(&grant.operation_id)
    .bind(&grant.operation_hash)
    .bind(canonicalization_version)
    .bind(uuid(grant.realm_id.as_ref())?)
    .bind(grant.client_id.as_str())
    .bind(grant.subject_user_id.as_ref())
    .bind(&grant.resource)
    .bind(&grant.tool)
    .bind(mutation_json)
    .bind(&grant.origin_access_token_jti)
    .bind(&grant.dpop_jkt)
    .bind(grant.approval_auth_time)
    .bind(&grant.approval_acr)
    .bind(approval_amr)
    .bind(status_name(grant.status))
    .bind(&grant.result_json)
    .bind(grant.issued_at)
    .bind(grant.expires_at)
    .bind(grant.updated_at)
    .execute(storage.pool())
    .await
    .map_err(sqlx_error)?;
    Ok(())
}

pub(crate) async fn execute_grant(
    storage: &PostgresStorage,
    token_jti: &JwtId,
    operation_hash: &str,
    mutation: &McpStepUpMutation,
    result_json: Value,
) -> Result<McpStepUpExecution, IssuerdError> {
    const MAX_SERIALIZATION_ATTEMPTS: usize = 8;

    for _ in 0..MAX_SERIALIZATION_ATTEMPTS {
        match execute_grant_once(storage, token_jti, operation_hash, mutation, result_json.clone())
            .await
        {
            Err(error) if is_serialization_failure(&error) => {}
            result => return result,
        }
    }
    Err(IssuerdError::TemporarilyUnavailable)
}

async fn execute_grant_once(
    storage: &PostgresStorage,
    token_jti: &JwtId,
    operation_hash: &str,
    mutation: &McpStepUpMutation,
    result_json: Value,
) -> Result<McpStepUpExecution, IssuerdError> {
    let mut tx = storage.pool().begin().await.map_err(sqlx_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(sqlx_error)?;
    let row: Option<PgStepUpGrant> =
        sqlx::query_as("SELECT * FROM mcp_step_up_grants WHERE token_jti = $1 FOR UPDATE")
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
        "UPDATE mcp_step_up_grants SET status = 'executing', updated_at = $2 WHERE token_jti = $1 AND status = 'active'",
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
                "UPDATE mcp_step_up_grants SET status = 'failed_definite', updated_at = $2 WHERE token_jti = $1",
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
        "UPDATE mcp_step_up_grants SET status = 'succeeded', result_json = $2, updated_at = $3 WHERE token_jti = $1",
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
    tx: &mut Transaction<'_, Postgres>,
    mutation: &McpStepUpMutation,
) -> Result<(), IssuerdError> {
    let mutation = mutation.redacted();
    match mutation {
        McpStepUpMutation::DeleteUser { expected } => {
            let current: Option<PgUser> =
                sqlx::query_as("SELECT * FROM users WHERE realm_id = $1 AND id = $2 FOR UPDATE")
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
                sqlx::query("DELETE FROM users WHERE realm_id = $1 AND id = $2")
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
                sqlx::query_as("SELECT * FROM groups WHERE realm_id = $1 AND id = $2 FOR UPDATE")
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
                sqlx::query("DELETE FROM groups WHERE realm_id = $1 AND id = $2")
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
                sqlx::query_as("SELECT * FROM roles WHERE realm_id = $1 AND id = $2 FOR UPDATE")
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
                sqlx::query("DELETE FROM roles WHERE realm_id = $1 AND id = $2")
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
                sqlx::query_as("SELECT * FROM clients WHERE realm_id = $1 AND id = $2 FOR UPDATE")
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
                sqlx::query("DELETE FROM clients WHERE realm_id = $1 AND id = $2")
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
                sqlx::query_as("SELECT * FROM clients WHERE realm_id = $1 AND id = $2 FOR UPDATE")
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
                    r#"UPDATE clients SET redirect_uris = $3, web_origins = $4, attributes = $5,
                        public_client = $6, bearer_only = $7, consent_required = $8,
                        full_scope_allowed = $9, service_accounts_enabled = $10
                        WHERE realm_id = $1 AND id = $2"#,
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
            let current: Option<PgRealm> =
                sqlx::query_as("SELECT * FROM realms WHERE id = $1 FOR UPDATE")
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
                    r#"UPDATE realms SET display_name = $2, enabled = $3, ssl_required = $4,
                        access_token_lifespan = $5, refresh_token_lifespan = $6,
                        sso_session_idle_timeout = $7, sso_session_max_lifespan = $8,
                        offline_session_idle_timeout = $9, login_theme = $10, email_theme = $11,
                        admin_theme = $12, registration_enabled = $13, reset_password_allowed = $14,
                        remember_me_enabled = $15, verify_email_enabled = $16,
                        login_with_email_allowed = $17, duplicate_emails_allowed = $18,
                        edit_username_allowed = $19, updated_at = now() WHERE id = $1"#,
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
            let current: Option<PgRealm> =
                sqlx::query_as("SELECT * FROM realms WHERE id = $1 FOR UPDATE")
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
                    "UPDATE realms SET events_enabled = $2, events_expiration_secs = $3, admin_events_enabled = $4, include_representations = $5, events_listeners = $6, updated_at = now() WHERE id = $1",
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
                "INSERT INTO identity_providers (id, realm_id, alias, provider_id, enabled, config) VALUES ($1, $2, $3, $4, $5, $6)",
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
            let current: Option<PgIdentityProvider> = sqlx::query_as(
                "SELECT * FROM identity_providers WHERE realm_id = $1 AND id = $2 FOR UPDATE",
            )
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
                    "UPDATE identity_providers SET alias = $3, provider_id = $4, enabled = $5, config = $6 WHERE realm_id = $1 AND id = $2",
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
            let current: Option<PgIdentityProvider> = sqlx::query_as(
                "SELECT * FROM identity_providers WHERE realm_id = $1 AND id = $2 FOR UPDATE",
            )
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
                sqlx::query("DELETE FROM identity_providers WHERE realm_id = $1 AND id = $2")
                    .bind(uuid(realm_id.as_ref())?)
                    .bind(uuid(expected.id.as_ref())?)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::UpdateFlow { expected, updated } => {
            let current: Option<PgFlowConfig> = sqlx::query_as(
                "SELECT * FROM flow_configs WHERE realm_id = $1 AND alias = $2 FOR UPDATE",
            )
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
                    "UPDATE flow_configs SET stages = $3 WHERE realm_id = $1 AND alias = $2",
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
            let current: Option<PgRealm> =
                sqlx::query_as("SELECT * FROM realms WHERE id = $1 FOR UPDATE")
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
                sqlx::query("UPDATE realms SET not_before = $2, updated_at = now() WHERE id = $1")
                    .bind(uuid(expected.id.as_ref())?)
                    .bind(not_before)
                    .execute(&mut **tx)
                    .await
                    .map_err(sqlx_error)?
                    .rows_affected(),
            )
        }
        McpStepUpMutation::DeleteRealm { expected } => {
            let current: Option<PgRealm> =
                sqlx::query_as("SELECT * FROM realms WHERE id = $1 FOR UPDATE")
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
                sqlx::query("DELETE FROM realms WHERE id = $1")
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
                "SELECT * FROM credentials WHERE realm_id = $1 AND user_id = $2 AND credential_type = 'totp' FOR UPDATE",
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
                        "DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND id = $3",
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
                "SELECT * FROM credentials WHERE realm_id = $1 AND user_id = $2 AND id = $3 FOR UPDATE",
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
                    "DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND id = $3",
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
                sqlx::query_as("SELECT * FROM roles WHERE realm_id = $1 AND id = $2 FOR UPDATE")
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
                    "SELECT EXISTS(SELECT 1 FROM user_client_roles WHERE realm_id = $1 AND user_id = $2 AND role_id = $3)",
                )
            } else {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM user_realm_roles WHERE realm_id = $1 AND user_id = $2 AND role_id = $3)",
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
                        "INSERT INTO user_client_roles (realm_id, user_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    )
                }
                (true, false) => {
                    sqlx::query(
                        "DELETE FROM user_client_roles WHERE realm_id = $1 AND user_id = $2 AND role_id = $3",
                    )
                }
                (false, true) => {
                    sqlx::query(
                        "INSERT INTO user_realm_roles (realm_id, user_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    )
                }
                (false, false) => {
                    sqlx::query(
                        "DELETE FROM user_realm_roles WHERE realm_id = $1 AND user_id = $2 AND role_id = $3",
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
                sqlx::query_as("SELECT * FROM groups WHERE realm_id = $1 AND id = $2 FOR UPDATE")
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
                sqlx::query_as("SELECT * FROM roles WHERE realm_id = $1 AND id = $2 FOR UPDATE")
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
                sqlx::query("UPDATE groups SET realm_roles = $3, client_roles = $4 WHERE realm_id = $1 AND id = $2")
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

const SERIALIZATION_FAILURE: &str =
    "MCP step-up transaction serialization failure (SQLSTATE 40001)";

fn is_serialization_failure(error: &IssuerdError) -> bool {
    matches!(error, IssuerdError::ServerError(message) if message == SERIALIZATION_FAILURE)
}

fn sqlx_error(error: sqlx::Error) -> IssuerdError {
    match error {
        sqlx::Error::Database(ref db) if db.code().as_deref() == Some("40001") => {
            IssuerdError::ServerError(SERIALIZATION_FAILURE.into())
        }
        sqlx::Error::Database(ref db) if db.code().as_deref() == Some("23505") => {
            IssuerdError::Conflict
        }
        sqlx::Error::Database(ref db) if db.constraint().is_some() => {
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
    ["secret", "password", "credential", "privatekey", "token"]
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt};

    use super::*;
    use crate::{json::JsonFileStorage, memory::InMemoryStorage};

    fn realm_and_user() -> (Realm, User) {
        let id = uuid::Uuid::new_v4().to_string();
        let realm = Realm {
            id: RealmId::new(id).unwrap(),
            name: RealmName::new(format!("step-up-{}", uuid::Uuid::new_v4())).unwrap(),
            ..Realm::default()
        };
        let now = chrono::Utc::now();
        let user = User {
            id: UserId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm.id.clone(),
            username: Username::new(format!("delete-{}", uuid::Uuid::new_v4())).unwrap(),
            email: None,
            email_verified: false,
            first_name: Some(DisplayName::new("Before").unwrap()),
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        (realm, user)
    }

    fn test_grant(user: &User) -> McpStepUpGrant {
        let now = chrono::Utc::now().timestamp();
        McpStepUpGrant {
            version: 1,
            operation_id: uuid::Uuid::new_v4().to_string(),
            operation_hash: "test-operation-hash".into(),
            canonicalization_version: 1,
            realm_id: user.realm_id.clone(),
            client_id: ClientIdentifier::new("test-client").unwrap(),
            subject_user_id: user.id.clone(),
            resource: "https://issuer.example/realms/test/mcp".into(),
            tool: "users_delete".into(),
            mutation: McpStepUpMutation::DeleteUser {
                expected: user.clone(),
            },
            origin_access_token_jti: "origin-jti".into(),
            token_jti: JwtId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            dpop_jkt: "test-jkt".into(),
            approval_auth_time: now,
            approval_acr: None,
            approval_amr: vec!["pwd".into()],
            status: McpStepUpExecutionStatus::Active,
            result_json: None,
            issued_at: now,
            expires_at: now + 120,
            updated_at: now,
        }
    }

    async fn grant_lifecycle(storage: &dyn Storage) {
        let (realm, user) = realm_and_user();
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();
        let user = storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
        let grant = test_grant(&user);
        let mutation = grant.mutation.clone();
        storage.create_mcp_step_up_grant(&grant).await.unwrap();
        assert_eq!(
            storage.create_mcp_step_up_grant(&grant).await.unwrap_err(),
            IssuerdError::Conflict
        );

        let result = serde_json::json!({"deleted": true, "id": user.id});
        let execution = storage
            .execute_mcp_step_up(&grant.token_jti, &grant.operation_hash, &mutation, result.clone())
            .await
            .unwrap();
        assert_eq!(execution.status, McpStepUpExecutionStatus::Succeeded);
        assert_eq!(execution.result_json, Some(result.clone()));
        let replay = storage
            .execute_mcp_step_up(&grant.token_jti, &grant.operation_hash, &mutation, result)
            .await
            .unwrap();
        assert_eq!(replay, execution);
        assert!(storage.get_user(&realm.id, &user.id).await.unwrap().is_none());

        let (_, changed) = realm_and_user();
        storage.create_user(&realm.id, &changed).await.unwrap();
        let changed = storage.get_user(&realm.id, &changed.id).await.unwrap().unwrap();
        let changed_grant = test_grant(&changed);
        storage.create_mcp_step_up_grant(&changed_grant).await.unwrap();
        assert_eq!(
            storage
                .execute_mcp_step_up(
                    &changed_grant.token_jti,
                    "wrong",
                    &changed_grant.mutation,
                    Value::Null,
                )
                .await
                .unwrap_err(),
            IssuerdError::AccessDenied
        );
        let mut modified = changed.clone();
        modified.first_name = Some(DisplayName::new("After").unwrap());
        storage.update_user(&realm.id, &modified).await.unwrap();
        assert_eq!(
            storage
                .execute_mcp_step_up(
                    &changed_grant.token_jti,
                    &changed_grant.operation_hash,
                    &changed_grant.mutation,
                    Value::Null,
                )
                .await
                .unwrap_err(),
            IssuerdError::Conflict
        );
        assert!(storage.get_user(&realm.id, &changed.id).await.unwrap().is_some());
        assert_eq!(
            storage
                .get_mcp_step_up_grant(&changed_grant.token_jti)
                .await
                .unwrap()
                .unwrap()
                .status,
            McpStepUpExecutionStatus::FailedDefinite
        );
    }

    #[tokio::test]
    async fn memory_executes_once_reconciles_and_fails_changed_preconditions() {
        grant_lifecycle(&InMemoryStorage::new()).await;
    }

    async fn concurrent_reconciliation<S: Storage + 'static>(storage: Arc<S>, calls: usize) {
        let (realm, user) = realm_and_user();
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &user).await.unwrap();
        let user = storage.get_user(&realm.id, &user.id).await.unwrap().unwrap();
        let grant = test_grant(&user);
        storage.create_mcp_step_up_grant(&grant).await.unwrap();
        let start = Arc::new(tokio::sync::Barrier::new(calls));
        let mut tasks = tokio::task::JoinSet::new();
        for attempt in 0..calls {
            let storage = Arc::clone(&storage);
            let grant = grant.clone();
            let start = Arc::clone(&start);
            tasks.spawn(async move {
                start.wait().await;
                storage
                    .execute_mcp_step_up(
                        &grant.token_jti,
                        &grant.operation_hash,
                        &grant.mutation,
                        serde_json::json!({"attempt": attempt}),
                    )
                    .await
            });
        }
        let mut executions = Vec::new();
        while let Some(result) = tasks.join_next().await {
            executions.push(result.unwrap());
        }
        assert_eq!(executions.len(), calls);
        assert!(
            executions.iter().all(Result::is_ok),
            "concurrent execution results: {executions:?}"
        );
        let executions: Vec<_> = executions.into_iter().map(Result::unwrap).collect();
        assert!(executions.iter().all(|execution| execution == &executions[0]));
        let stored = storage.get_mcp_step_up_grant(&grant.token_jti).await.unwrap().unwrap();
        assert_eq!(stored.result_json, executions[0].result_json);
        assert!(storage.get_user(&realm.id, &user.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_concurrent_consumption_executes_once_and_replays_one_outcome() {
        concurrent_reconciliation(Arc::new(InMemoryStorage::new()), 12).await;
    }

    #[tokio::test]
    async fn json_snapshot_roundtrip_preserves_execution_outcome() {
        let path = std::env::temp_dir()
            .join(format!("issuerd-step-up-test-{}.json", uuid::Uuid::new_v4()));
        let (realm, user) = realm_and_user();
        let grant = test_grant(&user);
        {
            let storage = JsonFileStorage::new(&path).unwrap();
            storage.create_realm(&realm).await.unwrap();
            storage.create_user(&realm.id, &user).await.unwrap();
            storage.create_mcp_step_up_grant(&grant).await.unwrap();
            storage
                .execute_mcp_step_up(
                    &grant.token_jti,
                    &grant.operation_hash,
                    &grant.mutation,
                    serde_json::json!({"deleted": true}),
                )
                .await
                .unwrap();
        }
        {
            let storage = JsonFileStorage::new(&path).unwrap();
            let stored = storage.get_mcp_step_up_grant(&grant.token_jti).await.unwrap().unwrap();
            assert_eq!(stored.status, McpStepUpExecutionStatus::Succeeded);
            assert_eq!(stored.result_json, Some(serde_json::json!({"deleted": true})));
            assert!(storage.get_user(&realm.id, &user.id).await.unwrap().is_none());
        }
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn postgres_executes_once_reconciles_and_fails_changed_preconditions() {
        if std::process::Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| !status.success())
            .unwrap_or(true)
        {
            eprintln!("skipping PostgreSQL step-up test: Docker unavailable");
            return;
        }
        let image = GenericImage::new("postgres", "15-alpine")
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_DB", "test");
        let container = image.start().await.unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let storage = Arc::new(
            PostgresStorage::connect(&format!("postgres://postgres:postgres@{host}:{port}/test"))
                .await
                .unwrap(),
        );
        storage.run_migrations().await.unwrap();
        grant_lifecycle(storage.as_ref()).await;

        for _ in 0..4 {
            concurrent_reconciliation(Arc::clone(&storage), 16).await;
        }
    }

    async fn execute_variant(storage: &dyn Storage, subject: &User, mutation: McpStepUpMutation) {
        let mut grant = test_grant(subject);
        grant.tool = mutation.tool().into();
        grant.mutation = mutation.clone();
        storage.create_mcp_step_up_grant(&grant).await.unwrap();
        let execution = storage
            .execute_mcp_step_up(
                &grant.token_jti,
                &grant.operation_hash,
                &mutation,
                serde_json::json!({"status": "completed"}),
            )
            .await
            .unwrap_or_else(|error| panic!("{} failed: {error:?}", grant.tool));
        assert_eq!(execution.status, McpStepUpExecutionStatus::Succeeded);
    }

    fn test_group(realm: &Realm, name: &str) -> Group {
        Group {
            id: GroupId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            name: GroupName::new(name).unwrap(),
            path: GroupPath::new(format!("/{name}")).unwrap(),
            realm_id: realm.id.clone(),
            parent_id: None,
            sub_groups: Vec::new(),
            attributes: HashMap::new(),
            realm_roles: Vec::new(),
            client_roles: HashMap::new(),
        }
    }

    fn test_role(realm: &Realm, name: &str) -> Role {
        Role {
            id: RoleId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            name: RoleName::new(name).unwrap(),
            description: None,
            realm_id: realm.id.clone(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    fn client(realm: &Realm, identifier: &str) -> Client {
        Client {
            id: ClientId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new(identifier).unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("must-survive".into()),
            redirect_uris: Vec::new(),
            web_origins: Vec::new(),
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    async fn mutation_matrix(storage: &dyn Storage) {
        let (realm, subject) = realm_and_user();
        storage.create_realm(&realm).await.unwrap();
        storage.create_user(&realm.id, &subject).await.unwrap();
        let subject = storage.get_user(&realm.id, &subject.id).await.unwrap().unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::DeleteUser {
                expected: subject.clone(),
            },
        )
        .await;
        assert!(storage.get_user(&realm.id, &subject.id).await.unwrap().is_none());
        storage.create_user(&realm.id, &subject).await.unwrap();

        let group = test_group(&realm, "delete-group");
        storage.create_group(&realm.id, &group).await.unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::DeleteGroup {
                expected: group.clone(),
            },
        )
        .await;
        assert!(storage.get_group(&realm.id, &group.id).await.unwrap().is_none());

        let role = test_role(&realm, "delete-role");
        storage.create_role(&realm.id, &role).await.unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::DeleteRole {
                expected: role.clone(),
            },
        )
        .await;
        assert!(storage.get_role(&realm.id, &role.id).await.unwrap().is_none());

        let client = client(&realm, "security-client");
        storage.create_client(&realm.id, &client).await.unwrap();
        let mut updated = client.clone();
        updated.redirect_uris = vec![RedirectUri::new("https://app.example/callback").unwrap()];
        updated.web_origins = vec![WebOrigin::new("https://app.example").unwrap()];
        updated.public_client = true;
        updated.bearer_only = true;
        updated.consent_required = true;
        updated.full_scope_allowed = false;
        updated.service_accounts_enabled = true;
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::UpdateClientSecurity {
                expected: client.clone(),
                updated: updated.clone(),
            },
        )
        .await;
        let secured = storage.get_client(&realm.id, &client.id).await.unwrap().unwrap();
        assert_eq!(secured.secret.as_deref(), Some("must-survive"));
        assert_eq!(secured.redirect_uris, updated.redirect_uris);
        assert!(secured.public_client);
        assert!(secured.bearer_only);
        assert!(secured.consent_required);
        assert!(!secured.full_scope_allowed);
        assert!(secured.service_accounts_enabled);
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::DeleteClient {
                expected: secured.clone(),
            },
        )
        .await;
        assert!(storage.get_client(&realm.id, &client.id).await.unwrap().is_none());

        let mut realm_settings = storage.get_realm(&realm.id).await.unwrap().unwrap();
        let expected_realm = realm_settings.clone();
        realm_settings.display_name = Some(DisplayName::new("After").unwrap());
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::UpdateRealmSettings {
                expected: expected_realm,
                updated: realm_settings,
            },
        )
        .await;
        assert_eq!(
            storage
                .get_realm(&realm.id)
                .await
                .unwrap()
                .unwrap()
                .display_name
                .unwrap()
                .as_str(),
            "After"
        );

        let expected_realm = storage.get_realm(&realm.id).await.unwrap().unwrap();
        let mut events = expected_realm.clone();
        events.events_expiration_secs = 600;
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::UpdateEventsConfig {
                expected: expected_realm,
                updated: events,
            },
        )
        .await;
        assert_eq!(
            storage.get_realm(&realm.id).await.unwrap().unwrap().events_expiration_secs,
            600
        );

        let idp = IdentityProviderConfig {
            id: IdentityProviderId::new(uuid::Uuid::new_v4()).unwrap(),
            alias: Alias::new("strict-idp").unwrap(),
            provider_id: ProviderId::new("oidc"),
            enabled: false,
            config: [("clientSecret".into(), "idp-secret".into())].into_iter().collect(),
        };
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::CreateIdentityProvider {
                realm_id: realm.id.clone(),
                new: idp.clone(),
            },
        )
        .await;
        storage.update_identity_provider(&realm.id, &idp).await.unwrap();
        let expected_idp =
            storage.get_identity_provider(&realm.id, &idp.id).await.unwrap().unwrap();
        let mut updated_idp = expected_idp.clone();
        updated_idp.alias = Alias::new("strict-idp-renamed").unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::UpdateIdentityProvider {
                realm_id: realm.id.clone(),
                expected: expected_idp,
                updated: updated_idp.clone(),
            },
        )
        .await;
        let renamed = storage.get_identity_provider(&realm.id, &idp.id).await.unwrap().unwrap();
        assert_eq!(renamed.alias.as_str(), "strict-idp-renamed");
        assert_eq!(renamed.config["clientSecret"], "idp-secret");
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::DeleteIdentityProvider {
                realm_id: realm.id.clone(),
                expected: renamed,
            },
        )
        .await;

        let stage_id = FlowStageId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        let flow = FlowConfig {
            alias: Alias::new("custom-flow").unwrap(),
            realm_id: realm.id.clone(),
            provider_id: "basic-flow".into(),
            top_level: true,
            built_in: false,
            stages: vec![FlowStage {
                id: stage_id,
                requirement: Requirement::Required,
                authenticator: Alias::new("auth-username-password").unwrap(),
                priority: 1,
                sub_flow_alias: None,
                authenticator_config: Some(AuthenticatorConfig {
                    alias: Alias::new("password-config").unwrap(),
                    config: serde_json::Map::from_iter([
                        ("secret".into(), Value::String("flow-secret".into())),
                        ("mode".into(), Value::String("safe".into())),
                    ]),
                }),
            }],
        };
        storage.create_flow_config(&realm.id, &flow).await.unwrap();
        let mut updated_flow = flow.clone();
        updated_flow.stages[0].requirement = Requirement::Alternative;
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::UpdateFlow {
                expected: flow,
                updated: updated_flow,
            },
        )
        .await;
        let flow = storage.get_flow_config(&realm.id, "custom-flow").await.unwrap().unwrap();
        assert_eq!(flow.stages[0].requirement, Requirement::Alternative);
        let config = flow.stages[0].authenticator_config.as_ref().unwrap();
        assert_eq!(config.config["secret"], "flow-secret");
        assert_eq!(config.config["mode"], "safe");

        let expected_realm = storage.get_realm(&realm.id).await.unwrap().unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::PushNotBefore {
                expected: expected_realm,
                not_before: 123,
            },
        )
        .await;
        assert_eq!(storage.get_realm(&realm.id).await.unwrap().unwrap().not_before, 123);

        let totp = Credential {
            id: CredentialId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            credential_type: CredentialType::Totp,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: b"totp-secret".to_vec(),
            credential_data: serde_json::json!({"temporary": false}),
            priority: 0,
        };
        storage.create_credential(&realm.id, &subject.id, &totp).await.unwrap();
        let expected = storage
            .get_credentials(&realm.id, &subject.id, CredentialType::Totp)
            .await
            .unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::DeleteTotp {
                realm_id: realm.id.clone(),
                user_id: subject.id.clone(),
                expected,
            },
        )
        .await;
        assert!(storage
            .get_credentials(&realm.id, &subject.id, CredentialType::Totp)
            .await
            .unwrap()
            .is_empty());

        let webauthn = Credential {
            id: CredentialId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            credential_type: CredentialType::WebAuthn,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: b"webauthn-secret".to_vec(),
            credential_data: serde_json::json!({"temporary": false}),
            priority: 0,
        };
        storage.create_credential(&realm.id, &subject.id, &webauthn).await.unwrap();
        let expected = storage
            .list_credentials(&realm.id, &subject.id)
            .await
            .unwrap()
            .into_iter()
            .find(|credential| credential.id == webauthn.id)
            .unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::DeleteWebauthn {
                realm_id: realm.id.clone(),
                user_id: subject.id.clone(),
                expected,
            },
        )
        .await;

        let mapped_role = test_role(&realm, "mapped-role");
        storage.create_role(&realm.id, &mapped_role).await.unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::UserRoleMapping {
                realm_id: realm.id.clone(),
                user_id: subject.id.clone(),
                expected_role: mapped_role.clone(),
                client_role: false,
                assign: true,
                expected_present: false,
            },
        )
        .await;
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::UserRoleMapping {
                realm_id: realm.id.clone(),
                user_id: subject.id.clone(),
                expected_role: mapped_role.clone(),
                client_role: false,
                assign: false,
                expected_present: true,
            },
        )
        .await;

        let mapped_group = test_group(&realm, "mapped-group");
        storage.create_group(&realm.id, &mapped_group).await.unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::GroupRoleMapping {
                expected: mapped_group.clone(),
                expected_role: mapped_role.clone(),
                client_id: None,
                assign: true,
            },
        )
        .await;
        let mapped_group = storage.get_group(&realm.id, &mapped_group.id).await.unwrap().unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::GroupRoleMapping {
                expected: mapped_group,
                expected_role: mapped_role,
                client_id: None,
                assign: false,
            },
        )
        .await;

        let expected_realm = storage.get_realm(&realm.id).await.unwrap().unwrap();
        execute_variant(
            storage,
            &subject,
            McpStepUpMutation::DeleteRealm {
                expected: expected_realm,
            },
        )
        .await;
        assert!(storage.get_realm(&realm.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_supports_every_strict_mutation_variant() {
        mutation_matrix(&InMemoryStorage::new()).await;
    }

    #[tokio::test]
    async fn postgres_supports_every_strict_mutation_variant() {
        if std::process::Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| !status.success())
            .unwrap_or(true)
        {
            eprintln!("skipping PostgreSQL mutation matrix: Docker unavailable");
            return;
        }
        let image = GenericImage::new("postgres", "15-alpine")
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_DB", "test");
        let container = image.start().await.unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let storage =
            PostgresStorage::connect(&format!("postgres://postgres:postgres@{host}:{port}/test"))
                .await
                .unwrap();
        storage.run_migrations().await.unwrap();
        mutation_matrix(&storage).await;
    }
}
