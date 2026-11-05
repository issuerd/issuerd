// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use chrono::{DateTime, Utc};
use issuerd_core::{Consent, IssuerdError, UserSession};
use serde_json::Value;

use crate::db_types::{PgConsent, PgUserSession};

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct SqliteConsent {
    pub(crate) realm_id: uuid::Uuid,
    pub(crate) user_id: uuid::Uuid,
    pub(crate) client_id: uuid::Uuid,
    pub(crate) granted_scopes: Value,
    pub(crate) granted_realm_roles: Value,
    pub(crate) granted_client_roles: Value,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) last_updated_at: DateTime<Utc>,
}

impl TryFrom<SqliteConsent> for Consent {
    type Error = IssuerdError;

    fn try_from(row: SqliteConsent) -> Result<Self, Self::Error> {
        PgConsent {
            realm_id: row.realm_id,
            user_id: row.user_id,
            client_id: row.client_id.to_string(),
            granted_scopes: row.granted_scopes,
            granted_realm_roles: row.granted_realm_roles,
            granted_client_roles: row.granted_client_roles,
            created_at: row.created_at,
            last_updated_at: row.last_updated_at,
        }
        .try_into()
    }
}

impl TryFrom<&Consent> for SqliteConsent {
    type Error = IssuerdError;

    fn try_from(value: &Consent) -> Result<Self, Self::Error> {
        let row = PgConsent::try_from(value)?;
        Ok(Self {
            realm_id: row.realm_id,
            user_id: row.user_id,
            client_id: crate::db_types::to_uuid(value.client_id.as_ref())?,
            granted_scopes: row.granted_scopes,
            granted_realm_roles: row.granted_realm_roles,
            granted_client_roles: row.granted_client_roles,
            created_at: row.created_at,
            last_updated_at: row.last_updated_at,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct SqliteUserSession {
    pub(crate) id: uuid::Uuid,
    pub(crate) realm_id: uuid::Uuid,
    pub(crate) user_id: uuid::Uuid,
    pub(crate) login_username: String,
    pub(crate) ip_address: Option<String>,
    pub(crate) auth_method: Option<String>,
    pub(crate) remember_me: bool,
    pub(crate) offline: bool,
    pub(crate) started: DateTime<Utc>,
    pub(crate) last_session_refresh: DateTime<Utc>,
    pub(crate) auth_time: DateTime<Utc>,
    pub(crate) impersonator: Option<uuid::Uuid>,
}

impl TryFrom<SqliteUserSession> for UserSession {
    type Error = IssuerdError;

    fn try_from(row: SqliteUserSession) -> Result<Self, Self::Error> {
        PgUserSession {
            id: row.id,
            realm_id: row.realm_id,
            user_id: row.user_id,
            login_username: row.login_username,
            ip_address: row.ip_address,
            auth_method: row.auth_method,
            remember_me: row.remember_me,
            offline: row.offline,
            started: row.started,
            last_session_refresh: row.last_session_refresh,
            auth_time: row.auth_time,
            impersonator: row.impersonator.map(|id| id.to_string()),
        }
        .try_into()
    }
}

impl TryFrom<&UserSession> for SqliteUserSession {
    type Error = IssuerdError;

    fn try_from(value: &UserSession) -> Result<Self, Self::Error> {
        let row = PgUserSession::try_from(value)?;
        Ok(Self {
            id: row.id,
            realm_id: row.realm_id,
            user_id: row.user_id,
            login_username: row.login_username,
            ip_address: row.ip_address,
            auth_method: row.auth_method,
            remember_me: row.remember_me,
            offline: row.offline,
            started: row.started,
            last_session_refresh: row.last_session_refresh,
            auth_time: row.auth_time,
            impersonator: value
                .impersonator
                .as_ref()
                .map(|id| crate::db_types::to_uuid(id.as_ref()))
                .transpose()?,
        })
    }
}
