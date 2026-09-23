// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Row types and JSON/UUID conversion helpers for the PostgreSQL adapter.

use chrono::{DateTime, Utc};
use issuerd_core::*;
use serde_json::Value;
use sqlx::FromRow;
use std::collections::HashMap;

fn to_uuid(id: &str) -> Result<uuid::Uuid, IssuerdError> {
    uuid::Uuid::parse_str(id).map_err(|e| IssuerdError::ServerError(format!("invalid uuid: {e}")))
}

fn json_to_map_string_string(value: Value) -> Result<HashMap<String, String>, IssuerdError> {
    if value.is_null() {
        return Ok(HashMap::new());
    }
    serde_json::from_value(value)
        .map_err(|e| IssuerdError::ServerError(format!("json deserialization error: {e}")))
}

fn json_to_map<K, V>(value: Value) -> Result<HashMap<K, V>, IssuerdError>
where
    K: serde::de::DeserializeOwned + Eq + std::hash::Hash,
    V: serde::de::DeserializeOwned,
{
    if value.is_null() {
        return Ok(HashMap::new());
    }
    serde_json::from_value(value)
        .map_err(|e| IssuerdError::ServerError(format!("json deserialization error: {e}")))
}

fn json_to_vec<T: serde::de::DeserializeOwned>(value: Value) -> Result<Vec<T>, IssuerdError> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    serde_json::from_value(value)
        .map_err(|e| IssuerdError::ServerError(format!("json deserialization error: {e}")))
}

fn json_to_scope(value: Value) -> Result<Scope, IssuerdError> {
    if value.is_null() {
        return Ok(Scope::empty());
    }
    serde_json::from_value(value)
        .map_err(|e| IssuerdError::ServerError(format!("json deserialization error: {e}")))
}

pub(crate) fn map_to_json<T: serde::Serialize>(value: T) -> Result<Value, IssuerdError> {
    serde_json::to_value(value)
        .map_err(|e| IssuerdError::ServerError(format!("json serialization error: {e}")))
}

/// Convert a Postgres `INTEGER` (`i32`) into a domain `u32`, clamping
/// negative values to 0.
fn i32_to_u32(value: i32) -> u32 {
    u32::try_from(value.max(0)).unwrap_or(0)
}

/// Convert a domain `u32` into a Postgres `INTEGER` (`i32`), clamping
/// out-of-range values to `i32::MAX`.
fn u32_to_i32(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

// ------------------------------------------------------------------
// Realm
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgRealm {
    pub id: uuid::Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub ssl_required: String,
    pub password_policy: Value,
    pub login_theme: Option<String>,
    pub email_theme: Option<String>,
    pub admin_theme: Option<String>,
    pub default_role: Option<String>,
    pub access_token_lifespan: i64,
    pub refresh_token_lifespan: i64,
    pub sso_session_idle_timeout: i64,
    pub sso_session_max_lifespan: i64,
    pub offline_session_idle_timeout: i64,
    pub brute_force_protected: bool,
    pub max_login_failures: i32,
    pub wait_increment_secs: i32,
    pub max_failure_wait_secs: i32,
    pub lockout_duration_secs: i32,
    pub registration_enabled: bool,
    pub reset_password_allowed: bool,
    pub remember_me_enabled: bool,
    pub verify_email_enabled: bool,
    pub login_with_email_allowed: bool,
    pub duplicate_emails_allowed: bool,
    pub edit_username_allowed: bool,
    pub remember_me_session_idle_secs: i64,
    pub otp_algorithm: String,
    pub otp_digits: i32,
    pub otp_period_secs: i32,
    pub otp_look_ahead_window: i32,
    pub internationalization_enabled: bool,
    pub supported_locales: Value,
    pub default_locale: Option<String>,
    pub events_enabled: bool,
    pub events_expiration_secs: i64,
    pub admin_events_enabled: bool,
    pub include_representations: bool,
    pub events_listeners: Value,
    pub not_before: i64,
    pub default_groups: Value,
    pub browser_flow: Option<String>,
    pub direct_grant_flow: Option<String>,
    pub reset_credentials_flow: Option<String>,
    pub first_broker_login_flow: Option<String>,
    pub registration_flow: Option<String>,
    pub attributes: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<PgRealm> for Realm {
    type Error = IssuerdError;

    fn try_from(pg: PgRealm) -> Result<Self, Self::Error> {
        let ssl_required = match pg.ssl_required.as_str() {
            "none" => SslRequired::None,
            "external" => SslRequired::External,
            "all" => SslRequired::All,
            _ => SslRequired::External,
        };
        Ok(Self {
            id: RealmId::new(pg.id.to_string()).unwrap(),
            name: RealmName::new(pg.name).unwrap_or(RealmName::new("unknown").unwrap()),
            display_name: pg.display_name.map(DisplayName::new).transpose()?,
            enabled: pg.enabled,
            ssl_required,
            password_policy: serde_json::from_value(pg.password_policy).unwrap_or_default(),
            login_theme: pg.login_theme.map(ThemeName::new).transpose()?,
            email_theme: pg.email_theme.map(ThemeName::new).transpose()?,
            admin_theme: pg.admin_theme.map(ThemeName::new).transpose()?,
            default_role: pg.default_role,
            access_token_lifespan: pg
                .access_token_lifespan
                .try_into()
                .unwrap_or(SecondsNonZero::new(1)),
            refresh_token_lifespan: pg
                .refresh_token_lifespan
                .try_into()
                .unwrap_or(SecondsNonZero::new(1)),
            sso_session_idle_timeout: pg
                .sso_session_idle_timeout
                .try_into()
                .unwrap_or(SecondsNonZero::new(1)),
            sso_session_max_lifespan: pg
                .sso_session_max_lifespan
                .try_into()
                .unwrap_or(SecondsNonZero::new(1)),
            offline_session_idle_timeout: pg
                .offline_session_idle_timeout
                .try_into()
                .unwrap_or(SecondsNonZero::new(1)),
            brute_force_protected: pg.brute_force_protected,
            max_login_failures: i32_to_u32(pg.max_login_failures),
            wait_increment_secs: i32_to_u32(pg.wait_increment_secs),
            max_failure_wait_secs: i32_to_u32(pg.max_failure_wait_secs),
            lockout_duration_secs: i32_to_u32(pg.lockout_duration_secs),
            registration_enabled: pg.registration_enabled,
            reset_password_allowed: pg.reset_password_allowed,
            remember_me_enabled: pg.remember_me_enabled,
            verify_email_enabled: pg.verify_email_enabled,
            login_with_email_allowed: pg.login_with_email_allowed,
            duplicate_emails_allowed: pg.duplicate_emails_allowed,
            edit_username_allowed: pg.edit_username_allowed,
            remember_me_session_idle_secs: pg
                .remember_me_session_idle_secs
                .try_into()
                .unwrap_or(SecondsNonZero::new(604_800)),
            otp_policy: OtpPolicy {
                // Unknown algorithm spellings degrade to the Keycloak default
                // rather than failing the realm load (forward compatibility,
                // same pattern as `ssl_required` above).
                algorithm: pg.otp_algorithm.parse::<OtpHashAlgorithm>().unwrap_or_default(),
                digits: i32_to_u32(pg.otp_digits),
                period_secs: i32_to_u32(pg.otp_period_secs),
                look_ahead_window: i32_to_u32(pg.otp_look_ahead_window),
            },
            internationalization_enabled: pg.internationalization_enabled,
            supported_locales: json_to_vec(pg.supported_locales)?,
            default_locale: pg.default_locale,
            events_enabled: pg.events_enabled,
            events_expiration_secs: pg.events_expiration_secs,
            admin_events_enabled: pg.admin_events_enabled,
            include_representations: pg.include_representations,
            events_listeners: json_to_vec(pg.events_listeners)?,
            not_before: pg.not_before,
            default_groups: json_to_vec(pg.default_groups)?,
            browser_flow: pg.browser_flow,
            direct_grant_flow: pg.direct_grant_flow,
            reset_credentials_flow: pg.reset_credentials_flow,
            first_broker_login_flow: pg.first_broker_login_flow,
            registration_flow: pg.registration_flow,
            attributes: json_to_map_string_string(pg.attributes)?,
        })
    }
}

impl TryFrom<&Realm> for PgRealm {
    type Error = IssuerdError;

    fn try_from(r: &Realm) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(r.id.as_ref())?,
            name: r.name.to_string(),
            display_name: r.display_name.as_ref().map(|n| n.to_string()),
            enabled: r.enabled,
            ssl_required: serde_json::to_string(&r.ssl_required)
                .map_err(|e| IssuerdError::ServerError(format!("json serialization error: {e}")))?
                .trim_matches('"')
                .to_string(),
            password_policy: serde_json::to_value(&r.password_policy)
                .map_err(|e| IssuerdError::ServerError(format!("json serialization error: {e}")))?,
            login_theme: r.login_theme.as_ref().map(|t| t.to_string()),
            email_theme: r.email_theme.as_ref().map(|t| t.to_string()),
            admin_theme: r.admin_theme.as_ref().map(|t| t.to_string()),
            default_role: r.default_role.clone(),
            access_token_lifespan: r.access_token_lifespan.get() as i64,
            refresh_token_lifespan: r.refresh_token_lifespan.get() as i64,
            sso_session_idle_timeout: r.sso_session_idle_timeout.get() as i64,
            sso_session_max_lifespan: r.sso_session_max_lifespan.get() as i64,
            offline_session_idle_timeout: r.offline_session_idle_timeout.get() as i64,
            brute_force_protected: r.brute_force_protected,
            max_login_failures: u32_to_i32(r.max_login_failures),
            wait_increment_secs: u32_to_i32(r.wait_increment_secs),
            max_failure_wait_secs: u32_to_i32(r.max_failure_wait_secs),
            lockout_duration_secs: u32_to_i32(r.lockout_duration_secs),
            registration_enabled: r.registration_enabled,
            reset_password_allowed: r.reset_password_allowed,
            remember_me_enabled: r.remember_me_enabled,
            verify_email_enabled: r.verify_email_enabled,
            login_with_email_allowed: r.login_with_email_allowed,
            duplicate_emails_allowed: r.duplicate_emails_allowed,
            edit_username_allowed: r.edit_username_allowed,
            remember_me_session_idle_secs: r.remember_me_session_idle_secs.get() as i64,
            otp_algorithm: r.otp_policy.algorithm.as_str().to_string(),
            otp_digits: u32_to_i32(r.otp_policy.digits),
            otp_period_secs: u32_to_i32(r.otp_policy.period_secs),
            otp_look_ahead_window: u32_to_i32(r.otp_policy.look_ahead_window),
            internationalization_enabled: r.internationalization_enabled,
            supported_locales: map_to_json(&r.supported_locales)?,
            default_locale: r.default_locale.clone(),
            events_enabled: r.events_enabled,
            events_expiration_secs: r.events_expiration_secs,
            admin_events_enabled: r.admin_events_enabled,
            include_representations: r.include_representations,
            events_listeners: map_to_json(&r.events_listeners)?,
            not_before: r.not_before,
            default_groups: map_to_json(&r.default_groups)?,
            browser_flow: r.browser_flow.clone(),
            direct_grant_flow: r.direct_grant_flow.clone(),
            reset_credentials_flow: r.reset_credentials_flow.clone(),
            first_broker_login_flow: r.first_broker_login_flow.clone(),
            registration_flow: r.registration_flow.clone(),
            attributes: map_to_json(&r.attributes)?,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
}

// ------------------------------------------------------------------
// User
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgUser {
    pub id: uuid::Uuid,
    pub realm_id: uuid::Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub federation_link: Option<String>,
    pub attributes: Value,
    pub required_actions: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<PgUser> for User {
    type Error = IssuerdError;

    fn try_from(pg: PgUser) -> Result<Self, Self::Error> {
        Ok(Self {
            id: UserId::new(pg.id.to_string()).unwrap(),
            realm_id: RealmId::new(pg.realm_id.to_string()).unwrap(),
            username: Username::new(pg.username)?,
            email: pg
                .email
                .map(Email::new)
                .transpose()
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid email: {e}")))?,
            email_verified: pg.email_verified,
            first_name: pg.first_name.map(DisplayName::new).transpose()?,
            last_name: pg.last_name.map(DisplayName::new).transpose()?,
            enabled: pg.enabled,
            federation_link: pg.federation_link,
            attributes: json_to_map(pg.attributes)?,
            required_actions: json_to_vec(pg.required_actions)?,
            created_at: pg.created_at,
            updated_at: pg.updated_at,
        })
    }
}

impl TryFrom<&User> for PgUser {
    type Error = IssuerdError;

    fn try_from(u: &User) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(u.id.as_ref())?,
            realm_id: to_uuid(u.realm_id.as_ref())?,
            username: u.username.to_string(),
            email: u.email.as_ref().map(|e| e.to_string()),
            email_verified: u.email_verified,
            first_name: u.first_name.as_ref().map(|n| n.to_string()),
            last_name: u.last_name.as_ref().map(|n| n.to_string()),
            enabled: u.enabled,
            federation_link: u.federation_link.clone(),
            attributes: map_to_json(&u.attributes)?,
            required_actions: map_to_json(&u.required_actions)?,
            created_at: u.created_at,
            updated_at: u.updated_at,
        })
    }
}

// ------------------------------------------------------------------
// Client
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgClient {
    pub id: uuid::Uuid,
    pub realm_id: uuid::Uuid,
    pub client_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub protocol: String,
    pub public_client: bool,
    pub bearer_only: bool,
    pub client_authenticator_type: String,
    pub secret: Option<String>,
    pub redirect_uris: Value,
    pub web_origins: Value,
    pub default_scopes: Value,
    pub optional_scopes: Value,
    pub consent_required: bool,
    pub full_scope_allowed: bool,
    pub service_accounts_enabled: bool,
    pub protocol_mappers: Value,
    pub scope_mappings: Value,
    pub attributes: Value,
}

impl TryFrom<PgClient> for Client {
    type Error = IssuerdError;

    fn try_from(pg: PgClient) -> Result<Self, Self::Error> {
        Ok(Self {
            id: ClientId::new(pg.id.to_string()).unwrap(),
            realm_id: RealmId::new(pg.realm_id.to_string()).unwrap(),
            client_id: ClientIdentifier::new(pg.client_id)?,
            name: pg.name.map(DisplayName::new).transpose()?,
            description: pg.description,
            enabled: pg.enabled,
            protocol: serde_json::from_value(serde_json::Value::String(pg.protocol))
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid protocol: {e}")))?,
            public_client: pg.public_client,
            bearer_only: pg.bearer_only,
            client_authenticator_type: serde_json::from_value(serde_json::Value::String(
                pg.client_authenticator_type,
            ))
            .map_err(|e| {
                IssuerdError::InvalidRequest(format!("invalid client_authenticator_type: {e}"))
            })?,
            secret: pg.secret,
            redirect_uris: serde_json::from_value::<Vec<String>>(pg.redirect_uris)
                .map_err(|e| IssuerdError::ServerError(format!("json deserialization error: {e}")))?
                .into_iter()
                .map(RedirectUri::new)
                .collect::<Result<Vec<_>, _>>()?,
            web_origins: serde_json::from_value::<Vec<String>>(pg.web_origins)
                .map_err(|e| IssuerdError::ServerError(format!("json deserialization error: {e}")))?
                .into_iter()
                .map(WebOrigin::new)
                .collect::<Result<Vec<_>, _>>()?,
            default_scopes: json_to_scope(pg.default_scopes)?,
            optional_scopes: json_to_scope(pg.optional_scopes)?,
            consent_required: pg.consent_required,
            full_scope_allowed: pg.full_scope_allowed,
            service_accounts_enabled: pg.service_accounts_enabled,
            protocol_mappers: json_to_vec(pg.protocol_mappers)?,
            scope_mappings: serde_json::from_value(pg.scope_mappings).map_err(|e| {
                IssuerdError::ServerError(format!("json deserialization error: {e}"))
            })?,
            attributes: json_to_map_string_string(pg.attributes)?,
        })
    }
}

impl TryFrom<&Client> for PgClient {
    type Error = IssuerdError;

    fn try_from(c: &Client) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(c.id.as_ref())?,
            realm_id: to_uuid(c.realm_id.as_ref())?,
            client_id: c.client_id.to_string(),
            name: c.name.as_ref().map(|n| n.to_string()),
            description: c.description.clone(),
            enabled: c.enabled,
            protocol: serde_json::to_string(&c.protocol).unwrap().trim_matches('"').to_string(),
            public_client: c.public_client,
            bearer_only: c.bearer_only,
            client_authenticator_type: serde_json::to_string(&c.client_authenticator_type)
                .unwrap()
                .trim_matches('"')
                .to_string(),
            secret: c.secret.clone(),
            redirect_uris: map_to_json(&c.redirect_uris)?,
            web_origins: map_to_json(&c.web_origins)?,
            default_scopes: map_to_json(&c.default_scopes)?,
            optional_scopes: map_to_json(&c.optional_scopes)?,
            consent_required: c.consent_required,
            full_scope_allowed: c.full_scope_allowed,
            service_accounts_enabled: c.service_accounts_enabled,
            protocol_mappers: map_to_json(&c.protocol_mappers)?,
            scope_mappings: map_to_json(&c.scope_mappings)?,
            attributes: map_to_json(&c.attributes)?,
        })
    }
}

// ------------------------------------------------------------------
// ClientScope
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgClientScope {
    pub id: uuid::Uuid,
    pub realm_id: uuid::Uuid,
    pub name: String,
    pub description: Option<String>,
    pub protocol: String,
    pub attributes: Value,
    pub protocol_mappers: Value,
    pub scope_mappings: Value,
}

impl TryFrom<PgClientScope> for ClientScope {
    type Error = IssuerdError;

    fn try_from(pg: PgClientScope) -> Result<Self, Self::Error> {
        Ok(Self {
            id: ClientScopeId::new(pg.id.to_string()).unwrap(),
            realm_id: RealmId::new(pg.realm_id.to_string()).unwrap(),
            name: pg.name,
            description: pg.description,
            protocol: serde_json::from_value(serde_json::Value::String(pg.protocol))
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid protocol: {e}")))?,
            attributes: json_to_map_string_string(pg.attributes)?,
            protocol_mappers: json_to_vec(pg.protocol_mappers)?,
            scope_mappings: serde_json::from_value(pg.scope_mappings).map_err(|e| {
                IssuerdError::ServerError(format!("json deserialization error: {e}"))
            })?,
        })
    }
}

impl TryFrom<&ClientScope> for PgClientScope {
    type Error = IssuerdError;

    fn try_from(s: &ClientScope) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(s.id.as_ref())?,
            realm_id: to_uuid(s.realm_id.as_ref())?,
            name: s.name.clone(),
            description: s.description.clone(),
            protocol: serde_json::to_string(&s.protocol).unwrap().trim_matches('"').to_string(),
            attributes: map_to_json(&s.attributes)?,
            protocol_mappers: map_to_json(&s.protocol_mappers)?,
            scope_mappings: map_to_json(&s.scope_mappings)?,
        })
    }
}

// ------------------------------------------------------------------
// Role
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgRole {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: Option<String>,
    pub realm_id: uuid::Uuid,
    pub client_role: bool,
    pub client_id: Option<uuid::Uuid>,
    pub composite: bool,
    pub composites: Value,
    pub attributes: Value,
}

impl TryFrom<PgRole> for Role {
    type Error = IssuerdError;

    fn try_from(pg: PgRole) -> Result<Self, Self::Error> {
        Ok(Self {
            id: RoleId::new(pg.id.to_string()).unwrap(),
            name: RoleName::new(pg.name)?,
            description: pg.description,
            realm_id: RealmId::new(pg.realm_id.to_string()).unwrap(),
            client_role: pg.client_role,
            client_id: pg.client_id.map(|c| ClientId::new(c.to_string()).unwrap()),
            composite: pg.composite,
            composites: json_to_vec(pg.composites)?,
            attributes: json_to_map(pg.attributes)?,
        })
    }
}

impl TryFrom<&Role> for PgRole {
    type Error = IssuerdError;

    fn try_from(r: &Role) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(r.id.as_ref())?,
            name: r.name.to_string(),
            description: r.description.clone(),
            realm_id: to_uuid(r.realm_id.as_ref())?,
            client_role: r.client_role,
            client_id: r.client_id.as_ref().map(|c| to_uuid(c.as_ref())).transpose()?,
            composite: r.composite,
            composites: map_to_json(&r.composites)?,
            attributes: map_to_json(&r.attributes)?,
        })
    }
}

// ------------------------------------------------------------------
// Group
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgGroup {
    pub id: uuid::Uuid,
    pub name: String,
    pub path: String,
    pub realm_id: uuid::Uuid,
    pub parent_id: Option<uuid::Uuid>,
    pub attributes: Value,
    pub realm_roles: Value,
    pub client_roles: Value,
}

impl TryFrom<PgGroup> for Group {
    type Error = IssuerdError;

    fn try_from(pg: PgGroup) -> Result<Self, Self::Error> {
        Ok(Self {
            id: GroupId::new(pg.id.to_string()).unwrap(),
            name: RoleName::new(pg.name)?,
            path: GroupPath::new(pg.path)?,
            realm_id: RealmId::new(pg.realm_id.to_string()).unwrap(),
            parent_id: pg.parent_id.map(|p| GroupId::new(p.to_string()).unwrap()),
            sub_groups: vec![],
            attributes: json_to_map(pg.attributes)?,
            realm_roles: json_to_vec(pg.realm_roles)?,
            client_roles: json_to_map(pg.client_roles)?,
        })
    }
}

impl TryFrom<&Group> for PgGroup {
    type Error = IssuerdError;

    fn try_from(g: &Group) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(g.id.as_ref())?,
            name: g.name.to_string(),
            path: g.path.as_ref().to_string(),
            realm_id: to_uuid(g.realm_id.as_ref())?,
            parent_id: g.parent_id.as_ref().map(|p| to_uuid(p.as_ref())).transpose()?,
            attributes: map_to_json(&g.attributes)?,
            realm_roles: map_to_json(&g.realm_roles)?,
            client_roles: map_to_json(&g.client_roles)?,
        })
    }
}

// ------------------------------------------------------------------
// Credential
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgCredential {
    pub id: uuid::Uuid,
    pub realm_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub credential_type: String,
    pub user_label: Option<String>,
    pub created_date: DateTime<Utc>,
    pub secret_data: Vec<u8>,
    pub credential_data: Value,
    pub priority: i32,
}

impl TryFrom<PgCredential> for Credential {
    type Error = IssuerdError;

    fn try_from(pg: PgCredential) -> Result<Self, Self::Error> {
        let credential_type = serde_json::from_value(Value::String(pg.credential_type))
            .unwrap_or(CredentialType::Custom("unknown".to_string()));
        Ok(Self {
            id: CredentialId::new(pg.id)?,
            credential_type,
            user_label: pg.user_label,
            created_date: pg.created_date,
            secret_data: pg.secret_data,
            credential_data: pg.credential_data,
            priority: pg.priority,
        })
    }
}

impl TryFrom<&Credential> for PgCredential {
    type Error = IssuerdError;

    fn try_from(c: &Credential) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(c.id.as_ref())?,
            realm_id: uuid::Uuid::nil(), // filled by caller
            user_id: uuid::Uuid::nil(),  // filled by caller
            credential_type: serde_json::to_string(&c.credential_type)
                .map_err(|e| IssuerdError::ServerError(format!("json serialization error: {e}")))?
                .trim_matches('"')
                .to_string(),
            user_label: c.user_label.clone(),
            created_date: c.created_date,
            secret_data: c.secret_data.clone(),
            credential_data: c.credential_data.clone(),
            priority: c.priority,
        })
    }
}

// ------------------------------------------------------------------
// UserSession
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgUserSession {
    pub id: uuid::Uuid,
    pub realm_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub login_username: String,
    pub ip_address: Option<String>,
    pub auth_method: Option<String>,
    pub remember_me: bool,
    pub offline: bool,
    pub started: DateTime<Utc>,
    pub last_session_refresh: DateTime<Utc>,
    pub auth_time: DateTime<Utc>,
    pub impersonator: Option<String>,
}

impl TryFrom<PgUserSession> for UserSession {
    type Error = IssuerdError;

    fn try_from(pg: PgUserSession) -> Result<Self, Self::Error> {
        Ok(Self {
            id: SessionId::new(pg.id.to_string()).unwrap(),
            realm_id: RealmId::new(pg.realm_id.to_string()).unwrap(),
            user_id: UserId::new(pg.user_id.to_string()).unwrap(),
            login_username: Username::new(pg.login_username)
                .unwrap_or(Username::new("unknown").unwrap()),
            ip_address: pg
                .ip_address
                .and_then(|s| s.parse().ok())
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            auth_method: pg
                .auth_method
                .map(|s| {
                    serde_json::from_value(serde_json::Value::String(s)).map_err(|e| {
                        IssuerdError::InvalidRequest(format!("invalid auth_method: {e}"))
                    })
                })
                .transpose()?
                .unwrap_or(AuthMethod::Password),
            remember_me: pg.remember_me,
            offline: pg.offline,
            started: pg.started,
            last_session_refresh: pg.last_session_refresh,
            auth_time: pg.auth_time,
            impersonator: pg.impersonator.map(UserId::new).transpose()?,
            clients: vec![],
        })
    }
}

impl TryFrom<&UserSession> for PgUserSession {
    type Error = IssuerdError;

    fn try_from(s: &UserSession) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(s.id.as_ref())?,
            realm_id: to_uuid(s.realm_id.as_ref())?,
            user_id: to_uuid(s.user_id.as_ref())?,
            login_username: s.login_username.to_string(),
            ip_address: Some(s.ip_address.to_string()),
            auth_method: Some(
                serde_json::to_string(&s.auth_method).unwrap().trim_matches('"').to_string(),
            ),
            remember_me: s.remember_me,
            offline: s.offline,
            started: s.started,
            last_session_refresh: s.last_session_refresh,
            auth_time: s.auth_time,
            impersonator: s.impersonator.as_ref().map(|u| u.to_string()),
        })
    }
}

// ------------------------------------------------------------------
// ClientSession
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgClientSession {
    pub id: uuid::Uuid,
    pub client_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub auth_method: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl TryFrom<PgClientSession> for ClientSession {
    type Error = IssuerdError;

    fn try_from(pg: PgClientSession) -> Result<Self, Self::Error> {
        Ok(Self {
            id: ClientSessionId::new(pg.id.to_string()).unwrap(),
            client_id: ClientId::new(pg.client_id.to_string()).unwrap(),
            session_id: SessionId::new(pg.session_id.to_string()).unwrap(),
            redirect_uri: pg.redirect_uri.and_then(|s| RedirectUri::new(s).ok()),
            state: pg.state,
            auth_method: pg
                .auth_method
                .map(|s| {
                    serde_json::from_value(serde_json::Value::String(s)).map_err(|e| {
                        IssuerdError::InvalidRequest(format!("invalid auth_method: {e}"))
                    })
                })
                .transpose()?
                .unwrap_or(AuthMethod::Password),
            timestamp: pg.timestamp,
        })
    }
}

impl TryFrom<&ClientSession> for PgClientSession {
    type Error = IssuerdError;

    fn try_from(c: &ClientSession) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(c.id.as_ref())?,
            client_id: to_uuid(c.client_id.as_ref())?,
            session_id: to_uuid(c.session_id.as_ref())?,
            redirect_uri: c.redirect_uri.as_ref().map(|r| r.to_string()),
            state: c.state.clone(),
            auth_method: Some(
                serde_json::to_string(&c.auth_method).unwrap().trim_matches('"').to_string(),
            ),
            timestamp: c.timestamp,
        })
    }
}

// ------------------------------------------------------------------
// Event
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgEvent {
    pub id: uuid::Uuid,
    pub realm_id: uuid::Uuid,
    pub event_time: DateTime<Utc>,
    pub event_type: String,
    pub ip_address: Option<String>,
    pub client_id: Option<uuid::Uuid>,
    pub user_id: Option<uuid::Uuid>,
    pub session_id: Option<uuid::Uuid>,
    pub error: Option<String>,
    pub details: Value,
}

impl TryFrom<PgEvent> for Event {
    type Error = IssuerdError;

    fn try_from(pg: PgEvent) -> Result<Self, Self::Error> {
        let event_type = serde_json::from_value(Value::String(pg.event_type))
            .unwrap_or(EventType::Custom("unknown".to_string()));
        Ok(Self {
            id: EventId::new(pg.id.to_string()).unwrap(),
            realm_id: RealmId::new(pg.realm_id.to_string()).unwrap(),
            event_time: pg.event_time,
            event_type,
            ip_address: pg.ip_address.and_then(|s| s.parse().ok()),
            client_id: pg.client_id.map(|c| ClientId::new(c.to_string()).unwrap()),
            user_id: pg.user_id.map(|u| UserId::new(u.to_string()).unwrap()),
            session_id: pg.session_id.map(|s| SessionId::new(s.to_string()).unwrap()),
            error: pg.error,
            details: json_to_map_string_string(pg.details)?,
        })
    }
}

impl TryFrom<&Event> for PgEvent {
    type Error = IssuerdError;

    fn try_from(e: &Event) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(e.id.as_ref())?,
            realm_id: to_uuid(e.realm_id.as_ref())?,
            event_time: e.event_time,
            event_type: serde_json::to_string(&e.event_type)
                .map_err(|e| IssuerdError::ServerError(format!("json serialization error: {e}")))?
                .trim_matches('"')
                .to_string(),
            ip_address: e.ip_address.map(|ip| ip.to_string()),
            client_id: e.client_id.as_ref().map(|c| to_uuid(c.as_ref())).transpose()?,
            user_id: e.user_id.as_ref().map(|u| to_uuid(u.as_ref())).transpose()?,
            session_id: e.session_id.as_ref().map(|s| to_uuid(s.as_ref())).transpose()?,
            error: e.error.clone(),
            details: map_to_json(&e.details)?,
        })
    }
}

// ------------------------------------------------------------------
// AdminEvent
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgAdminEvent {
    pub id: uuid::Uuid,
    pub realm_id: Option<uuid::Uuid>,
    pub auth_realm_id: Option<uuid::Uuid>,
    /// Public OAuth client_id string (e.g. "admin-cli") — not the client's
    /// internal UUID (migration 015).
    pub auth_client_id: Option<String>,
    pub auth_user_id: Option<uuid::Uuid>,
    pub operation_type: String,
    pub resource_type: String,
    pub resource_path: String,
    pub representation: Option<String>,
    pub error: Option<String>,
    pub event_time: DateTime<Utc>,
}

impl TryFrom<PgAdminEvent> for AdminEvent {
    type Error = IssuerdError;

    fn try_from(pg: PgAdminEvent) -> Result<Self, Self::Error> {
        let operation_type = serde_json::from_value(Value::String(pg.operation_type))
            .unwrap_or(OperationType::Action);
        Ok(Self {
            id: EventId::new(pg.id.to_string()).unwrap(),
            realm_id: RealmId::new(pg.realm_id.map(|r| r.to_string()).unwrap_or_default()).unwrap(),
            auth_realm_id: pg.auth_realm_id.map(RealmId::new).transpose()?,
            auth_client_id: pg.auth_client_id.map(ClientId::new).transpose()?,
            auth_user_id: pg.auth_user_id.map(UserId::new).transpose()?,
            operation_type,
            resource_type: serde_json::from_value(Value::String(pg.resource_type))
                .unwrap_or(ResourceType::Realm),
            resource_path: pg.resource_path,
            representation: pg.representation,
            error: pg.error,
            event_time: pg.event_time,
        })
    }
}

impl TryFrom<&AdminEvent> for PgAdminEvent {
    type Error = IssuerdError;

    fn try_from(e: &AdminEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(e.id.as_ref())?,
            realm_id: Some(to_uuid(e.realm_id.as_ref())?),
            auth_realm_id: e.auth_realm_id.as_ref().map(|r| to_uuid(r.as_ref())).transpose()?,
            auth_client_id: e.auth_client_id.as_ref().map(|c| c.as_ref().to_string()),
            auth_user_id: e.auth_user_id.as_ref().map(|u| to_uuid(u.as_ref())).transpose()?,
            operation_type: serde_json::to_string(&e.operation_type)
                .map_err(|e| IssuerdError::ServerError(format!("json serialization error: {e}")))?
                .trim_matches('"')
                .to_string(),
            resource_type: serde_json::to_string(&e.resource_type)
                .map_err(|e| IssuerdError::ServerError(format!("json serialization error: {e}")))?
                .trim_matches('"')
                .to_string(),
            resource_path: e.resource_path.clone(),
            representation: e.representation.clone(),
            error: e.error.clone(),
            event_time: e.event_time,
        })
    }
}

// ------------------------------------------------------------------
// Consent
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgConsent {
    pub realm_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub client_id: String,
    pub granted_scopes: Value,
    pub granted_realm_roles: Value,
    pub granted_client_roles: Value,
    pub created_at: DateTime<Utc>,
    pub last_updated_at: DateTime<Utc>,
}

impl TryFrom<PgConsent> for Consent {
    type Error = IssuerdError;

    fn try_from(pg: PgConsent) -> Result<Self, Self::Error> {
        Ok(Self {
            client_id: ClientId::new(pg.client_id)?,
            user_id: UserId::new(pg.user_id.to_string()).unwrap(),
            granted_scopes: json_to_scope(pg.granted_scopes)?,
            granted_realm_roles: json_to_vec(pg.granted_realm_roles)?,
            granted_client_roles: json_to_map(pg.granted_client_roles)?,
            created_at: pg.created_at,
            last_updated_at: pg.last_updated_at,
        })
    }
}

impl TryFrom<&Consent> for PgConsent {
    type Error = IssuerdError;

    fn try_from(c: &Consent) -> Result<Self, Self::Error> {
        Ok(Self {
            realm_id: uuid::Uuid::nil(), // filled by caller
            user_id: to_uuid(c.user_id.as_ref())?,
            client_id: c.client_id.to_string(),
            granted_scopes: map_to_json(&c.granted_scopes)?,
            granted_realm_roles: map_to_json(&c.granted_realm_roles)?,
            granted_client_roles: map_to_json(&c.granted_client_roles)?,
            created_at: c.created_at,
            last_updated_at: c.last_updated_at,
        })
    }
}

// ------------------------------------------------------------------
// IdentityProvider
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgIdentityProvider {
    pub id: uuid::Uuid,
    pub realm_id: uuid::Uuid,
    pub alias: String,
    pub provider_id: String,
    pub enabled: bool,
    pub config: Value,
}

impl TryFrom<PgIdentityProvider> for IdentityProviderConfig {
    type Error = IssuerdError;

    fn try_from(pg: PgIdentityProvider) -> Result<Self, Self::Error> {
        Ok(Self {
            id: IdentityProviderId::new(pg.id)?,
            alias: Alias::new(pg.alias)?,
            provider_id: ProviderId::new(pg.provider_id),
            enabled: pg.enabled,
            config: json_to_map_string_string(pg.config)?,
        })
    }
}

impl TryFrom<&IdentityProviderConfig> for PgIdentityProvider {
    type Error = IssuerdError;

    fn try_from(i: &IdentityProviderConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            id: to_uuid(i.id.as_ref())?,
            realm_id: uuid::Uuid::nil(), // filled by caller
            alias: i.alias.to_string(),
            provider_id: i.provider_id.to_string(),
            enabled: i.enabled,
            config: map_to_json(&i.config)?,
        })
    }
}

// ------------------------------------------------------------------
// IdentityProviderLink
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgIdentityProviderLink {
    pub realm_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub provider_alias: String,
    pub external_subject: String,
    pub external_username: Option<String>,
    pub stored_refresh_token: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<PgIdentityProviderLink> for IdentityProviderLink {
    type Error = IssuerdError;

    fn try_from(pg: PgIdentityProviderLink) -> Result<Self, Self::Error> {
        Ok(Self {
            user_id: UserId::new(pg.user_id.to_string())?,
            provider_alias: pg.provider_alias,
            external_subject: pg.external_subject,
            external_username: pg.external_username,
            stored_refresh_token: pg.stored_refresh_token,
            created_at: pg.created_at,
        })
    }
}

// ------------------------------------------------------------------
// FlowConfig
// ------------------------------------------------------------------
#[derive(Debug, FromRow)]
pub struct PgFlowConfig {
    pub alias: String,
    pub realm_id: uuid::Uuid,
    pub provider_id: String,
    pub top_level: bool,
    pub built_in: bool,
    pub stages: Value,
}

impl TryFrom<PgFlowConfig> for FlowConfig {
    type Error = IssuerdError;

    fn try_from(pg: PgFlowConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            alias: Alias::new(pg.alias)?,
            realm_id: RealmId::new(pg.realm_id.to_string()).unwrap(),
            provider_id: pg.provider_id,
            top_level: pg.top_level,
            built_in: pg.built_in,
            stages: serde_json::from_value(pg.stages).unwrap_or_default(),
        })
    }
}

impl TryFrom<&FlowConfig> for PgFlowConfig {
    type Error = IssuerdError;

    fn try_from(f: &FlowConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            alias: f.alias.to_string(),
            realm_id: to_uuid(f.realm_id.as_ref())?,
            provider_id: f.provider_id.clone(),
            top_level: f.top_level,
            built_in: f.built_in,
            stages: map_to_json(&f.stages)?,
        })
    }
}

// ------------------------------------------------------------------
// StoredSigningKey
// ------------------------------------------------------------------
//
// Row shape after migration 017 (envelope encryption, expand phase):
// `private_der` holds plaintext for legacy/unencrypted rows and is NULL for
// rows written by a KEK-enabled binary, which carry `private_der_enc`
// (ciphertext blob: version || nonce || ciphertext || tag) plus the `kek_kid`
// naming the KEK that encrypted them. Runtime `FromRow` maps by column name
// and ignores extra columns, so pre-encryption binaries keep reading the
// table (they only cannot decode encrypted-only rows — a documented
// mixed-version caveat).
#[derive(Debug, FromRow)]
pub struct PgSigningKey {
    pub kid: String,
    pub alg: String,
    pub created_at: DateTime<Utc>,
    pub private_der: Option<Vec<u8>>,
    pub private_der_enc: Option<Vec<u8>>,
    pub kek_kid: Option<String>,
    pub public_jwk: Value,
    pub active: bool,
}

impl Drop for PgSigningKey {
    fn drop(&mut self) {
        if let Some(der) = &mut self.private_der {
            zeroize::Zeroize::zeroize(der);
        }
    }
}

impl TryFrom<PgSigningKey> for StoredSigningKey {
    type Error = IssuerdError;

    fn try_from(mut pg: PgSigningKey) -> Result<Self, Self::Error> {
        Ok(Self {
            kid: KeyId::new(std::mem::take(&mut pg.kid))?,
            alg: pg.alg.parse()?,
            created_at: pg.created_at,
            // Decryption of ciphertext-only rows happens in
            // `PostgresStorage::list_signing_keys` before this conversion;
            // reaching here without plaintext is a caller bug.
            private_der: pg.private_der.take().ok_or_else(|| {
                IssuerdError::KeyEncryption(
                    "signing-key row carries no plaintext (decrypt it first)".to_string(),
                )
            })?,
            public_jwk: serde_json::from_value(std::mem::take(&mut pg.public_jwk)).map_err(
                |e| IssuerdError::ServerError(format!("json deserialization error: {e}")),
            )?,
            active: pg.active,
        })
    }
}

impl TryFrom<&StoredSigningKey> for PgSigningKey {
    type Error = IssuerdError;

    fn try_from(k: &StoredSigningKey) -> Result<Self, Self::Error> {
        Ok(Self {
            kid: k.kid.to_string(),
            alg: k.alg.as_str().to_string(),
            created_at: k.created_at,
            private_der: Some(k.private_der.clone()),
            private_der_enc: None,
            kek_kid: None,
            public_jwk: map_to_json(&k.public_jwk)?,
            active: k.active,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::collections::HashMap;

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
    fn json_to_map_string_string_null() {
        let result = json_to_map_string_string(json!(null)).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn json_to_map_string_string_valid() {
        let result = json_to_map_string_string(json!({"key": "value"})).unwrap();
        assert_eq!(result.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn json_to_map_string_string_invalid() {
        let result = json_to_map_string_string(json!("not an object"));
        assert!(result.is_err());
    }

    #[test]
    fn json_to_map_null() {
        let result: HashMap<String, Vec<String>> = json_to_map(json!(null)).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn json_to_map_valid() {
        let result: HashMap<String, Vec<String>> = json_to_map(json!({"key": ["a", "b"]})).unwrap();
        assert_eq!(result.get("key"), Some(&vec!["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn json_to_vec_null() {
        let result: Vec<String> = json_to_vec(json!(null)).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn json_to_vec_valid() {
        let result: Vec<String> = json_to_vec(json!(["a", "b"])).unwrap();
        assert_eq!(result, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn map_to_json_valid() {
        let mut map = HashMap::new();
        map.insert("key".to_string(), "value".to_string());
        let result = map_to_json(&map).unwrap();
        assert_eq!(result, json!({"key": "value"}));
    }

    #[test]
    fn json_to_map_invalid() {
        let result: Result<HashMap<String, Vec<String>>, _> = json_to_map(json!("not an object"));
        assert!(result.is_err());
    }

    #[test]
    fn json_to_vec_invalid() {
        let result: Result<Vec<String>, _> = json_to_vec(json!("not an array"));
        assert!(result.is_err());
    }

    #[test]
    fn json_to_scope_null() {
        let result = json_to_scope(json!(null)).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn json_to_scope_valid() {
        let result = json_to_scope(json!(["openid", "profile"])).unwrap();
        assert!(result.contains("openid"));
        assert!(result.contains("profile"));
    }

    #[test]
    fn map_to_json_error() {
        use serde::{Serialize, Serializer};

        struct FailSerialize;
        impl Serialize for FailSerialize {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                Err(serde::ser::Error::custom("always fails"))
            }
        }

        let result = map_to_json(FailSerialize);
        assert!(result.is_err());
    }

    fn pg_realm() -> PgRealm {
        PgRealm {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            display_name: Some("Test".to_string()),
            enabled: true,
            ssl_required: "external".to_string(),
            password_policy: json!({}),
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            default_role: None,
            access_token_lifespan: 300,
            refresh_token_lifespan: 1800,
            sso_session_idle_timeout: 1800,
            sso_session_max_lifespan: 36000,
            offline_session_idle_timeout: 2592000,
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
            remember_me_session_idle_secs: 604_800,
            otp_algorithm: "HmacSHA1".to_string(),
            otp_digits: 6,
            otp_period_secs: 30,
            otp_look_ahead_window: 1,
            internationalization_enabled: false,
            supported_locales: json!([]),
            default_locale: None,
            events_enabled: false,
            events_expiration_secs: 0,
            admin_events_enabled: false,
            include_representations: false,
            events_listeners: json!(["logging"]),
            not_before: 0,
            default_groups: json!([]),
            browser_flow: None,
            direct_grant_flow: None,
            reset_credentials_flow: None,
            first_broker_login_flow: None,
            registration_flow: None,
            attributes: json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn pg_realm_try_into_realm() {
        let pg = pg_realm();
        let realm: Realm = pg.try_into().unwrap();
        assert_eq!(realm.name, "test");
        assert!(matches!(realm.ssl_required, SslRequired::External));
    }

    #[test]
    fn pg_realm_ssl_required_none() {
        let mut pg = pg_realm();
        pg.ssl_required = "none".to_string();
        let realm: Realm = pg.try_into().unwrap();
        assert!(matches!(realm.ssl_required, SslRequired::None));
    }

    #[test]
    fn pg_realm_ssl_required_all() {
        let mut pg = pg_realm();
        pg.ssl_required = "all".to_string();
        let realm: Realm = pg.try_into().unwrap();
        assert!(matches!(realm.ssl_required, SslRequired::All));
    }

    #[test]
    fn pg_realm_ssl_required_unknown() {
        let mut pg = pg_realm();
        pg.ssl_required = "unknown".to_string();
        let realm: Realm = pg.try_into().unwrap();
        assert!(matches!(realm.ssl_required, SslRequired::External));
    }

    #[test]
    fn realm_try_into_pg_realm() {
        let realm = Realm {
            id: RealmId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            name: RealmName::new("test").unwrap(),
            display_name: None,
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
        };
        let pg: PgRealm = (&realm).try_into().unwrap();
        assert_eq!(pg.name, "test");
    }

    fn pg_user() -> PgUser {
        PgUser {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            username: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            email_verified: true,
            first_name: Some("Alice".to_string()),
            last_name: Some("Smith".to_string()),
            enabled: true,
            federation_link: None,
            attributes: json!({}),
            required_actions: json!([]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn pg_user_try_into_user() {
        let pg = pg_user();
        let user: User = pg.try_into().unwrap();
        assert_eq!(user.username, "alice");
    }

    #[test]
    fn user_try_into_pg_user() {
        let user = User {
            id: UserId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            username: Username::new("alice").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let pg: PgUser = (&user).try_into().unwrap();
        assert_eq!(pg.username, "alice");
    }

    fn pg_client() -> PgClient {
        PgClient {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            client_id: "my-app".to_string(),
            name: Some("My App".to_string()),
            description: None,
            enabled: true,
            protocol: "openid-connect".to_string(),
            public_client: false,
            bearer_only: false,
            client_authenticator_type: "client-secret".to_string(),
            secret: Some("s3cr3t".to_string()),
            redirect_uris: json!([]),
            web_origins: json!([]),
            default_scopes: json!([]),
            optional_scopes: json!([]),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: json!([]),
            scope_mappings: json!({"realm_roles":[],"client_roles":{}}),
            attributes: json!({}),
        }
    }

    #[test]
    fn pg_client_try_into_client() {
        let pg = pg_client();
        let client: Client = pg.try_into().unwrap();
        assert_eq!(client.client_id, "my-app");
    }

    #[test]
    fn client_try_into_pg_client() {
        let client = Client {
            id: ClientId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        let pg: PgClient = (&client).try_into().unwrap();
        assert_eq!(pg.client_id, "my-app");
    }

    #[test]
    fn pg_client_scope_roundtrip() {
        let scope = ClientScope {
            id: ClientScopeId::new("550e8400-e29b-41d4-a716-446655440002").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            name: "profile".to_string(),
            description: Some("OpenID Connect built-in scope: profile".to_string()),
            protocol: ClientProtocol::OpenIdConnect,
            attributes: HashMap::from([(
                "display.on.consent.screen".to_string(),
                "true".to_string(),
            )]),
            protocol_mappers: vec![ProtocolMapper {
                id: MapperId::new("mapper-1").unwrap(),
                name: "username".to_string(),
                mapper_type: MapperType::UserProperty,
                config: HashMap::from([(
                    "claim.name".to_string(),
                    "preferred_username".to_string(),
                )]),
            }],
            scope_mappings: ScopeMappings {
                realm_roles: vec![RoleId::new("role-1").unwrap()],
                client_roles: HashMap::new(),
            },
        };
        let pg: PgClientScope = (&scope).try_into().unwrap();
        assert_eq!(pg.name, "profile");
        assert_eq!(pg.protocol, "openid-connect");
        let back: ClientScope = pg.try_into().unwrap();
        assert_eq!(back, scope);
    }

    fn pg_role() -> PgRole {
        PgRole {
            id: uuid::Uuid::new_v4(),
            name: "admin".to_string(),
            description: Some("Admin".to_string()),
            realm_id: uuid::Uuid::new_v4(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: json!([]),
            attributes: json!({}),
        }
    }

    #[test]
    fn pg_role_try_into_role() {
        let pg = pg_role();
        let role: Role = pg.try_into().unwrap();
        assert_eq!(role.name, RoleName::new("admin").unwrap());
    }

    #[test]
    fn role_try_into_pg_role() {
        let role = Role {
            id: RoleId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: None,
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            client_role: false,
            client_id: None,
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        let pg: PgRole = (&role).try_into().unwrap();
        assert_eq!(pg.name, "admin");
    }

    fn pg_group() -> PgGroup {
        PgGroup {
            id: uuid::Uuid::new_v4(),
            name: "admins".to_string(),
            path: "/admins".to_string(),
            realm_id: uuid::Uuid::new_v4(),
            parent_id: None,
            attributes: json!({}),
            realm_roles: json!([]),
            client_roles: json!({}),
        }
    }

    #[test]
    fn pg_group_try_into_group() {
        let pg = pg_group();
        let group: Group = pg.try_into().unwrap();
        assert_eq!(group.name, GroupName::new("admins").unwrap());
    }

    #[test]
    fn group_try_into_pg_group() {
        let group = Group {
            id: GroupId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: GroupPath::new("/admins").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            parent_id: None,
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        let pg: PgGroup = (&group).try_into().unwrap();
        assert_eq!(pg.name, "admins");
    }

    #[test]
    fn pg_credential_try_into_credential() {
        let pg = PgCredential {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            credential_type: "password".to_string(),
            user_label: Some("label".to_string()),
            created_date: Utc::now(),
            secret_data: vec![1, 2, 3],
            credential_data: json!({}),
            priority: 1,
        };
        let cred: Credential = pg.try_into().unwrap();
        assert!(matches!(cred.credential_type, CredentialType::Password));
    }

    #[test]
    fn credential_try_into_pg_credential() {
        let cred = Credential {
            id: CredentialId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: vec![],
            credential_data: json!(null),
            priority: 0,
        };
        let pg: PgCredential = (&cred).try_into().unwrap();
        assert_eq!(pg.realm_id, uuid::Uuid::nil());
    }

    #[test]
    fn pg_user_session_try_into_user_session() {
        let pg = PgUserSession {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            login_username: "alice".to_string(),
            ip_address: Some("127.0.0.1".parse().unwrap()),
            auth_method: Some("password".to_string()),
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
        };
        let session: UserSession = pg.try_into().unwrap();
        assert_eq!(session.login_username, "alice");
    }

    #[test]
    fn user_session_try_into_pg_user_session() {
        let session = UserSession {
            id: SessionId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            user_id: UserId::new("550e8400-e29b-41d4-a716-446655440002").unwrap(),
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
        };
        let pg: PgUserSession = (&session).try_into().unwrap();
        assert_eq!(pg.login_username, "alice");
    }

    #[test]
    fn pg_client_session_try_into_client_session() {
        let pg = PgClientSession {
            id: uuid::Uuid::new_v4(),
            client_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            redirect_uri: Some("https://app.example.com".parse().unwrap()),
            state: Some("xyz".to_string()),
            auth_method: Some("password".to_string()),
            timestamp: Utc::now(),
        };
        let cs: ClientSession = pg.try_into().unwrap();
        assert_eq!(cs.auth_method, AuthMethod::Password);
    }

    #[test]
    fn client_session_try_into_pg_client_session() {
        let cs = ClientSession {
            id: ClientSessionId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            client_id: ClientId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            session_id: SessionId::new("550e8400-e29b-41d4-a716-446655440002").unwrap(),
            redirect_uri: None,
            state: None,
            auth_method: AuthMethod::Password,
            timestamp: Utc::now(),
        };
        let pg: PgClientSession = (&cs).try_into().unwrap();
        assert_eq!(pg.auth_method, Some("password".to_string()));
    }

    #[test]
    fn pg_event_try_into_event() {
        let pg = PgEvent {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            event_time: Utc::now(),
            event_type: "login".to_string(),
            ip_address: Some("127.0.0.1".parse().unwrap()),
            client_id: Some(uuid::Uuid::new_v4()),
            user_id: Some(uuid::Uuid::new_v4()),
            session_id: Some(uuid::Uuid::new_v4()),
            error: None,
            details: json!({}),
        };
        let event: Event = pg.try_into().unwrap();
        assert!(matches!(event.event_type, EventType::Login));
    }

    #[test]
    fn event_try_into_pg_event() {
        let event = Event {
            id: EventId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            event_time: Utc::now(),
            event_type: EventType::Login,
            ip_address: None,
            client_id: None,
            user_id: None,
            session_id: None,
            error: None,
            details: HashMap::new(),
        };
        let pg: PgEvent = (&event).try_into().unwrap();
        assert_eq!(pg.event_type, "login");
    }

    #[test]
    fn pg_admin_event_try_into_admin_event() {
        let pg = PgAdminEvent {
            id: uuid::Uuid::new_v4(),
            realm_id: Some(uuid::Uuid::new_v4()),
            auth_realm_id: Some(uuid::Uuid::new_v4()),
            auth_client_id: Some("admin-cli".to_string()),
            auth_user_id: Some(uuid::Uuid::new_v4()),
            operation_type: "CREATE".to_string(),
            resource_type: "REALM".to_string(),
            resource_path: "/realms/test".to_string(),
            representation: None,
            error: None,
            event_time: Utc::now(),
        };
        let event: AdminEvent = pg.try_into().unwrap();
        assert!(matches!(event.operation_type, OperationType::Create));
    }

    #[test]
    fn pg_admin_event_unknown_operation() {
        let pg = PgAdminEvent {
            id: uuid::Uuid::new_v4(),
            realm_id: Some(uuid::Uuid::new_v4()),
            auth_realm_id: Some(uuid::Uuid::new_v4()),
            auth_client_id: None,
            auth_user_id: None,
            operation_type: "UNKNOWN".to_string(),
            resource_type: "REALM".to_string(),
            resource_path: "/".to_string(),
            representation: None,
            error: None,
            event_time: Utc::now(),
        };
        let event: AdminEvent = pg.try_into().unwrap();
        assert!(matches!(event.operation_type, OperationType::Action));
    }

    #[test]
    fn pg_consent_try_into_consent() {
        let pg = PgConsent {
            realm_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            client_id: "client-1".to_string(),
            granted_scopes: json!([]),
            granted_realm_roles: json!([]),
            granted_client_roles: json!({}),
            created_at: Utc::now(),
            last_updated_at: Utc::now(),
        };
        let consent: Consent = pg.try_into().unwrap();
        assert_eq!(consent.client_id.as_ref(), "client-1");
    }

    #[test]
    fn consent_try_into_pg_consent() {
        let consent = Consent {
            client_id: ClientId::new("client-1").unwrap(),
            user_id: UserId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            granted_scopes: Scope::empty(),
            granted_realm_roles: vec![],
            granted_client_roles: HashMap::new(),
            created_at: Utc::now(),
            last_updated_at: Utc::now(),
        };
        let pg: PgConsent = (&consent).try_into().unwrap();
        assert_eq!(pg.realm_id, uuid::Uuid::nil());
    }

    #[test]
    fn pg_identity_provider_try_into_config() {
        let pg = PgIdentityProvider {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            alias: "google".to_string(),
            provider_id: "google".to_string(),
            enabled: true,
            config: json!({"clientId": "123"}),
        };
        let config: IdentityProviderConfig = pg.try_into().unwrap();
        assert_eq!(config.alias, Alias::new("google").unwrap());
    }

    #[test]
    fn identity_provider_try_into_pg() {
        let config = IdentityProviderConfig {
            id: IdentityProviderId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            alias: Alias::new("google").unwrap(),
            provider_id: ProviderId::new("google"),
            enabled: true,
            config: HashMap::new(),
        };
        let pg: PgIdentityProvider = (&config).try_into().unwrap();
        assert_eq!(pg.realm_id, uuid::Uuid::nil());
    }

    #[test]
    fn pg_flow_config_try_into_flow_config() {
        let pg = PgFlowConfig {
            alias: "browser".to_string(),
            realm_id: uuid::Uuid::new_v4(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: json!([]),
        };
        let flow: FlowConfig = pg.try_into().unwrap();
        assert_eq!(flow.alias, Alias::new("browser").unwrap());
    }

    #[test]
    fn flow_config_try_into_pg_flow_config() {
        let flow = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![],
        };
        let pg: PgFlowConfig = (&flow).try_into().unwrap();
        assert_eq!(pg.alias, "browser");
    }

    // ------------------------------------------------------------------
    // Error-path coverage for reverse TryFroms (to_uuid failures)
    // ------------------------------------------------------------------

    #[test]
    fn realm_try_into_pg_realm_invalid_uuid() {
        let realm = Realm {
            id: RealmId::new("not-a-uuid").unwrap(),
            name: RealmName::new("test").unwrap(),
            display_name: None,
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
        };
        let result: Result<PgRealm, _> = (&realm).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn user_try_into_pg_user_invalid_uuid() {
        let user = User {
            id: UserId::new("bad-uuid").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            username: Username::new("alice").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let result: Result<PgUser, _> = (&user).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn client_try_into_pg_client_invalid_uuid() {
        let client = Client {
            id: ClientId::new("bad").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        let result: Result<PgClient, _> = (&client).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn role_try_into_pg_role_invalid_uuid() {
        let role = Role {
            id: RoleId::new("bad").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: None,
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            client_role: false,
            client_id: Some(ClientId::new("also-bad").unwrap()),
            composite: false,
            composites: vec![],
            attributes: HashMap::new(),
        };
        let result: Result<PgRole, _> = (&role).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn group_try_into_pg_group_invalid_uuid() {
        let group = Group {
            id: GroupId::new("bad").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: GroupPath::new("/admins").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            parent_id: Some(GroupId::new("also-bad").unwrap()),
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![],
            client_roles: HashMap::new(),
        };
        let result: Result<PgGroup, _> = (&group).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn credential_try_into_pg_credential_invalid_uuid() {
        let cred = Credential {
            id: CredentialId::new("not-a-uuid").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: Utc::now(),
            secret_data: vec![],
            credential_data: json!(null),
            priority: 0,
        };
        let result: Result<PgCredential, _> = (&cred).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn user_session_try_into_pg_user_session_invalid_uuid() {
        let session = UserSession {
            id: SessionId::new("bad").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            user_id: UserId::new("550e8400-e29b-41d4-a716-446655440002").unwrap(),
            login_username: Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
            clients: vec![],
        };
        let result: Result<PgUserSession, _> = (&session).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn client_session_try_into_pg_client_session_invalid_uuid() {
        let cs = ClientSession {
            id: ClientSessionId::new("bad").unwrap(),
            client_id: ClientId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            session_id: SessionId::new("550e8400-e29b-41d4-a716-446655440002").unwrap(),
            redirect_uri: None,
            state: None,
            auth_method: AuthMethod::Password,
            timestamp: Utc::now(),
        };
        let result: Result<PgClientSession, _> = (&cs).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn event_try_into_pg_event_invalid_uuid() {
        let event = Event {
            id: EventId::new("bad").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            event_time: Utc::now(),
            event_type: EventType::Login,
            ip_address: None,
            client_id: Some(ClientId::new("also-bad").unwrap()),
            user_id: None,
            session_id: None,
            error: None,
            details: HashMap::new(),
        };
        let result: Result<PgEvent, _> = (&event).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn admin_event_try_into_pg_admin_event_invalid_uuid() {
        let event = AdminEvent {
            id: EventId::new("bad").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            auth_realm_id: Some(RealmId::new("also-bad").unwrap()),
            auth_client_id: None,
            auth_user_id: None,
            operation_type: OperationType::Create,
            resource_type: ResourceType::Realm,
            resource_path: "/".to_string(),
            representation: None,
            error: None,
            event_time: Utc::now(),
        };
        let result: Result<PgAdminEvent, _> = (&event).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn consent_try_into_pg_consent_invalid_uuid() {
        let consent = Consent {
            client_id: ClientId::new("client-1").unwrap(),
            user_id: UserId::new("not-a-uuid").unwrap(),
            granted_scopes: Scope::empty(),
            granted_realm_roles: vec![],
            granted_client_roles: HashMap::new(),
            created_at: Utc::now(),
            last_updated_at: Utc::now(),
        };
        let result: Result<PgConsent, _> = (&consent).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn identity_provider_try_into_pg_invalid_uuid() {
        let config = IdentityProviderConfig {
            id: IdentityProviderId::new("not-a-uuid").unwrap(),
            alias: Alias::new("google").unwrap(),
            provider_id: ProviderId::new("google"),
            enabled: true,
            config: HashMap::new(),
        };
        let result: Result<PgIdentityProvider, _> = (&config).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn flow_config_try_into_pg_flow_config_invalid_uuid() {
        let flow = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("bad").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![],
        };
        let result: Result<PgFlowConfig, _> = (&flow).try_into();
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // Error-path coverage for forward TryFroms (JSON / validation failures)
    // ------------------------------------------------------------------

    #[test]
    fn pg_realm_invalid_display_name() {
        let mut pg = pg_realm();
        pg.display_name = Some("\x00".to_string());
        let result: Result<Realm, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_realm_invalid_login_theme() {
        let mut pg = pg_realm();
        pg.login_theme = Some("\x00".to_string());
        let result: Result<Realm, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_realm_invalid_attributes_json() {
        let mut pg = pg_realm();
        pg.attributes = json!("not an object");
        let result: Result<Realm, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_user_invalid_email() {
        let mut pg = pg_user();
        pg.email = Some("not-an-email".to_string());
        let result: Result<User, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_user_invalid_first_name() {
        let mut pg = pg_user();
        pg.first_name = Some("\x00".to_string());
        let result: Result<User, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_user_invalid_attributes_json() {
        let mut pg = pg_user();
        pg.attributes = json!("not an object");
        let result: Result<User, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_client_invalid_client_id() {
        let mut pg = pg_client();
        pg.client_id = "".to_string();
        let result: Result<Client, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_client_invalid_protocol() {
        let mut pg = pg_client();
        pg.protocol = "unknown-protocol".to_string();
        let result: Result<Client, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_client_invalid_redirect_uris_json() {
        let mut pg = pg_client();
        pg.redirect_uris = json!("not an array");
        let result: Result<Client, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_client_invalid_web_origins_json() {
        let mut pg = pg_client();
        pg.web_origins = json!("not an array");
        let result: Result<Client, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_client_invalid_redirect_uri_in_array() {
        let mut pg = pg_client();
        pg.redirect_uris = json!(["not-a-url"]); // empty string is invalid URL
        let result: Result<Client, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_client_invalid_web_origin_in_array() {
        let mut pg = pg_client();
        pg.web_origins = json!(["://bad"]);
        let result: Result<Client, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_client_invalid_default_scopes_json() {
        let mut pg = pg_client();
        pg.default_scopes = json!("not an array");
        let result: Result<Client, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_role_invalid_name() {
        let mut pg = pg_role();
        pg.name = "".to_string();
        let result: Result<Role, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_role_invalid_composites_json() {
        let mut pg = pg_role();
        pg.composites = json!("not an array");
        let result: Result<Role, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_group_invalid_name() {
        let mut pg = pg_group();
        pg.name = "".to_string();
        let result: Result<Group, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_group_invalid_path() {
        let mut pg = pg_group();
        pg.path = "no-leading-slash".to_string();
        let result: Result<Group, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_group_invalid_attributes_json() {
        let mut pg = pg_group();
        pg.attributes = json!("not an object");
        let result: Result<Group, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_user_session_invalid_auth_method() {
        let pg = PgUserSession {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            login_username: "alice".to_string(),
            ip_address: Some("127.0.0.1".parse().unwrap()),
            auth_method: Some("unknown_method".to_string()),
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
        };
        let result: Result<UserSession, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_client_session_invalid_auth_method() {
        let pg = PgClientSession {
            id: uuid::Uuid::new_v4(),
            client_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            redirect_uri: None,
            state: None,
            auth_method: Some("unknown".to_string()),
            timestamp: Utc::now(),
        };
        let result: Result<ClientSession, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_event_invalid_details_json() {
        let pg = PgEvent {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            event_time: Utc::now(),
            event_type: "login".to_string(),
            ip_address: None,
            client_id: None,
            user_id: None,
            session_id: None,
            error: None,
            details: json!("not an object"),
        };
        let result: Result<Event, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_admin_event_unknown_resource_type() {
        let pg = PgAdminEvent {
            id: uuid::Uuid::new_v4(),
            realm_id: Some(uuid::Uuid::new_v4()),
            auth_realm_id: None,
            auth_client_id: None,
            auth_user_id: None,
            operation_type: "CREATE".to_string(),
            resource_type: "UNKNOWN".to_string(),
            resource_path: "/".to_string(),
            representation: None,
            error: None,
            event_time: Utc::now(),
        };
        let event: AdminEvent = pg.try_into().unwrap();
        assert!(matches!(event.resource_type, ResourceType::Realm));
    }

    #[test]
    fn pg_consent_invalid_granted_scopes_json() {
        let pg = PgConsent {
            realm_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            client_id: "client-1".to_string(),
            granted_scopes: json!("not an array"),
            granted_realm_roles: json!([]),
            granted_client_roles: json!({}),
            created_at: Utc::now(),
            last_updated_at: Utc::now(),
        };
        let result: Result<Consent, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_consent_invalid_client_id() {
        let pg = PgConsent {
            realm_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            client_id: "".to_string(),
            granted_scopes: json!([]),
            granted_realm_roles: json!([]),
            granted_client_roles: json!({}),
            created_at: Utc::now(),
            last_updated_at: Utc::now(),
        };
        let result: Result<Consent, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_identity_provider_invalid_alias() {
        let pg = PgIdentityProvider {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            alias: "".to_string(),
            provider_id: "google".to_string(),
            enabled: true,
            config: json!({}),
        };
        let result: Result<IdentityProviderConfig, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_identity_provider_invalid_config_json() {
        let pg = PgIdentityProvider {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            alias: "google".to_string(),
            provider_id: "google".to_string(),
            enabled: true,
            config: json!("not an object"),
        };
        let result: Result<IdentityProviderConfig, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_flow_config_invalid_alias() {
        let pg = PgFlowConfig {
            alias: "".to_string(),
            realm_id: uuid::Uuid::new_v4(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: json!([]),
        };
        let result: Result<FlowConfig, _> = pg.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn pg_realm_invalid_ssl_required_defaults_to_external() {
        let mut pg = pg_realm();
        pg.ssl_required = "garbage".to_string();
        let realm: Realm = pg.try_into().unwrap();
        assert!(matches!(realm.ssl_required, SslRequired::External));
    }

    #[test]
    fn pg_user_session_invalid_ip_address_defaults_to_localhost() {
        let pg = PgUserSession {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            login_username: "alice".to_string(),
            ip_address: Some("not-an-ip".to_string()),
            auth_method: Some("password".to_string()),
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
        };
        let session: UserSession = pg.try_into().unwrap();
        assert_eq!(session.ip_address, std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn pg_user_session_null_auth_method_defaults_password() {
        let pg = PgUserSession {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            login_username: "alice".to_string(),
            ip_address: None,
            auth_method: None,
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
        };
        let session: UserSession = pg.try_into().unwrap();
        assert!(matches!(session.auth_method, AuthMethod::Password));
    }

    #[test]
    fn pg_client_session_null_auth_method_defaults_password() {
        let pg = PgClientSession {
            id: uuid::Uuid::new_v4(),
            client_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            redirect_uri: None,
            state: None,
            auth_method: None,
            timestamp: Utc::now(),
        };
        let cs: ClientSession = pg.try_into().unwrap();
        assert!(matches!(cs.auth_method, AuthMethod::Password));
    }

    #[test]
    fn pg_credential_unknown_type_defaults_to_custom() {
        let pg = PgCredential {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            credential_type: "yubikey".to_string(),
            user_label: None,
            created_date: Utc::now(),
            secret_data: vec![],
            credential_data: json!({}),
            priority: 0,
        };
        let cred: Credential = pg.try_into().unwrap();
        assert!(matches!(cred.credential_type, CredentialType::Custom(ref s) if s == "yubikey"));
    }

    #[test]
    fn pg_event_unknown_event_type_defaults_to_custom() {
        let pg = PgEvent {
            id: uuid::Uuid::new_v4(),
            realm_id: uuid::Uuid::new_v4(),
            event_time: Utc::now(),
            event_type: "custom_event".to_string(),
            ip_address: None,
            client_id: None,
            user_id: None,
            session_id: None,
            error: None,
            details: json!({}),
        };
        let event: Event = pg.try_into().unwrap();
        assert!(matches!(event.event_type, EventType::Custom(ref s) if s == "unknown"));
    }

    // ------------------------------------------------------------------
    // Reverse TryFrom coverage with all optional fields populated
    // ------------------------------------------------------------------

    #[test]
    fn realm_try_into_pg_realm_all_fields() {
        let realm = Realm {
            id: RealmId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            name: RealmName::new("test").unwrap(),
            display_name: Some(DisplayName::new("Test").unwrap()),
            enabled: true,
            ssl_required: SslRequired::External,
            password_policy: PasswordPolicy::default(),
            login_theme: Some(ThemeName::new("keycloak").unwrap()),
            email_theme: Some(ThemeName::new("email").unwrap()),
            admin_theme: Some(ThemeName::new("admin").unwrap()),
            default_role: Some("default".to_string()),
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
            internationalization_enabled: true,
            supported_locales: vec!["en".to_string(), "de".to_string()],
            default_locale: Some("en".to_string()),
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
            attributes: {
                let mut m = HashMap::new();
                m.insert("k".to_string(), "v".to_string());
                m
            },
        };
        let pg: PgRealm = (&realm).try_into().unwrap();
        assert_eq!(pg.display_name, Some("Test".to_string()));
        assert_eq!(pg.login_theme, Some("keycloak".to_string()));
        assert_eq!(pg.email_theme, Some("email".to_string()));
        assert_eq!(pg.admin_theme, Some("admin".to_string()));
        assert!(pg.internationalization_enabled);
        assert_eq!(pg.supported_locales, json!(["en", "de"]));
        assert_eq!(pg.default_locale, Some("en".to_string()));
    }

    #[test]
    fn user_try_into_pg_user_all_fields() {
        let user = User {
            id: UserId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: Some(DisplayName::new("Smith").unwrap()),
            enabled: true,
            federation_link: Some("ldap".to_string()),
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let pg: PgUser = (&user).try_into().unwrap();
        assert_eq!(pg.email, Some("alice@example.com".to_string()));
        assert_eq!(pg.first_name, Some("Alice".to_string()));
        assert_eq!(pg.last_name, Some("Smith".to_string()));
    }

    #[test]
    fn client_try_into_pg_client_all_fields() {
        let client = Client {
            id: ClientId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: Some(DisplayName::new("My App").unwrap()),
            description: Some("desc".to_string()),
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![RedirectUri::new("https://app.example.com").unwrap()],
            web_origins: vec![WebOrigin::new("https://app.example.com").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::parse("profile"),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        let pg: PgClient = (&client).try_into().unwrap();
        assert_eq!(pg.name, Some("My App".to_string()));
        assert_eq!(pg.description, Some("desc".to_string()));
    }

    #[test]
    fn role_try_into_pg_role_all_fields() {
        let role = Role {
            id: RoleId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            name: RoleName::new("admin").unwrap(),
            description: Some("Admin".to_string()),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            client_role: true,
            client_id: Some(ClientId::new("550e8400-e29b-41d4-a716-446655440002").unwrap()),
            composite: true,
            composites: vec![RoleName::new("r1").unwrap()],
            attributes: {
                let mut m = HashMap::new();
                m.insert("k".to_string(), vec!["v".to_string()]);
                m
            },
        };
        let pg: PgRole = (&role).try_into().unwrap();
        assert_eq!(pg.description, Some("Admin".to_string()));
        assert!(pg.client_id.is_some());
    }

    #[test]
    fn group_try_into_pg_group_with_parent() {
        let group = Group {
            id: GroupId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            name: GroupName::new("admins").unwrap(),
            path: GroupPath::new("/admins").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            parent_id: Some(GroupId::new("550e8400-e29b-41d4-a716-446655440002").unwrap()),
            sub_groups: vec![],
            attributes: HashMap::new(),
            realm_roles: vec![RoleName::new("r1").unwrap()],
            client_roles: {
                let mut m = HashMap::new();
                m.insert(
                    ClientId::new("550e8400-e29b-41d4-a716-446655440003").unwrap(),
                    vec![RoleName::new("r1").unwrap()],
                );
                m
            },
        };
        let pg: PgGroup = (&group).try_into().unwrap();
        assert!(pg.parent_id.is_some());
    }

    #[test]
    fn event_try_into_pg_event_all_fields() {
        let event = Event {
            id: EventId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            event_time: Utc::now(),
            event_type: EventType::Login,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            client_id: Some(ClientId::new("550e8400-e29b-41d4-a716-446655440002").unwrap()),
            user_id: Some(UserId::new("550e8400-e29b-41d4-a716-446655440003").unwrap()),
            session_id: Some(SessionId::new("550e8400-e29b-41d4-a716-446655440004").unwrap()),
            error: Some("fail".to_string()),
            details: {
                let mut m = HashMap::new();
                m.insert("k".to_string(), "v".to_string());
                m
            },
        };
        let pg: PgEvent = (&event).try_into().unwrap();
        assert_eq!(pg.ip_address, Some("127.0.0.1".to_string()));
        assert!(pg.client_id.is_some());
        assert!(pg.user_id.is_some());
        assert!(pg.session_id.is_some());
        assert_eq!(pg.error, Some("fail".to_string()));
    }

    #[test]
    fn admin_event_try_into_pg_admin_event_all_fields() {
        let event = AdminEvent {
            id: EventId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            realm_id: RealmId::new("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            auth_realm_id: Some(RealmId::new("550e8400-e29b-41d4-a716-446655440002").unwrap()),
            auth_client_id: Some(ClientId::new("550e8400-e29b-41d4-a716-446655440003").unwrap()),
            auth_user_id: Some(UserId::new("550e8400-e29b-41d4-a716-446655440004").unwrap()),
            operation_type: OperationType::Create,
            resource_type: ResourceType::Realm,
            resource_path: "/".to_string(),
            representation: Some("{}".to_string()),
            error: Some("err".to_string()),
            event_time: Utc::now(),
        };
        let pg: PgAdminEvent = (&event).try_into().unwrap();
        assert!(pg.auth_realm_id.is_some());
        assert!(pg.auth_client_id.is_some());
        assert!(pg.auth_user_id.is_some());
        assert_eq!(pg.representation, Some("{}".to_string()));
        assert_eq!(pg.error, Some("err".to_string()));
    }
}
