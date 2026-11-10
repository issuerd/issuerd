// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Versioned webhook payloads, subscriptions, deliveries, and filter matching.

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::events::{AdminEvent, Event, EventType, OperationType, ResourceType};
use crate::ids::{EventId, RealmId, UserId, WebhookDeliveryId, WebhookSubscriptionId};
use crate::IssuerdError;

pub const WEBHOOK_SCHEMA_VERSION: u32 = 1;
const MAX_FILTERS: usize = 64;
const MAX_FILTER_LEN: usize = 128;

fn default_filters() -> Vec<String> {
    vec!["*".to_string()]
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WebhookSecret(String);

impl WebhookSecret {
    pub fn new(value: impl Into<String>) -> Result<Self, IssuerdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IssuerdError::InvalidRequest("webhook secret cannot be empty".to_string()));
        }
        if value.len() > 1024 {
            return Err(IssuerdError::InvalidRequest(
                "webhook secret cannot exceed 1024 bytes".to_string(),
            ));
        }
        if value.chars().any(|c| c.is_control()) {
            return Err(IssuerdError::InvalidRequest(
                "webhook secret cannot contain control characters".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebhookSecret([redacted])")
    }
}

impl Drop for WebhookSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookSubscription {
    pub id: WebhookSubscriptionId,
    pub realm_id: RealmId,
    pub url: String,
    pub secret: WebhookSecret,
    pub enabled: bool,
    #[serde(default = "default_filters")]
    pub event_types: Vec<String>,
    #[serde(default)]
    pub include_representation: bool,
    pub created_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
}

impl WebhookSubscription {
    pub fn validate(&self) -> Result<(), IssuerdError> {
        validate_webhook_filters(&self.event_types)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WebhookEventKind {
    User,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookUserEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookAuthDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookAdminEvent {
    pub operation_type: OperationType,
    pub resource_type: ResourceType,
    pub resource_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub auth_details: WebhookAuthDetails,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebhookEventData {
    User(WebhookUserEvent),
    Admin(WebhookAdminEvent),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookEvent {
    pub schema_version: u32,
    pub id: EventId,
    pub time: i64,
    pub kind: WebhookEventKind,
    pub realm_id: RealmId,
    pub realm_name: String,
    #[serde(flatten)]
    pub data: WebhookEventData,
}

impl WebhookEvent {
    pub fn from_user_event(
        event: &Event,
        realm_name: impl Into<String>,
        public_client_id: Option<String>,
    ) -> Self {
        Self {
            schema_version: WEBHOOK_SCHEMA_VERSION,
            id: event.id.clone(),
            time: event.event_time.timestamp_millis(),
            kind: WebhookEventKind::User,
            realm_id: event.realm_id.clone(),
            realm_name: realm_name.into(),
            data: WebhookEventData::User(WebhookUserEvent {
                event_type: event_type_name(&event.event_type),
                client_id: public_client_id,
                user_id: event.user_id.as_ref().map(ToString::to_string),
                session_id: event.session_id.as_ref().map(ToString::to_string),
                ip_address: event.ip_address.map(|ip| ip.to_string()),
                error: event.error.clone(),
                details: event.details.clone(),
            }),
        }
    }

    pub fn from_admin_event(
        event: &AdminEvent,
        realm_name: impl Into<String>,
        auth_realm_name: Option<String>,
        include_representation: bool,
    ) -> Self {
        Self {
            schema_version: WEBHOOK_SCHEMA_VERSION,
            id: event.id.clone(),
            time: event.event_time.timestamp_millis(),
            kind: WebhookEventKind::Admin,
            realm_id: event.realm_id.clone(),
            realm_name: realm_name.into(),
            data: WebhookEventData::Admin(WebhookAdminEvent {
                operation_type: event.operation_type,
                resource_type: event.resource_type,
                resource_path: event.resource_path.clone(),
                representation: include_representation
                    .then(|| event.representation.clone())
                    .flatten(),
                error: event.error.clone(),
                auth_details: WebhookAuthDetails {
                    user_id: event.auth_user_id.as_ref().map(ToString::to_string),
                    realm_id: event.auth_realm_id.as_ref().map(ToString::to_string),
                    realm_name: auth_realm_name,
                    client_id: event.auth_client_id.as_ref().map(ToString::to_string),
                    ip_address: None,
                },
            }),
        }
    }

    pub fn filter_key(&self) -> String {
        match &self.data {
            WebhookEventData::User(event) => format!("USER.{}", event.event_type),
            WebhookEventData::Admin(event) => format!(
                "ADMIN.{}.{}",
                resource_type_name(event.resource_type),
                operation_type_name(event.operation_type)
            ),
        }
    }

    pub fn matches(&self, filters: &[String]) -> bool {
        let key = self.filter_key();
        filters.iter().any(|filter| {
            filter == "*"
                || filter == &key
                || (self.kind == WebhookEventKind::User && filter == "USER.*")
                || (self.kind == WebhookEventKind::Admin && filter == "ADMIN.*")
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeliveryStatus {
    Pending,
    InProgress,
    Delivered,
    Dead,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub sequence: i64,
    pub id: WebhookDeliveryId,
    pub subscription_id: WebhookSubscriptionId,
    pub event_id: EventId,
    pub payload: String,
    pub status: WebhookDeliveryStatus,
    pub attempts: u32,
    pub next_attempt_at: DateTime<Utc>,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebhookDeliveryTask {
    pub delivery: WebhookDelivery,
    pub subscription: WebhookSubscription,
}

pub fn webhook_signing_input(timestamp: i64, raw_body: &str) -> String {
    format!("{timestamp}.{raw_body}")
}

pub fn validate_webhook_filters(filters: &[String]) -> Result<(), IssuerdError> {
    if filters.is_empty() || filters.len() > MAX_FILTERS {
        return Err(IssuerdError::InvalidRequest(format!(
            "webhook eventTypes must contain between 1 and {MAX_FILTERS} entries"
        )));
    }
    for filter in filters {
        validate_filter(filter)?;
    }
    Ok(())
}

fn validate_filter(filter: &str) -> Result<(), IssuerdError> {
    let valid_shape = filter == "*"
        || filter == "USER.*"
        || filter == "ADMIN.*"
        || filter.strip_prefix("USER.").is_some_and(valid_filter_segment)
        || filter.strip_prefix("ADMIN.").is_some_and(|suffix| {
            let mut parts = suffix.split('.');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(resource), Some(operation), None) => {
                    valid_filter_segment(resource) && valid_filter_segment(operation)
                }
                _ => false,
            }
        });
    if filter.is_empty()
        || filter.len() > MAX_FILTER_LEN
        || !filter
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '*'))
        || !valid_shape
    {
        return Err(IssuerdError::InvalidRequest(format!(
            "invalid webhook event filter: {filter}"
        )));
    }
    Ok(())
}

fn valid_filter_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn event_type_name(event_type: &EventType) -> String {
    match event_type {
        EventType::Login => "LOGIN".to_string(),
        EventType::LoginError => "LOGIN_ERROR".to_string(),
        EventType::Register => "REGISTER".to_string(),
        EventType::Logout => "LOGOUT".to_string(),
        EventType::CodeToToken => "CODE_TO_TOKEN".to_string(),
        EventType::CodeToTokenError => "CODE_TO_TOKEN_ERROR".to_string(),
        EventType::ClientLogin => "CLIENT_LOGIN".to_string(),
        EventType::ClientLoginError => "CLIENT_LOGIN_ERROR".to_string(),
        EventType::RefreshToken => "REFRESH_TOKEN".to_string(),
        EventType::RefreshTokenError => "REFRESH_TOKEN_ERROR".to_string(),
        EventType::InvalidSignature => "INVALID_SIGNATURE".to_string(),
        EventType::RegisterError => "REGISTER_ERROR".to_string(),
        EventType::LogoutError => "LOGOUT_ERROR".to_string(),
        EventType::TokenExchange => "TOKEN_EXCHANGE".to_string(),
        EventType::TokenExchangeError => "TOKEN_EXCHANGE_ERROR".to_string(),
        EventType::CibaAuth => "CIBA_AUTH".to_string(),
        EventType::CibaAuthError => "CIBA_AUTH_ERROR".to_string(),
        EventType::CibaApprove => "CIBA_APPROVE".to_string(),
        EventType::CibaDeny => "CIBA_DENY".to_string(),
        EventType::Custom(value) => value.to_ascii_uppercase(),
    }
}

fn operation_type_name(operation: OperationType) -> &'static str {
    match operation {
        OperationType::Create => "CREATE",
        OperationType::Update => "UPDATE",
        OperationType::Delete => "DELETE",
        OperationType::Action => "ACTION",
    }
}

fn resource_type_name(resource: ResourceType) -> &'static str {
    match resource {
        ResourceType::Realm => "REALM",
        ResourceType::User => "USER",
        ResourceType::Client => "CLIENT",
        ResourceType::ClientScope => "CLIENT_SCOPE",
        ResourceType::Group => "GROUP",
        ResourceType::Role => "ROLE",
        ResourceType::Session => "SESSION",
        ResourceType::IdentityProvider => "IDENTITY_PROVIDER",
        ResourceType::UserFederation => "USER_FEDERATION",
        ResourceType::InitialAccessToken => "INITIAL_ACCESS_TOKEN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ClientId, SessionId};

    fn user_event() -> Event {
        Event {
            id: EventId::new("event-1").unwrap(),
            realm_id: RealmId::new("realm-uuid").unwrap(),
            event_time: DateTime::from_timestamp_millis(1_762_000_000_123).unwrap(),
            event_type: EventType::Login,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            client_id: Some(ClientId::new("client-uuid").unwrap()),
            user_id: Some(UserId::new("user-uuid").unwrap()),
            session_id: Some(SessionId::new("session-uuid").unwrap()),
            error: None,
            details: HashMap::from([("method".to_string(), "password".to_string())]),
        }
    }

    fn admin_event() -> AdminEvent {
        AdminEvent {
            id: EventId::new("event-2").unwrap(),
            realm_id: RealmId::new("realm-uuid").unwrap(),
            auth_realm_id: Some(RealmId::new("master-uuid").unwrap()),
            auth_client_id: Some(ClientId::new("admin-cli").unwrap()),
            auth_user_id: Some(UserId::new("admin-uuid").unwrap()),
            operation_type: OperationType::Create,
            resource_type: ResourceType::User,
            resource_path: "users/user-uuid".to_string(),
            representation: Some("{\"username\":\"alice\"}".to_string()),
            error: None,
            event_time: DateTime::from_timestamp_millis(1_762_000_000_456).unwrap(),
        }
    }

    #[test]
    fn user_payload_is_versioned_and_keycloak_shaped() {
        let event = WebhookEvent::from_user_event(
            &user_event(),
            "demo",
            Some("account-console".to_string()),
        );
        assert_eq!(event.filter_key(), "USER.LOGIN");
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["kind"], "USER");
        assert_eq!(value["time"], 1_762_000_000_123_i64);
        assert_eq!(value["type"], "LOGIN");
        assert_eq!(value["realmId"], "realm-uuid");
        assert_eq!(value["realmName"], "demo");
        assert_eq!(value["clientId"], "account-console");
        assert_eq!(value["details"]["method"], "password");
        assert!(value.get("realm_id").is_none());
        assert!(value.get("event_type").is_none());
    }

    #[test]
    fn admin_payload_filters_and_representation_policy() {
        let event = WebhookEvent::from_admin_event(
            &admin_event(),
            "demo",
            Some("master".to_string()),
            false,
        );
        assert_eq!(event.filter_key(), "ADMIN.USER.CREATE");
        assert!(event.matches(&["ADMIN.USER.CREATE".to_string()]));
        assert!(event.matches(&["ADMIN.*".to_string()]));
        assert!(event.matches(&["*".to_string()]));
        assert!(!event.matches(&["USER.*".to_string()]));
        let value = serde_json::to_value(&event).unwrap();
        assert!(value.get("representation").is_none());
        assert_eq!(value["authDetails"]["clientId"], "admin-cli");
        assert_eq!(value["authDetails"]["realmName"], "master");

        let with_representation = WebhookEvent::from_admin_event(
            &admin_event(),
            "demo",
            Some("master".to_string()),
            true,
        );
        assert!(with_representation.matches(&["ADMIN.USER.CREATE".to_string()]));
        assert_eq!(
            serde_json::to_value(with_representation).unwrap()["representation"],
            "{\"username\":\"alice\"}"
        );
    }

    #[test]
    fn custom_user_events_have_a_stable_filter_name() {
        let mut event = user_event();
        event.event_type = EventType::Custom("custom_event".to_string());
        let event = WebhookEvent::from_user_event(&event, "demo", None);
        assert_eq!(event.filter_key(), "USER.CUSTOM_EVENT");
        assert!(event.matches(&["USER.CUSTOM_EVENT".to_string()]));
    }

    #[test]
    fn filter_validation_accepts_only_the_documented_grammar() {
        for valid in ["*", "USER.*", "ADMIN.*", "USER.LOGIN", "ADMIN.USER.CREATE"] {
            validate_webhook_filters(&[valid.to_string()]).unwrap();
        }
        for invalid in [
            "",
            "LOGIN",
            "USER.",
            "ADMIN.USER",
            "USER.LOGIN.*",
            "USER.LOGIN.EXTRA",
            "admin.*",
            "USER.login",
            "ADMIN.USER.CREATE.EXTRA",
            "USER.LOGIN EXTRA",
        ] {
            assert!(validate_webhook_filters(&[invalid.to_string()]).is_err(), "{invalid}");
        }
        assert!(validate_webhook_filters(&[]).is_err());
    }

    #[test]
    fn secret_is_redacted_in_debug_but_survives_storage_serialization() {
        let secret = WebhookSecret::new("very-secret-value").unwrap();
        assert!(!format!("{secret:?}").contains("very-secret-value"));
        let json = serde_json::to_string(&secret).unwrap();
        let decoded: WebhookSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.as_str(), "very-secret-value");
        for invalid in ["", "line\nfeed"] {
            assert!(WebhookSecret::new(invalid).is_err());
        }
    }

    #[test]
    fn signing_input_contains_timestamp_and_exact_body() {
        assert_eq!(webhook_signing_input(42, "{\"a\":1}"), "42.{\"a\":1}");
    }
}
