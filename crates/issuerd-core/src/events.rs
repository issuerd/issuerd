// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Audit event models: user events, admin events, and their type enumerations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ids::{ClientId, EventId, RealmId, SessionId, UserId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub realm_id: RealmId,
    pub event_time: DateTime<Utc>,
    pub event_type: EventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<std::net::IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<ClientId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<UserId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminEvent {
    pub id: EventId,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_client_id: Option<ClientId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_user_id: Option<UserId>,
    pub operation_type: OperationType,
    pub resource_type: ResourceType,
    pub resource_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub event_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum OperationType {
    Create,
    Update,
    Delete,
    Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceType {
    Realm,
    User,
    Client,
    ClientScope,
    Group,
    Role,
    Session,
    IdentityProvider,
    UserFederation,
    /// Initial access token for dynamic client registration.
    InitialAccessToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Login,
    LoginError,
    Register,
    Logout,
    CodeToToken,
    CodeToTokenError,
    ClientLogin,
    ClientLoginError,
    RefreshToken,
    RefreshTokenError,
    InvalidSignature,
    RegisterError,
    LogoutError,
    /// RFC 8693 token exchange succeeded.
    TokenExchange,
    /// RFC 8693 token exchange failed.
    TokenExchangeError,
    /// CIBA backchannel authentication request accepted.
    CibaAuth,
    /// CIBA backchannel authentication request rejected, or an approval
    /// submission failed (e.g. unknown/expired `auth_req_id`).
    CibaAuthError,
    /// CIBA request approved by the user at the approval endpoint.
    CibaApprove,
    /// CIBA request denied by the user at the approval endpoint.
    CibaDeny,
    Custom(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn roundtrip<
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
    >(
        value: &T,
    ) {
        let json = serde_json::to_string(value).unwrap();
        let back: T = serde_json::from_str(&json).unwrap();
        assert_eq!(*value, back);
    }

    #[test]
    fn event_roundtrip() {
        let e = Event {
            id: EventId::new("event-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            event_time: Utc::now(),
            event_type: EventType::Login,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            client_id: Some(ClientId::new("client-1").unwrap()),
            user_id: Some(UserId::new("user-1").unwrap()),
            session_id: Some(SessionId::new("session-1").unwrap()),
            error: None,
            details: {
                let mut m = std::collections::HashMap::new();
                m.insert("method".to_string(), "password".to_string());
                m
            },
        };
        roundtrip(&e);
    }

    #[test]
    fn admin_event_roundtrip() {
        let e = AdminEvent {
            id: EventId::new("event-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            auth_realm_id: Some(RealmId::new("realm-1").unwrap()),
            auth_client_id: Some(ClientId::new("client-1").unwrap()),
            auth_user_id: Some(UserId::new("user-1").unwrap()),
            operation_type: OperationType::Create,
            resource_type: ResourceType::Realm,
            resource_path: " realms/realm-1 ".to_string(),
            representation: Some("{}".to_string()),
            error: None,
            event_time: Utc::now(),
        };
        roundtrip(&e);
    }

    #[test]
    fn event_type_custom_roundtrip() {
        let et = EventType::Custom("custom_event".to_string());
        let json = serde_json::to_string(&et).unwrap();
        let back: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(et, back);
    }

    #[test]
    fn event_type_ciba_wire_names() {
        // The wire names are an API contract (admin enum listings, stored
        // events, query filters) — snake_case, matching the other variants.
        let cases = [
            (EventType::CibaAuth, "\"ciba_auth\""),
            (EventType::CibaAuthError, "\"ciba_auth_error\""),
            (EventType::CibaApprove, "\"ciba_approve\""),
            (EventType::CibaDeny, "\"ciba_deny\""),
        ];
        for (variant, wire) in cases {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, wire);
            roundtrip(&variant);
        }
    }

    #[test]
    fn operation_type_roundtrip() {
        roundtrip(&OperationType::Create);
        roundtrip(&OperationType::Update);
        roundtrip(&OperationType::Delete);
        roundtrip(&OperationType::Action);
    }
}
