// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Built-in event listeners: the always-registered logging listener.

//! Built-in event listeners.
//!
//! A realm's `events_listeners` list names listeners from
//! [`crate::state::ServerState::event_listeners`]; `"logging"` is always
//! registered. Unknown names are ignored at dispatch time (debug-logged).

use async_trait::async_trait;
use issuerd_core::{AdminEvent, Event, EventListener, IssuerdError};
use tracing::info;

/// Listener id registered for [`LoggingEventListener`].
pub const LOGGING_LISTENER_ID: &str = "logging";

/// Writes every dispatched event to the tracing log at INFO with structured
/// fields — the always-available audit trail for realms that enable events.
pub struct LoggingEventListener;

#[async_trait]
impl EventListener for LoggingEventListener {
    async fn on_event(&self, event: &Event) -> Result<(), IssuerdError> {
        info!(
            realm = %event.realm_id,
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            client_id = ?event.client_id,
            session_id = ?event.session_id,
            error = ?event.error,
            "user event"
        );
        Ok(())
    }

    async fn on_admin_event(&self, event: &AdminEvent) -> Result<(), IssuerdError> {
        info!(
            realm = %event.realm_id,
            operation = ?event.operation_type,
            resource_type = ?event.resource_type,
            resource_path = %event.resource_path,
            error = ?event.error,
            "admin event"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{EventId, EventType, OperationType, RealmId, ResourceType};

    #[tokio::test]
    async fn logging_listener_accepts_events() {
        let listener = LoggingEventListener;
        let event = Event {
            id: EventId::new("evt-1").unwrap(),
            realm_id: RealmId::new("master").unwrap(),
            event_time: chrono::Utc::now(),
            event_type: EventType::Login,
            ip_address: None,
            client_id: None,
            user_id: None,
            session_id: None,
            error: None,
            details: Default::default(),
        };
        listener.on_event(&event).await.unwrap();

        let admin_event = AdminEvent {
            id: EventId::new("evt-2").unwrap(),
            realm_id: RealmId::new("master").unwrap(),
            auth_realm_id: None,
            auth_client_id: None,
            auth_user_id: None,
            operation_type: OperationType::Action,
            resource_type: ResourceType::Session,
            resource_path: "backchannel-logout/app".to_string(),
            representation: None,
            error: None,
            event_time: chrono::Utc::now(),
        };
        listener.on_admin_event(&admin_event).await.unwrap();
    }
}
