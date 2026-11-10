// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Normalized user/admin event publication into durable webhook outboxes.

use issuerd_core::*;

async fn publish_with_subscriptions(
    storage: &dyn Storage,
    event: &WebhookEvent,
    subscriptions: Vec<WebhookSubscription>,
) -> Result<usize, IssuerdError> {
    let mut enqueued = 0;
    for subscription in subscriptions
        .into_iter()
        .filter(|subscription| subscription.enabled && event.matches(&subscription.event_types))
    {
        let event = event.clone().with_subscription_policy(&subscription);
        if storage
            .enqueue_webhook_delivery(&event.realm_id, &subscription.id, &event)
            .await?
        {
            enqueued += 1;
        }
    }
    Ok(enqueued)
}

pub async fn publish_webhook_event(
    storage: &dyn Storage,
    event: &WebhookEvent,
) -> Result<usize, IssuerdError> {
    let subscriptions = match storage.list_webhook_subscriptions(&event.realm_id).await {
        Ok(subscriptions) => subscriptions,
        Err(IssuerdError::UnsupportedOperation) => return Ok(0),
        Err(error) => return Err(error),
    };
    publish_with_subscriptions(storage, event, subscriptions).await
}

pub async fn publish_user_event(
    storage: &dyn Storage,
    event: &Event,
) -> Result<usize, IssuerdError> {
    let subscriptions = match storage.list_webhook_subscriptions(&event.realm_id).await {
        Ok(subscriptions) => subscriptions,
        Err(IssuerdError::UnsupportedOperation) => return Ok(0),
        Err(error) => return Err(error),
    };
    if subscriptions.is_empty() {
        return Ok(0);
    }
    let realm = storage.get_realm(&event.realm_id).await?;
    let realm_name = realm
        .as_ref()
        .map(|realm| realm.name.to_string())
        .unwrap_or_else(|| event.realm_id.to_string());
    let public_client_id = match &event.client_id {
        Some(client_id) => storage
            .get_client(&event.realm_id, client_id)
            .await?
            .map(|client| client.client_id.to_string()),
        None => None,
    };
    let event = WebhookEvent::from_user_event(event, realm_name, public_client_id);
    publish_with_subscriptions(storage, &event, subscriptions).await
}

pub async fn publish_admin_event(
    storage: &dyn Storage,
    event: &AdminEvent,
) -> Result<usize, IssuerdError> {
    let subscriptions = match storage.list_webhook_subscriptions(&event.realm_id).await {
        Ok(subscriptions) => subscriptions,
        Err(IssuerdError::UnsupportedOperation) => return Ok(0),
        Err(error) => return Err(error),
    };
    if subscriptions.is_empty() {
        return Ok(0);
    }
    let realm = storage.get_realm(&event.realm_id).await?;
    let realm_name = realm
        .as_ref()
        .map(|realm| realm.name.to_string())
        .unwrap_or_else(|| event.realm_id.to_string());
    let include_representation = realm.is_some_and(|realm| realm.include_representations);
    let auth_realm_name = match &event.auth_realm_id {
        Some(realm_id) => storage.get_realm(realm_id).await?.map(|realm| realm.name.to_string()),
        None => None,
    };
    let mut event = event.clone();
    event.representation = redact_admin_representation(event.resource_type, event.representation);
    let event =
        WebhookEvent::from_admin_event(&event, realm_name, auth_realm_name, include_representation);
    publish_with_subscriptions(storage, &event, subscriptions).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryStorage;
    use chrono::Utc;

    fn realm() -> Realm {
        Realm {
            id: RealmId::new("realm-1").unwrap(),
            name: RealmName::new("demo").unwrap(),
            ..Realm::default()
        }
    }

    fn client(realm: &Realm) -> Client {
        Client {
            id: ClientId::new("client-uuid").unwrap(),
            realm_id: realm.id.clone(),
            client_id: ClientIdentifier::new("app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: true,
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
            protocol_mappers: vec![],
            scope_mappings: Default::default(),
            attributes: Default::default(),
        }
    }

    fn subscription(
        realm: &Realm,
        id: &str,
        filters: &[&str],
        enabled: bool,
        include_representation: bool,
    ) -> WebhookSubscription {
        WebhookSubscription {
            id: WebhookSubscriptionId::new(id).unwrap(),
            realm_id: realm.id.clone(),
            url: "https://receiver.example/events".to_string(),
            secret: WebhookSecret::new("secret").unwrap(),
            enabled,
            event_types: filters.iter().map(|value| value.to_string()).collect(),
            include_representation,
            created_by: None,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn user_publication_resolves_public_client_and_filters_subscriptions() {
        let storage = InMemoryStorage::new();
        let realm = realm();
        storage.create_realm(&realm).await.unwrap();
        storage.create_client(&realm.id, &client(&realm)).await.unwrap();
        storage
            .create_webhook_subscription(
                &realm.id,
                &subscription(&realm, "matching", &["USER.LOGIN"], true, false),
            )
            .await
            .unwrap();
        storage
            .create_webhook_subscription(
                &realm.id,
                &subscription(&realm, "other-kind", &["ADMIN.*"], true, false),
            )
            .await
            .unwrap();
        storage
            .create_webhook_subscription(
                &realm.id,
                &subscription(&realm, "disabled", &["*"], false, false),
            )
            .await
            .unwrap();
        let event = Event {
            id: EventId::new("event-1").unwrap(),
            realm_id: realm.id.clone(),
            event_time: Utc::now(),
            event_type: EventType::Login,
            ip_address: None,
            client_id: Some(ClientId::new("client-uuid").unwrap()),
            user_id: None,
            session_id: None,
            error: None,
            details: Default::default(),
        };
        assert_eq!(publish_user_event(&storage, &event).await.unwrap(), 1);
        assert_eq!(publish_user_event(&storage, &event).await.unwrap(), 0);
        let deliveries = storage
            .list_webhook_deliveries(&realm.id, None, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        let payload: serde_json::Value = serde_json::from_str(&deliveries[0].payload).unwrap();
        assert_eq!(payload["clientId"], "app");
        assert_eq!(payload["type"], "LOGIN");
        assert_eq!(payload["realmName"], "demo");
    }

    #[tokio::test]
    async fn admin_publication_applies_per_subscription_representation_policy() {
        let storage = InMemoryStorage::new();
        let mut realm = realm();
        realm.include_representations = true;
        realm.admin_events_enabled = false;
        storage.create_realm(&realm).await.unwrap();
        storage
            .create_webhook_subscription(
                &realm.id,
                &subscription(&realm, "redacted", &["ADMIN.REALM.UPDATE"], true, false),
            )
            .await
            .unwrap();
        storage
            .create_webhook_subscription(
                &realm.id,
                &subscription(&realm, "represented", &["ADMIN.REALM.UPDATE"], true, true),
            )
            .await
            .unwrap();
        let representation = format!(
            "{{\"attributes\":{{\"{}\":\"secret-key\",\"other\":\"ok\"}}}}",
            Realm::PAIRWISE_SECTOR_KEY_ATTRIBUTE
        );
        let event = AdminEvent {
            id: EventId::new("event-2").unwrap(),
            realm_id: realm.id.clone(),
            auth_realm_id: Some(realm.id.clone()),
            auth_client_id: Some(ClientId::new("admin-cli").unwrap()),
            auth_user_id: None,
            operation_type: OperationType::Update,
            resource_type: ResourceType::Realm,
            resource_path: "realms/demo".to_string(),
            representation: Some(representation),
            error: None,
            event_time: Utc::now(),
        };
        assert_eq!(publish_admin_event(&storage, &event).await.unwrap(), 2);
        let deliveries = storage
            .list_webhook_deliveries(&realm.id, None, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 2);
        for delivery in deliveries {
            let payload: serde_json::Value = serde_json::from_str(&delivery.payload).unwrap();
            if delivery.subscription_id.as_ref() == "redacted" {
                assert!(payload.get("representation").is_none());
            } else {
                let representation = payload["representation"].as_str().unwrap();
                assert!(!representation.contains("secret-key"));
                assert!(representation.contains("other"));
            }
        }

        realm.include_representations = false;
        storage.update_realm(&realm).await.unwrap();
        let mut event = event;
        event.id = EventId::new("event-3").unwrap();
        assert_eq!(publish_admin_event(&storage, &event).await.unwrap(), 2);
        let deliveries = storage
            .list_webhook_deliveries(&realm.id, None, &Pagination::default())
            .await
            .unwrap();
        let redacted: Vec<_> = deliveries
            .iter()
            .filter(|delivery| delivery.event_id.as_ref() == "event-3")
            .collect();
        assert_eq!(redacted.len(), 2);
        for delivery in redacted {
            let payload: serde_json::Value = serde_json::from_str(&delivery.payload).unwrap();
            assert!(payload.get("representation").is_none());
        }
    }
}
