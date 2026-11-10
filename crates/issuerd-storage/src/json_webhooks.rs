// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// JSON persistence delegation for webhook subscriptions and deliveries.

use std::time::Duration;

use chrono::{DateTime, Utc};
use issuerd_core::*;

use crate::json::JsonFileStorage;

impl JsonFileStorage {
    pub async fn create_webhook_subscription(
        &self,
        realm: &RealmId,
        subscription: &WebhookSubscription,
    ) -> Result<(), IssuerdError> {
        self.inner.create_webhook_subscription(realm, subscription).await?;
        self.persist()
    }

    pub async fn get_webhook_subscription(
        &self,
        realm: &RealmId,
        id: &WebhookSubscriptionId,
    ) -> Result<Option<WebhookSubscription>, IssuerdError> {
        self.inner.get_webhook_subscription(realm, id).await
    }

    pub async fn list_webhook_subscriptions(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<WebhookSubscription>, IssuerdError> {
        self.inner.list_webhook_subscriptions(realm).await
    }

    pub async fn update_webhook_subscription(
        &self,
        realm: &RealmId,
        subscription: &WebhookSubscription,
    ) -> Result<(), IssuerdError> {
        self.inner.update_webhook_subscription(realm, subscription).await?;
        self.persist()
    }

    pub async fn delete_webhook_subscription(
        &self,
        realm: &RealmId,
        id: &WebhookSubscriptionId,
    ) -> Result<(), IssuerdError> {
        self.inner.delete_webhook_subscription(realm, id).await?;
        self.persist()
    }

    pub async fn enqueue_webhook_delivery(
        &self,
        realm: &RealmId,
        subscription_id: &WebhookSubscriptionId,
        event: &WebhookEvent,
    ) -> Result<bool, IssuerdError> {
        let inserted = self.inner.enqueue_webhook_delivery(realm, subscription_id, event).await?;
        if inserted {
            self.persist()?;
        }
        Ok(inserted)
    }

    pub async fn claim_webhook_deliveries(
        &self,
        worker_id: &str,
        limit: u32,
        lease_duration: Duration,
    ) -> Result<Vec<WebhookDeliveryTask>, IssuerdError> {
        let tasks = self.inner.claim_webhook_deliveries(worker_id, limit, lease_duration).await?;
        self.persist()?;
        Ok(tasks)
    }

    pub async fn complete_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
        lease_owner: &str,
    ) -> Result<(), IssuerdError> {
        self.inner.complete_webhook_delivery(realm, id, lease_owner).await?;
        self.persist()
    }

    pub async fn fail_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
        lease_owner: &str,
        error: &str,
        next_attempt_at: Option<DateTime<Utc>>,
    ) -> Result<(), IssuerdError> {
        self.inner
            .fail_webhook_delivery(realm, id, lease_owner, error, next_attempt_at)
            .await?;
        self.persist()
    }

    pub async fn replay_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
    ) -> Result<(), IssuerdError> {
        self.inner.replay_webhook_delivery(realm, id).await?;
        self.persist()
    }

    pub async fn list_webhook_deliveries(
        &self,
        realm: &RealmId,
        subscription_id: Option<WebhookSubscriptionId>,
        pagination: &Pagination,
    ) -> Result<Vec<WebhookDelivery>, IssuerdError> {
        self.inner.list_webhook_deliveries(realm, subscription_id, pagination).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscriptions_and_deliveries_survive_json_reopen() {
        let realm = RealmId::new("realm-1").unwrap();
        let subscription = WebhookSubscription {
            id: WebhookSubscriptionId::new("subscription-1").unwrap(),
            realm_id: realm.clone(),
            url: "https://receiver.example/events".to_string(),
            secret: WebhookSecret::new("secret").unwrap(),
            enabled: true,
            event_types: vec!["*".to_string()],
            include_representation: false,
            created_by: None,
            created_at: Utc::now(),
        };
        let event = WebhookEvent::from_user_event(
            &Event {
                id: EventId::new("event-1").unwrap(),
                realm_id: realm.clone(),
                event_time: Utc::now(),
                event_type: EventType::Register,
                ip_address: None,
                client_id: None,
                user_id: None,
                session_id: None,
                error: None,
                details: Default::default(),
            },
            "demo",
            None,
        );
        let path = std::env::temp_dir()
            .join(format!("issuerd-webhooks-{}.json", issuerd_core::utils::generate_id()));

        let storage = JsonFileStorage::new(&path).unwrap();
        storage.create_webhook_subscription(&realm, &subscription).await.unwrap();
        storage
            .enqueue_webhook_delivery(&realm, &subscription.id, &event)
            .await
            .unwrap();
        drop(storage);

        let storage = JsonFileStorage::new(&path).unwrap();
        let stored = storage
            .get_webhook_subscription(&realm, &subscription.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.secret.as_str(), "secret");
        let claimed = storage
            .claim_webhook_deliveries("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        let id = claimed[0].delivery.id.clone();
        storage
            .complete_webhook_delivery(
                &realm,
                &id,
                claimed[0].delivery.lease_owner.as_deref().unwrap(),
            )
            .await
            .unwrap();
        drop(storage);

        let storage = JsonFileStorage::new(&path).unwrap();
        let history = storage
            .list_webhook_deliveries(&realm, None, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, WebhookDeliveryStatus::Delivered);
        drop(storage);
        std::fs::remove_file(path).unwrap();
    }
}
