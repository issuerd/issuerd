// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// In-memory webhook subscriptions and durable-delivery semantics.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use issuerd_core::*;

use crate::memory::InMemoryStorage;

#[derive(Default)]
pub(crate) struct MemoryWebhookState {
    pub subscriptions: DashMap<(RealmId, WebhookSubscriptionId), WebhookSubscription>,
    pub deliveries: DashMap<WebhookDeliveryId, WebhookDelivery>,
    pub next_sequence: AtomicI64,
    pub lock: tokio::sync::Mutex<()>,
}

impl MemoryWebhookState {
    pub fn snapshot(&self) -> (Vec<WebhookSubscription>, Vec<WebhookDelivery>, i64) {
        (
            self.subscriptions.iter().map(|entry| entry.value().clone()).collect(),
            self.deliveries.iter().map(|entry| entry.value().clone()).collect(),
            self.next_sequence.load(Ordering::Relaxed),
        )
    }

    pub fn restore(
        &self,
        subscriptions: Vec<WebhookSubscription>,
        deliveries: Vec<WebhookDelivery>,
        next_sequence: i64,
    ) {
        self.subscriptions.clear();
        self.deliveries.clear();
        for subscription in subscriptions {
            self.subscriptions
                .insert((subscription.realm_id.clone(), subscription.id.clone()), subscription);
        }
        let max_sequence = deliveries.iter().map(|delivery| delivery.sequence).max().unwrap_or(0);
        for delivery in deliveries {
            self.deliveries.insert(delivery.id.clone(), delivery);
        }
        self.next_sequence.store(next_sequence.max(max_sequence), Ordering::Relaxed);
    }
}

fn lease_expiry(now: DateTime<Utc>, duration: Duration) -> Result<DateTime<Utc>, IssuerdError> {
    let duration = chrono::Duration::from_std(duration)
        .map_err(|e| IssuerdError::InvalidRequest(format!("invalid webhook lease: {e}")))?;
    now.checked_add_signed(duration)
        .ok_or_else(|| IssuerdError::InvalidRequest("webhook lease overflows timestamp".into()))
}

fn subscription_for_delivery(
    state: &MemoryWebhookState,
    realm: &RealmId,
    id: &WebhookDeliveryId,
) -> Result<(WebhookDelivery, WebhookSubscription), IssuerdError> {
    let delivery = state
        .deliveries
        .get(id)
        .map(|entry| entry.clone())
        .ok_or(IssuerdError::NotFound)?;
    let subscription = state
        .subscriptions
        .get(&(realm.clone(), delivery.subscription_id.clone()))
        .map(|entry| entry.value().clone())
        .ok_or(IssuerdError::NotFound)?;
    Ok((delivery, subscription))
}

impl InMemoryStorage {
    pub async fn create_webhook_subscription(
        &self,
        realm: &RealmId,
        subscription: &WebhookSubscription,
    ) -> Result<(), IssuerdError> {
        subscription.validate()?;
        if subscription.realm_id != *realm {
            return Err(IssuerdError::InvalidRequest("webhook subscription realm mismatch".into()));
        }
        let _guard = self.webhooks.lock.lock().await;
        let key = (realm.clone(), subscription.id.clone());
        if self.webhooks.subscriptions.contains_key(&key) {
            return Err(IssuerdError::Conflict);
        }
        self.webhooks.subscriptions.insert(key, subscription.clone());
        Ok(())
    }

    pub async fn get_webhook_subscription(
        &self,
        realm: &RealmId,
        id: &WebhookSubscriptionId,
    ) -> Result<Option<WebhookSubscription>, IssuerdError> {
        Ok(self
            .webhooks
            .subscriptions
            .get(&(realm.clone(), id.clone()))
            .map(|entry| entry.value().clone()))
    }

    pub async fn list_webhook_subscriptions(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<WebhookSubscription>, IssuerdError> {
        let mut subscriptions: Vec<_> = self
            .webhooks
            .subscriptions
            .iter()
            .filter(|entry| entry.key().0 == *realm)
            .map(|entry| entry.value().clone())
            .collect();
        subscriptions.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(subscriptions)
    }

    pub async fn update_webhook_subscription(
        &self,
        realm: &RealmId,
        subscription: &WebhookSubscription,
    ) -> Result<(), IssuerdError> {
        subscription.validate()?;
        if subscription.realm_id != *realm {
            return Err(IssuerdError::InvalidRequest("webhook subscription realm mismatch".into()));
        }
        let _guard = self.webhooks.lock.lock().await;
        let key = (realm.clone(), subscription.id.clone());
        if !self.webhooks.subscriptions.contains_key(&key) {
            return Err(IssuerdError::NotFound);
        }
        self.webhooks.subscriptions.insert(key, subscription.clone());
        Ok(())
    }

    pub async fn delete_webhook_subscription(
        &self,
        realm: &RealmId,
        id: &WebhookSubscriptionId,
    ) -> Result<(), IssuerdError> {
        let _guard = self.webhooks.lock.lock().await;
        self.webhooks.subscriptions.remove(&(realm.clone(), id.clone()));
        self.webhooks.deliveries.retain(|_, delivery| delivery.subscription_id != *id);
        Ok(())
    }

    pub async fn enqueue_webhook_delivery(
        &self,
        realm: &RealmId,
        subscription_id: &WebhookSubscriptionId,
        event: &WebhookEvent,
    ) -> Result<bool, IssuerdError> {
        if event.realm_id != *realm {
            return Err(IssuerdError::InvalidRequest("webhook event realm mismatch".into()));
        }
        let _guard = self.webhooks.lock.lock().await;
        if !self
            .webhooks
            .subscriptions
            .contains_key(&(realm.clone(), subscription_id.clone()))
        {
            return Err(IssuerdError::NotFound);
        }
        if self
            .webhooks
            .deliveries
            .iter()
            .any(|entry| entry.subscription_id == *subscription_id && entry.event_id == event.id)
        {
            return Ok(false);
        }
        let now = Utc::now();
        let delivery = WebhookDelivery {
            sequence: self.webhooks.next_sequence.fetch_add(1, Ordering::Relaxed) + 1,
            id: WebhookDeliveryId::new(issuerd_core::utils::generate_id())?,
            subscription_id: subscription_id.clone(),
            event_id: event.id.clone(),
            payload: serde_json::to_string(event)
                .map_err(|e| IssuerdError::ServerError(format!("webhook payload: {e}")))?,
            status: WebhookDeliveryStatus::Pending,
            attempts: 0,
            next_attempt_at: now,
            lease_owner: None,
            lease_expires_at: None,
            last_error: None,
            created_at: now,
            updated_at: now,
            delivered_at: None,
        };
        self.webhooks.deliveries.insert(delivery.id.clone(), delivery);
        Ok(true)
    }

    pub async fn claim_webhook_deliveries(
        &self,
        worker_id: &str,
        limit: u32,
        lease_duration: Duration,
    ) -> Result<Vec<WebhookDeliveryTask>, IssuerdError> {
        let _guard = self.webhooks.lock.lock().await;
        let now = Utc::now();
        let lease_expires_at = lease_expiry(now, lease_duration)?;
        for mut delivery in self.webhooks.deliveries.iter_mut() {
            if delivery.status == WebhookDeliveryStatus::InProgress
                && delivery.lease_expires_at.is_some_and(|expiry| expiry <= now)
            {
                delivery.status = WebhookDeliveryStatus::Pending;
                delivery.lease_owner = None;
                delivery.lease_expires_at = None;
                delivery.updated_at = now;
            }
        }
        let mut candidates: Vec<_> = self
            .webhooks
            .deliveries
            .iter()
            .filter_map(|entry| {
                let delivery = entry.value();
                let subscription = self.webhooks.subscriptions.get(&(
                    delivery_realm(self, &delivery.subscription_id),
                    delivery.subscription_id.clone(),
                ))?;
                (subscription.enabled
                    && delivery.status == WebhookDeliveryStatus::Pending
                    && delivery.next_attempt_at <= now)
                    .then(|| (delivery.clone(), subscription.clone()))
            })
            .collect();
        candidates.sort_by_key(|(delivery, _)| delivery.sequence);
        candidates.truncate(limit as usize);
        let mut tasks = Vec::with_capacity(candidates.len());
        for (mut delivery, subscription) in candidates {
            let lease_owner = format!("{worker_id}:{}", issuerd_core::utils::generate_id());
            delivery.status = WebhookDeliveryStatus::InProgress;
            delivery.lease_owner = Some(lease_owner);
            delivery.lease_expires_at = Some(lease_expires_at);
            delivery.updated_at = now;
            self.webhooks.deliveries.insert(delivery.id.clone(), delivery.clone());
            tasks.push(WebhookDeliveryTask {
                delivery,
                subscription,
            });
        }
        Ok(tasks)
    }

    pub async fn complete_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
        lease_owner: &str,
    ) -> Result<(), IssuerdError> {
        let _guard = self.webhooks.lock.lock().await;
        let (mut delivery, _) = subscription_for_delivery(&self.webhooks, realm, id)?;
        if delivery.status != WebhookDeliveryStatus::InProgress
            || delivery.lease_owner.as_deref() != Some(lease_owner)
        {
            return Err(IssuerdError::Conflict);
        }
        let now = Utc::now();
        delivery.status = WebhookDeliveryStatus::Delivered;
        delivery.lease_owner = None;
        delivery.lease_expires_at = None;
        delivery.last_error = None;
        delivery.updated_at = now;
        delivery.delivered_at = Some(now);
        self.webhooks.deliveries.insert(id.clone(), delivery);
        Ok(())
    }

    pub async fn fail_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
        lease_owner: &str,
        error: &str,
        next_attempt_at: Option<DateTime<Utc>>,
    ) -> Result<(), IssuerdError> {
        let _guard = self.webhooks.lock.lock().await;
        let (mut delivery, _) = subscription_for_delivery(&self.webhooks, realm, id)?;
        if delivery.status != WebhookDeliveryStatus::InProgress
            || delivery.lease_owner.as_deref() != Some(lease_owner)
        {
            return Err(IssuerdError::Conflict);
        }
        delivery.attempts = delivery.attempts.saturating_add(1);
        delivery.status = if next_attempt_at.is_some() {
            WebhookDeliveryStatus::Pending
        } else {
            WebhookDeliveryStatus::Dead
        };
        delivery.next_attempt_at = next_attempt_at.unwrap_or(delivery.next_attempt_at);
        delivery.lease_owner = None;
        delivery.lease_expires_at = None;
        delivery.last_error = Some(error.to_string());
        delivery.updated_at = Utc::now();
        self.webhooks.deliveries.insert(id.clone(), delivery);
        Ok(())
    }

    pub async fn replay_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
    ) -> Result<(), IssuerdError> {
        let _guard = self.webhooks.lock.lock().await;
        let (mut delivery, _) = subscription_for_delivery(&self.webhooks, realm, id)?;
        if delivery.status == WebhookDeliveryStatus::InProgress {
            return Err(IssuerdError::Conflict);
        }
        let now = Utc::now();
        delivery.status = WebhookDeliveryStatus::Pending;
        delivery.attempts = 0;
        delivery.next_attempt_at = now;
        delivery.lease_owner = None;
        delivery.lease_expires_at = None;
        delivery.last_error = None;
        delivery.updated_at = now;
        delivery.delivered_at = None;
        self.webhooks.deliveries.insert(id.clone(), delivery);
        Ok(())
    }

    pub async fn list_webhook_deliveries(
        &self,
        realm: &RealmId,
        subscription_id: Option<WebhookSubscriptionId>,
        pagination: &Pagination,
    ) -> Result<Vec<WebhookDelivery>, IssuerdError> {
        let mut deliveries: Vec<_> = self
            .webhooks
            .deliveries
            .iter()
            .filter(|entry| {
                subscription_id.as_ref().is_none_or(|id| entry.subscription_id == *id)
                    && self
                        .webhooks
                        .subscriptions
                        .contains_key(&(realm.clone(), entry.subscription_id.clone()))
            })
            .map(|entry| entry.value().clone())
            .collect();
        deliveries.sort_by_key(|delivery| std::cmp::Reverse(delivery.sequence));
        let first = pagination.first.max(0) as usize;
        let max = pagination.max.max(0) as usize;
        Ok(deliveries.into_iter().skip(first).take(max).collect())
    }
}

fn delivery_realm(storage: &InMemoryStorage, subscription_id: &WebhookSubscriptionId) -> RealmId {
    storage
        .webhooks
        .subscriptions
        .iter()
        .find(|entry| entry.key().1 == *subscription_id)
        .map(|entry| entry.key().0.clone())
        .unwrap_or_else(|| RealmId::new("unknown").expect("non-empty realm fallback"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("realm-1").unwrap()
    }

    fn subscription() -> WebhookSubscription {
        WebhookSubscription {
            id: WebhookSubscriptionId::new("subscription-1").unwrap(),
            realm_id: realm_id(),
            url: "https://receiver.example/events".to_string(),
            secret: WebhookSecret::new("secret").unwrap(),
            enabled: true,
            event_types: vec!["*".to_string()],
            include_representation: false,
            created_by: None,
            created_at: Utc::now(),
        }
    }

    fn event() -> WebhookEvent {
        let event = Event {
            id: EventId::new("event-1").unwrap(),
            realm_id: realm_id(),
            event_time: Utc::now(),
            event_type: EventType::Register,
            ip_address: None,
            client_id: None,
            user_id: None,
            session_id: None,
            error: None,
            details: Default::default(),
        };
        WebhookEvent::from_user_event(&event, "demo", None)
    }

    #[tokio::test]
    pub async fn outbox_is_idempotent_and_excludes_competing_workers() {
        let storage = InMemoryStorage::new();
        storage.create_webhook_subscription(&realm_id(), &subscription()).await.unwrap();
        assert!(storage
            .enqueue_webhook_delivery(&realm_id(), &subscription().id, &event())
            .await
            .unwrap());
        assert!(!storage
            .enqueue_webhook_delivery(&realm_id(), &subscription().id, &event())
            .await
            .unwrap());

        let first = storage
            .claim_webhook_deliveries("worker-1", 10, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        assert!(storage
            .claim_webhook_deliveries("worker-2", 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty());
        let id = first[0].delivery.id.clone();
        let first_lease = first[0].delivery.lease_owner.clone().unwrap();
        assert!(matches!(
            storage.replay_webhook_delivery(&realm_id(), &id).await,
            Err(IssuerdError::Conflict)
        ));
        storage.complete_webhook_delivery(&realm_id(), &id, &first_lease).await.unwrap();
        assert!(storage
            .claim_webhook_deliveries("worker-2", 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty());

        storage.replay_webhook_delivery(&realm_id(), &id).await.unwrap();
        let replayed = storage
            .claim_webhook_deliveries("worker-2", 10, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].delivery.event_id, event().id);
        assert_ne!(replayed[0].delivery.lease_owner.as_deref(), Some(first_lease.as_str()));
        assert!(matches!(
            storage.complete_webhook_delivery(&realm_id(), &id, &first_lease).await,
            Err(IssuerdError::Conflict)
        ));
        assert_eq!(
            storage
                .list_webhook_deliveries(&realm_id(), None, &Pagination::default())
                .await
                .unwrap()[0]
                .status,
            WebhookDeliveryStatus::InProgress
        );
    }

    #[tokio::test]
    pub async fn failed_attempts_retry_dead_and_recover_expired_leases() {
        let storage = InMemoryStorage::new();
        storage.create_webhook_subscription(&realm_id(), &subscription()).await.unwrap();
        storage
            .enqueue_webhook_delivery(&realm_id(), &subscription().id, &event())
            .await
            .unwrap();
        let claimed =
            storage.claim_webhook_deliveries("worker-1", 1, Duration::ZERO).await.unwrap();
        let id = claimed[0].delivery.id.clone();

        let recovered = storage
            .claim_webhook_deliveries("worker-2", 1, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].delivery.lease_owner.as_deref().unwrap().starts_with("worker-2:"));
        assert!(matches!(
            storage
                .fail_webhook_delivery(
                    &realm_id(),
                    &id,
                    claimed[0].delivery.lease_owner.as_deref().unwrap(),
                    "stale",
                    None,
                )
                .await,
            Err(IssuerdError::Conflict)
        ));
        storage
            .fail_webhook_delivery(
                &realm_id(),
                &id,
                recovered[0].delivery.lease_owner.as_deref().unwrap(),
                "temporary",
                Some(Utc::now() - chrono::Duration::seconds(1)),
            )
            .await
            .unwrap();
        let retried = storage
            .claim_webhook_deliveries("worker-3", 1, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(retried[0].delivery.attempts, 1);
        storage
            .fail_webhook_delivery(
                &realm_id(),
                &id,
                retried[0].delivery.lease_owner.as_deref().unwrap(),
                "permanent",
                None,
            )
            .await
            .unwrap();
        assert!(storage
            .claim_webhook_deliveries("worker-4", 1, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty());
        let history = storage
            .list_webhook_deliveries(&realm_id(), None, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(history[0].status, WebhookDeliveryStatus::Dead);
    }

    #[tokio::test]
    pub async fn disabled_subscriptions_are_not_claimed_and_snapshots_restore_state() {
        let storage = InMemoryStorage::new();
        let mut subscription = subscription();
        subscription.enabled = false;
        storage.create_webhook_subscription(&realm_id(), &subscription).await.unwrap();
        storage
            .enqueue_webhook_delivery(&realm_id(), &subscription.id, &event())
            .await
            .unwrap();
        assert!(storage
            .claim_webhook_deliveries("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty());

        let (subscriptions, deliveries, next_sequence) = storage.webhooks.snapshot();
        let restored = InMemoryStorage::new();
        restored.webhooks.restore(subscriptions, deliveries, next_sequence);
        assert_eq!(restored.list_webhook_subscriptions(&realm_id()).await.unwrap().len(), 1);
        assert_eq!(
            restored
                .list_webhook_deliveries(&realm_id(), None, &Pagination::default())
                .await
                .unwrap()
                .len(),
            1
        );
        restored
            .webhooks
            .subscriptions
            .get_mut(&(realm_id(), subscription.id.clone()))
            .unwrap()
            .enabled = true;
        let claimed = restored
            .claim_webhook_deliveries("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(claimed[0].delivery.sequence, 1);
    }
}
