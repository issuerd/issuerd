// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// PostgreSQL webhook subscriptions and transactional outbox operations.

use std::time::Duration;

use chrono::{DateTime, Utc};
use issuerd_core::*;
use sqlx::{PgPool, Postgres, QueryBuilder, Transaction};

use crate::db_types::to_uuid;
use crate::postgres::PostgresStorage;

#[derive(sqlx::FromRow)]
struct PgWebhookSubscription {
    id: uuid::Uuid,
    realm_id: uuid::Uuid,
    url: String,
    secret: String,
    enabled: bool,
    event_types: serde_json::Value,
    include_representation: bool,
    created_by: Option<uuid::Uuid>,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct PgWebhookDelivery {
    sequence: i64,
    id: uuid::Uuid,
    realm_id: uuid::Uuid,
    subscription_id: uuid::Uuid,
    event_id: uuid::Uuid,
    payload: String,
    status: String,
    attempts: i32,
    next_attempt_at: DateTime<Utc>,
    lease_owner: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
}

fn subscription_from_row(row: PgWebhookSubscription) -> Result<WebhookSubscription, IssuerdError> {
    Ok(WebhookSubscription {
        id: WebhookSubscriptionId::new(row.id.to_string())?,
        realm_id: RealmId::new(row.realm_id.to_string())?,
        url: row.url,
        secret: WebhookSecret::new(row.secret)?,
        enabled: row.enabled,
        event_types: serde_json::from_value(row.event_types)
            .map_err(|e| IssuerdError::ServerError(format!("webhook filters: {e}")))?,
        include_representation: row.include_representation,
        created_by: row.created_by.map(|id| UserId::new(id.to_string())).transpose()?,
        created_at: row.created_at,
    })
}

fn delivery_from_row(row: PgWebhookDelivery) -> Result<WebhookDelivery, IssuerdError> {
    let status = match row.status.as_str() {
        "pending" => WebhookDeliveryStatus::Pending,
        "in_progress" => WebhookDeliveryStatus::InProgress,
        "delivered" => WebhookDeliveryStatus::Delivered,
        "dead" => WebhookDeliveryStatus::Dead,
        other => {
            return Err(IssuerdError::ServerError(format!(
                "unknown webhook delivery status: {other}"
            )))
        }
    };
    Ok(WebhookDelivery {
        sequence: row.sequence,
        id: WebhookDeliveryId::new(row.id.to_string())?,
        subscription_id: WebhookSubscriptionId::new(row.subscription_id.to_string())?,
        event_id: EventId::new(row.event_id.to_string())?,
        payload: row.payload,
        status,
        attempts: u32::try_from(row.attempts)
            .map_err(|_| IssuerdError::ServerError("negative webhook attempts".into()))?,
        next_attempt_at: row.next_attempt_at,
        lease_owner: row.lease_owner,
        lease_expires_at: row.lease_expires_at,
        last_error: row.last_error,
        created_at: row.created_at,
        updated_at: row.updated_at,
        delivered_at: row.delivered_at,
    })
}

fn status_name(status: WebhookDeliveryStatus) -> &'static str {
    match status {
        WebhookDeliveryStatus::Pending => "pending",
        WebhookDeliveryStatus::InProgress => "in_progress",
        WebhookDeliveryStatus::Delivered => "delivered",
        WebhookDeliveryStatus::Dead => "dead",
    }
}

async fn select_subscription(
    pool: &PgPool,
    realm: &RealmId,
    id: &WebhookSubscriptionId,
) -> Result<Option<WebhookSubscription>, IssuerdError> {
    sqlx::query_as::<_, PgWebhookSubscription>(
        "SELECT * FROM webhook_subscriptions WHERE realm_id = $1 AND id = $2",
    )
    .bind(to_uuid(realm.as_ref())?)
    .bind(to_uuid(id.as_ref())?)
    .fetch_optional(pool)
    .await
    .map_err(crate::postgres::sqlx_err)?
    .map(subscription_from_row)
    .transpose()
}

async fn select_subscription_tx(
    tx: &mut Transaction<'_, Postgres>,
    realm: &RealmId,
    id: &WebhookSubscriptionId,
) -> Result<WebhookSubscription, IssuerdError> {
    let row = sqlx::query_as::<_, PgWebhookSubscription>(
        "SELECT * FROM webhook_subscriptions WHERE realm_id = $1 AND id = $2",
    )
    .bind(to_uuid(realm.as_ref())?)
    .bind(to_uuid(id.as_ref())?)
    .fetch_one(&mut **tx)
    .await
    .map_err(crate::postgres::sqlx_err)?;
    subscription_from_row(row)
}

impl PostgresStorage {
    pub async fn create_webhook_subscription(
        &self,
        realm: &RealmId,
        subscription: &WebhookSubscription,
    ) -> Result<(), IssuerdError> {
        subscription.validate()?;
        if subscription.realm_id != *realm {
            return Err(IssuerdError::InvalidRequest("webhook subscription realm mismatch".into()));
        }
        let result = sqlx::query(
            "INSERT INTO webhook_subscriptions (
                id, realm_id, url, secret, enabled, event_types,
                include_representation, created_by, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO NOTHING",
        )
        .bind(to_uuid(subscription.id.as_ref())?)
        .bind(to_uuid(realm.as_ref())?)
        .bind(&subscription.url)
        .bind(subscription.secret.as_str())
        .bind(subscription.enabled)
        .bind(
            serde_json::to_value(&subscription.event_types)
                .map_err(|e| IssuerdError::ServerError(format!("webhook filters: {e}")))?,
        )
        .bind(subscription.include_representation)
        .bind(subscription.created_by.as_ref().map(|id| to_uuid(id.as_ref())).transpose()?)
        .bind(subscription.created_at)
        .execute(self.pool())
        .await
        .map_err(crate::postgres::sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::Conflict);
        }
        Ok(())
    }

    pub async fn get_webhook_subscription(
        &self,
        realm: &RealmId,
        id: &WebhookSubscriptionId,
    ) -> Result<Option<WebhookSubscription>, IssuerdError> {
        select_subscription(self.pool(), realm, id).await
    }

    pub async fn list_webhook_subscriptions(
        &self,
        realm: &RealmId,
    ) -> Result<Vec<WebhookSubscription>, IssuerdError> {
        sqlx::query_as::<_, PgWebhookSubscription>(
            "SELECT * FROM webhook_subscriptions WHERE realm_id = $1 ORDER BY created_at, id",
        )
        .bind(to_uuid(realm.as_ref())?)
        .fetch_all(self.pool())
        .await
        .map_err(crate::postgres::sqlx_err)?
        .into_iter()
        .map(subscription_from_row)
        .collect()
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
        let result = sqlx::query(
            "UPDATE webhook_subscriptions SET
                url = $3, secret = $4, enabled = $5, event_types = $6,
                include_representation = $7, created_by = $8, created_at = $9
            WHERE realm_id = $1 AND id = $2",
        )
        .bind(to_uuid(realm.as_ref())?)
        .bind(to_uuid(subscription.id.as_ref())?)
        .bind(&subscription.url)
        .bind(subscription.secret.as_str())
        .bind(subscription.enabled)
        .bind(
            serde_json::to_value(&subscription.event_types)
                .map_err(|e| IssuerdError::ServerError(format!("webhook filters: {e}")))?,
        )
        .bind(subscription.include_representation)
        .bind(subscription.created_by.as_ref().map(|id| to_uuid(id.as_ref())).transpose()?)
        .bind(subscription.created_at)
        .execute(self.pool())
        .await
        .map_err(crate::postgres::sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    pub async fn delete_webhook_subscription(
        &self,
        realm: &RealmId,
        id: &WebhookSubscriptionId,
    ) -> Result<(), IssuerdError> {
        sqlx::query("DELETE FROM webhook_subscriptions WHERE realm_id = $1 AND id = $2")
            .bind(to_uuid(realm.as_ref())?)
            .bind(to_uuid(id.as_ref())?)
            .execute(self.pool())
            .await
            .map_err(crate::postgres::sqlx_err)?;
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
        if select_subscription(self.pool(), realm, subscription_id).await?.is_none() {
            return Err(IssuerdError::NotFound);
        }
        let now = Utc::now();
        let inserted = sqlx::query_scalar::<_, i64>(
            "INSERT INTO webhook_deliveries (
                id, subscription_id, event_id, payload, status, attempts,
                next_attempt_at, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, 'pending', 0, $5, $5, $5)
            ON CONFLICT (subscription_id, event_id) DO NOTHING RETURNING sequence",
        )
        .bind(to_uuid(&issuerd_core::utils::generate_id())?)
        .bind(to_uuid(subscription_id.as_ref())?)
        .bind(to_uuid(event.id.as_ref())?)
        .bind(
            serde_json::to_string(event)
                .map_err(|e| IssuerdError::ServerError(format!("webhook payload: {e}")))?,
        )
        .bind(now)
        .fetch_optional(self.pool())
        .await
        .map_err(crate::postgres::sqlx_err)?;
        Ok(inserted.is_some())
    }

    pub async fn claim_webhook_deliveries(
        &self,
        worker_id: &str,
        limit: u32,
        lease_duration: Duration,
    ) -> Result<Vec<WebhookDeliveryTask>, IssuerdError> {
        let lease_duration = chrono::Duration::from_std(lease_duration)
            .map_err(|e| IssuerdError::InvalidRequest(format!("invalid webhook lease: {e}")))?;
        let now = Utc::now();
        let lease_expires_at = now.checked_add_signed(lease_duration).ok_or_else(|| {
            IssuerdError::InvalidRequest("webhook lease overflows timestamp".into())
        })?;
        let mut tx = self.pool().begin().await.map_err(crate::postgres::sqlx_err)?;
        sqlx::query(
            "UPDATE webhook_deliveries SET
                status = 'pending', lease_owner = NULL, lease_expires_at = NULL, updated_at = $1
            WHERE status = 'in_progress' AND lease_expires_at <= $1",
        )
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(crate::postgres::sqlx_err)?;
        let rows = sqlx::query_as::<_, PgWebhookDelivery>(
            "SELECT d.*, s.realm_id FROM webhook_deliveries d
            JOIN webhook_subscriptions s ON s.id = d.subscription_id
            WHERE d.status = 'pending' AND d.next_attempt_at <= $1 AND s.enabled = TRUE
            ORDER BY d.sequence LIMIT $2 FOR UPDATE OF d SKIP LOCKED",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await
        .map_err(crate::postgres::sqlx_err)?;
        let mut tasks = Vec::with_capacity(rows.len());
        for row in rows {
            let realm = RealmId::new(row.realm_id.to_string())?;
            let id = WebhookDeliveryId::new(row.id.to_string())?;
            let subscription_id = WebhookSubscriptionId::new(row.subscription_id.to_string())?;
            sqlx::query(
                "UPDATE webhook_deliveries SET
                    status = 'in_progress', lease_owner = $2, lease_expires_at = $3, updated_at = $4
                WHERE id = $1",
            )
            .bind(row.id)
            .bind(worker_id)
            .bind(lease_expires_at)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(crate::postgres::sqlx_err)?;
            let mut delivery = delivery_from_row(row)?;
            delivery.status = WebhookDeliveryStatus::InProgress;
            delivery.lease_owner = Some(worker_id.to_string());
            delivery.lease_expires_at = Some(lease_expires_at);
            delivery.updated_at = now;
            let subscription = select_subscription_tx(&mut tx, &realm, &subscription_id).await?;
            tasks.push(WebhookDeliveryTask {
                delivery,
                subscription,
            });
            let _ = id;
        }
        tx.commit().await.map_err(crate::postgres::sqlx_err)?;
        Ok(tasks)
    }

    pub async fn complete_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
    ) -> Result<(), IssuerdError> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE webhook_deliveries SET
                status = 'delivered', lease_owner = NULL, lease_expires_at = NULL,
                last_error = NULL, updated_at = $3, delivered_at = $3
            WHERE id = $1 AND subscription_id IN (
                SELECT id FROM webhook_subscriptions WHERE realm_id = $2
            )",
        )
        .bind(to_uuid(id.as_ref())?)
        .bind(to_uuid(realm.as_ref())?)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(crate::postgres::sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    pub async fn fail_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
        error: &str,
        next_attempt_at: Option<DateTime<Utc>>,
    ) -> Result<(), IssuerdError> {
        let status = if next_attempt_at.is_some() {
            WebhookDeliveryStatus::Pending
        } else {
            WebhookDeliveryStatus::Dead
        };
        let result = sqlx::query(
            "UPDATE webhook_deliveries SET
                status = $3, attempts = attempts + 1,
                next_attempt_at = COALESCE($4, next_attempt_at),
                lease_owner = NULL, lease_expires_at = NULL,
                last_error = $5, updated_at = $6
            WHERE id = $1 AND subscription_id IN (
                SELECT id FROM webhook_subscriptions WHERE realm_id = $2
            )",
        )
        .bind(to_uuid(id.as_ref())?)
        .bind(to_uuid(realm.as_ref())?)
        .bind(status_name(status))
        .bind(next_attempt_at)
        .bind(error)
        .bind(Utc::now())
        .execute(self.pool())
        .await
        .map_err(crate::postgres::sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    pub async fn replay_webhook_delivery(
        &self,
        realm: &RealmId,
        id: &WebhookDeliveryId,
    ) -> Result<(), IssuerdError> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE webhook_deliveries SET
                status = 'pending', attempts = 0, next_attempt_at = $3,
                lease_owner = NULL, lease_expires_at = NULL, last_error = NULL,
                updated_at = $3, delivered_at = NULL
            WHERE id = $1 AND subscription_id IN (
                SELECT id FROM webhook_subscriptions WHERE realm_id = $2
            )",
        )
        .bind(to_uuid(id.as_ref())?)
        .bind(to_uuid(realm.as_ref())?)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(crate::postgres::sqlx_err)?;
        if result.rows_affected() == 0 {
            return Err(IssuerdError::NotFound);
        }
        Ok(())
    }

    pub async fn list_webhook_deliveries(
        &self,
        realm: &RealmId,
        subscription_id: Option<WebhookSubscriptionId>,
        pagination: &Pagination,
    ) -> Result<Vec<WebhookDelivery>, IssuerdError> {
        let mut query = QueryBuilder::<Postgres>::new(
            "SELECT d.*, s.realm_id FROM webhook_deliveries d
            JOIN webhook_subscriptions s ON s.id = d.subscription_id WHERE s.realm_id = ",
        );
        query.push_bind(to_uuid(realm.as_ref())?);
        if let Some(id) = subscription_id {
            query.push(" AND d.subscription_id = ");
            query.push_bind(to_uuid(id.as_ref())?);
        }
        query
            .push(" ORDER BY d.sequence DESC OFFSET ")
            .push_bind(pagination.first.max(0))
            .push(" LIMIT ")
            .push_bind(pagination.max.max(0));
        query
            .build_query_as::<PgWebhookDelivery>()
            .fetch_all(self.pool())
            .await
            .map_err(crate::postgres::sqlx_err)?
            .into_iter()
            .map(delivery_from_row)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription(realm: &RealmId) -> WebhookSubscription {
        WebhookSubscription {
            id: WebhookSubscriptionId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm.clone(),
            url: "https://receiver.example/events".to_string(),
            secret: WebhookSecret::new("secret").unwrap(),
            enabled: true,
            event_types: vec!["*".to_string()],
            include_representation: false,
            created_by: None,
            created_at: Utc::now(),
        }
    }

    fn event(realm: &RealmId) -> WebhookEvent {
        WebhookEvent::from_user_event(
            &Event {
                id: EventId::new(issuerd_core::utils::generate_id()).unwrap(),
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
        )
    }

    #[tokio::test]
    async fn postgres_webhook_outbox_lifecycle() {
        let docker_available = std::process::Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !docker_available {
            eprintln!("skipping postgres_webhook_outbox_lifecycle: docker unavailable");
            return;
        }
        use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt};
        let image = GenericImage::new("postgres", "15-alpine")
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_DB", "test");
        let container = image.start().await.expect("postgres container start");
        let host = container.get_host().await.expect("container host");
        let port = container.get_host_port_ipv4(5432).await.expect("container port");
        let url = format!("postgres://postgres:postgres@{host}:{port}/test");
        let storage = PostgresStorage::connect(&url).await.unwrap();
        storage.run_migrations().await.unwrap();
        let realm = RealmId::new(issuerd_core::utils::generate_id()).unwrap();
        let realm_model = Realm {
            id: realm.clone(),
            name: RealmName::new("webhook-test").unwrap(),
            ..Realm::default()
        };
        storage.create_realm(&realm_model).await.unwrap();
        let subscription = subscription(&realm);
        storage.create_webhook_subscription(&realm, &subscription).await.unwrap();
        let event = event(&realm);

        assert!(storage
            .enqueue_webhook_delivery(&realm, &subscription.id, &event)
            .await
            .unwrap());
        assert!(!storage
            .enqueue_webhook_delivery(&realm, &subscription.id, &event)
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

        storage
            .fail_webhook_delivery(
                &realm,
                &id,
                "temporary",
                Some(Utc::now() - chrono::Duration::seconds(1)),
            )
            .await
            .unwrap();
        let retried =
            storage.claim_webhook_deliveries("worker-2", 10, Duration::ZERO).await.unwrap();
        assert_eq!(retried[0].delivery.attempts, 1);
        let recovered = storage
            .claim_webhook_deliveries("worker-3", 10, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(recovered[0].delivery.lease_owner.as_deref(), Some("worker-3"));
        storage.fail_webhook_delivery(&realm, &id, "permanent", None).await.unwrap();
        assert!(storage
            .claim_webhook_deliveries("worker-4", 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty());

        storage.replay_webhook_delivery(&realm, &id).await.unwrap();
        let replayed = storage
            .claim_webhook_deliveries("worker-5", 10, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(replayed[0].delivery.attempts, 0);
        storage.complete_webhook_delivery(&realm, &id).await.unwrap();
        let history = storage
            .list_webhook_deliveries(&realm, None, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, WebhookDeliveryStatus::Delivered);

        storage.delete_webhook_subscription(&realm, &subscription.id).await.unwrap();
        assert!(storage
            .list_webhook_deliveries(&realm, None, &Pagination::default())
            .await
            .unwrap()
            .is_empty());
        storage.close().await;
        drop(storage);
        drop(container);
    }
}
