// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Realm webhook subscription administration and delivery replay.

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use issuerd_core::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::PaginationQueryParams,
    error::AdminApiError,
    state::AdminApiState,
};

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebhookSubscriptionRepresentation {
    pub id: String,
    pub url: String,
    pub enabled: bool,
    pub event_types: Vec<String>,
    pub include_representation: bool,
    pub created_by: Option<String>,
    pub created_at: String,
}

impl From<WebhookSubscription> for WebhookSubscriptionRepresentation {
    fn from(subscription: WebhookSubscription) -> Self {
        Self {
            id: subscription.id.to_string(),
            url: subscription.url,
            enabled: subscription.enabled,
            event_types: subscription.event_types,
            include_representation: subscription.include_representation,
            created_by: subscription.created_by.map(|id| id.to_string()),
            created_at: subscription.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebhookSubscriptionCreateRequest {
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub event_types: Option<Vec<String>>,
    #[serde(default)]
    pub include_representation: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebhookSubscriptionUpdateRequest {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub event_types: Option<Vec<String>>,
    #[serde(default)]
    pub include_representation: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebhookDeliveryRepresentation {
    pub sequence: i64,
    pub id: String,
    pub event_id: String,
    pub status: WebhookDeliveryStatus,
    pub attempts: u32,
    pub next_attempt_at: String,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub delivered_at: Option<String>,
}

impl From<WebhookDelivery> for WebhookDeliveryRepresentation {
    fn from(delivery: WebhookDelivery) -> Self {
        Self {
            sequence: delivery.sequence,
            id: delivery.id.to_string(),
            event_id: delivery.event_id.to_string(),
            status: delivery.status,
            attempts: delivery.attempts,
            next_attempt_at: delivery.next_attempt_at.to_rfc3339(),
            last_error: delivery.last_error,
            created_at: delivery.created_at.to_rfc3339(),
            updated_at: delivery.updated_at.to_rfc3339(),
            delivered_at: delivery.delivered_at.map(|time| time.to_rfc3339()),
        }
    }
}

fn validate_url(value: &str) -> Result<(), AdminApiError> {
    if value.len() > 2048 {
        return Err(AdminApiError::BadRequest("webhook URL exceeds 2048 bytes".into()));
    }
    let url = url::Url::parse(value)
        .map_err(|error| AdminApiError::BadRequest(format!("invalid webhook URL: {error}")))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(AdminApiError::BadRequest("webhook URL must be an absolute HTTPS URL".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AdminApiError::BadRequest("webhook URL must not contain userinfo".into()));
    }
    if url.fragment().is_some() {
        return Err(AdminApiError::BadRequest("webhook URL must not contain a fragment".into()));
    }
    Ok(())
}

fn subscription_id(value: &str) -> Result<WebhookSubscriptionId, AdminApiError> {
    uuid::Uuid::parse_str(value)
        .map_err(|_| AdminApiError::BadRequest("invalid webhook subscription UUID".into()))?;
    WebhookSubscriptionId::new(value).map_err(AdminApiError::from)
}

fn delivery_id(value: &str) -> Result<WebhookDeliveryId, AdminApiError> {
    uuid::Uuid::parse_str(value)
        .map_err(|_| AdminApiError::BadRequest("invalid webhook delivery UUID".into()))?;
    WebhookDeliveryId::new(value).map_err(AdminApiError::from)
}

async fn load_realm(state: &AdminApiState, name: &str) -> Result<Realm, AdminApiError> {
    state.storage.get_realm_by_name(name).await?.ok_or(AdminApiError::NotFound)
}

async fn find_delivery(
    state: &AdminApiState,
    realm: &RealmId,
    subscription: &WebhookSubscriptionId,
    delivery: &WebhookDeliveryId,
) -> Result<WebhookDelivery, AdminApiError> {
    state
        .storage
        .list_webhook_deliveries(realm, Some(subscription.clone()), &Pagination::new(0, i32::MAX))
        .await?
        .into_iter()
        .find(|candidate| candidate.id == *delivery)
        .ok_or(AdminApiError::NotFound)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/webhooks",
    tag = "Webhooks",
    summary = "List webhook subscriptions",
    description = "Lists realm webhook subscriptions without secret material. Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Subscriptions", body = Vec<WebhookSubscriptionRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_webhooks(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    Path(realm): Path<String>,
) -> Result<Json<Vec<WebhookSubscriptionRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let subscriptions = state
        .storage
        .list_webhook_subscriptions(&realm.id)
        .await?
        .into_iter()
        .map(WebhookSubscriptionRepresentation::from)
        .collect();
    Ok(Json(subscriptions))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/webhooks",
    tag = "Webhooks",
    summary = "Create a webhook subscription",
    description = "Creates a realm webhook subscription. The supplied secret is used for HMAC-SHA256 and is never returned. Requires `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(description = "Subscription", content = WebhookSubscriptionCreateRequest),
    responses(
        (status = 201, description = "Subscription created", body = WebhookSubscriptionRepresentation),
        (status = 400, description = "Invalid subscription", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn create_webhook(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    Path(realm): Path<String>,
    Json(body): Json<WebhookSubscriptionCreateRequest>,
) -> Result<(StatusCode, Json<WebhookSubscriptionRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    validate_url(&body.url)?;
    let secret = WebhookSecret::new(
        body.secret
            .ok_or_else(|| AdminApiError::BadRequest("webhook secret is required".into()))?,
    )?;
    let subscription = WebhookSubscription {
        id: WebhookSubscriptionId::new(issuerd_core::utils::generate_id())?,
        realm_id: realm.id.clone(),
        url: body.url,
        secret,
        enabled: body.enabled.unwrap_or(true),
        event_types: body.event_types.unwrap_or_else(|| vec!["*".to_string()]),
        include_representation: body.include_representation.unwrap_or(false),
        created_by: Some(auth.claims.sub.clone()),
        created_at: Utc::now(),
    };
    subscription.validate()?;
    state.storage.create_webhook_subscription(&realm.id, &subscription).await?;
    let id = subscription.id.to_string();
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Create,
        ResourceType::Realm,
        &format!("webhooks/{id}"),
        None,
    )
    .await;
    Ok((StatusCode::CREATED, Json(subscription.into())))
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/webhooks/{id}",
    tag = "Webhooks",
    summary = "Get a webhook subscription",
    description = "Gets one realm webhook subscription without secret material. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Subscription UUID"),
    ),
    responses(
        (status = 200, description = "Subscription", body = WebhookSubscriptionRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Subscription not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_webhook(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    Path((realm, id)): Path<(String, String)>,
) -> Result<Json<WebhookSubscriptionRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let subscription = state
        .storage
        .get_webhook_subscription(&realm.id, &subscription_id(&id)?)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    Ok(Json(subscription.into()))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/webhooks/{id}",
    tag = "Webhooks",
    summary = "Update a webhook subscription",
    description = "Updates selected fields of a webhook subscription, including optional secret rotation. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Subscription UUID"),
    ),
    request_body(description = "Updated fields", content = WebhookSubscriptionUpdateRequest),
    responses(
        (status = 200, description = "Subscription updated", body = WebhookSubscriptionRepresentation),
        (status = 400, description = "Invalid update", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Subscription not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn update_webhook(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    Path((realm, id)): Path<(String, String)>,
    Json(body): Json<WebhookSubscriptionUpdateRequest>,
) -> Result<Json<WebhookSubscriptionRepresentation>, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let id = subscription_id(&id)?;
    let mut subscription = state
        .storage
        .get_webhook_subscription(&realm.id, &id)
        .await?
        .ok_or(AdminApiError::NotFound)?;
    if let Some(url) = body.url {
        validate_url(&url)?;
        subscription.url = url;
    }
    if let Some(secret) = body.secret {
        subscription.secret = WebhookSecret::new(secret)?;
    }
    if let Some(enabled) = body.enabled {
        subscription.enabled = enabled;
    }
    if let Some(filters) = body.event_types {
        subscription.event_types = filters;
    }
    if let Some(include) = body.include_representation {
        subscription.include_representation = include;
    }
    subscription.validate()?;
    state.storage.update_webhook_subscription(&realm.id, &subscription).await?;
    let id = subscription.id.to_string();
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Update,
        ResourceType::Realm,
        &format!("webhooks/{id}"),
        None,
    )
    .await;
    Ok(Json(subscription.into()))
}

#[utoipa::path(
    delete,
    path = "/admin/realms/{realm}/webhooks/{id}",
    tag = "Webhooks",
    summary = "Delete a webhook subscription",
    description = "Deletes a webhook subscription and its delivery history. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Subscription UUID"),
    ),
    responses(
        (status = 204, description = "Subscription deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Subscription not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn delete_webhook(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    Path((realm, id)): Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let id = subscription_id(&id)?;
    if state.storage.get_webhook_subscription(&realm.id, &id).await?.is_none() {
        return Err(AdminApiError::NotFound);
    }
    state.storage.delete_webhook_subscription(&realm.id, &id).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Delete,
        ResourceType::Realm,
        &format!("webhooks/{id}"),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/webhooks/{id}/deliveries",
    tag = "Webhooks",
    summary = "List webhook deliveries",
    description = "Lists delivery status and retry metadata without event payloads or secrets. Requires `view-realm` or `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Subscription UUID"),
        PaginationQueryParams,
    ),
    responses(
        (status = 200, description = "Deliveries", body = Vec<WebhookDeliveryRepresentation>),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Subscription not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn list_webhook_deliveries(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    Path((realm, id)): Path<(String, String)>,
    Query(params): Query<PaginationQueryParams>,
) -> Result<Json<Vec<WebhookDeliveryRepresentation>>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let id = subscription_id(&id)?;
    if state.storage.get_webhook_subscription(&realm.id, &id).await?.is_none() {
        return Err(AdminApiError::NotFound);
    }
    let deliveries = state
        .storage
        .list_webhook_deliveries(&realm.id, Some(id), &Pagination::new(params.first, params.max))
        .await?
        .into_iter()
        .map(WebhookDeliveryRepresentation::from)
        .collect();
    Ok(Json(deliveries))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/webhooks/{id}/deliveries/{delivery_id}/replay",
    tag = "Webhooks",
    summary = "Replay a webhook delivery",
    description = "Returns a dead or already delivered event to the durable queue with the same event ID and idempotency key. Requires `manage-realm` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Subscription UUID"),
        ("delivery_id" = String, Path, description = "Delivery UUID"),
    ),
    responses(
        (status = 202, description = "Delivery queued", body = WebhookDeliveryRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Delivery not found", body = crate::error::AdminApiErrorResponse),
        (status = 409, description = "Delivery is already in progress", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn replay_webhook_delivery(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    Path((realm, id, delivery)): Path<(String, String, String)>,
) -> Result<(StatusCode, Json<WebhookDeliveryRepresentation>), AdminApiError> {
    require_roles(&auth, &["manage-realm"])?;
    let realm = load_realm(&state, &realm).await?;
    let subscription = subscription_id(&id)?;
    let delivery = delivery_id(&delivery)?;
    let current = find_delivery(&state, &realm.id, &subscription, &delivery).await?;
    if current.status == WebhookDeliveryStatus::InProgress {
        return Err(AdminApiError::Conflict);
    }
    state.storage.replay_webhook_delivery(&realm.id, &delivery).await?;
    let replayed = find_delivery(&state, &realm.id, &subscription, &delivery).await?;
    crate::audit::emit_admin_event(
        &state,
        &auth,
        &realm.id,
        OperationType::Action,
        ResourceType::Session,
        &format!("webhooks/{subscription}/deliveries/{delivery}/replay"),
        None,
    )
    .await;
    Ok((StatusCode::ACCEPTED, Json(replayed.into())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, response::Response, Router};
    use tower::ServiceExt;

    fn app(state: Arc<AdminApiState>) -> Router {
        crate::routes::admin_routes(state)
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        if body.is_empty() {
            serde_json::Value::Null
        } else {
            let text = String::from_utf8_lossy(&body);
            serde_json::from_str(&text)
                .unwrap_or_else(|_| serde_json::Value::String(text.into_owned()))
        }
    }

    async fn request(
        app: Router,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let body = body.map_or_else(Body::empty, |value| Body::from(value.to_string()));
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", "Bearer valid-token")
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        (status, response_json(response).await)
    }

    fn subscription(realm: &RealmId, filters: &[&str]) -> WebhookSubscription {
        WebhookSubscription {
            id: WebhookSubscriptionId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm.clone(),
            url: "https://receiver.example/events".to_string(),
            secret: WebhookSecret::new("secret").unwrap(),
            enabled: true,
            event_types: filters.iter().map(|value| value.to_string()).collect(),
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
            "master",
            None,
        )
    }

    #[tokio::test]
    async fn crud_masks_secrets_and_validates_input_and_roles() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = app(state.clone());
        let create = serde_json::json!({
            "url": "https://receiver.example/events",
            "secret": "initial-secret",
            "eventTypes": ["USER.REGISTER"]
        });
        let (status, created) =
            request(app.clone(), "POST", "/realms/master/webhooks", Some(create)).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert!(created.get("secret").is_none());
        let id = created["id"].as_str().unwrap();

        let (status, listed) = request(app.clone(), "GET", "/realms/master/webhooks", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert!(listed[0].get("secret").is_none());

        let (status, updated) = request(
            app.clone(),
            "PUT",
            &format!("/realms/master/webhooks/{id}"),
            Some(serde_json::json!({"enabled": false, "secret": "rotated-secret"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        let realm = RealmId::new("master").unwrap();
        let id_typed = WebhookSubscriptionId::new(id).unwrap();
        let stored = state
            .storage
            .get_webhook_subscription(&realm, &id_typed)
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.enabled);
        assert_eq!(stored.secret.as_str(), "rotated-secret");

        let (status, _) = request(
            app.clone(),
            "POST",
            "/realms/master/webhooks",
            Some(serde_json::json!({"url": "http://insecure.example", "secret": "secret"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = request(
            app.clone(),
            "POST",
            "/realms/master/webhooks",
            Some(serde_json::json!({"url": "https://receiver.example"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let read_only =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-realm").unwrap()
            ]);
        let (status, _) = request(
            crate::webhooks::tests::app(read_only),
            "POST",
            "/realms/master/webhooks",
            Some(serde_json::json!({"url": "https://receiver.example", "secret": "secret"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) =
            request(app.clone(), "DELETE", &format!("/realms/master/webhooks/{id}"), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, listed) = request(app, "GET", "/realms/master/webhooks", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(listed.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delivery_replay_checks_ownership_and_in_progress_state() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("manage-realm").unwrap()
            ]);
        let app = app(state.clone());
        let realm = RealmId::new("master").unwrap();
        let first = subscription(&realm, &["USER.REGISTER"]);
        let second = subscription(&realm, &["USER.REGISTER"]);
        state.storage.create_webhook_subscription(&realm, &first).await.unwrap();
        state.storage.create_webhook_subscription(&realm, &second).await.unwrap();
        state
            .storage
            .enqueue_webhook_delivery(&realm, &first.id, &event(&realm))
            .await
            .unwrap();
        let delivery = state
            .storage
            .list_webhook_deliveries(&realm, Some(first.id.clone()), &Pagination::default())
            .await
            .unwrap()[0]
            .id
            .clone();
        state
            .storage
            .fail_webhook_delivery(&realm, &delivery, "permanent", None)
            .await
            .unwrap();

        let deliveries_path = format!("/realms/master/webhooks/{}/deliveries", first.id);
        let (status, history) = request(app.clone(), "GET", &deliveries_path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(history.as_array().unwrap().len(), 1);
        assert_eq!(history[0]["status"], "dead");
        assert!(history[0].get("payload").is_none());

        let wrong_replay =
            format!("/realms/master/webhooks/{}/deliveries/{delivery}/replay", second.id);
        let (status, _) = request(app.clone(), "POST", &wrong_replay, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let replay = format!("/realms/master/webhooks/{}/deliveries/{delivery}/replay", first.id);
        let (status, replayed) = request(app.clone(), "POST", &replay, None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{replayed}");
        assert_eq!(replayed["status"], "pending");

        state
            .storage
            .claim_webhook_deliveries("worker-1", 1, std::time::Duration::from_secs(30))
            .await
            .unwrap();
        let (status, _) = request(app, "POST", &replay, None).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
}
