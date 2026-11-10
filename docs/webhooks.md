# Webhook event listeners

Realm-scoped webhooks deliver authentication and administration events to external systems over HTTPS. They are intended for audit pipelines, alerting, user provisioning, and downstream workflows that need an event after Issuerd has committed it.

## Delivery contract

- **At least once:** a receiver can see the same event more than once after a lost response, restart, or lease expiry. Exactly-once delivery is not claimed.
- Every event has a stable UUID, also sent as `Idempotency-Key` and `X-Issuerd-Event-Id`. Deduplicate using that value and the subscription ID.
- Deliveries are queued durably before any network I/O. Login and admin requests never wait for a receiver.
- Each `(subscription_id, event_id)` is unique. Retries and manual replay retain the same event ID and idempotency key.
- Subscription secrets are accepted only on create/update and are never returned by the API or logged. Protect database and snapshot backups as secret-bearing material.
- Payload `schemaVersion` is `1`. `kind` is `USER` or `ADMIN`; field names follow Keycloak where practical.
- `events_enabled` and `admin_events_enabled` continue to control local audit storage and the legacy logging listener. Webhook subscriptions have independent `enabled` flags and do not require local audit retention.

## Configure a subscription

Create a subscription through the Admin API with a `manage-realm` token:

```bash
curl -X POST "https://issuerd.example.com/admin/realms/myrealm/webhooks" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://receiver.example.com/issuerd-events",
    "secret": "replace-with-a-long-random-secret",
    "enabled": true,
    "eventTypes": ["USER.LOGIN", "USER.REGISTER", "ADMIN.USER.CREATE"],
    "includeRepresentation": false
  }'
```

The response contains the subscription UUID, filters, and creation metadata, but **not** the secret. Save the secret used for signing verification securely yourself.

Endpoints:

| Method | Path | Purpose | Required role |
|---|---|---|---|
| `GET` | `/admin/realms/{realm}/webhooks` | List subscriptions | `view-realm` or `manage-realm` |
| `POST` | `/admin/realms/{realm}/webhooks` | Create a subscription | `manage-realm` |
| `GET` | `/admin/realms/{realm}/webhooks/{id}` | Get one subscription | `view-realm` or `manage-realm` |
| `PUT` | `/admin/realms/{realm}/webhooks/{id}` | Update fields or rotate the secret | `manage-realm` |
| `DELETE` | `/admin/realms/{realm}/webhooks/{id}` | Delete a subscription and its deliveries | `manage-realm` |
| `GET` | `/admin/realms/{realm}/webhooks/{id}/deliveries` | Delivery status and retry metadata | `view-realm` or `manage-realm` |
| `POST` | `/admin/realms/{realm}/webhooks/{id}/deliveries/{delivery_id}/replay` | Requeue a delivery | `manage-realm` |

Create accepts `url`, `secret`, `enabled`, `eventTypes`, and `includeRepresentation`. Update accepts the same fields except that all are optional and preserve the previous value when omitted. The URL must be absolute HTTPS, without userinfo or a fragment. Secrets must be non-empty and are validated without being logged.

Delivery history contains `sequence`, `id`, `eventId`, `status`, `attempts`, `nextAttemptAt`, `lastError`, and timestamps. It deliberately excludes the event payload and secret material.

### Provisioning

The same subscription can be declared once in `provision.yaml`:

```yaml
webhooks:
  - realm: myrealm
    url: ${ISSUERD_WEBHOOK_URL}
    secret: ${ISSUERD_WEBHOOK_SECRET}
    enabled: true
    event_types:
      - USER.LOGIN
      - USER.REGISTER
      - ADMIN.USER.CREATE
    include_representation: false
```

`event_types` defaults to `["*"]`, `enabled` to `true`, and `include_representation` to `false`. Existing subscriptions with the same URL are skipped on subsequent provisioning runs. Old provision files without a `webhooks` field are unchanged.

## Filters

| Filter | Matches |
|---|---|
| `*` | Every user and admin event |
| `USER.*` | Every user event |
| `ADMIN.*` | Every admin event |
| `USER.LOGIN` | Successful interactive login |
| `USER.LOGIN_ERROR` | Failed login, including authorization/JAR/PAR failures |
| `USER.REGISTER` | Self-registration |
| `USER.LOGOUT` | Logout and token revocation |
| `ADMIN.USER.CREATE` | Administrator-created user |
| `ADMIN.CLIENT.UPDATE` | Client update |

Admin filters use `ADMIN.<RESOURCE_TYPE>.<OPERATION_TYPE>`. The operation is `CREATE`, `UPDATE`, `DELETE`, or `ACTION`. Self-registration and administrator-created users deliberately remain different event families; no duplicate `USER_CREATED` event is invented.

## Payloads

User events include:

```json
{
  "schemaVersion": 1,
  "id": "7a6f3d9c-...",
  "time": 1762800000123,
  "kind": "USER",
  "realmId": "realm-uuid",
  "realmName": "myrealm",
  "type": "LOGIN_ERROR",
  "clientId": "my-app",
  "userId": "user-uuid",
  "sessionId": "session-uuid",
  "ipAddress": "192.0.2.10",
  "error": "invalid_user_credentials",
  "details": {
    "username": "alice",
    "error": "invalid_user_credentials"
  }
}
```

Admin events include `operationType`, `resourceType`, `resourcePath`, optional `representation`, and `authDetails`:

```json
{
  "schemaVersion": 1,
  "id": "8b7e4a1f-...",
  "time": 1762800000456,
  "kind": "ADMIN",
  "realmId": "realm-uuid",
  "realmName": "myrealm",
  "operationType": "CREATE",
  "resourceType": "USER",
  "resourcePath": "users/user-uuid",
  "authDetails": {
    "realmId": "master-uuid",
    "realmName": "master",
    "clientId": "admin-cli",
    "userId": "admin-uuid"
  }
}
```

`time` is Unix time in milliseconds. `clientId` is the public OAuth client identifier, not the internal client UUID. `representation` is omitted by default and is emitted only when both the realm and the subscription permit it. Realm sector keys are redacted using the same rule as the Admin API.

## HMAC-SHA256 verification

Each request includes:

```text
Idempotency-Key: <event UUID>
X-Issuerd-Event-Id: <event UUID>
X-Issuerd-Signature: t=<unix-seconds>,v1=<lowercase-hex-hmac-sha256>
Content-Type: application/json
```

The signature input is exactly `<timestamp>.<raw-request-body>`, with no newline between them. Verify the HMAC over the raw bytes before parsing JSON. Also check the timestamp against a short acceptance window and deduplicate the event ID.

Example verifier:

```python
import hashlib
import hmac
import time


def verify(secret: str, timestamp: str, signature: str, body: bytes) -> bool:
    if not signature.startswith(f"t={timestamp},v1="):
        return False
    if abs(time.time() - int(timestamp)) > 300:
        return False
    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.{body.decode('utf-8')}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature, expected)
```

Retries generate a new timestamp and signature while preserving the event ID. A receiver should answer a duplicate successfully instead of applying the event again.

## Retry, dead letter, and replay

A background worker claims due deliveries with expiring leases and restores abandoned leases after a restart. Multiple nodes exclude each other through storage transactions.

- `2xx`: delivered.
- Transport failures, `408`, `425`, `429`, and `5xx`: exponential backoff with jitter. The default starts at one second, caps at 60 seconds, and allows at most eight failed attempts. `Retry-After` is honored and capped at one hour.
- Ordinary `4xx`: the delivery becomes `dead` instead of being retried forever.
- `in_progress` cannot be replayed and returns `409 Conflict`.

`POST .../replay` moves a dead or completed delivery back to `pending` with zero attempts, preserving the event ID and idempotency key. `lastError` and `deliveredAt` are cleared. A wrong subscription UUID returns `404` even when the delivery exists elsewhere in the realm.

## Outbound security

- HTTPS and certificate verification are mandatory. Additional private roots can be supplied with `[outbound_http] extra_ca_bundle`.
- Redirects are rejected. DNS resolution is pinned to the connection.
- Private, loopback, link-local, and other non-public addresses require the explicit `[outbound_http] allow_private_addresses = true` opt-in, intended only for trusted internal integrations and test rigs.
- Requests have a ten-second timeout. Responses are drained with a 64 KiB cap.
- URLs, payloads, and secrets are not written to application logs.

## Operational notes

PostgreSQL migration `019_webhooks.sql` and SQLite migration `020_webhooks.sql` add subscriptions and durable deliveries. In-memory and JSON backends implement the same semantics, with JSON snapshots preserving subscriptions, deliveries, and sequence state. SQLite remains single-node; multi-node delivery is supported only through shared PostgreSQL storage.

The durable outbox is not Redis Pub/Sub and does not depend on cache retention. Backup and restore procedures must include the webhook tables or JSON snapshot, since pending deliveries and subscription secrets live there.

Dynamic Java plugins are not loaded. The existing `EventListener` trait remains the in-process extension point, while webhooks are the supported out-of-process integration contract.
