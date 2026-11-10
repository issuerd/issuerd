# Webhook Event Listeners: Implementation Plan

Issue: https://github.com/issuerd/issuerd/issues/178

## Context and outcome

Issuerd already has an object-safe `EventListener` trait, but only the built-in
logging listener is registered. User-event listeners run inline in the request
path, admin events do not reach listeners, and several producers write directly
to storage. There is no retry, delivery recovery, or external subscription
contract.

The implementation will provide realm-scoped webhook subscriptions for both
user and admin events, Keycloak-shaped versioned payloads, HMAC-SHA256
signatures, event filtering, and durable at-least-once delivery that does not
perform network I/O in authentication or administration request paths.

## Public contract

- Delivery semantics are **at least once**. An event has a stable UUID, and each
  `(subscription_id, event_id)` pair is unique. Receivers must deduplicate using
  the event ID or `Idempotency-Key` header.
- Payloads are versioned with `schemaVersion = 1` and distinguish `USER` and
  `ADMIN` events. Field names follow Keycloak where practical (`time`, `type`,
  `realmId`, `realmName`, `clientId`, `operationType`, `resourceType`,
  `resourcePath`, `authDetails`). Internal storage models are not exposed.
- Filters support `*`, `USER.*`, `ADMIN.*`, `USER.LOGIN`, and compound admin
  filters such as `ADMIN.USER.CREATE`.
- Self-registration remains `USER.REGISTER`; an administrator creating a user is
  `ADMIN.USER.CREATE`. No parallel synthetic `USER_CREATED` taxonomy is added.
- Headers include `Idempotency-Key`, `X-Issuerd-Event-Id`, and
  `X-Issuerd-Signature: t=<unix>,v1=<hex-hmac-sha256>`. The signature input is
  `<timestamp>.<raw-body>`.
- Subscription secrets are write-only in API responses and never logged.
  Representations remain disabled by default and use the same redaction rules as
  the existing Admin API.
- Existing `events_enabled` and `admin_events_enabled` behavior is preserved for
  current storage and listeners. Webhook subscriptions have independent
  `enabled` flags, so local audit retention need not be enabled for delivery.

## Non-goals for this implementation

- No Java plugin ABI, dynamic Rust library loader, or JavaScript execution.
- No exactly-once claim, Kafka/NATS broker, or Redis Pub/Sub delivery queue.
- No new admin SPA surface in the initial implementation; CRUD is exposed via
  the Admin REST API and provisioning.
- No new event taxonomy beyond the required additive event types. Missing
  coverage is added only where a requested integration scenario lacks an event.

## Work stages and commit boundaries

### 1. Plan

Add this document and commit it independently.

### 2. Event and subscription vocabulary

Add additive core models for subscriptions, normalized webhook events,
deliveries, filters, and status values. Implement and test payload mapping,
filter matching, and signing input construction. Keep storage and transport out
of pure mapping code.

Commit: `Add webhook event and subscription models`

### 3. Durable storage and outbox

Add append-only `019_webhooks.sql` for PostgreSQL and `020_webhooks.sql` for SQLite. Subscription
rows hold realm ownership, endpoint, secret, enabled state, filters, and
representation policy. Delivery rows hold a monotonically increasing sequence,
event ID, payload, status, attempts, schedule, lease, and last error, with a
unique `(subscription_id, event_id)` constraint.

Extend `Storage` additively with subscription CRUD and outbox operations:
enqueue with insert-if-absent, claim due deliveries with expiring leases,
record success, schedule retry, mark dead, recover expired leases, and replay.
Use `FOR UPDATE SKIP LOCKED` on PostgreSQL and immediate transactions on SQLite.
Keep in-memory and JSON behavior semantically aligned and snapshots compatible.

Commit: `Add durable webhook subscriptions and outbox`

### 4. Unified event publication

Route OIDC, Admin API, dynamic registration, logout, and impersonation event
production through one dispatch path that publishes normalized events to
matching enabled subscriptions. Preserve current audit-storage behavior and the
existing logging listener. Wire `on_admin_event` where appropriate, but do not
silently change the meaning of current realm settings.

Publication follows the existing non-fatal audit behavior after the relevant
business mutation. Once committed, an outbox entry is delivered at least once;
atomicity between the business mutation and event creation is not claimed by
this listener-based implementation. No receiver network I/O happens in request
paths.

Commit: `Publish user and admin events to webhook outbox`

### 5. Background HTTPS delivery

Add a lifecycle-managed worker that claims due deliveries only after commit,
recovers stale leases, and sends bounded HTTPS POST requests outside request
paths. Reuse the outbound SSRF protections: HTTPS by default, DNS pinning, no
redirects, explicit private-address opt-in, connection/request timeouts, and a
small response-body cap.

Retry transport failures, 408, 429, and 5xx with exponential backoff and jitter;
honor bounded `Retry-After`. Ordinary 4xx responses become dead deliveries.
Expired leases and response-loss ambiguity can produce duplicates, which the
idempotency contract handles deliberately.

Commit: `Deliver webhooks asynchronously with durable retry`

### 6. Administration and operations

Add additive Admin REST CRUD under `/admin/realms/{realm}/webhooks`, plus
read-only delivery status and explicit replay. Never return secrets on reads.
Validate event filters, endpoint policy, and representation settings. Add
provisioning support with the same validation and no secret logging. Regenerate
OpenAPI and the web client SDK only as required by the API change.

Document configuration, payload/filter formats, signature verification,
idempotency, retry/dead-letter behavior, SSRF/private-address policy, and
operational recovery. Update `CHANGELOG.md` and relevant agent/architecture
notes to match the implemented behavior.

Commit: `Expose and document webhook administration`

### 7. Verification

Run focused unit and integration tests at every stage. Final coverage must
include:

- payload mapping, filter matching, HMAC verification, and secret masking;
- user registration, admin user creation, logout, and revocation event mapping;
- insert-if-absent and replay behavior on PostgreSQL, SQLite, memory, and JSON;
- retry/backoff, ordinary 4xx dead-lettering, `Retry-After`, stale-lease
  recovery, and manual replay;
- receiver downtime not delaying or failing login/admin requests;
- duplicate delivery after a lost response, with the same idempotency key;
- two workers competing for deliveries and preserving lease exclusion;
- HTTPS/SSRF/private-address enforcement and response-size limits;
- end-to-end delivery for admin, self-registration, broker/LDAP, logout, and
  revocation paths on PostgreSQL and SQLite.

Run `cargo test --locked --workspace`, strict clippy, fmt, dylint, cargo audit,
cargo deny, OpenAPI sync, and `git diff --check`. Commits are made only after the
relevant stage is green; no push or deployment is implied by this plan.
