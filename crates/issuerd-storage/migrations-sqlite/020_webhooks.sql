-- SQLite mirror of the PostgreSQL webhook outbox. UUIDs are 16-byte BLOBs;
-- timestamps are Unix milliseconds; payload TEXT preserves the exact signed bytes.

CREATE TABLE webhook_subscriptions (
    id BLOB PRIMARY KEY,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    event_types TEXT NOT NULL,
    include_representation INTEGER NOT NULL DEFAULT 0,
    created_by BLOB,
    created_at INTEGER NOT NULL
);

CREATE INDEX webhook_subscriptions_realm_idx
    ON webhook_subscriptions (realm_id, created_at, id);

CREATE TABLE webhook_deliveries (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE,
    subscription_id BLOB NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    event_id BLOB NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'in_progress', 'delivered', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    lease_owner TEXT,
    lease_expires_at INTEGER,
    last_error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    delivered_at INTEGER,
    UNIQUE (subscription_id, event_id)
);

CREATE INDEX webhook_deliveries_due_idx
    ON webhook_deliveries (status, next_attempt_at, sequence);
CREATE INDEX webhook_deliveries_subscription_sequence_idx
    ON webhook_deliveries (subscription_id, sequence DESC);
CREATE INDEX webhook_deliveries_lease_idx
    ON webhook_deliveries (status, lease_expires_at);
