-- Realm-scoped webhook subscriptions and durable at-least-once deliveries.
-- Payload is TEXT intentionally: the exact serialized bytes are signed and sent.

CREATE TABLE webhook_subscriptions (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    event_types JSONB NOT NULL,
    include_representation BOOLEAN NOT NULL DEFAULT FALSE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX webhook_subscriptions_realm_idx
    ON webhook_subscriptions (realm_id, created_at, id);

CREATE TABLE webhook_deliveries (
    sequence BIGSERIAL PRIMARY KEY,
    id UUID NOT NULL UNIQUE,
    subscription_id UUID NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'in_progress', 'delivered', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    UNIQUE (subscription_id, event_id)
);

CREATE INDEX webhook_deliveries_due_idx
    ON webhook_deliveries (status, next_attempt_at, sequence);
CREATE INDEX webhook_deliveries_subscription_sequence_idx
    ON webhook_deliveries (subscription_id, sequence DESC);
CREATE INDEX webhook_deliveries_lease_idx
    ON webhook_deliveries (status, lease_expires_at);
