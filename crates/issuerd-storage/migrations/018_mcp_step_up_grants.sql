-- Durable single-use grants for operation-bound MCP CIBA step-up.
-- Grant consumption, conditional target mutation, and execution outcome commit
-- in one transaction. Sensitive expected state is redacted before persistence.

CREATE TABLE mcp_step_up_grants (
    token_jti TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    operation_hash TEXT NOT NULL,
    canonicalization_version INTEGER NOT NULL,
    realm_id UUID NOT NULL,
    client_id TEXT NOT NULL,
    subject_user_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    tool TEXT NOT NULL,
    mutation_json JSONB NOT NULL,
    origin_access_token_jti TEXT NOT NULL,
    dpop_jkt TEXT NOT NULL,
    approval_auth_time BIGINT NOT NULL,
    approval_acr TEXT,
    approval_amr JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'executing', 'succeeded', 'failed_definite', 'outcome_unknown')),
    result_json JSONB,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX mcp_step_up_grants_status_expires_idx
    ON mcp_step_up_grants (status, expires_at);
