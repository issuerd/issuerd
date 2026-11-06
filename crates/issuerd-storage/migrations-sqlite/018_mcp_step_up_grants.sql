CREATE TABLE mcp_step_up_grants (
    token_jti TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    operation_hash TEXT NOT NULL,
    canonicalization_version INTEGER NOT NULL,
    realm_id BLOB NOT NULL,
    client_id TEXT NOT NULL,
    subject_user_id BLOB NOT NULL,
    resource TEXT NOT NULL,
    tool TEXT NOT NULL,
    mutation_json TEXT NOT NULL,
    origin_access_token_jti TEXT NOT NULL,
    dpop_jkt TEXT NOT NULL,
    approval_auth_time INTEGER NOT NULL,
    approval_acr TEXT,
    approval_amr TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'executing', 'succeeded', 'failed_definite', 'outcome_unknown')),
    result_json TEXT,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX mcp_step_up_grants_status_expires_idx
    ON mcp_step_up_grants (status, expires_at);
