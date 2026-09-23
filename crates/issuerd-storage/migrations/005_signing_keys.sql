CREATE TABLE IF NOT EXISTS signing_keys (
    kid         TEXT PRIMARY KEY,
    alg         TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    private_der BYTEA NOT NULL,
    public_jwk  JSONB NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT TRUE
);
