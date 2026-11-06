CREATE TABLE signing_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    created_at TEXT NOT NULL,
    private_der BLOB,
    public_jwk TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
