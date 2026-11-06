ALTER TABLE users ADD COLUMN username_search TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN email_search TEXT;

CREATE INDEX idx_users_realm_username_search ON users(realm_id, username_search);
CREATE INDEX idx_users_realm_email_search ON users(realm_id, email_search);
