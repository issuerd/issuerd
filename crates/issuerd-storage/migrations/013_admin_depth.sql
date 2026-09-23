-- Realm events configuration, not-before revocation cutoff, default
-- groups, flow bindings, and session impersonation. JSONB string lists follow
-- the convention used by clients.redirect_uris / realms.supported_locales.
ALTER TABLE realms ADD COLUMN IF NOT EXISTS events_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS events_expiration_secs BIGINT NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS admin_events_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS include_representations BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS events_listeners JSONB NOT NULL DEFAULT '["logging"]'::jsonb;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS not_before BIGINT NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS default_groups JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS browser_flow TEXT;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS direct_grant_flow TEXT;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS reset_credentials_flow TEXT;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS first_broker_login_flow TEXT;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS registration_flow TEXT;

-- Impersonation: the administrator user id that created the
-- session via impersonation; NULL for regular logins. TEXT (no FK) because
-- the impersonating admin may live in a different realm (e.g. master).
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS impersonator TEXT;
