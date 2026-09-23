-- Offline token semantics. Offline sessions (created when the
-- granted scopes include `offline_access`) back `typ: Offline` refresh
-- tokens, use the realm's offline_session_idle_timeout, and survive SSO
-- session expiry/logout. Existing rows are online sessions.
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS offline BOOLEAN NOT NULL DEFAULT FALSE;
