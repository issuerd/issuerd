-- User self-service — separate idle timeout for "remember me"
-- sessions so remembered sessions can outlive interactive SSO sessions.
ALTER TABLE realms ADD COLUMN IF NOT EXISTS remember_me_session_idle_secs BIGINT NOT NULL DEFAULT 604800;
