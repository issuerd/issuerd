-- Account security — user required actions + realm brute-force
-- detection and login-settings toggles.
ALTER TABLE users ADD COLUMN IF NOT EXISTS required_actions JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE realms ADD COLUMN IF NOT EXISTS brute_force_protected BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS max_login_failures INTEGER NOT NULL DEFAULT 5;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS wait_increment_secs INTEGER NOT NULL DEFAULT 60;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS max_failure_wait_secs INTEGER NOT NULL DEFAULT 900;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS lockout_duration_secs INTEGER NOT NULL DEFAULT 900;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS registration_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS reset_password_allowed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS remember_me_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS verify_email_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS login_with_email_allowed BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS duplicate_emails_allowed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS edit_username_allowed BOOLEAN NOT NULL DEFAULT true;
