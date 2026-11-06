ALTER TABLE realms ADD COLUMN events_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN events_expiration_secs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN admin_events_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN include_representations INTEGER NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN events_listeners TEXT NOT NULL DEFAULT '["logging"]';
ALTER TABLE realms ADD COLUMN not_before INTEGER NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN default_groups TEXT NOT NULL DEFAULT '[]';
ALTER TABLE realms ADD COLUMN browser_flow TEXT;
ALTER TABLE realms ADD COLUMN direct_grant_flow TEXT;
ALTER TABLE realms ADD COLUMN reset_credentials_flow TEXT;
ALTER TABLE realms ADD COLUMN first_broker_login_flow TEXT;
ALTER TABLE realms ADD COLUMN registration_flow TEXT;

ALTER TABLE user_sessions ADD COLUMN impersonator BLOB;
