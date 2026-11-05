ALTER TABLE realms ADD COLUMN internationalization_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN supported_locales TEXT NOT NULL DEFAULT '[]';
ALTER TABLE realms ADD COLUMN default_locale TEXT;
