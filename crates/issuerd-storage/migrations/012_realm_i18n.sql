-- Realm internationalization settings. `supported_locales` stores a
-- JSON array of BCP 47 locale tags, matching the JSONB convention used by the
-- other string-list columns (e.g. clients.redirect_uris).
ALTER TABLE realms ADD COLUMN IF NOT EXISTS internationalization_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS supported_locales JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS default_locale TEXT;
