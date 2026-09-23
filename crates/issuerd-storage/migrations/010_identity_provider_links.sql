-- Identity brokering account links.
--
-- One row per (user, identity provider) link: which external subject at which
-- provider maps to which local user. Uniqueness:
--   - (realm_id, provider_alias, external_subject) — an external account maps
--     to exactly one local user;
--   - (realm_id, user_id, provider_alias) — a local user holds at most one
--     link per provider.
CREATE TABLE identity_provider_links (
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_alias TEXT NOT NULL,
    external_subject TEXT NOT NULL,
    external_username TEXT,
    stored_refresh_token TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, provider_alias, external_subject),
    UNIQUE (realm_id, user_id, provider_alias),
    -- Deleting the provider removes its account links.
    CONSTRAINT fk_idp_links_provider
        FOREIGN KEY (realm_id, provider_alias)
        REFERENCES identity_providers (realm_id, alias) ON DELETE CASCADE
);
