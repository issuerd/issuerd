CREATE TABLE identity_provider_links (
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_alias TEXT NOT NULL,
    external_subject TEXT NOT NULL,
    external_username TEXT,
    stored_refresh_token TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (realm_id, provider_alias, external_subject),
    UNIQUE (realm_id, user_id, provider_alias),
    CONSTRAINT fk_idp_links_provider
        FOREIGN KEY (realm_id, provider_alias)
        REFERENCES identity_providers (realm_id, alias) ON DELETE CASCADE
);
