ALTER TABLE clients ADD COLUMN service_accounts_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN protocol_mappers TEXT NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN scope_mappings TEXT NOT NULL DEFAULT '{"realm_roles":[],"client_roles":{}}';

CREATE UNIQUE INDEX roles_realm_client_name_key
    ON roles (realm_id, COALESCE(client_id, X'00000000000000000000000000000000'), name);

CREATE TABLE client_scopes (
    id BLOB PRIMARY KEY,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    protocol TEXT NOT NULL DEFAULT 'openid-connect',
    attributes TEXT NOT NULL DEFAULT '{}',
    protocol_mappers TEXT NOT NULL DEFAULT '[]',
    scope_mappings TEXT NOT NULL DEFAULT '{"realm_roles":[],"client_roles":{}}',
    UNIQUE(realm_id, name)
);

CREATE TABLE client_client_scopes (
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id BLOB NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope_id BLOB NOT NULL REFERENCES client_scopes(id) ON DELETE CASCADE,
    is_default INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (client_id, scope_id)
);

CREATE TABLE realm_default_client_scopes (
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    scope_id BLOB NOT NULL REFERENCES client_scopes(id) ON DELETE CASCADE,
    is_default INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (realm_id, scope_id)
);

CREATE TABLE user_client_roles (
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BLOB NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (realm_id, user_id, role_id)
);
