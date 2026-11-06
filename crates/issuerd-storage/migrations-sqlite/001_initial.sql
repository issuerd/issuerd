CREATE TABLE realms (
    id BLOB PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    ssl_required TEXT NOT NULL DEFAULT 'external',
    password_policy TEXT,
    login_theme TEXT,
    email_theme TEXT,
    admin_theme TEXT,
    default_role TEXT,
    access_token_lifespan INTEGER NOT NULL DEFAULT 300,
    refresh_token_lifespan INTEGER NOT NULL DEFAULT 1800,
    sso_session_idle_timeout INTEGER NOT NULL DEFAULT 1800,
    sso_session_max_lifespan INTEGER NOT NULL DEFAULT 36000,
    offline_session_idle_timeout INTEGER NOT NULL DEFAULT 2592000,
    attributes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id BLOB PRIMARY KEY,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    email TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    first_name TEXT,
    last_name TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    federation_link TEXT,
    attributes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(realm_id, username)
);
CREATE INDEX idx_users_realm_email ON users(realm_id, email);

CREATE TABLE clients (
    id BLOB PRIMARY KEY,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    name TEXT,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    protocol TEXT NOT NULL DEFAULT 'openid-connect',
    public_client INTEGER NOT NULL DEFAULT 0,
    bearer_only INTEGER NOT NULL DEFAULT 0,
    client_authenticator_type TEXT NOT NULL DEFAULT 'client-secret',
    secret TEXT,
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    web_origins TEXT NOT NULL DEFAULT '[]',
    default_scopes TEXT NOT NULL DEFAULT '[]',
    optional_scopes TEXT NOT NULL DEFAULT '[]',
    consent_required INTEGER NOT NULL DEFAULT 0,
    full_scope_allowed INTEGER NOT NULL DEFAULT 1,
    attributes TEXT,
    UNIQUE(realm_id, client_id)
);

CREATE TABLE roles (
    id BLOB PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_role INTEGER NOT NULL DEFAULT 0,
    client_id BLOB REFERENCES clients(id) ON DELETE CASCADE,
    composite INTEGER NOT NULL DEFAULT 0,
    composites TEXT,
    attributes TEXT
);

CREATE TABLE groups (
    id BLOB PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    parent_id BLOB REFERENCES groups(id) ON DELETE CASCADE,
    attributes TEXT,
    realm_roles TEXT,
    client_roles TEXT,
    UNIQUE(realm_id, name)
);

CREATE TABLE credentials (
    id BLOB PRIMARY KEY,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL,
    user_label TEXT,
    created_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    secret_data BLOB,
    credential_data TEXT,
    priority INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_credentials_user ON credentials(realm_id, user_id, credential_type);

CREATE TABLE user_sessions (
    id BLOB PRIMARY KEY,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_username TEXT NOT NULL,
    ip_address TEXT,
    auth_method TEXT,
    remember_me INTEGER NOT NULL DEFAULT 0,
    started TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_session_refresh TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    auth_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_sessions_user ON user_sessions(realm_id, user_id);
CREATE INDEX idx_sessions_refresh ON user_sessions(realm_id, last_session_refresh);

CREATE TABLE client_sessions (
    id BLOB PRIMARY KEY,
    client_id BLOB NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    session_id BLOB NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
    redirect_uri TEXT,
    state TEXT,
    auth_method TEXT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE events (
    id BLOB PRIMARY KEY,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    event_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    client_id BLOB,
    user_id BLOB,
    session_id BLOB,
    error TEXT,
    details TEXT
);
CREATE INDEX idx_events_realm_time ON events(realm_id, event_time);
CREATE INDEX idx_events_type ON events(event_type);

CREATE TABLE admin_events (
    id BLOB PRIMARY KEY,
    realm_id BLOB REFERENCES realms(id) ON DELETE CASCADE,
    auth_realm_id BLOB,
    auth_client_id TEXT,
    auth_user_id BLOB,
    operation_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_path TEXT NOT NULL,
    representation TEXT,
    error TEXT,
    event_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE consents (
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id BLOB NOT NULL,
    granted_scopes TEXT NOT NULL DEFAULT '[]',
    granted_realm_roles TEXT NOT NULL DEFAULT '[]',
    granted_client_roles TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (realm_id, user_id, client_id)
);

CREATE TABLE identity_providers (
    id BLOB PRIMARY KEY,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    config TEXT,
    UNIQUE(realm_id, alias)
);

CREATE TABLE flow_configs (
    alias TEXT NOT NULL,
    realm_id BLOB NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL,
    top_level INTEGER NOT NULL DEFAULT 1,
    built_in INTEGER NOT NULL DEFAULT 1,
    stages TEXT,
    PRIMARY KEY (realm_id, alias)
);
