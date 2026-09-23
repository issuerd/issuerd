CREATE TABLE realms (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    ssl_required TEXT NOT NULL DEFAULT 'external',
    password_policy JSONB,
    login_theme TEXT,
    email_theme TEXT,
    admin_theme TEXT,
    default_role TEXT,
    access_token_lifespan BIGINT NOT NULL DEFAULT 300,
    refresh_token_lifespan BIGINT NOT NULL DEFAULT 1800,
    sso_session_idle_timeout BIGINT NOT NULL DEFAULT 1800,
    sso_session_max_lifespan BIGINT NOT NULL DEFAULT 36000,
    offline_session_idle_timeout BIGINT NOT NULL DEFAULT 2592000,
    attributes JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    email TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    first_name TEXT,
    last_name TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    federation_link TEXT,
    attributes JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(realm_id, username)
);
CREATE INDEX idx_users_realm_email ON users(realm_id, email);

CREATE TABLE clients (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    name TEXT,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    protocol TEXT NOT NULL DEFAULT 'openid-connect',
    public_client BOOLEAN NOT NULL DEFAULT false,
    bearer_only BOOLEAN NOT NULL DEFAULT false,
    client_authenticator_type TEXT NOT NULL DEFAULT 'client-secret',
    secret TEXT,
    redirect_uris JSONB NOT NULL DEFAULT '[]',
    web_origins JSONB NOT NULL DEFAULT '[]',
    default_scopes JSONB NOT NULL DEFAULT '[]',
    optional_scopes JSONB NOT NULL DEFAULT '[]',
    consent_required BOOLEAN NOT NULL DEFAULT false,
    full_scope_allowed BOOLEAN NOT NULL DEFAULT true,
    attributes JSONB,
    UNIQUE(realm_id, client_id)
);

CREATE TABLE roles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_role BOOLEAN NOT NULL DEFAULT false,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    composite BOOLEAN NOT NULL DEFAULT false,
    composites JSONB,
    attributes JSONB,
    UNIQUE(realm_id, name)
);

CREATE TABLE groups (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    attributes JSONB,
    realm_roles JSONB,
    client_roles JSONB,
    UNIQUE(realm_id, name)
);

CREATE TABLE credentials (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL,
    user_label TEXT,
    created_date TIMESTAMPTZ NOT NULL DEFAULT now(),
    secret_data BYTEA,
    credential_data JSONB,
    priority INT NOT NULL DEFAULT 0
);
CREATE INDEX idx_credentials_user ON credentials(realm_id, user_id, credential_type);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_username TEXT NOT NULL,
    ip_address TEXT,
    auth_method TEXT,
    remember_me BOOLEAN NOT NULL DEFAULT false,
    started TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_session_refresh TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sessions_user ON user_sessions(realm_id, user_id);
CREATE INDEX idx_sessions_refresh ON user_sessions(realm_id, last_session_refresh);

CREATE TABLE client_sessions (
    id UUID PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
    redirect_uri TEXT,
    state TEXT,
    auth_method TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE events (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    event_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type TEXT NOT NULL,
    ip_address TEXT,
    client_id UUID,
    user_id UUID,
    session_id UUID,
    error TEXT,
    details JSONB
);
CREATE INDEX idx_events_realm_time ON events(realm_id, event_time);
CREATE INDEX idx_events_type ON events(event_type);

CREATE TABLE admin_events (
    id UUID PRIMARY KEY,
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    auth_realm_id UUID,
    auth_client_id UUID,
    auth_user_id UUID,
    operation_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_path TEXT NOT NULL,
    representation TEXT,
    error TEXT,
    event_time TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE consents (
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    granted_scopes JSONB NOT NULL DEFAULT '[]',
    granted_realm_roles JSONB NOT NULL DEFAULT '[]',
    granted_client_roles JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, user_id, client_id)
);

CREATE TABLE identity_providers (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    config JSONB,
    UNIQUE(realm_id, alias)
);

CREATE TABLE flow_configs (
    alias TEXT NOT NULL,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL,
    top_level BOOLEAN NOT NULL DEFAULT true,
    built_in BOOLEAN NOT NULL DEFAULT true,
    stages JSONB,
    PRIMARY KEY (realm_id, alias)
);
