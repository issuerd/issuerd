-- Client scopes & protocol mappers.
--
-- Clients gain a service-account flag plus JSONB columns for client-local
-- protocol mappers and scope-mappings. Client scopes are first-class,
-- realm-scoped resources; association tables wire them to clients
-- (default vs optional) and to realm defaults (default-default vs
-- default-optional). User client-role mappings mirror user_realm_roles.

ALTER TABLE clients ADD COLUMN IF NOT EXISTS service_accounts_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS protocol_mappers JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS scope_mappings JSONB NOT NULL DEFAULT '{"realm_roles":[],"client_roles":{}}'::jsonb;

-- Client roles are plain `roles` rows with client_id set. The original
-- UNIQUE(realm_id, name) constraint forbade same-named client roles across
-- different clients; replace it with an index keyed by the owning client
-- (the zero UUID stands in for realm roles) so realm roles stay unique per
-- realm and client roles unique per owning client.
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_realm_id_name_key;
CREATE UNIQUE INDEX roles_realm_client_name_key
    ON roles (realm_id, COALESCE(client_id, '00000000-0000-0000-0000-000000000000'::uuid), name);

CREATE TABLE client_scopes (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    protocol TEXT NOT NULL DEFAULT 'openid-connect',
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    protocol_mappers JSONB NOT NULL DEFAULT '[]'::jsonb,
    scope_mappings JSONB NOT NULL DEFAULT '{"realm_roles":[],"client_roles":{}}'::jsonb,
    UNIQUE(realm_id, name)
);

-- is_default: true = default scope (always granted), false = optional
-- (granted only when requested via the `scope` parameter).
CREATE TABLE client_client_scopes (
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES client_scopes(id) ON DELETE CASCADE,
    is_default BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (client_id, scope_id)
);

-- is_default: true = default-default scope, false = default-optional scope.
CREATE TABLE realm_default_client_scopes (
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES client_scopes(id) ON DELETE CASCADE,
    is_default BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (realm_id, scope_id)
);

CREATE TABLE user_client_roles (
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id  UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (realm_id, user_id, role_id)
);
