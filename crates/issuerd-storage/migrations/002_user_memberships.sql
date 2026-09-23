CREATE TABLE user_realm_roles (
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id  UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (realm_id, user_id, role_id)
);

CREATE TABLE user_groups (
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (realm_id, user_id, group_id)
);
