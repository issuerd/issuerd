// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use issuerd_core::{
    AccessTokenClaims, Audience, Client, ClientAuthenticatorType, ClientId, ClientIdentifier,
    ClientProtocol, Email, Group, GroupId, GroupName, GroupPath, Issuer, JwtId, JwtType, Realm,
    RealmAccess, RealmId, RealmName, RedirectUri, Role, RoleId, RoleName, Scope, SslRequired,
    Storage, User, UserId, Username, WebOrigin,
};
use issuerd_storage::InMemoryStorage;

use crate::McpAuthContext;

pub const REALM_ID: &str = "10000000-0000-4000-8000-000000000001";
pub const ALICE_ID: &str = "20000000-0000-4000-8000-000000000001";
pub const ALICIA_ID: &str = "20000000-0000-4000-8000-000000000002";
pub const BOB_ID: &str = "20000000-0000-4000-8000-000000000003";
pub const ALPHA_CLIENT_ID: &str = "30000000-0000-4000-8000-000000000001";
pub const BETA_CLIENT_ID: &str = "30000000-0000-4000-8000-000000000002";
pub const ZETA_CLIENT_ID: &str = "30000000-0000-4000-8000-000000000003";
pub const ALPHA_ROLE_ID: &str = "40000000-0000-4000-8000-000000000001";
pub const ZETA_ROLE_ID: &str = "40000000-0000-4000-8000-000000000002";
pub const CLIENT_ROLE_ID: &str = "40000000-0000-4000-8000-000000000003";
pub const ALPHA_GROUP_ID: &str = "50000000-0000-4000-8000-000000000001";
pub const ZETA_GROUP_ID: &str = "50000000-0000-4000-8000-000000000002";
pub const REALM_SECRET: &str = "REALM-SMTP-CANARY-SECRET";
pub const PAIRWISE_SECRET: &str = "PAIRWISE-CANARY-SECRET";
pub const USER_SECRET: &str = "USER-ATTRIBUTE-CANARY-SECRET";
pub const CLIENT_SECRET: &str = "CLIENT-CANARY-SECRET";
pub const CLIENT_ATTRIBUTE_SECRET: &str = "CLIENT-ATTRIBUTE-CANARY-SECRET";
pub const GROUP_SECRET: &str = "GROUP-ATTRIBUTE-CANARY-SECRET";
pub const ROLE_SECRET: &str = "ROLE-ATTRIBUTE-CANARY-SECRET";

pub fn auth(scope: &str, roles: &[&str]) -> McpAuthContext {
    auth_with("agent", "internal-user", scope, roles)
}

pub fn auth_with(azp: &str, user_id: &str, scope: &str, roles: &[&str]) -> McpAuthContext {
    McpAuthContext {
        realm_id: RealmId::new(REALM_ID).unwrap(),
        realm_name: RealmName::new("demo").unwrap(),
        user_id: UserId::new(user_id).unwrap(),
        azp: ClientIdentifier::new(azp).unwrap(),
        claims: AccessTokenClaims {
            jti: JwtId::new("token-id").unwrap(),
            iss: Issuer::new("https://issuer.example/realms/demo").unwrap(),
            sub: UserId::new("pairwise-subject").unwrap(),
            aud: Audience::from_values(vec![
                azp.to_string(),
                "https://issuer.example/realms/demo/mcp".to_string(),
            ])
            .unwrap(),
            exp: 100,
            iat: 1,
            nbf: 1,
            scope: Scope::parse(scope),
            typ: JwtType::Bearer,
            azp: Some(azp.to_string()),
            session_state: None,
            realm_access: Some(RealmAccess {
                roles: roles.iter().map(|role| RoleName::new(*role).unwrap()).collect(),
            }),
            resource_access: None,
            sid: None,
            claims: None,
            cnf: None,
            authorization_details: None,
            resource: Some("https://issuer.example/realms/demo/mcp".to_string()),
        },
    }
}

pub fn realm() -> Realm {
    let mut realm = Realm {
        id: RealmId::new(REALM_ID).unwrap(),
        name: RealmName::new("demo").unwrap(),
        display_name: Some("Demo Realm".try_into().unwrap()),
        enabled: true,
        ssl_required: SslRequired::External,
        registration_enabled: true,
        internationalization_enabled: true,
        supported_locales: vec!["en".into(), "de".into()],
        default_locale: Some("en".into()),
        ..Realm::default()
    };
    realm.attributes.insert("smtpServer.password".into(), REALM_SECRET.into());
    realm.attributes.insert("pairwise_sector_key".into(), PAIRWISE_SECRET.into());
    realm
}

pub fn user(id: &str, username: &str, email: &str) -> User {
    let timestamp = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    User {
        id: UserId::new(id).unwrap(),
        realm_id: RealmId::new(REALM_ID).unwrap(),
        username: Username::new(username).unwrap(),
        email: Some(Email::new(email).unwrap()),
        email_verified: true,
        first_name: Some(format!("Given {username}").try_into().unwrap()),
        last_name: Some("Surname".try_into().unwrap()),
        enabled: true,
        federation_link: Some("ldap-private".into()),
        attributes: HashMap::from([
            ("password".into(), vec![USER_SECRET.into()]),
            ("custom.secret".into(), vec![USER_SECRET.into()]),
        ]),
        required_actions: vec!["VERIFY_EMAIL".into()],
        created_at: timestamp,
        updated_at: timestamp,
    }
}

pub fn client(id: &str, client_id: &str) -> Client {
    Client {
        id: ClientId::new(id).unwrap(),
        realm_id: RealmId::new(REALM_ID).unwrap(),
        client_id: ClientIdentifier::new(client_id).unwrap(),
        name: Some(format!("{client_id} name").try_into().unwrap()),
        description: Some("read model fixture".into()),
        enabled: true,
        protocol: ClientProtocol::OpenIdConnect,
        public_client: true,
        bearer_only: false,
        client_authenticator_type: ClientAuthenticatorType::ClientSecret,
        secret: Some(CLIENT_SECRET.into()),
        redirect_uris: vec![
            RedirectUri::new("https://z.example/callback").unwrap(),
            RedirectUri::new("https://a.example/callback").unwrap(),
        ],
        web_origins: vec![
            WebOrigin::new("https://z.example").unwrap(),
            WebOrigin::new("https://a.example").unwrap(),
        ],
        default_scopes: Scope::from(vec!["roles".into(), "profile".into()]),
        optional_scopes: Scope::from(vec!["mcp:read".into(), "email".into()]),
        consent_required: true,
        full_scope_allowed: false,
        service_accounts_enabled: true,
        protocol_mappers: Vec::new(),
        scope_mappings: Default::default(),
        attributes: HashMap::from([
            ("password".into(), CLIENT_ATTRIBUTE_SECRET.into()),
            ("custom.secret".into(), CLIENT_ATTRIBUTE_SECRET.into()),
        ]),
    }
}

pub fn role(id: &str, name: &str) -> Role {
    Role {
        id: RoleId::new(id).unwrap(),
        name: RoleName::new(name).unwrap(),
        description: Some(format!("{name} description")),
        realm_id: RealmId::new(REALM_ID).unwrap(),
        client_role: false,
        client_id: None,
        composite: false,
        composites: Vec::new(),
        attributes: HashMap::from([("password".into(), vec![ROLE_SECRET.into()])]),
    }
}

pub fn group(id: &str, name: &str, parent_id: Option<GroupId>) -> Group {
    let path = if parent_id.is_some() {
        format!("/alpha-group/{name}")
    } else {
        format!("/{name}")
    };
    Group {
        id: GroupId::new(id).unwrap(),
        name: GroupName::new(name).unwrap(),
        path: GroupPath::new(path).unwrap(),
        realm_id: RealmId::new(REALM_ID).unwrap(),
        parent_id,
        sub_groups: Vec::new(),
        attributes: HashMap::from([("password".into(), vec![GROUP_SECRET.into()])]),
        realm_roles: Vec::new(),
        client_roles: HashMap::new(),
    }
}

pub async fn storage() -> Arc<InMemoryStorage> {
    let storage = Arc::new(InMemoryStorage::new());
    let realm = realm();
    storage.create_realm(&realm).await.unwrap();
    for fixture in [
        user(ALICIA_ID, "alicia", "alicia@example.com"),
        user(BOB_ID, "bob", "bob@other.example"),
        user(ALICE_ID, "alice", "alice@example.com"),
    ] {
        storage.create_user(&realm.id, &fixture).await.unwrap();
    }
    for fixture in [
        client(ZETA_CLIENT_ID, "zeta-client"),
        client(BETA_CLIENT_ID, "beta-client"),
        client(ALPHA_CLIENT_ID, "alpha-client"),
    ] {
        storage.create_client(&realm.id, &fixture).await.unwrap();
    }

    let mut client_role = role(CLIENT_ROLE_ID, "client-only-role");
    client_role.client_role = true;
    client_role.client_id = Some(ClientId::new(ALPHA_CLIENT_ID).unwrap());
    storage.create_role(&realm.id, &client_role).await.unwrap();
    for (id, name) in [(ZETA_ROLE_ID, "zeta-role"), (ALPHA_ROLE_ID, "alpha-role")] {
        let mut role = role(id, name);
        if name == "zeta-role" {
            role.composite = true;
            role.composites = vec![RoleName::new("alpha-role").unwrap()];
        }
        storage.create_role(&realm.id, &role).await.unwrap();
        storage
            .add_user_realm_role(&realm.id, &UserId::new(ALICE_ID).unwrap(), &role.id)
            .await
            .unwrap();
    }
    let alpha_group = group(ALPHA_GROUP_ID, "alpha-group", None);
    let zeta_group =
        group(ZETA_GROUP_ID, "zeta-group", Some(GroupId::new(ALPHA_GROUP_ID).unwrap()));
    for group in [zeta_group, alpha_group] {
        storage.create_group(&realm.id, &group).await.unwrap();
        storage
            .add_user_group(&realm.id, &UserId::new(ALICE_ID).unwrap(), &group.id)
            .await
            .unwrap();
    }
    for user_id in [ALICIA_ID, BOB_ID] {
        storage
            .add_user_group(
                &realm.id,
                &UserId::new(user_id).unwrap(),
                &GroupId::new(ZETA_GROUP_ID).unwrap(),
            )
            .await
            .unwrap();
    }
    storage
}
