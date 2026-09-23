// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Secondary federation integration tests against an OpenLDAP container.

//! Secondary federation integration tests against OpenLDAP.
//!
//! These tests are ignored by default because they require the OpenLDAP
//! container to be running:
//!   docker compose -f docker-compose.integration.yml up -d openldap
//!   cargo test --test integration federation_ldap -- --ignored

use std::net::TcpStream;
use std::time::Duration;

use crate::harness::TestHarness;
use issuerd_core::FederationProvider;
use issuerd_federation::ldap::config::LdapConfig;
use issuerd_federation::ldap::connection::{LdapClient, LdapConnection};
use issuerd_federation::ldap::provider::LdapFederationProvider;
use issuerd_federation::mapper::{
    GroupMapper, MembershipType, UserAttributeMapper, UserRolesRetrieveStrategy,
};

fn openldap_available() -> bool {
    TcpStream::connect_timeout(&"127.0.0.1:1389".parse().unwrap(), Duration::from_secs(2)).is_ok()
}

fn openldap_config() -> LdapConfig {
    let mut config = std::collections::HashMap::new();
    config.insert("connectionUrl".to_string(), "ldap://localhost:1389".to_string());
    config.insert("bindDn".to_string(), "cn=admin,dc=test,dc=issuerd,dc=local".to_string());
    config.insert("bindCredential".to_string(), "admin".to_string());
    config.insert("usersDn".to_string(), "ou=users,dc=test,dc=issuerd,dc=local".to_string());
    config.insert("baseDn".to_string(), "dc=test,dc=issuerd,dc=local".to_string());
    config.insert("usernameLdapAttribute".to_string(), "uid".to_string());
    config.insert("rdnLdapAttribute".to_string(), "uid".to_string());
    config.insert("uuidLdapAttribute".to_string(), "entryUUID".to_string());
    config.insert(
        "userObjectClasses".to_string(),
        "inetOrgPerson,organizationalPerson".to_string(),
    );
    config.insert("vendor".to_string(), "GENERIC".to_string());
    config.insert("searchScope".to_string(), "SUBTREE".to_string());
    config.insert("editMode".to_string(), "WRITABLE".to_string());
    LdapConfig::from_hashmap(&config).unwrap()
}

#[tokio::test]
#[ignore = "requires OpenLDAP container"]
async fn ldap_openldap_bind_and_search() {
    if !openldap_available() {
        eprintln!("SKIP: OpenLDAP not available on localhost:1389");
        return;
    }

    let mut conn = LdapConnection::connect("ldap://localhost:1389", false, false)
        .await
        .expect("connect to OpenLDAP");

    conn.bind("cn=admin,dc=test,dc=issuerd,dc=local", "admin")
        .await
        .expect("bind as admin");

    let entries = conn
        .search(
            "ou=users,dc=test,dc=issuerd,dc=local",
            ldap3::Scope::Subtree,
            "(&(objectClass=inetOrgPerson)(uid=testuser))",
            &["uid", "mail", "cn", "sn"],
        )
        .await
        .expect("search for testuser");

    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.attrs.get("uid"), Some(&vec!["testuser".to_string()]));
    assert_eq!(entry.attrs.get("mail"), Some(&vec!["testuser@test.issuerd.local".to_string()]));
}

#[tokio::test]
#[ignore = "requires OpenLDAP container"]
async fn ldap_openldap_password_validation() {
    if !openldap_available() {
        eprintln!("SKIP: OpenLDAP not available on localhost:1389");
        return;
    }

    let provider = LdapFederationProvider::new("openldap".to_string(), openldap_config(), vec![])
        .await
        .expect("create LDAP provider");

    let valid = provider
        .validate_password("testuser", "Password123!")
        .await
        .expect("validate password");
    assert!(valid);

    let invalid = provider
        .validate_password("testuser", "wrong")
        .await
        .expect("validate password request");
    assert!(!invalid);
}

#[tokio::test]
#[ignore = "requires OpenLDAP container"]
async fn ldap_openldap_attribute_mapping() {
    if !openldap_available() {
        eprintln!("SKIP: OpenLDAP not available on localhost:1389");
        return;
    }

    let mappers: Vec<Box<dyn issuerd_federation::mapper::LdapMapper>> = vec![
        Box::new(UserAttributeMapper {
            user_attribute: "email".to_string(),
            ldap_attribute: "mail".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        }),
        Box::new(UserAttributeMapper {
            user_attribute: "firstName".to_string(),
            ldap_attribute: "cn".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        }),
    ];

    let provider = LdapFederationProvider::new("openldap".to_string(), openldap_config(), mappers)
        .await
        .expect("create LDAP provider");

    let user = provider.find_user("testuser").await.expect("find user").expect("user exists");

    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, Some("testuser@test.issuerd.local".to_string()));
    assert_eq!(user.first_name, Some(issuerd_core::DisplayName::new("Test User").unwrap()));
}

#[tokio::test]
#[ignore = "requires OpenLDAP container"]
async fn ldap_openldap_group_memberof() {
    if !openldap_available() {
        eprintln!("SKIP: OpenLDAP not available on localhost:1389");
        return;
    }

    let mappers: Vec<Box<dyn issuerd_federation::mapper::LdapMapper>> =
        vec![Box::new(GroupMapper {
            groups_dn: "ou=groups,dc=test,dc=issuerd,dc=local".to_string(),
            group_name_attribute: "cn".to_string(),
            group_object_classes: vec!["groupOfUniqueNames".to_string()],
            membership_attribute: "uniqueMember".to_string(),
            membership_type: MembershipType::Dn,
            mode: issuerd_federation::mapper::GroupSyncMode::ReadOnly,
            preserve_group_inheritance: false,
            user_roles_retrieve_strategy: UserRolesRetrieveStrategy::GetGroupsFromUserMemberOf,
            member_of_attribute: "memberOf".to_string(),
            groups_include: None,
        })];

    let provider = LdapFederationProvider::new("openldap".to_string(), openldap_config(), mappers)
        .await
        .expect("create LDAP provider");

    let user = provider.find_user("testuser").await.expect("find user").expect("user exists");

    // GetGroupsFromUserMemberOf extracts group CNs from the user entry's
    // memberOf DNs (provided by the OpenLDAP memberOf overlay).
    let memberships = user.attributes.get("memberOf").cloned().unwrap_or_default();
    assert!(
        memberships.iter().any(|m| m.contains("developers")),
        "expected testuser to be member of developers, got {:?}",
        memberships
    );
}

#[tokio::test]
#[ignore = "requires OpenLDAP container"]
async fn ldap_openldap_auth_flow_login_success() {
    if !openldap_available() {
        eprintln!("SKIP: OpenLDAP not available on localhost:1389");
        return;
    }

    let harness = TestHarness::new().await;
    let realm = harness.create_realm("openldap-auth").await;
    harness.configure_openldap_provider("openldap-auth").await;
    let client = harness.create_client("openldap-auth", false).await;

    let tokens = harness
        .authenticate_user("openldap-auth", &client.client_id, "testuser", "Password123!")
        .await;

    assert!(!tokens.access_token.is_empty());

    let user = harness
        .storage
        .get_user_by_username(&realm.id, "testuser")
        .await
        .unwrap()
        .expect("user should be imported");
    assert_eq!(user.federation_link, Some("openldap".to_string()));
}
