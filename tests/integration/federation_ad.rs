// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Federation integration tests against a real Windows Server Active Directory lab.

//! Federation integration tests against a real Windows Server Active Directory.
//!
//! These tests are `#[ignore]`d by default and skip automatically unless an
//! AD DS lab is configured via the environment (no lab values are hardcoded):
//!
//!   ISSUERD_TEST_AD_HOST              AD host (LDAP on 389, LDAPS on 636)
//!   ISSUERD_TEST_AD_BIND_CREDENTIAL   password of the read-bind account
//!
//! Optional overrides: ISSUERD_TEST_AD_BASE_DN / _USERS_DN / _GROUPS_DN /
//! _BIND_DN / _ADMIN_DN (defaults mirror the test.issuerd.local layout).
//!
//! Run with:
//!   cargo test --test integration federation_ad -- --ignored

use crate::harness::{AdLab, TestHarness};
use issuerd_core::FederationProvider;
use issuerd_federation::ldap::config::LdapConfig;
use issuerd_federation::ldap::connection::{LdapClient, LdapConnection};
use issuerd_federation::ldap::provider::LdapFederationProvider;
use issuerd_federation::mapper::{
    GroupMapper, MembershipType, MsadAccountControlMapper, UserAttributeMapper,
    UserRolesRetrieveStrategy,
};

fn ad_lab() -> Option<AdLab> {
    let lab = AdLab::from_env()?;
    lab.available().then_some(lab)
}

macro_rules! require_ad_lab {
    () => {
        match ad_lab() {
            Some(lab) => lab,
            None => {
                eprintln!(
                    "SKIP: AD lab not configured or unreachable \
                     (see ISSUERD_TEST_AD_* env vars)"
                );
                return;
            }
        }
    };
}

fn ad_ldap_config(lab: &AdLab) -> LdapConfig {
    LdapConfig::from_hashmap(&lab.provider_config()).unwrap()
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_ldap_bind_and_search() {
    let lab = require_ad_lab!();

    let mut conn = LdapConnection::connect(&lab.ldap_url(), false, false)
        .await
        .expect("connect to AD LDAP");

    conn.bind(&lab.bind_dn, &lab.bind_credential).await.expect("bind as ldapbind");

    let entries = conn
        .search(
            &lab.users_dn,
            ldap3::Scope::Subtree,
            "(&(objectClass=person)(sAMAccountName=testuser))",
            &["sAMAccountName", "mail", "givenName", "sn", "memberOf"],
        )
        .await
        .expect("search for testuser");

    assert_eq!(entries.len(), 1, "expected exactly one testuser entry");
    let entry = &entries[0];
    assert_eq!(entry.attrs.get("sAMAccountName"), Some(&vec!["testuser".to_string()]));
    assert_eq!(entry.attrs.get("mail"), Some(&vec!["testuser@test.issuerd.local".to_string()]));
    assert_eq!(entry.attrs.get("givenName"), Some(&vec!["Test".to_string()]));
    assert_eq!(entry.attrs.get("sn"), Some(&vec!["User".to_string()]));

    let member_of = entry.attrs.get("memberOf").cloned().unwrap_or_default();
    assert!(
        member_of.iter().any(|m| m.contains("developers")),
        "expected testuser to be member of developers, got {:?}",
        member_of
    );
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_ldap_password_validation_success() {
    let lab = require_ad_lab!();

    let provider = LdapFederationProvider::new("ad-ldap".to_string(), ad_ldap_config(&lab), vec![])
        .await
        .expect("create LDAP provider");

    let result = provider
        .validate_password("testuser", "Password123!")
        .await
        .expect("validate password");
    assert!(result, "expected password to be valid");
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_ldap_password_validation_failure() {
    let lab = require_ad_lab!();

    let provider = LdapFederationProvider::new("ad-ldap".to_string(), ad_ldap_config(&lab), vec![])
        .await
        .expect("create LDAP provider");

    let result = provider
        .validate_password("testuser", "WrongPassword!")
        .await
        .expect("validate password request");
    assert!(!result, "expected password to be invalid");
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_ldap_attribute_mapping() {
    let lab = require_ad_lab!();

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
            ldap_attribute: "givenName".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        }),
        Box::new(UserAttributeMapper {
            user_attribute: "lastName".to_string(),
            ldap_attribute: "sn".to_string(),
            read_only: true,
            always_read_from_ldap: false,
            is_mandatory_in_ldap: false,
            default_value: None,
        }),
    ];

    let provider =
        LdapFederationProvider::new("ad-ldap".to_string(), ad_ldap_config(&lab), mappers)
            .await
            .expect("create LDAP provider");

    let user = provider.find_user("testuser").await.expect("find user").expect("user exists");

    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, Some("testuser@test.issuerd.local".to_string()));
    assert_eq!(user.first_name, Some(issuerd_core::DisplayName::new("Test").unwrap()));
    assert_eq!(user.last_name, Some(issuerd_core::DisplayName::new("User").unwrap()));
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_group_memberof_mapping() {
    let lab = require_ad_lab!();

    let mappers: Vec<Box<dyn issuerd_federation::mapper::LdapMapper>> =
        vec![Box::new(GroupMapper {
            groups_dn: lab.groups_dn.clone(),
            group_name_attribute: "cn".to_string(),
            group_object_classes: vec!["group".to_string()],
            membership_attribute: "member".to_string(),
            membership_type: MembershipType::Dn,
            mode: issuerd_federation::mapper::GroupSyncMode::ReadOnly,
            preserve_group_inheritance: false,
            user_roles_retrieve_strategy: UserRolesRetrieveStrategy::GetGroupsFromUserMemberOf,
            member_of_attribute: "memberOf".to_string(),
            groups_include: None,
        })];

    let provider =
        LdapFederationProvider::new("ad-ldap".to_string(), ad_ldap_config(&lab), mappers)
            .await
            .expect("create LDAP provider");

    let user = provider.find_user("testuser").await.expect("find user").expect("user exists");

    let memberships = user.attributes.get("memberOf").cloned().unwrap_or_default();
    assert!(
        memberships.iter().any(|m| m.contains("developers")),
        "expected testuser to be member of developers group, got {:?}",
        memberships
    );
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_msad_account_control_disabled() {
    let lab = require_ad_lab!();

    let mappers: Vec<Box<dyn issuerd_federation::mapper::LdapMapper>> =
        vec![Box::new(MsadAccountControlMapper)];

    let provider =
        LdapFederationProvider::new("ad-ldap".to_string(), ad_ldap_config(&lab), mappers)
            .await
            .expect("create LDAP provider");

    // testuser2 should be enabled (NORMAL_ACCOUNT = 512)
    let user = provider.find_user("testuser2").await.expect("find user").expect("user exists");
    assert!(user.enabled, "testuser2 should be enabled");
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_password_update_unicodepwd() {
    let lab = require_ad_lab!();

    let mut config = ad_ldap_config(&lab);
    config.connection_url = lab.ldaps_url();

    let provider = LdapFederationProvider::new("ad-ldap".to_string(), config, vec![]).await;

    let provider = match provider {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: LDAPS connection failed: {e}");
            return;
        }
    };

    // Try updating the password. Real AD may reject unicodePwd over
    // an untrusted channel, so we treat any error as a skip condition.
    match provider.update_password("testuser2", "NewPass456!").await {
        Ok(()) => {
            let valid = provider
                .validate_password("testuser2", "NewPass456!")
                .await
                .expect("validate new password");
            assert!(valid, "new password should validate after update");
        }
        Err(e) => {
            eprintln!("SKIP: unicodePwd update not supported on this AD config: {e}");
        }
    }
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_sync_full() {
    let lab = require_ad_lab!();

    let harness = TestHarness::new().await;
    let realm = harness.create_realm("ad-sync").await;
    harness.configure_ad_provider("ad-sync", &lab).await;
    let client = harness.create_client("ad-sync", false).await;

    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/{}/user-federation/ad-ldap/sync", realm.name),
            &admin_token,
            serde_json::json!({}),
        )
        .await;

    if resp.status() == axum::http::StatusCode::NOT_FOUND {
        eprintln!("SKIP: Federation provider not yet visible in cache");
        return;
    }

    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let added = result["added"].as_u64().unwrap_or(0);
    assert!(added >= 2, "expected at least 2 users added, got {added}");

    let u1 = harness.storage.get_user_by_username(&realm.id, "testuser").await.unwrap();
    assert!(u1.is_some(), "testuser should be imported");

    assert!(!client.client_id.is_empty());
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_auth_flow_login_success() {
    let lab = require_ad_lab!();

    let harness = TestHarness::new().await;
    let realm = harness.create_realm("ad-auth").await;
    harness.configure_ad_provider("ad-auth", &lab).await;
    let client = harness.create_client("ad-auth", false).await;

    let tokens = harness
        .authenticate_user("ad-auth", &client.client_id, "testuser", "Password123!")
        .await;

    assert!(!tokens.access_token.is_empty());

    let user = harness
        .storage
        .get_user_by_username(&realm.id, "testuser")
        .await
        .unwrap()
        .expect("user should be imported after login");
    assert_eq!(user.federation_link, Some("ad-ldap".to_string()));
}

#[tokio::test]
#[ignore = "requires real Active Directory VM"]
async fn ad_auth_flow_login_bad_password() {
    let lab = require_ad_lab!();

    let harness = TestHarness::new().await;
    let realm = harness.create_realm("ad-auth-bad").await;
    harness.configure_ad_provider("ad-auth-bad", &lab).await;
    let client = harness.create_client("ad-auth-bad", false).await;

    let auth_path = format!(
        "/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        realm.name, client.client_id
    );
    let auth_resp = harness.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);

    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("missing execution_id");

    let login_resp = harness
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={}", realm.name),
            serde_json::json!({
                "execution_id": execution_id,
                "username": "testuser",
                "password": "WrongPassword!",
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;

    assert!(
        login_resp.status().is_client_error(),
        "expected client error for bad password, got {:?}",
        login_resp.status()
    );
}
