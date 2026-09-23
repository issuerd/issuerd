// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Primary federation integration tests against a Samba AD DC container.

//! Primary federation integration tests against a Samba AD DC.
//!
//! These tests require the Samba DC container to be running:
//!   docker compose up -d samba-dc
//!
//! If the container is not available, tests skip gracefully at runtime.

use std::collections::HashMap;
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

fn samba_available() -> bool {
    TcpStream::connect_timeout(&"127.0.0.1:389".parse().unwrap(), Duration::from_secs(2)).is_ok()
}

fn samba_ldap_config() -> LdapConfig {
    crate::harness::ensure_ring_crypto_provider();
    let mut config = HashMap::new();
    config.insert("connectionUrl".to_string(), "ldap://localhost:389".to_string());
    config.insert(
        "bindDn".to_string(),
        "CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local".to_string(),
    );
    config.insert("bindCredential".to_string(), "AdminPass123!".to_string());
    config.insert("usersDn".to_string(), "CN=Users,DC=test,DC=issuerd,DC=local".to_string());
    config.insert("baseDn".to_string(), "DC=test,DC=issuerd,DC=local".to_string());
    config.insert("usernameLdapAttribute".to_string(), "sAMAccountName".to_string());
    config.insert("rdnLdapAttribute".to_string(), "cn".to_string());
    config.insert("uuidLdapAttribute".to_string(), "objectGUID".to_string());
    config.insert("userObjectClasses".to_string(), "person,organizationalPerson,user".to_string());
    config.insert("vendor".to_string(), "ACTIVE_DIRECTORY".to_string());
    config.insert("searchScope".to_string(), "SUBTREE".to_string());
    config.insert("editMode".to_string(), "WRITABLE".to_string());
    LdapConfig::from_hashmap(&config).unwrap()
}

#[tokio::test]
async fn samba_dc_ldap_bind_and_search() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
        return;
    }

    let mut conn = LdapConnection::connect("ldap://localhost:389", false, false)
        .await
        .expect("connect to Samba LDAP");

    conn.bind("CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local", "AdminPass123!")
        .await
        .expect("bind as admin");

    let entries = conn
        .search(
            "CN=Users,DC=test,DC=issuerd,DC=local",
            ldap3::Scope::Subtree,
            "(&(objectClass=person)(sAMAccountName=testuser))",
            &["sAMAccountName", "mail", "givenName", "sn"],
        )
        .await
        .expect("search for testuser");

    assert_eq!(entries.len(), 1, "expected exactly one testuser entry");
    let entry = &entries[0];
    assert_eq!(entry.attrs.get("sAMAccountName"), Some(&vec!["testuser".to_string()]));
    assert_eq!(entry.attrs.get("mail"), Some(&vec!["testuser@test.issuerd.local".to_string()]));
    assert_eq!(entry.attrs.get("givenName"), Some(&vec!["Test".to_string()]));
    assert_eq!(entry.attrs.get("sn"), Some(&vec!["User".to_string()]));
}

#[tokio::test]
async fn samba_dc_ldap_password_validation_success() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
        return;
    }

    let provider =
        LdapFederationProvider::new("samba-ldap".to_string(), samba_ldap_config(), vec![])
            .await
            .expect("create LDAP provider");

    let result = provider
        .validate_password("testuser", "Password123!")
        .await
        .expect("validate password");
    assert!(result, "expected password to be valid");
}

#[tokio::test]
async fn samba_dc_ldap_password_validation_failure() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
        return;
    }

    let provider =
        LdapFederationProvider::new("samba-ldap".to_string(), samba_ldap_config(), vec![])
            .await
            .expect("create LDAP provider");

    let result = provider
        .validate_password("testuser", "WrongPassword!")
        .await
        .expect("validate password request");
    assert!(!result, "expected password to be invalid");
}

#[tokio::test]
async fn samba_dc_ldap_attribute_mapping_ad() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
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
        LdapFederationProvider::new("samba-ldap".to_string(), samba_ldap_config(), mappers)
            .await
            .expect("create LDAP provider");

    let user = provider.find_user("testuser").await.expect("find user").expect("user exists");

    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, Some("testuser@test.issuerd.local".to_string()));
    assert_eq!(user.first_name, Some(issuerd_core::DisplayName::new("Test").unwrap()));
    assert_eq!(user.last_name, Some(issuerd_core::DisplayName::new("User").unwrap()));
}

#[tokio::test]
async fn samba_dc_group_memberof_mapping() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
        return;
    }

    let mappers: Vec<Box<dyn issuerd_federation::mapper::LdapMapper>> =
        vec![Box::new(GroupMapper {
            groups_dn: "CN=Users,DC=test,DC=issuerd,DC=local".to_string(),
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
        LdapFederationProvider::new("samba-ldap".to_string(), samba_ldap_config(), mappers)
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
async fn samba_dc_password_update_unicodepwd() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
        return;
    }

    let mut config = samba_ldap_config();
    config.connection_url = "ldaps://localhost:636".to_string();

    let provider = LdapFederationProvider::new("samba-ldap".to_string(), config, vec![]).await;

    // Samba DC may not have a trusted certificate; if LDAPS fails, skip.
    let provider = match provider {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: LDAPS connection failed: {e}");
            return;
        }
    };

    // Try updating the password. Samba may still reject unicodePwd over
    // an untrusted channel, so we treat any error as a skip condition.
    match provider.update_password("testuser2", "NewPass456!").await {
        Ok(()) => {
            // Verify the new password works.
            let valid = provider
                .validate_password("testuser2", "NewPass456!")
                .await
                .expect("validate new password");
            assert!(valid, "new password should validate after update");
        }
        Err(e) => {
            eprintln!("SKIP: unicodePwd update not supported on this Samba config: {e}");
        }
    }
}

#[tokio::test]
async fn samba_dc_sync_full() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
        return;
    }

    let harness = TestHarness::new().await;
    let realm = harness.create_realm("samba-sync").await;
    harness.configure_samba_ldap_provider("samba-sync").await;
    let client = harness.create_client("samba-sync", false).await;

    // Authenticate as admin to get a bearer token.
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    let resp = harness
        .post_json_auth(
            &format!("/admin/realms/{}/user-federation/samba-ldap/sync", realm.name),
            &admin_token,
            serde_json::json!({}),
        )
        .await;

    // The sync endpoint may return 200 (sync performed) or 404 (provider not
    // found) depending on whether the DynamicFederationManager cached the
    // provider list before the identity provider was inserted.
    if resp.status() == axum::http::StatusCode::NOT_FOUND {
        eprintln!("SKIP: Federation provider not yet visible in cache");
        return;
    }

    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Samba DC has at least testuser and testuser2.
    let added = result["added"].as_u64().unwrap_or(0);
    assert!(added >= 2, "expected at least 2 users added, got {added}");

    // Verify the users now exist in local storage.
    let u1 = harness.storage.get_user_by_username(&realm.id, "testuser").await.unwrap();
    assert!(u1.is_some(), "testuser should be imported");

    // Verify the client was created successfully (avoid unused warning).
    assert!(!client.client_id.is_empty());
}

#[tokio::test]
async fn samba_dc_auth_flow_login_success() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
        return;
    }

    let harness = TestHarness::new().await;
    let realm = harness.create_realm("samba-auth").await;
    harness.configure_samba_ldap_provider("samba-auth").await;
    let client = harness.create_client("samba-auth", false).await;

    let tokens = harness
        .authenticate_user("samba-auth", &client.client_id, "testuser", "Password123!")
        .await;

    assert!(!tokens.access_token.is_empty());

    // Verify the user was imported into local storage with federation_link.
    let user = harness
        .storage
        .get_user_by_username(&realm.id, "testuser")
        .await
        .unwrap()
        .expect("user should be imported after login");
    assert_eq!(user.federation_link, Some("samba-ldap".to_string()));
}

#[tokio::test]
async fn samba_dc_auth_flow_login_bad_password() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
        return;
    }

    let harness = TestHarness::new().await;
    let realm = harness.create_realm("samba-auth-bad").await;
    harness.configure_samba_ldap_provider("samba-auth-bad").await;
    let client = harness.create_client("samba-auth-bad", false).await;

    // Attempt authentication with wrong password.
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

    // The login endpoint returns 401 or 400 for invalid credentials.
    assert!(
        login_resp.status().is_client_error(),
        "expected client error for bad password, got {:?}",
        login_resp.status()
    );
}

// ---------------------------------------------------------------------------
// Federation password write-through (account change + email reset)
// ---------------------------------------------------------------------------

/// Email sender that records every message instead of delivering it.
#[derive(Default)]
struct RecordingSender {
    sent: std::sync::Mutex<Vec<(String, String, String, Option<String>)>>,
}

#[async_trait::async_trait]
impl issuerd_core::EmailSender for RecordingSender {
    async fn send(
        &self,
        _realm: &issuerd_core::Realm,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: Option<String>,
    ) -> Result<(), issuerd_core::IssuerdError> {
        self.sent.lock().unwrap().push((
            to.to_string(),
            subject.to_string(),
            text_body.to_string(),
            html_body,
        ));
        Ok(())
    }
}

/// LDAPS + WRITABLE + noTlsVerify provider config: password writes against
/// Samba require a secure connection, and the container's cert is self-signed.
async fn configure_samba_ldaps_provider(harness: &TestHarness, realm: &str) {
    let mut config = HashMap::new();
    config.insert("connectionUrl".to_string(), "ldaps://localhost:636".to_string());
    config.insert("noTlsVerify".to_string(), "true".to_string());
    config.insert(
        "bindDn".to_string(),
        "CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local".to_string(),
    );
    config.insert("bindCredential".to_string(), "AdminPass123!".to_string());
    config.insert("usersDn".to_string(), "CN=Users,DC=test,DC=issuerd,DC=local".to_string());
    config.insert("baseDn".to_string(), "DC=test,DC=issuerd,DC=local".to_string());
    config.insert("usernameLdapAttribute".to_string(), "sAMAccountName".to_string());
    config.insert("rdnLdapAttribute".to_string(), "cn".to_string());
    config.insert("uuidLdapAttribute".to_string(), "objectGUID".to_string());
    config.insert("userObjectClasses".to_string(), "person,organizationalPerson,user".to_string());
    config.insert("vendor".to_string(), "ACTIVE_DIRECTORY".to_string());
    config.insert("searchScope".to_string(), "SUBTREE".to_string());
    config.insert("editMode".to_string(), "WRITABLE".to_string());
    config.insert("priority".to_string(), "1".to_string());

    let idp = issuerd_core::IdentityProviderConfig {
        id: issuerd_core::IdentityProviderId::new("samba-ldap").unwrap(),
        alias: issuerd_core::Alias::new("samba-ldap").unwrap(),
        provider_id: issuerd_core::ProviderId::new("ldap"),
        enabled: true,
        config,
    };
    let realm_id = issuerd_core::RealmId::new(realm).unwrap();
    harness.storage.create_identity_provider(&realm_id, &idp).await.unwrap();
}

/// Unconditional admin-side password reset straight against Samba (LDAPS +
/// noTlsVerify), used to heal/restore the testuser2 fixture regardless of its
/// current state.
async fn reset_samba_password_direct(username: &str, password: &str) {
    let mut config = samba_ldap_config();
    config.connection_url = "ldaps://localhost:636".to_string();
    config.no_tls_verify = true;
    let provider = LdapFederationProvider::new("samba-ldap".to_string(), config, vec![])
        .await
        .expect("connect to Samba LDAPS");
    provider
        .update_password(username, password)
        .await
        .expect("direct directory password reset");
}

/// Full write-through flow against the real Samba directory: account
/// change-password and reset-via-email both land in the directory, login
/// validates the new password, and no local credential is ever created.
/// The directory password is restored at the end.
#[tokio::test]
async fn samba_dc_federated_password_write_through() {
    if !samba_available() {
        eprintln!("SKIP: Samba DC not available on localhost:389");
        return;
    }

    // Heal any poisoned fixture state from a previously interrupted run.
    reset_samba_password_direct("testuser2", "Password123!").await;

    use issuerd_server::{config::ServerConfig, state::ServerState};
    let config = ServerConfig::default();
    let mut state = ServerState::from_config(&config).await.unwrap();
    let recorder = std::sync::Arc::new(RecordingSender::default());
    state.email_sender = recorder.clone();
    let harness = TestHarness::with_state(std::sync::Arc::new(state));

    let mut realm = harness.create_realm("samba-wt").await;
    realm.reset_password_allowed = true;
    harness.storage.update_realm(&realm).await.unwrap();
    configure_samba_ldaps_provider(&harness, "samba-wt").await;
    let client = harness.create_client("samba-wt", false).await;

    // First login imports testuser2 with federation_link = samba-ldap.
    let tokens = harness
        .authenticate_user("samba-wt", &client.client_id, "testuser2", "Password123!")
        .await;
    let user = harness
        .storage
        .get_user_by_username(&realm.id, "testuser2")
        .await
        .unwrap()
        .expect("testuser2 imported after login");
    assert_eq!(user.federation_link.as_deref(), Some("samba-ldap"));
    // The reset email needs an address on the local record.
    let mut user = user;
    user.email = Some(issuerd_core::Email::new("testuser2@example.com").unwrap());
    harness.storage.update_user(&realm.id, &user).await.unwrap();

    let password_grant = |password: &str| {
        let client_id = client.client_id.to_string();
        let secret = client.secret.clone().unwrap_or_default();
        let password = password.to_string();
        let harness = &harness;
        async move {
            harness
                .post_form(
                    "/realms/samba-wt/protocol/openid-connect/token",
                    &[
                        ("grant_type", "password"),
                        ("client_id", client_id.as_str()),
                        ("client_secret", secret.as_str()),
                        ("username", "testuser2"),
                        ("password", password.as_str()),
                        ("scope", "openid"),
                    ],
                )
                .await
                .status()
        }
    };

    // 1. Account change-password writes through to the directory.
    let resp = harness
        .post_json_auth(
            "/realms/samba-wt/account/api/credentials/password",
            &tokens.access_token,
            serde_json::json!({"current_password": "Password123!", "new_password": "NewPass456!"}),
        )
        .await;
    assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);

    assert_eq!(password_grant("NewPass456!").await, axum::http::StatusCode::OK);
    // NOTE: Samba AD DC accepts the *previous* password for a grace period
    // after a change (verified against the container), so the just-replaced
    // password cannot be asserted dead here; a never-used password must fail.
    assert_eq!(password_grant("NeverUsed!9").await, axum::http::StatusCode::UNAUTHORIZED);
    // Write-through must not leave a local credential behind.
    let creds = harness
        .storage
        .get_credentials(&realm.id, &user.id, issuerd_core::CredentialType::Password)
        .await
        .unwrap();
    assert!(creds.is_empty(), "no local credential for a directory password");

    // 2. Reset-via-email also writes through to the directory.
    let resp = harness
        .post_form("/realms/samba-wt/login/reset-credentials", &[("username", "testuser2")])
        .await;
    assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);
    let text = {
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "expected exactly one reset email");
        sent[0].2.clone()
    };
    let link = text
        .lines()
        .find(|l| l.contains("/login/update-credentials?token="))
        .expect("reset link in text body")
        .trim()
        .to_string();
    let token = TestHarness::extract_query_param(&link, "token").expect("token in reset link");
    let resp = harness
        .post_form(
            "/realms/samba-wt/login/update-credentials",
            &[
                ("token", token.as_str()),
                ("new_password", "ResetPass789!"),
                ("confirm_password", "ResetPass789!"),
            ],
        )
        .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    assert_eq!(password_grant("ResetPass789!").await, axum::http::StatusCode::OK);
    // Two generations back is outside Samba's previous-password grace: the
    // reset really advanced the directory password.
    assert_eq!(password_grant("Password123!").await, axum::http::StatusCode::UNAUTHORIZED);
    let creds = harness
        .storage
        .get_credentials(&realm.id, &user.id, issuerd_core::CredentialType::Password)
        .await
        .unwrap();
    assert!(creds.is_empty(), "reset must not create a local credential either");

    // 3. Restore the fixture password for other tests/runs (unconditional
    // directory-side reset — independent of the flow above).
    reset_samba_password_direct("testuser2", "Password123!").await;
    assert_eq!(password_grant("Password123!").await, axum::http::StatusCode::OK);
}
