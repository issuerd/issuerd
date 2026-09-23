// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Large-scale federation load test against OpenLDAP (bulk user/group sync and validation).

//! Large-scale load test against OpenLDAP.
//!
//! Requires:
//!   ISSUERD_FEDERATION_LOAD_TEST=openldap (or all)
//!   docker compose -f docker-compose.integration.yml up -d postgres openldap

use crate::federation_load_common::*;
use issuerd_federation::ldap::connection::LdapClient;

const TOTAL_USERS: usize = 100_000;
const TOTAL_GROUPS: usize = 1_000;
const USERS_PER_GROUP: usize = TOTAL_USERS / TOTAL_GROUPS;
const CHUNK_SIZE: usize = 5_000;

#[tokio::test]
async fn openldap_load_test_100k_users() {
    if !load_test_enabled("openldap") {
        eprintln!("SKIP: set ISSUERD_FEDERATION_LOAD_TEST=openldap to run this test");
        return;
    }

    // ------------------------------------------------------------------
    // 1. Reset environment
    // ------------------------------------------------------------------
    reset_docker_service("openldap");
    assert!(
        wait_for_port("127.0.0.1", 1389, 120),
        "OpenLDAP did not become available on port 1389"
    );
    assert!(
        wait_for_ldap_ready(
            "issuerd-openldap",
            "cn=admin,dc=test,dc=issuerd,dc=local",
            "admin",
            120
        ),
        "OpenLDAP LDAP did not become ready"
    );

    // ------------------------------------------------------------------
    // 2. Bulk create users and groups via LDIF
    // ------------------------------------------------------------------
    eprintln!("[load-test] Creating {TOTAL_USERS} users in OpenLDAP...");
    let user_chunks = TOTAL_USERS.div_ceil(CHUNK_SIZE);
    for chunk in 0..user_chunks {
        let start = chunk * CHUNK_SIZE;
        let count = (start + CHUNK_SIZE).min(TOTAL_USERS) - start;
        let ldif_path = format!("/tmp/openldap_users_{chunk}.ldif");
        write_openldap_user_ldif_chunk(&ldif_path, start, count);
        docker_cp(&ldif_path, "issuerd-openldap", &ldif_path);
        import_ldif_into_container(
            "issuerd-openldap",
            "cn=admin,dc=test,dc=issuerd,dc=local",
            "admin",
            &ldif_path,
        );
        std::fs::remove_file(&ldif_path).ok();
        eprintln!("[load-test]  ... users {}-{} done", start, start + count - 1);
    }

    eprintln!("[load-test] Creating {TOTAL_GROUPS} groups in OpenLDAP...");
    let group_chunks = TOTAL_GROUPS.div_ceil(CHUNK_SIZE);
    for chunk in 0..group_chunks {
        let start = chunk * CHUNK_SIZE;
        let count = (start + CHUNK_SIZE).min(TOTAL_GROUPS) - start;
        let ldif_path = format!("/tmp/openldap_groups_{chunk}.ldif");
        write_openldap_group_ldif_chunk(&ldif_path, start, count);
        docker_cp(&ldif_path, "issuerd-openldap", &ldif_path);
        import_ldif_into_container(
            "issuerd-openldap",
            "cn=admin,dc=test,dc=issuerd,dc=local",
            "admin",
            &ldif_path,
        );
        std::fs::remove_file(&ldif_path).ok();
        eprintln!("[load-test]  ... groups {}-{} done", start, start + count - 1);
    }

    eprintln!("[load-test] Assigning group memberships...");
    let membership_chunk_size = 100;
    let membership_chunks = TOTAL_GROUPS.div_ceil(membership_chunk_size);
    for chunk in 0..membership_chunks {
        let start = chunk * membership_chunk_size;
        let end = (start + membership_chunk_size).min(TOTAL_GROUPS);
        let group_indices: Vec<usize> = (start..end).collect();
        let ldif_path = format!("/tmp/openldap_members_{chunk}.ldif");
        write_openldap_membership_ldif(&ldif_path, &group_indices, USERS_PER_GROUP);
        docker_cp(&ldif_path, "issuerd-openldap", &ldif_path);
        import_ldif_into_container(
            "issuerd-openldap",
            "cn=admin,dc=test,dc=issuerd,dc=local",
            "admin",
            &ldif_path,
        );
        std::fs::remove_file(&ldif_path).ok();
        eprintln!("[load-test]  ... memberships {}-{} done", start, end - 1);
    }

    // ------------------------------------------------------------------
    // 3. Build Issuerd harness and configure realm
    // ------------------------------------------------------------------
    let harness = LoadTestHarness::new_with_postgres().await;
    let realm = harness.create_realm("openldap-load").await;
    harness.configure_openldap_provider("openldap-load").await;
    let client = harness.create_client("openldap-load", false).await;

    // ------------------------------------------------------------------
    // 4. Full sync
    // ------------------------------------------------------------------
    eprintln!("[load-test] Triggering full sync...");
    let sync_result = harness.trigger_sync("openldap-load", "openldap").await;
    eprintln!("[load-test] Sync result: {sync_result:?}");
    assert!(
        sync_result.added >= TOTAL_USERS - 100,
        "expected at least {} users added, got {}",
        TOTAL_USERS,
        sync_result.added
    );

    let u0 = harness.storage.get_user_by_username(&realm.id, "loaduser_0").await.unwrap();
    assert!(u0.is_some(), "loaduser_0 should be imported");

    // ------------------------------------------------------------------
    // 5. Sample login tests (100 users)
    // ------------------------------------------------------------------
    eprintln!("[load-test] Testing login for 100 sample users...");
    for i in 0..100 {
        let username = format!("loaduser_{i}");
        let tokens = harness
            .authenticate_user("openldap-load", &client.client_id, &username, "Password123!")
            .await;
        assert!(!tokens.access_token.is_empty(), "login failed for {username}");
    }
    eprintln!("[load-test] Login tests passed.");

    // ------------------------------------------------------------------
    // 6. Group changes in LDAP, re-sync
    // ------------------------------------------------------------------
    eprintln!("[load-test] Changing group memberships for 100 users in LDAP...");
    let mut conn = issuerd_federation::ldap::connection::LdapConnection::connect(
        "ldap://localhost:1389",
        false,
        false,
    )
    .await
    .expect("connect to OpenLDAP");
    conn.bind("cn=admin,dc=test,dc=issuerd,dc=local", "admin")
        .await
        .expect("bind as admin");

    for i in 100..200 {
        let old_group = i / USERS_PER_GROUP;
        let new_group = 500 + (i - 100);
        let user_dn = format!("uid=loaduser_{i},ou=users,dc=test,dc=issuerd,dc=local");
        let old_group_dn =
            format!("cn=loadgroup_{old_group},ou=groups,dc=test,dc=issuerd,dc=local");
        let new_group_dn =
            format!("cn=loadgroup_{new_group},ou=groups,dc=test,dc=issuerd,dc=local");

        // Remove from old group
        if let Err(e) = conn
            .modify_replace(&old_group_dn, "member", &[user_dn.clone().into_bytes()])
            .await
        {
            eprintln!("[load-test] warning removing member: {e}");
        }
        // Add to new group
        if let Err(e) = conn.modify_add(&new_group_dn, "member", &[user_dn.into_bytes()]).await {
            eprintln!("[load-test] warning adding member: {e}");
        }
    }

    let sync_result2 = harness.trigger_sync("openldap-load", "openldap").await;
    eprintln!("[load-test] Re-sync result: {sync_result2:?}");
    assert!(
        sync_result2.updated >= 100,
        "expected at least 100 updated, got {}",
        sync_result2.updated
    );

    let tokens = harness
        .authenticate_user("openldap-load", &client.client_id, "loaduser_150", "Password123!")
        .await;
    assert!(!tokens.access_token.is_empty());
    eprintln!("[load-test] Group change test passed.");

    // ------------------------------------------------------------------
    // 7. Disable 50 users
    // ------------------------------------------------------------------
    eprintln!("[load-test] Disabling 50 users in LDAP...");
    for i in 200..250 {
        let user_dn = format!("uid=loaduser_{i},ou=users,dc=test,dc=issuerd,dc=local");
        // OpenLDAP: change password to something random to prevent bind
        let random_pw = format!("disabled_{}", issuerd_core::utils::generate_id());
        if let Err(e) =
            conn.modify_replace(&user_dn, "userPassword", &[random_pw.into_bytes()]).await
        {
            eprintln!("[load-test] warning disabling user: {e}");
        }
    }

    let sync_result3 = harness.trigger_sync("openldap-load", "openldap").await;
    eprintln!("[load-test] Disable sync result: {sync_result3:?}");

    // Verify disabled user cannot login
    let auth_path = format!(
        "/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        realm.name, client.client_id
    );
    let auth_resp = harness.get(&auth_path).await;
    assert_eq!(auth_resp.status(), axum::http::StatusCode::SEE_OTHER);
    let location = auth_resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id = LoadTestHarness::extract_query_param(location, "execution_id").unwrap();

    let login_resp = harness
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={}", realm.name),
            serde_json::json!({
                "execution_id": execution_id,
                "username": "loaduser_200",
                "password": "Password123!",
            }),
            &LoadTestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert!(
        login_resp.status().is_client_error(),
        "expected login failure for disabled user, got {:?}",
        login_resp.status()
    );
    eprintln!("[load-test] Disable test passed.");

    // ------------------------------------------------------------------
    // 8. Password changes for 50 users
    // ------------------------------------------------------------------
    eprintln!("[load-test] Changing passwords for 50 users...");
    for i in 250..300 {
        let user_dn = format!("uid=loaduser_{i},ou=users,dc=test,dc=issuerd,dc=local");
        let new_pass = "NewPass456!";
        if let Err(e) = conn
            .modify_replace(&user_dn, "userPassword", &[new_pass.as_bytes().to_vec()])
            .await
        {
            eprintln!("[load-test] warning changing password: {e}");
        }
    }

    let tokens = harness
        .authenticate_user("openldap-load", &client.client_id, "loaduser_250", "NewPass456!")
        .await;
    assert!(!tokens.access_token.is_empty(), "new password should work");

    let auth_resp2 = harness.get(&auth_path).await;
    let location2 = auth_resp2.headers().get("location").unwrap().to_str().unwrap();
    let execution_id2 = LoadTestHarness::extract_query_param(location2, "execution_id").unwrap();
    let login_resp2 = harness
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={}", realm.name),
            serde_json::json!({
                "execution_id": execution_id2,
                "username": "loaduser_250",
                "password": "Password123!",
            }),
            &LoadTestHarness::flow_cookie(&execution_id2),
        )
        .await;
    assert!(
        login_resp2.status().is_client_error(),
        "old password should fail, got {:?}",
        login_resp2.status()
    );
    eprintln!("[load-test] Password change test passed.");

    eprintln!("[load-test] OpenLDAP load test COMPLETE.");
}
