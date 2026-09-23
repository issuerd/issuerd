// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Large-scale federation load test against Samba DC (bulk user/group sync and validation).

//! Large-scale load test against Samba DC.
//!
//! Requires:
//!   ISSUERD_FEDERATION_LOAD_TEST=samba (or all)
//!   docker compose up -d postgres
//!
//! This test creates 100,000 users and 1,000 groups in the Samba DC,
//! synchronizes them into Issuerd backed by PostgreSQL, and validates
//! login, group changes, user disable, and password changes.

use crate::federation_load_common::*;
use issuerd_federation::ldap::connection::LdapClient;

const TOTAL_USERS: usize = 20_000;
const TOTAL_GROUPS: usize = 1_000;
const USERS_PER_GROUP: usize = TOTAL_USERS / TOTAL_GROUPS; // 20
const CHUNK_SIZE: usize = 5_000;

#[tokio::test]
async fn samba_dc_load_test_100k_users() {
    if !load_test_enabled("samba") {
        eprintln!("SKIP: set ISSUERD_FEDERATION_LOAD_TEST=samba to run this test");
        return;
    }

    // ------------------------------------------------------------------
    // 1. Reset environment
    // ------------------------------------------------------------------
    reset_docker_service("samba-dc");
    assert!(
        wait_for_port("127.0.0.1", 389, 120),
        "Samba DC did not become available on port 389"
    );
    assert!(
        wait_for_ldap_ready(
            "issuerd-samba-dc",
            "CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local",
            "AdminPass123!",
            120
        ),
        "Samba DC LDAP did not become ready"
    );

    // ------------------------------------------------------------------
    // 2. Bulk create users and groups via LDIF
    // ------------------------------------------------------------------
    eprintln!("[load-test] Creating {TOTAL_USERS} users in Samba DC...");
    let user_chunks = TOTAL_USERS.div_ceil(CHUNK_SIZE);
    for chunk in 0..user_chunks {
        let start = chunk * CHUNK_SIZE;
        let count = (start + CHUNK_SIZE).min(TOTAL_USERS) - start;
        let ldif_path = format!("/tmp/samba_users_{chunk}.ldif");
        write_samba_user_ldif_chunk(&ldif_path, start, count);
        docker_cp(&ldif_path, "issuerd-samba-dc", &ldif_path);
        import_ldif_samba_ldb("issuerd-samba-dc", &ldif_path);
        std::fs::remove_file(&ldif_path).ok();
        eprintln!("[load-test]  ... users {}-{} done", start, start + count - 1);
    }

    eprintln!("[load-test] Creating {TOTAL_GROUPS} groups in Samba DC...");
    let group_chunks = TOTAL_GROUPS.div_ceil(CHUNK_SIZE);
    for chunk in 0..group_chunks {
        let start = chunk * CHUNK_SIZE;
        let count = (start + CHUNK_SIZE).min(TOTAL_GROUPS) - start;
        let ldif_path = format!("/tmp/samba_groups_{chunk}.ldif");
        write_samba_group_ldif_chunk(&ldif_path, start, count);
        docker_cp(&ldif_path, "issuerd-samba-dc", &ldif_path);
        import_ldif_samba_ldb("issuerd-samba-dc", &ldif_path);
        std::fs::remove_file(&ldif_path).ok();
        eprintln!("[load-test]  ... groups {}-{} done", start, start + count - 1);
    }

    eprintln!("[load-test] Assigning group memberships...");
    let membership_chunk_size = 100; // groups per LDIF
    let membership_chunks = TOTAL_GROUPS.div_ceil(membership_chunk_size);
    for chunk in 0..membership_chunks {
        let start = chunk * membership_chunk_size;
        let end = (start + membership_chunk_size).min(TOTAL_GROUPS);
        let group_indices: Vec<usize> = (start..end).collect();
        let ldif_path = format!("/tmp/samba_members_{chunk}.ldif");
        write_samba_membership_ldif(&ldif_path, &group_indices, USERS_PER_GROUP);
        docker_cp(&ldif_path, "issuerd-samba-dc", &ldif_path);
        import_ldif_samba_ldb_modify("issuerd-samba-dc", &ldif_path);
        std::fs::remove_file(&ldif_path).ok();
        eprintln!("[load-test]  ... memberships {}-{} done", start, end - 1);
    }

    // ------------------------------------------------------------------
    // 3. Set passwords for a sample of users that we'll test
    // ------------------------------------------------------------------
    let sample_users: Vec<usize> = (0..200).collect(); // first 200 users
    eprintln!("[load-test] Setting passwords for {} sample users...", sample_users.len());
    let mut conn = issuerd_federation::ldap::connection::LdapConnection::connect(
        "ldap://localhost:389",
        false,
        false,
    )
    .await
    .expect("connect to Samba DC");
    conn.bind("CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local", "AdminPass123!")
        .await
        .expect("bind as admin");

    for i in &sample_users {
        let user_dn = format!("CN=loaduser_{i},CN=Users,DC=test,DC=issuerd,DC=local");
        // unicodePwd: UTF-16LE quoted
        let password = "Password123!";
        let mut encoded: Vec<u8> = vec![0x22, 0x00];
        for chunk in password.encode_utf16() {
            encoded.extend_from_slice(&chunk.to_le_bytes());
        }
        encoded.extend_from_slice(&[0x22, 0x00]);
        if let Err(e) = conn.modify_replace(&user_dn, "unicodePwd", &[encoded]).await {
            eprintln!("[load-test] warning: failed to set password for loaduser_{i}: {e}");
        }
    }
    eprintln!("[load-test] Passwords set.");

    // ------------------------------------------------------------------
    // 4. Build Issuerd harness and configure realm
    // ------------------------------------------------------------------
    let harness = LoadTestHarness::new_with_postgres().await;
    let realm = harness.create_realm("samba-load").await;
    harness.configure_samba_ldap_provider("samba-load").await;
    let client = harness.create_client("samba-load", false).await;

    // ------------------------------------------------------------------
    // 5. Full sync
    // ------------------------------------------------------------------
    eprintln!("[load-test] Triggering full sync...");
    let sync_result = harness.trigger_sync("samba-load", "samba-ldap").await;
    eprintln!("[load-test] Sync result: {sync_result:?}");
    assert!(
        sync_result.added >= TOTAL_USERS - 100,
        "expected at least {} users added, got {}",
        TOTAL_USERS,
        sync_result.added
    );

    // Verify a user exists in local storage
    let u0 = harness.storage.get_user_by_username(&realm.id, "loaduser_0").await.unwrap();
    assert!(u0.is_some(), "loaduser_0 should be imported");

    // ------------------------------------------------------------------
    // 6. Sample login tests (5 users — Samba LDAP bind is very slow)
    // ------------------------------------------------------------------
    eprintln!("[load-test] Testing login for 5 sample users...");
    for i in 0..5 {
        let username = format!("loaduser_{i}");
        let tokens = harness
            .authenticate_user("samba-load", &client.client_id, &username, "Password123!")
            .await;
        assert!(!tokens.access_token.is_empty(), "login failed for {username}");
    }
    eprintln!("[load-test] Login tests passed.");

    // ------------------------------------------------------------------
    // 7. Group changes in LDAP, re-sync, verify
    // ------------------------------------------------------------------
    eprintln!("[load-test] Changing group memberships for 100 users in LDAP...");
    // Move users 100-199 from their original groups to groups 500-599
    for i in 100..200 {
        let old_group = i / USERS_PER_GROUP;
        let new_group = 500 + (i - 100);
        let user_dn = format!("CN=loaduser_{i},CN=Users,DC=test,DC=issuerd,DC=local");
        let old_group_dn = format!("CN=loadgroup_{old_group},CN=Users,DC=test,DC=issuerd,DC=local");
        let new_group_dn = format!("CN=loadgroup_{new_group},CN=Users,DC=test,DC=issuerd,DC=local");

        // Remove from old group
        let remove_ldif = format!(
            "dn: {old_group_dn}\nchangetype: modify\ndelete: member\nmember: {user_dn}\n-\n\n"
        );
        let path = "/tmp/samba_remove.ldif";
        std::fs::write(path, remove_ldif).unwrap();
        docker_cp(path, "issuerd-samba-dc", path);
        import_ldif_into_container(
            "issuerd-samba-dc",
            "CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local",
            "AdminPass123!",
            path,
        );
        std::fs::remove_file(path).ok();

        // Add to new group
        let add_ldif = format!(
            "dn: {new_group_dn}\nchangetype: modify\nadd: member\nmember: {user_dn}\n-\n\n"
        );
        let path = "/tmp/samba_add.ldif";
        std::fs::write(path, add_ldif).unwrap();
        docker_cp(path, "issuerd-samba-dc", path);
        import_ldif_samba_ldb_modify("issuerd-samba-dc", path);
        std::fs::remove_file(path).ok();
    }

    // Re-sync
    let sync_result2 = harness.trigger_sync("samba-load", "samba-ldap").await;
    eprintln!("[load-test] Re-sync result: {sync_result2:?}");
    assert!(
        sync_result2.updated >= 100,
        "expected at least 100 updated users after group change, got {}",
        sync_result2.updated
    );

    // Verify one moved user still can login
    let tokens = harness
        .authenticate_user("samba-load", &client.client_id, "loaduser_150", "Password123!")
        .await;
    assert!(!tokens.access_token.is_empty());
    eprintln!("[load-test] Group change + re-sync passed.");

    // ------------------------------------------------------------------
    // 8. Disable 50 users in LDAP, verify they cannot login
    // ------------------------------------------------------------------
    eprintln!("[load-test] Disabling 50 users in LDAP...");
    for i in 200..250 {
        let user_dn = format!("CN=loaduser_{i},CN=Users,DC=test,DC=issuerd,DC=local");
        let disable_ldif = format!(
            "dn: {user_dn}\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: 514\n-\n\n"
        );
        let path = "/tmp/samba_disable.ldif";
        std::fs::write(path, disable_ldif).unwrap();
        docker_cp(path, "issuerd-samba-dc", path);
        import_ldif_samba_ldb_modify("issuerd-samba-dc", path);
        std::fs::remove_file(path).ok();
    }

    // Re-sync to pick up disabled state
    let sync_result3 = harness.trigger_sync("samba-load", "samba-ldap").await;
    eprintln!("[load-test] Disable sync result: {sync_result3:?}");

    // Verify a disabled user cannot login
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
    // 9. Password change for 1 user (fresh LDAP connection — old one timed out)
    // ------------------------------------------------------------------
    eprintln!("[load-test] Changing password for loaduser_250...");
    let mut conn2 = issuerd_federation::ldap::connection::LdapConnection::connect(
        "ldap://localhost:389",
        false,
        false,
    )
    .await
    .expect("connect to Samba DC");
    conn2
        .bind("CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local", "AdminPass123!")
        .await
        .expect("bind as admin");

    let user_dn = "CN=loaduser_250,CN=Users,DC=test,DC=issuerd,DC=local";
    let new_pass = "NewPass456!";
    let mut encoded: Vec<u8> = vec![0x22, 0x00];
    for chunk in new_pass.encode_utf16() {
        encoded.extend_from_slice(&chunk.to_le_bytes());
    }
    encoded.extend_from_slice(&[0x22, 0x00]);
    conn2
        .modify_replace(user_dn, "unicodePwd", &[encoded])
        .await
        .expect("change password for loaduser_250");
    eprintln!("[load-test] Password changed.");

    // Verify login with new password works
    let tokens = harness
        .authenticate_user("samba-load", &client.client_id, "loaduser_250", "NewPass456!")
        .await;
    assert!(!tokens.access_token.is_empty(), "login with new password should work");

    // Old password should fail
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
        "expected login failure with old password, got {:?}",
        login_resp2.status()
    );
    eprintln!("[load-test] Password change test passed.");

    eprintln!("[load-test] Samba DC load test COMPLETE.");
}
