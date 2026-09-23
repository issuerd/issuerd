// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Large-scale federation load test against a real Windows Server Active Directory lab.

//! Large-scale load test against real Windows Server Active Directory.
//!
//! Requires:
//!   ISSUERD_FEDERATION_LOAD_TEST=ad (or all)
//!   An AD lab configured via the ISSUERD_TEST_AD_* environment variables
//!   (see `AdLab` in tests/harness), including _ADMIN_PASSWORD and the
//!   Hyper-V reset target _VM_NAME / _VM_SNAPSHOT
//!   PostgreSQL running on localhost:5432

use crate::federation_load_common::*;
use crate::harness::AdLab;
use issuerd_federation::ldap::connection::{LdapClient, LdapConnection};

const TOTAL_USERS: usize = 100_000;
const TOTAL_GROUPS: usize = 1_000;
const USERS_PER_GROUP: usize = TOTAL_USERS / TOTAL_GROUPS;
const CONCURRENCY: usize = 5;

#[tokio::test]
async fn ad_load_test_100k_users() {
    if !load_test_enabled("ad") {
        eprintln!("SKIP: set ISSUERD_FEDERATION_LOAD_TEST=ad to run this test");
        return;
    }

    let lab = AdLab::from_env().expect(
        "set ISSUERD_TEST_AD_HOST and ISSUERD_TEST_AD_BIND_CREDENTIAL for the AD load test",
    );
    let ad_host = lab.host.clone();
    let ad_ldap_url = lab.ldap_url();
    let ad_ldaps_url = lab.ldaps_url();
    let ad_bind_dn = lab.bind_dn.clone();
    let ad_bind_pw = lab.bind_credential.clone();
    let ad_admin_dn = lab.admin_dn.clone();
    // Administrator credentials are required for bulk user/group creation.
    let ad_admin_pw = lab
        .admin_password
        .clone()
        .expect("set ISSUERD_TEST_AD_ADMIN_PASSWORD for the AD load test");
    let ad_users_dn = lab.users_dn.clone();
    let ad_groups_dn = lab.groups_dn.clone();
    let (vm_name, vm_snapshot) = match (lab.vm_name.clone(), lab.vm_snapshot.clone()) {
        (Some(vm), Some(snapshot)) => (vm, snapshot),
        _ => panic!(
            "set ISSUERD_TEST_AD_VM_NAME and ISSUERD_TEST_AD_VM_SNAPSHOT for the AD load test"
        ),
    };

    // ------------------------------------------------------------------
    // 1. Reset environment
    // ------------------------------------------------------------------
    reset_hyperv_vm(&vm_name, &vm_snapshot);
    assert!(
        wait_for_port(&ad_host, 389, 300),
        "AD did not become available on {ad_host}:389"
    );

    // ------------------------------------------------------------------
    // 2. Bulk create users via direct LDAP adds (concurrent)
    // ------------------------------------------------------------------
    eprintln!("[load-test] Creating {TOTAL_USERS} users in AD...");
    let users_per_task = TOTAL_USERS / CONCURRENCY;
    let mut handles = Vec::new();

    for task_id in 0..CONCURRENCY {
        let start = task_id * users_per_task;
        let end = if task_id == CONCURRENCY - 1 {
            TOTAL_USERS
        } else {
            start + users_per_task
        };

        let (ldap_url, admin_dn, admin_pw, users_dn) = (
            ad_ldap_url.clone(),
            ad_admin_dn.clone(),
            ad_admin_pw.clone(),
            ad_users_dn.clone(),
        );
        handles.push(tokio::spawn(async move {
            let mut conn = LdapConnection::connect(&ldap_url, false, false).await.expect("connect to AD");
            conn.bind(&admin_dn, &admin_pw).await.expect("bind to AD as admin");

            let mut success = 0usize;
            let mut failed = 0usize;
            for i in start..end {
                let user_dn = format!("CN=loaduser_{i},{users_dn}");
                let attrs = vec![
                    (
                        "objectClass".to_string(),
                        vec![
                            "top".to_string(),
                            "person".to_string(),
                            "organizationalPerson".to_string(),
                            "user".to_string(),
                        ],
                    ),
                    ("cn".to_string(), vec![format!("loaduser_{i}")]),
                    ("sAMAccountName".to_string(), vec![format!("loaduser_{i}")]),
                    ("givenName".to_string(), vec!["Load".to_string()]),
                    ("sn".to_string(), vec![format!("User{i}")]),
                    ("mail".to_string(), vec![format!("loaduser_{i}@test.issuerd.local")]),
                    ("userAccountControl".to_string(), vec!["544".to_string()]), // enabled, passwd_not_reqd
                ];
                if let Err(e) = conn.add(&user_dn, attrs).await {
                    failed += 1;
                    if failed <= 5 {
                        eprintln!("[load-test] warning: failed to add loaduser_{i}: {e}");
                    }
                } else {
                    success += 1;
                }
                if i > start && (i - start).is_multiple_of(1000) {
                    eprintln!("[load-test]  ... task {task_id} users {start}-{i} done (ok={success}, err={failed})");
                }
            }
            eprintln!("[load-test]  ... task {task_id} complete ({start}-{end}) ok={success} err={failed}");
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
    eprintln!("[load-test] User creation complete.");

    // ------------------------------------------------------------------
    // 3. Bulk create groups
    // ------------------------------------------------------------------
    eprintln!("[load-test] Creating {TOTAL_GROUPS} groups in AD...");
    let mut conn = LdapConnection::connect(&ad_ldap_url, false, false)
        .await
        .expect("connect to AD");
    conn.bind(&ad_admin_dn, &ad_admin_pw).await.expect("bind to AD as admin");

    // Ensure the groups OU exists
    let groups_ou_dn = ad_groups_dn.clone();
    let groups_ou_attrs = vec![
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "organizationalUnit".to_string()],
        ),
        ("ou".to_string(), vec!["IssuerdGroups".to_string()]),
    ];
    if let Err(e) = conn.add(&groups_ou_dn, groups_ou_attrs).await {
        eprintln!("[load-test] warning: failed to create groups OU (may already exist): {e}");
    }

    for i in 0..TOTAL_GROUPS {
        let group_dn = format!("CN=loadgroup_{i},{ad_groups_dn}");
        let attrs = vec![
            ("objectClass".to_string(), vec!["top".to_string(), "group".to_string()]),
            ("cn".to_string(), vec![format!("loadgroup_{i}")]),
            ("groupType".to_string(), vec!["-2147483646".to_string()]),
        ];
        if let Err(e) = conn.add(&group_dn, attrs).await {
            eprintln!("[load-test] warning: failed to add loadgroup_{i}: {e}");
        }
        if i > 0 && i % 100 == 0 {
            eprintln!("[load-test]  ... groups 0-{i} done");
        }
    }
    eprintln!("[load-test] Group creation complete.");

    // ------------------------------------------------------------------
    // 4. Assign group memberships
    // ------------------------------------------------------------------
    eprintln!("[load-test] Assigning group memberships...");
    for gi in 0..TOTAL_GROUPS {
        let group_dn = format!("CN=loadgroup_{gi},{ad_groups_dn}");
        for ui in 0..USERS_PER_GROUP {
            let user_idx = gi * USERS_PER_GROUP + ui;
            let user_dn = format!("CN=loaduser_{user_idx},{ad_users_dn}");
            if let Err(e) = conn.modify_add(&group_dn, "member", &[user_dn.into_bytes()]).await {
                eprintln!("[load-test] warning adding member: {e}");
            }
        }
        if gi > 0 && gi % 100 == 0 {
            eprintln!("[load-test]  ... memberships for groups 0-{gi} done");
        }
    }
    eprintln!("[load-test] Membership assignment complete.");

    // ------------------------------------------------------------------
    // 5. Set passwords for sample users over LDAPS
    // ------------------------------------------------------------------
    eprintln!("[load-test] Setting passwords for sample users via LDAPS...");
    let ldaps_conn = LdapConnection::connect(&ad_ldaps_url, false, true).await;
    let mut ldaps_conn = match ldaps_conn {
        Ok(mut c) => {
            if let Err(e) = c.bind(&ad_bind_dn, &ad_bind_pw).await {
                eprintln!("[load-test] LDAPS bind failed: {e}, password tests will be skipped");
                None
            } else {
                Some(c)
            }
        }
        Err(e) => {
            eprintln!("[load-test] LDAPS connection failed: {e}, password tests will be skipped");
            None
        }
    };

    if let Some(ref mut c) = ldaps_conn {
        for i in 0..300 {
            let user_dn = format!("CN=loaduser_{i},{ad_users_dn}");
            let password = "Password123!";
            let mut encoded: Vec<u8> = vec![0x22, 0x00];
            for chunk in password.encode_utf16() {
                encoded.extend_from_slice(&chunk.to_le_bytes());
            }
            encoded.extend_from_slice(&[0x22, 0x00]);
            if let Err(e) = c.modify_replace(&user_dn, "unicodePwd", &[encoded]).await {
                eprintln!("[load-test] warning: failed to set password for loaduser_{i}: {e}");
            }
        }
        eprintln!("[load-test] Passwords set for 300 sample users.");
    }

    // ------------------------------------------------------------------
    // 6. Build Issuerd harness and configure realm
    // ------------------------------------------------------------------
    let harness = LoadTestHarness::new_with_postgres().await;
    let realm = harness.create_realm("ad-load").await;
    harness.configure_ad_provider("ad-load", &lab).await;
    let client = harness.create_client("ad-load", false).await;

    // ------------------------------------------------------------------
    // 7. Full sync
    // ------------------------------------------------------------------
    eprintln!("[load-test] Triggering full sync...");
    let sync_result = harness.trigger_sync("ad-load", "ad-ldap").await;
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
    // 8. Sample login tests (only if LDAPS worked)
    // ------------------------------------------------------------------
    if ldaps_conn.is_some() {
        eprintln!("[load-test] Testing login for 100 sample users...");
        for i in 0..100 {
            let username = format!("loaduser_{i}");
            let tokens = harness
                .authenticate_user("ad-load", &client.client_id, &username, "Password123!")
                .await;
            assert!(!tokens.access_token.is_empty(), "login failed for {username}");
        }
        eprintln!("[load-test] Login tests passed.");
    } else {
        eprintln!("[load-test] SKIPPING login tests (no LDAPS)");
    }

    // ------------------------------------------------------------------
    // 9. Group changes in LDAP, re-sync
    // ------------------------------------------------------------------
    eprintln!("[load-test] Changing group memberships for 100 users in LDAP...");
    for i in 100..200 {
        let old_group = i / USERS_PER_GROUP;
        let new_group = 500 + (i - 100);
        let user_dn = format!("CN=loaduser_{i},{ad_users_dn}");
        let old_group_dn = format!("CN=loadgroup_{old_group},{ad_groups_dn}");
        let new_group_dn = format!("CN=loadgroup_{new_group},{ad_groups_dn}");

        if let Err(e) = conn
            .modify_replace(&old_group_dn, "member", &[user_dn.clone().into_bytes()])
            .await
        {
            eprintln!("[load-test] warning removing member: {e}");
        }
        if let Err(e) = conn.modify_add(&new_group_dn, "member", &[user_dn.into_bytes()]).await {
            eprintln!("[load-test] warning adding member: {e}");
        }
    }

    let sync_result2 = harness.trigger_sync("ad-load", "ad-ldap").await;
    eprintln!("[load-test] Re-sync result: {sync_result2:?}");
    assert!(
        sync_result2.updated >= 100,
        "expected at least 100 updated, got {}",
        sync_result2.updated
    );

    if ldaps_conn.is_some() {
        let tokens = harness
            .authenticate_user("ad-load", &client.client_id, "loaduser_150", "Password123!")
            .await;
        assert!(!tokens.access_token.is_empty());
    }
    eprintln!("[load-test] Group change test passed.");

    // ------------------------------------------------------------------
    // 10. Disable 50 users
    // ------------------------------------------------------------------
    eprintln!("[load-test] Disabling 50 users in AD...");
    for i in 200..250 {
        let user_dn = format!("CN=loaduser_{i},{ad_users_dn}");
        if let Err(e) =
            conn.modify_replace(&user_dn, "userAccountControl", &[b"514".to_vec()]).await
        {
            eprintln!("[load-test] warning disabling user: {e}");
        }
    }

    let sync_result3 = harness.trigger_sync("ad-load", "ad-ldap").await;
    eprintln!("[load-test] Disable sync result: {sync_result3:?}");

    let auth_path = format!(
        "/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz",
        realm.name, client.client_id
    );

    if ldaps_conn.is_some() {
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
    } else {
        eprintln!("[load-test] SKIPPING disable login verification (no LDAPS)");
    }

    // ------------------------------------------------------------------
    // 11. Password changes for 50 users
    // ------------------------------------------------------------------
    if let Some(ref mut c) = ldaps_conn {
        eprintln!("[load-test] Changing passwords for 50 users...");
        for i in 250..300 {
            let user_dn = format!("CN=loaduser_{i},{ad_users_dn}");
            let new_pass = "NewPass456!";
            let mut encoded: Vec<u8> = vec![0x22, 0x00];
            for chunk in new_pass.encode_utf16() {
                encoded.extend_from_slice(&chunk.to_le_bytes());
            }
            encoded.extend_from_slice(&[0x22, 0x00]);
            if let Err(e) = c.modify_replace(&user_dn, "unicodePwd", &[encoded]).await {
                eprintln!("[load-test] warning changing password: {e}");
            }
        }

        let tokens = harness
            .authenticate_user("ad-load", &client.client_id, "loaduser_250", "NewPass456!")
            .await;
        assert!(!tokens.access_token.is_empty(), "new password should work");

        let auth_resp2 = harness.get(&auth_path).await;
        let location2 = auth_resp2.headers().get("location").unwrap().to_str().unwrap();
        let execution_id2 =
            LoadTestHarness::extract_query_param(location2, "execution_id").unwrap();
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
    } else {
        eprintln!("[load-test] SKIPPING password change tests (no LDAPS)");
    }

    eprintln!("[load-test] AD load test COMPLETE.");
}
