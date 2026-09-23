// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Ignored benchmark-style throughput tests for discovery and token issuance.

use crate::harness::TestHarness;

#[tokio::test]
#[ignore = "benchmark"]
async fn bench_discovery_1000() {
    let harness = TestHarness::new().await;
    let start = tokio::time::Instant::now();
    for _ in 0..1000 {
        let resp = harness.get("/.well-known/openid-configuration").await;
        assert_eq!(resp.status(), 200);
    }
    let elapsed = start.elapsed();
    let rps = 1000.0 / elapsed.as_secs_f64();
    println!(
        "1000 discovery requests: {:?} (avg {:?}) => {:.0} req/s",
        elapsed,
        elapsed / 1000,
        rps
    );
}

#[tokio::test]
#[ignore = "benchmark"]
async fn bench_token_issuance_1000() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let start = tokio::time::Instant::now();
    for _ in 0..1000 {
        let resp = harness
            .post_form(
                "/realms/test/protocol/openid-connect/token",
                &[
                    ("grant_type", "password"),
                    ("client_id", &client.client_id),
                    ("client_secret", client.secret.as_deref().unwrap_or("")),
                    ("username", "alice"),
                    ("password", "password123"),
                    ("scope", "openid"),
                ],
            )
            .await;
        assert_eq!(resp.status(), 200);
    }
    let elapsed = start.elapsed();
    let rps = 1000.0 / elapsed.as_secs_f64();
    println!(
        "1000 password grant requests: {:?} (avg {:?}) => {:.0} req/s",
        elapsed,
        elapsed / 1000,
        rps
    );
}

#[tokio::test]
#[ignore = "benchmark"]
async fn bench_validate_token_1000() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    // Issue a single token
    let token_resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "password"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("username", "alice"),
                ("password", "password123"),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(token_resp.status(), 200);
    let body = axum::body::to_bytes(token_resp.into_body(), usize::MAX).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let access_token = token_json["access_token"].as_str().unwrap();

    // Validate it 1000 times via userinfo endpoint
    let start = tokio::time::Instant::now();
    for _ in 0..1000 {
        let resp = harness
            .get_auth("/realms/test/protocol/openid-connect/userinfo", access_token)
            .await;
        assert_eq!(resp.status(), 200);
    }
    let elapsed = start.elapsed();
    let rps = 1000.0 / elapsed.as_secs_f64();
    println!(
        "1000 token validations (userinfo): {:?} (avg {:?}) => {:.0} req/s",
        elapsed,
        elapsed / 1000,
        rps
    );
}

#[tokio::test]
#[ignore = "benchmark"]
async fn bench_auth_code_flow_100() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let start = tokio::time::Instant::now();
    for _ in 0..100 {
        let tokens = harness
            .authenticate_user("test", &client.client_id, "alice", "password123")
            .await;
        assert!(!tokens.access_token.is_empty());
    }
    let elapsed = start.elapsed();
    let rps = 100.0 / elapsed.as_secs_f64();
    println!(
        "100 auth code flows: {:?} (avg {:?}) => {:.0} req/s",
        elapsed,
        elapsed / 100,
        rps
    );
}

// ---------------------------------------------------------------------------
// Phase 1 CPU attribution: time each stage of a warm-cache userinfo request
// separately (tests/perf/INVESTIGATION_PLAN.md). Run:
//   cargo test --test integration bench_userinfo_stage_attribution -- --ignored --nocapture
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "benchmark"]
async fn bench_userinfo_stage_attribution() {
    use issuerd_core::{ClaimTarget, ClientIdentifier, RealmId};
    use issuerd_server::{claims, claims_cache::ClaimsReader, session_cache};
    use std::sync::Arc;
    use std::time::Instant;

    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let user = harness.create_user("test", "alice", "password123").await;

    // Mint one token via ROPC, mirroring the perf rig's userinfo scenario.
    let token_resp = harness
        .post_form(
            "/realms/test/protocol/openid-connect/token",
            &[
                ("grant_type", "password"),
                ("client_id", &client.client_id),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("username", "alice"),
                ("password", "password123"),
                ("scope", "openid profile"),
            ],
        )
        .await;
    assert_eq!(token_resp.status(), 200);
    let body = axum::body::to_bytes(token_resp.into_body(), usize::MAX).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = token_json["access_token"].as_str().unwrap().to_string();

    // The harness keeps no `state` handle; rebuild one sharing the same
    // storage/cache via a second harness around the same components.
    let state = Arc::new(
        issuerd_server::state::ServerState::from_components(
            &issuerd_server::config::ServerConfig::default(),
            Arc::clone(&harness.storage),
            Arc::clone(&harness.cache),
        )
        .await
        .unwrap(),
    );
    let realm_id = RealmId::new("test").unwrap();
    let validated = state.token_service.validate_access_token(&token).unwrap();
    let claims = validated.claims;
    let sid = claims.sid.clone().expect("sid");
    let iss = claims.iss.as_str().to_string();
    let cid = ClientIdentifier::new(claims.aud.as_str()).unwrap();
    let scope_names = claims.scope.to_vec();

    // Warm every cache entry with one full request.
    let resp = harness.get_auth("/realms/test/protocol/openid-connect/userinfo", &token).await;
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    const N: u32 = 5_000;
    let mut rows: Vec<(&'static str, f64)> = Vec::new();
    let mut timed = |name: &'static str, n: u32, start: Instant| {
        let us = start.elapsed().as_secs_f64() * 1e6 / f64::from(n);
        rows.push((name, us));
    };

    // 1. Revocation check: key alloc + cache GET (miss).
    let start = Instant::now();
    for _ in 0..N {
        let key = format!("revoked:{token}");
        std::hint::black_box(harness.cache.get(&key).await.unwrap());
    }
    timed("revoked-key alloc + GET", N, start);

    // 2. RS256 access-token verification (sync crypto + claims parse).
    let start = Instant::now();
    for _ in 0..N {
        std::hint::black_box(state.token_service.validate_access_token(&token).unwrap());
    }
    timed("validate_access_token (RS256)", N, start);

    // 3. Issuer realm resolution (realm-by-name cache hit).
    let start = Instant::now();
    for _ in 0..N {
        std::hint::black_box(state.resolve_issuer_realm(&iss).await.unwrap());
    }
    timed("resolve_issuer_realm (hit)", N, start);

    // 4. Session-validity snapshot (session + sessv GETs).
    let start = Instant::now();
    for _ in 0..N {
        std::hint::black_box(session_cache::session_snapshot(&state, &realm_id, &sid).await);
    }
    timed("session_snapshot (hit)", N, start);

    // 5. ClaimsReader::user_claims — epoch GET + entry GET + JSON deserialize.
    let start = Instant::now();
    for _ in 0..N {
        let r = ClaimsReader::new(&state, &realm_id);
        std::hint::black_box(r.user_claims(&user.id).await);
    }
    timed("user_claims (hit, new reader)", N, start);

    // 6. ClaimsReader::client.
    let start = Instant::now();
    for _ in 0..N {
        let r = ClaimsReader::new(&state, &realm_id);
        std::hint::black_box(r.client(&cid).await);
    }
    timed("client (hit, new reader)", N, start);

    // 7. ClaimsReader::realm_catalog — the largest entry.
    let start = Instant::now();
    for _ in 0..N {
        let r = ClaimsReader::new(&state, &realm_id);
        std::hint::black_box(r.realm_catalog().await);
    }
    timed("realm_catalog (hit, new reader)", N, start);

    // 8. Full overlay assembly (own reader: epoch + catalog [+ user_claims]).
    let start = Instant::now();
    for _ in 0..N {
        std::hint::black_box(
            claims::build_claims_overlay(
                &state,
                &realm_id,
                Some(&client),
                &user,
                &scope_names,
                ClaimTarget::UserInfo,
            )
            .await
            .unwrap(),
        );
    }
    timed("build_claims_overlay", N, start);

    // 9. Response render proxy: Value round-trip of the real response body.
    let start = Instant::now();
    for _ in 0..N {
        let v: serde_json::Value = serde_json::from_value(response_json.clone()).unwrap();
        std::hint::black_box(serde_json::to_vec(&v).unwrap());
    }
    timed("response Value clone+serialize", N, start);

    // 10. Full in-process HTTP userinfo (router oneshot, warm caches).
    let start = Instant::now();
    for _ in 0..N {
        let resp = harness.get_auth("/realms/test/protocol/openid-connect/userinfo", &token).await;
        assert_eq!(resp.status(), 200);
        std::hint::black_box(resp);
    }
    timed("FULL userinfo HTTP (in-process)", N, start);

    // Discovery full path for reference (stale-gap scenario).
    let start = Instant::now();
    for _ in 0..N {
        let resp = harness.get("/realms/test/.well-known/openid-configuration").await;
        assert_eq!(resp.status(), 200);
        std::hint::black_box(resp);
    }
    timed("FULL discovery HTTP (in-process)", N, start);

    println!("\n=== userinfo stage attribution (warm cache, {N} iters each) ===");
    let rps = 19_500.0; // large-tier measured ceiling
    let mut sum = 0.0;
    for (name, us) in &rows {
        let cores = us * rps / 1e6;
        if !name.starts_with("FULL") {
            sum += us;
        }
        println!("{name:<36} {us:8.1} µs/op   {cores:5.2} cores @ {rps:.0} rps");
    }
    println!(
        "{:<36} {sum:8.1} µs      {:5.2} cores",
        "SUM (stages, no HTTP)",
        sum * rps / 1e6
    );
}

#[tokio::test]
#[ignore = "benchmark"]
async fn bench_concurrent_token_issuance_1000() {
    let harness = TestHarness::new().await;
    let _realm = harness.create_realm("test").await;
    let client = harness.create_client("test", false).await;
    let _user = harness.create_user("test", "alice", "password123").await;

    let start = tokio::time::Instant::now();
    let mut handles = Vec::new();
    for _ in 0..50 {
        handles.push(tokio::spawn({
            let harness = harness.clone();
            let client_id = client.client_id.clone();
            let secret = client.secret.clone().unwrap_or_default();
            async move {
                for _ in 0..20 {
                    let resp = harness
                        .post_form(
                            "/realms/test/protocol/openid-connect/token",
                            &[
                                ("grant_type", "password"),
                                ("client_id", &client_id),
                                ("client_secret", &secret),
                                ("username", "alice"),
                                ("password", "password123"),
                                ("scope", "openid"),
                            ],
                        )
                        .await;
                    assert_eq!(resp.status(), 200);
                }
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let elapsed = start.elapsed();
    let rps = 1000.0 / elapsed.as_secs_f64();
    println!(
        "1000 concurrent password grant requests (50x20): {:?} => {:.0} req/s",
        elapsed, rps
    );
}
