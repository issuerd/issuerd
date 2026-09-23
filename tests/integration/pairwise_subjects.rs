// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Pairwise subject identifiers (OIDC Core §8) integration tests.
//!
//! A client opts in via the `subject_type` attribute (`public` default |
//! `pairwise`). Pairwise clients receive `sub = base64url(HMAC-SHA256(
//! sector_key, len(sector) || sector || user_id))` in ID/access/refresh/logout
//! tokens (and, derived from those, in userinfo and introspection output),
//! keyed by the realm's secret sector key (realm attribute, seeded at realm
//! creation). The sector identifier is the host of `sector_identifier_uri`
//! when set (validated at registration against the served JSON document),
//! else the common host of the registered redirect URIs.
//!
//! The sector document fetch is SSRF-hardened (https-only, publicly routable
//! IPs only, no redirects, capped body, uniform error), so these tests do not
//! serve real documents over loopback http: the rejection paths are exercised
//! here, and document validation itself is unit-tested in `issuerd-core`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use crate::harness::TestHarness;

/// Decode the payload segment of a JWT without verifying the signature.
fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Create a confidential client whose redirect URIs live on `redirect_uris`
/// and which is opted into pairwise subjects.
async fn create_pairwise_client(
    harness: &TestHarness,
    realm: &str,
    redirect_uris: &[&str],
    extra_attributes: &[(&str, &str)],
) -> issuerd_core::Client {
    let mut client = harness.create_client(realm, false).await;
    client.redirect_uris = redirect_uris
        .iter()
        .map(|u| issuerd_core::RedirectUri::new(*u).unwrap())
        .collect();
    client.attributes.insert("subject_type".to_string(), "pairwise".to_string());
    for (k, v) in extra_attributes {
        client.attributes.insert(k.to_string(), v.to_string());
    }
    harness.storage.update_client(&client.realm_id, &client).await.unwrap();
    client
}

/// ROPC login; asserts HTTP 200 and returns the decoded token response.
async fn password_grant(
    harness: &TestHarness,
    realm: &str,
    client: &issuerd_core::Client,
    username: &str,
    password: &str,
    scope: &str,
) -> serde_json::Value {
    let resp = harness
        .post_form(
            &format!("/realms/{realm}/protocol/openid-connect/token"),
            &[
                ("grant_type", "password"),
                ("username", username),
                ("password", password),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
                ("scope", scope),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// POST an admin client-creation body; returns (status, raw body text).
async fn create_client_raw(
    harness: &TestHarness,
    realm: &str,
    admin_token: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let resp = harness
        .post_json_auth(&format!("/admin/realms/{realm}/clients"), admin_token, body)
        .await;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn discovery_advertises_pairwise() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-disc").await;

    let resp = harness.get("/realms/pair-disc/.well-known/openid-configuration").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["subject_types_supported"], serde_json::json!(["public", "pairwise"]));
}

#[tokio::test]
async fn public_client_sub_is_user_id() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-public").await;
    let client = harness.create_client("pair-public", false).await;
    let user = harness.create_user("pair-public", "alice", "password123").await;

    let json =
        password_grant(&harness, "pair-public", &client, "alice", "password123", "openid").await;
    let access = json["access_token"].as_str().unwrap();
    assert_eq!(jwt_claims(access)["sub"], serde_json::json!(user.id.0));
}

#[tokio::test]
async fn pairwise_sub_differs_across_sectors_and_hides_user_id() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-sectors").await;
    let client_a =
        create_pairwise_client(&harness, "pair-sectors", &["https://a.example.com/cb"], &[]).await;
    let client_b =
        create_pairwise_client(&harness, "pair-sectors", &["https://b.example.com/cb"], &[]).await;
    let user = harness.create_user("pair-sectors", "alice", "password123").await;

    let sub_a = jwt_claims(
        password_grant(&harness, "pair-sectors", &client_a, "alice", "password123", "openid").await
            ["access_token"]
            .as_str()
            .unwrap(),
    )["sub"]
        .as_str()
        .unwrap()
        .to_string();
    let sub_b = jwt_claims(
        password_grant(&harness, "pair-sectors", &client_b, "alice", "password123", "openid").await
            ["access_token"]
            .as_str()
            .unwrap(),
    )["sub"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ne!(sub_a, sub_b, "different sectors must see different subjects");
    assert_ne!(sub_a, user.id.0, "pairwise sub must not leak the user id");
    assert_ne!(sub_b, user.id.0, "pairwise sub must not leak the user id");
}

#[tokio::test]
async fn pairwise_sub_shared_within_sector() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-shared").await;
    let client_1 =
        create_pairwise_client(&harness, "pair-shared", &["https://app.example.com/cb1"], &[])
            .await;
    let client_2 =
        create_pairwise_client(&harness, "pair-shared", &["https://app.example.com/cb2"], &[])
            .await;
    harness.create_user("pair-shared", "alice", "password123").await;

    let sub_1 = jwt_claims(
        password_grant(&harness, "pair-shared", &client_1, "alice", "password123", "openid").await
            ["access_token"]
            .as_str()
            .unwrap(),
    )["sub"]
        .clone();
    let sub_2 = jwt_claims(
        password_grant(&harness, "pair-shared", &client_2, "alice", "password123", "openid").await
            ["access_token"]
            .as_str()
            .unwrap(),
    )["sub"]
        .clone();

    assert_eq!(sub_1, sub_2, "same sector must see the same subject");
}

#[tokio::test]
async fn pairwise_sub_stable_across_logins() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-stable").await;
    let client =
        create_pairwise_client(&harness, "pair-stable", &["https://app.example.com/cb"], &[]).await;
    harness.create_user("pair-stable", "alice", "password123").await;

    let first = jwt_claims(
        password_grant(&harness, "pair-stable", &client, "alice", "password123", "openid").await
            ["access_token"]
            .as_str()
            .unwrap(),
    )["sub"]
        .clone();
    let second = jwt_claims(
        password_grant(&harness, "pair-stable", &client, "alice", "password123", "openid").await
            ["access_token"]
            .as_str()
            .unwrap(),
    )["sub"]
        .clone();

    assert_eq!(first, second, "pairwise sub must be deterministic");
}

#[tokio::test]
async fn pairwise_id_token_and_refresh_token_carry_pairwise_sub() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-tokens").await;
    let client =
        create_pairwise_client(&harness, "pair-tokens", &["https://app.example.com/cb"], &[]).await;
    let user = harness.create_user("pair-tokens", "alice", "password123").await;

    let json =
        password_grant(&harness, "pair-tokens", &client, "alice", "password123", "openid").await;
    let access_sub = jwt_claims(json["access_token"].as_str().unwrap())["sub"].clone();
    let id_sub = jwt_claims(json["id_token"].as_str().unwrap())["sub"].clone();
    let refresh_sub = jwt_claims(json["refresh_token"].as_str().unwrap())["sub"].clone();

    assert_eq!(id_sub, access_sub, "ID token and access token must agree");
    assert_eq!(
        refresh_sub, access_sub,
        "refresh tokens carry the pairwise sub too (a public sub there would break unlinkability)"
    );
    assert_ne!(access_sub, serde_json::json!(user.id.0));
}

#[tokio::test]
async fn pairwise_userinfo_and_introspection_consistent() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-userinfo").await;
    let client =
        create_pairwise_client(&harness, "pair-userinfo", &["https://app.example.com/cb"], &[])
            .await;
    harness.create_user("pair-userinfo", "alice", "password123").await;

    let json = password_grant(
        &harness,
        "pair-userinfo",
        &client,
        "alice",
        "password123",
        "openid profile email",
    )
    .await;
    let access_token = json["access_token"].as_str().unwrap();
    let token_sub = jwt_claims(access_token)["sub"].clone();

    // Userinfo echoes the pairwise sub AND still resolves the user's profile
    // claims (the user is resolved through the token's session).
    let resp = harness
        .get_auth("/realms/pair-userinfo/protocol/openid-connect/userinfo", access_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let userinfo: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(userinfo["sub"], token_sub);
    assert_eq!(userinfo["email"], serde_json::json!("alice@example.com"));

    // Introspection reports the token's claims, so the pairwise sub shows
    // through consistently.
    let resp = harness
        .post_form(
            "/realms/pair-userinfo/protocol/openid-connect/token/introspect",
            &[
                ("token", access_token),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let introspection: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["sub"], token_sub);
}

#[tokio::test]
async fn pairwise_refresh_rotation_resolves_user_via_session() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-refresh").await;
    let client =
        create_pairwise_client(&harness, "pair-refresh", &["https://app.example.com/cb"], &[])
            .await;
    harness.create_user("pair-refresh", "alice", "password123").await;

    let json =
        password_grant(&harness, "pair-refresh", &client, "alice", "password123", "openid").await;
    let refresh_token = json["refresh_token"].as_str().unwrap().to_string();
    let original_sub = jwt_claims(json["access_token"].as_str().unwrap())["sub"].clone();

    // The refresh grant cannot reverse the pairwise sub — it resolves the
    // user through the session and must succeed.
    let resp = harness
        .post_form(
            "/realms/pair-refresh/protocol/openid-connect/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let rotated: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let new_access_sub = jwt_claims(rotated["access_token"].as_str().unwrap())["sub"].clone();
    let new_refresh_sub = jwt_claims(rotated["refresh_token"].as_str().unwrap())["sub"].clone();
    assert_eq!(new_access_sub, original_sub);
    assert_eq!(new_refresh_sub, original_sub);
}

#[tokio::test]
async fn admin_create_pairwise_client_ambiguous_sector_rejected() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-admin").await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    // Two redirect hosts without a sector_identifier_uri is ambiguous.
    let resp = harness
        .post_json_auth(
            "/admin/realms/pair-admin/clients",
            &admin_token,
            serde_json::json!({
                "client_id": "ambiguous",
                "enabled": true,
                "redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"],
                "attributes": {"subject_type": "pairwise"}
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A single redirect host resolves unambiguously.
    let resp = harness
        .post_json_auth(
            "/admin/realms/pair-admin/clients",
            &admin_token,
            serde_json::json!({
                "client_id": "unambiguous",
                "enabled": true,
                "redirect_uris": ["https://a.example.com/cb", "https://a.example.com/other"],
                "attributes": {"subject_type": "pairwise"}
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn admin_create_pairwise_client_sector_identifier_uri_validation() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-sectoruri").await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    // Plain http is rejected before any fetch (OIDC Core §8.1 https-MUST,
    // re-tightened as SSRF hardening).
    let (status, body) = create_client_raw(
        &harness,
        "pair-sectoruri",
        &admin_token,
        serde_json::json!({
            "client_id": "http-sector",
            "enabled": true,
            "redirect_uris": ["https://a.example.com/cb"],
            "attributes": {
                "subject_type": "pairwise",
                "sector_identifier_uri": "http://sector.example.com/sector.json"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("https"), "body: {body}");

    // An https URL resolving to a non-public address (loopback literal) →
    // rejected with the uniform fetch error…
    let (status_loop, body_loop) = create_client_raw(
        &harness,
        "pair-sectoruri",
        &admin_token,
        serde_json::json!({
            "client_id": "loopback-sector",
            "enabled": true,
            "redirect_uris": ["https://a.example.com/cb"],
            "attributes": {
                "subject_type": "pairwise",
                "sector_identifier_uri": "https://127.0.0.1/sector.json"
            }
        }),
    )
    .await;
    assert_eq!(status_loop, StatusCode::BAD_REQUEST);
    assert!(body_loop.contains("could not be fetched"), "body: {body_loop}");

    // …and an unreachable https host (RFC 2606 `.invalid` fails DNS fast)
    // produces the IDENTICAL error — no connect-vs-DNS oracle.
    let (status_dead, body_dead) = create_client_raw(
        &harness,
        "pair-sectoruri",
        &admin_token,
        serde_json::json!({
            "client_id": "dead-sector",
            "enabled": true,
            "redirect_uris": ["https://a.example.com/cb"],
            "attributes": {
                "subject_type": "pairwise",
                "sector_identifier_uri": "https://sector.invalid/sector.json"
            }
        }),
    )
    .await;
    assert_eq!(status_dead, StatusCode::BAD_REQUEST);
    assert_eq!(body_loop, body_dead, "failure modes must be indistinguishable");
}

/// Session-liveness regression (2026-09 review): a pairwise `sub` is an
/// irreversible HMAC that never resolves to a stored user — the
/// destroyed-session check must still invalidate the token.
#[tokio::test]
async fn pairwise_token_invalidated_when_session_destroyed() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-invalidate").await;
    let client =
        create_pairwise_client(&harness, "pair-invalidate", &["https://app.example.com/cb"], &[])
            .await;
    harness.create_user("pair-invalidate", "carol", "password123").await;

    let json =
        password_grant(&harness, "pair-invalidate", &client, "carol", "password123", "openid")
            .await;
    let access_token = json["access_token"].as_str().unwrap().to_string();
    let claims = jwt_claims(&access_token);
    let sid = claims["sid"].as_str().expect("access token carries sid").to_string();

    // Live session → userinfo works.
    let resp = harness
        .get_auth("/realms/pair-invalidate/protocol/openid-connect/userinfo", &access_token)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Destroy the session (logout / admin teardown); the token must die too.
    // Both real teardown paths invalidate the session-validity cache
    // synchronously — mirror that here since the test deletes directly.
    let realm_id = issuerd_core::RealmId::new("pair-invalidate").unwrap();
    harness
        .storage
        .delete_user_session(&realm_id, &issuerd_core::SessionId::new(&sid).unwrap())
        .await
        .unwrap();
    harness
        .cache
        .delete(&issuerd_cluster::cache_keys::session("pair-invalidate", &sid))
        .await
        .unwrap();

    let resp = harness
        .get_auth("/realms/pair-invalidate/protocol/openid-connect/userinfo", &access_token)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = harness
        .post_form(
            "/realms/pair-invalidate/protocol/openid-connect/token/introspect",
            &[
                ("token", access_token.as_str()),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], false);
}

#[tokio::test]
async fn admin_update_pairwise_client_revalidates() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-update").await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;

    let resp = harness
        .post_json_auth(
            "/admin/realms/pair-update/clients",
            &admin_token,
            serde_json::json!({
                "client_id": "evolving",
                "enabled": true,
                "redirect_uris": ["https://a.example.com/cb"],
                "attributes": {"subject_type": "pairwise"}
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let id = created["id"].as_str().unwrap();

    // Adding a second redirect host without a sector_identifier_uri is
    // rejected on update.
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/admin/realms/pair-update/clients/{id}"))
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {admin_token}"))
        .body(Body::from(
            serde_json::json!({
                "client_id": "evolving",
                "enabled": true,
                "redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"],
                "attributes": {"subject_type": "pairwise"}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A sector_identifier_uri that cannot be fetched under the hardened
    // rules (https loopback here) is rejected on update too — revalidation
    // runs on every write, so a persisted sector setup cannot be smuggled
    // past the SSRF guard later.
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/admin/realms/pair-update/clients/{id}"))
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {admin_token}"))
        .body(Body::from(
            serde_json::json!({
                "client_id": "evolving",
                "enabled": true,
                "redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"],
                "attributes": {
                    "subject_type": "pairwise",
                    "sector_identifier_uri": "https://127.0.0.1/sector.json"
                }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dcr_pairwise_validation() {
    let harness = TestHarness::new().await;
    let mut realm = harness.create_realm("pair-dcr").await;
    realm
        .attributes
        .insert("dynamic_client_registration_enabled".to_string(), "true".to_string());
    harness.storage.update_realm(&realm).await.unwrap();

    // Ambiguous sector → invalid_client_metadata.
    let req = Request::builder()
        .method("POST")
        .uri("/realms/pair-dcr/clients-registrations/default")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"],
                "attributes": {"subject_type": "pairwise"}
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client_metadata");

    // A sector_identifier_uri over plain http is rejected before any fetch —
    // the DCR path enforces the same SSRF-hardened rules (no unauthenticated
    // internal-network probing via the open registration endpoint).
    let req = Request::builder()
        .method("POST")
        .uri("/realms/pair-dcr/clients-registrations/default")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"],
                "attributes": {
                    "subject_type": "pairwise",
                    "sector_identifier_uri": "http://169.254.169.254/latest/meta-data"
                }
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client_metadata");

    // An https sector URI pointing at a non-public address is rejected with
    // the uniform fetch failure (no internal-network oracle).
    let req = Request::builder()
        .method("POST")
        .uri("/realms/pair-dcr/clients-registrations/default")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"],
                "attributes": {
                    "subject_type": "pairwise",
                    "sector_identifier_uri": "https://192.168.0.1/sector.json"
                }
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn pairwise_service_account_client_credentials_not_affected() {
    let harness = TestHarness::new().await;
    harness.create_realm("pair-cc").await;
    // A pairwise-flagged client running client_credentials: the grant subject
    // is already client-scoped (synthetic or service-account), so pairwise
    // derivation must not apply — and issuance must not fail over the missing
    // redirect URIs.
    let mut client = create_pairwise_client(&harness, "pair-cc", &[], &[]).await;
    client.service_accounts_enabled = true;
    harness.storage.update_client(&client.realm_id, &client).await.unwrap();

    let resp = harness
        .post_form(
            "/realms/pair-cc/protocol/openid-connect/token",
            &[
                ("grant_type", "client_credentials"),
                ("client_id", client.client_id.as_ref()),
                ("client_secret", client.secret.as_deref().unwrap_or("")),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let sub = jwt_claims(json["access_token"].as_str().unwrap())["sub"].clone();
    // Synthetic fallback (no service-account user provisioned): sub = client_id.
    assert_eq!(sub, serde_json::json!(client.client_id.as_ref()));
}
