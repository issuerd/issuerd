// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Legacy smoke tests (storage roundtrip, discovery serialization).

//! Issuerd legacy smoke tests.
//!
//! Run with:
//!   cargo test --test legacy_smoke

use issuerd_core::{RealmId, SecondsNonZero, Storage};
use issuerd_storage::memory::InMemoryStorage;

#[tokio::test]
async fn in_memory_storage_roundtrip() {
    let storage = InMemoryStorage::new();
    let realm = issuerd_core::Realm {
        id: RealmId::new("test-realm").unwrap(),
        name: issuerd_core::RealmName::new("test").unwrap(),
        display_name: None,
        enabled: true,
        ssl_required: issuerd_core::SslRequired::External,
        password_policy: issuerd_core::PasswordPolicy::default(),
        login_theme: None,
        email_theme: None,
        admin_theme: None,
        default_role: None,
        access_token_lifespan: SecondsNonZero::new(300),
        refresh_token_lifespan: SecondsNonZero::new(1800),
        sso_session_idle_timeout: SecondsNonZero::new(1800),
        sso_session_max_lifespan: SecondsNonZero::new(36000),
        offline_session_idle_timeout: SecondsNonZero::new(2592000),
        attributes: Default::default(),
        ..Default::default()
    };

    storage.create_realm(&realm).await.unwrap();
    let fetched = storage.get_realm(&realm.id).await.unwrap();
    assert!(fetched.is_some());
    assert_eq!(fetched.unwrap().name, "test");
}

#[tokio::test]
async fn discovery_response_serialization() {
    let doc = issuerd_protocol::discovery::DiscoveryResponse::for_realm(
        "https://auth.example.com",
        "test",
    );
    let json = serde_json::to_string_pretty(&doc).unwrap();
    assert!(json.contains("issuer"));
    assert!(json.contains("authorization_endpoint"));
}

#[tokio::test]
async fn pkce_s256_verification() {
    use issuerd_protocol::pkce::PkceVerifier;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert!(PkceVerifier::verify(
        verifier,
        challenge,
        Some(issuerd_core::PkceCodeChallengeMethod::S256)
    )
    .is_ok());
}
