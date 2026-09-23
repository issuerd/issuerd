// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Envelope encryption for signing keys at rest — end-to-end over real
//! PostgreSQL (testcontainers; both tests skip gracefully without Docker).
//!
//! - [`key_encryption_two_nodes_share_kek`]: two full nodes boot through
//!   [`ServerState::from_config`] with the same `[crypto.key_encryption]`
//!   section; the database holds ciphertext only, and a token signed by node A
//!   verifies on node B (shared key set decrypted on both sides).
//! - [`key_encryption_wrong_kek_fails_boot`]: a node configured with the wrong
//!   KEK (different bytes under the same key id, or an unknown key id) fails
//!   boot with a clear error — never a plaintext fallback.

use issuerd_server::config::{CryptoSettings, KeyEncryptionConfig, ServerConfig, StorageConfig};
use issuerd_server::state::ServerState;

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn kek_base64(byte: u8) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode([byte; 32])
}

fn config_with_kek(url: &str, key_id: &str, kek_byte: u8) -> ServerConfig {
    ServerConfig {
        storage: StorageConfig::Postgres {
            url: url.to_string(),
        },
        crypto: CryptoSettings {
            key_encryption: Some(KeyEncryptionConfig {
                key_id: key_id.to_string(),
                key_base64: kek_base64(kek_byte),
                previous_keys: vec![],
            }),
        },
        ..Default::default()
    }
}

async fn start_postgres() -> (String, testcontainers::ContainerAsync<testcontainers::GenericImage>)
{
    use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt};
    let img = GenericImage::new("postgres", "15-alpine")
        .with_wait_for(WaitFor::message_on_stderr("database system is ready to accept connections"))
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_DB", "test");
    let container = img.start().await.expect("postgres container start");
    let host = container.get_host().await.expect("container host");
    let port = container.get_host_port_ipv4(5432).await.expect("container port");
    (format!("postgres://postgres:postgres@{host}:{port}/test"), container)
}

#[tokio::test]
async fn key_encryption_two_nodes_share_kek() {
    if !docker_available() {
        eprintln!("skipping key_encryption_two_nodes_share_kek: docker unavailable");
        return;
    }
    let (url, _container) = start_postgres().await;

    // Both nodes boot through the full daemon wiring (connect → migrations →
    // re-encryption sweep → keystore load) with identical KEK config.
    let config = config_with_kek(&url, "e2e-kek", 42);
    let state_a = ServerState::from_config(&config).await.expect("node A boot");
    let state_b = ServerState::from_config(&config).await.expect("node B boot");

    // Acceptance criterion: the DB dump holds ciphertext key material only.
    type RawRow = (Option<Vec<u8>>, Option<Vec<u8>>, Option<String>);
    let pool = sqlx::PgPool::connect(&url).await.expect("raw pool");
    let rows: Vec<RawRow> =
        sqlx::query_as("SELECT private_der, private_der_enc, kek_kid FROM signing_keys")
            .fetch_all(&pool)
            .await
            .expect("raw signing-key rows");
    assert!(!rows.is_empty(), "boot must persist a signing key");
    for (der, enc, kek_kid) in &rows {
        assert!(der.is_none(), "private_der must be NULL (ciphertext-only)");
        assert!(enc.is_some(), "private_der_enc must hold the ciphertext blob");
        assert_eq!(kek_kid.as_deref(), Some("e2e-kek"));
    }

    // Both nodes loaded the same shared key set (node B decrypted what node A
    // wrote through its own pool + KEK).
    let jwks_a = state_a.crypto.get_public_keys().await.expect("jwks A");
    let jwks_b = state_b.crypto.get_public_keys().await.expect("jwks B");
    assert_eq!(jwks_a, jwks_b);

    // A token signed by node A validates on node B.
    let key = &jwks_a.keys[0];
    let token = state_a
        .crypto
        .sign(r#"{"sub":"cross-node"}"#, key.alg, &key.kid)
        .await
        .expect("node A signs");
    assert!(state_b.crypto.verify(&token, key.alg, &key.kid).await.expect("node B verifies"));
}

#[tokio::test]
async fn key_encryption_wrong_kek_fails_boot() {
    if !docker_available() {
        eprintln!("skipping key_encryption_wrong_kek_fails_boot: docker unavailable");
        return;
    }
    let (url, _container) = start_postgres().await;

    // Node with the correct KEK boots and persists an encrypted signing key.
    ServerState::from_config(&config_with_kek(&url, "e2e-kek", 42))
        .await
        .expect("first boot with correct KEK");

    // Same key id, different key bytes: the boot sweep cannot decrypt the row
    // and fails the daemon with an error naming the KEK id.
    let err = ServerState::from_config(&config_with_kek(&url, "e2e-kek", 43))
        .await
        .err()
        .expect("wrong KEK bytes must fail boot");
    assert!(matches!(err, issuerd_core::IssuerdError::KeyEncryption(_)), "got: {err}");
    assert!(err.to_string().contains("e2e-kek"), "error names the KEK id: {err}");

    // Unknown key id (no matching previous_keys entry): same fail-closed boot.
    let err = ServerState::from_config(&config_with_kek(&url, "other-kek", 42))
        .await
        .err()
        .expect("unknown KEK id must fail boot");
    assert!(matches!(err, issuerd_core::IssuerdError::KeyEncryption(_)), "got: {err}");
    assert!(err.to_string().contains("e2e-kek"), "error names the row's kek_kid: {err}");
}
