// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Envelope encryption for signing keys at rest (AES-256-GCM KEK provider).
//
//! Local [`KeyEncryptionKeyProvider`] backed by `ring`'s AES-256-GCM.
//!
//! The Key Encryption Key (KEK) comes from configuration (`[crypto.key_encryption]`,
//! preferably via the environment), never from the database. Every encrypted row
//! stores the id of the KEK that produced it (`kek_kid`), so KEKs rotate by adding
//! the new pair as active and demoting the old one to `previous_keys` (decrypt-only).
//!
//! # Ciphertext blob layout
//!
//! `0x01 || nonce(12) || ciphertext || GCM tag(16)` — a version tag byte, the
//! per-encryption random 96-bit nonce, then the AEAD output. The version tag
//! leaves room for a future cipher swap without a schema change.
//!
//! # Memory hygiene (honest limits)
//!
//! - Caller-supplied KEK arrays are zeroized after the `ring` keys are built.
//! - Plaintext copies made during `encrypt` are zeroized before returning.
//! - Decrypted key material is returned as an owned buffer; storage wraps it in
//!   `zeroize::Zeroizing` until it moves into `StoredSigningKey`, whose `Drop`
//!   zeroizes it.
//! - What we cannot erase: the resident signing key inside the token crate's
//!   keystore (it must stay usable while the key signs) and the internal copies
//!   `ring` / `jsonwebtoken::EncodingKey` make per sign call. The guarantee
//!   delivered here is "no additional long-lived plaintext copies beyond the
//!   resident key, prompt erasure of transient buffers and retired keys".

use std::collections::HashMap;

use issuerd_core::{IssuerdError, KeyEncryptionKeyProvider};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

/// Version tag byte prefixing every ciphertext blob (see module docs).
const BLOB_VERSION: u8 = 0x01;
/// AES-GCM nonce length (96 bits) and tag length (128 bits), both fixed.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Smallest valid blob: version || nonce || empty plaintext || tag.
const MIN_BLOB_LEN: usize = 1 + NONCE_LEN + TAG_LEN;
/// KEK ids are operator-chosen labels persisted on each row; bound their length.
const MAX_KEY_ID_LEN: usize = 64;

fn kek_err(msg: impl Into<String>) -> IssuerdError {
    IssuerdError::KeyEncryption(msg.into())
}

/// AES-256-GCM envelope-encryption provider.
///
/// Holds the active KEK (encrypt + decrypt) plus any number of previous KEKs
/// (decrypt-only, KEK rotation window). See the module docs for the blob
/// layout and the memory-hygiene contract.
pub struct Aes256GcmKekProvider {
    active_kid: String,
    keys: HashMap<String, LessSafeKey>,
    rng: SystemRandom,
}

impl Aes256GcmKekProvider {
    /// Build a provider from the active KEK plus optional previous KEKs.
    ///
    /// `active_kid` is persisted on every newly encrypted row. All key ids
    /// must be non-empty, at most 64 chars, and unique (the active id must not
    /// collide with a previous one). The source key arrays are zeroized once
    /// the `ring` key objects exist.
    pub fn new(
        active_kid: String,
        mut active_key: [u8; 32],
        previous: Vec<(String, [u8; 32])>,
    ) -> Result<Self, IssuerdError> {
        validate_key_id(&active_kid)?;
        let mut keys = HashMap::with_capacity(previous.len() + 1);
        let active = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &active_key)
                .map_err(|_| kek_err("active KEK is not a valid AES-256 key"))?,
        );
        active_key.zeroize();
        keys.insert(active_kid.clone(), active);

        for (kid, mut raw) in previous {
            validate_key_id(&kid)?;
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &raw).map_err(|_| {
                kek_err(format!("previous KEK '{kid}' is not a valid AES-256 key"))
            })?);
            raw.zeroize();
            if keys.insert(kid.clone(), key).is_some() {
                return Err(kek_err(format!("duplicate KEK key_id '{kid}'")));
            }
        }
        Ok(Self {
            active_kid,
            keys,
            rng: SystemRandom::new(),
        })
    }
}

impl KeyEncryptionKeyProvider for Aes256GcmKekProvider {
    fn active_key_id(&self) -> &str {
        &self.active_kid
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, IssuerdError> {
        let key = self
            .keys
            .get(&self.active_kid)
            .ok_or_else(|| kek_err("active KEK missing from provider key set"))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| kek_err("secure random generation failed"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| kek_err("AES-GCM seal failed"))?;

        let mut blob = Vec::with_capacity(MIN_BLOB_LEN + in_out.len());
        blob.push(BLOB_VERSION);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&in_out);
        blob.extend_from_slice(tag.as_ref());
        // `in_out` still holds a plaintext copy — erase it.
        in_out.zeroize();
        Ok(blob)
    }

    fn decrypt(&self, key_id: &str, blob: &[u8]) -> Result<Vec<u8>, IssuerdError> {
        let key = self.keys.get(key_id).ok_or_else(|| {
            kek_err(format!(
                "no KEK configured with key_id '{key_id}' (configure it under previous_keys)"
            ))
        })?;
        if blob.len() < MIN_BLOB_LEN || blob[0] != BLOB_VERSION {
            return Err(kek_err("malformed signing-key ciphertext blob"));
        }
        let nonce = Nonce::assume_unique_for_key(
            <[u8; NONCE_LEN]>::try_from(&blob[1..1 + NONCE_LEN])
                .map_err(|_| kek_err("malformed signing-key ciphertext blob"))?,
        );
        let mut in_out = blob[1 + NONCE_LEN..].to_vec();
        let plaintext = key.open_in_place(nonce, Aad::empty(), &mut in_out).map_err(|_| {
            kek_err(format!("signing-key ciphertext does not decrypt with KEK '{key_id}'"))
        })?;
        let len = plaintext.len();
        in_out.truncate(len);
        Ok(in_out)
    }
}

fn validate_key_id(key_id: &str) -> Result<(), IssuerdError> {
    if key_id.is_empty() {
        return Err(kek_err("KEK key_id must not be empty"));
    }
    if key_id.len() > MAX_KEY_ID_LEN {
        return Err(kek_err(format!(
            "KEK key_id must be at most {MAX_KEY_ID_LEN} chars, got {}",
            key_id.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Aes256GcmKekProvider {
        Aes256GcmKekProvider::new("kek-1".to_string(), [7u8; 32], vec![]).unwrap()
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let p = provider();
        let plaintext = b"pkcs8-der-bytes".to_vec();
        let blob = p.encrypt(&plaintext).unwrap();
        assert_eq!(blob[0], BLOB_VERSION);
        assert_eq!(blob.len(), MIN_BLOB_LEN + plaintext.len());
        // Ciphertext region differs from the plaintext.
        assert_ne!(blob[1 + NONCE_LEN..1 + NONCE_LEN + plaintext.len()], plaintext[..]);
        assert_eq!(p.decrypt("kek-1", &blob).unwrap(), plaintext);
    }

    #[test]
    fn nonces_differ_across_encryptions() {
        let p = provider();
        let a = p.encrypt(b"same plaintext").unwrap();
        let b = p.encrypt(b"same plaintext").unwrap();
        // Random per-encryption nonce: ciphertexts (and nonces) must differ.
        assert_ne!(a, b);
        assert_ne!(&a[1..1 + NONCE_LEN], &b[1..1 + NONCE_LEN]);
        // Both still decrypt to the same plaintext.
        assert_eq!(p.decrypt("kek-1", &a).unwrap(), p.decrypt("kek-1", &b).unwrap());
    }

    #[test]
    fn wrong_kek_fails_closed() {
        let a = Aes256GcmKekProvider::new("kek-1".to_string(), [1u8; 32], vec![]).unwrap();
        let b = Aes256GcmKekProvider::new("kek-1".to_string(), [2u8; 32], vec![]).unwrap();
        let blob = a.encrypt(b"secret").unwrap();
        let err = b.decrypt("kek-1", &blob).unwrap_err();
        assert!(matches!(err, IssuerdError::KeyEncryption(_)));
    }

    #[test]
    fn unknown_key_id_fails() {
        let p = provider();
        let blob = p.encrypt(b"secret").unwrap();
        let err = p.decrypt("no-such-kek", &blob).unwrap_err();
        assert!(err.to_string().contains("no-such-kek"));
    }

    #[test]
    fn tampered_blob_fails() {
        let p = provider();
        let blob = p.encrypt(b"secret").unwrap();
        for (label, mut bad) in [
            ("bad version byte", {
                let mut b = blob.clone();
                b[0] = 0x02;
                b
            }),
            ("truncated", blob[..blob.len() - 1].to_vec()),
            ("flipped ciphertext byte", {
                let mut b = blob.clone();
                let i = b.len() - 2;
                b[i] ^= 0x01;
                b
            }),
        ] {
            assert!(p.decrypt("kek-1", &bad).is_err(), "{label} must not decrypt");
            bad.zeroize();
        }
    }

    #[test]
    fn duplicate_key_id_rejected() {
        let err = Aes256GcmKekProvider::new(
            "kek-1".to_string(),
            [1u8; 32],
            vec![("kek-1".to_string(), [2u8; 32])],
        )
        .err()
        .expect("duplicate active/previous key_id must fail");
        assert!(err.to_string().contains("duplicate KEK key_id 'kek-1'"));

        let err = Aes256GcmKekProvider::new(
            "kek-1".to_string(),
            [1u8; 32],
            vec![
                ("old".to_string(), [2u8; 32]),
                ("old".to_string(), [3u8; 32]),
            ],
        )
        .err()
        .expect("duplicate previous key_id must fail");
        assert!(err.to_string().contains("duplicate KEK key_id 'old'"));
    }

    #[test]
    fn invalid_key_ids_rejected() {
        assert!(Aes256GcmKekProvider::new(String::new(), [1u8; 32], vec![]).is_err());
        assert!(
            Aes256GcmKekProvider::new("x".repeat(MAX_KEY_ID_LEN + 1), [1u8; 32], vec![]).is_err()
        );
        assert!(Aes256GcmKekProvider::new(
            "ok".to_string(),
            [1u8; 32],
            vec![(String::new(), [2u8; 32])]
        )
        .is_err());
    }

    #[test]
    fn previous_kek_decrypts_but_active_encrypts() {
        // Rotation window: old rows (encrypted under 'old') still read, new
        // rows are written under 'new'.
        let old = Aes256GcmKekProvider::new("old".to_string(), [9u8; 32], vec![]).unwrap();
        let legacy_blob = old.encrypt(b"secret").unwrap();

        let rotated = Aes256GcmKekProvider::new(
            "new".to_string(),
            [8u8; 32],
            vec![("old".to_string(), [9u8; 32])],
        )
        .unwrap();
        assert_eq!(rotated.active_key_id(), "new");
        assert_eq!(rotated.decrypt("old", &legacy_blob).unwrap(), b"secret");

        let new_blob = rotated.encrypt(b"secret").unwrap();
        assert_eq!(rotated.decrypt("new", &new_blob).unwrap(), b"secret");
        // The retired provider cannot read rows written under the new KEK.
        assert!(old.decrypt("new", &new_blob).is_err());
    }
}
