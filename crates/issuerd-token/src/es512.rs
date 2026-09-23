// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! ES512 (ECDSA over P-521 with SHA-512) JWS signing and verification.
//!
//! `jsonwebtoken` (backed by `ring`) has no P-521 support, so ES512 tokens
//! are produced and verified manually here via the `p521` crate, which the
//! keystore already uses for P-521 key generation. The wire format follows
//! JWA (RFC 7518 §3.4): the signature is the fixed-width `R || S`
//! concatenation (66 bytes each, 132 total), base64url-encoded without
//! padding.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use issuerd_core::{IssuerdError, Jwk, KeyId};
use p521::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p521::pkcs8::DecodePrivateKey;

/// Sign `message` (the JWS signing input `header.payload`) with a P-521
/// private key in PKCS#8 DER form, returning the raw 132-byte ES512
/// signature. ES512 is ECDSA over P-521 with a SHA-512 message digest, which
/// is exactly the digest `p521` binds to its `Signer` implementation.
pub fn sign_es512(private_der: &[u8], message: &[u8]) -> Result<Vec<u8>, IssuerdError> {
    let secret = p521::SecretKey::from_pkcs8_der(private_der)
        .map_err(|e| IssuerdError::ServerError(format!("ES512 private key parse failed: {e}")))?;
    let signing_key = SigningKey::from_bytes(&secret.to_bytes())
        .map_err(|e| IssuerdError::ServerError(format!("ES512 private key invalid: {e}")))?;
    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a raw ES512 signature over `message` against the P-521 public key
/// in `jwk` (base64url uncompressed-point coordinates `x`/`y`). A malformed
/// signature or message mismatch yields `Ok(false)`; a malformed key is an
/// error.
pub fn verify_es512(jwk: &Jwk, message: &[u8], signature: &[u8]) -> Result<bool, IssuerdError> {
    let x = jwk
        .x
        .as_ref()
        .ok_or_else(|| IssuerdError::InvalidRequest("EC JWK missing x".into()))?;
    let y = jwk
        .y
        .as_ref()
        .ok_or_else(|| IssuerdError::InvalidRequest("EC JWK missing y".into()))?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x.as_str())
        .map_err(|e| IssuerdError::InvalidRequest(format!("invalid base64 in EC JWK x: {e}")))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y.as_str())
        .map_err(|e| IssuerdError::InvalidRequest(format!("invalid base64 in EC JWK y: {e}")))?;

    // SEC 1 uncompressed point: 0x04 || X || Y (66-byte coordinates for P-521).
    let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    point.push(0x04);
    point.extend_from_slice(&x_bytes);
    point.extend_from_slice(&y_bytes);
    let verifying_key = VerifyingKey::from_sec1_bytes(&point)
        .map_err(|e| IssuerdError::InvalidRequest(format!("invalid P-521 public key: {e}")))?;

    let Ok(signature) = Signature::from_slice(signature) else {
        return Ok(false);
    };
    Ok(verifying_key.verify(message, &signature).is_ok())
}

/// Produce a compact JWS (`header.payload.signature`) for `payload_json`
/// signed with the given P-521 key. The header mirrors the exact shape
/// `jsonwebtoken` emits for the other algorithms:
/// `{"typ":"JWT","alg":"ES512","kid":...}`.
pub fn encode_es512_jws(
    payload_json: &str,
    kid: &KeyId,
    private_der: &[u8],
) -> Result<String, IssuerdError> {
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "ES512",
        "kid": kid.to_string(),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let message = format!("{header_b64}.{payload_b64}");
    let signature = sign_es512(private_der, message.as_bytes())?;
    Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::KeyStore;
    use issuerd_core::Algorithm;

    #[test]
    fn es512_roundtrip() {
        let key = KeyStore::generate_key(Algorithm::Es512, 2048).unwrap();
        let message = b"header.payload";
        let signature = sign_es512(&key.private_der, message).unwrap();
        // P-521 coordinates are 66 bytes each: R || S = 132 bytes.
        assert_eq!(signature.len(), 132);
        let valid = verify_es512(&key.public_jwk, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn es512_tampered_message_fails() {
        let key = KeyStore::generate_key(Algorithm::Es512, 2048).unwrap();
        let signature = sign_es512(&key.private_der, b"header.payload").unwrap();
        let valid = verify_es512(&key.public_jwk, b"header.tampered", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn es512_wrong_key_fails() {
        let key = KeyStore::generate_key(Algorithm::Es512, 2048).unwrap();
        let other = KeyStore::generate_key(Algorithm::Es512, 2048).unwrap();
        let signature = sign_es512(&key.private_der, b"header.payload").unwrap();
        let valid = verify_es512(&other.public_jwk, b"header.payload", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn es512_malformed_signature_is_false_not_error() {
        let key = KeyStore::generate_key(Algorithm::Es512, 2048).unwrap();
        let valid = verify_es512(&key.public_jwk, b"header.payload", &[1, 2, 3]).unwrap();
        assert!(!valid);
    }

    #[test]
    fn es512_invalid_private_der_errors() {
        let result = sign_es512(b"not a key", b"msg");
        assert!(result.is_err());
    }

    #[test]
    fn es512_missing_jwk_coordinates_error() {
        let mut jwk = KeyStore::generate_key(Algorithm::Es512, 2048).unwrap().public_jwk.clone();
        jwk.x = None;
        let result = verify_es512(&jwk, b"msg", &[0u8; 132]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing x"));
    }

    #[test]
    fn encode_es512_jws_structure_and_verification() {
        let key = KeyStore::generate_key(Algorithm::Es512, 2048).unwrap();
        let token = encode_es512_jws(r#"{"sub":"user-1"}"#, &key.kid, &key.private_der).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Header shape matches jsonwebtoken's output for the other algorithms.
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES512");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], key.kid.to_string());

        // The signature verifies over the emitted signing input.
        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert!(verify_es512(&key.public_jwk, message.as_bytes(), &signature).unwrap());
    }
}
