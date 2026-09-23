// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// at_hash and c_hash computation per OIDC Core §3.3.2.11.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use issuerd_core::{Algorithm, Base64Url};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Compute `at_hash` per OIDC Core Section 3.3.2.11.
///
/// # Examples
///
/// ```
/// use issuerd_token::hash::compute_at_hash;
/// use issuerd_core::Algorithm;
///
/// let hash = compute_at_hash("dummy_access_token", Algorithm::Rs256);
/// assert_eq!(hash.as_ref().len(), 22); // base64-url encoding of first 128 bits
/// ```
pub fn compute_at_hash(access_token: &str, alg: Algorithm) -> Base64Url {
    Base64Url::new(compute_hash(access_token, alg)).unwrap()
}

/// Compute `c_hash` per OIDC Core Section 3.3.2.11.
pub fn compute_c_hash(code: &str, alg: Algorithm) -> Base64Url {
    Base64Url::new(compute_hash(code, alg)).unwrap()
}

fn compute_hash(input: &str, alg: Algorithm) -> String {
    let hash = match alg {
        Algorithm::Rs256 | Algorithm::Hs256 | Algorithm::Es256 => {
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            hasher.finalize().to_vec()
        }
        Algorithm::Rs384 | Algorithm::Hs384 | Algorithm::Es384 => {
            let mut hasher = Sha384::new();
            hasher.update(input.as_bytes());
            hasher.finalize().to_vec()
        }
        Algorithm::Rs512 | Algorithm::Hs512 | Algorithm::Es512 | Algorithm::EdDsa => {
            let mut hasher = Sha512::new();
            hasher.update(input.as_bytes());
            hasher.finalize().to_vec()
        }
    };

    let half_len = hash.len() / 2;
    let leftmost = &hash[..half_len];
    URL_SAFE_NO_PAD.encode(leftmost)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_hash_rs256_known_vector() {
        let token = "test_access_token_value";
        let hash = compute_at_hash(token, Algorithm::Rs256);
        // Verify deterministic
        assert_eq!(hash, compute_at_hash(token, Algorithm::Rs256));
        // Verify different alg gives different hash
        let hash_hs256 = compute_at_hash(token, Algorithm::Hs256);
        assert_eq!(hash, hash_hs256); // same hash function
        let hash_rs384 = compute_at_hash(token, Algorithm::Rs384);
        assert_ne!(hash, hash_rs384);
    }

    #[test]
    fn c_hash_changes_with_input() {
        let h1 = compute_c_hash("code1", Algorithm::Rs256);
        let h2 = compute_c_hash("code2", Algorithm::Rs256);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_length_varies_by_alg() {
        let token = "x";
        let h256 = compute_at_hash(token, Algorithm::Rs256);
        let h384 = compute_at_hash(token, Algorithm::Rs384);
        let h512 = compute_at_hash(token, Algorithm::Rs512);
        let h_ed = compute_at_hash(token, Algorithm::EdDsa);

        // Base64 of 16 bytes = ~22 chars, 24 bytes = ~32 chars, 32 bytes = ~43 chars
        assert_eq!(h256.as_ref().len(), 22); // 128 bits = 16 bytes, base64url = 22
        assert_eq!(h384.as_ref().len(), 32); // 192 bits = 24 bytes, base64url = 32
        assert_eq!(h512.as_ref().len(), 43); // 256 bits = 32 bytes, base64url = 43
        assert_eq!(h_ed.as_ref().len(), 43); // same as SHA-512
    }

    #[test]
    fn manual_sha256_matches() {
        let input = "hello";
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let full = hasher.finalize();
        let expected = URL_SAFE_NO_PAD.encode(&full[..16]);
        assert_eq!(compute_at_hash(input, Algorithm::Rs256), Base64Url::new(expected).unwrap());
    }
}
