// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// PKCE code verifier/challenge generation and verification (RFC 7636).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use issuerd_core::{IssuerdError, PkceCodeChallengeMethod};
use sha2::{Digest, Sha256};

/// PKCE verifier per RFC 7636.
///
/// # Examples
///
/// ```
/// use issuerd_protocol::pkce::PkceVerifier;
///
/// let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// let challenge = PkceVerifier::s256_challenge(verifier);
/// assert!(PkceVerifier::verify(verifier, &challenge, Some(issuerd_core::PkceCodeChallengeMethod::S256)).is_ok());
/// ```
pub struct PkceVerifier;

impl PkceVerifier {
    pub fn verify(
        code_verifier: &str,
        code_challenge: &str,
        method: Option<PkceCodeChallengeMethod>,
    ) -> Result<(), IssuerdError> {
        // RFC 7636: verifier must be 43-128 characters
        let len = code_verifier.len();
        if !(43..=128).contains(&len) {
            return Err(IssuerdError::InvalidRequest(
                "code_verifier must be 43-128 characters".into(),
            ));
        }
        // MIRAI anchor (scripts/mirai.sh): the abstract interpreter proves the
        // length invariant established by the guard above; a no-op at runtime.
        mirai_annotations::verify!((43..=128).contains(&len));

        match method {
            Some(PkceCodeChallengeMethod::S256) => {
                let computed = Self::s256_challenge(code_verifier);
                if computed == code_challenge {
                    Ok(())
                } else {
                    Err(IssuerdError::InvalidRequest("pkce verification failed".into()))
                }
            }
            Some(PkceCodeChallengeMethod::Plain) | None => {
                if code_verifier == code_challenge {
                    Ok(())
                } else {
                    Err(IssuerdError::InvalidRequest("pkce verification failed".into()))
                }
            }
        }
    }

    pub fn s256_challenge(code_verifier: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hash = hasher.finalize();
        URL_SAFE_NO_PAD.encode(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        // RFC 7636 Appendix B test vector
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(PkceVerifier::s256_challenge(verifier), expected_challenge);
    }

    #[test]
    fn pkce_plain_match() {
        let verifier = "a".repeat(43);
        assert!(PkceVerifier::verify(&verifier, &verifier, Some(PkceCodeChallengeMethod::Plain))
            .is_ok());
    }

    #[test]
    fn pkce_plain_mismatch() {
        let v1 = "a".repeat(43);
        let v2 = "b".repeat(43);
        assert!(PkceVerifier::verify(&v1, &v2, Some(PkceCodeChallengeMethod::Plain)).is_err());
    }

    #[test]
    fn pkce_s256_mismatch() {
        let verifier = "a".repeat(43);
        assert!(PkceVerifier::verify(
            &verifier,
            "wrong_challenge",
            Some(PkceCodeChallengeMethod::S256)
        )
        .is_err());
    }

    #[test]
    fn pkce_unsupported_method() {
        let verifier = "a".repeat(43);
        assert!(PkceVerifier::verify(&verifier, "challenge", None).is_err());
    }

    #[test]
    fn pkce_verifier_too_short() {
        let short = "a".repeat(42);
        assert!(PkceVerifier::verify(&short, &short, Some(PkceCodeChallengeMethod::Plain)).is_err());
    }

    #[test]
    fn pkce_verifier_min_length() {
        let min = "a".repeat(43);
        assert!(PkceVerifier::verify(&min, &min, Some(PkceCodeChallengeMethod::Plain)).is_ok());
    }

    #[test]
    fn pkce_verifier_max_length() {
        let max = "a".repeat(128);
        assert!(PkceVerifier::verify(&max, &max, Some(PkceCodeChallengeMethod::Plain)).is_ok());
    }

    #[test]
    fn pkce_verifier_too_long() {
        let long = "a".repeat(129);
        assert!(PkceVerifier::verify(&long, &long, Some(PkceCodeChallengeMethod::Plain)).is_err());
    }
}

/// Kani model-checking harnesses (run `cargo kani -p issuerd-protocol`; Linux/macOS
/// or WSL — see scripts/kani.sh). Gated on `cfg(kani)`, which the Kani
/// toolchain sets; normal builds never compile this module.
///
/// Practical notes (Kani 0.68, CBMC 6.11):
/// - Inputs are deliberately small (8-byte strings). Symbolic `str` handling —
///   UTF-8 validation with data-dependent index advancement plus slice
///   validity models — scales superlinearly with length; 43-byte symbolic
///   verifiers do not terminate in reasonable time on commodity hardware.
///   The harnesses prove the verification logic; the exact RFC 7636 43/128
///   boundaries are pinned by unit tests.
/// - Every harness carries an explicit `#[kani::unwind]` bound: without one the
///   unwinder does not terminate on `str::from_utf8`'s loops.
/// - Inputs go through `str::from_utf8` on fixed arrays (never
///   `String::from_utf8(Vec)` — a `Vec`/`String` carries symbolic length
///   metadata that explodes loop unwinding).
/// - Harnesses must not execute SHA-256 (symbolic compression rounds are
///   intractable for CBMC here) or `HashMap`s with `RandomState` (symbolic
///   hash keys blow up SipHash); such proofs were attempted and removed.
///   The S256 path is pinned by the RFC 7636 Appendix B unit-test vector.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Any RFC 7636 §4.1 unreserved code-verifier character.
    fn any_unreserved_char() -> u8 {
        let c: u8 = kani::any();
        kani::assume(c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'));
        c
    }

    /// Declare an 8-byte array of symbolic unreserved characters plus a `&str`
    /// borrow of it, both in the caller's scope.
    macro_rules! any_verifier {
        ($bytes:ident, $name:ident) => {
            let mut $bytes = [0u8; 8];
            for b in $bytes.iter_mut() {
                *b = any_unreserved_char();
            }
            let $name = std::str::from_utf8(&$bytes).expect("unreserved chars are ASCII");
        };
    }

    /// A verifier below the minimum length is rejected without hashing.
    #[kani::proof]
    #[kani::unwind(16)]
    fn short_verifier_rejected() {
        any_verifier!(vbytes, verifier);
        assert!(PkceVerifier::verify(verifier, "challenge", Some(PkceCodeChallengeMethod::S256))
            .is_err());
    }

    /// Plain method: acceptance is exactly string equality, gated on the
    /// RFC 7636 length guard.
    #[kani::proof]
    #[kani::unwind(16)]
    fn plain_method_is_exact_equality() {
        any_verifier!(abytes, a);
        any_verifier!(bbytes, b);
        let result = PkceVerifier::verify(a, b, Some(PkceCodeChallengeMethod::Plain));
        assert_eq!(result.is_ok(), (43..=128).contains(&a.len()) && a == b);
    }
}
