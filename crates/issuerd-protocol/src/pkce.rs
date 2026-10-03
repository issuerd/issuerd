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
    /// Verify a code verifier against the stored challenge. S256 only —
    /// matching the `code_challenge_methods_supported` discovery
    /// advertisement: `plain` is never accepted, and neither is a missing
    /// method (RFC 7636 §4.3 defaults it to plain, so accepting it would be
    /// plain through the back door). The authorize endpoint refuses to issue
    /// codes for non-S256 challenges, so a non-S256 method reaching the
    /// token endpoint cannot be redeemed either.
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
                Err(IssuerdError::InvalidRequest("code_challenge_method must be S256".into()))
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
    fn pkce_s256_match() {
        let verifier = "a".repeat(43);
        let challenge = PkceVerifier::s256_challenge(&verifier);
        assert!(PkceVerifier::verify(&verifier, &challenge, Some(PkceCodeChallengeMethod::S256))
            .is_ok());
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
    fn pkce_plain_rejected() {
        // `plain` is never accepted — not even when verifier and challenge
        // match exactly (S256-only, matching the discovery advertisement).
        let verifier = "a".repeat(43);
        assert!(PkceVerifier::verify(&verifier, &verifier, Some(PkceCodeChallengeMethod::Plain))
            .is_err());
    }

    #[test]
    fn pkce_missing_method_rejected() {
        // RFC 7636 §4.3 defaults a missing method to plain — rejected too.
        let verifier = "a".repeat(43);
        assert!(PkceVerifier::verify(&verifier, &verifier, None).is_err());
    }

    #[test]
    fn pkce_verifier_too_short() {
        let short = "a".repeat(42);
        let challenge = PkceVerifier::s256_challenge(&short);
        assert!(
            PkceVerifier::verify(&short, &challenge, Some(PkceCodeChallengeMethod::S256)).is_err()
        );
    }

    #[test]
    fn pkce_verifier_min_length() {
        let min = "a".repeat(43);
        let challenge = PkceVerifier::s256_challenge(&min);
        assert!(PkceVerifier::verify(&min, &challenge, Some(PkceCodeChallengeMethod::S256)).is_ok());
    }

    #[test]
    fn pkce_verifier_max_length() {
        let max = "a".repeat(128);
        let challenge = PkceVerifier::s256_challenge(&max);
        assert!(PkceVerifier::verify(&max, &challenge, Some(PkceCodeChallengeMethod::S256)).is_ok());
    }

    #[test]
    fn pkce_verifier_too_long() {
        let long = "a".repeat(129);
        let challenge = PkceVerifier::s256_challenge(&long);
        assert!(
            PkceVerifier::verify(&long, &challenge, Some(PkceCodeChallengeMethod::S256)).is_err()
        );
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

    /// Plain and missing methods are never accepted (S256-only policy).
    /// With the 8-byte harness inputs the RFC 7636 length guard dominates;
    /// the method-rejection arm for valid-length verifiers is pinned by the
    /// `pkce_plain_rejected` / `pkce_missing_method_rejected` unit tests.
    #[kani::proof]
    #[kani::unwind(16)]
    fn non_s256_methods_always_rejected() {
        any_verifier!(abytes, a);
        any_verifier!(bbytes, b);
        assert!(PkceVerifier::verify(a, b, Some(PkceCodeChallengeMethod::Plain)).is_err());
        assert!(PkceVerifier::verify(a, b, None).is_err());
    }
}
