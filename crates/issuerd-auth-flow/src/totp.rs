// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! RFC 6238 TOTP (time-based one-time password) implementation.
//!
//! Pure functions only — no storage, cache, clock, or I/O dependencies beyond
//! the OS RNG used by [`generate_secret`]. Secrets are base32-encoded
//! (RFC 4648, no padding) exactly as authenticator apps expect them; codes are
//! HMAC-SHA-1/256/512 over a 30-second (configurable) time step with RFC 4226
//! dynamic truncation, verified against a small step window with replay
//! protection.

use issuerd_core::{OtpHashAlgorithm, OtpPolicy};
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// Base32 (RFC 4648, no padding) — hand-rolled; no external crate
// ---------------------------------------------------------------------------

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32-encode without padding (RFC 4648 §6).
pub(crate) fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        // Number of 5-bit groups actually carried by this chunk.
        let chars = match chunk.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        for i in 0..chars {
            let shift = 35 - i * 5;
            out.push(B32_ALPHABET[((bits >> shift) & 0x1F) as usize] as char);
        }
    }
    out
}

/// Base32-decode, tolerating lowercase input and `=` padding. Returns `None`
/// on any invalid character.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.chars() {
        if c == '=' {
            break; // tolerate (and stop at) RFC 4648 padding
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        // `acc` keeps only the low `nbits` bits relevant; those never exceed
        // 12 bits, so the shifting below cannot lose live data.
        acc = (acc << 5) | u64::from(v);
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// Percent-encode for URL path/query segments (unreserved characters pass
/// through, everything else is `%XX`). Used for the `otpauth://` label and
/// query parameters.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The `algorithm` query-parameter spelling used by `otpauth://` URIs
/// (distinct from the Keycloak/`OtpHashAlgorithm` wire spelling).
fn otpauth_algorithm(alg: &OtpHashAlgorithm) -> &'static str {
    match alg {
        OtpHashAlgorithm::HmacSha1 => "SHA1",
        OtpHashAlgorithm::HmacSha256 => "SHA256",
        OtpHashAlgorithm::HmacSha512 => "SHA512",
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a fresh TOTP secret: 20 random bytes (160 bits, the RFC 4226
/// recommended minimum) base32-encoded without padding.
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

/// Compute the TOTP code for a raw key at an explicit time step.
///
/// `step` is `unix_time / period_secs` computed by the caller; `digits` is
/// typically 6 or 8. The result is zero-padded to exactly `digits` characters.
pub fn totp_at(key: &[u8], step: u64, digits: u32, alg: &OtpHashAlgorithm) -> String {
    // Defend the login path against a misconfigured realm OTP policy:
    // 10^digits must fit into a u32, and a zero-width code is meaningless.
    let digits = digits.clamp(1, 9);
    let algorithm = match alg {
        OtpHashAlgorithm::HmacSha1 => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        OtpHashAlgorithm::HmacSha256 => ring::hmac::HMAC_SHA256,
        OtpHashAlgorithm::HmacSha512 => ring::hmac::HMAC_SHA512,
    };
    let hmac_key = ring::hmac::Key::new(algorithm, key);
    let tag = ring::hmac::sign(&hmac_key, &step.to_be_bytes());
    let digest = tag.as_ref();
    // RFC 4226 §5.3 dynamic truncation.
    let offset = usize::from(digest[digest.len() - 1] & 0x0F);
    let binary = (u32::from(digest[offset] & 0x7F) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10u32.pow(digits);
    let code = binary % modulus;
    format!("{code:0width$}", width = digits as usize)
}

/// Verify a user-supplied TOTP code against a base32 secret.
///
/// Checks the current step, one step back (clock skew / slow entry), and up to
/// `policy.look_ahead_window` steps ahead. Steps at or before
/// `last_used_step` are rejected so a code already consumed for a login cannot
/// be replayed. Returns the matched step on success (the caller persists it as
/// the new `last_used_step`), `None` on any mismatch or undecodable secret.
/// Code comparison is constant-time.
pub fn verify(
    secret_b32: &str,
    code: &str,
    now_secs: u64,
    policy: &OtpPolicy,
    last_used_step: Option<u64>,
) -> Option<u64> {
    let key = base32_decode(secret_b32)?;
    let period = u64::from(policy.period_secs.max(1));
    let current = now_secs / period;
    let first = current.saturating_sub(1);
    let last = current.saturating_add(u64::from(policy.look_ahead_window));
    for step in first..=last {
        if last_used_step.is_some_and(|used| step <= used) {
            continue;
        }
        let expected = totp_at(&key, step, policy.digits, &policy.algorithm);
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            return Some(step);
        }
    }
    None
}

/// Build the `otpauth://` provisioning URI authenticator apps scan.
///
/// Format: `otpauth://totp/{issuer}:{account}?secret=…&issuer=…&algorithm=…&digits=…&period=…`
/// with the label parts percent-encoded.
pub fn otpauth_url(issuer: &str, account: &str, secret_b32: &str, policy: &OtpPolicy) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        url_encode(issuer),
        url_encode(account),
        secret_b32,
        url_encode(issuer),
        otpauth_algorithm(&policy.algorithm),
        policy.digits,
        policy.period_secs,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Base32
    // ------------------------------------------------------------------

    #[test]
    fn base32_rfc4648_vectors() {
        // RFC 4648 §10 test vectors (padding stripped).
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn base32_roundtrip_arbitrary_lengths() {
        for len in 0..=32usize {
            let data: Vec<u8> =
                (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect();
            let encoded = base32_encode(&data);
            let decoded = base32_decode(&encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for len {len} ({encoded})");
        }
    }

    #[test]
    fn base32_decode_tolerates_padding_and_lowercase() {
        assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode("mzxw6ytb").unwrap(), b"fooba");
        assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(base32_decode("MY======").unwrap(), b"f");
    }

    #[test]
    fn base32_decode_rejects_invalid_characters() {
        assert!(base32_decode("MZXW6!").is_none());
        assert!(base32_decode("MZXW 6").is_none());
        assert!(base32_decode("018").is_none());
    }

    // ------------------------------------------------------------------
    // RFC 6238 Appendix B test vectors (30 s step, 8 digits)
    // ------------------------------------------------------------------

    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    /// (unix_time, step, SHA1, SHA256, SHA512)
    const RFC6238_VECTORS: &[(u64, u64, &str, &str, &str)] = &[
        (59, 1, "94287082", "46119246", "90693936"),
        (1111111109, 37037036, "07081804", "68084774", "25091201"),
        (1111111111, 37037037, "14050471", "67062674", "99943326"),
        (1234567890, 41152263, "89005924", "91819424", "93441116"),
        (2000000000, 66666666, "69279037", "90698825", "38618901"),
        (20000000000, 666666666, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn rfc6238_appendix_b_sha1() {
        for &(time, step, sha1, _, _) in RFC6238_VECTORS {
            assert_eq!(time / 30, step, "vector step mismatch");
            assert_eq!(totp_at(SEED_SHA1, step, 8, &OtpHashAlgorithm::HmacSha1), sha1);
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha256() {
        for &(_, step, _, sha256, _) in RFC6238_VECTORS {
            assert_eq!(totp_at(SEED_SHA256, step, 8, &OtpHashAlgorithm::HmacSha256), sha256);
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha512() {
        for &(_, step, _, _, sha512) in RFC6238_VECTORS {
            assert_eq!(totp_at(SEED_SHA512, step, 8, &OtpHashAlgorithm::HmacSha512), sha512);
        }
    }

    #[test]
    fn six_digit_output_is_zero_padded() {
        for step in 0..100u64 {
            let code = totp_at(SEED_SHA1, step, 6, &OtpHashAlgorithm::HmacSha1);
            assert_eq!(code.len(), 6, "step {step} produced {code}");
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn extreme_digits_do_not_panic() {
        // A misconfigured realm OTP policy must never overflow 10^digits or
        // panic the login path: digits are clamped to 1..=9.
        for digits in [0, 1, 9, 10, 20, u32::MAX] {
            let code = totp_at(SEED_SHA1, 1, digits, &OtpHashAlgorithm::HmacSha1);
            let expected_len = digits.clamp(1, 9) as usize;
            assert_eq!(code.len(), expected_len, "digits {digits} produced {code}");
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    // ------------------------------------------------------------------
    // verify(): window, replay, decoding
    // ------------------------------------------------------------------

    fn policy() -> OtpPolicy {
        OtpPolicy::default() // HmacSHA1, 6 digits, 30 s, look-ahead 1
    }

    fn secret() -> String {
        base32_encode(SEED_SHA1)
    }

    fn code_at_step(step: u64) -> String {
        totp_at(SEED_SHA1, step, 6, &OtpHashAlgorithm::HmacSha1)
    }

    #[test]
    fn verify_accepts_current_step_and_returns_it() {
        let now = 30_000 * 30; // step 30000
        let code = code_at_step(30_000);
        assert_eq!(verify(&secret(), &code, now, &policy(), None), Some(30_000));
    }

    #[test]
    fn verify_accepts_one_step_back_and_lookahead() {
        let now = 30_000 * 30;
        // One step behind (clock skew / slow entry).
        assert_eq!(verify(&secret(), &code_at_step(29_999), now, &policy(), None), Some(29_999));
        // One step ahead (within look_ahead_window = 1).
        assert_eq!(verify(&secret(), &code_at_step(30_001), now, &policy(), None), Some(30_001));
    }

    #[test]
    fn verify_rejects_outside_window() {
        let now = 30_000 * 30;
        assert_eq!(verify(&secret(), &code_at_step(29_998), now, &policy(), None), None);
        assert_eq!(verify(&secret(), &code_at_step(30_002), now, &policy(), None), None);
        assert_eq!(verify(&secret(), "000000", now, &policy(), None), None);
        assert_eq!(verify(&secret(), "not-a-code", now, &policy(), None), None);
    }

    #[test]
    fn verify_rejects_replay_at_or_before_last_used_step() {
        let now = 30_000 * 30;
        // The current-step code was already consumed.
        assert_eq!(verify(&secret(), &code_at_step(30_000), now, &policy(), Some(30_000)), None);
        // The previous step is also at/before the watermark: rejected.
        assert_eq!(verify(&secret(), &code_at_step(29_999), now, &policy(), Some(30_000)), None);
        // A fresh future step is still fine.
        assert_eq!(
            verify(&secret(), &code_at_step(30_001), now, &policy(), Some(30_000)),
            Some(30_001)
        );
    }

    #[test]
    fn verify_rejects_undecodable_secret() {
        let now = 30_000 * 30;
        assert_eq!(verify("not base32!!", "123456", now, &policy(), None), None);
    }

    #[test]
    fn verify_honors_sha256_policy() {
        let sha256 = OtpPolicy {
            algorithm: OtpHashAlgorithm::HmacSha256,
            ..OtpPolicy::default()
        };
        let now = 30_000 * 30;
        let code = totp_at(SEED_SHA256, 30_000, 6, &OtpHashAlgorithm::HmacSha256);
        assert_eq!(verify(&base32_encode(SEED_SHA256), &code, now, &sha256, None), Some(30_000));
        // Same code must not validate under the SHA1 policy.
        assert_eq!(verify(&base32_encode(SEED_SHA256), &code, now, &policy(), None), None);
    }

    // ------------------------------------------------------------------
    // generate_secret / otpauth_url
    // ------------------------------------------------------------------

    #[test]
    fn generated_secret_is_160_bits_of_valid_base32() {
        let s = generate_secret();
        assert_eq!(s.len(), 32, "20 bytes -> 32 base32 chars");
        let decoded = base32_decode(&s).unwrap();
        assert_eq!(decoded.len(), 20);
        // Two secrets are (overwhelmingly) distinct.
        assert_ne!(s, generate_secret());
    }

    #[test]
    fn otpauth_url_layout_and_encoding() {
        let policy = OtpPolicy::default();
        let url = otpauth_url("Iron Cloak", "alice@example.com", "JBSWY3DPEHPK3PXP", &policy);
        assert_eq!(
            url,
            "otpauth://totp/Iron%20Cloak:alice%40example.com?secret=JBSWY3DPEHPK3PXP\
             &issuer=Iron%20Cloak&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn otpauth_url_reflects_policy() {
        let policy = OtpPolicy {
            algorithm: OtpHashAlgorithm::HmacSha512,
            digits: 8,
            period_secs: 60,
            look_ahead_window: 2,
        };
        let url = otpauth_url("issuer", "acct", "ABCDEF", &policy);
        assert!(url.contains("algorithm=SHA512"));
        assert!(url.contains("digits=8"));
        assert!(url.contains("period=60"));
    }

    #[test]
    fn url_encode_leaves_unreserved_and_escapes_rest() {
        assert_eq!(url_encode("abcXYZ019-._~"), "abcXYZ019-._~");
        assert_eq!(url_encode("a b+c/d:e"), "a%20b%2Bc%2Fd%3Ae");
        assert_eq!(url_encode("ü"), "%C3%BC");
    }
}
