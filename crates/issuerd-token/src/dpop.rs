// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! DPoP proof validation per RFC 9449.
//!
//! A DPoP proof is a JWT sent in the `DPoP` HTTP header, signed by a
//! client-generated key whose public JWK rides in the proof's `jwk` header.
//! Tokens issued against a verified proof carry `cnf.jkt` (the RFC 7638
//! thumbprint of that JWK), which sender-constrains them: the same key must
//! prove possession whenever the token is presented (token endpoint,
//! userinfo, ...).
//!
//! Pure cryptography and claim-shape checks only — no storage, no network.
//! The caller (issuerd-server) supplies the expected `htm`/`htu` values, enforces
//! `jti` single-use via its distributed cache, and threads the returned
//! thumbprint into token issuance.
//!
//! Checks performed (RFC 9449 §4.2/§4.3):
//! - header: `typ: dpop+jwt`, asymmetric alg allowlist (the same accept set
//!   as external ID tokens / `private_key_jwt` — HS* is meaningless here
//!   because the verification key comes from the proof itself), `jwk`
//!   present, public only (no private members), family-matching `alg`;
//! - signature against the embedded `jwk`;
//! - claims: `jti` present (bounded length), `htm`/`htu` match the request,
//!   `iat` within the acceptance window, `ath` (SHA-256 of the presented
//!   access token, §4.2) when the caller requires it, and `nonce` equal to
//!   the caller-supplied expected value (§8/§9 server-provided nonces) when
//!   one is set — the crate stays storage-free: the caller (issuerd-server)
//!   verifies the nonce against its distributed cache and passes the consumed
//!   value in.
//!
//! All failures map to the uniform [`IssuerdError::InvalidDpopProof`]; the
//! endpoint logs specifics itself.

use base64::Engine;
use issuerd_core::IssuerdError;
use sha2::Digest;

use crate::external::{alg_matches_kty, decoding_key, map_alg, ExternalJwk};

/// Header `typ` required on DPoP proof JWTs (RFC 9449 §4.2).
pub const DPOP_PROOF_TYP: &str = "dpop+jwt";

/// Upper bound on the accepted `jti` length — bounds replay-cache key size.
const MAX_JTI_LEN: usize = 256;

/// Upper bound on the accepted `nonce` length — bounds nonce-cache key size
/// (server-issued nonces are 43 chars; the cap exists for hostile claims).
const MAX_NONCE_LEN: usize = 256;

/// JWK members that carry private (or symmetric) key material. A proof
/// embedding any of them is rejected outright (RFC 9449 §4.2: the `jwk`
/// header parameter MUST NOT contain a private key).
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Requirements a DPoP proof must satisfy for one HTTP request.
#[derive(Debug, Clone)]
pub struct DpopProofRequirements<'a> {
    /// Expected `htm` claim: the HTTP method of the request (`"POST"`, ...).
    pub expected_htm: &'a str,
    /// Accepted `htu` values: the endpoint URL(s) the request legitimately
    /// targets (realm-id and realm-name spellings both count).
    pub accepted_htu: &'a [String],
    /// When the request presents an access token (resource-side use, RFC 9449
    /// §7.1), the proof must carry its `ath` hash. `None` at the token
    /// endpoint (§5.1: `ath` is not required there).
    pub expected_ath: Option<&'a str>,
    /// How far in the past `iat` may lie (acceptance window; also sizes the
    /// replay-cache TTL).
    pub max_age_secs: i64,
    /// Clock-skew leeway for `iat` in the future.
    pub leeway_secs: i64,
    /// Current time (injected so validation stays pure/testable).
    pub now: i64,
    /// RFC 9449 §8/§9 server-provided nonce: when `Some`, the proof MUST
    /// carry a `nonce` claim equal to this value (bounded length). The
    /// caller obtained the value from its nonce store — verification here
    /// binds it to the signed claims; the store's existence/TTL/single-use
    /// semantics live in the caller. When `None`, no nonce is required and
    /// a `nonce` claim is ignored.
    pub expected_nonce: Option<&'a str>,
}

/// A verified DPoP proof: everything the endpoint needs to bind tokens and
/// enforce replay protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpopProof {
    /// RFC 7638 SHA-256 thumbprint of the proof's public JWK — the value to
    /// embed as `cnf.jkt` in issued tokens.
    pub jkt: String,
    /// The proof's `jti` (replay-cache key material).
    pub jti: String,
    /// The proof's `iat` (replay-cache TTL sizing).
    pub iat: i64,
}

#[derive(Debug, serde::Deserialize)]
struct DpopHeader {
    alg: String,
    typ: Option<String>,
    jwk: Option<serde_json::Value>,
}

/// The public JWK embedded in the proof header, parsed leniently (`kid`,
/// `alg`, `use`, ... may all be present; only the members needed for
/// verification + thumbprint are modeled).
#[derive(Debug, serde::Deserialize)]
struct DpopJwk {
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    n: Option<String>,
    e: Option<String>,
    kid: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct DpopClaims {
    jti: Option<String>,
    htm: Option<String>,
    htu: Option<String>,
    iat: Option<i64>,
    ath: Option<String>,
    nonce: Option<String>,
}

fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `ath` claim value for an access token: base64url(SHA-256(token))
/// (RFC 9449 §4.2).
pub fn access_token_hash(access_token: &str) -> String {
    b64url_encode(&sha2::Sha256::digest(access_token.as_bytes()))
}

/// RFC 7638 SHA-256 JWK thumbprint of a public-JWK JSON document.
///
/// Rejects documents containing private key material. Exposed for tests and
/// for callers that need the thumbprint of an arbitrary JWK; proof
/// validation computes the thumbprint from its own parsed copy.
pub fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, IssuerdError> {
    let jwk = parse_public_jwk(jwk)?;
    Ok(thumbprint_of(&jwk))
}

/// Parse the `jwk` header value, refusing private/symmetric material.
fn parse_public_jwk(value: &serde_json::Value) -> Result<DpopJwk, IssuerdError> {
    let object = value.as_object().ok_or(IssuerdError::InvalidDpopProof)?;
    if PRIVATE_JWK_MEMBERS.iter().any(|member| object.contains_key(*member)) {
        return Err(IssuerdError::InvalidDpopProof);
    }
    let jwk: DpopJwk =
        serde_json::from_value(value.clone()).map_err(|_| IssuerdError::InvalidDpopProof)?;
    // The members the thumbprint (and verification) needs must be present.
    let complete = match jwk.kty.as_str() {
        "RSA" => jwk.n.is_some() && jwk.e.is_some(),
        "EC" => jwk.crv.is_some() && jwk.x.is_some() && jwk.y.is_some(),
        "OKP" => jwk.crv.is_some() && jwk.x.is_some(),
        _ => false,
    };
    if !complete {
        return Err(IssuerdError::InvalidDpopProof);
    }
    Ok(jwk)
}

/// RFC 7638 §3.2: the thumbprint input is the JSON object of exactly the
/// required members, in lexicographic order, with no whitespace. The member
/// values are base64url/fixed tokens, so plain `format!` needs no escaping.
fn thumbprint_of(jwk: &DpopJwk) -> String {
    let canonical = match jwk.kty.as_str() {
        "RSA" => format!(
            "{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}",
            jwk.e.as_deref().unwrap_or_default(),
            jwk.n.as_deref().unwrap_or_default()
        ),
        "EC" => format!(
            "{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            jwk.crv.as_deref().unwrap_or_default(),
            jwk.x.as_deref().unwrap_or_default(),
            jwk.y.as_deref().unwrap_or_default()
        ),
        "OKP" => format!(
            "{{\"crv\":\"{}\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
            jwk.crv.as_deref().unwrap_or_default(),
            jwk.x.as_deref().unwrap_or_default()
        ),
        // Unreachable: parse_public_jwk rejects unknown kty.
        _ => unreachable!("thumbprint of unknown kty"),
    };
    b64url_encode(&sha2::Sha256::digest(canonical.as_bytes()))
}

/// Validate a DPoP proof JWT against the request it accompanies.
pub fn validate_dpop_proof(
    proof: &str,
    requirements: &DpopProofRequirements<'_>,
) -> Result<VerifiedDpopProof, IssuerdError> {
    // Exactly three compact-JWS segments.
    if proof.split('.').count() != 3 {
        return Err(IssuerdError::InvalidDpopProof);
    }
    let header_b64 = proof.split('.').next().unwrap_or_default();
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| IssuerdError::InvalidDpopProof)?;
    let header: DpopHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| IssuerdError::InvalidDpopProof)?;

    if header.typ.as_deref() != Some(DPOP_PROOF_TYP) {
        return Err(IssuerdError::InvalidDpopProof);
    }
    // Asymmetric allowlist only (same accept set as external ID tokens).
    let alg = map_alg(&header.alg).map_err(|_| IssuerdError::InvalidDpopProof)?;

    let jwk_value = header.jwk.ok_or(IssuerdError::InvalidDpopProof)?;
    let jwk = parse_public_jwk(&jwk_value)?;
    if !alg_matches_kty(&jwk.kty, alg) {
        return Err(IssuerdError::InvalidDpopProof);
    }
    let jkt = thumbprint_of(&jwk);

    let external = ExternalJwk {
        kty: jwk.kty.clone(),
        kid: jwk.kid.clone(),
        n: jwk.n.clone(),
        e: jwk.e.clone(),
        x: jwk.x.clone(),
        y: jwk.y.clone(),
    };
    let key = decoding_key(&external).map_err(|_| IssuerdError::InvalidDpopProof)?;

    // DPoP proofs carry no exp/aud — only the signature matters to
    // jsonwebtoken; all claim rules are enforced below.
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let claims: DpopClaims = jsonwebtoken::decode(proof, &key, &validation)
        .map_err(|_| IssuerdError::InvalidDpopProof)?
        .claims;

    let jti = claims
        .jti
        .filter(|s| !s.is_empty() && s.len() <= MAX_JTI_LEN)
        .ok_or(IssuerdError::InvalidDpopProof)?;

    if claims.htm.as_deref() != Some(requirements.expected_htm) {
        return Err(IssuerdError::InvalidDpopProof);
    }
    let htu = claims.htu.ok_or(IssuerdError::InvalidDpopProof)?;
    if !requirements.accepted_htu.iter().any(|accepted| accepted == &htu) {
        return Err(IssuerdError::InvalidDpopProof);
    }

    let iat = claims.iat.ok_or(IssuerdError::InvalidDpopProof)?;
    let now = requirements.now;
    if iat > now + requirements.leeway_secs || iat < now - requirements.max_age_secs {
        return Err(IssuerdError::InvalidDpopProof);
    }

    if let Some(access_token) = requirements.expected_ath {
        match claims.ath {
            Some(ref ath) if *ath == access_token_hash(access_token) => {}
            _ => return Err(IssuerdError::InvalidDpopProof),
        }
    }

    // RFC 9449 §8/§9: when the caller expects a server-provided nonce, the
    // proof must echo exactly that value in its `nonce` claim.
    if let Some(expected) = requirements.expected_nonce {
        match claims.nonce {
            Some(ref nonce) if nonce.len() <= MAX_NONCE_LEN && nonce == expected => {}
            _ => return Err(IssuerdError::InvalidDpopProof),
        }
    }

    Ok(VerifiedDpopProof { jkt, jti, iat })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTU: &str = "http://localhost:8080/realms/master/protocol/openid-connect/token";
    const TOKEN: &str = "sample-access-token";

    fn requirements() -> DpopProofRequirements<'static> {
        DpopProofRequirements {
            expected_htm: "POST",
            accepted_htu: Box::leak(vec![HTU.to_string()].into_boxed_slice()),
            expected_ath: None,
            max_age_secs: 300,
            leeway_secs: 60,
            now: chrono::Utc::now().timestamp(),
            expected_nonce: None,
        }
    }

    // ------------------------------------------------------------------
    // Test signers (hand-rolled compact JWS so the header can carry `jwk`)
    // ------------------------------------------------------------------

    use ring::signature::KeyPair as _;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn assemble(
        header: serde_json::Value,
        claims: serde_json::Value,
        sign: &dyn Fn(&[u8]) -> Vec<u8>,
    ) -> String {
        let input = format!(
            "{}.{}",
            b64(serde_json::to_vec(&header).unwrap().as_slice()),
            b64(serde_json::to_vec(&claims).unwrap().as_slice())
        );
        let signature = sign(input.as_bytes());
        format!("{input}.{}", b64(&signature))
    }

    /// P-256 key pair; ES256 signatures in the fixed R||S form JWS expects.
    struct EcKey {
        pair: ring::signature::EcdsaKeyPair,
        x: String,
        y: String,
    }

    fn gen_ec() -> EcKey {
        let rng = ring::rand::SystemRandom::new();
        let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            doc.as_ref(),
            &rng,
        )
        .unwrap();
        let public = pair.public_key().as_ref();
        assert_eq!(public.len(), 65);
        let (x, y) = (b64(&public[1..33]), b64(&public[33..65]));
        EcKey { pair, x, y }
    }

    impl EcKey {
        fn public_jwk(&self) -> serde_json::Value {
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": self.x, "y": self.y})
        }

        fn proof(&self, claims: serde_json::Value) -> String {
            self.proof_with_header(claims, serde_json::json!({}))
        }

        fn proof_with_header(
            &self,
            claims: serde_json::Value,
            header_extra: serde_json::Value,
        ) -> String {
            let mut header = serde_json::json!({
                "alg": "ES256",
                "typ": DPOP_PROOF_TYP,
                "jwk": self.public_jwk(),
            });
            header
                .as_object_mut()
                .unwrap()
                .extend(header_extra.as_object().unwrap().clone());
            assemble(header, claims, &|input| {
                let rng = ring::rand::SystemRandom::new();
                self.pair.sign(&rng, input).unwrap().as_ref().to_vec()
            })
        }
    }

    /// RSA key pair via the `rsa` crate; RS256 = PKCS#1 v1.5 over SHA-256.
    struct RsaKey {
        private: rsa::RsaPrivateKey,
        n: String,
        e: String,
    }

    fn gen_rsa() -> RsaKey {
        let mut rng = rand::thread_rng();
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = private.to_public_key();
        use rsa::traits::PublicKeyParts;
        RsaKey {
            private,
            n: b64(&public.n().to_bytes_be()),
            e: b64(&public.e().to_bytes_be()),
        }
    }

    impl RsaKey {
        fn public_jwk(&self) -> serde_json::Value {
            serde_json::json!({"kty": "RSA", "n": self.n, "e": self.e})
        }

        fn proof(&self, claims: serde_json::Value) -> String {
            let header = serde_json::json!({
                "alg": "RS256",
                "typ": DPOP_PROOF_TYP,
                "jwk": self.public_jwk(),
            });
            assemble(header, claims, &|input| {
                let digest = sha2::Sha256::digest(input);
                // RS256 PKCS#1 v1.5 DigestInfo prefix for SHA-256 (the
                // `sha2/oid` feature is off, so spell the constant out).
                let padding = rsa::Pkcs1v15Sign {
                    hash_len: Some(32),
                    prefix: [
                        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                    ]
                    .into(),
                };
                let mut rng = rand::thread_rng();
                self.private.sign_with_rng(&mut rng, padding, &digest).unwrap()
            })
        }
    }

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "jti": issuerd_core::utils::generate_id(),
            "htm": "POST",
            "htu": HTU,
            "iat": chrono::Utc::now().timestamp(),
        })
    }

    // ------------------------------------------------------------------
    // Thumbprint (RFC 7638)
    // ------------------------------------------------------------------

    /// RFC 7638 §3.2 example: the RSA key's SHA-256 thumbprint is fixed by
    /// the specification.
    #[test]
    fn rfc7638_rsa_thumbprint_vector() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        assert_eq!(jwk_thumbprint(&jwk).unwrap(), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn thumbprint_covers_ec_and_okp_shapes() {
        // No spec vector — assert the canonical-member construction directly:
        // lexicographic order, required members only.
        let ec = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "xx", "y": "yy", "kid": "ignored"});
        let expected = b64(sha2::Sha256::digest(
            b"{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"xx\",\"y\":\"yy\"}",
        )
        .as_slice());
        assert_eq!(jwk_thumbprint(&ec).unwrap(), expected);

        let okp = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "xx"});
        let expected =
            b64(sha2::Sha256::digest(b"{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"xx\"}")
                .as_slice());
        assert_eq!(jwk_thumbprint(&okp).unwrap(), expected);
    }

    #[test]
    fn thumbprint_rejects_private_material_and_incomplete_keys() {
        let with_private = serde_json::json!({"kty": "RSA", "n": "n", "e": "e", "d": "secret"});
        assert!(matches!(jwk_thumbprint(&with_private), Err(IssuerdError::InvalidDpopProof)));
        let symmetric = serde_json::json!({"kty": "oct", "k": "secret"});
        assert!(matches!(jwk_thumbprint(&symmetric), Err(IssuerdError::InvalidDpopProof)));
        let incomplete = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "xx"});
        assert!(matches!(jwk_thumbprint(&incomplete), Err(IssuerdError::InvalidDpopProof)));
    }

    // ------------------------------------------------------------------
    // Proof validation
    // ------------------------------------------------------------------

    #[test]
    fn es256_proof_accepted() {
        let key = gen_ec();
        let proof = key.proof(valid_claims());
        let verified = validate_dpop_proof(&proof, &requirements()).unwrap();
        assert_eq!(verified.jkt, jwk_thumbprint(&key.public_jwk()).unwrap());
        assert_eq!(verified.jti, valid_claims_static_jti(&proof));
    }

    #[test]
    fn rsa_proof_accepted() {
        let key = gen_rsa();
        let proof = key.proof(valid_claims());
        let verified = validate_dpop_proof(&proof, &requirements()).unwrap();
        assert_eq!(verified.jkt, jwk_thumbprint(&key.public_jwk()).unwrap());
    }

    /// Pull the jti back out of a signed proof (decode without verification).
    fn valid_claims_static_jti(proof: &str) -> String {
        let payload = proof.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["jti"].as_str().unwrap().to_string()
    }

    #[test]
    fn ath_checked_when_required() {
        let key = gen_ec();
        let mut claims = valid_claims();
        claims["ath"] = serde_json::json!(access_token_hash(TOKEN));
        let proof = key.proof(claims);
        let req = DpopProofRequirements {
            expected_ath: Some(TOKEN),
            ..requirements()
        };
        assert!(validate_dpop_proof(&proof, &req).is_ok());

        // Wrong hash and missing claim are both rejected.
        let mut claims = valid_claims();
        claims["ath"] = serde_json::json!(access_token_hash("other-token"));
        let proof = key.proof(claims);
        assert!(matches!(validate_dpop_proof(&proof, &req), Err(IssuerdError::InvalidDpopProof)));
        let proof = key.proof(valid_claims());
        assert!(matches!(validate_dpop_proof(&proof, &req), Err(IssuerdError::InvalidDpopProof)));
    }

    #[test]
    fn wrong_typ_rejected() {
        let key = gen_ec();
        let proof = key.proof_with_header(valid_claims(), serde_json::json!({"typ": "JWT"}));
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));
    }

    #[test]
    fn symmetric_alg_rejected() {
        let key = gen_ec();
        // Header claims HS256; the signature is still ES256, but the alg
        // allowlist fires before any verification.
        let proof = key.proof_with_header(valid_claims(), serde_json::json!({"alg": "HS256"}));
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));
    }

    #[test]
    fn private_jwk_rejected() {
        let key = gen_ec();
        let mut jwk = key.public_jwk();
        jwk["d"] = serde_json::json!("private-material");
        let proof = key.proof_with_header(valid_claims(), serde_json::json!({"jwk": jwk}));
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));
    }

    #[test]
    fn alg_kty_mismatch_rejected() {
        // EC key but header alg claims RS256 — the family check must fire.
        let key = gen_ec();
        let proof = key.proof_with_header(valid_claims(), serde_json::json!({"alg": "RS256"}));
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));
    }

    #[test]
    fn tampered_signature_rejected() {
        let key = gen_ec();
        let proof = key.proof(valid_claims());
        let mut parts: Vec<&str> = proof.split('.').collect();
        // Flip the signature to a different (validly shaped) value.
        parts[2] = Box::leak(b64(&[0u8; 64]).into_boxed_str());
        let forged = parts.join(".");
        assert!(matches!(
            validate_dpop_proof(&forged, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));
    }

    #[test]
    fn htm_htu_mismatch_rejected() {
        let key = gen_ec();
        let mut claims = valid_claims();
        claims["htm"] = serde_json::json!("GET");
        let proof = key.proof(claims);
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));

        let mut claims = valid_claims();
        claims["htu"] = serde_json::json!(
            "http://localhost:8080/realms/master/protocol/openid-connect/userinfo"
        );
        let proof = key.proof(claims);
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));
    }

    #[test]
    fn iat_window_enforced() {
        let key = gen_ec();
        let now = chrono::Utc::now().timestamp();

        // Stale (beyond max_age).
        let mut claims = valid_claims();
        claims["iat"] = serde_json::json!(now - 301);
        let proof = key.proof(claims);
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));

        // Future beyond leeway.
        let mut claims = valid_claims();
        claims["iat"] = serde_json::json!(now + 61);
        let proof = key.proof(claims);
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));

        // Inside leeway both ways is fine.
        let mut claims = valid_claims();
        claims["iat"] = serde_json::json!(now + 30);
        let proof = key.proof(claims);
        assert!(validate_dpop_proof(&proof, &requirements()).is_ok());
    }

    #[test]
    fn nonce_checked_when_expected() {
        let key = gen_ec();
        let req = DpopProofRequirements {
            expected_nonce: Some("server-nonce-1"),
            ..requirements()
        };

        // Matching nonce claim: accepted.
        let mut claims = valid_claims();
        claims["nonce"] = serde_json::json!("server-nonce-1");
        let proof = key.proof(claims);
        assert!(validate_dpop_proof(&proof, &req).is_ok());

        // Wrong value: rejected.
        let mut claims = valid_claims();
        claims["nonce"] = serde_json::json!("server-nonce-2");
        let proof = key.proof(claims);
        assert!(matches!(validate_dpop_proof(&proof, &req), Err(IssuerdError::InvalidDpopProof)));

        // Missing claim: rejected.
        let proof = key.proof(valid_claims());
        assert!(matches!(validate_dpop_proof(&proof, &req), Err(IssuerdError::InvalidDpopProof)));

        // Oversized claim: rejected even when it starts with the expected
        // value (bounds the nonce-store key size).
        let mut claims = valid_claims();
        claims["nonce"] = serde_json::json!("x".repeat(MAX_NONCE_LEN + 1));
        let proof = key.proof(claims);
        assert!(matches!(validate_dpop_proof(&proof, &req), Err(IssuerdError::InvalidDpopProof)));
    }

    #[test]
    fn nonce_ignored_when_not_expected() {
        // Disabled mode: a `nonce` claim neither helps nor hurts.
        let key = gen_ec();
        let mut claims = valid_claims();
        claims["nonce"] = serde_json::json!("anything");
        let proof = key.proof(claims);
        assert!(validate_dpop_proof(&proof, &requirements()).is_ok());
    }

    #[test]
    fn missing_or_malformed_claims_rejected() {
        let key = gen_ec();

        // Missing jti.
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("jti");
        let proof = key.proof(claims);
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));

        // Oversized jti (bounds the replay-cache key).
        let mut claims = valid_claims();
        claims["jti"] = serde_json::json!("x".repeat(MAX_JTI_LEN + 1));
        let proof = key.proof(claims);
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));

        // Missing iat.
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("iat");
        let proof = key.proof(claims);
        assert!(matches!(
            validate_dpop_proof(&proof, &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));

        // Not a compact JWS at all.
        assert!(matches!(
            validate_dpop_proof("not-a-jwt", &requirements()),
            Err(IssuerdError::InvalidDpopProof)
        ));
    }
}
