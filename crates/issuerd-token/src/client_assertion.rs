// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Validation of JWT client assertions (private_key_jwt / client_secret_jwt).

//! Validation of JWT client assertions (`private_key_jwt` and
//! `client_secret_jwt`) per RFC 7523 §2.2 / RFC 7521 §4.2 and OIDC Core §9.
//!
//! Pure cryptography and claim-shape checks only — no storage, no network.
//! The caller (issuerd-server) supplies the verification material (the client's
//! JWKS document, inline or fetched, or the client secret) and enforces `jti`
//! single-use via its distributed cache.
//!
//! Checks performed:
//! - signature: against a JWKS key matching `kid` + algorithm family
//!   (`private_key_jwt`, asymmetric algs only) or HMAC keyed with the client
//!   secret (`client_secret_jwt`, HS256/384/512 only);
//! - `iss` == `sub` == the `client_id` from the request (RFC 7523 §3);
//! - `aud` is present and contains at least one of the accepted audiences
//!   (issuer URL, token endpoint URL, PAR endpoint URL — RFC 9126 §2);
//! - `exp` present, not expired (leeway applies), and not further than
//!   `max_lifetime_secs` out — the cap bounds the server-side replay cache;
//! - `iat`, when present, not in the future (jsonwebtoken does not check it).

use issuerd_core::IssuerdError;

use crate::external::{alg_matches_kty, decoding_key, ExternalJwks};

/// Verified claims of a client assertion JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAssertionClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: Option<i64>,
    pub jti: Option<String>,
}

/// Requirements a client assertion must satisfy.
#[derive(Debug, Clone)]
pub struct ClientAssertionRequirements<'a> {
    /// The `client_id` from the request: `iss` and `sub` must both equal it.
    pub expected_client_id: &'a str,
    /// `aud` must contain at least one of these values.
    pub accepted_audiences: &'a [String],
    /// Clock-skew leeway in seconds (applied to `exp`/`iat`).
    pub leeway_secs: u64,
    /// Maximum assertion lifetime: an `exp` further than this many seconds in
    /// the future is rejected. Bounds how long the server must remember a
    /// `jti` for replay rejection.
    pub max_lifetime_secs: u64,
}

/// Decode target for the assertion payload. `exp`/`aud` presence and
/// freshness are additionally enforced by the `jsonwebtoken::Validation`
/// (which inspects the raw JSON), so the `Option`s here are belt-and-braces
/// checked in `check_claims`.
#[derive(Debug, serde::Deserialize)]
struct AssertionPayload {
    iss: Option<String>,
    sub: Option<String>,
    #[serde(default)]
    aud: AudList,
    exp: Option<i64>,
    iat: Option<i64>,
    jti: Option<String>,
}

/// `aud` arrives as a string or an array of strings (RFC 7519 §4.1.3).
#[derive(Debug, Default)]
struct AudList(Vec<String>);

impl<'de> serde::Deserialize<'de> for AudList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Single(String),
            Many(Vec<String>),
        }
        Ok(match Repr::deserialize(deserializer)? {
            Repr::Single(s) => AudList(vec![s]),
            Repr::Many(v) => AudList(v),
        })
    }
}

fn invalid() -> IssuerdError {
    // Uniform, detail-free error for claim-shape failures: assertion failures
    // must not leak internals to clients. The endpoint logs specifics itself.
    // Crypto/parse failures embed the jsonwebtoken/serde cause at the call
    // site (`invalid client assertion: {e}`) — these messages never reach the
    // OAuth client (endpoints answer a fixed `invalid_client`), so the cause
    // is safe to carry for upstream WARN logs.
    IssuerdError::InvalidToken
}

/// A crypto/parse failure with the underlying cause embedded (see [`invalid`]).
fn invalid_caused(context: &str, e: impl std::fmt::Display) -> IssuerdError {
    IssuerdError::InvalidRequest(format!("invalid client assertion ({context}): {e}"))
}

/// Verify a `client_secret_jwt` assertion: HMAC-signed (HS256/384/512) with
/// the client secret as the key.
pub fn validate_client_secret_assertion(
    assertion: &str,
    client_secret: &str,
    requirements: &ClientAssertionRequirements<'_>,
) -> Result<ClientAssertionClaims, IssuerdError> {
    use jsonwebtoken::Algorithm as A;
    let header =
        jsonwebtoken::decode_header(assertion).map_err(|e| invalid_caused("malformed JWT", e))?;
    match header.alg {
        A::HS256 | A::HS384 | A::HS512 => {}
        other => {
            return Err(IssuerdError::InvalidRequest(format!(
                "unsupported client assertion algorithm for client_secret_jwt: {other:?}"
            )))
        }
    }
    let key = jsonwebtoken::DecodingKey::from_secret(client_secret.as_bytes());
    let validation = assertion_validation(header.alg, requirements);
    decode_and_check(assertion, &key, &validation, requirements)
}

/// Verify a `private_key_jwt` assertion against the client's JWKS document.
/// Only asymmetric algorithms are accepted; candidate keys are filtered by
/// `kid` (when the assertion carries one) and algorithm family.
pub fn validate_private_key_assertion(
    assertion: &str,
    jwks: &serde_json::Value,
    requirements: &ClientAssertionRequirements<'_>,
) -> Result<ClientAssertionClaims, IssuerdError> {
    use jsonwebtoken::Algorithm as A;
    let header =
        jsonwebtoken::decode_header(assertion).map_err(|e| invalid_caused("malformed JWT", e))?;
    match header.alg {
        A::RS256 | A::RS384 | A::RS512 | A::ES256 | A::ES384 | A::EdDSA => {}
        other => {
            return Err(IssuerdError::InvalidRequest(format!(
                "unsupported client assertion algorithm for private_key_jwt: {other:?}"
            )))
        }
    }
    let jwks: ExternalJwks = serde_json::from_value(jwks.clone())
        .map_err(|e| invalid_caused("malformed client JWKS", e))?;
    let keys = candidate_keys(&jwks, header.alg, header.kid.as_deref());
    if keys.is_empty() {
        return Err(invalid());
    }
    let validation = assertion_validation(header.alg, requirements);
    let mut last_err = invalid();
    for key in keys {
        match decode_and_check(assertion, &key, &validation, requirements) {
            Ok(claims) => return Ok(claims),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Whether the JWKS contains a key that could plausibly have signed this
/// assertion (`kid` + algorithm family). The server uses this to decide
/// whether an unknown `kid` warrants one JWKS refetch (key rotation).
pub fn jwks_covers_assertion(jwks: &serde_json::Value, assertion: &str) -> bool {
    let Ok(header) = jsonwebtoken::decode_header(assertion) else {
        return false;
    };
    let Ok(jwks) = serde_json::from_value::<ExternalJwks>(jwks.clone()) else {
        return false;
    };
    jwks.keys.iter().any(|k| {
        alg_matches_kty(&k.kty, header.alg) && kid_matches(header.kid.as_deref(), k.kid.as_deref())
    })
}

fn assertion_validation(
    alg: jsonwebtoken::Algorithm,
    requirements: &ClientAssertionRequirements<'_>,
) -> jsonwebtoken::Validation {
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.leeway = requirements.leeway_secs;
    // `exp` stays a required claim (Validation::new default); a missing `aud`
    // or one disjoint from the accepted list is rejected here, and
    // `check_claims` re-checks presence explicitly.
    validation.set_audience(requirements.accepted_audiences);
    validation
}

/// Candidate verification keys: right algorithm family, and `kid`-matching
/// when the assertion names a key (a JWKS key without `kid` cannot satisfy a
/// named `kid`; an unnamed assertion tries every key of the family).
///
/// Shared with [`crate::request_object`] (JAR validation uses the identical
/// key-selection rule).
pub(crate) fn candidate_keys(
    jwks: &ExternalJwks,
    alg: jsonwebtoken::Algorithm,
    kid: Option<&str>,
) -> Vec<jsonwebtoken::DecodingKey> {
    jwks.keys
        .iter()
        .filter(|k| alg_matches_kty(&k.kty, alg))
        .filter(|k| kid_matches(kid, k.kid.as_deref()))
        .filter_map(|k| decoding_key(k).ok())
        .collect()
}

fn kid_matches(assertion_kid: Option<&str>, jwk_kid: Option<&str>) -> bool {
    match (assertion_kid, jwk_kid) {
        (Some(want), Some(have)) => want == have,
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn decode_and_check(
    assertion: &str,
    key: &jsonwebtoken::DecodingKey,
    validation: &jsonwebtoken::Validation,
    requirements: &ClientAssertionRequirements<'_>,
) -> Result<ClientAssertionClaims, IssuerdError> {
    let payload = jsonwebtoken::decode::<AssertionPayload>(assertion, key, validation)
        .map_err(|e| invalid_caused("JWT validation", e))?
        .claims;
    check_claims(payload, requirements)
}

fn check_claims(
    payload: AssertionPayload,
    requirements: &ClientAssertionRequirements<'_>,
) -> Result<ClientAssertionClaims, IssuerdError> {
    // RFC 7523 §3 / OIDC Core §9: iss and sub both identify the client, and
    // both must equal the client_id the request was made with.
    let iss = payload.iss.filter(|s| !s.is_empty()).ok_or_else(invalid)?;
    let sub = payload.sub.filter(|s| !s.is_empty()).ok_or_else(invalid)?;
    if iss != requirements.expected_client_id || sub != requirements.expected_client_id {
        return Err(invalid());
    }
    if payload.aud.0.is_empty() {
        return Err(invalid());
    }
    let exp = payload.exp.ok_or_else(invalid)?;
    let now = chrono::Utc::now().timestamp();
    let leeway = requirements.leeway_secs as i64;
    // jsonwebtoken does not validate iat: reject assertions dated in the
    // future (beyond leeway).
    if let Some(iat) = payload.iat {
        if iat > now + leeway {
            return Err(invalid());
        }
    }
    // Lifetime cap: without it a client could force the server to remember a
    // jti (replay protection) for an unbounded time.
    if exp > now + requirements.max_lifetime_secs as i64 + leeway {
        return Err(invalid());
    }
    Ok(ClientAssertionClaims {
        iss,
        sub,
        aud: payload.aud.0,
        exp,
        iat: payload.iat,
        jti: payload.jti,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::{CryptoConfig, RingCryptoProvider};
    use base64::Engine;
    use issuerd_core::{Algorithm, CryptoProvider};

    const CLIENT_ID: &str = "jwt-client";
    const SECRET: &str = "super-secret-value";

    fn issuer() -> String {
        "https://auth.example.com/realms/test".to_string()
    }

    fn token_url() -> String {
        format!("{}/protocol/openid-connect/token", issuer())
    }

    fn accepted() -> Vec<String> {
        vec![issuer(), token_url()]
    }

    fn req_with(aud: &[String]) -> ClientAssertionRequirements<'_> {
        ClientAssertionRequirements {
            expected_client_id: CLIENT_ID,
            accepted_audiences: aud,
            leeway_secs: 60,
            max_lifetime_secs: 300,
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": token_url(),
            "exp": now() + 240,
            "iat": now(),
            "jti": "jti-1",
        })
    }

    // --- RS256 fixture (private_key_jwt) ------------------------------------

    struct RsaFixture {
        crypto: RingCryptoProvider,
        jwks: serde_json::Value,
        kid: String,
    }

    async fn rsa_fixture() -> RsaFixture {
        let crypto = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwk_set = crypto.get_public_keys().await.unwrap();
        let kid = jwk_set.keys[0].kid.to_string();
        let jwks = serde_json::to_value(&jwk_set).unwrap();
        RsaFixture { crypto, jwks, kid }
    }

    impl RsaFixture {
        async fn sign(&self, claims: serde_json::Value) -> String {
            self.crypto
                .sign(
                    &serde_json::to_string(&claims).unwrap(),
                    Algorithm::Rs256,
                    &issuerd_core::KeyId::new(self.kid.clone()).unwrap(),
                )
                .await
                .unwrap()
        }
    }

    // --- HMAC helper (client_secret_jwt) -------------------------------------

    fn sign_hs256(claims: serde_json::Value, secret: &str) -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    // --- private_key_jwt ------------------------------------------------------

    #[tokio::test]
    async fn private_key_jwt_valid_roundtrip() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        let token = fx.sign(valid_claims()).await;
        let claims = validate_private_key_assertion(&token, &fx.jwks, &req_with(&aud)).unwrap();
        assert_eq!(claims.iss, CLIENT_ID);
        assert_eq!(claims.sub, CLIENT_ID);
        assert_eq!(claims.jti.as_deref(), Some("jti-1"));
    }

    #[tokio::test]
    async fn private_key_jwt_audience_array_accepted() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!(["https://other.example.com", issuer()]);
        let token = fx.sign(claims).await;
        let claims = validate_private_key_assertion(&token, &fx.jwks, &req_with(&aud)).unwrap();
        assert_eq!(claims.aud.len(), 2);
    }

    #[tokio::test]
    async fn private_key_jwt_wrong_signature_rejected() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        let token = fx.sign(valid_claims()).await;
        let other = rsa_fixture().await;
        assert!(validate_private_key_assertion(&token, &other.jwks, &req_with(&aud)).is_err());
    }

    #[tokio::test]
    async fn private_key_jwt_wrong_iss_sub_rejected() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        for (claim, value) in [("iss", "other"), ("sub", "other")] {
            let mut claims = valid_claims();
            claims[claim] = serde_json::json!(value);
            let token = fx.sign(claims).await;
            assert!(
                validate_private_key_assertion(&token, &fx.jwks, &req_with(&aud)).is_err(),
                "{claim} mismatch must reject"
            );
        }
    }

    #[tokio::test]
    async fn private_key_jwt_audience_rejections() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        // aud naming none of the accepted values.
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!("https://attacker.example.com");
        let token = fx.sign(claims).await;
        assert!(validate_private_key_assertion(&token, &fx.jwks, &req_with(&aud)).is_err());
        // aud missing entirely.
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("aud");
        let token = fx.sign(claims).await;
        assert!(validate_private_key_assertion(&token, &fx.jwks, &req_with(&aud)).is_err());
    }

    #[tokio::test]
    async fn private_key_jwt_expired_and_oversized_lifetime_rejected() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        // Expired beyond leeway.
        let mut claims = valid_claims();
        claims["exp"] = serde_json::json!(now() - 3600);
        claims["iat"] = serde_json::json!(now() - 3700);
        let token = fx.sign(claims).await;
        assert!(validate_private_key_assertion(&token, &fx.jwks, &req_with(&aud)).is_err());
        // exp beyond the lifetime cap (fresh, but too long-lived).
        let mut claims = valid_claims();
        claims["exp"] = serde_json::json!(now() + 3600);
        let token = fx.sign(claims).await;
        assert!(validate_private_key_assertion(&token, &fx.jwks, &req_with(&aud)).is_err());
    }

    #[tokio::test]
    async fn private_key_jwt_future_iat_rejected() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        let mut claims = valid_claims();
        claims["iat"] = serde_json::json!(now() + 3600);
        let token = fx.sign(claims).await;
        assert!(validate_private_key_assertion(&token, &fx.jwks, &req_with(&aud)).is_err());
    }

    #[tokio::test]
    async fn private_key_jwt_hmac_alg_rejected() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        let token = sign_hs256(valid_claims(), SECRET);
        assert!(matches!(
            validate_private_key_assertion(&token, &fx.jwks, &req_with(&aud)),
            Err(IssuerdError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn private_key_jwt_unknown_kid_rejected_and_detected() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        let token = fx.sign(valid_claims()).await;
        // A JWKS from a different key neither validates nor covers the kid.
        let other = rsa_fixture().await;
        assert!(!jwks_covers_assertion(&other.jwks, &token));
        assert!(validate_private_key_assertion(&token, &other.jwks, &req_with(&aud)).is_err());
        // The signing JWKS covers it, and an empty JWKS does not.
        assert!(jwks_covers_assertion(&fx.jwks, &token));
        assert!(!jwks_covers_assertion(&serde_json::json!({"keys": []}), &token));
        assert!(!jwks_covers_assertion(&serde_json::json!({"keys": []}), "not-a-jwt"));
    }

    #[tokio::test]
    async fn private_key_jwt_kidless_assertion_falls_back_to_family_keys() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        // A kidless assertion (hand-crafted header, invalid signature) must be
        // *covered* by the JWKS (family match, no kid filter) and then cleanly
        // rejected on signature — never a panic, never a false accept.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&valid_claims()).unwrap());
        let forged = format!("{header}.{claims}.AAAA");
        assert!(jwks_covers_assertion(&fx.jwks, &forged));
        assert!(validate_private_key_assertion(&forged, &fx.jwks, &req_with(&aud)).is_err());
    }

    // --- client_secret_jwt ----------------------------------------------------

    #[test]
    fn client_secret_jwt_valid_roundtrip() {
        let aud = accepted();
        let token = sign_hs256(valid_claims(), SECRET);
        let claims = validate_client_secret_assertion(&token, SECRET, &req_with(&aud)).unwrap();
        assert_eq!(claims.iss, CLIENT_ID);
        assert_eq!(claims.exp, now() + 240);
    }

    #[test]
    fn client_secret_jwt_wrong_secret_rejected() {
        let aud = accepted();
        let token = sign_hs256(valid_claims(), SECRET);
        assert!(validate_client_secret_assertion(&token, "other-secret", &req_with(&aud)).is_err());
    }

    #[test]
    fn client_secret_jwt_claim_rules_enforced() {
        let aud = accepted();
        // iss != client_id
        let mut claims = valid_claims();
        claims["iss"] = serde_json::json!("other");
        assert!(validate_client_secret_assertion(
            &sign_hs256(claims, SECRET),
            SECRET,
            &req_with(&aud)
        )
        .is_err());
        // aud wrong
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!("https://attacker.example.com");
        assert!(validate_client_secret_assertion(
            &sign_hs256(claims, SECRET),
            SECRET,
            &req_with(&aud)
        )
        .is_err());
        // expired
        let mut claims = valid_claims();
        claims["exp"] = serde_json::json!(now() - 3600);
        assert!(validate_client_secret_assertion(
            &sign_hs256(claims, SECRET),
            SECRET,
            &req_with(&aud)
        )
        .is_err());
    }

    #[tokio::test]
    async fn client_secret_jwt_asymmetric_alg_rejected() {
        let fx = rsa_fixture().await;
        let aud = accepted();
        let token = fx.sign(valid_claims()).await;
        assert!(matches!(
            validate_client_secret_assertion(&token, SECRET, &req_with(&aud)),
            Err(IssuerdError::InvalidRequest(_))
        ));
    }

    #[test]
    fn client_secret_jwt_hs384_hs512_accepted() {
        let aud = accepted();
        for alg in [
            jsonwebtoken::Algorithm::HS384,
            jsonwebtoken::Algorithm::HS512,
        ] {
            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(alg),
                &valid_claims(),
                &jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes()),
            )
            .unwrap();
            assert!(validate_client_secret_assertion(&token, SECRET, &req_with(&aud)).is_ok());
        }
    }
}
