// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Validation of external (brokered) ID tokens for identity brokering.

//! Validation of **external** ID tokens for identity brokering.
//!
//! Unlike the realm's own tokens (validated against the internal keystore via
//! [`crate::token_manager::TokenManager`]), brokered ID tokens are signed by an
//! external IdP whose public keys arrive as a fetched JWKS document. This
//! module validates such tokens purely cryptographically — no storage, no
//! network (the JWKS document is fetched by the caller, via the `BrokerClient`
//! abstraction, and cached).
//!
//! Checks performed (OIDC Core 3.1.3.7):
//! - signature against a JWKS key matching `kid` (and algorithm family);
//! - `exp` (with leeway) and `nbf` via `jsonwebtoken`;
//! - `aud` contains our client id, and `azp` matches when `aud` has several
//!   entries;
//! - `iss` equals the expected issuer when one is configured;
//! - `nonce` equals the expected nonce when one was sent (replay protection).
//!
//! Only asymmetric algorithms are accepted (RSA / EC / EdDSA). HMAC-signed ID
//! tokens (`HS*`, keyed by the client secret) are rejected: accepting them
//! would require shipping the client secret into validation and offers no
//! security advantage over the server-to-server code exchange that precedes
//! this step.

use base64::Engine;
use issuerd_core::IssuerdError;

/// Requirements a brokered ID token must satisfy.
#[derive(Debug, Clone)]
pub struct ExternalIdTokenRequirements<'a> {
    /// Expected `iss` (from discovery or the configured issuer). When `None`
    /// the issuer is not checked (IdPs without a stable issuer, e.g. some
    /// social providers).
    pub expected_issuer: Option<&'a str>,
    /// Our client id at the external IdP; must appear in `aud`.
    pub expected_audience: &'a str,
    /// The nonce sent on the authorization request, when any.
    pub expected_nonce: Option<&'a str>,
    /// Clock-skew leeway in seconds.
    pub leeway_secs: u64,
}

/// A JWK from an external JWKS document, parsed leniently (RFC 7517 marks
/// `alg`/`use` optional, and real-world IdPs omit them — unknown fields such
/// as `alg` are simply ignored here; the token header pins the algorithm).
///
/// Shared with `crate::client_assertion`, which validates client
/// assertions against per-client JWKS documents of the same shape.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ExternalJwk {
    pub(crate) kty: String,
    pub(crate) kid: Option<String>,
    pub(crate) n: Option<String>,
    pub(crate) e: Option<String>,
    pub(crate) x: Option<String>,
    pub(crate) y: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ExternalJwks {
    pub(crate) keys: Vec<ExternalJwk>,
}

#[derive(Debug, serde::Deserialize)]
struct TokenHeader {
    kid: Option<String>,
    alg: String,
}

fn invalid() -> IssuerdError {
    // Uniform, detail-free error for rejections that carry no underlying
    // cause (key selection, azp, nonce). Failures that do have a cause go
    // through [`invalid_caused`].
    IssuerdError::InvalidToken
}

/// Validation failure with the upstream cause embedded in the message. These
/// messages only ever reach server-side logs (the broker endpoint maps every
/// validation failure to a generic client-facing error), so including the
/// cause is safe and lets upstream WARN records distinguish an expired token
/// from a bad signature or a malformed JWKS document.
fn invalid_caused(context: &str, cause: impl std::fmt::Display) -> IssuerdError {
    IssuerdError::InvalidRequest(format!("{context}: {cause}"))
}

pub(crate) fn map_alg(name: &str) -> Result<jsonwebtoken::Algorithm, IssuerdError> {
    match name {
        "RS256" => Ok(jsonwebtoken::Algorithm::RS256),
        "RS384" => Ok(jsonwebtoken::Algorithm::RS384),
        "RS512" => Ok(jsonwebtoken::Algorithm::RS512),
        "ES256" => Ok(jsonwebtoken::Algorithm::ES256),
        "ES384" => Ok(jsonwebtoken::Algorithm::ES384),
        "EdDSA" => Ok(jsonwebtoken::Algorithm::EdDSA),
        other => Err(IssuerdError::InvalidRequest(format!(
            "unsupported external ID token algorithm: {other}"
        ))),
    }
}

pub(crate) fn decoding_key(jwk: &ExternalJwk) -> Result<jsonwebtoken::DecodingKey, IssuerdError> {
    match jwk.kty.as_str() {
        "RSA" => {
            let (n, e) = match (&jwk.n, &jwk.e) {
                (Some(n), Some(e)) => (n, e),
                _ => return Err(invalid()),
            };
            jsonwebtoken::DecodingKey::from_rsa_components(n, e)
                .map_err(|e| invalid_caused("invalid RSA JWK components", e))
        }
        "EC" => {
            let (x, y) = match (&jwk.x, &jwk.y) {
                (Some(x), Some(y)) => (x, y),
                _ => return Err(invalid()),
            };
            jsonwebtoken::DecodingKey::from_ec_components(x, y)
                .map_err(|e| invalid_caused("invalid EC JWK components", e))
        }
        "OKP" => {
            let x = jwk.x.as_ref().ok_or_else(invalid)?;
            jsonwebtoken::DecodingKey::from_ed_components(x)
                .map_err(|e| invalid_caused("invalid OKP JWK components", e))
        }
        other => Err(IssuerdError::InvalidRequest(format!("unsupported JWK kty: {other}"))),
    }
}

/// Whether the JWK could plausibly have signed a token with `alg`.
pub(crate) fn alg_matches_kty(kty: &str, alg: jsonwebtoken::Algorithm) -> bool {
    use jsonwebtoken::Algorithm as A;
    match kty {
        "RSA" => matches!(alg, A::RS256 | A::RS384 | A::RS512),
        "EC" => matches!(alg, A::ES256 | A::ES384),
        "OKP" => matches!(alg, A::EdDSA),
        _ => false,
    }
}

/// Validate an external ID token against a fetched JWKS document.
///
/// Returns the full claim set on success (subject extraction and mapping into
/// a `BrokeredIdentity` is the caller's job, via
/// `issuerd_core::BrokeredIdentity::from_claims`).
pub fn validate_external_id_token(
    jwks: &serde_json::Value,
    token: &str,
    requirements: &ExternalIdTokenRequirements<'_>,
) -> Result<serde_json::Value, IssuerdError> {
    // Header first: kid + alg select the candidate keys.
    let header_b64 = token.split('.').next().unwrap_or_default();
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| invalid_caused("malformed external ID token header", e))?;
    let header: TokenHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| invalid_caused("malformed external ID token header", e))?;
    let alg = map_alg(&header.alg)?;

    let jwks: ExternalJwks = serde_json::from_value(jwks.clone())
        .map_err(|e| invalid_caused("malformed external JWKS document", e))?;

    // Candidate keys: kid match when the token carries one, otherwise every
    // key of the right family (some IdPs omit kid).
    let candidates: Vec<&ExternalJwk> = jwks
        .keys
        .iter()
        .filter(|k| alg_matches_kty(&k.kty, alg))
        .filter(|k| match (&header.kid, &k.kid) {
            (Some(want), Some(have)) => want == have,
            (Some(_), None) => false,
            (None, _) => true,
        })
        .collect();
    if candidates.is_empty() {
        return Err(invalid());
    }

    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.leeway = requirements.leeway_secs;
    validation.set_audience(&[requirements.expected_audience]);
    if let Some(iss) = requirements.expected_issuer {
        validation.set_issuer(&[iss]);
    }

    let mut last_err = invalid();
    let mut claims: Option<serde_json::Value> = None;
    for jwk in candidates {
        let key = match decoding_key(jwk) {
            Ok(k) => k,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        match jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation) {
            Ok(data) => {
                claims = Some(data.claims);
                break;
            }
            Err(e) => {
                last_err = invalid_caused("external ID token validation failed", e);
            }
        }
    }
    let claims = claims.ok_or(last_err)?;

    // azp: required when aud lists several audiences (OIDC Core 3.1.3.7).
    if let Some(aud) = claims.get("aud") {
        let multi = match aud {
            serde_json::Value::Array(list) => list.len() > 1,
            _ => false,
        };
        if multi {
            let azp = claims.get("azp").and_then(|v| v.as_str());
            if azp != Some(requirements.expected_audience) {
                return Err(invalid());
            }
        }
    }

    // nonce: replay protection for the implicit-ish surface of brokering.
    if let Some(expected) = requirements.expected_nonce {
        let actual = claims.get("nonce").and_then(|v| v.as_str());
        if actual != Some(expected) {
            return Err(invalid());
        }
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::{CryptoConfig, RingCryptoProvider};
    use issuerd_core::{Algorithm, CryptoProvider};

    const ISSUER: &str = "https://idp.example.com";
    const CLIENT_ID: &str = "issuerd-broker";

    struct Fixture {
        crypto: RingCryptoProvider,
        jwks: serde_json::Value,
        kid: String,
    }

    async fn fixture() -> Fixture {
        let crypto = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwk_set = crypto.get_public_keys().await.unwrap();
        let kid = jwk_set.keys[0].kid.to_string();
        // Serialize as a fetched JWKS document would arrive over the wire.
        let jwks = serde_json::to_value(&jwk_set).unwrap();
        Fixture { crypto, jwks, kid }
    }

    impl Fixture {
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

    fn valid_claims() -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({
            "iss": ISSUER,
            "sub": "ext-sub-1",
            "aud": CLIENT_ID,
            "exp": now + 300,
            "iat": now,
            "nonce": "n-123",
            "email": "user@example.com"
        })
    }

    fn requirements<'a>() -> ExternalIdTokenRequirements<'a> {
        ExternalIdTokenRequirements {
            expected_issuer: Some(ISSUER),
            expected_audience: CLIENT_ID,
            expected_nonce: Some("n-123"),
            leeway_secs: 60,
        }
    }

    #[tokio::test]
    async fn valid_token_roundtrip() {
        let fx = fixture().await;
        let token = fx.sign(valid_claims()).await;
        let claims = validate_external_id_token(&fx.jwks, &token, &requirements()).unwrap();
        assert_eq!(claims["sub"], "ext-sub-1");
        assert_eq!(claims["email"], "user@example.com");
    }

    #[tokio::test]
    async fn wrong_issuer_rejected() {
        let fx = fixture().await;
        let mut claims = valid_claims();
        claims["iss"] = serde_json::json!("https://evil.example.com");
        let token = fx.sign(claims).await;
        match validate_external_id_token(&fx.jwks, &token, &requirements()) {
            Err(IssuerdError::InvalidRequest(msg)) => {
                assert!(msg.contains("validation failed"), "cause embedded: {msg}");
                assert!(msg.contains("InvalidIssuer"), "cause embedded: {msg}");
            }
            other => panic!("expected InvalidRequest with cause, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let fx = fixture().await;
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!("someone-else");
        let token = fx.sign(claims).await;
        match validate_external_id_token(&fx.jwks, &token, &requirements()) {
            Err(IssuerdError::InvalidRequest(msg)) => {
                assert!(msg.contains("validation failed"), "cause embedded: {msg}");
                assert!(msg.contains("InvalidAudience"), "cause embedded: {msg}");
            }
            other => panic!("expected InvalidRequest with cause, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_nonce_rejected() {
        let fx = fixture().await;
        let mut claims = valid_claims();
        claims["nonce"] = serde_json::json!("n-other");
        let token = fx.sign(claims).await;
        assert!(matches!(
            validate_external_id_token(&fx.jwks, &token, &requirements()),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let fx = fixture().await;
        let mut claims = valid_claims();
        let now = chrono::Utc::now().timestamp();
        claims["exp"] = serde_json::json!(now - 3600);
        let token = fx.sign(claims).await;
        match validate_external_id_token(&fx.jwks, &token, &requirements()) {
            Err(IssuerdError::InvalidRequest(msg)) => {
                assert!(msg.contains("validation failed"), "cause embedded: {msg}");
                assert!(msg.contains("ExpiredSignature"), "cause embedded: {msg}");
            }
            other => panic!("expected InvalidRequest with cause, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tampered_payload_rejected() {
        let fx = fixture().await;
        let token = fx.sign(valid_claims()).await;
        let mut parts: Vec<&str> = token.split('.').collect();
        let mut claims = valid_claims();
        claims["sub"] = serde_json::json!("attacker");
        parts[1] = Box::leak(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).unwrap())
                .into_boxed_str(),
        );
        let forged = parts.join(".");
        match validate_external_id_token(&fx.jwks, &forged, &requirements()) {
            Err(IssuerdError::InvalidRequest(msg)) => {
                assert!(msg.contains("validation failed"), "cause embedded: {msg}");
                assert!(msg.contains("InvalidSignature"), "cause embedded: {msg}");
            }
            other => panic!("expected InvalidRequest with cause, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_kid_rejected() {
        let fx = fixture().await;
        let token = fx.sign(valid_claims()).await;
        // Swap in a JWKS from a *different* key: no candidate matches.
        let other = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let other_jwks = serde_json::to_value(other.get_public_keys().await.unwrap()).unwrap();
        assert!(matches!(
            validate_external_id_token(&other_jwks, &token, &requirements()),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn multi_audience_requires_azp() {
        let fx = fixture().await;
        // aud array without azp -> rejected.
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!([CLIENT_ID, "second"]);
        let token = fx.sign(claims).await;
        assert!(matches!(
            validate_external_id_token(&fx.jwks, &token, &requirements()),
            Err(IssuerdError::InvalidToken)
        ));
        // With matching azp -> accepted.
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!([CLIENT_ID, "second"]);
        claims["azp"] = serde_json::json!(CLIENT_ID);
        let token = fx.sign(claims).await;
        assert!(validate_external_id_token(&fx.jwks, &token, &requirements()).is_ok());
    }

    #[tokio::test]
    async fn hs256_header_rejected() {
        let fx = fixture().await;
        let token = fx.sign(valid_claims()).await;
        // Rewrite the header alg to HS256 (signature no longer matters).
        let parts: Vec<&str> = token.split('.').collect();
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let forged = format!("{header}.{}.{}", parts[1], parts[2]);
        assert!(matches!(
            validate_external_id_token(&fx.jwks, &forged, &requirements()),
            Err(IssuerdError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn nonce_unchecked_when_not_required() {
        let fx = fixture().await;
        let mut claims = valid_claims();
        claims["nonce"] = serde_json::json!("whatever");
        let token = fx.sign(claims).await;
        let req = ExternalIdTokenRequirements {
            expected_nonce: None,
            ..requirements()
        };
        assert!(validate_external_id_token(&fx.jwks, &token, &req).is_ok());
    }
}
