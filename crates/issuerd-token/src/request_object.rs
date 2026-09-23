// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Validation of signed Request Objects (JAR, RFC 9101).
//!
//! Pure cryptography and envelope-claim checks only — no storage, no network.
//! The caller (issuerd-server) supplies the verification material (the client's
//! JWKS document, inline or fetched, or the client secret) and converts the
//! returned claims into authorization-request parameters.
//!
//! Checks performed:
//! - the JWT is signed: `none` (unsigned Request Objects) and unknown
//!   algorithms are always rejected — FAPI-aligned, stricter than Keycloak's
//!   default (which tolerates unsigned objects unless the client pins a
//!   signature algorithm), and required by the OIDC conformance
//!   unsigned-request-object module;
//! - signature: against a JWKS key matching `kid` + algorithm family
//!   (asymmetric algorithms) or HMAC keyed with the client secret
//!   (HS256/384/512 — RFC 9101 §10.2);
//! - `iss` is REQUIRED and equals the `client_id` from the enclosing
//!   authorization request (RFC 9101 §4);
//! - `aud`, when present, must include the realm issuer URL (RFC 9101 §4
//!   lists `aud` as REQUIRED; absence is tolerated for Keycloak
//!   compatibility);
//! - `exp`, when present, must be fresh (leeway applies); `iat`, when
//!   present, must not be in the future.

use issuerd_core::IssuerdError;

use crate::client_assertion::candidate_keys;
use crate::external::ExternalJwks;

/// Requirements a Request Object must satisfy.
#[derive(Debug, Clone)]
pub struct RequestObjectRequirements<'a> {
    /// The `client_id` from the enclosing authorization request: `iss` must
    /// equal it (RFC 9101 §4).
    pub expected_client_id: &'a str,
    /// The realm issuer URL: `aud`, when present, must contain it.
    pub accepted_issuer: &'a str,
    /// Clock-skew leeway in seconds (applied to `exp`/`iat`).
    pub leeway_secs: u64,
}

fn invalid() -> IssuerdError {
    // Uniform, detail-free error for claim-shape failures: request-object
    // failures must not leak internals to clients. The endpoint logs specifics
    // itself. Crypto/parse failures embed the jsonwebtoken/serde cause at the
    // call site (`invalid request object: {e}`) — these messages never reach
    // the OAuth client (the endpoint answers a fixed `invalid_request`), so
    // the cause is safe to carry for upstream WARN logs.
    IssuerdError::InvalidToken
}

/// A crypto/parse failure with the underlying cause embedded (see [`invalid`]).
fn invalid_caused(context: &str, e: impl std::fmt::Display) -> IssuerdError {
    IssuerdError::InvalidRequest(format!("invalid request object ({context}): {e}"))
}

/// Verify a signed Request Object and return its claims on success.
///
/// `client_jwks` is the client's JWKS document (inline or already fetched)
/// for asymmetric algorithms; `client_secret` keys HMAC algorithms. Passing
/// neither always fails — an unsigned (or unverifiable) Request Object is
/// rejected.
pub fn validate_request_object(
    request_object: &str,
    client_jwks: Option<&serde_json::Value>,
    client_secret: Option<&str>,
    requirements: &RequestObjectRequirements<'_>,
) -> Result<serde_json::Map<String, serde_json::Value>, IssuerdError> {
    use jsonwebtoken::Algorithm as A;
    let header = jsonwebtoken::decode_header(request_object)
        .map_err(|e| invalid_caused("malformed JWT", e))?;

    let keys: Vec<jsonwebtoken::DecodingKey> = match header.alg {
        A::RS256 | A::RS384 | A::RS512 | A::ES256 | A::ES384 | A::EdDSA => {
            let jwks = client_jwks.ok_or_else(invalid)?;
            let jwks: ExternalJwks = serde_json::from_value(jwks.clone())
                .map_err(|e| invalid_caused("malformed client JWKS", e))?;
            candidate_keys(&jwks, header.alg, header.kid.as_deref())
        }
        A::HS256 | A::HS384 | A::HS512 => {
            let secret = client_secret.filter(|s| !s.is_empty()).ok_or_else(invalid)?;
            vec![jsonwebtoken::DecodingKey::from_secret(secret.as_bytes())]
        }
        other => {
            return Err(IssuerdError::InvalidRequest(format!(
                "request object must be signed with a supported algorithm: {other:?}"
            )))
        }
    };
    if keys.is_empty() {
        return Err(invalid());
    }

    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.leeway = requirements.leeway_secs;
    // `exp` is optional on Request Objects (RFC 9101 §4 does not mandate it);
    // freshness is still enforced when the claim is present.
    validation.required_spec_claims.remove("exp");
    // `aud` is optional and allowlist-checked manually below.
    validation.validate_aud = false;

    let mut last_err = invalid();
    for key in &keys {
        match jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
            request_object,
            key,
            &validation,
        ) {
            Ok(data) => return check_claims(data.claims, requirements),
            Err(e) => last_err = invalid_caused("JWT validation", e),
        }
    }
    Err(last_err)
}

/// Envelope-claim checks: `iss` binds the object to the requesting client;
/// `aud` (when present) binds it to this server; `iat` must not be future.
fn check_claims(
    claims: serde_json::Map<String, serde_json::Value>,
    requirements: &RequestObjectRequirements<'_>,
) -> Result<serde_json::Map<String, serde_json::Value>, IssuerdError> {
    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(invalid)?;
    if iss != requirements.expected_client_id {
        return Err(invalid());
    }

    if let Some(aud) = claims.get("aud") {
        let covered = match aud {
            serde_json::Value::String(s) => s == requirements.accepted_issuer,
            serde_json::Value::Array(list) => list
                .iter()
                .filter_map(|v| v.as_str())
                .any(|s| s == requirements.accepted_issuer),
            _ => false,
        };
        if !covered {
            return Err(invalid());
        }
    }

    // jsonwebtoken does not validate iat: reject objects dated in the future
    // (beyond leeway).
    if let Some(iat) = claims.get("iat").and_then(|v| v.as_i64()) {
        let now = chrono::Utc::now().timestamp();
        if iat > now + requirements.leeway_secs as i64 {
            return Err(invalid());
        }
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{Algorithm, CryptoProvider};
    use std::sync::Arc;

    const SECRET: &str = "s3cr3t";
    const CLIENT_ID: &str = "jar-client";
    const ISSUER: &str = "http://localhost:8080/realms/master";

    fn requirements() -> RequestObjectRequirements<'static> {
        RequestObjectRequirements {
            expected_client_id: CLIENT_ID,
            accepted_issuer: ISSUER,
            leeway_secs: 60,
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": CLIENT_ID,
            "aud": ISSUER,
            "exp": now() + 300,
            "iat": now(),
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "https://client.example.com/cb",
            "scope": "openid profile",
            "state": "s-1",
        })
    }

    fn sign_hs256(claims: &serde_json::Value, secret: &str) -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    async fn rsa_material() -> (serde_json::Value, Arc<crate::RingCryptoProvider>, String) {
        let crypto = Arc::new(
            crate::RingCryptoProvider::new(crate::CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = serde_json::to_value(crypto.get_public_keys().await.unwrap()).unwrap();
        let kid = jwks["keys"][0]["kid"].as_str().unwrap().to_string();
        (jwks, crypto, kid)
    }

    async fn sign_rs256(
        crypto: &crate::RingCryptoProvider,
        kid: &str,
        claims: &serde_json::Value,
    ) -> String {
        crypto
            .sign(
                &serde_json::to_string(claims).unwrap(),
                Algorithm::Rs256,
                &issuerd_core::KeyId::new(kid).unwrap(),
            )
            .await
            .unwrap()
    }

    #[test]
    fn hs256_request_object_accepted() {
        let jwt = sign_hs256(&valid_claims(), SECRET);
        let claims = validate_request_object(&jwt, None, Some(SECRET), &requirements()).unwrap();
        assert_eq!(claims["response_type"], "code");
        assert_eq!(claims["redirect_uri"], "https://client.example.com/cb");
    }

    #[test]
    fn hs256_request_object_wrong_secret_rejected() {
        let jwt = sign_hs256(&valid_claims(), "wrong-secret");
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_err());
    }

    #[test]
    fn hs256_request_object_without_secret_rejected() {
        let jwt = sign_hs256(&valid_claims(), SECRET);
        // No verification material configured at all.
        assert!(validate_request_object(&jwt, None, None, &requirements()).is_err());
    }

    #[test]
    fn unsigned_request_object_rejected() {
        // alg=none: header + payload + empty signature. jsonwebtoken's
        // Algorithm enum has no `none` variant, so this is rejected at header
        // decode — either way, an unsigned Request Object never validates.
        let header = base64_url(br#"{"alg":"none"}"#);
        let payload = base64_url(serde_json::to_string(&valid_claims()).unwrap().as_bytes());
        let jwt = format!("{header}.{payload}.");
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_err());
    }

    #[test]
    fn unsupported_algorithm_rejected_with_invalid_request() {
        // An alg jsonwebtoken recognizes but the validator does not accept
        // (PS256) is rejected before any signature work — a fake signature
        // segment is enough to reach the algorithm check.
        let header = base64_url(br#"{"alg":"PS256"}"#);
        let payload = base64_url(serde_json::to_string(&valid_claims()).unwrap().as_bytes());
        let jwt = format!("{header}.{payload}.ZmFrZQ");
        let err = validate_request_object(&jwt, None, Some(SECRET), &requirements()).unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn rs256_request_object_accepted_via_jwks() {
        let (jwks, crypto, kid) = rsa_material().await;
        let jwt = sign_rs256(&crypto, &kid, &valid_claims()).await;
        let claims = validate_request_object(&jwt, Some(&jwks), None, &requirements()).unwrap();
        assert_eq!(claims["client_id"], CLIENT_ID);
    }

    #[tokio::test]
    async fn rs256_request_object_wrong_key_rejected() {
        let (jwks, _crypto, _kid) = rsa_material().await;
        // Signed by a DIFFERENT provider than the JWKS contains.
        let (_other_jwks, other_crypto, other_kid) = rsa_material().await;
        let jwt = sign_rs256(&other_crypto, &other_kid, &valid_claims()).await;
        assert!(validate_request_object(&jwt, Some(&jwks), None, &requirements()).is_err());
    }

    #[tokio::test]
    async fn rs256_request_object_without_jwks_rejected() {
        let (_jwks, crypto, kid) = rsa_material().await;
        let jwt = sign_rs256(&crypto, &kid, &valid_claims()).await;
        assert!(validate_request_object(&jwt, None, None, &requirements()).is_err());
    }

    #[test]
    fn iss_mismatch_rejected() {
        let mut claims = valid_claims();
        claims["iss"] = serde_json::json!("other-client");
        let jwt = sign_hs256(&claims, SECRET);
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_err());
    }

    #[test]
    fn missing_iss_rejected() {
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("iss");
        let jwt = sign_hs256(&claims, SECRET);
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_err());
    }

    #[test]
    fn aud_mismatch_rejected_when_present() {
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!("https://other-issuer.example.com");
        let jwt = sign_hs256(&claims, SECRET);
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_err());
    }

    #[test]
    fn aud_array_covering_issuer_accepted() {
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!(["https://other.example.com", ISSUER]);
        let jwt = sign_hs256(&claims, SECRET);
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_ok());
    }

    #[test]
    fn missing_aud_tolerated() {
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("aud");
        let jwt = sign_hs256(&claims, SECRET);
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_ok());
    }

    #[test]
    fn expired_request_object_rejected() {
        let mut claims = valid_claims();
        claims["exp"] = serde_json::json!(now() - 3600);
        let jwt = sign_hs256(&claims, SECRET);
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_err());
    }

    #[test]
    fn missing_exp_tolerated() {
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("exp");
        let jwt = sign_hs256(&claims, SECRET);
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_ok());
    }

    #[test]
    fn future_iat_rejected() {
        let mut claims = valid_claims();
        claims["iat"] = serde_json::json!(now() + 3600);
        let jwt = sign_hs256(&claims, SECRET);
        assert!(validate_request_object(&jwt, None, Some(SECRET), &requirements()).is_err());
    }

    #[test]
    fn malformed_jwt_rejected() {
        assert!(validate_request_object("not-a-jwt", None, Some(SECRET), &requirements()).is_err());
        assert!(validate_request_object("", None, Some(SECRET), &requirements()).is_err());
    }

    fn base64_url(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
}
