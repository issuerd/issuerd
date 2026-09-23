// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Short-lived, single-purpose signed action tokens for user self-service flows.

//! Short-lived, single-purpose signed action tokens (relocated from
//! `issuerd-server` so `issuerd-admin-api` can use them).
//!
//! Action tokens are compact JWS payloads signed with the realm's current
//! signing key (via [`issuerd_core::CryptoProvider`]). They back out-of-band user
//! self-service flows: the reset-credentials email link, the remember-me
//! cookie, broker account linking, and execute-actions emails. They
//! deliberately bypass `TokenService` — their claims shape
//! ([`issuerd_core::ActionTokenClaims`]) is not an access token, so signature,
//! purpose, realm binding, and expiry are all verified here manually.
//!
//! Single-use semantics are **not** enforced here: flows that need them
//! (reset-credentials) consume the `jti` through the distributed cache at the
//! point of use, while reusable tokens (remember-me cookie) skip that step.

use base64::Engine;
use chrono::Utc;
use issuerd_core::{
    ActionTokenClaims, Algorithm, CryptoProvider, IssuerdError, KeyId, RealmId, UserId,
};

/// Leeway (seconds) applied when checking `exp`, for clock skew between
/// nodes in a cluster.
const EXP_LEEWAY_SECS: i64 = 60;

/// Issue a signed action token with the realm's current signing key.
pub async fn issue_action_token(
    crypto: &dyn CryptoProvider,
    claims: &ActionTokenClaims,
) -> Result<String, IssuerdError> {
    let jwks = crypto.get_public_keys().await?;
    let key = jwks
        .keys
        .first()
        .ok_or_else(|| IssuerdError::ServerError("no active signing key".to_string()))?;
    let payload = serde_json::to_string(claims)
        .map_err(|e| IssuerdError::ServerError(format!("action token serialization: {e}")))?;
    crypto.sign(&payload, key.alg, &key.kid).await
}

/// Verify an action token: signature, purpose, realm binding, and expiry.
///
/// Returns the decoded claims on success. Callers enforcing single-use must
/// additionally consume `claims.jti` from the cache.
pub async fn verify_action_token(
    crypto: &dyn CryptoProvider,
    token: &str,
    expected_purpose: &str,
    realm_id: &RealmId,
) -> Result<ActionTokenClaims, IssuerdError> {
    let invalid = || IssuerdError::InvalidRequest("invalid or expired action token".to_string());

    let mut parts = token.split('.');
    let (header_b64, payload_b64) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(_sig), None) => (h, p),
        _ => return Err(invalid()),
    };

    #[derive(serde::Deserialize)]
    struct TokenHeader {
        kid: String,
        alg: String,
    }
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| invalid())?;
    let header: TokenHeader = serde_json::from_slice(&header_bytes).map_err(|_| invalid())?;
    let alg: Algorithm = header.alg.parse().map_err(|_| invalid())?;

    let ok = crypto.verify(token, alg, &KeyId::new(header.kid)?).await?;
    if !ok {
        return Err(invalid());
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| invalid())?;
    let claims: ActionTokenClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| invalid())?;

    if claims.purpose != expected_purpose || claims.realm != realm_id.as_ref() {
        return Err(invalid());
    }
    if Utc::now().timestamp() > claims.exp + EXP_LEEWAY_SECS {
        return Err(invalid());
    }
    Ok(claims)
}

/// Build the claims for a freshly minted action token.
pub fn action_token_claims(
    user_id: &UserId,
    realm_id: &RealmId,
    purpose: &str,
    ttl_secs: i64,
) -> ActionTokenClaims {
    let now = Utc::now().timestamp();
    ActionTokenClaims {
        sub: user_id.to_string(),
        realm: realm_id.to_string(),
        purpose: purpose.to_string(),
        exp: now + ttl_secs,
        iat: now,
        jti: issuerd_core::utils::generate_id(),
        auth_time: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::{CryptoConfig, RingCryptoProvider};

    fn test_crypto() -> RingCryptoProvider {
        RingCryptoProvider::new(CryptoConfig::default()).unwrap()
    }

    fn test_realm_id() -> RealmId {
        RealmId::new("realm-1").unwrap()
    }

    fn test_user_id() -> UserId {
        UserId::new("user-1").unwrap()
    }

    #[tokio::test]
    async fn issue_and_verify_roundtrip() {
        let crypto = test_crypto();
        let claims =
            action_token_claims(&test_user_id(), &test_realm_id(), "reset-credentials", 900);

        let token = issue_action_token(&crypto, &claims).await.unwrap();
        assert_eq!(token.split('.').count(), 3, "action token is a compact JWS");

        let verified = verify_action_token(&crypto, &token, "reset-credentials", &test_realm_id())
            .await
            .unwrap();
        assert_eq!(verified, claims);
    }

    #[tokio::test]
    async fn verify_rejects_purpose_mismatch() {
        let crypto = test_crypto();
        let claims =
            action_token_claims(&test_user_id(), &test_realm_id(), "reset-credentials", 900);
        let token = issue_action_token(&crypto, &claims).await.unwrap();

        let err = verify_action_token(&crypto, &token, "remember-me", &test_realm_id())
            .await
            .unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn verify_rejects_realm_mismatch() {
        let crypto = test_crypto();
        let claims =
            action_token_claims(&test_user_id(), &test_realm_id(), "reset-credentials", 900);
        let token = issue_action_token(&crypto, &claims).await.unwrap();

        let other_realm = RealmId::new("realm-2").unwrap();
        let err = verify_action_token(&crypto, &token, "reset-credentials", &other_realm)
            .await
            .unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn verify_rejects_expired_token() {
        let crypto = test_crypto();
        // exp lands beyond the 60-second leeway in the past.
        let claims =
            action_token_claims(&test_user_id(), &test_realm_id(), "reset-credentials", -120);
        let token = issue_action_token(&crypto, &claims).await.unwrap();

        let err = verify_action_token(&crypto, &token, "reset-credentials", &test_realm_id())
            .await
            .unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn verify_rejects_malformed_two_part_token() {
        let crypto = test_crypto();
        let err =
            verify_action_token(&crypto, "header.payload", "reset-credentials", &test_realm_id())
                .await
                .unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)));
    }
}
