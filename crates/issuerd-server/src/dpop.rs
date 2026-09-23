// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// DPoP (RFC 9449) endpoint wiring: header extraction, jti replay cache, cnf.jkt binding.

//! DPoP (RFC 9449) endpoint wiring (DPoP chosen over mTLS: it is pure
//! HTTP-header machinery, testable in-process, and needs no TLS termination
//! contract).
//!
//! Proof validation itself is pure and lives in [`issuerd_token::dpop`]; this
//! module adds the stateful parts:
//! - `DPoP` header extraction and the expected `htm`/`htu` derivation from
//!   the configured issuer (the discovery-advertised realm-name spelling is
//!   primary; the realm-id spelling is accepted as tolerance —
//!   `resolve_realm` serves both),
//! - `jti` single-use enforcement in the distributed cache
//!   (`dpop_jti:{realm_id}:{jti}`, TTL = the proof's remaining acceptance
//!   window) via the atomic cache `increment` — the
//!   client-assertion replay-cache pattern, failing closed when the cache is
//!   unavailable,
//! - the `cnf.jkt` claims-overlay merge used to bind issued access tokens
//!   ([`bind_cnf_overlay`]) and the `token_type` response switch
//!   ([`token_type`]).
//!
//! Server-provided DPoP nonces (RFC 9449 §8) are intentionally not
//! implemented (OPTIONAL in the RFC); replay protection rides on `jti` +
//! `iat` instead.

use issuerd_core::{IssuerdError, RealmId};

use crate::state::ServerState;

/// How far in the past a proof's `iat` may lie (acceptance window). Also the
/// upper bound of the replay-cache TTL: a replayed `jti` is only possible
/// while its proof would still be accepted.
pub(crate) const DPOP_PROOF_MAX_AGE_SECS: i64 = 300;
/// Clock-skew leeway for `iat` values in the future.
const DPOP_PROOF_LEEWAY_SECS: i64 = 60;

fn jti_cache_key(realm_id: &RealmId, jti: &str) -> String {
    format!("dpop_jti:{}:{jti}", realm_id.0)
}

/// Accepted `htu` values for `endpoint` (the path tail after
/// `/protocol/openid-connect/`, e.g. `"token"`): the discovery-advertised
/// realm-NAME URL, plus the realm-id spelling as tolerance when the two
/// differ (realm resolution accepts both).
fn accepted_htus(
    state: &ServerState,
    realm_id: &RealmId,
    realm_name: Option<&str>,
    endpoint: &str,
) -> Vec<String> {
    let base = state.config.issuer_url.trim_end_matches('/');
    let primary = realm_name.unwrap_or(realm_id.0.as_str());
    let mut urls = vec![format!(
        "{base}/realms/{primary}/protocol/openid-connect/{endpoint}"
    )];
    if realm_name.is_some_and(|name| name != realm_id.0) {
        urls.push(format!("{base}/realms/{}/protocol/openid-connect/{endpoint}", realm_id.0));
    }
    urls
}

/// Extract and verify the `DPoP` proof header of a request, if present.
///
/// Returns `Ok(None)` when no `DPoP` header was sent (plain Bearer flow). On
/// success the proof's `jti` is burned in the replay cache (fail-closed).
/// All failures map to the uniform [`IssuerdError::InvalidDpopProof`]; specifics
/// are logged, not returned.
pub(crate) async fn verify_proof_header(
    state: &ServerState,
    realm_id: &RealmId,
    realm_name: Option<&str>,
    headers: &axum::http::HeaderMap,
    htm: &str,
    endpoint: &str,
    access_token: Option<&str>,
) -> Result<Option<issuerd_token::VerifiedDpopProof>, IssuerdError> {
    let Some(value) = headers.get("dpop") else {
        return Ok(None);
    };
    let proof = value.to_str().map_err(|_| {
        tracing::debug!(realm = %realm_id, "DPoP header is not valid ASCII");
        IssuerdError::InvalidDpopProof
    })?;

    let requirements = issuerd_token::DpopProofRequirements {
        expected_htm: htm,
        accepted_htu: &accepted_htus(state, realm_id, realm_name, endpoint),
        expected_ath: access_token,
        max_age_secs: DPOP_PROOF_MAX_AGE_SECS,
        leeway_secs: DPOP_PROOF_LEEWAY_SECS,
        now: issuerd_core::utils::now_secs() as i64,
    };
    let verified = issuerd_token::validate_dpop_proof(proof, &requirements).map_err(|e| {
        // An `ath` mismatch on a presented access token means a bound token
        // was replayed under a different proof key — security-relevant, so
        // WARN. Every other proof failure is routine client noise (DEBUG).
        if ath_mismatch(proof, access_token) {
            tracing::warn!(realm = %realm_id, error = %e, "DPoP proof ath mismatch for presented access token");
        } else {
            tracing::debug!(realm = %realm_id, error = %e, "DPoP proof validation failed");
        }
        IssuerdError::InvalidDpopProof
    })?;

    // jti single-use (RFC 9449 §11.1): the atomic increment creates the key
    // with the TTL on first use, so exactly one presentation of a `jti`
    // succeeds and the marker expires with the proof's acceptance window.
    let ttl =
        (verified.iat + DPOP_PROOF_MAX_AGE_SECS).saturating_sub(requirements.now).max(1) as u64;
    let uses = state
        .cache
        .increment(
            &jti_cache_key(realm_id, &verified.jti),
            Some(std::time::Duration::from_secs(ttl)),
        )
        .await
        .map_err(|e| {
            tracing::warn!(realm = %realm_id, error = %e, "DPoP replay cache unavailable");
            IssuerdError::InvalidDpopProof
        })?;
    if uses != 1 {
        tracing::warn!(realm = %realm_id, "DPoP proof jti replayed");
        return Err(IssuerdError::InvalidDpopProof);
    }

    Ok(Some(verified))
}

/// Best-effort classification of an already-rejected proof: does its `ath`
/// claim mismatch the presented access token? Reads the proof payload without
/// verifying it — the read only picks a log level, never an auth decision.
fn ath_mismatch(proof: &str, access_token: Option<&str>) -> bool {
    let Some(access_token) = access_token else {
        return false;
    };
    let Some(payload) = proof.split('.').nth(1) else {
        return false;
    };
    let Ok(bytes) =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
    else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    let expected = issuerd_token::access_token_hash(access_token);
    claims.get("ath").and_then(serde_json::Value::as_str) != Some(expected.as_str())
}

/// Merge a `cnf.jkt` binding into a claims overlay. Access tokens are bound
/// through the overlay path (see `TokenManager::issue_access_token_with_roles`
/// and the `cnf` note on `RESERVED_OVERLAY_CLAIMS`); refresh tokens take the
/// binding as a typed parameter instead.
pub(crate) fn bind_cnf_overlay(
    overlay: Option<serde_json::Map<String, serde_json::Value>>,
    dpop_jkt: Option<&str>,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    match (overlay, dpop_jkt) {
        (overlay, None) => overlay,
        (overlay, Some(jkt)) => {
            let mut map = overlay.unwrap_or_default();
            map.insert("cnf".to_string(), serde_json::json!({ "jkt": jkt }));
            Some(map)
        }
    }
}

/// The `token_type` value for a token response (RFC 9449 §4.2: `DPoP` when
/// the issued access token is bound to a proof key).
pub(crate) fn token_type(dpop_bound: bool) -> String {
    if dpop_bound { "DPoP" } else { "Bearer" }.to_string()
}

/// 401 response for DPoP failures at protected-resource endpoints (userinfo):
/// JSON body plus the RFC 9449 §7.1 `WWW-Authenticate: DPoP` challenge.
pub(crate) fn challenge_response(error: &str, description: &str) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let mut response = (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": error})),
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        format!("DPoP error=\"{error}\", error_description=\"{description}\"")
            .parse()
            .expect("DPoP challenge header values are static-safe"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use ring::signature::KeyPair as _;
    use std::sync::Arc;

    const MASTER: &str = "master";

    /// P-256 DPoP key + compact-JWS proof builder (header carries `jwk`).
    struct EcKey {
        pair: ring::signature::EcdsaKeyPair,
        jwk: serde_json::Value,
    }

    fn gen_key() -> EcKey {
        use base64::Engine as _;
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
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": b64(&public[1..33]), "y": b64(&public[33..65]),
        });
        EcKey { pair, jwk }
    }

    impl EcKey {
        fn proof(&self, htm: &str, htu: &str, jti: &str, ath: Option<&str>) -> String {
            use base64::Engine as _;
            let header = serde_json::json!({
                "alg": "ES256", "typ": "dpop+jwt", "jwk": self.jwk,
            });
            let mut claims = serde_json::json!({
                "jti": jti,
                "htm": htm,
                "htu": htu,
                "iat": issuerd_core::utils::now_secs() as i64,
            });
            if let Some(ath) = ath {
                claims["ath"] = serde_json::json!(issuerd_token::access_token_hash(ath));
            }
            let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
            let input = format!(
                "{}.{}",
                b64(&serde_json::to_vec(&header).unwrap()),
                b64(&serde_json::to_vec(&claims).unwrap())
            );
            let rng = ring::rand::SystemRandom::new();
            let sig = self.pair.sign(&rng, input.as_bytes()).unwrap();
            format!("{input}.{}", b64(sig.as_ref()))
        }

        fn jkt(&self) -> String {
            issuerd_token::jwk_thumbprint(&self.jwk).unwrap()
        }
    }

    async fn test_state() -> Arc<ServerState> {
        Arc::new(ServerState::from_config(&ServerConfig::default()).await.unwrap())
    }

    fn headers_with(proof: Option<&str>) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        if let Some(proof) = proof {
            headers.insert("dpop", proof.parse().unwrap());
        }
        headers
    }

    fn token_htu(state: &ServerState) -> String {
        format!("{}/realms/{MASTER}/protocol/openid-connect/token", state.config.issuer_url)
    }

    #[tokio::test]
    async fn absent_header_is_bearer_flow() {
        let state = test_state().await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let result = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(None),
            "POST",
            "token",
            None,
        )
        .await
        .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn valid_proof_verifies_and_binds() {
        let state = test_state().await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let proof = key.proof("POST", &token_htu(&state), "jti-ok-1", None);
        let result = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            "token",
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.jkt, key.jkt());
    }

    #[tokio::test]
    async fn jti_replay_rejected() {
        let state = test_state().await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let proof = key.proof("POST", &token_htu(&state), "jti-replay-1", None);
        let headers = headers_with(Some(&proof));
        assert!(verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers,
            "POST",
            "token",
            None
        )
        .await
        .is_ok());
        assert!(matches!(
            verify_proof_header(&state, &realm_id, Some(MASTER), &headers, "POST", "token", None)
                .await,
            Err(IssuerdError::InvalidDpopProof)
        ));
    }

    #[tokio::test]
    async fn wrong_endpoint_or_method_rejected() {
        let state = test_state().await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        // htm mismatch.
        let proof = key.proof("GET", &token_htu(&state), "jti-htm", None);
        assert!(verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            "token",
            None,
        )
        .await
        .is_err());
        // htu mismatch (userinfo URL against the token endpoint).
        let htu =
            format!("{}/realms/{MASTER}/protocol/openid-connect/userinfo", state.config.issuer_url);
        let proof = key.proof("POST", &htu, "jti-htu", None);
        assert!(verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            "token",
            None,
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn ath_enforced_when_token_present() {
        let state = test_state().await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let htu = token_htu(&state);
        // ath missing → rejected when an access token is presented.
        let proof = key.proof("POST", &htu, "jti-ath-missing", None);
        assert!(verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            "token",
            Some("the-access-token"),
        )
        .await
        .is_err());
        // Correct ath → accepted.
        let proof = key.proof("POST", &htu, "jti-ath-ok", Some("the-access-token"));
        assert!(verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            "token",
            Some("the-access-token"),
        )
        .await
        .is_ok());
    }

    #[test]
    fn bind_cnf_overlay_merges() {
        // No binding: overlay passes through untouched.
        assert_eq!(bind_cnf_overlay(None, None), None);
        let mut existing = serde_json::Map::new();
        existing.insert("x".to_string(), serde_json::json!(1));
        assert_eq!(bind_cnf_overlay(Some(existing.clone()), None), Some(existing.clone()));
        // Binding creates / extends the overlay.
        let bound = bind_cnf_overlay(None, Some("thumb")).unwrap();
        assert_eq!(bound["cnf"], serde_json::json!({"jkt": "thumb"}));
        let bound = bind_cnf_overlay(Some(existing), Some("thumb")).unwrap();
        assert_eq!(bound["cnf"], serde_json::json!({"jkt": "thumb"}));
        assert_eq!(bound["x"], serde_json::json!(1));
    }

    #[test]
    fn token_type_switch() {
        assert_eq!(token_type(true), "DPoP");
        assert_eq!(token_type(false), "Bearer");
    }

    #[tokio::test]
    async fn accepted_htu_lists_name_then_id() {
        let state = test_state().await;
        let base = state.config.issuer_url.clone();
        let realm_id = RealmId::new("uuid-id").unwrap();

        // Name == id: a single accepted URL.
        let htus = accepted_htus(&state, &RealmId::new(MASTER).unwrap(), Some(MASTER), "token");
        assert_eq!(
            htus,
            vec![format!(
                "{base}/realms/{MASTER}/protocol/openid-connect/token"
            )]
        );

        // UUID-id realm addressed by name (e.g. PostgresStorage): the name
        // spelling (discovery-advertised) is primary; the id spelling is
        // accepted as tolerance.
        let htus = accepted_htus(&state, &realm_id, Some("human-name"), "token");
        assert_eq!(
            htus,
            vec![
                format!("{base}/realms/human-name/protocol/openid-connect/token"),
                format!("{base}/realms/uuid-id/protocol/openid-connect/token"),
            ]
        );
    }
}
