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
//! - opt-in server-provided nonces (RFC 9449 §8/§9, `[dpop.nonce]`):
//!   unguessable random values issued via the `DPoP-Nonce` response header,
//!   stored in the distributed cache (`dpop-nonce:{realm_id}:{nonce}`, TTL =
//!   the configured lifetime) and consumed atomically on verification
//!   (single-use); proofs without a live nonce are challenged with
//!   `use_dpop_nonce` per the configured mode,
//! - the `cnf.jkt` claims-overlay merge used to bind issued access tokens
//!   ([`bind_cnf_overlay`]) and the `token_type` response switch
//!   ([`token_type`]).
//!
//! With nonce mode `disabled` (the default) replay protection rides on `jti`
//! + `iat` only — the pre-feature behavior.

use base64::Engine as _;
use issuerd_cluster::cache_keys;
use issuerd_core::RealmId;

use crate::config::DpopNonceMode;
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

/// Upper bound on the nonce-claim length the server will look up in its
/// cache (server-issued nonces are 43 chars; mirrors the token crate's
/// claim cap so an oversized claim never becomes a cache key).
const MAX_NONCE_CLAIM_LEN: usize = 256;

/// The `DPoP-Nonce` HTTP response header (RFC 9449 §8/§9).
pub(crate) const DPOP_NONCE_HEADER: &str = "dpop-nonce";

/// Result of processing the `DPoP` header of one request.
pub(crate) struct DpopVerification {
    /// The verified proof (`None` = no `DPoP` header: plain Bearer flow).
    pub proof: Option<issuerd_token::VerifiedDpopProof>,
    /// Fresh server nonce to advertise via the `DPoP-Nonce` response header
    /// (`Some` only when nonce mode is enabled AND a proof was presented —
    /// Bearer flows never carry it). Issuance failure degrades to `None`
    /// (WARN logged): the response simply lacks the header.
    pub response_nonce: Option<String>,
}

/// Why DPoP processing rejected the request.
#[derive(Debug)]
pub(crate) enum DpopRejection {
    /// The proof itself failed validation (or the cache backing the
    /// nonce/jti checks is unavailable) — map to `invalid_dpop_proof`.
    InvalidProof,
    /// Nonce gate failure: the proof carried no (or a stale/unknown/used)
    /// nonce under `required`, or a stale/unknown/used one under
    /// `supported`. Carries the fresh nonce the endpoint MUST return in the
    /// `DPoP-Nonce` header of a `use_dpop_nonce` error response
    /// (RFC 9449 §8/§9 — the client's retry signal).
    UseDpopNonce(String),
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
/// Returns a [`DpopVerification`] with `proof: None` when no `DPoP` header
/// was sent (plain Bearer flow). On success the proof's `jti` is burned in
/// the replay cache (fail-closed), the presented nonce (if any) is consumed,
/// and a fresh nonce is issued for the response when nonce mode is enabled.
/// Proof failures map to [`DpopRejection::InvalidProof`]; specifics are
/// logged, not returned.
pub(crate) async fn verify_proof_header(
    state: &ServerState,
    realm_id: &RealmId,
    realm_name: Option<&str>,
    headers: &axum::http::HeaderMap,
    htm: &str,
    endpoint: &str,
    access_token: Option<&str>,
) -> Result<DpopVerification, DpopRejection> {
    let Some(value) = headers.get("dpop") else {
        return Ok(DpopVerification {
            proof: None,
            response_nonce: None,
        });
    };
    let proof = value.to_str().map_err(|_| {
        tracing::debug!(realm = %realm_id, "DPoP header is not valid ASCII");
        DpopRejection::InvalidProof
    })?;

    // Nonce gate (RFC 9449 §8/§9), evaluated before the cryptographic
    // checks: the claim value selects the cache key to consume; the
    // signed-claim equality check against the consumed value then happens
    // under signature in `validate_dpop_proof` (`expected_nonce`).
    let nonce_mode = state.config.dpop.nonce.mode;
    let expected_nonce: Option<String> = if nonce_mode == DpopNonceMode::Disabled {
        None
    } else {
        match unverified_nonce_claim(proof) {
            Some(claim) if claim.len() <= MAX_NONCE_CLAIM_LEN => {
                // A presented nonce must be one this server issued: consume
                // it atomically (single-use) — `get_and_delete` makes the
                // first presenter win and concurrent replays fail.
                let key = cache_keys::dpop_nonce(&realm_id.0, &claim);
                match state.cache.get_and_delete(&key).await {
                    Ok(Some(_)) => Some(claim),
                    Ok(None) => {
                        tracing::debug!(
                            realm = %realm_id,
                            "DPoP proof carries an unknown, stale, or already-used nonce"
                        );
                        return Err(nonce_challenge(state, realm_id).await);
                    }
                    Err(e) => {
                        tracing::warn!(realm = %realm_id, error = %e, "DPoP nonce cache unavailable");
                        return Err(DpopRejection::InvalidProof);
                    }
                }
            }
            // Absent, unparsable, or oversized claim. Under `required` the
            // nonce is mandatory; under `supported` only an oversized claim
            // (which can never be server-issued) is challenged — absence is
            // tolerated.
            claim if nonce_mode == DpopNonceMode::Required || claim.is_some() => {
                tracing::debug!(realm = %realm_id, "DPoP proof without a usable server nonce");
                return Err(nonce_challenge(state, realm_id).await);
            }
            _ => None,
        }
    };

    let requirements = issuerd_token::DpopProofRequirements {
        expected_htm: htm,
        accepted_htu: &accepted_htus(state, realm_id, realm_name, endpoint),
        expected_ath: access_token,
        max_age_secs: DPOP_PROOF_MAX_AGE_SECS,
        leeway_secs: DPOP_PROOF_LEEWAY_SECS,
        now: issuerd_core::utils::now_secs() as i64,
        expected_nonce: expected_nonce.as_deref(),
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
        DpopRejection::InvalidProof
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
            DpopRejection::InvalidProof
        })?;
    if uses != 1 {
        tracing::warn!(realm = %realm_id, "DPoP proof jti replayed");
        return Err(DpopRejection::InvalidProof);
    }

    // The proof is good: hand the client its next nonce (§8.2 — the server
    // decides when to supply a new value; single-use nonces mean every
    // proof-carrying response carries one).
    let response_nonce = if nonce_mode == DpopNonceMode::Disabled {
        None
    } else {
        issue_nonce(state, realm_id).await
    };
    Ok(DpopVerification {
        proof: Some(verified),
        response_nonce,
    })
}

/// Read the `nonce` claim from a proof payload WITHOUT verifying the
/// signature — the value only selects the cache key to consume; trust comes
/// from the signed-claim equality check in `validate_dpop_proof`.
fn unverified_nonce_claim(proof: &str) -> Option<String> {
    let payload = proof.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("nonce").and_then(serde_json::Value::as_str).map(str::to_string)
}

/// Mint and store a fresh server nonce: 256 bits of CSPRNG entropy,
/// base64url-encoded (unguessable, per RFC 9449 §8 "MUST be unpredictable"),
/// keyed in the distributed cache with the configured lifetime. The entry's
/// existence is the only state — the marker value carries nothing.
///
/// Failure (RNG or cache) degrades to `None` with a WARN: issuance is
/// best-effort so a cache hiccup does not fail an otherwise valid request —
/// a client that then presents no/stale nonce is simply challenged again.
async fn issue_nonce(state: &ServerState, realm_id: &RealmId) -> Option<String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 32];
    if let Err(e) = ring::rand::SystemRandom::new().fill(&mut bytes) {
        tracing::warn!(realm = %realm_id, error = ?e, "DPoP nonce generation failed");
        return None;
    }
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let key = cache_keys::dpop_nonce(&realm_id.0, &nonce);
    let ttl = std::time::Duration::from_secs(state.config.dpop.nonce.lifetime_secs);
    match state.cache.set(&key, vec![1], Some(ttl)).await {
        Ok(()) => Some(nonce),
        Err(e) => {
            tracing::warn!(realm = %realm_id, error = %e, "DPoP nonce issuance failed");
            None
        }
    }
}

/// Build the `use_dpop_nonce` rejection carrying a fresh nonce. Falls back
/// to [`DpopRejection::InvalidProof`] when no nonce could be issued (a
/// challenge without a nonce would send the client into a useless retry
/// loop; the WARN is already logged by [`issue_nonce`]).
async fn nonce_challenge(state: &ServerState, realm_id: &RealmId) -> DpopRejection {
    match issue_nonce(state, realm_id).await {
        Some(nonce) => DpopRejection::UseDpopNonce(nonce),
        None => DpopRejection::InvalidProof,
    }
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

/// Attach a fresh server nonce to a response as the `DPoP-Nonce` header
/// (RFC 9449 §8/§9). No-op when `nonce` is `None` (disabled mode, Bearer
/// flows, issuance failure). The nonce is server-generated base64url, so
/// header-value encoding cannot fail; the `from_str` guard is defensive.
pub(crate) fn with_nonce_header(
    mut response: axum::response::Response,
    nonce: Option<&str>,
) -> axum::response::Response {
    if let Some(nonce) = nonce {
        if let Ok(value) = axum::http::HeaderValue::from_str(nonce) {
            response.headers_mut().insert(DPOP_NONCE_HEADER, value);
        }
    }
    response
}

/// 400 response for a nonce-gate failure at the token endpoint (RFC 9449
/// §8): the `use_dpop_nonce` JSON error plus the `DPoP-Nonce` header
/// carrying the fresh nonce the client must echo on retry.
pub(crate) fn use_dpop_nonce_response(nonce: &str) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let response = (
        axum::http::StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({
            "error": "use_dpop_nonce",
            "error_description": "Authorization server requires nonce in DPoP proof",
        })),
    )
        .into_response();
    with_nonce_header(response, Some(nonce))
}

/// 401 response for DPoP failures at protected-resource endpoints (userinfo):
/// JSON body plus the RFC 9449 §7.1 `WWW-Authenticate: DPoP` challenge. The
/// fresh nonce (when the failure is a nonce-gate rejection) rides in the
/// `DPoP-Nonce` header per §9.
pub(crate) fn challenge_response(
    error: &str,
    description: &str,
    nonce: Option<&str>,
) -> axum::response::Response {
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
    with_nonce_header(response, nonce)
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
            self.proof_with_nonce(htm, htu, jti, ath, None)
        }

        fn proof_with_nonce(
            &self,
            htm: &str,
            htu: &str,
            jti: &str,
            ath: Option<&str>,
            nonce: Option<&str>,
        ) -> String {
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
            if let Some(nonce) = nonce {
                claims["nonce"] = serde_json::json!(nonce);
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
        test_state_with_mode(DpopNonceMode::Disabled).await
    }

    async fn test_state_with_mode(mode: DpopNonceMode) -> Arc<ServerState> {
        let mut config = ServerConfig::default();
        config.dpop.nonce.mode = mode;
        Arc::new(ServerState::from_config(&config).await.unwrap())
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
        assert!(result.proof.is_none());
        assert!(result.response_nonce.is_none());
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
        .unwrap();
        let verified = result.proof.unwrap();
        assert_eq!(verified.jkt, key.jkt());
        // Disabled mode (the default): no nonce is issued.
        assert!(result.response_nonce.is_none());
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
            Err(DpopRejection::InvalidProof)
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

    // ------------------------------------------------------------------
    // Server-provided nonces ([dpop.nonce], RFC 9449 §8/§9)
    // ------------------------------------------------------------------

    /// Verify a token-endpoint proof against `state` and unwrap the
    /// `use_dpop_nonce` challenge.
    async fn expect_nonce_challenge(
        state: &Arc<ServerState>,
        realm_id: &RealmId,
        proof: &str,
    ) -> String {
        match verify_proof_header(
            state,
            realm_id,
            Some(MASTER),
            &headers_with(Some(proof)),
            "POST",
            "token",
            None,
        )
        .await
        {
            Err(DpopRejection::UseDpopNonce(nonce)) => nonce,
            other => panic!("expected use_dpop_nonce challenge, got {}", outcome_kind(&other)),
        }
    }

    fn outcome_kind(outcome: &Result<DpopVerification, DpopRejection>) -> &'static str {
        match outcome {
            Ok(_) => "Ok",
            Err(DpopRejection::InvalidProof) => "Err(InvalidProof)",
            Err(DpopRejection::UseDpopNonce(_)) => "Err(UseDpopNonce)",
        }
    }

    #[tokio::test]
    async fn required_mode_challenge_retry_and_single_use() {
        let state = test_state_with_mode(DpopNonceMode::Required).await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();

        // The captured-proof scenario: a well-formed proof with a fresh
        // `iat`/`jti` but no server nonce is NOT accepted — the response
        // challenges with a fresh nonce.
        let proof = key.proof("POST", &token_htu(&state), "jti-req-1", None);
        let nonce = expect_nonce_challenge(&state, &realm_id, &proof).await;

        // Retry echoing the server nonce: accepted; the response issues the
        // NEXT nonce.
        let proof =
            key.proof_with_nonce("POST", &token_htu(&state), "jti-req-2", None, Some(&nonce));
        let outcome = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            "token",
            None,
        )
        .await
        .unwrap();
        assert!(outcome.proof.is_some());
        let next = outcome.response_nonce.expect("success issues a fresh nonce");
        assert_ne!(next, nonce);

        // The consumed nonce is burned (single-use): reusing it challenges
        // again even with an otherwise valid, fresh proof.
        let proof =
            key.proof_with_nonce("POST", &token_htu(&state), "jti-req-3", None, Some(&nonce));
        let renewed = expect_nonce_challenge(&state, &realm_id, &proof).await;
        assert_ne!(renewed, nonce);

        // And a made-up nonce never validates.
        let proof = key.proof_with_nonce(
            "POST",
            &token_htu(&state),
            "jti-req-4",
            None,
            Some("attacker-guess"),
        );
        expect_nonce_challenge(&state, &realm_id, &proof).await;
    }

    #[tokio::test]
    async fn required_mode_oversized_nonce_claim_challenged_without_cache_lookup() {
        let state = test_state_with_mode(DpopNonceMode::Required).await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let huge = "x".repeat(MAX_NONCE_CLAIM_LEN + 1);
        let proof =
            key.proof_with_nonce("POST", &token_htu(&state), "jti-req-big", None, Some(&huge));
        expect_nonce_challenge(&state, &realm_id, &proof).await;
    }

    #[tokio::test]
    async fn supported_mode_accepts_absent_nonce_and_issues() {
        let state = test_state_with_mode(DpopNonceMode::Supported).await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();

        // No nonce claim: accepted, and the response advertises a fresh nonce.
        let proof = key.proof("POST", &token_htu(&state), "jti-sup-1", None);
        let outcome = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            "token",
            None,
        )
        .await
        .unwrap();
        assert!(outcome.proof.is_some());
        let nonce = outcome.response_nonce.expect("supported mode always issues");

        // Echoing the issued nonce works too (and consumes it).
        let proof =
            key.proof_with_nonce("POST", &token_htu(&state), "jti-sup-2", None, Some(&nonce));
        let outcome = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            "token",
            None,
        )
        .await
        .unwrap();
        assert!(outcome.proof.is_some());
        assert!(outcome.response_nonce.is_some());
    }

    #[tokio::test]
    async fn supported_mode_challenges_present_but_unknown_nonce() {
        let state = test_state_with_mode(DpopNonceMode::Supported).await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();

        // A presented nonce must be server-issued and live: an unknown value
        // is challenged (the RFC retry path), NOT silently ignored.
        let proof =
            key.proof_with_nonce("POST", &token_htu(&state), "jti-sup-x", None, Some("made-up"));
        expect_nonce_challenge(&state, &realm_id, &proof).await;
    }

    #[tokio::test]
    async fn disabled_mode_ignores_nonce_claims() {
        let state = test_state().await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let proof =
            key.proof_with_nonce("POST", &token_htu(&state), "jti-dis-1", None, Some("anything"));
        let outcome = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            "token",
            None,
        )
        .await
        .unwrap();
        assert!(outcome.proof.is_some());
        assert!(outcome.response_nonce.is_none());
    }

    #[tokio::test]
    async fn nonce_challenge_response_shapes() {
        // Token endpoint (RFC 9449 §8): 400 + JSON error + DPoP-Nonce header.
        let response = use_dpop_nonce_response("fresh-nonce");
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(response.headers().get(DPOP_NONCE_HEADER).unwrap(), "fresh-nonce");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "use_dpop_nonce");

        // Resource endpoint (§9): 401 + WWW-Authenticate + DPoP-Nonce header.
        let response = challenge_response(
            "use_dpop_nonce",
            "Resource server requires nonce in DPoP proof",
            Some("rs-nonce"),
        );
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let www = response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(www.starts_with("DPoP error=\"use_dpop_nonce\""), "got: {www}");
        assert_eq!(response.headers().get(DPOP_NONCE_HEADER).unwrap(), "rs-nonce");

        // Non-nonce challenges carry no nonce header.
        let response = challenge_response("invalid_dpop_proof", "the DPoP proof is invalid", None);
        assert!(response.headers().get(DPOP_NONCE_HEADER).is_none());
    }
}
