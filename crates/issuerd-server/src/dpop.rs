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
//! - `DPoP` header extraction and the `htm`/`htu` check against the
//!   caller-declared accepted paths (realm-relative, e.g.
//!   `protocol/openid-connect/token`), derived from the configured issuer
//!   (the discovery-advertised realm-name spelling is primary; the realm-id
//!   spelling is accepted as tolerance — `resolve_realm` serves both),
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
    /// nonce/jti checks is unavailable) — map to `invalid_dpop_proof`. A fresh
    /// response nonce is included when nonce mode is enabled and issuance works.
    InvalidProof(Option<String>),
    /// Nonce gate failure: the proof carried no (or a stale/unknown/used)
    /// nonce under `required`, or a stale/unknown/used one under
    /// `supported`. Carries the fresh nonce the endpoint MUST return in the
    /// `DPoP-Nonce` header of a `use_dpop_nonce` error response
    /// (RFC 9449 §8/§9 — the client's retry signal).
    UseDpopNonce(String),
}

/// Accepted `htu` values for `accepted_paths` (realm-relative request paths,
/// e.g. `protocol/openid-connect/token` or `mcp`): for each path, the
/// discovery-advertised realm-NAME URL, plus the realm-id spelling as
/// tolerance when the two differ (realm resolution accepts both).
fn accepted_htus(
    state: &ServerState,
    realm_id: &RealmId,
    realm_name: Option<&str>,
    accepted_paths: &[&str],
) -> Vec<String> {
    let primary = match realm_name {
        Some(segment) => issuerd_core::urls::decode_realm_segment(segment)
            .ok()
            .map(|name| name.to_string()),
        None => Some(realm_id.0.clone()),
    };
    let mut urls = Vec::with_capacity(accepted_paths.len() * 2);
    for path in accepted_paths {
        let segments: Vec<&str> = path.split('/').filter(|segment| !segment.is_empty()).collect();
        if let Some(primary) = primary.as_deref() {
            if let Ok(builder) =
                issuerd_core::urls::RealmUrlBuilder::new(&state.config.issuer_url, primary)
            {
                urls.push(builder.path(&segments).to_string());
            }
        }
        if realm_name.is_some() && primary.as_deref() != Some(realm_id.0.as_str()) {
            if let Ok(builder) = issuerd_core::urls::RealmUrlBuilder::new(
                &state.config.issuer_url,
                realm_id.0.as_str(),
            ) {
                urls.push(builder.path(&segments).to_string());
            }
        }
    }
    urls
}

/// Extract and verify the `DPoP` proof header of a request, if present.
/// Legacy endpoints accept the canonical realm-name HTU and the existing UUID
/// alias for each declared realm-relative path, using the configured nonce mode.
pub(crate) async fn verify_proof_header(
    state: &ServerState,
    realm_id: &RealmId,
    realm_name: Option<&str>,
    headers: &axum::http::HeaderMap,
    htm: &str,
    accepted_paths: &[&str],
    access_token: Option<&str>,
) -> Result<DpopVerification, DpopRejection> {
    let accepted_htus = accepted_htus(state, realm_id, realm_name, accepted_paths);
    verify_proof_header_inner(
        state,
        realm_id,
        headers,
        htm,
        &accepted_htus,
        state.config.dpop.nonce.mode,
        access_token,
    )
    .await
}

/// Strict verification for the MCP resource: only the exact canonical HTU is
/// accepted, and endpoint policy upgrades `supported` nonces to `required`.
/// Disabled nonce mode remains disabled.
#[allow(dead_code)]
pub(crate) async fn verify_mcp_proof_header(
    state: &ServerState,
    realm_id: &RealmId,
    headers: &axum::http::HeaderMap,
    htm: &str,
    canonical_htu: &str,
    access_token: Option<&str>,
) -> Result<DpopVerification, DpopRejection> {
    let nonce_mode = match state.config.dpop.nonce.mode {
        DpopNonceMode::Disabled => DpopNonceMode::Disabled,
        DpopNonceMode::Supported | DpopNonceMode::Required => DpopNonceMode::Required,
    };
    let accepted_htu = [canonical_htu.to_string()];
    verify_proof_header_inner(
        state,
        realm_id,
        headers,
        htm,
        &accepted_htu,
        nonce_mode,
        access_token,
    )
    .await
}

async fn verify_proof_header_inner(
    state: &ServerState,
    realm_id: &RealmId,
    headers: &axum::http::HeaderMap,
    htm: &str,
    accepted_htu: &[String],
    nonce_mode: DpopNonceMode,
    access_token: Option<&str>,
) -> Result<DpopVerification, DpopRejection> {
    let mut values = headers.get_all("dpop").iter();
    let Some(value) = values.next() else {
        return Ok(DpopVerification {
            proof: None,
            response_nonce: None,
        });
    };
    if values.next().is_some() {
        tracing::debug!(realm = %realm_id, "multiple DPoP proof headers");
        return Err(invalid_proof(state, realm_id, nonce_mode).await);
    }
    let proof = match value.to_str() {
        Ok(proof) => proof,
        Err(_) => {
            tracing::debug!(realm = %realm_id, "DPoP header is not valid ASCII");
            return Err(invalid_proof(state, realm_id, nonce_mode).await);
        }
    };

    // Read a candidate nonce without consuming it. Signature and expected
    // claims are verified before the atomic compare-and-delete below, so an
    // invalid proof cannot burn another party's live nonce.
    let (expected_nonce, nonce_entry, needs_nonce_challenge) = if nonce_mode
        == DpopNonceMode::Disabled
    {
        (None, None, false)
    } else {
        match unverified_nonce_claim(proof) {
            Some(claim) if claim.len() <= MAX_NONCE_CLAIM_LEN => {
                let key = cache_keys::dpop_nonce(&realm_id.0, &claim);
                match state.cache.get(&key).await {
                    Ok(Some(expected)) => (Some(claim), Some((key, expected)), false),
                    Ok(None) => (Some(claim), None, true),
                    Err(e) => {
                        tracing::warn!(realm = %realm_id, error = %e, "DPoP nonce cache unavailable");
                        return Err(invalid_proof(state, realm_id, nonce_mode).await);
                    }
                }
            }
            claim => (None, None, nonce_mode == DpopNonceMode::Required || claim.is_some()),
        }
    };

    let requirements = issuerd_token::DpopProofRequirements {
        expected_htm: htm,
        accepted_htu,
        expected_ath: access_token,
        max_age_secs: DPOP_PROOF_MAX_AGE_SECS,
        leeway_secs: DPOP_PROOF_LEEWAY_SECS,
        now: issuerd_core::utils::now_secs() as i64,
        expected_nonce: expected_nonce.as_deref(),
    };
    let verified = match issuerd_token::validate_dpop_proof(proof, &requirements) {
        Ok(verified) => verified,
        Err(e) => {
            if ath_mismatch(proof, access_token) {
                tracing::warn!(realm = %realm_id, error = %e, "DPoP proof ath mismatch for presented access token");
            } else {
                tracing::debug!(realm = %realm_id, error = %e, "DPoP proof validation failed");
            }
            return Err(invalid_proof(state, realm_id, nonce_mode).await);
        }
    };

    if needs_nonce_challenge {
        tracing::debug!(realm = %realm_id, "DPoP proof without a usable server nonce");
        return Err(nonce_challenge(state, realm_id).await);
    }

    // jti single-use (RFC 9449 §11.1). The jti marker and nonce are separate
    // cache resources and cannot be consumed as one transaction: a nonce-CAS
    // failure after this increment leaves the jti burned, so the client must
    // retry with a fresh proof and nonce. Every failure remains fail-closed.
    let ttl =
        (verified.iat + DPOP_PROOF_MAX_AGE_SECS).saturating_sub(requirements.now).max(1) as u64;
    let uses = match state
        .cache
        .increment(
            &jti_cache_key(realm_id, &verified.jti),
            Some(std::time::Duration::from_secs(ttl)),
        )
        .await
    {
        Ok(uses) => uses,
        Err(e) => {
            tracing::warn!(realm = %realm_id, error = %e, "DPoP replay cache unavailable");
            return Err(invalid_proof(state, realm_id, nonce_mode).await);
        }
    };
    if uses != 1 {
        tracing::warn!(realm = %realm_id, "DPoP proof jti replayed");
        return Err(invalid_proof(state, realm_id, nonce_mode).await);
    }

    if let Some((key, expected)) = nonce_entry {
        match state.cache.compare_and_delete(&key, expected).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(realm = %realm_id, "DPoP nonce changed or was consumed concurrently");
                return Err(nonce_challenge(state, realm_id).await);
            }
            Err(e) => {
                tracing::warn!(realm = %realm_id, error = %e, "DPoP nonce consumption failed");
                return Err(invalid_proof(state, realm_id, nonce_mode).await);
            }
        }
    }

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
/// signature — the value only selects the cache key to inspect; trust comes
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
        tracing::warn!(realm = %realm_id, error = %e, "DPoP nonce generation failed");
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
        None => DpopRejection::InvalidProof(None),
    }
}

async fn invalid_proof(
    state: &ServerState,
    realm_id: &RealmId,
    nonce_mode: DpopNonceMode,
) -> DpopRejection {
    let response_nonce = if nonce_mode == DpopNonceMode::Disabled {
        None
    } else {
        issue_nonce(state, realm_id).await
    };
    DpopRejection::InvalidProof(response_nonce)
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

    fn mcp_htu(state: &ServerState, realm: &str) -> String {
        issuerd_protocol::discovery::ProtectedResourceMetadata::for_realm(
            &state.config.issuer_url,
            realm,
        )
        .resource
        .to_string()
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
            &["protocol/openid-connect/token"],
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
            &["protocol/openid-connect/token"],
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
            &["protocol/openid-connect/token"],
            None
        )
        .await
        .is_ok());
        assert!(matches!(
            verify_proof_header(
                &state,
                &realm_id,
                Some(MASTER),
                &headers,
                "POST",
                &["protocol/openid-connect/token"],
                None,
            )
            .await,
            Err(DpopRejection::InvalidProof(_))
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
            &["protocol/openid-connect/token"],
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
            &["protocol/openid-connect/token"],
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
            &["protocol/openid-connect/token"],
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
            &["protocol/openid-connect/token"],
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
        let htus = accepted_htus(
            &state,
            &RealmId::new(MASTER).unwrap(),
            Some(MASTER),
            &["protocol/openid-connect/token"],
        );
        assert_eq!(
            htus,
            vec![format!(
                "{base}/realms/{MASTER}/protocol/openid-connect/token"
            )]
        );

        // UUID-id realm addressed by name (e.g. PostgresStorage): the name
        // spelling (discovery-advertised) is primary; the id spelling is
        // accepted as tolerance.
        let htus = accepted_htus(
            &state,
            &realm_id,
            Some("human-name"),
            &["protocol/openid-connect/token"],
        );
        assert_eq!(
            htus,
            vec![
                format!("{base}/realms/human-name/protocol/openid-connect/token"),
                format!("{base}/realms/uuid-id/protocol/openid-connect/token"),
            ]
        );
    }

    #[tokio::test]
    async fn realm_relative_path_proof_accepted() {
        // The future MCP route is `POST /realms/{realm}/mcp` — outside the
        // /protocol/openid-connect/ namespace. A proof minted for that exact
        // URL must validate when the caller declares the realm-relative path.
        let state = test_state().await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let htu = format!("{}/realms/{MASTER}/mcp", state.config.issuer_url);
        let proof = key.proof("POST", &htu, "jti-mcp-path", None);
        let result = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&proof)),
            "POST",
            &["mcp"],
            None,
        )
        .await;
        assert!(result.is_ok(), "proof for the caller-declared path must verify");
        assert_eq!(result.unwrap().proof.unwrap().jkt, key.jkt());
    }

    #[tokio::test]
    async fn undeclared_path_proof_rejected() {
        // Widening is explicit: with the caller accepting `mcp`, a proof
        // minted for any other path (here a sibling `/realms/{realm}/admin`)
        // still fails — the check stays an exact URL match.
        let state = test_state().await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let htu = format!("{}/realms/{MASTER}/admin", state.config.issuer_url);
        let proof = key.proof("POST", &htu, "jti-undeclared", None);
        assert!(matches!(
            verify_proof_header(
                &state,
                &realm_id,
                Some(MASTER),
                &headers_with(Some(&proof)),
                "POST",
                &["mcp"],
                None,
            )
            .await,
            Err(DpopRejection::InvalidProof(_))
        ));
    }

    #[tokio::test]
    async fn accepted_htus_derive_each_path_in_both_spellings() {
        let state = test_state().await;
        let base = state.config.issuer_url.clone();
        let realm_id = RealmId::new("uuid-id").unwrap();

        // Multiple realm-relative paths (the OIDC endpoint spelling and a
        // non-OIDC route): each is derived in the name spelling followed by
        // the id spelling.
        let htus = accepted_htus(
            &state,
            &realm_id,
            Some("human-name"),
            &["protocol/openid-connect/token", "mcp"],
        );
        assert_eq!(
            htus,
            vec![
                format!("{base}/realms/human-name/protocol/openid-connect/token"),
                format!("{base}/realms/uuid-id/protocol/openid-connect/token"),
                format!("{base}/realms/human-name/mcp"),
                format!("{base}/realms/uuid-id/mcp"),
            ]
        );
    }

    #[tokio::test]
    async fn accepted_htus_decode_the_inbound_realm_once() {
        let state = test_state().await;
        let realm_id = RealmId::new("uuid-id").unwrap();
        let htus = accepted_htus(&state, &realm_id, Some("tenant%7Bone%7D"), &["mcp"]);
        assert_eq!(
            htus,
            vec![
                format!("{}/realms/tenant%7Bone%7D/mcp", state.config.issuer_url),
                format!("{}/realms/uuid-id/mcp", state.config.issuer_url),
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
            &["protocol/openid-connect/token"],
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
            Err(DpopRejection::InvalidProof(_)) => "Err(InvalidProof)",
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
            &["protocol/openid-connect/token"],
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
            &["protocol/openid-connect/token"],
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
            &["protocol/openid-connect/token"],
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
            &["protocol/openid-connect/token"],
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
        assert_eq!(response.headers().get_all(DPOP_NONCE_HEADER).iter().count(), 1);
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

    #[tokio::test]
    async fn duplicate_proof_headers_are_rejected_by_legacy_and_strict_entry_points() {
        let state = test_state().await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let htu = token_htu(&state);
        let proof = key.proof("POST", &htu, "jti-duplicate", None);
        let mut headers = axum::http::HeaderMap::new();
        headers.append("dpop", proof.parse().unwrap());
        headers.append("dpop", proof.parse().unwrap());

        let legacy = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers,
            "POST",
            &["protocol/openid-connect/token"],
            None,
        )
        .await;
        assert!(matches!(legacy, Err(DpopRejection::InvalidProof(_))));

        let strict = verify_mcp_proof_header(&state, &realm_id, &headers, "POST", &htu, None).await;
        assert!(matches!(strict, Err(DpopRejection::InvalidProof(_))));
    }

    #[tokio::test]
    async fn wrong_signature_preserves_live_nonce_and_jti_and_returns_fresh_nonce() {
        let state = test_state_with_mode(DpopNonceMode::Required).await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let initial = key.proof("POST", &token_htu(&state), "jti-nonce-init", None);
        let nonce = expect_nonce_challenge(&state, &realm_id, &initial).await;
        let valid =
            key.proof_with_nonce("POST", &token_htu(&state), "jti-preserved", None, Some(&nonce));
        let mut parts: Vec<String> = valid.split('.').map(str::to_string).collect();
        parts[2] = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]);
        let forged = parts.join(".");

        let rejected = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&forged)),
            "POST",
            &["protocol/openid-connect/token"],
            None,
        )
        .await;
        let Err(DpopRejection::InvalidProof(Some(fresh))) = rejected else {
            panic!("wrong signature must carry a fresh post-proof response nonce");
        };
        assert_ne!(fresh, nonce);
        let nonce_key = cache_keys::dpop_nonce(&realm_id.0, &nonce);
        assert!(state.cache.get(&nonce_key).await.unwrap().is_some());

        let accepted = verify_proof_header(
            &state,
            &realm_id,
            Some(MASTER),
            &headers_with(Some(&valid)),
            "POST",
            &["protocol/openid-connect/token"],
            None,
        )
        .await
        .expect("the invalid signature must burn neither nonce nor jti");
        assert!(accepted.proof.is_some());
        assert!(state.cache.get(&nonce_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn strict_mcp_nonce_policy_rejects_downgrade_but_honors_disabled() {
        let state = test_state_with_mode(DpopNonceMode::Supported).await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let htu = mcp_htu(&state, MASTER);
        let proof = key.proof("POST", &htu, "jti-strict-downgrade", None);
        let challenged = verify_mcp_proof_header(
            &state,
            &realm_id,
            &headers_with(Some(&proof)),
            "POST",
            &htu,
            None,
        )
        .await;
        let Err(DpopRejection::UseDpopNonce(nonce)) = challenged else {
            panic!("MCP must require a nonce when the endpoint mode is supported");
        };
        let retry = key.proof_with_nonce("POST", &htu, "jti-strict-retry", None, Some(&nonce));
        assert!(verify_mcp_proof_header(
            &state,
            &realm_id,
            &headers_with(Some(&retry)),
            "POST",
            &htu,
            None,
        )
        .await
        .is_ok());

        let disabled = test_state_with_mode(DpopNonceMode::Disabled).await;
        let htu = mcp_htu(&disabled, MASTER);
        let proof = key.proof("POST", &htu, "jti-strict-disabled", None);
        let accepted = verify_mcp_proof_header(
            &disabled,
            &realm_id,
            &headers_with(Some(&proof)),
            "POST",
            &htu,
            None,
        )
        .await
        .unwrap();
        assert!(accepted.response_nonce.is_none());
    }

    #[tokio::test]
    async fn concurrent_nonce_consumption_has_one_winner_and_replay_fails() {
        let state = test_state_with_mode(DpopNonceMode::Required).await;
        let realm_id = RealmId::new(MASTER).unwrap();
        let key = gen_key();
        let htu = mcp_htu(&state, MASTER);
        let initial = key.proof("POST", &htu, "jti-concurrent-init", None);
        let Err(DpopRejection::UseDpopNonce(nonce)) = verify_mcp_proof_header(
            &state,
            &realm_id,
            &headers_with(Some(&initial)),
            "POST",
            &htu,
            None,
        )
        .await
        else {
            panic!("initial strict proof must receive a nonce challenge");
        };
        let first = key.proof_with_nonce("POST", &htu, "jti-concurrent-1", None, Some(&nonce));
        let second = key.proof_with_nonce("POST", &htu, "jti-concurrent-2", None, Some(&nonce));

        let mut tasks = Vec::new();
        for proof in [first, second] {
            let state = state.clone();
            let realm_id = realm_id.clone();
            let htu = htu.clone();
            tasks.push(tokio::spawn(async move {
                verify_mcp_proof_header(
                    &state,
                    &realm_id,
                    &headers_with(Some(&proof)),
                    "POST",
                    &htu,
                    None,
                )
                .await
            }));
        }
        let first_result = tasks.remove(0).await.unwrap();
        let second_result = tasks.remove(0).await.unwrap();
        let successes =
            [&first_result, &second_result].iter().filter(|result| result.is_ok()).count();
        let nonce_challenges = [&first_result, &second_result]
            .iter()
            .filter(|result| matches!(result, Err(DpopRejection::UseDpopNonce(_))))
            .count();
        assert_eq!((successes, nonce_challenges), (1, 1));
        assert!(state
            .cache
            .get(&cache_keys::dpop_nonce(&realm_id.0, &nonce))
            .await
            .unwrap()
            .is_none());

        let replay =
            key.proof_with_nonce("POST", &htu, "jti-concurrent-replay", None, Some(&nonce));
        assert!(matches!(
            verify_mcp_proof_header(
                &state,
                &realm_id,
                &headers_with(Some(&replay)),
                "POST",
                &htu,
                None,
            )
            .await,
            Err(DpopRejection::UseDpopNonce(_))
        ));
    }

    #[tokio::test]
    async fn special_realm_token_resolves_to_canonical_resource_and_strict_htu() {
        let state = test_state().await;
        let realm = issuerd_core::Realm {
            id: RealmId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: issuerd_core::RealmName::new("tenant{one}").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        let master_id = RealmId::new(MASTER).unwrap();
        let mut user = state
            .storage
            .get_user(&master_id, &issuerd_core::UserId::new("admin").unwrap())
            .await
            .unwrap()
            .unwrap();
        user.id = issuerd_core::UserId::new("special-user").unwrap();
        user.realm_id = realm.id.clone();
        let mut client = state
            .storage
            .get_client_by_client_id(
                &master_id,
                &issuerd_core::ClientIdentifier::new("admin-cli").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        client.id = issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap();
        client.realm_id = realm.id.clone();
        client.client_id = issuerd_core::ClientIdentifier::new("special-client").unwrap();
        let access = state
            .token_manager
            .issue_access_token(
                &user,
                &client,
                &realm,
                &["openid".to_string()],
                &issuerd_core::SessionId::new("special-session").unwrap(),
            )
            .await
            .unwrap();

        let validated = state.token_service.validate_access_token(&access.token).unwrap();
        assert_eq!(
            validated.claims.iss.as_str(),
            format!("{}/realms/tenant%7Bone%7D", state.config.issuer_url)
        );
        let resolved = state
            .resolve_issuer_realm(validated.claims.iss.as_str())
            .await
            .unwrap()
            .expect("encoded canonical issuer resolves");
        assert_eq!(resolved.id, realm.id);
        let htu = mcp_htu(&state, resolved.name.as_str());
        assert_eq!(htu, format!("{}/realms/tenant%7Bone%7D/mcp", state.config.issuer_url));

        let key = gen_key();
        let proof = key.proof("POST", &htu, "jti-special-canonical", Some(&access.token));
        let accepted = verify_mcp_proof_header(
            &state,
            &realm.id,
            &headers_with(Some(&proof)),
            "POST",
            &htu,
            Some(&access.token),
        )
        .await
        .unwrap();
        assert_eq!(accepted.proof.unwrap().jkt, key.jkt());

        let alias_htu = format!("{}/realms/{}/mcp", state.config.issuer_url, realm.id);
        let alias = key.proof("POST", &alias_htu, "jti-special-alias", Some(&access.token));
        assert!(matches!(
            verify_mcp_proof_header(
                &state,
                &realm.id,
                &headers_with(Some(&alias)),
                "POST",
                &htu,
                Some(&access.token),
            )
            .await,
            Err(DpopRejection::InvalidProof(_))
        ));
    }
}
