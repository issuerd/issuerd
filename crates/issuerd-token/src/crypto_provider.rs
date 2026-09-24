// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Ring-backed CryptoProvider: key generation, signing, verification, and the keystore.

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use issuerd_core::{
    Algorithm, Base64Url, CryptoProvider, IssuerdError, Jwk, JwkKty, JwkSet, JwkUse, KeyId,
    StoredSigningKey,
};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use rand::RngCore;
use ring::signature::KeyPair;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;

/// Configuration for cryptographic operations.
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Server-default token-signing algorithm for realms that do not set the
    /// `default_signature_algorithm` attribute, and the algorithm of keys
    /// generated without an explicit algorithm choice (first boot, bare
    /// rotation). Defaults to EdDSA (Ed25519): new deployments start on a
    /// fast, modern elliptic-curve algorithm and RSA key generation stays an
    /// explicit, opt-in compatibility choice. When no active key of this
    /// algorithm exists, issuance falls back to the newest active key
    /// overall, so pre-existing RS256-only deployments keep signing RS256
    /// until an EdDSA key is deliberately rotated in.
    pub default_alg: Algorithm,
    pub rsa_key_size: u32,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            default_alg: Algorithm::EdDsa,
            rsa_key_size: 2048,
        }
    }
}

/// In-memory store of signing keys.
pub struct KeyStore {
    active: Vec<SigningKey>,
    passive: Vec<SigningKey>,
}

/// A single signing key with its metadata and PKCS#8 DER private key.
///
/// `private_der` is zeroized on drop: the resident copy must stay usable while
/// the key signs, but retired keys (keystore reload) and transient copies are
/// erased promptly. `ring` / `jsonwebtoken::EncodingKey` still hold internal
/// copies outside our control (see the issuerd-storage `key_encryption` module
/// docs for the honest limits).
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub kid: KeyId,
    pub alg: Algorithm,
    pub created_at: DateTime<Utc>,
    /// PKCS#8 DER-encoded private key (or raw secret for HMAC).
    pub private_der: Vec<u8>,
    /// Public key represented as a JWK.
    pub public_jwk: Jwk,
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private_der);
    }
}

impl SigningKey {
    /// Rebuild a signing key from its persisted shared-storage representation.
    pub fn from_stored(key: &StoredSigningKey) -> Self {
        Self {
            kid: key.kid.clone(),
            alg: key.alg,
            created_at: key.created_at,
            private_der: key.private_der.clone(),
            public_jwk: key.public_jwk.clone(),
        }
    }

    /// Convert to the persisted shared-storage representation, marking whether
    /// the key is currently eligible for signing.
    pub fn to_stored(&self, active: bool) -> StoredSigningKey {
        StoredSigningKey {
            kid: self.kid.clone(),
            alg: self.alg,
            created_at: self.created_at,
            private_der: self.private_der.clone(),
            public_jwk: self.public_jwk.clone(),
            active,
        }
    }
}

impl KeyStore {
    /// Create a new keystore with one active key.
    pub fn new(config: &CryptoConfig) -> Result<Self, IssuerdError> {
        let active = vec![Self::generate_key(config.default_alg, config.rsa_key_size)?];
        Ok(Self {
            active,
            passive: Vec::new(),
        })
    }

    /// Build a keystore from persisted shared signing keys.
    ///
    /// Keys flagged `active` become signing candidates; the rest are kept for
    /// validation only. Each list is sorted by `created_at` ascending (`kid`
    /// tiebreak) so every cluster node derives an identical ordering from the
    /// same stored set.
    pub fn from_stored_keys(keys: &[StoredSigningKey]) -> Self {
        let mut active = Vec::new();
        let mut passive = Vec::new();
        for key in keys {
            let signing_key = SigningKey::from_stored(key);
            if key.active {
                active.push(signing_key);
            } else {
                passive.push(signing_key);
            }
        }
        Self::sort_by_created_at(&mut active);
        Self::sort_by_created_at(&mut passive);
        Self { active, passive }
    }

    /// Sort keys by creation time ascending, breaking ties on `kid` so the
    /// result is fully deterministic even for identical timestamps.
    fn sort_by_created_at(keys: &mut [SigningKey]) {
        keys.sort_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.kid.cmp(&b.kid)));
    }

    /// Generate a new signing key for the given algorithm.
    pub fn generate_key(alg: Algorithm, rsa_bits: u32) -> Result<SigningKey, IssuerdError> {
        let kid = KeyId::new(issuerd_core::utils::generate_id()).unwrap();
        let created_at = Utc::now();

        let (private_der, public_jwk) = match alg {
            Algorithm::Rs256 | Algorithm::Rs384 | Algorithm::Rs512 => {
                generate_rsa_key(&kid, alg, rsa_bits)?
            }
            Algorithm::Es256 => generate_ec_p256(&kid, alg)?,
            Algorithm::Es384 => generate_ec_p384(&kid, alg)?,
            Algorithm::Es512 => generate_ec_p521(&kid, alg)?,
            Algorithm::EdDsa => generate_eddsa_key(&kid, alg)?,
            Algorithm::Hs256 | Algorithm::Hs384 | Algorithm::Hs512 => generate_hmac_key(&kid, alg)?,
        };

        Ok(SigningKey {
            kid,
            alg,
            created_at,
            private_der,
            public_jwk,
        })
    }

    /// Generate the signing-key set for a fresh deployment (an empty shared
    /// `signing_keys` table): the key for `default_alg` — the signing
    /// default — plus, when that is not already RS256, an RS256 key of
    /// `rsa_bits` bits.
    ///
    /// OIDC Core §15.1 makes RS256 mandatory-to-implement and discovery (§3)
    /// must advertise it in `id_token_signing_alg_values_supported`, so a
    /// fresh key set always contains an active RS256 key even when EdDSA is
    /// the default signing algorithm. The `default_alg` key is strictly the
    /// newest so "newest active key" selection (JWKS `keys[0]`, discovery
    /// ordering) prefers it. All returned keys are meant to be persisted
    /// active.
    pub fn generate_initial_key_set(
        default_alg: Algorithm,
        rsa_bits: u32,
    ) -> Result<Vec<SigningKey>, IssuerdError> {
        let primary = Self::generate_key(default_alg, rsa_bits)?;
        if default_alg == Algorithm::Rs256 {
            return Ok(vec![primary]);
        }
        let mut mti_rsa = Self::generate_key(Algorithm::Rs256, rsa_bits)?;
        if mti_rsa.created_at >= primary.created_at {
            mti_rsa.created_at = primary.created_at - chrono::Duration::nanoseconds(1);
        }
        Ok(vec![mti_rsa, primary])
    }

    /// Find a key by its key id, searching active then passive.
    pub fn find_key(&self, kid: &KeyId) -> Option<&SigningKey> {
        self.active
            .iter()
            .find(|k| &k.kid == kid)
            .or_else(|| self.passive.iter().find(|k| &k.kid == kid))
    }

    /// Find an **active** (signing-eligible) key by its key id.
    ///
    /// Signing must go through this lookup, not [`KeyStore::find_key`]: a
    /// passive (disabled) key still verifies but must never sign again.
    pub fn find_active_key(&self, kid: &KeyId) -> Option<&SigningKey> {
        self.active.iter().find(|k| &k.kid == kid)
    }

    /// Sort `keys` newest-first (`kid` tiebreak) and return their public
    /// JWKs with symmetric key material stripped.
    fn public_jwks_of(keys: &[SigningKey]) -> Vec<Jwk> {
        let mut sorted: Vec<&SigningKey> = keys.iter().collect();
        sorted.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.kid.cmp(&b.kid)));
        sorted
            .into_iter()
            .map(|k| {
                let mut jwk = k.public_jwk.clone();
                jwk.k = None;
                jwk
            })
            .collect()
    }

    /// Return all public JWKs (active + passive).
    ///
    /// Ordering contract: **active keys first, newest first**, then passive
    /// keys (also newest first). `TokenManager::sign_claims` and
    /// `TokenManager::active_alg` pick `keys[0]` of the active-only snapshot
    /// (see [`KeyStore::active_public_jwks`]) as the signing key, so this
    /// ordering makes every cluster node that loaded the same shared key set
    /// deterministically sign with the **newest active** key, while rotated
    /// keys remain published for validation.
    ///
    /// Symmetric (`oct`) keys carry the HMAC secret in `k`; that material must
    /// never leave the server, so it is stripped here at the exposure
    /// boundary. Verification reads the in-store copy, which retains `k`.
    pub fn public_jwks(&self) -> Vec<Jwk> {
        let mut jwks = Self::public_jwks_of(&self.active);
        jwks.extend(Self::public_jwks_of(&self.passive));
        jwks
    }

    /// Return the public JWKs of the **active** keys only, newest first.
    ///
    /// Same `k`-stripping as [`KeyStore::public_jwks`]. This is the set
    /// signing-key selection must use: passive keys are published (they still
    /// verify) but are not eligible to sign.
    pub fn active_public_jwks(&self) -> Vec<Jwk> {
        Self::public_jwks_of(&self.active)
    }
}

fn generate_rsa_key(
    kid: &KeyId,
    alg: Algorithm,
    bits: u32,
) -> Result<(Vec<u8>, Jwk), IssuerdError> {
    let mut rng = rand::thread_rng();
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, bits as usize)
        .map_err(|e| IssuerdError::ServerError(format!("RSA key generation failed: {e}")))?;
    let pkcs1_der = priv_key
        .to_pkcs1_der()
        .map_err(|e| IssuerdError::ServerError(format!("PKCS#1 DER encoding failed: {e}")))?
        .as_bytes()
        .to_vec();

    let pub_key = priv_key.to_public_key();
    let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());

    let jwk = Jwk {
        kty: JwkKty::Rsa,
        kid: kid.clone(),
        alg,
        use_: JwkUse::Sig,
        n: Some(Base64Url::new(n).unwrap()),
        e: Some(Base64Url::new(e).unwrap()),
        x: None,
        y: None,
        crv: None,
        k: None,
    };

    Ok((pkcs1_der, jwk))
}

fn generate_ec_p256(kid: &KeyId, alg: Algorithm) -> Result<(Vec<u8>, Jwk), IssuerdError> {
    let mut rng = rand::thread_rng();
    let secret = p256::SecretKey::random(&mut rng);
    let pkcs8_der = secret
        .to_pkcs8_der()
        .map_err(|e| IssuerdError::ServerError(format!("EC PKCS#8 encoding failed: {e}")))?
        .as_bytes()
        .to_vec();

    let public = secret.public_key();
    let encoded = public.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded.x().expect("uncompressed point has x"));
    let y = URL_SAFE_NO_PAD.encode(encoded.y().expect("uncompressed point has y"));

    let jwk = Jwk {
        kty: JwkKty::Ec,
        kid: kid.clone(),
        alg,
        use_: JwkUse::Sig,
        n: None,
        e: None,
        x: Some(Base64Url::new(x).unwrap()),
        y: Some(Base64Url::new(y).unwrap()),
        crv: Some(issuerd_core::JwkCurve::P256),
        k: None,
    };

    Ok((pkcs8_der, jwk))
}

fn generate_ec_p384(kid: &KeyId, alg: Algorithm) -> Result<(Vec<u8>, Jwk), IssuerdError> {
    let mut rng = rand::thread_rng();
    let secret = p384::SecretKey::random(&mut rng);
    let pkcs8_der = secret
        .to_pkcs8_der()
        .map_err(|e| IssuerdError::ServerError(format!("EC PKCS#8 encoding failed: {e}")))?
        .as_bytes()
        .to_vec();

    let public = secret.public_key();
    let encoded = public.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded.x().expect("uncompressed point has x"));
    let y = URL_SAFE_NO_PAD.encode(encoded.y().expect("uncompressed point has y"));

    let jwk = Jwk {
        kty: JwkKty::Ec,
        kid: kid.clone(),
        alg,
        use_: JwkUse::Sig,
        n: None,
        e: None,
        x: Some(Base64Url::new(x).unwrap()),
        y: Some(Base64Url::new(y).unwrap()),
        crv: Some(issuerd_core::JwkCurve::P384),
        k: None,
    };

    Ok((pkcs8_der, jwk))
}

fn generate_ec_p521(kid: &KeyId, alg: Algorithm) -> Result<(Vec<u8>, Jwk), IssuerdError> {
    let mut rng = rand::thread_rng();
    let secret = p521::SecretKey::random(&mut rng);
    let pkcs8_der = secret
        .to_pkcs8_der()
        .map_err(|e| IssuerdError::ServerError(format!("EC PKCS#8 encoding failed: {e}")))?
        .as_bytes()
        .to_vec();

    let public = secret.public_key();
    let encoded = public.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded.x().expect("uncompressed point has x"));
    let y = URL_SAFE_NO_PAD.encode(encoded.y().expect("uncompressed point has y"));

    let jwk = Jwk {
        kty: JwkKty::Ec,
        kid: kid.clone(),
        alg,
        use_: JwkUse::Sig,
        n: None,
        e: None,
        x: Some(Base64Url::new(x).unwrap()),
        y: Some(Base64Url::new(y).unwrap()),
        crv: Some(issuerd_core::JwkCurve::P521),
        k: None,
    };

    Ok((pkcs8_der, jwk))
}

fn generate_eddsa_key(kid: &KeyId, alg: Algorithm) -> Result<(Vec<u8>, Jwk), IssuerdError> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| IssuerdError::ServerError(format!("EdDSA key generation failed: {e}")))?;
    let pkcs8_bytes = pkcs8.as_ref().to_vec();

    let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)
        .map_err(|e| IssuerdError::ServerError(format!("EdDSA key parse failed: {e}")))?;
    let public_key_bytes = keypair.public_key().as_ref().to_vec();

    let x = URL_SAFE_NO_PAD.encode(&public_key_bytes);

    let jwk = Jwk {
        kty: JwkKty::Okp,
        kid: kid.clone(),
        alg,
        use_: JwkUse::Sig,
        n: None,
        e: None,
        x: Some(Base64Url::new(x).unwrap()),
        y: None,
        crv: Some(issuerd_core::JwkCurve::Ed25519),
        k: None,
    };

    Ok((pkcs8_bytes, jwk))
}

fn generate_hmac_key(kid: &KeyId, alg: Algorithm) -> Result<(Vec<u8>, Jwk), IssuerdError> {
    let len = match alg {
        Algorithm::Hs256 => 32,
        Algorithm::Hs384 => 48,
        Algorithm::Hs512 => 64,
        _ => unreachable!(),
    };
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);

    let k = URL_SAFE_NO_PAD.encode(&bytes);

    let jwk = Jwk {
        kty: JwkKty::Oct,
        kid: kid.clone(),
        alg,
        use_: JwkUse::Sig,
        n: None,
        e: None,
        x: None,
        y: None,
        crv: None,
        k: Some(Base64Url::new(k).unwrap()),
    };

    Ok((bytes, jwk))
}

/// [`CryptoProvider`] implementation backed by `jsonwebtoken` + `ring`.
pub struct RingCryptoProvider {
    key_store: Arc<std::sync::RwLock<KeyStore>>,
    config: CryptoConfig,
}

impl RingCryptoProvider {
    pub fn new(config: CryptoConfig) -> Result<Self, IssuerdError> {
        let key_store = KeyStore::new(&config)?;
        Ok(Self {
            key_store: Arc::new(std::sync::RwLock::new(key_store)),
            config,
        })
    }

    /// Create a provider whose key store is loaded from persisted shared keys.
    ///
    /// Cluster nodes call this at boot so every node signs with the same
    /// shared key set. When `keys` is empty (fresh installation), a new key
    /// is generated exactly as in [`RingCryptoProvider::new`] so startup never
    /// breaks.
    pub fn from_signing_keys(
        config: CryptoConfig,
        keys: &[StoredSigningKey],
    ) -> Result<Self, IssuerdError> {
        if keys.is_empty() {
            return Self::new(config);
        }
        let key_store = KeyStore::from_stored_keys(keys);
        Ok(Self {
            key_store: Arc::new(std::sync::RwLock::new(key_store)),
            config,
        })
    }

    /// Replace the key store contents from persisted shared keys.
    ///
    /// Used by the JWKS polling task to pick up keys added or rotated by other
    /// cluster nodes. An empty slice is a no-op: the existing keys are kept.
    pub fn reload_keys(&self, keys: &[StoredSigningKey]) -> Result<(), IssuerdError> {
        if keys.is_empty() {
            return Ok(());
        }
        let new_store = KeyStore::from_stored_keys(keys);
        let mut store = self
            .key_store
            .write()
            .map_err(|_| IssuerdError::ServerError("key store poisoned".into()))?;
        *store = new_store;
        Ok(())
    }
}

fn map_alg(alg: Algorithm) -> Result<jsonwebtoken::Algorithm, IssuerdError> {
    match alg {
        Algorithm::Rs256 => Ok(jsonwebtoken::Algorithm::RS256),
        Algorithm::Rs384 => Ok(jsonwebtoken::Algorithm::RS384),
        Algorithm::Rs512 => Ok(jsonwebtoken::Algorithm::RS512),
        Algorithm::Es256 => Ok(jsonwebtoken::Algorithm::ES256),
        Algorithm::Es384 => Ok(jsonwebtoken::Algorithm::ES384),
        // ES512 is handled by the manual `es512` path (jsonwebtoken/ring has
        // no P-521 support); reaching this arm is a programming error.
        Algorithm::Es512 => Err(IssuerdError::InvalidRequest(
            "ES512 is not supported by jsonwebtoken; use the es512 module path".into(),
        )),
        Algorithm::Hs256 => Ok(jsonwebtoken::Algorithm::HS256),
        Algorithm::Hs384 => Ok(jsonwebtoken::Algorithm::HS384),
        Algorithm::Hs512 => Ok(jsonwebtoken::Algorithm::HS512),
        Algorithm::EdDsa => Ok(jsonwebtoken::Algorithm::EdDSA),
    }
}

fn build_encoding_key(alg: Algorithm, private_der: &[u8]) -> jsonwebtoken::EncodingKey {
    match alg {
        Algorithm::Rs256 | Algorithm::Rs384 | Algorithm::Rs512 => {
            jsonwebtoken::EncodingKey::from_rsa_der(private_der)
        }
        Algorithm::Es256 | Algorithm::Es384 | Algorithm::Es512 => {
            jsonwebtoken::EncodingKey::from_ec_der(private_der)
        }
        Algorithm::Hs256 | Algorithm::Hs384 | Algorithm::Hs512 => {
            jsonwebtoken::EncodingKey::from_secret(private_der)
        }
        Algorithm::EdDsa => jsonwebtoken::EncodingKey::from_ed_der(private_der),
    }
}

fn build_decoding_key(jwk: &Jwk) -> Result<jsonwebtoken::DecodingKey, IssuerdError> {
    match jwk.kty {
        JwkKty::Rsa => {
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| IssuerdError::InvalidRequest("RSA JWK missing modulus".into()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| IssuerdError::InvalidRequest("RSA JWK missing exponent".into()))?;
            jsonwebtoken::DecodingKey::from_rsa_components(n.as_str(), e.as_str())
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid RSA JWK: {e}")))
        }
        JwkKty::Ec => {
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| IssuerdError::InvalidRequest("EC JWK missing x".into()))?;
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| IssuerdError::InvalidRequest("EC JWK missing y".into()))?;
            jsonwebtoken::DecodingKey::from_ec_components(x.as_str(), y.as_str())
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid EC JWK: {e}")))
        }
        JwkKty::Okp => {
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| IssuerdError::InvalidRequest("OKP JWK missing x".into()))?;
            jsonwebtoken::DecodingKey::from_ed_components(x.as_str())
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid OKP JWK: {e}")))
        }
        JwkKty::Oct => {
            let k = jwk
                .k
                .as_ref()
                .ok_or_else(|| IssuerdError::InvalidRequest("oct JWK missing k".into()))?;
            let bytes = URL_SAFE_NO_PAD.decode(k.as_str()).map_err(|e| {
                IssuerdError::InvalidRequest(format!("invalid base64 in oct JWK: {e}"))
            })?;
            Ok(jsonwebtoken::DecodingKey::from_secret(&bytes))
        }
    }
}

#[async_trait]
impl CryptoProvider for RingCryptoProvider {
    async fn sign(
        &self,
        payload: &str,
        alg: Algorithm,
        kid: &KeyId,
    ) -> Result<String, IssuerdError> {
        let store = self
            .key_store
            .read()
            .map_err(|_| IssuerdError::ServerError("key store poisoned".into()))?;
        // Fail closed: only active keys may sign. A kid that resolves to a
        // passive (disabled) key — e.g. just disabled via the admin API —
        // is rejected rather than quietly used (`PUT /keys/{kid}/disable`
        // contract: "still validates, never signs"). Verification keeps using
        // `find_key`, so passive keys still verify.
        let signing_key = store.find_active_key(kid).ok_or_else(|| {
            if store.find_key(kid).is_some() {
                IssuerdError::InvalidRequest(format!(
                    "key is disabled (passive) and cannot sign: {kid}"
                ))
            } else {
                IssuerdError::InvalidRequest(format!("unknown key id: {kid}"))
            }
        })?;

        // ES512 has no jsonwebtoken mapping (ring lacks P-521); it is signed
        // manually via the p521 crate.
        if alg == Algorithm::Es512 {
            // Match the jsonwebtoken path: reject non-JSON payloads.
            serde_json::from_str::<serde_json::Value>(payload)
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid JSON payload: {e}")))?;
            return crate::es512::encode_es512_jws(payload, kid, &signing_key.private_der);
        }

        let jwt_alg = map_alg(alg)?;
        let encoding_key = build_encoding_key(alg, &signing_key.private_der);

        let header = jsonwebtoken::Header {
            alg: jwt_alg,
            kid: Some(kid.to_string()),
            ..Default::default()
        };

        // Parse payload as serde_json::Value to preserve exact JSON semantics.
        let claims: serde_json::Value = serde_json::from_str(payload)
            .map_err(|e| IssuerdError::InvalidRequest(format!("invalid JSON payload: {e}")))?;

        jsonwebtoken::encode(&header, &claims, &encoding_key)
            .map_err(|e| IssuerdError::ServerError(format!("signing failed: {e}")))
    }

    async fn verify(&self, token: &str, alg: Algorithm, kid: &KeyId) -> Result<bool, IssuerdError> {
        let store = self
            .key_store
            .read()
            .map_err(|_| IssuerdError::ServerError("key store poisoned".into()))?;
        let signing_key = store
            .find_key(kid)
            .ok_or_else(|| IssuerdError::InvalidRequest(format!("unknown key id: {kid}")))?;

        // ES512 is verified manually via the p521 crate; see sign.
        if alg == Algorithm::Es512 {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() != 3 {
                return Ok(false);
            }
            let Ok(signature) = URL_SAFE_NO_PAD.decode(parts[2]) else {
                return Ok(false);
            };
            let message = format!("{}.{}", parts[0], parts[1]);
            return crate::es512::verify_es512(
                &signing_key.public_jwk,
                message.as_bytes(),
                &signature,
            );
        }

        let jwt_alg = map_alg(alg)?;
        let decoding_key = build_decoding_key(&signing_key.public_jwk)?;
        drop(store);

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Ok(false);
        }
        let message = format!("{}.{}", parts[0], parts[1]);
        match jsonwebtoken::crypto::verify(parts[2], message.as_bytes(), &decoding_key, jwt_alg) {
            Ok(valid) => Ok(valid),
            Err(_) => Ok(false),
        }
    }

    async fn get_public_keys(&self) -> Result<JwkSet, IssuerdError> {
        let store = self
            .key_store
            .read()
            .map_err(|_| IssuerdError::ServerError("key store poisoned".into()))?;
        Ok(JwkSet {
            keys: store.public_jwks(),
        })
    }

    async fn get_active_public_keys(&self) -> Result<JwkSet, IssuerdError> {
        let store = self
            .key_store
            .read()
            .map_err(|_| IssuerdError::ServerError("key store poisoned".into()))?;
        Ok(JwkSet {
            keys: store.active_public_jwks(),
        })
    }

    async fn active_signing_algorithms(&self) -> Result<Vec<Algorithm>, IssuerdError> {
        let store = self
            .key_store
            .read()
            .map_err(|_| IssuerdError::ServerError("key store poisoned".into()))?;
        // Distinct algorithms of the active keys, newest first (the keystore
        // sorts active keys by created_at ascending). Symmetric (HMAC)
        // algorithms are never advertised: discovery publishes this list in
        // `id_token_signing_alg_values_supported`, and HS* verification
        // requires the shared secret, which must never leave the server.
        let mut algs = Vec::new();
        for key in store.active.iter().rev() {
            if !key.alg.is_symmetric() && !algs.contains(&key.alg) {
                algs.push(key.alg);
            }
        }
        Ok(algs)
    }

    async fn rotate_keys(&self) -> Result<(), IssuerdError> {
        let mut store = self
            .key_store
            .write()
            .map_err(|_| IssuerdError::ServerError("key store poisoned".into()))?;
        let mut old_active = Vec::new();
        std::mem::swap(&mut old_active, &mut store.active);
        store.passive.extend(old_active);
        let new_key = KeyStore::generate_key(self.config.default_alg, self.config.rsa_key_size)?;
        store.active.push(new_key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_2048_key_generation_ok() {
        let sk = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        assert!(!sk.kid.to_string().is_empty());
        assert_eq!(sk.public_jwk.kty, JwkKty::Rsa);
        assert!(sk.public_jwk.n.is_some());
        assert!(sk.public_jwk.e.is_some());
    }

    #[test]
    fn rsa_4096_key_generation_ok() {
        let sk = KeyStore::generate_key(Algorithm::Rs512, 4096).unwrap();
        assert!(!sk.kid.to_string().is_empty());
        assert_eq!(sk.public_jwk.kty, JwkKty::Rsa);
        assert!(sk.public_jwk.n.is_some());
        assert!(sk.public_jwk.e.is_some());
    }

    #[test]
    fn ec_p256_key_generation_ok() {
        let sk = KeyStore::generate_key(Algorithm::Es256, 2048).unwrap();
        assert!(!sk.kid.to_string().is_empty());
        assert_eq!(sk.public_jwk.kty, JwkKty::Ec);
        assert_eq!(sk.public_jwk.crv, Some(issuerd_core::JwkCurve::P256));
        assert!(sk.public_jwk.x.is_some());
        assert!(sk.public_jwk.y.is_some());
    }

    #[test]
    fn ec_p384_key_generation_ok() {
        let sk = KeyStore::generate_key(Algorithm::Es384, 2048).unwrap();
        assert!(!sk.kid.to_string().is_empty());
        assert_eq!(sk.public_jwk.kty, JwkKty::Ec);
        assert_eq!(sk.public_jwk.crv, Some(issuerd_core::JwkCurve::P384));
        assert!(sk.public_jwk.x.is_some());
        assert!(sk.public_jwk.y.is_some());
    }

    #[test]
    fn ed25519_key_generation_ok() {
        let sk = KeyStore::generate_key(Algorithm::EdDsa, 2048).unwrap();
        assert!(!sk.kid.to_string().is_empty());
        assert_eq!(sk.public_jwk.kty, JwkKty::Okp);
        assert_eq!(sk.public_jwk.crv, Some(issuerd_core::JwkCurve::Ed25519));
        assert!(sk.public_jwk.x.is_some());
    }

    #[test]
    fn hmac_key_generation_ok() {
        let sk256 = KeyStore::generate_key(Algorithm::Hs256, 2048).unwrap();
        assert_eq!(sk256.private_der.len(), 32);
        assert_eq!(sk256.public_jwk.kty, JwkKty::Oct);
        assert!(sk256.public_jwk.k.is_some());

        let sk384 = KeyStore::generate_key(Algorithm::Hs384, 2048).unwrap();
        assert_eq!(sk384.private_der.len(), 48);

        let sk512 = KeyStore::generate_key(Algorithm::Hs512, 2048).unwrap();
        assert_eq!(sk512.private_der.len(), 64);
    }

    #[tokio::test]
    async fn sign_rejects_invalid_json_payload() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let result = provider.sign("not valid json", Algorithm::Rs256, &kid).await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("invalid JSON payload"));
    }

    #[tokio::test]
    async fn keystore_find_key_passive() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks_before = provider.get_public_keys().await.unwrap();
        let old_kid = jwks_before.keys[0].kid.clone();

        provider.rotate_keys().await.unwrap();

        // Old key should still be findable (now passive).
        let store = provider.key_store.read().unwrap();
        assert!(store.find_key(&old_kid).is_some());
    }

    #[test]
    fn keystore_find_active_key_skips_passive() {
        let active = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let passive = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let store = KeyStore::from_stored_keys(&[active.to_stored(true), passive.to_stored(false)]);

        assert_eq!(store.find_active_key(&active.kid).map(|k| &k.kid), Some(&active.kid));
        // Passive keys are invisible to the signing lookup but still found by
        // the verification lookup.
        assert!(store.find_active_key(&passive.kid).is_none());
        assert!(store.find_key(&passive.kid).is_some());
        assert_eq!(store.active_public_jwks().len(), 1);
        assert_eq!(store.active_public_jwks()[0].kid, active.kid);
        assert_eq!(store.public_jwks().len(), 2);
    }

    #[tokio::test]
    async fn sign_with_passive_key_fails_closed_but_still_verifies() {
        // Start with one active key, sign a token, then disable the key.
        let key = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let kid = key.kid.clone();
        let provider =
            RingCryptoProvider::from_signing_keys(CryptoConfig::default(), &[key.to_stored(true)])
                .unwrap();
        let payload = r#"{"sub":"user-1"}"#;
        let token = provider.sign(payload, Algorithm::Rs256, &kid).await.unwrap();

        // Disable: the key becomes passive (as PUT /keys/{kid}/disable does).
        provider.reload_keys(&[key.to_stored(false)]).unwrap();

        // Fail closed: signing with a disabled key errors instead of using it.
        let result = provider.sign(payload, Algorithm::Rs256, &kid).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));

        // Tokens it signed while active still verify.
        assert!(provider.verify(&token, Algorithm::Rs256, &kid).await.unwrap());
    }

    #[tokio::test]
    async fn get_active_public_keys_excludes_passive_keys() {
        let active = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let mut passive = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        passive.created_at = active.created_at + chrono::Duration::seconds(1);
        let provider = RingCryptoProvider::from_signing_keys(
            CryptoConfig::default(),
            &[active.to_stored(true), passive.to_stored(false)],
        )
        .unwrap();

        // The full set publishes both (passive still verifies)...
        let all = provider.get_public_keys().await.unwrap();
        assert_eq!(all.keys.len(), 2);
        // ...the active set only the signing-eligible key, even though the
        // passive key is newer.
        let active_jwks = provider.get_active_public_keys().await.unwrap();
        assert_eq!(active_jwks.keys.len(), 1);
        assert_eq!(active_jwks.keys[0].kid, active.kid);
    }

    #[tokio::test]
    async fn get_active_public_keys_strips_hmac_secret() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Hs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let active = provider.get_active_public_keys().await.unwrap();
        assert_eq!(active.keys.len(), 1);
        assert!(active.keys.iter().all(|k| k.k.is_none()));
    }

    #[tokio::test]
    async fn active_signing_algorithms_excludes_symmetric() {
        let rsa = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let mut hmac = KeyStore::generate_key(Algorithm::Hs256, 2048).unwrap();
        hmac.created_at = rsa.created_at + chrono::Duration::seconds(1);
        let provider = RingCryptoProvider::from_signing_keys(
            CryptoConfig::default(),
            &[rsa.to_stored(true), hmac.to_stored(true)],
        )
        .unwrap();

        // The newer HS256 key is active but must not be advertised.
        assert_eq!(provider.active_signing_algorithms().await.unwrap(), vec![Algorithm::Rs256]);
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_rs256() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Rs256, &kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::Rs256, &kid).await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_hs256() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Hs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Hs256, &kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::Hs256, &kid).await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn public_jwks_never_expose_hmac_secret() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Hs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        // Rotate so both an active and a passive oct key exist.
        provider.rotate_keys().await.unwrap();

        let jwks = provider.get_public_keys().await.unwrap();
        assert!(jwks.keys.len() >= 2);
        assert!(jwks.keys.iter().all(|k| k.kty == JwkKty::Oct));
        assert!(
            jwks.keys.iter().all(|k| k.k.is_none()),
            "published JWKS must never contain the symmetric key material"
        );
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_eddsa() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::EdDsa,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::EdDsa, &kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::EdDsa, &kid).await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn verify_tampered_payload_fails() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1"}"#;
        let token = provider.sign(payload, Algorithm::Rs256, &kid).await.unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let fake_claims = URL_SAFE_NO_PAD.encode(r#"{"sub":"user-2"}"#);
        parts[1] = &fake_claims;
        let tampered = parts.join(".");
        let valid = provider.verify(&tampered, Algorithm::Rs256, &kid).await.unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn get_public_keys_roundtrips() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let json = serde_json::to_string(&jwks).unwrap();
        let back: JwkSet = serde_json::from_str(&json).unwrap();
        assert_eq!(jwks.keys.len(), back.keys.len());
    }

    #[test]
    fn crypto_config_default() {
        let config = CryptoConfig::default();
        // Asymmetric-first policy: new realms/keys default to EdDSA; RS256
        // remains selectable as an explicit compatibility choice.
        assert_eq!(config.default_alg, Algorithm::EdDsa);
        assert_eq!(config.rsa_key_size, 2048);
    }

    #[test]
    fn ec_p521_key_generation_ok() {
        let sk = KeyStore::generate_key(Algorithm::Es512, 2048).unwrap();
        assert!(!sk.kid.to_string().is_empty());
        assert_eq!(sk.public_jwk.kty, JwkKty::Ec);
        assert_eq!(sk.public_jwk.crv, Some(issuerd_core::JwkCurve::P521));
        assert!(sk.public_jwk.x.is_some());
        assert!(sk.public_jwk.y.is_some());
    }

    #[tokio::test]
    async fn sign_with_invalid_json_payload_returns_error() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let result = provider.sign("not json", Algorithm::Rs256, &kid).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid JSON payload"));
    }

    #[tokio::test]
    async fn verify_malformed_token_not_three_parts() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let valid = provider.verify("only.two.parts", Algorithm::Rs256, &kid).await.unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn verify_unknown_kid_returns_error() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();

        let result = provider
            .verify("a.b.c", Algorithm::Rs256, &KeyId::new("unknown").unwrap())
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown key id"));
    }

    #[tokio::test]
    async fn sign_unknown_kid_returns_error() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();

        let result =
            provider.sign(r#"{}"#, Algorithm::Rs256, &KeyId::new("unknown").unwrap()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown key id"));
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_es512() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Es512,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Es512, &kid).await.unwrap();

        // Header carries the ES512 alg and the signing kid.
        let header_bytes = URL_SAFE_NO_PAD.decode(token.split('.').next().unwrap()).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES512");
        assert_eq!(header["kid"], kid.to_string());

        let valid = provider.verify(&token, Algorithm::Es512, &kid).await.unwrap();
        assert!(valid);

        // Tampering with the payload invalidates the signature.
        let mut parts: Vec<&str> = token.split('.').collect();
        let fake_claims = URL_SAFE_NO_PAD.encode(r#"{"sub":"user-2"}"#);
        parts[1] = &fake_claims;
        let tampered = parts.join(".");
        let valid = provider.verify(&tampered, Algorithm::Es512, &kid).await.unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn verify_es512_malformed_token_returns_false() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Es512,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        // Not three segments, and not valid base64url in the signature slot.
        assert!(!provider.verify("only.two.parts", Algorithm::Es512, &kid).await.unwrap());
        assert!(!provider.verify("a.b.!!!", Algorithm::Es512, &kid).await.unwrap());
    }

    #[tokio::test]
    async fn sign_es512_rejects_invalid_json_payload() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Es512,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let result = provider.sign("not json", Algorithm::Es512, &kid).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid JSON payload"));
    }

    #[tokio::test]
    async fn active_signing_algorithms_reports_active_keys_newest_first() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        assert_eq!(provider.active_signing_algorithms().await.unwrap(), vec![Algorithm::Rs256]);

        // Load a shared key set with two active keys of different algorithms.
        let rsa = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap().to_stored(true);
        // Ensure a strictly later created_at for deterministic ordering.
        let mut es = KeyStore::generate_key(Algorithm::Es256, 2048).unwrap();
        es.created_at = rsa.created_at + chrono::Duration::seconds(1);
        let es = es.to_stored(true);
        let old_rsa = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap().to_stored(false);
        provider.reload_keys(&[rsa, es, old_rsa]).unwrap();

        assert_eq!(
            provider.active_signing_algorithms().await.unwrap(),
            vec![Algorithm::Es256, Algorithm::Rs256]
        );
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_es256() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Es256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Es256, &kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::Es256, &kid).await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_hs384() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Hs384,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Hs384, &kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::Hs384, &kid).await.unwrap();
        assert!(valid);
    }

    #[test]
    fn map_alg_es512_error() {
        let result = map_alg(Algorithm::Es512);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ES512 is not supported"));
    }

    #[test]
    fn rsa_key_generation_invalid_bits_fails() {
        let result = KeyStore::generate_key(Algorithm::Rs256, 0);
        assert!(result.is_err());
    }

    #[test]
    fn provider_new_with_invalid_rsa_bits_fails() {
        let bad_config = CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 0,
        };
        let result = RingCryptoProvider::new(bad_config);
        assert!(result.is_err());
    }

    #[test]
    fn build_decoding_key_missing_rsa_n() {
        let jwk = Jwk {
            kty: JwkKty::Rsa,
            kid: KeyId::new("k1").unwrap(),
            alg: Algorithm::Rs256,
            use_: JwkUse::Sig,
            n: None,
            e: Some(Base64Url::new("AQAB").unwrap()),
            x: None,
            y: None,
            crv: None,
            k: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing modulus"));
    }

    #[test]
    fn build_decoding_key_missing_rsa_e() {
        let jwk = Jwk {
            kty: JwkKty::Rsa,
            kid: KeyId::new("k1").unwrap(),
            alg: Algorithm::Rs256,
            use_: JwkUse::Sig,
            n: Some(Base64Url::new("abc").unwrap()),
            e: None,
            x: None,
            y: None,
            crv: None,
            k: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing exponent"));
    }

    #[test]
    fn build_decoding_key_missing_ec_x() {
        let jwk = Jwk {
            kty: JwkKty::Ec,
            kid: KeyId::new("k1").unwrap(),
            alg: Algorithm::Es256,
            use_: JwkUse::Sig,
            n: None,
            e: None,
            x: None,
            y: Some(Base64Url::new("yyy").unwrap()),
            crv: Some(issuerd_core::JwkCurve::P256),
            k: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing x"));
    }

    #[test]
    fn build_decoding_key_missing_ec_y() {
        let jwk = Jwk {
            kty: JwkKty::Ec,
            kid: KeyId::new("k1").unwrap(),
            alg: Algorithm::Es256,
            use_: JwkUse::Sig,
            n: None,
            e: None,
            x: Some(Base64Url::new("xxx").unwrap()),
            y: None,
            crv: Some(issuerd_core::JwkCurve::P256),
            k: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing y"));
    }

    #[test]
    fn build_decoding_key_missing_okp_x() {
        let jwk = Jwk {
            kty: JwkKty::Okp,
            kid: KeyId::new("k1").unwrap(),
            alg: Algorithm::EdDsa,
            use_: JwkUse::Sig,
            n: None,
            e: None,
            x: None,
            y: None,
            crv: Some(issuerd_core::JwkCurve::Ed25519),
            k: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing x"));
    }

    #[test]
    fn build_decoding_key_missing_oct_k() {
        let jwk = Jwk {
            kty: JwkKty::Oct,
            kid: KeyId::new("k1").unwrap(),
            alg: Algorithm::Hs256,
            use_: JwkUse::Sig,
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
            k: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing k"));
    }

    #[test]
    fn build_decoding_key_unknown_kty_rejected_at_deserialization() {
        let json = r#"{"kty":"UNKNOWN","kid":"k1","alg":"RS256","use":"sig"}"#;
        let result = serde_json::from_str::<Jwk>(json);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rotate_keys_moves_active_to_passive() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks_before = provider.get_public_keys().await.unwrap();
        let old_kid = jwks_before.keys[0].kid.clone();

        provider.rotate_keys().await.unwrap();

        let jwks_after = provider.get_public_keys().await.unwrap();
        assert_eq!(jwks_after.keys.len(), 2);
        let new_kid = &jwks_after.keys[0].kid;
        assert_ne!(new_kid, &old_kid);

        // Old key should still be present (now passive).
        let old_still_present = jwks_after.keys.iter().any(|k| k.kid == old_kid);
        assert!(old_still_present);
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_rs384() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs384,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Rs384, &kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::Rs384, &kid).await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_rs512() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs512,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Rs512, &kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::Rs512, &kid).await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_hs512() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Hs512,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Hs512, &kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::Hs512, &kid).await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn sign_verify_roundtrip_es384() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Es384,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Es384, &kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::Es384, &kid).await.unwrap();
        assert!(valid);
    }

    #[test]
    fn map_alg_all_variants() {
        assert_eq!(map_alg(Algorithm::Rs256).unwrap(), jsonwebtoken::Algorithm::RS256);
        assert_eq!(map_alg(Algorithm::Rs384).unwrap(), jsonwebtoken::Algorithm::RS384);
        assert_eq!(map_alg(Algorithm::Rs512).unwrap(), jsonwebtoken::Algorithm::RS512);
        assert_eq!(map_alg(Algorithm::Es256).unwrap(), jsonwebtoken::Algorithm::ES256);
        assert_eq!(map_alg(Algorithm::Es384).unwrap(), jsonwebtoken::Algorithm::ES384);
        assert_eq!(map_alg(Algorithm::Hs256).unwrap(), jsonwebtoken::Algorithm::HS256);
        assert_eq!(map_alg(Algorithm::Hs384).unwrap(), jsonwebtoken::Algorithm::HS384);
        assert_eq!(map_alg(Algorithm::Hs512).unwrap(), jsonwebtoken::Algorithm::HS512);
        assert_eq!(map_alg(Algorithm::EdDsa).unwrap(), jsonwebtoken::Algorithm::EdDSA);
    }

    #[test]
    fn keystore_find_key_and_public_jwks() {
        let store = KeyStore::new(&CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = store.public_jwks();
        assert_eq!(jwks.len(), 1);
        let kid = jwks[0].kid.clone();
        assert!(store.find_key(&kid).is_some());
        assert!(store.find_key(&KeyId::new("missing").unwrap()).is_none());
    }

    #[tokio::test]
    async fn verify_malformed_signature_returns_false() {
        let provider = RingCryptoProvider::new(CryptoConfig {
            default_alg: Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        let kid = jwks.keys[0].kid.clone();

        // Signature contains characters not valid in base64url
        let valid = provider
            .verify("header.payload.not!!!valid", Algorithm::Rs256, &kid)
            .await
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn build_decoding_key_invalid_oct_base64() {
        // "a" is valid base64url characters but invalid base64 length (1 mod 4)
        let jwk = Jwk {
            kty: JwkKty::Oct,
            kid: KeyId::new("k1").unwrap(),
            alg: Algorithm::Hs256,
            use_: JwkUse::Sig,
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
            k: Some(Base64Url::new("a").unwrap()),
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("base64")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn stored_key_roundtrip_preserves_signing_behavior() {
        let original = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let stored = original.to_stored(true);
        assert!(stored.active);

        let restored = SigningKey::from_stored(&stored);
        assert_eq!(restored.kid, original.kid);
        assert_eq!(restored.alg, original.alg);
        assert_eq!(restored.created_at, original.created_at);
        assert_eq!(restored.private_der, original.private_der);
        assert_eq!(restored.public_jwk, original.public_jwk);

        // A provider booted from the stored key signs and verifies with the
        // same kid exactly as the original in-memory key would.
        let provider =
            RingCryptoProvider::from_signing_keys(CryptoConfig::default(), &[stored]).unwrap();
        let payload = r#"{"sub":"user-1","iss":"test"}"#;
        let token = provider.sign(payload, Algorithm::Rs256, &original.kid).await.unwrap();
        let valid = provider.verify(&token, Algorithm::Rs256, &original.kid).await.unwrap();
        assert!(valid);
    }

    #[test]
    fn from_stored_keys_splits_active_passive_and_prefers_newest_active() {
        let active_key = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let passive_key = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();

        let mut stored_active = active_key.to_stored(true);
        stored_active.created_at = Utc::now();
        let mut stored_passive = passive_key.to_stored(false);
        stored_passive.created_at = Utc::now() - chrono::Duration::hours(1);

        // Insert newest last to prove the keystore ordering is deterministic
        // regardless of input order.
        let store = KeyStore::from_stored_keys(&[stored_passive, stored_active]);
        let jwks = store.public_jwks();
        assert_eq!(jwks.len(), 2);
        assert!(jwks.iter().any(|j| j.kid == active_key.kid));
        assert!(jwks.iter().any(|j| j.kid == passive_key.kid));

        // Signing kid selection reads keys[0] — it must be the newest ACTIVE key.
        assert_eq!(jwks[0].kid, active_key.kid);
        assert_eq!(jwks[1].kid, passive_key.kid);
        assert!(store.find_key(&active_key.kid).is_some());
        assert!(store.find_key(&passive_key.kid).is_some());
    }

    #[test]
    fn public_jwks_active_key_precedes_newer_passive_key() {
        let active_key = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let passive_key = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();

        let mut stored_active = active_key.to_stored(true);
        stored_active.created_at = Utc::now() - chrono::Duration::hours(2);
        let mut stored_passive = passive_key.to_stored(false);
        // Passive key is NEWER than the active one; it must still lose.
        stored_passive.created_at = Utc::now();

        let store = KeyStore::from_stored_keys(&[stored_active, stored_passive]);
        let jwks = store.public_jwks();
        assert_eq!(
            jwks[0].kid, active_key.kid,
            "the newest ACTIVE key must be selected for signing, not the newest key overall"
        );
        assert_eq!(jwks[1].kid, passive_key.kid);
    }

    #[tokio::test]
    async fn from_signing_keys_empty_slice_generates_key() {
        let provider = RingCryptoProvider::from_signing_keys(CryptoConfig::default(), &[]).unwrap();
        let jwks = provider.get_public_keys().await.unwrap();
        assert_eq!(jwks.keys.len(), 1);
        // The generated key follows the server-default algorithm (EdDSA).
        assert_eq!(jwks.keys[0].alg, Algorithm::EdDsa);
    }

    #[tokio::test]
    async fn generate_initial_key_set_pairs_default_with_mti_rs256() {
        // Fresh deployments boot with the default (EdDSA) key AND an active
        // RS256 key: OIDC Core §15.1 mandates RS256 support/advertisement.
        let keys = KeyStore::generate_initial_key_set(Algorithm::EdDsa, 2048).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].alg, Algorithm::Rs256);
        assert_eq!(keys[1].alg, Algorithm::EdDsa);
        assert!(
            keys[1].created_at > keys[0].created_at,
            "the default-algorithm key must be the newest active key"
        );

        // Loaded as an all-active shared set, discovery's source
        // (`active_signing_algorithms`) advertises both, default first.
        let stored: Vec<_> = keys.iter().map(|k| k.to_stored(true)).collect();
        let provider =
            RingCryptoProvider::from_signing_keys(CryptoConfig::default(), &stored).unwrap();
        assert_eq!(
            provider.active_signing_algorithms().await.unwrap(),
            vec![Algorithm::EdDsa, Algorithm::Rs256]
        );
        // The newest-active fallback signing key (`keys[0]`) is the EdDSA one.
        let jwks = provider.get_active_public_keys().await.unwrap();
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].alg, Algorithm::EdDsa);
        assert_eq!(jwks.keys[1].alg, Algorithm::Rs256);
    }

    #[test]
    fn generate_initial_key_set_with_rs256_default_is_single_key() {
        // RS256 as the requested algorithm already covers the MTI key.
        let keys = KeyStore::generate_initial_key_set(Algorithm::Rs256, 2048).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].alg, Algorithm::Rs256);

        // Other algorithms pair with RS256 the same way.
        let keys = KeyStore::generate_initial_key_set(Algorithm::Es256, 2048).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].alg, Algorithm::Rs256);
        assert_eq!(keys[1].alg, Algorithm::Es256);
    }

    #[tokio::test]
    async fn reload_keys_replaces_set_and_empty_slice_is_noop() {
        let provider = RingCryptoProvider::new(CryptoConfig::default()).unwrap();
        let initial = provider.get_public_keys().await.unwrap();
        let old_kid = initial.keys[0].kid.clone();
        let old_alg = initial.keys[0].alg;
        let payload = r#"{"sub":"user-1"}"#;
        let old_token = provider.sign(payload, old_alg, &old_kid).await.unwrap();

        let new_key = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let new_kid = new_key.kid.clone();
        provider.reload_keys(&[new_key.to_stored(true)]).unwrap();

        // The new key signs and verifies.
        let token = provider.sign(payload, Algorithm::Rs256, &new_kid).await.unwrap();
        assert!(provider.verify(&token, Algorithm::Rs256, &new_kid).await.unwrap());

        // The old kid is gone from the published set and no longer verifies.
        let jwks = provider.get_public_keys().await.unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert!(!jwks.keys.iter().any(|j| j.kid == old_kid));
        let result = provider.verify(&old_token, old_alg, &old_kid).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown key id"));

        // Reloading an empty slice keeps the current set untouched.
        provider.reload_keys(&[]).unwrap();
        assert!(provider.verify(&token, Algorithm::Rs256, &new_kid).await.unwrap());
    }
}
