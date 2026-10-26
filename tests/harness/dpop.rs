// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use base64::Engine as _;
use ring::signature::KeyPair as _;

pub struct DpopKey {
    pair: ring::signature::EcdsaKeyPair,
    jwk: serde_json::Value,
}

impl DpopKey {
    pub fn new() -> Self {
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
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": b64(&public[1..33]), "y": b64(&public[33..65]),
        });
        Self { pair, jwk }
    }

    pub fn jkt(&self) -> String {
        issuerd_token::jwk_thumbprint(&self.jwk).unwrap()
    }

    pub fn proof(&self, opts: &ProofOpts) -> String {
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let header = serde_json::json!({"alg": "ES256", "typ": opts.typ, "jwk": self.jwk});
        let mut claims = serde_json::json!({
            "jti": opts.jti,
            "htm": opts.htm,
            "htu": opts.htu,
            "iat": opts.iat,
        });
        if let Some(ref access_token) = opts.ath {
            claims["ath"] = serde_json::json!(issuerd_token::access_token_hash(access_token));
        }
        if let Some(ref nonce) = opts.nonce {
            claims["nonce"] = serde_json::json!(nonce);
        }
        let input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(&header).unwrap()),
            b64(&serde_json::to_vec(&claims).unwrap())
        );
        let rng = ring::rand::SystemRandom::new();
        let signature = self.pair.sign(&rng, input.as_bytes()).unwrap();
        format!("{input}.{}", b64(signature.as_ref()))
    }
}

pub struct ProofOpts {
    pub htm: String,
    pub htu: String,
    pub jti: String,
    pub iat: i64,
    pub ath: Option<String>,
    pub typ: String,
    pub nonce: Option<String>,
}

impl ProofOpts {
    pub fn new(htm: impl Into<String>, htu: impl Into<String>) -> Self {
        Self {
            htm: htm.into(),
            htu: htu.into(),
            jti: issuerd_core::utils::generate_id(),
            iat: chrono::Utc::now().timestamp(),
            ath: None,
            typ: "dpop+jwt".to_string(),
            nonce: None,
        }
    }
}
