// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Keycloak-compatible password-hash normalization and verification.

use std::num::NonZeroU32;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::{engine::general_purpose, Engine as _};
use issuerd_core::{Credential, IssuerdError};
use ring::pbkdf2;
use serde_json::{json, Map, Value};

pub const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;
pub const MAX_ARGON2_ITERATIONS: u32 = 10;
pub const MAX_ARGON2_MEMORY_KIB: u32 = 65_536;
pub const MAX_ARGON2_PARALLELISM: u32 = 4;
pub const MAX_CREDENTIAL_JSON_BYTES: usize = 16 * 1024;
pub const MAX_PHC_BYTES: usize = 4096;

const MIN_SALT_BYTES: usize = 8;
const MAX_SALT_BYTES: usize = 64;
const MIN_ARGON2_HASH_BYTES: usize = 16;
const MAX_ARGON2_HASH_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAlgorithm {
    Argon2id,
    Pbkdf2Sha256,
    Pbkdf2Sha512,
}

impl PasswordAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Argon2id => "argon2id",
            Self::Pbkdf2Sha256 => "pbkdf2-sha256",
            Self::Pbkdf2Sha512 => "pbkdf2-sha512",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPassword {
    pub algorithm: PasswordAlgorithm,
    pub secret_data: Vec<u8>,
    pub credential_data: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerification {
    Match,
    NoMatch,
    Unsupported,
}

#[derive(Debug)]
struct Pbkdf2Parts {
    algorithm: PasswordAlgorithm,
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn invalid(message: &str) -> IssuerdError {
    IssuerdError::InvalidRequest(message.to_string())
}

fn validate_salt(salt: &[u8]) -> Result<(), IssuerdError> {
    if !(MIN_SALT_BYTES..=MAX_SALT_BYTES).contains(&salt.len()) {
        return Err(invalid("password salt length is outside the supported bounds"));
    }
    Ok(())
}

fn decode_phc_base64(value: &str) -> Result<Vec<u8>, IssuerdError> {
    general_purpose::STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| general_purpose::STANDARD.decode(value))
        .map_err(|_| invalid("password hash contains invalid base64"))
}

fn decode_keycloak_base64(value: &str) -> Result<Vec<u8>, IssuerdError> {
    let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    decode_phc_base64(&compact)
}

fn pbkdf2_ring_algorithm(algorithm: PasswordAlgorithm) -> Option<pbkdf2::Algorithm> {
    match algorithm {
        PasswordAlgorithm::Pbkdf2Sha256 => Some(pbkdf2::PBKDF2_HMAC_SHA256),
        PasswordAlgorithm::Pbkdf2Sha512 => Some(pbkdf2::PBKDF2_HMAC_SHA512),
        PasswordAlgorithm::Argon2id => None,
    }
}

fn pbkdf2_hash_length(algorithm: PasswordAlgorithm) -> Option<usize> {
    match algorithm {
        PasswordAlgorithm::Pbkdf2Sha256 => Some(32),
        PasswordAlgorithm::Pbkdf2Sha512 => Some(64),
        PasswordAlgorithm::Argon2id => None,
    }
}

fn validate_pbkdf2(parts: &Pbkdf2Parts) -> Result<(), IssuerdError> {
    if parts.iterations == 0 || parts.iterations > MAX_PBKDF2_ITERATIONS {
        return Err(invalid("PBKDF2 iteration count is outside the supported bounds"));
    }
    validate_salt(&parts.salt)?;
    if Some(parts.hash.len()) != pbkdf2_hash_length(parts.algorithm) {
        return Err(invalid("PBKDF2 derived-key length does not match its algorithm"));
    }
    Ok(())
}

fn pbkdf2_metadata(parts: &Pbkdf2Parts) -> Value {
    json!({
        "hash_algorithm": parts.algorithm.as_str(),
        "hash_iterations": parts.iterations,
    })
}

fn pbkdf2_phc(parts: &Pbkdf2Parts) -> String {
    format!(
        "${}$i={}${}${}",
        parts.algorithm.as_str(),
        parts.iterations,
        general_purpose::STANDARD_NO_PAD.encode(&parts.salt),
        general_purpose::STANDARD_NO_PAD.encode(&parts.hash)
    )
}

fn normalized_pbkdf2(parts: Pbkdf2Parts) -> Result<NormalizedPassword, IssuerdError> {
    validate_pbkdf2(&parts)?;
    Ok(NormalizedPassword {
        algorithm: parts.algorithm,
        secret_data: pbkdf2_phc(&parts).into_bytes(),
        credential_data: pbkdf2_metadata(&parts),
    })
}

fn parse_pbkdf2_phc(encoded: &str) -> Result<Pbkdf2Parts, IssuerdError> {
    if encoded.len() > MAX_PHC_BYTES {
        return Err(invalid("password PHC string is too large"));
    }
    let (algorithm, rest) = if let Some(rest) = encoded.strip_prefix("$pbkdf2-sha256$") {
        (PasswordAlgorithm::Pbkdf2Sha256, rest)
    } else if let Some(rest) = encoded.strip_prefix("$pbkdf2-sha512$") {
        (PasswordAlgorithm::Pbkdf2Sha512, rest)
    } else {
        return Err(invalid("unsupported PBKDF2 PHC algorithm"));
    };
    let mut segments = rest.split('$');
    let parameters = segments.next().ok_or_else(|| invalid("invalid PBKDF2 PHC string"))?;
    let salt = segments.next().ok_or_else(|| invalid("invalid PBKDF2 PHC string"))?;
    let hash = segments.next().ok_or_else(|| invalid("invalid PBKDF2 PHC string"))?;
    if segments.next().is_some() {
        return Err(invalid("invalid PBKDF2 PHC string"));
    }

    let mut iterations = None;
    let mut declared_length = None;
    for parameter in parameters.split(',') {
        if let Some(value) = parameter.strip_prefix('i') {
            let value =
                value.strip_prefix('=').ok_or_else(|| invalid("invalid PBKDF2 parameters"))?;
            if iterations.is_some() {
                return Err(invalid("duplicate PBKDF2 iteration parameter"));
            }
            iterations =
                Some(value.parse::<u32>().map_err(|_| invalid("invalid PBKDF2 iterations"))?);
        } else if let Some(value) = parameter.strip_prefix('l') {
            let value =
                value.strip_prefix('=').ok_or_else(|| invalid("invalid PBKDF2 parameters"))?;
            if declared_length.is_some() {
                return Err(invalid("duplicate PBKDF2 length parameter"));
            }
            declared_length =
                Some(value.parse::<usize>().map_err(|_| invalid("invalid PBKDF2 length"))?);
        } else {
            return Err(invalid("unsupported PBKDF2 PHC parameter"));
        }
    }
    let parts = Pbkdf2Parts {
        algorithm,
        iterations: iterations.ok_or_else(|| invalid("missing PBKDF2 iterations"))?,
        salt: decode_phc_base64(salt)?,
        hash: decode_phc_base64(hash)?,
    };
    validate_pbkdf2(&parts)?;
    if declared_length.is_some() && declared_length != Some(parts.hash.len()) {
        return Err(invalid("PBKDF2 PHC length parameter does not match the hash"));
    }
    Ok(parts)
}

fn normalize_argon2_phc(encoded: &str) -> Result<NormalizedPassword, IssuerdError> {
    if encoded.len() > MAX_PHC_BYTES {
        return Err(invalid("password PHC string is too large"));
    }
    let parsed = PasswordHash::new(encoded).map_err(|_| invalid("invalid Argon2 PHC string"))?;
    let argon2_version: u32 = argon2::Version::V0x13.into();
    if parsed.algorithm != argon2::Algorithm::Argon2id.ident()
        || parsed.version.unwrap_or(argon2_version) != argon2_version
    {
        return Err(invalid("unsupported Argon2 algorithm or version"));
    }
    let params =
        argon2::Params::try_from(&parsed).map_err(|_| invalid("invalid Argon2 parameters"))?;
    if params.t_cost() > MAX_ARGON2_ITERATIONS
        || params.m_cost() > MAX_ARGON2_MEMORY_KIB
        || params.p_cost() > MAX_ARGON2_PARALLELISM
    {
        return Err(invalid("Argon2 work parameters exceed the supported limits"));
    }
    let salt = parsed.salt.ok_or_else(|| invalid("missing Argon2 salt"))?;
    validate_salt(&decode_phc_base64(salt.as_str())?)?;
    let hash = parsed.hash.ok_or_else(|| invalid("missing Argon2 hash"))?;
    if !(MIN_ARGON2_HASH_BYTES..=MAX_ARGON2_HASH_BYTES).contains(&hash.len()) {
        return Err(invalid("Argon2 hash length is outside the supported bounds"));
    }
    Ok(NormalizedPassword {
        algorithm: PasswordAlgorithm::Argon2id,
        secret_data: encoded.as_bytes().to_vec(),
        credential_data: json!({
            "hash_algorithm": "argon2id",
            "hash_iterations": params.t_cost(),
            "memory_kib": params.m_cost(),
            "parallelism": params.p_cost(),
            "version": 19,
            "hash_length": hash.len(),
        }),
    })
}

/// Normalize a direct Argon2id or PBKDF2 PHC string without performing password hashing.
pub fn normalize_password_hash(encoded: &str) -> Result<NormalizedPassword, IssuerdError> {
    if encoded.starts_with("$argon2") {
        normalize_argon2_phc(encoded)
    } else if encoded.starts_with("$pbkdf2-") {
        normalized_pbkdf2(parse_pbkdf2_phc(encoded)?)
    } else {
        Err(invalid("unsupported password hash format"))
    }
}

fn json_object(value: &Value) -> Result<Map<String, Value>, IssuerdError> {
    match value {
        Value::Object(object) => {
            if serde_json::to_vec(object)
                .map_or(true, |bytes| bytes.len() > MAX_CREDENTIAL_JSON_BYTES)
            {
                return Err(invalid("credential JSON is too large"));
            }
            Ok(object.clone())
        }
        Value::String(encoded) => {
            if encoded.len() > MAX_CREDENTIAL_JSON_BYTES {
                return Err(invalid("credential JSON is too large"));
            }
            match serde_json::from_str::<Value>(encoded)
                .map_err(|_| invalid("credential JSON is malformed"))?
            {
                Value::Object(object) => Ok(object),
                _ => Err(invalid("credential JSON must contain an object")),
            }
        }
        _ => Err(invalid("credential JSON must be an object or a JSON-encoded object")),
    }
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, IssuerdError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("credential JSON is missing a required string field"))
}

fn required_u32(object: &Map<String, Value>, key: &str) -> Result<u32, IssuerdError> {
    let value = object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("credential JSON is missing a required numeric field"))?;
    u32::try_from(value).map_err(|_| invalid("credential numeric parameter is too large"))
}

fn algorithm_data_value<'a>(
    data: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, IssuerdError> {
    match data.get(key) {
        Some(Value::String(value)) => Ok(value),
        Some(Value::Array(values)) if values.len() == 1 => values[0]
            .as_str()
            .ok_or_else(|| invalid("Argon2 algorithmData values must be strings")),
        _ => Err(invalid("Argon2 algorithmData must contain single-value fields")),
    }
}

fn algorithm_data_u32(data: &Map<String, Value>, key: &str) -> Result<u32, IssuerdError> {
    if let Some(value) = data.get(key).and_then(Value::as_u64) {
        return u32::try_from(value).map_err(|_| invalid("Argon2 numeric parameter is too large"));
    }
    algorithm_data_value(data, key)?
        .parse::<u32>()
        .map_err(|_| invalid("invalid Argon2 numeric algorithmData"))
}

fn normalize_keycloak_argon2(
    credential: &Map<String, Value>,
    secret: &Map<String, Value>,
) -> Result<NormalizedPassword, IssuerdError> {
    let iterations = required_u32(credential, "hashIterations")?;
    if iterations == 0 || iterations > MAX_ARGON2_ITERATIONS {
        return Err(invalid("Argon2 iteration count exceeds the supported limit"));
    }
    let data_value = credential
        .get("algorithmData")
        .filter(|value| value.is_object() || value.is_string())
        .or_else(|| credential.get("additionalParameters"))
        .ok_or_else(|| invalid("Keycloak Argon2 algorithmData is missing"))?;
    let data = json_object(data_value).map_err(|_| {
        invalid("Keycloak Argon2 algorithmData is not an object or JSON object string")
    })?;
    if algorithm_data_value(&data, "version")? != "1.3"
        || algorithm_data_value(&data, "type")? != "id"
    {
        return Err(invalid("unsupported Keycloak Argon2 type or version"));
    }
    let memory = algorithm_data_u32(&data, "memory")?;
    let parallelism = algorithm_data_u32(&data, "parallelism")?;
    let hash_length = algorithm_data_u32(&data, "hashLength")? as usize;
    if memory > MAX_ARGON2_MEMORY_KIB || parallelism == 0 || parallelism > MAX_ARGON2_PARALLELISM {
        return Err(invalid("Argon2 memory or parallelism exceeds the supported limit"));
    }
    if !(MIN_ARGON2_HASH_BYTES..=MAX_ARGON2_HASH_BYTES).contains(&hash_length) {
        return Err(invalid("Argon2 hash length is outside the supported bounds"));
    }
    let salt = decode_keycloak_base64(required_string(secret, "salt")?)?;
    let hash = decode_keycloak_base64(required_string(secret, "value")?)?;
    validate_salt(&salt)?;
    if hash.len() != hash_length {
        return Err(invalid("Argon2 hash length does not match algorithmData"));
    }
    let encoded = format!(
        "$argon2id$v=19$m={memory},t={iterations},p={parallelism}${}${}",
        general_purpose::STANDARD_NO_PAD.encode(salt),
        general_purpose::STANDARD_NO_PAD.encode(hash)
    );
    normalize_argon2_phc(&encoded)
}

fn normalize_keycloak_pbkdf2(
    algorithm: PasswordAlgorithm,
    credential: &Map<String, Value>,
    secret: &Map<String, Value>,
) -> Result<NormalizedPassword, IssuerdError> {
    let parts = Pbkdf2Parts {
        algorithm,
        iterations: required_u32(credential, "hashIterations")?,
        salt: decode_keycloak_base64(required_string(secret, "salt")?)?,
        hash: decode_keycloak_base64(required_string(secret, "value")?)?,
    };
    normalized_pbkdf2(parts)
}

/// Normalize a Keycloak `credentialData`/`secretData` pair. Either field may be
/// an object or a string containing a JSON object.
pub fn normalize_keycloak_password(
    credential_data: &Value,
    secret_data: &Value,
) -> Result<NormalizedPassword, IssuerdError> {
    let credential = json_object(credential_data)?;
    let secret = json_object(secret_data)?;
    match required_string(&credential, "algorithm")? {
        "argon2" => normalize_keycloak_argon2(&credential, &secret),
        "pbkdf2-sha256" => {
            normalize_keycloak_pbkdf2(PasswordAlgorithm::Pbkdf2Sha256, &credential, &secret)
        }
        "pbkdf2-sha512" => {
            normalize_keycloak_pbkdf2(PasswordAlgorithm::Pbkdf2Sha512, &credential, &secret)
        }
        _ => Err(invalid("unsupported Keycloak password algorithm")),
    }
}

fn verify_normalized(candidate: &str, normalized: &NormalizedPassword) -> PasswordVerification {
    let Ok(encoded) = std::str::from_utf8(&normalized.secret_data) else {
        return PasswordVerification::Unsupported;
    };
    match normalized.algorithm {
        PasswordAlgorithm::Argon2id => {
            let Ok(parsed) = PasswordHash::new(encoded) else {
                return PasswordVerification::Unsupported;
            };
            if Argon2::default().verify_password(candidate.as_bytes(), &parsed).is_ok() {
                PasswordVerification::Match
            } else {
                PasswordVerification::NoMatch
            }
        }
        PasswordAlgorithm::Pbkdf2Sha256 | PasswordAlgorithm::Pbkdf2Sha512 => {
            let Ok(parts) = parse_pbkdf2_phc(encoded) else {
                return PasswordVerification::Unsupported;
            };
            let Some(algorithm) = pbkdf2_ring_algorithm(parts.algorithm) else {
                return PasswordVerification::Unsupported;
            };
            let Some(iterations) = NonZeroU32::new(parts.iterations) else {
                return PasswordVerification::Unsupported;
            };
            if pbkdf2::verify(algorithm, iterations, &parts.salt, candidate.as_bytes(), &parts.hash)
                .is_ok()
            {
                PasswordVerification::Match
            } else {
                PasswordVerification::NoMatch
            }
        }
    }
}

/// Verify a candidate against a normalized PHC credential or an unnormalized
/// Keycloak JSON pair. Unsupported and malformed stored values fail closed.
pub fn verify_password(candidate: &str, credential: &Credential) -> PasswordVerification {
    let Ok(secret) = std::str::from_utf8(&credential.secret_data) else {
        return PasswordVerification::Unsupported;
    };
    let normalized = if secret.starts_with('$') {
        normalize_password_hash(secret)
    } else {
        normalize_keycloak_password(&credential.credential_data, &Value::String(secret.to_string()))
    };
    match normalized {
        Ok(normalized) => verify_normalized(candidate, &normalized),
        Err(_) => PasswordVerification::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::PasswordHasher;
    use issuerd_core::{CredentialId, CredentialType};

    const PASSWORD: &str = "correct horse battery staple";
    const SALT_B64: &str = "a2V5Y2xvYWstc2FsdA";

    fn credential(secret: &str, data: Value) -> Credential {
        Credential {
            id: CredentialId::new("credential-1").unwrap(),
            credential_type: CredentialType::Password,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: secret.as_bytes().to_vec(),
            credential_data: data,
            priority: 1,
        }
    }

    fn pbkdf2_pair(algorithm: &str, iterations: u32, hash: &str) -> (Value, Value) {
        (
            json!({"hashIterations": iterations, "algorithm": algorithm}),
            json!({"value": hash, "salt": SALT_B64}),
        )
    }

    #[test]
    fn pbkdf2_known_answers_direct_and_keycloak_forms() {
        let vectors = [
            ("pbkdf2-sha256", 27_500, "R9/y5pwOp8WGpqw1oD3GDq/9FE00ll8Rzm9iRfM7paE"),
            ("pbkdf2-sha256", 600_000, "hsOJl3GhDYMSY6f/peJVng13yRqoAxMO43lSz7QOL3E"),
            ("pbkdf2-sha512", 27_500, "sc7lEf9hMdrCyUDO1nu3GCBVLghgJoc9+mkS9k+lXJ7TfIyvb8YCdnkJI1gD0RIq2D9hrohj6UqgQ/hTHjJpRQ"),
            ("pbkdf2-sha512", 210_000, "FENVvG2zqwkKUJN0i70N6PXF4rRKvd7Hv/P2Lvv086THElFQJfVPjeTdj4+DxfZ1ozzrmSLB1eOKVw2p001Ddw"),
        ];
        for (algorithm, iterations, hash) in vectors {
            let direct = format!("${algorithm}$i={iterations}${SALT_B64}${hash}");
            let normalized = normalize_password_hash(&direct).unwrap();
            assert_eq!(normalized.algorithm.as_str(), algorithm);
            assert_eq!(verify_normalized(PASSWORD, &normalized), PasswordVerification::Match);
            assert_eq!(verify_normalized("wrong", &normalized), PasswordVerification::NoMatch);

            let (credential_data, secret_data) = pbkdf2_pair(algorithm, iterations, hash);
            let imported = normalize_keycloak_password(&credential_data, &secret_data).unwrap();
            assert_eq!(imported, normalized);
            let raw = credential(&secret_data.to_string(), credential_data);
            assert_eq!(verify_password(PASSWORD, &raw), PasswordVerification::Match);
            assert_eq!(verify_password("wrong", &raw), PasswordVerification::NoMatch);
        }
    }

    #[test]
    fn json_encoded_pairs_and_mime_whitespace_are_accepted() {
        let (credential_data, mut secret_data) =
            pbkdf2_pair("pbkdf2-sha256", 27_500, "R9/y5pwOp8WGpqw1oD3GDq/9FE00ll8Rzm9iRfM7paE");
        secret_data["salt"] = Value::String("a2V5Y2xv\r\nYWstc2FsdA==".to_string());
        let credential_data = Value::String(credential_data.to_string());
        let secret_data = Value::String(secret_data.to_string());
        let normalized = normalize_keycloak_password(&credential_data, &secret_data).unwrap();
        assert_eq!(verify_normalized(PASSWORD, &normalized), PasswordVerification::Match);
    }

    #[test]
    fn keycloak_argon2id_mlabs_parameters_normalize_and_verify() {
        let params = argon2::Params::new(7168, 5, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let salt = SaltString::from_b64(SALT_B64).unwrap();
        let hash = argon2.hash_password(PASSWORD.as_bytes(), &salt).unwrap().to_string();
        let parsed = PasswordHash::new(&hash).unwrap();
        let raw_hash = parsed.hash.unwrap();
        let credential_data = json!({
            "hashIterations": 5,
            "algorithm": "argon2",
            "algorithmData": {
                "version": ["1.3"],
                "type": ["id"],
                "hashLength": ["32"],
                "memory": ["7168"],
                "parallelism": ["1"]
            }
        });
        let secret_data = json!({
            "value": general_purpose::STANDARD.encode(raw_hash.as_bytes()),
            "salt": general_purpose::STANDARD.encode(b"keycloak-salt"),
        });
        let normalized = normalize_keycloak_password(&credential_data, &secret_data).unwrap();
        let mut database_credential_data = credential_data.clone();
        let algorithm_data = database_credential_data["algorithmData"].take();
        database_credential_data["additionalParameters"] =
            Value::String(algorithm_data.to_string());
        assert_eq!(
            normalize_keycloak_password(&database_credential_data, &secret_data).unwrap(),
            normalized
        );
        let encoded = std::str::from_utf8(&normalized.secret_data).unwrap();
        assert!(encoded.starts_with("$argon2id$v=19$m=7168,t=5,p=1$"));
        assert_eq!(verify_normalized(PASSWORD, &normalized), PasswordVerification::Match);
        assert_eq!(verify_normalized("wrong", &normalized), PasswordVerification::NoMatch);
        let metadata = normalized.credential_data.to_string();
        assert!(!metadata.contains(salt.as_str()));
        assert!(!metadata.contains(&general_purpose::STANDARD_NO_PAD.encode(raw_hash.as_bytes())));
    }

    #[test]
    fn direct_argon2id_still_verifies() {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default().hash_password(PASSWORD.as_bytes(), &salt).unwrap().to_string();
        let stored = credential(&hash, Value::Null);
        assert_eq!(verify_password(PASSWORD, &stored), PasswordVerification::Match);
        assert_eq!(verify_password("wrong", &stored), PasswordVerification::NoMatch);
    }

    #[test]
    fn malformed_and_resource_hostile_inputs_fail_closed_without_echoing_secrets() {
        let canary = "raw-secret-canary";
        let oversized = "x".repeat(MAX_CREDENTIAL_JSON_BYTES + 1);
        let cases = vec![
            (
                json!({"algorithm": "pbkdf2", "hashIterations": 1}),
                json!({"value": canary, "salt": SALT_B64}),
            ),
            (
                json!({"algorithm": "pbkdf2-sha256", "hashIterations": MAX_PBKDF2_ITERATIONS + 1}),
                json!({"value": canary, "salt": SALT_B64}),
            ),
            (
                json!({"algorithm": "argon2", "hashIterations": 5, "algorithmData": {"version": ["1.2"], "type": ["id"], "hashLength": ["32"], "memory": ["7168"], "parallelism": ["1"]}}),
                json!({"value": canary, "salt": SALT_B64}),
            ),
            (
                json!({"algorithm": "argon2", "hashIterations": 5, "algorithmData": {"version": ["1.3"], "type": ["i"], "hashLength": ["32"], "memory": ["7168"], "parallelism": ["1"]}}),
                json!({"value": canary, "salt": SALT_B64}),
            ),
            (
                json!({"algorithm": "argon2", "hashIterations": 5, "algorithmData": {"version": ["1.3"], "type": ["id"], "hashLength": ["32"], "memory": [format!("{}", MAX_ARGON2_MEMORY_KIB + 1)], "parallelism": ["1"]}}),
                json!({"value": canary, "salt": SALT_B64}),
            ),
            (Value::String(oversized), json!({"value": canary, "salt": SALT_B64})),
            (Value::String(format!("{{\"algorithm\":\"{canary}\"}}")), json!({})),
        ];
        for (credential_data, secret_data) in cases {
            let error = normalize_keycloak_password(&credential_data, &secret_data).unwrap_err();
            assert!(!error.to_string().contains(canary));
        }
    }

    #[test]
    fn invalid_phc_variants_are_unsupported() {
        let valid =
            "$pbkdf2-sha256$i=27500$a2V5Y2xvYWstc2FsdA$R9/y5pwOp8WGpqw1oD3GDq/9FE00ll8Rzm9iRfM7paE";
        let invalid = [
            "$pbkdf2$i=27500$a2V5Y2xvYWstc2FsdA$AAAA",
            "$pbkdf2-sha256$i=0$a2V5Y2xvYWstc2FsdA$AAAA",
            "$pbkdf2-sha256$i=2000001$a2V5Y2xvYWstc2FsdA$AAAA",
            "$pbkdf2-sha256$i=27500$a2V5Y2xvYWstc2FsdA$AAAA",
            "$pbkdf2-sha256$i=27500$a2V5Y2xvYWstc2FsdA$!!!!",
            "$argon2i$v=19$m=7168,t=5,p=1$a2V5Y2xvYWstc2FsdA$AAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=16$m=7168,t=5,p=1$a2V5Y2xvYWstc2FsdA$AAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=65537,t=5,p=1$a2V5Y2xvYWstc2FsdA$AAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=7168,t=11,p=1$a2V5Y2xvYWstc2FsdA$AAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=7168,t=5,p=5$a2V5Y2xvYWstc2FsdA$AAAAAAAAAAAAAAAAAAAAAA",
        ];
        for encoded in invalid {
            let stored = credential(encoded, Value::Null);
            assert_eq!(
                verify_password(PASSWORD, &stored),
                PasswordVerification::Unsupported,
                "{encoded}"
            );
        }
        let stored = credential(valid, Value::Null);
        assert_eq!(verify_password(PASSWORD, &stored), PasswordVerification::Match);
    }
}
