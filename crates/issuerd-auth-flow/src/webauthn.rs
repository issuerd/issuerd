// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! WebAuthn/passkey second factor.
//!
//! The ceremonies are driven by `webauthn-rs`; this module adapts them to the
//! Issuerd storage/cache traits:
//!
//! - [`build_webauthn`] constructs the relying-party object from config values.
//! - [`user_handle`] derives the deterministic WebAuthn user handle (UUID v5)
//!   so registration and authentication agree on the handle for a user id.
//! - [`passkey_to_bytes`] / [`passkey_from_bytes`] persist passkeys inside the
//!   existing [`Credential`](issuerd_core::Credential) model (`secret_data`).
//! - [`WebAuthnAuthenticator`] is the conditional browser-flow stage: it
//!   challenges users who own a passkey and verifies their assertion.
//!
//! Passwordless (username-less) login is out of scope; this is WebAuthn as a
//! second factor only.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use issuerd_core::{
    AuthContext, AuthStepResult, Challenge, Credential, CredentialType, DistributedCache,
    IssuerdError, Realm, RealmId, Storage, UserId,
};
use tracing::{instrument, warn};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PublicKeyCredential, Webauthn, WebauthnBuilder,
};

/// Cache TTL for an in-flight authentication ceremony state.
const AUTH_CEREMONY_TTL_SECS: u64 = 300;

/// Fixed UUID v5 namespace for WebAuthn user handles. Arbitrary but constant:
/// changing it would change every user's handle and orphan registered
/// credentials, so never rotate it.
const USER_HANDLE_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    0x7a, 0x3d, 0x51, 0xe8, 0x2b, 0x9f, 0x4c, 0x01, 0x9a, 0x6d, 0x0e, 0x72, 0xb5, 0x48, 0xc3, 0x96,
]);

/// Build the `webauthn-rs` relying-party object.
///
/// `rp_id` must be an effective domain of `rp_origin` (the library enforces
/// this); `rp_name` is the human label shown by authenticators.
pub fn build_webauthn(
    rp_id: &str,
    rp_origin: &url::Url,
    rp_name: &str,
) -> Result<Webauthn, IssuerdError> {
    WebauthnBuilder::new(rp_id, rp_origin)
        .and_then(|builder| builder.rp_name(rp_name).build())
        .map_err(|e| {
            IssuerdError::ServerError(format!(
                "invalid WebAuthn relying-party configuration: {e:?}"
            ))
        })
}

/// Derive the relying-party id and origin from the configured issuer URL.
///
/// The rp_id is the issuer's host; the origin is the issuer URL itself (path
/// components are ignored by `webauthn-rs`, which only compares scheme, host
/// and port).
pub fn relying_party_from_issuer(issuer_url: &str) -> Result<(String, url::Url), IssuerdError> {
    let origin = url::Url::parse(issuer_url).map_err(|e| {
        IssuerdError::InvalidRequest(format!("issuer_url is not an absolute URL: {e}"))
    })?;
    let rp_id = origin
        .host_str()
        .ok_or_else(|| IssuerdError::InvalidRequest("issuer_url has no host".to_string()))?
        .to_string();
    Ok((rp_id, origin))
}

/// Deterministic WebAuthn user handle for a user id (UUID v5 over a fixed
/// namespace) so registration and authentication derive the same handle.
pub fn user_handle(user_id: &UserId) -> uuid::Uuid {
    uuid::Uuid::new_v5(&USER_HANDLE_NAMESPACE, user_id.as_ref().as_bytes())
}

/// Serialize a passkey for storage in `Credential.secret_data`.
pub fn passkey_to_bytes(passkey: &Passkey) -> Result<Vec<u8>, IssuerdError> {
    serde_json::to_vec(passkey)
        .map_err(|e| IssuerdError::ServerError(format!("failed to serialize passkey: {e}")))
}

/// Deserialize a passkey from `Credential.secret_data`.
pub fn passkey_from_bytes(data: &[u8]) -> Result<Passkey, IssuerdError> {
    serde_json::from_slice(data)
        .map_err(|e| IssuerdError::InvalidRequest(format!("invalid stored passkey: {e}")))
}

/// Cache key holding the in-flight authentication ceremony state.
fn auth_ceremony_key(realm_id: &RealmId, user_id: &UserId) -> String {
    format!("webauthn-auth:{realm_id}:{user_id}")
}

/// Human RP name for a realm (display name when set, else the realm name).
fn rp_name(realm: &Realm) -> &str {
    realm.display_name.as_ref().map(|d| d.as_str()).unwrap_or(realm.name.as_str())
}

/// Conditional second-factor authenticator for users with a registered
/// passkey.
///
/// Contract (mirrors the OTP stage):
///
/// - No user in context, the `second_factor_ok` attribute set (OTP already
///   satisfied this login), a missing realm, or no WebAuthn credentials →
///   `Attempted` (pass-through; the stage is gated by the
///   conditional-user-configured condition).
/// - No `webauthn_assertion` parameter → fresh authentication options are
///   generated, the ceremony state is cached, and a
///   [`Challenge::WebAuthn`] carrying the options JSON is returned.
/// - A `webauthn_assertion` parameter → the cached ceremony state is consumed
///   and the assertion verified. On success the credential counters are
///   persisted and the stage succeeds. A bad/expired/missing state or an
///   invalid assertion is NEVER a `Failure` — conditional-stage failures are
///   swallowed by the executor, which would bypass the second factor — the
///   stage re-challenges with fresh options instead.
pub struct WebAuthnAuthenticator {
    storage: Arc<dyn Storage>,
    cache: Arc<dyn DistributedCache>,
    rp_id: String,
    rp_origin: url::Url,
}

impl WebAuthnAuthenticator {
    pub fn new(
        storage: Arc<dyn Storage>,
        cache: Arc<dyn DistributedCache>,
        rp_id: String,
        rp_origin: url::Url,
    ) -> Self {
        Self {
            storage,
            cache,
            rp_id,
            rp_origin,
        }
    }

    /// Load the user's WebAuthn credentials with their deserialized passkeys.
    /// Corrupt entries are skipped (logged) so one bad row cannot lock the
    /// user out of their other passkeys.
    async fn load_passkeys(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<(Credential, Passkey)>, IssuerdError> {
        let creds = self
            .storage
            .get_credentials(realm_id, user_id, CredentialType::WebAuthn)
            .await?;
        let mut out = Vec::with_capacity(creds.len());
        for cred in creds {
            match passkey_from_bytes(&cred.secret_data) {
                Ok(passkey) => out.push((cred, passkey)),
                Err(e) => {
                    warn!(realm = %realm_id, user = %user_id, error = %e, "skipping corrupt passkey credential")
                }
            }
        }
        Ok(out)
    }

    /// Issue fresh authentication options and cache the ceremony state.
    async fn challenge(
        &self,
        realm: &Realm,
        user_id: &UserId,
        stored: &[(Credential, Passkey)],
    ) -> AuthStepResult {
        let webauthn = match build_webauthn(&self.rp_id, &self.rp_origin, rp_name(realm)) {
            Ok(w) => w,
            Err(e) => return AuthStepResult::Failure(e),
        };
        let passkeys: Vec<Passkey> = stored.iter().map(|(_, p)| p.clone()).collect();
        let (rcr, ceremony) = match webauthn.start_passkey_authentication(&passkeys) {
            Ok(v) => v,
            Err(e) => {
                return AuthStepResult::Failure(IssuerdError::ServerError(format!(
                    "failed to start WebAuthn authentication: {e:?}"
                )))
            }
        };
        let state_bytes = match serde_json::to_vec(&ceremony) {
            Ok(b) => b,
            Err(e) => {
                return AuthStepResult::Failure(IssuerdError::ServerError(format!(
                    "failed to serialize WebAuthn ceremony state: {e}"
                )))
            }
        };
        if let Err(e) = self
            .cache
            .set(
                &auth_ceremony_key(&realm.id, user_id),
                state_bytes,
                Some(Duration::from_secs(AUTH_CEREMONY_TTL_SECS)),
            )
            .await
        {
            return AuthStepResult::Failure(e);
        }
        let options = match serde_json::to_string(&rcr.public_key) {
            Ok(o) => o,
            Err(e) => {
                return AuthStepResult::Failure(IssuerdError::ServerError(format!(
                    "failed to serialize WebAuthn options: {e}"
                )))
            }
        };
        AuthStepResult::Challenge(Challenge::WebAuthn {
            action_url: String::new(),
            challenge: options,
        })
    }

    /// Verify a submitted assertion against the cached ceremony state. Any
    /// failure re-challenges with fresh options (never `Failure`).
    async fn verify_assertion(
        &self,
        realm: &Realm,
        user_id: &UserId,
        stored: &[(Credential, Passkey)],
        assertion_json: &str,
    ) -> AuthStepResult {
        let key = auth_ceremony_key(&realm.id, user_id);
        // The state is single-use: consumed whether or not the assertion
        // verifies, so a rejected assertion cannot be replayed.
        let state_bytes = match self.cache.get_and_delete(&key).await {
            Ok(Some(b)) => b,
            _ => {
                warn!(realm = %realm.id, user = %user_id, "webauthn ceremony state missing or expired");
                return self.challenge(realm, user_id, stored).await;
            }
        };
        let parsed =
            (|| -> Result<(PublicKeyCredential, PasskeyAuthentication), serde_json::Error> {
                let credential: PublicKeyCredential = serde_json::from_str(assertion_json)?;
                let ceremony: PasskeyAuthentication = serde_json::from_slice(&state_bytes)?;
                Ok((credential, ceremony))
            })();
        let (credential, ceremony) = match parsed {
            Ok(v) => v,
            Err(e) => {
                warn!(realm = %realm.id, user = %user_id, error = %e, "unparsable webauthn assertion or state");
                return self.challenge(realm, user_id, stored).await;
            }
        };
        let webauthn = match build_webauthn(&self.rp_id, &self.rp_origin, rp_name(realm)) {
            Ok(w) => w,
            Err(e) => return AuthStepResult::Failure(e),
        };
        match webauthn.finish_passkey_authentication(&credential, &ceremony) {
            Ok(result) => {
                // Persist updated authenticator properties (signature counter,
                // backup flags) on the matched credential before succeeding —
                // like the OTP replay watermark, a persistence failure fails
                // the stage rather than silently dropping the update.
                for (cred, passkey) in stored {
                    let mut updated_passkey = passkey.clone();
                    if updated_passkey.update_credential(&result) != Some(true) {
                        continue;
                    }
                    let mut updated = cred.clone();
                    match passkey_to_bytes(&updated_passkey) {
                        Ok(bytes) => updated.secret_data = bytes,
                        Err(e) => return AuthStepResult::Failure(e),
                    }
                    if let Err(e) =
                        self.storage.update_credential(&realm.id, user_id, &updated).await
                    {
                        return AuthStepResult::Failure(e);
                    }
                }
                AuthStepResult::Success
            }
            Err(e) => {
                warn!(realm = %realm.id, user = %user_id, error = %e, "webauthn assertion rejected");
                self.challenge(realm, user_id, stored).await
            }
        }
    }
}

#[async_trait]
impl issuerd_core::Authenticator for WebAuthnAuthenticator {
    fn id(&self) -> &str {
        "auth-webauthn"
    }

    fn display_name(&self) -> &str {
        "WebAuthn Authenticator"
    }

    fn requires_user(&self) -> bool {
        true
    }

    fn configured_for(&self, context: &AuthContext) -> bool {
        // Best-effort sync check; full check happens in authenticate
        context.user_id.is_some()
    }

    #[instrument(skip(self, context), fields(authenticator = %self.id(), realm = %context.realm_id))]
    async fn authenticate(&self, context: &mut AuthContext) -> AuthStepResult {
        let user_id = match context.user_id {
            Some(ref id) => id.clone(),
            None => return AuthStepResult::Attempted,
        };

        // OTP already satisfied the second factor for this login (users with
        // both credential types are challenged for OTP first by flow order).
        if context.attributes.contains_key("second_factor_ok") {
            return AuthStepResult::Attempted;
        }

        // A missing realm degrades to pass-through instead of failing: at a
        // Conditional flow stage the executor swallows failures
        // (skip_conditional_scope), so a Failure here would let the login
        // succeed WITHOUT a second factor.
        let realm = match self.storage.get_realm(&context.realm_id).await {
            Ok(Some(realm)) => realm,
            Ok(None) => return AuthStepResult::Attempted,
            Err(e) => return AuthStepResult::Failure(e),
        };

        let stored = match self.load_passkeys(&context.realm_id, &user_id).await {
            Ok(s) => s,
            Err(e) => return AuthStepResult::Failure(e),
        };
        if stored.is_empty() {
            return AuthStepResult::Attempted;
        }

        if let Some(assertion) =
            context.parameters.get("webauthn_assertion").and_then(|v| v.first()).cloned()
        {
            return self.verify_assertion(&realm, &user_id, &stored, &assertion).await;
        }

        self.challenge(&realm, &user_id, &stored).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::Engine;
    use issuerd_core::{Authenticator, CredentialId, RealmName};
    use ring::signature::KeyPair as _;

    use super::*;

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const RP_ID: &str = "localhost";
    const ORIGIN: &str = "http://localhost:8080";

    fn rp_origin() -> url::Url {
        url::Url::parse(ORIGIN).unwrap()
    }

    fn test_realm() -> Realm {
        Realm {
            id: RealmId::new("realm-1").unwrap(),
            name: RealmName::new("realm-1").unwrap(),
            display_name: None,
            enabled: true,
            ..Default::default()
        }
    }

    fn test_context(user_id: Option<&str>) -> AuthContext {
        AuthContext {
            realm_id: test_realm().id,
            client_id: None,
            user_id: user_id.map(|u| UserId::new(u).unwrap()),
            session_id: None,
            ip_address: None,
            parameters: HashMap::new(),
            attributes: HashMap::new(),
            current_challenge: None,
        }
    }

    // -----------------------------------------------------------------------
    // Minimal soft authenticator ("none" attestation + real ES256 signatures)
    //
    // The soft-token crate (webauthn-authenticator-rs) cannot build on every
    // dev host (openssl), so the ceremonies below run against a hand-rolled
    // RFC-conformant authenticator instead. Registration uses "none"
    // attestation (no signature needed); assertions are genuinely signed and
    // verified by webauthn-rs.
    // -----------------------------------------------------------------------

    struct SoftKey {
        pkcs8: Vec<u8>,
        cred_id: Vec<u8>,
        counter: u32,
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
    }

    fn cose_ec2_key_cbor(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut out = vec![0xA5]; // map(5)
        out.extend([0x01, 0x02]); // 1: 2 (kty EC2)
        out.extend([0x03, 0x26]); // 3: -7 (ES256)
        out.extend([0x20, 0x01]); // -1: 1 (P-256)
        out.push(0x21); // -2: x
        out.extend([0x58, 0x20]); // bytes(32)
        out.extend_from_slice(x);
        out.push(0x22); // -3: y
        out.extend([0x58, 0x20]);
        out.extend_from_slice(y);
        out
    }

    fn none_attestation_object(auth_data: &[u8]) -> Vec<u8> {
        assert!(auth_data.len() < 256);
        let mut out = vec![0xA3]; // map(3)
        out.push(0x63); // text(3)
        out.extend(b"fmt");
        out.push(0x64); // text(4)
        out.extend(b"none");
        out.push(0x67); // text(7)
        out.extend(b"attStmt");
        out.push(0xA0); // empty map
        out.push(0x68); // text(8)
        out.extend(b"authData");
        out.extend([0x58, auth_data.len() as u8]); // bytes(n), n < 256
        out.extend_from_slice(auth_data);
        out
    }

    fn client_data_json(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": kind,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        }))
        .unwrap()
    }

    /// Run a genuine registration ceremony against the localhost RP and
    /// return the soft key plus the verified passkey.
    fn register_soft_key(user_id: &UserId) -> (SoftKey, Passkey) {
        let webauthn = build_webauthn(RP_ID, &rp_origin(), "Test").unwrap();
        let (ccr, state) = webauthn
            .start_passkey_registration(user_handle(user_id), "alice", "Alice", None)
            .unwrap();
        let options = serde_json::to_value(&ccr.public_key).unwrap();
        let challenge = options["challenge"].as_str().unwrap();

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let public_key = key_pair.public_key().as_ref();
        assert_eq!(public_key.len(), 65, "expected uncompressed P-256 point");
        let (x, y) = (&public_key[1..33], &public_key[33..65]);

        let cred_id: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(1)).collect();
        let mut auth_data = sha256(RP_ID.as_bytes());
        auth_data.push(0x45); // user present | user verified | attested data
        auth_data.extend([0, 0, 0, 0]); // counter 0
        auth_data.extend([0u8; 16]); // zero AAGUID
        auth_data.extend([0, 32]); // credential id length (u16 BE)
        auth_data.extend(&cred_id);
        auth_data.extend(cose_ec2_key_cbor(x, y));

        let attestation = none_attestation_object(&auth_data);
        let client_data = client_data_json("webauthn.create", challenge, ORIGIN);
        let reg: webauthn_rs::prelude::RegisterPublicKeyCredential =
            serde_json::from_value(serde_json::json!({
                "id": B64.encode(&cred_id),
                "rawId": B64.encode(&cred_id),
                "response": {
                    "attestationObject": B64.encode(&attestation),
                    "clientDataJSON": B64.encode(&client_data),
                },
                "type": "public-key",
            }))
            .unwrap();
        let passkey = webauthn.finish_passkey_registration(&reg, &state).unwrap();
        (
            SoftKey {
                pkcs8: pkcs8.as_ref().to_vec(),
                cred_id,
                counter: 0,
            },
            passkey,
        )
    }

    /// Produce a genuine ES256-signed assertion for the given request options.
    fn sign_assertion(key: &mut SoftKey, options: &serde_json::Value) -> serde_json::Value {
        let challenge = options["challenge"].as_str().unwrap();
        let rp_id = options["rpId"].as_str().unwrap();
        let client_data = client_data_json("webauthn.get", challenge, ORIGIN);
        key.counter += 1;
        let mut auth_data = sha256(rp_id.as_bytes());
        auth_data.push(0x05); // user present | user verified
        auth_data.extend(key.counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend(sha256(&client_data));

        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &key.pkcs8,
            &rng,
        )
        .unwrap();
        let signature = key_pair.sign(&rng, &signed).unwrap();

        serde_json::json!({
            "id": B64.encode(&key.cred_id),
            "rawId": B64.encode(&key.cred_id),
            "response": {
                "authenticatorData": B64.encode(&auth_data),
                "clientDataJSON": B64.encode(&client_data),
                "signature": B64.encode(signature.as_ref()),
                "userHandle": null,
            },
            "type": "public-key",
        })
    }

    /// In-memory storage with the realm and a WebAuthn credential for `user`.
    async fn storage_with_passkey(user: &UserId, passkey: &Passkey) -> Arc<dyn Storage> {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let realm = test_realm();
        storage.create_realm(&realm).await.unwrap();
        let cred = Credential {
            id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: CredentialType::WebAuthn,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: passkey_to_bytes(passkey).unwrap(),
            credential_data: serde_json::json!({"cred_id": "test"}),
            priority: 0,
        };
        storage.create_credential(&realm.id, user, &cred).await.unwrap();
        storage
    }

    fn authenticator(storage: Arc<dyn Storage>) -> WebAuthnAuthenticator {
        WebAuthnAuthenticator::new(
            storage,
            Arc::new(issuerd_cluster::InMemoryCache::new()),
            RP_ID.to_string(),
            rp_origin(),
        )
    }

    fn assert_challenge_options(result: AuthStepResult) -> serde_json::Value {
        match result {
            AuthStepResult::Challenge(Challenge::WebAuthn { challenge, .. }) => {
                let options: serde_json::Value = serde_json::from_str(&challenge)
                    .expect("challenge must carry parseable options JSON");
                assert!(options["challenge"].is_string(), "options must carry a challenge");
                assert!(options["allowCredentials"].is_array(), "options must allow credentials");
                options
            }
            other => panic!("expected WebAuthn challenge, got {other:?}"),
        }
    }

    #[test]
    fn user_handle_is_deterministic() {
        let alice = UserId::new("alice").unwrap();
        let bob = UserId::new("bob").unwrap();
        assert_eq!(user_handle(&alice), user_handle(&alice));
        assert_ne!(user_handle(&alice), user_handle(&bob));
        assert_eq!(user_handle(&alice).get_version_num(), 5);
    }

    #[test]
    fn build_webauthn_rejects_rp_mismatch() {
        let origin = rp_origin();
        assert!(build_webauthn("example.com", &origin, "Test").is_err());
        assert!(build_webauthn(RP_ID, &origin, "Test").is_ok());
    }

    #[test]
    fn relying_party_from_issuer_extracts_host() {
        let (rp_id, origin) =
            relying_party_from_issuer("https://idm.example.com:8443/realms/x").unwrap();
        assert_eq!(rp_id, "idm.example.com");
        assert_eq!(origin.host_str(), Some("idm.example.com"));
        assert!(relying_party_from_issuer("not a url").is_err());
    }

    #[test]
    fn passkey_serde_roundtrip() {
        let user = UserId::new("alice").unwrap();
        let (_key, passkey) = register_soft_key(&user);
        let bytes = passkey_to_bytes(&passkey).unwrap();
        let restored = passkey_from_bytes(&bytes).unwrap();
        assert_eq!(restored, passkey);
        assert!(passkey_from_bytes(b"not json").is_err());
    }

    #[tokio::test]
    async fn no_user_is_attempted() {
        let auth = authenticator(Arc::new(issuerd_storage::InMemoryStorage::new()));
        let mut ctx = test_context(None);
        assert!(matches!(auth.authenticate(&mut ctx).await, AuthStepResult::Attempted));
    }

    #[tokio::test]
    async fn second_factor_marker_is_attempted() {
        let user = UserId::new("alice").unwrap();
        let (_key, passkey) = register_soft_key(&user);
        let auth = authenticator(storage_with_passkey(&user, &passkey).await);
        let mut ctx = test_context(Some("alice"));
        ctx.attributes.insert("second_factor_ok".to_string(), "true".to_string());
        assert!(matches!(auth.authenticate(&mut ctx).await, AuthStepResult::Attempted));
    }

    #[tokio::test]
    async fn user_without_credentials_is_attempted() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        storage.create_realm(&test_realm()).await.unwrap();
        let auth = authenticator(storage);
        let mut ctx = test_context(Some("alice"));
        assert!(matches!(auth.authenticate(&mut ctx).await, AuthStepResult::Attempted));
    }

    #[tokio::test]
    async fn missing_realm_is_attempted() {
        // Storage has a credential but no realm row.
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let user = UserId::new("alice").unwrap();
        let (_key, passkey) = register_soft_key(&user);
        let cred = Credential {
            id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: CredentialType::WebAuthn,
            user_label: None,
            created_date: chrono::Utc::now(),
            secret_data: passkey_to_bytes(&passkey).unwrap(),
            credential_data: serde_json::json!({}),
            priority: 0,
        };
        storage.create_credential(&test_realm().id, &user, &cred).await.unwrap();
        let auth = authenticator(storage);
        let mut ctx = test_context(Some("alice"));
        assert!(matches!(auth.authenticate(&mut ctx).await, AuthStepResult::Attempted));
    }

    #[tokio::test]
    async fn credentials_without_assertion_challenge() {
        let user = UserId::new("alice").unwrap();
        let (key, passkey) = register_soft_key(&user);
        let auth = authenticator(storage_with_passkey(&user, &passkey).await);
        let mut ctx = test_context(Some("alice"));
        let options = assert_challenge_options(auth.authenticate(&mut ctx).await);
        assert_eq!(options["rpId"], RP_ID);
        assert_eq!(options["userVerification"], "required");
        let allowed = options["allowCredentials"].as_array().unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0]["id"], B64.encode(&key.cred_id));

        // The ceremony state was cached for the resume.
        let cached = auth.cache.get(&auth_ceremony_key(&test_realm().id, &user)).await.unwrap();
        assert!(cached.is_some());
    }

    #[tokio::test]
    async fn bad_assertion_json_rechallenges() {
        let user = UserId::new("alice").unwrap();
        let (_key, passkey) = register_soft_key(&user);
        let auth = authenticator(storage_with_passkey(&user, &passkey).await);
        let mut ctx = test_context(Some("alice"));
        ctx.parameters
            .insert("webauthn_assertion".to_string(), vec!["not json".to_string()]);
        // No ceremony state cached → fresh options, never a Failure.
        assert_challenge_options(auth.authenticate(&mut ctx).await);
    }

    #[tokio::test]
    async fn tampered_assertion_rechallenges_and_consumes_state() {
        let user = UserId::new("alice").unwrap();
        let (mut key, passkey) = register_soft_key(&user);
        let auth = authenticator(storage_with_passkey(&user, &passkey).await);
        let mut ctx = test_context(Some("alice"));

        // Get options + cached state, then corrupt the signature.
        let options = assert_challenge_options(auth.authenticate(&mut ctx).await);
        let mut assertion = sign_assertion(&mut key, &options);
        assertion["response"]["signature"] = serde_json::json!(B64.encode([0u8; 70]));
        ctx.parameters.insert(
            "webauthn_assertion".to_string(),
            vec![serde_json::to_string(&assertion).unwrap()],
        );
        // Bad signature → fresh challenge, and the old state was consumed.
        assert_challenge_options(auth.authenticate(&mut ctx).await);
    }

    #[tokio::test]
    async fn full_ceremony_succeeds_and_persists_counter() {
        let user = UserId::new("alice").unwrap();
        let (mut key, passkey) = register_soft_key(&user);
        let storage = storage_with_passkey(&user, &passkey).await;
        let auth = authenticator(storage.clone());
        let mut ctx = test_context(Some("alice"));

        // Step 1: challenge.
        let options = assert_challenge_options(auth.authenticate(&mut ctx).await);

        // Step 2: genuine assertion → Success, counter persisted.
        let assertion = sign_assertion(&mut key, &options);
        ctx.parameters.insert(
            "webauthn_assertion".to_string(),
            vec![serde_json::to_string(&assertion).unwrap()],
        );
        assert!(matches!(auth.authenticate(&mut ctx).await, AuthStepResult::Success));

        let creds = storage
            .get_credentials(&test_realm().id, &user, CredentialType::WebAuthn)
            .await
            .unwrap();
        assert_eq!(creds.len(), 1);
        let stored: serde_json::Value = serde_json::from_slice(&creds[0].secret_data).unwrap();
        // Passkey serializes nested: {"cred": {..., "counter": n, ...}}.
        assert_eq!(stored["cred"]["counter"], 1, "authenticator counter must be persisted");

        // The ceremony state was consumed: re-submitting the same assertion
        // re-challenges instead of succeeding twice.
        assert_challenge_options(auth.authenticate(&mut ctx).await);
    }
}
