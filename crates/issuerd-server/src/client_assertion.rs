// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// JWT client authentication (private_key_jwt / client_secret_jwt) per RFC 7523 and OIDC Core.

//! JWT client authentication (`private_key_jwt` / `client_secret_jwt`) per
//! RFC 7523 §2.2 and OIDC Core §9.
//!
//! [`verify_client_auth`] is the single client-credential check for every
//! client-authenticated form endpoint (token, PAR, revoke, introspect). It
//! dispatches on the client's configured `client_authenticator_type`
//! (Keycloak spellings `client-secret` / `client-jwt` / `client-secret-jwt`):
//! a client pinned to a JWT method is rejected when it presents anything else,
//! and vice versa.
//!
//! Assertion validation itself is pure and lives in
//! [`issuerd_token::client_assertion`]; this module adds the stateful parts:
//! - resolving the client's verification JWKS from its attributes (Keycloak
//!   spellings `use.jwks.string`+`jwks.string` for an inline set, or
//!   `use.jwks.url`+`jwks.url` fetched over HTTP, cached per client for
//!   [`JWKS_CACHE_TTL_SECS`] with one refetch-on-kid-miss retry — the
//!   broker JWKS cache pattern — rate-limited per client by the
//!   `client_jwks_kid_miss:{realm_id}:{client_id}` cooldown marker so an
//!   unauthenticated unknown-`kid` flood cannot force an outbound fetch on
//!   every request), and
//! - `jti` single-use enforcement in the distributed cache
//!   (`client_assertion_jti:{realm_id}:{client_id}:{jti}`, TTL = remaining
//!   assertion lifetime + [`ASSERTION_LEEWAY_SECS`], so the marker outlives
//!   the window in which the assertion is still accepted) via the atomic
//!   cache `increment`.

use std::collections::HashMap;

use issuerd_core::{Client, ClientAuthenticatorType, IssuerdError, RealmId};
use tracing::{debug, warn};

use crate::state::ServerState;

/// Client attribute (`"true"`): the client's JWKS is stored inline in
/// [`ATTR_JWKS_STRING`]. Keycloak spelling (`OIDCAdvancedConfigWrapper`).
pub(crate) const ATTR_USE_JWKS_STRING: &str = "use.jwks.string";
/// Client attribute holding the inline JWKS document (JSON text).
pub(crate) const ATTR_JWKS_STRING: &str = "jwks.string";
/// Client attribute (`"true"`): fetch the client's JWKS from
/// [`ATTR_JWKS_URL`] over HTTP.
pub(crate) const ATTR_USE_JWKS_URL: &str = "use.jwks.url";
/// Client attribute holding the URL the client's JWKS is fetched from.
pub(crate) const ATTR_JWKS_URL: &str = "jwks.url";

/// How long a fetched client JWKS stays cached per (realm, client).
const JWKS_CACHE_TTL_SECS: u64 = 300;
/// Clock-skew leeway for assertion `exp`/`iat` checks.
const ASSERTION_LEEWAY_SECS: u64 = 60;
/// Maximum assertion lifetime (now → `exp`). Bounds the replay-cache TTL;
/// matches Keycloak's default `maxExp` for JWT client authentication.
const MAX_ASSERTION_LIFETIME_SECS: u64 = 300;
/// Cooldown between forced kid-miss JWKS refetches per (realm, client).
/// Without it, any unauthenticated request carrying an unknown `kid` would
/// trigger a live outbound GET to the client's `jwks.url`.
const KID_MISS_REFETCH_COOLDOWN_SECS: u64 = 60;

fn jwks_cache_key(realm_id: &RealmId, client_id: &issuerd_core::ClientId) -> String {
    format!("client_jwks:{}:{}", realm_id.0, client_id.0)
}

/// Cooldown marker for the kid-miss forced JWKS refetch (one refetch per
/// client per [`KID_MISS_REFETCH_COOLDOWN_SECS`]).
fn jwks_kid_miss_key(realm_id: &RealmId, client_id: &issuerd_core::ClientId) -> String {
    format!("client_jwks_kid_miss:{}:{}", realm_id.0, client_id.0)
}

/// `jti` replay markers are scoped per client: RFC 7523 §3 requires `jti`
/// uniqueness per issuer (client) only, so a global key would let one client
/// burn another's `jti` values.
fn jti_cache_key(realm_id: &RealmId, client_id: &issuerd_core::ClientId, jti: &str) -> String {
    format!("client_assertion_jti:{}:{}:{jti}", realm_id.0, client_id.0)
}

fn unauthorized(reason: &str) -> IssuerdError {
    // The specific reason goes to the log; the endpoint answers a uniform
    // `invalid_client` (token endpoint: 400, the others: 401 — their
    // pre-existing shapes are unchanged).
    debug!(reason, "client authentication failed");
    IssuerdError::UnauthorizedClient
}

/// Authenticate a confidential client on a form-posted endpoint. `params` are
/// the merged form parameters (Basic-auth credentials already folded in by
/// the caller). Failures map to `IssuerdError::UnauthorizedClient`; each endpoint
/// renders its own `invalid_client` response shape.
pub(crate) async fn verify_client_auth(
    state: &ServerState,
    realm_id: &RealmId,
    realm_name: &str,
    client: &Client,
    params: &HashMap<String, String>,
) -> Result<(), IssuerdError> {
    // RFC 6749 §2.3: the client MUST NOT use more than one authentication
    // method in each request.
    let has_secret = params.get("client_secret").is_some_and(|s| !s.is_empty());
    let has_assertion = params.get("client_assertion").is_some_and(|s| !s.is_empty());
    if has_secret && has_assertion {
        return Err(unauthorized("client_secret and client_assertion are mutually exclusive"));
    }

    match client.client_authenticator_type {
        ClientAuthenticatorType::ClientJwt | ClientAuthenticatorType::ClientSecretJwt => {
            let claims = validate_assertion(state, realm_id, realm_name, client, params).await?;
            enforce_jti_single_use(state, realm_id, &client.id, &claims).await
        }
        // `client-x509` is not implemented; it keeps the pre-24.2 behavior of
        // falling back to the shared-secret check.
        ClientAuthenticatorType::ClientSecret | ClientAuthenticatorType::ClientX509 => {
            verify_client_secret(client, params)
        }
    }
}

/// The pre-24.2 credential check: shared secret, constant-time comparison.
fn verify_client_secret(
    client: &Client,
    params: &HashMap<String, String>,
) -> Result<(), IssuerdError> {
    let provided = params.get("client_secret").map(String::as_str).unwrap_or("");
    let expected = client.secret.as_deref().unwrap_or("");
    let secrets_match: bool =
        subtle::ConstantTimeEq::ct_eq(provided.as_bytes(), expected.as_bytes()).into();
    if provided.is_empty() || !secrets_match {
        return Err(unauthorized("client secret mismatch"));
    }
    Ok(())
}

/// Validate the `client_assertion` parameter against the client's configured
/// JWT method and return the verified claims (the caller enforces `jti`
/// single-use).
async fn validate_assertion(
    state: &ServerState,
    realm_id: &RealmId,
    realm_name: &str,
    client: &Client,
    params: &HashMap<String, String>,
) -> Result<issuerd_token::ClientAssertionClaims, IssuerdError> {
    let assertion_type = params.get("client_assertion_type").map(String::as_str);
    if assertion_type != Some(issuerd_protocol::token::CLIENT_ASSERTION_TYPE_JWT_BEARER) {
        return Err(unauthorized("unsupported or missing client_assertion_type"));
    }
    let assertion = params
        .get("client_assertion")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| unauthorized("client_assertion missing"))?;

    // RFC 7523 §3 + RFC 9126 §2: aud must name the authorization server —
    // the realm issuer (realm-NAME based) or one of the assertion-accepting
    // endpoint URLs.
    let realm_base =
        format!("{}/realms/{}", state.config.issuer_url.trim_end_matches('/'), realm_name);
    let accepted = vec![
        realm_base.clone(),
        format!("{realm_base}/protocol/openid-connect/token"),
        format!("{realm_base}/protocol/openid-connect/ext/par"),
    ];
    let requirements = issuerd_token::ClientAssertionRequirements {
        expected_client_id: client.client_id.as_str(),
        accepted_audiences: &accepted,
        leeway_secs: ASSERTION_LEEWAY_SECS,
        max_lifetime_secs: MAX_ASSERTION_LIFETIME_SECS,
    };

    match client.client_authenticator_type {
        ClientAuthenticatorType::ClientSecretJwt => {
            let secret = client.secret.as_deref().ok_or_else(|| {
                unauthorized("client pinned to client-secret-jwt has no secret configured")
            })?;
            issuerd_token::validate_client_secret_assertion(assertion, secret, &requirements)
                .map_err(|e| {
                    debug!(client_id = %client.client_id, error = %e, "client assertion validation failed");
                    e
                })
        }
        ClientAuthenticatorType::ClientJwt => {
            validate_private_key(state, realm_id, client, assertion, &requirements).await
        }
        // Unreachable: the caller dispatches JWT methods only.
        other => Err(unauthorized(match other {
            ClientAuthenticatorType::ClientSecret => "client is pinned to client-secret",
            ClientAuthenticatorType::ClientX509 => "client is pinned to client-x509",
            ClientAuthenticatorType::ClientJwt | ClientAuthenticatorType::ClientSecretJwt => {
                "unreachable"
            }
        })),
    }
}

/// The client's inline JWKS document (`use.jwks.string` + `jwks.string`,
/// Keycloak spellings), if configured. `Ok(None)` when no inline JWKS is
/// configured; `Err` when configured but missing/malformed. Shared with the
/// JAR validator, which verifies Request Objects against the
/// same material.
pub(crate) fn inline_client_jwks(
    client: &Client,
) -> Result<Option<serde_json::Value>, IssuerdError> {
    if client.attributes.get(ATTR_USE_JWKS_STRING).is_none_or(|v| v != "true") {
        return Ok(None);
    }
    let raw = client.attributes.get(ATTR_JWKS_STRING).ok_or_else(|| {
        IssuerdError::InvalidRequest("use.jwks.string is true but jwks.string is not set".into())
    })?;
    let jwks = serde_json::from_str(raw).map_err(|_| {
        IssuerdError::InvalidRequest("jwks.string is not a valid JSON JWKS document".into())
    })?;
    Ok(Some(jwks))
}

/// The URL the client's JWKS is fetched from (`use.jwks.url` + `jwks.url`),
/// if configured. Shared with the JAR validator.
pub(crate) fn client_jwks_url(client: &Client) -> Result<Option<String>, IssuerdError> {
    if client.attributes.get(ATTR_USE_JWKS_URL).is_none_or(|v| v != "true") {
        return Ok(None);
    }
    let url = client.attributes.get(ATTR_JWKS_URL).ok_or_else(|| {
        IssuerdError::InvalidRequest("use.jwks.url is true but jwks.url is not set".into())
    })?;
    Ok(Some(url.clone()))
}

/// `private_key_jwt`: verify against the client's JWKS — inline
/// (`jwks.string`) or fetched (`jwks.url`, cached, one refetch-on-kid-miss
/// retry per [`KID_MISS_REFETCH_COOLDOWN_SECS`] so a client key rotation is
/// picked up quickly without letting unauthenticated unknown kids force an
/// outbound fetch on every request).
async fn validate_private_key(
    state: &ServerState,
    realm_id: &RealmId,
    client: &Client,
    assertion: &str,
    requirements: &issuerd_token::ClientAssertionRequirements<'_>,
) -> Result<issuerd_token::ClientAssertionClaims, IssuerdError> {
    // Inline JWKS wins when both sources are configured (Keycloak's
    // OIDCAdvancedConfigWrapper precedence).
    if let Some(jwks) = inline_client_jwks(client).map_err(|e| unauthorized(&e.to_string()))? {
        return issuerd_token::validate_private_key_assertion(assertion, &jwks, requirements)
            .map_err(|e| {
                debug!(client_id = %client.client_id, error = %e, "client assertion validation failed");
                e
            });
    }

    if let Some(url) = client_jwks_url(client).map_err(|e| unauthorized(&e.to_string()))? {
        let jwks = fetch_client_jwks(state, realm_id, &client.id, &url, false).await?;
        return match issuerd_token::validate_private_key_assertion(assertion, &jwks, requirements) {
            Ok(claims) => Ok(claims),
            Err(first_err) => {
                debug!(client_id = %client.client_id, error = %first_err, "client assertion validation against cached JWKS failed");
                // One refetch when the cached set does not cover the
                // assertion's kid (client rotated keys; broker JWKS cache
                // pattern).
                if issuerd_token::jwks_covers_assertion(&jwks, assertion) {
                    return Err(first_err);
                }
                // Rate-limit forced refetches per client: an unauthenticated
                // unknown kid must not trigger an outbound GET on every
                // request. On any cache error, fail toward fewer fetches.
                let miss_key = jwks_kid_miss_key(realm_id, &client.id);
                match state.cache.get(&miss_key).await {
                    Ok(Some(_)) => {
                        debug!(
                            client_id = %client.client_id,
                            "client JWKS kid-miss refetch still in cooldown; rejecting"
                        );
                        return Err(first_err);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(
                            realm = %realm_id,
                            error = %e,
                            "kid-miss cooldown lookup failed; skipping client JWKS refetch"
                        );
                        return Err(first_err);
                    }
                }
                debug!(
                    client_id = %client.client_id,
                    "cached client JWKS does not cover the assertion kid; refetching"
                );
                let fresh = fetch_client_jwks(state, realm_id, &client.id, &url, true).await?;
                if let Err(e) = state
                    .cache
                    .set(
                        &miss_key,
                        vec![1],
                        Some(std::time::Duration::from_secs(KID_MISS_REFETCH_COOLDOWN_SECS)),
                    )
                    .await
                {
                    warn!(realm = %realm_id, error = %e, "kid-miss cooldown marker not stored");
                }
                issuerd_token::validate_private_key_assertion(assertion, &fresh, requirements)
                    .map_err(|e| {
                        debug!(client_id = %client.client_id, error = %e, "client assertion validation against refetched JWKS failed");
                        e
                    })
            }
        };
    }

    Err(unauthorized("client pinned to client-jwt has no JWKS configured"))
}

/// Fetch the client JWKS through the per-(realm, client) cache.
/// `force_refresh` bypasses the cached copy (the one-shot kid-miss retry).
/// The HTTP GET rides the broker client abstraction so tests can
/// stub it and production gets the short-timeout reqwest client.
pub(crate) async fn fetch_client_jwks(
    state: &ServerState,
    realm_id: &RealmId,
    client_id: &issuerd_core::ClientId,
    jwks_url: &str,
    force_refresh: bool,
) -> Result<serde_json::Value, IssuerdError> {
    let cache_key = jwks_cache_key(realm_id, client_id);
    if !force_refresh {
        if let Ok(Some(bytes)) = state.cache.get(&cache_key).await {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                return Ok(json);
            }
        }
    }
    let json = state.broker_client.get_json(jwks_url).await?;
    if let Ok(bytes) = serde_json::to_vec(&json) {
        let _ = state
            .cache
            .set(&cache_key, bytes, Some(std::time::Duration::from_secs(JWKS_CACHE_TTL_SECS)))
            .await;
    }
    Ok(json)
}

/// Enforce `jti` single-use (OIDC Core §9 discourages assertion reuse; FAPI
/// requires rejecting it). The atomic cache `increment` creates the key with
/// the TTL on first use, so exactly one presentation of a `jti` succeeds.
/// The marker must outlive the window in which the assertion is accepted:
/// validation applies [`ASSERTION_LEEWAY_SECS`] of clock-skew leeway to `exp`,
/// so the TTL covers the remaining lifetime plus that leeway.
async fn enforce_jti_single_use(
    state: &ServerState,
    realm_id: &RealmId,
    client_id: &issuerd_core::ClientId,
    claims: &issuerd_token::ClientAssertionClaims,
) -> Result<(), IssuerdError> {
    let jti = claims
        .jti
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| unauthorized("client assertion missing jti"))?;
    let now = issuerd_core::utils::now_secs() as i64;
    let ttl = (claims.exp + ASSERTION_LEEWAY_SECS as i64).saturating_sub(now).max(1) as u64;
    let uses = state
        .cache
        .increment(
            &jti_cache_key(realm_id, client_id, jti),
            Some(std::time::Duration::from_secs(ttl)),
        )
        .await
        .map_err(|e| {
            // Fail closed: without the replay cache, single-use cannot be
            // guaranteed.
            warn!(realm = %realm_id, error = %e, "client assertion replay cache unavailable");
            IssuerdError::UnauthorizedClient
        })?;
    if uses != 1 {
        warn!(realm = %realm_id, "client assertion jti replayed");
        return Err(IssuerdError::UnauthorizedClient);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use issuerd_core::{
        ClientId, ClientIdentifier, ClientProtocol, CryptoProvider, DistributedCache, Scope,
    };
    use std::sync::Arc;

    const SECRET: &str = "s3cr3t";

    fn make_client(auth_type: ClientAuthenticatorType) -> Client {
        Client {
            id: ClientId::new("client-uuid-1").unwrap(),
            realm_id: RealmId::new("master").unwrap(),
            client_id: ClientIdentifier::new("jwt-test-client").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: auth_type,
            secret: Some(SECRET.to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn sign_hs256(claims: serde_json::Value, secret: &str) -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    /// Claims accepted by `ServerConfig::default()`'s issuer
    /// (`http://localhost:8080`) for the master realm.
    fn valid_claims(jti: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": "jwt-test-client",
            "sub": "jwt-test-client",
            "aud": "http://localhost:8080/realms/master/protocol/openid-connect/token",
            "exp": now() + 240,
            "iat": now(),
            "jti": jti,
        })
    }

    fn assertion_params(assertion: &str) -> HashMap<String, String> {
        HashMap::from([
            ("client_id".to_string(), "jwt-test-client".to_string()),
            (
                "client_assertion_type".to_string(),
                issuerd_protocol::token::CLIENT_ASSERTION_TYPE_JWT_BEARER.to_string(),
            ),
            ("client_assertion".to_string(), assertion.to_string()),
        ])
    }

    async fn test_state() -> Arc<ServerState> {
        Arc::new(ServerState::from_config(&ServerConfig::default()).await.unwrap())
    }

    /// Delegating cache that records every `increment` key/TTL, so tests can
    /// assert the replay-marker lifetime without sleeping.
    struct RecordingCache {
        inner: issuerd_cluster::InMemoryCache,
        increments: std::sync::Mutex<Vec<(String, Option<std::time::Duration>)>>,
    }

    impl RecordingCache {
        fn new() -> Self {
            Self {
                inner: issuerd_cluster::InMemoryCache::new(),
                increments: Default::default(),
            }
        }
    }

    impl Default for RecordingCache {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl DistributedCache for RecordingCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<std::time::Duration>,
        ) -> Result<(), IssuerdError> {
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), IssuerdError> {
            self.inner.delete(key).await
        }
        async fn compare_and_swap(
            &self,
            key: &str,
            expected: Option<Vec<u8>>,
            new: Vec<u8>,
        ) -> Result<bool, IssuerdError> {
            self.inner.compare_and_swap(key, expected, new).await
        }
        async fn increment(
            &self,
            key: &str,
            ttl: Option<std::time::Duration>,
        ) -> Result<u64, IssuerdError> {
            self.increments.lock().unwrap().push((key.to_string(), ttl));
            self.inner.increment(key, ttl).await
        }
        async fn publish(&self, channel: &str, message: Vec<u8>) -> Result<(), IssuerdError> {
            self.inner.publish(channel, message).await
        }
        async fn subscribe(
            &self,
            channel: &str,
            handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
        ) -> Result<(), IssuerdError> {
            self.inner.subscribe(channel, handler).await
        }
    }

    #[tokio::test]
    async fn secret_method_accepts_secret_and_rejects_assertion() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let client = make_client(ClientAuthenticatorType::ClientSecret);

        // Secret accepted.
        let params = HashMap::from([
            ("client_id".to_string(), "jwt-test-client".to_string()),
            ("client_secret".to_string(), SECRET.to_string()),
        ]);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_ok());

        // A client pinned to client-secret cannot authenticate with an
        // otherwise-valid assertion.
        let assertion = sign_hs256(valid_claims("jti-secret-pinned"), SECRET);
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_err());
    }

    #[tokio::test]
    async fn both_methods_in_one_request_rejected() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let client = make_client(ClientAuthenticatorType::ClientSecretJwt);
        let assertion = sign_hs256(valid_claims("jti-both"), SECRET);
        let mut params = assertion_params(&assertion);
        params.insert("client_secret".to_string(), SECRET.to_string());
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_err());
    }

    #[tokio::test]
    async fn secret_jwt_method_accepts_valid_assertion() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let client = make_client(ClientAuthenticatorType::ClientSecretJwt);
        let assertion = sign_hs256(valid_claims("jti-ok-1"), SECRET);
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_ok());
    }

    #[tokio::test]
    async fn secret_jwt_method_rejects_wrong_secret_and_bad_type() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let client = make_client(ClientAuthenticatorType::ClientSecretJwt);

        // Signed with a different secret.
        let assertion = sign_hs256(valid_claims("jti-bad-secret"), "wrong");
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_err());

        // Wrong client_assertion_type.
        let assertion = sign_hs256(valid_claims("jti-bad-type"), SECRET);
        let mut params = assertion_params(&assertion);
        params.insert("client_assertion_type".to_string(), "urn:other".to_string());
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_err());
    }

    #[tokio::test]
    async fn jti_replay_rejected() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let client = make_client(ClientAuthenticatorType::ClientSecretJwt);
        let assertion = sign_hs256(valid_claims("jti-replay-me"), SECRET);
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_ok());
        // Second presentation of the same assertion → replay.
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_err());
    }

    #[tokio::test]
    async fn missing_jti_rejected() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let client = make_client(ClientAuthenticatorType::ClientSecretJwt);
        let mut claims = valid_claims("jti-x");
        claims.as_object_mut().unwrap().remove("jti");
        let assertion = sign_hs256(claims, SECRET);
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_err());
    }

    #[tokio::test]
    async fn private_key_jwt_requires_configured_jwks() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        // Pinned to client-jwt but neither jwks.string nor jwks.url set.
        let client = make_client(ClientAuthenticatorType::ClientJwt);
        let assertion = sign_hs256(valid_claims("jti-no-jwks"), SECRET);
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_err());
    }

    #[tokio::test]
    async fn private_key_jwt_inline_jwks_roundtrip() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();

        let crypto = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
            default_alg: issuerd_core::Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwk_set = crypto.get_public_keys().await.unwrap();
        let kid = jwk_set.keys[0].kid.to_string();

        let mut client = make_client(ClientAuthenticatorType::ClientJwt);
        client.attributes.insert(ATTR_USE_JWKS_STRING.to_string(), "true".to_string());
        client
            .attributes
            .insert(ATTR_JWKS_STRING.to_string(), serde_json::to_string(&jwk_set).unwrap());

        let assertion = crypto
            .sign(
                &serde_json::to_string(&valid_claims("jti-inline")).unwrap(),
                issuerd_core::Algorithm::Rs256,
                &issuerd_core::KeyId::new(kid).unwrap(),
            )
            .await
            .unwrap();
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_ok());
    }

    #[tokio::test]
    async fn private_key_jwt_url_source_uses_broker_client() {
        // MockBrokerClient stubs the JWKS GET — proves fetch+cache wiring
        // without real HTTP (the loopback HTTP path is covered by the
        // integration tests).
        let crypto = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
            default_alg: issuerd_core::Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let jwks = serde_json::to_value(crypto.get_public_keys().await.unwrap()).unwrap();
        let kid = jwks["keys"][0]["kid"].as_str().unwrap().to_string();

        let mut broker = issuerd_core::MockBrokerClient::new();
        broker.expect_get_json().returning(move |_| Ok(jwks.clone()));

        let cfg = ServerConfig::default();
        let base = ServerState::from_config(&cfg).await.unwrap();
        let state = ServerState {
            broker_client: Arc::new(broker),
            ..base
        };

        let realm_id = RealmId::new("master").unwrap();
        let mut client = make_client(ClientAuthenticatorType::ClientJwt);
        client.attributes.insert(ATTR_USE_JWKS_URL.to_string(), "true".to_string());
        client
            .attributes
            .insert(ATTR_JWKS_URL.to_string(), "https://client.example.com/jwks".to_string());

        let assertion = crypto
            .sign(
                &serde_json::to_string(&valid_claims("jti-url")).unwrap(),
                issuerd_core::Algorithm::Rs256,
                &issuerd_core::KeyId::new(kid).unwrap(),
            )
            .await
            .unwrap();
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_ok());

        // The JWKS is now cached: subsequent assertions validate without
        // another fetch. Assert the cache entry directly (the mock is not
        // strict about call counts).
        assert!(state.cache.get(&jwks_cache_key(&realm_id, &client.id)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn jti_replay_marker_ttl_covers_leeway_window() {
        // valid_claims() expires 240s out; the assertion stays acceptable
        // until exp + ASSERTION_LEEWAY_SECS, so the replay marker must live
        // ~300s, not ~240s.
        let cache = Arc::new(RecordingCache::new());
        let base = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        let state = ServerState {
            cache: cache.clone(),
            ..base
        };
        let realm_id = RealmId::new("master").unwrap();
        let client = make_client(ClientAuthenticatorType::ClientSecretJwt);

        let assertion = sign_hs256(valid_claims("jti-ttl"), SECRET);
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_ok());

        let recorded = cache.increments.lock().unwrap();
        let (key, ttl) = recorded
            .iter()
            .find(|(k, _)| k.starts_with("client_assertion_jti:"))
            .expect("jti replay marker increment recorded");
        let ttl = ttl.expect("replay marker must carry a TTL").as_secs();
        let expected = 240 + ASSERTION_LEEWAY_SECS;
        // Allow a couple of seconds for the time between claim construction
        // and enforcement to tick over.
        assert!(
            (expected - 2..=expected).contains(&ttl),
            "replay marker TTL {ttl}s must cover the leeway window (~{expected}s)"
        );
        assert!(key.contains("client-uuid-1"), "replay marker key must be client-scoped: {key}");
    }

    #[tokio::test]
    async fn jti_replay_cache_scoped_per_client() {
        let state = test_state().await;
        let realm_id = RealmId::new("master").unwrap();
        let client_a = make_client(ClientAuthenticatorType::ClientSecretJwt);
        let mut client_b = make_client(ClientAuthenticatorType::ClientSecretJwt);
        client_b.id = ClientId::new("client-uuid-2").unwrap();
        client_b.client_id = ClientIdentifier::new("jwt-test-client-b").unwrap();

        let assertion_a = sign_hs256(valid_claims("jti-shared"), SECRET);
        let params_a = assertion_params(&assertion_a);
        assert!(verify_client_auth(&state, &realm_id, "master", &client_a, &params_a)
            .await
            .is_ok());

        // RFC 7523 §3 scopes jti uniqueness per issuer: the same jti from a
        // different client is not a replay.
        let mut claims_b = valid_claims("jti-shared");
        claims_b["iss"] = serde_json::json!("jwt-test-client-b");
        claims_b["sub"] = serde_json::json!("jwt-test-client-b");
        let assertion_b = sign_hs256(claims_b, SECRET);
        let mut params_b = assertion_params(&assertion_b);
        params_b.insert("client_id".to_string(), "jwt-test-client-b".to_string());
        assert!(verify_client_auth(&state, &realm_id, "master", &client_b, &params_b)
            .await
            .is_ok());

        // A second presentation by the same client still is a replay.
        assert!(verify_client_auth(&state, &realm_id, "master", &client_b, &params_b)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn kid_miss_jwks_refetch_rate_limited_per_client() {
        let signer = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
            default_alg: issuerd_core::Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let kid = signer.get_public_keys().await.unwrap().keys[0].kid.to_string();
        // The served JWKS comes from a different key pair, so the assertion's
        // kid is never covered and every presentation is a kid-miss.
        let other = issuerd_token::RingCryptoProvider::new(issuerd_token::CryptoConfig {
            default_alg: issuerd_core::Algorithm::Rs256,
            rsa_key_size: 2048,
        })
        .unwrap();
        let served_jwks = serde_json::to_value(other.get_public_keys().await.unwrap()).unwrap();
        let served_bytes = serde_json::to_vec(&served_jwks).unwrap();

        // Exactly one outbound fetch is allowed across both requests; mockall
        // verifies the call count when the mock drops.
        let mut broker = issuerd_core::MockBrokerClient::new();
        broker.expect_get_json().times(1).returning(move |_| Ok(served_jwks.clone()));

        let base = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        let state = ServerState {
            broker_client: Arc::new(broker),
            ..base
        };

        let realm_id = RealmId::new("master").unwrap();
        let mut client = make_client(ClientAuthenticatorType::ClientJwt);
        client.attributes.insert(ATTR_USE_JWKS_URL.to_string(), "true".to_string());
        client
            .attributes
            .insert(ATTR_JWKS_URL.to_string(), "https://client.example.com/jwks".to_string());

        // Pre-seed the JWKS cache so the only possible fetch is the kid-miss
        // refetch itself.
        state
            .cache
            .set(&jwks_cache_key(&realm_id, &client.id), served_bytes, None)
            .await
            .unwrap();

        // First unknown kid: validation fails against the cached set, the one
        // allowed refetch runs, and validation still fails.
        let assertion = signer
            .sign(
                &serde_json::to_string(&valid_claims("jti-miss-1")).unwrap(),
                issuerd_core::Algorithm::Rs256,
                &issuerd_core::KeyId::new(kid.clone()).unwrap(),
            )
            .await
            .unwrap();
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_err());
        assert!(
            state
                .cache
                .get(&jwks_kid_miss_key(&realm_id, &client.id))
                .await
                .unwrap()
                .is_some(),
            "the refetch must arm the cooldown marker"
        );

        // Second unknown kid inside the cooldown: rejected with no further
        // outbound fetch (the mock's times(1) would fail otherwise).
        let assertion = signer
            .sign(
                &serde_json::to_string(&valid_claims("jti-miss-2")).unwrap(),
                issuerd_core::Algorithm::Rs256,
                &issuerd_core::KeyId::new(kid).unwrap(),
            )
            .await
            .unwrap();
        let params = assertion_params(&assertion);
        assert!(verify_client_auth(&state, &realm_id, "master", &client, &params).await.is_err());
    }
}
