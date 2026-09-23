// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Token manager for issuing and validating JWT tokens.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use issuerd_core::{
    AccessTokenClaims, Acr, Algorithm, Audience, Client, ClientIdentifier, CryptoProvider,
    IdTokenClaims, IntrospectionResponse, Issuer, IssuerdError, Jwk, JwkKty, JwkSet, JwsType,
    JwtType, KeyId, LogoutToken, LogoutTokenClaims, Nonce, Realm, RealmAccess, RealmName,
    RefreshTokenClaims, SessionId, User, UserSession, ValidatedAccessToken, ValidatedRefreshToken,
};
use url::Url;

use crate::hash::{compute_at_hash, compute_c_hash};
use crate::jwt::{AccessToken, IdToken, RefreshToken};

/// Manages issuance and validation of JWT tokens.
pub struct TokenManager<C: CryptoProvider> {
    crypto: Arc<C>,
    issuer_base_url: String,
    /// Parsed form of `issuer_base_url`, used for structural issuer
    /// validation. `None` (an unparseable base URL) fails every issuer
    /// check closed.
    issuer_base_parsed: Option<Url>,
    clock_skew: std::time::Duration,
    /// Full published key set (active + passive) — used for verification.
    jwks: std::sync::RwLock<JwkSet>,
    /// Active keys only — used for signing-key selection. A disabled
    /// (passive) key still verifies but must never sign again, so
    /// `select_signing_jwk` reads this snapshot, never `jwks`.
    active_jwks: std::sync::RwLock<JwkSet>,
    /// Memoized decoding keys by kid: JWK component base64-decoding and key
    /// construction happen once per key instead of once per request.
    /// Cleared by [`TokenManager::refresh_jwks`], so rotation/disable
    /// propagate together with the key set.
    decoding_keys: std::sync::RwLock<HashMap<KeyId, Arc<jsonwebtoken::DecodingKey>>>,
    default_alg: Algorithm,
}

/// Lifetime of a JARM authorization-response JWT: short, since
/// the JWT only needs to survive the front-channel redirect.
const JARM_RESPONSE_LIFETIME_SECS: i64 = 60;

impl<C: CryptoProvider> TokenManager<C> {
    /// Create a new token manager.
    ///
    /// The default token-signing algorithm matches
    /// [`CryptoConfig::default`][crate::CryptoConfig] (EdDSA); use
    /// [`TokenManager::with_default_alg`] to override it.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use std::time::Duration;
    /// use issuerd_token::{CryptoConfig, RingCryptoProvider};
    /// use issuerd_token::token_manager::TokenManager;
    /// use issuerd_core::JwkSet;
    ///
    /// # fn main() -> Result<(), issuerd_core::IssuerdError> {
    /// let crypto = Arc::new(RingCryptoProvider::new(CryptoConfig {
    ///     default_alg: issuerd_core::Algorithm::Rs256,
    ///     rsa_key_size: 2048,
    /// })?);
    /// let jwks = JwkSet { keys: vec![] };
    /// let tm = TokenManager::new(crypto, "https://issuer".to_string(), Duration::from_secs(60), jwks);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        crypto: Arc<C>,
        issuer_base_url: String,
        clock_skew: std::time::Duration,
        jwks: JwkSet,
    ) -> Self {
        Self::with_default_alg(crypto, issuer_base_url, clock_skew, jwks, Algorithm::EdDsa)
    }

    /// Create a token manager with an explicit default token-signing
    /// algorithm.
    ///
    /// The default signs tokens for realms that do not set the
    /// `default_signature_algorithm` attribute: issuance picks
    /// the newest active key of the resolved algorithm, falling back to the
    /// newest active key overall when no key matches.
    ///
    /// The passed `jwks` seeds both the verification snapshot and the
    /// signing-selection snapshot. It is assumed to contain active keys only
    /// (conservative, mirroring the [`CryptoProvider::get_active_public_keys`]
    /// default); call [`TokenManager::refresh_jwks`] to install the true
    /// active-only signing snapshot.
    pub fn with_default_alg(
        crypto: Arc<C>,
        issuer_base_url: String,
        clock_skew: std::time::Duration,
        jwks: JwkSet,
        default_alg: Algorithm,
    ) -> Self {
        // Normalize once: every derived issuer/URL assumes no trailing `/`.
        let issuer_base_url = issuer_base_url.trim_end_matches('/').to_string();
        let issuer_base_parsed = Url::parse(&issuer_base_url).ok();
        Self {
            crypto,
            issuer_base_url,
            issuer_base_parsed,
            clock_skew,
            active_jwks: std::sync::RwLock::new(jwks.clone()),
            jwks: std::sync::RwLock::new(jwks),
            decoding_keys: std::sync::RwLock::new(HashMap::new()),
            default_alg,
        }
    }

    fn issuer_for_realm(&self, realm: &Realm) -> Issuer {
        Issuer::new(format!("{}/realms/{}", self.issuer_base_url, realm.name.as_str())).unwrap()
    }

    /// Structural check that `iss` names a realm of this deployment: parsed
    /// as a URL, its scheme, host, and port must equal the configured issuer
    /// base URL exactly, the path must be exactly
    /// `{base_path}/realms/{name}` where `{name}` passes [`RealmName`]
    /// validation (a single safe segment — this rejects trailing slashes and
    /// extra path segments, which leave a `/` or a URL-reserved character in
    /// the candidate name), and there must be no userinfo, query, or
    /// fragment. Issuers are realm-NAME based; pre-switch id-spelled issuers
    /// stay rejected downstream by name-only realm resolution.
    fn is_realm_issuer(&self, iss: &str) -> bool {
        let Some(base) = &self.issuer_base_parsed else {
            return false;
        };
        let Ok(url) = Url::parse(iss) else {
            return false;
        };
        if url.scheme() != base.scheme()
            || url.host_str() != base.host_str()
            || url.port_or_known_default() != base.port_or_known_default()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return false;
        }
        let Some(name) = url
            .path()
            .strip_prefix(base.path().trim_end_matches('/'))
            .and_then(|rest| rest.strip_prefix("/realms/"))
        else {
            return false;
        };
        RealmName::new(name).is_ok()
    }

    /// Refresh the cached JWK sets from the crypto provider: the full
    /// published set (verification) and the active-only set (signing-key
    /// selection).
    pub async fn refresh_jwks(&self) -> Result<(), IssuerdError> {
        let new_jwks = self.crypto.get_public_keys().await?;
        let new_active = self.crypto.get_active_public_keys().await?;
        {
            let mut guard = self
                .jwks
                .write()
                .map_err(|_| IssuerdError::ServerError("JWKS cache poisoned".into()))?;
            *guard = new_jwks;
        }
        let mut active_guard = self
            .active_jwks
            .write()
            .map_err(|_| IssuerdError::ServerError("JWKS cache poisoned".into()))?;
        *active_guard = new_active;
        // Clear memoized decoding keys: the refreshed set may have dropped
        // or re-generated keys, and stale entries must never outlive it.
        self.decoding_keys
            .write()
            .map_err(|_| IssuerdError::ServerError("JWKS cache poisoned".into()))?
            .clear();
        Ok(())
    }

    /// Memoized decoding key for `kid`. Built lazily from the JWK on first
    /// use; cleared together with the key snapshots on refresh.
    fn decoding_key_for(
        &self,
        kid: &KeyId,
        jwk: &Jwk,
    ) -> Result<Arc<jsonwebtoken::DecodingKey>, IssuerdError> {
        let poisoned = || IssuerdError::ServerError("JWKS cache poisoned".into());
        if let Some(key) = self.decoding_keys.read().map_err(|_| poisoned())?.get(kid) {
            return Ok(Arc::clone(key));
        }
        let key = Arc::new(jwk_to_decoding_key(jwk)?);
        self.decoding_keys
            .write()
            .map_err(|_| poisoned())?
            .insert(kid.clone(), Arc::clone(&key));
        Ok(key)
    }

    /// Issue an access token.
    pub async fn issue_access_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        scope: &[String],
        session_id: &SessionId,
    ) -> Result<AccessToken, IssuerdError> {
        self.issue_access_token_with_roles(user, client, realm, scope, session_id, None, None, None)
            .await
    }

    /// Issue an access token with realm roles embedded.
    ///
    /// `claims_overlay` carries protocol-mapper output: arbitrary
    /// extra claims merged into the signed payload. Keys colliding with
    /// security-critical registered claims are dropped (see
    /// [`RESERVED_OVERLAY_CLAIMS`]); `aud`, `realm_access`, and
    /// `resource_access` may legitimately be supplied through the overlay.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_access_token_with_roles(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        scope: &[String],
        session_id: &SessionId,
        realm_access: Option<issuerd_core::RealmAccess>,
        claims: Option<serde_json::Value>,
        claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<AccessToken, IssuerdError> {
        let now = Utc::now().timestamp();
        let claims = AccessTokenClaims {
            jti: issuerd_core::JwtId::new(issuerd_core::utils::generate_id()).unwrap(),
            iss: self.issuer_for_realm(realm),
            // Pairwise clients get a sector-scoped subject.
            sub: crate::pairwise::effective_subject(user, client, realm)?,
            aud: Audience::new(client.client_id.to_string()).unwrap(),
            exp: now + realm.access_token_lifespan.get() as i64,
            iat: now,
            nbf: now,
            scope: issuerd_core::Scope::from(scope.to_vec()),
            typ: JwtType::Bearer,
            azp: Some(client.client_id.to_string()),
            session_state: None,
            realm_access,
            resource_access: None,
            sid: Some(session_id.clone()),
            claims,
            // DPoP binding arrives through the claims overlay,
            // merged post-serialization by `sign_claims_with_overlay` — the
            // typed field stays `None` here and is only populated on decode.
            cnf: None,
            // RAR authorization details likewise arrive through
            // the claims overlay; populated on decode.
            authorization_details: None,
        };

        let token = self
            .sign_claims_with_overlay(&claims, claims_overlay, self.signing_alg_for_realm(realm))
            .await?
            .0;
        Ok(AccessToken { token, claims })
    }

    /// Issue a refresh token.
    ///
    /// `offline` marks the token as an offline refresh token
    /// (`typ: Offline`, Keycloak `TokenUtil.TOKEN_TYPE_OFFLINE`): it is bound
    /// to an offline session rather than the SSO session, so its lifetime is
    /// derived from `Realm.offline_session_idle_timeout` instead of
    /// `Realm.refresh_token_lifespan`. (Keycloak offline tokens carry no
    /// `exp` at all; ours expire after the offline idle window and are
    /// re-minted on every rotation — the effective cutoff is identical.)
    ///
    /// `dpop_jkt` (RFC 9449 §5.1) binds the refresh token to a
    /// DPoP key: the refresh grant then requires a proof from the same key
    /// and slides the binding onto the rotated token.
    ///
    /// `authorization_details` (RFC 9396 §6) carries the granted
    /// RAR authorization details on the refresh token — the durable artifact
    /// of the grant — so the refresh grant can re-issue (or narrow) them
    /// without a storage lookup.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_refresh_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        session_id: &SessionId,
        scope: &[String],
        offline: bool,
        dpop_jkt: Option<&str>,
        authorization_details: Option<&[serde_json::Value]>,
    ) -> Result<RefreshToken, IssuerdError> {
        let now = Utc::now().timestamp();
        let lifespan = if offline {
            realm.offline_session_idle_timeout.get()
        } else {
            realm.refresh_token_lifespan.get()
        };
        let claims = RefreshTokenClaims {
            jti: issuerd_core::JwtId::new(issuerd_core::utils::generate_id()).unwrap(),
            iss: self.issuer_for_realm(realm),
            // Refresh tokens are client-visible JWTs, so they
            // carry the pairwise subject too — a public `sub` here would let
            // colluding clients correlate the user across sectors. The
            // refresh grant resolves the user through the session (`sid`).
            sub: crate::pairwise::effective_subject(user, client, realm)?,
            aud: Audience::new(client.client_id.to_string()).unwrap(),
            exp: now + lifespan as i64,
            iat: now,
            typ: if offline {
                JwtType::Offline
            } else {
                JwtType::Refresh
            },
            sid: session_id.clone(),
            scope: issuerd_core::Scope::from(scope.to_vec()),
            cnf: dpop_jkt.map(|jkt| issuerd_core::ConfirmationClaim {
                jkt: jkt.to_string(),
            }),
            authorization_details: authorization_details.map(<[serde_json::Value]>::to_vec),
        };

        let (token, _) = self.sign_claims(&claims, self.signing_alg_for_realm(realm)).await?;
        Ok(RefreshToken { token, claims })
    }

    /// Issue an ID token.
    ///
    /// Profile/email/address/phone claims are no longer gated here: they are
    /// produced by protocol-mapper evaluation in
    /// `issuerd-server` and supplied through `claims_overlay` (which is also how
    /// the OIDC Core §5.4 "userinfo claims only in pure implicit flows" rule
    /// is applied — the caller simply passes an empty overlay when an access
    /// token or code is issued alongside).
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_id_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        nonce: Option<&str>,
        auth_time: chrono::DateTime<Utc>,
        session_id: &SessionId,
        access_token: Option<&AccessToken>,
        code: Option<&str>,
        acr_values: Option<&[String]>,
        claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<IdToken, IssuerdError> {
        let now = Utc::now().timestamp();
        let alg = self.signing_alg_for_realm(realm);
        let alg = self.active_alg(alg).await?;

        let mut claims = IdTokenClaims {
            iss: self.issuer_for_realm(realm),
            // Pairwise clients get a sector-scoped subject.
            sub: crate::pairwise::effective_subject(user, client, realm)?,
            aud: Audience::new(client.client_id.to_string()).unwrap(),
            exp: now + realm.access_token_lifespan.get() as i64,
            iat: now,
            auth_time: Some(auth_time.timestamp()),
            nonce: nonce.map(|s| Nonce::new(s).unwrap()),
            acr: acr_values.and_then(|v| v.first()).and_then(|s| Acr::new(s).ok()),
            amr: None,
            azp: Some(client.client_id.to_string()),
            sid: Some(session_id.clone()),
            at_hash: access_token.map(|at| compute_at_hash(&at.token, alg)),
            c_hash: code.map(|c| compute_c_hash(c, alg)),
            name: None,
            given_name: None,
            family_name: None,
            preferred_username: None,
            email: None,
            email_verified: None,
            address: None,
            phone_number: None,
            phone_number_verified: None,
            realm_access: None,
            resource_access: None,
        };

        let (token, header_alg) =
            self.sign_claims_with_overlay(&claims, claims_overlay, alg).await?;

        // Re-compute hashes with the actual algorithm used for signing.
        let actual_alg = header_alg
            .parse()
            .map_err(|_| IssuerdError::ServerError("unknown signing algorithm".into()))?;
        if access_token.is_some() {
            claims.at_hash = access_token.map(|at| compute_at_hash(&at.token, actual_alg));
        }
        if code.is_some() {
            claims.c_hash = code.map(|c| compute_c_hash(c, actual_alg));
        }

        Ok(IdToken { token, claims })
    }

    /// Issue a logout token for backchannel logout.
    pub async fn issue_logout_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        session_id: &SessionId,
    ) -> Result<LogoutToken, IssuerdError> {
        let now = Utc::now().timestamp();
        let claims = LogoutTokenClaims {
            iss: self.issuer_for_realm(realm),
            // The logout token's sub must match the (possibly
            // pairwise) subject the client knows from its ID tokens, or the
            // client cannot correlate the session to terminate.
            sub: crate::pairwise::effective_subject(user, client, realm)?,
            aud: Audience::new(client.client_id.to_string()).unwrap(),
            iat: now,
            jti: issuerd_core::JwtId::new(issuerd_core::utils::generate_id()).unwrap(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
            sid: session_id.clone(),
        };

        let (token, _) = self.sign_claims(&claims, self.signing_alg_for_realm(realm)).await?;
        Ok(LogoutToken { token, claims })
    }

    /// Sign an authorization response as a JARM JWT (JWT Secured
    /// Authorization Response Mode for OAuth 2.0).
    /// The response parameters (`code`, `state`, `id_token`, `error`, ...)
    /// become claims alongside the envelope JARM §2.3 requires: `iss` (the
    /// realm issuer), `aud` (the client_id), `exp`, and `iat`. Envelope
    /// claims win on collision — response parameters never legitimately
    /// carry them. The JWT lives only as long as the front-channel redirect
    /// needs ([`JARM_RESPONSE_LIFETIME_SECS`]); it is signed with the realm's
    /// token-signing key, so clients verify it against the realm JWKS.
    pub async fn sign_authorization_response(
        &self,
        realm: &Realm,
        client_id: &str,
        params: &[(String, String)],
    ) -> Result<String, IssuerdError> {
        let now = Utc::now().timestamp();
        let mut claims = serde_json::Map::with_capacity(params.len() + 4);
        for (key, value) in params {
            claims.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        claims.insert(
            "iss".to_string(),
            serde_json::Value::String(self.issuer_for_realm(realm).as_str().to_string()),
        );
        claims.insert("aud".to_string(), serde_json::Value::String(client_id.to_string()));
        claims
            .insert("exp".to_string(), serde_json::Value::from(now + JARM_RESPONSE_LIFETIME_SECS));
        claims.insert("iat".to_string(), serde_json::Value::from(now));

        let (token, _) = self.sign_claims(&claims, self.signing_alg_for_realm(realm)).await?;
        Ok(token)
    }

    /// Stateless validation of an access token.
    pub fn validate_access_token(&self, token: &str) -> Result<ValidatedAccessToken, IssuerdError> {
        let (claims, issuerd_alg, kid) =
            self.decode_token::<AccessTokenClaims>(token, true, None)?;

        // jsonwebtoken 9 does not validate iat; check manually.
        let now = Utc::now().timestamp();
        if claims.iat > now + self.clock_skew.as_secs() as i64 {
            return Err(IssuerdError::InvalidToken);
        }

        // Validate issuer structurally to support realm-specific issuers.
        if !self.is_realm_issuer(claims.iss.as_str()) {
            return Err(IssuerdError::InvalidToken);
        }

        Ok(ValidatedAccessToken {
            claims,
            header: issuerd_core::JwsHeader {
                alg: issuerd_alg,
                typ: Some(JwsType::Jwt),
                kid,
            },
        })
    }

    /// Stateless validation of a refresh token.
    pub fn validate_refresh_token(
        &self,
        token: &str,
    ) -> Result<ValidatedRefreshToken, IssuerdError> {
        let (claims, issuerd_alg, kid) =
            self.decode_token::<RefreshTokenClaims>(token, false, None)?;

        // Only tokens actually issued as refresh tokens qualify: access
        // tokens share most of the claim shape, so without this check a
        // hint-less revocation probe (or the refresh grant itself) would
        // accept an access token as a refresh token. Offline refresh tokens
        // (`typ: Offline`) are refresh tokens too.
        if !matches!(claims.typ, JwtType::Refresh | JwtType::Offline) {
            return Err(IssuerdError::InvalidToken);
        }

        let now = Utc::now().timestamp();
        if claims.iat > now + self.clock_skew.as_secs() as i64 {
            return Err(IssuerdError::InvalidToken);
        }

        // Validate issuer structurally to support realm-specific issuers.
        if !self.is_realm_issuer(claims.iss.as_str()) {
            return Err(IssuerdError::InvalidToken);
        }

        Ok(ValidatedRefreshToken {
            claims,
            header: issuerd_core::JwsHeader {
                alg: issuerd_alg,
                typ: Some(JwsType::Jwt),
                kid,
            },
        })
    }

    /// Validate an ID token.
    pub fn validate_id_token(
        &self,
        token: &str,
        client: &Client,
        nonce: Option<&str>,
    ) -> Result<IdTokenClaims, IssuerdError> {
        let (claims, _, _) =
            self.decode_token::<IdTokenClaims>(token, true, Some(client.client_id.as_str()))?;

        // jsonwebtoken 9 does not validate iat; check manually.
        let now = Utc::now().timestamp();
        if claims.iat > now + self.clock_skew.as_secs() as i64 {
            return Err(IssuerdError::InvalidToken);
        }

        // Validate issuer using the structural realm-family check, same as
        // the other validators: issuers are realm-NAME based, and the
        // client's realm name is not available here.
        if !self.is_realm_issuer(claims.iss.as_str()) {
            return Err(IssuerdError::InvalidToken);
        }

        if let Some(expected_nonce) = nonce {
            if claims.nonce.as_deref() != Some(expected_nonce) {
                return Err(IssuerdError::InvalidToken);
            }
        }

        if claims.aud.as_str() != client.client_id.as_str() {
            return Err(IssuerdError::InvalidToken);
        }

        if let Some(ref azp) = claims.azp {
            if azp != client.client_id.as_str() {
                return Err(IssuerdError::InvalidToken);
            }
        }

        Ok(claims)
    }

    /// Validate an `id_token_hint` at the logout endpoint (OIDC RP-Initiated Logout).
    ///
    /// Cryptographic validation only (signature, expiry, issuer family) — the client is
    /// unknown at this point, so audience and nonce checks are skipped; callers read
    /// `aud`/`azp` from the returned claims for client binding.
    pub fn validate_id_token_hint(&self, token: &str) -> Result<IdTokenClaims, IssuerdError> {
        let (claims, _, _) = self.decode_token::<IdTokenClaims>(token, true, None)?;

        // jsonwebtoken 9 does not validate iat; check manually.
        let now = Utc::now().timestamp();
        if claims.iat > now + self.clock_skew.as_secs() as i64 {
            return Err(IssuerdError::InvalidToken);
        }

        // Validate issuer structurally to support realm-specific issuers.
        if !self.is_realm_issuer(claims.iss.as_str()) {
            return Err(IssuerdError::InvalidToken);
        }

        Ok(claims)
    }

    /// Decode and cryptographically validate a token against the cached JWKS,
    /// returning the claims, the header algorithm, and the signing key id.
    ///
    /// `validate_nbf` and `audience` mirror the per-token-type
    /// `jsonwebtoken::Validation` knobs (aud disabled when `None`). All
    /// algorithms except ES512 go through `jsonwebtoken`; ES512 tokens are
    /// verified manually because `jsonwebtoken` (ring) has no P-521 support —
    /// the same exp/nbf/leeway/aud rules are applied.
    fn decode_token<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        validate_nbf: bool,
        audience: Option<&str>,
    ) -> Result<(T, Algorithm, KeyId), IssuerdError> {
        // Peek at the raw header first: jsonwebtoken cannot parse an ES512
        // header (its Algorithm enum has no P-521 variant).
        let (alg_str, kid_str) = peek_jwt_header(token)?;
        let kid = KeyId::new(kid_str).map_err(|_| IssuerdError::InvalidToken)?;

        let jwks = self
            .jwks
            .read()
            .map_err(|_| IssuerdError::ServerError("JWKS cache poisoned".into()))?;
        let jwk = jwks.keys.iter().find(|k| k.kid == kid).ok_or(IssuerdError::InvalidToken)?;

        if alg_str == "ES512" {
            let claims =
                decode_es512_claims(token, jwk, self.clock_skew.as_secs(), validate_nbf, audience)?;
            return Ok((claims, Algorithm::Es512, kid));
        }

        // The peeked header already carries alg: map it instead of letting
        // jsonwebtoken re-parse the header segment a second time.
        let alg =
            jsonwebtoken::Algorithm::from_str(&alg_str).map_err(|_| IssuerdError::InvalidToken)?;
        let decoding_key = self.decoding_key_for(&kid, jwk)?;
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.validate_exp = true;
        validation.validate_nbf = validate_nbf;
        validation.leeway = self.clock_skew.as_secs();
        // Skip issuer validation here; we check manually to support realm-specific issuers.
        // Audience is enforced by the library only when the caller pinned one
        // (jsonwebtoken 9: `set_audience` alone does not enable the check);
        // otherwise callers verify the audience themselves.
        validation.validate_aud = audience.is_some();
        if let Some(aud) = audience {
            validation.set_audience(&[aud]);
        }
        validation.required_spec_claims.clear();

        let token_data = jsonwebtoken::decode::<T>(token, &decoding_key, &validation)
            .map_err(|_| IssuerdError::InvalidToken)?;

        let issuerd_alg = map_jwt_alg(alg)?;
        Ok((token_data.claims, issuerd_alg, kid))
    }

    /// Build an introspection response.
    pub fn introspect(
        &self,
        token: &str,
        session: Option<&UserSession>,
    ) -> Result<IntrospectionResponse, IssuerdError> {
        match self.validate_access_token(token) {
            Ok(validated) => {
                let c = validated.claims;
                // RFC 9449 §6.1: a DPoP-bound token introspects with
                // `token_type: DPoP` and its `cnf` confirmation claim.
                let token_type = if c.cnf.is_some() {
                    issuerd_core::TokenType::Dpop
                } else {
                    issuerd_core::TokenType::Bearer
                };
                Ok(IntrospectionResponse {
                    active: true,
                    scope: Some(c.scope.clone()),
                    client_id: c.azp.as_deref().and_then(|s| ClientIdentifier::new(s).ok()),
                    username: session.map(|s| s.login_username.clone()),
                    token_type: Some(token_type),
                    cnf: c.cnf.clone(),
                    // RFC 9396 §9.2: reflect the granted authorization details.
                    authorization_details: c.authorization_details.clone(),
                    exp: Some(c.exp),
                    iat: Some(c.iat),
                    nbf: Some(c.nbf),
                    sub: Some(c.sub.to_string()),
                    aud: Some(c.aud.clone()),
                    iss: Some(c.iss.clone()),
                    jti: Some(c.jti),
                })
            }
            Err(_) => Ok(IntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                cnf: None,
                authorization_details: None,
                exp: None,
                iat: None,
                nbf: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            }),
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Resolve the signing algorithm for a realm: its
    /// `default_signature_algorithm` attribute when set to a known algorithm,
    /// otherwise the server default.
    fn signing_alg_for_realm(&self, realm: &Realm) -> Algorithm {
        realm.default_signature_algorithm().unwrap_or(self.default_alg)
    }

    async fn active_alg(&self, alg: Algorithm) -> Result<Algorithm, IssuerdError> {
        let jwks = self
            .active_jwks
            .read()
            .map_err(|_| IssuerdError::ServerError("JWKS cache poisoned".into()))?;
        let jwk = select_signing_jwk(&jwks, alg)
            .ok_or_else(|| IssuerdError::ServerError("no active signing keys".into()))?;
        Ok(jwk.alg)
    }

    async fn sign_claims<T: serde::Serialize>(
        &self,
        claims: &T,
        alg: Algorithm,
    ) -> Result<(String, String), IssuerdError> {
        let (kid, alg) = {
            let jwks = self
                .active_jwks
                .read()
                .map_err(|_| IssuerdError::ServerError("JWKS cache poisoned".into()))?;
            let jwk = select_signing_jwk(&jwks, alg)
                .ok_or_else(|| IssuerdError::ServerError("no active signing keys".into()))?;
            (jwk.kid.clone(), jwk.alg)
        };
        let payload = serde_json::to_string(claims)
            .map_err(|e| IssuerdError::ServerError(format!("JSON serialization failed: {e}")))?;
        let token = self.crypto.sign(&payload, alg, &kid).await?;
        Ok((token, alg.to_string()))
    }

    /// Sign claims after merging a protocol-mapper overlay.
    ///
    /// The claims struct is serialized to a JSON object, then overlay entries
    /// are inserted (overlay wins on collision), except keys in
    /// [`RESERVED_OVERLAY_CLAIMS`], which are always taken from the typed
    /// claims struct. Returns the compact JWS and the algorithm used.
    async fn sign_claims_with_overlay<T: serde::Serialize>(
        &self,
        claims: &T,
        overlay: Option<serde_json::Map<String, serde_json::Value>>,
        alg: Algorithm,
    ) -> Result<(String, String), IssuerdError> {
        match overlay {
            None => self.sign_claims(claims, alg).await,
            Some(overlay) => {
                let mut value = serde_json::to_value(claims).map_err(|e| {
                    IssuerdError::ServerError(format!("JSON serialization failed: {e}"))
                })?;
                if let serde_json::Value::Object(map) = &mut value {
                    for (key, val) in overlay {
                        if RESERVED_OVERLAY_CLAIMS.contains(&key.as_str()) {
                            continue;
                        }
                        map.insert(key, val);
                    }
                }
                self.sign_claims(&value, alg).await
            }
        }
    }
}

/// Select the signing key for the resolved algorithm from the **active-only**
/// JWKS snapshot (`TokenManager::active_jwks`).
///
/// The snapshot is ordered **newest active first** (the
/// `KeyStore::active_public_jwks` contract), so the first key matching `alg`
/// is the newest active key of that algorithm — this is how a realm's
/// `default_signature_algorithm` attribute picks which
/// server-global active key signs its tokens. Passive (disabled) keys are not
/// in this snapshot and therefore never sign. When no key matches, the
/// default signing key (`keys[0]`, the newest active key overall) is used so
/// issuance never breaks on a misconfigured realm.
fn select_signing_jwk(jwks: &JwkSet, alg: Algorithm) -> Option<&Jwk> {
    jwks.keys.iter().find(|k| k.alg == alg).or_else(|| jwks.keys.first())
}

/// Claims that a protocol-mapper overlay may never override.
///
/// `aud`, `realm_access`, `resource_access`, and `allowed_origins` are
/// deliberately absent: those are exactly the claims the role/audience/
/// web-origin mappers legitimately produce. `cnf` is likewise absent on
/// purpose: it is how the token endpoint injects the DPoP key binding
/// after mapper evaluation — mapper configs are admin-trusted,
/// so no new threat is introduced.
const RESERVED_OVERLAY_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "exp",
    "iat",
    "nbf",
    "jti",
    "typ",
    "scope",
    "azp",
    "sid",
    "at_hash",
    "c_hash",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "claims",
];

fn jwk_to_decoding_key(jwk: &Jwk) -> Result<jsonwebtoken::DecodingKey, IssuerdError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    match jwk.kty {
        JwkKty::Rsa => {
            let n =
                jwk.n.as_ref().map(|b| b.as_str()).ok_or_else(|| {
                    IssuerdError::InvalidRequest("RSA JWK missing modulus".into())
                })?;
            let e =
                jwk.e.as_ref().map(|b| b.as_str()).ok_or_else(|| {
                    IssuerdError::InvalidRequest("RSA JWK missing exponent".into())
                })?;
            jsonwebtoken::DecodingKey::from_rsa_components(n, e)
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid RSA JWK: {e}")))
        }
        JwkKty::Ec => {
            let x = jwk
                .x
                .as_ref()
                .map(|b| b.as_str())
                .ok_or_else(|| IssuerdError::InvalidRequest("EC JWK missing x".into()))?;
            let y = jwk
                .y
                .as_ref()
                .map(|b| b.as_str())
                .ok_or_else(|| IssuerdError::InvalidRequest("EC JWK missing y".into()))?;
            jsonwebtoken::DecodingKey::from_ec_components(x, y)
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid EC JWK: {e}")))
        }
        JwkKty::Okp => {
            let x = jwk
                .x
                .as_ref()
                .map(|b| b.as_str())
                .ok_or_else(|| IssuerdError::InvalidRequest("OKP JWK missing x".into()))?;
            jsonwebtoken::DecodingKey::from_ed_components(x)
                .map_err(|e| IssuerdError::InvalidRequest(format!("invalid OKP JWK: {e}")))
        }
        JwkKty::Oct => {
            let k = jwk
                .k
                .as_ref()
                .map(|b| b.as_str())
                .ok_or_else(|| IssuerdError::InvalidRequest("oct JWK missing k".into()))?;
            let bytes = URL_SAFE_NO_PAD.decode(k).map_err(|e| {
                IssuerdError::InvalidRequest(format!("invalid base64 in oct JWK: {e}"))
            })?;
            Ok(jsonwebtoken::DecodingKey::from_secret(&bytes))
        }
    }
}

impl<C: CryptoProvider + 'static> issuerd_core::TokenService for TokenManager<C> {
    fn validate_access_token(&self, token: &str) -> Result<ValidatedAccessToken, IssuerdError> {
        self.validate_access_token(token)
    }

    fn validate_id_token(
        &self,
        token: &str,
        client: &Client,
        nonce: Option<&str>,
    ) -> Result<IdTokenClaims, IssuerdError> {
        self.validate_id_token(token, client, nonce)
    }

    fn validate_refresh_token(&self, token: &str) -> Result<ValidatedRefreshToken, IssuerdError> {
        self.validate_refresh_token(token)
    }

    fn validate_id_token_hint(&self, token: &str) -> Result<IdTokenClaims, IssuerdError> {
        self.validate_id_token_hint(token)
    }
}

// ---------------------------------------------------------------------------
// TokenIssuer trait
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait TokenIssuer: Send + Sync {
    async fn issue_access_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        scope: &[String],
        session_id: &SessionId,
    ) -> Result<AccessToken, IssuerdError>;

    async fn issue_access_token_with_roles(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        scope: &[String],
        session_id: &SessionId,
        realm_access: Option<RealmAccess>,
        claims: Option<serde_json::Value>,
        claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<AccessToken, IssuerdError>;

    async fn issue_refresh_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        session_id: &SessionId,
        scope: &[String],
        offline: bool,
        dpop_jkt: Option<&str>,
        authorization_details: Option<&[serde_json::Value]>,
    ) -> Result<RefreshToken, IssuerdError>;

    async fn issue_id_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        nonce: Option<&str>,
        auth_time: chrono::DateTime<chrono::Utc>,
        session_id: &SessionId,
        access_token: Option<&AccessToken>,
        code: Option<&str>,
        acr_values: Option<&[String]>,
        claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<IdToken, IssuerdError>;

    /// Issue a logout token for OIDC back-channel logout.
    async fn issue_logout_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        session_id: &SessionId,
    ) -> Result<LogoutToken, IssuerdError>;

    /// Sign an authorization response as a JARM JWT: the
    /// response parameters become claims under the JARM envelope
    /// (`iss`/`aud`/`exp`/`iat`), signed with the realm's signing key.
    async fn sign_authorization_response(
        &self,
        realm: &Realm,
        client_id: &str,
        params: &[(String, String)],
    ) -> Result<String, IssuerdError>;
}

#[async_trait]
impl<C: CryptoProvider + 'static> TokenIssuer for TokenManager<C> {
    async fn issue_access_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        scope: &[String],
        session_id: &SessionId,
    ) -> Result<AccessToken, IssuerdError> {
        self.issue_access_token(user, client, realm, scope, session_id).await
    }

    async fn issue_access_token_with_roles(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        scope: &[String],
        session_id: &SessionId,
        realm_access: Option<RealmAccess>,
        claims: Option<serde_json::Value>,
        claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<AccessToken, IssuerdError> {
        self.issue_access_token_with_roles(
            user,
            client,
            realm,
            scope,
            session_id,
            realm_access,
            claims,
            claims_overlay,
        )
        .await
    }

    async fn issue_refresh_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        session_id: &SessionId,
        scope: &[String],
        offline: bool,
        dpop_jkt: Option<&str>,
        authorization_details: Option<&[serde_json::Value]>,
    ) -> Result<RefreshToken, IssuerdError> {
        self.issue_refresh_token(
            user,
            client,
            realm,
            session_id,
            scope,
            offline,
            dpop_jkt,
            authorization_details,
        )
        .await
    }

    async fn issue_id_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        nonce: Option<&str>,
        auth_time: chrono::DateTime<chrono::Utc>,
        session_id: &SessionId,
        access_token: Option<&AccessToken>,
        code: Option<&str>,
        acr_values: Option<&[String]>,
        claims_overlay: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<IdToken, IssuerdError> {
        self.issue_id_token(
            user,
            client,
            realm,
            nonce,
            auth_time,
            session_id,
            access_token,
            code,
            acr_values,
            claims_overlay,
        )
        .await
    }

    async fn issue_logout_token(
        &self,
        user: &User,
        client: &Client,
        realm: &Realm,
        session_id: &SessionId,
    ) -> Result<LogoutToken, IssuerdError> {
        self.issue_logout_token(user, client, realm, session_id).await
    }

    async fn sign_authorization_response(
        &self,
        realm: &Realm,
        client_id: &str,
        params: &[(String, String)],
    ) -> Result<String, IssuerdError> {
        self.sign_authorization_response(realm, client_id, params).await
    }
}

/// Extract `(alg, kid)` from a JWT header without going through
/// `jsonwebtoken` — its `Algorithm` enum cannot represent ES512, so
/// `decode_header` would fail on otherwise valid ES512 tokens. Both a
/// malformed header and a missing `alg`/`kid` yield [`IssuerdError::InvalidToken`],
/// matching the previous `decode_header` + `kid.ok_or(...)` behavior.
fn peek_jwt_header(token: &str) -> Result<(String, String), IssuerdError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let first = token.split('.').next().ok_or(IssuerdError::InvalidToken)?;
    let bytes = URL_SAFE_NO_PAD.decode(first).map_err(|_| IssuerdError::InvalidToken)?;
    let header: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| IssuerdError::InvalidToken)?;
    let alg = header.get("alg").and_then(|a| a.as_str()).ok_or(IssuerdError::InvalidToken)?;
    let kid = header.get("kid").and_then(|k| k.as_str()).ok_or(IssuerdError::InvalidToken)?;
    Ok((alg.to_string(), kid.to_string()))
}

/// Decode and validate an ES512 token manually (signature, `exp`, optional
/// `nbf`, optional audience), mirroring the `jsonwebtoken::Validation` rules
/// applied to the other algorithms: `exp`/`nbf` are honored when present
/// (with the configured leeway) and a pinned audience must match the `aud`
/// claim. Anything malformed or failing validation yields
/// [`IssuerdError::InvalidToken`].
fn decode_es512_claims<T: serde::de::DeserializeOwned>(
    token: &str,
    jwk: &Jwk,
    leeway_secs: u64,
    validate_nbf: bool,
    audience: Option<&str>,
) -> Result<T, IssuerdError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    #[derive(serde::Deserialize)]
    struct ClaimsProbe {
        exp: Option<i64>,
        nbf: Option<i64>,
        aud: Option<issuerd_core::Audience>,
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(IssuerdError::InvalidToken);
    }
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| IssuerdError::InvalidToken)?;
    if !crate::es512::verify_es512(jwk, message.as_bytes(), &signature)? {
        return Err(IssuerdError::InvalidToken);
    }

    let payload = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| IssuerdError::InvalidToken)?;
    let probe: ClaimsProbe =
        serde_json::from_slice(&payload).map_err(|_| IssuerdError::InvalidToken)?;
    let now = Utc::now().timestamp();
    if let Some(exp) = probe.exp {
        if now > exp + leeway_secs as i64 {
            return Err(IssuerdError::InvalidToken);
        }
    }
    if validate_nbf {
        if let Some(nbf) = probe.nbf {
            if (now + leeway_secs as i64) < nbf {
                return Err(IssuerdError::InvalidToken);
            }
        }
    }
    if let Some(expected) = audience {
        if probe.aud.as_ref().map(|a| a.as_str()) != Some(expected) {
            return Err(IssuerdError::InvalidToken);
        }
    }

    serde_json::from_slice(&payload).map_err(|_| IssuerdError::InvalidToken)
}

fn map_jwt_alg(alg: jsonwebtoken::Algorithm) -> Result<Algorithm, IssuerdError> {
    match alg {
        jsonwebtoken::Algorithm::RS256 => Ok(Algorithm::Rs256),
        jsonwebtoken::Algorithm::RS384 => Ok(Algorithm::Rs384),
        jsonwebtoken::Algorithm::RS512 => Ok(Algorithm::Rs512),
        jsonwebtoken::Algorithm::ES256 => Ok(Algorithm::Es256),
        jsonwebtoken::Algorithm::ES384 => Ok(Algorithm::Es384),
        jsonwebtoken::Algorithm::HS256 => Ok(Algorithm::Hs256),
        jsonwebtoken::Algorithm::HS384 => Ok(Algorithm::Hs384),
        jsonwebtoken::Algorithm::HS512 => Ok(Algorithm::Hs512),
        jsonwebtoken::Algorithm::EdDSA => Ok(Algorithm::EdDsa),
        _ => Err(IssuerdError::InvalidRequest("unsupported JWT algorithm".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::{CryptoConfig, KeyStore, RingCryptoProvider};
    use chrono::Utc;
    use issuerd_core::{
        AuthMethod, Base64Url, ClientAuthenticatorType, ClientId, ClientProtocol, DisplayName,
        Email, JwkKty, JwkSet, JwkUse, JwtType, KeyId, RealmId, Scope, SecondsNonZero, SessionId,
        UserId, Username,
    };
    use serde_json;
    use std::collections::HashMap;
    use std::time::Duration;

    fn test_user() -> User {
        User {
            id: UserId::new("user-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            username: Username::new("alice").unwrap(),
            email: Some(Email::new("alice@example.com").unwrap()),
            email_verified: true,
            first_name: Some(DisplayName::new("Alice").unwrap()),
            last_name: Some(DisplayName::new("Smith").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn test_client() -> Client {
        Client {
            id: ClientId::new("client-1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: false,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        }
    }

    fn test_realm() -> Realm {
        Realm {
            id: RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            display_name: None,
            enabled: true,
            ssl_required: issuerd_core::SslRequired::External,
            password_policy: issuerd_core::PasswordPolicy::default(),
            login_theme: None,
            email_theme: None,
            admin_theme: None,
            default_role: None,
            access_token_lifespan: SecondsNonZero::new(300),
            refresh_token_lifespan: SecondsNonZero::new(1800),
            sso_session_idle_timeout: SecondsNonZero::new(1800),
            sso_session_max_lifespan: SecondsNonZero::new(36000),
            offline_session_idle_timeout: SecondsNonZero::new(2592000),
            brute_force_protected: false,
            max_login_failures: 5,
            wait_increment_secs: 60,
            max_failure_wait_secs: 900,
            lockout_duration_secs: 900,
            registration_enabled: false,
            reset_password_allowed: false,
            remember_me_enabled: false,
            verify_email_enabled: false,
            login_with_email_allowed: true,
            duplicate_emails_allowed: false,
            edit_username_allowed: true,
            remember_me_session_idle_secs: SecondsNonZero::new(604_800),
            otp_policy: issuerd_core::OtpPolicy::default(),
            internationalization_enabled: false,
            supported_locales: Vec::new(),
            default_locale: None,
            attributes: HashMap::new(),
            ..Default::default()
        }
    }

    fn test_jwk(alg: Algorithm) -> issuerd_core::Jwk {
        issuerd_core::Jwk {
            kty: if alg == Algorithm::EdDsa {
                JwkKty::Okp
            } else {
                JwkKty::Rsa
            },
            kid: KeyId::new("key-1").unwrap(),
            alg,
            use_: JwkUse::Sig,
            n: Some(Base64Url::new("test").unwrap()),
            e: Some(Base64Url::new("AQAB").unwrap()),
            x: None,
            y: None,
            crv: None,
            k: None,
        }
    }

    /// Decode the payload segment (segment 2) of a compact JWS into JSON.
    fn decode_payload(token: &str) -> serde_json::Value {
        use base64::Engine;
        let segment = token.split('.').nth(1).expect("compact JWS has 3 segments");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .expect("payload segment is base64url");
        serde_json::from_slice(&bytes).expect("payload segment is JSON")
    }

    #[tokio::test]
    async fn jarm_authorization_response_signing() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let params = vec![
            ("code".to_string(), "code-123".to_string()),
            ("state".to_string(), "s-1".to_string()),
        ];
        let jwt = tm.sign_authorization_response(&test_realm(), "my-app", &params).await.unwrap();

        // The JARM envelope carries iss/aud/exp/iat; response params ride
        // alongside as claims.
        let payload = decode_payload(&jwt);
        assert_eq!(payload["iss"], "https://issuer/realms/test");
        assert_eq!(payload["aud"], "my-app");
        assert_eq!(payload["code"], "code-123");
        assert_eq!(payload["state"], "s-1");
        let now = Utc::now().timestamp();
        let exp = payload["exp"].as_i64().unwrap();
        assert!(exp > now && exp <= now + 60);
        assert!(payload["iat"].as_i64().unwrap() <= now);

        // The JWT verifies against the realm's public JWKS (client-side
        // validation path) and decodes as a map of response params.
        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
        let jwk_set = crypto.get_public_keys().await.unwrap();
        let jwk = &jwk_set.keys[0];
        let key = jsonwebtoken::DecodingKey::from_rsa_components(
            jwk.n.as_ref().unwrap().as_str(),
            jwk.e.as_ref().unwrap().as_str(),
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&["my-app"]);
        let data = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
            &jwt,
            &key,
            &validation,
        )
        .unwrap();
        assert_eq!(data.claims["code"], "code-123");
    }

    #[tokio::test]
    async fn jarm_envelope_wins_param_collisions() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm =
            TokenManager::new(crypto, "https://issuer".to_string(), Duration::from_secs(60), jwks);
        // A malicious/buggy caller passing envelope-named params cannot
        // override the JARM envelope.
        let params = vec![("iss".to_string(), "https://evil.example.com".to_string())];
        let jwt = tm.sign_authorization_response(&test_realm(), "my-app", &params).await.unwrap();
        let payload = decode_payload(&jwt);
        assert_eq!(payload["iss"], "https://issuer/realms/test");
    }

    #[tokio::test]
    async fn access_token_issuance() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_sign().times(1).returning(|_, _, _| Ok("header.payload.sig".into()));
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string(), "profile".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(token.claims.typ, JwtType::Bearer);
        assert_eq!(token.claims.iss.as_str(), "https://issuer/realms/test");
        assert_eq!(token.claims.sid, Some(SessionId::new("s1").unwrap()));
        assert_eq!(token.claims.scope, issuerd_core::Scope::parse("openid profile"));
        assert_eq!(
            token.claims.exp - token.claims.iat,
            test_realm().access_token_lifespan.get() as i64
        );
    }

    #[tokio::test]
    async fn refresh_token_issuance() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_sign().times(1).returning(|_, _, _| Ok("header.payload.sig".into()));
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );
        let token = tm
            .issue_refresh_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &SessionId::new("s1").unwrap(),
                &["openid".to_string()],
                false,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(token.claims.typ, JwtType::Refresh);
        assert_eq!(
            token.claims.exp - token.claims.iat,
            test_realm().refresh_token_lifespan.get() as i64
        );
    }

    #[tokio::test]
    async fn offline_refresh_token_issuance() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_sign().times(1).returning(|_, _, _| Ok("header.payload.sig".into()));
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );
        let token = tm
            .issue_refresh_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &SessionId::new("s1").unwrap(),
                &["openid".to_string(), "offline_access".to_string()],
                true,
                None,
                None,
            )
            .await
            .unwrap();

        // Offline class: Keycloak's `typ: Offline`, lifetime from the realm's
        // offline session idle timeout instead of the refresh-token lifespan.
        assert_eq!(token.claims.typ, JwtType::Offline);
        assert_eq!(
            token.claims.exp - token.claims.iat,
            test_realm().offline_session_idle_timeout.get() as i64
        );
    }

    #[tokio::test]
    async fn id_token_with_nonce_and_hashes() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_sign().times(1).returning(|_, _, _| Ok("header.payload.sig".into()));
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );

        let access_token = AccessToken {
            token: "dummy_at".to_string(),
            claims: AccessTokenClaims {
                jti: issuerd_core::JwtId::new("jti").unwrap(),
                iss: Issuer::new("https://iss").unwrap(),
                sub: UserId::new("u1").unwrap(),
                aud: Audience::new("aud").unwrap(),
                exp: 0,
                iat: 0,
                nbf: 0,
                scope: issuerd_core::Scope::parse("openid"),
                typ: JwtType::Bearer,
                azp: None,
                session_state: None,
                realm_access: None,
                resource_access: None,
                sid: None,
                claims: None,
                cnf: None,
                authorization_details: None,
            },
        };

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                Some("nonce-123"),
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                Some(&access_token),
                Some("auth-code"),
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(id_token.claims.nonce, Some(Nonce::new("nonce-123").unwrap()));
        assert!(id_token.claims.at_hash.is_some());
        assert!(id_token.claims.c_hash.is_some());
        assert_eq!(id_token.claims.at_hash, Some(compute_at_hash("dummy_at", Algorithm::Rs256)));
        assert_eq!(id_token.claims.c_hash, Some(compute_c_hash("auth-code", Algorithm::Rs256)));
        assert_eq!(id_token.claims.azp, Some("my-app".to_string()));
        // Profile claims are never populated on the typed struct:
        // they reach the wire exclusively through the claims overlay.
        assert_eq!(id_token.claims.preferred_username, None);
    }

    #[tokio::test]
    async fn id_token_without_optional_fields() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_sign().times(1).returning(|_, _, _| Ok("header.payload.sig".into()));
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                None,
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(id_token.claims.nonce, None);
        assert_eq!(id_token.claims.at_hash, None);
        assert_eq!(id_token.claims.c_hash, None);
    }

    #[tokio::test]
    async fn id_token_with_address_claim() {
        // The address claim is assembled by a protocol mapper in
        // issuerd-server and passed in via the claims overlay; it lands only in the
        // signed payload, never on the typed claims struct.
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let mut overlay = serde_json::Map::new();
        overlay.insert(
            "address".to_string(),
            serde_json::json!({
                "formatted": "123 Main St",
                "street_address": "Main St",
                "locality": "Springfield",
                "region": "IL",
                "postal_code": "62701",
                "country": "US",
            }),
        );

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                None,
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                Some(overlay),
            )
            .await
            .unwrap();

        // The typed struct never carries overlay entries.
        assert_eq!(id_token.claims.address, None);

        let payload = decode_payload(&id_token.token);
        let addr = payload.get("address").expect("address claim in signed payload");
        assert_eq!(addr["formatted"], "123 Main St");
        assert_eq!(addr["street_address"], "Main St");
        assert_eq!(addr["locality"], "Springfield");
        assert_eq!(addr["region"], "IL");
        assert_eq!(addr["postal_code"], "62701");
        assert_eq!(addr["country"], "US");
    }

    #[tokio::test]
    async fn id_token_profile_claims_via_overlay() {
        // The user's first/last name is no longer consulted here: profile
        // claims are assembled by protocol mappers and arrive via
        // the claims overlay.
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let mut user = test_user();
        user.first_name = None;
        user.last_name = None;

        let mut overlay = serde_json::Map::new();
        overlay.insert("name".to_string(), serde_json::json!("alice"));
        overlay.insert("preferred_username".to_string(), serde_json::json!("alice"));

        let id_token = tm
            .issue_id_token(
                &user,
                &test_client(),
                &test_realm(),
                None,
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                Some(overlay),
            )
            .await
            .unwrap();

        // Typed profile fields stay None; overlay entries are wire-only.
        assert_eq!(id_token.claims.name, None);
        assert_eq!(id_token.claims.given_name, None);
        assert_eq!(id_token.claims.family_name, None);
        assert_eq!(id_token.claims.preferred_username, None);

        let payload = decode_payload(&id_token.token);
        assert_eq!(payload["name"], "alice");
        assert_eq!(payload["preferred_username"], "alice");
    }

    #[tokio::test]
    async fn active_alg_empty_jwks_fails() {
        let mock = issuerd_core::MockCryptoProvider::new();
        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet { keys: vec![] },
        );

        let result = tm.active_alg(Algorithm::Rs256).await;
        assert!(matches!(result, Err(IssuerdError::ServerError(_))));
    }

    #[tokio::test]
    async fn issue_access_token_empty_jwks_fails() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_sign().never();
        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet { keys: vec![] },
        );

        let result = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await;
        assert!(matches!(result, Err(IssuerdError::ServerError(_))));
    }

    #[tokio::test]
    async fn id_token_claims_come_from_overlay() {
        // Scopes no longer gate claims inside the token manager:
        // without an overlay the signed payload carries no profile/email/
        // address/phone claims at all; with an overlay it carries exactly the
        // overlay entries.
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let user = test_user();
        let client = test_client();
        let realm = test_realm();
        let session_id = SessionId::new("s1").unwrap();
        let now = Utc::now();

        // No overlay — payload contains none of the profile-family claims,
        // even though the user has names and an e-mail address.
        let id_token = tm
            .issue_id_token(&user, &client, &realm, None, now, &session_id, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(id_token.claims.given_name, None);
        assert_eq!(id_token.claims.family_name, None);
        assert_eq!(id_token.claims.preferred_username, None);
        assert_eq!(id_token.claims.email, None);
        assert_eq!(id_token.claims.email_verified, None);
        assert_eq!(id_token.claims.address, None);
        assert_eq!(id_token.claims.phone_number, None);
        assert_eq!(id_token.claims.phone_number_verified, None);
        let payload = decode_payload(&id_token.token);
        for key in [
            "name",
            "given_name",
            "family_name",
            "preferred_username",
            "email",
            "email_verified",
            "address",
            "phone_number",
            "phone_number_verified",
        ] {
            assert!(payload.get(key).is_none(), "payload must not contain {key}");
        }

        // Overlay supplied by the caller — every entry lands in the signed
        // payload while the typed struct fields stay None.
        let mut overlay = serde_json::Map::new();
        overlay.insert("given_name".to_string(), serde_json::json!("Alice"));
        overlay.insert("family_name".to_string(), serde_json::json!("Smith"));
        overlay.insert("preferred_username".to_string(), serde_json::json!("alice"));
        overlay.insert("email".to_string(), serde_json::json!("alice@example.com"));
        overlay.insert("email_verified".to_string(), serde_json::json!(true));
        let id_token = tm
            .issue_id_token(
                &user,
                &client,
                &realm,
                None,
                now,
                &session_id,
                None,
                None,
                None,
                Some(overlay),
            )
            .await
            .unwrap();
        assert_eq!(id_token.claims.given_name, None);
        assert_eq!(id_token.claims.family_name, None);
        assert_eq!(id_token.claims.preferred_username, None);
        assert_eq!(id_token.claims.email, None);
        assert_eq!(id_token.claims.email_verified, None);
        let payload = decode_payload(&id_token.token);
        assert_eq!(payload["given_name"], "Alice");
        assert_eq!(payload["family_name"], "Smith");
        assert_eq!(payload["preferred_username"], "alice");
        assert_eq!(payload["email"], "alice@example.com");
        assert_eq!(payload["email_verified"], true);
    }

    #[tokio::test]
    async fn id_token_empty_overlay_emits_no_profile_claims() {
        // OIDC Core §5.4 (userinfo claims stay out of the ID token when an
        // access token or code is issued alongside) is now applied by the
        // caller passing an empty overlay; the token manager itself
        // no longer inspects scopes or the access_token/code parameters for
        // claim gating.
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let user = test_user();
        let client = test_client();
        let realm = test_realm();
        let session_id = SessionId::new("s1").unwrap();
        let now = Utc::now();

        let profile_keys = [
            "name",
            "given_name",
            "family_name",
            "preferred_username",
            "email",
            "email_verified",
        ];

        // access_token present (token endpoint) + empty overlay: hashes are
        // emitted, profile claims are not.
        let id_token = tm
            .issue_id_token(
                &user,
                &client,
                &realm,
                None,
                now,
                &session_id,
                Some(&AccessToken {
                    token: "at".to_string(),
                    claims: AccessTokenClaims {
                        jti: issuerd_core::JwtId::new("jti").unwrap(),
                        iss: Issuer::new("https://iss").unwrap(),
                        sub: UserId::new("u1").unwrap(),
                        aud: Audience::new("aud").unwrap(),
                        exp: 0,
                        iat: 0,
                        nbf: 0,
                        scope: issuerd_core::Scope::parse("openid profile email"),
                        typ: JwtType::Bearer,
                        azp: None,
                        session_state: None,
                        realm_access: None,
                        resource_access: None,
                        sid: None,
                        claims: None,
                        cnf: None,
                        authorization_details: None,
                    },
                }),
                None,
                None,
                Some(serde_json::Map::new()),
            )
            .await
            .unwrap();
        assert!(id_token.claims.at_hash.is_some());
        assert_eq!(id_token.claims.given_name, None);
        assert_eq!(id_token.claims.family_name, None);
        assert_eq!(id_token.claims.preferred_username, None);
        assert_eq!(id_token.claims.email, None);
        assert_eq!(id_token.claims.email_verified, None);
        let payload = decode_payload(&id_token.token);
        assert!(payload.get("at_hash").is_some());
        for key in profile_keys {
            assert!(payload.get(key).is_none(), "payload must not contain {key}");
        }

        // code present (hybrid flow authorization endpoint) + empty overlay:
        // same outcome, with c_hash instead.
        let id_token = tm
            .issue_id_token(
                &user,
                &client,
                &realm,
                None,
                now,
                &session_id,
                None,
                Some("code"),
                None,
                Some(serde_json::Map::new()),
            )
            .await
            .unwrap();
        assert!(id_token.claims.c_hash.is_some());
        assert_eq!(id_token.claims.given_name, None);
        assert_eq!(id_token.claims.family_name, None);
        assert_eq!(id_token.claims.preferred_username, None);
        assert_eq!(id_token.claims.email, None);
        assert_eq!(id_token.claims.email_verified, None);
        let payload = decode_payload(&id_token.token);
        assert!(payload.get("c_hash").is_some());
        for key in profile_keys {
            assert!(payload.get(key).is_none(), "payload must not contain {key}");
        }
    }

    #[tokio::test]
    async fn id_token_address_and_phone_claims_via_overlay() {
        // Address/phone claims are overlay-driven: the caller
        // supplies exactly the claims the resolved client scopes produced.
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let client = test_client();
        let realm = test_realm();
        let session_id = SessionId::new("s1").unwrap();
        let now = Utc::now();

        // Phone-only overlay — phone claims on the wire, address absent.
        let mut overlay = serde_json::Map::new();
        overlay.insert("phone_number".to_string(), serde_json::json!("+1-555-123-4567"));
        overlay.insert("phone_number_verified".to_string(), serde_json::json!(true));
        let id_token = tm
            .issue_id_token(
                &test_user(),
                &client,
                &realm,
                None,
                now,
                &session_id,
                None,
                None,
                None,
                Some(overlay),
            )
            .await
            .unwrap();
        assert_eq!(id_token.claims.address, None);
        assert_eq!(id_token.claims.phone_number, None);
        assert_eq!(id_token.claims.phone_number_verified, None);
        let payload = decode_payload(&id_token.token);
        assert!(payload.get("address").is_none());
        assert_eq!(payload["phone_number"], "+1-555-123-4567");
        assert_eq!(payload["phone_number_verified"], true);

        // Address + phone overlay — both present, sparse address sub-fields
        // are passed through verbatim.
        let mut overlay = serde_json::Map::new();
        overlay.insert(
            "address".to_string(),
            serde_json::json!({
                "formatted": "123 Main St, Springfield, IL",
                "street_address": "123 Main St",
                "locality": "Springfield",
                "country": "US",
            }),
        );
        overlay.insert("phone_number".to_string(), serde_json::json!("+1-555-123-4567"));
        let id_token = tm
            .issue_id_token(
                &test_user(),
                &client,
                &realm,
                None,
                now,
                &session_id,
                None,
                None,
                None,
                Some(overlay),
            )
            .await
            .unwrap();
        let payload = decode_payload(&id_token.token);
        let addr = payload.get("address").expect("address claim in signed payload");
        assert_eq!(addr["formatted"], "123 Main St, Springfield, IL");
        assert_eq!(addr["street_address"], "123 Main St");
        assert_eq!(addr["locality"], "Springfield");
        assert!(addr.get("region").is_none());
        assert!(addr.get("postal_code").is_none());
        assert_eq!(addr["country"], "US");
        assert_eq!(payload["phone_number"], "+1-555-123-4567");

        // No overlay — neither claim is emitted.
        let id_token = tm
            .issue_id_token(
                &test_user(),
                &client,
                &realm,
                None,
                now,
                &session_id,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(id_token.claims.address, None);
        assert_eq!(id_token.claims.phone_number, None);
        assert_eq!(id_token.claims.phone_number_verified, None);
        let payload = decode_payload(&id_token.token);
        assert!(payload.get("address").is_none());
        assert!(payload.get("phone_number").is_none());
        assert!(payload.get("phone_number_verified").is_none());
    }

    #[tokio::test]
    async fn id_token_acr_from_acr_values() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_sign().times(2).returning(|_, _, _| Ok("header.payload.sig".into()));
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );

        let user = test_user();
        let client = test_client();
        let realm = test_realm();
        let session_id = SessionId::new("s1").unwrap();
        let now = Utc::now();

        // acr_values provided — first value is emitted
        let id_token = tm
            .issue_id_token(
                &user,
                &client,
                &realm,
                None,
                now,
                &session_id,
                None,
                None,
                Some(&["1".to_string(), "2".to_string()]),
                None,
            )
            .await
            .unwrap();
        assert_eq!(id_token.claims.acr, Some(Acr::new("1").unwrap()));

        // acr_values empty / None — acr claim absent
        let id_token = tm
            .issue_id_token(&user, &client, &realm, None, now, &session_id, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(id_token.claims.acr, None);
    }

    #[tokio::test]
    async fn logout_token_issuance() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_sign().times(1).returning(|_, _, _| Ok("header.payload.sig".into()));
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );

        let logout = tm
            .issue_logout_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        assert!(logout
            .claims
            .events
            .get("http://schemas.openid.net/event/backchannel-logout")
            .is_some());
        assert_eq!(logout.claims.sid, SessionId::new("s1").unwrap());
    }

    // ------------------------------------------------------------------
    // Validation tests
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn access_token_validate_roundtrip() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        let validated = tm.validate_access_token(&token.token).unwrap();
        assert_eq!(validated.claims.sub, UserId::new("user-1").unwrap());
        assert_eq!(validated.claims.iss.as_str(), "https://issuer/realms/test");
    }

    #[tokio::test]
    async fn expired_access_token_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(0),
            jwks,
        );

        let mut realm = test_realm();
        realm.access_token_lifespan = issuerd_core::SecondsNonZero::new(1); // 1 second

        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &realm,
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        // Wait for token to expire.
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(matches!(
            tm.validate_access_token(&token.token),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn wrong_issuer_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks.clone(),
        );

        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        let evil_tm =
            TokenManager::new(crypto, "https://evil".to_string(), Duration::from_secs(60), jwks);
        assert!(matches!(
            evil_tm.validate_access_token(&token.token),
            Err(IssuerdError::InvalidToken)
        ));
    }

    /// Token manager for pure issuer-check tests: the check never touches
    /// the crypto provider, so an expectation-less mock is fine.
    fn issuer_check_tm(base: &str) -> TokenManager<issuerd_core::MockCryptoProvider> {
        TokenManager::new(
            Arc::new(issuerd_core::MockCryptoProvider::new()),
            base.to_string(),
            Duration::from_secs(60),
            JwkSet { keys: vec![] },
        )
    }

    #[test]
    fn realm_issuer_check_accepts_legitimate_issuers() {
        let tm = issuer_check_tm("https://ex.com");
        for iss in [
            "https://ex.com/realms/master",
            "https://ex.com/realms/my-realm_1.2",
            // An explicit default port still names the same origin.
            "https://ex.com:443/realms/master",
        ] {
            assert!(tm.is_realm_issuer(iss), "expected {iss} to be accepted");
        }

        // Base URL with an explicit non-default port.
        let tm = issuer_check_tm("https://ex.com:8443");
        assert!(tm.is_realm_issuer("https://ex.com:8443/realms/master"));

        // Base URL carrying a path prefix.
        let tm = issuer_check_tm("https://ex.com/iam");
        assert!(tm.is_realm_issuer("https://ex.com/iam/realms/master"));
    }

    #[test]
    fn realm_issuer_check_rejects_malformed_issuers() {
        let tm = issuer_check_tm("https://ex.com");
        for iss in [
            // Trailing slash.
            "https://ex.com/realms/master/",
            // Extra path segment.
            "https://ex.com/realms/master/extra",
            // The `realms` path segment is case-sensitive.
            "https://ex.com/REALMS/master",
            "https://ex.com/Realms/master",
            // Missing realm name.
            "https://ex.com/realms",
            "https://ex.com/realms/",
            // URL normalization swallows the dot segment, leaving no name.
            "https://ex.com/realms/..",
            // Scheme mismatch (http vs https).
            "http://ex.com/realms/master",
            // Non-default port where the base has none.
            "https://ex.com:8443/realms/master",
            // Host suffix collision the old starts_with check accepted.
            "https://ex.com.evil.com/realms/master",
            // Userinfo must not smuggle a foreign authority past the check.
            "https://ex.com@evil.com/realms/master",
            "https://evil.com@ex.com/realms/master",
            // Query and fragment are not part of an issuer.
            "https://ex.com/realms/master?x=1",
            "https://ex.com/realms/master#frag",
            // Percent-encoded / otherwise invalid realm names.
            "https://ex.com/realms/my%20realm",
            "https://ex.com/realms/a%2Fb",
            // Different host, wrong path shape, not a URL, empty.
            "https://evil.com/realms/master",
            "https://ex.com/other/master",
            "not-a-url",
            "",
        ] {
            assert!(!tm.is_realm_issuer(iss), "expected {iss} to be rejected");
        }

        // Explicit-port base rejects a missing or different port.
        let tm = issuer_check_tm("https://ex.com:8443");
        assert!(!tm.is_realm_issuer("https://ex.com/realms/master"));
        assert!(!tm.is_realm_issuer("https://ex.com:443/realms/master"));

        // Path-prefix base requires the prefix.
        let tm = issuer_check_tm("https://ex.com/iam");
        assert!(!tm.is_realm_issuer("https://ex.com/realms/master"));
    }

    fn access_claims_with_issuer(iss: &str) -> AccessTokenClaims {
        AccessTokenClaims {
            jti: issuerd_core::JwtId::new("jti").unwrap(),
            iss: Issuer::new(iss).unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("aud").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            nbf: Utc::now().timestamp() - 1,
            scope: issuerd_core::Scope::parse("openid"),
            typ: JwtType::Bearer,
            azp: None,
            session_state: None,
            realm_access: None,
            resource_access: None,
            sid: Some(SessionId::new("s1").unwrap()),
            claims: None,
            cnf: None,
            authorization_details: None,
        }
    }

    #[tokio::test]
    async fn access_token_malformed_issuer_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm =
            TokenManager::new(crypto, "https://issuer".to_string(), Duration::from_secs(60), jwks);

        // Sanity: the legitimate realm issuer still validates end-to-end.
        let (token, _) = tm
            .sign_claims(&access_claims_with_issuer("https://issuer/realms/test"), Algorithm::Rs256)
            .await
            .unwrap();
        assert!(tm.validate_access_token(&token).is_ok());

        for bad_iss in [
            // Host suffix collision: starts with the base URL string.
            "https://issuer.evil.com/realms/test",
            "https://issuer/realms/test/",
            "https://issuer/realms/test/extra",
            "http://issuer/realms/test",
            "https://issuer/realms/test?x=1",
        ] {
            let (token, _) = tm
                .sign_claims(&access_claims_with_issuer(bad_iss), Algorithm::Rs256)
                .await
                .unwrap();
            assert!(
                matches!(tm.validate_access_token(&token), Err(IssuerdError::InvalidToken)),
                "expected {bad_iss} to be rejected"
            );
        }
    }

    #[tokio::test]
    async fn id_token_malformed_issuer_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm =
            TokenManager::new(crypto, "https://issuer".to_string(), Duration::from_secs(60), jwks);

        let id_claims = |iss: &str| IdTokenClaims {
            iss: Issuer::new(iss).unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("my-app").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            auth_time: Some(Utc::now().timestamp()),
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            sid: Some(SessionId::new("s1").unwrap()),
            at_hash: None,
            c_hash: None,
            name: None,
            given_name: None,
            family_name: None,
            preferred_username: None,
            email: None,
            email_verified: None,
            address: None,
            phone_number: None,
            phone_number_verified: None,
            realm_access: None,
            resource_access: None,
        };

        // Sanity: the legitimate realm issuer still validates end-to-end.
        let (token, _) = tm
            .sign_claims(&id_claims("https://issuer/realms/test"), Algorithm::Rs256)
            .await
            .unwrap();
        assert!(tm.validate_id_token(&token, &test_client(), None).is_ok());
        assert!(tm.validate_id_token_hint(&token).is_ok());

        for bad_iss in [
            "https://issuer.evil.com/realms/test",
            "https://issuer/realms/test/",
            "https://issuer/realms/test/extra",
            "http://issuer/realms/test",
            "https://issuer/realms/test#frag",
        ] {
            let (token, _) = tm.sign_claims(&id_claims(bad_iss), Algorithm::Rs256).await.unwrap();
            assert!(
                matches!(
                    tm.validate_id_token(&token, &test_client(), None),
                    Err(IssuerdError::InvalidToken)
                ),
                "expected {bad_iss} to be rejected by validate_id_token"
            );
            assert!(
                matches!(tm.validate_id_token_hint(&token), Err(IssuerdError::InvalidToken)),
                "expected {bad_iss} to be rejected by validate_id_token_hint"
            );
        }
    }

    #[tokio::test]
    async fn introspection_active_and_inactive() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        let session = UserSession {
            id: SessionId::new("s1").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            user_id: UserId::new("user-1").unwrap(),
            login_username: issuerd_core::Username::new("alice").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: Utc::now(),
            last_session_refresh: Utc::now(),
            auth_time: Utc::now(),
            impersonator: None,
            clients: vec![],
        };

        let resp = tm.introspect(&token.token, Some(&session)).unwrap();
        assert!(resp.active);
        assert_eq!(resp.username, Some(Username::new("alice").unwrap()));

        let resp2 = tm.introspect("not.a.token", None).unwrap();
        assert!(!resp2.active);
    }

    // ------------------------------------------------------------------
    // Key rotation E2E
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn token_valid_after_key_rotation() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        // Validate before rotation.
        assert!(tm.validate_access_token(&token.token).is_ok());

        // Rotate keys.
        crypto.rotate_keys().await.unwrap();
        tm.refresh_jwks().await.unwrap();

        // Validate after rotation — passive key should still verify.
        assert!(tm.validate_access_token(&token.token).is_ok());

        // New token should also validate.
        let new_token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();
        assert!(tm.validate_access_token(&new_token.token).is_ok());
    }

    #[tokio::test]
    async fn mock_provider_usable_for_validation() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });
        mock.expect_get_active_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );

        // We can't validate a real token with a mock provider that can't sign,
        // but we can prove the JWKS cache is populated.
        assert!(tm.refresh_jwks().await.is_ok());
    }

    #[tokio::test]
    async fn unknown_kid_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let _jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto,
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet { keys: vec![] },
        );

        assert!(matches!(tm.validate_access_token("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im5vbmUifQ.eyJzdWIiOiJ1c2VyLTEifQ.invalid"), Err(IssuerdError::InvalidToken)));
    }

    #[tokio::test]
    async fn access_token_with_roles() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_sign().times(1).returning(|_, _, _| Ok("header.payload.sig".into()));
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );

        let realm_access = issuerd_core::RealmAccess {
            roles: vec![
                issuerd_core::RoleName::new("admin").unwrap(),
                issuerd_core::RoleName::new("user").unwrap(),
            ],
        };

        let token = tm
            .issue_access_token_with_roles(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
                Some(realm_access.clone()),
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(token.claims.realm_access, Some(realm_access));
    }

    // ------------------------------------------------------------------
    // Claims overlay
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn access_token_overlay_realm_access_roundtrip() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let mut overlay = serde_json::Map::new();
        overlay
            .insert("realm_access".to_string(), serde_json::json!({ "roles": ["admin", "user"] }));

        let token = tm
            .issue_access_token_with_roles(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
                None,
                None,
                Some(overlay),
            )
            .await
            .unwrap();

        // The returned struct does not carry overlay entries...
        assert_eq!(token.claims.realm_access, None);

        // ...but the signed payload does, and stateless validation decodes
        // it back into the typed field.
        let payload = decode_payload(&token.token);
        assert_eq!(payload["realm_access"], serde_json::json!({ "roles": ["admin", "user"] }));
        let validated = tm.validate_access_token(&token.token).unwrap();
        assert_eq!(
            validated.claims.realm_access,
            Some(issuerd_core::RealmAccess {
                roles: vec![
                    issuerd_core::RoleName::new("admin").unwrap(),
                    issuerd_core::RoleName::new("user").unwrap(),
                ],
            })
        );
    }

    #[tokio::test]
    async fn access_token_overlay_reserved_claims_filtered() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let mut overlay = serde_json::Map::new();
        overlay.insert("iss".to_string(), serde_json::json!("https://evil/realms/test"));
        overlay.insert("sub".to_string(), serde_json::json!("attacker"));
        overlay.insert("exp".to_string(), serde_json::json!(4_000_000_000i64));

        let token = tm
            .issue_access_token_with_roles(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
                None,
                None,
                Some(overlay),
            )
            .await
            .unwrap();

        // Reserved keys are always taken from the typed claims struct.
        let payload = decode_payload(&token.token);
        assert_eq!(payload["iss"], "https://issuer/realms/test");
        assert_eq!(payload["sub"], "user-1");
        assert_eq!(payload["exp"], token.claims.exp);

        let validated = tm.validate_access_token(&token.token).unwrap();
        assert_eq!(validated.claims.sub, UserId::new("user-1").unwrap());
        assert_eq!(validated.claims.iss.as_str(), "https://issuer/realms/test");
    }

    #[tokio::test]
    async fn access_token_overlay_aud_array_validates() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        // An audience mapper may legitimately widen `aud` to a JSON array.
        let mut overlay = serde_json::Map::new();
        overlay.insert("aud".to_string(), serde_json::json!(["my-app", "other"]));

        let token = tm
            .issue_access_token_with_roles(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
                None,
                None,
                Some(overlay),
            )
            .await
            .unwrap();

        let payload = decode_payload(&token.token);
        assert_eq!(payload["aud"], serde_json::json!(["my-app", "other"]));

        // Validation still works: Audience deserialization tolerates the
        // multi-audience array form and takes the first entry.
        let validated = tm.validate_access_token(&token.token).unwrap();
        assert_eq!(validated.claims.aud, Audience::new("my-app").unwrap());
    }

    #[tokio::test]
    async fn refresh_token_validate_roundtrip() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let token = tm
            .issue_refresh_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &SessionId::new("s1").unwrap(),
                &["openid".to_string()],
                false,
                None,
                None,
            )
            .await
            .unwrap();

        let validated = tm.validate_refresh_token(&token.token).unwrap();
        assert_eq!(validated.claims.sub, UserId::new("user-1").unwrap());
        assert_eq!(validated.claims.typ, JwtType::Refresh);
    }

    #[tokio::test]
    async fn offline_refresh_token_validate_roundtrip() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        // Offline refresh tokens (typ: Offline) pass the same validation path
        // as online ones; access tokens still do not (covered by
        // access_token_rejected_as_refresh_token).
        let token = tm
            .issue_refresh_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &SessionId::new("s1").unwrap(),
                &["openid".to_string(), "offline_access".to_string()],
                true,
                None,
                None,
            )
            .await
            .unwrap();

        let validated = tm.validate_refresh_token(&token.token).unwrap();
        assert_eq!(validated.claims.sub, UserId::new("user-1").unwrap());
        assert_eq!(validated.claims.typ, JwtType::Offline);
    }

    #[tokio::test]
    async fn access_token_rejected_as_refresh_token() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        // Access tokens share most of the refresh-token claim shape; the typ
        // claim must keep them out of the refresh path (hint-less revocation
        // probes and the refresh grant both rely on this).
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();
        assert!(tm.validate_refresh_token(&token.token).is_err());
    }

    #[tokio::test]
    async fn refresh_token_expired_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(0),
            jwks,
        );

        let mut realm = test_realm();
        realm.refresh_token_lifespan = SecondsNonZero::new(1);

        let token = tm
            .issue_refresh_token(
                &test_user(),
                &test_client(),
                &realm,
                &SessionId::new("s1").unwrap(),
                &["openid".to_string()],
                false,
                None,
                None,
            )
            .await
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(matches!(
            tm.validate_refresh_token(&token.token),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn id_token_validate_roundtrip() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                Some("nonce-123"),
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let claims = tm
            .validate_id_token(&id_token.token, &test_client(), Some("nonce-123"))
            .unwrap();
        assert_eq!(claims.sub, UserId::new("user-1").unwrap());
        assert_eq!(claims.nonce, Some(Nonce::new("nonce-123").unwrap()));
    }

    #[tokio::test]
    async fn id_token_wrong_nonce_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                Some("nonce-123"),
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        assert!(matches!(
            tm.validate_id_token(&id_token.token, &test_client(), Some("wrong-nonce")),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn id_token_wrong_aud_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                None,
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let mut evil_client = test_client();
        evil_client.client_id = ClientIdentifier::new("evil-app").unwrap();

        assert!(matches!(
            tm.validate_id_token(&id_token.token, &evil_client, None),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn id_token_wrong_azp_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let mut evil_client = test_client();
        evil_client.client_id = ClientIdentifier::new("evil-app").unwrap();
        // Craft a token where aud matches evil_client but azp is my-app.
        let bad_claims = IdTokenClaims {
            iss: Issuer::new("https://issuer/realms/test").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("evil-app").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            auth_time: Some(Utc::now().timestamp()),
            nonce: None,
            acr: None,
            amr: None,
            azp: Some("my-app".to_string()),
            sid: Some(SessionId::new("s1").unwrap()),
            at_hash: None,
            c_hash: None,
            name: None,
            given_name: None,
            family_name: None,
            preferred_username: Some(Username::new("alice").unwrap()),
            email: None,
            email_verified: None,
            address: None,
            phone_number: None,
            phone_number_verified: None,
            realm_access: None,
            resource_access: None,
        };

        let (token, _) = tm.sign_claims(&bad_claims, Algorithm::Rs256).await.unwrap();

        assert!(matches!(
            tm.validate_id_token(&token, &evil_client, None),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn decode_token_enforces_pinned_audience() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm =
            TokenManager::new(crypto, "https://issuer".to_string(), Duration::from_secs(60), jwks);

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                None,
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // The matching pinned audience decodes.
        assert!(tm.decode_token::<IdTokenClaims>(&id_token.token, true, Some("my-app")).is_ok());
        // A wrong pinned audience is rejected by the jsonwebtoken check itself
        // (decode_token has no manual aud check of its own).
        assert!(matches!(
            tm.decode_token::<IdTokenClaims>(&id_token.token, true, Some("other-app")),
            Err(IssuerdError::InvalidToken)
        ));
        // No pin → no audience enforcement at this layer (callers check aud).
        assert!(tm.decode_token::<IdTokenClaims>(&id_token.token, true, None).is_ok());
    }

    #[tokio::test]
    async fn id_token_expired_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(0),
            jwks,
        );

        let mut realm = test_realm();
        realm.access_token_lifespan = issuerd_core::SecondsNonZero::new(1);

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &realm,
                None,
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(matches!(
            tm.validate_id_token(&id_token.token, &test_client(), None),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn token_service_validate_access_token() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        let service: Arc<dyn issuerd_core::TokenService> = Arc::new(tm);
        let validated = service.validate_access_token(&token.token).unwrap();
        assert_eq!(validated.claims.sub, UserId::new("user-1").unwrap());
    }

    #[tokio::test]
    async fn token_service_validate_id_token() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                Some("nonce-123"),
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let service: Arc<dyn issuerd_core::TokenService> = Arc::new(tm);
        let claims = service
            .validate_id_token(&id_token.token, &test_client(), Some("nonce-123"))
            .unwrap();
        assert_eq!(claims.sub, UserId::new("user-1").unwrap());
    }

    #[tokio::test]
    async fn active_alg_empty_jwks_error() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_get_public_keys().returning(|| Ok(JwkSet { keys: vec![] }));

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet { keys: vec![] },
        );

        let result = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &[],
                &SessionId::new("s1").unwrap(),
            )
            .await;
        assert!(matches!(
            result,
            Err(IssuerdError::ServerError(ref msg)) if msg == "no active signing keys"
        ));
    }

    #[tokio::test]
    async fn validate_access_token_invalid_iat_future() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(0),
            jwks,
        );

        // Manually create claims with iat in the future.
        let future_iat = Utc::now().timestamp() + 3600;
        let claims = AccessTokenClaims {
            jti: issuerd_core::JwtId::new("jti").unwrap(),
            iss: Issuer::new("https://issuer").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("my-app").unwrap(),
            exp: future_iat + 300,
            iat: future_iat,
            nbf: 0,
            scope: issuerd_core::Scope::parse("openid"),
            typ: JwtType::Bearer,
            azp: None,
            session_state: None,
            realm_access: None,
            resource_access: None,
            sid: None,
            claims: None,
            cnf: None,
            authorization_details: None,
        };

        let (token, _) = tm.sign_claims(&claims, Algorithm::Rs256).await.unwrap();
        assert!(matches!(tm.validate_access_token(&token), Err(IssuerdError::InvalidToken)));
    }

    // ------------------------------------------------------------------
    // jwk_to_decoding_key & map_jwt_alg coverage
    // ------------------------------------------------------------------

    #[test]
    fn jwk_to_decoding_key_missing_rsa_n() {
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
        let result = jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing modulus"));
    }

    #[test]
    fn jwk_to_decoding_key_missing_rsa_e() {
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
        let result = jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing exponent"));
    }

    #[test]
    fn jwk_to_decoding_key_missing_ec_x() {
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
        let result = jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing x"));
    }

    #[test]
    fn jwk_to_decoding_key_missing_ec_y() {
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
        let result = jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing y"));
    }

    #[test]
    fn jwk_to_decoding_key_missing_okp_x() {
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
        let result = jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing x"));
    }

    #[test]
    fn jwk_to_decoding_key_missing_oct_k() {
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
        let result = jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(err.to_string().contains("missing k"));
    }

    #[test]
    fn jwk_to_decoding_key_unknown_kty_rejected_at_deserialization() {
        let json = r#"{"kty":"UNKNOWN","kid":"k1","alg":"RS256","use":"sig"}"#;
        let result = serde_json::from_str::<Jwk>(json);
        assert!(result.is_err());
    }

    #[test]
    fn map_jwt_alg_all_variants() {
        assert_eq!(map_jwt_alg(jsonwebtoken::Algorithm::RS256).unwrap(), Algorithm::Rs256);
        assert_eq!(map_jwt_alg(jsonwebtoken::Algorithm::RS384).unwrap(), Algorithm::Rs384);
        assert_eq!(map_jwt_alg(jsonwebtoken::Algorithm::RS512).unwrap(), Algorithm::Rs512);
        assert_eq!(map_jwt_alg(jsonwebtoken::Algorithm::ES256).unwrap(), Algorithm::Es256);
        assert_eq!(map_jwt_alg(jsonwebtoken::Algorithm::ES384).unwrap(), Algorithm::Es384);
        assert_eq!(map_jwt_alg(jsonwebtoken::Algorithm::HS256).unwrap(), Algorithm::Hs256);
        assert_eq!(map_jwt_alg(jsonwebtoken::Algorithm::HS384).unwrap(), Algorithm::Hs384);
        assert_eq!(map_jwt_alg(jsonwebtoken::Algorithm::HS512).unwrap(), Algorithm::Hs512);
        assert_eq!(map_jwt_alg(jsonwebtoken::Algorithm::EdDSA).unwrap(), Algorithm::EdDsa);
    }

    #[tokio::test]
    async fn alg_none_token_rejected() {
        // Craft a raw JWT with alg=none. jsonwebtoken does not recognise "none",
        // so decode_header should fail and our validation must reject it.
        let none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyLTEifQ.";

        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto,
            "https://issuer".to_string(),
            std::time::Duration::from_secs(60),
            jwks,
        );

        assert!(matches!(tm.validate_access_token(none_token), Err(IssuerdError::InvalidToken)));
    }

    /// Feed 1000 random strings into token validation and ensure it never panics.
    #[tokio::test]
    async fn validate_never_panics_on_random_input() {
        use rand::Rng;
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto,
            "https://issuer".to_string(),
            std::time::Duration::from_secs(60),
            jwks,
        );

        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let len = rng.gen_range(0..256);
            let garbage: String = (0..len).map(|_| rng.gen_range(0u8..128u8) as char).collect();
            let _ = tm.validate_access_token(&garbage);
        }
    }

    #[tokio::test]
    async fn id_token_aud_mismatch_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let mut evil_client = test_client();
        evil_client.client_id = ClientIdentifier::new("evil-app").unwrap();
        let bad_claims = IdTokenClaims {
            iss: Issuer::new("https://issuer/realms/test").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("my-app").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            auth_time: Some(Utc::now().timestamp()),
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            sid: Some(SessionId::new("s1").unwrap()),
            at_hash: None,
            c_hash: None,
            name: None,
            given_name: None,
            family_name: None,
            preferred_username: Some(Username::new("alice").unwrap()),
            email: None,
            email_verified: None,
            address: None,
            phone_number: None,
            phone_number_verified: None,
            realm_access: None,
            resource_access: None,
        };

        let (token, _) = tm.sign_claims(&bad_claims, Algorithm::Rs256).await.unwrap();
        assert!(matches!(
            tm.validate_id_token(&token, &evil_client, None),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn token_service_trait_delegations() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let ts: &dyn issuerd_core::TokenService = &tm;
        let result = ts.validate_access_token("not.a.token");
        assert!(matches!(result, Err(IssuerdError::InvalidToken)));

        let result = ts.validate_refresh_token("not.a.token");
        assert!(matches!(result, Err(IssuerdError::InvalidToken)));

        let result = ts.validate_id_token("not.a.token", &test_client(), None);
        assert!(matches!(result, Err(IssuerdError::InvalidToken)));
    }

    #[tokio::test]
    async fn token_issuer_trait_delegations() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let ti: &dyn crate::TokenIssuer = &tm;
        let at = ti
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &[],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();
        assert!(!at.token.is_empty());

        let rt = ti
            .issue_refresh_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &SessionId::new("s1").unwrap(),
                &[],
                false,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(!rt.token.is_empty());

        let idt = ti
            .issue_id_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                None,
                Utc::now(),
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(!idt.token.is_empty());

        let at_roles = ti
            .issue_access_token_with_roles(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["admin".to_string()],
                &SessionId::new("s1").unwrap(),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(!at_roles.token.is_empty());
    }

    #[test]
    fn jwk_to_decoding_key_invalid_oct_base64() {
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
        let result = jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("base64")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn refresh_jwks_error_propagates() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_get_public_keys()
            .returning(|| Err(IssuerdError::ServerError("crypto down".into())));

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet { keys: vec![] },
        );

        let result = tm.refresh_jwks().await;
        assert!(matches!(result, Err(IssuerdError::ServerError(_))));
    }

    #[tokio::test]
    async fn sign_claims_error_propagates() {
        let mut mock = issuerd_core::MockCryptoProvider::new();
        mock.expect_get_public_keys().returning(|| {
            Ok(JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            })
        });
        mock.expect_sign()
            .returning(|_, _, _| Err(IssuerdError::ServerError("signing failed".into())));

        let tm = TokenManager::new(
            Arc::new(mock),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet {
                keys: vec![test_jwk(Algorithm::Rs256)],
            },
        );

        let result = tm.sign_claims(&"test", Algorithm::Rs256).await;
        assert!(matches!(result, Err(IssuerdError::ServerError(_))));
    }

    #[tokio::test]
    async fn introspect_valid_token_without_session() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        let resp = tm.introspect(&token.token, None).unwrap();
        assert!(resp.active);
        assert_eq!(resp.username, None);
    }

    #[tokio::test]
    async fn refresh_token_future_iat_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let claims = RefreshTokenClaims {
            jti: issuerd_core::JwtId::new("jti").unwrap(),
            iss: Issuer::new("https://issuer/realms/test").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("aud").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp() + 1000, // future iat
            scope: issuerd_core::Scope::parse("openid"),
            typ: JwtType::Refresh,
            sid: SessionId::new("s1").unwrap(),
            cnf: None,
            authorization_details: None,
        };

        let (token, _) = tm.sign_claims(&claims, Algorithm::Rs256).await.unwrap();
        assert!(matches!(tm.validate_refresh_token(&token), Err(IssuerdError::InvalidToken)));
    }

    #[tokio::test]
    async fn refresh_token_wrong_issuer_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let claims = RefreshTokenClaims {
            jti: issuerd_core::JwtId::new("jti").unwrap(),
            iss: Issuer::new("https://evil/realms/test").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("aud").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            scope: issuerd_core::Scope::parse("openid"),
            typ: JwtType::Refresh,
            sid: SessionId::new("s1").unwrap(),
            cnf: None,
            authorization_details: None,
        };

        let (token, _) = tm.sign_claims(&claims, Algorithm::Rs256).await.unwrap();
        assert!(matches!(tm.validate_refresh_token(&token), Err(IssuerdError::InvalidToken)));
    }

    #[tokio::test]
    async fn refresh_token_malformed_issuer_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let refresh_claims = |iss: &str| RefreshTokenClaims {
            jti: issuerd_core::JwtId::new("jti").unwrap(),
            iss: Issuer::new(iss).unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("aud").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            scope: issuerd_core::Scope::parse("openid"),
            typ: JwtType::Refresh,
            sid: SessionId::new("s1").unwrap(),
            cnf: None,
            authorization_details: None,
        };

        // Sanity: the legitimate realm issuer still validates end-to-end.
        let (token, _) = tm
            .sign_claims(&refresh_claims("https://issuer/realms/test"), Algorithm::Rs256)
            .await
            .unwrap();
        assert!(tm.validate_refresh_token(&token).is_ok());

        for bad_iss in [
            "https://issuer.evil.com/realms/test",
            "https://issuer/realms/test/",
            "https://issuer/realms/test/extra",
            "http://issuer/realms/test",
        ] {
            let (token, _) =
                tm.sign_claims(&refresh_claims(bad_iss), Algorithm::Rs256).await.unwrap();
            assert!(
                matches!(tm.validate_refresh_token(&token), Err(IssuerdError::InvalidToken)),
                "expected {bad_iss} to be rejected"
            );
        }
    }

    #[tokio::test]
    async fn id_token_future_iat_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let claims = IdTokenClaims {
            iss: Issuer::new("https://issuer/realms/test").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("my-app").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp() + 1000, // future iat
            auth_time: Some(Utc::now().timestamp()),
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            sid: Some(SessionId::new("s1").unwrap()),
            at_hash: None,
            c_hash: None,
            name: None,
            given_name: None,
            family_name: None,
            preferred_username: None,
            email: None,
            email_verified: None,
            address: None,
            phone_number: None,
            phone_number_verified: None,
            realm_access: None,
            resource_access: None,
        };

        let (token, _) = tm.sign_claims(&claims, Algorithm::Rs256).await.unwrap();
        assert!(matches!(
            tm.validate_id_token(&token, &test_client(), None),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn id_token_wrong_issuer_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let claims = IdTokenClaims {
            iss: Issuer::new("https://evil/realms/test").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("my-app").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            auth_time: Some(Utc::now().timestamp()),
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            sid: Some(SessionId::new("s1").unwrap()),
            at_hash: None,
            c_hash: None,
            name: None,
            given_name: None,
            family_name: None,
            preferred_username: None,
            email: None,
            email_verified: None,
            address: None,
            phone_number: None,
            phone_number_verified: None,
            realm_access: None,
            resource_access: None,
        };

        let (token, _) = tm.sign_claims(&claims, Algorithm::Rs256).await.unwrap();
        assert!(matches!(
            tm.validate_id_token(&token, &test_client(), None),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn id_token_missing_nonce_rejected() {
        let crypto = Arc::new(
            RingCryptoProvider::new(CryptoConfig {
                default_alg: Algorithm::Rs256,
                rsa_key_size: 2048,
            })
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        let claims = IdTokenClaims {
            iss: Issuer::new("https://issuer/realms/test").unwrap(),
            sub: UserId::new("user-1").unwrap(),
            aud: Audience::new("my-app").unwrap(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            auth_time: Some(Utc::now().timestamp()),
            nonce: None, // missing nonce
            acr: None,
            amr: None,
            azp: None,
            sid: Some(SessionId::new("s1").unwrap()),
            at_hash: None,
            c_hash: None,
            name: None,
            given_name: None,
            family_name: None,
            preferred_username: None,
            email: None,
            email_verified: None,
            address: None,
            phone_number: None,
            phone_number_verified: None,
            realm_access: None,
            resource_access: None,
        };

        let (token, _) = tm.sign_claims(&claims, Algorithm::Rs256).await.unwrap();
        assert!(matches!(
            tm.validate_id_token(&token, &test_client(), Some("expected-nonce")),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[test]
    fn refresh_token_missing_kid_rejected() {
        // JWT header without kid
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEifQ.invalid";
        let crypto = issuerd_core::MockCryptoProvider::new();
        let tm = TokenManager::new(
            Arc::new(crypto),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            JwkSet { keys: vec![] },
        );
        assert!(matches!(tm.validate_refresh_token(token), Err(IssuerdError::InvalidToken)));
    }

    // ------------------------------------------------------------------
    // Algorithm agility
    // ------------------------------------------------------------------

    /// Decode the header segment of a compact JWS into JSON.
    fn decode_header(token: &str) -> serde_json::Value {
        use base64::Engine;
        let segment = token.split('.').next().expect("compact JWS has a header");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .expect("header segment is base64url");
        serde_json::from_slice(&bytes).expect("header segment is JSON")
    }

    /// Token manager backed by a real provider with four ACTIVE keys of
    /// different algorithms: EdDSA (oldest), RS256, ES256, ES512 (newest).
    /// The JWKS snapshot therefore orders them `[ES512, ES256, RS256, EdDSA]`.
    async fn multi_alg_tm() -> (TokenManager<RingCryptoProvider>, Vec<(String, Algorithm)>) {
        let eddsa = KeyStore::generate_key(Algorithm::EdDsa, 2048).unwrap();
        let mut rsa = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        rsa.created_at = eddsa.created_at + chrono::Duration::seconds(1);
        let mut es256 = KeyStore::generate_key(Algorithm::Es256, 2048).unwrap();
        es256.created_at = eddsa.created_at + chrono::Duration::seconds(2);
        let mut es512 = KeyStore::generate_key(Algorithm::Es512, 2048).unwrap();
        es512.created_at = eddsa.created_at + chrono::Duration::seconds(3);
        let kids = vec![
            (eddsa.kid.to_string(), Algorithm::EdDsa),
            (rsa.kid.to_string(), Algorithm::Rs256),
            (es256.kid.to_string(), Algorithm::Es256),
            (es512.kid.to_string(), Algorithm::Es512),
        ];
        let stored = vec![
            eddsa.to_stored(true),
            rsa.to_stored(true),
            es256.to_stored(true),
            es512.to_stored(true),
        ];
        let crypto = Arc::new(
            RingCryptoProvider::from_signing_keys(CryptoConfig::default(), &stored).unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm =
            TokenManager::new(crypto, "https://issuer".to_string(), Duration::from_secs(60), jwks);
        (tm, kids)
    }

    fn realm_with_alg(alg: &str) -> Realm {
        let mut realm = test_realm();
        realm
            .attributes
            .insert(Realm::DEFAULT_SIGNATURE_ALGORITHM_ATTRIBUTE.to_string(), alg.to_string());
        realm
    }

    #[tokio::test]
    async fn realm_algorithm_selects_matching_active_key() {
        let (tm, kids) = multi_alg_tm().await;
        let es256_kid = &kids[2].0;
        let session = SessionId::new("s1").unwrap();

        // Realm pinned to ES256 signs with the active ES256 key.
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &realm_with_alg("ES256"),
                &["openid".to_string()],
                &session,
            )
            .await
            .unwrap();
        let header = decode_header(&token.token);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], es256_kid.as_str());
        assert!(tm.validate_access_token(&token.token).is_ok());

        // A realm without the attribute keeps the server default (EdDSA) even
        // though newer RS*/ES* keys are active.
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &session,
            )
            .await
            .unwrap();
        let header = decode_header(&token.token);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["kid"], kids[0].0.as_str());
        assert!(tm.validate_access_token(&token.token).is_ok());

        // A realm explicitly pinned to RS256 (compatibility choice) signs with
        // the active RS256 key.
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &realm_with_alg("RS256"),
                &["openid".to_string()],
                &session,
            )
            .await
            .unwrap();
        let header = decode_header(&token.token);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], kids[1].0.as_str());
        assert!(tm.validate_access_token(&token.token).is_ok());
    }

    #[tokio::test]
    async fn realm_algorithm_without_active_key_falls_back_to_default() {
        let (tm, kids) = multi_alg_tm().await;

        // No ES384 key exists: issuance falls back to the default signing key.
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &realm_with_alg("ES384"),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();
        let header = decode_header(&token.token);
        assert_eq!(header["alg"], "ES512", "keys[0] is the newest active key");
        assert_eq!(header["kid"], kids[3].0.as_str());
        assert!(tm.validate_access_token(&token.token).is_ok());
    }

    #[tokio::test]
    async fn realm_algorithm_with_only_passive_key_falls_back_to_default() {
        // One active RS256 key plus a passive (disabled) ES256 key — the state
        // after an admin disables the realm-pinned algorithm's only key.
        let rsa = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let mut es256 = KeyStore::generate_key(Algorithm::Es256, 2048).unwrap();
        es256.created_at = rsa.created_at + chrono::Duration::seconds(1);
        let rsa_kid = rsa.kid.to_string();
        let es256_kid = es256.kid.to_string();
        let stored = vec![rsa.to_stored(true), es256.to_stored(false)];
        let crypto = Arc::new(
            RingCryptoProvider::from_signing_keys(CryptoConfig::default(), &stored).unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        assert_eq!(jwks.keys.len(), 2, "passive keys stay published for verification");
        let tm =
            TokenManager::new(crypto, "https://issuer".to_string(), Duration::from_secs(60), jwks);
        // The constructor seeds the signing snapshot conservatively; a refresh
        // installs the true active-only set.
        tm.refresh_jwks().await.unwrap();

        // A realm pinned to ES256 must not sign with the disabled key: the
        // fallback is the newest ACTIVE key (RS256).
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &realm_with_alg("ES256"),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();
        let header = decode_header(&token.token);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], rsa_kid.as_str());
        assert_ne!(header["kid"], es256_kid.as_str(), "a disabled key must never sign");
        assert!(tm.validate_access_token(&token.token).is_ok());
    }

    #[tokio::test]
    async fn passive_key_tokens_still_validate_after_disable() {
        let key = KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        let crypto = Arc::new(
            RingCryptoProvider::from_signing_keys(CryptoConfig::default(), &[key.to_stored(true)])
                .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm = TokenManager::new(
            crypto.clone(),
            "https://issuer".to_string(),
            Duration::from_secs(60),
            jwks,
        );

        // Issued while the key is active.
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();

        // The admin disables the key; the node reloads provider + snapshots.
        crypto.reload_keys(&[key.to_stored(false)]).unwrap();
        tm.refresh_jwks().await.unwrap();

        // The passive key still verifies previously issued tokens...
        assert!(tm.validate_access_token(&token.token).is_ok());
        // ...but new issuance is impossible: no active signing keys remain.
        let result = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &test_realm(),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await;
        assert!(matches!(
            result,
            Err(IssuerdError::ServerError(ref msg)) if msg == "no active signing keys"
        ));
    }

    #[tokio::test]
    async fn es512_access_token_roundtrip() {
        let (tm, kids) = multi_alg_tm().await;
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &realm_with_alg("ES512"),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();
        let header = decode_header(&token.token);
        assert_eq!(header["alg"], "ES512");
        assert_eq!(header["kid"], kids[3].0.as_str());

        let validated = tm.validate_access_token(&token.token).unwrap();
        assert_eq!(validated.header.alg, Algorithm::Es512);
        assert_eq!(validated.claims.sub, UserId::new("user-1").unwrap());
    }

    #[tokio::test]
    async fn es512_id_token_roundtrip_with_at_hash() {
        let (tm, _) = multi_alg_tm().await;
        let realm = realm_with_alg("ES512");
        let session = SessionId::new("s1").unwrap();
        let access = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &realm,
                &["openid".to_string()],
                &session,
            )
            .await
            .unwrap();

        let id_token = tm
            .issue_id_token(
                &test_user(),
                &test_client(),
                &realm,
                Some("nonce-1"),
                Utc::now(),
                &session,
                Some(&access),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let header = decode_header(&id_token.token);
        assert_eq!(header["alg"], "ES512");
        // at_hash uses the JWS alg's hash (SHA-512 → 43 base64url chars).
        let at_hash = id_token.claims.at_hash.expect("at_hash present");
        assert_eq!(at_hash.as_ref().len(), 43);

        tm.validate_id_token(&id_token.token, &test_client(), Some("nonce-1")).unwrap();

        // Wrong audience and wrong nonce are rejected on the ES512 path too.
        let mut other_client = test_client();
        other_client.client_id = ClientIdentifier::new("other-app").unwrap();
        assert!(matches!(
            tm.validate_id_token(&id_token.token, &other_client, None),
            Err(IssuerdError::InvalidToken)
        ));
        assert!(matches!(
            tm.validate_id_token(&id_token.token, &test_client(), Some("wrong-nonce")),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn es512_refresh_token_roundtrip() {
        let (tm, _) = multi_alg_tm().await;
        let token = tm
            .issue_refresh_token(
                &test_user(),
                &test_client(),
                &realm_with_alg("ES512"),
                &SessionId::new("s1").unwrap(),
                &["openid".to_string()],
                false,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(decode_header(&token.token)["alg"], "ES512");
        let validated = tm.validate_refresh_token(&token.token).unwrap();
        assert_eq!(validated.header.alg, Algorithm::Es512);
    }

    #[tokio::test]
    async fn es512_expired_token_rejected() {
        let (tm, _) = multi_alg_tm().await;
        // Rebuild a zero-leeway manager over the same key set.
        let crypto = Arc::new(
            RingCryptoProvider::from_signing_keys(
                CryptoConfig::default(),
                &[KeyStore::generate_key(Algorithm::Es512, 2048).unwrap().to_stored(true)],
            )
            .unwrap(),
        );
        let jwks = crypto.get_public_keys().await.unwrap();
        let tm_zero =
            TokenManager::new(crypto, "https://issuer".to_string(), Duration::from_secs(0), jwks);
        let _ = tm;

        let mut realm = realm_with_alg("ES512");
        realm.access_token_lifespan = issuerd_core::SecondsNonZero::new(1);
        let token = tm_zero
            .issue_access_token(
                &test_user(),
                &test_client(),
                &realm,
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(matches!(
            tm_zero.validate_access_token(&token.token),
            Err(IssuerdError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn es512_tampered_payload_rejected() {
        let (tm, _) = multi_alg_tm().await;
        let token = tm
            .issue_access_token(
                &test_user(),
                &test_client(),
                &realm_with_alg("ES512"),
                &["openid".to_string()],
                &SessionId::new("s1").unwrap(),
            )
            .await
            .unwrap();
        let mut parts: Vec<&str> = token.token.split('.').collect();
        use base64::Engine;
        let fake = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"mallory","iss":"https://issuer/realms/test"}"#);
        parts[1] = Box::leak(fake.into_boxed_str());
        let tampered = parts.join(".");
        assert!(matches!(tm.validate_access_token(&tampered), Err(IssuerdError::InvalidToken)));
    }
}
