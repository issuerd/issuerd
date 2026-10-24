// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Admin authentication middleware and realm-binding role authorization.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::borrow::Cow;
use std::sync::Arc;

use crate::{error::AdminApiError, state::AdminApiState};
use tracing::{instrument, warn};

#[derive(Debug, Clone)]
pub struct AdminAuth {
    pub claims: issuerd_core::AccessTokenClaims,
}

/// Name of the bootstrap realm whose administrators may manage every realm
/// (Keycloak's `master` realm model).
const MASTER_REALM: &str = "master";

#[instrument(skip(state, request), fields(path = %request.uri().path(), method = %request.method()))]
pub async fn admin_auth_middleware(
    State(state): State<Arc<AdminApiState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AdminApiError> {
    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(AdminApiError::Unauthorized)?;
    let token = header.strip_prefix("Bearer ").ok_or(AdminApiError::Unauthorized)?;
    let validated = state.token_service.validate_access_token(token).map_err(|e| {
        warn!(error = %e, "admin API authentication failed");
        AdminApiError::Unauthorized
    })?;
    // Bearer-only API: a DPoP-bound token (`cnf.jkt`) must be presented with
    // a proof (RFC 9449 §7.1), which this API does not accept — reject the
    // downgrade instead of letting a stolen proof-bound token authenticate
    // as plain Bearer (same rule as the account API).
    if validated.claims.cnf.is_some() {
        warn!("admin API authentication failed: DPoP-bound token presented as Bearer");
        return Err(AdminApiError::Unauthorized);
    }
    enforce_not_revoked(&state, token).await?;
    enforce_realm_binding(&state, &validated.claims, request.method(), request.uri().path())
        .await?;
    request.extensions_mut().insert(AdminAuth {
        claims: validated.claims,
    });
    Ok(next.run(request).await)
}

/// Bind the token to the realm named in the request path and enforce the
/// realm revocation cutoff (`not_before`).
///
/// Keycloak model: a token issued by the `master` realm administers every
/// realm; any other token administers only the realm that issued it. Paths
/// without a `{realm}` segment (realm creation/listing) are master-only, with
/// one exception family: `GET /admin/serverinfo` and the read-only
/// `GET /admin/enums/*` listings serve server-global capability metadata
/// (enum lists, provider ids, version — no realm-scoped data) and are
/// readable by any authenticated admin token, because every realm's admin
/// console loads them (Keycloak console parity). The exemption is enforced
/// for GET requests only; the handlers still require
/// `view-realm`/`manage-realm`.
///
/// When a realm's `not_before` is set (non-zero), tokens with `iat` before
/// the cutoff are rejected with 401. Both the issuing realm (parsed from the
/// token's `iss`, whose trailing segment is the realm **name**) and the path
/// realm are checked when they differ — e.g. a master token administering
/// another realm must satisfy both cutoffs. A realm **storage error** fails
/// closed (500): without the realm row the revocation cutoff cannot be
/// enforced, so the request is rejected. A realm that simply does not exist
/// (`Ok(None)`) is not an error — an unknown path realm is left to the
/// handler to 404.
///
/// The token's backing user session must also still exist (see
/// [`enforce_live_session`]), so logout and session deletion end admin
/// access immediately.
async fn enforce_realm_binding(
    state: &AdminApiState,
    claims: &issuerd_core::AccessTokenClaims,
    method: &axum::http::Method,
    path: &str,
) -> Result<(), AdminApiError> {
    // The token's home realm name is the trailing segment of the issuer URL
    // (`{base}/realms/{name}`).
    let iss: &str = claims.iss.as_ref();
    let Some(token_realm) = issuerd_core::typestate::extract_realm_from_issuer(iss) else {
        warn!("admin API authorization denied: token issuer carries no realm");
        return Err(AdminApiError::Forbidden);
    };
    // Load the issuing realm once: it drives both the master-realm check and
    // the not_before cutoff. A storage error fails closed: without the realm
    // there is no revocation cutoff to enforce, so the request is rejected.
    let issuing_realm = match state.storage.get_realm_by_name(token_realm).await {
        Ok(realm) => realm,
        Err(e) => {
            warn!(realm = %token_realm, error = %e,
                "issuing realm lookup failed; rejecting admin request (fail-closed)");
            return Err(AdminApiError::Internal(anyhow::Error::new(e)));
        }
    };
    enforce_not_before(issuing_realm.as_ref(), claims)?;
    enforce_admin_client(state, issuing_realm.as_ref(), claims).await?;
    enforce_live_session(state, issuing_realm.as_ref(), claims).await?;
    if issuing_realm.as_ref().is_some_and(|r| r.name.as_str() == MASTER_REALM) {
        // Master tokens administer every realm; when the path names a
        // different realm, that realm's not_before applies too.
        if let Some(path_realm) = path_realm_segment(path)? {
            if path_realm != MASTER_REALM {
                let realm = match state.storage.get_realm_by_name(&path_realm).await {
                    Ok(realm) => realm,
                    Err(e) => {
                        warn!(realm = %path_realm, error = %e,
                            "path realm lookup failed; rejecting admin request (fail-closed)");
                        return Err(AdminApiError::Internal(anyhow::Error::new(e)));
                    }
                };
                enforce_not_before(realm.as_ref(), claims)?;
            }
        }
        return Ok(());
    }
    let Some(path_realm) = path_realm_segment(path)? else {
        // Server metadata and the enum listings are server-global and
        // realm-agnostic; every realm's admin console reads them, so they are
        // exempt from the master-only rule (the handlers enforce
        // view-realm/manage-realm on top). The exemption is method-scoped to
        // GET: a future non-GET route under these prefixes must not silently
        // inherit it.
        if *method == axum::http::Method::GET
            && (path == "/admin/serverinfo" || path.starts_with("/admin/enums/"))
        {
            return Ok(());
        }
        warn!("admin API authorization denied: realm-less path requires a master realm token");
        return Err(AdminApiError::Forbidden);
    };
    match state.storage.get_realm_by_name(&path_realm).await {
        Ok(Some(realm)) if realm.name.as_str() == token_realm => {
            // Same realm as the issuer — enforce the cutoff from the freshly
            // loaded path-realm row.
            enforce_not_before(Some(&realm), claims)?;
            Ok(())
        }
        Ok(Some(_)) => {
            warn!(realm = %path_realm, "admin API authorization denied: cross-realm token");
            Err(AdminApiError::Forbidden)
        }
        // Unknown realm: let the handler produce the 404.
        Ok(None) => Ok(()),
        // Storage error: fail closed — without the realm row the not_before
        // cutoff cannot be enforced.
        Err(e) => {
            warn!(realm = %path_realm, error = %e,
                "path realm lookup failed; rejecting admin request (fail-closed)");
            Err(AdminApiError::Internal(anyhow::Error::new(e)))
        }
    }
}

/// Accept admin credentials only from the built-in admin client or from a
/// custom client explicitly enabled by a `manage-realm` administrator.
async fn enforce_admin_client(
    state: &AdminApiState,
    issuing_realm: Option<&issuerd_core::Realm>,
    claims: &issuerd_core::AccessTokenClaims,
) -> Result<(), AdminApiError> {
    let Some(realm) = issuing_realm else {
        warn!("admin API authentication failed: token issuing realm no longer exists");
        return Err(AdminApiError::Unauthorized);
    };
    let client_name = claims.azp.as_deref().unwrap_or_else(|| claims.aud.as_str());
    let Ok(identifier) = issuerd_core::ClientIdentifier::new(client_name) else {
        return Err(AdminApiError::Forbidden);
    };
    let client = state
        .storage
        .get_client_by_client_id(&realm.id, &identifier)
        .await
        .map_err(fail_closed)?
        .ok_or(AdminApiError::Forbidden)?;
    if client.admin_api_access_allowed() {
        return Ok(());
    }
    warn!(realm = %realm.name, client_id = %client_name,
        "admin API authorization denied: client is not enabled for admin access");
    Err(AdminApiError::Forbidden)
}

/// Reject tokens issued before a realm's revocation cutoff (`not_before`).
///
/// `None` means the realm does not exist, so there is no cutoff to compare
/// against; storage errors are rejected by the caller before this point.
fn enforce_not_before(
    realm: Option<&issuerd_core::Realm>,
    claims: &issuerd_core::AccessTokenClaims,
) -> Result<(), AdminApiError> {
    if let Some(realm) = realm {
        if realm.not_before > 0 && claims.iat < realm.not_before {
            warn!(
                realm = %realm.name,
                not_before = realm.not_before,
                iat = claims.iat,
                "admin API authorization denied: token issued before realm not_before"
            );
            return Err(AdminApiError::Unauthorized);
        }
    }
    Ok(())
}

/// Reject tokens on the revocation blocklist (`revoked:{token}`), written by
/// the RFC 7009 `/revoke` endpoint and authorization-code replay detection.
///
/// A cache error fails closed: revocation cannot be evaluated, so the token
/// must not be treated as valid.
async fn enforce_not_revoked(state: &AdminApiState, token: &str) -> Result<(), AdminApiError> {
    match state.cache.get(&format!("revoked:{token}")).await {
        Ok(Some(_)) => {
            warn!("admin API authentication failed: token has been revoked");
            Err(AdminApiError::Unauthorized)
        }
        Ok(None) => Ok(()),
        Err(e) => {
            warn!(error = %e, "admin API revocation lookup failed; rejecting token (fail-closed)");
            Err(AdminApiError::Internal(anyhow::Error::new(e)))
        }
    }
}

/// Reject a token whose backing user session (`sid`) no longer exists —
/// logout, admin session deletion, SSO-idle cleanup — mirroring the server's
/// `enforce_token_validity` gate used by userinfo and the account API.
///
/// Session-less client-credentials tokens carry a synthetic, never-persisted
/// `sid` and are recognized by shape instead. A token whose issuing realm no
/// longer exists has no session to back it and is rejected; a storage error
/// fails closed (500).
async fn enforce_live_session(
    state: &AdminApiState,
    issuing_realm: Option<&issuerd_core::Realm>,
    claims: &issuerd_core::AccessTokenClaims,
) -> Result<(), AdminApiError> {
    let Some(sid) = claims.sid.as_ref() else {
        return Ok(());
    };
    let Some(realm) = issuing_realm else {
        warn!("admin API authentication failed: token issuing realm no longer exists");
        return Err(AdminApiError::Unauthorized);
    };
    let session = state.storage.get_user_session(&realm.id, sid).await.map_err(fail_closed)?;
    if session.is_some() || is_sessionless_client_token(state, &realm.id, claims).await? {
        return Ok(());
    }
    warn!(realm = %realm.name, "admin API authentication failed: token session no longer exists");
    Err(AdminApiError::Unauthorized)
}

/// Recognize session-less client-credentials tokens by shape: `sub` equals
/// the requesting client's own `client_id` (legacy synthetic shape), or the
/// id of the client-linked service-account user. Mirrors
/// `issuerd_server::routes::oidc::is_sessionless_client_token`.
async fn is_sessionless_client_token(
    state: &AdminApiState,
    realm_id: &issuerd_core::RealmId,
    claims: &issuerd_core::AccessTokenClaims,
) -> Result<bool, AdminApiError> {
    let client_name = claims.azp.clone().unwrap_or_else(|| claims.aud.as_str().to_string());
    if claims.sub.as_ref() == client_name {
        return Ok(true);
    }
    let Ok(identifier) = issuerd_core::ClientIdentifier::new(&client_name) else {
        return Ok(false);
    };
    let client = match state
        .storage
        .get_client_by_client_id(realm_id, &identifier)
        .await
        .map_err(fail_closed)?
    {
        Some(c) if c.service_accounts_enabled => c,
        _ => return Ok(false),
    };
    Ok(matches!(
        issuerd_core::service_account::find_service_account_user(
            state.storage.as_ref(),
            realm_id,
            &client,
        )
        .await
        .map_err(fail_closed)?,
        Some(user) if user.id == claims.sub
    ))
}

/// Map a storage failure on a token-validity lookup to a fail-closed
/// 500: the gate cannot be evaluated, so the request is rejected.
fn fail_closed(e: issuerd_core::IssuerdError) -> AdminApiError {
    warn!(error = %e, "admin token validity lookup failed; rejecting request (fail-closed)");
    AdminApiError::Internal(anyhow::Error::new(e))
}

/// Extract the `{realm}` segment from `/…/realms/{realm}/…` request paths.
///
/// The segment is percent-decoded exactly as axum's `Path` extractor decodes
/// it for the handler, so the binding is checked against the realm the
/// handler acts on (`mast%65r` binds as `master`). A segment whose escapes
/// do not decode to UTF-8 is rejected with 400, as the handler's extractor
/// would reject it.
fn path_realm_segment(path: &str) -> Result<Option<Cow<'_, str>>, AdminApiError> {
    let mut segments = path.split('/');
    while let Some(segment) = segments.next() {
        if segment == "realms" {
            // `count` is the `/realms/count` route, not a realm name. The
            // router matches that static route on the raw segment, so the
            // check is made before decoding.
            let Some(raw) = segments.next().filter(|s| !s.is_empty() && *s != "count") else {
                return Ok(None);
            };
            return match percent_decode_utf8(raw) {
                Some(decoded) => Ok(Some(decoded)),
                None => {
                    warn!("admin API request rejected: realm path segment is not valid UTF-8");
                    Err(AdminApiError::BadRequest("invalid realm path segment".to_string()))
                }
            };
        }
    }
    Ok(None)
}

/// Percent-decode like axum's path parameters
/// (`percent_encoding::percent_decode(..).decode_utf8()`): `%` followed by two
/// hex digits becomes that byte, any other `%` stays literal, and the result
/// must be valid UTF-8.
fn percent_decode_utf8(raw: &str) -> Option<Cow<'_, str>> {
    if !raw.contains('%') {
        return Some(Cow::Borrowed(raw));
    }
    let hex = |b: Option<&u8>| b.and_then(|&b| char::from(b).to_digit(16));
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
            (b'%', Some(hi), Some(lo)) => {
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok().map(Cow::Owned)
}

pub fn require_roles(auth: &AdminAuth, allowed: &[&str]) -> Result<(), AdminApiError> {
    let roles = auth.claims.realm_access.as_ref().map(|ra| &ra.roles[..]).unwrap_or(&[]);
    if allowed
        .iter()
        .any(|&allowed_role| roles.iter().any(|r| r.as_ref() == allowed_role))
    {
        Ok(())
    } else {
        warn!(roles = ?allowed, token_roles = ?roles, "admin API authorization denied: insufficient roles");
        Err(AdminApiError::Forbidden)
    }
}

/// Whether the admin token carries `role`. A silent check for shaping a
/// response; use [`require_roles`] to authorize.
pub fn has_realm_role(auth: &AdminAuth, role: &str) -> bool {
    auth.claims
        .realm_access
        .as_ref()
        .is_some_and(|ra| ra.roles.iter().any(|r| r.as_ref() == role))
}

/// Require the admin token to be issued by the master realm.
///
/// Server-global mutations (signing-key rotation/disable) are not scoped to
/// the path realm, so the middleware's realm binding — which lets any realm
/// administer itself — is not enough on its own. This mirrors the
/// realm-less-path master rule in [`enforce_realm_binding`]. The middleware
/// has already validated the issuer before the handler runs: the realm
/// segment is present, the issuing realm row was loaded from storage
/// (fail-closed on error), and its `not_before` cutoff was enforced, so a
/// plain issuer-segment comparison is sufficient here.
pub fn require_master_token(auth: &AdminAuth) -> Result<(), AdminApiError> {
    let iss: &str = auth.claims.iss.as_ref();
    match issuerd_core::typestate::extract_realm_from_issuer(iss) {
        Some(realm) if realm == MASTER_REALM => Ok(()),
        Some(realm) => {
            warn!(realm = %realm,
                "admin API authorization denied: server-global operation requires a master realm token");
            Err(AdminApiError::Forbidden)
        }
        None => {
            warn!("admin API authorization denied: token issuer carries no realm");
            Err(AdminApiError::Forbidden)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{AccessTokenClaims, Audience, Issuer, JwtId, JwtType, RealmAccess};

    fn auth_with_issuer_and_roles(iss: &str, roles: Vec<issuerd_core::RoleName>) -> AdminAuth {
        AdminAuth {
            claims: AccessTokenClaims {
                jti: JwtId::new("jti").unwrap(),
                iss: Issuer::new(iss).unwrap(),
                sub: issuerd_core::UserId::new("admin").unwrap(),
                aud: Audience::new("admin-cli").unwrap(),
                exp: 9999999999,
                iat: 0,
                nbf: 0,
                scope: issuerd_core::Scope::parse("openid"),
                typ: JwtType::Bearer,
                azp: Some("admin-cli".to_string()),
                session_state: None,
                realm_access: Some(RealmAccess { roles }),
                resource_access: None,
                sid: None,
                claims: None,
                cnf: None,
                authorization_details: None,
            },
        }
    }

    fn auth_with_roles(roles: Vec<issuerd_core::RoleName>) -> AdminAuth {
        auth_with_issuer_and_roles("https://iss", roles)
    }

    fn auth_without_realm_access() -> AdminAuth {
        AdminAuth {
            claims: AccessTokenClaims {
                jti: JwtId::new("jti").unwrap(),
                iss: Issuer::new("https://iss").unwrap(),
                sub: issuerd_core::UserId::new("admin").unwrap(),
                aud: Audience::new("aud").unwrap(),
                exp: 9999999999,
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
        }
    }

    #[test]
    fn require_roles_matching() {
        let auth = auth_with_roles(vec![issuerd_core::RoleName::new("view-realm").unwrap()]);
        assert!(require_roles(&auth, &["view-realm", "manage-realm"]).is_ok());
    }

    #[test]
    fn require_roles_no_match() {
        let auth = auth_with_roles(vec![issuerd_core::RoleName::new("view-users").unwrap()]);
        assert!(matches!(require_roles(&auth, &["view-realm"]), Err(AdminApiError::Forbidden)));
    }

    #[test]
    fn require_roles_empty_allowed() {
        let auth = auth_with_roles(vec![issuerd_core::RoleName::new("view-realm").unwrap()]);
        assert!(matches!(require_roles(&auth, &[]), Err(AdminApiError::Forbidden)));
    }

    #[test]
    fn require_roles_no_realm_access() {
        let auth = auth_without_realm_access();
        assert!(matches!(require_roles(&auth, &["view-realm"]), Err(AdminApiError::Forbidden)));
    }

    #[test]
    fn require_master_token_accepts_master_issuer() {
        let auth = auth_with_issuer_and_roles(
            "http://localhost:8080/realms/master",
            vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
        );
        assert!(require_master_token(&auth).is_ok());
    }

    #[test]
    fn require_master_token_rejects_non_master_issuer() {
        // A delegated realm admin's token — even one carrying manage-realm —
        // fails the master-realm binding.
        let auth = auth_with_issuer_and_roles(
            "http://localhost:8080/realms/tenant",
            vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
        );
        assert!(matches!(require_master_token(&auth), Err(AdminApiError::Forbidden)));
    }

    #[test]
    fn require_master_token_rejects_realm_less_issuer() {
        let auth = auth_with_roles(vec![issuerd_core::RoleName::new("manage-realm").unwrap()]);
        assert!(matches!(require_master_token(&auth), Err(AdminApiError::Forbidden)));
    }

    // -- Realm binding (Watchlist W1) ----------------------------------------

    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use issuerd_core::{IssuerdError, ValidatedAccessToken};
    use tower::ServiceExt;

    struct IssMockTokenService {
        iss: String,
        iat: i64,
    }

    impl issuerd_core::TokenService for IssMockTokenService {
        fn validate_access_token(&self, token: &str) -> Result<ValidatedAccessToken, IssuerdError> {
            let client_id = token.strip_prefix("client:").unwrap_or("admin-cli");
            Ok(ValidatedAccessToken {
                claims: AccessTokenClaims {
                    jti: JwtId::new("jti").unwrap(),
                    iss: Issuer::new(&self.iss).unwrap(),
                    sub: issuerd_core::UserId::new("admin").unwrap(),
                    aud: Audience::new(client_id).unwrap(),
                    exp: 9999999999,
                    iat: self.iat,
                    nbf: 0,
                    scope: issuerd_core::Scope::parse("openid"),
                    typ: JwtType::Bearer,
                    azp: Some(client_id.to_string()),
                    session_state: None,
                    realm_access: Some(RealmAccess {
                        roles: vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
                    }),
                    resource_access: None,
                    sid: None,
                    claims: None,
                    cnf: None,
                    authorization_details: None,
                },
                header: issuerd_core::JwsHeader {
                    alg: issuerd_core::Algorithm::Rs256,
                    typ: Some(issuerd_core::JwsType::Jwt),
                    kid: issuerd_core::KeyId::new("key-1").unwrap(),
                },
            })
        }

        fn validate_id_token(
            &self,
            _token: &str,
            _client: &issuerd_core::Client,
            _nonce: Option<&str>,
        ) -> Result<issuerd_core::IdTokenClaims, IssuerdError> {
            unimplemented!()
        }

        fn validate_refresh_token(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::ValidatedRefreshToken, IssuerdError> {
            unimplemented!()
        }

        fn validate_id_token_hint(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::IdTokenClaims, IssuerdError> {
            unimplemented!()
        }
    }

    fn binding_state_with_iat(iss: &str, iat: i64) -> Arc<AdminApiState> {
        let mut crypto = issuerd_core::MockCryptoProvider::new();
        crypto
            .expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));
        Arc::new(AdminApiState {
            storage: crate::test_utils::tests::storage_with_master_realm(),
            token_service: Arc::new(IssMockTokenService {
                iss: iss.to_string(),
                iat,
            }),
            crypto: Arc::new(crypto),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender: Arc::new(issuerd_core::MockEmailSender::new()),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            mcp_enabled: false,
            base_url: "http://localhost:8080".to_string(),
            email_bundle: None,
            available_locales: issuerd_core::i18n::SHIPPED_LOCALES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }

    async fn state_with_tenant_and_iat(iss: &str, iat: i64) -> Arc<AdminApiState> {
        let state = binding_state_with_iat(iss, iat);
        let tenant = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("tenant-uuid").unwrap(),
            name: issuerd_core::RealmName::new("tenant").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&tenant).await.unwrap();
        let admin_cli =
            crate::realms::build_admin_cli_client(&tenant.id, "http://localhost:8080").unwrap();
        state.storage.create_client(&tenant.id, &admin_cli).await.unwrap();
        state
    }

    async fn state_with_tenant(iss: &str) -> Arc<AdminApiState> {
        state_with_tenant_and_iat(iss, 0).await
    }

    /// Set the `not_before` cutoff of a realm looked up by name.
    async fn set_not_before(state: &Arc<AdminApiState>, realm_name: &str, not_before: i64) {
        let mut realm = state.storage.get_realm_by_name(realm_name).await.unwrap().unwrap();
        realm.not_before = not_before;
        state.storage.update_realm(&realm).await.unwrap();
    }

    fn binding_app(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms", get(|| async { StatusCode::OK }))
            .route("/admin/realms/{realm}/users", get(|| async { StatusCode::OK }))
            .route("/admin/serverinfo", get(|| async { StatusCode::OK }))
            .route("/admin/enums/protocols", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(state.clone(), admin_auth_middleware))
            .with_state(state)
    }

    async fn call(app: Router, uri: &str) -> StatusCode {
        call_with_token(app, uri, "token").await
    }

    async fn call_with_token(app: Router, uri: &str, token: &str) -> StatusCode {
        app.oneshot(
            Request::builder()
                .uri(uri)
                .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    fn segment(path: &str) -> Option<String> {
        path_realm_segment(path).unwrap().map(Cow::into_owned)
    }

    #[test]
    fn path_realm_segment_extraction() {
        assert_eq!(segment("/admin/realms/master/users").as_deref(), Some("master"));
        assert_eq!(segment("/admin/realms/tenant").as_deref(), Some("tenant"));
        assert_eq!(segment("/admin/realms"), None);
        assert_eq!(segment("/admin/realms/count"), None);
        assert_eq!(segment("/admin/serverinfo"), None);
        assert_eq!(segment("/admin/enums/protocols"), None);
    }

    #[test]
    fn path_realm_segment_is_percent_decoded_like_axum_path() {
        assert_eq!(segment("/admin/realms/mast%65r/users").as_deref(), Some("master"));
        assert_eq!(segment("/admin/realms/%6D%61%73%74%65%72").as_deref(), Some("master"));
        // An encoded `count` is routed to `/realms/{realm}`, not `/realms/count`.
        assert_eq!(segment("/admin/realms/c%6Funt").as_deref(), Some("count"));
        // `%` without two hex digits stays literal (percent_encoding semantics).
        assert_eq!(segment("/admin/realms/a%zz%4").as_deref(), Some("a%zz%4"));
        assert_eq!(segment("/admin/realms/%%41").as_deref(), Some("%A"));
        assert_eq!(segment("/admin/realms/caf%C3%A9").as_deref(), Some("caf\u{e9}"));
        assert!(matches!(
            path_realm_segment("/admin/realms/%FF/users"),
            Err(AdminApiError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn path_realm_segment_matches_axum_path_extractor() {
        // The binding must see the same realm value the handler extracts.
        let app = Router::new().route(
            "/admin/realms/{realm}/users",
            get(|axum::extract::Path(realm): axum::extract::Path<String>| async move { realm }),
        );
        for raw in [
            "master",
            "mast%65r",
            "%6d%61ster",
            "a%zz%4",
            "%%41",
            "caf%C3%A9",
            "%FF",
        ] {
            let uri = format!("/admin/realms/{raw}/users");
            let response = app
                .clone()
                .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            match path_realm_segment(&uri) {
                Ok(Some(decoded)) => {
                    assert_eq!(response.status(), StatusCode::OK, "{raw}");
                    let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
                    assert_eq!(body, decoded.as_bytes(), "{raw}");
                }
                Ok(None) => panic!("{raw}: segment not extracted"),
                Err(_) => assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{raw}"),
            }
        }
    }

    #[tokio::test]
    async fn master_token_administers_any_realm() {
        let state = state_with_tenant("http://localhost:8080/realms/master").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenant/users").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn realm_token_administers_own_realm() {
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenant/users").await, StatusCode::OK);
    }

    async fn state_with_custom_client(enabled: bool, admin_api_access: bool) -> Arc<AdminApiState> {
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let realm_id = issuerd_core::RealmId::new("tenant-uuid").unwrap();
        let mut client =
            crate::realms::build_admin_cli_client(&realm_id, "http://localhost:8080").unwrap();
        client.id = issuerd_core::ClientId::new("shop-uuid").unwrap();
        client.client_id = issuerd_core::ClientIdentifier::new("shop").unwrap();
        client.enabled = enabled;
        if admin_api_access {
            client.attributes.insert(
                issuerd_core::Client::ADMIN_API_ACCESS_ATTRIBUTE.to_string(),
                "true".to_string(),
            );
        }
        state.storage.create_client(&realm_id, &client).await.unwrap();
        state
    }

    #[tokio::test]
    async fn ordinary_relying_party_token_is_not_an_admin_credential() {
        let app = binding_app(state_with_custom_client(true, false).await);
        assert_eq!(
            call_with_token(app, "/admin/realms/tenant/users", "client:shop").await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn explicitly_enabled_custom_client_is_an_admin_credential() {
        let app = binding_app(state_with_custom_client(true, true).await);
        assert_eq!(
            call_with_token(app, "/admin/realms/tenant/users", "client:shop").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn disabled_custom_client_is_not_an_admin_credential() {
        let app = binding_app(state_with_custom_client(false, true).await);
        assert_eq!(
            call_with_token(app, "/admin/realms/tenant/users", "client:shop").await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn realm_token_denied_for_other_realm() {
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/master/users").await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn realm_token_denied_for_percent_encoded_other_realm() {
        // The handler's `Path` extractor decodes `mast%65r` to `master`, so the
        // binding must reject it exactly like the plain spelling.
        for uri in [
            "/admin/realms/mast%65r/users",
            "/admin/realms/%6Daster/users",
        ] {
            let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
            let app = binding_app(state);
            assert_eq!(call(app, uri).await, StatusCode::FORBIDDEN, "{uri}");
        }
    }

    #[tokio::test]
    async fn realm_token_administers_own_realm_percent_encoded() {
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenan%74/users").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_utf8_realm_segment_is_rejected() {
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/%FF/users").await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn realm_token_denied_for_realm_less_path() {
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms").await, StatusCode::FORBIDDEN);
    }

    // -- Server metadata: realm-less but readable by any admin token ---------

    #[tokio::test]
    async fn realm_token_reads_serverinfo() {
        // Keycloak console parity: every realm's admin console loads
        // serverinfo, and the payload is server-global capability metadata
        // only, so a realm-bound admin token may read it.
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/serverinfo").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn master_token_reads_serverinfo() {
        let state = state_with_tenant("http://localhost:8080/realms/master").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/serverinfo").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn anonymous_serverinfo_read_is_unauthorized() {
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        let status = app
            .oneshot(Request::builder().uri("/admin/serverinfo").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn not_before_still_applies_to_serverinfo_reads() {
        // The relaxation does not bypass realm revocation: a token issued
        // before its issuing realm's cutoff is still rejected.
        let state = state_with_tenant_and_iat("http://localhost:8080/realms/tenant", 500).await;
        set_not_before(&state, "tenant", 1000).await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/serverinfo").await, StatusCode::UNAUTHORIZED);
    }

    // -- Enum listings: realm-less but readable by any admin token ------------

    #[tokio::test]
    async fn realm_token_reads_enums() {
        // The `/admin/enums/*` listings carry the same server-global metadata
        // serverinfo aggregates, so a realm-bound admin token may read them.
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/enums/protocols").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn master_token_reads_enums() {
        let state = state_with_tenant("http://localhost:8080/realms/master").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/enums/protocols").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn anonymous_enums_read_is_unauthorized() {
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        let status = app
            .oneshot(Request::builder().uri("/admin/enums/protocols").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn not_before_still_applies_to_enums_reads() {
        // Same as serverinfo: the relaxation does not bypass realm revocation.
        let state = state_with_tenant_and_iat("http://localhost:8080/realms/tenant", 500).await;
        set_not_before(&state, "tenant", 1000).await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/enums/protocols").await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metadata_exemption_is_get_only() {
        // A non-GET request under an exempt prefix still requires a master
        // token: the middleware rejects it before the router would answer 405.
        for uri in ["/admin/serverinfo", "/admin/enums/protocols"] {
            let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
            let app = binding_app(state);
            let status = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header(axum::http::header::AUTHORIZATION, "Bearer token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status();
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        }
    }

    #[tokio::test]
    async fn token_without_realm_issuer_denied() {
        let state = state_with_tenant("https://issuer-without-realm").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenant/users").await, StatusCode::FORBIDDEN);
    }

    // -- Realm not_before revocation cutoff ----------------------------------

    #[tokio::test]
    async fn not_before_rejects_token_issued_before_cutoff() {
        let state = state_with_tenant_and_iat("http://localhost:8080/realms/tenant", 500).await;
        set_not_before(&state, "tenant", 1000).await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenant/users").await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn not_before_allows_token_issued_at_cutoff() {
        // Only `iat < not_before` is rejected; a token issued exactly at the
        // cutoff survives.
        let state = state_with_tenant_and_iat("http://localhost:8080/realms/tenant", 1000).await;
        set_not_before(&state, "tenant", 1000).await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenant/users").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn not_before_zero_disables_the_cutoff() {
        // `not_before = 0` (the default) means "no revocation cutoff": the
        // comparison must stay disabled even for a degenerate negative-iat
        // token, which `0 >= 0 && iat < 0` would wrongly reject.
        let state = state_with_tenant_and_iat("http://localhost:8080/realms/tenant", -1).await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenant/users").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn not_before_of_path_realm_rejects_master_token() {
        // A master token administering another realm is checked against the
        // path realm's cutoff too.
        let state = state_with_tenant_and_iat("http://localhost:8080/realms/master", 500).await;
        set_not_before(&state, "tenant", 1000).await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenant/users").await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn not_before_of_percent_encoded_path_realm_rejects_master_token() {
        let state = state_with_tenant_and_iat("http://localhost:8080/realms/master", 500).await;
        set_not_before(&state, "tenant", 1000).await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenan%74/users").await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn not_before_of_issuing_realm_rejects_master_token() {
        // The issuing (master) realm's cutoff applies to every request.
        let state = state_with_tenant_and_iat("http://localhost:8080/realms/master", 500).await;
        set_not_before(&state, "master", 1000).await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/tenant/users").await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn not_before_fails_open_for_unloadable_path_realm() {
        // Master token against an unknown path realm: the binding allows it
        // (the handler produces the 404) and the not_before lookup fails open.
        let state = state_with_tenant_and_iat("http://localhost:8080/realms/master", 500).await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/ghost/users").await, StatusCode::OK);
    }

    // -- Fail-closed on storage errors ----------------------------------------

    fn binding_state_with_mock_storage(mock: issuerd_core::MockStorage) -> Arc<AdminApiState> {
        let mut crypto = issuerd_core::MockCryptoProvider::new();
        crypto
            .expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));
        Arc::new(AdminApiState {
            storage: Arc::new(mock),
            token_service: Arc::new(IssMockTokenService {
                iss: "http://localhost:8080/realms/master".to_string(),
                iat: 0,
            }),
            crypto: Arc::new(crypto),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender: Arc::new(issuerd_core::MockEmailSender::new()),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            mcp_enabled: false,
            base_url: "http://localhost:8080".to_string(),
            email_bundle: None,
            available_locales: issuerd_core::i18n::SHIPPED_LOCALES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }

    #[tokio::test]
    async fn issuing_realm_storage_error_fails_closed() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_get_realm_by_name()
            .returning(|_| Err(IssuerdError::ServerError("db down".into())));
        let app = binding_app(binding_state_with_mock_storage(mock));
        // not_before cannot be enforced without the realm row: reject.
        assert_eq!(
            call(app, "/admin/realms/master/users").await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn path_realm_storage_error_fails_closed_for_master_token() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_get_realm_by_name().returning(|name| {
            if name == "master" {
                Ok(Some(crate::test_utils::tests::master_realm()))
            } else {
                Err(IssuerdError::ServerError("db down".into()))
            }
        });
        mock.expect_get_client_by_client_id().returning(|realm, _| {
            Ok(Some(
                crate::realms::build_admin_cli_client(realm, "http://localhost:8080").unwrap(),
            ))
        });
        let app = binding_app(binding_state_with_mock_storage(mock));
        assert_eq!(
            call(app, "/admin/realms/tenant/users").await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn path_realm_storage_error_fails_closed_for_realm_token() {
        // Issuing-realm lookup succeeds, the path-realm re-lookup fails: the
        // cutoff must still not be skipped.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mut state_mock = issuerd_core::MockStorage::new();
        state_mock.expect_get_realm_by_name().returning(move |_name| {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok(Some(issuerd_core::Realm {
                    id: issuerd_core::RealmId::new("tenant-uuid").unwrap(),
                    name: issuerd_core::RealmName::new("tenant").unwrap(),
                    ..Default::default()
                }))
            } else {
                Err(IssuerdError::ServerError("db down".into()))
            }
        });
        state_mock.expect_get_client_by_client_id().returning(|realm, _| {
            Ok(Some(
                crate::realms::build_admin_cli_client(realm, "http://localhost:8080").unwrap(),
            ))
        });
        let mut crypto = issuerd_core::MockCryptoProvider::new();
        crypto
            .expect_get_public_keys()
            .returning(|| Ok(issuerd_core::JwkSet { keys: vec![] }));
        let state = Arc::new(AdminApiState {
            storage: Arc::new(state_mock),
            token_service: Arc::new(IssMockTokenService {
                iss: "http://localhost:8080/realms/tenant".to_string(),
                iat: 0,
            }),
            crypto: Arc::new(crypto),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender: Arc::new(issuerd_core::MockEmailSender::new()),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            signing_key_reload: Arc::new(|| {}),
            mcp_enabled: false,
            base_url: "http://localhost:8080".to_string(),
            email_bundle: None,
            available_locales: issuerd_core::i18n::SHIPPED_LOCALES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        });
        let app = binding_app(state);
        assert_eq!(
            call(app, "/admin/realms/tenant/users").await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    // -- Token lifecycle: DPoP binding, revocation, live session -------------

    const TENANT_ISS: &str = "http://localhost:8080/realms/tenant";

    struct ClaimsMockTokenService(AccessTokenClaims);

    impl issuerd_core::TokenService for ClaimsMockTokenService {
        fn validate_access_token(
            &self,
            _token: &str,
        ) -> Result<ValidatedAccessToken, IssuerdError> {
            Ok(ValidatedAccessToken {
                claims: self.0.clone(),
                header: issuerd_core::JwsHeader {
                    alg: issuerd_core::Algorithm::Rs256,
                    typ: Some(issuerd_core::JwsType::Jwt),
                    kid: issuerd_core::KeyId::new("key-1").unwrap(),
                },
            })
        }

        fn validate_id_token(
            &self,
            _token: &str,
            _client: &issuerd_core::Client,
            _nonce: Option<&str>,
        ) -> Result<issuerd_core::IdTokenClaims, IssuerdError> {
            unimplemented!()
        }

        fn validate_refresh_token(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::ValidatedRefreshToken, IssuerdError> {
            unimplemented!()
        }

        fn validate_id_token_hint(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::IdTokenClaims, IssuerdError> {
            unimplemented!()
        }
    }

    struct FailingCache;

    #[async_trait::async_trait]
    impl issuerd_core::DistributedCache for FailingCache {
        async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, IssuerdError> {
            Err(IssuerdError::ServerError("cache down".to_string()))
        }
        async fn set(
            &self,
            _key: &str,
            _value: Vec<u8>,
            _ttl: Option<std::time::Duration>,
        ) -> Result<(), IssuerdError> {
            Ok(())
        }
        async fn delete(&self, _key: &str) -> Result<(), IssuerdError> {
            Ok(())
        }
        async fn compare_and_swap(
            &self,
            _key: &str,
            _expected: Option<Vec<u8>>,
            _new: Vec<u8>,
        ) -> Result<bool, IssuerdError> {
            Ok(false)
        }
        async fn publish(&self, _channel: &str, _message: Vec<u8>) -> Result<(), IssuerdError> {
            Ok(())
        }
        async fn subscribe(
            &self,
            _channel: &str,
            _handler: Box<dyn Fn(Vec<u8>) + Send + Sync>,
        ) -> Result<(), IssuerdError> {
            Ok(())
        }
    }

    fn tenant_realm() -> issuerd_core::Realm {
        issuerd_core::Realm {
            id: issuerd_core::RealmId::new("tenant-uuid").unwrap(),
            name: issuerd_core::RealmName::new("tenant").unwrap(),
            ..Default::default()
        }
    }

    /// Unbound tenant-realm admin token claims (`sub = admin`, no `sid`).
    fn tenant_claims() -> AccessTokenClaims {
        let roles = vec![issuerd_core::RoleName::new("manage-realm").unwrap()];
        auth_with_issuer_and_roles(TENANT_ISS, roles).claims
    }

    fn sid(id: &str) -> Option<issuerd_core::SessionId> {
        Some(issuerd_core::SessionId::new(id).unwrap())
    }

    /// Binding state (master + tenant realms) whose token validates to `claims`.
    async fn lifecycle_state(claims: AccessTokenClaims) -> AdminApiState {
        let Ok(mut state) = Arc::try_unwrap(state_with_tenant(TENANT_ISS).await) else {
            unreachable!("a freshly built state has a single owner");
        };
        state.token_service = Arc::new(ClaimsMockTokenService(claims));
        state
    }

    async fn call_tenant_users(state: AdminApiState) -> StatusCode {
        call(binding_app(Arc::new(state)), "/admin/realms/tenant/users").await
    }

    fn admin_session(id: &str) -> issuerd_core::UserSession {
        let now = chrono::Utc::now();
        issuerd_core::UserSession {
            id: issuerd_core::SessionId::new(id).unwrap(),
            realm_id: tenant_realm().id,
            user_id: issuerd_core::UserId::new("admin").unwrap(),
            login_username: issuerd_core::Username::new("admin").unwrap(),
            ip_address: "127.0.0.1".parse().unwrap(),
            auth_method: issuerd_core::AuthMethod::Password,
            remember_me: false,
            offline: false,
            started: now,
            last_session_refresh: now,
            auth_time: now,
            impersonator: None,
            clients: vec![],
        }
    }

    #[tokio::test]
    async fn dpop_bound_token_presented_as_bearer_is_rejected() {
        let mut claims = tenant_claims();
        claims.cnf = Some(issuerd_core::ConfirmationClaim {
            jkt: "thumbprint".to_string(),
        });
        let state = lifecycle_state(claims).await;
        assert_eq!(call_tenant_users(state).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoked_token_is_rejected() {
        let state = lifecycle_state(tenant_claims()).await;
        // `call` presents the literal access token `token`.
        state.cache.set("revoked:token", b"1".to_vec(), None).await.unwrap();
        assert_eq!(call_tenant_users(state).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revocation_lookup_error_fails_closed() {
        let mut state = lifecycle_state(tenant_claims()).await;
        state.cache = Arc::new(FailingCache);
        assert_eq!(call_tenant_users(state).await, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn token_with_live_session_is_accepted() {
        let mut claims = tenant_claims();
        claims.sid = sid("sess-1");
        let state = lifecycle_state(claims).await;
        state
            .storage
            .create_user_session(&tenant_realm().id, &admin_session("sess-1"))
            .await
            .unwrap();
        assert_eq!(call_tenant_users(state).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn token_whose_session_ended_is_rejected() {
        // Logout and admin session deletion remove the session row: the token
        // must stop working immediately, not at expiry.
        let mut claims = tenant_claims();
        claims.sid = sid("sess-1");
        let state = lifecycle_state(claims).await;
        let realm_id = tenant_realm().id;
        state
            .storage
            .create_user_session(&realm_id, &admin_session("sess-1"))
            .await
            .unwrap();
        let session_id = issuerd_core::SessionId::new("sess-1").unwrap();
        state.storage.delete_user_session(&realm_id, &session_id).await.unwrap();
        assert_eq!(call_tenant_users(state).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn master_token_whose_session_ended_is_rejected() {
        let roles = vec![issuerd_core::RoleName::new("manage-realm").unwrap()];
        let mut claims =
            auth_with_issuer_and_roles("http://localhost:8080/realms/master", roles).claims;
        claims.sid = sid("gone");
        let state = lifecycle_state(claims).await;
        assert_eq!(call_tenant_users(state).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn session_token_from_deleted_realm_is_rejected() {
        // The issuing realm is gone, so no session can back the token.
        let roles = vec![issuerd_core::RoleName::new("manage-realm").unwrap()];
        let mut claims =
            auth_with_issuer_and_roles("http://localhost:8080/realms/ghost", roles).claims;
        claims.sid = sid("sess-1");
        let app = binding_app(Arc::new(lifecycle_state(claims).await));
        assert_eq!(call(app, "/admin/realms/ghost/users").await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn session_lookup_error_fails_closed() {
        let mut mock = issuerd_core::MockStorage::new();
        mock.expect_get_realm_by_name().returning(|_| Ok(Some(tenant_realm())));
        mock.expect_get_client_by_client_id().returning(|realm, _| {
            Ok(Some(
                crate::realms::build_admin_cli_client(realm, "http://localhost:8080").unwrap(),
            ))
        });
        mock.expect_get_user_session()
            .returning(|_, _| Err(IssuerdError::ServerError("db down".into())));
        let mut claims = tenant_claims();
        claims.sid = sid("sess-1");
        let mut state = lifecycle_state(claims).await;
        state.storage = Arc::new(mock);
        assert_eq!(call_tenant_users(state).await, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn sessionless_client_credentials_token_is_accepted() {
        // Legacy synthetic shape: `sub` = `azp` = client_id, with a synthetic,
        // never-persisted `sid`.
        let mut claims = tenant_claims();
        claims.sub = issuerd_core::UserId::new("admin-cli").unwrap();
        claims.azp = Some("admin-cli".to_string());
        claims.sid = sid("synthetic");
        let state = lifecycle_state(claims).await;
        assert_eq!(call_tenant_users(state).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn service_account_token_without_session_is_accepted() {
        // `sub` is the client-linked service-account user; the
        // client-credentials grant never persists the token's `sid`.
        let realm_id = tenant_realm().id;
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new("automation-uuid").unwrap(),
            realm_id: realm_id.clone(),
            client_id: issuerd_core::ClientIdentifier::new("automation").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: issuerd_core::ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
            secret: Some("secret".to_string()),
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: issuerd_core::Scope::empty(),
            optional_scopes: issuerd_core::Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: true,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::from([(
                issuerd_core::Client::ADMIN_API_ACCESS_ATTRIBUTE.to_string(),
                "true".to_string(),
            )]),
        };
        let mut claims = tenant_claims();
        claims.sub = client.service_account_user_id();
        claims.azp = Some("automation".to_string());
        claims.sid = sid("synthetic");
        let state = lifecycle_state(claims).await;
        state.storage.create_client(&realm_id, &client).await.unwrap();
        issuerd_core::service_account::ensure_service_account_user(
            state.storage.as_ref(),
            &realm_id,
            &client,
        )
        .await
        .unwrap();
        assert_eq!(call_tenant_users(state).await, StatusCode::OK);
    }
}
