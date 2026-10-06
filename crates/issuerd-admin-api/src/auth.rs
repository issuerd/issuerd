// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Admin authentication middleware and realm-binding role authorization.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
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
    enforce_realm_binding(&state, &validated.claims, request.uri().path()).await?;
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
/// one exception: `GET /admin/serverinfo` serves server-global capability
/// metadata (enum lists, provider ids, version — no realm-scoped data) and is
/// readable by any authenticated admin token, because every realm's admin
/// console loads it (Keycloak console parity). The handler still requires
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
async fn enforce_realm_binding(
    state: &AdminApiState,
    claims: &issuerd_core::AccessTokenClaims,
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
    if issuing_realm.as_ref().is_some_and(|r| r.name.as_str() == MASTER_REALM) {
        // Master tokens administer every realm; when the path names a
        // different realm, that realm's not_before applies too.
        if let Some(path_realm) = path_realm_segment(path) {
            if path_realm != MASTER_REALM {
                let realm = match state.storage.get_realm_by_name(path_realm).await {
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
    let Some(path_realm) = path_realm_segment(path) else {
        // Server metadata is server-global and realm-agnostic; every realm's
        // admin console reads it, so it is exempt from the master-only rule
        // (the handler enforces view-realm/manage-realm on top).
        if path == "/admin/serverinfo" {
            return Ok(());
        }
        warn!("admin API authorization denied: realm-less path requires a master realm token");
        return Err(AdminApiError::Forbidden);
    };
    match state.storage.get_realm_by_name(path_realm).await {
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

/// Extract the `{realm}` segment from `/…/realms/{realm}/…` request paths.
fn path_realm_segment(path: &str) -> Option<&str> {
    let mut segments = path.split('/');
    while let Some(segment) = segments.next() {
        if segment == "realms" {
            // `count` is the `/realms/count` route, not a realm name.
            return segments.next().filter(|s| !s.is_empty() && *s != "count");
        }
    }
    None
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
                aud: Audience::new("aud").unwrap(),
                exp: 9999999999,
                iat: 0,
                nbf: 0,
                scope: issuerd_core::Scope::parse("openid"),
                typ: JwtType::Bearer,
                azp: None,
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
        fn validate_access_token(
            &self,
            _token: &str,
        ) -> Result<ValidatedAccessToken, IssuerdError> {
            Ok(ValidatedAccessToken {
                claims: AccessTokenClaims {
                    jti: JwtId::new("jti").unwrap(),
                    iss: Issuer::new(&self.iss).unwrap(),
                    sub: issuerd_core::UserId::new("admin").unwrap(),
                    aud: Audience::new("aud").unwrap(),
                    exp: 9999999999,
                    iat: self.iat,
                    nbf: 0,
                    scope: issuerd_core::Scope::parse("openid"),
                    typ: JwtType::Bearer,
                    azp: None,
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
            base_url: "http://localhost:8080".to_string(),
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
            .layer(axum::middleware::from_fn_with_state(state.clone(), admin_auth_middleware))
            .with_state(state)
    }

    async fn call(app: Router, uri: &str) -> StatusCode {
        app.oneshot(
            Request::builder()
                .uri(uri)
                .header(axum::http::header::AUTHORIZATION, "Bearer token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    #[test]
    fn path_realm_segment_extraction() {
        assert_eq!(path_realm_segment("/admin/realms/master/users"), Some("master"));
        assert_eq!(path_realm_segment("/admin/realms/tenant"), Some("tenant"));
        assert_eq!(path_realm_segment("/admin/realms"), None);
        assert_eq!(path_realm_segment("/admin/realms/count"), None);
        assert_eq!(path_realm_segment("/admin/serverinfo"), None);
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

    #[tokio::test]
    async fn realm_token_denied_for_other_realm() {
        let state = state_with_tenant("http://localhost:8080/realms/tenant").await;
        let app = binding_app(state);
        assert_eq!(call(app, "/admin/realms/master/users").await, StatusCode::FORBIDDEN);
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
            base_url: "http://localhost:8080".to_string(),
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
            base_url: "http://localhost:8080".to_string(),
        });
        let app = binding_app(state);
        assert_eq!(
            call(app, "/admin/realms/tenant/users").await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
