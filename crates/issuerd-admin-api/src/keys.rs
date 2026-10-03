// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Signing-key administration: metadata listing, rotation, and disable.
// The keys live in the server-global `signing_keys` table shared by all
// realms and cluster nodes, so the mutating endpoints (rotate/disable) are
// restricted to master-realm tokens; listing stays available to any realm's
// view-realm/manage-realm admins.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tracing::info;

use crate::{
    auth::{require_master_token, require_roles, AdminAuth},
    dto::{KeyMetadataRepresentation, KeysMetadataRepresentation, RotateKeyRequest},
    error::AdminApiError,
    state::AdminApiState,
};

/// Minimum RSA key size accepted for rotation (bits).
const RSA_KEY_SIZE_MIN: u32 = 2048;
/// Maximum RSA key size accepted for rotation (bits); larger moduli take
/// disproportionately long to generate.
const RSA_KEY_SIZE_MAX: u32 = 8192;

/// Whether `alg` is RSA-based — the only family where `key_size` applies.
fn is_rsa(alg: issuerd_core::Algorithm) -> bool {
    matches!(
        alg,
        issuerd_core::Algorithm::Rs256
            | issuerd_core::Algorithm::Rs384
            | issuerd_core::Algorithm::Rs512
    )
}

/// Keycloak-style provider id for a stored key, derived from its JWK family.
fn provider_id_for(key: &issuerd_core::StoredSigningKey) -> String {
    match key.public_jwk.kty {
        issuerd_core::JwkKty::Rsa => "rsa-generated",
        issuerd_core::JwkKty::Ec => "ecdsa-generated",
        issuerd_core::JwkKty::Okp => "eddsa-generated",
        issuerd_core::JwkKty::Oct => "hmac-generated",
    }
    .to_string()
}

/// Build the key metadata response from the shared signing-key set (the
/// `signing_keys` table is the source of truth the keystores reload from).
/// Ordering follows the `KeyStore::public_jwks` contract — active keys first
/// (newest first), then passive keys (newest first) — and the `active` map
/// holds the newest active kid per algorithm (rotation keeps one
/// active key per algorithm, so the map may hold several entries).
fn keys_metadata_from_stored(
    mut keys: Vec<issuerd_core::StoredSigningKey>,
) -> KeysMetadataRepresentation {
    keys.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then_with(|| b.created_at.cmp(&a.created_at))
            .then_with(|| a.kid.cmp(&b.kid))
    });

    let mut active = std::collections::HashMap::new();
    let mut passive = Vec::new();

    for key in &keys {
        let meta = KeyMetadataRepresentation {
            provider_id: provider_id_for(key),
            kid: key.kid.to_string(),
            status: if key.active {
                issuerd_core::KeyStatus::Active
            } else {
                issuerd_core::KeyStatus::Passive
            },
            algorithm: key.alg,
            public_key: key.public_jwk.n.as_ref().map(|b| b.as_str().to_string()),
            certificate: None,
        };
        if key.active {
            // Ordered newest-first, so the first entry per algorithm wins.
            active.entry(key.alg.to_string()).or_insert_with(|| key.kid.to_string());
        }
        passive.push(meta);
    }

    KeysMetadataRepresentation { active, passive }
}

/// Derive key-generation parameters from a key's public JWK: the algorithm
/// verbatim and, for RSA, the size estimated from the base64url modulus
/// length (6 bits per character, rounded down to whole bytes; non-RSA
/// algorithms ignore the size).
fn key_params(jwk: &issuerd_core::Jwk) -> (issuerd_core::Algorithm, u32) {
    let bits = jwk.n.as_ref().map_or(2048, |n| ((n.as_str().len() * 6) / 8) as u32 * 8);
    (jwk.alg, bits)
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/keys",
    tag = "Keys",
    summary = "Get realm key metadata",
    description = "Returns metadata about active and passive cryptographic keys (algorithms, kids, status). Requires `view-realm` or `manage-realm` role.",
    params(("realm" = String, Path, description = "Realm name")),
    responses(
        (status = 200, description = "Key metadata", body = KeysMetadataRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_keys(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<KeysMetadataRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-realm", "manage-realm"])?;
    let keys = state.storage.list_signing_keys().await?;
    Ok(Json(keys_metadata_from_stored(keys)))
}

#[utoipa::path(
    post,
    path = "/admin/realms/{realm}/keys/rotate",
    tag = "Keys",
    summary = "Rotate the active signing key",
    description = "Generates a new active signing key and demotes the other active keys OF THE SAME ALGORITHM (rotation keeps exactly one active key per algorithm, so realms pinned to other algorithms via their `default_signature_algorithm` attribute keep their signing key). The optional body selects the algorithm and RSA key size; both default to the newest active key's parameters (the server-default algorithm EdDSA when no key exists, and on creation-timestamp ties). On an EMPTY key set the rotation establishes the fresh-deployment pair — the requested key plus, unless it is RS256 itself, an active RS256 key — so the OIDC Core mandatory-to-implement RS256 is advertised in discovery from the start. The endpoint reloads this node's keystore and returns the resulting key metadata. Signing keys are server-global (shared by all realms and cluster nodes via the `signing_keys` table); the realm path segment is namespace parity with Keycloak only. Peer cluster nodes pick the rotation up via JWKS polling. Requires a master-realm token with the `manage-realm` role; delegated realm admins cannot rotate the server-global keys.",
    params(("realm" = String, Path, description = "Realm name")),
    request_body(content = Option<RotateKeyRequest>, description = "Optional algorithm/size for the new key"),
    responses(
        (status = 200, description = "Key metadata after rotation", body = KeysMetadataRepresentation),
        (status = 400, description = "Unknown or symmetric (HMAC) algorithm, or invalid RSA key size", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn rotate_keys(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    body: Option<Json<RotateKeyRequest>>,
) -> Result<Json<KeysMetadataRepresentation>, AdminApiError> {
    // The key set is server-global, so rotation is bound to a master-realm
    // token — a delegated realm admin must not retune every realm's signing.
    require_master_token(&auth)?;
    require_roles(&auth, &["manage-realm"])?;
    // The path realm is namespace parity only; it must still exist (404).
    state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;

    let existing = state.storage.list_signing_keys().await?;
    // Default rotation parameters come from the newest active key; fall back
    // to the server-default algorithm (EdDSA) when no key exists. Timestamp
    // ties (the persisted initial pair can land in the same microsecond)
    // prefer the server-default algorithm, so an empty-body rotation on a
    // fresh deployment rotates the actual signing key deterministically.
    let current = existing.iter().filter(|k| k.active).max_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| {
                (a.alg == issuerd_core::Algorithm::EdDsa)
                    .cmp(&(b.alg == issuerd_core::Algorithm::EdDsa))
            })
            .then_with(|| a.kid.cmp(&b.kid))
    });
    let (default_alg, default_bits) = current
        .map(|k| key_params(&k.public_jwk))
        .unwrap_or((issuerd_core::Algorithm::EdDsa, 2048));

    let body = body.map(|Json(b)| b);
    let alg = match body.as_ref().and_then(|b| b.algorithm.as_deref()) {
        Some(raw) => raw
            .parse::<issuerd_core::Algorithm>()
            .map_err(|_| AdminApiError::BadRequest(format!("unknown signing algorithm: {raw}")))?,
        None => default_alg,
    };
    // Symmetric (HMAC) keys publish no usable public material (`k` is
    // stripped from the JWK), so a symmetric active signing key could never
    // be validated publicly — reject instead of bricking verification.
    if alg.is_symmetric() {
        return Err(AdminApiError::BadRequest(format!(
            "symmetric algorithm {alg} cannot be used as a signing key"
        )));
    }
    // `key_size` only feeds RSA generation; bound it so an absurd value
    // cannot hang a worker on a huge modulus. Non-RSA algorithms ignore it.
    if let Some(size) = body.as_ref().and_then(|b| b.key_size) {
        if is_rsa(alg) && !(RSA_KEY_SIZE_MIN..=RSA_KEY_SIZE_MAX).contains(&size) {
            return Err(AdminApiError::BadRequest(format!(
                "RSA key size must be {RSA_KEY_SIZE_MIN}..={RSA_KEY_SIZE_MAX} bits, got {size}"
            )));
        }
    }
    let bits = body.as_ref().and_then(|b| b.key_size).unwrap_or(default_bits);

    // A rotation on an EMPTY key set establishes the fresh-deployment set:
    // the requested algorithm's key plus — unless that is RS256 itself — an
    // active RS256 key, so the OIDC Core §15.1 MTI requirement (RS256
    // supported and advertised in discovery) holds from the start. On a
    // non-empty set exactly one new key is generated.
    let generated = if existing.is_empty() {
        issuerd_token::KeyStore::generate_initial_key_set(alg, bits)
    } else {
        issuerd_token::KeyStore::generate_key(alg, bits).map(|key| vec![key])
    }
    .map_err(|e| AdminApiError::BadRequest(format!("cannot generate {alg} key: {e}")))?;
    // The requested key is generated LAST (strictly the newest, so "newest
    // active key" selection prefers it); every generated key starts active.
    let mut stored_keys = Vec::with_capacity(generated.len());
    for key in &generated {
        let stored = key.to_stored(true);
        state.storage.create_signing_key(&stored).await?;
        stored_keys.push(stored);
    }
    let new_kids: Vec<issuerd_core::KeyId> = stored_keys.iter().map(|k| k.kid.clone()).collect();
    // Demote the other active keys of the SAME algorithm: exactly one active
    // key per algorithm going forward (a no-op on an empty pre-rotation set).
    for mut key in existing {
        if key.active && key.alg == alg && !new_kids.contains(&key.kid) {
            key.active = false;
            state.storage.update_signing_key(&key).await?;
        }
    }
    // Reload this node's keystore + JWKS snapshot immediately; peer cluster
    // nodes converge via the JWKS polling task.
    (state.signing_key_reload)();
    let primary = stored_keys.last().expect("rotation generates at least one key");
    info!(kid = %primary.kid, alg = %alg, "signing key rotated");

    let keys = state.storage.list_signing_keys().await?;
    let metadata = keys_metadata_from_stored(keys);
    // The audit event is attributed to the master realm (see
    // emit_global_admin_event): the path realm's events config cannot
    // suppress the trail of a server-global mutation.
    crate::audit::emit_global_admin_event(
        &state,
        &auth,
        issuerd_core::OperationType::Action,
        issuerd_core::ResourceType::Realm,
        "keys/rotate",
        serde_json::to_string(&metadata).ok(),
    )
    .await;
    Ok(Json(metadata))
}

#[utoipa::path(
    put,
    path = "/admin/realms/{realm}/keys/{kid}/disable",
    tag = "Keys",
    summary = "Disable a signing key",
    description = "Marks a key inactive. A disabled key is passive in Issuerd's model: it still validates previously issued tokens but never signs new ones. Fails with 400 when the target is the only active key (rotate first). Signing keys are server-global (shared `signing_keys` table); the realm path segment is namespace parity with Keycloak only. Requires a master-realm token with the `manage-realm` role; delegated realm admins cannot disable the server-global keys.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("kid" = String, Path, description = "Key ID"),
    ),
    responses(
        (status = 204, description = "Key disabled"),
        (status = 400, description = "Cannot disable the only active key", body = crate::error::AdminApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm or key not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn disable_key(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, kid)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, AdminApiError> {
    // Server-global key set: bound to a master-realm token (see rotate_keys).
    require_master_token(&auth)?;
    require_roles(&auth, &["manage-realm"])?;
    // The path realm is namespace parity only; it must still exist (404).
    state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let kid = issuerd_core::KeyId::new(kid)?;

    let keys = state.storage.list_signing_keys().await?;
    let mut target = keys.iter().find(|k| k.kid == kid).cloned().ok_or(AdminApiError::NotFound)?;
    if target.active && keys.iter().filter(|k| k.active).count() <= 1 {
        return Err(AdminApiError::BadRequest(
            "cannot disable the only active signing key; rotate first".to_string(),
        ));
    }
    target.active = false;
    state.storage.update_signing_key(&target).await?;
    // Reload this node's keystore + JWKS snapshot (see rotate_keys).
    (state.signing_key_reload)();
    info!(kid = %kid, alg = %target.alg, "signing key disabled");

    crate::audit::emit_global_admin_event(
        &state,
        &auth,
        issuerd_core::OperationType::Update,
        issuerd_core::ResourceType::Realm,
        &format!("keys/{kid}/disable"),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use issuerd_core::Algorithm;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn key_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route("/admin/realms/{realm}/keys", get(get_keys))
            .route("/admin/realms/{realm}/keys/rotate", axum::routing::post(rotate_keys))
            .route("/admin/realms/{realm}/keys/{kid}/disable", axum::routing::put(disable_key))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    fn noop_reload() -> Arc<dyn Fn() + Send + Sync> {
        Arc::new(|| {})
    }

    fn test_state(
        storage: Arc<issuerd_storage::InMemoryStorage>,
        reload: Arc<dyn Fn() + Send + Sync>,
    ) -> Arc<AdminApiState> {
        test_state_with_token_service(
            storage,
            reload,
            Arc::new(crate::test_utils::tests::MockTokenService {
                roles: vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
            }),
        )
    }

    fn test_state_with_token_service(
        storage: Arc<issuerd_storage::InMemoryStorage>,
        reload: Arc<dyn Fn() + Send + Sync>,
        token_service: Arc<dyn issuerd_core::TokenService>,
    ) -> Arc<AdminApiState> {
        Arc::new(AdminApiState {
            storage,
            token_service,
            crypto: Arc::new(issuerd_core::MockCryptoProvider::new()),
            federation_manager: Arc::new(issuerd_federation::NoOpFederationManager),
            plugin_registry: Arc::new(crate::test_utils::tests::stub_plugin_registry()),
            cache: Arc::new(issuerd_cluster::InMemoryCache::new()),
            email_sender: Arc::new(issuerd_core::MockEmailSender::new()),
            broker_client: Arc::new(issuerd_core::MockBrokerClient::new()),
            logout_notifier: Arc::new(issuerd_core::NoOpSessionLogoutNotifier),
            available_themes: vec!["issuerd".to_string()],
            token_issuer: Arc::new(crate::test_utils::tests::StubTokenIssuer::new()),
            base_url: "http://localhost:8080".to_string(),
            signing_key_reload: reload,
        })
    }

    /// Token service issuing a NON-master realm token (issuer realm `test`)
    /// carrying manage-realm — a delegated admin of the path realm.
    struct TenantTokenService;

    impl issuerd_core::TokenService for TenantTokenService {
        fn validate_access_token(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::ValidatedAccessToken, issuerd_core::IssuerdError> {
            Ok(issuerd_core::ValidatedAccessToken {
                claims: issuerd_core::AccessTokenClaims {
                    jti: issuerd_core::JwtId::new("jti").unwrap(),
                    iss: issuerd_core::Issuer::new("http://localhost:8080/realms/test").unwrap(),
                    sub: issuerd_core::UserId::new("admin").unwrap(),
                    aud: issuerd_core::Audience::new("aud").unwrap(),
                    exp: 9999999999,
                    iat: 0,
                    nbf: 0,
                    scope: issuerd_core::Scope::parse("openid"),
                    typ: issuerd_core::JwtType::Bearer,
                    azp: None,
                    session_state: None,
                    realm_access: Some(issuerd_core::RealmAccess {
                        roles: vec![issuerd_core::RoleName::new("manage-realm").unwrap()],
                    }),
                    resource_access: None,
                    sid: None,
                    claims: None,
                    cnf: None,
                    authorization_details: None,
                },
                header: issuerd_core::JwsHeader {
                    alg: Algorithm::Rs256,
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
        ) -> Result<issuerd_core::IdTokenClaims, issuerd_core::IssuerdError> {
            unimplemented!()
        }

        fn validate_refresh_token(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::ValidatedRefreshToken, issuerd_core::IssuerdError> {
            unimplemented!()
        }

        fn validate_id_token_hint(
            &self,
            _token: &str,
        ) -> Result<issuerd_core::IdTokenClaims, issuerd_core::IssuerdError> {
            unimplemented!()
        }
    }

    async fn seed_key_with_alg(
        storage: &Arc<issuerd_storage::InMemoryStorage>,
        alg: Algorithm,
        active: bool,
    ) -> issuerd_core::StoredSigningKey {
        let key = issuerd_token::KeyStore::generate_key(alg, 2048).unwrap().to_stored(active);
        issuerd_core::Storage::create_signing_key(storage.as_ref(), &key).await.unwrap();
        key
    }

    #[tokio::test]
    async fn get_keys_returns_metadata() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        seed_key_with_alg(&storage, Algorithm::Rs256, true).await;
        let state = test_state(storage, noop_reload());
        let app = key_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/keys")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_keys_multiple_keys_active_and_passive() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let active_key = seed_key_with_alg(&storage, Algorithm::Rs256, true).await;
        seed_key_with_alg(&storage, Algorithm::Rs256, false).await;
        let state = test_state(storage, noop_reload());
        let app = key_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/test/keys")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(meta.active.len(), 1);
        assert_eq!(meta.active.get("RS256").unwrap(), &active_key.kid.to_string());
        assert_eq!(meta.passive.len(), 2);
        assert_eq!(meta.passive[0].status, issuerd_core::KeyStatus::Active);
        assert_eq!(meta.passive[1].status, issuerd_core::KeyStatus::Passive);
    }

    // ------------------------------------------------------------------
    // Rotation / disable
    // ------------------------------------------------------------------

    async fn create_test_realm(
        storage: &Arc<issuerd_storage::InMemoryStorage>,
        admin_events: bool,
    ) -> issuerd_core::Realm {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            admin_events_enabled: admin_events,
            include_representations: admin_events,
            ..Default::default()
        };
        issuerd_core::Storage::create_realm(storage.as_ref(), &realm).await.unwrap();
        realm
    }

    async fn seed_key(
        storage: &Arc<issuerd_storage::InMemoryStorage>,
        active: bool,
    ) -> issuerd_core::StoredSigningKey {
        seed_key_with_alg(storage, Algorithm::Rs256, active).await
    }

    /// Enable admin-event recording and representation storage on the master
    /// realm (the realm key-administration events are attributed to).
    async fn configure_master_audit(
        storage: &Arc<issuerd_storage::InMemoryStorage>,
        include_representations: bool,
    ) {
        let mut master = issuerd_core::Storage::get_realm_by_name(storage.as_ref(), "master")
            .await
            .unwrap()
            .unwrap();
        master.admin_events_enabled = true;
        master.include_representations = include_representations;
        issuerd_core::Storage::update_realm(storage.as_ref(), &master).await.unwrap();
    }

    async fn admin_events(
        state: &Arc<AdminApiState>,
        realm_id: &str,
    ) -> Vec<issuerd_core::AdminEvent> {
        state
            .storage
            .query_admin_events(
                &issuerd_core::RealmId::new(realm_id).unwrap(),
                &issuerd_core::AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: issuerd_core::Pagination::default(),
                },
            )
            .await
            .unwrap()
    }

    fn flag_reload() -> (Arc<dyn Fn() + Send + Sync>, Arc<std::sync::atomic::AtomicBool>) {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let captured = flag.clone();
        (
            Arc::new(move || {
                captured.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
            flag,
        )
    }

    async fn call(app: Router, method: &str, uri: &str) -> (StatusCode, Vec<u8>) {
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, bytes.to_vec())
    }

    async fn call_json(
        app: Router,
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, Vec<u8>) {
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("Authorization", "Bearer valid-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, bytes.to_vec())
    }

    #[tokio::test]
    async fn rotate_keys_generates_new_active_and_demotes_old() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, true).await;
        configure_master_audit(&storage, true).await;
        let old = seed_key(&storage, true).await;

        let (reload, called) = flag_reload();
        let state = test_state(storage, reload);

        let (status, body) =
            call(key_routes(state.clone()), "POST", "/admin/realms/test/keys/rotate").await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();

        // Exactly one active key, and it is not the old one.
        assert_eq!(meta.active.len(), 1);
        let new_kid = meta.active.get("RS256").unwrap().clone();
        assert_ne!(new_kid, old.kid.to_string());
        assert_eq!(meta.passive.len(), 2);
        assert_eq!(meta.passive[0].kid, new_kid);
        assert_eq!(meta.passive[0].status, issuerd_core::KeyStatus::Active);
        assert_eq!(meta.passive[1].kid, old.kid.to_string());
        assert_eq!(meta.passive[1].status, issuerd_core::KeyStatus::Passive);

        // Storage agrees: new key active, old key demoted.
        let stored = state.storage.list_signing_keys().await.unwrap();
        let old_stored = stored.iter().find(|k| k.kid == old.kid).unwrap();
        assert!(!old_stored.active);
        let new_stored = stored.iter().find(|k| k.kid.to_string() == new_kid).unwrap();
        assert!(new_stored.active);

        // The same-node reload hook fired.
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));

        // The audit event is attributed to the MASTER realm (the keys are
        // server-global; the path realm only provides namespace parity).
        let events = admin_events(&state, "master").await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, issuerd_core::OperationType::Action);
        assert_eq!(events[0].resource_path, "keys/rotate");
        assert!(events[0].representation.as_ref().unwrap().contains(&new_kid));
        assert_eq!(events[0].auth_realm_id, Some(issuerd_core::RealmId::new("master").unwrap()));
        assert!(admin_events(&state, "realm-1").await.is_empty());
    }

    #[tokio::test]
    async fn rotate_keys_without_existing_keys_uses_server_default_fallback() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;

        let (reload, called) = flag_reload();
        let state = test_state(storage, reload);

        let (status, body) =
            call(key_routes(state.clone()), "POST", "/admin/realms/test/keys/rotate").await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();
        // The no-keys fallback establishes the fresh-deployment PAIR: the
        // server-default algorithm (EdDSA) plus an active RS256 key (OIDC
        // Core §15.1 — RS256 must be supported and advertised).
        assert_eq!(meta.active.len(), 2);
        assert_eq!(meta.passive.len(), 2);
        assert!(meta.active.contains_key("EdDSA"));
        assert!(meta.active.contains_key("RS256"));
        assert_eq!(meta.passive[0].algorithm, Algorithm::EdDsa);
        assert_eq!(meta.passive[0].status, issuerd_core::KeyStatus::Active);
        assert_eq!(meta.passive[1].algorithm, Algorithm::Rs256);
        assert_eq!(meta.passive[1].status, issuerd_core::KeyStatus::Active);
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn rotate_keys_on_empty_set_with_explicit_algorithm_adds_mti_rs256() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;

        let (reload, _) = flag_reload();
        let state = test_state(storage, reload);

        // Explicit non-RSA algorithm on an empty set: the requested key plus
        // the RS256 MTI key.
        let (status, body) = call_json(
            key_routes(state.clone()),
            "POST",
            "/admin/realms/test/keys/rotate",
            serde_json::json!({"algorithm": "ES256"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(meta.active.len(), 2);
        assert!(meta.active.contains_key("ES256"));
        assert!(meta.active.contains_key("RS256"));
    }

    #[tokio::test]
    async fn rotate_keys_on_empty_set_with_explicit_rs256_stays_single() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;

        let (reload, _) = flag_reload();
        let state = test_state(storage, reload);

        // Explicit RS256 on an empty set already covers the MTI key — no
        // second key is generated.
        let (status, body) = call_json(
            key_routes(state.clone()),
            "POST",
            "/admin/realms/test/keys/rotate",
            serde_json::json!({"algorithm": "RS256"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(meta.active.len(), 1);
        assert!(meta.active.contains_key("RS256"));
    }

    // ------------------------------------------------------------------
    // Per-algorithm rotation
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_with_algorithm_keeps_other_algorithms_active() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        let rsa = seed_key(&storage, true).await;

        let (reload, _) = flag_reload();
        let state = test_state(storage, reload);

        // Add an ES256 active key: the RS256 key must stay active.
        let (status, body) = call_json(
            key_routes(state.clone()),
            "POST",
            "/admin/realms/test/keys/rotate",
            serde_json::json!({"algorithm": "ES256"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(meta.active.len(), 2);
        assert_eq!(meta.active.get("RS256").unwrap(), &rsa.kid.to_string());
        let es_kid = meta.active.get("ES256").unwrap().clone();

        // Rotating ES256 again demotes only the old ES256 key.
        let (status, body) = call_json(
            key_routes(state.clone()),
            "POST",
            "/admin/realms/test/keys/rotate",
            serde_json::json!({"algorithm": "ES256"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(meta.active.len(), 2);
        assert_eq!(meta.active.get("RS256").unwrap(), &rsa.kid.to_string());
        let es_kid2 = meta.active.get("ES256").unwrap().clone();
        assert_ne!(es_kid, es_kid2);

        let stored = state.storage.list_signing_keys().await.unwrap();
        assert!(stored.iter().find(|k| k.kid == rsa.kid).unwrap().active);
        assert!(!stored.iter().find(|k| k.kid.to_string() == es_kid).unwrap().active);
        assert!(stored.iter().find(|k| k.kid.to_string() == es_kid2).unwrap().active);
    }

    #[tokio::test]
    async fn rotate_with_unknown_algorithm_rejected() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        seed_key(&storage, true).await;

        let (reload, called) = flag_reload();
        let state = test_state(storage, reload);

        let (status, body) = call_json(
            key_routes(state.clone()),
            "POST",
            "/admin/realms/test/keys/rotate",
            serde_json::json!({"algorithm": "FOOBAR"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8(body).unwrap().contains("unknown signing algorithm"));
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn rotate_with_hmac_algorithm_rejected() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        seed_key(&storage, true).await;

        let (reload, called) = flag_reload();
        let state = test_state(storage, reload);

        let (status, body) = call_json(
            key_routes(state.clone()),
            "POST",
            "/admin/realms/test/keys/rotate",
            serde_json::json!({"algorithm": "HS256"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8(body).unwrap().contains("symmetric algorithm"));
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        // No key was created; the seeded RS256 key stays the only one.
        let stored = state.storage.list_signing_keys().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].alg, Algorithm::Rs256);
    }

    #[tokio::test]
    async fn rotate_with_out_of_range_rsa_key_size_rejected() {
        for size in [512u32, 16384] {
            let storage = crate::test_utils::tests::storage_with_master_realm();
            create_test_realm(&storage, false).await;
            seed_key(&storage, true).await;

            let (reload, called) = flag_reload();
            let state = test_state(storage, reload);

            let (status, body) = call_json(
                key_routes(state.clone()),
                "POST",
                "/admin/realms/test/keys/rotate",
                serde_json::json!({"algorithm": "RS256", "key_size": size}),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "key_size {size} must be rejected");
            assert!(String::from_utf8(body).unwrap().contains("RSA key size"));
            assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn rotate_with_explicit_valid_rsa_key_size_succeeds() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        seed_key(&storage, true).await;

        let (reload, called) = flag_reload();
        let state = test_state(storage, reload);

        let (status, body) = call_json(
            key_routes(state.clone()),
            "POST",
            "/admin/realms/test/keys/rotate",
            serde_json::json!({"algorithm": "RS256", "key_size": 2048}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();
        assert_eq!(meta.active.len(), 1);
        assert!(meta.active.contains_key("RS256"));
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn rotate_ignores_key_size_for_non_rsa_algorithm() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        seed_key(&storage, true).await;

        let (reload, _) = flag_reload();
        let state = test_state(storage, reload);

        // 512 would be out of range for RSA; for EC it is simply ignored.
        let (status, body) = call_json(
            key_routes(state.clone()),
            "POST",
            "/admin/realms/test/keys/rotate",
            serde_json::json!({"algorithm": "ES256", "key_size": 512}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();
        assert!(meta.active.contains_key("ES256"));
    }

    #[tokio::test]
    async fn rotate_with_es512_algorithm_succeeds() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;

        let (reload, _) = flag_reload();
        let state = test_state(storage, reload);

        let (status, body) = call_json(
            key_routes(state.clone()),
            "POST",
            "/admin/realms/test/keys/rotate",
            serde_json::json!({"algorithm": "ES512"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();
        assert!(meta.active.contains_key("ES512"));
        let es512 = meta.passive.iter().find(|k| k.algorithm == Algorithm::Es512).unwrap();
        assert_eq!(es512.provider_id, "ecdsa-generated");
    }

    #[tokio::test]
    async fn disable_key_marks_it_passive() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        // The path realm has admin-event recording DISABLED — it must not
        // suppress the audit trail of a server-global mutation.
        create_test_realm(&storage, false).await;
        seed_key(&storage, true).await;
        let target = seed_key(&storage, true).await;

        let (reload, called) = flag_reload();
        let state = test_state(storage, reload);

        let (status, _) = call(
            key_routes(state.clone()),
            "PUT",
            &format!("/admin/realms/test/keys/{}/disable", target.kid),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let stored = state.storage.list_signing_keys().await.unwrap();
        let disabled = stored.iter().find(|k| k.kid == target.kid).unwrap();
        assert!(!disabled.active);
        assert_eq!(stored.iter().filter(|k| k.active).count(), 1);
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));

        // The audit event landed on the master realm despite the path
        // realm's disabled recording.
        let events = admin_events(&state, "master").await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, issuerd_core::OperationType::Update);
        assert_eq!(events[0].resource_path, format!("keys/{}/disable", target.kid));
        assert!(admin_events(&state, "realm-1").await.is_empty());
    }

    #[tokio::test]
    async fn disable_only_active_key_rejected() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        let only = seed_key(&storage, true).await;

        let (reload, called) = flag_reload();
        let state = test_state(storage, reload);

        let (status, _) = call(
            key_routes(state.clone()),
            "PUT",
            &format!("/admin/realms/test/keys/{}/disable", only.kid),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Still active, and the reload hook never fired.
        let stored = state.storage.list_signing_keys().await.unwrap();
        assert!(stored.iter().find(|k| k.kid == only.kid).unwrap().active);
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn disable_unknown_kid_404() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        seed_key(&storage, true).await;

        let (reload, called) = flag_reload();
        let state = test_state(storage, reload);

        let (status, _) =
            call(key_routes(state.clone()), "PUT", "/admin/realms/test/keys/no-such-kid/disable")
                .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    }

    // ------------------------------------------------------------------
    // Master-realm authorization (server-global key set)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_keys_rejects_non_master_token() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        seed_key(&storage, true).await;

        let (reload, called) = flag_reload();
        // A delegated admin of the path realm (manage-realm, issuer `test`).
        let state = test_state_with_token_service(storage, reload, Arc::new(TenantTokenService));

        let (status, _) =
            call(key_routes(state.clone()), "POST", "/admin/realms/test/keys/rotate").await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // No mutation, no reload, no audit event anywhere.
        let stored = state.storage.list_signing_keys().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].active);
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        assert!(admin_events(&state, "master").await.is_empty());
        assert!(admin_events(&state, "realm-1").await.is_empty());
    }

    #[tokio::test]
    async fn disable_key_rejects_non_master_token() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        seed_key(&storage, true).await;
        let target = seed_key(&storage, true).await;

        let (reload, called) = flag_reload();
        let state = test_state_with_token_service(storage, reload, Arc::new(TenantTokenService));

        let (status, _) = call(
            key_routes(state.clone()),
            "PUT",
            &format!("/admin/realms/test/keys/{}/disable", target.kid),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Both keys stay active; no reload, no audit event anywhere.
        let stored = state.storage.list_signing_keys().await.unwrap();
        assert_eq!(stored.iter().filter(|k| k.active).count(), 2);
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        assert!(admin_events(&state, "master").await.is_empty());
        assert!(admin_events(&state, "realm-1").await.is_empty());
    }

    #[tokio::test]
    async fn rotate_keys_audit_event_survives_path_realm_events_disabled() {
        let storage = crate::test_utils::tests::storage_with_master_realm();
        // Path realm with admin-event recording DISABLED: before the
        // master-realm attribution, this suppressed the audit trail of the
        // global mutation entirely.
        create_test_realm(&storage, false).await;
        seed_key(&storage, true).await;

        let (reload, _) = flag_reload();
        let state = test_state(storage, reload);

        let (status, _) =
            call(key_routes(state.clone()), "POST", "/admin/realms/test/keys/rotate").await;
        assert_eq!(status, StatusCode::OK);

        // The event is recorded against the master realm (master config
        // defaults: admin events on, representations off).
        let events = admin_events(&state, "master").await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, issuerd_core::OperationType::Action);
        assert_eq!(events[0].resource_path, "keys/rotate");
        assert_eq!(events[0].representation, None);
        assert!(admin_events(&state, "realm-1").await.is_empty());
    }

    #[test]
    fn key_params_derives_rsa_bits_from_modulus_length() {
        // An RSA-2048 modulus base64url-encodes to 342 chars; 6 bits per char
        // rounded down to whole bytes restores the 2048-bit size.
        let rsa = issuerd_token::KeyStore::generate_key(Algorithm::Rs256, 2048).unwrap();
        assert_eq!(key_params(&rsa.public_jwk), (Algorithm::Rs256, 2048));

        // Non-RSA keys carry no modulus: the size defaults to 2048 and is
        // ignored by generation downstream.
        let ed = issuerd_token::KeyStore::generate_key(Algorithm::EdDsa, 2048).unwrap();
        assert_eq!(key_params(&ed.public_jwk), (Algorithm::EdDsa, 2048));
    }

    #[tokio::test]
    async fn rotate_keys_tie_prefers_server_default_algorithm() {
        // Two active keys persisted in the same microsecond (the fresh-boot
        // pair can land like that): the empty-body rotation must pick the
        // server-default algorithm (EdDSA), not whichever key the kid
        // tie-break or storage iteration order would surface. The EdDSA key
        // deliberately gets the SMALLER kid so a broken algorithm tie-break
        // deterministically resolves to RS256 instead.
        let storage = crate::test_utils::tests::storage_with_master_realm();
        create_test_realm(&storage, false).await;
        let created_at = chrono::Utc::now();
        let mut ed = issuerd_token::KeyStore::generate_key(Algorithm::EdDsa, 2048)
            .unwrap()
            .to_stored(true);
        ed.created_at = created_at;
        ed.kid = issuerd_core::KeyId::new("aaaa").unwrap();
        let mut rsa = issuerd_token::KeyStore::generate_key(Algorithm::Rs256, 2048)
            .unwrap()
            .to_stored(true);
        rsa.created_at = created_at;
        rsa.kid = issuerd_core::KeyId::new("zzzz").unwrap();
        issuerd_core::Storage::create_signing_key(storage.as_ref(), &ed).await.unwrap();
        issuerd_core::Storage::create_signing_key(storage.as_ref(), &rsa).await.unwrap();

        let (reload, _) = flag_reload();
        let state = test_state(storage, reload);

        let (status, body) =
            call(key_routes(state.clone()), "POST", "/admin/realms/test/keys/rotate").await;
        assert_eq!(status, StatusCode::OK);
        let meta: KeysMetadataRepresentation = serde_json::from_slice(&body).unwrap();

        // A new EdDSA key is active; the seeded EdDSA key is demoted, the
        // other-algorithm RS256 key keeps signing.
        let ed_kid = meta.active.get("EdDSA").expect("EdDSA stays active").clone();
        assert_ne!(ed_kid, "aaaa", "rotation replaced the seeded EdDSA key");
        assert_eq!(meta.active.get("RS256").map(String::as_str), Some("zzzz"));
        let demoted = meta.passive.iter().find(|k| k.kid == "aaaa").unwrap();
        assert_eq!(demoted.status, issuerd_core::KeyStatus::Passive);
    }
}
