// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Client adapter-config download endpoints (keycloak.json, generic OIDC).

//! Client installation endpoints — Keycloak's "Download adapter config"
//! (`ClientResource.getInstallationProvider`).
//!
//! `GET /admin/realms/{realm}/clients/{id}/installation/providers/{provider_id}`
//! renders the client configuration in a provider-specific, downloadable
//! format:
//!
//! - `keycloak-oidc-keycloak-json` — the Keycloak OIDC adapter `keycloak.json`
//! - `generic-oidc-json` — product-neutral OIDC client configuration
//!
//! Unknown provider ids return 404, matching Keycloak's `NotFoundException`.

use axum::{
    extract::{Extension, State},
    Json,
};
use issuerd_core::{ClientId, Pagination};
use std::sync::Arc;

use crate::{
    auth::{require_roles, AdminAuth},
    dto::{
        AdapterCredentials, ClientInstallationProviderRepresentation,
        ClientInstallationRepresentation, GenericOidcClientConfigRepresentation,
        KeycloakAdapterConfigRepresentation,
    },
    error::AdminApiError,
    state::AdminApiState,
};

/// Provider id of the Keycloak OIDC adapter JSON format (`keycloak.json`).
pub const KEYCLOAK_OIDC_JSON_PROVIDER_ID: &str = "keycloak-oidc-keycloak-json";
/// Provider id of the generic OIDC client configuration JSON format.
pub const GENERIC_OIDC_JSON_PROVIDER_ID: &str = "generic-oidc-json";

/// Metadata of all available installation providers.
///
/// Drives the serverinfo `client_installations` list, which the admin SPA
/// uses to populate the "Download adapter config" format dropdown.
pub fn providers() -> Vec<ClientInstallationProviderRepresentation> {
    vec![
        ClientInstallationProviderRepresentation {
            id: KEYCLOAK_OIDC_JSON_PROVIDER_ID.to_string(),
            protocol: "openid-connect".to_string(),
            display_type: "Keycloak OIDC JSON".to_string(),
            help_text: "keycloak.json file used by Keycloak-compatible OIDC client adapters \
                to configure clients. Save it as keycloak.json in your application; you may \
                want to tweak it after downloading."
                .to_string(),
            filename: "keycloak.json".to_string(),
            media_type: "application/json".to_string(),
            download_only: false,
        },
        ClientInstallationProviderRepresentation {
            id: GENERIC_OIDC_JSON_PROVIDER_ID.to_string(),
            protocol: "openid-connect".to_string(),
            display_type: "Generic OIDC JSON".to_string(),
            help_text: "Product-neutral OIDC client configuration containing the issuer, \
                endpoint URLs, and the client's registration data."
                .to_string(),
            filename: "oidc-client-config.json".to_string(),
            media_type: "application/json".to_string(),
            download_only: false,
        },
    ]
}

/// Build the Keycloak adapter config (`keycloak.json`) for a client.
///
/// Mirrors `KeycloakOIDCClientInstallation.generateInstallation`:
/// `credentials` are included when the client can authenticate with a secret
/// (confidential, or bearer-only with service accounts enabled) **and actually
/// holds one** — confidential clients without a stored secret (e.g. JWT client
/// auth) get no `credentials` block, like Keycloak, rather than an empty
/// secret that would make the adapter attempt client-secret authentication.
/// The resource-role flags are set when the client defines its own roles.
fn keycloak_adapter_config(
    realm: &issuerd_core::Realm,
    client: &issuerd_core::Client,
    base_url: &str,
    has_client_roles: bool,
) -> KeycloakAdapterConfigRepresentation {
    let show_credentials =
        !client.public_client && (!client.bearer_only || client.service_accounts_enabled);
    KeycloakAdapterConfigRepresentation {
        realm: realm.name.to_string(),
        auth_server_url: format!("{base_url}/"),
        ssl_required: realm.ssl_required,
        resource: client.client_id.to_string(),
        public_client: (client.public_client && !client.bearer_only).then_some(true),
        bearer_only: client.bearer_only.then_some(true),
        use_resource_role_mappings: has_client_roles.then_some(true),
        verify_token_audience: has_client_roles.then_some(true),
        credentials: client
            .secret
            .clone()
            .filter(|_| show_credentials)
            .map(|secret| AdapterCredentials { secret }),
    }
}

/// Build the generic OIDC client configuration for a client.
///
/// Endpoint paths mirror the OIDC routes registered in
/// `issuerd-server/src/routes.rs` (`/realms/{realm}/protocol/openid-connect/...`).
fn generic_oidc_config(
    client: &issuerd_core::Client,
    base_url: &str,
    realm_name: &str,
) -> GenericOidcClientConfigRepresentation {
    let realm_base = format!("{base_url}/realms/{realm_name}");
    let oidc = format!("{realm_base}/protocol/openid-connect");
    GenericOidcClientConfigRepresentation {
        issuer: realm_base,
        authorization_endpoint: format!("{oidc}/auth"),
        token_endpoint: format!("{oidc}/token"),
        userinfo_endpoint: format!("{oidc}/userinfo"),
        jwks_uri: format!("{oidc}/certs"),
        end_session_endpoint: format!("{oidc}/logout"),
        introspection_endpoint: format!("{oidc}/token/introspect"),
        client_id: client.client_id.to_string(),
        // Secret-less confidential clients (e.g. JWT client auth) omit the
        // field entirely — an empty string would read as client-secret auth.
        client_secret: client.secret.clone().filter(|_| !client.public_client),
        redirect_uris: client.redirect_uris.iter().map(ToString::to_string).collect(),
    }
}

#[utoipa::path(
    get,
    path = "/admin/realms/{realm}/clients/{id}/installation/providers/{provider_id}",
    tag = "Clients",
    summary = "Download client adapter configuration",
    description = "Renders the client configuration in a provider-specific downloadable format (`keycloak-oidc-keycloak-json` for the Keycloak adapter `keycloak.json`, `generic-oidc-json` for a product-neutral OIDC config). Unknown provider ids return 404. Requires `view-clients` or `manage-clients` role.",
    params(
        ("realm" = String, Path, description = "Realm name"),
        ("id" = String, Path, description = "Client ID (internal UUID)"),
        ("provider_id" = String, Path, description = "Installation provider id (see serverinfo `client_installations`)")
    ),
    responses(
        (status = 200, description = "Client configuration in the requested format", body = ClientInstallationRepresentation),
        (status = 401, description = "Unauthorized", body = crate::error::AdminApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::AdminApiErrorResponse),
        (status = 404, description = "Realm, client, or provider not found", body = crate::error::AdminApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::AdminApiErrorResponse),
    )
)]
pub async fn get_installation_provider(
    State(state): State<Arc<AdminApiState>>,
    Extension(auth): Extension<AdminAuth>,
    axum::extract::Path((realm, id, provider_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<ClientInstallationRepresentation>, AdminApiError> {
    require_roles(&auth, &["view-clients", "manage-clients"])?;
    let realm_model =
        state.storage.get_realm_by_name(&realm).await?.ok_or(AdminApiError::NotFound)?;
    let client_id = ClientId::new(&id).map_err(|e| AdminApiError::BadRequest(e.to_string()))?;
    let client = state
        .storage
        .get_client(&realm_model.id, &client_id)
        .await?
        .ok_or(AdminApiError::NotFound)?;

    match provider_id.as_str() {
        KEYCLOAK_OIDC_JSON_PROVIDER_ID => {
            // Keycloak sets the resource-role flags when the client defines
            // roles of its own; one row is enough to know.
            let has_client_roles = !state
                .storage
                .list_client_roles(&realm_model.id, &client.id, &Pagination::new(0, 1))
                .await?
                .is_empty();
            Ok(Json(ClientInstallationRepresentation::Keycloak(keycloak_adapter_config(
                &realm_model,
                &client,
                &state.base_url,
                has_client_roles,
            ))))
        }
        GENERIC_OIDC_JSON_PROVIDER_ID => Ok(Json(ClientInstallationRepresentation::GenericOidc(
            generic_oidc_config(&client, &state.base_url, &realm),
        ))),
        _ => Err(AdminApiError::NotFound),
    }
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
    use issuerd_core::{ClientAuthenticatorType, ClientProtocol};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn installation_routes(state: Arc<AdminApiState>) -> Router {
        Router::new()
            .route(
                "/admin/realms/{realm}/clients/{id}/installation/providers/{provider_id}",
                get(get_installation_provider),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::admin_auth_middleware,
            ))
            .with_state(state)
    }

    fn test_client(realm_id: &issuerd_core::RealmId) -> issuerd_core::Client {
        issuerd_core::Client {
            id: issuerd_core::ClientId::new("client-1").unwrap(),
            realm_id: realm_id.clone(),
            client_id: issuerd_core::ClientIdentifier::new("my-app").unwrap(),
            name: Some(issuerd_core::DisplayName::new("My App").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: Some("old-secret".to_string()),
            redirect_uris: vec![
                issuerd_core::RedirectUri::new("https://app.example.com/cb").unwrap()
            ],
            web_origins: vec![],
            default_scopes: issuerd_core::Scope::empty(),
            optional_scopes: issuerd_core::Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        }
    }

    async fn setup(state: &Arc<AdminApiState>, client: issuerd_core::Client) {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new("realm-1").unwrap(),
            name: issuerd_core::RealmName::new("test").unwrap(),
            ..Default::default()
        };
        state.storage.create_realm(&realm).await.unwrap();
        state.storage.create_client(&realm.id, &client).await.unwrap();
    }

    async fn get_json(
        app: Router,
        realm: &str,
        client_id: &str,
        provider_id: &str,
    ) -> (StatusCode, serde_json::Value) {
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/admin/realms/{realm}/clients/{client_id}/installation/providers/{provider_id}"
                    ))
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn keycloak_json_confidential_client() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        setup(&state, test_client(&issuerd_core::RealmId::new("realm-1").unwrap())).await;
        let app = installation_routes(state);

        let (status, json) =
            get_json(app, "test", "client-1", KEYCLOAK_OIDC_JSON_PROVIDER_ID).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json,
            serde_json::json!({
                "realm": "test",
                "auth-server-url": "http://localhost:8080/",
                "ssl-required": "external",
                "resource": "my-app",
                "credentials": { "secret": "old-secret" }
            })
        );
    }

    #[tokio::test]
    async fn keycloak_json_public_client_has_no_credentials() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let mut client = test_client(&issuerd_core::RealmId::new("realm-1").unwrap());
        client.public_client = true;
        client.secret = None;
        setup(&state, client).await;
        let app = installation_routes(state);

        let (status, json) =
            get_json(app, "test", "client-1", KEYCLOAK_OIDC_JSON_PROVIDER_ID).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["public-client"], serde_json::json!(true));
        assert!(json.get("credentials").is_none());
        assert!(json.get("bearer-only").is_none());
    }

    #[tokio::test]
    async fn keycloak_json_secretless_confidential_client_omits_credentials() {
        // e.g. JWT client auth: confidential, but no stored secret — the
        // adapter must not receive an empty `"secret"`.
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let mut client = test_client(&issuerd_core::RealmId::new("realm-1").unwrap());
        client.client_authenticator_type = ClientAuthenticatorType::ClientJwt;
        client.secret = None;
        setup(&state, client).await;
        let app = installation_routes(state);

        let (status, json) =
            get_json(app, "test", "client-1", KEYCLOAK_OIDC_JSON_PROVIDER_ID).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["resource"], serde_json::json!("my-app"));
        assert!(json.get("credentials").is_none());
    }

    #[tokio::test]
    async fn keycloak_json_bearer_only_client_without_service_accounts_hides_credentials() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let mut client = test_client(&issuerd_core::RealmId::new("realm-1").unwrap());
        client.bearer_only = true;
        setup(&state, client).await;
        let app = installation_routes(state);

        let (status, json) =
            get_json(app, "test", "client-1", KEYCLOAK_OIDC_JSON_PROVIDER_ID).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["bearer-only"], serde_json::json!(true));
        assert!(json.get("public-client").is_none());
        assert!(json.get("credentials").is_none());
    }

    #[tokio::test]
    async fn keycloak_json_client_with_roles_sets_resource_role_flags() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let realm_id = issuerd_core::RealmId::new("realm-1").unwrap();
        setup(&state, test_client(&realm_id)).await;
        let role = issuerd_core::Role {
            id: issuerd_core::RoleId::new("role-1").unwrap(),
            name: issuerd_core::RoleName::new("app-admin").unwrap(),
            description: None,
            realm_id: realm_id.clone(),
            client_role: true,
            client_id: Some(issuerd_core::ClientId::new("client-1").unwrap()),
            composite: false,
            composites: vec![],
            attributes: std::collections::HashMap::new(),
        };
        state.storage.create_role(&realm_id, &role).await.unwrap();
        let app = installation_routes(state);

        let (status, json) =
            get_json(app, "test", "client-1", KEYCLOAK_OIDC_JSON_PROVIDER_ID).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["use-resource-role-mappings"], serde_json::json!(true));
        assert_eq!(json["verify-token-audience"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn generic_oidc_json_confidential_client() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        setup(&state, test_client(&issuerd_core::RealmId::new("realm-1").unwrap())).await;
        let app = installation_routes(state);

        let (status, json) = get_json(app, "test", "client-1", GENERIC_OIDC_JSON_PROVIDER_ID).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json,
            serde_json::json!({
                "issuer": "http://localhost:8080/realms/test",
                "authorization_endpoint": "http://localhost:8080/realms/test/protocol/openid-connect/auth",
                "token_endpoint": "http://localhost:8080/realms/test/protocol/openid-connect/token",
                "userinfo_endpoint": "http://localhost:8080/realms/test/protocol/openid-connect/userinfo",
                "jwks_uri": "http://localhost:8080/realms/test/protocol/openid-connect/certs",
                "end_session_endpoint": "http://localhost:8080/realms/test/protocol/openid-connect/logout",
                "introspection_endpoint": "http://localhost:8080/realms/test/protocol/openid-connect/token/introspect",
                "client_id": "my-app",
                "client_secret": "old-secret",
                "redirect_uris": ["https://app.example.com/cb"]
            })
        );
    }

    #[tokio::test]
    async fn generic_oidc_json_public_client_omits_secret() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let mut client = test_client(&issuerd_core::RealmId::new("realm-1").unwrap());
        client.public_client = true;
        client.secret = None;
        setup(&state, client).await;
        let app = installation_routes(state);

        let (status, json) = get_json(app, "test", "client-1", GENERIC_OIDC_JSON_PROVIDER_ID).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["client_id"], serde_json::json!("my-app"));
        assert!(json.get("client_secret").is_none());
    }

    #[tokio::test]
    async fn generic_oidc_json_secretless_confidential_client_omits_secret() {
        // e.g. JWT client auth: confidential, but no stored secret.
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let mut client = test_client(&issuerd_core::RealmId::new("realm-1").unwrap());
        client.client_authenticator_type = ClientAuthenticatorType::ClientJwt;
        client.secret = None;
        setup(&state, client).await;
        let app = installation_routes(state);

        let (status, json) = get_json(app, "test", "client-1", GENERIC_OIDC_JSON_PROVIDER_ID).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["client_id"], serde_json::json!("my-app"));
        assert!(json.get("client_secret").is_none());
    }

    #[tokio::test]
    async fn unknown_provider_is_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        setup(&state, test_client(&issuerd_core::RealmId::new("realm-1").unwrap())).await;
        let app = installation_routes(state);

        let (status, _) = get_json(app, "test", "client-1", "saml-sp-descriptor").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_client_is_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        setup(&state, test_client(&issuerd_core::RealmId::new("realm-1").unwrap())).await;
        let app = installation_routes(state);

        let (status, _) =
            get_json(app, "test", "no-such-client", KEYCLOAK_OIDC_JSON_PROVIDER_ID).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_realm_is_404() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-clients").unwrap()
            ]);
        let app = installation_routes(state);

        let (status, _) =
            get_json(app, "no-such-realm", "client-1", KEYCLOAK_OIDC_JSON_PROVIDER_ID).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn forbidden_without_view_or_manage_clients_role() {
        let state =
            crate::test_utils::tests::test_state(vec![
                issuerd_core::RoleName::new("view-users").unwrap()
            ]);
        setup(&state, test_client(&issuerd_core::RealmId::new("realm-1").unwrap())).await;
        let app = installation_routes(state);

        let (status, _) = get_json(app, "test", "client-1", KEYCLOAK_OIDC_JSON_PROVIDER_ID).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn provider_ids_match_between_metadata_and_dispatch() {
        let ids: Vec<String> = providers().into_iter().map(|p| p.id).collect();
        assert_eq!(
            ids,
            [
                KEYCLOAK_OIDC_JSON_PROVIDER_ID.to_string(),
                GENERIC_OIDC_JSON_PROVIDER_ID.to_string()
            ]
        );
    }
}
