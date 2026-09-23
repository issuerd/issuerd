// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// In-process Issuerd test target backed by the Axum router.

use std::collections::HashMap;

use axum::{body::Body, extract::ConnectInfo, http::Request, response::Response, Router};
use issuerd_server::{config::ServerConfig, routes::app_router, state::ServerState};
use tower::ServiceExt;

use super::target::{ClientInfo, RealmInfo, TestResponse, TokenBundle, UserInfo};
use issuerd_core::{ClientAuthenticatorType, ClientProtocol, RedirectUri, Scope};

pub struct IssuerdTarget {
    app: Router,
    storage: std::sync::Arc<dyn issuerd_core::Storage>,
}

impl IssuerdTarget {
    pub async fn new() -> Self {
        let config = ServerConfig::default();
        let state = std::sync::Arc::new(ServerState::from_config(&config).await.unwrap());
        let storage = std::sync::Arc::clone(&state.storage);
        let app = app_router(state);
        Self { app, storage }
    }

    fn add_connect_info(&self, mut req: Request<Body>) -> Request<Body> {
        use std::net::SocketAddr;
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));
        req
    }

    async fn into_test_response(resp: Response) -> TestResponse {
        let status = resp.status().as_u16();
        let mut headers = HashMap::new();
        for (name, value) in resp.headers() {
            let key = name.as_str().to_ascii_lowercase();
            let val = value.to_str().unwrap_or("").to_string();
            headers.entry(key).or_insert_with(Vec::new).push(val);
        }
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        TestResponse::new(status, headers, body)
    }
}

#[async_trait::async_trait]
impl super::target::OidcTestTarget for IssuerdTarget {
    async fn get(&self, path: &str) -> TestResponse {
        let req = Request::builder().method("GET").uri(path).body(Body::empty()).unwrap();
        let resp = self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap();
        Self::into_test_response(resp).await
    }

    async fn post_form(&self, path: &str, params: &[(&str, &str)]) -> TestResponse {
        let body = serde_urlencoded::to_string(params).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap();
        Self::into_test_response(resp).await
    }

    async fn post_json(&self, path: &str, body: serde_json::Value) -> TestResponse {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap();
        Self::into_test_response(resp).await
    }

    async fn get_auth(&self, path: &str, token: &str) -> TestResponse {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        let resp = self.app.clone().oneshot(self.add_connect_info(req)).await.unwrap();
        Self::into_test_response(resp).await
    }

    async fn create_realm(&self, name: &str) -> RealmInfo {
        let realm = issuerd_core::Realm {
            id: issuerd_core::RealmId::new(name).unwrap(),
            name: issuerd_core::RealmName::new(name).unwrap(),
            display_name: Some(issuerd_core::DisplayName::new(name).unwrap()),
            enabled: true,
            ..Default::default()
        };
        self.storage.create_realm(&realm).await.unwrap();
        RealmInfo {
            name: issuerd_core::RealmName::new(name).unwrap().to_string(),
        }
    }

    async fn create_client(&self, realm: &str, public: bool) -> ClientInfo {
        let secret = if public {
            None
        } else {
            Some(issuerd_core::utils::generate_id())
        };
        let client = issuerd_core::Client {
            id: issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: issuerd_core::RealmId::new(realm).unwrap(),
            client_id: issuerd_core::ClientIdentifier::new(format!(
                "client-{}",
                issuerd_core::utils::generate_id()
            ))
            .unwrap(),
            name: Some(issuerd_core::DisplayName::new("Test Client").unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: public,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: secret.clone(),
            redirect_uris: vec![RedirectUri::new("http://localhost:8080/cb").unwrap()],
            web_origins: vec![issuerd_core::WebOrigin::new("http://localhost:8080").unwrap()],
            default_scopes: Scope::parse("openid profile"),
            optional_scopes: Scope::parse("email"),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: HashMap::new(),
        };
        self.storage.create_client(&client.realm_id, &client).await.unwrap();
        ClientInfo {
            client_id: client.client_id.to_string(),
            secret: client.secret,
        }
    }

    async fn create_user(&self, realm: &str, username: &str, password: &str) -> UserInfo {
        let user = issuerd_core::User {
            id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: issuerd_core::RealmId::new(realm).unwrap(),
            username: issuerd_core::Username::new(username).unwrap(),
            email: Some(issuerd_core::Email::new(format!("{}@example.com", username)).unwrap()),
            email_verified: true,
            first_name: Some(issuerd_core::DisplayName::new("Test").unwrap()),
            last_name: Some(issuerd_core::DisplayName::new("User").unwrap()),
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        self.storage.create_user(&user.realm_id, &user).await.unwrap();

        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();

        let cred = issuerd_core::Credential {
            id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
            credential_type: issuerd_core::CredentialType::Password,
            user_label: Some("Password".to_string()),
            created_date: chrono::Utc::now(),
            secret_data: hash.into_bytes(),
            credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
            priority: 1,
        };
        self.storage.create_credential(&user.realm_id, &user.id, &cred).await.unwrap();

        UserInfo {
            username: username.to_string(),
        }
    }

    async fn get_token_via_password_grant(
        &self,
        realm: &str,
        client_id: &str,
        client_secret: Option<&str>,
        username: &str,
        password: &str,
        scope: &str,
    ) -> TokenBundle {
        let mut params: Vec<(&str, &str)> = vec![
            ("grant_type", "password"),
            ("client_id", client_id),
            ("username", username),
            ("password", password),
            ("scope", scope),
        ];
        if let Some(secret) = client_secret {
            params.push(("client_secret", secret));
        }

        let resp = self
            .post_form(&format!("/realms/{}/protocol/openid-connect/token", realm), &params)
            .await;

        assert_eq!(
            resp.status(),
            200,
            "password grant failed: {}",
            resp.json().unwrap_or_default()
        );

        let json = resp.json().unwrap();
        TokenBundle {
            access_token: json["access_token"].as_str().unwrap().to_string(),
            refresh_token: json["refresh_token"].as_str().map(|s| s.to_string()),
            id_token: json["id_token"].as_str().map(|s| s.to_string()),
            expires_in: json["expires_in"].as_u64().unwrap(),
        }
    }

    async fn cleanup(&self) {
        // In-memory storage is dropped with the target; nothing to do.
    }
}
