// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Test target trait and shared response/info types for dual-target integration tests.

use std::collections::HashMap;

use bytes::Bytes;

/// Simplified response type that works for both Axum in-process responses
/// and reqwest HTTP responses.
#[allow(dead_code)]
pub struct TestResponse {
    status: u16,
    headers: HashMap<String, Vec<String>>,
    body: Bytes,
}

#[allow(dead_code)]
impl TestResponse {
    pub fn new(status: u16, headers: HashMap<String, Vec<String>>, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .and_then(|v| v.first().map(|s| s.as_str()))
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

/// Information about a created realm.
pub struct RealmInfo {
    pub name: String,
}

/// Information about a created client.
pub struct ClientInfo {
    pub client_id: String,
    pub secret: Option<String>,
}

/// Information about a created user.
#[allow(dead_code)]
pub struct UserInfo {
    pub username: String,
}

/// Bundle of tokens returned from a successful token request.
#[allow(dead_code)]
pub struct TokenBundle {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_in: u64,
}

/// Abstraction over an OIDC test target (Issuerd in-process or Keycloak HTTP).
#[async_trait::async_trait]
pub trait OidcTestTarget: Send + Sync {
    async fn get(&self, path: &str) -> TestResponse;
    async fn post_form(&self, path: &str, params: &[(&str, &str)]) -> TestResponse;
    #[allow(unused)]
    async fn post_json(&self, path: &str, body: serde_json::Value) -> TestResponse;
    async fn get_auth(&self, path: &str, token: &str) -> TestResponse;

    async fn create_realm(&self, name: &str) -> RealmInfo;
    async fn create_client(&self, realm: &str, public: bool) -> ClientInfo;
    async fn create_user(&self, realm: &str, username: &str, password: &str) -> UserInfo;

    /// Acquire tokens via Resource Owner Password Credentials grant.
    async fn get_token_via_password_grant(
        &self,
        realm: &str,
        client_id: &str,
        client_secret: Option<&str>,
        username: &str,
        password: &str,
        scope: &str,
    ) -> TokenBundle;

    /// Clean up resources created during the test (realms, etc.).
    async fn cleanup(&self);
}

/// Run a test closure against each target selected by the `ISSUERD_TEST_TARGET`
/// environment variable.
///
/// - `issuerd` (default) – in-process only
/// - `keycloak` – Keycloak HTTP only
/// - `both` – both sequentially
pub async fn for_each_target<F, Fut>(f: F)
where
    F: Fn(Box<dyn OidcTestTarget>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mode = std::env::var("ISSUERD_TEST_TARGET").unwrap_or_else(|_| "issuerd".to_string());

    if mode == "issuerd" || mode == "both" {
        let target = super::issuerd::IssuerdTarget::new().await;
        f(Box::new(target)).await;
    }

    if mode == "keycloak" || mode == "both" {
        let target = super::keycloak::KeycloakTarget::new().await;
        f(Box::new(target)).await;
    }
}
