// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Keycloak test target driving a real Keycloak instance over HTTP for dual-target tests.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::Client;

use super::target::{ClientInfo, RealmInfo, TestResponse, TokenBundle, UserInfo};

const KEYCLOAK_BASE: &str = "http://localhost:8081";
pub struct KeycloakTarget {
    client: Client,
    admin_token: String,
    created_realms: Mutex<Vec<String>>,
}

impl KeycloakTarget {
    pub async fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client build failed");

        // Wait for Keycloak to be healthy
        Self::wait_for_keycloak(&client).await;

        // Obtain admin token
        let admin_token = Self::fetch_admin_token(&client).await;

        Self {
            client,
            admin_token,
            created_realms: Mutex::new(Vec::new()),
        }
    }

    async fn wait_for_keycloak(client: &Client) {
        let mut attempts = 0;
        let max_attempts = 30;
        let mut wait_secs = 2;

        while attempts < max_attempts {
            match client.get(format!("{}/health/ready", KEYCLOAK_BASE)).send().await {
                Ok(resp) if resp.status().is_success() => return,
                _ => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        panic!(
                            "Keycloak did not become ready after {} attempts. \
                             Ensure 'docker compose up -d' is running.",
                            max_attempts
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                    wait_secs = (wait_secs + 1).min(5);
                }
            }
        }
    }

    async fn fetch_admin_token(client: &Client) -> String {
        let resp = client
            .post(format!("{}/realms/master/protocol/openid-connect/token", KEYCLOAK_BASE))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("grant_type=password&client_id=admin-cli&username=admin&password=admin")
            .send()
            .await
            .expect("failed to request admin token; is Keycloak running?");

        if !resp.status().is_success() {
            panic!(
                "Admin token request failed: HTTP {} - body: {:?}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }

        let json: serde_json::Value = resp.json().await.expect("admin token response is not JSON");
        json["access_token"]
            .as_str()
            .expect("access_token missing in admin token response")
            .to_string()
    }

    async fn admin_post(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        let resp = self
            .client
            .post(format!("{}{}", KEYCLOAK_BASE, path))
            .header("Authorization", format!("Bearer {}", self.admin_token))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("admin POST {} failed: {}", path, e));
        resp
    }

    async fn admin_delete(&self, path: &str) -> reqwest::Response {
        let resp = self
            .client
            .delete(format!("{}{}", KEYCLOAK_BASE, path))
            .header("Authorization", format!("Bearer {}", self.admin_token))
            .send()
            .await
            .unwrap_or_else(|e| panic!("admin DELETE {} failed: {}", path, e));
        resp
    }

    async fn into_test_response(resp: reqwest::Response) -> TestResponse {
        let status = resp.status().as_u16();
        let mut headers = HashMap::new();
        for (name, value) in resp.headers() {
            let key = name.as_str().to_ascii_lowercase();
            let val = value.to_str().unwrap_or("").to_string();
            headers.entry(key).or_insert_with(Vec::new).push(val);
        }
        let body = resp.bytes().await.unwrap_or_default();
        TestResponse::new(status, headers, body)
    }
}

#[async_trait::async_trait]
impl super::target::OidcTestTarget for KeycloakTarget {
    async fn get(&self, path: &str) -> TestResponse {
        let resp = self
            .client
            .get(format!("{}{}", KEYCLOAK_BASE, path))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {} failed: {}", path, e));
        Self::into_test_response(resp).await
    }

    async fn post_form(&self, path: &str, params: &[(&str, &str)]) -> TestResponse {
        let resp = self
            .client
            .post(format!("{}{}", KEYCLOAK_BASE, path))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(params).unwrap())
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {} failed: {}", path, e));
        Self::into_test_response(resp).await
    }

    async fn post_json(&self, path: &str, body: serde_json::Value) -> TestResponse {
        let resp = self
            .client
            .post(format!("{}{}", KEYCLOAK_BASE, path))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {} failed: {}", path, e));
        Self::into_test_response(resp).await
    }

    async fn get_auth(&self, path: &str, token: &str) -> TestResponse {
        let resp = self
            .client
            .get(format!("{}{}", KEYCLOAK_BASE, path))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {} failed: {}", path, e));
        Self::into_test_response(resp).await
    }

    async fn create_realm(&self, name: &str) -> RealmInfo {
        let resp = self
            .admin_post("/admin/realms", serde_json::json!({"realm": name, "enabled": true}))
            .await;

        // Keycloak returns 201 on success, 409 if realm already exists
        let status = resp.status();
        if status != 201 && status != 409 {
            let body = resp.text().await.unwrap_or_default();
            panic!("create_realm failed: HTTP {} - {}", status, body);
        }

        self.created_realms.lock().unwrap().push(name.to_string());
        RealmInfo {
            name: name.to_string(),
        }
    }

    async fn create_client(&self, realm: &str, public: bool) -> ClientInfo {
        let client_id = format!("client-{}", issuerd_core::utils::generate_id());
        let body = serde_json::json!({
            "clientId": client_id,
            "name": "Test Client",
            "enabled": true,
            "publicClient": public,
            "bearerOnly": false,
            "standardFlowEnabled": true,
            "directAccessGrantsEnabled": true,
            "serviceAccountsEnabled": !public,
            "redirectUris": ["http://localhost:8080/cb"],
            "webOrigins": ["http://localhost:8080"],
            "defaultClientScopes": ["openid", "profile"],
            "optionalClientScopes": ["email"],
            "consentRequired": false,
            "fullScopeAllowed": true,
        });

        let resp = self.admin_post(&format!("/admin/realms/{}/clients", realm), body).await;

        let status = resp.status();
        if status != 201 {
            let text = resp.text().await.unwrap_or_default();
            panic!("create_client failed: HTTP {} - {}", status, text);
        }

        // For confidential clients, fetch the generated secret
        let secret = if !public {
            // Keycloak returns client id in Location header
            let location =
                resp.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("");
            let internal_id = location.rsplit('/').next().unwrap_or("");

            let secret_resp = self
                .client
                .get(format!(
                    "{}/admin/realms/{}/clients/{}/client-secret",
                    KEYCLOAK_BASE, realm, internal_id
                ))
                .header("Authorization", format!("Bearer {}", self.admin_token))
                .send()
                .await
                .unwrap();

            if secret_resp.status().is_success() {
                let secret_json: serde_json::Value = secret_resp.json().await.unwrap();
                secret_json["value"].as_str().map(|s| s.to_string())
            } else {
                None
            }
        } else {
            None
        };

        ClientInfo { client_id, secret }
    }

    async fn create_user(&self, realm: &str, username: &str, password: &str) -> UserInfo {
        let body = serde_json::json!({
            "username": username,
            "email": format!("{}@example.com", username),
            "emailVerified": true,
            "firstName": "Test",
            "lastName": "User",
            "enabled": true,
        });

        let resp = self.admin_post(&format!("/admin/realms/{}/users", realm), body).await;

        let status = resp.status();
        if status != 201 {
            let text = resp.text().await.unwrap_or_default();
            panic!("create_user failed: HTTP {} - {}", status, text);
        }

        // Extract user id from Location header
        let location = resp.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("");
        let user_id = location.rsplit('/').next().unwrap_or("");

        // Set password (non-temporary)
        let cred_body = serde_json::json!({
            "type": "password",
            "value": password,
            "temporary": false,
        });

        let cred_resp = self
            .client
            .put(format!(
                "{}/admin/realms/{}/users/{}/reset-password",
                KEYCLOAK_BASE, realm, user_id
            ))
            .header("Authorization", format!("Bearer {}", self.admin_token))
            .header("content-type", "application/json")
            .json(&cred_body)
            .send()
            .await
            .unwrap();

        let cred_status = cred_resp.status();
        if !cred_status.is_success() {
            let text = cred_resp.text().await.unwrap_or_default();
            panic!("set password failed: HTTP {} - {}", cred_status, text);
        }

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
            expires_in: json["expires_in"].as_u64().unwrap_or(0),
        }
    }

    async fn cleanup(&self) {
        let realms: Vec<String> = {
            let mut guard = self.created_realms.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        for realm in realms {
            let resp = self.admin_delete(&format!("/admin/realms/{}", realm)).await;
            if !resp.status().is_success() {
                eprintln!("Warning: failed to cleanup realm {}: HTTP {}", realm, resp.status());
            }
        }
    }
}
