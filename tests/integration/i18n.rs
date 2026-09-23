// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Login i18n and theme integration tests.

//! Login i18n and theme integration tests (Issuerd-only).
//!
//! The login-context endpoint resolves the UI locale (flow-pinned,
//! `Accept-Language`, realm default) and ships the matching message bundle;
//! the theme endpoint serves per-realm login theme assets with fallback to
//! the built-in `issuerd` theme; outbound mail follows the user's `locale`
//! attribute.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use tower::ServiceExt;

use crate::harness::TestHarness;

/// Create a realm with internationalization enabled (`en` + `de`).
async fn create_i18n_realm(harness: &TestHarness, name: &str) -> issuerd_core::Realm {
    let mut realm = harness.create_realm(name).await;
    realm.internationalization_enabled = true;
    realm.supported_locales = vec!["en".to_string(), "de".to_string()];
    realm.default_locale = Some("en".to_string());
    harness.storage.update_realm(&realm).await.unwrap();
    realm
}

/// GET with an optional `Accept-Language` header.
async fn get_with_language(
    harness: &TestHarness,
    path: &str,
    accept_language: Option<&str>,
) -> Response {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(value) = accept_language {
        builder = builder.header("accept-language", value);
    }
    let req = builder.body(Body::empty()).unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(req)).await.unwrap()
}

async fn json_body(resp: Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn login_context_reports_locale_and_messages() {
    let harness = TestHarness::new().await;
    create_i18n_realm(&harness, "i18n-ctx").await;

    // German preferred and allowed: German bundle.
    let resp = get_with_language(&harness, "/realms/i18n-ctx/login/context", Some("de")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["locale"], "de");
    assert_eq!(body["supported_locales"], serde_json::json!(["en", "de"]));
    assert_eq!(body["messages"]["login.title"], "Anmelden");
    assert_eq!(body["messages"]["consent.allow"], "Erlauben");
    // A German-missing key falls back to English per key (all keys exist in
    // the shipped bundles, so spot-check a shared one instead).
    assert!(body["messages"]["email.footer"].as_str().unwrap().contains("automatische"));

    // No preference: the realm default (en).
    let resp = get_with_language(&harness, "/realms/i18n-ctx/login/context", None).await;
    let body = json_body(resp).await;
    assert_eq!(body["locale"], "en");
    assert_eq!(body["messages"]["login.title"], "Sign In");

    // French is not in supported_locales: falls through to the realm default.
    let resp = get_with_language(&harness, "/realms/i18n-ctx/login/context", Some("fr")).await;
    let body = json_body(resp).await;
    assert_eq!(body["locale"], "en");
}

#[tokio::test]
async fn login_context_ignores_accept_language_when_i18n_disabled() {
    let harness = TestHarness::new().await;
    harness.create_realm("i18n-off").await;

    let resp = get_with_language(&harness, "/realms/i18n-off/login/context", Some("de")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["locale"], "en");
    assert_eq!(body["messages"]["login.title"], "Sign In");
    assert_eq!(body["supported_locales"], serde_json::json!([]));
}

#[tokio::test]
async fn login_context_reuses_flow_pinned_locale() {
    let harness = TestHarness::new().await;
    create_i18n_realm(&harness, "i18n-flow").await;
    let client = harness.create_client("i18n-flow", false).await;

    // The authorize request pins ui_locales=de on the pending flow.
    let auth_path = format!(
        "/realms/i18n-flow/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz&ui_locales=de",
        client.client_id
    );
    let resp = harness.get(&auth_path).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let execution_id =
        TestHarness::extract_query_param(location, "execution_id").expect("execution_id");

    // The login page fetches the context with its flow id; no Accept-Language
    // needed — the pinned locale wins.
    let resp = get_with_language(
        &harness,
        &format!("/realms/i18n-flow/login/context?execution_id={execution_id}"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["locale"], "de");
    assert_eq!(body["messages"]["login.submit"], "Anmelden");
}

#[tokio::test]
async fn theme_asset_served_from_default_theme() {
    let harness = TestHarness::new().await;
    harness.create_realm("i18n-theme").await;

    // The built-in issuerd theme ships login.css (served from the repo's
    // themes/ directory — cargo tests run with the workspace root as CWD).
    let resp = harness.get("/realms/i18n-theme/theme/login.css").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(content_type.starts_with("text/css"), "content-type: {content_type}");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("--issuerd-bg"));

    // Unknown asset / unknown realm / traversal.
    let resp = harness.get("/realms/i18n-theme/theme/no-such.css").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = harness.get("/realms/no-such-realm/theme/login.css").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = harness.get("/realms/i18n-theme/theme/../issuerd.toml").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn custom_theme_overrides_default_and_falls_back() {
    use issuerd_server::{config::ServerConfig, state::ServerState};

    // A scratch themes dir: `acme` overrides login.css, everything else falls
    // back to the local `issuerd` copy.
    let dir =
        std::env::temp_dir().join(format!("issuerd-themes-{}", issuerd_core::utils::generate_id()));
    std::fs::create_dir_all(dir.join("acme")).unwrap();
    std::fs::create_dir_all(dir.join("issuerd")).unwrap();
    std::fs::write(dir.join("acme").join("login.css"), "/* acme */\n:root { --issuerd-bg: #fff; }")
        .unwrap();
    std::fs::write(dir.join("issuerd").join("login.css"), "/* issuerd */").unwrap();
    std::fs::write(dir.join("issuerd").join("base.css"), "/* base-only */").unwrap();

    let mut config = ServerConfig::default();
    config.themes.dir = dir.clone();
    let state = std::sync::Arc::new(ServerState::from_config(&config).await.unwrap());
    let harness = TestHarness::with_state(state);

    let mut realm = harness.create_realm("i18n-acme").await;
    realm.login_theme = Some(issuerd_core::ThemeName::new("acme").unwrap());
    harness.storage.update_realm(&realm).await.unwrap();

    // Overridden file comes from the acme theme.
    let resp = harness.get("/realms/i18n-acme/theme/login.css").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("/* acme */"));

    // A file the acme theme does not ship falls back to the default theme.
    let resp = harness.get("/realms/i18n-acme/theme/base.css").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("/* base-only */"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn reset_password_email_uses_user_locale() {
    use issuerd_server::{config::ServerConfig, state::ServerState};

    #[derive(Default)]
    struct RecordingSender {
        sent: std::sync::Mutex<Vec<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl issuerd_core::EmailSender for RecordingSender {
        async fn send(
            &self,
            _realm: &issuerd_core::Realm,
            to: &str,
            subject: &str,
            _text_body: &str,
            _html_body: Option<String>,
        ) -> Result<(), issuerd_core::IssuerdError> {
            self.sent.lock().unwrap().push((to.to_string(), subject.to_string()));
            Ok(())
        }
    }

    let config = ServerConfig::default();
    let mut state = ServerState::from_config(&config).await.unwrap();
    let recorder = std::sync::Arc::new(RecordingSender::default());
    state.email_sender = recorder.clone();
    let harness = TestHarness::with_state(std::sync::Arc::new(state));

    let mut realm = harness.create_realm("i18n-mail").await;
    realm.internationalization_enabled = true;
    realm.supported_locales = vec!["en".to_string(), "de".to_string()];
    realm.reset_password_allowed = true;
    harness.storage.update_realm(&realm).await.unwrap();

    // German user (locale attribute) and a user without a preference.
    let mut user = harness.create_user("i18n-mail", "nils", "Password123!").await;
    user.attributes.insert("locale".to_string(), vec!["de".to_string()]);
    harness.storage.update_user(&realm.id.clone(), &user).await.unwrap();
    harness.create_user("i18n-mail", "olga", "Password123!").await;

    for username in ["nils", "olga"] {
        let resp = harness
            .post_form("/realms/i18n-mail/login/reset-credentials", &[("username", username)])
            .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    let sent = recorder.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 2, "both users get mail: {sent:?}");
    let german = sent.iter().find(|(to, _)| to == "nils@example.com").expect("nils mail");
    assert_eq!(german.1, "Setzen Sie Ihr Passwort zurück");
    let english = sent.iter().find(|(to, _)| to == "olga@example.com").expect("olga mail");
    assert_eq!(english.1, "Reset your password");
}
