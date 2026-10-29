// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::Engine;
use issuerd_server::routes::app_router;
use issuerd_server::state::ServerState;
use tower::ServiceExt;

use crate::harness::TestHarness;

const REALM_NAME: &str = "tenant{one}";
const REALM_SEGMENT: &str = "tenant%7Bone%7D";
const PASSWORD: &str = "Password123!";
const APP_REDIRECT: &str = "http://localhost:8080/cb";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

struct SpecialRealmFixture {
    state: Arc<ServerState>,
    harness: TestHarness,
    realm: issuerd_core::Realm,
}

async fn special_realm_fixture() -> SpecialRealmFixture {
    special_realm_fixture_with_config(crate::harness::test_config()).await
}

async fn special_realm_fixture_with_config(
    config: issuerd_server::config::ServerConfig,
) -> SpecialRealmFixture {
    let state = Arc::new(ServerState::from_config(&config).await.unwrap());
    let harness = TestHarness::with_state(Arc::clone(&state));
    let realm = issuerd_core::Realm {
        id: issuerd_core::RealmId::new(issuerd_core::utils::generate_id()).unwrap(),
        name: issuerd_core::RealmName::new(REALM_NAME).unwrap(),
        display_name: Some(issuerd_core::DisplayName::new("Special Realm").unwrap()),
        enabled: true,
        ..Default::default()
    };
    harness.storage.create_realm(&realm).await.unwrap();
    SpecialRealmFixture {
        state,
        harness,
        realm,
    }
}

async fn create_user(
    harness: &TestHarness,
    realm: &issuerd_core::Realm,
    username: &str,
) -> issuerd_core::User {
    let user = issuerd_core::User {
        id: issuerd_core::UserId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm.id.clone(),
        username: issuerd_core::Username::new(username).unwrap(),
        email: Some(issuerd_core::Email::new(format!("{username}@example.com")).unwrap()),
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
    harness.storage.create_user(&realm.id, &user).await.unwrap();

    use argon2::password_hash::rand_core::OsRng;
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(PASSWORD.as_bytes(), &salt).unwrap().to_string();
    let credential = issuerd_core::Credential {
        id: issuerd_core::CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
        credential_type: issuerd_core::CredentialType::Password,
        user_label: Some("Password".to_string()),
        created_date: chrono::Utc::now(),
        secret_data: hash.into_bytes(),
        credential_data: serde_json::json!({"hash_algorithm": "argon2id"}),
        priority: 1,
    };
    harness
        .storage
        .create_credential(&realm.id, &user.id, &credential)
        .await
        .unwrap();
    user
}

async fn create_client(
    harness: &TestHarness,
    realm: &issuerd_core::Realm,
    client_id: &str,
    secret: &str,
    redirect_uri: &str,
    token_exchange: bool,
) -> issuerd_core::Client {
    let mut attributes = HashMap::new();
    if token_exchange {
        attributes.insert("token.exchange.enabled".to_string(), "true".to_string());
    }
    let client = issuerd_core::Client {
        id: issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
        realm_id: realm.id.clone(),
        client_id: issuerd_core::ClientIdentifier::new(client_id).unwrap(),
        name: Some(issuerd_core::DisplayName::new(client_id).unwrap()),
        description: None,
        enabled: true,
        protocol: issuerd_core::ClientProtocol::OpenIdConnect,
        public_client: false,
        bearer_only: false,
        client_authenticator_type: issuerd_core::ClientAuthenticatorType::ClientSecret,
        secret: Some(secret.to_string()),
        redirect_uris: vec![issuerd_core::RedirectUri::new(redirect_uri).unwrap()],
        web_origins: vec![issuerd_core::WebOrigin::new("http://localhost:8080").unwrap()],
        default_scopes: issuerd_core::Scope::parse("openid profile email"),
        optional_scopes: issuerd_core::Scope::empty(),
        consent_required: false,
        full_scope_allowed: true,
        service_accounts_enabled: false,
        protocol_mappers: Vec::new(),
        scope_mappings: Default::default(),
        attributes,
    };
    harness.storage.create_client(&realm.id, &client).await.unwrap();
    client
}

async fn create_account_console(fixture: &SpecialRealmFixture) -> issuerd_core::Client {
    let mut client = issuerd_admin_api::realms::build_account_console_client(
        &fixture.realm.id,
        REALM_NAME,
        &fixture.harness.base_url,
    )
    .unwrap();
    client.redirect_uris.push(issuerd_core::RedirectUri::new(APP_REDIRECT).unwrap());
    fixture.harness.storage.create_client(&fixture.realm.id, &client).await.unwrap();
    client
}

async fn grant_realm_role(
    harness: &TestHarness,
    realm: &issuerd_core::Realm,
    user: &issuerd_core::User,
    name: &str,
) {
    let role = issuerd_core::Role {
        id: issuerd_core::RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
        name: issuerd_core::RoleName::new(name).unwrap(),
        description: None,
        realm_id: realm.id.clone(),
        client_role: false,
        client_id: None,
        composite: false,
        composites: Vec::new(),
        attributes: HashMap::new(),
    };
    harness.storage.create_role(&realm.id, &role).await.unwrap();
    harness
        .storage
        .add_user_realm_role(&realm.id, &user.id, &role.id)
        .await
        .unwrap();
}

async fn body_json(response: Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn jwt_part(token: &str, index: usize) -> serde_json::Value {
    let part = token.split('.').nth(index).expect("JWT segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn jwt_claims(token: &str) -> serde_json::Value {
    jwt_part(token, 1)
}

async fn reissue_with_issuer(state: &Arc<ServerState>, token: &str, issuer: &str) -> String {
    let header = jwt_part(token, 0);
    let mut claims = jwt_claims(token);
    claims["iss"] = serde_json::Value::String(issuer.to_string());
    let algorithm: issuerd_core::Algorithm = header["alg"].as_str().unwrap().parse().unwrap();
    let key_id = issuerd_core::KeyId::new(header["kid"].as_str().unwrap()).unwrap();
    state.crypto.sign(&claims.to_string(), algorithm, &key_id).await.unwrap()
}

fn raw_issuer(fixture: &SpecialRealmFixture) -> String {
    format!("{}/realms/{REALM_NAME}", fixture.harness.base_url)
}

fn token_path() -> String {
    format!("/realms/{REALM_SEGMENT}/protocol/openid-connect/token")
}

fn location(response: &Response) -> String {
    response.headers().get("location").unwrap().to_str().unwrap().to_string()
}

async fn get_with_cookie(harness: &TestHarness, path: &str, cookie: &str) -> Response {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    harness.app.clone().oneshot(harness.add_connect_info(request)).await.unwrap()
}

struct BrowserTokens {
    access_token: String,
    sso_token: String,
}

fn sso_cookie_value(response: &Response) -> String {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|cookie| !cookie.starts_with("issuerd_session_state_"))
        .find_map(|cookie| cookie.strip_prefix("issuerd_session_"))
        .and_then(|rest| rest.split(';').next()?.split_once('='))
        .map(|(_, value)| value.to_string())
        .expect("login response sets the SSO session cookie")
}

async fn authenticate_account_console(
    fixture: &SpecialRealmFixture,
    username: &str,
) -> BrowserTokens {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = issuerd_protocol::pkce::PkceVerifier::s256_challenge(verifier);
    let auth_path = format!(
        "/realms/{REALM_SEGMENT}/protocol/openid-connect/auth?response_type=code&client_id=account-console&redirect_uri={APP_REDIRECT}&scope=openid&state=xyz&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = fixture.harness.get(&auth_path).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let execution_id = TestHarness::extract_query_param(&location(&response), "execution_id")
        .expect("authorization redirect carries execution_id");

    let response = fixture
        .harness
        .post_json_with_cookie(
            &format!("/api/v1/auth/login?realm={REALM_SEGMENT}"),
            serde_json::json!({
                "execution_id": execution_id,
                "username": username,
                "password": PASSWORD,
            }),
            &TestHarness::flow_cookie(&execution_id),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let sso_token = sso_cookie_value(&response);
    let login = body_json(response).await;
    let code = login["code"].as_str().unwrap();

    let response = fixture
        .harness
        .post_form(
            &token_path(),
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", APP_REDIRECT),
                ("client_id", "account-console"),
                ("code_verifier", verifier),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;
    BrowserTokens {
        access_token: tokens["access_token"].as_str().unwrap().to_string(),
        sso_token,
    }
}

fn account_authorize_path() -> String {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = issuerd_protocol::pkce::PkceVerifier::s256_challenge(verifier);
    format!(
        "/realms/{REALM_SEGMENT}/protocol/openid-connect/auth?response_type=code&client_id=account-console&redirect_uri={APP_REDIRECT}&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
    )
}

#[tokio::test]
async fn token_exchange_accepts_canonical_and_legacy_raw_special_realm_issuers() {
    let fixture = special_realm_fixture().await;
    let client = create_client(
        &fixture.harness,
        &fixture.realm,
        "requesting",
        "requesting-secret",
        APP_REDIRECT,
        true,
    )
    .await;
    create_user(&fixture.harness, &fixture.realm, "alice").await;

    let response = fixture
        .harness
        .post_form(
            &token_path(),
            &[
                ("grant_type", "password"),
                ("client_id", "requesting"),
                ("client_secret", "requesting-secret"),
                ("username", "alice"),
                ("password", PASSWORD),
                ("scope", "openid"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let subject = body_json(response).await["access_token"].as_str().unwrap().to_string();
    assert_eq!(
        jwt_claims(&subject)["iss"].as_str().unwrap(),
        format!("{}/realms/{REALM_SEGMENT}", fixture.harness.base_url)
    );
    let legacy = reissue_with_issuer(&fixture.state, &subject, &raw_issuer(&fixture)).await;

    for (label, subject_token) in [("canonical", &subject), ("legacy raw", &legacy)] {
        let response = fixture
            .harness
            .post_form(
                &token_path(),
                &[
                    ("grant_type", EXCHANGE_GRANT),
                    ("client_id", "requesting"),
                    ("client_secret", "requesting-secret"),
                    ("subject_token", subject_token),
                    ("subject_token_type", ACCESS_TOKEN_TYPE),
                ],
            )
            .await;
        let status = response.status();
        let json = body_json(response).await;
        assert_eq!(status, StatusCode::OK, "{label}: {json}");
        assert_eq!(json["issued_token_type"], ACCESS_TOKEN_TYPE);
        assert_eq!(
            jwt_claims(json["access_token"].as_str().unwrap())["sub"],
            jwt_claims(subject_token)["sub"]
        );
    }

    for issuer in [
        format!("{}/realms/{}", fixture.harness.base_url, fixture.realm.id),
        format!("{}/realms/tenant%257Bone%257D", fixture.harness.base_url),
    ] {
        let aliased = reissue_with_issuer(&fixture.state, &subject, &issuer).await;
        let response = fixture
            .harness
            .post_form(
                &token_path(),
                &[
                    ("grant_type", EXCHANGE_GRANT),
                    ("client_id", "requesting"),
                    ("client_secret", "requesting-secret"),
                    ("subject_token", &aliased),
                    ("subject_token_type", ACCESS_TOKEN_TYPE),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{issuer}");
        assert_eq!(body_json(response).await["error"], "invalid_grant");
    }

    assert_eq!(client.realm_id, fixture.realm.id);
}

#[tokio::test]
async fn account_and_sso_cookie_accept_canonical_and_legacy_raw_special_realm_issuers() {
    let fixture = special_realm_fixture().await;
    create_account_console(&fixture).await;
    create_user(&fixture.harness, &fixture.realm, "alice").await;
    let tokens = authenticate_account_console(&fixture, "alice").await;
    assert!(jwt_claims(&tokens.access_token)["iss"]
        .as_str()
        .unwrap()
        .ends_with("/realms/tenant%7Bone%7D"));
    let legacy_access =
        reissue_with_issuer(&fixture.state, &tokens.access_token, &raw_issuer(&fixture)).await;
    let legacy_sso =
        reissue_with_issuer(&fixture.state, &tokens.sso_token, &raw_issuer(&fixture)).await;

    for (label, access_token) in [
        ("canonical", &tokens.access_token),
        ("legacy raw", &legacy_access),
    ] {
        let response = fixture
            .harness
            .get_auth(&format!("/realms/{REALM_SEGMENT}/account/api/me"), access_token)
            .await;
        let status = response.status();
        let json = body_json(response).await;
        assert_eq!(status, StatusCode::OK, "{label}: {json}");
        assert_eq!(json["username"], "alice");
    }

    for (label, sso_token) in [
        ("canonical", &tokens.sso_token),
        ("legacy raw", &legacy_sso),
    ] {
        let cookie = format!("issuerd_session_{}={sso_token}", fixture.realm.id);
        let response = get_with_cookie(&fixture.harness, &account_authorize_path(), &cookie).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{label}");
        assert!(
            location(&response).starts_with(APP_REDIRECT),
            "{label}: SSO cookie did not silently authenticate: {}",
            location(&response)
        );
    }
}

#[tokio::test]
async fn admin_auth_and_audit_accept_canonical_and_legacy_raw_special_realm_issuers() {
    let fixture = special_realm_fixture().await;
    let admin_cli = issuerd_admin_api::realms::build_admin_cli_client(
        &fixture.realm.id,
        &fixture.harness.base_url,
    )
    .unwrap();
    fixture
        .harness
        .storage
        .create_client(&fixture.realm.id, &admin_cli)
        .await
        .unwrap();
    let admin = create_user(&fixture.harness, &fixture.realm, "root").await;
    grant_realm_role(&fixture.harness, &fixture.realm, &admin, "manage-realm").await;
    grant_realm_role(&fixture.harness, &fixture.realm, &admin, "view-realm").await;

    let token = fixture.harness.get_admin_token(REALM_NAME, "root", PASSWORD).await;
    assert!(jwt_claims(&token)["iss"].as_str().unwrap().ends_with("/realms/tenant%7Bone%7D"));
    let legacy = reissue_with_issuer(&fixture.state, &token, &raw_issuer(&fixture)).await;

    for (label, admin_token, role_name) in [
        ("canonical", &token, "canonical-role"),
        ("legacy raw", &legacy, "legacy-role"),
    ] {
        let response = fixture
            .harness
            .get_auth(&format!("/admin/realms/{REALM_SEGMENT}"), admin_token)
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{label}");

        let response = fixture
            .harness
            .post_json_auth(
                &format!("/admin/realms/{REALM_SEGMENT}/roles"),
                admin_token,
                serde_json::json!({"name": role_name}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED, "{label}");

        let response = fixture
            .harness
            .get_auth(&format!("/admin/realms/{REALM_SEGMENT}/admin-events"), admin_token)
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{label}");
        let events = body_json(response).await;
        let event = events
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["resource_path"] == format!("roles/{role_name}"))
            .unwrap_or_else(|| panic!("missing {role_name} audit event: {events}"));
        assert_eq!(event["auth_realm_id"].as_str(), Some(fixture.realm.id.as_ref()), "{label}");
        assert_eq!(event["auth_username"], "root", "{label}");
    }

    let alias_issuer = format!("{}/realms/{}", fixture.harness.base_url, fixture.realm.id);
    let alias = reissue_with_issuer(&fixture.state, &token, &alias_issuer).await;
    let response = fixture
        .harness
        .get_auth(&format!("/admin/realms/{REALM_SEGMENT}"), &alias)
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

struct LoopbackIdp {
    base_url: String,
    harness: TestHarness,
}

async fn start_loopback_idp() -> LoopbackIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let config = issuerd_server::config::ServerConfig {
        issuer_url: base_url.clone(),
        ..crate::harness::test_config()
    };
    let state = Arc::new(ServerState::from_config(&config).await.unwrap());
    let harness = TestHarness::with_state(Arc::clone(&state));
    let app = app_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    LoopbackIdp { base_url, harness }
}

fn query_param(url: &str, key: &str) -> String {
    TestHarness::extract_query_param(url, key).unwrap_or_else(|| panic!("missing {key} in {url}"))
}

async fn external_login(ext: &LoopbackIdp, auth_url: &str) -> String {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let response = http.get(auth_url).send().await.unwrap();
    if response.status() != StatusCode::SEE_OTHER {
        let status = response.status();
        let body = response.text().await.unwrap();
        panic!("external authorize failed with {status}: {body}; URL: {auth_url}");
    }
    let login_page = response.headers().get("location").unwrap().to_str().unwrap().to_string();
    let execution_id = query_param(&login_page, "execution_id");
    let response = http
        .post(format!("{}/api/v1/auth/login?realm=ext", ext.base_url))
        .header("content-type", "application/json")
        .header("cookie", TestHarness::flow_cookie(&execution_id))
        .body(
            serde_json::json!({
                "execution_id": execution_id,
                "username": "extuser",
                "password": PASSWORD,
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let login: serde_json::Value = response.json().await.unwrap();
    login["code"].as_str().unwrap().to_string()
}

async fn begin_account_link(fixture: &SpecialRealmFixture, bearer: &str) -> (String, String) {
    let response = fixture
        .harness
        .post_json_auth(
            &format!("/realms/{REALM_SEGMENT}/account/api/linked-accounts/ext"),
            bearer,
            serde_json::json!(null),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let start = body_json(response).await;
    let response = fixture.harness.get(start["redirect_url"].as_str().unwrap()).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let external_url = location(&response);
    let state = query_param(&external_url, "state");
    (external_url, state)
}

async fn finish_account_link(
    fixture: &SpecialRealmFixture,
    ext: &LoopbackIdp,
    bearer: &str,
    sso_token: &str,
) {
    let (external_url, state) = begin_account_link(fixture, bearer).await;
    let code = external_login(ext, &external_url).await;
    let cookie = format!("issuerd_session_{}={sso_token}", fixture.realm.id);
    let response = get_with_cookie(
        &fixture.harness,
        &format!("/realms/{REALM_SEGMENT}/broker/ext/endpoint?code={code}&state={state}"),
        &cookie,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let redirect = location(&response);
    assert!(
        redirect
            .starts_with(&format!("/realms/{REALM_SEGMENT}/account/linked-accounts?linked=ext")),
        "broker link failed or returned a non-canonical realm path: {redirect}"
    );
}

#[tokio::test]
async fn broker_linking_accepts_canonical_and_legacy_raw_special_realm_sso_cookies() {
    let mut config = crate::harness::test_config();
    config.outbound_http.allow_private_identity_providers = true;
    let fixture = special_realm_fixture_with_config(config).await;
    create_account_console(&fixture).await;
    create_user(&fixture.harness, &fixture.realm, "alice").await;
    let tokens = authenticate_account_console(&fixture, "alice").await;

    let ext = start_loopback_idp().await;
    let ext_realm = ext.harness.create_realm("ext").await;
    let callback =
        format!("{}/realms/{REALM_SEGMENT}/broker/ext/endpoint", fixture.harness.base_url);
    create_client(&ext.harness, &ext_realm, "broker-client", "broker-secret", &callback, false)
        .await;
    let ext_user = ext.harness.create_user("ext", "extuser", PASSWORD).await;
    let mut idp_config = HashMap::new();
    idp_config.insert("clientId".to_string(), "broker-client".to_string());
    idp_config.insert("clientSecret".to_string(), "broker-secret".to_string());
    idp_config.insert("issuer".to_string(), format!("{}/realms/ext", ext.base_url));
    let idp = issuerd_core::IdentityProviderConfig {
        id: issuerd_core::IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap(),
        alias: issuerd_core::Alias::new("ext").unwrap(),
        provider_id: issuerd_core::ProviderId::new("oidc"),
        enabled: true,
        config: idp_config,
    };
    fixture
        .harness
        .storage
        .create_identity_provider(&fixture.realm.id, &idp)
        .await
        .unwrap();

    for (label, sso_token) in [
        ("canonical", tokens.sso_token.clone()),
        (
            "legacy raw",
            reissue_with_issuer(&fixture.state, &tokens.sso_token, &raw_issuer(&fixture)).await,
        ),
    ] {
        finish_account_link(&fixture, &ext, &tokens.access_token, &sso_token).await;
        let link = fixture
            .harness
            .storage
            .get_identity_provider_link(&fixture.realm.id, "ext", ext_user.id.as_ref())
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{label}: broker identity was not linked"));
        assert_eq!(link.external_subject, ext_user.id.as_ref());

        let response = fixture
            .harness
            .delete_auth(
                &format!("/realms/{REALM_SEGMENT}/account/api/linked-accounts/ext"),
                &tokens.access_token,
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{label}");
    }
}
