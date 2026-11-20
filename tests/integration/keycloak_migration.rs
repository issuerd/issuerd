// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Keycloak realm migration acceptance through the real Admin and OIDC APIs.

use std::collections::HashMap;

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use axum::http::StatusCode;
use base64::Engine;
use issuerd_core::CredentialType;

use crate::harness::TestHarness;

const REALM: &str = "migration-lab";
const CLIENT_ID: &str = "migration-check";
const CLIENT_SECRET: &str = "target-only-synthetic-secret";
const PASSWORD: &str = "correct horse battery staple";
const SALT_B64: &str = "a2V5Y2xvYWstc2FsdA";
const P256_CURRENT: &str = "hsOJl3GhDYMSY6f/peJVng13yRqoAxMO43lSz7QOL3E";
const P256_LEGACY: &str = "R9/y5pwOp8WGpqw1oD3GDq/9FE00ll8Rzm9iRfM7paE";
const P512_CURRENT: &str =
    "FENVvG2zqwkKUJN0i70N6PXF4rRKvd7Hv/P2Lvv086THElFQJfVPjeTdj4+DxfZ1ozzrmSLB1eOKVw2p001Ddw";
const P512_LEGACY: &str =
    "sc7lEf9hMdrCyUDO1nu3GCBVLghgJoc9+mkS9k+lXJ7TfIyvb8YCdnkJI1gD0RIq2D9hrohj6UqgQ/hTHjJpRQ";

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("JWT payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn keycloak_pair(algorithm: &str, iterations: u32, hash: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "password",
        "credentialData": {"algorithm": algorithm, "hashIterations": iterations},
        "secretData": {"value": hash, "salt": SALT_B64}
    })
}

fn mapper(name: &str, mapper_type: &str, extra: &[(&str, &str)]) -> serde_json::Value {
    let mut config = serde_json::Map::from_iter([
        ("access.token.claim".to_string(), serde_json::json!("true")),
        ("id.token.claim".to_string(), serde_json::json!("true")),
        ("userinfo.token.claim".to_string(), serde_json::json!("true")),
    ]);
    for (key, value) in extra {
        config.insert((*key).to_string(), serde_json::json!(value));
    }
    serde_json::json!({
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": mapper_type,
        "config": config
    })
}

fn migration_document(argon2_hash: &str) -> serde_json::Value {
    let user = |username: &str, credentials: Vec<serde_json::Value>| {
        serde_json::json!({
            "username": username,
            "enabled": true,
            "emailVerified": true,
            "firstName": "Alice",
            "lastName": "Migration",
            "attributes": {
                "department": ["engineering"],
                "optionalNote": ["optional-value"],
                "address_locality": ["Tartu"],
                "address_street": ["Migration Street 1"]
            },
            "credentials": credentials,
            "requiredActions": []
        })
    };
    let mut alice = user(
        "alice-argon2id",
        vec![serde_json::json!({"type": "password", "secretData": argon2_hash})],
    );
    alice["realmRoles"] = serde_json::json!(["migration-realm-role"]);
    alice["clientRoles"] = serde_json::json!({CLIENT_ID: ["migration-client-role"]});
    alice["groups"] = serde_json::json!(["/developers"]);
    let mut disabled =
        user("disabled-user", vec![keycloak_pair("pbkdf2-sha256", 27_500, P256_LEGACY)]);
    disabled["enabled"] = serde_json::json!(false);

    serde_json::json!({
        "users": [
            alice,
            user("bob-p256-current", vec![keycloak_pair("pbkdf2-sha256", 600_000, P256_CURRENT)]),
            user("carol-p512-current", vec![keycloak_pair("pbkdf2-sha512", 210_000, P512_CURRENT)]),
            user("dave-p256-legacy", vec![keycloak_pair("pbkdf2-sha256", 27_500, P256_LEGACY)]),
            user("erin-p512-legacy", vec![keycloak_pair("pbkdf2-sha512", 27_500, P512_LEGACY)]),
            disabled,
            user("no-password", vec![]),
            user("history-only", vec![{
                let mut credential = keycloak_pair("pbkdf2-sha256", 27_500, P256_LEGACY);
                credential["type"] = serde_json::json!("password-history");
                credential
            }])
        ],
        "groups": [{
            "name": "developers",
            "path": "/developers",
            "realmRoles": ["group-realm-role"],
            "clientRoles": {CLIENT_ID: ["group-client-role"]}
        }],
        "clients": [{
            "clientId": CLIENT_ID,
            "secret": CLIENT_SECRET,
            "publicClient": false,
            "fullScopeAllowed": false,
            "redirectUris": ["http://localhost:8080/cb"],
            "webOrigins": ["http://localhost:8080"],
            "defaultClientScopes": ["migration-default"],
            "optionalClientScopes": ["migration-optional"]
        }],
        "roles": {
            "realm": [
                {"name": "migration-realm-role"},
                {"name": "group-realm-role"}
            ],
            "client": {
                CLIENT_ID: [
                    {"name": "migration-client-role"},
                    {"name": "group-client-role"}
                ]
            }
        },
        "clientScopes": [
            {
                "name": "migration-default",
                "protocol": "openid-connect",
                "protocolMappers": [
                    mapper("department", "oidc-usermodel-attribute-mapper", &[
                        ("user.attribute", "department"),
                        ("claim.name", "dept"),
                        ("jsonType.label", "String")
                    ]),
                    mapper("first name", "oidc-usermodel-property-mapper", &[
                        ("user.property", "firstName"),
                        ("claim.name", "given_name_custom")
                    ]),
                    mapper("full name", "oidc-full-name-mapper", &[]),
                    mapper("address", "oidc-address-mapper", &[]),
                    mapper("groups", "oidc-group-membership-mapper", &[
                        ("claim.name", "groups"),
                        ("full.path", "false")
                    ]),
                    mapper("realm roles", "oidc-usermodel-realm-role-mapper", &[]),
                    mapper("client roles", "oidc-usermodel-client-role-mapper", &[
                        ("usermodel.clientRoleMapping.clientId", CLIENT_ID)
                    ]),
                    mapper("audience", "oidc-audience-mapper", &[
                        ("included.custom.audience", "migration-extra-audience")
                    ]),
                    mapper("origins", "oidc-allowed-origins-mapper", &[])
                ]
            },
            {
                "name": "migration-optional",
                "protocol": "openid-connect",
                "protocolMappers": [
                    mapper("optional", "oidc-usermodel-attribute-mapper", &[
                        ("user.attribute", "optionalNote"),
                        ("claim.name", "optional_claim")
                    ])
                ]
            }
        ],
        "scopeMappings": [
            {"client": CLIENT_ID, "roles": ["migration-realm-role", "group-realm-role"]},
            {"clientScope": "migration-default", "roles": ["migration-realm-role", "group-realm-role"]}
        ],
        "clientScopeMappings": {
            CLIENT_ID: [
                {"client": CLIENT_ID, "roles": ["migration-client-role", "group-client-role"]},
                {"clientScope": "migration-default", "roles": ["migration-client-role", "group-client-role"]}
            ]
        }
    })
}

async fn password_grant(
    harness: &TestHarness,
    username: &str,
    password: &str,
    scope: &str,
) -> (StatusCode, serde_json::Value) {
    let response = harness
        .post_form(
            &format!("/realms/{REALM}/protocol/openid-connect/token"),
            &[
                ("grant_type", "password"),
                ("client_id", CLIENT_ID),
                ("client_secret", CLIENT_SECRET),
                ("username", username),
                ("password", password),
                ("scope", scope),
            ],
        )
        .await;
    let status = response.status();
    (status, response_json(response).await)
}

async fn successful_grant(
    harness: &TestHarness,
    username: &str,
    password: &str,
    scope: &str,
) -> serde_json::Value {
    let (status, body) = password_grant(harness, username, password, scope).await;
    assert_eq!(status, StatusCode::OK, "{username}: {body}");
    assert!(body["access_token"].as_str().is_some(), "{username}: {body}");
    body
}

async fn userinfo(harness: &TestHarness, access_token: &str) -> serde_json::Value {
    let response = harness
        .get_auth(&format!("/realms/{REALM}/protocol/openid-connect/userinfo"), access_token)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

async fn stored_password(
    harness: &TestHarness,
    username: &str,
) -> (issuerd_core::UserId, issuerd_core::Credential) {
    let realm_id = harness.storage.get_realm_by_name(REALM).await.unwrap().unwrap().id;
    let user = harness
        .storage
        .get_user_by_username(&realm_id, username)
        .await
        .unwrap()
        .unwrap();
    let credentials = harness
        .storage
        .get_credentials(&realm_id, &user.id, CredentialType::Password)
        .await
        .unwrap();
    assert_eq!(credentials.len(), 1, "{username}");
    (user.id, credentials.into_iter().next().unwrap())
}

#[tokio::test]
async fn keycloak_export_import_login_claims_and_password_lifecycle() {
    let harness = TestHarness::new().await;
    let admin_token = harness.get_admin_token("master", "admin", "admin").await;
    let response = harness
        .post_json_auth(
            "/admin/realms",
            &admin_token,
            serde_json::json!({"realm": REALM, "enabled": true}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let salt = SaltString::from_b64(SALT_B64).unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(7168, 5, 1, Some(32)).unwrap(),
    );
    let argon2_hash = argon2.hash_password(PASSWORD.as_bytes(), &salt).unwrap().to_string();
    let response = harness
        .post_json_auth(
            &format!("/admin/realms/{REALM}/partialImport?ifResourceExists=FAIL"),
            &admin_token,
            migration_document(&argon2_hash),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK, "{}", response_json(response).await);

    let enabled = [
        "alice-argon2id",
        "bob-p256-current",
        "carol-p512-current",
        "dave-p256-legacy",
        "erin-p512-legacy",
    ];
    let mut imported = HashMap::new();
    for username in enabled {
        let (_, credential) = stored_password(&harness, username).await;
        imported.insert(username, credential);
    }

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = issuerd_protocol::pkce::PkceVerifier::s256_challenge(verifier);
    for username in enabled {
        let tokens =
            successful_grant(&harness, username, PASSWORD, "openid migration-default").await;
        let (status, _) = password_grant(&harness, username, "wrong-password", "openid").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{username}");
        if username == "alice-argon2id" {
            let claims = userinfo(&harness, tokens["access_token"].as_str().unwrap()).await;
            assert_eq!(claims["dept"], "engineering");
            assert_eq!(claims["given_name_custom"], "Alice");
            assert_eq!(claims["name"], "Alice Migration");
            assert_eq!(claims["address"]["locality"], "Tartu");
            assert_eq!(claims["address"]["street_address"], "Migration Street 1");
            assert_eq!(claims["groups"], serde_json::json!(["developers"]));
            for role in ["migration-realm-role", "group-realm-role"] {
                assert!(claims["realm_access"]["roles"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!(role)));
            }
            for role in ["migration-client-role", "group-client-role"] {
                assert!(claims["resource_access"][CLIENT_ID]["roles"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!(role)));
            }
            assert!(claims["aud"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("migration-extra-audience")));
            assert_eq!(claims["allowed_origins"], serde_json::json!(["http://localhost:8080"]));
            assert!(claims.get("optional_claim").is_none());
            harness
                .authenticate_user_with_pkce(
                    REALM, CLIENT_ID, username, PASSWORD, &challenge, "S256", verifier,
                )
                .await;
        }
        if username == "bob-p256-current" {
            harness
                .authenticate_user_with_pkce(
                    REALM, CLIENT_ID, username, PASSWORD, &challenge, "S256", verifier,
                )
                .await;
        }
    }

    let default_tokens = successful_grant(&harness, "alice-argon2id", PASSWORD, "openid").await;
    let access_claims = jwt_claims(default_tokens["access_token"].as_str().unwrap());
    assert_eq!(access_claims["dept"], "engineering");
    assert!(access_claims.get("optional_claim").is_none());
    let optional_tokens = successful_grant(
        &harness,
        "alice-argon2id",
        PASSWORD,
        "openid migration-default migration-optional",
    )
    .await;
    let optional_claims =
        userinfo(&harness, optional_tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(optional_claims["optional_claim"], "optional-value");

    for username in ["disabled-user", "no-password", "history-only"] {
        let (status, _) = password_grant(&harness, username, PASSWORD, "openid").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{username}");
    }
    for (username, credential) in &imported {
        let (_, current) = stored_password(&harness, username).await;
        assert_eq!(&current, credential, "successful login rewrote {username}");
    }

    let (alice_id, _) = stored_password(&harness, "alice-argon2id").await;
    let response = harness
        .get_auth(&format!("/admin/realms/{REALM}/users/{alice_id}/credentials"), &admin_token)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let credentials = response_json(response).await;
    let serialized = credentials.to_string();
    assert!(!serialized.contains(&argon2_hash));
    assert!(!serialized.contains(SALT_B64));
    for credential in credentials.as_array().unwrap() {
        assert!(credential.get("secretData").is_none_or(serde_json::Value::is_null));
        assert!(credential.get("secret_data").is_none_or(serde_json::Value::is_null));
        assert!(credential.get("value").is_none_or(serde_json::Value::is_null));
    }

    let (bob_id, _) = stored_password(&harness, "bob-p256-current").await;
    let response = harness
        .put_json_auth(
            &format!("/admin/realms/{REALM}/users/{bob_id}/reset-password"),
            &admin_token,
            serde_json::json!({"type": "password", "value": "N0wPassword!", "temporary": false}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let (_, changed) = stored_password(&harness, "bob-p256-current").await;
    assert!(String::from_utf8(changed.secret_data.clone())
        .unwrap()
        .starts_with("$argon2id$"));
    let (status, _) = password_grant(&harness, "bob-p256-current", PASSWORD, "openid").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    successful_grant(&harness, "bob-p256-current", "N0wPassword!", "openid").await;
    for (username, credential) in &imported {
        if *username != "bob-p256-current" {
            let (_, current) = stored_password(&harness, username).await;
            assert_eq!(&current, credential, "password reset changed {username}");
        }
    }
}
