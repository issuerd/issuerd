// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::sync::Arc;

use axum::http::StatusCode;
use issuerd_core::{
    typestate::{AccountSessionGuard, RealmBound},
    BrokerIdpSettings, ClientIdentifier, Pagination,
};
use issuerd_mcp::{
    account_tools::{
        AccountConsentOutput, AccountConsentsOutput, AccountProfileOutput, AccountSessionOutput,
        AccountSessionsOutput, LinkedAccountOutput, LinkedAccountsOutput, MeConsentRevokeArgs,
        MeLinkedAccountUnlinkArgs, MeSessionLogoutArgs, MeUpdateProfileArgs, SecureActionOutput,
    },
    write_tools::{McpOperation, WriteOutput},
    McpAuthContext, McpError, ToolName,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{routes::account as account_api, state::ServerState};

pub async fn account(
    state: Arc<ServerState>,
    auth: &McpAuthContext,
    operation: McpOperation,
) -> Result<Value, McpError> {
    let tool = operation.tool;
    match tool {
        ToolName::MeGetProfile => {
            let _: issuerd_mcp::tools::NoArgs = decode(&operation)?;
            profile(&state, auth).await
        }
        ToolName::MeUpdateProfile => {
            let args: MeUpdateProfileArgs = decode(&operation)?;
            let guard = guard(auth);
            let response = account_api::account_update_me_with_guard(
                &state,
                &guard,
                account_api::UpdateMeRequest {
                    first_name: args.first_name,
                    last_name: args.last_name,
                    email: args.email,
                    username: args.username,
                },
            )
            .await;
            ensure_success(response.status())?;
            profile(&state, auth).await
        }
        ToolName::MeSessionsList => {
            let _: issuerd_mcp::tools::NoArgs = decode(&operation)?;
            let mut sessions = state
                .storage
                .list_sessions(&auth.realm_id, Some(auth.user_id.clone()), &Pagination::default())
                .await?;
            sessions.sort_by(|left, right| {
                right
                    .last_session_refresh
                    .cmp(&left.last_session_refresh)
                    .then_with(|| left.id.cmp(&right.id))
            });
            output(AccountSessionsOutput {
                sessions: sessions
                    .into_iter()
                    .map(|session| AccountSessionOutput {
                        id: session.id.to_string(),
                        ip_address: session.ip_address.to_string(),
                        started: session.started.to_rfc3339(),
                        last_session_refresh: session.last_session_refresh.to_rfc3339(),
                        clients: session
                            .clients
                            .into_iter()
                            .map(|client| client.client_id.to_string())
                            .collect(),
                    })
                    .collect(),
            })
        }
        ToolName::MeSessionsLogout => {
            let args: MeSessionLogoutArgs = decode(&operation)?;
            let response = account_api::account_logout_session_with_guard(
                &state,
                Some(auth.realm_name.to_string()),
                &guard(auth),
                args.id.clone(),
                auth.claims.sid.clone(),
            )
            .await;
            ensure_success(response.status())?;
            output(WriteOutput::completed_count(tool, Some(args.id), 1))
        }
        ToolName::MeConsentsList => {
            let _: issuerd_mcp::tools::NoArgs = decode(&operation)?;
            let mut consents = state.storage.get_consents(&auth.realm_id, &auth.user_id).await?;
            consents.sort_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.client_id.cmp(&right.client_id))
            });
            let mut result = Vec::new();
            for consent in consents {
                let Some(client) =
                    state.storage.get_client(&auth.realm_id, &consent.client_id).await?
                else {
                    continue;
                };
                let mut granted_scopes = consent.granted_scopes.to_vec();
                granted_scopes.sort();
                result.push(AccountConsentOutput {
                    client_id: client.client_id.to_string(),
                    granted_scopes,
                    created_at: consent.created_at.to_rfc3339(),
                    last_updated_at: consent.last_updated_at.to_rfc3339(),
                });
            }
            output(AccountConsentsOutput { consents: result })
        }
        ToolName::MeConsentsRevoke => {
            let args: MeConsentRevokeArgs = decode(&operation)?;
            let identifier = ClientIdentifier::new(&args.client_id)?;
            if state
                .storage
                .get_client_by_client_id(&auth.realm_id, &identifier)
                .await?
                .is_none()
            {
                return Err(McpError::NotFound("client"));
            }
            let response = account_api::account_delete_consent_with_guard(
                &state,
                &guard(auth),
                args.client_id.clone(),
            )
            .await;
            ensure_success(response.status())?;
            output(WriteOutput::completed(tool, Some(args.client_id)))
        }
        ToolName::MeLinkedAccountsList => {
            let _: issuerd_mcp::tools::NoArgs = decode(&operation)?;
            let mut links = state
                .storage
                .list_identity_provider_links(&auth.realm_id, &auth.user_id)
                .await?;
            links.sort_by(|left, right| left.provider_alias.cmp(&right.provider_alias));
            let idps = state.storage.list_identity_providers(&auth.realm_id).await?;
            let linked_accounts = links
                .into_iter()
                .map(|link| {
                    let (provider_id, display_name) = idps
                        .iter()
                        .find(|idp| idp.alias.as_ref() == link.provider_alias)
                        .map(|idp| {
                            (
                                idp.provider_id.as_str().to_string(),
                                BrokerIdpSettings::new(idp).display_name(),
                            )
                        })
                        .unwrap_or_else(|| (String::new(), link.provider_alias.clone()));
                    LinkedAccountOutput {
                        alias: link.provider_alias,
                        provider_id,
                        display_name,
                        external_username: link.external_username,
                        created_at: link.created_at.to_rfc3339(),
                    }
                })
                .collect();
            output(LinkedAccountsOutput { linked_accounts })
        }
        ToolName::MeLinkedAccountsUnlink => {
            let args: MeLinkedAccountUnlinkArgs = decode(&operation)?;
            let response = account_api::account_unlink_identity_with_guard(
                &state,
                &guard(auth),
                args.alias.clone(),
            )
            .await;
            ensure_success(response.status())?;
            output(WriteOutput::completed(tool, Some(args.alias)))
        }
        ToolName::MeTotpEnroll | ToolName::MeWebauthnRegister => {
            let _: issuerd_mcp::tools::NoArgs = decode(&operation)?;
            let action_url = account_security_url(&state, auth)?;
            output(SecureActionOutput {
                action_url,
                ceremony: if tool == ToolName::MeTotpEnroll {
                    "totp_enrollment"
                } else {
                    "webauthn_registration"
                }
                .into(),
            })
        }
        _ => unreachable!("MCP account dispatcher received a non-account tool"),
    }
}

async fn profile(state: &Arc<ServerState>, auth: &McpAuthContext) -> Result<Value, McpError> {
    let user = state
        .storage
        .get_user(&auth.realm_id, &auth.user_id)
        .await?
        .ok_or(McpError::NotFound("user"))?;
    let response = account_api::build_me_response(state, &auth.realm_id, &user)
        .await
        .map_err(|response| response_error(response.status()))?;
    let mut roles = response.roles;
    roles.sort();
    output(AccountProfileOutput {
        id: response.id,
        username: response.username,
        email: response.email,
        first_name: response.first_name,
        last_name: response.last_name,
        email_verified: response.email_verified,
        enabled: response.enabled,
        roles,
    })
}

fn guard(auth: &McpAuthContext) -> AccountSessionGuard {
    AccountSessionGuard::bind(RealmBound::new(auth.realm_id.clone(), auth.user_id.clone()))
}

fn account_security_url(
    state: &Arc<ServerState>,
    auth: &McpAuthContext,
) -> Result<String, McpError> {
    let mut url = url::Url::parse(&state.config.issuer_url)
        .map_err(|error| McpError::TransportConfig(error.to_string()))?;
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|_| McpError::TransportConfig("issuer URL cannot be a base URL".into()))?
        .pop_if_empty()
        .push("realms")
        .push(auth.realm_name.as_str())
        .push("account")
        .push("security");
    Ok(url.into())
}

fn ensure_success(status: StatusCode) -> Result<(), McpError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(response_error(status))
    }
}

fn response_error(status: StatusCode) -> McpError {
    match status {
        StatusCode::BAD_REQUEST => McpError::InvalidInput("account operation rejected".into()),
        StatusCode::FORBIDDEN => McpError::Forbidden("account operation forbidden"),
        StatusCode::NOT_FOUND => McpError::NotFound("resource"),
        StatusCode::CONFLICT => McpError::Conflict("account operation conflict"),
        _ => McpError::Backend(issuerd_core::IssuerdError::ServerError(
            "account operation failed".into(),
        )),
    }
}

fn decode<T: DeserializeOwned>(operation: &McpOperation) -> Result<T, McpError> {
    serde_json::from_value(operation.arguments.clone())
        .map_err(|error| McpError::InvalidInput(error.to_string()))
}

fn output(value: impl serde::Serialize) -> Result<Value, McpError> {
    serde_json::to_value(value).map_err(|_| {
        McpError::Backend(issuerd_core::IssuerdError::ServerError(
            "account result serialization failed".into(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use issuerd_core::{
        AccessTokenClaims, Alias, Audience, AuthMethod, Client, ClientAuthenticatorType,
        ClientProtocol, Consent, Credential, CredentialId, CredentialType, Email,
        IdentityProviderConfig, IdentityProviderId, IdentityProviderLink, Issuer, JwtId, JwtType,
        ProviderId, RealmAccess, RealmName, Scope, SessionId, User, UserId, UserSession, Username,
    };
    use serde_json::json;

    struct Fixture {
        state: Arc<ServerState>,
        auth: McpAuthContext,
        user_id: UserId,
        client_id: issuerd_core::ClientId,
        session_id: SessionId,
    }

    async fn fixture() -> Fixture {
        let state = Arc::new(
            crate::state::ServerState::from_config(&crate::config::ServerConfig::with_test_admin())
                .await
                .unwrap(),
        );
        let realm = state.storage.get_realm_by_name("master").await.unwrap().unwrap();
        let realm_id = realm.id.clone();
        let user_id = UserId::new(issuerd_core::utils::generate_id()).unwrap();
        let now = Utc::now();
        let user = User {
            id: user_id.clone(),
            realm_id: realm_id.clone(),
            username: Username::new("mcp-account-user").unwrap(),
            email: Some(Email::new("mcp-account-user@example.com").unwrap()),
            email_verified: true,
            first_name: Some("Before".try_into().unwrap()),
            last_name: Some("User".try_into().unwrap()),
            enabled: true,
            federation_link: None,
            attributes: Default::default(),
            required_actions: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        state.storage.create_user(&realm_id, &user).await.unwrap();
        state
            .storage
            .create_credential(
                &realm_id,
                &user_id,
                &Credential {
                    id: CredentialId::new(issuerd_core::utils::generate_id()).unwrap(),
                    credential_type: CredentialType::Password,
                    user_label: Some("password".into()),
                    created_date: now,
                    secret_data: b"not-a-real-password".to_vec(),
                    credential_data: json!({"temporary": false}),
                    priority: 0,
                },
            )
            .await
            .unwrap();
        let client = Client {
            id: issuerd_core::ClientId::new(issuerd_core::utils::generate_id()).unwrap(),
            realm_id: realm_id.clone(),
            client_id: ClientIdentifier::new("mcp-account-client").unwrap(),
            name: Some("MCP account client".try_into().unwrap()),
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: true,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: Vec::new(),
            web_origins: Vec::new(),
            default_scopes: Scope::parse("profile"),
            optional_scopes: Scope::parse("email"),
            consent_required: true,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: Default::default(),
        };
        state.storage.create_client(&realm_id, &client).await.unwrap();
        state
            .storage
            .create_consent(
                &realm_id,
                &Consent {
                    client_id: client.id.clone(),
                    user_id: user_id.clone(),
                    granted_scopes: Scope::parse("openid profile"),
                    granted_realm_roles: Vec::new(),
                    granted_client_roles: Default::default(),
                    created_at: now,
                    last_updated_at: now,
                },
            )
            .await
            .unwrap();
        let idp = IdentityProviderConfig {
            id: IdentityProviderId::new(issuerd_core::utils::generate_id()).unwrap(),
            alias: Alias::new("mcp-account-idp").unwrap(),
            provider_id: ProviderId::new("oidc"),
            enabled: true,
            config: [("displayName".to_string(), "MCP Account IdP".to_string())]
                .into_iter()
                .collect(),
        };
        state.storage.create_identity_provider(&realm_id, &idp).await.unwrap();
        state
            .storage
            .create_identity_provider_link(
                &realm_id,
                &IdentityProviderLink {
                    user_id: user_id.clone(),
                    provider_alias: idp.alias.to_string(),
                    external_subject: "external-subject".into(),
                    external_username: Some("external-user".into()),
                    stored_refresh_token: Some("refresh-token-canary".into()),
                    created_at: now,
                },
            )
            .await
            .unwrap();
        let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        state
            .storage
            .create_user_session(
                &realm_id,
                &UserSession {
                    id: session_id.clone(),
                    realm_id: realm_id.clone(),
                    user_id: user_id.clone(),
                    login_username: user.username.clone(),
                    ip_address: "127.0.0.1".parse().unwrap(),
                    auth_method: AuthMethod::Password,
                    remember_me: false,
                    offline: false,
                    started: now,
                    last_session_refresh: now,
                    auth_time: now,
                    impersonator: None,
                    clients: Vec::new(),
                },
            )
            .await
            .unwrap();
        let claims = AccessTokenClaims {
            jti: JwtId::new("mcp-account-test").unwrap(),
            iss: Issuer::new("http://localhost/realms/master").unwrap(),
            sub: user_id.clone(),
            aud: Audience::new("mcp-account-client").unwrap(),
            exp: 4_000_000_000,
            iat: 1,
            nbf: 1,
            scope: Scope::parse("openid"),
            typ: JwtType::Bearer,
            azp: Some("mcp-account-client".into()),
            session_state: None,
            realm_access: Some(RealmAccess { roles: Vec::new() }),
            resource_access: None,
            sid: Some(session_id.clone()),
            claims: None,
            cnf: None,
            authorization_details: None,
            resource: Some("http://localhost/realms/master/mcp".into()),
        };
        let auth = McpAuthContext {
            realm_id: realm_id.clone(),
            realm_name: RealmName::new("master").unwrap(),
            user_id: user_id.clone(),
            azp: ClientIdentifier::new("mcp-account-client").unwrap(),
            claims,
        };
        Fixture {
            state,
            auth,
            user_id,
            client_id: client.id,
            session_id,
        }
    }

    async fn call(fixture: &Fixture, tool: ToolName, arguments: Value) -> Result<Value, McpError> {
        let operation = issuerd_mcp::account_tools::parse_operation(
            tool,
            Some(arguments.as_object().unwrap().clone()),
        )?;
        account(fixture.state.clone(), &fixture.auth, operation).await
    }

    #[tokio::test]
    async fn all_account_tools_are_self_scoped_and_secret_free() {
        let fixture = fixture().await;
        let realm = &fixture.auth.realm_id;
        let mut outputs = Vec::new();

        let profile = call(&fixture, ToolName::MeGetProfile, json!({})).await.unwrap();
        assert_eq!(profile["id"], fixture.user_id.to_string());
        outputs.push(profile);

        let updated = call(
            &fixture,
            ToolName::MeUpdateProfile,
            json!({"firstName": "After", "email": "after@example.com"}),
        )
        .await
        .unwrap();
        assert_eq!(updated["firstName"], "After");
        assert_eq!(updated["emailVerified"], false);
        outputs.push(updated);

        let sessions = call(&fixture, ToolName::MeSessionsList, json!({})).await.unwrap();
        assert_eq!(sessions["sessions"].as_array().unwrap().len(), 1);
        outputs.push(sessions);

        let consents = call(&fixture, ToolName::MeConsentsList, json!({})).await.unwrap();
        assert_eq!(consents["consents"][0]["clientId"], "mcp-account-client");
        outputs.push(consents);

        let links = call(&fixture, ToolName::MeLinkedAccountsList, json!({})).await.unwrap();
        assert_eq!(links["linkedAccounts"][0]["alias"], "mcp-account-idp");
        assert!(!links.to_string().contains("refresh-token-canary"));
        outputs.push(links);

        for tool in [ToolName::MeTotpEnroll, ToolName::MeWebauthnRegister] {
            let enrollment = call(&fixture, tool, json!({})).await.unwrap();
            assert!(enrollment["actionUrl"]
                .as_str()
                .unwrap()
                .ends_with("/realms/master/account/security"));
            for forbidden in ["secret", "qrSvg", "otpauthUrl", "publicKey", "credential"] {
                assert!(!enrollment.to_string().contains(forbidden));
            }
            outputs.push(enrollment);
        }

        let other_session = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        fixture
            .state
            .storage
            .create_user_session(
                realm,
                &UserSession {
                    id: other_session.clone(),
                    realm_id: realm.clone(),
                    user_id: UserId::new(issuerd_core::utils::generate_id()).unwrap(),
                    login_username: Username::new("someone-else").unwrap(),
                    ip_address: "127.0.0.1".parse().unwrap(),
                    auth_method: AuthMethod::Password,
                    remember_me: false,
                    offline: false,
                    started: Utc::now(),
                    last_session_refresh: Utc::now(),
                    auth_time: Utc::now(),
                    impersonator: None,
                    clients: Vec::new(),
                },
            )
            .await
            .unwrap();
        assert!(call(
            &fixture,
            ToolName::MeSessionsLogout,
            json!({"id": other_session.to_string()}),
        )
        .await
        .is_err());
        assert!(fixture
            .state
            .storage
            .get_user_session(realm, &other_session)
            .await
            .unwrap()
            .is_some());

        outputs.push(
            call(
                &fixture,
                ToolName::MeSessionsLogout,
                json!({"id": fixture.session_id.to_string()}),
            )
            .await
            .unwrap(),
        );
        assert!(fixture
            .state
            .storage
            .get_user_session(realm, &fixture.session_id)
            .await
            .unwrap()
            .is_none());

        outputs.push(
            call(&fixture, ToolName::MeConsentsRevoke, json!({"clientId": "mcp-account-client"}))
                .await
                .unwrap(),
        );
        assert!(fixture
            .state
            .storage
            .get_consents(realm, &fixture.user_id)
            .await
            .unwrap()
            .is_empty());

        outputs.push(
            call(&fixture, ToolName::MeLinkedAccountsUnlink, json!({"alias": "mcp-account-idp"}))
                .await
                .unwrap(),
        );
        assert!(fixture
            .state
            .storage
            .list_identity_provider_links(realm, &fixture.user_id)
            .await
            .unwrap()
            .is_empty());

        let serialized = outputs.into_iter().map(|value| value.to_string()).collect::<String>();
        for canary in [
            "refresh-token-canary",
            "not-a-real-password",
            "secretData",
            "credentialData",
            "otpauth://",
            "publicKey",
        ] {
            assert!(!serialized.contains(canary), "leaked {canary}");
        }
        let _ = &fixture.client_id;
    }
}
