// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OAuth2 token endpoint request parsing and grant-type validation (RFC 6749 and extensions).

use std::collections::HashMap;

use issuerd_core::{
    Assertion, AuthorizationCode, Client, ClientIdentifier, ClientSecret, IssuerdError, Password,
    Realm, RefreshToken, Scope,
};
use serde::{Deserialize, Serialize};

use crate::utils::parse_scope;

/// `client_assertion_type` value carrying a JWT client assertion
/// (RFC 7523 §2.2 / OIDC Core §9).
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// `subject_token_type` / `requested_token_type` value for OAuth2 access
/// tokens (RFC 8693 §3). This is the only token type the
/// token-exchange grant accepts and issues.
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    pub code: Option<AuthorizationCode>,
    pub redirect_uri: Option<url::Url>,
    pub client_id: Option<ClientIdentifier>,
    pub client_secret: Option<ClientSecret>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<RefreshToken>,
    pub scope: Scope,
    pub username: Option<String>,
    pub password: Option<Password>,
    /// OTP code for the password grant's second factor (Keycloak direct-grant
    /// `totp` parameter): required when the user has OTP credentials enrolled.
    pub totp: Option<String>,
    pub assertion: Option<Assertion>,
    pub assertion_type: Option<String>,
    pub device_code: Option<String>,
    pub auth_req_id: Option<String>,
    // RFC 8693 token exchange
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    /// Target audience: the `client_id` of the client the exchanged token is
    /// minted for.
    pub audience: Option<String>,
    /// Impersonation exchange: user id the exchanged token is minted for.
    pub requested_subject: Option<String>,
    /// Delegation is out of scope; parsed so it can be rejected explicitly.
    pub actor_token: Option<String>,
    /// RAR authorization details narrowing (RFC 9396 §6): parsed
    /// and structurally validated for every grant; only the
    /// `authorization_code` and `refresh_token` grants honor it — the server
    /// rejects it for the others.
    pub authorization_details: Option<Vec<serde_json::Value>>,
}

impl TokenRequest {
    pub fn parse(body: &HashMap<String, String>) -> Result<Self, IssuerdError> {
        let grant_type = body
            .get("grant_type")
            .ok_or_else(|| IssuerdError::InvalidRequest("missing grant_type".into()))?
            .parse()
            .map_err(|_| IssuerdError::InvalidRequest("unsupported grant_type".into()))?;

        let redirect_uri = match body.get("redirect_uri") {
            Some(u) => Some(
                u.parse::<url::Url>()
                    .map_err(|_| IssuerdError::InvalidRequest("invalid redirect_uri".into()))?,
            ),
            None => None,
        };

        Ok(Self {
            grant_type,
            code: body
                .get("code")
                .filter(|s| !s.is_empty())
                .map(|s| AuthorizationCode::new(s.clone()))
                .transpose()?,
            redirect_uri,
            client_id: body.get("client_id").map(|s| s.as_str().try_into()).transpose()?,
            client_secret: body
                .get("client_secret")
                .filter(|s| !s.is_empty())
                .map(|s| ClientSecret::new(s.clone()))
                .transpose()?,
            code_verifier: body.get("code_verifier").cloned(),
            refresh_token: body
                .get("refresh_token")
                .filter(|s| !s.is_empty())
                .map(|s| RefreshToken::new(s.clone()))
                .transpose()?,
            scope: parse_scope(body.get("scope")),
            username: body.get("username").cloned(),
            password: body
                .get("password")
                .filter(|s| !s.is_empty())
                .map(|s| Password::new(s.clone()))
                .transpose()?,
            totp: body.get("totp").filter(|s| !s.is_empty()).cloned(),
            assertion: body
                .get("assertion")
                .filter(|s| !s.is_empty())
                .map(|s| Assertion::new(s.clone()))
                .transpose()?,
            assertion_type: body.get("assertion_type").cloned(),
            device_code: body.get("device_code").cloned(),
            auth_req_id: body.get("auth_req_id").cloned(),
            subject_token: body.get("subject_token").filter(|s| !s.is_empty()).cloned(),
            subject_token_type: body.get("subject_token_type").cloned(),
            requested_token_type: body.get("requested_token_type").cloned(),
            audience: body.get("audience").filter(|s| !s.is_empty()).cloned(),
            requested_subject: body.get("requested_subject").filter(|s| !s.is_empty()).cloned(),
            actor_token: body.get("actor_token").filter(|s| !s.is_empty()).cloned(),
            authorization_details: crate::authorization::parse_authorization_details(
                body.get("authorization_details"),
            )?,
        })
    }

    pub fn validate(&self, _realm: &Realm, client: &Client) -> Result<(), IssuerdError> {
        match self.grant_type {
            GrantType::AuthorizationCode => {
                if self.code.is_none() {
                    return Err(IssuerdError::InvalidGrant);
                }
                if self.redirect_uri.is_none() {
                    return Err(IssuerdError::InvalidGrant);
                }
                if client.public_client && self.code_verifier.is_none() {
                    return Err(IssuerdError::InvalidGrant);
                }
            }
            GrantType::RefreshToken => {
                if self.refresh_token.is_none() {
                    return Err(IssuerdError::InvalidGrant);
                }
            }
            GrantType::Password => {
                if self.username.is_none() || self.password.is_none() {
                    return Err(IssuerdError::InvalidGrant);
                }
            }
            GrantType::ClientCredentials => {
                // No extra required fields
            }
            GrantType::DeviceCode => {
                if self.device_code.is_none() {
                    return Err(IssuerdError::InvalidGrant);
                }
            }
            GrantType::Ciba => {
                if self.auth_req_id.is_none() {
                    return Err(IssuerdError::InvalidGrant);
                }
            }
            GrantType::TokenExchange => {
                // RFC 8693 §2.1: subject_token and subject_token_type are
                // REQUIRED.
                if self.subject_token.is_none() || self.subject_token_type.is_none() {
                    return Err(IssuerdError::InvalidGrant);
                }
                // Only access tokens issued by this server are accepted as
                // subject tokens (external-IdP and refresh-token subjects are
                // out of scope).
                if self.subject_token_type.as_deref() != Some(TOKEN_TYPE_ACCESS_TOKEN) {
                    return Err(IssuerdError::InvalidRequest(
                        "unsupported subject_token_type".into(),
                    ));
                }
                // Only access tokens are issued; any other requested type is
                // rejected rather than silently downgraded.
                if let Some(requested) = self.requested_token_type.as_deref() {
                    if requested != TOKEN_TYPE_ACCESS_TOKEN {
                        return Err(IssuerdError::InvalidRequest(
                            "unsupported requested_token_type".into(),
                        ));
                    }
                }
                // Delegation (actor_token) is out of scope.
                if self.actor_token.is_some() {
                    return Err(IssuerdError::InvalidRequest(
                        "actor_token (delegation) is not supported".into(),
                    ));
                }
            }
            GrantType::JwtBearer => {
                if self.assertion.is_none() || self.assertion_type.is_none() {
                    return Err(IssuerdError::InvalidGrant);
                }
            }
        }

        // RFC 6749 §3.3: every explicitly requested scope must be available
        // to the client. (The refresh grant additionally requires the
        // requested scope to be a subset of the originally granted scope —
        // enforced by the token endpoint, which has the grant context.)
        if !self.scope.is_empty() {
            let available: std::collections::HashSet<&str> = client
                .default_scopes
                .iter()
                .chain(client.optional_scopes.iter())
                .map(String::as_str)
                .collect();
            if self.scope.iter().any(|s| !available.contains(s.as_str())) {
                return Err(IssuerdError::InvalidScope);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    #[serde(rename = "refresh_token")]
    RefreshToken,
    #[serde(rename = "password")]
    Password,
    #[serde(rename = "client_credentials")]
    ClientCredentials,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode,
    #[serde(rename = "urn:openid:params:grant-type:ciba")]
    Ciba,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:token-exchange")]
    TokenExchange,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:jwt-bearer")]
    JwtBearer,
}

impl GrantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
            GrantType::Password => "password",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            GrantType::Ciba => "urn:openid:params:grant-type:ciba",
            GrantType::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
            GrantType::JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",
        }
    }
}

impl std::str::FromStr for GrantType {
    type Err = IssuerdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "refresh_token" => Ok(GrantType::RefreshToken),
            "password" => Ok(GrantType::Password),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "urn:ietf:params:oauth:grant-type:device_code" => Ok(GrantType::DeviceCode),
            "urn:openid:params:grant-type:ciba" => Ok(GrantType::Ciba),
            "urn:ietf:params:oauth:grant-type:token-exchange" => Ok(GrantType::TokenExchange),
            "urn:ietf:params:oauth:grant-type:jwt-bearer" => Ok(GrantType::JwtBearer),
            _ => Err(IssuerdError::InvalidRequest("unsupported grant_type".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{ClientAuthenticatorType, ClientProtocol};
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest]
    #[case("authorization_code", GrantType::AuthorizationCode)]
    #[case("refresh_token", GrantType::RefreshToken)]
    #[case("password", GrantType::Password)]
    #[case("client_credentials", GrantType::ClientCredentials)]
    #[case("urn:ietf:params:oauth:grant-type:device_code", GrantType::DeviceCode)]
    #[case("urn:openid:params:grant-type:ciba", GrantType::Ciba)]
    #[case(
        "urn:ietf:params:oauth:grant-type:token-exchange",
        GrantType::TokenExchange
    )]
    #[case("urn:ietf:params:oauth:grant-type:jwt-bearer", GrantType::JwtBearer)]
    fn grant_type_parsing(#[case] input: &str, #[case] expected: GrantType) {
        assert_eq!(GrantType::from_str(input).unwrap(), expected);
    }

    #[test]
    fn grant_type_invalid_rejection() {
        assert!(GrantType::from_str("unknown").is_err());
    }

    #[rstest]
    #[case(GrantType::AuthorizationCode, "authorization_code")]
    #[case(GrantType::RefreshToken, "refresh_token")]
    #[case(GrantType::Password, "password")]
    #[case(GrantType::ClientCredentials, "client_credentials")]
    #[case(GrantType::DeviceCode, "urn:ietf:params:oauth:grant-type:device_code")]
    #[case(GrantType::Ciba, "urn:openid:params:grant-type:ciba")]
    #[case(
        GrantType::TokenExchange,
        "urn:ietf:params:oauth:grant-type:token-exchange"
    )]
    #[case(GrantType::JwtBearer, "urn:ietf:params:oauth:grant-type:jwt-bearer")]
    fn grant_type_as_str(#[case] gt: GrantType, #[case] expected: &str) {
        assert_eq!(gt.as_str(), expected);
    }

    #[test]
    fn token_request_parse_authorization_code() {
        let mut body = HashMap::new();
        body.insert("grant_type".to_string(), "authorization_code".to_string());
        body.insert("code".to_string(), "abc".to_string());
        body.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        body.insert("client_id".to_string(), "client1".to_string());
        body.insert("code_verifier".to_string(), "verifier".to_string());
        body.insert("scope".to_string(), "openid profile".to_string());

        let req = TokenRequest::parse(&body).unwrap();
        assert_eq!(req.grant_type, GrantType::AuthorizationCode);
        assert_eq!(req.code, Some(AuthorizationCode::new("abc").unwrap()));
        assert_eq!(req.redirect_uri, Some("https://example.com/cb".parse().unwrap()));
        assert_eq!(req.scope, Scope::parse("openid profile"));
    }

    #[test]
    fn token_request_parse_password_grant_with_totp() {
        let mut body = HashMap::new();
        body.insert("grant_type".to_string(), "password".to_string());
        body.insert("username".to_string(), "alice".to_string());
        body.insert("password".to_string(), "secret".to_string());
        body.insert("totp".to_string(), "123456".to_string());

        let req = TokenRequest::parse(&body).unwrap();
        assert_eq!(req.grant_type, GrantType::Password);
        assert_eq!(req.totp.as_deref(), Some("123456"));

        // An empty `totp` parameter is treated as absent.
        body.insert("totp".to_string(), String::new());
        assert!(TokenRequest::parse(&body).unwrap().totp.is_none());
    }

    #[test]
    fn token_request_parse_missing_grant_type() {
        let body = HashMap::new();
        assert!(TokenRequest::parse(&body).is_err());
    }

    #[test]
    fn token_request_parse_invalid_grant_type() {
        let mut body = HashMap::new();
        body.insert("grant_type".to_string(), "magic".to_string());
        assert!(TokenRequest::parse(&body).is_err());
    }

    #[test]
    fn token_request_parse_invalid_redirect_uri() {
        let mut body = HashMap::new();
        body.insert("grant_type".to_string(), "authorization_code".to_string());
        body.insert("redirect_uri".to_string(), "not-a-url".to_string());
        assert!(TokenRequest::parse(&body).is_err());
    }

    #[test]
    fn validate_authorization_code_missing_code() {
        let req = TokenRequest {
            grant_type: GrantType::AuthorizationCode,
            code: None,
            redirect_uri: Some("https://example.com/cb".parse().unwrap()),
            client_id: None,
            client_secret: None,
            code_verifier: Some("verifier_123".to_string()),
            refresh_token: None,
            scope: Scope::empty(),
            username: None,
            password: None,
            totp: None,
            assertion: None,
            assertion_type: None,
            device_code: None,
            auth_req_id: None,
            subject_token: None,
            subject_token_type: None,
            requested_token_type: None,
            audience: None,
            requested_subject: None,
            actor_token: None,
            authorization_details: None,
        };
        let client = make_test_client(false);
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn validate_authorization_code_public_client_missing_verifier() {
        let req = TokenRequest {
            grant_type: GrantType::AuthorizationCode,
            code: Some(AuthorizationCode::new("code").unwrap()),
            redirect_uri: Some("https://example.com/cb".parse().unwrap()),
            client_id: None,
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: Scope::empty(),
            username: None,
            password: None,
            totp: None,
            assertion: None,
            assertion_type: None,
            device_code: None,
            auth_req_id: None,
            subject_token: None,
            subject_token_type: None,
            requested_token_type: None,
            audience: None,
            requested_subject: None,
            actor_token: None,
            authorization_details: None,
        };
        let client = make_test_client(true);
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn validate_refresh_token_missing_token() {
        let req = TokenRequest {
            grant_type: GrantType::RefreshToken,
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: Scope::empty(),
            username: None,
            password: None,
            totp: None,
            assertion: None,
            assertion_type: None,
            device_code: None,
            auth_req_id: None,
            subject_token: None,
            subject_token_type: None,
            requested_token_type: None,
            audience: None,
            requested_subject: None,
            actor_token: None,
            authorization_details: None,
        };
        assert!(req.validate(&Realm::default(), &make_test_client(false)).is_err());
    }

    #[test]
    fn validate_password_missing_username() {
        let req = TokenRequest {
            grant_type: GrantType::Password,
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: Scope::empty(),
            username: None,
            password: Some(Password::new("secret").unwrap()),
            totp: None,
            assertion: None,
            assertion_type: None,
            device_code: None,
            auth_req_id: None,
            subject_token: None,
            subject_token_type: None,
            requested_token_type: None,
            audience: None,
            requested_subject: None,
            actor_token: None,
            authorization_details: None,
        };
        assert!(req.validate(&Realm::default(), &make_test_client(false)).is_err());
    }

    #[test]
    fn validate_client_credentials_ok() {
        let req = TokenRequest {
            grant_type: GrantType::ClientCredentials,
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: Scope::empty(),
            username: None,
            password: None,
            totp: None,
            assertion: None,
            assertion_type: None,
            device_code: None,
            auth_req_id: None,
            subject_token: None,
            subject_token_type: None,
            requested_token_type: None,
            audience: None,
            requested_subject: None,
            actor_token: None,
            authorization_details: None,
        };
        assert!(req.validate(&Realm::default(), &make_test_client(false)).is_ok());
    }

    #[test]
    fn token_exchange_parse_full_request() {
        let mut body = HashMap::new();
        body.insert(
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        );
        body.insert("client_id".to_string(), "client1".to_string());
        body.insert("subject_token".to_string(), "subject.jwt".to_string());
        body.insert(
            "subject_token_type".to_string(),
            "urn:ietf:params:oauth:token-type:access_token".to_string(),
        );
        body.insert(
            "requested_token_type".to_string(),
            "urn:ietf:params:oauth:token-type:access_token".to_string(),
        );
        body.insert("audience".to_string(), "target-client".to_string());

        let req = TokenRequest::parse(&body).unwrap();
        assert_eq!(req.grant_type, GrantType::TokenExchange);
        assert_eq!(req.subject_token.as_deref(), Some("subject.jwt"));
        assert_eq!(req.subject_token_type.as_deref(), Some(TOKEN_TYPE_ACCESS_TOKEN));
        assert_eq!(req.requested_token_type.as_deref(), Some(TOKEN_TYPE_ACCESS_TOKEN));
        assert_eq!(req.audience.as_deref(), Some("target-client"));
        assert!(req.requested_subject.is_none());
        assert!(req.actor_token.is_none());
        assert!(req.validate(&Realm::default(), &make_test_client(false)).is_ok());
    }

    #[test]
    fn token_request_parses_authorization_details() {
        let mut body = HashMap::new();
        body.insert("grant_type".to_string(), "authorization_code".to_string());
        body.insert("code".to_string(), "code-1".to_string());
        body.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        body.insert(
            "authorization_details".to_string(),
            r#"[{"type":"payment_initiation","actions":["initiate"]}]"#.to_string(),
        );
        let req = TokenRequest::parse(&body).unwrap();
        let details = req.authorization_details.unwrap();
        assert_eq!(
            details,
            vec![serde_json::json!({"type":"payment_initiation","actions":["initiate"]})]
        );

        // Malformed values are rejected with the RFC 9396 error code.
        body.insert("authorization_details".to_string(), r#"{"type":"x"}"#.to_string());
        let err = TokenRequest::parse(&body).unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidAuthorizationDetails(_)));
    }

    fn make_token_exchange_request(
        subject_token: Option<&str>,
        subject_token_type: Option<&str>,
    ) -> TokenRequest {
        TokenRequest {
            grant_type: GrantType::TokenExchange,
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scope: Scope::empty(),
            username: None,
            password: None,
            totp: None,
            assertion: None,
            assertion_type: None,
            device_code: None,
            auth_req_id: None,
            subject_token: subject_token.map(str::to_string),
            subject_token_type: subject_token_type.map(str::to_string),
            requested_token_type: None,
            audience: None,
            requested_subject: None,
            actor_token: None,
            authorization_details: None,
        }
    }

    #[test]
    fn token_exchange_validate_requires_subject_token_and_type() {
        let client = make_test_client(false);
        let missing_both = make_token_exchange_request(None, None);
        assert!(missing_both.validate(&Realm::default(), &client).is_err());
        let missing_type = make_token_exchange_request(Some("tok"), None);
        assert!(missing_type.validate(&Realm::default(), &client).is_err());
        let missing_token = make_token_exchange_request(None, Some(TOKEN_TYPE_ACCESS_TOKEN));
        assert!(missing_token.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn token_exchange_validate_rejects_non_access_token_subject_type() {
        let client = make_test_client(false);
        let req = make_token_exchange_request(
            Some("tok"),
            Some("urn:ietf:params:oauth:token-type:refresh_token"),
        );
        let err = req.validate(&Realm::default(), &client).unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidRequest(_)));
    }

    #[test]
    fn token_exchange_validate_rejects_unsupported_requested_token_type() {
        let client = make_test_client(false);
        let mut req = make_token_exchange_request(Some("tok"), Some(TOKEN_TYPE_ACCESS_TOKEN));
        req.requested_token_type = Some("urn:ietf:params:oauth:token-type:id_token".to_string());
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn token_exchange_validate_rejects_actor_token() {
        let client = make_test_client(false);
        let mut req = make_token_exchange_request(Some("tok"), Some(TOKEN_TYPE_ACCESS_TOKEN));
        req.actor_token = Some("actor.jwt".to_string());
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn token_exchange_validate_minimal_ok() {
        let client = make_test_client(false);
        let req = make_token_exchange_request(Some("tok"), Some(TOKEN_TYPE_ACCESS_TOKEN));
        assert!(req.validate(&Realm::default(), &client).is_ok());
    }

    fn make_test_client(public_client: bool) -> Client {
        Client {
            id: issuerd_core::ClientId::new("client-1").unwrap(),
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            client_id: ClientIdentifier::new("client1").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client,
            bearer_only: false,
            client_authenticator_type: ClientAuthenticatorType::ClientSecret,
            secret: None,
            redirect_uris: vec![],
            web_origins: vec![],
            default_scopes: Scope::empty(),
            optional_scopes: Scope::empty(),
            consent_required: false,
            full_scope_allowed: true,
            service_accounts_enabled: false,
            protocol_mappers: Vec::new(),
            scope_mappings: Default::default(),
            attributes: std::collections::HashMap::new(),
        }
    }
}
