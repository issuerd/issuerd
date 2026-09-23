// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Device authorization grant request parsing and validation (RFC 8628).

use std::collections::HashMap;

use issuerd_core::{Client, ClientIdentifier, IssuerdError, Scope};
use serde::Serialize;

use crate::utils::parse_scope;

#[derive(Debug, Clone)]
pub struct DeviceAuthorizationRequest {
    pub client_id: ClientIdentifier,
    pub scope: Scope,
}

impl DeviceAuthorizationRequest {
    pub fn parse(body: &HashMap<String, String>) -> Result<Self, IssuerdError> {
        let client_id = body
            .get("client_id")
            .ok_or_else(|| IssuerdError::InvalidRequest("missing client_id".into()))?
            .as_str()
            .try_into()?;

        let scope = parse_scope(body.get("scope"));

        Ok(Self { client_id, scope })
    }

    pub fn validate(&self, client: &Client) -> Result<(), IssuerdError> {
        if self.client_id != client.client_id {
            return Err(IssuerdError::InvalidRequest("client_id mismatch".into()));
        }
        if !client.enabled {
            return Err(IssuerdError::UnauthorizedClient);
        }
        // RFC 6749 §3.3: every requested scope must be assigned to the client
        // (same rule as the authorization and token endpoints) — otherwise a
        // client could pick up scopes such as `offline_access` that the admin
        // deliberately left unassigned.
        let available: std::collections::HashSet<&str> = client
            .default_scopes
            .iter()
            .chain(client.optional_scopes.iter())
            .map(String::as_str)
            .collect();
        if self.scope.iter().any(|s| !available.contains(s.as_str())) {
            return Err(IssuerdError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{ClientAuthenticatorType, ClientProtocol};

    fn make_test_client() -> Client {
        Client {
            id: issuerd_core::ClientId::new("client-1").unwrap(),
            realm_id: issuerd_core::RealmId::new("realm-1").unwrap(),
            client_id: ClientIdentifier::new("client1").unwrap(),
            name: None,
            description: None,
            enabled: true,
            protocol: ClientProtocol::OpenIdConnect,
            public_client: false,
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

    #[test]
    fn device_auth_request_parse_minimal() {
        let mut body = HashMap::new();
        body.insert("client_id".to_string(), "client1".to_string());

        let req = DeviceAuthorizationRequest::parse(&body).unwrap();
        assert_eq!(req.client_id, "client1");
        assert!(req.scope.is_empty());
    }

    #[test]
    fn device_auth_request_parse_with_scope() {
        let mut body = HashMap::new();
        body.insert("client_id".to_string(), "client1".to_string());
        body.insert("scope".to_string(), "openid profile".to_string());

        let req = DeviceAuthorizationRequest::parse(&body).unwrap();
        assert_eq!(req.scope, Scope::parse("openid profile"));
    }

    #[test]
    fn device_auth_request_missing_client_id() {
        let body = HashMap::new();
        assert!(DeviceAuthorizationRequest::parse(&body).is_err());
    }

    #[test]
    fn device_auth_validate_ok() {
        let client = make_test_client();
        let req = DeviceAuthorizationRequest {
            client_id: ClientIdentifier::new("client1").unwrap(),
            scope: Scope::empty(),
        };
        assert!(req.validate(&client).is_ok());
    }

    #[test]
    fn device_auth_validate_wrong_client_id() {
        let client = make_test_client();
        let req = DeviceAuthorizationRequest {
            client_id: ClientIdentifier::new("other_client").unwrap(),
            scope: Scope::empty(),
        };
        assert!(req.validate(&client).is_err());
    }

    #[test]
    fn device_auth_validate_disabled_client() {
        let mut client = make_test_client();
        client.enabled = false;
        let req = DeviceAuthorizationRequest {
            client_id: ClientIdentifier::new("client1").unwrap(),
            scope: Scope::empty(),
        };
        assert!(req.validate(&client).is_err());
    }
}
