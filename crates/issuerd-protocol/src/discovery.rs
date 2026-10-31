// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OIDC Discovery 1.0 metadata types (subject types, client auth methods, algorithms).

use serde::{Deserialize, Serialize};
use url::Url;

/// Subject type supported by the OP per OIDC Discovery 1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectType {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "pairwise")]
    Pairwise,
}

impl SubjectType {
    /// Return the wire-name for this subject type.
    pub fn as_str(&self) -> &'static str {
        match self {
            SubjectType::Public => "public",
            SubjectType::Pairwise => "pairwise",
        }
    }
}

impl std::str::FromStr for SubjectType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public" => Ok(SubjectType::Public),
            "pairwise" => Ok(SubjectType::Pairwise),
            _ => Err(()),
        }
    }
}

/// Token endpoint client authentication methods per OAuth 2.0/OIDC Discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    ClientSecretPost,
    ClientSecretBasic,
    ClientSecretJwt,
    PrivateKeyJwt,
    TlsClientAuth,
    SelfSignedTlsClientAuth,
    None,
}

impl TokenEndpointAuthMethod {
    /// Return the wire-name for this authentication method.
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenEndpointAuthMethod::ClientSecretPost => "client_secret_post",
            TokenEndpointAuthMethod::ClientSecretBasic => "client_secret_basic",
            TokenEndpointAuthMethod::ClientSecretJwt => "client_secret_jwt",
            TokenEndpointAuthMethod::PrivateKeyJwt => "private_key_jwt",
            TokenEndpointAuthMethod::TlsClientAuth => "tls_client_auth",
            TokenEndpointAuthMethod::SelfSignedTlsClientAuth => "self_signed_tls_client_auth",
            TokenEndpointAuthMethod::None => "none",
        }
    }
}

impl std::str::FromStr for TokenEndpointAuthMethod {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "client_secret_post" => Ok(TokenEndpointAuthMethod::ClientSecretPost),
            "client_secret_basic" => Ok(TokenEndpointAuthMethod::ClientSecretBasic),
            "client_secret_jwt" => Ok(TokenEndpointAuthMethod::ClientSecretJwt),
            "private_key_jwt" => Ok(TokenEndpointAuthMethod::PrivateKeyJwt),
            "tls_client_auth" => Ok(TokenEndpointAuthMethod::TlsClientAuth),
            "self_signed_tls_client_auth" => Ok(TokenEndpointAuthMethod::SelfSignedTlsClientAuth),
            "none" => Ok(TokenEndpointAuthMethod::None),
            _ => Err(()),
        }
    }
}

/// Serde helper for `Vec<issuerd_core::Scope>` as an array of space-separated strings.
mod scope_vec {
    use issuerd_core::Scope;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(scopes: &[Scope], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec: Vec<String> = scopes.iter().map(|s| s.to_space_separated()).collect();
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Scope>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<String> = Vec::deserialize(deserializer)?;
        Ok(vec.into_iter().map(|s| Scope::parse(&s)).collect())
    }
}

/// OpenID Connect Discovery response per OIDC Discovery 1.0 spec.
///
/// All fields in this struct are required per the spec for a basic OIDC provider.
/// Optional fields may be added later with `#[serde(skip_serializing_if = "Option::is_none")]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Url,
    pub jwks_uri: Url,
    pub introspection_endpoint: Url,
    pub revocation_endpoint: Url,
    pub end_session_endpoint: Url,
    /// The OP iframe URL (OIDC Session Management 1.0 §4.2). Always
    /// advertised: the endpoint exists on every realm.
    pub check_session_iframe: Url,
    pub device_authorization_endpoint: Url,
    pub backchannel_authentication_endpoint: Url,
    /// OpenID CIBA delivery modes implemented by this server. Poll only.
    pub backchannel_token_delivery_modes_supported: Vec<String>,
    /// PAR endpoint per RFC 9126 §5.
    pub pushed_authorization_request_endpoint: Url,
    /// Dynamic client registration endpoint (RFC 7591 §3).
    /// `None` — and therefore omitted from the JSON — unless the realm opted
    /// in via its `dynamic_client_registration_enabled` attribute; the server
    /// handler overrides this per realm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<Url>,
    /// Whether authorization request data is accepted only via PAR
    /// (RFC 9126 §5). Default `false`; the server handler overrides this per
    /// realm from the `require_pushed_authorization_requests` realm attribute.
    pub require_pushed_authorization_requests: bool,
    /// JAR (RFC 9101): signed Request Objects via the `request`
    /// parameter are implemented.
    pub request_parameter_supported: bool,
    /// JAR-by-reference: `request_uri` is implemented for client-registered
    /// URIs (fetched SSRF-guarded, signed-only — `none` is never accepted).
    pub request_uri_parameter_supported: bool,
    /// Signing algorithms accepted for Request Objects (RFC 9101 §10.2):
    /// asymmetric against the client's JWKS, HMAC with the client secret.
    pub request_object_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
    /// JARM: algorithms the server may use to sign authorization
    /// responses (`response_mode=jwt` family). The server handler overrides
    /// this per request with the active signing algorithms.
    pub authorization_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
    /// RFC 9207 authorization responses carry the exact realm issuer in `iss`.
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    #[serde(with = "scope_vec")]
    pub scopes_supported: Vec<issuerd_core::Scope>,
    pub response_types_supported: Vec<crate::authorization::ResponseType>,
    pub response_modes_supported: Vec<crate::authorization::ResponseMode>,
    pub grant_types_supported: Vec<crate::token::GrantType>,
    pub acr_values_supported: Vec<issuerd_core::Acr>,
    pub subject_types_supported: Vec<SubjectType>,
    pub id_token_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
    /// Algorithms the server may use to sign userinfo responses (OIDC Core
    /// §5.3.2). Same source as the id_token list: the active signing keys.
    pub userinfo_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    /// Signing algorithms accepted for `private_key_jwt` / `client_secret_jwt`
    /// client assertions (OIDC Discovery 1.0; required when either method is
    /// advertised).
    pub token_endpoint_auth_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
    /// Signing algorithms accepted for DPoP proof JWTs (RFC 9449 §5.1): the
    /// asymmetric accept set of the proof validator.
    pub dpop_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
    /// RAR authorization-details types (RFC 9396 §10). Empty (and
    /// therefore omitted from the JSON) means the deployment defines no type
    /// list — any type is then accepted. The server handler populates this
    /// per realm from the realm's `authorization_details_types` attribute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_details_types_supported: Vec<String>,
    pub claims_supported: Vec<issuerd_core::ClaimName>,
    pub code_challenge_methods_supported: Vec<issuerd_core::PkceCodeChallengeMethod>,
    /// OIDC Back-Channel Logout 1.0.
    pub backchannel_logout_supported: bool,
    /// Back-channel logout tokens carry the `sid` claim.
    pub backchannel_logout_session_supported: bool,
    /// OIDC Front-Channel Logout 1.0.
    pub frontchannel_logout_supported: bool,
    /// Front-channel logout iframes are called with `iss` + `sid`.
    pub frontchannel_logout_session_supported: bool,
}

impl DiscoveryResponse {
    /// Build the discovery document for a realm.
    ///
    /// # Examples
    ///
    /// ```
    /// use issuerd_protocol::discovery::DiscoveryResponse;
    ///
    /// let response = DiscoveryResponse::for_realm("https://issuer.example", "demo");
    /// assert_eq!(response.issuer.as_str(), "https://issuer.example/realms/demo");
    /// assert_eq!(
    ///     response.token_endpoint.as_str(),
    ///     "https://issuer.example/realms/demo/protocol/openid-connect/token"
    /// );
    /// ```
    ///
    /// # Panics
    ///
    /// Panics when the configured base URL and realm name cannot form canonical URLs.
    pub fn for_realm(base_url: &str, realm: &str) -> Self {
        let urls = issuerd_core::urls::RealmUrlBuilder::new(base_url, realm)
            .expect("the configured base URL and a valid realm name form canonical URLs");
        let issuer = urls.issuer();
        Self {
            authorization_endpoint: urls.path(&["protocol", "openid-connect", "auth"]),
            token_endpoint: urls.path(&["protocol", "openid-connect", "token"]),
            userinfo_endpoint: urls.path(&["protocol", "openid-connect", "userinfo"]),
            jwks_uri: urls.path(&["protocol", "openid-connect", "certs"]),
            introspection_endpoint: urls.path(&[
                "protocol",
                "openid-connect",
                "token",
                "introspect",
            ]),
            revocation_endpoint: urls.path(&["protocol", "openid-connect", "revoke"]),
            end_session_endpoint: urls.path(&["protocol", "openid-connect", "logout"]),
            check_session_iframe: urls.path(&[
                "protocol",
                "openid-connect",
                "check_session_iframe",
            ]),
            device_authorization_endpoint: urls.path(&[
                "protocol",
                "openid-connect",
                "auth",
                "device",
            ]),
            backchannel_authentication_endpoint: urls.path(&[
                "protocol",
                "openid-connect",
                "ext",
                "ciba",
                "auth",
            ]),
            backchannel_token_delivery_modes_supported: vec!["poll".into()],
            pushed_authorization_request_endpoint: urls.path(&[
                "protocol",
                "openid-connect",
                "ext",
                "par",
            ]),
            // Set per realm by the server handler only when the
            // realm enables dynamic client registration.
            registration_endpoint: None,
            require_pushed_authorization_requests: false,
            // JAR (signed request objects) is implemented;
            // JAR-by-reference for client-registered URIs is implemented too.
            request_parameter_supported: true,
            request_uri_parameter_supported: true,
            request_object_signing_alg_values_supported: vec![
                issuerd_core::Algorithm::Rs256,
                issuerd_core::Algorithm::Rs384,
                issuerd_core::Algorithm::Rs512,
                issuerd_core::Algorithm::Es256,
                issuerd_core::Algorithm::Es384,
                issuerd_core::Algorithm::EdDsa,
                issuerd_core::Algorithm::Hs256,
                issuerd_core::Algorithm::Hs384,
                issuerd_core::Algorithm::Hs512,
            ],
            authorization_signing_alg_values_supported: vec![issuerd_core::Algorithm::Rs256],
            authorization_response_iss_parameter_supported: true,
            issuer,
            scopes_supported: vec![
                issuerd_core::Scope::parse("openid"),
                issuerd_core::Scope::parse("profile"),
                issuerd_core::Scope::parse("email"),
                issuerd_core::Scope::parse("offline_access"),
                issuerd_core::Scope::parse("address"),
                issuerd_core::Scope::parse("phone"),
                // Real client scopes seeded into every realm.
                issuerd_core::Scope::parse("roles"),
                issuerd_core::Scope::parse("web-origins"),
                issuerd_core::Scope::parse("acr"),
            ],
            response_types_supported: vec![
                // Every OIDC response type the authorization endpoint accepts
                // (bare `token` is OAuth2-only and deliberately excluded).
                crate::authorization::ResponseType::Code,
                crate::authorization::ResponseType::CodeIdToken,
                crate::authorization::ResponseType::CodeIdTokenToken,
                crate::authorization::ResponseType::CodeToken,
                crate::authorization::ResponseType::IdToken,
                crate::authorization::ResponseType::IdTokenToken,
                // OIDCD-3 (Dynamic profile) probes for the token-first
                // spelling of the implicit pair; both are the same type, so
                // advertise both (Keycloak does the same).
                crate::authorization::ResponseType::TokenIdToken,
            ],
            response_modes_supported: vec![
                crate::authorization::ResponseMode::Query,
                crate::authorization::ResponseMode::Fragment,
                // form_post and the JARM family are implemented.
                crate::authorization::ResponseMode::FormPost,
                crate::authorization::ResponseMode::Jwt,
                crate::authorization::ResponseMode::QueryJwt,
                crate::authorization::ResponseMode::FragmentJwt,
                crate::authorization::ResponseMode::FormPostJwt,
            ],
            grant_types_supported: vec![
                crate::token::GrantType::AuthorizationCode,
                // Implicit and hybrid flows are implemented (the
                // authorization endpoint issues tokens directly).
                crate::token::GrantType::Implicit,
                crate::token::GrantType::RefreshToken,
                crate::token::GrantType::ClientCredentials,
                crate::token::GrantType::DeviceCode,
                crate::token::GrantType::Ciba,
                // Token exchange (RFC 8693) is implemented.
                crate::token::GrantType::TokenExchange,
            ],
            acr_values_supported: vec![
                issuerd_core::Acr::new("1").unwrap(),
                issuerd_core::Acr::new("0").unwrap(),
            ],
            // Pairwise subjects are implemented (per-client
            // `subject_type` opt-in).
            subject_types_supported: vec![SubjectType::Public, SubjectType::Pairwise],
            id_token_signing_alg_values_supported: vec![issuerd_core::Algorithm::Rs256],
            userinfo_signing_alg_values_supported: vec![issuerd_core::Algorithm::Rs256],
            token_endpoint_auth_methods_supported: vec![
                TokenEndpointAuthMethod::ClientSecretPost,
                TokenEndpointAuthMethod::ClientSecretBasic,
                // JWT client assertions are implemented.
                TokenEndpointAuthMethod::ClientSecretJwt,
                TokenEndpointAuthMethod::PrivateKeyJwt,
                TokenEndpointAuthMethod::None,
            ],
            token_endpoint_auth_signing_alg_values_supported: vec![
                issuerd_core::Algorithm::Rs256,
                issuerd_core::Algorithm::Rs384,
                issuerd_core::Algorithm::Rs512,
                issuerd_core::Algorithm::Es256,
                issuerd_core::Algorithm::Es384,
                issuerd_core::Algorithm::EdDsa,
                issuerd_core::Algorithm::Hs256,
                issuerd_core::Algorithm::Hs384,
                issuerd_core::Algorithm::Hs512,
            ],
            // DPoP proofs are asymmetric-only: the accept set of the proof
            // validator (`issuerd_token::dpop::validate_dpop_proof`), shared
            // with the RFC 9728 protected-resource metadata via the constant.
            dpop_signing_alg_values_supported:
                issuerd_core::Algorithm::DPOP_SIGNING_ALG_VALUES_SUPPORTED.to_vec(),
            // Populated per realm by the server handler from the
            // realm's `authorization_details_types` attribute; omitted when
            // the deployment defines no type list.
            authorization_details_types_supported: Vec::new(),
            claims_supported: vec![
                issuerd_core::ClaimName::new("sub").unwrap(),
                issuerd_core::ClaimName::new("iss").unwrap(),
                issuerd_core::ClaimName::new("aud").unwrap(),
                issuerd_core::ClaimName::new("exp").unwrap(),
                issuerd_core::ClaimName::new("iat").unwrap(),
                issuerd_core::ClaimName::new("email").unwrap(),
                issuerd_core::ClaimName::new("name").unwrap(),
                issuerd_core::ClaimName::new("preferred_username").unwrap(),
            ],
            code_challenge_methods_supported: vec![issuerd_core::PkceCodeChallengeMethod::S256],
            // Back-channel and front-channel logout are implemented.
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
            frontchannel_logout_supported: true,
            frontchannel_logout_session_supported: true,
        }
    }
}

/// OAuth 2.0 Protected Resource Metadata (RFC 9728 §3.2) for a realm's MCP
/// resource (`{issuer_url}/realms/{realm}/mcp`).
///
/// The path-suffixed RFC 9728 §3.1 form preserves any issuer base path:
/// `/.well-known/oauth-protected-resource/{issuer-path}/realms/{realm}/mcp`.
/// The bare `/.well-known/oauth-protected-resource` route is also available
/// as an explicit `resource_metadata` alias for the master realm, not as
/// origin-level metadata. Groundwork for the MCP endpoint (GitHub issue #39).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// The protected resource identifier (RFC 9728 §3.2 `resource`).
    pub resource: Url,
    /// Authorization servers issuing tokens for this resource: the realm
    /// issuer URL — identical to the OIDC discovery document's `issuer`.
    pub authorization_servers: Vec<Url>,
    /// The minimal basic scope set advertised for initial MCP authorization.
    pub scopes_supported: Vec<String>,
    /// Whether access tokens must be DPoP-bound (RFC 9728 §3.2).
    #[serde(default)]
    pub dpop_bound_access_tokens_required: bool,
    /// DPoP proof signing algorithms accepted at the resource (RFC 9449
    /// §5.1): the same validator accept set the OIDC discovery document
    /// advertises (`Algorithm::DPOP_SIGNING_ALG_VALUES_SUPPORTED`).
    pub dpop_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
    /// RFC 6750 bearer-token presentation methods. Empty omits the field for
    /// the strict DPoP profile; explicit Bearer compatibility advertises the
    /// Authorization header only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bearer_methods_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    /// Build strict DPoP-only metadata for the realm named `realm`.
    pub fn for_realm(base_url: &str, realm: &str) -> Self {
        Self::for_realm_with_profile(base_url, realm, true)
    }

    /// Build metadata describing the configured DPoP/Bearer profile.
    pub fn for_realm_with_profile(base_url: &str, realm: &str, require_dpop: bool) -> Self {
        let urls = issuerd_core::urls::RealmUrlBuilder::new(base_url, realm)
            .expect("the configured base URL and a valid realm name form canonical URLs");
        Self {
            resource: urls.path(&["mcp"]),
            authorization_servers: vec![urls.issuer()],
            scopes_supported: vec![issuerd_core::MCP_SCOPE_READ.to_string()],
            dpop_bound_access_tokens_required: require_dpop,
            dpop_signing_alg_values_supported:
                issuerd_core::Algorithm::DPOP_SIGNING_ALG_VALUES_SUPPORTED.to_vec(),
            bearer_methods_supported: if require_dpop {
                Vec::new()
            } else {
                vec!["header".to_string()]
            },
        }
    }

    /// Derive the RFC 9728 §3.1 metadata URL for the realm's MCP resource,
    /// preserving any path prefix in the configured issuer URL.
    pub fn metadata_url_for_realm(base_url: &str, realm: &str) -> Url {
        issuerd_core::urls::RealmUrlBuilder::new(base_url, realm)
            .expect("the configured base URL and a valid realm name form canonical URLs")
            .with_prefix(&[".well-known", "oauth-protected-resource"], &["mcp"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_url_construction() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        assert_eq!(d.issuer.as_str(), "https://auth.example.com/realms/test-realm");
        assert_eq!(
            d.authorization_endpoint.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/auth"
        );
        assert_eq!(
            d.token_endpoint.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/token"
        );
        assert_eq!(
            d.userinfo_endpoint.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/userinfo"
        );
        assert_eq!(
            d.jwks_uri.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/certs"
        );
        assert_eq!(
            d.introspection_endpoint.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/token/introspect"
        );
        assert_eq!(
            d.revocation_endpoint.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/revoke"
        );
        assert_eq!(
            d.end_session_endpoint.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/logout"
        );
        assert_eq!(
            d.check_session_iframe.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/check_session_iframe"
        );
        assert_eq!(
            d.device_authorization_endpoint.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/auth/device"
        );
        assert_eq!(
            d.backchannel_authentication_endpoint.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/ext/ciba/auth"
        );
        assert_eq!(
            d.pushed_authorization_request_endpoint.as_str(),
            "https://auth.example.com/realms/test-realm/protocol/openid-connect/ext/par"
        );
        assert!(!d.require_pushed_authorization_requests);
    }

    #[test]
    fn discovery_serialization_roundtrip() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        let json = serde_json::to_string(&d).unwrap();
        let back: DiscoveryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(d.issuer, back.issuer);
        assert_eq!(d.authorization_endpoint, back.authorization_endpoint);
        assert_eq!(
            d.pushed_authorization_request_endpoint,
            back.pushed_authorization_request_endpoint
        );
        assert_eq!(
            d.require_pushed_authorization_requests,
            back.require_pushed_authorization_requests
        );
        assert_eq!(d.scopes_supported, back.scopes_supported);
        assert_eq!(d.response_types_supported, back.response_types_supported);
        assert_eq!(d.response_modes_supported, back.response_modes_supported);
        assert_eq!(d.request_parameter_supported, back.request_parameter_supported);
        assert_eq!(d.request_uri_parameter_supported, back.request_uri_parameter_supported);
        assert_eq!(
            d.request_object_signing_alg_values_supported,
            back.request_object_signing_alg_values_supported
        );
        assert_eq!(
            d.authorization_signing_alg_values_supported,
            back.authorization_signing_alg_values_supported
        );
        assert_eq!(d.subject_types_supported, back.subject_types_supported);
        assert_eq!(
            d.token_endpoint_auth_methods_supported,
            back.token_endpoint_auth_methods_supported
        );
        assert_eq!(
            d.token_endpoint_auth_signing_alg_values_supported,
            back.token_endpoint_auth_signing_alg_values_supported
        );
    }

    #[test]
    fn discovery_advertises_jwt_client_auth_truthfully() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        // Both JWT assertion methods are implemented.
        assert!(d
            .token_endpoint_auth_methods_supported
            .contains(&TokenEndpointAuthMethod::ClientSecretJwt));
        assert!(d
            .token_endpoint_auth_methods_supported
            .contains(&TokenEndpointAuthMethod::PrivateKeyJwt));
        // The signing-alg list must cover every algorithm the assertion
        // validator accepts (asymmetric for private_key_jwt, HMAC for
        // client_secret_jwt).
        let algs = &d.token_endpoint_auth_signing_alg_values_supported;
        for alg in [
            issuerd_core::Algorithm::Rs256,
            issuerd_core::Algorithm::Rs384,
            issuerd_core::Algorithm::Rs512,
            issuerd_core::Algorithm::Es256,
            issuerd_core::Algorithm::Es384,
            issuerd_core::Algorithm::EdDsa,
            issuerd_core::Algorithm::Hs256,
            issuerd_core::Algorithm::Hs384,
            issuerd_core::Algorithm::Hs512,
        ] {
            assert!(algs.contains(&alg), "missing {alg}");
        }
        // Unimplemented methods stay unadvertised.
        assert!(!d
            .token_endpoint_auth_methods_supported
            .contains(&TokenEndpointAuthMethod::TlsClientAuth));
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"token_endpoint_auth_signing_alg_values_supported\""));
        assert!(json.contains("\"private_key_jwt\""));
        assert!(json.contains("\"client_secret_jwt\""));
        assert!(json.contains("\"HS256\""));
    }

    #[test]
    fn dpop_alg_list_is_the_shared_validator_accept_set() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        // The advertised set IS the proof validator's accept set — one shared
        // constant, not a hand-synced copy (RFC 9449 §5.1).
        assert_eq!(
            d.dpop_signing_alg_values_supported,
            issuerd_core::Algorithm::DPOP_SIGNING_ALG_VALUES_SUPPORTED
        );
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(
            json["dpop_signing_alg_values_supported"],
            serde_json::json!(["RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"])
        );
    }

    #[test]
    fn protected_resource_metadata_defaults_to_strict_dpop() {
        let doc = ProtectedResourceMetadata::for_realm("https://auth.example.com", "test-realm");
        let json = serde_json::to_value(&doc).unwrap();
        let mut keys: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "authorization_servers",
                "dpop_bound_access_tokens_required",
                "dpop_signing_alg_values_supported",
                "resource",
                "scopes_supported"
            ]
        );
        assert_eq!(json["resource"], "https://auth.example.com/realms/test-realm/mcp");
        assert_eq!(
            json["authorization_servers"],
            serde_json::json!(["https://auth.example.com/realms/test-realm"])
        );
        assert_eq!(json["scopes_supported"], serde_json::json!(["mcp:read"]));
        assert_eq!(json["dpop_bound_access_tokens_required"], true);
        assert_eq!(
            json["dpop_signing_alg_values_supported"],
            serde_json::json!(["RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"])
        );
        assert!(json.get("bearer_methods_supported").is_none());
        assert!(doc.bearer_methods_supported.is_empty());
    }

    #[test]
    fn protected_resource_metadata_explicit_bearer_compatibility() {
        let doc = ProtectedResourceMetadata::for_realm_with_profile(
            "https://auth.example.com",
            "test-realm",
            false,
        );
        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(json["dpop_bound_access_tokens_required"], false);
        assert_eq!(json["bearer_methods_supported"], serde_json::json!(["header"]));
        assert_eq!(json["scopes_supported"], serde_json::json!(["mcp:read"]));
    }

    #[test]
    fn discovery_advertises_public_client_auth_and_authorization_issuer() {
        let doc = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        assert!(doc
            .token_endpoint_auth_methods_supported
            .contains(&TokenEndpointAuthMethod::None));
        assert!(doc.authorization_response_iss_parameter_supported);
        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(json["authorization_response_iss_parameter_supported"], true);
        assert!(json["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("none")));
    }

    #[test]
    fn protected_resource_metadata_uses_realm_name_and_trims_base_slash() {
        let doc = ProtectedResourceMetadata::for_realm("https://auth.example.com/", "demo");
        assert_eq!(doc.resource.as_str(), "https://auth.example.com/realms/demo/mcp");
        assert_eq!(doc.authorization_servers[0].as_str(), "https://auth.example.com/realms/demo");
    }

    #[test]
    fn protected_resource_metadata_url_preserves_issuer_path_prefix() {
        let url = ProtectedResourceMetadata::metadata_url_for_realm(
            "https://auth.example.com/iam",
            "demo",
        );
        assert_eq!(
            url.as_str(),
            "https://auth.example.com/.well-known/oauth-protected-resource/iam/realms/demo/mcp"
        );
        let url =
            ProtectedResourceMetadata::metadata_url_for_realm("https://auth.example.com/", "demo");
        assert_eq!(
            url.as_str(),
            "https://auth.example.com/.well-known/oauth-protected-resource/realms/demo/mcp"
        );
    }

    #[test]
    fn special_realm_urls_share_one_canonical_encoding() {
        let discovery = DiscoveryResponse::for_realm("https://auth.example.com/iam", "tenant{one}");
        let resource =
            ProtectedResourceMetadata::for_realm("https://auth.example.com/iam", "tenant{one}");
        let issuer = "https://auth.example.com/iam/realms/tenant%7Bone%7D";
        assert_eq!(discovery.issuer.as_str(), issuer);
        assert_eq!(
            discovery.token_endpoint.as_str(),
            format!("{issuer}/protocol/openid-connect/token")
        );
        assert_eq!(resource.authorization_servers, vec![discovery.issuer]);
        assert_eq!(resource.resource.as_str(), format!("{issuer}/mcp"));
        assert_eq!(
            ProtectedResourceMetadata::metadata_url_for_realm(
                "https://auth.example.com/iam",
                "tenant{one}"
            )
            .as_str(),
            "https://auth.example.com/.well-known/oauth-protected-resource/iam/realms/tenant%7Bone%7D/mcp"
        );
    }

    #[test]
    fn protected_resource_metadata_serialization_roundtrip() {
        let doc = ProtectedResourceMetadata::for_realm("https://auth.example.com", "test-realm");
        let json = serde_json::to_string(&doc).unwrap();
        let back: ProtectedResourceMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(doc.resource, back.resource);
        assert_eq!(doc.authorization_servers, back.authorization_servers);
        assert_eq!(doc.scopes_supported, back.scopes_supported);
        assert_eq!(doc.dpop_signing_alg_values_supported, back.dpop_signing_alg_values_supported);
        assert_eq!(doc.bearer_methods_supported, back.bearer_methods_supported);
    }

    #[test]
    fn discovery_json_contains_expected_fields() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"issuer\""));
        assert!(json.contains("\"authorization_endpoint\""));
        assert!(json.contains("\"token_endpoint\""));
        assert!(json.contains("\"userinfo_endpoint\""));
        assert!(json.contains("\"jwks_uri\""));
        assert!(json.contains("\"introspection_endpoint\""));
        assert!(json.contains("\"revocation_endpoint\""));
        assert!(json.contains("\"end_session_endpoint\""));
        assert!(json.contains("\"scopes_supported\""));
        assert!(json.contains("\"response_types_supported\""));
        assert!(json.contains("\"response_modes_supported\""));
        assert!(json.contains("\"grant_types_supported\""));
        assert!(json.contains("\"backchannel_token_delivery_modes_supported\":[\"poll\"]"));
        assert!(!json.contains("\"backchannel_authentication_delivery_modes_supported\""));
        assert!(json.contains("\"acr_values_supported\""));
        assert!(json.contains("\"subject_types_supported\""));
        assert!(json.contains("\"id_token_signing_alg_values_supported\""));
        assert!(json.contains("\"token_endpoint_auth_methods_supported\""));
        assert!(json.contains("\"token_endpoint_auth_signing_alg_values_supported\""));
        assert!(json.contains("\"claims_supported\""));
        assert!(json.contains("\"code_challenge_methods_supported\""));
        // PAR is implemented and advertised.
        assert!(json.contains("\"pushed_authorization_request_endpoint\""));
        assert!(json.contains("\"require_pushed_authorization_requests\":false"));
        // Token exchange (RFC 8693) is implemented and advertised.
        assert!(json.contains("\"urn:ietf:params:oauth:grant-type:token-exchange\""));
        // JAR-by-reference for client-registered URIs is implemented.
        assert!(json.contains("\"request_parameter_supported\":true"));
        assert!(json.contains("\"request_uri_parameter_supported\":true"));
        assert!(json.contains("\"request_object_signing_alg_values_supported\""));
        assert!(json.contains("\"authorization_signing_alg_values_supported\""));
        // Signed userinfo (OIDC Core §5.3.2) is implemented: the advertised
        // list mirrors the id_token list.
        assert!(json.contains("\"userinfo_signing_alg_values_supported\":[\"RS256\"]"));
        // Pairwise subjects are implemented and advertised.
        assert!(json.contains("\"subject_types_supported\":[\"public\",\"pairwise\"]"));
        // Session management (the OP iframe endpoint) is implemented and
        // therefore advertised (OIDC Session Management 1.0 §4.2).
        assert!(json.contains("\"check_session_iframe\""));
        // Registration is implemented but per-realm opt-in — the
        // default (`None`) keeps the metadata out of the document.
        assert!(!json.contains("\"registration_endpoint\""));
        // Back-channel and front-channel logout are implemented and
        // therefore advertised.
        assert!(json.contains("\"backchannel_logout_supported\":true"));
        assert!(json.contains("\"backchannel_logout_session_supported\":true"));
        assert!(json.contains("\"frontchannel_logout_supported\":true"));
        assert!(json.contains("\"frontchannel_logout_session_supported\":true"));
    }

    #[test]
    fn subject_type_serde_and_from_str() {
        assert_eq!(SubjectType::Public.as_str(), "public");
        assert_eq!(SubjectType::Pairwise.as_str(), "pairwise");
        assert_eq!("public".parse::<SubjectType>().unwrap(), SubjectType::Public);
        assert_eq!("pairwise".parse::<SubjectType>().unwrap(), SubjectType::Pairwise);
        assert!("unknown".parse::<SubjectType>().is_err());

        let json = serde_json::to_string(&SubjectType::Public).unwrap();
        assert_eq!(json, "\"public\"");
        let back: SubjectType = serde_json::from_str("\"pairwise\"").unwrap();
        assert_eq!(back, SubjectType::Pairwise);
    }

    #[test]
    fn token_endpoint_auth_method_serde_and_from_str() {
        let variants = [
            (TokenEndpointAuthMethod::ClientSecretPost, "client_secret_post"),
            (TokenEndpointAuthMethod::ClientSecretBasic, "client_secret_basic"),
            (TokenEndpointAuthMethod::ClientSecretJwt, "client_secret_jwt"),
            (TokenEndpointAuthMethod::PrivateKeyJwt, "private_key_jwt"),
            (TokenEndpointAuthMethod::TlsClientAuth, "tls_client_auth"),
            (TokenEndpointAuthMethod::SelfSignedTlsClientAuth, "self_signed_tls_client_auth"),
            (TokenEndpointAuthMethod::None, "none"),
        ];
        for (variant, wire) in variants {
            assert_eq!(variant.as_str(), wire);
            assert_eq!(wire.parse::<TokenEndpointAuthMethod>().unwrap(), variant);
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, format!("\"{}\"", wire));
        }
        assert!("unknown".parse::<TokenEndpointAuthMethod>().is_err());
    }

    #[test]
    fn discovery_response_types_and_modes_match_implementation() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        // Every implemented response type is advertised: the code flow plus
        // the implicit/hybrid combinations (bare `token` is OAuth2-only and
        // stays unadvertised — the authorization endpoint rejects it). The
        // token-first spelling of the implicit pair is the same type
        // advertised twice (OIDCD-3 probes for it).
        assert_eq!(
            d.response_types_supported,
            vec![
                crate::authorization::ResponseType::Code,
                crate::authorization::ResponseType::CodeIdToken,
                crate::authorization::ResponseType::CodeIdTokenToken,
                crate::authorization::ResponseType::CodeToken,
                crate::authorization::ResponseType::IdToken,
                crate::authorization::ResponseType::IdTokenToken,
                crate::authorization::ResponseType::TokenIdToken,
            ]
        );
        // `implicit` is advertised as a grant (OIDCD-3).
        assert!(d.grant_types_supported.contains(&crate::token::GrantType::Implicit));
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"implicit\""));
        assert!(json.contains("\"id_token token\""));
        // The typed list above is authoritative: bare `token` is not in it.
        // form_post and the JARM family are implemented and
        // therefore advertised.
        assert_eq!(
            d.response_modes_supported,
            vec![
                crate::authorization::ResponseMode::Query,
                crate::authorization::ResponseMode::Fragment,
                crate::authorization::ResponseMode::FormPost,
                crate::authorization::ResponseMode::Jwt,
                crate::authorization::ResponseMode::QueryJwt,
                crate::authorization::ResponseMode::FragmentJwt,
                crate::authorization::ResponseMode::FormPostJwt,
            ]
        );
    }

    #[test]
    fn discovery_advertises_jar_truthfully() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        assert!(d.request_parameter_supported);
        // JAR-by-reference for client-registered URIs is implemented.
        assert!(d.request_uri_parameter_supported);
        // The request-object alg list must cover every algorithm the validator
        // accepts (asymmetric against the client JWKS, HMAC with the secret).
        let algs = &d.request_object_signing_alg_values_supported;
        for alg in [
            issuerd_core::Algorithm::Rs256,
            issuerd_core::Algorithm::Rs384,
            issuerd_core::Algorithm::Rs512,
            issuerd_core::Algorithm::Es256,
            issuerd_core::Algorithm::Es384,
            issuerd_core::Algorithm::EdDsa,
            issuerd_core::Algorithm::Hs256,
            issuerd_core::Algorithm::Hs384,
            issuerd_core::Algorithm::Hs512,
        ] {
            assert!(algs.contains(&alg), "missing {alg}");
        }
        // JARM defaults to RS256; the handler overrides per realm.
        assert_eq!(
            d.authorization_signing_alg_values_supported,
            vec![issuerd_core::Algorithm::Rs256]
        );
    }

    #[test]
    fn discovery_advertises_rar_truthfully() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        // RFC 9396 §10: generic mode — the deployment defines no
        // authorization-details types, so the metadata is omitted entirely
        // rather than advertising an empty list (which would falsely claim
        // "no types supported" while any type is in fact accepted).
        assert!(d.authorization_details_types_supported.is_empty());
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("authorization_details_types_supported"));
        // When the deployment pins its types (realm attribute, populated by
        // the server handler), they are advertised verbatim.
        let mut d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        d.authorization_details_types_supported = vec!["payment_initiation".to_string()];
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"authorization_details_types_supported\":[\"payment_initiation\"]"));
    }

    #[test]
    fn discovery_advertises_registration_truthfully() {
        // RFC 7591 §3: registration is per-realm opt-in, so the
        // default document omits the endpoint entirely.
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        assert_eq!(d.registration_endpoint, None);
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("registration_endpoint"));
        // When the realm opted in, the server handler sets the endpoint and
        // it is advertised; deserialization tolerates its absence.
        let mut d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        d.registration_endpoint = Some(
            Url::parse(
                "https://auth.example.com/realms/test-realm/clients-registrations/openid-connect",
            )
            .unwrap(),
        );
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains(
            "\"registration_endpoint\":\"https://auth.example.com/realms/test-realm/clients-registrations/openid-connect\""
        ));
        let back: DiscoveryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.registration_endpoint, d.registration_endpoint);
    }

    #[test]
    fn discovery_scopes_supported_serializes_as_string_array() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        let json = serde_json::to_string(&d).unwrap();
        // Each Scope should serialize as a single string in the array
        assert!(json.contains("\"openid\""));
        assert!(json.contains("\"profile\""));
        // It should NOT contain nested arrays like ["openid"]
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let scopes = parsed["scopes_supported"].as_array().unwrap();
        assert!(scopes.iter().all(|v| v.is_string()));
    }

    #[test]
    fn discovery_claims_supported_serializes_as_string_array() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        let json = serde_json::to_string(&d).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let claims = parsed["claims_supported"].as_array().unwrap();
        assert!(claims.iter().all(|v| v.is_string()));
        assert!(claims.iter().any(|v| v == "sub"));
    }

    #[test]
    fn discovery_acr_values_supported_typed() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        assert_eq!(d.acr_values_supported.len(), 2);
        assert!(d.acr_values_supported.contains(&issuerd_core::Acr::new("1").unwrap()));
    }

    #[test]
    fn discovery_id_token_algs_typed() {
        let d = DiscoveryResponse::for_realm("https://auth.example.com", "test-realm");
        assert_eq!(d.id_token_signing_alg_values_supported, vec![issuerd_core::Algorithm::Rs256]);
    }
}

/// Property-based tests for the discovery wire-name parsers and the
/// `scopes_supported` serde helper.
///
/// `SubjectType` / `TokenEndpointAuthMethod`: a string parses iff it is
/// exactly one variant's `as_str()` wire name, and the documented error for
/// everything else is `Err(())`. Candidates mix exact wire names, generated
/// near-misses (case, padding, NUL, `-` for `_`, JSON quoting, truncation)
/// and arbitrary Unicode. `FromStr` and serde must agree on every input.
///
/// `scope_vec`: scope sets built by `Scope::parse` survive the
/// array-of-space-separated-strings form unchanged, and any array of strings
/// deserializes to its normalized (`Scope::parse`) form.
#[cfg(test)]
mod proptests {
    use std::fmt::Debug;
    use std::str::FromStr;

    use super::*;
    use issuerd_core::Scope;
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;
    use serde::de::DeserializeOwned;

    const SUBJECT_TYPES: &[SubjectType] = &[SubjectType::Public, SubjectType::Pairwise];

    const AUTH_METHODS: &[TokenEndpointAuthMethod] = &[
        TokenEndpointAuthMethod::ClientSecretPost,
        TokenEndpointAuthMethod::ClientSecretBasic,
        TokenEndpointAuthMethod::ClientSecretJwt,
        TokenEndpointAuthMethod::PrivateKeyJwt,
        TokenEndpointAuthMethod::TlsClientAuth,
        TokenEndpointAuthMethod::SelfSignedTlsClientAuth,
        TokenEndpointAuthMethod::None,
    ];

    /// Any Unicode text of 0–64 chars. `any::<String>()` excludes control
    /// characters (`\PC*`), so this builds from `any::<char>()` instead.
    fn arbitrary_text() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<char>(), 0..64).prop_map(|c| c.into_iter().collect())
    }

    /// A wire name altered just enough that it must no longer parse.
    fn near_miss(wire: &str, how: usize) -> String {
        match how {
            0 => wire.to_uppercase(),
            1 => format!("{wire} "),
            2 => format!(" {wire}"),
            3 => format!("{wire}\0"),
            4 => wire.replace('_', "-"),
            5 => format!("\"{wire}\""),
            6 => wire[..wire.len() - 1].to_string(),
            _ => wire[..1].to_uppercase() + &wire[1..],
        }
    }

    /// Exact wire names, near-misses of them, empty, and arbitrary text.
    fn wire_candidate(wire: Vec<&'static str>) -> impl Strategy<Value = String> {
        prop_oneof![
            1 => Just(String::new()),
            2 => prop::sample::select(wire.clone()).prop_map(str::to_string),
            3 => (prop::sample::select(wire), 0..8usize).prop_map(|(w, how)| near_miss(w, how)),
            3 => arbitrary_text(),
        ]
    }

    /// `s` parses iff it is exactly one variant's wire name; otherwise the
    /// error is `Err(())`. Serde deserialization must give the same answer.
    fn assert_parses_exactly_wire_names<T>(
        s: &str,
        all: &[T],
        as_str: fn(&T) -> &'static str,
    ) -> Result<(), TestCaseError>
    where
        T: FromStr<Err = ()> + DeserializeOwned + PartialEq + Debug + Copy,
    {
        let expected = all.iter().copied().find(|v| as_str(v) == s);
        prop_assert_eq!(s.parse::<T>(), expected.ok_or(()));
        let via_serde = serde_json::from_value::<T>(serde_json::Value::String(s.to_string()));
        prop_assert_eq!(via_serde.ok(), expected);
        Ok(())
    }

    /// RFC 6749 §3.3 scope-token characters: `%x21 / %x23-5B / %x5D-7E`.
    fn scope_token() -> impl Strategy<Value = String> {
        "[!#-\\[\\]-~]{1,20}"
    }

    /// ASCII and Unicode whitespace that `Scope::parse` must treat as a separator.
    fn separator() -> impl Strategy<Value = &'static str> {
        prop::sample::select(&[" ", "  ", "\t", "\n", "\r\n", "\u{a0}", "\u{3000}"][..])
    }

    /// A raw scope string: tokens joined by mixed whitespace, or arbitrary text.
    fn raw_scope_string() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => prop::collection::vec((separator(), scope_token()), 0..8)
                .prop_map(|parts| parts.into_iter().map(|(sep, tok)| format!("{sep}{tok}")).collect()),
            1 => arbitrary_text(),
        ]
    }

    fn serialize(scopes: &[Scope]) -> serde_json::Value {
        scope_vec::serialize(scopes, serde_json::value::Serializer).expect("scopes serialize")
    }

    /// Compile-time guard: a new variant breaks these matches until it is
    /// added to `SUBJECT_TYPES` / `AUTH_METHODS` above.
    #[test]
    fn variant_lists_are_exhaustive() {
        for v in SUBJECT_TYPES {
            match v {
                SubjectType::Public | SubjectType::Pairwise => {}
            }
        }
        for v in AUTH_METHODS {
            match v {
                TokenEndpointAuthMethod::ClientSecretPost
                | TokenEndpointAuthMethod::ClientSecretBasic
                | TokenEndpointAuthMethod::ClientSecretJwt
                | TokenEndpointAuthMethod::PrivateKeyJwt
                | TokenEndpointAuthMethod::TlsClientAuth
                | TokenEndpointAuthMethod::SelfSignedTlsClientAuth
                | TokenEndpointAuthMethod::None => {}
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Exactly the two wire names parse; everything else is `Err(())`.
        #[test]
        fn subject_type_parses_exactly_wire_names(
            s in wire_candidate(SUBJECT_TYPES.iter().map(SubjectType::as_str).collect()),
        ) {
            assert_parses_exactly_wire_names(&s, SUBJECT_TYPES, SubjectType::as_str)?;
        }

        /// Exactly the seven wire names parse; everything else is `Err(())`.
        #[test]
        fn token_endpoint_auth_method_parses_exactly_wire_names(
            s in wire_candidate(AUTH_METHODS.iter().map(TokenEndpointAuthMethod::as_str).collect()),
        ) {
            assert_parses_exactly_wire_names(&s, AUTH_METHODS, TokenEndpointAuthMethod::as_str)?;
        }

        /// Normalized scope sets serialize to one space-separated string each
        /// and deserialize back unchanged.
        #[test]
        fn scope_vec_roundtrips(
            raws in prop::collection::vec(raw_scope_string(), 0..6),
        ) {
            let scopes: Vec<Scope> = raws.iter().map(|r| Scope::parse(r)).collect();
            let wire = serialize(&scopes);

            let expected_wire: Vec<serde_json::Value> =
                scopes.iter().map(|s| s.to_space_separated().into()).collect();
            prop_assert_eq!(&wire, &serde_json::Value::Array(expected_wire));

            let back = scope_vec::deserialize(wire).expect("serialized scopes deserialize");
            prop_assert_eq!(back, scopes);
        }

        /// Any array of strings deserializes to its `Scope::parse` form, and
        /// that form is a fixpoint of serialize → deserialize.
        #[test]
        fn scope_vec_deserialize_normalizes_any_strings(
            raws in prop::collection::vec(raw_scope_string(), 0..6),
        ) {
            let input = serde_json::Value::Array(raws.iter().map(|r| r.clone().into()).collect());
            let scopes = scope_vec::deserialize(input).expect("any string array deserializes");
            let expected: Vec<Scope> = raws.iter().map(|r| Scope::parse(r)).collect();
            prop_assert_eq!(&scopes, &expected);

            let again = scope_vec::deserialize(serialize(&scopes)).expect("re-deserializes");
            prop_assert_eq!(again, scopes);
        }
    }
}
