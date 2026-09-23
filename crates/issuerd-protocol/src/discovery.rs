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
    pub device_authorization_endpoint: Url,
    pub backchannel_authentication_endpoint: Url,
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
    /// JAR-by-reference (`request_uri` pointing at an arbitrary URL) is NOT
    /// implemented (PAR URNs are not "by-reference" in this sense) — always
    /// `false`, advertised truthfully.
    pub request_uri_parameter_supported: bool,
    /// Signing algorithms accepted for Request Objects (RFC 9101 §10.2):
    /// asymmetric against the client's JWKS, HMAC with the client secret.
    pub request_object_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
    /// JARM: algorithms the server may use to sign authorization
    /// responses (`response_mode=jwt` family). The server handler overrides
    /// this per request with the active signing algorithms.
    pub authorization_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
    #[serde(with = "scope_vec")]
    pub scopes_supported: Vec<issuerd_core::Scope>,
    pub response_types_supported: Vec<crate::authorization::ResponseType>,
    pub response_modes_supported: Vec<crate::authorization::ResponseMode>,
    pub grant_types_supported: Vec<crate::token::GrantType>,
    pub acr_values_supported: Vec<issuerd_core::Acr>,
    pub subject_types_supported: Vec<SubjectType>,
    pub id_token_signing_alg_values_supported: Vec<issuerd_core::Algorithm>,
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
    pub fn for_realm(base_url: &str, realm: &str) -> Self {
        let issuer =
            Url::parse(&format!("{}/realms/{}", base_url.trim_end_matches('/'), realm)).unwrap();
        Self {
            authorization_endpoint: Url::parse(&format!("{}/protocol/openid-connect/auth", issuer))
                .unwrap(),
            token_endpoint: Url::parse(&format!("{}/protocol/openid-connect/token", issuer))
                .unwrap(),
            userinfo_endpoint: Url::parse(&format!("{}/protocol/openid-connect/userinfo", issuer))
                .unwrap(),
            jwks_uri: Url::parse(&format!("{}/protocol/openid-connect/certs", issuer)).unwrap(),
            introspection_endpoint: Url::parse(&format!(
                "{}/protocol/openid-connect/token/introspect",
                issuer
            ))
            .unwrap(),
            revocation_endpoint: Url::parse(&format!("{}/protocol/openid-connect/revoke", issuer))
                .unwrap(),
            end_session_endpoint: Url::parse(&format!("{}/protocol/openid-connect/logout", issuer))
                .unwrap(),
            device_authorization_endpoint: Url::parse(&format!(
                "{}/protocol/openid-connect/auth/device",
                issuer
            ))
            .unwrap(),
            backchannel_authentication_endpoint: Url::parse(&format!(
                "{}/protocol/openid-connect/ext/ciba/auth",
                issuer
            ))
            .unwrap(),
            pushed_authorization_request_endpoint: Url::parse(&format!(
                "{}/protocol/openid-connect/ext/par",
                issuer
            ))
            .unwrap(),
            // Set per realm by the server handler only when the
            // realm enables dynamic client registration.
            registration_endpoint: None,
            require_pushed_authorization_requests: false,
            // JAR (signed request objects) is implemented;
            // JAR-by-reference from arbitrary URLs is not.
            request_parameter_supported: true,
            request_uri_parameter_supported: false,
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
                crate::authorization::ResponseType::Code,
                crate::authorization::ResponseType::IdToken,
                crate::authorization::ResponseType::CodeIdToken,
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
            token_endpoint_auth_methods_supported: vec![
                TokenEndpointAuthMethod::ClientSecretPost,
                TokenEndpointAuthMethod::ClientSecretBasic,
                // JWT client assertions are implemented.
                TokenEndpointAuthMethod::ClientSecretJwt,
                TokenEndpointAuthMethod::PrivateKeyJwt,
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
            // DPoP proofs are asymmetric-only (the accept set of
            // `issuerd_token::dpop::validate_dpop_proof`; keep in sync).
            dpop_signing_alg_values_supported: vec![
                issuerd_core::Algorithm::Rs256,
                issuerd_core::Algorithm::Rs384,
                issuerd_core::Algorithm::Rs512,
                issuerd_core::Algorithm::Es256,
                issuerd_core::Algorithm::Es384,
                issuerd_core::Algorithm::EdDsa,
            ],
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
        // JAR-by-reference is not implemented — advertised truthfully as
        // `false` (JAR via the `request` parameter IS implemented).
        assert!(json.contains("\"request_parameter_supported\":true"));
        assert!(json.contains("\"request_uri_parameter_supported\":false"));
        assert!(json.contains("\"request_object_signing_alg_values_supported\""));
        assert!(json.contains("\"authorization_signing_alg_values_supported\""));
        // Pairwise subjects are implemented and advertised.
        assert!(json.contains("\"subject_types_supported\":[\"public\",\"pairwise\"]"));
        // Unimplemented features must NOT be advertised (truthful discovery).
        assert!(!json.contains("\"check_session_iframe\""));
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
        // Only implemented response types are advertised.
        assert_eq!(
            d.response_types_supported,
            vec![
                crate::authorization::ResponseType::Code,
                crate::authorization::ResponseType::IdToken,
                crate::authorization::ResponseType::CodeIdToken,
            ]
        );
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
        assert!(!d.request_uri_parameter_supported);
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
