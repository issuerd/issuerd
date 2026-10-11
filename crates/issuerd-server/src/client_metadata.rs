// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! RFC 7591/7592 client-metadata attribute keys and typed accessors.
//!
//! OIDC/OAuth2 client-metadata fields that have no first-class column in the
//! [`Client`] model ride in its `attributes` map under the RFC's snake_case
//! names — the pre-existing convention of the `backchannel_logout_uri` /
//! `frontchannel_logout_uri` keys (`crate::routes::logout`). They are
//! written by the dynamic-client-registration translation layer
//! (`crate::routes::client_registration`), settable through the Admin
//! API's generic client-attributes channel, and read back for the RFC 7592
//! registration responses and by the logout endpoints.
//!
//! Two internal bookkeeping keys use the `dcr.` prefix so they can never
//! collide with a metadata field a client could register: `dcr.grant_types`
//! (the registered grant-type list) and `dcr.client_id_issued_at` (unix
//! seconds, stamped once at DCR creation).

use issuerd_core::Client;

/// RFC 7591 + OIDC RP-Initiated Logout: the per-client list of approved
/// post-logout redirect targets, stored as one JSON array of URI strings.
/// When present and non-empty, RP-initiated logout validates
/// `post_logout_redirect_uri` against THIS list; when absent/empty the
/// logout endpoint falls back to the client's `redirect_uris` (the
/// pre-existing behavior).
pub const ATTR_POST_LOGOUT_REDIRECT_URIS: &str = "post_logout_redirect_uris";

/// OIDC Third-Party-Initiated Login: the RP's login-initiation URL
/// (registration bookkeeping; issuerd never calls it).
pub const ATTR_INITIATE_LOGIN_URI: &str = "initiate_login_uri";

/// OIDC Front-Channel Logout 1.0: `"true"`/`"false"`; when `"false"` the
/// front-channel iframe URL is called WITHOUT the `iss`/`sid` query
/// parameters. Default (attribute absent) is `true` — the historical
/// always-append behavior.
pub const ATTR_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED: &str = "frontchannel_logout_session_required";

/// OIDC Back-Channel Logout 1.0: `"true"`/`"false"`; when `"false"` the
/// logout token omits the `sid` claim and correlates the session by `sub`
/// alone. Default (attribute absent) is `true`.
pub const ATTR_BACKCHANNEL_LOGOUT_SESSION_REQUIRED: &str = "backchannel_logout_session_required";

/// RFC 7591: the client's pinned token-endpoint authentication method
/// (`client_secret_basic`, `client_secret_post`, `client_secret_jwt`,
/// `private_key_jwt`, `none`).
pub const ATTR_TOKEN_ENDPOINT_AUTH_METHOD: &str = "token_endpoint_auth_method";

/// RFC 7591 (OIDC registration): the JWS algorithm the client wants its ID
/// tokens signed with. ID-token issuance honors it (strict: the keyset must
/// have an active key for it — never a silent fallback). The constant is the
/// `issuerd_core` one — `issuerd_token` reads the attribute directly.
pub const ATTR_ID_TOKEN_SIGNED_RESPONSE_ALG: &str =
    issuerd_core::Client::ID_TOKEN_SIGNED_RESPONSE_ALG_ATTRIBUTE;

/// RFC 7591 (OIDC registration): the JWS algorithm the client wants userinfo
/// responses signed with. When set, userinfo answers with a signed JWT
/// (`application/jwt`). The constant is the `issuerd_core` one.
pub const ATTR_USERINFO_SIGNED_RESPONSE_ALG: &str =
    issuerd_core::Client::USERINFO_SIGNED_RESPONSE_ALG_ATTRIBUTE;

/// RFC 7591: URL of the client's logo (https only at registration).
pub const ATTR_LOGO_URI: &str = "logo_uri";

/// RFC 7591: URL of the client's data-protection policy (https only).
pub const ATTR_POLICY_URI: &str = "policy_uri";

/// RFC 7591: URL of the client's terms of service (https only).
pub const ATTR_TOS_URI: &str = "tos_uri";

/// OIDC registration: the client's pre-registered `request_uri` values
/// (JAR-by-reference, OIDC Core §6.2), stored as a JSON array of URI
/// strings. The authorization endpoint only ever fetches URIs on this list
/// (exact string match).
pub const ATTR_REQUEST_URIS: &str = "request_uris";

/// OIDC registration: the JWS algorithm the client's Request Objects must be
/// signed with (`request_object_signing_alg`). Stored and echoed.
pub const ATTR_REQUEST_OBJECT_SIGNING_ALG: &str = "request_object_signing_alg";

/// Registration bookkeeping (not an RFC field): the `grant_types` list the
/// client registered, stored as a JSON array of strings.
pub const ATTR_DCR_GRANT_TYPES: &str = "dcr.grant_types";
/// Registration bookkeeping (not an RFC field): unix seconds at which the
/// client identifier was issued via dynamic registration. Stamped once at
/// creation and carried across RFC 7592 updates.
pub const ATTR_DCR_CLIENT_ID_ISSUED_AT: &str = "dcr.client_id_issued_at";

/// A non-empty attribute value, borrowed.
fn attribute<'a>(client: &'a Client, key: &str) -> Option<&'a str> {
    client.attributes.get(key).map(String::as_str).filter(|s| !s.is_empty())
}

/// Parse a JSON-array-of-strings attribute value; a single bare string is
/// tolerated as a one-element list (admin-set values). Anything else —
/// including the empty string — yields an empty list.
pub fn parse_string_list(raw: &str) -> Vec<String> {
    match serde_json::from_str::<Vec<String>>(raw) {
        Ok(list) => list,
        Err(_) if raw.is_empty() => Vec::new(),
        Err(_) => vec![raw.to_string()],
    }
}

/// The registered post-logout redirect URIs (empty when unset).
pub fn post_logout_redirect_uris(client: &Client) -> Vec<String> {
    attribute(client, ATTR_POST_LOGOUT_REDIRECT_URIS)
        .map(parse_string_list)
        .unwrap_or_default()
}

/// The registered `initiate_login_uri`, when set.
pub fn initiate_login_uri(client: &Client) -> Option<&str> {
    attribute(client, ATTR_INITIATE_LOGIN_URI)
}

/// Whether front-channel logout iframes for this client carry `iss`/`sid`
/// (default `true` when the attribute is absent).
pub fn frontchannel_logout_session_required(client: &Client) -> bool {
    client
        .attributes
        .get(ATTR_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED)
        .map(String::as_str)
        != Some("false")
}

/// Whether back-channel logout tokens for this client carry the `sid` claim
/// (default `true` when the attribute is absent).
pub fn backchannel_logout_session_required(client: &Client) -> bool {
    client
        .attributes
        .get(ATTR_BACKCHANNEL_LOGOUT_SESSION_REQUIRED)
        .map(String::as_str)
        != Some("false")
}

/// The registered `token_endpoint_auth_method`, when set.
pub fn token_endpoint_auth_method(client: &Client) -> Option<&str> {
    attribute(client, ATTR_TOKEN_ENDPOINT_AUTH_METHOD)
}

/// The registered `id_token_signed_response_alg`, when set.
pub fn id_token_signed_response_alg(client: &Client) -> Option<&str> {
    attribute(client, ATTR_ID_TOKEN_SIGNED_RESPONSE_ALG)
}

/// The registered `userinfo_signed_response_alg`, when set.
pub fn userinfo_signed_response_alg(client: &Client) -> Option<&str> {
    attribute(client, ATTR_USERINFO_SIGNED_RESPONSE_ALG)
}

/// The registered `logo_uri`, when set.
pub fn logo_uri(client: &Client) -> Option<&str> {
    attribute(client, ATTR_LOGO_URI)
}

/// The registered `policy_uri`, when set.
pub fn policy_uri(client: &Client) -> Option<&str> {
    attribute(client, ATTR_POLICY_URI)
}

/// The registered `tos_uri`, when set.
pub fn tos_uri(client: &Client) -> Option<&str> {
    attribute(client, ATTR_TOS_URI)
}

/// The client's pre-registered `request_uri` list (empty when unset).
pub fn request_uris(client: &Client) -> Vec<String> {
    attribute(client, ATTR_REQUEST_URIS).map(parse_string_list).unwrap_or_default()
}

/// The registered `request_object_signing_alg`, when set.
pub fn request_object_signing_alg(client: &Client) -> Option<&str> {
    attribute(client, ATTR_REQUEST_OBJECT_SIGNING_ALG)
}

/// The grant types the client registered (`dcr.grant_types`), `None` when
/// absent.
pub fn dcr_grant_types(client: &Client) -> Option<Vec<String>> {
    attribute(client, ATTR_DCR_GRANT_TYPES).map(parse_string_list)
}

/// The unix-seconds DCR creation stamp, `None` when absent or unparseable.
pub fn dcr_client_id_issued_at(client: &Client) -> Option<i64> {
    attribute(client, ATTR_DCR_CLIENT_ID_ISSUED_AT)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{
        ClientAuthenticatorType, ClientId, ClientIdentifier, ClientProtocol, RealmId, Scope,
    };
    use std::collections::HashMap;

    fn client_with(attributes: &[(&str, &str)]) -> Client {
        Client {
            id: ClientId::new("client-uuid").unwrap(),
            realm_id: RealmId::new("realm").unwrap(),
            client_id: ClientIdentifier::new("my-app").unwrap(),
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
            attributes: attributes
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn parse_string_list_accepts_json_array_and_bare_string() {
        assert_eq!(
            parse_string_list("[\"https://a.example.com/x\", \"https://b.example.com/y\"]"),
            vec![
                "https://a.example.com/x".to_string(),
                "https://b.example.com/y".to_string()
            ]
        );
        // A single bare string (how an admin would type it) is one entry.
        assert_eq!(
            parse_string_list("https://a.example.com/x"),
            vec!["https://a.example.com/x".to_string()]
        );
        assert_eq!(parse_string_list("[]"), Vec::<String>::new());
        assert_eq!(parse_string_list(""), Vec::<String>::new());
    }

    #[test]
    fn post_logout_redirect_uris_accessor() {
        assert!(post_logout_redirect_uris(&client_with(&[])).is_empty());
        let client =
            client_with(&[(ATTR_POST_LOGOUT_REDIRECT_URIS, "[\"https://app.example.com/done\"]")]);
        assert_eq!(post_logout_redirect_uris(&client), vec!["https://app.example.com/done"]);
    }

    #[test]
    fn session_required_flags_default_true_and_honor_false() {
        let unset = client_with(&[]);
        assert!(frontchannel_logout_session_required(&unset));
        assert!(backchannel_logout_session_required(&unset));

        let explicit_true = client_with(&[
            (ATTR_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED, "true"),
            (ATTR_BACKCHANNEL_LOGOUT_SESSION_REQUIRED, "true"),
        ]);
        assert!(frontchannel_logout_session_required(&explicit_true));
        assert!(backchannel_logout_session_required(&explicit_true));

        let explicit_false = client_with(&[
            (ATTR_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED, "false"),
            (ATTR_BACKCHANNEL_LOGOUT_SESSION_REQUIRED, "false"),
        ]);
        assert!(!frontchannel_logout_session_required(&explicit_false));
        assert!(!backchannel_logout_session_required(&explicit_false));
    }

    #[test]
    fn scalar_accessors() {
        let client = client_with(&[
            (ATTR_INITIATE_LOGIN_URI, "https://app.example.com/login"),
            (ATTR_TOKEN_ENDPOINT_AUTH_METHOD, "private_key_jwt"),
            (ATTR_ID_TOKEN_SIGNED_RESPONSE_ALG, "ES256"),
            (ATTR_USERINFO_SIGNED_RESPONSE_ALG, "RS256"),
            (ATTR_LOGO_URI, "https://app.example.com/logo.png"),
            (ATTR_POLICY_URI, "https://app.example.com/policy"),
            (ATTR_TOS_URI, "https://app.example.com/tos"),
        ]);
        assert_eq!(initiate_login_uri(&client), Some("https://app.example.com/login"));
        assert_eq!(token_endpoint_auth_method(&client), Some("private_key_jwt"));
        assert_eq!(id_token_signed_response_alg(&client), Some("ES256"));
        assert_eq!(userinfo_signed_response_alg(&client), Some("RS256"));
        assert_eq!(logo_uri(&client), Some("https://app.example.com/logo.png"));
        assert_eq!(policy_uri(&client), Some("https://app.example.com/policy"));
        assert_eq!(tos_uri(&client), Some("https://app.example.com/tos"));

        let unset = client_with(&[]);
        assert_eq!(initiate_login_uri(&unset), None);
        assert_eq!(token_endpoint_auth_method(&unset), None);
        assert_eq!(id_token_signed_response_alg(&unset), None);
        assert_eq!(userinfo_signed_response_alg(&unset), None);
        assert_eq!(logo_uri(&unset), None);
        assert_eq!(policy_uri(&unset), None);
        assert_eq!(tos_uri(&unset), None);
    }

    #[test]
    fn dcr_bookkeeping_accessors() {
        let client = client_with(&[
            (ATTR_DCR_GRANT_TYPES, "[\"authorization_code\", \"refresh_token\"]"),
            (ATTR_DCR_CLIENT_ID_ISSUED_AT, "1759000000"),
        ]);
        assert_eq!(
            dcr_grant_types(&client),
            Some(vec![
                "authorization_code".to_string(),
                "refresh_token".to_string()
            ])
        );
        assert_eq!(dcr_client_id_issued_at(&client), Some(1759000000));

        let unset = client_with(&[]);
        assert_eq!(dcr_grant_types(&unset), None);
        assert_eq!(dcr_client_id_issued_at(&unset), None);

        let garbage = client_with(&[(ATTR_DCR_CLIENT_ID_ISSUED_AT, "not-a-number")]);
        assert_eq!(dcr_client_id_issued_at(&garbage), None);
    }
}
