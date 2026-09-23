// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// OAuth2/OIDC authorization endpoint request parsing and validation.

use std::collections::HashMap;

use issuerd_core::{
    Base64Url, Client, ClientIdentifier, IssuerdError, Nonce, PkceCodeChallengeMethod, Realm, Scope,
};
use serde::{Deserialize, Serialize};

use crate::utils::{parse_opt_u64, parse_required_url, parse_scope, parse_space_separated};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub response_type: ResponseType,
    pub client_id: ClientIdentifier,
    pub redirect_uri: url::Url,
    pub scope: Scope,
    pub state: Option<String>,
    pub nonce: Option<Nonce>,
    /// Explicitly requested `response_mode`; `None` = not requested (the spec
    /// default for the response type applies: query for code, fragment for
    /// implicit/hybrid).
    pub response_mode: Option<ResponseMode>,
    pub prompt: Vec<Prompt>,
    pub max_age: Option<u64>,
    pub code_challenge: Option<Base64Url>,
    pub code_challenge_method: Option<PkceCodeChallengeMethod>,
    pub login_hint: Option<String>,
    pub id_token_hint: Option<String>,
    pub acr_values: Vec<String>,
    pub ui_locales: Vec<String>,
    pub claims: Option<serde_json::Value>,
    /// RAR authorization details (RFC 9396 §2): the parsed JSON
    /// array, structurally validated (every element is an object with a
    /// non-empty string `type`). Type values are extensible; no type-specific
    /// semantics are evaluated.
    pub authorization_details: Option<Vec<serde_json::Value>>,
    /// Issuerd-specific hint (`registration=true`): when the realm allows
    /// self-registration and the request would render the login page, the
    /// authorize endpoint redirects to the registration form instead, and the
    /// paused login flow resumes after the account is created. Any other value
    /// (or absence) parses to `false` — additive and ignored unless exactly
    /// `true`.
    pub registration: bool,
    pub request: Option<String>,
    pub request_uri: Option<String>,
}

impl AuthorizationRequest {
    /// Parse an OIDC authorization request from a parameter map.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use issuerd_protocol::authorization::AuthorizationRequest;
    ///
    /// let mut params = HashMap::new();
    /// params.insert("response_type".to_string(), "code".to_string());
    /// params.insert("client_id".to_string(), "my-app".to_string());
    /// params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
    /// params.insert("scope".to_string(), "openid profile".to_string());
    ///
    /// let req = AuthorizationRequest::parse(&params).unwrap();
    /// assert_eq!(req.client_id, "my-app");
    /// assert_eq!(req.scope, issuerd_core::Scope::parse("openid profile"));
    /// ```
    pub fn parse(params: &HashMap<String, String>) -> Result<Self, IssuerdError> {
        let response_type = params
            .get("response_type")
            .ok_or_else(|| IssuerdError::InvalidRequest("missing response_type".into()))?
            .parse()
            .map_err(|_| IssuerdError::InvalidRequest("unsupported response_type".into()))?;

        let client_id = params
            .get("client_id")
            .ok_or_else(|| IssuerdError::InvalidRequest("missing client_id".into()))?
            .as_str()
            .try_into()?;

        let redirect_uri = parse_required_url(params, "redirect_uri")?;

        let scope = parse_scope(params.get("scope"));

        let response_mode = params
            .get("response_mode")
            .map(|s| s.parse())
            .transpose()
            .map_err(|_| IssuerdError::InvalidRequest("unsupported response_mode".into()))?;

        let prompt = parse_prompt(params.get("prompt"))?;

        let max_age = parse_opt_u64(params, "max_age")?;

        let claims = params
            .get("claims")
            .map(|s| serde_json::from_str(s))
            .transpose()
            .map_err(|_| IssuerdError::InvalidRequest("invalid claims JSON".into()))?;

        let authorization_details =
            parse_authorization_details(params.get("authorization_details"))?;

        // JAR (RFC 9101): a `request`/`request_uri` parameter
        // never reaches plain parsing — the server validates the signed
        // request object (or resolves the PAR reference) BEFORE this point
        // and re-parses the extracted claims. Seeing either here means the
        // extraction layer was skipped, so reject defensively (JAR-by-
        // reference from arbitrary URLs is not implemented at all).
        if params.contains_key("request") || params.contains_key("request_uri") {
            return Err(IssuerdError::RequestNotSupported);
        }

        Ok(Self {
            response_type,
            client_id,
            redirect_uri,
            scope,
            state: params.get("state").cloned(),
            nonce: params.get("nonce").map(|s| Nonce::new(s.clone())).transpose()?,
            response_mode,
            prompt,
            max_age,
            code_challenge: params
                .get("code_challenge")
                .map(|s| Base64Url::new(s.clone()))
                .transpose()?,
            code_challenge_method: params
                .get("code_challenge_method")
                .map(|s| {
                    serde_json::from_value(serde_json::Value::String(s.clone())).map_err(|e| {
                        IssuerdError::InvalidRequest(format!("invalid code_challenge_method: {e}"))
                    })
                })
                .transpose()?,
            login_hint: params.get("login_hint").cloned(),
            id_token_hint: params.get("id_token_hint").cloned(),
            acr_values: parse_space_separated(params.get("acr_values")),
            ui_locales: parse_space_separated(params.get("ui_locales")),
            claims,
            authorization_details,
            registration: params.get("registration").is_some_and(|v| v == "true"),
            request: params.get("request").cloned(),
            request_uri: params.get("request_uri").cloned(),
        })
    }

    pub fn validate(&self, realm: &Realm, client: &Client) -> Result<(), IssuerdError> {
        // Redirect URI: Keycloak-compatible match (exact, or trailing-`*`
        // wildcard prefix) and no fragment
        if !client.redirect_uris.iter().any(|r| r.matches(self.redirect_uri.as_str())) {
            return Err(IssuerdError::InvalidRequest("redirect_uri not registered".into()));
        }
        if self.redirect_uri.fragment().is_some() {
            return Err(IssuerdError::InvalidRequest(
                "redirect_uri must not contain a fragment".into(),
            ));
        }

        // Response type check against client attributes
        let allowed = client
            .attributes
            .get("response_types")
            .map(|s| s.split_whitespace().collect::<Vec<_>>())
            .unwrap_or_else(|| {
                vec![
                    "code",
                    "id_token",
                    "token",
                    "code id_token",
                    "code token",
                    "id_token token",
                    "code id_token token",
                ]
            });
        if !allowed.contains(&self.response_type.as_str()) {
            return Err(IssuerdError::InvalidRequest(
                "response_type not allowed for client".into(),
            ));
        }

        // Scope: intersect with client's available scopes
        let available_scopes: std::collections::HashSet<String> = client
            .default_scopes
            .iter()
            .chain(client.optional_scopes.iter())
            .cloned()
            .collect();

        for scope in &self.scope {
            if !available_scopes.contains(scope) {
                return Err(IssuerdError::InvalidScope);
            }
        }

        // If response_type includes id_token, openid must be present
        if self.response_type.has_id_token() && !self.scope.contains("openid") {
            return Err(IssuerdError::InvalidRequest(
                "openid scope required for id_token response_type".into(),
            ));
        }

        // PKCE: required for public clients when response_type includes code
        if client.public_client && self.response_type.has_code() && self.code_challenge.is_none() {
            return Err(IssuerdError::InvalidRequest(
                "code_challenge required for public clients".into(),
            ));
        }

        // Prompt: if None is present, no other prompts allowed (defensive check)
        if self.prompt.contains(&Prompt::None) && self.prompt.len() > 1 {
            return Err(IssuerdError::InvalidRequest(
                "prompt 'none' must be the only prompt value".into(),
            ));
        }

        // Max age: if present, must be > 0
        if let Some(max_age) = self.max_age {
            if max_age == 0 {
                return Err(IssuerdError::InvalidRequest("max_age must be > 0".into()));
            }
        }

        // RAR (RFC 9396 §5): when the realm pins its supported
        // authorization-details types (`authorization_details_types`
        // attribute), every requested type must be listed. Without the
        // attribute any type is accepted — types are extensible (§2.1).
        if let (Some(supported), Some(details)) =
            (realm.authorization_details_types(), &self.authorization_details)
        {
            let unknown = details
                .iter()
                .filter_map(|d| d.get("type").and_then(|t| t.as_str()))
                .find(|t| !supported.iter().any(|s| s == t));
            if let Some(t) = unknown {
                return Err(IssuerdError::InvalidAuthorizationDetails(format!(
                    "authorization details type \"{t}\" is not supported by this realm"
                )));
            }
        }

        Ok(())
    }
}

/// Parse and structurally validate the RAR `authorization_details` parameter
/// (RFC 9396 §2).
///
/// The value must be a JSON array whose elements are objects each carrying a
/// non-empty string `type` member. Types are extensible (§2.1) — no type
/// registry is consulted here; a realm may pin an allowlist via its
/// `authorization_details_types` attribute, enforced in
/// [`AuthorizationRequest::validate`]. All other element members are
/// type-specific and pass through untouched.
///
/// Shared by the authorization endpoint ([`AuthorizationRequest::parse`]) and
/// the token endpoint (`TokenRequest::parse`, RFC 9396 §6).
pub fn parse_authorization_details(
    raw: Option<&String>,
) -> Result<Option<Vec<serde_json::Value>>, IssuerdError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|_| IssuerdError::InvalidAuthorizationDetails("not valid JSON".into()))?;
    let serde_json::Value::Array(elements) = value else {
        return Err(IssuerdError::InvalidAuthorizationDetails("must be a JSON array".into()));
    };
    for element in &elements {
        let valid = element.get("type").and_then(|t| t.as_str()).is_some_and(|t| !t.is_empty());
        if !valid {
            return Err(IssuerdError::InvalidAuthorizationDetails(
                "every element must be an object with a non-empty string \"type\"".into(),
            ));
        }
    }
    Ok(Some(elements))
}

/// Conservative RAR narrowing check (RFC 9396 §6.1): every
/// requested element must be present verbatim in the granted set.
///
/// The RFC leaves comparison semantics to each authorization-details type;
/// without type-specific logic, exact JSON equality is the only safe rule.
/// A restricted-field narrowing that would be legitimate for a specific type
/// is rejected — documented in `tests/KEYCLOAK_DIFFS.md`.
pub fn authorization_details_is_subset(
    requested: &[serde_json::Value],
    granted: &[serde_json::Value],
) -> bool {
    requested.iter().all(|r| granted.contains(r))
}

fn parse_prompt(value: Option<&String>) -> Result<Vec<Prompt>, IssuerdError> {
    let prompts = parse_space_separated(value);
    if prompts.is_empty() {
        return Ok(Vec::new());
    }

    let parsed: Vec<Prompt> = prompts
        .iter()
        .map(|s| match s.as_str() {
            "none" => Ok(Prompt::None),
            "login" => Ok(Prompt::Login),
            "consent" => Ok(Prompt::Consent),
            "select_account" => Ok(Prompt::SelectAccount),
            _ => Err(IssuerdError::InvalidRequest(format!("invalid prompt: {}", s))),
        })
        .collect::<Result<Vec<_>, _>>()?;

    if parsed.contains(&Prompt::None) && parsed.len() > 1 {
        return Err(IssuerdError::InvalidRequest(
            "prompt 'none' must be the only prompt value".into(),
        ));
    }

    Ok(parsed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    #[serde(rename = "query")]
    Query,
    #[serde(rename = "fragment")]
    Fragment,
    #[serde(rename = "form_post")]
    FormPost,
    /// JARM (JWT Secured Authorization Response Mode): `jwt`
    /// resolves to the response type's default mode, JARM-wrapped.
    #[serde(rename = "jwt")]
    Jwt,
    #[serde(rename = "query.jwt")]
    QueryJwt,
    #[serde(rename = "fragment.jwt")]
    FragmentJwt,
    #[serde(rename = "form_post.jwt")]
    FormPostJwt,
}

impl ResponseMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseMode::Query => "query",
            ResponseMode::Fragment => "fragment",
            ResponseMode::FormPost => "form_post",
            ResponseMode::Jwt => "jwt",
            ResponseMode::QueryJwt => "query.jwt",
            ResponseMode::FragmentJwt => "fragment.jwt",
            ResponseMode::FormPostJwt => "form_post.jwt",
        }
    }

    /// Whether the authorization response is packaged as a JARM JWT
    /// (a single `response` parameter) for this mode.
    pub fn is_jwt_secured(&self) -> bool {
        matches!(
            self,
            ResponseMode::Jwt
                | ResponseMode::QueryJwt
                | ResponseMode::FragmentJwt
                | ResponseMode::FormPostJwt
        )
    }
}

impl std::str::FromStr for ResponseMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "query" => Ok(ResponseMode::Query),
            "fragment" => Ok(ResponseMode::Fragment),
            "form_post" => Ok(ResponseMode::FormPost),
            "jwt" => Ok(ResponseMode::Jwt),
            "query.jwt" => Ok(ResponseMode::QueryJwt),
            "fragment.jwt" => Ok(ResponseMode::FragmentJwt),
            "form_post.jwt" => Ok(ResponseMode::FormPostJwt),
            _ => Err(()),
        }
    }
}

/// JWT envelope claims that must never become authorization parameters when a
/// Request Object's claims are converted into the parameter map (RFC 9101 §4).
const REQUEST_OBJECT_ENVELOPE_CLAIMS: [&str; 6] = ["iss", "aud", "exp", "nbf", "iat", "jti"];

/// Convert the claims of a *validated* Request Object (RFC 9101 §4)
/// into the parameter map [`AuthorizationRequest::parse`] consumes.
///
/// This is a pure shape conversion — the caller (issuerd-server) has already
/// verified the JWT signature and the envelope claims. Values arrive as JSON:
/// strings pass through, numbers/bools are stringified, arrays/objects (e.g.
/// a nested `claims` parameter) are re-serialized compactly, nulls and the
/// JWT envelope claims (`iss`/`aud`/`exp`/`nbf`/`iat`/`jti`) are dropped.
pub fn request_object_claims_to_params(
    claims: &serde_json::Map<String, serde_json::Value>,
) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for (name, value) in claims {
        if REQUEST_OBJECT_ENVELOPE_CLAIMS.contains(&name.as_str()) {
            continue;
        }
        let v = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Null => continue,
            // Serialization of a parsed JSON value cannot fail.
            other => serde_json::to_string(other).expect("JSON re-serialization"),
        };
        params.insert(name.clone(), v);
    }
    params
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    #[serde(rename = "code")]
    Code,
    #[serde(rename = "token")]
    Token,
    #[serde(rename = "id_token")]
    IdToken,
    #[serde(rename = "code id_token")]
    CodeIdToken,
    #[serde(rename = "code token")]
    CodeToken,
    #[serde(rename = "id_token token")]
    IdTokenToken,
    #[serde(rename = "code id_token token")]
    CodeIdTokenToken,
}

impl ResponseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseType::Code => "code",
            ResponseType::Token => "token",
            ResponseType::IdToken => "id_token",
            ResponseType::CodeIdToken => "code id_token",
            ResponseType::CodeToken => "code token",
            ResponseType::IdTokenToken => "id_token token",
            ResponseType::CodeIdTokenToken => "code id_token token",
        }
    }

    pub fn has_code(&self) -> bool {
        matches!(
            self,
            ResponseType::Code
                | ResponseType::CodeIdToken
                | ResponseType::CodeToken
                | ResponseType::CodeIdTokenToken
        )
    }

    pub fn has_token(&self) -> bool {
        matches!(
            self,
            ResponseType::Token
                | ResponseType::CodeToken
                | ResponseType::IdTokenToken
                | ResponseType::CodeIdTokenToken
        )
    }

    pub fn has_id_token(&self) -> bool {
        matches!(
            self,
            ResponseType::IdToken
                | ResponseType::CodeIdToken
                | ResponseType::IdTokenToken
                | ResponseType::CodeIdTokenToken
        )
    }
}

impl std::str::FromStr for ResponseType {
    type Err = IssuerdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "code" => Ok(ResponseType::Code),
            "id_token" => Ok(ResponseType::IdToken),
            "token" => Ok(ResponseType::Token),
            "code id_token" => Ok(ResponseType::CodeIdToken),
            "code token" => Ok(ResponseType::CodeToken),
            "id_token token" => Ok(ResponseType::IdTokenToken),
            "code id_token token" => Ok(ResponseType::CodeIdTokenToken),
            _ => Err(IssuerdError::InvalidRequest("unsupported response_type".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::{
        ClientAuthenticatorType, ClientProtocol, PkceCodeChallengeMethod, RedirectUri,
    };
    use rstest::rstest;

    use std::str::FromStr;

    #[rstest]
    #[case("code", ResponseType::Code)]
    #[case("id_token", ResponseType::IdToken)]
    #[case("token", ResponseType::Token)]
    #[case("code id_token", ResponseType::CodeIdToken)]
    #[case("code token", ResponseType::CodeToken)]
    #[case("id_token token", ResponseType::IdTokenToken)]
    #[case("code id_token token", ResponseType::CodeIdTokenToken)]
    fn response_type_parsing(#[case] input: &str, #[case] expected: ResponseType) {
        assert_eq!(ResponseType::from_str(input).unwrap(), expected);
    }

    #[test]
    fn response_type_invalid_rejection() {
        assert!(ResponseType::from_str("unknown").is_err());
    }

    #[rstest]
    #[case(ResponseType::Code, "code")]
    #[case(ResponseType::Token, "token")]
    #[case(ResponseType::IdToken, "id_token")]
    #[case(ResponseType::CodeIdToken, "code id_token")]
    #[case(ResponseType::CodeToken, "code token")]
    #[case(ResponseType::IdTokenToken, "id_token token")]
    #[case(ResponseType::CodeIdTokenToken, "code id_token token")]
    fn response_type_as_str(#[case] rt: ResponseType, #[case] expected: &str) {
        assert_eq!(rt.as_str(), expected);
    }

    #[test]
    fn response_type_has_flags() {
        assert!(ResponseType::Code.has_code());
        assert!(!ResponseType::Code.has_token());
        assert!(!ResponseType::Code.has_id_token());

        assert!(ResponseType::CodeIdTokenToken.has_code());
        assert!(ResponseType::CodeIdTokenToken.has_token());
        assert!(ResponseType::CodeIdTokenToken.has_id_token());
    }

    #[rstest]
    #[case("query", ResponseMode::Query)]
    #[case("fragment", ResponseMode::Fragment)]
    #[case("form_post", ResponseMode::FormPost)]
    #[case("jwt", ResponseMode::Jwt)]
    #[case("query.jwt", ResponseMode::QueryJwt)]
    #[case("fragment.jwt", ResponseMode::FragmentJwt)]
    #[case("form_post.jwt", ResponseMode::FormPostJwt)]
    fn response_mode_parsing(#[case] input: &str, #[case] expected: ResponseMode) {
        assert_eq!(input.parse::<ResponseMode>().unwrap(), expected);
    }

    #[test]
    fn response_mode_invalid_rejection() {
        assert!("unknown".parse::<ResponseMode>().is_err());
    }

    #[rstest]
    #[case(ResponseMode::Query, "query")]
    #[case(ResponseMode::Fragment, "fragment")]
    #[case(ResponseMode::FormPost, "form_post")]
    #[case(ResponseMode::Jwt, "jwt")]
    #[case(ResponseMode::QueryJwt, "query.jwt")]
    #[case(ResponseMode::FragmentJwt, "fragment.jwt")]
    #[case(ResponseMode::FormPostJwt, "form_post.jwt")]
    fn response_mode_as_str(#[case] mode: ResponseMode, #[case] expected: &str) {
        assert_eq!(mode.as_str(), expected);
    }

    #[rstest]
    #[case(ResponseMode::Query, false)]
    #[case(ResponseMode::Fragment, false)]
    #[case(ResponseMode::FormPost, false)]
    #[case(ResponseMode::Jwt, true)]
    #[case(ResponseMode::QueryJwt, true)]
    #[case(ResponseMode::FragmentJwt, true)]
    #[case(ResponseMode::FormPostJwt, true)]
    fn response_mode_jwt_secured(#[case] mode: ResponseMode, #[case] expected: bool) {
        assert_eq!(mode.is_jwt_secured(), expected);
    }

    #[test]
    fn response_mode_serde_roundtrip() {
        // Wire spellings include the JARM dotted forms.
        for mode in [
            ResponseMode::Query,
            ResponseMode::Fragment,
            ResponseMode::FormPost,
            ResponseMode::Jwt,
            ResponseMode::QueryJwt,
            ResponseMode::FragmentJwt,
            ResponseMode::FormPostJwt,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, format!("\"{}\"", mode.as_str()));
            let back: ResponseMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[rstest]
    #[case("login", vec![Prompt::Login])]
    #[case("consent", vec![Prompt::Consent])]
    #[case("none", vec![Prompt::None])]
    #[case("select_account", vec![Prompt::SelectAccount])]
    #[case("login consent", vec![Prompt::Login, Prompt::Consent])]
    fn prompt_parsing(#[case] input: &str, #[case] expected: Vec<Prompt>) {
        let result = parse_prompt(Some(&input.to_string())).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn prompt_none_mixed_fails() {
        assert!(parse_prompt(Some(&"none login".to_string())).is_err());
        assert!(parse_prompt(Some(&"login none".to_string())).is_err());
    }

    #[test]
    fn prompt_invalid_value_fails() {
        assert!(parse_prompt(Some(&"invalid".to_string())).is_err());
    }

    #[test]
    fn authorization_request_parse_minimal() {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());

        let req = AuthorizationRequest::parse(&params).unwrap();
        assert_eq!(req.response_type, ResponseType::Code);
        assert_eq!(req.client_id, "client1");
        assert_eq!(req.redirect_uri.to_string(), "https://example.com/cb");
        assert!(req.scope.is_empty());
        assert_eq!(req.response_mode, None);
        assert!(req.prompt.is_empty());
    }

    #[test]
    fn authorization_request_parse_full() {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code id_token".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        params.insert("scope".to_string(), "openid profile".to_string());
        params.insert("state".to_string(), "xyz".to_string());
        params.insert("nonce".to_string(), "abc".to_string());
        params.insert("response_mode".to_string(), "fragment".to_string());
        params.insert("prompt".to_string(), "login consent".to_string());
        params.insert("max_age".to_string(), "3600".to_string());
        params.insert("code_challenge".to_string(), "challenge_123".to_string());
        params.insert("code_challenge_method".to_string(), "S256".to_string());
        params.insert("acr_values".to_string(), "1 2".to_string());
        params.insert("ui_locales".to_string(), "en fr".to_string());
        params.insert("claims".to_string(), r#"{"userinfo":{"name":null}}"#.to_string());
        let req = AuthorizationRequest::parse(&params).unwrap();
        assert_eq!(req.response_type, ResponseType::CodeIdToken);
        assert_eq!(req.scope, Scope::parse("openid profile"));
        assert_eq!(req.state, Some("xyz".to_string()));
        assert_eq!(req.nonce, Some(Nonce::new("abc").unwrap()));
        assert_eq!(req.response_mode, Some(ResponseMode::Fragment));
        assert_eq!(req.prompt, vec![Prompt::Login, Prompt::Consent]);
        assert_eq!(req.max_age, Some(3600));
        assert_eq!(req.code_challenge, Some(Base64Url::new("challenge_123").unwrap()));
        assert_eq!(req.code_challenge_method, Some(PkceCodeChallengeMethod::S256));
        assert_eq!(req.acr_values, vec!["1", "2"]);
        assert_eq!(req.ui_locales, vec!["en", "fr"]);
        assert_eq!(req.claims, Some(serde_json::json!({"userinfo":{"name":null}})));
    }

    #[rstest]
    #[case(Some("true"), true)]
    #[case(Some("1"), false)]
    #[case(Some("false"), false)]
    #[case(Some("yes"), false)]
    #[case(None, false)]
    fn registration_hint_parsing(#[case] value: Option<&str>, #[case] expected: bool) {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        if let Some(v) = value {
            params.insert("registration".to_string(), v.to_string());
        }
        let req = AuthorizationRequest::parse(&params).unwrap();
        assert_eq!(req.registration, expected);
    }

    #[test]
    fn authorization_request_missing_required_fields() {
        let params = HashMap::new();
        assert!(AuthorizationRequest::parse(&params).is_err());

        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        assert!(AuthorizationRequest::parse(&params).is_err());

        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        assert!(AuthorizationRequest::parse(&params).is_err());
    }

    #[test]
    fn authorization_request_invalid_redirect_uri() {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "not-a-url".to_string());
        assert!(AuthorizationRequest::parse(&params).is_err());
    }

    #[test]
    fn authorization_request_reject_request_param() {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        params.insert(
            "request".to_string(),
            "eyJhbGciOiJub25lIn0.eyJpc3MiOiJjbGllbnQxIn0.".to_string(),
        );
        let err = AuthorizationRequest::parse(&params).unwrap_err();
        assert_eq!(err, IssuerdError::RequestNotSupported);
    }

    #[test]
    fn authorization_request_reject_request_uri_param() {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        params.insert("request_uri".to_string(), "https://example.com/request".to_string());
        let err = AuthorizationRequest::parse(&params).unwrap_err();
        assert_eq!(err, IssuerdError::RequestNotSupported);
    }

    #[test]
    fn authorization_request_parses_authorization_details() {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        params.insert(
            "authorization_details".to_string(),
            r#"[{"type":"account_information","actions":["list_accounts"]},{"type":"https://scheme.example.com/payment_initiation"}]"#
                .to_string(),
        );
        let req = AuthorizationRequest::parse(&params).unwrap();
        let details = req.authorization_details.unwrap();
        assert_eq!(details.len(), 2);
        assert_eq!(details[0]["type"], "account_information");
        // Type values are extensible (RFC 9396 §2.1): unknown types and
        // type-specific fields pass through untouched.
        assert_eq!(details[1]["type"], "https://scheme.example.com/payment_initiation");
    }

    #[test]
    fn authorization_request_authorization_details_absent() {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        let req = AuthorizationRequest::parse(&params).unwrap();
        assert_eq!(req.authorization_details, None);
    }

    #[rstest::rstest]
    // Not JSON at all.
    #[case("not json")]
    // A JSON object, not an array.
    #[case(r#"{"type":"account_information"}"#)]
    // Element is not an object.
    #[case(r#"["account_information"]"#)]
    // Element without a `type` member.
    #[case(r#"[{"actions":["read"]}]"#)]
    // `type` is not a string.
    #[case(r#"[{"type":42}]"#)]
    // `type` is the empty string.
    #[case(r#"[{"type":""}]"#)]
    fn authorization_request_rejects_malformed_authorization_details(#[case] raw: &str) {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        params.insert("authorization_details".to_string(), raw.to_string());
        let err = AuthorizationRequest::parse(&params).unwrap_err();
        assert!(
            matches!(err, IssuerdError::InvalidAuthorizationDetails(_)),
            "expected invalid_authorization_details, got {err}"
        );
        assert_eq!(err.oauth_error_code().as_ref(), "invalid_authorization_details");
    }

    #[test]
    fn parse_authorization_details_empty_array_is_valid() {
        // Structurally valid; carries no grant.
        let parsed = parse_authorization_details(Some(&"[]".to_string())).unwrap();
        assert_eq!(parsed, Some(vec![]));
        assert!(parse_authorization_details(None).unwrap().is_none());
    }

    #[test]
    fn authorization_details_subset_exact_containment() {
        let granted = vec![
            serde_json::json!({"type":"account_information","actions":["list_accounts","read_balances"]}),
            serde_json::json!({"type":"payment_initiation"}),
        ];
        // Full set and single element are subsets.
        assert!(authorization_details_is_subset(&granted, &granted));
        assert!(authorization_details_is_subset(&[granted[1].clone()], &granted));
        // Empty request is trivially a subset.
        assert!(authorization_details_is_subset(&[], &granted));
        // Unknown element is not.
        assert!(!authorization_details_is_subset(
            &[serde_json::json!({"type":"other"})],
            &granted
        ));
        // Field-level narrowing is NOT exact containment (conservative
        // rejection — see tests/KEYCLOAK_DIFFS.md).
        assert!(!authorization_details_is_subset(
            &[serde_json::json!({"type":"account_information","actions":["list_accounts"]})],
            &granted
        ));
        // Nothing granted, something requested.
        assert!(!authorization_details_is_subset(&granted, &[]));
    }

    #[test]
    fn authorization_request_invalid_claims_json() {
        let mut params = HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), "client1".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/cb".to_string());
        params.insert("claims".to_string(), "not json".to_string());
        assert!(AuthorizationRequest::parse(&params).is_err());
    }

    #[test]
    fn request_object_claims_conversion_drops_envelope() {
        let claims = serde_json::json!({
            "iss": "client1",
            "aud": "https://issuer.example.com/realms/master",
            "exp": 1_700_000_000,
            "iat": 1_699_999_000,
            "nbf": 1_699_999_000,
            "jti": "abc",
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://example.com/cb",
            "scope": "openid profile",
            "max_age": 3600,
            "claims": {"userinfo": {"name": null}},
            "do_not_use": null,
        });
        let params = request_object_claims_to_params(claims.as_object().unwrap());
        assert_eq!(params.get("response_type").unwrap(), "code");
        assert_eq!(params.get("client_id").unwrap(), "client1");
        assert_eq!(params.get("redirect_uri").unwrap(), "https://example.com/cb");
        assert_eq!(params.get("scope").unwrap(), "openid profile");
        // Numbers stringify; nested objects re-serialize compactly.
        assert_eq!(params.get("max_age").unwrap(), "3600");
        assert_eq!(params.get("claims").unwrap(), r#"{"userinfo":{"name":null}}"#);
        // Envelope claims and nulls are dropped.
        for dropped in ["iss", "aud", "exp", "iat", "nbf", "jti", "do_not_use"] {
            assert!(!params.contains_key(dropped), "{dropped} must be dropped");
        }
        // The converted map parses as a normal authorization request.
        let req = AuthorizationRequest::parse(&params).unwrap();
        assert_eq!(req.response_type, ResponseType::Code);
        assert_eq!(req.client_id, "client1");
    }

    #[test]
    fn request_object_claims_conversion_bool_and_array() {
        let claims = serde_json::json!({
            "response_type": "code",
            "some_flag": true,
            "some_array": ["a", "b"],
        });
        let params = request_object_claims_to_params(claims.as_object().unwrap());
        assert_eq!(params.get("some_flag").unwrap(), "true");
        assert_eq!(params.get("some_array").unwrap(), r#"["a","b"]"#);
    }

    #[test]
    fn validate_redirect_uri_exact_match() {
        let client = Client {
            redirect_uris: vec![RedirectUri::new("https://client.example.com/cb").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            public_client: false,
            attributes: std::collections::HashMap::new(),
            ..make_client_defaults()
        };
        let req = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: ClientIdentifier::new("client1").unwrap(),
            redirect_uri: "https://client.example.com/cb".parse().unwrap(),
            scope: Scope::parse("openid"),
            state: None,
            nonce: None,
            response_mode: None,
            prompt: vec![],
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: vec![],
            ui_locales: vec![],
            claims: None,
            authorization_details: None,
            registration: false,
            request: None,
            request_uri: None,
        };
        assert!(req.validate(&Realm::default(), &client).is_ok());
    }

    /// Keycloak parity: a registered URI with a trailing `*` matches any
    /// request URI under that prefix.
    #[test]
    fn validate_redirect_uri_trailing_wildcard() {
        let client = Client {
            redirect_uris: vec![RedirectUri::new("https://client.example.com/app/*").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            public_client: false,
            attributes: std::collections::HashMap::new(),
            ..make_client_defaults()
        };
        let mut req = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: ClientIdentifier::new("client1").unwrap(),
            redirect_uri: "https://client.example.com/app/cb".parse().unwrap(),
            scope: Scope::parse("openid"),
            state: None,
            nonce: None,
            response_mode: None,
            prompt: vec![],
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: vec![],
            ui_locales: vec![],
            claims: None,
            authorization_details: None,
            registration: false,
            request: None,
            request_uri: None,
        };
        assert!(req.validate(&Realm::default(), &client).is_ok());

        // Outside the prefix (and off-host) still fails.
        req.redirect_uri = "https://client.example.com/other/cb".parse().unwrap();
        assert!(req.validate(&Realm::default(), &client).is_err());
        req.redirect_uri = "https://evil.example.com/app/cb".parse().unwrap();
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn validate_redirect_uri_not_registered() {
        let client = Client {
            redirect_uris: vec![RedirectUri::new("https://client.example.com/cb").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            public_client: false,
            attributes: std::collections::HashMap::new(),
            ..make_client_defaults()
        };
        let req = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: ClientIdentifier::new("client1").unwrap(),
            redirect_uri: "https://other.example.com/cb".parse().unwrap(),
            scope: Scope::parse("openid"),
            state: None,
            nonce: None,
            response_mode: None,
            prompt: vec![],
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: vec![],
            ui_locales: vec![],
            claims: None,
            authorization_details: None,
            registration: false,
            request: None,
            request_uri: None,
        };
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn validate_redirect_uri_with_fragment() {
        let client = Client {
            redirect_uris: vec![RedirectUri::new("https://client.example.com/cb").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            public_client: false,
            attributes: std::collections::HashMap::new(),
            ..make_client_defaults()
        };
        let req = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: ClientIdentifier::new("client1").unwrap(),
            redirect_uri: "https://client.example.com/cb#frag".parse().unwrap(),
            scope: Scope::parse("openid"),
            state: None,
            nonce: None,
            response_mode: None,
            prompt: vec![],
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: vec![],
            ui_locales: vec![],
            claims: None,
            authorization_details: None,
            registration: false,
            request: None,
            request_uri: None,
        };
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn validate_pkce_required_for_public_client() {
        let client = Client {
            public_client: true,
            redirect_uris: vec![RedirectUri::new("https://client.example.com/cb").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            attributes: std::collections::HashMap::new(),
            ..make_client_defaults()
        };
        let req = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: ClientIdentifier::new("client1").unwrap(),
            redirect_uri: "https://client.example.com/cb".parse().unwrap(),
            scope: Scope::parse("openid"),
            state: None,
            nonce: None,
            response_mode: None,
            prompt: vec![],
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: vec![],
            ui_locales: vec![],
            claims: None,
            authorization_details: None,
            registration: false,
            request: None,
            request_uri: None,
        };
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn validate_max_age_zero() {
        let client = Client {
            redirect_uris: vec![RedirectUri::new("https://client.example.com/cb").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            public_client: false,
            attributes: std::collections::HashMap::new(),
            ..make_client_defaults()
        };
        let req = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: ClientIdentifier::new("client1").unwrap(),
            redirect_uri: "https://client.example.com/cb".parse().unwrap(),
            scope: Scope::parse("openid"),
            state: None,
            nonce: None,
            response_mode: None,
            prompt: vec![],
            max_age: Some(0),
            code_challenge: Some(Base64Url::new("challenge_123").unwrap()),
            code_challenge_method: Some(PkceCodeChallengeMethod::S256),
            login_hint: None,
            id_token_hint: None,
            acr_values: vec![],
            ui_locales: vec![],
            claims: None,
            authorization_details: None,
            registration: false,
            request: None,
            request_uri: None,
        };
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn validate_openid_required_for_id_token() {
        let client = Client {
            redirect_uris: vec![RedirectUri::new("https://client.example.com/cb").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            public_client: false,
            attributes: std::collections::HashMap::new(),
            ..make_client_defaults()
        };
        let req = AuthorizationRequest {
            response_type: ResponseType::IdToken,
            client_id: ClientIdentifier::new("client1").unwrap(),
            redirect_uri: "https://client.example.com/cb".parse().unwrap(),
            scope: Scope::parse("profile"), // missing openid
            state: None,
            nonce: None,
            response_mode: None,
            prompt: vec![],
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: vec![],
            ui_locales: vec![],
            claims: None,
            authorization_details: None,
            registration: false,
            request: None,
            request_uri: None,
        };
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn validate_scope_not_allowed() {
        let client = Client {
            redirect_uris: vec![RedirectUri::new("https://client.example.com/cb").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            public_client: false,
            attributes: std::collections::HashMap::new(),
            ..make_client_defaults()
        };
        let req = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: ClientIdentifier::new("client1").unwrap(),
            redirect_uri: "https://client.example.com/cb".parse().unwrap(),
            scope: Scope::parse("email"), // not in client scopes
            state: None,
            nonce: None,
            response_mode: None,
            prompt: vec![],
            max_age: None,
            code_challenge: Some(Base64Url::new("challenge_123").unwrap()),
            code_challenge_method: Some(PkceCodeChallengeMethod::S256),
            login_hint: None,
            id_token_hint: None,
            acr_values: vec![],
            ui_locales: vec![],
            claims: None,
            authorization_details: None,
            registration: false,
            request: None,
            request_uri: None,
        };
        assert!(req.validate(&Realm::default(), &client).is_err());
    }

    #[test]
    fn validate_authorization_details_realm_type_allowlist() {
        let client = Client {
            redirect_uris: vec![RedirectUri::new("https://client.example.com/cb").unwrap()],
            default_scopes: Scope::parse("openid"),
            optional_scopes: Scope::empty(),
            public_client: false,
            attributes: std::collections::HashMap::new(),
            ..make_client_defaults()
        };
        let req = |type_value: &str| AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: ClientIdentifier::new("client1").unwrap(),
            redirect_uri: "https://client.example.com/cb".parse().unwrap(),
            scope: Scope::parse("openid"),
            state: None,
            nonce: None,
            response_mode: None,
            prompt: vec![],
            max_age: None,
            code_challenge: Some(Base64Url::new("challenge_123").unwrap()),
            code_challenge_method: Some(PkceCodeChallengeMethod::S256),
            login_hint: None,
            id_token_hint: None,
            acr_values: vec![],
            ui_locales: vec![],
            claims: None,
            authorization_details: Some(vec![serde_json::json!({"type": type_value})]),
            registration: false,
            request: None,
            request_uri: None,
        };

        // No realm attribute: any type is accepted (extensible per §2.1).
        let realm = Realm::default();
        assert!(req("anything_at_all").validate(&realm, &client).is_ok());

        // Realm pins its supported types: unlisted types are rejected (§5).
        let mut realm = Realm::default();
        realm.attributes.insert(
            Realm::AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE.to_string(),
            "payment_initiation account_information".to_string(),
        );
        assert!(req("payment_initiation").validate(&realm, &client).is_ok());
        let err = req("medical_record").validate(&realm, &client).unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidAuthorizationDetails(_)));
    }

    fn make_client_defaults() -> Client {
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

    // ------------------------------------------------------------------
    // Property-based & fuzz-style tests
    // ------------------------------------------------------------------

    /// Generate 1000 random parameter maps and ensure `parse` never panics.
    #[test]
    fn parse_never_panics_on_random_input() {
        use rand::Rng;
        let keys = [
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "nonce",
            "response_mode",
            "prompt",
            "max_age",
            "code_challenge",
            "code_challenge_method",
            "login_hint",
            "id_token_hint",
            "acr_values",
            "ui_locales",
            "claims",
            "authorization_details",
            "request",
            "request_uri",
        ];
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let mut params = HashMap::new();
            let num_entries = rng.gen_range(0..keys.len());
            for _ in 0..num_entries {
                let key = keys[rng.gen_range(0..keys.len())];
                let value_len = rng.gen_range(0..64);
                let value: String =
                    (0..value_len).map(|_| rng.gen_range(32u8..127u8) as char).collect();
                params.insert(key.to_string(), value);
            }
            let _ = AuthorizationRequest::parse(&params);
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_does_not_panic(params: std::collections::HashMap<String, String>) {
            let _ = AuthorizationRequest::parse(&params);
        }
    }
}
