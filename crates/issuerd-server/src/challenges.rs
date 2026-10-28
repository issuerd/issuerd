// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Scheme-aware `WWW-Authenticate` challenge builders for protected resources.

//! Bearer and DPoP challenges combining RFC 6750 §3.1, RFC 9449 §7-9, and
//! the RFC 9728 §5.1 `resource_metadata` auth-param. Separate builders cover
//! no-credential discovery, token and proof failures, nonce retry, and exact
//! runtime scope deficiencies.
//!
//! URL values use safe RFC 9110 quoted-string rendering. Error and description
//! values are limited to the RFC 6750 visible-ASCII set; Unicode, controls,
//! and quoted-pair escaping are rejected. Scope tokens use their narrower RFC
//! 6750 grammar. DPoP challenges advertise the shared validator algorithm set.
//! Invalid inputs omit the malformed challenge headers and log a warning.
//! Every response is marked `no-store` and `no-cache`; compatibility discovery
//! appends Bearer and DPoP as separate header values.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use tracing::warn;

/// Render one URL auth-param value as ASCII quoted-string content
/// (RFC 9110 §5.6.4), escaping `"` and `\` and rejecting controls.
fn quote_auth_param(value: &str) -> Option<String> {
    if !value.is_ascii() || value.chars().any(char::is_control) {
        return None;
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    Some(quoted)
}

/// RFC 6750 §3.1 restricts error and description values to
/// `%x20-21 / %x23-5B / %x5D-7E`; quoted-pair escaping does not widen it.
fn is_rfc6750_error_value(value: &str) -> bool {
    value.bytes().all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// Authentication schemes supported by protected-resource challenges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeScheme {
    Bearer,
    Dpop,
}

impl ChallengeScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::Dpop => "DPoP",
        }
    }
}

/// RFC 6750 §3.1 `scope-token`: `1*( %x21 / %x23-5B / %x5D-7E )` — visible
/// ASCII except `"` and `\`. Neither is escapable inside the scope list (the
/// grammar allows no quoted-pair), so a token containing one is rejected, not
/// quoted.
fn is_scope_token(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| matches!(b, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// The quoted `resource_metadata` parameter (RFC 9728 §5.1): the value must
/// be an absolute URL and survive quoted-string rendering.
fn quoted_metadata_url(resource_metadata: &str) -> Option<String> {
    if url::Url::parse(resource_metadata).is_err() {
        return None;
    }
    quote_auth_param(resource_metadata)
}

fn dpop_algs() -> String {
    issuerd_core::Algorithm::DPOP_SIGNING_ALG_VALUES_SUPPORTED
        .iter()
        .map(|alg| alg.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn scheme_challenge_header_value(
    scheme: ChallengeScheme,
    resource_metadata: &str,
    error: Option<&str>,
    error_description: Option<&str>,
    required_scopes: &[&str],
) -> Option<String> {
    if error.is_none() && error_description.is_some() {
        return None;
    }
    if let Some(error) = error {
        if error.is_empty() || !is_rfc6750_error_value(error) {
            return None;
        }
    }
    if error_description.is_some_and(|value| !is_rfc6750_error_value(value)) {
        return None;
    }
    if error == Some("insufficient_scope") && required_scopes.is_empty() {
        return None;
    }
    if !required_scopes.iter().all(|scope| is_scope_token(scope)) {
        return None;
    }
    let metadata = quoted_metadata_url(resource_metadata)?;
    let mut params = Vec::new();
    if let Some(error) = error {
        params.push(format!("error=\"{error}\""));
    }
    if let Some(description) = error_description {
        params.push(format!("error_description=\"{description}\""));
    }
    params.push(format!("resource_metadata=\"{metadata}\""));
    if scheme == ChallengeScheme::Dpop {
        params.push(format!("algs=\"{}\"", dpop_algs()));
    }
    if !required_scopes.is_empty() {
        params.push(format!("scope=\"{}\"", required_scopes.join(" ")));
    }
    Some(format!("{} {}", scheme.as_str(), params.join(", ")))
}

/// Backward-compatible Bearer header builder. `None` keeps the original
/// no-credential discovery form; use [`no_credentials_challenge`] for the MCP
/// discovery matrix instead.
pub fn invalid_token_header_value(
    resource_metadata: &str,
    error_description: Option<&str>,
) -> Option<String> {
    scheme_challenge_header_value(
        ChallengeScheme::Bearer,
        resource_metadata,
        error_description.map(|_| "invalid_token"),
        error_description,
        &[],
    )
}

/// Runtime `invalid_token` on the scheme attempted by the request.
pub fn invalid_token_header_value_for_scheme(
    scheme: ChallengeScheme,
    resource_metadata: &str,
    error_description: Option<&str>,
) -> Option<String> {
    scheme_challenge_header_value(
        scheme,
        resource_metadata,
        Some("invalid_token"),
        error_description,
        &[],
    )
}

/// DPoP proof validation failure (RFC 9449 §7.1).
pub fn invalid_dpop_proof_header_value(
    resource_metadata: &str,
    error_description: Option<&str>,
) -> Option<String> {
    scheme_challenge_header_value(
        ChallengeScheme::Dpop,
        resource_metadata,
        Some("invalid_dpop_proof"),
        error_description,
        &[],
    )
}

/// DPoP nonce retry challenge (RFC 9449 §8/§9).
pub fn use_dpop_nonce_header_value(
    resource_metadata: &str,
    error_description: Option<&str>,
) -> Option<String> {
    scheme_challenge_header_value(
        ChallengeScheme::Dpop,
        resource_metadata,
        Some("use_dpop_nonce"),
        error_description,
        &[],
    )
}

/// Runtime scope deficiency on the authenticated request scheme, with exactly
/// the operation's required scope set and no implicit hierarchy.
pub fn insufficient_scope_header_value_for_scheme(
    scheme: ChallengeScheme,
    required_scopes: &[&str],
    resource_metadata: &str,
) -> Option<String> {
    scheme_challenge_header_value(
        scheme,
        resource_metadata,
        Some("insufficient_scope"),
        None,
        required_scopes,
    )
}

/// The `WWW-Authenticate` value for a 403 insufficient-scope challenge
/// (RFC 6750 §3.1 + SEP-835): `Bearer error="insufficient_scope",
/// scope="<required scopes>"`, plus `resource_metadata="<url>"` when given.
///
/// `required_scopes` are joined into the space-separated `scope` parameter;
/// every entry must be a valid RFC 6750 `scope-token` and the list must be
/// non-empty. Returns `None` — never a malformed value — on any violation, or
/// when `resource_metadata` fails the 401 variant's checks.
pub fn insufficient_scope_header_value(
    required_scopes: &[&str],
    resource_metadata: Option<&str>,
) -> Option<String> {
    if required_scopes.is_empty() || !required_scopes.iter().all(|s| is_scope_token(s)) {
        return None;
    }
    let mut value =
        format!("Bearer error=\"insufficient_scope\", scope=\"{}\"", required_scopes.join(" "));
    if let Some(resource_metadata) = resource_metadata {
        let metadata = quoted_metadata_url(resource_metadata)?;
        value.push_str(", resource_metadata=\"");
        value.push_str(&metadata);
        value.push('"');
    }
    Some(value)
}

fn scheme_error_challenge_response(
    status: StatusCode,
    scheme: ChallengeScheme,
    resource_metadata: &str,
    error: &'static str,
    error_description: Option<&str>,
    required_scopes: &[&str],
) -> Response {
    let mut body = serde_json::json!({"error": error});
    if let Some(description) = error_description {
        body["error_description"] = serde_json::json!(description);
    } else if error == "insufficient_scope" && !required_scopes.is_empty() {
        body["error_description"] = serde_json::json!(format!(
            "the access token does not grant the required scope(s): {}",
            required_scopes.join(" ")
        ));
    }
    let mut response = (status, Json(body)).into_response();
    match scheme_challenge_header_value(
        scheme,
        resource_metadata,
        Some(error),
        error_description,
        required_scopes,
    ) {
        Some(value) => {
            response
                .headers_mut()
                .append(header::WWW_AUTHENTICATE, challenge_header_value(&value));
        }
        None => {
            warn!(error, "challenge value rejected; responding without WWW-Authenticate");
        }
    }
    decorate_no_store(&mut response);
    response
}

/// Initial no-credential discovery. Strict mode emits only DPoP; explicit
/// compatibility appends Bearer then DPoP. Neither form carries an OAuth error
/// body, and both advertise the minimal initial scope.
pub fn no_credentials_challenge(resource_metadata: &str, require_dpop: bool) -> Response {
    let schemes = if require_dpop {
        vec![ChallengeScheme::Dpop]
    } else {
        vec![ChallengeScheme::Bearer, ChallengeScheme::Dpop]
    };
    let challenges: Option<Vec<String>> = schemes
        .into_iter()
        .map(|scheme| {
            scheme_challenge_header_value(
                scheme,
                resource_metadata,
                None,
                None,
                &[issuerd_core::MCP_SCOPE_READ],
            )
        })
        .collect();
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    match challenges {
        Some(challenges) => {
            for challenge in challenges {
                response
                    .headers_mut()
                    .append(header::WWW_AUTHENTICATE, challenge_header_value(&challenge));
            }
        }
        None => {
            warn!("discovery challenge value rejected; responding without WWW-Authenticate");
        }
    }
    decorate_no_store(&mut response);
    response
}

/// Runtime `invalid_token` response on the attempted authentication scheme.
pub fn invalid_token_challenge_for_scheme(
    scheme: ChallengeScheme,
    resource_metadata: &str,
    error_description: Option<&str>,
) -> Response {
    scheme_error_challenge_response(
        StatusCode::UNAUTHORIZED,
        scheme,
        resource_metadata,
        "invalid_token",
        error_description,
        &[],
    )
}

/// Missing, malformed, replayed, or otherwise invalid DPoP proof.
pub fn invalid_dpop_proof_challenge(
    resource_metadata: &str,
    error_description: Option<&str>,
) -> Response {
    scheme_error_challenge_response(
        StatusCode::UNAUTHORIZED,
        ChallengeScheme::Dpop,
        resource_metadata,
        "invalid_dpop_proof",
        error_description,
        &[],
    )
}

/// Actual runtime scope miss using the authenticated request scheme and the
/// exact required scope set.
pub fn insufficient_scope_challenge_for_scheme(
    scheme: ChallengeScheme,
    required_scopes: &[&str],
    resource_metadata: &str,
) -> Response {
    scheme_error_challenge_response(
        StatusCode::FORBIDDEN,
        scheme,
        resource_metadata,
        "insufficient_scope",
        None,
        required_scopes,
    )
}

fn dpop_nonce_header_value(nonce: &str) -> Option<HeaderValue> {
    if nonce.is_empty() || !nonce.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    HeaderValue::from_str(nonce).ok()
}

/// Nonce retry response with one challenge and exactly one `DPoP-Nonce`.
pub fn use_dpop_nonce_challenge(
    resource_metadata: &str,
    dpop_nonce: &str,
    error_description: Option<&str>,
) -> Response {
    let mut body = serde_json::json!({"error": "use_dpop_nonce"});
    if let Some(description) = error_description {
        body["error_description"] = serde_json::json!(description);
    }
    let mut response = (StatusCode::UNAUTHORIZED, Json(body)).into_response();
    match (
        use_dpop_nonce_header_value(resource_metadata, error_description),
        dpop_nonce_header_value(dpop_nonce),
    ) {
        (Some(challenge), Some(nonce)) => {
            response
                .headers_mut()
                .append(header::WWW_AUTHENTICATE, challenge_header_value(&challenge));
            response.headers_mut().append("dpop-nonce", nonce);
        }
        _ => {
            warn!(
                "use_dpop_nonce challenge or nonce rejected; responding without challenge headers"
            );
        }
    }
    decorate_no_store(&mut response);
    response
}

/// 401 challenge for a missing/invalid access token (RFC 6750 §3.1): the JSON
/// error body ([`crate::openapi::OAuth2ErrorResponse`] shape), the
/// `WWW-Authenticate` challenge from [`invalid_token_header_value`], and the
/// RFC 6749 §5.1 `no-store`/`no-cache` cache directives (token-endpoint
/// parity).
///
/// When the header value cannot be built (see [`invalid_token_header_value`])
/// the response degrades to status + body without the challenge header and a
/// WARN is logged — the caller's values are server-derived, so a rejection
/// means operator misconfiguration, not client input.
pub fn invalid_token_challenge(
    resource_metadata: &str,
    error_description: Option<&str>,
) -> Response {
    let mut body = serde_json::json!({"error": "invalid_token"});
    if let Some(description) = error_description {
        body["error_description"] = serde_json::json!(description);
    }
    let mut response = (StatusCode::UNAUTHORIZED, Json(body)).into_response();
    match invalid_token_header_value(resource_metadata, error_description) {
        Some(value) => {
            response
                .headers_mut()
                .append(header::WWW_AUTHENTICATE, challenge_header_value(&value));
        }
        None => {
            warn!("invalid_token challenge value rejected; responding without WWW-Authenticate");
        }
    }
    decorate_no_store(&mut response);
    response
}

/// 403 challenge for an under-scoped access token (RFC 6750 §3.1 + SEP-835):
/// the JSON error body ([`crate::openapi::OAuth2ErrorResponse`] shape), the
/// `WWW-Authenticate` challenge from [`insufficient_scope_header_value`], and
/// the same cache directives as [`invalid_token_challenge`]. Degrades like the
/// 401 variant when the header value cannot be built.
pub fn insufficient_scope_challenge(
    required_scopes: &[&str],
    resource_metadata: Option<&str>,
) -> Response {
    let mut body = serde_json::json!({"error": "insufficient_scope"});
    if !required_scopes.is_empty() {
        body["error_description"] = serde_json::json!(format!(
            "the access token does not grant the required scope(s): {}",
            required_scopes.join(" ")
        ));
    }
    let mut response = (StatusCode::FORBIDDEN, Json(body)).into_response();
    match insufficient_scope_header_value(required_scopes, resource_metadata) {
        Some(value) => {
            response
                .headers_mut()
                .append(header::WWW_AUTHENTICATE, challenge_header_value(&value));
        }
        None => {
            warn!(
                "insufficient_scope challenge value rejected; responding without WWW-Authenticate"
            );
        }
    }
    decorate_no_store(&mut response);
    response
}

/// Convert a validated ASCII challenge string into a header value.
fn challenge_header_value(value: &str) -> HeaderValue {
    HeaderValue::from_str(value)
        .expect("challenge builders reject non-ASCII and control characters")
}

/// RFC 6749 §5.1's cache directives (token-endpoint parity): challenge
/// responses carry security decisions and must never be cached.
fn decorate_no_store(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, StatusCode};

    /// An RFC 9728 resource-metadata URL as the `/mcp` middleware derives it.
    const META: &str =
        "https://idp.example.com/.well-known/oauth-protected-resource/realms/master/mcp";

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ------------------------------------------------------------------
    // Header-value serialization (byte-exact)
    // ------------------------------------------------------------------

    #[test]
    fn invalid_token_header_value_without_error_is_bare_metadata() {
        // No credentials presented: RFC 6750 §3.1 — no error code, just the
        // metadata pointer.
        assert_eq!(
            invalid_token_header_value(META, None).unwrap(),
            format!("Bearer resource_metadata=\"{META}\"")
        );
    }

    #[test]
    fn invalid_token_header_value_with_error_description() {
        assert_eq!(
            invalid_token_header_value(META, Some("The access token expired")).unwrap(),
            format!(
                "Bearer error=\"invalid_token\", error_description=\"The access token expired\", resource_metadata=\"{META}\""
            )
        );
    }

    #[test]
    fn error_description_rejects_quoted_pair_escaping() {
        assert!(invalid_token_header_value(META, Some("say \"hi\"")).is_none());
        assert!(invalid_token_header_value(META, Some("say \\hi")).is_none());
        assert_eq!(quote_auth_param("say \"hi\" \\end").as_deref(), Some("say \\\"hi\\\" \\\\end"));
    }

    #[test]
    fn header_value_rejects_control_characters() {
        // CR/LF is the header-injection vector; every C0/C1/DEL control must
        // be rejected in every interpolated value.
        for bad in [
            "\r", "\n", "\r\n", "\0", "\u{1b}", "\u{7f}", "\t", "a\u{85}b",
        ] {
            assert!(
                invalid_token_header_value(META, Some(bad)).is_none(),
                "description with {bad:?} must be rejected"
            );
            let bad_url = format!("https://idp.example.com/{bad}");
            assert!(
                invalid_token_header_value(&bad_url, None).is_none(),
                "metadata URL with {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn header_value_rejects_non_absolute_metadata_url() {
        for bad in ["", "/relative/path", "not a url", "example.com/x", "?query"] {
            assert!(
                invalid_token_header_value(bad, None).is_none(),
                "non-absolute metadata URL {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn header_value_rejects_unicode_error_and_description() {
        assert!(invalid_token_header_value(META, Some("токен истёк")).is_none());
        assert!(scheme_challenge_header_value(
            ChallengeScheme::Bearer,
            META,
            Some("ошибка"),
            None,
            &[],
        )
        .is_none());
    }

    #[test]
    fn insufficient_scope_header_value_single_scope() {
        assert_eq!(
            insufficient_scope_header_value(&["mcp:write"], None).unwrap(),
            "Bearer error=\"insufficient_scope\", scope=\"mcp:write\""
        );
    }

    #[test]
    fn insufficient_scope_header_value_joins_scope_list() {
        assert_eq!(
            insufficient_scope_header_value(&["mcp:read", "mcp:write"], None).unwrap(),
            "Bearer error=\"insufficient_scope\", scope=\"mcp:read mcp:write\""
        );
    }

    #[test]
    fn insufficient_scope_header_value_with_resource_metadata() {
        assert_eq!(
            insufficient_scope_header_value(&["mcp:read", "mcp:write"], Some(META)).unwrap(),
            format!(
                "Bearer error=\"insufficient_scope\", scope=\"mcp:read mcp:write\", resource_metadata=\"{META}\""
            )
        );
    }

    #[test]
    fn insufficient_scope_header_value_rejects_invalid_scope_tokens() {
        // scope-token is 1*( %x21 / %x23-5B / %x5D-7E ): no space, no DQUOTE,
        // no backslash, no controls, no non-ASCII.
        for bad in [
            "mcp read",
            "mcp\"read",
            "mcp\\read",
            "",
            "mcp\tread",
            "mcp:чтение",
            "mcp\u{7f}read",
        ] {
            assert!(
                insufficient_scope_header_value(&[bad], None).is_none(),
                "scope token {bad:?} must be rejected"
            );
        }
        // A single bad entry rejects the whole list.
        assert!(insufficient_scope_header_value(&["mcp:read", "mcp read"], None).is_none());
        // The list itself must be non-empty.
        assert!(insufficient_scope_header_value(&[], None).is_none());
    }

    #[test]
    fn insufficient_scope_header_value_rejects_bad_metadata_url() {
        assert!(insufficient_scope_header_value(&["mcp:read"], Some("/relative")).is_none());
        assert!(
            insufficient_scope_header_value(&["mcp:read"], Some("https://e.com/a\nb")).is_none()
        );
    }

    // ------------------------------------------------------------------
    // Full responses
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn invalid_token_challenge_response_is_rfc6750_shaped() {
        let response = invalid_token_challenge(META, Some("The access token expired"));
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE].to_str().unwrap(),
            format!(
                "Bearer error=\"invalid_token\", error_description=\"The access token expired\", resource_metadata=\"{META}\""
            )
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let body = body_json(response).await;
        assert_eq!(
            body,
            serde_json::json!({
                "error": "invalid_token",
                "error_description": "The access token expired",
            })
        );
    }

    #[tokio::test]
    async fn invalid_token_challenge_response_without_error_params() {
        let response = invalid_token_challenge(META, None);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE].to_str().unwrap(),
            format!("Bearer resource_metadata=\"{META}\"")
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        let body = body_json(response).await;
        // OAuth2ErrorResponse shape: the optional description key is absent.
        assert_eq!(body, serde_json::json!({"error": "invalid_token"}));
    }

    #[tokio::test]
    async fn insufficient_scope_challenge_response_is_rfc6750_shaped() {
        let response = insufficient_scope_challenge(&["mcp:read", "mcp:write"], Some(META));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE].to_str().unwrap(),
            format!(
                "Bearer error=\"insufficient_scope\", scope=\"mcp:read mcp:write\", resource_metadata=\"{META}\""
            )
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let body = body_json(response).await;
        assert_eq!(
            body,
            serde_json::json!({
                "error": "insufficient_scope",
                "error_description":
                    "the access token does not grant the required scope(s): mcp:read mcp:write",
            })
        );
    }

    #[tokio::test]
    async fn insufficient_scope_challenge_response_without_resource_metadata() {
        let response = insufficient_scope_challenge(&["mcp:write"], None);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE].to_str().unwrap(),
            "Bearer error=\"insufficient_scope\", scope=\"mcp:write\""
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        let body = body_json(response).await;
        assert_eq!(
            body,
            serde_json::json!({
                "error": "insufficient_scope",
                "error_description":
                    "the access token does not grant the required scope(s): mcp:write",
            })
        );
    }

    #[tokio::test]
    async fn invalid_token_challenge_omits_challenge_header_on_rejected_input() {
        // A CR/LF-carrying value must never reach a header: the response
        // degrades to status + JSON body without WWW-Authenticate.
        let response = invalid_token_challenge(META, Some("bad\r\ndescription"));
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        let body = body_json(response).await;
        // The body stays intact: serde_json escapes control characters.
        assert_eq!(body["error"], "invalid_token");
        assert_eq!(body["error_description"], "bad\r\ndescription");
    }

    #[tokio::test]
    async fn insufficient_scope_challenge_omits_challenge_header_on_rejected_input() {
        let response = insufficient_scope_challenge(&[], Some(META));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        let body = body_json(response).await;
        // No scopes: nothing to describe either.
        assert_eq!(body, serde_json::json!({"error": "insufficient_scope"}));
    }

    fn www_authenticate_values(response: &Response) -> Vec<String> {
        response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn dpop_error_headers_carry_metadata_and_shared_algs() {
        assert_eq!(
            invalid_token_header_value_for_scheme(ChallengeScheme::Dpop, META, None).unwrap(),
            format!("DPoP error=\"invalid_token\", resource_metadata=\"{META}\", algs=\"RS256 RS384 RS512 ES256 ES384 EdDSA\"")
        );
        assert_eq!(
            invalid_dpop_proof_header_value(META, Some("Invalid proof")).unwrap(),
            format!("DPoP error=\"invalid_dpop_proof\", error_description=\"Invalid proof\", resource_metadata=\"{META}\", algs=\"RS256 RS384 RS512 ES256 ES384 EdDSA\"")
        );
        assert_eq!(
            use_dpop_nonce_header_value(META, None).unwrap(),
            format!("DPoP error=\"use_dpop_nonce\", resource_metadata=\"{META}\", algs=\"RS256 RS384 RS512 ES256 ES384 EdDSA\"")
        );
    }

    #[test]
    fn dpop_scope_header_uses_exact_operation_scopes() {
        assert_eq!(
            insufficient_scope_header_value_for_scheme(
                ChallengeScheme::Dpop,
                &["mcp:write", "mcp:step_up"],
                META,
            )
            .unwrap(),
            format!("DPoP error=\"insufficient_scope\", resource_metadata=\"{META}\", algs=\"RS256 RS384 RS512 ES256 ES384 EdDSA\", scope=\"mcp:write mcp:step_up\"")
        );
    }

    #[tokio::test]
    async fn strict_no_credentials_response_is_one_bodyless_dpop_discovery_challenge() {
        let response = no_credentials_challenge(META, true);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate_values(&response),
            [format!("DPoP resource_metadata=\"{META}\", algs=\"RS256 RS384 RS512 ES256 ES384 EdDSA\", scope=\"mcp:read\"")]
        );
        assert!(response.headers().get(header::CONTENT_TYPE).is_none());
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn compatibility_no_credentials_response_appends_bearer_and_dpop() {
        let response = no_credentials_challenge(META, false);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let values = www_authenticate_values(&response);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], format!("Bearer resource_metadata=\"{META}\", scope=\"mcp:read\""));
        assert_eq!(
            values[1],
            format!("DPoP resource_metadata=\"{META}\", algs=\"RS256 RS384 RS512 ES256 ES384 EdDSA\", scope=\"mcp:read\"")
        );
        assert!(values.iter().all(|value| !value.contains("error")));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn invalid_dpop_proof_response_uses_dpop_scheme() {
        let response = invalid_dpop_proof_challenge(META, None);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate_values(&response),
            [format!("DPoP error=\"invalid_dpop_proof\", resource_metadata=\"{META}\", algs=\"RS256 RS384 RS512 ES256 ES384 EdDSA\"")]
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(body_json(response).await, serde_json::json!({"error": "invalid_dpop_proof"}));
    }

    #[tokio::test]
    async fn nonce_response_has_exactly_one_nonce_header() {
        let response = use_dpop_nonce_challenge(META, "nonce-1", None);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let nonces: Vec<_> = response.headers().get_all("dpop-nonce").iter().collect();
        assert_eq!(nonces.len(), 1);
        assert_eq!(nonces[0], "nonce-1");
        assert_eq!(
            www_authenticate_values(&response),
            [format!("DPoP error=\"use_dpop_nonce\", resource_metadata=\"{META}\", algs=\"RS256 RS384 RS512 ES256 ES384 EdDSA\"")]
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(body_json(response).await, serde_json::json!({"error": "use_dpop_nonce"}));
    }

    #[tokio::test]
    async fn nonce_response_rejects_invalid_nonce_without_headers() {
        for bad in ["", "bad nonce", "bad\nnonce", "плохой"] {
            let response = use_dpop_nonce_challenge(META, bad, None);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(response.headers().get("dpop-nonce").is_none());
            assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        }
    }

    #[tokio::test]
    async fn runtime_scheme_and_scope_challenges_have_expected_statuses() {
        for scheme in [ChallengeScheme::Bearer, ChallengeScheme::Dpop] {
            let response = invalid_token_challenge_for_scheme(scheme, META, None);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let value = &www_authenticate_values(&response)[0];
            assert!(value.starts_with(scheme.as_str()));
            assert!(value.contains("error=\"invalid_token\""));
            assert_eq!(value.contains("algs="), scheme == ChallengeScheme::Dpop);

            let response = insufficient_scope_challenge_for_scheme(scheme, &["mcp:write"], META);
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let value = &www_authenticate_values(&response)[0];
            assert!(value.starts_with(scheme.as_str()));
            assert!(value.contains("error=\"insufficient_scope\""));
            assert!(value.ends_with("scope=\"mcp:write\""));
            assert!(!value.contains("mcp:read"));
            assert_eq!(value.contains("algs="), scheme == ChallengeScheme::Dpop);
        }
    }
}
