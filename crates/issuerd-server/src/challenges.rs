// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// `WWW-Authenticate: Bearer` challenge builders (RFC 6750 §3.1 + RFC 9728 §5.1) —
// groundwork for the future `/mcp` route (issue #39, plan item G2).

//! `WWW-Authenticate: Bearer` challenges for protected-resource endpoints:
//! RFC 6750 §3.1 error challenges extended with the RFC 9728 §5.1
//! `resource_metadata` auth-param.
//!
//! The MCP authorization flow drives incremental scope elevation off these
//! challenges: a 401 carrying `resource_metadata` (missing/invalid token)
//! tells the client where the protected-resource metadata document lives; a
//! 403 carrying `error="insufficient_scope"` and `scope` (SEP-835) tells it
//! which scopes to request on step-up. Nothing calls these builders yet —
//! the Phase-1 `/mcp` middleware wires them; they are `pub` and fully
//! unit-tested here.
//!
//! Header-value safety: every auth-param value is emitted as an RFC 9110
//! §5.6.4 quoted-string with `"`/`\` escaping, values containing control
//! characters (CR/LF included — header injection) are REJECTED, scope tokens
//! are restricted to the RFC 6750 §3.1 `scope-token` charset, and
//! `resource_metadata` must be an absolute URL. When any value is rejected
//! the response builders degrade to status + JSON error body WITHOUT the
//! `WWW-Authenticate` header (with a WARN) — a malformed challenge can never
//! be emitted.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use tracing::warn;

/// Render one auth-param value as quoted-string content (RFC 9110 §5.6.4):
/// `"` and `\` are backslash-escaped. Returns `None` when the value carries a
/// control character (CR/LF included): quoted-strings cannot carry them, so
/// such a value must never reach a header.
fn quote_auth_param(value: &str) -> Option<String> {
    if value.chars().any(char::is_control) {
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

/// The `WWW-Authenticate` value for a 401 Bearer challenge (RFC 6750 §3.1):
/// `Bearer resource_metadata="<url>"`, optionally preceded by
/// `error="invalid_token", error_description="..."`.
///
/// Per RFC 6750 §3.1 the error code is omitted when the request carried no
/// credentials at all (`error_description: None`); a rejected/expired token
/// passes a description and gets `error="invalid_token"`.
///
/// Returns `None` — never a malformed value — when `resource_metadata` is not
/// an absolute URL or any value contains a control character (CR/LF header
/// injection).
pub fn invalid_token_header_value(
    resource_metadata: &str,
    error_description: Option<&str>,
) -> Option<String> {
    let metadata = quoted_metadata_url(resource_metadata)?;
    let mut value = String::from("Bearer ");
    if let Some(description) = error_description {
        let description = quote_auth_param(description)?;
        value.push_str("error=\"invalid_token\", error_description=\"");
        value.push_str(&description);
        value.push_str("\", ");
    }
    value.push_str("resource_metadata=\"");
    value.push_str(&metadata);
    value.push('"');
    Some(value)
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
                .insert(header::WWW_AUTHENTICATE, challenge_header_value(&value));
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
                .insert(header::WWW_AUTHENTICATE, challenge_header_value(&value));
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

/// Convert a built challenge string into a header value. Cannot fail: the
/// builders admit only characters `HeaderValue` accepts (control characters
/// are rejected earlier, and the remainder is visible ASCII or non-control
/// multi-byte UTF-8).
fn challenge_header_value(value: &str) -> HeaderValue {
    HeaderValue::from_str(value)
        .expect("challenge values pass control-character rejection; HeaderValue accepts the rest")
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
    fn header_value_escapes_quotes_and_backslashes() {
        assert_eq!(
            invalid_token_header_value(META, Some("say \"hi\" \\end")).unwrap(),
            format!(
                "Bearer error=\"invalid_token\", error_description=\"say \\\"hi\\\" \\\\end\", resource_metadata=\"{META}\""
            )
        );
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
    fn header_value_passes_unicode_description_through() {
        // Non-control non-ASCII is RFC 9110 obs-text territory and passes
        // unescaped (server-derived descriptions are plain ASCII in practice).
        let value = invalid_token_header_value(META, Some("токен истёк")).unwrap();
        assert!(value.contains("error_description=\"токен истёк\""), "{value}");
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
}
