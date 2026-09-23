// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Authorization-response packaging: response_mode resolution, JARM wrapping, and form_post.

//! Authorization-response packaging: `response_mode` resolution,
//! JARM (JWT Secured Authorization Response Mode for OAuth 2.0) wrapping, and
//! the `form_post` auto-submit page.
//!
//! Every authorization response — success and error — funnels through
//! [`authorization_response`] / [`oauth_error_redirect`], which honor the
//! `response_mode` from the authorization request. Without an explicit mode
//! the spec default applies (OIDC Core 3.1.2.3 / OAuth 2.0 Multiple Response
//! Types): query for the code flow, fragment for implicit/hybrid.
//!
//! JARM modes package the whole response parameter set as one signed JWT
//! delivered in a single `response` parameter; `form_post` delivers the
//! parameters as hidden inputs of an auto-submitting HTML form.

use axum::response::{Html, IntoResponse, Redirect, Response};
use issuerd_core::{IssuerdError, Realm};
use issuerd_protocol::authorization::ResponseMode;

use crate::{routes::oidc, state::ServerState};

/// Everything needed to package one authorization response.
pub(crate) struct ResponsePackaging<'a> {
    pub realm: &'a Realm,
    /// Human-readable client_id (the JARM `aud`).
    pub client_id: &'a str,
    /// The requested `response_mode`; `None` = the spec default applies.
    pub requested_mode: Option<ResponseMode>,
    /// Whether the response type's default mode is the fragment (the
    /// response type carries an id_token).
    pub default_fragment: bool,
}

impl<'a> ResponsePackaging<'a> {
    /// Packaging for the initial authorize-request paths: requested mode and
    /// default come straight from the parsed [`AuthorizationRequest`].
    pub(crate) fn from_request(
        realm: &'a Realm,
        client_id: &'a str,
        auth_req: &'a issuerd_protocol::authorization::AuthorizationRequest,
    ) -> Self {
        Self {
            realm,
            client_id,
            requested_mode: auth_req.response_mode,
            default_fragment: auth_req.response_type.has_id_token(),
        }
    }

    /// Packaging for the continuation paths (login POST, required actions,
    /// consent, broker): everything rides the stored [`PendingAuthData`].
    pub(crate) fn from_pending(realm: &'a Realm, pending: &'a oidc::PendingAuthData) -> Self {
        Self {
            realm,
            client_id: &pending.client_id,
            requested_mode: pending.response_mode,
            default_fragment: pending
                .response_type
                .parse::<issuerd_protocol::authorization::ResponseType>()
                .is_ok_and(|rt| rt.has_id_token()),
        }
    }
}

/// The resolved delivery mechanism for one authorization response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectiveMode {
    Query,
    Fragment,
    FormPost,
    QueryJwt,
    FragmentJwt,
    FormPostJwt,
}

impl EffectiveMode {
    fn is_jwt_secured(self) -> bool {
        matches!(
            self,
            EffectiveMode::QueryJwt | EffectiveMode::FragmentJwt | EffectiveMode::FormPostJwt
        )
    }
}

/// Resolve the requested response mode against the spec default
/// (`default_fragment` = the response type carries an id_token):
/// - no explicit mode → query (code) or fragment (implicit/hybrid);
/// - `jwt` → the default mode, JARM-wrapped;
/// - explicit modes are honored as requested.
pub(crate) fn resolve_effective_mode(
    requested: Option<ResponseMode>,
    default_fragment: bool,
) -> EffectiveMode {
    match requested {
        None => {
            if default_fragment {
                EffectiveMode::Fragment
            } else {
                EffectiveMode::Query
            }
        }
        Some(ResponseMode::Query) => EffectiveMode::Query,
        Some(ResponseMode::Fragment) => EffectiveMode::Fragment,
        Some(ResponseMode::FormPost) => EffectiveMode::FormPost,
        Some(ResponseMode::Jwt) => {
            if default_fragment {
                EffectiveMode::FragmentJwt
            } else {
                EffectiveMode::QueryJwt
            }
        }
        Some(ResponseMode::QueryJwt) => EffectiveMode::QueryJwt,
        Some(ResponseMode::FragmentJwt) => EffectiveMode::FragmentJwt,
        Some(ResponseMode::FormPostJwt) => EffectiveMode::FormPostJwt,
    }
}

/// Build the final authorization response: a 303 redirect (query/fragment)
/// or an auto-submitting HTML page (form_post). The JARM modes sign the whole
/// parameter set into one `response` JWT first (signed with the realm key;
/// clients verify against the realm JWKS).
pub(crate) async fn authorization_response(
    state: &ServerState,
    redirect_uri: &str,
    params: &[(&str, &str)],
    packaging: &ResponsePackaging<'_>,
) -> Response {
    let mode = resolve_effective_mode(packaging.requested_mode, packaging.default_fragment);
    if mode.is_jwt_secured() {
        let owned: Vec<(String, String)> =
            params.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
        let jwt = match state
            .token_manager
            .sign_authorization_response(packaging.realm, packaging.client_id, &owned)
            .await
        {
            Ok(j) => j,
            Err(e) => {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(oidc::error_response(&e)),
                )
                    .into_response();
            }
        };
        return deliver(redirect_uri, &[("response", jwt.as_str())], mode);
    }
    deliver(redirect_uri, params, mode)
}

/// Deliver an (already final) parameter set per the resolved mode.
fn deliver(redirect_uri: &str, params: &[(&str, &str)], mode: EffectiveMode) -> Response {
    match mode {
        EffectiveMode::Query | EffectiveMode::QueryJwt => {
            Redirect::to(&oidc::build_redirect_url(redirect_uri, params, false)).into_response()
        }
        EffectiveMode::Fragment | EffectiveMode::FragmentJwt => {
            Redirect::to(&oidc::build_redirect_url(redirect_uri, params, true)).into_response()
        }
        EffectiveMode::FormPost | EffectiveMode::FormPostJwt => {
            form_post_page(redirect_uri, params)
        }
    }
}

/// The error-path twin of [`authorization_response`]: the OAuth2 error
/// parameters (`error`, `error_description`, `state`) packaged per the
/// requested response mode — JARM wraps error responses exactly like success
/// responses. Only call this with a redirect_uri that has already been
/// validated as registered for the client (RFC 6749 §4.1.2.1).
pub(crate) async fn oauth_error_redirect(
    state: &ServerState,
    redirect_uri: &str,
    error: &IssuerdError,
    state_param: Option<&str>,
    packaging: &ResponsePackaging<'_>,
) -> Response {
    let error_code = error.oauth_error_code();
    let error_desc = error.to_string();
    let desc = error_desc.strip_prefix("invalid request: ").unwrap_or(&error_desc);
    let mut params: Vec<(&str, &str)> =
        vec![("error", error_code.as_ref()), ("error_description", desc)];
    if let Some(s) = state_param {
        params.push(("state", s));
    }
    authorization_response(state, redirect_uri, &params, packaging).await
}

/// The `form_post` response mode page (OAuth 2.0 Form Post Response Mode):
/// an auto-submitting HTML form POSTing the response parameters to the
/// client's redirect_uri.
///
/// Conformance-critical (the rule for server-rendered pages): the
/// auto-submit must work in HtmlUnit without modern JS — a plain `<form>`
/// plus `onload` submit, no modules, no fetch. All values are HTML-escaped.
pub(crate) fn form_post_page(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let mut inputs = String::new();
    for (name, value) in params {
        inputs.push_str(&format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\"/>",
            crate::email::html_escape(name),
            crate::email::html_escape(value),
        ));
    }
    let page = format!(
        "<!DOCTYPE html>\
         <html><head><meta charset=\"utf-8\"/><title>Submitting&#8230;</title></head>\
         <body onload=\"document.forms[0].submit()\">\
         <form method=\"post\" action=\"{}\">{}\
         <noscript><p>JavaScript is disabled. Press Continue to proceed.</p>\
         <button type=\"submit\">Continue</button></noscript>\
         </form></body></html>",
        crate::email::html_escape(redirect_uri),
        inputs,
    );
    Html(page).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    #[test]
    fn mode_resolution_defaults() {
        // No explicit mode: query for code, fragment for id_token-bearing.
        assert_eq!(resolve_effective_mode(None, false), EffectiveMode::Query);
        assert_eq!(resolve_effective_mode(None, true), EffectiveMode::Fragment);
    }

    #[test]
    fn mode_resolution_explicit_passthrough() {
        for (requested, expected) in [
            (ResponseMode::Query, EffectiveMode::Query),
            (ResponseMode::Fragment, EffectiveMode::Fragment),
            (ResponseMode::FormPost, EffectiveMode::FormPost),
            (ResponseMode::QueryJwt, EffectiveMode::QueryJwt),
            (ResponseMode::FragmentJwt, EffectiveMode::FragmentJwt),
            (ResponseMode::FormPostJwt, EffectiveMode::FormPostJwt),
        ] {
            assert_eq!(resolve_effective_mode(Some(requested), false), expected);
            // Explicit modes ignore the response-type default.
            assert_eq!(resolve_effective_mode(Some(requested), true), expected);
        }
    }

    #[test]
    fn mode_resolution_jwt_follows_default() {
        assert_eq!(resolve_effective_mode(Some(ResponseMode::Jwt), false), EffectiveMode::QueryJwt);
        assert_eq!(
            resolve_effective_mode(Some(ResponseMode::Jwt), true),
            EffectiveMode::FragmentJwt
        );
    }

    #[tokio::test]
    async fn form_post_page_shape_and_escaping() {
        let resp = form_post_page(
            "https://client.example.com/cb?x=1&y=2",
            &[("code", "c-1"), ("state", "<s>&\"'\n")],
        );
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        // Auto-submit without modern JS (HtmlUnit-safe), POST to the exact
        // redirect_uri, parameters in the body — never in the page URL.
        assert!(html.contains("<body onload=\"document.forms[0].submit()\">"));
        assert!(html.contains(
            "<form method=\"post\" action=\"https://client.example.com/cb?x=1&amp;y=2\">"
        ));
        assert!(html.contains("<input type=\"hidden\" name=\"code\" value=\"c-1\"/>"));
        assert!(html.contains(
            "<input type=\"hidden\" name=\"state\" value=\"&lt;s&gt;&amp;&quot;&#39;\n\"/>"
        ));
        assert!(html.contains("<noscript>"));
        // The parameters must not be baked into any redirect URL.
        assert!(!html.contains("?code="));
    }

    #[tokio::test]
    async fn jarm_success_response_signed_and_fragmented() {
        let state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        let realm = state.resolve_realm("master").await.unwrap().unwrap();
        let packaging = ResponsePackaging {
            realm: &realm,
            client_id: "admin-cli",
            requested_mode: Some(ResponseMode::Jwt),
            default_fragment: false,
        };
        let resp = authorization_response(
            &state,
            "http://localhost:3000/cb",
            &[("code", "c-9"), ("state", "s-9")],
            &packaging,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::SEE_OTHER);
        let location = resp.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap();
        // `jwt` with a code default resolves to query.jwt.
        let jwt = location
            .strip_prefix("http://localhost:3000/cb?response=")
            .expect("JARM delivered as a single query parameter");
        let claims = decode_payload(jwt);
        assert_eq!(claims["iss"], "http://localhost:8080/realms/master");
        assert_eq!(claims["aud"], "admin-cli");
        assert_eq!(claims["code"], "c-9");
        assert_eq!(claims["state"], "s-9");
        assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
    }

    #[tokio::test]
    async fn jarm_error_response_also_wrapped() {
        let state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        let realm = state.resolve_realm("master").await.unwrap().unwrap();
        let packaging = ResponsePackaging {
            realm: &realm,
            client_id: "admin-cli",
            requested_mode: Some(ResponseMode::FragmentJwt),
            default_fragment: false,
        };
        let resp = oauth_error_redirect(
            &state,
            "http://localhost:3000/cb",
            &IssuerdError::LoginRequired,
            Some("s-1"),
            &packaging,
        )
        .await;
        let location = resp.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap();
        let jwt = location
            .strip_prefix("http://localhost:3000/cb#response=")
            .expect("JARM error delivered in the fragment");
        let claims = decode_payload(jwt);
        assert_eq!(claims["error"], "login_required");
        assert_eq!(claims["state"], "s-1");
    }

    #[tokio::test]
    async fn form_post_jwt_delivers_response_field_in_body() {
        let state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        let realm = state.resolve_realm("master").await.unwrap().unwrap();
        let packaging = ResponsePackaging {
            realm: &realm,
            client_id: "admin-cli",
            requested_mode: Some(ResponseMode::FormPostJwt),
            default_fragment: false,
        };
        let resp = authorization_response(
            &state,
            "http://localhost:3000/cb",
            &[("code", "c-1")],
            &packaging,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("name=\"response\" value=\""));
        assert!(!html.contains("name=\"code\""));
    }

    #[tokio::test]
    async fn plain_modes_deliver_unwrapped() {
        let state = ServerState::from_config(&ServerConfig::default()).await.unwrap();
        let realm = state.resolve_realm("master").await.unwrap().unwrap();

        // form_post (unwrapped).
        let packaging = ResponsePackaging {
            realm: &realm,
            client_id: "admin-cli",
            requested_mode: Some(ResponseMode::FormPost),
            default_fragment: false,
        };
        let resp = authorization_response(
            &state,
            "http://localhost:3000/cb",
            &[("code", "c-1"), ("state", "s-1")],
            &packaging,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("name=\"code\" value=\"c-1\""));
        assert!(html.contains("name=\"state\" value=\"s-1\""));

        // fragment default for id_token-bearing response types.
        let packaging = ResponsePackaging {
            realm: &realm,
            client_id: "admin-cli",
            requested_mode: None,
            default_fragment: true,
        };
        let resp = authorization_response(
            &state,
            "http://localhost:3000/cb",
            &[("id_token", "t-1")],
            &packaging,
        )
        .await;
        let location = resp.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap();
        assert!(location.starts_with("http://localhost:3000/cb#id_token=t-1"));
    }

    fn decode_payload(jwt: &str) -> serde_json::Value {
        use base64::Engine;
        let segment = jwt.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(segment).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}
