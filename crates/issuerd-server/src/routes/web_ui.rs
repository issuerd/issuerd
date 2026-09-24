// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Embedded admin console SPA and web UI asset serving.

use std::sync::Arc;

use axum::{
    extract::{Extension, OriginalUri, Path, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};

use crate::{middleware::realm::ResolvedRealm, state::ServerState};

/// URL prefix that owns the admin console SPA. Everything under it is client-side
/// routing; the REST admin API lives directly under `/admin` next to it.
pub const ADMIN_CONSOLE_PREFIX: &str = "/admin/console";

#[cfg(webclient_present)]
mod embedded {
    use include_dir::{include_dir, Dir};
    pub static DIR: Dir<'_> = include_dir!("$ISSUERD_WEB_DIST");
}

#[cfg(not(webclient_present))]
mod embedded {
    pub fn get_file(_: &str) -> Option<&'static [u8]> {
        None
    }
    pub fn get_index_html() -> Option<&'static [u8]> {
        None
    }
}

#[cfg(webclient_present)]
fn get_file(path: &str) -> Option<&'static [u8]> {
    let normalized = path.trim_start_matches('/');
    embedded::DIR.get_file(normalized).map(|f| f.contents())
}

#[cfg(webclient_present)]
fn get_index_html() -> Option<&'static [u8]> {
    embedded::DIR.get_file("index.html").map(|f| f.contents())
}

#[cfg(not(webclient_present))]
fn get_file(path: &str) -> Option<&'static [u8]> {
    embedded::get_file(path)
}

#[cfg(not(webclient_present))]
fn get_index_html() -> Option<&'static [u8]> {
    embedded::get_index_html()
}

pub async fn static_handler(
    State(_state): State<Arc<ServerState>>,
    path: Option<Path<String>>,
    Extension(ResolvedRealm(_realm)): Extension<ResolvedRealm>,
) -> Response {
    let path = path.map(|p| p.0).unwrap_or_default();

    // Serve account.html for account console routes: /realms/{realm}/account/*
    if path.starts_with("realms/") {
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() >= 3 && segments[2] == "account" {
            // ...but never for the account REST API namespace: an unmatched
            // /realms/{realm}/account/api/* path is an API typo, not a page.
            if segments.get(3) == Some(&"api") {
                return not_found_json();
            }
            if let Some(contents) = get_file("account.html") {
                return ([(header::CONTENT_TYPE, "text/html")], contents).into_response();
            }
        }
    }

    if let Some(contents) = get_file(&path) {
        let mime = mime_guess::from_path(&path).first_or_octet_stream();
        return ([(header::CONTENT_TYPE, mime.as_ref())], contents).into_response();
    }

    // Unknown path. Only the admin console (`/admin/console/*`, handled by
    // `admin_console_handler`) and the account console own SPA fallbacks;
    // everything else is a missing resource and answers 404.
    not_found_json()
}

/// Fallback mounted inside the nested `/admin` router: it owns every `/admin/*`
/// path that is not an Admin API route. Requests below `/admin/console` get the
/// admin SPA shell (client-side routing decides 404s there); bare `/admin`
/// redirects into the console; anything else under `/admin` is an API typo and
/// answers JSON 404.
pub async fn admin_console_handler(method: Method, OriginalUri(uri): OriginalUri) -> Response {
    let path = uri.path();

    if path == "/admin" || path == "/admin/" {
        if method == Method::GET {
            return Redirect::temporary(ADMIN_CONSOLE_PREFIX).into_response();
        }
        return not_found_json();
    }

    let Some(rest) = path.strip_prefix(ADMIN_CONSOLE_PREFIX).and_then(|r| {
        if r.is_empty() {
            Some("")
        } else {
            r.strip_prefix('/')
        }
    }) else {
        return not_found_json();
    };

    if method != Method::GET && method != Method::HEAD {
        return not_found_json();
    }

    if !rest.is_empty() {
        if let Some(contents) = get_file(rest) {
            let mime = mime_guess::from_path(rest).first_or_octet_stream();
            return ([(header::CONTENT_TYPE, mime.as_ref())], contents).into_response();
        }
        // Missing concrete file (has an extension): 404, never the SPA shell.
        if std::path::Path::new(rest).extension().is_some() {
            return not_found_json();
        }
    }

    spa_fallback_response(get_index_html())
}

fn not_found_json() -> Response {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response()
}

fn spa_fallback_response(contents: Option<&'static [u8]>) -> Response {
    match contents {
        Some(contents) => ([(header::CONTENT_TYPE, "text/html")], contents).into_response(),
        None => (StatusCode::NOT_FOUND, "Web UI not embedded. Build webclientsrc first.")
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use axum::http::Uri;

    #[tokio::test]
    async fn missing_file_fallback() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let response = static_handler(
            State(state.clone()),
            Some(Path("nonexistent".to_string())),
            Extension(ResolvedRealm(None)),
        )
        .await;
        // Unknown extension-less path outside the SPA prefixes -> 404.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = static_handler(
            State(state),
            Some(Path("missing.css".to_string())),
            Extension(ResolvedRealm(None)),
        )
        .await;
        // Has extension -> concrete file -> 404
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn static_file_served() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let response = static_handler(
            State(state),
            Some(Path("index.html".to_string())),
            Extension(ResolvedRealm(None)),
        )
        .await;
        #[cfg(webclient_present)]
        {
            assert_eq!(response.status(), StatusCode::OK);
            let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
            assert_eq!(content_type, "text/html");
        }
        #[cfg(not(webclient_present))]
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn embedded_fonts_served_same_origin() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        for (path, mime) in [
            ("fonts/fonts.css", "text/css"),
            ("fonts/inter-latin.woff2", "font/woff2"),
        ] {
            let response = static_handler(
                State(state.clone()),
                Some(Path(path.to_string())),
                Extension(ResolvedRealm(None)),
            )
            .await;
            #[cfg(webclient_present)]
            {
                assert_eq!(response.status(), StatusCode::OK, "path: {path}");
                let content_type =
                    response.headers().get("content-type").unwrap().to_str().unwrap();
                assert_eq!(content_type, mime, "path: {path}");
            }
            #[cfg(not(webclient_present))]
            {
                let _ = mime;
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }
        }
    }

    #[tokio::test]
    async fn account_api_typo_is_404_not_spa_shell() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let response = static_handler(
            State(state),
            Some(Path("realms/master/account/api/bogus".to_string())),
            Extension(ResolvedRealm(None)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn account_console_route_serves_account_html() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let response = static_handler(
            State(state),
            Some(Path("realms/master/account/security".to_string())),
            Extension(ResolvedRealm(None)),
        )
        .await;
        #[cfg(webclient_present)]
        assert_eq!(response.status(), StatusCode::OK);
        #[cfg(not(webclient_present))]
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_console_routes_serve_spa_shell() {
        for uri in [
            "/admin/console",
            "/admin/console/",
            "/admin/console/users/abc",
        ] {
            let response =
                admin_console_handler(Method::GET, OriginalUri(Uri::try_from(uri).unwrap())).await;
            #[cfg(webclient_present)]
            assert_eq!(response.status(), StatusCode::OK, "uri: {uri}");
            #[cfg(not(webclient_present))]
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "uri: {uri}");
        }
    }

    #[tokio::test]
    async fn admin_console_rejects_api_typos_and_missing_files() {
        // API typo under /admin (not the console prefix) -> JSON 404
        let response = admin_console_handler(
            Method::GET,
            OriginalUri(Uri::from_static("/admin/bogus-api-path")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Missing concrete asset below the console prefix -> 404
        let response = admin_console_handler(
            Method::GET,
            OriginalUri(Uri::from_static("/admin/console/missing.css")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Non-GET below the console prefix -> 404
        let response = admin_console_handler(
            Method::POST,
            OriginalUri(Uri::from_static("/admin/console/users")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn bare_admin_redirects_to_console() {
        let response =
            admin_console_handler(Method::GET, OriginalUri(Uri::from_static("/admin"))).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get("location").unwrap().to_str().unwrap(),
            ADMIN_CONSOLE_PREFIX
        );
    }

    #[test]
    fn spa_fallback_response_with_contents() {
        let response = spa_fallback_response(Some(b"<html></html>"));
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn spa_fallback_response_without_contents() {
        let response = spa_fallback_response(None);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
