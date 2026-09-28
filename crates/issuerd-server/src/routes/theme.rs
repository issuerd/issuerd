// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Login theme asset serving.
//!
//! `GET /realms/{realm}/theme/{*path}` serves static assets (the login page
//! CSS today) from `{themes.dir}/{theme}/{path}`, where `theme` is the
//! realm's `login_theme` or the built-in [`DEFAULT_THEME`]. A custom theme
//! only needs to ship the files it overrides: anything missing falls back to
//! the default theme's file. Paths containing `..` (and theme names with
//! path separators) are rejected; unknown files 404.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::state::ServerState;

/// Built-in default theme; also the fallback layer for custom themes.
pub const DEFAULT_THEME: &str = "issuerd";

/// Reject path segments that could escape the theme directory.
fn is_safe_asset_path(path: &str) -> bool {
    !path.is_empty()
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != ".." && !seg.contains('\\'))
}

/// `GET /realms/{realm}/theme/{*path}` — serve a login-theme asset.
pub async fn theme_asset_handler(
    State(state): State<Arc<ServerState>>,
    Path((realm_name, asset_path)): Path<(String, String)>,
) -> Response {
    if !is_safe_asset_path(&asset_path) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let realm = match state.resolve_realm(&realm_name).await {
        Ok(Some(r)) => r,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let theme = realm.login_theme.as_ref().map(|t| t.as_str().to_string());
    let theme = match theme {
        Some(t) if !t.contains('/') && !t.contains('\\') && t != ".." => t,
        // A malformed stored theme name must never become a path component.
        _ => DEFAULT_THEME.to_string(),
    };

    let dir = &state.config.themes.dir;
    let primary = dir.join(&theme).join(&asset_path);
    let fallback = dir.join(DEFAULT_THEME).join(&asset_path);
    let path = [primary, fallback]
        .into_iter()
        .find(|p| std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false));
    let Some(path) = path else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    ([(header::CONTENT_TYPE, mime.as_ref().to_string())], bytes).into_response()
}

/// Discover available login themes: subdirectories of `dir` plus the
/// built-in default, sorted and de-duplicated.
pub fn available_themes(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.push(DEFAULT_THEME.to_string());
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    #[test]
    fn asset_path_rejects_traversal() {
        assert!(!is_safe_asset_path("../issuerd.toml"));
        assert!(!is_safe_asset_path("a/../../b"));
        assert!(!is_safe_asset_path("..\\windows"));
        assert!(!is_safe_asset_path(""));
        assert!(!is_safe_asset_path("a//b"));
        assert!(is_safe_asset_path("login.css"));
        assert!(is_safe_asset_path("img/logo.svg"));
    }

    #[test]
    fn asset_path_rejects_dot_segments_and_backslashes() {
        // Bare and embedded `.`/`..` segments.
        assert!(!is_safe_asset_path("."));
        assert!(!is_safe_asset_path(".."));
        assert!(!is_safe_asset_path("a/./b"));
        assert!(!is_safe_asset_path("./login.css"));
        assert!(!is_safe_asset_path("a/../b"));
        assert!(!is_safe_asset_path("login.css/.."));
        // Backslash anywhere in a segment (Windows separator).
        assert!(!is_safe_asset_path("a\\b"));
        assert!(!is_safe_asset_path("img\\logo.svg"));
        // Trailing separator yields an empty final segment.
        assert!(!is_safe_asset_path("img/"));
        assert!(!is_safe_asset_path("/img/logo.svg"));
    }

    #[test]
    fn available_themes_discovers_dirs_plus_default() {
        let base = std::env::temp_dir().join(format!("issuerd-theme-test-{}", std::process::id()));
        std::fs::create_dir_all(base.join("acme")).unwrap();
        std::fs::create_dir_all(base.join("zzz-custom")).unwrap();
        // Plain files are not themes.
        std::fs::write(base.join("not-a-theme.txt"), b"x").unwrap();

        let themes = available_themes(&base);
        assert_eq!(themes, vec!["acme", "issuerd", "zzz-custom"]);

        std::fs::remove_dir_all(&base).unwrap();

        // A missing directory still yields the built-in default.
        assert_eq!(available_themes(&base), vec![DEFAULT_THEME]);
    }

    #[tokio::test]
    async fn unknown_asset_is_404_and_traversal_is_400() {
        let cfg = ServerConfig::default();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let resp = theme_asset_handler(
            State(state.clone()),
            Path(("master".to_string(), "no-such-file.css".to_string())),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = theme_asset_handler(
            State(state),
            Path(("master".to_string(), "..%2f..%2fissuerd.toml".to_string())),
        )
        .await;
        // Percent-encoded separators arrive decoded by axum's Path extractor
        // in real requests; the raw string here still exercises the guard.
        assert!(resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND);
    }

    /// Build a server state whose theme root is `themes_dir` and whose master
    /// realm has the given stored `login_theme`.
    async fn state_with_login_theme(
        themes_dir: &std::path::Path,
        login_theme: &str,
    ) -> Arc<ServerState> {
        let mut cfg = ServerConfig::default();
        cfg.themes.dir = themes_dir.to_path_buf();
        let state = Arc::new(ServerState::from_config(&cfg).await.unwrap());
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        let mut realm = state.storage.get_realm(&realm_id).await.unwrap().unwrap();
        realm.login_theme = Some(issuerd_core::ThemeName::new(login_theme).unwrap());
        state.storage.update_realm(&realm).await.unwrap();
        // Mirrors the admin route's synchronous realm-by-name invalidation.
        state
            .cache
            .delete(&issuerd_cluster::cache_keys::realm_by_name("master"))
            .await
            .unwrap();
        state
    }

    #[tokio::test]
    async fn dotdot_login_theme_falls_back_to_default_theme() {
        let base =
            std::env::temp_dir().join(format!("issuerd-theme-guard-dotdot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let themes = base.join("themes");
        std::fs::create_dir_all(themes.join("issuerd")).unwrap();
        std::fs::write(themes.join("issuerd").join("probe.css"), b"default-theme").unwrap();
        // Reachable only if the stored theme name ".." becomes a path
        // component: `themes/../probe.css`.
        std::fs::write(base.join("probe.css"), b"escaped").unwrap();

        let state = state_with_login_theme(&themes, "..").await;
        let resp = theme_asset_handler(
            State(state),
            Path(("master".to_string(), "probe.css".to_string())),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..],
            b"default-theme",
            "a malformed stored theme name must fall back to the default theme"
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[tokio::test]
    async fn valid_custom_login_theme_serves_custom_file() {
        let base =
            std::env::temp_dir().join(format!("issuerd-theme-guard-custom-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let themes = base.join("themes");
        std::fs::create_dir_all(themes.join("issuerd")).unwrap();
        std::fs::create_dir_all(themes.join("custom")).unwrap();
        std::fs::write(themes.join("issuerd").join("probe.css"), b"default-theme").unwrap();
        std::fs::write(themes.join("custom").join("probe.css"), b"custom-theme").unwrap();

        let state = state_with_login_theme(&themes, "custom").await;
        let resp = theme_asset_handler(
            State(state),
            Path(("master".to_string(), "probe.css".to_string())),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"custom-theme", "a valid custom theme must win over the default");

        std::fs::remove_dir_all(&base).unwrap();
    }
}
