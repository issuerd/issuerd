// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! RFC 9728 OAuth 2.0 Protected Resource Metadata for the realm MCP resources.
//!
//! MCP clients discover the authorization server for a protected resource
//! from this document before starting OAuth. Two routes serve it (both gated
//! by `[mcp] enabled`, default off — a disabled gate answers 404 exactly like
//! an unknown realm, revealing nothing):
//!
//! - `GET /.well-known/oauth-protected-resource` — the bare form, serving the
//!   **master** realm's MCP resource (mirrors how bare
//!   `/.well-known/openid-configuration` falls back to `master` in
//!   [`super::oidc::discovery_handler`]);
//! - `GET /.well-known/oauth-protected-resource/realms/{realm}/mcp` — the
//!   RFC 9728 §3.1 path-inserted form for the resource
//!   `{issuer_url}/realms/{realm}/mcp`.
//!
//! The RealmResolution middleware only extracts realms from `/realms/` and
//! `/admin/realms/` prefixes, so these requests arrive unresolved and the
//! handler resolves the path segment itself. The document is tiny — derived
//! from the config, the realm name, and the shared DPoP alg constant — so it
//! is rendered per request without the discovery cache; the response carries
//! the same JSON content type (and equally no Cache-Control) as the OIDC
//! discovery document.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use tracing::{error, warn};

use issuerd_core::IssuerdError;
use issuerd_protocol::discovery::ProtectedResourceMetadata;

use super::oidc::raw_json_response;
use crate::state::ServerState;

/// The single resource indicator this deployment recognizes
/// (RFC 8707 §2.1): the realm's MCP resource URI — the same derivation the
/// protected-resource metadata document publishes, so the discovery document
/// and the allowlist can never drift apart.
pub(crate) fn realm_mcp_resource(issuer_url: &str, realm_name: &str) -> String {
    ProtectedResourceMetadata::for_realm(issuer_url, realm_name)
        .resource
        .to_string()
}

/// Validate an RFC 8707 `resource` parameter against the realm's allowlist.
///
/// Fail-closed (§2.1): with `[mcp] enabled = false` any present `resource`
/// parameter is rejected with `invalid_target`; with the surface enabled the
/// only accepted value is the realm's MCP resource URI. An absent parameter
/// always passes.
pub(crate) fn validate_resource_param(
    config: &crate::config::ServerConfig,
    realm_name: &str,
    resource: Option<&str>,
) -> Result<(), IssuerdError> {
    let Some(resource) = resource else {
        return Ok(());
    };
    if !config.mcp.enabled {
        return Err(IssuerdError::InvalidTarget(
            "resource indicators are not supported by this server".into(),
        ));
    }
    if resource != realm_mcp_resource(&config.issuer_url, realm_name) {
        return Err(IssuerdError::InvalidTarget("unknown resource".into()));
    }
    Ok(())
}

/// `GET /.well-known/oauth-protected-resource` — bare form: the master
/// realm's MCP resource metadata.
pub async fn protected_resource_metadata_handler(
    State(state): State<Arc<ServerState>>,
) -> Response {
    serve(&state, "master").await
}

/// `GET /.well-known/oauth-protected-resource/realms/{realm}/mcp` — the
/// RFC 9728 §3.1 path-suffixed form for the resource
/// `{issuer_url}/realms/{realm}/mcp`.
pub async fn protected_resource_metadata_realm_handler(
    State(state): State<Arc<ServerState>>,
    Path(realm): Path<String>,
) -> Response {
    serve(&state, &realm).await
}

/// Uniform 404 for a disabled feature gate and an unknown realm alike — a
/// disabled MCP surface must not reveal whether the realm exists.
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not_found"}))).into_response()
}

async fn serve(state: &Arc<ServerState>, realm_segment: &str) -> Response {
    if !state.config.mcp.enabled {
        return not_found();
    }
    match state.resolve_realm(realm_segment).await {
        Ok(Some(realm)) => {
            let metadata =
                ProtectedResourceMetadata::for_realm(&state.config.issuer_url, realm.name.as_str());
            match serde_json::to_vec(&metadata) {
                Ok(body) => raw_json_response(body),
                Err(e) => {
                    error!(
                        realm = %realm.id,
                        error = %e,
                        "protected-resource metadata serialization failed"
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "serialization_failed"})),
                    )
                        .into_response()
                }
            }
        }
        Ok(None) => not_found(),
        Err(e) => {
            warn!(error = %e, "protected-resource metadata: realm resolution failed");
            not_found()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_mcp_resource_matches_metadata_document() {
        assert_eq!(
            realm_mcp_resource("http://localhost:8080", "demo"),
            "http://localhost:8080/realms/demo/mcp"
        );
        // A trailing slash on the issuer URL is trimmed, like the metadata.
        assert_eq!(
            realm_mcp_resource("http://localhost:8080/", "demo"),
            "http://localhost:8080/realms/demo/mcp"
        );
    }

    #[test]
    fn validate_resource_param_absent_always_passes() {
        let config = crate::config::ServerConfig::default();
        assert!(validate_resource_param(&config, "demo", None).is_ok());
    }

    #[test]
    fn validate_resource_param_rejected_when_mcp_disabled() {
        let config = crate::config::ServerConfig::default();
        let err =
            validate_resource_param(&config, "demo", Some("http://localhost:8080/realms/demo/mcp"))
                .unwrap_err();
        assert!(matches!(err, IssuerdError::InvalidTarget(_)));
    }

    #[test]
    fn validate_resource_param_exact_allowlist_match() {
        let mut config = crate::config::ServerConfig::default();
        config.mcp.enabled = true;

        // The realm's MCP resource URI passes...
        assert!(validate_resource_param(
            &config,
            "demo",
            Some("http://localhost:8080/realms/demo/mcp")
        )
        .is_ok());
        // ...but only byte-for-byte: other realms, other paths, trailing
        // slashes, and normalization tricks all fail closed.
        for bad in [
            "http://localhost:8080/realms/other/mcp",
            "http://localhost:8080/realms/demo/mcp/",
            "http://localhost:8080/realms/demo/mcp?x=1",
            "http://localhost:8080/realms/demo",
            "https://localhost:8080/realms/demo/mcp",
        ] {
            let err = validate_resource_param(&config, "demo", Some(bad)).unwrap_err();
            assert!(matches!(err, IssuerdError::InvalidTarget(_)), "accepted {bad}");
            assert_eq!(err.oauth_error_code().as_ref(), "invalid_target");
        }
    }
}
