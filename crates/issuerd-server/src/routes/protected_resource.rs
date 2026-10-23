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

use issuerd_protocol::discovery::ProtectedResourceMetadata;

use super::oidc::raw_json_response;
use crate::state::ServerState;

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
