// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt as _;
use issuerd_core::{AccessTokenClaims, IssuerdError, Realm};
use issuerd_mcp::{
    transport::{
        validate_host_and_origin, IssuerdStreamableHttpService, McpTransportConfig,
        MAX_REQUEST_BODY_BYTES,
    },
    McpAuthContext, McpError, McpRateLimiter, McpToolExecutor,
};
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, ErrorData, GetMeta, JsonRpcError, ProtocolVersion,
    RequestId,
};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tower::Service as _;

use super::{
    oidc::{
        enforce_mcp_token_validity, resolve_mcp_azp_client, resolve_mcp_token_user, McpTokenError,
    },
    protected_resource::{realm_mcp_metadata_url, realm_mcp_resource},
};
use crate::{
    challenges::{
        insufficient_scope_challenge_for_scheme, invalid_dpop_proof_challenge,
        invalid_token_challenge_for_scheme, no_credentials_challenge, use_dpop_nonce_challenge,
        ChallengeScheme,
    },
    dpop::{verify_mcp_proof_header, DpopRejection, DPOP_NONCE_HEADER},
    state::ServerState,
};

const MCP_PROTOCOL_VERSION: &str = "MCP-Protocol-Version";
const MCP_METHOD: &str = "Mcp-Method";
const MCP_NAME: &str = "Mcp-Name";
const BASE64_HEADER_PREFIX: &str = "=?base64?";
const BASE64_HEADER_SUFFIX: &str = "?=";
const MODERN_VERSION: &str = "2026-07-28";

pub fn mount(
    router: Router<Arc<ServerState>>,
    state: &Arc<ServerState>,
    admin_state: Arc<issuerd_admin_api::state::AdminApiState>,
) -> Router<Arc<ServerState>> {
    mount_with_response_mode(router, state, admin_state, true)
}

fn mount_with_response_mode(
    router: Router<Arc<ServerState>>,
    state: &Arc<ServerState>,
    admin_state: Arc<issuerd_admin_api::state::AdminApiState>,
    json_response: bool,
) -> Router<Arc<ServerState>> {
    if !state.config.mcp.enabled {
        return router.route("/realms/{realm}/mcp", any(disabled_handler));
    }
    let adapter = Arc::new(
        McpHttpAdapter::new(Arc::clone(state), admin_state, json_response)
            .expect("invalid [mcp] transport configuration"),
    );
    router.route(
        "/realms/{realm}/mcp",
        any(move |request: Request| {
            let adapter = Arc::clone(&adapter);
            async move { adapter.handle(request).await }
        }),
    )
}

async fn disabled_handler() -> StatusCode {
    StatusCode::NOT_FOUND
}

struct McpHttpAdapter {
    state: Arc<ServerState>,
    executor: Arc<McpToolExecutor>,
    transport_config: McpTransportConfig,
    service: IssuerdStreamableHttpService,
}

impl McpHttpAdapter {
    fn new(
        state: Arc<ServerState>,
        admin_state: Arc<issuerd_admin_api::state::AdminApiState>,
        json_response: bool,
    ) -> Result<Self, McpError> {
        let transport_config = McpTransportConfig::for_issuer(
            &state.config.issuer_url,
            state.config.mcp.allowed_origins.clone(),
            CancellationToken::new(),
        )?;
        let executor = Arc::new(
            McpToolExecutor::new(
                Arc::clone(&state.storage),
                McpRateLimiter::new(
                    Arc::clone(&state.cache),
                    u64::from(state.config.mcp.invocation_rate_limit_per_minute),
                ),
            )
            .with_application_service(Arc::new(
                crate::mcp_service::ServerMcpApplicationService::new(
                    admin_state,
                    Arc::clone(&state),
                ),
            )),
        );
        let service = issuerd_mcp::transport::streamable_http_service_with_json_response(
            Arc::clone(&executor),
            transport_config.clone(),
            json_response,
        )?;
        Ok(Self {
            state,
            executor,
            transport_config,
            service,
        })
    }

    async fn handle(&self, request: Request) -> Response {
        if let Err(error) =
            validate_host_and_origin(&self.transport_config, request.uri(), request.headers())
        {
            return finalize_response(
                AdapterError::text(error.status(), error.message()).into_response(),
                None,
            );
        }
        if request.method() != Method::POST {
            return self.call_sdk(request, None).await;
        }
        if let Err(error) = validate_post_headers(request.headers()) {
            return finalize_response(error.into_response(), None);
        }

        let (mut parts, body) = request.into_parts();
        let body = match read_post_body(body).await {
            Ok(body) => body,
            Err(error) => return finalize_response(error.into_response(), None),
        };
        let validated = match validate_post(&parts.headers, body) {
            Ok(validated) => validated,
            Err(error) => return finalize_response(error.into_response(), None),
        };
        let target_realm = match resolve_target_realm(&self.state, &parts.uri).await {
            Ok(realm) => realm,
            Err(response) => return finalize_response(*response, None),
        };
        let resource =
            realm_mcp_resource(&self.state.config.issuer_url, target_realm.name.as_str());
        let metadata =
            realm_mcp_metadata_url(&self.state.config.issuer_url, target_realm.name.as_str());
        let authenticated =
            match self.authenticate(&parts.headers, &target_realm, &resource, &metadata).await {
                Ok(authenticated) => authenticated,
                Err(error) => {
                    let (response, nonce) = *error;
                    return finalize_response(response, nonce.as_deref());
                }
            };
        let response_nonce = authenticated.response_nonce;

        if let Some(tool_name) = validated.tool_name.as_deref() {
            match self
                .executor
                .preflight(
                    tool_name,
                    authenticated.context.clone(),
                    issuerd_core::utils::now_secs(),
                )
                .await
            {
                Ok(permit) => {
                    parts.extensions.insert(authenticated.context);
                    parts.extensions.insert(permit);
                }
                Err(McpError::UnknownTool(name)) => {
                    let status = if validated.modern {
                        StatusCode::NOT_FOUND
                    } else {
                        StatusCode::OK
                    };
                    let response = json_error(
                        status,
                        validated.id,
                        ErrorData::new(
                            rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                            format!("unknown tool: {name}"),
                            None,
                        ),
                    )
                    .into_response();
                    return finalize_response(response, response_nonce.as_deref());
                }
                Err(error) => {
                    let response = preflight_error_response(error, authenticated.scheme, &metadata);
                    return finalize_response(response, response_nonce.as_deref());
                }
            }
        } else {
            parts.extensions.insert(authenticated.context);
        }

        let request = Request::from_parts(parts, Body::from(validated.body));
        self.call_sdk(request, response_nonce.as_deref()).await
    }

    async fn authenticate(
        &self,
        headers: &HeaderMap,
        target_realm: &Realm,
        resource: &str,
        metadata: &str,
    ) -> AuthResult<AuthenticatedRequest> {
        let credential = match parse_authorization(headers, self.state.config.mcp.require_dpop) {
            Ok(Some(credential)) => credential,
            Ok(None) => {
                return Err(auth_error(
                    no_credentials_challenge(metadata, self.state.config.mcp.require_dpop),
                    None,
                ));
            }
            Err(scheme) => {
                return Err(auth_error(
                    invalid_token_challenge_for_scheme(scheme, metadata, None),
                    None,
                ));
            }
        };
        let scheme = credential.scheme;
        let invalid_token =
            || auth_error(invalid_token_challenge_for_scheme(scheme, metadata, None), None);
        let validated =
            self.state
                .token_service
                .validate_access_token(&credential.token)
                .map_err(|error| match error {
                    IssuerdError::ServerError(_)
                    | IssuerdError::KeyEncryption(_)
                    | IssuerdError::TemporarilyUnavailable => {
                        auth_error(service_unavailable(), None)
                    }
                    _ => invalid_token(),
                })?;
        let claims = validated.claims;
        let validity = enforce_mcp_token_validity(&self.state, &credential.token, &claims)
            .await
            .map_err(|error| token_error(error, metadata, scheme))?;
        if validity.realm.id != target_realm.id
            || claims.resource.as_deref() != Some(resource)
            || !claims.aud.contains(resource)
        {
            return Err(invalid_token());
        }
        let user = resolve_mcp_token_user(&self.state, &validity)
            .await
            .map_err(|error| token_error(error, metadata, scheme))?;
        let client = resolve_mcp_azp_client(&self.state, &validity, &claims)
            .await
            .map_err(|error| token_error(error, metadata, scheme))?;
        let context = McpAuthContext {
            realm_id: target_realm.id.clone(),
            realm_name: target_realm.name.clone(),
            user_id: user.id,
            azp: client.client_id,
            claims: claims.clone(),
        };

        let response_nonce = self
            .enforce_dpop(headers, target_realm, resource, metadata, &credential, &claims)
            .await?;
        Ok(AuthenticatedRequest {
            context,
            scheme,
            response_nonce,
        })
    }

    async fn enforce_dpop(
        &self,
        headers: &HeaderMap,
        target_realm: &Realm,
        resource: &str,
        metadata: &str,
        credential: &Credential,
        claims: &AccessTokenClaims,
    ) -> AuthResult<Option<String>> {
        let invalid_token = || {
            auth_error(invalid_token_challenge_for_scheme(credential.scheme, metadata, None), None)
        };
        if self.state.config.mcp.require_dpop && credential.scheme != ChallengeScheme::Dpop {
            if claims.cnf.is_some() {
                return Err(invalid_token());
            }
            return Err(auth_error(invalid_dpop_proof_challenge(metadata, None), None));
        }
        match credential.scheme {
            ChallengeScheme::Bearer => {
                if claims.cnf.is_some() {
                    return Err(invalid_token());
                }
                return Ok(None);
            }
            ChallengeScheme::Dpop if claims.cnf.is_none() => return Err(invalid_token()),
            ChallengeScheme::Dpop => {}
        }

        let verification = verify_mcp_proof_header(
            &self.state,
            &target_realm.id,
            headers,
            "POST",
            resource,
            Some(&credential.token),
        )
        .await
        .map_err(|error| match error {
            DpopRejection::UseDpopNonce(nonce) => {
                auth_error(use_dpop_nonce_challenge(metadata, &nonce, None), None)
            }
            DpopRejection::TemporarilyUnavailable => auth_error(service_unavailable(), None),
            DpopRejection::InvalidProof(response_nonce) => {
                auth_error(invalid_dpop_proof_challenge(metadata, None), response_nonce)
            }
        })?;
        let response_nonce = verification.response_nonce;
        let Some(proof) = verification.proof else {
            return Err(auth_error(invalid_dpop_proof_challenge(metadata, None), None));
        };
        if claims.cnf.as_ref().map(|cnf| &cnf.jkt) != Some(&proof.jkt) {
            return Err(auth_error(
                invalid_token_challenge_for_scheme(credential.scheme, metadata, None),
                response_nonce,
            ));
        }
        Ok(response_nonce)
    }

    async fn call_sdk(&self, request: Request, response_nonce: Option<&str>) -> Response {
        let mut service = self.service.clone();
        let response = match service.call(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        };
        let (parts, body) = response.into_parts();
        finalize_response(Response::from_parts(parts, Body::new(body)), response_nonce)
    }
}

struct AuthenticatedRequest {
    context: McpAuthContext,
    scheme: ChallengeScheme,
    response_nonce: Option<String>,
}

#[derive(Debug)]
struct Credential {
    scheme: ChallengeScheme,
    token: String,
}

fn parse_authorization(
    headers: &HeaderMap,
    require_dpop: bool,
) -> Result<Option<Credential>, ChallengeScheme> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    let fallback = if require_dpop {
        ChallengeScheme::Dpop
    } else {
        ChallengeScheme::Bearer
    };
    let hinted_scheme = authorization_scheme(first).unwrap_or(fallback);
    if values.next().is_some() {
        return Err(hinted_scheme);
    }
    let value = first.to_str().ok().and_then(|value| {
        let mut fields = value.split_whitespace();
        let scheme = fields.next()?;
        let token = fields.next()?;
        if fields.next().is_some() || token.is_empty() {
            return None;
        }
        let scheme = if scheme.eq_ignore_ascii_case("bearer") {
            ChallengeScheme::Bearer
        } else if scheme.eq_ignore_ascii_case("dpop") {
            ChallengeScheme::Dpop
        } else {
            return None;
        };
        Some(Credential {
            scheme,
            token: token.to_string(),
        })
    });
    match value {
        Some(credential) => Ok(Some(credential)),
        None => Err(hinted_scheme),
    }
}

fn authorization_scheme(value: &HeaderValue) -> Option<ChallengeScheme> {
    let scheme = value.to_str().ok()?.split_whitespace().next()?;
    if scheme.eq_ignore_ascii_case("bearer") {
        Some(ChallengeScheme::Bearer)
    } else if scheme.eq_ignore_ascii_case("dpop") {
        Some(ChallengeScheme::Dpop)
    } else {
        None
    }
}

type AuthError = Box<(Response, Option<String>)>;
type AuthResult<T> = Result<T, AuthError>;

fn auth_error(response: Response, nonce: Option<String>) -> AuthError {
    Box::new((response, nonce))
}

fn token_error(error: McpTokenError, metadata: &str, scheme: ChallengeScheme) -> AuthError {
    let response = match error {
        McpTokenError::InvalidToken => invalid_token_challenge_for_scheme(scheme, metadata, None),
        McpTokenError::DisabledUser | McpTokenError::DisabledClient => {
            StatusCode::FORBIDDEN.into_response()
        }
        McpTokenError::TemporarilyUnavailable => service_unavailable(),
    };
    auth_error(response, None)
}

fn preflight_error_response(error: McpError, scheme: ChallengeScheme, metadata: &str) -> Response {
    match error {
        McpError::MissingScope(scope) => {
            insufficient_scope_challenge_for_scheme(scheme, &[scope], metadata)
        }
        McpError::MissingRole { .. } => StatusCode::FORBIDDEN.into_response(),
        McpError::RateLimited { retry_after_secs } => {
            let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
            if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        McpError::TemporarilyUnavailable(_) | McpError::Backend(_) => service_unavailable(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn resolve_target_realm(state: &Arc<ServerState>, uri: &Uri) -> Result<Realm, Box<Response>> {
    let Some(segment) = uri
        .path()
        .strip_prefix("/realms/")
        .and_then(|path| path.strip_suffix("/mcp"))
        .filter(|segment| !segment.is_empty() && !segment.contains('/'))
    else {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    };
    let Ok(decoded) = issuerd_core::urls::decode_realm_segment(segment) else {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    };
    match state.resolve_realm(segment).await {
        Ok(Some(realm)) if realm.name == decoded => Ok(realm),
        Ok(_) => Err(Box::new(StatusCode::NOT_FOUND.into_response())),
        Err(error) => {
            tracing::warn!(error = %error, "MCP target realm resolution failed");
            Err(Box::new(service_unavailable()))
        }
    }
}

fn service_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({"error": "temporarily_unavailable"})),
    )
        .into_response()
}

fn finalize_response(mut response: Response, response_nonce: Option<&str>) -> Response {
    response.headers_mut().remove("mcp-session-id");
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if let Some(nonce) = response_nonce {
        if let Ok(value) = HeaderValue::from_str(nonce) {
            response.headers_mut().insert(DPOP_NONCE_HEADER, value);
        }
    }
    response
}

#[derive(Debug)]
struct AdapterError {
    status: StatusCode,
    content_type: Option<&'static str>,
    body: Bytes,
}

impl AdapterError {
    fn text(status: StatusCode, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: None,
            body: Bytes::from(body.into()),
        }
    }

    fn into_response(self) -> Response {
        let mut builder = Response::builder().status(self.status);
        if let Some(content_type) = self.content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        builder.body(Body::from(self.body)).expect("valid MCP error response")
    }
}

fn json_error(status: StatusCode, id: Option<RequestId>, error: ErrorData) -> AdapterError {
    let body = serde_json::to_vec(&JsonRpcError::new(id, error)).expect("serialize JSON-RPC error");
    AdapterError {
        status,
        content_type: Some("application/json"),
        body: Bytes::from(body),
    }
}

fn header_mismatch(id: Option<RequestId>, message: impl Into<String>) -> AdapterError {
    json_error(StatusCode::BAD_REQUEST, id, ErrorData::header_mismatch(message.into(), None))
}

fn invalid_params(id: Option<RequestId>, message: impl Into<String>) -> AdapterError {
    json_error(StatusCode::BAD_REQUEST, id, ErrorData::invalid_params(message.into(), None))
}

fn unsupported_version(id: Option<RequestId>, requested: &str) -> AdapterError {
    json_error(
        StatusCode::BAD_REQUEST,
        id,
        ErrorData::unsupported_protocol_version(
            protocol_version(requested),
            issuerd_mcp::server::SUPPORTED_PROTOCOL_VERSIONS,
        ),
    )
}

fn protocol_version(version: &str) -> ProtocolVersion {
    serde_json::from_value(Value::String(version.to_string()))
        .expect("a string is a protocol version")
}

fn is_supported_version(version: &str) -> bool {
    issuerd_mcp::server::SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .any(|supported| supported.as_str() == version)
}

fn validate_post_headers(headers: &HeaderMap) -> Result<(), AdapterError> {
    issuerd_mcp::transport::validate_post_media_headers(headers)
        .map_err(|error| AdapterError::text(error.status(), error.message()))
}

async fn read_post_body(body: Body) -> Result<Bytes, AdapterError> {
    let mut collected = BytesMut::new();
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            AdapterError::text(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read request body: {error}"),
            )
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if data.len() > MAX_REQUEST_BODY_BYTES.saturating_sub(collected.len()) {
            return Err(AdapterError::text(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Payload Too Large: request body exceeds {MAX_REQUEST_BODY_BYTES} bytes"),
            ));
        }
        collected.extend_from_slice(&data);
    }
    Ok(collected.freeze())
}

#[derive(Debug)]
struct ValidatedRequest {
    id: Option<RequestId>,
    tool_name: Option<String>,
    modern: bool,
    body: Bytes,
}

fn validate_post(headers: &HeaderMap, body: Bytes) -> Result<ValidatedRequest, AdapterError> {
    validate_post_headers(headers)?;
    let value = issuerd_mcp::json::parse(&body).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            None,
            ErrorData::parse_error("Invalid JSON or duplicate object key", None),
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            None,
            ErrorData::invalid_request(
                "expected one JSON-RPC object; batches are not supported",
                None,
            ),
        )
    })?;
    let message = serde_json::from_slice::<ClientJsonRpcMessage>(&body).map_err(|error| {
        AdapterError::text(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("fail to deserialize request body {error}"),
        )
    })?;

    let mut id = None;
    let mut initialize = false;
    let mut discover = false;
    let mut initialize_version = None;
    let mut meta_version = None;
    let mut missing_meta = Vec::new();
    let mut tool_name = None;
    if let ClientJsonRpcMessage::Request(request) = &message {
        id = Some(request.id.clone());
        if let ClientRequest::InitializeRequest(request) = &request.request {
            initialize = true;
            initialize_version = Some(request.params.protocol_version.as_str().to_string());
        }
        discover = matches!(request.request, ClientRequest::DiscoverRequest(_));
        if let ClientRequest::CallToolRequest(request) = &request.request {
            tool_name = Some(request.params.name.to_string());
        }
        let meta = request.request.get_meta();
        meta_version = meta.protocol_version().map(|version| version.as_str().to_string());
        missing_meta = meta.missing_required_keys(&ProtocolVersion::V_2026_07_28);
    }
    let method = object.get("method").and_then(Value::as_str);
    let params = object.get("params");
    if method == Some("tools/call") {
        let parsed = serde_json::from_value::<rmcp::model::CallToolRequestParams>(
            params.cloned().unwrap_or(Value::Null),
        )
        .map_err(|error| {
            AdapterError::text(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("fail to deserialize request body {error}"),
            )
        })?;
        tool_name = Some(parsed.name.to_string());
    }

    if initialize {
        validate_initialize(
            headers,
            initialize_version.as_deref().unwrap_or_default(),
            id.clone(),
        )?;
        return Ok(ValidatedRequest {
            id,
            tool_name: None,
            modern: false,
            body,
        });
    }

    let header_version = match single_header(headers, MCP_PROTOCOL_VERSION) {
        Ok(Some(version)) => version,
        Ok(None) => {
            let message = if meta_version.is_some() {
                "request _meta protocolVersion requires MCP-Protocol-Version header"
            } else {
                "Missing MCP-Protocol-Version header for request requiring per-request protocol metadata"
            };
            return Err(header_mismatch(id, message));
        }
        Err(message) => return Err(header_mismatch(id, message)),
    };
    if !is_supported_version(header_version) {
        return Err(unsupported_version(id, header_version));
    }
    validate_standard_headers(headers, header_version, method, params, id.clone())?;

    if let Some(meta_version) = meta_version.as_deref() {
        if header_version != meta_version {
            return Err(header_mismatch(
                id,
                format!(
                    "MCP-Protocol-Version header ({header_version}) does not match request _meta protocolVersion ({meta_version})"
                ),
            ));
        }
    } else if matches!(&message, ClientJsonRpcMessage::Request(_))
        && (discover || header_version >= MODERN_VERSION)
    {
        return Err(invalid_params(
            id,
            format!(
                "Invalid params: request _meta is missing or has malformed required fields: {}",
                missing_meta.join(", ")
            ),
        ));
    }
    if meta_version.is_some() && !missing_meta.is_empty() {
        return Err(invalid_params(
            id,
            format!(
                "request _meta is missing or has malformed required fields: {}",
                missing_meta.join(", ")
            ),
        ));
    }
    if let Some(meta_version) = meta_version.as_deref() {
        if !is_supported_version(meta_version) {
            return Err(unsupported_version(id, meta_version));
        }
    }
    if matches!(message, ClientJsonRpcMessage::Response(_) | ClientJsonRpcMessage::Error(_)) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            None,
            ErrorData::invalid_request("stateless server does not accept JSON-RPC responses", None),
        ));
    }

    if method == Some("tools/call") && !matches!(&message, ClientJsonRpcMessage::Request(_)) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            id,
            ErrorData::invalid_request("tools/call requires a JSON-RPC request id", None),
        ));
    }

    Ok(ValidatedRequest {
        id,
        tool_name,
        modern: meta_version.is_some() || discover,
        body,
    })
}

fn validate_initialize(
    headers: &HeaderMap,
    body_version: &str,
    id: Option<RequestId>,
) -> Result<(), AdapterError> {
    if let Some(header_version) =
        single_header(headers, MCP_PROTOCOL_VERSION).map_err(|message| {
            json_error(
                StatusCode::BAD_REQUEST,
                id.clone(),
                ErrorData::invalid_request(message, None),
            )
        })?
    {
        if header_version != body_version {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                id,
                ErrorData::invalid_request(
                    format!(
                        "Invalid Request: MCP-Protocol-Version header ({header_version}) does not match initialize params.protocolVersion ({body_version})"
                    ),
                    None,
                ),
            ));
        }
        if header_version >= MODERN_VERSION {
            validate_initialize_method_header(headers, id)?;
        }
    }
    Ok(())
}

fn validate_initialize_method_header(
    headers: &HeaderMap,
    id: Option<RequestId>,
) -> Result<(), AdapterError> {
    match single_header(headers, MCP_METHOD) {
        Ok(None) => Ok(()),
        Ok(Some("initialize")) => Ok(()),
        Ok(Some(method)) => Err(header_mismatch(
            id,
            format!("Mcp-Method header `{method}` does not match body method `initialize`"),
        )),
        Err(message) => Err(header_mismatch(id, message)),
    }
}

fn validate_standard_headers(
    headers: &HeaderMap,
    version: &str,
    method: Option<&str>,
    params: Option<&Value>,
    id: Option<RequestId>,
) -> Result<(), AdapterError> {
    if version < MODERN_VERSION {
        return Ok(());
    }
    let Some(method) = method else {
        return Ok(());
    };
    match single_header(headers, MCP_METHOD) {
        Ok(Some(actual)) if actual == method => {}
        Ok(Some(actual)) => {
            return Err(header_mismatch(
                id,
                format!("Mcp-Method header `{actual}` does not match body method `{method}`"),
            ));
        }
        Ok(None) => return Err(header_mismatch(id, "missing required Mcp-Method header")),
        Err(message) => return Err(header_mismatch(id, message)),
    }
    if let Some(expected) = expected_mcp_name(method, params) {
        match single_header(headers, MCP_NAME) {
            Ok(Some(raw)) => {
                let decoded = decode_header_value(raw).ok_or_else(|| {
                    header_mismatch(id.clone(), "Mcp-Name header is not valid Base64")
                })?;
                if decoded != expected {
                    return Err(header_mismatch(
                        id,
                        format!(
                            "Mcp-Name header `{decoded}` does not match body value `{expected}`"
                        ),
                    ));
                }
            }
            Ok(None) => {
                return Err(header_mismatch(
                    id,
                    format!("missing required Mcp-Name header for `{method}`"),
                ));
            }
            Err(message) => return Err(header_mismatch(id, message)),
        }
    }
    Ok(())
}

fn expected_mcp_name(method: &str, params: Option<&Value>) -> Option<String> {
    let key = match method {
        "tools/call" | "prompts/get" => "name",
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => "uri",
        "tasks/get" | "tasks/update" | "tasks/cancel" => "taskId",
        _ => return None,
    };
    params?.get(key)?.as_str().map(str::to_string)
}

fn decode_header_value(value: &str) -> Option<String> {
    match value
        .strip_prefix(BASE64_HEADER_PREFIX)
        .and_then(|inner| inner.strip_suffix(BASE64_HEADER_SUFFIX))
    {
        Some(inner) => String::from_utf8(BASE64_STANDARD.decode(inner).ok()?).ok(),
        None => Some(value.to_string()),
    }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, String> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(format!("duplicate {name} header"));
    }
    Ok(Some(value.to_str().map_err(|_| format!("invalid {name} header encoding"))?))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use issuerd_core::{
        AuthMethod, RealmAccess, RoleName, SessionId, User, UserId, UserSession, Username,
    };
    use serde_json::json;

    fn headers(version: Option<&str>, method: Option<&str>, name: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(version) = version {
            headers.insert(MCP_PROTOCOL_VERSION, version.parse().unwrap());
        }
        if let Some(method) = method {
            headers.insert(MCP_METHOD, method.parse().unwrap());
        }
        if let Some(name) = name {
            headers.insert(MCP_NAME, name.parse().unwrap());
        }
        headers
    }

    fn modern_body(method: &str, mut params: Value) -> String {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        json!({"jsonrpc":"2.0","id":7,"method":method,"params":params}).to_string()
    }

    fn validate(body: &str, headers: &HeaderMap) -> Result<ValidatedRequest, AdapterError> {
        validate_post(headers, Bytes::from(body.to_string()))
    }

    fn assert_rpc_error(
        result: Result<ValidatedRequest, AdapterError>,
        status: StatusCode,
        code: i32,
    ) -> AdapterError {
        let error = result.expect_err("expected structural rejection");
        assert_eq!(error.status, status);
        let body: Value = serde_json::from_slice(&error.body).unwrap();
        assert_eq!(body["error"]["code"], code, "{body}");
        error
    }

    #[test]
    fn legacy_versions_are_explicit_and_initialize_keeps_negotiation() {
        let body = r#" {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}} "#;
        assert_rpc_error(
            validate(body, &headers(None, None, None)),
            StatusCode::BAD_REQUEST,
            -32020,
        );
        let error = assert_rpc_error(
            validate(body, &headers(Some("2025-03-26"), None, None)),
            StatusCode::BAD_REQUEST,
            -32022,
        );
        let body_json: Value = serde_json::from_slice(&error.body).unwrap();
        assert_eq!(body_json["error"]["data"]["requested"], "2025-03-26");
        assert_eq!(
            body_json["error"]["data"]["supported"],
            json!(["2025-06-18", "2025-11-25", "2026-07-28"])
        );

        for version in ["2025-06-18", "2025-11-25"] {
            let validated = validate(body, &headers(Some(version), None, None)).unwrap();
            assert!(!validated.modern);
            assert_eq!(validated.body, Bytes::from(body));
        }

        let initialize = json!({
            "jsonrpc":"2.0","id":2,"method":"initialize","params":{
                "protocolVersion":"2025-03-26",
                "capabilities":{},
                "clientInfo":{"name":"test","version":"1"}
            }
        })
        .to_string();
        assert!(validate(&initialize, &headers(None, None, None)).is_ok());
        let mismatch = initialize.replace("2025-03-26", "2025-06-18");
        assert_rpc_error(
            validate(&mismatch, &headers(Some("2025-11-25"), None, None)),
            StatusCode::BAD_REQUEST,
            -32600,
        );
    }

    #[test]
    fn modern_meta_and_standard_header_errors_follow_rmcp_shapes_and_order() {
        let missing_meta = json!({
            "jsonrpc":"2.0","id":7,"method":"tools/list","params":{}
        })
        .to_string();
        assert_rpc_error(
            validate(&missing_meta, &headers(Some(MODERN_VERSION), Some("tools/list"), None)),
            StatusCode::BAD_REQUEST,
            -32602,
        );

        let modern = modern_body("tools/list", json!({}));
        let valid =
            validate(&modern, &headers(Some(MODERN_VERSION), Some("tools/list"), None)).unwrap();
        assert!(valid.modern);

        let without_capabilities =
            modern.replace("\"io.modelcontextprotocol/clientCapabilities\":{}", "\"other\":true");
        let error = assert_rpc_error(
            validate(
                &without_capabilities,
                &headers(Some(MODERN_VERSION), Some("tools/list"), None),
            ),
            StatusCode::BAD_REQUEST,
            -32602,
        );
        let message: Value = serde_json::from_slice(&error.body).unwrap();
        assert!(message["error"]["message"]
            .as_str()
            .unwrap()
            .contains("io.modelcontextprotocol/clientCapabilities"));

        let without_method = headers(Some(MODERN_VERSION), None, None);
        let error = assert_rpc_error(
            validate(&without_capabilities, &without_method),
            StatusCode::BAD_REQUEST,
            -32020,
        );
        let message: Value = serde_json::from_slice(&error.body).unwrap();
        assert!(message["error"]["message"].as_str().unwrap().contains("Mcp-Method"));

        let error = assert_rpc_error(
            validate(&modern, &headers(None, Some("tools/list"), None)),
            StatusCode::BAD_REQUEST,
            -32020,
        );
        let message: Value = serde_json::from_slice(&error.body).unwrap();
        assert!(message["error"]["message"]
            .as_str()
            .unwrap()
            .contains("requires MCP-Protocol-Version header"));

        let mismatched = modern.replace("2026-07-28", "2025-11-25");
        assert_rpc_error(
            validate(&mismatched, &headers(Some(MODERN_VERSION), Some("tools/list"), None)),
            StatusCode::BAD_REQUEST,
            -32020,
        );

        let notification = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(validate(
            notification,
            &headers(Some(MODERN_VERSION), Some("notifications/initialized"), None,),
        )
        .is_ok());

        let unsupported = modern.replace("2026-07-28", "2099-01-01");
        let error = assert_rpc_error(
            validate(&unsupported, &headers(Some("2099-01-01"), Some("tools/list"), None)),
            StatusCode::BAD_REQUEST,
            -32022,
        );
        let body: Value = serde_json::from_slice(&error.body).unwrap();
        assert_eq!(body["error"]["data"]["requested"], "2099-01-01");
    }

    #[test]
    fn modern_tool_name_uses_rmcp_base64_decoding_and_singleton_headers() {
        let body = modern_body("tools/call", json!({"name":"realm_get","arguments":{}}));
        assert_rpc_error(
            validate(&body, &headers(Some(MODERN_VERSION), Some("tools/call"), None)),
            StatusCode::BAD_REQUEST,
            -32020,
        );
        assert_rpc_error(
            validate(&body, &headers(Some(MODERN_VERSION), Some("tools/call"), Some("users_get"))),
            StatusCode::BAD_REQUEST,
            -32020,
        );
        let encoded = "=?base64?cmVhbG1fZ2V0?=";
        let validated =
            validate(&body, &headers(Some(MODERN_VERSION), Some("tools/call"), Some(encoded)))
                .unwrap();
        assert_eq!(validated.tool_name.as_deref(), Some("realm_get"));
        assert_rpc_error(
            validate(
                &body,
                &headers(Some(MODERN_VERSION), Some("tools/call"), Some("=?base64?!!!?=")),
            ),
            StatusCode::BAD_REQUEST,
            -32020,
        );

        let mut duplicate = headers(Some(MODERN_VERSION), Some("tools/call"), Some("realm_get"));
        duplicate.append(MCP_METHOD, "tools/list".parse().unwrap());
        assert_rpc_error(validate(&body, &duplicate), StatusCode::BAD_REQUEST, -32020);
    }

    #[test]
    fn duplicate_json_batch_and_malformed_calls_cannot_reach_policy() {
        let duplicate = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"realm_get","arguments":{"x":1,"x":2}}}"#;
        assert_rpc_error(
            validate(duplicate, &headers(Some("2025-11-25"), None, None)),
            StatusCode::BAD_REQUEST,
            -32700,
        );
        assert_rpc_error(
            validate(
                r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
                &headers(Some("2025-11-25"), None, None),
            ),
            StatusCode::BAD_REQUEST,
            -32600,
        );
        let malformed_call =
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}"#;
        let error = validate(malformed_call, &headers(Some("2025-11-25"), None, None)).unwrap_err();
        assert_eq!(error.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(String::from_utf8_lossy(&error.body).contains("fail to deserialize request body"));

        let legacy_notification = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"realm_get","arguments":{}}}"#;
        assert_rpc_error(
            validate(legacy_notification, &headers(Some("2025-11-25"), None, None)),
            StatusCode::BAD_REQUEST,
            -32600,
        );
        let modern_notification =
            modern_body("tools/call", json!({"name":"realm_get","arguments":{}}))
                .replace(r#""id":7,"#, "");
        assert_rpc_error(
            validate(
                &modern_notification,
                &headers(Some(MODERN_VERSION), Some("tools/call"), Some("realm_get")),
            ),
            StatusCode::BAD_REQUEST,
            -32600,
        );
        for invalid_headers in [
            headers(Some(MODERN_VERSION), None, Some("realm_get")),
            headers(Some(MODERN_VERSION), Some("tools/list"), Some("realm_get")),
        ] {
            assert_rpc_error(
                validate(&modern_notification, &invalid_headers),
                StatusCode::BAD_REQUEST,
                -32020,
            );
        }

        let executor_owned_argument_validation = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"users_search","arguments":{"max":"not-a-number"}}
        })
        .to_string();
        assert!(validate(
            &executor_owned_argument_validation,
            &headers(Some("2025-11-25"), None, None),
        )
        .is_ok());
    }

    #[test]
    fn post_media_validation_is_exact_and_allows_standard_parameters() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let mut missing_accept = headers(Some("2025-11-25"), None, None);
        missing_accept.remove(header::ACCEPT);
        let error = validate(body, &missing_accept).unwrap_err();
        assert_eq!(error.status, StatusCode::NOT_ACCEPTABLE);

        for accept in [
            "application/json;q=0, text/event-stream",
            "application/jsonx, text/event-stream",
            "application/json, text/event-stream;q=0",
        ] {
            let mut invalid = headers(Some("2025-11-25"), None, None);
            invalid.insert(header::ACCEPT, accept.parse().unwrap());
            let error = validate(body, &invalid).unwrap_err();
            assert_eq!(error.status, StatusCode::NOT_ACCEPTABLE, "{accept}");
        }

        let mut split_accept = headers(Some("2025-11-25"), None, None);
        split_accept.remove(header::ACCEPT);
        split_accept.append(header::ACCEPT, "application/json".parse().unwrap());
        split_accept.append(header::ACCEPT, "text/event-stream".parse().unwrap());
        split_accept
            .insert(header::CONTENT_TYPE, "application/json; charset=utf-8".parse().unwrap());
        assert!(validate(body, &split_accept).is_ok());

        for content_type in ["text/plain", "application/jsonx"] {
            let mut wrong_type = headers(Some("2025-11-25"), None, None);
            wrong_type.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
            let error = validate(body, &wrong_type).unwrap_err();
            assert_eq!(error.status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{content_type}");
        }
    }

    #[tokio::test]
    async fn post_body_cap_is_four_mib() {
        let error = read_post_body(Body::from(vec![b' '; MAX_REQUEST_BODY_BYTES + 1]))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    struct Loopback {
        base_url: String,
        state: Arc<ServerState>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Loopback {
        async fn stop(self) {
            self.task.abort();
            let _ = self.task.await;
        }
    }

    async fn spawn_loopback(enabled: bool, rate_limit: u32) -> Loopback {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = crate::config::ServerConfig::with_test_admin();
        config.issuer_url = format!("http://{address}");
        config.mcp.enabled = enabled;
        config.mcp.require_dpop = false;
        config.mcp.invocation_rate_limit_per_minute = rate_limit;
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let app = crate::routes::app_router(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        });
        Loopback {
            base_url: config.issuer_url,
            state,
            task,
        }
    }

    async fn issue_token(
        state: &Arc<ServerState>,
        user: &User,
        roles: &[&str],
        scope: &str,
    ) -> String {
        let realm = state.storage.get_realm_by_name("master").await.unwrap().unwrap();
        let client = state
            .storage
            .get_client_by_client_id(
                &realm.id,
                &issuerd_core::ClientIdentifier::new("admin-cli").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let session_id = SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let now = chrono::Utc::now();
        state
            .storage
            .create_user_session(
                &realm.id,
                &UserSession {
                    id: session_id.clone(),
                    realm_id: realm.id.clone(),
                    user_id: user.id.clone(),
                    login_username: user.username.clone(),
                    ip_address: std::net::IpAddr::from([127, 0, 0, 1]),
                    auth_method: AuthMethod::Password,
                    remember_me: false,
                    offline: false,
                    started: now,
                    last_session_refresh: now,
                    auth_time: now,
                    impersonator: None,
                    clients: Vec::new(),
                },
            )
            .await
            .unwrap();
        let resource = realm_mcp_resource(&state.config.issuer_url, "master");
        let overlay = crate::claims::bind_resource_aud_overlay(
            None,
            client.client_id.as_str(),
            Some(&resource),
        );
        state
            .token_manager
            .issue_access_token_with_roles(
                user,
                &client,
                &realm,
                &[scope.to_string()],
                &session_id,
                Some(RealmAccess {
                    roles: roles.iter().map(|role| RoleName::new(*role).unwrap()).collect(),
                }),
                None,
                overlay,
            )
            .await
            .unwrap()
            .token
    }

    async fn admin_user(state: &Arc<ServerState>) -> User {
        let realm_id = issuerd_core::RealmId::new("master").unwrap();
        state.storage.get_user_by_username(&realm_id, "admin").await.unwrap().unwrap()
    }

    fn legacy_request(method: &str, params: Value) -> String {
        json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string()
    }

    async fn post_raw(
        client: &reqwest::Client,
        url: &str,
        token: Option<&str>,
        version: Option<&str>,
        body: String,
    ) -> reqwest::Response {
        let mut request = client
            .post(url)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body(body);
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(version) = version {
            request = request.header(MCP_PROTOCOL_VERSION, version);
        }
        request.send().await.unwrap()
    }

    async fn response_json(response: reqwest::Response) -> Value {
        let status = response.status();
        let bytes = response.bytes().await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!("HTTP {status} returned non-JSON body {bytes:?}: {error}")
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_bearer_list_call_preflight_once_and_disabled_404() {
        let server = spawn_loopback(true, 1).await;
        let url = format!("{}/realms/master/mcp", server.base_url);
        let client = reqwest::Client::new();
        let user = admin_user(&server.state).await;
        let token = issue_token(
            &server.state,
            &user,
            &[
                "view-realm",
                "manage-realm",
                "view-users",
                "manage-users",
                "view-clients",
                "manage-clients",
            ],
            "mcp:read",
        )
        .await;
        assert_eq!(
            server
                .state
                .token_service
                .validate_access_token(&token)
                .unwrap()
                .claims
                .resource
                .as_deref(),
            Some(format!("{}/realms/master/mcp", server.base_url).as_str())
        );

        let duplicate = client
            .post(&url)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header(MCP_PROTOCOL_VERSION, "2025-11-25")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":1,"x":2}}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(duplicate).await["error"]["code"], -32700);

        let no_credentials = post_raw(
            &client,
            &url,
            None,
            Some("2025-11-25"),
            legacy_request("tools/list", json!({})),
        )
        .await;
        assert_eq!(no_credentials.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(no_credentials.headers().get_all(header::WWW_AUTHENTICATE).iter().count(), 2);
        assert!(no_credentials.bytes().await.unwrap().is_empty());

        for method in [Method::GET, Method::DELETE] {
            let response = client
                .request(method, &url)
                .header("Last-Event-ID", "not-a-session")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert!(!response.headers().contains_key("mcp-session-id"));
        }

        let invalid_origin = client
            .post(&url)
            .header("Origin", "https://attacker.example")
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header(MCP_PROTOCOL_VERSION, "2025-11-25")
            .body(legacy_request("tools/list", json!({})))
            .send()
            .await
            .unwrap();
        assert_eq!(invalid_origin.status(), StatusCode::FORBIDDEN);

        let list = post_raw(
            &client,
            &url,
            Some(&token),
            Some("2025-11-25"),
            legacy_request("tools/list", json!({})),
        )
        .await;
        assert_eq!(list.status(), StatusCode::OK);
        let list = response_json(list).await;
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 23);

        let call = legacy_request("tools/call", json!({"name":"realm_get","arguments":{}}));
        let first = post_raw(&client, &url, Some(&token), Some("2025-11-25"), call.clone()).await;
        assert_eq!(first.status(), StatusCode::OK);
        let first = response_json(first).await;
        assert_eq!(first["result"]["structuredContent"]["realm"], "master");
        assert_eq!(first["result"]["isError"], false);

        let limited = post_raw(&client, &url, Some(&token), Some("2025-11-25"), call).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key(header::RETRY_AFTER));
        server.stop().await;

        let disabled = spawn_loopback(false, 60).await;
        let disabled_url = format!("{}/realms/master/mcp", disabled.base_url);
        let response = post_raw(
            &client,
            &disabled_url,
            None,
            Some("2025-11-25"),
            legacy_request("tools/list", json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        disabled.stop().await;
    }

    #[tokio::test]
    async fn unknown_tool_counts_once_and_unknown_modern_method_stays_sdk_404() {
        let server = spawn_loopback(true, 2).await;
        let url = format!("{}/realms/master/mcp", server.base_url);
        let client = reqwest::Client::new();
        let user = admin_user(&server.state).await;
        let token = issue_token(&server.state, &user, &["view-realm"], "mcp:read").await;

        let unknown_method = client
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header(MCP_PROTOCOL_VERSION, MODERN_VERSION)
            .header(MCP_METHOD, "unknown/method")
            .body(modern_body("unknown/method", json!({})))
            .send()
            .await
            .unwrap();
        assert_eq!(unknown_method.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_json(unknown_method).await["error"]["code"], -32601);

        let unknown_tool = post_raw(
            &client,
            &url,
            Some(&token),
            Some("2025-11-25"),
            legacy_request("tools/call", json!({"name":"not_a_tool","arguments":{}})),
        )
        .await;
        assert_eq!(unknown_tool.status(), StatusCode::OK);
        assert_eq!(response_json(unknown_tool).await["error"]["code"], -32601);

        let call = legacy_request("tools/call", json!({"name":"realm_get","arguments":{}}));
        let success = post_raw(&client, &url, Some(&token), Some("2025-11-25"), call.clone()).await;
        assert_eq!(success.status(), StatusCode::OK);
        assert_eq!(response_json(success).await["result"]["isError"], false);
        let limited = post_raw(&client, &url, Some(&token), Some("2025-11-25"), call).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_permits_and_principals_do_not_bleed() {
        let server = spawn_loopback(true, 100).await;
        let url = format!("{}/realms/master/mcp", server.base_url);
        let admin = admin_user(&server.state).await;
        let admin_token = issue_token(&server.state, &admin, &["view-realm"], "mcp:read").await;
        let now = chrono::Utc::now();
        let reader = User {
            id: UserId::new("client-reader").unwrap(),
            realm_id: issuerd_core::RealmId::new("master").unwrap(),
            username: Username::new("client-reader").unwrap(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            federation_link: None,
            attributes: HashMap::new(),
            required_actions: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        server.state.storage.create_user(&reader.realm_id, &reader).await.unwrap();
        let reader_token = issue_token(&server.state, &reader, &["view-clients"], "mcp:read").await;

        let mut tasks = Vec::new();
        for index in 0..16 {
            let client = reqwest::Client::new();
            let url = url.clone();
            let even = index % 2 == 0;
            let token = if even {
                admin_token.clone()
            } else {
                reader_token.clone()
            };
            tasks.push(tokio::spawn(async move {
                let (tool, arguments) = if even {
                    ("realm_get", json!({}))
                } else {
                    ("clients_list", json!({"clientId":"admin-cli"}))
                };
                let body = json!({
                    "jsonrpc":"2.0","id":index,"method":"tools/call",
                    "params":{"name":tool,"arguments":arguments}
                })
                .to_string();
                let response =
                    post_raw(&client, &url, Some(&token), Some("2025-11-25"), body).await;
                let status = response.status();
                let body = response_json(response).await;
                (index, even, status, body)
            }));
        }
        for task in tasks {
            let (index, even, status, body) = task.await.unwrap();
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["id"], index);
            assert_eq!(body["result"]["isError"], false, "{body}");
            if even {
                assert_eq!(body["result"]["structuredContent"]["realm"], "master");
            } else {
                assert_eq!(
                    body["result"]["structuredContent"]["clients"][0]["clientId"],
                    "admin-cli"
                );
            }
        }
        server.stop().await;
    }

    async fn spawn_loopback_with_response_mode(json_response: bool) -> Loopback {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = crate::config::ServerConfig::with_test_admin();
        config.issuer_url = format!("http://{address}");
        config.mcp.enabled = true;
        config.mcp.require_dpop = false;
        let state = Arc::new(ServerState::from_config(&config).await.unwrap());
        let admin_state = crate::mcp_service::admin_state(&state);
        let app = mount_with_response_mode(Router::new(), &state, admin_state, json_response)
            .with_state(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        });
        Loopback {
            base_url: config.issuer_url,
            state,
            task,
        }
    }

    #[tokio::test]
    async fn production_adapter_emits_sse_with_auth_and_no_store() {
        let server = spawn_loopback_with_response_mode(false).await;
        let url = format!("{}/realms/master/mcp", server.base_url);
        let client = reqwest::Client::new();
        let user = admin_user(&server.state).await;
        let token = issue_token(&server.state, &user, &["view-realm"], "mcp:read").await;
        let response = post_raw(
            &client,
            &url,
            Some(&token),
            Some("2025-11-25"),
            legacy_request("tools/call", json!({"name":"realm_get","arguments":{}})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert!(!response.headers().contains_key("mcp-session-id"));
        let body = response.text().await.unwrap();
        let data = body
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .expect("SSE response carries a JSON-RPC event");
        let message: Value = serde_json::from_str(data).unwrap();
        assert_eq!(message["result"]["isError"], false);
        assert_eq!(message["result"]["structuredContent"]["realm"], "master");
        server.stop().await;
    }
}
