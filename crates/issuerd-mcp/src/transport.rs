// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::{fmt::Display, sync::Arc};

use http_body::Body;
use rmcp::transport::streamable_http_server::{
    session::never::NeverSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use tokio_util::sync::CancellationToken;

use crate::{error::McpError, executor::McpToolExecutor, server::IssuerdMcpServer};

pub const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

type RmcpStreamableHttpService = StreamableHttpService<IssuerdMcpServer, NeverSessionManager>;

#[derive(Clone)]
pub struct IssuerdStreamableHttpService {
    inner: RmcpStreamableHttpService,
    config: McpTransportConfig,
}

impl<RequestBody> tower_service::Service<http::Request<RequestBody>>
    for IssuerdStreamableHttpService
where
    RequestBody: Body + Send + 'static,
    RequestBody::Error: Display,
    RequestBody::Data: Send + 'static,
{
    type Response =
        <RmcpStreamableHttpService as tower_service::Service<http::Request<RequestBody>>>::Response;
    type Error =
        <RmcpStreamableHttpService as tower_service::Service<http::Request<RequestBody>>>::Error;
    type Future =
        <RmcpStreamableHttpService as tower_service::Service<http::Request<RequestBody>>>::Future;

    fn call(&mut self, mut request: http::Request<RequestBody>) -> Self::Future {
        let method = request.method().clone();
        let uri = request.uri().clone();
        let _ = canonicalize_sdk_request(&self.config, &method, &uri, request.headers_mut());
        <RmcpStreamableHttpService as tower_service::Service<http::Request<RequestBody>>>::call(
            &mut self.inner,
            request,
        )
    }

    fn poll_ready(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        <RmcpStreamableHttpService as tower_service::Service<
            http::Request<RequestBody>,
        >>::poll_ready(&mut self.inner, context)
    }
}

#[derive(Debug, Clone)]
pub struct McpTransportConfig {
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    cancellation_token: CancellationToken,
    scheme_default_port: Option<u16>,
}

impl McpTransportConfig {
    pub fn new(
        allowed_hosts: Vec<String>,
        allowed_origins: Vec<String>,
        cancellation_token: CancellationToken,
    ) -> Result<Self, McpError> {
        let allowed_hosts = normalize_hosts(allowed_hosts)?;
        let allowed_origins = normalize_origins(allowed_origins)?;
        Ok(Self {
            allowed_hosts,
            allowed_origins,
            cancellation_token,
            scheme_default_port: None,
        })
    }

    pub fn for_issuer(
        issuer_url: &str,
        allowed_origins: Vec<String>,
        cancellation_token: CancellationToken,
    ) -> Result<Self, McpError> {
        let url = url::Url::parse(issuer_url)
            .map_err(|_| McpError::TransportConfig("issuer_url is invalid".into()))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(McpError::TransportConfig(
                "issuer_url must be an HTTP(S) URL without userinfo".into(),
            ));
        }
        let host = match url.host() {
            Some(url::Host::Domain(domain)) => domain.to_string(),
            Some(url::Host::Ipv4(address)) => address.to_string(),
            Some(url::Host::Ipv6(address)) => format!("[{address}]"),
            None => {
                return Err(McpError::TransportConfig(
                    "issuer_url must have a nonempty authority".into(),
                ));
            }
        };
        let port = url.port_or_known_default().ok_or_else(|| {
            McpError::TransportConfig("issuer_url must have a known HTTP(S) port".into())
        })?;
        let scheme_default_port = if url.scheme() == "http" { 80 } else { 443 };
        let authority = format!("{host}:{port}");
        let mut config = Self::new(vec![authority], allowed_origins, cancellation_token)?;
        config.scheme_default_port = Some(scheme_default_port);
        Ok(config)
    }

    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation_token
    }
}

pub fn streamable_http_config(config: &McpTransportConfig) -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_stateless_protocol_metadata_required(false)
        .with_max_request_body_bytes(MAX_REQUEST_BODY_BYTES)
        .with_cancellation_token(config.cancellation_token.clone())
        .with_allowed_hosts(config.allowed_hosts.clone())
        .with_allowed_origins(config.allowed_origins.clone())
        .enforce_origin_validation()
}

pub fn streamable_http_service(
    executor: Arc<McpToolExecutor>,
    config: McpTransportConfig,
) -> Result<IssuerdStreamableHttpService, McpError> {
    let sdk_config = streamable_http_config(&config);
    let inner = StreamableHttpService::new(
        move || Ok(IssuerdMcpServer::new(Arc::clone(&executor))),
        Arc::new(NeverSessionManager::default()),
        sdk_config,
    );
    Ok(IssuerdStreamableHttpService { inner, config })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportHeaderError {
    status: http::StatusCode,
    message: &'static str,
}

impl TransportHeaderError {
    fn new(status: http::StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }

    fn bad_request(message: &'static str) -> Self {
        Self::new(http::StatusCode::BAD_REQUEST, message)
    }

    fn forbidden(message: &'static str) -> Self {
        Self::new(http::StatusCode::FORBIDDEN, message)
    }

    pub fn status(self) -> http::StatusCode {
        self.status
    }

    pub fn message(self) -> &'static str {
        self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedAuthority {
    host: String,
    port: Option<u16>,
}

fn normalize_authority(host: &str, port: Option<u16>) -> NormalizedAuthority {
    NormalizedAuthority {
        host: host.trim_matches('[').trim_matches(']').to_ascii_lowercase(),
        port,
    }
}

fn parse_allowed_authority(allowed: &str) -> Option<NormalizedAuthority> {
    let allowed = allowed.trim();
    if allowed.is_empty() {
        return None;
    }
    if let Ok(authority) = http::uri::Authority::try_from(allowed) {
        return Some(normalize_authority(authority.host(), authority.port_u16()));
    }
    Some(normalize_authority(allowed, None))
}

fn request_authority(
    uri: &http::Uri,
    headers: &http::HeaderMap,
) -> Result<NormalizedAuthority, TransportHeaderError> {
    let mut values = headers.get_all(http::header::HOST).iter();
    if let Some(host) = values.next() {
        if values.next().is_some() {
            return Err(TransportHeaderError::bad_request("Bad Request: multiple Host headers"));
        }
        let host = host.to_str().map_err(|_| {
            TransportHeaderError::bad_request("Bad Request: Invalid Host header encoding")
        })?;
        let authority = http::uri::Authority::try_from(host)
            .map_err(|_| TransportHeaderError::bad_request("Bad Request: Invalid Host header"))?;
        return Ok(normalize_authority(authority.host(), authority.port_u16()));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| TransportHeaderError::bad_request("Bad Request: missing Host header"))?;
    Ok(normalize_authority(authority.host(), authority.port_u16()))
}

fn matching_allowed_authority(
    host: &NormalizedAuthority,
    config: &McpTransportConfig,
) -> Option<NormalizedAuthority> {
    config
        .allowed_hosts
        .iter()
        .filter_map(|allowed| parse_allowed_authority(allowed))
        .find(|allowed| {
            allowed.host == host.host
                && match allowed.port {
                    Some(port) => host.port.or(config.scheme_default_port) == Some(port),
                    None => true,
                }
        })
}

fn validate_host(
    uri: &http::Uri,
    headers: &http::HeaderMap,
    config: &McpTransportConfig,
) -> Result<(), TransportHeaderError> {
    let host = request_authority(uri, headers)?;
    if matching_allowed_authority(&host, config).is_none() {
        return Err(TransportHeaderError::forbidden("Forbidden: Host header is not allowed"));
    }
    Ok(())
}

fn authority_string(authority: &NormalizedAuthority) -> String {
    let host = if authority.host.contains(':') {
        format!("[{}]", authority.host)
    } else {
        authority.host.clone()
    };
    match authority.port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn canonicalize_sdk_request(
    config: &McpTransportConfig,
    method: &http::Method,
    uri: &http::Uri,
    headers: &mut http::HeaderMap,
) -> Result<(), TransportHeaderError> {
    validate_host_and_origin(config, uri, headers)?;
    let host = request_authority(uri, headers)?;
    let allowed = matching_allowed_authority(&host, config)
        .ok_or_else(|| TransportHeaderError::forbidden("Forbidden: Host header is not allowed"))?;
    let authority = http::HeaderValue::from_str(&authority_string(&allowed))
        .map_err(|_| TransportHeaderError::bad_request("Bad Request: Invalid Host header"))?;
    headers.insert(http::header::HOST, authority);
    if method == http::Method::POST {
        validate_post_media_headers(headers)?;
        headers.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers
            .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
    }
    Ok(())
}

fn validate_origin(
    headers: &http::HeaderMap,
    config: &McpTransportConfig,
) -> Result<(), TransportHeaderError> {
    let mut values = headers.get_all(http::header::ORIGIN).iter();
    let Some(origin) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(TransportHeaderError::forbidden("Forbidden: multiple Origin headers"));
    }
    let origin = origin.to_str().map_err(|_| {
        TransportHeaderError::forbidden("Forbidden: Invalid Origin header encoding")
    })?;
    let normalized = normalize_origin(origin)
        .map_err(|_| TransportHeaderError::forbidden("Forbidden: Invalid Origin header"))?;
    if !config.allowed_origins.contains(&normalized) {
        return Err(TransportHeaderError::forbidden("Forbidden: Origin header is not allowed"));
    }
    Ok(())
}

pub fn validate_host_and_origin(
    config: &McpTransportConfig,
    uri: &http::Uri,
    headers: &http::HeaderMap,
) -> Result<(), TransportHeaderError> {
    validate_host(uri, headers, config)?;
    validate_origin(headers, config)
}

pub fn validate_post_media_headers(headers: &http::HeaderMap) -> Result<(), TransportHeaderError> {
    if !accepts_media_type(headers, "application/json")
        || !accepts_media_type(headers, "text/event-stream")
    {
        return Err(TransportHeaderError::new(
            http::StatusCode::NOT_ACCEPTABLE,
            "Not Acceptable: Client must accept both application/json and text/event-stream",
        ));
    }
    let mut content_types = headers.get_all(http::header::CONTENT_TYPE).iter();
    let content_type = content_types.next().and_then(|value| value.to_str().ok());
    let valid_content_type = content_types.next().is_none()
        && content_type.is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        });
    if !valid_content_type {
        return Err(TransportHeaderError::new(
            http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported Media Type: Content-Type must be application/json",
        ));
    }
    Ok(())
}

fn accepts_media_type(headers: &http::HeaderMap, wanted: &str) -> bool {
    let (wanted_type, _) = wanted.split_once('/').expect("MIME type has a subtype");
    headers
        .get_all(http::header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|entry| {
            let mut parts = entry.trim().split(';');
            let media = parts.next().map(str::trim).unwrap_or_default();
            let wildcard = format!("{wanted_type}/*");
            if !media.eq_ignore_ascii_case(wanted)
                && !media.eq_ignore_ascii_case(&wildcard)
                && !media.eq_ignore_ascii_case("*/*")
            {
                return false;
            }
            let mut quality = 1.0;
            for parameter in parts {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    continue;
                };
                if name.trim().eq_ignore_ascii_case("q") {
                    quality = match value.trim().parse::<f32>() {
                        Ok(value) if (0.0..=1.0).contains(&value) => value,
                        _ => return false,
                    };
                }
            }
            quality > 0.0
        })
}

fn normalize_hosts(hosts: Vec<String>) -> Result<Vec<String>, McpError> {
    if hosts.is_empty() {
        return Err(McpError::TransportConfig("allowed_hosts must not be empty".into()));
    }
    let mut normalized = Vec::with_capacity(hosts.len());
    for host in hosts {
        let host = host.trim();
        if host.is_empty() {
            return Err(McpError::TransportConfig(
                "allowed_hosts must not contain blank entries".into(),
            ));
        }
        normalized.push(host.to_string());
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalize_origins(origins: Vec<String>) -> Result<Vec<String>, McpError> {
    let mut normalized = Vec::with_capacity(origins.len());
    for (index, origin) in origins.into_iter().enumerate() {
        let origin = normalize_origin(&origin).map_err(|reason| {
            McpError::TransportConfig(format!("invalid allowed Origin at index {index}: {reason}"))
        })?;
        normalized.push(origin);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalize_origin(origin: &str) -> Result<String, &'static str> {
    let origin = origin.trim();
    let url = url::Url::parse(origin).map_err(|_| "not an absolute URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("must be an HTTP(S) origin without credentials, path, query, or fragment");
    }
    let host = match url.host() {
        Some(url::Host::Domain(domain)) => domain.to_string(),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        None => return Err("has no host"),
    };
    let port = match url.port() {
        Some(port) => port,
        None if url.scheme() == "http" => 80,
        None => 443,
    };
    Ok(format!("{}://{host}:{port}", url.scheme()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::McpRateLimiter;
    use crate::test_support::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use issuerd_cluster::InMemoryCache;
    use issuerd_core::Storage;
    use tower_service::Service;

    #[test]
    fn transport_uses_stateless_bounded_host_and_origin_configuration() {
        let token = CancellationToken::new();
        let config = McpTransportConfig::new(
            vec!["issuer.example".into()],
            vec![
                "https://client.example".into(),
                "http://localhost:3000".into(),
            ],
            token.clone(),
        )
        .unwrap();
        let sdk = streamable_http_config(&config);
        assert!(!sdk.legacy_session_mode);
        assert!(sdk.json_response);
        assert!(!sdk.stateless_protocol_metadata_required);
        assert_eq!(sdk.max_request_body_bytes, MAX_REQUEST_BODY_BYTES);
        assert_eq!(sdk.allowed_hosts, ["issuer.example"]);
        assert_eq!(sdk.allowed_origins, ["http://localhost:3000", "https://client.example:443"]);
        assert!(sdk.session_store.is_none());
        assert!(!token.is_cancelled());
    }

    #[test]
    fn empty_or_blank_hosts_are_rejected() {
        for hosts in [
            Vec::new(),
            vec![" ".into()],
            vec!["issuer.example".into(), "".into()],
        ] {
            assert!(McpTransportConfig::new(hosts, Vec::new(), CancellationToken::new()).is_err());
        }
    }

    #[test]
    fn origins_are_exact_and_explicitly_port_normalized() {
        let config = McpTransportConfig::new(
            vec!["issuer.example".into()],
            vec![
                "https://client.example".into(),
                "https://client.example:443".into(),
                "http://client.example".into(),
                "http://[::1]".into(),
            ],
            CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(
            config.allowed_origins,
            [
                "http://[::1]:80",
                "http://client.example:80",
                "https://client.example:443",
            ]
        );
    }

    #[test]
    fn malformed_or_wildcard_origins_are_rejected() {
        for origin in [
            "",
            "null",
            "client.example",
            "https://client.example:*",
            "https://client.example/path",
            "https://user:password@client.example",
            "https://client.example/?query=yes",
            "https://client.example/#fragment",
            "ftp://client.example",
        ] {
            assert!(
                McpTransportConfig::new(
                    vec!["issuer.example".into()],
                    vec![origin.into()],
                    CancellationToken::new(),
                )
                .is_err(),
                "accepted {origin}"
            );
        }
    }

    #[test]
    fn issuer_authority_and_outer_header_checks_share_exact_normalization() {
        let config = McpTransportConfig::for_issuer(
            "http://[::1]:8080/iam",
            vec!["https://client.example".into()],
            CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(config.allowed_hosts, ["[::1]:8080"]);
        let uri: http::Uri = "http://[::1]:8080/realms/demo/mcp".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "[::1]:8080".parse().unwrap());
        validate_host_and_origin(&config, &uri, &headers).unwrap();

        for origin in ["https://client.example", "https://client.example:443"] {
            headers.insert(http::header::ORIGIN, origin.parse().unwrap());
            validate_host_and_origin(&config, &uri, &headers).unwrap();
        }
        for origin in ["https://client.example:444", "null", "not-an-origin"] {
            headers.insert(http::header::ORIGIN, origin.parse().unwrap());
            assert_eq!(
                validate_host_and_origin(&config, &uri, &headers).unwrap_err().status(),
                http::StatusCode::FORBIDDEN
            );
        }
        headers.remove(http::header::ORIGIN);
        headers.insert(http::header::HOST, "[::1]:8081".parse().unwrap());
        assert_eq!(
            validate_host_and_origin(&config, &uri, &headers).unwrap_err().status(),
            http::StatusCode::FORBIDDEN
        );

        let empty_origins = McpTransportConfig::new(
            vec!["[::1]:8080".into()],
            Vec::new(),
            CancellationToken::new(),
        )
        .unwrap();
        headers.insert(http::header::HOST, "[::1]:8080".parse().unwrap());
        validate_host_and_origin(&empty_origins, &uri, &headers).unwrap();
        headers.insert(http::header::ORIGIN, "https://client.example".parse().unwrap());
        assert_eq!(
            validate_host_and_origin(&empty_origins, &uri, &headers).unwrap_err().status(),
            http::StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn issuer_default_port_is_exact_and_missing_host_port_means_that_default() {
        let config = McpTransportConfig::for_issuer(
            "https://issuer.example/iam",
            Vec::new(),
            CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(config.allowed_hosts, ["issuer.example:443"]);
        let uri: http::Uri = "https://issuer.example/realms/demo/mcp".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        for authority in ["issuer.example", "issuer.example:443"] {
            headers.insert(http::header::HOST, authority.parse().unwrap());
            validate_host_and_origin(&config, &uri, &headers).unwrap();
        }
        headers.insert(http::header::HOST, "issuer.example:444".parse().unwrap());
        assert_eq!(
            validate_host_and_origin(&config, &uri, &headers).unwrap_err().status(),
            http::StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn outer_header_checks_reject_ambiguous_or_missing_host() {
        let config = McpTransportConfig::new(
            vec!["issuer.example".into()],
            Vec::new(),
            CancellationToken::new(),
        )
        .unwrap();
        let uri: http::Uri = "/realms/demo/mcp".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        assert_eq!(
            validate_host_and_origin(&config, &uri, &headers).unwrap_err().status(),
            http::StatusCode::BAD_REQUEST
        );
        headers.append(http::header::HOST, "issuer.example".parse().unwrap());
        headers.append(http::header::HOST, "issuer.example".parse().unwrap());
        assert_eq!(
            validate_host_and_origin(&config, &uri, &headers).unwrap_err().status(),
            http::StatusCode::BAD_REQUEST
        );
    }

    async fn service(origins: Vec<String>) -> IssuerdStreamableHttpService {
        let storage: Arc<dyn Storage> = storage().await;
        streamable_http_service(
            Arc::new(McpToolExecutor::new(
                storage,
                McpRateLimiter::new(Arc::new(InMemoryCache::new()), 60),
            )),
            McpTransportConfig::new(
                vec!["issuer.example".into()],
                origins,
                CancellationToken::new(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn request(origin: Option<&str>) -> http::Request<Full<Bytes>> {
        let mut builder = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://issuer.example/realms/demo/mcp")
            .header(http::header::HOST, "issuer.example")
            .header(http::header::ACCEPT, "application/json, text/event-stream")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("MCP-Protocol-Version", "2025-11-25")
            .extension(auth("mcp:read", &["view-realm"]));
        if let Some(origin) = origin {
            builder = builder.header(http::header::ORIGIN, origin);
        }
        builder
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "jsonrpc":"2.0","id":1,"method":"tools/call",
                    "params":{"name":"realm_get","arguments":{}}
                })
                .to_string(),
            )))
            .unwrap()
    }

    #[tokio::test]
    async fn empty_origin_allowlist_rejects_every_present_origin_but_not_cli_requests() {
        let mut service = service(Vec::new()).await;
        let rejected = service.call(request(Some("https://any.example"))).await.unwrap();
        assert_eq!(rejected.status(), http::StatusCode::FORBIDDEN);

        let accepted = service.call(request(None)).await.unwrap();
        assert_eq!(accepted.status(), http::StatusCode::OK);
        let body = accepted.into_body().collect().await.unwrap().to_bytes();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn allowed_origin_requires_the_normalized_exact_port() {
        let mut service = service(vec!["https://client.example".into()]).await;
        let accepted = service.call(request(Some("https://client.example"))).await.unwrap();
        assert_eq!(accepted.status(), http::StatusCode::OK);
        let accepted_default =
            service.call(request(Some("https://client.example:443"))).await.unwrap();
        assert_eq!(accepted_default.status(), http::StatusCode::OK);
        let rejected = service.call(request(Some("https://client.example:444"))).await.unwrap();
        assert_eq!(rejected.status(), http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn legacy_initialize_and_initialized_work_without_session_ids() {
        let mut service = service(Vec::new()).await;
        let initialize = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://issuer.example/realms/demo/mcp")
            .header(http::header::HOST, "issuer.example")
            .header(http::header::ACCEPT, "application/json, text/event-stream")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("MCP-Protocol-Version", "2025-06-18")
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "jsonrpc":"2.0","id":1,"method":"initialize",
                    "params":{
                        "protocolVersion":"2025-06-18",
                        "capabilities":{},
                        "clientInfo":{"name":"test-client","version":"1.0.0"}
                    }
                })
                .to_string(),
            )))
            .unwrap();
        let response = service.call(initialize).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert!(!response.headers().contains_key("mcp-session-id"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(result["result"]["serverInfo"]["name"], "issuerd");

        let initialized = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://issuer.example/realms/demo/mcp")
            .header(http::header::HOST, "issuer.example")
            .header(http::header::ACCEPT, "application/json, text/event-stream")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("MCP-Protocol-Version", "2025-06-18")
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "jsonrpc":"2.0","method":"notifications/initialized","params":{}
                })
                .to_string(),
            )))
            .unwrap();
        let response = service.call(initialized).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::ACCEPTED);
        assert!(!response.headers().contains_key("mcp-session-id"));
    }

    #[tokio::test]
    async fn host_and_methods_follow_the_helper_contract() {
        let mut service = service(Vec::new()).await;
        let wrong_host = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://evil.example/realms/demo/mcp")
            .header(http::header::HOST, "evil.example")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(service.call(wrong_host).await.unwrap().status(), http::StatusCode::FORBIDDEN);

        for method in [http::Method::GET, http::Method::DELETE] {
            let request = http::Request::builder()
                .method(method)
                .uri("https://issuer.example/realms/demo/mcp")
                .header(http::header::HOST, "issuer.example")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let response = service.call(request).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers().get(http::header::ALLOW).unwrap(), "POST");
            assert!(!response.headers().contains_key("mcp-session-id"));
        }
    }

    async fn service_for(config: McpTransportConfig) -> IssuerdStreamableHttpService {
        let storage: Arc<dyn Storage> = storage().await;
        streamable_http_service(
            Arc::new(McpToolExecutor::new(
                storage,
                McpRateLimiter::new(Arc::new(InMemoryCache::new()), 60),
            )),
            config,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn sdk_accepts_default_port_host_with_or_without_explicit_port() {
        let config = McpTransportConfig::for_issuer(
            "https://issuer.example",
            Vec::new(),
            CancellationToken::new(),
        )
        .unwrap();
        let mut service = service_for(config).await;
        for authority in ["issuer.example", "issuer.example:443"] {
            let mut request = request(None);
            request.headers_mut().insert(http::header::HOST, authority.parse().unwrap());
            let response = service.call(request).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK, "Host: {authority}");
        }
    }

    #[test]
    fn non_default_omitted_host_port_is_rejected_by_outer_validation() {
        let config = McpTransportConfig::for_issuer(
            "https://issuer.example:8443",
            Vec::new(),
            CancellationToken::new(),
        )
        .unwrap();
        let uri = "https://issuer.example:8443/realms/demo/mcp".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "issuer.example".parse().unwrap());
        assert_eq!(
            validate_host_and_origin(&config, &uri, &headers).unwrap_err().status(),
            http::StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn sdk_accepts_case_insensitive_content_type_and_split_accept() {
        let mut service = service(Vec::new()).await;
        let mut mixed_case = request(None);
        mixed_case
            .headers_mut()
            .insert(http::header::CONTENT_TYPE, "Application/JSON".parse().unwrap());
        assert_eq!(service.call(mixed_case).await.unwrap().status(), http::StatusCode::OK);

        let mut split_accept = request(None);
        split_accept.headers_mut().remove(http::header::ACCEPT);
        split_accept
            .headers_mut()
            .append(http::header::ACCEPT, "application/json".parse().unwrap());
        split_accept
            .headers_mut()
            .append(http::header::ACCEPT, "text/event-stream".parse().unwrap());
        assert_eq!(service.call(split_accept).await.unwrap().status(), http::StatusCode::OK);
    }

    #[test]
    fn invalid_origin_errors_never_include_the_configured_value() {
        for origin in [
            "https://user:ORIGIN-SECRET@client.example",
            "https://client.example/?access_token=ORIGIN-SECRET",
            "https://client.example/#ORIGIN-SECRET",
        ] {
            let error = McpTransportConfig::for_issuer(
                "https://issuer.example",
                vec![origin.to_string()],
                CancellationToken::new(),
            )
            .unwrap_err();
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("ORIGIN-SECRET"), "{rendered}");
            assert!(!rendered.contains(origin), "{rendered}");
        }
    }
}
