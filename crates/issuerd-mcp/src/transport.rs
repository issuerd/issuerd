// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::sync::Arc;

use rmcp::transport::streamable_http_server::{
    session::never::NeverSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use tokio_util::sync::CancellationToken;

use crate::{error::McpError, executor::McpToolExecutor, server::IssuerdMcpServer};

pub const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

pub type IssuerdStreamableHttpService =
    StreamableHttpService<IssuerdMcpServer, NeverSessionManager>;

#[derive(Debug, Clone)]
pub struct McpTransportConfig {
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    cancellation_token: CancellationToken,
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
        })
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
    let config = streamable_http_config(&config);
    Ok(StreamableHttpService::new(
        move || Ok(IssuerdMcpServer::new(Arc::clone(&executor))),
        Arc::new(NeverSessionManager::default()),
        config,
    ))
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
    for origin in origins {
        normalized.push(normalize_origin(&origin)?);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalize_origin(origin: &str) -> Result<String, McpError> {
    let origin = origin.trim();
    let url = url::Url::parse(origin)
        .map_err(|_| McpError::TransportConfig(format!("invalid allowed Origin: {origin}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(McpError::TransportConfig(format!(
            "allowed Origin must be an HTTP(S) origin without credentials, path, query, or fragment: {origin}"
        )));
    }
    let host = match url.host() {
        Some(url::Host::Domain(domain)) => domain.to_string(),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        None => {
            return Err(McpError::TransportConfig(format!("allowed Origin has no host: {origin}")));
        }
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
}
