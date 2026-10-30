// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode,
    Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};

use crate::{
    auth::McpAuthContext,
    error::McpError,
    executor::{McpToolExecutor, McpToolPermit},
    policy,
};

pub const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2025_06_18,
    ProtocolVersion::V_2025_11_25,
    ProtocolVersion::V_2026_07_28,
];

#[derive(Clone)]
pub struct IssuerdMcpServer {
    executor: Arc<McpToolExecutor>,
}

impl IssuerdMcpServer {
    pub fn new(executor: Arc<McpToolExecutor>) -> Self {
        Self { executor }
    }

    pub fn executor(&self) -> &Arc<McpToolExecutor> {
        &self.executor
    }
}

impl ServerHandler for IssuerdMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::LATEST_WITH_INITIALIZE)
            .with_server_info(
                Implementation::new("issuerd", env!("CARGO_PKG_VERSION"))
                    .with_title("Issuerd")
                    .with_description("Issuerd read-only realm administration MCP tools")
                    .with_website_url("https://issuerd.org"),
            )
            .with_instructions(
                "Read-only realm tools. Scope and realm-role policy is evaluated per request.",
            )
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        crate::policy::ToolName::parse(name).and_then(|tool| {
            (self.executor.step_up_enabled() || !crate::strict_tools::is_strict(tool))
                .then(|| crate::tools::definition(tool))
        })
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let auth = auth_from_context(&context).map_err(protocol_error)?;
        let tools = crate::tools::definitions()
            .into_iter()
            .filter(|tool| {
                crate::policy::ToolName::parse(tool.name.as_ref()).is_some_and(|name| {
                    (self.executor.step_up_enabled() || !crate::strict_tools::is_strict(name))
                        && policy::decide_for(name, &auth).is_allowed()
                })
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let auth = auth_from_context(&context).map_err(protocol_error)?;
        let tool = match crate::policy::ToolName::parse(request.name.as_ref()) {
            Some(tool) => tool,
            None => {
                let error = self
                    .executor
                    .preflight(request.name.as_ref(), auth, issuerd_core::utils::now_secs())
                    .await
                    .expect_err("unknown tools cannot receive a preflight permit");
                return Err(protocol_error(error));
            }
        };
        let existing_permit = permit_from_context(&context);
        let permit = match existing_permit {
            Some(permit) => {
                if permit.tool != tool || permit.auth != auth {
                    return Err(protocol_error(McpError::PermitMismatch));
                }
                permit
            }
            None => match self
                .executor
                .preflight(request.name.as_ref(), auth, issuerd_core::utils::now_secs())
                .await
            {
                Ok(permit) => permit,
                Err(error) if matches!(error, McpError::UnknownTool(_)) => {
                    return Err(protocol_error(error));
                }
                Err(error) => return Ok(tool_error(error)),
            },
        };
        if let Some(result) = context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<crate::executor::McpStrictResult>())
        {
            return Ok(CallToolResult::structured(result.0.clone()).into());
        }
        match self.executor.execute(&permit, request.arguments).await {
            Ok(value) => Ok(CallToolResult::structured(value).into()),
            Err(error) if matches!(error, McpError::UnknownTool(_)) => Err(protocol_error(error)),
            Err(error) => Ok(tool_error(error)),
        }
    }
}

fn tool_error(error: McpError) -> CallToolResponse {
    CallToolResult::error(vec![ContentBlock::text(error.public_tool_message())]).into()
}

fn protocol_error(error: McpError) -> ErrorData {
    match error {
        McpError::UnknownTool(name) => {
            ErrorData::new(ErrorCode::METHOD_NOT_FOUND, format!("unknown tool: {name}"), None)
        }
        McpError::PermitMismatch => {
            ErrorData::invalid_request("MCP preflight permit mismatch", None)
        }
        McpError::MissingAuthenticationContext => {
            ErrorData::internal_error("missing MCP authentication context", None)
        }
        other => ErrorData::internal_error(other.public_tool_message(), None),
    }
}

fn auth_from_context(context: &RequestContext<RoleServer>) -> Result<McpAuthContext, McpError> {
    context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<McpAuthContext>())
        .cloned()
        .ok_or(McpError::MissingAuthenticationContext)
}

fn permit_from_context(context: &RequestContext<RoleServer>) -> Option<McpToolPermit> {
    context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<McpToolPermit>())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::McpRateLimiter;
    use crate::test_support::*;
    use crate::transport::{streamable_http_service, McpTransportConfig};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use issuerd_cluster::InMemoryCache;
    use issuerd_core::Storage;
    use serde_json::{json, Value};
    use tokio_util::sync::CancellationToken;
    use tower_service::Service;

    fn server() -> IssuerdMcpServer {
        IssuerdMcpServer::new(Arc::new(McpToolExecutor::new(
            Arc::new(issuerd_storage::InMemoryStorage::new()),
            McpRateLimiter::new(Arc::new(InMemoryCache::new()), 60),
        )))
    }

    #[test]
    fn discovery_is_truthful_and_exact() {
        let server = server();
        let info = server.get_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);
        assert_eq!(info.server_info.name, "issuerd");
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.capabilities.tools.as_ref().unwrap().list_changed, None);
        assert!(info.capabilities.resources.is_none());
        assert!(info.capabilities.prompts.is_none());
        let supported = server.supported_protocol_versions();
        let versions: Vec<_> = supported.iter().map(ProtocolVersion::as_str).collect();
        assert_eq!(versions, ["2025-06-18", "2025-11-25", "2026-07-28"]);
        assert!(server.get_tool("realm_get").is_some());
        assert!(server.get_tool("tools/get").is_none());
    }

    struct TestService {
        service: crate::transport::IssuerdStreamableHttpService,
    }

    async fn service(limit: u64) -> TestService {
        let storage: Arc<dyn Storage> = storage().await;
        let executor = Arc::new(McpToolExecutor::new(
            storage,
            McpRateLimiter::new(Arc::new(InMemoryCache::new()), limit),
        ));
        let service = streamable_http_service(
            executor,
            McpTransportConfig::new(
                vec!["issuer.example".into()],
                Vec::new(),
                CancellationToken::new(),
            )
            .unwrap(),
        )
        .unwrap();
        TestService { service }
    }

    fn request(
        method: &str,
        body: Value,
        auth: McpAuthContext,
        permit: Option<McpToolPermit>,
    ) -> http::Request<Full<Bytes>> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri("https://issuer.example/realms/demo/mcp")
            .header(http::header::HOST, "issuer.example")
            .header(http::header::ACCEPT, "application/json, text/event-stream")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("MCP-Protocol-Version", "2025-11-25")
            .extension(auth);
        if let Some(permit) = permit {
            builder = builder.extension(permit);
        }
        builder.body(Full::new(Bytes::from(body.to_string()))).unwrap()
    }

    async fn call_service(
        service: &mut crate::transport::IssuerdStreamableHttpService,
        request: http::Request<Full<Bytes>>,
    ) -> (http::StatusCode, Value) {
        let response = service.call(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, value)
    }

    #[tokio::test]
    async fn list_tools_uses_the_callers_policy() {
        let mut service = service(60).await.service;
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
        let (_, response) = call_service(
            &mut service,
            request("POST", body.clone(), auth("mcp:read", &["view-realm"]), None),
        )
        .await;
        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<_> = tools.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "events_search",
                "flows_list",
                "groups_get",
                "groups_list",
                "idp_get",
                "idp_list",
                "keys_list",
                "realm_get",
                "roles_get",
                "roles_list",
                "serverinfo_get",
                "sessions_list"
            ]
        );
        assert!(tools.iter().all(|tool| tool["outputSchema"].is_object()));
        assert!(response["result"].get("ttlMs").is_none());
        assert!(response["result"].get("cacheScope").is_none());
        assert!(response["result"].get("resultType").is_none());

        let (_, response) = call_service(
            &mut service,
            request("POST", body, auth("mcp:read", &["view-users", "manage-clients"]), None),
        )
        .await;
        let names: Vec<_> = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "client_scopes_list",
                "clients_get",
                "clients_list",
                "groups_members",
                "users_get",
                "users_get_credentials",
                "users_get_groups",
                "users_get_role_mappings",
                "users_get_sessions",
                "users_search"
            ]
        );
    }

    #[tokio::test]
    async fn structured_success_has_a_text_mirror_and_errors_are_text_only() {
        let mut service = service(60).await.service;
        let call = json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"realm_get","arguments":{}}
        });
        let (_, response) = call_service(
            &mut service,
            request("POST", call, auth("mcp:read", &["view-realm"]), None),
        )
        .await;
        let result = &response["result"];
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["realm"], "demo");
        assert_eq!(result["content"][0]["type"], "text");
        let mirror: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(mirror, result["structuredContent"]);

        let missing = json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"users_get","arguments":{"id":"20000000-0000-4000-8000-000000000099"}}
        });
        let (_, response) = call_service(
            &mut service,
            request("POST", missing, auth("mcp:read", &["view-users"]), None),
        )
        .await;
        let result = &response["result"];
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"], Value::Null);
        assert_eq!(result["content"][0]["type"], "text");
        assert!(result["content"][0]["text"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn unknown_tool_is_a_protocol_error_and_is_counted() {
        let mut service = service(1).await.service;
        let unknown = json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"unknown","arguments":{}}
        });
        let (_, response) = call_service(
            &mut service,
            request("POST", unknown, auth("mcp:read", &["view-realm"]), None),
        )
        .await;
        assert_eq!(response["error"]["code"], -32601);
        assert!(response.get("result").is_none());

        let known = json!({
            "jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{"name":"realm_get","arguments":{}}
        });
        let (_, response) = call_service(
            &mut service,
            request("POST", known, auth("mcp:read", &["view-realm"]), None),
        )
        .await;
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("rate limit"));
    }

    #[tokio::test]
    async fn supplied_permit_skips_second_count_and_is_tool_and_principal_bound() {
        let storage: Arc<dyn Storage> = storage().await;
        let executor = Arc::new(McpToolExecutor::new(
            storage,
            McpRateLimiter::new(Arc::new(InMemoryCache::new()), 1),
        ));
        let context = auth("mcp:read", &["view-realm"]);
        let permit = executor.preflight("realm_get", context.clone(), 120).await.unwrap();
        let mut service = streamable_http_service(
            Arc::clone(&executor),
            McpTransportConfig::new(
                vec!["issuer.example".into()],
                Vec::new(),
                CancellationToken::new(),
            )
            .unwrap(),
        )
        .unwrap();
        let call = json!({
            "jsonrpc":"2.0","id":6,"method":"tools/call",
            "params":{"name":"realm_get","arguments":{}}
        });
        let (_, response) = call_service(
            &mut service,
            request("POST", call.clone(), context.clone(), Some(permit.clone())),
        )
        .await;
        assert_eq!(response["result"]["isError"], false);

        let (_, response) = call_service(
            &mut service,
            request(
                "POST",
                call,
                auth_with("other", "other-user", "mcp:read", &["view-realm"]),
                Some(permit),
            ),
        )
        .await;
        assert_eq!(response["error"]["code"], -32600);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn alternating_principals_do_not_bleed_across_concurrent_requests() {
        let service = service(100).await.service;
        let mut tasks = Vec::new();
        for index in 0..24 {
            let mut service = service.clone();
            tasks.push(tokio::spawn(async move {
                let (role, expected) = if index % 2 == 0 {
                    ("view-realm", "realm_get")
                } else {
                    ("view-clients", "clients_list")
                };
                let (tool, arguments) = if expected == "realm_get" {
                    ("realm_get", json!({}))
                } else {
                    ("clients_list", json!({"clientId": "alpha-client"}))
                };
                let call = json!({
                    "jsonrpc":"2.0","id":index,"method":"tools/call",
                    "params":{"name":tool,"arguments":arguments}
                });
                let auth = auth_with(
                    if index % 2 == 0 {
                        "realm-agent"
                    } else {
                        "client-agent"
                    },
                    &format!("user-{index}"),
                    "mcp:read",
                    &[role],
                );
                let (_, response) =
                    call_service(&mut service, request("POST", call, auth, None)).await;
                if expected == "realm_get" {
                    assert_eq!(response["result"]["structuredContent"]["realm"], "demo");
                } else {
                    assert_eq!(
                        response["result"]["structuredContent"]["clients"][0]["clientId"],
                        "alpha-client"
                    );
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    }
}
