// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::sync::Arc;

use issuerd_core::{ClientId, ClientIdentifier, Pagination, RealmId, RealmName, Storage, UserId};
use rmcp::model::JsonObject;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::{
    auth::McpAuthContext,
    error::McpError,
    policy::{self, PolicyDecision, PolicyDeny, ToolName, ToolPolicy},
    rate_limit::McpRateLimiter,
    tools::{
        ClientGetArgs, ClientOutput, ClientsListArgs, ClientsOutput, NoArgs, RealmOutput,
        UserDetailsOutput, UserGetArgs, UserOutput, UsersOutput, UsersSearchArgs,
        DEFAULT_PAGE_SIZE, MAX_INPUT_STRING_BYTES, MAX_PAGE_SIZE,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTarget {
    pub realm_id: RealmId,
    pub realm_name: RealmName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolPermit {
    pub tool: ToolName,
    pub policy: &'static ToolPolicy,
    pub target: McpTarget,
    pub auth: McpAuthContext,
}

#[derive(Clone)]
pub struct McpToolExecutor {
    storage: Arc<dyn Storage>,
    limiter: McpRateLimiter,
}

impl McpToolExecutor {
    pub fn new(storage: Arc<dyn Storage>, limiter: McpRateLimiter) -> Self {
        Self { storage, limiter }
    }

    pub fn limiter(&self) -> &McpRateLimiter {
        &self.limiter
    }

    pub async fn preflight(
        &self,
        tool_name: &str,
        auth: McpAuthContext,
        now: u64,
    ) -> Result<McpToolPermit, McpError> {
        self.limiter.acquire(&auth, now).await?;
        let tool = ToolName::parse(tool_name)
            .ok_or_else(|| McpError::UnknownTool(tool_name.to_string()))?;
        let tool_policy = policy::policy_for(tool);
        deny_to_error(policy::decide(tool_policy, &auth))?;
        let target = McpTarget {
            realm_id: auth.realm_id.clone(),
            realm_name: auth.realm_name.clone(),
        };
        Ok(McpToolPermit {
            tool,
            policy: tool_policy,
            target,
            auth,
        })
    }

    pub async fn execute(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        deny_to_error(policy::decide(permit.policy, &permit.auth))?;
        match permit.tool {
            ToolName::RealmGet => self.realm_get(permit, arguments).await,
            ToolName::UsersSearch => self.users_search(permit, arguments).await,
            ToolName::UsersGet => self.users_get(permit, arguments).await,
            ToolName::ClientsList => self.clients_list(permit, arguments).await,
            ToolName::ClientsGet => self.clients_get(permit, arguments).await,
        }
    }

    async fn realm_get(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let _: NoArgs = decode(arguments)?;
        let realm = self
            .storage
            .get_realm(&permit.target.realm_id)
            .await?
            .ok_or(McpError::NotFound("realm"))?;
        output(RealmOutput::from(&realm))
    }

    async fn users_search(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let args: UsersSearchArgs = decode(arguments)?;
        validate_optional_bounded(&args.username, "username", MAX_INPUT_STRING_BYTES)?;
        validate_optional_bounded(&args.email, "email", 254)?;
        validate_optional_bounded(&args.search, "search", MAX_INPUT_STRING_BYTES)?;
        let mut users = if let Some(username) = exact_filter(&args.username) {
            self.storage
                .get_user_by_username(&permit.target.realm_id, username)
                .await?
                .into_iter()
                .collect()
        } else if let Some(email) = exact_filter(&args.email) {
            self.storage
                .get_user_by_email(&permit.target.realm_id, email)
                .await?
                .into_iter()
                .collect()
        } else {
            let pagination = pagination(args.first, args.max)?;
            self.storage
                .list_users(
                    &permit.target.realm_id,
                    args.search.as_deref().unwrap_or_default(),
                    &pagination,
                )
                .await?
        };
        sort_users(&mut users);
        output(UsersOutput {
            users: users.iter().map(UserOutput::from).collect(),
        })
    }

    async fn users_get(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let args: UserGetArgs = decode(arguments)?;
        let id = required_id(&args.id, "id")?;
        let user_id = UserId::new(id).map_err(|error| McpError::InvalidInput(error.to_string()))?;
        let user = self
            .storage
            .get_user(&permit.target.realm_id, &user_id)
            .await?
            .ok_or(McpError::NotFound("user"))?;
        let role_ids =
            self.storage.list_user_realm_roles(&permit.target.realm_id, &user_id).await?;
        let mut realm_roles = Vec::with_capacity(role_ids.len());
        for role_id in role_ids {
            if let Some(role) = self.storage.get_role(&permit.target.realm_id, &role_id).await? {
                realm_roles.push(role.name.to_string());
            }
        }
        realm_roles.sort();
        realm_roles.dedup();
        let mut groups: Vec<_> = self
            .storage
            .list_user_groups(&permit.target.realm_id, &user_id)
            .await?
            .into_iter()
            .map(|id| id.to_string())
            .collect();
        groups.sort();
        groups.dedup();
        output(UserDetailsOutput {
            user: UserOutput::from(&user),
            realm_roles,
            groups,
        })
    }

    async fn clients_list(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let args: ClientsListArgs = decode(arguments)?;
        validate_optional_bounded(&args.client_id, "clientId", MAX_INPUT_STRING_BYTES)?;
        let mut clients = if let Some(client_id) = exact_filter(&args.client_id) {
            let identifier = ClientIdentifier::new(client_id)
                .map_err(|error| McpError::InvalidInput(error.to_string()))?;
            self.storage
                .get_client_by_client_id(&permit.target.realm_id, &identifier)
                .await?
                .into_iter()
                .collect()
        } else {
            let pagination = pagination(args.first, args.max)?;
            self.storage.list_clients(&permit.target.realm_id, &pagination).await?
        };
        clients.sort_by(|left, right| {
            left.client_id
                .as_str()
                .cmp(right.client_id.as_str())
                .then_with(|| left.id.cmp(&right.id))
        });
        output(ClientsOutput {
            clients: clients.iter().map(ClientOutput::from).collect(),
        })
    }

    async fn clients_get(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let args: ClientGetArgs = decode(arguments)?;
        let id = required_id(&args.id, "id")?;
        let uuid = uuid::Uuid::parse_str(id)
            .map_err(|_| McpError::InvalidInput("id must be a client UUID".into()))?;
        let client_id = ClientId::new(uuid.to_string())
            .map_err(|error| McpError::InvalidInput(error.to_string()))?;
        let client = self
            .storage
            .get_client(&permit.target.realm_id, &client_id)
            .await?
            .ok_or(McpError::NotFound("client"))?;
        output(ClientOutput::from(&client))
    }
}

fn deny_to_error(decision: PolicyDecision) -> Result<(), McpError> {
    match decision {
        PolicyDecision::Allow => Ok(()),
        PolicyDecision::Deny(PolicyDeny::MissingScope(scope)) => Err(McpError::MissingScope(scope)),
        PolicyDecision::Deny(PolicyDeny::MissingRole { tool, roles }) => {
            Err(McpError::MissingRole { tool, roles })
        }
    }
}

fn decode<T: DeserializeOwned>(arguments: Option<JsonObject>) -> Result<T, McpError> {
    serde_json::from_value(Value::Object(arguments.unwrap_or_default()))
        .map_err(|error| McpError::InvalidInput(error.to_string()))
}

fn output(value: impl Serialize) -> Result<Value, McpError> {
    serde_json::to_value(value).map_err(|_| {
        McpError::Backend(issuerd_core::IssuerdError::ServerError(
            "tool result serialization failed".into(),
        ))
    })
}

fn exact_filter(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|value| !value.is_empty())
}

fn validate_optional_bounded(
    value: &Option<String>,
    field: &str,
    maximum_bytes: usize,
) -> Result<(), McpError> {
    if let Some(value) = value {
        validate_bounded(value, field, maximum_bytes)?;
    }
    Ok(())
}

fn required_id<'a>(value: &'a str, field: &str) -> Result<&'a str, McpError> {
    validate_bounded(value, field, MAX_INPUT_STRING_BYTES)?;
    if value.is_empty() || value.trim() != value {
        return Err(McpError::InvalidInput(format!(
            "{field} must be nonempty and have no surrounding whitespace"
        )));
    }
    Ok(value)
}

fn validate_bounded(value: &str, field: &str, maximum_bytes: usize) -> Result<(), McpError> {
    if value.len() > maximum_bytes {
        return Err(McpError::InvalidInput(format!("{field} exceeds {maximum_bytes} bytes")));
    }
    if value.chars().any(char::is_control) {
        return Err(McpError::InvalidInput(format!("{field} must not contain control characters")));
    }
    Ok(())
}

fn pagination(first: Option<u32>, max: Option<u32>) -> Result<Pagination, McpError> {
    let first = first.unwrap_or(0);
    let max = max.unwrap_or(DEFAULT_PAGE_SIZE);
    if max > MAX_PAGE_SIZE {
        return Err(McpError::InvalidInput(format!("max must be at most {MAX_PAGE_SIZE}")));
    }
    let first = i32::try_from(first)
        .map_err(|_| McpError::InvalidInput("first exceeds the supported range".into()))?;
    Ok(Pagination::new(first, max as i32))
}

fn sort_users(users: &mut [issuerd_core::User]) {
    users.sort_by(|left, right| {
        left.username
            .as_str()
            .cmp(right.username.as_str())
            .then_with(|| left.id.cmp(&right.id))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use issuerd_cluster::InMemoryCache;
    use issuerd_core::{IssuerdError, MockStorage};
    use serde_json::json;

    const NOW: u64 = 120;

    fn executor_with_limit(storage: Arc<dyn Storage>, limit: u64) -> McpToolExecutor {
        McpToolExecutor::new(storage, McpRateLimiter::new(Arc::new(InMemoryCache::new()), limit))
    }

    fn executor(storage: Arc<dyn Storage>) -> McpToolExecutor {
        executor_with_limit(storage, 1_000)
    }

    fn arguments(value: Value) -> Option<JsonObject> {
        Some(value.as_object().unwrap().clone())
    }

    async fn permit(executor: &McpToolExecutor, tool: ToolName) -> McpToolPermit {
        let role = match tool {
            ToolName::RealmGet => "view-realm",
            ToolName::UsersGet | ToolName::UsersSearch => "view-users",
            ToolName::ClientsGet | ToolName::ClientsList => "view-clients",
        };
        executor.preflight(tool.as_str(), auth("mcp:read", &[role]), NOW).await.unwrap()
    }

    async fn execute(
        executor: &McpToolExecutor,
        tool: ToolName,
        args: Value,
    ) -> Result<Value, McpError> {
        let permit = permit(executor, tool).await;
        executor.execute(&permit, arguments(args)).await
    }

    #[tokio::test]
    async fn realm_get_happy_path_and_all_dto_canaries() {
        let result = execute(&executor(storage().await), ToolName::RealmGet, json!({}))
            .await
            .unwrap();
        assert_eq!(result["realm"], "demo");
        let serialized = result.to_string();
        for canary in [REALM_SECRET, PAIRWISE_SECRET, "attributes", "smtpServer"] {
            assert!(!serialized.contains(canary), "leaked {canary}");
        }
    }

    #[tokio::test]
    async fn users_exact_username_precedes_every_other_filter_and_pagination() {
        let result = execute(
            &executor(storage().await),
            ToolName::UsersSearch,
            json!({
                "username": "  alice  ",
                "email": "bob@other.example",
                "search": "no-match",
                "first": 4_294_967_295_u32,
                "max": 101
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["users"].as_array().unwrap().len(), 1);
        assert_eq!(result["users"][0]["username"], "alice");
    }

    #[tokio::test]
    async fn users_exact_email_precedes_substring_and_pagination() {
        let result = execute(
            &executor(storage().await),
            ToolName::UsersSearch,
            json!({"email": " bob@other.example ", "search": "alice", "max": 0}),
        )
        .await
        .unwrap();
        assert_eq!(result["users"].as_array().unwrap().len(), 1);
        assert_eq!(result["users"][0]["username"], "bob");
    }

    #[tokio::test]
    async fn users_substring_only_covers_username_and_email_with_stable_order() {
        let result =
            execute(&executor(storage().await), ToolName::UsersSearch, json!({"search": "ali"}))
                .await
                .unwrap();
        let usernames: Vec<_> = result["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|user| user["username"].as_str().unwrap())
            .collect();
        assert_eq!(usernames, ["alice", "alicia"]);
        for user in result["users"].as_array().unwrap() {
            assert!(user.get("realmRoles").is_none());
            assert!(user.get("groups").is_none());
            assert!(!user.to_string().contains(USER_SECRET));
        }

        for query in ["Given", "Surname"] {
            let no_name_match = execute(
                &executor(storage().await),
                ToolName::UsersSearch,
                json!({"search": query}),
            )
            .await
            .unwrap();
            assert!(no_name_match["users"].as_array().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn users_pagination_defaults_bounds_and_empty_pages() {
        let executor = executor(storage().await);
        let result = execute(&executor, ToolName::UsersSearch, json!({"first": 1, "max": 1}))
            .await
            .unwrap();
        assert_eq!(result["users"].as_array().unwrap().len(), 1);
        assert_eq!(result["users"][0]["username"], "alicia");

        let default_page = execute(&executor, ToolName::UsersSearch, json!({})).await.unwrap();
        assert_eq!(default_page["users"].as_array().unwrap().len(), 3);
        let empty = execute(&executor, ToolName::UsersSearch, json!({"max": 0})).await.unwrap();
        assert!(empty["users"].as_array().unwrap().is_empty());
        let beyond = execute(&executor, ToolName::UsersSearch, json!({"first": 99})).await.unwrap();
        assert!(beyond["users"].as_array().unwrap().is_empty());

        for args in [
            json!({"max": 101}),
            json!({"first": 4_294_967_295_u32}),
            json!({"search": "x".repeat(256)}),
            json!({"username": "x".repeat(256)}),
            json!({"email": "x".repeat(255)}),
            json!({"max": -1}),
            json!({"first": -1}),
        ] {
            assert!(matches!(
                execute(&executor, ToolName::UsersSearch, args).await,
                Err(McpError::InvalidInput(_))
            ));
        }
    }

    #[tokio::test]
    async fn users_get_includes_only_direct_sorted_roles_and_groups() {
        let result =
            execute(&executor(storage().await), ToolName::UsersGet, json!({"id": ALICE_ID}))
                .await
                .unwrap();
        assert_eq!(result["id"], ALICE_ID);
        assert_eq!(result["realmRoles"], json!(["alpha-role", "zeta-role"]));
        let groups = result["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups[0].as_str().unwrap() < groups[1].as_str().unwrap());
        assert!(!result.to_string().contains(USER_SECRET));
        assert!(result.get("attributes").is_none());
        assert!(result.get("clientRoles").is_none());
    }

    #[tokio::test]
    async fn user_get_validates_input_and_not_found() {
        let executor = executor(storage().await);
        for args in [
            json!({"id": "missing"}),
            json!({"id": format!(" {ALICE_ID} ")}),
            json!({"id": ""}),
            json!({"id": "x".repeat(256)}),
        ] {
            let result = execute(&executor, ToolName::UsersGet, args).await;
            if matches!(result, Err(McpError::NotFound("user"))) {
                continue;
            }
            assert!(matches!(result, Err(McpError::InvalidInput(_))), "{result:?}");
        }
    }

    #[tokio::test]
    async fn clients_exact_identifier_precedes_pagination() {
        let result = execute(
            &executor(storage().await),
            ToolName::ClientsList,
            json!({"clientId": " alpha-client ", "first": 99, "max": 101}),
        )
        .await
        .unwrap();
        assert_eq!(result["clients"].as_array().unwrap().len(), 1);
        assert_eq!(result["clients"][0]["id"], ALPHA_CLIENT_ID);
        let serialized = result.to_string();
        for canary in [
            CLIENT_SECRET,
            CLIENT_ATTRIBUTE_SECRET,
            "attributes",
            "protocolMappers",
        ] {
            assert!(!serialized.contains(canary), "leaked {canary}");
        }
    }

    #[tokio::test]
    async fn clients_list_is_sorted_and_paginated() {
        let executor = executor(storage().await);
        let all = execute(&executor, ToolName::ClientsList, json!({})).await.unwrap();
        let names: Vec<_> = all["clients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|client| client["clientId"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["alpha-client", "beta-client", "zeta-client"]);

        let page = execute(&executor, ToolName::ClientsList, json!({"first": 1, "max": 1}))
            .await
            .unwrap();
        assert_eq!(page["clients"].as_array().unwrap().len(), 1);
        assert_eq!(page["clients"][0]["clientId"], "beta-client");
        for args in [json!({"max": 101}), json!({"clientId": "x".repeat(256)})] {
            assert!(matches!(
                execute(&executor, ToolName::ClientsList, args).await,
                Err(McpError::InvalidInput(_))
            ));
        }
    }

    #[tokio::test]
    async fn clients_get_requires_internal_uuid_and_redacts() {
        let executor = executor(storage().await);
        let result = execute(&executor, ToolName::ClientsGet, json!({"id": ALPHA_CLIENT_ID}))
            .await
            .unwrap();
        assert_eq!(result["clientId"], "alpha-client");
        assert!(!result.to_string().contains(CLIENT_SECRET));
        assert!(result.get("secret").is_none());
        assert!(result.get("protocolMappers").is_none());
        assert!(result.get("attributes").is_none());

        assert!(matches!(
            execute(&executor, ToolName::ClientsGet, json!({"id": "alpha-client"})).await,
            Err(McpError::InvalidInput(_))
        ));
        assert_eq!(
            execute(
                &executor,
                ToolName::ClientsGet,
                json!({"id": "99999999-9999-4999-8999-999999999999"})
            )
            .await,
            Err(McpError::NotFound("client"))
        );
    }

    #[tokio::test]
    async fn every_successful_result_conforms_to_its_output_schema() {
        let executor = executor(storage().await);
        let cases = [
            (ToolName::RealmGet, json!({})),
            (ToolName::UsersSearch, json!({"search": "ali"})),
            (ToolName::UsersGet, json!({"id": ALICE_ID})),
            (ToolName::ClientsList, json!({})),
            (ToolName::ClientsGet, json!({"id": ALPHA_CLIENT_ID})),
        ];
        for (tool, args) in cases {
            let result = execute(&executor, tool, args).await.unwrap();
            let definition = crate::tools::definition(tool);
            let schema = Value::Object(definition.output_schema.unwrap().as_ref().clone());
            assert_schema(&schema, &schema, &result);
        }
    }

    fn assert_schema(root: &Value, schema: &Value, value: &Value) {
        if let Some(reference) = schema["$ref"].as_str() {
            let target =
                reference.strip_prefix("#/").unwrap().split('/').fold(root, |current, segment| {
                    current
                        .get(segment.replace("~1", "/").replace("~0", "~"))
                        .unwrap_or(&Value::Null)
                });
            assert_schema(root, target, value);
            return;
        }
        if let Some(all_of) = schema["allOf"].as_array() {
            for part in all_of {
                assert_schema(root, part, value);
            }
        }
        if let Some(any_of) = schema["anyOf"].as_array() {
            assert!(
                any_of.iter().any(|part| matches_schema_type(part, value)),
                "{schema} vs {value}"
            );
        }
        if let Some(one_of) = schema["oneOf"].as_array() {
            assert_eq!(one_of.iter().filter(|part| matches_schema_type(part, value)).count(), 1);
        }
        assert!(matches_schema_type(schema, value), "{schema} vs {value}");
        if value.is_object() {
            let object = value.as_object().unwrap();
            for required in schema["required"].as_array().into_iter().flatten() {
                assert!(object.contains_key(required.as_str().unwrap()), "missing {required}");
            }
            if schema["additionalProperties"] == false {
                let properties = schema["properties"].as_object();
                assert!(object.keys().all(|key| {
                    properties.is_some_and(|properties| properties.contains_key(key))
                }));
            }
            for (key, property_schema) in schema["properties"].as_object().into_iter().flatten() {
                if let Some(property) = object.get(key) {
                    assert_schema(root, property_schema, property);
                }
            }
        }
        if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
            for item in array {
                assert_schema(root, items, item);
            }
        }
    }

    fn matches_schema_type(schema: &Value, value: &Value) -> bool {
        match schema["type"].as_str() {
            Some("object") => value.is_object(),
            Some("array") => value.is_array(),
            Some("string") => value.is_string(),
            Some("boolean") => value.is_boolean(),
            Some("integer") => value.is_i64() || value.is_u64(),
            Some("number") => value.is_number(),
            Some("null") => value.is_null(),
            Some(_) => true,
            None => schema["type"].as_array().is_none_or(|types| {
                types.iter().any(|kind| matches_schema_type(&json!({"type": kind}), value))
            }),
        }
    }

    #[tokio::test]
    async fn unknown_and_under_authorized_calls_consume_allowance() {
        let storage: Arc<dyn Storage> = storage().await;
        let unknown_executor = executor_with_limit(Arc::clone(&storage), 1);
        let context = auth("mcp:read", &["view-realm"]);
        assert!(matches!(
            unknown_executor.preflight("not_a_tool", context.clone(), NOW).await,
            Err(McpError::UnknownTool(_))
        ));
        assert!(matches!(
            unknown_executor.preflight("realm_get", context, NOW).await,
            Err(McpError::RateLimited { .. })
        ));

        let denied_executor = executor_with_limit(storage, 1);
        let denied = auth("openid", &["view-realm"]);
        assert_eq!(
            denied_executor.preflight("realm_get", denied, NOW).await,
            Err(McpError::MissingScope("mcp:read"))
        );
        assert!(matches!(
            denied_executor
                .preflight("realm_get", auth("mcp:read", &["view-realm"]), NOW)
                .await,
            Err(McpError::RateLimited { .. })
        ));
    }

    #[tokio::test]
    async fn execute_repeats_policy_without_counting_permit_again() {
        let storage: Arc<dyn Storage> = storage().await;
        let executor = executor_with_limit(storage, 1);
        let permit = permit(&executor, ToolName::RealmGet).await;
        executor.execute(&permit, None).await.unwrap();
        executor.execute(&permit, None).await.unwrap();

        let mut revoked = permit.clone();
        revoked.auth = auth("mcp:read", &["unrelated"]);
        assert!(matches!(
            executor.execute(&revoked, None).await,
            Err(McpError::MissingRole { .. })
        ));
    }

    #[tokio::test]
    async fn backend_temporary_failures_remain_typed() {
        let mut mock = MockStorage::new();
        mock.expect_get_realm().returning(|_| Err(IssuerdError::TemporarilyUnavailable));
        let executor = executor(Arc::new(mock));
        let permit = permit(&executor, ToolName::RealmGet).await;
        let error = executor.execute(&permit, None).await.unwrap_err();
        assert_eq!(error, McpError::Backend(IssuerdError::TemporarilyUnavailable));
        assert!(error.is_temporary());
    }

    #[tokio::test]
    async fn business_and_input_errors_never_produce_success_values() {
        let executor = executor(storage().await);
        for result in [
            execute(&executor, ToolName::UsersGet, json!({"id": "missing"})).await,
            execute(&executor, ToolName::UsersSearch, json!({"max": 1000})).await,
            execute(&executor, ToolName::ClientsGet, json!({"id": "not-a-uuid"})).await,
        ] {
            assert!(result.is_err());
        }
    }
}
