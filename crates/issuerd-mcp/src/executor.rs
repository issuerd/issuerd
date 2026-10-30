// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use issuerd_core::{
    escape_scan_pattern, expand_composites, list_all_roles, ClientId, ClientIdentifier, GroupId,
    Pagination, RealmId, RealmName, Role, RoleName, Storage, User, UserId,
};
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
        AttackDetectionStatusOutput, ClientGetArgs, ClientOutput, ClientRoleMappingsOutput,
        ClientsListArgs, ClientsOutput, CredentialOutput, GroupGetArgs, GroupMembersArgs,
        GroupOutput, GroupsListArgs, GroupsOutput, NoArgs, RealmOutput, RoleGetArgs, RoleOutput,
        RolesListArgs, RolesOutput, UserCredentialsOutput, UserDetailsOutput, UserGetArgs,
        UserOutput, UserRoleMappingsOutput, UserSessionOutput, UserSessionsOutput, UsersOutput,
        UsersSearchArgs, DEFAULT_PAGE_SIZE, MAX_INPUT_STRING_BYTES, MAX_PAGE_SIZE,
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

#[derive(Debug, Clone)]
pub struct McpStrictResult(pub Value);

#[derive(Debug)]
pub enum McpStrictCoordination {
    NotStrict,
    Pending(Box<crate::step_up::PendingOperation>),
    Complete(Value),
}

#[derive(Clone)]
pub struct McpToolExecutor {
    pub(crate) storage: Arc<dyn Storage>,
    pub(crate) application: Option<Arc<dyn crate::services::McpApplicationService>>,
    limiter: McpRateLimiter,
    step_up_enabled: bool,
}

impl McpToolExecutor {
    pub fn new(storage: Arc<dyn Storage>, limiter: McpRateLimiter) -> Self {
        Self {
            storage,
            application: None,
            limiter,
            step_up_enabled: false,
        }
    }

    pub fn with_step_up(mut self, enabled: bool) -> Self {
        self.step_up_enabled = enabled;
        self
    }

    pub fn step_up_enabled(&self) -> bool {
        self.step_up_enabled
    }

    pub fn with_application_service(
        mut self,
        application: Arc<dyn crate::services::McpApplicationService>,
    ) -> Self {
        self.application = Some(application);
        self
    }

    pub fn limiter(&self) -> &McpRateLimiter {
        &self.limiter
    }

    pub async fn coordinate_strict(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
        resource: String,
        dpop_jkt: Option<String>,
        now: i64,
    ) -> Result<McpStrictCoordination, McpError> {
        if !self.step_up_enabled {
            return Ok(McpStrictCoordination::NotStrict);
        }
        let operation = if crate::strict_tools::is_strict(permit.tool) {
            crate::strict_tools::parse_operation(permit.tool, arguments)?
        } else if crate::policy::is_strict_self_service(permit.tool) {
            crate::account_tools::parse_operation(permit.tool, arguments)?
        } else if crate::write_tools::is_admin_write(permit.tool) {
            crate::write_tools::parse_operation(permit.tool, arguments)?
        } else {
            return Ok(McpStrictCoordination::NotStrict);
        };
        if permit.auth.has_scope(issuerd_core::MCP_SCOPE_STEP_UP) {
            let Some(dpop_jkt) = dpop_jkt.clone() else {
                return Err(McpError::Forbidden("strict operations require DPoP"));
            };
            if let Some(grant) = self.storage.get_mcp_step_up_grant(&permit.auth.claims.jti).await?
            {
                if grant.tool != permit.tool.as_str()
                    || grant.realm_id != permit.auth.realm_id
                    || grant.client_id != permit.auth.azp
                    || grant.subject_user_id != permit.auth.user_id
                    || grant.resource != resource
                    || crate::strict_tools::target_id(&operation, &permit.auth)
                        != Some(grant.mutation.target_id())
                {
                    return Err(McpError::OperationBindingMismatch);
                }
                if grant.status != issuerd_core::McpStepUpExecutionStatus::Active {
                    return self
                        .execute_strict(permit, operation, grant.mutation, resource, dpop_jkt, now)
                        .await;
                }
            }
        }
        let application = self.application.as_ref().ok_or_else(|| {
            McpError::Backend(issuerd_core::IssuerdError::ServerError(
                "MCP application service is not configured".into(),
            ))
        })?;
        let Some(mutation) = application.prepare_strict(&permit.auth, operation.clone()).await?
        else {
            return Ok(McpStrictCoordination::NotStrict);
        };
        let Some(dpop_jkt) = dpop_jkt else {
            return Err(McpError::Forbidden("strict operations require DPoP"));
        };
        if permit.auth.has_scope(issuerd_core::MCP_SCOPE_STEP_UP) {
            return self.execute_strict(permit, operation, mutation, resource, dpop_jkt, now).await;
        }

        let pending = crate::step_up::PendingOperation::new(
            &permit.auth,
            resource,
            permit.tool,
            operation.arguments,
            mutation,
            dpop_jkt,
            now,
            crate::step_up::DEFAULT_OPERATION_TTL_SECS,
        )?;
        let bytes = serde_json::to_vec(&pending).map_err(|error| {
            McpError::Backend(issuerd_core::IssuerdError::ServerError(format!(
                "pending operation serialization failed: {error}"
            )))
        })?;
        let key = pending_operation_key(&pending.realm_id, &pending.operation_id);
        let created = self
            .limiter
            .cache()
            .create_if_absent(
                &key,
                bytes,
                Some(std::time::Duration::from_secs(
                    u64::try_from(pending.expires_at.saturating_sub(now).max(1))
                        .unwrap_or(u64::MAX),
                )),
            )
            .await?;
        if !created {
            return Err(McpError::Conflict("operation identifier already exists"));
        }
        Ok(McpStrictCoordination::Pending(Box::new(pending)))
    }

    async fn execute_strict(
        &self,
        permit: &McpToolPermit,
        operation: crate::write_tools::McpOperation,
        mutation: issuerd_core::McpStepUpMutation,
        resource: String,
        dpop_jkt: String,
        now: i64,
    ) -> Result<McpStrictCoordination, McpError> {
        let grant = self
            .storage
            .get_mcp_step_up_grant(&permit.auth.claims.jti)
            .await?
            .ok_or(McpError::OperationBindingMismatch)?;
        let reconciled = grant.status == issuerd_core::McpStepUpExecutionStatus::Succeeded;
        let target_id = grant.mutation.target_id();
        let pending = crate::step_up::PendingOperation::for_execution(
            &permit.auth,
            resource,
            permit.tool,
            operation.arguments,
            mutation,
            &grant,
        )?;
        crate::step_up::verify_grant(&permit.auth, &grant, &pending, &dpop_jkt, now)?;
        let result = serde_json::to_value(crate::write_tools::WriteOutput::completed(
            permit.tool,
            Some(target_id),
        ))
        .map_err(|error| {
            McpError::Backend(issuerd_core::IssuerdError::ServerError(format!(
                "strict result serialization failed: {error}"
            )))
        })?;
        let execution = self
            .storage
            .execute_mcp_step_up(
                &permit.auth.claims.jti,
                &pending.operation_hash,
                &pending.mutation,
                result,
            )
            .await
            .map_err(|error| match error {
                issuerd_core::IssuerdError::AccessDenied => McpError::OperationBindingMismatch,
                issuerd_core::IssuerdError::InvalidGrant => McpError::GrantExpired,
                issuerd_core::IssuerdError::Conflict => {
                    McpError::Conflict("step-up target preconditions changed")
                }
                other => McpError::Backend(other),
            })?;
        if execution.status != issuerd_core::McpStepUpExecutionStatus::Succeeded {
            return Err(McpError::OutcomeUnknown);
        }
        let application = self.application.as_ref().ok_or_else(|| {
            McpError::Backend(issuerd_core::IssuerdError::ServerError(
                "MCP application service is not configured".into(),
            ))
        })?;
        if !reconciled {
            application.strict_committed(&grant).await;
        }
        execution.result_json.map(McpStrictCoordination::Complete).ok_or_else(|| {
            McpError::Backend(issuerd_core::IssuerdError::ServerError(
                "committed strict result is missing".into(),
            ))
        })
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
        if crate::strict_tools::is_strict(tool) && !self.step_up_enabled {
            return Err(McpError::UnknownTool(tool_name.to_string()));
        }
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
        if crate::account_tools::is_account_tool(permit.tool) {
            let operation = crate::account_tools::parse_operation(permit.tool, arguments)?;
            let application = self.application.as_ref().ok_or_else(|| {
                McpError::Backend(issuerd_core::IssuerdError::ServerError(
                    "MCP application service is not configured".into(),
                ))
            })?;
            return application.account(&permit.auth, operation).await;
        }
        if crate::write_tools::is_admin_write(permit.tool) {
            let operation = crate::write_tools::parse_operation(permit.tool, arguments)?;
            let application = self.application.as_ref().ok_or_else(|| {
                McpError::Backend(issuerd_core::IssuerdError::ServerError(
                    "MCP application service is not configured".into(),
                ))
            })?;
            return application.write(&permit.auth, operation).await;
        }
        match permit.tool {
            ToolName::AttackDetectionStatus => {
                self.attack_detection_status(permit, arguments).await
            }
            ToolName::ClientScopesList
            | ToolName::EventsSearch
            | ToolName::FlowsList
            | ToolName::IdpGet
            | ToolName::IdpList
            | ToolName::KeysList
            | ToolName::ServerinfoGet
            | ToolName::SessionsList => {
                crate::read_inventory::execute(self, permit, arguments).await
            }
            ToolName::RealmGet => self.realm_get(permit, arguments).await,
            ToolName::UsersSearch => self.users_search(permit, arguments).await,
            ToolName::UsersGet => self.users_get(permit, arguments).await,
            ToolName::UsersGetGroups => self.users_get_groups(permit, arguments).await,
            ToolName::UsersGetRoleMappings => self.users_get_role_mappings(permit, arguments).await,
            ToolName::UsersGetSessions => self.users_get_sessions(permit, arguments).await,
            ToolName::UsersGetCredentials => self.users_get_credentials(permit, arguments).await,
            ToolName::ClientsList => self.clients_list(permit, arguments).await,
            ToolName::ClientsGet => self.clients_get(permit, arguments).await,
            ToolName::GroupsList => self.groups_list(permit, arguments).await,
            ToolName::GroupsGet => self.groups_get(permit, arguments).await,
            ToolName::GroupsMembers => self.groups_members(permit, arguments).await,
            ToolName::RolesList => self.roles_list(permit, arguments).await,
            ToolName::RolesGet => self.roles_get(permit, arguments).await,
            _ => unreachable!("admin writes use the application service"),
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
        let uuid = uuid::Uuid::parse_str(id)
            .map_err(|_| McpError::InvalidInput("id must be a user UUID".into()))?;
        let user_id = UserId::new(uuid.to_string())
            .map_err(|error| McpError::InvalidInput(error.to_string()))?;
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

    async fn load_user(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<(User, UserId), McpError> {
        let args: UserGetArgs = decode(arguments)?;
        let id = required_id(&args.id, "id")?;
        let uuid = uuid::Uuid::parse_str(id)
            .map_err(|_| McpError::InvalidInput("id must be a user UUID".into()))?;
        let user_id = UserId::new(uuid.to_string())
            .map_err(|error| McpError::InvalidInput(error.to_string()))?;
        let user = self
            .storage
            .get_user(&permit.target.realm_id, &user_id)
            .await?
            .ok_or(McpError::NotFound("user"))?;
        Ok((user, user_id))
    }

    async fn users_get_groups(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let (_, user_id) = self.load_user(permit, arguments).await?;
        let group_ids = self.storage.list_user_groups(&permit.target.realm_id, &user_id).await?;
        let mut groups = self.storage.get_groups_batch(&permit.target.realm_id, &group_ids).await?;
        groups.sort_by(|left, right| {
            left.name.as_str().cmp(right.name.as_str()).then_with(|| left.id.cmp(&right.id))
        });
        output(GroupsOutput {
            groups: groups.iter().map(GroupOutput::from).collect(),
        })
    }

    async fn users_get_role_mappings(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let (_, user_id) = self.load_user(permit, arguments).await?;
        let all_roles = list_all_roles(self.storage.as_ref(), &permit.target.realm_id).await?;
        let direct_realm_ids: HashSet<_> = self
            .storage
            .list_user_realm_roles(&permit.target.realm_id, &user_id)
            .await?
            .into_iter()
            .collect();
        let direct_client_ids: HashSet<_> = self
            .storage
            .list_user_client_roles(&permit.target.realm_id, &user_id)
            .await?
            .into_iter()
            .collect();
        let group_ids = self.storage.list_user_groups(&permit.target.realm_id, &user_id).await?;
        let groups = self.storage.get_groups_batch(&permit.target.realm_id, &group_ids).await?;
        let mut seeds: Vec<_> = all_roles
            .iter()
            .filter(|role| {
                direct_realm_ids.contains(&role.id) || direct_client_ids.contains(&role.id)
            })
            .cloned()
            .collect();
        for group in groups {
            seeds.extend(
                all_roles
                    .iter()
                    .filter(|role| {
                        if role.client_role {
                            role.client_id
                                .as_ref()
                                .and_then(|client_id| group.client_roles.get(client_id))
                                .is_some_and(|names| names.contains(&role.name))
                        } else {
                            group.realm_roles.contains(&role.name)
                        }
                    })
                    .cloned(),
            );
        }
        let effective = expand_composites(seeds, &all_roles);
        let effective_ids: HashSet<_> = effective.iter().map(|role| role.id.clone()).collect();

        let realm_mappings = role_outputs(
            all_roles
                .iter()
                .filter(|role| !role.client_role && direct_realm_ids.contains(&role.id)),
        );
        let available_realm_mappings = role_outputs(
            all_roles
                .iter()
                .filter(|role| !role.client_role && !effective_ids.contains(&role.id)),
        );
        let effective_realm_mappings =
            role_outputs(effective.iter().filter(|role| !role.client_role));

        let clients = self
            .storage
            .list_clients(
                &permit.target.realm_id,
                &Pagination {
                    first: 0,
                    max: i32::MAX,
                },
            )
            .await?;
        let mut client_mappings = BTreeMap::new();
        for client in clients {
            if !all_roles
                .iter()
                .any(|role| role.client_role && role.client_id.as_ref() == Some(&client.id))
            {
                continue;
            }
            let mappings = role_outputs(all_roles.iter().filter(|role| {
                role.client_role
                    && role.client_id.as_ref() == Some(&client.id)
                    && direct_client_ids.contains(&role.id)
            }));
            let available_mappings = role_outputs(all_roles.iter().filter(|role| {
                role.client_role
                    && role.client_id.as_ref() == Some(&client.id)
                    && !effective_ids.contains(&role.id)
            }));
            let effective_mappings =
                role_outputs(effective.iter().filter(|role| {
                    role.client_role && role.client_id.as_ref() == Some(&client.id)
                }));
            client_mappings.insert(
                client.client_id.to_string(),
                ClientRoleMappingsOutput {
                    id: client.id.to_string(),
                    client: client.client_id.to_string(),
                    mappings,
                    available_mappings,
                    effective_mappings,
                },
            );
        }
        output(UserRoleMappingsOutput {
            realm_mappings,
            available_realm_mappings,
            effective_realm_mappings,
            client_mappings,
        })
    }

    async fn users_get_sessions(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let (_, user_id) = self.load_user(permit, arguments).await?;
        let mut sessions = self
            .storage
            .list_sessions(&permit.target.realm_id, Some(user_id), &Pagination::default())
            .await?;
        sessions.sort_by(|left, right| {
            right
                .last_session_refresh
                .cmp(&left.last_session_refresh)
                .then_with(|| left.id.cmp(&right.id))
        });
        output(UserSessionsOutput {
            sessions: sessions.iter().map(UserSessionOutput::from).collect(),
        })
    }

    async fn users_get_credentials(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let (_, user_id) = self.load_user(permit, arguments).await?;
        let mut credentials =
            self.storage.list_credentials(&permit.target.realm_id, &user_id).await?;
        credentials.sort_by(|left, right| {
            (left.priority, left.created_date)
                .cmp(&(right.priority, right.created_date))
                .then_with(|| left.id.cmp(&right.id))
        });
        output(UserCredentialsOutput {
            credentials: credentials.iter().map(CredentialOutput::from).collect(),
        })
    }

    async fn attack_detection_status(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let (user, _) = self.load_user(permit, arguments).await?;
        let mut num_failures = 0_u32;
        for key in self
            .user_cache_keys("login-failure", &permit.target.realm_id, user.username.as_str())
            .await?
        {
            if let Some(raw) = self.limiter.cache().get(&key).await? {
                let count = std::str::from_utf8(&raw)
                    .ok()
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap_or(0);
                num_failures = num_failures.saturating_add(count);
            }
        }
        let locked = !self
            .user_cache_keys("login-lockout", &permit.target.realm_id, user.username.as_str())
            .await?
            .is_empty();
        output(AttackDetectionStatusOutput {
            user_id: user.id.to_string(),
            username: user.username.to_string(),
            num_failures,
            locked,
        })
    }

    async fn user_cache_keys(
        &self,
        family: &str,
        realm_id: &RealmId,
        username: &str,
    ) -> Result<Vec<String>, McpError> {
        let prefix = format!("{family}:{realm_id}:{username}:");
        let pattern = format!("{}*", escape_scan_pattern(&prefix));
        let mut keys = self.limiter.cache().scan_keys(&pattern).await?;
        keys.retain(|key| key.starts_with(&prefix));
        Ok(keys)
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

    async fn groups_list(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let args: GroupsListArgs = decode(arguments)?;
        let pagination = pagination(args.first, args.max)?;
        let mut groups = self.storage.list_groups(&permit.target.realm_id, &pagination).await?;
        groups.sort_by(|left, right| {
            left.name.as_str().cmp(right.name.as_str()).then_with(|| left.id.cmp(&right.id))
        });
        output(GroupsOutput {
            groups: groups.iter().map(GroupOutput::from).collect(),
        })
    }

    async fn groups_get(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let args: GroupGetArgs = decode(arguments)?;
        let id = required_id(&args.id, "id")?;
        let uuid = uuid::Uuid::parse_str(id)
            .map_err(|_| McpError::InvalidInput("id must be a group UUID".into()))?;
        let group_id = GroupId::new(uuid.to_string())
            .map_err(|error| McpError::InvalidInput(error.to_string()))?;
        let group = self
            .storage
            .get_group(&permit.target.realm_id, &group_id)
            .await?
            .ok_or(McpError::NotFound("group"))?;
        output(GroupOutput::from(&group))
    }

    async fn groups_members(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let args: GroupMembersArgs = decode(arguments)?;
        let id = required_id(&args.id, "id")?;
        let uuid = uuid::Uuid::parse_str(id)
            .map_err(|_| McpError::InvalidInput("id must be a group UUID".into()))?;
        let group_id = GroupId::new(uuid.to_string())
            .map_err(|error| McpError::InvalidInput(error.to_string()))?;
        let pagination = pagination(args.first, args.max)?;
        self.storage
            .get_group(&permit.target.realm_id, &group_id)
            .await?
            .ok_or(McpError::NotFound("group"))?;
        let mut members = self
            .storage
            .list_group_members(
                &permit.target.realm_id,
                &group_id,
                pagination.first,
                pagination.max,
            )
            .await?;
        sort_users(&mut members);
        output(crate::tools::GroupMembersOutput {
            members: members.iter().map(UserOutput::from).collect(),
        })
    }

    async fn roles_list(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let args: RolesListArgs = decode(arguments)?;
        let pagination = pagination(args.first, args.max)?;
        let required = pagination.first.saturating_add(pagination.max);
        let mut roles = Vec::new();
        let mut storage_first = 0;
        if pagination.max > 0 {
            loop {
                let batch = self
                    .storage
                    .list_roles(
                        &permit.target.realm_id,
                        &Pagination {
                            first: storage_first,
                            max: 100,
                        },
                    )
                    .await?;
                let batch_len = batch.len();
                roles.extend(batch.into_iter().filter(|role| !role.client_role));
                if batch_len < 100 || roles.len() >= required as usize {
                    break;
                }
                storage_first = storage_first.saturating_add(100);
            }
        }
        roles.sort_by(|left, right| {
            left.name.as_str().cmp(right.name.as_str()).then_with(|| left.id.cmp(&right.id))
        });
        let roles = roles
            .into_iter()
            .skip(pagination.first.max(0) as usize)
            .take(pagination.max.max(0) as usize)
            .collect::<Vec<_>>();
        output(RolesOutput {
            roles: roles.iter().map(RoleOutput::from).collect(),
        })
    }

    async fn roles_get(
        &self,
        permit: &McpToolPermit,
        arguments: Option<JsonObject>,
    ) -> Result<Value, McpError> {
        let args: RoleGetArgs = decode(arguments)?;
        let name = required_id(&args.name, "name")?;
        let name =
            RoleName::new(name).map_err(|error| McpError::InvalidInput(error.to_string()))?;
        let role = self
            .storage
            .get_role_by_name(&permit.target.realm_id, name.as_str())
            .await?
            .ok_or(McpError::NotFound("role"))?;
        output(RoleOutput::from(&role))
    }
}

pub fn pending_operation_key(realm_id: &RealmId, operation_id: &str) -> String {
    format!("mcp:op:{{{realm_id}}}:{operation_id}")
}

fn role_outputs<'a>(roles: impl IntoIterator<Item = &'a Role>) -> Vec<RoleOutput> {
    let mut roles: Vec<_> = roles.into_iter().cloned().collect();
    roles.sort_by(|left, right| {
        left.name.as_str().cmp(right.name.as_str()).then_with(|| left.id.cmp(&right.id))
    });
    roles.iter().map(RoleOutput::from).collect()
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

pub(crate) fn decode<T: DeserializeOwned>(arguments: Option<JsonObject>) -> Result<T, McpError> {
    serde_json::from_value(Value::Object(arguments.unwrap_or_default()))
        .map_err(|error| McpError::InvalidInput(error.to_string()))
}

pub(crate) fn output(value: impl Serialize) -> Result<Value, McpError> {
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

pub(crate) fn pagination(first: Option<u32>, max: Option<u32>) -> Result<Pagination, McpError> {
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
    use issuerd_core::{CredentialType, DistributedCache, IssuerdError, MockStorage};
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
            ToolName::AttackDetectionStatus => "manage-users",
            ToolName::RealmGet
            | ToolName::EventsSearch
            | ToolName::FlowsList
            | ToolName::GroupsGet
            | ToolName::GroupsList
            | ToolName::IdpGet
            | ToolName::IdpList
            | ToolName::KeysList
            | ToolName::RolesGet
            | ToolName::RolesList
            | ToolName::ServerinfoGet
            | ToolName::SessionsList => "view-realm",
            ToolName::UsersGet
            | ToolName::UsersGetCredentials
            | ToolName::UsersGetGroups
            | ToolName::UsersGetRoleMappings
            | ToolName::UsersGetSessions
            | ToolName::UsersSearch
            | ToolName::GroupsMembers => "view-users",
            ToolName::ClientScopesList | ToolName::ClientsGet | ToolName::ClientsList => {
                "view-clients"
            }
            _ => "manage-realm",
        };
        let scope = if tool.tier() == crate::policy::RiskTier::T0 {
            "mcp:read"
        } else {
            "mcp:write"
        };
        executor.preflight(tool.as_str(), auth(scope, &[role]), NOW).await.unwrap()
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
    async fn groups_list_and_get_are_sorted_hierarchical_and_redacted() {
        let executor = executor(storage().await);
        let all = execute(&executor, ToolName::GroupsList, json!({})).await.unwrap();
        let groups = all["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["id"], ALPHA_GROUP_ID);
        assert_eq!(groups[0]["parentId"], Value::Null);
        assert_eq!(groups[1]["id"], ZETA_GROUP_ID);
        assert_eq!(groups[1]["parentId"], ALPHA_GROUP_ID);
        assert_eq!(groups[1]["path"], "/alpha-group/zeta-group");
        assert!(!all.to_string().contains(GROUP_SECRET));
        assert!(all["groups"][0].get("attributes").is_none());
        assert!(all["groups"][0].get("realmRoles").is_none());

        let page = execute(&executor, ToolName::GroupsList, json!({"first":1,"max":1}))
            .await
            .unwrap();
        assert_eq!(page["groups"].as_array().unwrap().len(), 1);
        let get = execute(&executor, ToolName::GroupsGet, json!({"id":ZETA_GROUP_ID}))
            .await
            .unwrap();
        assert_eq!(get["name"], "zeta-group");
        assert!(!get.to_string().contains(GROUP_SECRET));
    }

    #[tokio::test]
    async fn groups_list_preserves_storage_name_order_across_page_boundaries() {
        let storage = Arc::new(issuerd_storage::InMemoryStorage::new());
        let realm = realm();
        storage.create_realm(&realm).await.unwrap();
        let parent = group("60000000-0000-4000-8000-000000000001", "z", None);
        let other_root = group("60000000-0000-4000-8000-000000000002", "b", None);
        let mut child = group("60000000-0000-4000-8000-000000000003", "a", Some(parent.id.clone()));
        child.path = issuerd_core::GroupPath::new("/z/a").unwrap();
        for group in [parent, other_root, child] {
            storage.create_group(&realm.id, &group).await.unwrap();
        }
        let executor = executor(storage);

        let first = execute(&executor, ToolName::GroupsList, json!({"first":0,"max":2}))
            .await
            .unwrap();
        let first_names: Vec<_> = first["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group["name"].as_str().unwrap())
            .collect();
        assert_eq!(first_names, ["a", "b"]);
        let second = execute(&executor, ToolName::GroupsList, json!({"first":2,"max":2}))
            .await
            .unwrap();
        assert_eq!(second["groups"].as_array().unwrap().len(), 1);
        assert_eq!(second["groups"][0]["name"], "z");
    }

    #[tokio::test]
    async fn group_id_and_pagination_inputs_are_validated_before_storage() {
        let executor = executor(storage().await);
        for tool in [ToolName::GroupsGet, ToolName::GroupsMembers] {
            for args in [
                json!({"id":"not-a-uuid"}),
                json!({"id":format!(" {ALPHA_GROUP_ID} ")}),
                json!({"id":""}),
            ] {
                assert!(matches!(
                    execute(&executor, tool, args).await,
                    Err(McpError::InvalidInput(_))
                ));
            }
            assert_eq!(
                execute(&executor, tool, json!({"id":"99999999-9999-4999-8999-999999999999"}))
                    .await,
                Err(McpError::NotFound("group"))
            );
        }
        for args in [json!({"max":101}), json!({"first":4_294_967_295_u32})] {
            assert!(matches!(
                execute(&executor, ToolName::GroupsList, args.clone()).await,
                Err(McpError::InvalidInput(_))
            ));
            assert!(matches!(
                execute(&executor, ToolName::RolesList, args).await,
                Err(McpError::InvalidInput(_))
            ));
        }
        assert!(matches!(
            execute(
                &executor,
                ToolName::GroupsMembers,
                json!({"id":"99999999-9999-4999-8999-999999999999","max":101})
            )
            .await,
            Err(McpError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn groups_members_returns_sorted_safe_users() {
        let executor = executor(storage().await);
        let result = execute(&executor, ToolName::GroupsMembers, json!({"id":ZETA_GROUP_ID}))
            .await
            .unwrap();
        let names: Vec<_> = result["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|user| user["username"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["alice", "alicia", "bob"]);
        assert!(!result.to_string().contains(USER_SECRET));
        assert!(result["members"][0].get("credentials").is_none());
        let page = execute(
            &executor,
            ToolName::GroupsMembers,
            json!({"id":ZETA_GROUP_ID,"first":1,"max":1}),
        )
        .await
        .unwrap();
        assert_eq!(page["members"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn roles_list_and_get_preserve_role_shape_without_attributes() {
        let executor = executor(storage().await);
        let list = execute(&executor, ToolName::RolesList, json!({})).await.unwrap();
        let roles = list["roles"].as_array().unwrap();
        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0]["name"], "alpha-role");
        assert_eq!(roles[1]["name"], "zeta-role");
        assert_eq!(roles[1]["composite"], true);
        assert_eq!(roles[1]["composites"], json!(["alpha-role"]));
        assert!(roles.iter().all(|role| role["clientRole"] == false));
        assert!(!list.to_string().contains(ROLE_SECRET));
        assert!(list["roles"][0].get("attributes").is_none());
        let page = execute(&executor, ToolName::RolesList, json!({"first":1,"max":1}))
            .await
            .unwrap();
        assert_eq!(page["roles"].as_array().unwrap().len(), 1);
        assert_eq!(page["roles"][0]["name"], "zeta-role");

        let realm = execute(&executor, ToolName::RolesGet, json!({"name":"zeta-role"}))
            .await
            .unwrap();
        assert_eq!(realm["containerId"], REALM_ID);
        let client = execute(&executor, ToolName::RolesGet, json!({"name":"client-only-role"}))
            .await
            .unwrap();
        assert_eq!(client["clientRole"], true);
        assert_eq!(client["containerId"], ALPHA_CLIENT_ID);
        for args in [
            json!({"name":""}),
            json!({"name":" leading"}),
            json!({"name":"x".repeat(256)}),
        ] {
            assert!(matches!(
                execute(&executor, ToolName::RolesGet, args).await,
                Err(McpError::InvalidInput(_))
            ));
        }
        assert_eq!(
            execute(&executor, ToolName::RolesGet, json!({"name":"missing"})).await,
            Err(McpError::NotFound("role"))
        );
    }

    #[tokio::test]
    async fn roles_list_empty_page_does_not_read_storage() {
        let executor = executor(Arc::new(MockStorage::new()));
        let result = execute(&executor, ToolName::RolesList, json!({"first":99,"max":0}))
            .await
            .unwrap();
        assert!(result["roles"].as_array().unwrap().is_empty());
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
            json!({"id": "not-a-uuid"}),
        ] {
            let result = execute(&executor, ToolName::UsersGet, args).await;
            assert!(matches!(result, Err(McpError::InvalidInput(_))), "{result:?}");
            assert!(!result.unwrap_err().public_tool_message().contains("storage backend"));
        }

        let unknown = execute(
            &executor,
            ToolName::UsersGet,
            json!({"id": "20000000-0000-4000-8000-000000000099"}),
        )
        .await;
        assert!(matches!(unknown, Err(McpError::NotFound("user"))), "{unknown:?}");

        let uppercase =
            execute(&executor, ToolName::UsersGet, json!({"id": ALICE_ID.to_uppercase()}))
                .await
                .unwrap();
        assert_eq!(uppercase["id"], ALICE_ID);
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

    fn role_names(value: &Value) -> Vec<&str> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|role| role["name"].as_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn users_get_groups_returns_curated_direct_memberships() {
        let executor = executor(storage().await);
        let result = execute(&executor, ToolName::UsersGetGroups, json!({"id": ALICE_ID}))
            .await
            .unwrap();
        let names: Vec<_> = result["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["alpha-group", "zeta-group"]);
        assert_eq!(result["groups"][1]["parentId"], ALPHA_GROUP_ID);
        assert!(!result.to_string().contains(GROUP_SECRET));
        assert!(result["groups"][0].get("attributes").is_none());
    }

    #[tokio::test]
    async fn users_get_role_mappings_distinguishes_direct_available_and_effective_roles() {
        let storage = storage().await;
        let realm = realm();
        let alice = UserId::new(ALICE_ID).unwrap();
        storage
            .add_user_client_role(
                &realm.id,
                &alice,
                &issuerd_core::RoleId::new(CLIENT_ROLE_ID).unwrap(),
            )
            .await
            .unwrap();
        for (id, name, client_role) in [
            ("40000000-0000-4000-8000-000000000004", "available-realm-role", false),
            ("40000000-0000-4000-8000-000000000005", "group-realm-role", false),
            ("40000000-0000-4000-8000-000000000006", "client-available-role", true),
            ("40000000-0000-4000-8000-000000000007", "client-group-role", true),
        ] {
            let mut role = role(id, name);
            role.client_role = client_role;
            role.client_id = client_role.then(|| ClientId::new(ALPHA_CLIENT_ID).unwrap());
            storage.create_role(&realm.id, &role).await.unwrap();
        }
        let mut alpha_group = storage
            .get_group(&realm.id, &GroupId::new(ALPHA_GROUP_ID).unwrap())
            .await
            .unwrap()
            .unwrap();
        alpha_group.realm_roles = vec![RoleName::new("group-realm-role").unwrap()];
        alpha_group.client_roles.insert(
            ClientId::new(ALPHA_CLIENT_ID).unwrap(),
            vec![RoleName::new("client-group-role").unwrap()],
        );
        storage.update_group(&realm.id, &alpha_group).await.unwrap();
        let executor = executor(storage);

        let result = execute(&executor, ToolName::UsersGetRoleMappings, json!({"id": ALICE_ID}))
            .await
            .unwrap();
        assert_eq!(role_names(&result["realmMappings"]), ["alpha-role", "zeta-role"]);
        assert_eq!(role_names(&result["availableRealmMappings"]), ["available-realm-role"]);
        assert_eq!(
            role_names(&result["effectiveRealmMappings"]),
            ["alpha-role", "group-realm-role", "zeta-role"]
        );
        let client = &result["clientMappings"]["alpha-client"];
        assert_eq!(client["id"], ALPHA_CLIENT_ID);
        assert_eq!(client["client"], "alpha-client");
        assert_eq!(role_names(&client["mappings"]), ["client-only-role"]);
        assert_eq!(role_names(&client["availableMappings"]), ["client-available-role"]);
        assert_eq!(
            role_names(&client["effectiveMappings"]),
            ["client-group-role", "client-only-role"]
        );
        assert!(result["clientMappings"].get("beta-client").is_none());
        assert!(!result.to_string().contains(ROLE_SECRET));
        assert!(client["mappings"][0].get("attributes").is_none());
    }

    #[tokio::test]
    async fn users_get_role_mappings_does_not_hide_group_storage_failures() {
        let expected_user = user(ALICE_ID, "alice", "alice@example.com");
        let mut mock = MockStorage::new();
        mock.expect_get_user().returning(move |_, _| Ok(Some(expected_user.clone())));
        mock.expect_list_roles().returning(|_, _| Ok(Vec::new()));
        mock.expect_list_user_realm_roles().returning(|_, _| Ok(Vec::new()));
        mock.expect_list_user_client_roles().returning(|_, _| Ok(Vec::new()));
        mock.expect_list_user_groups()
            .returning(|_, _| Err(IssuerdError::TemporarilyUnavailable));
        mock.expect_list_clients().returning(|_, _| Ok(Vec::new()));
        let executor = executor(Arc::new(mock));

        assert_eq!(
            execute(&executor, ToolName::UsersGetRoleMappings, json!({"id": ALICE_ID})).await,
            Err(McpError::Backend(IssuerdError::TemporarilyUnavailable))
        );
    }

    #[tokio::test]
    async fn users_get_sessions_returns_sorted_admin_fields_only() {
        let storage = storage().await;
        let realm = realm();
        for (id, refresh) in [
            ("session-old", 1_700_000_000),
            ("session-new", 1_800_000_000),
        ] {
            storage
                .create_user_session(&realm.id, &session(id, ALICE_ID, refresh))
                .await
                .unwrap();
        }
        let executor = executor(storage);
        let result = execute(&executor, ToolName::UsersGetSessions, json!({"id": ALICE_ID}))
            .await
            .unwrap();
        let sessions = result["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0]["id"], "session-new");
        assert_eq!(sessions[0]["userId"], ALICE_ID);
        assert_eq!(sessions[0]["username"], "alice");
        assert_eq!(sessions[0]["ipAddress"], "127.0.0.1");
        assert_eq!(sessions[0]["started"], 1_800_000_000_i64);
        assert_eq!(sessions[0]["lastAccess"], 1_800_000_000_i64);
        assert_eq!(sessions[0]["offline"], false);
        assert_eq!(sessions[0]["clients"][ALPHA_CLIENT_ID], "password");
        for field in [
            "rememberMe",
            "authTime",
            "impersonator",
            "redirectUri",
            "state",
            "authMethod",
        ] {
            assert!(sessions[0].get(field).is_none(), "exposed {field}");
        }
        assert!(!result.to_string().contains(CREDENTIAL_SECRET));
    }

    #[tokio::test]
    async fn users_get_credentials_returns_sorted_scalar_metadata_without_payloads() {
        let storage = storage().await;
        let realm = realm();
        let alice = UserId::new(ALICE_ID).unwrap();
        for fixture in [
            credential("credential-later", CredentialType::Password, 20, 1_800_000_000),
            credential("credential-first", CredentialType::Totp, 10, 1_700_000_000),
        ] {
            storage.create_credential(&realm.id, &alice, &fixture).await.unwrap();
        }
        let executor = executor(storage);
        let result = execute(&executor, ToolName::UsersGetCredentials, json!({"id": ALICE_ID}))
            .await
            .unwrap();
        let credentials = result["credentials"].as_array().unwrap();
        assert_eq!(credentials.len(), 2);
        assert_eq!(credentials[0]["id"], "credential-first");
        assert_eq!(credentials[0]["type"], "totp");
        assert_eq!(credentials[0]["createdDate"], 1_700_000_000_000_i64);
        assert_eq!(credentials[0]["priority"], 10);
        assert_eq!(credentials[0]["temporary"], true);
        assert_eq!(credentials[1]["type"], "password");
        for credential in credentials {
            for field in ["secretData", "credentialData", "value"] {
                assert!(credential.get(field).is_none(), "exposed {field}");
            }
        }
        assert!(!result.to_string().contains(CREDENTIAL_SECRET));
    }

    #[tokio::test]
    async fn attack_detection_status_aggregates_only_the_target_users_cache_entries() {
        let cache = Arc::new(InMemoryCache::new());
        for (key, value) in [
            (format!("login-failure:{REALM_ID}:alice:192.0.2.1"), "2"),
            (format!("login-failure:{REALM_ID}:alice:192.0.2.2"), "3"),
            (format!("login-failure:{REALM_ID}:alice:192.0.2.3"), "invalid"),
            (format!("login-failure:{REALM_ID}:alicia:192.0.2.4"), "100"),
        ] {
            cache.set(&key, value.as_bytes().to_vec(), None).await.unwrap();
        }
        cache
            .set(&format!("login-lockout:{REALM_ID}:alice:192.0.2.1"), b"1".to_vec(), None)
            .await
            .unwrap();
        let executor = McpToolExecutor::new(storage().await, McpRateLimiter::new(cache, 1_000));
        let result = execute(&executor, ToolName::AttackDetectionStatus, json!({"id": ALICE_ID}))
            .await
            .unwrap();
        assert_eq!(result["userId"], ALICE_ID);
        assert_eq!(result["username"], "alice");
        assert_eq!(result["numFailures"], 5);
        assert_eq!(result["locked"], true);
    }

    #[tokio::test]
    async fn all_user_detail_tools_validate_ids_and_require_an_existing_user() {
        let executor = executor(storage().await);
        for tool in [
            ToolName::AttackDetectionStatus,
            ToolName::UsersGetCredentials,
            ToolName::UsersGetGroups,
            ToolName::UsersGetRoleMappings,
            ToolName::UsersGetSessions,
        ] {
            assert!(matches!(
                execute(&executor, tool, json!({"id": "not-a-uuid"})).await,
                Err(McpError::InvalidInput(_))
            ));
            assert_eq!(
                execute(&executor, tool, json!({"id": "99999999-9999-4999-8999-999999999999"}))
                    .await,
                Err(McpError::NotFound("user"))
            );
        }
    }

    #[tokio::test]
    async fn every_successful_result_conforms_to_its_output_schema() {
        let executor = executor(storage().await);
        let cases = [
            (ToolName::AttackDetectionStatus, json!({"id": ALICE_ID})),
            (ToolName::RealmGet, json!({})),
            (ToolName::UsersSearch, json!({"search": "ali"})),
            (ToolName::UsersGet, json!({"id": ALICE_ID})),
            (ToolName::UsersGetCredentials, json!({"id": ALICE_ID})),
            (ToolName::UsersGetGroups, json!({"id": ALICE_ID})),
            (ToolName::UsersGetRoleMappings, json!({"id": ALICE_ID})),
            (ToolName::UsersGetSessions, json!({"id": ALICE_ID})),
            (ToolName::ClientsList, json!({})),
            (ToolName::ClientsGet, json!({"id": ALPHA_CLIENT_ID})),
            (ToolName::GroupsList, json!({})),
            (ToolName::GroupsGet, json!({"id": ALPHA_GROUP_ID})),
            (ToolName::GroupsMembers, json!({"id": ZETA_GROUP_ID})),
            (ToolName::RolesList, json!({})),
            (ToolName::RolesGet, json!({"name": "zeta-role"})),
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
