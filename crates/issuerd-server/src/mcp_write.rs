// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::collections::HashSet;
use std::sync::Arc;

use axum::{Extension, Json};
use issuerd_admin_api::{
    auth::AdminAuth,
    dto::{
        ClientRepresentation, ExecuteActionsEmailParams, GroupRepresentation, RoleRepresentation,
        UserRepresentation,
    },
    error::AdminApiError,
    state::AdminApiState,
};
use issuerd_core::{ClientId, RoleName, SessionId};
use issuerd_mcp::{
    write_tools::{
        ClientCreateArgs, ClientSetScopesArgs, ClientUpdateProfileArgs, GroupChildArgs,
        GroupCreateArgs, GroupUpdateArgs, McpOperation, RoleAssignmentArgs, RoleCreateArgs,
        RoleUpdateArgs, UserActionsEmailArgs, UserCreateArgs, UserGroupArgs,
        UserRevokeSessionsArgs, UserSetEnabledArgs, UserUpdateArgs, WriteOutput,
    },
    McpAuthContext, McpError, ToolName,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub async fn write(
    state: Arc<AdminApiState>,
    auth: &McpAuthContext,
    operation: McpOperation,
) -> Result<Value, McpError> {
    let admin = AdminAuth {
        claims: auth.claims.clone(),
    };
    let realm = auth.realm_name.to_string();
    let realm_id = auth.realm_id.clone();
    let tool = operation.tool;
    let output = match tool {
        ToolName::UsersCreate => {
            let args: UserCreateArgs = decode(&operation)?;
            validate_attributes(&args.attributes)?;
            let body = UserRepresentation {
                id: None,
                username: required_text(&args.username, "username")?,
                email: optional_text(&args.email, "email", 254)?,
                first_name: optional_text(&args.first_name, "firstName", 255)?,
                last_name: optional_text(&args.last_name, "lastName", 255)?,
                enabled: args.enabled,
                email_verified: args.email_verified,
                created_at: None,
                attributes: args.attributes.map(|attributes| attributes.into_iter().collect()),
                credentials: None,
                realm_roles: None,
                client_roles: None,
                groups: None,
                required_actions: args.required_actions,
            };
            let (_, Json(created)) = issuerd_admin_api::users::create_user(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path(realm),
                Json(body),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, created.id)
        }
        ToolName::UsersUpdate => {
            let args: UserUpdateArgs = decode(&operation)?;
            validate_attributes(&args.attributes)?;
            let id = canonical_uuid(&args.id, "id")?;
            let existing = state
                .storage
                .get_user(&realm_id, &issuerd_core::UserId::new(&id)?)
                .await?
                .ok_or(McpError::NotFound("user"))?;
            let mut body = UserRepresentation::from(existing);
            if let Some(username) = args.username {
                body.username = required_text(&username, "username")?;
            }
            if args.email.is_some() {
                body.email = optional_text(&args.email, "email", 254)?;
            }
            if args.first_name.is_some() {
                body.first_name = optional_text(&args.first_name, "firstName", 255)?;
            }
            if args.last_name.is_some() {
                body.last_name = optional_text(&args.last_name, "lastName", 255)?;
            }
            if args.email_verified.is_some() {
                body.email_verified = args.email_verified;
            }
            if args.required_actions.is_some() {
                body.required_actions = args.required_actions;
            }
            if let Some(attributes) = args.attributes {
                body.attributes = Some(attributes.into_iter().collect());
            }
            issuerd_admin_api::users::update_user(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path((realm, id.clone())),
                Json(body),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, Some(id))
        }
        ToolName::UsersSetEnabled => {
            let args: UserSetEnabledArgs = decode(&operation)?;
            let id = canonical_uuid(&args.id, "id")?;
            let existing = state
                .storage
                .get_user(&realm_id, &issuerd_core::UserId::new(&id)?)
                .await?
                .ok_or(McpError::NotFound("user"))?;
            let mut body = UserRepresentation::from(existing);
            body.enabled = Some(args.enabled);
            issuerd_admin_api::users::update_user(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path((realm, id.clone())),
                Json(body),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, Some(id))
        }
        ToolName::UsersSendActionsEmail => {
            let args: UserActionsEmailArgs = decode(&operation)?;
            let id = canonical_uuid(&args.id, "id")?;
            if args.actions.is_empty() || args.actions.len() > 20 {
                return Err(McpError::InvalidInput(
                    "actions must contain between 1 and 20 action ids".into(),
                ));
            }
            for action in &args.actions {
                required_text(action, "actions")?;
            }
            issuerd_admin_api::user_actions::execute_actions_email(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path((realm, id.clone())),
                axum::extract::Query(ExecuteActionsEmailParams {
                    redirect_uri: None,
                    lifespan: args.lifespan,
                }),
                Json(args.actions),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, Some(id))
        }
        ToolName::UsersRevokeSessions => {
            let args: UserRevokeSessionsArgs = decode(&operation)?;
            let id = canonical_uuid(&args.id, "id")?;
            let user_id = issuerd_core::UserId::new(&id)?;
            state
                .storage
                .get_user(&realm_id, &user_id)
                .await?
                .ok_or(McpError::NotFound("user"))?;
            let sessions = match args.session_id {
                Some(session_id) => {
                    let session_id = canonical_uuid(&session_id, "sessionId")?;
                    let session_id = SessionId::new(session_id)?;
                    let session = state
                        .storage
                        .get_user_session(&realm_id, &session_id)
                        .await?
                        .ok_or(McpError::NotFound("session"))?;
                    if session.user_id != user_id {
                        return Err(McpError::Forbidden(
                            "session does not belong to the target user",
                        ));
                    }
                    vec![session]
                }
                None => {
                    state
                        .storage
                        .list_sessions(
                            &realm_id,
                            Some(user_id),
                            &issuerd_core::Pagination::default(),
                        )
                        .await?
                }
            };
            let count = u32::try_from(sessions.len()).unwrap_or(u32::MAX);
            for session in sessions {
                issuerd_admin_api::sessions::delete_session(
                    axum::extract::State(state.clone()),
                    Extension(admin.clone()),
                    axum::extract::Path((realm.clone(), session.id.to_string())),
                )
                .await
                .map_err(admin_error)?;
            }
            WriteOutput::completed_count(tool, Some(id), count)
        }
        ToolName::UsersAddToGroup | ToolName::UsersRemoveFromGroup => {
            let args: UserGroupArgs = decode(&operation)?;
            let id = canonical_uuid(&args.id, "id")?;
            let group_id = canonical_uuid(&args.group_id, "groupId")?;
            let path = axum::extract::Path((realm, id.clone(), group_id));
            if tool == ToolName::UsersAddToGroup {
                issuerd_admin_api::users::add_user_group(
                    axum::extract::State(state.clone()),
                    Extension(admin),
                    path,
                )
                .await
                .map_err(admin_error)?;
            } else {
                issuerd_admin_api::users::remove_user_group(
                    axum::extract::State(state.clone()),
                    Extension(admin),
                    path,
                )
                .await
                .map_err(admin_error)?;
            }
            WriteOutput::completed(tool, Some(id))
        }
        ToolName::UsersAssignRole
        | ToolName::UsersUnassignRole
        | ToolName::GroupsAssignRole
        | ToolName::GroupsUnassignRole => {
            let args: RoleAssignmentArgs = decode(&operation)?;
            let id = canonical_uuid(&args.id, "id")?;
            let (role, client) = resolve_role(&state, &realm_id, &args).await?;
            let roles = Json(vec![role]);
            let is_user = matches!(tool, ToolName::UsersAssignRole | ToolName::UsersUnassignRole);
            let assign = matches!(tool, ToolName::UsersAssignRole | ToolName::GroupsAssignRole);
            match (is_user, assign, client) {
                (true, true, None) => {
                    issuerd_admin_api::users::add_user_realm_roles(
                        axum::extract::State(state.clone()),
                        Extension(admin),
                        axum::extract::Path((realm, id.clone())),
                        roles,
                    )
                    .await
                    .map_err(admin_error)?;
                }
                (true, false, None) => {
                    issuerd_admin_api::users::remove_user_realm_roles(
                        axum::extract::State(state.clone()),
                        Extension(admin),
                        axum::extract::Path((realm, id.clone())),
                        roles,
                    )
                    .await
                    .map_err(admin_error)?;
                }
                (true, true, Some(client)) => {
                    issuerd_admin_api::users::add_user_client_roles(
                        axum::extract::State(state.clone()),
                        Extension(admin),
                        axum::extract::Path((realm, id.clone(), client.id.to_string())),
                        roles,
                    )
                    .await
                    .map_err(admin_error)?;
                }
                (true, false, Some(client)) => {
                    issuerd_admin_api::users::remove_user_client_roles(
                        axum::extract::State(state.clone()),
                        Extension(admin),
                        axum::extract::Path((realm, id.clone(), client.id.to_string())),
                        roles,
                    )
                    .await
                    .map_err(admin_error)?;
                }
                (false, true, None) => {
                    issuerd_admin_api::groups::add_group_realm_roles(
                        axum::extract::State(state.clone()),
                        Extension(admin),
                        axum::extract::Path((realm, id.clone())),
                        roles,
                    )
                    .await
                    .map_err(admin_error)?;
                }
                (false, false, None) => {
                    issuerd_admin_api::groups::remove_group_realm_roles(
                        axum::extract::State(state.clone()),
                        Extension(admin),
                        axum::extract::Path((realm, id.clone())),
                        roles,
                    )
                    .await
                    .map_err(admin_error)?;
                }
                (false, true, Some(client)) => {
                    issuerd_admin_api::groups::add_group_client_roles(
                        axum::extract::State(state.clone()),
                        Extension(admin),
                        axum::extract::Path((realm, id.clone(), client.id.to_string())),
                        roles,
                    )
                    .await
                    .map_err(admin_error)?;
                }
                (false, false, Some(client)) => {
                    issuerd_admin_api::groups::remove_group_client_roles(
                        axum::extract::State(state.clone()),
                        Extension(admin),
                        axum::extract::Path((realm, id.clone(), client.id.to_string())),
                        roles,
                    )
                    .await
                    .map_err(admin_error)?;
                }
            }
            WriteOutput::completed(tool, Some(id))
        }
        ToolName::GroupsCreate => {
            let args: GroupCreateArgs = decode(&operation)?;
            validate_attributes(&args.attributes)?;
            let name = required_text(&args.name, "name")?;
            let (_, Json(created)) = issuerd_admin_api::groups::create_group(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path(realm),
                Json(GroupRepresentation {
                    id: None,
                    name: name.clone(),
                    path: Some(format!("/{name}")),
                    attributes: args.attributes.map(|attributes| attributes.into_iter().collect()),
                    realm_roles: None,
                    client_roles: None,
                    sub_groups: None,
                    parent_id: None,
                }),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, created.id)
        }
        ToolName::GroupsUpdate => {
            let args: GroupUpdateArgs = decode(&operation)?;
            validate_attributes(&args.attributes)?;
            let id = canonical_uuid(&args.id, "id")?;
            let existing = state
                .storage
                .get_group(&realm_id, &issuerd_core::GroupId::new(&id)?)
                .await?
                .ok_or(McpError::NotFound("group"))?;
            let mut body = GroupRepresentation::from(existing);
            if let Some(name) = args.name {
                body.name = required_text(&name, "name")?;
            }
            if let Some(attributes) = args.attributes {
                body.attributes = Some(attributes.into_iter().collect());
            }
            issuerd_admin_api::groups::update_group(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path((realm, id.clone())),
                Json(body),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, Some(id))
        }
        ToolName::GroupsAddChild => {
            let args: GroupChildArgs = decode(&operation)?;
            validate_attributes(&args.attributes)?;
            let id = canonical_uuid(&args.id, "id")?;
            let (_, Json(created)) = issuerd_admin_api::groups::create_child_group(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path((realm, id)),
                Json(GroupRepresentation {
                    id: None,
                    name: required_text(&args.name, "name")?,
                    path: None,
                    attributes: args.attributes.map(|attributes| attributes.into_iter().collect()),
                    realm_roles: None,
                    client_roles: None,
                    sub_groups: None,
                    parent_id: None,
                }),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, created.id)
        }
        ToolName::RolesCreate => {
            let args: RoleCreateArgs = decode(&operation)?;
            let (_, Json(created)) = issuerd_admin_api::roles::create_realm_role(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path(realm),
                Json(RoleRepresentation {
                    id: None,
                    name: required_text(&args.name, "name")?,
                    description: optional_text(&args.description, "description", 1024)?,
                    composite: Some(
                        args.composites.as_ref().is_some_and(|roles| !roles.is_empty()),
                    ),
                    composites: Some(role_names(args.composites)?),
                    client_role: Some(false),
                    container_id: None,
                    attributes: None,
                }),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, created.id)
        }
        ToolName::RolesUpdate => {
            let args: RoleUpdateArgs = decode(&operation)?;
            let name = required_text(&args.name, "name")?;
            let existing = state
                .storage
                .get_role_by_name(&realm_id, &name)
                .await?
                .ok_or(McpError::NotFound("role"))?;
            let mut body = RoleRepresentation::from(existing);
            if let Some(new_name) = args.new_name {
                body.name = required_text(&new_name, "newName")?;
            }
            if args.description.is_some() {
                body.description = optional_text(&args.description, "description", 1024)?;
            }
            if let Some(composites) = args.composites {
                body.composites = Some(role_names(Some(composites))?);
                body.composite = Some(!body.composites.as_ref().unwrap().is_empty());
            }
            let id = body.id.clone();
            issuerd_admin_api::roles::update_realm_role(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path((realm, name)),
                Json(body),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, id)
        }
        ToolName::ClientsCreate => {
            let args: ClientCreateArgs = decode(&operation)?;
            validate_scope_names(&args.default_scopes, true)?;
            validate_scope_names(&args.optional_scopes, false)?;
            let (_, Json(created)) = issuerd_admin_api::clients::create_client(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path(realm),
                Json(ClientRepresentation {
                    id: None,
                    client_id: required_text(&args.client_id, "clientId")?,
                    name: optional_text(&args.name, "name", 255)?,
                    description: optional_text(&args.description, "description", 1024)?,
                    enabled: Some(true),
                    protocol: Some(issuerd_core::ClientProtocol::OpenIdConnect),
                    public_client: Some(args.public_client.unwrap_or(true)),
                    bearer_only: Some(false),
                    client_authenticator_type: None,
                    redirect_uris: args.redirect_uris,
                    web_origins: args.web_origins,
                    default_scopes: args.default_scopes,
                    optional_scopes: args.optional_scopes,
                    consent_required: args.consent_required,
                    full_scope_allowed: Some(true),
                    service_accounts_enabled: Some(false),
                    protocol_mappers: None,
                    secret: None,
                    attributes: None,
                }),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, created.id)
        }
        ToolName::ClientsUpdateProfile => {
            let args: ClientUpdateProfileArgs = decode(&operation)?;
            let id = canonical_uuid(&args.id, "id")?;
            let existing = state
                .storage
                .get_client(&realm_id, &ClientId::new(&id)?)
                .await?
                .ok_or(McpError::NotFound("client"))?;
            let mut body = ClientRepresentation::from(existing);
            if args.name.is_some() {
                body.name = optional_text(&args.name, "name", 255)?;
            }
            if args.description.is_some() {
                body.description = optional_text(&args.description, "description", 1024)?;
            }
            issuerd_admin_api::clients::update_client(
                axum::extract::State(state.clone()),
                Extension(admin),
                axum::extract::Path((realm, id.clone())),
                Json(body),
            )
            .await
            .map_err(admin_error)?;
            WriteOutput::completed(tool, Some(id))
        }
        ToolName::ClientsSetDefaultScopes => {
            let args: ClientSetScopesArgs = decode(&operation)?;
            validate_scope_names(&args.default_scopes, true)?;
            validate_scope_names(&args.optional_scopes, false)?;
            let id = canonical_uuid(&args.id, "id")?;
            let client_id = ClientId::new(&id)?;
            state
                .storage
                .get_client(&realm_id, &client_id)
                .await?
                .ok_or(McpError::NotFound("client"))?;
            if let (Some(default), Some(optional)) = (&args.default_scopes, &args.optional_scopes) {
                let default: HashSet<_> = default.iter().collect();
                if optional.iter().any(|scope| default.contains(scope)) {
                    return Err(McpError::InvalidInput(
                        "a scope cannot be both default and optional".into(),
                    ));
                }
            }
            let current =
                state.storage.list_client_scope_assignments(&realm_id, &client_id).await?;
            let mut desired = Vec::new();
            for (names, is_default) in [
                (args.default_scopes.as_ref(), true),
                (args.optional_scopes.as_ref(), false),
            ] {
                let Some(names) = names else { continue };
                for name in names {
                    let scope = state
                        .storage
                        .get_client_scope_by_name(&realm_id, name)
                        .await?
                        .ok_or(McpError::NotFound("client scope"))?;
                    desired.push((scope.id, is_default));
                }
            }
            for (scope_id, is_default) in current.iter().filter(|entry| !desired.contains(entry)) {
                unassign_scope(&state, &admin, &realm, &id, scope_id, *is_default).await?;
            }
            for (scope_id, is_default) in desired.iter().filter(|entry| !current.contains(entry)) {
                assign_scope(&state, &admin, &realm, &id, scope_id, *is_default).await?;
            }
            WriteOutput::completed_count(tool, Some(id), desired.len() as u32)
        }
        _ => unreachable!("MCP admin write dispatcher received a non-write tool"),
    };
    serde_json::to_value(output).map_err(|_| {
        McpError::Backend(issuerd_core::IssuerdError::ServerError(
            "write result serialization failed".into(),
        ))
    })
}

async fn resolve_role(
    state: &Arc<AdminApiState>,
    realm_id: &issuerd_core::RealmId,
    args: &RoleAssignmentArgs,
) -> Result<(RoleRepresentation, Option<issuerd_core::Client>), McpError> {
    let role_name = required_text(&args.role, "role")?;
    if let Some(client_id) = &args.client_id {
        let identifier = issuerd_core::ClientIdentifier::new(client_id)?;
        let client = state
            .storage
            .get_client_by_client_id(realm_id, &identifier)
            .await?
            .ok_or(McpError::NotFound("client"))?;
        let role = state
            .storage
            .get_client_role_by_name(realm_id, &client.id, &role_name)
            .await?
            .ok_or(McpError::NotFound("role"))?;
        Ok((RoleRepresentation::from(role), Some(client)))
    } else {
        let role = state
            .storage
            .get_role_by_name(realm_id, &role_name)
            .await?
            .ok_or(McpError::NotFound("role"))?;
        if role.client_role {
            return Err(McpError::NotFound("role"));
        }
        Ok((RoleRepresentation::from(role), None))
    }
}

async fn assign_scope(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm: &str,
    client_id: &str,
    scope_id: &issuerd_core::ClientScopeId,
    default: bool,
) -> Result<(), McpError> {
    let path =
        axum::extract::Path((realm.to_string(), client_id.to_string(), scope_id.to_string()));
    if default {
        issuerd_admin_api::client_scopes::assign_default_client_scope(
            axum::extract::State(state.clone()),
            Extension(auth.clone()),
            path,
        )
        .await
        .map_err(admin_error)?;
    } else {
        issuerd_admin_api::client_scopes::assign_optional_client_scope(
            axum::extract::State(state.clone()),
            Extension(auth.clone()),
            path,
        )
        .await
        .map_err(admin_error)?;
    }
    Ok(())
}

async fn unassign_scope(
    state: &Arc<AdminApiState>,
    auth: &AdminAuth,
    realm: &str,
    client_id: &str,
    scope_id: &issuerd_core::ClientScopeId,
    default: bool,
) -> Result<(), McpError> {
    let path =
        axum::extract::Path((realm.to_string(), client_id.to_string(), scope_id.to_string()));
    if default {
        issuerd_admin_api::client_scopes::unassign_default_client_scope(
            axum::extract::State(state.clone()),
            Extension(auth.clone()),
            path,
        )
        .await
        .map_err(admin_error)?;
    } else {
        issuerd_admin_api::client_scopes::unassign_optional_client_scope(
            axum::extract::State(state.clone()),
            Extension(auth.clone()),
            path,
        )
        .await
        .map_err(admin_error)?;
    }
    Ok(())
}

fn decode<T: DeserializeOwned>(operation: &McpOperation) -> Result<T, McpError> {
    serde_json::from_value(operation.arguments.clone())
        .map_err(|error| McpError::InvalidInput(error.to_string()))
}

fn canonical_uuid(value: &str, field: &str) -> Result<String, McpError> {
    required_text(value, field)?;
    uuid::Uuid::parse_str(value)
        .map(|uuid| uuid.to_string())
        .map_err(|_| McpError::InvalidInput(format!("{field} must be a UUID")))
}

fn required_text(value: &str, field: &str) -> Result<String, McpError> {
    if value.is_empty() || value.trim() != value || value.len() > 255 {
        return Err(McpError::InvalidInput(format!(
            "{field} must be nonempty, at most 255 bytes, and have no surrounding whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(McpError::InvalidInput(format!("{field} must not contain control characters")));
    }
    Ok(value.into())
}

fn optional_text(
    value: &Option<String>,
    field: &str,
    maximum: usize,
) -> Result<Option<String>, McpError> {
    value
        .as_ref()
        .map(|value| {
            if value.len() > maximum || value.chars().any(char::is_control) {
                return Err(McpError::InvalidInput(format!("{field} is invalid")));
            }
            Ok(value.clone())
        })
        .transpose()
}

fn validate_attributes(
    attributes: &Option<std::collections::BTreeMap<String, Vec<String>>>,
) -> Result<(), McpError> {
    let Some(attributes) = attributes else {
        return Ok(());
    };
    if attributes.len() > 100 {
        return Err(McpError::InvalidInput("at most 100 attributes are allowed".into()));
    }
    for (key, values) in attributes {
        required_text(key, "attribute name")?;
        if sensitive_key(key) {
            return Err(McpError::Forbidden(
                "secret-bearing attribute values are not accepted through MCP",
            ));
        }
        if values.len() > 100 || values.iter().any(|value| value.len() > 4096) {
            return Err(McpError::InvalidInput("attribute values are too large".into()));
        }
    }
    Ok(())
}

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    ["secret", "password", "credential", "privatekey", "token"]
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

fn validate_scope_names(names: &Option<Vec<String>>, default: bool) -> Result<(), McpError> {
    let Some(names) = names else { return Ok(()) };
    if names.len() > 100 {
        return Err(McpError::InvalidInput("at most 100 scopes are allowed".into()));
    }
    for name in names {
        required_text(name, "scope")?;
        if default && issuerd_core::is_mcp_scope_name(name) {
            return Err(McpError::Forbidden("MCP scopes cannot be assigned as default scopes"));
        }
    }
    Ok(())
}

fn role_names(names: Option<Vec<String>>) -> Result<Vec<RoleName>, McpError> {
    names
        .unwrap_or_default()
        .into_iter()
        .map(|name| RoleName::new(required_text(&name, "composites")?).map_err(McpError::from))
        .collect()
}

fn admin_error(error: AdminApiError) -> McpError {
    match error {
        AdminApiError::Unauthorized | AdminApiError::Forbidden => {
            McpError::Forbidden("operation forbidden")
        }
        AdminApiError::NotFound => McpError::NotFound("resource"),
        AdminApiError::Conflict | AdminApiError::ConflictWithMessage(_) => {
            McpError::Conflict("operation conflict")
        }
        AdminApiError::BadRequest(message) => McpError::InvalidInput(message),
        AdminApiError::PasswordPolicy(error) => McpError::InvalidInput(error.to_string()),
        AdminApiError::NotImplemented(_) => McpError::Forbidden("operation is not supported"),
        AdminApiError::Internal(_) => McpError::Backend(issuerd_core::IssuerdError::ServerError(
            "admin operation failed".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use issuerd_core::{
        AccessTokenClaims, AdminEventQuery, Audience, AuthMethod, ClientIdentifier, Issuer, JwtId,
        JwtType, Pagination, RealmAccess, RealmId, RealmName, Role, RoleId, Scope, UserId,
        UserSession,
    };
    use serde_json::json;

    struct Fixture {
        state: Arc<AdminApiState>,
        auth: McpAuthContext,
        realm_id: RealmId,
    }

    async fn fixture() -> Fixture {
        let mut state =
            crate::state::ServerState::from_config(&crate::config::ServerConfig::with_test_admin())
                .await
                .unwrap();
        let mut email = issuerd_core::MockEmailSender::new();
        email.expect_send().times(1).returning(|_, _, _, _, _| Ok(()));
        state.email_sender = Arc::new(email);
        let state = Arc::new(state);
        let realm = state.storage.get_realm_by_name("master").await.unwrap().unwrap();
        let realm_id = realm.id.clone();
        let roles = [
            "manage-realm",
            "manage-users",
            "manage-clients",
            "view-realm",
            "view-users",
            "view-clients",
        ];
        let claims = AccessTokenClaims {
            jti: JwtId::new("mcp-write-test").unwrap(),
            iss: Issuer::new("http://localhost/realms/master").unwrap(),
            sub: UserId::new("admin").unwrap(),
            aud: Audience::new("admin-cli").unwrap(),
            exp: 4_000_000_000,
            iat: 1,
            nbf: 1,
            scope: Scope::parse("openid mcp:write"),
            typ: JwtType::Bearer,
            azp: Some("admin-cli".into()),
            session_state: None,
            realm_access: Some(RealmAccess {
                roles: roles.iter().map(|role| RoleName::new(*role).unwrap()).collect(),
            }),
            resource_access: None,
            sid: None,
            claims: None,
            cnf: None,
            authorization_details: None,
            resource: Some("http://localhost/realms/master/mcp".into()),
        };
        let auth = McpAuthContext {
            realm_id: realm_id.clone(),
            realm_name: RealmName::new("master").unwrap(),
            user_id: UserId::new("admin").unwrap(),
            azp: ClientIdentifier::new("admin-cli").unwrap(),
            claims,
        };
        Fixture {
            state: crate::mcp_service::admin_state(&state),
            auth,
            realm_id,
        }
    }

    async fn call(fixture: &Fixture, tool: ToolName, arguments: Value) -> Result<Value, McpError> {
        let operation = issuerd_mcp::write_tools::parse_operation(
            tool,
            Some(arguments.as_object().unwrap().clone()),
        )?;
        write(fixture.state.clone(), &fixture.auth, operation).await
    }

    fn id(output: &Value) -> String {
        output["id"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn all_admin_write_tools_mutate_storage_and_emit_audit() {
        let fixture = fixture().await;
        let realm = &fixture.realm_id;

        let user_id = id(&call(
            &fixture,
            ToolName::UsersCreate,
            json!({
                "username": "mcp-write-user",
                "email": "mcp-write-user@example.com",
                "firstName": "Before"
            }),
        )
        .await
        .unwrap());
        let user_uuid = UserId::new(&user_id).unwrap();
        assert!(fixture
            .state
            .storage
            .list_credentials(realm, &user_uuid)
            .await
            .unwrap()
            .is_empty());

        call(
            &fixture,
            ToolName::UsersUpdate,
            json!({"id": user_id, "firstName": "After", "attributes": {"team": ["iam"]}}),
        )
        .await
        .unwrap();
        call(&fixture, ToolName::UsersSetEnabled, json!({"id": user_id, "enabled": false}))
            .await
            .unwrap();
        assert!(
            !fixture
                .state
                .storage
                .get_user(realm, &user_uuid)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        call(&fixture, ToolName::UsersSetEnabled, json!({"id": user_id, "enabled": true}))
            .await
            .unwrap();
        let user = fixture.state.storage.get_user(realm, &user_uuid).await.unwrap().unwrap();
        assert_eq!(user.first_name.as_ref().unwrap().as_str(), "After");
        assert_eq!(user.attributes["team"], ["iam"]);

        call(
            &fixture,
            ToolName::UsersSendActionsEmail,
            json!({"id": user_id, "actions": ["UPDATE_PASSWORD"], "lifespan": 600}),
        )
        .await
        .unwrap();

        let group_id = id(&call(&fixture, ToolName::GroupsCreate, json!({"name": "mcp-parent"}))
            .await
            .unwrap());
        let child_id = id(&call(
            &fixture,
            ToolName::GroupsAddChild,
            json!({"id": group_id, "name": "mcp-child"}),
        )
        .await
        .unwrap());
        assert_eq!(
            fixture
                .state
                .storage
                .get_group(realm, &issuerd_core::GroupId::new(&child_id).unwrap())
                .await
                .unwrap()
                .unwrap()
                .parent_id
                .unwrap()
                .to_string(),
            group_id
        );
        call(
            &fixture,
            ToolName::GroupsUpdate,
            json!({"id": group_id, "name": "mcp-parent-renamed"}),
        )
        .await
        .unwrap();

        call(&fixture, ToolName::UsersAddToGroup, json!({"id": user_id, "groupId": group_id}))
            .await
            .unwrap();
        assert!(fixture
            .state
            .storage
            .list_user_groups(realm, &user_uuid)
            .await
            .unwrap()
            .iter()
            .any(|group| group.to_string() == group_id));
        call(
            &fixture,
            ToolName::UsersRemoveFromGroup,
            json!({"id": user_id, "groupId": group_id}),
        )
        .await
        .unwrap();
        assert!(fixture
            .state
            .storage
            .list_user_groups(realm, &user_uuid)
            .await
            .unwrap()
            .is_empty());

        let role_id = id(&call(&fixture, ToolName::RolesCreate, json!({"name": "mcp-role"}))
            .await
            .unwrap());
        call(
            &fixture,
            ToolName::RolesUpdate,
            json!({"name": "mcp-role", "newName": "mcp-role-renamed", "description": "updated"}),
        )
        .await
        .unwrap();
        let role = fixture
            .state
            .storage
            .get_role_by_name(realm, "mcp-role-renamed")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(role.id.to_string(), role_id);

        let client_id = id(&call(
            &fixture,
            ToolName::ClientsCreate,
            json!({"clientId": "mcp-write-client", "defaultScopes": ["profile"]}),
        )
        .await
        .unwrap());
        call(
            &fixture,
            ToolName::ClientsUpdateProfile,
            json!({"id": client_id, "name": "Updated client", "description": "safe"}),
        )
        .await
        .unwrap();
        call(
            &fixture,
            ToolName::ClientsSetDefaultScopes,
            json!({"id": client_id, "defaultScopes": ["profile"], "optionalScopes": ["email"]}),
        )
        .await
        .unwrap();
        let client_uuid = ClientId::new(&client_id).unwrap();
        let assignments = fixture
            .state
            .storage
            .list_client_scope_assignments(realm, &client_uuid)
            .await
            .unwrap();
        assert_eq!(assignments.len(), 2);
        assert!(assignments.iter().any(|(_, default)| *default));
        assert!(assignments.iter().any(|(_, default)| !*default));

        let client_role = Role {
            id: RoleId::new(issuerd_core::utils::generate_id()).unwrap(),
            name: RoleName::new("mcp-client-role").unwrap(),
            description: None,
            realm_id: realm.clone(),
            client_role: true,
            client_id: Some(client_uuid.clone()),
            composite: false,
            composites: Vec::new(),
            attributes: Default::default(),
        };
        fixture.state.storage.create_role(realm, &client_role).await.unwrap();

        call(
            &fixture,
            ToolName::UsersAssignRole,
            json!({"id": user_id, "role": "mcp-role-renamed"}),
        )
        .await
        .unwrap();
        assert!(fixture
            .state
            .storage
            .list_user_realm_roles(realm, &user_uuid)
            .await
            .unwrap()
            .contains(&role.id));
        call(
            &fixture,
            ToolName::UsersUnassignRole,
            json!({"id": user_id, "role": "mcp-role-renamed"}),
        )
        .await
        .unwrap();
        assert!(!fixture
            .state
            .storage
            .list_user_realm_roles(realm, &user_uuid)
            .await
            .unwrap()
            .contains(&role.id));

        call(
            &fixture,
            ToolName::GroupsAssignRole,
            json!({"id": group_id, "role": "mcp-role-renamed"}),
        )
        .await
        .unwrap();
        assert!(fixture
            .state
            .storage
            .get_group(realm, &issuerd_core::GroupId::new(&group_id).unwrap())
            .await
            .unwrap()
            .unwrap()
            .realm_roles
            .contains(&role.name));
        call(
            &fixture,
            ToolName::GroupsUnassignRole,
            json!({"id": group_id, "role": "mcp-role-renamed"}),
        )
        .await
        .unwrap();

        call(
            &fixture,
            ToolName::UsersAssignRole,
            json!({"id": user_id, "role": "mcp-client-role", "clientId": "mcp-write-client"}),
        )
        .await
        .unwrap();
        assert!(fixture
            .state
            .storage
            .list_user_client_roles(realm, &user_uuid)
            .await
            .unwrap()
            .contains(&client_role.id));
        call(
            &fixture,
            ToolName::UsersUnassignRole,
            json!({"id": user_id, "role": "mcp-client-role", "clientId": "mcp-write-client"}),
        )
        .await
        .unwrap();

        call(
            &fixture,
            ToolName::GroupsAssignRole,
            json!({"id": group_id, "role": "mcp-client-role", "clientId": "mcp-write-client"}),
        )
        .await
        .unwrap();
        call(
            &fixture,
            ToolName::GroupsUnassignRole,
            json!({"id": group_id, "role": "mcp-client-role", "clientId": "mcp-write-client"}),
        )
        .await
        .unwrap();

        let session_id = issuerd_core::SessionId::new(issuerd_core::utils::generate_id()).unwrap();
        let now = Utc::now();
        fixture
            .state
            .storage
            .create_user_session(
                realm,
                &UserSession {
                    id: session_id.clone(),
                    realm_id: realm.clone(),
                    user_id: user_uuid.clone(),
                    login_username: issuerd_core::Username::new("mcp-write-user").unwrap(),
                    ip_address: "127.0.0.1".parse().unwrap(),
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
        let revoked = call(&fixture, ToolName::UsersRevokeSessions, json!({"id": user_id}))
            .await
            .unwrap();
        assert_eq!(revoked["count"], 1);
        assert!(fixture
            .state
            .storage
            .get_user_session(realm, &session_id)
            .await
            .unwrap()
            .is_none());

        assert!(call(
            &fixture,
            ToolName::UsersUpdate,
            json!({"id": user_id, "attributes": {"password": ["must-not-be-audited"]}}),
        )
        .await
        .is_err());
        assert!(call(
            &fixture,
            ToolName::ClientsSetDefaultScopes,
            json!({"id": client_id, "defaultScopes": ["mcp:read"]}),
        )
        .await
        .is_err());

        let count = fixture
            .state
            .storage
            .count_admin_events(
                realm,
                &AdminEventQuery {
                    operation_type: None,
                    resource_type: None,
                    auth_user_id: None,
                    date_from: None,
                    date_to: None,
                    pagination: Pagination::default(),
                },
            )
            .await
            .unwrap();
        assert!(count >= 19, "expected mutation audit events, got {count}");
    }
}
