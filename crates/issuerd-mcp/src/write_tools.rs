// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::collections::BTreeMap;

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{error::McpError, executor::decode, policy::ToolName};

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WriteOutput {
    pub tool: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

impl WriteOutput {
    pub fn completed(tool: ToolName, id: Option<String>) -> Self {
        Self {
            tool: tool.as_str().into(),
            status: "completed".into(),
            id,
            count: None,
        }
    }

    pub fn completed_count(tool: ToolName, id: Option<String>, count: u32) -> Self {
        Self {
            tool: tool.as_str().into(),
            status: "completed".into(),
            id,
            count: Some(count),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpOperation {
    pub tool: ToolName,
    pub arguments: Value,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserCreateArgs {
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    pub email_verified: Option<bool>,
    pub required_actions: Option<Vec<String>>,
    pub attributes: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserUpdateArgs {
    pub id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email_verified: Option<bool>,
    pub required_actions: Option<Vec<String>>,
    pub attributes: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserSetEnabledArgs {
    pub id: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserActionsEmailArgs {
    pub id: String,
    pub actions: Vec<String>,
    pub lifespan: Option<i64>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserRevokeSessionsArgs {
    pub id: String,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserGroupArgs {
    pub id: String,
    pub group_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleAssignmentArgs {
    pub id: String,
    pub role: String,
    pub client_id: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupCreateArgs {
    pub name: String,
    pub attributes: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupUpdateArgs {
    pub id: String,
    pub name: Option<String>,
    pub attributes: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupChildArgs {
    pub id: String,
    pub name: String,
    pub attributes: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleCreateArgs {
    pub name: String,
    pub description: Option<String>,
    pub composites: Option<Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleUpdateArgs {
    pub name: String,
    pub new_name: Option<String>,
    pub description: Option<String>,
    pub composites: Option<Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientCreateArgs {
    pub client_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub public_client: Option<bool>,
    pub redirect_uris: Option<Vec<String>>,
    pub web_origins: Option<Vec<String>>,
    pub default_scopes: Option<Vec<String>>,
    pub optional_scopes: Option<Vec<String>>,
    pub consent_required: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientUpdateProfileArgs {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientSetScopesArgs {
    pub id: String,
    pub default_scopes: Option<Vec<String>>,
    pub optional_scopes: Option<Vec<String>>,
}

pub fn is_admin_write(tool: ToolName) -> bool {
    matches!(
        tool,
        ToolName::ClientsCreate
            | ToolName::ClientsSetDefaultScopes
            | ToolName::ClientsUpdateProfile
            | ToolName::GroupsAddChild
            | ToolName::GroupsAssignRole
            | ToolName::GroupsCreate
            | ToolName::GroupsUnassignRole
            | ToolName::GroupsUpdate
            | ToolName::RolesCreate
            | ToolName::RolesUpdate
            | ToolName::UsersAddToGroup
            | ToolName::UsersAssignRole
            | ToolName::UsersCreate
            | ToolName::UsersRemoveFromGroup
            | ToolName::UsersRevokeSessions
            | ToolName::UsersSendActionsEmail
            | ToolName::UsersSetEnabled
            | ToolName::UsersUnassignRole
            | ToolName::UsersUpdate
    )
}

pub fn parse_operation(
    tool: ToolName,
    arguments: Option<JsonObject>,
) -> Result<McpOperation, McpError> {
    let arguments = match tool {
        ToolName::UsersCreate => canonical::<UserCreateArgs>(arguments)?,
        ToolName::UsersUpdate => canonical::<UserUpdateArgs>(arguments)?,
        ToolName::UsersSetEnabled => canonical::<UserSetEnabledArgs>(arguments)?,
        ToolName::UsersSendActionsEmail => canonical::<UserActionsEmailArgs>(arguments)?,
        ToolName::UsersRevokeSessions => canonical::<UserRevokeSessionsArgs>(arguments)?,
        ToolName::UsersAddToGroup | ToolName::UsersRemoveFromGroup => {
            canonical::<UserGroupArgs>(arguments)?
        }
        ToolName::UsersAssignRole
        | ToolName::UsersUnassignRole
        | ToolName::GroupsAssignRole
        | ToolName::GroupsUnassignRole => canonical::<RoleAssignmentArgs>(arguments)?,
        ToolName::GroupsCreate => canonical::<GroupCreateArgs>(arguments)?,
        ToolName::GroupsUpdate => canonical::<GroupUpdateArgs>(arguments)?,
        ToolName::GroupsAddChild => canonical::<GroupChildArgs>(arguments)?,
        ToolName::RolesCreate => canonical::<RoleCreateArgs>(arguments)?,
        ToolName::RolesUpdate => canonical::<RoleUpdateArgs>(arguments)?,
        ToolName::ClientsCreate => canonical::<ClientCreateArgs>(arguments)?,
        ToolName::ClientsUpdateProfile => canonical::<ClientUpdateProfileArgs>(arguments)?,
        ToolName::ClientsSetDefaultScopes => canonical::<ClientSetScopesArgs>(arguments)?,
        _ => unreachable!("write operation parser received a non-write tool"),
    };
    Ok(McpOperation { tool, arguments })
}

fn canonical<T: Serialize + serde::de::DeserializeOwned>(
    arguments: Option<JsonObject>,
) -> Result<Value, McpError> {
    let value: T = decode(arguments)?;
    serde_json::to_value(value).map_err(|_| {
        McpError::Backend(issuerd_core::IssuerdError::ServerError(
            "write argument serialization failed".into(),
        ))
    })
}

pub fn definition(name: ToolName) -> Option<Tool> {
    if !is_admin_write(name) {
        return None;
    }
    let description = match name {
        ToolName::UsersCreate => "Create a user without an initial password or credential payload.",
        ToolName::UsersUpdate => {
            "Update user profile fields and safe attributes without changing enabled state."
        }
        ToolName::UsersSetEnabled => {
            "Enable or disable a user without changing other profile fields."
        }
        ToolName::UsersSendActionsEmail => {
            "Send a required-action email through the existing Admin flow."
        }
        ToolName::UsersRevokeSessions => "Revoke one user session or every session of a user.",
        ToolName::UsersAddToGroup => "Add a user to an existing group.",
        ToolName::UsersRemoveFromGroup => "Remove a user from a group.",
        ToolName::UsersAssignRole => "Assign a realm or client role to a user.",
        ToolName::UsersUnassignRole => "Remove a realm or client role from a user.",
        ToolName::GroupsAssignRole => "Assign a realm or client role to a group.",
        ToolName::GroupsUnassignRole => "Remove a realm or client role from a group.",
        ToolName::GroupsCreate => "Create a top-level group with safe attributes.",
        ToolName::GroupsUpdate => "Rename a group or replace its safe attributes.",
        ToolName::GroupsAddChild => "Create a child group beneath an existing parent.",
        ToolName::RolesCreate => "Create a realm role with optional composite membership.",
        ToolName::RolesUpdate => "Rename a realm role or update its description and composites.",
        ToolName::ClientsCreate => "Create a client with safe defaults and no Admin API access.",
        ToolName::ClientsUpdateProfile => "Update only a client's display name and description.",
        ToolName::ClientsSetDefaultScopes => {
            "Replace a client's default and optional scope assignments."
        }
        _ => unreachable!("write definition received a non-write tool"),
    };
    let tool = Tool::new(name.as_str(), description, std::sync::Arc::new(serde_json::Map::new()));
    let tool = match name {
        ToolName::UsersCreate => tool.with_input_schema::<UserCreateArgs>(),
        ToolName::UsersUpdate => tool.with_input_schema::<UserUpdateArgs>(),
        ToolName::UsersSetEnabled => tool.with_input_schema::<UserSetEnabledArgs>(),
        ToolName::UsersSendActionsEmail => tool.with_input_schema::<UserActionsEmailArgs>(),
        ToolName::UsersRevokeSessions => tool.with_input_schema::<UserRevokeSessionsArgs>(),
        ToolName::UsersAddToGroup | ToolName::UsersRemoveFromGroup => {
            tool.with_input_schema::<UserGroupArgs>()
        }
        ToolName::UsersAssignRole
        | ToolName::UsersUnassignRole
        | ToolName::GroupsAssignRole
        | ToolName::GroupsUnassignRole => tool.with_input_schema::<RoleAssignmentArgs>(),
        ToolName::GroupsCreate => tool.with_input_schema::<GroupCreateArgs>(),
        ToolName::GroupsUpdate => tool.with_input_schema::<GroupUpdateArgs>(),
        ToolName::GroupsAddChild => tool.with_input_schema::<GroupChildArgs>(),
        ToolName::RolesCreate => tool.with_input_schema::<RoleCreateArgs>(),
        ToolName::RolesUpdate => tool.with_input_schema::<RoleUpdateArgs>(),
        ToolName::ClientsCreate => tool.with_input_schema::<ClientCreateArgs>(),
        ToolName::ClientsUpdateProfile => tool.with_input_schema::<ClientUpdateProfileArgs>(),
        ToolName::ClientsSetDefaultScopes => tool.with_input_schema::<ClientSetScopesArgs>(),
        _ => unreachable!("write definition received a non-write tool"),
    };
    let create = matches!(
        name,
        ToolName::UsersCreate
            | ToolName::GroupsCreate
            | ToolName::GroupsAddChild
            | ToolName::RolesCreate
            | ToolName::ClientsCreate
    );
    let external = matches!(name, ToolName::UsersSendActionsEmail);
    Some(
        tool.with_output_schema::<WriteOutput>()
            .with_annotations(ToolAnnotations::from_raw(
                None,
                Some(false),
                Some(false),
                Some(!create && !external),
                Some(external),
            )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn write_inputs_reject_unknown_and_secret_bearing_fields() {
        for (tool, value) in [
            (ToolName::UsersCreate, json!({"username":"alice","credentials":[]})),
            (ToolName::UsersUpdate, json!({"id":"user","enabled":false})),
            (ToolName::ClientsCreate, json!({"clientId":"agent","secret":"secret"})),
            (
                ToolName::ClientsCreate,
                json!({"clientId":"agent","attributes":{"admin_api_access":"true"}}),
            ),
            (ToolName::ClientsUpdateProfile, json!({"id":"client","redirectUris":[]})),
        ] {
            assert!(parse_operation(tool, Some(value.as_object().unwrap().clone())).is_err());
        }
    }

    #[test]
    fn write_definitions_have_safe_output_and_action_annotations() {
        for tool in ToolName::ALL.into_iter().filter(|tool| is_admin_write(*tool)) {
            let definition = definition(tool).unwrap();
            assert_eq!(definition.annotations.as_ref().unwrap().read_only_hint, Some(false));
            assert_eq!(definition.annotations.as_ref().unwrap().destructive_hint, Some(false));
            assert_eq!(definition.output_schema.unwrap()["type"], "object");
        }
        assert_eq!(
            definition(ToolName::UsersSendActionsEmail)
                .unwrap()
                .annotations
                .unwrap()
                .open_world_hint,
            Some(true)
        );
    }
}
