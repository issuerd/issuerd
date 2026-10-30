// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::collections::BTreeMap;

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::McpError,
    executor::decode,
    policy::{RiskTier, ToolName},
    tools::NoArgs,
    write_tools::{McpOperation, WriteOutput},
};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteArgs {
    pub id: String,
    pub confirmation: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleDeleteArgs {
    pub name: String,
    pub confirmation: String,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientSecurityArgs {
    pub id: String,
    pub redirect_uris: Option<Vec<String>>,
    pub web_origins: Option<Vec<String>>,
    pub public_client: Option<bool>,
    pub bearer_only: Option<bool>,
    pub consent_required: Option<bool>,
    pub full_scope_allowed: Option<bool>,
    pub service_accounts_enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RealmSslRequired {
    None,
    External,
    All,
}

impl From<RealmSslRequired> for issuerd_core::SslRequired {
    fn from(value: RealmSslRequired) -> Self {
        match value {
            RealmSslRequired::None => Self::None,
            RealmSslRequired::External => Self::External,
            RealmSslRequired::All => Self::All,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RealmSettingsArgs {
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
    pub ssl_required: Option<RealmSslRequired>,
    pub access_token_lifespan: Option<i64>,
    pub refresh_token_lifespan: Option<i64>,
    pub sso_session_idle_timeout: Option<i64>,
    pub sso_session_max_lifespan: Option<i64>,
    pub offline_session_idle_timeout: Option<i64>,
    pub login_theme: Option<String>,
    pub email_theme: Option<String>,
    pub admin_theme: Option<String>,
    pub registration_enabled: Option<bool>,
    pub reset_password_allowed: Option<bool>,
    pub remember_me_enabled: Option<bool>,
    pub verify_email_enabled: Option<bool>,
    pub login_with_email_allowed: Option<bool>,
    pub duplicate_emails_allowed: Option<bool>,
    pub edit_username_allowed: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventsConfigArgs {
    pub events_enabled: Option<bool>,
    pub events_expiration_secs: Option<i64>,
    pub admin_events_enabled: Option<bool>,
    pub include_representations: Option<bool>,
    pub events_listeners: Option<Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdpCreateArgs {
    pub id: String,
    pub alias: String,
    pub provider_id: String,
    pub enabled: Option<bool>,
    pub config: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdpUpdateArgs {
    pub id: String,
    pub alias: Option<String>,
    pub provider_id: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowRequirement {
    Required,
    Alternative,
    Optional,
    Disabled,
    Conditional,
}

impl From<FlowRequirement> for issuerd_core::Requirement {
    fn from(value: FlowRequirement) -> Self {
        match value {
            FlowRequirement::Required => Self::Required,
            FlowRequirement::Alternative => Self::Alternative,
            FlowRequirement::Optional => Self::Optional,
            FlowRequirement::Disabled => Self::Disabled,
            FlowRequirement::Conditional => Self::Conditional,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowExecutionArgs {
    pub id: String,
    pub requirement: FlowRequirement,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowUpdateArgs {
    pub alias: String,
    pub executions: Vec<FlowExecutionArgs>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotBeforeArgs {
    pub not_before: i64,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RealmDeleteArgs {
    pub confirm_name: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebauthnDeleteArgs {
    pub id: String,
}

pub fn is_strict(tool: ToolName) -> bool {
    tool.tier() == RiskTier::T3
}

pub fn parse_operation(
    tool: ToolName,
    arguments: Option<JsonObject>,
) -> Result<McpOperation, McpError> {
    let arguments = match tool {
        ToolName::UsersDelete
        | ToolName::GroupsDelete
        | ToolName::ClientsDelete
        | ToolName::IdpDelete => canonical::<DeleteArgs>(arguments)?,
        ToolName::RolesDelete => canonical::<RoleDeleteArgs>(arguments)?,
        ToolName::ClientsUpdateSecurity => canonical::<ClientSecurityArgs>(arguments)?,
        ToolName::RealmUpdateSettings => canonical::<RealmSettingsArgs>(arguments)?,
        ToolName::EventsConfigUpdate => canonical::<EventsConfigArgs>(arguments)?,
        ToolName::IdpCreate => canonical::<IdpCreateArgs>(arguments)?,
        ToolName::IdpUpdate => canonical::<IdpUpdateArgs>(arguments)?,
        ToolName::FlowsUpdateExecutions => canonical::<FlowUpdateArgs>(arguments)?,
        ToolName::PushNotBefore => canonical::<NotBeforeArgs>(arguments)?,
        ToolName::RealmDelete => canonical::<RealmDeleteArgs>(arguments)?,
        ToolName::MeTotpDelete => canonical::<NoArgs>(arguments)?,
        ToolName::MeWebauthnDelete => canonical::<WebauthnDeleteArgs>(arguments)?,
        _ => return Err(McpError::UnknownTool(tool.to_string())),
    };
    Ok(McpOperation { tool, arguments })
}

fn canonical<T: Serialize + serde::de::DeserializeOwned>(
    arguments: Option<JsonObject>,
) -> Result<Value, McpError> {
    let value: T = decode(arguments)?;
    serde_json::to_value(value).map_err(|_| {
        McpError::Backend(issuerd_core::IssuerdError::ServerError(
            "strict argument serialization failed".into(),
        ))
    })
}

pub fn definition(name: ToolName) -> Option<Tool> {
    if !is_strict(name) {
        return None;
    }
    let description = match name {
        ToolName::UsersDelete => "Delete an existing user after fresh exact-operation approval.",
        ToolName::GroupsDelete => "Delete a group after fresh exact-operation approval.",
        ToolName::RolesDelete => "Delete a realm role after fresh exact-operation approval.",
        ToolName::ClientsDelete => "Delete a client after fresh exact-operation approval.",
        ToolName::ClientsUpdateSecurity => {
            "Update client redirect, origin, and grant security after exact-operation approval."
        }
        ToolName::RealmUpdateSettings => {
            "Update realm security settings after exact-operation approval."
        }
        ToolName::EventsConfigUpdate => {
            "Update event retention without disabling administrative audit."
        }
        ToolName::IdpCreate => {
            "Create an identity provider with non-secret configuration and explicit approval."
        }
        ToolName::IdpUpdate => {
            "Update an identity provider with non-secret configuration and explicit approval."
        }
        ToolName::IdpDelete => "Delete an identity provider after exact-operation approval.",
        ToolName::FlowsUpdateExecutions => {
            "Change authentication execution requirements without removing the last factor."
        }
        ToolName::PushNotBefore => {
            "Revoke tokens issued before an exact Unix timestamp after explicit approval."
        }
        ToolName::RealmDelete => "Delete the current realm after naming it and approving exactly.",
        ToolName::MeTotpDelete => {
            "Remove your own TOTP authenticators after fresh exact-operation approval."
        }
        ToolName::MeWebauthnDelete => {
            "Remove one of your own WebAuthn credentials after exact-operation approval."
        }
        _ => return None,
    };
    let tool = Tool::new(name.as_str(), description, std::sync::Arc::new(serde_json::Map::new()));
    let tool = match name {
        ToolName::UsersDelete
        | ToolName::GroupsDelete
        | ToolName::ClientsDelete
        | ToolName::IdpDelete => tool.with_input_schema::<DeleteArgs>(),
        ToolName::RolesDelete => tool.with_input_schema::<RoleDeleteArgs>(),
        ToolName::ClientsUpdateSecurity => tool.with_input_schema::<ClientSecurityArgs>(),
        ToolName::RealmUpdateSettings => tool.with_input_schema::<RealmSettingsArgs>(),
        ToolName::EventsConfigUpdate => tool.with_input_schema::<EventsConfigArgs>(),
        ToolName::IdpCreate => tool.with_input_schema::<IdpCreateArgs>(),
        ToolName::IdpUpdate => tool.with_input_schema::<IdpUpdateArgs>(),
        ToolName::FlowsUpdateExecutions => tool.with_input_schema::<FlowUpdateArgs>(),
        ToolName::PushNotBefore => tool.with_input_schema::<NotBeforeArgs>(),
        ToolName::RealmDelete => tool.with_input_schema::<RealmDeleteArgs>(),
        ToolName::MeTotpDelete => tool.with_input_schema::<NoArgs>(),
        ToolName::MeWebauthnDelete => tool.with_input_schema::<WebauthnDeleteArgs>(),
        _ => return None,
    };
    Some(
        tool.with_output_schema::<WriteOutput>()
            .with_annotations(ToolAnnotations::from_raw(
                None,
                Some(false),
                Some(true),
                Some(false),
                Some(false),
            )),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn strict_schemas_reject_unknown_secret_and_placeholder_fields() {
        for (tool, value) in [
            (
                ToolName::UsersDelete,
                json!({"id":"user","confirmation":"DELETE","password":"x"}),
            ),
            (
                ToolName::IdpCreate,
                json!({"id":"id","alias":"oidc","providerId":"oidc","clientSecret":"x"}),
            ),
            (ToolName::MeTotpDelete, json!({"seed":"secret"})),
            (ToolName::RealmDelete, json!({"name":"demo"})),
            (ToolName::FlowsUpdateExecutions, json!({"alias":"browser","config":{}})),
        ] {
            assert!(parse_operation(tool, Some(value.as_object().unwrap().clone())).is_err());
        }
    }

    #[test]
    fn strict_definitions_are_destructive_and_have_typed_results() {
        for tool in ToolName::ALL.into_iter().filter(|tool| is_strict(*tool)) {
            let definition = definition(tool).unwrap();
            assert_eq!(definition.annotations.unwrap().destructive_hint, Some(true));
            assert_eq!(definition.output_schema.unwrap()["type"], "object");
        }
    }
}
