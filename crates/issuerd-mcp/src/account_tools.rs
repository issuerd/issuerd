// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::McpError,
    executor::decode,
    policy::ToolName,
    tools::NoArgs,
    write_tools::{McpOperation, WriteOutput},
};

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountProfileOutput {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    pub email_verified: bool,
    pub enabled: bool,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountSessionOutput {
    pub id: String,
    pub ip_address: String,
    pub started: String,
    pub last_session_refresh: String,
    pub clients: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountSessionsOutput {
    pub sessions: Vec<AccountSessionOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountConsentOutput {
    pub client_id: String,
    pub granted_scopes: Vec<String>,
    pub created_at: String,
    pub last_updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountConsentsOutput {
    pub consents: Vec<AccountConsentOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LinkedAccountOutput {
    pub alias: String,
    pub provider_id: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_username: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LinkedAccountsOutput {
    pub linked_accounts: Vec<LinkedAccountOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecureActionOutput {
    pub action_url: String,
    pub ceremony: String,
}

mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Ok(Some(Option::<T>::deserialize(deserializer)?))
    }
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeUpdateProfileArgs {
    #[serde(default, deserialize_with = "double_option::deserialize")]
    pub first_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    pub last_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    pub email: Option<Option<String>>,
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeSessionLogoutArgs {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeConsentRevokeArgs {
    pub client_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeLinkedAccountUnlinkArgs {
    pub alias: String,
}

pub fn is_account_tool(tool: ToolName) -> bool {
    matches!(
        tool,
        ToolName::MeConsentsList
            | ToolName::MeConsentsRevoke
            | ToolName::MeGetProfile
            | ToolName::MeLinkedAccountsList
            | ToolName::MeLinkedAccountsUnlink
            | ToolName::MeSessionsList
            | ToolName::MeSessionsLogout
            | ToolName::MeTotpEnroll
            | ToolName::MeUpdateProfile
            | ToolName::MeWebauthnRegister
    )
}

pub fn parse_operation(
    tool: ToolName,
    arguments: Option<JsonObject>,
) -> Result<McpOperation, McpError> {
    let arguments = match tool {
        ToolName::MeGetProfile
        | ToolName::MeSessionsList
        | ToolName::MeConsentsList
        | ToolName::MeLinkedAccountsList
        | ToolName::MeTotpEnroll
        | ToolName::MeWebauthnRegister => canonical::<NoArgs>(arguments)?,
        ToolName::MeUpdateProfile => canonical::<MeUpdateProfileArgs>(arguments)?,
        ToolName::MeSessionsLogout => canonical::<MeSessionLogoutArgs>(arguments)?,
        ToolName::MeConsentsRevoke => canonical::<MeConsentRevokeArgs>(arguments)?,
        ToolName::MeLinkedAccountsUnlink => canonical::<MeLinkedAccountUnlinkArgs>(arguments)?,
        _ => unreachable!("account operation parser received a non-account tool"),
    };
    Ok(McpOperation { tool, arguments })
}

fn canonical<T: Serialize + serde::de::DeserializeOwned>(
    arguments: Option<JsonObject>,
) -> Result<Value, McpError> {
    let value: T = decode(arguments)?;
    serde_json::to_value(value).map_err(|_| {
        McpError::Backend(issuerd_core::IssuerdError::ServerError(
            "account argument serialization failed".into(),
        ))
    })
}

pub fn definition(name: ToolName) -> Option<Tool> {
    if !is_account_tool(name) {
        return None;
    }
    let description = match name {
        ToolName::MeGetProfile => {
            "Return the authenticated user's own profile and direct realm roles."
        }
        ToolName::MeUpdateProfile => {
            "Update the authenticated user's own profile with Account semantics."
        }
        ToolName::MeSessionsList => "List only the authenticated user's active sessions.",
        ToolName::MeSessionsLogout => "Log out one session owned by the authenticated user.",
        ToolName::MeConsentsList => "List only the authenticated user's client consents.",
        ToolName::MeConsentsRevoke => "Revoke one of the authenticated user's client consents.",
        ToolName::MeLinkedAccountsList => {
            "List only the authenticated user's linked external identities."
        }
        ToolName::MeLinkedAccountsUnlink => {
            "Unlink an external identity while preserving a sign-in method."
        }
        ToolName::MeTotpEnroll => {
            "Return a same-origin account-console link for browser-only TOTP enrollment."
        }
        ToolName::MeWebauthnRegister => {
            "Return a same-origin account-console link for browser-only WebAuthn registration."
        }
        _ => unreachable!("account definition received a non-account tool"),
    };
    let tool = Tool::new(name.as_str(), description, std::sync::Arc::new(serde_json::Map::new()));
    let read = matches!(
        name,
        ToolName::MeGetProfile
            | ToolName::MeSessionsList
            | ToolName::MeConsentsList
            | ToolName::MeLinkedAccountsList
    );
    let tool = match name {
        ToolName::MeGetProfile => {
            tool.with_input_schema::<NoArgs>().with_output_schema::<AccountProfileOutput>()
        }
        ToolName::MeUpdateProfile => tool
            .with_input_schema::<MeUpdateProfileArgs>()
            .with_output_schema::<AccountProfileOutput>(),
        ToolName::MeSessionsList => {
            tool.with_input_schema::<NoArgs>().with_output_schema::<AccountSessionsOutput>()
        }
        ToolName::MeSessionsLogout => tool
            .with_input_schema::<MeSessionLogoutArgs>()
            .with_output_schema::<WriteOutput>(),
        ToolName::MeConsentsList => {
            tool.with_input_schema::<NoArgs>().with_output_schema::<AccountConsentsOutput>()
        }
        ToolName::MeConsentsRevoke => tool
            .with_input_schema::<MeConsentRevokeArgs>()
            .with_output_schema::<WriteOutput>(),
        ToolName::MeLinkedAccountsList => {
            tool.with_input_schema::<NoArgs>().with_output_schema::<LinkedAccountsOutput>()
        }
        ToolName::MeLinkedAccountsUnlink => tool
            .with_input_schema::<MeLinkedAccountUnlinkArgs>()
            .with_output_schema::<WriteOutput>(),
        ToolName::MeTotpEnroll | ToolName::MeWebauthnRegister => {
            tool.with_input_schema::<NoArgs>().with_output_schema::<SecureActionOutput>()
        }
        _ => unreachable!("account definition received a non-account tool"),
    };
    Some(tool.with_annotations(ToolAnnotations::from_raw(
        None,
        Some(read),
        Some(false),
        Some(true),
        Some(false),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn profile_update_supports_tri_state_fields_but_no_credentials() {
        let clear: MeUpdateProfileArgs = serde_json::from_value(json!({
            "firstName": null,
            "email": null
        }))
        .unwrap();
        assert_eq!(clear.first_name, Some(None));
        assert_eq!(clear.email, Some(None));
        assert!(serde_json::from_value::<MeUpdateProfileArgs>(json!({
            "password": "secret"
        }))
        .is_err());
    }

    #[test]
    fn enrollment_schemas_have_no_secret_output_channels() {
        for tool in [ToolName::MeTotpEnroll, ToolName::MeWebauthnRegister] {
            let definition = definition(tool).unwrap();
            let schema = definition.output_schema.unwrap();
            let properties = schema["properties"].as_object().unwrap();
            assert!(properties.contains_key("actionUrl"));
            assert!(properties.contains_key("ceremony"));
            for forbidden in ["secret", "qrSvg", "otpauthUrl", "publicKey", "credential"] {
                assert!(!properties.contains_key(forbidden));
            }
        }
    }
}
