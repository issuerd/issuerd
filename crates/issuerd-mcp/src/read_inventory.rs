// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use issuerd_core::{
    AdminEventQuery, ClaimTarget, ClientProtocol, EventQuery, FlowConfig, IdentityProviderConfig,
    JwkKty, StoredSigningKey,
};
use rmcp::model::JsonObject;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    error::McpError,
    executor::{decode, output, pagination, McpToolExecutor, McpToolPermit},
    policy::ToolName,
    tools::{NoArgs, RoleGetArgs, UserSessionOutput},
};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionsListArgs {
    pub first: Option<u32>,
    pub max: Option<u32>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventsSearchArgs {
    pub admin: Option<bool>,
    pub event_type: Option<String>,
    pub operation_type: Option<String>,
    pub resource_type: Option<String>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub first: Option<u32>,
    pub max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnumValueOutput {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfoOutput {
    pub version: String,
    pub capabilities: BTreeMap<String, Vec<EnumValueOutput>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionsOutput {
    pub sessions: Vec<UserSessionOutput>,
    pub total: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventOutput {
    pub id: String,
    pub time: i64,
    pub realm_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_realm_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventsOutput {
    pub kind: String,
    pub events: Vec<AuditEventOutput>,
    pub total: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KeyOutput {
    pub provider_id: String,
    pub kid: String,
    pub status: String,
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KeysOutput {
    pub active: BTreeMap<String, String>,
    pub keys: Vec<KeyOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolMapperOutput {
    pub id: String,
    pub name: String,
    pub protocol_mapper: String,
    pub access_token: bool,
    pub id_token: bool,
    pub userinfo: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientScopeOutput {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub protocol: String,
    pub protocol_mappers: Vec<ProtocolMapperOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientScopesOutput {
    pub client_scopes: Vec<ClientScopeOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdpOutput {
    pub id: String,
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub provider_id: String,
    pub enabled: bool,
    pub config: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdpsOutput {
    pub identity_providers: Vec<IdpOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowStageOutput {
    pub id: String,
    pub requirement: String,
    pub authenticator: String,
    pub priority: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_flow_alias: Option<String>,
    pub has_config: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowOutput {
    pub alias: String,
    pub provider_id: String,
    pub top_level: bool,
    pub built_in: bool,
    pub stages: Vec<FlowStageOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowsOutput {
    pub flows: Vec<FlowOutput>,
}

pub(crate) async fn execute(
    executor: &McpToolExecutor,
    permit: &McpToolPermit,
    arguments: Option<JsonObject>,
) -> Result<serde_json::Value, McpError> {
    match permit.tool {
        ToolName::ServerinfoGet => {
            let _: NoArgs = decode(arguments)?;
            let service = executor.application.as_ref().ok_or_else(|| {
                McpError::Backend(issuerd_core::IssuerdError::ServerError(
                    "MCP application service is not configured".into(),
                ))
            })?;
            output(service.server_info().await?)
        }
        ToolName::EventsSearch => events_search(executor, permit, arguments).await,
        ToolName::SessionsList => sessions_list(executor, permit, arguments).await,
        ToolName::KeysList => keys_list(executor, permit, arguments).await,
        ToolName::ClientScopesList => client_scopes_list(executor, permit, arguments).await,
        ToolName::IdpList => idp_list(executor, permit, arguments).await,
        ToolName::IdpGet => idp_get(executor, permit, arguments).await,
        ToolName::FlowsList => flows_list(executor, permit, arguments).await,
        _ => unreachable!("read inventory dispatcher received a non-inventory tool"),
    }
}

async fn sessions_list(
    executor: &McpToolExecutor,
    permit: &McpToolPermit,
    arguments: Option<JsonObject>,
) -> Result<serde_json::Value, McpError> {
    let args: SessionsListArgs = decode(arguments)?;
    let pagination = pagination(args.first, args.max)?;
    let mut sessions = executor
        .storage
        .list_sessions(&permit.target.realm_id, None, &pagination)
        .await?;
    sessions.sort_by(|left, right| {
        right
            .last_session_refresh
            .cmp(&left.last_session_refresh)
            .then_with(|| left.id.cmp(&right.id))
    });
    let total = executor.storage.count_sessions(&permit.target.realm_id, None).await?;
    output(SessionsOutput {
        sessions: sessions.iter().map(UserSessionOutput::from).collect(),
        total,
    })
}

async fn events_search(
    executor: &McpToolExecutor,
    permit: &McpToolPermit,
    arguments: Option<JsonObject>,
) -> Result<serde_json::Value, McpError> {
    let args: EventsSearchArgs = decode(arguments)?;
    let realm = executor
        .storage
        .get_realm(&permit.target.realm_id)
        .await?
        .ok_or(McpError::NotFound("realm"))?;
    let pagination = pagination(args.first, args.max)?;
    let date_from = parse_date(args.date_from.as_deref(), "dateFrom")?;
    let date_to = parse_date(args.date_to.as_deref(), "dateTo")?;
    let date_from = clamp_date_from(date_from, realm.events_expiration_secs);
    if args.admin.unwrap_or(false) {
        let query = AdminEventQuery {
            operation_type: parse_enum(args.operation_type.as_deref(), "operationType")?,
            resource_type: parse_enum(args.resource_type.as_deref(), "resourceType")?,
            auth_user_id: None,
            date_from,
            date_to,
            pagination,
        };
        let total = executor.storage.count_admin_events(&realm.id, &query).await?;
        let events = executor.storage.query_admin_events(&realm.id, &query).await?;
        let mut output_events = Vec::with_capacity(events.len());
        for event in events {
            let auth_realm = event.auth_realm_id.clone().unwrap_or_else(|| realm.id.clone());
            let auth_username = match event.auth_user_id.as_ref() {
                Some(user_id) => executor
                    .storage
                    .get_user(&auth_realm, user_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|user| user.username.to_string()),
                None => None,
            };
            output_events.push(AuditEventOutput {
                id: event.id.to_string(),
                time: event.event_time.timestamp(),
                realm_id: event.realm_id.to_string(),
                event_type: None,
                operation_type: Some(wire_string(&event.operation_type)?),
                resource_type: Some(wire_string(&event.resource_type)?),
                resource_path: Some(event.resource_path),
                client_id: None,
                user_id: None,
                username: None,
                session_id: None,
                ip_address: None,
                auth_realm_id: event.auth_realm_id.map(|id| id.to_string()),
                auth_client_id: event.auth_client_id.map(|id| id.to_string()),
                auth_user_id: event.auth_user_id.map(|id| id.to_string()),
                auth_username,
                error: event.error,
            });
        }
        output(EventsOutput {
            kind: "admin".into(),
            events: output_events,
            total,
        })
    } else {
        let query = EventQuery {
            event_type: parse_enum(args.event_type.as_deref(), "eventType")?,
            client_id: None,
            user_id: None,
            date_from,
            date_to,
            pagination,
        };
        let total = executor.storage.count_events(&realm.id, &query).await?;
        let events = executor.storage.query_events(&realm.id, &query).await?;
        let mut output_events = Vec::with_capacity(events.len());
        for event in events {
            let username = match event.user_id.as_ref() {
                Some(user_id) => match executor.storage.get_user(&realm.id, user_id).await {
                    Ok(Some(user)) => Some(user.username.to_string()),
                    _ => event.details.get("username").cloned(),
                },
                None => None,
            };
            output_events.push(AuditEventOutput {
                id: event.id.to_string(),
                time: event.event_time.timestamp(),
                realm_id: event.realm_id.to_string(),
                event_type: Some(wire_string(&event.event_type)?),
                operation_type: None,
                resource_type: None,
                resource_path: None,
                client_id: event.client_id.map(|id| id.to_string()),
                user_id: event.user_id.map(|id| id.to_string()),
                username,
                session_id: event.session_id.map(|id| id.to_string()),
                ip_address: event.ip_address.map(|ip| ip.to_string()),
                auth_realm_id: None,
                auth_client_id: None,
                auth_user_id: None,
                auth_username: None,
                error: event.error,
            });
        }
        output(EventsOutput {
            kind: "user".into(),
            events: output_events,
            total,
        })
    }
}

async fn keys_list(
    executor: &McpToolExecutor,
    permit: &McpToolPermit,
    arguments: Option<JsonObject>,
) -> Result<serde_json::Value, McpError> {
    let _: NoArgs = decode(arguments)?;
    let realm = executor
        .storage
        .get_realm(&permit.target.realm_id)
        .await?
        .ok_or(McpError::NotFound("realm"))?;
    let _ = realm;
    let mut keys = executor.storage.list_signing_keys().await?;
    keys.sort_by(|left, right| {
        right
            .active
            .cmp(&left.active)
            .then_with(|| right.created_at.cmp(&left.created_at))
            .then_with(|| left.kid.cmp(&right.kid))
    });
    let mut active = BTreeMap::new();
    for key in keys.iter().filter(|key| key.active) {
        active.entry(key.alg.to_string()).or_insert_with(|| key.kid.to_string());
    }
    output(KeysOutput {
        active,
        keys: keys.iter().map(key_output).collect::<Result<_, _>>()?,
    })
}

async fn client_scopes_list(
    executor: &McpToolExecutor,
    permit: &McpToolPermit,
    arguments: Option<JsonObject>,
) -> Result<serde_json::Value, McpError> {
    let args: SessionsListArgs = decode(arguments)?;
    let pagination = pagination(args.first, args.max)?;
    let mut scopes = executor
        .storage
        .list_client_scopes(&permit.target.realm_id, &pagination)
        .await?;
    scopes.sort_by(|left, right| left.name.cmp(&right.name).then_with(|| left.id.cmp(&right.id)));
    output(ClientScopesOutput {
        client_scopes: scopes
            .iter()
            .map(|scope| {
                let mut protocol_mappers: Vec<_> = scope
                    .protocol_mappers
                    .iter()
                    .map(|mapper| {
                        Ok(ProtocolMapperOutput {
                            id: mapper.id.to_string(),
                            name: mapper.name.clone(),
                            protocol_mapper: wire_string(&mapper.mapper_type)?,
                            access_token: mapper.applies_to(ClaimTarget::AccessToken),
                            id_token: mapper.applies_to(ClaimTarget::IdToken),
                            userinfo: mapper.applies_to(ClaimTarget::UserInfo),
                        })
                    })
                    .collect::<Result<_, McpError>>()?;
                protocol_mappers.sort_by(|left: &ProtocolMapperOutput, right| {
                    left.name.cmp(&right.name).then_with(|| left.id.cmp(&right.id))
                });
                Ok(ClientScopeOutput {
                    id: scope.id.to_string(),
                    name: scope.name.clone(),
                    description: scope.description.clone(),
                    protocol: protocol_name(&scope.protocol).into(),
                    protocol_mappers,
                })
            })
            .collect::<Result<_, McpError>>()?,
    })
}

async fn idp_list(
    executor: &McpToolExecutor,
    permit: &McpToolPermit,
    arguments: Option<JsonObject>,
) -> Result<serde_json::Value, McpError> {
    let _: NoArgs = decode(arguments)?;
    let mut idps = executor.storage.list_identity_providers(&permit.target.realm_id).await?;
    idps.sort_by(|left, right| left.alias.as_str().cmp(right.alias.as_str()));
    output(IdpsOutput {
        identity_providers: idps.iter().map(idp_output).collect(),
    })
}

async fn idp_get(
    executor: &McpToolExecutor,
    permit: &McpToolPermit,
    arguments: Option<JsonObject>,
) -> Result<serde_json::Value, McpError> {
    let args: RoleGetArgs = decode(arguments)?;
    let alias = args.name.trim();
    if alias.is_empty() || alias != args.name || alias.len() > 255 {
        return Err(McpError::InvalidInput(
            "name must be a nonempty IdP alias without surrounding whitespace".into(),
        ));
    }
    let idp = executor
        .storage
        .get_identity_provider_by_alias(&permit.target.realm_id, alias)
        .await?
        .ok_or(McpError::NotFound("identity provider"))?;
    output(idp_output(&idp))
}

async fn flows_list(
    executor: &McpToolExecutor,
    permit: &McpToolPermit,
    arguments: Option<JsonObject>,
) -> Result<serde_json::Value, McpError> {
    let _: NoArgs = decode(arguments)?;
    let mut flows = executor.storage.list_flow_configs(&permit.target.realm_id).await?;
    flows.sort_by(|left, right| left.alias.as_str().cmp(right.alias.as_str()));
    output(FlowsOutput {
        flows: flows.iter().map(flow_output).collect::<Result<_, _>>()?,
    })
}

fn key_output(key: &StoredSigningKey) -> Result<KeyOutput, McpError> {
    Ok(KeyOutput {
        provider_id: match key.public_jwk.kty {
            JwkKty::Rsa => "rsa-generated",
            JwkKty::Ec => "ecdsa-generated",
            JwkKty::Okp => "eddsa-generated",
            JwkKty::Oct => "hmac-generated",
        }
        .into(),
        kid: key.kid.to_string(),
        status: if key.active { "ACTIVE" } else { "PASSIVE" }.into(),
        algorithm: key.alg.to_string(),
        public_key: key.public_jwk.n.as_ref().map(|value| value.as_str().to_string()),
    })
}

fn idp_output(idp: &IdentityProviderConfig) -> IdpOutput {
    let config = idp
        .config
        .iter()
        .filter(|(key, _)| !sensitive_config_key(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    IdpOutput {
        id: idp.id.to_string(),
        alias: idp.alias.to_string(),
        display_name: idp.config.get("displayName").cloned(),
        provider_id: idp.provider_id.as_str().into(),
        enabled: idp.enabled,
        config,
    }
}

fn sensitive_config_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "secret",
        "password",
        "credential",
        "privatekey",
        "accesstoken",
        "refreshtoken",
    ]
    .iter()
    .any(|fragment| normalized.contains(fragment))
}

fn flow_output(flow: &FlowConfig) -> Result<FlowOutput, McpError> {
    let mut stages = flow
        .stages
        .iter()
        .map(|stage| {
            Ok(FlowStageOutput {
                id: stage.id.to_string(),
                requirement: wire_string(&stage.requirement)?,
                authenticator: stage.authenticator.to_string(),
                priority: stage.priority,
                sub_flow_alias: stage.sub_flow_alias.as_ref().map(ToString::to_string),
                has_config: stage.authenticator_config.is_some(),
            })
        })
        .collect::<Result<Vec<_>, McpError>>()?;
    stages.sort_by_key(|stage: &FlowStageOutput| stage.priority);
    Ok(FlowOutput {
        alias: flow.alias.to_string(),
        provider_id: flow.provider_id.clone(),
        top_level: flow.top_level,
        built_in: flow.built_in,
        stages,
    })
}

fn protocol_name(protocol: &ClientProtocol) -> &'static str {
    match protocol {
        ClientProtocol::OpenIdConnect => "openid-connect",
        ClientProtocol::Saml => "saml",
    }
}

fn parse_enum<T: DeserializeOwned>(
    value: Option<&str>,
    field: &str,
) -> Result<Option<T>, McpError> {
    value
        .map(|value| {
            if value.len() > 255 || value.chars().any(char::is_control) {
                return Err(McpError::InvalidInput(format!("{field} is invalid")));
            }
            serde_json::from_value(serde_json::Value::String(value.into()))
                .map_err(|_| McpError::InvalidInput(format!("{field} is invalid")))
        })
        .transpose()
}

fn parse_date(value: Option<&str>, field: &str) -> Result<Option<DateTime<Utc>>, McpError> {
    value
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|date| date.with_timezone(&Utc))
                .map_err(|_| McpError::InvalidInput(format!("{field} must be RFC 3339")))
        })
        .transpose()
}

fn clamp_date_from(
    requested: Option<DateTime<Utc>>,
    expiration_secs: i64,
) -> Option<DateTime<Utc>> {
    if expiration_secs <= 0 {
        return requested;
    }
    let cutoff = Utc::now() - chrono::Duration::seconds(expiration_secs);
    Some(requested.map_or(cutoff, |from| from.max(cutoff)))
}

fn wire_string(value: &impl Serialize) -> Result<String, McpError> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            McpError::Backend(issuerd_core::IssuerdError::ServerError(
                "tool enum serialization failed".into(),
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_idp_values_are_omitted_not_masked() {
        let idp = IdentityProviderConfig {
            id: issuerd_core::IdentityProviderId::new("idp-1").unwrap(),
            alias: issuerd_core::Alias::new("broker").unwrap(),
            provider_id: issuerd_core::ProviderId::new("oidc"),
            enabled: true,
            config: [
                ("clientId".into(), "public-client".into()),
                ("clientSecret".into(), "secret-canary".into()),
                ("bindCredential".into(), "bind-canary".into()),
                ("private_key".into(), "key-canary".into()),
                ("displayName".into(), "Broker".into()),
            ]
            .into_iter()
            .collect(),
        };
        let value = serde_json::to_value(idp_output(&idp)).unwrap();
        assert_eq!(value["config"]["clientId"], "public-client");
        assert_eq!(value["displayName"], "Broker");
        for canary in ["secret-canary", "bind-canary", "key-canary", "clientSecret"] {
            assert!(!value.to_string().contains(canary));
        }
    }

    #[test]
    fn strict_new_inputs_reject_unknown_fields() {
        assert!(serde_json::from_str::<EventsSearchArgs>(r#"{"unexpected":true}"#).is_err());
        assert!(serde_json::from_str::<SessionsListArgs>(r#"{"unexpected":true}"#).is_err());
    }

    #[test]
    fn event_dates_are_strict_and_retention_clamps() {
        assert!(parse_date(Some("not-a-date"), "dateFrom").is_err());
        assert!(parse_date(Some("2026-10-30T12:00:00Z"), "dateFrom").unwrap().is_some());
        let old = DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(clamp_date_from(Some(old), 60).unwrap() > old);
    }

    #[test]
    fn sensitive_key_fragments_cover_common_spellings() {
        for key in [
            "clientSecret",
            "bindCredential",
            "password",
            "private_key",
            "accessToken",
            "refresh-token",
        ] {
            assert!(sensitive_config_key(key), "{key}");
        }
        for key in ["clientId", "authorizationUrl", "displayName"] {
            assert!(!sensitive_config_key(key), "{key}");
        }
    }

    #[test]
    fn event_output_has_no_arbitrary_detail_or_representation_channel() {
        let schema = schemars::schema_for!(AuditEventOutput);
        let value = serde_json::to_value(schema).unwrap();
        let properties = value["properties"].as_object().unwrap();
        for forbidden in ["details", "representation"] {
            assert!(!properties.contains_key(forbidden));
        }
        assert!(properties.contains_key("resourcePath"));
    }
}
