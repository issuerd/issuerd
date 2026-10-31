// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use issuerd_core::{IssuerdError, Pagination};
use rmcp::model::Resource;
use serde_json::Value;

use crate::{
    error::McpError,
    executor::McpToolExecutor,
    policy::{self, ToolName},
    tools::{ClientOutput, ClientsOutput, RoleOutput, RolesOutput},
    McpAuthContext,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResourceKind {
    Clients,
    Roles,
    Config,
}

impl ResourceKind {
    const ALL: [Self; 3] = [Self::Clients, Self::Roles, Self::Config];

    const fn path(self) -> &'static str {
        match self {
            Self::Clients => "clients",
            Self::Roles => "roles",
            Self::Config => "config",
        }
    }

    const fn tool(self) -> ToolName {
        match self {
            Self::Clients => ToolName::ClientsList,
            Self::Roles => ToolName::RolesList,
            Self::Config => ToolName::RealmGet,
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::Clients => "Realm clients",
            Self::Roles => "Realm roles",
            Self::Config => "Realm configuration",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Clients => {
                "Complete realm client catalog with secrets and arbitrary configuration omitted."
            }
            Self::Roles => {
                "Complete realm-role catalog with client roles and arbitrary attributes omitted."
            }
            Self::Config => "Curated non-secret configuration for the current realm.",
        }
    }
}

fn uri(auth: &McpAuthContext, kind: ResourceKind) -> String {
    format!("issuerd://realm/{}/{}", auth.realm_name, kind.path())
}

pub fn definitions(auth: &McpAuthContext) -> Vec<Resource> {
    ResourceKind::ALL
        .into_iter()
        .filter(|kind| policy::decide_for(kind.tool(), auth).is_allowed())
        .map(|kind| {
            Resource::new(uri(auth, kind), format!("realm_{}", kind.path()))
                .with_title(kind.title())
                .with_description(kind.description())
                .with_mime_type("application/json")
        })
        .collect()
}

pub async fn read(
    executor: &McpToolExecutor,
    auth: McpAuthContext,
    requested_uri: &str,
    now: u64,
) -> Result<(String, Value), McpError> {
    let kind = ResourceKind::ALL
        .into_iter()
        .find(|kind| uri(&auth, *kind) == requested_uri)
        .ok_or(McpError::NotFound("resource"))?;
    let permit = executor.preflight(kind.tool().as_str(), auth, now).await?;
    let value = match kind {
        ResourceKind::Config => executor.execute(&permit, None).await?,
        ResourceKind::Clients => {
            let mut clients = executor
                .storage
                .list_clients(
                    &permit.target.realm_id,
                    &Pagination {
                        first: 0,
                        max: i32::MAX,
                    },
                )
                .await?;
            clients.sort_by(|left, right| {
                left.client_id
                    .as_str()
                    .cmp(right.client_id.as_str())
                    .then_with(|| left.id.cmp(&right.id))
            });
            to_value(ClientsOutput {
                clients: clients.iter().map(ClientOutput::from).collect(),
            })?
        }
        ResourceKind::Roles => {
            let mut roles = executor
                .storage
                .list_roles(
                    &permit.target.realm_id,
                    &Pagination {
                        first: 0,
                        max: i32::MAX,
                    },
                )
                .await?;
            roles.retain(|role| !role.client_role);
            roles.sort_by(|left, right| {
                left.name.as_str().cmp(right.name.as_str()).then_with(|| left.id.cmp(&right.id))
            });
            to_value(RolesOutput {
                roles: roles.iter().map(RoleOutput::from).collect(),
            })?
        }
    };
    Ok((uri(&permit.auth, kind), value))
}

fn to_value<T: serde::Serialize>(output: T) -> Result<Value, McpError> {
    serde_json::to_value(output)
        .map_err(|error| McpError::Backend(IssuerdError::ServerError(error.to_string())))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use issuerd_cluster::InMemoryCache;

    use super::*;
    use crate::{test_support::*, McpRateLimiter};

    fn executor(storage: Arc<issuerd_storage::InMemoryStorage>) -> McpToolExecutor {
        McpToolExecutor::new(storage, McpRateLimiter::new(Arc::new(InMemoryCache::new()), 60))
    }

    #[tokio::test]
    async fn resource_reads_are_complete_redacted_and_realm_bound() {
        let executor = executor(storage().await);
        let clients = read(
            &executor,
            auth("mcp:read", &["view-clients"]),
            "issuerd://realm/demo/clients",
            1,
        )
        .await
        .unwrap();
        assert_eq!(clients.0, "issuerd://realm/demo/clients");
        assert_eq!(clients.1["clients"].as_array().unwrap().len(), 3);
        let serialized = clients.1.to_string();
        for canary in [CLIENT_SECRET, CLIENT_ATTRIBUTE_SECRET, "attributes"] {
            assert!(!serialized.contains(canary));
        }

        let roles =
            read(&executor, auth("mcp:read", &["view-realm"]), "issuerd://realm/demo/roles", 2)
                .await
                .unwrap();
        assert_eq!(roles.1["roles"].as_array().unwrap().len(), 2);
        assert!(!roles.1.to_string().contains(ROLE_SECRET));

        let config =
            read(&executor, auth("mcp:read", &["view-realm"]), "issuerd://realm/demo/config", 3)
                .await
                .unwrap();
        assert_eq!(config.1["realm"], "demo");
        assert!(!config.1.to_string().contains(REALM_SECRET));

        for invalid in [
            "issuerd://realm/other/clients",
            "issuerd://realm/demo/clients/",
            "issuerd://realm/demo/secrets",
            "issuerd://realm/%64emo/clients",
        ] {
            assert!(matches!(
                read(&executor, auth("mcp:read", &["view-clients"]), invalid, 4).await,
                Err(McpError::NotFound("resource"))
            ));
        }
    }

    #[test]
    fn resource_listing_uses_each_resources_policy() {
        let all = definitions(&auth("mcp:read", &["view-realm", "view-clients"]));
        assert_eq!(all.len(), 3);
        assert!(all
            .iter()
            .all(|resource| resource.mime_type.as_deref() == Some("application/json")));

        let clients = definitions(&auth("mcp:read", &["view-clients"]));
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].uri, "issuerd://realm/demo/clients");
        assert!(definitions(&auth("mcp:read", &[])).is_empty());
        assert!(definitions(&auth("mcp:step_up", &["view-realm", "view-clients"])).is_empty());
    }

    #[tokio::test]
    async fn reads_repeat_policy_and_consume_one_invocation_allowance() {
        let storage = storage().await;
        let executor =
            McpToolExecutor::new(storage, McpRateLimiter::new(Arc::new(InMemoryCache::new()), 2));
        assert!(matches!(
            read(&executor, auth("mcp:read", &[]), "issuerd://realm/demo/clients", 1,).await,
            Err(McpError::MissingRole { .. })
        ));
        read(
            &executor,
            auth("mcp:read", &["view-clients"]),
            "issuerd://realm/demo/clients",
            1,
        )
        .await
        .unwrap();
        assert!(matches!(
            read(
                &executor,
                auth("mcp:read", &["view-clients"]),
                "issuerd://realm/demo/clients",
                1,
            )
            .await,
            Err(McpError::RateLimited { .. })
        ));
    }
}
