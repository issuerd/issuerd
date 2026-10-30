// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use issuerd_admin_api::state::AdminApiState;
use issuerd_mcp::{
    read_inventory::{EnumValueOutput, ServerInfoOutput},
    services::McpApplicationService,
    McpError,
};

use crate::{routes::theme, state::ServerState};

pub fn admin_state(state: &Arc<ServerState>) -> Arc<AdminApiState> {
    Arc::new(AdminApiState {
        storage: state.storage.clone(),
        token_service: state.token_service.clone(),
        crypto: state.crypto.clone(),
        federation_manager: state.federation_manager.clone(),
        plugin_registry: state.plugin_registry.clone(),
        cache: state.cache.clone(),
        email_sender: state.email_sender.clone(),
        broker_client: state.broker_client.clone(),
        logout_notifier: state.logout_notifier.clone(),
        available_themes: theme::available_themes(&state.config.themes.dir),
        available_locales: theme::available_locales(&state.config.themes.dir),
        token_issuer: state.token_manager.clone(),
        signing_key_reload: state.signing_key_reload.clone(),
        mcp_enabled: state.config.mcp.enabled,
        base_url: state.config.issuer_url.trim_end_matches('/').to_string(),
        email_bundle: {
            let themes_dir = state.config.themes.dir.clone();
            let resolver = move |realm: &issuerd_core::Realm, user: &issuerd_core::User| {
                crate::i18n::message_bundle(
                    Some(themes_dir.as_path()),
                    realm.email_theme.as_ref().map(|theme| theme.as_str()),
                    &crate::i18n::user_locale(realm, user),
                )
            };
            Some(Arc::new(resolver) as issuerd_admin_api::state::EmailBundleResolver)
        },
    })
}

pub struct ServerMcpApplicationService {
    admin_state: Arc<AdminApiState>,
}

impl ServerMcpApplicationService {
    pub fn new(admin_state: Arc<AdminApiState>) -> Self {
        Self { admin_state }
    }
}

#[async_trait]
impl McpApplicationService for ServerMcpApplicationService {
    async fn server_info(&self) -> Result<ServerInfoOutput, McpError> {
        let info = issuerd_admin_api::enums::build_server_info(&self.admin_state).await;
        let version = info.version.clone();
        let value = serde_json::to_value(info).map_err(|error| {
            McpError::Backend(issuerd_core::IssuerdError::ServerError(error.to_string()))
        })?;
        let mut capabilities = BTreeMap::new();
        for (name, value) in value.as_object().into_iter().flatten() {
            if name == "version" {
                continue;
            }
            if let Ok(values) = serde_json::from_value::<Vec<EnumValueOutput>>(value.clone()) {
                capabilities.insert(name.clone(), values);
            }
        }
        Ok(ServerInfoOutput {
            version,
            capabilities,
        })
    }
}
