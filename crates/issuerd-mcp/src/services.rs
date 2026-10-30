// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use async_trait::async_trait;

use crate::{
    auth::McpAuthContext, error::McpError, read_inventory::ServerInfoOutput,
    write_tools::McpOperation,
};

#[async_trait]
pub trait McpApplicationService: Send + Sync {
    async fn server_info(&self) -> Result<ServerInfoOutput, McpError>;

    async fn write(
        &self,
        auth: &McpAuthContext,
        operation: McpOperation,
    ) -> Result<serde_json::Value, McpError>;

    async fn account(
        &self,
        auth: &McpAuthContext,
        operation: McpOperation,
    ) -> Result<serde_json::Value, McpError>;
}
