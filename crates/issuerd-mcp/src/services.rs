// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use async_trait::async_trait;

use issuerd_core::{McpStepUpGrant, McpStepUpMutation};

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

    /// Resolve a strict operation and its current preconditions. `None` keeps
    /// the ordinary T0/T1/T2 dispatcher; `Some` requires operation-bound CIBA.
    async fn prepare_strict(
        &self,
        auth: &McpAuthContext,
        operation: McpOperation,
    ) -> Result<Option<McpStepUpMutation>, McpError>;

    /// Run cache invalidation and audit after a committed strict operation.
    /// Implementations must not repeat the mutation or expose sensitive output.
    async fn strict_committed(&self, grant: &McpStepUpGrant);
}
