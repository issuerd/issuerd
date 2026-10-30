// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use async_trait::async_trait;

use crate::{error::McpError, read_inventory::ServerInfoOutput};

#[async_trait]
pub trait McpApplicationService: Send + Sync {
    async fn server_info(&self) -> Result<ServerInfoOutput, McpError>;
}
