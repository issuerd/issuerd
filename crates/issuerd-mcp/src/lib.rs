// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

#![forbid(unsafe_code)]

pub mod account_tools;
pub mod auth;
pub mod error;
pub mod executor;
pub mod json;
pub mod policy;
pub mod rate_limit;
pub mod read_inventory;
pub mod server;
pub mod services;
pub mod step_up;
pub mod strict_tools;
pub mod tools;
pub mod transport;
pub mod write_tools;

#[cfg(test)]
mod test_support;

pub use auth::McpAuthContext;
pub use error::McpError;
pub use executor::{McpTarget, McpToolExecutor, McpToolPermit};
pub use policy::{PolicyDecision, PolicyDeny, ToolName, ToolPolicy};
pub use rate_limit::McpRateLimiter;
pub use server::IssuerdMcpServer;
