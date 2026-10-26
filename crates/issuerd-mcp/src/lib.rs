// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

#![forbid(unsafe_code)]

pub mod auth;
pub mod error;
pub mod executor;
pub mod json;
pub mod policy;
pub mod rate_limit;
pub mod server;
pub mod tools;
pub mod transport;

#[cfg(test)]
mod test_support;

pub use auth::McpAuthContext;
pub use error::McpError;
pub use executor::{McpTarget, McpToolExecutor, McpToolPermit};
pub use policy::{PolicyDecision, PolicyDeny, ToolName, ToolPolicy};
pub use rate_limit::McpRateLimiter;
pub use server::IssuerdMcpServer;
