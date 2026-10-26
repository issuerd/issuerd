// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use issuerd_core::IssuerdError;

use crate::policy::ToolName;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpError {
    #[error("unknown MCP tool: {0}")]
    UnknownTool(String),
    #[error("required scope: {0}")]
    MissingScope(&'static str),
    #[error("tool {tool} requires one of these realm roles: {roles:?}")]
    MissingRole {
        tool: ToolName,
        roles: &'static [&'static str],
    },
    #[error("MCP invocation rate limit exceeded")]
    RateLimited { retry_after_secs: u64 },
    #[error("temporarily unavailable: {0}")]
    TemporarilyUnavailable(&'static str),
    #[error("invalid tool input: {0}")]
    InvalidInput(String),
    #[error("{0} not found")]
    NotFound(&'static str),
    #[error("storage backend failure: {0}")]
    Backend(IssuerdError),
    #[error("missing MCP authentication context")]
    MissingAuthenticationContext,
    #[error("MCP preflight permit does not match the requested tool")]
    PermitMismatch,
    #[error("invalid MCP transport configuration: {0}")]
    TransportConfig(String),
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
}

impl McpError {
    pub fn is_temporary(&self) -> bool {
        match self {
            Self::TemporarilyUnavailable(_) => true,
            Self::Backend(error) => matches!(error, IssuerdError::TemporarilyUnavailable),
            _ => false,
        }
    }

    pub fn public_tool_message(&self) -> String {
        match self {
            Self::UnknownTool(name) => format!("unknown tool: {name}"),
            Self::MissingScope(scope) => format!("required scope: {scope}"),
            Self::MissingRole { roles, .. } => {
                format!("required realm role: one of {}", roles.join(", "))
            }
            Self::RateLimited { .. } => "invocation rate limit exceeded".to_string(),
            Self::TemporarilyUnavailable(_) => "service temporarily unavailable".to_string(),
            Self::InvalidInput(message) => format!("invalid tool input: {message}"),
            Self::NotFound(entity) => format!("{entity} not found"),
            Self::Backend(_) if self.is_temporary() => {
                "storage backend temporarily unavailable".to_string()
            }
            Self::Backend(_) => "storage backend failure".to_string(),
            Self::MissingAuthenticationContext => "missing authentication context".to_string(),
            Self::PermitMismatch => "invalid preflight permit".to_string(),
            Self::TransportConfig(_) => "transport configuration failure".to_string(),
            Self::InvalidJson(message) => format!("invalid JSON: {message}"),
        }
    }
}

impl From<IssuerdError> for McpError {
    fn from(error: IssuerdError) -> Self {
        Self::Backend(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_backend_errors_stay_typed_without_leaking_details() {
        let temporary = McpError::Backend(IssuerdError::TemporarilyUnavailable);
        assert!(temporary.is_temporary());
        assert_eq!(temporary.public_tool_message(), "storage backend temporarily unavailable");

        let permanent = McpError::Backend(IssuerdError::ServerError("private SQL".into()));
        assert!(!permanent.is_temporary());
        assert_eq!(permanent.public_tool_message(), "storage backend failure");
        assert!(!permanent.public_tool_message().contains("private SQL"));
    }
}
