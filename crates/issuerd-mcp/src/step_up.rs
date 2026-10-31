// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Typed operation coordination and versioned canonical operation hashes.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use issuerd_core::{
    ClientIdentifier, McpStepUpExecutionStatus, McpStepUpGrant, McpStepUpMutation, RealmId, UserId,
};
use rmcp::model::JsonObject;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{auth::McpAuthContext, error::McpError, policy::ToolName};

pub const CANONICALIZATION_VERSION: u32 = 1;
pub const DEFAULT_OPERATION_TTL_SECS: u64 = 300;
pub const DEFAULT_GRANT_TTL_SECS: u64 = 120;
pub const DEFAULT_APPROVAL_MAX_AUTH_AGE_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingOperation {
    pub version: u32,
    pub operation_id: String,
    pub canonicalization_version: u32,
    pub realm_id: RealmId,
    pub client_id: ClientIdentifier,
    pub subject_user_id: UserId,
    pub resource: String,
    pub tool: ToolName,
    pub canonical_args_json: Value,
    pub operation_hash: String,
    pub binding_message: String,
    pub mutation: McpStepUpMutation,
    pub origin_access_token_jti: String,
    pub origin_dpop_jkt: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Serialize)]
struct CanonicalOperation<'a> {
    canonicalization_version: u32,
    tool: &'static str,
    arguments: Value,
    mutation: &'a McpStepUpMutation,
}

impl PendingOperation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth: &McpAuthContext,
        resource: String,
        tool: ToolName,
        canonical_args_json: Value,
        mutation: McpStepUpMutation,
        origin_dpop_jkt: String,
        now: i64,
        ttl_secs: u64,
    ) -> Result<Self, McpError> {
        let operation_hash = operation_hash(tool, &canonical_args_json, &mutation)?;
        let binding_message = format!("Approve {}: {}", tool.as_str(), mutation.target_id());
        validate_binding_message(&binding_message)?;
        Ok(Self {
            version: 1,
            operation_id: secure_id(),
            canonicalization_version: CANONICALIZATION_VERSION,
            realm_id: auth.realm_id.clone(),
            client_id: auth.azp.clone(),
            subject_user_id: auth.user_id.clone(),
            resource,
            tool,
            canonical_args_json: canonicalize(canonical_args_json),
            operation_hash,
            binding_message,
            mutation: mutation.redacted(),
            origin_access_token_jti: auth.claims.jti.to_string(),
            origin_dpop_jkt,
            created_at: now,
            expires_at: now.saturating_add(i64::try_from(ttl_secs).unwrap_or(i64::MAX)),
        })
    }

    pub fn for_execution(
        auth: &McpAuthContext,
        resource: String,
        tool: ToolName,
        canonical_args_json: Value,
        _mutation: McpStepUpMutation,
        grant: &McpStepUpGrant,
    ) -> Result<Self, McpError> {
        let mut operation = Self::new(
            auth,
            resource,
            tool,
            canonical_args_json,
            grant.mutation.clone(),
            grant.dpop_jkt.clone(),
            grant.issued_at,
            u64::try_from(grant.expires_at.saturating_sub(grant.issued_at).max(0))
                .unwrap_or(u64::MAX),
        )?;
        operation.operation_id = grant.operation_id.clone();
        operation.origin_access_token_jti = grant.origin_access_token_jti.clone();
        Ok(operation)
    }

    pub fn arguments(&self) -> Result<Option<JsonObject>, McpError> {
        self.canonical_args_json
            .as_object()
            .cloned()
            .map(Some)
            .ok_or_else(|| McpError::InvalidInput("operation arguments must be an object".into()))
    }

    pub fn validate_binding(&self, operation: &PendingOperation) -> bool {
        self.operation_hash == operation.operation_hash
            && self.canonicalization_version == operation.canonicalization_version
            && self.realm_id == operation.realm_id
            && self.client_id == operation.client_id
            && self.subject_user_id == operation.subject_user_id
            && self.resource == operation.resource
            && self.tool == operation.tool
            && self.canonical_args_json == operation.canonical_args_json
            && self.mutation == operation.mutation
            && self.origin_access_token_jti == operation.origin_access_token_jti
            && self.origin_dpop_jkt == operation.origin_dpop_jkt
            && self.created_at == operation.created_at
            && self.expires_at == operation.expires_at
    }
}

pub fn operation_hash(
    tool: ToolName,
    arguments: &Value,
    mutation: &McpStepUpMutation,
) -> Result<String, McpError> {
    let redacted = mutation.redacted();
    let canonical = CanonicalOperation {
        canonicalization_version: CANONICALIZATION_VERSION,
        tool: tool.as_str(),
        arguments: canonicalize(arguments.clone()),
        mutation: &redacted,
    };
    let bytes = serde_json::to_vec(&canonical).map_err(|error| {
        McpError::Backend(issuerd_core::IssuerdError::ServerError(format!(
            "operation canonicalization failed: {error}"
        )))
    })?;
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(encoded)
}

pub fn validate_binding_message(message: &str) -> Result<(), McpError> {
    if message.is_empty()
        || message.chars().count() > 100
        || message.chars().any(char::is_control)
        || message.trim() != message
    {
        return Err(McpError::InvalidInput(
            "binding_message must be 1..=100 Unicode scalar values of plain text without controls"
                .into(),
        ));
    }
    Ok(())
}

pub fn secure_id() -> String {
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn verify_grant(
    auth: &McpAuthContext,
    grant: &McpStepUpGrant,
    operation: &PendingOperation,
    dpop_jkt: &str,
    now: i64,
) -> Result<(), McpError> {
    if grant.canonicalization_version != CANONICALIZATION_VERSION
        || grant.operation_id != operation.operation_id
        || grant.operation_hash
            != operation_hash(operation.tool, &operation.canonical_args_json, &operation.mutation)?
        || grant.realm_id != auth.realm_id
        || grant.client_id != auth.azp
        || grant.subject_user_id != auth.user_id
        || grant.resource != operation.resource
        || grant.tool != operation.tool.as_str()
        || grant.mutation != operation.mutation.redacted()
        || grant.origin_access_token_jti != operation.origin_access_token_jti
        || grant.token_jti != auth.claims.jti
        || grant.dpop_jkt != dpop_jkt
        || grant.dpop_jkt != operation.origin_dpop_jkt
        || grant.approval_auth_time > now
        || now.saturating_sub(grant.approval_auth_time)
            > i64::try_from(DEFAULT_APPROVAL_MAX_AUTH_AGE_SECS).unwrap_or(i64::MAX)
    {
        return Err(McpError::OperationBindingMismatch);
    }
    if grant.status == McpStepUpExecutionStatus::OutcomeUnknown {
        return Err(McpError::OutcomeUnknown);
    }
    if grant.status == McpStepUpExecutionStatus::Active && grant.expires_at <= now {
        return Err(McpError::GrantExpired);
    }
    if grant.status == McpStepUpExecutionStatus::FailedDefinite {
        return Err(McpError::Conflict("step-up target preconditions changed"));
    }
    Ok(())
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<serde_json::Map<_, _>>()
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use issuerd_core::{Realm, RealmName, UserId};
    use serde_json::json;

    use super::*;
    use crate::test_support::auth;

    #[test]
    fn identifiers_are_256_bit_base64url_and_unique() {
        let values: BTreeSet<_> = (0..100).map(|_| secure_id()).collect();
        assert_eq!(values.len(), 100);
        for value in values {
            assert_eq!(value.len(), 43);
            assert_eq!(URL_SAFE_NO_PAD.decode(value).unwrap().len(), 32);
        }
    }

    #[test]
    fn hash_sorts_nested_objects_preserves_arrays_and_covers_exact_mutation() {
        let mutation = McpStepUpMutation::DeleteRealm {
            expected: Realm::default(),
        };
        let first = operation_hash(
            ToolName::RealmDelete,
            &json!({"confirmation":"master","nested":{"z":1,"a":[2,1]}}),
            &mutation,
        )
        .unwrap();
        let reordered = operation_hash(
            ToolName::RealmDelete,
            &json!({"nested":{"a":[2,1],"z":1},"confirmation":"master"}),
            &mutation,
        )
        .unwrap();
        assert_eq!(first, reordered);
        assert_ne!(
            first,
            operation_hash(
                ToolName::RealmDelete,
                &json!({"confirmation":"master","nested":{"a":[1,2],"z":1}}),
                &mutation,
            )
            .unwrap()
        );
        assert_ne!(first, operation_hash(ToolName::UsersDelete, &json!({}), &mutation).unwrap());
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn pending_operation_recomputes_typed_arguments_and_binding() {
        let context = auth("openid mcp:write", &["manage-realm"]);
        let operation = PendingOperation::new(
            &context,
            "https://issuer.example/realms/demo/mcp".into(),
            ToolName::RealmDelete,
            json!({"confirmation":"demo"}),
            McpStepUpMutation::DeleteRealm {
                expected: Realm {
                    name: RealmName::new("demo").unwrap(),
                    ..Realm::default()
                },
            },
            "proof-key".into(),
            100,
            300,
        )
        .unwrap();
        assert_eq!(operation.arguments().unwrap().unwrap()["confirmation"], "demo");
        assert_eq!(operation.expires_at, 400);
        assert!(operation.validate_binding(&operation.clone()));
        let mut edited = operation.clone();
        edited.canonical_args_json["confirmation"] = json!("other");
        assert!(!operation.validate_binding(&edited));
        let _ = UserId::new("unused").unwrap();
    }

    #[test]
    fn binding_message_uses_unicode_scalar_limit_and_rejects_controls() {
        assert!(validate_binding_message(&"é".repeat(100)).is_ok());
        for message in [
            "",
            " leading",
            "trailing ",
            "line\nfeed",
            "zero\u{200b}width",
        ] {
            if message.contains('\u{200b}') {
                assert!(validate_binding_message(message).is_ok());
            } else {
                assert!(validate_binding_message(message).is_err());
            }
        }
        assert!(validate_binding_message(&"é".repeat(101)).is_err());
    }
}
