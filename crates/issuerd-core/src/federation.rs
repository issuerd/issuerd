// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// User federation SPI: provider types/config, FederationManager, and sync result models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::DisplayName;
use std::sync::Arc;

use crate::error::IssuerdError;
use crate::ids::RealmId;
use crate::models::Alias;

/// Type of external federation provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationProviderType {
    Ldap,
    Kerberos,
}

/// Edit mode for a federation provider — controls whether writes are
/// propagated back to the external directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditMode {
    ReadOnly,
    Writable,
    Unsynced,
}

/// Realm-level configuration for a federation provider instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationProviderConfig {
    pub id: String,
    pub realm_id: RealmId,
    pub alias: Alias,
    pub provider_type: FederationProviderType,
    pub enabled: bool,
    pub priority: i32,
    pub import_enabled: bool,
    pub edit_mode: EditMode,
    pub config: HashMap<String, String>,
}

/// A user record produced by a federation provider before it is (optionally)
/// imported into local `Storage`.
#[derive(Debug, Clone, Default)]
pub struct FederatedUser {
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub first_name: Option<DisplayName>,
    pub last_name: Option<DisplayName>,
    pub enabled: bool,
    pub attributes: HashMap<String, Vec<String>>,
    pub federation_link: String,
    pub external_id: Option<String>,
    /// External group names the user belongs to (e.g. extracted from the
    /// LDAP `memberOf` attribute by a group mapper). `None` means the
    /// provider does not report group memberships at all — callers must
    /// leave local memberships untouched (distinct from `Some(vec![])`,
    /// which authoritatively means "member of nothing").
    pub groups: Option<Vec<String>>,
}

/// Result of a user synchronisation run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncResult {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub failed: usize,
    pub last_sync: DateTime<Utc>,
}

/// Status of a single SPNEGO authentication step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpnegoStatus {
    Authenticated,
    Continue,
    Failed,
}

/// Result of a SPNEGO `authenticate_spnego` call.
#[derive(Debug, Clone)]
pub struct SpnegoAuthResult {
    pub principal: Option<String>,
    pub response_token: Option<String>,
    pub status: SpnegoStatus,
}

/// Errors produced by the federation layer.
///
/// These are kept separate from `IssuerdError` so that the federation crate can
/// reason about retry / circuit-breaker behaviour without leaking internal
/// details to the rest of the workspace.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FederationError {
    #[error("provider unavailable: {0}")]
    ProviderUnavailable(String),
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("user not found")]
    UserNotFound,
    #[error("operation not supported")]
    NotSupported,
    #[error("schema mismatch: {0}")]
    SchemaMismatch(String),
    #[error("network error: {0}")]
    NetworkError(String),
    #[error("configuration error: {0}")]
    ConfigError(String),
}

/// Capability-based trait for external user directories.
///
/// Default implementations return `FederationError::NotSupported` so that
/// concrete providers only need to implement the capabilities they actually
/// provide.  The trait is object-safe (`Arc<dyn FederationProvider>`).
#[async_trait::async_trait]
pub trait FederationProvider: Send + Sync {
    fn id(&self) -> &str;
    fn provider_type(&self) -> FederationProviderType;

    /// Look up a user by username in the external directory.
    async fn find_user(&self, username: &str) -> Result<Option<FederatedUser>, FederationError>;

    /// Look up a user by email.
    async fn find_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<FederatedUser>, FederationError>;

    /// Validate a password against the external directory.
    /// Returns `Ok(true)` on success, `Ok(false)` on bad password, `Err` on
    /// system failure.
    async fn validate_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<bool, FederationError>;

    /// Update the user's password in the external directory.
    /// Default: `NotSupported`.
    async fn update_password(
        &self,
        _username: &str,
        _password: &str,
    ) -> Result<(), FederationError> {
        Err(FederationError::NotSupported)
    }

    /// Whether `update_password` can actually write to the external directory
    /// (i.e. it will not return `NotSupported`). Drives UI/API decisions about
    /// offering password changes for federated users. Default: `false`.
    fn supports_password_update(&self) -> bool {
        false
    }

    /// Validate that an imported local user still exists in the external directory.
    /// Default: delegates to `find_user`.
    async fn validate_imported_user(
        &self,
        username: &str,
    ) -> Result<Option<FederatedUser>, FederationError> {
        self.find_user(username).await
    }

    /// Synchronise all users from the external directory.
    /// Default: `NotSupported`.
    async fn sync_users(&self) -> Result<SyncResult, FederationError> {
        Err(FederationError::NotSupported)
    }

    /// Incremental sync since a given timestamp.
    /// Default: `NotSupported`.
    async fn sync_users_since(&self, _since: DateTime<Utc>) -> Result<SyncResult, FederationError> {
        Err(FederationError::NotSupported)
    }

    /// Accept a SPNEGO token and return the authentication result.
    /// Default: `NotSupported`.
    async fn authenticate_spnego(&self, _token: &str) -> Result<SpnegoAuthResult, FederationError> {
        Err(FederationError::NotSupported)
    }

    /// Stream all users from the external directory.
    /// Default: `NotSupported`.
    async fn stream_users(&self) -> Result<Vec<FederatedUser>, FederationError> {
        Err(FederationError::NotSupported)
    }
}

/// High-level manager that resolves federation providers for a realm and
/// orchestrates cross-provider lookups.
#[async_trait::async_trait]
pub trait FederationManager: Send + Sync {
    /// Return providers for a realm sorted by priority (highest first).
    async fn providers_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<Arc<dyn FederationProvider>>, IssuerdError>;

    /// Find a user across all federation providers for a realm.
    /// Stops at the first provider that returns a user.
    async fn find_user(
        &self,
        realm_id: &RealmId,
        username: &str,
    ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, IssuerdError>;

    /// Same, but by email.
    async fn find_user_by_email(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<Option<(Arc<dyn FederationProvider>, FederatedUser)>, IssuerdError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federated_user_default_enabled() {
        let u = FederatedUser::default();
        assert!(!u.enabled); // Default bool is false
    }

    #[test]
    fn sync_result_aggregation() {
        let r = SyncResult {
            added: 1,
            updated: 2,
            removed: 3,
            failed: 4,
            last_sync: Utc::now(),
        };
        assert_eq!(r.added + r.updated + r.removed + r.failed, 10);
    }

    #[test]
    fn federation_error_display() {
        let cases = vec![
            (
                FederationError::ProviderUnavailable("down".into()),
                "provider unavailable: down",
            ),
            (FederationError::InvalidCredentials, "invalid credentials"),
            (FederationError::UserNotFound, "user not found"),
            (FederationError::NotSupported, "operation not supported"),
            (
                FederationError::SchemaMismatch("missing mail".into()),
                "schema mismatch: missing mail",
            ),
            (FederationError::NetworkError("timeout".into()), "network error: timeout"),
            (FederationError::ConfigError("bad url".into()), "configuration error: bad url"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn edit_mode_roundtrip() {
        for mode in [EditMode::ReadOnly, EditMode::Writable, EditMode::Unsynced] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: EditMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn federation_provider_type_roundtrip() {
        for ty in [
            FederationProviderType::Ldap,
            FederationProviderType::Kerberos,
        ] {
            let json = serde_json::to_string(&ty).unwrap();
            let back: FederationProviderType = serde_json::from_str(&json).unwrap();
            assert_eq!(ty, back);
        }
    }

    #[test]
    fn federation_provider_trait_object_safe() {
        let _: Option<Arc<dyn FederationProvider>> = None;
    }

    #[test]
    fn federation_manager_trait_object_safe() {
        let _: Option<Arc<dyn FederationManager>> = None;
    }

    // A minimal mock provider that implements only the required methods.
    struct MockProvider;

    #[async_trait::async_trait]
    impl FederationProvider for MockProvider {
        fn id(&self) -> &str {
            "mock"
        }
        fn provider_type(&self) -> FederationProviderType {
            FederationProviderType::Ldap
        }
        async fn find_user(
            &self,
            _username: &str,
        ) -> Result<Option<FederatedUser>, FederationError> {
            Ok(None)
        }
        async fn find_user_by_email(
            &self,
            _email: &str,
        ) -> Result<Option<FederatedUser>, FederationError> {
            Ok(None)
        }
        async fn validate_password(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<bool, FederationError> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn default_update_password_returns_not_supported() {
        let provider = MockProvider;
        let result = provider.update_password("alice", "secret").await;
        assert_eq!(result.unwrap_err(), FederationError::NotSupported);
    }

    #[tokio::test]
    async fn default_validate_imported_user_delegates_to_find_user() {
        let provider = MockProvider;
        let result = provider.validate_imported_user("alice").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn default_sync_users_returns_not_supported() {
        let provider = MockProvider;
        let result = provider.sync_users().await;
        assert_eq!(result.unwrap_err(), FederationError::NotSupported);
    }

    #[tokio::test]
    async fn default_sync_users_since_returns_not_supported() {
        let provider = MockProvider;
        let result = provider.sync_users_since(Utc::now()).await;
        assert_eq!(result.unwrap_err(), FederationError::NotSupported);
    }

    #[tokio::test]
    async fn default_authenticate_spnego_returns_not_supported() {
        let provider = MockProvider;
        let result = provider.authenticate_spnego("token").await;
        assert_eq!(result.unwrap_err(), FederationError::NotSupported);
    }

    #[tokio::test]
    async fn default_stream_users_returns_not_supported() {
        let provider = MockProvider;
        let result = provider.stream_users().await;
        assert_eq!(result.unwrap_err(), FederationError::NotSupported);
    }
}
