// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Plugin registry trait resolving authenticators and required actions at runtime.

use std::sync::Arc;

use async_trait::async_trait;
use issuerd_core::{Authenticator, IssuerdError, RequiredAction};

#[async_trait]
pub trait PluginRegistry: Send + Sync {
    async fn get_authenticator(
        &self,
        id: &str,
    ) -> Result<Option<Arc<dyn Authenticator>>, IssuerdError>;
    async fn get_required_action(
        &self,
        id: &str,
    ) -> Result<Option<Arc<dyn RequiredAction>>, IssuerdError>;
    fn list_authenticator_ids(&self) -> Vec<String>;
    fn list_required_action_ids(&self) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time object-safety check
    #[test]
    fn plugin_registry_is_object_safe() {
        let _: Option<Box<dyn PluginRegistry>> = None;
    }
}
