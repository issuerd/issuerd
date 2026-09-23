// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Built-in SAML identity provider stub.

use async_trait::async_trait;
use issuerd_core::{AuthContext, AuthStepResult, IdentityProvider as IdP};

/// Built-in SAML identity provider.
pub struct SamlIdentityProvider;

#[async_trait]
impl IdP for SamlIdentityProvider {
    fn id(&self) -> &str {
        "saml"
    }

    async fn authenticate(&self, _context: &mut AuthContext) -> AuthStepResult {
        AuthStepResult::Attempted
    }
}
