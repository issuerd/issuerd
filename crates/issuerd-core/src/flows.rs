// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Built-in authentication flow constructors shared by storage seeding and the server.

//! Built-in authentication flow constructors.
//!
//! Moved verbatim from `issuerd-server::state` so every crate shares
//! the same definitions: the storage layer seeds them on realm creation
//! (`issuerd-storage::seed`), the server bootstrap registers them, and the admin
//! API lists them.

use crate::ids::{FlowStageId, RealmId};
use crate::models::{Alias, FlowConfig, FlowStage, Requirement};

/// Default browser login flow: cookie → SPNEGO → IdP redirect →
/// username/password, then a conditional second factor (OTP, then WebAuthn).
pub fn default_browser_flow(realm_id: RealmId) -> FlowConfig {
    FlowConfig {
        alias: Alias::new("browser").unwrap(),
        realm_id,
        provider_id: "basic-flow".to_string(),
        top_level: true,
        built_in: true,
        stages: vec![
            FlowStage {
                id: FlowStageId::new("cookie-auth").unwrap(),
                requirement: Requirement::Alternative,
                authenticator: Alias::new("auth-cookie").unwrap(),
                priority: 1,
                sub_flow_alias: None,
                authenticator_config: None,
            },
            FlowStage {
                id: FlowStageId::new("auth-spnego").unwrap(),
                requirement: Requirement::Alternative,
                authenticator: Alias::new("auth-spnego").unwrap(),
                priority: 2,
                sub_flow_alias: None,
                authenticator_config: None,
            },
            // Identity brokering: with a `kc_idp_hint` on the
            // authorization request this stage challenges with a realm-relative
            // `/broker/{alias}/login` redirect that the HTTP layer anchors and
            // forwards to. Without a hint it is Attempted and the group falls
            // through to the login form. Placed after cookie/SPNEGO so an
            // existing SSO session still wins over the hint (Keycloak order).
            FlowStage {
                id: FlowStageId::new("idp-redirect").unwrap(),
                requirement: Requirement::Alternative,
                authenticator: Alias::new("auth-idp-redirect").unwrap(),
                priority: 3,
                sub_flow_alias: None,
                authenticator_config: None,
            },
            FlowStage {
                id: FlowStageId::new("username-password").unwrap(),
                requirement: Requirement::Alternative,
                authenticator: Alias::new("auth-username-password").unwrap(),
                priority: 4,
                sub_flow_alias: None,
                authenticator_config: None,
            },
            // Conditional second factor: the condition succeeds
            // only when the authenticated user has a TOTP credential or a
            // WebAuthn passkey, in which case the OTP/WebAuthn stages run. When
            // the condition is Attempted (no credential), the executor's
            // conditional semantics skip every immediately-following
            // Conditional stage, so password-only logins are unchanged.
            FlowStage {
                id: FlowStageId::new("conditional-user-configured").unwrap(),
                requirement: Requirement::Conditional,
                authenticator: Alias::new("conditional-user-configured").unwrap(),
                priority: 5,
                sub_flow_alias: None,
                authenticator_config: None,
            },
            FlowStage {
                id: FlowStageId::new("auth-otp-form").unwrap(),
                requirement: Requirement::Conditional,
                authenticator: Alias::new("auth-otp-form").unwrap(),
                priority: 6,
                sub_flow_alias: None,
                authenticator_config: None,
            },
            // WebAuthn runs after the OTP stage: users with only a passkey are
            // challenged here; users with both factors satisfy the second
            // factor via OTP first, which sets the `second_factor_ok` marker
            // that makes this stage pass through.
            //
            // The requirement is OPTIONAL, not Conditional: the executor
            // treats an Attempted/Failure at a Conditional stage as "skip the
            // following Conditional scope", so a passkey-only user (OTP stage
            // Attempted) would have this stage skipped and log in WITHOUT a
            // second factor. Optional stages are not scope-skipped, and the
            // stage itself is a no-op (Attempted) for users without passkeys,
            // so password-only logins are unchanged. The stage converts every
            // user-facing failure into a re-challenge internally; like at a
            // Conditional stage, a genuine infra Failure is swallowed by the
            // executor — see the authenticator's contract docs.
            FlowStage {
                id: FlowStageId::new("auth-webauthn").unwrap(),
                requirement: Requirement::Optional,
                authenticator: Alias::new("auth-webauthn").unwrap(),
                priority: 7,
                sub_flow_alias: None,
                authenticator_config: None,
            },
        ],
    }
}

/// Flat single-stage self-registration flow.
///
/// Deliberately not a "profile form → password form → verify-email" chain as
/// sketched in the plan: the one `RegistrationAuthenticator` stage validates
/// the whole form and creates the account; verify-email rides the
/// required-action machinery. See the authenticator's docs for the rationale.
pub fn registration_flow(realm_id: RealmId) -> FlowConfig {
    FlowConfig {
        alias: Alias::new("registration").unwrap(),
        realm_id,
        provider_id: "basic-flow".to_string(),
        top_level: true,
        built_in: true,
        stages: vec![FlowStage {
            id: FlowStageId::new("registration").unwrap(),
            requirement: Requirement::Required,
            authenticator: Alias::new("auth-registration").unwrap(),
            priority: 1,
            sub_flow_alias: None,
            authenticator_config: None,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_browser_flow_structure() {
        let flow = default_browser_flow(RealmId::new("test").unwrap());
        assert_eq!(flow.alias, Alias::new("browser").unwrap());
        assert_eq!(flow.stages.len(), 7);
        assert!(flow.stages.iter().all(|s| s.authenticator_config.is_none()));
    }

    #[test]
    fn registration_flow_structure() {
        let flow = registration_flow(RealmId::new("test").unwrap());
        assert_eq!(flow.alias, Alias::new("registration").unwrap());
        assert_eq!(flow.stages.len(), 1);
        assert_eq!(flow.stages[0].requirement, Requirement::Required);
    }

    #[test]
    fn flows_roundtrip_through_json() {
        for flow in [
            default_browser_flow(RealmId::new("test").unwrap()),
            registration_flow(RealmId::new("test").unwrap()),
        ] {
            let json = serde_json::to_string(&flow).unwrap();
            let back: FlowConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(flow, back);
        }
    }
}
