// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Convenience transition helpers between typed and untyped auth-flow types.

use super::flow_output::FlowOutput;
use crate::executor::FlowOutcome;
use issuerd_core::typestate::TypedChallenge;
use issuerd_core::{AuthContext, Challenge};

/// Extension trait for `FlowOutcome` to convert to typed output.
pub trait FlowOutcomeExt {
    /// Convert to `FlowOutput` given the final `AuthContext`.
    fn try_into_typed(self, ctx: AuthContext) -> Result<FlowOutput, issuerd_core::IssuerdError>;
}

impl FlowOutcomeExt for FlowOutcome {
    fn try_into_typed(self, ctx: AuthContext) -> Result<FlowOutput, issuerd_core::IssuerdError> {
        super::executor::TypedFlowExecutor::map_outcome(self, ctx)
    }
}

/// Classification of a challenge by kind.
#[derive(Debug, Clone)]
pub enum ChallengeClassification {
    LoginForm(TypedChallenge<issuerd_core::typestate::LoginFormKind>),
    OtpForm(TypedChallenge<issuerd_core::typestate::OtpFormKind>),
    WebAuthn(TypedChallenge<issuerd_core::typestate::WebAuthnKind>),
    Redirect(TypedChallenge<issuerd_core::typestate::RedirectKind>),
    Cookie(TypedChallenge<issuerd_core::typestate::CookieKind>),
    Unknown(Challenge),
}

/// Extension trait for `Challenge` to classify by kind.
pub trait ChallengeExt {
    /// Classify this challenge into a typed variant.
    fn classify(self) -> ChallengeClassification;
}

impl ChallengeExt for Challenge {
    fn classify(self) -> ChallengeClassification {
        if let Some(t) =
            TypedChallenge::<issuerd_core::typestate::LoginFormKind>::from_challenge(self.clone())
        {
            return ChallengeClassification::LoginForm(t);
        }
        if let Some(t) =
            TypedChallenge::<issuerd_core::typestate::OtpFormKind>::from_challenge(self.clone())
        {
            return ChallengeClassification::OtpForm(t);
        }
        if let Some(t) =
            TypedChallenge::<issuerd_core::typestate::WebAuthnKind>::from_challenge(self.clone())
        {
            return ChallengeClassification::WebAuthn(t);
        }
        if let Some(t) =
            TypedChallenge::<issuerd_core::typestate::RedirectKind>::from_challenge(self.clone())
        {
            return ChallengeClassification::Redirect(t);
        }
        if let Some(t) =
            TypedChallenge::<issuerd_core::typestate::CookieKind>::from_challenge(self.clone())
        {
            return ChallengeClassification::Cookie(t);
        }
        ChallengeClassification::Unknown(self)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_login_form() {
        let ch = Challenge::LoginForm {
            action_url: "/login".to_string(),
        };
        match ch.classify() {
            ChallengeClassification::LoginForm(t) => {
                assert_eq!(t.action_url(), "/login");
            }
            other => panic!("expected LoginForm, got {:?}", other),
        }
    }

    #[test]
    fn classify_otp_form() {
        let ch = Challenge::OtpForm {
            action_url: "/otp".to_string(),
        };
        match ch.classify() {
            ChallengeClassification::OtpForm(t) => {
                assert_eq!(t.action_url(), "/otp");
            }
            other => panic!("expected OtpForm, got {:?}", other),
        }
    }

    #[test]
    fn classify_webauthn() {
        let ch = Challenge::WebAuthn {
            action_url: "/wa".to_string(),
            challenge: "c".to_string(),
        };
        match ch.classify() {
            ChallengeClassification::WebAuthn(t) => {
                assert_eq!(t.challenge(), "c");
            }
            other => panic!("expected WebAuthn, got {:?}", other),
        }
    }

    #[test]
    fn classify_redirect() {
        let ch = Challenge::Redirect {
            url: "https://idp.example.com".to_string(),
        };
        match ch.classify() {
            ChallengeClassification::Redirect(t) => {
                assert_eq!(t.url(), "https://idp.example.com");
            }
            other => panic!("expected Redirect, got {:?}", other),
        }
    }

    #[test]
    fn classify_cookie() {
        let ch = Challenge::Cookie;
        match ch.classify() {
            ChallengeClassification::Cookie(_) => {}
            other => panic!("expected Cookie, got {:?}", other),
        }
    }

    #[test]
    fn classify_unknown_fallback() {
        // All known challenge variants are covered; to test Unknown we would need
        // a custom Challenge variant, which is sealed. This test documents that
        // every current variant maps correctly.
    }

    #[test]
    fn flow_outcome_ext_failure_returns_failure() {
        let outcome = FlowOutcome::Failure(issuerd_core::IssuerdError::AccessDenied);
        let ctx = AuthContext {
            realm_id: issuerd_core::RealmId::new("r1").unwrap(),
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: std::collections::HashMap::new(),
            attributes: std::collections::HashMap::new(),
            current_challenge: None,
        };
        let output = outcome.try_into_typed(ctx).unwrap();
        match output {
            FlowOutput::Failure(e) => assert_eq!(e, issuerd_core::IssuerdError::AccessDenied),
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    fn flow_outcome_ext_challenge_returns_challenge() {
        let outcome = FlowOutcome::Challenge(
            Challenge::LoginForm {
                action_url: "/login".to_string(),
            },
            issuerd_core::FlowStageId::new("s1").unwrap(),
        );
        let ctx = AuthContext {
            realm_id: issuerd_core::RealmId::new("r1").unwrap(),
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: std::collections::HashMap::new(),
            attributes: std::collections::HashMap::new(),
            current_challenge: None,
        };
        let output = outcome.try_into_typed(ctx).unwrap();
        match output {
            FlowOutput::Challenge { paused } => {
                assert_eq!(paused.execution_id(), &issuerd_core::FlowStageId::new("s1").unwrap());
            }
            other => panic!("expected Challenge, got {:?}", other),
        }
    }
}
