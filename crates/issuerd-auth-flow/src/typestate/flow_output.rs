// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Typed output of flow execution: authenticated success, paused-for-challenge, or failure.

use issuerd_core::typestate::{
    ActionsPending, AuthenticatedState, ChallengeKind, TypedAuthContext, TypedFlowResult,
};
use issuerd_core::{Challenge, FlowStageId, IssuerdError};
use std::marker::PhantomData;

/// Output of a typed flow execution.
#[derive(Debug, Clone)]
pub enum FlowOutput {
    /// Flow completed successfully — user is authenticated.
    Success {
        ctx: Box<TypedAuthContext<AuthenticatedState>>,
        result: Box<TypedFlowResult<ActionsPending>>,
    },
    /// Flow paused for a challenge.
    Challenge { paused: ErasedPausedFlow },
    /// Flow failed.
    Failure(IssuerdError),
}

/// A kind-erased paused flow handle.
///
/// The concrete challenge kind can be recovered via `downcast`.
#[derive(Debug, Clone)]
pub struct ErasedPausedFlow {
    execution_id: FlowStageId,
    challenge: Challenge,
    user_id: Option<issuerd_core::UserId>,
}

impl ErasedPausedFlow {
    /// Create a new erased paused flow.
    pub fn new(execution_id: FlowStageId, challenge: Challenge) -> Self {
        Self {
            execution_id,
            challenge,
            user_id: None,
        }
    }

    /// Attach the user id held by the paused flow's context, if the flow had
    /// already authenticated the user when the challenge was issued (e.g. the
    /// OTP second-factor stage runs after a successful password check).
    pub fn with_user_id(mut self, user_id: Option<issuerd_core::UserId>) -> Self {
        self.user_id = user_id;
        self
    }

    /// The execution ID that must be resumed.
    pub fn execution_id(&self) -> &FlowStageId {
        &self.execution_id
    }

    /// The untyped challenge.
    pub fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// The user id of the paused flow's context, when already authenticated.
    pub fn user_id(&self) -> Option<&issuerd_core::UserId> {
        self.user_id.as_ref()
    }

    /// Try to recover a typed challenge of the expected kind.
    pub fn downcast<K: ChallengeKind + 'static>(&self) -> Option<TypedPausedFlow<K>> {
        match &self.challenge {
            Challenge::LoginForm { .. }
                if std::any::TypeId::of::<K>()
                    == std::any::TypeId::of::<issuerd_core::typestate::LoginFormKind>() => {}
            Challenge::OtpForm { .. }
                if std::any::TypeId::of::<K>()
                    == std::any::TypeId::of::<issuerd_core::typestate::OtpFormKind>() => {}
            Challenge::WebAuthn { .. }
                if std::any::TypeId::of::<K>()
                    == std::any::TypeId::of::<issuerd_core::typestate::WebAuthnKind>() => {}
            Challenge::Redirect { .. }
                if std::any::TypeId::of::<K>()
                    == std::any::TypeId::of::<issuerd_core::typestate::RedirectKind>() => {}
            Challenge::Cookie
                if std::any::TypeId::of::<K>()
                    == std::any::TypeId::of::<issuerd_core::typestate::CookieKind>() => {}
            _ => return None,
        }
        Some(TypedPausedFlow {
            execution_id: self.execution_id.clone(),
            _kind: PhantomData,
        })
    }
}

/// A paused flow with proven challenge kind.
#[derive(Debug, Clone)]
pub struct TypedPausedFlow<K: ChallengeKind> {
    execution_id: FlowStageId,
    _kind: PhantomData<fn() -> K>,
}

impl<K: ChallengeKind> TypedPausedFlow<K> {
    /// The execution ID that must be resumed.
    pub fn execution_id(&self) -> &FlowStageId {
        &self.execution_id
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::typestate::{
        CookieKind, LoginFormKind, OtpFormKind, RedirectKind, WebAuthnKind,
    };

    #[test]
    fn erased_paused_flow_new_and_accessors() {
        let eid = FlowStageId::new("stage-1").unwrap();
        let ch = Challenge::LoginForm {
            action_url: "/login".to_string(),
        };
        let paused = ErasedPausedFlow::new(eid.clone(), ch.clone());
        assert_eq!(paused.execution_id(), &eid);
        assert!(matches!(paused.challenge(), Challenge::LoginForm { .. }));
        assert!(paused.user_id().is_none());
    }

    #[test]
    fn erased_paused_flow_carries_user_id() {
        let uid = issuerd_core::UserId::new("alice").unwrap();
        let paused = ErasedPausedFlow::new(
            FlowStageId::new("s1").unwrap(),
            Challenge::OtpForm {
                action_url: "/otp".to_string(),
            },
        )
        .with_user_id(Some(uid.clone()));
        assert_eq!(paused.user_id(), Some(&uid));
    }

    #[test]
    fn downcast_login_form_succeeds() {
        let paused = ErasedPausedFlow::new(
            FlowStageId::new("s1").unwrap(),
            Challenge::LoginForm {
                action_url: "/login".to_string(),
            },
        );
        let typed = paused.downcast::<LoginFormKind>().unwrap();
        assert_eq!(typed.execution_id(), &FlowStageId::new("s1").unwrap());
    }

    #[test]
    fn downcast_otp_form_succeeds() {
        let paused = ErasedPausedFlow::new(
            FlowStageId::new("s1").unwrap(),
            Challenge::OtpForm {
                action_url: "/otp".to_string(),
            },
        );
        assert!(paused.downcast::<OtpFormKind>().is_some());
    }

    #[test]
    fn downcast_webauthn_succeeds() {
        let paused = ErasedPausedFlow::new(
            FlowStageId::new("s1").unwrap(),
            Challenge::WebAuthn {
                action_url: "/wa".to_string(),
                challenge: "c".to_string(),
            },
        );
        assert!(paused.downcast::<WebAuthnKind>().is_some());
    }

    #[test]
    fn downcast_redirect_succeeds() {
        let paused = ErasedPausedFlow::new(
            FlowStageId::new("s1").unwrap(),
            Challenge::Redirect {
                url: "https://example.com".to_string(),
            },
        );
        assert!(paused.downcast::<RedirectKind>().is_some());
    }

    #[test]
    fn downcast_cookie_succeeds() {
        let paused = ErasedPausedFlow::new(FlowStageId::new("s1").unwrap(), Challenge::Cookie);
        assert!(paused.downcast::<CookieKind>().is_some());
    }

    #[test]
    fn downcast_mismatch_returns_none() {
        let paused = ErasedPausedFlow::new(
            FlowStageId::new("s1").unwrap(),
            Challenge::LoginForm {
                action_url: "/login".to_string(),
            },
        );
        assert!(paused.downcast::<OtpFormKind>().is_none());
        assert!(paused.downcast::<WebAuthnKind>().is_none());
        assert!(paused.downcast::<RedirectKind>().is_none());
        assert!(paused.downcast::<CookieKind>().is_none());
    }

    #[test]
    fn downcast_all_mismatch_permutations() {
        // otp vs login
        let paused = ErasedPausedFlow::new(
            FlowStageId::new("s1").unwrap(),
            Challenge::OtpForm {
                action_url: "/otp".to_string(),
            },
        );
        assert!(paused.downcast::<LoginFormKind>().is_none());

        // webauthn vs login
        let paused = ErasedPausedFlow::new(
            FlowStageId::new("s1").unwrap(),
            Challenge::WebAuthn {
                action_url: "/wa".to_string(),
                challenge: "c".to_string(),
            },
        );
        assert!(paused.downcast::<LoginFormKind>().is_none());

        // redirect vs login
        let paused = ErasedPausedFlow::new(
            FlowStageId::new("s1").unwrap(),
            Challenge::Redirect {
                url: "https://example.com".to_string(),
            },
        );
        assert!(paused.downcast::<LoginFormKind>().is_none());

        // cookie vs login
        let paused = ErasedPausedFlow::new(FlowStageId::new("s1").unwrap(), Challenge::Cookie);
        assert!(paused.downcast::<LoginFormKind>().is_none());
    }
}
