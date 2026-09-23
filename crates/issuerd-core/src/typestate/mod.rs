// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Typestate FSM foundation for authentication and session lifecycle.
//!
//! This module provides sealed traits and zero-sized marker types that encode
//! state at the type level. Invalid transitions become compile-time errors.

mod action_state;
mod auth_context;
mod auth_guard;
mod auth_state;
mod challenge;
mod challenge_kind;
mod flow_result;
mod realm_bound;
mod redirect;
mod session;
mod session_state;

pub use action_state::{ActionState, ActionsCleared, ActionsPending};
pub use auth_context::TypedAuthContext;
pub use auth_guard::AccountSessionGuard;
pub use auth_state::{AnonymousState, AuthState, AuthenticatedState, ChallengedState};
pub use challenge::TypedChallenge;
pub use challenge_kind::{
    ChallengeKind, CookieKind, LoginFormKind, OtpFormKind, RedirectKind, WebAuthnKind,
};
pub use flow_result::TypedFlowResult;
pub use realm_bound::{extract_realm_from_issuer, RealmBound};
pub use redirect::SafeRedirectTarget;
pub use session::TypedSession;
pub use session_state::{
    SessionAnonymous, SessionAuthenticated, SessionAuthorized, SessionConsentRequired,
    SessionExpired, SessionState,
};

/// Sealed trait pattern — prevents external implementations of state traits.
mod private {
    pub trait Sealed {}
}

/// Marker trait for flow execution status types.
pub trait FlowStatus: private::Sealed {}

/// Running flow — execution is in progress.
#[derive(Debug, Clone)]
pub struct RunningFlow;
impl private::Sealed for RunningFlow {}
impl FlowStatus for RunningFlow {}

/// Completed flow — all stages finished successfully.
#[derive(Debug, Clone)]
pub struct CompletedFlow;
impl private::Sealed for CompletedFlow {}
impl FlowStatus for CompletedFlow {}

/// Failed flow — a required stage failed.
#[derive(Debug, Clone)]
pub struct FailedFlow;
impl private::Sealed for FailedFlow {}
impl FlowStatus for FailedFlow {}

/// Trait for OIDC authorization request lifecycle states.
pub trait AuthRequestState: private::Sealed {
    /// Type of the user field in this state.
    type UserType: Clone + std::fmt::Debug;
    /// Type of the session field in this state.
    type SessionType: Clone + std::fmt::Debug;
}

/// Initial authorization request — no user authenticated yet.
#[derive(Debug, Clone)]
pub struct AuthInit;
impl private::Sealed for AuthInit {}
impl AuthRequestState for AuthInit {
    type UserType = ();
    type SessionType = ();
}

/// User has been authenticated — session created.
#[derive(Debug, Clone)]
pub struct AuthAuthenticated;
impl private::Sealed for AuthAuthenticated {}
impl AuthRequestState for AuthAuthenticated {
    type UserType = crate::User;
    type SessionType = crate::UserSession;
}

/// Consent has been checked/recorded.
#[derive(Debug, Clone)]
pub struct AuthConsented;
impl private::Sealed for AuthConsented {}
impl AuthRequestState for AuthConsented {
    type UserType = crate::User;
    type SessionType = crate::UserSession;
}

/// Tokens have been issued — ready to redirect.
#[derive(Debug, Clone)]
pub struct AuthAuthorized;
impl private::Sealed for AuthAuthorized {}
impl AuthRequestState for AuthAuthorized {
    type UserType = crate::User;
    type SessionType = crate::UserSession;
}

/// Trait for pending auth data cache states.
pub trait PendingState: private::Sealed {
    /// JSON tag used for round-trip serialisation.
    const TAG: &'static str;
}

/// Pending auth data for an anonymous / not-yet-challenged request.
#[derive(Debug, Clone)]
pub struct PendingAnonymous;
impl private::Sealed for PendingAnonymous {}
impl PendingState for PendingAnonymous {
    const TAG: &'static str = "anonymous";
}

/// Pending auth data when a challenge has been issued.
#[derive(Debug, Clone)]
pub struct PendingChallenged<K: ChallengeKind> {
    _kind: std::marker::PhantomData<fn() -> K>,
}
impl<K: ChallengeKind> private::Sealed for PendingChallenged<K> {}
impl<K: ChallengeKind> PendingState for PendingChallenged<K> {
    const TAG: &'static str = "challenged";
}

/// Pending auth data when required actions are pending.
#[derive(Debug, Clone)]
pub struct PendingActionRequired;
impl private::Sealed for PendingActionRequired {}
impl PendingState for PendingActionRequired {
    const TAG: &'static str = "action_required";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_types_are_zst() {
        assert_eq!(std::mem::size_of::<AnonymousState>(), 0);
        assert_eq!(std::mem::size_of::<AuthenticatedState>(), 0);
        assert_eq!(std::mem::size_of::<ChallengedState>(), 0);
        assert_eq!(std::mem::size_of::<SessionAnonymous>(), 0);
        assert_eq!(std::mem::size_of::<SessionAuthenticated>(), 0);
        assert_eq!(std::mem::size_of::<SessionConsentRequired>(), 0);
        assert_eq!(std::mem::size_of::<SessionAuthorized>(), 0);
        assert_eq!(std::mem::size_of::<SessionExpired>(), 0);
        assert_eq!(std::mem::size_of::<LoginFormKind>(), 0);
        assert_eq!(std::mem::size_of::<OtpFormKind>(), 0);
        assert_eq!(std::mem::size_of::<WebAuthnKind>(), 0);
        assert_eq!(std::mem::size_of::<RedirectKind>(), 0);
        assert_eq!(std::mem::size_of::<CookieKind>(), 0);
        assert_eq!(std::mem::size_of::<ActionsPending>(), 0);
        assert_eq!(std::mem::size_of::<ActionsCleared>(), 0);
        assert_eq!(std::mem::size_of::<AuthInit>(), 0);
        assert_eq!(std::mem::size_of::<AuthAuthenticated>(), 0);
        assert_eq!(std::mem::size_of::<AuthConsented>(), 0);
        assert_eq!(std::mem::size_of::<AuthAuthorized>(), 0);
        assert_eq!(std::mem::size_of::<PendingAnonymous>(), 0);
        assert_eq!(std::mem::size_of::<PendingActionRequired>(), 0);
    }

    /// ```compile_fail
    /// use issuerd_core::typestate::AuthState;
    /// struct Evil;
    /// impl AuthState for Evil { type UserIdType = String; }
    /// ```
    #[allow(dead_code)]
    fn sealed_trait_external_impl_fails() {}
}
