// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// TypedFlowResult: flow result with required-actions state encoded in the type.

use std::marker::PhantomData;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::ids::{ClientId, SessionId, UserId};
use crate::models::AuthMethod;

use super::{ActionState, ActionsCleared, ActionsPending};
use super::{SessionAuthorized, TypedSession};

/// Flow result with required-actions state encoded in the type parameter.
#[derive(Debug, Clone)]
pub struct TypedFlowResult<A: ActionState> {
    pub user_id: UserId,
    pub session_id: SessionId,
    pub auth_time: DateTime<Utc>,
    pub required_actions: A::ListType,
}

impl TypedFlowResult<ActionsPending> {
    /// Create a new pending result.
    pub fn new_pending(user_id: UserId, session_id: SessionId, actions: Vec<String>) -> Self {
        Self {
            user_id,
            session_id,
            auth_time: Utc::now(),
            required_actions: actions,
        }
    }

    /// Transition to cleared — drops the actions list.
    pub fn into_cleared(self) -> TypedFlowResult<ActionsCleared> {
        TypedFlowResult {
            user_id: self.user_id,
            session_id: self.session_id,
            auth_time: self.auth_time,
            required_actions: (),
        }
    }
}

impl TypedFlowResult<ActionsCleared> {
    /// Create a new cleared result.
    pub fn new_cleared(user_id: UserId, session_id: SessionId) -> Self {
        Self {
            user_id,
            session_id,
            auth_time: Utc::now(),
            required_actions: (),
        }
    }

    /// Create a cleared result preserving the original authentication time.
    ///
    /// Used by the required-action continuation: the user authenticated at
    /// the start of the flow, so tokens issued after the last action clears
    /// must keep the original `auth_time`, not the completion time.
    pub fn new_cleared_at(
        user_id: UserId,
        session_id: SessionId,
        auth_time: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id,
            session_id,
            auth_time,
            required_actions: (),
        }
    }

    /// Promote to an authorized session.
    pub fn into_authorized_session(
        self,
        client_id: ClientId,
        ip: IpAddr,
        method: AuthMethod,
        remember_me: bool,
    ) -> TypedSession<SessionAuthorized> {
        TypedSession {
            user_id: self.user_id,
            client_id,
            session_id: self.session_id,
            auth_time: self.auth_time,
            auth_method: method,
            remember_me,
            ip_address: ip,
            _state: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ClientId, SessionId, UserId};

    #[test]
    fn cleared_result_becomes_authorized_session() {
        let result = TypedFlowResult::<ActionsCleared>::new_cleared(
            UserId::new("alice").unwrap(),
            SessionId::new("s1").unwrap(),
        );
        let session = result.into_authorized_session(
            ClientId::new("c1").unwrap(),
            "127.0.0.1".parse().unwrap(),
            AuthMethod::Password,
            true,
        );
        assert_eq!(session.user_id, UserId::new("alice").unwrap());
    }

    #[test]
    fn into_cleared_drops_actions_list() {
        let pending = TypedFlowResult::<ActionsPending>::new_pending(
            UserId::new("alice").unwrap(),
            SessionId::new("s1").unwrap(),
            vec!["VERIFY_EMAIL".to_string()],
        );
        let cleared = pending.into_cleared();
        let _unit: () = cleared.required_actions;
        assert_eq!(_unit, ());
    }

    /// ```compile_fail
    /// use issuerd_core::typestate::{TypedFlowResult, ActionsPending};
    /// use issuerd_core::ids::ClientId;
    /// use issuerd_core::models::AuthMethod;
    /// fn f(r: TypedFlowResult<ActionsPending>) {
    ///     let _ = r.into_authorized_session(ClientId::new("c").unwrap(), "127.0.0.1".parse().unwrap(), AuthMethod::Password, false);
    /// }
    /// ```
    #[allow(dead_code)]
    fn compile_fail_pending_into_session() {}
}
