// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Authentication state markers controlling whether user_id is optional or required.

use super::private;
use crate::UserId;

/// Authentication state — determines whether `user_id` is optional or required.
pub trait AuthState: private::Sealed {
    /// The type of `user_id` in this state.
    type UserIdType: Clone + std::fmt::Debug;
}

/// Anonymous — user has not yet authenticated.
#[derive(Debug, Clone)]
pub struct AnonymousState;
impl private::Sealed for AnonymousState {}
impl AuthState for AnonymousState {
    type UserIdType = Option<UserId>;
}

/// Authenticated — user has successfully authenticated.
#[derive(Debug, Clone)]
pub struct AuthenticatedState;
impl private::Sealed for AuthenticatedState {}
impl AuthState for AuthenticatedState {
    type UserIdType = UserId;
}

/// Challenged — user is in the middle of a multi-step challenge.
#[derive(Debug, Clone)]
pub struct ChallengedState;
impl private::Sealed for ChallengedState {}
impl AuthState for ChallengedState {
    type UserIdType = Option<UserId>;
}
