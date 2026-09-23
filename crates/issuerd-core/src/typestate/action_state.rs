// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Required-actions state markers (pending with action list vs. cleared).

use super::private;

/// Required-actions state marker trait.
pub trait ActionState: private::Sealed {
    /// The type carried for `required_actions` in this state.
    type ListType;
}

/// Required actions are pending — carries the list of action IDs.
#[derive(Debug, Clone)]
pub struct ActionsPending;
impl private::Sealed for ActionsPending {}
impl ActionState for ActionsPending {
    type ListType = Vec<String>;
}

/// Required actions have been cleared — carries unit as proof.
#[derive(Debug, Clone)]
pub struct ActionsCleared;
impl private::Sealed for ActionsCleared {}
impl ActionState for ActionsCleared {
    type ListType = ();
}
