// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Pending auth data with a typestate tag for cache round-trips.

use std::marker::PhantomData;

use issuerd_core::{
    typestate::{PendingActionRequired, PendingAnonymous, PendingState},
    IssuerdError,
};

use crate::routes::PendingAuthData;

/// Pending auth data with a typestate tag.
#[derive(Debug, Clone)]
pub struct TypedPendingAuthData<S: PendingState> {
    inner: PendingAuthData,
    _state: PhantomData<fn() -> S>,
}

impl TypedPendingAuthData<PendingAnonymous> {
    /// Wrap pending auth data as anonymous.
    pub fn new(inner: PendingAuthData) -> Self {
        Self {
            inner,
            _state: PhantomData,
        }
    }
}

impl TypedPendingAuthData<PendingActionRequired> {
    /// Wrap pending auth data as action-required.
    pub fn new_action_required(inner: PendingAuthData) -> Self {
        Self {
            inner,
            _state: PhantomData,
        }
    }
}

impl<S: PendingState> TypedPendingAuthData<S> {
    /// Borrow the underlying `PendingAuthData`.
    pub fn inner(&self) -> &PendingAuthData {
        &self.inner
    }

    /// Consume and return the untyped `PendingAuthData` with tag set.
    pub fn into_untyped(mut self) -> PendingAuthData {
        self.inner._typestate_tag = S::TAG.to_string();
        self.inner
    }
}

/// Kind-erased deserialized pending auth data.
#[derive(Debug, Clone)]
pub enum TypedPendingAuthDataEnum {
    Anonymous(TypedPendingAuthData<PendingAnonymous>),
    Challenged(PendingAuthData),
    ActionRequired(TypedPendingAuthData<PendingActionRequired>),
}

impl TypedPendingAuthDataEnum {
    /// Deserialize from untyped `PendingAuthData`.
    pub fn from_untyped(data: PendingAuthData) -> Result<Self, IssuerdError> {
        match data._typestate_tag.as_str() {
            "anonymous" | "" => {
                Ok(TypedPendingAuthDataEnum::Anonymous(TypedPendingAuthData::new(data)))
            }
            "challenged" => Ok(TypedPendingAuthDataEnum::Challenged(data)),
            "action_required" => Ok(TypedPendingAuthDataEnum::ActionRequired(
                TypedPendingAuthData::new_action_required(data),
            )),
            _ => Err(IssuerdError::InvalidRequest("unknown pending auth typestate tag".into())),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_core::FlowStageId;

    fn sample_pending() -> PendingAuthData {
        PendingAuthData {
            realm_id: "master".to_string(),
            client_id: "admin-cli".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: None,
            nonce: None,
            response_type: "code".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            ip_address: None,
            execution_id: FlowStageId::new("username-password").unwrap(),
            acr_values: vec![],
            claims: None,
            _typestate_tag: "anonymous".to_string(),
            attempt_count: 0,
            remember_me: false,
            user_id: None,
            prompt_consent: false,
            locale: None,
            response_mode: None,
            authorization_details: None,
        }
    }

    #[test]
    fn roundtrip_anonymous_pending_auth() {
        let data = sample_pending();
        let typed = TypedPendingAuthData::<PendingAnonymous>::new(data.clone());
        let untyped = typed.into_untyped();
        assert_eq!(untyped._typestate_tag, "anonymous");
        let back = TypedPendingAuthDataEnum::from_untyped(untyped).unwrap();
        match back {
            TypedPendingAuthDataEnum::Anonymous(_) => {}
            other => panic!("expected Anonymous, got {:?}", other),
        }
    }

    #[test]
    fn roundtrip_challenged_pending_auth() {
        let mut data = sample_pending();
        data._typestate_tag = "challenged".to_string();
        let back = TypedPendingAuthDataEnum::from_untyped(data).unwrap();
        match back {
            TypedPendingAuthDataEnum::Challenged(_) => {}
            other => panic!("expected Challenged, got {:?}", other),
        }
    }

    #[test]
    fn unknown_tag_returns_error() {
        let mut data = sample_pending();
        data._typestate_tag = "unknown".to_string();
        assert!(TypedPendingAuthDataEnum::from_untyped(data).is_err());
    }

    #[test]
    fn missing_tag_defaults_to_anonymous() {
        let mut data = sample_pending();
        data._typestate_tag = "".to_string();
        let back = TypedPendingAuthDataEnum::from_untyped(data).unwrap();
        match back {
            TypedPendingAuthDataEnum::Anonymous(_) => {}
            other => panic!("expected Anonymous, got {:?}", other),
        }
    }

    #[test]
    fn roundtrip_action_required_pending_auth() {
        let data = sample_pending();
        let typed =
            TypedPendingAuthData::<PendingActionRequired>::new_action_required(data.clone());
        let untyped = typed.into_untyped();
        assert_eq!(untyped._typestate_tag, "action_required");
        let back = TypedPendingAuthDataEnum::from_untyped(untyped).unwrap();
        match back {
            TypedPendingAuthDataEnum::ActionRequired(t) => {
                assert_eq!(t.inner().realm_id, "master");
            }
            other => panic!("expected ActionRequired, got {:?}", other),
        }
    }

    #[test]
    fn inner_borrows_underlying_data() {
        let data = sample_pending();
        let typed = TypedPendingAuthData::<PendingAnonymous>::new(data.clone());
        assert_eq!(typed.inner().client_id, "admin-cli");
        assert_eq!(typed.inner().realm_id, "master");
    }
}
