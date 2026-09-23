// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Typestate safety shell around the runtime flow executor.
//!
//! This module provides `TypedFlowExecutor` and `FlowOutput`, which wrap the
//! existing `FlowExecutor` with compile-time proofs for authentication state.

pub mod executor;
pub mod flow_output;
pub mod transitions;

pub use executor::TypedFlowExecutor;
pub use flow_output::{ErasedPausedFlow, FlowOutput, TypedPausedFlow};
pub use transitions::{ChallengeClassification, ChallengeExt, FlowOutcomeExt};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;
    use crate::executor::FlowExecutor;
    use crate::plugin_registry::PluginRegistry;
    use issuerd_core::{
        AuthContext, AuthStepResult, Authenticator, Challenge, FlowConfig, FlowStage, IssuerdError,
        RealmId, Requirement, UserId,
    };

    fn test_auth_context() -> AuthContext {
        AuthContext {
            realm_id: RealmId::new("realm-1").unwrap(),
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            parameters: HashMap::new(),
            attributes: HashMap::new(),
            current_challenge: None,
        }
    }

    fn stage(id: &str, req: Requirement, auth: &str, priority: i32) -> FlowStage {
        FlowStage {
            id: issuerd_core::FlowStageId::new(id).unwrap(),
            requirement: req,
            authenticator: issuerd_core::Alias::new(auth).unwrap(),
            priority,
            sub_flow_alias: None,
            authenticator_config: None,
        }
    }

    mockall::mock! {
        pub PluginRegistry {}
        #[async_trait::async_trait]
        impl PluginRegistry for PluginRegistry {
            async fn get_authenticator(&self, id: &str) -> Result<Option<Arc<dyn issuerd_core::Authenticator>>, IssuerdError>;
            async fn get_required_action(&self, id: &str) -> Result<Option<Arc<dyn issuerd_core::RequiredAction>>, IssuerdError>;
            fn list_authenticator_ids(&self) -> Vec<String>;
            fn list_required_action_ids(&self) -> Vec<String>;
        }
    }

    #[derive(Clone)]
    #[allow(clippy::type_complexity)]
    struct TestAuthenticator {
        id: String,
        result: std::sync::Arc<
            std::sync::Mutex<Box<dyn FnMut(&mut AuthContext) -> AuthStepResult + Send>>,
        >,
    }

    impl TestAuthenticator {
        fn new<F>(id: &str, result: F) -> Self
        where
            F: FnMut(&mut AuthContext) -> AuthStepResult + Send + 'static,
        {
            Self {
                id: id.to_string(),
                result: std::sync::Arc::new(std::sync::Mutex::new(Box::new(result))),
            }
        }
    }

    #[async_trait::async_trait]
    impl issuerd_core::Authenticator for TestAuthenticator {
        fn id(&self) -> &str {
            &self.id
        }
        fn display_name(&self) -> &str {
            &self.id
        }
        fn requires_user(&self) -> bool {
            false
        }
        fn configured_for(&self, _ctx: &AuthContext) -> bool {
            true
        }
        async fn authenticate(&self, ctx: &mut AuthContext) -> AuthStepResult {
            (self.result.lock().unwrap())(ctx)
        }
    }

    #[test]
    fn test_authenticator_trait_methods() {
        let auth = TestAuthenticator::new("test-auth", |_ctx| AuthStepResult::Success);
        assert_eq!(auth.id(), "test-auth");
        assert_eq!(auth.display_name(), "test-auth");
        assert!(!auth.requires_user());
        assert!(auth.configured_for(&test_auth_context()));
    }

    #[tokio::test]
    async fn typed_execute_success_yields_authenticated_ctx() {
        let auth = TestAuthenticator::new("mock-auth", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("mock-auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = TypedFlowExecutor::new(FlowExecutor::new(Arc::new(reg), &[]));
        let config = FlowConfig {
            alias: issuerd_core::Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "mock-auth", 1)],
        };
        let ctx = issuerd_core::typestate::TypedAuthContext::new_anonymous(
            RealmId::new("realm-1").unwrap(),
        );
        let output = executor.execute(&config, ctx).await.unwrap();
        match output {
            FlowOutput::Success { ctx, .. } => {
                assert_eq!(ctx.user_id, UserId::new("alice").unwrap());
            }
            other => panic!("expected Success, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn typed_execute_challenge_yields_erased_paused_flow() {
        let auth = TestAuthenticator::new("mock-auth", |_ctx| {
            AuthStepResult::Challenge(Challenge::LoginForm {
                action_url: "/login".to_string(),
            })
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("mock-auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = TypedFlowExecutor::new(FlowExecutor::new(Arc::new(reg), &[]));
        let config = FlowConfig {
            alias: issuerd_core::Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "mock-auth", 1)],
        };
        let ctx = issuerd_core::typestate::TypedAuthContext::new_anonymous(
            RealmId::new("realm-1").unwrap(),
        );
        let output = executor.execute(&config, ctx).await.unwrap();
        match output {
            FlowOutput::Challenge { paused } => {
                assert_eq!(paused.execution_id(), &issuerd_core::FlowStageId::new("s1").unwrap());
            }
            other => panic!("expected Challenge, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn erased_paused_flow_downcast_login_form_succeeds() {
        let paused = ErasedPausedFlow::new(
            issuerd_core::FlowStageId::new("s1").unwrap(),
            Challenge::LoginForm {
                action_url: "/login".to_string(),
            },
        );
        assert!(paused.downcast::<issuerd_core::typestate::LoginFormKind>().is_some());
    }

    #[tokio::test]
    async fn erased_paused_flow_downcast_otp_form_fails() {
        let paused = ErasedPausedFlow::new(
            issuerd_core::FlowStageId::new("s1").unwrap(),
            Challenge::LoginForm {
                action_url: "/login".to_string(),
            },
        );
        assert!(paused.downcast::<issuerd_core::typestate::OtpFormKind>().is_none());
    }

    #[tokio::test]
    async fn typed_continue_flow_delegates_to_inner() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cc = call_count.clone();
        let auth = TestAuthenticator::new("auth-chal", move |ctx| {
            let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                AuthStepResult::Challenge(Challenge::OtpForm {
                    action_url: "/otp".to_string(),
                })
            } else {
                ctx.user_id = Some(UserId::new("alice").unwrap());
                AuthStepResult::Success
            }
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-chal"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = TypedFlowExecutor::new(FlowExecutor::new(Arc::new(reg), &[]));
        let config = FlowConfig {
            alias: issuerd_core::Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth-chal", 1)],
        };
        let ctx = issuerd_core::typestate::TypedAuthContext::new_anonymous(
            RealmId::new("realm-1").unwrap(),
        );
        let output = executor.execute(&config, ctx).await.unwrap();
        let eid = match output {
            FlowOutput::Challenge { paused } => paused.execution_id().clone(),
            other => panic!("expected Challenge, got {:?}", other),
        };

        let ctx = issuerd_core::typestate::TypedAuthContext::new_anonymous(
            RealmId::new("realm-1").unwrap(),
        );
        let output = executor.continue_flow(&config, &eid, ctx).await.unwrap();
        match output {
            FlowOutput::Success { ctx, .. } => {
                assert_eq!(ctx.user_id, UserId::new("alice").unwrap());
            }
            other => panic!("expected Success on continue, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn map_outcome_failure_returns_failure() {
        let outcome = crate::executor::FlowOutcome::Failure(IssuerdError::AccessDenied);
        let ctx = test_auth_context();
        let output = TypedFlowExecutor::map_outcome(outcome, ctx).unwrap();
        match output {
            FlowOutput::Failure(e) => assert_eq!(e, IssuerdError::AccessDenied),
            other => panic!("expected Failure, got {:?}", other),
        }
    }
}
