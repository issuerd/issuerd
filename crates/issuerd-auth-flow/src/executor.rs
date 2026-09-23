// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Authentication flow executor: runs flow stages to success, challenge, or failure outcomes.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;
use issuerd_core::{
    Alias, AuthContext, AuthStepResult, Challenge, FlowConfig, FlowStage, FlowStageId,
    IssuerdError, Requirement, SessionId, UserId,
};
use tracing::{debug, warn};

use crate::plugin_registry::PluginRegistry;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FlowResult {
    pub user_id: UserId,
    pub session_id: SessionId,
    pub auth_time: chrono::DateTime<Utc>,
    pub required_actions: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum FlowOutcome {
    Success(FlowResult),
    Challenge(Challenge, FlowStageId), // challenge + execution_id
    Failure(IssuerdError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    NotEvaluated,
    Success,
    Attempted,
    Failed,
    Skipped,
}

// ---------------------------------------------------------------------------
// FlowExecutor
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct FlowExecutor {
    registry: Arc<dyn PluginRegistry>,
    flows: HashMap<Alias, FlowConfig>,
}

impl FlowExecutor {
    pub fn new(registry: Arc<dyn PluginRegistry>, flows: &[FlowConfig]) -> Self {
        let mut map = HashMap::new();
        for f in flows {
            map.insert(f.alias.clone(), f.clone());
        }
        Self {
            registry,
            flows: map,
        }
    }

    pub async fn execute(
        &self,
        flow_config: &FlowConfig,
        context: &mut AuthContext,
    ) -> Result<FlowOutcome, IssuerdError> {
        let mut state = FlowState {
            execution_status: HashMap::new(),
            flow_path: vec![flow_config.alias.clone()],
        };
        let outcome = self.execute_stages(&flow_config.stages, context, &mut state, 0).await?;
        self.finalize_outcome(outcome, context).await
    }

    pub async fn continue_flow(
        &self,
        flow_config: &FlowConfig,
        execution_id: &FlowStageId,
        context: &mut AuthContext,
    ) -> Result<FlowOutcome, IssuerdError> {
        let mut state = FlowState {
            execution_status: HashMap::new(),
            flow_path: vec![flow_config.alias.clone()],
        };

        // Find the stage index
        let idx =
            flow_config.stages.iter().position(|s| s.id == *execution_id).ok_or_else(|| {
                IssuerdError::InvalidRequest(format!("unknown execution_id: {execution_id}"))
            })?;

        let stage = &flow_config.stages[idx];

        // A disabled stage is never executed: mirror `execute_stages` and
        // skip straight to the remaining stages. Without this, naming a
        // disabled stage as the resume point would execute it anyway.
        if matches!(stage.requirement, Requirement::Disabled) {
            state.execution_status.insert(stage.id.clone(), ExecutionStatus::Skipped);
            let remaining = &flow_config.stages[idx + 1..];
            let rest = self.execute_stages(remaining, context, &mut state, 0).await?;
            return self.finalize_outcome(rest, context).await;
        }

        let outcome = self.execute_stage(stage, context, &mut state, 0).await?;

        match outcome {
            StageOutcome::Success => {
                state.execution_status.insert(stage.id.clone(), ExecutionStatus::Success);
                // Continue with remaining stages
                let remaining = &flow_config.stages[idx + 1..];
                let rest = self.execute_stages(remaining, context, &mut state, 0).await?;
                self.finalize_outcome(rest, context).await
            }
            StageOutcome::Challenge(c) => Ok(FlowOutcome::Challenge(c, execution_id.clone())),
            StageOutcome::Failure(e) => {
                state.execution_status.insert(stage.id.clone(), ExecutionStatus::Failed);
                // Handle according to requirement
                match stage.requirement {
                    Requirement::Required | Requirement::Alternative | Requirement::Conditional => {
                        Ok(FlowOutcome::Failure(e))
                    }
                    Requirement::Optional | Requirement::Disabled => {
                        // Continue with remaining stages
                        let remaining = &flow_config.stages[idx + 1..];
                        let rest = self.execute_stages(remaining, context, &mut state, 0).await?;
                        self.finalize_outcome(rest, context).await
                    }
                }
            }
            StageOutcome::Attempted => {
                state.execution_status.insert(stage.id.clone(), ExecutionStatus::Attempted);
                match stage.requirement {
                    Requirement::Required | Requirement::Alternative | Requirement::Conditional => {
                        Ok(FlowOutcome::Failure(IssuerdError::AccessDenied))
                    }
                    Requirement::Optional | Requirement::Disabled => {
                        let remaining = &flow_config.stages[idx + 1..];
                        let rest = self.execute_stages(remaining, context, &mut state, 0).await?;
                        self.finalize_outcome(rest, context).await
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn execute_stages<'a>(
        &'a self,
        stages: &'a [FlowStage],
        context: &'a mut AuthContext,
        state: &'a mut FlowState,
        depth: usize,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<FlowOutcome, IssuerdError>> + Send + 'a>>
    {
        Box::pin(async move {
            if depth > 10 {
                return Ok(FlowOutcome::Failure(IssuerdError::ServerError(
                    "flow recursion depth exceeded".into(),
                )));
            }

            let mut i = 0;
            let mut skip_conditional_scope = false;

            while i < stages.len() {
                let stage = &stages[i];

                let req = match stage.requirement {
                    Requirement::Required => ActiveRequirement::Required,
                    Requirement::Optional => ActiveRequirement::Optional,
                    Requirement::Conditional => ActiveRequirement::Conditional,
                    Requirement::Alternative => ActiveRequirement::Alternative,
                    Requirement::Disabled => {
                        state.execution_status.insert(stage.id.clone(), ExecutionStatus::Skipped);
                        i += 1;
                        continue;
                    }
                };

                if skip_conditional_scope && req == ActiveRequirement::Conditional {
                    state.execution_status.insert(stage.id.clone(), ExecutionStatus::Skipped);
                    i += 1;
                    continue;
                }
                skip_conditional_scope = false;

                // Handle sub-flow
                if let Some(alias) = &stage.sub_flow_alias {
                    let nested = match self.flows.get(alias).cloned() {
                        Some(n) => n,
                        None => {
                            return Err(IssuerdError::InvalidRequest(format!(
                                "unknown sub-flow alias: {alias}"
                            )));
                        }
                    };
                    state.flow_path.push(alias.clone());
                    let sub = self.execute_subflow(&nested, context, state, depth + 1).await?;
                    state.flow_path.pop();

                    match sub {
                        FlowOutcome::Success(_) => {
                            state
                                .execution_status
                                .insert(stage.id.clone(), ExecutionStatus::Success);
                            i += 1;
                            continue;
                        }
                        FlowOutcome::Challenge(c, eid) => {
                            return Ok(FlowOutcome::Challenge(c, eid));
                        }
                        FlowOutcome::Failure(e) => {
                            state
                                .execution_status
                                .insert(stage.id.clone(), ExecutionStatus::Failed);
                            match req {
                                ActiveRequirement::Required | ActiveRequirement::Alternative => {
                                    return Ok(FlowOutcome::Failure(e));
                                }
                                ActiveRequirement::Conditional => {
                                    skip_conditional_scope = true;
                                    i += 1;
                                    continue;
                                }
                                ActiveRequirement::Optional => {
                                    i += 1;
                                    continue;
                                }
                            }
                        }
                    }
                }

                // Handle alternative groups
                if req == ActiveRequirement::Alternative {
                    let group_start = i;
                    let group_end = stages[group_start..]
                        .iter()
                        .position(|s| s.requirement != Requirement::Alternative)
                        .map(|p| group_start + p)
                        .unwrap_or(stages.len());
                    let group = &stages[group_start..group_end];

                    let mut any_success = false;
                    let mut last_error = None;

                    for alt_stage in group {
                        if let Some(alias) = &alt_stage.sub_flow_alias {
                            // Sub-flow inside alternative group
                            let nested = match self.flows.get(alias).cloned() {
                                Some(n) => n,
                                None => {
                                    return Err(IssuerdError::InvalidRequest(format!(
                                        "unknown sub-flow alias: {alias}"
                                    )));
                                }
                            };
                            state.flow_path.push(alias.clone());
                            let sub =
                                self.execute_subflow(&nested, context, state, depth + 1).await?;
                            state.flow_path.pop();

                            match sub {
                                FlowOutcome::Success(_) => {
                                    state
                                        .execution_status
                                        .insert(alt_stage.id.clone(), ExecutionStatus::Success);
                                    any_success = true;
                                    break;
                                }
                                FlowOutcome::Challenge(c, eid) => {
                                    return Ok(FlowOutcome::Challenge(c, eid));
                                }
                                FlowOutcome::Failure(e) => {
                                    state
                                        .execution_status
                                        .insert(alt_stage.id.clone(), ExecutionStatus::Failed);
                                    last_error = Some(e);
                                }
                            }
                            continue;
                        }

                        let outcome = self.execute_stage(alt_stage, context, state, depth).await?;
                        match outcome {
                            StageOutcome::Success => {
                                state
                                    .execution_status
                                    .insert(alt_stage.id.clone(), ExecutionStatus::Success);
                                any_success = true;
                                break;
                            }
                            StageOutcome::Challenge(c) => {
                                return Ok(FlowOutcome::Challenge(c, alt_stage.id.clone()));
                            }
                            StageOutcome::Failure(e) => {
                                state
                                    .execution_status
                                    .insert(alt_stage.id.clone(), ExecutionStatus::Failed);
                                last_error = Some(e);
                            }
                            StageOutcome::Attempted => {
                                state
                                    .execution_status
                                    .insert(alt_stage.id.clone(), ExecutionStatus::Attempted);
                            }
                        }
                    }

                    if !any_success {
                        if let Some(e) = last_error {
                            return Ok(FlowOutcome::Failure(e));
                        }
                        // All attempted
                        return Ok(FlowOutcome::Failure(IssuerdError::AccessDenied));
                    }

                    i = group_end;
                    continue;
                }

                // Required, Optional, Conditional (non-subflow)
                let outcome = self.execute_stage(stage, context, state, depth).await?;

                match outcome {
                    StageOutcome::Success => {
                        state.execution_status.insert(stage.id.clone(), ExecutionStatus::Success);
                        i += 1;
                    }
                    StageOutcome::Challenge(c) => {
                        return Ok(FlowOutcome::Challenge(c, stage.id.clone()));
                    }
                    StageOutcome::Failure(e) => {
                        state.execution_status.insert(stage.id.clone(), ExecutionStatus::Failed);
                        if req == ActiveRequirement::Required {
                            return Ok(FlowOutcome::Failure(e));
                        }
                        if req == ActiveRequirement::Conditional {
                            skip_conditional_scope = true;
                        }
                        i += 1;
                    }
                    StageOutcome::Attempted => {
                        state.execution_status.insert(stage.id.clone(), ExecutionStatus::Attempted);
                        if req == ActiveRequirement::Required {
                            return Ok(FlowOutcome::Failure(IssuerdError::AccessDenied));
                        }
                        if req == ActiveRequirement::Conditional {
                            skip_conditional_scope = true;
                        }
                        i += 1;
                    }
                }
            }

            // All stages processed
            if context.user_id.is_some() {
                Ok(FlowOutcome::Success(FlowResult {
                    user_id: context.user_id.clone().unwrap(),
                    session_id: context.session_id.clone().unwrap_or_else(|| {
                        SessionId::new(issuerd_core::utils::generate_id()).unwrap()
                    }),
                    auth_time: Utc::now(),
                    required_actions: vec![],
                }))
            } else {
                Ok(FlowOutcome::Failure(IssuerdError::AccessDenied))
            }
        })
    }

    fn execute_subflow<'a>(
        &'a self,
        flow_config: &'a FlowConfig,
        context: &'a mut AuthContext,
        state: &'a mut FlowState,
        depth: usize,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<FlowOutcome, IssuerdError>> + Send + 'a>>
    {
        Box::pin(
            async move { self.execute_stages(&flow_config.stages, context, state, depth).await },
        )
    }

    async fn execute_stage(
        &self,
        stage: &FlowStage,
        context: &mut AuthContext,
        state: &mut FlowState,
        _depth: usize,
    ) -> Result<StageOutcome, IssuerdError> {
        let authenticator = match self.registry.get_authenticator(&stage.authenticator).await? {
            Some(a) => a,
            None => {
                // Operator config error: the flow references an authenticator
                // that is not registered.
                warn!(
                    realm = %context.realm_id,
                    flow = state.flow_path.last().map(Alias::as_str).unwrap_or("?"),
                    stage = %stage.authenticator,
                    "stage failed: unknown authenticator"
                );
                return Ok(StageOutcome::Failure(IssuerdError::InvalidRequest(format!(
                    "unknown authenticator: {}",
                    stage.authenticator
                ))));
            }
        };

        if stage.requirement == Requirement::Optional && !authenticator.configured_for(context) {
            return Ok(StageOutcome::Attempted);
        }

        let result = authenticator.authenticate(context).await;
        match result {
            AuthStepResult::Success => Ok(StageOutcome::Success),
            AuthStepResult::Failure(e) => {
                let flow = state.flow_path.last().map(Alias::as_str).unwrap_or("?");
                if matches!(e, IssuerdError::ServerError(_) | IssuerdError::UnsupportedOperation) {
                    warn!(
                        realm = %context.realm_id,
                        flow = %flow,
                        stage = %stage.authenticator,
                        error = %e,
                        "stage failed"
                    );
                } else {
                    debug!(
                        realm = %context.realm_id,
                        flow = %flow,
                        stage = %stage.authenticator,
                        error = %e,
                        "stage failed"
                    );
                }
                Ok(StageOutcome::Failure(e))
            }
            AuthStepResult::Challenge(c) => Ok(StageOutcome::Challenge(c)),
            AuthStepResult::Attempted => Ok(StageOutcome::Attempted),
        }
    }

    async fn finalize_outcome(
        &self,
        outcome: FlowOutcome,
        context: &AuthContext,
    ) -> Result<FlowOutcome, IssuerdError> {
        let FlowOutcome::Success(mut result) = outcome else {
            return Ok(outcome);
        };

        // Evaluate required actions
        for id in self.registry.list_required_action_ids() {
            if let Some(action) = self.registry.get_required_action(&id).await? {
                if action.evaluate(context).await {
                    result.required_actions.push(id);
                }
            }
        }

        Ok(FlowOutcome::Success(result))
    }
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FlowState {
    execution_status: HashMap<FlowStageId, ExecutionStatus>,
    flow_path: Vec<Alias>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveRequirement {
    Required,
    Optional,
    Conditional,
    Alternative,
}

enum StageOutcome {
    Success,
    Failure(IssuerdError),
    Challenge(Challenge),
    Attempted,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use async_trait::async_trait;
    use issuerd_core::{
        AuthContext, AuthStepResult, Authenticator, Challenge, FlowConfig, FlowStage, IssuerdError,
        RealmId, RequiredAction, Requirement, UserId,
    };

    use super::*;

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
            id: FlowStageId::new(id).unwrap(),
            requirement: req,
            authenticator: Alias::new(auth).unwrap(),
            priority,
            sub_flow_alias: None,
            authenticator_config: None,
        }
    }

    mockall::mock! {
        pub PluginRegistry {}
        #[async_trait]
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

    #[async_trait]
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

    #[derive(Clone)]
    #[allow(clippy::type_complexity)]
    struct TestRequiredAction {
        id: String,
        evaluate_result:
            std::sync::Arc<std::sync::Mutex<Box<dyn FnMut(&AuthContext) -> bool + Send>>>,
    }

    impl TestRequiredAction {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                evaluate_result: std::sync::Arc::new(std::sync::Mutex::new(Box::new(|_| true))),
            }
        }
    }

    #[async_trait]
    impl issuerd_core::RequiredAction for TestRequiredAction {
        fn id(&self) -> &str {
            &self.id
        }
        fn display_name(&self) -> &str {
            &self.id
        }
        async fn evaluate(&self, ctx: &AuthContext) -> bool {
            (self.evaluate_result.lock().unwrap())(ctx)
        }
        async fn process(&self, _ctx: &mut AuthContext) -> issuerd_core::RequiredActionResult {
            issuerd_core::RequiredActionResult::Success
        }
    }

    // -----------------------------------------------------------------------
    // Assertion helpers (with dedicated panic-coverage tests)
    // -----------------------------------------------------------------------

    fn assert_success(outcome: FlowOutcome) -> FlowResult {
        match outcome {
            FlowOutcome::Success(r) => r,
            other => panic!("expected Success, got {:?}", other),
        }
    }

    fn assert_failure(outcome: FlowOutcome) -> IssuerdError {
        match outcome {
            FlowOutcome::Failure(e) => e,
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    fn assert_challenge(outcome: FlowOutcome) -> (Challenge, FlowStageId) {
        match outcome {
            FlowOutcome::Challenge(c, eid) => (c, eid),
            other => panic!("expected Challenge, got {:?}", other),
        }
    }

    #[test]
    #[should_panic(expected = "expected Success")]
    fn assert_success_panics_on_failure() {
        assert_success(FlowOutcome::Failure(IssuerdError::AccessDenied));
    }

    #[test]
    #[should_panic(expected = "expected Failure")]
    fn assert_failure_panics_on_success() {
        assert_failure(FlowOutcome::Success(FlowResult {
            user_id: UserId::new("alice").unwrap(),
            session_id: SessionId::new("s1").unwrap(),
            auth_time: Utc::now(),
            required_actions: vec![],
        }));
    }

    #[test]
    #[should_panic(expected = "expected Challenge")]
    fn assert_challenge_panics_on_success() {
        assert_challenge(FlowOutcome::Success(FlowResult {
            user_id: UserId::new("alice").unwrap(),
            session_id: SessionId::new("s1").unwrap(),
            auth_time: Utc::now(),
            required_actions: vec![],
        }));
    }

    fn assert_server_error(outcome: FlowOutcome) {
        match outcome {
            FlowOutcome::Failure(IssuerdError::ServerError(_)) => {}
            other => panic!("expected Failure(ServerError), got {:?}", other),
        }
    }

    fn assert_invalid_request(outcome: FlowOutcome) {
        match outcome {
            FlowOutcome::Failure(IssuerdError::InvalidRequest(_)) => {}
            other => panic!("expected Failure(InvalidRequest), got {:?}", other),
        }
    }

    #[test]
    #[should_panic(expected = "expected Failure(ServerError)")]
    fn assert_server_error_panics() {
        assert_server_error(FlowOutcome::Success(FlowResult {
            user_id: UserId::new("alice").unwrap(),
            session_id: SessionId::new("s1").unwrap(),
            auth_time: Utc::now(),
            required_actions: vec![],
        }));
    }

    #[test]
    #[should_panic(expected = "expected Failure(InvalidRequest)")]
    fn assert_invalid_request_panics() {
        assert_invalid_request(FlowOutcome::Success(FlowResult {
            user_id: UserId::new("alice").unwrap(),
            session_id: SessionId::new("s1").unwrap(),
            auth_time: Utc::now(),
            required_actions: vec![],
        }));
    }

    fn assert_action_success(result: issuerd_core::RequiredActionResult) {
        match result {
            issuerd_core::RequiredActionResult::Success => {}
            other => panic!("expected Success, got {:?}", other),
        }
    }

    #[test]
    #[should_panic(expected = "expected Success")]
    fn assert_action_success_panics() {
        assert_action_success(issuerd_core::RequiredActionResult::Failure(
            IssuerdError::AccessDenied,
        ));
    }

    // -----------------------------------------------------------------------
    // Linear success / failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn linear_flow_success() {
        let auth = TestAuthenticator::new("mock-auth", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("mock-auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "mock-auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.user_id, UserId::new("alice").unwrap());
    }

    #[tokio::test]
    async fn linear_flow_failure_aborts() {
        let auth = TestAuthenticator::new("mock-auth", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("mock-auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "mock-auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::InvalidGrant);
    }

    // -----------------------------------------------------------------------
    // Alternative groups
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn alternative_first_fails_second_succeeds() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Alternative, "auth1", 1),
                stage("s2", Requirement::Alternative, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.user_id, UserId::new("alice").unwrap());
    }

    #[tokio::test]
    async fn alternative_all_fail() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth2 = TestAuthenticator::new("auth2", |_| {
            AuthStepResult::Failure(IssuerdError::AccessDenied)
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Alternative, "auth1", 1),
                stage("s2", Requirement::Alternative, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::AccessDenied);
    }

    // -----------------------------------------------------------------------
    // Optional / Disabled
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn optional_not_configured_is_skipped() {
        #[derive(Clone)]
        struct OptionalAuth;
        #[async_trait]
        impl issuerd_core::Authenticator for OptionalAuth {
            fn id(&self) -> &str {
                "auth-opt"
            }
            fn display_name(&self) -> &str {
                "AuthOpt"
            }
            fn requires_user(&self) -> bool {
                false
            }
            fn configured_for(&self, _ctx: &AuthContext) -> bool {
                false
            }
            async fn authenticate(&self, _ctx: &mut AuthContext) -> AuthStepResult {
                AuthStepResult::Success
            }
        }

        // Directly cover trait methods
        let opt = OptionalAuth;
        assert_eq!(opt.id(), "auth-opt");
        assert_eq!(opt.display_name(), "AuthOpt");
        assert!(!opt.requires_user());
        assert!(!opt.configured_for(&test_auth_context()));
        let mut ctx2 = test_auth_context();
        let _ = opt.authenticate(&mut ctx2).await;

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-opt"))
            .returning(|_| Ok(Some(Arc::new(OptionalAuth))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Optional, "auth-opt", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::AccessDenied);
    }

    #[tokio::test]
    async fn disabled_stage_never_invoked() {
        let _auth = TestAuthenticator::new("auth-dis", |_| AuthStepResult::Success);

        let mut reg = MockPluginRegistry::new();
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Disabled, "auth-dis", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::AccessDenied);
    }

    // -----------------------------------------------------------------------
    // Challenge / continue_flow
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn challenge_then_continue_success() {
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

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth-chal", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let (_, eid) = assert_challenge(outcome);
        assert_eq!(eid, FlowStageId::new("s1").unwrap());

        let outcome = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await
            .unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.user_id, UserId::new("alice").unwrap());
    }

    // -----------------------------------------------------------------------
    // Sub-flow depth 3
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn nested_subflow_depth_3() {
        let auth = TestAuthenticator::new("auth-pwd", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-pwd"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub_b = FlowConfig {
            alias: Alias::new("sub-b").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("s-b1", Requirement::Required, "auth-pwd", 1)],
        };
        let sub_a = FlowConfig {
            alias: Alias::new("sub-a").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-a1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub-b").unwrap()),
                authenticator_config: None,
            }],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-top1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub-a").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub_a, sub_b]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.user_id, UserId::new("alice").unwrap());
    }

    // -----------------------------------------------------------------------
    // Conditional
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn conditional_true_runs_remaining() {
        let auth = TestAuthenticator::new("auth-cond", |_| AuthStepResult::Success);
        let auth2 = TestAuthenticator::new("auth-next", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-cond"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-next"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Conditional, "auth-cond", 1),
                stage("s2", Requirement::Required, "auth-next", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.user_id, UserId::new("alice").unwrap());
    }

    #[tokio::test]
    async fn conditional_false_skips_remaining() {
        let auth = TestAuthenticator::new("auth-cond", |_| AuthStepResult::Attempted);
        let auth2 = TestAuthenticator::new("auth-next", |_| AuthStepResult::Success);

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-cond"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-next"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Conditional, "auth-cond", 1),
                stage("s2", Requirement::Required, "auth-next", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::AccessDenied);
    }

    // -----------------------------------------------------------------------
    // Alternative in sub-flow
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn alternative_in_subflow() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Alternative, "auth1", 1),
                stage("s2", Requirement::Alternative, "auth2", 2),
            ],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-top1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.user_id, UserId::new("alice").unwrap());
    }

    // -----------------------------------------------------------------------
    // Required actions integration
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn required_actions_populated_after_success() {
        let auth = TestAuthenticator::new("auth", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });
        let action = TestRequiredAction::new("terms");

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec!["terms".to_string()]);
        reg.expect_get_required_action()
            .with(mockall::predicate::eq("terms"))
            .returning(move |_| Ok(Some(Arc::new(action.clone()))));

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.required_actions, vec!["terms"]);
    }

    // -----------------------------------------------------------------------
    // E2E: browser flow (cookie -> password -> OTP)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn browser_flow_cookie_attempted_password_success_otp_challenge() {
        let cookie_auth = TestAuthenticator::new("auth-cookie", |_| AuthStepResult::Attempted);
        let pwd_auth = TestAuthenticator::new("auth-password", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });
        let otp_auth = TestAuthenticator::new("auth-otp", |_| {
            AuthStepResult::Challenge(Challenge::OtpForm {
                action_url: "/otp".to_string(),
            })
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-cookie"))
            .returning(move |_| Ok(Some(Arc::new(cookie_auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-password"))
            .returning(move |_| Ok(Some(Arc::new(pwd_auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-otp"))
            .returning(move |_| Ok(Some(Arc::new(otp_auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Alternative, "auth-cookie", 1),
                stage("s2", Requirement::Alternative, "auth-password", 2),
                stage("s3", Requirement::Required, "auth-otp", 3),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let (_, eid) = assert_challenge(outcome);
        assert_eq!(eid, FlowStageId::new("s3").unwrap());

        // continue_flow with OTP success
        let otp_auth2 = TestAuthenticator::new("auth-otp", |_| AuthStepResult::Success);

        let mut reg2 = MockPluginRegistry::new();
        reg2.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-otp"))
            .returning(move |_| Ok(Some(Arc::new(otp_auth2.clone()))));
        reg2.expect_list_required_action_ids().return_const(vec![]);

        let executor2 = FlowExecutor::new(Arc::new(reg2), &[]);
        let outcome = executor2
            .continue_flow(&config, &FlowStageId::new("s3").unwrap(), &mut ctx)
            .await
            .unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.user_id, UserId::new("alice").unwrap());
    }

    // -----------------------------------------------------------------------
    // E2E: custom mock authenticator injection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn custom_mock_authenticator_injection() {
        let auth = TestAuthenticator::new("custom-mock", |ctx| {
            ctx.attributes.insert("custom".to_string(), "injected".to_string());
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("custom-mock"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "custom-mock", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        assert_success(outcome);
        assert_eq!(ctx.attributes.get("custom"), Some(&"injected".to_string()));
    }

    // -----------------------------------------------------------------------
    // Error propagation from execute_stages through execute
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn execute_propagates_registry_error() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(|_| Err(IssuerdError::ServerError("db down".into())));

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let result = executor.execute(&config, &mut ctx).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // continue_flow edge cases
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn continue_flow_unknown_execution_id() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let result = executor
            .continue_flow(&config, &FlowStageId::new("unknown").unwrap(), &mut ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn continue_flow_challenge_preserved() {
        let auth = TestAuthenticator::new("auth", |_| {
            AuthStepResult::Challenge(Challenge::OtpForm {
                action_url: "/otp".to_string(),
            })
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await
            .unwrap();
        assert!(
            matches!(outcome, FlowOutcome::Challenge(Challenge::OtpForm { .. }, eid) if eid == FlowStageId::new("s1").unwrap())
        );
    }

    #[tokio::test]
    async fn continue_flow_failure_optional_continues() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Optional, "auth1", 1),
                stage("s2", Requirement::Required, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await
            .unwrap();
        assert_success(outcome);
    }

    #[tokio::test]
    async fn continue_flow_failure_required_returns_failure() {
        let auth =
            TestAuthenticator::new("auth", |_| AuthStepResult::Failure(IssuerdError::InvalidGrant));

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await
            .unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn continue_flow_attempted_optional_continues() {
        let auth1 = TestAuthenticator::new("auth1", |_| AuthStepResult::Attempted);
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Optional, "auth1", 1),
                stage("s2", Requirement::Required, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await
            .unwrap();
        assert_success(outcome);
    }

    #[tokio::test]
    async fn continue_flow_attempted_required_returns_failure() {
        let auth = TestAuthenticator::new("auth", |_| AuthStepResult::Attempted);

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await
            .unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::AccessDenied);
    }

    // -----------------------------------------------------------------------
    // Depth limit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn depth_limit_exceeded() {
        let auth = TestAuthenticator::new("auth", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        // Cover the closure body directly
        let mut ctx2 = test_auth_context();
        let _ = auth.authenticate(&mut ctx2).await;

        let mut reg = MockPluginRegistry::new();
        reg.expect_list_required_action_ids().return_const(vec![]);

        // Self-referencing sub-flow to trigger infinite recursion guard
        let sub = FlowConfig {
            alias: Alias::new("self").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("self").unwrap()),
                authenticator_config: None,
            }],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-top1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("self").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        assert_server_error(outcome);
    }

    // -----------------------------------------------------------------------
    // Sub-flow edge cases
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sub_flow_unknown_alias() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_list_required_action_ids().return_const(vec![]);

        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-top1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("missing").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let mut ctx = test_auth_context();
        let result = executor.execute(&top, &mut ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sub_flow_challenge_propagates() {
        let auth = TestAuthenticator::new("auth", |_| {
            AuthStepResult::Challenge(Challenge::OtpForm {
                action_url: "/otp".to_string(),
            })
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-top1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, FlowOutcome::Challenge(Challenge::OtpForm { .. }, eid) if eid == FlowStageId::new("s1").unwrap())
        );
    }

    #[tokio::test]
    async fn sub_flow_failure_required_propagates() {
        let auth =
            TestAuthenticator::new("auth", |_| AuthStepResult::Failure(IssuerdError::InvalidGrant));

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-top1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn sub_flow_failure_conditional_skips_scope() {
        let auth =
            TestAuthenticator::new("auth", |_| AuthStepResult::Failure(IssuerdError::InvalidGrant));

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Conditional, "auth", 1),
                stage("s2", Requirement::Conditional, "auth2", 2),
            ],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-top1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        // s1 fails conditional -> skip_conditional_scope=true -> s2 skipped -> no user_id -> AccessDenied
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::AccessDenied);
    }

    #[tokio::test]
    async fn sub_flow_failure_optional_continues() {
        let auth =
            TestAuthenticator::new("auth", |_| AuthStepResult::Failure(IssuerdError::InvalidGrant));
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Optional, "auth", 1),
                stage("s2", Requirement::Required, "auth2", 2),
            ],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-top1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        assert_success(outcome);
    }

    // -----------------------------------------------------------------------
    // Alternative group edge cases
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sub_flow_failure_alternative_propagates() {
        let auth =
            TestAuthenticator::new("auth", |_| AuthStepResult::Failure(IssuerdError::InvalidGrant));

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s-top1").unwrap(),
                requirement: Requirement::Alternative,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::InvalidGrant);
    }

    #[tokio::test]
    async fn alternative_challenge_propagates() {
        let auth = TestAuthenticator::new("auth", |_| {
            AuthStepResult::Challenge(Challenge::OtpForm {
                action_url: "/otp".to_string(),
            })
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Alternative, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, FlowOutcome::Challenge(Challenge::OtpForm { .. }, eid) if eid == FlowStageId::new("s1").unwrap())
        );
    }

    #[tokio::test]
    async fn alternative_all_attempted_returns_failure() {
        let auth = TestAuthenticator::new("auth", |_| AuthStepResult::Attempted);

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Alternative, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::AccessDenied);
    }

    // -----------------------------------------------------------------------
    // Optional / Conditional / Attempted edge cases (non-alternative, non-subflow)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn optional_stage_failure_continues() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Optional, "auth1", 1),
                stage("s2", Requirement::Required, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        assert_success(outcome);
    }

    #[tokio::test]
    async fn conditional_stage_failure_skips_scope() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Conditional, "auth1", 1),
                stage("s2", Requirement::Conditional, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        // s1 fails conditional -> skip s2 -> no user_id -> AccessDenied
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::AccessDenied);
    }

    #[tokio::test]
    async fn required_stage_attempted_fails() {
        let auth = TestAuthenticator::new("auth", |_| AuthStepResult::Attempted);

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let err = assert_failure(outcome);
        assert_eq!(err, IssuerdError::AccessDenied);
    }

    // -----------------------------------------------------------------------
    // Unknown authenticator
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unknown_authenticator_returns_failure() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("missing"))
            .returning(|_| Ok(None));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "missing", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        assert_invalid_request(outcome);
    }

    // -----------------------------------------------------------------------
    // finalize_outcome: required action None
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn finalize_required_action_none() {
        let auth = TestAuthenticator::new("auth", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec!["missing".to_string()]);
        reg.expect_get_required_action()
            .with(mockall::predicate::eq("missing"))
            .returning(|_| Ok(None));

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        assert_success(outcome);
    }

    #[tokio::test]
    async fn sub_flow_stage_conditional_failure_skips_scope() {
        let auth =
            TestAuthenticator::new("auth", |_| AuthStepResult::Failure(IssuerdError::InvalidGrant));
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                FlowStage {
                    id: FlowStageId::new("s-top1").unwrap(),
                    requirement: Requirement::Conditional,
                    authenticator: Alias::new("sub-flow").unwrap(),
                    priority: 1,
                    sub_flow_alias: Some(Alias::new("sub").unwrap()),
                    authenticator_config: None,
                },
                stage("s-top2", Requirement::Required, "auth2", 2),
            ],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        assert_success(outcome);
    }

    #[tokio::test]
    async fn sub_flow_stage_optional_failure_continues() {
        let auth =
            TestAuthenticator::new("auth", |_| AuthStepResult::Failure(IssuerdError::InvalidGrant));
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                FlowStage {
                    id: FlowStageId::new("s-top1").unwrap(),
                    requirement: Requirement::Optional,
                    authenticator: Alias::new("sub-flow").unwrap(),
                    priority: 1,
                    sub_flow_alias: Some(Alias::new("sub").unwrap()),
                    authenticator_config: None,
                },
                stage("s-top2", Requirement::Required, "auth2", 2),
            ],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        assert_success(outcome);
    }

    #[tokio::test]
    async fn alternative_group_inner_sub_flow_challenge_propagates() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth_sub = TestAuthenticator::new("auth-sub", |_| {
            AuthStepResult::Challenge(Challenge::OtpForm {
                action_url: "/otp".to_string(),
            })
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-sub"))
            .returning(move |_| Ok(Some(Arc::new(auth_sub.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth-sub", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s-top1", Requirement::Alternative, "auth1", 1),
                FlowStage {
                    id: FlowStageId::new("s-top2").unwrap(),
                    requirement: Requirement::Alternative,
                    authenticator: Alias::new("sub-flow").unwrap(),
                    priority: 2,
                    sub_flow_alias: Some(Alias::new("sub").unwrap()),
                    authenticator_config: None,
                },
            ],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, FlowOutcome::Challenge(Challenge::OtpForm { .. }, eid) if eid == FlowStageId::new("s1").unwrap())
        );
    }

    #[tokio::test]
    async fn alternative_group_inner_sub_flow_success_breaks() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth_sub = TestAuthenticator::new("auth-sub", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-sub"))
            .returning(move |_| Ok(Some(Arc::new(auth_sub.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth-sub", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s-top1", Requirement::Alternative, "auth1", 1),
                FlowStage {
                    id: FlowStageId::new("s-top2").unwrap(),
                    requirement: Requirement::Alternative,
                    authenticator: Alias::new("sub-flow").unwrap(),
                    priority: 2,
                    sub_flow_alias: Some(Alias::new("sub").unwrap()),
                    authenticator_config: None,
                },
            ],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        assert_success(outcome);
    }

    #[tokio::test]
    async fn alternative_group_inner_sub_flow_failure_then_next_succeeds() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth_sub = TestAuthenticator::new("auth-sub", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth3 = TestAuthenticator::new("auth3", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-sub"))
            .returning(move |_| Ok(Some(Arc::new(auth_sub.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth3"))
            .returning(move |_| Ok(Some(Arc::new(auth3.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth-sub", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s-top1", Requirement::Alternative, "auth1", 1),
                FlowStage {
                    id: FlowStageId::new("s-top2").unwrap(),
                    requirement: Requirement::Alternative,
                    authenticator: Alias::new("sub-flow").unwrap(),
                    priority: 2,
                    sub_flow_alias: Some(Alias::new("sub").unwrap()),
                    authenticator_config: None,
                },
                stage("s-top3", Requirement::Alternative, "auth3", 3),
            ],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&top, &mut ctx).await.unwrap();
        assert_success(outcome);
    }

    #[tokio::test]
    async fn finalize_outcome_registry_error_propagates() {
        let auth = TestAuthenticator::new("auth", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec!["bad".to_string()]);
        reg.expect_get_required_action()
            .with(mockall::predicate::eq("bad"))
            .returning(|_| Err(IssuerdError::ServerError("registry down".into())));

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let result = executor.execute(&config, &mut ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn alternative_group_unknown_subflow_alias() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("s1").unwrap(),
                requirement: Requirement::Alternative,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("nonexistent").unwrap()),
                authenticator_config: None,
            }],
        };
        let mut ctx = test_auth_context();
        let result = executor.execute(&config, &mut ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn continue_flow_disabled_stage_failure_continues() {
        let auth = TestAuthenticator::new("auth-dis", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-dis"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Disabled, "auth-dis", 1),
                stage("s2", Requirement::Required, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await
            .unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.user_id, UserId::new("alice").unwrap());
    }

    #[tokio::test]
    async fn continue_flow_disabled_stage_attempted_continues() {
        let auth = TestAuthenticator::new("auth-dis", |_| AuthStepResult::Attempted);
        let auth2 = TestAuthenticator::new("auth2", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth-dis"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(move |_| Ok(Some(Arc::new(auth2.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Disabled, "auth-dis", 1),
                stage("s2", Requirement::Required, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let outcome = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await
            .unwrap();
        let result = assert_success(outcome);
        assert_eq!(result.user_id, UserId::new("alice").unwrap());
    }

    #[tokio::test]
    async fn finalize_outcome_action_not_found() {
        let auth = TestAuthenticator::new("auth", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec!["missing".to_string()]);
        reg.expect_get_required_action()
            .with(mockall::predicate::eq("missing"))
            .returning(|_| Ok(None));

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let result = assert_success(outcome);
        assert!(result.required_actions.is_empty());
    }

    #[tokio::test]
    async fn test_authenticator_trait_methods() {
        let auth = TestAuthenticator::new("my-auth", |_| AuthStepResult::Success);
        assert_eq!(auth.id(), "my-auth");
        assert_eq!(auth.display_name(), "my-auth");
        assert!(!auth.requires_user());
        assert!(auth.configured_for(&test_auth_context()));
    }

    #[tokio::test]
    async fn test_required_action_trait_methods() {
        let action = TestRequiredAction::new("my-action");
        assert_eq!(action.id(), "my-action");
        assert_eq!(action.display_name(), "my-action");
        assert!(action.evaluate(&test_auth_context()).await);
        assert_action_success(action.process(&mut test_auth_context()).await);
    }

    #[test]
    fn mock_plugin_registry_list_authenticator_ids() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_list_authenticator_ids().return_const(vec!["a".to_string()]);
        let ids = reg.list_authenticator_ids();
        assert_eq!(ids, vec!["a".to_string()]);
    }

    // -----------------------------------------------------------------------
    // Error-propagation coverage for remaining branches
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn continue_flow_execute_stage_error() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(|_| Err(IssuerdError::ServerError("boom".into())));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let result = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn continue_flow_success_then_remaining_error() {
        let auth1 = TestAuthenticator::new("auth1", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(|_| Err(IssuerdError::ServerError("boom".into())));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Required, "auth1", 1),
                stage("s2", Requirement::Required, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let result = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn continue_flow_optional_failure_then_remaining_error() {
        let auth1 = TestAuthenticator::new("auth1", |_| {
            AuthStepResult::Failure(IssuerdError::InvalidGrant)
        });

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(|_| Err(IssuerdError::ServerError("boom".into())));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Optional, "auth1", 1),
                stage("s2", Requirement::Required, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let result = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn continue_flow_optional_attempted_then_remaining_error() {
        let auth1 = TestAuthenticator::new("auth1", |_| AuthStepResult::Attempted);

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth1"))
            .returning(move |_| Ok(Some(Arc::new(auth1.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth2"))
            .returning(|_| Err(IssuerdError::ServerError("boom".into())));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Optional, "auth1", 1),
                stage("s2", Requirement::Required, "auth2", 2),
            ],
        };
        let mut ctx = test_auth_context();
        let result = executor
            .continue_flow(&config, &FlowStageId::new("s1").unwrap(), &mut ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn execute_subflow_stage_error() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("sub-auth"))
            .returning(|_| Err(IssuerdError::ServerError("boom".into())));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("sub1", Requirement::Required, "sub-auth", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("top1").unwrap(),
                requirement: Requirement::Required,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let result = executor.execute(&top, &mut ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn alternative_group_subflow_error() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("sub-auth"))
            .returning(|_| Err(IssuerdError::ServerError("boom".into())));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("sub1", Requirement::Required, "sub-auth", 1)],
        };
        let top = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![FlowStage {
                id: FlowStageId::new("top1").unwrap(),
                requirement: Requirement::Alternative,
                authenticator: Alias::new("sub-flow").unwrap(),
                priority: 1,
                sub_flow_alias: Some(Alias::new("sub").unwrap()),
                authenticator_config: None,
            }],
        };

        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let mut ctx = test_auth_context();
        let result = executor.execute(&top, &mut ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn alternative_group_stage_error() {
        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(|_| Err(IssuerdError::ServerError("boom".into())));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Alternative, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let result = executor.execute(&config, &mut ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn alternative_group_second_stage_unknown_subflow_alias() {
        let auth =
            TestAuthenticator::new("auth", |_| AuthStepResult::Failure(IssuerdError::InvalidGrant));

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Alternative, "auth", 1),
                FlowStage {
                    id: FlowStageId::new("s2").unwrap(),
                    requirement: Requirement::Alternative,
                    authenticator: Alias::new("sub-flow").unwrap(),
                    priority: 2,
                    sub_flow_alias: Some(Alias::new("nonexistent").unwrap()),
                    authenticator_config: None,
                },
            ],
        };
        let mut ctx = test_auth_context();
        let result = executor.execute(&config, &mut ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn alternative_group_second_stage_subflow_error() {
        let auth =
            TestAuthenticator::new("auth", |_| AuthStepResult::Failure(IssuerdError::InvalidGrant));

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("sub-auth"))
            .returning(|_| Err(IssuerdError::ServerError("boom".into())));
        reg.expect_list_required_action_ids().return_const(vec![]);

        let sub = FlowConfig {
            alias: Alias::new("sub").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: false,
            built_in: true,
            stages: vec![stage("sub1", Requirement::Required, "sub-auth", 1)],
        };
        let executor = FlowExecutor::new(Arc::new(reg), &[sub]);
        let config = FlowConfig {
            alias: Alias::new("top").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![
                stage("s1", Requirement::Alternative, "auth", 1),
                FlowStage {
                    id: FlowStageId::new("s2").unwrap(),
                    requirement: Requirement::Alternative,
                    authenticator: Alias::new("sub-flow").unwrap(),
                    priority: 2,
                    sub_flow_alias: Some(Alias::new("sub").unwrap()),
                    authenticator_config: None,
                },
            ],
        };
        let mut ctx = test_auth_context();
        let result = executor.execute(&config, &mut ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn finalize_outcome_evaluate_false() {
        let auth = TestAuthenticator::new("auth", |ctx| {
            ctx.user_id = Some(UserId::new("alice").unwrap());
            AuthStepResult::Success
        });
        let _action = TestRequiredAction::new("skip-action");
        // Override evaluate to return false
        let action2 = TestRequiredAction {
            id: "skip-action".to_string(),
            evaluate_result: std::sync::Arc::new(std::sync::Mutex::new(Box::new(|_| false))),
        };

        let mut reg = MockPluginRegistry::new();
        reg.expect_get_authenticator()
            .with(mockall::predicate::eq("auth"))
            .returning(move |_| Ok(Some(Arc::new(auth.clone()))));
        reg.expect_list_required_action_ids()
            .return_const(vec!["skip-action".to_string()]);
        reg.expect_get_required_action()
            .with(mockall::predicate::eq("skip-action"))
            .returning(move |_| Ok(Some(Arc::new(action2.clone()))));

        let executor = FlowExecutor::new(Arc::new(reg), &[]);
        let config = FlowConfig {
            alias: Alias::new("browser").unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            stages: vec![stage("s1", Requirement::Required, "auth", 1)],
        };
        let mut ctx = test_auth_context();
        let outcome = executor.execute(&config, &mut ctx).await.unwrap();
        let result = assert_success(outcome);
        assert!(result.required_actions.is_empty());
    }
}
