// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Typed wrapper around FlowExecutor mapping untyped outcomes to typed ones at the boundary.

use issuerd_core::typestate::{
    ActionsPending, AnonymousState, AuthenticatedState, TypedAuthContext, TypedFlowResult,
};
use issuerd_core::{AuthContext, FlowConfig, IssuerdError};

use super::flow_output::{ErasedPausedFlow, FlowOutput};
use crate::executor::{FlowExecutor, FlowOutcome};

/// Typed wrapper around `FlowExecutor`.
///
/// Delegates all execution logic to the inner executor and maps untyped
/// outcomes to typed ones at the boundary.
#[derive(Clone)]
pub struct TypedFlowExecutor {
    inner: FlowExecutor,
}

impl TypedFlowExecutor {
    /// Wrap an existing `FlowExecutor`.
    pub fn new(inner: FlowExecutor) -> Self {
        Self { inner }
    }

    /// Execute a flow with a typed anonymous context.
    pub async fn execute(
        &self,
        flow_config: &FlowConfig,
        ctx: TypedAuthContext<AnonymousState>,
    ) -> Result<FlowOutput, IssuerdError> {
        let mut untyped_ctx = ctx.into_untyped();
        let outcome = self.inner.execute(flow_config, &mut untyped_ctx).await?;
        Self::map_outcome(outcome, untyped_ctx)
    }

    /// Continue a paused flow with a typed anonymous context.
    pub async fn continue_flow(
        &self,
        flow_config: &FlowConfig,
        execution_id: &issuerd_core::FlowStageId,
        ctx: TypedAuthContext<AnonymousState>,
    ) -> Result<FlowOutput, IssuerdError> {
        let mut untyped_ctx = ctx.into_untyped();
        let outcome = self.inner.continue_flow(flow_config, execution_id, &mut untyped_ctx).await?;
        Self::map_outcome(outcome, untyped_ctx)
    }

    pub(crate) fn map_outcome(
        outcome: FlowOutcome,
        untyped_ctx: AuthContext,
    ) -> Result<FlowOutput, IssuerdError> {
        match outcome {
            FlowOutcome::Success(result) => {
                let typed_ctx =
                    TypedAuthContext::<AuthenticatedState>::try_from_untyped(untyped_ctx)?;
                let typed_result = TypedFlowResult::<ActionsPending>::new_pending(
                    result.user_id,
                    result.session_id,
                    result.required_actions,
                );
                Ok(FlowOutput::Success {
                    ctx: Box::new(typed_ctx),
                    result: Box::new(typed_result),
                })
            }
            FlowOutcome::Challenge(challenge, execution_id) => Ok(FlowOutput::Challenge {
                // Surface the paused context's user id: the OTP stage pauses
                // AFTER the password stage authenticated the user, and the
                // login handler must re-seed it when the flow resumes.
                paused: ErasedPausedFlow::new(execution_id, challenge)
                    .with_user_id(untyped_ctx.user_id),
            }),
            FlowOutcome::Failure(e) => Ok(FlowOutput::Failure(e)),
        }
    }
}
