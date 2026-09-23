// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

//! Static validation of a realm's authentication flow set.
//!
//! [`validate_flows`] runs the flow-set checks the admin API enforces before
//! persisting flow changes ("validation on save"). The whole set is validated
//! at once because sub-flow references and cycles cross flow boundaries. The
//! checks are deliberately pure — no async, no I/O: the [`PluginRegistry`]
//! authenticator lookup is driven synchronously, which is sound because
//! registry implementations are contractually cheap in-memory lookups (the
//! same invariant the `block_on_ready` idiom in `issuerd-storage::seed` and
//! `issuerd-admin-api::test_utils` relies on, except a pending lookup is reported
//! as an error instead of panicking).

use std::collections::{HashMap, HashSet};

use issuerd_core::{FlowConfig, Requirement};

use crate::plugin_registry::PluginRegistry;

/// Validate a realm's complete flow set, returning every problem found as a
/// human-readable string naming the flow alias (and stage, where applicable).
///
/// Checks, in order:
///
/// 1. Every stage with a `sub_flow_alias` references an alias present in
///    `flows`. Resolution mirrors the executor (`FlowExecutor::new` /
///    `executor.rs`): a last-duplicate-wins alias map, and `stage.authenticator`
///    is ignored — never resolved — while `sub_flow_alias` is `Some`.
/// 2. Every stage *without* a `sub_flow_alias` names an authenticator the
///    registry resolves (`registry.get_authenticator` returns `Some`).
/// 3. The sub-flow reference graph is acyclic (DFS with an in-stack set; the
///    error names the cycle path).
/// 4. Stage ids are unique within each flow.
/// 5. Every non-empty top-level flow has at least one non-`Disabled` stage
///    (otherwise the flow can never succeed). Empty top-level flows pass:
///    they are the legitimate intermediate state between flow creation and
///    adding executions (Keycloak's `addFlow` creates flows empty too).
///
/// Errors are collected, not short-circuited, and are returned in a
/// deterministic order (flow slice order, then stage order; cycle reports
/// last). `Ok(())` means the set is saveable.
pub fn validate_flows(
    flows: &[FlowConfig],
    registry: &dyn PluginRegistry,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Flow lookup mirroring `FlowExecutor::new`: later duplicates overwrite
    // earlier ones.
    let mut by_alias: HashMap<&str, &FlowConfig> = HashMap::new();
    for flow in flows {
        by_alias.insert(flow.alias.as_str(), flow);
    }

    for flow in flows {
        check_stages(flow, &by_alias, registry, &mut errors);
        check_duplicate_stage_ids(flow, &mut errors);
        check_top_level_has_enabled_stage(flow, &mut errors);
    }
    detect_cycles(flows, &by_alias, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Rules 1 and 2: sub-flow alias existence / authenticator existence.
fn check_stages(
    flow: &FlowConfig,
    by_alias: &HashMap<&str, &FlowConfig>,
    registry: &dyn PluginRegistry,
    errors: &mut Vec<String>,
) {
    for stage in &flow.stages {
        if let Some(alias) = &stage.sub_flow_alias {
            if !by_alias.contains_key(alias.as_str()) {
                errors.push(format!(
                    "flow '{}' stage '{}': unknown sub-flow alias '{alias}'",
                    flow.alias, stage.id
                ));
            }
            continue;
        }
        match authenticator_exists(registry, stage.authenticator.as_str()) {
            Ok(true) => {}
            Ok(false) => errors.push(format!(
                "flow '{}' stage '{}': unknown authenticator '{}'",
                flow.alias, stage.id, stage.authenticator
            )),
            Err(reason) => errors.push(format!(
                "flow '{}' stage '{}': failed to look up authenticator '{}': {reason}",
                flow.alias, stage.id, stage.authenticator
            )),
        }
    }
}

/// Rule 4: no duplicate `FlowStageId` within a single flow.
fn check_duplicate_stage_ids(flow: &FlowConfig, errors: &mut Vec<String>) {
    let mut seen = HashSet::new();
    for stage in &flow.stages {
        if !seen.insert(&stage.id) {
            errors.push(format!("flow '{}': duplicate stage id '{}'", flow.alias, stage.id));
        }
    }
}

/// Rule 5: a top-level flow that has stages but all are `Disabled` can never
/// succeed. An empty stage list is allowed: a newly created flow is empty
/// until executions are added, so rejecting it would make flow creation
/// impossible.
fn check_top_level_has_enabled_stage(flow: &FlowConfig, errors: &mut Vec<String>) {
    if flow.top_level
        && !flow.stages.is_empty()
        && flow.stages.iter().all(|s| s.requirement == Requirement::Disabled)
    {
        errors.push(format!(
            "top-level flow '{}' has no enabled stages; it can never succeed",
            flow.alias
        ));
    }
}

/// Rule 3: cycle detection over the sub-flow reference graph.
///
/// Only aliases that resolve to a flow in the set participate; dangling
/// aliases were already reported by [`check_stages`] and the executor errors
/// on them before recursing anyway.
fn detect_cycles(
    flows: &[FlowConfig],
    by_alias: &HashMap<&str, &FlowConfig>,
    errors: &mut Vec<String>,
) {
    let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
    for flow in flows {
        let targets: Vec<&str> = flow
            .stages
            .iter()
            .filter_map(|s| s.sub_flow_alias.as_deref())
            .filter(|alias| by_alias.contains_key(alias))
            .collect();
        adjacency.insert(flow.alias.as_str(), targets);
    }

    let mut marks: HashMap<&str, Mark> = HashMap::new();
    let mut path: Vec<&str> = Vec::new();
    for flow in flows {
        let alias = flow.alias.as_str();
        if !marks.contains_key(alias) {
            visit(alias, &adjacency, &mut marks, &mut path, errors);
        }
    }
}

/// DFS node mark: `InStack` while the node is on the current path (gray),
/// `Done` once fully explored (black).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    InStack,
    Done,
}

fn visit<'a>(
    alias: &'a str,
    adjacency: &HashMap<&'a str, Vec<&'a str>>,
    marks: &mut HashMap<&'a str, Mark>,
    path: &mut Vec<&'a str>,
    errors: &mut Vec<String>,
) {
    marks.insert(alias, Mark::InStack);
    path.push(alias);
    if let Some(targets) = adjacency.get(alias) {
        for target in targets {
            match marks.get(target) {
                Some(Mark::InStack) => {
                    let start = path.iter().position(|a| a == target).unwrap_or(0);
                    let mut cycle: Vec<&str> = path[start..].to_vec();
                    cycle.push(target);
                    errors.push(format!("sub-flow cycle detected: {}", cycle.join(" -> ")));
                }
                Some(Mark::Done) => {}
                None => visit(target, adjacency, marks, path, errors),
            }
        }
    }
    path.pop();
    marks.insert(alias, Mark::Done);
}

/// Look up an authenticator synchronously. `PluginRegistry` lookups are
/// contractually cheap and immediately ready (the production registry is an
/// in-memory map); a future that pends or fails is reported as `Err` so the
/// caller records a validation error rather than blocking or panicking.
fn authenticator_exists(registry: &dyn PluginRegistry, id: &str) -> Result<bool, String> {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut lookup = registry.get_authenticator(id);
    match lookup.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(Ok(found)) => Ok(found.is_some()),
        std::task::Poll::Ready(Err(e)) => Err(e.to_string()),
        std::task::Poll::Pending => {
            Err("registry lookup did not complete synchronously".to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use issuerd_core::{
        Alias, AuthContext, AuthStepResult, Authenticator, FlowStage, FlowStageId, IssuerdError,
        RealmId, RequiredAction,
    };

    use super::*;

    // -----------------------------------------------------------------------
    // Stub registry / authenticator
    // -----------------------------------------------------------------------

    struct StubAuthenticator;

    #[async_trait]
    impl Authenticator for StubAuthenticator {
        fn id(&self) -> &str {
            "stub"
        }
        fn display_name(&self) -> &str {
            "Stub"
        }
        fn requires_user(&self) -> bool {
            false
        }
        fn configured_for(&self, _ctx: &AuthContext) -> bool {
            true
        }
        async fn authenticate(&self, _ctx: &mut AuthContext) -> AuthStepResult {
            AuthStepResult::Attempted
        }
    }

    struct StubRegistry {
        authenticators: HashSet<&'static str>,
    }

    fn registry_with(known: &'static [&'static str]) -> StubRegistry {
        StubRegistry {
            authenticators: known.iter().copied().collect(),
        }
    }

    #[async_trait]
    impl PluginRegistry for StubRegistry {
        async fn get_authenticator(
            &self,
            id: &str,
        ) -> Result<Option<Arc<dyn Authenticator>>, IssuerdError> {
            Ok(self
                .authenticators
                .contains(id)
                .then(|| Arc::new(StubAuthenticator) as Arc<dyn Authenticator>))
        }

        async fn get_required_action(
            &self,
            _id: &str,
        ) -> Result<Option<Arc<dyn RequiredAction>>, IssuerdError> {
            Ok(None)
        }

        fn list_authenticator_ids(&self) -> Vec<String> {
            self.authenticators.iter().map(|s| (*s).to_string()).collect()
        }

        fn list_required_action_ids(&self) -> Vec<String> {
            Vec::new()
        }
    }

    // -----------------------------------------------------------------------
    // FlowConfig builders
    // -----------------------------------------------------------------------

    fn stage(id: &str, requirement: Requirement, authenticator: &str) -> FlowStage {
        FlowStage {
            id: FlowStageId::new(id).unwrap(),
            requirement,
            authenticator: Alias::new(authenticator).unwrap(),
            priority: 0,
            sub_flow_alias: None,
            authenticator_config: None,
        }
    }

    fn subflow_stage(id: &str, requirement: Requirement, target: &str) -> FlowStage {
        FlowStage {
            sub_flow_alias: Some(Alias::new(target).unwrap()),
            ..stage(id, requirement, "sub-flow")
        }
    }

    fn flow(alias: &str, top_level: bool, stages: Vec<FlowStage>) -> FlowConfig {
        FlowConfig {
            alias: Alias::new(alias).unwrap(),
            realm_id: RealmId::new("realm-1").unwrap(),
            provider_id: "basic-flow".to_string(),
            top_level,
            built_in: false,
            stages,
        }
    }

    // -----------------------------------------------------------------------
    // Table-driven cases
    // -----------------------------------------------------------------------

    struct Case {
        name: &'static str,
        flows: Vec<FlowConfig>,
        known_authenticators: &'static [&'static str],
        expected_errors: Vec<String>,
    }

    fn cases() -> Vec<Case> {
        vec![
            Case {
                name: "valid set passes (sub-flow ref, ignored authenticator, cross-flow id reuse)",
                flows: vec![
                    flow(
                        "browser",
                        true,
                        vec![
                            stage("s1", Requirement::Required, "auth-cookie"),
                            // `sub-flow` is not a registered authenticator, but the
                            // executor never resolves it while sub_flow_alias is Some.
                            subflow_stage("s2", Requirement::Required, "forms"),
                        ],
                    ),
                    // Stage id `s1` reused across flows is fine (rule 4 is per-flow).
                    flow("forms", false, vec![stage("s1", Requirement::Required, "auth-forms")]),
                    // All-disabled is only an error for top-level flows.
                    flow(
                        "disabled-sub",
                        false,
                        vec![stage("d1", Requirement::Disabled, "auth-forms")],
                    ),
                ],
                known_authenticators: &["auth-cookie", "auth-forms"],
                expected_errors: vec![],
            },
            Case {
                name: "unknown sub-flow alias",
                flows: vec![flow(
                    "browser",
                    true,
                    vec![subflow_stage("s1", Requirement::Required, "missing")],
                )],
                known_authenticators: &[],
                expected_errors: vec![
                    "flow 'browser' stage 's1': unknown sub-flow alias 'missing'".to_string(),
                ],
            },
            Case {
                name: "unknown authenticator",
                flows: vec![flow(
                    "browser",
                    true,
                    vec![stage("s1", Requirement::Required, "auth-nope")],
                )],
                known_authenticators: &["auth-cookie"],
                expected_errors: vec![
                    "flow 'browser' stage 's1': unknown authenticator 'auth-nope'".to_string(),
                ],
            },
            Case {
                name: "disabled stage still validates its authenticator",
                flows: vec![flow(
                    "browser",
                    true,
                    vec![
                        stage("s1", Requirement::Disabled, "auth-nope"),
                        stage("s2", Requirement::Required, "auth-cookie"),
                    ],
                )],
                known_authenticators: &["auth-cookie"],
                expected_errors: vec![
                    "flow 'browser' stage 's1': unknown authenticator 'auth-nope'".to_string(),
                ],
            },
            Case {
                name: "two-flow cycle",
                flows: vec![
                    flow("a", false, vec![subflow_stage("s1", Requirement::Required, "b")]),
                    flow("b", false, vec![subflow_stage("s1", Requirement::Required, "a")]),
                ],
                known_authenticators: &[],
                expected_errors: vec!["sub-flow cycle detected: a -> b -> a".to_string()],
            },
            Case {
                name: "self cycle",
                flows: vec![flow(
                    "loop",
                    false,
                    vec![subflow_stage("s1", Requirement::Required, "loop")],
                )],
                known_authenticators: &[],
                expected_errors: vec!["sub-flow cycle detected: loop -> loop".to_string()],
            },
            Case {
                name: "duplicate stage id within one flow",
                flows: vec![flow(
                    "browser",
                    true,
                    vec![
                        stage("s1", Requirement::Required, "auth-cookie"),
                        stage("s1", Requirement::Optional, "auth-cookie"),
                    ],
                )],
                known_authenticators: &["auth-cookie"],
                expected_errors: vec!["flow 'browser': duplicate stage id 's1'".to_string()],
            },
            Case {
                name: "top-level flow with all stages disabled",
                flows: vec![flow(
                    "browser",
                    true,
                    vec![stage("s1", Requirement::Disabled, "auth-cookie")],
                )],
                known_authenticators: &["auth-cookie"],
                expected_errors: vec![
                    "top-level flow 'browser' has no enabled stages; it can never succeed"
                        .to_string(),
                ],
            },
            Case {
                name: "empty top-level flow passes (intermediate state before adding executions)",
                flows: vec![flow("browser", true, vec![])],
                known_authenticators: &[],
                expected_errors: vec![],
            },
            Case {
                name: "all errors are collected, not short-circuited",
                flows: vec![
                    flow(
                        "browser",
                        true,
                        vec![
                            stage("s1", Requirement::Required, "auth-nope"),
                            stage("s1", Requirement::Required, "auth-cookie"),
                            subflow_stage("s2", Requirement::Required, "missing"),
                        ],
                    ),
                    flow("a", false, vec![subflow_stage("x", Requirement::Required, "a")]),
                ],
                known_authenticators: &["auth-cookie"],
                expected_errors: vec![
                    "flow 'browser' stage 's1': unknown authenticator 'auth-nope'".to_string(),
                    "flow 'browser' stage 's2': unknown sub-flow alias 'missing'".to_string(),
                    "flow 'browser': duplicate stage id 's1'".to_string(),
                    "sub-flow cycle detected: a -> a".to_string(),
                ],
            },
        ]
    }

    #[test]
    fn validate_flows_table_driven() {
        for case in cases() {
            let registry = registry_with(case.known_authenticators);
            let result = validate_flows(&case.flows, &registry);
            if case.expected_errors.is_empty() {
                assert!(result.is_ok(), "case '{}' expected Ok, got {:?}", case.name, result);
            } else {
                let errors = result.expect_err("expected validation errors");
                assert_eq!(errors, case.expected_errors, "case '{}'", case.name);
            }
        }
    }
}
