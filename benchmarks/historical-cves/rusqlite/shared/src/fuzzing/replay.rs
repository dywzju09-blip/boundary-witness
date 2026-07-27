use bw_experiment::{
    minimize_actions, replay_minimized, ActionSequence, MinimizationTarget, MinimizedArtifact,
    ObjectiveClassification, ObjectiveClassifier, ObjectiveKind, ObjectiveObservation,
    ObjectivePolicy, ReplayConfig, ReplaySummary,
};
use bw_model::ExecutionEvidence;

use crate::fuzzing::{
    run_scalar_function_sequence, run_update_hook_sequence, HarnessError, HarnessRunResult,
};

pub fn evaluate_update_hook_objective(
    sequence: &ActionSequence,
) -> HarnessRunResult<ObjectiveClassification> {
    let result = run_update_hook_sequence(sequence)?;
    let findings = result.findings;
    Ok(classifier().classify(&ObjectiveObservation {
        evidence: evidence_from_findings(!findings.is_empty()),
        findings,
    }))
}

pub fn minimize_update_hook_sequence(
    sequence: &ActionSequence,
) -> HarnessRunResult<MinimizedArtifact> {
    let classification = evaluate_update_hook_objective(sequence)?;
    let target = MinimizationTarget::from_classification(&classification).ok_or_else(|| {
        HarnessError::new("update_hook sequence does not produce a primary objective")
    })?;

    minimize_actions(sequence, &target, |candidate| {
        evaluate_update_hook_objective(candidate).unwrap_or_else(|_| none_objective())
    })
    .map_err(|error| HarnessError::new(error.to_string()))
}

pub fn evaluate_scalar_function_objective(
    sequence: &ActionSequence,
) -> HarnessRunResult<ObjectiveClassification> {
    let result = run_scalar_function_sequence(sequence)?;
    let findings = result.findings;
    Ok(classifier().classify(&ObjectiveObservation {
        evidence: evidence_from_findings(!findings.is_empty()),
        findings,
    }))
}

pub fn minimize_scalar_function_sequence(
    sequence: &ActionSequence,
) -> HarnessRunResult<MinimizedArtifact> {
    let classification = evaluate_scalar_function_objective(sequence)?;
    let target = MinimizationTarget::from_classification(&classification).ok_or_else(|| {
        HarnessError::new("scalar function sequence does not produce a primary objective")
    })?;

    minimize_actions(sequence, &target, |candidate| {
        evaluate_scalar_function_objective(candidate).unwrap_or_else(|_| none_objective())
    })
    .map_err(|error| HarnessError::new(error.to_string()))
}

pub fn replay_scalar_function_sequence(
    sequence: &ActionSequence,
    classification: &ObjectiveClassification,
    config: ReplayConfig,
) -> HarnessRunResult<ReplaySummary> {
    let target = MinimizationTarget::from_classification(classification)
        .ok_or_else(|| HarnessError::new("replay requires a primary objective target"))?;
    replay_minimized(sequence, &target, config, |candidate| {
        evaluate_scalar_function_objective(candidate).unwrap_or_else(|_| none_objective())
    })
    .map_err(|error| HarnessError::new(error.to_string()))
}

pub fn replay_update_hook_sequence(
    sequence: &ActionSequence,
    classification: &ObjectiveClassification,
    config: ReplayConfig,
) -> HarnessRunResult<ReplaySummary> {
    let target = MinimizationTarget::from_classification(classification)
        .ok_or_else(|| HarnessError::new("replay requires a primary objective target"))?;
    replay_minimized(sequence, &target, config, |candidate| {
        evaluate_update_hook_objective(candidate).unwrap_or_else(|_| none_objective())
    })
    .map_err(|error| HarnessError::new(error.to_string()))
}

fn classifier() -> ObjectiveClassifier {
    ObjectiveClassifier::new(ObjectivePolicy::callback_lifetime_default())
}

fn evidence_from_findings(has_contract_finding: bool) -> ExecutionEvidence {
    ExecutionEvidence {
        has_contract_finding,
        has_asan_evidence: false,
        has_native_crash: false,
        has_panic: false,
        has_timeout: false,
    }
}

fn none_objective() -> ObjectiveClassification {
    ObjectiveClassification {
        objective_kind: ObjectiveKind::None,
        primary_rule_id: None,
        normalized_signature: None,
        progress_states: Vec::new(),
        secondary_findings: Vec::new(),
        evidence_refs: Vec::new(),
    }
}
