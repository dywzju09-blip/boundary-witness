use serde::{Deserialize, Serialize};

use crate::{
    ActionSequence, ExperimentError, MinimizationTarget, ObjectiveClassification, ObjectiveKind,
    Result,
};

pub const D1_REPLAY_SUMMARY_SCHEMA_V01: &str = "boundary-witness.d1-replay-summary/0.1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayConfig {
    pub repeat_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySummary {
    pub schema_version: String,
    pub repeat_count: usize,
    pub success_count: usize,
    pub stable: bool,
    pub target: MinimizationTarget,
    pub attempts: Vec<ReplayAttempt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAttempt {
    pub attempt: usize,
    pub objective_kind: ObjectiveKind,
    pub primary_rule_id: Option<String>,
    pub normalized_signature: Option<String>,
    pub matched_target: bool,
}

pub fn replay_minimized<F>(
    sequence: &ActionSequence,
    target: &MinimizationTarget,
    config: ReplayConfig,
    mut evaluator: F,
) -> Result<ReplaySummary>
where
    F: FnMut(&ActionSequence) -> ObjectiveClassification,
{
    sequence.validate()?;
    if config.repeat_count == 0 {
        return Err(ExperimentError::InvalidInput(
            "replay repeat_count must be greater than zero".to_owned(),
        ));
    }

    let mut attempts = Vec::with_capacity(config.repeat_count);
    for attempt in 1..=config.repeat_count {
        let classification = evaluator(sequence);
        let matched_target = target.matches(&classification);
        attempts.push(ReplayAttempt {
            attempt,
            objective_kind: classification.objective_kind,
            primary_rule_id: classification.primary_rule_id,
            normalized_signature: classification.normalized_signature,
            matched_target,
        });
    }
    let success_count = attempts
        .iter()
        .filter(|attempt| attempt.matched_target)
        .count();
    Ok(ReplaySummary {
        schema_version: D1_REPLAY_SUMMARY_SCHEMA_V01.to_owned(),
        repeat_count: config.repeat_count,
        success_count,
        stable: success_count == config.repeat_count,
        target: target.clone(),
        attempts,
    })
}
