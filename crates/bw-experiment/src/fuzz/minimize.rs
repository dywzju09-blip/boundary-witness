use serde::{Deserialize, Serialize};

use crate::{
    ActionSequence, ExperimentError, FuzzAction, ObjectiveClassification, ObjectiveKind, Result,
    SeedProvenance, SqlOp,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizationTarget {
    pub objective_kind: ObjectiveKind,
    pub primary_rule_id: Option<String>,
    pub normalized_signature: Option<String>,
}

impl MinimizationTarget {
    #[must_use]
    pub fn from_classification(classification: &ObjectiveClassification) -> Option<Self> {
        if classification.objective_kind != ObjectiveKind::Primary {
            return None;
        }
        Some(Self {
            objective_kind: classification.objective_kind,
            primary_rule_id: classification.primary_rule_id.clone(),
            normalized_signature: classification.normalized_signature.clone(),
        })
    }

    #[must_use]
    pub fn matches(&self, classification: &ObjectiveClassification) -> bool {
        classification.objective_kind == self.objective_kind
            && classification.primary_rule_id == self.primary_rule_id
            && classification.normalized_signature == self.normalized_signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizedArtifact {
    pub sequence: ActionSequence,
    pub classification: ObjectiveClassification,
    pub report: MinimizationReport,
    pub witness_stages: WitnessStages,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizationReport {
    pub original_len: usize,
    pub minimized_len: usize,
    pub attempts: usize,
    pub accepted: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStages {
    pub has_register: bool,
    pub has_owner_end: bool,
    pub has_later_trigger: bool,
}

pub fn minimize_actions<F>(
    sequence: &ActionSequence,
    target: &MinimizationTarget,
    mut evaluator: F,
) -> Result<MinimizedArtifact>
where
    F: FnMut(&ActionSequence) -> ObjectiveClassification,
{
    sequence.validate()?;
    let initial = evaluator(sequence);
    if !target.matches(&initial) {
        return Err(ExperimentError::InvalidInput(
            "initial sequence does not reproduce target objective".to_owned(),
        ));
    }

    let mut current = sequence.clone();
    let mut current_classification = initial;
    let mut attempts = 0;
    let mut accepted = 0;

    loop {
        let mut changed = false;
        for index in 0..current.actions.len() {
            let candidate = without_action(&current, index);
            attempts += 1;
            let classification = evaluator(&candidate);
            if target.matches(&classification) {
                current = candidate;
                current_classification = classification;
                accepted += 1;
                changed = true;
                break;
            }
        }
        if !changed {
            break;
        }
    }

    for index in 0..current.actions.len() {
        let FuzzAction::ExecuteSql { op } = current.actions[index] else {
            continue;
        };
        for replacement in [
            SqlOp::Insert,
            SqlOp::Update,
            SqlOp::Delete,
            SqlOp::SelectScalar,
        ] {
            if replacement == op {
                continue;
            }
            let candidate = with_sql_replacement(&current, index, replacement);
            attempts += 1;
            let classification = evaluator(&candidate);
            if target.matches(&classification) {
                current = candidate;
                current_classification = classification;
                accepted += 1;
                break;
            }
        }
    }

    let witness_stages = WitnessStages::from_sequence(&current);
    Ok(MinimizedArtifact {
        report: MinimizationReport {
            original_len: sequence.actions.len(),
            minimized_len: current.actions.len(),
            attempts,
            accepted,
        },
        sequence: current,
        classification: current_classification,
        witness_stages,
    })
}

impl WitnessStages {
    #[must_use]
    pub fn from_sequence(sequence: &ActionSequence) -> Self {
        let mut stages = Self::default();
        for action in &sequence.actions {
            match action {
                FuzzAction::RegisterBorrowed { .. } => {
                    stages.has_register = true;
                }
                FuzzAction::EndOwnerScope if stages.has_register => {
                    stages.has_owner_end = true;
                }
                FuzzAction::ExecuteSql { .. } if stages.has_owner_end => {
                    stages.has_later_trigger = true;
                }
                _ => {}
            }
        }
        stages
    }
}

fn without_action(sequence: &ActionSequence, index: usize) -> ActionSequence {
    let mut candidate = sequence.clone();
    candidate.actions.remove(index);
    mark_minimized(&mut candidate);
    candidate
}

fn with_sql_replacement(
    sequence: &ActionSequence,
    index: usize,
    replacement: SqlOp,
) -> ActionSequence {
    let mut candidate = sequence.clone();
    candidate.actions[index] = FuzzAction::ExecuteSql { op: replacement };
    mark_minimized(&mut candidate);
    candidate
}

fn mark_minimized(sequence: &mut ActionSequence) {
    sequence.provenance = SeedProvenance {
        kind: "minimized".to_owned(),
        name: sequence.provenance.name.clone(),
    };
}
