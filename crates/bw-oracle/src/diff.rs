use std::collections::BTreeSet;

use bw_model::{CheckpointKind, RuntimeEvent};
use serde::{Deserialize, Serialize};

use crate::NormalizedFinding;

const REQUIRED_CHECKPOINTS: [CheckpointKind; 3] = [
    CheckpointKind::Registered,
    CheckpointKind::OwnerEndedOrReleased,
    CheckpointKind::LaterCallbackPhase,
];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CheckpointCoverage {
    present: BTreeSet<CheckpointKind>,
}

impl CheckpointCoverage {
    #[must_use]
    pub fn new(checkpoints: impl IntoIterator<Item = CheckpointKind>) -> Self {
        Self {
            present: checkpoints.into_iter().collect(),
        }
    }

    pub fn observe(&mut self, event: &RuntimeEvent) {
        if let RuntimeEvent::Checkpoint(checkpoint) = event {
            self.present.insert(checkpoint.checkpoint);
        }
    }

    #[must_use]
    pub fn missing_required(&self) -> Vec<CheckpointKind> {
        REQUIRED_CHECKPOINTS
            .into_iter()
            .filter(|checkpoint| !self.present.contains(checkpoint))
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingDiff {
    pub comparable: bool,
    pub added_signatures: Vec<String>,
    pub removed_signatures: Vec<String>,
    pub unchanged_signatures: Vec<String>,
    pub baseline_missing_checkpoints: Vec<CheckpointKind>,
    pub candidate_missing_checkpoints: Vec<CheckpointKind>,
}

/// 对两个规范化 finding 集合进行确定性集合差分。
#[must_use]
pub fn diff_findings(
    baseline: &[NormalizedFinding],
    candidate: &[NormalizedFinding],
    baseline_checkpoints: &CheckpointCoverage,
    candidate_checkpoints: &CheckpointCoverage,
) -> FindingDiff {
    let baseline_signatures = baseline
        .iter()
        .map(|finding| finding.signature.clone())
        .collect::<BTreeSet<_>>();
    let candidate_signatures = candidate
        .iter()
        .map(|finding| finding.signature.clone())
        .collect::<BTreeSet<_>>();
    let baseline_missing_checkpoints = baseline_checkpoints.missing_required();
    let candidate_missing_checkpoints = candidate_checkpoints.missing_required();
    FindingDiff {
        comparable: baseline_missing_checkpoints.is_empty()
            && candidate_missing_checkpoints.is_empty(),
        added_signatures: candidate_signatures
            .difference(&baseline_signatures)
            .cloned()
            .collect(),
        removed_signatures: baseline_signatures
            .difference(&candidate_signatures)
            .cloned()
            .collect(),
        unchanged_signatures: baseline_signatures
            .intersection(&candidate_signatures)
            .cloned()
            .collect(),
        baseline_missing_checkpoints,
        candidate_missing_checkpoints,
    }
}
