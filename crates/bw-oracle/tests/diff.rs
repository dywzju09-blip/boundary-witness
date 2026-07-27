mod common;

use bw_model::CheckpointKind;
use bw_oracle::{CheckpointCoverage, diff_findings, normalize_finding};
use common::sample_finding;

fn normalized(id: &str, semantic: &str) -> bw_oracle::NormalizedFinding {
    let mut finding = sample_finding(id);
    finding.normalized_signature = format!("BW-LIFE-002|{semantic}");
    normalize_finding(&finding).expect("finding should normalize")
}

fn complete_checkpoints() -> CheckpointCoverage {
    CheckpointCoverage::new([
        CheckpointKind::Registered,
        CheckpointKind::OwnerEndedOrReleased,
        CheckpointKind::LaterCallbackPhase,
    ])
}

#[test]
fn diff_is_deterministic_and_checkpoint_aware() {
    let first = normalized("a", "semantic:a");
    let shared = normalized("b", "semantic:b");
    let added = normalized("c", "semantic:c");
    let checkpoints = complete_checkpoints();

    let diff = diff_findings(
        &[shared.clone(), first.clone()],
        &[added.clone(), shared.clone()],
        &checkpoints,
        &checkpoints,
    );

    assert!(diff.comparable);
    assert_eq!(diff.added_signatures, vec![added.signature]);
    assert_eq!(diff.removed_signatures, vec![first.signature]);
    assert_eq!(diff.unchanged_signatures, vec![shared.signature]);
    assert!(diff.baseline_missing_checkpoints.is_empty());
    assert!(diff.candidate_missing_checkpoints.is_empty());
}

#[test]
fn missing_later_phase_makes_runs_non_comparable() {
    let baseline = complete_checkpoints();
    let candidate = CheckpointCoverage::new([
        CheckpointKind::Registered,
        CheckpointKind::OwnerEndedOrReleased,
    ]);

    let diff = diff_findings(&[], &[], &baseline, &candidate);

    assert!(!diff.comparable);
    assert_eq!(
        diff.candidate_missing_checkpoints,
        vec![CheckpointKind::LaterCallbackPhase]
    );
}
