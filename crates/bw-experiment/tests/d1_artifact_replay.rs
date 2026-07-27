use std::{fs, path::PathBuf};

use bw_experiment::{
    ActionSequence, ApiKind, D1ArtifactRecord, FuzzAction, MinimizationTarget,
    ObjectiveClassification, ObjectiveKind, ReplayConfig, minimize_actions, replay_minimized,
};

#[test]
fn artifact_record_has_stable_digest_and_roundtrips() {
    let sequence = load_sequence("fixtures/fuzz/d1/artifacts/redundant-update-hook.json");
    let objective = witness_objective();

    let artifact = D1ArtifactRecord::new(
        "campaign:test",
        ApiKind::UpdateHook,
        b"raw-libfuzzer-bytes",
        sequence.clone(),
        objective.clone(),
    )
    .unwrap();

    assert_eq!(artifact.artifact_digest.len(), 64);
    assert_eq!(artifact.raw_input_sha256.len(), 64);
    assert_eq!(artifact.decoded_actions, sequence);
    assert_eq!(
        artifact.objective.primary_rule_id.as_deref(),
        Some("BW-LIFE-002")
    );

    let json = serde_json::to_string(&artifact).unwrap();
    let parsed = D1ArtifactRecord::from_json_str(&json).unwrap();
    assert_eq!(parsed, artifact);
}

#[test]
fn reducer_removes_redundant_actions_but_preserves_witness_stages() {
    let sequence = load_sequence("fixtures/fuzz/d1/artifacts/redundant-update-hook.json");
    let target = MinimizationTarget::from_classification(&witness_objective()).unwrap();

    let minimized = minimize_actions(&sequence, &target, fake_update_hook_evaluator).unwrap();

    assert!(minimized.sequence.actions.len() < sequence.actions.len());
    assert!(minimized.witness_stages.has_register);
    assert!(minimized.witness_stages.has_owner_end);
    assert!(minimized.witness_stages.has_later_trigger);
    assert_eq!(
        minimized.classification.primary_rule_id.as_deref(),
        Some("BW-LIFE-002")
    );
    assert_eq!(
        minimized.classification.normalized_signature.as_deref(),
        Some("BW-LIFE-002|semantic:d1:update:borrowed-capture")
    );
}

#[test]
fn replay_requires_stable_objective_across_all_attempts() {
    let sequence = load_sequence("fixtures/fuzz/d1/artifacts/redundant-update-hook.json");
    let target = MinimizationTarget::from_classification(&witness_objective()).unwrap();
    let minimized = minimize_actions(&sequence, &target, fake_update_hook_evaluator).unwrap();

    let summary = replay_minimized(
        &minimized.sequence,
        &target,
        ReplayConfig { repeat_count: 20 },
        fake_update_hook_evaluator,
    )
    .unwrap();

    assert_eq!(summary.repeat_count, 20);
    assert_eq!(summary.success_count, 20);
    assert!(summary.stable);
}

fn fake_update_hook_evaluator(sequence: &ActionSequence) -> ObjectiveClassification {
    let mut saw_borrowed_register = false;
    let mut saw_owner_end_after_register = false;
    for action in &sequence.actions {
        match action {
            FuzzAction::RegisterBorrowed {
                api: ApiKind::UpdateHook,
            } => saw_borrowed_register = true,
            FuzzAction::EndOwnerScope if saw_borrowed_register => {
                saw_owner_end_after_register = true;
            }
            FuzzAction::ExecuteSql {
                op:
                    bw_experiment::SqlOp::Insert
                    | bw_experiment::SqlOp::Update
                    | bw_experiment::SqlOp::Delete,
            } if saw_owner_end_after_register => {
                return witness_objective();
            }
            _ => {}
        }
    }
    ObjectiveClassification {
        objective_kind: ObjectiveKind::None,
        primary_rule_id: None,
        normalized_signature: None,
        progress_states: Vec::new(),
        secondary_findings: Vec::new(),
        evidence_refs: Vec::new(),
    }
}

fn witness_objective() -> ObjectiveClassification {
    ObjectiveClassification {
        objective_kind: ObjectiveKind::Primary,
        primary_rule_id: Some("BW-LIFE-002".to_owned()),
        normalized_signature: Some("BW-LIFE-002|semantic:d1:update:borrowed-capture".to_owned()),
        progress_states: vec!["BW-LIFE-003".to_owned()],
        secondary_findings: Vec::new(),
        evidence_refs: Vec::new(),
    }
}

fn load_sequence(relative: &str) -> ActionSequence {
    ActionSequence::from_json_str(&fs::read_to_string(repo_root().join(relative)).unwrap()).unwrap()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
