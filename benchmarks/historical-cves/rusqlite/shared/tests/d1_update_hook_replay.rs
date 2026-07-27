use std::{fs, path::PathBuf};

use bw_experiment::{ActionSequence, ObjectiveKind, ReplayConfig};
use rusqlite_lab_shared::fuzzing::{
    evaluate_update_hook_objective, minimize_update_hook_sequence, replay_update_hook_sequence,
};

#[test]
fn real_update_hook_harness_can_minimize_and_replay_primary_objective() {
    let sequence = load_sequence("fixtures/fuzz/d1/update_hook/borrowed-complete.json");
    let classification = evaluate_update_hook_objective(&sequence).unwrap();
    assert_eq!(classification.objective_kind, ObjectiveKind::Primary);
    assert_eq!(
        classification.primary_rule_id.as_deref(),
        Some("BW-LIFE-002")
    );

    let minimized = minimize_update_hook_sequence(&sequence).unwrap();
    assert!(minimized.witness_stages.has_register);
    assert!(minimized.witness_stages.has_owner_end);
    assert!(minimized.witness_stages.has_later_trigger);

    let summary = replay_update_hook_sequence(
        &minimized.sequence,
        &minimized.classification,
        ReplayConfig { repeat_count: 20 },
    )
    .unwrap();
    assert_eq!(summary.success_count, 20);
    assert!(summary.stable);
}

#[test]
fn owned_update_hook_fixture_is_not_a_primary_objective() {
    let sequence = load_sequence("fixtures/fuzz/d1/update_hook/owned-safe.json");
    let classification = evaluate_update_hook_objective(&sequence).unwrap();

    assert_eq!(classification.objective_kind, ObjectiveKind::None);
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
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
