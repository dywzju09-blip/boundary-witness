use std::fs;

use bw_experiment::{
    ApiKind, D2_BASELINES_SCHEMA_V01, D2BaselineConfigFile, ObjectiveClassification, ObjectiveKind,
    RandomActionGenerator, RandomBaselineObservation, RandomBaselineRunner,
};
use tempfile::tempdir;

#[test]
fn fixed_seed_produces_same_action_sequence_and_different_seed_changes_it() {
    let mut left = RandomActionGenerator::new(11, ApiKind::UpdateHook, 12);
    let mut right = RandomActionGenerator::new(11, ApiKind::UpdateHook, 12);
    let mut different = RandomActionGenerator::new(12, ApiKind::UpdateHook, 12);

    assert_eq!(left.next_sequence(), right.next_sequence());
    assert_ne!(left.next_sequence(), different.next_sequence());
}

#[test]
fn random_baseline_stops_at_budget_and_counts_invalid_sequences() {
    let temp = tempdir().unwrap();
    let config = config_toml(temp.path().join("artifacts").display().to_string(), 3);
    let config = D2BaselineConfigFile::parse_toml(&config).unwrap();
    let mut calls = 0usize;

    let summary = RandomBaselineRunner::new(config.random_action.clone())
        .run(|_| {
            calls += 1;
            RandomBaselineObservation {
                valid_sequence: calls != 1,
                objective: none_objective(),
                replay_success_count: None,
                feedback_key: None,
            }
        })
        .unwrap();

    assert_eq!(calls, 3);
    assert_eq!(summary.executions, 3);
    assert_eq!(
        summary.valid_sequence_count + summary.invalid_sequence_count,
        summary.executions
    );
    assert!(summary.invalid_sequence_count > 0);
}

#[test]
fn primary_objective_is_saved_as_replayable_artifact() {
    let temp = tempdir().unwrap();
    let artifact_dir = temp.path().join("artifacts");
    let config = config_toml(artifact_dir.display().to_string(), 4);
    let config = D2BaselineConfigFile::parse_toml(&config).unwrap();
    let mut calls = 0usize;

    let summary = RandomBaselineRunner::new(config.random_action)
        .run(|_| {
            calls += 1;
            RandomBaselineObservation {
                valid_sequence: true,
                objective: if calls == 2 {
                    primary_objective()
                } else {
                    none_objective()
                },
                replay_success_count: if calls == 2 { Some(20) } else { None },
                feedback_key: Some("borrowed_retained".to_owned()),
            }
        })
        .unwrap();

    assert_eq!(summary.primary_count, 1);
    assert_eq!(summary.representative_artifact_paths.len(), 1);
    assert_eq!(summary.replay_success_count, Some(20));
    let artifact = fs::read_to_string(&summary.representative_artifact_paths[0]).unwrap();
    assert!(artifact.contains("boundary-witness.d1-artifact/0.1"));
    assert!(artifact.contains("BW-LIFE-002"));
}

#[test]
fn repository_d2_baseline_config_loads_without_answer_labels() {
    let config = D2BaselineConfigFile::parse_toml(include_str!(
        "../../../experiments/configs/d2-baselines.toml"
    ))
    .unwrap();

    assert_eq!(config.schema_version, D2_BASELINES_SCHEMA_V01);
    assert_eq!(config.random_action.api, ApiKind::UpdateHook);
    let public = format!("{config:?}").to_lowercase();
    for banned in ["cve", "vulnerable", "fixed", "expected"] {
        assert!(
            !public.contains(banned),
            "D2 baseline config leaked answer label {banned}: {public}"
        );
    }
}

fn config_toml(artifact_dir: String, execution_budget: u64) -> String {
    format!(
        r#"
schema_version = "boundary-witness.d2-baselines/0.1"
suite_id = "suite:d2-rusqlite-update-hook"
groups = ["random_action"]

[shared_budget]
campaign_count = 1
cpu_minutes = 10
seed_list = [7]
initial_corpus_digest = "1111111111111111111111111111111111111111111111111111111111111111"
max_sequence_len = 8
objective_policy_digest = "2222222222222222222222222222222222222222222222222222222222222222"
target_build_id = "build:d1:rusqlite:callback-lifecycle"
sanitizer = "asan"

[random_action]
baseline_id = "random-action-test"
api = "update_hook"
target = "update_hook_actions"
cpu_minutes = 10
max_sequence_len = 8
execution_budget = {execution_budget}
seed = 7
artifact_dir = "{artifact_dir}"
objective_config = "experiments/configs/d1-objectives.toml"
replay_repeat_count = 20
"#
    )
}

fn primary_objective() -> ObjectiveClassification {
    ObjectiveClassification {
        objective_kind: ObjectiveKind::Primary,
        primary_rule_id: Some("BW-LIFE-002".to_owned()),
        normalized_signature: Some("BW-LIFE-002|generic-callback-lifecycle".to_owned()),
        progress_states: vec!["BW-LIFE-003".to_owned()],
        secondary_findings: Vec::new(),
        evidence_refs: Vec::new(),
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
