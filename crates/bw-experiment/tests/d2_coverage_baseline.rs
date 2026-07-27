use std::path::PathBuf;

use bw_experiment::{
    ApiKind, CoverageBaselineRunner, D1CampaignOutcome, D1CampaignRecord, D2BaselineConfigFile,
    ObjectiveClassification, ObjectiveKind, RandomBaselineKind, RandomBaselineSummary,
    coverage_only_saves_primary_artifact,
};

#[test]
fn coverage_only_config_cannot_enable_contract_state_feedback() {
    let mut config = D2BaselineConfigFile::parse_toml(include_str!(
        "../../../experiments/configs/d2-baselines.toml"
    ))
    .unwrap();
    let coverage = config
        .coverage_only
        .as_ref()
        .expect("repository config should include coverage-only group");
    assert!(!coverage.contract_state_feedback);

    config
        .coverage_only
        .as_mut()
        .unwrap()
        .contract_state_feedback = true;
    assert!(config.validate().is_err());
}

#[test]
fn coverage_only_target_still_exposes_primary_as_artifact() {
    assert!(coverage_only_saves_primary_artifact(&primary_objective()));
    assert!(!coverage_only_saves_primary_artifact(&none_objective()));
}

#[test]
fn coverage_only_summary_schema_matches_random_baseline_shape() {
    let config = D2BaselineConfigFile::parse_toml(include_str!(
        "../../../experiments/configs/d2-baselines.toml"
    ))
    .unwrap();
    let coverage = CoverageBaselineRunner::new(config.coverage_only.unwrap())
        .summarize_record(record())
        .unwrap();
    let random = RandomBaselineSummary {
        schema_version: "boundary-witness.d2-random-summary/0.1".to_owned(),
        baseline_kind: RandomBaselineKind::RandomAction,
        baseline_id: "random-action-small".to_owned(),
        api: ApiKind::UpdateHook,
        target: "update_hook_actions".to_owned(),
        seed: 1,
        cpu_minutes: 10,
        executions: 3,
        sequence_generation_count: 3,
        valid_sequence_count: 2,
        invalid_sequence_count: 1,
        progress_count: 0,
        secondary_count: 0,
        primary_count: 1,
        time_to_first_primary_ms: Some(7),
        minimized_len: Some(6),
        replay_success_count: Some(20),
        feedback_snapshot_coverage_count: 0,
        representative_artifact_digest: Some(hex_digest()),
        representative_artifact_paths: vec![PathBuf::from("artifact.json")],
    };

    let coverage_keys = object_keys(&coverage);
    let random_keys = object_keys(&random);

    for required in [
        "baseline_kind",
        "baseline_id",
        "api",
        "target",
        "executions",
        "valid_sequence_count",
        "invalid_sequence_count",
        "primary_count",
        "time_to_first_primary_ms",
        "minimized_len",
        "replay_success_count",
        "feedback_snapshot_coverage_count",
    ] {
        assert!(coverage_keys.contains(&required.to_owned()));
        assert!(random_keys.contains(&required.to_owned()));
    }
}

fn record() -> D1CampaignRecord {
    D1CampaignRecord {
        campaign_id: "coverage-only-0001".to_owned(),
        api: ApiKind::UpdateHook,
        target: "update_hook_coverage_only".to_owned(),
        seed: 1,
        cpu_minutes: 10,
        executions: 3,
        valid_sequence_count: 2,
        invalid_sequence_count: 1,
        progress_count: 0,
        secondary_count: 0,
        primary_count: 1,
        time_to_first_primary_ms: Some(7),
        minimized_len: Some(6),
        replay_success_count: Some(20),
        representative_artifact_digest: Some(hex_digest()),
        outcome: D1CampaignOutcome::PrimaryFound,
    }
}

fn primary_objective() -> ObjectiveClassification {
    ObjectiveClassification {
        objective_kind: ObjectiveKind::Primary,
        primary_rule_id: Some("BW-LIFE-002".to_owned()),
        normalized_signature: Some("BW-LIFE-002|generic-callback-lifecycle".to_owned()),
        progress_states: Vec::new(),
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

fn object_keys(value: &impl serde::Serialize) -> Vec<String> {
    let serde_json::Value::Object(object) = serde_json::to_value(value).unwrap() else {
        panic!("summary should serialize as object");
    };
    object.keys().cloned().collect()
}

fn hex_digest() -> String {
    "a".repeat(64)
}
