use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use bw_experiment::{
    ActionSequence, D1CampaignOutcome, D1CampaignRecord, MinimizedArtifact, ReplaySummary,
};

#[test]
fn cli_minimizes_and_replays_update_hook_action_json() {
    let temp_dir = unique_temp_dir();
    fs::create_dir_all(&temp_dir).unwrap();
    let minimized_path = temp_dir.join("minimized.json");
    let replay_path = temp_dir.join("replay-summary.json");

    let input = repo_root().join("fixtures/fuzz/d1/update_hook/borrowed-complete.json");
    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-d1"))
            .arg("minimize")
            .arg(&input)
            .arg(&minimized_path),
    );
    let minimized: MinimizedArtifact =
        serde_json::from_str(&fs::read_to_string(&minimized_path).unwrap()).unwrap();
    assert!(minimized.witness_stages.has_register);

    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-d1"))
            .arg("replay")
            .arg(&minimized_path)
            .arg(&replay_path)
            .arg("--repeat")
            .arg("20"),
    );
    let replay: ReplaySummary =
        serde_json::from_str(&fs::read_to_string(&replay_path).unwrap()).unwrap();
    assert_eq!(replay.success_count, 20);
    assert!(replay.stable);

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn cli_minimizes_and_replays_scalar_function_action_json() {
    let temp_dir = unique_temp_dir();
    fs::create_dir_all(&temp_dir).unwrap();
    let minimized_path = temp_dir.join("minimized.json");
    let replay_path = temp_dir.join("replay-summary.json");

    let input = repo_root().join("fixtures/fuzz/d1/scalar-function/borrowed-complete.json");
    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-d1"))
            .arg("minimize")
            .arg("--api")
            .arg("create_scalar_function")
            .arg(&input)
            .arg(&minimized_path),
    );
    let minimized: MinimizedArtifact =
        serde_json::from_str(&fs::read_to_string(&minimized_path).unwrap()).unwrap();
    assert!(minimized.witness_stages.has_register);

    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-d1"))
            .arg("replay")
            .arg("--api")
            .arg("create_scalar_function")
            .arg(&minimized_path)
            .arg(&replay_path)
            .arg("--repeat")
            .arg("20"),
    );
    let replay: ReplaySummary =
        serde_json::from_str(&fs::read_to_string(&replay_path).unwrap()).unwrap();
    assert_eq!(replay.success_count, 20);
    assert!(replay.stable);

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn cli_decodes_raw_bytes_to_action_json() {
    let temp_dir = unique_temp_dir();
    fs::create_dir_all(&temp_dir).unwrap();
    let raw_path = temp_dir.join("input.bytes");
    let action_path = temp_dir.join("actions.json");
    fs::write(&raw_path, [0u8, 1, 2, 3, 0, 6, 7, 0]).unwrap();

    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-d1"))
            .arg("decode")
            .arg(&raw_path)
            .arg(&action_path),
    );
    let decoded =
        ActionSequence::from_json_str(&fs::read_to_string(&action_path).unwrap()).unwrap();
    assert!(!decoded.actions.is_empty());

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn cli_materializes_jsonl_corpus_to_raw_seed_files() {
    let temp_dir = unique_temp_dir();
    fs::create_dir_all(&temp_dir).unwrap();
    let corpus_jsonl = repo_root().join("experiments/corpus/d1/update-hook/safe-fragments.jsonl");
    let output_dir = temp_dir.join("corpus");

    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-d1"))
            .arg("materialize-corpus")
            .arg(&corpus_jsonl)
            .arg(&output_dir),
    );

    let mut seed_files = fs::read_dir(&output_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    seed_files.sort();
    assert_eq!(seed_files.len(), 3);

    for seed in seed_files {
        let raw = fs::read(seed).unwrap();
        let decoded = ActionSequence::decode_bytes(
            &raw,
            bw_experiment::ActionDecodeOptions {
                max_actions: 32,
                source: "test".to_owned(),
            },
        );
        decoded.validate().unwrap();
    }

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn cli_generates_d2_random_action_campaign_records() {
    let temp_dir = unique_temp_dir();
    fs::create_dir_all(&temp_dir).unwrap();
    let config_path = temp_dir.join("d2-random.toml");
    let records_root = temp_dir.join("records");
    fs::write(
        &config_path,
        r#"
schema_version = "boundary-witness.d2-baselines/0.1"
suite_id = "suite:d2-random-cli-test"
groups = ["random_action"]

[shared_budget]
campaign_count = 2
cpu_minutes = 1
seed_list = [1784401001, 1784401002]
initial_corpus_digest = "1111111111111111111111111111111111111111111111111111111111111111"
max_sequence_len = 8
objective_policy_digest = "2222222222222222222222222222222222222222222222222222222222222222"
target_build_id = "build:d2:test"
sanitizer = "asan"

[random_action]
baseline_id = "random-action-test"
api = "update_hook"
target = "update_hook_actions"
cpu_minutes = 1
max_sequence_len = 8
execution_budget = 3
seed = 1784401001
artifact_dir = "target/d2/test-random/artifacts"
objective_config = "experiments/configs/d1-objectives.toml"
sanitizer = "asan"
replay_repeat_count = 20
"#,
    )
    .unwrap();

    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-d1"))
            .arg("d2-random-records")
            .arg(&config_path)
            .arg(&records_root),
    );

    let records_path = records_root
        .join("random_action")
        .join("campaign-records.jsonl");
    let body = fs::read_to_string(records_path).unwrap();
    let records = body
        .lines()
        .map(|line| serde_json::from_str::<D1CampaignRecord>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].target, "update_hook_actions");
    assert_eq!(records[0].cpu_minutes, 1);
    assert_eq!(records[0].seed, 1784401001);
    assert_eq!(records[1].seed, 1784401002);

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn cli_generates_d2_coverage_artifact_campaign_record() {
    let temp_dir = unique_temp_dir();
    fs::create_dir_all(&temp_dir).unwrap();
    let config_path = temp_dir.join("d2-coverage.toml");
    let records_root = temp_dir.join("records");
    let campaign_dir = temp_dir.join("campaign-001");
    let artifact_dir = campaign_dir.join("artifacts");
    fs::create_dir_all(&artifact_dir).unwrap();
    write_d2_coverage_config(&config_path);
    write_counters(&campaign_dir.join("counters.json"), 7, 6, 1, 2, 0, 1, 11, 0);

    let fixture = repo_root().join("fixtures/fuzz/d1/update_hook/borrowed-complete.json");
    let sequence = ActionSequence::from_json_str(&fs::read_to_string(fixture).unwrap()).unwrap();
    fs::write(
        artifact_dir.join("crash-bw-life"),
        sequence.encode_seed_bytes(),
    )
    .unwrap();

    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-d1"))
            .arg("d2-coverage-record")
            .arg(&config_path)
            .arg("coverage_only")
            .arg(&records_root)
            .arg("1")
            .arg("1784401001")
            .arg(campaign_dir.join("counters.json"))
            .arg(&artifact_dir)
            .arg("77")
            .arg("1234"),
    );

    let records = read_d2_group_records(&records_root, "coverage_only");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].campaign_id, "coverage-only-test-001");
    assert_eq!(records[0].target, "update_hook_coverage_only");
    assert_eq!(records[0].seed, 1784401001);
    assert_eq!(records[0].executions, 7);
    assert_eq!(records[0].outcome, D1CampaignOutcome::PrimaryFound);
    assert_eq!(records[0].replay_success_count, Some(20));
    assert!(records[0].minimized_len.is_some());
    assert_eq!(
        records[0]
            .representative_artifact_digest
            .as_ref()
            .unwrap()
            .len(),
        64
    );
    assert!(campaign_dir.join("decoded-actions.json").exists());
    assert!(campaign_dir.join("minimized.json").exists());
    assert!(campaign_dir.join("replay-summary.json").exists());

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn cli_generates_d2_state_feedback_timeout_record_and_progress_coverage() {
    let temp_dir = unique_temp_dir();
    fs::create_dir_all(&temp_dir).unwrap();
    let config_path = temp_dir.join("d2-coverage.toml");
    let records_root = temp_dir.join("records");
    let campaign_dir = temp_dir.join("campaign-001");
    let artifact_dir = campaign_dir.join("artifacts");
    fs::create_dir_all(&artifact_dir).unwrap();
    write_d2_coverage_config(&config_path);
    write_counters(&campaign_dir.join("counters.json"), 5, 5, 0, 3, 1, 0, 0, 4);

    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-d1"))
            .arg("d2-coverage-record")
            .arg(&config_path)
            .arg("coverage_state")
            .arg(&records_root)
            .arg("1")
            .arg("1784401001")
            .arg(campaign_dir.join("counters.json"))
            .arg(&artifact_dir)
            .arg("0")
            .arg("600000"),
    );

    let records = read_d2_group_records(&records_root, "coverage_state");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].campaign_id, "coverage-state-test-001");
    assert_eq!(records[0].target, "update_hook_state_feedback");
    assert_eq!(records[0].outcome, D1CampaignOutcome::Timeout);
    assert_eq!(records[0].representative_artifact_digest, None);
    assert_eq!(
        fs::read_to_string(
            records_root
                .join("coverage_state")
                .join("progress-state-coverage.txt")
        )
        .unwrap(),
        "4\n"
    );

    fs::remove_dir_all(&temp_dir).unwrap();
}

fn assert_success(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_d2_group_records(records_root: &Path, group: &str) -> Vec<D1CampaignRecord> {
    let body = fs::read_to_string(records_root.join(group).join("campaign-records.jsonl")).unwrap();
    body.lines()
        .map(|line| serde_json::from_str::<D1CampaignRecord>(line).unwrap())
        .collect()
}

fn write_counters(
    path: &Path,
    executions: u64,
    valid: u64,
    invalid: u64,
    progress: u64,
    secondary: u64,
    primary: u64,
    time_to_first_primary_ms: u64,
    feedback_snapshot_coverage_count: u64,
) {
    let time_to_first = if time_to_first_primary_ms == 0 {
        serde_json::Value::Null
    } else {
        serde_json::Value::from(time_to_first_primary_ms)
    };
    fs::write(
        path,
        serde_json::json!({
            "schema_version": "boundary-witness.d1-fuzz-counters/0.1",
            "executions": executions,
            "valid_sequence_count": valid,
            "invalid_sequence_count": invalid,
            "progress_count": progress,
            "secondary_count": secondary,
            "primary_count": primary,
            "tool_error_count": 0,
            "time_to_first_primary_ms": time_to_first,
            "feedback_snapshot_coverage_count": feedback_snapshot_coverage_count
        })
        .to_string(),
    )
    .unwrap();
}

fn write_d2_coverage_config(path: &Path) {
    fs::write(
        path,
        r#"
schema_version = "boundary-witness.d2-baselines/0.1"
suite_id = "suite:d2-coverage-cli-test"
groups = ["coverage_only", "coverage_state"]

[shared_budget]
campaign_count = 1
cpu_minutes = 10
seed_list = [1784401001]
initial_corpus_digest = "1111111111111111111111111111111111111111111111111111111111111111"
max_sequence_len = 32
objective_policy_digest = "2222222222222222222222222222222222222222222222222222222222222222"
target_build_id = "build:d2:test"
sanitizer = "asan"

[random_action]
baseline_id = "random-action-test"
api = "update_hook"
target = "update_hook_actions"
cpu_minutes = 10
max_sequence_len = 32
execution_budget = 3
seed = 1784401001
artifact_dir = "target/d2/test-random/artifacts"
objective_config = "experiments/configs/d1-objectives.toml"
sanitizer = "asan"
replay_repeat_count = 20

[coverage_only]
baseline_id = "coverage-only-test"
api = "update_hook"
target = "update_hook_coverage_only"
cpu_minutes = 10
max_sequence_len = 32
initial_corpus = "target/d2/input/update-hook-corpus"
artifact_dir = "target/d2/coverage-only/artifacts"
objective_config = "experiments/configs/d1-objectives.toml"
sanitizer = "asan"
replay_repeat_count = 20
seed = 1784401001
contract_state_feedback = false

[coverage_state]
baseline_id = "coverage-state-test"
api = "update_hook"
target = "update_hook_state_feedback"
cpu_minutes = 10
max_sequence_len = 32
initial_corpus = "target/d2/input/update-hook-corpus"
artifact_dir = "target/d2/coverage-state/artifacts"
objective_config = "experiments/configs/d1-objectives.toml"
sanitizer = "asan"
replay_repeat_count = 20
seed = 1784401001
contract_state_feedback = true
"#,
    )
    .unwrap();
}

fn unique_temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "bw-d1-cli-test-{}-{}",
        std::process::id(),
        monotonic_nanos()
    ))
}

fn monotonic_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn repo_root() -> PathBuf {
    manifest_dir()
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

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}
