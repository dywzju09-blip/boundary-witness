use std::{fs, path::PathBuf};

use bw_experiment::{D1_ROLLUP_SCHEMA_V01, summarize_d1_run_dirs};

#[test]
fn summarizes_multiple_d1_run_directories() {
    let temp = tempfile::tempdir().unwrap();
    let formal = temp.path().join("formal");
    let scalar = temp.path().join("scalar");
    fs::create_dir_all(&formal).unwrap();
    fs::create_dir_all(&scalar).unwrap();
    write_json(
        formal.join("summary.json"),
        r#"{
          "schema_version": "boundary-witness.d1-formal-summary/0.1",
          "campaign_count": 2,
          "primary_found_campaigns": 1,
          "safe_only": {"artifact_count": 0},
          "campaigns": [
            {
              "campaign_id": "d1-uh-formal-001",
              "outcome": "primary_found",
              "executions": 10,
              "valid_sequence_count": 7,
              "invalid_sequence_count": 3,
              "secondary_count": 2,
              "time_to_first_primary_ms": 125,
              "minimized_len": 6,
              "replay_success_count": 20
            },
            {
              "campaign_id": "d1-uh-formal-002",
              "outcome": "timeout",
              "executions": 5,
              "valid_sequence_count": 2,
              "invalid_sequence_count": 3,
              "secondary_count": 0,
              "time_to_first_primary_ms": null,
              "minimized_len": null,
              "replay_success_count": null
            }
          ]
        }"#,
    );
    write_json(
        scalar.join("summary.json"),
        r#"{
          "schema_version": "boundary-witness.d1-scalar-smoke-summary/0.1",
          "campaign_count": 1,
          "primary_found_campaigns": 1,
          "campaigns": [
            {
              "campaign_id": "d1-scalar-smoke-001",
              "outcome": "primary_found",
              "executions": 8,
              "valid_sequence_count": 4,
              "invalid_sequence_count": 4,
              "secondary_count": 1,
              "time_to_first_primary_ms": 250,
              "minimized_len": 5,
              "replay_success_count": 20
            }
          ]
        }"#,
    );

    let summary = summarize_d1_run_dirs(&[formal.clone(), scalar.clone()]).unwrap();

    assert_eq!(summary.schema_version, D1_ROLLUP_SCHEMA_V01);
    assert_eq!(summary.run_count, 2);
    assert_eq!(summary.campaign_count, 3);
    assert_eq!(summary.primary_success_campaigns, 2);
    assert_eq!(summary.timeout_campaigns, 1);
    assert_eq!(summary.secondary_count, 3);
    assert_eq!(summary.valid_sequence_ratio_ppm, 13 * 1_000_000 / 23);
    assert_eq!(summary.time_to_first_primary_ms.values, [125, 250]);
    assert_eq!(summary.minimized_len.values, [5, 6]);
    assert_eq!(summary.replay_success_count, 40);
    assert_eq!(summary.runs[0].path, formal);
    assert_eq!(summary.runs[1].path, scalar);
}

fn write_json(path: PathBuf, body: &str) {
    fs::write(path, body).unwrap();
}
