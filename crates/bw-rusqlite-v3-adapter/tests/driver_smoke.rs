use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

use bw_blind_model::{BlindCaseObservation, BlindCaseStatus};
use tempfile::TempDir;

#[test]
fn driver_writes_clean_observation_for_empty_findings() {
    let fixture = Fixture::new(fake_bw_clean_script());

    let output = Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-v3-adapter"))
        .env("BW_RUSQLITE_V3_CASE_ROOT", &fixture.case_root)
        .env("BW_BLIND_CASE_ID", "blind-0123456789abcdef")
        .env("BW_BLIND_SUITE_ID", "suite.rusqlite.m12")
        .env("BW_BLIND_SPLIT", "gate")
        .env(
            "BW_BLIND_METHOD_COMMIT",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .env("BW_BLIND_MANIFEST_SHA256", "a".repeat(64))
        .env("BW_CHILD_WORK_DIR", &fixture.work_root)
        .output()
        .expect("adapter should start");

    assert!(
        output.status.success(),
        "adapter failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let observation =
        BlindCaseObservation::from_path(fixture.work_root.join("observation.json")).unwrap();
    assert_eq!(observation.status, BlindCaseStatus::Completed);
    assert!(observation.findings.is_empty());
    assert!(observation.witness.is_none());
    observation.validate(20).unwrap();
}

#[test]
fn driver_replays_confirmed_finding_and_writes_witness() {
    let fixture = Fixture::new(fake_bw_confirmed_script());

    let output = Command::new(env!("CARGO_BIN_EXE_bw-rusqlite-v3-adapter"))
        .env("BW_RUSQLITE_V3_CASE_ROOT", &fixture.case_root)
        .env("BW_BLIND_CASE_ID", "blind-0123456789abcdef")
        .env("BW_BLIND_SUITE_ID", "suite.rusqlite.m12")
        .env("BW_BLIND_SPLIT", "gate")
        .env(
            "BW_BLIND_METHOD_COMMIT",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .env("BW_BLIND_MANIFEST_SHA256", "a".repeat(64))
        .env("BW_CHILD_WORK_DIR", &fixture.work_root)
        .output()
        .expect("adapter should start");

    assert!(
        output.status.success(),
        "adapter failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let observation =
        BlindCaseObservation::from_path(fixture.work_root.join("observation.json")).unwrap();
    assert_eq!(observation.status, BlindCaseStatus::Completed);
    assert_eq!(observation.findings.len(), 1);
    let witness = observation.witness.as_ref().unwrap();
    assert_eq!(witness.artifact_path, "witness/witness.json");
    assert_eq!(witness.replay_attempts, 20);
    assert_eq!(witness.replay_successes, 20);
    observation.validate(20).unwrap();
    assert!(fixture.work_root.join("witness/witness.json").is_file());
    assert!(
        fixture
            .work_root
            .join("attempts/19/findings.jsonl")
            .is_file()
    );
}

struct Fixture {
    _root: TempDir,
    case_root: std::path::PathBuf,
    work_root: std::path::PathBuf,
}

impl Fixture {
    fn new(fake_bw: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let case_root = root.path().join("case");
        let work_root = root.path().join("work");
        fs::create_dir_all(case_root.join("payload/bin")).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        write_executable(&case_root.join("payload/bin/case"), fake_case_script());
        write_executable(&case_root.join("payload/bin/bw"), fake_bw);
        fs::write(case_root.join("payload/static-facts.jsonl"), static_facts()).unwrap();
        fs::write(
            case_root.join("payload/contract.toml"),
            "schema_version = \"test\"\n",
        )
        .unwrap();
        Self {
            _root: root,
            case_root,
            work_root,
        }
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn fake_case_script() -> &'static str {
    r#"#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$BW_TRACE_DIR"
cat > "$BW_TRACE_DIR/trace-index.json" <<'JSON'
{"schema_version":"bw.trace-index/0.1","segments":[{"path":"trace-0000.jsonl","compressed":false,"event_start":0,"event_count":0}]}
JSON
: > "$BW_TRACE_DIR/trace-0000.jsonl"
"#
}

fn fake_bw_clean_script() -> &'static str {
    r#"#!/usr/bin/env bash
set -euo pipefail
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[[ -n "$output" ]]
: > "$output"
"#
}

fn fake_bw_confirmed_script() -> &'static str {
    r#"#!/usr/bin/env bash
set -euo pipefail
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[[ -n "$output" ]]
cat > "$output" <<'JSON'
{"schema_version":"bw.finding/0.1","record_id":"finding:test","rule_id":"callback-retention.uaf","classification":"confirmed_violation","subject_object":null,"subject_callback":null,"first_violation_event":"record:event","evidence":[{"record_id":"record:event","source_kind":"runtime_event","description_code":"test"}],"context_rule_ids":[],"state_before":{"object_state":null,"capture_state":null,"callback_state":null,"owner_state":null},"state_after":{"object_state":null,"capture_state":null,"callback_state":null,"owner_state":null},"normalized_signature":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","producer":"test","build_id":"build:test","run_id":"run:test","message":"confirmed"}
JSON
exit 1
"#
}

fn static_facts() -> &'static str {
    r#"{"schema_version":"bw.static/0.1","record_id":"fact:callback","producer":"test","build_id":"build:test","payload":{"kind":"callback_site","site_id":"site:callback","semantic_site_key":"semantic:callback","def_path":"main::{closure#0}"}}
"#
}
