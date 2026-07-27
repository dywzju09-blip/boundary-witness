use std::{fs, path::Path};

use bw_experiment::{
    FinalizeRun, RunDirectory, RunMetadata, ToolchainVersions, verify_run_integrity,
};
use tempfile::tempdir;

fn metadata() -> RunMetadata {
    RunMetadata {
        git_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        deployment_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        image_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_owned(),
        config_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
        build_id: "d0-debug-test".to_owned(),
        host: "test-host".to_owned(),
        cpu_limit: Some(2),
        seed: Some(7),
        toolchains: ToolchainVersions {
            stable: "rustc 1.97.0".to_owned(),
            compiler_nightly: Some("nightly-2026-01-01".to_owned()),
        },
    }
}

fn write_minimal_evidence(run: &RunDirectory) {
    fs::write(run.traces_dir().join("trace.jsonl"), "{}\n").unwrap();
    fs::write(run.logs_dir().join("stdout.log"), "ok\n").unwrap();
}

fn finalize_fixture(root: &Path, run_id: &str) -> std::path::PathBuf {
    let run = RunDirectory::create(root, run_id, metadata()).unwrap();
    write_minimal_evidence(&run);

    run.finalize(FinalizeRun {
        summary: serde_json::json!({ "case": "smoke", "status": "ok" }),
        execution: None,
        required_trace_files: vec!["trace.jsonl".to_owned()],
        required_log_files: vec!["stdout.log".to_owned()],
    })
    .unwrap()
    .path()
    .to_path_buf()
}

#[test]
fn run_directory_is_partial_until_successful_finalization() {
    let temp = tempdir().unwrap();
    let run_id = "20260718T151500Z-0123456-a1b2c3d4";
    let run = RunDirectory::create(temp.path(), run_id, metadata()).unwrap();

    assert_eq!(run.run_id(), run_id);
    assert!(run.partial_path().exists());
    assert!(run.partial_path().ends_with(format!("{run_id}.partial")));
    assert_eq!(run.final_path(), temp.path().join(run_id));
    assert!(!run.final_path().exists());
    assert!(run.input_dir().is_dir());
    assert!(run.traces_dir().is_dir());
    assert!(run.artifacts_dir().is_dir());
    assert!(run.logs_dir().is_dir());
    assert!(run.findings_path().is_file());

    write_minimal_evidence(&run);
    let finalized = run
        .finalize(FinalizeRun {
            summary: serde_json::json!({ "case": "smoke", "status": "ok" }),
            execution: None,
            required_trace_files: vec!["trace.jsonl".to_owned()],
            required_log_files: vec!["stdout.log".to_owned()],
        })
        .unwrap();

    assert!(!finalized.path().ends_with(format!("{run_id}.partial")));
    assert!(finalized.path().join("manifest.json").is_file());
    assert!(finalized.path().join("summary.json").is_file());
    assert!(finalized.path().join("checksums.sha256").is_file());
    assert!(finalized.path().join("COMPLETE").is_file());
    verify_run_integrity(finalized.path()).unwrap();
}

#[test]
fn finalization_refuses_missing_required_trace() {
    let temp = tempdir().unwrap();
    let run =
        RunDirectory::create(temp.path(), "20260718T151501Z-0123456-a1b2c3d4", metadata()).unwrap();
    fs::write(run.logs_dir().join("stdout.log"), "ok\n").unwrap();

    let error = run
        .finalize(FinalizeRun {
            summary: serde_json::json!({ "case": "missing-trace" }),
            execution: None,
            required_trace_files: vec!["trace.jsonl".to_owned()],
            required_log_files: vec!["stdout.log".to_owned()],
        })
        .unwrap_err()
        .to_string();

    assert!(error.contains("missing required trace file"), "{error}");
}

#[test]
fn integrity_verification_fails_after_trace_delete_or_log_tamper() {
    let temp = tempdir().unwrap();
    let deleted_trace = finalize_fixture(temp.path(), "20260718T151502Z-0123456-a1b2c3d4");
    fs::remove_file(deleted_trace.join("traces/trace.jsonl")).unwrap();
    let error = verify_run_integrity(&deleted_trace)
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing checksummed file"), "{error}");

    let tampered_log = finalize_fixture(temp.path(), "20260718T151503Z-0123456-a1b2c3d4");
    fs::write(tampered_log.join("logs/stdout.log"), "tampered\n").unwrap();
    let error = verify_run_integrity(&tampered_log).unwrap_err().to_string();
    assert!(error.contains("checksum mismatch"), "{error}");
}
