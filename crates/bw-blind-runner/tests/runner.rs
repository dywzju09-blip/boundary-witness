use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::sync::Mutex;

use bw_blind_model::{
    BLIND_INSTALL_RECEIPT_SCHEMA_V01, BLIND_POLICY_SCHEMA_V01, BLIND_PUBLIC_SCHEMA_V01,
    BlindCaseId, BlindCaseObservation, BlindCaseStatus, BlindCommandSpec, BlindPolicy,
    BlindPublicCase, BlindPublicManifest, BlindSplit, FormalIsolationBackend, InstallReceipt,
    MANDATORY_FORBIDDEN_PUBLIC_TOKENS, TestReceiptKey,
};
use bw_blind_runner::{RunOptions, run_public_pack};
use bw_experiment::{RunMetadata, ToolchainVersions, verify_run_integrity};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const CASE_ID: &str = "blind-8f34a923d01c77ab";
const SECOND_CASE_ID: &str = "blind-0123456789abcdef";
const METHOD_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const WITNESS_CONTENT: &str = "synthetic witness\n";
const RECEIPT_SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[cfg(target_os = "linux")]
static ENVIRONMENT_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn rejects_dynamic_forbidden_marker_in_observation_output() {
    let fixture = Fixture::new_with_install_receipt()
        .with_adapter_script("printf '%s%s' 'gh' 'sa-' > \"$BW_CHILD_WORK_DIR/observation.json\"");
    let error = run_public_pack(fixture.options())
        .err()
        .unwrap()
        .to_string();
    assert_output_scan_rejected_before_finalize(&fixture, &error);
}

#[test]
fn rejects_dynamic_forbidden_marker_in_stdout_stderr_and_witness() {
    for channel in ["stdout", "stderr", "witness"] {
        let fixture = Fixture::new_with_install_receipt().with_dynamic_leak_channel(channel);
        let error = run_public_pack(fixture.options())
            .err()
            .unwrap()
            .to_string();
        assert_output_scan_rejected_before_finalize(&fixture, &error);
    }
}

#[test]
fn rejects_forbidden_metadata_host_after_writing_final_candidate_artifacts() {
    let fixture = Fixture::new_with_install_receipt().with_forbidden_policy_token("candidate-host");
    let mut options = fixture.options();
    options.metadata.host = "candidate-host".to_owned();

    let error = run_public_pack(options)
        .err()
        .expect("forbidden metadata host must reject the final candidate")
        .to_string();

    assert!(
        error.contains("runner output contains forbidden token"),
        "{error}"
    );
    assert!(
        fixture.adapter_execution_marker.exists(),
        "the normal adapter must run before final-candidate scanning"
    );
    let partial = partial_artifacts(&fixture);
    assert!(
        partial.join("blind-runner-receipt.json").is_file(),
        "the runner receipt must be written before final-candidate scanning"
    );
    assert!(
        partial.join("observations.jsonl").is_file(),
        "observations must be written before final-candidate scanning"
    );
}

#[test]
fn rejects_forbidden_summary_content_before_finalize() {
    let fixture = Fixture::new_with_install_receipt().with_forbidden_policy_token("finalized");

    let error = run_public_pack(fixture.options())
        .err()
        .expect("forbidden summary content must reject the run")
        .to_string();

    assert!(
        error.contains("runner output summary contains forbidden public token"),
        "{error}"
    );
    let partial = partial_artifacts(&fixture);
    assert!(
        partial.join("blind-runner-receipt.json").is_file(),
        "the runner receipt must be written before summary scanning"
    );
    assert!(
        !partial
            .parent()
            .expect("partial artifacts must have a run parent")
            .join("summary.json")
            .exists(),
        "summary scanning must reject before finalization writes summary.json"
    );
}

#[test]
fn rejects_valid_observation_with_forbidden_witness_before_copying_it() {
    let fixture = Fixture::new_with_install_receipt().with_valid_leak_channel("witness");

    let error = run_public_pack(fixture.options())
        .err()
        .expect("forbidden witness must reject the run")
        .to_string();

    assert_output_scan_rejected_before_finalize(&fixture, &error);
    assert!(
        !partial_artifacts(&fixture).join("witnesses").exists(),
        "the leaking witness must not be copied into public artifacts"
    );
}

#[test]
fn rejects_unsafe_child_output_entries_before_finalize() {
    for (kind, body) in [
        (
            "symlink",
            "ln -s observation.json \"$BW_CHILD_WORK_DIR/linked-observation.json\"",
        ),
        (
            "hardlink",
            "ln \"$BW_CHILD_WORK_DIR/observation.json\" \"$BW_CHILD_WORK_DIR/linked-observation.json\"",
        ),
        ("fifo", "mkfifo \"$BW_CHILD_WORK_DIR/stream.fifo\""),
    ] {
        let fixture = Fixture::new_with_install_receipt().with_valid_output_suffix(body);
        let error = run_public_pack(fixture.options())
            .err()
            .expect("unsafe child output must reject the run")
            .to_string();

        assert!(
            error.contains("runner output contains unsafe path"),
            "{kind}: {error}"
        );
        assert_output_scan_rejected_before_finalize(&fixture, &error);
    }
}

#[test]
fn cleans_background_children_before_output_scan_and_finalize() {
    let fixture = Fixture::new_with_install_receipt()
        .with_valid_output_suffix("(sleep 1; printf '%s%s' 'gh' 'sa-' > stdout.log) &");

    let report = run_public_pack(fixture.options()).expect("background process must be cleaned");
    thread::sleep(Duration::from_millis(1_200));

    let children = report.final_run.path().join("logs/children");
    let child_dir = fs::read_dir(children)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let stdout = fs::read_to_string(child_dir.join("stdout.log")).unwrap();
    assert!(
        !stdout.contains("ghsa-"),
        "a background child rewrote finalized public output: {stdout:?}"
    );
    verify_run_integrity(report.final_run.path()).unwrap();
}

#[test]
fn rejects_fake_digest_pack_without_install_receipt() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut options = fixture.options();
    options.install_receipt = fixture._root.path().join("missing-install-receipt.json");

    assert_run_error_contains(options, "install receipt");
}

#[test]
fn rejects_install_receipt_for_another_archive() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut receipt = fixture.read_install_receipt();
    receipt.archive_sha256 = "b".repeat(64);
    fixture.write_install_receipt(&receipt);

    assert_run_error_contains(fixture.options(), "install receipt archive_sha256 mismatch");
}

#[test]
fn rejects_resigned_install_receipt_for_another_public_manifest_before_execution() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut receipt = fixture.read_install_receipt();
    receipt.public_manifest_sha256 = "b".repeat(64);
    fixture.write_install_receipt(&receipt);

    assert_provenance_rejection_before_execution(
        &fixture,
        fixture.options(),
        "public_manifest_sha256",
    );
}

#[test]
fn rejects_resigned_install_receipt_for_another_method_commit_before_execution() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut receipt = fixture.read_install_receipt();
    receipt.method_commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    fixture.write_install_receipt(&receipt);

    assert_provenance_rejection_before_execution(&fixture, fixture.options(), "method_commit");
}

#[test]
fn rejects_raw_manifest_method_commit_before_semantic_audit_or_execution() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let manifest_path = fixture.pack.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["method_commit"] =
        serde_json::Value::String("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned());
    manifest["cases"][0]["timeout_seconds"] = serde_json::Value::from(0);
    fs::write(
        &manifest_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
    )
    .unwrap();
    write_checksums(&fixture.pack);
    fixture.write_install_receipt(&fixture.install_receipt_template());

    let error = match run_public_pack(fixture.options()) {
        Ok(_) => panic!("semantic-invalid pack must be rejected"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("install receipt method_commit mismatch"));
    assert!(!error.contains("timeout_seconds must be non-zero"));
    assert!(!fixture.runs.exists());
    assert!(!fixture.adapter_execution_marker.exists());
}

#[test]
fn rejects_resigned_install_receipt_for_another_installed_path_before_execution() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut receipt = fixture.read_install_receipt();
    receipt.installed_path = fixture._root.path().display().to_string();
    fixture.write_install_receipt(&receipt);

    assert_provenance_rejection_before_execution(&fixture, fixture.options(), "installed_path");
}

#[test]
fn rejects_resigned_install_receipt_for_another_installed_tree_before_execution() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut receipt = fixture.read_install_receipt();
    receipt.installed_pack_tree_sha256 = "b".repeat(64);
    fixture.write_install_receipt(&receipt);

    assert_provenance_rejection_before_execution(
        &fixture,
        fixture.options(),
        "installed_pack_tree_sha256",
    );
}

#[test]
fn rejects_resigned_install_receipt_for_another_policy_before_execution() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut receipt = fixture.read_install_receipt();
    receipt.policy_sha256 = "b".repeat(64);
    fixture.write_install_receipt(&receipt);

    assert_provenance_rejection_before_execution(&fixture, fixture.options(), "policy_sha256");
}

#[test]
fn writes_runner_receipt_bound_to_finalized_run() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let report = run_public_pack(fixture.options()).unwrap();

    assert!(report.runner_receipt_path.is_file());
    let receipt = fixture.read_runner_receipt(&report.runner_receipt_path);
    let error = receipt
        .verify(&fixture.receipt_key)
        .unwrap_err()
        .to_string();
    assert!(error.contains("formal runner receipt requires trusted isolation"));
    assert_eq!(
        receipt.isolation_backend,
        FormalIsolationBackend::NativeUntrustedSmoke
    );
    assert_eq!(receipt.run_id, report.final_run.run_id());
    assert_eq!(receipt.public_manifest_sha256, fixture.manifest_sha256());
    assert_eq!(
        receipt.install_receipt_sha256,
        fixture.install_receipt_sha256()
    );
}

#[test]
fn native_smoke_receipt_uses_explicit_runner_identity() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let report = run_public_pack(fixture.options()).unwrap();
    let receipt = fixture.read_runner_receipt(&report.runner_receipt_path);

    assert_eq!(receipt.method_commit, METHOD_COMMIT);
    assert_eq!(receipt.runner_commit, RUNNER_COMMIT);
    assert_eq!(receipt.host_id, RUNNER_HOST_ID);
}

#[test]
fn formal_run_rejects_native_untrusted_smoke() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut options = fixture.options();
    options.metadata.image_digest = "boundary-witness-d0:test".to_owned();

    assert_run_error_contains(options, "formal run requires trusted isolation");
    assert!(!fixture.runs.exists());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_host_rejects_formal_isolation_before_creating_a_run() {
    for backend in [
        FormalIsolationBackend::Container,
        FormalIsolationBackend::CgroupPidNamespace,
    ] {
        let fixture = Fixture::new(AdapterBehavior::Completed);
        let mut options = fixture.options();
        options.isolation_backend = backend;
        options.metadata.image_digest = "boundary-witness-d0:test".to_owned();

        assert_run_error_contains(options, "Linux-only trusted isolation backend");
        assert!(!fixture.runs.exists());
        assert!(
            !fixture.adapter_execution_marker.exists(),
            "formal backend configuration failure must not execute an adapter"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn missing_container_image_preflight_creates_no_run_or_receipt() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let _environment_lock = ENVIRONMENT_MUTEX
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let _environment = install_fake_docker(&fixture, "exit 1\n");
    let mut options = fixture.options();
    options.isolation_backend = FormalIsolationBackend::Container;
    options.metadata.image_digest =
        "boundary-witness-runtime-preflight-missing-6e1f4d9a:test".to_owned();

    assert_run_error_contains(options, "container engine preflight failed");
    assert!(
        !fixture.runs.exists(),
        "image preflight failure must not create the runs root or a partial run"
    );
    assert!(
        !fixture.adapter_execution_marker.exists(),
        "image preflight failure must not execute an adapter or issue a receipt"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn container_engine_run_failure_does_not_finalize_or_issue_a_runner_receipt() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let _environment_lock = ENVIRONMENT_MUTEX
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let _environment = install_fake_docker(
        &fixture,
        "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n  exit 0\nfi\nif [ \"$1\" = run ]; then\n  exit 125\nfi\nexit 1\n",
    );
    let mut options = fixture.options();
    options.isolation_backend = FormalIsolationBackend::Container;
    options.metadata.image_digest = "boundary-witness-runtime-fake-engine:test".to_owned();

    let error = match run_public_pack(options) {
        Ok(_) => panic!("container engine exit 125 must fail the runner"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("exit 125"), "{error}");
    assert!(
        !error.contains("ToolError"),
        "engine failure must not become a case ToolError: {error}"
    );
    assert!(
        fixture.runs.exists(),
        "the failed engine run should remain partial"
    );
    let run = fs::read_dir(&fixture.runs)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .next()
        .expect("engine failure must create a partial run");
    assert!(
        run.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".partial")),
        "engine failure must not finalize the run: {}",
        run.display()
    );
    assert!(
        !run.join("artifacts/blind-runner-receipt.json").exists(),
        "engine failure must not issue a runner receipt"
    );
}

#[test]
fn runner_receipt_evidence_digest_is_recomputable_from_finalized_run() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let report = run_public_pack(fixture.options()).unwrap();
    let receipt = fixture.read_runner_receipt(&report.runner_receipt_path);

    assert_eq!(
        receipt.run_checksums_sha256,
        runner_evidence_digest(report.final_run.path()),
    );

    let checksums = fs::read_to_string(report.final_run.path().join("checksums.sha256")).unwrap();
    assert!(checksums.lines().any(|line| {
        line == format!(
            "{}  artifacts/blind-runner-receipt.json",
            report.runner_receipt_sha256
        )
    }));
    assert_ne!(
        receipt.run_checksums_sha256,
        sha256_path(&report.final_run.path().join("checksums.sha256")),
        "runner evidence digest must not be interpreted as the final checksum-manifest digest",
    );
}

#[test]
fn runs_a_public_pack_and_finalizes_canonical_observations() {
    let fixture = Fixture::new(AdapterBehavior::Completed);

    let report = run_public_pack(fixture.options()).expect("valid public run");

    assert_eq!(report.suite_id, "suite-2026-001");
    assert_eq!(report.split, BlindSplit::Gate);
    assert_eq!(report.case_count, 1);
    assert_eq!(report.completed_count, 1);
    assert_eq!(report.failed_count, 0);
    verify_run_integrity(report.final_run.path()).unwrap();

    let observations_path = report.final_run.path().join("artifacts/observations.jsonl");
    let jsonl = fs::read_to_string(observations_path).unwrap();
    let observation = BlindCaseObservation::parse_json(jsonl.trim_end()).unwrap();
    assert_eq!(observation.status, BlindCaseStatus::Completed);
    let witness = observation.witness.as_ref().unwrap();
    assert!(
        witness
            .artifact_path
            .starts_with(&format!("witnesses/{CASE_ID}/"))
    );
    assert!(
        report
            .final_run
            .path()
            .join("artifacts")
            .join(&witness.artifact_path)
            .is_file()
    );
    assert_eq!(
        jsonl,
        format!("{}\n", serde_json::to_string(&observation).unwrap())
    );
}

#[test]
fn runs_a_public_pack_with_relative_pack_and_runs_roots() {
    let fixture = Fixture::new_relative(AdapterBehavior::Completed);
    assert!(fixture.pack.is_relative());
    assert!(fixture.runs.is_relative());

    let report = run_public_pack(fixture.options()).expect("valid relative-root public run");

    assert_eq!(report.completed_count, 1);
    assert_eq!(report.failed_count, 0);
    assert!(report.final_run.path().is_absolute());
    verify_run_integrity(report.final_run.path()).unwrap();
}

#[test]
fn rejects_metadata_for_a_different_manifest_before_creating_a_run() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut options = fixture.options();
    options.metadata.config_digest =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned();

    assert_run_error_contains(
        options,
        "config digest does not match audited public manifest",
    );
    assert!(!fixture.runs.exists());
}

#[test]
fn rejects_metadata_for_a_different_method_commit_before_creating_a_run() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut options = fixture.options();
    options.metadata.git_commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();

    assert_run_error_contains(
        options,
        "git commit does not match raw public manifest method_commit",
    );
    assert!(!fixture.runs.exists());
}

#[test]
fn rejects_invalid_deployment_digest_before_creating_a_run() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut options = fixture.options();
    options.metadata.deployment_sha256 = "operator-supplied".to_owned();

    assert_run_error_contains(
        options,
        "deployment digest must be 64 lowercase hexadecimal characters",
    );
    assert!(!fixture.runs.exists());
}

#[test]
fn rejects_deployment_digest_not_bound_to_installed_pack_path() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut options = fixture.options();
    options.metadata.deployment_sha256 = "b".repeat(64);

    assert_run_error_contains(
        options,
        "installed public pack directory name must match deployment digest",
    );
    assert!(!fixture.runs.exists());
}

#[test]
fn rejects_runs_root_inside_public_pack_before_creating_a_run() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut options = fixture.options();
    options.runs_root = fixture.pack.join("runs");

    assert_run_error_contains(options, "public pack and runs root must not overlap");
    assert!(!fixture.pack.join("runs").exists());
}

#[test]
fn rejects_public_pack_inside_runs_root() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut options = fixture.options();
    options.runs_root = fixture.pack.parent().unwrap().to_path_buf();

    assert_run_error_contains(options, "public pack and runs root must not overlap");
}

#[cfg(unix)]
#[test]
fn rejects_a_public_pack_with_a_symlinked_ancestor_before_execution() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(AdapterBehavior::Completed);
    let physical_root = fixture.pack.parent().unwrap();
    let linked_root = physical_root.join("linked-root");
    symlink(physical_root, &linked_root).unwrap();
    let mut options = fixture.options();
    options.public_pack_root = linked_root.join("pack");

    assert_run_error_contains(options, "symlink");
}

#[test]
fn rejects_a_public_pack_root_with_parent_traversal_before_execution() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let physical_root = fixture.pack.parent().unwrap();
    fs::create_dir(physical_root.join("discarded")).unwrap();
    let mut options = fixture.options();
    options.public_pack_root = physical_root.join("discarded/../pack");

    assert_run_error_contains(options, "'.' or '..'");
}

#[test]
fn rejects_a_public_pack_root_with_a_current_directory_component_before_execution() {
    let fixture = Fixture::new(AdapterBehavior::Completed);
    let mut options = fixture.options();
    options.public_pack_root = fixture.pack.parent().unwrap().join("./pack");

    assert_run_error_contains(options, "'.' or '..'");
}

#[test]
fn applies_manifest_env_before_overwriting_reserved_protocol_keys() {
    let env = BTreeMap::from([
        ("BW_PUBLIC_CONFIG".to_owned(), "public-value".to_owned()),
        ("BW_BLIND_CASE_ID".to_owned(), "spoofed-case".to_owned()),
        ("BW_BLIND_SUITE_ID".to_owned(), "spoofed-suite".to_owned()),
        ("BW_BLIND_SPLIT".to_owned(), "spoofed-split".to_owned()),
        (
            "BW_BLIND_METHOD_COMMIT".to_owned(),
            "spoofed-commit".to_owned(),
        ),
        (
            "BW_BLIND_MANIFEST_SHA256".to_owned(),
            "spoofed-manifest".to_owned(),
        ),
        (
            "BW_CHILD_WORK_DIR".to_owned(),
            "spoofed-work-dir".to_owned(),
        ),
    ]);
    let fixture = Fixture::new_with_env(AdapterBehavior::RequiresManifestEnv, env);

    let report = run_public_pack(fixture.options()).expect("manifest environment run");

    assert_eq!(report.completed_count, 1);
    assert_eq!(report.failed_count, 0);
}

#[test]
fn timeout_becomes_a_failed_non_completed_observation() {
    assert_adapter_failure(AdapterBehavior::Timeout, BlindCaseStatus::TimedOut);
}

#[test]
fn malformed_json_becomes_a_failed_non_completed_observation() {
    assert_adapter_failure(AdapterBehavior::MalformedJson, BlindCaseStatus::ToolError);
}

#[test]
fn wrong_case_id_becomes_a_failed_non_completed_observation() {
    assert_adapter_failure(AdapterBehavior::WrongCaseId, BlindCaseStatus::ToolError);
}

#[test]
fn missing_witness_artifact_becomes_a_failed_non_completed_observation() {
    assert_adapter_failure(
        AdapterBehavior::MissingWitnessArtifact,
        BlindCaseStatus::ToolError,
    );
}

#[test]
fn non_zero_exit_becomes_a_failed_non_completed_observation() {
    assert_adapter_failure(AdapterBehavior::NonZeroExit, BlindCaseStatus::ToolError);
}

#[test]
fn executes_audited_case_bytes_when_an_earlier_adapter_rewrites_a_later_program() {
    let fixture = Fixture::new_rewrite_attack();
    let second_program = fixture
        .pack
        .join("cases")
        .join(SECOND_CASE_ID)
        .join("adapter/bin/driver");

    let report = run_public_pack(fixture.options()).expect("stable audited snapshot run");

    assert_eq!(report.case_count, 2);
    assert_eq!(report.completed_count, 2);
    assert_eq!(report.failed_count, 0);
    assert_eq!(
        fs::read_to_string(second_program).unwrap(),
        "#!/bin/sh\nexit 73\n",
        "the attack must really rewrite the installed path so the test proves snapshot isolation"
    );
}

fn assert_adapter_failure(behavior: AdapterBehavior, expected_status: BlindCaseStatus) {
    let fixture = Fixture::new(behavior);

    let report = run_public_pack(fixture.options()).expect("case failure should finalize the run");

    assert_eq!(report.case_count, 1);
    assert_eq!(report.completed_count, 0);
    assert_eq!(report.failed_count, 1);
    verify_run_integrity(report.final_run.path()).unwrap();

    let jsonl =
        fs::read_to_string(report.final_run.path().join("artifacts/observations.jsonl")).unwrap();
    let observation = BlindCaseObservation::parse_json(jsonl.trim_end()).unwrap();
    assert_eq!(observation.status, expected_status);
    assert!(observation.findings.is_empty());
    assert!(observation.witness.is_none());
}

fn assert_output_scan_rejected_before_finalize(fixture: &Fixture, error: &str) {
    assert!(
        error.contains("runner output contains forbidden token")
            || error.contains("runner output contains unsafe path"),
        "{error}"
    );
    let partial = partial_artifacts(fixture);
    assert!(
        !partial.join("blind-runner-receipt.json").exists(),
        "output scan must fail before a runner receipt is written"
    );
    assert!(
        !partial
            .parent()
            .expect("partial artifacts must have a run parent")
            .join("logs/execution-source")
            .join(CASE_ID)
            .exists(),
        "failed cases must not leave a materialized execution snapshot"
    );
}

fn partial_artifacts(fixture: &Fixture) -> PathBuf {
    let run = fs::read_dir(&fixture.runs)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .next()
        .expect("run creation should leave a partial candidate");
    assert!(
        run.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".partial")),
        "failed scan must not finalize a run: {}",
        run.display()
    );
    run.join("artifacts")
}

fn assert_run_error_contains(options: RunOptions, expected: &str) {
    let error = match run_public_pack(options) {
        Ok(_) => panic!("expected public-pack audit to reject the supplied root"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains(expected),
        "expected error containing {expected:?}, got {error:?}"
    );
}

fn assert_provenance_rejection_before_execution(
    fixture: &Fixture,
    options: RunOptions,
    expected: &str,
) {
    assert_run_error_contains(options, expected);
    assert!(
        !fixture.runs.exists(),
        "provenance rejection must not create a run"
    );
    assert!(
        !fixture.adapter_execution_marker.exists(),
        "provenance rejection must not execute an adapter"
    );
}

#[derive(Clone, Copy)]
enum AdapterBehavior {
    Completed,
    RequiresManifestEnv,
    Timeout,
    MalformedJson,
    WrongCaseId,
    MissingWitnessArtifact,
    NonZeroExit,
}

struct Fixture {
    _root: TempDir,
    pack: PathBuf,
    runs: PathBuf,
    install_receipt: PathBuf,
    receipt_key: TestReceiptKey,
    adapter_execution_marker: PathBuf,
}

impl Fixture {
    fn new_with_install_receipt() -> Self {
        Self::new(AdapterBehavior::Completed)
    }

    fn with_adapter_script(self, body: &str) -> Self {
        self.with_adapter_program(format!("#!/bin/sh\n{body}\n"))
    }

    fn with_forbidden_policy_token(self, token: &str) -> Self {
        let policy_path = self.pack.join("policy.toml");
        let mut forbidden_public_filename_tokens = mandatory_policy_tokens();
        forbidden_public_filename_tokens.push(token.to_owned());
        let policy = BlindPolicy {
            schema_version: BLIND_POLICY_SCHEMA_V01.to_owned(),
            minimum_replay_attempts: 3,
            gate_minimum_confirmed_cases: 1,
            forbidden_public_filename_tokens,
        };
        fs::write(&policy_path, toml_text(&policy)).unwrap();

        let manifest_path = self.pack.join("manifest.json");
        let mut manifest: BlindPublicManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest.policy_sha256 = sha256_path(&policy_path);
        write_manifest(&manifest_path, &manifest);
        write_checksums(&self.pack);
        self.write_install_receipt(&self.install_receipt_template());
        self
    }

    fn with_adapter_program(self, script: String) -> Self {
        let adapter_path = self.case_root().join("adapter/bin/driver");
        fs::write(adapter_path, script).unwrap();
        let manifest_path = self.pack.join("manifest.json");
        let mut manifest: BlindPublicManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest.cases[0].case_sha256 = tree_digest(&self.case_root());
        write_manifest(&manifest_path, &manifest);
        write_checksums(&self.pack);
        self.write_install_receipt(&self.install_receipt_template());
        self
    }

    fn with_valid_output_suffix(self, suffix: &str) -> Self {
        let script = adapter_script(AdapterBehavior::Completed, &self.adapter_execution_marker);
        let script = script.replacen("\nexit 0\n", &format!("\n{suffix}\nexit 0\n"), 1);
        self.with_adapter_program(script)
    }

    fn with_dynamic_leak_channel(self, channel: &str) -> Self {
        self.with_valid_leak_channel(channel)
    }

    fn with_valid_leak_channel(self, channel: &str) -> Self {
        let body = match channel {
            "stdout" => "printf '%s%s' 'gh' 'sa-'",
            "stderr" => "printf '%s%s' 'gh' 'sa-' >&2",
            "witness" => "printf '%s%s' 'gh' 'sa-' > \"$BW_CHILD_WORK_DIR/witness/replay.json\"",
            _ => panic!("unsupported dynamic leak channel: {channel}"),
        };
        let mut script = adapter_script(AdapterBehavior::Completed, &self.adapter_execution_marker);
        if channel == "witness" {
            script = script.replace(
                &sha256_bytes(WITNESS_CONTENT.as_bytes()),
                &sha256_bytes(b"ghsa-"),
            );
        }
        let script = script.replacen("\nexit 0\n", &format!("\n{body}\nexit 0\n"), 1);
        self.with_adapter_program(script)
    }

    fn new(behavior: AdapterBehavior) -> Self {
        let root = workspace_tempdir();
        let physical_root = root.path().canonicalize().unwrap();
        Self::build(root, physical_root, behavior, BTreeMap::new())
    }

    fn new_relative(behavior: AdapterBehavior) -> Self {
        let current_dir = std::env::current_dir().unwrap().canonicalize().unwrap();
        let root = workspace_tempdir();
        let relative_root = root.path().strip_prefix(current_dir).unwrap().to_path_buf();
        Self::build(root, relative_root, behavior, BTreeMap::new())
    }

    fn new_with_env(behavior: AdapterBehavior, env: BTreeMap<String, String>) -> Self {
        let root = workspace_tempdir();
        let physical_root = root.path().canonicalize().unwrap();
        Self::build(root, physical_root, behavior, env)
    }

    fn new_rewrite_attack() -> Self {
        let root = workspace_tempdir();
        let physical_root = root.path().canonicalize().unwrap();
        let pack = physical_root.join("a".repeat(64));
        let runs = physical_root.join("runs");
        let fixture = Self {
            _root: root,
            pack,
            runs,
            install_receipt: physical_root.join("install-receipt.json"),
            receipt_key: receipt_key(),
            adapter_execution_marker: physical_root.join("adapter-executed"),
        };

        let policy = BlindPolicy {
            schema_version: BLIND_POLICY_SCHEMA_V01.to_owned(),
            minimum_replay_attempts: 3,
            gate_minimum_confirmed_cases: 1,
            forbidden_public_filename_tokens: mandatory_policy_tokens(),
        };
        let policy_text = toml_text(&policy);
        fs::create_dir_all(&fixture.pack).unwrap();
        fs::write(fixture.pack.join("policy.toml"), &policy_text).unwrap();

        let second_program = fixture
            .pack
            .join("cases")
            .join(SECOND_CASE_ID)
            .join("adapter/bin/driver");
        let mut cases = Vec::new();
        for case_id in [CASE_ID, SECOND_CASE_ID] {
            let case_root = fixture.pack.join("cases").join(case_id);
            fs::create_dir_all(case_root.join("adapter/bin")).unwrap();
            fs::write(case_root.join("COMPLETE"), "complete\n").unwrap();
            let program = case_root.join("adapter/bin/driver");
            let script = if case_id == CASE_ID {
                format!(
                    "#!/bin/sh\nprintf '#!/bin/sh\\nexit 73\\n' > '{}'\n{}",
                    second_program.display(),
                    adapter_script(
                        AdapterBehavior::Completed,
                        &fixture.adapter_execution_marker
                    )
                )
            } else {
                adapter_script(
                    AdapterBehavior::Completed,
                    &fixture.adapter_execution_marker,
                )
            };
            fs::write(&program, script).unwrap();
            let mut permissions = fs::metadata(&program).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&program, permissions).unwrap();
            cases.push(BlindPublicCase {
                case_id: BlindCaseId::parse(case_id).unwrap(),
                case_root: format!("cases/{case_id}"),
                case_sha256: tree_digest(&case_root),
                command: BlindCommandSpec {
                    program: "adapter/bin/driver".to_owned(),
                    args: Vec::new(),
                    env: BTreeMap::new(),
                },
                timeout_seconds: 10,
            });
        }

        let manifest = BlindPublicManifest {
            schema_version: BLIND_PUBLIC_SCHEMA_V01.to_owned(),
            suite_id: "suite-2026-001".to_owned(),
            split: BlindSplit::Gate,
            method_commit: METHOD_COMMIT.to_owned(),
            policy_sha256: sha256_bytes(policy_text.as_bytes()),
            cases,
        };
        write_manifest(&fixture.pack.join("manifest.json"), &manifest);
        write_checksums(&fixture.pack);
        fixture.write_install_receipt(&fixture.install_receipt_template());
        fixture
    }

    fn build(
        root: TempDir,
        physical_root: PathBuf,
        behavior: AdapterBehavior,
        env: BTreeMap<String, String>,
    ) -> Self {
        let pack = physical_root.join("a".repeat(64));
        let runs = physical_root.join("runs");
        let fixture = Self {
            _root: root,
            pack,
            runs,
            install_receipt: physical_root.join("install-receipt.json"),
            receipt_key: receipt_key(),
            adapter_execution_marker: physical_root.join("adapter-executed"),
        };

        let case_root = fixture.case_root();
        fs::create_dir_all(case_root.join("adapter/bin")).unwrap();
        fs::write(case_root.join("COMPLETE"), "complete\n").unwrap();

        let policy = BlindPolicy {
            schema_version: BLIND_POLICY_SCHEMA_V01.to_owned(),
            minimum_replay_attempts: 3,
            gate_minimum_confirmed_cases: 1,
            forbidden_public_filename_tokens: mandatory_policy_tokens(),
        };
        let policy_text = toml_text(&policy);
        fs::write(fixture.pack.join("policy.toml"), &policy_text).unwrap();

        let adapter_path = case_root.join("adapter/bin/driver");
        fs::write(
            &adapter_path,
            adapter_script(behavior, &fixture.adapter_execution_marker),
        )
        .unwrap();
        let mut permissions = fs::metadata(&adapter_path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&adapter_path, permissions).unwrap();

        let manifest = BlindPublicManifest {
            schema_version: BLIND_PUBLIC_SCHEMA_V01.to_owned(),
            suite_id: "suite-2026-001".to_owned(),
            split: BlindSplit::Gate,
            method_commit: METHOD_COMMIT.to_owned(),
            policy_sha256: sha256_bytes(policy_text.as_bytes()),
            cases: vec![BlindPublicCase {
                case_id: BlindCaseId::parse(CASE_ID).unwrap(),
                case_root: format!("cases/{CASE_ID}"),
                case_sha256: tree_digest(&case_root),
                command: BlindCommandSpec {
                    program: "adapter/bin/driver".to_owned(),
                    args: Vec::new(),
                    env,
                },
                timeout_seconds: if matches!(behavior, AdapterBehavior::Timeout) {
                    1
                } else {
                    10
                },
            }],
        };
        write_manifest(&fixture.pack.join("manifest.json"), &manifest);
        write_checksums(&fixture.pack);
        fixture.write_install_receipt(&fixture.install_receipt_template());
        fixture
    }

    fn case_root(&self) -> PathBuf {
        self.pack.join("cases").join(CASE_ID)
    }

    fn options(&self) -> RunOptions {
        let mut metadata = metadata();
        metadata.config_digest = sha256_path(&self.pack.join("manifest.json"));
        metadata.image_digest = "native-untrusted-smoke".to_owned();
        RunOptions {
            public_pack_root: self.pack.clone(),
            runs_root: self.runs.clone(),
            metadata,
            install_receipt: self.install_receipt.clone(),
            receipt_key: self.receipt_key.clone(),
            isolation_backend: FormalIsolationBackend::NativeUntrustedSmoke,
            runner_commit: RUNNER_COMMIT.to_owned(),
            runner_host_id: RUNNER_HOST_ID.to_owned(),
        }
    }

    fn install_receipt_template(&self) -> InstallReceipt {
        InstallReceipt {
            schema_version: BLIND_INSTALL_RECEIPT_SCHEMA_V01.to_owned(),
            installer_version: "synthetic-installer-v1".to_owned(),
            installer_commit: METHOD_COMMIT.to_owned(),
            method_commit: METHOD_COMMIT.to_owned(),
            archive_sha256: "a".repeat(64),
            deployment_json_sha256: "d".repeat(64),
            public_manifest_sha256: self.manifest_sha256(),
            policy_sha256: sha256_path(&self.pack.join("policy.toml")),
            installed_pack_tree_sha256: installed_tree_digest(&self.pack),
            installed_path: self.pack.canonicalize().unwrap().display().to_string(),
            created_at_utc: "2026-07-19T00:00:00Z".to_owned(),
            host_id: "synthetic-host".to_owned(),
            trust: bw_blind_model::ReceiptTrust {
                key_id: String::new(),
                signature_sha256: String::new(),
            },
        }
    }

    fn write_install_receipt(&self, receipt: &InstallReceipt) {
        let mut receipt = receipt.clone();
        self.receipt_key.sign_install(&mut receipt).unwrap();
        fs::write(&self.install_receipt, serde_json::to_vec(&receipt).unwrap()).unwrap();
    }

    fn read_install_receipt(&self) -> InstallReceipt {
        serde_json::from_slice(&fs::read(&self.install_receipt).unwrap()).unwrap()
    }

    fn read_runner_receipt(&self, path: &Path) -> bw_blind_model::RunnerReceipt {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn manifest_sha256(&self) -> String {
        sha256_path(&self.pack.join("manifest.json"))
    }

    fn install_receipt_sha256(&self) -> String {
        sha256_path(&self.install_receipt)
    }
}

fn receipt_key() -> TestReceiptKey {
    TestReceiptKey::from_hex("synthetic-receipt-key", RECEIPT_SECRET).unwrap()
}

const RUNNER_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const RUNNER_HOST_ID: &str = "synthetic-runner-host";

fn workspace_tempdir() -> TempDir {
    let current_dir = std::env::current_dir().unwrap().canonicalize().unwrap();
    for _ in 0..100 {
        let temp = tempfile::tempdir_in(&current_dir).unwrap();
        let path = temp.path().display().to_string();
        if MANDATORY_FORBIDDEN_PUBLIC_TOKENS
            .iter()
            .all(|token| !path.to_ascii_lowercase().contains(token))
        {
            return temp;
        }
    }
    panic!("could not create a synthetic tempdir without forbidden public tokens");
}

#[cfg(target_os = "linux")]
struct EnvironmentGuard {
    path: Option<std::ffi::OsString>,
    container_engine: Option<std::ffi::OsString>,
}

#[cfg(target_os = "linux")]
impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.path {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
            match &self.container_engine {
                Some(engine) => std::env::set_var("BW_CONTAINER_ENGINE", engine),
                None => std::env::remove_var("BW_CONTAINER_ENGINE"),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn install_fake_docker(fixture: &Fixture, body: &str) -> EnvironmentGuard {
    let bin = fixture._root.path().join("fake-container-bin");
    fs::create_dir(&bin).unwrap();
    let docker = bin.join("docker");
    fs::write(&docker, format!("#!/bin/sh\n{body}")).unwrap();
    let mut permissions = fs::metadata(&docker).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&docker, permissions).unwrap();

    let guard = EnvironmentGuard {
        path: std::env::var_os("PATH"),
        container_engine: std::env::var_os("BW_CONTAINER_ENGINE"),
    };
    let path = match &guard.path {
        Some(current) => {
            let mut entries = vec![bin.clone()];
            entries.extend(std::env::split_paths(current));
            std::env::join_paths(entries).unwrap()
        }
        None => bin.into_os_string(),
    };
    unsafe {
        std::env::set_var("PATH", path);
        std::env::set_var("BW_CONTAINER_ENGINE", "docker");
    }
    guard
}

fn adapter_script(behavior: AdapterBehavior, execution_marker: &Path) -> String {
    if matches!(behavior, AdapterBehavior::Timeout) {
        return format!(
            "#!/bin/sh\ntouch '{}'\nsleep 30\n",
            execution_marker.display()
        );
    }
    if matches!(behavior, AdapterBehavior::MalformedJson) {
        return format!(
            "#!/bin/sh\ntouch '{}'\nprintf '{{not json\\n' > \"$BW_CHILD_WORK_DIR/observation.json\"\n",
            execution_marker.display()
        );
    }

    let case_id = if matches!(behavior, AdapterBehavior::WrongCaseId) {
        "blind-aaaaaaaaaaaaaaaa"
    } else {
        "$BW_BLIND_CASE_ID"
    };
    let create_witness = if matches!(behavior, AdapterBehavior::MissingWitnessArtifact) {
        "mkdir -p \"$BW_CHILD_WORK_DIR/witness\""
    } else {
        "mkdir -p \"$BW_CHILD_WORK_DIR/witness\"\nprintf 'synthetic witness\\n' > \"$BW_CHILD_WORK_DIR/witness/replay.json\""
    };
    let exit = if matches!(behavior, AdapterBehavior::NonZeroExit) {
        "exit 7"
    } else {
        "exit 0"
    };
    let require_manifest_env = if matches!(behavior, AdapterBehavior::RequiresManifestEnv) {
        r#"if [ "$BW_PUBLIC_CONFIG" != "public-value" ]; then
  exit 9
fi"#
    } else {
        ""
    };
    format!(
        r#"#!/bin/sh
touch "{}"
{require_manifest_env}
{create_witness}
cat > "$BW_CHILD_WORK_DIR/observation.json" <<EOF
{{
  "schema_version":"boundary-witness.blind-observed/0.1",
  "suite_id":"$BW_BLIND_SUITE_ID",
  "split":"$BW_BLIND_SPLIT",
  "case_id":"{case_id}",
  "method_commit":"$BW_BLIND_METHOD_COMMIT",
  "public_manifest_sha256":"$BW_BLIND_MANIFEST_SHA256",
  "status":"completed",
  "findings":[{{
    "rule_id":"callback.lifecycle.borrow_escape",
    "classification":"confirmed_violation",
    "normalized_signature":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "evidence_complete":true
  }}],
  "witness":{{
    "artifact_path":"witness/replay.json",
    "artifact_sha256":"{}",
    "replay_attempts":20,
    "replay_successes":20
  }}
}}
EOF
{exit}
"#,
        execution_marker.display(),
        sha256_bytes(WITNESS_CONTENT.as_bytes())
    )
}

fn metadata() -> RunMetadata {
    RunMetadata {
        git_commit: METHOD_COMMIT.to_owned(),
        deployment_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        image_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_owned(),
        config_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
        build_id: "blind-runner-test".to_owned(),
        host: "test-host".to_owned(),
        cpu_limit: Some(1),
        seed: None,
        toolchains: ToolchainVersions {
            stable: "rustc-test".to_owned(),
            compiler_nightly: None,
        },
    }
}

fn mandatory_policy_tokens() -> Vec<String> {
    MANDATORY_FORBIDDEN_PUBLIC_TOKENS
        .iter()
        .map(|token| (*token).to_owned())
        .collect()
}

fn toml_text(policy: &BlindPolicy) -> String {
    let tokens = policy
        .forbidden_public_filename_tokens
        .iter()
        .map(|token| format!("\"{token}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "schema_version = \"{}\"\nminimum_replay_attempts = {}\ngate_minimum_confirmed_cases = {}\nforbidden_public_filename_tokens = [{tokens}]\n",
        policy.schema_version, policy.minimum_replay_attempts, policy.gate_minimum_confirmed_cases
    )
}

fn write_manifest(path: &Path, manifest: &BlindPublicManifest) {
    let mut bytes = serde_json::to_vec_pretty(manifest).unwrap();
    bytes.push(b'\n');
    fs::write(path, bytes).unwrap();
}

fn write_checksums(root: &Path) {
    let mut output = String::new();
    for relative in regular_files(root) {
        if relative == "checksums.sha256" {
            continue;
        }
        writeln!(
            &mut output,
            "{}  {}",
            sha256_path(&root.join(&relative)),
            relative
        )
        .unwrap();
    }
    fs::write(root.join("checksums.sha256"), output).unwrap();
}

fn tree_digest(case_root: &Path) -> String {
    let mut hasher = Sha256::new();
    for relative in regular_files(case_root) {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(sha256_path(&case_root.join(relative)).as_bytes());
    }
    hex_lower(&hasher.finalize())
}

fn installed_tree_digest(root: &Path) -> String {
    fn add_directory(hasher: &mut Sha256, path: &[u8], mode: u32) {
        hasher.update(b"D");
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path);
        hasher.update(mode.to_be_bytes());
    }

    fn add_file(hasher: &mut Sha256, path: &[u8], mode: u32, bytes: &[u8]) {
        hasher.update(b"F");
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path);
        hasher.update(mode.to_be_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(Sha256::digest(bytes));
    }

    let mut hasher = Sha256::new();
    let root_mode = fs::metadata(root).unwrap().permissions().mode() & 0o7777;
    add_directory(&mut hasher, b".", root_mode);
    for relative in regular_files_and_directories(root) {
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.is_dir() {
            add_directory(&mut hasher, relative.as_bytes(), mode);
        } else {
            add_file(
                &mut hasher,
                relative.as_bytes(),
                mode,
                &fs::read(path).unwrap(),
            );
        }
    }
    hex_lower(&hasher.finalize())
}

fn regular_files_and_directories(root: &Path) -> Vec<String> {
    fn visit(root: &Path, current: &Path, output: &mut Vec<String>) {
        let mut entries = fs::read_dir(current)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if entry.file_type().unwrap().is_dir() {
                output.push(relative);
                visit(root, &path, output);
            } else {
                output.push(relative);
            }
        }
    }

    let mut output = Vec::new();
    visit(root, root, &mut output);
    output.sort();
    output
}

fn regular_files(root: &Path) -> Vec<String> {
    fn visit(root: &Path, current: &Path, output: &mut Vec<String>) {
        let mut entries = fs::read_dir(current)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                visit(root, &path, output);
            } else if file_type.is_file() {
                output.push(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }

    let mut output = Vec::new();
    visit(root, root, &mut output);
    output.sort();
    output
}

fn sha256_path(path: &Path) -> String {
    sha256_bytes(&fs::read(path).unwrap())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn runner_evidence_digest(run_root: &Path) -> String {
    fn add_file(hasher: &mut Sha256, run_root: &Path, relative: &str) {
        let bytes = fs::read(run_root.join(relative)).unwrap();
        hasher.update(b"F");
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(Sha256::digest(bytes));
    }

    fn add_tree(hasher: &mut Sha256, run_root: &Path, relative: &str) {
        let root = run_root.join(relative);
        hasher.update(b"T");
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        if !root.exists() {
            hasher.update(b"absent");
            return;
        }
        hasher.update(b"present");
        for child in regular_files(&root) {
            add_file(hasher, run_root, &format!("{relative}/{child}"));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(b"boundary-witness.runner-evidence-digest/0.1\0");
    add_file(&mut hasher, run_root, "findings.jsonl");
    add_file(&mut hasher, run_root, "artifacts/observations.jsonl");
    for relative in ["artifacts/witnesses", "logs/children", "traces"] {
        add_tree(&mut hasher, run_root, relative);
    }
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
