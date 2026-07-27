use std::{fs, path::Path};

use assert_cmd::Command;
use bw_blind_model::{
    BLIND_INSTALL_RECEIPT_SCHEMA_V01, BLIND_RUNNER_RECEIPT_SCHEMA_V01, BlindPublicManifest,
    FormalIsolationBackend, InstallReceipt, ReceiptTrust, RunnerReceipt, TestReceiptKey,
};
use bw_experiment::{FinalizeRun, RunDirectory, RunMetadata, ToolchainVersions};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const SALT: &str = "00112233445566778899aabbccddeeff";
const CASE_ID: &str = "blind-0000000000000001";
const RECEIPT_SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn pack_cli_prints_json_and_writes_separated_outputs() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let policy = temp.path().join("policy.toml");
    let public_out = temp.path().join("public");
    let private_out = temp.path().join("private");
    write_pack_source(&source);
    write_policy(&policy);

    let output = Command::cargo_bin("bw-blind-pack")
        .unwrap()
        .args([
            "--source",
            path(&source),
            "--policy",
            path(&policy),
            "--public-out",
            path(&public_out),
            "--private-out",
            path(&private_out),
            "--id-salt-hex",
            SALT,
            "--commit",
            COMMIT,
        ])
        .assert()
        .success()
        .get_output()
        .clone();

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["suite_id"], "cli-suite");
    assert_eq!(report["split_counts"]["gate"], 1);
    assert!(public_out.join("nday-gate/manifest.json").is_file());
    assert!(private_out.join("ground-truth/nday-gate.json").is_file());
}

#[test]
fn reveal_cli_prints_gate_decision_and_writes_reveal_json() {
    let fixture = RevealFixture::new(2);

    let output = fixture.command().assert().success().get_output().clone();

    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["gate_passed"], true);
    let reveal: Value = serde_json::from_slice(&fs::read(&fixture.out).unwrap()).unwrap();
    assert_eq!(reveal["suite_id"], "cli-suite");
    assert_eq!(reveal["total_cases"], 1);
    assert_eq!(
        decision["reveal_report_sha256"],
        sha256(&fs::read(&fixture.out).unwrap())
    );
}

#[test]
fn reveal_cli_exits_one_when_valid_gate_fails() {
    let fixture = RevealFixture::new(1);

    let output = fixture.command().assert().code(1).get_output().clone();

    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["gate_passed"], false);
    assert!(fixture.out.is_file());
}

#[test]
fn reveal_cli_rejects_output_that_aliases_an_input_or_finalized_run() {
    let fixture = RevealFixture::new(2);

    fixture
        .command_with_out(&fixture.manifest)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("must not alias input"));
    fixture
        .command_with_out(&fixture.run.join("artifacts/observations.jsonl"))
        .assert()
        .code(2)
        .stderr(predicates::str::contains("finalized run directory"));

    for input in [
        &fixture.install_receipt,
        &fixture.runner_receipt,
        &fixture.receipt_key,
    ] {
        let assertion = fixture.command_with_out(input).assert().code(2);
        let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
        assert!(
            stderr.contains("must not alias input") || stderr.contains("frozen input directory"),
            "unexpected CLI rejection: {stderr}"
        );
    }
}

struct RevealFixture {
    _temp: tempfile::TempDir,
    manifest: std::path::PathBuf,
    policy: std::path::PathBuf,
    run: std::path::PathBuf,
    ground_truth: std::path::PathBuf,
    out: std::path::PathBuf,
    install_receipt: std::path::PathBuf,
    runner_receipt: std::path::PathBuf,
    receipt_key: std::path::PathBuf,
}

impl RevealFixture {
    fn new(replay_successes: u32) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let public = temp.path().join("public");
        let private = temp.path().join("private/ground-truth");
        let runs = temp.path().join("runs");
        let results = temp.path().join("results");
        let trusted = temp.path().join("trusted");
        fs::create_dir_all(&public).unwrap();
        fs::create_dir_all(&private).unwrap();
        fs::create_dir_all(&results).unwrap();
        fs::create_dir_all(&trusted).unwrap();
        let policy = public.join("policy.toml");
        write_policy(&policy);
        let policy_sha256 = sha256(&fs::read(&policy).unwrap());
        let manifest = public.join("manifest.json");
        let manifest_value = json!({
            "schema_version": "boundary-witness.blind-public/0.1",
            "suite_id": "cli-suite",
            "split": "gate",
            "method_commit": COMMIT,
            "policy_sha256": policy_sha256,
            "cases": [{
                "case_id": CASE_ID,
                "case_root": format!("cases/{CASE_ID}"),
                "case_sha256": "a".repeat(64),
                "command": { "program": "adapter/run", "args": [], "env": {} },
                "timeout_seconds": 30
            }]
        });
        fs::write(
            &manifest,
            serde_json::to_vec_pretty(&manifest_value).unwrap(),
        )
        .unwrap();
        let manifest_sha256 = sha256(&fs::read(&manifest).unwrap());

        let ground_truth = private.join("ground-truth.json");
        fs::write(
            &ground_truth,
            serde_json::to_vec_pretty(&json!({
                "schema_version": "boundary-witness.blind-ground-truth/0.1",
                "suite_id": "cli-suite",
                "split": "gate",
                "public_manifest_sha256": manifest_sha256,
                "cases": [{
                    "case_id": CASE_ID,
                    "curator_key": "opaque-case",
                    "role": "violation",
                    "component": "component",
                    "api": "api",
                    "root_cause_key": "root-cause",
                    "paired_case_ids": [],
                    "source_revision": "revision"
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let observations = temp.path().join("observations.jsonl");
        let install_receipt = trusted.join("install-receipt.json");
        let runner_receipt = trusted.join("runner-receipt.json");
        let receipt_key = trusted.join("receipt-key.hex");
        let key = TestReceiptKey::from_hex("cli-receipt-key", RECEIPT_SECRET).unwrap();
        fs::write(&receipt_key, RECEIPT_SECRET).unwrap();
        let completed = replay_successes == 2;
        let findings = if completed {
            json!([{
                "rule_id": "callback.lifecycle.borrow_escape",
                "classification": "confirmed_violation",
                "normalized_signature": "b".repeat(64),
                "evidence_complete": true
            }])
        } else {
            json!([])
        };
        let witness = if completed {
            json!({
                "artifact_path": "witness/replay.json",
                "artifact_sha256": sha256(b"synthetic witness\n"),
                "replay_attempts": 2,
                "replay_successes": 2
            })
        } else {
            Value::Null
        };
        let observation = json!({
            "schema_version": "boundary-witness.blind-observed/0.1",
            "suite_id": "cli-suite",
            "split": "gate",
            "case_id": CASE_ID,
            "method_commit": COMMIT,
            "public_manifest_sha256": manifest_sha256,
            "status": if completed { "completed" } else { "tool_error" },
            "findings": findings,
            "witness": witness
        });
        fs::write(
            &observations,
            format!("{}\n", serde_json::to_string(&observation).unwrap()),
        )
        .unwrap();
        let run = RunDirectory::create(
            &runs,
            "cli-finalized-run",
            RunMetadata {
                git_commit: COMMIT.to_owned(),
                deployment_sha256: "d".repeat(64),
                image_digest: format!("sha256:{}", "e".repeat(64)),
                config_digest: manifest_sha256.clone(),
                build_id: "blind-cli-test".to_owned(),
                host: "cli-host".to_owned(),
                cpu_limit: None,
                seed: None,
                toolchains: ToolchainVersions {
                    stable: "rustc-test".to_owned(),
                    compiler_nightly: None,
                },
            },
        )
        .unwrap();
        fs::copy(
            &observations,
            run.artifacts_dir().join("observations.jsonl"),
        )
        .unwrap();
        if completed {
            fs::create_dir_all(run.artifacts_dir().join("witness")).unwrap();
            fs::write(
                run.artifacts_dir().join("witness/replay.json"),
                b"synthetic witness\n",
            )
            .unwrap();
        }
        let mut install = InstallReceipt {
            schema_version: BLIND_INSTALL_RECEIPT_SCHEMA_V01.to_owned(),
            installer_version: "synthetic-installer".to_owned(),
            installer_commit: COMMIT.to_owned(),
            method_commit: COMMIT.to_owned(),
            archive_sha256: "d".repeat(64),
            deployment_json_sha256: "e".repeat(64),
            public_manifest_sha256: manifest_sha256.clone(),
            policy_sha256,
            installed_pack_tree_sha256: "f".repeat(64),
            installed_path: "synthetic-pack".to_owned(),
            created_at_utc: "2026-07-19T00:00:00Z".to_owned(),
            host_id: "synthetic-installer".to_owned(),
            trust: ReceiptTrust {
                key_id: String::new(),
                signature_sha256: String::new(),
            },
        };
        key.sign_install(&mut install).unwrap();
        let install_bytes = serde_json::to_vec(&install).unwrap();
        fs::write(&install_receipt, &install_bytes).unwrap();
        let observations_bytes = fs::read(run.artifacts_dir().join("observations.jsonl")).unwrap();
        let mut runner = RunnerReceipt {
            schema_version: BLIND_RUNNER_RECEIPT_SCHEMA_V01.to_owned(),
            runner_version: "synthetic-runner".to_owned(),
            runner_commit: COMMIT.to_owned(),
            run_id: run.run_id().to_owned(),
            suite_id: "cli-suite".to_owned(),
            split: "gate".to_owned(),
            method_commit: COMMIT.to_owned(),
            archive_sha256: "d".repeat(64),
            deployment_json_sha256: "e".repeat(64),
            install_receipt_sha256: sha256(&install_bytes),
            public_manifest_sha256: manifest_sha256.clone(),
            policy_sha256: sha256(&fs::read(&policy).unwrap()),
            case_count: 1,
            isolation_backend: FormalIsolationBackend::Container,
            case_execution_snapshot_digest: case_execution_snapshot_digest(
                &manifest,
                &manifest_sha256,
            ),
            observations_sha256: sha256(&observations_bytes),
            stdout_stderr_digest: "b".repeat(64),
            witness_tree_sha256: "c".repeat(64),
            run_checksums_sha256: runner_evidence_digest(run.partial_path()),
            created_at_utc: "2026-07-19T00:00:00Z".to_owned(),
            host_id: "synthetic-runner".to_owned(),
            trust: ReceiptTrust {
                key_id: String::new(),
                signature_sha256: String::new(),
            },
        };
        key.sign_runner(&mut runner).unwrap();
        let runner_bytes = serde_json::to_vec(&runner).unwrap();
        fs::write(
            run.artifacts_dir().join("blind-runner-receipt.json"),
            &runner_bytes,
        )
        .unwrap();
        fs::write(&runner_receipt, runner_bytes).unwrap();
        let run = run
            .finalize(FinalizeRun {
                summary: json!({
                    "schema_version": "boundary-witness.blind-run/0.1",
                    "suite_id": "cli-suite",
                    "split": "gate",
                    "case_count": 1,
                    "completed_count": usize::from(completed),
                    "failed_count": usize::from(!completed),
                    "method_commit": COMMIT,
                    "public_manifest_sha256": manifest_sha256,
                    "deployment_sha256": "d".repeat(64),
                }),
                execution: None,
                required_trace_files: Vec::new(),
                required_log_files: Vec::new(),
            })
            .unwrap()
            .path()
            .to_path_buf();
        let out = results.join("reveal.json");
        Self {
            _temp: temp,
            manifest,
            policy,
            run,
            ground_truth,
            out,
            install_receipt,
            runner_receipt,
            receipt_key,
        }
    }

    fn command(&self) -> Command {
        self.command_with_out(&self.out)
    }

    fn command_with_out(&self, out: &Path) -> Command {
        let mut command = Command::cargo_bin("bw-blind-reveal").unwrap();
        command.args([
            "--manifest",
            path(&self.manifest),
            "--policy",
            path(&self.policy),
            "--run",
            path(&self.run),
            "--ground-truth",
            path(&self.ground_truth),
            "--install-receipt",
            path(&self.install_receipt),
            "--runner-receipt",
            path(&self.runner_receipt),
            "--receipt-key",
            path(&self.receipt_key),
            "--receipt-key-id",
            "cli-receipt-key",
            "--out",
            path(out),
        ]);
        command
    }
}

fn write_pack_source(source: &Path) {
    let case = source.join("cases/opaque-case");
    fs::create_dir_all(case.join("adapter")).unwrap();
    fs::write(case.join("adapter/run"), "synthetic\n").unwrap();
    fs::write(
        source.join("source.toml"),
        r#"suite_id = "cli-suite"

[[cases]]
curator_key = "opaque-case"
split = "gate"
role = "violation"
component = "component"
api = "api"
root_cause_key = "root-cause"
paired_with = []
source_revision = "revision"
case_dir = "cases/opaque-case"
public_command = { program = "adapter/run", args = [], env = {} }
timeout_seconds = 30
"#,
    )
    .unwrap();
}

fn write_policy(path: &Path) {
    fs::write(
        path,
        r#"schema_version = "boundary-witness.blind-policy/0.1"
minimum_replay_attempts = 2
gate_minimum_confirmed_cases = 1
forbidden_public_filename_tokens = ["ground-truth", "ground_truth", "cve-", "ghsa-", "advisory", "poc", "proof-of-concept", "proof_of_concept", "expected-result", "expected_result", "expected result", "private"]
"#,
    )
    .unwrap();
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn runner_evidence_digest(root: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"boundary-witness.runner-evidence-digest/0.1\0");
    for relative in ["findings.jsonl", "artifacts/observations.jsonl"] {
        hasher.update(b"F");
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(Sha256::digest(fs::read(root.join(relative)).unwrap()));
    }
    for tree in ["artifacts/witnesses", "logs/children", "traces"] {
        hasher.update(b"T");
        hasher.update(tree.as_bytes());
        hasher.update([0]);
        let path = root.join(tree);
        if path.exists() {
            hasher.update(b"present");
        } else {
            hasher.update(b"absent");
        }
    }
    format!("{:x}", hasher.finalize())
}

fn case_execution_snapshot_digest(manifest_path: &Path, manifest_sha256: &str) -> String {
    let manifest =
        BlindPublicManifest::parse_json(&fs::read_to_string(manifest_path).unwrap()).unwrap();
    let mut cases = manifest.cases.iter().collect::<Vec<_>>();
    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));

    let mut hasher = Sha256::new();
    hasher.update(manifest_sha256.as_bytes());
    hasher.update([0]);
    for case in cases {
        hasher.update(case.case_id.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(case.case_sha256.as_bytes());
        hasher.update([0]);
    }
    sha256(&hasher.finalize())
}
