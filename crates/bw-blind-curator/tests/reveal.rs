use std::{fs, path::PathBuf};

use bw_blind_curator::{GateDecision, RevealOptions, reveal};
use bw_blind_model::{
    BLIND_INSTALL_RECEIPT_SCHEMA_V01, BLIND_RUNNER_RECEIPT_SCHEMA_V01, BlindPublicManifest,
    FormalIsolationBackend, InstallReceipt, ReceiptTrust, RunnerReceipt, TestReceiptKey,
};
use bw_experiment::{FinalizeRun, RunDirectory, RunMetadata, ToolchainVersions};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const SUITE_ID: &str = "synthetic-nday";
const METHOD_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VIOLATION_ID: &str = "blind-0000000000000001";
const SAFE_ID: &str = "blind-0000000000000002";
const FIXED_ID: &str = "blind-0000000000000003";
const RULE_ID: &str = "callback.lifecycle.borrow_escape";
const RECEIPT_SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn reveal_rejects_generic_finalized_run_without_runner_receipt() {
    let fixture = Fixture::generic_finalized_run_without_receipts();
    let error = reveal(fixture.options()).unwrap_err().to_string();
    assert!(error.contains("runner receipt is required"), "{error}");
}

#[test]
fn reveal_rejects_runner_receipt_for_another_run_id() {
    let fixture = Fixture::with_signed_receipts();
    fixture.rewrite_runner_receipt_run_id("other-run");
    let error = reveal(fixture.options()).unwrap_err().to_string();
    assert!(error.contains("runner receipt run_id mismatch"), "{error}");
}

#[test]
fn reveal_rejects_consumed_bytes_checksum_mismatch() {
    let fixture = Fixture::with_signed_receipts();
    fixture.replace_observations_after_checksum_with_same_path();
    let error = reveal(fixture.options()).unwrap_err().to_string();
    assert!(error.contains("run evidence checksum mismatch"), "{error}");
}

#[test]
fn reveal_rejects_evidence_tree_root_that_is_not_a_directory() {
    for relative in ["artifacts/witnesses", "logs/children", "traces"] {
        let fixture = Fixture::with_signed_receipts();
        let root = fixture.run_path.join(relative);
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        } else {
            fs::create_dir_all(root.parent().unwrap()).unwrap();
        }
        fs::write(&root, b"not a directory\n").unwrap();

        let error = reveal(fixture.options()).unwrap_err().to_string();

        assert!(
            error.contains(&format!(
                "runner evidence root is not a directory: {relative}"
            )),
            "{error}"
        );
    }
}

#[cfg(unix)]
#[test]
fn reveal_rejects_intermediate_evidence_directory_symlink() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::with_signed_receipts();
    let artifacts = fixture.run_path.join("artifacts");
    let replacement = fixture._root.path().join("external-artifacts");
    fs::rename(&artifacts, &replacement).unwrap();
    symlink(&replacement, &artifacts).unwrap();

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(error.contains("run snapshot rejects symlink"), "{error}");
}

#[test]
fn reveal_rejects_native_untrusted_smoke_runner_receipt() {
    let fixture = Fixture::with_signed_receipts();
    fixture.rewrite_runner_receipt(|receipt| {
        receipt.isolation_backend = FormalIsolationBackend::NativeUntrustedSmoke;
    });

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(
        error.contains("formal reveal requires trusted isolation"),
        "{error}"
    );
}

#[test]
fn reveal_rejects_runner_receipt_with_wrong_verification_key() {
    let fixture = Fixture::with_signed_receipts();
    let mut options = fixture.options();
    options.receipt_key = TestReceiptKey::from_hex(
        "other-synthetic-receipt-key",
        "101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f",
    )
    .unwrap();

    let error = reveal(options).unwrap_err().to_string();

    assert!(
        error.contains("receipt trust key_id does not match verification key"),
        "{error}"
    );
}

#[test]
fn reveal_rejects_runner_receipt_with_wrong_signature() {
    let fixture = Fixture::with_signed_receipts();
    fixture.corrupt_runner_receipt_signature();

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(error.contains("receipt signature mismatch"), "{error}");
}

#[test]
fn reveal_rejects_runner_receipt_with_install_receipt_sha_mismatch() {
    let fixture = Fixture::with_signed_receipts();
    fixture.rewrite_runner_receipt(|receipt| {
        receipt.install_receipt_sha256 = "b".repeat(64);
    });

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(
        error.contains("runner receipt install receipt checksum mismatch"),
        "{error}"
    );
}

#[test]
fn reveal_rejects_resigned_runner_receipt_case_count_mismatch() {
    let fixture = Fixture::with_signed_receipts();
    fixture.rewrite_runner_receipt(|receipt| {
        receipt.case_count = 1;
    });

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(
        error.contains("runner receipt case_count mismatch"),
        "{error}"
    );
}

#[test]
fn reveal_rejects_resigned_runner_receipt_suite_id_mismatch() {
    let fixture = Fixture::with_signed_receipts();
    fixture.rewrite_runner_receipt(|receipt| {
        receipt.suite_id = "synthetic-other-suite".to_owned();
    });

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(
        error.contains("runner receipt suite_id mismatch"),
        "{error}"
    );
}

#[test]
fn reveal_rejects_resigned_runner_receipt_split_mismatch() {
    let fixture = Fixture::with_signed_receipts();
    fixture.rewrite_runner_receipt(|receipt| {
        receipt.split = "evaluation".to_owned();
    });

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(error.contains("runner receipt split mismatch"), "{error}");
}

#[test]
fn reveal_rejects_resigned_runner_receipt_execution_snapshot_mismatch() {
    let fixture = Fixture::with_signed_receipts();
    fixture.rewrite_runner_receipt(|receipt| {
        receipt.case_execution_snapshot_digest = "b".repeat(64);
    });

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(
        error.contains("runner receipt case_execution_snapshot_digest mismatch"),
        "{error}"
    );
}

#[test]
fn reveal_rejects_external_runner_receipt_bytes_that_differ_from_finalized_run() {
    let fixture = Fixture::with_signed_receipts();
    fs::write(&fixture.runner_receipt_path, b"different receipt bytes\n").unwrap();

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(
        error.contains("runner receipt does not match finalized run receipt"),
        "{error}"
    );
}

#[test]
fn gate_passes_when_violation_has_stable_confirmed_witness_and_controls_are_clean() {
    let fixture = Fixture::new("gate");

    let first_report = reveal(fixture.options()).unwrap();
    let first_decision = GateDecision::from_reveal(&first_report, &fixture.policy()).unwrap();
    let second_report = reveal(fixture.options()).unwrap();
    let second_decision = GateDecision::from_reveal(&second_report, &fixture.policy()).unwrap();

    assert_eq!(serialized(&first_report), serialized(&second_report));
    assert_eq!(serialized(&first_decision), serialized(&second_decision));
    assert!(first_decision.gate_passed);
    assert_eq!(first_decision.passed_violation_cases, 1);
    assert_eq!(
        first_decision.confirmed_root_causes,
        ["synthetic.callback.borrow_escape"]
    );
    assert!(first_decision.control_failures.is_empty());
    assert!(first_decision.incomplete_cases.is_empty());
    assert_eq!(first_decision.suite_id, first_report.suite_id());
    assert_eq!(first_decision.split, first_report.split());
    assert_eq!(first_decision.method_commit, first_report.method_commit());
    assert_eq!(
        first_decision.public_manifest_sha256,
        first_report.public_manifest_sha256()
    );
    for digest in [
        first_report.policy_sha256(),
        first_report.ground_truth_sha256(),
        first_report.run_checksums_sha256(),
        first_report.observations_sha256(),
        &first_decision.reveal_report_sha256,
    ] {
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert_eq!(
        first_decision.reveal_report_sha256,
        sha256(&{
            let mut bytes = serde_json::to_vec_pretty(&first_report).unwrap();
            bytes.push(b'\n');
            bytes
        })
    );
}

#[test]
fn reveal_rejects_tampered_or_standalone_observations() {
    let fixture = Fixture::new("gate");
    fs::write(
        fixture.run_path.join("artifacts/observations.jsonl"),
        fs::read(&fixture.observations_path).unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.run_path.join("artifacts/observations.jsonl"),
        b"{}\n",
    )
    .unwrap();

    let tampered = reveal(fixture.options()).unwrap_err().to_string();
    assert!(tampered.contains("checksum mismatch"), "{tampered}");

    let mut standalone = fixture.options();
    standalone.run_directory = fixture._root.path().join("standalone");
    fs::create_dir(&standalone.run_directory).unwrap();
    fs::copy(
        &fixture.observations_path,
        standalone.run_directory.join("observations.jsonl"),
    )
    .unwrap();
    let detached = reveal(standalone).unwrap_err().to_string();
    assert!(detached.contains("checksums.sha256"), "{detached}");
}

#[test]
fn reveal_rejects_a_finalized_run_without_blind_run_summary_identity() {
    let fixture = Fixture::new("gate");
    fixture.write_run("synthetic.generic-run/0.1");

    let error = reveal(fixture.options()).unwrap_err().to_string();

    assert!(
        error.contains("run summary is not bound to blind run identity"),
        "{error}"
    );
}

#[test]
fn cloned_reveal_report_preserves_sealed_verified_state() {
    let fixture = Fixture::new("gate");
    let report = reveal(fixture.options()).unwrap();
    let cloned = report.clone();

    assert_eq!(serialized(&cloned), serialized(&report));
    assert_eq!(cloned.cases().len(), cloned.total_cases());
    assert!(
        GateDecision::from_reveal(&cloned, &fixture.policy())
            .unwrap()
            .gate_passed
    );
}

#[test]
fn gate_rejects_policy_weaker_than_the_manifest_bound_policy() {
    let fixture = Fixture::new_with_minimum_confirmed_cases("gate", 2);
    let report = reveal(fixture.options()).unwrap();

    let bound_decision = GateDecision::from_reveal(&report, &fixture.policy()).unwrap();
    assert!(!bound_decision.gate_passed);
    assert_eq!(bound_decision.passed_violation_cases, 1);

    let mut weaker_policy = fixture.policy();
    weaker_policy.gate_minimum_confirmed_cases = 1;
    let error = GateDecision::from_reveal(&report, &weaker_policy)
        .unwrap_err()
        .to_string();

    assert!(error.contains("policy does not match policy verified during reveal"));
}

#[test]
fn gate_fails_when_replay_success_is_nineteen_of_twenty() {
    let mut fixture = Fixture::new("gate");
    fixture.observations[0]["status"] = json!("tool_error");
    fixture.observations[0]["findings"] = json!([]);
    fixture.observations[0]["witness"] = Value::Null;
    fixture.write_observations();

    let first_report = reveal(fixture.options()).unwrap();
    let first_decision = GateDecision::from_reveal(&first_report, &fixture.policy()).unwrap();
    let second_report = reveal(fixture.options()).unwrap();
    let second_decision = GateDecision::from_reveal(&second_report, &fixture.policy()).unwrap();

    assert_eq!(serialized(&first_report), serialized(&second_report));
    assert_eq!(serialized(&first_decision), serialized(&second_decision));
    assert!(!first_decision.gate_passed);
    assert_eq!(first_decision.passed_violation_cases, 0);
    assert_eq!(first_decision.incomplete_cases, [VIOLATION_ID]);
}

#[test]
fn gate_fails_when_evidence_is_incomplete() {
    let mut fixture = Fixture::new("gate");
    fixture.observations[0]["status"] = json!("tool_error");
    fixture.observations[0]["findings"] = json!([]);
    fixture.observations[0]["witness"] = Value::Null;
    fixture.write_observations();

    let first_report = reveal(fixture.options()).unwrap();
    let first_decision = GateDecision::from_reveal(&first_report, &fixture.policy()).unwrap();
    let second_report = reveal(fixture.options()).unwrap();
    let second_decision = GateDecision::from_reveal(&second_report, &fixture.policy()).unwrap();

    assert_eq!(serialized(&first_report), serialized(&second_report));
    assert_eq!(serialized(&first_decision), serialized(&second_decision));
    assert!(!first_decision.gate_passed);
    assert_eq!(first_decision.passed_violation_cases, 0);
    assert_eq!(first_decision.incomplete_cases, [VIOLATION_ID]);
}

#[test]
fn gate_fails_when_control_has_same_rule_finding() {
    let mut fixture = Fixture::new("gate");
    fixture.observations[1]["findings"] = json!([confirmed_finding()]);
    fixture.observations[1]["witness"] = stable_witness();
    fixture.write_observations();

    let first_report = reveal(fixture.options()).unwrap();
    let first_decision = GateDecision::from_reveal(&first_report, &fixture.policy()).unwrap();
    let second_report = reveal(fixture.options()).unwrap();
    let second_decision = GateDecision::from_reveal(&second_report, &fixture.policy()).unwrap();

    assert_eq!(serialized(&first_report), serialized(&second_report));
    assert_eq!(serialized(&first_decision), serialized(&second_decision));
    assert!(!first_decision.gate_passed);
    assert_eq!(first_decision.control_failures, [SAFE_ID]);
}

#[test]
fn gate_fails_when_a_control_did_not_complete() {
    let mut fixture = Fixture::new("gate");
    fixture.observations[1]["status"] = json!("tool_error");
    fixture.write_observations();

    let report = reveal(fixture.options()).unwrap();
    let decision = GateDecision::from_reveal(&report, &fixture.policy()).unwrap();

    assert!(!decision.gate_passed);
    assert_eq!(decision.control_failures, [SAFE_ID]);
    assert_eq!(decision.incomplete_cases, [SAFE_ID]);
}

#[test]
fn reveal_rejects_missing_observation_case_via_runner_receipt_count_binding() {
    let mut fixture = Fixture::new("gate");
    fixture.observations.pop();
    fixture.write_observations();

    let first_error = reveal(fixture.options()).unwrap_err().to_string();
    let second_error = reveal(fixture.options()).unwrap_err().to_string();

    assert_eq!(first_error, second_error);
    assert!(
        first_error.contains("runner receipt case_count mismatch with public manifest"),
        "{first_error}"
    );
}

#[test]
fn reveal_rejects_commit_or_manifest_digest_mismatch() {
    let mut commit_fixture = Fixture::new("gate");
    commit_fixture.observations[0]["method_commit"] =
        json!("cccccccccccccccccccccccccccccccccccccccc");
    commit_fixture.write_observations();

    let first_commit_error = reveal(commit_fixture.options()).unwrap_err().to_string();
    let second_commit_error = reveal(commit_fixture.options()).unwrap_err().to_string();
    assert_eq!(first_commit_error, second_commit_error);
    assert!(first_commit_error.contains("method commit mismatch"));

    let mut digest_fixture = Fixture::new("gate");
    digest_fixture.observations[0]["public_manifest_sha256"] =
        json!("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    digest_fixture.write_observations();

    let first_digest_error = reveal(digest_fixture.options()).unwrap_err().to_string();
    let second_digest_error = reveal(digest_fixture.options()).unwrap_err().to_string();
    assert_eq!(first_digest_error, second_digest_error);
    assert!(first_digest_error.contains("public manifest digest mismatch"));
}

#[test]
fn evaluation_split_refuses_gate_decision() {
    let fixture = Fixture::new("evaluation");

    let first_report = reveal(fixture.options()).unwrap();
    let second_report = reveal(fixture.options()).unwrap();
    assert_eq!(serialized(&first_report), serialized(&second_report));

    let first_error = GateDecision::from_reveal(&first_report, &fixture.policy())
        .unwrap_err()
        .to_string();
    let second_error = GateDecision::from_reveal(&second_report, &fixture.policy())
        .unwrap_err()
        .to_string();
    assert_eq!(first_error, second_error);
    assert!(first_error.contains("gate decision requires gate split"));
}

struct Fixture {
    _root: TempDir,
    manifest_path: PathBuf,
    policy_path: PathBuf,
    observations_path: PathBuf,
    run_path: PathBuf,
    ground_truth_path: PathBuf,
    install_receipt_path: PathBuf,
    runner_receipt_path: PathBuf,
    receipt_key: TestReceiptKey,
    observations: Vec<Value>,
}

impl Fixture {
    fn new(split: &str) -> Self {
        Self::new_with_minimum_confirmed_cases(split, 1)
    }

    fn new_with_minimum_confirmed_cases(split: &str, minimum_confirmed_cases: u32) -> Self {
        let root = tempfile::tempdir().unwrap();
        let manifest_path = root.path().join("manifest.json");
        let policy_path = root.path().join("policy.toml");
        let observations_path = root.path().join("observations.jsonl");
        let run_path = root.path().join("runs/synthetic-finalized-run");
        let ground_truth_path = root.path().join("ground-truth.json");
        let install_receipt_path = root.path().join("install-receipt.json");
        let runner_receipt_path = root.path().join("runner-receipt.json");
        let policy = format!(
            "schema_version = \"boundary-witness.blind-policy/0.1\"\nminimum_replay_attempts = 20\ngate_minimum_confirmed_cases = {minimum_confirmed_cases}\nforbidden_public_filename_tokens = [\"ground-truth\", \"ground_truth\", \"cve-\", \"ghsa-\", \"advisory\", \"poc\", \"proof-of-concept\", \"proof_of_concept\", \"expected-result\", \"expected_result\", \"expected result\", \"private\"]\n"
        );
        fs::write(&policy_path, &policy).unwrap();
        let policy_sha256 = sha256(policy.as_bytes());

        let manifest = json!({
            "schema_version": "boundary-witness.blind-public/0.1",
            "suite_id": SUITE_ID,
            "split": split,
            "method_commit": METHOD_COMMIT,
            "policy_sha256": policy_sha256,
            "cases": [public_case(VIOLATION_ID), public_case(SAFE_ID), public_case(FIXED_ID)],
        });
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(&manifest_path, &manifest_bytes).unwrap();
        let manifest_sha256 = sha256(&manifest_bytes);

        let ground_truth = json!({
            "schema_version": "boundary-witness.blind-ground-truth/0.1",
            "suite_id": SUITE_ID,
            "split": split,
            "public_manifest_sha256": manifest_sha256,
            "cases": [
                truth_case(
                    VIOLATION_ID,
                    "violation",
                    "synthetic.callback.borrow_escape",
                    &[SAFE_ID, FIXED_ID],
                ),
                truth_case(
                    SAFE_ID,
                    "safe_control",
                    "synthetic.callback.borrow_escape",
                    &[VIOLATION_ID],
                ),
                truth_case(
                    FIXED_ID,
                    "fixed_control",
                    "synthetic.callback.borrow_escape",
                    &[VIOLATION_ID],
                ),
            ],
        });
        fs::write(
            &ground_truth_path,
            serde_json::to_vec_pretty(&ground_truth).unwrap(),
        )
        .unwrap();

        let observations = vec![
            observation(
                split,
                VIOLATION_ID,
                &manifest_sha256,
                vec![confirmed_finding()],
                stable_witness(),
            ),
            observation(split, SAFE_ID, &manifest_sha256, Vec::new(), Value::Null),
            observation(split, FIXED_ID, &manifest_sha256, Vec::new(), Value::Null),
        ];
        let fixture = Self {
            _root: root,
            manifest_path,
            policy_path,
            observations_path,
            run_path,
            ground_truth_path,
            install_receipt_path,
            runner_receipt_path,
            receipt_key: TestReceiptKey::from_hex("synthetic-receipt-key", RECEIPT_SECRET).unwrap(),
            observations,
        };
        fixture.write_observations();
        fixture
    }

    fn options(&self) -> RevealOptions {
        RevealOptions {
            public_manifest: self.manifest_path.clone(),
            policy: self.policy_path.clone(),
            run_directory: self.run_path.clone(),
            ground_truth: self.ground_truth_path.clone(),
            install_receipt: self.install_receipt_path.clone(),
            runner_receipt: self.runner_receipt_path.clone(),
            receipt_key: self.receipt_key.clone(),
        }
    }

    fn generic_finalized_run_without_receipts() -> Self {
        let fixture = Self::new("gate");
        fs::remove_file(fixture.run_path.join("artifacts/blind-runner-receipt.json")).unwrap();
        rewrite_checksums(&fixture.run_path);
        fixture
    }

    fn with_signed_receipts() -> Self {
        Self::new("gate")
    }

    fn rewrite_runner_receipt_run_id(&self, run_id: &str) {
        self.rewrite_runner_receipt(|receipt| {
            receipt.run_id = run_id.to_owned();
        });
    }

    fn rewrite_runner_receipt(&self, mutate: impl FnOnce(&mut RunnerReceipt)) {
        let mut receipt: RunnerReceipt = serde_json::from_slice(
            &fs::read(self.run_path.join("artifacts/blind-runner-receipt.json")).unwrap(),
        )
        .unwrap();
        mutate(&mut receipt);
        self.receipt_key.sign_runner(&mut receipt).unwrap();
        let bytes = serde_json::to_vec(&receipt).unwrap();
        fs::write(
            self.run_path.join("artifacts/blind-runner-receipt.json"),
            &bytes,
        )
        .unwrap();
        fs::write(&self.runner_receipt_path, bytes).unwrap();
        rewrite_checksums(&self.run_path);
    }

    fn corrupt_runner_receipt_signature(&self) {
        let mut receipt: RunnerReceipt = serde_json::from_slice(
            &fs::read(self.run_path.join("artifacts/blind-runner-receipt.json")).unwrap(),
        )
        .unwrap();
        receipt.trust.signature_sha256 = "b".repeat(64);
        let bytes = serde_json::to_vec(&receipt).unwrap();
        fs::write(
            self.run_path.join("artifacts/blind-runner-receipt.json"),
            &bytes,
        )
        .unwrap();
        fs::write(&self.runner_receipt_path, bytes).unwrap();
        rewrite_checksums(&self.run_path);
    }

    fn replace_observations_after_checksum_with_same_path(&self) {
        fs::write(self.run_path.join("artifacts/observations.jsonl"), b"{}\n").unwrap();
    }

    fn policy(&self) -> bw_blind_model::BlindPolicy {
        bw_blind_model::BlindPolicy::from_path(&self.policy_path).unwrap()
    }

    fn write_observations(&self) {
        let mut jsonl = self
            .observations
            .iter()
            .map(|observation| serde_json::to_string(observation).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        jsonl.push('\n');
        fs::write(&self.observations_path, jsonl).unwrap();
        self.write_run("boundary-witness.blind-run/0.1");
    }

    fn write_run(&self, summary_schema: &str) {
        if let Some(runs_root) = self.run_path.parent() {
            let _ = fs::remove_dir_all(runs_root);
            let run = RunDirectory::create(
                runs_root,
                "synthetic-finalized-run",
                RunMetadata {
                    git_commit: METHOD_COMMIT.to_owned(),
                    deployment_sha256: "a".repeat(64),
                    image_digest: format!("sha256:{}", "b".repeat(64)),
                    config_digest: sha256(&fs::read(&self.manifest_path).unwrap()),
                    build_id: "synthetic-reveal-test".to_owned(),
                    host: "synthetic-host".to_owned(),
                    cpu_limit: None,
                    seed: None,
                    toolchains: ToolchainVersions {
                        stable: "rustc-test".to_owned(),
                        compiler_nightly: None,
                    },
                },
            )
            .unwrap();
            fs::write(
                run.artifacts_dir().join("observations.jsonl"),
                fs::read(&self.observations_path).unwrap(),
            )
            .unwrap();
            for observation in &self.observations {
                if let Some(relative) = observation["witness"]["artifact_path"].as_str() {
                    let path = run.artifacts_dir().join(relative);
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    fs::write(path, b"synthetic witness\n").unwrap();
                }
            }
            let split = self.observations[0]["split"].as_str().unwrap();
            let manifest_sha256 = sha256(&fs::read(&self.manifest_path).unwrap());
            let policy_sha256 = sha256(&fs::read(&self.policy_path).unwrap());
            let mut install = InstallReceipt {
                schema_version: BLIND_INSTALL_RECEIPT_SCHEMA_V01.to_owned(),
                installer_version: "synthetic-installer".to_owned(),
                installer_commit: METHOD_COMMIT.to_owned(),
                method_commit: METHOD_COMMIT.to_owned(),
                archive_sha256: "a".repeat(64),
                deployment_json_sha256: "b".repeat(64),
                public_manifest_sha256: manifest_sha256.clone(),
                policy_sha256,
                installed_pack_tree_sha256: "c".repeat(64),
                installed_path: "synthetic-pack".to_owned(),
                created_at_utc: "2026-07-19T00:00:00Z".to_owned(),
                host_id: "synthetic-installer".to_owned(),
                trust: ReceiptTrust {
                    key_id: String::new(),
                    signature_sha256: String::new(),
                },
            };
            self.receipt_key.sign_install(&mut install).unwrap();
            let install_bytes = serde_json::to_vec(&install).unwrap();
            fs::write(&self.install_receipt_path, &install_bytes).unwrap();
            let observations_bytes =
                fs::read(run.artifacts_dir().join("observations.jsonl")).unwrap();
            let mut runner = RunnerReceipt {
                schema_version: BLIND_RUNNER_RECEIPT_SCHEMA_V01.to_owned(),
                runner_version: "synthetic-runner".to_owned(),
                runner_commit: METHOD_COMMIT.to_owned(),
                run_id: run.run_id().to_owned(),
                suite_id: SUITE_ID.to_owned(),
                split: split.to_owned(),
                method_commit: METHOD_COMMIT.to_owned(),
                archive_sha256: "a".repeat(64),
                deployment_json_sha256: "b".repeat(64),
                install_receipt_sha256: sha256(&install_bytes),
                public_manifest_sha256: manifest_sha256.clone(),
                policy_sha256: sha256(&fs::read(&self.policy_path).unwrap()),
                case_count: self.observations.len() as u64,
                isolation_backend: FormalIsolationBackend::Container,
                case_execution_snapshot_digest: execution_snapshot_digest(
                    &BlindPublicManifest::from_path(&self.manifest_path).unwrap(),
                    &manifest_sha256,
                ),
                observations_sha256: sha256(&observations_bytes),
                stdout_stderr_digest: "e".repeat(64),
                witness_tree_sha256: "f".repeat(64),
                run_checksums_sha256: runner_evidence_digest(run.partial_path()),
                created_at_utc: "2026-07-19T00:00:00Z".to_owned(),
                host_id: "synthetic-runner".to_owned(),
                trust: ReceiptTrust {
                    key_id: String::new(),
                    signature_sha256: String::new(),
                },
            };
            self.receipt_key.sign_runner(&mut runner).unwrap();
            let runner_bytes = serde_json::to_vec(&runner).unwrap();
            fs::write(
                run.artifacts_dir().join("blind-runner-receipt.json"),
                &runner_bytes,
            )
            .unwrap();
            fs::write(&self.runner_receipt_path, &runner_bytes).unwrap();
            run.finalize(FinalizeRun {
                summary: json!({
                    "schema_version": summary_schema,
                    "suite_id": SUITE_ID,
                    "split": split,
                    "case_count": self.observations.len(),
                    "completed_count": self.observations.iter().filter(|value| value["status"] == "completed").count(),
                    "failed_count": self.observations.iter().filter(|value| value["status"] != "completed").count(),
                    "method_commit": METHOD_COMMIT,
                    "public_manifest_sha256": manifest_sha256,
                    "deployment_sha256": "a".repeat(64),
                }),
                execution: None,
                required_trace_files: Vec::new(),
                required_log_files: Vec::new(),
            })
            .unwrap();
        }
    }
}

fn execution_snapshot_digest(manifest: &BlindPublicManifest, manifest_sha256: &str) -> String {
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

fn public_case(case_id: &str) -> Value {
    json!({
        "case_id": case_id,
        "case_root": format!("cases/{case_id}"),
        "case_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "command": { "program": "adapter/bin/run", "args": [], "env": {} },
        "timeout_seconds": 60,
    })
}

fn truth_case(case_id: &str, role: &str, root_cause_key: &str, paired: &[&str]) -> Value {
    json!({
        "case_id": case_id,
        "curator_key": format!("curator-{case_id}"),
        "role": role,
        "component": "synthetic-component",
        "api": "callback_api",
        "root_cause_key": root_cause_key,
        "paired_case_ids": paired,
        "source_revision": "vulnerable-revision",
    })
}

fn observation(
    split: &str,
    case_id: &str,
    manifest_sha256: &str,
    findings: Vec<Value>,
    witness: Value,
) -> Value {
    json!({
        "schema_version": "boundary-witness.blind-observed/0.1",
        "suite_id": SUITE_ID,
        "split": split,
        "case_id": case_id,
        "method_commit": METHOD_COMMIT,
        "public_manifest_sha256": manifest_sha256,
        "status": "completed",
        "findings": findings,
        "witness": witness,
    })
}

fn confirmed_finding() -> Value {
    json!({
        "rule_id": RULE_ID,
        "classification": "confirmed_violation",
        "normalized_signature": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "evidence_complete": true,
    })
}

fn stable_witness() -> Value {
    json!({
        "artifact_path": "witnesses/reproducer.json",
        "artifact_sha256": sha256(b"synthetic witness\n"),
        "replay_attempts": 20,
        "replay_successes": 20,
    })
}

fn serialized(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn rewrite_checksums(root: &PathBuf) {
    let mut files = Vec::new();
    collect_files(root, &mut files);
    files.sort();
    let output = files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            format!("{}  {relative}\n", sha256(&fs::read(&path).unwrap()))
        })
        .collect::<String>();
    fs::write(root.join("checksums.sha256"), output).unwrap();
}

fn collect_files(current: &std::path::Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(current).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().unwrap() == "checksums.sha256" {
            continue;
        }
        if path.is_dir() {
            collect_files(&path, output);
        } else {
            output.push(path);
        }
    }
}

fn runner_evidence_digest(root: &std::path::Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"boundary-witness.runner-evidence-digest/0.1\0");
    hash_evidence_file(&mut hasher, root, "findings.jsonl");
    hash_evidence_file(&mut hasher, root, "artifacts/observations.jsonl");
    for tree in ["artifacts/witnesses", "logs/children", "traces"] {
        hash_evidence_tree(&mut hasher, root, tree);
    }
    format!("{:x}", hasher.finalize())
}

fn hash_evidence_file(hasher: &mut Sha256, root: &std::path::Path, relative: &str) {
    hasher.update(b"F");
    hasher.update(relative.as_bytes());
    hasher.update([0]);
    hasher.update(Sha256::digest(fs::read(root.join(relative)).unwrap()));
}

fn hash_evidence_tree(hasher: &mut Sha256, root: &std::path::Path, relative: &str) {
    hasher.update(b"T");
    hasher.update(relative.as_bytes());
    hasher.update([0]);
    let tree = root.join(relative);
    if !tree.exists() {
        hasher.update(b"absent");
        return;
    }
    hasher.update(b"present");
    let mut files = Vec::new();
    collect_files(&tree, &mut files);
    files.sort();
    for path in files {
        let path = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        hash_evidence_file(hasher, root, &path);
    }
}
