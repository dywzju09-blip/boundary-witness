use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use bw_blind_curator::{PackOptions, RevealOptions, pack, reveal};
use bw_blind_model::{
    BLIND_INSTALL_RECEIPT_SCHEMA_V01, BlindSplit, FormalIsolationBackend, InstallReceipt,
    ReceiptTrust, TestReceiptKey,
};
use bw_blind_runner::{RunOptions, audit_public_pack, run_public_pack};
use bw_experiment::{FinalizeRun, RunDirectory, RunMetadata};
use bw_model::ToolchainVersions;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const METHOD_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const ARCHIVE_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const WITNESS_CONTENT: &str = "synthetic witness\n";
const RECEIPT_SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const RUNNER_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const RUNNER_HOST_ID: &str = "synthetic-runner-host";

#[test]
fn synthetic_blind_gate_native_smoke_rejects_reveal_and_post_pack_tampering() {
    let fixture = Fixture::new();
    let pack_report = pack(fixture.pack_options()).expect("pack synthetic private source");
    let packed_gate_root = fixture.public_out.join("nday-gate");
    let gate_pack_root = fixture.public_out.join(ARCHIVE_SHA256);
    fs::rename(&packed_gate_root, &gate_pack_root).unwrap();
    let eval_pack_root = fixture.public_out.join("nday-eval");

    assert_eq!(pack_report.split_counts[&BlindSplit::Gate], 2);
    assert_eq!(pack_report.split_counts[&BlindSplit::Evaluation], 1);
    assert!(eval_pack_root.join("manifest.json").is_file());
    assert!(
        fixture
            .private_out
            .join("ground-truth/nday-eval.json")
            .is_file()
    );

    let audit_report = audit_public_pack(&gate_pack_root).expect("audit synthetic gate pack");
    assert_eq!(audit_report.split, BlindSplit::Gate);
    assert_eq!(audit_report.case_count, 2);

    fixture.write_install_receipt(&gate_pack_root);
    let run_report = run_public_pack(fixture.run_options(
        gate_pack_root.clone(),
        fixture.runs_root.clone(),
        audit_report.manifest_sha256.clone(),
    ))
    .expect("run audited synthetic gate pack");
    assert_eq!(run_report.split, BlindSplit::Gate);
    assert_eq!(run_report.case_count, 2);
    assert_eq!(run_report.completed_count, 2);

    let reveal_error = reveal(RevealOptions {
        public_manifest: gate_pack_root.join("manifest.json"),
        policy: gate_pack_root.join("policy.toml"),
        run_directory: run_report.final_run.path().to_path_buf(),
        ground_truth: fixture.private_out.join("ground-truth/nday-gate.json"),
        install_receipt: fixture.install_receipt.clone(),
        runner_receipt: run_report.runner_receipt_path.clone(),
        receipt_key: fixture.receipt_key.clone(),
    })
    .unwrap_err()
    .to_string();
    assert!(
        reveal_error.contains("formal reveal requires trusted isolation"),
        "{reveal_error}"
    );

    let missing_runner_receipt_error = reveal(RevealOptions {
        public_manifest: gate_pack_root.join("manifest.json"),
        policy: gate_pack_root.join("policy.toml"),
        run_directory: run_report.final_run.path().to_path_buf(),
        ground_truth: fixture.private_out.join("ground-truth/nday-gate.json"),
        install_receipt: fixture.install_receipt.clone(),
        runner_receipt: run_report
            .final_run
            .path()
            .join("artifacts/missing-runner-receipt.json"),
        receipt_key: fixture.receipt_key.clone(),
    })
    .unwrap_err()
    .to_string();
    assert!(
        missing_runner_receipt_error.contains("runner receipt is required"),
        "{missing_runner_receipt_error}"
    );

    let generic_finalized_run = fixture.generic_finalized_run_without_runner_receipt();
    assert!(
        !generic_finalized_run
            .path()
            .join("artifacts/blind-runner-receipt.json")
            .exists()
    );
    let generic_finalized_run_error = reveal(RevealOptions {
        public_manifest: gate_pack_root.join("manifest.json"),
        policy: gate_pack_root.join("policy.toml"),
        run_directory: generic_finalized_run.path().to_path_buf(),
        ground_truth: fixture.private_out.join("ground-truth/nday-gate.json"),
        install_receipt: fixture.install_receipt.clone(),
        runner_receipt: generic_finalized_run
            .path()
            .join("artifacts/blind-runner-receipt.json"),
        receipt_key: fixture.receipt_key.clone(),
    })
    .unwrap_err()
    .to_string();
    assert!(
        generic_finalized_run_error.contains("runner receipt is required"),
        "{generic_finalized_run_error}"
    );

    let eval_manifest = fs::read(eval_pack_root.join("manifest.json")).unwrap();
    assert_eq!(
        sha256_bytes(&eval_manifest),
        pack_report.public_manifest_sha256[&BlindSplit::Evaluation]
    );
    assert_ne!(
        pack_report.public_manifest_sha256[&BlindSplit::Evaluation],
        audit_report.manifest_sha256
    );

    let tampered_case = first_case_program(&gate_pack_root);
    fs::write(&tampered_case, "tampered synthetic input\n").unwrap();
    let audit_error = audit_public_pack(&gate_pack_root).unwrap_err().to_string();
    assert!(audit_error.contains("checksum mismatch"));

    let rejected_runs_root = fixture.root.path().join("rejected-runs");
    let run_error = match run_public_pack(fixture.run_options(
        gate_pack_root,
        rejected_runs_root.clone(),
        audit_report.manifest_sha256,
    )) {
        Ok(_) => panic!("tampered pack must not execute"),
        Err(error) => error.to_string(),
    };
    assert!(run_error.contains("installed_pack_tree_sha256 mismatch"));
    assert!(!rejected_runs_root.exists());
}

struct Fixture {
    root: TempDir,
    source_root: PathBuf,
    policy_path: PathBuf,
    public_out: PathBuf,
    private_out: PathBuf,
    runs_root: PathBuf,
    install_receipt: PathBuf,
    receipt_key: TestReceiptKey,
}

impl Fixture {
    fn new() -> Self {
        let current_dir = std::env::current_dir().unwrap().canonicalize().unwrap();
        let root = tempfile::tempdir_in(current_dir).unwrap();
        let physical_root = root.path().canonicalize().unwrap();
        let source_root = physical_root.join("private-source");
        let policy_path = physical_root.join("policy.toml");
        let public_out = physical_root.join("public");
        let private_out = physical_root.join("curator-private");
        let runs_root = physical_root.join("runs");
        let install_receipt = physical_root.join("install-receipt.json");
        fs::create_dir_all(&source_root).unwrap();

        let cases = [
            SourceCase {
                key: "opaque-alpha",
                split: "gate",
                role: "violation",
                paired_with: &["opaque-beta"],
                emits_finding: true,
            },
            SourceCase {
                key: "opaque-beta",
                split: "gate",
                role: "safe_control",
                paired_with: &["opaque-alpha"],
                emits_finding: false,
            },
            SourceCase {
                key: "opaque-gamma",
                split: "evaluation",
                role: "fixed_control",
                paired_with: &[],
                emits_finding: false,
            },
        ];
        let mut source_toml = String::from("suite_id = \"synthetic-suite\"\n");
        for source_case in cases {
            let case_root = source_root.join("cases").join(source_case.key);
            fs::create_dir_all(case_root.join("adapter/bin")).unwrap();
            let driver = case_root.join("adapter/bin/driver");
            fs::write(&driver, adapter_script(source_case.emits_finding)).unwrap();
            let mut permissions = fs::metadata(&driver).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&driver, permissions).unwrap();
            source_toml.push_str(&source_case.to_toml());
        }
        fs::write(source_root.join("source.toml"), source_toml).unwrap();
        fs::write(
            &policy_path,
            r#"schema_version = "boundary-witness.blind-policy/0.1"
minimum_replay_attempts = 20
gate_minimum_confirmed_cases = 1
forbidden_public_filename_tokens = ["ground-truth", "ground_truth", "cve-", "ghsa-", "advisory", "poc", "proof-of-concept", "proof_of_concept", "expected-result", "expected_result", "expected result", "private"]
"#,
        )
        .unwrap();

        Self {
            root,
            source_root,
            policy_path,
            public_out,
            private_out,
            runs_root,
            install_receipt,
            receipt_key: TestReceiptKey::from_hex("synthetic-receipt-key", RECEIPT_SECRET).unwrap(),
        }
    }

    fn pack_options(&self) -> PackOptions {
        PackOptions {
            source_root: self.source_root.clone(),
            policy_path: self.policy_path.clone(),
            public_out: self.public_out.clone(),
            private_out: self.private_out.clone(),
            id_salt_hex: "00112233445566778899aabbccddeeff".to_owned(),
            method_commit: METHOD_COMMIT.to_owned(),
        }
    }

    fn run_options(
        &self,
        public_pack_root: PathBuf,
        runs_root: PathBuf,
        manifest_sha256: String,
    ) -> RunOptions {
        let mut metadata = run_metadata(manifest_sha256);
        metadata.image_digest = "native-untrusted-smoke".to_owned();
        RunOptions {
            public_pack_root,
            runs_root,
            metadata,
            install_receipt: self.install_receipt.clone(),
            receipt_key: self.receipt_key.clone(),
            isolation_backend: FormalIsolationBackend::NativeUntrustedSmoke,
            runner_commit: RUNNER_COMMIT.to_owned(),
            runner_host_id: RUNNER_HOST_ID.to_owned(),
        }
    }

    fn write_install_receipt(&self, pack_root: &Path) {
        let mut receipt = InstallReceipt {
            schema_version: BLIND_INSTALL_RECEIPT_SCHEMA_V01.to_owned(),
            installer_version: "synthetic-installer-v1".to_owned(),
            installer_commit: METHOD_COMMIT.to_owned(),
            method_commit: METHOD_COMMIT.to_owned(),
            archive_sha256: ARCHIVE_SHA256.to_owned(),
            deployment_json_sha256: "d".repeat(64),
            public_manifest_sha256: sha256_path(&pack_root.join("manifest.json")),
            policy_sha256: sha256_path(&pack_root.join("policy.toml")),
            installed_pack_tree_sha256: installed_tree_digest(pack_root),
            installed_path: pack_root.canonicalize().unwrap().display().to_string(),
            created_at_utc: "2026-07-19T00:00:00Z".to_owned(),
            host_id: "synthetic-installer-host".to_owned(),
            trust: ReceiptTrust {
                key_id: String::new(),
                signature_sha256: String::new(),
            },
        };
        self.receipt_key.sign_install(&mut receipt).unwrap();
        fs::write(&self.install_receipt, serde_json::to_vec(&receipt).unwrap()).unwrap();
    }

    fn generic_finalized_run_without_runner_receipt(&self) -> bw_experiment::FinalizedRun {
        let run = RunDirectory::create(
            self.root.path().join("generic-runs"),
            "synthetic-generic-finalized-run",
            run_metadata("generic-finalized-run".to_owned()),
        )
        .unwrap();
        fs::write(run.artifacts_dir().join("observations.jsonl"), b"").unwrap();
        run.finalize(FinalizeRun {
            summary: serde_json::json!({
                "schema_version": "synthetic.generic-run/0.1",
                "note": "synthetic fixture without a runner receipt",
            }),
            execution: None,
            required_trace_files: Vec::new(),
            required_log_files: Vec::new(),
        })
        .unwrap()
    }
}

struct SourceCase {
    key: &'static str,
    split: &'static str,
    role: &'static str,
    paired_with: &'static [&'static str],
    emits_finding: bool,
}

impl SourceCase {
    fn to_toml(&self) -> String {
        let paired_with = self
            .paired_with
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"
[[cases]]
curator_key = "{}"
split = "{}"
role = "{}"
component = "synthetic-component"
api = "synthetic-api"
root_cause_key = "synthetic-root"
paired_with = [{}]
source_revision = "synthetic-revision"
case_dir = "cases/{}"
public_command = {{ program = "adapter/bin/driver", args = [], env = {{}} }}
timeout_seconds = 10
"#,
            self.key, self.split, self.role, paired_with, self.key
        )
    }
}

fn adapter_script(emits_finding: bool) -> String {
    let (findings, witness, create_witness) = if emits_finding {
        (
            format!(
                r#"[{{"rule_id":"synthetic.lifecycle.rule","classification":"confirmed_violation","normalized_signature":"{}","evidence_complete":true}}]"#,
                "c".repeat(64)
            ),
            format!(
                r#"{{"artifact_path":"witness/replay.json","artifact_sha256":"{}","replay_attempts":20,"replay_successes":20}}"#,
                sha256_bytes(WITNESS_CONTENT.as_bytes())
            ),
            "mkdir -p \"$BW_CHILD_WORK_DIR/witness\"\nprintf 'synthetic witness\\n' > \"$BW_CHILD_WORK_DIR/witness/replay.json\"",
        )
    } else {
        ("[]".to_owned(), "null".to_owned(), "")
    };
    format!(
        r#"#!/bin/sh
set -eu
{create_witness}
cat > "$BW_CHILD_WORK_DIR/observation.json" <<EOF
{{"schema_version":"boundary-witness.blind-observed/0.1","suite_id":"$BW_BLIND_SUITE_ID","split":"$BW_BLIND_SPLIT","case_id":"$BW_BLIND_CASE_ID","method_commit":"$BW_BLIND_METHOD_COMMIT","public_manifest_sha256":"$BW_BLIND_MANIFEST_SHA256","status":"completed","findings":{findings},"witness":{witness}}}
EOF
"#
    )
}

fn run_metadata(config_digest: String) -> RunMetadata {
    RunMetadata {
        git_commit: METHOD_COMMIT.to_owned(),
        deployment_sha256: ARCHIVE_SHA256.to_owned(),
        image_digest: format!("sha256:{}", "b".repeat(64)),
        config_digest,
        build_id: "synthetic-blind-e2e".to_owned(),
        host: "synthetic-linux-runner".to_owned(),
        cpu_limit: Some(1),
        seed: Some(7),
        toolchains: ToolchainVersions {
            stable: "rustc-synthetic".to_owned(),
            compiler_nightly: None,
        },
    }
}

fn first_case_program(pack_root: &Path) -> PathBuf {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(pack_root.join("manifest.json")).unwrap()).unwrap();
    let case_root = manifest["cases"][0]["case_root"].as_str().unwrap();
    let program = manifest["cases"][0]["command"]["program"].as_str().unwrap();
    pack_root.join(case_root).join(program)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_path(path: &Path) -> String {
    sha256_bytes(&fs::read(path).unwrap())
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
    format!("{:x}", hasher.finalize())
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
