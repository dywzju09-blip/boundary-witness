use std::{
    fmt::Write as _,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use assert_cmd::Command;
use bw_blind_model::{
    BLIND_INSTALL_RECEIPT_SCHEMA_V01, InstallReceipt, ReceiptTrust, TestReceiptKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const DEPLOYMENT: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const IMAGE: &str = "native-untrusted-smoke";

#[test]
fn run_cli_requires_install_provenance_arguments() {
    let fixture = PublicPack::new();
    let runs = fixture._temp.path().join("runs");

    Command::cargo_bin("bw-blind-run")
        .unwrap()
        .args([
            "--pack",
            path(&fixture.pack),
            "--runs-root",
            path(&runs),
            "--commit",
            COMMIT,
            "--deployment-sha256",
            DEPLOYMENT,
            "--image-digest",
            IMAGE,
            "--stable-toolchain",
            "1.97.0",
        ])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("required arguments"));
}

#[test]
fn run_cli_requires_explicit_runner_identity_arguments() {
    let fixture = PublicPack::new();
    let runs = fixture._temp.path().join("runs");

    Command::cargo_bin("bw-blind-run")
        .unwrap()
        .args(base_run_args(&fixture.pack, &runs, COMMIT, DEPLOYMENT))
        .args(fixture.provenance_args_without_runner_identity())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("required arguments"));
}

#[test]
fn run_cli_verifies_install_receipt_before_auditing_the_pack() {
    let fixture = PublicPack::new();
    let runs = fixture._temp.path().join("runs");
    let mut receipt: Value =
        serde_json::from_slice(&fs::read(&fixture.install_receipt).unwrap()).unwrap();
    receipt["trust"]["signature_sha256"] = Value::String("a".repeat(64));
    fs::write(
        &fixture.install_receipt,
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
    fs::write(fixture.pack.join("manifest.json"), "not JSON").unwrap();

    Command::cargo_bin("bw-blind-run")
        .unwrap()
        .args(base_run_args(&fixture.pack, &runs, COMMIT, DEPLOYMENT))
        .args(fixture.provenance_args())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("receipt signature mismatch"));
}

#[test]
fn run_cli_binds_signed_receipt_to_pack_before_auditing_semantics() {
    let fixture = PublicPack::new();
    let runs = fixture._temp.path().join("runs");
    // Keep the receipt signature valid while making the current pack both
    // provenance-mismatched and semantically unparsable.
    fs::write(fixture.pack.join("manifest.json"), "not JSON").unwrap();

    Command::cargo_bin("bw-blind-run")
        .unwrap()
        .args(base_run_args(&fixture.pack, &runs, COMMIT, DEPLOYMENT))
        .args(fixture.provenance_args())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("public_manifest_sha256 mismatch"));

    assert!(!runs.exists());
}

#[test]
fn audit_cli_accepts_a_public_pack_and_prints_json() {
    let fixture = PublicPack::new();

    let output = Command::cargo_bin("bw-blind-audit")
        .unwrap()
        .arg(&fixture.pack)
        .assert()
        .success()
        .get_output()
        .clone();

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["suite_id"], "cli-suite");
    assert_eq!(report["case_count"], 0);
}

#[test]
fn run_cli_uses_public_metadata_and_prints_json() {
    let fixture = PublicPack::new_with_case();
    let runs = fixture._temp.path().join("runs");
    let public_manifest_sha256 = sha256(&fs::read(fixture.pack.join("manifest.json")).unwrap());

    let output = Command::cargo_bin("bw-blind-run")
        .unwrap()
        .args(base_run_args(&fixture.pack, &runs, COMMIT, DEPLOYMENT))
        .args(fixture.provenance_args())
        .assert()
        .success()
        .get_output()
        .clone();

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["suite_id"], "cli-suite");
    assert_eq!(report["case_count"], 1);
    let run_path = std::path::PathBuf::from(report["run_path"].as_str().unwrap());
    let manifest: Value =
        serde_json::from_slice(&fs::read(run_path.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["git_commit"], COMMIT);
    assert_eq!(manifest["deployment_sha256"], DEPLOYMENT);
    assert_eq!(manifest["image_digest"], IMAGE);
    assert_eq!(manifest["config_digest"], public_manifest_sha256);
    assert_eq!(manifest["toolchains"]["stable"], "1.97.0");
}

#[test]
fn runner_rejects_ground_truth_without_advertising_it() {
    let output = Command::cargo_bin("bw-blind-run")
        .unwrap()
        .args(["--ground-truth", "private.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("runner does not accept ground truth")
    );

    for binary in ["bw-blind-audit", "bw-blind-run"] {
        let output = Command::cargo_bin(binary)
            .unwrap()
            .arg("--help")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            !String::from_utf8(output.stdout)
                .unwrap()
                .contains("ground-truth")
        );
    }
}

#[test]
fn run_cli_rejects_mismatched_commit_and_invalid_deployment_digest() {
    let fixture = PublicPack::new();
    let runs = fixture._temp.path().join("runs");
    let command = |commit: &str, deployment: &str| {
        let mut command = Command::cargo_bin("bw-blind-run").unwrap();
        command.args(base_run_args(&fixture.pack, &runs, commit, deployment));
        command.args(fixture.provenance_args());
        command
    };

    command("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DEPLOYMENT)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("git commit does not match"));
    command(COMMIT, "not-a-digest")
        .assert()
        .code(2)
        .stderr(predicates::str::contains(
            "deployment digest must be 64 lowercase hexadecimal characters",
        ));
    assert!(!runs.exists());
}

struct PublicPack {
    _temp: tempfile::TempDir,
    pack: PathBuf,
    install_receipt: PathBuf,
    receipt_key: PathBuf,
}

impl PublicPack {
    fn new() -> Self {
        let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let pack = temp.path().canonicalize().unwrap().join(DEPLOYMENT);
        fs::create_dir_all(pack.join("cases")).unwrap();
        let policy = r#"schema_version = "boundary-witness.blind-policy/0.1"
minimum_replay_attempts = 2
gate_minimum_confirmed_cases = 1
forbidden_public_filename_tokens = ["ground-truth", "ground_truth", "cve-", "ghsa-", "advisory", "poc", "proof-of-concept", "proof_of_concept", "expected-result", "expected_result", "expected result", "private"]
"#;
        fs::write(pack.join("policy.toml"), policy).unwrap();
        fs::write(
            pack.join("manifest.json"),
            serde_json::to_vec_pretty(&json!({
                "schema_version": "boundary-witness.blind-public/0.1",
                "suite_id": "cli-suite",
                "split": "gate",
                "method_commit": COMMIT,
                "policy_sha256": sha256(policy.as_bytes()),
                "cases": []
            }))
            .unwrap(),
        )
        .unwrap();
        let mut checksums = ["manifest.json", "policy.toml"]
            .map(|relative| {
                format!(
                    "{}  {relative}",
                    sha256(&fs::read(pack.join(relative)).unwrap())
                )
            })
            .join("\n");
        checksums.push('\n');
        fs::write(pack.join("checksums.sha256"), checksums).unwrap();
        let install_receipt = temp.path().join("install-receipt.json");
        let receipt_key = temp.path().join("receipt-key.hex");
        fs::write(&receipt_key, RECEIPT_SECRET).unwrap();
        let fixture = Self {
            _temp: temp,
            pack,
            install_receipt,
            receipt_key,
        };
        fixture.write_install_receipt();
        fixture
    }

    fn new_with_case() -> Self {
        let fixture = Self::new();
        let case_root = fixture.pack.join("cases/blind-8f34a923d01c77ab");
        let driver = case_root.join("adapter/bin/driver");
        fs::create_dir_all(driver.parent().unwrap()).unwrap();
        fs::write(case_root.join("COMPLETE"), "complete\n").unwrap();
        fs::write(&driver, "#!/bin/sh\nexit 1\n").unwrap();
        let mut permissions = fs::metadata(&driver).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&driver, permissions).unwrap();

        let policy = fs::read_to_string(fixture.pack.join("policy.toml")).unwrap();
        fs::write(
            fixture.pack.join("manifest.json"),
            serde_json::to_vec_pretty(&json!({
                "schema_version": "boundary-witness.blind-public/0.1",
                "suite_id": "cli-suite",
                "split": "gate",
                "method_commit": COMMIT,
                "policy_sha256": sha256(policy.as_bytes()),
                "cases": [{
                    "case_id": "blind-8f34a923d01c77ab",
                    "case_root": "cases/blind-8f34a923d01c77ab",
                    "case_sha256": case_tree_digest(&case_root),
                    "command": { "program": "adapter/bin/driver", "args": [], "env": {} },
                    "timeout_seconds": 10
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        write_checksums(&fixture.pack);
        fixture.write_install_receipt();
        fixture
    }

    fn provenance_args(&self) -> Vec<String> {
        let mut args = self.provenance_args_without_runner_identity();
        args.extend([
            "--runner-commit".to_owned(),
            "fedcba9876543210fedcba9876543210fedcba98".to_owned(),
            "--runner-host-id".to_owned(),
            "cli-synthetic-runner".to_owned(),
        ]);
        args
    }

    fn provenance_args_without_runner_identity(&self) -> Vec<String> {
        vec![
            "--install-receipt".to_owned(),
            path(&self.install_receipt).to_owned(),
            "--receipt-key".to_owned(),
            path(&self.receipt_key).to_owned(),
            "--receipt-key-id".to_owned(),
            "cli-receipt-key".to_owned(),
            "--isolation".to_owned(),
            "native-untrusted-smoke".to_owned(),
        ]
    }

    fn write_install_receipt(&self) {
        let key = TestReceiptKey::from_hex("cli-receipt-key", RECEIPT_SECRET).unwrap();
        let mut receipt = InstallReceipt {
            schema_version: BLIND_INSTALL_RECEIPT_SCHEMA_V01.to_owned(),
            installer_version: "synthetic-installer-v1".to_owned(),
            installer_commit: COMMIT.to_owned(),
            method_commit: COMMIT.to_owned(),
            archive_sha256: DEPLOYMENT.to_owned(),
            deployment_json_sha256: "d".repeat(64),
            public_manifest_sha256: sha256(&fs::read(self.pack.join("manifest.json")).unwrap()),
            policy_sha256: sha256(&fs::read(self.pack.join("policy.toml")).unwrap()),
            installed_pack_tree_sha256: installed_tree_digest(&self.pack),
            installed_path: self.pack.canonicalize().unwrap().display().to_string(),
            created_at_utc: "2026-07-19T00:00:00Z".to_owned(),
            host_id: "cli-synthetic-host".to_owned(),
            trust: ReceiptTrust {
                key_id: String::new(),
                signature_sha256: String::new(),
            },
        };
        key.sign_install(&mut receipt).unwrap();
        fs::write(&self.install_receipt, serde_json::to_vec(&receipt).unwrap()).unwrap();
    }
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn base_run_args<'a>(
    pack: &'a Path,
    runs: &'a Path,
    commit: &'a str,
    deployment: &'a str,
) -> Vec<&'a str> {
    vec![
        "--pack",
        path(pack),
        "--runs-root",
        path(runs),
        "--commit",
        commit,
        "--deployment-sha256",
        deployment,
        "--image-digest",
        IMAGE,
        "--stable-toolchain",
        "1.97.0",
    ]
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

const RECEIPT_SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1e1f";

fn write_checksums(root: &Path) {
    let mut checksums = String::new();
    for relative in regular_files(root) {
        if relative != "checksums.sha256" {
            writeln!(
                &mut checksums,
                "{}  {relative}",
                sha256(&fs::read(root.join(&relative)).unwrap())
            )
            .unwrap();
        }
    }
    fs::write(root.join("checksums.sha256"), checksums).unwrap();
}

fn case_tree_digest(case_root: &Path) -> String {
    let mut hasher = Sha256::new();
    for relative in regular_files(case_root) {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(sha256(&fs::read(case_root.join(&relative)).unwrap()).as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn installed_tree_digest(root: &Path) -> String {
    let mut hasher = Sha256::new();
    let root_mode = fs::metadata(root).unwrap().permissions().mode() & 0o7777;
    add_directory(&mut hasher, b".", root_mode);
    for relative in regular_paths(root) {
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.is_dir() {
            add_directory(&mut hasher, relative.as_bytes(), mode);
        } else {
            let bytes = fs::read(path).unwrap();
            hasher.update(b"F");
            hasher.update((relative.len() as u64).to_be_bytes());
            hasher.update(relative.as_bytes());
            hasher.update(mode.to_be_bytes());
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(Sha256::digest(bytes));
        }
    }
    format!("{:x}", hasher.finalize())
}

fn add_directory(hasher: &mut Sha256, path: &[u8], mode: u32) {
    hasher.update(b"D");
    hasher.update((path.len() as u64).to_be_bytes());
    hasher.update(path);
    hasher.update(mode.to_be_bytes());
}

fn regular_files(root: &Path) -> Vec<String> {
    regular_paths(root)
        .into_iter()
        .filter(|relative| root.join(relative).is_file())
        .collect()
}

fn regular_paths(root: &Path) -> Vec<String> {
    fn visit(root: &Path, current: &Path, output: &mut Vec<String>) {
        let mut entries = fs::read_dir(current)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            output.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            if entry.file_type().unwrap().is_dir() {
                visit(root, &path, output);
            }
        }
    }

    let mut output = Vec::new();
    visit(root, root, &mut output);
    output.sort();
    output
}
