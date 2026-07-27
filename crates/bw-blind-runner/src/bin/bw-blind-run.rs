use std::{error::Error, ffi::OsStr, fs, path::PathBuf};

use bw_blind_model::{FormalIsolationBackend, TestReceiptKey};
use bw_blind_runner::{RunOptions, run_public_pack, verify_install_receipt};
use bw_experiment::{RunMetadata, ToolchainVersions};
use clap::Parser;
use serde_json::json;

#[derive(Debug, Parser)]
#[command(about = "Run a public blind N-day pack")]
struct Cli {
    #[arg(long)]
    pack: PathBuf,
    #[arg(long)]
    runs_root: PathBuf,
    #[arg(long)]
    commit: String,
    #[arg(long)]
    deployment_sha256: String,
    #[arg(long)]
    image_digest: String,
    #[arg(long)]
    stable_toolchain: String,
    #[arg(long)]
    install_receipt: PathBuf,
    #[arg(long)]
    receipt_key: PathBuf,
    #[arg(long)]
    receipt_key_id: String,
    /// `container` is Linux-only formal evidence; `native-untrusted-smoke` is local smoke only.
    #[arg(long, value_parser = parse_isolation_backend)]
    isolation: FormalIsolationBackend,
    /// Commit of the runner binary/source, not the public method commit supplied by --commit.
    #[arg(long)]
    runner_commit: String,
    /// Stable host or service identity for the runner receipt.
    #[arg(long)]
    runner_host_id: String,
}

fn main() {
    reject_ground_truth_argument();
    if let Err(error) = run(Cli::parse()) {
        eprintln!("bw-blind-run: {error}");
        std::process::exit(2);
    }
}

fn reject_ground_truth_argument() {
    let has_ground_truth = std::env::args_os().skip(1).any(|argument| {
        argument == OsStr::new("--ground-truth")
            || argument.to_string_lossy().starts_with("--ground-truth=")
    });
    if has_ground_truth {
        eprintln!("bw-blind-run: runner does not accept ground truth");
        std::process::exit(2);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let receipt_key = read_receipt_key(&cli.receipt_key, cli.receipt_key_id)?;
    // Authenticate install provenance before parsing untrusted pack semantics.
    let verified_install_receipt = verify_install_receipt(&cli.install_receipt, &receipt_key)?;
    let metadata = RunMetadata {
        git_commit: cli.commit,
        deployment_sha256: cli.deployment_sha256,
        image_digest: cli.image_digest,
        config_digest: verified_install_receipt.receipt.public_manifest_sha256,
        build_id: "bw-blind-runner".to_owned(),
        host: cli.runner_host_id.clone(),
        cpu_limit: None,
        seed: None,
        toolchains: ToolchainVersions {
            stable: cli.stable_toolchain,
            compiler_nightly: None,
        },
    };
    let report = run_public_pack(RunOptions {
        public_pack_root: cli.pack,
        runs_root: cli.runs_root,
        metadata,
        install_receipt: cli.install_receipt,
        receipt_key,
        isolation_backend: cli.isolation,
        runner_commit: cli.runner_commit,
        runner_host_id: cli.runner_host_id,
    })?;
    println!(
        "{}",
        json!({
            "run_id": report.final_run.run_id(),
            "run_path": report.final_run.path(),
            "suite_id": report.suite_id,
            "split": report.split,
            "case_count": report.case_count,
            "completed_count": report.completed_count,
            "failed_count": report.failed_count,
            "runner_receipt_path": report.runner_receipt_path,
            "runner_receipt_sha256": report.runner_receipt_sha256,
        })
    );
    Ok(())
}

fn read_receipt_key(
    path: &std::path::Path,
    key_id: String,
) -> Result<TestReceiptKey, Box<dyn Error>> {
    let secret = fs::read_to_string(path)?;
    Ok(TestReceiptKey::from_hex(key_id, secret.trim())?)
}

fn parse_isolation_backend(input: &str) -> Result<FormalIsolationBackend, String> {
    match input {
        "container" => Ok(FormalIsolationBackend::Container),
        "cgroup-pid-namespace" => Ok(FormalIsolationBackend::CgroupPidNamespace),
        "native-untrusted-smoke" => Ok(FormalIsolationBackend::NativeUntrustedSmoke),
        _ => Err(
            "isolation must be container, cgroup-pid-namespace, or native-untrusted-smoke"
                .to_owned(),
        ),
    }
}
