use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use bw_blind_curator::{GateDecision, RevealOptions, reveal};
use bw_blind_model::{BlindPolicy, BlindSplit, TestReceiptKey};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(about = "Reveal private truth for blind N-day observations")]
struct Cli {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    run: PathBuf,
    #[arg(long)]
    ground_truth: PathBuf,
    #[arg(long)]
    install_receipt: PathBuf,
    #[arg(long)]
    runner_receipt: PathBuf,
    #[arg(long)]
    receipt_key: PathBuf,
    #[arg(long)]
    receipt_key_id: String,
    #[arg(long)]
    out: PathBuf,
}

fn main() {
    match run(Cli::parse()) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("bw-blind-reveal: {error}");
            std::process::exit(2);
        }
    }
}

fn run(cli: Cli) -> Result<i32, Box<dyn Error>> {
    ensure_output_is_separate(&cli)?;
    let policy = BlindPolicy::from_path(&cli.policy)?;
    let receipt_key = read_receipt_key(&cli.receipt_key, cli.receipt_key_id)?;
    let report = reveal(RevealOptions {
        public_manifest: cli.manifest,
        policy: cli.policy,
        run_directory: cli.run,
        ground_truth: cli.ground_truth,
        install_receipt: cli.install_receipt,
        runner_receipt: cli.runner_receipt,
        receipt_key,
    })?;

    let mut output = serde_json::to_vec_pretty(&report)?;
    output.push(b'\n');
    fs::write(cli.out, output)?;

    if report.split() == BlindSplit::Gate {
        let decision = GateDecision::from_reveal(&report, &policy)?;
        println!("{}", serde_json::to_string(&decision)?);
        Ok(i32::from(!decision.gate_passed))
    } else {
        println!("{}", serde_json::to_string(&report)?);
        Ok(0)
    }
}

fn ensure_output_is_separate(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let output = physical_destination(&cli.out)?;
    for input in [
        &cli.manifest,
        &cli.policy,
        &cli.ground_truth,
        &cli.install_receipt,
        &cli.runner_receipt,
        &cli.receipt_key,
    ] {
        let input = fs::canonicalize(input)?;
        if output == input {
            return Err(format!("reveal output must not alias input: {}", input.display()).into());
        }
        if let Some(parent) = input.parent()
            && output.starts_with(parent)
        {
            return Err(format!(
                "reveal output must not be inside frozen input directory: {}",
                parent.display()
            )
            .into());
        }
    }
    let run = fs::canonicalize(&cli.run)?;
    if output == run || output.starts_with(&run) {
        return Err("reveal output must not be inside finalized run directory".into());
    }
    Ok(())
}

fn read_receipt_key(path: &Path, key_id: String) -> Result<TestReceiptKey, Box<dyn Error>> {
    let hex = fs::read_to_string(path)?;
    Ok(TestReceiptKey::from_hex(key_id, hex.trim())?)
}

fn physical_destination(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut ancestor = absolute;
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(&ancestor) {
            Ok(mut destination) => {
                for component in missing.iter().rev() {
                    destination.push(component);
                }
                return Ok(destination);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(component) = ancestor.file_name() else {
                    return Err(error);
                };
                missing.push(component.to_os_string());
                ancestor.pop();
            }
            Err(error) => return Err(error),
        }
    }
}
