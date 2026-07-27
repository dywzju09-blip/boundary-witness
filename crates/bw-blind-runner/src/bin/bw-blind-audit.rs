use std::{error::Error, path::PathBuf};

use bw_blind_runner::audit_public_pack;
use clap::Parser;
use serde_json::json;

#[derive(Debug, Parser)]
#[command(about = "Audit a public blind N-day pack")]
struct Cli {
    public_pack_root: PathBuf,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("bw-blind-audit: {error}");
        std::process::exit(2);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let audit = audit_public_pack(cli.public_pack_root)?;
    println!(
        "{}",
        json!({
            "suite_id": audit.suite_id,
            "split": audit.split,
            "method_commit": audit.method_commit,
            "manifest_sha256": audit.manifest_sha256,
            "case_count": audit.case_count,
            "case_digests": audit.case_digests,
        })
    );
    Ok(())
}
