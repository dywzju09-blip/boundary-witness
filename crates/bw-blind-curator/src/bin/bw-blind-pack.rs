use std::{error::Error, path::PathBuf};

use bw_blind_curator::{PackOptions, pack};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(about = "Build separated public and private blind N-day packs")]
struct Cli {
    #[arg(long)]
    source: PathBuf,
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    public_out: PathBuf,
    #[arg(long)]
    private_out: PathBuf,
    #[arg(long)]
    id_salt_hex: String,
    #[arg(long = "commit")]
    method_commit: String,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("bw-blind-pack: {error}");
        std::process::exit(2);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let report = pack(PackOptions {
        source_root: cli.source,
        policy_path: cli.policy,
        public_out: cli.public_out,
        private_out: cli.private_out,
        id_salt_hex: cli.id_salt_hex,
        method_commit: cli.method_commit,
    })?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
