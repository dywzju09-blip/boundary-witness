use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use bw_model::{CallbackRetentionContract, Finding, RuntimeEventEnvelope, StaticFactEnvelope};
use bw_oracle::{Oracle, OracleEngine, StaticFactIndex};
use clap::Args;

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl_values, read_to_string, validate_trace},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct AnalyzeArgs {
    #[arg(long = "static")]
    static_facts: PathBuf,
    #[arg(long)]
    contract: PathBuf,
    #[arg(long)]
    trace: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

pub fn run(args: AnalyzeArgs) -> Result<CommandStatus, CliError> {
    validate_trace(&args.trace, args.max_line_bytes)?;

    let static_facts =
        read_jsonl_values::<StaticFactEnvelope>(&args.static_facts, args.max_line_bytes)?;
    let static_index = StaticFactIndex::from_envelopes(static_facts)?;
    let contract = CallbackRetentionContract::from_toml_str(&read_to_string(&args.contract)?)?;
    let events = read_jsonl_values::<RuntimeEventEnvelope>(&args.trace, args.max_line_bytes)?;

    let mut oracle = Oracle::new(static_index, contract);
    for event in &events {
        oracle.observe(event)?;
    }
    let summary = oracle.finish()?;
    write_findings(args.output.as_deref(), summary.findings())?;

    if summary.findings().is_empty() {
        Ok(CommandStatus::Success)
    } else {
        Ok(CommandStatus::Finding)
    }
}

fn write_findings(path: Option<&Path>, findings: &[Finding]) -> Result<(), CliError> {
    match path {
        Some(path) => {
            let file = File::create(path).map_err(|error| {
                CliError::input("BW-IO", format!("{}: {}", path.display(), error))
            })?;
            let mut writer = BufWriter::new(file);
            write_findings_to(&mut writer, findings)
        }
        None => {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            write_findings_to(&mut stdout, findings)
        }
    }
}

fn write_findings_to(writer: &mut impl Write, findings: &[Finding]) -> Result<(), CliError> {
    for finding in findings {
        serde_json::to_writer(&mut *writer, finding)
            .map_err(|error| CliError::internal(error.to_string()))?;
        writer
            .write_all(b"\n")
            .map_err(|error| CliError::input("BW-IO", error.to_string()))?;
    }
    Ok(())
}
