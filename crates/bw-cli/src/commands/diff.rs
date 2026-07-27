use std::path::PathBuf;

use bw_model::{CheckpointKind, Finding, RuntimeEvent, RuntimeEventEnvelope};
use bw_oracle::{CheckpointCoverage, diff_findings, normalize_finding};
use clap::Args;

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl_values, validate_trace, write_json_stdout},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct DiffArgs {
    #[arg(long)]
    baseline: PathBuf,
    #[arg(long)]
    candidate: PathBuf,
    #[arg(long)]
    baseline_trace: PathBuf,
    #[arg(long)]
    candidate_trace: PathBuf,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

pub fn run(args: DiffArgs) -> Result<CommandStatus, CliError> {
    let baseline_findings = normalize_findings(read_jsonl_values::<Finding>(
        &args.baseline,
        args.max_line_bytes,
    )?)?;
    let candidate_findings = normalize_findings(read_jsonl_values::<Finding>(
        &args.candidate,
        args.max_line_bytes,
    )?)?;
    let baseline_checkpoints = checkpoint_coverage(&args.baseline_trace, args.max_line_bytes)?;
    let candidate_checkpoints = checkpoint_coverage(&args.candidate_trace, args.max_line_bytes)?;
    let diff = diff_findings(
        &baseline_findings,
        &candidate_findings,
        &baseline_checkpoints,
        &candidate_checkpoints,
    );

    let has_difference = !diff.added_signatures.is_empty()
        || !diff.removed_signatures.is_empty()
        || !diff.comparable;
    write_json_stdout(&diff)?;
    if has_difference {
        Ok(CommandStatus::Finding)
    } else {
        Ok(CommandStatus::Success)
    }
}

fn normalize_findings(
    findings: Vec<Finding>,
) -> Result<Vec<bw_oracle::NormalizedFinding>, CliError> {
    findings
        .iter()
        .map(normalize_finding)
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

fn checkpoint_coverage(
    path: &std::path::Path,
    max_line_bytes: usize,
) -> Result<CheckpointCoverage, CliError> {
    validate_trace(path, max_line_bytes)?;
    let mut checkpoints = Vec::<CheckpointKind>::new();
    for event in read_jsonl_values::<RuntimeEventEnvelope>(path, max_line_bytes)? {
        if let RuntimeEvent::Checkpoint(checkpoint) = event.payload {
            checkpoints.push(checkpoint.checkpoint);
        }
    }
    Ok(CheckpointCoverage::new(checkpoints))
}
