use std::{env, error::Error, fs, path::PathBuf, process::ExitCode};

use rusqlite_lab_shared::blind_runner::{
    parse_ground_truth, parse_runner_config, read_observed_results, run_config,
    verify_against_ground_truth, write_observed_results, GroundTruthSet,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bw-rusqlite-runner: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("run") => {
            let config_path = required_path(&mut args, "config path")?;
            let results_path = required_path(&mut args, "observed results path")?;
            let config = parse_runner_config(&fs::read_to_string(config_path)?)?;
            let results = run_config(&config)?;
            write_observed_results(&results_path, &results)?;
        }
        Some("verify") => {
            let results_path = required_path(&mut args, "observed results path")?;
            let ground_truth_path = required_path(&mut args, "ground truth path")?;
            let ground_truth = parse_ground_truth(&fs::read_to_string(ground_truth_path)?)?;
            let observed = read_observed_results(&results_path)?;
            let report = verify_against_ground_truth(
                &observed,
                &GroundTruthSet {
                    cases: ground_truth.cases,
                },
            )?;
            serde_json::to_writer_pretty(std::io::stdout(), &report)?;
            println!();
            if !report.mismatches.is_empty() {
                return Err("blind verification found mismatches".into());
            }
        }
        _ => {
            eprintln!(
                "usage:\n  bw-rusqlite-runner run <config.toml> <observed.jsonl>\n  bw-rusqlite-runner verify <observed.jsonl> <ground-truth.toml>"
            );
            return Err("invalid command".into());
        }
    }
    Ok(())
}

fn required_path(
    args: &mut impl Iterator<Item = String>,
    label: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {label}").into())
}
