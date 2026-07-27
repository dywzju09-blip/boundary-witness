use std::{collections::VecDeque, env, error::Error, path::PathBuf};

use bw_experiment::{
    D0CaseMatrix, D0GroundTruth, D0RunMode, D0RunOptions, RunMetadata, ToolchainVersions, run_d0,
    validate_d0_matrix_against_ground_truth,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("bw-d0: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1).collect::<VecDeque<_>>();
    match args.pop_front().as_deref() {
        Some("--check-matrix") => {
            let matrix_path = required_value(&mut args, "matrix path")?;
            expect_flag(&mut args, "--ground-truth")?;
            let ground_truth_path = required_value(&mut args, "ground truth path")?;
            let matrix = D0CaseMatrix::from_path(matrix_path)?;
            let ground_truth = D0GroundTruth::from_path(ground_truth_path)?;
            validate_d0_matrix_against_ground_truth(&matrix, &ground_truth)?;
            println!(
                "{{\"status\":\"ok\",\"suite_id\":\"{}\",\"cases\":{},\"repetitions\":{}}}",
                matrix.suite_id,
                matrix.cases.len(),
                matrix.repetitions
            );
            Ok(())
        }
        Some("run") => {
            let cli = RunCli::parse(args)?;
            let matrix = D0CaseMatrix::from_path(&cli.matrix)?;
            let report = run_d0(D0RunOptions {
                matrix,
                repo_root: cli.repo_root,
                runs_root: cli.runs_root,
                contract: cli.contract,
                mode: cli.mode,
                metadata: RunMetadata {
                    git_commit: cli.commit,
                    deployment_sha256: cli.deployment_sha256,
                    image_digest: cli.image_digest,
                    config_digest: cli.config_digest,
                    build_id: cli.build_id,
                    host: cli.host,
                    cpu_limit: cli.cpu_limit,
                    seed: None,
                    toolchains: ToolchainVersions {
                        stable: cli.stable_toolchain,
                        compiler_nightly: cli.compiler_nightly,
                    },
                },
            })?;
            println!(
                "{{\"status\":\"ok\",\"mode\":\"{}\",\"run_id\":\"{}\",\"path\":\"{}\",\"total_replays\":{},\"compile_check_count\":{}}}",
                mode_label(cli.mode),
                escape_json(report.final_run.run_id()),
                escape_json(&report.final_run.path().display().to_string()),
                report.summary.total_replays,
                report.compile_check_count
            );
            Ok(())
        }
        None => {
            print_usage();
            Ok(())
        }
        _ => Err("invalid arguments".into()),
    }
}

#[derive(Debug)]
struct RunCli {
    matrix: PathBuf,
    repo_root: PathBuf,
    runs_root: PathBuf,
    contract: PathBuf,
    mode: D0RunMode,
    commit: String,
    deployment_sha256: String,
    image_digest: String,
    config_digest: String,
    build_id: String,
    host: String,
    stable_toolchain: String,
    compiler_nightly: Option<String>,
    cpu_limit: Option<u32>,
}

impl RunCli {
    fn parse(mut args: VecDeque<String>) -> Result<Self, Box<dyn Error>> {
        let mut cli = Self {
            matrix: PathBuf::from("experiments/configs/d0-cases.toml"),
            repo_root: PathBuf::from("."),
            runs_root: PathBuf::from("/root/boundary-witness/runs"),
            contract: PathBuf::from("contracts/callback-retention/contract.toml"),
            mode: D0RunMode::Preflight,
            commit: String::new(),
            deployment_sha256: String::new(),
            image_digest: "native".to_owned(),
            config_digest: String::new(),
            build_id: String::new(),
            host: env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_owned()),
            stable_toolchain: String::new(),
            compiler_nightly: None,
            cpu_limit: None,
        };

        while let Some(flag) = args.pop_front() {
            match flag.as_str() {
                "--matrix" => cli.matrix = PathBuf::from(required_value(&mut args, "--matrix")?),
                "--repo-root" => {
                    cli.repo_root = PathBuf::from(required_value(&mut args, "--repo-root")?);
                }
                "--runs-root" => {
                    cli.runs_root = PathBuf::from(required_value(&mut args, "--runs-root")?);
                }
                "--contract" => {
                    cli.contract = PathBuf::from(required_value(&mut args, "--contract")?);
                }
                "--mode" => cli.mode = parse_mode(&required_value(&mut args, "--mode")?)?,
                "--commit" => cli.commit = required_value(&mut args, "--commit")?,
                "--deployment-sha256" => {
                    cli.deployment_sha256 = required_value(&mut args, "--deployment-sha256")?;
                }
                "--image-digest" => cli.image_digest = required_value(&mut args, "--image-digest")?,
                "--config-digest" => {
                    cli.config_digest = required_value(&mut args, "--config-digest")?
                }
                "--build-id" => cli.build_id = required_value(&mut args, "--build-id")?,
                "--host" => cli.host = required_value(&mut args, "--host")?,
                "--stable-toolchain" => {
                    cli.stable_toolchain = required_value(&mut args, "--stable-toolchain")?;
                }
                "--compiler-nightly" => {
                    cli.compiler_nightly = Some(required_value(&mut args, "--compiler-nightly")?);
                }
                "--cpu-limit" => {
                    cli.cpu_limit = Some(required_value(&mut args, "--cpu-limit")?.parse()?);
                }
                _ => return Err(format!("unknown flag {flag}").into()),
            }
        }

        require_non_empty(&cli.commit, "--commit")?;
        require_non_empty(&cli.deployment_sha256, "--deployment-sha256")?;
        require_non_empty(&cli.config_digest, "--config-digest")?;
        require_non_empty(&cli.stable_toolchain, "--stable-toolchain")?;
        if cli.build_id.is_empty() {
            let short = cli.commit.get(0..7).unwrap_or(cli.commit.as_str());
            cli.build_id = format!("d0:{}:{short}", mode_label(cli.mode));
        }

        Ok(cli)
    }
}

fn required_value(args: &mut VecDeque<String>, label: &str) -> Result<String, Box<dyn Error>> {
    args.pop_front()
        .ok_or_else(|| format!("missing value for {label}").into())
}

fn expect_flag(args: &mut VecDeque<String>, expected: &str) -> Result<(), Box<dyn Error>> {
    let actual = args
        .pop_front()
        .ok_or_else(|| format!("missing required flag {expected}"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected flag {expected}, got {actual}").into())
    }
}

fn require_non_empty(value: &str, label: &str) -> Result<(), Box<dyn Error>> {
    if value.trim().is_empty() {
        Err(format!("missing required {label}").into())
    } else {
        Ok(())
    }
}

fn parse_mode(value: &str) -> Result<D0RunMode, Box<dyn Error>> {
    match value {
        "preflight" => Ok(D0RunMode::Preflight),
        "formal" => Ok(D0RunMode::Formal),
        _ => Err(format!("invalid --mode {value}; expected preflight or formal").into()),
    }
}

fn mode_label(mode: D0RunMode) -> &'static str {
    match mode {
        D0RunMode::Preflight => "preflight",
        D0RunMode::Formal => "formal",
    }
}

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn print_usage() {
    println!(
        "usage:\n  bw-d0 --check-matrix experiments/configs/d0-cases.toml --ground-truth experiments/ground-truth/d0-cases.toml\n  bw-d0 run --commit <sha> --deployment-sha256 <sha256> --config-digest <sha256> --stable-toolchain <rustc-version> [--mode preflight|formal] [--repo-root .] [--runs-root /root/boundary-witness/runs] [--contract contracts/callback-retention/contract.toml]"
    );
}
