use std::{
    collections::VecDeque,
    env,
    error::Error,
    ffi::OsStr,
    path::{Path, PathBuf},
};

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
            let runs_root = cli.resolve_runs_root();
            let report = run_d0(D0RunOptions {
                matrix,
                repo_root: cli.repo_root,
                runs_root,
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
    /// `None` 表示未显式指定；实际路径由 [`RunCli::resolve_runs_root`] 决定。
    runs_root: Option<PathBuf>,
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
            runs_root: None,
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
                    cli.runs_root = Some(PathBuf::from(required_value(&mut args, "--runs-root")?));
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

    /// 按 `--runs-root` > `BW_RUNS_ROOT` > `<repo-root>/runs` 的优先级解析 run 输出根目录。
    ///
    /// 默认值落在仓库内是有意的：`.gitignore` 已忽略 `/runs/`，DVC 也按仓库内目录跟踪数据。
    /// 不使用绝对默认路径，避免在非 root 环境下写入失败或越过部署边界。
    fn resolve_runs_root(&self) -> PathBuf {
        resolve_runs_root(
            self.runs_root.as_deref(),
            env::var_os("BW_RUNS_ROOT").as_deref(),
            &self.repo_root,
        )
    }
}

/// [`RunCli::resolve_runs_root`] 的纯逻辑，便于在不改进程环境的前提下测试。
fn resolve_runs_root(
    explicit: Option<&Path>,
    env_value: Option<&OsStr>,
    repo_root: &Path,
) -> PathBuf {
    if let Some(runs_root) = explicit {
        return runs_root.to_path_buf();
    }
    match env_value {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => repo_root.join("runs"),
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
        "usage:\n  bw-d0 --check-matrix experiments/configs/d0-cases.toml --ground-truth experiments/ground-truth/d0-cases.toml\n  bw-d0 run --commit <sha> --deployment-sha256 <sha256> --config-digest <sha256> --stable-toolchain <rustc-version> [--mode preflight|formal] [--repo-root .] [--runs-root <dir>] [--contract contracts/callback-retention/contract.toml]\n\nrun output root resolves as --runs-root > $BW_RUNS_ROOT > <repo-root>/runs"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_runs_root_wins_over_environment() {
        let resolved = resolve_runs_root(
            Some(Path::new("/explicit/runs")),
            Some(OsStr::new("/env/runs")),
            Path::new("/repo"),
        );
        assert_eq!(resolved, PathBuf::from("/explicit/runs"));
    }

    #[test]
    fn environment_wins_over_repo_default() {
        let resolved = resolve_runs_root(None, Some(OsStr::new("/env/runs")), Path::new("/repo"));
        assert_eq!(resolved, PathBuf::from("/env/runs"));
    }

    #[test]
    fn empty_environment_falls_back_to_repo_default() {
        let resolved = resolve_runs_root(None, Some(OsStr::new("")), Path::new("/repo"));
        assert_eq!(resolved, PathBuf::from("/repo/runs"));
    }

    #[test]
    fn default_runs_root_stays_inside_the_repository() {
        let resolved = resolve_runs_root(None, None, Path::new("."));
        assert_eq!(resolved, PathBuf::from("./runs"));
        assert!(
            resolved.is_relative(),
            "default must not be an absolute path"
        );
    }
}
