//! M12 盲测结果的独立事后 verifier 启动器。
//!
//! 设计意图：
//! - runner 运行阶段只读取 `experiments/configs/rusqlite-m12-cases.toml`。
//! - ground truth 只在所有子进程、trace、findings 都关闭后由本程序传给 verifier。
//! - 本程序不链接 `bw-oracle`，也不链接任何 benchmark child；它只启动已构建的
//!   `bw-rusqlite-runner verify <observed.jsonl> <ground-truth.toml>`。
//!
//! 用法：
//! ```bash
//! rustc experiments/tools/verify_blind_results.rs -o target/verify_blind_results
//! target/verify_blind_results \
//!   experiments/runs/rusqlite-m12/observed.jsonl \
//!   experiments/ground-truth/rusqlite-m12.toml
//! ```
//!
//! 如 runner 二进制不在默认位置，可设置：
//! ```bash
//! BW_RUSQLITE_RUNNER=benchmarks/historical-cves/rusqlite/shared/target/debug/bw-rusqlite-runner \
//!   target/verify_blind_results <observed.jsonl> <ground-truth.toml>
//! ```

use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(observed_path) = args.next() else {
        eprintln!("usage: verify_blind_results <observed.jsonl> <ground-truth.toml>");
        return ExitCode::from(2);
    };
    let Some(ground_truth_path) = args.next() else {
        eprintln!("usage: verify_blind_results <observed.jsonl> <ground-truth.toml>");
        return ExitCode::from(2);
    };

    let runner = env::var_os("BW_RUSQLITE_RUNNER")
        .map(PathBuf::from)
        .unwrap_or_else(default_runner_path);
    let status = std::process::Command::new(&runner)
        .arg("verify")
        .arg(observed_path)
        .arg(ground_truth_path)
        .status();

    match status {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(error) => {
            eprintln!("failed to start {}: {error}", runner.display());
            ExitCode::from(1)
        }
    }
}

fn default_runner_path() -> PathBuf {
    PathBuf::from("benchmarks/historical-cves/rusqlite/shared/target/debug/bw-rusqlite-runner")
}
