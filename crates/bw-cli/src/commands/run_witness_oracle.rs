use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    commands::{write_json_file, write_json_stdout},
    exit::{CliError, CommandStatus},
};

const ORACLE_RESULT_SCHEMA_V1: &str = "bw.oracle-result/0.1";

/// 独立 oracle 执行：构建 harness → 运行 → 以 ASan 为最终裁决者判定结果。
///
/// 本项目 runtime 只负责编排与证据记录，**不进证据链顶层**：最终裁决由 ASan
/// （独立 oracle）给出。本命令把「构建 + 运行 + 解析 + 证据落盘」统一成可复现
/// 的流程，并支持 `--expect` 做变异校验（断言生成器/判据的判别力）。
#[derive(Args)]
pub struct RunWitnessOracleArgs {
    #[arg(long)]
    harness_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = 120)]
    timeout_seconds: u64,
    /// ASAN_OPTIONS；缺省 `detect_leaks=0`（leak 检测会干扰 UAF 判定）。
    #[arg(long)]
    asan_options: Option<String>,
    /// 额外环境变量（可重复）：`CFLTK_BUNDLE_DIR=/path` 形状。
    #[arg(long = "env")]
    env_vars: Vec<String>,
    /// 运行命令前缀（二进制路径追加其后），如 `xvfb-run -a`。缺省直接执行二进制。
    #[arg(long)]
    run_command: Option<String>,
    /// 期望结果（变异校验）：`triggered | clean | build_failed | runtime_error`。
    /// 实测不符 → 命令以非 0 退出（供测试/CI 断言判别力）。
    #[arg(long)]
    expect: Option<String>,
    #[arg(long, default_value = "cargo")]
    cargo: PathBuf,
    #[arg(long)]
    toolchain: Option<String>,
    #[arg(long, default_value = "1048576")]
    max_line_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleOutcome {
    /// ASan 报告了错误（heap-use-after-free 等）且进程非 0 退出。
    Triggered,
    /// 无 ASan 错误（进程 0 退出或正常完成）。
    Clean,
    /// harness 构建失败（负对照的 fixed 版：判定 refused → 编不过）。
    BuildFailed,
    /// 运行超时（无 ASan 错误，但进程未按时结束）。
    Timeout,
    /// 非 0 退出且无 ASan 错误（运行期错误，不是 UAF 证据）。
    RuntimeError,
}

impl OracleOutcome {
    fn as_str(self) -> &'static str {
        match self {
            OracleOutcome::Triggered => "triggered",
            OracleOutcome::Clean => "clean",
            OracleOutcome::BuildFailed => "build_failed",
            OracleOutcome::Timeout => "timeout",
            OracleOutcome::RuntimeError => "runtime_error",
        }
    }
}

#[derive(Debug, Serialize)]
struct OracleResult {
    schema_version: String,
    run_id: String,
    harness_dir: String,
    outcome: String,
    exit_code: Option<i32>,
    asan_error_count: usize,
    summary: Option<String>,
    build_stderr_tail: Option<String>,
    log_path: String,
    log_sha256: String,
    elapsed_ms: u64,
    expected: Option<String>,
    expect_matched: bool,
}

fn sha256_bytes(bytes: &[u8]) -> Result<[u8; 32], CliError> {
    Ok(Sha256::digest(bytes).into())
}

fn hex_digest(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 解析 ASan 输出：错误计数与 SUMMARY 行。不信任任何"看起来像"的文本，只认
/// ASan 的标准前缀。
fn parse_asan_output(text: &str) -> (usize, Option<String>) {
    let count = text
        .lines()
        .filter(|line| line.contains("ERROR: AddressSanitizer"))
        .count();
    let summary = text
        .lines()
        .find(|line| line.contains("SUMMARY: AddressSanitizer"))
        .map(|line| line.trim().to_owned());
    (count, summary)
}

fn run_cargo_build(
    cargo: &Path,
    harness_dir: &Path,
    toolchain: Option<&str>,
) -> Result<Result<(), String>, CliError> {
    let mut cmd = Command::new(cargo);
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(harness_dir.join("Cargo.toml"));
    if let Some(tc) = toolchain {
        cmd.env("RUSTUP_TOOLCHAIN", tc);
    }
    let output = cmd
        .output()
        .map_err(|e| CliError::input("BW-ORACLE-SPAWN", format!("cargo: {e}")))?;
    if output.status.success() {
        Ok(Ok(()))
    } else {
        // 优先展示真实错误行（`error[E..]` / `error:`），而不是盲目 tail——
        // cargo 的 warning 块可能很长，tail 会掩盖 E0425 这类负对照关键证据。
        let stderr_text = String::from_utf8_lossy(&output.stderr).into_owned();
        let stderr_lines: Vec<&str> = stderr_text.lines().collect();
        let tail = {
            let error_lines: Vec<&str> = stderr_lines
                .iter()
                .filter(|line| line.contains("error") || line.contains("E[0-9]"))
                .cloned()
                .collect();
            if error_lines.is_empty() {
                stderr_lines.iter().rev().take(20).rev().cloned().collect::<Vec<_>>().join("\n")
            } else {
                error_lines.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
            }
        };
        Ok(Err(tail))
    }
}

fn find_bin(harness_dir: &Path, bin_name: &str) -> Option<PathBuf> {
    let candidate = harness_dir.join("target/debug").join(bin_name);
    if candidate.is_file() {
        return Some(candidate);
    }
    // 生成器产物 bin name == package name；兜底扫 target/debug 下匹配前缀。
    fs::read_dir(harness_dir.join("target/debug"))
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.is_file()
                && p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("bw-witness-"))
        })
}

fn parse_package_name(cargo_toml: &str) -> Option<String> {
    cargo_toml
        .lines()
        .find(|line| line.trim_start().starts_with("name = "))
        .and_then(|line| {
            let value = line.split('=').nth(1)?.trim().trim_matches('"');
            if value.is_empty() {
                None
            } else {
                Some(value.to_owned())
            }
        })
}

/// 判定 outcome：错误计数与退出码的组合是裁决输入，不引入本项目 runtime 结论。
fn decide(
    build_ok: bool,
    build_stderr: Option<&str>,
    exit_code: Option<i32>,
    asan_errors: usize,
    timed_out: bool,
) -> OracleOutcome {
    if !build_ok {
        let _ = build_stderr;
        return OracleOutcome::BuildFailed;
    }
    if timed_out {
        return OracleOutcome::Timeout;
    }
    if asan_errors > 0 {
        return OracleOutcome::Triggered;
    }
    match exit_code {
        Some(0) => OracleOutcome::Clean,
        _ => OracleOutcome::RuntimeError,
    }
}

fn expect_matches(outcome: OracleOutcome, expected: Option<&str>) -> bool {
    match expected {
        None => true,
        Some(exp) => exp == outcome.as_str(),
    }
}

pub fn run(args: RunWitnessOracleArgs) -> Result<CommandStatus, CliError> {
    let harness_dir = args.harness_dir.clone();
    let cargo_path = harness_dir.join("Cargo.toml");
    let main_path = harness_dir.join("src/main.rs");
    if !cargo_path.is_file() || !main_path.is_file() {
        return Err(CliError::input(
            "BW-ORACLE-HARNESS",
            format!("harness 不完整（缺 Cargo.toml 或 src/main.rs）：{}", harness_dir.display()),
        ));
    }
    let cargo_toml_text = fs::read_to_string(&cargo_path)
        .map_err(|e| CliError::input("BW-IO", format!("Cargo.toml: {e}")))?;
    let bin_name = parse_package_name(&cargo_toml_text).ok_or_else(|| {
        CliError::input("BW-ORACLE-HARNESS", "无法从 Cargo.toml 解析包名（生成物应含 [package] name）")
    })?;

    let logs_dir = harness_dir.join("oracle-logs");
    fs::create_dir_all(&logs_dir).map_err(|e| CliError::input("BW-IO", e.to_string()))?;
    let log_path = logs_dir.join(format!("{}.log", args.run_id));
    let result_path = logs_dir.join(format!("{}.json", args.run_id));

    let started = Instant::now();

    // 1) 构建（ASan profile 来自生成物 Cargo.toml，oracle 不注入插桩配置）。
    let build_result = run_cargo_build(&args.cargo, &harness_dir, args.toolchain.as_deref())?;
    let build_ok = build_result.is_ok();
    let build_stderr = build_result.err();

    // 2) 运行（timeout 外包：`timeout <sec> [run_command...] <binary>`）。
    let mut run_log = String::new();
    let mut exit_code = None;
    let mut timed_out = false;
    let mut asan_errors = 0usize;
    let mut summary = None;
    if build_ok {
        let bin = find_bin(&harness_dir, &bin_name).ok_or_else(|| {
            CliError::input("BW-ORACLE-BIN", format!("构建成功但找不到二进制：{bin_name}"))
        })?;
        let mut cmd = Command::new("timeout");
        cmd.arg(args.timeout_seconds.to_string());
        if let Some(prefix) = &args.run_command {
            // run_command 是空格分隔的前缀（如 `xvfb-run -a`）。
            for part in prefix.split_whitespace() {
                cmd.arg(part);
            }
        }
        cmd.arg(&bin);
        let asan_options = args
            .asan_options
            .clone()
            .unwrap_or_else(|| "detect_leaks=0".to_owned());
        cmd.env("ASAN_OPTIONS", asan_options);
        if let Some(tc) = &args.toolchain {
            cmd.env("RUSTUP_TOOLCHAIN", tc);
        }
        for kv in &args.env_vars {
            if let Some((k, v)) = kv.split_once('=') {
                cmd.env(k, v);
            }
        }
        // LD_LIBRARY_PATH：nightly toolchain lib（ASan runtime 依赖）。
        let mut ld = String::new();
        if let Ok(existing) = std::env::var("LD_LIBRARY_PATH") {
            ld.push_str(&existing);
        }
        if let Ok(sysroot_lib) = std::env::var("BW_ORACLE_LD_LIBRARY_PATH") {
            if !ld.is_empty() {
                ld.push(':');
            }
            ld.push_str(&sysroot_lib);
        }
        if !ld.is_empty() {
            cmd.env("LD_LIBRARY_PATH", ld);
        }
        let output = cmd
            .output()
            .map_err(|e| CliError::input("BW-ORACLE-SPAWN", format!("timeout: {e}")))?;
        exit_code = output.status.code();
        timed_out = exit_code == Some(124);
        run_log = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if !stderr.is_empty() {
            run_log.push_str("\n--- stderr ---\n");
            run_log.push_str(&stderr);
        }
        let parsed = parse_asan_output(&run_log);
        asan_errors = parsed.0;
        summary = parsed.1;
    }

    let outcome = decide(build_ok, build_stderr.as_deref(), exit_code, asan_errors, timed_out);
    let expect_matched = expect_matches(outcome, args.expect.as_deref());

    fs::write(&log_path, &run_log).map_err(|e| CliError::input("BW-IO", e.to_string()))?;
    let log_sha256 = hex_digest(sha256_bytes(run_log.as_bytes())?);

    let result = OracleResult {
        schema_version: ORACLE_RESULT_SCHEMA_V1.to_owned(),
        run_id: args.run_id.clone(),
        harness_dir: harness_dir.display().to_string(),
        outcome: outcome.as_str().to_owned(),
        exit_code,
        asan_error_count: asan_errors,
        summary,
        build_stderr_tail: build_stderr,
        log_path: log_path.display().to_string(),
        log_sha256,
        elapsed_ms: started.elapsed().as_millis() as u64,
        expected: args.expect.clone(),
        expect_matched,
    };
    write_json_file(&result_path, &result)?;

    let mut status = serde_json::to_value(&result)
        .map_err(|e| CliError::input("BW-ORACLE-SERIALIZE", e.to_string()))?;
    status["kind"] = serde_json::json!("witness-oracle");
    write_json_stdout(&status)?;

    if !expect_matched {
        return Err(CliError::input(
            "BW-ORACLE-EXPECT",
            format!(
                "期望 {} 但实测 {}（变异校验失败：判据/生成器可能失去判别力）",
                args.expect.unwrap_or_default(),
                outcome.as_str()
            ),
        ));
    }
    Ok(CommandStatus::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_asan_output_counts_errors_and_summary() {
        let text = "==123==ERROR: AddressSanitizer: heap-use-after-free on address ...\nREAD of size 8\nSUMMARY: AddressSanitizer: heap-use-after-free in Vec<u8>::len\n";
        let (count, summary) = parse_asan_output(text);
        assert_eq!(count, 1);
        assert!(summary.unwrap().contains("heap-use-after-free"));
        let (count, summary) = parse_asan_output("no asan here\n");
        assert_eq!(count, 0);
        assert!(summary.is_none());
    }

    #[test]
    fn decide_maps_exit_and_errors() {
        assert_eq!(decide(true, None, Some(1), 1, false), OracleOutcome::Triggered);
        assert_eq!(decide(true, None, Some(0), 0, false), OracleOutcome::Clean);
        assert_eq!(decide(false, Some("E0425".into()), None, 0, false), OracleOutcome::BuildFailed);
        assert_eq!(decide(true, None, Some(124), 0, true), OracleOutcome::Timeout);
        assert_eq!(decide(true, None, Some(101), 0, false), OracleOutcome::RuntimeError);
    }

    #[test]
    fn expect_matching_works() {
        assert!(expect_matches(OracleOutcome::Triggered, Some("triggered")));
        assert!(!expect_matches(OracleOutcome::Triggered, Some("clean")));
        assert!(expect_matches(OracleOutcome::Clean, None));
        assert!(expect_matches(OracleOutcome::BuildFailed, Some("build_failed")));
    }

    #[test]
    fn parse_package_name_reads_generated_toml() {
        let toml = "[package]\nname = \"bw-witness-adapter_rusqlite_update_hook-0_26_1\"\nversion = \"0.1.0\"\n";
        assert_eq!(
            parse_package_name(toml).as_deref(),
            Some("bw-witness-adapter_rusqlite_update_hook-0_26_1")
        );
    }
}
