//! 在控制矩阵下编译并执行 safe-only 客户端，用独立 oracle 出回执（阶段 5.3/5.4）。
//!
//! # oracle 的独立性
//!
//! 本命令对「UB 是否发生」的判断**只**来自 AddressSanitizer 的输出（经
//! `bw_experiment::parse_asan_log` 解析）。它不读判定、不读计划、不做任何语义
//! 推断——反证的证明力恰恰来自这个判官与推导链的隔离。
//!
//! # 三态纪律延伸到执行层
//!
//! primary 无报告输出 `Inconclusive`，绝不输出「已证伪」：有限次执行不能证伪
//! may-property。只有 primary 触发且全部控制组符合预期，才升级为
//! `ConfirmedCounterexample`；任何一个控制组违反预期都会把整个计划拉回
//! `Inconclusive` 并留下显式的违规记录——那说明我们对组件行为的模型错了。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use bw_model::{CONTROLS_SCHEMA_V01, WitnessStatus};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    commands::{
        DEFAULT_MAX_LINE_BYTES, hex_digest, read_jsonl, safe_client::ClientVariant,
        write_json_file, write_records,
    },
    exit::{CliError, CommandStatus},
};

/// 一次执行的四态结论。与三态判定的映射在 [`aggregate`] 里完成。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunOutcome {
    /// primary 触发了目标 oracle 报告。
    ConfirmedCounterexample,
    /// 按预期干净退出（控制组）或 primary 未触发前的中性记录。
    Clean,
    /// 预期触发但没触发。不是证伪。
    Inconclusive,
    /// 预期干净却触发了报告——控制失败，整个计划的确认随之失效。
    ControlViolated,
    BuildFailed,
    ExecutionFailed,
}

impl RunOutcome {
    const fn token(self) -> &'static str {
        match self {
            Self::ConfirmedCounterexample => "confirmed_counterexample",
            Self::Clean => "clean",
            Self::Inconclusive => "inconclusive",
            Self::ControlViolated => "control_violated",
            Self::BuildFailed => "build_failed",
            Self::ExecutionFailed => "execution_failed",
        }
    }

    fn met_expectation(self) -> bool {
        matches!(self, Self::ConfirmedCounterexample | Self::Clean)
    }

    /// 从回执里的 outcome token 还原枚举。
    fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "confirmed_counterexample" => Self::ConfirmedCounterexample,
            "clean" => Self::Clean,
            "inconclusive" => Self::Inconclusive,
            "control_violated" => Self::ControlViolated,
            "build_failed" => Self::BuildFailed,
            "execution_failed" => Self::ExecutionFailed,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum Expectation {
    Confirmed,
    Clean,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlsFile {
    schema_version: String,
    control: Vec<ControlEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlEntry {
    role: String,
    build_id: String,
    client_variant: String,
    /// 可选过滤：只作用于判定所属外部 artifact 等于该值的客户端。
    /// primary 必须用它——判定是对哪个外部实现做的，反证就要链接哪个实现。
    #[serde(default)]
    foreign_artifact: Option<String>,
    /// 可选过滤：只作用于该 API 的客户端。判别性控制用它精确到单个计划。
    #[serde(default)]
    api_id: Option<String>,
    expectation: Expectation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationManifestFile {
    schema_version: String,
    run_id: String,
    adapter_id: String,
    #[allow(dead_code)]
    component_crate: String,
    #[allow(dead_code)]
    component_version: Option<String>,
    #[allow(dead_code)]
    output_root: String,
    #[allow(dead_code)]
    generated: serde_json::Value,
    #[allow(dead_code)]
    refused: serde_json::Value,
    foreign_builds: Vec<ManifestBuild>,
    #[allow(dead_code)]
    notes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBuild {
    id: String,
    source: String,
    source_sha256: String,
    provides_trigger_symbol: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientRecord {
    plan_id: String,
    api_id: String,
    /// 计划判定的外部 artifact；控制矩阵的 primary 过滤键。
    foreign_artifact: String,
    client_variant: String,
    dir: String,
    /// 生成器写的人类可读包名；执行器按 dir 定位 crate，此字段仅保完整性。
    #[allow(dead_code)]
    package: String,
    main_rs_sha256: String,
    references_trigger: bool,
}

#[derive(Serialize)]
struct Receipt {
    schema_version: &'static str,
    run_id: String,
    plan_id: String,
    api_id: String,
    /// 计划判定的外部 artifact（血缘：判定是对哪个外部实现做的）。
    foreign_artifact: String,
    control_role: String,
    client_variant: String,
    expectation: &'static str,
    foreign_build_id: String,
    foreign_source: String,
    foreign_source_sha256: String,
    main_rs_sha256: String,
    binary_sha256: Option<String>,
    toolchain: String,
    rustc_version: String,
    build_argv: Vec<String>,
    build_exit_code: Option<i32>,
    run_argv: Vec<String>,
    run_exit_code: Option<i32>,
    stderr_sha256: String,
    stderr_tail: String,
    sanitizer_report: Option<bw_experiment::SanitizerReport>,
    outcome: &'static str,
    skipped_reason: Option<&'static str>,
}

#[derive(Serialize)]
struct PlanFinding {
    plan_id: String,
    api_id: String,
    witness_status: WitnessStatus,
    control_violations: Vec<String>,
}

#[derive(Serialize)]
struct RunSummary {
    schema_version: &'static str,
    run_id: String,
    adapter_id: String,
    toolchain: String,
    rustc_version: String,
    executions: usize,
    skipped: usize,
    by_outcome: BTreeMap<String, usize>,
    findings: Vec<PlanFinding>,
    notes: Vec<&'static str>,
}

#[derive(Args)]
pub struct RunSafeClientArgs {
    /// `generate-safe-client` 的输出目录（读 generation-manifest.json 与 clients.jsonl）。
    #[arg(long = "clients-dir")]
    clients_dir: PathBuf,
    /// 判决后产物：控制矩阵（bw.controls/0.1）。
    #[arg(long = "controls")]
    controls: PathBuf,
    #[arg(long, default_value = "nightly")]
    toolchain: String,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    /// cargo 构建目录（CARGO_TARGET_DIR）。默认放在 output-dir 的**兄弟**目录
    /// `<output-dir>-target`：构建中间物成千上万，混进 run 目录会让 verify-run
    /// 的零容忍清单核对永远不可能通过。
    #[arg(long = "target-dir")]
    target_dir: Option<PathBuf>,
}

pub fn run(args: RunSafeClientArgs) -> Result<CommandStatus, CliError> {
    let manifest_text = std::fs::read_to_string(args.clients_dir.join("generation-manifest.json"))
        .map_err(|error| {
            CliError::input(
                "BW-IO",
                format!(
                    "{}: {error}",
                    args.clients_dir.join("generation-manifest.json").display()
                ),
            )
        })?;
    let manifest: GenerationManifestFile = serde_json::from_str(&manifest_text)
        .map_err(|error| CliError::input("BW-SAFE-CLIENT-MANIFEST", error.to_string()))?;
    if manifest.schema_version != bw_model::SAFE_CLIENT_SCHEMA_V01 {
        return Err(CliError::input(
            "BW-SAFE-CLIENT-MANIFEST",
            format!(
                "不支持的生成清单 schema {}，当前要求 {}",
                manifest.schema_version,
                bw_model::SAFE_CLIENT_SCHEMA_V01
            ),
        ));
    }
    if manifest.foreign_builds.is_empty() {
        return Err(CliError::input(
            "BW-SAFE-CLIENT-MANIFEST",
            "generation manifest 里没有外部构建条目；控制矩阵无法配对".to_owned(),
        ));
    }
    let clients: Vec<ClientRecord> = read_jsonl(
        &args.clients_dir.join("clients.jsonl"),
        DEFAULT_MAX_LINE_BYTES,
    )?
    .into_iter()
    .map(|located| located.value)
    .collect();

    let controls_text = std::fs::read_to_string(&args.controls).map_err(|error| {
        CliError::input("BW-IO", format!("{}: {error}", args.controls.display()))
    })?;
    let controls: ControlsFile = toml::from_str(&controls_text).map_err(|error| {
        CliError::input("BW-CONTROLS-SCHEMA", format!("控制矩阵解析失败: {error}"))
    })?;
    if controls.schema_version != CONTROLS_SCHEMA_V01 {
        return Err(CliError::input(
            "BW-CONTROLS-SCHEMA",
            format!(
                "不支持的 controls schema {}，当前要求 {CONTROLS_SCHEMA_V01}",
                controls.schema_version
            ),
        ));
    }
    // 客户端变体 token 必须是生成器认识的；拼错的矩阵在这里爆掉而不是静默零匹配。
    for entry in &controls.control {
        if ClientVariant::from_token(&entry.client_variant).is_none() {
            return Err(CliError::input(
                "BW-CONTROLS-SCHEMA",
                format!("未知客户端变体 token `{}`", entry.client_variant),
            ));
        }
    }

    let target_dir = args.target_dir.clone().unwrap_or_else(|| {
        let mut sibling = args.output_dir.clone().into_os_string();
        sibling.push("-target");
        std::path::PathBuf::from(sibling)
    });
    if target_dir.starts_with(&args.output_dir) {
        return Err(CliError::input(
            "BW-RUN-SAFE-CLIENT-INPUT",
            format!(
                "--target-dir `{}` 在 output-dir `{}` 之内：构建中间物会污染被校验的 run 目录",
                target_dir.display(),
                args.output_dir.display()
            ),
        ));
    }
    if target_dir.starts_with(&args.clients_dir) {
        return Err(CliError::input(
            "BW-RUN-SAFE-CLIENT-INPUT",
            format!(
                "--target-dir `{}` 在 clients-dir `{}` 之内：构建中间物会污染被校验的生成目录",
                target_dir.display(),
                args.clients_dir.display()
            ),
        ));
    }
    std::fs::create_dir_all(&target_dir)?;
    let rustc_version = probe_rustc(&args.toolchain);

    // 把客户端 crate 暂存进构建区再编译：cargo 会改写暂存副本（生成 Cargo.lock 等），
    // 被校验的 clients_dir 必须保持与 generate-safe-client 写出时逐字节一致。
    let clients = stage_clients(&clients, &target_dir.join("staged-clients"))?;

    let mut receipts = Vec::<Receipt>::new();
    for entry in &controls.control {
        let matching: Vec<&ClientRecord> = clients
            .iter()
            .filter(|client| client.client_variant == entry.client_variant)
            .filter(|client| match &entry.foreign_artifact {
                Some(artifact) => &client.foreign_artifact == artifact,
                None => true,
            })
            .filter(|client| match &entry.api_id {
                Some(api_id) => &client.api_id == api_id,
                None => true,
            })
            .collect();
        if matching.is_empty() {
            return Err(CliError::input(
                "BW-CONTROLS-SCHEMA",
                format!(
                    "控制 `{}`（变体 `{}`，artifact {:?}）在生成产物中没有任何匹配客户端",
                    entry.role, entry.client_variant, entry.foreign_artifact
                ),
            ));
        }
        for client in matching {
            receipts.push(execute_one(
                client,
                entry,
                &manifest,
                &args,
                &target_dir,
                &rustc_version,
            ));
        }
    }

    receipts.sort_by(|left, right| {
        (&left.plan_id, &left.control_role, &left.client_variant).cmp(&(
            &right.plan_id,
            &right.control_role,
            &right.client_variant,
        ))
    });

    let receipts_path = args.output_dir.join("witness-receipts.jsonl");
    write_records(&receipts_path, &receipts)?;

    let summary = aggregate(
        &manifest.run_id,
        &manifest.adapter_id,
        &args.toolchain,
        &rustc_version,
        &receipts,
    );
    let summary_path = args.output_dir.join("witness-summary.json");
    write_json_file(&summary_path, &summary)?;

    // 回执与聚合进 verify-run 清单体系：run 目录里除这两个产物外不允许有别的文件。
    crate::commands::write_checksums(
        &[
            ("witness-receipts.jsonl".to_owned(), receipts_path.clone()),
            ("witness-summary.json".to_owned(), summary_path.clone()),
        ],
        &args.output_dir.join("checksums.sha256"),
    )?;
    std::fs::create_dir_all(&args.output_dir)?;

    let status = serde_json::json!({
        "kind": "witness-execution",
        "run_id": manifest.run_id,
        "receipts": receipts_path,
        "summary": summary_path,
        "executions": summary.executions,
        "skipped": summary.skipped,
        "findings": summary.findings.iter().filter(|f| f.witness_status == WitnessStatus::ConfirmedCounterexample).count(),
    });
    crate::commands::write_json_stdout(&status)?;
    Ok(CommandStatus::Success)
}

fn probe_rustc(toolchain: &str) -> String {
    // `cargo +toolchain --version` 稳定可用；`cargo rustc --version` 会把参数
    // 传给底层 rustc 而报错。
    let output = Command::new("cargo")
        .args([format!("+{toolchain}"), "--version".to_owned()])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(output) => format!(
            "probe-failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => format!("probe-spawn-failed: {error}"),
    }
}

/// 把客户端 crate 复制进暂存区并重定向记录里的 dir。
///
/// cargo 构建会在 crate 目录里写 `Cargo.lock`；直接在被校验的生成目录里构建，
/// verify-run 的零容忍清单核对必然失败。暂存副本是构建的私有输入，原始目录
/// 保持与 generate-safe-client 写出时逐字节一致。
fn stage_clients(
    clients: &[ClientRecord],
    stage_root: &Path,
) -> Result<Vec<ClientRecord>, CliError> {
    let _ = std::fs::remove_dir_all(stage_root);
    std::fs::create_dir_all(stage_root)?;
    let mut staged = Vec::<ClientRecord>::with_capacity(clients.len());
    for client in clients {
        let source = PathBuf::from(&client.dir);
        let relative = source
            .file_name()
            .ok_or_else(|| {
                CliError::input(
                    "BW-RUN-SAFE-CLIENT-INPUT",
                    format!("客户端目录没有尾段: {}", source.display()),
                )
            })?
            .to_owned();
        let destination = stage_root.join(&relative);
        copy_tree(&source, &destination)?;
        let mut record = client.clone();
        record.dir = destination.display().to_string();
        staged.push(record);
    }
    Ok(staged)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {error}", source.display())))?
    {
        let entry = entry.map_err(|error| CliError::input("BW-IO", error.to_string()))?;
        let entry_path = entry.path();
        let target = destination.join(entry.file_name());
        if entry_path.is_dir() {
            copy_tree(&entry_path, &target)?;
        } else {
            std::fs::copy(&entry_path, &target).map_err(|error| {
                CliError::input("BW-IO", format!("{}: {error}", entry_path.display()))
            })?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_one(
    client: &ClientRecord,
    entry: &ControlEntry,
    manifest: &GenerationManifestFile,
    args: &RunSafeClientArgs,
    target_dir: &Path,
    rustc_version: &str,
) -> Receipt {
    let expectation_token = match entry.expectation {
        Expectation::Confirmed => "confirmed",
        Expectation::Clean => "clean",
    };
    let base = Receipt {
        schema_version: bw_model::WITNESS_RECEIPT_SCHEMA_V01,
        run_id: manifest.run_id.clone(),
        plan_id: client.plan_id.clone(),
        api_id: client.api_id.clone(),
        foreign_artifact: client.foreign_artifact.clone(),
        control_role: entry.role.clone(),
        client_variant: client.client_variant.clone(),
        expectation: expectation_token,
        foreign_build_id: entry.build_id.clone(),
        foreign_source: String::new(),
        foreign_source_sha256: String::new(),
        main_rs_sha256: client.main_rs_sha256.clone(),
        binary_sha256: None,
        toolchain: args.toolchain.clone(),
        rustc_version: rustc_version.to_owned(),
        build_argv: Vec::new(),
        build_exit_code: None,
        run_argv: Vec::new(),
        run_exit_code: None,
        stderr_sha256: hex_digest(Sha256::digest(b"")),
        stderr_tail: String::new(),
        sanitizer_report: None,
        outcome: RunOutcome::ExecutionFailed.token(),
        skipped_reason: None,
    };

    let Some(build) = manifest
        .foreign_builds
        .iter()
        .find(|build| build.id == entry.build_id)
    else {
        let mut receipt = base;
        receipt.outcome = RunOutcome::ExecutionFailed.token();
        receipt.skipped_reason = Some("foreign_build_not_in_manifest");
        return receipt;
    };
    if !build.provides_trigger_symbol && client.references_trigger {
        // 同步 stub 没有 trigger 符号：引用触发的客户端链接不上，
        // 这类配对必须整体省略触发步骤（机械省略，adapter 里已声明）。
        let mut receipt = base;
        receipt.foreign_source = build.source.clone();
        receipt.foreign_source_sha256 = build.source_sha256.clone();
        receipt.outcome = RunOutcome::ExecutionFailed.token();
        receipt.skipped_reason = Some("trigger_symbol_unavailable");
        return receipt;
    }

    let harness_dir = PathBuf::from(&client.dir);
    let manifest_path = harness_dir.join("Cargo.toml");
    if !manifest_path.is_file() {
        let mut receipt = base;
        receipt.skipped_reason = Some("harness_directory_missing");
        return receipt;
    }

    let mut build_command = Command::new("cargo");
    build_command
        .args([
            format!("+{}", args.toolchain),
            "build".to_owned(),
            "--manifest-path".to_owned(),
        ])
        .arg(&manifest_path);
    build_command
        .env("RUSTFLAGS", "-Zsanitizer=address")
        .env("CARGO_TARGET_DIR", target_dir)
        .env("BW_FOREIGN_SOURCE", &build.source)
        .env_remove("BW_REAL_CC");

    let build_argv = command_argv(&build_command);
    let built = match build_command.output() {
        Ok(output) => output,
        Err(error) => {
            let mut receipt = base;
            receipt.build_argv = build_argv;
            receipt.stderr_tail = format!("spawn failed: {error}");
            receipt.outcome = RunOutcome::ExecutionFailed.token();
            receipt.skipped_reason = Some("cargo_spawn_failed");
            return receipt;
        }
    };
    if !built.status.success() {
        let mut receipt = base;
        receipt.build_argv = build_argv;
        receipt.build_exit_code = built.status.code();
        let stderr = String::from_utf8_lossy(&built.stderr).to_string();
        receipt.stderr_sha256 = hex_digest(Sha256::digest(stderr.as_bytes()));
        receipt.stderr_tail = tail(&stderr);
        receipt.outcome = RunOutcome::BuildFailed.token();
        return receipt;
    }

    // 二进制名固定为 witness（生成器写死 [[bin]] name）。
    let binary = target_dir.join("debug").join("witness");
    let binary_sha256 = std::fs::read(&binary)
        .ok()
        .map(|bytes| hex_digest(Sha256::digest(bytes)));

    let mut run_command = Command::new(&binary);
    run_command.env("ASAN_OPTIONS", "detect_leaks=0");
    let run_argv = command_argv(&run_command);
    let ran = match run_command.output() {
        Ok(output) => output,
        Err(error) => {
            let mut receipt = base;
            receipt.build_argv = build_argv;
            receipt.run_argv = run_argv;
            receipt.stderr_tail = format!("spawn failed: {error}");
            receipt.outcome = RunOutcome::ExecutionFailed.token();
            return receipt;
        }
    };

    let stderr = String::from_utf8_lossy(&ran.stderr).to_string();
    let report = bw_experiment::parse_asan_log(&stderr);
    let outcome = match (entry.expectation, report.is_some()) {
        (Expectation::Confirmed, true) => RunOutcome::ConfirmedCounterexample,
        (Expectation::Confirmed, false) => RunOutcome::Inconclusive,
        (Expectation::Clean, false) => RunOutcome::Clean,
        (Expectation::Clean, true) => RunOutcome::ControlViolated,
    };

    Receipt {
        build_argv,
        build_exit_code: built.status.code(),
        run_argv,
        run_exit_code: ran.status.code(),
        stderr_sha256: hex_digest(Sha256::digest(stderr.as_bytes())),
        stderr_tail: tail(&stderr),
        sanitizer_report: report,
        outcome: outcome.token(),
        binary_sha256,
        ..base
    }
}

fn command_argv(command: &Command) -> Vec<String> {
    let mut argv = vec![command.get_program().to_string_lossy().to_string()];
    argv.extend(
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string()),
    );
    argv
}

/// 收据里只留诊断所需的 stderr 尾部；全文以 sha256 存证。
fn tail(stderr: &str) -> String {
    const MAX_TAIL_LINES: usize = 40;
    let lines: Vec<&str> = stderr.lines().collect();
    let start = lines.len().saturating_sub(MAX_TAIL_LINES);
    lines[start..].join("\n")
}

fn aggregate(
    run_id: &str,
    adapter_id: &str,
    toolchain: &str,
    rustc_version: &str,
    receipts: &[Receipt],
) -> RunSummary {
    let mut by_outcome = BTreeMap::<String, usize>::new();
    for receipt in receipts {
        *by_outcome.entry(receipt.outcome.to_owned()).or_default() += 1;
    }

    // 按 plan 聚合：primary 的结论 + 所有控制组是否守住预期。
    let mut by_plan = BTreeMap::<&str, Vec<&Receipt>>::new();
    for receipt in receipts {
        by_plan
            .entry(receipt.plan_id.as_str())
            .or_default()
            .push(receipt);
    }

    let mut findings = Vec::<PlanFinding>::new();
    for (plan_id, group) in &by_plan {
        let Some(primary) = group
            .iter()
            // 按 role 找 primary，不能按 client_variant：fixed_foreign_implementation
            // 等判别控制同样跑 primary 变体的客户端。
            .find(|receipt| receipt.control_role == "primary")
        else {
            findings.push(PlanFinding {
                plan_id: (*plan_id).to_owned(),
                api_id: group[0].api_id.clone(),
                witness_status: WitnessStatus::NotAttempted,
                control_violations: vec!["no_primary_execution_recorded".to_owned()],
            });
            continue;
        };
        let mut violations = Vec::<String>::new();
        for receipt in group {
            if receipt.skipped_reason.is_some() {
                violations.push(format!(
                    "{}:{}:skipped({})",
                    receipt.control_role,
                    receipt.client_variant,
                    receipt.skipped_reason.unwrap()
                ));
                continue;
            }
            let Some(outcome) = RunOutcome::from_token(receipt.outcome) else {
                violations.push(format!(
                    "{}:{}:unknown_outcome({})",
                    receipt.control_role, receipt.client_variant, receipt.outcome
                ));
                continue;
            };
            if !outcome.met_expectation() {
                violations.push(format!(
                    "{}:{}:{}",
                    receipt.control_role, receipt.client_variant, receipt.outcome
                ));
            }
        }
        let primary_outcome = RunOutcome::from_token(primary.outcome);
        let witness_status = match primary_outcome {
            Some(RunOutcome::ConfirmedCounterexample) => {
                if violations.is_empty() {
                    // 控制组失败说明行为模型有错：不能让带伤的反证通过闸门，
                    // 因此 violations 非空时降级为 Inconclusive（见下）。
                    WitnessStatus::ConfirmedCounterexample
                } else {
                    WitnessStatus::Inconclusive
                }
            }
            Some(RunOutcome::Inconclusive) | Some(RunOutcome::ControlViolated) => {
                WitnessStatus::Inconclusive
            }
            Some(RunOutcome::BuildFailed) | Some(RunOutcome::ExecutionFailed) | None => {
                WitnessStatus::NotAttempted
            }
            Some(RunOutcome::Clean) => WitnessStatus::Inconclusive,
        };
        findings.push(PlanFinding {
            plan_id: (*plan_id).to_owned(),
            api_id: primary.api_id.clone(),
            witness_status,
            control_violations: violations,
        });
    }
    findings.sort_by(|left, right| left.plan_id.cmp(&right.plan_id));

    let executions = receipts
        .iter()
        .filter(|r| r.skipped_reason.is_none())
        .count();
    let skipped = receipts.len() - executions;
    RunSummary {
        schema_version: CONTROLS_SCHEMA_V01,
        run_id: run_id.to_owned(),
        adapter_id: adapter_id.to_owned(),
        toolchain: toolchain.to_owned(),
        rustc_version: rustc_version.to_owned(),
        executions,
        skipped,
        by_outcome,
        findings,
        notes: vec![
            "inconclusive is not falsification; may-properties cannot be refuted by finite runs",
            "any control violation demotes the whole plan back to inconclusive",
        ],
    }
}
