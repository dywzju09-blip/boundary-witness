//! 阶段 5.3（D3）：声明式 adapter + 判定驱动的反证 harness 生成器。
//!
//! 替换旧版硬编码 rusqlite 模板（44 处 rusqlite、`SUPPORTED_APIS` 写死四个 API）。
//! 旧版无条件产出「注册→drop→触发」，跑出的违规是剧本自带的；本生成器只从
//! **冻结 adapter** 读「如何合法调用公开 API」，危险时序由判定结果推导。
//!
//! 生成物的四个槽：
//!
//! | 槽 | 来源 |
//! | --- | --- |
//! | setup | adapter（人工写一次，冻结） |
//! | register | adapter + 判定给的参数角色 |
//! | invalidate | **由判定的 `PermitsNonStaticCapture` + guard 结论推出** |
//! | trigger | adapter |
//!
//! 判定说不能分离（`RequiresStaticCapture` / guard 绑定 / 缺证）→ **不生成**
//! invalidate 块：回调仍引用 referent，而 referent 未定义 → 编译失败。这正是
//! 负对照要的行为——fixed 版在编译期就拒绝该时序，而不是跑出一个「干净」程序。
//!
//! 生成物带 `#![forbid(unsafe_code)]`，不依赖 bw-runtime：最终裁决由独立 oracle
//! （ASan）给出，本项目 runtime 只作辅助定位。**不许用大模型生成 harness**：
//! 模型可能「记得」这个 CVE，生成的是回忆不是推导，且不可复现。

use std::{
    fs,
    path::{Path, PathBuf},
};

use bw_model::{EffectiveCaptureAdmission, RegistrationGuard, RustContractFact};
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, hex_digest, read_jsonl, write_json_file},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct GenerateWitnessHarnessArgs {
    /// 冻结的声明式 adapter（`bw.adapter/0.1` TOML）。
    #[arg(long)]
    adapter: PathBuf,
    /// `extract-rust-contracts` 的产物。
    #[arg(long)]
    contracts: PathBuf,
    /// `judge-hand-offs` 的产物。
    #[arg(long)]
    verdicts: PathBuf,
    /// 仓库根，用于解析 vendored 依赖路径。
    #[arg(long = "repo-root")]
    repo_root: PathBuf,
    /// `adapter.target.versions` 里要生成的版本；缺省取第一个。
    #[arg(long = "crate-version")]
    crate_version: Option<String>,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

/// `bw.adapter/0.1`。只描述「如何合法调用公开 API」。
///
/// 与缺陷相关的信息（drop 时机、触发顺序、预期结果）禁止出现在 adapter 里，
/// 见 `adapters/rusqlite/update_hook.toml` 的冻结记录与 Gate B 判据。
#[derive(Debug, Deserialize)]
struct AdapterConfig {
    schema_version: String,
    adapter_id: String,
    target: AdapterTarget,
    #[serde(default)]
    setup: Vec<AdapterStep>,
    registration: AdapterRegistration,
    trigger: AdapterStep,
    teardown: AdapterStep,
}

#[derive(Debug, Deserialize)]
struct AdapterTarget {
    /// adapter 里该字段名是 `crate`（Rust 关键字，serde rename）。
    #[serde(rename = "crate")]
    crate_name: String,
    versions: Vec<String>,
    #[serde(default)]
    features: Vec<String>,
    api_path: String,
}

#[derive(Debug, Deserialize)]
struct AdapterStep {
    step: String,
    rust: String,
}

#[derive(Debug, Deserialize)]
struct AdapterRegistration {
    receiver: String,
    method: String,
    callback_signature: String,
    #[allow(dead_code)]
    callback_arg_index: u32,
    #[allow(dead_code)]
    accepts_none_to_clear: bool,
}

/// `extract-rust-contracts` 的一行。只取生成需要的那部分。
#[derive(Debug, Deserialize)]
struct RustContractRow {
    api_id: String,
    #[serde(default)]
    contract: Option<RustContractFact>,
}

/// `judge-hand-offs` 的一行。只取生成需要的那部分。
#[derive(Debug, Deserialize)]
struct JointVerdictRow {
    api_id: String,
    #[serde(default)]
    outcome: Option<JointOutcome>,
}

#[derive(Debug, Deserialize)]
struct JointOutcome {
    #[serde(default)]
    outcome: String,
    #[serde(default)]
    verdicts: Vec<JointSubjectVerdict>,
}

#[derive(Debug, Deserialize)]
struct JointSubjectVerdict {
    subject: String,
    #[serde(default)]
    static_verdict: Option<String>,
    #[serde(default)]
    witness_obligation: Option<String>,
}

/// invalidate 槽的推导结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InvalidateDecision {
    /// 分离可构造：生成 referent 声明 + 捕获 + 显式失效。
    Generated,
    /// 判定说不能分离：不生成 invalidate 块，产物必然编不过（负对照行为）。
    Refused { reason: String },
}

/// invalidate 必须由判定的 `PermitsNonStaticCapture` + guard 结论推出。
///
/// - `PermitsNonStaticCapture` + `guard = None` → 分离可构造；
/// - `RequiresStaticCapture` → 类型层排除借用捕获（fixed 版形状）；
/// - `ContextDependent` / `Unresolved` → 签名不足以判定，缺证不猜；
/// - guard 把槽位存活绑到 subject → 分离不可构造。
fn decide_invalidate(contract: Option<&RustContractFact>) -> InvalidateDecision {
    let Some(contract) = contract else {
        return InvalidateDecision::Refused {
            reason: "contract_missing: 该 API 没有装配出 Rust 契约事实".to_owned(),
        };
    };
    match contract.capture_admission {
        EffectiveCaptureAdmission::PermitsNonStaticCapture => match contract.guard {
            RegistrationGuard::None => InvalidateDecision::Generated,
            other => InvalidateDecision::Refused {
                reason: format!(
                    "guard_binds_slot_to_subject: guard={other:?} 把槽位存活绑到被捕对象上，分离不可构造"
                ),
            },
        },
        EffectiveCaptureAdmission::RequiresStaticCapture => InvalidateDecision::Refused {
            reason: "requires_static_capture: 类型层排除借用捕获，referent 分离不可构造".to_owned(),
        },
        EffectiveCaptureAdmission::ContextDependent => InvalidateDecision::Refused {
            reason: "context_dependent: 签名不足以判定分离可行性".to_owned(),
        },
        EffectiveCaptureAdmission::Unresolved => InvalidateDecision::Refused {
            reason: "capture_admission_unresolved".to_owned(),
        },
    }
}

/// 从 `FnMut(A, B, C)` 形状的签名里解析回调参数类型列表。
fn parse_callback_params(signature: &str) -> Option<Vec<String>> {
    let open = signature.find('(')?;
    let close = signature.rfind(')')?;
    if close <= open {
        return None;
    }
    let inner = &signature[open + 1..close];
    if inner.trim().is_empty() {
        return Some(Vec::new());
    }
    let params = inner
        .split(',')
        .map(|part| part.trim().to_owned())
        .collect::<Vec<_>>();
    if params.iter().any(|part| part.is_empty()) {
        return None;
    }
    Some(params)
}

/// 渲染 `src/main.rs`。
///
/// invalidate 被拒时，回调仍然引用 `witness_referent`，而 referent 未声明——
/// **这是故意的**：判定说不能分离，程序就该编不过，负对照不需要一个「干净」的程序。
fn render_main(
    adapter: &AdapterConfig,
    decision: &InvalidateDecision,
    callback_params: &[String],
    referent: &str,
) -> String {
    let setup = adapter
        .setup
        .iter()
        .map(|step| step.rust.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let params = callback_params
        .iter()
        .map(|ty| format!("_: {ty}"))
        .collect::<Vec<_>>()
        .join(", ");
    // 注册调用不写死 `?`：真实 API 的注册方法常返回 `()`（rusqlite 0.26.1 的
    // update_hook 即如此）。`let _ =` 对 `()` 与 `Result` 两种返回都成立。
    let register = format!(
        "let _ = {}.{}(Some(callback));",
        adapter.registration.receiver, adapter.registration.method
    );
    let (invalidate_block, expected_compile) = match decision {
        InvalidateDecision::Generated => (
            format!(
                "    // invalidate：让 referent 在注册仍然有效时失效（由判定推出）。\n    // referent 用堆对象（Box）：失效后访问走 heap-use-after-free，ASan 对堆的\n    // 检测可靠；Rust 栈 use-after-scope 的 ASan 插桩不可靠（已知 rust-lang 限制）。\n    let {referent} = Box::new(String::from(\"bw-witness-referent\"));\n    let callback = |{params}| {{\n        let _ = {referent}.len();\n    }};\n    {register}\n    drop({referent});"
            ),
            true,
        ),
        InvalidateDecision::Refused { reason } => (
            format!(
                "    // invalidate 未生成：{reason}\n    // referent 未声明，本程序必然编不过——负对照行为。\n    let callback = |{params}| {{\n        let _ = {referent}.len();\n    }};\n    {register}"
            ),
            false,
        ),
    };
    format!(
        r#"#![forbid(unsafe_code)]

// Generated by `bw generate-witness-harness` (stage 5.3). Do not edit by hand.
// adapter: {adapter_id}
// contract api: {api_id}
// invalidate: {decision}
// expected_compile: {expected_compile}

// 回调参数类型与 setup 片段来自 adapter 原文（完整路径），不需要 use 行；
// 若 adapter 使用短名，编译错误会暴露 adapter 的缺陷（缺证路径）。
fn main() -> Result<(), Box<dyn std::error::Error>> {{
{setup}
{invalidate_block}
{trigger}
{teardown}
    Ok(())
}}
"#,
        adapter_id = adapter.adapter_id,
        api_id = adapter.target.api_path,
        decision = serde_json::to_value(decision)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "unknown".to_owned()),
        expected_compile = expected_compile,
        setup = setup,
        invalidate_block = invalidate_block,
        trigger = adapter.trigger.rust,
        teardown = adapter.teardown.rust,
    )
}

/// 渲染 `Cargo.toml`：pinned `=version` + vendored patch，与静态分析绑定的
/// 外部构建同源（bundled sqlite 由 libsqlite3-sys 构建）。
fn render_cargo_toml(
    harness_name: &str,
    repo_root: &Path,
    version: &str,
    features: &[String],
) -> String {
    let features = features
        .iter()
        .map(|feature| format!("\"{feature}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"# Generated by `bw generate-witness-harness` (stage 5.3). Do not edit by hand.
[package]
name = "{harness_name}"
version = "0.1.0"
edition = "2021"
publish = false

[workspace]

[[bin]]
name = "{harness_name}"
path = "src/main.rs"

[dependencies]
rusqlite = {{ version = "={version}", features = [{features}] }}

[patch.crates-io]
rusqlite = {{ path = "{root}/benchmarks/historical-cves/rusqlite/vendor/rusqlite-{version}" }}
"#,
        harness_name = harness_name,
        root = repo_root.display(),
        version = version,
        features = features,
    )
}

fn sanitize_slug(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .to_ascii_lowercase()
}

pub fn run(args: GenerateWitnessHarnessArgs) -> Result<CommandStatus, CliError> {
    let adapter_text = fs::read_to_string(&args.adapter)
        .map_err(|error| CliError::input("BW-IO", format!("adapter: {error}")))?;
    let adapter: AdapterConfig = toml::from_str(&adapter_text)
        .map_err(|error| CliError::input("BW-ADAPTER", error.to_string()))?;

    let contracts: Vec<RustContractRow> = read_jsonl(&args.contracts, args.max_line_bytes)?
        .into_iter()
        .map(|located| located.value)
        .collect();
    let verdicts: Vec<JointVerdictRow> = read_jsonl(&args.verdicts, args.max_line_bytes)?
        .into_iter()
        .map(|located| located.value)
        .collect();

    // 版本：显式参数优先，否则取 adapter 冻结时列出的第一个（vulnerable）。
    let version = args
        .crate_version
        .clone()
        .unwrap_or_else(|| {
            adapter
                .target
                .versions
                .first()
                .cloned()
                .unwrap_or_default()
        });
    if version.is_empty() {
        return Err(CliError::input(
            "BW-ADAPTER",
            "adapter.target.versions 为空且未指定 --crate-version",
        ));
    }
    // vendored 源缺失 = 无法链接与静态分析绑定的精确构建，缺证拒绝而不是凑合。
    let vendor_dir = args
        .repo_root
        .join("benchmarks/historical-cves/rusqlite/vendor")
        .join(format!("rusqlite-{version}"));
    if !vendor_dir.is_dir() {
        return Err(CliError::input(
            "BW-VENDOR",
            format!("vendored rusqlite-{version} 不存在（{}）", vendor_dir.display()),
        ));
    }

    // 匹配契约与判定：adapter.api_path 的尾段（`update_hook`）对齐契约 api_id
    // 的尾段。这只是**选择生成对象**，两侧证据的联结由 judge-hand-offs 完成。
    let api_tail = adapter
        .target
        .api_path
        .rsplit("::")
        .next()
        .unwrap_or("")
        .to_owned();
    let contract_row = contracts.iter().find(|row| {
        row.api_id == adapter.target.api_path
            || row.api_id.ends_with(&format!("::{api_tail}"))
    });
    let Some(contract_row) = contract_row else {
        return Err(CliError::input(
            "BW-CONTRACT",
            format!("没有匹配 API {} 的 Rust 契约", adapter.target.api_path),
        ));
    };
    let verdict_row = verdicts
        .iter()
        .find(|row| row.api_id == contract_row.api_id)
        .and_then(|row| row.outcome.as_ref())
        .filter(|outcome| outcome.outcome == "joined");
    let captured_referent_verdict = verdict_row
        .map(|outcome| {
            outcome
                .verdicts
                .iter()
                .find(|verdict| verdict.subject == "captured_referent")
        })
        .flatten();
    let _ = captured_referent_verdict; // 诊断信息；判定本身的完备性由 judge 负责。

    let decision = decide_invalidate(contract_row.contract.as_ref());
    let expected_compile = matches!(decision, InvalidateDecision::Generated);
    let callback_params = parse_callback_params(&adapter.registration.callback_signature)
        .ok_or_else(|| {
            CliError::input(
                "BW-ADAPTER",
                format!(
                    "无法解析 callback_signature: {}",
                    adapter.registration.callback_signature
                ),
            )
        })?;

    let referent = "witness_referent";
    let main_rs = render_main(&adapter, &decision, &callback_params, referent);
    let harness_name = format!(
        "bw-witness-{}-{}",
        sanitize_slug(&adapter.adapter_id),
        sanitize_slug(&version)
    );
    let cargo_toml = render_cargo_toml(
        &harness_name,
        &args.repo_root,
        &version,
        &adapter.target.features,
    );

    fs::create_dir_all(args.output_dir.join("src"))
        .map_err(|error| CliError::input("BW-IO", error.to_string()))?;
    let main_path = args.output_dir.join("src/main.rs");
    let cargo_path = args.output_dir.join("Cargo.toml");
    fs::write(&main_path, main_rs).map_err(|error| CliError::input("BW-IO", error.to_string()))?;
    fs::write(&cargo_path, cargo_toml).map_err(|error| CliError::input("BW-IO", error.to_string()))?;

    let summary = serde_json::json!({
        "schema_version": "bw.witness-generation/0.1",
        "run_id": args.run_id,
        "adapter_id": adapter.adapter_id,
        "api_id": contract_row.api_id,
        "crate_version": version,
        "invalidate": serde_json::to_value(&decision).unwrap_or(serde_json::json!(null)),
        "expected_compile": expected_compile,
        "files": {
            "src/main.rs": hex_digest(sha256_bytes(&fs::read(&main_path).map_err(|e| CliError::input("BW-IO", e.to_string()))?)?),
            "Cargo.toml": hex_digest(sha256_bytes(&fs::read(&cargo_path).map_err(|e| CliError::input("BW-IO", e.to_string()))?)?),
        },
    });
    let summary_path = args.output_dir.join("generation-summary.json");
    write_json_file(&summary_path, &summary)?;
    let mut status = summary.clone();
    status["kind"] = serde_json::json!("witness-generation");
    status["output_dir"] = serde_json::json!(args.output_dir.display().to_string());
    crate::commands::write_json_stdout(&status)?;
    Ok(CommandStatus::Success)
}

fn sha256_bytes(bytes: &[u8]) -> Result<[u8; 32], CliError> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> AdapterConfig {
        toml::from_str(
            r#"
schema_version = "bw.adapter/0.1"
adapter_id = "adapter:rusqlite:update_hook"

[target]
crate = "rusqlite"
versions = ["0.26.1", "0.26.2"]
features = ["bundled", "hooks"]
api_path = "rusqlite::Connection::update_hook"

[[setup]]
step = "open_connection"
rust = "let conn = rusqlite::Connection::open_in_memory()?;"

[[setup]]
step = "create_table"
rust = "conn.execute_batch(\"CREATE TABLE t (v INTEGER)\")?;"

[registration]
receiver = "conn"
method = "update_hook"
callback_signature = "FnMut(rusqlite::hooks::Action, &str, &str, i64)"
callback_arg_index = 0
accepts_none_to_clear = true

[trigger]
step = "perform_write"
rust = "conn.execute(\"INSERT INTO t (v) VALUES (1)\", [])?;"

[teardown]
step = "drop_connection"
rust = "drop(conn);"
"#,
        )
        .expect("test adapter should parse")
    }

    fn contract_row(admission: &str, guard: &str) -> RustContractRow {
        let json = format!(
            r#"{{"schema_version":"bw.rust-contract/0.1","run_id":"t","api_id":"hooks::<impl Connection>::update_hook","foreign_symbol":"sqlite3_update_hook","contract":{{"hand_off":{{"rust_artifact":"a","build_profile":"b","safe_entry_instance":"s","rust_def_instance":"d","call_occurrence":"c","foreign_symbol":"sqlite3_update_hook","callback_arg_index":1,"userdata_arg_index":2,"registration_key":null,"registration_generation":"multiple_static_sites"}},"capture_admission":"{admission}","guard":"{guard}","allocation":"unresolved","evidence":[]}}}}"#
        );
        serde_json::from_str(&json).expect("contract row should parse")
    }

    #[test]
    fn invalidate_generated_when_capture_permitted_and_no_guard() {
        let row = contract_row("permits_non_static_capture", "none");
        let decision = decide_invalidate(row.contract.as_ref());
        assert_eq!(decision, InvalidateDecision::Generated);
        let main_rs = render_main(
            &adapter(),
            &decision,
            &[
                "rusqlite::hooks::Action".to_owned(),
                "&str".to_owned(),
                "&str".to_owned(),
                "i64".to_owned(),
            ],
            "witness_referent",
        );
        assert!(main_rs.contains("let witness_referent = Box::new(String::from(\"bw-witness-referent\"));"));
        assert!(main_rs.contains("drop(witness_referent);"));
        assert!(main_rs.contains("let _ = conn.update_hook(Some(callback));"));
        assert!(main_rs.contains("let _ = witness_referent.len();"));
        assert!(main_rs.contains("#![forbid(unsafe_code)]"));
        assert!(!main_rs.contains("bw_runtime"));
    }

    #[test]
    fn invalidate_refused_when_requires_static_capture() {
        let row = contract_row("requires_static_capture", "none");
        let decision = decide_invalidate(row.contract.as_ref());
        assert!(matches!(decision, InvalidateDecision::Refused { .. }));
        let main_rs = render_main(
            &adapter(),
            &decision,
            &["rusqlite::hooks::Action".to_owned(), "&str".to_owned()],
            "witness_referent",
        );
        // 不生成 referent 声明与 drop；回调仍引用它 → 必然编不过（负对照行为）。
        assert!(!main_rs.contains("let witness_referent ="));
        assert!(!main_rs.contains("drop(witness_referent);"));
        assert!(main_rs.contains("let _ = witness_referent.len();"));
        assert!(main_rs.contains("expected_compile: false"));
    }

    #[test]
    fn invalidate_refused_when_guard_binds_slot() {
        let row = contract_row("permits_non_static_capture", "ties_slot_to_subject");
        let decision = decide_invalidate(row.contract.as_ref());
        assert!(matches!(
            decision,
            InvalidateDecision::Refused { reason } if reason.contains("guard_binds_slot_to_subject")
        ));
    }

    #[test]
    fn invalidate_refused_when_contract_missing() {
        let decision = decide_invalidate(None);
        assert!(matches!(
            decision,
            InvalidateDecision::Refused { reason } if reason.contains("contract_missing")
        ));
    }

    #[test]
    fn parse_callback_params_splits_signature() {
        let params = parse_callback_params("FnMut(rusqlite::hooks::Action, &str, &str, i64)").unwrap();
        assert_eq!(
            params,
            vec![
                "rusqlite::hooks::Action".to_owned(),
                "&str".to_owned(),
                "&str".to_owned(),
                "i64".to_owned()
            ]
        );
        assert_eq!(parse_callback_params("FnMut()").unwrap(), Vec::<String>::new());
        assert!(parse_callback_params("FnMut((").is_none());
    }

    #[test]
    fn cargo_toml_pins_version_and_vendor() {
        let cargo = render_cargo_toml(
            "bw-witness-adapter-rusqlite-update_hook-0-26-1",
            Path::new("/repo"),
            "0.26.1",
            &["bundled".to_owned(), "hooks".to_owned()],
        );
        assert!(cargo.contains("rusqlite = { version = \"=0.26.1\", features = [\"bundled\", \"hooks\"] }"));
        assert!(cargo.contains("vendor/rusqlite-0.26.1"));
        assert!(!cargo.contains("bw_runtime"));
        assert!(!cargo.contains("bw-model"));
    }
}
