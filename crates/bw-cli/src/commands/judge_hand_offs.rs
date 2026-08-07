//! 把两侧事实按分层身份精确联结，并产出三态静态判定。
//!
//! 这是执行计划阶段 4.5 的静态闭环终点：
//!
//! ```text
//! Rust facts ──┐
//!              ├─→ 精确 join ─→ P3 判定 ─→ evidence lineage
//! foreign facts┘
//! ```
//!
//! # 中间产物可以留存，但不能改了再往下走
//!
//! 本命令**只读**上游产物。它不接受任何「补一个字段让它联结上」的开关——那样得到的
//! 判定说明的是补丁，不是被扫的组件。联结不上就是联结不上，按原因分类计数。
//!
//! # 拒绝也是产物
//!
//! 被拒绝的交出点必须逐条写出来并带原因。只输出成功联结的那些，会让 attrition
//! waterfall 少掉最重要的一段——大多数交出点是在哪一层掉的。

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use bw_foreign_ir::ForeignAnalysis;
use bw_model::{ForeignHandOffKey, JoinOutcome, RustContractFact, join_hand_off};
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, hex_digest, read_jsonl, write_json_file, write_records},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct JudgeHandOffsArgs {
    /// `extract-rust-contracts` 的产物。
    #[arg(long = "rust-contracts")]
    rust_contracts: PathBuf,
    /// `extract-foreign-facts` 的产物。
    #[arg(long = "foreign-facts")]
    foreign_facts: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

const SCHEMA_VERSION: &str = "bw.joint-verdict/0.1";

/// `extract-rust-contracts` 写出的一行。只取联结需要的那部分。
#[derive(Debug, Deserialize)]
struct RustContractRecord {
    api_id: String,
    #[serde(default)]
    contract: Option<RustContractFact>,
}

/// `extract-foreign-facts` 写出的一行。
#[derive(Debug, Deserialize)]
struct ForeignFactRecord {
    hand_off: ForeignHandOffKey,
    analysis: ForeignAnalysis,
}

/// 一个交出点的联结与判定结果。
#[derive(Debug, Serialize)]
struct JointRecord {
    schema_version: &'static str,
    run_id: String,
    /// 诊断用：让人一眼看出是哪个 Rust API。**不参与联结。**
    api_id: String,
    outcome: JoinOutcome,
}

/// 判定与拒绝的分类计数。
#[derive(Debug, Default, Serialize)]
struct JointSummary {
    schema_version: &'static str,
    run_id: String,
    rust_contracts_total: usize,
    foreign_facts_total: usize,
    /// 联结成功的交出点数。
    joined: usize,
    /// 联结被拒绝的交出点数。
    rejected: usize,
    /// Rust 侧有契约，但没有任何外部侧事实谈同一个符号。
    no_foreign_counterpart: usize,
    /// 按 `JoinRejection` 分别计数。**不合并成「联结失败」。**
    rejection_reasons: BTreeMap<String, usize>,
    /// 按 `StaticVerdict` 分别计数（每个交出点两类生命周期各算一条）。
    verdicts: BTreeMap<String, usize>,
    /// 按 `WitnessObligation` 分别计数。
    obligations: BTreeMap<String, usize>,
}

pub fn run(args: JudgeHandOffsArgs) -> Result<CommandStatus, CliError> {
    let rust: Vec<RustContractRecord> = read_jsonl(&args.rust_contracts, args.max_line_bytes)?
        .into_iter()
        .map(|located| located.value)
        .collect();
    let foreign: Vec<ForeignFactRecord> = read_jsonl(&args.foreign_facts, args.max_line_bytes)?
        .into_iter()
        .map(|located| located.value)
        .collect();

    // 外部侧按符号建索引。**这是唯一允许的检索键**：符号是两侧共有的那一项。
    // 按 API 名或候选分片检索一律禁止（ADR-0003 第五条）。
    let mut foreign_by_symbol = BTreeMap::<String, &ForeignFactRecord>::new();
    for record in &foreign {
        foreign_by_symbol.insert(record.hand_off.foreign_symbol.clone(), record);
    }

    let mut summary = JointSummary {
        schema_version: SCHEMA_VERSION,
        run_id: args.run_id.clone(),
        rust_contracts_total: rust.len(),
        foreign_facts_total: foreign.len(),
        ..JointSummary::default()
    };

    let mut records = Vec::new();
    for record in &rust {
        // 装配失败的 Rust 侧记录没有契约，谈不上联结——它已经在上游按 gap 计过数。
        let Some(contract) = record.contract.as_ref() else {
            continue;
        };
        let Some(foreign) = foreign_by_symbol.get(contract.hand_off.foreign_symbol.as_str()) else {
            summary.no_foreign_counterpart += 1;
            continue;
        };

        let behavior = foreign
            .analysis
            .clone()
            .into_behavior_fact(foreign.hand_off.clone());
        let outcome = join_hand_off(contract, &behavior, &foreign.analysis.slots);

        match &outcome {
            JoinOutcome::Joined(trace) => {
                summary.joined += 1;
                for verdict in &trace.verdicts {
                    bump(&mut summary.verdicts, &verdict.static_verdict)?;
                    if let Some(obligation) = verdict.witness_obligation {
                        bump(&mut summary.obligations, &obligation)?;
                    }
                }
            }
            JoinOutcome::Rejected { reasons, .. } => {
                summary.rejected += 1;
                for reason in reasons {
                    bump(&mut summary.rejection_reasons, reason)?;
                }
            }
        }
        records.push(JointRecord {
            schema_version: SCHEMA_VERSION,
            run_id: args.run_id.clone(),
            api_id: record.api_id.clone(),
            outcome,
        });
    }
    // 同一输入重复运行要逐字节一致。
    records.sort_by(|left, right| left.api_id.cmp(&right.api_id));

    std::fs::create_dir_all(&args.output_dir)?;
    let records_path = args.output_dir.join("joint-verdicts.jsonl");
    write_records(&records_path, &records)?;
    let summary_path = args.output_dir.join("joint-verdict-summary.json");
    write_json_file(&summary_path, &summary)?;

    let incompatible = summary
        .verdicts
        .get("supported_incompatibility")
        .copied()
        .unwrap_or_default();
    let status = serde_json::json!({
        "kind": "joint-verdicts",
        "run_id": args.run_id,
        "records": records_path,
        "summary": summary_path,
        "records_sha256": sha256_of(&records_path)?,
        "joined": summary.joined,
        "rejected": summary.rejected,
        "no_foreign_counterpart": summary.no_foreign_counterpart,
        "supported_incompatibility": incompatible,
    });
    crate::commands::write_json_stdout(&status)?;
    Ok(CommandStatus::Success)
}

fn bump<T: Serialize>(counts: &mut BTreeMap<String, usize>, value: &T) -> Result<(), CliError> {
    let token = serde_json::to_value(value)
        .map_err(|error| CliError::internal(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| "unknown".to_owned());
    *counts.entry(token).or_default() += 1;
    Ok(())
}

fn sha256_of(path: &Path) -> Result<String, CliError> {
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
    Ok(hex_digest(Sha256::digest(bytes)))
}
