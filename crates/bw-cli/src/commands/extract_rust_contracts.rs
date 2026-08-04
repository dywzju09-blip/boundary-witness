//! 把编译器产出的静态事实装配成 Rust 侧契约事实，并写出可校验的产物。
//!
//! 这是执行计划阶段 1.4 的入口：在此之前，`assemble_rust_contract_facts` 只有测试在
//! 调用，Rust 侧**跑不起来**——阶段 1 的完成条件要求它能独立运行并回答「哪个 public
//! safe API，在什么 hand-off，把什么生命周期义务交给了外部组件」。
//!
//! # 产物只用于 Rust 侧回归
//!
//! 装配出的 `HandOffId` 只填得出 Rust 侧那几段，外部 artifact 与符号要等阶段 2 接上
//! 真实构建。**因此它还不能进 P3 的联结。**

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use bw_model::{HandOffId, RustContractAssembly, StaticFactEnvelope, assemble_rust_contract_facts};
use clap::Args;
use serde::Serialize;

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, hex_digest, read_jsonl, write_json_file, write_records},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct ExtractRustContractsArgs {
    /// compiler 写出的 `static-facts.jsonl`。
    #[arg(long)]
    facts: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    /// 参与 `HandOffId` 的构建配置标识。阶段 2 会换成真实 build profile。
    #[arg(long = "build-profile", default_value = "unbound")]
    build_profile: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

/// 装配结果的一条记录。`gaps` 非空即表示该交出点没有装配成契约。
#[derive(Debug, Serialize)]
struct RustContractRecord {
    schema_version: &'static str,
    run_id: String,
    api_id: String,
    callback_param: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    contract: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    gaps: Vec<String>,
}

/// 缺证原因的计数。**这是 attrition waterfall 的输入**，不能只报总数。
#[derive(Debug, Default, Serialize)]
struct RustContractSummary {
    schema_version: &'static str,
    run_id: String,
    hand_offs_total: usize,
    assembled: usize,
    gapped: usize,
    /// 按 gap 原因分别计数。
    gap_reasons: BTreeMap<String, usize>,
    /// 按事实层 `Unresolved` 原因分别计数。
    unresolved_reasons: BTreeMap<String, usize>,
}

const SCHEMA_VERSION: &str = "bw.rust-contract/0.1";

pub fn run(args: ExtractRustContractsArgs) -> Result<CommandStatus, CliError> {
    let facts: Vec<StaticFactEnvelope> = read_jsonl(&args.facts, args.max_line_bytes)?
        .into_iter()
        .map(|located| located.value)
        .collect();

    let build_profile = args.build_profile.clone();
    let hand_off_id = move |api_id: &str, callback_param: &str| HandOffId {
        rust_artifact: String::from("pending-stage-2"),
        rust_def_instance: api_id.to_owned(),
        call_occurrence: format!("callback_param:{callback_param}"),
        foreign_artifact: String::from("pending-stage-2"),
        foreign_symbol: String::from("pending-stage-2"),
        callback_arg_index: 0,
        userdata_arg_index: None,
        registration_key: None,
        build_profile: build_profile.clone(),
    };

    let assembly = assemble_rust_contract_facts(&facts, &hand_off_id);
    let mut summary = RustContractSummary {
        schema_version: SCHEMA_VERSION,
        run_id: args.run_id.clone(),
        hand_offs_total: assembly.len(),
        ..RustContractSummary::default()
    };
    for reason in unresolved_reason_counts(&facts) {
        *summary.unresolved_reasons.entry(reason).or_default() += 1;
    }

    let mut records = Vec::new();
    for item in assembly {
        match item {
            RustContractAssembly::Assembled(fact) => {
                summary.assembled += 1;
                records.push(RustContractRecord {
                    schema_version: SCHEMA_VERSION,
                    run_id: args.run_id.clone(),
                    api_id: fact.hand_off.rust_def_instance.clone(),
                    callback_param: fact
                        .hand_off
                        .call_occurrence
                        .trim_start_matches("callback_param:")
                        .to_owned(),
                    contract: Some(
                        serde_json::to_value(&*fact)
                            .map_err(|error| CliError::internal(error.to_string()))?,
                    ),
                    gaps: Vec::new(),
                });
            }
            RustContractAssembly::Gap {
                api_id,
                callback_param,
                gaps,
            } => {
                summary.gapped += 1;
                let gaps = gaps
                    .into_iter()
                    .map(|gap| {
                        serde_json::to_value(gap)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .unwrap_or_else(|| "unknown".to_owned())
                    })
                    .collect::<Vec<_>>();
                for gap in &gaps {
                    *summary.gap_reasons.entry(gap.clone()).or_default() += 1;
                }
                records.push(RustContractRecord {
                    schema_version: SCHEMA_VERSION,
                    run_id: args.run_id.clone(),
                    api_id,
                    callback_param,
                    contract: None,
                    gaps,
                });
            }
        }
    }
    // 排序让同一输入的产物逐字节稳定——阶段 1.4 要求重复运行结果一致。
    records.sort_by(|left, right| {
        left.api_id
            .cmp(&right.api_id)
            .then(left.callback_param.cmp(&right.callback_param))
    });

    std::fs::create_dir_all(&args.output_dir)?;
    let records_path = args.output_dir.join("rust-contracts.jsonl");
    write_records(&records_path, &records)?;
    let summary_path = args.output_dir.join("rust-contract-summary.json");
    write_json_file(&summary_path, &summary)?;

    let status = serde_json::json!({
        "kind": "rust-contracts",
        "run_id": args.run_id,
        "records": records_path,
        "summary": summary_path,
        "records_sha256": sha256_of(&records_path)?,
        "hand_offs_total": summary.hand_offs_total,
        "assembled": summary.assembled,
        "gapped": summary.gapped,
    });
    crate::commands::write_json_stdout(&status)?;
    Ok(CommandStatus::Success)
}

/// 事实层 `Unresolved` 原因的计数。
fn unresolved_reason_counts(facts: &[StaticFactEnvelope]) -> Vec<String> {
    use bw_model::StaticFact;

    let token = |reason: Option<bw_model::UnresolvedReason>| {
        reason.and_then(|reason| {
            serde_json::to_value(reason)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
        })
    };
    facts
        .iter()
        .filter_map(|fact| match &fact.payload {
            StaticFact::RegistrationGuard(guard) => token(guard.unresolved_reason),
            StaticFact::AllocationOwnership(ownership) => token(ownership.unresolved_reason),
            StaticFact::SafeEntryLineage(lineage) => token(lineage.unresolved_reason),
            _ => None,
        })
        .collect()
}

fn sha256_of(path: &Path) -> Result<String, CliError> {
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
    Ok(hex_digest(Sha256::digest(bytes)))
}
