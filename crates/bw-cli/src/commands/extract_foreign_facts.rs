//! 从真实构建捕获的外部 LLVM IR 里提取外部侧行为事实。
//!
//! 这是执行计划阶段 3 的入口。输入是阶段 2 的 `cc-capture` 捕获的 bitcode 转成的文本 IR
//! （`llvm-dis`），加一份只声明符号与参数角色的 RoleMap；输出是 Q1 / Q4′ / 降级 Q3 的
//! 四项正交结论与指令级证据。
//!
//! # 产物里没有 `HandOffId`
//!
//! 交出点身份要 Rust 侧与外部侧各出一半，本命令只看得见外部侧。**因此这里刻意不填
//! 占位身份**——填了就会有人把它拿去 join。两侧绑定是阶段 4 的 P0。

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use bw_foreign_ir::{ForeignAnalysis, ForeignRoleMap, SlotId, analyze_text};
use bw_model::ForeignHandOffKey;
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::{
    commands::{hex_digest, write_json_file, write_records},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct ExtractForeignFactsArgs {
    /// `llvm-dis` 产出的文本 IR。
    #[arg(long)]
    ir: PathBuf,
    /// RoleMap：只声明符号与参数角色，**不声明行为**。
    #[arg(long)]
    roles: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    /// 被分析的外部 artifact 标识，写进产物供阶段 4 绑定回查。
    #[arg(long = "foreign-artifact")]
    foreign_artifact: String,
    /// 构建配置。**必须与 Rust 侧同值**，否则联结会以 build mismatch 被拒绝。
    ///
    /// 它在提取时就记进产物，而不是留到联结时由调用方断言——事后断言等于没有检查。
    #[arg(long = "build-profile")]
    build_profile: String,
}

/// RoleMap 文件。
///
/// **只能声明符号与参数角色。** 「是否保留」「是否晚调」「是否清槽」一律由 IR 回答；
/// 把它们写进 RoleMap 就等于让结论来自人工标注，阶段 3 的完成条件明确禁止。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleMapFile {
    schema_version: String,
    /// 出处与依据，仅供人读。
    #[serde(default)]
    notes: Vec<String>,
    roles: Vec<ForeignRoleMap>,
}

use bw_model::FOREIGN_BEHAVIOR_SCHEMA_V01 as SCHEMA_VERSION;
use bw_model::FOREIGN_ROLE_MAP_SCHEMA_V01 as ROLE_MAP_SCHEMA_VERSION;

#[derive(Debug, Serialize)]
struct ForeignFactRecord {
    schema_version: &'static str,
    run_id: String,
    /// 外部侧那半个交出点身份。**另一半在 Rust 侧**，完整身份由联结合成。
    hand_off: ForeignHandOffKey,
    /// 仅作诊断：符号已经在 `hand_off` 里，这里重复一份是为了让产物可读。
    register_symbol: String,
    /// 分析结论与全部证据。
    analysis: ForeignAnalysis,
}

/// 缺证与分析边界的分类计数。**这是 attrition waterfall 的外部侧输入。**
#[derive(Debug, Default, Serialize)]
struct ForeignFactSummary {
    schema_version: &'static str,
    run_id: String,
    foreign_artifact: String,
    hand_offs_total: usize,
    /// RoleMap 自带的出处说明，随产物一起留存。
    role_map_notes: Vec<String>,
    /// 至少找到一个槽位的交出点数。
    with_slots: usize,
    retention_counts: BTreeMap<String, usize>,
    invocation_counts: BTreeMap<String, usize>,
    clear_counts: BTreeMap<String, usize>,
    path_compatibility_counts: BTreeMap<String, usize>,
    /// 按 [`bw_foreign_ir::BoundaryReason`] 分别计数，不合并成「不可分析」。
    boundary_reasons: BTreeMap<String, usize>,
}

pub fn run(args: ExtractForeignFactsArgs) -> Result<CommandStatus, CliError> {
    let roles_text = std::fs::read_to_string(&args.roles).map_err(|error| {
        CliError::input("BW-IO", format!("{}: {}", args.roles.display(), error))
    })?;
    let role_map: RoleMapFile = serde_json::from_str(&roles_text)
        .map_err(|error| CliError::input("BW-SCHEMA", format!("role map: {error}")))?;
    if role_map.schema_version != ROLE_MAP_SCHEMA_VERSION {
        return Err(CliError::input(
            "BW-SCHEMA",
            format!(
                "role map schema {} is not {ROLE_MAP_SCHEMA_VERSION}",
                role_map.schema_version
            ),
        ));
    }

    let ir_text = std::fs::read_to_string(&args.ir)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", args.ir.display(), error)))?;

    let mut summary = ForeignFactSummary {
        schema_version: SCHEMA_VERSION,
        run_id: args.run_id.clone(),
        foreign_artifact: args.foreign_artifact.clone(),
        hand_offs_total: role_map.roles.len(),
        role_map_notes: role_map.notes.clone(),
        ..ForeignFactSummary::default()
    };

    let mut records = Vec::new();
    for roles in &role_map.roles {
        let analysis = analyze_text(&ir_text, roles).map_err(|error| {
            CliError::input("BW-SCHEMA", format!("{}: {error}", args.ir.display()))
        })?;

        if !analysis.slots.is_empty() {
            summary.with_slots += 1;
        }
        bump(&mut summary.retention_counts, &analysis.retention)?;
        bump(&mut summary.invocation_counts, &analysis.invocation)?;
        bump(&mut summary.clear_counts, &analysis.clear)?;
        bump(
            &mut summary.path_compatibility_counts,
            &analysis.path_compatibility,
        )?;
        for boundary in &analysis.boundaries {
            bump(&mut summary.boundary_reasons, &boundary.reason)?;
        }

        records.push(ForeignFactRecord {
            schema_version: SCHEMA_VERSION,
            run_id: args.run_id.clone(),
            hand_off: ForeignHandOffKey {
                foreign_artifact: args.foreign_artifact.clone(),
                build_profile: args.build_profile.clone(),
                foreign_symbol: roles.register_symbol.clone(),
                callback_arg_index: roles.callback_arg_index as u32,
                userdata_arg_index: roles.userdata_arg_index.map(|index| index as u32),
                registration_key: None,
            },
            register_symbol: roles.register_symbol.clone(),
            analysis,
        });
    }
    // 同一输入重复运行要逐字节一致。
    records.sort_by(|left, right| left.register_symbol.cmp(&right.register_symbol));

    std::fs::create_dir_all(&args.output_dir)?;
    let records_path = args.output_dir.join("foreign-facts.jsonl");
    write_records(&records_path, &records)?;
    let summary_path = args.output_dir.join("foreign-fact-summary.json");
    write_json_file(&summary_path, &summary)?;

    let slots: usize = records
        .iter()
        .map(|record| record.analysis.slots.len())
        .sum();
    let status = serde_json::json!({
        "kind": "foreign-facts",
        "run_id": args.run_id,
        "foreign_artifact": args.foreign_artifact,
        "records": records_path,
        "summary": summary_path,
        "records_sha256": sha256_of(&records_path)?,
        "hand_offs_total": summary.hand_offs_total,
        "with_slots": summary.with_slots,
        "slots_total": slots,
        "slots": records
            .iter()
            .flat_map(|record| record.analysis.slots.iter().map(SlotId::describe))
            .collect::<Vec<_>>(),
    });
    crate::commands::write_json_stdout(&status)?;
    Ok(CommandStatus::Success)
}

/// 按枚举的 serde 取值分类计数。取值名直接用序列化形式，产物与代码不会漂移。
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
