//! 把三态判定推导成反证计划（执行计划阶段 5.1）。
//!
//! 输入是 [`super::judge_hand_offs`] 的产物与 `extract-rust-contracts` 的产物：
//!
//! ```text
//! joint-verdicts.jsonl ──┐
//!                        ├─→ 关联契约事实 ─→ plan_witness ─→ plans / refusals
//! rust-contracts.jsonl ──┘
//! ```
//!
//! # 拒绝也是产物
//!
//! 相容判定、没挂义务的缺证、关联不上的判定都必须逐条写出并带原因。只输出成功
//! 计划会让覆盖缺口不可见——那正是「看起来在合成反证，其实什么都没生成」的形状。
//!
//! # 与 rust-contracts 的关联是诊断级的
//!
//! 判定的身份里已经有 safe entry / def instance / 符号与参数角色；本命令按这六段
//! 身份把契约事实关联回来，**只为选择生成形状**。证据的联结只发生在上游
//! `judge-hand-offs`，这里不做任何二次联结，也绝不按 API 名匹配。

use std::collections::BTreeMap;

use bw_model::{
    CompatibilityVerdict, JoinOutcome, RustContractFact, WITNESS_PLAN_SCHEMA_V01, WitnessPlan,
    WitnessPlanInput, plan_witness,
};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, hex_digest, read_jsonl, write_json_file, write_records},
    exit::{CliError, CommandStatus},
};

/// 一个交出点的联结与判定结果。与 `judge_hand_offs` 写出的 wire 格式一致。
#[derive(Debug, Deserialize)]
struct JointRecord {
    run_id: String,
    api_id: String,
    outcome: JoinOutcome,
}

/// `extract-rust-contracts` 写出的一行。
#[derive(Debug, Deserialize)]
struct RustContractRecord {
    #[serde(default)]
    contract: Option<RustContractFact>,
}

/// 关联键：两侧半键重叠的身份段加上 Rust 侧独有的交出点定位。
///
/// **不含 api_id**——那是诊断字段（ADR-0003 第五条），拿它当检索键等于按名字近似。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CorrelationKey {
    safe_entry_instance: String,
    rust_def_instance: String,
    call_occurrence: String,
    foreign_symbol: String,
    callback_arg_index: u32,
    userdata_arg_index: Option<u32>,
}

impl CorrelationKey {
    fn from_rust(contract: &RustContractFact) -> Self {
        let key = &contract.hand_off;
        Self {
            safe_entry_instance: key.safe_entry_instance.clone(),
            rust_def_instance: key.rust_def_instance.clone(),
            call_occurrence: key.call_occurrence.clone(),
            foreign_symbol: key.foreign_symbol.clone(),
            callback_arg_index: key.callback_arg_index,
            userdata_arg_index: key.userdata_arg_index,
        }
    }

    fn from_verdict(verdict: &CompatibilityVerdict) -> Option<Self> {
        let key = &verdict.hand_off;
        // 外部 artifact 缺席时（Rust-only 变体）身份是诊断用的残缺键，
        // 不得再参与任何组合——包括这里的关联。
        if key.foreign_artifact.is_empty() {
            return None;
        }
        Some(Self {
            safe_entry_instance: key.safe_entry_instance.clone(),
            rust_def_instance: key.rust_def_instance.clone(),
            call_occurrence: key.call_occurrence.clone(),
            foreign_symbol: key.foreign_symbol.clone(),
            callback_arg_index: key.callback_arg_index,
            userdata_arg_index: key.userdata_arg_index,
        })
    }
}

#[derive(Debug, Serialize)]
struct PlanRecord {
    schema_version: &'static str,
    run_id: String,
    api_id: String,
    /// 上游 joint-verdicts 里该判定的行号（1 起），lineage 回查用。
    verdict_line: usize,
    plan: WitnessPlan,
}

#[derive(Debug, Serialize)]
struct RefusalRecord {
    schema_version: &'static str,
    run_id: String,
    api_id: String,
    verdict_line: usize,
    subject: String,
    reason_token: &'static str,
}

#[derive(Debug, Serialize)]
struct PlanWitnessesSummary {
    schema_version: &'static str,
    run_id: String,
    joined_traces: usize,
    rejected_traces: usize,
    verdicts_total: usize,
    planned_total: usize,
    refused_total: usize,
    uncorrelatable_verdicts: usize,
    by_input_kind: BTreeMap<String, usize>,
    by_shape: BTreeMap<String, usize>,
    refusal_reasons: BTreeMap<String, usize>,
}

#[derive(Args)]
pub struct PlanWitnessesArgs {
    /// `judge-hand-offs` 写出的 joint-verdicts.jsonl。
    #[arg(long = "joint-verdicts")]
    joint_verdicts: std::path::PathBuf,
    /// `extract-rust-contracts` 写出的产物。
    #[arg(long = "rust-contracts")]
    rust_contracts: std::path::PathBuf,
    #[arg(long = "output-dir")]
    output_dir: std::path::PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

pub fn run(args: PlanWitnessesArgs) -> Result<CommandStatus, CliError> {
    let joints: Vec<JointRecord> = read_jsonl(&args.joint_verdicts, args.max_line_bytes)?
        .into_iter()
        .map(|located| located.value)
        .collect();
    // 输入一致性：判定记录的 run_id 必须与本次运行声明的一致。混入别的 run
    // 的判定会让 plan 的 lineage 指向一个不存在的上游。
    if let Some(foreign) = joints.iter().find(|joint| joint.run_id != args.run_id) {
        return Err(CliError::input(
            "BW-WITNESS-PLAN-INPUT",
            format!(
                "joint-verdicts 里的 run_id `{}` 与 --run-id `{}` 不一致",
                foreign.run_id, args.run_id
            ),
        ));
    }
    let contracts: Vec<RustContractRecord> = read_jsonl(&args.rust_contracts, args.max_line_bytes)?
        .into_iter()
        .map(|located| located.value)
        .collect();

    // 同一关联键出现多次时拒绝关联——分不清是哪一条契约的事实，宁可不规划。
    let mut contract_by_key = BTreeMap::<CorrelationKey, &RustContractFact>::new();
    let mut ambiguous_keys = 0usize;
    for record in &contracts {
        let Some(contract) = record.contract.as_ref() else {
            continue;
        };
        if contract_by_key
            .insert(CorrelationKey::from_rust(contract), contract)
            .is_some()
        {
            ambiguous_keys += 1;
        }
    }

    let mut summary = PlanWitnessesSummary {
        schema_version: WITNESS_PLAN_SCHEMA_V01,
        run_id: args.run_id.clone(),
        ..PlanWitnessesSummary::default_placeholder()
    };

    let mut plans = Vec::<PlanRecord>::new();
    let mut refusals = Vec::<RefusalRecord>::new();

    for (index, joint) in joints.iter().enumerate() {
        let verdict_line = index + 1;
        match &joint.outcome {
            JoinOutcome::Joined(trace) => {
                summary.joined_traces += 1;
                for verdict in &trace.verdicts {
                    summary.verdicts_total += 1;
                    let correlated = CorrelationKey::from_verdict(verdict)
                        .and_then(|key| contract_by_key.get(&key).copied());
                    let Some(contract) = correlated else {
                        summary.uncorrelatable_verdicts += 1;
                        refusals.push(RefusalRecord {
                            schema_version: WITNESS_PLAN_SCHEMA_V01,
                            run_id: args.run_id.clone(),
                            api_id: joint.api_id.clone(),
                            verdict_line,
                            subject: subject_token(verdict.subject),
                            reason_token: "rust_contract_not_correlated",
                        });
                        continue;
                    };
                    let verdict_digest = hex_digest(Sha256::digest(
                        serde_json::to_string(verdict)
                            .map_err(|error| CliError::internal(error.to_string()))?,
                    ));
                    match plan_witness(&WitnessPlanInput {
                        api_id: &joint.api_id,
                        verdict,
                        rust_contract: Some(contract),
                        verdict_digest: verdict_digest.clone(),
                    }) {
                        Ok(plan) => {
                            summary.count_plan(&plan);
                            plans.push(PlanRecord {
                                schema_version: WITNESS_PLAN_SCHEMA_V01,
                                run_id: args.run_id.clone(),
                                api_id: joint.api_id.clone(),
                                verdict_line,
                                plan,
                            });
                        }
                        Err(refusal) => {
                            summary.refused_total += 1;
                            bump(&mut summary.refusal_reasons, refusal.token().to_owned());
                            refusals.push(RefusalRecord {
                                schema_version: WITNESS_PLAN_SCHEMA_V01,
                                run_id: args.run_id.clone(),
                                api_id: joint.api_id.clone(),
                                verdict_line,
                                subject: subject_token(verdict.subject),
                                reason_token: refusal.token(),
                            });
                        }
                    }
                }
            }
            JoinOutcome::Rejected { reasons, .. } => {
                summary.rejected_traces += 1;
                for reason in reasons {
                    let token = serde_json::to_value(reason)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_else(|| "unknown".to_owned());
                    bump(
                        &mut summary.refusal_reasons,
                        format!("join_rejected:{token}"),
                    );
                }
            }
        }
    }

    // 决定性输出：同一输入重复运行逐字节一致。
    plans.sort_by(|left, right| left.plan.plan_id.cmp(&right.plan.plan_id));
    refusals.sort_by(|left, right| {
        (
            &left.api_id,
            &left.subject,
            left.reason_token,
            left.verdict_line,
        )
            .cmp(&(
                &right.api_id,
                &right.subject,
                right.reason_token,
                right.verdict_line,
            ))
    });

    std::fs::create_dir_all(&args.output_dir)?;
    let plans_path = args.output_dir.join("witness-plans.jsonl");
    write_records(&plans_path, &plans)?;
    let refusals_path = args.output_dir.join("witness-plan-refusals.jsonl");
    write_records(&refusals_path, &refusals)?;
    let summary_path = args.output_dir.join("witness-plan-summary.json");
    write_json_file(&summary_path, &summary)?;
    crate::commands::write_checksums(
        &[
            (
                "witness-plan-refusals.jsonl".to_owned(),
                refusals_path.clone(),
            ),
            ("witness-plan-summary.json".to_owned(), summary_path.clone()),
            ("witness-plans.jsonl".to_owned(), plans_path.clone()),
        ],
        &args.output_dir.join("checksums.sha256"),
    )?;

    let status = serde_json::json!({
        "kind": "witness-plans",
        "run_id": args.run_id,
        "plans": plans_path,
        "refusals": refusals_path,
        "summary": summary_path,
        "plans_sha256": sha_of(&plans_path)?,
        "planned": plans.len(),
        "refused": refusals.len(),
        "ambiguous_contract_keys": ambiguous_keys,
    });
    crate::commands::write_json_stdout(&status)?;
    Ok(CommandStatus::Success)
}

fn subject_token(subject: bw_model::LifetimeSubject) -> String {
    serde_json::to_value(subject)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn bump(counts: &mut BTreeMap<String, usize>, token: String) {
    *counts.entry(token).or_default() += 1;
}

fn sha_of(path: &std::path::Path) -> Result<String, CliError> {
    let bytes = std::fs::read(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
    Ok(hex_digest(Sha256::digest(bytes)))
}

impl PlanWitnessesSummary {
    /// serde 需要的全默认构造；schema_version 与 run_id 由调用方立即覆盖。
    fn default_placeholder() -> Self {
        Self {
            schema_version: WITNESS_PLAN_SCHEMA_V01,
            run_id: String::new(),
            joined_traces: 0,
            rejected_traces: 0,
            verdicts_total: 0,
            planned_total: 0,
            refused_total: 0,
            uncorrelatable_verdicts: 0,
            by_input_kind: BTreeMap::new(),
            by_shape: BTreeMap::new(),
            refusal_reasons: BTreeMap::new(),
        }
    }

    fn count_plan(&mut self, plan: &WitnessPlan) {
        self.planned_total += 1;
        let kind = serde_json::to_value(plan.input_kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        bump(&mut self.by_input_kind, kind);
        let shape = serde_json::to_value(plan.shape)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        bump(&mut self.by_shape, shape);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 关联键必须由六段身份组成，**不含 api_id**——那是诊断字段（ADR-0003 第五条），
    /// 拿它当检索键等于按名字近似。Rust-only 变体（外部 artifact 缺席）不得参与关联。
    #[test]
    fn correlation_key_excludes_rust_only_artifacts_and_uses_identity_only() {
        fn key() -> bw_model::RustHandOffKey {
            bw_model::RustHandOffKey {
                rust_artifact: "rust:test".to_owned(),
                build_profile: "test/dev".to_owned(),
                safe_entry_instance: "Registry::register_borrowed".to_owned(),
                rust_def_instance: "Registry::register_borrowed".to_owned(),
                call_occurrence: "site:x".to_owned(),
                foreign_symbol: "fixture_register".to_owned(),
                callback_arg_index: 0,
                userdata_arg_index: Some(1),
                registration_key: None,
                registration_generation: bw_model::RegistrationGeneration::UniqueStaticSite,
            }
        }
        fn key_as_hand_off() -> bw_model::HandOffId {
            let k = key();
            bw_model::HandOffId {
                rust_artifact: k.rust_artifact,
                foreign_artifact: "foreign:stub".to_owned(),
                build_profile: k.build_profile,
                safe_entry_instance: k.safe_entry_instance,
                rust_def_instance: k.rust_def_instance,
                call_occurrence: k.call_occurrence,
                foreign_symbol: k.foreign_symbol,
                callback_arg_index: k.callback_arg_index,
                userdata_arg_index: k.userdata_arg_index,
                registration_key: k.registration_key,
                registration_generation: k.registration_generation,
            }
        }
        let contract = bw_model::RustContractFact {
            hand_off: key(),
            capture_admission: bw_model::EffectiveCaptureAdmission::PermitsNonStaticCapture,
            guard: bw_model::RegistrationGuard::None,
            allocation: bw_model::AllocationOwnership::ForeignOwnedUntilUnregister,
            evidence: Vec::new(),
        };
        let from_contract = CorrelationKey::from_rust(&contract);
        assert_eq!(from_contract.foreign_symbol, "fixture_register");
        assert_eq!(
            from_contract.safe_entry_instance,
            "Registry::register_borrowed"
        );

        // 外部 artifact 为空：判定是 Rust-only 诊断记录，返回 None。
        let mut verdict = CompatibilityVerdict {
            hand_off: bw_model::HandOffId {
                rust_artifact: "rust:test".to_owned(),
                foreign_artifact: String::new(),
                build_profile: "test/dev".to_owned(),
                ..key_as_hand_off()
            },
            subject: bw_model::LifetimeSubject::CapturedReferent,
            static_verdict: bw_model::StaticVerdict::InsufficientEvidence,
            evidence_grade: None,
            witness_status: bw_model::WitnessStatus::NotAttempted,
            witness_obligation: Some(bw_model::WitnessObligation::EstablishJointTrace),
            assumptions: Vec::new(),
        };
        assert_eq!(CorrelationKey::from_verdict(&verdict), None);

        verdict.hand_off.foreign_artifact = "foreign:stub".to_owned();
        let correlated = CorrelationKey::from_verdict(&verdict).expect("artifact 在场即可关联");
        assert_eq!(correlated, from_contract);
    }
}
