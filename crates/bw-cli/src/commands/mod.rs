use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
};

use bw_model::JsonlReader;
use clap::Subcommand;
use serde::de::DeserializeOwned;

use crate::exit::{CliError, CommandStatus};

mod account_adapter_effort;
mod analyze;
mod audit_lifecycle_contracts;
mod build_failure_taxonomy;
mod build_lifecycle_graph_v2;
mod build_lifecycle_graph_v3;
mod build_precheck;
mod build_witness_plan;
mod compare_anonymous_pairs;
mod diff;
mod emit_candidates;
mod extract_lifecycle_evidence;
mod extract_static_facts;
mod generate_witness_harness;
mod index_boundaries;
mod materialize_lifecycle_contracts;
mod rank_lifecycle;
mod rank_lifecycle_v2;
mod reveal_static_ranking;
mod validate;
mod verify_run;

pub(crate) const DEFAULT_MAX_LINE_BYTES: usize = 1024 * 1024;

pub(crate) fn strip_rust_comments(line: &str, block_comment_depth: &mut usize) -> String {
    let bytes = line.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut in_string = false;

    while index < bytes.len() {
        if *block_comment_depth > 0 {
            if bytes[index..].starts_with(b"/*") {
                *block_comment_depth += 1;
                output.extend_from_slice(b"  ");
                index += 2;
            } else if bytes[index..].starts_with(b"*/") {
                *block_comment_depth -= 1;
                output.extend_from_slice(b"  ");
                index += 2;
            } else {
                output.push(b' ');
                index += 1;
            }
            continue;
        }

        if in_string {
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                output.extend_from_slice(&bytes[index..index + 2]);
                index += 2;
            } else {
                if bytes[index] == b'"' {
                    in_string = false;
                }
                output.push(bytes[index]);
                index += 1;
            }
            continue;
        }

        if bytes[index..].starts_with(b"//") {
            break;
        }
        if bytes[index..].starts_with(b"/*") {
            *block_comment_depth += 1;
            output.extend_from_slice(b"  ");
            index += 2;
            continue;
        }
        if bytes[index] == b'"' {
            in_string = true;
            output.push(bytes[index]);
            index += 1;
            continue;
        }

        output.push(bytes[index]);
        index += 1;
    }

    String::from_utf8(output).expect("comment stripping preserves UTF-8 code bytes")
}

#[derive(Subcommand)]
pub enum Command {
    /// 校验版本化 BoundaryWitness 证据。
    Validate(validate::ValidateArgs),
    /// 分析已校验的事实与运行轨迹。
    Analyze(analyze::AnalyzeArgs),
    /// 对 V3.2 corpus manifest 中的 crate 执行构建预检。
    BuildPrecheck(build_precheck::BuildPrecheckArgs),
    /// 对 V3.2 buildable crate 执行边界索引。
    IndexBoundaries(index_boundaries::IndexBoundariesArgs),
    /// 将 V3.2 boundary index 转为 candidate JSONL.zst 分片。
    EmitCandidates(emit_candidates::EmitCandidatesArgs),
    /// 为 V3.2 candidate 构建 lifecycle subgraph 并排序。
    RankLifecycle(rank_lifecycle::RankLifecycleArgs),
    /// 从本地源码提取 V3.2.6 中性生命周期证据。
    ExtractLifecycleEvidence(extract_lifecycle_evidence::ExtractLifecycleEvidenceArgs),
    /// 用 compiler wrapper 批量物化 V3.2.x 静态事实与 MIR 覆盖。
    ExtractStaticFacts(extract_static_facts::ExtractStaticFactsArgs),
    /// 基于 V3.2.6 证据构建 lifecycle graph v2 与 feature。
    BuildLifecycleGraphV2(build_lifecycle_graph_v2::BuildLifecycleGraphV2Args),
    /// 基于 V3.2.6 facts/contracts 构建 object-bound lifecycle graph v3。
    BuildLifecycleGraphV3(build_lifecycle_graph_v3::BuildLifecycleGraphV3Args),
    /// 基于 V3.2.6 feature 执行 evidence-driven ranking v2。
    RankLifecycleV2(rank_lifecycle_v2::RankLifecycleV2Args),
    /// 为 V3.2.6 高优先级候选生成本地受控 witness 计划。
    BuildWitnessPlan(build_witness_plan::BuildWitnessPlanArgs),
    /// 从已绑定的 witness plan 生成本地受控 harness 源码。
    GenerateWitnessHarness(generate_witness_harness::GenerateWitnessHarnessArgs),
    /// 把 harness 的运行时 site id 补进静态事实，供 oracle 判定。
    BridgeWitnessFacts(generate_witness_harness::BridgeWitnessFactsArgs),
    /// 审计 V3.2.x 本地 lifecycle contract registry 覆盖。
    AuditLifecycleContracts(audit_lifecycle_contracts::AuditLifecycleContractsArgs),
    /// 从版本化 callback retention contract registry materialize 生命周期 contract。
    MaterializeLifecycleContracts(
        materialize_lifecycle_contracts::MaterializeLifecycleContractsArgs,
    ),
    /// 比较匿名 left/right 生命周期特征可分性。
    CompareAnonymousPairs(compare_anonymous_pairs::CompareAnonymousPairsArgs),
    /// 记录 V3.2 动态验证准备阶段的 adapter effort accounting。
    AccountAdapterEffort(account_adapter_effort::AccountAdapterEffortArgs),
    /// 汇总 V3.2 pilot 未完成样本的 failure taxonomy。
    BuildFailureTaxonomy(build_failure_taxonomy::BuildFailureTaxonomyArgs),
    /// 在 ranking freeze 之后，用私有 ground truth 做静态 ranking reveal。
    RevealStaticRanking(reveal_static_ranking::RevealStaticRankingArgs),
    /// 校验本地同步的 V3.2 run checksum manifest。
    VerifyRun(verify_run::VerifyRunArgs),
    /// 比较两组规范化分析结果。
    Diff(diff::DiffArgs),
}

pub fn run(command: Command) -> Result<CommandStatus, CliError> {
    match command {
        Command::Validate(args) => validate::run(args),
        Command::Analyze(args) => analyze::run(args),
        Command::BuildPrecheck(args) => build_precheck::run(args),
        Command::IndexBoundaries(args) => index_boundaries::run(args),
        Command::EmitCandidates(args) => emit_candidates::run(args),
        Command::RankLifecycle(args) => rank_lifecycle::run(args),
        Command::ExtractLifecycleEvidence(args) => extract_lifecycle_evidence::run(args),
        Command::ExtractStaticFacts(args) => extract_static_facts::run(args),
        Command::BuildLifecycleGraphV2(args) => build_lifecycle_graph_v2::run(args),
        Command::BuildLifecycleGraphV3(args) => build_lifecycle_graph_v3::run(args),
        Command::RankLifecycleV2(args) => rank_lifecycle_v2::run(args),
        Command::BuildWitnessPlan(args) => build_witness_plan::run(args),
        Command::GenerateWitnessHarness(args) => generate_witness_harness::run(args),
        Command::BridgeWitnessFacts(args) => generate_witness_harness::run_bridge(args),
        Command::AuditLifecycleContracts(args) => audit_lifecycle_contracts::run(args),
        Command::MaterializeLifecycleContracts(args) => materialize_lifecycle_contracts::run(args),
        Command::CompareAnonymousPairs(args) => compare_anonymous_pairs::run(args),
        Command::AccountAdapterEffort(args) => account_adapter_effort::run(args),
        Command::BuildFailureTaxonomy(args) => build_failure_taxonomy::run(args),
        Command::RevealStaticRanking(args) => reveal_static_ranking::run(args),
        Command::VerifyRun(args) => verify_run::run(args),
        Command::Diff(args) => diff::run(args),
    }
}

pub(crate) fn read_jsonl<T>(
    path: &Path,
    max_line_bytes: usize,
) -> Result<Vec<bw_model::Located<T>>, CliError>
where
    T: DeserializeOwned,
{
    let reader = open_jsonl(path)?;
    let records = JsonlReader::new(reader, path.to_path_buf(), max_line_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(records)
}

pub(crate) fn read_jsonl_values<T>(path: &Path, max_line_bytes: usize) -> Result<Vec<T>, CliError>
where
    T: DeserializeOwned,
{
    Ok(read_jsonl(path, max_line_bytes)?
        .into_iter()
        .map(|located| located.value)
        .collect())
}

pub(crate) fn open_jsonl(path: &Path) -> Result<Box<dyn BufRead>, CliError> {
    let file = File::open(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
    if path.extension().is_some_and(|extension| extension == "zst") {
        let decoder = zstd::stream::read::Decoder::new(file)
            .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
        Ok(Box::new(BufReader::new(decoder)))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

pub(crate) fn read_to_string(path: &Path) -> Result<String, CliError> {
    std::fs::read_to_string(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))
}

pub(crate) fn write_json_stdout<T: serde::Serialize>(value: &T) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, value)
        .map_err(|error| CliError::internal(error.to_string()))?;
    use std::io::Write as _;
    stdout
        .write_all(b"\n")
        .map_err(|error| CliError::input("BW-IO", error.to_string()))
}

pub(crate) fn validate_trace(path: &Path, max_line_bytes: usize) -> Result<(), CliError> {
    bw_model::validate_runtime_path(path, max_line_bytes)?;
    Ok(())
}
