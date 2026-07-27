use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde::{Deserialize, Serialize};

use super::artifact::sha256_hex;
use crate::{
    D1CampaignOutcome, D1CampaignRecord, D1CampaignSummary, D2BaselineConfigFile, ExperimentError,
    Result, summarize_d1_campaigns,
};

pub const D2_COMPARISON_SCHEMA_V01: &str = "boundary-witness.d2-comparison/0.1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum D2BaselineGroupKind {
    RandomAction,
    CoverageOnly,
    CoverageState,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D2SharedBudget {
    pub campaign_count: u64,
    pub cpu_minutes: u64,
    pub seed_list: Vec<u64>,
    pub initial_corpus_digest: String,
    pub max_sequence_len: usize,
    pub objective_policy_digest: String,
    pub target_build_id: String,
    pub sanitizer: String,
}

impl D2SharedBudget {
    pub fn validate(&self) -> Result<()> {
        if self.campaign_count == 0 {
            return Err(ExperimentError::InvalidInput(
                "shared_budget.campaign_count must be greater than zero".to_owned(),
            ));
        }
        if self.cpu_minutes == 0 {
            return Err(ExperimentError::InvalidInput(
                "shared_budget.cpu_minutes must be greater than zero".to_owned(),
            ));
        }
        if self.seed_list.is_empty() {
            return Err(ExperimentError::InvalidInput(
                "shared_budget.seed_list must not be empty".to_owned(),
            ));
        }
        if self.seed_list.len() as u64 != self.campaign_count {
            return Err(ExperimentError::InvalidInput(format!(
                "shared_budget.seed_list length {} must equal shared_budget.campaign_count {}",
                self.seed_list.len(),
                self.campaign_count
            )));
        }
        if self.max_sequence_len == 0 {
            return Err(ExperimentError::InvalidInput(
                "shared_budget.max_sequence_len must be greater than zero".to_owned(),
            ));
        }
        for (field, value) in [
            ("initial_corpus_digest", self.initial_corpus_digest.as_str()),
            (
                "objective_policy_digest",
                self.objective_policy_digest.as_str(),
            ),
        ] {
            if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(ExperimentError::InvalidInput(format!(
                    "shared_budget.{field} must be sha256 hex"
                )));
            }
        }
        for (field, value) in [
            ("target_build_id", self.target_build_id.as_str()),
            ("sanitizer", self.sanitizer.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ExperimentError::InvalidInput(format!(
                    "shared_budget.{field} must not be empty"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D2ComparisonConfigDigest {
    pub group_count: usize,
    pub cpu_minutes: u64,
    pub seed_list: Vec<u64>,
    pub config_digest: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D2ComparisonSummary {
    pub schema_version: String,
    pub suite_id: String,
    pub config_digest: String,
    pub groups: Vec<D2BaselineGroupKind>,
    pub group_results: Vec<D2GroupComparisonResult>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D2GroupComparisonResult {
    pub group: D2BaselineGroupKind,
    pub baseline_id: String,
    pub status: String,
    pub campaign_count: u64,
    pub cpu_minutes: u64,
    pub seed_list: Vec<u64>,
    pub primary_success_count: u64,
    pub time_to_first_primary_ms: Option<u64>,
    pub valid_sequence_ratio: Option<f64>,
    pub minimized_sequence_len: Option<usize>,
    pub replay_success_count: Option<usize>,
    pub progress_state_coverage: u64,
    pub secondary_finding_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct D2GroupCampaignRecords {
    pub group: D2BaselineGroupKind,
    pub progress_state_coverage: u64,
    pub records: Vec<D1CampaignRecord>,
}

pub fn verify_d2_budget_equivalence(
    config: &D2BaselineConfigFile,
) -> Result<D2ComparisonConfigDigest> {
    config.validate()?;
    let shared = &config.shared_budget;

    for group in &config.groups {
        match group {
            D2BaselineGroupKind::RandomAction => {
                require_equal(
                    "random_action.cpu_minutes",
                    config.random_action.cpu_minutes,
                    shared.cpu_minutes,
                )?;
                require_equal(
                    "random_action.max_sequence_len",
                    config.random_action.max_sequence_len,
                    shared.max_sequence_len,
                )?;
                require_seed(
                    "random_action.seed",
                    config.random_action.seed,
                    &shared.seed_list,
                )?;
                if let Some(sanitizer) = &config.random_action.sanitizer {
                    require_str_equal("random_action.sanitizer", sanitizer, &shared.sanitizer)?;
                }
            }
            D2BaselineGroupKind::CoverageOnly => {
                let coverage = config.coverage_only.as_ref().ok_or_else(|| {
                    ExperimentError::InvalidInput("missing [coverage_only] group config".to_owned())
                })?;
                require_equal(
                    "coverage_only.cpu_minutes",
                    coverage.cpu_minutes,
                    shared.cpu_minutes,
                )?;
                require_equal(
                    "coverage_only.max_sequence_len",
                    coverage.max_sequence_len,
                    shared.max_sequence_len,
                )?;
                require_seed("coverage_only.seed", coverage.seed, &shared.seed_list)?;
                require_str_equal(
                    "coverage_only.sanitizer",
                    &coverage.sanitizer,
                    &shared.sanitizer,
                )?;
            }
            D2BaselineGroupKind::CoverageState => {
                let state = config.coverage_state.as_ref().ok_or_else(|| {
                    ExperimentError::InvalidInput(
                        "missing [coverage_state] group config".to_owned(),
                    )
                })?;
                require_equal(
                    "coverage_state.cpu_minutes",
                    state.cpu_minutes,
                    shared.cpu_minutes,
                )?;
                require_equal(
                    "coverage_state.max_sequence_len",
                    state.max_sequence_len,
                    shared.max_sequence_len,
                )?;
                require_seed("coverage_state.seed", state.seed, &shared.seed_list)?;
                require_str_equal(
                    "coverage_state.sanitizer",
                    &state.sanitizer,
                    &shared.sanitizer,
                )?;
            }
        }
    }

    let digest = config_digest(config)?;
    Ok(D2ComparisonConfigDigest {
        group_count: config.groups.len(),
        cpu_minutes: shared.cpu_minutes,
        seed_list: shared.seed_list.clone(),
        config_digest: digest,
    })
}

pub fn comparison_summary(config: &D2BaselineConfigFile) -> Result<D2ComparisonSummary> {
    let digest = verify_d2_budget_equivalence(config)?;
    let group_results = config
        .groups
        .iter()
        .map(|group| configured_group_result(config, *group))
        .collect::<Result<Vec<_>>>()?;
    Ok(D2ComparisonSummary {
        schema_version: D2_COMPARISON_SCHEMA_V01.to_owned(),
        suite_id: config.suite_id.clone(),
        config_digest: digest.config_digest,
        groups: config.groups.clone(),
        group_results,
    })
}

pub fn comparison_summary_from_group_records(
    config: &D2BaselineConfigFile,
    group_records: &[D2GroupCampaignRecords],
) -> Result<D2ComparisonSummary> {
    let digest = verify_d2_budget_equivalence(config)?;
    let by_group = validate_group_record_set(config, group_records)?;
    let mut results = Vec::with_capacity(config.groups.len());
    for group in &config.groups {
        let records = by_group.get(group).ok_or_else(|| {
            ExperimentError::InvalidInput(format!(
                "missing D2 campaign records for group {}",
                group.as_str()
            ))
        })?;
        results.push(completed_group_result(config, records)?);
    }
    Ok(D2ComparisonSummary {
        schema_version: D2_COMPARISON_SCHEMA_V01.to_owned(),
        suite_id: config.suite_id.clone(),
        config_digest: digest.config_digest,
        groups: config.groups.clone(),
        group_results: results,
    })
}

pub fn comparison_summary_from_record_root(
    config: &D2BaselineConfigFile,
    records_root: impl AsRef<Path>,
) -> Result<D2ComparisonSummary> {
    let records_root = records_root.as_ref();
    let mut groups = Vec::with_capacity(config.groups.len());
    for group in &config.groups {
        let group_root = records_root.join(group.as_str());
        let records = read_campaign_records_jsonl(&group_root.join("campaign-records.jsonl"))?;
        let progress_state_coverage = read_progress_state_coverage(&group_root)?;
        groups.push(D2GroupCampaignRecords {
            group: *group,
            progress_state_coverage,
            records,
        });
    }
    comparison_summary_from_group_records(config, &groups)
}

pub fn format_d2_config_field(config: &D2BaselineConfigFile, field: &str) -> Result<String> {
    let output = match field {
        "shared_budget.cpu_minutes" => format!("{}\n", config.shared_budget.cpu_minutes),
        "shared_budget.seed_list" => {
            config
                .shared_budget
                .seed_list
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        }
        "coverage_only.target" => format!(
            "{}\n",
            config
                .coverage_only
                .as_ref()
                .ok_or_else(|| {
                    ExperimentError::InvalidInput("missing [coverage_only] group config".to_owned())
                })?
                .target
        ),
        "coverage_state.target" => format!(
            "{}\n",
            config
                .coverage_state
                .as_ref()
                .ok_or_else(|| {
                    ExperimentError::InvalidInput(
                        "missing [coverage_state] group config".to_owned(),
                    )
                })?
                .target
        ),
        other => {
            return Err(ExperimentError::InvalidInput(format!(
                "unsupported D2 config field: {other}"
            )));
        }
    };
    Ok(output)
}

#[must_use]
pub fn render_d2_summary_markdown(summary: &D2ComparisonSummary) -> String {
    let mut output = String::new();
    output.push_str("# BoundaryWitness D2 对照摘要\n\n");
    output.push_str("本摘要只描述 D2 小规模观察结果，不声明统计显著优势。\n\n");
    output.push_str("| group | status | primary_success_count | time_to_first_primary_ms | valid_sequence_ratio | minimized_sequence_len | progress_state_coverage | secondary_finding_count |\n");
    output.push_str("|---|---|---:|---:|---:|---:|---:|---:|\n");
    for result in &summary.group_results {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            result.group.as_str(),
            result.status,
            result.primary_success_count,
            optional_u64(result.time_to_first_primary_ms),
            optional_f64(result.valid_sequence_ratio),
            optional_usize(result.minimized_sequence_len),
            result.progress_state_coverage,
            result.secondary_finding_count
        ));
    }
    output.push('\n');
    output.push_str("| 字段 | 值 |\n");
    output.push_str("|---|---|\n");
    output.push_str(&format!("| suite_id | {} |\n", summary.suite_id));
    output.push_str(&format!("| config_digest | {} |\n", summary.config_digest));
    output
}

fn configured_group_result(
    config: &D2BaselineConfigFile,
    group: D2BaselineGroupKind,
) -> Result<D2GroupComparisonResult> {
    let baseline_id = match group {
        D2BaselineGroupKind::RandomAction => config.random_action.baseline_id.clone(),
        D2BaselineGroupKind::CoverageOnly => config
            .coverage_only
            .as_ref()
            .ok_or_else(|| {
                ExperimentError::InvalidInput("missing [coverage_only] group config".to_owned())
            })?
            .baseline_id
            .clone(),
        D2BaselineGroupKind::CoverageState => config
            .coverage_state
            .as_ref()
            .ok_or_else(|| {
                ExperimentError::InvalidInput("missing [coverage_state] group config".to_owned())
            })?
            .baseline_id
            .clone(),
    };
    Ok(D2GroupComparisonResult {
        group,
        baseline_id,
        status: "configured".to_owned(),
        campaign_count: config.shared_budget.campaign_count,
        cpu_minutes: config.shared_budget.cpu_minutes,
        seed_list: config.shared_budget.seed_list.clone(),
        primary_success_count: 0,
        time_to_first_primary_ms: None,
        valid_sequence_ratio: None,
        minimized_sequence_len: None,
        replay_success_count: None,
        progress_state_coverage: 0,
        secondary_finding_count: 0,
    })
}

fn completed_group_result(
    config: &D2BaselineConfigFile,
    group_records: &D2GroupCampaignRecords,
) -> Result<D2GroupComparisonResult> {
    let campaign_summary = summarize_d1_campaigns(&group_records.records)?;
    let (baseline_id, expected_target) = group_config_identity(config, group_records.group)?;
    Ok(D2GroupComparisonResult {
        group: group_records.group,
        baseline_id,
        status: "completed".to_owned(),
        campaign_count: campaign_summary.total_campaigns as u64,
        cpu_minutes: config.shared_budget.cpu_minutes,
        seed_list: seeds_for_records(&group_records.records),
        primary_success_count: campaign_summary.primary_success_campaigns as u64,
        time_to_first_primary_ms: campaign_summary
            .time_to_first_primary_ms
            .iter()
            .copied()
            .min(),
        valid_sequence_ratio: valid_sequence_ratio(&campaign_summary),
        minimized_sequence_len: group_records
            .records
            .iter()
            .filter_map(|record| record.minimized_len)
            .min(),
        replay_success_count: group_records
            .records
            .iter()
            .filter(|record| {
                record.outcome == D1CampaignOutcome::PrimaryFound || record.primary_count > 0
            })
            .filter_map(|record| record.replay_success_count)
            .reduce(|left, right| left.saturating_add(right)),
        progress_state_coverage: group_records.progress_state_coverage,
        secondary_finding_count: campaign_summary
            .campaigns
            .iter()
            .map(|record| record.secondary_count)
            .sum(),
    })
    .and_then(|result| {
        for record in &group_records.records {
            if record.target != expected_target {
                return Err(ExperimentError::InvalidInput(format!(
                    "D2 group {} record target {} does not match expected {}",
                    group_records.group.as_str(),
                    record.target,
                    expected_target
                )));
            }
        }
        Ok(result)
    })
}

fn validate_group_record_set<'a>(
    config: &D2BaselineConfigFile,
    group_records: &'a [D2GroupCampaignRecords],
) -> Result<BTreeMap<D2BaselineGroupKind, &'a D2GroupCampaignRecords>> {
    let mut by_group = BTreeMap::new();
    let configured: BTreeSet<_> = config.groups.iter().copied().collect();
    for records in group_records {
        if !configured.contains(&records.group) {
            return Err(ExperimentError::InvalidInput(format!(
                "D2 records include unconfigured group {}",
                records.group.as_str()
            )));
        }
        if by_group.insert(records.group, records).is_some() {
            return Err(ExperimentError::InvalidInput(format!(
                "duplicate D2 campaign records for group {}",
                records.group.as_str()
            )));
        }
        validate_group_records(config, records)?;
    }
    for group in &config.groups {
        if !by_group.contains_key(group) {
            return Err(ExperimentError::InvalidInput(format!(
                "missing D2 campaign records for group {}",
                group.as_str()
            )));
        }
    }
    Ok(by_group)
}

fn validate_group_records(
    config: &D2BaselineConfigFile,
    group_records: &D2GroupCampaignRecords,
) -> Result<()> {
    let (_, expected_target) = group_config_identity(config, group_records.group)?;
    if group_records.records.len() as u64 != config.shared_budget.campaign_count {
        return Err(ExperimentError::InvalidInput(format!(
            "D2 group {} campaign count mismatch: actual={} expected={}",
            group_records.group.as_str(),
            group_records.records.len(),
            config.shared_budget.campaign_count
        )));
    }
    for record in &group_records.records {
        if record.api != crate::ApiKind::UpdateHook {
            return Err(ExperimentError::InvalidInput(format!(
                "D2 group {} record api {:?} is not update_hook",
                group_records.group.as_str(),
                record.api
            )));
        }
        if record.target != expected_target {
            return Err(ExperimentError::InvalidInput(format!(
                "D2 group {} record target {} does not match expected {}",
                group_records.group.as_str(),
                record.target,
                expected_target
            )));
        }
        if record.cpu_minutes != config.shared_budget.cpu_minutes {
            return Err(ExperimentError::InvalidInput(format!(
                "D2 group {} record cpu_minutes {} does not match shared budget {}",
                group_records.group.as_str(),
                record.cpu_minutes,
                config.shared_budget.cpu_minutes
            )));
        }
        if !config.shared_budget.seed_list.contains(&record.seed) {
            return Err(ExperimentError::InvalidInput(format!(
                "D2 group {} record seed {} is not in shared seed_list",
                group_records.group.as_str(),
                record.seed
            )));
        }
    }
    Ok(())
}

fn group_config_identity(
    config: &D2BaselineConfigFile,
    group: D2BaselineGroupKind,
) -> Result<(String, String)> {
    match group {
        D2BaselineGroupKind::RandomAction => Ok((
            config.random_action.baseline_id.clone(),
            config.random_action.target.clone(),
        )),
        D2BaselineGroupKind::CoverageOnly => {
            let coverage = config.coverage_only.as_ref().ok_or_else(|| {
                ExperimentError::InvalidInput("missing [coverage_only] group config".to_owned())
            })?;
            Ok((coverage.baseline_id.clone(), coverage.target.clone()))
        }
        D2BaselineGroupKind::CoverageState => {
            let state = config.coverage_state.as_ref().ok_or_else(|| {
                ExperimentError::InvalidInput("missing [coverage_state] group config".to_owned())
            })?;
            Ok((state.baseline_id.clone(), state.target.clone()))
        }
    }
}

fn seeds_for_records(records: &[D1CampaignRecord]) -> Vec<u64> {
    records.iter().map(|record| record.seed).collect()
}

fn valid_sequence_ratio(summary: &D1CampaignSummary) -> Option<f64> {
    if summary.total_executions == 0 {
        None
    } else {
        Some(summary.valid_sequence_count as f64 / summary.total_executions as f64)
    }
}

fn read_campaign_records_jsonl(path: &Path) -> Result<Vec<D1CampaignRecord>> {
    let input = fs::read_to_string(path).map_err(|error| ExperimentError::io(path, error))?;
    let mut records = Vec::new();
    for (index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let input = serde_json::from_str::<D2CampaignRecordInput>(line).map_err(|error| {
            ExperimentError::InvalidInput(format!(
                "invalid D2 campaign record {}:{}: {error}",
                path.display(),
                index + 1
            ))
        })?;
        records.push(input.into_record());
    }
    Ok(records)
}

fn read_progress_state_coverage(group_root: &Path) -> Result<u64> {
    let path = group_root.join("progress-state-coverage.txt");
    if !path.exists() {
        return Ok(0);
    }
    let input = fs::read_to_string(&path).map_err(|error| ExperimentError::io(&path, error))?;
    let trimmed = input.trim();
    trimmed.parse::<u64>().map_err(|error| {
        ExperimentError::InvalidInput(format!(
            "invalid progress-state-coverage at {}: {error}",
            path.display()
        ))
    })
}

#[derive(Deserialize)]
struct D2CampaignRecordInput {
    campaign_id: String,
    api: crate::ApiKind,
    target: String,
    seed: u64,
    cpu_minutes: u64,
    executions: u64,
    valid_sequence_count: u64,
    invalid_sequence_count: u64,
    progress_count: u64,
    secondary_count: u64,
    primary_count: u64,
    time_to_first_primary_ms: Option<u64>,
    minimized_len: Option<usize>,
    replay_success_count: Option<usize>,
    representative_artifact_digest: Option<String>,
    outcome: D1CampaignOutcome,
}

impl D2CampaignRecordInput {
    fn into_record(self) -> D1CampaignRecord {
        D1CampaignRecord {
            campaign_id: self.campaign_id,
            api: self.api,
            target: self.target,
            seed: self.seed,
            cpu_minutes: self.cpu_minutes,
            executions: self.executions,
            valid_sequence_count: self.valid_sequence_count,
            invalid_sequence_count: self.invalid_sequence_count,
            progress_count: self.progress_count,
            secondary_count: self.secondary_count,
            primary_count: self.primary_count,
            time_to_first_primary_ms: self.time_to_first_primary_ms,
            minimized_len: self.minimized_len,
            replay_success_count: self.replay_success_count,
            representative_artifact_digest: self.representative_artifact_digest,
            outcome: self.outcome,
        }
    }
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "not_run".to_owned(), |value| value.to_string())
}

fn optional_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "not_run".to_owned(), |value| value.to_string())
}

fn optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "not_run".to_owned(), |value| format!("{value:.4}"))
}

fn require_equal<T>(field: &str, actual: T, expected: T) -> Result<()>
where
    T: Copy + Eq + std::fmt::Display,
{
    if actual != expected {
        return Err(ExperimentError::InvalidInput(format!(
            "{field} budget mismatch: actual={actual} expected={expected}"
        )));
    }
    Ok(())
}

fn require_str_equal(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        return Err(ExperimentError::InvalidInput(format!(
            "{field} budget mismatch: actual={actual} expected={expected}"
        )));
    }
    Ok(())
}

fn require_seed(field: &str, seed: u64, seed_list: &[u64]) -> Result<()> {
    if !seed_list.contains(&seed) {
        return Err(ExperimentError::InvalidInput(format!(
            "{field} seed mismatch: {seed} not in shared seed list"
        )));
    }
    Ok(())
}

fn config_digest(config: &D2BaselineConfigFile) -> Result<String> {
    #[derive(Serialize)]
    struct DigestMaterial<'a> {
        schema_version: &'a str,
        suite_id: &'a str,
        groups: &'a [D2BaselineGroupKind],
        shared_budget: &'a D2SharedBudget,
    }
    Ok(sha256_hex(&serde_json::to_vec(&DigestMaterial {
        schema_version: config.schema_version.as_str(),
        suite_id: config.suite_id.as_str(),
        groups: &config.groups,
        shared_budget: &config.shared_budget,
    })?))
}

impl D2BaselineGroupKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RandomAction => "random_action",
            Self::CoverageOnly => "coverage_only",
            Self::CoverageState => "coverage_state",
        }
    }
}
