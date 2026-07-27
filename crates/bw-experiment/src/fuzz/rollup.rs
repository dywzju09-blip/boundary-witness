use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{ExperimentError, Result};

pub const D1_ROLLUP_SCHEMA_V01: &str = "boundary-witness.d1-rollup-summary/0.1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1RollupSummary {
    pub schema_version: String,
    pub run_count: usize,
    pub campaign_count: usize,
    pub primary_success_campaigns: usize,
    pub primary_success_ratio_ppm: u64,
    pub timeout_campaigns: usize,
    pub tool_error_campaigns: usize,
    pub executions: u64,
    pub valid_sequence_count: u64,
    pub invalid_sequence_count: u64,
    pub valid_sequence_ratio_ppm: u64,
    pub progress_count: u64,
    pub secondary_count: u64,
    pub replay_success_count: u64,
    pub time_to_first_primary_ms: D1Distribution,
    pub minimized_len: D1Distribution,
    pub runs: Vec<D1RunRollup>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1Distribution {
    pub values: Vec<u64>,
    pub min: Option<u64>,
    pub median: Option<u64>,
    pub max: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1RunRollup {
    pub path: PathBuf,
    pub summary_schema_version: String,
    pub campaign_count: usize,
    pub primary_success_campaigns: usize,
}

#[derive(Default)]
struct Totals {
    campaign_count: usize,
    primary_success_campaigns: usize,
    timeout_campaigns: usize,
    tool_error_campaigns: usize,
    executions: u64,
    valid_sequence_count: u64,
    invalid_sequence_count: u64,
    progress_count: u64,
    secondary_count: u64,
    replay_success_count: u64,
    time_to_first_primary_ms: Vec<u64>,
    minimized_len: Vec<u64>,
}

pub fn summarize_d1_run_dirs(paths: &[PathBuf]) -> Result<D1RollupSummary> {
    if paths.is_empty() {
        return Err(ExperimentError::InvalidInput(
            "at least one D1 run directory is required".to_owned(),
        ));
    }

    let mut totals = Totals::default();
    let mut runs = Vec::new();
    for path in paths {
        let loaded = load_run_summary(path)?;
        totals.campaign_count += loaded.campaign_count;
        totals.primary_success_campaigns += loaded.primary_success_campaigns;
        totals.timeout_campaigns += loaded.timeout_campaigns;
        totals.tool_error_campaigns += loaded.tool_error_campaigns;
        totals.executions = totals.executions.saturating_add(loaded.executions);
        totals.valid_sequence_count = totals
            .valid_sequence_count
            .saturating_add(loaded.valid_sequence_count);
        totals.invalid_sequence_count = totals
            .invalid_sequence_count
            .saturating_add(loaded.invalid_sequence_count);
        totals.progress_count = totals.progress_count.saturating_add(loaded.progress_count);
        totals.secondary_count = totals
            .secondary_count
            .saturating_add(loaded.secondary_count);
        totals.replay_success_count = totals
            .replay_success_count
            .saturating_add(loaded.replay_success_count);
        totals
            .time_to_first_primary_ms
            .extend(loaded.time_to_first_primary_ms);
        totals.minimized_len.extend(loaded.minimized_len);
        runs.push(loaded.run);
    }

    Ok(D1RollupSummary {
        schema_version: D1_ROLLUP_SCHEMA_V01.to_owned(),
        run_count: runs.len(),
        campaign_count: totals.campaign_count,
        primary_success_campaigns: totals.primary_success_campaigns,
        primary_success_ratio_ppm: ratio_ppm(
            totals.primary_success_campaigns as u64,
            totals.campaign_count as u64,
        ),
        timeout_campaigns: totals.timeout_campaigns,
        tool_error_campaigns: totals.tool_error_campaigns,
        executions: totals.executions,
        valid_sequence_count: totals.valid_sequence_count,
        invalid_sequence_count: totals.invalid_sequence_count,
        valid_sequence_ratio_ppm: ratio_ppm(totals.valid_sequence_count, totals.executions),
        progress_count: totals.progress_count,
        secondary_count: totals.secondary_count,
        replay_success_count: totals.replay_success_count,
        time_to_first_primary_ms: D1Distribution::from_values(totals.time_to_first_primary_ms),
        minimized_len: D1Distribution::from_values(totals.minimized_len),
        runs,
    })
}

struct LoadedRunSummary {
    run: D1RunRollup,
    campaign_count: usize,
    primary_success_campaigns: usize,
    timeout_campaigns: usize,
    tool_error_campaigns: usize,
    executions: u64,
    valid_sequence_count: u64,
    invalid_sequence_count: u64,
    progress_count: u64,
    secondary_count: u64,
    replay_success_count: u64,
    time_to_first_primary_ms: Vec<u64>,
    minimized_len: Vec<u64>,
}

fn load_run_summary(path: &Path) -> Result<LoadedRunSummary> {
    let summary_path = path.join("summary.json");
    let input = fs::read_to_string(&summary_path)
        .map_err(|error| ExperimentError::io(&summary_path, error))?;
    let value: serde_json::Value = serde_json::from_str(&input)?;
    let schema = string_field(&value, "schema_version")?;
    let campaigns = value
        .get("campaigns")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ExperimentError::InvalidInput(format!(
                "{}: summary.campaigns must be an array",
                summary_path.display()
            ))
        })?;

    let mut loaded = LoadedRunSummary {
        run: D1RunRollup {
            path: path.to_path_buf(),
            summary_schema_version: schema.to_owned(),
            campaign_count: campaigns.len(),
            primary_success_campaigns: 0,
        },
        campaign_count: campaigns.len(),
        primary_success_campaigns: 0,
        timeout_campaigns: 0,
        tool_error_campaigns: 0,
        executions: 0,
        valid_sequence_count: 0,
        invalid_sequence_count: 0,
        progress_count: 0,
        secondary_count: 0,
        replay_success_count: 0,
        time_to_first_primary_ms: Vec::new(),
        minimized_len: Vec::new(),
    };

    for record in campaigns {
        let outcome = record
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        if outcome == "primary_found" {
            loaded.primary_success_campaigns += 1;
        }
        if outcome == "timeout" {
            loaded.timeout_campaigns += 1;
        }
        if outcome == "tool_error" {
            loaded.tool_error_campaigns += 1;
        }
        loaded.executions = loaded
            .executions
            .saturating_add(u64_field(record, "executions"));
        loaded.valid_sequence_count = loaded
            .valid_sequence_count
            .saturating_add(u64_field(record, "valid_sequence_count"));
        loaded.invalid_sequence_count = loaded
            .invalid_sequence_count
            .saturating_add(u64_field(record, "invalid_sequence_count"));
        loaded.progress_count = loaded
            .progress_count
            .saturating_add(u64_field(record, "progress_count"));
        loaded.secondary_count = loaded
            .secondary_count
            .saturating_add(u64_field(record, "secondary_count"));
        loaded.replay_success_count = loaded
            .replay_success_count
            .saturating_add(u64_field(record, "replay_success_count"));
        if let Some(value) = optional_u64_field(record, "time_to_first_primary_ms") {
            loaded.time_to_first_primary_ms.push(value);
        }
        if let Some(value) = optional_u64_field(record, "minimized_len") {
            loaded.minimized_len.push(value);
        }
    }
    loaded.run.primary_success_campaigns = loaded.primary_success_campaigns;
    Ok(loaded)
}

impl D1Distribution {
    fn from_values(mut values: Vec<u64>) -> Self {
        values.sort_unstable();
        let min = values.first().copied();
        let max = values.last().copied();
        let median = if values.is_empty() {
            None
        } else {
            Some(values[values.len() / 2])
        };
        Self {
            values,
            min,
            median,
            max,
        }
    }
}

fn string_field<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ExperimentError::InvalidInput(format!("{field} must be a string")))
}

fn u64_field(value: &serde_json::Value, field: &str) -> u64 {
    optional_u64_field(value, field).unwrap_or(0)
}

fn optional_u64_field(value: &serde_json::Value, field: &str) -> Option<u64> {
    value.get(field).and_then(serde_json::Value::as_u64)
}

fn ratio_ppm(numerator: u64, denominator: u64) -> u64 {
    numerator
        .saturating_mul(1_000_000)
        .checked_div(denominator)
        .unwrap_or(0)
}
