use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{ApiKind, ExperimentError, Result};

pub const D1_CAMPAIGNS_SCHEMA_V01: &str = "boundary-witness.d1-campaigns/0.1";
pub const D1_SUMMARY_SCHEMA_V01: &str = "boundary-witness.d1-summary/0.1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1CampaignConfigFile {
    pub schema_version: String,
    pub suite_id: String,
    pub campaigns: Vec<D1CampaignConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1CampaignConfig {
    pub campaign_id: String,
    pub api: ApiKind,
    pub target: String,
    pub cpu_minutes: u64,
    pub max_sequence_len: usize,
    pub initial_corpus: PathBuf,
    pub artifact_dir: PathBuf,
    pub objective_config: PathBuf,
    pub sanitizer: String,
    pub replay_repeat_count: usize,
    pub seed: u64,
}

impl D1CampaignConfigFile {
    pub fn parse_toml(input: &str) -> Result<Self> {
        let config = toml::from_str::<Self>(input).map_err(|error| {
            ExperimentError::InvalidInput(format!("invalid d1 campaign config toml: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|error| ExperimentError::io(path, error))?;
        Self::parse_toml(&input)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != D1_CAMPAIGNS_SCHEMA_V01 {
            return Err(ExperimentError::InvalidInput(format!(
                "unsupported d1 campaign schema_version: {}",
                self.schema_version
            )));
        }
        if self.suite_id.trim().is_empty() {
            return Err(ExperimentError::InvalidInput(
                "suite_id must not be empty".to_owned(),
            ));
        }
        let mut campaign_ids = BTreeSet::new();
        let mut seeds = BTreeSet::new();
        for campaign in &self.campaigns {
            campaign.validate()?;
            if !campaign_ids.insert(campaign.campaign_id.clone()) {
                return Err(ExperimentError::InvalidInput(format!(
                    "duplicate campaign_id: {}",
                    campaign.campaign_id
                )));
            }
            if !seeds.insert(campaign.seed) {
                return Err(ExperimentError::InvalidInput(format!(
                    "duplicate campaign seed: {}",
                    campaign.seed
                )));
            }
        }
        Ok(())
    }
}

impl D1CampaignConfig {
    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("campaign_id", self.campaign_id.as_str()),
            ("target", self.target.as_str()),
            ("sanitizer", self.sanitizer.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ExperimentError::InvalidInput(format!(
                    "{field} must not be empty"
                )));
            }
        }
        if self.cpu_minutes == 0 {
            return Err(ExperimentError::InvalidInput(
                "cpu_minutes must be greater than zero".to_owned(),
            ));
        }
        if self.max_sequence_len == 0 {
            return Err(ExperimentError::InvalidInput(
                "max_sequence_len must be greater than zero".to_owned(),
            ));
        }
        if self.replay_repeat_count == 0 {
            return Err(ExperimentError::InvalidInput(
                "replay_repeat_count must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum D1CampaignOutcome {
    PrimaryFound,
    Timeout,
    NoPrimary,
    ToolError,
    CrashWithoutPrimary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1CampaignRecord {
    pub campaign_id: String,
    pub api: ApiKind,
    pub target: String,
    pub seed: u64,
    pub cpu_minutes: u64,
    pub executions: u64,
    pub valid_sequence_count: u64,
    pub invalid_sequence_count: u64,
    pub progress_count: u64,
    pub secondary_count: u64,
    pub primary_count: u64,
    pub time_to_first_primary_ms: Option<u64>,
    pub minimized_len: Option<usize>,
    pub replay_success_count: Option<usize>,
    pub representative_artifact_digest: Option<String>,
    pub outcome: D1CampaignOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1CampaignSummary {
    pub schema_version: String,
    pub total_campaigns: usize,
    pub primary_success_campaigns: usize,
    pub timeout_campaigns: usize,
    pub progress_campaigns: usize,
    pub secondary_campaigns: usize,
    pub total_executions: u64,
    pub valid_sequence_count: u64,
    pub invalid_sequence_count: u64,
    pub valid_sequence_ratio_ppm: u64,
    pub time_to_first_primary_ms: Vec<u64>,
    pub campaigns: Vec<D1CampaignRecord>,
}

pub fn summarize_d1_campaigns(records: &[D1CampaignRecord]) -> Result<D1CampaignSummary> {
    let mut campaign_ids = BTreeSet::new();
    let mut total_executions = 0u64;
    let mut valid_sequence_count = 0u64;
    let mut invalid_sequence_count = 0u64;
    let mut primary_success_campaigns = 0usize;
    let mut timeout_campaigns = 0usize;
    let mut progress_campaigns = 0usize;
    let mut secondary_campaigns = 0usize;
    let mut time_to_first_primary_ms = Vec::new();

    for record in records {
        validate_record(record)?;
        if !campaign_ids.insert(record.campaign_id.clone()) {
            return Err(ExperimentError::InvalidInput(format!(
                "duplicate campaign_id: {}",
                record.campaign_id
            )));
        }
        total_executions = total_executions.saturating_add(record.executions);
        valid_sequence_count = valid_sequence_count.saturating_add(record.valid_sequence_count);
        invalid_sequence_count =
            invalid_sequence_count.saturating_add(record.invalid_sequence_count);
        if record.outcome == D1CampaignOutcome::PrimaryFound || record.primary_count > 0 {
            primary_success_campaigns += 1;
        }
        if record.outcome == D1CampaignOutcome::Timeout {
            timeout_campaigns += 1;
        }
        if record.progress_count > 0 {
            progress_campaigns += 1;
        }
        if record.secondary_count > 0 {
            secondary_campaigns += 1;
        }
        if let Some(time) = record.time_to_first_primary_ms {
            time_to_first_primary_ms.push(time);
        }
    }

    let valid_sequence_ratio_ppm = valid_sequence_count
        .saturating_mul(1_000_000)
        .checked_div(total_executions)
        .unwrap_or(0);

    Ok(D1CampaignSummary {
        schema_version: D1_SUMMARY_SCHEMA_V01.to_owned(),
        total_campaigns: records.len(),
        primary_success_campaigns,
        timeout_campaigns,
        progress_campaigns,
        secondary_campaigns,
        total_executions,
        valid_sequence_count,
        invalid_sequence_count,
        valid_sequence_ratio_ppm,
        time_to_first_primary_ms,
        campaigns: records.to_vec(),
    })
}

fn validate_record(record: &D1CampaignRecord) -> Result<()> {
    for (field, value) in [
        ("campaign_id", record.campaign_id.as_str()),
        ("target", record.target.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(ExperimentError::InvalidInput(format!(
                "{field} must not be empty"
            )));
        }
    }
    if record.cpu_minutes == 0 {
        return Err(ExperimentError::InvalidInput(
            "cpu_minutes must be greater than zero".to_owned(),
        ));
    }
    if record.valid_sequence_count + record.invalid_sequence_count != record.executions {
        return Err(ExperimentError::InvalidInput(format!(
            "campaign {} valid+invalid sequence counts do not equal executions",
            record.campaign_id
        )));
    }
    if let Some(digest) = &record.representative_artifact_digest
        && (digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()))
    {
        return Err(ExperimentError::InvalidInput(format!(
            "campaign {} representative_artifact_digest must be sha256 hex",
            record.campaign_id
        )));
    }
    Ok(())
}
