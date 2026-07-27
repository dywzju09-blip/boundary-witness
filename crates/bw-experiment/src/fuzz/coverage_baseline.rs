use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    ApiKind, D1CampaignOutcome, D1CampaignRecord, ExperimentError, ObjectiveClassification,
    ObjectiveKind, Result,
};

pub const D2_COVERAGE_SUMMARY_SCHEMA_V01: &str = "boundary-witness.d2-coverage-summary/0.1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageBaselineConfig {
    pub baseline_id: String,
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
    pub contract_state_feedback: bool,
}

impl CoverageBaselineConfig {
    pub fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("baseline_id", self.baseline_id.as_str()),
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
        if self.contract_state_feedback {
            return Err(ExperimentError::InvalidInput(
                "coverage_only baseline must not enable contract_state_feedback".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageBaselineKind {
    CoverageOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageBaselineSummary {
    pub schema_version: String,
    pub baseline_kind: CoverageBaselineKind,
    pub baseline_id: String,
    pub api: ApiKind,
    pub target: String,
    pub seed: u64,
    pub cpu_minutes: u64,
    pub executions: u64,
    pub sequence_generation_count: u64,
    pub valid_sequence_count: u64,
    pub invalid_sequence_count: u64,
    pub progress_count: u64,
    pub secondary_count: u64,
    pub primary_count: u64,
    pub time_to_first_primary_ms: Option<u64>,
    pub minimized_len: Option<usize>,
    pub replay_success_count: Option<usize>,
    pub feedback_snapshot_coverage_count: u64,
    pub representative_artifact_digest: Option<String>,
    pub representative_artifact_paths: Vec<PathBuf>,
    pub outcome: D1CampaignOutcome,
}

pub struct CoverageBaselineRunner {
    config: CoverageBaselineConfig,
}

impl CoverageBaselineRunner {
    #[must_use]
    pub fn new(config: CoverageBaselineConfig) -> Self {
        Self { config }
    }

    pub fn summarize_record(&self, record: D1CampaignRecord) -> Result<CoverageBaselineSummary> {
        self.config.validate()?;
        if record.api != self.config.api {
            return Err(ExperimentError::InvalidInput(format!(
                "coverage record api {:?} does not match config {:?}",
                record.api, self.config.api
            )));
        }
        if record.target != self.config.target {
            return Err(ExperimentError::InvalidInput(format!(
                "coverage record target {} does not match config {}",
                record.target, self.config.target
            )));
        }
        if record.cpu_minutes != self.config.cpu_minutes {
            return Err(ExperimentError::InvalidInput(format!(
                "coverage record cpu_minutes {} does not match config {}",
                record.cpu_minutes, self.config.cpu_minutes
            )));
        }
        if record.valid_sequence_count + record.invalid_sequence_count != record.executions {
            return Err(ExperimentError::InvalidInput(
                "coverage record valid+invalid counts do not match executions".to_owned(),
            ));
        }
        Ok(CoverageBaselineSummary {
            schema_version: D2_COVERAGE_SUMMARY_SCHEMA_V01.to_owned(),
            baseline_kind: CoverageBaselineKind::CoverageOnly,
            baseline_id: self.config.baseline_id.clone(),
            api: record.api,
            target: record.target,
            seed: record.seed,
            cpu_minutes: record.cpu_minutes,
            executions: record.executions,
            sequence_generation_count: record.executions,
            valid_sequence_count: record.valid_sequence_count,
            invalid_sequence_count: record.invalid_sequence_count,
            progress_count: record.progress_count,
            secondary_count: record.secondary_count,
            primary_count: record.primary_count,
            time_to_first_primary_ms: record.time_to_first_primary_ms,
            minimized_len: record.minimized_len,
            replay_success_count: record.replay_success_count,
            feedback_snapshot_coverage_count: 0,
            representative_artifact_digest: record.representative_artifact_digest.clone(),
            representative_artifact_paths: record
                .representative_artifact_digest
                .map(|digest| self.config.artifact_dir.join(format!("{digest}.json")))
                .into_iter()
                .collect(),
            outcome: record.outcome,
        })
    }
}

#[must_use]
pub fn coverage_only_saves_primary_artifact(classification: &ObjectiveClassification) -> bool {
    classification.objective_kind == ObjectiveKind::Primary
}
