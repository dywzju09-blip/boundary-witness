use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{
    coverage_baseline::CoverageBaselineConfig,
    d2_compare::{D2BaselineGroupKind, D2SharedBudget},
    state_feedback::StateFeedbackConfig,
};
use crate::{
    ActionDecodeOptions, ActionSequence, ApiKind, D1ArtifactRecord, ExperimentError, FuzzAction,
    ObjectiveClassification, ObjectiveKind, Result, SeedProvenance, fuzz::artifact::sha256_hex,
};

pub const D2_BASELINES_SCHEMA_V01: &str = "boundary-witness.d2-baselines/0.1";
pub const D2_RANDOM_SUMMARY_SCHEMA_V01: &str = "boundary-witness.d2-random-summary/0.1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D2BaselineConfigFile {
    pub schema_version: String,
    pub suite_id: String,
    #[serde(default = "default_d2_groups")]
    pub groups: Vec<D2BaselineGroupKind>,
    #[serde(default)]
    pub shared_budget: D2SharedBudget,
    pub random_action: RandomBaselineConfig,
    pub coverage_only: Option<CoverageBaselineConfig>,
    pub coverage_state: Option<StateFeedbackConfig>,
}

impl D2BaselineConfigFile {
    pub fn parse_toml(input: &str) -> Result<Self> {
        let config = toml::from_str::<Self>(input).map_err(|error| {
            ExperimentError::InvalidInput(format!("invalid d2 baseline config toml: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|error| ExperimentError::io(path, error))?;
        Self::parse_toml(&input)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != D2_BASELINES_SCHEMA_V01 {
            return Err(ExperimentError::InvalidInput(format!(
                "unsupported d2 baseline schema_version: {}",
                self.schema_version
            )));
        }
        if self.suite_id.trim().is_empty() {
            return Err(ExperimentError::InvalidInput(
                "suite_id must not be empty".to_owned(),
            ));
        }
        if self.groups.is_empty() {
            return Err(ExperimentError::InvalidInput(
                "groups must not be empty".to_owned(),
            ));
        }
        self.shared_budget.validate()?;
        self.random_action.validate()?;
        if let Some(coverage_only) = &self.coverage_only {
            coverage_only.validate()?;
        }
        if let Some(coverage_state) = &self.coverage_state {
            coverage_state.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RandomBaselineConfig {
    pub baseline_id: String,
    pub api: ApiKind,
    pub target: String,
    pub cpu_minutes: u64,
    pub max_sequence_len: usize,
    pub execution_budget: u64,
    pub seed: u64,
    #[serde(default)]
    pub initial_corpus: Option<PathBuf>,
    pub artifact_dir: PathBuf,
    pub objective_config: PathBuf,
    #[serde(default)]
    pub sanitizer: Option<String>,
    pub replay_repeat_count: usize,
}

impl RandomBaselineConfig {
    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("baseline_id", self.baseline_id.as_str()),
            ("target", self.target.as_str()),
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
        if self.execution_budget == 0 {
            return Err(ExperimentError::InvalidInput(
                "execution_budget must be greater than zero".to_owned(),
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

fn default_d2_groups() -> Vec<D2BaselineGroupKind> {
    vec![D2BaselineGroupKind::RandomAction]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RandomBaselineKind {
    RandomAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RandomBaselineObservation {
    pub valid_sequence: bool,
    pub objective: ObjectiveClassification,
    pub replay_success_count: Option<usize>,
    pub feedback_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RandomBaselineSummary {
    pub schema_version: String,
    pub baseline_kind: RandomBaselineKind,
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
}

pub struct RandomBaselineRunner {
    config: RandomBaselineConfig,
}

impl RandomBaselineRunner {
    #[must_use]
    pub fn new(config: RandomBaselineConfig) -> Self {
        Self { config }
    }

    pub fn run(
        &self,
        mut evaluate: impl FnMut(&ActionSequence) -> RandomBaselineObservation,
    ) -> Result<RandomBaselineSummary> {
        fs::create_dir_all(&self.config.artifact_dir)
            .map_err(|error| ExperimentError::io(&self.config.artifact_dir, error))?;

        let mut generator = RandomActionGenerator::new(
            self.config.seed,
            self.config.api,
            self.config.max_sequence_len,
        );
        let mut valid_sequence_count = 0u64;
        let mut invalid_sequence_count = 0u64;
        let mut progress_count = 0u64;
        let mut secondary_count = 0u64;
        let mut primary_count = 0u64;
        let mut representative_artifact_digest = None;
        let mut representative_artifact_paths = Vec::new();
        let mut replay_success_count = None;
        let mut minimized_len = None;
        let mut feedback_keys = BTreeSet::new();

        for _ in 0..self.config.execution_budget {
            let generated = generator.next_generated();
            let observation = evaluate(&generated.sequence);
            if observation.valid_sequence {
                valid_sequence_count += 1;
            } else {
                invalid_sequence_count += 1;
            }
            if let Some(key) = observation.feedback_key
                && !key.is_empty()
            {
                feedback_keys.insert(key);
            }

            match observation.objective.objective_kind {
                ObjectiveKind::Primary => {
                    primary_count += 1;
                    minimized_len.get_or_insert(generated.sequence.actions.len());
                    replay_success_count = observation.replay_success_count;
                    if representative_artifact_digest.is_none() {
                        let artifact = D1ArtifactRecord::new(
                            self.config.baseline_id.clone(),
                            self.config.api,
                            &generated.raw_input,
                            generated.sequence,
                            observation.objective,
                        )?;
                        let path = self.config.artifact_dir.join(format!(
                            "{}-{}.json",
                            self.config.baseline_id, artifact.artifact_digest
                        ));
                        let output = serde_json::to_vec_pretty(&artifact)?;
                        fs::write(&path, output)
                            .map_err(|error| ExperimentError::io(&path, error))?;
                        representative_artifact_digest = Some(artifact.artifact_digest);
                        representative_artifact_paths.push(path);
                    }
                }
                ObjectiveKind::Progress => progress_count += 1,
                ObjectiveKind::Secondary => secondary_count += 1,
                ObjectiveKind::None => {}
            }
        }

        Ok(RandomBaselineSummary {
            schema_version: D2_RANDOM_SUMMARY_SCHEMA_V01.to_owned(),
            baseline_kind: RandomBaselineKind::RandomAction,
            baseline_id: self.config.baseline_id.clone(),
            api: self.config.api,
            target: self.config.target.clone(),
            seed: self.config.seed,
            cpu_minutes: self.config.cpu_minutes,
            executions: self.config.execution_budget,
            sequence_generation_count: self.config.execution_budget,
            valid_sequence_count,
            invalid_sequence_count,
            progress_count,
            secondary_count,
            primary_count,
            time_to_first_primary_ms: None,
            minimized_len,
            replay_success_count,
            feedback_snapshot_coverage_count: feedback_keys.len() as u64,
            representative_artifact_digest,
            representative_artifact_paths,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RandomActionGenerator {
    rng: SplitMix64,
    api: ApiKind,
    max_sequence_len: usize,
}

impl RandomActionGenerator {
    #[must_use]
    pub fn new(seed: u64, api: ApiKind, max_sequence_len: usize) -> Self {
        Self {
            rng: SplitMix64::new(seed),
            api,
            max_sequence_len: max_sequence_len.max(1),
        }
    }

    #[must_use]
    pub fn next_sequence(&mut self) -> ActionSequence {
        self.next_generated().sequence
    }

    fn next_generated(&mut self) -> GeneratedActionSequence {
        let max_bytes = self.max_sequence_len.saturating_mul(2).max(1);
        let byte_len = (self.rng.next_u64() as usize % max_bytes) + 1;
        let mut raw_input = Vec::with_capacity(byte_len);
        for _ in 0..byte_len {
            raw_input.push(self.rng.next_u64() as u8);
        }
        let mut sequence = ActionSequence::decode_bytes(
            &raw_input,
            ActionDecodeOptions {
                max_actions: self.max_sequence_len,
                source: "d2-random-action".to_owned(),
            },
        );
        normalize_api(&mut sequence, self.api);
        sequence.provenance = SeedProvenance::decoded_bytes(format!(
            "d2-random:{}:{}",
            self.api_tag(),
            sha256_hex(&raw_input)
        ));
        GeneratedActionSequence {
            raw_input,
            sequence,
        }
    }

    fn api_tag(&self) -> &'static str {
        match self.api {
            ApiKind::UpdateHook => "update_hook",
            ApiKind::CreateScalarFunction => "create_scalar_function",
        }
    }
}

#[derive(Clone, Debug)]
struct GeneratedActionSequence {
    raw_input: Vec<u8>,
    sequence: ActionSequence,
}

#[derive(Clone, Debug)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

fn normalize_api(sequence: &mut ActionSequence, api: ApiKind) {
    for action in &mut sequence.actions {
        match action {
            FuzzAction::RegisterBorrowed { api: action_api }
            | FuzzAction::RegisterOwned { api: action_api }
            | FuzzAction::Unregister { api: action_api } => {
                *action_api = api;
            }
            _ => {}
        }
    }
}
