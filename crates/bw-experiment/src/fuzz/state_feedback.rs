use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ApiKind, ExperimentError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFeedbackConfig {
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

impl StateFeedbackConfig {
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
        if !self.contract_state_feedback {
            return Err(ExperimentError::InvalidInput(
                "coverage_state baseline must enable contract_state_feedback".to_owned(),
            ));
        }
        Ok(())
    }
}
