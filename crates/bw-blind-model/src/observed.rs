use std::{collections::BTreeSet, path::Path};

use crate::{
    BlindCaseId, BlindModelError, BlindSplit, Result,
    error::validation,
    public::{is_lower_hex, is_relative_slash_path, is_suite_id},
};

pub const BLIND_OBSERVED_SCHEMA_V01: &str = "boundary-witness.blind-observed/0.1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlindCaseStatus {
    Completed,
    BuildFailed,
    Unsupported,
    TimedOut,
    ToolError,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindObservedFinding {
    pub rule_id: String,
    pub classification: bw_model::FindingClassification,
    pub normalized_signature: String,
    pub evidence_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindWitnessEvidence {
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub replay_attempts: u32,
    pub replay_successes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindCaseObservation {
    pub schema_version: String,
    pub suite_id: String,
    pub split: BlindSplit,
    pub case_id: BlindCaseId,
    pub method_commit: String,
    pub public_manifest_sha256: String,
    pub status: BlindCaseStatus,
    pub findings: Vec<BlindObservedFinding>,
    pub witness: Option<BlindWitnessEvidence>,
}

impl BlindCaseObservation {
    pub fn parse_json(input: &str) -> Result<Self> {
        let observation: Self = serde_json::from_str(input)?;
        observation.validate(0)?;
        Ok(observation)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let input = std::fs::read_to_string(path).map_err(|source| BlindModelError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_json(&input)
    }

    pub fn validate(&self, minimum_replays: u32) -> Result<()> {
        if self.schema_version != BLIND_OBSERVED_SCHEMA_V01 {
            return Err(validation("unsupported blind observed schema_version"));
        }
        if !is_suite_id(&self.suite_id) {
            return Err(validation(
                "suite_id must use ASCII alphanumeric, '-', '_', or '.'",
            ));
        }
        BlindCaseId::parse(self.case_id.as_str())?;
        if !is_lower_hex(&self.method_commit, 40) {
            return Err(validation(
                "method_commit must be 40 lowercase hexadecimal characters",
            ));
        }
        if !is_lower_hex(&self.public_manifest_sha256, 64) {
            return Err(validation(
                "public_manifest_sha256 must be 64 lowercase hexadecimal characters",
            ));
        }
        if self.status != BlindCaseStatus::Completed {
            if !self.findings.is_empty() || self.witness.is_some() {
                return Err(validation(
                    "non-completed observations must not include findings or witness",
                ));
            }
            return Ok(());
        }

        let mut finding_keys = BTreeSet::new();
        let has_confirmed_violation = self.findings.iter().any(|finding| {
            finding.classification == bw_model::FindingClassification::ConfirmedViolation
        });
        for finding in &self.findings {
            if finding.rule_id.is_empty() {
                return Err(validation("finding rule_id must be non-empty"));
            }
            if !is_lower_hex(&finding.normalized_signature, 64) {
                return Err(validation(
                    "normalized_signature must be 64 lowercase hexadecimal characters",
                ));
            }
            if finding.classification == bw_model::FindingClassification::ConfirmedViolation
                && !finding.evidence_complete
            {
                return Err(validation("confirmed violations require complete evidence"));
            }
            if !finding_keys.insert((&finding.rule_id, &finding.normalized_signature)) {
                return Err(validation(
                    "finding rule_id and normalized_signature pairs must be unique",
                ));
            }
        }

        if has_confirmed_violation && self.witness.is_none() {
            return Err(validation("confirmed violations require a witness"));
        }
        if let Some(witness) = &self.witness {
            if !is_relative_slash_path(&witness.artifact_path) {
                return Err(validation(
                    "artifact_path must be a non-empty relative slash path",
                ));
            }
            if !is_lower_hex(&witness.artifact_sha256, 64) {
                return Err(validation(
                    "artifact_sha256 must be 64 lowercase hexadecimal characters",
                ));
            }
            if witness.replay_attempts < minimum_replays {
                return Err(validation(
                    "witness replay_attempts must meet minimum policy",
                ));
            }
            if witness.replay_successes != witness.replay_attempts {
                return Err(validation(
                    "witness replay_successes must equal replay_attempts",
                ));
            }
        }
        Ok(())
    }
}
