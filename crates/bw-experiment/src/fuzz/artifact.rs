use serde::{Deserialize, Serialize};

use crate::{
    ActionSequence, ApiKind, ExperimentError, ObjectiveClassification, ObjectiveKind, Result,
};

pub const D1_ARTIFACT_SCHEMA_V01: &str = "boundary-witness.d1-artifact/0.1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ArtifactRecord {
    pub schema_version: String,
    pub campaign_id: String,
    pub api: ApiKind,
    pub artifact_digest: String,
    pub raw_input_sha256: String,
    pub decoded_actions: ActionSequence,
    pub minimized_actions: Option<ActionSequence>,
    pub objective: ObjectiveClassification,
}

impl D1ArtifactRecord {
    pub fn new(
        campaign_id: impl Into<String>,
        api: ApiKind,
        raw_input: &[u8],
        decoded_actions: ActionSequence,
        objective: ObjectiveClassification,
    ) -> Result<Self> {
        decoded_actions.validate()?;
        if objective.objective_kind != ObjectiveKind::Primary {
            return Err(ExperimentError::InvalidInput(
                "d1 artifact requires a primary objective".to_owned(),
            ));
        }
        let campaign_id = campaign_id.into();
        if campaign_id.trim().is_empty() {
            return Err(ExperimentError::InvalidInput(
                "campaign_id must not be empty".to_owned(),
            ));
        }
        let raw_input_sha256 = sha256_hex(raw_input);
        let artifact_digest = artifact_digest(&campaign_id, api, &raw_input_sha256, &objective)?;
        Ok(Self {
            schema_version: D1_ARTIFACT_SCHEMA_V01.to_owned(),
            campaign_id,
            api,
            artifact_digest,
            raw_input_sha256,
            decoded_actions,
            minimized_actions: None,
            objective,
        })
    }

    pub fn from_json_str(input: &str) -> Result<Self> {
        let artifact = serde_json::from_str::<Self>(input)?;
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != D1_ARTIFACT_SCHEMA_V01 {
            return Err(ExperimentError::InvalidInput(format!(
                "unsupported d1 artifact schema_version: {}",
                self.schema_version
            )));
        }
        if self.artifact_digest.len() != 64 || !self.artifact_digest.is_ascii() {
            return Err(ExperimentError::InvalidInput(
                "artifact_digest must be a sha256 hex digest".to_owned(),
            ));
        }
        if self.raw_input_sha256.len() != 64 || !self.raw_input_sha256.is_ascii() {
            return Err(ExperimentError::InvalidInput(
                "raw_input_sha256 must be a sha256 hex digest".to_owned(),
            ));
        }
        self.decoded_actions.validate()?;
        if let Some(minimized) = &self.minimized_actions {
            minimized.validate()?;
        }
        Ok(())
    }
}

fn artifact_digest(
    campaign_id: &str,
    api: ApiKind,
    raw_input_sha256: &str,
    objective: &ObjectiveClassification,
) -> Result<String> {
    #[derive(Serialize)]
    struct DigestMaterial<'a> {
        campaign_id: &'a str,
        api: ApiKind,
        raw_input_sha256: &'a str,
        primary_rule_id: &'a Option<String>,
        normalized_signature: &'a Option<String>,
    }

    let material = DigestMaterial {
        campaign_id,
        api,
        raw_input_sha256,
        primary_rule_id: &objective.primary_rule_id,
        normalized_signature: &objective.normalized_signature,
    };
    Ok(sha256_hex(&serde_json::to_vec(&material)?))
}

pub(crate) fn sha256_hex(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
