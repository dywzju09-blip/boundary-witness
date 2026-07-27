use bw_blind_model::{BlindCaseId, BlindCommandSpec, BlindSplit};

pub const BLIND_GROUND_TRUTH_SCHEMA_V01: &str = "boundary-witness.blind-ground-truth/0.1";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruthRole {
    Violation,
    SafeControl,
    FixedControl,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TruthSource {
    pub suite_id: String,
    pub cases: Vec<PackSourceCase>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSourceCase {
    pub curator_key: String,
    pub split: BlindSplit,
    pub role: TruthRole,
    pub component: String,
    pub api: String,
    pub root_cause_key: String,
    pub paired_with: Vec<String>,
    pub source_revision: String,
    pub case_dir: String,
    pub public_command: BlindCommandSpec,
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindGroundTruth {
    pub schema_version: String,
    pub suite_id: String,
    pub split: BlindSplit,
    pub public_manifest_sha256: String,
    pub cases: Vec<BlindTruthCase>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindTruthCase {
    pub case_id: BlindCaseId,
    pub curator_key: String,
    pub role: TruthRole,
    pub component: String,
    pub api: String,
    pub root_cause_key: String,
    pub paired_case_ids: Vec<BlindCaseId>,
    pub source_revision: String,
}
