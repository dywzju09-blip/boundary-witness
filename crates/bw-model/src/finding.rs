use serde::{Deserialize, Serialize};

use crate::{
    BuildId, FINDING_SCHEMA_V01, InstanceId, ModelError, RecordId, RunId,
    schema::{deserialize_finding_schema, require_schema_version},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClassification {
    Exposure,
    ConfirmedViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    StaticFact,
    ContractClause,
    RuntimeEvent,
}

/// Finding 对可审计输入记录的机器可读引用。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    pub record_id: RecordId,
    pub source_kind: EvidenceSourceKind,
    pub description_code: String,
}

/// 违规事件前后的稳定生命周期状态摘要。
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingStateSnapshot {
    pub object_state: Option<String>,
    pub capture_state: Option<String>,
    pub callback_state: Option<String>,
    pub owner_state: Option<String>,
}

/// Oracle 产生的版本化、可规范化 finding。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    #[serde(deserialize_with = "deserialize_finding_schema")]
    pub schema_version: String,
    pub record_id: RecordId,
    pub rule_id: String,
    pub classification: FindingClassification,
    pub subject_object: Option<InstanceId>,
    pub subject_callback: Option<InstanceId>,
    pub first_violation_event: RecordId,
    pub evidence: Vec<EvidenceReference>,
    pub context_rule_ids: Vec<String>,
    pub state_before: FindingStateSnapshot,
    pub state_after: FindingStateSnapshot,
    pub normalized_signature: String,
    pub producer: String,
    pub build_id: BuildId,
    pub run_id: RunId,
    pub message: String,
}

impl Finding {
    /// 解析并精确校验 `bw.finding/0.1`。
    pub fn from_json_str(input: &str) -> Result<Self, ModelError> {
        require_schema_version(input, FINDING_SCHEMA_V01)?;
        Ok(serde_json::from_str(input)?)
    }
}
