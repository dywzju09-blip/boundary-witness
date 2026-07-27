use bw_model::{FindingClassification, FindingStateSnapshot};
use serde::{Deserialize, Serialize};

/// 排除运行身份后，用于跨构建和跨 replay 比较的 finding。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedFinding {
    pub rule_id: String,
    pub classification: FindingClassification,
    pub semantic_key: String,
    pub static_evidence_codes: Vec<String>,
    pub contract_clause_ids: Vec<String>,
    pub runtime_relation_codes: Vec<String>,
    pub context_rule_ids: Vec<String>,
    pub state_before: FindingStateSnapshot,
    pub state_after: FindingStateSnapshot,
    pub signature: String,
}
