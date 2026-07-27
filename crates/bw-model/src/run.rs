use serde::{Deserialize, Serialize};

use crate::{
    BuildId, ModelError, RUN_SCHEMA_V01, RunId,
    schema::{deserialize_run_schema, require_schema_version},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryOutcome {
    NoFinding,
    ContractFinding,
    Asan,
    NativeCrash,
    Panic,
    Timeout,
    InvalidInput,
    ToolError,
}

/// 可以同时成立的独立执行证据，不能被压缩为唯一 outcome。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidence {
    pub has_contract_finding: bool,
    pub has_asan_evidence: bool,
    pub has_native_crash: bool,
    pub has_panic: bool,
    pub has_timeout: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResult {
    pub primary_outcome: PrimaryOutcome,
    pub evidence: ExecutionEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainVersions {
    pub stable: String,
    pub compiler_nightly: Option<String>,
}

/// 一次实验运行的不可变身份和完成状态。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    #[serde(deserialize_with = "deserialize_run_schema")]
    pub schema_version: String,
    pub run_id: RunId,
    pub build_id: BuildId,
    pub git_commit: String,
    pub deployment_sha256: String,
    pub image_digest: String,
    pub config_digest: String,
    pub host: String,
    pub cpu_limit: Option<u32>,
    pub seed: Option<u64>,
    pub toolchains: ToolchainVersions,
    pub started_at_utc: String,
    pub completed_at_utc: Option<String>,
    pub execution: Option<ExecutionResult>,
}

impl RunManifest {
    /// 解析并精确校验 `bw.run/0.1`。
    pub fn from_json_str(input: &str) -> Result<Self, ModelError> {
        require_schema_version(input, RUN_SCHEMA_V01)?;
        Ok(serde_json::from_str(input)?)
    }
}
