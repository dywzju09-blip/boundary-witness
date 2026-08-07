use serde::{Deserialize, Deserializer};

use crate::ModelError;

pub const STATIC_SCHEMA_V01: &str = "bw.static/0.1";
pub const STATIC_SCHEMA_V02: &str = "bw.static/0.2";
pub const TRACE_SCHEMA_V01: &str = "bw.trace/0.1";
pub const CONTRACT_SCHEMA_V01: &str = "bw.contract/0.1";
pub const FINDING_SCHEMA_V01: &str = "bw.finding/0.1";
pub const RUN_SCHEMA_V01: &str = "bw.run/0.1";

// ---------------------------------------------------------------------------
// 跨界回调持有期关系链（执行计划阶段 1.4 / 3 / 4）
// ---------------------------------------------------------------------------
//
// **协议身份集中登记在这里。** 这四个常量原本散在三个 CLI 文件里各写一份；同一个协议
// 版本号在多处定义，早晚会出现产物写 A、消费方认 B 的情况。
//
// 与 `v3.2.x` 那一族不同，`bw.*` 记录**不出 JSON Schema 文件**：约束由严格反序列化
// 承担（`deny_unknown_fields` + 类型化枚举 + 必填字段）。这与 `bw.static/0.2` 一致。
// 因此这次升版**没有新增 schema 目录**，符合 codebase-realignment 的 D2 复核判据。

/// Rust 侧契约事实。
pub const RUST_CONTRACT_SCHEMA_V01: &str = "bw.rust-contract/0.1";
/// 外部侧行为事实。
pub const FOREIGN_BEHAVIOR_SCHEMA_V01: &str = "bw.foreign-behavior/0.1";
/// 外部符号与参数角色映射。**只声明绑定，不声明行为。**
pub const FOREIGN_ROLE_MAP_SCHEMA_V01: &str = "bw.foreign-role-map/0.1";
/// 两侧联结之后的三态判定。
pub const JOINT_VERDICT_SCHEMA_V01: &str = "bw.joint-verdict/0.1";

#[derive(Deserialize)]
struct SchemaHeader {
    schema_version: String,
}

pub(crate) fn require_schema_version(
    input: &str,
    expected: &'static str,
) -> Result<(), ModelError> {
    let header: SchemaHeader = serde_json::from_str(input)?;
    if header.schema_version == expected {
        Ok(())
    } else {
        Err(ModelError::UnsupportedSchema {
            expected,
            found: header.schema_version,
        })
    }
}

pub(crate) fn require_static_schema_version(input: &str) -> Result<(), ModelError> {
    let header: SchemaHeader = serde_json::from_str(input)?;
    if matches!(
        header.schema_version.as_str(),
        STATIC_SCHEMA_V01 | STATIC_SCHEMA_V02
    ) {
        Ok(())
    } else {
        Err(ModelError::UnsupportedSchema {
            expected: "bw.static/0.1 or bw.static/0.2",
            found: header.schema_version,
        })
    }
}

pub(crate) fn require_toml_schema_version(
    input: &str,
    expected: &'static str,
) -> Result<(), ModelError> {
    let header: SchemaHeader = toml::from_str(input)?;
    if header.schema_version == expected {
        Ok(())
    } else {
        Err(ModelError::UnsupportedSchema {
            expected,
            found: header.schema_version,
        })
    }
}

fn deserialize_exact_schema<'de, D>(
    deserializer: D,
    expected: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let version = String::deserialize(deserializer)?;
    if version == expected {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(format_args!(
            "不支持 schema {version}，当前要求 {expected}"
        )))
    }
}

pub(crate) fn deserialize_static_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let version = String::deserialize(deserializer)?;
    if matches!(version.as_str(), STATIC_SCHEMA_V01 | STATIC_SCHEMA_V02) {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(format_args!(
            "不支持 schema {version}，当前要求 bw.static/0.1 或 bw.static/0.2"
        )))
    }
}

pub(crate) fn deserialize_trace_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, TRACE_SCHEMA_V01)
}

pub(crate) fn deserialize_contract_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, CONTRACT_SCHEMA_V01)
}

pub(crate) fn deserialize_finding_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, FINDING_SCHEMA_V01)
}

pub(crate) fn deserialize_run_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, RUN_SCHEMA_V01)
}

pub(crate) fn deserialize_v3_2_corpus_manifest_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_CORPUS_MANIFEST_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_buildability_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_BUILDABILITY_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_boundary_index_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_BOUNDARY_INDEX_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_candidate_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_CANDIDATE_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_lifecycle_graph_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_LIFECYCLE_GRAPH_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_ranked_candidate_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_RANKED_CANDIDATE_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_adapter_effort_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_ADAPTER_EFFORT_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_failure_taxonomy_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_FAILURE_TAXONOMY_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_5_private_ground_truth_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_5_PRIVATE_GROUND_TRUTH_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_6_lifecycle_evidence_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_LIFECYCLE_EVIDENCE_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_6_lifecycle_fact_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_LIFECYCLE_FACT_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_6_lifecycle_coverage_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_LIFECYCLE_COVERAGE_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_6_lifecycle_feature_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_LIFECYCLE_FEATURE_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_6_lifecycle_graph_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_LIFECYCLE_GRAPH_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_6_lifecycle_graph_v3_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_LIFECYCLE_GRAPH_V3_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_6_ranked_candidate_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_RANKED_CANDIDATE_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_6_anonymous_pair_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_ANONYMOUS_PAIR_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_pair_delta_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let version = String::deserialize(deserializer)?;
    if matches!(
        version.as_str(),
        crate::V3_2_6_PAIR_DELTA_SCHEMA_V1 | crate::V3_2_7_PAIR_DELTA_SCHEMA_V1
    ) {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(format_args!(
            "不支持 pair delta schema {version}"
        )))
    }
}

pub(crate) fn deserialize_v3_2_6_lifecycle_contract_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_LIFECYCLE_CONTRACT_SCHEMA_V1)
}

pub(crate) fn deserialize_v3_2_6_witness_plan_schema<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_schema(deserializer, crate::V3_2_6_WITNESS_PLAN_SCHEMA_V1)
}
