use std::{collections::BTreeSet, path::Path};

use serde::{Deserialize, Serialize};

use crate::{Located, ModelError, public_tokens::reject_public_forbidden_token};

pub const V3_2_BUILDABILITY_SCHEMA_V1: &str = "v3.2.buildability.1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32BuildabilityRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_buildability_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub crate_id: String,
    pub status: V32BuildabilityStatus,
    pub toolchain: String,
    pub target: String,
    #[serde(default)]
    pub native_dependencies: Vec<String>,
    pub elapsed_ms: u64,
    pub log_ref: String,
    pub failure_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_status: Option<V32BuildabilityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_failure_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_status: Option<V32BuildabilityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_failure_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_rustflags: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32BuildabilityStatus {
    Buildable,
    NotBuildable,
    RequiresSystemDependency,
    UnsupportedTarget,
    Timeout,
    ToolError,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V32BuildabilitySummary {
    pub record_count: u64,
    pub buildable_count: u64,
    pub failed_count: u64,
}

pub fn validate_v3_2_buildability<I>(records: I) -> Result<V32BuildabilitySummary, ModelError>
where
    I: IntoIterator<Item = Located<V32BuildabilityRecord>>,
{
    let mut summary = V32BuildabilitySummary::default();
    let mut run_id: Option<String> = None;
    let mut crate_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text(&located, "run_id", &record.run_id)?;
        validate_required_text(&located, "crate_id", &record.crate_id)?;
        validate_required_text(&located, "toolchain", &record.toolchain)?;
        validate_required_text(&located, "target", &record.target)?;
        validate_required_text(&located, "log_ref", &record.log_ref)?;
        validate_log_ref(&located, &record.log_ref)?;
        reject_private_tokens(&located, "run_id", &record.run_id)?;
        reject_private_tokens(&located, "crate_id", &record.crate_id)?;
        reject_private_tokens(&located, "toolchain", &record.toolchain)?;
        reject_private_tokens(&located, "target", &record.target)?;
        reject_private_tokens(&located, "log_ref", &record.log_ref)?;
        reject_optional_private_tokens(
            &located,
            "original_failure_class",
            record.original_failure_class.as_deref(),
        )?;
        reject_optional_private_tokens(
            &located,
            "fallback_failure_class",
            record.fallback_failure_class.as_deref(),
        )?;
        reject_optional_private_tokens(
            &located,
            "fallback_rustflags",
            record.fallback_rustflags.as_deref(),
        )?;
        for dependency in &record.native_dependencies {
            reject_private_tokens(&located, "native_dependencies", dependency)?;
        }
        if record
            .original_failure_class
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(at(
                &located,
                "BW-BUILDABILITY-ORIGINAL-FAILURE-CLASS-EMPTY",
                "original_failure_class 不能为空",
            ));
        }
        if record
            .fallback_failure_class
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(at(
                &located,
                "BW-BUILDABILITY-FALLBACK-FAILURE-CLASS-EMPTY",
                "fallback_failure_class 不能为空",
            ));
        }
        if record
            .fallback_rustflags
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(at(
                &located,
                "BW-BUILDABILITY-FALLBACK-RUSTFLAGS-EMPTY",
                "fallback_rustflags 不能为空",
            ));
        }
        if record.fallback_status.is_some() && record.fallback_rustflags.is_none() {
            return Err(at(
                &located,
                "BW-BUILDABILITY-FALLBACK-RUSTFLAGS-MISSING",
                "fallback_status 存在时必须记录 fallback_rustflags",
            ));
        }
        if record.fallback_status.is_none() && record.fallback_rustflags.is_some() {
            return Err(at(
                &located,
                "BW-BUILDABILITY-FALLBACK-STATUS-MISSING",
                "fallback_rustflags 存在时必须记录 fallback_status",
            ));
        }

        if let Some(expected) = &run_id {
            if expected != &record.run_id {
                return Err(at(
                    &located,
                    "BW-BUILDABILITY-RUN-MISMATCH",
                    format!(
                        "同一 buildability 文件出现 run_id {expected} 和 {}",
                        record.run_id
                    ),
                ));
            }
        } else {
            run_id = Some(record.run_id.clone());
        }

        if !crate_ids.insert(record.crate_id.clone()) {
            return Err(at(
                &located,
                "BW-BUILDABILITY-CRATE-DUPLICATE",
                format!("crate_id {} 重复", record.crate_id),
            ));
        }

        match record.status {
            V32BuildabilityStatus::Buildable => {
                if record.failure_class.is_some() {
                    return Err(at(
                        &located,
                        "BW-BUILDABILITY-BUILDABLE-HAS-FAILURE",
                        "buildable 记录不能携带 failure_class",
                    ));
                }
                summary.buildable_count += 1;
            }
            _ => {
                let failure = record.failure_class.as_deref().unwrap_or_default();
                validate_required_text(&located, "failure_class", failure)?;
                reject_private_tokens(&located, "failure_class", failure)?;
                summary.failed_count += 1;
            }
        }

        summary.record_count += 1;
    }

    Ok(summary)
}

fn validate_required_text(
    located: &Located<V32BuildabilityRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at(
            located,
            "BW-BUILDABILITY-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_log_ref(
    located: &Located<V32BuildabilityRecord>,
    log_ref: &str,
) -> Result<(), ModelError> {
    let path = Path::new(log_ref);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(at(
            located,
            "BW-BUILDABILITY-LOG-REF",
            "log_ref 必须是 run/logs 根目录下的相对路径，不能是绝对路径或包含 ..",
        ));
    }
    Ok(())
}

fn reject_private_tokens(
    located: &Located<V32BuildabilityRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_public_forbidden_token(field, value)
        .map_err(|message| at(located, "BW-BUILDABILITY-PRIVATE-TOKEN", message))
}

fn reject_optional_private_tokens(
    located: &Located<V32BuildabilityRecord>,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ModelError> {
    if let Some(value) = value {
        reject_private_tokens(located, field, value)?;
    }
    Ok(())
}

fn at(
    located: &Located<V32BuildabilityRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, message).at_line(located.path.clone(), located.line)
}
