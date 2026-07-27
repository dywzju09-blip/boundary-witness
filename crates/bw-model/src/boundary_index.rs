use std::{collections::BTreeSet, path::Path};

use serde::{Deserialize, Serialize};

use crate::{Located, ModelError, public_tokens::reject_public_forbidden_token};

pub const V3_2_BOUNDARY_INDEX_SCHEMA_V1: &str = "v3.2.boundary_index.1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32BoundaryIndexRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_boundary_index_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub crate_id: String,
    pub boundary_id: String,
    pub boundary_kind: V32BoundaryKind,
    pub api_path: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<V32BoundaryEvidenceRef>,
    pub confidence: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32BoundaryKind {
    NativeLibrary,
    CallbackRegistration,
    CallbackUnregistration,
    ForeignRetainedPointer,
    OpaqueHandleTransfer,
    ReturnedBorrow,
    ExternalBuffer,
    NegativeSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32BoundaryEvidenceRef {
    pub kind: V32BoundaryEvidenceKind,
    pub path: String,
    pub line_start: Option<u64>,
    pub line_end: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32BoundaryEvidenceKind {
    SourceSpan,
    Manifest,
    BuildLog,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V32BoundaryIndexSummary {
    pub record_count: u64,
    pub boundary_count: u64,
    pub negative_count: u64,
}

pub fn validate_v3_2_boundary_index<I>(records: I) -> Result<V32BoundaryIndexSummary, ModelError>
where
    I: IntoIterator<Item = Located<V32BoundaryIndexRecord>>,
{
    let mut summary = V32BoundaryIndexSummary::default();
    let mut run_id: Option<String> = None;
    let mut boundary_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text(&located, "run_id", &record.run_id)?;
        validate_required_text(&located, "crate_id", &record.crate_id)?;
        validate_required_text(&located, "boundary_id", &record.boundary_id)?;
        validate_required_text(&located, "confidence", &record.confidence)?;
        validate_confidence(&located, &record.confidence)?;
        reject_private_identity_tokens(&located, "run_id", &record.run_id)?;
        reject_private_identity_tokens(&located, "boundary_id", &record.boundary_id)?;
        reject_private_identity_tokens(&located, "crate_id", &record.crate_id)?;
        reject_private_identity_tokens(&located, "confidence", &record.confidence)?;
        if let Some(api_path) = &record.api_path {
            validate_required_text(&located, "api_path", api_path)?;
            reject_private_identity_tokens(&located, "api_path", api_path)?;
        }
        for note in &record.notes {
            reject_private_identity_tokens(&located, "notes", note)?;
        }

        if let Some(expected) = &run_id {
            if expected != &record.run_id {
                return Err(at(
                    &located,
                    "BW-BOUNDARY-RUN-MISMATCH",
                    format!(
                        "同一 boundary index 文件出现 run_id {expected} 和 {}",
                        record.run_id
                    ),
                ));
            }
        } else {
            run_id = Some(record.run_id.clone());
        }

        if !boundary_ids.insert(record.boundary_id.clone()) {
            return Err(at(
                &located,
                "BW-BOUNDARY-ID-DUPLICATE",
                format!("boundary_id {} 重复", record.boundary_id),
            ));
        }

        if record.evidence_refs.is_empty() {
            return Err(at(
                &located,
                "BW-BOUNDARY-EVIDENCE-EMPTY",
                "boundary index 记录必须包含至少一条 evidence_refs",
            ));
        }
        for evidence in &record.evidence_refs {
            validate_evidence_ref(&located, evidence)?;
        }

        match record.boundary_kind {
            V32BoundaryKind::NegativeSummary => {
                if record.api_path.is_some() {
                    return Err(at(
                        &located,
                        "BW-BOUNDARY-NEGATIVE-API-PATH",
                        "negative_summary 记录不能携带 api_path",
                    ));
                }
                summary.negative_count += 1;
            }
            _ => {
                let api_path = record.api_path.as_deref().unwrap_or_default();
                validate_required_text(&located, "api_path", api_path)?;
                summary.boundary_count += 1;
            }
        }

        summary.record_count += 1;
    }

    Ok(summary)
}

fn validate_required_text(
    located: &Located<V32BoundaryIndexRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at(
            located,
            "BW-BOUNDARY-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_confidence(
    located: &Located<V32BoundaryIndexRecord>,
    confidence: &str,
) -> Result<(), ModelError> {
    if !matches!(confidence, "high" | "medium" | "low") {
        return Err(at(
            located,
            "BW-BOUNDARY-CONFIDENCE",
            "confidence 必须是 high、medium 或 low",
        ));
    }
    Ok(())
}

fn validate_evidence_ref(
    located: &Located<V32BoundaryIndexRecord>,
    evidence: &V32BoundaryEvidenceRef,
) -> Result<(), ModelError> {
    validate_required_text(located, "evidence_refs.path", &evidence.path)?;
    validate_relative_ref(located, &evidence.path)?;
    reject_private_identity_tokens(located, "evidence_refs.path", &evidence.path)?;

    if evidence.kind == V32BoundaryEvidenceKind::SourceSpan {
        let Some(line_start) = evidence.line_start else {
            return Err(at(
                located,
                "BW-BOUNDARY-SOURCE-SPAN",
                "source_span evidence 必须包含 line_start",
            ));
        };
        let Some(line_end) = evidence.line_end else {
            return Err(at(
                located,
                "BW-BOUNDARY-SOURCE-SPAN",
                "source_span evidence 必须包含 line_end",
            ));
        };
        if line_start == 0 || line_end < line_start {
            return Err(at(
                located,
                "BW-BOUNDARY-SOURCE-SPAN",
                "source_span 行号必须从 1 开始，且 line_end 不能小于 line_start",
            ));
        }
    }

    Ok(())
}

fn validate_relative_ref(
    located: &Located<V32BoundaryIndexRecord>,
    value: &str,
) -> Result<(), ModelError> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(at(
            located,
            "BW-BOUNDARY-REF-PATH",
            "evidence path 必须是相对路径，不能是绝对路径或包含 ..",
        ));
    }
    Ok(())
}

fn reject_private_identity_tokens(
    located: &Located<V32BoundaryIndexRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_public_forbidden_token(field, value)
        .map_err(|message| at(located, "BW-BOUNDARY-PRIVATE-TOKEN", message))
}

fn at(
    located: &Located<V32BoundaryIndexRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, message).at_line(located.path.clone(), located.line)
}
