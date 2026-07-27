use std::{collections::BTreeSet, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    Located, ModelError, V32BoundaryEvidenceKind, V32BoundaryEvidenceRef, V32BoundaryIndexRecord,
    V32BoundaryKind, public_tokens::reject_public_forbidden_token,
};

pub const V3_2_CANDIDATE_SCHEMA_V1: &str = "v3.2.candidate.1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32CandidateRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_candidate_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub candidate_id: String,
    pub crate_id: String,
    pub boundary_id: String,
    pub pattern_family: V32PatternFamily,
    pub confidence: V32CandidateConfidence,
    #[serde(default)]
    pub evidence_refs: Vec<V32BoundaryEvidenceRef>,
    pub api_path: Option<String>,
    pub recommended_next_step: V32RecommendedNextStep,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32PatternFamily {
    RetainedBorrowedCallback,
    CallbackLifecycleRelease,
    ForeignRetainedPointer,
    OpaqueHandleTransfer,
    NativeLibraryBoundary,
    ReturnedBorrowView,
    ExternalBufferView,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32CandidateConfidence {
    NeedsDynamicValidation,
    StaticOnly,
    LowPriority,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32RecommendedNextStep {
    GenerateLifecycleSubgraph,
    ManualReview,
    Defer,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V32CandidateSummary {
    pub record_count: u64,
    pub needs_dynamic_validation_count: u64,
    pub static_only_count: u64,
    pub low_priority_count: u64,
}

pub fn candidate_from_boundary(
    boundary: &V32BoundaryIndexRecord,
    run_id: &str,
) -> Option<V32CandidateRecord> {
    let pattern_family = pattern_family_from_boundary(boundary.boundary_kind)?;
    let confidence = confidence_from_boundary(boundary.boundary_kind, &boundary.confidence);
    let recommended_next_step = recommended_next_step_from_confidence(confidence);
    Some(V32CandidateRecord {
        schema_version: V3_2_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: run_id.to_owned(),
        candidate_id: candidate_id_from_boundary_id(&boundary.boundary_id),
        crate_id: boundary.crate_id.clone(),
        boundary_id: boundary.boundary_id.clone(),
        pattern_family,
        confidence,
        evidence_refs: boundary.evidence_refs.clone(),
        api_path: boundary.api_path.clone(),
        recommended_next_step,
        notes: vec![
            "candidate is not a vulnerability conclusion".to_owned(),
            format!(
                "source_boundary_kind={}",
                boundary_kind_slug(boundary.boundary_kind)
            ),
        ],
    })
}

pub fn validate_v3_2_candidates<I>(records: I) -> Result<V32CandidateSummary, ModelError>
where
    I: IntoIterator<Item = Located<V32CandidateRecord>>,
{
    let mut summary = V32CandidateSummary::default();
    let mut run_id: Option<String> = None;
    let mut candidate_ids = BTreeSet::<String>::new();
    let mut boundary_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text(&located, "run_id", &record.run_id)?;
        validate_required_text(&located, "candidate_id", &record.candidate_id)?;
        validate_required_text(&located, "crate_id", &record.crate_id)?;
        validate_required_text(&located, "boundary_id", &record.boundary_id)?;
        reject_private_identity_tokens(&located, "run_id", &record.run_id)?;
        reject_private_identity_tokens(&located, "candidate_id", &record.candidate_id)?;
        reject_private_identity_tokens(&located, "crate_id", &record.crate_id)?;
        reject_private_identity_tokens(&located, "boundary_id", &record.boundary_id)?;
        if let Some(api_path) = &record.api_path {
            validate_required_text(&located, "api_path", api_path)?;
            reject_private_identity_tokens(&located, "api_path", api_path)?;
        } else {
            return Err(at(
                &located,
                "BW-CANDIDATE-API-PATH",
                "candidate 记录必须包含 api_path",
            ));
        }
        for note in &record.notes {
            reject_private_identity_tokens(&located, "notes", note)?;
        }

        if let Some(expected) = &run_id {
            if expected != &record.run_id {
                return Err(at(
                    &located,
                    "BW-CANDIDATE-RUN-MISMATCH",
                    format!(
                        "同一 candidate 分片出现 run_id {expected} 和 {}",
                        record.run_id
                    ),
                ));
            }
        } else {
            run_id = Some(record.run_id.clone());
        }

        if !candidate_ids.insert(record.candidate_id.clone()) {
            return Err(at(
                &located,
                "BW-CANDIDATE-ID-DUPLICATE",
                format!("candidate_id {} 重复", record.candidate_id),
            ));
        }
        if !boundary_ids.insert(record.boundary_id.clone()) {
            return Err(at(
                &located,
                "BW-CANDIDATE-BOUNDARY-DUPLICATE",
                format!("boundary_id {} 被多个 candidate 复用", record.boundary_id),
            ));
        }

        if record.evidence_refs.is_empty() {
            return Err(at(
                &located,
                "BW-CANDIDATE-EVIDENCE-EMPTY",
                "candidate 记录必须包含至少一条 evidence_refs",
            ));
        }
        for evidence in &record.evidence_refs {
            validate_evidence_ref(&located, evidence)?;
        }

        match record.confidence {
            V32CandidateConfidence::NeedsDynamicValidation => {
                summary.needs_dynamic_validation_count += 1;
            }
            V32CandidateConfidence::StaticOnly => summary.static_only_count += 1,
            V32CandidateConfidence::LowPriority => summary.low_priority_count += 1,
        }
        summary.record_count += 1;
    }

    Ok(summary)
}

fn pattern_family_from_boundary(kind: V32BoundaryKind) -> Option<V32PatternFamily> {
    match kind {
        V32BoundaryKind::CallbackRegistration => Some(V32PatternFamily::RetainedBorrowedCallback),
        V32BoundaryKind::CallbackUnregistration => Some(V32PatternFamily::CallbackLifecycleRelease),
        V32BoundaryKind::ForeignRetainedPointer => Some(V32PatternFamily::ForeignRetainedPointer),
        V32BoundaryKind::OpaqueHandleTransfer => Some(V32PatternFamily::OpaqueHandleTransfer),
        V32BoundaryKind::NativeLibrary => Some(V32PatternFamily::NativeLibraryBoundary),
        V32BoundaryKind::ReturnedBorrow => Some(V32PatternFamily::ReturnedBorrowView),
        V32BoundaryKind::ExternalBuffer => Some(V32PatternFamily::ExternalBufferView),
        V32BoundaryKind::NegativeSummary => None,
    }
}

fn confidence_from_boundary(
    kind: V32BoundaryKind,
    boundary_confidence: &str,
) -> V32CandidateConfidence {
    match kind {
        V32BoundaryKind::NativeLibrary => {
            if boundary_confidence == "low" {
                V32CandidateConfidence::LowPriority
            } else {
                V32CandidateConfidence::StaticOnly
            }
        }
        V32BoundaryKind::CallbackRegistration
        | V32BoundaryKind::CallbackUnregistration
        | V32BoundaryKind::ForeignRetainedPointer
        | V32BoundaryKind::OpaqueHandleTransfer => {
            if boundary_confidence == "low" {
                V32CandidateConfidence::LowPriority
            } else {
                V32CandidateConfidence::NeedsDynamicValidation
            }
        }
        V32BoundaryKind::ReturnedBorrow | V32BoundaryKind::ExternalBuffer => {
            if boundary_confidence == "low" {
                V32CandidateConfidence::LowPriority
            } else {
                V32CandidateConfidence::StaticOnly
            }
        }
        V32BoundaryKind::NegativeSummary => V32CandidateConfidence::LowPriority,
    }
}

fn recommended_next_step_from_confidence(
    confidence: V32CandidateConfidence,
) -> V32RecommendedNextStep {
    match confidence {
        V32CandidateConfidence::NeedsDynamicValidation => {
            V32RecommendedNextStep::GenerateLifecycleSubgraph
        }
        V32CandidateConfidence::StaticOnly => V32RecommendedNextStep::GenerateLifecycleSubgraph,
        V32CandidateConfidence::LowPriority => V32RecommendedNextStep::Defer,
    }
}

fn candidate_id_from_boundary_id(boundary_id: &str) -> String {
    if let Some(rest) = boundary_id.strip_prefix("boundary:") {
        format!("candidate:{rest}")
    } else {
        format!("candidate:{boundary_id}")
    }
}

fn boundary_kind_slug(kind: V32BoundaryKind) -> &'static str {
    match kind {
        V32BoundaryKind::NativeLibrary => "native_library",
        V32BoundaryKind::CallbackRegistration => "callback_registration",
        V32BoundaryKind::CallbackUnregistration => "callback_unregistration",
        V32BoundaryKind::ForeignRetainedPointer => "foreign_retained_pointer",
        V32BoundaryKind::OpaqueHandleTransfer => "opaque_handle_transfer",
        V32BoundaryKind::ReturnedBorrow => "returned_borrow",
        V32BoundaryKind::ExternalBuffer => "external_buffer",
        V32BoundaryKind::NegativeSummary => "negative_summary",
    }
}

fn validate_required_text(
    located: &Located<V32CandidateRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at(
            located,
            "BW-CANDIDATE-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_evidence_ref(
    located: &Located<V32CandidateRecord>,
    evidence: &V32BoundaryEvidenceRef,
) -> Result<(), ModelError> {
    validate_required_text(located, "evidence_refs.path", &evidence.path)?;
    validate_relative_ref(located, &evidence.path)?;
    reject_private_identity_tokens(located, "evidence_refs.path", &evidence.path)?;

    if evidence.kind == V32BoundaryEvidenceKind::SourceSpan {
        let Some(line_start) = evidence.line_start else {
            return Err(at(
                located,
                "BW-CANDIDATE-SOURCE-SPAN",
                "source_span evidence 必须包含 line_start",
            ));
        };
        let Some(line_end) = evidence.line_end else {
            return Err(at(
                located,
                "BW-CANDIDATE-SOURCE-SPAN",
                "source_span evidence 必须包含 line_end",
            ));
        };
        if line_start == 0 || line_end < line_start {
            return Err(at(
                located,
                "BW-CANDIDATE-SOURCE-SPAN",
                "source_span 行号必须从 1 开始，且 line_end 不能小于 line_start",
            ));
        }
    }

    Ok(())
}

fn validate_relative_ref(
    located: &Located<V32CandidateRecord>,
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
            "BW-CANDIDATE-REF-PATH",
            "evidence path 必须是相对路径，不能是绝对路径或包含 ..",
        ));
    }
    Ok(())
}

fn reject_private_identity_tokens(
    located: &Located<V32CandidateRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_public_forbidden_token(field, value)
        .map_err(|message| at(located, "BW-CANDIDATE-PRIVATE-TOKEN", message))
}

fn at(
    located: &Located<V32CandidateRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, message).at_line(located.path.clone(), located.line)
}
