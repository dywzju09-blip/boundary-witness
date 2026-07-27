use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    Located, ModelError, V32AdapterEffortRecord, V32BoundaryIndexRecord, V32BoundaryKind,
    V32BuildabilityRecord, V32BuildabilityStatus, public_tokens::reject_public_forbidden_token,
};

pub const V3_2_FAILURE_TAXONOMY_SCHEMA_V1: &str = "v3.2.failure_taxonomy.1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32FailureTaxonomyRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_failure_taxonomy_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub subject_kind: V32TaxonomySubjectKind,
    pub subject_id: String,
    pub crate_id: String,
    pub stage: V32TaxonomyStage,
    pub failure_class: V32FailureClass,
    pub is_infrastructure_failure: bool,
    pub is_method_negative: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32TaxonomySubjectKind {
    Crate,
    Candidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32TaxonomyStage {
    BuildPrecheck,
    BoundaryIndex,
    CandidatePartition,
    LifecycleRanking,
    DynamicPrep,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32FailureClass {
    RequiresSystemDependency,
    CargoCheckFailed,
    NotBuildable,
    UnsupportedTarget,
    Timeout,
    ToolError,
    NoSupportedBoundaryPattern,
    DeferredStaticOnly,
    AnalyzerUnsupported,
    InsufficientEvidence,
    IntegrityFailure,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V32FailureTaxonomySummary {
    pub record_count: u64,
    pub infrastructure_failure_count: u64,
    pub method_negative_count: u64,
    pub build_failure_count: u64,
    pub no_boundary_count: u64,
    pub deferred_count: u64,
}

/// Build pilot incomplete-sample taxonomy from earlier stage outputs.
pub fn build_failure_taxonomy(
    run_id: &str,
    buildability: &[V32BuildabilityRecord],
    boundary_index: &[V32BoundaryIndexRecord],
    adapter_effort: &[V32AdapterEffortRecord],
) -> Vec<V32FailureTaxonomyRecord> {
    let mut records = Vec::new();

    for build in buildability {
        if build.status == V32BuildabilityStatus::Buildable {
            continue;
        }
        let failure_class = map_build_failure(build);
        records.push(V32FailureTaxonomyRecord {
            schema_version: V3_2_FAILURE_TAXONOMY_SCHEMA_V1.to_owned(),
            run_id: run_id.to_owned(),
            subject_kind: V32TaxonomySubjectKind::Crate,
            subject_id: build.crate_id.clone(),
            crate_id: build.crate_id.clone(),
            stage: V32TaxonomyStage::BuildPrecheck,
            failure_class,
            is_infrastructure_failure: matches!(
                failure_class,
                V32FailureClass::RequiresSystemDependency
                    | V32FailureClass::ToolError
                    | V32FailureClass::Timeout
                    | V32FailureClass::UnsupportedTarget
            ),
            is_method_negative: false,
            notes: vec![
                "build failure is not a no-vulnerability conclusion".to_owned(),
                format!("source_status={}", buildability_status_slug(build.status)),
                format!(
                    "source_failure_class={}",
                    build.failure_class.as_deref().unwrap_or("null")
                ),
            ],
        });
    }

    let mut boundaries_by_crate =
        std::collections::BTreeMap::<String, Vec<&V32BoundaryIndexRecord>>::new();
    for boundary in boundary_index {
        boundaries_by_crate
            .entry(boundary.crate_id.clone())
            .or_default()
            .push(boundary);
    }
    for (crate_id, items) in boundaries_by_crate {
        let only_negative = items
            .iter()
            .all(|item| item.boundary_kind == V32BoundaryKind::NegativeSummary);
        if only_negative {
            records.push(V32FailureTaxonomyRecord {
                schema_version: V3_2_FAILURE_TAXONOMY_SCHEMA_V1.to_owned(),
                run_id: run_id.to_owned(),
                subject_kind: V32TaxonomySubjectKind::Crate,
                subject_id: crate_id.clone(),
                crate_id,
                stage: V32TaxonomyStage::BoundaryIndex,
                failure_class: V32FailureClass::NoSupportedBoundaryPattern,
                is_infrastructure_failure: false,
                is_method_negative: false,
                notes: vec![
                    "no supported boundary pattern is not a no-vulnerability conclusion".to_owned(),
                    "current heuristic scan of src/**/*.rs found no supported boundary pattern"
                        .to_owned(),
                ],
            });
        }
    }

    for effort in adapter_effort {
        if effort.adapter_needed {
            continue;
        }
        records.push(V32FailureTaxonomyRecord {
            schema_version: V3_2_FAILURE_TAXONOMY_SCHEMA_V1.to_owned(),
            run_id: run_id.to_owned(),
            subject_kind: V32TaxonomySubjectKind::Candidate,
            subject_id: effort.candidate_id.clone(),
            crate_id: effort.crate_id.clone(),
            stage: V32TaxonomyStage::DynamicPrep,
            failure_class: V32FailureClass::DeferredStaticOnly,
            is_infrastructure_failure: false,
            is_method_negative: false,
            notes: vec![
                "deferred dynamic preparation is not a no-vulnerability conclusion".to_owned(),
                format!(
                    "blocked_reason={}",
                    effort.blocked_reason.as_deref().unwrap_or("null")
                ),
                format!("rank={} score={}", effort.rank, effort.score),
            ],
        });
    }

    records.sort_by(|left, right| {
        left.stage
            .to_order()
            .cmp(&right.stage.to_order())
            .then_with(|| left.crate_id.cmp(&right.crate_id))
            .then_with(|| left.subject_id.cmp(&right.subject_id))
    });
    records
}

pub fn validate_v3_2_failure_taxonomy<I>(
    records: I,
) -> Result<V32FailureTaxonomySummary, ModelError>
where
    I: IntoIterator<Item = Located<V32FailureTaxonomyRecord>>,
{
    let mut summary = V32FailureTaxonomySummary::default();
    let mut run_id: Option<String> = None;
    let mut subject_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text(&located, "run_id", &record.run_id)?;
        validate_required_text(&located, "subject_id", &record.subject_id)?;
        validate_required_text(&located, "crate_id", &record.crate_id)?;
        reject_private_tokens(&located, "run_id", &record.run_id)?;
        reject_private_tokens(&located, "subject_id", &record.subject_id)?;
        reject_private_tokens(&located, "crate_id", &record.crate_id)?;
        for note in &record.notes {
            reject_private_tokens(&located, "notes", note)?;
        }

        if record.is_method_negative {
            // Pilot taxonomy for incomplete samples must never claim "no vulnerability".
            return Err(at(
                &located,
                "BW-TAXONOMY-METHOD-NEGATIVE",
                "当前 pilot failure taxonomy 禁止把未完成样本标记为 is_method_negative=true",
            ));
        }

        if let Some(expected) = &run_id {
            if expected != &record.run_id {
                return Err(at(
                    &located,
                    "BW-TAXONOMY-RUN-MISMATCH",
                    format!(
                        "同一 failure taxonomy 文件出现 run_id {expected} 和 {}",
                        record.run_id
                    ),
                ));
            }
        } else {
            run_id = Some(record.run_id.clone());
        }

        let subject_key = format!("{:?}:{}", record.subject_kind, record.subject_id);
        if !subject_ids.insert(subject_key) {
            return Err(at(
                &located,
                "BW-TAXONOMY-SUBJECT-DUPLICATE",
                format!(
                    "subject {}/{} 重复",
                    subject_kind_slug(record.subject_kind),
                    record.subject_id
                ),
            ));
        }

        if record.is_infrastructure_failure {
            summary.infrastructure_failure_count += 1;
        }
        if record.is_method_negative {
            summary.method_negative_count += 1;
        }
        match record.failure_class {
            V32FailureClass::RequiresSystemDependency
            | V32FailureClass::CargoCheckFailed
            | V32FailureClass::NotBuildable
            | V32FailureClass::UnsupportedTarget
            | V32FailureClass::Timeout
            | V32FailureClass::ToolError => summary.build_failure_count += 1,
            V32FailureClass::NoSupportedBoundaryPattern => summary.no_boundary_count += 1,
            V32FailureClass::DeferredStaticOnly => summary.deferred_count += 1,
            _ => {}
        }
        summary.record_count += 1;
    }

    Ok(summary)
}

fn map_build_failure(build: &V32BuildabilityRecord) -> V32FailureClass {
    if let Some(class) = build.failure_class.as_deref() {
        match class {
            "requires_system_dependency" => return V32FailureClass::RequiresSystemDependency,
            "cargo_check_failed" => return V32FailureClass::CargoCheckFailed,
            "unsupported_target" => return V32FailureClass::UnsupportedTarget,
            "timeout" => return V32FailureClass::Timeout,
            "tool_error" => return V32FailureClass::ToolError,
            "not_buildable" => return V32FailureClass::NotBuildable,
            _ => {}
        }
    }
    match build.status {
        V32BuildabilityStatus::RequiresSystemDependency => {
            V32FailureClass::RequiresSystemDependency
        }
        V32BuildabilityStatus::NotBuildable => V32FailureClass::NotBuildable,
        V32BuildabilityStatus::UnsupportedTarget => V32FailureClass::UnsupportedTarget,
        V32BuildabilityStatus::Timeout => V32FailureClass::Timeout,
        V32BuildabilityStatus::ToolError => V32FailureClass::ToolError,
        V32BuildabilityStatus::Buildable => V32FailureClass::IntegrityFailure,
    }
}

fn buildability_status_slug(status: V32BuildabilityStatus) -> &'static str {
    match status {
        V32BuildabilityStatus::Buildable => "buildable",
        V32BuildabilityStatus::NotBuildable => "not_buildable",
        V32BuildabilityStatus::RequiresSystemDependency => "requires_system_dependency",
        V32BuildabilityStatus::UnsupportedTarget => "unsupported_target",
        V32BuildabilityStatus::Timeout => "timeout",
        V32BuildabilityStatus::ToolError => "tool_error",
    }
}

fn subject_kind_slug(kind: V32TaxonomySubjectKind) -> &'static str {
    match kind {
        V32TaxonomySubjectKind::Crate => "crate",
        V32TaxonomySubjectKind::Candidate => "candidate",
    }
}

impl V32TaxonomyStage {
    fn to_order(self) -> u8 {
        match self {
            Self::BuildPrecheck => 1,
            Self::BoundaryIndex => 2,
            Self::CandidatePartition => 3,
            Self::LifecycleRanking => 4,
            Self::DynamicPrep => 5,
        }
    }
}

fn validate_required_text(
    located: &Located<V32FailureTaxonomyRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at(
            located,
            "BW-TAXONOMY-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn reject_private_tokens(
    located: &Located<V32FailureTaxonomyRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_public_forbidden_token(field, value)
        .map_err(|message| at(located, "BW-TAXONOMY-PRIVATE-TOKEN", message))
}

fn at(
    located: &Located<V32FailureTaxonomyRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, message).at_line(located.path.clone(), located.line)
}
