use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Located, ModelError, public_tokens::reject_public_forbidden_token};

pub const V3_2_CORPUS_MANIFEST_SCHEMA_V1: &str = "v3.2.corpus_manifest.1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32CorpusManifestRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_corpus_manifest_schema")]
    pub schema_version: String,
    pub corpus_id: String,
    pub crate_id: String,
    pub crate_name: String,
    pub version: String,
    pub source_kind: V32CorpusSourceKind,
    pub source_ref: String,
    pub selection_reason: Vec<V32CorpusSelectionReason>,
    pub intake_status: V32CorpusIntakeStatus,
    #[serde(default)]
    pub intake_notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32CorpusSourceKind {
    CratesIo,
    GitArchive,
    LocalArchive,
    RegistrySnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32CorpusSelectionReason {
    NativeDependency,
    CallbackApiCandidate,
    FfiDependency,
    BindgenUsage,
    LinksMetadata,
    PureRust,
    IteratorApiCandidate,
    ContainerLifecycleSurface,
    WrapperApiCandidate,
    DestructureLifecycleSurface,
    AllocatorApiCandidate,
    IteratorLifetimeSurface,
    ConcurrentCellSurface,
    ConversionApiCandidate,
    SliceViewSurface,
    ManualExclusionRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32CorpusIntakeStatus {
    Accepted,
    Excluded,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V32CorpusManifestSummary {
    pub record_count: u64,
    pub accepted_count: u64,
    pub excluded_count: u64,
}

pub fn validate_v3_2_corpus_manifest<I>(records: I) -> Result<V32CorpusManifestSummary, ModelError>
where
    I: IntoIterator<Item = Located<V32CorpusManifestRecord>>,
{
    let mut summary = V32CorpusManifestSummary::default();
    let mut corpus_id: Option<String> = None;
    let mut crate_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text(&located, "corpus_id", &record.corpus_id)?;
        validate_required_text(&located, "crate_id", &record.crate_id)?;
        validate_required_text(&located, "crate_name", &record.crate_name)?;
        validate_required_text(&located, "version", &record.version)?;
        validate_required_text(&located, "source_ref", &record.source_ref)?;
        reject_private_identity_tokens(&located, "corpus_id", &record.corpus_id)?;
        reject_private_identity_tokens(&located, "crate_id", &record.crate_id)?;
        reject_private_identity_tokens(&located, "crate_name", &record.crate_name)?;
        reject_private_identity_tokens(&located, "version", &record.version)?;
        reject_private_identity_tokens(&located, "source_ref", &record.source_ref)?;
        for note in &record.intake_notes {
            reject_private_identity_tokens(&located, "intake_notes", note)?;
        }
        if record.selection_reason.is_empty() {
            return Err(at(
                &located,
                "BW-CORPUS-SELECTION-EMPTY",
                "selection_reason 至少需要一个冻结枚举值",
            ));
        }
        if record.intake_status == V32CorpusIntakeStatus::Excluded && record.intake_notes.is_empty()
        {
            return Err(at(
                &located,
                "BW-CORPUS-EXCLUSION-NOTE-MISSING",
                "excluded 记录必须在 intake_notes 中说明排除原因",
            ));
        }
        if let Some(expected) = &corpus_id {
            if expected != &record.corpus_id {
                return Err(at(
                    &located,
                    "BW-CORPUS-ID-MISMATCH",
                    format!(
                        "同一 manifest 出现 corpus_id {expected} 和 {}",
                        record.corpus_id
                    ),
                ));
            }
        } else {
            corpus_id = Some(record.corpus_id.clone());
        }
        if !crate_ids.insert(record.crate_id.clone()) {
            return Err(at(
                &located,
                "BW-CORPUS-CRATE-DUPLICATE",
                format!("crate_id {} 重复", record.crate_id),
            ));
        }

        summary.record_count += 1;
        match record.intake_status {
            V32CorpusIntakeStatus::Accepted => summary.accepted_count += 1,
            V32CorpusIntakeStatus::Excluded => summary.excluded_count += 1,
        }
    }

    Ok(summary)
}

fn validate_required_text(
    located: &Located<V32CorpusManifestRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at(
            located,
            "BW-CORPUS-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn reject_private_identity_tokens(
    located: &Located<V32CorpusManifestRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_public_forbidden_token(field, value)
        .map_err(|message| at(located, "BW-CORPUS-PRIVATE-TOKEN", message))
}

fn at(
    located: &Located<V32CorpusManifestRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, message).at_line(located.path.clone(), located.line)
}
