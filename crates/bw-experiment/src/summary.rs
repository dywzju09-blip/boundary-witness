use std::collections::{BTreeMap, BTreeSet};

use bw_model::{ExecutionEvidence, PrimaryOutcome};
use serde::{Deserialize, Serialize};

use crate::{CallbackApi, ExperimentError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRecord {
    pub api: CallbackApi,
    pub case_id: String,
    pub build_id: String,
    pub replay_id: String,
    pub primary_outcome: PrimaryOutcome,
    pub finding_signature: Option<String>,
    pub evidence: ExecutionEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentSummary {
    pub schema_version: String,
    pub total_replays: usize,
    pub buckets: Vec<OutcomeBucket>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeBucket {
    pub api: CallbackApi,
    pub case_id: String,
    pub build_id: String,
    pub primary_outcome: PrimaryOutcome,
    pub finding_signature: Option<String>,
    pub count: usize,
    pub replay_ids: Vec<String>,
    pub evidence_counts: EvidenceCounts,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCounts {
    pub contract_finding: usize,
    pub asan_evidence: usize,
    pub native_crash: usize,
    pub panic: usize,
    pub timeout: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct BucketKey {
    api: CallbackApi,
    case_id: String,
    build_id: String,
    primary_outcome: String,
    finding_signature: Option<String>,
}

pub fn summarize_replays(records: &[ReplayRecord]) -> Result<ExperimentSummary> {
    let mut replay_ids = BTreeSet::new();
    let mut buckets = BTreeMap::<BucketKey, OutcomeBucket>::new();

    for record in records {
        validate_replay_record(record)?;
        if !replay_ids.insert(record.replay_id.clone()) {
            return Err(ExperimentError::InvalidInput(format!(
                "duplicate replay_id: {}",
                record.replay_id
            )));
        }

        let key = BucketKey {
            api: record.api,
            case_id: record.case_id.clone(),
            build_id: record.build_id.clone(),
            primary_outcome: outcome_label(record.primary_outcome).to_owned(),
            finding_signature: record.finding_signature.clone(),
        };
        let bucket = buckets.entry(key).or_insert_with(|| OutcomeBucket {
            api: record.api,
            case_id: record.case_id.clone(),
            build_id: record.build_id.clone(),
            primary_outcome: record.primary_outcome,
            finding_signature: record.finding_signature.clone(),
            count: 0,
            replay_ids: Vec::new(),
            evidence_counts: EvidenceCounts::default(),
        });
        bucket.count += 1;
        bucket.replay_ids.push(record.replay_id.clone());
        bucket.evidence_counts.add(&record.evidence);
    }

    Ok(ExperimentSummary {
        schema_version: "boundary-witness.experiment-summary/0.1".to_owned(),
        total_replays: records.len(),
        buckets: buckets.into_values().collect(),
    })
}

impl ExperimentSummary {
    #[must_use]
    pub fn timeout_replays(&self) -> usize {
        self.buckets
            .iter()
            .map(|bucket| bucket.evidence_counts.timeout)
            .sum()
    }

    #[must_use]
    pub fn bucket(
        &self,
        api: CallbackApi,
        case_id: &str,
        build_id: &str,
        primary_outcome: PrimaryOutcome,
        finding_signature: Option<&str>,
    ) -> Option<&OutcomeBucket> {
        self.buckets.iter().find(|bucket| {
            bucket.api == api
                && bucket.case_id == case_id
                && bucket.build_id == build_id
                && bucket.primary_outcome == primary_outcome
                && bucket.finding_signature.as_deref() == finding_signature
        })
    }
}

impl EvidenceCounts {
    fn add(&mut self, evidence: &ExecutionEvidence) {
        self.contract_finding += usize::from(evidence.has_contract_finding);
        self.asan_evidence += usize::from(evidence.has_asan_evidence);
        self.native_crash += usize::from(evidence.has_native_crash);
        self.panic += usize::from(evidence.has_panic);
        self.timeout += usize::from(evidence.has_timeout);
    }
}

fn validate_replay_record(record: &ReplayRecord) -> Result<()> {
    for (field, value) in [
        ("case_id", record.case_id.as_str()),
        ("build_id", record.build_id.as_str()),
        ("replay_id", record.replay_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(ExperimentError::InvalidInput(format!(
                "{field} must not be empty"
            )));
        }
    }
    Ok(())
}

fn outcome_label(outcome: PrimaryOutcome) -> &'static str {
    match outcome {
        PrimaryOutcome::NoFinding => "no_finding",
        PrimaryOutcome::ContractFinding => "contract_finding",
        PrimaryOutcome::Asan => "asan",
        PrimaryOutcome::NativeCrash => "native_crash",
        PrimaryOutcome::Panic => "panic",
        PrimaryOutcome::Timeout => "timeout",
        PrimaryOutcome::InvalidInput => "invalid_input",
        PrimaryOutcome::ToolError => "tool_error",
    }
}
