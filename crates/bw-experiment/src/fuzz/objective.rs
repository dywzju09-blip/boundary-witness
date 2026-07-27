use std::{collections::BTreeSet, fs, path::Path};

use bw_model::{EvidenceReference, ExecutionEvidence, Finding};
use serde::{Deserialize, Serialize};

use crate::{ExperimentError, Result};

pub const D1_OBJECTIVES_SCHEMA_V01: &str = "boundary-witness.d1-objectives/0.1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectivePolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub primary: Vec<String>,
    pub progress: Vec<String>,
    pub secondary: Vec<String>,
}

impl ObjectivePolicy {
    pub fn parse_toml(input: &str) -> Result<Self> {
        let policy = toml::from_str::<Self>(input).map_err(|error| {
            ExperimentError::InvalidInput(format!("invalid d1 objective policy toml: {error}"))
        })?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|error| ExperimentError::io(path, error))?;
        Self::parse_toml(&input)
    }

    #[must_use]
    pub fn callback_lifetime_default() -> Self {
        Self {
            schema_version: D1_OBJECTIVES_SCHEMA_V01.to_owned(),
            policy_id: "d1-callback-lifetime".to_owned(),
            primary: vec!["BW-LIFE-001".to_owned(), "BW-LIFE-002".to_owned()],
            progress: vec!["BW-LIFE-003".to_owned()],
            secondary: vec!["BW-FREE-001".to_owned()],
        }
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != D1_OBJECTIVES_SCHEMA_V01 {
            return Err(ExperimentError::InvalidInput(format!(
                "unsupported d1 objective policy schema_version: {}",
                self.schema_version
            )));
        }
        if self.policy_id.trim().is_empty() {
            return Err(ExperimentError::InvalidInput(
                "objective policy_id must not be empty".to_owned(),
            ));
        }
        for (field, rules) in [
            ("primary", &self.primary),
            ("progress", &self.progress),
            ("secondary", &self.secondary),
        ] {
            if rules.iter().any(|rule| rule.trim().is_empty()) {
                return Err(ExperimentError::InvalidInput(format!(
                    "objective {field} contains empty rule id"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectiveClassifier {
    policy: ObjectivePolicy,
}

impl ObjectiveClassifier {
    #[must_use]
    pub fn new(policy: ObjectivePolicy) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn classify(&self, observation: &ObjectiveObservation) -> ObjectiveClassification {
        let secondary_findings = matching_rule_ids(&observation.findings, &self.policy.secondary);
        let progress_states = matching_rule_ids(&observation.findings, &self.policy.progress);

        if let Some(primary) = first_matching_finding(&observation.findings, &self.policy.primary) {
            return ObjectiveClassification {
                objective_kind: ObjectiveKind::Primary,
                primary_rule_id: Some(primary.rule_id.clone()),
                normalized_signature: Some(primary.normalized_signature.clone()),
                progress_states,
                secondary_findings,
                evidence_refs: primary.evidence.clone(),
            };
        }

        if !progress_states.is_empty() {
            return ObjectiveClassification {
                objective_kind: ObjectiveKind::Progress,
                primary_rule_id: None,
                normalized_signature: None,
                progress_states,
                secondary_findings,
                evidence_refs: Vec::new(),
            };
        }

        if !secondary_findings.is_empty() {
            return ObjectiveClassification {
                objective_kind: ObjectiveKind::Secondary,
                primary_rule_id: None,
                normalized_signature: None,
                progress_states,
                secondary_findings,
                evidence_refs: Vec::new(),
            };
        }

        let _ = observation.evidence;
        ObjectiveClassification {
            objective_kind: ObjectiveKind::None,
            primary_rule_id: None,
            normalized_signature: None,
            progress_states,
            secondary_findings,
            evidence_refs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectiveObservation {
    pub findings: Vec<Finding>,
    pub evidence: ExecutionEvidence,
}

impl ObjectiveObservation {
    #[must_use]
    pub fn findings(findings: Vec<Finding>) -> Self {
        Self {
            evidence: ExecutionEvidence {
                has_contract_finding: !findings.is_empty(),
                has_asan_evidence: false,
                has_native_crash: false,
                has_panic: false,
                has_timeout: false,
            },
            findings,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveKind {
    Primary,
    Progress,
    Secondary,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveClassification {
    pub objective_kind: ObjectiveKind,
    pub primary_rule_id: Option<String>,
    pub normalized_signature: Option<String>,
    pub progress_states: Vec<String>,
    pub secondary_findings: Vec<String>,
    pub evidence_refs: Vec<EvidenceReference>,
}

fn first_matching_finding<'a>(
    findings: &'a [Finding],
    ordered_rules: &[String],
) -> Option<&'a Finding> {
    for rule in ordered_rules {
        if let Some(finding) = findings.iter().find(|finding| finding.rule_id == *rule) {
            return Some(finding);
        }
    }
    None
}

fn matching_rule_ids(findings: &[Finding], rules: &[String]) -> Vec<String> {
    let allowed = rules.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for finding in findings {
        if allowed.contains(finding.rule_id.as_str()) && seen.insert(finding.rule_id.clone()) {
            output.push(finding.rule_id.clone());
        }
    }
    output
}
