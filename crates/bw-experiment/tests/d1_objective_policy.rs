use std::{fs, path::PathBuf};

use bw_experiment::{ObjectiveClassifier, ObjectiveKind, ObjectiveObservation, ObjectivePolicy};
use bw_model::{
    BuildId, EvidenceReference, EvidenceSourceKind, ExecutionEvidence, Finding,
    FindingClassification, FindingStateSnapshot, InstanceId, RecordId, RunId,
};

#[test]
fn objective_policy_loads_from_toml_and_classifies_rule_groups() {
    let policy = ObjectivePolicy::parse_toml(
        &fs::read_to_string(repo_root().join("experiments/configs/d1-objectives.toml")).unwrap(),
    )
    .unwrap();
    let classifier = ObjectiveClassifier::new(policy);

    assert_eq!(
        classifier
            .classify(&ObjectiveObservation::findings(vec![finding(
                "BW-LIFE-001",
                FindingClassification::ConfirmedViolation,
            )]))
            .objective_kind,
        ObjectiveKind::Primary
    );
    assert_eq!(
        classifier
            .classify(&ObjectiveObservation::findings(vec![finding(
                "BW-LIFE-002",
                FindingClassification::ConfirmedViolation,
            )]))
            .objective_kind,
        ObjectiveKind::Primary
    );
    assert_eq!(
        classifier
            .classify(&ObjectiveObservation::findings(vec![finding(
                "BW-LIFE-003",
                FindingClassification::Exposure,
            )]))
            .objective_kind,
        ObjectiveKind::Progress
    );
    assert_eq!(
        classifier
            .classify(&ObjectiveObservation::findings(vec![finding(
                "BW-FREE-001",
                FindingClassification::ConfirmedViolation,
            )]))
            .objective_kind,
        ObjectiveKind::Secondary
    );
}

#[test]
fn primary_objective_wins_without_dropping_secondary_evidence() {
    let classifier = ObjectiveClassifier::new(ObjectivePolicy::callback_lifetime_default());
    let classification = classifier.classify(&ObjectiveObservation::findings(vec![
        finding("BW-FREE-001", FindingClassification::ConfirmedViolation),
        finding("BW-LIFE-002", FindingClassification::ConfirmedViolation),
    ]));

    assert_eq!(classification.objective_kind, ObjectiveKind::Primary);
    assert_eq!(
        classification.primary_rule_id.as_deref(),
        Some("BW-LIFE-002")
    );
    assert!(
        classification
            .normalized_signature
            .as_deref()
            .unwrap()
            .starts_with("BW-LIFE-002|")
    );
    assert_eq!(classification.secondary_findings, ["BW-FREE-001"]);
    assert!(
        classification
            .evidence_refs
            .iter()
            .any(|reference| reference.description_code == "BW-EVIDENCE-CALLBACK-INVOKE")
    );
}

#[test]
fn asan_or_panic_without_contract_finding_is_not_primary_objective() {
    let classifier = ObjectiveClassifier::new(ObjectivePolicy::callback_lifetime_default());
    let classification = classifier.classify(&ObjectiveObservation {
        findings: Vec::new(),
        evidence: ExecutionEvidence {
            has_contract_finding: false,
            has_asan_evidence: true,
            has_native_crash: false,
            has_panic: true,
            has_timeout: false,
        },
    });

    assert_eq!(classification.objective_kind, ObjectiveKind::None);
    assert!(classification.primary_rule_id.is_none());
    assert!(classification.secondary_findings.is_empty());
}

fn finding(rule_id: &str, classification: FindingClassification) -> Finding {
    Finding {
        schema_version: bw_model::FINDING_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("finding:{rule_id}")),
        rule_id: rule_id.to_owned(),
        classification,
        subject_object: Some(InstanceId::from("object:d1")),
        subject_callback: Some(InstanceId::from("callback:d1")),
        first_violation_event: RecordId::from("event:invoke"),
        evidence: vec![
            EvidenceReference {
                record_id: RecordId::from("fact:capture"),
                source_kind: EvidenceSourceKind::StaticFact,
                description_code: "BW-EVIDENCE-BORROWED-CAPTURE".to_owned(),
            },
            EvidenceReference {
                record_id: RecordId::from("clause:borrow-outlives-retention"),
                source_kind: EvidenceSourceKind::ContractClause,
                description_code: "BW-EVIDENCE-CONTRACT-CLAUSE".to_owned(),
            },
            EvidenceReference {
                record_id: RecordId::from("event:invoke"),
                source_kind: EvidenceSourceKind::RuntimeEvent,
                description_code: "BW-EVIDENCE-CALLBACK-INVOKE".to_owned(),
            },
        ],
        context_rule_ids: Vec::new(),
        state_before: FindingStateSnapshot {
            object_state: Some("ended".to_owned()),
            capture_state: Some("ended".to_owned()),
            callback_state: Some("retained".to_owned()),
            owner_state: Some("open".to_owned()),
        },
        state_after: FindingStateSnapshot {
            object_state: Some("ended".to_owned()),
            capture_state: Some("ended".to_owned()),
            callback_state: Some("retained".to_owned()),
            owner_state: Some("open".to_owned()),
        },
        normalized_signature: format!("{rule_id}|semantic:d1"),
        producer: "bw-oracle@test".to_owned(),
        build_id: BuildId::from("build:d1"),
        run_id: RunId::from("run:d1"),
        message: "message must not be parsed by objective classifier".to_owned(),
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
