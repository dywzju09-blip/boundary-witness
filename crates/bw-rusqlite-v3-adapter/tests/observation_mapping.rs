use bw_blind_model::{BlindCaseId, BlindCaseStatus, BlindSplit};
use bw_model::FindingClassification;
use bw_rusqlite_v3_adapter::{ObservationInput, observation_from_findings};

#[test]
fn confirmed_finding_requires_complete_witness() {
    let observation = observation_from_findings(ObservationInput {
        suite_id: "suite.rusqlite.m12".to_owned(),
        split: BlindSplit::Gate,
        case_id: BlindCaseId::parse("blind-0123456789abcdef").unwrap(),
        method_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        public_manifest_sha256: "a".repeat(64),
        findings: vec![(
            "callback-retention.uaf".to_owned(),
            FindingClassification::ConfirmedViolation,
            "b".repeat(64),
            true,
        )],
        witness_path: Some("witness/witness.json".to_owned()),
        witness_sha256: Some("c".repeat(64)),
        replay_attempts: 20,
        replay_successes: 20,
    })
    .unwrap();

    assert_eq!(observation.status, BlindCaseStatus::Completed);
    assert_eq!(observation.findings.len(), 1);
    assert!(observation.witness.is_some());
    observation.validate(20).unwrap();
}

#[test]
fn clean_case_has_no_findings_or_witness() {
    let observation = observation_from_findings(ObservationInput {
        suite_id: "suite.rusqlite.m12".to_owned(),
        split: BlindSplit::Gate,
        case_id: BlindCaseId::parse("blind-0123456789abcdef").unwrap(),
        method_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        public_manifest_sha256: "a".repeat(64),
        findings: vec![],
        witness_path: None,
        witness_sha256: None,
        replay_attempts: 0,
        replay_successes: 0,
    })
    .unwrap();

    assert_eq!(observation.status, BlindCaseStatus::Completed);
    assert!(observation.findings.is_empty());
    assert!(observation.witness.is_none());
    observation.validate(20).unwrap();
}

#[test]
fn analyzer_signatures_are_rehashed_for_public_observations() {
    let raw_analyzer_signature = "callback-retention.uaf:site:runtime-evidence";
    let observation = observation_from_findings(ObservationInput {
        suite_id: "suite.rusqlite.m12".to_owned(),
        split: BlindSplit::Gate,
        case_id: BlindCaseId::parse("blind-0123456789abcdef").unwrap(),
        method_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        public_manifest_sha256: "a".repeat(64),
        findings: vec![(
            "callback-retention.uaf".to_owned(),
            FindingClassification::ConfirmedViolation,
            raw_analyzer_signature.to_owned(),
            true,
        )],
        witness_path: Some("witness/witness.json".to_owned()),
        witness_sha256: Some("c".repeat(64)),
        replay_attempts: 20,
        replay_successes: 20,
    })
    .unwrap();

    let public_signature = &observation.findings[0].normalized_signature;
    assert_ne!(public_signature, raw_analyzer_signature);
    assert_eq!(public_signature.len(), 64);
    assert!(
        public_signature
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    );
    observation.validate(20).unwrap();
}
