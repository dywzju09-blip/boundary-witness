use bw_experiment::{
    ActionSequence, ExecutionEvidence, ObjectiveClassifier, ObjectiveKind, ObjectiveObservation,
    ObjectivePolicy,
};
use bw_fuzz_observer::ContractFeedbackState;
use rusqlite_lab_shared::fuzzing::{
    run_update_hook_sequence, run_update_hook_sequence_with_observer,
};

#[test]
fn observer_does_not_change_findings_or_primary_outcome() {
    let sequence = observer_fixture("borrowed-complete.json");

    let without_observer = run_update_hook_sequence(&sequence).unwrap();
    let with_observer = run_update_hook_sequence_with_observer(&sequence).unwrap();

    assert_eq!(without_observer.outcome, with_observer.outcome);
    assert_eq!(
        without_observer.invalid_reason,
        with_observer.invalid_reason
    );
    assert_eq!(without_observer.rule_ids(), with_observer.rule_ids());
    assert_eq!(
        without_observer.normalized_signatures(),
        with_observer.normalized_signatures()
    );
    assert_eq!(
        classify(without_observer.findings.clone()).objective_kind,
        ObjectiveKind::Primary
    );
    assert_eq!(
        classify(without_observer.findings).primary_rule_id,
        classify(with_observer.findings.clone()).primary_rule_id
    );

    let snapshot = with_observer
        .feedback_snapshot
        .expect("observer run should expose a feedback snapshot");
    assert!(snapshot.contains(ContractFeedbackState::BorrowedRetained));
    assert!(snapshot.contains(ContractFeedbackState::BorrowEndedRetained));
    assert!(snapshot.contains(ContractFeedbackState::InvokedAfterEnd));
}

#[test]
fn observer_snapshot_is_empty_for_safe_owned_sequence() {
    let sequence = observer_fixture("owned-safe.json");

    let result = run_update_hook_sequence_with_observer(&sequence).unwrap();

    assert!(result.findings.is_empty());
    assert_eq!(
        result
            .feedback_snapshot
            .expect("observer run should expose a feedback snapshot")
            .feedback_key(),
        ""
    );
}

fn classify(findings: Vec<bw_model::Finding>) -> bw_experiment::ObjectiveClassification {
    ObjectiveClassifier::new(ObjectivePolicy::callback_lifetime_default()).classify(
        &ObjectiveObservation {
            evidence: ExecutionEvidence {
                has_contract_finding: !findings.is_empty(),
                has_asan_evidence: false,
                has_native_crash: false,
                has_panic: false,
                has_timeout: false,
            },
            findings,
        },
    )
}

fn observer_fixture(name: &str) -> ActionSequence {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures/fuzz/d2/observer")
        .join(name);
    ActionSequence::from_json_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
