use bw_fuzz_observer::{ContractFeedbackState, ContractStateFeedback, FeedbackStateSnapshot};

#[test]
fn new_contract_state_is_interesting_but_repeated_state_is_not() {
    let mut feedback = ContractStateFeedback::default();
    let first = snapshot([ContractFeedbackState::BorrowedRetained]);
    let second = snapshot([ContractFeedbackState::BorrowedRetained]);

    let first_decision = feedback.observe_snapshot(&first);
    let second_decision = feedback.observe_snapshot(&second);

    assert!(first_decision.interesting);
    assert_eq!(first_decision.key.as_deref(), Some("borrowed_retained"));
    assert!(!second_decision.interesting);
    assert_eq!(second_decision.key, None);
}

#[test]
fn state_transition_key_is_rewarded_once() {
    let mut feedback = ContractStateFeedback::default();
    let _ = feedback.observe_snapshot(&snapshot([ContractFeedbackState::BorrowedRetained]));

    let decision = feedback.observe_snapshot(&snapshot([
        ContractFeedbackState::BorrowedRetained,
        ContractFeedbackState::BorrowEndedRetained,
    ]));
    let repeated = feedback.observe_snapshot(&snapshot([
        ContractFeedbackState::BorrowedRetained,
        ContractFeedbackState::BorrowEndedRetained,
    ]));

    assert!(decision.interesting);
    assert_eq!(
        decision.key.as_deref(),
        Some("borrowed_retained->borrow_ended_retained")
    );
    assert!(!repeated.interesting);
}

#[test]
fn primary_finding_is_not_a_feedback_input() {
    let mut feedback = ContractStateFeedback::default();
    let decision = feedback.observe_primary_marker("BW-LIFE-002");

    assert!(!decision.interesting);
    assert_eq!(feedback.seen_key_count(), 0);
}

#[test]
fn cve_version_and_path_text_do_not_change_feedback_key() {
    let mut feedback = ContractStateFeedback::default();
    let clean = snapshot([ContractFeedbackState::InvokedAfterEnd]);
    let noisy = snapshot_with_diagnostics(
        [ContractFeedbackState::InvokedAfterEnd],
        "CVE-2021-32737 /tmp/vulnerable-rusqlite-0.26.1",
    );

    assert_eq!(clean.feedback_key(), noisy.feedback_key());
    assert_eq!(
        feedback.observe_snapshot(&clean).key,
        Some("invoked_after_end".to_owned())
    );
    assert_eq!(feedback.observe_snapshot(&noisy).key, None);
}

fn snapshot(states: impl IntoIterator<Item = ContractFeedbackState>) -> FeedbackStateSnapshot {
    FeedbackStateSnapshot::from_states(states)
}

fn snapshot_with_diagnostics(
    states: impl IntoIterator<Item = ContractFeedbackState>,
    diagnostics: &str,
) -> FeedbackStateSnapshot {
    let mut snapshot = FeedbackStateSnapshot::from_states(states);
    snapshot.add_diagnostic_note(diagnostics);
    snapshot
}
