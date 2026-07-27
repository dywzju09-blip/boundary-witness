use std::{fs, path::PathBuf};

use bw_experiment::{
    ActionSequence, ApiKind, FuzzAction, SeedProvenance, SqlOp, D1_ACTION_SCHEMA_V01,
};
use rusqlite_lab_shared::fuzzing::{run_update_hook_sequence, HarnessOutcome};

#[test]
fn update_hook_iteration_state_is_never_reused() {
    let first = run_update_hook_sequence(&sequence(
        "retained-borrow-without-trigger",
        vec![
            FuzzAction::OpenConnection,
            FuzzAction::CreateTable,
            FuzzAction::CreateBorrowedState,
            FuzzAction::RegisterBorrowed {
                api: ApiKind::UpdateHook,
            },
            FuzzAction::EndOwnerScope,
        ],
    ))
    .unwrap();

    assert_eq!(first.outcome, HarnessOutcome::Completed);
    assert_eq!(first.rule_ids(), ["BW-LIFE-003"]);

    let second = run_update_hook_sequence(&sequence(
        "fresh-sql-only-iteration",
        vec![
            FuzzAction::OpenConnection,
            FuzzAction::CreateTable,
            FuzzAction::ExecuteSql { op: SqlOp::Insert },
        ],
    ))
    .unwrap();

    assert_eq!(second.outcome, HarnessOutcome::Completed);
    assert!(second.findings.is_empty());
    assert_eq!(second.counters.callback_invocations, 0);
    assert_ne!(first.run_id, second.run_id);
}

#[test]
fn malformed_sequence_returns_invalid_input_instead_of_panicking() {
    let result = run_update_hook_sequence(&sequence(
        "sql-before-open",
        vec![FuzzAction::ExecuteSql { op: SqlOp::Insert }],
    ))
    .unwrap();

    assert_eq!(result.outcome, HarnessOutcome::InvalidInput);
    assert_eq!(
        result.invalid_reason.as_deref(),
        Some("connection_not_open")
    );
    assert!(result.findings.is_empty());
}

#[test]
fn update_hook_complete_borrowed_chain_emits_lifecycle_finding() {
    let input =
        fs::read_to_string(repo_root().join("fixtures/fuzz/d1/update_hook/borrowed-complete.json"))
            .unwrap();
    let sequence = ActionSequence::from_json_str(&input).unwrap();

    let result = run_update_hook_sequence(&sequence).unwrap();

    assert_eq!(result.outcome, HarnessOutcome::Completed);
    assert!(result.rule_ids().contains(&"BW-LIFE-002"));
    assert!(result
        .normalized_signatures()
        .iter()
        .any(|signature| signature.starts_with("BW-LIFE-002|")));
    assert!(result.counters.callback_invocations >= 1);
}

fn sequence(name: &str, actions: Vec<FuzzAction>) -> ActionSequence {
    ActionSequence {
        schema_version: D1_ACTION_SCHEMA_V01.to_owned(),
        actions,
        decoder: Default::default(),
        provenance: SeedProvenance::initial_corpus(name),
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
