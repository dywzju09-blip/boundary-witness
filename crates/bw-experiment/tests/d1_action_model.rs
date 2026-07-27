use std::{fs, path::PathBuf};

use bw_experiment::{
    ActionDecodeOptions, ActionSequence, ApiKind, CorpusPolicy, D1_ACTION_SCHEMA_V01, FuzzAction,
    SeedProvenance, SqlOp,
};

#[test]
fn action_sequence_json_roundtrips_and_rejects_unknown_fields() {
    let sequence = ActionSequence {
        schema_version: D1_ACTION_SCHEMA_V01.to_owned(),
        actions: vec![
            FuzzAction::OpenConnection,
            FuzzAction::CreateTable,
            FuzzAction::CreateBorrowedState,
            FuzzAction::RegisterBorrowed {
                api: ApiKind::UpdateHook,
            },
            FuzzAction::EndOwnerScope,
            FuzzAction::ExecuteSql { op: SqlOp::Insert },
        ],
        decoder: Default::default(),
        provenance: SeedProvenance::initial_corpus("roundtrip"),
    };

    let json = serde_json::to_string(&sequence).unwrap();
    let parsed = ActionSequence::from_json_str(&json).unwrap();
    assert_eq!(parsed, sequence);

    let bad_top_level = format!(
        r#"{{
  "schema_version": "{D1_ACTION_SCHEMA_V01}",
  "actions": [],
  "decoder": {{"source": "unit-test", "input_len": 0, "truncated": false}},
  "provenance": {{"kind": "unit_test", "name": "bad"}},
  "cve": "CVE-0000-0000"
}}"#
    );
    assert!(ActionSequence::from_json_str(&bad_top_level).is_err());

    let bad_action = format!(
        r#"{{
  "schema_version": "{D1_ACTION_SCHEMA_V01}",
  "actions": [
    {{"kind": "register_borrowed", "api": "update_hook", "vulnerable": true}}
  ],
  "decoder": {{"source": "unit-test", "input_len": 0, "truncated": false}},
  "provenance": {{"kind": "unit_test", "name": "bad"}}
}}"#
    );
    assert!(ActionSequence::from_json_str(&bad_action).is_err());
}

#[test]
fn arbitrary_byte_decoder_never_panics_and_respects_max_length() {
    for input in [
        &[][..],
        &[0],
        &[1, 2, 3, 4, 5, 6],
        &(0u8..=255).collect::<Vec<_>>(),
    ] {
        let decoded = ActionSequence::decode_bytes(
            input,
            ActionDecodeOptions {
                max_actions: 8,
                source: "unit-test".to_owned(),
            },
        );
        assert!(decoded.actions.len() <= 8);
        decoded.validate().unwrap();
    }
}

#[test]
fn corpus_policy_rejects_complete_dangerous_seed_but_allows_safe_fragments() {
    let policy = CorpusPolicy;
    let dangerous = ActionSequence {
        schema_version: D1_ACTION_SCHEMA_V01.to_owned(),
        actions: vec![
            FuzzAction::OpenConnection,
            FuzzAction::CreateTable,
            FuzzAction::CreateBorrowedState,
            FuzzAction::RegisterBorrowed {
                api: ApiKind::UpdateHook,
            },
            FuzzAction::EndOwnerScope,
            FuzzAction::ExecuteSql { op: SqlOp::Insert },
        ],
        decoder: Default::default(),
        provenance: SeedProvenance::initial_corpus("dangerous-complete-chain"),
    };

    let error = policy.audit_sequence(&dangerous).unwrap_err().to_string();
    assert!(
        error.contains("complete dangerous seed"),
        "unexpected error: {error}"
    );

    for relative in [
        "experiments/corpus/d1/update-hook/safe-fragments.jsonl",
        "experiments/corpus/d1/scalar-function/safe-fragments.jsonl",
    ] {
        let input = fs::read_to_string(repo_root().join(relative)).unwrap();
        let audit = policy.audit_jsonl_str(&input).unwrap();
        assert!(audit.sequences > 0, "empty corpus: {relative}");
        assert!(audit.actions > 0, "empty action corpus: {relative}");
    }
}

#[test]
fn safe_seed_jsonl_can_be_materialized_to_decoder_bytes() {
    for relative in [
        "experiments/corpus/d1/update-hook/safe-fragments.jsonl",
        "experiments/corpus/d1/scalar-function/safe-fragments.jsonl",
    ] {
        let input = fs::read_to_string(repo_root().join(relative)).unwrap();
        for line in input.lines().filter(|line| !line.trim().is_empty()) {
            let sequence = ActionSequence::from_json_str(line).unwrap();
            let bytes = sequence.encode_seed_bytes();
            let decoded = ActionSequence::decode_bytes(
                &bytes,
                ActionDecodeOptions {
                    max_actions: sequence.actions.len(),
                    source: "seed-roundtrip".to_owned(),
                },
            );
            assert_eq!(decoded.actions, sequence.actions);
        }
    }
}

#[test]
fn scalar_function_complete_chain_is_also_rejected() {
    let sequence = ActionSequence {
        schema_version: D1_ACTION_SCHEMA_V01.to_owned(),
        actions: vec![
            FuzzAction::RegisterBorrowed {
                api: ApiKind::CreateScalarFunction,
            },
            FuzzAction::EndOwnerScope,
            FuzzAction::ExecuteSql {
                op: SqlOp::SelectScalar,
            },
        ],
        decoder: Default::default(),
        provenance: SeedProvenance::initial_corpus("scalar-dangerous-complete-chain"),
    };

    assert!(CorpusPolicy.audit_sequence(&sequence).is_err());
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
