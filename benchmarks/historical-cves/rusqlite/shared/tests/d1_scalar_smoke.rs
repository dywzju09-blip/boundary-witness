use bw_experiment::{
    ActionSequence, ApiKind, FuzzAction, ObjectiveKind, SqlOp, D1_ACTION_SCHEMA_V01,
};
use bw_model::RuntimeEvent;
use rusqlite_lab_shared::fuzzing::{
    evaluate_scalar_function_objective, minimize_scalar_function_sequence,
    run_scalar_function_sequence,
};

#[test]
fn scalar_adapter_emits_generic_callback_lifecycle_events() {
    let result = run_scalar_function_sequence(&owned_safe_sequence()).unwrap();

    assert_eq!(
        generic_lifecycle_event_kinds(&result.events),
        [
            "callback_register",
            "capture_bind",
            "callback_invoke",
            "callback_unregister",
            "object_drop",
            "object_drop",
        ]
    );
    assert!(result.core_rule_ids().is_empty());
}

#[test]
fn borrowed_scalar_sequence_uses_shared_primary_objective_policy() {
    let classification = evaluate_scalar_function_objective(&borrowed_complete_sequence()).unwrap();

    assert_eq!(classification.objective_kind, ObjectiveKind::Primary);
    assert_eq!(
        classification.primary_rule_id.as_deref(),
        Some("BW-LIFE-002")
    );
}

#[test]
fn scalar_primary_sequence_minimizes_to_shared_witness_stages() {
    let minimized = minimize_scalar_function_sequence(&borrowed_complete_sequence()).unwrap();

    assert!(minimized.witness_stages.has_register);
    assert!(minimized.witness_stages.has_owner_end);
    assert!(minimized.witness_stages.has_later_trigger);
    assert_eq!(
        minimized.classification.primary_rule_id.as_deref(),
        Some("BW-LIFE-002")
    );
}

#[test]
fn owned_scalar_sequence_is_not_primary() {
    let classification = evaluate_scalar_function_objective(&owned_safe_sequence()).unwrap();

    assert_eq!(classification.objective_kind, ObjectiveKind::None);
}

fn borrowed_complete_sequence() -> ActionSequence {
    ActionSequence {
        schema_version: D1_ACTION_SCHEMA_V01.to_owned(),
        actions: vec![
            FuzzAction::OpenConnection,
            FuzzAction::CreateTable,
            FuzzAction::CreateBorrowedState,
            FuzzAction::RegisterBorrowed {
                api: ApiKind::CreateScalarFunction,
            },
            FuzzAction::EndOwnerScope,
            FuzzAction::ExecuteSql {
                op: SqlOp::SelectScalar,
            },
        ],
        decoder: Default::default(),
        provenance: bw_experiment::SeedProvenance::initial_corpus("scalar-borrowed-complete"),
    }
}

fn owned_safe_sequence() -> ActionSequence {
    ActionSequence {
        schema_version: D1_ACTION_SCHEMA_V01.to_owned(),
        actions: vec![
            FuzzAction::OpenConnection,
            FuzzAction::CreateTable,
            FuzzAction::RegisterOwned {
                api: ApiKind::CreateScalarFunction,
            },
            FuzzAction::ExecuteSql {
                op: SqlOp::SelectScalar,
            },
            FuzzAction::Unregister {
                api: ApiKind::CreateScalarFunction,
            },
            FuzzAction::EndOwnerScope,
            FuzzAction::CloseConnection,
        ],
        decoder: Default::default(),
        provenance: bw_experiment::SeedProvenance::initial_corpus("scalar-owned-safe"),
    }
}

fn generic_lifecycle_event_kinds(events: &[bw_model::RuntimeEventEnvelope]) -> Vec<&'static str> {
    events
        .iter()
        .filter_map(|event| match &event.payload {
            RuntimeEvent::CallbackRegister(_) => Some("callback_register"),
            RuntimeEvent::CaptureBind(_) => Some("capture_bind"),
            RuntimeEvent::CallbackInvoke(_) => Some("callback_invoke"),
            RuntimeEvent::CallbackUnregister(_) => Some("callback_unregister"),
            RuntimeEvent::ObjectDrop(_) => Some("object_drop"),
            _ => None,
        })
        .collect()
}
