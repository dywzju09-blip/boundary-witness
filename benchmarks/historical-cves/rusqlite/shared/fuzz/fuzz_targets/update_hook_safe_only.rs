#![no_main]

use std::sync::OnceLock;

#[path = "support/d1_counters.rs"]
mod d1_counters;

use bw_experiment::{
    ActionDecodeOptions, ActionSequence, ApiKind, FuzzAction, ObjectiveClassifier,
    ObjectiveKind, ObjectiveObservation, ObjectivePolicy,
};
use bw_model::ExecutionEvidence;
use libfuzzer_sys::fuzz_target;
use rusqlite_lab_shared::fuzzing::run_update_hook_sequence;

fuzz_target!(|data: &[u8]| {
    let decoded = ActionSequence::decode_bytes(
        data,
        ActionDecodeOptions {
            max_actions: 32,
            source: "libfuzzer:update_hook_safe_only".to_owned(),
        },
    );
    let sequence = update_hook_safe_only(decoded);

    let Ok(result) = run_update_hook_sequence(&sequence) else {
        d1_counters::record_tool_error();
        return;
    };
    let classification = classifier().classify(&ObjectiveObservation {
        evidence: evidence_from_findings(!result.findings.is_empty()),
        findings: result.findings.clone(),
    });
    d1_counters::record(&result, &classification);
    if classification.objective_kind == ObjectiveKind::Primary {
        d1_counters::flush_now();
        panic!(
            "safe-only target produced primary objective: {} {}",
            classification.primary_rule_id.unwrap_or_default(),
            classification.normalized_signature.unwrap_or_default()
        );
    }
});

fn update_hook_safe_only(mut sequence: ActionSequence) -> ActionSequence {
    sequence.actions = sequence
        .actions
        .into_iter()
        .filter_map(|action| match action {
            FuzzAction::RegisterBorrowed { .. } => Some(FuzzAction::RegisterOwned {
                api: ApiKind::UpdateHook,
            }),
            FuzzAction::RegisterOwned { .. } => Some(FuzzAction::RegisterOwned {
                api: ApiKind::UpdateHook,
            }),
            FuzzAction::Unregister { .. } => Some(FuzzAction::Unregister {
                api: ApiKind::UpdateHook,
            }),
            FuzzAction::OpenConnection
            | FuzzAction::CreateTable
            | FuzzAction::CreateBorrowedState
            | FuzzAction::EndOwnerScope
            | FuzzAction::ExecuteSql { .. }
            | FuzzAction::CloseConnection => Some(action),
        })
        .collect();
    sequence.provenance.kind = "safe_only_generated".to_owned();
    sequence
}

fn classifier() -> &'static ObjectiveClassifier {
    static CLASSIFIER: OnceLock<ObjectiveClassifier> = OnceLock::new();
    CLASSIFIER.get_or_init(|| {
        ObjectiveClassifier::new(ObjectivePolicy::callback_lifetime_default())
    })
}

fn evidence_from_findings(has_contract_finding: bool) -> ExecutionEvidence {
    ExecutionEvidence {
        has_contract_finding,
        has_asan_evidence: false,
        has_native_crash: false,
        has_panic: false,
        has_timeout: false,
    }
}
