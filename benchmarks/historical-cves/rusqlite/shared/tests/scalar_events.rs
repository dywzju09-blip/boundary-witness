use std::sync::Arc;

use bw_model::{
    BuildId, CallbackApiEntry, CallbackCaptureFact, CallbackReleaseReason,
    CallbackRetentionContract, CaptureMode, CheckpointKind, ContractClause, ContractClauseKind,
    EvidenceSourceKind, InvokeRole, ObjectSiteFact, RecordId, RegistrationRole, ReleaseBehavior,
    RuntimeEvent, RuntimeEventEnvelope, SemanticSiteKey, SiteId, StaticFact, StaticFactEnvelope,
};
use bw_oracle::{Oracle, OracleEngine, StaticFactIndex};
use bw_runtime::{MemorySink, RuntimeContext, Tracked};
use rusqlite_lab_shared::{scalar_function::ScalarFunctionConnection, OwnedCounter};

#[test]
fn safe_owned_scalar_function_events_have_generic_order_and_no_core_finding() {
    let sink = Arc::new(MemorySink::default());
    let runtime = RuntimeContext::new("run:scalar".into(), "trace:scalar".into(), sink.clone());
    runtime
        .emit_trace_start(BuildId::from("build:test"))
        .unwrap();

    let connection =
        ScalarFunctionConnection::open(runtime.clone(), site("site:connection")).unwrap();
    let counter = Tracked::new(runtime.clone(), site("site:object"), OwnedCounter::new());
    let token = connection
        .register("bw_counter", 0, site("site:callback"))
        .unwrap();
    token
        .bind_object(counter.id(), &site("site:object"))
        .unwrap();
    token.invoke(site("site:invoke")).unwrap();
    connection
        .remove("bw_counter", 0, site("site:remove"))
        .unwrap();
    drop(counter);
    connection.close(site("site:connection-drop")).unwrap();
    runtime.emit_trace_end().unwrap();

    let events = sink.snapshot();
    assert_eq!(
        event_kinds(&events),
        [
            "trace_start",
            "object_create",
            "object_create",
            "callback_register",
            "capture_bind",
            "callback_invoke",
            "callback_unregister",
            "object_drop",
            "object_drop",
            "trace_end"
        ]
    );

    let summary = analyze(events);
    assert!(summary.core_rule_ids().is_empty());
    assert!(summary.exposure_rule_ids().is_empty());
}

#[test]
fn borrowed_scalar_function_sequence_uses_static_contract_and_runtime_evidence() {
    let sink = Arc::new(MemorySink::default());
    let runtime = RuntimeContext::new("run:scalar".into(), "trace:scalar".into(), sink.clone());
    runtime
        .emit_trace_start(BuildId::from("build:test"))
        .unwrap();

    let connection =
        ScalarFunctionConnection::open(runtime.clone(), site("site:connection")).unwrap();
    let counter = Tracked::new(runtime.clone(), site("site:object"), OwnedCounter::new());
    let token = connection
        .register("bw_counter", 0, site("site:callback"))
        .unwrap();
    token
        .bind_object(counter.id(), &site("site:object"))
        .unwrap();
    drop(counter);
    token.invoke(site("site:invoke")).unwrap();
    runtime.emit_trace_end().unwrap();

    let summary = analyze_with_capture_mode(sink.snapshot(), CaptureMode::Borrowed);
    let finding = summary
        .finding("BW-LIFE-002")
        .expect("borrowed scalar callback invoked after drop should be detected");
    assert!(finding
        .evidence
        .iter()
        .any(|reference| reference.source_kind == EvidenceSourceKind::StaticFact));
    assert!(finding
        .evidence
        .iter()
        .any(|reference| reference.source_kind == EvidenceSourceKind::ContractClause));
    assert!(finding
        .evidence
        .iter()
        .any(|reference| reference.source_kind == EvidenceSourceKind::RuntimeEvent));
}

#[test]
fn replacing_scalar_function_releases_previous_callback() {
    let sink = Arc::new(MemorySink::default());
    let runtime = RuntimeContext::new("run:scalar".into(), "trace:scalar".into(), sink.clone());
    runtime
        .emit_trace_start(BuildId::from("build:test"))
        .unwrap();

    let connection =
        ScalarFunctionConnection::open(runtime.clone(), site("site:connection")).unwrap();
    let first = connection
        .register("bw_counter", 0, site("site:callback:first"))
        .unwrap();
    let second = connection
        .register("bw_counter", 0, site("site:callback:second"))
        .unwrap();

    let error = first.invoke(site("site:invoke:first")).unwrap_err();
    assert_eq!(error.code(), "BW-RUNTIME-CALLBACK-RELEASED");
    second.invoke(site("site:invoke:second")).unwrap();

    let events = sink.snapshot();
    assert_eq!(
        unregister_reasons(&events),
        [CallbackReleaseReason::Replacement]
    );
}

#[test]
fn closing_scalar_owner_releases_retained_callback_before_owner_drop() {
    let sink = Arc::new(MemorySink::default());
    let runtime = RuntimeContext::new("run:scalar".into(), "trace:scalar".into(), sink.clone());
    runtime
        .emit_trace_start(BuildId::from("build:test"))
        .unwrap();

    let connection =
        ScalarFunctionConnection::open(runtime.clone(), site("site:connection")).unwrap();
    let token = connection
        .register("bw_counter", 0, site("site:callback"))
        .unwrap();
    connection.close(site("site:connection-drop")).unwrap();

    let error = token.invoke(site("site:invoke")).unwrap_err();
    assert_eq!(error.code(), "BW-RUNTIME-CALLBACK-RELEASED");

    let events = sink.snapshot();
    assert_eq!(
        event_kinds(&events),
        [
            "trace_start",
            "object_create",
            "callback_register",
            "callback_unregister",
            "object_drop",
        ]
    );
    assert_eq!(
        unregister_reasons(&events),
        [CallbackReleaseReason::OwnerDrop]
    );
}

#[test]
fn borrowed_no_trigger_scalar_function_stays_exposure_only() {
    let sink = Arc::new(MemorySink::default());
    let runtime = RuntimeContext::new("run:scalar".into(), "trace:scalar".into(), sink.clone());
    runtime
        .emit_trace_start(BuildId::from("build:test"))
        .unwrap();

    let connection =
        ScalarFunctionConnection::open(runtime.clone(), site("site:connection")).unwrap();
    let counter = Tracked::new(runtime.clone(), site("site:object"), OwnedCounter::new());
    let token = connection
        .register("bw_counter", 0, site("site:callback"))
        .unwrap();
    token
        .bind_object(counter.id(), &site("site:object"))
        .unwrap();
    runtime.emit_checkpoint(CheckpointKind::Registered).unwrap();
    drop(counter);
    runtime
        .emit_checkpoint(CheckpointKind::LaterCallbackPhase)
        .unwrap();
    connection.close(site("site:connection-drop")).unwrap();
    runtime.emit_trace_end().unwrap();

    let summary = analyze_with_capture_mode(sink.snapshot(), CaptureMode::Borrowed);
    assert!(summary.core_rule_ids().is_empty());
    assert_eq!(summary.exposure_rule_ids(), ["BW-LIFE-003"]);
}

#[test]
fn unregister_before_drop_scalar_function_has_no_core_or_exposure_finding() {
    let sink = Arc::new(MemorySink::default());
    let runtime = RuntimeContext::new("run:scalar".into(), "trace:scalar".into(), sink.clone());
    runtime
        .emit_trace_start(BuildId::from("build:test"))
        .unwrap();

    let connection =
        ScalarFunctionConnection::open(runtime.clone(), site("site:connection")).unwrap();
    let counter = Tracked::new(runtime.clone(), site("site:object"), OwnedCounter::new());
    let token = connection
        .register("bw_counter", 0, site("site:callback"))
        .unwrap();
    token
        .bind_object(counter.id(), &site("site:object"))
        .unwrap();
    connection
        .remove("bw_counter", 0, site("site:remove"))
        .unwrap();
    runtime
        .emit_checkpoint(CheckpointKind::OwnerEndedOrReleased)
        .unwrap();
    drop(counter);
    connection.close(site("site:connection-drop")).unwrap();
    runtime.emit_trace_end().unwrap();

    let summary = analyze_with_capture_mode(sink.snapshot(), CaptureMode::Borrowed);
    assert!(summary.core_rule_ids().is_empty());
    assert!(summary.exposure_rule_ids().is_empty());
}

fn analyze(events: Vec<RuntimeEventEnvelope>) -> bw_oracle::AnalysisSummary {
    analyze_with_capture_mode(events, CaptureMode::Owned)
}

fn analyze_with_capture_mode(
    events: Vec<RuntimeEventEnvelope>,
    mode: CaptureMode,
) -> bw_oracle::AnalysisSummary {
    let static_facts = StaticFactIndex::from_envelopes([
        static_envelope(
            "fact:object",
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site("site:object"),
                semantic_site_key: SemanticSiteKey::from("semantic:object"),
                type_name: "OwnedCounter".to_owned(),
            }),
        ),
        static_envelope(
            "fact:capture",
            StaticFact::CallbackCapture(CallbackCaptureFact {
                site_id: site("site:capture"),
                semantic_site_key: SemanticSiteKey::from("semantic:capture"),
                callback_site_id: site("site:callback"),
                object_site_id: site("site:object"),
                capture_ordinal: 0,
                capture_mode: mode,
            }),
        ),
    ])
    .expect("static facts should build");
    let mut oracle = Oracle::new(static_facts, contract());
    for event in events {
        oracle.observe(&event).expect("event should be accepted");
    }
    oracle.finish().expect("analysis should finish")
}

fn contract() -> CallbackRetentionContract {
    CallbackRetentionContract {
        schema_version: bw_model::CONTRACT_SCHEMA_V01.to_owned(),
        contract_id: "contract:scalar-function".to_owned(),
        producer: "boundary-witness@test-commit".to_owned(),
        clauses: vec![
            ContractClause {
                clause_id: "clause:register-retains".to_owned(),
                kind: ContractClauseKind::RetainAfterRegister,
                description: "register 后外部 owner 可以保留 callback".to_owned(),
            },
            ContractClause {
                clause_id: "clause:unregister-releases".to_owned(),
                kind: ContractClauseKind::ReleaseOnUnregister,
                description: "remove 释放 scalar function callback".to_owned(),
            },
            ContractClause {
                clause_id: "clause:owner-drop-releases".to_owned(),
                kind: ContractClauseKind::ReleaseOnOwnerDrop,
                description: "connection drop 释放 callback".to_owned(),
            },
            ContractClause {
                clause_id: "clause:invoke-retained".to_owned(),
                kind: ContractClauseKind::InvokeWhileRetained,
                description: "retained callback 可被外部调用".to_owned(),
            },
            ContractClause {
                clause_id: "clause:borrow-outlives-retention".to_owned(),
                kind: ContractClauseKind::BorrowMustOutliveRetention,
                description: "borrow 必须覆盖 callback 保留期".to_owned(),
            },
            ContractClause {
                clause_id: "clause:no-use-after-end".to_owned(),
                kind: ContractClauseKind::NoUseAfterLifetimeEnd,
                description: "对象生命周期结束后不得使用".to_owned(),
            },
        ],
        api_entries: vec![
            CallbackApiEntry {
                clause_id: "clause:register-retains".to_owned(),
                api_id: "api:rusqlite:create_scalar_function".to_owned(),
                registration_role: Some(RegistrationRole::Register),
                release_behavior: ReleaseBehavior::None,
                owner_kind: "connection".to_owned(),
                invoke_role: None,
            },
            CallbackApiEntry {
                clause_id: "clause:unregister-releases".to_owned(),
                api_id: "api:rusqlite:create_scalar_function".to_owned(),
                registration_role: Some(RegistrationRole::Unregister),
                release_behavior: ReleaseBehavior::ReleaseCurrent,
                owner_kind: "connection".to_owned(),
                invoke_role: None,
            },
            CallbackApiEntry {
                clause_id: "clause:invoke-retained".to_owned(),
                api_id: "api:rusqlite:create_scalar_function".to_owned(),
                registration_role: None,
                release_behavior: ReleaseBehavior::None,
                owner_kind: "connection".to_owned(),
                invoke_role: Some(InvokeRole::Callback),
            },
        ],
    }
}

fn static_envelope(record: &str, payload: StaticFact) -> StaticFactEnvelope {
    StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(record),
        producer: "bw-rustc@test-commit".to_owned(),
        build_id: BuildId::from("build:test"),
        artifact: None,
        source_ref: None,
        payload,
    }
}

fn site(value: &str) -> SiteId {
    SiteId::from(value)
}

fn event_kinds(events: &[RuntimeEventEnvelope]) -> Vec<&'static str> {
    events
        .iter()
        .map(|event| match event.payload {
            RuntimeEvent::TraceStart(_) => "trace_start",
            RuntimeEvent::ObjectCreate(_) => "object_create",
            RuntimeEvent::CallbackRegister(_) => "callback_register",
            RuntimeEvent::CaptureBind(_) => "capture_bind",
            RuntimeEvent::CallbackInvoke(_) => "callback_invoke",
            RuntimeEvent::CallbackUnregister(_) => "callback_unregister",
            RuntimeEvent::ObjectDrop(_) => "object_drop",
            RuntimeEvent::TraceEnd(_) => "trace_end",
            _ => "other",
        })
        .collect()
}

fn unregister_reasons(events: &[RuntimeEventEnvelope]) -> Vec<CallbackReleaseReason> {
    events
        .iter()
        .filter_map(|event| match &event.payload {
            RuntimeEvent::CallbackUnregister(unregister) => Some(unregister.reason),
            _ => None,
        })
        .collect()
}
