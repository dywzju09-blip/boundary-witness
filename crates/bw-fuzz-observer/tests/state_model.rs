use bw_fuzz_observer::{ContractFeedbackState, ContractStateObserver};
use bw_model::{
    BuildId, CallbackCaptureFact, CallbackInvokeEvent, CallbackRegisterEvent, CaptureBindEvent,
    CaptureMode, CheckpointEvent, CheckpointKind, ObjectCreateEvent, ObjectDropEvent, ObjectKind,
    RecordId, RunId, RuntimeEvent, RuntimeEventEnvelope, STATIC_SCHEMA_V01, SiteId, StaticFact,
    StaticFactEnvelope, TRACE_SCHEMA_V01, TraceEndEvent, TraceId,
};

fn static_capture(
    record_suffix: &str,
    callback_site: &str,
    object_site: &str,
) -> StaticFactEnvelope {
    StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("fact:{record_suffix}")),
        producer: "state-model-test".to_owned(),
        build_id: BuildId::from("build:test"),
        artifact: None,
        source_ref: None,
        payload: StaticFact::CallbackCapture(CallbackCaptureFact {
            site_id: SiteId::from(format!("site:capture:{record_suffix}")),
            semantic_site_key: format!("semantic:capture:{record_suffix}").into(),
            callback_site_id: SiteId::from(callback_site),
            object_site_id: SiteId::from(object_site),
            capture_ordinal: 0,
            capture_mode: CaptureMode::Borrowed,
        }),
    }
}

fn event(seq: u64, payload: RuntimeEvent) -> RuntimeEventEnvelope {
    RuntimeEventEnvelope {
        schema_version: TRACE_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("event:{seq}")),
        run_id: RunId::from("run:test"),
        trace_id: TraceId::from("trace:test"),
        seq,
        thread_id: "main".to_owned(),
        source: "state-model-test".to_owned(),
        payload,
    }
}

fn vulnerable_sequence(callback_id: &str, object_id: &str) -> Vec<RuntimeEventEnvelope> {
    vec![
        event(
            0,
            RuntimeEvent::TraceStart(bw_model::TraceStartEvent {
                build_id: BuildId::from("build:test"),
            }),
        ),
        event(
            1,
            RuntimeEvent::ObjectCreate(ObjectCreateEvent {
                instance_id: "owner:1".into(),
                site_id: "site:owner".into(),
                object_kind: ObjectKind::ExternalOwner,
                epoch: 0,
                address_diag: Some("0xabc123".to_owned()),
            }),
        ),
        event(
            2,
            RuntimeEvent::ObjectCreate(ObjectCreateEvent {
                instance_id: object_id.into(),
                site_id: "site:object".into(),
                object_kind: ObjectKind::Tracked,
                epoch: 0,
                address_diag: Some("/tmp/build/path:99".to_owned()),
            }),
        ),
        event(
            3,
            RuntimeEvent::CallbackRegister(CallbackRegisterEvent {
                callback_instance_id: callback_id.into(),
                callback_site_id: "site:callback".into(),
                owner_instance_id: "owner:1".into(),
                registration_site_id: "site:register".into(),
                api_id: "api:register".to_owned(),
            }),
        ),
        event(
            4,
            RuntimeEvent::CaptureBind(CaptureBindEvent {
                callback_instance_id: callback_id.into(),
                callback_site_id: "site:callback".into(),
                object_instance_id: object_id.into(),
                object_site_id: "site:object".into(),
            }),
        ),
        event(
            5,
            RuntimeEvent::Checkpoint(CheckpointEvent {
                checkpoint: CheckpointKind::Registered,
            }),
        ),
        event(
            6,
            RuntimeEvent::ObjectDrop(ObjectDropEvent {
                instance_id: object_id.into(),
                drop_site_id: "site:drop".into(),
            }),
        ),
        event(
            7,
            RuntimeEvent::CallbackInvoke(CallbackInvokeEvent {
                callback_instance_id: callback_id.into(),
                invoke_site_id: "site:invoke".into(),
                api_id: "api:invoke".to_owned(),
            }),
        ),
        event(8, RuntimeEvent::TraceEnd(TraceEndEvent { event_count: 9 })),
    ]
}

#[test]
fn same_event_sequence_produces_deterministic_state_bits() {
    let facts = vec![static_capture("borrowed", "site:callback", "site:object")];
    let events = vulnerable_sequence("callback:1", "object:1");

    let left = ContractStateObserver::from_static_facts(facts.clone())
        .unwrap()
        .observe_all(events.clone())
        .unwrap();
    let right = ContractStateObserver::from_static_facts(facts)
        .unwrap()
        .observe_all(events)
        .unwrap();

    assert_eq!(left, right);
    assert!(left.contains(ContractFeedbackState::BorrowedRetained));
    assert!(left.contains(ContractFeedbackState::BorrowEndedRetained));
    assert!(left.contains(ContractFeedbackState::InvokedAfterEnd));
}

#[test]
fn renaming_runtime_objects_does_not_change_feedback_key() {
    let facts = vec![static_capture("borrowed", "site:callback", "site:object")];
    let original = ContractStateObserver::from_static_facts(facts.clone())
        .unwrap()
        .observe_all(vulnerable_sequence("callback:1", "object:1"))
        .unwrap();
    let renamed = ContractStateObserver::from_static_facts(facts)
        .unwrap()
        .observe_all(vulnerable_sequence("callback:renamed", "object:renamed"))
        .unwrap();

    assert_eq!(original.feedback_key(), renamed.feedback_key());
}

#[test]
fn no_borrow_callback_relation_keeps_state_empty() {
    let snapshot = ContractStateObserver::from_static_facts([])
        .unwrap()
        .observe_all(vulnerable_sequence("callback:1", "object:1"))
        .unwrap();

    assert!(snapshot.states().is_empty());
    assert_eq!(snapshot.feedback_key(), "");
}

#[test]
fn state_bits_have_stable_serialized_names_without_diagnostic_identity() {
    let snapshot = ContractStateObserver::from_static_facts([static_capture(
        "borrowed",
        "site:callback",
        "site:object",
    )])
    .unwrap()
    .observe_all(vulnerable_sequence("callback:1", "object:1"))
    .unwrap();

    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(json.contains("borrowed_retained"));
    assert!(json.contains("borrow_ended_retained"));
    assert!(json.contains("invoked_after_end"));
    assert!(!json.contains("callback:1"));
    assert!(!json.contains("object:1"));
    assert!(!json.contains("0xabc123"));
    assert!(!json.contains("/tmp/build/path"));
}
