use bw_model::{
    BuildId, CallbackApiEntry, CallbackCaptureFact, CallbackInvokeEvent, CallbackRegisterEvent,
    CallbackRetentionContract, CaptureBindEvent, CaptureMode, ContractClause, ContractClauseKind,
    InstanceId, InvokeRole, ObjectCreateEvent, ObjectDropEvent, ObjectKind, ObjectSiteFact,
    RecordId, RegistrationRole, ReleaseBehavior, RuntimeEvent, RuntimeEventEnvelope,
    SemanticSiteKey, SiteId, StaticFact, StaticFactEnvelope, TRACE_SCHEMA_V01, TraceEndEvent,
    TraceId, TraceStartEvent,
};
use bw_oracle::{Oracle, OracleEngine, StaticFactIndex};

#[test]
fn update_hook_and_scalar_function_use_same_lifecycle_rule_shape() {
    let update = analyze("api:rusqlite:update_hook");
    let scalar = analyze("api:rusqlite:create_scalar_function");

    assert_eq!(update.core_rule_ids(), ["BW-LIFE-002"]);
    assert_eq!(scalar.core_rule_ids(), ["BW-LIFE-002"]);
    assert_eq!(
        update.normalized_signatures().unwrap(),
        scalar.normalized_signatures().unwrap()
    );
}

fn analyze(api_id: &str) -> bw_oracle::AnalysisSummary {
    let static_facts = StaticFactIndex::from_envelopes([
        static_envelope(
            "fact:object",
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site("site:object"),
                semantic_site_key: SemanticSiteKey::from("semantic:object"),
                type_name: "TrackedCounter".to_owned(),
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
                capture_mode: CaptureMode::Borrowed,
            }),
        ),
    ])
    .expect("static facts should build");
    let mut oracle = Oracle::new(static_facts, contract(api_id));
    for event in retained_callback_invoked_after_borrow_end(api_id) {
        oracle.observe(&event).expect("event should be accepted");
    }
    oracle.finish().expect("analysis should finish")
}

fn retained_callback_invoked_after_borrow_end(api_id: &str) -> Vec<RuntimeEventEnvelope> {
    let run_id = "run:cross-api";
    let trace_id = TraceId::from("trace:cross-api");
    let owner_id = InstanceId::from("run:cross-api:owner:1");
    let object_id = InstanceId::from("run:cross-api:object:1");
    let callback_id = InstanceId::from("run:cross-api:callback:1");
    [
        RuntimeEvent::TraceStart(TraceStartEvent {
            build_id: BuildId::from("build:test"),
        }),
        RuntimeEvent::ObjectCreate(ObjectCreateEvent {
            instance_id: owner_id.clone(),
            site_id: site("site:connection"),
            object_kind: ObjectKind::ExternalOwner,
            epoch: 0,
            address_diag: None,
        }),
        RuntimeEvent::ObjectCreate(ObjectCreateEvent {
            instance_id: object_id.clone(),
            site_id: site("site:object"),
            object_kind: ObjectKind::Tracked,
            epoch: 0,
            address_diag: None,
        }),
        RuntimeEvent::CallbackRegister(CallbackRegisterEvent {
            callback_instance_id: callback_id.clone(),
            callback_site_id: site("site:callback"),
            owner_instance_id: owner_id,
            registration_site_id: site("site:callback"),
            api_id: api_id.to_owned(),
        }),
        RuntimeEvent::CaptureBind(CaptureBindEvent {
            callback_instance_id: callback_id.clone(),
            callback_site_id: site("site:callback"),
            object_instance_id: object_id.clone(),
            object_site_id: site("site:object"),
        }),
        RuntimeEvent::ObjectDrop(ObjectDropEvent {
            instance_id: object_id,
            drop_site_id: site("site:object-drop"),
        }),
        RuntimeEvent::CallbackInvoke(CallbackInvokeEvent {
            callback_instance_id: callback_id,
            invoke_site_id: site("site:invoke"),
            api_id: api_id.to_owned(),
        }),
        RuntimeEvent::TraceEnd(TraceEndEvent { event_count: 7 }),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, payload)| RuntimeEventEnvelope {
        schema_version: TRACE_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("record:{}", index + 1)),
        run_id: run_id.into(),
        trace_id: trace_id.clone(),
        seq: (index + 1) as u64,
        thread_id: "test".to_owned(),
        source: "cross-api-test".to_owned(),
        payload,
    })
    .collect()
}

fn contract(api_id: &str) -> CallbackRetentionContract {
    CallbackRetentionContract {
        schema_version: bw_model::CONTRACT_SCHEMA_V01.to_owned(),
        contract_id: "contract:cross-api".to_owned(),
        producer: "boundary-witness@test-commit".to_owned(),
        clauses: vec![
            ContractClause {
                clause_id: "clause:register-retains".to_owned(),
                kind: ContractClauseKind::RetainAfterRegister,
                description: "register 后外部 owner 可以保留 callback".to_owned(),
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
                api_id: api_id.to_owned(),
                registration_role: Some(RegistrationRole::Register),
                release_behavior: ReleaseBehavior::None,
                owner_kind: "connection".to_owned(),
                invoke_role: None,
            },
            CallbackApiEntry {
                clause_id: "clause:invoke-retained".to_owned(),
                api_id: api_id.to_owned(),
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
