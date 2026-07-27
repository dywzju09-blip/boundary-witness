use bw_model::{
    BuildId, CallbackApiEntry, CallbackCaptureFact, CallbackInvokeEvent, CallbackRegisterEvent,
    CallbackRetentionContract, CaptureBindEvent, CaptureMode, ContractClause, ContractClauseKind,
    EvidenceSourceKind, InstanceId, InvokeRole, ObjectCreateEvent, ObjectDropEvent, ObjectKind,
    ObjectSiteFact, RecordId, RegistrationRole, ReleaseBehavior, RunId, RuntimeEvent,
    RuntimeEventEnvelope, SemanticSiteKey, SiteId, StaticFact, StaticFactEnvelope,
    TRACE_SCHEMA_V01, TraceId, TraceStartEvent,
};
use bw_oracle::{Oracle, OracleEngine, StaticFactIndex};

#[test]
fn finding_requires_static_runtime_and_contract_sources() {
    let summary = analyze(
        static_facts([capture_fact("fact:capture", CaptureMode::Borrowed)])
            .expect("static facts should build"),
        contract(),
        violation_trace("api:register", "api:invoke"),
    )
    .expect("analysis should finish");

    let finding = summary
        .finding("BW-LIFE-002")
        .expect("borrow-ended invoke should produce BW-LIFE-002");
    let mut source_kinds = finding
        .evidence
        .iter()
        .map(|reference| match reference.source_kind {
            EvidenceSourceKind::StaticFact => "static_fact",
            EvidenceSourceKind::ContractClause => "contract_clause",
            EvidenceSourceKind::RuntimeEvent => "runtime_event",
        })
        .collect::<Vec<_>>();
    source_kinds.sort();
    source_kinds.dedup();
    assert_eq!(
        source_kinds,
        vec!["contract_clause", "runtime_event", "static_fact"]
    );
    assert!(
        finding
            .evidence
            .iter()
            .any(|reference| reference.record_id.0 == "fact:capture")
    );
    assert!(
        finding
            .evidence
            .iter()
            .any(|reference| reference.record_id.0 == "clause:borrow-outlives-retention")
    );
    assert!(summary.normalized_findings().is_ok());
}

#[test]
fn missing_static_capture_rejects_runtime_binding_instead_of_defaulting_to_borrowed() {
    let error = analyze(
        static_facts([]).expect("object-only static facts should build"),
        contract(),
        violation_trace("api:register", "api:invoke"),
    )
    .expect_err("missing capture fact should reject runtime binding");

    assert_eq!(error.code(), "BW-ORACLE-STATIC-CAPTURE-MISSING");
}

#[test]
fn ambiguous_static_capture_rejects_runtime_binding() {
    let error = analyze(
        static_facts([
            capture_fact("fact:capture:1", CaptureMode::Borrowed),
            capture_fact("fact:capture:2", CaptureMode::Owned),
        ])
        .expect("ambiguous capture facts are indexed for bind-time rejection"),
        contract(),
        violation_trace("api:register", "api:invoke"),
    )
    .expect_err("ambiguous capture fact should reject runtime binding");

    assert_eq!(error.code(), "BW-ORACLE-STATIC-CAPTURE-AMBIGUOUS");
}

#[test]
fn unknown_register_or_invoke_api_is_rejected_by_contract_role_mapping() {
    let unknown_register = analyze(
        static_facts([capture_fact("fact:capture", CaptureMode::Borrowed)])
            .expect("static facts should build"),
        contract(),
        violation_trace("api:unknown-register", "api:invoke"),
    )
    .expect_err("unknown register API must not default to retained");
    assert_eq!(unknown_register.code(), "BW-ORACLE-CONTRACT-API-MISSING");

    let unknown_invoke = analyze(
        static_facts([capture_fact("fact:capture", CaptureMode::Borrowed)])
            .expect("static facts should build"),
        contract(),
        violation_trace("api:register", "api:unknown-invoke"),
    )
    .expect_err("unknown invoke API must not default to callback invocation");
    assert_eq!(unknown_invoke.code(), "BW-ORACLE-CONTRACT-API-MISSING");
}

#[test]
fn owned_static_capture_prevents_borrow_lifetime_finding_for_same_runtime_sequence() {
    let summary = analyze(
        static_facts([capture_fact("fact:capture", CaptureMode::Owned)])
            .expect("static facts should build"),
        contract(),
        violation_trace("api:register", "api:invoke"),
    )
    .expect("analysis should finish");

    assert!(summary.core_rule_ids().is_empty());
    assert!(summary.exposure_rule_ids().is_empty());
}

fn analyze(
    static_facts: StaticFactIndex,
    contract: CallbackRetentionContract,
    events: impl IntoIterator<Item = RuntimeEventEnvelope>,
) -> Result<bw_oracle::AnalysisSummary, bw_oracle::OracleError> {
    let mut oracle = Oracle::new(static_facts, contract);
    for event in events {
        oracle.observe(&event)?;
    }
    oracle.finish()
}

fn static_facts(
    captures: impl IntoIterator<Item = StaticFactEnvelope>,
) -> Result<StaticFactIndex, bw_oracle::OracleError> {
    StaticFactIndex::from_envelopes(
        [static_envelope(
            "fact:object",
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site("site:object"),
                semantic_site_key: SemanticSiteKey::from("semantic:object"),
                type_name: "TrackedState".to_owned(),
            }),
        )]
        .into_iter()
        .chain(captures),
    )
}

fn capture_fact(record_id: &str, capture_mode: CaptureMode) -> StaticFactEnvelope {
    static_envelope(
        record_id,
        StaticFact::CallbackCapture(CallbackCaptureFact {
            site_id: site(record_id),
            semantic_site_key: SemanticSiteKey::from("semantic:capture"),
            callback_site_id: site("site:callback"),
            object_site_id: site("site:object"),
            capture_ordinal: 0,
            capture_mode,
        }),
    )
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

fn contract() -> CallbackRetentionContract {
    CallbackRetentionContract {
        schema_version: bw_model::CONTRACT_SCHEMA_V01.to_owned(),
        contract_id: "contract:retained-callback".to_owned(),
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
                description: "retained 状态允许调用 callback".to_owned(),
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
                api_id: "api:register".to_owned(),
                registration_role: Some(RegistrationRole::Register),
                release_behavior: ReleaseBehavior::None,
                owner_kind: "external_owner".to_owned(),
                invoke_role: None,
            },
            CallbackApiEntry {
                clause_id: "clause:invoke-retained".to_owned(),
                api_id: "api:invoke".to_owned(),
                registration_role: None,
                release_behavior: ReleaseBehavior::None,
                owner_kind: "external_owner".to_owned(),
                invoke_role: Some(InvokeRole::Callback),
            },
        ],
    }
}

fn violation_trace(register_api: &str, invoke_api: &str) -> Vec<RuntimeEventEnvelope> {
    vec![
        event(
            0,
            RuntimeEvent::TraceStart(TraceStartEvent {
                build_id: BuildId::from("build:test"),
            }),
        ),
        event(
            1,
            RuntimeEvent::ObjectCreate(ObjectCreateEvent {
                instance_id: instance("owner:1"),
                site_id: site("site:owner"),
                object_kind: ObjectKind::ExternalOwner,
                epoch: 0,
                address_diag: None,
            }),
        ),
        event(
            2,
            RuntimeEvent::ObjectCreate(ObjectCreateEvent {
                instance_id: instance("object:1"),
                site_id: site("site:object"),
                object_kind: ObjectKind::Tracked,
                epoch: 0,
                address_diag: None,
            }),
        ),
        event(
            3,
            RuntimeEvent::CallbackRegister(CallbackRegisterEvent {
                callback_instance_id: instance("callback:1"),
                callback_site_id: site("site:callback"),
                owner_instance_id: instance("owner:1"),
                registration_site_id: site("site:register"),
                api_id: register_api.to_owned(),
            }),
        ),
        event(
            4,
            RuntimeEvent::CaptureBind(CaptureBindEvent {
                callback_instance_id: instance("callback:1"),
                callback_site_id: site("site:callback"),
                object_instance_id: instance("object:1"),
                object_site_id: site("site:object"),
            }),
        ),
        event(
            5,
            RuntimeEvent::ObjectDrop(ObjectDropEvent {
                instance_id: instance("object:1"),
                drop_site_id: site("site:drop"),
            }),
        ),
        event(
            6,
            RuntimeEvent::CallbackInvoke(CallbackInvokeEvent {
                callback_instance_id: instance("callback:1"),
                invoke_site_id: site("site:invoke"),
                api_id: invoke_api.to_owned(),
            }),
        ),
    ]
}

fn event(seq: u64, payload: RuntimeEvent) -> RuntimeEventEnvelope {
    RuntimeEventEnvelope {
        schema_version: TRACE_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("event:{seq}")),
        run_id: RunId::from("run:test"),
        trace_id: TraceId::from("trace:test"),
        seq,
        thread_id: "main".to_owned(),
        source: "bw-runtime".to_owned(),
        payload,
    }
}

fn site(value: &str) -> SiteId {
    SiteId::from(value)
}

fn instance(value: &str) -> InstanceId {
    InstanceId::from(value)
}
