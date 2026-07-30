//! 集成测试共享辅助。每个测试二进制单独编译本模块，因此未被该二进制用到的
//! 辅助会报 dead_code——这是编译模型的产物，不是真的死代码。
#![allow(dead_code)]

use bw_model::{
    BuildId, CallbackCaptureFact, CallbackRegisterEvent, CaptureBindEvent, CaptureMode,
    EvidenceReference, EvidenceSourceKind, Finding, FindingClassification, FindingStateSnapshot,
    InstanceId, ObjectCreateEvent, ObjectKind, ObjectSiteFact, RecordId, RunId, RuntimeEvent,
    RuntimeEventEnvelope, SemanticSiteKey, SiteId, StaticFact, StaticFactEnvelope,
    TRACE_SCHEMA_V01, TraceId, TraceStartEvent,
};
use bw_oracle::StaticFactIndex;

pub fn sample_finding(id_suffix: &str) -> Finding {
    Finding {
        schema_version: bw_model::FINDING_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("finding:{id_suffix}")),
        rule_id: "BW-LIFE-002".to_owned(),
        classification: FindingClassification::ConfirmedViolation,
        subject_object: Some(InstanceId::from(format!("object:{id_suffix}"))),
        subject_callback: Some(InstanceId::from(format!("callback:{id_suffix}"))),
        first_violation_event: RecordId::from(format!("event:invoke:{id_suffix}")),
        evidence: vec![
            EvidenceReference {
                record_id: RecordId::from(format!("fact:capture:{id_suffix}")),
                source_kind: EvidenceSourceKind::StaticFact,
                description_code: "BW-EVIDENCE-BORROWED-CAPTURE".to_owned(),
            },
            EvidenceReference {
                record_id: RecordId::from("clause:borrow-outlives-retention"),
                source_kind: EvidenceSourceKind::ContractClause,
                description_code: "BW-EVIDENCE-CONTRACT-CLAUSE".to_owned(),
            },
            EvidenceReference {
                record_id: RecordId::from(format!("event:bind:{id_suffix}")),
                source_kind: EvidenceSourceKind::RuntimeEvent,
                description_code: "BW-EVIDENCE-CAPTURE-BIND".to_owned(),
            },
            EvidenceReference {
                record_id: RecordId::from(format!("event:end:{id_suffix}")),
                source_kind: EvidenceSourceKind::RuntimeEvent,
                description_code: "BW-EVIDENCE-BORROW-END".to_owned(),
            },
            EvidenceReference {
                record_id: RecordId::from(format!("event:invoke:{id_suffix}")),
                source_kind: EvidenceSourceKind::RuntimeEvent,
                description_code: "BW-EVIDENCE-CALLBACK-INVOKE".to_owned(),
            },
        ],
        context_rule_ids: Vec::new(),
        state_before: FindingStateSnapshot {
            object_state: Some("ended".to_owned()),
            capture_state: Some("ended".to_owned()),
            callback_state: Some("retained".to_owned()),
            owner_state: Some("open".to_owned()),
        },
        state_after: FindingStateSnapshot {
            object_state: Some("ended".to_owned()),
            capture_state: Some("ended".to_owned()),
            callback_state: Some("retained".to_owned()),
            owner_state: Some("open".to_owned()),
        },
        normalized_signature: "BW-LIFE-002|semantic:capture".to_owned(),
        producer: format!("bw-oracle@{id_suffix}"),
        build_id: BuildId::from(format!("build:{id_suffix}")),
        run_id: RunId::from(format!("run:{id_suffix}")),
        message: format!("仅供阅读的消息 {id_suffix}"),
    }
}

// 以下辅助此前在 properties.rs 与 rules.rs 各存一份逐字节相同的副本。
// 它们构造的是 oracle 的输入形状；两份漂移会让两个测试文件实际测的不是同一个
// 场景，而断言仍然各自通过。

pub fn event(seq: u64, payload: RuntimeEvent) -> RuntimeEventEnvelope {
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

pub fn instance(value: &str) -> InstanceId {
    InstanceId::from(value)
}

pub fn site(value: &str) -> SiteId {
    SiteId::from(value)
}

pub fn static_envelope(record: &str, payload: StaticFact) -> StaticFactEnvelope {
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

pub fn setup_events() -> Vec<RuntimeEventEnvelope> {
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
                api_id: "api:register".to_owned(),
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
    ]
}

pub fn static_facts(mode: CaptureMode) -> StaticFactIndex {
    StaticFactIndex::from_envelopes([
        static_envelope(
            "fact:object",
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site("site:object"),
                semantic_site_key: SemanticSiteKey::from("semantic:object"),
                type_name: "TrackedState".to_owned(),
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
    .expect("static facts should be valid")
}
