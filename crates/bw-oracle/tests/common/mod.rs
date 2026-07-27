use bw_model::{
    BuildId, EvidenceReference, EvidenceSourceKind, Finding, FindingClassification,
    FindingStateSnapshot, InstanceId, RecordId, RunId,
};

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
