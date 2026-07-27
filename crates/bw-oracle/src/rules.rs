use std::collections::BTreeMap;

use bw_model::{
    CallbackRetentionContract, CaptureMode, ContractClauseKind, EvidenceReference,
    EvidenceSourceKind, FindingClassification, FindingStateSnapshot, InstanceId, RecordId,
    RuntimeEvent, RuntimeEventEnvelope,
};

use crate::{
    CallbackLifecycle, CaptureLifecycle, ObjectLifecycle, OracleError, OracleState,
    StaticFactIndex, state::SubjectKey,
};

pub(crate) const LIFE_001_PRIORITY: u16 = 400;
pub(crate) const LIFE_002_PRIORITY: u16 = 300;
pub(crate) const FREE_001_PRIORITY: u16 = 200;
pub(crate) const LIFE_003_PRIORITY: u16 = 100;

#[derive(Clone, Debug)]
pub(crate) struct RuleCandidate {
    pub rule_id: &'static str,
    pub priority: u16,
    pub classification: FindingClassification,
    pub subject: SubjectKey,
    pub evidence: Vec<EvidenceReference>,
    pub message: String,
    pub normalized_signature: String,
    pub context_rule_ids: Vec<String>,
}

pub(crate) fn evaluate(
    event: &RuntimeEventEnvelope,
    state: &OracleState,
    static_facts: &StaticFactIndex,
    contract: &CallbackRetentionContract,
    before: &BTreeMap<SubjectKey, FindingStateSnapshot>,
) -> Result<Vec<RuleCandidate>, OracleError> {
    match &event.payload {
        RuntimeEvent::ObjectUse(used) => {
            evaluate_object_use(event, &used.instance_id, state, static_facts, contract)
        }
        RuntimeEvent::CallbackInvoke(invoked) => evaluate_callback_invoke(
            event,
            &invoked.callback_instance_id,
            state,
            static_facts,
            contract,
        ),
        RuntimeEvent::ObjectDrop(dropped) => evaluate_borrow_end(
            event,
            &dropped.instance_id,
            state,
            static_facts,
            contract,
            before,
        ),
        RuntimeEvent::ObjectFree(freed) => {
            let mut candidates = evaluate_borrow_end(
                event,
                &freed.instance_id,
                state,
                static_facts,
                contract,
                before,
            )?;
            if let Some(candidate) = evaluate_repeated_free(
                event,
                &freed.instance_id,
                state,
                static_facts,
                contract,
                before,
            )? {
                candidates.push(candidate);
            }
            Ok(candidates)
        }
        _ => Ok(Vec::new()),
    }
}

fn evaluate_object_use(
    event: &RuntimeEventEnvelope,
    object_id: &InstanceId,
    state: &OracleState,
    static_facts: &StaticFactIndex,
    contract: &CallbackRetentionContract,
) -> Result<Vec<RuleCandidate>, OracleError> {
    let object = require_object(state, object_id)?;
    if object.lifecycle == ObjectLifecycle::Live {
        return Ok(Vec::new());
    }
    let (static_record, object_fact) = static_facts.object_fact(&object.site_id)?;
    let semantic_key = static_facts
        .semantic_key(&object.site_id)
        .unwrap_or(&object_fact.semantic_site_key);
    let clause = require_clause(contract, ContractClauseKind::NoUseAfterLifetimeEnd)?;
    let end_record = object.end_record.as_ref().ok_or_else(|| {
        OracleError::new(
            "BW-ORACLE-EVIDENCE-END-MISSING",
            format!("对象 {object_id} 已结束但缺少结束事件引用"),
        )
    })?;
    Ok(vec![RuleCandidate {
        rule_id: "BW-LIFE-001",
        priority: LIFE_001_PRIORITY,
        classification: FindingClassification::ConfirmedViolation,
        subject: SubjectKey {
            object: Some(object_id.clone()),
            callback: None,
        },
        evidence: evidence(
            static_record,
            "BW-EVIDENCE-OBJECT-SITE",
            &clause.clause_id,
            [
                (end_record, "BW-EVIDENCE-LIFETIME-END"),
                (&event.record_id, "BW-EVIDENCE-OBJECT-USE"),
            ],
        ),
        message: format!("对象 {object_id} 在生命周期结束后被使用"),
        normalized_signature: format!("BW-LIFE-001|{semantic_key}"),
        context_rule_ids: Vec::new(),
    }])
}

fn evaluate_callback_invoke(
    event: &RuntimeEventEnvelope,
    callback_id: &InstanceId,
    state: &OracleState,
    static_facts: &StaticFactIndex,
    contract: &CallbackRetentionContract,
) -> Result<Vec<RuleCandidate>, OracleError> {
    let callback = state.callbacks.get(callback_id).ok_or_else(|| {
        OracleError::new(
            "BW-ORACLE-CALLBACK-MISSING",
            format!("callback {callback_id} 尚未注册"),
        )
    })?;
    let clause = require_clause(contract, ContractClauseKind::BorrowMustOutliveRetention)?;
    let mut candidates = Vec::new();
    for ((captured_callback, object_id), capture) in
        state
            .captures
            .iter()
            .filter(|((captured_callback, _), capture)| {
                captured_callback == callback_id
                    && capture.capture_mode == CaptureMode::Borrowed
                    && capture.lifecycle == CaptureLifecycle::Ended
            })
    {
        let object = require_object(state, object_id)?;
        let (static_record, capture_fact) =
            static_facts.capture_fact(&callback.site_id, &object.site_id)?;
        let semantic_key = static_facts
            .semantic_key(&capture_fact.site_id)
            .unwrap_or(&capture_fact.semantic_site_key);
        let end_record = capture.end_record.as_ref().ok_or_else(|| {
            OracleError::new(
                "BW-ORACLE-EVIDENCE-END-MISSING",
                format!(
                    "borrow {} -> {} 已结束但缺少事件引用",
                    callback_id, object_id
                ),
            )
        })?;
        candidates.push(RuleCandidate {
            rule_id: "BW-LIFE-002",
            priority: LIFE_002_PRIORITY,
            classification: FindingClassification::ConfirmedViolation,
            subject: SubjectKey {
                object: Some(object_id.clone()),
                callback: Some(captured_callback.clone()),
            },
            evidence: evidence(
                static_record,
                "BW-EVIDENCE-BORROWED-CAPTURE",
                &clause.clause_id,
                [
                    (&capture.bind_record, "BW-EVIDENCE-CAPTURE-BIND"),
                    (end_record, "BW-EVIDENCE-BORROW-END"),
                    (&event.record_id, "BW-EVIDENCE-CALLBACK-INVOKE"),
                ],
            ),
            message: format!("callback {callback_id} 在 borrow {object_id} 结束后被调用"),
            normalized_signature: format!("BW-LIFE-002|{semantic_key}"),
            context_rule_ids: Vec::new(),
        });
    }
    Ok(candidates)
}

fn evaluate_borrow_end(
    event: &RuntimeEventEnvelope,
    object_id: &InstanceId,
    state: &OracleState,
    static_facts: &StaticFactIndex,
    contract: &CallbackRetentionContract,
    before: &BTreeMap<SubjectKey, FindingStateSnapshot>,
) -> Result<Vec<RuleCandidate>, OracleError> {
    let object = require_object(state, object_id)?;
    let clause = require_clause(contract, ContractClauseKind::BorrowMustOutliveRetention)?;
    let mut candidates = Vec::new();
    for ((callback_id, captured_object), capture) in
        state
            .captures
            .iter()
            .filter(|((_, captured_object), capture)| {
                captured_object == object_id
                    && capture.capture_mode == CaptureMode::Borrowed
                    && capture.lifecycle == CaptureLifecycle::Ended
            })
    {
        let callback = state.callbacks.get(callback_id).ok_or_else(|| {
            OracleError::new(
                "BW-ORACLE-CALLBACK-MISSING",
                format!("capture 引用了未知 callback {callback_id}"),
            )
        })?;
        if callback.lifecycle != CallbackLifecycle::Retained {
            continue;
        }
        let subject = SubjectKey {
            object: Some(captured_object.clone()),
            callback: Some(callback_id.clone()),
        };
        if before
            .get(&subject)
            .and_then(|snapshot| snapshot.capture_state.as_deref())
            != Some("active")
        {
            continue;
        }
        let (static_record, capture_fact) =
            static_facts.capture_fact(&callback.site_id, &object.site_id)?;
        let semantic_key = static_facts
            .semantic_key(&capture_fact.site_id)
            .unwrap_or(&capture_fact.semantic_site_key);
        candidates.push(RuleCandidate {
            rule_id: "BW-LIFE-003",
            priority: LIFE_003_PRIORITY,
            classification: FindingClassification::Exposure,
            subject,
            evidence: evidence(
                static_record,
                "BW-EVIDENCE-BORROWED-CAPTURE",
                &clause.clause_id,
                [
                    (&capture.bind_record, "BW-EVIDENCE-CAPTURE-BIND"),
                    (&callback.register_record, "BW-EVIDENCE-CALLBACK-RETAINED"),
                    (&event.record_id, "BW-EVIDENCE-BORROW-END"),
                ],
            ),
            message: format!("borrow {object_id} 已结束，但 callback {callback_id} 仍被外部保留"),
            normalized_signature: format!("BW-LIFE-003|{semantic_key}"),
            context_rule_ids: Vec::new(),
        });
    }
    Ok(candidates)
}

fn evaluate_repeated_free(
    event: &RuntimeEventEnvelope,
    object_id: &InstanceId,
    state: &OracleState,
    static_facts: &StaticFactIndex,
    contract: &CallbackRetentionContract,
    before: &BTreeMap<SubjectKey, FindingStateSnapshot>,
) -> Result<Option<RuleCandidate>, OracleError> {
    let subject = SubjectKey {
        object: Some(object_id.clone()),
        callback: None,
    };
    if before
        .get(&subject)
        .and_then(|snapshot| snapshot.object_state.as_deref())
        != Some("freed")
    {
        return Ok(None);
    }
    let object = require_object(state, object_id)?;
    let first_free = object.first_free_record.as_ref().ok_or_else(|| {
        OracleError::new(
            "BW-ORACLE-EVIDENCE-FREE-MISSING",
            format!("对象 {object_id} 标记为 freed 但缺少首次 free 事件"),
        )
    })?;
    let (static_record, object_fact) = static_facts.object_fact(&object.site_id)?;
    let semantic_key = static_facts
        .semantic_key(&object.site_id)
        .unwrap_or(&object_fact.semantic_site_key);
    let clause = require_clause(contract, ContractClauseKind::FreeAtMostOnce)?;
    Ok(Some(RuleCandidate {
        rule_id: "BW-FREE-001",
        priority: FREE_001_PRIORITY,
        classification: FindingClassification::ConfirmedViolation,
        subject,
        evidence: evidence(
            static_record,
            "BW-EVIDENCE-OBJECT-SITE",
            &clause.clause_id,
            [
                (first_free, "BW-EVIDENCE-FIRST-FREE"),
                (&event.record_id, "BW-EVIDENCE-REPEATED-FREE"),
            ],
        ),
        message: format!("对象 {object_id} 的同一代次被再次释放"),
        normalized_signature: format!("BW-FREE-001|{semantic_key}"),
        context_rule_ids: Vec::new(),
    }))
}

fn require_object<'a>(
    state: &'a OracleState,
    object_id: &InstanceId,
) -> Result<&'a crate::ObjectState, OracleError> {
    state.objects.get(object_id).ok_or_else(|| {
        OracleError::new(
            "BW-ORACLE-OBJECT-MISSING",
            format!("对象 {object_id} 尚未创建"),
        )
    })
}

pub(crate) fn require_clause(
    contract: &CallbackRetentionContract,
    kind: ContractClauseKind,
) -> Result<&bw_model::ContractClause, OracleError> {
    let mut matches = contract.clauses.iter().filter(|clause| clause.kind == kind);
    let clause = matches.next().ok_or_else(|| {
        OracleError::new(
            "BW-ORACLE-CONTRACT-CLAUSE-MISSING",
            format!("contract 缺少 {kind:?} clause"),
        )
    })?;
    if matches.next().is_some() {
        return Err(OracleError::new(
            "BW-ORACLE-CONTRACT-CLAUSE-AMBIGUOUS",
            format!("contract 包含多条 {kind:?} clause"),
        ));
    }
    Ok(clause)
}

fn evidence<'a>(
    static_record: &RecordId,
    static_description: &str,
    clause_id: &str,
    runtime_records: impl IntoIterator<Item = (&'a RecordId, &'static str)>,
) -> Vec<EvidenceReference> {
    let mut evidence = vec![
        EvidenceReference {
            record_id: static_record.clone(),
            source_kind: EvidenceSourceKind::StaticFact,
            description_code: static_description.to_owned(),
        },
        EvidenceReference {
            record_id: RecordId::from(clause_id),
            source_kind: EvidenceSourceKind::ContractClause,
            description_code: "BW-EVIDENCE-CONTRACT-CLAUSE".to_owned(),
        },
    ];
    evidence.extend(
        runtime_records
            .into_iter()
            .map(|(record_id, description_code)| EvidenceReference {
                record_id: record_id.clone(),
                source_kind: EvidenceSourceKind::RuntimeEvent,
                description_code: description_code.to_owned(),
            }),
    );
    evidence
}
