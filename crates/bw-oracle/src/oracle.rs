use std::collections::BTreeMap;

use bw_model::{
    CallbackApiEntry, CallbackRetentionContract, CaptureMode, ContractClauseKind,
    FINDING_SCHEMA_V01, Finding, FindingClassification, FindingStateSnapshot, InstanceId,
    ObjectKind, RecordId, RegistrationRole, ReleaseBehavior, RuntimeEvent, RuntimeEventEnvelope,
    TRACE_SCHEMA_V01,
};

use crate::{
    CallbackLifecycle, CallbackState, CaptureLifecycle, CaptureState, ExternalOwnerLifecycle,
    ExternalOwnerState, ObjectLifecycle, ObjectState, OracleError, OracleState, StaticFactIndex,
    rules::{self, RuleCandidate},
    state::SubjectKey,
};

pub trait OracleEngine {
    fn observe(&mut self, event: &RuntimeEventEnvelope) -> Result<Vec<Finding>, OracleError>;
    fn finish(self) -> Result<AnalysisSummary, OracleError>;
}

pub struct Oracle {
    static_facts: StaticFactIndex,
    contract: CallbackRetentionContract,
    state: OracleState,
    findings: Vec<Finding>,
    observed_events: u64,
    next_finding: u64,
    current_run: Option<bw_model::RunId>,
    current_build: Option<bw_model::BuildId>,
}

impl Oracle {
    #[must_use]
    pub fn new(static_facts: StaticFactIndex, contract: CallbackRetentionContract) -> Self {
        Self {
            static_facts,
            contract,
            state: OracleState::default(),
            findings: Vec::new(),
            observed_events: 0,
            next_finding: 1,
            current_run: None,
            current_build: None,
        }
    }

    fn verify_event_context(&mut self, event: &RuntimeEventEnvelope) -> Result<(), OracleError> {
        if event.schema_version != TRACE_SCHEMA_V01 {
            return Err(OracleError::new(
                "BW-ORACLE-TRACE-SCHEMA",
                format!("Oracle 只接受 {TRACE_SCHEMA_V01}"),
            ));
        }
        match &event.payload {
            RuntimeEvent::TraceStart(start) => {
                if let Some(static_build) = self.static_facts.build_id()
                    && static_build != &start.build_id
                {
                    return Err(OracleError::new(
                        "BW-ORACLE-BUILD-MISMATCH",
                        format!(
                            "运行 build_id {} 与静态 build_id {} 不一致",
                            start.build_id, static_build
                        ),
                    ));
                }
                if let Some(run_id) = &self.current_run {
                    if run_id != &event.run_id {
                        return Err(OracleError::new(
                            "BW-ORACLE-RUN-MISMATCH",
                            format!("Oracle 同时收到 run_id {run_id} 和 {}", event.run_id),
                        ));
                    }
                } else {
                    self.current_run = Some(event.run_id.clone());
                }
                self.current_build = Some(start.build_id.clone());
            }
            _ => {
                let run_id = self.current_run.as_ref().ok_or_else(|| {
                    OracleError::new(
                        "BW-ORACLE-TRACE-START-MISSING",
                        "Oracle 在 trace_start 前收到运行事件",
                    )
                })?;
                if run_id != &event.run_id {
                    return Err(OracleError::new(
                        "BW-ORACLE-RUN-MISMATCH",
                        format!("事件 run_id {} 与当前 run_id {run_id} 不一致", event.run_id),
                    ));
                }
            }
        }
        Ok(())
    }

    fn reduce(&mut self, event: &RuntimeEventEnvelope) -> Result<(), OracleError> {
        match &event.payload {
            RuntimeEvent::TraceStart(_)
            | RuntimeEvent::ObjectUse(_)
            | RuntimeEvent::Checkpoint(_)
            | RuntimeEvent::TraceEnd(_) => Ok(()),
            RuntimeEvent::ObjectCreate(created) => {
                if self.state.objects.contains_key(&created.instance_id) {
                    return Err(OracleError::new(
                        "BW-ORACLE-OBJECT-DUPLICATE",
                        format!("对象 {} 被重复创建", created.instance_id),
                    ));
                }
                self.state.objects.insert(
                    created.instance_id.clone(),
                    ObjectState {
                        site_id: created.site_id.clone(),
                        object_kind: created.object_kind,
                        lifecycle: ObjectLifecycle::Live,
                        created_record: event.record_id.clone(),
                        end_record: None,
                        first_free_record: None,
                    },
                );
                if created.object_kind == ObjectKind::ExternalOwner {
                    self.state.owners.insert(
                        created.instance_id.clone(),
                        ExternalOwnerState {
                            lifecycle: ExternalOwnerLifecycle::Open,
                            close_record: None,
                        },
                    );
                }
                Ok(())
            }
            RuntimeEvent::CallbackRegister(registered) => {
                require_api_entry(&self.contract, &registered.api_id, |entry| {
                    matches!(
                        entry.registration_role,
                        Some(RegistrationRole::Register | RegistrationRole::Replace)
                    )
                })?;
                if !self
                    .state
                    .owners
                    .contains_key(&registered.owner_instance_id)
                {
                    return Err(OracleError::new(
                        "BW-ORACLE-OWNER-MISSING",
                        format!("owner {} 尚未创建", registered.owner_instance_id),
                    ));
                }
                if self
                    .state
                    .callbacks
                    .contains_key(&registered.callback_instance_id)
                {
                    return Err(OracleError::new(
                        "BW-ORACLE-CALLBACK-DUPLICATE",
                        format!("callback {} 被重复注册", registered.callback_instance_id),
                    ));
                }
                self.state.callbacks.insert(
                    registered.callback_instance_id.clone(),
                    CallbackState {
                        site_id: registered.callback_site_id.clone(),
                        owner_instance_id: registered.owner_instance_id.clone(),
                        api_id: registered.api_id.clone(),
                        lifecycle: CallbackLifecycle::Retained,
                        register_record: event.record_id.clone(),
                        release_record: None,
                    },
                );
                Ok(())
            }
            RuntimeEvent::CaptureBind(binding) => {
                if !self
                    .state
                    .callbacks
                    .contains_key(&binding.callback_instance_id)
                {
                    return Err(OracleError::new(
                        "BW-ORACLE-CALLBACK-MISSING",
                        format!("callback {} 尚未注册", binding.callback_instance_id),
                    ));
                }
                if !self.state.objects.contains_key(&binding.object_instance_id) {
                    return Err(OracleError::new(
                        "BW-ORACLE-OBJECT-MISSING",
                        format!("对象 {} 尚未创建", binding.object_instance_id),
                    ));
                }
                let (record_id, static_capture) = self
                    .static_facts
                    .capture_fact(&binding.callback_site_id, &binding.object_site_id)?;
                let key = (
                    binding.callback_instance_id.clone(),
                    binding.object_instance_id.clone(),
                );
                if self.state.captures.contains_key(&key) {
                    return Err(OracleError::new(
                        "BW-ORACLE-CAPTURE-DUPLICATE",
                        format!(
                            "callback {} 与对象 {} 被重复绑定",
                            binding.callback_instance_id, binding.object_instance_id
                        ),
                    ));
                }
                self.state.captures.insert(
                    key,
                    CaptureState {
                        capture_mode: static_capture.capture_mode,
                        lifecycle: CaptureLifecycle::Active,
                        static_fact_record: record_id.clone(),
                        bind_record: event.record_id.clone(),
                        end_record: None,
                    },
                );
                Ok(())
            }
            RuntimeEvent::CallbackUnregister(unregistered) => {
                require_api_entry(&self.contract, &unregistered.api_id, |entry| {
                    entry.registration_role == Some(RegistrationRole::Unregister)
                        && entry.release_behavior != ReleaseBehavior::None
                })?;
                let callback = self
                    .state
                    .callbacks
                    .get_mut(&unregistered.callback_instance_id)
                    .ok_or_else(|| {
                        OracleError::new(
                            "BW-ORACLE-CALLBACK-MISSING",
                            format!("callback {} 尚未注册", unregistered.callback_instance_id),
                        )
                    })?;
                if callback.owner_instance_id != unregistered.owner_instance_id {
                    return Err(OracleError::new(
                        "BW-ORACLE-OWNER-MISMATCH",
                        format!(
                            "callback {} 的 owner 与注销事件不一致",
                            unregistered.callback_instance_id
                        ),
                    ));
                }
                callback.lifecycle = CallbackLifecycle::Released;
                callback.release_record = Some(event.record_id.clone());
                Ok(())
            }
            RuntimeEvent::CallbackInvoke(invoked) => {
                require_api_entry(&self.contract, &invoked.api_id, |entry| {
                    entry.invoke_role == Some(bw_model::InvokeRole::Callback)
                })?;
                if !self
                    .state
                    .callbacks
                    .contains_key(&invoked.callback_instance_id)
                {
                    return Err(OracleError::new(
                        "BW-ORACLE-CALLBACK-MISSING",
                        format!("callback {} 尚未注册", invoked.callback_instance_id),
                    ));
                }
                Ok(())
            }
            RuntimeEvent::ObjectDrop(dropped) => {
                let object_kind = {
                    let object = self
                        .state
                        .objects
                        .get_mut(&dropped.instance_id)
                        .ok_or_else(|| {
                            OracleError::new(
                                "BW-ORACLE-OBJECT-MISSING",
                                format!("对象 {} 尚未创建", dropped.instance_id),
                            )
                        })?;
                    if object.lifecycle != ObjectLifecycle::Freed {
                        object.lifecycle = ObjectLifecycle::Ended;
                        object
                            .end_record
                            .get_or_insert_with(|| event.record_id.clone());
                    }
                    object.object_kind
                };
                self.end_borrowed_captures(&dropped.instance_id, &event.record_id);
                if object_kind == ObjectKind::ExternalOwner {
                    rules::require_clause(&self.contract, ContractClauseKind::ReleaseOnOwnerDrop)?;
                    if let Some(owner) = self.state.owners.get_mut(&dropped.instance_id) {
                        owner.lifecycle = ExternalOwnerLifecycle::Closed;
                        owner.close_record = Some(event.record_id.clone());
                    }
                    for callback in self
                        .state
                        .callbacks
                        .values_mut()
                        .filter(|callback| callback.owner_instance_id == dropped.instance_id)
                    {
                        callback.lifecycle = CallbackLifecycle::Released;
                        callback.release_record = Some(event.record_id.clone());
                    }
                }
                Ok(())
            }
            RuntimeEvent::ObjectFree(freed) => {
                let first_free = {
                    let object =
                        self.state
                            .objects
                            .get_mut(&freed.instance_id)
                            .ok_or_else(|| {
                                OracleError::new(
                                    "BW-ORACLE-OBJECT-MISSING",
                                    format!("对象 {} 尚未创建", freed.instance_id),
                                )
                            })?;
                    if object.lifecycle == ObjectLifecycle::Freed {
                        false
                    } else {
                        object.lifecycle = ObjectLifecycle::Freed;
                        object.end_record = Some(event.record_id.clone());
                        object.first_free_record = Some(event.record_id.clone());
                        true
                    }
                };
                if first_free {
                    self.end_borrowed_captures(&freed.instance_id, &event.record_id);
                }
                Ok(())
            }
        }
    }

    fn end_borrowed_captures(&mut self, object_id: &InstanceId, record_id: &RecordId) {
        for ((_, captured_object), capture) in
            self.state
                .captures
                .iter_mut()
                .filter(|((_, captured_object), capture)| {
                    captured_object == object_id
                        && capture.capture_mode == CaptureMode::Borrowed
                        && capture.lifecycle == CaptureLifecycle::Active
                })
        {
            debug_assert_eq!(captured_object, object_id);
            capture.lifecycle = CaptureLifecycle::Ended;
            capture.end_record = Some(record_id.clone());
        }
    }

    fn make_finding(
        &mut self,
        event: &RuntimeEventEnvelope,
        candidate: RuleCandidate,
        before: &BTreeMap<SubjectKey, FindingStateSnapshot>,
    ) -> Result<Finding, OracleError> {
        let build_id = self.current_build.clone().ok_or_else(|| {
            OracleError::new(
                "BW-ORACLE-BUILD-MISSING",
                "生成 finding 时缺少 trace_start build_id",
            )
        })?;
        let record_id = RecordId::from(format!("finding:{}", self.next_finding));
        self.next_finding += 1;
        Ok(Finding {
            schema_version: FINDING_SCHEMA_V01.to_owned(),
            record_id,
            rule_id: candidate.rule_id.to_owned(),
            classification: candidate.classification,
            subject_object: candidate.subject.object.clone(),
            subject_callback: candidate.subject.callback.clone(),
            first_violation_event: event.record_id.clone(),
            evidence: candidate.evidence,
            context_rule_ids: candidate.context_rule_ids,
            state_before: before.get(&candidate.subject).cloned().unwrap_or_default(),
            state_after: self.state.snapshot(&candidate.subject),
            normalized_signature: candidate.normalized_signature,
            producer: "bw-oracle@0.1".to_owned(),
            build_id,
            run_id: event.run_id.clone(),
            message: candidate.message,
        })
    }
}

impl OracleEngine for Oracle {
    fn observe(&mut self, event: &RuntimeEventEnvelope) -> Result<Vec<Finding>, OracleError> {
        self.verify_event_context(event)?;
        let subjects = self.state.subjects_for_event(&event.payload);
        let before = subjects
            .into_iter()
            .map(|subject| {
                let snapshot = self.state.snapshot(&subject);
                (subject, snapshot)
            })
            .collect::<BTreeMap<_, _>>();
        self.reduce(event)?;
        let candidates = rules::evaluate(
            event,
            &self.state,
            &self.static_facts,
            &self.contract,
            &before,
        )?;
        let candidates = select_highest_priority(candidates);
        let mut emitted = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            emitted.push(self.make_finding(event, candidate, &before)?);
        }
        self.observed_events += 1;
        self.findings.extend(emitted.iter().cloned());
        Ok(emitted)
    }

    fn finish(self) -> Result<AnalysisSummary, OracleError> {
        Ok(AnalysisSummary {
            findings: self.findings,
            observed_events: self.observed_events,
        })
    }
}

fn require_api_entry<'a>(
    contract: &'a CallbackRetentionContract,
    api_id: &str,
    predicate: impl Fn(&CallbackApiEntry) -> bool,
) -> Result<&'a CallbackApiEntry, OracleError> {
    let mut matches = contract
        .api_entries
        .iter()
        .filter(|entry| entry.api_id == api_id && predicate(entry));
    let entry = matches.next().ok_or_else(|| {
        OracleError::new(
            "BW-ORACLE-CONTRACT-API-MISSING",
            format!("contract 缺少 api_id {api_id} 的兼容 role"),
        )
    })?;
    if matches.next().is_some() {
        return Err(OracleError::new(
            "BW-ORACLE-CONTRACT-API-AMBIGUOUS",
            format!("api_id {api_id} 匹配多条 contract role"),
        ));
    }
    Ok(entry)
}

fn select_highest_priority(candidates: Vec<RuleCandidate>) -> Vec<RuleCandidate> {
    let mut selected = BTreeMap::<SubjectKey, RuleCandidate>::new();
    for mut candidate in candidates {
        match selected.get_mut(&candidate.subject) {
            None => {
                selected.insert(candidate.subject.clone(), candidate);
            }
            Some(existing) if candidate.priority > existing.priority => {
                candidate
                    .context_rule_ids
                    .append(&mut existing.context_rule_ids);
                candidate.context_rule_ids.push(existing.rule_id.to_owned());
                *existing = candidate;
            }
            Some(existing) => {
                existing.context_rule_ids.push(candidate.rule_id.to_owned());
            }
        }
    }
    let mut selected = selected.into_values().collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.subject.cmp(&right.subject))
    });
    selected
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisSummary {
    findings: Vec<Finding>,
    pub observed_events: u64,
}

impl AnalysisSummary {
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    #[must_use]
    pub fn finding(&self, rule_id: &str) -> Option<&Finding> {
        self.findings
            .iter()
            .find(|finding| finding.rule_id == rule_id)
    }

    #[must_use]
    pub fn rule_ids(&self) -> Vec<&str> {
        self.findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect()
    }

    #[must_use]
    pub fn core_rule_ids(&self) -> Vec<&str> {
        self.findings
            .iter()
            .filter(|finding| finding.classification == FindingClassification::ConfirmedViolation)
            .map(|finding| finding.rule_id.as_str())
            .collect()
    }

    #[must_use]
    pub fn exposure_rule_ids(&self) -> Vec<&str> {
        self.findings
            .iter()
            .filter(|finding| finding.classification == FindingClassification::Exposure)
            .map(|finding| finding.rule_id.as_str())
            .collect()
    }

    pub fn normalized_findings(&self) -> Result<Vec<crate::NormalizedFinding>, OracleError> {
        self.findings.iter().map(crate::normalize_finding).collect()
    }

    pub fn normalized_signatures(&self) -> Result<Vec<String>, OracleError> {
        let mut signatures = self
            .normalized_findings()?
            .into_iter()
            .map(|finding| finding.signature)
            .collect::<Vec<_>>();
        signatures.sort();
        signatures.dedup();
        Ok(signatures)
    }
}

#[cfg(test)]
mod tests {
    use bw_model::FindingClassification;

    use super::{RuleCandidate, SubjectKey, select_highest_priority};

    fn candidate(rule_id: &'static str, priority: u16) -> RuleCandidate {
        RuleCandidate {
            rule_id,
            priority,
            classification: FindingClassification::ConfirmedViolation,
            subject: SubjectKey {
                object: Some(bw_model::InstanceId::from("object:1")),
                callback: Some(bw_model::InstanceId::from("callback:1")),
            },
            evidence: Vec::new(),
            message: String::new(),
            normalized_signature: String::new(),
            context_rule_ids: Vec::new(),
        }
    }

    #[test]
    fn highest_priority_rule_wins_for_same_event_subject() {
        let selected = select_highest_priority(vec![
            candidate("BW-LIFE-003", 100),
            candidate("BW-LIFE-002", 300),
            candidate("BW-LIFE-001", 400),
        ]);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].rule_id, "BW-LIFE-001");
        assert_eq!(selected[0].context_rule_ids, ["BW-LIFE-003", "BW-LIFE-002"]);
    }
}
