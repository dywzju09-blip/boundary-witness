use std::{
    error::Error,
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use bw_fuzz_observer::{ContractStateObserver, FeedbackStateSnapshot};
use bw_model::{
    BuildId, CallbackApiEntry, CallbackCaptureFact, CallbackRetentionContract, CaptureMode,
    ContractClause, ContractClauseKind, Finding, FindingClassification, InvokeRole, ObjectSiteFact,
    RecordId, RegistrationRole, ReleaseBehavior, RuntimeEvent, RuntimeEventEnvelope,
    SemanticSiteKey, SiteId, StaticFact, StaticFactEnvelope,
};
use bw_oracle::{Oracle, OracleEngine, StaticFactIndex};
use bw_runtime::{MemorySink, RuntimeContext};

static NEXT_ITERATION: AtomicU64 = AtomicU64::new(1);

pub type HarnessRunResult<T> = Result<T, HarnessError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarnessOutcome {
    Completed,
    InvalidInput,
    RuntimeError,
    OracleError,
    ToolError,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HarnessCounters {
    pub events: usize,
    pub callback_registrations: usize,
    pub callback_unregistrations: usize,
    pub callback_invocations: usize,
    pub object_drops: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessResult {
    pub run_id: String,
    pub outcome: HarnessOutcome,
    pub invalid_reason: Option<String>,
    pub effective_actions: usize,
    pub counters: HarnessCounters,
    pub events: Vec<RuntimeEventEnvelope>,
    pub findings: Vec<Finding>,
    pub feedback_snapshot: Option<FeedbackStateSnapshot>,
}

impl HarnessResult {
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
    pub fn normalized_signatures(&self) -> Vec<&str> {
        self.findings
            .iter()
            .map(|finding| finding.normalized_signature.as_str())
            .collect()
    }
}

#[derive(Debug)]
pub struct HarnessError {
    message: String,
}

impl HarnessError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for HarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for HarnessError {}

impl From<bw_runtime::RuntimeError> for HarnessError {
    fn from(value: bw_runtime::RuntimeError) -> Self {
        Self::new(value.to_string())
    }
}

impl From<bw_oracle::OracleError> for HarnessError {
    fn from(value: bw_oracle::OracleError) -> Self {
        Self::new(value.to_string())
    }
}

impl From<bw_fuzz_observer::ObserverError> for HarnessError {
    fn from(value: bw_fuzz_observer::ObserverError) -> Self {
        Self::new(value.to_string())
    }
}

impl From<rusqlite::Error> for HarnessError {
    fn from(value: rusqlite::Error) -> Self {
        Self::new(value.to_string())
    }
}

pub struct HarnessRuntime {
    pub run_id: String,
    pub runtime: RuntimeContext,
    pub sink: Arc<MemorySink>,
}

impl HarnessRuntime {
    pub fn start(api_label: &str) -> HarnessRunResult<Self> {
        let iteration = NEXT_ITERATION.fetch_add(1, Ordering::SeqCst);
        let run_id = format!("run:d1:{api_label}:{iteration}");
        let trace_id = format!("trace:d1:{api_label}:{iteration}");
        let sink = Arc::new(MemorySink::default());
        let runtime = RuntimeContext::new(run_id.as_str().into(), trace_id.into(), sink.clone());
        runtime.emit_trace_start(BuildId::from(build_id()))?;
        Ok(Self {
            run_id,
            runtime,
            sink,
        })
    }
}

pub fn finish_with_analysis(
    harness: HarnessRuntime,
    outcome: HarnessOutcome,
    invalid_reason: Option<String>,
    effective_actions: usize,
) -> HarnessRunResult<HarnessResult> {
    finish_with_analysis_and_feedback(harness, outcome, invalid_reason, effective_actions, false)
}

pub fn finish_with_analysis_and_feedback(
    harness: HarnessRuntime,
    mut outcome: HarnessOutcome,
    mut invalid_reason: Option<String>,
    effective_actions: usize,
    collect_feedback: bool,
) -> HarnessRunResult<HarnessResult> {
    harness.runtime.emit_trace_end()?;
    harness.runtime.finish()?;
    let events = harness.sink.snapshot();
    let counters = HarnessCounters::from_events(&events);
    let feedback_snapshot = if collect_feedback {
        match observe_feedback(events.clone()) {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                outcome = HarnessOutcome::ToolError;
                invalid_reason = Some(error.to_string());
                None
            }
        }
    } else {
        None
    };
    let findings = match analyze_events(events.clone()) {
        Ok(findings) => findings,
        Err(error) if outcome == HarnessOutcome::InvalidInput => {
            return Ok(HarnessResult {
                run_id: harness.run_id,
                outcome,
                invalid_reason,
                effective_actions,
                counters,
                events,
                findings: vec![oracle_error_finding(error)],
                feedback_snapshot,
            });
        }
        Err(error) => return Err(error.into()),
    };
    Ok(HarnessResult {
        run_id: harness.run_id,
        outcome,
        invalid_reason,
        effective_actions,
        counters,
        events,
        findings,
        feedback_snapshot,
    })
}

pub fn build_id() -> &'static str {
    "build:d1:rusqlite:callback-lifecycle"
}

pub fn site(value: &'static str) -> SiteId {
    SiteId::from(value)
}

impl HarnessCounters {
    fn from_events(events: &[RuntimeEventEnvelope]) -> Self {
        let mut counters = Self {
            events: events.len(),
            ..Self::default()
        };
        for event in events {
            match event.payload {
                RuntimeEvent::CallbackRegister(_) => counters.callback_registrations += 1,
                RuntimeEvent::CallbackUnregister(_) => counters.callback_unregistrations += 1,
                RuntimeEvent::CallbackInvoke(_) => counters.callback_invocations += 1,
                RuntimeEvent::ObjectDrop(_) => counters.object_drops += 1,
                _ => {}
            }
        }
        counters
    }
}

fn analyze_events(
    events: Vec<RuntimeEventEnvelope>,
) -> Result<Vec<Finding>, bw_oracle::OracleError> {
    let mut oracle = Oracle::new(static_facts()?, contract());
    for event in &events {
        oracle.observe(event)?;
    }
    Ok(oracle.finish()?.findings().to_vec())
}

fn observe_feedback(
    events: Vec<RuntimeEventEnvelope>,
) -> Result<FeedbackStateSnapshot, bw_fuzz_observer::ObserverError> {
    ContractStateObserver::from_static_facts(static_fact_envelopes())?.observe_all(events)
}

fn static_facts() -> Result<StaticFactIndex, bw_oracle::OracleError> {
    StaticFactIndex::from_envelopes(static_fact_envelopes())
}

fn static_fact_envelopes() -> Vec<StaticFactEnvelope> {
    vec![
        static_envelope(
            "fact:d1:update:object:borrowed",
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site("site:d1:update:object:borrowed"),
                semantic_site_key: SemanticSiteKey::from("semantic:d1:update:borrowed-object"),
                type_name: "BorrowedCounter".to_owned(),
            }),
        ),
        static_envelope(
            "fact:d1:update:object:owned",
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site("site:d1:update:object:owned"),
                semantic_site_key: SemanticSiteKey::from("semantic:d1:update:owned-object"),
                type_name: "OwnedCounter".to_owned(),
            }),
        ),
        static_envelope(
            "fact:d1:update:capture:borrowed",
            StaticFact::CallbackCapture(CallbackCaptureFact {
                site_id: site("site:d1:update:capture:borrowed"),
                semantic_site_key: SemanticSiteKey::from("semantic:d1:update:borrowed-capture"),
                callback_site_id: site("site:d1:update:callback:borrowed"),
                object_site_id: site("site:d1:update:object:borrowed"),
                capture_ordinal: 0,
                capture_mode: CaptureMode::Borrowed,
            }),
        ),
        static_envelope(
            "fact:d1:update:capture:owned",
            StaticFact::CallbackCapture(CallbackCaptureFact {
                site_id: site("site:d1:update:capture:owned"),
                semantic_site_key: SemanticSiteKey::from("semantic:d1:update:owned-capture"),
                callback_site_id: site("site:d1:update:callback:owned"),
                object_site_id: site("site:d1:update:object:owned"),
                capture_ordinal: 0,
                capture_mode: CaptureMode::Owned,
            }),
        ),
        static_envelope(
            "fact:d1:scalar:object:borrowed",
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site("site:d1:scalar:object:borrowed"),
                semantic_site_key: SemanticSiteKey::from("semantic:d1:scalar:borrowed-object"),
                type_name: "BorrowedCounter".to_owned(),
            }),
        ),
        static_envelope(
            "fact:d1:scalar:object:owned",
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site("site:d1:scalar:object:owned"),
                semantic_site_key: SemanticSiteKey::from("semantic:d1:scalar:owned-object"),
                type_name: "OwnedCounter".to_owned(),
            }),
        ),
        static_envelope(
            "fact:d1:scalar:capture:borrowed",
            StaticFact::CallbackCapture(CallbackCaptureFact {
                site_id: site("site:d1:scalar:capture:borrowed"),
                semantic_site_key: SemanticSiteKey::from("semantic:d1:scalar:borrowed-capture"),
                callback_site_id: site("site:d1:scalar:callback:borrowed"),
                object_site_id: site("site:d1:scalar:object:borrowed"),
                capture_ordinal: 0,
                capture_mode: CaptureMode::Borrowed,
            }),
        ),
        static_envelope(
            "fact:d1:scalar:capture:owned",
            StaticFact::CallbackCapture(CallbackCaptureFact {
                site_id: site("site:d1:scalar:capture:owned"),
                semantic_site_key: SemanticSiteKey::from("semantic:d1:scalar:owned-capture"),
                callback_site_id: site("site:d1:scalar:callback:owned"),
                object_site_id: site("site:d1:scalar:object:owned"),
                capture_ordinal: 0,
                capture_mode: CaptureMode::Owned,
            }),
        ),
    ]
}

fn static_envelope(record: &str, payload: StaticFact) -> StaticFactEnvelope {
    StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(record),
        producer: "bw-rusqlite-d1-harness@test".to_owned(),
        build_id: BuildId::from(build_id()),
        artifact: None,
        source_ref: None,
        payload,
    }
}

fn contract() -> CallbackRetentionContract {
    CallbackRetentionContract {
        schema_version: bw_model::CONTRACT_SCHEMA_V01.to_owned(),
        contract_id: "contract:d1:update-hook".to_owned(),
        producer: "boundary-witness@test".to_owned(),
        clauses: vec![
            ContractClause {
                clause_id: "clause:register-retains".to_owned(),
                kind: ContractClauseKind::RetainAfterRegister,
                description: "register 后外部 owner 可以保留 callback".to_owned(),
            },
            ContractClause {
                clause_id: "clause:unregister-releases".to_owned(),
                kind: ContractClauseKind::ReleaseOnUnregister,
                description: "unregister 释放 callback".to_owned(),
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
                api_id: crate::runtime::UPDATE_HOOK_API_ID.to_owned(),
                registration_role: Some(RegistrationRole::Register),
                release_behavior: ReleaseBehavior::None,
                owner_kind: "external_owner".to_owned(),
                invoke_role: None,
            },
            CallbackApiEntry {
                clause_id: "clause:unregister-releases".to_owned(),
                api_id: crate::runtime::UPDATE_HOOK_API_ID.to_owned(),
                registration_role: Some(RegistrationRole::Unregister),
                release_behavior: ReleaseBehavior::ReleaseCurrent,
                owner_kind: "external_owner".to_owned(),
                invoke_role: None,
            },
            CallbackApiEntry {
                clause_id: "clause:invoke-retained".to_owned(),
                api_id: crate::runtime::UPDATE_HOOK_API_ID.to_owned(),
                registration_role: None,
                release_behavior: ReleaseBehavior::None,
                owner_kind: "external_owner".to_owned(),
                invoke_role: Some(InvokeRole::Callback),
            },
            CallbackApiEntry {
                clause_id: "clause:register-retains".to_owned(),
                api_id: crate::runtime::CREATE_SCALAR_FUNCTION_API_ID.to_owned(),
                registration_role: Some(RegistrationRole::Register),
                release_behavior: ReleaseBehavior::None,
                owner_kind: "external_owner".to_owned(),
                invoke_role: None,
            },
            CallbackApiEntry {
                clause_id: "clause:unregister-releases".to_owned(),
                api_id: crate::runtime::CREATE_SCALAR_FUNCTION_API_ID.to_owned(),
                registration_role: Some(RegistrationRole::Unregister),
                release_behavior: ReleaseBehavior::ReleaseCurrent,
                owner_kind: "external_owner".to_owned(),
                invoke_role: None,
            },
            CallbackApiEntry {
                clause_id: "clause:invoke-retained".to_owned(),
                api_id: crate::runtime::CREATE_SCALAR_FUNCTION_API_ID.to_owned(),
                registration_role: None,
                release_behavior: ReleaseBehavior::None,
                owner_kind: "external_owner".to_owned(),
                invoke_role: Some(InvokeRole::Callback),
            },
        ],
    }
}

fn oracle_error_finding(error: bw_oracle::OracleError) -> Finding {
    Finding {
        schema_version: bw_model::FINDING_SCHEMA_V01.to_owned(),
        record_id: RecordId::from("finding:d1:oracle-error"),
        rule_id: error.code().to_owned(),
        classification: FindingClassification::Exposure,
        subject_object: None,
        subject_callback: None,
        first_violation_event: RecordId::from("record:d1:invalid"),
        evidence: Vec::new(),
        context_rule_ids: Vec::new(),
        state_before: Default::default(),
        state_after: Default::default(),
        normalized_signature: format!("{}|invalid-input", error.code()),
        producer: "bw-rusqlite-d1-harness@test".to_owned(),
        build_id: BuildId::from(build_id()),
        run_id: "run:d1:invalid".into(),
        message: error.to_string(),
    }
}
