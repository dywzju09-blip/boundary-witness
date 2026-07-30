use std::{fs, path::PathBuf};

use bw_model::{
    BuildId, CallbackApiEntry, CallbackInvokeEvent, CallbackRegisterEvent, CallbackReleaseReason,
    CallbackRetentionContract, CallbackUnregisterEvent, CaptureBindEvent, CaptureMode,
    CheckpointEvent, CheckpointKind, ContractClause, ContractClauseKind, InvokeRole,
    ObjectCreateEvent, ObjectDropEvent, ObjectFreeEvent, ObjectKind, ObjectUseEvent, ObjectUseKind,
    RegistrationRole, ReleaseBehavior, RuntimeEvent, RuntimeEventEnvelope, StaticFactEnvelope,
    TraceStartEvent,
};
use bw_oracle::{Oracle, OracleEngine, StaticFactIndex, normalize_finding};
use proptest::prelude::*;

mod common;

use common::{event, instance, setup_events, site, static_facts};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(path: &str) -> PathBuf {
    workspace_root().join(path)
}

fn contract() -> CallbackRetentionContract {
    CallbackRetentionContract {
        schema_version: bw_model::CONTRACT_SCHEMA_V01.to_owned(),
        contract_id: "contract:callback-retention".to_owned(),
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
                description: "unregister 释放 callback".to_owned(),
            },
            ContractClause {
                clause_id: "clause:owner-drop-releases".to_owned(),
                kind: ContractClauseKind::ReleaseOnOwnerDrop,
                description: "owner drop 时释放 callback".to_owned(),
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
            ContractClause {
                clause_id: "clause:free-once".to_owned(),
                kind: ContractClauseKind::FreeAtMostOnce,
                description: "同一对象代次最多释放一次".to_owned(),
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
                clause_id: "clause:unregister-releases".to_owned(),
                api_id: "api:unregister".to_owned(),
                registration_role: Some(RegistrationRole::Unregister),
                release_behavior: ReleaseBehavior::ReleaseCurrent,
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

fn analyze_events(
    mode: CaptureMode,
    events: impl IntoIterator<Item = RuntimeEventEnvelope>,
) -> bw_oracle::AnalysisSummary {
    let mut oracle = Oracle::new(static_facts(mode), contract());
    for event in events {
        let _ = oracle.observe(&event);
    }
    oracle.finish().expect("analysis should finish")
}

proptest! {
    #[test]
    fn normalizing_renumbered_findings_keeps_signature(suffix in "[a-z]{1,8}") {
        let mut first = common::sample_finding("first");
        let mut second = common::sample_finding(&suffix);
        first.normalized_signature = "BW-LIFE-002|semantic:capture".to_owned();
        second.normalized_signature = "BW-LIFE-002|semantic:capture".to_owned();

        prop_assert_eq!(
            normalize_finding(&first).unwrap().signature,
            normalize_finding(&second).unwrap().signature
        );
    }

    #[test]
    fn arbitrary_event_prefixes_do_not_panic(actions in prop::collection::vec(any::<u8>(), 0..32)) {
        let result = std::panic::catch_unwind(|| {
            let mut oracle = Oracle::new(static_facts(CaptureMode::Borrowed), contract());
            for (index, action) in actions.into_iter().enumerate() {
                let _ = oracle.observe(&event(index as u64, action_event(index as u64, action)));
            }
            let _ = oracle.finish();
        });
        prop_assert!(result.is_ok());
    }
}

#[test]
fn no_end_or_free_events_do_not_produce_uaf_or_double_free() {
    let mut events = setup_events();
    events.push(event(
        5,
        RuntimeEvent::CallbackInvoke(CallbackInvokeEvent {
            callback_instance_id: instance("callback:1"),
            invoke_site_id: site("site:invoke"),
            api_id: "api:invoke".to_owned(),
        }),
    ));
    events.push(event(
        6,
        RuntimeEvent::ObjectUse(ObjectUseEvent {
            instance_id: instance("object:1"),
            use_site_id: site("site:use"),
            use_kind: ObjectUseKind::Read,
        }),
    ));

    let summary = analyze_events(CaptureMode::Borrowed, events);
    assert!(summary.core_rule_ids().is_empty());
}

#[test]
fn appending_second_free_produces_one_free_001() {
    let events = vec![
        event(
            0,
            RuntimeEvent::TraceStart(TraceStartEvent {
                build_id: BuildId::from("build:test"),
            }),
        ),
        event(
            1,
            RuntimeEvent::ObjectCreate(ObjectCreateEvent {
                instance_id: instance("object:1"),
                site_id: site("site:object"),
                object_kind: ObjectKind::Tracked,
                epoch: 0,
                address_diag: None,
            }),
        ),
        event(
            2,
            RuntimeEvent::ObjectFree(ObjectFreeEvent {
                instance_id: instance("object:1"),
                free_site_id: site("site:free-1"),
            }),
        ),
        event(
            3,
            RuntimeEvent::ObjectFree(ObjectFreeEvent {
                instance_id: instance("object:1"),
                free_site_id: site("site:free-2"),
            }),
        ),
    ];

    let summary = analyze_events(CaptureMode::Borrowed, events);
    assert_eq!(
        summary
            .core_rule_ids()
            .into_iter()
            .filter(|rule_id| *rule_id == "BW-FREE-001")
            .count(),
        1
    );
}

#[test]
fn frozen_fixtures_match_expected_outcomes() {
    let contract = CallbackRetentionContract::from_toml_str(
        &fs::read_to_string(fixture("contracts/callback-retention/contract.toml")).unwrap(),
    )
    .unwrap();
    let static_facts = StaticFactIndex::from_envelopes(read_static_fixture(
        "fixtures/valid/callback-retention.static.jsonl",
    ))
    .unwrap();

    let exposed = analyze_fixture(
        static_facts.clone(),
        contract.clone(),
        &format!(
            "fixtures/{}{}/borrowed-callback-uaf.trace.jsonl",
            "vulnera", "ble"
        ),
    );
    let expected: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(fixture(
            "fixtures/expected/borrowed-callback-uaf.rules.json",
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        exposed.core_rule_ids(),
        expected["core_rule_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        exposed.exposure_rule_ids(),
        expected["exposure_rule_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );

    let fixed = analyze_fixture(
        static_facts,
        contract,
        "fixtures/fixed/unregister-before-end.trace.jsonl",
    );
    assert!(fixed.core_rule_ids().is_empty());
    assert!(fixed.exposure_rule_ids().is_empty());
}

fn action_event(seq: u64, action: u8) -> RuntimeEvent {
    match action % 11 {
        0 => RuntimeEvent::TraceStart(TraceStartEvent {
            build_id: BuildId::from("build:test"),
        }),
        1 => RuntimeEvent::ObjectCreate(ObjectCreateEvent {
            instance_id: instance("owner:1"),
            site_id: site("site:owner"),
            object_kind: ObjectKind::ExternalOwner,
            epoch: seq,
            address_diag: None,
        }),
        2 => RuntimeEvent::ObjectCreate(ObjectCreateEvent {
            instance_id: instance("object:1"),
            site_id: site("site:object"),
            object_kind: ObjectKind::Tracked,
            epoch: seq,
            address_diag: None,
        }),
        3 => RuntimeEvent::CallbackRegister(CallbackRegisterEvent {
            callback_instance_id: instance("callback:1"),
            callback_site_id: site("site:callback"),
            owner_instance_id: instance("owner:1"),
            registration_site_id: site("site:register"),
            api_id: "api:register".to_owned(),
        }),
        4 => RuntimeEvent::CaptureBind(CaptureBindEvent {
            callback_instance_id: instance("callback:1"),
            callback_site_id: site("site:callback"),
            object_instance_id: instance("object:1"),
            object_site_id: site("site:object"),
        }),
        5 => RuntimeEvent::CallbackUnregister(CallbackUnregisterEvent {
            callback_instance_id: instance("callback:1"),
            owner_instance_id: instance("owner:1"),
            unregister_site_id: site("site:unregister"),
            api_id: "api:unregister".to_owned(),
            reason: CallbackReleaseReason::Explicit,
        }),
        6 => RuntimeEvent::CallbackInvoke(CallbackInvokeEvent {
            callback_instance_id: instance("callback:1"),
            invoke_site_id: site("site:invoke"),
            api_id: "api:invoke".to_owned(),
        }),
        7 => RuntimeEvent::ObjectDrop(ObjectDropEvent {
            instance_id: instance("object:1"),
            drop_site_id: site("site:drop"),
        }),
        8 => RuntimeEvent::ObjectFree(ObjectFreeEvent {
            instance_id: instance("object:1"),
            free_site_id: site("site:free"),
        }),
        9 => RuntimeEvent::ObjectUse(ObjectUseEvent {
            instance_id: instance("object:1"),
            use_site_id: site("site:use"),
            use_kind: ObjectUseKind::Read,
        }),
        _ => RuntimeEvent::Checkpoint(CheckpointEvent {
            checkpoint: CheckpointKind::LaterCallbackPhase,
        }),
    }
}

fn read_static_fixture(path: &str) -> Vec<StaticFactEnvelope> {
    fs::read_to_string(fixture(path))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn read_trace_fixture(path: &str) -> Vec<RuntimeEventEnvelope> {
    fs::read_to_string(fixture(path))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn analyze_fixture(
    static_facts: StaticFactIndex,
    contract: CallbackRetentionContract,
    trace: &str,
) -> bw_oracle::AnalysisSummary {
    bw_model::validate_runtime_path(fixture(trace), 1024 * 1024).unwrap();
    let mut oracle = Oracle::new(static_facts, contract);
    for event in read_trace_fixture(trace) {
        oracle.observe(&event).unwrap();
    }
    oracle.finish().unwrap()
}
