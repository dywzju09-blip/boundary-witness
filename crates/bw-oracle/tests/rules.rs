use bw_model::{
    CallbackApiEntry, CallbackInvokeEvent, CallbackRetentionContract, CallbackUnregisterEvent,
    CaptureMode, ContractClause, ContractClauseKind, InvokeRole, ObjectFreeEvent, ObjectUseEvent,
    ObjectUseKind, RegistrationRole, ReleaseBehavior, RuntimeEvent, RuntimeEventEnvelope,
};
use bw_oracle::{Oracle, OracleEngine};

mod common;

use common::{event, instance, setup_events, site, static_facts};

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
                clause_id: "clause:unregister-releases".to_owned(),
                kind: ContractClauseKind::ReleaseOnUnregister,
                description: "unregister 释放 callback".to_owned(),
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

fn oracle(mode: CaptureMode) -> Oracle {
    Oracle::new(static_facts(mode), contract())
}

fn observe_all(oracle: &mut Oracle, events: impl IntoIterator<Item = RuntimeEventEnvelope>) {
    for event in events {
        oracle.observe(&event).expect("event should be observed");
    }
}

fn drop_object(seq: u64) -> RuntimeEventEnvelope {
    event(
        seq,
        RuntimeEvent::ObjectDrop(bw_model::ObjectDropEvent {
            instance_id: instance("object:1"),
            drop_site_id: site("site:drop"),
        }),
    )
}

#[test]
fn borrow_end_while_retained_emits_life_003_exposure() {
    let mut oracle = oracle(CaptureMode::Borrowed);
    observe_all(&mut oracle, setup_events());
    oracle
        .observe(&drop_object(5))
        .expect("drop should be observed");

    let summary = oracle.finish().expect("analysis should finish");
    assert_eq!(summary.exposure_rule_ids(), vec!["BW-LIFE-003"]);
    assert!(summary.core_rule_ids().is_empty());
}

#[test]
fn invoked_after_borrow_end_emits_life_002() {
    let mut oracle = oracle(CaptureMode::Borrowed);
    observe_all(&mut oracle, setup_events());
    observe_all(
        &mut oracle,
        [
            drop_object(5),
            event(
                6,
                RuntimeEvent::CallbackInvoke(CallbackInvokeEvent {
                    callback_instance_id: instance("callback:1"),
                    invoke_site_id: site("site:invoke"),
                    api_id: "api:invoke".to_owned(),
                }),
            ),
        ],
    );

    assert_eq!(
        oracle
            .finish()
            .expect("analysis should finish")
            .core_rule_ids(),
        vec!["BW-LIFE-002"]
    );
}

#[test]
fn actual_use_after_end_emits_life_001() {
    let mut oracle = oracle(CaptureMode::Borrowed);
    observe_all(&mut oracle, setup_events());
    observe_all(
        &mut oracle,
        [
            drop_object(5),
            event(
                6,
                RuntimeEvent::ObjectUse(ObjectUseEvent {
                    instance_id: instance("object:1"),
                    use_site_id: site("site:use"),
                    use_kind: ObjectUseKind::Read,
                }),
            ),
        ],
    );

    assert_eq!(
        oracle
            .finish()
            .expect("analysis should finish")
            .core_rule_ids(),
        vec!["BW-LIFE-001"]
    );
}

#[test]
fn second_free_emits_free_001() {
    let mut oracle = oracle(CaptureMode::Borrowed);
    observe_all(
        &mut oracle,
        setup_events().into_iter().take(3).chain([
            event(
                3,
                RuntimeEvent::ObjectFree(ObjectFreeEvent {
                    instance_id: instance("object:1"),
                    free_site_id: site("site:free-1"),
                }),
            ),
            event(
                4,
                RuntimeEvent::ObjectFree(ObjectFreeEvent {
                    instance_id: instance("object:1"),
                    free_site_id: site("site:free-2"),
                }),
            ),
        ]),
    );

    assert_eq!(
        oracle
            .finish()
            .expect("analysis should finish")
            .core_rule_ids(),
        vec!["BW-FREE-001"]
    );
}

#[test]
fn live_object_use_is_safe() {
    let mut oracle = oracle(CaptureMode::Borrowed);
    observe_all(&mut oracle, setup_events());
    oracle
        .observe(&event(
            5,
            RuntimeEvent::ObjectUse(ObjectUseEvent {
                instance_id: instance("object:1"),
                use_site_id: site("site:use"),
                use_kind: ObjectUseKind::Read,
            }),
        ))
        .expect("live use should be observed");

    assert!(
        oracle
            .finish()
            .expect("analysis should finish")
            .rule_ids()
            .is_empty()
    );
}

#[test]
fn single_free_is_safe() {
    let mut oracle = oracle(CaptureMode::Borrowed);
    observe_all(
        &mut oracle,
        setup_events().into_iter().take(3).chain([event(
            3,
            RuntimeEvent::ObjectFree(ObjectFreeEvent {
                instance_id: instance("object:1"),
                free_site_id: site("site:free-1"),
            }),
        )]),
    );

    assert!(
        oracle
            .finish()
            .expect("analysis should finish")
            .rule_ids()
            .is_empty()
    );
}

#[test]
fn owned_capture_and_live_object_are_safe() {
    let mut oracle = oracle(CaptureMode::Owned);
    observe_all(&mut oracle, setup_events());
    observe_all(
        &mut oracle,
        [
            drop_object(5),
            event(
                6,
                RuntimeEvent::CallbackInvoke(CallbackInvokeEvent {
                    callback_instance_id: instance("callback:1"),
                    invoke_site_id: site("site:invoke"),
                    api_id: "api:invoke".to_owned(),
                }),
            ),
        ],
    );

    assert!(
        oracle
            .finish()
            .expect("analysis should finish")
            .rule_ids()
            .is_empty()
    );
}

#[test]
fn unregister_before_borrow_end_is_safe() {
    let mut oracle = oracle(CaptureMode::Borrowed);
    observe_all(&mut oracle, setup_events());
    observe_all(
        &mut oracle,
        [
            event(
                5,
                RuntimeEvent::CallbackUnregister(CallbackUnregisterEvent {
                    callback_instance_id: instance("callback:1"),
                    owner_instance_id: instance("owner:1"),
                    unregister_site_id: site("site:unregister"),
                    api_id: "api:unregister".to_owned(),
                    reason: bw_model::CallbackReleaseReason::Explicit,
                }),
            ),
            drop_object(6),
        ],
    );

    assert!(
        oracle
            .finish()
            .expect("analysis should finish")
            .rule_ids()
            .is_empty()
    );
}
