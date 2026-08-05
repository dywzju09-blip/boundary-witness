//! Gate R：核心关系的四个 matched fixture。
//!
//! fixture 与源码的对应关系见
//! `benchmarks/compiler-fixtures/callback-retention-relation/foreign/README.md`。
//!
//! 外部侧取值在本阶段由 C stub 手工标注（`manual foreign oracle` 变体）。P1/P2 会把
//! 它们换成从真实构建的 LLVM IR 推导的结果；**关系本身不因来源改变**，所以这些断言
//! 到那时仍然有效。

use bw_model::{
    AllocationOwnership, CompatibilityVerdict, EffectiveCaptureAdmission, EvidenceGrade,
    ForeignBehaviorFact, ForeignClear, ForeignInvocation, ForeignPathCompatibility,
    ForeignRetention, HandOffId, LifetimeSubject, RegistrationGuard, RustContractFact,
    StaticVerdict, WitnessObligation, WitnessStatus, hand_off_is_incompatible, judge,
    judge_hand_off,
};

fn hand_off() -> HandOffId {
    HandOffId {
        rust_artifact: "artifact:callback-retention-relation".to_owned(),
        rust_def_instance: "Registry::register".to_owned(),
        call_occurrence: "call:0".to_owned(),
        foreign_artifact: "artifact:fixture-foreign".to_owned(),
        foreign_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: Some(1),
        registration_key: Some("slot:global".to_owned()),
        build_profile: "x86_64-unknown-linux-gnu/default".to_owned(),
    }
}

/// `register_borrowed`：允许捕获借用，无 guard，分配交出后仍由 Rust 侧持有。
fn rust_borrowed_no_guard() -> RustContractFact {
    RustContractFact {
        hand_off: hand_off(),
        capture_admission: EffectiveCaptureAdmission::PermitsNonStaticCapture,
        guard: RegistrationGuard::None,
        allocation: AllocationOwnership::ForeignOwnedUntilUnregister,
        evidence: vec!["src/lib.rs Registry::register_borrowed".to_owned()],
    }
}

/// `register_guarded`：**fixture 2 与 3 共用**。两者的 Rust 事实必须完全相等。
fn rust_borrowed_with_guard() -> RustContractFact {
    RustContractFact {
        hand_off: hand_off(),
        capture_admission: EffectiveCaptureAdmission::PermitsNonStaticCapture,
        guard: RegistrationGuard::TiesSlotToSubject,
        allocation: AllocationOwnership::ForeignOwnedUntilUnregister,
        evidence: vec!["src/lib.rs Registry::register_guarded".to_owned()],
    }
}

/// `register_static_then_free`：`'static` bound，但分配提前释放。
fn rust_static_alloc_freed_early() -> RustContractFact {
    RustContractFact {
        hand_off: hand_off(),
        capture_admission: EffectiveCaptureAdmission::RequiresStaticCapture,
        guard: RegistrationGuard::None,
        allocation: AllocationOwnership::RustRetainsAndMayFreeEarly,
        evidence: vec!["src/lib.rs Registry::register_static_then_free".to_owned()],
    }
}

/// `retain_late_invoke.c` / `retain_late_invoke_leaky.c` 的共同部分。
fn foreign(clear: ForeignClear) -> ForeignBehaviorFact {
    ForeignBehaviorFact {
        hand_off: hand_off(),
        retention: ForeignRetention::MayRetain,
        invocation: ForeignInvocation::MayInvokeAfterReturn,
        clear,
        // 两个 stub 的 `fixture_register` 都是直线代码，保留 store 无条件发生。
        path_compatibility: ForeignPathCompatibility::RetainOnEveryPath,
        invoke_evidence: Some(EvidenceGrade::PathSupportedLateInvoke),
        evidence: vec!["foreign/retain_late_invoke*.c".to_owned()],
    }
}

/// `synchronous_only.c`。
fn foreign_synchronous() -> ForeignBehaviorFact {
    ForeignBehaviorFact {
        hand_off: hand_off(),
        retention: ForeignRetention::NoRetain,
        invocation: ForeignInvocation::SynchronousInvokeOnly,
        // 这个 stub 的 `fixture_unregister` 是空的：没有槽位，也就无所谓清不清。
        // **不能记 `ClearsOnAllPaths`**——那会让判定器把不存在的注销当成有效保护。
        // 判定不受影响：`NoRetain` 已经否定了晚调。
        clear: ForeignClear::Unresolved,
        path_compatibility: ForeignPathCompatibility::Unresolved,
        invoke_evidence: None,
        evidence: vec!["foreign/synchronous_only.c".to_owned()],
    }
}

fn verdict_for(
    rust: &RustContractFact,
    foreign: Option<&ForeignBehaviorFact>,
    subject: LifetimeSubject,
) -> StaticVerdict {
    judge(rust, foreign, subject).static_verdict
}

// ---------------------------------------------------------------------------
// 四个 matched fixture
// ---------------------------------------------------------------------------

#[test]
fn fixture_1_borrowed_capture_without_guard_is_incompatible() {
    let verdicts = judge_hand_off(
        &rust_borrowed_no_guard(),
        Some(&foreign(ForeignClear::Unresolved)),
    );
    assert!(hand_off_is_incompatible(&verdicts));

    let referent = &verdicts[0];
    assert_eq!(referent.subject, LifetimeSubject::CapturedReferent);
    assert_eq!(
        referent.static_verdict,
        StaticVerdict::SupportedIncompatibility
    );
    // 分配由外部持有到注销，这一类生命周期本身相容。
    assert_eq!(
        verdicts[1].static_verdict,
        StaticVerdict::CompatibleWithinAnalyzedFragment
    );
}

#[test]
fn fixture_2_guard_with_working_unregister_is_compatible() {
    let verdicts = judge_hand_off(
        &rust_borrowed_with_guard(),
        Some(&foreign(ForeignClear::ClearsOnAllPaths)),
    );
    assert!(!hand_off_is_incompatible(&verdicts));
    for verdict in &verdicts {
        assert_eq!(
            verdict.static_verdict,
            StaticVerdict::CompatibleWithinAnalyzedFragment,
            "{:?} 应判相容：guard 把注册绑在被捕对象上，且注销真的清空槽位",
            verdict.subject
        );
    }
}

#[test]
fn fixture_3_guard_with_leaky_unregister_is_incompatible() {
    let verdicts = judge_hand_off(
        &rust_borrowed_with_guard(),
        Some(&foreign(ForeignClear::MayLeaveSlotPopulated)),
    );
    assert!(hand_off_is_incompatible(&verdicts));

    let referent = &verdicts[0];
    assert_eq!(
        referent.static_verdict,
        StaticVerdict::SupportedIncompatibility
    );
    assert_eq!(referent.evidence_grade, Some(EvidenceGrade::GuardDefeated));
}

#[test]
fn fixture_4_static_bound_with_early_freed_allocation_is_incompatible() {
    let verdicts = judge_hand_off(
        &rust_static_alloc_freed_early(),
        Some(&foreign(ForeignClear::Unresolved)),
    );
    assert!(hand_off_is_incompatible(&verdicts));

    // `'static` 排除了借用捕获这一子问题……
    assert_eq!(
        verdicts[0].static_verdict,
        StaticVerdict::CompatibleWithinAnalyzedFragment
    );
    // ……但它对回调分配的存活不表态。旧的 2×2 矩阵在这一格漏报。
    assert_eq!(verdicts[1].subject, LifetimeSubject::CallbackAllocation);
    assert_eq!(
        verdicts[1].static_verdict,
        StaticVerdict::SupportedIncompatibility
    );
}

// ---------------------------------------------------------------------------
// Gate R 的通过条件：Full 能分开 2 与 3，Rust-only 不能
// ---------------------------------------------------------------------------

#[test]
fn fixtures_2_and_3_share_an_identical_rust_side() {
    // 这两个 fixture 的全部差别必须落在外部侧。若这条断言失败，后面那条分离性断言
    // 就失去意义——分开它们可能只是因为 Rust 侧本来就不同。
    assert_eq!(rust_borrowed_with_guard(), rust_borrowed_with_guard());
}

#[test]
fn full_separates_fixtures_2_and_3() {
    let rust = rust_borrowed_with_guard();
    let compatible = verdict_for(
        &rust,
        Some(&foreign(ForeignClear::ClearsOnAllPaths)),
        LifetimeSubject::CapturedReferent,
    );
    let incompatible = verdict_for(
        &rust,
        Some(&foreign(ForeignClear::MayLeaveSlotPopulated)),
        LifetimeSubject::CapturedReferent,
    );
    assert_ne!(
        compatible, incompatible,
        "Rust 侧相同、只有外部侧清槽行为不同的两个 fixture 必须被分开"
    );
    assert_eq!(compatible, StaticVerdict::CompatibleWithinAnalyzedFragment);
    assert_eq!(incompatible, StaticVerdict::SupportedIncompatibility);
}

#[test]
fn rust_only_cannot_separate_fixtures_2_and_3() {
    // fixture 2 与 3 的 Rust 事实完全相同，因此 Rust-only 对两者只能给出同一组结论。
    // 这就是「分不开」的定义。
    let rust = rust_borrowed_with_guard();
    let as_fixture_2: Vec<StaticVerdict> = judge_hand_off(&rust, None)
        .iter()
        .map(|verdict| verdict.static_verdict)
        .collect();
    let as_fixture_3 = as_fixture_2.clone();
    assert_eq!(as_fixture_2, as_fixture_3);

    // 判别力落在被捕对象这一类生命周期上：没有外部侧清槽证据时只能记缺证。
    let referent = judge(&rust, None, LifetimeSubject::CapturedReferent);
    assert_eq!(referent.static_verdict, StaticVerdict::InsufficientEvidence);
    assert!(
        referent
            .assumptions
            .iter()
            .any(|note| note.contains("guard validity is a foreign-side question")),
        "缺证原因必须写清缺的是哪一半"
    );
}

#[test]
fn allocation_subject_is_decidable_without_foreign_evidence() {
    // 一个值得记下来的边界：并非关系的每一项都需要外部证据。分配的归属是纯 Rust 侧
    // 事实——`ForeignOwnedUntilUnregister` 意味着 Rust 代码不会提前回收它，安全客户端
    // 因而无法让它悬垂，这个结论不需要看外部侧。
    //
    // 外部证据的净贡献集中在 guard 分支（Q4′）。**Gate A 的增益必须归因到那里**，
    // 不能笼统地说「因为我们看了外部侧」。
    let verdict = judge(
        &rust_borrowed_with_guard(),
        None,
        LifetimeSubject::CallbackAllocation,
    );
    assert_eq!(
        verdict.static_verdict,
        StaticVerdict::CompatibleWithinAnalyzedFragment
    );
}

#[test]
fn rust_only_must_not_call_a_guarded_api_compatible() {
    // 这是 Rust-only 最容易犯的错：看到 guard 就假定它有效。那样 fixture 3 会成为
    // 静默漏报。判定器必须拒绝这个捷径。
    let verdict = judge(
        &rust_borrowed_with_guard(),
        None,
        LifetimeSubject::CapturedReferent,
    );
    assert_ne!(
        verdict.static_verdict,
        StaticVerdict::CompatibleWithinAnalyzedFragment
    );
}

// ---------------------------------------------------------------------------
// 非空性检查
// ---------------------------------------------------------------------------

#[test]
fn swapping_fixture_3_stub_for_a_clearing_one_flips_the_verdict() {
    // 把 fixture 3 的 C stub 换成「注销真的清槽」，判定必须翻转为相容。若不翻转，
    // 说明判定器根本没有读 Q4′ 的证据。
    let rust = rust_borrowed_with_guard();
    let before = verdict_for(
        &rust,
        Some(&foreign(ForeignClear::MayLeaveSlotPopulated)),
        LifetimeSubject::CapturedReferent,
    );
    let after = verdict_for(
        &rust,
        Some(&foreign(ForeignClear::ClearsOnAllPaths)),
        LifetimeSubject::CapturedReferent,
    );
    assert_eq!(before, StaticVerdict::SupportedIncompatibility);
    assert_eq!(after, StaticVerdict::CompatibleWithinAnalyzedFragment);
}

#[test]
fn synchronous_foreign_implementation_makes_every_fixture_compatible() {
    // 外部侧只同步调用时，无论 Rust 侧 bound 多松都不相容不了。这条同时验证判定器
    // 确实在读 Q1/Q3，而不是只看 Rust 侧。
    for rust in [
        rust_borrowed_no_guard(),
        rust_borrowed_with_guard(),
        rust_static_alloc_freed_early(),
    ] {
        let verdicts = judge_hand_off(&rust, Some(&foreign_synchronous()));
        assert!(
            !hand_off_is_incompatible(&verdicts),
            "同步外部实现下不应有不相容结论"
        );
    }
}

// ---------------------------------------------------------------------------
// 三个正交维度的纪律
// ---------------------------------------------------------------------------

#[test]
fn degraded_q3_evidence_cannot_reach_supported_incompatibility() {
    // 降级 Q3 只证明「同槽位存在间接调用点」。它的正确输出是缺证加一条反证义务，
    // **不是弱化的不相容结论**——没有第四态。
    let mut fact = foreign(ForeignClear::Unresolved);
    fact.invoke_evidence = Some(EvidenceGrade::SameSlotInvokeCandidate);

    let verdict = judge(
        &rust_borrowed_no_guard(),
        Some(&fact),
        LifetimeSubject::CapturedReferent,
    );
    assert_eq!(verdict.static_verdict, StaticVerdict::InsufficientEvidence);
    assert_eq!(
        verdict.evidence_grade,
        Some(EvidenceGrade::SameSlotInvokeCandidate)
    );
    assert_eq!(
        verdict.witness_obligation,
        Some(WitnessObligation::EstablishLateInvoke)
    );
    assert_eq!(verdict.witness_status, WitnessStatus::NotAttempted);
}

#[test]
fn identity_mismatch_is_not_joined() {
    // 两侧事实的交出点身份不等时不得组合——`SameArtifactSlotAndRole`。
    let mut fact = foreign(ForeignClear::MayLeaveSlotPopulated);
    fact.hand_off.call_occurrence = "call:7".to_owned();

    let verdict = judge(
        &rust_borrowed_with_guard(),
        Some(&fact),
        LifetimeSubject::CapturedReferent,
    );
    assert_eq!(verdict.static_verdict, StaticVerdict::InsufficientEvidence);
    assert!(
        verdict
            .assumptions
            .iter()
            .any(|note| note.contains("hand-off identity does not match"))
    );
}

#[test]
fn verdicts_are_reported_per_subject_not_merged() {
    // fixture 4 的两类生命周期结论相反。合并成一个结论会丢掉不相容的那一半。
    let verdicts: Vec<CompatibilityVerdict> = judge_hand_off(
        &rust_static_alloc_freed_early(),
        Some(&foreign(ForeignClear::Unresolved)),
    );
    assert_eq!(verdicts.len(), LifetimeSubject::ALL.len());
    assert_ne!(verdicts[0].static_verdict, verdicts[1].static_verdict);
}
