//! 阶段 3 的验收：Q1 / Q4′ / 降级 Q3 在四个 matched fixture 的**真实 IR** 上给出正确答案。
//!
//! 输入是 `benchmarks/compiler-fixtures/callback-retention-relation/foreign/ir/*.ll`，由
//! clang 14 从同目录的 C stub 直接产出，未经改写。重新生成见该目录的 `README.md`。
//!
//! # 本文件里最重要的一条
//!
//! [`q4_prime_separates_the_clearing_stub_from_the_leaky_one`] 是 Gate R 的核心：fixture 2
//! 与 fixture 3 的 **Rust 侧完全相同**，差别只在 `fixture_unregister` 的实现。若这条过
//! 不了，外部侧对本关系就没有净贡献。

use bw_foreign_ir::{
    BoundaryReason, ForeignRoleMap, RetainedSubject, SlotClearEvidence, SlotId, analyze_text,
};
use bw_model::{
    AllocationOwnership, EffectiveCaptureAdmission, EvidenceGrade, ForeignClear, ForeignInvocation,
    ForeignPathCompatibility, ForeignRetention, HandOffId, LifetimeSubject, RegistrationGuard,
    RustContractFact, StaticVerdict, judge,
};

const IR_DIR: &str = "../../benchmarks/compiler-fixtures/callback-retention-relation/foreign/ir";

fn ir(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(IR_DIR)
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// 四个 stub 的注册入口签名一致，因此共用一份角色映射。
fn roles() -> ForeignRoleMap {
    ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: Some(1),
        clear_symbol: Some("fixture_unregister".to_owned()),
    }
}

fn slots_of(name: &str) -> Vec<String> {
    let analysis = analyze_text(&ir(name), &roles()).expect("parses");
    let mut described: Vec<String> = analysis.slots.iter().map(SlotId::describe).collect();
    described.sort();
    described
}

// ---------------------------------------------------------------------------
// Q1
// ---------------------------------------------------------------------------

#[test]
fn q1_tracks_both_parameters_to_the_globals_they_are_stored_into() {
    let analysis = analyze_text(&ir("retain_late_invoke.ll"), &roles()).expect("parses");

    assert_eq!(analysis.retention, ForeignRetention::MayRetain);
    assert_eq!(
        slots_of("retain_late_invoke.ll"),
        ["@g_callback", "@g_user_data"]
    );

    // 回调与 user data 必须分别归属，不能混成一条。
    let subjects: Vec<RetainedSubject> = analysis
        .retention_sites
        .iter()
        .map(|site| site.subject)
        .collect();
    assert!(subjects.contains(&RetainedSubject::Callback));
    assert!(subjects.contains(&RetainedSubject::UserData));

    // 证据要能回查到具体那条 store 指令。
    assert!(
        analysis
            .retention_sites
            .iter()
            .all(|site| site.instruction.contains("store")),
        "sites: {:?}",
        analysis.retention_sites
    );
}

#[test]
fn q1_does_not_stop_at_the_first_slot() {
    // leaky stub 注册时写了四个槽位。**Q4′ 的判别力完全依赖这里找全。**
    assert_eq!(
        slots_of("retain_late_invoke_leaky.ll"),
        [
            "@g_cached_callback",
            "@g_cached_user_data",
            "@g_callback",
            "@g_user_data",
        ]
    );
}

#[test]
fn q1_reports_no_retention_only_when_every_use_was_enumerated() {
    // 负对照：回调只被同步调用，user data 被交回给这次调用，没有任何跨调用存活的存储。
    let analysis = analyze_text(&ir("synchronous_only.ll"), &roles()).expect("parses");

    assert_eq!(analysis.retention, ForeignRetention::NoRetain);
    assert!(analysis.slots.is_empty());
    assert_eq!(
        analysis.invocation,
        ForeignInvocation::SynchronousInvokeOnly
    );
    assert!(
        analysis.boundaries.is_empty(),
        "「没保留」这个否定结论不允许带着未查清的边界：{:?}",
        analysis.boundaries
    );
}

#[test]
fn an_unanalysable_use_yields_unresolved_rather_than_no_retention() {
    // 非空性检查：把回调交给一个本模块看不到的函数。它**可能**在那里被存起来，因此
    // 正确答案是缺证。如果这里给出 `NoRetain`，上面那条负对照就毫无意义了。
    let source = r#"
declare void @opaque_sink(void (i8*)*)

define dso_local void @fixture_register(void (i8*)* noundef %0, i8* noundef %1) {
  %3 = alloca void (i8*)*, align 8
  store void (i8*)* %0, void (i8*)** %3, align 8
  %4 = load void (i8*)*, void (i8*)** %3, align 8
  call void @opaque_sink(void (i8*)* %4)
  ret void
}
"#;
    let analysis = analyze_text(source, &roles()).expect("parses");

    assert_eq!(analysis.retention, ForeignRetention::Unresolved);
    assert!(
        analysis
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == BoundaryReason::EscapesToUnknownCallee),
        "boundaries: {:?}",
        analysis.boundaries
    );
}

// ---------------------------------------------------------------------------
// Q4′——本阶段的判别项
// ---------------------------------------------------------------------------

#[test]
fn q4_prime_separates_the_clearing_stub_from_the_leaky_one() {
    let clearing = analyze_text(&ir("retain_late_invoke_clearing.ll"), &roles()).expect("parses");
    let leaky = analyze_text(&ir("retain_late_invoke_leaky.ll"), &roles()).expect("parses");

    assert_eq!(clearing.clear, ForeignClear::ClearsOnAllPaths);
    assert_eq!(leaky.clear, ForeignClear::MayLeaveSlotPopulated);

    // 两个 stub 的 Q1 与 Q3 是一样的：判别力**只**来自 Q4′。
    assert_eq!(clearing.retention, leaky.retention);
    assert_eq!(clearing.invocation, leaky.invocation);
}

#[test]
fn q4_prime_names_the_slots_the_unregister_forgot() {
    let leaky = analyze_text(&ir("retain_late_invoke_leaky.ll"), &roles()).expect("parses");

    let mut missed: Vec<String> = leaky
        .clear_sites
        .iter()
        .filter(|site| site.evidence == SlotClearEvidence::NotWritten)
        .map(|site| site.slot.describe())
        .collect();
    missed.sort();
    assert_eq!(missed, ["@g_cached_callback", "@g_cached_user_data"]);
}

#[test]
fn q4_prime_requires_the_clearing_store_on_every_returning_path() {
    let clearing = analyze_text(&ir("retain_late_invoke_clearing.ll"), &roles()).expect("parses");
    assert!(
        clearing
            .clear_sites
            .iter()
            .all(|site| site.evidence == SlotClearEvidence::WritesNullOnEveryPath),
        "sites: {:?}",
        clearing.clear_sites
    );
}

#[test]
fn a_missing_clear_entry_is_unresolved_not_clears() {
    // `retain_late_invoke.ll` 根本没有 `fixture_unregister`。缺一个符号不等于「清干净了」。
    let analysis = analyze_text(&ir("retain_late_invoke.ll"), &roles()).expect("parses");

    assert_eq!(analysis.clear, ForeignClear::Unresolved);
    assert!(
        analysis
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == BoundaryReason::SymbolNotDefined)
    );
}

// ---------------------------------------------------------------------------
// 降级 Q3
// ---------------------------------------------------------------------------

#[test]
fn q3_finds_the_same_slot_indirect_call_and_grades_it_as_a_candidate_only() {
    let analysis = analyze_text(&ir("retain_late_invoke.ll"), &roles()).expect("parses");

    assert_eq!(analysis.invocation, ForeignInvocation::MayInvokeAfterReturn);
    // **降级实现只能给出候选级证据。** 给出更强的等级就是把「存在调用点」当成了
    // 「晚调可达」。
    assert_eq!(
        analysis.invoke_evidence,
        Some(EvidenceGrade::SameSlotInvokeCandidate)
    );

    let site = analysis
        .invoke_sites
        .iter()
        .find(|site| site.function == "fixture_fire")
        .expect("dispatch function invokes through the slot");
    assert_eq!(site.slot.describe(), "@g_callback");
}

#[test]
fn q3_follows_the_fallback_dispatch_path_too() {
    // leaky stub 的 `fixture_fire` 在主槽位为空时回退到缓存槽位。两个调用点都要记。
    let analysis = analyze_text(&ir("retain_late_invoke_leaky.ll"), &roles()).expect("parses");

    let mut slots: Vec<String> = analysis
        .invoke_sites
        .iter()
        .map(|site| site.slot.describe())
        .collect();
    slots.sort();
    assert_eq!(slots, ["@g_cached_callback", "@g_callback"]);
}

// ---------------------------------------------------------------------------
// 正交性与端到端
// ---------------------------------------------------------------------------

#[test]
fn the_four_foreign_dimensions_are_recorded_separately() {
    let analysis = analyze_text(&ir("retain_late_invoke_leaky.ll"), &roles()).expect("parses");

    assert_eq!(analysis.retention, ForeignRetention::MayRetain);
    assert_eq!(analysis.invocation, ForeignInvocation::MayInvokeAfterReturn);
    assert_eq!(analysis.clear, ForeignClear::MayLeaveSlotPopulated);
    // 注册函数是直线代码，四条 store 无条件发生。
    assert_eq!(
        analysis.path_compatibility,
        ForeignPathCompatibility::RetainOnEveryPath
    );
}

fn hand_off() -> HandOffId {
    HandOffId {
        rust_artifact: "artifact:callback-retention-relation".to_owned(),
        rust_def_instance: "Registry::register_guarded".to_owned(),
        call_occurrence: "call:0".to_owned(),
        foreign_artifact: "artifact:fixture-foreign".to_owned(),
        foreign_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: Some(1),
        registration_key: None,
        build_profile: "dev".to_owned(),
    }
}

/// fixture 2 与 fixture 3 共用的 Rust 形状：`register_guarded`。
fn guarded_rust_contract() -> RustContractFact {
    RustContractFact {
        hand_off: hand_off(),
        capture_admission: EffectiveCaptureAdmission::PermitsNonStaticCapture,
        guard: RegistrationGuard::OwnerDropUnregisters,
        allocation: AllocationOwnership::ForeignOwnedUntilUnregister,
        evidence: vec!["src/lib.rs Registry::register_guarded".to_owned()],
    }
}

#[test]
fn the_same_rust_side_gets_different_verdicts_from_the_ir_alone() {
    // Gate R 的 C2：Rust 侧一个字都没变，判定却必须分开。
    let rust = guarded_rust_contract();

    let clearing = analyze_text(&ir("retain_late_invoke_clearing.ll"), &roles())
        .expect("parses")
        .into_behavior_fact(hand_off());
    let leaky = analyze_text(&ir("retain_late_invoke_leaky.ll"), &roles())
        .expect("parses")
        .into_behavior_fact(hand_off());

    let clearing_verdict = judge(&rust, Some(&clearing), LifetimeSubject::CapturedReferent);
    let leaky_verdict = judge(&rust, Some(&leaky), LifetimeSubject::CapturedReferent);

    assert_eq!(
        clearing_verdict.static_verdict,
        StaticVerdict::CompatibleWithinAnalyzedFragment,
        "guard 真清槽的 API 不得误报"
    );
    assert_ne!(
        leaky_verdict.static_verdict,
        StaticVerdict::CompatibleWithinAnalyzedFragment,
        "guard 被击穿时不得判相容"
    );
    assert_eq!(
        leaky_verdict.evidence_grade,
        Some(EvidenceGrade::GuardDefeated)
    );
}

#[test]
fn rust_only_cannot_reach_the_same_conclusion() {
    // 反过来的一半：没有外部侧事实时，guard 只能得出缺证。**若 Rust-only 也能分开
    // 2 和 3，外部侧就没有净贡献。**
    let rust = guarded_rust_contract();
    let verdict = judge(&rust, None, LifetimeSubject::CapturedReferent);
    assert_eq!(verdict.static_verdict, StaticVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// 从真实目标上量出来的两个形状
// ---------------------------------------------------------------------------

#[test]
fn an_entry_guard_early_return_is_unresolved_not_a_defeated_guard() {
    // 形状取自真实的 `sqlite3_update_hook`：
    //
    //     if( !sqlite3SafetyCheckOk(db) ){ return 0; }
    //
    // 于是写槽位那条 store 只落在两条返回路径中的一条上。**这不等于「注销漏了槽位」。**
    // 若把它并进 `MayLeaveSlotPopulated`，每一个带入口参数校验的 C API 都会被判成
    // guard 被击穿，Q4′ 到规模上就没有判别力了。
    let source = r#"
%struct.conn = type { i8*, void (i8*)* }

declare i32 @safety_check(%struct.conn*)

define void @fixture_register(%struct.conn* noundef %0, void (i8*)* noundef %1) {
  %3 = alloca %struct.conn*, align 8
  %4 = alloca void (i8*)*, align 8
  store %struct.conn* %0, %struct.conn** %3, align 8
  store void (i8*)* %1, void (i8*)** %4, align 8
  %5 = load %struct.conn*, %struct.conn** %3, align 8
  %6 = call i32 @safety_check(%struct.conn* noundef %5)
  %7 = icmp ne i32 %6, 0
  br i1 %7, label %8, label %13

8:
  %9 = load void (i8*)*, void (i8*)** %4, align 8
  %10 = load %struct.conn*, %struct.conn** %3, align 8
  %11 = getelementptr inbounds %struct.conn, %struct.conn* %10, i32 0, i32 1
  store void (i8*)* %9, void (i8*)** %11, align 8
  br label %13

13:
  ret void
}
"#;
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 1,
        userdata_arg_index: None,
        clear_symbol: Some("fixture_register".to_owned()),
    };
    let analysis = analyze_text(source, &roles).expect("parses");

    assert_eq!(analysis.retention, ForeignRetention::MayRetain);
    assert_eq!(
        analysis.clear,
        ForeignClear::Unresolved,
        "入口校验的提前返回只能得出缺证"
    );
    assert!(
        analysis
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == BoundaryReason::ClearOnlyOnSomePaths),
        "缺证必须写明是哪一种：{:?}",
        analysis.boundaries
    );
    // 保留路径的无条件性是单独一维，如实记录，不与 Q4′ 混。
    assert_eq!(
        analysis.path_compatibility,
        ForeignPathCompatibility::RetainOnSomePaths
    );
}

#[test]
fn q3_matches_a_dispatch_site_that_reaches_the_slot_through_another_struct() {
    // 形状取自真实的 `sqlite3VdbeExec`：注册时 `db` 是形参，派发时是 `p->db`。
    //
    // **槽位身份必须只认「结构体类型 + 字段路径」。** 早先的实现要求基址来自形参，
    // 真实 sqlite3 上因此丢掉了全部五个调用点，Q3 直接变成缺证。
    let source = r#"
%struct.conn = type { void (i8*)* }
%struct.vm = type { %struct.conn* }

define void @fixture_register(%struct.conn* noundef %0, void (i8*)* noundef %1) {
  %3 = alloca %struct.conn*, align 8
  %4 = alloca void (i8*)*, align 8
  store %struct.conn* %0, %struct.conn** %3, align 8
  store void (i8*)* %1, void (i8*)** %4, align 8
  %5 = load void (i8*)*, void (i8*)** %4, align 8
  %6 = load %struct.conn*, %struct.conn** %3, align 8
  %7 = getelementptr inbounds %struct.conn, %struct.conn* %6, i32 0, i32 0
  store void (i8*)* %5, void (i8*)** %7, align 8
  ret void
}

define void @dispatch(%struct.vm* noundef %0) {
  %2 = alloca %struct.vm*, align 8
  store %struct.vm* %0, %struct.vm** %2, align 8
  %3 = load %struct.vm*, %struct.vm** %2, align 8
  %4 = getelementptr inbounds %struct.vm, %struct.vm* %3, i32 0, i32 0
  %5 = load %struct.conn*, %struct.conn** %4, align 8
  %6 = getelementptr inbounds %struct.conn, %struct.conn* %5, i32 0, i32 0
  %7 = load void (i8*)*, void (i8*)** %6, align 8
  call void %7(i8* null)
  ret void
}
"#;
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 1,
        userdata_arg_index: None,
        clear_symbol: None,
    };
    let analysis = analyze_text(source, &roles).expect("parses");

    assert_eq!(analysis.invocation, ForeignInvocation::MayInvokeAfterReturn);
    let site = analysis
        .invoke_sites
        .iter()
        .find(|site| site.function == "dispatch")
        .unwrap_or_else(|| panic!("no dispatch site; sites: {:?}", analysis.invoke_sites));
    assert_eq!(site.slot.describe(), "%struct.conn[0.0]");
}

#[test]
fn a_field_of_a_locally_allocated_struct_is_not_proven_retention() {
    // caller-owned 判定的非空性：写进本函数内新分配的结构体的字段，既不是保留，
    // 也不足以说「没保留」。
    let source = r#"
%struct.local = type { void (i8*)* }

declare i8* @sink(%struct.local*)

define void @fixture_register(void (i8*)* noundef %0) {
  %2 = alloca %struct.local, align 8
  %3 = alloca void (i8*)*, align 8
  store void (i8*)* %0, void (i8*)** %3, align 8
  %4 = load void (i8*)*, void (i8*)** %3, align 8
  %5 = getelementptr inbounds %struct.local, %struct.local* %2, i32 0, i32 0
  store void (i8*)* %4, void (i8*)** %5, align 8
  ret void
}
"#;
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: None,
        clear_symbol: None,
    };
    let analysis = analyze_text(source, &roles).expect("parses");

    assert_eq!(analysis.retention, ForeignRetention::Unresolved);
    assert!(
        analysis
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == BoundaryReason::SlotNotProvenCallerOwned),
        "boundaries: {:?}",
        analysis.boundaries
    );
}
