//! PG-1 验收：`RegistrationGuard` 事实必须从真实签名与 `Drop` MIR 产出。
//!
//! 用的是 Gate R 的四个 matched fixture 的 Rust 侧
//! （`benchmarks/compiler-fixtures/callback-retention-relation/`）。判据来自
//! `docs/roadmap/implementation-plan.md` 的 PG-1，完成谓词是：编译器产出的取值与
//! `crates/bw-model/tests/compatibility.rs` 里手写的那组**逐字段一致**。
//!
//! 本文件只覆盖 guard 这一个事实。`AllocationOwnership`（PG-2）还没有产出方，
//! 那一半的取值目前仍是手写的。

use std::{collections::BTreeMap, fs, process::Command};

use bw_model::{AllocationOwnership, RegistrationGuard, StaticFact, StaticFactEnvelope};

/// 事实层观察到的一个交出点：回调 bound 与 guard 必须能按 `(api_id, callback_param)` 配对。
#[derive(Debug, Default)]
struct HandOff {
    guard: Option<RegistrationGuard>,
    guard_type: Option<String>,
    foreign_release_callee: Option<String>,
    ownership: Option<AllocationOwnership>,
    has_into_raw_evidence: bool,
    has_reclaim_evidence: bool,
    has_bound_fact: bool,
}

#[test]
fn registration_guard_is_derived_from_signature_and_drop_mir() {
    let hand_offs = analyze_relation_fixture();

    // fixture 2 与 3 共用的 Rust 侧。guard 形状齐全：返回值带 `'reg`、`'reg` 正是回调
    // bound 的那个声明、`Registration` 的 `Drop` 调了外部函数。
    let guarded = &hand_offs["Registry::register_guarded::F"];
    assert_eq!(
        guarded.guard,
        Some(RegistrationGuard::TiesSlotToSubject),
        "register_guarded 的 guard 必须从签名与 Drop MIR 判出来"
    );
    assert_eq!(guarded.guard_type.as_deref(), Some("Registration"));
    assert_eq!(
        guarded.foreign_release_callee.as_deref(),
        Some("fixture_unregister"),
        "guard 的判据是「Drop 里调了外部函数」，被调方必须可回查"
    );

    // fixture 1 的 Rust 侧：允许捕获借用，没有任何 guard。它与 register_guarded 的差别
    // 只在返回值——**这是本测试真正要钉住的对比**。
    let borrowed = &hand_offs["Registry::register_borrowed::F"];
    assert_eq!(
        borrowed.guard,
        Some(RegistrationGuard::None),
        "无返回值的注册 API 不得被判成有 guard"
    );
    assert_eq!(borrowed.guard_type, None);
    assert_eq!(borrowed.foreign_release_callee, None);

    // fixture 4 的 Rust 侧：`'static` bound、分配提前释放，同样没有 guard。
    assert_eq!(
        hand_offs["Registry::register_static_then_free::F"].guard,
        Some(RegistrationGuard::None)
    );
    // 负对照：`'static` + 分配交给外部，也没有 guard。
    assert_eq!(
        hand_offs["Registry::register_static_owned::F"].guard,
        Some(RegistrationGuard::None)
    );

    // 判定关系要同时读两个事实，因此每个回调参数上两者必须齐备。缺一半会让判定静默
    // 落到缺证，而不是报错——这正是最难发现的失败方式。
    for (key, hand_off) in &hand_offs {
        assert!(
            hand_off.has_bound_fact,
            "{key} 有 guard 事实却没有配对的 callback_lifetime_bound 事实"
        );
        assert!(
            hand_off.guard.is_some(),
            "{key} 有 callback_lifetime_bound 事实却没有配对的 guard 事实"
        );
        assert!(
            hand_off.ownership.is_some(),
            "{key} 缺少配对的 allocation ownership 事实"
        );
    }
}

fn analyze_relation_fixture() -> BTreeMap<String, HandOff> {
    let facts = relation_fixture_facts();
    let mut hand_offs = BTreeMap::<String, HandOff>::new();
    for fact in &facts {
        match &fact.payload {
            StaticFact::RegistrationGuard(guard) => {
                assert!(
                    fact.is_authoritative_lifecycle_binding(),
                    "guard 事实必须带 v0.2 artifact identity 与 source anchor"
                );
                let entry = hand_offs
                    .entry(format!("{}::{}", guard.api_id, guard.callback_param))
                    .or_default();
                entry.guard = Some(guard.guard);
                entry.guard_type = guard.guard_type.clone();
                entry.foreign_release_callee = guard.foreign_release_callee.clone();
            }
            StaticFact::AllocationOwnership(ownership) => {
                assert!(
                    fact.is_authoritative_lifecycle_binding(),
                    "allocation ownership 事实必须带 v0.2 artifact identity 与 source anchor"
                );
                let entry = hand_offs
                    .entry(format!("{}::{}", ownership.api_id, ownership.callback_param))
                    .or_default();
                entry.ownership = Some(ownership.ownership);
                entry.has_into_raw_evidence = ownership.into_raw_site_id.is_some();
                entry.has_reclaim_evidence = ownership.reclaim_site_id.is_some();
            }
            StaticFact::CallbackLifetimeBound(bound) => {
                hand_offs
                    .entry(format!("{}::{}", bound.api_id, bound.callback_param))
                    .or_default()
                    .has_bound_fact = true;
            }
            _ => {}
        }
    }
    hand_offs
}

fn relation_fixture_facts() -> Vec<StaticFactEnvelope> {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/callback-retention-relation/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                {
                    "crate_name": "callback_retention_relation",
                    "target": "lib",
                    "package_name": "callback-retention-relation"
                }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    read_static_facts(&analysis_dir.join("static-facts.jsonl"))
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn read_static_facts(path: &std::path::Path) -> Vec<StaticFactEnvelope> {
    fs::read_to_string(path)
        .expect("static-facts.jsonl should be written")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("static fact should parse"))
        .collect()
}

/// PG-2 验收：`AllocationOwnership` 必须从本函数体内的 raw pointer 转移事实判出来。
///
/// **本测试真正钉住的是 `register_static_then_free` 与 `register_static_owned` 的对比。**
/// 两者的签名完全相同（都是 `F: FnMut() + 'static`、都无返回值），差别只在交出之后有没有
/// 一次 `Box::from_raw` 回收。`'static` bound 对这个差别完全不表态——这正是把回调**捕获**
/// 与回调**分配**分开的理由。
#[test]
fn allocation_ownership_is_derived_from_raw_pointer_transfers() {
    let hand_offs = analyze_relation_fixture();

    // fixture 4 的 Rust 侧：交出后立刻 `Box::from_raw` 回收，外部槽位里的指针从此悬垂。
    let freed = &hand_offs["Registry::register_static_then_free::F"];
    assert_eq!(
        freed.ownership,
        Some(AllocationOwnership::RustRetainsAndMayFreeEarly),
        "into_raw 之后配对到 from_raw，必须判为 Rust 侧仍有回收路径"
    );
    assert!(
        freed.has_into_raw_evidence && freed.has_reclaim_evidence,
        "该判定的两个证据点都要可回查"
    );

    // 负对照：签名与上面**完全相同**，只是没有那次回收。
    let owned = &hand_offs["Registry::register_static_owned::F"];
    assert_eq!(
        owned.ownership,
        Some(AllocationOwnership::ForeignOwnedUntilUnregister),
        "没有回收路径时分配归外部，签名与 register_static_then_free 相同不影响这一判定"
    );
    assert!(owned.has_into_raw_evidence);
    assert!(
        !owned.has_reclaim_evidence,
        "没有回收就不该有回收证据点"
    );

    assert_ne!(
        freed.ownership, owned.ownership,
        "两个签名相同、只有分配回收行为不同的 API 必须被分开——这是 PG-2 的全部意义"
    );

    // fixture 1/2/3 的 Rust 侧同样把分配交给外部。
    for key in [
        "Registry::register_borrowed::F",
        "Registry::register_guarded::F",
    ] {
        assert_eq!(
            hand_offs[key].ownership,
            Some(AllocationOwnership::ForeignOwnedUntilUnregister),
            "{key} 交出后没有回收路径"
        );
    }
}
