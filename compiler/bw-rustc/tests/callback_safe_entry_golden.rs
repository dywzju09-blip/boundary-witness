//! 1.2 验收：safe-entry lineage 必须把 safe / unsafe / private-helper 三组分开。
//!
//! 用 `benchmarks/compiler-fixtures/callback-safe-entry/`。四个形状的回调 bound 完全
//! 相同，差别只在「谁能走到这个交出点」——判定看的必须是可达性，不是可见性。

use std::{collections::BTreeMap, fs, process::Command};

use bw_model::{SafeEntryLineage, StaticFact, StaticFactEnvelope};

#[derive(Debug)]
struct Lineage {
    lineage: SafeEntryLineage,
    owner_is_unsafe_fn: bool,
    entry_def_path: Option<String>,
    hops: Option<u32>,
}

#[test]
fn safe_entry_lineage_separates_safe_unsafe_and_unreachable_hand_offs() {
    let lineages = analyze();

    // 组 1：公开安全 API 自身就是入口。
    let direct = &lineages["public_safe_register::F"];
    assert_eq!(direct.lineage, SafeEntryLineage::DirectPublicSafeEntry);
    assert!(!direct.owner_is_unsafe_fn);
    assert_eq!(direct.hops, Some(0));

    // 组 2：公开但是 `unsafe fn`，调用它本来就要写 unsafe，不算安全入口。
    let unsafe_entry = &lineages["public_unsafe_register::F"];
    assert_eq!(unsafe_entry.lineage, SafeEntryLineage::NoPublicSafeEntry);
    assert!(
        unsafe_entry.owner_is_unsafe_fn,
        "`unsafe fn` 必须被记下来，否则无法解释为什么它不算安全交出点"
    );

    // 组 3：私有 helper，但有公开安全 wrapper 调它。**本 fixture 的重点。**
    let via_wrapper = &lineages["private_helper_register::F"];
    assert_eq!(
        via_wrapper.lineage,
        SafeEntryLineage::ReachableFromPublicSafeEntry,
        "私有不等于安全客户端到不了——把两者混同会漏掉整整一类真实交出点"
    );
    assert_eq!(
        via_wrapper.entry_def_path.as_deref(),
        Some("wrapper_over_private_helper"),
        "可达时必须能说出是哪个入口可达"
    );
    assert_eq!(via_wrapper.hops, Some(1));

    // 组 4：私有 helper，只有 `unsafe fn` 调它 → 仍然不可达。
    let unreachable = &lineages["unreachable_private_register::F"];
    assert_eq!(
        unreachable.lineage,
        SafeEntryLineage::NoPublicSafeEntry,
        "只有 unsafe 入口能到达时不算安全交出点"
    );
    assert_eq!(unreachable.entry_def_path, None);

    // 组 3 与组 4 的差别只有「有没有安全 wrapper 调它」——这是判定看可达性而不是
    // 看可见性的证明。
    assert_ne!(via_wrapper.lineage, unreachable.lineage);

    // 共享 helper 被组 1 的公开安全 API 调用，因此也是可达的。
    assert_eq!(
        lineages["hand_off::F"].lineage,
        SafeEntryLineage::ReachableFromPublicSafeEntry
    );
    // trampoline 是 `unsafe extern "C" fn`，只被外部调用，安全客户端到不了。
    assert_eq!(
        lineages["trampoline::F"].lineage,
        SafeEntryLineage::NoPublicSafeEntry
    );
}

fn analyze() -> BTreeMap<String, Lineage> {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let fixture = repo.join("benchmarks/compiler-fixtures/callback-safe-entry/Cargo.toml");
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
                    "crate_name": "callback_safe_entry",
                    "target": "lib",
                    "package_name": "callback-safe-entry"
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

    let facts: Vec<StaticFactEnvelope> = fs::read_to_string(analysis_dir.join("static-facts.jsonl"))
        .expect("static-facts.jsonl should be written")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("static fact should parse"))
        .collect();

    let mut out = BTreeMap::new();
    for fact in &facts {
        if let StaticFact::SafeEntryLineage(lineage) = &fact.payload {
            out.insert(
                format!("{}::{}", lineage.api_id, lineage.callback_param),
                Lineage {
                    lineage: lineage.lineage,
                    owner_is_unsafe_fn: lineage.owner_is_unsafe_fn,
                    entry_def_path: lineage.entry_def_path.clone(),
                    hops: lineage.hops,
                },
            );
        }
    }
    assert!(!out.is_empty(), "fixture 必须产出 safe-entry lineage 事实");
    out
}
