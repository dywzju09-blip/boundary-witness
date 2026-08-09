//! 阶段 5.2 判据修正的回归：userdata 参数角色推断与 0 跳 safe-entry lineage。
//!
//! 对应两处修改：
//!
//! 1. `foreign_callback_calls` 的 userdata 只认 callback **之后**的第一个裸指针参数。
//!    之前的规则把「第一个裸指针参数」当 userdata，真实 C API 的接收者
//!    （sqlite3* 之类 handle）被误判成上下文，造成 user_data_role_mismatch；
//! 2. `safe_entry_lineages` 先判 0 跳 public safe entry，再判调用图完整性。
//!    之前的顺序在调用图不完整时把 0 跳也降级，真实 crate 的公开 API lineage
//!    恒为 Unresolved。
//!
//! fixture 见 `benchmarks/compiler-fixtures/foreign-symbol-roles/`。

use std::{collections::BTreeMap, fs, process::Command};

use bw_model::{ForeignSymbolResolution, SafeEntryLineage, StaticFact, StaticFactEnvelope};

#[derive(Debug, Clone)]
struct Binding {
    symbol: Option<String>,
    callback_arg_index: Option<u32>,
    userdata_arg_index: Option<u32>,
    resolution: ForeignSymbolResolution,
}

#[derive(Debug)]
struct Lineage {
    lineage: SafeEntryLineage,
    unresolved_reason: Option<String>,
}

#[test]
fn userdata_role_follows_callback_parameter() {
    let (bindings, _) = analyze();

    // handle 在 callback 前：userdata 必须是 callback 后的第一个裸指针，不得把
    // handle（参数 0）误判成 userdata。
    let with_handle = &bindings["register_with_handle::F"];
    assert_eq!(with_handle.symbol.as_deref(), Some("fixture_register_with_handle"));
    assert_eq!(with_handle.callback_arg_index, Some(1));
    assert_eq!(with_handle.userdata_arg_index, Some(2));

    // userdata 在 callback 前：缺证不猜，ud=None。
    let ud_first = &bindings["register_ud_first::F"];
    assert_eq!(ud_first.symbol.as_deref(), Some("fixture_register_ud_first"));
    assert_eq!(ud_first.callback_arg_index, Some(1));
    assert_eq!(ud_first.userdata_arg_index, None);

    // 原始形状：cb=0、ud=1，不得因新规则回归。
    let plain = &bindings["register_plain::F"];
    assert_eq!(plain.symbol.as_deref(), Some("fixture_register_plain"));
    assert_eq!(plain.callback_arg_index, Some(0));
    assert_eq!(plain.userdata_arg_index, Some(1));
}

#[test]
fn zero_hop_safe_entry_wins_over_incomplete_call_graph() {
    let (_, lineages) = analyze();

    // 调用图因 dispatch 的间接调用不完整，但 0 跳 public safe entry 不依赖调用图。
    for api in [
        "register_with_handle::F",
        "register_ud_first::F",
        "register_plain::F",
        "register_via_private::F",
    ] {
        let entry = &lineages[api];
        assert_eq!(
            entry.lineage,
            SafeEntryLineage::DirectPublicSafeEntry,
            "{api} 自身是 public safe API，即使调用图不完整也必须是 0 跳 DirectPublicSafeEntry"
        );
    }

    // 私有 hand-off 在调用图不完整时降为 Unresolved，**不是** NoPublicSafeEntry——
    // 缺证不是否定。
    let private = &lineages["private_register::F"];
    assert_eq!(private.lineage, SafeEntryLineage::Unresolved);
    assert_eq!(
        private.unresolved_reason.as_deref(),
        Some("lineage_call_graph_incomplete")
    );
}

fn analyze() -> (BTreeMap<String, Binding>, BTreeMap<String, Lineage>) {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let fixture = repo.join("benchmarks/compiler-fixtures/foreign-symbol-roles/Cargo.toml");
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
                    "crate_name": "foreign_symbol_roles",
                    "target": "lib",
                    "package_name": "foreign-symbol-roles"
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

    let mut bindings = BTreeMap::new();
    let mut lineages = BTreeMap::new();
    for fact in &facts {
        match &fact.payload {
            StaticFact::ForeignSymbolBinding(binding) => {
                bindings.insert(
                    format!("{}::{}", binding.api_id, binding.callback_param),
                    Binding {
                        symbol: binding.symbol.clone(),
                        callback_arg_index: binding.callback_arg_index,
                        userdata_arg_index: binding.userdata_arg_index,
                        resolution: binding.resolution,
                    },
                );
            }
            StaticFact::SafeEntryLineage(lineage) => {
                lineages.insert(
                    format!("{}::{}", lineage.api_id, lineage.callback_param),
                    Lineage {
                        lineage: lineage.lineage,
                        unresolved_reason: lineage.unresolved_reason.and_then(|reason| {
                            serde_json::to_value(reason)
                                .ok()
                                .and_then(|value| value.as_str().map(str::to_owned))
                        }),
                    },
                );
            }
            _ => {}
        }
    }
    assert!(!bindings.is_empty(), "fixture 必须产出 foreign symbol binding 事实");
    assert!(!lineages.is_empty(), "fixture 必须产出 safe-entry lineage 事实");
    (bindings, lineages)
}
