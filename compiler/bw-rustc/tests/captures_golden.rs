use std::{collections::BTreeMap, fs, process::Command};

use bw_model::{CaptureMode, SiteId, StaticFact, StaticFactEnvelope};

#[test]
fn callback_capture_fixture_emits_static_facts() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/callback-captures/Cargo.toml");
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
                { "crate_name": "callback_captures", "target": "lib" }
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

    let facts = read_static_facts(&analysis_dir.join("static-facts.jsonl"));
    let capture_modes = facts
        .iter()
        .filter_map(|fact| match &fact.payload {
            StaticFact::CallbackCapture(capture) => Some(capture.capture_mode),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(
        capture_modes.contains(&CaptureMode::Borrowed),
        "borrowed capture should be extracted"
    );
    assert!(
        capture_modes.contains(&CaptureMode::Owned),
        "owned capture should be extracted"
    );
    assert!(
        capture_modes.len() >= 5,
        "expected all fixture captures, got {capture_modes:?}"
    );

    let actual = normalized_fact_lines(&facts);
    let expected = read_expected_lines(&repo.join("fixtures/compiler/captures.expected.jsonl"));
    assert_eq!(expected, actual);
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

fn read_expected_lines(path: &std::path::Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("captures.expected.jsonl should exist")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalized_fact_lines(facts: &[StaticFactEnvelope]) -> Vec<String> {
    let mut callback_by_site = BTreeMap::<SiteId, String>::new();
    for fact in facts {
        if let StaticFact::CallbackSite(callback) = &fact.payload {
            callback_by_site.insert(callback.site_id.clone(), callback.def_path.clone());
        }
    }

    let mut lines = facts
        .iter()
        .map(|fact| match &fact.payload {
            StaticFact::ObjectSite(object) => serde_json::json!({
                "kind": "object_site",
                "type_name": object.type_name,
            }),
            StaticFact::CallbackSite(callback) => serde_json::json!({
                "kind": "callback_site",
                "def_path": callback.def_path,
            }),
            StaticFact::CallbackCapture(capture) => serde_json::json!({
                "kind": "callback_capture",
                "callback_def_path": callback_by_site
                    .get(&capture.callback_site_id)
                    .expect("capture should reference emitted callback site"),
                "capture_ordinal": capture.capture_ordinal,
                "capture_mode": capture.capture_mode,
            }),
            StaticFact::ObjectFlow(flow)
                if flow.flow_kind == bw_model::ObjectFlowKind::ClosureCapture =>
            {
                serde_json::json!({
                    "kind": "object_flow",
                    "callback_def_path": callback_by_site
                        .get(&flow.to_site_id)
                        .expect("closure-capture flow should reference emitted callback site"),
                    "flow_kind": flow.flow_kind,
                    "field_path": flow.field_path,
                })
            }
            StaticFact::ObjectFlow(flow)
                if flow.flow_kind == bw_model::ObjectFlowKind::FieldLoad
                    && flow.from_object_kind == bw_model::ObjectFlowObjectKind::Callback
                    && flow.field_path.as_deref().is_some_and(|field_path| {
                        field_path.starts_with("closure_capture_ordinal:")
                    }) =>
            {
                serde_json::json!({
                    "kind": "object_flow",
                    "callback_def_path": callback_by_site
                        .get(&flow.from_site_id)
                        .expect("closure-use flow should reference emitted callback site"),
                    "flow_kind": flow.flow_kind,
                    "field_path": flow.field_path,
                })
            }
            other => panic!("unexpected fact in capture golden: {other:?}"),
        })
        .map(|value| serde_json::to_string(&value).expect("normalized fact should serialize"))
        .collect::<Vec<_>>();
    lines.sort();
    lines
}
