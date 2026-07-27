use std::{fs, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use assert_cmd::Command;
use predicates::prelude::*;
use sha2::{Digest, Sha256};

#[test]
fn malformed_trace_exits_two_without_finding() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("malformed-trace.jsonl");
    fs::write(
        &trace,
        [
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:start","run_id":"run:test","trace_id":"trace:test","seq":0,"thread_id":"main","source":"cli-test","payload":{"kind":"trace_start","build_id":"build:test"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:use","run_id":"run:test","trace_id":"trace:test","seq":1,"thread_id":"main","source":"cli-test","payload":{"kind":"object_use","instance_id":"object:missing","use_site_id":"site:use","use_kind":"read"}}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args(["validate", "--kind", "trace", trace.to_str().unwrap()])
        .assert()
        .code(2)
        .stdout("")
        .stderr(predicate::str::contains("BW-TRACE"));
}

#[test]
fn analyze_prints_findings_jsonl_and_exits_one() {
    let temp = tempfile::tempdir().unwrap();
    let inputs = write_minimal_inputs(temp.path());

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "analyze",
            "--static",
            inputs.static_facts.to_str().unwrap(),
            "--contract",
            inputs.contract.to_str().unwrap(),
            "--trace",
            inputs.trace.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr("")
        .stdout(predicate::str::contains(r#""rule_id":"BW-LIFE-002""#));
}

#[test]
fn diff_outputs_checkpoint_aware_json_and_exits_one_for_added_findings() {
    let temp = tempfile::tempdir().unwrap();
    let inputs = write_minimal_inputs(temp.path());
    let baseline = temp.path().join("baseline-findings.jsonl");
    let candidate = temp.path().join("candidate-findings.jsonl");
    fs::write(&baseline, "").unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "analyze",
            "--static",
            inputs.static_facts.to_str().unwrap(),
            "--contract",
            inputs.contract.to_str().unwrap(),
            "--trace",
            inputs.trace.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr("");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "diff",
            "--baseline",
            baseline.to_str().unwrap(),
            "--candidate",
            candidate.to_str().unwrap(),
            "--baseline-trace",
            inputs.trace.to_str().unwrap(),
            "--candidate-trace",
            inputs.trace.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""comparable":true"#)
                .and(predicate::str::contains(r#""added_signatures":["#)),
        );
}

#[test]
fn validate_v3_2_corpus_manifest_accepts_public_intake_records() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        [
            r#"{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.pilot.001","crate_id":"crate:alpha","crate_name":"alpha","version":"1.2.3","source_kind":"crates_io","source_ref":"crates.io:alpha:1.2.3","selection_reason":["native_dependency","callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}"#,
            r#"{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.pilot.001","crate_id":"crate:beta","crate_name":"beta","version":"0.9.0","source_kind":"crates_io","source_ref":"crates.io:beta:0.9.0","selection_reason":["manual_exclusion_record"],"intake_status":"excluded","intake_notes":["requires unsupported non-Linux target"]}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-corpus-manifest",
            manifest.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-corpus-manifest""#)
                .and(predicate::str::contains(r#""record_count":2"#))
                .and(predicate::str::contains(r#""accepted_count":1"#))
                .and(predicate::str::contains(r#""excluded_count":1"#)),
        );
}

#[test]
fn validate_v3_2_corpus_manifest_accepts_v3_3_lifecycle_intake_reasons() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        r#"{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-3.sealed.holdout.r2","crate_id":"crate:alpha:1.0.0","crate_name":"alpha","version":"1.0.0","source_kind":"local_archive","source_ref":"sources/alpha-1.0.0","selection_reason":["pure_rust","iterator_api_candidate","container_lifecycle_surface"],"intake_status":"accepted","intake_notes":[]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-corpus-manifest",
            manifest.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""record_count":1"#));
}

#[test]
fn validate_v3_3_scanner_freeze_accepts_public_freeze_record() {
    let temp = tempfile::tempdir().unwrap();
    let freeze = temp.path().join("scanner-freeze.json");
    fs::write(&freeze, scanner_freeze_fixture()).unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-3-scanner-freeze",
            freeze.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-3-scanner-freeze""#)
                .and(predicate::str::contains(r#""record_count":1"#)),
        );
}

#[test]
fn validate_v3_2_public_records_reject_unknown_fields() {
    let temp = tempfile::tempdir().unwrap();

    let manifest = temp.path().join("corpus-manifest-unknown.jsonl");
    fs::write(
        &manifest,
        r#"{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.pilot.001","crate_id":"crate:alpha","crate_name":"alpha","version":"1.2.3","source_kind":"crates_io","source_ref":"crates.io:alpha:1.2.3","selection_reason":["native_dependency"],"intake_status":"accepted","intake_notes":[],"unexpected":"nope"}"#,
    )
    .unwrap();
    assert_validate_fails(
        "v3-2-corpus-manifest",
        &manifest,
        predicate::str::contains("unknown field"),
    );

    let ranked = temp.path().join("ranked-candidate-unknown.jsonl");
    fs::write(
        &ranked,
        r#"{"schema_version":"v3.2.ranked_candidate.1","run_id":"run:v3-2","rank":1,"candidate_id":"candidate:alpha","crate_id":"crate:alpha","pattern_family":"native_library_boundary","score":2,"score_breakdown":{"foreign_retention_without_owned_anchor":0,"missing_unregister_before_drop":0,"cross_language_alias":0,"opaque_handle_without_owner":0,"callback_retained_across_drop":0,"confidence_bonus":2},"risk_features":{"foreign_retention_without_owned_anchor":false,"missing_unregister_before_drop":false,"cross_language_alias":false,"opaque_handle_without_owner":false,"callback_retained_across_drop":false},"lifecycle_graph_path":"lifecycle-graphs/candidate-alpha.json","ranking_reason":"score=2; active_risk_features=none; confidence_bonus=2","notes":[],"unexpected":"nope"}"#,
    )
    .unwrap();
    assert_validate_fails(
        "v3-2-ranked-candidate",
        &ranked,
        predicate::str::contains("unknown field"),
    );
}

#[test]
fn validate_v3_2_public_records_reject_forbidden_tokens() {
    let temp = tempfile::tempdir().unwrap();

    let boundary = temp.path().join("boundary-index-token.jsonl");
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v3-2","crate_id":"crate:alpha","boundary_id":"boundary:alpha","boundary_kind":"native_library","api_path":"alpha::ffi","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":1}],"confidence":"medium","notes":["vulnerable marker must not be public"]}"#,
    )
    .unwrap();
    assert_validate_fails(
        "v3-2-boundary-index",
        &boundary,
        predicate::str::contains("BW-BOUNDARY-PRIVATE-TOKEN"),
    );

    let candidate = temp.path().join("candidate-token.jsonl");
    fs::write(
        &candidate,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v3-2","candidate_id":"candidate:alpha","crate_id":"crate:alpha","boundary_id":"boundary:alpha","pattern_family":"native_library_boundary","confidence":"static_only","evidence_refs":[{"kind":"source_span","path":"src/fixed.rs","line_start":1,"line_end":1}],"api_path":"alpha::ffi","recommended_next_step":"generate_lifecycle_subgraph","notes":[]}"#,
    )
    .unwrap();
    assert_validate_fails(
        "v3-2-candidate",
        &candidate,
        predicate::str::contains("BW-CANDIDATE-PRIVATE-TOKEN"),
    );

    let graph = temp.path().join("lifecycle-graph-token.json");
    fs::write(
        &graph,
        r#"{"schema_version":"v3.2.lifecycle_graph.1","run_id":"run:v3-2","candidate_id":"candidate:alpha","crate_id":"crate:alpha","pattern_family":"native_library_boundary","nodes":[{"node_id":"n1","node_kind":"rust_object","label":"expected owner","lifetime_role":"owned"},{"node_id":"n2","node_kind":"foreign_api","label":"ffi api","lifetime_role":"unknown"}],"edges":[{"from":"n1","to":"n2","edge_kind":"alias_across_languages","evidence_ref":"src/lib.rs:1"}],"risk_features":{"foreign_retention_without_owned_anchor":false,"missing_unregister_before_drop":false,"cross_language_alias":true,"opaque_handle_without_owner":false,"callback_retained_across_drop":false},"notes":[]}"#,
    )
    .unwrap();
    assert_validate_fails(
        "v3-2-lifecycle-graph",
        &graph,
        predicate::str::contains("BW-LIFECYCLE-PRIVATE-TOKEN"),
    );

    let ranked = temp.path().join("ranked-candidate-token.jsonl");
    fs::write(
        &ranked,
        r#"{"schema_version":"v3.2.ranked_candidate.1","run_id":"run:v3-2","rank":1,"candidate_id":"candidate:alpha","crate_id":"crate:alpha","pattern_family":"native_library_boundary","score":2,"score_breakdown":{"foreign_retention_without_owned_anchor":0,"missing_unregister_before_drop":0,"cross_language_alias":0,"opaque_handle_without_owner":0,"callback_retained_across_drop":0,"confidence_bonus":2},"risk_features":{"foreign_retention_without_owned_anchor":false,"missing_unregister_before_drop":false,"cross_language_alias":false,"opaque_handle_without_owner":false,"callback_retained_across_drop":false},"lifecycle_graph_path":"lifecycle-graphs/candidate-alpha.json","ranking_reason":"patch evidence should not be public","notes":[]}"#,
    )
    .unwrap();
    assert_validate_fails(
        "v3-2-ranked-candidate",
        &ranked,
        predicate::str::contains("BW-RANK-PRIVATE-TOKEN"),
    );

    let adapter = temp.path().join("adapter-effort-token.jsonl");
    fs::write(
        &adapter,
        r#"{"schema_version":"v3.2.adapter_effort.1","run_id":"run:v3-2","candidate_id":"candidate:alpha","crate_id":"crate:alpha","pattern_family":"native_library_boundary","rank":1,"score":2,"adapter_needed":false,"adapter_kind":"none","effort_class":"deferred","manual_minutes":0,"generated_lines":0,"manual_lines":0,"blocked_reason":"advisory-linked sample","notes":[]}"#,
    )
    .unwrap();
    assert_validate_fails(
        "v3-2-adapter-effort",
        &adapter,
        predicate::str::contains("BW-ADAPTER-PRIVATE-TOKEN"),
    );

    let taxonomy = temp.path().join("failure-taxonomy-token.jsonl");
    fs::write(
        &taxonomy,
        r#"{"schema_version":"v3.2.failure_taxonomy.1","run_id":"run:v3-2","subject_kind":"candidate","subject_id":"candidate:alpha","crate_id":"crate:alpha","stage":"dynamic_prep","failure_class":"deferred_static_only","is_infrastructure_failure":false,"is_method_negative":false,"notes":["poc label must not be public"]}"#,
    )
    .unwrap();
    assert_validate_fails(
        "v3-2-failure-taxonomy",
        &taxonomy,
        predicate::str::contains("BW-TAXONOMY-PRIVATE-TOKEN"),
    );
}

#[test]
fn validate_static_accepts_aggregate_multiple_builds() {
    let temp = tempfile::tempdir().unwrap();
    let facts = temp.path().join("static-facts.jsonl");
    fs::write(
        &facts,
        [
            r#"{"schema_version":"bw.static/0.2","record_id":"static:build-a:callback","producer":"cli-test","build_id":"build:a","artifact":{"crate_id":"crate:a:0.1.0","package_name":"a","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"a::callback"},"payload":{"kind":"callback_site","site_id":"callback:a","semantic_site_key":"semantic:a","def_path":"a::callback"}}"#,
            r#"{"schema_version":"bw.static/0.2","record_id":"static:build-b:callback","producer":"cli-test","build_id":"build:b","artifact":{"crate_id":"crate:b:0.1.0","package_name":"b","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"b::callback"},"payload":{"kind":"callback_site","site_id":"callback:b","semantic_site_key":"semantic:b","def_path":"b::callback"}}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args(["validate", "--kind", "static", facts.to_str().unwrap()])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"static""#)
                .and(predicate::str::contains(r#""record_count":2"#)),
        );
}

#[test]
fn validate_static_keeps_same_build_id_artifacts_separate() {
    let temp = tempfile::tempdir().unwrap();
    let facts = temp.path().join("static-facts.jsonl");
    fs::write(
        &facts,
        [
            r#"{"schema_version":"bw.static/0.2","record_id":"static:shared:callback","producer":"cli-test","build_id":"build:shared","artifact":{"crate_id":"crate:openssl:0.10.69","package_name":"openssl","package_version":"0.10.69","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"openssl::callback"},"payload":{"kind":"callback_site","site_id":"callback:shared","semantic_site_key":"semantic:shared","def_path":"openssl::callback"}}"#,
            r#"{"schema_version":"bw.static/0.2","record_id":"static:shared:callback","producer":"cli-test","build_id":"build:shared","artifact":{"crate_id":"crate:openssl:0.10.70","package_name":"openssl","package_version":"0.10.70","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"openssl::callback"},"payload":{"kind":"callback_site","site_id":"callback:shared","semantic_site_key":"semantic:shared","def_path":"openssl::callback"}}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args(["validate", "--kind", "static", facts.to_str().unwrap()])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"static""#)
                .and(predicate::str::contains(r#""record_count":2"#)),
        );
}

#[test]
fn extract_lifecycle_static_facts_only_emits_verifiable_provenance_chain() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("scoped");
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"
[package]
name = "scoped"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        crate_dir.join("src/lib.rs"),
        [
            "pub fn near_boundary() {",
            "    let anchor = 1;",
            "    let callback = || anchor;",
            "    callback();",
            "    let far = 2;",
            "    drop(far);",
            "    let _tail = far;",
            "}",
        ]
        .join("\n"),
    )
    .unwrap();

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.provenance-test","crate_id":"crate:scoped:0.1.0","crate_name":"scoped","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let boundary = temp.path().join("boundary-index.jsonl");
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:scoped:0.1.0","boundary_id":"boundary:scoped:001","boundary_kind":"callback_registration","api_path":"source_api::scoped","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":1}],"confidence":"high","notes":["synthetic boundary"]}"#,
    )
    .unwrap();

    let candidates = temp.path().join("candidates.jsonl");
    fs::write(
        &candidates,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:scoped:001","crate_id":"crate:scoped:0.1.0","boundary_id":"boundary:scoped:001","pattern_family":"foreign_retained_pointer","confidence":"static_only","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":1}],"api_path":"source_api::scoped","recommended_next_step":"generate_lifecycle_subgraph","notes":["candidate is not a vulnerability conclusion"]}"#,
    )
    .unwrap();

    let static_facts = temp.path().join("static-facts.jsonl");
    fs::write(
        &static_facts,
        [
            r#"{"schema_version":"bw.static/0.2","record_id":"fact:object:anchor","producer":"cli-test","build_id":"build:scoped:lib","artifact":{"crate_id":"crate:scoped:0.1.0","package_name":"scoped","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"scoped::near_boundary"},"payload":{"kind":"object_site","site_id":"site:anchor","semantic_site_key":"semantic:anchor","type_name":"usize"}}"#,
            r#"{"schema_version":"bw.static/0.2","record_id":"fact:capture:anchor","producer":"cli-test","build_id":"build:scoped:lib","artifact":{"crate_id":"crate:scoped:0.1.0","package_name":"scoped","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":5,"line_end":5,"symbol_path":"scoped::near_boundary::{closure#0}"},"payload":{"kind":"callback_capture","site_id":"site:capture-anchor","semantic_site_key":"semantic:capture-anchor","callback_site_id":"site:callback","object_site_id":"site:anchor","capture_ordinal":0,"capture_mode":"borrowed"}}"#,
            r#"{"schema_version":"bw.static/0.2","record_id":"fact:capture:far","producer":"cli-test","build_id":"build:scoped:lib","artifact":{"crate_id":"crate:scoped:0.1.0","package_name":"scoped","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":6,"line_end":6,"symbol_path":"scoped::near_boundary::{closure#0}"},"payload":{"kind":"callback_capture","site_id":"site:capture-far","semantic_site_key":"semantic:capture-far","callback_site_id":"site:callback","object_site_id":"site:far-object","capture_ordinal":1,"capture_mode":"borrowed"}}"#,
            r#"{"schema_version":"bw.static/0.2","record_id":"fact:object:far","producer":"cli-test","build_id":"build:scoped:lib","artifact":{"crate_id":"crate:scoped:0.1.0","package_name":"scoped","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":7,"line_end":7,"symbol_path":"scoped::near_boundary"},"payload":{"kind":"object_site","site_id":"site:far-object","semantic_site_key":"semantic:far-object","type_name":"usize"}}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let output_dir = temp.path().join("lifecycle-evidence");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-lifecycle-evidence",
            "--manifest",
            manifest.to_str().unwrap(),
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--candidates",
            candidates.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--run-id",
            "run:v326-provenance-test",
        ])
        .assert()
        .code(0)
        .stderr("");

    let graph_dir = temp.path().join("lifecycle-v3");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates.to_str().unwrap(),
            "--evidence",
            output_dir
                .join("lifecycle-evidence.jsonl.zst")
                .to_str()
                .unwrap(),
            "--facts",
            output_dir
                .join("lifecycle-facts.jsonl.zst")
                .to_str()
                .unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            graph_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-provenance-test",
        ])
        .assert()
        .code(0)
        .stderr("");

    let fact_text = read_zstd_to_string(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert!(fact_text.contains(r#""static_fact_record_id":"fact:object:anchor""#));
    assert!(!fact_text.contains(r#""static_fact_record_id":"fact:object:far""#));
}

#[test]
fn extract_lifecycle_atomic_ordering_static_facts_stay_candidate_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("atomic-scoped");
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"
[package]
name = "atomic-scoped"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        crate_dir.join("src/lib.rs"),
        [
            "pub mod raw {",
            "    pub fn next() { let _ = \"AtomicPtr::load(Relaxed)\"; }",
            "}",
            "",
            "pub mod filler_a {",
            "    pub fn a() {}",
            "}",
            "pub mod filler_b {",
            "    pub fn b() {}",
            "}",
            "pub mod filler_c {",
            "    pub fn c() {}",
            "}",
            "pub mod filler_d {",
            "    pub fn d() {}",
            "}",
            "pub mod counter {",
            "    pub fn get() { let _ = \"AtomicUsize::load(Relaxed)\"; }",
            "}",
        ]
        .join("\n"),
    )
    .unwrap();

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.atomic-scope-test","crate_id":"crate:atomic-scoped:0.1.0","crate_name":"atomic-scoped","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["iterator_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let boundary = temp.path().join("boundary-index.jsonl");
    fs::write(
        &boundary,
        [
            r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:atomic-scoped:0.1.0","boundary_id":"boundary:atomic:raw","boundary_kind":"returned_borrow","api_path":"raw::RelaxedIter::<T>::next","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":2,"line_end":2}],"confidence":"medium","notes":["synthetic atomic ordering boundary"]}"#,
            r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:atomic-scoped:0.1.0","boundary_id":"boundary:atomic:counter","boundary_kind":"returned_borrow","api_path":"counter::Counter::get","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":18,"line_end":18}],"confidence":"medium","notes":["synthetic counter boundary"]}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let candidates = temp.path().join("candidates.jsonl");
    fs::write(
        &candidates,
        [
            r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:atomic:raw","crate_id":"crate:atomic-scoped:0.1.0","boundary_id":"boundary:atomic:raw","pattern_family":"returned_borrow_view","confidence":"static_only","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":2,"line_end":2}],"api_path":"raw::RelaxedIter::<T>::next","recommended_next_step":"generate_lifecycle_subgraph","notes":["candidate is not a vulnerability conclusion"]}"#,
            r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:atomic:counter","crate_id":"crate:atomic-scoped:0.1.0","boundary_id":"boundary:atomic:counter","pattern_family":"returned_borrow_view","confidence":"static_only","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":18,"line_end":18}],"api_path":"counter::Counter::get","recommended_next_step":"generate_lifecycle_subgraph","notes":["candidate is not a vulnerability conclusion"]}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let static_facts = temp.path().join("static-facts.jsonl");
    fs::write(
        &static_facts,
        [
            r#"{"schema_version":"bw.static/0.2","record_id":"static:atomic:raw-next","producer":"cli-test","build_id":"build:atomic-scoped:lib","artifact":{"crate_id":"crate:atomic-scoped:0.1.0","package_name":"atomic-scoped","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":2,"line_end":2,"symbol_path":"raw::RelaxedIter::<T>::next"},"payload":{"kind":"atomic_ordering","site_id":"site:atomic:raw-next","semantic_site_key":"semantic:atomic:raw-next","api_id":"raw::RelaxedIter::<T>::next","operation":"load","ordering":"relaxed","target_type_name":"std::sync::atomic::AtomicPtr<Node<T>>"}}"#,
            r#"{"schema_version":"bw.static/0.2","record_id":"static:atomic:counter-get","producer":"cli-test","build_id":"build:atomic-scoped:lib","artifact":{"crate_id":"crate:atomic-scoped:0.1.0","package_name":"atomic-scoped","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":18,"line_end":18,"symbol_path":"counter::Counter::get"},"payload":{"kind":"atomic_ordering","site_id":"site:atomic:counter-get","semantic_site_key":"semantic:atomic:counter-get","api_id":"counter::Counter::get","operation":"load","ordering":"relaxed","target_type_name":"std::sync::atomic::AtomicUsize"}}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let output_dir = temp.path().join("lifecycle-evidence");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-lifecycle-evidence",
            "--manifest",
            manifest.to_str().unwrap(),
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--candidates",
            candidates.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--run-id",
            "run:v326-atomic-scope-test",
        ])
        .assert()
        .code(0)
        .stderr("");

    let fact_text = read_zstd_to_string(&output_dir.join("lifecycle-facts.jsonl.zst"));
    let raw_facts = fact_text
        .lines()
        .filter(|line| line.contains(r#""candidate_id":"candidate:atomic:raw""#))
        .collect::<Vec<_>>();
    let counter_facts = fact_text
        .lines()
        .filter(|line| line.contains(r#""candidate_id":"candidate:atomic:counter""#))
        .collect::<Vec<_>>();
    assert!(
        raw_facts
            .iter()
            .any(|line| line.contains(r#""static_fact_record_id":"static:atomic:raw-next""#))
    );
    assert!(
        !raw_facts
            .iter()
            .any(|line| line.contains(r#""static_fact_record_id":"static:atomic:counter-get""#))
    );
    assert!(
        counter_facts
            .iter()
            .any(|line| line.contains(r#""static_fact_record_id":"static:atomic:counter-get""#))
    );
    assert!(
        !counter_facts
            .iter()
            .any(|line| line.contains(r#""static_fact_record_id":"static:atomic:raw-next""#))
    );
}

#[test]
fn extract_lifecycle_object_flow_with_multiple_claimants_is_not_duplicated() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("object-flow-scoped");
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"
[package]
name = "object-flow-scoped"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        crate_dir.join("src/lib.rs"),
        [
            "pub mod object_flow_demo {",
            "    pub fn unrelated() {}",
            "    pub fn borrow_view() {",
            "        let owner = 1;",
            "        let view = &owner;",
            "        let _ = view;",
            "    }",
            "}",
        ]
        .join("\n"),
    )
    .unwrap();

    let source_alias = format!(
        "source_api::{}",
        hex_digest(Sha256::digest(b"src::lib::borrow_view"))
    );
    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.object-flow-scope-test","crate_id":"crate:object-flow-scoped:0.1.0","crate_name":"object-flow-scoped","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["iterator_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let boundary = temp.path().join("boundary-index.jsonl");
    fs::write(
        &boundary,
        [
            r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:object-flow-scoped:0.1.0","boundary_id":"boundary:object-flow:owned","boundary_kind":"returned_borrow","api_path":"object_flow_demo::borrow_view","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":5,"line_end":5}],"confidence":"medium","notes":["synthetic object flow boundary"]}"#.to_owned(),
            format!(r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:object-flow-scoped:0.1.0","boundary_id":"boundary:object-flow:alias","boundary_kind":"returned_borrow","api_path":"{source_alias}","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":7,"line_end":7}}],"confidence":"medium","notes":["synthetic object flow alias boundary"]}}"#),
        ]
        .join("\n"),
    )
    .unwrap();

    let candidates = temp.path().join("candidates.jsonl");
    fs::write(
        &candidates,
        [
            r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:object-flow:owned","crate_id":"crate:object-flow-scoped:0.1.0","boundary_id":"boundary:object-flow:owned","pattern_family":"returned_borrow_view","confidence":"static_only","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":5,"line_end":5}],"api_path":"object_flow_demo::borrow_view","recommended_next_step":"generate_lifecycle_subgraph","notes":["candidate is not a vulnerability conclusion"]}"#.to_owned(),
            format!(r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:object-flow:alias","crate_id":"crate:object-flow-scoped:0.1.0","boundary_id":"boundary:object-flow:alias","pattern_family":"returned_borrow_view","confidence":"static_only","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":7,"line_end":7}}],"api_path":"{source_alias}","recommended_next_step":"generate_lifecycle_subgraph","notes":["candidate is not a vulnerability conclusion"]}}"#),
        ]
        .join("\n"),
    )
    .unwrap();

    let static_facts = temp.path().join("static-facts.jsonl");
    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:object-flow:ambiguous","producer":"cli-test","build_id":"build:object-flow:lib","artifact":{"crate_id":"crate:object-flow-scoped:0.1.0","package_name":"object-flow-scoped","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":5,"line_end":5,"symbol_path":"object_flow_demo::borrow_view"},"payload":{"kind":"object_flow","site_id":"site:flow:borrow-view","semantic_site_key":"semantic:flow:borrow-view","from_site_id":"site:owner","from_object_kind":"rust_owner","to_site_id":"site:returned","to_object_kind":"returned_ref","flow_kind":"return_value","api_id":"object_flow_demo::borrow_view"}}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("lifecycle-evidence");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-lifecycle-evidence",
            "--manifest",
            manifest.to_str().unwrap(),
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--candidates",
            candidates.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--run-id",
            "run:v326-object-flow-scope-test",
        ])
        .assert()
        .code(0)
        .stderr("");

    let fact_text = read_zstd_to_string(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert!(
        !fact_text.contains(r#""static_fact_record_id":"static:object-flow:ambiguous""#),
        "{fact_text}"
    );
    assert!(
        !fact_text.contains(r#""fact_kind":"object_flow""#),
        "{fact_text}"
    );
}

#[test]
fn build_witness_plan_uses_returned_view_chain_for_miri_handoff() {
    let temp = tempfile::tempdir().unwrap();
    let graph_dir = temp.path().join("graphs-v3");
    fs::create_dir_all(&graph_dir).unwrap();
    fs::write(
        graph_dir.join("candidate_returned.json"),
        r#"{
  "schema_version":"v3.2.6.lifecycle_graph_v3.1",
  "run_id":"run:v326",
  "candidate_id":"candidate:returned",
  "crate_id":"crate:returned:0.1.0",
  "pattern_family":"returned_borrow_view",
  "objects":[
    {"object_id":"rust_owner:site:owner","object_kind":"rust_owner","label":"rust_owner:site:owner","source_ref":null,"fact_refs":["fact:returned:relation"]},
    {"object_id":"returned_ref:site:view","object_kind":"returned_ref","label":"returned_ref:site:view","source_ref":null,"fact_refs":["fact:returned:relation","fact:returned:persist"]},
    {"object_id":"storage:site:slot","object_kind":"storage","label":"storage:site:slot","source_ref":null,"fact_refs":["fact:returned:persist"]},
    {"object_id":"static_site:site:invalidate","object_kind":"static_site","label":"static_site:site:invalidate","source_ref":null,"fact_refs":["fact:returned:order"]}
  ],
  "edges":[
    {"edge_id":"edge:returned:borrow","from_object_id":"rust_owner:site:owner","to_object_id":"returned_ref:site:view","relation":"borrow","ordering":"same_site","evidence_refs":[],"fact_refs":["fact:returned:relation"]},
    {"edge_id":"edge:returned:persist","from_object_id":"returned_ref:site:view","to_object_id":"storage:site:slot","relation":"persist","ordering":"same_site","evidence_refs":[],"fact_refs":["fact:returned:persist"]},
    {"edge_id":"edge:returned:invalidate","from_object_id":"storage:site:slot","to_object_id":"static_site:site:invalidate","relation":"invalidate","ordering":"before","evidence_refs":[],"fact_refs":["fact:returned:order"]}
  ],
  "object_chains":[
    {"chain_id":"chain:returned:view","object_ids":["rust_owner:site:owner","returned_ref:site:view","storage:site:slot","static_site:site:invalidate"],"edge_ids":["edge:returned:borrow","edge:returned:persist","edge:returned:invalidate"],"fact_refs":["fact:returned:relation","fact:returned:persist","fact:returned:order"],"evidence_refs":["evidence:returned:1"],"chain_status":"verified_static_chain"}
  ],
  "evidence_refs":["evidence:returned:1"],
  "incomplete_reasons":[],
  "notes":["graph v3 is object-bound and not a defect conclusion"]
}"#,
    )
    .unwrap();
    let ranked = temp.path().join("ranked.jsonl");
    fs::write(
        &ranked,
        r#"{"schema_version":"v3.2.6.ranked_candidate_v2.1","run_id":"run:v326","rank":1,"score":36,"score_breakdown":{"has_foreign_register":0,"foreign_may_retain_callback":0,"foreign_may_retain_user_data":0,"has_borrowed_capture":0,"has_raw_pointer_escape":0,"raw_parts_transfer_without_drop_prevention":0,"has_drop_prevention":0,"manual_drop_prevention_without_drop_guard":0,"callback_user_data_owner_reconstruction_without_leak_guard":0,"has_returned_borrow_relation":8,"has_unconstrained_return_lifetime":0,"has_persisted_returned_borrow":4,"returned_borrow_persistence_before_invalidation":14,"returned_borrow_persistence_after_invalidation":0,"has_external_buffer_binding":0,"has_external_buffer_lifetime_bound":0,"relaxed_atomic_load_in_iterator":0,"acquire_atomic_load_in_iterator":0,"has_verified_object_chain":4,"has_release_order_chain":0,"has_persisted_invalidation_use_chain":6,"rust_object_may_drop_before_foreign_release":0,"missing_unregister_before_drop":0,"release_order_unknown":0,"opaque_handle_without_owner":0,"needs_dynamic_witness":0,"has_owned_anchor":0,"has_drop_guard":0,"registration_release_pair_found":0,"has_static_bound":0,"has_arc_anchor":0,"release_covers_callback":0},"candidate_id":"candidate:returned","crate_id":"crate:returned:0.1.0","pattern_family":"returned_borrow_view","risk_features":["has_returned_borrow_relation","has_persisted_returned_borrow","returned_borrow_persistence_before_invalidation","has_verified_object_chain","has_persisted_invalidation_use_chain"],"protective_features":[],"feature_evidence_refs":{"has_persisted_invalidation_use_chain":["fact:returned:order"]},"missing_evidence":[],"lifecycle_graph_path":"graphs-v3/candidate_returned.json","ranking_reason":"score=36; candidate ranking is not a defect conclusion","notes":["candidate ranking is not a defect conclusion"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("witness");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-witness-plan",
            "--ranked-candidates",
            ranked.to_str().unwrap(),
            "--graphs-dir",
            graph_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-witness-object-flow-test",
        ])
        .assert()
        .code(0)
        .stderr("");

    let plan_text = read_zstd_to_string(&output_dir.join("witness-plans.jsonl.zst"));
    assert!(plan_text.contains(r#""action_kind":"persist_returned_view""#));
    assert!(plan_text.contains(r#""action_kind":"invalidate_owner""#));
    assert!(plan_text.contains(r#""action_kind":"use_returned_view""#));
    assert!(plan_text.contains(r#""action_kind":"run_miri_check""#));
    assert!(!plan_text.contains(r#""action_kind":"register_callback""#));
}

#[test]
fn build_witness_plan_routes_external_buffer_to_lifetime_plan() {
    let temp = tempfile::tempdir().unwrap();
    let graph_dir = temp.path().join("graphs-v3");
    fs::create_dir_all(&graph_dir).unwrap();
    fs::write(
        graph_dir.join("candidate_external.json"),
        r#"{
  "schema_version":"v3.2.6.lifecycle_graph_v3.1",
  "run_id":"run:v326",
  "candidate_id":"candidate:external",
  "crate_id":"crate:external:0.1.0",
  "pattern_family":"external_buffer_view",
  "objects":[
    {"object_id":"rust_owner:site:source","object_kind":"rust_owner","label":"rust_owner:site:source","source_ref":null,"fact_refs":["fact:external:binding"]},
    {"object_id":"user_data:site:buffer","object_kind":"user_data","label":"user_data:site:buffer","source_ref":null,"fact_refs":["fact:external:binding"]}
  ],
  "edges":[
    {"edge_id":"edge:external:binding","from_object_id":"rust_owner:site:source","to_object_id":"user_data:site:buffer","relation":"raw_escape","ordering":"same_site","evidence_refs":["evidence:external:1"],"fact_refs":["fact:external:binding"]}
  ],
  "object_chains":[
    {"chain_id":"chain:external:binding","object_ids":["rust_owner:site:source","user_data:site:buffer"],"edge_ids":["edge:external:binding"],"fact_refs":["fact:external:binding"],"evidence_refs":["evidence:external:1"],"chain_status":"partial_chain"}
  ],
  "evidence_refs":["evidence:external:1"],
  "incomplete_reasons":["use_ordering_proof_missing"],
  "notes":["graph v3 is object-bound and not a defect conclusion"]
}"#,
    )
    .unwrap();
    let ranked = temp.path().join("ranked.jsonl");
    fs::write(
        &ranked,
        r#"{"schema_version":"v3.2.6.ranked_candidate_v2.1","run_id":"run:v326","rank":1,"score":10,"score_breakdown":{"has_foreign_register":0,"foreign_may_retain_callback":0,"foreign_may_retain_user_data":0,"has_borrowed_capture":0,"has_raw_pointer_escape":0,"raw_parts_transfer_without_drop_prevention":0,"has_drop_prevention":0,"manual_drop_prevention_without_drop_guard":0,"callback_user_data_owner_reconstruction_without_leak_guard":0,"has_returned_borrow_relation":0,"has_unconstrained_return_lifetime":0,"has_persisted_returned_borrow":0,"returned_borrow_persistence_before_invalidation":0,"returned_borrow_persistence_after_invalidation":0,"has_external_buffer_binding":10,"has_external_buffer_lifetime_bound":0,"relaxed_atomic_load_in_iterator":0,"acquire_atomic_load_in_iterator":0,"has_verified_object_chain":0,"has_release_order_chain":0,"has_persisted_invalidation_use_chain":0,"rust_object_may_drop_before_foreign_release":0,"missing_unregister_before_drop":0,"release_order_unknown":0,"opaque_handle_without_owner":0,"needs_dynamic_witness":0,"has_owned_anchor":0,"has_drop_guard":0,"registration_release_pair_found":0,"has_static_bound":0,"has_arc_anchor":0,"release_covers_callback":0},"candidate_id":"candidate:external","crate_id":"crate:external:0.1.0","pattern_family":"external_buffer_view","risk_features":["has_external_buffer_binding"],"protective_features":[],"feature_evidence_refs":{"has_external_buffer_binding":["fact:external:binding"]},"missing_evidence":["complete_risk_chain_missing"],"lifecycle_graph_path":"graphs-v3/candidate_external.json","chain_summary":{"top_chain_id":"chain:external:binding","top_chain_status":"partial_chain","verified_chain_count":0,"partial_chain_count":1,"ambiguous_chain_count":0,"observation_only_chain_count":0,"chain_fact_refs":["fact:external:binding"],"chain_incomplete_reasons":["complete_risk_chain_missing"],"recommended_witness_route":"external_buffer_lifetime"},"ranking_reason":"score=10; candidate ranking is not a defect conclusion","notes":["candidate ranking is not a defect conclusion"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("witness");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-witness-plan",
            "--ranked-candidates",
            ranked.to_str().unwrap(),
            "--graphs-dir",
            graph_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-witness-external-buffer-test",
        ])
        .assert()
        .code(0)
        .stderr("");

    let plan_text = read_zstd_to_string(&output_dir.join("witness-plans.jsonl.zst"));
    assert!(plan_text.contains(r#""action_kind":"run_miri_check""#));
    assert!(plan_text.contains(r#""runtime_observers":["external_buffer_bind""#));
    assert!(plan_text.contains("route:external_buffer_lifetime"));
    assert!(plan_text.contains("graph_incomplete_reason:use_ordering_proof_missing"));
    assert!(!plan_text.contains(r#""action_kind":"register_callback""#));
    assert!(!plan_text.contains(r#""action_kind":"replace_or_unregister""#));
}

#[test]
fn build_witness_plan_rejects_ranked_graph_identity_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let graph_dir = temp.path().join("graphs-v3");
    fs::create_dir_all(&graph_dir).unwrap();
    fs::write(
        graph_dir.join("candidate_alpha.json"),
        r#"{
  "schema_version":"v3.2.6.lifecycle_graph_v3.1",
  "run_id":"run:v326",
  "candidate_id":"candidate:beta",
  "crate_id":"crate:beta:0.1.0",
  "pattern_family":"returned_borrow_view",
  "objects":[
    {"object_id":"rust_owner:site:owner","object_kind":"rust_owner","label":"rust_owner:site:owner","source_ref":null,"fact_refs":["fact:beta:relation"]},
    {"object_id":"returned_ref:site:view","object_kind":"returned_ref","label":"returned_ref:site:view","source_ref":null,"fact_refs":["fact:beta:relation"]}
  ],
  "edges":[
    {"edge_id":"edge:beta:borrow","from_object_id":"rust_owner:site:owner","to_object_id":"returned_ref:site:view","relation":"borrow","ordering":"same_site","evidence_refs":[],"fact_refs":["fact:beta:relation"]}
  ],
  "object_chains":[
    {"chain_id":"chain:beta:view","object_ids":["rust_owner:site:owner","returned_ref:site:view"],"edge_ids":["edge:beta:borrow"],"fact_refs":["fact:beta:relation"],"evidence_refs":[],"chain_status":"partial_chain"}
  ],
  "evidence_refs":[],
  "incomplete_reasons":["use_ordering_proof_missing"],
  "notes":["graph v3 is object-bound and not a defect conclusion"]
}"#,
    )
    .unwrap();
    let ranked = temp.path().join("ranked.jsonl");
    fs::write(
        &ranked,
        r#"{"schema_version":"v3.2.6.ranked_candidate_v2.1","run_id":"run:v326","rank":1,"score":8,"score_breakdown":{"has_foreign_register":0,"foreign_may_retain_callback":0,"foreign_may_retain_user_data":0,"has_borrowed_capture":0,"has_raw_pointer_escape":0,"raw_parts_transfer_without_drop_prevention":0,"has_drop_prevention":0,"manual_drop_prevention_without_drop_guard":0,"callback_user_data_owner_reconstruction_without_leak_guard":0,"has_returned_borrow_relation":8,"has_unconstrained_return_lifetime":0,"has_persisted_returned_borrow":0,"returned_borrow_persistence_before_invalidation":0,"returned_borrow_persistence_after_invalidation":0,"has_external_buffer_binding":0,"has_external_buffer_lifetime_bound":0,"relaxed_atomic_load_in_iterator":0,"acquire_atomic_load_in_iterator":0,"has_verified_object_chain":0,"has_release_order_chain":0,"has_persisted_invalidation_use_chain":0,"rust_object_may_drop_before_foreign_release":0,"missing_unregister_before_drop":0,"release_order_unknown":0,"opaque_handle_without_owner":0,"needs_dynamic_witness":0,"has_owned_anchor":0,"has_drop_guard":0,"registration_release_pair_found":0,"has_static_bound":0,"has_arc_anchor":0,"release_covers_callback":0},"candidate_id":"candidate:alpha","crate_id":"crate:alpha:0.1.0","pattern_family":"returned_borrow_view","risk_features":["has_returned_borrow_relation"],"protective_features":[],"feature_evidence_refs":{"has_returned_borrow_relation":["fact:alpha:relation"]},"missing_evidence":["use_ordering_proof_missing"],"lifecycle_graph_path":"graphs-v3/candidate_alpha.json","ranking_reason":"score=8; candidate ranking is not a defect conclusion","notes":["candidate ranking is not a defect conclusion"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("witness");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-witness-plan",
            "--ranked-candidates",
            ranked.to_str().unwrap(),
            "--graphs-dir",
            graph_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-witness-identity-mismatch-test",
        ])
        .assert()
        .code(2)
        .stdout("")
        .stderr(predicate::str::contains("BW-V326-WITNESS-GRAPH-MISMATCH"));
}

fn assert_validate_fails<P>(kind: &str, path: &Path, stderr: P)
where
    P: predicates::Predicate<str>,
{
    Command::cargo_bin("bw")
        .unwrap()
        .args(["validate", "--kind", kind, path.to_str().unwrap()])
        .assert()
        .code(2)
        .stdout("")
        .stderr(stderr);
}

fn scanner_freeze_fixture() -> &'static str {
    r#"{
        "schema_version":"v3.3.scanner_freeze.1",
        "run_id":"v3-3-sealed-r2-test",
        "frozen_at_utc":"2026-07-24T08:00:00Z",
        "method":{
            "commit":"0123456789abcdef0123456789abcdef01234567",
            "branch":"docs-v3-1-nday-gate",
            "worktree_required_clean":true
        },
        "inputs":{
            "corpus_manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "anonymous_pairs_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "feature_profile_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "source_checksums_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "contract_toml_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "api_map_sha256":{"rusqlite":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
        },
        "toolchain":{
            "cargo_build_locked_for_method":true,
            "scanner_build_precheck_locked":true,
            "static_facts_rustup_toolchain":"nightly-2026-07-08",
            "static_facts_dyld_library_path":"/toolchain/lib",
            "stable_rustc":"rustc 1.97.0"
        },
        "source_identity_scan":{
            "scanner_metadata_forbidden_tokens":"pass",
            "source_tree_strong_identity_tokens_zero":true,
            "generic_source_token_counts":{"expected":0,"fixed":0,"patch":0}
        },
        "outputs":{
            "buildability_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
            "boundary_index_sha256":"2222222222222222222222222222222222222222222222222222222222222222",
            "static_facts_sha256":"3333333333333333333333333333333333333333333333333333333333333333",
            "mir_coverage_sha256":"4444444444444444444444444444444444444444444444444444444444444444",
            "candidates_sha256":"5555555555555555555555555555555555555555555555555555555555555555",
            "contracts_sha256":"6666666666666666666666666666666666666666666666666666666666666666",
            "lifecycle_evidence_sha256":"7777777777777777777777777777777777777777777777777777777777777777",
            "lifecycle_facts_sha256":"8888888888888888888888888888888888888888888888888888888888888888",
            "lifecycle_coverage_sha256":"9999999999999999999999999999999999999999999999999999999999999999",
            "lifecycle_features_sha256":"abababababababababababababababababababababababababababababababab",
            "ranked_candidates_sha256":"babababababababababababababababababababababababababababababababa"
        },
        "notes":["candidate/ranking is not a vulnerability conclusion"]
    }"#
}

#[test]
fn build_precheck_writes_zstd_buildability_records_for_local_crate() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("local-ok");
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"
[package]
name = "local-ok"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(crate_dir.join("src/lib.rs"), "pub fn ok() -> u8 { 1 }\n").unwrap();

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.pilot.001","crate_id":"crate:local-ok","crate_name":"local-ok","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["ffi_dependency"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let output = temp.path().join("buildability.jsonl.zst");
    let logs_root = temp.path().join("logs");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-precheck",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--logs-root",
            logs_root.to_str().unwrap(),
            "--run-id",
            "v3-2-precheck-test",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-buildability-precheck""#)
                .and(predicate::str::contains(r#""record_count":1"#))
                .and(predicate::str::contains(r#""buildable_count":1"#)),
        );

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-buildability",
            output.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-buildability""#)
                .and(predicate::str::contains(r#""record_count":1"#))
                .and(predicate::str::contains(r#""buildable_count":1"#)),
        );
}

#[cfg(unix)]
#[test]
fn build_precheck_retries_compatibility_rustflags_for_legacy_lints() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("ascii-legacy");
    write_minimal_crate(&crate_dir, "ascii-legacy");

    let fake_cargo_log = temp.path().join("fake-cargo-rustflags.log");
    let fake_cargo = temp.path().join("fake-cargo.sh");
    fs::write(
        &fake_cargo,
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
  echo "cargo 1.99.0-test"
  exit 0
fi

rustflags="${RUSTFLAGS:-}"
if [ -z "$rustflags" ]; then
  echo "<unset>" >> "${BW_FAKE_CARGO_LOG:?}"
else
  echo "$rustflags" >> "${BW_FAKE_CARGO_LOG:?}"
fi

case " $rustflags " in
  *" -A useless_deprecated "*) has_useless=1 ;;
  *) has_useless=0 ;;
esac
case " $rustflags " in
  *" -A dangerous_implicit_autorefs "*) has_autoref=1 ;;
  *) has_autoref=0 ;;
esac
case " $rustflags " in
  *" -A bindings_with_variant_name "*) has_bindings=1 ;;
  *) has_bindings=0 ;;
esac

if [ "$has_useless" = "1" ] && [ "$has_autoref" = "1" ] && [ "$has_bindings" = "1" ]; then
  exit 0
fi

echo "error: lint useless_deprecated is denied by default" >&2
echo "error: lint dangerous_implicit_autorefs is denied by default" >&2
echo "error: lint bindings_with_variant_name is denied by default" >&2
exit 101
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_cargo).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_cargo, permissions).unwrap();

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.pilot.compat-rustflags-test","crate_id":"crate:ascii-legacy","crate_name":"ascii-legacy","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["pure_rust"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let output = temp.path().join("buildability.jsonl");
    let logs_root = temp.path().join("logs");

    Command::cargo_bin("bw")
        .unwrap()
        .env("BW_FAKE_CARGO_LOG", &fake_cargo_log)
        .env_remove("RUSTFLAGS")
        .args([
            "build-precheck",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--logs-root",
            logs_root.to_str().unwrap(),
            "--run-id",
            "v3-2-precheck-compat-rustflags-test",
            "--cargo",
            fake_cargo.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""record_count":1"#)
                .and(predicate::str::contains(r#""buildable_count":1"#))
                .and(predicate::str::contains(r#""failed_count":0"#))
                .and(predicate::str::contains(r#""fallback_attempt_count":1"#))
                .and(predicate::str::contains(r#""fallback_buildable_count":1"#)),
        );

    let records = fs::read_to_string(&output).unwrap();
    assert!(records.contains(r#""crate_id":"crate:ascii-legacy""#));
    assert!(records.contains(r#""status":"buildable""#));
    assert!(records.contains(r#""failure_class":null"#));
    assert!(records.contains(r#""original_status":"not_buildable""#));
    assert!(
        records.contains(r#""original_failure_class":"legacy_lint_requires_compat_rustflags""#)
    );
    assert!(records.contains(r#""fallback_status":"buildable""#));
    assert!(records.contains(r#""fallback_rustflags":"-A useless_deprecated -A dangerous_implicit_autorefs -A bindings_with_variant_name""#));

    let invocations = fs::read_to_string(&fake_cargo_log).unwrap();
    let rustflags: Vec<&str> = invocations.lines().collect();
    assert_eq!(rustflags.len(), 2, "{invocations}");
    assert_eq!(rustflags[0], "<unset>");
    assert!(rustflags[1].contains("-A useless_deprecated"));
    assert!(rustflags[1].contains("-A dangerous_implicit_autorefs"));
    assert!(rustflags[1].contains("-A bindings_with_variant_name"));

    let build_log = fs::read_to_string(logs_root.join("build/crate_ascii-legacy.log")).unwrap();
    assert!(build_log.contains("compat fallback"));
    assert!(build_log.contains("compat rustflags"));
    assert!(build_log.contains("initial cargo check stderr"));
    assert!(build_log.contains("bindings_with_variant_name"));
    assert!(build_log.contains("compat fallback outcome: compat rustflags fallback succeeded"));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-buildability",
            output.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""buildable_count":1"#));
}

#[cfg(unix)]
#[test]
fn build_precheck_times_out_one_crate_and_continues() {
    let temp = tempfile::tempdir().unwrap();
    let slow_crate = temp.path().join("local-slow");
    write_minimal_crate(&slow_crate, "local-slow");
    let fast_crate = temp.path().join("local-fast");
    write_minimal_crate(&fast_crate, "local-fast");

    let fake_cargo = temp.path().join("fake-cargo.sh");
    fs::write(
        &fake_cargo,
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "cargo 1.99.0-test"
  exit 0
fi
manifest=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--manifest-path" ]; then
    manifest="$arg"
  fi
  prev="$arg"
done
case "$manifest" in
  *local-slow*) exec sleep 5 ;;
  *) exit 0 ;;
esac
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_cargo).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_cargo, permissions).unwrap();

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            "{}\n{}",
            format_args!(
                r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.pilot.timeout-test","crate_id":"crate:local-slow","crate_name":"local-slow","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["ffi_dependency"],"intake_status":"accepted","intake_notes":[]}}"#,
                slow_crate.display()
            ),
            format_args!(
                r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.pilot.timeout-test","crate_id":"crate:local-fast","crate_name":"local-fast","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["ffi_dependency"],"intake_status":"accepted","intake_notes":[]}}"#,
                fast_crate.display()
            )
        ),
    )
    .unwrap();

    let output = temp.path().join("buildability.jsonl");
    let logs_root = temp.path().join("logs");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-precheck",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--logs-root",
            logs_root.to_str().unwrap(),
            "--run-id",
            "v3-2-precheck-timeout-test",
            "--cargo",
            fake_cargo.to_str().unwrap(),
            "--timeout-seconds",
            "1",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""record_count":2"#)
                .and(predicate::str::contains(r#""buildable_count":1"#))
                .and(predicate::str::contains(r#""failed_count":1"#)),
        );

    let records = fs::read_to_string(&output).unwrap();
    assert!(records.contains(r#""crate_id":"crate:local-slow""#));
    assert!(records.contains(r#""status":"timeout""#));
    assert!(records.contains(r#""failure_class":"timeout""#));
    assert!(records.contains(r#""crate_id":"crate:local-fast""#));
    assert!(records.contains(r#""status":"buildable""#));

    let timeout_log = fs::read_to_string(logs_root.join("build/crate_local-slow.log")).unwrap();
    assert!(timeout_log.contains("timeout"));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-buildability",
            output.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-buildability""#)
                .and(predicate::str::contains(r#""record_count":2"#))
                .and(predicate::str::contains(r#""buildable_count":1"#))
                .and(predicate::str::contains(r#""failed_count":1"#)),
        );
}

#[cfg(unix)]
#[test]
fn extract_static_facts_runs_rustc_wrapper_for_local_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("static-fact-crate");
    write_minimal_crate(&crate_dir, "static-fact-crate");
    let lock_status = std::process::Command::new("cargo")
        .args([
            "generate-lockfile",
            "--manifest-path",
            crate_dir.join("Cargo.toml").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(lock_status.success());

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.static-fact-test","crate_id":"crate:static-fact-crate:0.1.0","crate_name":"static-fact-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let fake_wrapper = temp.path().join("fake-bw-rustc.sh");
    fs::write(
        &fake_wrapper,
        r#"#!/bin/sh
set -eu
out="${BW_STATIC_EXTRACT_OUTPUT_DIR:?}"
mkdir -p "$out/static-facts"
cat > "$out/static-facts.jsonl" <<'JSON'
{"schema_version":"bw.static/0.2","record_id":"static:fixture:callback","producer":"fake-bw-rustc","build_id":"build:fixture","artifact":{"crate_id":"crate:static-fact-crate:0.1.0","package_name":"static-fact-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"static_fact_crate::ok"},"payload":{"kind":"callback_site","site_id":"callback:fixture","semantic_site_key":"fixture","def_path":"static_fact_crate::ok"}}
JSON
cat > "$out/mir-coverage.json" <<'JSON'
{"schema_version":"bw.mir-coverage/0.1","expected_packages":[{"name":"static-fact-crate","version":"0.1.0"}],"seen_packages":[{"name":"static-fact-crate","version":"0.1.0"}],"seen_targets":[{"package":"static-fact-crate","version":"0.1.0","target":"lib"}],"seen_bodies":[{"package":"static-fact-crate","version":"0.1.0","target":"lib","def_path":"static_fact_crate::ok"}],"skipped":[]}
JSON
exec "$@"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_wrapper, permissions).unwrap();

    let output_dir = temp.path().join("static-analysis");
    let logs_root = temp.path().join("logs");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-static-facts",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--logs-root",
            logs_root.to_str().unwrap(),
            "--run-id",
            "v3-2-static-fact-test",
            "--rustc-wrapper",
            fake_wrapper.to_str().unwrap(),
            "--locked",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-static-fact-extraction""#)
                .and(predicate::str::contains(r#""record_count":1"#))
                .and(predicate::str::contains(r#""analyzed_count":1"#)),
        );

    let static_facts = output_dir.join("static-facts.jsonl");
    let mir_coverage = output_dir.join("mir-coverage.json");
    assert!(static_facts.is_file());
    assert!(mir_coverage.is_file());
    assert!(output_dir.join("static-extraction-status.jsonl").is_file());
    assert!(output_dir.join("checksums.sha256").is_file());

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "static",
            static_facts.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""kind":"static""#));
}

#[cfg(unix)]
#[test]
fn extract_static_facts_sets_python_env_for_cargo_check() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("static-fact-crate");
    write_minimal_crate(&crate_dir, "static-fact-crate");
    let lock_status = std::process::Command::new("cargo")
        .args([
            "generate-lockfile",
            "--manifest-path",
            crate_dir.join("Cargo.toml").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(lock_status.success());

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.static-fact-test","crate_id":"crate:static-fact-crate:0.1.0","crate_name":"static-fact-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let fake_python = temp.path().join("python-with-distutils");
    fs::write(&fake_python, "#!/bin/sh\nexit 0\n").unwrap();
    let mut permissions = fs::metadata(&fake_python).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_python, permissions).unwrap();

    let fake_wrapper = temp.path().join("python-aware-bw-rustc.sh");
    fs::write(
        &fake_wrapper,
        format!(
            r#"#!/bin/sh
set -eu
case " $* " in
  *"--crate-name static_fact_crate"*)
    test "${{PYTHON:-}}" = "{python}"
    test "${{npm_config_python:-}}" = "{python}"
    out="${{BW_STATIC_EXTRACT_OUTPUT_DIR:?}}"
    mkdir -p "$out/static-facts"
    cat > "$out/static-facts.jsonl" <<'JSON'
{{"schema_version":"bw.static/0.2","record_id":"static:fixture:python-env","producer":"fake-bw-rustc","build_id":"build:fixture","artifact":{{"crate_id":"crate:static-fact-crate:0.1.0","package_name":"static-fact-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"static_fact_crate::ok"}},"payload":{{"kind":"callback_site","site_id":"callback:fixture","semantic_site_key":"fixture","def_path":"static_fact_crate::ok"}}}}
JSON
    cat > "$out/mir-coverage.json" <<'JSON'
{{"schema_version":"bw.mir-coverage/0.1","expected_packages":[{{"name":"static-fact-crate","version":"0.1.0"}}],"seen_packages":[{{"name":"static-fact-crate","version":"0.1.0"}}],"seen_targets":[{{"package":"static-fact-crate","version":"0.1.0","target":"lib"}}],"seen_bodies":[{{"package":"static-fact-crate","version":"0.1.0","target":"lib","def_path":"static_fact_crate::ok"}}],"skipped":[]}}
JSON
    ;;
esac
exec "$@"
"#,
            python = fake_python.display()
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_wrapper, permissions).unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-static-facts",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output-dir",
            temp.path().join("static-analysis").to_str().unwrap(),
            "--logs-root",
            temp.path().join("logs").to_str().unwrap(),
            "--run-id",
            "v3-2-static-fact-python-test",
            "--rustc-wrapper",
            fake_wrapper.to_str().unwrap(),
            "--python",
            fake_python.to_str().unwrap(),
            "--locked",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-static-fact-extraction""#)
                .and(predicate::str::contains(r#""analyzed_count":1"#))
                .and(predicate::str::contains(r#""failed_count":0"#)),
        );
}

#[cfg(unix)]
#[test]
fn extract_static_facts_sets_compatibility_rustflags_for_nightly_lints() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("static-fact-crate");
    write_minimal_crate(&crate_dir, "static-fact-crate");
    let lock_status = std::process::Command::new("cargo")
        .args([
            "generate-lockfile",
            "--manifest-path",
            crate_dir.join("Cargo.toml").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(lock_status.success());

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.static-fact-test","crate_id":"crate:static-fact-crate:0.1.0","crate_name":"static-fact-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let fake_wrapper = temp.path().join("rustflags-aware-bw-rustc.sh");
    fs::write(
        &fake_wrapper,
        r#"#!/bin/sh
set -eu
case " $* " in
  *"--crate-name static_fact_crate"*)
    case " ${RUSTFLAGS:-} " in
      *" -A useless_deprecated "*) ;;
      *) echo "missing static-extraction compatibility rustflags" >&2; exit 43 ;;
    esac
    case " ${RUSTFLAGS:-} " in
      *" -A dangerous_implicit_autorefs "*) ;;
      *) echo "missing dangerous implicit autoref compatibility rustflags" >&2; exit 44 ;;
    esac
    case " ${RUSTFLAGS:-} " in
      *" -A bindings_with_variant_name "*) ;;
      *) echo "missing bindings-with-variant-name compatibility rustflags" >&2; exit 45 ;;
    esac
    out="${BW_STATIC_EXTRACT_OUTPUT_DIR:?}"
    mkdir -p "$out/static-facts"
    cat > "$out/static-facts.jsonl" <<'JSON'
{"schema_version":"bw.static/0.2","record_id":"static:fixture:rustflags","producer":"fake-bw-rustc","build_id":"build:fixture","artifact":{"crate_id":"crate:static-fact-crate:0.1.0","package_name":"static-fact-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"static_fact_crate::ok"},"payload":{"kind":"callback_site","site_id":"callback:fixture","semantic_site_key":"fixture","def_path":"static_fact_crate::ok"}}
JSON
    cat > "$out/mir-coverage.json" <<'JSON'
{"schema_version":"bw.mir-coverage/0.1","expected_packages":[{"name":"static-fact-crate","version":"0.1.0"}],"seen_packages":[{"name":"static-fact-crate","version":"0.1.0"}],"seen_targets":[{"package":"static-fact-crate","version":"0.1.0","target":"lib"}],"seen_bodies":[{"package":"static-fact-crate","version":"0.1.0","target":"lib","def_path":"static_fact_crate::ok"}],"skipped":[]}
JSON
    ;;
esac
exec "$@"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_wrapper, permissions).unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-static-facts",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output-dir",
            temp.path().join("static-analysis").to_str().unwrap(),
            "--logs-root",
            temp.path().join("logs").to_str().unwrap(),
            "--run-id",
            "v3-2-static-fact-rustflags-test",
            "--rustc-wrapper",
            fake_wrapper.to_str().unwrap(),
            "--locked",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-static-fact-extraction""#)
                .and(predicate::str::contains(r#""analyzed_count":1"#))
                .and(predicate::str::contains(r#""failed_count":0"#)),
        );
}

#[cfg(unix)]
#[test]
fn extract_static_facts_all_features_reaches_rustc_wrapper() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("static-fact-crate");
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "static-fact-crate"
version = "0.1.0"
edition = "2024"

[features]
gated = []
"#,
    )
    .unwrap();
    fs::write(
        crate_dir.join("src/lib.rs"),
        r#"#[cfg(feature = "gated")]
pub fn gated_lifecycle_api() {}

pub fn always_compiled() {}
"#,
    )
    .unwrap();
    let lock_status = std::process::Command::new("cargo")
        .args([
            "generate-lockfile",
            "--manifest-path",
            crate_dir.join("Cargo.toml").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(lock_status.success());

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.static-fact-test","crate_id":"crate:static-fact-crate:0.1.0","crate_name":"static-fact-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let fake_wrapper = temp.path().join("feature-aware-bw-rustc.sh");
    fs::write(
        &fake_wrapper,
        r#"#!/bin/sh
set -eu
case " $* " in
  *"--crate-name static_fact_crate"*)
    case " $* " in
      *'feature="gated"'*) ;;
      *) echo "missing gated feature cfg" >&2; exit 41 ;;
    esac
    out="${BW_STATIC_EXTRACT_OUTPUT_DIR:?}"
    mkdir -p "$out/static-facts"
    cat > "$out/static-facts.jsonl" <<'JSON'
{"schema_version":"bw.static/0.2","record_id":"static:fixture:gated","producer":"fake-bw-rustc","build_id":"build:fixture","artifact":{"crate_id":"crate:static-fact-crate:0.1.0","package_name":"static-fact-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":2,"line_end":2,"symbol_path":"static_fact_crate::gated_lifecycle_api"},"payload":{"kind":"callback_site","site_id":"callback:gated","semantic_site_key":"fixture:gated","def_path":"static_fact_crate::gated_lifecycle_api"}}
JSON
    cat > "$out/mir-coverage.json" <<'JSON'
{"schema_version":"bw.mir-coverage/0.1","expected_packages":[{"name":"static-fact-crate","version":"0.1.0"}],"seen_packages":[{"name":"static-fact-crate","version":"0.1.0"}],"seen_targets":[{"package":"static-fact-crate","version":"0.1.0","target":"lib"}],"seen_bodies":[{"package":"static-fact-crate","version":"0.1.0","target":"lib","def_path":"static_fact_crate::gated_lifecycle_api"}],"skipped":[]}
JSON
    ;;
esac
exec "$@"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_wrapper, permissions).unwrap();

    let output_dir = temp.path().join("static-analysis");
    let logs_root = temp.path().join("logs");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-static-facts",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--logs-root",
            logs_root.to_str().unwrap(),
            "--run-id",
            "v3-2-static-fact-test",
            "--rustc-wrapper",
            fake_wrapper.to_str().unwrap(),
            "--locked",
            "--all-features",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-static-fact-extraction""#)
                .and(predicate::str::contains(r#""analyzed_count":1"#))
                .and(predicate::str::contains(r#""failed_count":0"#)),
        );

    let static_facts = fs::read_to_string(output_dir.join("static-facts.jsonl")).unwrap();
    assert!(static_facts.contains("gated_lifecycle_api"));
}

#[cfg(unix)]
#[test]
fn extract_static_facts_applies_feature_profile_per_crate() {
    let temp = tempfile::tempdir().unwrap();
    let feature_a = temp.path().join("feature-a");
    let feature_b = temp.path().join("feature-b");
    write_feature_gated_crate(&feature_a, "feature-a", "gated");
    write_feature_gated_crate(&feature_b, "feature-b", "other");
    for crate_dir in [&feature_a, &feature_b] {
        let lock_status = std::process::Command::new("cargo")
            .args([
                "generate-lockfile",
                "--manifest-path",
                crate_dir.join("Cargo.toml").to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(lock_status.success());
    }

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            "{}\n{}",
            format_args!(
                r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.static-feature-profile-test","crate_id":"crate:feature-a:0.1.0","crate_name":"feature-a","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
                feature_a.display()
            ),
            format_args!(
                r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.static-feature-profile-test","crate_id":"crate:feature-b:0.1.0","crate_name":"feature-b","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
                feature_b.display()
            )
        ),
    )
    .unwrap();

    let profile = temp.path().join("feature-profile.jsonl");
    fs::write(
        &profile,
        r#"{"schema_version":"v3.2.static_feature_profile.1","crate_id":"crate:feature-a:0.1.0","crate_name":"feature-a","version":"0.1.0","all_features":false,"no_default_features":false,"features":["gated"],"source_refs":["Cargo.toml:[features]"],"notes":["cfg gated boundary surface coverage"]}"#,
    )
    .unwrap();

    let fake_wrapper = temp.path().join("feature-profile-bw-rustc.sh");
    fs::write(
        &fake_wrapper,
        r#"#!/bin/sh
set -eu
case " $* " in
  *"--crate-name feature_a"*)
    case " $* " in
      *'feature="gated"'*) ;;
      *) echo "feature-a missing gated cfg" >&2; exit 41 ;;
    esac
    out="${BW_STATIC_EXTRACT_OUTPUT_DIR:?}"
    mkdir -p "$out"
    cat >> "$out/static-facts.jsonl" <<'JSON'
{"schema_version":"bw.static/0.2","record_id":"static:fixture:feature-a","producer":"fake-bw-rustc","build_id":"build:fixture:a","artifact":{"crate_id":"crate:feature-a:0.1.0","package_name":"feature-a","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":2,"line_end":2,"symbol_path":"feature_a::gated_api"},"payload":{"kind":"callback_site","site_id":"callback:feature-a","semantic_site_key":"fixture:feature-a","def_path":"feature_a::gated_api"}}
JSON
    ;;
  *"--crate-name feature_b"*)
    case " $* " in
      *'feature="gated"'*) echo "feature-b received feature-a cfg" >&2; exit 42 ;;
    esac
    out="${BW_STATIC_EXTRACT_OUTPUT_DIR:?}"
    mkdir -p "$out"
    cat >> "$out/static-facts.jsonl" <<'JSON'
{"schema_version":"bw.static/0.2","record_id":"static:fixture:feature-b","producer":"fake-bw-rustc","build_id":"build:fixture:b","artifact":{"crate_id":"crate:feature-b:0.1.0","package_name":"feature-b","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":4,"line_end":4,"symbol_path":"feature_b::always_compiled"},"payload":{"kind":"callback_site","site_id":"callback:feature-b","semantic_site_key":"fixture:feature-b","def_path":"feature_b::always_compiled"}}
JSON
    ;;
esac
exec "$@"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_wrapper, permissions).unwrap();

    let output_dir = temp.path().join("static-analysis");
    let logs_root = temp.path().join("logs");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-static-facts",
            "--manifest",
            manifest.to_str().unwrap(),
            "--feature-profile",
            profile.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--logs-root",
            logs_root.to_str().unwrap(),
            "--run-id",
            "v3-2-static-feature-profile-test",
            "--rustc-wrapper",
            fake_wrapper.to_str().unwrap(),
            "--locked",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""record_count":2"#)
                .and(predicate::str::contains(r#""analyzed_count":2"#))
                .and(predicate::str::contains(r#""failed_count":0"#)),
        );

    let static_facts = fs::read_to_string(output_dir.join("static-facts.jsonl")).unwrap();
    assert!(static_facts.contains("feature_a::gated_api"));
    assert!(static_facts.contains("feature_b::always_compiled"));
}

#[cfg(unix)]
#[test]
fn extract_static_facts_rejects_duplicate_feature_profile_entries() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("feature-profile-invalid");
    write_feature_gated_crate(&crate_dir, "feature-profile-invalid", "gated");

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.static-feature-profile-invalid","crate_id":"crate:feature-profile-invalid:0.1.0","crate_name":"feature-profile-invalid","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();

    let profile = temp.path().join("feature-profile.jsonl");
    fs::write(
        &profile,
        r#"{"schema_version":"v3.2.static_feature_profile.1","crate_id":"crate:feature-profile-invalid:0.1.0","crate_name":"feature-profile-invalid","version":"0.1.0","features":["gated","gated"],"source_refs":["Cargo.toml:[features].gated"],"notes":["cfg gated boundary surface coverage"]}"#,
    )
    .unwrap();

    let fake_wrapper = temp.path().join("fake-bw-rustc.sh");
    fs::write(&fake_wrapper, "#!/bin/sh\nexit 0\n").unwrap();
    let mut permissions = fs::metadata(&fake_wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_wrapper, permissions).unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-static-facts",
            "--manifest",
            manifest.to_str().unwrap(),
            "--feature-profile",
            profile.to_str().unwrap(),
            "--output-dir",
            temp.path().join("static-analysis").to_str().unwrap(),
            "--logs-root",
            temp.path().join("logs").to_str().unwrap(),
            "--run-id",
            "v3-2-static-feature-profile-invalid",
            "--rustc-wrapper",
            fake_wrapper.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stdout("")
        .stderr(
            predicate::str::contains("BW-V32-STATIC-FACT-FEATURE-PROFILE")
                .and(predicate::str::contains("重复")),
        );
}

#[test]
fn verify_run_accepts_local_checksum_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(run_dir.join("stage")).unwrap();
    fs::write(run_dir.join("summary.json"), "{}\n").unwrap();
    fs::write(run_dir.join("stage/output.jsonl"), "{\"ok\":true}\n").unwrap();
    fs::write(
        run_dir.join("stage/checksums.sha256"),
        "nested stage checksum\n",
    )
    .unwrap();

    let mut lines = [
        checksum_line(&run_dir, "stage/output.jsonl"),
        checksum_line(&run_dir, "summary.json"),
    ];
    lines.sort();
    fs::write(
        run_dir.join("checksums.sha256"),
        format!("{}\n", lines.join("\n")),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args(["verify-run", "--run-dir", run_dir.to_str().unwrap()])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-verify-run""#)
                .and(predicate::str::contains(r#""verified_count":2"#)),
        );
}

#[test]
fn verify_run_accepts_custom_checksum_manifest_name() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::write(run_dir.join("summary.json"), "{}\n").unwrap();
    fs::write(
        run_dir.join("checksums.txt"),
        format!("{}\n", checksum_line(&run_dir, "summary.json")),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "verify-run",
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--checksums",
            "checksums.txt",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-verify-run""#)
                .and(predicate::str::contains(r#""verified_count":1"#)),
        );
}

#[test]
fn verify_run_rejects_checksum_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::write(run_dir.join("summary.json"), "{}\n").unwrap();
    fs::write(
        run_dir.join("checksums.sha256"),
        format!("{}  summary.json\n", "0".repeat(64)),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args(["verify-run", "--run-dir", run_dir.to_str().unwrap()])
        .assert()
        .code(2)
        .stdout("")
        .stderr(predicate::str::contains("BW-V32-VERIFY-CHECKSUM"));
}

#[test]
fn index_boundaries_writes_boundary_records_and_negative_summary() {
    let temp = tempfile::tempdir().unwrap();
    let boundary_crate = temp.path().join("ffi-wrapper");
    fs::create_dir_all(boundary_crate.join("src")).unwrap();
    fs::write(
        boundary_crate.join("Cargo.toml"),
        r#"
[package]
name = "ffi-wrapper"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let boundary_source = r#"
//! Register callback user_data from this documentation example only.
/* Register callback user_data from this block comment only. */
use std::ffi::c_void;

pub type Callback = extern "C" fn(*mut c_void);

unsafe extern "C" {
    pub fn native_register_callback(cb: Option<Callback>, user_data: *mut c_void);
    pub fn native_unregister_callback(user_data: *mut c_void);
}

#[repr(transparent)]
pub struct NativeHandle(*mut c_void);

pub unsafe fn register_callback(cb: Option<Callback>, user_data: *mut c_void) {
    unsafe { native_register_callback(cb, user_data) };
}

pub unsafe fn fixed_register_callback(cb: Option<Callback>, user_data: *mut c_void) {
    unsafe { native_register_callback(cb, user_data) };
}
pub unsafe extern "C" fn bridge_callback(_user_data: *mut c_void) {}

pub unsafe fn clear_foreign_hook(user_data: *mut c_void) {
    unsafe { ffi::clear_hook(None, user_data) };
    unsafe { ffi::install_hook(Some(bridge_callback), user_data) };
}

pub unsafe fn clear_hook_without_release_contract(user_data: *mut c_void) {
    unsafe { ffi::set_hook(None, user_data) };
}

pub unsafe fn hand_off_to_foreign_runtime(user_data: *mut c_void) {
    unsafe { ffi::install_hook(Some(bridge_callback), user_data) };
}

pub unsafe fn set_foreign_mode(mode: usize) {
    unsafe { ffi::set_mode(Some(mode), std::ptr::null_mut()) };
}

pub unsafe fn set_hook_mode(mode: usize) {
    unsafe { ffi::set_hook(Some(mode), std::ptr::null_mut()) };
}

pub unsafe fn set_hook_without_context() {
    unsafe { ffi::set_hook(Some(bridge_callback), 0) };
}

pub unsafe fn hand_off_closure_to_foreign_runtime(boxed_hook: *mut c_void) {
    unsafe {
        ffi::commit_hook(
            Some(call_boxed_closure::<usize>),
            boxed_hook as *mut _,
        )
    };
}

pub unsafe fn heap_callback_handoff() {
    let callback_user_data = Box::into_raw(Box::new(7usize)) as *mut c_void;
    unsafe { ffi::install_handler(Some(bridge_callback), callback_user_data) };
}

pub unsafe fn export_native_handle(owner: NativeHandle) {
    let exported_handle = owner.0 as *mut c_void;
    unsafe { ffi::accept_handle(exported_handle) };
}
"#;
    let clear_ffi_callback_line = boundary_source
        .lines()
        .position(|line| line.contains("ffi::clear_hook(None, user_data)"))
        .map(|index| index as u64 + 1)
        .unwrap();
    let local_register_wrapper_line = boundary_source
        .lines()
        .position(|line| line.contains("pub unsafe fn register_callback"))
        .map(|index| index as u64 + 1)
        .unwrap();
    let fixed_register_wrapper_line = boundary_source
        .lines()
        .position(|line| line.contains("pub unsafe fn fixed_register_callback"))
        .map(|index| index as u64 + 1)
        .unwrap();
    let direct_ffi_callback_line = boundary_source
        .lines()
        .position(|line| line.contains("ffi::install_hook(Some(bridge_callback)"))
        .map(|index| index as u64 + 1)
        .unwrap();
    let generic_clear_hook_line = boundary_source
        .lines()
        .position(|line| line.contains("ffi::set_hook(None, user_data)"))
        .map(|index| index as u64 + 1)
        .unwrap();
    let non_callback_mode_line = boundary_source
        .lines()
        .position(|line| line.contains("ffi::set_mode(Some(mode)"))
        .map(|index| index as u64 + 1)
        .unwrap();
    let non_callback_hook_mode_line = boundary_source
        .lines()
        .position(|line| line.contains("ffi::set_hook(Some(mode)"))
        .map(|index| index as u64 + 1)
        .unwrap();
    let callback_without_context_line = boundary_source
        .lines()
        .position(|line| line.contains("ffi::set_hook(Some(bridge_callback), 0)"))
        .map(|index| index as u64 + 1)
        .unwrap();
    let closure_handoff_line = boundary_source
        .lines()
        .position(|line| line.contains("ffi::commit_hook("))
        .map(|index| index as u64 + 1)
        .unwrap();
    let heap_callback_handoff_line = boundary_source
        .lines()
        .position(|line| line.contains("callback_user_data = Box::into_raw"))
        .map(|index| index as u64 + 1)
        .unwrap();
    let exported_handle_line = boundary_source
        .lines()
        .position(|line| line.contains("exported_handle = owner.0 as *mut c_void"))
        .map(|index| index as u64 + 1)
        .unwrap();
    fs::write(boundary_crate.join("src/lib.rs"), boundary_source).unwrap();

    let plain_crate = temp.path().join("plain");
    fs::create_dir_all(plain_crate.join("src")).unwrap();
    fs::write(
        plain_crate.join("Cargo.toml"),
        r#"
[package]
name = "plain"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        plain_crate.join("src/lib.rs"),
        "pub fn plain() -> u8 { 1 }\n",
    )
    .unwrap();

    let manifest = temp.path().join("corpus-manifest.jsonl");
    fs::write(
        &manifest,
        format!(
            "{}\n{}",
            format_args!(
                r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.pilot.boundary-test","crate_id":"crate:ffi-wrapper:0.1.0","crate_name":"ffi-wrapper","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["ffi_dependency","callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
                boundary_crate.display()
            ),
            format_args!(
                r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus.v3-2.pilot.boundary-test","crate_id":"crate:plain:0.1.0","crate_name":"plain","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["ffi_dependency"],"intake_status":"accepted","intake_notes":[]}}"#,
                plain_crate.display()
            )
        ),
    )
    .unwrap();

    let buildability = temp.path().join("buildability.jsonl");
    fs::write(
        &buildability,
        [
            r#"{"schema_version":"v3.2.buildability.1","run_id":"v3-2-precheck-test","crate_id":"crate:ffi-wrapper:0.1.0","status":"buildable","toolchain":"cargo test; rustc test","target":"x86_64-unknown-linux-gnu","native_dependencies":[],"elapsed_ms":1,"log_ref":"build/ffi-wrapper.log","failure_class":null}"#,
            r#"{"schema_version":"v3.2.buildability.1","run_id":"v3-2-precheck-test","crate_id":"crate:plain:0.1.0","status":"buildable","toolchain":"cargo test; rustc test","target":"x86_64-unknown-linux-gnu","native_dependencies":[],"elapsed_ms":1,"log_ref":"build/plain.log","failure_class":null}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let output = temp.path().join("boundary-index.jsonl.zst");
    let logs_root = temp.path().join("logs");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "index-boundaries",
            "--manifest",
            manifest.to_str().unwrap(),
            "--buildability",
            buildability.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--logs-root",
            logs_root.to_str().unwrap(),
            "--run-id",
            "v3-2-boundary-test",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-boundary-index""#)
                .and(predicate::str::contains(r#""crate_count":2"#))
                .and(predicate::str::contains(r#""negative_count":1"#)),
        );

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-boundary-index",
            output.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-boundary-index""#)
                .and(predicate::str::contains(r#""negative_count":1"#)),
        );

    let records = read_zstd_to_string(&output);
    assert!(
        records
            .matches(r#""boundary_kind":"callback_registration""#)
            .count()
            >= 3
    );
    assert!(records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "callback_registration"
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == direct_ffi_callback_line
                })
    }));
    assert!(!records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "callback_registration"
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == clear_ffi_callback_line
                })
    }));
    assert!(!records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "callback_unregistration"
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == generic_clear_hook_line
                })
    }));
    assert!(!records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "callback_registration"
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == local_register_wrapper_line
                })
    }));
    assert!(!records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "callback_registration"
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == fixed_register_wrapper_line
                })
    }));
    assert!(!records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "callback_registration"
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == non_callback_mode_line
                })
    }));
    assert!(!records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "callback_registration"
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == non_callback_hook_mode_line
                })
    }));
    assert!(!records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "callback_registration"
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == callback_without_context_line
                })
    }));
    assert!(records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "callback_registration"
            && record["confidence"] == "medium"
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == closure_handoff_line
                })
    }));
    assert!(records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "foreign_retained_pointer"
            && record["api_path"]
                .as_str()
                .is_some_and(|api_path| api_path.starts_with("source_api::"))
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == heap_callback_handoff_line
                })
    }));
    assert!(records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["boundary_kind"] == "opaque_handle_transfer"
            && record["api_path"]
                .as_str()
                .is_some_and(|api_path| api_path.starts_with("source_api::"))
            && record["evidence_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| {
                    reference["path"] == "src/lib.rs"
                        && reference["line_start"] == exported_handle_line
                })
    }));
    assert!(records.contains(r#""api_path":"source_api::"#));
    assert!(!records.contains("fixed_register_callback"));
    assert!(!records.contains(r#""path":"src/lib.rs","line_start":2,"line_end":2"#));
    assert!(!records.contains(r#""path":"src/lib.rs","line_start":3,"line_end":3"#));
    assert!(records.contains(r#""boundary_kind":"callback_unregistration""#));
    assert!(records.contains(r#""boundary_kind":"foreign_retained_pointer""#));
    assert!(records.contains(r#""boundary_kind":"opaque_handle_transfer""#));
    assert!(records.contains(r#""boundary_kind":"native_library""#));
    assert!(records.contains(r#""boundary_kind":"negative_summary""#));

    let candidates_dir = temp.path().join("candidates-out");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "emit-candidates",
            "--boundary-index",
            output.to_str().unwrap(),
            "--output-dir",
            candidates_dir.to_str().unwrap(),
            "--run-id",
            "v3-2-candidate-test",
            "--records-per-part",
            "2",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""kind":"v3-2-candidate-partition""#)
                .and(predicate::str::contains(r#""skipped_negative_count":1"#)),
        );

    let part0 = candidates_dir.join("candidates/part-00000.jsonl.zst");
    assert!(part0.is_file());
    assert!(candidates_dir.join("partition-manifest.json").is_file());
    assert!(candidates_dir.join("checksums.sha256").is_file());

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-candidate",
            part0.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""kind":"v3-2-candidate""#));

    let mut candidate_parts = fs::read_dir(candidates_dir.join("candidates"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    candidate_parts.sort();
    let candidate_text = candidate_parts
        .iter()
        .map(|part| read_zstd_to_string(part))
        .collect::<String>();
    assert!(candidate_text.contains(r#""pattern_family":"retained_borrowed_callback""#));
    assert!(candidate_text.contains(r#""candidate is not a vulnerability conclusion""#));

    let lifecycle_dir = temp.path().join("lifecycle-out");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "rank-lifecycle",
            "--candidates",
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            lifecycle_dir.to_str().unwrap(),
            "--run-id",
            "v3-2-lifecycle-test",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-lifecycle-ranking""#,
        ));

    let ranked = lifecycle_dir.join("ranked-candidates.jsonl.zst");
    assert!(ranked.is_file());
    assert!(lifecycle_dir.join("checksums.sha256").is_file());

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-ranked-candidate",
            ranked.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-ranked-candidate""#,
        ));

    let ranked_text = read_zstd_to_string(&ranked);
    assert!(ranked_text.contains(r#""ranking is not a vulnerability conclusion""#));
    assert!(ranked_text.contains(r#""lifecycle_graph_path":"lifecycle-graphs/"#));

    let adapter_dir = temp.path().join("adapter-out");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "account-adapter-effort",
            "--ranked-candidates",
            lifecycle_dir.to_str().unwrap(),
            "--output-dir",
            adapter_dir.to_str().unwrap(),
            "--run-id",
            "v3-2-adapter-test",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""kind":"v3-2-adapter-effort""#));

    let effort = adapter_dir.join("adapter-effort.jsonl.zst");
    assert!(effort.is_file());
    assert!(adapter_dir.join("checksums.sha256").is_file());

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-adapter-effort",
            effort.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""kind":"v3-2-adapter-effort""#));

    let effort_text = read_zstd_to_string(&effort);
    assert!(effort_text.contains("hidden answer channel"));
    assert!(effort_text.contains(r#""effort_class""#));

    // taxonomy needs a tiny buildability file for the two buildable crates
    let taxonomy_buildability = temp.path().join("taxonomy-buildability.jsonl");
    fs::write(
        &taxonomy_buildability,
        [
            r#"{"schema_version":"v3.2.buildability.1","run_id":"v3-2-precheck-test","crate_id":"crate:ffi-wrapper:0.1.0","status":"buildable","toolchain":"cargo test; rustc test","target":"x86_64-unknown-linux-gnu","native_dependencies":[],"elapsed_ms":1,"log_ref":"build/ffi-wrapper.log","failure_class":null}"#,
            r#"{"schema_version":"v3.2.buildability.1","run_id":"v3-2-precheck-test","crate_id":"crate:plain:0.1.0","status":"buildable","toolchain":"cargo test; rustc test","target":"x86_64-unknown-linux-gnu","native_dependencies":[],"elapsed_ms":1,"log_ref":"build/plain.log","failure_class":null}"#,
            r#"{"schema_version":"v3.2.buildability.1","run_id":"v3-2-precheck-test","crate_id":"crate:missing-sys:0.1.0","status":"requires_system_dependency","toolchain":"cargo test; rustc test","target":"x86_64-unknown-linux-gnu","native_dependencies":["libfoo"],"elapsed_ms":1,"log_ref":"build/missing.log","failure_class":"requires_system_dependency"}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let taxonomy_dir = temp.path().join("taxonomy-out");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-failure-taxonomy",
            "--buildability",
            taxonomy_buildability.to_str().unwrap(),
            "--boundary-index",
            output.to_str().unwrap(),
            "--adapter-effort",
            effort.to_str().unwrap(),
            "--output-dir",
            taxonomy_dir.to_str().unwrap(),
            "--run-id",
            "v3-2-taxonomy-test",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-failure-taxonomy""#,
        ));

    let taxonomy = taxonomy_dir.join("failure-taxonomy.jsonl.zst");
    assert!(taxonomy.is_file());
    assert!(taxonomy_dir.join("pilot-funnel.json").is_file());

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-failure-taxonomy",
            taxonomy.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-failure-taxonomy""#,
        ));

    let taxonomy_text = read_zstd_to_string(&taxonomy);
    assert!(
        taxonomy_text.contains("no-vulnerability conclusion")
            || taxonomy_text.contains("not a no-vulnerability")
    );
}

#[test]
fn emit_candidates_can_add_static_lifecycle_neutral_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let boundary = temp.path().join("boundary.jsonl");
    let static_facts = temp.path().join("static-facts.jsonl");
    let output_dir = temp.path().join("candidates-out");

    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:lifecycle-neutral","boundary_id":"boundary:lifecycle:callback:001","boundary_kind":"callback_registration","api_path":"lifecycle_neutral::register_callback","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":40,"line_end":42}],"confidence":"high","notes":["synthetic boundary"]}"#,
    )
    .unwrap();
    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:lifecycle:return-view","producer":"fixture","build_id":"build:lifecycle-neutral","artifact":{"crate_id":"crate:lifecycle-neutral","package_name":"lifecycle-neutral","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":5,"line_end":5,"symbol_path":"lifecycle_neutral::borrowed_view"},"payload":{"kind":"returned_borrow_relation","site_id":"site:lifecycle:return:relation","semantic_site_key":"lifecycle:return","source_site_id":"site:lifecycle:return:source","returned_site_id":"site:lifecycle:return:returned","api_id":"lifecycle_neutral::borrowed_view"}}
{"schema_version":"bw.static/0.2","record_id":"static:lifecycle:external-buffer","producer":"fixture","build_id":"build:lifecycle-neutral","artifact":{"crate_id":"crate:lifecycle-neutral","package_name":"lifecycle-neutral","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":12,"line_end":12,"symbol_path":"lifecycle_neutral::external_slice"},"payload":{"kind":"external_buffer_binding","site_id":"site:lifecycle:buffer:binding","semantic_site_key":"lifecycle:buffer","source_site_id":"site:lifecycle:buffer:source","buffer_site_id":"site:lifecycle:buffer:buffer","api_id":"lifecycle_neutral::external_slice"}}
{"schema_version":"bw.static/0.2","record_id":"static:lifecycle:selector-buffer","producer":"fixture","build_id":"build:lifecycle-neutral","artifact":{"crate_id":"crate:lifecycle-neutral","package_name":"lifecycle-neutral","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":16,"line_end":20,"symbol_path":"lifecycle_neutral::select_next_proto"},"payload":{"kind":"external_buffer_binding","site_id":"site:lifecycle:selector:binding","semantic_site_key":"lifecycle:selector","source_site_id":"site:lifecycle:selector:source","buffer_site_id":"site:lifecycle:selector:buffer","api_id":"lifecycle_neutral::select_next_proto"}}
{"schema_version":"bw.static/0.2","record_id":"static:lifecycle:sqlite-field-name","producer":"fixture","build_id":"build:lifecycle-neutral","artifact":{"crate_id":"crate:lifecycle-neutral","package_name":"lifecycle-neutral","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/sqlite/connection/stmt.rs","line_start":68,"line_end":68,"symbol_path":"sqlite::connection::stmt::Statement::field_name"},"payload":{"kind":"returned_borrow_relation","site_id":"site:lifecycle:sqlite-field-name:relation","semantic_site_key":"lifecycle:sqlite-field-name","source_site_id":"site:lifecycle:sqlite-field-name:source","returned_site_id":"site:lifecycle:sqlite-field-name:returned","api_id":"sqlite::connection::stmt::Statement::field_name"}}
{"schema_version":"bw.static/0.2","record_id":"static:lifecycle:raw-parts","producer":"fixture","build_id":"build:lifecycle-neutral","artifact":{"crate_id":"crate:lifecycle-neutral","package_name":"lifecycle-neutral","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/buffer.rs","line_start":197,"line_end":197,"symbol_path":"lifecycle_neutral::raw_parts_ownership_transfer"},"payload":{"kind":"raw_pointer_transfer","site_id":"site:lifecycle:raw-parts:transfer","semantic_site_key":"lifecycle:raw-parts","user_data_site_id":"site:lifecycle:raw-parts:user-data","transfer_kind":"from_raw_parts"}}
{"schema_version":"bw.static/0.2","record_id":"static:lifecycle:ordinary-builder","producer":"fixture","build_id":"build:lifecycle-neutral","artifact":{"crate_id":"crate:lifecycle-neutral","package_name":"lifecycle-neutral","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":20,"line_end":20,"symbol_path":"lifecycle_neutral::builder_name"},"payload":{"kind":"returned_borrow_relation","site_id":"site:lifecycle:ordinary:relation","semantic_site_key":"lifecycle:ordinary","source_site_id":"site:lifecycle:ordinary:source","returned_site_id":"site:lifecycle:ordinary:returned","api_id":"lifecycle_neutral::builder_name"}}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "emit-candidates",
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
            "--records-per-part",
            "10",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""candidate_count":6"#).and(predicate::str::contains(
                r#""static_lifecycle_candidate_count":5"#,
            )),
        );

    let candidate_text = read_zstd_to_string(&output_dir.join("candidates/part-00000.jsonl.zst"));
    assert!(candidate_text.contains(r#""pattern_family":"retained_borrowed_callback""#));
    assert!(candidate_text.contains(r#""pattern_family":"foreign_retained_pointer""#));
    assert!(candidate_text.contains(r#""pattern_family":"returned_borrow_view""#));
    assert!(candidate_text.contains(r#""pattern_family":"external_buffer_view""#));
    assert!(candidate_text.contains(r#""source_boundary_kind=foreign_retained_pointer""#));
    assert!(candidate_text.contains(r#""source_boundary_kind=returned_borrow""#));
    assert!(candidate_text.contains(r#""source_boundary_kind=external_buffer""#));
    assert!(candidate_text.contains(r#""api_path":"lifecycle_neutral::borrowed_view""#));
    assert!(candidate_text.contains(r#""api_path":"lifecycle_neutral::external_slice""#));
    assert!(candidate_text.contains(r#""api_path":"lifecycle_neutral::select_next_proto""#));
    assert!(candidate_text.contains(
        r#""api_path":"lifecycle_neutral::raw_parts_ownership_transfer::Vec::from_raw_parts""#
    ));
    assert!(
        candidate_text.contains(r#""api_path":"sqlite::connection::stmt::Statement::field_name""#)
    );
    assert!(!candidate_text.contains("builder_name"));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-candidate",
            output_dir
                .join("candidates/part-00000.jsonl.zst")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""kind":"v3-2-candidate""#));
}

#[test]
fn emit_candidates_can_add_pure_rust_lifecycle_bridge_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let boundary = temp.path().join("boundary.jsonl");
    let static_facts = temp.path().join("static-facts.jsonl");
    let output_dir = temp.path().join("candidates-out");

    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:pure-rust-lifecycle","boundary_id":"boundary:pure-rust-lifecycle:negative-summary","boundary_kind":"negative_summary","api_path":null,"evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"high","notes":["no legacy boundary pattern found"]}"#,
    )
    .unwrap();
    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:pure:thread-local:get-or-try","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/thread_local.rs","line_start":224,"line_end":224,"symbol_path":"ThreadLocal::<T>::get_or_try"},"payload":{"kind":"returned_borrow_relation","site_id":"site:pure:thread-local:return","semantic_site_key":"semantic:pure:thread-local:return","source_site_id":"site:pure:thread-local:source","returned_site_id":"site:pure:thread-local:returned","api_id":"ThreadLocal::<T>::get_or_try"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:instrumented:object","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/instrument.rs","line_start":367,"line_end":367,"symbol_path":"instrument::Instrumented::<T>::into_inner"},"payload":{"kind":"object_site","site_id":"site:pure:instrumented:object","semantic_site_key":"semantic:pure:instrumented:object","type_name":"instrument::Instrumented<T>"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:instrumented:forget","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/instrument.rs","line_start":367,"line_end":367,"symbol_path":"instrument::Instrumented::<T>::into_inner"},"payload":{"kind":"drop_prevention","site_id":"site:pure:instrumented:forget","semantic_site_key":"semantic:pure:instrumented:forget","object_site_id":"site:pure:instrumented:object","prevention_kind":"mem_forget"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:wrapper:object","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/wrapper.rs","line_start":73,"line_end":73,"symbol_path":"wrapper::OwnedWrapper::<T>::into_inner"},"payload":{"kind":"object_site","site_id":"site:pure:wrapper:guard","semantic_site_key":"semantic:pure:wrapper:guard","type_name":"wrapper::InnerGuard<T>"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:wrapper:drop","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/wrapper.rs","line_start":73,"line_end":73,"symbol_path":"wrapper::OwnedWrapper::<T>::into_inner"},"payload":{"kind":"drop_site","site_id":"site:pure:wrapper:drop","semantic_site_key":"semantic:pure:wrapper:drop","object_site_id":"site:pure:wrapper:guard","drop_kind":"explicit"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:lru:object","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lru.rs","line_start":547,"line_end":547,"symbol_path":"LruCache::<K, V, S>::pop"},"payload":{"kind":"object_site","site_id":"site:pure:lru:entry","semantic_site_key":"semantic:pure:lru:entry","type_name":"alloc::boxed::Box<LruEntry<K, V>>"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:lru:drop","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lru.rs","line_start":547,"line_end":547,"symbol_path":"LruCache::<K, V, S>::pop"},"payload":{"kind":"drop_site","site_id":"site:pure:lru:drop","semantic_site_key":"semantic:pure:lru:drop","object_site_id":"site:pure:lru:entry","drop_kind":"explicit"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:lru:peek-lru-signature","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lru.rs","line_start":477,"line_end":477,"symbol_path":"LruCache::<K, V, S>::peek_lru"},"payload":{"kind":"returned_borrow_relation","site_id":"site:pure:lru:peek-lru:return","semantic_site_key":"semantic:pure:lru:peek-lru:return","source_site_id":"site:pure:lru:peek-lru:receiver","returned_site_id":"site:pure:lru:peek-lru:returned","api_id":"LruCache::<K, V, S>::peek_lru"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:arena-vec:into-iter-unconstrained","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/arena_vec.rs","line_start":64,"line_end":64,"symbol_path":"<arena::ArenaVec<'arena, T> as core::iter::IntoIterator>::into_iter"},"payload":{"kind":"returned_borrow_relation","site_id":"site:pure:arena-vec:into-iter:return","semantic_site_key":"semantic:pure:arena-vec:into-iter:return","source_site_id":"site:pure:arena-vec:receiver","returned_site_id":"site:pure:arena-vec:returned","api_id":"<arena::ArenaVec<'arena, T> as core::iter::IntoIterator>::into_iter","relation_kind":"unconstrained_return_lifetime"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:atomic:rawiter-relaxed","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/raw_iter.rs","line_start":88,"line_end":88,"symbol_path":"raw::RelaxedIter::<T>::next"},"payload":{"kind":"atomic_ordering","site_id":"site:pure:atomic:rawiter-relaxed","semantic_site_key":"semantic:pure:atomic:rawiter-relaxed","api_id":"raw::RelaxedIter::<T>::next","operation":"load","ordering":"relaxed","target_type_name":"std::sync::atomic::AtomicPtr<Node<T>>"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:atomic:rawiter-acquire","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/raw_iter.rs","line_start":104,"line_end":104,"symbol_path":"raw::AcquireIter::<T>::next"},"payload":{"kind":"atomic_ordering","site_id":"site:pure:atomic:rawiter-acquire","semantic_site_key":"semantic:pure:atomic:rawiter-acquire","api_id":"raw::AcquireIter::<T>::next","operation":"load","ordering":"acquire","target_type_name":"core::sync::atomic::AtomicPtr<Node<T>>"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:atomic:counter-relaxed","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/counter.rs","line_start":11,"line_end":11,"symbol_path":"counter::Counter::get"},"payload":{"kind":"atomic_ordering","site_id":"site:pure:atomic:counter-relaxed","semantic_site_key":"semantic:pure:atomic:counter-relaxed","api_id":"counter::Counter::get","operation":"load","ordering":"relaxed","target_type_name":"std::sync::atomic::AtomicUsize"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:ordinary:object","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/ordinary.rs","line_start":40,"line_end":40,"symbol_path":"ordinary::unchecked_unwrap_none"},"payload":{"kind":"object_site","site_id":"site:pure:ordinary:option","semantic_site_key":"semantic:pure:ordinary:option","type_name":"core::option::Option<T>"}}
{"schema_version":"bw.static/0.2","record_id":"static:pure:ordinary:drop","producer":"fixture","build_id":"build:pure-rust","artifact":{"crate_id":"crate:pure-rust-lifecycle","package_name":"pure-rust-lifecycle","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/ordinary.rs","line_start":40,"line_end":40,"symbol_path":"ordinary::unchecked_unwrap_none"},"payload":{"kind":"drop_site","site_id":"site:pure:ordinary:drop","semantic_site_key":"semantic:pure:ordinary:drop","object_site_id":"site:pure:ordinary:option","drop_kind":"explicit"}}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "emit-candidates",
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
            "--records-per-part",
            "10",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""candidate_count":8"#).and(predicate::str::contains(
                r#""static_lifecycle_candidate_count":8"#,
            )),
        );

    let candidate_text = read_zstd_to_string(&output_dir.join("candidates/part-00000.jsonl.zst"));
    assert!(candidate_text.contains(r#""api_path":"ThreadLocal::<T>::get_or_try""#));
    assert!(candidate_text.contains(r#""api_path":"instrument::Instrumented::<T>::into_inner""#));
    assert!(candidate_text.contains(r#""api_path":"wrapper::OwnedWrapper::<T>::into_inner""#));
    assert!(candidate_text.contains(r#""api_path":"LruCache::<K, V, S>::pop""#));
    assert!(candidate_text.contains(r#""api_path":"LruCache::<K, V, S>::peek_lru""#));
    assert!(candidate_text.contains(
        r#""api_path":"<arena::ArenaVec<'arena, T> as core::iter::IntoIterator>::into_iter""#
    ));
    assert!(candidate_text.contains(r#""api_path":"raw::RelaxedIter::<T>::next""#));
    assert!(candidate_text.contains(r#""api_path":"raw::AcquireIter::<T>::next""#));
    assert!(candidate_text.contains(r#""pattern_family":"returned_borrow_view""#));
    assert!(candidate_text.contains(r#""pattern_family":"foreign_retained_pointer""#));
    assert!(!candidate_text.contains("unchecked_unwrap_none"));
    assert!(!candidate_text.contains(r#""api_path":"counter::Counter::get""#));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-candidate",
            output_dir
                .join("candidates/part-00000.jsonl.zst")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""kind":"v3-2-candidate""#));
}

fn read_zstd_to_string(path: &Path) -> String {
    use std::io::Read as _;

    let file = fs::File::open(path).unwrap();
    let mut decoder = zstd::stream::read::Decoder::new(file).unwrap();
    let mut output = String::new();
    decoder.read_to_string(&mut output).unwrap();
    output
}

fn write_minimal_crate(crate_dir: &Path, name: &str) {
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        format!(
            r#"
[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
"#
        ),
    )
    .unwrap();
    fs::write(crate_dir.join("src/lib.rs"), "pub fn ok() -> u8 { 1 }\n").unwrap();
}

fn write_feature_gated_crate(crate_dir: &Path, name: &str, feature: &str) {
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        format!(
            r#"
[package]
name = "{name}"
version = "0.1.0"
edition = "2024"

[features]
{feature} = []
"#
        ),
    )
    .unwrap();
    fs::write(
        crate_dir.join("src/lib.rs"),
        format!(
            r#"#[cfg(feature = "{feature}")]
pub fn gated_api() -> u8 {{ 7 }}

pub fn always_compiled() -> u8 {{ 1 }}
"#
        ),
    )
    .unwrap();
}

fn checksum_line(root: &Path, relative: &str) -> String {
    let bytes = fs::read(root.join(relative)).unwrap();
    format!("{}  {relative}", hex_digest(Sha256::digest(bytes)))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

struct Inputs {
    static_facts: std::path::PathBuf,
    contract: std::path::PathBuf,
    trace: std::path::PathBuf,
}

fn write_minimal_inputs(dir: &Path) -> Inputs {
    let static_facts = dir.join("static.jsonl");
    let contract = dir.join("contract.toml");
    let trace = dir.join("trace.jsonl");

    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.1","record_id":"fact:capture","producer":"cli-test","build_id":"build:test","payload":{"kind":"callback_capture","site_id":"site:capture","semantic_site_key":"semantic:capture","callback_site_id":"site:callback","object_site_id":"site:object","capture_ordinal":0,"capture_mode":"borrowed"}}"#,
    )
    .unwrap();
    fs::write(
        &contract,
        r#"
schema_version = "bw.contract/0.1"
contract_id = "contract:callback-retention"
producer = "cli-test"

[[clauses]]
clause_id = "clause:register-retains"
kind = "retain_after_register"
description = "register retains callback until a matching release"

[[clauses]]
clause_id = "clause:borrow-outlives-retention"
kind = "borrow_must_outlive_retention"
description = "borrow must outlive retained callback"

[[api_entries]]
clause_id = "clause:register-retains"
api_id = "api:register"
registration_role = "register"
release_behavior = "none"
owner_kind = "external_owner"

[[api_entries]]
clause_id = "clause:borrow-outlives-retention"
api_id = "api:invoke"
release_behavior = "none"
owner_kind = "external_owner"
invoke_role = "callback"
"#,
    )
    .unwrap();
    fs::write(
        &trace,
        [
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:start","run_id":"run:test","trace_id":"trace:test","seq":0,"thread_id":"main","source":"cli-test","payload":{"kind":"trace_start","build_id":"build:test"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:owner-create","run_id":"run:test","trace_id":"trace:test","seq":1,"thread_id":"main","source":"cli-test","payload":{"kind":"object_create","instance_id":"owner:1","site_id":"site:owner","object_kind":"external_owner","epoch":0,"address_diag":null}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:object-create","run_id":"run:test","trace_id":"trace:test","seq":2,"thread_id":"main","source":"cli-test","payload":{"kind":"object_create","instance_id":"object:1","site_id":"site:object","object_kind":"tracked","epoch":0,"address_diag":null}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:register","run_id":"run:test","trace_id":"trace:test","seq":3,"thread_id":"main","source":"cli-test","payload":{"kind":"callback_register","callback_instance_id":"callback:1","callback_site_id":"site:callback","owner_instance_id":"owner:1","registration_site_id":"site:register","api_id":"api:register"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:bind","run_id":"run:test","trace_id":"trace:test","seq":4,"thread_id":"main","source":"cli-test","payload":{"kind":"capture_bind","callback_instance_id":"callback:1","callback_site_id":"site:callback","object_instance_id":"object:1","object_site_id":"site:object"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:checkpoint-registered","run_id":"run:test","trace_id":"trace:test","seq":5,"thread_id":"main","source":"cli-test","payload":{"kind":"checkpoint","checkpoint":"registered"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:drop","run_id":"run:test","trace_id":"trace:test","seq":6,"thread_id":"main","source":"cli-test","payload":{"kind":"object_drop","instance_id":"object:1","drop_site_id":"site:drop"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:checkpoint-ended","run_id":"run:test","trace_id":"trace:test","seq":7,"thread_id":"main","source":"cli-test","payload":{"kind":"checkpoint","checkpoint":"owner_ended_or_released"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:invoke","run_id":"run:test","trace_id":"trace:test","seq":8,"thread_id":"main","source":"cli-test","payload":{"kind":"callback_invoke","callback_instance_id":"callback:1","invoke_site_id":"site:invoke","api_id":"api:invoke"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:checkpoint-later","run_id":"run:test","trace_id":"trace:test","seq":9,"thread_id":"main","source":"cli-test","payload":{"kind":"checkpoint","checkpoint":"later_callback_phase"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:end","run_id":"run:test","trace_id":"trace:test","seq":10,"thread_id":"main","source":"cli-test","payload":{"kind":"trace_end","event_count":11}}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    Inputs {
        static_facts,
        contract,
        trace,
    }
}
