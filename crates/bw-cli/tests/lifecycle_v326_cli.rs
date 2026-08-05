use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use assert_cmd::Command;
use predicates::prelude::*;
use sha2::{Digest, Sha256};

fn public_safe_tempdir() -> tempfile::TempDir {
    static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bw-cli-lifecycle-test-temp");
    fs::create_dir_all(&root).unwrap();
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    tempfile::Builder::new()
        .prefix(&format!("bw{}{}_", std::process::id(), sequence))
        .rand_bytes(0)
        .tempdir_in(root)
        .unwrap()
}

#[test]
fn extract_lifecycle_evidence_finds_register_and_owned_anchor() {
    let temp = public_safe_tempdir();
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();

    let source_ref = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v3-2-6/callback-owned-anchor")
        .canonicalize()
        .unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:owned-anchor","crate_name":"callback-owned-anchor","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            source_ref.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:owned-anchor","boundary_id":"boundary:owned:001","boundary_kind":"callback_registration","api_path":"owned::register","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":12}],"confidence":"high","notes":["synthetic boundary"]}"#,
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:owned:001","crate_id":"crate:owned-anchor","boundary_id":"boundary:owned:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":12}],"api_path":"owned::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
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
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-6-lifecycle-evidence""#,
        ));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-lifecycle-evidence",
            output_dir
                .join("lifecycle-evidence.jsonl.zst")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""record_count":"#));
}

#[test]
fn extract_lifecycle_evidence_derives_source_lifecycle_facts() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("source-facts-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "source-facts-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

fn set_hook(_cb: Option<extern "C" fn(*mut c_void)>, _user_data: *mut c_void) {}
fn clear_hook(_cb: Option<extern "C" fn(*mut c_void)>) {}

pub fn register_alpha() {
    let raw = Box::into_raw(Box::new(7_u32)) as *mut c_void;
    set_hook(Some(alpha_callback), raw);
    clear_hook(Some(alpha_callback));
}

extern "C" fn alpha_callback(_user_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();

    let start_line = line_number(source, "let raw = Box::into_raw");
    let end_line = line_number(source, "clear_hook(Some");
    let boundary_line = line_number(source, "set_hook(Some(alpha_callback)");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v327","crate_id":"crate:source-facts","crate_name":"source-facts-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v327","crate_id":"crate:source-facts","boundary_id":"boundary:alpha:001","boundary_kind":"callback_registration","api_path":"source_facts::register_alpha","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{boundary_line},"line_end":{boundary_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v327","candidate_id":"candidate:alpha:001","crate_id":"crate:source-facts","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{start_line},"line_end":{end_line}}}],"api_path":"source_facts::register_alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v327",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""fact_count":"#));

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert!(facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::RegisterCall
            && fact
                .object_ids
                .iter()
                .all(|object_id| object_id.starts_with("source_evidence:"))
    }));
    assert!(
        !facts
            .iter()
            .any(|fact| fact.fact_kind == bw_model::V326LifecycleFactKind::ReleaseCall)
    );
    assert!(facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::OwnedMoveCapture
            && fact
                .object_ids
                .iter()
                .all(|id| id.starts_with("source_evidence:"))
    }));
    assert!(facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::RawPointerEscape
            && fact
                .object_ids
                .iter()
                .all(|id| id.starts_with("source_evidence:"))
    }));
    assert!(
        facts
            .iter()
            .flat_map(|fact| fact.object_ids.iter())
            .all(|object_id| !object_id.starts_with("callback:"))
    );

    let graph_dir = temp.path().join("source-facts-graph");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates_dir.to_str().unwrap(),
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
            "--output-dir",
            graph_dir.to_str().unwrap(),
            "--run-id",
            "run:v327",
        ])
        .assert()
        .code(0)
        .stderr("");
    let graph = fs::read_to_string(graph_dir.join("graphs-v3/candidate_alpha_001.json")).unwrap();
    assert!(graph.contains("observation:callback:"));
    assert!(graph.contains("mir_hir_fact_missing"));
    assert!(graph.contains("callback_object_identity_unavailable"));
}

#[test]
fn extract_lifecycle_evidence_does_not_promote_local_hook_lexemes_to_register_facts() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("local-hook-lexeme-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "local-hook-lexeme-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

fn set_hook(_callback: Option<extern "C" fn(*mut c_void)>, _data: *mut c_void) {}

pub fn local_wrapper() {
    let raw = &7_u32 as *const u32 as *mut c_void;
    set_hook(Some(local_callback), raw);
}

extern "C" fn local_callback(_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();

    let wrapper_line = line_number(source, "set_hook(Some(local_callback)");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:local-hook","crate_name":"local-hook-lexeme-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:local-hook","boundary_id":"boundary:local:001","boundary_kind":"foreign_retained_pointer","api_path":"local_hook::wrapper","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{wrapper_line},"line_end":{wrapper_line}}}],"confidence":"medium","notes":["synthetic non-registration boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:local:001","crate_id":"crate:local-hook","boundary_id":"boundary:local:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{wrapper_line},"line_end":{wrapper_line}}}],"api_path":"local_hook::wrapper","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let evidence = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert!(
        !evidence
            .iter()
            .any(|item| item.evidence_kind == bw_model::V326EvidenceKind::ForeignRegister)
    );
    assert!(
        !facts
            .iter()
            .any(|item| item.fact_kind == bw_model::V326LifecycleFactKind::RegisterCall)
    );
}

#[test]
fn exact_api_release_proofs_stay_source_scoped_when_api_id_is_shared() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("shared-api-proof-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "shared-api-proof-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"fn ffi_create_function_v2(_tag: u32) {}

pub fn register_alpha() {
    ffi_create_function_v2(1);
}

fn unrelated_padding_one() {}
fn unrelated_padding_two() {}
fn unrelated_padding_three() {}
fn unrelated_padding_four() {}
fn unrelated_padding_five() {}

pub fn register_beta() {
    ffi_create_function_v2(2);
}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();

    let alpha_line = line_number(source, "ffi_create_function_v2(1)");
    let beta_line = line_number(source, "ffi_create_function_v2(2)");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let static_facts = temp.path().join("static-facts.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:shared-api-proof","crate_name":"shared-api-proof-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:shared-api-proof","boundary_id":"boundary:alpha:proof","boundary_kind":"foreign_retained_pointer","api_path":"api:fixture:shared_create_function:register","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line}}}],"confidence":"high","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:shared-api-proof","boundary_id":"boundary:beta:proof","boundary_kind":"foreign_retained_pointer","api_path":"api:fixture:shared_create_function:register","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_line},"line_end":{beta_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:proof","crate_id":"crate:shared-api-proof","boundary_id":"boundary:alpha:proof","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line}}}],"api_path":"api:fixture:shared_create_function:register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:proof","crate_id":"crate:shared-api-proof","boundary_id":"boundary:beta:proof","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_line},"line_end":{beta_line}}}],"api_path":"api:fixture:shared_create_function:register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
    )
    .unwrap();

    let artifact = serde_json::json!({
        "crate_id": "crate:shared-api-proof",
        "package_name": "shared-api-proof-crate",
        "package_version": "0.1.0",
        "target": "lib"
    });
    let static_records = [
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:alpha:register",
            "producer": "fixture",
            "build_id": "build:shared-api-proof",
            "artifact": artifact.clone(),
            "source_ref": {"path": "src/lib.rs", "line_start": alpha_line, "line_end": alpha_line, "symbol_path": "fixture::register_alpha"},
            "payload": {"kind": "registration_site", "site_id": "site:alpha:register", "semantic_site_key": "semantic:alpha:register", "callback_site_id": null, "user_data_site_id": "site:alpha:user-data", "api_id": "api:fixture:shared_create_function:register", "role": "register"}
        }),
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:alpha:from-raw",
            "producer": "fixture",
            "build_id": "build:shared-api-proof",
            "artifact": artifact.clone(),
            "source_ref": {"path": "src/lib.rs", "line_start": alpha_line, "line_end": alpha_line, "symbol_path": "fixture::register_alpha"},
            "payload": {"kind": "raw_pointer_transfer", "site_id": "site:alpha:from-raw", "semantic_site_key": "semantic:alpha:from-raw", "user_data_site_id": "site:alpha:user-data", "transfer_kind": "from_raw"}
        }),
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:alpha:proof",
            "producer": "fixture",
            "build_id": "build:shared-api-proof",
            "artifact": artifact.clone(),
            "source_ref": {"path": "src/lib.rs", "line_start": alpha_line, "line_end": alpha_line, "symbol_path": "fixture::register_alpha"},
            "payload": {"kind": "release_path_proof", "site_id": "site:alpha:proof", "semantic_site_key": "semantic:alpha:proof", "registration_site_id": "site:alpha:register", "release_site_id": "site:alpha:from-raw", "object_site_id": "site:alpha:user-data"}
        }),
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:beta:register",
            "producer": "fixture",
            "build_id": "build:shared-api-proof",
            "artifact": artifact.clone(),
            "source_ref": {"path": "src/lib.rs", "line_start": beta_line, "line_end": beta_line, "symbol_path": "fixture::register_beta"},
            "payload": {"kind": "registration_site", "site_id": "site:beta:register", "semantic_site_key": "semantic:beta:register", "callback_site_id": null, "user_data_site_id": "site:beta:user-data", "api_id": "api:fixture:shared_create_function:register", "role": "register"}
        }),
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:beta:from-raw",
            "producer": "fixture",
            "build_id": "build:shared-api-proof",
            "artifact": artifact.clone(),
            "source_ref": {"path": "src/lib.rs", "line_start": beta_line, "line_end": beta_line, "symbol_path": "fixture::register_beta"},
            "payload": {"kind": "raw_pointer_transfer", "site_id": "site:beta:from-raw", "semantic_site_key": "semantic:beta:from-raw", "user_data_site_id": "site:beta:user-data", "transfer_kind": "from_raw"}
        }),
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:beta:proof",
            "producer": "fixture",
            "build_id": "build:shared-api-proof",
            "artifact": artifact.clone(),
            "source_ref": {"path": "src/lib.rs", "line_start": beta_line, "line_end": beta_line, "symbol_path": "fixture::register_beta"},
            "payload": {"kind": "release_path_proof", "site_id": "site:beta:proof", "semantic_site_key": "semantic:beta:proof", "registration_site_id": "site:beta:register", "release_site_id": "site:beta:from-raw", "object_site_id": "site:beta:user-data"}
        }),
    ];
    fs::write(
        &static_facts,
        static_records
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    let alpha_proofs = facts
        .iter()
        .filter(|fact| fact.candidate_id == "candidate:alpha:proof")
        .filter(|fact| fact.fact_kind == bw_model::V326LifecycleFactKind::ReleasePathProof)
        .collect::<Vec<_>>();
    let beta_proofs = facts
        .iter()
        .filter(|fact| fact.candidate_id == "candidate:beta:proof")
        .filter(|fact| fact.fact_kind == bw_model::V326LifecycleFactKind::ReleasePathProof)
        .collect::<Vec<_>>();

    assert_eq!(alpha_proofs.len(), 1);
    assert_eq!(beta_proofs.len(), 1);
    assert_eq!(
        alpha_proofs[0].object_ids,
        vec![
            "user_data:site:alpha:user-data",
            "static_site:site:alpha:register",
            "release_endpoint:site:alpha:from-raw",
        ]
    );
    assert_eq!(
        beta_proofs[0].object_ids,
        vec![
            "user_data:site:beta:user-data",
            "static_site:site:beta:register",
            "release_endpoint:site:beta:from-raw",
        ]
    );
    assert!(
        facts
            .iter()
            .filter(|fact| fact.candidate_id == "candidate:alpha:proof")
            .flat_map(|fact| fact.object_ids.iter())
            .all(|object_id| !object_id.contains("site:beta:"))
    );
    assert!(
        facts
            .iter()
            .filter(|fact| fact.candidate_id == "candidate:beta:proof")
            .flat_map(|fact| fact.object_ids.iter())
            .all(|object_id| !object_id.contains("site:alpha:"))
    );
}

#[test]
fn source_api_anchor_includes_same_owner_static_unregister_without_release_proof() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("source-api-owner-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "source-api-owner-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("lib.rs"),
        r#"pub fn install_hook() {
    register_hook();
    let _a = 1;
    let _b = 2;
    let _c = 3;
    let _d = 4;
    let _e = 5;
    unregister_hook();
}

fn register_hook() {}
fn unregister_hook() {}
"#,
    )
    .unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let static_facts = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    let source_api = format!(
        "source_api::{}",
        hex_digest(Sha256::digest(b"src::lib::install_hook"))
    );
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:source-api-owner","crate_name":"source-api-owner-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:source-api-owner","boundary_id":"boundary:source-api-owner:001","boundary_kind":"callback_registration","api_path":"{source_api}","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":2,"line_end":2}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:source-api-owner:001","crate_id":"crate:source-api-owner","boundary_id":"boundary:source-api-owner:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":2,"line_end":2}}],"api_path":"{source_api}","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
    )
    .unwrap();

    let artifact = serde_json::json!({
        "crate_id": "crate:source-api-owner",
        "package_name": "source-api-owner-crate",
        "package_version": "0.1.0",
        "target": "lib"
    });
    let static_records = [
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:source-api-owner:register",
            "producer": "fixture",
            "build_id": "build:source-api-owner",
            "artifact": artifact.clone(),
            "source_ref": {"path": "src/lib.rs", "line_start": 2, "line_end": 2, "symbol_path": "fixture::install_hook"},
            "payload": {"kind": "registration_site", "site_id": "site:source-api-owner:register", "semantic_site_key": "semantic:source-api-owner:register", "callback_site_id": "site:source-api-owner:callback", "user_data_site_id": null, "api_id": "api:fixture:hook:register", "role": "register"}
        }),
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:source-api-owner:unregister",
            "producer": "fixture",
            "build_id": "build:source-api-owner",
            "artifact": artifact,
            "source_ref": {"path": "src/lib.rs", "line_start": 8, "line_end": 8, "symbol_path": "fixture::install_hook"},
            "payload": {"kind": "registration_site", "site_id": "site:source-api-owner:unregister", "semantic_site_key": "semantic:source-api-owner:unregister", "callback_site_id": null, "user_data_site_id": null, "api_id": "api:fixture:hook:unregister", "role": "unregister"}
        }),
    ];
    fs::write(
        &static_facts,
        static_records
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:source-api-owner:001"
            && fact.fact_kind == bw_model::V326LifecycleFactKind::RegisterCall
    }));
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:source-api-owner:001"
            && fact.fact_kind == bw_model::V326LifecycleFactKind::UnregisterCall
            && fact.source_ref.line_start == Some(8)
    }));
    assert!(facts.iter().all(|fact| {
        fact.candidate_id != "candidate:source-api-owner:001"
            || fact.fact_kind != bw_model::V326LifecycleFactKind::ReleasePathProof
    }));
}

#[test]
fn source_api_registration_links_sibling_unregistration_without_compiler_alias_match() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("source-api-sibling-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "source-api-sibling-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("lib.rs"),
        r#"pub fn install_hook() {
    register_hook();
}

pub fn remove_hook() {
    unregister_hook();
}

fn register_hook() {}
fn unregister_hook() {}
"#,
    )
    .unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let static_facts = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    let source_api = source_api_id("src/lib.rs", "public_hook_owner");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:source-api-sibling","crate_name":"source-api-sibling-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:source-api-sibling","boundary_id":"boundary:source-api-sibling:register","boundary_kind":"callback_registration","api_path":"{source_api}","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":2,"line_end":2}}],"confidence":"high","notes":["synthetic register boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:source-api-sibling","boundary_id":"boundary:source-api-sibling:unregister","boundary_kind":"callback_unregistration","api_path":"{source_api}","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":6,"line_end":6}}],"confidence":"high","notes":["synthetic unregister boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:source-api-sibling:register","crate_id":"crate:source-api-sibling","boundary_id":"boundary:source-api-sibling:register","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":2,"line_end":2}}],"api_path":"{source_api}","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic register candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:source-api-sibling:unregister","crate_id":"crate:source-api-sibling","boundary_id":"boundary:source-api-sibling:unregister","pattern_family":"callback_lifecycle_release","confidence":"static_only","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":6,"line_end":6}}],"api_path":"{source_api}","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic unregister candidate"]}}"#
        ),
    )
    .unwrap();

    let artifact = serde_json::json!({
        "crate_id": "crate:source-api-sibling",
        "package_name": "source-api-sibling-crate",
        "package_version": "0.1.0",
        "target": "lib"
    });
    let static_records = [
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:source-api-sibling:register",
            "producer": "fixture",
            "build_id": "build:source-api-sibling",
            "artifact": artifact.clone(),
            "source_ref": {"path": "src/lib.rs", "line_start": 2, "line_end": 2, "symbol_path": "fixture::compiler_hook_owner"},
            "payload": {"kind": "registration_site", "site_id": "site:source-api-sibling:register", "semantic_site_key": "semantic:source-api-sibling:register", "callback_site_id": "site:source-api-sibling:callback", "user_data_site_id": null, "api_id": "api:fixture:hook:register", "role": "register"}
        }),
        serde_json::json!({
            "schema_version": "bw.static/0.2",
            "record_id": "static:source-api-sibling:unregister",
            "producer": "fixture",
            "build_id": "build:source-api-sibling",
            "artifact": artifact,
            "source_ref": {"path": "src/lib.rs", "line_start": 6, "line_end": 6, "symbol_path": "fixture::compiler_hook_owner"},
            "payload": {"kind": "registration_site", "site_id": "site:source-api-sibling:unregister", "semantic_site_key": "semantic:source-api-sibling:unregister", "callback_site_id": null, "user_data_site_id": null, "api_id": "api:fixture:hook:unregister", "role": "unregister"}
        }),
    ];
    fs::write(
        &static_facts,
        static_records
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let evidence = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    let sibling_evidence = evidence
        .iter()
        .find(|record| {
            record.candidate_id == "candidate:source-api-sibling:register"
                && record.evidence_kind == bw_model::V326EvidenceKind::ForeignUnregister
                && record.details["signal"] == "sibling_candidate_unregistration"
        })
        .expect("registration candidate should link same-owner sibling unregister evidence");
    assert_eq!(
        sibling_evidence.details["sibling_candidate_id"],
        "candidate:source-api-sibling:unregister"
    );
    assert_eq!(
        sibling_evidence.details["relation"],
        "same_source_api_owner"
    );
    assert_eq!(sibling_evidence.source_ref.line_start, Some(6));

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert!(facts.iter().all(|fact| {
        fact.candidate_id != "candidate:source-api-sibling:register"
            || fact.fact_kind != bw_model::V326LifecycleFactKind::ReleasePathProof
    }));
}

#[test]
fn source_derived_facts_stay_candidate_scoped_across_two_callbacks() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("source-fact-scope-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "source-fact-scope-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

fn set_alpha_hook(_cb: Option<extern "C" fn(*mut c_void)>, _user_data: *mut c_void) {}
fn set_beta_hook(_cb: Option<extern "C" fn(*mut c_void)>, _user_data: *mut c_void) {}

pub fn register_alpha() {
    set_alpha_hook(Some(alpha_callback), std::ptr::null_mut());
}

pub fn register_beta() {
    set_beta_hook(Some(beta_callback), std::ptr::null_mut());
}

extern "C" fn alpha_callback(_user_data: *mut c_void) {}
extern "C" fn beta_callback(_user_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();

    let alpha_line = line_number(source, "set_alpha_hook(Some");
    let beta_line = line_number(source, "set_beta_hook(Some");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v327","crate_id":"crate:source-fact-scope","crate_name":"source-fact-scope-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            "source-fact-scope-crate"
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v327","crate_id":"crate:source-fact-scope","boundary_id":"boundary:alpha:001","boundary_kind":"callback_registration","api_path":"scope::register_alpha","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line}}}],"confidence":"high","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v327","crate_id":"crate:source-fact-scope","boundary_id":"boundary:beta:001","boundary_kind":"callback_registration","api_path":"scope::register_beta","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_line},"line_end":{beta_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v327","candidate_id":"candidate:alpha:001","crate_id":"crate:source-fact-scope","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line}}}],"api_path":"scope::register_alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v327","candidate_id":"candidate:beta:001","crate_id":"crate:source-fact-scope","boundary_id":"boundary:beta:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_line},"line_end":{beta_line}}}],"api_path":"scope::register_beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v327",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    let alpha_facts = facts
        .iter()
        .filter(|fact| fact.candidate_id == "candidate:alpha:001")
        .collect::<Vec<_>>();
    let beta_facts = facts
        .iter()
        .filter(|fact| fact.candidate_id == "candidate:beta:001")
        .collect::<Vec<_>>();

    let alpha_object_ids = alpha_facts
        .iter()
        .flat_map(|fact| fact.object_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let beta_object_ids = beta_facts
        .iter()
        .flat_map(|fact| fact.object_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    assert!(!alpha_object_ids.is_empty());
    assert!(!beta_object_ids.is_empty());
    assert!(
        alpha_object_ids
            .iter()
            .all(|object_id| object_id.starts_with("source_evidence:"))
    );
    assert!(
        beta_object_ids
            .iter()
            .all(|object_id| object_id.starts_with("source_evidence:"))
    );
    assert!(alpha_object_ids.is_disjoint(&beta_object_ids));
}

#[test]
fn rank_lifecycle_v2_orders_by_evidence_features() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let high = bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
        features.has_foreign_register = true;
        features.foreign_may_retain_callback = true;
        features.has_borrowed_capture = true;
        features.missing_unregister_before_drop = true;
        features.needs_dynamic_witness = true;
    });
    let mut low =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
            features.has_foreign_register = true;
            features.has_owned_anchor = true;
            features.has_static_bound = true;
        });
    low.candidate_id = "candidate:sample:002".to_owned();
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &high).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &low).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();

    let output_dir = temp.path().join("ranking-v2");
    let graph_dir = output_dir.join("graphs-v3");
    fs::create_dir_all(&graph_dir).unwrap();
    fs::write(
        graph_dir.join("candidate_sample_001.json"),
        r#"{
  "schema_version":"v3.2.6.lifecycle_graph_v3.1",
  "run_id":"run:v326",
  "candidate_id":"candidate:sample:001",
  "crate_id":"crate:sample",
  "pattern_family":"retained_borrowed_callback",
  "objects":[
    {"object_id":"callback:sample","object_kind":"callback","label":"callback:sample","source_ref":null,"fact_refs":["fact:sample:register"]},
    {"object_id":"user_data:sample","object_kind":"user_data","label":"user_data:sample","source_ref":null,"fact_refs":["fact:sample:register"]}
  ],
  "edges":[
    {"edge_id":"edge:sample:register","from_object_id":"user_data:sample","to_object_id":"callback:sample","relation":"register","ordering":"same_site","evidence_refs":[],"fact_refs":["fact:sample:register"]}
  ],
  "object_chains":[
    {"chain_id":"chain:sample:callback","object_ids":["user_data:sample","callback:sample"],"edge_ids":["edge:sample:register"],"fact_refs":["fact:sample:register"],"evidence_refs":["evidence:sample:chain"],"chain_status":"verified_static_chain"}
  ],
  "evidence_refs":["evidence:sample:chain"],
  "incomplete_reasons":[],
  "notes":["graph v3 fixture for ranked chain summary"]
}"#,
    )
    .unwrap();
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "rank-lifecycle-v2",
            "--features",
            features_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--graph-dir",
            "graphs-v3",
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-6-ranked-candidate""#,
        ));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-ranked-candidate",
            output_dir
                .join("ranked-candidates.jsonl.zst")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""ranked_count":2"#));

    let ranked = read_zst_ranked(&output_dir.join("ranked-candidates.jsonl.zst"));
    assert!(
        ranked
            .iter()
            .all(|record| record.lifecycle_graph_path.starts_with("graphs-v3/"))
    );
    assert_eq!(
        ranked[0].chain_summary.top_chain_id.as_deref(),
        Some("chain:sample:callback")
    );
    assert_eq!(ranked[0].chain_summary.verified_chain_count, 1);
    assert_eq!(
        ranked[0].chain_summary.recommended_witness_route,
        bw_model::V326WitnessRoute::CallbackLifecycle
    );
    assert!(
        ranked[0]
            .chain_summary
            .chain_fact_refs
            .contains(&"fact:sample:register".to_owned())
    );
}

#[test]
fn rank_lifecycle_v2_scores_manual_drop_prevention_signal() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let manual_drop =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
            features.has_drop_prevention = true;
            features.has_owned_anchor = true;
        });
    let mut returned_borrow =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
            features.has_returned_borrow_relation = true;
        });
    returned_borrow.candidate_id = "candidate:sample:returned-borrow".to_owned();
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &manual_drop).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &returned_borrow).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();

    let output_dir = temp.path().join("ranking-v2");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "rank-lifecycle-v2",
            "--features",
            features_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--graph-dir",
            "graphs-v3",
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""max_score":8"#));

    let ranked = read_zst_ranked(&output_dir.join("ranked-candidates.jsonl.zst"));
    assert_eq!(ranked[0].candidate_id, manual_drop.candidate_id);
    assert!(
        ranked[0]
            .risk_features
            .contains(&"has_drop_prevention".to_owned())
    );
    assert_eq!(ranked[0].score_breakdown.has_drop_prevention, 20);
}

#[test]
fn compare_anonymous_pairs_detects_drop_guard_delta() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.missing_unregister_before_drop = true;
        },
    );
    let right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.has_drop_guard = true;
            features.release_covers_callback = true;
        },
    );
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &left).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &right).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();

    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:v326","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("pair-analysis");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""kind":"v3-2-7-pair-delta""#))
        .stdout(predicate::str::contains(r#""separable_static_count":1"#));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-7-pair-delta",
            output_dir.join("pair-deltas.jsonl.zst").to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""record_count":1"#));
}

#[test]
fn compare_anonymous_pairs_uses_aligned_candidate_instead_of_first_crate_feature() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");

    let mut left_inactive =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate("crate:left", |_| {});
    left_inactive.candidate_id = "candidate:crate:left:001".to_owned();
    left_inactive.pattern_family = bw_model::V32PatternFamily::NativeLibraryBoundary;

    let mut left_callback = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.missing_unregister_before_drop = true;
        },
    );
    left_callback.candidate_id = "candidate:crate:left:002".to_owned();

    let mut right_inactive =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate("crate:right", |_| {});
    right_inactive.candidate_id = "candidate:crate:right:001".to_owned();
    right_inactive.pattern_family = bw_model::V32PatternFamily::NativeLibraryBoundary;

    let mut right_callback = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.has_drop_guard = true;
            features.release_covers_callback = true;
        },
    );
    right_callback.candidate_id = "candidate:crate:right:002".to_owned();

    let mut bytes = Vec::new();
    for feature in [
        &left_inactive,
        &left_callback,
        &right_inactive,
        &right_callback,
    ] {
        serde_json::to_writer(&mut bytes, feature).unwrap();
        bytes.push(b'\n');
    }
    fs::write(&features_path, bytes).unwrap();

    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"native_library_boundary","confidence":"static_only","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":1}],"api_path":"extern","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:002","crate_id":"crate:left","boundary_id":"boundary:left:002","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"native_library_boundary","confidence":"static_only","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":1}],"api_path":"extern","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:002","crate_id":"crate:right","boundary_id":"boundary:right:002","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();

    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:v326","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("pair-analysis");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""separable_static_count":1"#))
        .stdout(predicate::str::contains(
            r#""insufficient_evidence_count":1"#,
        ));

    let deltas = read_zst_pair_deltas(&output_dir.join("pair-deltas.jsonl.zst"));
    assert_eq!(deltas.len(), 2);
    assert!(deltas.iter().all(|delta| !delta.comparison_key.is_empty()));
    assert_eq!(
        deltas
            .iter()
            .filter(|delta| {
                delta.distinguishability == bw_model::V326Distinguishability::SeparableStatic
            })
            .count(),
        1
    );
    assert_eq!(
        deltas
            .iter()
            .filter(|delta| {
                delta.distinguishability == bw_model::V326Distinguishability::InsufficientEvidence
            })
            .count(),
        1
    );
}

#[test]
fn compare_anonymous_pairs_reports_coverage_gap_diagnostics() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let coverage_path = temp.path().join("lifecycle-coverage.jsonl");

    let mut left =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate("crate:left", |_| {});
    left.candidate_id = "candidate:crate:left:001".to_owned();
    left.missing_evidence = vec![
        "foreign_contract_missing".to_owned(),
        "object_binding_unproven".to_owned(),
    ];
    let mut right =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate("crate:right", |_| {});
    right.candidate_id = "candidate:crate:right:001".to_owned();
    right.missing_evidence = vec![
        "mir_hir_fact_missing".to_owned(),
        "release_order_unknown".to_owned(),
    ];

    let mut feature_bytes = Vec::new();
    for feature in [&left, &right] {
        serde_json::to_writer(&mut feature_bytes, feature).unwrap();
        feature_bytes.push(b'\n');
    }
    fs::write(&features_path, feature_bytes).unwrap();

    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();

    fs::write(
        &coverage_path,
        r#"{"schema_version":"v3.2.6.lifecycle_coverage.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","covered_function_bodies":[],"covered_trait_impls":[],"covered_drop_impls":[],"unavailable_paths":[{"path":"candidate:crate:left:001","reason":"static_facts_missing","notes":["static fact bridge did not cover this candidate"]},{"path":"candidate:crate:left:001","reason":"source_only_fallback","notes":["source-only fallback remains"]}],"fact_refs":[],"notes":["coverage manifest is candidate-scoped"]}
{"schema_version":"v3.2.6.lifecycle_coverage.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","covered_function_bodies":[],"covered_trait_impls":[],"covered_drop_impls":[],"unavailable_paths":[{"path":"candidate:crate:right:001::drop","reason":"drop_impl_unavailable","notes":["Drop impl was not covered"]}],"fact_refs":[],"notes":["coverage manifest is candidate-scoped"]}"#,
    )
    .unwrap();

    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:v326","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("pair-analysis");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--coverage",
            coverage_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""insufficient_evidence_count":1"#,
        ));

    let deltas = read_zst_pair_deltas(&output_dir.join("pair-deltas.jsonl.zst"));
    assert_eq!(deltas.len(), 1);
    let notes = deltas[0].notes.join("\n");
    assert!(notes.contains("MIR/HIR static fact coverage is missing"));
    assert!(notes.contains("foreign contract coverage is missing"));
    assert!(notes.contains("cross-function object binding proof is unavailable"));
    assert!(notes.contains("release coverage or ordering proof is unavailable"));
    assert!(notes.contains("source-only scope gap remains"));
}

#[test]
fn compare_anonymous_pairs_does_not_report_release_gap_when_release_is_proven() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let coverage_path = temp.path().join("lifecycle-coverage.jsonl");

    let mut left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_raw_pointer_escape = true;
            features.registration_release_pair_found = true;
            features.release_covers_callback = true;
        },
    );
    left.candidate_id = "candidate:crate:left:001".to_owned();
    let mut right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.has_raw_pointer_escape = true;
            features.registration_release_pair_found = true;
            features.release_covers_callback = true;
        },
    );
    right.candidate_id = "candidate:crate:right:001".to_owned();

    let mut feature_bytes = Vec::new();
    for feature in [&left, &right] {
        serde_json::to_writer(&mut feature_bytes, feature).unwrap();
        feature_bytes.push(b'\n');
    }
    fs::write(&features_path, feature_bytes).unwrap();

    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();

    fs::write(
        &coverage_path,
        r#"{"schema_version":"v3.2.6.lifecycle_coverage.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","covered_function_bodies":[],"covered_trait_impls":[],"covered_drop_impls":[],"unavailable_paths":[{"path":"candidate:crate:left:001::drop","reason":"drop_impl_unavailable","notes":["Drop impl was not covered"]}],"fact_refs":[],"notes":["coverage manifest is candidate-scoped"]}
{"schema_version":"v3.2.6.lifecycle_coverage.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","covered_function_bodies":[],"covered_trait_impls":[],"covered_drop_impls":[],"unavailable_paths":[{"path":"candidate:crate:right:001::drop","reason":"drop_impl_unavailable","notes":["Drop impl was not covered"]}],"fact_refs":[],"notes":["coverage manifest is candidate-scoped"]}"#,
    )
    .unwrap();

    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:v326","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("pair-analysis");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--coverage",
            coverage_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""indistinguishable_static_only_count":1"#,
        ));

    let deltas = read_zst_pair_deltas(&output_dir.join("pair-deltas.jsonl.zst"));
    assert_eq!(deltas.len(), 1);
    let notes = deltas[0].notes.join("\n");
    assert!(!notes.contains("release coverage or ordering proof is unavailable"));
}

#[test]
fn compare_anonymous_pairs_marks_one_sided_ambiguous_alignment_as_insufficient() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let mut first = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
        },
    );
    first.candidate_id = "candidate:crate:left:001".to_owned();
    let mut second = first.clone();
    second.candidate_id = "candidate:crate:left:002".to_owned();
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &first).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &second).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:002","crate_id":"crate:left","boundary_id":"boundary:left:002","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":11,"line_end":11}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:v326","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();
    let output_dir = temp.path().join("pair-analysis");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""insufficient_evidence_count":1"#,
        ))
        .stdout(predicate::str::contains(r#""unpaired_count":0"#));
}

#[test]
fn compare_anonymous_pairs_does_not_compare_different_api_paths() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let mut left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.missing_unregister_before_drop = true;
        },
    );
    left.candidate_id = "candidate:crate:left:001".to_owned();
    let mut right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.has_drop_guard = true;
            features.release_covers_callback = true;
        },
    );
    right.candidate_id = "candidate:crate:right:001".to_owned();

    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &left).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &right).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:v326","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            temp.path().join("pair-analysis").to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""separable_static_count":0"#))
        .stdout(predicate::str::contains(r#""unpaired_count":2"#));
}

#[test]
fn compare_anonymous_pairs_keeps_generic_api_alignment_insufficient() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let mut left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.missing_unregister_before_drop = true;
        },
    );
    left.candidate_id = "candidate:crate:left:001".to_owned();
    let mut right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.has_drop_guard = true;
            features.release_covers_callback = true;
        },
    );
    right.candidate_id = "candidate:crate:right:001".to_owned();

    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &left).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &right).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"callback_registration","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"callback_registration","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:v326","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            temp.path().join("pair-analysis").to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""separable_static_count":0"#))
        .stdout(predicate::str::contains(
            r#""insufficient_evidence_count":1"#,
        ));
}

#[test]
fn compare_anonymous_pairs_treats_exact_contract_api_ids_as_specific() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let mut left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.foreign_may_retain_user_data = true;
            features.has_raw_pointer_escape = true;
            features.has_owned_anchor = true;
            features.has_box_into_raw = true;
        },
    );
    left.candidate_id = "candidate:crate:left:001".to_owned();
    left.pattern_family = bw_model::V32PatternFamily::ForeignRetainedPointer;
    let mut right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.foreign_may_retain_user_data = true;
            features.has_raw_pointer_escape = true;
            features.has_owned_anchor = true;
            features.has_box_into_raw = true;
        },
    );
    right.candidate_id = "candidate:crate:right:001".to_owned();
    right.pattern_family = bw_model::V32PatternFamily::ForeignRetainedPointer;

    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &left).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &right).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"api:openssl:ssl_set_ex_data:register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic exact contract candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":12,"line_end":12}],"api_path":"api:openssl:ssl_set_ex_data:register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic exact contract candidate"]}"#,
    )
    .unwrap();
    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:pair-fixture","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();
    let output_dir = temp.path().join("pair-analysis");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:published",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""indistinguishable_static_only_count":1"#,
        ))
        .stdout(predicate::str::contains(
            r#""insufficient_evidence_count":0"#,
        ));

    let deltas = read_zst_pair_deltas(&output_dir.join("pair-deltas.jsonl.zst"));
    assert_eq!(deltas.len(), 1);
    assert_eq!(
        deltas[0].distinguishability,
        bw_model::V326Distinguishability::IndistinguishableStaticOnly
    );
    assert!(
        !deltas[0]
            .notes
            .iter()
            .any(|note| note.contains("not source-bound and specific"))
    );
}

#[test]
fn compare_anonymous_pairs_rejects_extra_segment_contract_api_identity() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let mut left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.foreign_may_retain_user_data = true;
            features.has_raw_pointer_escape = true;
        },
    );
    left.candidate_id = "candidate:crate:left:001".to_owned();
    left.pattern_family = bw_model::V32PatternFamily::ForeignRetainedPointer;
    let mut right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.foreign_may_retain_user_data = true;
            features.has_raw_pointer_escape = true;
        },
    );
    right.candidate_id = "candidate:crate:right:001".to_owned();
    right.pattern_family = bw_model::V32PatternFamily::ForeignRetainedPointer;

    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &left).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &right).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"api:openssl:ssl:set_ex_data:register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic malformed contract candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":12,"line_end":12}],"api_path":"api:openssl:ssl:set_ex_data:register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic malformed contract candidate"]}"#,
    )
    .unwrap();
    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:pair-fixture","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();
    let output_dir = temp.path().join("pair-analysis");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:published",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""separable_static_count":0"#))
        .stdout(predicate::str::contains(
            r#""insufficient_evidence_count":1"#,
        ));

    let deltas = read_zst_pair_deltas(&output_dir.join("pair-deltas.jsonl.zst"));
    assert_eq!(deltas.len(), 1);
    assert_eq!(
        deltas[0].distinguishability,
        bw_model::V326Distinguishability::InsufficientEvidence
    );
    assert!(
        deltas[0]
            .notes
            .iter()
            .any(|note| note.contains("not source-bound and specific"))
    );
}

#[test]
fn compare_anonymous_pairs_keeps_unqualified_api_alignment_insufficient() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let mut left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.missing_unregister_before_drop = true;
        },
    );
    left.candidate_id = "candidate:crate:left:001".to_owned();
    let mut right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.has_drop_guard = true;
            features.release_covers_callback = true;
        },
    );
    right.candidate_id = "candidate:crate:right:001".to_owned();

    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &left).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &right).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:pair-fixture","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            temp.path().join("pair-analysis").to_str().unwrap(),
            "--run-id",
            "run:published",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""separable_static_count":0"#))
        .stdout(predicate::str::contains(
            r#""insufficient_evidence_count":1"#,
        ));
}

#[test]
fn compare_anonymous_pairs_rejects_candidate_feature_run_mismatch() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let mut left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
        },
    );
    left.candidate_id = "candidate:crate:left:001".to_owned();
    let mut right = left.clone();
    right.crate_id = "crate:right".to_owned();
    right.candidate_id = "candidate:crate:right:001".to_owned();

    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &left).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &right).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:old","candidate_id":"candidate:crate:left:001","crate_id":"crate:left","boundary_id":"boundary:left:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:old","candidate_id":"candidate:crate:right:001","crate_id":"crate:right","boundary_id":"boundary:right:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::register_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:pair-fixture","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            temp.path().join("pair-analysis").to_str().unwrap(),
            "--run-id",
            "run:published",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-V326-PAIR-RUN-MISMATCH"));
}

#[test]
fn compare_anonymous_pairs_marks_candidates_without_features_insufficient() {
    let temp = public_safe_tempdir();
    let features_path = temp.path().join("lifecycle-features.jsonl");
    let candidates_path = temp.path().join("candidates.jsonl");
    let mut left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.missing_unregister_before_drop = true;
        },
    );
    left.candidate_id = "candidate:crate:left:covered".to_owned();
    let mut right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.has_drop_guard = true;
            features.release_covers_callback = true;
        },
    );
    right.candidate_id = "candidate:crate:right:covered".to_owned();

    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &left).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &right).unwrap();
    bytes.push(b'\n');
    fs::write(&features_path, bytes).unwrap();
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:covered","crate_id":"crate:left","boundary_id":"boundary:left:covered","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::covered","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:left:missing","crate_id":"crate:left","boundary_id":"boundary:left:missing","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":20,"line_end":20}],"api_path":"fixture::missing","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:covered","crate_id":"crate:right","boundary_id":"boundary:right:covered","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"fixture::covered","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate:right:missing","crate_id":"crate:right","boundary_id":"boundary:right:missing","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":20,"line_end":20}],"api_path":"fixture::missing","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    let pair_manifest = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_manifest,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:pair-fixture","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();
    let output_dir = temp.path().join("pair-analysis");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "compare-anonymous-pairs",
            "--features",
            features_path.to_str().unwrap(),
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--pair-manifest",
            pair_manifest.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:published",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""comparison_count":2"#))
        .stdout(predicate::str::contains(r#""separable_static_count":1"#))
        .stdout(predicate::str::contains(
            r#""insufficient_evidence_count":1"#,
        ));

    assert!(
        read_zst_pair_deltas(&output_dir.join("pair-deltas.jsonl.zst"))
            .iter()
            .all(|delta| delta.pair_manifest_run_id == "run:pair-fixture")
    );
}

#[test]
fn validate_rejects_unknown_field_in_lifecycle_evidence() {
    let temp = public_safe_tempdir();
    let evidence_path = temp.path().join("lifecycle-evidence.jsonl");
    fs::write(
        &evidence_path,
        r#"{"schema_version":"v3.2.6.lifecycle_evidence.1","run_id":"run:v326","record_id":"evidence:alpha:0001","crate_id":"crate:alpha","candidate_id":"candidate:alpha:001","evidence_kind":"foreign_register","source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":null,"text_sha256":null},"confidence":"medium","details":{},"notes":["neutral lifecycle evidence"],"cve":"CVE-0000-0000"}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-lifecycle-evidence",
            evidence_path.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown field"));
}

#[test]
fn validate_rejects_unknown_field_in_anonymous_pair() {
    let temp = public_safe_tempdir();
    let pair_path = temp.path().join("anonymous-pairs.jsonl");
    fs::write(
        &pair_path,
        r#"{"schema_version":"v3.2.6.anonymous_pair.1","run_id":"run:v326","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","relation_hint":"same_project_or_related_version","notes":["anonymous comparison only"],"vulnerable":true}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-anonymous-pair",
            pair_path.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown field"));
}

#[test]
fn validate_rejects_forbidden_token_inside_pair_delta_features() {
    let temp = public_safe_tempdir();
    let delta_path = temp.path().join("pair-deltas.jsonl");
    fs::write(
        &delta_path,
        r#"{"schema_version":"v3.2.6.pair_delta.1","run_id":"run:v326","pair_id":"pair:001","left_crate_id":"crate:left","right_crate_id":"crate:right","left_top_features":["vulnerable"],"right_top_features":["has_drop_guard"],"semantic_delta":["right_added_patch"],"distinguishability":"separable_static","notes":["anonymous comparison only"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-pair-delta",
            delta_path.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-V326-DELTA"));
}

#[test]
fn extract_lifecycle_evidence_scopes_same_crate_candidates_to_their_boundary_lines() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("scoped-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "scoped-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

unsafe extern "C" {
    fn set_alpha_hook(cb: Option<extern "C" fn(*mut c_void)>, user_data: *mut c_void);
    fn set_beta_hook(cb: Option<extern "C" fn(*mut c_void)>, user_data: *mut c_void);
}

pub fn register_alpha() {
    let local = 7_u32;
    let user_data = &local as *const u32 as *mut c_void;
    // Register callback user_data in this comment only.
    set_alpha_hook(Some(alpha_callback), user_data);
}

extern "C" fn alpha_callback(_user_data: *mut c_void) {}









pub struct BetaOwner {
    data: Box<u32>,
}

impl BetaOwner {
    pub fn register_beta(self) {
        let raw = Box::into_raw(self.data) as *mut c_void;
        set_beta_hook(Some(beta_callback), raw);
    }
}

extern "C" fn beta_callback(_user_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();

    let alpha_line = line_number(source, "set_alpha_hook(Some");
    let alpha_comment_line =
        line_number(source, "Register callback user_data in this comment only");
    let beta_line = line_number(source, "set_beta_hook(Some");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:scoped","crate_name":"scoped-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:scoped","boundary_id":"boundary:alpha:001","boundary_kind":"callback_registration","api_path":"scoped::register_alpha","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line}}}],"confidence":"high","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:scoped","boundary_id":"boundary:beta:001","boundary_kind":"callback_registration","api_path":"scoped::register_beta","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_line},"line_end":{beta_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:scoped","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line}}}],"api_path":"scoped::register_alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:scoped","boundary_id":"boundary:beta:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_line},"line_end":{beta_line}}}],"api_path":"scoped::register_beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let records = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    let alpha_lines = evidence_lines_for(&records, "candidate:alpha:001");
    let beta_lines = evidence_lines_for(&records, "candidate:beta:001");

    assert!(alpha_lines.contains(&alpha_line));
    assert!(!alpha_lines.contains(&alpha_comment_line));
    assert!(beta_lines.contains(&beta_line));
    assert!(!alpha_lines.contains(&beta_line));
    assert!(!beta_lines.contains(&alpha_line));
    assert_ne!(alpha_lines, beta_lines);
}

#[test]
fn extract_lifecycle_evidence_assigns_overlapping_context_to_nearest_boundary() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("overlap-scope-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "overlap-scope-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

pub fn register_both() {
    let alpha_data = Box::into_raw(Box::new(1_u8)) as *mut c_void;
    unsafe { ffi::set_alpha_hook(Some(alpha_callback), alpha_data) };

    let beta_data = Box::into_raw(Box::new(2_u8)) as *mut c_void;
    unsafe { ffi::set_beta_hook(Some(beta_callback), beta_data) };
}

extern "C" fn alpha_callback(_data: *mut c_void) {}
extern "C" fn beta_callback(_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();

    let alpha_raw_line = line_number(source, "Box::into_raw(Box::new(1_u8))");
    let alpha_register_line = line_number(source, "ffi::set_alpha_hook");
    let beta_raw_line = line_number(source, "Box::into_raw(Box::new(2_u8))");
    let beta_register_line = line_number(source, "ffi::set_beta_hook");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:overlap","crate_name":"overlap-scope-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:overlap","boundary_id":"boundary:alpha:001","boundary_kind":"callback_registration","api_path":"overlap::alpha","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_register_line},"line_end":{alpha_register_line}}}],"confidence":"medium","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:overlap","boundary_id":"boundary:beta:001","boundary_kind":"callback_registration","api_path":"overlap::beta","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_register_line},"line_end":{beta_register_line}}}],"confidence":"medium","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:overlap","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_register_line},"line_end":{alpha_register_line}}}],"api_path":"overlap::alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:overlap","boundary_id":"boundary:beta:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_register_line},"line_end":{beta_register_line}}}],"api_path":"overlap::beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let records = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    let alpha_lines = evidence_lines_for(&records, "candidate:alpha:001");
    let beta_lines = evidence_lines_for(&records, "candidate:beta:001");

    assert!(alpha_lines.contains(&alpha_raw_line));
    assert!(alpha_lines.contains(&alpha_register_line));
    assert!(!alpha_lines.contains(&beta_raw_line));
    assert!(!alpha_lines.contains(&beta_register_line));
    assert!(beta_lines.contains(&beta_raw_line));
    assert!(beta_lines.contains(&beta_register_line));
    assert!(!beta_lines.contains(&alpha_raw_line));
    assert!(!beta_lines.contains(&alpha_register_line));
}

#[test]
fn extract_lifecycle_evidence_does_not_treat_callback_definition_name_as_object_binding() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("callback-binding-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "callback-binding-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::{ffi::c_void, ptr};

mod ffi {
    use super::c_void;
    pub unsafe fn set_alpha_hook(_callback: Option<unsafe extern "C" fn(*mut c_void)>, _data: *mut c_void) {}
    pub unsafe fn set_beta_hook(_callback: Option<unsafe extern "C" fn(*mut c_void)>, _data: *mut c_void) {}
}

unsafe extern "C" fn alpha_callback(value: *mut c_void) {
    let _ = value as *mut u8;
}

unsafe extern "C" fn beta_callback(value: *mut c_void) {
    let _ = value as *mut u8;
}

fn install_callbacks() {
    unsafe { ffi::set_alpha_hook(Some(alpha_callback), ptr::null_mut()); }
    unsafe { ffi::set_beta_hook(Some(beta_callback), ptr::null_mut()); }
}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();

    let alpha_raw_line = line_number(source, "value as *mut u8;");
    let beta_raw_line = source
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            line.contains("value as *mut u8;")
                .then_some(index as u64 + 1)
        })
        .nth(1)
        .unwrap();
    let alpha_register_line = line_number(source, "ffi::set_alpha_hook(Some(alpha_callback)");
    let beta_register_line = line_number(source, "ffi::set_beta_hook(Some(beta_callback)");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:callback-binding","crate_name":"callback-binding-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:callback-binding","boundary_id":"boundary:alpha:001","boundary_kind":"foreign_retained_pointer","api_path":"source_api::alpha","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_raw_line},"line_end":{alpha_raw_line}}}],"confidence":"medium","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:callback-binding","boundary_id":"boundary:beta:001","boundary_kind":"foreign_retained_pointer","api_path":"source_api::beta","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_raw_line},"line_end":{beta_raw_line}}}],"confidence":"medium","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:callback-binding","boundary_id":"boundary:alpha:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_raw_line},"line_end":{alpha_raw_line}}}],"api_path":"source_api::alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:callback-binding","boundary_id":"boundary:beta:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_raw_line},"line_end":{beta_raw_line}}}],"api_path":"source_api::beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let records = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    let alpha_raw = records
        .iter()
        .find(|record| {
            record.candidate_id == "candidate:alpha:001"
                && record.evidence_kind == bw_model::V326EvidenceKind::RawPointerEscape
        })
        .expect("alpha raw pointer evidence must remain candidate-scoped");

    assert_ne!(
        serde_json::Value::String("callback:alpha_callback".to_owned()),
        alpha_raw.details["callback_object_id"]
    );
    assert!(!records.iter().any(|record| {
        record.candidate_id == "candidate:alpha:001"
            && record.source_ref.line_start == Some(beta_register_line)
    }));
    assert!(!records.iter().any(|record| {
        record.candidate_id == "candidate:beta:001"
            && record.source_ref.line_start == Some(alpha_register_line)
    }));
    assert!(!records.iter().any(|record| {
        record.evidence_kind == bw_model::V326EvidenceKind::ForeignRegister
            && (record.source_ref.line_start == Some(alpha_register_line)
                || record.source_ref.line_start == Some(beta_register_line))
    }));
}

#[test]
fn extract_lifecycle_evidence_does_not_cross_bind_same_named_callbacks_in_different_files() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("same-name-callbacks-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "same-name-callbacks-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub mod alpha;\npub mod beta;\n").unwrap();
    let alpha_source = r#"use std::ffi::c_void;

pub unsafe extern "C" fn callback(value: *mut c_void) {
    let _ = value as *mut u8;
}

pub fn install() {
    unsafe { ffi::set_hook(Some(callback), std::ptr::null_mut()); }
}
"#;
    let beta_source = r#"use std::ffi::c_void;

pub unsafe extern "C" fn callback(value: *mut c_void) {
    let _ = value as *mut u8;
}

pub fn install() {
    unsafe { ffi::set_hook(Some(callback), std::ptr::null_mut()); }
}
"#;
    fs::write(src_dir.join("alpha.rs"), alpha_source).unwrap();
    fs::write(src_dir.join("beta.rs"), beta_source).unwrap();

    let alpha_raw_line = line_number(alpha_source, "value as *mut u8;");
    let beta_raw_line = line_number(beta_source, "value as *mut u8;");
    let alpha_register_line = line_number(alpha_source, "ffi::set_hook(Some(callback)");
    let beta_register_line = line_number(beta_source, "ffi::set_hook(Some(callback)");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:same-name","crate_name":"same-name-callbacks-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:same-name","boundary_id":"boundary:alpha:001","boundary_kind":"foreign_retained_pointer","api_path":"source_api::alpha","evidence_refs":[{{"kind":"source_span","path":"src/alpha.rs","line_start":{alpha_raw_line},"line_end":{alpha_raw_line}}}],"confidence":"medium","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:same-name","boundary_id":"boundary:beta:001","boundary_kind":"foreign_retained_pointer","api_path":"source_api::beta","evidence_refs":[{{"kind":"source_span","path":"src/beta.rs","line_start":{beta_raw_line},"line_end":{beta_raw_line}}}],"confidence":"medium","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:same-name","boundary_id":"boundary:alpha:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/alpha.rs","line_start":{alpha_raw_line},"line_end":{alpha_raw_line}}}],"api_path":"source_api::alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:same-name","boundary_id":"boundary:beta:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/beta.rs","line_start":{beta_raw_line},"line_end":{beta_raw_line}}}],"api_path":"source_api::beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let records = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    for (candidate_id, path, raw_line, register_line, other_path) in [
        (
            "candidate:alpha:001",
            "src/alpha.rs",
            alpha_raw_line,
            alpha_register_line,
            "src/beta.rs",
        ),
        (
            "candidate:beta:001",
            "src/beta.rs",
            beta_raw_line,
            beta_register_line,
            "src/alpha.rs",
        ),
    ] {
        assert!(records.iter().any(|record| {
            record.candidate_id == candidate_id
                && record.evidence_kind == bw_model::V326EvidenceKind::RawPointerEscape
                && record.source_ref.path == path
                && record.source_ref.line_start == Some(raw_line)
        }));
        assert!(!records.iter().any(|record| {
            record.candidate_id == candidate_id && record.source_ref.path == other_path
        }));
        assert!(!records.iter().any(|record| {
            record.candidate_id == candidate_id
                && record.evidence_kind == bw_model::V326EvidenceKind::ForeignRegister
                && record.source_ref.line_start == Some(register_line)
        }));
    }
}

#[test]
fn extract_lifecycle_evidence_does_not_scan_source_without_spans() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("fallback-scope-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "fallback-scope-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

mod alpha {
    use std::ffi::c_void;

    unsafe extern "C" {
        pub fn set_hook(cb: Option<extern "C" fn(*mut c_void)>, user_data: *mut c_void);
    }
}

mod beta {
    use std::ffi::c_void;

    unsafe extern "C" {
        pub fn set_hook(cb: Option<extern "C" fn(*mut c_void)>, user_data: *mut c_void);
    }
}

pub fn register_alpha() {
    unsafe { alpha::set_hook(Some(alpha_callback), Box::into_raw(Box::new(1_u8)) as *mut _) };
}

pub fn register_beta() {
    unsafe { beta::set_hook(Some(beta_callback), Box::into_raw(Box::new(2_u8)) as *mut _) };
}

extern "C" fn alpha_callback(_user_data: *mut c_void) {}
extern "C" fn beta_callback(_user_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:fallback-scope","crate_name":"fallback-scope-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            temp.path().join("missing-source").display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:fallback-scope","boundary_id":"boundary:alpha:001","boundary_kind":"callback_registration","api_path":"alpha::set_hook","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"medium","notes":["synthetic boundary without source span"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:fallback-scope","boundary_id":"boundary:beta:001","boundary_kind":"callback_registration","api_path":"beta::set_hook","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"medium","notes":["synthetic boundary without source span"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:fallback-scope","boundary_id":"boundary:generic:001","boundary_kind":"callback_registration","api_path":"set_hook","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"medium","notes":["synthetic boundary without source span"]}"#,
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:fallback-scope","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"api_path":"alpha::set_hook","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate without source span"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:fallback-scope","boundary_id":"boundary:beta:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"api_path":"beta::set_hook","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate without source span"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:generic:001","crate_id":"crate:fallback-scope","boundary_id":"boundary:generic:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"api_path":"set_hook","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate without source span"]}"#,
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
            candidates_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let records = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    let alpha_lines = evidence_lines_for(&records, "candidate:alpha:001");
    let beta_lines = evidence_lines_for(&records, "candidate:beta:001");
    let generic_lines = evidence_lines_for(&records, "candidate:generic:001");

    assert!(alpha_lines.is_empty());
    assert!(beta_lines.is_empty());
    assert!(generic_lines.is_empty());
}

#[test]
fn extract_lifecycle_evidence_writes_lifecycle_facts_and_coverage_manifest() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("fact-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "fact-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

unsafe extern "C" {
    fn set_fact_hook(cb: Option<extern "C" fn(*mut c_void)>, user_data: *mut c_void);
    fn clear_fact_hook(cb: Option<extern "C" fn(*mut c_void)>);
}

pub fn register_fact() {
    let local = 7_u32;
    let user_data = &local as *const u32 as *mut c_void;
    set_fact_hook(Some(fact_callback), user_data);
}

pub fn release_fact() {
    unsafe { clear_fact_hook(None); }
}

extern "C" fn fact_callback(_user_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();
    let register_line = line_number(source, "set_fact_hook(Some");

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:fact","crate_name":"fact-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:fact","boundary_id":"boundary:fact:001","boundary_kind":"callback_registration","api_path":"fact_crate::register_fact","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{register_line},"line_end":{register_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:fact:001","crate_id":"crate:fact","boundary_id":"boundary:fact:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{register_line},"line_end":{register_line}}}],"api_path":"fact_crate::register_fact","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &facts_path,
        format!(
            r#"{{"schema_version":"bw.static/0.2","record_id":"static:fact:callback","producer":"fixture","build_id":"build:fixture","artifact":{{"crate_id":"crate:fact","package_name":"fact-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{register_line},"line_end":{register_line},"symbol_path":"fact_crate::fact_callback"}},"payload":{{"kind":"callback_site","site_id":"callback:fact","semantic_site_key":"src/lib.rs:{register_line}","def_path":"fact_crate::fact_callback"}}}}
{{"schema_version":"bw.static/0.2","record_id":"static:fact:capture","producer":"fixture","build_id":"build:fixture","artifact":{{"crate_id":"crate:fact","package_name":"fact-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{register_line},"line_end":{register_line},"symbol_path":null}},"payload":{{"kind":"callback_capture","site_id":"capture:fact","semantic_site_key":"src/lib.rs:{register_line}","callback_site_id":"callback:fact","object_site_id":"object:fact_user_data","capture_ordinal":0,"capture_mode":"borrowed"}}}}
{{"schema_version":"bw.static/0.2","record_id":"static:fact:register","producer":"fixture","build_id":"build:fixture","artifact":{{"crate_id":"crate:fact","package_name":"fact-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{register_line},"line_end":{register_line},"symbol_path":"fact_crate::register_fact"}},"payload":{{"kind":"registration_site","site_id":"registration:fact","semantic_site_key":"src/lib.rs:{register_line}","callback_site_id":"callback:fact","api_id":"fact_crate::register_fact","role":"register"}}}}
{{"schema_version":"bw.static/0.2","record_id":"static:fact:unregister","producer":"fixture","build_id":"build:fixture","artifact":{{"crate_id":"crate:fact","package_name":"fact-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{release_line},"line_end":{release_line},"symbol_path":"fact_crate::release_fact"}},"payload":{{"kind":"registration_site","site_id":"unregistration:fact","semantic_site_key":"src/lib.rs:{release_line}","callback_site_id":"callback:fact","api_id":"fact_crate::release_fact","role":"unregister"}}}}"#,
            release_line = line_number(source, "clear_fact_hook(None"),
        ),
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""fact_count":4"#))
        .stdout(predicate::str::contains(r#""coverage_count":1"#));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-lifecycle-fact",
            output_dir
                .join("lifecycle-facts.jsonl.zst")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""record_count":4"#));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-lifecycle-coverage",
            output_dir
                .join("lifecycle-coverage.jsonl.zst")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""record_count":1"#));

    let graph_dir = temp.path().join("lifecycle-graph");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates_dir.to_str().unwrap(),
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
            facts_path.to_str().unwrap(),
            "--output-dir",
            graph_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");
    let graph = fs::read_to_string(graph_dir.join("graphs-v3/candidate_fact_001.json")).unwrap();
    assert!(graph.contains("callback:callback:fact"));
}

#[test]
fn build_lifecycle_graph_v3_keeps_unverified_same_crate_candidates_separate() {
    let temp = public_safe_tempdir();
    let candidates_dir = temp.path().join("candidates");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:scoped","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"scoped::register_alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:scoped","boundary_id":"boundary:beta:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":30,"line_end":30}],"api_path":"scoped::register_beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();

    let evidence_path = temp.path().join("lifecycle-evidence.jsonl");
    fs::write(
        &evidence_path,
        r#"{"schema_version":"v3.2.6.lifecycle_evidence.1","run_id":"run:v326","record_id":"evidence:alpha:register","crate_id":"crate:scoped","candidate_id":"candidate:alpha:001","evidence_kind":"foreign_register","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"scoped::register_alpha","text_sha256":null},"confidence":"medium","details":{"callback_object_id":"callback:alpha"},"notes":["neutral lifecycle evidence"]}
{"schema_version":"v3.2.6.lifecycle_evidence.1","run_id":"run:v326","record_id":"evidence:beta:register","crate_id":"crate:scoped","candidate_id":"candidate:beta:001","evidence_kind":"foreign_register","source_ref":{"path":"src/lib.rs","line_start":30,"line_end":30,"symbol_path":"scoped::register_beta","text_sha256":null},"confidence":"medium","details":{"callback_object_id":"callback:beta"},"notes":["neutral lifecycle evidence"]}
{"schema_version":"v3.2.6.lifecycle_evidence.1","run_id":"run:v326","record_id":"evidence:beta:owned","crate_id":"crate:scoped","candidate_id":"candidate:beta:001","evidence_kind":"owned_anchor","source_ref":{"path":"src/lib.rs","line_start":29,"line_end":29,"symbol_path":"scoped::register_beta","text_sha256":null},"confidence":"high","details":{"object_id":"user_data:beta"},"notes":["neutral lifecycle evidence"]}"#,
    )
    .unwrap();
    // Unverified source_observation facts: valid public shape, but cannot bind stable
    // callback: ids. Graph-v3 must keep each candidate on independent observation nodes.
    let facts_path = temp.path().join("lifecycle-facts.jsonl");
    fs::write(
        &facts_path,
        r#"{"schema_version":"v3.2.6.lifecycle_fact.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:scoped","fact_id":"fact:alpha:register","fact_kind":"register_call","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"scoped::register_alpha","text_sha256":null},"symbol_path":"scoped::register_alpha","confidence":"high","coverage_state":"covered","provenance":{"origin":"source_observation"},"object_ids":["source_evidence:evidence:alpha:register"],"evidence_refs":["evidence:alpha:register"],"notes":["source observation; not authoritative binding"]}
{"schema_version":"v3.2.6.lifecycle_fact.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:scoped","fact_id":"fact:beta:register","fact_kind":"register_call","source_ref":{"path":"src/lib.rs","line_start":30,"line_end":30,"symbol_path":"scoped::register_beta","text_sha256":null},"symbol_path":"scoped::register_beta","confidence":"high","coverage_state":"covered","provenance":{"origin":"source_observation"},"object_ids":["source_evidence:evidence:beta:register"],"evidence_refs":["evidence:beta:register"],"notes":["source observation; not authoritative binding"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("graph-v3");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates_dir.to_str().unwrap(),
            "--evidence",
            evidence_path.to_str().unwrap(),
            "--facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-6-lifecycle-graph-v3""#,
        ));

    let alpha_graph =
        fs::read_to_string(output_dir.join("graphs-v3/candidate_alpha_001.json")).unwrap();
    let beta_graph =
        fs::read_to_string(output_dir.join("graphs-v3/candidate_beta_001.json")).unwrap();
    assert!(alpha_graph.contains("observation:callback:evidence_alpha_register"));
    assert!(!alpha_graph.contains("evidence_beta_register"));
    assert!(beta_graph.contains("observation:callback:evidence_beta_register"));
    assert!(!beta_graph.contains("evidence_alpha_register"));
}

#[test]
fn build_lifecycle_graph_v3_rejects_static_fact_without_source_artifact() {
    let temp = public_safe_tempdir();
    let candidates_path = temp.path().join("candidates.jsonl");
    let evidence_path = temp.path().join("lifecycle-evidence.jsonl");
    let facts_path = temp.path().join("lifecycle-facts.jsonl");
    let output_dir = temp.path().join("graph-v3");
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:provenance:001","crate_id":"crate:provenance","boundary_id":"boundary:provenance:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"provenance::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    fs::write(
        &evidence_path,
        r#"{"schema_version":"v3.2.6.lifecycle_evidence.1","run_id":"run:v326","record_id":"evidence:provenance:register","crate_id":"crate:provenance","candidate_id":"candidate:provenance:001","evidence_kind":"foreign_register","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"provenance::register","text_sha256":null},"confidence":"medium","details":{},"notes":["neutral lifecycle evidence"]}"#,
    )
    .unwrap();
    fs::write(
        &facts_path,
        r#"{"schema_version":"v3.2.6.lifecycle_fact.1","run_id":"run:v326","candidate_id":"candidate:provenance:001","crate_id":"crate:provenance","fact_id":"fact:provenance:register","fact_kind":"register_call","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"provenance::register","text_sha256":null},"symbol_path":"provenance::register","confidence":"high","coverage_state":"covered","provenance":{"origin":"static_artifact","static_fact_record_id":"static:provenance:register","static_build_id":"build:fixture","static_producer":"fixture"},"object_ids":["callback:alpha","static_site:register"],"evidence_refs":["evidence:provenance:register"],"notes":["candidate-scoped static lifecycle fact"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--evidence",
            evidence_path.to_str().unwrap(),
            "--facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("BW-V326-FACT-PROVENANCE"));
}

#[test]
fn build_lifecycle_graph_v3_rejects_evidence_with_candidate_crate_mismatch() {
    let temp = public_safe_tempdir();
    let candidates_path = temp.path().join("candidates.jsonl");
    let evidence_path = temp.path().join("lifecycle-evidence.jsonl");
    let output_dir = temp.path().join("graph-v3");
    fs::write(
        &candidates_path,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:crate-check:001","crate_id":"crate:alpha","boundary_id":"boundary:crate-check:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"crate_check::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    fs::write(
        &evidence_path,
        r#"{"schema_version":"v3.2.6.lifecycle_evidence.1","run_id":"run:v326","record_id":"evidence:crate-check:register","crate_id":"crate:beta","candidate_id":"candidate:crate-check:001","evidence_kind":"foreign_register","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"crate_check::register","text_sha256":null},"confidence":"medium","details":{},"notes":["neutral lifecycle evidence"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates_path.to_str().unwrap(),
            "--evidence",
            evidence_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("BW-V326-EVIDENCE-CANDIDATE-CRATE"));
}

#[test]
fn extract_lifecycle_facts_do_not_bleed_across_same_crate_api_namespace() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("fact-scope-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "fact-scope-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

pub fn register_alpha() {
    set_alpha_hook(Some(alpha_callback), std::ptr::null_mut::<c_void>());
}

pub fn register_beta() {
    set_beta_hook(Some(beta_callback), std::ptr::null_mut::<c_void>());
}

fn set_alpha_hook(_cb: Option<extern "C" fn(*mut c_void)>, _user_data: *mut c_void) {}
fn set_beta_hook(_cb: Option<extern "C" fn(*mut c_void)>, _user_data: *mut c_void) {}
extern "C" fn alpha_callback(_user_data: *mut c_void) {}
extern "C" fn beta_callback(_user_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();
    let alpha_line = line_number(source, "set_alpha_hook(Some");
    let beta_line = line_number(source, "set_beta_hook(Some");

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:fact-scope","crate_name":"fact-scope-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:fact-scope","boundary_id":"boundary:alpha:001","boundary_kind":"callback_registration","api_path":"scoped::register_alpha","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line}}}],"confidence":"high","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:fact-scope","boundary_id":"boundary:beta:001","boundary_kind":"callback_registration","api_path":"scoped::register_beta","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_line},"line_end":{beta_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:fact-scope","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line}}}],"api_path":"scoped::register_alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:fact-scope","boundary_id":"boundary:beta:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_line},"line_end":{beta_line}}}],"api_path":"scoped::register_beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &facts_path,
        format!(
            r#"{{"schema_version":"bw.static/0.2","record_id":"static:alpha:register","producer":"fixture","build_id":"build:fixture","artifact":{{"crate_id":"crate:fact-scope","package_name":"fact-scope-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line},"symbol_path":"scoped::register_alpha"}},"payload":{{"kind":"registration_site","site_id":"registration:alpha","semantic_site_key":"macro-expansion","callback_site_id":"callback:alpha","api_id":"scoped::register_alpha","role":"register"}}}}
{{"schema_version":"bw.static/0.2","record_id":"static:alpha:unregister","producer":"fixture","build_id":"build:fixture","artifact":{{"crate_id":"crate:fact-scope","package_name":"fact-scope-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{alpha_line},"line_end":{alpha_line},"symbol_path":"scoped::release_alpha"}},"payload":{{"kind":"registration_site","site_id":"unregistration:alpha","semantic_site_key":"other.rs:87","callback_site_id":"callback:alpha","api_id":"scoped::release_alpha","role":"unregister"}}}}"#,
        ),
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    let alpha_facts = facts
        .iter()
        .filter(|fact| fact.candidate_id == "candidate:alpha:001")
        .collect::<Vec<_>>();
    let beta_facts = facts
        .iter()
        .filter(|fact| fact.candidate_id == "candidate:beta:001")
        .collect::<Vec<_>>();

    // Alpha owns the exclusive static register/unregister pair via exact API / site hop.
    assert_eq!(alpha_facts.len(), 2);
    assert!(alpha_facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::RegisterCall
            && fact.provenance.origin == bw_model::V326LifecycleFactOrigin::StaticArtifact
    }));
    assert!(alpha_facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::UnregisterCall
            && fact.provenance.origin == bw_model::V326LifecycleFactOrigin::StaticArtifact
    }));

    // Beta has no exclusive static facts. It may emit non-authoritative source
    // observations for its own boundary, but must not receive alpha's static
    // callback/register/unregister artifacts or callback object ids.
    assert!(beta_facts.iter().all(|fact| {
        fact.provenance.origin == bw_model::V326LifecycleFactOrigin::SourceObservation
            && fact
                .object_ids
                .iter()
                .all(|object_id| object_id.starts_with("source_evidence:"))
            && !fact
                .object_ids
                .iter()
                .any(|object_id| object_id.contains("callback:alpha"))
            && fact.provenance.static_fact_record_id.is_none()
    }));
    assert!(
        !facts.iter().any(|fact| {
            fact.candidate_id == "candidate:beta:001"
                && fact.provenance.origin == bw_model::V326LifecycleFactOrigin::StaticArtifact
        }),
        "beta must not inherit alpha static facts"
    );
}

#[test]
fn extract_lifecycle_facts_expand_static_site_identity_without_cross_candidate_leak() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("fact-tail-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "fact-tail-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn placeholder() {}\n").unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:fact-tail","crate_name":"fact-tail-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:fact-tail","boundary_id":"boundary:alpha:001","boundary_kind":"callback_registration","api_path":"alpha_component::register","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"medium","notes":["synthetic boundary without source span"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:fact-tail","boundary_id":"boundary:beta:001","boundary_kind":"callback_registration","api_path":"beta_component::register","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"medium","notes":["synthetic boundary without source span"]}"#,
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:fact-tail","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"api_path":"alpha_component::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate without source span"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:fact-tail","boundary_id":"boundary:beta:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"api_path":"beta_component::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate without source span"]}"#,
    )
    .unwrap();
    fs::write(
        &facts_path,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:alpha:register","producer":"fixture","build_id":"build:fixture","artifact":{"crate_id":"crate:fact-tail","package_name":"fact-tail-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"alpha_component::register"},"payload":{"kind":"registration_site","site_id":"registration:alpha","semantic_site_key":"macro-expansion","callback_site_id":"callback:alpha","api_id":"alpha_component::register","role":"register"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].candidate_id, "candidate:alpha:001");
}

#[test]
fn extract_lifecycle_facts_anchor_multiline_static_registration_to_inner_candidate_span() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("multiline-static-anchor-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "multiline-static-anchor-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("lib.rs"),
        r#"pub fn other_register() {
    let _other = 1;
}

pub fn register_sql_function() {
    setup();
    prepare();
    unsafe {
        sqlite3_create_function_v2(
            db(),
            name(),
            callback_fn() as *mut c_void,
            destroy_fn(),
        );
    }
}
"#,
    )
    .unwrap();

    let target_api = "api:synthetic:multiline-static-target";
    let sibling_api = "api:synthetic:multiline-static-sibling";
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:multiline-static-anchor","crate_name":"multiline-static-anchor-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:multiline-static-anchor","boundary_id":"boundary:target:001","boundary_kind":"callback_registration","api_path":"{target_api}","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":12,"line_end":12}}],"confidence":"high","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:multiline-static-anchor","boundary_id":"boundary:sibling:001","boundary_kind":"callback_registration","api_path":"{sibling_api}","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":2,"line_end":2}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:target:001","crate_id":"crate:multiline-static-anchor","boundary_id":"boundary:target:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":12,"line_end":12}}],"api_path":"{target_api}","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:sibling:001","crate_id":"crate:multiline-static-anchor","boundary_id":"boundary:sibling:001","pattern_family":"foreign_retained_pointer","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":2,"line_end":2}}],"api_path":"{sibling_api}","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic sibling candidate"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &facts_path,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:target:register","producer":"fixture","build_id":"build:multiline-static","artifact":{"crate_id":"crate:multiline-static-anchor","package_name":"multiline-static-anchor-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":8,"line_end":14,"symbol_path":"sqlite::connection::raw::RawConnection::register_sql_function"},"payload":{"kind":"registration_site","site_id":"site:target:register","semantic_site_key":"semantic:target:register","callback_site_id":null,"user_data_site_id":"site:target:user-data","api_id":"api:diesel:sqlite3_create_function_v2:register","role":"register"}}
{"schema_version":"bw.static/0.2","record_id":"static:target:into-raw","producer":"fixture","build_id":"build:multiline-static","artifact":{"crate_id":"crate:multiline-static-anchor","package_name":"multiline-static-anchor-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":8,"line_end":14,"symbol_path":"sqlite::connection::raw::RawConnection::register_sql_function"},"payload":{"kind":"raw_pointer_transfer","site_id":"site:target:into-raw","semantic_site_key":"semantic:target:into-raw","user_data_site_id":"site:target:user-data","transfer_kind":"into_raw"}}
{"schema_version":"bw.static/0.2","record_id":"static:target:from-raw","producer":"fixture","build_id":"build:multiline-static","artifact":{"crate_id":"crate:multiline-static-anchor","package_name":"multiline-static-anchor-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":8,"line_end":14,"symbol_path":"sqlite::connection::raw::RawConnection::register_sql_function"},"payload":{"kind":"raw_pointer_transfer","site_id":"site:target:from-raw","semantic_site_key":"semantic:target:from-raw","user_data_site_id":"site:target:user-data","transfer_kind":"from_raw"}}
{"schema_version":"bw.static/0.2","record_id":"static:target:release-proof","producer":"fixture","build_id":"build:multiline-static","artifact":{"crate_id":"crate:multiline-static-anchor","package_name":"multiline-static-anchor-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":8,"line_end":14,"symbol_path":"sqlite::connection::raw::RawConnection::register_sql_function"},"payload":{"kind":"release_path_proof","site_id":"site:target:release-proof","semantic_site_key":"semantic:target:release-proof","registration_site_id":"site:target:register","release_site_id":"site:target:from-raw","object_site_id":"site:target:user-data"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    let target_facts = facts
        .iter()
        .filter(|fact| fact.candidate_id == "candidate:target:001")
        .collect::<Vec<_>>();
    assert!(target_facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::RegisterCall
            && fact.provenance.origin == bw_model::V326LifecycleFactOrigin::StaticArtifact
            && fact.provenance.static_fact_record_id.as_deref() == Some("static:target:register")
    }));
    assert!(target_facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::ReleasePathProof
            && fact.provenance.static_fact_record_id.as_deref()
                == Some("static:target:release-proof")
    }));
    assert!(
        !facts.iter().any(|fact| {
            fact.candidate_id == "candidate:sibling:001"
                && fact.provenance.origin == bw_model::V326LifecycleFactOrigin::StaticArtifact
        }),
        "sibling candidate must not inherit multiline static registration facts"
    );
}

#[test]
fn extract_lifecycle_facts_drop_static_fact_with_ambiguous_candidate_api_anchor() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("ambiguous-static-anchor-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "ambiguous-static-anchor-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn placeholder() {}\n").unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:ambiguous-static","crate_name":"ambiguous-static-anchor-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:ambiguous-static","boundary_id":"boundary:shared:001","boundary_kind":"callback_registration","api_path":"shared_component::register","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"medium","notes":["synthetic boundary without source span"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:ambiguous-static","boundary_id":"boundary:shared:002","boundary_kind":"callback_registration","api_path":"shared_component::register","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"medium","notes":["synthetic boundary without source span"]}"#,
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:shared:001","crate_id":"crate:ambiguous-static","boundary_id":"boundary:shared:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"api_path":"shared_component::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate without source span"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:shared:002","crate_id":"crate:ambiguous-static","boundary_id":"boundary:shared:002","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"api_path":"shared_component::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate without source span"]}"#,
    )
    .unwrap();
    fs::write(
        &facts_path,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:shared:register","producer":"fixture","build_id":"build:fixture","artifact":{"crate_id":"crate:ambiguous-static","package_name":"ambiguous-static-anchor-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"shared_component::register"},"payload":{"kind":"registration_site","site_id":"registration:shared","semantic_site_key":"macro-expansion","callback_site_id":"callback:shared","api_id":"shared_component::register","role":"register"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    assert!(read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst")).is_empty());
}

#[test]
fn extract_lifecycle_facts_do_not_treat_cross_version_record_ids_as_ambiguous() {
    let temp = tempfile::Builder::new()
        .prefix("bwversioned000")
        .rand_bytes(0)
        .tempdir()
        .unwrap();
    let crate_v1_dir = temp.path().join("versioned-crate-0.1.0");
    let crate_v2_dir = temp.path().join("versioned-crate-0.2.0");
    fs::create_dir_all(crate_v1_dir.join("src")).unwrap();
    fs::create_dir_all(crate_v2_dir.join("src")).unwrap();
    for crate_dir in [&crate_v1_dir, &crate_v2_dir] {
        fs::write(
            crate_dir.join("Cargo.toml"),
            r#"[package]
name = "versioned-crate"
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(crate_dir.join("src/lib.rs"), "pub fn register() {}\n").unwrap();
    }

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:versioned:0.1.0","crate_name":"versioned-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}
{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:versioned:0.2.0","crate_name":"versioned-crate","version":"0.2.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_v1_dir.display(),
            crate_v2_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:versioned:0.1.0","boundary_id":"boundary:versioned:010","boundary_kind":"callback_registration","api_path":"versioned::register","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":1}],"confidence":"high","notes":["synthetic boundary"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:versioned:0.2.0","boundary_id":"boundary:versioned:020","boundary_kind":"callback_registration","api_path":"versioned::register","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":1}],"confidence":"high","notes":["synthetic boundary"]}"#,
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:versioned:010","crate_id":"crate:versioned:0.1.0","boundary_id":"boundary:versioned:010","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":1}],"api_path":"versioned::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:versioned:020","crate_id":"crate:versioned:0.2.0","boundary_id":"boundary:versioned:020","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":1}],"api_path":"versioned::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    fs::write(
        &facts_path,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:shared:register","producer":"fixture","build_id":"build:versioned:010","artifact":{"crate_id":"crate:versioned:0.1.0","package_name":"versioned-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"versioned::register"},"payload":{"kind":"registration_site","site_id":"registration:versioned:010","semantic_site_key":"versioned:010","callback_site_id":"callback:versioned:010","api_id":"versioned::register","role":"register"}}
{"schema_version":"bw.static/0.2","record_id":"static:shared:register","producer":"fixture","build_id":"build:versioned:020","artifact":{"crate_id":"crate:versioned:0.2.0","package_name":"versioned-crate","package_version":"0.2.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"versioned::register"},"payload":{"kind":"registration_site","site_id":"registration:versioned:020","semantic_site_key":"versioned:020","callback_site_id":"callback:versioned:020","api_id":"versioned::register","role":"register"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert_eq!(facts.len(), 2);
    assert!(facts.iter().all(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::RegisterCall
            && fact.provenance.origin == bw_model::V326LifecycleFactOrigin::StaticArtifact
    }));
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:versioned:010"
            && fact.provenance.static_build_id.as_deref() == Some("build:versioned:010")
    }));
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:versioned:020"
            && fact.provenance.static_build_id.as_deref() == Some("build:versioned:020")
    }));
}

#[test]
fn extract_lifecycle_facts_scope_returned_borrow_and_external_buffer_to_matching_candidate() {
    let temp = tempfile::Builder::new()
        .prefix("bwscope000")
        .rand_bytes(0)
        .tempdir()
        .unwrap();
    let crate_dir = temp.path().join("scope-facts-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "scope-facts-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"pub fn returned_borrow(owner: &i32) -> &i32 {
    owner
}

pub struct ExternalBuffer {
    raw: *const u8,
}

pub fn external_buffer(source: &[u8]) -> ExternalBuffer {
    ExternalBuffer {
        raw: source.as_ptr(),
    }
}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:scope-facts:0.1.0","crate_name":"scope-facts-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:scope-facts:0.1.0","boundary_id":"boundary:scope:return","boundary_kind":"callback_registration","api_path":"scope_facts::returned_borrow","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":3}],"confidence":"high","notes":["synthetic boundary"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:scope-facts:0.1.0","boundary_id":"boundary:scope:buffer","boundary_kind":"callback_registration","api_path":"scope_facts::external_buffer","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":9,"line_end":13}],"confidence":"high","notes":["synthetic boundary"]}"#,
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:scope:return","crate_id":"crate:scope-facts:0.1.0","boundary_id":"boundary:scope:return","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":1,"line_end":3}],"api_path":"scope_facts::returned_borrow","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:scope:buffer","crate_id":"crate:scope-facts:0.1.0","boundary_id":"boundary:scope:buffer","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":9,"line_end":13}],"api_path":"scope_facts::external_buffer","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    fs::write(
        &facts_path,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:scope:return","producer":"fixture","build_id":"build:scope-facts","artifact":{"crate_id":"crate:scope-facts:0.1.0","package_name":"scope-facts-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"scope_facts::returned_borrow"},"payload":{"kind":"returned_borrow_relation","site_id":"site:scope:return:relation","semantic_site_key":"scope:return","source_site_id":"site:scope:return:source","returned_site_id":"site:scope:return:returned","api_id":"scope_facts::returned_borrow","relation_kind":"unconstrained_return_lifetime"}}
{"schema_version":"bw.static/0.2","record_id":"static:scope:buffer","producer":"fixture","build_id":"build:scope-facts","artifact":{"crate_id":"crate:scope-facts:0.1.0","package_name":"scope-facts-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":9,"line_end":9,"symbol_path":"scope_facts::external_buffer"},"payload":{"kind":"external_buffer_binding","site_id":"site:scope:buffer:binding","semantic_site_key":"scope:buffer","source_site_id":"site:scope:buffer:source","buffer_site_id":"site:scope:buffer:buffer","api_id":"scope_facts::external_buffer"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    let return_candidate_facts = facts
        .iter()
        .filter(|fact| fact.candidate_id == "candidate:scope:return")
        .collect::<Vec<_>>();
    let buffer_candidate_facts = facts
        .iter()
        .filter(|fact| fact.candidate_id == "candidate:scope:buffer")
        .collect::<Vec<_>>();

    assert!(
        return_candidate_facts.iter().any(|fact| {
            fact.fact_kind == bw_model::V326LifecycleFactKind::ReturnedBorrowRelation
        })
    );
    assert!(return_candidate_facts.iter().any(|fact| {
        fact.object_ids.iter().any(|object_id| {
            object_id == "static_site:returned_borrow_relation_kind:unconstrained_return_lifetime"
        })
    }));
    assert!(
        return_candidate_facts.iter().all(|fact| {
            fact.fact_kind != bw_model::V326LifecycleFactKind::ExternalBufferBinding
        })
    );
    assert!(
        buffer_candidate_facts.iter().any(|fact| {
            fact.fact_kind == bw_model::V326LifecycleFactKind::ExternalBufferBinding
        })
    );
    assert!(
        buffer_candidate_facts.iter().all(|fact| {
            fact.fact_kind != bw_model::V326LifecycleFactKind::ReturnedBorrowRelation
        })
    );
}

#[test]
fn extract_lifecycle_facts_scope_persisted_returned_borrow_to_matching_candidate() {
    let temp = tempfile::Builder::new()
        .prefix("bwpersist000")
        .rand_bytes(0)
        .tempdir()
        .unwrap();
    let crate_dir = temp.path().join("persisted-facts-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "persisted-facts-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("lib.rs"),
        r#"pub mod stmt {
    pub struct Statement;
    pub struct StatementUse;

    impl Statement {
        pub fn field_name(owner: &str) -> &str {
            owner
        }
    }
}

pub fn persisted_view(owner: &str) -> &str {
    owner
}

pub fn unrelated_view(owner: &str) -> &str {
    owner
}
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("storage.rs"),
        r#"pub fn collect_field_name(owner: &str) -> Vec<&str> {
    vec![owner]
}
"#,
    )
    .unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:persisted-facts:0.1.0","crate_name":"persisted-facts-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:persisted-facts:0.1.0","boundary_id":"boundary:persisted:field_name","boundary_kind":"returned_borrow","api_path":"persisted_facts::stmt::Statement::field_name","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":5,"line_end":7}],"confidence":"high","notes":["synthetic boundary"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:persisted-facts:0.1.0","boundary_id":"boundary:persisted:field_name_storage","boundary_kind":"returned_borrow","api_path":"persisted_facts::stmt::StatementUse::field_name","evidence_refs":[{"kind":"source_span","path":"src/storage.rs","line_start":1,"line_end":2}],"confidence":"high","notes":["synthetic boundary"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:persisted-facts:0.1.0","boundary_id":"boundary:persisted:view","boundary_kind":"callback_registration","api_path":"persisted_facts::persisted_view","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":11,"line_end":13}],"confidence":"high","notes":["synthetic boundary"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:persisted-facts:0.1.0","boundary_id":"boundary:persisted:unrelated","boundary_kind":"callback_registration","api_path":"persisted_facts::unrelated_view","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":15,"line_end":17}],"confidence":"high","notes":["synthetic boundary"]}"#,
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:persisted:field_name","crate_id":"crate:persisted-facts:0.1.0","boundary_id":"boundary:persisted:field_name","pattern_family":"returned_borrow_view","confidence":"static_only","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":5,"line_end":7}],"api_path":"persisted_facts::stmt::Statement::field_name","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:persisted:field_name_storage","crate_id":"crate:persisted-facts:0.1.0","boundary_id":"boundary:persisted:field_name_storage","pattern_family":"returned_borrow_view","confidence":"static_only","evidence_refs":[{"kind":"source_span","path":"src/storage.rs","line_start":1,"line_end":2}],"api_path":"persisted_facts::stmt::StatementUse::field_name","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:persisted:view","crate_id":"crate:persisted-facts:0.1.0","boundary_id":"boundary:persisted:view","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":11,"line_end":13}],"api_path":"persisted_facts::persisted_view","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:persisted:unrelated","crate_id":"crate:persisted-facts:0.1.0","boundary_id":"boundary:persisted:unrelated","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":15,"line_end":17}],"api_path":"persisted_facts::unrelated_view","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}"#,
    )
    .unwrap();
    fs::write(
        &facts_path,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:persisted:view","producer":"fixture","build_id":"build:persisted-facts","artifact":{"crate_id":"crate:persisted-facts:0.1.0","package_name":"persisted-facts-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":11,"line_end":11,"symbol_path":"persisted_facts::persisted_view"},"payload":{"kind":"persisted_returned_borrow","site_id":"site:persisted:view:relation","semantic_site_key":"persisted:view","source_site_id":"site:persisted:view:source","returned_site_id":"site:persisted:view:returned","storage_site_id":"site:persisted:view:storage","api_id":"persisted_facts::persisted_view"}}
{"schema_version":"bw.static/0.2","record_id":"static:relation:field_name","producer":"fixture","build_id":"build:persisted-facts","artifact":{"crate_id":"crate:persisted-facts:0.1.0","package_name":"persisted-facts-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":6,"line_end":6,"symbol_path":"persisted_facts::stmt::Statement::field_name"},"payload":{"kind":"returned_borrow_relation","site_id":"site:persisted:field_name:surface","semantic_site_key":"persisted:field_name:surface","source_site_id":"site:persisted:field_name:source","returned_site_id":"site:persisted:field_name:returned","api_id":"persisted_facts::stmt::Statement::field_name"}}
{"schema_version":"bw.static/0.2","record_id":"static:persisted:field_name","producer":"fixture","build_id":"build:persisted-facts","artifact":{"crate_id":"crate:persisted-facts:0.1.0","package_name":"persisted-facts-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/storage.rs","line_start":1,"line_end":1,"symbol_path":"persisted_facts::storage::collect_field_name"},"payload":{"kind":"persisted_returned_borrow","site_id":"site:persisted:field_name:relation","semantic_site_key":"persisted:field_name","source_site_id":"site:persisted:field_name:source","returned_site_id":"site:persisted:field_name:returned","storage_site_id":"site:persisted:field_name:storage","api_id":"persisted_facts::stmt::StatementUse::field_name"}}
{"schema_version":"bw.static/0.2","record_id":"static:persisted:field_name:order","producer":"fixture","build_id":"build:persisted-facts","artifact":{"crate_id":"crate:persisted-facts:0.1.0","package_name":"persisted-facts-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/storage.rs","line_start":2,"line_end":2,"symbol_path":"persisted_facts::storage::step_then_use"},"payload":{"kind":"returned_borrow_invalidation_order","site_id":"site:persisted:field_name:order","semantic_site_key":"persisted:field_name:order","persisted_site_id":"site:persisted:field_name:relation","invalidation_site_id":"site:persisted:field_name:invalidation","use_site_id":"site:persisted:field_name:use","api_id":"persisted_facts::stmt::StatementUse::field_name","invalidation_api_id":"persisted_facts::stmt::StatementUse::step","ordering":"persistence_before_invalidation_use"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:persisted:view"
            && fact.fact_kind == bw_model::V326LifecycleFactKind::PersistedReturnedBorrow
            && fact.symbol_path.as_deref() == Some("persisted_facts::persisted_view")
            && fact.provenance.static_fact_record_id.as_deref() == Some("static:persisted:view")
    }));
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:persisted:field_name"
            && fact.fact_kind == bw_model::V326LifecycleFactKind::ReturnedBorrowRelation
            && fact.symbol_path.as_deref() == Some("persisted_facts::stmt::Statement::field_name")
            && fact.provenance.static_fact_record_id.as_deref()
                == Some("static:relation:field_name")
    }));
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:persisted:field_name"
            && fact.fact_kind == bw_model::V326LifecycleFactKind::PersistedReturnedBorrow
            && fact.symbol_path.as_deref()
                == Some("persisted_facts::stmt::StatementUse::field_name")
            && fact.provenance.static_fact_record_id.as_deref()
                == Some("static:persisted:field_name")
    }));
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:persisted:field_name"
            && fact.fact_kind == bw_model::V326LifecycleFactKind::ReturnedBorrowInvalidationOrder
            && fact.symbol_path.as_deref()
                == Some("persisted_facts::stmt::StatementUse::field_name")
            && fact.provenance.static_fact_record_id.as_deref()
                == Some("static:persisted:field_name:order")
    }));
    assert!(facts.iter().all(|fact| {
        fact.candidate_id != "candidate:persisted:unrelated"
            || fact.fact_kind != bw_model::V326LifecycleFactKind::PersistedReturnedBorrow
    }));
    assert!(facts.iter().all(|fact| {
        fact.candidate_id != "candidate:persisted:unrelated"
            || fact.fact_kind != bw_model::V326LifecycleFactKind::ReturnedBorrowInvalidationOrder
    }));
    assert!(facts.iter().all(|fact| {
        fact.candidate_id != "candidate:persisted:field_name_storage"
            || fact.fact_kind != bw_model::V326LifecycleFactKind::PersistedReturnedBorrow
    }));
    assert!(facts.iter().all(|fact| {
        fact.candidate_id != "candidate:persisted:field_name_storage"
            || fact.fact_kind != bw_model::V326LifecycleFactKind::ReturnedBorrowInvalidationOrder
    }));

    let graph_dir = temp.path().join("lifecycle-graph");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates_dir.to_str().unwrap(),
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
            facts_path.to_str().unwrap(),
            "--output-dir",
            graph_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");
    let features = read_zst_features(&graph_dir.join("lifecycle-features.jsonl.zst"));
    let field_name_features = features
        .iter()
        .find(|feature| feature.candidate_id == "candidate:persisted:field_name")
        .unwrap();
    assert!(field_name_features.features.has_returned_borrow_relation);
    assert!(field_name_features.features.has_persisted_returned_borrow);
    assert!(
        field_name_features
            .features
            .returned_borrow_persistence_before_invalidation
    );
}

#[test]
fn extract_lifecycle_facts_match_source_api_alias_without_source_span() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("source-api-alias-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "source-api-alias-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("lib.rs"),
        r#"pub fn returned_borrow(owner: &i32) -> &i32 {
    owner
}

pub fn unrelated(owner: &i32) -> &i32 {
    owner
}
"#,
    )
    .unwrap();

    let returned_api = source_api_id("src/lib.rs", "returned_borrow");
    let unrelated_api = source_api_id("src/lib.rs", "unrelated");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:source-api-alias","crate_name":"source-api-alias-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:source-api-alias","boundary_id":"boundary:source-api:returned","boundary_kind":"callback_registration","api_path":"{returned_api}","evidence_refs":[{{"kind":"manifest","path":"Cargo.toml"}}],"confidence":"high","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:source-api-alias","boundary_id":"boundary:source-api:unrelated","boundary_kind":"callback_registration","api_path":"{unrelated_api}","evidence_refs":[{{"kind":"manifest","path":"Cargo.toml"}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:source-api:returned","crate_id":"crate:source-api-alias","boundary_id":"boundary:source-api:returned","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"manifest","path":"Cargo.toml"}}],"api_path":"{returned_api}","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:source-api:unrelated","crate_id":"crate:source-api-alias","boundary_id":"boundary:source-api:unrelated","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"manifest","path":"Cargo.toml"}}],"api_path":"{unrelated_api}","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &facts_path,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:source-api:returned","producer":"fixture","build_id":"build:source-api-alias","artifact":{"crate_id":"crate:source-api-alias","package_name":"source-api-alias-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":1,"line_end":1,"symbol_path":"scope_facts::returned_borrow"},"payload":{"kind":"returned_borrow_relation","site_id":"site:source-api:returned:relation","semantic_site_key":"source-api:returned","source_site_id":"site:source-api:returned:source","returned_site_id":"site:source-api:returned:returned","api_id":"scope_facts::returned_borrow"}}
{"schema_version":"bw.static/0.2","record_id":"static:source-api:unrelated","producer":"fixture","build_id":"build:source-api-alias","artifact":{"crate_id":"crate:source-api-alias","package_name":"source-api-alias-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":5,"line_end":5,"symbol_path":"scope_facts::unrelated"},"payload":{"kind":"returned_borrow_relation","site_id":"site:source-api:unrelated:relation","semantic_site_key":"source-api:unrelated","source_site_id":"site:source-api:unrelated:source","returned_site_id":"site:source-api:unrelated:returned","api_id":"scope_facts::unrelated"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&output_dir.join("lifecycle-facts.jsonl.zst"));
    assert_eq!(
        facts
            .iter()
            .filter(
                |fact| fact.provenance.origin == bw_model::V326LifecycleFactOrigin::StaticArtifact
            )
            .count(),
        2
    );
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:source-api:returned"
            && fact.fact_kind == bw_model::V326LifecycleFactKind::ReturnedBorrowRelation
            && fact.symbol_path.as_deref() == Some("scope_facts::returned_borrow")
            && fact.provenance.static_fact_record_id.as_deref()
                == Some("static:source-api:returned")
    }));
    assert!(facts.iter().any(|fact| {
        fact.candidate_id == "candidate:source-api:unrelated"
            && fact.fact_kind == bw_model::V326LifecycleFactKind::ReturnedBorrowRelation
            && fact.symbol_path.as_deref() == Some("scope_facts::unrelated")
            && fact.provenance.static_fact_record_id.as_deref()
                == Some("static:source-api:unrelated")
    }));
    assert!(facts.iter().all(|fact| {
        (fact.candidate_id == "candidate:source-api:returned"
            && fact.symbol_path.as_deref() != Some("scope_facts::unrelated"))
            || (fact.candidate_id == "candidate:source-api:unrelated"
                && fact.symbol_path.as_deref() != Some("scope_facts::returned_borrow"))
    }));
}

#[test]
fn emitted_static_lifecycle_candidates_are_consumed_by_extractor() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("neutral-candidates-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "neutral-candidates-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("lib.rs"),
        r#"pub struct BufferView {
    raw: *const u8,
}

pub fn borrowed_view(owner: &[u8]) -> &[u8] {
    owner
}

pub fn external_slice(source: &[u8]) -> BufferView {
    BufferView {
        raw: source.as_ptr(),
    }
}
"#,
    )
    .unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let static_facts = temp.path().join("static-facts.jsonl");
    let candidates_dir = temp.path().join("candidates-out");
    let evidence_dir = temp.path().join("lifecycle-evidence");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:neutral-candidates","crate_name":"neutral-candidates-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:neutral-candidates","boundary_id":"boundary:neutral:negative-summary","boundary_kind":"negative_summary","api_path":null,"evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"high","notes":["no supported boundary pattern found in scanned Rust sources"]}"#,
    )
    .unwrap();
    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:neutral:borrowed-view","producer":"fixture","build_id":"build:neutral-candidates","artifact":{"crate_id":"crate:neutral-candidates","package_name":"neutral-candidates-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":5,"line_end":5,"symbol_path":"neutral_candidates::borrowed_view"},"payload":{"kind":"returned_borrow_relation","site_id":"site:neutral:borrowed-view:relation","semantic_site_key":"neutral:borrowed-view","source_site_id":"site:neutral:borrowed-view:source","returned_site_id":"site:neutral:borrowed-view:returned","api_id":"neutral_candidates::borrowed_view"}}
{"schema_version":"bw.static/0.2","record_id":"static:neutral:external-slice","producer":"fixture","build_id":"build:neutral-candidates","artifact":{"crate_id":"crate:neutral-candidates","package_name":"neutral-candidates-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":9,"line_end":9,"symbol_path":"neutral_candidates::external_slice"},"payload":{"kind":"external_buffer_binding","site_id":"site:neutral:external-slice:binding","semantic_site_key":"neutral:external-slice","source_site_id":"site:neutral:external-slice:source","buffer_site_id":"site:neutral:external-slice:buffer","api_id":"neutral_candidates::external_slice"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""candidate_count":2"#).and(predicate::str::contains(
                r#""static_lifecycle_candidate_count":2"#,
            )),
        );

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-lifecycle-evidence",
            "--manifest",
            manifest.to_str().unwrap(),
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--candidates",
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            evidence_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&evidence_dir.join("lifecycle-facts.jsonl.zst"));
    let returned_candidates = facts
        .iter()
        .filter(|fact| fact.fact_kind == bw_model::V326LifecycleFactKind::ReturnedBorrowRelation)
        .map(|fact| fact.candidate_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let external_candidates = facts
        .iter()
        .filter(|fact| fact.fact_kind == bw_model::V326LifecycleFactKind::ExternalBufferBinding)
        .map(|fact| fact.candidate_id.clone())
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(returned_candidates.len(), 1);
    assert_eq!(external_candidates.len(), 1);
    assert!(returned_candidates.is_disjoint(&external_candidates));
}

#[test]
fn callback_user_data_reconstruction_static_fact_emits_retained_callback_candidate() {
    let temp = public_safe_tempdir();
    let boundary = temp.path().join("boundary.jsonl");
    let static_facts = temp.path().join("static-facts.jsonl");
    let candidates_dir = temp.path().join("candidates-out");

    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:callback-userdata","boundary_id":"boundary:callback-userdata:negative-summary","boundary_kind":"negative_summary","api_path":null,"evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"high","notes":["no supported boundary pattern found in scanned Rust sources"]}"#,
    )
    .unwrap();
    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:callback-userdata:stream-callback","producer":"fixture","build_id":"build:callback-userdata","artifact":{"crate_id":"crate:callback-userdata","package_name":"callback-userdata-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/stream.rs","line_start":42,"line_end":42,"symbol_path":"callback_userdata::stream_callback"},"payload":{"kind":"callback_user_data_reconstruction","site_id":"site:callback-userdata:reconstruct","semantic_site_key":"semantic:callback-userdata:reconstruct","callback_site_id":"site:callback-userdata:callback","user_data_site_id":"site:callback-userdata:user-data","object_site_id":"site:callback-userdata:stream-data","reconstruction_kind":"owner_from_transmute"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""candidate_count":1"#).and(predicate::str::contains(
                r#""static_lifecycle_candidate_count":1"#,
            )),
        );

    let candidates = read_zst_candidates(&candidates_dir.join("candidates/part-00000.jsonl.zst"));
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].pattern_family,
        bw_model::V32PatternFamily::RetainedBorrowedCallback
    );
    assert_eq!(
        candidates[0].api_path.as_deref(),
        Some("callback_userdata::stream_callback")
    );
    assert!(
        candidates[0]
            .notes
            .iter()
            .any(|note| note == "candidate is not a vulnerability conclusion")
    );
}

#[test]
fn callback_user_data_emitted_candidate_is_consumed_by_extractor() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("callback-userdata-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "callback-userdata-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("stream.rs"),
        r#"pub extern "C" fn stream_callback(user_data: *mut core::ffi::c_void) {
    let _ = user_data;
}
"#,
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub mod stream;\n").unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let static_facts = temp.path().join("static-facts.jsonl");
    let candidates_dir = temp.path().join("candidates-out");
    let evidence_dir = temp.path().join("lifecycle-evidence");

    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:callback-userdata","crate_name":"callback-userdata-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:callback-userdata","boundary_id":"boundary:callback-userdata:negative-summary","boundary_kind":"negative_summary","api_path":null,"evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"high","notes":["no supported boundary pattern found in scanned Rust sources"]}"#,
    )
    .unwrap();
    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:callback-userdata:stream-callback","producer":"fixture","build_id":"build:callback-userdata","artifact":{"crate_id":"crate:callback-userdata","package_name":"callback-userdata-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/stream.rs","line_start":2,"line_end":2,"symbol_path":"callback_userdata::stream_callback"},"payload":{"kind":"callback_user_data_reconstruction","site_id":"site:callback-userdata:reconstruct","semantic_site_key":"semantic:callback-userdata:reconstruct","callback_site_id":"site:callback-userdata:callback","user_data_site_id":"site:callback-userdata:user-data","object_site_id":"site:callback-userdata:stream-data","reconstruction_kind":"owner_from_transmute"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-lifecycle-evidence",
            "--manifest",
            manifest.to_str().unwrap(),
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--candidates",
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            evidence_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let candidates = read_zst_candidates(&candidates_dir.join("candidates/part-00000.jsonl.zst"));
    let facts = read_zst_facts(&evidence_dir.join("lifecycle-facts.jsonl.zst"));
    let callback_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == bw_model::V326LifecycleFactKind::CallbackUserDataReconstruction
        })
        .collect::<Vec<_>>();

    assert_eq!(candidates.len(), 1);
    assert_eq!(callback_facts.len(), 1);
    assert_eq!(callback_facts[0].candidate_id, candidates[0].candidate_id);
    assert_eq!(
        callback_facts[0].symbol_path.as_deref(),
        Some("callback_user_data_reconstruction::owner_from_transmute")
    );
}

#[test]
fn callback_user_data_static_candidate_keeps_fact_with_nearby_legacy_candidate() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("callback-userdata-overlap-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "callback-userdata-overlap-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"pub extern "C" fn stream_callback(user_data: *mut core::ffi::c_void) {
    let _ = unsafe { core::mem::transmute::<*mut core::ffi::c_void, &mut StreamData>(user_data) };
}

pub struct StreamData;
"#;
    fs::write(src_dir.join("stream.rs"), source).unwrap();
    fs::write(src_dir.join("lib.rs"), "pub mod stream;\n").unwrap();

    let callback_line = line_number(source, "core::mem::transmute");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let evidence_dir = temp.path().join("lifecycle-evidence");
    let graph_dir = temp.path().join("lifecycle-v3");
    let static_facts = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();

    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:callback-userdata-overlap","crate_name":"callback-userdata-overlap-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:callback-userdata-overlap","boundary_id":"boundary:legacy:001","boundary_kind":"callback_registration","api_path":"callback_userdata::legacy_wrapper","evidence_refs":[{{"kind":"source_span","path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line}}}],"confidence":"medium","notes":["synthetic legacy boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:callback-userdata-overlap","boundary_id":"boundary:callback-userdata:001","boundary_kind":"callback_registration","api_path":"callback_userdata::stream_callback","evidence_refs":[{{"kind":"source_span","path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line}}}],"confidence":"medium","notes":["synthetic static lifecycle boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:aaa:legacy","crate_id":"crate:callback-userdata-overlap","boundary_id":"boundary:legacy:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line}}}],"api_path":"callback_userdata::legacy_wrapper","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic legacy candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:callback-userdata:stream-callback","crate_id":"crate:callback-userdata-overlap","boundary_id":"boundary:callback-userdata:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line}}}],"api_path":"callback_userdata::stream_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic static lifecycle candidate"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &static_facts,
        format!(
            r#"{{"schema_version":"bw.static/0.2","record_id":"static:callback-userdata:stream-callback","producer":"fixture","build_id":"build:callback-userdata","artifact":{{"crate_id":"crate:callback-userdata-overlap","package_name":"callback-userdata-overlap-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line},"symbol_path":"callback_userdata::stream_callback"}},"payload":{{"kind":"callback_user_data_reconstruction","site_id":"site:callback-userdata:reconstruct","semantic_site_key":"semantic:callback-userdata:reconstruct","callback_site_id":"site:callback-userdata:callback","user_data_site_id":"site:callback-userdata:user-data","object_site_id":"site:callback-userdata:stream-data","reconstruction_kind":"owner_from_transmute"}}}}
{{"schema_version":"bw.static/0.2","record_id":"static:callback-userdata:register-flow","producer":"fixture","build_id":"build:callback-userdata","artifact":{{"crate_id":"crate:callback-userdata-overlap","package_name":"callback-userdata-overlap-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line},"symbol_path":"callback_userdata::stream_callback"}},"payload":{{"kind":"object_flow","site_id":"site:callback-userdata:register-flow","semantic_site_key":"semantic:callback-userdata:register-flow","from_site_id":"site:callback-userdata:user-data","from_object_kind":"user_data","to_site_id":"site:callback-userdata:registered-handle","to_object_kind":"opaque_handle","flow_kind":"field_store","api_id":"callback_userdata::stream_callback","field_path":"callback_user_data:callback_userdata::stream_callback:stream_callback"}}}}
{{"schema_version":"bw.static/0.2","record_id":"static:callback-userdata:callback-flow","producer":"fixture","build_id":"build:callback-userdata","artifact":{{"crate_id":"crate:callback-userdata-overlap","package_name":"callback-userdata-overlap-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line},"symbol_path":"callback_userdata::stream_callback"}},"payload":{{"kind":"object_flow","site_id":"site:callback-userdata:callback-flow","semantic_site_key":"semantic:callback-userdata:callback-flow","from_site_id":"site:callback-userdata:registered-handle","from_object_kind":"opaque_handle","to_site_id":"site:callback-userdata:callback-userdata","to_object_kind":"user_data","flow_kind":"field_load","api_id":"callback_userdata::stream_callback","field_path":"callback_user_data:callback_userdata::stream_callback:stream_callback"}}}}"#
        ),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-lifecycle-evidence",
            "--manifest",
            manifest.to_str().unwrap(),
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--candidates",
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            evidence_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&evidence_dir.join("lifecycle-facts.jsonl.zst"));
    let callback_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == bw_model::V326LifecycleFactKind::CallbackUserDataReconstruction
        })
        .collect::<Vec<_>>();

    assert_eq!(callback_facts.len(), 1);
    assert_eq!(
        callback_facts[0].candidate_id,
        "candidate:callback-userdata:stream-callback"
    );

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates_dir.to_str().unwrap(),
            "--evidence",
            evidence_dir
                .join("lifecycle-evidence.jsonl.zst")
                .to_str()
                .unwrap(),
            "--facts",
            evidence_dir
                .join("lifecycle-facts.jsonl.zst")
                .to_str()
                .unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            graph_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let features = read_zst_features(&graph_dir.join("lifecycle-features.jsonl.zst"));
    let static_candidate_features = features
        .iter()
        .find(|feature| feature.candidate_id == "candidate:callback-userdata:stream-callback")
        .unwrap();
    let legacy_features = features
        .iter()
        .find(|feature| feature.candidate_id == "candidate:aaa:legacy")
        .unwrap();

    assert!(
        static_candidate_features
            .features
            .callback_user_data_owner_reconstruction_without_leak_guard
    );
    assert!(
        !legacy_features
            .features
            .callback_user_data_owner_reconstruction_without_leak_guard
    );
}

#[test]
fn callback_user_data_static_fact_survives_duplicate_same_api_claimant() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("callback-userdata-duplicate-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "callback-userdata-duplicate-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"pub extern "C" fn stream_callback(user_data: *mut core::ffi::c_void) {
    let _ = unsafe { core::mem::transmute::<*mut core::ffi::c_void, &mut StreamData>(user_data) };
}

pub struct StreamData;
"#;
    fs::write(src_dir.join("stream.rs"), source).unwrap();
    fs::write(src_dir.join("lib.rs"), "pub mod stream;\n").unwrap();

    let callback_line = line_number(source, "core::mem::transmute");
    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let evidence_dir = temp.path().join("lifecycle-evidence");
    let static_facts = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();

    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:callback-userdata-duplicate","crate_name":"callback-userdata-duplicate-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:callback-userdata-duplicate","boundary_id":"boundary:legacy:duplicate","boundary_kind":"callback_registration","api_path":"callback_userdata::stream_callback","evidence_refs":[{{"kind":"source_span","path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line}}}],"confidence":"medium","notes":["synthetic duplicate boundary"]}}"#
        ),
    )
    .unwrap();
    let static_boundary_identity = format!(
        "crate:callback-userdata-duplicate:src/stream.rs:{callback_line}:callback_userdata::stream_callback"
    );
    let static_boundary_suffix = hex_digest(Sha256::digest(static_boundary_identity.as_bytes()));
    let static_boundary_id = format!(
        "boundary:crate_callback-userdata-duplicate:callback-registration:{}",
        &static_boundary_suffix[..16]
    );
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:legacy:same-api","crate_id":"crate:callback-userdata-duplicate","boundary_id":"boundary:legacy:duplicate","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line}}}],"api_path":"callback_userdata::stream_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic pre-existing candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:callback-userdata:static-bridge","crate_id":"crate:callback-userdata-duplicate","boundary_id":"{static_boundary_id}","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line}}}],"api_path":"callback_userdata::stream_callback","recommended_next_step":"generate_lifecycle_subgraph","notes":["candidate emitted from authoritative lifecycle static fact"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &static_facts,
        format!(
            r#"{{"schema_version":"bw.static/0.2","record_id":"fact:callback_user_data_reconstruction:stream_callback","producer":"bw-rustc","build_id":"build:callback-userdata-duplicate","artifact":{{"crate_id":"crate:callback-userdata-duplicate","package_name":"callback-userdata-duplicate-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/stream.rs","line_start":{callback_line},"line_end":{callback_line},"symbol_path":"callback_userdata::stream_callback"}},"payload":{{"kind":"callback_user_data_reconstruction","site_id":"site:callback_user_data_reconstruction:reconstruct","semantic_site_key":"semantic:callback_user_data_reconstruction:reconstruct","callback_site_id":"site:callback_user_data_reconstruction:callback","user_data_site_id":"site:callback_user_data_reconstruction:user_data","object_site_id":"site:callback_user_data_reconstruction:stream_data","reconstruction_kind":"owner_from_transmute"}}}}"#
        ),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-lifecycle-evidence",
            "--manifest",
            manifest.to_str().unwrap(),
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--candidates",
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            evidence_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&evidence_dir.join("lifecycle-facts.jsonl.zst"));
    let callback_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == bw_model::V326LifecycleFactKind::CallbackUserDataReconstruction
        })
        .collect::<Vec<_>>();

    assert_eq!(callback_facts.len(), 1);
    assert_eq!(
        callback_facts[0].candidate_id,
        "candidate:callback-userdata:static-bridge"
    );
}

#[test]
fn persisted_returned_borrow_static_fact_emits_candidate_and_filters_std_adapter() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("persisted-candidate-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "persisted-candidate-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("lib.rs"),
        r#"pub mod stmt {
    pub struct StatementUse;

    impl StatementUse {
        pub fn field_name(owner: &str) -> &str {
            owner
        }
    }
}

pub fn collect_field_name(owner: &str) -> Vec<&str> {
    vec![stmt::StatementUse::field_name(owner)]
}
"#,
    )
    .unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let static_facts = temp.path().join("static-facts.jsonl");
    let candidates_dir = temp.path().join("candidates-out");
    let evidence_dir = temp.path().join("lifecycle-evidence");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:persisted-candidate","crate_name":"persisted-candidate-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:persisted-candidate","boundary_id":"boundary:persisted-candidate:negative-summary","boundary_kind":"negative_summary","api_path":null,"evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"high","notes":["no supported boundary pattern found in scanned Rust sources"]}"#,
    )
    .unwrap();
    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:persisted-candidate:field-name","producer":"fixture","build_id":"build:persisted-candidate","artifact":{"crate_id":"crate:persisted-candidate","package_name":"persisted-candidate-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"persisted_candidate::collect_field_name"},"payload":{"kind":"persisted_returned_borrow","site_id":"site:persisted-candidate:field-name","semantic_site_key":"semantic:persisted-candidate:field-name","source_site_id":"site:persisted-candidate:source","returned_site_id":"site:persisted-candidate:returned","storage_site_id":"site:persisted-candidate:storage","api_id":"persisted_candidate::stmt::StatementUse::field_name"}}
{"schema_version":"bw.static/0.2","record_id":"static:persisted-candidate:std-index","producer":"fixture","build_id":"build:persisted-candidate","artifact":{"crate_id":"crate:persisted-candidate","package_name":"persisted-candidate-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"persisted_candidate::collect_field_name"},"payload":{"kind":"persisted_returned_borrow","site_id":"site:persisted-candidate:std-index","semantic_site_key":"semantic:persisted-candidate:std-index","source_site_id":"site:persisted-candidate:std-source","returned_site_id":"site:persisted-candidate:std-returned","storage_site_id":"site:persisted-candidate:std-storage","api_id":"std::ops::Index::index"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""candidate_count":1"#).and(predicate::str::contains(
                r#""static_lifecycle_candidate_count":1"#,
            )),
        );

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-lifecycle-evidence",
            "--manifest",
            manifest.to_str().unwrap(),
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--candidates",
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            evidence_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&evidence_dir.join("lifecycle-facts.jsonl.zst"));
    assert_eq!(
        facts
            .iter()
            .filter(|fact| {
                fact.fact_kind == bw_model::V326LifecycleFactKind::PersistedReturnedBorrow
            })
            .count(),
        1
    );
    assert!(facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::PersistedReturnedBorrow
            && fact.symbol_path.as_deref()
                == Some("persisted_candidate::stmt::StatementUse::field_name")
            && fact.provenance.static_fact_record_id.as_deref()
                == Some("static:persisted-candidate:field-name")
    }));
}

#[test]
fn emitted_raw_pointer_registration_candidate_is_consumed_by_extractor() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("retained-user-data-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "retained-user-data-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("lib.rs"),
        r#"pub fn set_ex_data<T>(data: T) {
    let boxed = Box::new(data);
    let pointer = Box::into_raw(boxed);
    unsafe {
        ffi_set_ex_data(pointer);
    }
}

pub struct ContextBuilder;

impl ContextBuilder {
    pub fn set_ex_data_inner<T>(&mut self, data: T) {
        let boxed = Box::new(data);
        let pointer = Box::into_raw(boxed);
        unsafe {
            ffi_ctx_set_ex_data(pointer);
        }
    }
}
"#,
    )
    .unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let static_facts = temp.path().join("static-facts.jsonl");
    let candidates_dir = temp.path().join("candidates-out");
    let evidence_dir = temp.path().join("lifecycle-evidence");
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:retained-user-data","crate_name":"retained-user-data-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:retained-user-data","boundary_id":"boundary:retained-user-data:negative-summary","boundary_kind":"negative_summary","api_path":null,"evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"high","notes":["no supported boundary pattern found in scanned Rust sources"]}"#,
    )
    .unwrap();
    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:retained-user-data:raw","producer":"fixture","build_id":"build:retained-user-data","artifact":{"crate_id":"crate:retained-user-data","package_name":"retained-user-data-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":3,"line_end":3,"symbol_path":"retained_user_data::set_ex_data"},"payload":{"kind":"raw_pointer_transfer","site_id":"site:retained-user-data:raw","semantic_site_key":"semantic:retained-user-data:raw","user_data_site_id":"site:retained-user-data:user-data","transfer_kind":"into_raw"}}
{"schema_version":"bw.static/0.2","record_id":"static:retained-user-data:register","producer":"fixture","build_id":"build:retained-user-data","artifact":{"crate_id":"crate:retained-user-data","package_name":"retained-user-data-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":5,"line_end":5,"symbol_path":"retained_user_data::set_ex_data"},"payload":{"kind":"registration_site","site_id":"site:retained-user-data:register","semantic_site_key":"semantic:retained-user-data:register","callback_site_id":null,"user_data_site_id":"site:retained-user-data:user-data","api_id":"api:openssl:ssl_set_ex_data:register","role":"register"}}
{"schema_version":"bw.static/0.2","record_id":"static:retained-user-data:ctx-raw","producer":"fixture","build_id":"build:retained-user-data","artifact":{"crate_id":"crate:retained-user-data","package_name":"retained-user-data-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":12,"line_end":12,"symbol_path":"retained_user_data::ContextBuilder::set_ex_data_inner"},"payload":{"kind":"raw_pointer_transfer","site_id":"site:retained-user-data:ctx-raw","semantic_site_key":"semantic:retained-user-data:ctx-raw","user_data_site_id":"site:retained-user-data:ctx-user-data","transfer_kind":"into_raw"}}
{"schema_version":"bw.static/0.2","record_id":"static:retained-user-data:ctx-register","producer":"fixture","build_id":"build:retained-user-data","artifact":{"crate_id":"crate:retained-user-data","package_name":"retained-user-data-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":14,"line_end":14,"symbol_path":"retained_user_data::ContextBuilder::set_ex_data_inner"},"payload":{"kind":"registration_site","site_id":"site:retained-user-data:ctx-register","semantic_site_key":"semantic:retained-user-data:ctx-register","callback_site_id":null,"user_data_site_id":"site:retained-user-data:ctx-user-data","api_id":"api:openssl:ssl_ctx_set_ex_data:register","role":"register"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""candidate_count":2"#).and(predicate::str::contains(
                r#""static_lifecycle_candidate_count":2"#,
            )),
        );

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-lifecycle-evidence",
            "--manifest",
            manifest.to_str().unwrap(),
            "--boundary-index",
            boundary.to_str().unwrap(),
            "--candidates",
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            static_facts.to_str().unwrap(),
            "--output-dir",
            evidence_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let facts = read_zst_facts(&evidence_dir.join("lifecycle-facts.jsonl.zst"));
    assert!(facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::RegisterCall
            && fact.symbol_path.as_deref() == Some("api:openssl:ssl_set_ex_data:register")
    }));
    assert!(facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::RegisterCall
            && fact.symbol_path.as_deref() == Some("api:openssl:ssl_ctx_set_ex_data:register")
    }));
    assert!(facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::RawPointerEscape
            && fact.provenance.static_fact_record_id.as_deref()
                == Some("static:retained-user-data:raw")
    }));
    assert!(facts.iter().any(|fact| {
        fact.fact_kind == bw_model::V326LifecycleFactKind::RawPointerEscape
            && fact.provenance.static_fact_record_id.as_deref()
                == Some("static:retained-user-data:ctx-raw")
    }));
}

#[test]
fn emit_candidates_does_not_duplicate_static_registration_when_boundary_already_covers_span() {
    let temp = public_safe_tempdir();
    let boundary = temp.path().join("boundary.jsonl");
    let static_facts = temp.path().join("static-facts.jsonl");
    let candidates_dir = temp.path().join("candidates-out");
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:retained-user-data","boundary_id":"boundary:retained-user-data:source","boundary_kind":"callback_registration","api_path":"retained_user_data::set_ex_data","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":5,"line_end":5}],"confidence":"medium","notes":["synthetic source boundary"]}"#,
    )
    .unwrap();
    fs::write(
        &static_facts,
        r#"{"schema_version":"bw.static/0.2","record_id":"static:retained-user-data:register","producer":"fixture","build_id":"build:retained-user-data","artifact":{"crate_id":"crate:retained-user-data","package_name":"retained-user-data-crate","package_version":"0.1.0","target":"lib"},"source_ref":{"path":"src/lib.rs","line_start":5,"line_end":8,"symbol_path":"retained_user_data::set_ex_data"},"payload":{"kind":"registration_site","site_id":"site:retained-user-data:register","semantic_site_key":"semantic:retained-user-data:register","callback_site_id":null,"user_data_site_id":"site:retained-user-data:user-data","api_id":"api:openssl:ssl_set_ex_data:register","role":"register"}}"#,
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
            candidates_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(
            predicate::str::contains(r#""candidate_count":1"#).and(predicate::str::contains(
                r#""static_lifecycle_candidate_count":0"#,
            )),
        );
}

#[test]
fn extract_lifecycle_evidence_binds_static_lifetime_bound_from_selected_fact_signature() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("signature-bound-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "signature-bound-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

pub fn register_alpha<F>(
    hook: Option<F>,
)
where
    F: FnMut(i32) + Send + 'static,
{
    let holder = Box::new(hook);
    let raw = Box::into_raw(holder) as *mut c_void;
    let _pad_01 = raw.is_null();
    let _pad_02 = _pad_01;
    let _pad_03 = _pad_02;
    let _pad_04 = _pad_03;
    let _pad_05 = _pad_04;
    unsafe {
        ffi_set_alpha_hook(Some(alpha_trampoline::<F>), raw);
    }
}

pub fn register_beta<F>(
    hook: Option<F>,
)
where
    F: FnMut(i32) + Send,
{
    let holder = Box::new(hook);
    let raw = Box::into_raw(holder) as *mut c_void;
    unsafe {
        ffi_set_beta_hook(Some(beta_trampoline::<F>), raw);
    }
}

unsafe extern "C" fn alpha_trampoline<F>(_user_data: *mut c_void) {}
unsafe extern "C" fn beta_trampoline<F>(_user_data: *mut c_void) {}
unsafe fn ffi_set_alpha_hook<F>(_cb: Option<unsafe extern "C" fn(*mut c_void)>, _user_data: *mut c_void) {}
unsafe fn ffi_set_beta_hook<F>(_cb: Option<unsafe extern "C" fn(*mut c_void)>, _user_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();
    let alpha_static_bound_line = line_number(source, "F: FnMut(i32) + Send + 'static");
    let alpha_register_line = line_number(source, "ffi_set_alpha_hook(Some");
    let beta_register_line = line_number(source, "ffi_set_beta_hook(Some");
    assert!(
        alpha_register_line > alpha_static_bound_line + 3,
        "test fixture must keep the signature bound outside the normal source radius"
    );

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:signature-bound","crate_name":"signature-bound-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:signature-bound","boundary_id":"boundary:alpha:001","boundary_kind":"callback_registration","api_path":"lifetime_scope::register_alpha","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_register_line},"line_end":{alpha_register_line}}}],"confidence":"high","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:signature-bound","boundary_id":"boundary:beta:001","boundary_kind":"callback_registration","api_path":"lifetime_scope::register_beta","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_register_line},"line_end":{beta_register_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:signature","crate_id":"crate:signature-bound","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_register_line},"line_end":{alpha_register_line}}}],"api_path":"lifetime_scope::register_alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:signature","crate_id":"crate:signature-bound","boundary_id":"boundary:beta:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_register_line},"line_end":{beta_register_line}}}],"api_path":"lifetime_scope::register_beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &facts_path,
        format!(
            r#"{{"schema_version":"bw.static/0.2","record_id":"static:alpha:register","producer":"fixture","build_id":"build:fixture","artifact":{{"crate_id":"crate:signature-bound","package_name":"signature-bound-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{alpha_register_line},"line_end":{alpha_register_line},"symbol_path":"lifetime_scope::register_alpha"}},"payload":{{"kind":"registration_site","site_id":"registration:alpha","semantic_site_key":"signature-bound:alpha","callback_site_id":"callback:alpha","user_data_site_id":"user_data:alpha","api_id":"lifetime_scope::register_alpha","role":"register"}}}}
{{"schema_version":"bw.static/0.2","record_id":"static:beta:register","producer":"fixture","build_id":"build:fixture","artifact":{{"crate_id":"crate:signature-bound","package_name":"signature-bound-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{beta_register_line},"line_end":{beta_register_line},"symbol_path":"lifetime_scope::register_beta"}},"payload":{{"kind":"registration_site","site_id":"registration:beta","semantic_site_key":"signature-bound:beta","callback_site_id":"callback:beta","user_data_site_id":"user_data:beta","api_id":"lifetime_scope::register_beta","role":"register"}}}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let evidence = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    let alpha_lifetime_bounds = evidence
        .iter()
        .filter(|record| {
            record.candidate_id == "candidate:alpha:signature"
                && record.evidence_kind == bw_model::V326EvidenceKind::LifetimeBound
        })
        .collect::<Vec<_>>();
    assert_eq!(alpha_lifetime_bounds.len(), 1);
    assert_eq!(
        alpha_lifetime_bounds[0].source_ref.line_start,
        Some(alpha_static_bound_line)
    );
    assert!(
        evidence.iter().all(|record| {
            record.candidate_id != "candidate:beta:signature"
                || record.evidence_kind != bw_model::V326EvidenceKind::LifetimeBound
        }),
        "signature lifetime evidence must stay bound to the selected candidate scope"
    );
}

#[test]
fn extract_lifecycle_evidence_binds_external_buffer_static_lifetime_signature() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("external-buffer-bound-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "external-buffer-bound-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"pub struct ExternalBuffer;

pub fn external_alpha<T>(data: T) -> ExternalBuffer
where
    T: AsMut<[u8]> + Send + 'static,
{
    let _pad_01 = 1;
    let _pad_02 = _pad_01;
    let _pad_03 = _pad_02;
    let _pad_04 = _pad_03;
    create_external(data) // alpha external
}

pub fn external_beta<T>(data: T) -> ExternalBuffer
where
    T: AsMut<[u8]> + Send,
{
    create_external(data) // beta external
}

fn create_external<T>(_data: T) -> ExternalBuffer
where
    T: AsMut<[u8]> + Send,
{
    ExternalBuffer
}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();
    let alpha_static_bound_line = line_number(source, "T: AsMut<[u8]> + Send + 'static");
    let alpha_external_line = line_number(source, "create_external(data) // alpha external");
    let beta_external_line = line_number(source, "create_external(data) // beta external");
    assert!(
        alpha_external_line > alpha_static_bound_line + 3,
        "test fixture must keep the signature bound outside the normal source radius"
    );

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:external-buffer-bound","crate_name":"external-buffer-bound-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["ffi_dependency"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:external-buffer-bound","boundary_id":"boundary:external:alpha","boundary_kind":"external_buffer","api_path":"external_buffer_bound::external_alpha","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_external_line},"line_end":{alpha_external_line}}}],"confidence":"high","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:external-buffer-bound","boundary_id":"boundary:external:beta","boundary_kind":"external_buffer","api_path":"external_buffer_bound::external_beta","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_external_line},"line_end":{beta_external_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:external:alpha","crate_id":"crate:external-buffer-bound","boundary_id":"boundary:external:alpha","pattern_family":"external_buffer_view","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{alpha_external_line},"line_end":{alpha_external_line}}}],"api_path":"external_buffer_bound::external_alpha","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:external:beta","crate_id":"crate:external-buffer-bound","boundary_id":"boundary:external:beta","pattern_family":"external_buffer_view","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{beta_external_line},"line_end":{beta_external_line}}}],"api_path":"external_buffer_bound::external_beta","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &facts_path,
        format!(
            r#"{{"schema_version":"bw.static/0.2","record_id":"static:external:alpha","producer":"fixture","build_id":"build:external-buffer","artifact":{{"crate_id":"crate:external-buffer-bound","package_name":"external-buffer-bound-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{alpha_external_line},"line_end":{alpha_external_line},"symbol_path":"external_buffer_bound::external_alpha"}},"payload":{{"kind":"external_buffer_binding","site_id":"site:external:alpha","semantic_site_key":"semantic:external:alpha","source_site_id":"site:external:alpha:source","buffer_site_id":"site:external:alpha:buffer","api_id":"external_buffer_bound::external_alpha"}}}}
{{"schema_version":"bw.static/0.2","record_id":"static:external:beta","producer":"fixture","build_id":"build:external-buffer","artifact":{{"crate_id":"crate:external-buffer-bound","package_name":"external-buffer-bound-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{beta_external_line},"line_end":{beta_external_line},"symbol_path":"external_buffer_bound::external_beta"}},"payload":{{"kind":"external_buffer_binding","site_id":"site:external:beta","semantic_site_key":"semantic:external:beta","source_site_id":"site:external:beta:source","buffer_site_id":"site:external:beta:buffer","api_id":"external_buffer_bound::external_beta"}}}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let evidence = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    let alpha_lifetime_bounds = evidence
        .iter()
        .filter(|record| {
            record.candidate_id == "candidate:external:alpha"
                && record.evidence_kind == bw_model::V326EvidenceKind::LifetimeBound
        })
        .collect::<Vec<_>>();
    assert_eq!(alpha_lifetime_bounds.len(), 1);
    assert_eq!(
        alpha_lifetime_bounds[0].source_ref.line_start,
        Some(alpha_static_bound_line)
    );
    assert!(
        evidence.iter().all(|record| {
            record.candidate_id != "candidate:external:beta"
                || record.evidence_kind != bw_model::V326EvidenceKind::LifetimeBound
        }),
        "external-buffer signature lifetime evidence must stay scoped to the selected fact"
    );
}

#[test]
fn extract_lifecycle_evidence_binds_selector_return_lifetime_to_all_inputs() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("selector-bound-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "selector-bound-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"pub fn select_unbound<'a>(
    server: &[u8],
    client: &'a [u8],
) -> Option<&'a [u8]> { // selector signature loose
    let _ = (server.as_ptr(), client.as_ptr());
    foreign_select(server, client) // unbound selector call
}

pub fn select_bound<'a>(
    server: &'a [u8],
    client: &'a [u8],
) -> Option<&'a [u8]> { // selector signature tied
    let _ = (server.as_ptr(), client.as_ptr());
    foreign_select(server, client) // bound selector call
}

fn foreign_select<'a>(_server: &'a [u8], client: &'a [u8]) -> Option<&'a [u8]> {
    Some(client)
}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();
    let unbound_signature_line = line_number(source, "selector signature loose");
    let bound_signature_line = line_number(source, "selector signature tied");
    let unbound_call_line = line_number(source, "foreign_select(server, client) // unbound");
    let bound_call_line = line_number(source, "foreign_select(server, client) // bound");

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let facts_path = temp.path().join("static-facts.jsonl");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:selector-bound","crate_name":"selector-bound-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["ffi_dependency"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:selector-bound","boundary_id":"boundary:selector:unbound","boundary_kind":"external_buffer","api_path":"selector_bound::select_unbound","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{unbound_call_line},"line_end":{unbound_call_line}}}],"confidence":"high","notes":["synthetic boundary"]}}
{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:selector-bound","boundary_id":"boundary:selector:bound","boundary_kind":"external_buffer","api_path":"selector_bound::select_bound","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{bound_call_line},"line_end":{bound_call_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:selector:unbound","crate_id":"crate:selector-bound","boundary_id":"boundary:selector:unbound","pattern_family":"external_buffer_view","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{unbound_call_line},"line_end":{unbound_call_line}}}],"api_path":"selector_bound::select_unbound","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}
{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:selector:bound","crate_id":"crate:selector-bound","boundary_id":"boundary:selector:bound","pattern_family":"external_buffer_view","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{bound_call_line},"line_end":{bound_call_line}}}],"api_path":"selector_bound::select_bound","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &facts_path,
        format!(
            r#"{{"schema_version":"bw.static/0.2","record_id":"static:selector:unbound","producer":"fixture","build_id":"build:selector","artifact":{{"crate_id":"crate:selector-bound","package_name":"selector-bound-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{unbound_call_line},"line_end":{unbound_call_line},"symbol_path":"selector_bound::select_unbound"}},"payload":{{"kind":"external_buffer_binding","site_id":"site:selector:unbound","semantic_site_key":"semantic:selector:unbound","source_site_id":"site:selector:unbound:source","buffer_site_id":"site:selector:unbound:buffer","api_id":"selector_bound::select_unbound"}}}}
{{"schema_version":"bw.static/0.2","record_id":"static:selector:bound","producer":"fixture","build_id":"build:selector","artifact":{{"crate_id":"crate:selector-bound","package_name":"selector-bound-crate","package_version":"0.1.0","target":"lib"}},"source_ref":{{"path":"src/lib.rs","line_start":{bound_call_line},"line_end":{bound_call_line},"symbol_path":"selector_bound::select_bound"}},"payload":{{"kind":"external_buffer_binding","site_id":"site:selector:bound","semantic_site_key":"semantic:selector:bound","source_site_id":"site:selector:bound:source","buffer_site_id":"site:selector:bound:buffer","api_id":"selector_bound::select_bound"}}}}"#
        ),
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
            candidates_dir.to_str().unwrap(),
            "--static-facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let evidence = read_zst_evidence(&output_dir.join("lifecycle-evidence.jsonl.zst"));
    let bound_lifetime_bounds = evidence
        .iter()
        .filter(|record| {
            record.candidate_id == "candidate:selector:bound"
                && record.evidence_kind == bw_model::V326EvidenceKind::LifetimeBound
        })
        .collect::<Vec<_>>();
    assert_eq!(bound_lifetime_bounds.len(), 1);
    assert_eq!(
        bound_lifetime_bounds[0].source_ref.line_start,
        Some(bound_signature_line)
    );
    assert_eq!(
        bound_lifetime_bounds[0].details["signal"],
        "return lifetime covers external buffer inputs"
    );
    assert!(
        evidence.iter().all(|record| {
            record.candidate_id != "candidate:selector:unbound"
                || record.evidence_kind != bw_model::V326EvidenceKind::LifetimeBound
        }),
        "unbound selector signature must not receive return-lifetime coverage evidence"
    );
    assert!(
        unbound_signature_line != bound_signature_line,
        "test fixture must keep selector signatures distinct"
    );
}

#[test]
fn extract_lifecycle_coverage_maps_mir_coverage_seen_and_skipped_bodies() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("mir-coverage-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "mir-coverage-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    let source = r#"use std::ffi::c_void;

pub fn register_fact() {
    set_fact_hook(Some(fact_callback), std::ptr::null_mut::<c_void>());
}

fn set_fact_hook(_cb: Option<extern "C" fn(*mut c_void)>, _user_data: *mut c_void) {}
extern "C" fn fact_callback(_user_data: *mut c_void) {}
"#;
    fs::write(src_dir.join("lib.rs"), source).unwrap();
    let register_line = line_number(source, "set_fact_hook(Some");

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let mir_coverage = temp.path().join("mir-coverage.json");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:mir-coverage","crate_name":"mir-coverage-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        format!(
            r#"{{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:mir-coverage","boundary_id":"boundary:mir:001","boundary_kind":"callback_registration","api_path":"mir_coverage::register_fact","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{register_line},"line_end":{register_line}}}],"confidence":"high","notes":["synthetic boundary"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:mir:001","crate_id":"crate:mir-coverage","boundary_id":"boundary:mir:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":{register_line},"line_end":{register_line}}}],"api_path":"mir_coverage::register_fact","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &mir_coverage,
        r#"{"schema_version":"bw.mir-coverage/0.1","expected_packages":[{"name":"mir-coverage-crate","version":"0.1.0"}],"seen_packages":[{"name":"mir-coverage-crate","version":"0.1.0"}],"seen_targets":[{"package":"mir-coverage-crate","version":"0.1.0","target":"lib"}],"seen_bodies":[{"package":"mir-coverage-crate","version":"0.1.0","target":"lib","def_path":"mir_coverage::register_fact"}],"skipped":[{"package":"mir-coverage-crate","version":"0.1.0","target":"lib","def_path":"mir_coverage::register_fact","reason":"macro_expansion"}]}"#,
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
            candidates_dir.to_str().unwrap(),
            "--mir-coverage",
            mir_coverage.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let coverage = read_zst_coverage(&output_dir.join("lifecycle-coverage.jsonl.zst"));
    assert_eq!(coverage.len(), 1);
    assert!(
        coverage[0]
            .covered_function_bodies
            .contains(&"mir_coverage::register_fact".to_owned())
    );
    assert!(
        coverage[0]
            .unavailable_paths
            .iter()
            .any(|gap| gap.path == "mir_coverage::register_fact"
                && gap.reason == bw_model::V326CoverageGapReason::MacroExpansion)
    );
}

#[test]
fn extract_lifecycle_coverage_requires_exact_api_for_mir_bodies() {
    let temp = public_safe_tempdir();
    let crate_dir = temp.path().join("mir-tail-crate");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "mir-tail-crate"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn placeholder() {}\n").unwrap();

    let manifest = temp.path().join("corpus.jsonl");
    let boundary = temp.path().join("boundary.jsonl");
    let candidates_dir = temp.path().join("candidates");
    let mir_coverage = temp.path().join("mir-coverage.json");
    fs::create_dir_all(&candidates_dir).unwrap();
    fs::write(
        &manifest,
        format!(
            r#"{{"schema_version":"v3.2.corpus_manifest.1","corpus_id":"corpus:v326","crate_id":"crate:mir-tail","crate_name":"mir-tail-crate","version":"0.1.0","source_kind":"local_archive","source_ref":"{}","selection_reason":["callback_api_candidate"],"intake_status":"accepted","intake_notes":[]}}"#,
            crate_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &boundary,
        r#"{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:mir-tail","boundary_id":"boundary:alpha:001","boundary_kind":"callback_registration","api_path":"alpha_component::register","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"medium","notes":["synthetic boundary without source span"]}
{"schema_version":"v3.2.boundary_index.1","run_id":"run:v326","crate_id":"crate:mir-tail","boundary_id":"boundary:beta:001","boundary_kind":"callback_registration","api_path":"beta_component::register","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"confidence":"medium","notes":["synthetic boundary without source span"]}"#,
    )
    .unwrap();
    fs::write(
        candidates_dir.join("part-00000.jsonl"),
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:mir-tail","boundary_id":"boundary:alpha:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"api_path":"alpha_component::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate without source span"]}
{"schema_version":"v3.2.candidate.1","run_id":"run:v326","candidate_id":"candidate:beta:001","crate_id":"crate:mir-tail","boundary_id":"boundary:beta:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"manifest","path":"Cargo.toml","line_start":null,"line_end":null}],"api_path":"beta_component::register","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic candidate without source span"]}"#,
    )
    .unwrap();
    fs::write(
        &mir_coverage,
        r#"{"schema_version":"bw.mir-coverage/0.1","expected_packages":[{"name":"mir-tail-crate","version":"0.1.0"}],"seen_packages":[{"name":"mir-tail-crate","version":"0.1.0"}],"seen_targets":[{"package":"mir-tail-crate","version":"0.1.0","target":"lib"}],"seen_bodies":[{"package":"mir-tail-crate","version":"0.1.0","target":"lib","def_path":"alpha_component::register"}],"skipped":[{"package":"mir-tail-crate","version":"0.1.0","target":"lib","def_path":"alpha_component::register","reason":"macro_expansion"},{"package":"mir-tail-crate","version":"0.1.0","target":"lib","def_path":"alpha_component::Owner::drop","reason":"macro_expansion"}]}"#,
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
            candidates_dir.to_str().unwrap(),
            "--mir-coverage",
            mir_coverage.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
        ])
        .assert()
        .code(0)
        .stderr("");

    let coverage = read_zst_coverage(&output_dir.join("lifecycle-coverage.jsonl.zst"));
    let alpha = coverage
        .iter()
        .find(|record| record.candidate_id == "candidate:alpha:001")
        .expect("alpha coverage should exist");
    let beta = coverage
        .iter()
        .find(|record| record.candidate_id == "candidate:beta:001")
        .expect("beta coverage should exist");

    assert!(
        alpha
            .covered_function_bodies
            .contains(&"alpha_component::register".to_owned())
    );
    assert!(
        alpha
            .unavailable_paths
            .iter()
            .any(|gap| gap.path == "alpha_component::register")
    );
    assert!(
        !beta
            .covered_function_bodies
            .contains(&"alpha_component::register".to_owned())
    );
    assert!(
        !beta
            .unavailable_paths
            .iter()
            .any(|gap| gap.path == "alpha_component::register")
    );
    assert!(
        !alpha
            .unavailable_paths
            .iter()
            .any(|gap| gap.path == "alpha_component::Owner::drop")
    );
    assert!(
        !beta
            .unavailable_paths
            .iter()
            .any(|gap| gap.path == "alpha_component::Owner::drop")
    );
}

#[test]
fn validate_rejects_lifecycle_fact_missing_provenance() {
    let temp = public_safe_tempdir();
    let path = temp.path().join("facts.jsonl");
    fs::write(
        &path,
        r#"{"schema_version":"v3.2.6.lifecycle_fact.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:alpha","fact_id":"fact:alpha:0001","fact_kind":"register_call","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"alpha::register","text_sha256":null},"symbol_path":"alpha::register","confidence":"medium","coverage_state":"covered","object_ids":["source_evidence:evidence:alpha:0001"],"evidence_refs":["evidence:alpha:0001"],"notes":["missing provenance"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-lifecycle-fact",
            path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("provenance").or(predicate::str::contains("missing")));
}

#[test]
fn validate_rejects_source_observation_with_stable_object_ids() {
    let temp = public_safe_tempdir();
    let path = temp.path().join("facts.jsonl");
    fs::write(
        &path,
        r#"{"schema_version":"v3.2.6.lifecycle_fact.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:alpha","fact_id":"fact:alpha:0001","fact_kind":"register_call","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"alpha::register","text_sha256":null},"symbol_path":"alpha::register","confidence":"medium","coverage_state":"covered","provenance":{"origin":"source_observation"},"object_ids":["callback:alpha","user_data:alpha"],"evidence_refs":["evidence:alpha:0001"],"notes":["forged stable ids"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-lifecycle-fact",
            path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("BW-V326-FACT-OBJECT-ID"));
}

#[test]
fn validate_rejects_contract_retention_lifecycle_fact() {
    let temp = public_safe_tempdir();
    let path = temp.path().join("facts.jsonl");
    fs::write(
        &path,
        r#"{"schema_version":"v3.2.6.lifecycle_fact.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:alpha","fact_id":"fact:forged:retention","fact_kind":"contract_retention","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"alpha::register","text_sha256":null},"symbol_path":"alpha::register","confidence":"medium","coverage_state":"covered","provenance":{"origin":"source_observation"},"object_ids":["source_evidence:evidence:alpha:0001"],"evidence_refs":["evidence:alpha:0001"],"notes":["forged retention"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-lifecycle-fact",
            path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("BW-V326-FACT-CONTRACT-RETENTION"));
}

#[test]
fn lifecycle_fact_public_schema_excludes_model_rejected_values() {
    let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/v3-2-6/lifecycle-fact.schema.json");
    let schema: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(schema_path).expect("lifecycle fact schema should be readable"),
    )
    .expect("lifecycle fact schema should be JSON");

    let fact_kinds = schema["properties"]["fact_kind"]["enum"]
        .as_array()
        .expect("lifecycle fact schema should enumerate fact kinds");
    assert!(
        !fact_kinds.contains(&serde_json::Value::String("contract_retention".to_owned())),
        "public schema must not advertise a fact kind rejected by bw validate"
    );

    let provenance_origins = schema["$defs"]["provenance"]["properties"]["origin"]["enum"]
        .as_array()
        .expect("lifecycle fact schema should enumerate provenance origins");
    assert!(
        !provenance_origins.contains(&serde_json::Value::String("legacy".to_owned())),
        "public schema must not advertise a provenance origin rejected by bw validate"
    );
}

#[test]
fn build_lifecycle_graph_v3_rejects_forged_contract_retention_fact_input() {
    let temp = public_safe_tempdir();
    let candidates = temp.path().join("candidates.jsonl");
    let evidence = temp.path().join("evidence.jsonl");
    let facts = temp.path().join("facts.jsonl");
    let output_dir = temp.path().join("out");
    fs::write(
        &candidates,
        r#"{"schema_version":"v3.2.candidate.1","run_id":"run:p0","candidate_id":"candidate:p0:001","crate_id":"crate:p0","boundary_id":"boundary:p0:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}],"api_path":"p0::set_hook","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic"]}"#,
    )
    .unwrap();
    fs::write(
        &evidence,
        r#"{"schema_version":"v3.2.6.lifecycle_evidence.1","run_id":"run:p0","record_id":"evidence:p0:register","crate_id":"crate:p0","candidate_id":"candidate:p0:001","evidence_kind":"foreign_register","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"p0::set_hook","text_sha256":null},"confidence":"medium","details":{},"notes":["neutral"]}"#,
    )
    .unwrap();
    fs::write(
        &facts,
        r#"{"schema_version":"v3.2.6.lifecycle_fact.1","run_id":"run:p0","candidate_id":"candidate:p0:001","crate_id":"crate:p0","fact_id":"fact:forged:retention","fact_kind":"contract_retention","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"p0::set_hook","text_sha256":null},"symbol_path":"p0::set_hook","confidence":"medium","coverage_state":"covered","provenance":{"origin":"source_observation"},"object_ids":["source_evidence:evidence:p0:register"],"evidence_refs":["evidence:p0:register"],"notes":["forged retention"]}"#,
    )
    .unwrap();

    // graph-v3 loads facts through validate_v3_2_6_lifecycle_facts, so forged
    // ContractRetention cannot enter feature derivation at all.
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates.to_str().unwrap(),
            "--evidence",
            evidence.to_str().unwrap(),
            "--facts",
            facts.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:p0",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("BW-V326-FACT-CONTRACT-RETENTION"));
}

#[test]
fn build_lifecycle_graph_v3_rejects_registry_contract_without_manifest() {
    let temp = public_safe_tempdir();
    let (candidates, evidence) = write_minimal_graph_inputs(
        temp.path(),
        "run:v326-graph-contract-gate",
        "api:rusqlite:update_hook:register",
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let contract_toml = root.join("contracts/callback-retention/contract.toml");
    let api_map_toml = root.join("contracts/callback-retention/rusqlite-api-map.toml");
    let contracts_dir = temp.path().join("materialized-contracts");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "materialize-lifecycle-contracts",
            "--contract-toml",
            contract_toml.to_str().unwrap(),
            "--api-map-toml",
            api_map_toml.to_str().unwrap(),
            "--run-id",
            "run:v326-graph-contract-gate",
            "--component-id",
            "component:rusqlite",
            "--output-dir",
            contracts_dir.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates.to_str().unwrap(),
            "--evidence",
            evidence.to_str().unwrap(),
            "--contracts",
            contracts_dir
                .join("lifecycle-contracts.jsonl")
                .to_str()
                .unwrap(),
            "--output-dir",
            temp.path()
                .join("graphs-missing-manifest")
                .to_str()
                .unwrap(),
            "--run-id",
            "run:v326-graph-contract-gate",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-AUDIT-SOURCE"));
}

#[test]
fn build_lifecycle_graph_v3_accepts_verified_registry_manifest() {
    let temp = public_safe_tempdir();
    let (candidates, evidence) = write_minimal_graph_inputs(
        temp.path(),
        "run:v326-graph-contract-verified",
        "api:rusqlite:update_hook:register",
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let contract_toml = root.join("contracts/callback-retention/contract.toml");
    let api_map_toml = root.join("contracts/callback-retention/rusqlite-api-map.toml");
    let contracts_dir = temp.path().join("materialized-contracts");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "materialize-lifecycle-contracts",
            "--contract-toml",
            contract_toml.to_str().unwrap(),
            "--api-map-toml",
            api_map_toml.to_str().unwrap(),
            "--run-id",
            "run:v326-graph-contract-verified",
            "--component-id",
            "component:rusqlite",
            "--output-dir",
            contracts_dir.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates.to_str().unwrap(),
            "--evidence",
            evidence.to_str().unwrap(),
            "--contracts",
            contracts_dir
                .join("lifecycle-contracts.jsonl")
                .to_str()
                .unwrap(),
            "--registry-manifest",
            contracts_dir
                .join("registry-manifest.json")
                .to_str()
                .unwrap(),
            "--output-dir",
            temp.path()
                .join("graphs-verified-manifest")
                .to_str()
                .unwrap(),
            "--run-id",
            "run:v326-graph-contract-verified",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""contract_source_audit_state":"registry_manifest_verified""#,
        ))
        .stdout(predicate::str::contains(
            r#""contract_input_checksum_verified_count":2"#,
        ));
}

#[test]
fn build_lifecycle_graph_v3_rejects_registry_input_checksum_mismatch() {
    let temp = public_safe_tempdir();
    let (candidates, evidence) = write_minimal_graph_inputs(
        temp.path(),
        "run:v326-graph-contract-checksum",
        "api:rusqlite:update_hook:register",
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let contract_toml = root.join("contracts/callback-retention/contract.toml");
    let api_map_toml = root.join("contracts/callback-retention/rusqlite-api-map.toml");
    let contracts_dir = temp.path().join("materialized-contracts");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "materialize-lifecycle-contracts",
            "--contract-toml",
            contract_toml.to_str().unwrap(),
            "--api-map-toml",
            api_map_toml.to_str().unwrap(),
            "--run-id",
            "run:v326-graph-contract-checksum",
            "--component-id",
            "component:rusqlite",
            "--output-dir",
            contracts_dir.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("");

    let manifest_path = contracts_dir.join("registry-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["api_map"]["sha256"] = serde_json::Value::String("0".repeat(64));
    manifest["api_maps"][0]["sha256"] = serde_json::Value::String("0".repeat(64));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-lifecycle-graph-v3",
            "--candidates",
            candidates.to_str().unwrap(),
            "--evidence",
            evidence.to_str().unwrap(),
            "--contracts",
            contracts_dir
                .join("lifecycle-contracts.jsonl")
                .to_str()
                .unwrap(),
            "--registry-manifest",
            manifest_path.to_str().unwrap(),
            "--output-dir",
            temp.path()
                .join("graphs-bad-input-checksum")
                .to_str()
                .unwrap(),
            "--run-id",
            "run:v326-graph-contract-checksum",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-AUDIT-CHECKSUM"));
}

#[test]
fn validate_accepts_v3_2_6_lifecycle_contract_public_record() {
    let temp = public_safe_tempdir();
    let contract_path = temp.path().join("contracts.jsonl");
    fs::write(
        &contract_path,
        r#"{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v326","contract_id":"contract:alpha","component_id":"component:alpha","api_id":"alpha::register_callback","retention":"may_retain_callback","replacement":"unknown","release":"covers_callback_and_user_data","owner_semantics":"foreign_owned","scope":"local_fixture","source":"manual_lifecycle_contract","evidence_refs":["evidence:alpha:0001"],"notes":["neutral lifecycle contract"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-lifecycle-contract",
            contract_path.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""record_count":1"#));
}

#[test]
fn validate_rejects_forbidden_token_in_lifecycle_contract_public_record() {
    let temp = public_safe_tempdir();
    let contract_path = temp.path().join("contracts.jsonl");
    fs::write(
        &contract_path,
        r#"{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v326","contract_id":"contract:alpha","component_id":"component:alpha","api_id":"alpha::register_callback","retention":"may_retain_callback","replacement":"unknown","release":"unknown","owner_semantics":"foreign_owned","scope":"local_fixture","source":"cve-note","evidence_refs":["evidence:alpha:0001"],"notes":["neutral lifecycle contract"]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-lifecycle-contract",
            contract_path.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-V326-CONTRACT"));
}

#[test]
fn audit_lifecycle_contracts_reports_exact_api_and_release_coverage() {
    let temp = public_safe_tempdir();
    let contracts_path = temp.path().join("contracts.jsonl");
    fs::write(
        &contracts_path,
        r#"{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v327","contract_id":"contract:alpha","component_id":"component:alpha","api_id":"alpha::set_hook","retention":"may_retain_callback","replacement":"replaces_prior_registration","release":"covers_callback_and_user_data","owner_semantics":"foreign_owned","scope":"local_fixture","source":"manual_lifecycle_contract","evidence_refs":["evidence:alpha:doc"],"notes":["neutral lifecycle contract"]}
{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v327","contract_id":"contract:beta","component_id":"component:beta","api_id":"beta::set_hook","retention":"unknown","replacement":"unknown","release":"unknown","owner_semantics":"unknown","scope":"local_fixture","source":"binding_doc_comment","evidence_refs":["evidence:beta:doc"],"notes":["neutral lifecycle contract"]}
{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v327","contract_id":"contract:gamma","component_id":"component:gamma","api_id":"api:gamma:set_hook:register","retention":"may_retain_callback","replacement":"unknown","release":"unknown","owner_semantics":"foreign_owned","scope":"local_fixture","source":"manual_lifecycle_contract","evidence_refs":["evidence:gamma:doc"],"notes":["neutral lifecycle contract"]}"#,
    )
    .unwrap();
    let output_dir = temp.path().join("contract-audit");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            contracts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v327",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-7-contract-audit""#,
        ))
        .stdout(predicate::str::contains(r#""contract_count":3"#))
        .stdout(predicate::str::contains(r#""exact_api_count":3"#))
        .stdout(predicate::str::contains(r#""release_coverage_count":1"#))
        .stdout(predicate::str::contains(
            r#""source_audit_state":"not_requested""#,
        ));

    let audit = fs::read_to_string(output_dir.join("contract-audit.json")).unwrap();
    assert!(audit.contains(r#""retention_may_retain_count": 2"#));
    assert!(audit.contains(r#""unknown_semantics_count": 2"#));
    assert!(output_dir.join("checksums.txt").is_file());
}

#[test]
fn audit_lifecycle_contracts_requires_manifest_for_registry_source() {
    let temp = public_safe_tempdir();
    let contracts_path = temp.path().join("contracts.jsonl");
    fs::write(
        &contracts_path,
        r#"{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v326-registry-required","contract_id":"contract:callback-retention#api:alpha:set_hook:register","component_id":"component:alpha","api_id":"api:alpha:set_hook:register","retention":"may_retain_callback","replacement":"unknown","release":"callback_only","owner_semantics":"foreign_owned","scope":"callback_retention_registry","source":"callback_retention_contract_registry","evidence_refs":["registry:api-map:alpha:api:alpha:set_hook:register"],"notes":["neutral lifecycle contract"]}"#,
    )
    .unwrap();
    let audit_dir = temp.path().join("audit");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            contracts_path.to_str().unwrap(),
            "--output-dir",
            audit_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-registry-required",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-AUDIT-SOURCE"));
}

#[test]
fn build_witness_plan_writes_neutral_controlled_plan() {
    let temp = public_safe_tempdir();
    let ranked_path = temp.path().join("ranked-candidates.jsonl");
    let ranked = bw_model::rank_v3_2_6_features(
        "run:v326",
        vec![
            bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
                features.has_foreign_register = true;
                features.has_borrowed_capture = true;
                features.missing_unregister_before_drop = true;
                features.needs_dynamic_witness = true;
            }),
        ],
    )
    .unwrap();
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &ranked[0]).unwrap();
    bytes.push(b'\n');
    fs::write(&ranked_path, bytes).unwrap();

    let graphs_dir = temp.path().join("graphs-v3");
    fs::create_dir_all(&graphs_dir).unwrap();
    fs::write(
        graphs_dir.join("candidate_sample_001.json"),
        r#"{"schema_version":"v3.2.6.lifecycle_graph_v3.1","run_id":"run:v326","candidate_id":"candidate:sample:001","crate_id":"crate:sample","pattern_family":"retained_borrowed_callback","objects":[{"object_id":"callback:sample","object_kind":"callback","label":"sample callback","source_ref":null,"fact_refs":[]}],"edges":[],"evidence_refs":["evidence:sample:has_foreign_register"],"incomplete_reasons":["release_endpoint_missing"],"notes":["graph v3 fixture"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("witness-plan");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "build-witness-plan",
            "--ranked-candidates",
            ranked_path.to_str().unwrap(),
            "--graphs-dir",
            graphs_dir.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326",
            "--limit",
            "1",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""kind":"v3-2-6-witness-plan""#));

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "validate",
            "--kind",
            "v3-2-6-witness-plan",
            output_dir.join("witness-plans.jsonl.zst").to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""record_count":1"#));
}

#[test]
fn reveal_static_ranking_accepts_v3_2_6_ranked_candidates() {
    let temp = public_safe_tempdir();
    let ranked_path = temp.path().join("ranked-v326.jsonl");
    let mut feature = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:alpha:1.0.0",
        |features| {
            features.has_foreign_register = true;
            features.missing_unregister_before_drop = true;
            features.needs_dynamic_witness = true;
        },
    );
    feature.candidate_id = "candidate:alpha:callback:0001".to_owned();
    let ranked = bw_model::rank_v3_2_6_features("run:v326-reveal", vec![feature]).unwrap();
    let mut ranked_bytes = Vec::new();
    serde_json::to_writer(&mut ranked_bytes, &ranked[0]).unwrap();
    ranked_bytes.push(b'\n');
    fs::write(&ranked_path, &ranked_bytes).unwrap();
    let ranked_sha = hex_digest(Sha256::digest(&ranked_bytes));

    let ground_truth_path = temp.path().join("ground-truth.jsonl");
    fs::write(
        &ground_truth_path,
        r#"{"schema_version":"v3.2.5.private_ground_truth.1","suite_id":"suite:v326-reveal","sample_id":"sample:alpha","public_crate_id":"crate:alpha:1.0.0","role":"vulnerable","paired_with":[],"expected_pattern_families":["retained_borrowed_callback"],"expected_api_substrings":[],"expected_path_substrings":[],"root_cause_key":"opaque","vulnerability_identity":null,"notes":["synthetic private test record"]}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("reveal");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "reveal-static-ranking",
            "--ranked-candidates",
            ranked_path.to_str().unwrap(),
            "--ground-truth",
            ground_truth_path.to_str().unwrap(),
            "--expected-ranked-sha256",
            &ranked_sha,
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-reveal",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-5-static-ranking-reveal""#,
        ))
        .stdout(predicate::str::contains(r#""top1_hit_count":1"#));
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

fn write_minimal_graph_inputs(
    root: &std::path::Path,
    run_id: &str,
    api_path: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let candidates = root.join("candidates.jsonl");
    let evidence = root.join("evidence.jsonl");
    fs::write(
        &candidates,
        format!(
            r#"{{"schema_version":"v3.2.candidate.1","run_id":"{run_id}","candidate_id":"candidate:graph-contract:001","crate_id":"crate:graph-contract","boundary_id":"boundary:graph-contract:001","pattern_family":"retained_borrowed_callback","confidence":"needs_dynamic_validation","evidence_refs":[{{"kind":"source_span","path":"src/lib.rs","line_start":10,"line_end":10}}],"api_path":"{api_path}","recommended_next_step":"generate_lifecycle_subgraph","notes":["synthetic"]}}"#
        ),
    )
    .unwrap();
    fs::write(
        &evidence,
        format!(
            r#"{{"schema_version":"v3.2.6.lifecycle_evidence.1","run_id":"{run_id}","record_id":"evidence:graph-contract:register","crate_id":"crate:graph-contract","candidate_id":"candidate:graph-contract:001","evidence_kind":"foreign_register","source_ref":{{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"{api_path}","text_sha256":null}},"confidence":"medium","details":{{}},"notes":["neutral"]}}"#
        ),
    )
    .unwrap();
    (candidates, evidence)
}

fn line_number(source: &str, needle: &str) -> u64 {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|index| index as u64 + 1)
        .unwrap()
}

fn source_api_id(path: &str, symbol: &str) -> String {
    let source_scope = path
        .trim_end_matches(".rs")
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("::");
    let source_identity = format!("{source_scope}::{symbol}");
    format!(
        "source_api::{:x}",
        Sha256::digest(source_identity.as_bytes())
    )
}

fn read_zst_evidence(path: &std::path::Path) -> Vec<bw_model::V326LifecycleEvidenceRecord> {
    let file = fs::File::open(path).unwrap();
    let decoder = zstd::stream::read::Decoder::new(file).unwrap();
    BufReader::new(decoder)
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
}

fn read_zst_facts(path: &std::path::Path) -> Vec<bw_model::V326LifecycleFactRecord> {
    let file = fs::File::open(path).unwrap();
    let decoder = zstd::stream::read::Decoder::new(file).unwrap();
    BufReader::new(decoder)
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
}

fn read_zst_coverage(path: &std::path::Path) -> Vec<bw_model::V326LifecycleCoverageRecord> {
    let file = fs::File::open(path).unwrap();
    let decoder = zstd::stream::read::Decoder::new(file).unwrap();
    BufReader::new(decoder)
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
}

fn read_zst_candidates(path: &std::path::Path) -> Vec<bw_model::V32CandidateRecord> {
    let file = fs::File::open(path).unwrap();
    let decoder = zstd::stream::read::Decoder::new(file).unwrap();
    BufReader::new(decoder)
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
}

fn read_zst_features(path: &std::path::Path) -> Vec<bw_model::V326LifecycleFeatureRecord> {
    let file = fs::File::open(path).unwrap();
    let decoder = zstd::stream::read::Decoder::new(file).unwrap();
    BufReader::new(decoder)
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
}

fn read_zst_ranked(path: &std::path::Path) -> Vec<bw_model::V326RankedCandidateRecord> {
    let file = fs::File::open(path).unwrap();
    let decoder = zstd::stream::read::Decoder::new(file).unwrap();
    BufReader::new(decoder)
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
}

fn read_zst_pair_deltas(path: &std::path::Path) -> Vec<bw_model::V326PairDeltaRecord> {
    let file = fs::File::open(path).unwrap();
    let decoder = zstd::stream::read::Decoder::new(file).unwrap();
    BufReader::new(decoder)
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
}

#[test]
fn materialize_lifecycle_contracts_emits_auditable_register_and_unregister_records() {
    let temp = public_safe_tempdir();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let contract_toml = root.join("contracts/callback-retention/contract.toml");
    let api_map_toml = root.join("contracts/callback-retention/rusqlite-api-map.toml");
    let output_dir = temp.path().join("materialized-contracts");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "materialize-lifecycle-contracts",
            "--contract-toml",
            contract_toml.to_str().unwrap(),
            "--api-map-toml",
            api_map_toml.to_str().unwrap(),
            "--run-id",
            "run:v326-registry",
            "--component-id",
            "component:rusqlite",
            "--output-dir",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""kind":"v3-2-6-lifecycle-contract-registry""#,
        ));

    let contracts_bytes = fs::read(output_dir.join("lifecycle-contracts.jsonl")).unwrap();
    let records = std::str::from_utf8(&contracts_bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<bw_model::V326LifecycleContractRecord>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(records.iter().any(|record| {
        record.api_id == "api:rusqlite:update_hook:register"
            && record.retention == bw_model::V326ContractRetention::MayRetainCallback
            && record.release == bw_model::V326ContractRelease::Unknown
    }));
    assert!(records.iter().any(|record| {
        record.api_id == "api:rusqlite:update_hook:unregister"
            && record.retention == bw_model::V326ContractRetention::Unknown
            && record.release == bw_model::V326ContractRelease::CallbackOnly
    }));
    assert!(records.iter().all(|record| {
        record.owner_semantics == bw_model::V326ForeignOwnerSemantics::ForeignOwned
    }));

    let manifest_bytes = fs::read(output_dir.join("registry-manifest.json")).unwrap();
    let registry: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(
        registry["registry_id"],
        "registry:contract:callback-retention:api-map:rusqlite-callbacks"
    );
    assert_eq!(registry["contract"]["schema_version"], "bw.contract/0.1");
    assert_eq!(registry["contract"]["id"], "contract:callback-retention");
    assert_eq!(registry["api_map"]["schema_version"], "bw.api-map/0.1");
    assert!(
        registry["materialized_apis"]
            .as_array()
            .unwrap()
            .iter()
            .any(|api| {
                api["api_map_id"] == "api-map:rusqlite-callbacks"
                    && api["rust_path"] == "rusqlite::Connection::update_hook"
                    && api["contract_api_id"] == "api:unregister"
            })
    );
    assert_eq!(
        registry["lifecycle_contracts_sha256"],
        hex_digest(Sha256::digest(&contracts_bytes))
    );

    let checksums = fs::read_to_string(output_dir.join("checksums.sha256")).unwrap();
    assert!(checksums.contains(&format!(
        "{}  lifecycle-contracts.jsonl",
        hex_digest(Sha256::digest(&contracts_bytes))
    )));
    assert!(checksums.contains(&format!(
        "{}  registry-manifest.json",
        hex_digest(Sha256::digest(&manifest_bytes))
    )));

    let audit_dir = temp.path().join("audited-contracts");
    let materialized_contracts_path = output_dir.join("lifecycle-contracts.jsonl");
    let registry_manifest_path = output_dir.join("registry-manifest.json");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            materialized_contracts_path.to_str().unwrap(),
            "--registry-manifest",
            registry_manifest_path.to_str().unwrap(),
            "--output-dir",
            audit_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-registry-audit",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""source_audit_state":"registry_manifest_verified""#,
        ))
        .stdout(predicate::str::contains(
            r#""unmatched_registry_evidence_ref_count":0"#,
        ));

    let audit = fs::read_to_string(audit_dir.join("contract-audit.json")).unwrap();
    assert!(audit.contains(r#""lifecycle_contracts_sha256_matches": true"#));
    assert!(audit.contains(r#""registry_evidence_ref_count": 8"#));
    assert!(audit.contains(r#""matched_registry_evidence_ref_count": 8"#));
}

#[test]
fn materialize_lifecycle_contracts_accepts_multiple_api_maps() {
    let temp = public_safe_tempdir();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let contract_toml = root.join("contracts/callback-retention/contract.toml");
    let rusqlite_api_map_toml = root.join("contracts/callback-retention/rusqlite-api-map.toml");
    let openssl_api_map_toml = temp.path().join("openssl-api-map.toml");
    fs::write(
        &openssl_api_map_toml,
        r#"schema_version = "bw.api-map/0.1"
map_id = "api-map:openssl-retained-user-data"
producer = "boundary-witness@v0.1"
contract_id = "contract:callback-retention"

[[apis]]
api_id = "api:openssl:ssl_ctx_set_ex_data:register"
rust_path = "openssl_sys::SSL_CTX_set_ex_data"
contract_api_id = "api:register"
callback_family = "openssl_ssl_ctx_ex_data"
notes = "SSL_CTX_set_ex_data 保存 caller-provided user-data pointer。"

[[apis]]
api_id = "api:openssl:ssl_set_ex_data:register"
rust_path = "openssl_sys::SSL_set_ex_data"
contract_api_id = "api:register"
callback_family = "openssl_ssl_ex_data"
notes = "SSL_set_ex_data 保存 caller-provided user-data pointer。"
"#,
    )
    .unwrap();
    let output_dir = temp.path().join("materialized-contracts");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "materialize-lifecycle-contracts",
            "--contract-toml",
            contract_toml.to_str().unwrap(),
            "--api-map-toml",
            rusqlite_api_map_toml.to_str().unwrap(),
            "--api-map-toml",
            openssl_api_map_toml.to_str().unwrap(),
            "--run-id",
            "run:v326-registry-multi",
            "--component-id",
            "component:callback-retention",
            "--output-dir",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""materialized_count":10"#));

    let contracts_bytes = fs::read(output_dir.join("lifecycle-contracts.jsonl")).unwrap();
    let records = std::str::from_utf8(&contracts_bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<bw_model::V326LifecycleContractRecord>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(records.iter().any(|record| {
        record.api_id == "api:rusqlite:update_hook:register"
            && record.retention == bw_model::V326ContractRetention::MayRetainCallback
    }));
    assert!(records.iter().any(|record| {
        record.api_id == "api:openssl:ssl_ctx_set_ex_data:register"
            && record.retention == bw_model::V326ContractRetention::MayRetainCallback
    }));
    assert!(records.iter().any(|record| {
        record.api_id == "api:openssl:ssl_set_ex_data:register"
            && record.retention == bw_model::V326ContractRetention::MayRetainCallback
    }));

    let manifest_bytes = fs::read(output_dir.join("registry-manifest.json")).unwrap();
    let registry: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let api_maps = registry["api_maps"].as_array().unwrap();
    assert_eq!(api_maps.len(), 2);
    assert!(
        api_maps
            .iter()
            .any(|api_map| api_map["id"] == "api-map:rusqlite-callbacks")
    );
    assert!(
        api_maps
            .iter()
            .any(|api_map| api_map["id"] == "api-map:openssl-retained-user-data")
    );
    let materialized = registry["materialized_apis"].as_array().unwrap();
    assert!(materialized.iter().any(|api| {
        api["api_map_id"] == "api-map:openssl-retained-user-data"
            && api["map_api_id"] == "api:openssl:ssl_set_ex_data:register"
    }));

    let audit_dir = temp.path().join("multi-map-audit");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            output_dir
                .join("lifecycle-contracts.jsonl")
                .to_str()
                .unwrap(),
            "--registry-manifest",
            output_dir.join("registry-manifest.json").to_str().unwrap(),
            "--output-dir",
            audit_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-registry-multi-audit",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(
            r#""source_audit_state":"registry_manifest_verified""#,
        ))
        .stdout(predicate::str::contains(r#""materialized_api_count":10"#))
        .stdout(predicate::str::contains(
            r#""matched_registry_evidence_ref_count":10"#,
        ));
}

#[test]
fn materialize_lifecycle_contracts_rejects_duplicate_api_map_ids() {
    let temp = public_safe_tempdir();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let contract_toml = root.join("contracts/callback-retention/contract.toml");
    let api_map_toml = root.join("contracts/callback-retention/rusqlite-api-map.toml");
    let output_dir = temp.path().join("duplicate-map-materialized-contracts");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "materialize-lifecycle-contracts",
            "--contract-toml",
            contract_toml.to_str().unwrap(),
            "--api-map-toml",
            api_map_toml.to_str().unwrap(),
            "--api-map-toml",
            api_map_toml.to_str().unwrap(),
            "--run-id",
            "run:v326-registry-duplicate-map",
            "--component-id",
            "component:callback-retention",
            "--output-dir",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-REGISTRY-MANIFEST"))
        .stderr(predicate::str::contains("api_map id 重复"));
}

#[test]
fn audit_lifecycle_contracts_rejects_unmatched_registry_evidence_ref() {
    let temp = public_safe_tempdir();
    let contracts_path = temp.path().join("contracts.jsonl");
    let contract_record = r#"{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v326-audit-negative","contract_id":"contract:callback-retention#api:alpha:set_hook:register","component_id":"component:alpha","api_id":"api:alpha:set_hook:register","retention":"may_retain_callback","replacement":"unknown","release":"callback_only","owner_semantics":"foreign_owned","scope":"callback_retention_registry","source":"callback_retention_contract_registry","evidence_refs":["registry:api-map:alpha:api:alpha:set_hook:other"],"notes":["neutral lifecycle contract"]}"#;
    fs::write(&contracts_path, format!("{contract_record}\n")).unwrap();
    let contracts_bytes = fs::read(&contracts_path).unwrap();
    let registry_manifest_path = temp.path().join("registry-manifest.json");
    let registry_manifest = serde_json::json!({
        "schema_version": "v3.2.6.callback_retention_registry.1",
        "registry_id": "registry:contract:callback-retention:api-map:alpha",
        "run_id": "run:v326-audit-negative",
        "component_id": "component:alpha",
        "contract": {
            "schema_version": "bw.contract/0.1",
            "id": "contract:callback-retention",
            "sha256": "0".repeat(64)
        },
        "api_map": {
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        },
        "api_maps": [{
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        }],
        "materialized_apis": [{
            "api_map_id": "api-map:alpha",
            "map_api_id": "api:alpha:set_hook:register",
            "rust_path": "alpha::set_hook",
            "contract_api_id": "api:register",
            "lifecycle_contract_id": "contract:callback-retention#api:alpha:set_hook:register"
        }],
        "skipped_api_entries": [],
        "lifecycle_contracts_path": "lifecycle-contracts.jsonl",
        "lifecycle_contracts_sha256": hex_digest(Sha256::digest(&contracts_bytes))
    });
    fs::write(
        &registry_manifest_path,
        serde_json::to_vec_pretty(&registry_manifest).unwrap(),
    )
    .unwrap();

    let audit_dir = temp.path().join("audit");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            contracts_path.to_str().unwrap(),
            "--registry-manifest",
            registry_manifest_path.to_str().unwrap(),
            "--output-dir",
            audit_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-audit-negative",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-AUDIT-EVIDENCE"));
}

#[test]
fn audit_lifecycle_contracts_rejects_registry_manifest_checksum_mismatch() {
    let temp = public_safe_tempdir();
    let contracts_path = temp.path().join("contracts.jsonl");
    let contract_record = r#"{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v326-audit-checksum","contract_id":"contract:callback-retention#api:alpha:set_hook:register","component_id":"component:alpha","api_id":"api:alpha:set_hook:register","retention":"may_retain_callback","replacement":"unknown","release":"callback_only","owner_semantics":"foreign_owned","scope":"callback_retention_registry","source":"callback_retention_contract_registry","evidence_refs":["registry:api-map:alpha:api:alpha:set_hook:register"],"notes":["neutral lifecycle contract"]}"#;
    fs::write(&contracts_path, format!("{contract_record}\n")).unwrap();
    let registry_manifest_path = temp.path().join("registry-manifest.json");
    let registry_manifest = serde_json::json!({
        "schema_version": "v3.2.6.callback_retention_registry.1",
        "registry_id": "registry:contract:callback-retention:api-map:alpha",
        "run_id": "run:v326-audit-checksum",
        "component_id": "component:alpha",
        "contract": {
            "schema_version": "bw.contract/0.1",
            "id": "contract:callback-retention",
            "sha256": "0".repeat(64)
        },
        "api_map": {
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        },
        "api_maps": [{
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        }],
        "materialized_apis": [{
            "api_map_id": "api-map:alpha",
            "map_api_id": "api:alpha:set_hook:register",
            "rust_path": "alpha::set_hook",
            "contract_api_id": "api:register",
            "lifecycle_contract_id": "contract:callback-retention#api:alpha:set_hook:register"
        }],
        "skipped_api_entries": [],
        "lifecycle_contracts_path": "lifecycle-contracts.jsonl",
        "lifecycle_contracts_sha256": "f".repeat(64)
    });
    fs::write(
        &registry_manifest_path,
        serde_json::to_vec_pretty(&registry_manifest).unwrap(),
    )
    .unwrap();

    let audit_dir = temp.path().join("audit");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            contracts_path.to_str().unwrap(),
            "--registry-manifest",
            registry_manifest_path.to_str().unwrap(),
            "--output-dir",
            audit_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-audit-checksum",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-AUDIT-CHECKSUM"));
}

#[test]
fn audit_lifecycle_contracts_rejects_registry_input_checksum_mismatch() {
    let temp = public_safe_tempdir();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let contract_toml = root.join("contracts/callback-retention/contract.toml");
    let api_map_toml = root.join("contracts/callback-retention/rusqlite-api-map.toml");
    let output_dir = temp.path().join("materialized-contracts");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "materialize-lifecycle-contracts",
            "--contract-toml",
            contract_toml.to_str().unwrap(),
            "--api-map-toml",
            api_map_toml.to_str().unwrap(),
            "--run-id",
            "run:v326-registry-input-checksum",
            "--component-id",
            "component:rusqlite",
            "--output-dir",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stderr("");

    let manifest_path = output_dir.join("registry-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["api_map"]["sha256"] = serde_json::Value::String("0".repeat(64));
    manifest["api_maps"][0]["sha256"] = serde_json::Value::String("0".repeat(64));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let audit_dir = temp.path().join("audit");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            output_dir
                .join("lifecycle-contracts.jsonl")
                .to_str()
                .unwrap(),
            "--registry-manifest",
            manifest_path.to_str().unwrap(),
            "--output-dir",
            audit_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-registry-input-checksum-audit",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-AUDIT-CHECKSUM"));
}

#[test]
fn audit_lifecycle_contracts_rejects_manifest_api_without_contract_record() {
    let temp = public_safe_tempdir();
    let contracts_path = temp.path().join("contracts.jsonl");
    fs::write(&contracts_path, "").unwrap();
    let contracts_bytes = fs::read(&contracts_path).unwrap();
    let registry_manifest_path = temp.path().join("registry-manifest.json");
    let registry_manifest = serde_json::json!({
        "schema_version": "v3.2.6.callback_retention_registry.1",
        "registry_id": "registry:contract:callback-retention:api-map:alpha",
        "run_id": "run:v326-audit-missing-contract",
        "component_id": "component:alpha",
        "contract": {
            "schema_version": "bw.contract/0.1",
            "id": "contract:callback-retention",
            "sha256": "0".repeat(64)
        },
        "api_map": {
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        },
        "api_maps": [{
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        }],
        "materialized_apis": [{
            "api_map_id": "api-map:alpha",
            "map_api_id": "api:alpha:set_hook:register",
            "rust_path": "alpha::set_hook",
            "contract_api_id": "api:register",
            "lifecycle_contract_id": "contract:callback-retention#api:alpha:set_hook:register"
        }],
        "skipped_api_entries": [],
        "lifecycle_contracts_path": "lifecycle-contracts.jsonl",
        "lifecycle_contracts_sha256": hex_digest(Sha256::digest(&contracts_bytes))
    });
    fs::write(
        &registry_manifest_path,
        serde_json::to_vec_pretty(&registry_manifest).unwrap(),
    )
    .unwrap();
    let audit_dir = temp.path().join("audit");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            contracts_path.to_str().unwrap(),
            "--registry-manifest",
            registry_manifest_path.to_str().unwrap(),
            "--output-dir",
            audit_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-audit-missing-contract",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-AUDIT-EVIDENCE"));
}

#[test]
fn audit_lifecycle_contracts_rejects_manifest_materialized_skipped_overlap() {
    let temp = public_safe_tempdir();
    let contracts_path = temp.path().join("contracts.jsonl");
    let contract_record = r#"{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v326-audit-overlap","contract_id":"contract:callback-retention#api:alpha:set_hook:register","component_id":"component:alpha","api_id":"api:alpha:set_hook:register","retention":"may_retain_callback","replacement":"unknown","release":"callback_only","owner_semantics":"foreign_owned","scope":"callback_retention_registry","source":"callback_retention_contract_registry","evidence_refs":["registry:api-map:alpha:api:alpha:set_hook:register"],"notes":["neutral lifecycle contract"]}"#;
    fs::write(&contracts_path, format!("{contract_record}\n")).unwrap();
    let contracts_bytes = fs::read(&contracts_path).unwrap();
    let registry_manifest_path = temp.path().join("registry-manifest.json");
    let registry_manifest = serde_json::json!({
        "schema_version": "v3.2.6.callback_retention_registry.1",
        "registry_id": "registry:contract:callback-retention:api-map:alpha",
        "run_id": "run:v326-audit-overlap",
        "component_id": "component:alpha",
        "contract": {
            "schema_version": "bw.contract/0.1",
            "id": "contract:callback-retention",
            "sha256": "0".repeat(64)
        },
        "api_map": {
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        },
        "api_maps": [{
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        }],
        "materialized_apis": [{
            "api_map_id": "api-map:alpha",
            "map_api_id": "api:alpha:set_hook:register",
            "rust_path": "alpha::set_hook",
            "contract_api_id": "api:register",
            "lifecycle_contract_id": "contract:callback-retention#api:alpha:set_hook:register"
        }],
        "skipped_api_entries": [{
            "api_map_id": "api-map:alpha",
            "map_api_id": "api:alpha:set_hook:register",
            "reason": "duplicate skipped source"
        }],
        "lifecycle_contracts_path": "lifecycle-contracts.jsonl",
        "lifecycle_contracts_sha256": hex_digest(Sha256::digest(&contracts_bytes))
    });
    fs::write(
        &registry_manifest_path,
        serde_json::to_vec_pretty(&registry_manifest).unwrap(),
    )
    .unwrap();
    let audit_dir = temp.path().join("audit");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            contracts_path.to_str().unwrap(),
            "--registry-manifest",
            registry_manifest_path.to_str().unwrap(),
            "--output-dir",
            audit_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-audit-overlap",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-AUDIT-MANIFEST"))
        .stderr(predicate::str::contains(
            "同时出现在 materialized 和 skipped",
        ));
}

#[test]
fn audit_lifecycle_contracts_rejects_multimap_skipped_without_api_map_id() {
    let temp = public_safe_tempdir();
    let contracts_path = temp.path().join("contracts.jsonl");
    let contract_record = r#"{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v326-audit-skipped-ambiguous","contract_id":"contract:callback-retention#api:alpha:set_hook:register","component_id":"component:alpha","api_id":"api:alpha:set_hook:register","retention":"may_retain_callback","replacement":"unknown","release":"callback_only","owner_semantics":"foreign_owned","scope":"callback_retention_registry","source":"callback_retention_contract_registry","evidence_refs":["registry:api-map:alpha:api:alpha:set_hook:register"],"notes":["neutral lifecycle contract"]}"#;
    fs::write(&contracts_path, format!("{contract_record}\n")).unwrap();
    let contracts_bytes = fs::read(&contracts_path).unwrap();
    let registry_manifest_path = temp.path().join("registry-manifest.json");
    let registry_manifest = serde_json::json!({
        "schema_version": "v3.2.6.callback_retention_registry.1",
        "registry_id": "registry:contract:callback-retention:multi-map",
        "run_id": "run:v326-audit-skipped-ambiguous",
        "component_id": "component:alpha",
        "contract": {
            "schema_version": "bw.contract/0.1",
            "id": "contract:callback-retention",
            "sha256": "0".repeat(64)
        },
        "api_map": {
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        },
        "api_maps": [{
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:alpha",
            "sha256": "1".repeat(64)
        }, {
            "schema_version": "bw.api-map/0.1",
            "id": "api-map:beta",
            "sha256": "2".repeat(64)
        }],
        "materialized_apis": [{
            "api_map_id": "api-map:alpha",
            "map_api_id": "api:alpha:set_hook:register",
            "rust_path": "alpha::set_hook",
            "contract_api_id": "api:register",
            "lifecycle_contract_id": "contract:callback-retention#api:alpha:set_hook:register"
        }],
        "skipped_api_entries": [{
            "map_api_id": "api:beta:set_hook:register",
            "reason": "not materialized in this fixture"
        }],
        "lifecycle_contracts_path": "lifecycle-contracts.jsonl",
        "lifecycle_contracts_sha256": hex_digest(Sha256::digest(&contracts_bytes))
    });
    fs::write(
        &registry_manifest_path,
        serde_json::to_vec_pretty(&registry_manifest).unwrap(),
    )
    .unwrap();
    let audit_dir = temp.path().join("audit");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "audit-lifecycle-contracts",
            "--contracts",
            contracts_path.to_str().unwrap(),
            "--registry-manifest",
            registry_manifest_path.to_str().unwrap(),
            "--output-dir",
            audit_dir.to_str().unwrap(),
            "--run-id",
            "run:v326-audit-skipped-ambiguous",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BW-CONTRACT-AUDIT-MANIFEST"))
        .stderr(predicate::str::contains("multi-map 场景不可去歧义"));
}

fn evidence_lines_for(
    records: &[bw_model::V326LifecycleEvidenceRecord],
    candidate_id: &str,
) -> Vec<u64> {
    records
        .iter()
        .filter(|record| record.candidate_id == candidate_id)
        .filter_map(|record| record.source_ref.line_start)
        .collect()
}

/// 阶段 1.4 验收：`extract-rust-contracts` 必须能独立跑起来，并把缺证原因分类计数。
///
/// 在此之前装配逻辑只有测试在调用，Rust 侧**跑不起来**——而阶段 1 的完成条件要求它
/// 能独立运行并回答「哪个 public safe API，在什么 hand-off，把什么义务交给了外部」。
#[test]
fn extract_rust_contracts_runs_standalone_and_counts_gaps() {
    let temp = public_safe_tempdir();
    let facts_path = temp.path().join("static-facts.jsonl");

    // 一个交出点四样事实齐备，另一个只有 bound——后者必须落 gap 且写清缺什么。
    let complete = r#"{"schema_version":"bw.static/0.2","record_id":"static:1","producer":"fixture","build_id":"b","payload":{"kind":"callback_lifetime_bound","site_id":"site:a1","semantic_site_key":"sem:a1","api_id":"demo::full","callback_param":"F","bound_lifetime":null,"bound_scope":"no_lifetime_bound"}}
{"schema_version":"bw.static/0.2","record_id":"static:2","producer":"fixture","build_id":"b","payload":{"kind":"registration_guard","site_id":"site:a2","semantic_site_key":"sem:a2","api_id":"demo::full","callback_param":"F","guard":"none"}}
{"schema_version":"bw.static/0.2","record_id":"static:3","producer":"fixture","build_id":"b","payload":{"kind":"allocation_ownership","site_id":"site:a3","semantic_site_key":"sem:a3","api_id":"demo::full","callback_param":"F","ownership":"foreign_owned_until_unregister"}}
{"schema_version":"bw.static/0.2","record_id":"static:4","producer":"fixture","build_id":"b","payload":{"kind":"safe_entry_lineage","site_id":"site:a4","semantic_site_key":"sem:a4","api_id":"demo::full","callback_param":"F","owner_is_unsafe_fn":false,"lineage":"direct_public_safe_entry"}}
{"schema_version":"bw.static/0.2","record_id":"static:5","producer":"fixture","build_id":"b","payload":{"kind":"callback_lifetime_bound","site_id":"site:b1","semantic_site_key":"sem:b1","api_id":"demo::partial","callback_param":"G","bound_lifetime":null,"bound_scope":"no_lifetime_bound"}}
"#;
    fs::write(&facts_path, complete).unwrap();

    let output_dir = temp.path().join("contracts");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-rust-contracts",
            "--facts",
            facts_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:stage14",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""assembled":1"#))
        .stdout(predicate::str::contains(r#""gapped":1"#));

    let summary: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(output_dir.join("rust-contract-summary.json")).unwrap(),
    )
    .unwrap();
    // 缺证必须按原因分类，不能只报总数——这是 attrition waterfall 的输入。
    assert_eq!(summary["gap_reasons"]["missing_guard"], 1);
    assert_eq!(summary["gap_reasons"]["missing_allocation_ownership"], 1);
    assert_eq!(summary["gap_reasons"]["missing_safe_entry_lineage"], 1);

    let records = fs::read_to_string(output_dir.join("rust-contracts.jsonl")).unwrap();
    assert!(records.contains("demo::full"));
    assert!(records.contains("demo::partial"));
}

/// 阶段 3 验收：`extract-foreign-facts` 必须能从文本 IR 独立跑出四项正交结论。
///
/// 这里用的 IR 是 matched fixture `retain_late_invoke_clearing.c` 的核心形状：注册把回调
/// 与 user data 写进两个全局槽位，注销把两个都写回 null，派发函数从槽位读出后间接调用。
#[test]
fn extract_foreign_facts_runs_standalone_and_records_four_dimensions() {
    let temp = public_safe_tempdir();
    let ir_path = temp.path().join("stub.ll");
    fs::write(
        &ir_path,
        r#"
@g_callback = internal global void (i8*)* null, align 8
@g_user_data = internal global i8* null, align 8

define dso_local void @fixture_register(void (i8*)* noundef %0, i8* noundef %1) {
  %3 = alloca void (i8*)*, align 8
  %4 = alloca i8*, align 8
  store void (i8*)* %0, void (i8*)** %3, align 8
  store i8* %1, i8** %4, align 8
  %5 = load void (i8*)*, void (i8*)** %3, align 8
  store void (i8*)* %5, void (i8*)** @g_callback, align 8
  %6 = load i8*, i8** %4, align 8
  store i8* %6, i8** @g_user_data, align 8
  ret void
}

define dso_local void @fixture_unregister() {
  store void (i8*)* null, void (i8*)** @g_callback, align 8
  store i8* null, i8** @g_user_data, align 8
  ret void
}

define dso_local void @fixture_fire() {
  %1 = load void (i8*)*, void (i8*)** @g_callback, align 8
  %2 = load i8*, i8** @g_user_data, align 8
  call void %1(i8* noundef %2)
  ret void
}
"#,
    )
    .unwrap();

    let roles_path = temp.path().join("roles.json");
    fs::write(
        &roles_path,
        r#"{
  "schema_version": "bw.foreign-role-map/0.1",
  "notes": ["fixture"],
  "roles": [
    {
      "register_symbol": "fixture_register",
      "callback_arg_index": 0,
      "userdata_arg_index": 1,
      "clear_symbol": "fixture_unregister"
    }
  ]
}"#,
    )
    .unwrap();

    let output_dir = temp.path().join("foreign");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-foreign-facts",
            "--ir",
            ir_path.to_str().unwrap(),
            "--roles",
            roles_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            "run:stage3",
            "--foreign-artifact",
            "artifact:fixture",
        ])
        .assert()
        .code(0)
        .stderr("")
        .stdout(predicate::str::contains(r#""slots_total":2"#));

    let summary: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(output_dir.join("foreign-fact-summary.json")).unwrap(),
    )
    .unwrap();
    // 四个维度必须分开计数，不能合并成一个总枚举（执行计划 3.4）。
    assert_eq!(summary["retention_counts"]["may_retain"], 1);
    assert_eq!(summary["invocation_counts"]["may_invoke_after_return"], 1);
    assert_eq!(summary["clear_counts"]["clears_on_all_paths"], 1);
    assert_eq!(
        summary["path_compatibility_counts"]["retain_on_every_path"],
        1
    );

    let records = fs::read_to_string(output_dir.join("foreign-facts.jsonl")).unwrap();
    // 证据必须能回查到指令，否则结论无法复核。
    assert!(records.contains("g_callback"));
    assert!(records.contains("fixture_fire"));
    // **产物里不得出现 HandOffId。** 身份要两侧各出一半，填占位会诱使下游拿去 join。
    assert!(!records.contains("hand_off"));
}

/// RoleMap 的 schema 版本对不上必须直接拒绝，不能按默认值继续。
#[test]
fn extract_foreign_facts_rejects_an_unknown_role_map_schema() {
    let temp = public_safe_tempdir();
    let ir_path = temp.path().join("stub.ll");
    fs::write(&ir_path, "define void @f() {\n  ret void\n}\n").unwrap();
    let roles_path = temp.path().join("roles.json");
    fs::write(
        &roles_path,
        r#"{"schema_version":"bw.foreign-role-map/9.9","roles":[]}"#,
    )
    .unwrap();

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "extract-foreign-facts",
            "--ir",
            ir_path.to_str().unwrap(),
            "--roles",
            roles_path.to_str().unwrap(),
            "--output-dir",
            temp.path().join("out").to_str().unwrap(),
            "--run-id",
            "run:stage3",
            "--foreign-artifact",
            "artifact:fixture",
        ])
        .assert()
        .failure();
}
