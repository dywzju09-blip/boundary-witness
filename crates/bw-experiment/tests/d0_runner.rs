use std::{
    fs,
    path::{Path, PathBuf},
};

use bw_experiment::{
    CallbackApi, D0CaseMatrix, D0ReplayAnalysis, D0RunMode, D0RunOptions, D0WorkKind,
    PrimaryOutcome, RunMetadata, ToolchainVersions, analyze_d0_replay, plan_d0_work, run_d0,
    verify_run_integrity,
};

#[test]
fn d0_preflight_and_formal_plans_expand_repetitions_without_labels() {
    let matrix = D0CaseMatrix::parse_toml(&fixture("experiments/configs/d0-cases.toml")).unwrap();
    let repo_root = PathBuf::from("/repo");

    let preflight = plan_d0_work(&matrix, D0RunMode::Preflight, &repo_root).unwrap();
    assert_eq!(preflight.items.len(), 12);
    assert_eq!(count_replays(&preflight.items), 10);
    assert_eq!(count_compile_checks(&preflight.items), 2);

    let formal = plan_d0_work(&matrix, D0RunMode::Formal, &repo_root).unwrap();
    assert_eq!(formal.items.len(), 202);
    assert_eq!(count_replays(&formal.items), 200);
    assert_eq!(count_compile_checks(&formal.items), 2);

    let first_replay = formal
        .items
        .iter()
        .find(|item| item.case_id == "d0-uh-001" && item.iteration == Some(1))
        .expect("first update-hook replay should be planned");
    assert!(matches!(first_replay.kind, D0WorkKind::Replay { .. }));
    assert_eq!(first_replay.api.to_string(), "update_hook");
    assert_eq!(first_replay.replay_id, "d0-uh-001-r001");
    match &first_replay.kind {
        D0WorkKind::Replay {
            static_facts,
            executable,
        } => {
            assert_eq!(
                static_facts,
                &PathBuf::from("/repo/experiments/artifacts/d0/static/d0-uh-001.jsonl")
            );
            assert_eq!(
                executable,
                &PathBuf::from("/repo/experiments/artifacts/d0/bin/d0-uh-001")
            );
        }
        D0WorkKind::CompileCheck { .. } => unreachable!("expected replay"),
    }

    let compile_check = formal
        .items
        .iter()
        .find(|item| item.case_id == "d0-sf-006")
        .expect("scalar compile-check should be planned");
    assert_eq!(compile_check.iteration, None);
    assert_eq!(compile_check.replay_id, "d0-sf-006-compile-check");
    assert!(matches!(
        compile_check.kind,
        D0WorkKind::CompileCheck { .. }
    ));
}

#[test]
fn d0_replay_analysis_writes_findings_and_normalized_signature() {
    let temp = tempfile::tempdir().unwrap();
    let inputs = write_minimal_inputs(temp.path());
    let findings_path = temp.path().join("findings.jsonl");

    let record = analyze_d0_replay(&D0ReplayAnalysis {
        api: CallbackApi::UpdateHook,
        case_id: "d0-uh-001".to_owned(),
        replay_id: "d0-uh-001-r001".to_owned(),
        build_id: "build:test".to_owned(),
        static_facts: inputs.static_facts,
        contract: inputs.contract,
        trace: inputs.trace,
        findings_output: findings_path.clone(),
    })
    .unwrap();

    assert_eq!(record.primary_outcome, PrimaryOutcome::ContractFinding);
    assert_eq!(record.finding_signature.as_deref().map(str::len), Some(64));
    assert!(record.evidence.has_contract_finding);

    let findings = fs::read_to_string(findings_path).unwrap();
    assert!(findings.contains(r#""rule_id":"BW-LIFE-002""#));
}

#[cfg(unix)]
#[test]
fn d0_runner_finalizes_a_preflight_run_directory() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join("bin")).unwrap();
    let inputs = write_minimal_inputs(&repo);
    let executable = repo.join("bin/fake-d0-case");
    write_fake_trace_executable(&executable);
    let mut permissions = fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).unwrap();

    let matrix = D0CaseMatrix::parse_toml(
        r#"
schema_version = "boundary-witness.d0-cases/0.1"
suite_id = "d0-test-suite"
repetitions = 20
timeout_ms = 5000
compile_timeout_ms = 120000

[[cases]]
case_id = "d0-test-001"
api = "update_hook"
operation = "run"
static_facts = "static.jsonl"
executable = "bin/fake-d0-case"
"#,
    )
    .unwrap();

    let report = run_d0(D0RunOptions {
        matrix,
        repo_root: repo.clone(),
        runs_root: temp.path().join("runs"),
        contract: inputs.contract,
        mode: D0RunMode::Preflight,
        metadata: RunMetadata {
            git_commit: "0123456789abcdef".to_owned(),
            deployment_sha256: "deployment-sha".to_owned(),
            image_digest: "native-test".to_owned(),
            config_digest: "config-sha".to_owned(),
            build_id: "d0-test-build".to_owned(),
            host: "localhost".to_owned(),
            cpu_limit: None,
            seed: None,
            toolchains: ToolchainVersions {
                stable: "rustc-test".to_owned(),
                compiler_nightly: None,
            },
        },
    })
    .unwrap();

    assert_eq!(report.summary.total_replays, 1);
    assert_eq!(report.compile_check_count, 0);
    assert!(report.final_run.path().join("COMPLETE").exists());
    assert!(
        report
            .final_run
            .path()
            .join("artifacts/replay-records.jsonl")
            .exists()
    );
    verify_run_integrity(report.final_run.path()).unwrap();
}

fn count_replays(items: &[bw_experiment::D0WorkItem]) -> usize {
    items
        .iter()
        .filter(|item| matches!(item.kind, D0WorkKind::Replay { .. }))
        .count()
}

fn count_compile_checks(items: &[bw_experiment::D0WorkItem]) -> usize {
    items
        .iter()
        .filter(|item| matches!(item.kind, D0WorkKind::CompileCheck { .. }))
        .count()
}

fn fixture(relative: &str) -> String {
    let path = repo_root().join(relative);
    fs::read_to_string(path).unwrap()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

struct Inputs {
    static_facts: PathBuf,
    contract: PathBuf,
    trace: PathBuf,
}

fn write_minimal_inputs(dir: &Path) -> Inputs {
    let static_facts = dir.join("static.jsonl");
    let contract = dir.join("contract.toml");
    let trace = dir.join("trace.jsonl");

    fs::write(
        &static_facts,
        [
            r#"{"schema_version":"bw.static/0.1","record_id":"fact:object","producer":"d0-test","build_id":"build:test","payload":{"kind":"object_site","site_id":"site:object","semantic_site_key":"semantic:object","type_name":"Tracked<BorrowedCounter>"}}"#,
            r#"{"schema_version":"bw.static/0.1","record_id":"fact:capture","producer":"d0-test","build_id":"build:test","payload":{"kind":"callback_capture","site_id":"site:capture","semantic_site_key":"semantic:capture","callback_site_id":"site:callback","object_site_id":"site:object","capture_ordinal":0,"capture_mode":"borrowed"}}"#,
        ]
        .join("\n"),
    )
    .unwrap();
    fs::write(
        &contract,
        r#"
schema_version = "bw.contract/0.1"
contract_id = "contract:callback-retention"
producer = "d0-test"

[[clauses]]
clause_id = "clause:register-retains"
kind = "retain_after_register"
description = "register retains callback"

[[clauses]]
clause_id = "clause:borrow-outlives-retention"
kind = "borrow_must_outlive_retention"
description = "borrow must outlive retained callback"

[[clauses]]
clause_id = "clause:no-use-after-lifetime-end"
kind = "no_use_after_lifetime_end"
description = "object must not be used after lifetime end"

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
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:start","run_id":"run:test","trace_id":"trace:test","seq":0,"thread_id":"main","source":"d0-test","payload":{"kind":"trace_start","build_id":"build:test"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:owner-create","run_id":"run:test","trace_id":"trace:test","seq":1,"thread_id":"main","source":"d0-test","payload":{"kind":"object_create","instance_id":"owner:1","site_id":"site:owner","object_kind":"external_owner","epoch":0,"address_diag":null}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:object-create","run_id":"run:test","trace_id":"trace:test","seq":2,"thread_id":"main","source":"d0-test","payload":{"kind":"object_create","instance_id":"object:1","site_id":"site:object","object_kind":"tracked","epoch":0,"address_diag":null}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:register","run_id":"run:test","trace_id":"trace:test","seq":3,"thread_id":"main","source":"d0-test","payload":{"kind":"callback_register","callback_instance_id":"callback:1","callback_site_id":"site:callback","owner_instance_id":"owner:1","registration_site_id":"site:register","api_id":"api:register"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:bind","run_id":"run:test","trace_id":"trace:test","seq":4,"thread_id":"main","source":"d0-test","payload":{"kind":"capture_bind","callback_instance_id":"callback:1","callback_site_id":"site:callback","object_instance_id":"object:1","object_site_id":"site:object"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:checkpoint-registered","run_id":"run:test","trace_id":"trace:test","seq":5,"thread_id":"main","source":"d0-test","payload":{"kind":"checkpoint","checkpoint":"registered"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:drop","run_id":"run:test","trace_id":"trace:test","seq":6,"thread_id":"main","source":"d0-test","payload":{"kind":"object_drop","instance_id":"object:1","drop_site_id":"site:drop"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:checkpoint-later","run_id":"run:test","trace_id":"trace:test","seq":7,"thread_id":"main","source":"d0-test","payload":{"kind":"checkpoint","checkpoint":"later_callback_phase"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:invoke","run_id":"run:test","trace_id":"trace:test","seq":8,"thread_id":"main","source":"d0-test","payload":{"kind":"callback_invoke","callback_instance_id":"callback:1","invoke_site_id":"site:invoke","api_id":"api:invoke"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:use","run_id":"run:test","trace_id":"trace:test","seq":9,"thread_id":"main","source":"d0-test","payload":{"kind":"object_use","instance_id":"object:1","use_site_id":"site:object","use_kind":"read"}}"#,
            r#"{"schema_version":"bw.trace/0.1","record_id":"event:end","run_id":"run:test","trace_id":"trace:test","seq":10,"thread_id":"main","source":"d0-test","payload":{"kind":"trace_end","event_count":11}}"#,
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

#[cfg(unix)]
fn write_fake_trace_executable(path: &Path) {
    fs::write(
        path,
        r#"#!/bin/sh
set -eu
mkdir -p "$BW_TRACE_DIR"
cat > "$BW_TRACE_DIR/trace-segment-000001.jsonl" <<EOF
{"schema_version":"bw.trace/0.1","record_id":"event:start","run_id":"$BW_RUN_ID","trace_id":"$BW_TRACE_ID","seq":0,"thread_id":"main","source":"d0-fake","payload":{"kind":"trace_start","build_id":"$BW_BUILD_ID"}}
{"schema_version":"bw.trace/0.1","record_id":"event:owner-create","run_id":"$BW_RUN_ID","trace_id":"$BW_TRACE_ID","seq":1,"thread_id":"main","source":"d0-fake","payload":{"kind":"object_create","instance_id":"owner:1","site_id":"site:owner","object_kind":"external_owner","epoch":0,"address_diag":null}}
{"schema_version":"bw.trace/0.1","record_id":"event:object-create","run_id":"$BW_RUN_ID","trace_id":"$BW_TRACE_ID","seq":2,"thread_id":"main","source":"d0-fake","payload":{"kind":"object_create","instance_id":"object:1","site_id":"site:object","object_kind":"tracked","epoch":0,"address_diag":null}}
{"schema_version":"bw.trace/0.1","record_id":"event:register","run_id":"$BW_RUN_ID","trace_id":"$BW_TRACE_ID","seq":3,"thread_id":"main","source":"d0-fake","payload":{"kind":"callback_register","callback_instance_id":"callback:1","callback_site_id":"site:callback","owner_instance_id":"owner:1","registration_site_id":"site:register","api_id":"api:register"}}
{"schema_version":"bw.trace/0.1","record_id":"event:bind","run_id":"$BW_RUN_ID","trace_id":"$BW_TRACE_ID","seq":4,"thread_id":"main","source":"d0-fake","payload":{"kind":"capture_bind","callback_instance_id":"callback:1","callback_site_id":"site:callback","object_instance_id":"object:1","object_site_id":"site:object"}}
{"schema_version":"bw.trace/0.1","record_id":"event:drop","run_id":"$BW_RUN_ID","trace_id":"$BW_TRACE_ID","seq":5,"thread_id":"main","source":"d0-fake","payload":{"kind":"object_drop","instance_id":"object:1","drop_site_id":"site:drop"}}
{"schema_version":"bw.trace/0.1","record_id":"event:invoke","run_id":"$BW_RUN_ID","trace_id":"$BW_TRACE_ID","seq":6,"thread_id":"main","source":"d0-fake","payload":{"kind":"callback_invoke","callback_instance_id":"callback:1","invoke_site_id":"site:invoke","api_id":"api:invoke"}}
{"schema_version":"bw.trace/0.1","record_id":"event:end","run_id":"$BW_RUN_ID","trace_id":"$BW_TRACE_ID","seq":7,"thread_id":"main","source":"d0-fake","payload":{"kind":"trace_end","event_count":8}}
EOF
cat > "$BW_TRACE_DIR/trace-index.json" <<EOF
{"schema_version":"bw.trace-index/0.1","segments":[{"path":"trace-segment-000001.jsonl","event_start":0,"event_end":7,"event_count":8,"sha256":"0000000000000000000000000000000000000000000000000000000000000000","compressed":false}]}
EOF
"#,
    )
    .unwrap();
}
