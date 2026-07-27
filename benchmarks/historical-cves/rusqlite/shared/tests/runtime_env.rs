use std::{fs, sync::Mutex};

use bw_model::{BuildId, TRACE_SCHEMA_V01};
use rusqlite_lab_shared::runtime::{benchmark_build_id, benchmark_runtime};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn benchmark_runtime_uses_memory_sink_without_trace_dir_env() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("BW_TRACE_DIR");
    std::env::remove_var("BW_RUN_ID");
    std::env::remove_var("BW_TRACE_ID");
    std::env::remove_var("BW_BUILD_ID");

    let runtime = benchmark_runtime("run:default", "trace:default")
        .expect("memory runtime should be constructed");
    runtime
        .emit_trace_start(benchmark_build_id("build:default"))
        .unwrap();
    runtime.emit_trace_end().unwrap();
    runtime.finish().unwrap();
}

#[test]
fn benchmark_runtime_writes_file_trace_when_trace_dir_env_is_set() {
    let _guard = ENV_LOCK.lock().unwrap();
    let trace_dir =
        std::env::temp_dir().join(format!("bw-runtime-env-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&trace_dir);
    std::env::set_var("BW_TRACE_DIR", &trace_dir);
    std::env::set_var("BW_TRACE_COMPRESS", "0");
    std::env::set_var("BW_RUN_ID", "run:env");
    std::env::set_var("BW_TRACE_ID", "trace:env");
    std::env::set_var("BW_BUILD_ID", "build:env");

    let runtime =
        benchmark_runtime("run:default", "trace:default").expect("file runtime should build");
    runtime
        .emit_trace_start(benchmark_build_id("build:default"))
        .unwrap();
    runtime.emit_trace_end().unwrap();
    runtime.finish().unwrap();

    let index = fs::read_to_string(trace_dir.join("trace-index.json"))
        .expect("trace index should be written");
    assert!(index.contains("trace-segment-000001.jsonl"));
    let segment = fs::read_to_string(trace_dir.join("trace-segment-000001.jsonl"))
        .expect("trace segment should be written");
    assert!(segment.contains(TRACE_SCHEMA_V01));
    assert!(segment.contains("\"build_id\":\"build:env\""));

    std::env::remove_var("BW_TRACE_DIR");
    std::env::remove_var("BW_TRACE_COMPRESS");
    std::env::remove_var("BW_RUN_ID");
    std::env::remove_var("BW_TRACE_ID");
    std::env::remove_var("BW_BUILD_ID");
    let _ = fs::remove_dir_all(&trace_dir);
}

#[test]
fn benchmark_build_id_falls_back_to_default() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("BW_BUILD_ID");

    assert_eq!(
        benchmark_build_id("build:default"),
        BuildId::from("build:default")
    );
}
