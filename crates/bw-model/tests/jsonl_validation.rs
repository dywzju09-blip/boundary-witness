use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

use bw_model::{
    BuildId, JsonlReader, RecordId, RunId, RuntimeEvent, RuntimeEventEnvelope, TRACE_SCHEMA_V01,
    TraceEndEvent, TraceId, TraceStartEvent, validate_runtime_path,
};

const MAX_LINE_BYTES: usize = 1024 * 1024;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/malformed")
        .join(name)
}

fn envelope(seq: u64, payload: RuntimeEvent) -> RuntimeEventEnvelope {
    RuntimeEventEnvelope {
        schema_version: TRACE_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("event:{seq}")),
        run_id: RunId::from("run:test"),
        trace_id: TraceId::from("trace:test"),
        seq,
        thread_id: "main".to_owned(),
        source: "bw-runtime".to_owned(),
        payload,
    }
}

fn json_line(event: &RuntimeEventEnvelope) -> String {
    serde_json::to_string(event).expect("event should serialize")
}

#[test]
fn duplicate_sequence_is_a_model_error_not_a_finding() {
    let error = validate_runtime_path(fixture("runtime-duplicate-seq.jsonl"), MAX_LINE_BYTES)
        .expect_err("duplicate sequence must fail validation");

    assert_eq!(error.code(), "BW-TRACE-SEQ-DUPLICATE");
    assert_eq!(error.line(), Some(3));
    assert!(
        error
            .path()
            .is_some_and(|path| path.ends_with("runtime-duplicate-seq.jsonl"))
    );
}

#[test]
fn missing_object_reference_is_rejected() {
    let error = validate_runtime_path(fixture("runtime-missing-object.jsonl"), MAX_LINE_BYTES)
        .expect_err("missing object must fail validation");

    assert_eq!(error.code(), "BW-TRACE-OBJECT-MISSING");
    assert_eq!(error.line(), Some(2));
}

#[test]
fn malformed_json_reports_physical_line_after_empty_line() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let path = directory.path().join("malformed.jsonl");
    let start = envelope(
        0,
        RuntimeEvent::TraceStart(TraceStartEvent {
            build_id: BuildId::from("build:test"),
        }),
    );
    fs::write(&path, format!("\n{}\nnot-json\n", json_line(&start)))
        .expect("fixture should be written");

    let error = validate_runtime_path(&path, MAX_LINE_BYTES)
        .expect_err("malformed JSON must fail validation");
    assert_eq!(error.code(), "BW-JSON-INVALID");
    assert_eq!(error.line(), Some(3));
    assert_eq!(error.path(), Some(path.as_path()));
}

#[test]
fn overlong_line_is_rejected_before_unbounded_reading() {
    let input = format!("{}\n", "x".repeat(64));
    let mut reader = JsonlReader::<_, RuntimeEventEnvelope>::new(
        Cursor::new(input.into_bytes()),
        PathBuf::from("memory.jsonl"),
        16,
    );

    let error = reader
        .next()
        .expect("reader should produce an error")
        .expect_err("overlong line must fail");
    assert_eq!(error.code(), "BW-JSONL-LINE-TOO-LONG");
    assert_eq!(error.line(), Some(1));
}

#[test]
fn compressed_runtime_stream_is_validated() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let path = directory.path().join("trace.jsonl.zst");
    write_zstd_trace(&path);

    let summary =
        validate_runtime_path(&path, MAX_LINE_BYTES).expect("compressed trace should be valid");
    assert_eq!(summary.record_count, 2);
    assert_eq!(summary.trace_count, 1);
}

fn write_zstd_trace(path: &Path) {
    let events = [
        envelope(
            0,
            RuntimeEvent::TraceStart(TraceStartEvent {
                build_id: BuildId::from("build:test"),
            }),
        ),
        envelope(1, RuntimeEvent::TraceEnd(TraceEndEvent { event_count: 2 })),
    ];
    let mut encoder =
        zstd::stream::write::Encoder::new(Vec::new(), 0).expect("zstd encoder should be created");
    for event in &events {
        writeln!(encoder, "{}", json_line(event)).expect("event should be compressed");
    }
    let compressed = encoder.finish().expect("zstd stream should finish");
    fs::write(path, compressed).expect("compressed trace should be written");
}
