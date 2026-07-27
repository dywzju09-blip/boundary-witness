use std::{fs, path::Path};

use bw_model::{
    CheckpointEvent, CheckpointKind, RecordId, RunId, RuntimeEvent, RuntimeEventEnvelope,
    TRACE_SCHEMA_V01, TraceId,
};
use bw_runtime::{EventSink, JsonlSink, MemorySink, TraceIndex};

#[test]
fn memory_sink_can_snapshot_and_clear_iteration_events() {
    let sink = MemorySink::default();
    sink.emit(event(1)).unwrap();
    sink.emit(event(2)).unwrap();

    assert_eq!(sink.snapshot().len(), 2);
    sink.clear();
    assert!(sink.snapshot().is_empty());
}

#[test]
fn jsonl_sink_segments_decode_to_the_same_events_as_memory_sink() {
    let temp = tempfile::tempdir().unwrap();
    let memory = MemorySink::default();
    let jsonl = JsonlSink::builder(temp.path())
        .max_events_per_segment(3)
        .compress(false)
        .build()
        .unwrap();

    for seq in 1..=5 {
        let event = event(seq);
        memory.emit(event.clone()).unwrap();
        jsonl.emit(event).unwrap();
    }
    jsonl.flush().unwrap();

    let index = TraceIndex::from_path(&temp.path().join("trace-index.json")).unwrap();
    assert_eq!(index.segments.len(), 2);
    assert_eq!(index.segments[0].event_count, 3);
    assert_eq!(index.segments[1].event_count, 2);
    assert!(
        index
            .segments
            .iter()
            .all(|segment| segment.sha256.len() == 64)
    );

    let decoded = decode_segments(temp.path(), &index);
    assert_eq!(decoded, memory.snapshot());
    assert!(fs::read_dir(temp.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|ext| ext == "partial")
    }));
}

fn decode_segments(root: &Path, index: &TraceIndex) -> Vec<RuntimeEventEnvelope> {
    let mut events = Vec::new();
    for segment in &index.segments {
        assert!(!segment.compressed);
        let input = fs::read_to_string(root.join(&segment.path)).unwrap();
        for line in input.lines() {
            events.push(RuntimeEventEnvelope::from_json_str(line).unwrap());
        }
    }
    events
}

fn event(seq: u64) -> RuntimeEventEnvelope {
    RuntimeEventEnvelope {
        schema_version: TRACE_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("record:{seq}")),
        run_id: RunId::from("run:sinks"),
        trace_id: TraceId::from("trace:sinks"),
        seq,
        thread_id: "test".to_owned(),
        source: "sink-test".to_owned(),
        payload: RuntimeEvent::Checkpoint(CheckpointEvent {
            checkpoint: CheckpointKind::Registered,
        }),
    }
}
