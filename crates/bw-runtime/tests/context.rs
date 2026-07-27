use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use bw_model::{BuildId, CheckpointKind, RuntimeEvent, RuntimeEventEnvelope};
use bw_runtime::{EventSink, RuntimeContext, RuntimeError};

#[test]
fn fresh_context_allocates_deterministic_logical_ids() {
    let sink = Arc::new(TestSink::default());
    let runtime = RuntimeContext::new(run("r1"), trace("t1"), sink);

    assert_eq!(runtime.next_object_id().0, "r1:object:1");
    assert_eq!(runtime.next_object_id().0, "r1:object:2");
    assert_eq!(runtime.next_callback_id().0, "r1:callback:1");
    assert_eq!(runtime.next_callback_id().0, "r1:callback:2");
    assert_eq!(runtime.next_owner_id().0, "r1:owner:1");
}

#[test]
fn emitted_events_use_context_envelope_and_monotonic_sequence() {
    let sink = Arc::new(TestSink::default());
    let runtime = RuntimeContext::new_with_source(
        run("r1"),
        trace("t1"),
        "rusqlite-update-hook-test",
        sink.clone(),
    );

    runtime.emit_trace_start(BuildId::from("build:1")).unwrap();
    runtime.emit_checkpoint(CheckpointKind::Registered).unwrap();
    runtime.emit_trace_end().unwrap();

    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].record_id.0, "r1:event:1");
    assert_eq!(events[1].record_id.0, "r1:event:2");
    assert_eq!(events[2].record_id.0, "r1:event:3");
    assert_eq!(events[0].seq, 1);
    assert_eq!(events[1].seq, 2);
    assert_eq!(events[2].seq, 3);
    assert!(events.iter().all(|event| event.run_id.0 == "r1"));
    assert!(events.iter().all(|event| event.trace_id.0 == "t1"));
    assert!(
        events
            .iter()
            .all(|event| event.source == "rusqlite-update-hook-test")
    );
    assert!(matches!(events[0].payload, RuntimeEvent::TraceStart(_)));
    assert!(matches!(events[1].payload, RuntimeEvent::Checkpoint(_)));
    assert!(matches!(events[2].payload, RuntimeEvent::TraceEnd(_)));
    assert_eq!(
        match &events[2].payload {
            RuntimeEvent::TraceEnd(end) => end.event_count,
            _ => unreachable!(),
        },
        2
    );
}

#[test]
fn finish_flushes_sink_before_reporting_deferred_error() {
    let sink = Arc::new(TestSink::fail_on_emit_and_flush());
    let runtime = RuntimeContext::new(run("r1"), trace("t1"), sink.clone());

    let emit_error = runtime
        .emit_checkpoint(CheckpointKind::Registered)
        .expect_err("emit failure should be returned to non-drop callers");
    assert_eq!(emit_error.code(), "BW-RUNTIME-SINK-EMIT");

    let finish_error = runtime
        .finish()
        .expect_err("finish should expose the first deferred sink error");
    assert_eq!(finish_error.code(), "BW-RUNTIME-SINK-EMIT");
    assert!(sink.flushed());
}

fn run(id: &str) -> bw_model::RunId {
    id.into()
}

fn trace(id: &str) -> bw_model::TraceId {
    id.into()
}

#[derive(Default)]
struct TestSink {
    events: Mutex<Vec<RuntimeEventEnvelope>>,
    emit_attempts: AtomicUsize,
    fail_emit: AtomicBool,
    fail_flush: AtomicBool,
    flushed: AtomicBool,
}

impl TestSink {
    fn fail_on_emit_and_flush() -> Self {
        Self {
            fail_emit: AtomicBool::new(true),
            fail_flush: AtomicBool::new(true),
            ..Self::default()
        }
    }

    fn events(&self) -> Vec<RuntimeEventEnvelope> {
        self.events.lock().unwrap().clone()
    }

    fn flushed(&self) -> bool {
        self.flushed.load(Ordering::SeqCst)
    }
}

impl EventSink for TestSink {
    fn emit(&self, event: RuntimeEventEnvelope) -> Result<(), RuntimeError> {
        self.emit_attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail_emit.load(Ordering::SeqCst) {
            return Err(RuntimeError::new(
                "BW-RUNTIME-SINK-EMIT",
                "test sink rejected event",
            ));
        }
        self.events.lock().unwrap().push(event);
        Ok(())
    }

    fn flush(&self) -> Result<(), RuntimeError> {
        self.flushed.store(true, Ordering::SeqCst);
        if self.fail_flush.load(Ordering::SeqCst) {
            return Err(RuntimeError::new(
                "BW-RUNTIME-SINK-FLUSH",
                "test sink rejected flush",
            ));
        }
        Ok(())
    }
}
