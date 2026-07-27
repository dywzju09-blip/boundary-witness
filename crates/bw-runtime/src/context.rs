use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use bw_model::{
    BuildId, CheckpointEvent, CheckpointKind, InstanceId, RecordId, RunId, RuntimeEvent,
    RuntimeEventEnvelope, TRACE_SCHEMA_V01, TraceEndEvent, TraceId, TraceStartEvent,
};

use crate::{AddressEpochs, EventSink, RuntimeError};

#[derive(Clone)]
pub struct RuntimeContext {
    inner: Arc<RuntimeInner>,
}

pub type RuntimeHandle = RuntimeContext;

struct RuntimeInner {
    run_id: RunId,
    trace_id: TraceId,
    source: String,
    sink: Arc<dyn EventSink>,
    next_object: AtomicU64,
    next_callback: AtomicU64,
    next_owner: AtomicU64,
    next_event: AtomicU64,
    epochs: Mutex<AddressEpochs>,
    deferred_error: Mutex<Option<RuntimeError>>,
}

impl RuntimeContext {
    #[must_use]
    pub fn new<S>(run_id: RunId, trace_id: TraceId, sink: Arc<S>) -> Self
    where
        S: EventSink + 'static,
    {
        Self::new_with_source(run_id, trace_id, "bw-runtime@0.1", sink)
    }

    #[must_use]
    pub fn new_with_source<S>(
        run_id: RunId,
        trace_id: TraceId,
        source: impl Into<String>,
        sink: Arc<S>,
    ) -> Self
    where
        S: EventSink + 'static,
    {
        let sink: Arc<dyn EventSink> = sink;
        Self {
            inner: Arc::new(RuntimeInner {
                run_id,
                trace_id,
                source: source.into(),
                sink,
                next_object: AtomicU64::new(1),
                next_callback: AtomicU64::new(1),
                next_owner: AtomicU64::new(1),
                next_event: AtomicU64::new(1),
                epochs: Mutex::new(AddressEpochs::default()),
                deferred_error: Mutex::new(None),
            }),
        }
    }

    #[must_use]
    pub fn next_object_id(&self) -> InstanceId {
        self.next_instance_id("object", &self.inner.next_object)
    }

    #[must_use]
    pub fn next_callback_id(&self) -> InstanceId {
        self.next_instance_id("callback", &self.inner.next_callback)
    }

    #[must_use]
    pub fn next_owner_id(&self) -> InstanceId {
        self.next_instance_id("owner", &self.inner.next_owner)
    }

    pub fn next_epoch_for_address(&self, address: usize) -> u64 {
        self.inner
            .epochs
            .lock()
            .expect("runtime epoch mutex should not be poisoned")
            .next_epoch(address)
    }

    pub fn emit_trace_start(&self, build_id: BuildId) -> Result<RecordId, RuntimeError> {
        self.emit(RuntimeEvent::TraceStart(TraceStartEvent { build_id }))
    }

    pub fn emit_checkpoint(&self, checkpoint: CheckpointKind) -> Result<RecordId, RuntimeError> {
        self.emit(RuntimeEvent::Checkpoint(CheckpointEvent { checkpoint }))
    }

    pub fn emit_trace_end(&self) -> Result<RecordId, RuntimeError> {
        let event_count = self
            .inner
            .next_event
            .load(Ordering::SeqCst)
            .saturating_sub(1);
        self.emit(RuntimeEvent::TraceEnd(TraceEndEvent { event_count }))
    }

    pub fn emit(&self, payload: RuntimeEvent) -> Result<RecordId, RuntimeError> {
        let event = self.envelope(payload);
        let record_id = event.record_id.clone();
        if let Err(error) = self.inner.sink.emit(event) {
            self.defer_error(error.clone());
            return Err(error);
        }
        Ok(record_id)
    }

    pub fn emit_deferred(&self, payload: RuntimeEvent) {
        if let Err(error) = self.emit(payload) {
            self.defer_error(error);
        }
    }

    pub fn finish(&self) -> Result<(), RuntimeError> {
        let flush_result = self.inner.sink.flush();
        let mut deferred = self
            .inner
            .deferred_error
            .lock()
            .expect("runtime deferred-error mutex should not be poisoned");
        if let Some(error) = deferred.take() {
            return Err(error);
        }
        flush_result
    }

    fn next_instance_id(&self, kind: &str, counter: &AtomicU64) -> InstanceId {
        let id = counter.fetch_add(1, Ordering::SeqCst);
        InstanceId::from(format!("{}:{kind}:{id}", self.inner.run_id))
    }

    fn envelope(&self, payload: RuntimeEvent) -> RuntimeEventEnvelope {
        let seq = self.inner.next_event.fetch_add(1, Ordering::SeqCst);
        RuntimeEventEnvelope {
            schema_version: TRACE_SCHEMA_V01.to_owned(),
            record_id: RecordId::from(format!("{}:event:{seq}", self.inner.run_id)),
            run_id: self.inner.run_id.clone(),
            trace_id: self.inner.trace_id.clone(),
            seq,
            thread_id: current_thread_id(),
            source: self.inner.source.clone(),
            payload,
        }
    }

    fn defer_error(&self, error: RuntimeError) {
        let mut deferred = self
            .inner
            .deferred_error
            .lock()
            .expect("runtime deferred-error mutex should not be poisoned");
        if deferred.is_none() {
            *deferred = Some(error);
        }
    }
}

fn current_thread_id() -> String {
    std::thread::current()
        .name()
        .map_or_else(|| "unnamed".to_owned(), ToOwned::to_owned)
}
