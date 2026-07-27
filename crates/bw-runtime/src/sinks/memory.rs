use std::sync::Mutex;

use bw_model::RuntimeEventEnvelope;

use crate::{EventSink, RuntimeError};

#[derive(Debug, Default)]
pub struct MemorySink {
    events: Mutex<Vec<RuntimeEventEnvelope>>,
}

impl MemorySink {
    #[must_use]
    pub fn snapshot(&self) -> Vec<RuntimeEventEnvelope> {
        self.events
            .lock()
            .expect("memory sink mutex should not be poisoned")
            .clone()
    }

    pub fn clear(&self) {
        self.events
            .lock()
            .expect("memory sink mutex should not be poisoned")
            .clear();
    }
}

impl EventSink for MemorySink {
    fn emit(&self, event: RuntimeEventEnvelope) -> Result<(), RuntimeError> {
        self.events
            .lock()
            .expect("memory sink mutex should not be poisoned")
            .push(event);
        Ok(())
    }

    fn flush(&self) -> Result<(), RuntimeError> {
        Ok(())
    }
}
