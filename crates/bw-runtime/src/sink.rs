use bw_model::RuntimeEventEnvelope;

use crate::RuntimeError;

pub trait EventSink: Send + Sync + std::panic::RefUnwindSafe {
    fn emit(&self, event: RuntimeEventEnvelope) -> Result<(), RuntimeError>;
    fn flush(&self) -> Result<(), RuntimeError>;
}
