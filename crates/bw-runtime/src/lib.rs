//! BoundaryWitness 的公共运行时边界。

mod callback;
mod context;
mod epoch;
mod error;
mod sink;
mod sinks;
mod tracked;

pub use callback::CallbackToken;
pub use context::{RuntimeContext, RuntimeHandle};
pub use epoch::AddressEpochs;
pub use error::RuntimeError;
pub use sink::EventSink;
pub use sinks::{JsonlSink, JsonlSinkBuilder, MemorySink, TraceIndex, TraceSegment};
pub use tracked::Tracked;
