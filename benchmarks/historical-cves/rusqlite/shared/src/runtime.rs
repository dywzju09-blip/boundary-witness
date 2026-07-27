use std::{env, sync::Arc};

use bw_model::{BuildId, RunId, TraceId};
use bw_runtime::{JsonlSink, MemorySink, RuntimeContext, RuntimeError};

pub const CREATE_SCALAR_FUNCTION_API_ID: &str = "api:rusqlite:create_scalar_function";
pub const UPDATE_HOOK_API_ID: &str = "api:rusqlite:update_hook";

pub fn benchmark_runtime(
    default_run_id: &str,
    default_trace_id: &str,
) -> Result<RuntimeContext, RuntimeError> {
    let run_id = env::var("BW_RUN_ID").unwrap_or_else(|_| default_run_id.to_owned());
    let trace_id = env::var("BW_TRACE_ID").unwrap_or_else(|_| default_trace_id.to_owned());
    if let Some(trace_dir) = env::var_os("BW_TRACE_DIR") {
        let compress = env::var("BW_TRACE_COMPRESS")
            .map(|value| !matches!(value.as_str(), "0" | "false" | "False" | "no" | "No"))
            .unwrap_or(false);
        let sink = Arc::new(JsonlSink::builder(trace_dir).compress(compress).build()?);
        Ok(RuntimeContext::new(
            RunId::from(run_id),
            TraceId::from(trace_id),
            sink,
        ))
    } else {
        let sink = Arc::new(MemorySink::default());
        Ok(RuntimeContext::new(
            RunId::from(run_id),
            TraceId::from(trace_id),
            sink,
        ))
    }
}

#[must_use]
pub fn benchmark_build_id(default_build_id: &str) -> BuildId {
    BuildId::from(env::var("BW_BUILD_ID").unwrap_or_else(|_| default_build_id.to_owned()))
}
