use std::{fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::RuntimeError;

pub const TRACE_INDEX_SCHEMA_V01: &str = "bw.trace-index/0.1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceSegment {
    pub path: String,
    pub event_start: u64,
    pub event_end: u64,
    pub event_count: u64,
    pub sha256: String,
    pub compressed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceIndex {
    pub schema_version: String,
    pub segments: Vec<TraceSegment>,
}

impl Default for TraceIndex {
    fn default() -> Self {
        Self {
            schema_version: TRACE_INDEX_SCHEMA_V01.to_owned(),
            segments: Vec::new(),
        }
    }
}

impl TraceIndex {
    pub fn from_path(path: &Path) -> Result<Self, RuntimeError> {
        let input = fs::read_to_string(path)
            .map_err(|error| RuntimeError::sink_io("read trace index", error))?;
        let index = serde_json::from_str::<Self>(&input)
            .map_err(|error| RuntimeError::new("BW-RUNTIME-SINK-JSON", error.to_string()))?;
        if index.schema_version != TRACE_INDEX_SCHEMA_V01 {
            return Err(RuntimeError::new(
                "BW-RUNTIME-SINK-SCHEMA",
                format!("unsupported trace index schema {}", index.schema_version),
            ));
        }
        Ok(index)
    }
}
