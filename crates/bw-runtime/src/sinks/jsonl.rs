use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use bw_model::RuntimeEventEnvelope;
use sha2::{Digest, Sha256};

use crate::{
    EventSink, RuntimeError,
    sinks::index::{TraceIndex, TraceSegment},
};

const DEFAULT_MAX_EVENTS_PER_SEGMENT: u64 = 1_000_000;
const DEFAULT_MAX_BYTES_PER_SEGMENT: u64 = 128 * 1024 * 1024;

#[derive(Debug)]
pub struct JsonlSink {
    inner: Mutex<JsonlSinkInner>,
}

#[derive(Debug)]
pub struct JsonlSinkBuilder {
    root: PathBuf,
    max_events_per_segment: u64,
    max_bytes_per_segment: u64,
    compress: bool,
}

impl JsonlSink {
    #[must_use]
    pub fn builder(root: impl AsRef<Path>) -> JsonlSinkBuilder {
        JsonlSinkBuilder {
            root: root.as_ref().to_path_buf(),
            max_events_per_segment: DEFAULT_MAX_EVENTS_PER_SEGMENT,
            max_bytes_per_segment: DEFAULT_MAX_BYTES_PER_SEGMENT,
            compress: true,
        }
    }
}

impl JsonlSinkBuilder {
    #[must_use]
    pub fn max_events_per_segment(mut self, max_events_per_segment: u64) -> Self {
        self.max_events_per_segment = max_events_per_segment.max(1);
        self
    }

    #[must_use]
    pub fn max_bytes_per_segment(mut self, max_bytes_per_segment: u64) -> Self {
        self.max_bytes_per_segment = max_bytes_per_segment.max(1);
        self
    }

    #[must_use]
    pub fn compress(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    pub fn build(self) -> Result<JsonlSink, RuntimeError> {
        fs::create_dir_all(&self.root)
            .map_err(|error| RuntimeError::sink_io("create trace directory", error))?;
        Ok(JsonlSink {
            inner: Mutex::new(JsonlSinkInner {
                root: self.root,
                max_events_per_segment: self.max_events_per_segment,
                max_bytes_per_segment: self.max_bytes_per_segment,
                compress: self.compress,
                next_segment: 1,
                current: None,
                index: TraceIndex::default(),
            }),
        })
    }
}

impl EventSink for JsonlSink {
    fn emit(&self, event: RuntimeEventEnvelope) -> Result<(), RuntimeError> {
        self.inner
            .lock()
            .expect("jsonl sink mutex should not be poisoned")
            .emit(event)
    }

    fn flush(&self) -> Result<(), RuntimeError> {
        self.inner
            .lock()
            .expect("jsonl sink mutex should not be poisoned")
            .flush()
    }
}

#[derive(Debug)]
struct JsonlSinkInner {
    root: PathBuf,
    max_events_per_segment: u64,
    max_bytes_per_segment: u64,
    compress: bool,
    next_segment: u64,
    current: Option<OpenSegment>,
    index: TraceIndex,
}

impl JsonlSinkInner {
    fn emit(&mut self, event: RuntimeEventEnvelope) -> Result<(), RuntimeError> {
        if self.current.is_none() {
            self.open_segment(event.seq)?;
        }

        let line = serde_json::to_string(&event)
            .map_err(|error| RuntimeError::new("BW-RUNTIME-SINK-JSON", error.to_string()))?;
        let current = self
            .current
            .as_mut()
            .expect("segment should be open before writing event");
        current
            .file
            .write_all(line.as_bytes())
            .and_then(|_| current.file.write_all(b"\n"))
            .map_err(|error| RuntimeError::sink_io("write trace event", error))?;
        current.event_end = event.seq;
        current.event_count += 1;
        current.byte_count += line.len() as u64 + 1;

        if current.event_count >= self.max_events_per_segment
            || current.byte_count >= self.max_bytes_per_segment
        {
            self.close_current_segment()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), RuntimeError> {
        self.close_current_segment()?;
        self.write_index()
    }

    fn open_segment(&mut self, event_start: u64) -> Result<(), RuntimeError> {
        let ordinal = self.next_segment;
        self.next_segment += 1;
        let partial_path = self
            .root
            .join(format!("trace-segment-{ordinal:06}.jsonl.partial"));
        let file = File::create(&partial_path)
            .map_err(|error| RuntimeError::sink_io("create trace segment", error))?;
        self.current = Some(OpenSegment {
            ordinal,
            event_start,
            event_end: event_start,
            event_count: 0,
            byte_count: 0,
            partial_path,
            file,
        });
        Ok(())
    }

    fn close_current_segment(&mut self) -> Result<(), RuntimeError> {
        let Some(mut current) = self.current.take() else {
            return Ok(());
        };
        current
            .file
            .flush()
            .and_then(|_| current.file.sync_all())
            .map_err(|error| RuntimeError::sink_io("flush trace segment", error))?;
        drop(current.file);

        let final_name = if self.compress {
            format!("trace-segment-{:06}.jsonl.zst", current.ordinal)
        } else {
            format!("trace-segment-{:06}.jsonl", current.ordinal)
        };
        let final_path = self.root.join(&final_name);

        if self.compress {
            compress_to_zstd(&current.partial_path, &final_path)?;
            fs::remove_file(&current.partial_path)
                .map_err(|error| RuntimeError::sink_io("remove partial trace segment", error))?;
        } else {
            fs::rename(&current.partial_path, &final_path)
                .map_err(|error| RuntimeError::sink_io("finalize trace segment", error))?;
        }

        let sha256 = sha256_file(&final_path)?;
        self.index.segments.push(TraceSegment {
            path: final_name,
            event_start: current.event_start,
            event_end: current.event_end,
            event_count: current.event_count,
            sha256,
            compressed: self.compress,
        });
        self.write_index()
    }

    fn write_index(&self) -> Result<(), RuntimeError> {
        let partial = self.root.join("trace-index.json.partial");
        let final_path = self.root.join("trace-index.json");
        let json = serde_json::to_vec_pretty(&self.index)
            .map_err(|error| RuntimeError::new("BW-RUNTIME-SINK-JSON", error.to_string()))?;
        fs::write(&partial, json)
            .map_err(|error| RuntimeError::sink_io("write trace index", error))?;
        fs::rename(&partial, &final_path)
            .map_err(|error| RuntimeError::sink_io("finalize trace index", error))?;
        Ok(())
    }
}

#[derive(Debug)]
struct OpenSegment {
    ordinal: u64,
    event_start: u64,
    event_end: u64,
    event_count: u64,
    byte_count: u64,
    partial_path: PathBuf,
    file: File,
}

fn compress_to_zstd(input_path: &Path, output_path: &Path) -> Result<(), RuntimeError> {
    let input = File::open(input_path)
        .map_err(|error| RuntimeError::sink_io("open partial trace", error))?;
    let output = File::create(output_path)
        .map_err(|error| RuntimeError::sink_io("create compressed trace", error))?;
    zstd::stream::copy_encode(input, output, 0)
        .map_err(|error| RuntimeError::sink_io("compress trace segment", error))?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, RuntimeError> {
    let mut file =
        File::open(path).map_err(|error| RuntimeError::sink_io("open finalized trace", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| RuntimeError::sink_io("hash finalized trace", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
