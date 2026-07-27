use std::{
    env, fs,
    os::raw::c_int,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::Instant,
};

use bw_experiment::{ObjectiveClassification, ObjectiveKind};
use rusqlite_lab_shared::fuzzing::{HarnessOutcome, HarnessResult};

unsafe extern "C" {
    fn atexit(callback: extern "C" fn()) -> c_int;
}

static STATE: OnceLock<Option<CounterState>> = OnceLock::new();

struct CounterState {
    path: PathBuf,
    started: Instant,
    executions: AtomicU64,
    valid_sequence_count: AtomicU64,
    invalid_sequence_count: AtomicU64,
    progress_count: AtomicU64,
    secondary_count: AtomicU64,
    primary_count: AtomicU64,
    tool_error_count: AtomicU64,
    first_primary_ms: AtomicU64,
    feedback_snapshot_coverage_count: AtomicU64,
}

impl CounterState {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            started: Instant::now(),
            executions: AtomicU64::new(0),
            valid_sequence_count: AtomicU64::new(0),
            invalid_sequence_count: AtomicU64::new(0),
            progress_count: AtomicU64::new(0),
            secondary_count: AtomicU64::new(0),
            primary_count: AtomicU64::new(0),
            tool_error_count: AtomicU64::new(0),
            first_primary_ms: AtomicU64::new(u64::MAX),
            feedback_snapshot_coverage_count: AtomicU64::new(0),
        }
    }

    fn record(&self, result: &HarnessResult, classification: &ObjectiveClassification) {
        let executions = self.executions.fetch_add(1, Ordering::Relaxed) + 1;
        if result.outcome == HarnessOutcome::InvalidInput {
            self.invalid_sequence_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.valid_sequence_count.fetch_add(1, Ordering::Relaxed);
        }

        match classification.objective_kind {
            ObjectiveKind::Primary => {
                self.primary_count.fetch_add(1, Ordering::Relaxed);
                let elapsed = self.started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                let _ = self.first_primary_ms.compare_exchange(
                    u64::MAX,
                    elapsed,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            ObjectiveKind::Progress => {
                self.progress_count.fetch_add(1, Ordering::Relaxed);
            }
            ObjectiveKind::Secondary => {
                self.secondary_count.fetch_add(1, Ordering::Relaxed);
            }
            ObjectiveKind::None => {}
        }
        if !classification.secondary_findings.is_empty() {
            self.secondary_count.fetch_add(1, Ordering::Relaxed);
        }
        if executions % 256 == 0 || classification.objective_kind == ObjectiveKind::Primary {
            self.flush();
        }
    }

    fn record_tool_error(&self) {
        self.tool_error_count.fetch_add(1, Ordering::Relaxed);
        self.flush();
    }

    #[allow(dead_code)]
    fn record_feedback_snapshot_coverage(&self) {
        let coverage_count = self
            .feedback_snapshot_coverage_count
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        if coverage_count % 16 == 0 {
            self.flush();
        }
    }

    fn flush(&self) {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let first_primary_ms = self.first_primary_ms.load(Ordering::Relaxed);
        let first_primary = if first_primary_ms == u64::MAX {
            "null".to_owned()
        } else {
            first_primary_ms.to_string()
        };
        let body = format!(
            concat!(
                "{{\n",
                "  \"schema_version\": \"boundary-witness.d1-fuzz-counters/0.1\",\n",
                "  \"executions\": {},\n",
                "  \"valid_sequence_count\": {},\n",
                "  \"invalid_sequence_count\": {},\n",
                "  \"progress_count\": {},\n",
                "  \"secondary_count\": {},\n",
                "  \"primary_count\": {},\n",
                "  \"tool_error_count\": {},\n",
                "  \"time_to_first_primary_ms\": {},\n",
                "  \"feedback_snapshot_coverage_count\": {}\n",
                "}}\n"
            ),
            self.executions.load(Ordering::Relaxed),
            self.valid_sequence_count.load(Ordering::Relaxed),
            self.invalid_sequence_count.load(Ordering::Relaxed),
            self.progress_count.load(Ordering::Relaxed),
            self.secondary_count.load(Ordering::Relaxed),
            self.primary_count.load(Ordering::Relaxed),
            self.tool_error_count.load(Ordering::Relaxed),
            first_primary,
            self.feedback_snapshot_coverage_count
                .load(Ordering::Relaxed),
        );
        let tmp = self.path.with_extension("json.tmp");
        if fs::write(&tmp, body).is_ok() {
            let _ = fs::rename(tmp, &self.path);
        }
    }
}

pub fn record(result: &HarnessResult, classification: &ObjectiveClassification) {
    if let Some(state) = state() {
        state.record(result, classification);
    }
}

pub fn record_tool_error() {
    if let Some(state) = state() {
        state.record_tool_error();
    }
}

#[allow(dead_code)]
pub fn record_feedback_snapshot_coverage() {
    if let Some(state) = state() {
        state.record_feedback_snapshot_coverage();
    }
}

pub fn flush_now() {
    if let Some(state) = state() {
        state.flush();
    }
}

fn state() -> Option<&'static CounterState> {
    STATE
        .get_or_init(|| {
            let path = env::var_os("BW_D1_COUNTERS_PATH").map(PathBuf::from)?;
            if unsafe { atexit(flush_at_exit) } != 0 {
                return None;
            }
            Some(CounterState::new(path))
        })
        .as_ref()
}

extern "C" fn flush_at_exit() {
    if let Some(Some(state)) = STATE.get() {
        state.flush();
    }
}
