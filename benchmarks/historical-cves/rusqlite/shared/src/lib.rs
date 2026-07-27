pub mod artifact_staging;
pub mod blind_runner;
pub mod fuzzing;
pub mod runtime;
pub mod scalar_function;
pub mod update_hook;

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

#[derive(Clone, Debug)]
pub struct OwnedCounter {
    hits: Arc<AtomicI64>,
}

impl OwnedCounter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hits: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn record(&self, value: i64) {
        self.hits.fetch_add(value, Ordering::Relaxed);
    }

    #[must_use]
    pub fn hits(&self) -> i64 {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Default for OwnedCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct BorrowedCounter {
    hits: AtomicI64,
}

impl BorrowedCounter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hits: AtomicI64::new(0),
        }
    }

    pub fn record(&self, value: i64) {
        self.hits.fetch_add(value, Ordering::Relaxed);
    }

    #[must_use]
    pub fn hits(&self) -> i64 {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Default for BorrowedCounter {
    fn default() -> Self {
        Self::new()
    }
}
