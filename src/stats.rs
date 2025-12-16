// ============================================================================
// stats.rs - Real-time Statistics Tracking
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use parking_lot::RwLock;

/// Thread-safe statistics tracker
pub struct Statistics {
    checked: AtomicU64,
    found: AtomicU64,
    start_time: RwLock<Instant>,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            checked: AtomicU64::new(0),
            found: AtomicU64::new(0),
            start_time: RwLock::new(Instant::now()),
        }
    }

    pub fn increment_checked(&self) {
        self.checked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_found(&self) {
        self.found.fetch_add(1, Ordering::Relaxed);
    }

    pub fn checked(&self) -> u64 {
        self.checked.load(Ordering::Relaxed)
    }

    pub fn found(&self) -> u64 {
        self.found.load(Ordering::Relaxed)
    }

    pub fn elapsed(&self) -> f64 {
        self.start_time.read().elapsed().as_secs_f64()
    }

    pub fn get_rate(&self) -> f64 {
        let checked = self.checked() as f64;
        let elapsed = self.elapsed();
        if elapsed > 0.0 {
            checked / elapsed
        } else {
            0.0
        }
    }

    /// Reset statistics (useful when resuming from checkpoint)
    pub fn reset(&self) {
        self.checked.store(0, Ordering::Relaxed);
        self.found.store(0, Ordering::Relaxed);
        *self.start_time.write() = Instant::now();
    }
}