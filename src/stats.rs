// ============================================================================
// stats.rs - Real-time Statistics Tracking
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Thread-safe statistics tracker
pub struct Statistics {
    checked: AtomicU64,
    found: AtomicU64,
    start_time: AtomicU64, // Unix timestamp in seconds (thread-safe)
}

impl Statistics {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            checked: AtomicU64::new(0),
            found: AtomicU64::new(0),
            start_time: AtomicU64::new(now),
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
        let start = self.start_time.load(Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (now - start) as f64
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.start_time.store(now, Ordering::Relaxed);
    }
}