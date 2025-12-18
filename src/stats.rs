use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Thread-safe statistics tracker
pub struct Statistics {
    checked: AtomicU64,
    found: AtomicU64,
    start_time: AtomicU64,
}

impl Default for Statistics {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn reset(&self) {
        self.checked.store(0, Ordering::Relaxed);
        self.found.store(0, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.start_time.store(now, Ordering::Relaxed);
    }

    /// FIXED: Always restore start_time if provided (don't keep current)
    pub fn restore(&self, checked: u64, found: u64, start_time: Option<u64>) {
        self.checked.store(checked, Ordering::Relaxed);
        self.found.store(found, Ordering::Relaxed);

        // FIXED: Always restore start_time, or use current if not provided
        let time_to_set = start_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        self.start_time.store(time_to_set, Ordering::Relaxed);
    }

    pub fn start_time(&self) -> u64 {
        self.start_time.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statistics_basic() {
        let stats = Statistics::new();

        assert_eq!(stats.checked(), 0);
        assert_eq!(stats.found(), 0);

        stats.increment_checked();
        stats.increment_found();

        assert_eq!(stats.checked(), 1);
        assert_eq!(stats.found(), 1);
    }

    #[test]
    fn test_statistics_restore() {
        let stats = Statistics::new();

        stats.restore(100, 5, Some(1234567890));

        assert_eq!(stats.checked(), 100);
        assert_eq!(stats.found(), 5);
        assert_eq!(stats.start_time(), 1234567890);
    }

    #[test]
    fn test_statistics_restore_without_start_time() {
        let stats = Statistics::new();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        stats.restore(50, 2, None);

        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(stats.checked(), 50);
        assert_eq!(stats.found(), 2);
        assert!(stats.start_time() >= before);
        assert!(stats.start_time() <= after);
    }

    #[test]
    fn test_statistics_rate_calculation() {
        let stats = Statistics::new();

        // Set a fixed start time (1 second ago)
        let one_sec_ago = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - 1;
        stats.restore(100, 5, Some(one_sec_ago));

        let rate = stats.get_rate();
        assert!(rate >= 50.0); // ~100 checked / ~2 seconds
    }

    #[test]
    fn test_statistics_reset() {
        let stats = Statistics::new();

        stats.increment_checked();
        stats.increment_found();

        stats.reset();

        assert_eq!(stats.checked(), 0);
        assert_eq!(stats.found(), 0);
    }
}