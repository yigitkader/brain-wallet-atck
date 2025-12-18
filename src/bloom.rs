use bloom::{BloomFilter as InternalBloom, ASMS};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::Result;

pub struct BloomFilterManager {
    active: parking_lot::RwLock<InternalBloom>,
    previous: parking_lot::RwLock<Option<InternalBloom>>,
    add_lock: parking_lot::Mutex<()>,
    active_count: AtomicU64,
    previous_count: AtomicU64,
    capacity: usize,
    false_positive_rate: f64,
}

impl BloomFilterManager {
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        let items_count = capacity;
        let fp_rate = false_positive_rate;

        let filter = InternalBloom::with_rate(fp_rate as f32, items_count as u32);

        Self {
            active: parking_lot::RwLock::new(filter),
            previous: parking_lot::RwLock::new(None),
            add_lock: parking_lot::Mutex::new(()),
            active_count: AtomicU64::new(0),
            previous_count: AtomicU64::new(0),
            capacity,
            false_positive_rate,
        }
    }

    /// Check if pattern exists in bloom filter
    pub fn contains<T: Hash>(&self, item: &T) -> bool {
        let hash = Self::hash_item(item);
        if self.active.read().contains(&hash) {
            return true;
        }
        self.previous
            .read()
            .as_ref()
            .is_some_and(|prev| prev.contains(&hash))
    }

    /// Add pattern to bloom filter (with atomic capacity check)
    /// FIXED: Atomic check-and-add to prevent race conditions
    pub fn add<T: Hash>(&self, item: &T) -> Result<()> {
        // Serialize rotate + count + insert to avoid races between fetch_add/insert and rotation.
        let _guard = self.add_lock.lock();

        // If active filter is near capacity, rotate it to "previous" instead of clearing.
        // This avoids losing duplicate knowledge for already-seen patterns.
        self.rotate_if_needed();

        let current = self.active_count.load(Ordering::Acquire);
        if current >= self.capacity as u64 {
            self.rotate_force();
        }

        // Safe to increment now (serialized)
        let new_count = self.active_count.fetch_add(1, Ordering::AcqRel) + 1;
        if new_count > self.capacity as u64 {
            // Should be extremely rare even with the guard, but keep it safe.
            self.active_count.fetch_sub(1, Ordering::AcqRel);
            self.rotate_force();
            self.active_count.fetch_add(1, Ordering::AcqRel);
        }

        let hash = Self::hash_item(item);
        self.active.write().insert(&hash);

        // Opportunistic rotate for subsequent inserts.
        self.rotate_if_needed();
        Ok(())
    }

    fn rotate_if_needed(&self) {
        let current = self.active_count.load(Ordering::Acquire);
        let threshold = self.capacity as u64 * 95 / 100;
        if current < threshold {
            return;
        }

        // Single-writer rotate using active write lock; keep previous coherent.
        let mut active = self.active.write();
        let mut previous = self.previous.write();

        // Double-check under lock to avoid unnecessary rotations.
        let current_locked = self.active_count.load(Ordering::Acquire);
        if current_locked < threshold {
            return;
        }

        use tracing::warn;
        warn!(
            "Bloom filter near capacity ({} / {}), rotating buffers...",
            current_locked,
            self.capacity
        );

        let new_active = InternalBloom::with_rate(self.false_positive_rate as f32, self.capacity as u32);
        let old_active = std::mem::replace(&mut *active, new_active);
        *previous = Some(old_active);

        self.previous_count.store(current_locked, Ordering::Release);
        self.active_count.store(0, Ordering::Release);
    }

    fn rotate_force(&self) {
        // Single-writer rotate using active write lock; keep previous coherent.
        let mut active = self.active.write();
        let mut previous = self.previous.write();

        let current_locked = self.active_count.load(Ordering::Acquire);

        use tracing::warn;
        warn!(
            "Bloom filter at capacity ({} / {}), forcing rotation...",
            current_locked,
            self.capacity
        );

        let new_active = InternalBloom::with_rate(self.false_positive_rate as f32, self.capacity as u32);
        let old_active = std::mem::replace(&mut *active, new_active);
        *previous = Some(old_active);

        self.previous_count.store(current_locked, Ordering::Release);
        self.active_count.store(0, Ordering::Release);
    }

    fn hash_item<T: Hash>(item: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        item.hash(&mut hasher);
        hasher.finish()
    }

    pub fn len(&self) -> usize {
        (self.active_count.load(Ordering::Relaxed) + self.previous_count.load(Ordering::Relaxed)) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn is_near_capacity(&self) -> bool {
        let current_count = self.active_count.load(Ordering::Relaxed) as usize;
        current_count >= (self.capacity * 95 / 100)
    }

    pub fn clear(&self) {
        self.active.write().clear();
        *self.previous.write() = None;
        self.active_count.store(0, Ordering::Release);
        self.previous_count.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter() {
        let bloom = BloomFilterManager::new(1000, 0.01);

        let item1 = "test1";
        let item2 = "test2";

        bloom.add(&item1).unwrap();
        assert!(bloom.contains(&item1));
        assert!(!bloom.contains(&item2));
    }

    #[test]
    fn test_bloom_filter_auto_rotate() {
        let bloom = BloomFilterManager::new(100, 0.01);

        for i in 0..95 {
            bloom.add(&format!("item_{}", i)).unwrap();
        }

        assert_eq!(bloom.len(), 95);

        bloom.add(&"item_95").unwrap();

        // Rotation keeps previous entries while starting a new active filter.
        assert_eq!(bloom.len(), 96);
        assert!(bloom.contains(&"item_95"));
        assert!(bloom.contains(&"item_0"));
    }

    #[test]
    fn test_bloom_filter_capacity_limit() {
        let bloom = BloomFilterManager::new(10, 0.01);

        for i in 0..9 {
            bloom.add(&format!("item_{}", i)).unwrap();
        }

        bloom.add(&"item_9").unwrap();

        // Rotation keeps previous entries while starting a new active filter.
        assert_eq!(bloom.len(), 10);
    }

    #[test]
    fn test_bloom_filter_clear() {
        let bloom = BloomFilterManager::new(1000, 0.01);

        bloom.add(&"item1").unwrap();
        bloom.add(&"item2").unwrap();
        assert_eq!(bloom.len(), 2);

        bloom.clear();
        assert_eq!(bloom.len(), 0);
        assert!(!bloom.contains(&"item1"));

        bloom.add(&"item3").unwrap();
        assert_eq!(bloom.len(), 1);
        assert!(bloom.contains(&"item3"));
    }

    /// Test concurrent access (multi-threaded)
    #[test]
    fn test_bloom_filter_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let bloom = Arc::new(BloomFilterManager::new(10000, 0.01));
        let mut handles = vec![];

        for thread_id in 0..10 {
            let bloom_clone = bloom.clone();
            let handle = thread::spawn(move || {
                for i in 0..100 {
                    let item = format!("thread_{}_item_{}", thread_id, i);
                    let _ = bloom_clone.add(&item);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have added ~1000 items (some may be deduplicated)
        assert!(bloom.len() <= 1000);
        assert!(bloom.len() >= 900); // Allow some duplicates
    }

    #[test]
    fn test_bloom_filter_concurrent_overflow_never_errors() {
        use std::sync::Arc;
        use std::thread;

        // Tiny capacity to force frequent rotations and hit overflow races.
        let bloom = Arc::new(BloomFilterManager::new(32, 0.01));
        let mut handles = vec![];

        for t in 0..8 {
            let bloom_clone = bloom.clone();
            handles.push(thread::spawn(move || {
                for i in 0..200 {
                    let item = format!("t{}_{}", t, i);
                    bloom_clone.add(&item).expect("add() should not error under concurrent overflow/rotation");
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // We inserted 1600 unique items; bloom is probabilistic and rotates,
        // so we only sanity-check that some items were recorded.
        assert!(!bloom.is_empty());
    }
}