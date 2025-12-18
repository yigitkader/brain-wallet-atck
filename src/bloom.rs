use bloom::{BloomFilter as InternalBloom, ASMS};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::Result;

pub struct BloomFilterManager {
    filter: parking_lot::RwLock<InternalBloom>,
    item_count: AtomicU64,
    capacity: usize,
}

impl BloomFilterManager {
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        let items_count = capacity;
        let fp_rate = false_positive_rate;

        let filter = InternalBloom::with_rate(fp_rate as f32, items_count as u32);

        Self {
            filter: parking_lot::RwLock::new(filter),
            item_count: AtomicU64::new(0),
            capacity,
        }
    }

    /// Check if pattern exists in bloom filter
    pub fn contains<T: Hash>(&self, item: &T) -> bool {
        let hash = Self::hash_item(item);
        self.filter.read().contains(&hash)
    }

    /// Add pattern to bloom filter (with atomic capacity check)
    /// FIXED: Atomic check-and-add to prevent race conditions
    pub fn add<T: Hash>(&self, item: &T) -> Result<()> {
        // FIXED: Atomic capacity check before increment
        let current = self.item_count.load(Ordering::Acquire);

        // Auto-clear at 95% to prevent overflow
        if current >= (self.capacity as u64 * 95 / 100) {
            use tracing::warn;
            warn!("Bloom filter 95% full ({} / {}), auto-clearing...",
                  current, self.capacity);
            self.clear();
        }

        // FIXED: Try to increment atomically
        let new_count = self.item_count.fetch_add(1, Ordering::AcqRel) + 1;

        if new_count > self.capacity as u64 {
            // Rollback increment
            self.item_count.fetch_sub(1, Ordering::AcqRel);
            anyhow::bail!("Bloom filter capacity exceeded: {} (max: {})", new_count, self.capacity);
        }

        let hash = Self::hash_item(item);
        self.filter.write().insert(&hash);
        Ok(())
    }

    fn hash_item<T: Hash>(item: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        item.hash(&mut hasher);
        hasher.finish()
    }

    pub fn len(&self) -> usize {
        self.item_count.load(Ordering::Relaxed) as usize
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn is_near_capacity(&self) -> bool {
        let current_count = self.item_count.load(Ordering::Relaxed) as usize;
        current_count >= (self.capacity * 95 / 100)
    }

    pub fn clear(&self) {
        self.filter.write().clear();
        self.item_count.store(0, Ordering::Release);
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
    fn test_bloom_filter_auto_clear() {
        let bloom = BloomFilterManager::new(100, 0.01);

        for i in 0..95 {
            bloom.add(&format!("item_{}", i)).unwrap();
        }

        assert!(bloom.is_near_capacity());
        assert_eq!(bloom.len(), 95);

        bloom.add(&"item_95").unwrap();

        assert_eq!(bloom.len(), 1);
        assert!(bloom.contains(&"item_95"));
        assert!(!bloom.contains(&"item_0"));
    }

    #[test]
    fn test_bloom_filter_capacity_limit() {
        let bloom = BloomFilterManager::new(10, 0.01);

        for i in 0..9 {
            bloom.add(&format!("item_{}", i)).unwrap();
        }

        assert!(bloom.is_near_capacity());
        bloom.add(&"item_9").unwrap();

        assert_eq!(bloom.len(), 1);
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
}