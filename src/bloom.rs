// ============================================================================
// bloom.rs - Bloom Filter for Duplicate Detection
// ============================================================================

use bloom::{BloomFilter as InternalBloom, ASMS};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

pub struct BloomFilterManager {
    filter: parking_lot::RwLock<InternalBloom>,
}

impl BloomFilterManager {
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        let items_count = capacity;
        let fp_rate = false_positive_rate;

        // Calculate optimal bloom filter parameters
        let filter = InternalBloom::with_rate(fp_rate as f32, items_count as u32);

        Self {
            filter: parking_lot::RwLock::new(filter),
        }
    }

    /// Check if pattern exists in bloom filter
    pub fn contains<T: Hash>(&self, item: &T) -> bool {
        let hash = Self::hash_item(item);
        self.filter.read().contains(&hash)
    }

    /// Add pattern to bloom filter
    pub fn add<T: Hash>(&self, item: &T) {
        let hash = Self::hash_item(item);
        self.filter.write().insert(&hash);
    }

    /// Hash any item to u64
    fn hash_item<T: Hash>(item: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        item.hash(&mut hasher);
        hasher.finish()
    }

    /// Get estimated number of items
    /// Note: Bloom filters don't track exact count, this is an approximation
    pub fn len(&self) -> usize {
        // We can't get exact count from bloom filter, but we can estimate
        // based on the number of hash operations. For now, return 0 as
        // the bloom crate doesn't provide a count method.
        // This is a limitation of the bloom filter implementation.
        0
    }

    /// Clear bloom filter (useful when starting fresh or resetting)
    pub fn clear(&self) {
        self.filter.write().clear();
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

        bloom.add(&item1);
        assert!(bloom.contains(&item1));
        assert!(!bloom.contains(&item2));
    }
}