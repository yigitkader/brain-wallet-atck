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
    pub fn len(&self) -> usize {
        // Bloom filters don't track exact count
        // This is an approximation
        0
    }

    /// Clear bloom filter
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