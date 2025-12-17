// ============================================================================
// bloom.rs - Bloom Filter for Duplicate Detection
// ============================================================================

use bloom::{BloomFilter as InternalBloom, ASMS};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::Result;

pub struct BloomFilterManager {
    filter: parking_lot::RwLock<InternalBloom>,
    item_count: AtomicU64, // Manual counter for accurate statistics
    capacity: usize, // Maximum capacity to prevent overflow
}

impl BloomFilterManager {
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        let items_count = capacity;
        let fp_rate = false_positive_rate;

        // Calculate optimal bloom filter parameters
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

    /// Add pattern to bloom filter (with capacity check)
    pub fn add<T: Hash>(&self, item: &T) -> Result<()> {
        let current_count = self.item_count.load(Ordering::Relaxed);
        if current_count >= self.capacity as u64 {
            anyhow::bail!("Bloom filter capacity exceeded: {} (max: {})", current_count, self.capacity);
        }
        
        let hash = Self::hash_item(item);
        self.filter.write().insert(&hash);
        self.item_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Hash any item to u64
    fn hash_item<T: Hash>(item: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        item.hash(&mut hasher);
        hasher.finish()
    }

    /// Get number of items added to bloom filter
    pub fn len(&self) -> usize {
        self.item_count.load(Ordering::Relaxed) as usize
    }

    /// Get capacity of bloom filter
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Check if bloom filter is near capacity (95% threshold)
    pub fn is_near_capacity(&self) -> bool {
        let current_count = self.item_count.load(Ordering::Relaxed) as usize;
        current_count >= (self.capacity * 95 / 100)
    }

    /// Clear bloom filter (useful when starting fresh or resetting)
    pub fn clear(&self) {
        self.filter.write().clear();
        self.item_count.store(0, Ordering::Relaxed);
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