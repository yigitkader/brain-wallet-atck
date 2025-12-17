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

    /// Add pattern to bloom filter (with proactive capacity management)
    /// Automatically clears at 95% capacity to prevent overflow
    pub fn add<T: Hash>(&self, item: &T) -> Result<()> {
        // Proactive clear at 95% capacity to prevent overflow
        // This prevents the bloom filter from reaching 100% and crashing
        if self.is_near_capacity() {
            use tracing::warn;
            warn!("Bloom filter 95% full ({} / {}), auto-clearing to prevent overflow...", 
                  self.item_count.load(Ordering::Relaxed), self.capacity);
            self.clear();
        }
        
        // Double-check capacity after potential clear
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

        bloom.add(&item1).unwrap();
        assert!(bloom.contains(&item1));
        assert!(!bloom.contains(&item2));
    }

    /// Test bloom filter overflow handling
    /// Verifies that bloom filter clears at 95% capacity and handles overflow gracefully
    #[test]
    fn test_bloom_filter_overflow() {
        let bloom = BloomFilterManager::new(100, 0.01); // Small capacity for testing

        // Fill bloom filter to near capacity (95%)
        // 95% of 100 = 95 items
        for i in 0..95 {
            bloom.add(&format!("item_{}", i)).unwrap();
        }

        // Verify we're at 95% capacity
        assert!(bloom.is_near_capacity(), "Bloom filter should be near capacity at 95%");
        assert_eq!(bloom.len(), 95);

        // Adding one more item should trigger auto-clear (happens inside add())
        // After clear, count should reset to 1 (the new item)
        bloom.add(&"item_95").unwrap();
        
        // After auto-clear, the count should be 1 (just the new item)
        // Note: The auto-clear happens inside add(), so the new item is added after clearing
        assert_eq!(bloom.len(), 1, "Bloom filter should have been cleared and new item added");
        assert!(bloom.contains(&"item_95"), "New item should be in bloom filter after clear");

        // Verify old items are gone (bloom filter was cleared)
        assert!(!bloom.contains(&"item_0"), "Old items should be gone after clear");
    }

    /// Test bloom filter capacity limits
    /// Note: Bloom filter auto-clears at 95% capacity, so we can't test exact capacity overflow
    /// Instead, we test that the auto-clear mechanism works correctly
    #[test]
    fn test_bloom_filter_capacity_limit() {
        let bloom = BloomFilterManager::new(10, 0.01); // Very small capacity

        // Fill to 95% capacity (9 items out of 10)
        // At 95%, auto-clear should trigger on next add
        for i in 0..9 {
            bloom.add(&format!("item_{}", i)).unwrap();
        }

        // Verify we're at 95% capacity
        assert!(bloom.is_near_capacity(), "Bloom filter should be near capacity at 95%");
        assert_eq!(bloom.len(), 9);

        // Adding one more item should trigger auto-clear (happens inside add())
        // After clear, count should reset to 1 (the new item)
        bloom.add(&"item_9").unwrap();
        
        // After auto-clear, the count should be 1 (just the new item)
        // The auto-clear happens inside add() when is_near_capacity() is true
        assert_eq!(bloom.len(), 1, "Bloom filter should have been auto-cleared and new item added");
        assert!(bloom.contains(&"item_9"), "New item should be in bloom filter after auto-clear");
        
        // Verify old items are gone (bloom filter was cleared)
        assert!(!bloom.contains(&"item_0"), "Old items should be gone after auto-clear");
    }

    /// Test bloom filter clear functionality
    #[test]
    fn test_bloom_filter_clear() {
        let bloom = BloomFilterManager::new(1000, 0.01);

        // Add some items
        bloom.add(&"item1").unwrap();
        bloom.add(&"item2").unwrap();
        assert_eq!(bloom.len(), 2);

        // Clear bloom filter
        bloom.clear();
        assert_eq!(bloom.len(), 0);
        assert!(!bloom.contains(&"item1"));
        assert!(!bloom.contains(&"item2"));

        // Can add items after clear
        bloom.add(&"item3").unwrap();
        assert_eq!(bloom.len(), 1);
        assert!(bloom.contains(&"item3"));
    }
}