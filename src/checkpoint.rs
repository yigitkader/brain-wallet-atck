// ============================================================================
// checkpoint.rs - Checkpoint Management for Resume
// ============================================================================

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use fs2::FileExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub last_index: usize,
    pub checked: u64,
    pub found: u64,
    pub timestamp: String,
    #[serde(default)] // Backward compatibility: if missing, use current time
    pub start_time: Option<u64>, // Unix timestamp in seconds (for accurate rate calculation when resuming)
}

pub struct CheckpointManager {
    path: String,
}

impl CheckpointManager {
    pub fn new(path: &str) -> Result<Self> {
        // Create output directory if it doesn't exist
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(Self {
            path: path.to_string(),
        })
    }

    /// Save checkpoint to file (atomic write with file locking to prevent corruption)
    /// start_time: Unix timestamp in seconds (None = use current time, Some(t) = preserve original start time)
    pub fn save(&self, index: usize, checked: u64, found: u64, start_time: Option<u64>) -> Result<()> {
        // Preserve original start_time from previous checkpoint if it exists, otherwise use provided or current time
        let preserved_start_time = if let Some(prev_checkpoint) = self.load_full().ok().flatten() {
            prev_checkpoint.start_time.or(start_time)
        } else {
            start_time
        };
        
        let checkpoint = Checkpoint {
            last_index: index,
            checked,
            found,
            timestamp: chrono::Utc::now().to_rfc3339(),
            start_time: preserved_start_time,
        };

        // Atomic write pattern: write to temp file first, then rename
        let temp_path = format!("{}.tmp", self.path);
        let file = File::create(&temp_path)
            .context("Failed to create temp checkpoint file")?;
        
        // Acquire exclusive lock to prevent concurrent writes from multiple processes
        file.lock_exclusive()
            .context("Failed to acquire exclusive lock on checkpoint file")?;
        
        let mut writer = BufWriter::new(file);

        serde_json::to_writer_pretty(&mut writer, &checkpoint)
            .context("Failed to write checkpoint")?;
        
        // Explicit flush to ensure data is written to disk before rename
        writer.flush()
            .context("Failed to flush checkpoint buffer")?;
        
        // Drop writer to close file handle and release lock
        drop(writer);

        // Atomic rename (POSIX guarantees this is atomic)
        std::fs::rename(&temp_path, &self.path)
            .context("Failed to rename temp checkpoint file")?;

        Ok(())
    }

    /// Load checkpoint from file (with shared lock for concurrent reads)
    /// Returns only the last_index for simple checkpoint resume
    /// For full checkpoint data including statistics, use load_full()
    /// Used in tests to verify checkpoint functionality
    #[allow(dead_code)] // Used in tests
    pub fn load(&self) -> Result<Option<usize>> {
        if let Some(checkpoint) = self.load_full()? {
            Ok(Some(checkpoint.last_index))
        } else {
            Ok(None)
        }
    }

    /// Load full checkpoint data (including statistics)
    pub fn load_full(&self) -> Result<Option<Checkpoint>> {
        if !Path::new(&self.path).exists() {
            return Ok(None);
        }

        let file = File::open(&self.path)
            .context("Failed to open checkpoint file")?;
        
        // Acquire shared lock to allow concurrent reads but prevent writes
        file.lock_shared()
            .context("Failed to acquire shared lock on checkpoint file")?;
        
        let reader = BufReader::new(file);

        let checkpoint: Checkpoint = serde_json::from_reader(reader)
            .context("Failed to parse checkpoint")?;

        Ok(Some(checkpoint))
    }

    /// Delete checkpoint file (useful for starting fresh)
    pub fn clear(&self) -> Result<()> {
        if Path::new(&self.path).exists() {
            fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_checkpoint_save_and_load() {
        // Test checkpoint save and load functionality
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        // Save checkpoint
        manager.save(100, 50, 2, Some(1234567890)).unwrap();

        // Load using load() method (simple version)
        let loaded_index = manager.load().unwrap();
        assert_eq!(loaded_index, Some(100));

        // Load using load_full() method (full version)
        let full_checkpoint = manager.load_full().unwrap().unwrap();
        assert_eq!(full_checkpoint.last_index, 100);
        assert_eq!(full_checkpoint.checked, 50);
        assert_eq!(full_checkpoint.found, 2);
        assert_eq!(full_checkpoint.start_time, Some(1234567890));
    }

    #[test]
    fn test_checkpoint_start_time_preservation() {
        // Test that start_time is preserved across multiple saves
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint2.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        let original_start_time = 1234567890;

        // First save with start_time
        manager.save(100, 50, 2, Some(original_start_time)).unwrap();

        // Second save without start_time (should preserve original)
        manager.save(200, 100, 4, None).unwrap();

        let checkpoint = manager.load_full().unwrap().unwrap();
        assert_eq!(checkpoint.start_time, Some(original_start_time),
                   "Start time should be preserved across saves");
    }

    #[test]
    fn test_checkpoint_clear() {
        // Test checkpoint clearing
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint3.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        // Save checkpoint
        manager.save(100, 50, 2, None).unwrap();
        assert!(manager.load().unwrap().is_some());

        // Clear checkpoint
        manager.clear().unwrap();
        assert!(manager.load().unwrap().is_none());
    }

    #[test]
    fn test_checkpoint_nonexistent() {
        // Test loading non-existent checkpoint
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("nonexistent.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        assert!(manager.load().unwrap().is_none());
        assert!(manager.load_full().unwrap().is_none());
    }

    /// Test checkpoint corruption handling
    /// Verifies that corrupted checkpoint files are handled gracefully
    #[test]
    fn test_checkpoint_corruption() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("corrupted_checkpoint.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        // Create a corrupted checkpoint file (invalid JSON)
        std::fs::write(&checkpoint_path, "invalid json content {").unwrap();

        // Loading corrupted checkpoint should return an error
        let result = manager.load_full();
        assert!(result.is_err(), "Loading corrupted checkpoint should fail");
        
        // Verify error message mentions parsing
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("parse") || error_msg.contains("Failed to parse"), 
                "Error should mention parsing failure, got: {}", error_msg);
    }

    /// Test checkpoint with missing fields (backward compatibility)
    #[test]
    fn test_checkpoint_missing_fields() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("old_checkpoint.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        // Create checkpoint with missing start_time field (old format)
        let old_checkpoint = r#"{
            "last_index": 100,
            "checked": 50,
            "found": 2,
            "timestamp": "2024-01-01T00:00:00Z"
        }"#;
        std::fs::write(&checkpoint_path, old_checkpoint).unwrap();

        // Should load successfully (start_time has default value)
        let checkpoint = manager.load_full().unwrap();
        assert!(checkpoint.is_some(), "Should load checkpoint with missing start_time");
        
        let cp = checkpoint.unwrap();
        assert_eq!(cp.last_index, 100);
        assert_eq!(cp.checked, 50);
        assert_eq!(cp.found, 2);
        assert_eq!(cp.start_time, None, "Missing start_time should default to None");
    }

    /// Test checkpoint atomic write (prevents corruption during write)
    #[test]
    fn test_checkpoint_atomic_write() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("atomic_checkpoint.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        // Save checkpoint (uses atomic write: temp file + rename)
        manager.save(100, 50, 2, Some(1234567890)).unwrap();

        // Verify checkpoint was written correctly
        let checkpoint = manager.load_full().unwrap().unwrap();
        assert_eq!(checkpoint.last_index, 100);
        assert_eq!(checkpoint.checked, 50);
        assert_eq!(checkpoint.found, 2);

        // Verify temp file doesn't exist (should be cleaned up)
        let temp_path = format!("{}.tmp", checkpoint_path.to_str().unwrap());
        assert!(!Path::new(&temp_path).exists(), "Temp file should be cleaned up after atomic write");
    }
}