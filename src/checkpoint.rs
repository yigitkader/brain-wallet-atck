use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use fs2::FileExt;
use parking_lot::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub last_index: usize,
    pub checked: u64,
    pub found: u64,
    pub timestamp: String,
    #[serde(default)]
    pub start_time: Option<u64>,
}

pub struct CheckpointManager {
    path: String,
    write_lock: Mutex<()>, // FIXED: Process-level write serialization
}

impl CheckpointManager {
    pub fn new(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(Self {
            path: path.to_string(),
            write_lock: Mutex::new(()),
        })
    }

    /// Save checkpoint to file (atomic write with process-safe locking)
    /// FIXED: Process-level lock + atomic write to prevent corruption
    pub fn save(&self, index: usize, checked: u64, found: u64, start_time: Option<u64>) -> Result<()> {
        // FIXED: Acquire process-level lock first
        let _guard = self.write_lock.lock();

        // Preserve original start_time
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

        // Atomic write pattern
        let temp_path = format!("{}.tmp.{}", self.path, std::process::id());
        let file = File::create(&temp_path)
            .context("Failed to create temp checkpoint file")?;

        // FIXED: Exclusive file lock (process-safe)
        file.lock_exclusive()
            .context("Failed to acquire exclusive lock on checkpoint file")?;

        let mut writer = BufWriter::new(file);

        serde_json::to_writer_pretty(&mut writer, &checkpoint)
            .context("Failed to write checkpoint")?;

        writer.flush()
            .context("Failed to flush checkpoint buffer")?;

        drop(writer);

        // Atomic rename
        match std::fs::rename(&temp_path, &self.path) {
            Ok(_) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&temp_path);
                Err(e).context("Failed to rename temp checkpoint file")
            }
        }
    }

    /// Load checkpoint from file (with shared lock)
    #[allow(dead_code)]
    pub fn load(&self) -> Result<Option<usize>> {
        if let Some(checkpoint) = self.load_full()? {
            Ok(Some(checkpoint.last_index))
        } else {
            Ok(None)
        }
    }

    /// Load full checkpoint data
    pub fn load_full(&self) -> Result<Option<Checkpoint>> {
        if !Path::new(&self.path).exists() {
            return Ok(None);
        }

        let file = File::open(&self.path)
            .context("Failed to open checkpoint file")?;

        file.lock_shared()
            .context("Failed to acquire shared lock on checkpoint file")?;

        let reader = BufReader::new(file);

        let checkpoint: Checkpoint = serde_json::from_reader(reader)
            .context("Failed to parse checkpoint")?;

        Ok(Some(checkpoint))
    }

    /// Delete checkpoint file
    pub fn clear(&self) -> Result<()> {
        let _guard = self.write_lock.lock();

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
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        manager.save(100, 50, 2, Some(1234567890)).unwrap();

        let loaded_index = manager.load().unwrap();
        assert_eq!(loaded_index, Some(100));

        let full_checkpoint = manager.load_full().unwrap().unwrap();
        assert_eq!(full_checkpoint.last_index, 100);
        assert_eq!(full_checkpoint.checked, 50);
        assert_eq!(full_checkpoint.found, 2);
        assert_eq!(full_checkpoint.start_time, Some(1234567890));
    }

    #[test]
    fn test_checkpoint_start_time_preservation() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint2.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        let original_start_time = 1234567890;

        manager.save(100, 50, 2, Some(original_start_time)).unwrap();
        manager.save(200, 100, 4, None).unwrap();

        let checkpoint = manager.load_full().unwrap().unwrap();
        assert_eq!(checkpoint.start_time, Some(original_start_time));
    }

    #[test]
    fn test_checkpoint_clear() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test_checkpoint3.json");
        let manager = CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap();

        manager.save(100, 50, 2, None).unwrap();
        assert!(manager.load().unwrap().is_some());

        manager.clear().unwrap();
        assert!(manager.load().unwrap().is_none());
    }

    #[test]
    fn test_checkpoint_concurrent_writes() {
        use std::sync::Arc;
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("concurrent_checkpoint.json");
        let manager = Arc::new(CheckpointManager::new(checkpoint_path.to_str().unwrap()).unwrap());

        let mut handles = vec![];

        for i in 0..10 {
            let manager_clone = manager.clone();
            let handle = thread::spawn(move || {
                manager_clone.save(i * 100, i * 50, i * 2, Some(1234567890 + i as u64)).unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should successfully save without corruption
        let checkpoint = manager.load_full().unwrap();
        assert!(checkpoint.is_some());
    }
}