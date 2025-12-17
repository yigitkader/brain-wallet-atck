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
    pub fn save(&self, index: usize, checked: u64, found: u64) -> Result<()> {
        let checkpoint = Checkpoint {
            last_index: index,
            checked,
            found,
            timestamp: chrono::Utc::now().to_rfc3339(),
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