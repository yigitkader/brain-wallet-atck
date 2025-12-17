// ============================================================================
// checkpoint.rs - Checkpoint Management for Resume
// ============================================================================

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::Path;

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

    /// Save checkpoint to file
    pub fn save(&self, index: usize, checked: u64, found: u64) -> Result<()> {
        let checkpoint = Checkpoint {
            last_index: index,
            checked,
            found,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let file = File::create(&self.path)
            .context("Failed to create checkpoint file")?;
        let writer = BufWriter::new(file);

        serde_json::to_writer_pretty(writer, &checkpoint)
            .context("Failed to write checkpoint")?;

        Ok(())
    }

    /// Load checkpoint from file
    pub fn load(&self) -> Result<Option<usize>> {
        if !Path::new(&self.path).exists() {
            return Ok(None);
        }

        let file = File::open(&self.path)
            .context("Failed to open checkpoint file")?;
        let reader = BufReader::new(file);

        let checkpoint: Checkpoint = serde_json::from_reader(reader)
            .context("Failed to parse checkpoint")?;

        Ok(Some(checkpoint.last_index))
    }

    /// Delete checkpoint file (useful for starting fresh)
    pub fn clear(&self) -> Result<()> {
        if Path::new(&self.path).exists() {
            fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}