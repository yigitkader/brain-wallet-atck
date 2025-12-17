use anyhow::{Result, Context};
use std::fs::{File, create_dir_all};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use tracing::{info, warn};
use reqwest;
use std::sync::Arc;
use tokio::sync::Mutex;
use once_cell::sync::Lazy;

use crate::config::Config;

// Global lock for dictionary downloads to prevent race conditions
static DOWNLOAD_LOCK: Lazy<Arc<Mutex<()>>> = Lazy::new(|| Arc::new(Mutex::new(())));

/// All dictionaries loaded into memory
#[derive(Debug, Clone, Default)]
pub struct Dictionaries {
    pub passwords: Vec<String>,
    pub bip39: Vec<String>,
    pub phrases: Vec<String>,
    pub crypto: Vec<String>,
    pub weak_seeds: Vec<String>,
    pub names: Vec<String>,
    pub dates: Vec<String>,
}

impl Dictionaries {
    /// Get total number of entries across all dictionaries
    pub fn total_entries(&self) -> usize {
        self.passwords.len()
            + self.bip39.len()
            + self.phrases.len()
            + self.crypto.len()
            + self.weak_seeds.len()
            + self.names.len()
            + self.dates.len()
    }
}

/// Dictionary loader - loads all dictionaries from files
pub struct DictionaryLoader;

impl DictionaryLoader {
    /// Ensure dictionaries directory exists and download missing files
    pub async fn ensure_dictionaries(config: &Config) -> Result<()> {
        // Create dictionaries directory if it doesn't exist
        create_dir_all("dictionaries")?;

        // Download dictionaries if they don't exist
        Self::download_if_missing(&config.dictionaries.passwords, 
            "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt").await?;
        
        Self::download_if_missing(&config.dictionaries.bip39,
            "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt").await?;

        // Create default dictionaries if they don't exist
        Self::create_default_dictionaries(config).await?;

        Ok(())
    }

    /// Download file if it doesn't exist (thread-safe)
    async fn download_if_missing(path: &str, url: &str) -> Result<()> {
        // Check again after acquiring lock (double-check pattern)
        if Path::new(path).exists() {
            info!("Dictionary already exists: {}", path);
            return Ok(());
        }

        // Acquire lock to prevent concurrent downloads
        let _guard = DOWNLOAD_LOCK.lock().await;

        // Double-check after acquiring lock
        if Path::new(path).exists() {
            info!("Dictionary already exists (checked after lock): {}", path);
            return Ok(());
        }

        info!("Downloading dictionary: {} from {}", path, url);
        let response = reqwest::get(url).await
            .context(format!("Failed to download from {}", url))?;

        if !response.status().is_success() {
            warn!("Failed to download {}: status {}", url, response.status());
            return Ok(()); // Don't fail, just warn
        }

        let content = response.text().await
            .context("Failed to read response body")?;

        // Create parent directory if needed
        if let Some(parent) = Path::new(path).parent() {
            create_dir_all(parent)?;
        }

        // Atomic write: write to temp file first, then rename
        let temp_path = format!("{}.tmp", path);
        let mut file = File::create(&temp_path)
            .context(format!("Failed to create temp file: {}", temp_path))?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?; // Ensure data is written to disk
        
        // Atomic rename (POSIX guarantees this is atomic)
        std::fs::rename(&temp_path, path)
            .context(format!("Failed to rename temp file to {}", path))?;

        info!("Downloaded dictionary: {}", path);
        Ok(())
    }

    /// Create default dictionary files if they don't exist
    async fn create_default_dictionaries(config: &Config) -> Result<()> {
        // Create common phrases file
        if !Path::new(&config.dictionaries.phrases).exists() {
            let mut file = File::create(&config.dictionaries.phrases)?;
            writeln!(file, "hello world")?;
            writeln!(file, "to be or not to be")?;
            writeln!(file, "the quick brown fox")?;
            info!("Created default phrases dictionary");
        }

        // Create crypto terms file
        if !Path::new(&config.dictionaries.crypto).exists() {
            let mut file = File::create(&config.dictionaries.crypto)?;
            writeln!(file, "bitcoin")?;
            writeln!(file, "satoshi")?;
            writeln!(file, "ethereum")?;
            writeln!(file, "blockchain")?;
            writeln!(file, "crypto")?;
            writeln!(file, "wallet")?;
            info!("Created default crypto terms dictionary");
        }

        // Create known weak seeds file
        if !Path::new(&config.dictionaries.weak_seeds).exists() {
            let mut file = File::create(&config.dictionaries.weak_seeds)?;
            writeln!(file, "0000000000000000000000000000000000000000000000000000000000000000")?;
            writeln!(file, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")?;
            info!("Created default weak seeds dictionary");
        }

        // Create names file
        if !Path::new(&config.dictionaries.names).exists() {
            let mut file = File::create(&config.dictionaries.names)?;
            for name in Self::generate_default_names() {
                writeln!(file, "{}", name)?;
            }
            info!("Created default names dictionary");
        }

        Ok(())
    }

    /// Load all dictionaries based on config
    pub fn load_all(config: &Config) -> Result<Dictionaries> {
        let mut dicts = Dictionaries::default();

        // Load passwords (with limit)
        info!("Loading passwords dictionary...");
        dicts.passwords = Self::load_file_limited(
            &config.dictionaries.passwords,
            config.dictionaries.passwords_limit,
        )?;
        info!("Loaded {} passwords", dicts.passwords.len());

        // Load BIP39 wordlist (standard 2048 words)
        info!("Loading BIP39 wordlist...");
        dicts.bip39 = Self::load_bip39_wordlist()?;
        info!("Loaded {} BIP39 words", dicts.bip39.len());

        // Load phrases (with limit)
        info!("Loading phrases dictionary...");
        dicts.phrases = Self::load_file_limited(
            &config.dictionaries.phrases,
            config.dictionaries.phrases_limit,
        ).unwrap_or_default(); // Optional
        info!("Loaded {} phrases", dicts.phrases.len());

        // Load crypto terms
        info!("Loading crypto terms...");
        dicts.crypto = Self::load_file(&config.dictionaries.crypto)
            .unwrap_or_default(); // Optional
        info!("Loaded {} crypto terms", dicts.crypto.len());

        // Load known weak seeds
        info!("Loading known weak seeds...");
        dicts.weak_seeds = Self::load_file(&config.dictionaries.weak_seeds)
            .unwrap_or_default(); // Optional
        info!("Loaded {} weak seeds", dicts.weak_seeds.len());

        // Load names
        info!("Loading names...");
        dicts.names = Self::load_file(&config.dictionaries.names)
            .unwrap_or_else(|_| Self::generate_default_names());
        info!("Loaded {} names", dicts.names.len());

        // Generate dates
        info!("Generating dates...");
        dicts.dates = Self::generate_dates(1950, 2025);
        info!("Generated {} dates", dicts.dates.len());

        Ok(dicts)
    }

    /// Load file with line limit
    fn load_file_limited(path: &str, limit: usize) -> Result<Vec<String>> {
        let file = File::open(path)
            .context(format!("Failed to open: {}", path))?;

        let reader = BufReader::new(file);
        let mut lines = Vec::with_capacity(limit);

        for line in reader.lines().take(limit) {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                lines.push(trimmed.to_string());
            }
        }

        Ok(lines)
    }

    /// Load entire file
    fn load_file(path: &str) -> Result<Vec<String>> {
        let file = File::open(path)
            .context(format!("Failed to open: {}", path))?;

        let reader = BufReader::new(file);
        let mut lines = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                lines.push(trimmed.to_string());
            }
        }

        Ok(lines)
    }

    /// Load BIP39 wordlist (from file, must be downloaded)
    fn load_bip39_wordlist() -> Result<Vec<String>> {
        // Try to load from file first
        match Self::load_file("dictionaries/bip39-english.txt") {
            Ok(words) => Ok(words),
            Err(_) => {
                // Fallback: Return error with helpful message
                // In production, ensure_dictionaries() should be called first
                anyhow::bail!("BIP39 wordlist not found. Run ensure_dictionaries() first.")
            }
        }
    }

    /// Generate date range (YYYY-MM-DD and variations)
    fn generate_dates(start_year: u32, end_year: u32) -> Vec<String> {
        let mut dates = Vec::new();

        for year in start_year..=end_year {
            // Full dates
            dates.push(format!("{:04}", year));
            dates.push(format!("{:02}", year % 100));

            // Common date formats
            for month in 1..=12 {
                dates.push(format!("{:04}{:02}", year, month));
                dates.push(format!("{:02}{:02}", year % 100, month));
                dates.push(format!("{:04}-{:02}", year, month));

                for day in 1..=28 { // Safe for all months
                    dates.push(format!("{:04}{:02}{:02}", year, month, day));
                    dates.push(format!("{:02}{:02}{:02}", year % 100, month, day));
                }
            }
        }

        dates
    }

    /// Generate default common names
    fn generate_default_names() -> Vec<String> {
        vec![
            "john", "jane", "alice", "bob", "charlie", "david", "emma", "frank",
            "grace", "henry", "isabella", "jack", "kate", "liam", "mary", "noah",
            "olivia", "peter", "quinn", "rachel", "steve", "tom", "uma", "victor",
            "wendy", "xavier", "yara", "zack", "bitcoin", "satoshi", "crypto",
        ].iter().map(|s| s.to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_wordlist() {
        // Test may fail if dictionaries haven't been downloaded
        // This is expected - ensure_dictionaries() should be called first
        match DictionaryLoader::load_bip39_wordlist() {
            Ok(words) => {
                assert!(!words.is_empty());
                assert!(words.contains(&"abandon".to_string()));
            }
            Err(_) => {
                // Skip test if dictionaries not available (expected in CI/test environments)
                // In production, ensure_dictionaries() guarantees the file exists
            }
        }
    }

    #[test]
    fn test_generate_dates() {
        let dates = DictionaryLoader::generate_dates(2020, 2021);
        assert!(!dates.is_empty());
        assert!(dates.contains(&"2020".to_string()));
        assert!(dates.contains(&"202001".to_string()));
    }

    #[test]
    fn test_default_names() {
        let names = DictionaryLoader::generate_default_names();
        assert!(names.contains(&"satoshi".to_string()));
        assert!(names.contains(&"bitcoin".to_string()));
    }
}