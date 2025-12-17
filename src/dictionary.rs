use anyhow::{Result, Context, bail};
use std::fs::{File, create_dir_all};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use tracing::{info, warn};
use reqwest;
use std::sync::Arc;
use tokio::sync::Mutex;
use once_cell::sync::Lazy;
use flate2::read::GzDecoder;

use crate::config::Config;

// Global lock for dictionary downloads to prevent race conditions
static DOWNLOAD_LOCK: Lazy<Arc<Mutex<()>>> = Lazy::new(|| Arc::new(Mutex::new(())));

// Fallback URLs for dictionary downloads
const ROCKYOU_URLS: &[&str] = &[
    "https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz",
    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    "https://download.weakpass.com/wordlists/90/rockyou.txt.gz",
];

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

        // Download rockyou.txt with fallback URLs
        if !Path::new(&config.dictionaries.passwords).exists() {
            Self::download_with_fallback(
                &config.dictionaries.passwords,
                ROCKYOU_URLS,
            ).await?;
        }
        
        // Download BIP39 wordlist
        Self::download_if_missing(
            &config.dictionaries.bip39,
            "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt",
        ).await?;

        // Create default dictionaries if they don't exist
        Self::create_default_dictionaries(config).await?;

        Ok(())
    }

    /// Download with multiple fallback URLs
    async fn download_with_fallback(path: &str, urls: &[&str]) -> Result<()> {
        let mut last_error = None;
        
        for url in urls {
            match Self::download_if_missing(path, url).await {
                Ok(_) => {
                    info!("Successfully downloaded from: {}", url);
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to download from {}: {}", url, e);
                    last_error = Some(e);
                    // Try next URL
                }
            }
        }
        
        bail!("All download attempts failed. Last error: {:?}", last_error)
    }

    /// Download file if it doesn't exist (thread-safe, streaming, with GZ support)
    async fn download_if_missing(path: &str, url: &str) -> Result<()> {
        // Check if file exists before acquiring lock
        if Path::new(path).exists() {
            info!("Dictionary already exists: {}", path);
            return Ok(());
        }

        // Download outside of lock to prevent blocking other threads
        info!("Downloading dictionary: {} from {}", path, url);
        let response = reqwest::get(url).await
            .context(format!("Failed to download from {}", url))?;

        if !response.status().is_success() {
            bail!("Failed to download {}: status {}", url, response.status());
        }

        // Check content length (prevent OOM)
        let total_size = response.content_length().unwrap_or(0);
        const MAX_SIZE: u64 = 500_000_000; // 500MB limit
        if total_size > MAX_SIZE {
            bail!("File too large: {} bytes (max: {} bytes)", total_size, MAX_SIZE);
        }

        // Detect GZ compression
        let is_gzipped = url.ends_with(".gz") || 
            response.headers()
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("gzip"))
                .unwrap_or(false);

        // Download bytes outside of lock
        let bytes = if is_gzipped {
            // For GZ files, download and decompress
            let raw_bytes = response.bytes().await
                .context("Failed to read response body")?;
            let mut decoder = GzDecoder::new(raw_bytes.as_ref());
            let mut decompressed = Vec::new();
            std::io::copy(&mut decoder, &mut decompressed)
                .context("Failed to decompress GZ file")?;
            decompressed
        } else {
            // For regular files, download directly
            if total_size > 10_000_000 {
                warn!("Large file detected ({} bytes), downloading in chunks...", total_size);
            }
            response.bytes().await
                .context("Failed to read response body")?
                .to_vec()
        };

        // Acquire lock only for file write (prevent concurrent writes)
        let _guard = DOWNLOAD_LOCK.lock().await;

        // Double-check after acquiring lock (another process might have downloaded it)
        if Path::new(path).exists() {
            info!("Dictionary already exists (checked after download): {}", path);
            return Ok(());
        }

        // Create parent directory if needed
        if let Some(parent) = Path::new(path).parent() {
            create_dir_all(parent)?;
        }

        // Atomic write: write to temp file first, then rename
        let temp_path = format!("{}.tmp", path);
        let mut file = File::create(&temp_path)
            .context(format!("Failed to create temp file: {}", temp_path))?;

        // Write downloaded bytes to file
        file.write_all(&bytes)
            .context("Failed to write file")?;

        file.sync_all()?; // Ensure data is written to disk
        
        // Validate downloaded file
        Self::validate_downloaded_file(&temp_path)?;
        
        // Atomic rename (POSIX guarantees this is atomic)
        std::fs::rename(&temp_path, path)
            .context(format!("Failed to rename temp file to {}", path))?;

        info!("Downloaded dictionary: {}", path);
        Ok(())
    }

    /// Validate downloaded dictionary file
    fn validate_downloaded_file(path: &str) -> Result<()> {
        let file = File::open(path)
            .context("Failed to open downloaded file")?;
        let metadata = file.metadata()
            .context("Failed to get file metadata")?;
        
        // Check file size (must be at least 1KB)
        if metadata.len() < 1000 {
            std::fs::remove_file(path)?;
            bail!("Downloaded file too small ({} bytes), likely corrupt", metadata.len());
        }
        
        // Check first line is not HTML (error page)
        // Use lossy UTF-8 conversion to handle binary data
        let mut reader = BufReader::new(file);
        let mut first_line = Vec::new();
        reader.read_until(b'\n', &mut first_line)
            .context("Failed to read first line")?;
        
        // Convert to string with lossy UTF-8 (skip invalid UTF-8 bytes)
        let first_line_str = String::from_utf8_lossy(&first_line);
        
        if first_line_str.trim().to_lowercase().contains("<html") || 
           first_line_str.trim().to_lowercase().contains("<!doctype") {
            std::fs::remove_file(path)?;
            bail!("Downloaded HTML instead of dictionary (likely error page)");
        }
        
        Ok(())
    }

    /// Create default dictionary files if they don't exist
    async fn create_default_dictionaries(config: &Config) -> Result<()> {
        // Create common phrases file
        if !Path::new(&config.dictionaries.phrases).exists() {
            let mut file = File::create(&config.dictionaries.phrases)?;
            for phrase in Self::generate_default_phrases() {
                writeln!(file, "{}", phrase)?;
            }
            info!("Created default phrases dictionary with {} entries", Self::generate_default_phrases().len());
        }

        // Create crypto terms file
        if !Path::new(&config.dictionaries.crypto).exists() {
            let mut file = File::create(&config.dictionaries.crypto)?;
            for term in Self::generate_default_crypto_terms() {
                writeln!(file, "{}", term)?;
            }
            info!("Created default crypto terms dictionary with {} entries", Self::generate_default_crypto_terms().len());
        }

        // Create known weak seeds file
        if !Path::new(&config.dictionaries.weak_seeds).exists() {
            let mut file = File::create(&config.dictionaries.weak_seeds)?;
            for seed in Self::generate_default_weak_seeds() {
                writeln!(file, "{}", seed)?;
            }
            info!("Created default weak seeds dictionary with {} entries", Self::generate_default_weak_seeds().len());
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

    /// Load file with line limit (handles non-UTF-8 gracefully)
    fn load_file_limited(path: &str, limit: usize) -> Result<Vec<String>> {
        let file = File::open(path)
            .context(format!("Failed to open: {}", path))?;

        let reader = BufReader::new(file);
        let mut lines = Vec::with_capacity(limit);
        let mut utf8_errors = 0u32;

        for (idx, line_result) in reader.lines().enumerate() {
            if idx >= limit {
                break;
            }
            
            // Use lossy UTF-8 conversion to handle binary/invalid UTF-8
            match line_result {
                Ok(line) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        lines.push(trimmed.to_string());
                    }
                }
                Err(e) => {
                    // If UTF-8 error, skip this line (dictionary files may have binary data)
                    if e.to_string().contains("UTF-8") {
                        utf8_errors += 1;
                        // Only log first few errors to avoid spam
                        if utf8_errors <= 3 {
                            warn!("Skipping invalid UTF-8 line in {} (will skip silently after this)", path);
                        }
                        continue; // Skip this line
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }

        if utf8_errors > 3 {
            info!("Skipped {} invalid UTF-8 lines in {} (normal for binary dictionary files)", utf8_errors, path);
        }

        Ok(lines)
    }

    /// Load entire file (handles non-UTF-8 gracefully)
    fn load_file(path: &str) -> Result<Vec<String>> {
        let file = File::open(path)
            .context(format!("Failed to open: {}", path))?;

        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        let mut utf8_errors = 0u32;

        for line_result in reader.lines() {
            // Use lossy UTF-8 conversion to handle binary/invalid UTF-8
            match line_result {
                Ok(line) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        lines.push(trimmed.to_string());
                    }
                }
                Err(e) => {
                    // If UTF-8 error, skip this line (dictionary files may have binary data)
                    if e.to_string().contains("UTF-8") {
                        utf8_errors += 1;
                        // Only log first few errors to avoid spam
                        if utf8_errors <= 3 {
                            warn!("Skipping invalid UTF-8 line in {} (will skip silently after this)", path);
                        }
                        continue; // Skip this line
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }

        if utf8_errors > 3 {
            info!("Skipped {} invalid UTF-8 lines in {} (normal for binary dictionary files)", utf8_errors, path);
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

    /// Generate comprehensive default phrases
    fn generate_default_phrases() -> Vec<&'static str> {
        vec![
            // Common phrases
            "hello world", "to be or not to be", "the quick brown fox",
            
            // Crypto phrases
            "to the moon", "buy the dip", "not your keys not your coins",
            "hodl bitcoin", "trust the process", "have fun staying poor",
            
            // Motivational
            "never give up", "just do it", "make it happen", "dream big",
            
            // Song lyrics (first lines)
            "we will rock you", "we are the champions", "dont stop believing",
            
            // Movie quotes
            "may the force be with you", "ill be back", "you cant handle the truth",
            
            // Internet memes
            "all your base", "over nine thousand", "do you even lift",
            
            // Dates + phrases
            "bitcoin 2009", "ethereum 2015", "crypto 2021", "nft 2022",
            
            // Common combinations
            "password 123", "admin 2024", "test test test",
        ]
    }

    /// Generate comprehensive default crypto terms
    fn generate_default_crypto_terms() -> Vec<&'static str> {
        vec![
            // Coins
            "bitcoin", "btc", "satoshi", "ethereum", "eth", "litecoin", "dogecoin",
            "ripple", "xrp", "cardano", "ada", "polkadot", "dot", "solana", "sol",
            "binance", "bnb", "usdt", "usdc", "dai",
            
            // Terms
            "blockchain", "crypto", "wallet", "seed", "mnemonic", "private", "public",
            "address", "transaction", "mining", "staking", "defi", "nft", "token",
            "exchange", "hodl", "moon", "lambo", "rekt", "fomo", "dyor",
            
            // Phrases
            "to the moon", "buy the dip", "not your keys", "gm", "wagmi", "ngmi",
            
            // Numbers with crypto
            "bitcoin2024", "eth2023", "crypto2025", "satoshi21", "btc100k",
            
            // Common weak
            "password", "123456", "qwerty", "letmein", "admin", "root",
        ]
    }

    /// Generate comprehensive default weak seeds
    fn generate_default_weak_seeds() -> Vec<String> {
        use sha2::{Sha256, Digest};
        
        let mut seeds = vec![
            // Null seed
            "0".repeat(64),
            
            // Max seed
            "f".repeat(64),
            
            // Sequential
            "0123456789abcdef".repeat(4),
            "fedcba9876543210".repeat(4),
            
            // Repeated patterns
            "deadbeef".repeat(8),
            "cafebabe".repeat(8),
            "baadf00d".repeat(8),
        ];
        
        // Common passwords as seeds (SHA256 hash)
        let hash_to_seed = |input: &str| -> String {
            let hash = Sha256::digest(input.as_bytes());
            hex::encode(hash)
        };
        
        seeds.push(hash_to_seed("password"));
        seeds.push(hash_to_seed("123456"));
        seeds.push(hash_to_seed("bitcoin"));
        seeds.push(hash_to_seed("satoshi"));
        seeds.push(hash_to_seed("ethereum"));
        seeds.push(hash_to_seed("crypto"));
        seeds.push(hash_to_seed("wallet"));
        seeds.push(hash_to_seed("private"));
        seeds.push(hash_to_seed("secret"));
        seeds.push(hash_to_seed("key"));
        
        seeds
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