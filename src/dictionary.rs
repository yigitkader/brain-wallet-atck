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

static DOWNLOAD_LOCK: Lazy<Arc<Mutex<()>>> = Lazy::new(|| Arc::new(Mutex::new(())));

const ROCKYOU_URLS: &[&str] = &[
    "https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz",
    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    "https://download.weakpass.com/wordlists/90/rockyou.txt.gz",
];

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

pub struct DictionaryLoader;

impl DictionaryLoader {
    pub async fn ensure_dictionaries(config: &Config) -> Result<()> {
        create_dir_all("dictionaries")?;

        if !Path::new(&config.dictionaries.passwords).exists() {
            Self::download_with_fallback(
                &config.dictionaries.passwords,
                ROCKYOU_URLS,
            ).await?;
        }

        Self::download_if_missing(
            &config.dictionaries.bip39,
            "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt",
        ).await?;

        Self::create_default_dictionaries(config).await?;

        Ok(())
    }

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
                }
            }
        }

        bail!("All download attempts failed. Last error: {:?}", last_error)
    }

    /// FIXED: Download with proper locking (lock BEFORE download, not after)
    async fn download_if_missing(path: &str, url: &str) -> Result<()> {
        // Fast path check
        if Path::new(path).exists() {
            info!("Dictionary already exists: {}", path);
            return Ok(());
        }

        // FIXED: Acquire lock BEFORE starting download
        let _guard = DOWNLOAD_LOCK.lock().await;

        // Double-check after acquiring lock
        if Path::new(path).exists() {
            info!("Dictionary already exists (checked after lock): {}", path);
            return Ok(());
        }

        // Download while holding lock
        info!("Downloading dictionary: {} from {}", path, url);
        let response = reqwest::get(url).await
            .context(format!("Failed to download from {}", url))?;

        if !response.status().is_success() {
            bail!("Failed to download {}: status {}", url, response.status());
        }

        let total_size = response.content_length().unwrap_or(0);
        const MAX_SIZE: u64 = 500_000_000;
        if total_size > MAX_SIZE {
            bail!("File too large: {} bytes (max: {} bytes)", total_size, MAX_SIZE);
        }

        let is_gzipped = url.ends_with(".gz") ||
            response.headers()
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("gzip"))
                .unwrap_or(false);

        let bytes = if is_gzipped {
            let raw_bytes = response.bytes().await
                .context("Failed to read response body")?;
            let mut decoder = GzDecoder::new(raw_bytes.as_ref());
            let mut decompressed = Vec::new();
            std::io::copy(&mut decoder, &mut decompressed)
                .context("Failed to decompress GZ file")?;
            decompressed
        } else {
            if total_size > 10_000_000 {
                warn!("Large file detected ({} bytes), downloading in chunks...", total_size);
            }
            response.bytes().await
                .context("Failed to read response body")?
                .to_vec()
        };

        if let Some(parent) = Path::new(path).parent() {
            create_dir_all(parent)?;
        }

        let temp_path = format!("{}.tmp", path);
        let mut file = File::create(&temp_path)
            .context(format!("Failed to create temp file: {}", temp_path))?;

        file.write_all(&bytes)
            .context("Failed to write file")?;

        file.sync_all()?;

        Self::validate_downloaded_file(&temp_path)?;

        std::fs::rename(&temp_path, path)
            .context(format!("Failed to rename temp file to {}", path))?;

        info!("Downloaded dictionary: {}", path);
        Ok(())
    }

    fn validate_downloaded_file(path: &str) -> Result<()> {
        let file = File::open(path)
            .context("Failed to open downloaded file")?;
        let metadata = file.metadata()
            .context("Failed to get file metadata")?;

        if metadata.len() < 1000 {
            std::fs::remove_file(path)?;
            bail!("Downloaded file too small ({} bytes), likely corrupt", metadata.len());
        }

        let mut reader = BufReader::new(file);
        let mut first_line = Vec::new();
        reader.read_until(b'\n', &mut first_line)
            .context("Failed to read first line")?;

        let first_line_str = String::from_utf8_lossy(&first_line);

        if first_line_str.trim().to_lowercase().contains("<html") ||
            first_line_str.trim().to_lowercase().contains("<!doctype") {
            std::fs::remove_file(path)?;
            bail!("Downloaded HTML instead of dictionary (likely error page)");
        }

        Ok(())
    }

    async fn create_default_dictionaries(config: &Config) -> Result<()> {
        if !Path::new(&config.dictionaries.phrases).exists() {
            let mut file = File::create(&config.dictionaries.phrases)?;
            for phrase in Self::generate_default_phrases() {
                writeln!(file, "{}", phrase)?;
            }
            info!("Created default phrases dictionary");
        }

        if !Path::new(&config.dictionaries.crypto).exists() {
            let mut file = File::create(&config.dictionaries.crypto)?;
            for term in Self::generate_default_crypto_terms() {
                writeln!(file, "{}", term)?;
            }
            info!("Created default crypto terms dictionary");
        }

        if !Path::new(&config.dictionaries.weak_seeds).exists() {
            let mut file = File::create(&config.dictionaries.weak_seeds)?;
            for seed in Self::generate_default_weak_seeds() {
                writeln!(file, "{}", seed)?;
            }
            info!("Created default weak seeds dictionary");
        }

        if !Path::new(&config.dictionaries.names).exists() {
            let mut file = File::create(&config.dictionaries.names)?;
            for name in Self::generate_default_names() {
                writeln!(file, "{}", name)?;
            }
            info!("Created default names dictionary");
        }

        Ok(())
    }

    pub fn load_all(config: &Config) -> Result<Dictionaries> {
        let mut dicts = Dictionaries::default();

        info!("Loading passwords dictionary...");
        dicts.passwords = Self::load_file_limited(
            &config.dictionaries.passwords,
            config.dictionaries.passwords_limit,
        )?;
        info!("Loaded {} passwords", dicts.passwords.len());

        info!("Loading BIP39 wordlist...");
        dicts.bip39 = Self::load_bip39_wordlist()?;
        info!("Loaded {} BIP39 words", dicts.bip39.len());

        info!("Loading phrases dictionary...");
        dicts.phrases = Self::load_file_limited(
            &config.dictionaries.phrases,
            config.dictionaries.phrases_limit,
        ).unwrap_or_default();
        info!("Loaded {} phrases", dicts.phrases.len());

        info!("Loading crypto terms...");
        dicts.crypto = Self::load_file(&config.dictionaries.crypto)
            .unwrap_or_default();
        info!("Loaded {} crypto terms", dicts.crypto.len());

        info!("Loading known weak seeds...");
        dicts.weak_seeds = Self::load_file(&config.dictionaries.weak_seeds)
            .unwrap_or_default();
        info!("Loaded {} weak seeds", dicts.weak_seeds.len());

        info!("Loading names...");
        dicts.names = Self::load_file(&config.dictionaries.names)
            .unwrap_or_else(|_| Self::generate_default_names());
        info!("Loaded {} names", dicts.names.len());

        info!("Generating dates...");
        dicts.dates = Self::generate_dates(1950, 2025);
        info!("Generated {} dates", dicts.dates.len());

        Ok(dicts)
    }

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

            match line_result {
                Ok(line) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        lines.push(trimmed.to_string());
                    }
                }
                Err(e) => {
                    if e.to_string().contains("UTF-8") {
                        utf8_errors += 1;
                        continue;
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }

        if utf8_errors > 0 {
            info!("Skipped {} invalid UTF-8 lines in {}", utf8_errors, path);
        }

        Ok(lines)
    }

    fn load_file(path: &str) -> Result<Vec<String>> {
        let file = File::open(path)
            .context(format!("Failed to open: {}", path))?;

        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        let mut utf8_errors = 0u32;

        for line_result in reader.lines() {
            match line_result {
                Ok(line) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        lines.push(trimmed.to_string());
                    }
                }
                Err(e) => {
                    if e.to_string().contains("UTF-8") {
                        utf8_errors += 1;
                        continue;
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }

        if utf8_errors > 0 {
            info!("Skipped {} invalid UTF-8 lines in {}", utf8_errors, path);
        }

        Ok(lines)
    }

    fn load_bip39_wordlist() -> Result<Vec<String>> {
        match Self::load_file("dictionaries/bip39-english.txt") {
            Ok(words) => Ok(words),
            Err(_) => {
                anyhow::bail!("BIP39 wordlist not found. Run ensure_dictionaries() first.")
            }
        }
    }

    fn generate_dates(start_year: u32, end_year: u32) -> Vec<String> {
        let mut dates = Vec::new();

        for year in start_year..=end_year {
            dates.push(format!("{:04}", year));
            dates.push(format!("{:02}", year % 100));

            for month in 1..=12 {
                dates.push(format!("{:04}{:02}", year, month));
                dates.push(format!("{:02}{:02}", year % 100, month));
                dates.push(format!("{:04}-{:02}", year, month));

                for day in 1..=28 {
                    dates.push(format!("{:04}{:02}{:02}", year, month, day));
                    dates.push(format!("{:02}{:02}{:02}", year % 100, month, day));
                }
            }
        }

        dates
    }

    fn generate_default_names() -> Vec<String> {
        vec![
            "john", "jane", "alice", "bob", "charlie", "david", "emma", "frank",
            "grace", "henry", "isabella", "jack", "kate", "liam", "mary", "noah",
            "olivia", "peter", "quinn", "rachel", "steve", "tom", "uma", "victor",
            "wendy", "xavier", "yara", "zack", "bitcoin", "satoshi", "crypto",
        ].iter().map(|s| s.to_string()).collect()
    }

    fn generate_default_phrases() -> Vec<&'static str> {
        vec![
            "hello world", "to be or not to be", "the quick brown fox",
            "to the moon", "buy the dip", "not your keys not your coins",
            "hodl bitcoin", "trust the process", "have fun staying poor",
            "never give up", "just do it", "make it happen", "dream big",
            "we will rock you", "we are the champions", "dont stop believing",
            "may the force be with you", "ill be back", "you cant handle the truth",
            "all your base", "over nine thousand", "do you even lift",
            "bitcoin 2009", "ethereum 2015", "crypto 2021", "nft 2022",
            "password 123", "admin 2024", "test test test",
        ]
    }

    fn generate_default_crypto_terms() -> Vec<&'static str> {
        vec![
            "bitcoin", "btc", "satoshi", "ethereum", "eth", "litecoin", "dogecoin",
            "ripple", "xrp", "cardano", "ada", "polkadot", "dot", "solana", "sol",
            "binance", "bnb", "usdt", "usdc", "dai",
            "blockchain", "crypto", "wallet", "seed", "mnemonic", "private", "public",
            "address", "transaction", "mining", "staking", "defi", "nft", "token",
            "exchange", "hodl", "moon", "lambo", "rekt", "fomo", "dyor",
            "to the moon", "buy the dip", "not your keys", "gm", "wagmi", "ngmi",
            "bitcoin2024", "eth2023", "crypto2025", "satoshi21", "btc100k",
            "password", "123456", "qwerty", "letmein", "admin", "root",
        ]
    }

    fn generate_default_weak_seeds() -> Vec<String> {
        use sha2::{Sha256, Digest};

        let mut seeds = vec![
            "0".repeat(64),
            "f".repeat(64),
            "0123456789abcdef".repeat(4),
            "fedcba9876543210".repeat(4),
            "deadbeef".repeat(8),
            "cafebabe".repeat(8),
            "baadf00d".repeat(8),
        ];

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