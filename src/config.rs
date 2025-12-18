use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::fs;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub attack: AttackConfig,
    pub dictionaries: DictionaryConfig,
    pub chains: ChainConfig,
    pub rate_limiting: RateLimitConfig,
    pub optimization: OptimizationConfig,
    pub api: ApiConfig,
    pub notifications: NotificationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    /// Priority levels to test first
    pub priorities: Vec<String>,

    /// Maximum patterns to test
    pub max_patterns: usize,

    /// Resume from checkpoint
    pub resume_from_checkpoint: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionaryConfig {
    /// Dictionary file paths
    pub passwords: String,
    pub bip39: String,
    pub phrases: String,
    pub crypto: String,
    pub weak_seeds: String,
    pub names: String,

    /// Limits for loading
    pub passwords_limit: usize,
    pub phrases_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Enabled blockchains
    pub enabled: Vec<String>,

    /// Bitcoin derivation paths
    pub btc_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Minimum delay between requests (ms)
    pub min_delay_ms: u64,

    /// Cooldown after batch (ms)
    pub batch_cooldown_ms: u64,

    /// Max retries
    pub max_retries: u32,

    /// Optional per-chain overrides (ms). If None, fall back to `min_delay_ms`.
    #[serde(default)]
    pub btc_min_delay_ms: Option<u64>,
    #[serde(default)]
    pub eth_min_delay_ms: Option<u64>,
    #[serde(default)]
    pub sol_min_delay_ms: Option<u64>,

    /// Optional per-chain cooldown overrides (ms). If None, fall back to `batch_cooldown_ms`.
    #[serde(default)]
    pub btc_batch_cooldown_ms: Option<u64>,
    #[serde(default)]
    pub eth_batch_cooldown_ms: Option<u64>,
    #[serde(default)]
    pub sol_batch_cooldown_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationConfig {
    /// Use bloom filter to skip duplicates
    pub use_bloom_filter: bool,

    /// Bloom filter capacity
    pub bloom_capacity: usize,

    /// Use GPU acceleration (requires CUDA)
    #[serde(default)]
    pub use_gpu: bool,

    /// Batch size for GPU
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Max password combinations for PasswordNumber pattern (prevents memory explosion)
    #[serde(default = "default_max_password_combinations")]
    pub max_password_combinations: usize,

    /// Max mutations per word (prevents memory explosion in pattern mutations)
    /// Each word can generate ~20 mutations (leetspeak, case, suffixes, prefixes)
    /// Lower this value to reduce memory usage
    #[serde(default = "default_max_mutations_per_word")]
    pub max_mutations_per_word: usize,

    /// Max words to generate mutations for (prevents memory explosion)
    /// Mutations are expensive: 1000 words × 20 mutations = 20K patterns
    #[serde(default = "default_max_mutation_words")]
    pub max_mutation_words: usize,

    /// BIP39 passphrases to try for mnemonic-derived seeds (BIP39 optional passphrase).
    /// Include empty string to try "no passphrase".
    #[serde(default = "default_bip39_passphrases")]
    pub bip39_passphrases: Vec<String>,
}

fn default_batch_size() -> usize {
    1000
}

fn default_max_password_combinations() -> usize {
    100
}

fn default_max_mutations_per_word() -> usize {
    10 // Limit mutations per word to prevent memory explosion
}

fn default_max_mutation_words() -> usize {
    1000 // Limit number of words to mutate (1000 words × 10 mutations = 10K patterns)
}

fn default_bip39_passphrases() -> Vec<String> {
    vec!["".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Webhook URL for alerts (can be set via WEBHOOK_URL env var for security)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,

    /// Email for alerts (can be set via EMAIL env var for security)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Alert on find
    pub alert_on_find: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Etherscan API key (can be set via ETHERSCAN_API_KEY env var)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etherscan_api_key: Option<String>,
}

impl Config {
    /// Load configuration from TOML file and environment variables
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .context(format!("Failed to read config file: {}", path))?;

        let mut config: Config = toml::from_str(&content)
            .context("Failed to parse TOML config")?;

        // Override sensitive values from environment variables (more secure)
        config.load_from_env();

        config.validate()?;

        Ok(config)
    }

    /// Load sensitive config from environment variables (overrides file config)
    fn load_from_env(&mut self) {
        // Webhook URL from environment variable (prevents credential leak in git)
        if let Ok(webhook) = std::env::var("WEBHOOK_URL") {
            if !webhook.is_empty() {
                self.notifications.webhook_url = Some(webhook);
            }
        }
        
        // Email from environment variable (prevents credential leak in git)
        if let Ok(email) = std::env::var("EMAIL") {
            if !email.is_empty() {
                self.notifications.email = Some(email);
            }
        }

        // Etherscan API key from environment variable
        if let Ok(key) = std::env::var("ETHERSCAN_API_KEY") {
            if !key.is_empty() {
                self.api.etherscan_api_key = Some(key);
            }
        }
    }

    /// Validate configuration
    fn validate(&self) -> Result<()> {
        if self.attack.max_patterns == 0 {
            anyhow::bail!("max_patterns must be greater than 0");
        }

        if self.chains.enabled.is_empty() {
            anyhow::bail!("At least one chain must be enabled");
        }

        if self.chains.btc_paths.is_empty() {
            anyhow::bail!("At least one BTC derivation path required");
        }

        // Rate limiting sanity checks (defaults are tuned for speed, but prevent nonsense values)
        if self.rate_limiting.min_delay_ms == 0 {
            anyhow::bail!("rate_limiting.min_delay_ms must be >= 1");
        }
        if self.rate_limiting.min_delay_ms > 60_000 {
            anyhow::bail!("rate_limiting.min_delay_ms is too high (>{}ms)", 60_000);
        }
        if self.rate_limiting.batch_cooldown_ms > 300_000 {
            anyhow::bail!("rate_limiting.batch_cooldown_ms is too high (>{}ms)", 300_000);
        }
        if self.rate_limiting.max_retries == 0 {
            anyhow::bail!("rate_limiting.max_retries must be >= 1");
        }
        if self.rate_limiting.max_retries > 100 {
            anyhow::bail!("rate_limiting.max_retries is too high (>{})", 100);
        }

        // Per-chain overrides sanity checks (if present)
        for (name, v) in [
            ("btc_min_delay_ms", self.rate_limiting.btc_min_delay_ms),
            ("eth_min_delay_ms", self.rate_limiting.eth_min_delay_ms),
            ("sol_min_delay_ms", self.rate_limiting.sol_min_delay_ms),
        ] {
            if let Some(ms) = v {
                if ms == 0 {
                    anyhow::bail!("rate_limiting.{} must be >= 1", name);
                }
                if ms > 60_000 {
                    anyhow::bail!("rate_limiting.{} is too high (>{}ms)", name, 60_000);
                }
            }
        }
        for (name, v) in [
            ("btc_batch_cooldown_ms", self.rate_limiting.btc_batch_cooldown_ms),
            ("eth_batch_cooldown_ms", self.rate_limiting.eth_batch_cooldown_ms),
            ("sol_batch_cooldown_ms", self.rate_limiting.sol_batch_cooldown_ms),
        ] {
            if let Some(ms) = v {
                if ms > 300_000 {
                    anyhow::bail!("rate_limiting.{} is too high (>{}ms)", name, 300_000);
                }
            }
        }

        // BIP39 passphrase explosion guard: each passphrase multiplies work.
        // Keep this conservative to prevent accidental OOM/network storms.
        let passphrase_count = self.optimization.bip39_passphrases.len();
        if passphrase_count > 5 {
            anyhow::bail!(
                "Too many BIP39 passphrases (max 5). Each passphrase multiplies work! Got {}",
                passphrase_count
            );
        }
        for (idx, p) in self.optimization.bip39_passphrases.iter().enumerate() {
            if p.len() > 256 {
                anyhow::bail!(
                    "BIP39 passphrase #{} is too long (>{} chars)",
                    idx,
                    256
                );
            }
        }

        Ok(())
    }

    /// Create default configuration
    pub fn default_toml() -> String {
        r#"
[attack]
priorities = ["known_weak", "single_word", "bip39_repeat"]
max_patterns = 10_000_000
resume_from_checkpoint = true

[dictionaries]
passwords = "dictionaries/rockyou.txt"
bip39 = "dictionaries/bip39-english.txt"
phrases = "dictionaries/common-phrases.txt"
crypto = "dictionaries/crypto-terms.txt"
weak_seeds = "dictionaries/known-weak-seeds.txt"
names = "dictionaries/top-names.txt"

passwords_limit = 1_000_000
phrases_limit = 100_000

[chains]
enabled = ["BTC", "ETH", "SOL"]

btc_paths = [
    "m/44'/0'/0'/0/0",   # Legacy
    "m/49'/0'/0'/0/0",   # SegWit
    "m/84'/0'/0'/0/0"    # Native SegWit
]

[rate_limiting]
min_delay_ms = 100
batch_cooldown_ms = 1000
max_retries = 10
btc_min_delay_ms = 1000
eth_min_delay_ms = 1000
sol_min_delay_ms = 1000
btc_batch_cooldown_ms = 0
eth_batch_cooldown_ms = 0
sol_batch_cooldown_ms = 0

[optimization]
use_bloom_filter = true
bloom_capacity = 100_000_000
use_gpu = false
batch_size = 1000
max_password_combinations = 100
max_mutations_per_word = 10
max_mutation_words = 1000
bip39_passphrases = [""]

[notifications]
webhook_url = ""
email = ""
alert_on_find = true

[api]
etherscan_api_key = ""
"#.to_string()
    }

    /// Save default config to file
    pub fn save_default(path: &str) -> Result<()> {
        fs::write(path, Self::default_toml())
            .context("Failed to write default config")?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            attack: AttackConfig {
                priorities: vec![
                    "known_weak".to_string(),
                    "single_word".to_string(),
                    "bip39_repeat".to_string(),
                ],
                max_patterns: 10_000_000,
                resume_from_checkpoint: true,
            },
            dictionaries: DictionaryConfig {
                passwords: "dictionaries/rockyou.txt".to_string(),
                bip39: "dictionaries/bip39-english.txt".to_string(),
                phrases: "dictionaries/common-phrases.txt".to_string(),
                crypto: "dictionaries/crypto-terms.txt".to_string(),
                weak_seeds: "dictionaries/known-weak-seeds.txt".to_string(),
                names: "dictionaries/top-names.txt".to_string(),
                passwords_limit: 1_000_000,
                phrases_limit: 100_000,
            },
            chains: ChainConfig {
                enabled: vec!["BTC".to_string(), "ETH".to_string()],
                btc_paths: vec![
                    "m/44'/0'/0'/0/0".to_string(),
                    "m/49'/0'/0'/0/0".to_string(),
                    "m/84'/0'/0'/0/0".to_string(),
                ],
            },
            rate_limiting: RateLimitConfig {
                min_delay_ms: 100,
                batch_cooldown_ms: 1000,
                max_retries: 10,
                btc_min_delay_ms: Some(1000),
                eth_min_delay_ms: Some(1000),
                sol_min_delay_ms: Some(1000),
                btc_batch_cooldown_ms: Some(0),
                eth_batch_cooldown_ms: Some(0),
                sol_batch_cooldown_ms: Some(0),
            },
            optimization: OptimizationConfig {
                use_bloom_filter: true,
                bloom_capacity: 100_000_000,
                use_gpu: false,
                batch_size: 1000,
                max_password_combinations: 100,
                max_mutations_per_word: 10,
                max_mutation_words: 1000,
                bip39_passphrases: vec!["".to_string()],
            },
            api: ApiConfig {
                etherscan_api_key: None,
            },
            notifications: NotificationConfig {
                webhook_url: None,
                email: None,
                alert_on_find: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.attack.max_patterns, 10_000_000);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml = toml::to_string(&config).unwrap();
        let parsed: Config = toml::from_str(&toml).unwrap();
        assert_eq!(parsed.attack.max_patterns, config.attack.max_patterns);
    }

    #[test]
    fn test_validate_rejects_too_many_bip39_passphrases() {
        let mut config = Config::default();
        config.optimization.bip39_passphrases = vec![
            "".to_string(),
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ];
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Too many BIP39 passphrases"), "got err: {}", err);
    }

    #[test]
    fn test_validate_rejects_invalid_rate_limit_overrides() {
        let mut config = Config::default();
        config.rate_limiting.eth_min_delay_ms = Some(0);
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("rate_limiting.eth_min_delay_ms must be >= 1"), "got err: {}", err);
    }
}