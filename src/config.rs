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
}

fn default_batch_size() -> usize {
    1000
}

fn default_max_password_combinations() -> usize {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Webhook URL for alerts
    pub webhook_url: Option<String>,

    /// Email for alerts
    pub email: Option<String>,

    /// Alert on find
    pub alert_on_find: bool,
}

impl Config {
    /// Load configuration from TOML file
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .context(format!("Failed to read config file: {}", path))?;

        let config: Config = toml::from_str(&content)
            .context("Failed to parse TOML config")?;

        config.validate()?;

        Ok(config)
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
min_delay_ms = 1000
batch_cooldown_ms = 5000
max_retries = 3

[optimization]
use_bloom_filter = true
bloom_capacity = 100_000_000
use_gpu = false
batch_size = 1000
max_password_combinations = 100

[notifications]
webhook_url = ""
email = ""
alert_on_find = true
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
                min_delay_ms: 1000,
                batch_cooldown_ms: 5000,
                max_retries: 3,
            },
            optimization: OptimizationConfig {
                use_bloom_filter: true,
                bloom_capacity: 100_000_000,
                use_gpu: false,
                batch_size: 1000,
                max_password_combinations: 100,
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
}