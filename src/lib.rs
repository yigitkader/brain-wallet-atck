// lib.rs - Brainwallet Security Auditor Library
// Enterprise-grade module organization

pub mod config;
pub mod dictionary;
pub mod pattern;
pub mod wallet;
pub mod balance;
pub mod stats;
pub mod checkpoint;
pub mod bloom;

// Re-exports for convenience
pub use config::Config;
pub use dictionary::{DictionaryLoader, Dictionaries};
pub use pattern::{AttackPattern, PatternGenerator};
pub use wallet::{WalletGenerator, WalletAddresses};
pub use balance::{BalanceChecker, BalanceResults};
pub use stats::Statistics;
pub use checkpoint::CheckpointManager;
pub use bloom::BloomFilterManager;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Error types
pub mod error {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum AuditorError {
        #[error("Configuration error: {0}")]
        Config(String),

        #[error("Dictionary loading error: {0}")]
        Dictionary(String),

        #[error("Pattern generation error: {0}")]
        Pattern(String),

        #[error("Wallet generation error: {0}")]
        Wallet(String),

        #[error("Balance check error: {0}")]
        Balance(String),

        #[error("Checkpoint error: {0}")]
        Checkpoint(String),

        #[error("IO error: {0}")]
        Io(#[from] std::io::Error),

        #[error("JSON error: {0}")]
        Json(#[from] serde_json::Error),

        #[error("Network error: {0}")]
        Network(#[from] reqwest::Error),
    }

    pub type Result<T> = std::result::Result<T, AuditorError>;
}

/// Utilities module
pub mod utils {

    /// Format balance with proper decimals
    pub fn format_balance(balance: f64, decimals: u8) -> String {
        format!("{:.1$}", balance, decimals as usize)
    }

    /// Format duration in human-readable format
    pub fn format_duration(seconds: f64) -> String {
        if seconds < 60.0 {
            format!("{:.1}s", seconds)
        } else if seconds < 3600.0 {
            format!("{:.1}m", seconds / 60.0)
        } else if seconds < 86400.0 {
            format!("{:.1}h", seconds / 3600.0)
        } else {
            format!("{:.1}d", seconds / 86400.0)
        }
    }

    /// Format number with thousands separator
    pub fn format_number(n: u64) -> String {
        let s = n.to_string();
        let mut result = String::new();
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        result.chars().rev().collect()
    }

    /// Estimate time remaining
    pub fn estimate_remaining(
        checked: u64,
        total: u64,
        rate: f64,
    ) -> String {
        if rate <= 0.0 {
            return "Unknown".to_string();
        }

        let remaining = total.saturating_sub(checked) as f64;
        let seconds = remaining / rate;
        format_duration(seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_balance() {
        assert_eq!(utils::format_balance(1.23456789, 8), "1.23456789");
        assert_eq!(utils::format_balance(0.0001, 4), "0.0001");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(utils::format_duration(30.0), "30.0s");
        assert_eq!(utils::format_duration(120.0), "2.0m");
        assert_eq!(utils::format_duration(7200.0), "2.0h");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(utils::format_number(1000), "1,000");
        assert_eq!(utils::format_number(1234567), "1,234,567");
    }
}