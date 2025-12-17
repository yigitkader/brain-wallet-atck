// lib.rs - Brainwallet Security Auditor Library
// Minimal library interface for potential future use

pub mod config;
pub mod dictionary;
pub mod pattern;
pub mod wallet;
pub mod balance;
pub mod stats;
pub mod checkpoint;
pub mod bloom;
pub mod notifications;

// Re-exports for convenience
pub use config::Config;
pub use dictionary::{DictionaryLoader, Dictionaries};
pub use pattern::{AttackPattern, PatternGenerator};
pub use wallet::{WalletGenerator, WalletAddresses};
pub use balance::{BalanceChecker, BalanceResults};
pub use stats::Statistics;
pub use checkpoint::CheckpointManager;
pub use bloom::BloomFilterManager;
pub use notifications::NotificationManager;