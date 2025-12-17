use anyhow::{Result, Context};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{ExtendedPrivKey, DerivationPath};
use bitcoin::Network;
use bip39::{Mnemonic, Language};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use std::str::FromStr;

use crate::config::Config;
use crate::pattern::AttackPattern;

type HmacSha512 = Hmac<sha2::Sha512>;

/// Wallet addresses for multiple chains
#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletAddresses {
    pub btc: Vec<String>,      // Multiple derivation paths
    pub eth: String,
    pub sol: Option<String>,   // Optional chains
}

/// Wallet generator - derives addresses from patterns
pub struct WalletGenerator {
    config: Config,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl WalletGenerator {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            secp: Secp256k1::new(),
        })
    }

    /// Generate wallet addresses from attack pattern
    pub fn generate(&self, pattern: &AttackPattern) -> Result<WalletAddresses> {
        // Convert pattern to seed
        let seed = self.pattern_to_seed(pattern)?;

        // Generate addresses for each chain
        let btc = self.generate_btc_addresses(&seed)?;
        let eth = self.generate_eth_address(&seed)?;
        let sol = if self.config.chains.enabled.contains(&"SOL".to_string()) {
            Some(self.generate_sol_address(&seed)?)
        } else {
            None
        };

        Ok(WalletAddresses { btc, eth, sol })
    }

    /// Convert pattern to 512-bit seed
    fn pattern_to_seed(&self, pattern: &AttackPattern) -> Result<[u8; 64]> {
        match pattern {
            // Known weak seed - direct hex conversion
            AttackPattern::KnownWeak { seed_hex } => {
                let bytes = hex::decode(seed_hex)
                    .context("Invalid hex seed")?;
                let mut seed = [0u8; 64];
                seed[..bytes.len().min(64)].copy_from_slice(&bytes[..bytes.len().min(64)]);
                Ok(seed)
            }

            // Single word - use PBKDF2 directly (NOT BIP39)
            // CRITICAL: Single word passphrases are NOT valid BIP39 mnemonics.
            // BIP39 requires checksum validation which will always fail for single words.
            // For BIP39 wallet attacks with repeated words, use Bip39Repeat pattern instead.
            AttackPattern::SingleWord { word } => {
                // Direct PBKDF2 - correct approach for single word passphrases
                self.pbkdf2_seed(word)
            }

            // BIP39 repeated word pattern - try BIP39 first, fallback to PBKDF2
            // This pattern attempts to create valid BIP39 mnemonics by repeating a word
            // (e.g., "abandon abandon ... abandon" 12 times)
            // If the checksum is valid, use BIP39 seed derivation; otherwise use PBKDF2
            AttackPattern::Bip39Repeat { word, count } => {
                // Create repeated word mnemonic
                let words: Vec<&str> = std::iter::repeat(word.as_str()).take(*count).collect();
                let repeated = words.join(" ");

                // Try to parse as valid BIP39 mnemonic (with checksum validation)
                if let Ok(mnemonic) = Mnemonic::parse_in_normalized(Language::English, &repeated) {
                    // Valid BIP39 mnemonic - use BIP39 seed derivation
                    Ok(mnemonic.to_seed(""))
                } else {
                    // Invalid BIP39 checksum - fallback to PBKDF2
                    // This handles cases where repeated words don't form valid BIP39 mnemonics
                    self.pbkdf2_seed(&repeated)
                }
            }
            
            // Try BIP39 mnemonic first for other patterns
            _ => {
                let mnemonic_str = pattern.to_mnemonic(&crate::dictionary::Dictionaries::default())?;

                // Try to parse as valid BIP39 (12/15/18/21/24 words)
                if let Ok(mnemonic) = Mnemonic::parse_in_normalized(Language::English, &mnemonic_str) {
                    let seed = mnemonic.to_seed("");
                    Ok(seed)
                } else {
                    // Fallback: Use PBKDF2 on raw text (for non-BIP39 patterns)
                    self.pbkdf2_seed(&mnemonic_str)
                }
            }
        }
    }

    /// Generate seed using PBKDF2 (for non-BIP39 passphrases)
    fn pbkdf2_seed(&self, passphrase: &str) -> Result<[u8; 64]> {
        let mut seed = [0u8; 64];
        pbkdf2::<HmacSha512>(
            passphrase.as_bytes(),
            b"mnemonic",
            2048,
            &mut seed,
        )?;
        Ok(seed)
    }

    /// Generate Bitcoin addresses (multiple derivation paths)
    fn generate_btc_addresses(&self, seed: &[u8; 64]) -> Result<Vec<String>> {
        let mut addresses = Vec::new();

        // Generate extended private key from seed
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
            .context("Failed to create BTC master key")?;

        // Derive addresses for each path
        for path_str in &self.config.chains.btc_paths {
            let path = DerivationPath::from_str(path_str)
                .context("Invalid derivation path")?;

            let derived = xpriv.derive_priv(&self.secp, &path)
                .context("Failed to derive key")?;

            let pubkey = derived.to_priv().public_key(&self.secp);
            
            // Use correct address type based on derivation path
            // CRITICAL: Each BIP44 path type has a specific address format
            // - m/44'/0' = Legacy (P2PKH) - Bitcoin mainnet only (coin_type = 0)
            // - m/49'/0' = SegWit (P2SH-P2WPKH) - Bitcoin mainnet only (coin_type = 0)
            // - m/84'/0' = Native SegWit (P2WPKH) - Bitcoin mainnet only (coin_type = 0)
            // 
            // SECURITY: We MUST check coin_type = 0 to prevent:
            // - m/44'/60'/... (Ethereum) from being treated as Bitcoin Legacy
            // - m/44'/1'/... (Bitcoin testnet) from being treated as Bitcoin mainnet
            // - m/44'/501'/... (Solana) from being treated as Bitcoin Legacy
            //
            // The starts_with check ensures coin_type is 0, not just any number after 44'
            let address = if path_str.starts_with("m/44'/0'") {
                // Legacy (P2PKH) - m/44'/0'/0'/0/0 (Bitcoin mainnet only, coin_type = 0)
                bitcoin::Address::p2pkh(&pubkey, Network::Bitcoin)
            } else if path_str.starts_with("m/49'/0'") {
                // SegWit (P2SH-P2WPKH) - m/49'/0'/0'/0/0 (Bitcoin mainnet only, coin_type = 0)
                bitcoin::Address::p2shwpkh(&pubkey, Network::Bitcoin)
                    .context("Failed to create SegWit address")?
            } else if path_str.starts_with("m/84'/0'") {
                // Native SegWit (P2WPKH) - m/84'/0'/0'/0/0 (Bitcoin mainnet only, coin_type = 0)
                bitcoin::Address::p2wpkh(&pubkey, Network::Bitcoin)
                    .context("Failed to create Native SegWit address")?
            } else {
                // Reject unknown derivation paths to prevent generating incorrect addresses
                // This includes:
                // - Testnet paths (m/44'/1', m/49'/1', m/84'/1')
                // - Other coin types (m/44'/60' = Ethereum, m/44'/501' = Solana, etc.)
                anyhow::bail!(
                    "Unsupported Bitcoin derivation path: {}. \
                    Supported paths: m/44'/0' (Legacy), m/49'/0' (SegWit), m/84'/0' (Native SegWit) - \
                    Bitcoin mainnet only (coin_type must be 0). \
                    Paths like m/44'/60' (Ethereum) or m/44'/1' (testnet) are rejected.",
                    path_str
                );
            };

            addresses.push(address.to_string());
        }

        Ok(addresses)
    }

    /// Generate Ethereum address
    /// Note: Network::Bitcoin is used for BIP32 master key derivation format.
    /// This is technically correct as BIP32 doesn't distinguish between networks at the master key level.
    /// The actual Ethereum address is derived using BIP44 path m/44'/60'/0'/0/0
    /// and uses keccak256 hash, which is correct for Ethereum.
    /// While Ethereum has its own network standards, BIP32 master key derivation is network-agnostic.
    fn generate_eth_address(&self, seed: &[u8; 64]) -> Result<String> {
        // Derive Ethereum key using BIP44 path: m/44'/60'/0'/0/0
        // Network::Bitcoin is used for BIP32 format (network-agnostic at master key level)
        // The final Ethereum address uses keccak256, which is Ethereum-specific
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, seed)?;
        let path = DerivationPath::from_str("m/44'/60'/0'/0/0")?;
        let derived = xpriv.derive_priv(&self.secp, &path)?;

        // Get public key
        let private_key = derived.to_priv();
        let secret_key = private_key.inner;
        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&self.secp, &secret_key);

        // Ethereum address = last 20 bytes of keccak256(public_key)
        // serialize_uncompressed() returns 65 bytes: 0x04 prefix (1 byte) + X coordinate (32 bytes) + Y coordinate (32 bytes)
        // Total: 1 + 32 + 32 = 65 bytes
        let pub_bytes_full = public_key.serialize_uncompressed();
        assert_eq!(pub_bytes_full.len(), 65, 
            "Uncompressed pubkey must be exactly 65 bytes: 0x04 prefix (1 byte) + X coordinate (32 bytes) + Y coordinate (32 bytes) = 65 bytes total");
        let pub_bytes = &pub_bytes_full[1..]; // Remove 0x04 prefix, get exactly 64 bytes (X + Y coordinates)
        assert_eq!(pub_bytes.len(), 64, 
            "Public key coordinates (X + Y) must be exactly 64 bytes after removing 0x04 prefix: X (32 bytes) + Y (32 bytes) = 64 bytes");
        let hash = Self::keccak256(pub_bytes);
        let address = hex::encode(&hash[12..]);

        Ok(format!("0x{}", address))
    }

    /// Generate Solana address
    /// Solana uses Ed25519, NOT secp256k1
    /// CRITICAL: Do NOT use secp256k1 derivation (Bitcoin) and then convert to Ed25519
    /// Instead, use the seed's first 32 bytes directly as Ed25519 seed
    fn generate_sol_address(&self, seed: &[u8; 64]) -> Result<String> {
        use ed25519_dalek::SigningKey;
        
        // Solana uses Ed25519, which is a different cryptographic curve than secp256k1 (Bitcoin)
        // We cannot derive a secp256k1 key and then use its bytes as Ed25519 seed
        // Instead, use the seed's first 32 bytes directly as Ed25519 seed
        let ed25519_seed: [u8; 32] = seed[0..32].try_into()
            .map_err(|_| anyhow::anyhow!("Invalid seed length for Ed25519"))?;
        
        // Create Ed25519 signing key directly from seed
        let signing_key = SigningKey::from_bytes(&ed25519_seed);
        
        // Get verifying key (public key)
        let verifying_key = signing_key.verifying_key();
        
        // Solana address is the Ed25519 public key encoded in base58
        let pubkey_bytes = verifying_key.to_bytes();
        assert_eq!(pubkey_bytes.len(), 32, "Ed25519 public key must be 32 bytes");
        
        Ok(bs58::encode(&pubkey_bytes).into_string())
    }

    /// Keccak256 hash (for Ethereum)
    fn keccak256(data: &[u8]) -> [u8; 32] {
        use tiny_keccak::{Hasher, Keccak};
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Bitcoin address generation with known BIP39 mnemonic
    /// BIP39 test vector: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    /// Expected: Valid Bitcoin addresses for different derivation paths
    #[test]
    fn test_btc_address_generation() {
        let mut config = Config::default();
        config.chains.btc_paths = vec![
            "m/44'/0'/0'/0/0".to_string(),  // Legacy
            "m/49'/0'/0'/0/0".to_string(),  // SegWit
            "m/84'/0'/0'/0/0".to_string(),  // Native SegWit
        ];
        let generator = WalletGenerator::new(&config).unwrap();

        // Use known BIP39 mnemonic
        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        
        // Should generate addresses for all paths
        assert_eq!(wallets.btc.len(), 3, "Should generate 3 BTC addresses for 3 paths");
        
        // Legacy address (P2PKH) should start with "1"
        assert!(wallets.btc[0].starts_with("1"), 
            "Legacy address should start with '1', got: {}", wallets.btc[0]);
        
        // SegWit address (P2SH-P2WPKH) should start with "3"
        assert!(wallets.btc[1].starts_with("3"), 
            "SegWit address should start with '3', got: {}", wallets.btc[1]);
        
        // Native SegWit address (P2WPKH) should start with "bc1"
        assert!(wallets.btc[2].starts_with("bc1"), 
            "Native SegWit address should start with 'bc1', got: {}", wallets.btc[2]);
        
        // All addresses should be valid base58/base32bech32 format
        for addr in &wallets.btc {
            assert!(!addr.is_empty(), "Address should not be empty");
            assert!(addr.len() >= 26 && addr.len() <= 62, 
                "Bitcoin address length should be between 26-62 chars, got: {} (len: {})", addr, addr.len());
        }
    }

    /// Test Ethereum address generation with known BIP39 mnemonic
    /// Expected: Valid Ethereum address (0x + 40 hex chars = 42 chars total)
    #[test]
    fn test_eth_address_generation() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        // Use known BIP39 mnemonic
        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        
        // Ethereum address format: 0x + 40 hex characters
        assert!(wallets.eth.starts_with("0x"), 
            "Ethereum address should start with '0x', got: {}", wallets.eth);
        assert_eq!(wallets.eth.len(), 42, 
            "Ethereum address should be 42 chars (0x + 40 hex), got: {} (len: {})", wallets.eth, wallets.eth.len());
        
        // Verify hex characters after 0x
        let hex_part = &wallets.eth[2..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()), 
            "Ethereum address hex part should contain only hex digits, got: {}", hex_part);
    }

    /// Test Solana address generation
    /// Solana uses Ed25519, address should be base58 encoded 32-byte public key
    #[test]
    fn test_sol_address_generation() {
        let mut config = Config::default();
        config.chains.enabled.push("SOL".to_string());
        let generator = WalletGenerator::new(&config).unwrap();

        // Use known BIP39 mnemonic
        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        
        // Solana address should be present
        assert!(wallets.sol.is_some(), "Solana address should be generated");
        let sol_addr = wallets.sol.unwrap();
        
        // Solana addresses are base58 encoded 32-byte Ed25519 public keys
        // Base58 encoding of 32 bytes results in 32-44 characters (typically ~44)
        assert!(sol_addr.len() >= 32 && sol_addr.len() <= 44, 
            "Solana address length should be 32-44 chars, got: {} (len: {})", sol_addr, sol_addr.len());
        
        // Verify base58 encoding (only contains base58 characters: 1-9, A-H, J-N, P-Z, a-k, m-z)
        assert!(sol_addr.chars().all(|c| {
            matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
        }), "Solana address should be valid base58, got: {}", sol_addr);
    }

    /// Test address generation consistency
    /// Same seed should always produce same addresses
    #[test]
    fn test_address_consistency() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        // Generate addresses twice
        let wallets1 = generator.generate(&pattern).unwrap();
        let wallets2 = generator.generate(&pattern).unwrap();
        
        // All addresses should be identical
        assert_eq!(wallets1.btc, wallets2.btc, "Bitcoin addresses should be consistent");
        assert_eq!(wallets1.eth, wallets2.eth, "Ethereum address should be consistent");
        if wallets1.sol.is_some() && wallets2.sol.is_some() {
            assert_eq!(wallets1.sol, wallets2.sol, "Solana address should be consistent");
        }
    }

    /// Test Bitcoin address format validation for all path types
    #[test]
    fn test_btc_address_formats() {
        let mut config = Config::default();
        config.chains.btc_paths = vec![
            "m/44'/0'/0'/0/0".to_string(),  // Legacy
            "m/49'/0'/0'/0/0".to_string(),  // SegWit
            "m/84'/0'/0'/0/0".to_string(),  // Native SegWit
        ];
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        
        // Verify each address type has correct format
        assert!(wallets.btc[0].starts_with("1"), "Legacy address format");
        assert!(wallets.btc[1].starts_with("3"), "SegWit address format");
        assert!(wallets.btc[2].starts_with("bc1"), "Native SegWit address format");
    }

    /// Test Ethereum address with different seeds
    #[test]
    fn test_eth_address_different_seeds() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        let patterns = vec![
            crate::pattern::AttackPattern::SingleWord { word: "test".to_string() },
            crate::pattern::AttackPattern::SingleWord { word: "password".to_string() },
            crate::pattern::AttackPattern::SingleWord { word: "123456".to_string() },
        ];

        let mut addresses = Vec::new();
        for pattern in patterns {
            let wallets = generator.generate(&pattern).unwrap();
            addresses.push(wallets.eth);
        }

        // All addresses should be unique
        assert_eq!(addresses.len(), 3);
        assert_ne!(addresses[0], addresses[1], "Different seeds should produce different addresses");
        assert_ne!(addresses[1], addresses[2], "Different seeds should produce different addresses");
        assert_ne!(addresses[0], addresses[2], "Different seeds should produce different addresses");

        // All should be valid Ethereum format
        for addr in &addresses {
            assert!(addr.starts_with("0x"));
            assert_eq!(addr.len(), 42);
        }
    }

    /// Test Solana address with different seeds
    #[test]
    fn test_sol_address_different_seeds() {
        let mut config = Config::default();
        config.chains.enabled.push("SOL".to_string());
        let generator = WalletGenerator::new(&config).unwrap();

        let patterns = vec![
            crate::pattern::AttackPattern::SingleWord { word: "test".to_string() },
            crate::pattern::AttackPattern::SingleWord { word: "password".to_string() },
        ];

        let mut addresses = Vec::new();
        for pattern in patterns {
            let wallets = generator.generate(&pattern).unwrap();
            if let Some(sol) = wallets.sol {
                addresses.push(sol);
            }
        }

        // Different seeds should produce different addresses
        assert_eq!(addresses.len(), 2);
        assert_ne!(addresses[0], addresses[1], "Different seeds should produce different Solana addresses");
    }

    /// Test direct seed to address conversion (unit test for individual functions)
    #[test]
    fn test_direct_seed_to_addresses() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        // Create a test seed (64 bytes)
        let test_seed = [0x42u8; 64];

        // Test Bitcoin address generation
        let btc_addresses = generator.generate_btc_addresses(&test_seed).unwrap();
        assert!(!btc_addresses.is_empty());
        for addr in &btc_addresses {
            assert!(addr.starts_with("1") || addr.starts_with("3") || addr.starts_with("bc1"));
        }

        // Test Ethereum address generation
        let eth_address = generator.generate_eth_address(&test_seed).unwrap();
        assert!(eth_address.starts_with("0x"));
        assert_eq!(eth_address.len(), 42);

        // Test Solana address generation
        let sol_address = generator.generate_sol_address(&test_seed).unwrap();
        assert!(!sol_address.is_empty());
        assert!(sol_address.len() >= 32 && sol_address.len() <= 44);
    }

    /// Test that invalid derivation paths are rejected
    #[test]
    fn test_invalid_btc_paths() {
        let mut config = Config::default();
        // Testnet path should be rejected (we only support mainnet)
        config.chains.btc_paths = vec!["m/44'/1'/0'/0/0".to_string()]; // Testnet
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        // Should fail because testnet paths are not supported
        let result = generator.generate(&pattern);
        assert!(result.is_err(), "Testnet paths should be rejected");
    }

    /// Test Bip39Repeat pattern - should try BIP39 first, fallback to PBKDF2
    #[test]
    fn test_bip39_repeat_pattern() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        // Test with known valid BIP39 mnemonic (12 words)
        // "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        // This is a valid BIP39 mnemonic with correct checksum
        let valid_pattern = crate::pattern::AttackPattern::Bip39Repeat {
            word: "abandon".to_string(),
            count: 12,
        };

        let wallets_valid = generator.generate(&valid_pattern).unwrap();
        assert!(!wallets_valid.btc.is_empty(), "Should generate BTC addresses");
        assert!(wallets_valid.eth.starts_with("0x"), "Should generate ETH address");

        // Test with invalid BIP39 mnemonic (same word repeated, but checksum will fail)
        // Most repeated words will fail BIP39 checksum validation
        let invalid_pattern = crate::pattern::AttackPattern::Bip39Repeat {
            word: "test".to_string(),
            count: 12,
        };

        // Should still work (fallback to PBKDF2)
        let wallets_invalid = generator.generate(&invalid_pattern).unwrap();
        assert!(!wallets_invalid.btc.is_empty(), "Should generate BTC addresses with PBKDF2 fallback");
        assert!(wallets_invalid.eth.starts_with("0x"), "Should generate ETH address with PBKDF2 fallback");

        // Different patterns should produce different addresses
        assert_ne!(wallets_valid.btc[0], wallets_invalid.btc[0], 
            "Valid BIP39 and invalid BIP39 (PBKDF2 fallback) should produce different addresses");
        assert_ne!(wallets_valid.eth, wallets_invalid.eth,
            "Valid BIP39 and invalid BIP39 (PBKDF2 fallback) should produce different ETH addresses");
    }

    /// Test SingleWord pattern uses PBKDF2 directly (not BIP39)
    #[test]
    fn test_single_word_uses_pbkdf2() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        // SingleWord should use PBKDF2 directly, not attempt BIP39
        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        
        // Should successfully generate addresses using PBKDF2
        assert!(!wallets.btc.is_empty(), "Should generate BTC addresses");
        assert!(wallets.eth.starts_with("0x"), "Should generate ETH address");
        assert_eq!(wallets.eth.len(), 42, "ETH address should be valid format");
    }

    /// Test Solana address generation with various seed types
    /// Comprehensive test for Solana Ed25519 address generation
    #[test]
    fn test_solana_address_generation_comprehensive() {
        let mut config = Config::default();
        config.chains.enabled.push("SOL".to_string());
        let generator = WalletGenerator::new(&config).unwrap();

        // Test with BIP39 mnemonic
        let bip39_pattern = crate::pattern::AttackPattern::Bip39Repeat {
            word: "abandon".to_string(),
            count: 12,
        };
        let wallets_bip39 = generator.generate(&bip39_pattern).unwrap();
        assert!(wallets_bip39.sol.is_some(), "BIP39 pattern should generate Solana address");
        let sol_bip39 = wallets_bip39.sol.unwrap();
        assert!(sol_bip39.len() >= 32 && sol_bip39.len() <= 44, 
                "Solana address should be valid length, got: {} (len: {})", sol_bip39, sol_bip39.len());

        // Test with single word (PBKDF2)
        let single_word_pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };
        let wallets_single = generator.generate(&single_word_pattern).unwrap();
        assert!(wallets_single.sol.is_some(), "Single word pattern should generate Solana address");
        let sol_single = wallets_single.sol.as_ref().unwrap().clone();
        
        // Verify addresses are different for different patterns
        assert_ne!(sol_bip39, sol_single, "Different patterns should produce different Solana addresses");

        // Test consistency (same pattern = same address)
        let wallets_single2 = generator.generate(&single_word_pattern).unwrap();
        assert_eq!(wallets_single.sol, wallets_single2.sol, 
                   "Same pattern should produce same Solana address");

        // Test with known weak seed
        let weak_seed_pattern = crate::pattern::AttackPattern::KnownWeak {
            seed_hex: "0".repeat(64),
        };
        let wallets_weak = generator.generate(&weak_seed_pattern).unwrap();
        assert!(wallets_weak.sol.is_some(), "Known weak seed should generate Solana address");
        let sol_weak = wallets_weak.sol.unwrap();
        
        // Verify all addresses are valid base58
        for addr in [&sol_bip39, &sol_single, &sol_weak] {
            assert!(addr.chars().all(|c| {
                matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
            }), "Solana address should be valid base58: {}", addr);
        }
    }

    /// Test that non-Bitcoin coin types are rejected (Ethereum, Solana, etc.)
    #[test]
    fn test_btc_path_rejects_other_coin_types() {
        let test_seed = [0x42u8; 64];

        // Test Ethereum path (m/44'/60'/0'/0/0) - should be rejected
        let mut config = Config::default();
        config.chains.btc_paths = vec!["m/44'/60'/0'/0/0".to_string()]; // Ethereum coin_type
        let generator = WalletGenerator::new(&config).unwrap();
        let result = generator.generate_btc_addresses(&test_seed);
        match result {
            Ok(addresses) => {
                panic!("Ethereum path (m/44'/60') should be rejected for BTC address generation, but got addresses: {:?}", addresses);
            }
            Err(e) => {
                assert!(e.to_string().contains("Unsupported Bitcoin derivation path"), 
                    "Error should mention unsupported path, got: {}", e);
            }
        }
        
        // Test Solana path (m/44'/501'/0'/0/0) - should be rejected
        let mut config = Config::default();
        config.chains.btc_paths = vec!["m/44'/501'/0'/0/0".to_string()]; // Solana coin_type
        let generator = WalletGenerator::new(&config).unwrap();
        let result = generator.generate_btc_addresses(&test_seed);
        match result {
            Ok(addresses) => {
                panic!("Solana path (m/44'/501') should be rejected for BTC address generation, but got addresses: {:?}", addresses);
            }
            Err(e) => {
                assert!(e.to_string().contains("Unsupported Bitcoin derivation path"), 
                    "Error should mention unsupported path, got: {}", e);
            }
        }

        // Test that valid Bitcoin paths still work
        let mut config = Config::default();
        config.chains.btc_paths = vec!["m/44'/0'/0'/0/0".to_string()]; // Bitcoin mainnet
        let generator = WalletGenerator::new(&config).unwrap();
        let addresses = generator.generate_btc_addresses(&test_seed).unwrap();
        assert!(!addresses.is_empty(), "Valid Bitcoin path should work");
    }
}