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
            // CRITICAL: BIP39 requires checksum validation. Repeating the same word 12 times
            // will almost never create a valid BIP39 mnemonic (checksum will fail).
            // For BIP39 wallet attacks, use Bip39Repeat pattern instead.
            AttackPattern::SingleWord { word } => {
                // Use PBKDF2 directly - this is the correct way for single word passphrases
                // BIP39 checksum validation would fail for repeated words anyway
                self.pbkdf2_seed(word)
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
            // - m/44'/0' = Legacy (P2PKH) - Bitcoin mainnet only
            // - m/49'/0' = SegWit (P2SH-P2WPKH) - Bitcoin mainnet only
            // - m/84'/0' = Native SegWit (P2WPKH) - Bitcoin mainnet only
            // Note: We only support mainnet (coin_type 0), not testnet (coin_type 1)
            // More specific check prevents edge cases like m/44'/1'/... (testnet) from being accepted
            let address = if path_str.starts_with("m/44'/0'") {
                // Legacy (P2PKH) - m/44'/0'/0'/0/0 (Bitcoin mainnet only)
                bitcoin::Address::p2pkh(&pubkey, Network::Bitcoin)
            } else if path_str.starts_with("m/49'/0'") {
                // SegWit (P2SH-P2WPKH) - m/49'/0'/0'/0/0 (Bitcoin mainnet only)
                bitcoin::Address::p2shwpkh(&pubkey, Network::Bitcoin)
                    .context("Failed to create SegWit address")?
            } else if path_str.starts_with("m/84'/0'") {
                // Native SegWit (P2WPKH) - m/84'/0'/0'/0/0 (Bitcoin mainnet only)
                bitcoin::Address::p2wpkh(&pubkey, Network::Bitcoin)
                    .context("Failed to create Native SegWit address")?
            } else {
                // Reject unknown derivation paths to prevent generating incorrect addresses
                // Note: Testnet paths (m/44'/1', etc.) are not supported
                anyhow::bail!("Unsupported Bitcoin derivation path: {}. Supported paths: m/44'/0' (Legacy), m/49'/0' (SegWit), m/84'/0' (Native SegWit) - mainnet only", path_str);
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
        // serialize_uncompressed() returns 65 bytes: 0x04 (1 byte) + X (32 bytes) + Y (32 bytes)
        let pub_bytes_full = public_key.serialize_uncompressed();
        assert_eq!(pub_bytes_full.len(), 65, "Uncompressed pubkey must be exactly 65 bytes: 0x04 prefix (1 byte) + X coordinate (32 bytes) + Y coordinate (32 bytes)");
        let pub_bytes = &pub_bytes_full[1..]; // Remove 0x04 prefix, get exactly 64 bytes (X + Y coordinates)
        assert_eq!(pub_bytes.len(), 64, "Public key coordinates (X + Y) must be exactly 64 bytes after removing 0x04 prefix");
        let hash = Self::keccak256(pub_bytes);
        let address = hex::encode(&hash[12..]);

        Ok(format!("0x{}", address))
    }

    /// Generate Solana address
    /// Solana uses Ed25519 with BIP44 derivation path m/44'/501'/0'/0'
    /// Standard Solana wallets use BIP44 derivation, then convert derived key to Ed25519
    fn generate_sol_address(&self, seed: &[u8; 64]) -> Result<String> {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        
        // Solana uses BIP44 path: m/44'/501'/0'/0'
        // Derive using BIP32/BIP44 first, then convert to Ed25519
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
            .context("Failed to create master key for Solana")?;
        let path = DerivationPath::from_str("m/44'/501'/0'/0'")
            .context("Invalid Solana derivation path")?;
        let derived = xpriv.derive_priv(&self.secp, &path)
            .context("Failed to derive Solana key")?;
        
        // Use first 32 bytes of the derived private key as Ed25519 seed
        // This is the standard way Solana wallets derive addresses
        let private_key_bytes = derived.to_priv().to_bytes();
        let ed25519_seed: [u8; 32] = private_key_bytes[0..32].try_into()
            .map_err(|_| anyhow::anyhow!("Invalid seed length for Ed25519"))?;
        
        // Create Ed25519 signing key from derived seed
        let signing_key = SigningKey::from_bytes(&ed25519_seed);
        
        // Get verifying key (public key)
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
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

    #[test]
    fn test_bip39_to_btc() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        assert!(!wallets.btc.is_empty());
        assert!(wallets.btc[0].starts_with("bc1") || wallets.btc[0].starts_with("1"));
    }

    #[test]
    fn test_eth_address_format() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        assert!(wallets.eth.starts_with("0x"));
        assert_eq!(wallets.eth.len(), 42); // 0x + 40 hex chars
    }
}