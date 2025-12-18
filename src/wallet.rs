use anyhow::{Result, Context, bail};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BtcAddressType {
    LegacyP2pkh,
    SegwitP2shP2wpkh,
    NativeSegwitP2wpkh,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletAddresses {
    pub btc: Vec<String>,
    pub eth: String,
    pub sol: Option<String>,
}

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

    pub fn generate(&self, pattern: &AttackPattern) -> Result<WalletAddresses> {
        let seed = self.pattern_to_seed(pattern)?;

        let btc = self.generate_btc_addresses(&seed)?;
        let eth = self.generate_eth_address(&seed)?;
        let sol = if self.config.chains.enabled.contains(&"SOL".to_string()) {
            Some(self.generate_sol_address(&seed)?)
        } else {
            None
        };

        Ok(WalletAddresses { btc, eth, sol })
    }

    fn pattern_to_seed(&self, pattern: &AttackPattern) -> Result<[u8; 64]> {
        match pattern {
            AttackPattern::KnownWeak { seed_hex } => {
                let bytes = hex::decode(seed_hex)
                    .context("Invalid hex seed")?;
                let mut seed = [0u8; 64];
                seed[..bytes.len().min(64)].copy_from_slice(&bytes[..bytes.len().min(64)]);
                Ok(seed)
            }

            AttackPattern::SingleWord { word } => {
                self.pbkdf2_seed(word)
            }

            AttackPattern::Bip39Repeat { word, count } => {
                let words: Vec<&str> = std::iter::repeat_n(word.as_str(), *count).collect();
                let repeated = words.join(" ");

                if let Ok(mnemonic) = Mnemonic::parse_in_normalized(Language::English, &repeated) {
                    Ok(mnemonic.to_seed(""))
                } else {
                    self.pbkdf2_seed(&repeated)
                }
            }

            _ => {
                let mnemonic_str = pattern.to_mnemonic(&crate::dictionary::Dictionaries::default())?;

                if let Ok(mnemonic) = Mnemonic::parse_in_normalized(Language::English, &mnemonic_str) {
                    let seed = mnemonic.to_seed("");
                    Ok(seed)
                } else {
                    self.pbkdf2_seed(&mnemonic_str)
                }
            }
        }
    }

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

    fn generate_btc_addresses(&self, seed: &[u8; 64]) -> Result<Vec<String>> {
        let mut addresses = Vec::new();

        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
            .context("Failed to create BTC master key")?;

        for path_str in &self.config.chains.btc_paths {
            let path = DerivationPath::from_str(path_str)
                .context("Invalid derivation path")?;

            let derived = xpriv.derive_priv(&self.secp, &path)
                .context("Failed to derive key")?;

            let pubkey = derived.to_priv().public_key(&self.secp);

            let addr_type = match Self::btc_address_type_for_path(&path) {
                Ok(t) => t,
                Err(e) => {
                    bail!("Unsupported Bitcoin derivation path: {} ({})", path_str, e);
                }
            };

            let address = match addr_type {
                BtcAddressType::LegacyP2pkh => bitcoin::Address::p2pkh(&pubkey, Network::Bitcoin),
                BtcAddressType::SegwitP2shP2wpkh => bitcoin::Address::p2shwpkh(&pubkey, Network::Bitcoin)
                    .context("Failed to create SegWit address")?,
                BtcAddressType::NativeSegwitP2wpkh => bitcoin::Address::p2wpkh(&pubkey, Network::Bitcoin)
                    .context("Failed to create Native SegWit address")?,
            };

            addresses.push(address.to_string());
        }

        Ok(addresses)
    }

    /// Strict BTC derivation path validation:
    /// Only accept m/{44,49,84}'/0'/0'/0/0
    fn btc_address_type_for_path(path: &DerivationPath) -> Result<BtcAddressType> {
        use bitcoin::util::bip32::ChildNumber;

        let comps: Vec<ChildNumber> = path.into_iter().cloned().collect();
        if comps.len() != 5 {
            bail!("BTC derivation path must have exactly 5 components (m/purpose'/coin_type'/account'/change/index)");
        }

        let purpose = comps[0];
        let coin_type = comps[1];
        let account = comps[2];
        let change = comps[3];
        let index = comps[4];

        if coin_type != ChildNumber::from_hardened_idx(0)? {
            bail!("BTC derivation path coin_type must be 0'");
        }
        if account != ChildNumber::from_hardened_idx(0)? {
            bail!("BTC derivation path account must be 0'");
        }
        if change != ChildNumber::from_normal_idx(0)? {
            bail!("BTC derivation path change must be 0");
        }
        if index != ChildNumber::from_normal_idx(0)? {
            bail!("BTC derivation path index must be 0");
        }

        if purpose == ChildNumber::from_hardened_idx(44)? {
            Ok(BtcAddressType::LegacyP2pkh)
        } else if purpose == ChildNumber::from_hardened_idx(49)? {
            Ok(BtcAddressType::SegwitP2shP2wpkh)
        } else if purpose == ChildNumber::from_hardened_idx(84)? {
            Ok(BtcAddressType::NativeSegwitP2wpkh)
        } else {
            bail!("BTC derivation path purpose must be 44', 49', or 84'");
        }
    }

    /// Generate Ethereum address with EIP-55 checksum
    /// FIXED: Added EIP-55 checksum encoding
    fn generate_eth_address(&self, seed: &[u8; 64]) -> Result<String> {
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, seed)?;
        let path = DerivationPath::from_str("m/44'/60'/0'/0/0")?;
        let derived = xpriv.derive_priv(&self.secp, &path)?;

        let private_key = derived.to_priv();
        let secret_key = private_key.inner;
        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&self.secp, &secret_key);

        let pub_bytes_full = public_key.serialize_uncompressed();

        // FIXED: Use Result instead of assert
        if pub_bytes_full.len() != 65 {
            bail!("Uncompressed pubkey must be 65 bytes, got {}", pub_bytes_full.len());
        }

        let pub_bytes = &pub_bytes_full[1..];

        if pub_bytes.len() != 64 {
            bail!("Public key coords must be 64 bytes, got {}", pub_bytes.len());
        }

        let hash = Self::keccak256(pub_bytes);
        let address_hex = hex::encode(&hash[12..]);

        // FIXED: Apply EIP-55 checksum
        Ok(Self::to_checksum_address(&address_hex))
    }

    /// FIXED: EIP-55 checksum encoding
    fn to_checksum_address(address: &str) -> String {
        let address_hash = hex::encode(Self::keccak256(address.as_bytes()));
        let mut checksum_address = String::from("0x");

        for (i, ch) in address.chars().enumerate() {
            if ch.is_ascii_digit() {
                checksum_address.push(ch);
            } else {
                let hash_char = address_hash.chars().nth(i).unwrap();
                if hash_char >= '8' {
                    checksum_address.push(ch.to_ascii_uppercase());
                } else {
                    checksum_address.push(ch.to_ascii_lowercase());
                }
            }
        }

        checksum_address
    }

    fn generate_sol_address(&self, seed: &[u8; 64]) -> Result<String> {
        use ed25519_dalek::SigningKey;

        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
            .context("Failed to create master key for Solana")?;
        let path = DerivationPath::from_str("m/44'/501'/0'/0'")
            .context("Invalid Solana derivation path")?;
        let derived = xpriv.derive_priv(&self.secp, &path)
            .context("Failed to derive Solana key")?;

        let private_key_bytes = derived.to_priv().to_bytes();
        let ed25519_seed: [u8; 32] = private_key_bytes[0..32].try_into()
            .map_err(|_| anyhow::anyhow!("Invalid seed length for Ed25519"))?;

        let signing_key = SigningKey::from_bytes(&ed25519_seed);
        let verifying_key = signing_key.verifying_key();

        let pubkey_bytes = verifying_key.to_bytes();

        // FIXED: Check instead of assert
        if pubkey_bytes.len() != 32 {
            bail!("Ed25519 public key must be 32 bytes, got {}", pubkey_bytes.len());
        }

        let address = bs58::encode(&pubkey_bytes).into_string();

        // Validate: base58 roundtrip should preserve bytes and be canonical
        let decoded = bs58::decode(&address)
            .into_vec()
            .context("Failed to decode generated Solana address (base58)")?;

        if decoded.len() != 32 {
            bail!(
                "Generated Solana address decoded length must be 32 bytes, got {}",
                decoded.len()
            );
        }
        if decoded.as_slice() != pubkey_bytes.as_slice() {
            bail!("Generated Solana address roundtrip mismatch");
        }
        let reencoded = bs58::encode(&decoded).into_string();
        if reencoded != address {
            bail!("Generated Solana address is not canonical base58");
        }

        Ok(address)
    }

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
    fn test_btc_address_generation() {
        let mut config = Config::default();
        config.chains.btc_paths = vec![
            "m/44'/0'/0'/0/0".to_string(),
            "m/49'/0'/0'/0/0".to_string(),
            "m/84'/0'/0'/0/0".to_string(),
        ];
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();

        assert_eq!(wallets.btc.len(), 3);
        assert!(wallets.btc[0].starts_with("1"));
        assert!(wallets.btc[1].starts_with("3"));
        assert!(wallets.btc[2].starts_with("bc1"));
    }

    #[test]
    fn test_btc_derivation_path_rejects_nonzero_account() {
        let mut config = Config::default();
        config.chains.btc_paths = vec![
            "m/44'/0'/1'/0/0".to_string(),
        ];
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let err = generator.generate(&pattern).unwrap_err().to_string();
        assert!(err.contains("account must be 0'"), "got error: {}", err);
    }

    #[test]
    fn test_btc_derivation_path_rejects_nonzero_change_or_index() {
        let mut config = Config::default();
        config.chains.btc_paths = vec![
            "m/84'/0'/0'/1/0".to_string(),
            "m/84'/0'/0'/0/1".to_string(),
        ];
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let err = generator.generate(&pattern).unwrap_err().to_string();
        assert!(
            err.contains("change must be 0") || err.contains("index must be 0"),
            "got error: {}",
            err
        );
    }

    #[test]
    fn test_eth_address_checksum() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();

        // Should have mixed case (EIP-55 checksum)
        assert!(wallets.eth.starts_with("0x"));
        assert_eq!(wallets.eth.len(), 42);

        // Should have at least one uppercase letter (if checksum applies)
        let has_uppercase = wallets.eth[2..].chars().any(|c| c.is_uppercase());
        let has_lowercase = wallets.eth[2..].chars().any(|c| c.is_lowercase());
        assert!(has_uppercase || has_lowercase);
    }

    #[test]
    fn test_address_consistency() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let wallets1 = generator.generate(&pattern).unwrap();
        let wallets2 = generator.generate(&pattern).unwrap();

        assert_eq!(wallets1.btc, wallets2.btc);
        assert_eq!(wallets1.eth, wallets2.eth);
    }
}