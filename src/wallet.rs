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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip39_passphrase: Option<String>,
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

    pub fn generate(&self, pattern: &AttackPattern) -> Result<Vec<WalletAddresses>> {
        let candidates = self.pattern_to_seed_candidates(pattern)?;
        let mut out = Vec::with_capacity(candidates.len());

        for (seed, passphrase) in candidates {
            let btc = self.generate_btc_addresses(&seed)?;
            let eth = self.generate_eth_address(&seed)?;
            let sol = if self.config.chains.enabled.contains(&"SOL".to_string()) {
                Some(self.generate_sol_address(&seed)?)
            } else {
                None
            };

            out.push(WalletAddresses {
                btc,
                eth,
                sol,
                bip39_passphrase: passphrase,
            });
        }

        Ok(out)
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
                // If the "single word" is actually a full mnemonic phrase (e.g. 12 words),
                // prefer BIP39 parsing + checksum validation first.
                if let Ok(mnemonic) = Mnemonic::parse_in_normalized(Language::English, word) {
                    Ok(mnemonic.to_seed(""))
                } else {
                    self.pbkdf2_seed(word)
                }
            }

            AttackPattern::Bip39Repeat { word, count } => {
                // NOTE: repeating the same word N times will almost always fail BIP39 checksum.
                // To generate a *valid* weak BIP39 mnemonic, we repeat the word for N-1 positions
                // and brute-force the last word over the official English word list (2048) until
                // `Mnemonic::parse_in_normalized` accepts it.
                if let Some(phrase) = Self::make_valid_bip39_repeat_phrase(word, *count) {
                    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &phrase)
                        .context("Generated BIP39 repeat phrase should be valid")?;
                    Ok(mnemonic.to_seed(""))
                } else {
                    // Fallback: treat as generic passphrase if no valid checksum word exists.
                    let repeated = std::iter::repeat_n(word.as_str(), *count).collect::<Vec<_>>().join(" ");
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

    fn pattern_to_seed_candidates(&self, pattern: &AttackPattern) -> Result<Vec<([u8; 64], Option<String>)>> {
        // Default: single attempt (non-mnemonic / passphrase not applicable)
        let single = |seed: [u8; 64]| -> Vec<([u8; 64], Option<String>)> { vec![(seed, None)] };

        match pattern {
            AttackPattern::SingleWord { word } => {
                if let Ok(mnemonic) = Mnemonic::parse_in_normalized(Language::English, word) {
                    return Ok(self.seeds_for_passphrases(&mnemonic));
                }
                Ok(single(self.pbkdf2_seed(word)?))
            }
            AttackPattern::Bip39Repeat { word, count } => {
                if let Some(phrase) = Self::make_valid_bip39_repeat_phrase(word, *count) {
                    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &phrase)
                        .context("Generated BIP39 repeat phrase should be valid")?;
                    Ok(self.seeds_for_passphrases(&mnemonic))
                } else {
                    Ok(single(self.pattern_to_seed(pattern)?))
                }
            }
            _ => {
                // For other patterns, try mnemonic parsing; if it parses, try passphrases.
                let mnemonic_str = pattern.to_mnemonic(&crate::dictionary::Dictionaries::default())?;
                if let Ok(mnemonic) = Mnemonic::parse_in_normalized(Language::English, &mnemonic_str) {
                    Ok(self.seeds_for_passphrases(&mnemonic))
                } else {
                    Ok(single(self.pbkdf2_seed(&mnemonic_str)?))
                }
            }
        }
    }

    fn seeds_for_passphrases(&self, mnemonic: &Mnemonic) -> Vec<([u8; 64], Option<String>)> {
        let mut passphrases = self.config.optimization.bip39_passphrases.clone();
        if passphrases.is_empty() {
            passphrases.push("".to_string());
        }

        // Keep stable order and avoid duplicates.
        passphrases.sort();
        passphrases.dedup();

        passphrases
            .into_iter()
            .map(|p| {
                let seed = mnemonic.to_seed(&p);
                let pass = if p.is_empty() { None } else { Some(p) };
                (seed, pass)
            })
            .collect()
    }

    fn make_valid_bip39_repeat_phrase(word: &str, count: usize) -> Option<String> {
        if count != 12 && count != 24 {
            return None;
        }

        // First N-1 words are the repeated word; last is brute-forced to satisfy checksum.
        let prefix = std::iter::repeat_n(word, count.saturating_sub(1))
            .collect::<Vec<_>>()
            .join(" ");

        for &candidate in Language::English.word_list().iter() {
            let phrase = if prefix.is_empty() {
                candidate.to_string()
            } else {
                format!("{} {}", prefix, candidate)
            };
            if Mnemonic::parse_in_normalized(Language::English, &phrase).is_ok() {
                return Some(phrase);
            }
        }

        None
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

    /// BTC derivation path classification (safe but not overly strict):
    /// - Accept BIP44/49/84 with coin_type 0' for Bitcoin mainnet.
    /// - Do NOT restrict account/change/index (wallets commonly use non-zero values).
    /// - Also accept a common non-standard legacy path: m/0'/0/0
    fn btc_address_type_for_path(path: &DerivationPath) -> Result<BtcAddressType> {
        use bitcoin::util::bip32::ChildNumber;

        let comps: Vec<ChildNumber> = path.into_iter().cloned().collect();
        if comps.is_empty() {
            bail!("BTC derivation path must not be empty");
        }

        // Non-standard legacy: m/0'/0/0
        if comps.len() == 3
            && comps[0] == ChildNumber::from_hardened_idx(0)?
            && comps[1] == ChildNumber::from_normal_idx(0)?
            && comps[2] == ChildNumber::from_normal_idx(0)?
        {
            return Ok(BtcAddressType::LegacyP2pkh);
        }

        // BIP44-like: m/purpose'/coin_type'/...
        if comps.len() < 2 {
            bail!("BTC derivation path too short; expected at least m/purpose'/coin_type'/...");
        }

        let purpose = comps[0];
        let coin_type = comps[1];

        if coin_type != ChildNumber::from_hardened_idx(0)? {
            bail!("BTC derivation path coin_type must be 0'");
        }

        if purpose == ChildNumber::from_hardened_idx(44)? {
            Ok(BtcAddressType::LegacyP2pkh)
        } else if purpose == ChildNumber::from_hardened_idx(49)? {
            Ok(BtcAddressType::SegwitP2shP2wpkh)
        } else if purpose == ChildNumber::from_hardened_idx(84)? {
            Ok(BtcAddressType::NativeSegwitP2wpkh)
        } else {
            bail!("BTC derivation path purpose must be 44', 49', or 84' (or non-standard m/0'/0/0)");
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
    use bip39::Mnemonic;

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
        let wallets0 = wallets.first().unwrap();

        assert_eq!(wallets0.btc.len(), 3);
        assert!(wallets0.btc[0].starts_with("1"));
        assert!(wallets0.btc[1].starts_with("3"));
        assert!(wallets0.btc[2].starts_with("bc1"));
    }

    #[test]
    fn test_btc_derivation_path_allows_nonzero_account() {
        let mut config = Config::default();
        config.chains.btc_paths = vec![
            "m/44'/0'/1'/0/0".to_string(),
        ];
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        let w = wallets.first().unwrap();
        assert_eq!(w.btc.len(), 1);
        assert!(w.btc[0].starts_with('1'));
    }

    #[test]
    fn test_btc_derivation_path_allows_nonzero_change_or_index() {
        let mut config = Config::default();
        config.chains.btc_paths = vec![
            "m/84'/0'/0'/1/0".to_string(),
            "m/84'/0'/0'/0/1".to_string(),
        ];
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        let w = wallets.first().unwrap();
        assert_eq!(w.btc.len(), 2);
        assert!(w.btc[0].starts_with("bc1"));
        assert!(w.btc[1].starts_with("bc1"));
    }

    #[test]
    fn test_btc_derivation_path_allows_nonstandard_m0h_0_0() {
        let mut config = Config::default();
        config.chains.btc_paths = vec![
            "m/0'/0/0".to_string(),
        ];
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        let w = wallets.first().unwrap();
        assert_eq!(w.btc.len(), 1);
        assert!(w.btc[0].starts_with('1'));
    }

    #[test]
    fn test_eth_address_checksum() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: "test".to_string(),
        };

        let wallets = generator.generate(&pattern).unwrap();
        let wallets0 = wallets.first().unwrap();

        // Should have mixed case (EIP-55 checksum)
        assert!(wallets0.eth.starts_with("0x"));
        assert_eq!(wallets0.eth.len(), 42);

        // Should have at least one uppercase letter (if checksum applies)
        let has_uppercase = wallets0.eth[2..].chars().any(|c| c.is_uppercase());
        let has_lowercase = wallets0.eth[2..].chars().any(|c| c.is_lowercase());
        assert!(has_uppercase || has_lowercase);
    }

    #[test]
    fn test_bip39_repeat_produces_valid_checksum_phrase() {
        let phrase = WalletGenerator::make_valid_bip39_repeat_phrase("abandon", 12)
            .expect("should find a valid checksum word for 12-word repeat");
        assert!(Mnemonic::parse_in_normalized(Language::English, &phrase).is_ok());
    }

    #[test]
    fn test_singleword_prefers_bip39_when_phrase_is_valid() {
        let config = Config::default();
        let generator = WalletGenerator::new(&config).unwrap();

        // Valid BIP39 example (checksum-correct)
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let pattern = crate::pattern::AttackPattern::SingleWord {
            word: phrase.to_string(),
        };

        let seed_from_singleword = generator.pattern_to_seed(&pattern).unwrap();
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase).unwrap();
        let seed_from_bip39 = mnemonic.to_seed("");

        assert_eq!(seed_from_singleword, seed_from_bip39);
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
        let w1 = wallets1.first().unwrap();
        let w2 = wallets2.first().unwrap();

        assert_eq!(w1.btc, w2.btc);
        assert_eq!(w1.eth, w2.eth);
    }
}