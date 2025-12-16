use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::config::Config;
use crate::dictionary::Dictionaries;

/// Attack pattern types with priority
#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub enum AttackPattern {
    /// Known weak seeds (CRITICAL priority)
    KnownWeak {
        seed_hex: String,
    },

    /// Single word mnemonic (HIGH priority)
    SingleWord {
        word: String,
    },

    /// Repeated BIP39 word (HIGH priority)
    Bip39Repeat {
        word: String,
        count: usize,
    },

    /// Sequential BIP39 words (HIGH priority)
    Bip39Sequential {
        start_index: usize,
        count: usize,
    },

    /// Common phrase as passphrase (MEDIUM priority)
    PhrasePassphrase {
        phrase: String,
    },

    /// Password + number combination (MEDIUM priority)
    PasswordNumber {
        password: String,
        number: u32,
    },

    /// Name + date combination (LOW priority)
    NameDate {
        name: String,
        date: String,
    },
}

impl AttackPattern {
    /// Get priority value (higher = more important)
    pub fn priority(&self) -> u8 {
        match self {
            AttackPattern::KnownWeak { .. } => 10,
            AttackPattern::SingleWord { .. } => 9,
            AttackPattern::Bip39Repeat { .. } => 8,
            AttackPattern::Bip39Sequential { .. } => 7,
            AttackPattern::PhrasePassphrase { .. } => 5,
            AttackPattern::PasswordNumber { .. } => 3,
            AttackPattern::NameDate { .. } => 1,
        }
    }

    /// Get pattern type as string
    pub fn pattern_type(&self) -> &str {
        match self {
            AttackPattern::KnownWeak { .. } => "known_weak",
            AttackPattern::SingleWord { .. } => "single_word",
            AttackPattern::Bip39Repeat { .. } => "bip39_repeat",
            AttackPattern::Bip39Sequential { .. } => "bip39_sequential",
            AttackPattern::PhrasePassphrase { .. } => "phrase_passphrase",
            AttackPattern::PasswordNumber { .. } => "password_number",
            AttackPattern::NameDate { .. } => "name_date",
        }
    }

    /// Convert pattern to mnemonic string
    pub fn to_mnemonic(&self, dictionaries: &Dictionaries) -> Result<String> {
        match self {
            AttackPattern::KnownWeak { seed_hex } => Ok(seed_hex.clone()),

            AttackPattern::SingleWord { word } => Ok(word.clone()),

            AttackPattern::Bip39Repeat { word, count } => {
                let words: Vec<String> = std::iter::repeat(word.clone())
                    .take(*count)
                    .collect();
                Ok(words.join(" "))
            }

            AttackPattern::Bip39Sequential { start_index, count } => {
                let words: Vec<String> = dictionaries.bip39
                    .iter()
                    .skip(*start_index)
                    .take(*count)
                    .cloned()
                    .collect();
                Ok(words.join(" "))
            }

            AttackPattern::PhrasePassphrase { phrase } => Ok(phrase.clone()),

            AttackPattern::PasswordNumber { password, number } => {
                Ok(format!("{}{}", password, number))
            }

            AttackPattern::NameDate { name, date } => {
                Ok(format!("{}{}", name, date))
            }
        }
    }

}

impl fmt::Display for AttackPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttackPattern::KnownWeak { seed_hex } => {
                write!(f, "KnownWeak({}...)", &seed_hex[..8.min(seed_hex.len())])
            }
            AttackPattern::SingleWord { word } => {
                write!(f, "SingleWord({})", word)
            }
            AttackPattern::Bip39Repeat { word, count } => {
                write!(f, "Bip39Repeat({} x{})", word, count)
            }
            AttackPattern::Bip39Sequential { start_index, count } => {
                write!(f, "Bip39Sequential([{}..{}])", start_index, start_index + count)
            }
            AttackPattern::PhrasePassphrase { phrase } => {
                write!(f, "PhrasePassphrase({})", phrase)
            }
            AttackPattern::PasswordNumber { password, number } => {
                write!(f, "PasswordNumber({} + {})", password, number)
            }
            AttackPattern::NameDate { name, date } => {
                write!(f, "NameDate({} + {})", name, date)
            }
        }
    }
}

/// Pattern generator - creates attack patterns from dictionaries
pub struct PatternGenerator;

impl PatternGenerator {
    /// Generate all attack patterns from dictionaries
    pub fn generate(dictionaries: &Dictionaries, config: &Config) -> Result<Vec<AttackPattern>> {
        let mut patterns = Vec::new();

        // 1. Known weak seeds (CRITICAL)
        for seed in &dictionaries.weak_seeds {
            patterns.push(AttackPattern::KnownWeak {
                seed_hex: seed.clone(),
            });
        }

        // 2. Top passwords as single words (HIGH)
        for word in dictionaries.passwords.iter().take(config.dictionaries.passwords_limit) {
            patterns.push(AttackPattern::SingleWord {
                word: word.clone(),
            });
        }

        // 3. BIP39 word repetitions (HIGH)
        for word in &dictionaries.bip39 {
            patterns.push(AttackPattern::Bip39Repeat {
                word: word.clone(),
                count: 12,
            });
            patterns.push(AttackPattern::Bip39Repeat {
                word: word.clone(),
                count: 24,
            });
        }

        // 4. Sequential BIP39 combinations (HIGH)
        patterns.push(AttackPattern::Bip39Sequential {
            start_index: 0,
            count: 12,
        });
        patterns.push(AttackPattern::Bip39Sequential {
            start_index: 0,
            count: 24,
        });

        // 5. Common phrases as passphrases (MEDIUM)
        for phrase in dictionaries.phrases.iter().take(config.dictionaries.phrases_limit) {
            patterns.push(AttackPattern::PhrasePassphrase {
                phrase: phrase.clone(),
            });
        }

        // 6. Password + number combinations (MEDIUM)
        // Only top 1000 passwords with numbers 0-9999
        for password in dictionaries.passwords.iter().take(1000) {
            for number in 0..10000 {
                patterns.push(AttackPattern::PasswordNumber {
                    password: password.clone(),
                    number,
                });
            }
        }

        // 7. Name + date combinations (LOW)
        for name in &dictionaries.names {
            for date in &dictionaries.dates {
                patterns.push(AttackPattern::NameDate {
                    name: name.clone(),
                    date: date.clone(),
                });
            }
        }

        // Add pattern mutations (leetspeak, case variations, etc.)
        patterns.extend(Self::generate_mutations(&dictionaries.passwords.iter().take(100).cloned().collect::<Vec<_>>()));

        Ok(patterns)
    }

    /// Generate pattern mutations (leetspeak, case variations)
    fn generate_mutations(base_words: &[String]) -> Vec<AttackPattern> {
        let mut mutations = Vec::new();

        for word in base_words {
            // Leetspeak mutations
            let mut leet = word.clone();
            leet = leet.replace('a', "4");
            leet = leet.replace('e', "3");
            leet = leet.replace('i', "1");
            leet = leet.replace('o', "0");
            leet = leet.replace('s', "5");
            mutations.push(AttackPattern::SingleWord { word: leet });

            // Case variations
            mutations.push(AttackPattern::SingleWord {
                word: word.to_uppercase()
            });
            mutations.push(AttackPattern::SingleWord {
                word: word.to_lowercase()
            });

            // Common suffixes
            for suffix in &["123", "!", "2024", "2023", "@", "#"] {
                mutations.push(AttackPattern::SingleWord {
                    word: format!("{}{}", word, suffix),
                });
            }

            // Common prefixes
            for prefix in &["my", "the", "crypto", "btc"] {
                mutations.push(AttackPattern::SingleWord {
                    word: format!("{}{}", prefix, word),
                });
            }
        }

        // Keyboard patterns
        for pattern in &["qwerty123", "asdfgh", "12345678", "qwertyuiop"] {
            mutations.push(AttackPattern::SingleWord {
                word: pattern.to_string(),
            });
        }

        mutations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_priority() {
        let known_weak = AttackPattern::KnownWeak {
            seed_hex: "abcd".to_string(),
        };
        let single_word = AttackPattern::SingleWord {
            word: "password".to_string(),
        };

        assert!(known_weak.priority() > single_word.priority());
    }

    #[test]
    fn test_pattern_to_mnemonic() {
        let pattern = AttackPattern::Bip39Repeat {
            word: "abandon".to_string(),
            count: 3,
        };

        let dicts = Dictionaries::default();
        let mnemonic = pattern.to_mnemonic(&dicts).unwrap();
        assert_eq!(mnemonic, "abandon abandon abandon");
    }
}