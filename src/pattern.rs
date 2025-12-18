use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::config::Config;
use crate::dictionary::Dictionaries;

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub enum AttackPattern {
    KnownWeak { seed_hex: String },
    SingleWord { word: String },
    Bip39Repeat { word: String, count: usize },
    Bip39Sequential { start_index: usize, count: usize },
    PhrasePassphrase { phrase: String },
    PasswordNumber { password: String, number: u32 },
    NameDate { name: String, date: String },
}

impl AttackPattern {
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

pub struct PatternGenerator;

impl PatternGenerator {
    /// Generate all attack patterns (lazy iterator - memory efficient)
    pub fn generate_iter<'a>(
        dictionaries: &'a Dictionaries,
        config: &'a Config,
    ) -> impl Iterator<Item = AttackPattern> + 'a {
        let known_weak_iter = dictionaries.weak_seeds.iter().map(|seed| {
            AttackPattern::KnownWeak {
                seed_hex: seed.clone(),
            }
        });

        let single_word_iter = dictionaries.passwords
            .iter()
            .take(config.dictionaries.passwords_limit)
            .map(|word| AttackPattern::SingleWord {
                word: word.clone(),
            });

        let bip39_repeat_iter = dictionaries.bip39.iter().flat_map(|word| {
            std::iter::once(AttackPattern::Bip39Repeat {
                word: word.clone(),
                count: 12,
            }).chain(std::iter::once(AttackPattern::Bip39Repeat {
                word: word.clone(),
                count: 24,
            }))
        });

        let bip39_sequential_iter = std::iter::once(AttackPattern::Bip39Sequential {
            start_index: 0,
            count: 12,
        }).chain(std::iter::once(AttackPattern::Bip39Sequential {
            start_index: 0,
            count: 24,
        }));

        let phrase_iter = dictionaries.phrases
            .iter()
            .take(config.dictionaries.phrases_limit)
            .map(|phrase| AttackPattern::PhrasePassphrase {
                phrase: phrase.clone(),
            })
            .chain(dictionaries.crypto.iter().map(|term| {
                AttackPattern::PhrasePassphrase {
                    phrase: term.clone(),
                }
            }));

        // FIXED: Use Arc<Vec> instead of cloning Vec for each password
        let max_password_combinations = config.optimization.max_password_combinations;
        let important_numbers = std::sync::Arc::new(vec![
            0u32, 1, 12, 123, 1234, 2023, 2024, 2025, 69, 420, 666, 777, 999, 2020, 2021, 2022
        ]);

        let password_number_iter = dictionaries.passwords
            .iter()
            .take(max_password_combinations)
            .flat_map(move |password| {
                let password = password.clone();
                let numbers = important_numbers.clone(); // Arc clone (cheap)
                numbers.iter().map(move |&number| {
                    AttackPattern::PasswordNumber {
                        password: password.clone(),
                        number,
                    }
                }).collect::<Vec<_>>().into_iter()
            });

        let name_date_iter = dictionaries.names.iter().flat_map(|name| {
            dictionaries.dates.iter().map(move |date| {
                AttackPattern::NameDate {
                    name: name.clone(),
                    date: date.clone(),
                }
            })
        });

        let mutation_word_limit = config.optimization.max_mutation_words;
        let mutation_iter = dictionaries.passwords
            .iter()
            .take(mutation_word_limit)
            .flat_map(move |word| {
                Self::generate_mutations_iter(word, config.optimization.max_mutations_per_word)
            });

        let keyboard_patterns_iter = Self::generate_keyboard_patterns();

        known_weak_iter
            .chain(single_word_iter)
            .chain(mutation_iter)
            .chain(keyboard_patterns_iter)
            .chain(bip39_repeat_iter)
            .chain(bip39_sequential_iter)
            .chain(phrase_iter)
            .chain(password_number_iter)
            .chain(name_date_iter)
    }

    fn generate_mutations_iter(
        word: &String,
        max_mutations_per_word: usize,
    ) -> impl Iterator<Item = AttackPattern> {
        let mut mutations = Vec::new();
        let mut word_mutations = 0;

        if word_mutations < max_mutations_per_word {
            let mut leet = word.clone();
            leet = leet.replace('a', "4");
            leet = leet.replace('e', "3");
            leet = leet.replace('i', "1");
            leet = leet.replace('o', "0");
            leet = leet.replace('s', "5");
            mutations.push(AttackPattern::SingleWord { word: leet });
            word_mutations += 1;
        }

        if word_mutations < max_mutations_per_word {
            mutations.push(AttackPattern::SingleWord {
                word: word.to_uppercase(),
            });
            word_mutations += 1;
        }

        if word_mutations < max_mutations_per_word {
            mutations.push(AttackPattern::SingleWord {
                word: word.to_lowercase(),
            });
            word_mutations += 1;
        }

        let suffixes = ["123", "!", "2024", "2023", "@", "#"];
        for suffix in &suffixes {
            if word_mutations >= max_mutations_per_word {
                break;
            }
            mutations.push(AttackPattern::SingleWord {
                word: format!("{}{}", word, suffix),
            });
            word_mutations += 1;
        }

        let prefixes = ["my", "the", "crypto", "btc"];
        for prefix in &prefixes {
            if word_mutations >= max_mutations_per_word {
                break;
            }
            mutations.push(AttackPattern::SingleWord {
                word: format!("{}{}", prefix, word),
            });
            word_mutations += 1;
        }

        mutations.into_iter()
    }

    fn generate_keyboard_patterns() -> impl Iterator<Item = AttackPattern> {
        std::iter::once(AttackPattern::SingleWord { word: "qwerty123".to_string() })
            .chain(std::iter::once(AttackPattern::SingleWord { word: "asdfgh".to_string() }))
            .chain(std::iter::once(AttackPattern::SingleWord { word: "12345678".to_string() }))
            .chain(std::iter::once(AttackPattern::SingleWord { word: "qwertyuiop".to_string() }))
    }

    #[allow(dead_code)]
    pub fn generate(dictionaries: &Dictionaries, config: &Config) -> Result<Vec<AttackPattern>> {
        let mut patterns = Vec::new();

        for seed in &dictionaries.weak_seeds {
            patterns.push(AttackPattern::KnownWeak {
                seed_hex: seed.clone(),
            });
        }

        for word in dictionaries.passwords.iter().take(config.dictionaries.passwords_limit) {
            patterns.push(AttackPattern::SingleWord {
                word: word.clone(),
            });
        }

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

        patterns.push(AttackPattern::Bip39Sequential {
            start_index: 0,
            count: 12,
        });
        patterns.push(AttackPattern::Bip39Sequential {
            start_index: 0,
            count: 24,
        });

        for phrase in dictionaries.phrases.iter().take(config.dictionaries.phrases_limit) {
            patterns.push(AttackPattern::PhrasePassphrase {
                phrase: phrase.clone(),
            });
        }

        for term in &dictionaries.crypto {
            patterns.push(AttackPattern::PhrasePassphrase {
                phrase: term.clone(),
            });
        }

        let max_password_combinations = config.optimization.max_password_combinations;
        let important_numbers = [0, 1, 12, 123, 1234, 2023, 2024, 2025, 69, 420, 666, 777, 999, 2020, 2021, 2022];
        for password in dictionaries.passwords.iter().take(max_password_combinations) {
            for &number in &important_numbers {
                patterns.push(AttackPattern::PasswordNumber {
                    password: password.clone(),
                    number,
                });
            }
        }

        for name in &dictionaries.names {
            for date in &dictionaries.dates {
                patterns.push(AttackPattern::NameDate {
                    name: name.clone(),
                    date: date.clone(),
                });
            }
        }

        let mutation_word_limit = config.optimization.max_mutation_words;
        let mutation_words: Vec<String> = dictionaries.passwords.iter()
            .take(mutation_word_limit)
            .cloned()
            .collect();
        patterns.extend(Self::generate_mutations(&mutation_words, config.optimization.max_mutations_per_word));

        Ok(patterns)
    }

    #[allow(dead_code)]
    fn generate_mutations(base_words: &[String], max_mutations_per_word: usize) -> Vec<AttackPattern> {
        let mut mutations = Vec::new();

        let estimated_capacity = (base_words.len() * max_mutations_per_word) + 4;
        mutations.reserve(estimated_capacity);

        for word in base_words {
            let mut word_mutations = 0;

            if word_mutations < max_mutations_per_word {
                let mut leet = word.clone();
                leet = leet.replace('a', "4");
                leet = leet.replace('e', "3");
                leet = leet.replace('i', "1");
                leet = leet.replace('o', "0");
                leet = leet.replace('s', "5");
                mutations.push(AttackPattern::SingleWord { word: leet });
                word_mutations += 1;
            }

            if word_mutations < max_mutations_per_word {
                mutations.push(AttackPattern::SingleWord {
                    word: word.to_uppercase()
                });
                word_mutations += 1;
            }

            if word_mutations < max_mutations_per_word {
                mutations.push(AttackPattern::SingleWord {
                    word: word.to_lowercase()
                });
                word_mutations += 1;
            }

            let suffixes = ["123", "!", "2024", "2023", "@", "#"];
            for suffix in &suffixes {
                if word_mutations >= max_mutations_per_word {
                    break;
                }
                mutations.push(AttackPattern::SingleWord {
                    word: format!("{}{}", word, suffix),
                });
                word_mutations += 1;
            }

            let prefixes = ["my", "the", "crypto", "btc"];
            for prefix in &prefixes {
                if word_mutations >= max_mutations_per_word {
                    break;
                }
                mutations.push(AttackPattern::SingleWord {
                    word: format!("{}{}", prefix, word),
                });
                word_mutations += 1;
            }
        }

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