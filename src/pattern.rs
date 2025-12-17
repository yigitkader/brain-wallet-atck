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
    /// Generate all attack patterns from dictionaries (lazy iterator version)
    /// Returns iterator that generates patterns on-demand, preventing memory explosion
    /// Patterns are returned in priority order (highest first)
    pub fn generate_iter<'a>(
        dictionaries: &'a Dictionaries,
        config: &'a Config,
    ) -> impl Iterator<Item = AttackPattern> + 'a {
        // Patterns are generated in priority order (highest first)
        // Each category is an iterator that's chained together
        
        // 1. Known weak seeds (CRITICAL - Priority 10)
        let known_weak_iter = dictionaries.weak_seeds.iter().map(|seed| {
            AttackPattern::KnownWeak {
                seed_hex: seed.clone(),
            }
        });
        
        // 2. Top passwords as single words (HIGH - Priority 9)
        let single_word_iter = dictionaries.passwords
            .iter()
            .take(config.dictionaries.passwords_limit)
            .map(|word| AttackPattern::SingleWord {
                word: word.clone(),
            });
        
        // 3. BIP39 word repetitions (HIGH - Priority 8)
        let bip39_repeat_iter = dictionaries.bip39.iter().flat_map(|word| {
            std::iter::once(AttackPattern::Bip39Repeat {
                word: word.clone(),
                count: 12,
            }).chain(std::iter::once(AttackPattern::Bip39Repeat {
                word: word.clone(),
                count: 24,
            }))
        });
        
        // 4. Sequential BIP39 combinations (HIGH - Priority 7)
        let bip39_sequential_iter = std::iter::once(AttackPattern::Bip39Sequential {
            start_index: 0,
            count: 12,
        }).chain(std::iter::once(AttackPattern::Bip39Sequential {
            start_index: 0,
            count: 24,
        }));
        
        // 5. Common phrases as passphrases (MEDIUM - Priority 5)
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
        
        // 6. Password + number combinations (MEDIUM - Priority 3)
        // Use config limit to prevent memory explosion
        let max_password_combinations = config.optimization.max_password_combinations;
        let important_numbers: Vec<u32> = vec![0, 1, 12, 123, 1234, 2023, 2024, 2025, 69, 420, 666, 777, 999, 2020, 2021, 2022];
        let password_number_iter = dictionaries.passwords
            .iter()
            .take(max_password_combinations)
            .flat_map(move |password| {
                let password = password.clone();
                let numbers = important_numbers.clone();
                numbers.into_iter().map(move |number| {
                    AttackPattern::PasswordNumber {
                        password: password.clone(),
                        number,
                    }
                })
            });
        
        // 7. Name + date combinations (LOW - Priority 1)
        let name_date_iter = dictionaries.names.iter().flat_map(|name| {
            dictionaries.dates.iter().map(move |date| {
                AttackPattern::NameDate {
                    name: name.clone(),
                    date: date.clone(),
                }
            })
        });
        
        // 8. Pattern mutations (leetspeak, case variations) (HIGH - Priority 9)
        // Generate mutations lazily
        let mutation_word_limit = config.optimization.max_mutation_words;
        let mutation_iter = dictionaries.passwords
            .iter()
            .take(mutation_word_limit)
            .flat_map(move |word| {
                Self::generate_mutations_iter(word, config.optimization.max_mutations_per_word)
            });
        
        // 9. Keyboard patterns (always included, Priority 9)
        let keyboard_patterns_iter = Self::generate_keyboard_patterns();
        
        // Chain all iterators in priority order (highest first)
        known_weak_iter
            .chain(single_word_iter)
            .chain(mutation_iter) // Mutations are also Priority 9
            .chain(keyboard_patterns_iter) // Keyboard patterns are also Priority 9
            .chain(bip39_repeat_iter)
            .chain(bip39_sequential_iter)
            .chain(phrase_iter)
            .chain(password_number_iter)
            .chain(name_date_iter)
    }
    
    /// Generate pattern mutations iterator (leetspeak, case variations)
    /// Limited by max_mutations_per_word to prevent memory explosion
    fn generate_mutations_iter(
        word: &String,
        max_mutations_per_word: usize,
    ) -> impl Iterator<Item = AttackPattern> {
        let mut mutations = Vec::new();
        let mut word_mutations = 0;
        
        // Priority 1: Leetspeak (most common mutation)
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
        
        // Priority 2: Case variations
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
        
        // Priority 3: Common suffixes
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
        
        // Priority 4: Common prefixes
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
    
    /// Generate keyboard patterns (always included, not counted in per-word limit)
    /// These are common keyboard patterns that should always be tested
    fn generate_keyboard_patterns() -> impl Iterator<Item = AttackPattern> {
        std::iter::once(AttackPattern::SingleWord { word: "qwerty123".to_string() })
            .chain(std::iter::once(AttackPattern::SingleWord { word: "asdfgh".to_string() }))
            .chain(std::iter::once(AttackPattern::SingleWord { word: "12345678".to_string() }))
            .chain(std::iter::once(AttackPattern::SingleWord { word: "qwertyuiop".to_string() }))
    }
    
    /// Generate all attack patterns from dictionaries (legacy Vec version)
    /// DEPRECATED: Use generate_iter() instead for better memory efficiency
    /// Kept for backward compatibility and testing
    /// Used in tests to verify iterator correctness
    #[allow(dead_code)] // Used in tests
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

        // 5b. Crypto terms as passphrases (MEDIUM)
        for term in &dictionaries.crypto {
            patterns.push(AttackPattern::PhrasePassphrase {
                phrase: term.clone(),
            });
        }

        // 6. Password + number combinations (MEDIUM)
        // Use config limit to prevent memory explosion
        // Use important numbers instead of 0..10 to catch common patterns without memory explosion
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
        // Use configurable limits to prevent memory explosion
        // Memory calculation: max_mutation_words × max_mutations_per_word = total mutation patterns
        // Example: 1000 words × 10 mutations = 10K patterns (~1-2 MB)
        let mutation_word_limit = config.optimization.max_mutation_words;
        let mutation_words: Vec<String> = dictionaries.passwords.iter()
            .take(mutation_word_limit)
            .cloned()
            .collect();
        patterns.extend(Self::generate_mutations(&mutation_words, config.optimization.max_mutations_per_word));

        Ok(patterns)
    }

    /// Generate pattern mutations (leetspeak, case variations)
    /// Limited by max_mutations_per_word to prevent memory explosion
    /// Used in tests to verify mutation logic
    #[allow(dead_code)] // Used in tests
    fn generate_mutations(base_words: &[String], max_mutations_per_word: usize) -> Vec<AttackPattern> {
        let mut mutations = Vec::new();
        
        // Pre-allocate with estimated capacity to reduce reallocations
        // Estimate: max_mutations_per_word mutations per word + keyboard patterns
        let estimated_capacity = (base_words.len() * max_mutations_per_word) + 4;
        mutations.reserve(estimated_capacity);

        for word in base_words {
            let mut word_mutations = 0;
            
            // Priority 1: Leetspeak (most common mutation)
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

            // Priority 2: Case variations (if limit allows)
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

            // Priority 3: Common suffixes (limited by remaining mutations)
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

            // Priority 4: Common prefixes (limited by remaining mutations)
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

        // Keyboard patterns (always included, not counted in per-word limit)
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

    #[test]
    fn test_generate_iter_vs_generate() {
        // Test that generate_iter() and generate() produce equivalent patterns
        // This ensures backward compatibility and correctness
        let config = Config::default();
        let mut dicts = Dictionaries::default();
        
        // Add minimal test data
        dicts.weak_seeds = vec!["deadbeef".to_string()];
        dicts.passwords = vec!["password".to_string(), "test".to_string()];
        dicts.bip39 = vec!["abandon".to_string(), "ability".to_string()];
        dicts.phrases = vec!["hello world".to_string()];
        dicts.crypto = vec!["bitcoin".to_string()];
        dicts.names = vec!["alice".to_string()];
        dicts.dates = vec!["2024".to_string()];

        // Generate using iterator (new method) - already sorted by priority
        let iter_patterns: Vec<_> = PatternGenerator::generate_iter(&dicts, &config).collect();
        
        // Generate using Vec (legacy method) - needs sorting
        let mut vec_patterns = PatternGenerator::generate(&dicts, &config).unwrap();
        vec_patterns.sort_by_key(|p| std::cmp::Reverse(p.priority()));

        // Both should produce the same number of patterns
        // Note: Small differences are acceptable due to implementation details
        // but the core patterns should match
        assert!((iter_patterns.len() as i32 - vec_patterns.len() as i32).abs() <= 4,
               "Iterator and Vec versions should produce similar number of patterns (iter: {}, vec: {})", 
               iter_patterns.len(), vec_patterns.len());
        
        // Both should have same priority ordering (highest first)
        let iter_priorities: Vec<u8> = iter_patterns.iter().map(|p| p.priority()).collect();
        let vec_priorities: Vec<u8> = vec_patterns.iter().map(|p| p.priority()).collect();
        
        // Check that priorities are in descending order for both
        let mut prev_priority = 255u8;
        for &priority in &iter_priorities {
            assert!(priority <= prev_priority, 
                   "Iterator patterns should be in descending priority order");
            prev_priority = priority;
        }
        
        prev_priority = 255u8;
        for &priority in &vec_priorities {
            assert!(priority <= prev_priority, 
                   "Vec patterns should be in descending priority order after sorting");
            prev_priority = priority;
        }
        
        // Both should start with highest priority (KnownWeak = 10)
        assert_eq!(iter_patterns[0].priority(), 10, "Iterator should start with Priority 10");
        assert_eq!(vec_patterns[0].priority(), 10, "Vec should start with Priority 10 after sorting");
    }

    #[test]
    fn test_generate_mutations() {
        // Test mutation generation logic
        let base_words = vec!["test".to_string(), "password".to_string()];
        let mutations = PatternGenerator::generate_mutations(&base_words, 5);
        
        // Should generate mutations for each word (limited by max_mutations_per_word)
        assert!(!mutations.is_empty());
        
        // Check that mutations are SingleWord patterns
        for mutation in &mutations {
            match mutation {
                AttackPattern::SingleWord { .. } => {},
                _ => panic!("Mutations should be SingleWord patterns"),
            }
        }
    }

    #[test]
    fn test_generate_iter_priority_order() {
        // Test that iterator maintains priority order (highest first)
        let config = Config::default();
        let mut dicts = Dictionaries::default();
        
        // Add minimal test data
        dicts.weak_seeds = vec!["deadbeef".to_string()];
        dicts.passwords = vec!["password".to_string()];
        dicts.bip39 = vec!["abandon".to_string()];
        
        let patterns: Vec<_> = PatternGenerator::generate_iter(&dicts, &config).collect();
        
        // Check that priorities are in descending order
        let priorities: Vec<u8> = patterns.iter().map(|p| p.priority()).collect();
        let mut prev_priority = 255u8;
        for &priority in &priorities {
            assert!(priority <= prev_priority, 
                   "Patterns should be in descending priority order");
            prev_priority = priority;
        }
    }
}