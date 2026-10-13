// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Diceware recovery passphrase generator engine.
//!
//! Generates memorable, high-entropy cryptographic passphrases using the
//! 2,048-word BIP-39 English dictionary with optional capitalization,
//! numeric digits, and custom separators.

use crate::passgen::wordlist::{get_word, BITS_PER_WORD, WORDLIST_SIZE};
use rand::Rng;
use zeroize::Zeroize;

/// Configuration options for Diceware passphrase generation.
#[derive(Debug, Clone)]
pub struct DicewareOptions {
    /// Number of words to select (standard: 6 for ~66 bits of entropy).
    pub words: usize,
    /// Delimiter string between words (default: "-").
    pub separator: String,
    /// Whether to capitalize the first letter of each word (TitleCase).
    pub capitalize: bool,
    /// Whether to append a random numeric digit (0-9) to each word.
    pub number: bool,
}

impl Default for DicewareOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".to_string(),
            capitalize: false,
            number: false,
        }
    }
}

/// Generate a Diceware passphrase using the provided random number generator.
///
/// Returns `(passphrase, theoretical_keyspace_entropy_bits)`.
pub fn generate_diceware<R: Rng>(rng: &mut R, opts: &DicewareOptions) -> (String, f64) {
    let word_count = opts.words.max(1);
    let mut selected_words = Vec::with_capacity(word_count);

    let mut entropy_bits = word_count as f64 * BITS_PER_WORD;
    if opts.number {
        // Appending a random digit 0..=9 adds log2(10) ≈ 3.3219 bits per word
        entropy_bits += word_count as f64 * (10.0f64).log2();
    }

    for _ in 0..word_count {
        let idx = rng.gen_range(0..WORDLIST_SIZE);
        let base_word = get_word(idx).unwrap_or("abandon");

        let mut word = if opts.capitalize {
            let mut chars = base_word.chars();
            match chars.next() {
                Some(first) => {
                    let mut s = first.to_uppercase().collect::<String>();
                    s.push_str(chars.as_str());
                    s
                }
                None => String::new(),
            }
        } else {
            base_word.to_string()
        };

        if opts.number {
            let digit = rng.gen_range(0..10);
            word.push_str(&digit.to_string());
        }

        selected_words.push(word);
    }

    let result = selected_words.join(&opts.separator);

    // Clean up intermediate word buffers
    for mut w in selected_words {
        w.zeroize();
    }

    (result, entropy_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_diceware_default_generation() {
        let mut rng = StdRng::seed_from_u64(42);
        let opts = DicewareOptions::default();
        let (phrase, entropy) = generate_diceware(&mut rng, &opts);

        assert_eq!(phrase.split('-').count(), 6);
        assert!((entropy - 66.0).abs() < 1e-4);
    }

    #[test]
    fn test_diceware_custom_separator_and_capitalize() {
        let mut rng = StdRng::seed_from_u64(999);
        let opts = DicewareOptions {
            words: 4,
            separator: ".".to_string(),
            capitalize: true,
            number: false,
        };
        let (phrase, entropy) = generate_diceware(&mut rng, &opts);

        let parts: Vec<&str> = phrase.split('.').collect();
        assert_eq!(parts.len(), 4);
        for part in parts {
            let first_char = part.chars().next().unwrap();
            assert!(first_char.is_ascii_uppercase());
        }
        assert!((entropy - 44.0).abs() < 1e-4);
    }

    #[test]
    fn test_diceware_with_numbers() {
        let mut rng = StdRng::seed_from_u64(12345);
        let opts = DicewareOptions {
            words: 3,
            separator: "_".to_string(),
            capitalize: false,
            number: true,
        };
        let (phrase, entropy) = generate_diceware(&mut rng, &opts);

        let parts: Vec<&str> = phrase.split('_').collect();
        assert_eq!(parts.len(), 3);
        for part in parts {
            let last_char = part.chars().last().unwrap();
            assert!(last_char.is_ascii_digit());
        }
        // 3 * 11 + 3 * log2(10) ≈ 33 + 9.9658 = 42.9658
        assert!(entropy > 42.0 && entropy < 44.0);
    }
}
