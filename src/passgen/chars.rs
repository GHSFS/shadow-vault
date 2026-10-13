// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Cryptographic random character passphrase and numeric PIN generator.
//!
//! Enforces uniform rejection sampling across configurable character sets,
//! guarantees class diversity (lowercase, uppercase, digits, symbols),
//! supports ambiguous character exclusion, and calculates exact keyspace entropy.

use crate::error::{Error, Result};
use rand::Rng;
use zeroize::Zeroize;

const LOWER_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT_CHARS: &[u8] = b"0123456789";
const SYMBOL_CHARS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

const AMBIGUOUS_CHARS: &[u8] = b"0Oo1lI|8B";

/// Configuration options for random character passphrase generation.
#[derive(Debug, Clone)]
pub struct CharOptions {
    /// Desired passphrase character length (default: 20).
    pub length: usize,
    /// Whether to exclude special punctuation symbols.
    pub no_symbols: bool,
    /// Whether to exclude numeric digits (0-9).
    pub no_numbers: bool,
    /// Whether to exclude uppercase letters (A-Z).
    pub no_upper: bool,
    /// Whether to exclude lowercase letters (a-z).
    pub no_lower: bool,
    /// Whether to exclude visually ambiguous characters (0, O, o, 1, l, I, 8, B, |).
    pub exclude_ambiguous: bool,
}

impl Default for CharOptions {
    fn default() -> Self {
        Self {
            length: 20,
            no_symbols: false,
            no_numbers: false,
            no_upper: false,
            no_lower: false,
            exclude_ambiguous: false,
        }
    }
}

/// Filter a byte slice by removing ambiguous characters if requested.
fn filter_charset(raw: &[u8], exclude_ambiguous: bool) -> Vec<u8> {
    raw.iter()
        .copied()
        .filter(|&b| !exclude_ambiguous || !AMBIGUOUS_CHARS.contains(&b))
        .collect()
}

/// Generate a cryptographically secure random character passphrase.
///
/// Returns `(passphrase, theoretical_keyspace_entropy_bits)`.
pub fn generate_chars<R: Rng>(rng: &mut R, opts: &CharOptions) -> Result<(String, f64)> {
    let length = opts.length.max(4);

    let mut classes: Vec<Vec<u8>> = Vec::new();
    let mut combined: Vec<u8> = Vec::new();

    if !opts.no_lower {
        let pool = filter_charset(LOWER_CHARS, opts.exclude_ambiguous);
        if !pool.is_empty() {
            combined.extend_from_slice(&pool);
            classes.push(pool);
        }
    }

    if !opts.no_upper {
        let pool = filter_charset(UPPER_CHARS, opts.exclude_ambiguous);
        if !pool.is_empty() {
            combined.extend_from_slice(&pool);
            classes.push(pool);
        }
    }

    if !opts.no_numbers {
        let pool = filter_charset(DIGIT_CHARS, opts.exclude_ambiguous);
        if !pool.is_empty() {
            combined.extend_from_slice(&pool);
            classes.push(pool);
        }
    }

    if !opts.no_symbols {
        let pool = filter_charset(SYMBOL_CHARS, opts.exclude_ambiguous);
        if !pool.is_empty() {
            combined.extend_from_slice(&pool);
            classes.push(pool);
        }
    }

    if combined.is_empty() {
        return Err(Error::Format(
            "cannot generate passphrase: all character sets were excluded".to_string(),
        ));
    }

    let pool_size = combined.len();
    let entropy_bits = length as f64 * (pool_size as f64).log2();

    let mut selected: Vec<u8> = Vec::with_capacity(length);

    // Guarantee at least one character from each active character class
    for class in &classes {
        if selected.len() < length {
            let idx = rng.gen_range(0..class.len());
            selected.push(class[idx]);
        }
    }

    // Fill remaining slots uniformly from the combined character pool
    while selected.len() < length {
        let idx = rng.gen_range(0..pool_size);
        selected.push(combined[idx]);
    }

    // Fisher-Yates shuffle to eliminate position bias from guaranteed class picks
    for i in (1..selected.len()).rev() {
        let j = rng.gen_range(0..=i);
        selected.swap(i, j);
    }

    let passphrase = String::from_utf8(selected.clone())
        .map_err(|e| Error::Format(format!("invalid UTF-8 in generated passphrase: {e}")))?;

    // Zeroize intermediate byte vector
    selected.zeroize();

    Ok((passphrase, entropy_bits))
}

/// Generate a cryptographically secure numeric PIN of the specified length.
///
/// Returns `(pin_string, theoretical_keyspace_entropy_bits)`.
pub fn generate_pin<R: Rng>(rng: &mut R, length: usize) -> (String, f64) {
    let len = length.max(1);
    let mut digits = String::with_capacity(len);

    for _ in 0..len {
        let d = rng.gen_range(0..10);
        digits.push_str(&d.to_string());
    }

    let entropy_bits = len as f64 * (10.0f64).log2();
    (digits, entropy_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_generate_chars_default_entropy_and_diversity() {
        let mut rng = StdRng::seed_from_u64(1001);
        let opts = CharOptions::default();
        let (pass, entropy) = generate_chars(&mut rng, &opts).expect("generation failed");

        assert_eq!(pass.len(), 20);
        assert!(entropy > 120.0); // Pool ~89 chars => 20 * ~6.47 bits ≈ 129 bits

        // Check diversity
        assert!(pass.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pass.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pass.chars().any(|c| c.is_ascii_digit()));
        assert!(pass.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_chars_exclude_ambiguous() {
        let mut rng = StdRng::seed_from_u64(2002);
        let opts = CharOptions {
            length: 100,
            exclude_ambiguous: true,
            ..Default::default()
        };
        let (pass, _) = generate_chars(&mut rng, &opts).expect("generation failed");

        for ch in pass.chars() {
            assert!(
                !AMBIGUOUS_CHARS.contains(&(ch as u8)),
                "found ambiguous char: {ch}"
            );
        }
    }

    #[test]
    fn test_generate_chars_no_symbols_no_numbers() {
        let mut rng = StdRng::seed_from_u64(3003);
        let opts = CharOptions {
            length: 16,
            no_symbols: true,
            no_numbers: true,
            ..Default::default()
        };
        let (pass, entropy) = generate_chars(&mut rng, &opts).expect("generation failed");

        assert_eq!(pass.len(), 16);
        assert!(pass.chars().all(|c| c.is_ascii_alphabetic()));
        // Pool size = 52 => 16 * log2(52) ≈ 16 * 5.7004 ≈ 91.2 bits
        assert!(entropy > 90.0 && entropy < 93.0);
    }

    #[test]
    fn test_generate_pin() {
        let mut rng = StdRng::seed_from_u64(4004);
        let (pin, entropy) = generate_pin(&mut rng, 8);

        assert_eq!(pin.len(), 8);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
        // 8 * log2(10) ≈ 26.575 bits
        assert!((entropy - 26.5754).abs() < 1e-3);
    }
}
