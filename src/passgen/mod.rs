// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Deterministic & CSPRNG Passphrase Generator (`svault keygen` / `passgen`).
//!
//! Provides:
//! - Diceware passphrase generator from BIP-39 2,048-word dictionary (`--words 6`).
//! - Character passphrases with configurable symbols, numbers, and ambiguous filtering (`--length 20`).
//! - Raw CSPRNG random bytes in Hex, Base64, or Base32 (`--bytes 32`).
//! - Numeric PIN generator (`--pin 6`).
//! - Reproducible deterministic generation via master seed + context (`--seed`).
//! - Theoretical keyspace and empirical Shannon entropy evaluation (`--entropy`).
//! - Integration with auto-expiring clipboard guard (`--clip`).
//! - Structured machine-readable JSON output (`--json`).

pub mod bytes;
pub mod chars;
pub mod entropy;
pub mod wordlist;
pub mod words;

pub use bytes::{generate_random_bytes, ByteEncoding};
pub use chars::{generate_chars, generate_pin, CharOptions};
#[allow(unused_imports)]
pub use entropy::{
    assess_passphrase, format_rating_badge, rate_entropy, EntropyRating, PassphraseAssessment,
};
#[allow(unused_imports)]
pub use wordlist::BIP39_WORDLIST;
pub use words::{generate_diceware, DicewareOptions};

use crate::error::Result;
use colored::Colorize;
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Generator mode and parameter container.
#[derive(Debug, Clone)]
pub enum PassgenMode {
    Diceware(DicewareOptions),
    Characters(CharOptions),
    Bytes(usize, ByteEncoding),
    Pin(usize),
}

/// A generated secret entry with metadata and security assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedItem {
    /// 1-indexed candidate counter.
    pub index: usize,
    /// Mode classification ("diceware", "characters", "bytes", "pin").
    pub mode: String,
    /// Plaintext generated secret or passphrase.
    pub secret: String,
    /// Cryptographic resilience and entropy assessment.
    #[serde(flatten)]
    pub assessment: PassphraseAssessment,
}

/// Deterministically derive a 32-byte seed for `StdRng` from a master seed and optional context.
fn derive_seed_rng(seed: &str, context: Option<&str>) -> StdRng {
    let mut hasher = Sha256::new();
    hasher.update(b"SVLT_PASSGEN_SEED_V1:");
    hasher.update(seed.as_bytes());
    if let Some(ctx) = context {
        hasher.update(b":CTX:");
        hasher.update(ctx.as_bytes());
    }
    let hash = hasher.finalize();
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&hash);
    let rng = StdRng::from_seed(seed_bytes);
    seed_bytes.zeroize();
    rng
}

/// Generate a batch of candidate passphrases or keys.
pub fn generate_batch(
    mode: &PassgenMode,
    count: usize,
    seed: Option<&str>,
    context: Option<&str>,
) -> Result<Vec<GeneratedItem>> {
    let batch_size = count.max(1);
    let mut items = Vec::with_capacity(batch_size);

    let mut deterministic_rng = seed.map(|s| derive_seed_rng(s, context));

    for idx in 1..=batch_size {
        let (secret, entropy_bits, mode_name) = match mode {
            PassgenMode::Diceware(opts) => {
                let (p, e) = if let Some(ref mut rng) = deterministic_rng {
                    generate_diceware(rng, opts)
                } else {
                    generate_diceware(&mut OsRng, opts)
                };
                (p, e, "diceware".to_string())
            }
            PassgenMode::Characters(opts) => {
                let (p, e) = if let Some(ref mut rng) = deterministic_rng {
                    generate_chars(rng, opts)?
                } else {
                    generate_chars(&mut OsRng, opts)?
                };
                (p, e, "characters".to_string())
            }
            PassgenMode::Bytes(bytes_count, encoding) => {
                let (p, e) = if let Some(ref mut rng) = deterministic_rng {
                    generate_random_bytes(rng, *bytes_count, *encoding)
                } else {
                    generate_random_bytes(&mut OsRng, *bytes_count, *encoding)
                };
                (p, e, "bytes".to_string())
            }
            PassgenMode::Pin(len) => {
                let (p, e) = if let Some(ref mut rng) = deterministic_rng {
                    generate_pin(rng, *len)
                } else {
                    generate_pin(&mut OsRng, *len)
                };
                (p, e, "pin".to_string())
            }
        };

        let assessment = assess_passphrase(&secret, entropy_bits);
        items.push(GeneratedItem {
            index: idx,
            mode: mode_name,
            secret,
            assessment,
        });
    }

    Ok(items)
}

/// Format and output the generated batch for CLI operator consumption.
#[allow(clippy::too_many_arguments)]
pub fn print_batch_cli(
    items: &[GeneratedItem],
    json: bool,
    show_entropy: bool,
    clip: bool,
    clip_ttl: u64,
) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(items)?);
    } else if items.len() == 1 {
        let item = &items[0];
        if show_entropy {
            println!(
                "{} {}",
                "Generated Secret:".bold(),
                item.secret.cyan().bold()
            );
            println!(
                "  Strength Rating:       {} [{}]",
                format_rating_badge(item.assessment.rating),
                item.assessment.rating_label
            );
            println!(
                "  Keyspace Entropy:      {:.1} bits",
                item.assessment.keyspace_entropy_bits
            );
            println!(
                "  Shannon Entropy:       {:.2} bits/byte",
                item.assessment.shannon_entropy_per_byte
            );
            println!(
                "  Effective Entropy:     {:.1} bits (Score: {}/4)",
                item.assessment.effective_entropy_bits, item.assessment.score
            );
            println!(
                "  Crack Time (Online):   {}",
                item.assessment.crack_time_online
            );
            println!(
                "  Crack Time (Argon2id): {}",
                item.assessment.crack_time_offline_argon2
            );
            println!(
                "  Crack Time (Fast GPU): {}",
                item.assessment.crack_time_offline_fast
            );
        } else {
            println!("{}", item.secret);
        }
    } else {
        println!(
            "{}",
            format!("=== [GENERATED SECRETS ({})] ===", items.len()).bold()
        );
        for item in items {
            let badge = format_rating_badge(item.assessment.rating);
            println!(
                "  {:>2}. {:<40} [{}] ({:.1} bits)",
                item.index, item.secret, badge, item.assessment.keyspace_entropy_bits
            );
        }
    }

    if clip && !items.is_empty() {
        let first_secret = &items[0].secret;
        let _ = crate::clipboard_guard::guard_interactive(
            first_secret,
            clip_ttl,
            Some("generated secret"),
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_seed_reproducibility() {
        let mode = PassgenMode::Diceware(DicewareOptions {
            words: 6,
            separator: "-".to_string(),
            capitalize: false,
            number: false,
        });

        let run1 = generate_batch(&mode, 3, Some("master-seed-xyz"), Some("service-a")).unwrap();
        let run2 = generate_batch(&mode, 3, Some("master-seed-xyz"), Some("service-a")).unwrap();
        let run3 = generate_batch(&mode, 3, Some("master-seed-xyz"), Some("service-b")).unwrap();

        for i in 0..3 {
            assert_eq!(run1[i].secret, run2[i].secret);
        }
        // Different context should produce different passphrases
        assert_ne!(run1[0].secret, run3[0].secret);
    }

    #[test]
    fn test_batch_generation_counts() {
        let mode = PassgenMode::Characters(CharOptions {
            length: 12,
            ..Default::default()
        });
        let batch = generate_batch(&mode, 5, None, None).unwrap();
        assert_eq!(batch.len(), 5);
        for (i, item) in batch.iter().enumerate() {
            assert_eq!(item.index, i + 1);
            assert_eq!(item.secret.len(), 12);
        }
    }
}
