// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Keyspace and Shannon entropy evaluation and rating engine.
//!
//! Categorizes generated secrets across five cryptographic resilience tiers,
//! interfaces with the audit module for pattern checks, and computes crack
//! time estimates across online and offline threat models.

use colored::Colorize;
use serde::{Deserialize, Serialize};

/// Categorical strength rating based on theoretical keyspace entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropyRating {
    /// Insufficient entropy (< 40 bits) vulnerable to automated dictionary sweeps.
    Weak,
    /// Moderate entropy (40..60 bits) suitable for transient or low-risk tokens.
    Fair,
    /// Strong entropy (60..80 bits) resilient against dedicated brute-force attempts.
    Strong,
    /// Very strong entropy (80..100 bits) resilient against high-throughput offline attacks.
    VeryStrong,
    /// Military-grade entropy (100+ bits) resistant against nation-state clusters.
    MilitaryGrade,
}

impl std::fmt::Display for EntropyRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Weak => write!(f, "WEAK"),
            Self::Fair => write!(f, "FAIR"),
            Self::Strong => write!(f, "STRONG"),
            Self::VeryStrong => write!(f, "VERY STRONG"),
            Self::MilitaryGrade => write!(f, "MILITARY GRADE"),
        }
    }
}

/// Detailed evaluation report for a generated secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseAssessment {
    /// Theoretical keyspace entropy in bits.
    pub keyspace_entropy_bits: f64,
    /// Shannon entropy in bits per byte.
    pub shannon_entropy_per_byte: f64,
    /// Effective entropy after pattern deduction.
    pub effective_entropy_bits: f64,
    /// Quantitative strength score (0..=4).
    pub score: u8,
    /// Categorical rating badge.
    pub rating: EntropyRating,
    /// Human-readable rating label.
    pub rating_label: String,
    /// Estimated time to crack via online rate-limited attack (100 guesses/sec).
    pub crack_time_online: String,
    /// Estimated time to crack via offline Argon2id attack (1,000 guesses/sec).
    pub crack_time_offline_argon2: String,
    /// Estimated time to crack via offline fast GPU cluster (10^10 guesses/sec).
    pub crack_time_offline_fast: String,
}

/// Classify entropy in bits into an `EntropyRating`.
pub fn rate_entropy(bits: f64) -> EntropyRating {
    if bits < 40.0 {
        EntropyRating::Weak
    } else if bits < 60.0 {
        EntropyRating::Fair
    } else if bits < 80.0 {
        EntropyRating::Strong
    } else if bits < 100.0 {
        EntropyRating::VeryStrong
    } else {
        EntropyRating::MilitaryGrade
    }
}

/// Format a colored terminal badge for the given rating.
pub fn format_rating_badge(rating: EntropyRating) -> colored::ColoredString {
    match rating {
        EntropyRating::Weak => "WEAK".red().bold(),
        EntropyRating::Fair => "FAIR".yellow().bold(),
        EntropyRating::Strong => "STRONG".green().bold(),
        EntropyRating::VeryStrong => "VERY STRONG".cyan().bold(),
        EntropyRating::MilitaryGrade => "MILITARY GRADE".magenta().bold(),
    }
}

/// Assess a generated passphrase using both theoretical keyspace entropy
/// and empirical character distribution analysis from `src/audit.rs`.
pub fn assess_passphrase(passphrase: &str, keyspace_entropy: f64) -> PassphraseAssessment {
    let audit_rep = crate::audit::audit_passphrase(passphrase);
    let rating = rate_entropy(keyspace_entropy);

    PassphraseAssessment {
        keyspace_entropy_bits: (keyspace_entropy * 10.0).round() / 10.0,
        shannon_entropy_per_byte: audit_rep.shannon_entropy_per_byte,
        effective_entropy_bits: audit_rep.effective_entropy_bits,
        score: audit_rep.score,
        rating,
        rating_label: rating.to_string(),
        crack_time_online: audit_rep.crack_time_online,
        crack_time_offline_argon2: audit_rep.crack_time_offline_argon2,
        crack_time_offline_fast: audit_rep.crack_time_offline_fast,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_entropy_thresholds() {
        assert_eq!(rate_entropy(30.0), EntropyRating::Weak);
        assert_eq!(rate_entropy(45.0), EntropyRating::Fair);
        assert_eq!(rate_entropy(66.0), EntropyRating::Strong);
        assert_eq!(rate_entropy(88.0), EntropyRating::VeryStrong);
        assert_eq!(rate_entropy(128.0), EntropyRating::MilitaryGrade);
    }

    #[test]
    fn test_assess_passphrase() {
        let assessment = assess_passphrase("correct-horse-battery-staple", 66.0);
        assert_eq!(assessment.rating, EntropyRating::Strong);
        assert!(assessment.shannon_entropy_per_byte > 3.0);
        assert!(!assessment.crack_time_online.is_empty());
    }
}
