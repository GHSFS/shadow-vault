// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Passphrase Strength & Steganography Carrier Entropy Auditor (`svault audit`).
//!
//! Provides:
//! - Shannon entropy calculation ($H = -\sum p_i \log_2 p_i$ bits/byte).
//! - Chi-square ($\chi^2$) goodness-of-fit uniformity analysis.
//! - Passphrase strength scoring (0..=4), pool size, effective entropy estimation.
//! - Detection of repetitions, ascending/descending sequences, keyboard walks,
//!   and common weak patterns (including leetspeak deobfuscation).
//! - Multi-threat crack time estimations (online rate-limited, offline Argon2id, offline fast GPU).
//! - Steganography carrier anomaly audit:
//!   - PNG chunk validation, `svLt` chunk verification, and post-IEND trailing data checks.
//!   - WAV RIFF subchunk validation and 16-bit PCM LSB stream anomaly checks.
//!   - `SVLT` container header and ciphertext Shannon entropy verification.
//! - Proactive memory zeroization (`Zeroize` / `Zeroizing`) on sensitive passphrase buffers.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const PNG_SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const IEND_TYPE: &[u8; 4] = b"IEND";
const SVLT_PNG_CHUNK: &[u8; 4] = b"svLt";
const RIFF_MAGIC: &[u8; 4] = b"RIFF";
const WAVE_MAGIC: &[u8; 4] = b"WAVE";
const SVLT_WAV_CHUNK: &[u8; 4] = b"svLt";
const SVLT_CONTAINER_MAGIC: &[u8; 4] = b"SVLT";

fn audit_embedded_container(
    context: &str,
    slice: &[u8],
    anomalies: &mut Vec<String>,
    findings: &mut Vec<String>,
) -> Option<(u8, bool, bool, String)> {
    if !slice.starts_with(SVLT_CONTAINER_MAGIC) {
        return None;
    }
    if slice.len() < crate::crypto::HEADER_LEN + 16 {
        anomalies.push(format!(
            "Embedded container in {context} is truncated ({len} bytes, minimum container size is 50 bytes with Poly1305 MAC tag)",
            len = slice.len()
        ));
        return None;
    }
    let version = slice[4];
    let flags = slice[5];
    let dpapi = (flags & crate::crypto::FLAG_DPAPI) != 0;
    let decoy = (flags & crate::crypto::FLAG_DECOY) != 0;
    let salt = &slice[6..22];
    let salt_hex = salt.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let salt_entropy = shannon_entropy(salt);

    if version != crate::crypto::VERSION && version != crate::crypto::VERSION_V2 {
        anomalies.push(format!(
            "Embedded container in {context} has unsupported version v{version} (supported versions: v1, v2)"
        ));
    }
    if (flags & !0x03) != 0 {
        anomalies.push(format!(
            "Embedded container in {context} has unknown flag bits: {flags:#04x}"
        ));
    }
    if salt_entropy < 2.5 {
        anomalies.push(format!(
            "Embedded container in {context} has low salt entropy ({salt_entropy:.2} bits/byte); KDF salt may lack CSPRNG randomness"
        ));
    }

    findings.push(format!("Embedded container version: v{version}"));
    findings.push(format!("Embedded container DPAPI hardware bound: {dpapi}"));
    if decoy {
        findings.push("Embedded container has plausible deniability decoy".into());
        if let Err(e) = crate::decoy::inspect_decoy(slice) {
            anomalies.push(format!(
                "Embedded decoy container in {context} layout anomaly: {e}"
            ));
        }
    }

    let ciphertext = &slice[crate::crypto::HEADER_LEN..];
    let cipher_entropy = shannon_entropy(ciphertext);
    findings.push(format!(
        "Embedded container in {context} ciphertext Shannon entropy: {cipher_entropy:.4} bits/byte"
    ));
    if !ciphertext.is_empty() {
        let max_theoretical = (ciphertext.len() as f64).log2().min(8.0);
        if ciphertext.len() >= 256 && cipher_entropy < 7.2 {
            anomalies.push(format!(
                "Embedded container in {context} ciphertext Shannon entropy is unusually low ({cipher_entropy:.2} bits/byte; expected > 7.2 for payloads >= 256 bytes)"
            ));
        } else if ciphertext.len() >= 32 && cipher_entropy < (max_theoretical * 0.70) {
            anomalies.push(format!(
                "Embedded container in {context} ciphertext Shannon entropy is unusually low ({cipher_entropy:.2} bits/byte; theoretical max: {max_theoretical:.2})"
            ));
        }
    }

    Some((version, dpapi, decoy, salt_hex))
}

/// Quantitative rating of passphrase strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrengthLevel {
    VeryWeak = 0,
    Weak = 1,
    Moderate = 2,
    Strong = 3,
    VeryStrong = 4,
}

impl std::fmt::Display for StrengthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VeryWeak => write!(f, "VERY WEAK"),
            Self::Weak => write!(f, "WEAK"),
            Self::Moderate => write!(f, "MODERATE"),
            Self::Strong => write!(f, "STRONG"),
            Self::VeryStrong => write!(f, "VERY STRONG"),
        }
    }
}

/// Detailed passphrase strength, entropy, and vulnerability assessment report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseAuditReport {
    /// Total character count (Unicode scalars).
    pub length_chars: usize,
    /// Total byte length in UTF-8.
    pub length_bytes: usize,
    /// Detected character set pool size ($R$).
    pub pool_size: usize,
    /// Shannon entropy in bits per byte ($0.0 \le H \le 8.0$).
    pub shannon_entropy_per_byte: f64,
    /// Total Shannon entropy in bits ($H \times \text{bytes}$).
    pub total_shannon_entropy_bits: f64,
    /// Theoretical pool entropy in bits ($L \log_2 R$).
    pub pool_entropy_bits: f64,
    /// Effective entropy after deducting pattern and dictionary penalties.
    pub effective_entropy_bits: f64,
    /// Quantitative strength score ($0..=4$).
    pub score: u8,
    /// Categorical strength level.
    pub strength: StrengthLevel,
    /// Estimated time to crack via online rate-limited attack (100 guesses/sec).
    pub crack_time_online: String,
    /// Estimated time to crack via offline Argon2id attack ($10^3$ guesses/sec).
    pub crack_time_offline_argon2: String,
    /// Estimated time to crack via offline GPU fast-hash cluster ($10^{10}$ guesses/sec).
    pub crack_time_offline_fast: String,
    /// Specific vulnerability warnings and detected weakness patterns.
    pub findings: Vec<String>,
    /// Concrete recommendations to improve passphrase resilience.
    pub suggestions: Vec<String>,
    /// Whether repeated character patterns were detected.
    pub has_repeats: bool,
    /// Whether sequential runs (e.g. `1234`, `abcd`) were detected.
    pub has_sequential: bool,
    /// Whether keyboard walk patterns (e.g. `qwerty`, `asdfgh`) were detected.
    pub has_keyboard_walk: bool,
    /// Whether common dictionary passwords or leetspeak variants were detected.
    pub has_common_pattern: bool,
}

/// Carrier media classification for steganographic analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierType {
    PngImage,
    WavAudio,
    SvaultContainer,
    TextFile,
    BinaryData,
}

impl std::fmt::Display for CarrierType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PngImage => write!(f, "PNG Image Carrier"),
            Self::WavAudio => write!(f, "WAV Audio Carrier"),
            Self::SvaultContainer => write!(f, "ShadowVault Encrypted Container"),
            Self::TextFile => write!(f, "Plaintext / Key File"),
            Self::BinaryData => write!(f, "Raw Binary Data"),
        }
    }
}

/// Steganalysis anomaly detection verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierVerdict {
    CleanCarrier,
    StegoCarrierDetected,
    SuspiciousAnomaly,
    EncryptedContainer,
    PlaintextFile,
    BinaryData,
}

impl std::fmt::Display for CarrierVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CleanCarrier => write!(f, "CLEAN CARRIER (No Hidden Data Detected)"),
            Self::StegoCarrierDetected => {
                write!(f, "STEGO CARRIER DETECTED (Hidden ShadowVault Payload)")
            }
            Self::SuspiciousAnomaly => write!(f, "SUSPICIOUS ANOMALY (Carrier Integrity Flagged)"),
            Self::EncryptedContainer => {
                write!(f, "ENCRYPTED CONTAINER (High-Entropy Authenticated Vault)")
            }
            Self::PlaintextFile => write!(f, "PLAINTEXT / TEXT DATA"),
            Self::BinaryData => write!(f, "RAW BINARY DATA"),
        }
    }
}

/// Detailed metadata extracted during carrier steganalysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrierDetails {
    pub container_version: Option<u8>,
    pub dpapi_bound: Option<bool>,
    pub decoy_container: Option<bool>,
    pub payload_bytes: Option<usize>,
    pub stego_chunk_present: bool,
    pub stego_lsb_present: bool,
    pub trailing_bytes: usize,
    pub total_chunks_or_subchunks: usize,
    pub salt_hex: Option<String>,
}

/// Comprehensive audit report for a carrier file or container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAuditReport {
    pub file_path: String,
    pub file_size: usize,
    pub carrier_type: CarrierType,
    pub shannon_entropy: f64,
    pub chi_square: f64,
    pub verdict: CarrierVerdict,
    pub details: CarrierDetails,
    pub anomalies: Vec<String>,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Combined audit report containing optional passphrase and carrier evaluations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedAuditReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<PassphraseAuditReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier: Option<FileAuditReport>,
}

/// Calculate the Shannon entropy in bits per byte ($0.0 \le H \le 8.0$) for arbitrary bytes.
///
/// Formula: $H(X) = -\sum_{i=0}^{255} p(b_i) \log_2 p(b_i)$ where $p(b_i) = \frac{\text{count}(b_i)}{N}$.
#[inline]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Calculate the Chi-Square ($\chi^2$) goodness-of-fit statistic against an ideal uniform distribution.
///
/// Degrees of freedom: $df = 255$. Ideal uniform cryptographic randomness yields $\chi^2 \approx 255$.
#[inline]
pub fn chi_square(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let expected = n / 256.0;
    let mut chi_sq = 0.0f64;
    for &c in &counts {
        let diff = c as f64 - expected;
        chi_sq += (diff * diff) / expected;
    }
    chi_sq
}

/// Evaluate passphrase strength, Shannon entropy, pool diversity, and vulnerability patterns.
///
/// Wipes intermediate buffers using `zeroize` upon completion.
pub fn audit_passphrase(passphrase: &str) -> PassphraseAuditReport {
    let length_chars = passphrase.chars().count();
    let length_bytes = passphrase.len();

    if length_chars == 0 {
        return PassphraseAuditReport {
            length_chars: 0,
            length_bytes: 0,
            pool_size: 0,
            shannon_entropy_per_byte: 0.0,
            total_shannon_entropy_bits: 0.0,
            pool_entropy_bits: 0.0,
            effective_entropy_bits: 0.0,
            score: 0,
            strength: StrengthLevel::VeryWeak,
            crack_time_online: "instant".into(),
            crack_time_offline_argon2: "instant".into(),
            crack_time_offline_fast: "instant".into(),
            findings: vec!["Passphrase is completely empty".into()],
            suggestions: vec![
                "Choose a passphrase with at least 14-16 characters or 5+ Diceware words".into(),
            ],
            has_repeats: false,
            has_sequential: false,
            has_keyboard_walk: false,
            has_common_pattern: false,
        };
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut has_whitespace = false;
    let mut has_unicode = false;
    let mut has_control = false;

    for ch in passphrase.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if ch.is_ascii_whitespace() {
            has_whitespace = true;
        } else if ch.is_ascii_punctuation() {
            has_symbol = true;
        } else if ch.is_ascii_control() {
            has_control = true;
        } else {
            has_unicode = true;
        }
    }

    let mut pool_size = 0usize;
    if has_lower {
        pool_size += 26;
    }
    if has_upper {
        pool_size += 26;
    }
    if has_digit {
        pool_size += 10;
    }
    if has_symbol {
        pool_size += 33;
    }
    if has_whitespace {
        pool_size += 1;
    }
    if has_unicode {
        pool_size += 128;
    }
    if has_control {
        pool_size += 10;
    }
    if pool_size == 0 {
        pool_size = 1;
    }

    let shannon_per_byte = shannon_entropy(passphrase.as_bytes());
    let total_shannon = shannon_per_byte * (length_bytes as f64);
    let pool_entropy = (length_chars as f64) * (pool_size as f64).log2();

    let mut findings = Vec::new();
    let mut suggestions = Vec::new();

    if has_control {
        findings.push("Contains non-printable ASCII control characters".into());
    }

    // 1. Repetition checks
    let (has_repeats, repeat_penalty) = check_repetitions(passphrase);
    if has_repeats {
        findings.push("Contains repetitive character sequences".into());
    }

    // 2. Sequential checks
    let (has_sequential, seq_penalty) = check_sequential(passphrase);
    if has_sequential {
        findings.push("Contains sequential ascending or descending character runs".into());
    }

    // 3. Keyboard walk checks
    let (has_keyboard_walk, kw_penalty) = check_keyboard_walks(passphrase);
    if has_keyboard_walk {
        findings.push("Contains common keyboard walk patterns (e.g. QWERTY layout)".into());
    }

    // 4. Common weak pattern & leetspeak checks
    let (has_common_pattern, pattern_penalty, matched_word) = check_common_patterns(passphrase);
    if has_common_pattern {
        if let Some(word) = matched_word {
            findings.push(format!(
                "Matches common weak dictionary pattern '{word}' (or leetspeak variant)"
            ));
        } else {
            findings.push("Matches common weak dictionary pattern".into());
        }
    }

    // Length findings
    if length_chars < 8 {
        findings.push(format!(
            "Critical: length is only {length_chars} characters (< 8 chars)"
        ));
    } else if length_chars < 12 {
        findings.push(format!(
            "Warning: length is only {length_chars} characters (< 12 chars)"
        ));
    }

    // Diversity findings & suggestions
    let mut diversity_count = 0;
    if has_lower {
        diversity_count += 1;
    }
    if has_upper {
        diversity_count += 1;
    }
    if has_digit {
        diversity_count += 1;
    }
    if has_symbol {
        diversity_count += 1;
    }
    if diversity_count < 3 {
        suggestions.push("Mix character types: uppercase, lowercase, digits, and symbols".into());
    }
    if length_chars < 16 {
        suggestions.push("Increase length to at least 16 characters for quantum-era margin".into());
    }
    if has_repeats || has_sequential || has_keyboard_walk {
        suggestions.push("Eliminate predictable sequences, repetitions, and keyboard walks".into());
    }
    if has_common_pattern {
        suggestions.push("Avoid dictionary words, slang, names, and obvious leetspeak substitutions (e.g. @ for a)".into());
    }

    // Compute effective entropy
    let total_penalty = repeat_penalty + seq_penalty + kw_penalty + pattern_penalty;
    let length_penalty = if length_chars < 12 {
        (12 - length_chars) as f64 * 3.5
    } else {
        0.0
    };

    let raw_effective = pool_entropy - total_penalty - length_penalty;
    let effective_entropy = raw_effective.max(0.0).min(pool_entropy);

    // Scoring: 0..=4
    let (score, strength) = if length_chars < 6
        || (has_common_pattern && length_chars < 12)
        || effective_entropy < 24.0
    {
        (0, StrengthLevel::VeryWeak)
    } else if length_chars < 10 || effective_entropy < 40.0 {
        (1, StrengthLevel::Weak)
    } else if length_chars < 14 || effective_entropy < 62.0 {
        (2, StrengthLevel::Moderate)
    } else if effective_entropy < 84.0 {
        (3, StrengthLevel::Strong)
    } else {
        (4, StrengthLevel::VeryStrong)
    };

    let crack_time_online = estimate_crack_time(effective_entropy, 100.0);
    let crack_time_offline_argon2 = estimate_crack_time(effective_entropy, 1_000.0);
    let crack_time_offline_fast = estimate_crack_time(effective_entropy, 10_000_000_000.0);

    PassphraseAuditReport {
        length_chars,
        length_bytes,
        pool_size,
        shannon_entropy_per_byte: shannon_per_byte,
        total_shannon_entropy_bits: total_shannon,
        pool_entropy_bits: pool_entropy,
        effective_entropy_bits: effective_entropy,
        score,
        strength,
        crack_time_online,
        crack_time_offline_argon2,
        crack_time_offline_fast,
        findings,
        suggestions,
        has_repeats,
        has_sequential,
        has_keyboard_walk,
        has_common_pattern,
    }
}

/// Audit a file path for steganographic anomalies, entropy metrics, or container validity.
pub fn audit_file(path: &Path) -> Result<FileAuditReport> {
    let data = std::fs::read(path).map_err(Error::Io)?;
    let filename = path.display().to_string();
    audit_carrier_bytes(&filename, &data)
}

/// Audit in-memory carrier bytes for steganographic anomalies, entropy metrics, or container validity.
pub fn audit_carrier_bytes(name: &str, data: &[u8]) -> Result<FileAuditReport> {
    let shannon = shannon_entropy(data);
    let chi_sq = chi_square(data);

    if data.starts_with(PNG_SIG) {
        audit_png_carrier(name, data, shannon, chi_sq)
    } else if data.len() >= 12 && &data[0..4] == RIFF_MAGIC && &data[8..12] == WAVE_MAGIC {
        audit_wav_carrier(name, data, shannon, chi_sq)
    } else if data.starts_with(SVLT_CONTAINER_MAGIC) {
        audit_svault_container(name, data, shannon, chi_sq)
    } else if is_likely_text(data) {
        audit_plaintext_file(name, data, shannon, chi_sq)
    } else {
        audit_binary_data(name, data, shannon, chi_sq)
    }
}

// ---------------------------------------------------------------------------
// Internal carrier inspection routines
// ---------------------------------------------------------------------------

fn audit_png_carrier(
    name: &str,
    data: &[u8],
    shannon: f64,
    chi_sq: f64,
) -> Result<FileAuditReport> {
    let mut anomalies = Vec::new();
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    let mut offset = 8;
    let mut chunk_count = 0usize;
    let mut ihdr_seen = false;
    let mut stego_chunk_present = false;
    let mut stego_payload_size = None;
    let mut iend_seen = false;
    let mut trailing_bytes = 0usize;
    let mut container_version = None;
    let mut dpapi_bound = None;
    let mut decoy_container = None;
    let mut salt_hex = None;

    while offset + 12 <= data.len() {
        let chunk_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;

        let chunk_type = &data[offset + 4..offset + 8];

        if chunk_len > 0x7fff_ffff {
            anomalies.push(format!(
                "PNG chunk '{}' declared length {chunk_len} exceeds specification maximum (2^31 - 1 bytes)",
                String::from_utf8_lossy(chunk_type)
            ));
        }

        let data_start = offset + 8;
        let data_end = data_start.saturating_add(chunk_len);

        if data_end.checked_add(4).map_or(true, |end| end > data.len()) {
            anomalies.push("Truncated PNG chunk header or payload encountered".into());
            break;
        }

        let chunk_data = &data[data_start..data_end];
        let expected_crc = u32::from_be_bytes([
            data[data_end],
            data[data_end + 1],
            data[data_end + 2],
            data[data_end + 3],
        ]);

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(chunk_type);
        hasher.update(chunk_data);
        let actual_crc = hasher.finalize();

        if actual_crc != expected_crc {
            anomalies.push(format!(
                "PNG chunk '{}' has invalid CRC-32 checksum (expected {expected_crc:#010x}, got {actual_crc:#010x})",
                String::from_utf8_lossy(chunk_type)
            ));
        }

        if chunk_count == 0 {
            if chunk_type != b"IHDR" {
                anomalies.push("First PNG chunk must be 'IHDR'".into());
            } else {
                ihdr_seen = true;
                if chunk_len != 13 {
                    anomalies.push(format!(
                        "PNG 'IHDR' chunk has invalid length {chunk_len} (must be exactly 13 bytes)"
                    ));
                }
            }
        } else if chunk_type == b"IHDR" {
            anomalies.push("Multiple 'IHDR' chunks detected in PNG carrier".into());
        }

        if chunk_type == b"acTL" {
            findings.push("Detected Animated Portable Network Graphics (APNG) carrier".into());
            if chunk_len != 8 {
                anomalies.push(format!(
                    "APNG 'acTL' chunk has invalid length {chunk_len} (must be 8 bytes)"
                ));
            }
        }

        chunk_count += 1;

        if chunk_type == SVLT_PNG_CHUNK {
            if stego_chunk_present {
                anomalies.push("Multiple private 'svLt' chunks detected in PNG carrier".into());
            }
            stego_chunk_present = true;
            stego_payload_size = Some(chunk_len);
            findings.push(format!(
                "Detected private steganography chunk 'svLt' with {chunk_len} bytes hidden payload"
            ));

            if let Some((v, dp, dec, s_hex)) = audit_embedded_container(
                "PNG 'svLt' chunk",
                chunk_data,
                &mut anomalies,
                &mut findings,
            ) {
                container_version = Some(v);
                dpapi_bound = Some(dp);
                decoy_container = Some(dec);
                salt_hex = Some(s_hex);
            }
        }

        offset = data_end + 4;

        if chunk_type == IEND_TYPE {
            iend_seen = true;
            if chunk_len != 0 {
                anomalies.push(format!(
                    "PNG 'IEND' chunk has non-zero payload length ({chunk_len} bytes; specification requires 0 bytes)"
                ));
            }
            if offset < data.len() {
                trailing_bytes = data.len() - offset;
                anomalies.push(format!(
                    "Found {trailing_bytes} trailing bytes after terminal IEND chunk (potential EOF append anomaly)"
                ));
            }
            break;
        }
    }

    if !ihdr_seen {
        anomalies.push("PNG carrier is missing required 'IHDR' chunk".into());
    }

    if !iend_seen {
        anomalies.push("PNG carrier is missing standard terminal IEND chunk".into());
        if offset < data.len() {
            let leftover = data.len() - offset;
            trailing_bytes = leftover;
            anomalies.push(format!(
                "Found {leftover} unparsed trailing bytes before IEND"
            ));
        }
    }

    let verdict = if !anomalies.is_empty() {
        CarrierVerdict::SuspiciousAnomaly
    } else if stego_chunk_present {
        CarrierVerdict::StegoCarrierDetected
    } else {
        CarrierVerdict::CleanCarrier
    };

    if stego_chunk_present {
        recommendations.push(
            "Carrier contains an active ShadowVault container; extract with 'svault extract'"
                .into(),
        );
    } else if verdict == CarrierVerdict::CleanCarrier {
        findings.push(format!(
            "Valid PNG image with {chunk_count} chunks. No steganographic signatures detected."
        ));
    }

    Ok(FileAuditReport {
        file_path: name.to_string(),
        file_size: data.len(),
        carrier_type: CarrierType::PngImage,
        shannon_entropy: shannon,
        chi_square: chi_sq,
        verdict,
        details: CarrierDetails {
            container_version,
            dpapi_bound,
            decoy_container,
            payload_bytes: stego_payload_size,
            stego_chunk_present,
            stego_lsb_present: false,
            trailing_bytes,
            total_chunks_or_subchunks: chunk_count,
            salt_hex,
        },
        anomalies,
        findings,
        recommendations,
    })
}

fn audit_wav_carrier(
    name: &str,
    data: &[u8],
    shannon: f64,
    chi_sq: f64,
) -> Result<FileAuditReport> {
    let mut anomalies = Vec::new();
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    let mut subchunk_count = 0usize;
    let mut fmt_seen = false;
    let mut data_seen = false;
    let mut fmt_info: Option<(u16, u16, u32, u16)> = None;
    let mut stego_chunk_present = false;
    let mut stego_lsb_present = false;
    let mut payload_bytes = None;
    let mut data_chunk_slice: Option<&[u8]> = None;
    let mut container_version = None;
    let mut dpapi_bound = None;
    let mut decoy_container = None;
    let mut salt_hex = None;
    let mut trailing_bytes = 0usize;

    if data.len() < 12 {
        anomalies.push("Truncated WAV carrier (less than 12-byte RIFF header)".into());
        return Ok(FileAuditReport {
            file_path: name.to_string(),
            file_size: data.len(),
            carrier_type: CarrierType::WavAudio,
            shannon_entropy: shannon,
            chi_square: chi_sq,
            verdict: CarrierVerdict::SuspiciousAnomaly,
            details: CarrierDetails {
                container_version: None,
                dpapi_bound: None,
                decoy_container: None,
                payload_bytes: None,
                stego_chunk_present: false,
                stego_lsb_present: false,
                trailing_bytes: 0,
                total_chunks_or_subchunks: 0,
                salt_hex: None,
            },
            anomalies,
            findings,
            recommendations,
        });
    }

    let declared_riff_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if declared_riff_size < 4 {
        anomalies.push(format!(
            "WAV RIFF declared size ({declared_riff_size} bytes) is invalid (< 4 bytes for 'WAVE' identifier)"
        ));
    }
    let expected_riff_len = declared_riff_size.saturating_add(8);
    if data.len() > expected_riff_len {
        let diff = data.len() - expected_riff_len;
        trailing_bytes = diff;
        anomalies.push(format!(
            "Found {diff} trailing bytes beyond declared RIFF length (potential EOF append anomaly)"
        ));
    } else if data.len() < expected_riff_len {
        let missing = expected_riff_len - data.len();
        anomalies.push(format!(
            "WAV carrier is truncated ({len} bytes, declared RIFF length expects {expected_riff_len} bytes; missing {missing} bytes)",
            len = data.len()
        ));
    }

    let mut offset = 12;
    while offset + 8 <= data.len() {
        let chunk_id = &data[offset..offset + 4];
        let chunk_size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;

        let content_start = offset + 8;
        let content_end = content_start.saturating_add(chunk_size);
        if content_end > data.len() {
            anomalies.push(format!(
                "Truncated WAV subchunk '{}' declared size {chunk_size} exceeds file length",
                String::from_utf8_lossy(chunk_id)
            ));
            break;
        }

        subchunk_count += 1;

        if chunk_id == b"fmt " {
            if fmt_seen {
                anomalies.push("Multiple 'fmt ' chunks detected in WAV carrier".into());
            }
            fmt_seen = true;
            if chunk_size < 16 {
                anomalies.push("WAV 'fmt ' chunk is truncated (< 16 bytes)".into());
            } else {
                let audio_format =
                    u16::from_le_bytes([data[content_start], data[content_start + 1]]);
                let num_channels =
                    u16::from_le_bytes([data[content_start + 2], data[content_start + 3]]);
                let sample_rate = u32::from_le_bytes([
                    data[content_start + 4],
                    data[content_start + 5],
                    data[content_start + 6],
                    data[content_start + 7],
                ]);
                let bits_per_sample =
                    u16::from_le_bytes([data[content_start + 14], data[content_start + 15]]);

                if num_channels == 0 {
                    anomalies.push("WAV 'fmt ' chunk specifies zero audio channels".into());
                }
                if sample_rate == 0 {
                    anomalies.push("WAV 'fmt ' chunk specifies zero sample rate".into());
                }
                if bits_per_sample == 0 {
                    anomalies.push("WAV 'fmt ' chunk specifies zero bits per sample".into());
                }
                fmt_info = Some((audio_format, num_channels, sample_rate, bits_per_sample));
            }
        } else if chunk_id == b"data" {
            data_seen = true;
            data_chunk_slice = Some(&data[content_start..content_end]);
            if chunk_size == 0 {
                anomalies.push("WAV 'data' chunk contains zero audio bytes".into());
            }
            if let Some((_, _, _, bits_per_sample)) = fmt_info {
                if bits_per_sample == 16 && chunk_size % 2 != 0 {
                    anomalies.push(format!(
                        "WAV 16-bit PCM 'data' chunk has unaligned odd length ({chunk_size} bytes)"
                    ));
                }
            }
        } else if chunk_id == SVLT_WAV_CHUNK {
            if stego_chunk_present {
                anomalies.push("Multiple dedicated RIFF 'svLt' metadata subchunks detected".into());
            }
            stego_chunk_present = true;

            if chunk_size < 4 {
                anomalies.push(
                    "WAV stego subchunk 'svLt' is truncated (missing CRC-32 checksum)".into(),
                );
            } else {
                let actual_payload_len = chunk_size - 4;
                payload_bytes = Some(actual_payload_len);
                let chunk_payload = &data[content_start..content_end - 4];
                let expected_crc = u32::from_le_bytes([
                    data[content_end - 4],
                    data[content_end - 3],
                    data[content_end - 2],
                    data[content_end - 1],
                ]);
                let actual_crc = crc32fast::hash(chunk_payload);
                if actual_crc != expected_crc {
                    anomalies.push(format!(
                        "WAV stego subchunk 'svLt' CRC-32 checksum mismatch (expected {expected_crc:#010x}, got {actual_crc:#010x})"
                    ));
                } else {
                    findings.push(format!(
                        "Detected dedicated RIFF 'svLt' metadata subchunk with {actual_payload_len} bytes valid payload (CRC-32 verified)"
                    ));
                }

                if let Some((v, dp, dec, s_hex)) = audit_embedded_container(
                    "RIFF 'svLt' subchunk",
                    chunk_payload,
                    &mut anomalies,
                    &mut findings,
                ) {
                    container_version = Some(v);
                    dpapi_bound = Some(dp);
                    decoy_container = Some(dec);
                    salt_hex = Some(s_hex);
                }
            }
        }

        if chunk_size % 2 == 1 {
            if content_end == data.len() {
                anomalies.push(
                    "WAV odd-sized subchunk at EOF is missing required 0x00 padding byte".into(),
                );
            } else if content_end < data.len() && data[content_end] != 0 {
                anomalies.push(format!(
                    "WAV odd-sized subchunk '{}' has non-zero padding byte ({:#04x}; potential covert channel)",
                    String::from_utf8_lossy(chunk_id),
                    data[content_end]
                ));
            }
        }

        // RIFF word boundary alignment
        offset = content_end + (chunk_size % 2);
    }

    if offset < data.len() {
        let leftover = data.len() - offset;
        if leftover > trailing_bytes {
            trailing_bytes = leftover;
            anomalies.push(format!(
                "Found {leftover} non-chunk trailing bytes at end of WAV file"
            ));
        }
    }

    if !fmt_seen {
        anomalies.push("WAV carrier is missing required 'fmt ' chunk".into());
    }
    if !data_seen {
        anomalies.push("WAV carrier is missing required 'data' chunk".into());
    }

    // Inspect PCM LSB stream if fmt and data chunk are valid
    if let Some((audio_format, num_channels, sample_rate, bits_per_sample)) = fmt_info {
        if audio_format == 1 && bits_per_sample == 16 {
            if let Some(audio_data) = data_chunk_slice {
                if audio_data.len() >= 128 {
                    let mut lsb_header = [0u8; 8];
                    for (bit_idx, i) in (0..128).step_by(2).enumerate() {
                        let bit = audio_data[i] & 1;
                        let byte_pos = bit_idx / 8;
                        let bit_pos = 7 - (bit_idx % 8);
                        lsb_header[byte_pos] |= bit << bit_pos;
                    }

                    if &lsb_header[0..4] == b"svLt" {
                        stego_lsb_present = true;
                        // FIX ENDIANNESS: wav.rs writes payload length as LITTLE-ENDIAN (u32::to_le_bytes)
                        let lsb_payload_len = u32::from_le_bytes([
                            lsb_header[4],
                            lsb_header[5],
                            lsb_header[6],
                            lsb_header[7],
                        ]) as usize;

                        let num_samples = audio_data.len() / 2;
                        let total_samples_needed =
                            (12usize.saturating_add(lsb_payload_len)).saturating_mul(8);

                        if num_samples < total_samples_needed {
                            anomalies.push(format!(
                                "16-bit PCM LSB stego stream declared payload length ({lsb_payload_len} bytes) exceeds audio capacity ({capacity} bytes)",
                                capacity = num_samples.saturating_sub(96) / 8
                            ));
                        } else {
                            let mut payload_buf = Zeroizing::new(vec![0u8; lsb_payload_len]);
                            for (byte_idx, item) in payload_buf.iter_mut().enumerate() {
                                let mut b = 0u8;
                                let start_sample = (8 + byte_idx) * 8;
                                for bit_idx in 0..8 {
                                    let sample_idx = start_sample + bit_idx;
                                    let bit = audio_data[sample_idx * 2] & 1;
                                    b |= bit << (7 - bit_idx);
                                }
                                *item = b;
                            }

                            let mut crc_bytes = [0u8; 4];
                            let crc_start_sample = (8 + lsb_payload_len) * 8;
                            for (byte_idx, item) in crc_bytes.iter_mut().enumerate() {
                                let mut b = 0u8;
                                let start_sample = crc_start_sample + byte_idx * 8;
                                for bit_idx in 0..8 {
                                    let sample_idx = start_sample + bit_idx;
                                    let bit = audio_data[sample_idx * 2] & 1;
                                    b |= bit << (7 - bit_idx);
                                }
                                *item = b;
                            }
                            let expected_crc = u32::from_le_bytes(crc_bytes);
                            let actual_crc = crc32fast::hash(&payload_buf);

                            if actual_crc != expected_crc {
                                anomalies.push(format!(
                                    "16-bit PCM LSB stego stream CRC-32 checksum mismatch (expected {expected_crc:#010x}, got {actual_crc:#010x})"
                                ));
                            } else {
                                findings.push(format!(
                                    "Detected 16-bit PCM LSB stego stream with valid 'svLt' magic header and verified CRC-32 ({lsb_payload_len} bytes)"
                                ));
                            }

                            if payload_bytes.is_none() {
                                payload_bytes = Some(lsb_payload_len);
                            }

                            if container_version.is_none() {
                                if let Some((v, dp, dec, s_hex)) = audit_embedded_container(
                                    "16-bit PCM LSB stream",
                                    &payload_buf,
                                    &mut anomalies,
                                    &mut findings,
                                ) {
                                    container_version = Some(v);
                                    dpapi_bound = Some(dp);
                                    decoy_container = Some(dec);
                                    salt_hex = Some(s_hex);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            findings.push(format!(
                "Audio format {audio_format}, {bits_per_sample}-bit depth ({num_channels} ch, {sample_rate} Hz): 16-bit PCM LSB steganography not supported (requires 16-bit uncompressed PCM)"
            ));
        }
    }

    let verdict = if !anomalies.is_empty() {
        CarrierVerdict::SuspiciousAnomaly
    } else if stego_chunk_present || stego_lsb_present {
        CarrierVerdict::StegoCarrierDetected
    } else {
        CarrierVerdict::CleanCarrier
    };

    if stego_chunk_present || stego_lsb_present {
        recommendations.push(
            "Carrier contains an active ShadowVault container; extract with 'svault extract-wav'"
                .into(),
        );
    } else if verdict == CarrierVerdict::CleanCarrier {
        findings.push(format!(
            "Valid WAV audio with {subchunk_count} subchunks. No steganographic signatures detected."
        ));
    }

    Ok(FileAuditReport {
        file_path: name.to_string(),
        file_size: data.len(),
        carrier_type: CarrierType::WavAudio,
        shannon_entropy: shannon,
        chi_square: chi_sq,
        verdict,
        details: CarrierDetails {
            container_version,
            dpapi_bound,
            decoy_container,
            payload_bytes,
            stego_chunk_present,
            stego_lsb_present,
            trailing_bytes,
            total_chunks_or_subchunks: subchunk_count,
            salt_hex,
        },
        anomalies,
        findings,
        recommendations,
    })
}

fn audit_svault_container(
    name: &str,
    data: &[u8],
    shannon: f64,
    chi_sq: f64,
) -> Result<FileAuditReport> {
    let mut anomalies = Vec::new();
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    // Minimum valid container is HEADER_LEN (34) + 16 (Poly1305 MAC tag) = 50 bytes!
    if data.len() < crate::crypto::HEADER_LEN + 16 {
        anomalies.push(format!(
            "Container is truncated ({len} bytes, minimum container size is 50 bytes with Poly1305 MAC tag)",
            len = data.len()
        ));
        return Ok(FileAuditReport {
            file_path: name.to_string(),
            file_size: data.len(),
            carrier_type: CarrierType::SvaultContainer,
            shannon_entropy: shannon,
            chi_square: chi_sq,
            verdict: CarrierVerdict::SuspiciousAnomaly,
            details: CarrierDetails {
                container_version: data.get(4).copied(),
                dpapi_bound: data.get(5).map(|f| (f & crate::crypto::FLAG_DPAPI) != 0),
                decoy_container: data.get(5).map(|f| (f & crate::crypto::FLAG_DECOY) != 0),
                payload_bytes: None,
                stego_chunk_present: false,
                stego_lsb_present: false,
                trailing_bytes: 0,
                total_chunks_or_subchunks: 0,
                salt_hex: None,
            },
            anomalies,
            findings,
            recommendations: vec!["Container is truncated and unrecoverable".into()],
        });
    }

    let version = data[4];
    let flags = data[5];
    let dpapi_bound = (flags & crate::crypto::FLAG_DPAPI) != 0;
    let decoy_container = (flags & crate::crypto::FLAG_DECOY) != 0;

    if version != crate::crypto::VERSION && version != crate::crypto::VERSION_V2 {
        anomalies.push(format!(
            "Unsupported container version v{version} (supported versions: v1, v2)"
        ));
    }
    if (flags & !0x03) != 0 {
        anomalies.push(format!("Unknown container flag bits: {flags:#04x}"));
    }

    let salt = &data[6..22];
    let salt_hex = salt.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let salt_entropy = shannon_entropy(salt);

    findings.push(format!("Container version: v{version}"));
    findings.push(format!("Windows DPAPI hardware binding: {dpapi_bound}"));
    if decoy_container {
        findings.push(
            "Plausible deniability dual-slot decoy container detected (hidden slot indistinguishable from random noise)".into(),
        );
    }

    if salt_entropy < 2.5 {
        anomalies.push(format!(
            "Low salt entropy ({salt_entropy:.2} bits/byte); KDF salt may lack CSPRNG randomness"
        ));
    }

    let ciphertext = &data[34..];
    let cipher_entropy = shannon_entropy(ciphertext);
    findings.push(format!(
        "Ciphertext Shannon entropy: {cipher_entropy:.4} bits/byte (ideal random: ~8.0)"
    ));

    if !ciphertext.is_empty() {
        let max_theoretical = (ciphertext.len() as f64).log2().min(8.0);
        if ciphertext.len() >= 256 && cipher_entropy < 7.2 {
            anomalies.push(format!(
                "Ciphertext Shannon entropy is unusually low ({cipher_entropy:.2} bits/byte; expected > 7.2 for payloads >= 256 bytes)"
            ));
        } else if ciphertext.len() >= 32 && cipher_entropy < (max_theoretical * 0.70) {
            anomalies.push(format!(
                "Ciphertext Shannon entropy is unusually low ({cipher_entropy:.2} bits/byte; theoretical max: {max_theoretical:.2})"
            ));
        }
    }

    let payload_bytes = if decoy_container {
        match crate::decoy::inspect_decoy(data) {
            Ok(info) => Some(info.payload_size),
            Err(e) => {
                anomalies.push(format!("Decoy container layout anomaly: {e}"));
                None
            }
        }
    } else {
        Some(ciphertext.len().saturating_sub(16))
    };

    let verdict = if !anomalies.is_empty() {
        CarrierVerdict::SuspiciousAnomaly
    } else {
        CarrierVerdict::EncryptedContainer
    };

    if verdict == CarrierVerdict::EncryptedContainer {
        recommendations.push("Container is intact; decrypt with 'svault decrypt'".into());
    } else {
        recommendations
            .push("Container exhibits anomalies or corruption; verify before decrypting".into());
    }

    Ok(FileAuditReport {
        file_path: name.to_string(),
        file_size: data.len(),
        carrier_type: CarrierType::SvaultContainer,
        shannon_entropy: shannon,
        chi_square: chi_sq,
        verdict,
        details: CarrierDetails {
            container_version: Some(version),
            dpapi_bound: Some(dpapi_bound),
            decoy_container: Some(decoy_container),
            payload_bytes,
            stego_chunk_present: false,
            stego_lsb_present: false,
            trailing_bytes: 0,
            total_chunks_or_subchunks: 1,
            salt_hex: Some(salt_hex),
        },
        anomalies,
        findings,
        recommendations,
    })
}

fn audit_plaintext_file(
    name: &str,
    data: &[u8],
    shannon: f64,
    chi_sq: f64,
) -> Result<FileAuditReport> {
    let text = String::from_utf8_lossy(data);
    let trimmed = text.trim();

    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    findings.push(format!(
        "File contains valid UTF-8 plaintext ({len} characters)",
        len = trimmed.chars().count()
    ));

    if trimmed.lines().count() == 1 && trimmed.len() <= 256 {
        findings.push(
            "Single-line passphrase or recovery key candidate detected. Auditing as passphrase."
                .into(),
        );
        let pass_report = audit_passphrase(trimmed);
        findings.push(format!(
            "Passphrase strength: {} (Score: {}/4, Effective entropy: {:.1} bits)",
            pass_report.strength, pass_report.score, pass_report.effective_entropy_bits
        ));
        for f in pass_report.findings {
            findings.push(format!("  - {f}"));
        }
        for s in pass_report.suggestions {
            recommendations.push(s);
        }
    } else {
        recommendations.push(
            "Encrypt sensitive plaintext using 'svault encrypt -i <file> -o <file.svault>'".into(),
        );
    }

    Ok(FileAuditReport {
        file_path: name.to_string(),
        file_size: data.len(),
        carrier_type: CarrierType::TextFile,
        shannon_entropy: shannon,
        chi_square: chi_sq,
        verdict: CarrierVerdict::PlaintextFile,
        details: CarrierDetails {
            container_version: None,
            dpapi_bound: None,
            decoy_container: None,
            payload_bytes: Some(data.len()),
            stego_chunk_present: false,
            stego_lsb_present: false,
            trailing_bytes: 0,
            total_chunks_or_subchunks: 0,
            salt_hex: None,
        },
        anomalies: Vec::new(),
        findings,
        recommendations,
    })
}

fn audit_binary_data(
    name: &str,
    data: &[u8],
    shannon: f64,
    chi_sq: f64,
) -> Result<FileAuditReport> {
    let mut anomalies = Vec::new();
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    if data.is_empty() {
        anomalies.push("File is completely empty (0 bytes)".into());
        findings.push("Zero-byte file contains no data or payload".into());
        recommendations.push("Verify file path; target file contains 0 bytes".into());
        return Ok(FileAuditReport {
            file_path: name.to_string(),
            file_size: 0,
            carrier_type: CarrierType::BinaryData,
            shannon_entropy: 0.0,
            chi_square: 0.0,
            verdict: CarrierVerdict::SuspiciousAnomaly,
            details: CarrierDetails {
                container_version: None,
                dpapi_bound: None,
                decoy_container: None,
                payload_bytes: Some(0),
                stego_chunk_present: false,
                stego_lsb_present: false,
                trailing_bytes: 0,
                total_chunks_or_subchunks: 0,
                salt_hex: None,
            },
            anomalies,
            findings,
            recommendations,
        });
    }

    recommendations.push(
        "Raw binary data; seal inside an authenticated container with 'svault encrypt'".into(),
    );

    if shannon > 7.9 {
        findings.push(format!(
            "High Shannon entropy ({shannon:.4} bits/byte); statistically indistinguishable from encrypted data or compressed stream"
        ));
    } else if shannon > 7.0 {
        findings.push(format!(
            "Moderate-high Shannon entropy ({shannon:.4} bits/byte); consistent with compressed data"
        ));
    } else {
        findings.push(format!(
            "Low-moderate Shannon entropy ({shannon:.4} bits/byte); consistent with structured binary or code"
        ));
    }

    Ok(FileAuditReport {
        file_path: name.to_string(),
        file_size: data.len(),
        carrier_type: CarrierType::BinaryData,
        shannon_entropy: shannon,
        chi_square: chi_sq,
        verdict: CarrierVerdict::BinaryData,
        details: CarrierDetails {
            container_version: None,
            dpapi_bound: None,
            decoy_container: None,
            payload_bytes: Some(data.len()),
            stego_chunk_present: false,
            stego_lsb_present: false,
            trailing_bytes: 0,
            total_chunks_or_subchunks: 0,
            salt_hex: None,
        },
        anomalies,
        findings,
        recommendations,
    })
}

fn is_likely_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let check_slice = if data.len() > 8192 {
        &data[..8192]
    } else {
        data
    };
    if check_slice.contains(&0) {
        return false;
    }
    let valid_slice = match std::str::from_utf8(check_slice) {
        Ok(s) => s,
        Err(e) if e.valid_up_to() > 0 && e.error_len().is_none() => {
            // Cut off at valid UTF-8 prefix if split occurred at slice boundary
            std::str::from_utf8(&check_slice[..e.valid_up_to()]).unwrap()
        }
        Err(_) => return false,
    };
    if valid_slice.is_empty() {
        return false;
    }
    // Verify non-control characters dominance
    let mut printables = 0usize;
    for ch in valid_slice.chars() {
        if !ch.is_control() || ch == '\n' || ch == '\r' || ch == '\t' {
            printables += 1;
        }
    }
    (printables as f64 / valid_slice.chars().count() as f64) > 0.95
}

// ---------------------------------------------------------------------------
// Pattern and vulnerability helpers
// ---------------------------------------------------------------------------

fn check_repetitions(pass: &str) -> (bool, f64) {
    let chars = Zeroizing::new(pass.chars().collect::<Vec<char>>());
    if chars.len() < 3 {
        return (false, 0.0);
    }

    let mut found = false;
    let mut penalty: f64 = 0.0;

    // Consecutive identical runs >= 3
    let mut run = 1;
    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            run += 1;
            if run >= 3 {
                found = true;
                penalty += 6.0;
            }
        } else {
            run = 1;
        }
    }

    // Repeated bigrams, trigrams, or 4-grams (e.g. `abab`, `abcabc`, `testtest`)
    let max_w = if chars.len() >= 8 { 4 } else { 3 };
    for w in 2..=max_w {
        if chars.len() < w * 2 {
            continue;
        }
        let mut seen = HashSet::new();
        for i in 0..=chars.len() - w {
            let sub: Zeroizing<String> = Zeroizing::new(chars[i..i + w].iter().collect());
            if !seen.insert((*sub).clone()) {
                found = true;
                penalty += 5.0;
                break;
            }
        }
    }

    (found, penalty.min(25.0))
}

fn check_sequential(pass: &str) -> (bool, f64) {
    let chars = Zeroizing::new(pass.chars().collect::<Vec<char>>());
    if chars.len() < 3 {
        return (false, 0.0);
    }

    let mut found = false;
    let mut penalty: f64 = 0.0;

    let mut asc_run = 1;
    let mut desc_run = 1;

    for i in 1..chars.len() {
        let prev_ch = chars[i - 1];
        let curr_ch = chars[i];

        let same_class = (prev_ch.is_ascii_digit() && curr_ch.is_ascii_digit())
            || (prev_ch.is_ascii_alphabetic() && curr_ch.is_ascii_alphabetic());

        if same_class {
            let prev = prev_ch.to_ascii_lowercase() as i32;
            let curr = curr_ch.to_ascii_lowercase() as i32;

            if curr == prev + 1 {
                asc_run += 1;
                if asc_run >= 3 {
                    found = true;
                    penalty += 7.0;
                }
            } else {
                asc_run = 1;
            }

            if curr == prev - 1 {
                desc_run += 1;
                if desc_run >= 3 {
                    found = true;
                    penalty += 7.0;
                }
            } else {
                desc_run = 1;
            }
        } else {
            asc_run = 1;
            desc_run = 1;
        }
    }

    (found, penalty.min(28.0))
}

fn check_keyboard_walks(pass: &str) -> (bool, f64) {
    let lower_chars = Zeroizing::new(
        pass.chars()
            .flat_map(|c| c.to_lowercase())
            .collect::<Vec<char>>(),
    );
    if lower_chars.len() < 3 {
        return (false, 0.0);
    }

    const ROWS: &[&str] = &[
        // QWERTY rows
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
        "!@#$%^&*()",
        // QWERTY vertical walks
        "1qaz",
        "2wsx",
        "3edc",
        "4rfv",
        "5tgb",
        "6yhn",
        "7ujm",
        "8ik,",
        "9ol.",
        "0p;/",
        "0plm",
        "plm",
        "qaz",
        "wsx",
        "edc",
        "rfv",
        "tgb",
        "yhn",
        "ujm",
        // QWERTZ
        "qwertzuiop",
        // AZERTY
        "azertyuiop",
        "qsdfghjklm",
        "wxcvbn",
        // Dvorak
        "',.pyfgcrl",
        "aoeuidhtns",
        ";qjkxbmwvz",
        // Colemak
        "qwfpgjluyd",
        "arstdhneio",
        "zxcvbkm",
        // Numpad rows & cols
        "789",
        "456",
        "123",
        "7410",
        "8520",
        "963",
    ];

    let mut found = false;
    let mut penalty: f64 = 0.0;

    for &row in ROWS {
        let rev_row: String = row.chars().rev().collect();
        for w in 3..=5 {
            if lower_chars.len() < w {
                continue;
            }
            for i in 0..=lower_chars.len() - w {
                let slice: Zeroizing<String> =
                    Zeroizing::new(lower_chars[i..i + w].iter().collect());
                if row.contains(&*slice) || rev_row.contains(&*slice) {
                    found = true;
                    penalty += 8.0;
                    if penalty >= 32.0 {
                        return (true, 32.0);
                    }
                }
            }
        }
    }

    (found, penalty.min(32.0))
}

fn check_common_patterns(pass: &str) -> (bool, f64, Option<String>) {
    let mut deobfuscated = Zeroizing::new(String::with_capacity(pass.len()));
    for ch in pass.chars() {
        let norm = match ch.to_ascii_lowercase() {
            '@' | '4' => 'a',
            '$' | '5' => 's',
            '0' => 'o',
            '1' | '!' | '|' => 'i',
            '3' => 'e',
            '7' | '+' => 't',
            '8' => 'b',
            other => other,
        };
        deobfuscated.push(norm);
    }

    const DICTIONARY: &[&str] = &[
        "password", "pass123", "admin", "welcome", "shadow", "vault", "letmein", "monkey",
        "dragon", "master", "access", "secret", "login", "iloveyou", "trustno1", "football",
        "baseball", "superman", "default", "qwerty", "123456", "12345678", "root", "toor",
        "passcode", "testing", "keyboard", "hunter2", "computer", "sunshine", "guest", "manager",
    ];

    for &word in DICTIONARY {
        if deobfuscated.contains(word) {
            let matched = Some(word.to_string());
            deobfuscated.zeroize();
            return (true, 30.0, matched);
        }
    }

    deobfuscated.zeroize();
    (false, 0.0, None)
}

fn estimate_crack_time(effective_entropy: f64, rate: f64) -> String {
    if effective_entropy <= 0.0 {
        return "instant".into();
    }
    if rate <= 0.0 {
        return "infinite".into();
    }

    // Half search space on average: 2^(H-1) guesses
    // log10(seconds) = (H - 1) * log10(2) - log10(rate)
    let log10_2 = std::f64::consts::LOG10_2;
    let log10_seconds = (effective_entropy - 1.0).max(0.0) * log10_2 - rate.log10();

    if log10_seconds < -3.0 {
        "< 1 millisecond".into()
    } else if log10_seconds < 0.0 {
        "< 1 second".into()
    } else if log10_seconds < 1.77815 {
        let seconds = 10.0f64.powf(log10_seconds);
        format!("{seconds:.1} seconds")
    } else if log10_seconds < 3.5563 {
        let minutes = 10.0f64.powf(log10_seconds) / 60.0;
        format!("{minutes:.1} minutes")
    } else if log10_seconds < 4.9365 {
        let hours = 10.0f64.powf(log10_seconds) / 3600.0;
        format!("{hours:.1} hours")
    } else if log10_seconds < 7.4988 {
        let days = 10.0f64.powf(log10_seconds) / 86400.0;
        format!("{days:.1} days")
    } else if log10_seconds < 9.4988 {
        let years = 10.0f64.powf(log10_seconds) / 31_536_000.0;
        format!("{years:.1} years")
    } else if log10_seconds < 11.4988 {
        let centuries = 10.0f64.powf(log10_seconds) / 3_153_600_000.0;
        format!("{centuries:.0} centuries")
    } else if log10_seconds < 14.4988 {
        let millennia = 10.0f64.powf(log10_seconds) / 31_536_000_000.0;
        format!("{millennia:.0} millennia")
    } else {
        let exp_years = log10_seconds - 7.4988;
        format!("> 10^{exp_years:.0} years")
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_empty_and_uniform() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        // All zeros: 1 symbol
        let zeros = [0u8; 100];
        assert_eq!(shannon_entropy(&zeros), 0.0);

        // Uniform 256 bytes
        let mut uniform = [0u8; 256];
        for (i, b) in uniform.iter_mut().enumerate() {
            *b = i as u8;
        }
        let h = shannon_entropy(&uniform);
        assert!((h - 8.0).abs() < 1e-6);
    }

    #[test]
    fn chi_square_empty_and_uniform() {
        assert_eq!(chi_square(&[]), 0.0);
        let mut uniform = [0u8; 256];
        for (i, b) in uniform.iter_mut().enumerate() {
            *b = i as u8;
        }
        let cs = chi_square(&uniform);
        assert!((cs - 0.0).abs() < 1e-6);
    }

    #[test]
    fn audit_empty_passphrase() {
        let rep = audit_passphrase("");
        assert_eq!(rep.score, 0);
        assert_eq!(rep.strength, StrengthLevel::VeryWeak);
        assert_eq!(rep.length_chars, 0);
        assert_eq!(rep.effective_entropy_bits, 0.0);
    }

    #[test]
    fn audit_weak_passphrases() {
        let rep1 = audit_passphrase("123456");
        assert_eq!(rep1.score, 0);
        assert_eq!(rep1.strength, StrengthLevel::VeryWeak);
        assert!(rep1.has_sequential);

        let rep2 = audit_passphrase("password");
        assert_eq!(rep2.score, 0);
        assert_eq!(rep2.strength, StrengthLevel::VeryWeak);
        assert!(rep2.has_common_pattern);

        let rep3 = audit_passphrase("P@ssw0rd1");
        assert_eq!(rep3.score, 0);
        assert_eq!(rep3.strength, StrengthLevel::VeryWeak);
        assert!(rep3.has_common_pattern);
    }

    #[test]
    fn audit_keyboard_walk_and_repeats() {
        let rep = audit_passphrase("qwerty123456");
        assert!(rep.has_keyboard_walk);
        assert!(rep.has_sequential);
        assert!(rep.score <= 1);

        let rep_rep = audit_passphrase("aaaaabbbbb");
        assert!(rep_rep.has_repeats);
        assert!(rep_rep.score <= 1);
    }

    #[test]
    fn audit_strong_passphrase() {
        let strong = "Kx9#mQ2$vL8!zW5&pT4@";
        let rep = audit_passphrase(strong);
        assert_eq!(rep.score, 4);
        assert_eq!(rep.strength, StrengthLevel::VeryStrong);
        assert!(!rep.has_repeats);
        assert!(!rep.has_sequential);
        assert!(!rep.has_keyboard_walk);
        assert!(!rep.has_common_pattern);
        assert!(rep.effective_entropy_bits > 85.0);
    }

    #[test]
    fn audit_png_clean_and_stego() {
        // Minimal valid 1x1 PNG bytes
        let clean_png = vec![
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // signature
            0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR len 13
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
            0x15, 0xc4, 0x89, // CRC
            0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, // IDAT len 10
            0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d,
            0xb4, // CRC
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, // IEND len 0
            0xae, 0x42, 0x60, 0x82, // CRC
        ];

        let rep_clean = audit_carrier_bytes("test.png", &clean_png).unwrap();
        assert_eq!(rep_clean.carrier_type, CarrierType::PngImage);
        assert_eq!(rep_clean.verdict, CarrierVerdict::CleanCarrier);
        assert!(!rep_clean.details.stego_chunk_present);
        assert_eq!(rep_clean.details.trailing_bytes, 0);

        // Embed payload using stego module
        let stego_png = crate::stego::embed_in_png(&clean_png, b"secret-payload").unwrap();
        let rep_stego = audit_carrier_bytes("stego.png", &stego_png).unwrap();
        assert_eq!(rep_stego.carrier_type, CarrierType::PngImage);
        assert_eq!(rep_stego.verdict, CarrierVerdict::StegoCarrierDetected);
        assert!(rep_stego.details.stego_chunk_present);
        assert_eq!(rep_stego.details.payload_bytes, Some(14));
    }

    #[test]
    fn audit_png_trailing_bytes_anomaly() {
        let mut corrupted_png = vec![
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // signature
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, // IEND len 0
            0xae, 0x42, 0x60, 0x82, // CRC
        ];
        corrupted_png.extend_from_slice(b"trailing-secret-append");

        let rep = audit_carrier_bytes("corrupted.png", &corrupted_png).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert_eq!(rep.details.trailing_bytes, 22);
        assert!(rep.anomalies.iter().any(|a| a.contains("trailing bytes")));
    }

    #[test]
    fn audit_svault_container_intact_and_truncated() {
        let plaintext = b"audit test secret";
        let sealed = crate::crypto::seal(plaintext, "test-passphrase", false).unwrap();

        let rep = audit_carrier_bytes("vault.svault", &sealed).unwrap();
        assert_eq!(rep.carrier_type, CarrierType::SvaultContainer);
        assert_eq!(rep.verdict, CarrierVerdict::EncryptedContainer);
        assert_eq!(rep.details.container_version, Some(1));
        assert_eq!(rep.details.dpapi_bound, Some(false));
        assert!(rep.details.salt_hex.is_some());

        // Truncated container
        let truncated = &sealed[..20];
        let rep_trunc = audit_carrier_bytes("truncated.svault", truncated).unwrap();
        assert_eq!(rep_trunc.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_trunc.anomalies.iter().any(|a| a.contains("truncated")));
    }

    #[test]
    fn audit_plaintext_and_binary() {
        let text = b"single-line-random-phrase-example";
        let rep_text = audit_carrier_bytes("secret.txt", text).unwrap();
        assert_eq!(rep_text.carrier_type, CarrierType::TextFile);
        assert_eq!(rep_text.verdict, CarrierVerdict::PlaintextFile);

        let binary = [0x00, 0xff, 0x12, 0x34, 0x88, 0x99, 0xaa, 0xbb];
        let rep_bin = audit_carrier_bytes("blob.bin", &binary).unwrap();
        assert_eq!(rep_bin.carrier_type, CarrierType::BinaryData);
        assert_eq!(rep_bin.verdict, CarrierVerdict::BinaryData);
    }

    #[test]
    fn audit_wav_clean_and_stego_chunk_and_lsb() {
        // Minimal valid 16-bit mono 44.1kHz PCM WAV
        let num_samples = 2000;
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        let riff_size = 36 + (num_samples * 2) as u32;
        wav.extend_from_slice(&riff_size.to_le_bytes());
        wav.extend_from_slice(b"WAVE");

        // fmt chunk
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes()); // subchunk1 size 16
        wav.extend_from_slice(&1u16.to_le_bytes()); // PCM = 1
        wav.extend_from_slice(&1u16.to_le_bytes()); // mono = 1
        wav.extend_from_slice(&44100u32.to_le_bytes()); // sample rate
        wav.extend_from_slice(&(44100u32 * 2).to_le_bytes()); // byte rate
        wav.extend_from_slice(&2u16.to_le_bytes()); // block align
        wav.extend_from_slice(&16u16.to_le_bytes()); // bits per sample

        // data chunk
        wav.extend_from_slice(b"data");
        let data_size = (num_samples * 2) as u32;
        wav.extend_from_slice(&data_size.to_le_bytes());
        for i in 0..num_samples {
            let sample = ((i as f64 * 0.1).sin() * 10000.0) as i16;
            wav.extend_from_slice(&sample.to_le_bytes());
        }

        // 1. Audit clean WAV
        let rep_clean = audit_carrier_bytes("audio.wav", &wav).unwrap();
        assert_eq!(rep_clean.carrier_type, CarrierType::WavAudio);
        assert_eq!(rep_clean.verdict, CarrierVerdict::CleanCarrier);
        assert!(!rep_clean.details.stego_chunk_present);
        assert!(!rep_clean.details.stego_lsb_present);

        // 2. Embed via chunk mode (payload = 12 bytes)
        let wav_chunk =
            crate::wav::embed_in_wav(&wav, b"chunk-secret", crate::wav::WavMode::Chunk).unwrap();
        let rep_chunk = audit_carrier_bytes("audio_chunk.wav", &wav_chunk).unwrap();
        assert_eq!(rep_chunk.carrier_type, CarrierType::WavAudio);
        assert_eq!(rep_chunk.verdict, CarrierVerdict::StegoCarrierDetected);
        assert!(rep_chunk.details.stego_chunk_present);
        assert_eq!(rep_chunk.details.payload_bytes, Some(12));

        // 3. Embed via LSB mode (payload = 10 bytes)
        let wav_lsb =
            crate::wav::embed_in_wav(&wav, b"lsb-secret", crate::wav::WavMode::Lsb).unwrap();
        let rep_lsb = audit_carrier_bytes("audio_lsb.wav", &wav_lsb).unwrap();
        assert_eq!(rep_lsb.carrier_type, CarrierType::WavAudio);
        assert_eq!(rep_lsb.verdict, CarrierVerdict::StegoCarrierDetected);
        assert!(rep_lsb.details.stego_lsb_present);
        assert_eq!(rep_lsb.details.payload_bytes, Some(10));
    }

    #[test]
    fn audit_utf8_korean_and_emoji_passphrase_no_panic() {
        // Multi-byte UTF-8 passphrases must never panic on byte boundaries
        let korean = "비밀번호123456";
        let rep = audit_passphrase(korean);
        assert!(rep.has_sequential);
        assert!(rep.has_keyboard_walk);
        assert_eq!(rep.length_chars, 10);
        assert_eq!(rep.length_bytes, 18);

        let cyrillic = "пароль123";
        let rep_cyr = audit_passphrase(cyrillic);
        assert_eq!(rep_cyr.length_chars, 9);

        let emoji = "🔑vault2026!🛡️";
        let rep_emoji = audit_passphrase(emoji);
        assert!(rep_emoji.length_chars >= 10);
        assert!(rep_emoji.effective_entropy_bits > 0.0);
    }

    #[test]
    fn audit_high_entropy_overflow_protection() {
        // Very high entropy passphrase (> 1024 bits) must not produce 'inf' or 'NaN'
        let long_pass = "Kx9#mQ2$vL8!zW5&pT4@".repeat(20);
        let rep = audit_passphrase(&long_pass);
        assert!(rep.effective_entropy_bits > 1000.0);
        assert!(!rep.crack_time_online.contains("inf"));
        assert!(!rep.crack_time_online.contains("NaN"));
        assert!(!rep.crack_time_offline_fast.contains("inf"));
        assert!(rep.crack_time_offline_fast.contains("> 10^"));
    }

    #[test]
    fn audit_non_standard_keyboard_walks() {
        // QWERTZ walk
        let rep_qwertz = audit_passphrase("qwertz999");
        assert!(rep_qwertz.has_keyboard_walk);

        // AZERTY walk
        let rep_azerty = audit_passphrase("azerty999");
        assert!(rep_azerty.has_keyboard_walk);

        // Dvorak walk
        let rep_dvorak = audit_passphrase("pyfgcr999");
        assert!(rep_dvorak.has_keyboard_walk);

        // Numpad walk
        let rep_numpad = audit_passphrase("789456123");
        assert!(rep_numpad.has_keyboard_walk);
    }

    #[test]
    fn audit_wav_corrupted_crc_chunk_and_lsb() {
        let num_samples = 2000;
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        let riff_size = 36 + (num_samples * 2) as u32;
        wav.extend_from_slice(&riff_size.to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&44100u32.to_le_bytes());
        wav.extend_from_slice(&(44100u32 * 2).to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        let data_size = (num_samples * 2) as u32;
        wav.extend_from_slice(&data_size.to_le_bytes());
        for i in 0..num_samples {
            let sample = ((i as f64 * 0.1).sin() * 8000.0) as i16;
            wav.extend_from_slice(&sample.to_le_bytes());
        }

        // Corrupted chunk CRC (even payload length so no 0x00 padding byte at end)
        let mut wav_chunk =
            crate::wav::embed_in_wav(&wav, b"secret-payload", crate::wav::WavMode::Chunk).unwrap();
        let last_idx = wav_chunk.len() - 1;
        wav_chunk[last_idx] ^= 0xFF; // Tamper CRC
        let rep_chunk = audit_carrier_bytes("corrupt_chunk.wav", &wav_chunk).unwrap();
        assert_eq!(rep_chunk.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_chunk
            .anomalies
            .iter()
            .any(|a| a.contains("CRC-32 checksum mismatch")));

        // Corrupted LSB CRC
        let mut wav_lsb =
            crate::wav::embed_in_wav(&wav, b"secret-lsb", crate::wav::WavMode::Lsb).unwrap();
        // Flip one LSB sample in the CRC region
        let sample_offset = 44 + (8 + 10) * 8 * 2;
        wav_lsb[sample_offset] ^= 1;
        let rep_lsb = audit_carrier_bytes("corrupt_lsb.wav", &wav_lsb).unwrap();
        assert_eq!(rep_lsb.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_lsb
            .anomalies
            .iter()
            .any(|a| a.contains("CRC-32 checksum mismatch")));
    }

    #[test]
    fn audit_wav_trailing_bytes_detection() {
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&36u32.to_le_bytes()); // riff size = 36
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&44100u32.to_le_bytes());
        wav.extend_from_slice(&(44100u32 * 2).to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&0u32.to_le_bytes());
        wav.extend_from_slice(b"malicious-trailing-bytes-injected-past-riff");

        let rep = audit_carrier_bytes("trailing.wav", &wav).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep.details.trailing_bytes > 0);
        assert!(rep.anomalies.iter().any(|a| a.contains("trailing bytes")));
    }

    #[test]
    fn audit_empty_file_and_truncated_containers() {
        // Empty file
        let rep_empty = audit_carrier_bytes("empty.bin", &[]).unwrap();
        assert_eq!(rep_empty.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_empty.anomalies.iter().any(|a| a.contains("empty")));

        // Container between 34 and 49 bytes (missing Poly1305 MAC)
        let mut trunc_container = vec![0u8; 40];
        trunc_container[0..4].copy_from_slice(b"SVLT");
        trunc_container[4] = 1;
        let rep_trunc = audit_carrier_bytes("trunc.svault", &trunc_container).unwrap();
        assert_eq!(rep_trunc.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_trunc.anomalies.iter().any(|a| a.contains("truncated")));
    }

    #[test]
    fn audit_utf8_text_split_at_boundary() {
        // Build a 1025-byte file where a 3-byte Korean character spans byte 1023..1026
        let mut text = "a".repeat(1023);
        text.push('가'); // 3 bytes
        let rep = audit_carrier_bytes("boundary.txt", text.as_bytes()).unwrap();
        assert_eq!(rep.carrier_type, CarrierType::TextFile);
        assert_eq!(rep.verdict, CarrierVerdict::PlaintextFile);
    }

    #[test]
    fn audit_png_embedded_container_metadata() {
        let clean_png = vec![
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];
        let sealed = crate::crypto::seal(b"classified", "audit-pass", false).unwrap();
        let stego_png = crate::stego::embed_in_png(&clean_png, &sealed).unwrap();

        let rep = audit_carrier_bytes("vault_stego.png", &stego_png).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::StegoCarrierDetected);
        assert_eq!(rep.details.container_version, Some(1));
        assert_eq!(rep.details.dpapi_bound, Some(false));
        assert!(rep.details.salt_hex.is_some());
    }

    #[test]
    fn audit_apng_carrier_clean_and_stego() {
        fn make_png_chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
            let mut chunk = Vec::new();
            chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
            chunk.extend_from_slice(chunk_type);
            chunk.extend_from_slice(data);
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(chunk_type);
            hasher.update(data);
            chunk.extend_from_slice(&hasher.finalize().to_be_bytes());
            chunk
        }

        let mut apng = Vec::new();
        apng.extend_from_slice(PNG_SIG);
        // IHDR
        let ihdr_data = [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        apng.extend_from_slice(&make_png_chunk(b"IHDR", &ihdr_data));
        // acTL (8 bytes: 2 frames, 0 plays)
        let actl_data = [0, 0, 0, 2, 0, 0, 0, 0];
        apng.extend_from_slice(&make_png_chunk(b"acTL", &actl_data));
        // fcTL (26 bytes frame control)
        let fctl_data = [0u8; 26];
        apng.extend_from_slice(&make_png_chunk(b"fcTL", &fctl_data));
        // IDAT (10 bytes)
        let idat_data = [0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01];
        apng.extend_from_slice(&make_png_chunk(b"IDAT", &idat_data));
        // IEND
        apng.extend_from_slice(&make_png_chunk(b"IEND", &[]));

        // 1. Audit clean APNG
        let rep_clean = audit_carrier_bytes("animation.png", &apng).unwrap();
        assert_eq!(rep_clean.carrier_type, CarrierType::PngImage);
        assert_eq!(rep_clean.verdict, CarrierVerdict::CleanCarrier);
        assert!(rep_clean.findings.iter().any(|f| f.contains("APNG")));

        // 2. Embed payload into APNG before IEND
        let stego_apng = crate::stego::embed_in_png(&apng, b"apng-hidden-vault").unwrap();
        let rep_stego = audit_carrier_bytes("animation_stego.png", &stego_apng).unwrap();
        assert_eq!(rep_stego.verdict, CarrierVerdict::StegoCarrierDetected);
        assert!(rep_stego.details.stego_chunk_present);
        assert_eq!(rep_stego.details.payload_bytes, Some(17));
        assert!(rep_stego.findings.iter().any(|f| f.contains("APNG")));
    }

    #[test]
    fn audit_png_corrupted_non_critical_chunk_crc() {
        let mut png = Vec::new();
        png.extend_from_slice(PNG_SIG);
        // IHDR
        let ihdr = [
            0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89,
        ];
        png.extend_from_slice(&ihdr);
        // tEXt chunk with deliberate CRC corruption
        let text_chunk = [
            0x00, 0x00, 0x00, 0x05, // len = 5
            0x74, 0x45, 0x58, 0x74, // 'tEXt'
            0x68, 0x65, 0x6c, 0x6c, 0x6f, // "hello"
            0x12, 0x34, 0x56, 0x78, // Corrupted CRC
        ];
        png.extend_from_slice(&text_chunk);
        // IEND
        png.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ]);

        let rep = audit_carrier_bytes("corrupted_text.png", &png).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep
            .anomalies
            .iter()
            .any(|a| a.contains("tEXt") && a.contains("invalid CRC-32")));
    }

    #[test]
    fn audit_png_missing_ihdr_and_multiple_ihdr() {
        // Missing IHDR (starts with IDAT)
        let mut no_ihdr = Vec::new();
        no_ihdr.extend_from_slice(PNG_SIG);
        no_ihdr.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, 0x49, 0x44, 0x41, 0x54, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ]);
        let rep_no_ihdr = audit_carrier_bytes("no_ihdr.png", &no_ihdr).unwrap();
        assert_eq!(rep_no_ihdr.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_no_ihdr
            .anomalies
            .iter()
            .any(|a| a.contains("First PNG chunk must be 'IHDR'")));

        // Multiple IHDR
        let clean_png = vec![
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15,
            0xc4, 0x89, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];
        let rep_multi_ihdr = audit_carrier_bytes("multi_ihdr.png", &clean_png).unwrap();
        assert_eq!(rep_multi_ihdr.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_multi_ihdr
            .anomalies
            .iter()
            .any(|a| a.contains("Multiple 'IHDR' chunks")));
    }

    #[test]
    fn audit_png_embedded_truncated_container_anomaly() {
        let clean_png = vec![
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];

        // 40-byte truncated container embedded in svLt chunk
        let mut truncated_container = vec![0u8; 40];
        truncated_container[0..4].copy_from_slice(b"SVLT");
        truncated_container[4] = 1;
        let stego_png = crate::stego::embed_in_png(&clean_png, &truncated_container).unwrap();

        let rep = audit_carrier_bytes("trunc_embed.png", &stego_png).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep
            .anomalies
            .iter()
            .any(|a| a.contains("Embedded container in PNG 'svLt' chunk is truncated")));
    }

    #[test]
    fn audit_wav_missing_fmt_or_data_chunk_anomalies() {
        // Missing fmt chunk
        let mut wav_no_fmt = Vec::new();
        wav_no_fmt.extend_from_slice(b"RIFF");
        wav_no_fmt.extend_from_slice(&20u32.to_le_bytes());
        wav_no_fmt.extend_from_slice(b"WAVEdata");
        wav_no_fmt.extend_from_slice(&4u32.to_le_bytes());
        wav_no_fmt.extend_from_slice(&[0, 0, 0, 0]);
        let rep_no_fmt = audit_carrier_bytes("no_fmt.wav", &wav_no_fmt).unwrap();
        assert_eq!(rep_no_fmt.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_no_fmt
            .anomalies
            .iter()
            .any(|a| a.contains("missing required 'fmt ' chunk")));

        // Missing data chunk
        let mut wav_no_data = Vec::new();
        wav_no_data.extend_from_slice(b"RIFF");
        wav_no_data.extend_from_slice(&28u32.to_le_bytes());
        wav_no_data.extend_from_slice(b"WAVEfmt ");
        wav_no_data.extend_from_slice(&16u32.to_le_bytes());
        wav_no_data.extend_from_slice(&1u16.to_le_bytes());
        wav_no_data.extend_from_slice(&1u16.to_le_bytes());
        wav_no_data.extend_from_slice(&44100u32.to_le_bytes());
        wav_no_data.extend_from_slice(&(44100u32 * 2).to_le_bytes());
        wav_no_data.extend_from_slice(&2u16.to_le_bytes());
        wav_no_data.extend_from_slice(&16u16.to_le_bytes());
        let rep_no_data = audit_carrier_bytes("no_data.wav", &wav_no_data).unwrap();
        assert_eq!(rep_no_data.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_no_data
            .anomalies
            .iter()
            .any(|a| a.contains("missing required 'data' chunk")));

        // Zero channels
        let mut wav_zero_ch = wav_no_data.clone();
        wav_zero_ch[22..24].copy_from_slice(&0u16.to_le_bytes());
        wav_zero_ch.extend_from_slice(b"data");
        wav_zero_ch.extend_from_slice(&4u32.to_le_bytes());
        wav_zero_ch.extend_from_slice(&[0, 0, 0, 0]);
        let rep_zero_ch = audit_carrier_bytes("zero_ch.wav", &wav_zero_ch).unwrap();
        assert_eq!(rep_zero_ch.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep_zero_ch
            .anomalies
            .iter()
            .any(|a| a.contains("zero audio channels")));
    }

    #[test]
    fn audit_wav_non_standard_sample_rates() {
        fn make_wav(sample_rate: u32) -> Vec<u8> {
            let num_samples = 2000;
            let mut wav = Vec::new();
            wav.extend_from_slice(b"RIFF");
            let riff_size = 36 + (num_samples * 2) as u32;
            wav.extend_from_slice(&riff_size.to_le_bytes());
            wav.extend_from_slice(b"WAVEfmt ");
            wav.extend_from_slice(&16u32.to_le_bytes());
            wav.extend_from_slice(&1u16.to_le_bytes());
            wav.extend_from_slice(&1u16.to_le_bytes());
            wav.extend_from_slice(&sample_rate.to_le_bytes());
            wav.extend_from_slice(&(sample_rate * 2).to_le_bytes());
            wav.extend_from_slice(&2u16.to_le_bytes());
            wav.extend_from_slice(&16u16.to_le_bytes());
            wav.extend_from_slice(b"data");
            let data_size = (num_samples * 2) as u32;
            wav.extend_from_slice(&data_size.to_le_bytes());
            for i in 0..num_samples {
                let sample = ((i as f64 * 0.1).sin() * 8000.0) as i16;
                wav.extend_from_slice(&sample.to_le_bytes());
            }
            wav
        }

        // 8000 Hz (Telephony)
        let wav_8k = make_wav(8000);
        let rep_8k = audit_carrier_bytes("telephony_8k.wav", &wav_8k).unwrap();
        assert_eq!(rep_8k.verdict, CarrierVerdict::CleanCarrier);

        let stego_8k =
            crate::wav::embed_in_wav(&wav_8k, b"secret-8k", crate::wav::WavMode::Lsb).unwrap();
        let rep_stego_8k = audit_carrier_bytes("stego_8k.wav", &stego_8k).unwrap();
        assert_eq!(rep_stego_8k.verdict, CarrierVerdict::StegoCarrierDetected);
        assert!(rep_stego_8k.details.stego_lsb_present);

        // 192000 Hz (Hi-Res Audio)
        let wav_192k = make_wav(192000);
        let rep_192k = audit_carrier_bytes("hires_192k.wav", &wav_192k).unwrap();
        assert_eq!(rep_192k.verdict, CarrierVerdict::CleanCarrier);
    }

    #[test]
    fn audit_wav_non_16bit_pcm_audio_format() {
        // 24-bit PCM WAV (audio_format = 1, bits_per_sample = 24)
        let mut wav_24bit = Vec::new();
        wav_24bit.extend_from_slice(b"RIFF");
        wav_24bit.extend_from_slice(&48u32.to_le_bytes());
        wav_24bit.extend_from_slice(b"WAVEfmt ");
        wav_24bit.extend_from_slice(&16u32.to_le_bytes());
        wav_24bit.extend_from_slice(&1u16.to_le_bytes());
        wav_24bit.extend_from_slice(&1u16.to_le_bytes());
        wav_24bit.extend_from_slice(&48000u32.to_le_bytes());
        wav_24bit.extend_from_slice(&(48000u32 * 3).to_le_bytes());
        wav_24bit.extend_from_slice(&3u16.to_le_bytes());
        wav_24bit.extend_from_slice(&24u16.to_le_bytes()); // 24-bit
        wav_24bit.extend_from_slice(b"data");
        wav_24bit.extend_from_slice(&12u32.to_le_bytes());
        wav_24bit.extend_from_slice(&[0u8; 12]);

        let rep = audit_carrier_bytes("audio_24bit.wav", &wav_24bit).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::CleanCarrier);
        assert!(rep
            .findings
            .iter()
            .any(|f| f.contains("24-bit depth") && f.contains("not supported")));
    }

    #[test]
    fn audit_wav_embedded_truncated_container_anomaly() {
        let num_samples = 2000;
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        let riff_size = 36 + (num_samples * 2) as u32;
        wav.extend_from_slice(&riff_size.to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&44100u32.to_le_bytes());
        wav.extend_from_slice(&(44100u32 * 2).to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        let data_size = (num_samples * 2) as u32;
        wav.extend_from_slice(&data_size.to_le_bytes());
        for i in 0..num_samples {
            let sample = ((i as f64 * 0.1).sin() * 8000.0) as i16;
            wav.extend_from_slice(&sample.to_le_bytes());
        }

        let mut trunc_container = vec![0u8; 40];
        trunc_container[0..4].copy_from_slice(b"SVLT");
        trunc_container[4] = 1;

        let stego_wav =
            crate::wav::embed_in_wav(&wav, &trunc_container, crate::wav::WavMode::Chunk).unwrap();

        let rep = audit_carrier_bytes("wav_trunc_embed.wav", &stego_wav).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep
            .anomalies
            .iter()
            .any(|a| a.contains("Embedded container in RIFF 'svLt' subchunk is truncated")));
    }

    #[test]
    fn audit_passphrase_vertical_keyboard_walks() {
        let rep_v1 = audit_passphrase("qazwsxedc");
        assert!(rep_v1.has_keyboard_walk);

        let rep_v2 = audit_passphrase("1qaz2wsx");
        assert!(rep_v2.has_keyboard_walk);

        let rep_v3 = audit_passphrase("rfvtgb123");
        assert!(rep_v3.has_keyboard_walk);
    }

    #[test]
    fn audit_passphrase_four_gram_repeats() {
        let rep = audit_passphrase("testtest2026!");
        assert!(rep.has_repeats);

        let rep_pass = audit_passphrase("passpass999");
        assert!(rep_pass.has_repeats);
    }

    #[test]
    fn audit_passphrase_ascii_control_characters() {
        let rep_nul = audit_passphrase("password\0extra");
        assert!(rep_nul
            .findings
            .iter()
            .any(|f| f.contains("non-printable ASCII control characters")));

        let rep_esc = audit_passphrase("secret\x1b12345");
        assert!(rep_esc
            .findings
            .iter()
            .any(|f| f.contains("non-printable ASCII control characters")));
    }

    #[test]
    fn audit_binary_file_with_text_prefix_not_classified_as_text() {
        let mut binary_data = Vec::new();
        binary_data.extend_from_slice(b"This looks like an innocent ASCII string at the header...");
        binary_data.push(0x00); // Null byte
        binary_data.extend_from_slice(&[0x12, 0x34, 0x56, 0xfe, 0xff, 0x88]);

        let rep = audit_carrier_bytes("hybrid.bin", &binary_data).unwrap();
        assert_eq!(rep.carrier_type, CarrierType::BinaryData);
        assert_ne!(rep.carrier_type, CarrierType::TextFile);
    }

    #[test]
    fn audit_corrupted_decoy_container() {
        let primary = b"secret-hidden";
        let decoy = b"harmless-decoy";
        let sealed = crate::decoy::seal_decoy(primary, "pass1", decoy, "pass2", false, 0).unwrap();

        // Corrupt decoy body len field (bytes 34..38) to exceed container length
        let mut tampered = sealed;
        tampered[34..38].copy_from_slice(&0x7FFFFFFF_u32.to_le_bytes());

        let rep = audit_carrier_bytes("corrupt_decoy.svault", &tampered).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep
            .anomalies
            .iter()
            .any(|a| a.contains("Decoy container layout anomaly")));
    }

    #[test]
    fn audit_png_iend_non_zero_length_anomaly() {
        let mut malformed_png = vec![
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // signature
            0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR len 13
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
            0x15, 0xc4, 0x89, // CRC
        ];
        // Malformed IEND with 4 bytes of payload
        let payload = b"iend";
        malformed_png.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        malformed_png.extend_from_slice(b"IEND");
        malformed_png.extend_from_slice(payload);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(b"IEND");
        hasher.update(payload);
        malformed_png.extend_from_slice(&hasher.finalize().to_be_bytes());

        let rep = audit_carrier_bytes("iend_payload.png", &malformed_png).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep
            .anomalies
            .iter()
            .any(|a| a.contains("non-zero payload length")));
    }

    #[test]
    fn audit_wav_truncated_riff_anomaly() {
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        // Declare huge RIFF length (1 MB)
        wav.extend_from_slice(&1_000_000u32.to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&44100u32.to_le_bytes());
        wav.extend_from_slice(&(44100u32 * 2).to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&100u32.to_le_bytes());
        wav.extend_from_slice(&[0u8; 100]);

        let rep = audit_carrier_bytes("trunc_riff.wav", &wav).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep
            .anomalies
            .iter()
            .any(|a| a.contains("WAV carrier is truncated")));
    }

    #[test]
    fn audit_wav_invalid_riff_declared_size() {
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&2u32.to_le_bytes()); // invalid size < 4
        wav.extend_from_slice(b"WAVE");

        let rep = audit_carrier_bytes("invalid_riff.wav", &wav).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep
            .anomalies
            .iter()
            .any(|a| a.contains("WAV RIFF declared size (2 bytes) is invalid")));
    }

    #[test]
    fn audit_wav_embedded_corrupted_decoy_container() {
        let num_samples = 2000;
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        let riff_size = 36 + (num_samples * 2) as u32;
        wav.extend_from_slice(&riff_size.to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&44100u32.to_le_bytes());
        wav.extend_from_slice(&(44100u32 * 2).to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        let data_size = (num_samples * 2) as u32;
        wav.extend_from_slice(&data_size.to_le_bytes());
        for i in 0..num_samples {
            let sample = ((i as f64 * 0.1).sin() * 8000.0) as i16;
            wav.extend_from_slice(&sample.to_le_bytes());
        }

        let primary = b"secret-hidden";
        let decoy = b"harmless-decoy";
        let mut sealed =
            crate::decoy::seal_decoy(primary, "pass1", decoy, "pass2", false, 0).unwrap();
        // Corrupt decoy body len
        sealed[34..38].copy_from_slice(&0x7FFFFFFF_u32.to_le_bytes());

        let stego_wav =
            crate::wav::embed_in_wav(&wav, &sealed, crate::wav::WavMode::Chunk).unwrap();
        let rep = audit_carrier_bytes("wav_corrupt_decoy.wav", &stego_wav).unwrap();
        assert_eq!(rep.verdict, CarrierVerdict::SuspiciousAnomaly);
        assert!(rep.anomalies.iter().any(|a| a.contains("layout anomaly")));
    }

    #[test]
    fn audit_passphrase_mixed_case_sequential_runs() {
        let rep_asc = audit_passphrase("AbCdEf999!");
        assert!(rep_asc.has_sequential);

        let rep_desc = audit_passphrase("ZyXwVu123!");
        assert!(rep_desc.has_sequential);
    }

    #[test]
    fn audit_passphrase_leetspeak_plus_for_t() {
        let rep = audit_passphrase("secre+123");
        assert!(rep.has_common_pattern);

        let rep_guest = audit_passphrase("gues+2026!");
        assert!(rep_guest.has_common_pattern);
    }

    #[test]
    fn audit_passphrase_extended_keyboard_walks() {
        let rep_plm = audit_passphrase("plm999!#");
        assert!(rep_plm.has_keyboard_walk);

        let rep_zero = audit_passphrase("0plm2026");
        assert!(rep_zero.has_keyboard_walk);
    }
}
