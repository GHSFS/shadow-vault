// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Reed-Solomon / Parity Error-Correcting Armor (`src/armor.rs`).
//!
//! Provides mathematically rigorous, production-grade error correction and ASCII armor:
//! - Cauchy MDS (Maximum Distance Separable) Reed-Solomon erasure coding over $\text{GF}(256)$
//!   using the standard Rijndael polynomial $P(x) = x^8 + x^4 + x^3 + x + 1$ ($\mathtt{0x11B}$).
//! - Generator matrix $[I_K; A]$ with Cauchy matrix entries $A_{i, j} = \frac{1}{(K + i) \oplus j}$.
//!   Because every submatrix of a Cauchy matrix is non-singular, ANY $K$ intact shards
//!   out of $K + M$ total stripes can reconstruct all $K$ original data shards.
//! - Gaussian elimination in $\text{GF}(256)$ with partial pivoting for exact matrix inversion.
//! - ASCII armored export/import format (`.svault.asc`) with per-stripe CRC-32 checksums,
//!   overall SHA-256 integrity binding, and 64-character line-wrapped Base64 encoding.
//! - Automated corruption detection, erasure isolation, and stripe repair (`repair_armored`).
//! - Proactive memory zeroization (`Zeroize` / `Zeroizing`) on secret payloads.

use crate::error::{Error, Result};
use crate::shamir::{gf_inv, gf_mul};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use crc32fast::Hasher as CrcHasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Standard header markers for ASCII armored ShadowVault files.
pub const ARMOR_HEADER_BEGIN: &str = "-----BEGIN SHADOW VAULT ARMORED FILE-----";
pub const ARMOR_HEADER_END: &str = "-----END SHADOW VAULT ARMORED FILE-----";

/// Accepted legacy or alternative begin markers for flexible interop.
const ALT_ARMOR_BEGINS: &[&str] = &[
    "-----BEGIN SHADOW VAULT ARMORED FILE-----",
    "-----BEGIN SHADOW VAULT ARMORED CONTAINER-----",
    "-----BEGIN SHADOW VAULT REED-SOLOMON ARMOR-----",
    "-----BEGIN SHADOW VAULT ARMOR-----",
];

const ALT_ARMOR_ENDS: &[&str] = &[
    "-----END SHADOW VAULT ARMORED FILE-----",
    "-----END SHADOW VAULT ARMORED CONTAINER-----",
    "-----END SHADOW VAULT REED-SOLOMON ARMOR-----",
    "-----END SHADOW VAULT ARMOR-----",
];

/// Status and metadata for an individual data or parity stripe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StripeInfo {
    /// Stripe index (0..data_stripes are data; >= data_stripes are parity).
    pub index: u8,
    /// Whether this stripe is parity.
    pub is_parity: bool,
    /// Expected CRC-32 checksum from the armor header.
    pub crc32: u32,
    /// Whether the stripe's payload is present, base64-valid, and matches its CRC-32.
    pub valid: bool,
    /// Byte length of the stripe payload.
    pub length: usize,
}

/// Metadata extracted during inspection of an armored file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmorMetadata {
    pub version: u8,
    pub mode: String,
    pub data_stripes: u8,
    pub parity_stripes: u8,
    pub original_length: usize,
    pub stripe_size: usize,
    pub payload_hash: String,
    pub stripes: Vec<StripeInfo>,
}

/// Diagnostic report generated when repairing an armored container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairReport {
    pub total_stripes: usize,
    pub data_stripes: usize,
    pub parity_stripes: usize,
    pub intact_stripes: usize,
    pub corrupted_stripes: usize,
    pub reconstructed_stripes: usize,
    pub success: bool,
    pub original_length: usize,
    pub payload_hash: String,
    pub message: String,
}

/// Compute the CRC-32 checksum of a byte slice.
#[inline]
pub fn compute_crc(data: &[u8]) -> u32 {
    let mut hasher = CrcHasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute the lowercase hex SHA-256 digest of a byte slice.
#[inline]
pub fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Quick check whether data begins with or contains a ShadowVault armor header.
pub fn is_armored(data: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(data) {
        let trimmed = text.trim_start().trim_start_matches('\u{feff}');
        ALT_ARMOR_BEGINS.iter().any(|&m| trimmed.contains(m))
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Cauchy MDS Matrix & Finite Field Erasure Coding
// ---------------------------------------------------------------------------

/// Construct an $M \times K$ Cauchy matrix over $\text{GF}(256)$ where $A_{i, j} = \frac{1}{(K + i) \oplus j}$.
///
/// Because $\{0, \dots, K-1\}$ and $\{K, \dots, K+M-1\}$ are disjoint subsets of $\text{GF}(256)$,
/// $(K + i) \oplus j \neq 0$ for all $i \in [0, M-1], j \in [0, K-1]$.
#[allow(clippy::needless_range_loop)]
pub fn build_cauchy_matrix(data_stripes: usize, parity_stripes: usize) -> Result<Vec<Vec<u8>>> {
    if data_stripes == 0 || parity_stripes == 0 {
        return Err(Error::Format(
            "stripe counts must be greater than zero".into(),
        ));
    }
    if data_stripes + parity_stripes > 256 {
        return Err(Error::Format(format!(
            "total stripes ({} + {}) exceeds GF(256) field capacity (256)",
            data_stripes, parity_stripes
        )));
    }

    let mut matrix = vec![vec![0u8; data_stripes]; parity_stripes];
    for i in 0..parity_stripes {
        let xi = (data_stripes + i) as u8;
        for j in 0..data_stripes {
            let yj = j as u8;
            let denom = xi ^ yj;
            matrix[i][j] = gf_inv(denom)?;
        }
    }
    Ok(matrix)
}

/// Invert an $N \times N$ matrix in $\text{GF}(256)$ using Gaussian elimination with partial pivoting.
#[allow(clippy::needless_range_loop)]
pub fn invert_matrix_gf256(matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let n = matrix.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    for row in matrix {
        if row.len() != n {
            return Err(Error::Crypto("matrix must be square for inversion".into()));
        }
    }

    // Augmented matrix [M | I] of dimension n x (2 * n)
    let mut aug = vec![vec![0u8; 2 * n]; n];
    for i in 0..n {
        for j in 0..n {
            aug[i][j] = matrix[i][j];
        }
        aug[i][n + i] = 1;
    }

    for col in 0..n {
        // Find pivot with non-zero entry
        let mut pivot_row = None;
        for r in col..n {
            if aug[r][col] != 0 {
                pivot_row = Some(r);
                break;
            }
        }
        let pivot_row = pivot_row.ok_or_else(|| {
            Error::Crypto(format!(
                "singular matrix in GF(256) Cauchy decoding at col {col}"
            ))
        })?;

        if pivot_row != col {
            aug.swap(col, pivot_row);
        }

        let pivot_val = aug[col][col];
        let inv_pivot = gf_inv(pivot_val)?;
        for c in col..(2 * n) {
            aug[col][c] = gf_mul(aug[col][c], inv_pivot);
        }

        for r in 0..n {
            if r != col {
                let factor = aug[r][col];
                if factor != 0 {
                    for c in col..(2 * n) {
                        let term = gf_mul(factor, aug[col][c]);
                        aug[r][c] ^= term;
                    }
                }
            }
        }
    }

    let mut inv = vec![vec![0u8; n]; n];
    for i in 0..n {
        for j in 0..n {
            inv[i][j] = aug[i][n + j];
        }
    }
    Ok(inv)
}

/// Generate $M$ Cauchy Reed-Solomon parity stripes from $K$ data shards of identical size.
pub fn generate_parity_stripes(
    data_shards: &[Vec<u8>],
    parity_count: usize,
) -> Result<Vec<Vec<u8>>> {
    let k = data_shards.len();
    if k == 0 || parity_count == 0 {
        return Ok(Vec::new());
    }
    let stripe_size = data_shards[0].len();
    for shard in data_shards {
        if shard.len() != stripe_size {
            return Err(Error::Format("inconsistent data shard sizes".into()));
        }
    }

    let cauchy = build_cauchy_matrix(k, parity_count)?;
    let mut parity_shards = vec![vec![0u8; stripe_size]; parity_count];

    for (i, row) in cauchy.iter().enumerate() {
        for (j, &coeff) in row.iter().enumerate() {
            if coeff == 0 {
                continue;
            }
            let data = &data_shards[j];
            let parity = &mut parity_shards[i];
            for b in 0..stripe_size {
                parity[b] ^= gf_mul(coeff, data[b]);
            }
        }
    }

    Ok(parity_shards)
}

/// Reconstruct $K$ original data shards from ANY $K$ intact shards (subset of data and/or parity shards).
pub fn reconstruct_data_shards(
    k: usize,
    m: usize,
    stripe_size: usize,
    intact_subset: &[(usize, &[u8])],
) -> Result<Vec<Vec<u8>>> {
    if intact_subset.len() != k {
        return Err(Error::Crypto(format!(
            "exact subset of {} shards required for reconstruction, provided {}",
            k,
            intact_subset.len()
        )));
    }

    // Fast path: if the subset contains exactly all data shards 0..k in order
    let all_data_intact = intact_subset
        .iter()
        .enumerate()
        .all(|(expected_idx, &(actual_idx, _))| expected_idx == actual_idx);
    if all_data_intact {
        return Ok(intact_subset.iter().map(|&(_, s)| s.to_vec()).collect());
    }

    let cauchy = build_cauchy_matrix(k, m)?;

    // Build the K x K submatrix G_sub corresponding to the selected shards
    let mut g_sub = vec![vec![0u8; k]; k];
    for (r, &(idx, _)) in intact_subset.iter().enumerate() {
        if idx < k {
            g_sub[r][idx] = 1;
        } else {
            let p_idx = idx - k;
            if p_idx >= cauchy.len() {
                return Err(Error::Format(format!(
                    "parity stripe index {} out of bounds (max parity index: {})",
                    idx,
                    k + m - 1
                )));
            }
            for c in 0..k {
                g_sub[r][c] = cauchy[p_idx][c];
            }
        }
    }

    // Invert G_sub in GF(256)
    let g_inv = invert_matrix_gf256(&g_sub)?;

    // Multiply G_inv by intact shard payloads
    let mut reconstructed = vec![vec![0u8; stripe_size]; k];
    for c in 0..k {
        for r in 0..k {
            let coeff = g_inv[c][r];
            if coeff == 0 {
                continue;
            }
            let shard_payload = intact_subset[r].1;
            for b in 0..stripe_size {
                reconstructed[c][b] ^= gf_mul(coeff, shard_payload[b]);
            }
        }
    }

    Ok(reconstructed)
}

// ---------------------------------------------------------------------------
// High-Level Armor, Dearmor & Repair Routines
// ---------------------------------------------------------------------------

/// Convert raw data or a `.svault` container into an error-correcting ASCII armored string.
///
/// Divides data into `data_stripes` blocks, generates `parity_stripes` Cauchy MDS recovery stripes,
/// computes CRC-32 checksums per stripe, and emits a structured `.svault.asc` document.
pub fn armor_data(data: &[u8], data_stripes: u8, parity_stripes: u8) -> Result<String> {
    if data_stripes == 0 {
        return Err(Error::Format("data_stripes must be at least 1".into()));
    }
    if parity_stripes == 0 {
        return Err(Error::Format("parity_stripes must be at least 1".into()));
    }
    let k = data_stripes as usize;
    let m = parity_stripes as usize;
    if k + m > 256 {
        return Err(Error::Format(format!(
            "total stripes ({k} + {m} = {}) exceeds GF(256) capacity 256",
            k + m
        )));
    }

    let payload_hash = compute_sha256_hex(data);
    let original_length = data.len();
    let stripe_size = if original_length == 0 {
        0
    } else {
        original_length.div_ceil(k)
    };

    // Partition data into K shards, padding last shard with zeros if needed
    let mut data_shards = Vec::with_capacity(k);
    for j in 0..k {
        let mut shard = vec![0u8; stripe_size];
        let start = j * stripe_size;
        if start < original_length {
            let end = (start + stripe_size).min(original_length);
            let slice_len = end - start;
            shard[..slice_len].copy_from_slice(&data[start..end]);
        }
        data_shards.push(shard);
    }

    // Generate M parity stripes
    let parity_shards = generate_parity_stripes(&data_shards, m)?;

    // Assemble stripe descriptors: (index, is_parity, crc32, payload)
    let mut stripes: Vec<(u8, bool, u32, &[u8])> = Vec::with_capacity(k + m);
    for (i, shard) in data_shards.iter().enumerate() {
        let crc = compute_crc(shard);
        stripes.push((i as u8, false, crc, shard.as_slice()));
    }
    for (i, shard) in parity_shards.iter().enumerate() {
        let crc = compute_crc(shard);
        stripes.push(((k + i) as u8, true, crc, shard.as_slice()));
    }

    // Render armored ASCII
    let mut out = String::new();
    out.push_str(ARMOR_HEADER_BEGIN);
    out.push('\n');
    out.push_str("Version: 1\n");
    out.push_str("Mode: Cauchy-RS-GF256\n");
    out.push_str(&format!("Data-Stripes: {data_stripes}\n"));
    out.push_str(&format!("Parity-Stripes: {parity_stripes}\n"));
    out.push_str(&format!("Original-Length: {original_length}\n"));
    out.push_str(&format!("Stripe-Size: {stripe_size}\n"));
    out.push_str(&format!("Payload-Hash: {payload_hash}\n"));
    out.push('\n');

    for (index, is_parity, crc32, payload) in &stripes {
        let type_label = if *is_parity {
            format!("PARITY {}", index.saturating_sub(data_stripes))
        } else {
            "DATA".to_string()
        };
        out.push_str(&format!(
            "=== STRIPE {} ({}) CRC32: {:08x} ===\n",
            index, type_label, crc32
        ));
        let b64 = BASE64.encode(payload);
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str(ARMOR_HEADER_END);
    out.push('\n');

    // Wipe sensitive intermediate data shards from memory
    for mut s in data_shards {
        s.zeroize();
    }

    Ok(out)
}

/// Parsed in-memory representation of an individual stripe from an armored document.
#[derive(Debug, Clone)]
struct ParsedStripe {
    index: u8,
    #[allow(dead_code)]
    is_parity: bool,
    #[allow(dead_code)]
    declared_crc: u32,
    payload: Option<Vec<u8>>,
    valid: bool,
}

/// Parse metadata and stripes from an armored text document without performing reconstruction.
fn parse_armored_internal(armored: &str) -> Result<(ArmorMetadata, Vec<ParsedStripe>)> {
    let trimmed = armored.trim_start().trim_start_matches('\u{feff}').trim();

    let begin_marker = ALT_ARMOR_BEGINS
        .iter()
        .find(|&&m| trimmed.contains(m))
        .ok_or_else(|| Error::Format("missing ASCII armor header marker".into()))?;

    let end_marker = ALT_ARMOR_ENDS
        .iter()
        .find(|&&m| trimmed.contains(m))
        .ok_or_else(|| Error::Format("missing ASCII armor footer marker".into()))?;

    let begin_pos = trimmed.find(begin_marker).unwrap() + begin_marker.len();
    let end_pos = trimmed.find(end_marker).unwrap();
    if end_pos <= begin_pos {
        return Err(Error::Format(
            "armored block has invalid header/footer order".into(),
        ));
    }
    let body = &trimmed[begin_pos..end_pos];

    let mut version = 1u8;
    let mut mode = "Cauchy-RS-GF256".to_string();
    let mut data_stripes: Option<u8> = None;
    let mut parity_stripes: Option<u8> = None;
    let mut original_length: Option<usize> = None;
    let mut stripe_size: Option<usize> = None;
    let mut payload_hash: Option<String> = None;

    // Split body into header section and stripe blocks
    let first_stripe_pos = body.find("=== STRIPE ");
    let (header_part, stripes_part) = match first_stripe_pos {
        Some(pos) => (&body[..pos], &body[pos..]),
        None => (body, ""),
    };

    for line in header_part.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim();
            match key.as_str() {
                "version" => {
                    if let Ok(ver) = val.parse::<u8>() {
                        version = ver;
                    }
                }
                "mode" => mode = val.to_string(),
                "data-stripes" | "datastripes" | "stripes" => {
                    data_stripes = val.parse::<u8>().ok();
                }
                "parity-stripes" | "paritystripes" | "parity" => {
                    parity_stripes = val.parse::<u8>().ok();
                }
                "original-length" | "originallength" | "length" => {
                    original_length = val.parse::<usize>().ok();
                }
                "stripe-size" | "stripesize" => {
                    stripe_size = val.parse::<usize>().ok();
                }
                "payload-hash" | "payloadhash" | "hash" | "sha256" => {
                    payload_hash = Some(val.to_lowercase());
                }
                _ => {}
            }
        }
    }

    let data_stripes = data_stripes
        .ok_or_else(|| Error::Format("missing 'Data-Stripes' header in armored file".into()))?;
    let parity_stripes = parity_stripes
        .ok_or_else(|| Error::Format("missing 'Parity-Stripes' header in armored file".into()))?;
    let original_length = original_length
        .ok_or_else(|| Error::Format("missing 'Original-Length' header in armored file".into()))?;
    let stripe_size = stripe_size.unwrap_or(if original_length == 0 {
        0
    } else {
        original_length.div_ceil(data_stripes as usize)
    });
    let payload_hash = payload_hash
        .ok_or_else(|| Error::Format("missing 'Payload-Hash' header in armored file".into()))?;

    // Parse stripes
    let mut parsed_stripes = Vec::new();
    let mut stripe_infos = Vec::new();

    if !stripes_part.is_empty() {
        // Split by "=== STRIPE " delimiter
        let sections = stripes_part.split("=== STRIPE ");
        for sec in sections {
            let sec = sec.trim();
            if sec.is_empty() {
                continue;
            }
            // First line contains e.g. "0 (DATA) CRC32: 3a2f1b0c ==="
            let (header_line, b64_body) = match sec.split_once('\n') {
                Some((h, b)) => (h.trim(), b),
                None => (sec.trim(), ""),
            };

            // Parse index
            let header_clean = header_line.trim_end_matches('=').trim();
            let mut parts = header_clean.split_whitespace();
            let idx_str = parts.next().unwrap_or("0");
            let index = idx_str.parse::<u8>().unwrap_or(0);
            let is_parity = index >= data_stripes || header_clean.to_uppercase().contains("PARITY");

            // Extract CRC32
            let mut declared_crc = 0u32;
            if let Some(crc_idx) = header_clean.to_uppercase().find("CRC32:") {
                let crc_str = &header_clean[crc_idx + 6..].trim();
                let hex_token = crc_str.split_whitespace().next().unwrap_or("");
                if let Ok(c) = u32::from_str_radix(hex_token, 16) {
                    declared_crc = c;
                }
            }

            // Extract clean base64 payload
            let b64_clean: String = b64_body.chars().filter(|c| !c.is_whitespace()).collect();
            let decoded = BASE64.decode(b64_clean.as_bytes());

            let mut valid = false;
            let mut payload = None;
            let mut len = 0usize;

            if let Ok(bytes) = decoded {
                let actual_crc = compute_crc(&bytes);
                len = bytes.len();
                if actual_crc == declared_crc && (stripe_size == 0 || bytes.len() == stripe_size) {
                    valid = true;
                    payload = Some(bytes);
                }
            }

            parsed_stripes.push(ParsedStripe {
                index,
                is_parity,
                declared_crc,
                payload,
                valid,
            });

            stripe_infos.push(StripeInfo {
                index,
                is_parity,
                crc32: declared_crc,
                valid,
                length: len,
            });
        }
    }

    // Sort stripes by index
    parsed_stripes.sort_by_key(|s| s.index);
    stripe_infos.sort_by_key(|s| s.index);

    let meta = ArmorMetadata {
        version,
        mode,
        data_stripes,
        parity_stripes,
        original_length,
        stripe_size,
        payload_hash,
        stripes: stripe_infos,
    };

    Ok((meta, parsed_stripes))
}

/// Inspect an armored file and return diagnostic information on all data and parity stripes.
pub fn inspect_armor(armored: &str) -> Result<ArmorMetadata> {
    let (meta, _) = parse_armored_internal(armored)?;
    Ok(meta)
}

/// Decode and reconstruct an ASCII armored file back to its original binary content.
///
/// If any data stripes were corrupted or erased in transit, Cauchy Reed-Solomon parity stripes
/// are used to reconstruct the erased blocks in $\text{GF}(256)$.
pub fn dearmor_data(armored: &str) -> Result<Zeroizing<Vec<u8>>> {
    let (meta, parsed_stripes) = parse_armored_internal(armored)?;
    let k = meta.data_stripes as usize;
    let m = meta.parity_stripes as usize;

    if meta.original_length == 0 {
        let expected = compute_sha256_hex(&[]);
        if meta.payload_hash != expected {
            return Err(Error::Crypto(format!(
                "payload hash mismatch: declared {}, actual {}",
                meta.payload_hash, expected
            )));
        }
        return Ok(Zeroizing::new(Vec::new()));
    }

    // Check if all data stripes 0..k are intact
    let mut data_shards_direct = Vec::with_capacity(k);
    let mut all_data_intact = true;
    for j in 0..k {
        if let Some(s) = parsed_stripes
            .iter()
            .find(|s| s.index == j as u8 && s.valid)
        {
            data_shards_direct.push(s.payload.as_ref().unwrap().clone());
        } else {
            all_data_intact = false;
            break;
        }
    }

    let reconstructed_data_shards = if all_data_intact {
        data_shards_direct
    } else {
        // Collect all intact stripes (both data and parity)
        let mut intact_subset = Vec::new();
        for s in &parsed_stripes {
            if s.valid {
                if let Some(ref p) = s.payload {
                    intact_subset.push((s.index as usize, p.as_slice()));
                    if intact_subset.len() == k {
                        break;
                    }
                }
            }
        }

        if intact_subset.len() < k {
            return Err(Error::Format(format!(
                "unrecoverable corruption: only {} intact stripes found, minimum {} required (total stripes: {})",
                intact_subset.len(),
                k,
                k + m
            )));
        }

        reconstruct_data_shards(k, m, meta.stripe_size, &intact_subset)?
    };

    // Concatenate reconstructed data shards and truncate to original length
    let mut recovered = Vec::with_capacity(k * meta.stripe_size);
    for shard in &reconstructed_data_shards {
        recovered.extend_from_slice(shard);
    }
    recovered.truncate(meta.original_length);

    // Verify cryptographic SHA-256 integrity
    let actual_hash = compute_sha256_hex(&recovered);
    if actual_hash != meta.payload_hash {
        recovered.zeroize();
        return Err(Error::Crypto(format!(
            "payload SHA-256 hash mismatch after Reed-Solomon reconstruction (expected: {}, actual: {})",
            meta.payload_hash, actual_hash
        )));
    }

    Ok(Zeroizing::new(recovered))
}

/// Inspect, repair, and re-emit a corrupted armored document with refreshed parity stripes.
///
/// Returns: `(repaired_armored_text, reconstructed_raw_payload, repair_report)`.
pub fn repair_armored(armored: &str) -> Result<(String, Zeroizing<Vec<u8>>, RepairReport)> {
    let (meta, parsed_stripes) = parse_armored_internal(armored)?;
    let k = meta.data_stripes as usize;
    let m = meta.parity_stripes as usize;
    let total_stripes = k + m;

    let intact_count = parsed_stripes.iter().filter(|s| s.valid).count();
    let corrupted_count = total_stripes.saturating_sub(intact_count);

    if intact_count < k {
        return Err(Error::Format(format!(
            "repair failed: only {} intact stripes available out of {} (requires at least {} data stripes)",
            intact_count, total_stripes, k
        )));
    }

    // Reconstruct data shards
    let mut intact_subset = Vec::new();
    for s in &parsed_stripes {
        if s.valid {
            if let Some(ref p) = s.payload {
                intact_subset.push((s.index as usize, p.as_slice()));
                if intact_subset.len() == k {
                    break;
                }
            }
        }
    }

    let reconstructed_data_shards = if meta.original_length == 0 {
        vec![vec![]; k]
    } else {
        reconstruct_data_shards(k, m, meta.stripe_size, &intact_subset)?
    };

    // Reconstruct payload and check hash
    let mut recovered = Vec::with_capacity(k * meta.stripe_size);
    for shard in &reconstructed_data_shards {
        recovered.extend_from_slice(shard);
    }
    recovered.truncate(meta.original_length);

    let actual_hash = compute_sha256_hex(&recovered);
    if actual_hash != meta.payload_hash {
        recovered.zeroize();
        return Err(Error::Crypto(format!(
            "repair failed: reconstructed payload hash mismatch (expected {}, got {})",
            meta.payload_hash, actual_hash
        )));
    }

    // Re-generate refreshed armored text with all pristine stripes
    let repaired_armored = armor_data(&recovered, meta.data_stripes, meta.parity_stripes)?;

    let reconstructed_stripes = corrupted_count;
    let report = RepairReport {
        total_stripes,
        data_stripes: k,
        parity_stripes: m,
        intact_stripes: intact_count,
        corrupted_stripes: corrupted_count,
        reconstructed_stripes,
        success: true,
        original_length: meta.original_length,
        payload_hash: meta.payload_hash,
        message: format!(
            "Successfully repaired container: {}/{} stripes restored via Cauchy MDS Reed-Solomon",
            reconstructed_stripes, total_stripes
        ),
    };

    Ok((repaired_armored, Zeroizing::new(recovered), report))
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::needless_range_loop, clippy::manual_div_ceil)]
mod tests {
    use super::*;

    #[test]
    fn test_cauchy_matrix_construction_and_elements_non_zero() {
        let k = 4;
        let m = 2;
        let cauchy = build_cauchy_matrix(k, m).unwrap();
        assert_eq!(cauchy.len(), m);
        assert_eq!(cauchy[0].len(), k);

        for row in &cauchy {
            for &val in row {
                assert_ne!(val, 0, "Cauchy matrix entries must be strictly non-zero");
            }
        }
    }

    #[test]
    fn test_invert_matrix_gf256_identity_and_properties() {
        let id2 = vec![vec![1u8, 0], vec![0, 1u8]];
        let inv2 = invert_matrix_gf256(&id2).unwrap();
        assert_eq!(inv2, id2);

        // 3x3 invertible test matrix in GF(256)
        let m = vec![vec![2u8, 3, 1], vec![1, 1, 0], vec![0, 4, 5]];
        let inv = invert_matrix_gf256(&m).unwrap();

        // Check m * inv == I_3
        for i in 0..3 {
            for j in 0..3 {
                let mut sum = 0u8;
                for k in 0..3 {
                    sum ^= gf_mul(m[i][k], inv[k][j]);
                }
                let expected = if i == j { 1 } else { 0 };
                assert_eq!(
                    sum, expected,
                    "Matrix inversion product mismatch at ({i}, {j})"
                );
            }
        }
    }

    #[test]
    fn test_cauchy_mds_all_submatrices_invertible() {
        // For K=3, M=2 (total 5 stripes), any 3 rows out of the [I_3; A] generator
        // matrix MUST be non-singular.
        let k = 3;
        let m = 2;
        let cauchy = build_cauchy_matrix(k, m).unwrap();

        let mut gen = vec![vec![0u8; k]; k + m];
        for i in 0..k {
            gen[i][i] = 1;
        }
        for i in 0..m {
            for j in 0..k {
                gen[k + i][j] = cauchy[i][j];
            }
        }

        // Test all C(5, 3) = 10 combinations of 3 rows
        let total = k + m;
        let mut count = 0;
        for r0 in 0..total {
            for r1 in (r0 + 1)..total {
                for r2 in (r1 + 1)..total {
                    let sub = vec![gen[r0].clone(), gen[r1].clone(), gen[r2].clone()];
                    let inv = invert_matrix_gf256(&sub);
                    assert!(
                        inv.is_ok(),
                        "Submatrix for rows ({r0}, {r1}, {r2}) must be invertible"
                    );
                    count += 1;
                }
            }
        }
        assert_eq!(count, 10);
    }

    #[test]
    fn test_parity_generation_and_single_erasure_recovery() {
        let secret_data = b"ShadowVault zero-trust hardware-bound encrypted storage";
        let k = 4;
        let m = 2;
        let stripe_size = (secret_data.len() + k - 1) / k;

        let mut data_shards = Vec::new();
        for j in 0..k {
            let mut shard = vec![0u8; stripe_size];
            let start = j * stripe_size;
            let end = (start + stripe_size).min(secret_data.len());
            shard[..(end - start)].copy_from_slice(&secret_data[start..end]);
            data_shards.push(shard);
        }

        let parity_shards = generate_parity_stripes(&data_shards, m).unwrap();
        assert_eq!(parity_shards.len(), m);

        // Erase data shard #1, replace with parity shard #0 (index = k = 4)
        let subset: Vec<(usize, &[u8])> = vec![
            (0, &data_shards[0]),
            (2, &data_shards[2]),
            (3, &data_shards[3]),
            (4, &parity_shards[0]),
        ];

        let reconstructed = reconstruct_data_shards(k, m, stripe_size, &subset).unwrap();
        assert_eq!(reconstructed, data_shards);
    }

    #[test]
    fn test_multiple_erasures_recovery_up_to_parity_capacity() {
        let secret = b"Maximum Distance Separable Reed-Solomon test vector 2026!";
        let k = 4;
        let m = 3;
        let stripe_size = (secret.len() + k - 1) / k;

        let mut data_shards = Vec::new();
        for j in 0..k {
            let mut shard = vec![0u8; stripe_size];
            let start = j * stripe_size;
            let end = (start + stripe_size).min(secret.len());
            shard[..(end - start)].copy_from_slice(&secret[start..end]);
            data_shards.push(shard);
        }

        let parity_shards = generate_parity_stripes(&data_shards, m).unwrap();

        // Erase 3 data shards (0, 1, 2) and recover using 1 data shard (3) and 3 parity shards (4, 5, 6)
        let subset: Vec<(usize, &[u8])> = vec![
            (3, &data_shards[3]),
            (4, &parity_shards[0]),
            (5, &parity_shards[1]),
            (6, &parity_shards[2]),
        ];

        let reconstructed = reconstruct_data_shards(k, m, stripe_size, &subset).unwrap();
        assert_eq!(reconstructed, data_shards);
    }

    #[test]
    fn test_armor_dearmor_roundtrip_clean() {
        let original = b"Top secret operational keys bound to Windows DPAPI and Argon2id KDF.";
        let armored = armor_data(original, 4, 2).unwrap();

        assert!(armored.contains(ARMOR_HEADER_BEGIN));
        assert!(armored.contains(ARMOR_HEADER_END));
        assert!(armored.contains("Data-Stripes: 4"));
        assert!(armored.contains("Parity-Stripes: 2"));

        let meta = inspect_armor(&armored).unwrap();
        assert_eq!(meta.data_stripes, 4);
        assert_eq!(meta.parity_stripes, 2);
        assert_eq!(meta.original_length, original.len());
        assert_eq!(meta.stripes.len(), 6);
        assert!(meta.stripes.iter().all(|s| s.valid));

        let recovered = dearmor_data(&armored).unwrap();
        assert_eq!(&*recovered, original);
    }

    #[test]
    fn test_armor_dearmor_empty_payload() {
        let empty = b"";
        let armored = armor_data(empty, 3, 2).unwrap();
        let recovered = dearmor_data(&armored).unwrap();
        assert_eq!(&*recovered, empty);
    }

    #[test]
    fn test_armor_dearmor_single_byte_payload() {
        let single = b"X";
        let armored = armor_data(single, 2, 2).unwrap();
        let recovered = dearmor_data(&armored).unwrap();
        assert_eq!(&*recovered, single);
    }

    #[test]
    fn test_dearmor_auto_recovers_from_corrupted_data_stripe() {
        let original = b"Corrupted stripe recovery test in ShadowVault ASCII armor!";
        let armored = armor_data(original, 4, 2).unwrap();

        // Tamper with Stripe 1 by altering characters in its payload
        let mut corrupted = String::new();
        let mut in_stripe_1 = false;
        for line in armored.lines() {
            if line.contains("=== STRIPE 1 (DATA)") {
                in_stripe_1 = true;
                corrupted.push_str(line);
                corrupted.push('\n');
            } else if in_stripe_1 && line.starts_with("=== STRIPE") {
                in_stripe_1 = false;
                corrupted.push_str(line);
                corrupted.push('\n');
            } else if in_stripe_1 && !line.is_empty() {
                // Invert characters in base64
                corrupted.push_str("ZZZZ9999AAAA\n");
            } else {
                corrupted.push_str(line);
                corrupted.push('\n');
            }
        }

        // Inspection must detect Stripe 1 is invalid
        let meta = inspect_armor(&corrupted).unwrap();
        assert!(!meta.stripes[1].valid);
        assert!(meta.stripes[0].valid);
        assert!(meta.stripes[2].valid);
        assert!(meta.stripes[3].valid);

        // Dearmor must transparently reconstruct the corrupted data shard via RS parity
        let recovered = dearmor_data(&corrupted).unwrap();
        assert_eq!(&*recovered, original);
    }

    #[test]
    fn test_repair_armored_restores_corrupted_document() {
        let original = b"Robust self-healing vault container error correction demo!";
        let armored = armor_data(original, 4, 2).unwrap();

        // Corrupt stripe 2 by replacing its payload lines with garbage
        let mut corrupted = String::new();
        let mut in_stripe_2 = false;
        for line in armored.lines() {
            if line.contains("=== STRIPE 2 (DATA)") {
                in_stripe_2 = true;
                corrupted.push_str(line);
                corrupted.push('\n');
            } else if in_stripe_2 && line.starts_with("=== STRIPE") {
                in_stripe_2 = false;
                corrupted.push_str(line);
                corrupted.push('\n');
            } else if in_stripe_2 && !line.is_empty() {
                corrupted.push_str("INVALID_BASE64_GARBAGE\n");
            } else {
                corrupted.push_str(line);
                corrupted.push('\n');
            }
        }

        let (repaired, recovered, report) = repair_armored(&corrupted).unwrap();
        assert!(report.success);
        assert_eq!(report.corrupted_stripes, 1);
        assert_eq!(report.reconstructed_stripes, 1);
        assert_eq!(&*recovered, original);

        // Repaired armored string must now be 100% valid
        let meta_repaired = inspect_armor(&repaired).unwrap();
        assert!(meta_repaired.stripes.iter().all(|s| s.valid));

        let recovered_from_repaired = dearmor_data(&repaired).unwrap();
        assert_eq!(&*recovered_from_repaired, original);
    }

    #[test]
    fn test_excessive_corruption_fails_dearmor() {
        let original = b"Too many corrupted stripes must trigger unrecoverable error.";
        let armored = armor_data(original, 4, 2).unwrap();

        // Corrupt 3 stripes (stripes 0, 1, and 2), leaving only 3 intact (need 4)
        let mut corrupted = String::new();
        let mut in_bad_stripe = false;
        for line in armored.lines() {
            if line.contains("=== STRIPE 0 ")
                || line.contains("=== STRIPE 1 ")
                || line.contains("=== STRIPE 2 ")
            {
                in_bad_stripe = true;
                corrupted.push_str(line);
                corrupted.push('\n');
            } else if in_bad_stripe && line.starts_with("=== STRIPE") {
                in_bad_stripe = false;
                corrupted.push_str(line);
                corrupted.push('\n');
            } else if in_bad_stripe && !line.is_empty() {
                corrupted.push_str("BADBADBAD\n");
            } else {
                corrupted.push_str(line);
                corrupted.push('\n');
            }
        }

        let res = dearmor_data(&corrupted);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("unrecoverable corruption"));
    }
}
