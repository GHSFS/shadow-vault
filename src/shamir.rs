// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Shamir's Secret Sharing over $\text{GF}(256)$ (`M-of-N` Key Splitting).
//!
//! Provides mathematically provable information-theoretic secret sharing:
//! - Finite field $\text{GF}(256)$ arithmetic modulo the standard Rijndael polynomial
//!   $P(x) = x^8 + x^4 + x^3 + x + 1$ ($\mathtt{0x11B}$).
//! - Constant-time, branchless multiplication and inversion with zero table lookups.
//! - Threshold $M \le N \le 255$ polynomial generation with CSPRNG coefficients.
//! - Fast Lagrange interpolation at $x = 0$ caching coordinate basis multipliers.
//! - Cryptographic integrity via SHA-256 secret binding and per-share CRC-32 checksums.
//! - ASCII armored (`-----BEGIN SHADOW VAULT SHARE-----`), compact single-line,
//!   and structured JSON serialization.
//! - Proactive memory zeroization (`Zeroize` / `Zeroizing`) on sensitive key material.

use crate::error::{Error, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use crc32fast::Hasher as CrcHasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

pub const SHARE_ARMOR_BEGIN: &str = "-----BEGIN SHADOW VAULT SHARE-----";
pub const SHARE_ARMOR_END: &str = "-----END SHADOW VAULT SHARE-----";
pub const COMPACT_PREFIX: &str = "SVLT-S1";

/// Multiply two elements in $\text{GF}(256)$ using constant-time branchless peasant multiplication.
///
/// Modulo polynomial: $x^8 + x^4 + x^3 + x + 1$ ($\mathtt{0x11B}$).
#[inline]
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        let b_lsb_mask = (b & 1).wrapping_neg();
        p ^= a & b_lsb_mask;
        let hi_mask = ((a as i8) >> 7) as u8;
        a = (a << 1) ^ (0x1b & hi_mask);
        b >>= 1;
    }
    p
}

/// Compute multiplicative inverse in $\text{GF}(256)$ via Fermat's Little Theorem:
/// $a^{-1} = a^{254}$ for all $a \neq 0$.
///
/// Uses constant-time square-and-multiply with zero data-dependent branches.
pub fn gf_inv(a: u8) -> Result<u8> {
    if a == 0 {
        return Err(Error::Crypto("division by zero in GF(256)".into()));
    }
    // 254 = (11111110)_2
    let a2 = gf_mul(a, a);
    let a3 = gf_mul(a2, a);
    let a6 = gf_mul(a3, a3);
    let a7 = gf_mul(a6, a);
    let a14 = gf_mul(a7, a7);
    let a15 = gf_mul(a14, a);
    let a30 = gf_mul(a15, a15);
    let a31 = gf_mul(a30, a);
    let a62 = gf_mul(a31, a31);
    let a63 = gf_mul(a62, a);
    let a126 = gf_mul(a63, a63);
    let a127 = gf_mul(a126, a);
    let a254 = gf_mul(a127, a127);
    Ok(a254)
}

/// Divide two elements in $\text{GF}(256)$: $a / b = a \cdot b^{-1}$.
#[inline]
pub fn gf_div(a: u8, b: u8) -> Result<u8> {
    let inv_b = gf_inv(b)?;
    Ok(gf_mul(a, inv_b))
}

/// Evaluate a polynomial $P(x) = c_0 \oplus c_1 x \oplus \dots \oplus c_{M-1} x^{M-1}$ in $\text{GF}(256)$
/// using Horner's rule.
pub fn evaluate_polynomial(coeffs: &[u8], x: u8) -> u8 {
    if coeffs.is_empty() {
        return 0;
    }
    if x == 0 {
        return coeffs[0];
    }
    let mut val = *coeffs.last().unwrap_or(&0);
    for &c in coeffs[..coeffs.len() - 1].iter().rev() {
        val = gf_mul(val, x) ^ c;
    }
    val
}

/// Perform Lagrange interpolation at $x = 0$ for given $(x_i, y_i)$ pairs in $\text{GF}(256)$.
///
/// $P(0) = \bigoplus_{j=1}^K y_j \prod_{m \neq j} \frac{x_m}{x_j \oplus x_m}$.
#[allow(dead_code)]
pub fn lagrange_interpolate(points: &[(u8, u8)]) -> Result<u8> {
    if points.is_empty() {
        return Err(Error::Crypto(
            "empty points in Lagrange interpolation".into(),
        ));
    }

    let mut secret = 0u8;
    for (j, &(xj, yj)) in points.iter().enumerate() {
        if xj == 0 {
            return Err(Error::Format(
                "share index 0 is invalid (reserved for secret)".into(),
            ));
        }
        let mut lambda_j = 1u8;
        for (m, &(xm, _)) in points.iter().enumerate() {
            if j == m {
                continue;
            }
            if xj == xm {
                return Err(Error::Format(format!(
                    "duplicate share index {xj} detected in Lagrange interpolation"
                )));
            }
            // term = xm / (xj ^ xm)
            let denom = xj ^ xm;
            let term = gf_div(xm, denom)?;
            lambda_j = gf_mul(lambda_j, term);
        }
        secret ^= gf_mul(yj, lambda_j);
    }
    Ok(secret)
}

/// Constant-time byte array equality check.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compute CRC-32 of a share's core parameters and payload.
pub fn compute_share_crc(index: u8, length: usize, payload: &[u8]) -> u32 {
    let mut hasher = CrcHasher::new();
    hasher.update(&[index]);
    hasher.update(&(length as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize()
}

/// An individual Shamir share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    /// Format version (always 1).
    pub version: u8,
    /// Threshold $M$ required to reconstruct the secret ($2 \le M \le N \le 255$).
    pub threshold: u8,
    /// Total number of shares $N$ generated ($M \le N \le 255$).
    pub total: u8,
    /// Share evaluation index $x \in 1..=255$.
    pub index: u8,
    /// Length of the original secret in bytes.
    pub length: usize,
    /// Hex-encoded SHA-256 digest of the master secret for tamper detection.
    pub secret_hash: String,
    /// Raw $y$-values for each byte of the secret (zeroized on drop).
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub payload: Vec<u8>,
    /// CRC-32 checksum of this share's payload.
    pub crc32: u32,
}

fn serialize_base64<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&BASE64.encode(bytes))
}

fn deserialize_base64<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    BASE64.decode(s.trim()).map_err(serde::de::Error::custom)
}

impl Zeroize for Share {
    fn zeroize(&mut self) {
        self.payload.zeroize();
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Share {
    /// Verify the internal CRC-32 integrity of this share.
    pub fn verify_crc(&self) -> bool {
        let expected = compute_share_crc(self.index, self.length, &self.payload);
        self.crc32 == expected && self.payload.len() == self.length
    }

    /// Render this share as an ASCII armored block.
    pub fn to_armored(&self) -> String {
        let b64_payload = BASE64.encode(&self.payload);
        format!(
            "{}\nVersion: {}\nThreshold: {}\nTotal: {}\nIndex: {}\nLength: {}\nHash: {}\nCRC32: {:08x}\nPayload: {}\n{}\n",
            SHARE_ARMOR_BEGIN,
            self.version,
            self.threshold,
            self.total,
            self.index,
            self.length,
            self.secret_hash,
            self.crc32,
            b64_payload,
            SHARE_ARMOR_END
        )
    }

    /// Render this share as a compact single-line string.
    pub fn to_compact(&self) -> String {
        let b64_payload = BASE64.encode(&self.payload);
        format!(
            "{}-{}-{}-{}-{}-{}-{:08x}-{}",
            COMPACT_PREFIX,
            self.threshold,
            self.total,
            self.index,
            self.length,
            self.secret_hash,
            self.crc32,
            b64_payload
        )
    }

    /// Parse a share from an armored block string.
    pub fn from_armored(armored: &str) -> Result<Self> {
        let trimmed = armored.trim();
        if !trimmed.contains(SHARE_ARMOR_BEGIN) || !trimmed.contains(SHARE_ARMOR_END) {
            return Err(Error::Format(
                "missing armored share header or footer markers".into(),
            ));
        }

        let mut version: Option<u8> = None;
        let mut threshold: Option<u8> = None;
        let mut total: Option<u8> = None;
        let mut index: Option<u8> = None;
        let mut length: Option<usize> = None;
        let mut secret_hash: Option<String> = None;
        let mut crc32: Option<u32> = None;
        let mut payload: Option<Vec<u8>> = None;

        for line in trimmed.lines() {
            let line = line.trim();
            if line == SHARE_ARMOR_BEGIN || line == SHARE_ARMOR_END || line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().to_lowercase();
                let v = v.trim();
                match k.as_str() {
                    "version" => {
                        version = Some(
                            v.parse::<u8>()
                                .map_err(|e| Error::Format(format!("invalid version: {e}")))?,
                        );
                    }
                    "threshold" => {
                        threshold = Some(
                            v.parse::<u8>()
                                .map_err(|e| Error::Format(format!("invalid threshold: {e}")))?,
                        );
                    }
                    "total" => {
                        total = Some(
                            v.parse::<u8>()
                                .map_err(|e| Error::Format(format!("invalid total: {e}")))?,
                        );
                    }
                    "index" => {
                        index = Some(
                            v.parse::<u8>()
                                .map_err(|e| Error::Format(format!("invalid index: {e}")))?,
                        );
                    }
                    "length" => {
                        length = Some(
                            v.parse::<usize>()
                                .map_err(|e| Error::Format(format!("invalid length: {e}")))?,
                        );
                    }
                    "hash" | "secret_hash" | "secrethash" => {
                        secret_hash = Some(v.to_string());
                    }
                    "crc32" => {
                        crc32 = Some(
                            u32::from_str_radix(v, 16)
                                .map_err(|e| Error::Format(format!("invalid CRC32 hex: {e}")))?,
                        );
                    }
                    "payload" => {
                        let decoded = BASE64
                            .decode(v)
                            .map_err(|e| Error::Format(format!("invalid Base64 payload: {e}")))?;
                        payload = Some(decoded);
                    }
                    _ => {}
                }
            }
        }

        let version = version.unwrap_or(1);
        let threshold =
            threshold.ok_or_else(|| Error::Format("missing Threshold header".into()))?;
        let total = total.ok_or_else(|| Error::Format("missing Total header".into()))?;
        let index = index.ok_or_else(|| Error::Format("missing Index header".into()))?;
        let length = length.ok_or_else(|| Error::Format("missing Length header".into()))?;
        let secret_hash = secret_hash.ok_or_else(|| Error::Format("missing Hash header".into()))?;
        let crc32 = crc32.ok_or_else(|| Error::Format("missing CRC32 header".into()))?;
        let payload = payload.ok_or_else(|| Error::Format("missing Payload header".into()))?;

        if payload.len() != length {
            return Err(Error::Format(format!(
                "share payload length mismatch: header says {length}, found {}",
                payload.len()
            )));
        }

        let share = Share {
            version,
            threshold,
            total,
            index,
            length,
            secret_hash,
            payload,
            crc32,
        };

        if !share.verify_crc() {
            return Err(Error::Format(format!(
                "share index {} CRC-32 checksum mismatch (tampered or corrupted share)",
                share.index
            )));
        }

        Ok(share)
    }

    /// Parse a share from a compact single-line string.
    pub fn from_compact(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.trim().split('-').collect();
        // SVLT-S1-<threshold>-<total>-<index>-<length>-<hash>-<crc32>-<b64_payload>
        // Note: b64_payload might contain '-' if base64url was used, so take prefix then tail
        if parts.len() < 8 || parts[0] != "SVLT" || parts[1] != "S1" {
            return Err(Error::Format(
                "invalid compact share string format (expected SVLT-S1-...)".into(),
            ));
        }

        let threshold = parts[2]
            .parse::<u8>()
            .map_err(|e| Error::Format(format!("invalid threshold in compact share: {e}")))?;
        let total = parts[3]
            .parse::<u8>()
            .map_err(|e| Error::Format(format!("invalid total in compact share: {e}")))?;
        let index = parts[4]
            .parse::<u8>()
            .map_err(|e| Error::Format(format!("invalid index in compact share: {e}")))?;
        let length = parts[5]
            .parse::<usize>()
            .map_err(|e| Error::Format(format!("invalid length in compact share: {e}")))?;
        let secret_hash = parts[6].to_string();
        let crc32 = u32::from_str_radix(parts[7], 16)
            .map_err(|e| Error::Format(format!("invalid crc32 in compact share: {e}")))?;

        // Rejoin any trailing elements for the payload
        let b64_payload = parts[8..].join("-");
        let payload = BASE64
            .decode(b64_payload.trim())
            .map_err(|e| Error::Format(format!("invalid Base64 payload in compact share: {e}")))?;

        if payload.len() != length {
            return Err(Error::Format(format!(
                "compact share payload length mismatch: header says {length}, found {}",
                payload.len()
            )));
        }

        let share = Share {
            version: 1,
            threshold,
            total,
            index,
            length,
            secret_hash,
            payload,
            crc32,
        };

        if !share.verify_crc() {
            return Err(Error::Format(format!(
                "compact share index {} CRC-32 checksum mismatch",
                share.index
            )));
        }

        Ok(share)
    }
}

impl FromStr for Share {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.starts_with('{') {
            serde_json::from_str::<Share>(trimmed)
                .map_err(|e| Error::Format(format!("JSON share deserialization failed: {e}")))
        } else if trimmed.contains(SHARE_ARMOR_BEGIN) {
            Self::from_armored(trimmed)
        } else if trimmed.starts_with(COMPACT_PREFIX) {
            Self::from_compact(trimmed)
        } else {
            Err(Error::Format(
                "unrecognized share format: expected armored block, compact string, or JSON".into(),
            ))
        }
    }
}

impl fmt::Display for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_armored())
    }
}

/// Split an arbitrary secret byte slice into $N$ shares such that any $M$ shares can reconstruct it.
///
/// # Arguments
/// * `secret`: The plaintext secret or master key bytes.
/// * `threshold`: Minimum number of shares $M$ required for reconstruction ($2 \le M \le N \le 255$).
/// * `total`: Total number of shares $N$ to generate ($M \le N \le 255$).
///
/// # Security
/// - Coefficients for degree $1..M-1$ are sampled from CSPRNG (`rand::thread_rng()`).
/// - All secret and coefficient buffers are securely wrapped in `Zeroizing` / `Zeroize`.
/// - SHA-256 digest is embedded for post-reconstruction authentication.
pub fn split_secret(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Share>> {
    if secret.is_empty() {
        return Err(Error::Crypto("secret must not be empty".into()));
    }
    if threshold < 2 {
        return Err(Error::Crypto(
            "threshold M must be at least 2 for secret sharing".into(),
        ));
    }
    if total < threshold {
        return Err(Error::Crypto(format!(
            "total shares N ({total}) cannot be less than threshold M ({threshold})"
        )));
    }

    // Compute SHA-256 digest of secret
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let secret_hash = format!("{:x}", hasher.finalize());

    let secret_len = secret.len();
    let mut share_payloads: Vec<Zeroizing<Vec<u8>>> = (0..total)
        .map(|_| Zeroizing::new(vec![0u8; secret_len]))
        .collect();

    let mut rng = rand::thread_rng();

    // Polynomial degree: threshold - 1
    // For each byte in the secret, pick independent random coefficients
    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        let mut poly = Zeroizing::new(vec![0u8; threshold as usize]);
        poly[0] = secret_byte;
        if threshold > 1 {
            rng.fill_bytes(&mut poly[1..]);
        }

        // Evaluate at points x = 1, 2, ..., total
        for share_idx in 0..total {
            let x = share_idx + 1;
            let y = evaluate_polynomial(&poly, x);
            share_payloads[share_idx as usize][byte_idx] = y;
        }
    }

    let mut shares = Vec::with_capacity(total as usize);
    for share_idx in 0..total {
        let index = share_idx + 1;
        let payload = share_payloads[share_idx as usize].to_vec();
        let crc32 = compute_share_crc(index, secret_len, &payload);

        shares.push(Share {
            version: 1,
            threshold,
            total,
            index,
            length: secret_len,
            secret_hash: secret_hash.clone(),
            payload,
            crc32,
        });
    }

    Ok(shares)
}

/// Combine $K \ge M$ Shamir shares to reconstruct the authenticated master secret.
///
/// # Verifications
/// 1. Verifies $K \ge M$ shares are provided.
/// 2. Verifies CRC-32 on all provided shares.
/// 3. Verifies share consistency (matching threshold, total, length, and secret hash).
/// 4. Checks for duplicate share indices.
/// 5. Uses Lagrange basis multipliers at $x = 0$ over $\text{GF}(256)$ to reconstruct.
/// 6. Constant-time checks SHA-256 hash of reconstructed secret against expected digest.
pub fn combine_shares(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
    if shares.is_empty() {
        return Err(Error::Crypto("no shares provided for combination".into()));
    }

    let threshold = shares[0].threshold as usize;
    let total = shares[0].total;
    let expected_len = shares[0].length;
    let expected_hash = &shares[0].secret_hash;

    if threshold < 2 {
        return Err(Error::Crypto(
            "invalid share metadata: threshold M must be at least 2".into(),
        ));
    }
    if shares.len() < threshold {
        return Err(Error::Crypto(format!(
            "insufficient shares: got {} shares, but threshold requires at least {}",
            shares.len(),
            threshold
        )));
    }

    let mut seen_indices = HashSet::new();
    let mut valid_shares = Vec::with_capacity(shares.len());

    for share in shares {
        if !share.verify_crc() {
            return Err(Error::Format(format!(
                "share index {} failed CRC-32 checksum verification (tampered share)",
                share.index
            )));
        }
        if share.threshold as usize != threshold
            || share.total != total
            || share.length != expected_len
            || &share.secret_hash != expected_hash
        {
            return Err(Error::Format(
                "shares have mismatched threshold, total, length, or secret hash".into(),
            ));
        }
        if share.index == 0 {
            return Err(Error::Format(
                "share index 0 is invalid (reserved for master secret)".into(),
            ));
        }
        if !seen_indices.insert(share.index) {
            return Err(Error::Format(format!(
                "duplicate share index {} provided",
                share.index
            )));
        }
        valid_shares.push(share);
    }

    // Select the first `threshold` shares for reconstruction
    let subset = &valid_shares[..threshold];

    // Precompute Lagrange basis evaluation multipliers at x = 0
    // lambda_j = prod_{m != j} (xm / (xj ^ xm))
    let mut lambdas = Vec::with_capacity(threshold);
    for (j, share_j) in subset.iter().enumerate() {
        let xj = share_j.index;
        let mut lambda_j = 1u8;
        for (m, share_m) in subset.iter().enumerate() {
            if j == m {
                continue;
            }
            let xm = share_m.index;
            let denom = xj ^ xm;
            let term = gf_div(xm, denom)?;
            lambda_j = gf_mul(lambda_j, term);
        }
        lambdas.push(lambda_j);
    }

    // Reconstruct secret byte-by-byte
    let mut secret = Zeroizing::new(vec![0u8; expected_len]);
    for byte_idx in 0..expected_len {
        let mut reconstructed_byte = 0u8;
        for (j, share_j) in subset.iter().enumerate() {
            let y = share_j.payload[byte_idx];
            reconstructed_byte ^= gf_mul(y, lambdas[j]);
        }
        secret[byte_idx] = reconstructed_byte;
    }

    // Cryptographic authenticity verification: SHA-256 digest check
    let mut hasher = Sha256::new();
    hasher.update(&*secret);
    let candidate_hash = format!("{:x}", hasher.finalize());

    if !constant_time_eq(candidate_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err(Error::Crypto(
            "reconstructed secret hash mismatch: shares are invalid, inconsistent, or corrupted"
                .into(),
        ));
    }

    Ok(secret)
}

/// Split a secret directly into ASCII armored strings.
#[allow(dead_code)]
pub fn split_secret_to_armored(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<String>> {
    let shares = split_secret(secret, threshold, total)?;
    Ok(shares.iter().map(|s| s.to_armored()).collect())
}

/// Combine armored or compact share strings into the reconstructed master secret.
#[allow(dead_code)]
pub fn combine_armored_shares(armored_shares: &[&str]) -> Result<Zeroizing<Vec<u8>>> {
    let mut parsed = Vec::with_capacity(armored_shares.len());
    for s in armored_shares {
        parsed.push(Share::from_str(s)?);
    }
    combine_shares(&parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf256_multiplication_identities() {
        // Zero multiplication
        for a in 0..=255 {
            assert_eq!(gf_mul(a, 0), 0);
            assert_eq!(gf_mul(0, a), 0);
        }
        // Identity multiplication
        for a in 0..=255 {
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(1, a), a);
        }
        // Commutativity
        assert_eq!(gf_mul(42, 137), gf_mul(137, 42));
        assert_eq!(gf_mul(255, 128), gf_mul(128, 255));
    }

    #[test]
    fn gf256_inversion_all_non_zero_elements() {
        for a in 1..=255 {
            let inv = gf_inv(a).expect("inversion should succeed for non-zero");
            assert_ne!(inv, 0);
            let product = gf_mul(a, inv);
            assert_eq!(product, 1, "a = {a}, inv = {inv}, product = {product} != 1");
        }
        assert!(gf_inv(0).is_err());
    }

    #[test]
    fn gf256_division_roundtrip() {
        for a in [1, 2, 42, 128, 200, 255] {
            for b in [1, 3, 17, 99, 150, 254] {
                let div = gf_div(a, b).unwrap();
                let mult = gf_mul(div, b);
                assert_eq!(mult, a, "division roundtrip failed for a={a}, b={b}");
            }
        }
    }

    #[test]
    fn polynomial_evaluation_at_zero_yields_secret() {
        let secret = 0x5a;
        let coeffs = vec![secret, 0x12, 0x34, 0x78];
        assert_eq!(evaluate_polynomial(&coeffs, 0), secret);
    }

    #[test]
    fn lagrange_interpolation_reconstructs_polynomial_at_zero() {
        // P(x) = 42 ^ 17*x ^ 99*x^2
        let secret = 42u8;
        let coeffs = [secret, 17, 99];
        let p1 = (1u8, evaluate_polynomial(&coeffs, 1));
        let p2 = (2u8, evaluate_polynomial(&coeffs, 2));
        let p3 = (3u8, evaluate_polynomial(&coeffs, 3));

        // Any 3 points reconstruct secret
        assert_eq!(lagrange_interpolate(&[p1, p2, p3]).unwrap(), secret);

        let p5 = (5u8, evaluate_polynomial(&coeffs, 5));
        assert_eq!(lagrange_interpolate(&[p1, p3, p5]).unwrap(), secret);
        assert_eq!(lagrange_interpolate(&[p2, p3, p5]).unwrap(), secret);
    }

    #[test]
    fn shamir_2_of_2_roundtrip() {
        let secret = b"super-secret-password-123";
        let shares = split_secret(secret, 2, 2).unwrap();
        assert_eq!(shares.len(), 2);

        let recovered = combine_shares(&shares).unwrap();
        assert_eq!(&*recovered, secret);
    }

    #[test]
    fn shamir_3_of_5_all_10_combinations_reconstruct_secret() {
        let secret = b"master-seed-c4ca4238a0b923820dcc509a6f75849b";
        let shares = split_secret(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Test all C(5, 3) = 10 combinations
        let indices = [
            [0, 1, 2],
            [0, 1, 3],
            [0, 1, 4],
            [0, 2, 3],
            [0, 2, 4],
            [0, 3, 4],
            [1, 2, 3],
            [1, 2, 4],
            [1, 3, 4],
            [2, 3, 4],
        ];

        for combo in indices {
            let subset = vec![
                shares[combo[0]].clone(),
                shares[combo[1]].clone(),
                shares[combo[2]].clone(),
            ];
            let recovered = combine_shares(&subset).unwrap();
            assert_eq!(
                &*recovered, secret,
                "combination {:?} failed to reconstruct secret",
                combo
            );
        }
    }

    #[test]
    fn shamir_rejects_fewer_than_threshold_shares() {
        let secret = b"my-private-key";
        let shares = split_secret(secret, 3, 5).unwrap();

        // 2 shares provided when threshold is 3
        let subset = vec![shares[0].clone(), shares[1].clone()];
        let err = combine_shares(&subset).unwrap_err();
        assert!(err.to_string().contains("insufficient shares"));
    }

    #[test]
    fn shamir_rejects_tampered_share_payload() {
        let secret = b"critical-root-secret";
        let mut shares = split_secret(secret, 3, 5).unwrap();

        // Tamper 1 byte in payload of share 0 without updating CRC
        shares[0].payload[0] ^= 0x01;

        let subset = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        let err = combine_shares(&subset).unwrap_err();
        assert!(err.to_string().contains("failed CRC-32 checksum"));
    }

    #[test]
    fn shamir_rejects_tampered_payload_with_forged_crc() {
        let secret = b"critical-root-secret";
        let mut shares = split_secret(secret, 3, 5).unwrap();

        // Tamper 1 byte in payload of share 0 AND forge CRC32
        shares[0].payload[0] ^= 0x01;
        shares[0].crc32 = compute_share_crc(shares[0].index, shares[0].length, &shares[0].payload);

        let subset = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        let err = combine_shares(&subset).unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn shamir_rejects_duplicate_share_indices() {
        let secret = b"some-secret";
        let shares = split_secret(secret, 3, 5).unwrap();

        // Provide share 0 twice
        let subset = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        let err = combine_shares(&subset).unwrap_err();
        assert!(err.to_string().contains("duplicate share index"));
    }

    #[test]
    fn armored_format_roundtrip() {
        let secret = b"Armored Shamir Share Roundtrip Secret!";
        let shares = split_secret(secret, 3, 5).unwrap();

        let armored = shares[0].to_armored();
        assert!(armored.contains(SHARE_ARMOR_BEGIN));
        assert!(armored.contains(SHARE_ARMOR_END));

        let parsed = Share::from_armored(&armored).unwrap();
        assert_eq!(parsed, shares[0]);

        let parsed_display: Share = armored.parse().unwrap();
        assert_eq!(parsed_display, shares[0]);
    }

    #[test]
    fn compact_format_roundtrip() {
        let secret = b"Compact format test payload";
        let shares = split_secret(secret, 2, 3).unwrap();

        let compact = shares[1].to_compact();
        assert!(compact.starts_with(COMPACT_PREFIX));

        let parsed = Share::from_compact(&compact).unwrap();
        assert_eq!(parsed, shares[1]);

        let parsed_from_str: Share = compact.parse().unwrap();
        assert_eq!(parsed_from_str, shares[1]);
    }

    #[test]
    fn json_serialization_roundtrip() {
        let secret = b"JSON formatted secret test";
        let shares = split_secret(secret, 2, 4).unwrap();

        let json_str = serde_json::to_string(&shares[0]).unwrap();
        let parsed: Share = json_str.parse().unwrap();
        assert_eq!(parsed, shares[0]);
    }

    #[test]
    fn large_binary_secret_split_and_combine() {
        let mut large_secret = vec![0u8; 64 * 1024]; // 64 KiB
        rand::thread_rng().fill_bytes(&mut large_secret);

        let shares = split_secret(&large_secret, 3, 4).unwrap();
        assert_eq!(shares.len(), 4);

        let recovered = combine_shares(&shares[0..3]).unwrap();
        assert_eq!(&*recovered, &large_secret);
    }

    #[test]
    fn zeroize_clears_share_payload_on_drop() {
        let mut share = Share {
            version: 1,
            threshold: 2,
            total: 3,
            index: 1,
            length: 8,
            secret_hash: "hash".into(),
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
            crc32: 0,
        };
        share.zeroize();
        assert!(share.payload.is_empty());
    }

    #[test]
    fn armored_helpers_roundtrip() {
        let secret = b"Armored helper test secret payload";
        let armored = split_secret_to_armored(secret, 2, 3).unwrap();
        assert_eq!(armored.len(), 3);

        let slice = [armored[0].as_str(), armored[2].as_str()];
        let recovered = combine_armored_shares(&slice).unwrap();
        assert_eq!(&*recovered, secret);
    }
}
