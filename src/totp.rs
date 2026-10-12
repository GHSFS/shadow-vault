// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! RFC 6238 TOTP (Time-based One-Time Password) & RFC 4226 HOTP 2FA Vault Engine.
//!
//! Provides zero-dependency Base32 codec (RFC 4648), self-contained RFC 3174 SHA-1,
//! RFC 2104 HMAC (SHA-1, SHA-256, SHA-512), dynamic truncation, constant-time verification,
//! Key URI parsing/serialization (`otpauth://totp/...`), and hardware-bound `.svault` container storage.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use zeroize::{Zeroize, Zeroizing};

/// Standard RFC 4648 Base32 alphabet: A-Z (0..25), 2-7 (26..31).
#[allow(dead_code)]
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Decode an RFC 4648 Base32 string into a `Zeroizing<Vec<u8>>` byte buffer.
/// Case-insensitive; ignores whitespace, hyphens, and '=' padding.
pub fn base32_decode(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;
    let mut out = Vec::new();

    for ch in s.chars() {
        if ch.is_whitespace() || ch == '-' || ch == '=' {
            continue;
        }
        let val = match ch {
            'A'..='Z' => (ch as u8 - b'A') as u64,
            'a'..='z' => (ch as u8 - b'a') as u64,
            '2'..='7' => (ch as u8 - b'2' + 26) as u64,
            _ => return Err(Error::Format(format!("invalid Base32 character: '{ch}'"))),
        };
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            out.push((buffer >> bits_left) as u8);
            buffer &= (1 << bits_left) - 1;
        }
    }

    Ok(Zeroizing::new(out))
}

/// Encode bytes into an RFC 4648 Base32 string with '=' padding.
#[allow(dead_code)]
pub fn base32_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;

    for &b in bytes {
        buffer = (buffer << 8) | (b as u64);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0x1F) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }

    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }

    while out.len() % 8 != 0 {
        out.push('=');
    }

    out
}

/// RFC 3174 compliant self-contained SHA-1 hash function.
/// Computes 160-bit (20-byte) message digest in constant-time 32-bit state without external crates.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let total_len = data.len();
    let total_bits = (total_len as u64).wrapping_mul(8);

    // Padding: data || 0x80 || 0x00... || 64-bit length
    let pad_zeros = (119usize.wrapping_sub(total_len % 64)) % 64;
    let padded_len = total_len + 1 + pad_zeros + 8;

    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(data);
    padded.push(0x80);
    padded.resize(total_len + 1 + pad_zeros, 0x00);
    padded.extend_from_slice(&total_bits.to_be_bytes());

    let mut w = [0u32; 80];

    for chunk in padded.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    digest[0..4].copy_from_slice(&h0.to_be_bytes());
    digest[4..8].copy_from_slice(&h1.to_be_bytes());
    digest[8..12].copy_from_slice(&h2.to_be_bytes());
    digest[12..16].copy_from_slice(&h3.to_be_bytes());
    digest[16..20].copy_from_slice(&h4.to_be_bytes());
    digest
}

/// Supported cryptographic hash algorithms for HMAC and TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum HashAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    /// Return HMAC internal block size in bytes.
    pub fn block_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 64,
            HashAlgorithm::Sha256 => 64,
            HashAlgorithm::Sha512 => 128,
        }
    }

    /// Return hash output digest size in bytes.
    #[allow(dead_code)]
    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha512 => 64,
        }
    }

    /// Parse algorithm name loosely from string (case-insensitive, ignoring hyphens).
    pub fn from_str_loose(s: &str) -> Result<Self> {
        let normalized = s.trim().to_uppercase().replace('-', "");
        match normalized.as_str() {
            "SHA1" => Ok(HashAlgorithm::Sha1),
            "SHA256" => Ok(HashAlgorithm::Sha256),
            "SHA512" => Ok(HashAlgorithm::Sha512),
            _ => Err(Error::Format(format!(
                "unsupported hash algorithm: '{s}' (supported: SHA1, SHA256, SHA512)"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha1 => "SHA1",
            HashAlgorithm::Sha256 => "SHA256",
            HashAlgorithm::Sha512 => "SHA512",
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Compute raw cryptographic hash digest for given algorithm.
pub fn hash_digest(algo: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algo {
        HashAlgorithm::Sha1 => sha1(data).to_vec(),
        HashAlgorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            Sha256::digest(data).to_vec()
        }
        HashAlgorithm::Sha512 => {
            use sha2::{Digest, Sha512};
            Sha512::digest(data).to_vec()
        }
    }
}

/// RFC 2104 HMAC implementation supporting SHA-1, SHA-256, and SHA-512.
pub fn hmac(algo: HashAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = algo.block_size();
    let mut key_block = Zeroizing::new(vec![0u8; block_size]);

    if key.len() > block_size {
        let hashed = hash_digest(algo, key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Zeroizing::new(vec![0u8; block_size]);
    let mut opad = Zeroizing::new(vec![0u8; block_size]);
    for i in 0..block_size {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner_input = Vec::with_capacity(block_size + data.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(data);
    let inner_hash = hash_digest(algo, &inner_input);

    let mut outer_input = Vec::with_capacity(block_size + inner_hash.len());
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_hash);
    hash_digest(algo, &outer_input)
}

/// RFC 4226 HOTP (HMAC-based One-Time Password) algorithm.
/// Truncates HMAC output dynamically and formats with leading zeros.
pub fn hotp(key: &[u8], counter: u64, digits: u32, algo: HashAlgorithm) -> Result<String> {
    if !(6..=8).contains(&digits) {
        return Err(Error::Crypto(format!(
            "invalid digits: {digits} (HOTP supports 6, 7, or 8 digits)"
        )));
    }
    let counter_bytes = counter.to_be_bytes();
    let mac = hmac(algo, key, &counter_bytes);
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    if offset + 4 > mac.len() {
        return Err(Error::Crypto("HMAC result truncated".into()));
    }

    let code_int = (((mac[offset] & 0x7f) as u32) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);

    let modulus = 10u32.pow(digits);
    let code = code_int % modulus;
    Ok(format!("{:0width$}", code, width = digits as usize))
}

/// RFC 6238 TOTP (Time-based One-Time Password) algorithm.
/// Derives step counter $T = \text{timestamp} / \text{period}$ and computes HOTP code.
pub fn totp(
    key: &[u8],
    timestamp: u64,
    period: u64,
    digits: u32,
    algo: HashAlgorithm,
) -> Result<String> {
    if period == 0 {
        return Err(Error::Crypto("period must be greater than zero".into()));
    }
    let counter = timestamp / period;
    hotp(key, counter, digits, algo)
}

/// Constant-time string equality check to prevent timing attacks.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a TOTP code against key and timestamp with time skew tolerance ($\pm \text{skew}$).
/// Evaluates all candidate windows without early termination to resist timing side-channels.
pub fn verify_totp(
    key: &[u8],
    code: &str,
    timestamp: u64,
    period: u64,
    digits: u32,
    algo: HashAlgorithm,
    skew: u32,
) -> Result<bool> {
    if period == 0 {
        return Err(Error::Crypto("period must be greater than zero".into()));
    }
    let current_step = (timestamp / period) as i64;
    let skew_i64 = skew as i64;
    let mut is_valid = false;

    for offset in -skew_i64..=skew_i64 {
        let step = current_step + offset;
        if step < 0 {
            continue;
        }
        let expected = hotp(key, step as u64, digits, algo)?;
        if constant_time_eq(code.trim(), &expected) {
            is_valid = true;
        }
    }

    Ok(is_valid)
}

/// Calculate remaining seconds before the current TOTP step window expires.
pub fn seconds_remaining(timestamp: u64, period: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    let elapsed = timestamp % period;
    period - elapsed
}

/// Render a visual Unicode progress bar showing remaining seconds in step.
pub fn render_progress_bar(remaining: u64, period: u64, bar_width: usize) -> String {
    if period == 0 || bar_width == 0 {
        return String::new();
    }
    let ratio = remaining as f64 / period as f64;
    let filled = (ratio * bar_width as f64).round() as usize;
    let filled = filled.min(bar_width);
    let empty = bar_width.saturating_sub(filled);
    format!(
        "[{}{}] {}s",
        "█".repeat(filled),
        "░".repeat(empty),
        remaining
    )
}

/// Percent-decode a URL string.
pub fn url_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(val) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(val);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Percent-encode a URL component.
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Parsed `otpauth://totp/...` URI model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuthUri {
    pub account: String,
    pub issuer: Option<String>,
    pub secret: String, // Base32 encoded secret
    pub algorithm: HashAlgorithm,
    pub digits: u32,
    pub period: u64,
}

impl OtpAuthUri {
    /// Parse key URI from string (`otpauth://totp/[Issuer:]Account?secret=...`).
    pub fn parse(uri_str: &str) -> Result<Self> {
        let uri = uri_str.trim();
        if !uri.starts_with("otpauth://totp/") {
            return Err(Error::Format(
                "invalid OTP URI scheme: expected 'otpauth://totp/'".into(),
            ));
        }

        let after_scheme = &uri["otpauth://totp/".len()..];
        let (raw_label, query_str) = match after_scheme.find('?') {
            Some(pos) => (&after_scheme[..pos], &after_scheme[pos + 1..]),
            None => return Err(Error::Format("missing query parameters in OTP URI".into())),
        };

        let decoded_label = url_decode(raw_label);
        let (label_issuer, account) = if let Some(idx) = decoded_label.find(':') {
            let iss = decoded_label[..idx].trim().to_string();
            let acc = decoded_label[idx + 1..].trim().to_string();
            (if iss.is_empty() { None } else { Some(iss) }, acc)
        } else {
            (None, decoded_label.trim().to_string())
        };

        if account.is_empty() {
            return Err(Error::Format("empty account name in OTP URI label".into()));
        }

        let mut secret = None;
        let mut query_issuer = None;
        let mut algorithm = HashAlgorithm::Sha1;
        let mut digits = 6u32;
        let mut period = 30u64;

        for param in query_str.split('&') {
            if param.is_empty() {
                continue;
            }
            let (k, v) = match param.find('=') {
                Some(pos) => (&param[..pos], url_decode(&param[pos + 1..])),
                None => (param, String::new()),
            };

            match k.to_ascii_lowercase().as_str() {
                "secret" => {
                    secret = Some(v.trim().to_string());
                }
                "issuer" => {
                    query_issuer = Some(v.trim().to_string());
                }
                "algorithm" => {
                    algorithm = HashAlgorithm::from_str_loose(&v)?;
                }
                "digits" => {
                    digits = v.parse::<u32>().map_err(|_| {
                        Error::Format(format!("invalid digits parameter in URI: '{v}'"))
                    })?;
                    if !(6..=8).contains(&digits) {
                        return Err(Error::Format(format!(
                            "unsupported digits in URI: {digits} (expected 6, 7, or 8)"
                        )));
                    }
                }
                "period" => {
                    period = v.parse::<u64>().map_err(|_| {
                        Error::Format(format!("invalid period parameter in URI: '{v}'"))
                    })?;
                    if period == 0 {
                        return Err(Error::Format("period in URI must be > 0".into()));
                    }
                }
                _ => {}
            }
        }

        let secret =
            secret.ok_or_else(|| Error::Format("missing 'secret' parameter in OTP URI".into()))?;
        if secret.is_empty() {
            return Err(Error::Format("empty 'secret' parameter in OTP URI".into()));
        }

        // Validate that secret decodes cleanly as Base32
        base32_decode(&secret)?;

        let issuer = query_issuer.or(label_issuer);

        Ok(OtpAuthUri {
            account,
            issuer,
            secret,
            algorithm,
            digits,
            period,
        })
    }

    /// Serialize model back to standard `otpauth://totp/...` URI.
    pub fn to_uri(&self) -> String {
        let label = match &self.issuer {
            Some(iss) => format!("{}:{}", url_encode(iss), url_encode(&self.account)),
            None => url_encode(&self.account),
        };

        let mut uri = format!(
            "otpauth://totp/{}?secret={}&algorithm={}&digits={}&period={}",
            label,
            self.secret,
            self.algorithm.as_str(),
            self.digits,
            self.period
        );

        if let Some(iss) = &self.issuer {
            uri.push_str(&format!("&issuer={}", url_encode(iss)));
        }

        uri
    }
}

fn default_digits() -> u32 {
    6
}

fn default_period() -> u64 {
    30
}

/// An individual TOTP account credential stored within the encrypted vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpRecord {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub secret: String, // Base32 encoded secret key
    #[serde(default)]
    pub algorithm: HashAlgorithm,
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[serde(default = "default_period")]
    pub period: u64,
    #[serde(default)]
    pub created_at: u64,
}

impl Drop for TotpRecord {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl TotpRecord {
    pub fn new(
        name: impl Into<String>,
        issuer: Option<String>,
        secret: impl Into<String>,
        algorithm: HashAlgorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self> {
        let secret = secret.into();
        base32_decode(&secret)?;

        let created_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(TotpRecord {
            name: name.into(),
            issuer,
            secret,
            algorithm,
            digits,
            period,
            created_at,
        })
    }

    pub fn to_uri(&self) -> String {
        OtpAuthUri {
            account: self.name.clone(),
            issuer: self.issuer.clone(),
            secret: self.secret.clone(),
            algorithm: self.algorithm,
            digits: self.digits,
            period: self.period,
        }
        .to_uri()
    }
}

/// Encrypted TOTP Vault containing 2FA account records sealed inside `.svault`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TotpVault {
    pub records: Vec<TotpRecord>,
    #[serde(skip)]
    pub dpapi_bound: bool,
}

impl Drop for TotpVault {
    fn drop(&mut self) {
        for r in &mut self.records {
            r.secret.zeroize();
        }
    }
}

impl TotpVault {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            dpapi_bound: false,
        }
    }

    /// Load existing vault from path or initialize empty if file does not exist.
    pub fn load_or_new(path: &Path, passphrase: &str) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        Self::load(path, passphrase)
    }

    /// Load and decrypt vault from `.svault` container.
    pub fn load(path: &Path, passphrase: &str) -> Result<Self> {
        let container_bytes = fs::read(path)?;
        let info = crate::crypto::inspect(&container_bytes)?;
        let mut decrypted = crate::crypto::open(&container_bytes, passphrase)?;
        let mut vault: TotpVault = serde_json::from_slice(&decrypted)
            .map_err(|e| Error::Format(format!("failed to deserialize TOTP vault JSON: {e}")))?;
        decrypted.zeroize();
        vault.dpapi_bound = info.dpapi_bound;
        Ok(vault)
    }

    /// Seal and save vault to `.svault` container using Argon2id + ChaCha20-Poly1305 AEAD + optional DPAPI.
    pub fn save(&self, path: &Path, passphrase: &str, bind_dpapi: bool) -> Result<()> {
        let json_bytes = Zeroizing::new(
            serde_json::to_vec_pretty(self)
                .map_err(|e| Error::Format(format!("failed to serialize TOTP vault: {e}")))?,
        );
        let sealed = crate::crypto::seal(&json_bytes, passphrase, bind_dpapi)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, sealed)?;
        Ok(())
    }

    /// Add a new record, rejecting case-insensitive duplicate names.
    pub fn add_record(&mut self, record: TotpRecord) -> Result<()> {
        let name_lower = record.name.to_lowercase();
        if self
            .records
            .iter()
            .any(|r| r.name.to_lowercase() == name_lower)
        {
            return Err(Error::Format(format!(
                "record with name '{}' already exists in vault",
                record.name
            )));
        }
        self.records.push(record);
        Ok(())
    }

    /// Look up record by name (case-insensitive).
    pub fn get_record(&self, name: &str) -> Option<&TotpRecord> {
        let name_lower = name.to_lowercase();
        self.records
            .iter()
            .find(|r| r.name.to_lowercase() == name_lower)
    }

    /// Remove record by name (case-insensitive).
    pub fn remove_record(&mut self, name: &str) -> Result<TotpRecord> {
        let name_lower = name.to_lowercase();
        if let Some(pos) = self
            .records
            .iter()
            .position(|r| r.name.to_lowercase() == name_lower)
        {
            Ok(self.records.remove(pos))
        } else {
            Err(Error::Format(format!(
                "record '{}' not found in vault",
                name
            )))
        }
    }

    /// List all account records.
    pub fn list_records(&self) -> &[TotpRecord] {
        &self.records
    }

    /// Generate TOTP code and remaining seconds for account at given timestamp.
    pub fn generate_code(&self, name: &str, timestamp: u64) -> Result<(String, u64)> {
        let record = self
            .get_record(name)
            .ok_or_else(|| Error::Format(format!("record '{}' not found in vault", name)))?;
        let raw_secret = base32_decode(&record.secret)?;
        let code = totp(
            &raw_secret,
            timestamp,
            record.period,
            record.digits,
            record.algorithm,
        )?;
        let remaining = seconds_remaining(timestamp, record.period);
        Ok((code, remaining))
    }

    /// Verify a TOTP code against account with skew tolerance.
    pub fn verify_code(&self, name: &str, code: &str, timestamp: u64, skew: u32) -> Result<bool> {
        let record = self
            .get_record(name)
            .ok_or_else(|| Error::Format(format!("record '{}' not found in vault", name)))?;
        let raw_secret = base32_decode(&record.secret)?;
        verify_totp(
            &raw_secret,
            code,
            timestamp,
            record.period,
            record.digits,
            record.algorithm,
            skew,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encode_decode_rfc_vectors() {
        // RFC 4648 Section 10 test vectors
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "MY======"),
            (b"fo", "MZXQ===="),
            (b"foo", "MZXW6==="),
            (b"foob", "MZXW6YQ="),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI======"),
        ];

        for &(plain, encoded) in vectors {
            assert_eq!(base32_encode(plain), encoded);
            let decoded = base32_decode(encoded).expect("decode failed");
            assert_eq!(&*decoded, plain);
        }
    }

    #[test]
    fn test_base32_decode_loose_case_and_padding_and_spaces() {
        let plain = b"foobar";
        // Lowercase, spaces, hyphens, omitted padding
        let variants = &[
            "mzxw6ytboi======",
            "MZXW6YTBOI",
            "mzxw 6ytb oi",
            "MZXW-6YTB-OI",
            "  MZXW 6ytb-OI==  ",
        ];

        for &v in variants {
            let decoded = base32_decode(v).unwrap();
            assert_eq!(&*decoded, plain);
        }
    }

    #[test]
    fn test_base32_decode_invalid_chars() {
        assert!(base32_decode("MZXW8===").is_err()); // '8' is invalid
        assert!(base32_decode("MZXW9===").is_err()); // '9' is invalid
        assert!(base32_decode("MZXW1===").is_err()); // '1' is invalid
        assert!(base32_decode("MZXW0===").is_err()); // '0' is invalid
        assert!(base32_decode("MZXW!===").is_err()); // '!' is invalid
    }

    #[test]
    fn test_sha1_nist_vectors() {
        // Empty string
        let empty_digest = sha1(b"");
        assert_eq!(
            hex::encode(empty_digest),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        // "abc"
        let abc_digest = sha1(b"abc");
        assert_eq!(
            hex::encode(abc_digest),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );

        // Long string
        let long_digest = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hex::encode(long_digest),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    // Hex helper module for tests without extra dependency
    mod hex {
        pub fn encode(bytes: impl AsRef<[u8]>) -> String {
            bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
        }
    }

    #[test]
    fn test_hmac_sha1_rfc2202_vectors() {
        // RFC 2202 Test Case 1
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac(HashAlgorithm::Sha1, &key, data);
        assert_eq!(hex::encode(mac), "b617318655057264e28bc0b6fb378c8ef146be00");

        // RFC 2202 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac(HashAlgorithm::Sha1, key, data);
        assert_eq!(hex::encode(mac), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");

        // RFC 2202 Test Case 3
        let key = vec![0xaa; 20];
        let data = vec![0xdd; 50];
        let mac = hmac(HashAlgorithm::Sha1, &key, &data);
        assert_eq!(hex::encode(mac), "125d7342b9ac11cd91a39af48aa17b4f63f175d3");
    }

    #[test]
    fn test_hmac_sha256_sha512_rfc4231_vectors() {
        // RFC 4231 Test Case 1 for SHA-256
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let mac256 = hmac(HashAlgorithm::Sha256, &key, data);
        assert_eq!(
            hex::encode(mac256),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // RFC 4231 Test Case 2 for SHA-256
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac256_2 = hmac(HashAlgorithm::Sha256, key, data);
        assert_eq!(
            hex::encode(mac256_2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        // RFC 4231 Test Case 1 for SHA-512
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let mac512 = hmac(HashAlgorithm::Sha512, &key, data);
        assert_eq!(
            hex::encode(mac512),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );

        // RFC 4231 Test Case 2 for SHA-512
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac512_2 = hmac(HashAlgorithm::Sha512, key, data);
        assert_eq!(
            hex::encode(mac512_2),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }

    #[test]
    fn test_rfc4226_hotp_appendix_d_vectors() {
        let key = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];

        for (count, &exp) in expected.iter().enumerate() {
            let code = hotp(key, count as u64, 6, HashAlgorithm::Sha1).unwrap();
            assert_eq!(code, exp, "HOTP mismatch at count {count}");
        }
    }

    #[test]
    fn test_rfc6238_totp_appendix_b_vectors() {
        // RFC 6238 Appendix B test secrets
        let k_sha1 = b"12345678901234567890";
        let k_sha256 = b"12345678901234567890123456789012";
        let k_sha512 = b"1234567890123456789012345678901234567890123456789012345678901234";

        struct TestVector {
            time: u64,
            exp_sha1: &'static str,
            exp_sha256: &'static str,
            exp_sha512: &'static str,
        }

        let vectors = [
            TestVector {
                time: 59,
                exp_sha1: "94287082",
                exp_sha256: "46119246",
                exp_sha512: "90693936",
            },
            TestVector {
                time: 1111111109,
                exp_sha1: "07081804",
                exp_sha256: "68084774",
                exp_sha512: "25091201",
            },
            TestVector {
                time: 1111111111,
                exp_sha1: "14050471",
                exp_sha256: "67062674",
                exp_sha512: "99943326",
            },
            TestVector {
                time: 1234567890,
                exp_sha1: "89005924",
                exp_sha256: "91819424",
                exp_sha512: "93441116",
            },
            TestVector {
                time: 2000000000,
                exp_sha1: "69279037",
                exp_sha256: "90698825",
                exp_sha512: "38618901",
            },
            TestVector {
                time: 20000000000,
                exp_sha1: "65353130",
                exp_sha256: "77737706",
                exp_sha512: "47863826",
            },
        ];

        for v in vectors {
            let c_sha1 = totp(k_sha1, v.time, 30, 8, HashAlgorithm::Sha1).unwrap();
            assert_eq!(c_sha1, v.exp_sha1, "SHA-1 mismatch at time {}", v.time);

            let c_sha256 = totp(k_sha256, v.time, 30, 8, HashAlgorithm::Sha256).unwrap();
            assert_eq!(
                c_sha256, v.exp_sha256,
                "SHA-256 mismatch at time {}",
                v.time
            );

            let c_sha512 = totp(k_sha512, v.time, 30, 8, HashAlgorithm::Sha512).unwrap();
            assert_eq!(
                c_sha512, v.exp_sha512,
                "SHA-512 mismatch at time {}",
                v.time
            );
        }
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("123456", "123456"));
        assert!(!constant_time_eq("123456", "123457"));
        assert!(!constant_time_eq("123456", "12345"));
        assert!(!constant_time_eq("", "1"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_verify_totp_with_skew() {
        let key = b"12345678901234567890";
        let time = 1234567890;
        let code = totp(key, time, 30, 6, HashAlgorithm::Sha1).unwrap();

        // Exact match
        assert!(verify_totp(key, &code, time, 30, 6, HashAlgorithm::Sha1, 0).unwrap());

        // Previous window (time - 30) with skew 1
        assert!(verify_totp(key, &code, time + 30, 30, 6, HashAlgorithm::Sha1, 1).unwrap());

        // Next window (time + 30) with skew 1
        assert!(verify_totp(key, &code, time - 30, 30, 6, HashAlgorithm::Sha1, 1).unwrap());

        // Two windows away with skew 1 -> invalid
        assert!(!verify_totp(key, &code, time + 60, 30, 6, HashAlgorithm::Sha1, 1).unwrap());
        // Two windows away with skew 2 -> valid
        assert!(verify_totp(key, &code, time + 60, 30, 6, HashAlgorithm::Sha1, 2).unwrap());
    }

    #[test]
    fn test_seconds_remaining_and_progress_bar() {
        assert_eq!(seconds_remaining(59, 30), 1);
        assert_eq!(seconds_remaining(60, 30), 30);
        assert_eq!(seconds_remaining(75, 30), 15);

        let bar15 = render_progress_bar(15, 30, 10);
        assert!(bar15.contains("█████░░░░░"));
        assert!(bar15.contains("15s"));

        let bar30 = render_progress_bar(30, 30, 10);
        assert!(bar30.contains("██████████"));
        assert!(bar30.contains("30s"));
    }

    #[test]
    fn test_uri_parse_and_serialize_roundtrip() {
        let original_uri = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&issuer=GitHub";
        let parsed = OtpAuthUri::parse(original_uri).expect("failed to parse URI");

        assert_eq!(parsed.account, "alice");
        assert_eq!(parsed.issuer.as_deref(), Some("GitHub"));
        assert_eq!(parsed.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.algorithm, HashAlgorithm::Sha1);
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);

        let serialized = parsed.to_uri();
        let re_parsed = OtpAuthUri::parse(&serialized).expect("failed to re-parse");
        assert_eq!(parsed, re_parsed);
    }

    #[test]
    fn test_uri_parse_edge_cases() {
        // Without issuer in label or query
        let uri = "otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP";
        let parsed = OtpAuthUri::parse(uri).unwrap();
        assert_eq!(parsed.account, "bob");
        assert_eq!(parsed.issuer, None);
        assert_eq!(parsed.algorithm, HashAlgorithm::Sha1);
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);

        // Invalid scheme
        assert!(OtpAuthUri::parse("https://example.com").is_err());
        // Missing secret
        assert!(OtpAuthUri::parse("otpauth://totp/alice?issuer=Google").is_err());
        // Invalid Base32 secret
        assert!(OtpAuthUri::parse("otpauth://totp/alice?secret=199999").is_err());
    }

    #[test]
    fn test_totp_vault_lifecycle() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_totp.svault");
        let passphrase = "correct_horse_battery_staple_2026!";

        // 1. Create new vault
        let mut vault = TotpVault::load_or_new(&vault_path, passphrase).unwrap();
        assert!(vault.list_records().is_empty());

        // 2. Add record
        let record = TotpRecord::new(
            "GitHub",
            Some("GitHub".into()),
            "JBSWY3DPEHPK3PXP",
            HashAlgorithm::Sha1,
            6,
            30,
        )
        .unwrap();
        vault.add_record(record).unwrap();

        // Adding duplicate name should fail
        let duplicate = TotpRecord::new(
            "github",
            None,
            "JBSWY3DPEHPK3PXP",
            HashAlgorithm::Sha1,
            6,
            30,
        )
        .unwrap();
        assert!(vault.add_record(duplicate).is_err());

        // 3. Save vault
        vault.save(&vault_path, passphrase, false).unwrap();
        assert!(vault_path.exists());

        // 4. Reload vault with correct passphrase
        let reloaded = TotpVault::load(&vault_path, passphrase).unwrap();
        assert_eq!(reloaded.list_records().len(), 1);
        let rec = reloaded.get_record("github").unwrap();
        assert_eq!(rec.name, "GitHub");

        // 5. Generate code
        let (code, remaining) = reloaded.generate_code("GitHub", 1234567890).unwrap();
        assert_eq!(code.len(), 6);
        assert!(remaining <= 30);

        // 6. Verify code
        assert!(reloaded
            .verify_code("GitHub", &code, 1234567890, 0)
            .unwrap());

        // 7. Wrong passphrase should fail
        assert!(TotpVault::load(&vault_path, "wrong_passphrase").is_err());

        // 8. Remove record
        let mut vault_mod = reloaded;
        let removed = vault_mod.remove_record("github").unwrap();
        assert_eq!(removed.name, "GitHub");
        assert!(vault_mod.list_records().is_empty());
    }

    #[test]
    fn test_totp_vault_zeroize_memory() {
        let mut record =
            TotpRecord::new("Test", None, "JBSWY3DPEHPK3PXP", HashAlgorithm::Sha1, 6, 30).unwrap();
        assert!(!record.secret.is_empty());
        record.secret.zeroize();
        assert!(record.secret.chars().all(|c| c == '\0'));
    }

    #[test]
    #[cfg(windows)]
    fn test_totp_vault_dpapi_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("dpapi_totp.svault");
        let passphrase = "dpapi_bound_passphrase!";

        let mut vault = TotpVault::new();
        vault
            .add_record(
                TotpRecord::new(
                    "SecureService",
                    None,
                    "JBSWY3DPEHPK3PXP",
                    HashAlgorithm::Sha256,
                    8,
                    60,
                )
                .unwrap(),
            )
            .unwrap();

        vault.save(&vault_path, passphrase, true).unwrap();

        let loaded = TotpVault::load(&vault_path, passphrase).unwrap();
        assert!(loaded.dpapi_bound);
        assert_eq!(loaded.list_records().len(), 1);
        let rec = loaded.get_record("SecureService").unwrap();
        assert_eq!(rec.digits, 8);
        assert_eq!(rec.period, 60);
        assert_eq!(rec.algorithm, HashAlgorithm::Sha256);
    }
}
