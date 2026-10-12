// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Keyfile + Passphrase Two-Factor Key Derivation engine (`src/keyfile.rs`).
//!
//! Provides cryptographically hardened two-factor authentication (2FA) and keyfile-only
//! key derivation for `.svault` containers:
//! - Streaming HMAC-SHA256 derivation with constant 64 KiB `Zeroizing` buffer memory footprint.
//! - Domain-separated pre-hashing:
//!   - 2FA Mode: `HMAC-SHA256(key = passphrase, data = "shadow-vault:keyfile-v1:" || keyfile_stream)`
//!   - Keyfile-Only Mode: `HMAC-SHA256(key = "shadow-vault:keyfile-only:v1", data = keyfile_stream)`
//! - Hardware token / USB keyfile CSPRNG generator (16 bytes to 1 MiB).
//! - SHA-256 keyfile fingerprinting and Shannon entropy inspection.
//! - Proactive zeroization of all intermediate secret material via `zeroize::Zeroizing`.

use crate::error::{Error, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

pub const DOMAIN_2FA_PREFIX: &[u8] = b"shadow-vault:keyfile-v1:";
pub const DOMAIN_KEYFILE_ONLY: &[u8] = b"shadow-vault:keyfile-only:v1";
#[allow(dead_code)]
pub const DEFAULT_KEYFILE_BYTES: usize = 64;
pub const MIN_KEYFILE_BYTES: usize = 16;
pub const MAX_KEYFILE_BYTES: usize = 1_048_576; // 1 MiB
pub const STREAM_BUFFER_SIZE: usize = 64 * 1024; // 64 KiB

/// Detailed inspection metrics for a cryptographic keyfile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyfileInfo {
    /// Canonical path to the keyfile.
    pub path: String,
    /// Total file size in bytes.
    pub size_bytes: u64,
    /// Cryptographic SHA-256 fingerprint formatted as `SHA256:<hex>`.
    pub fingerprint: String,
    /// Shannon entropy in bits per byte (0.0 to 8.0).
    pub shannon_entropy: f64,
    /// Human-readable evaluation of entropy quality.
    pub entropy_assessment: String,
    /// Indicates whether entropy and length are sufficient for production 2FA.
    pub recommended_for_2fa: bool,
}

impl KeyfileInfo {
    /// Formats a clean human-readable summary of keyfile metrics for terminal display.
    pub fn display_summary(&self) -> String {
        format!(
            "Keyfile Inspection Report:\n  Path:               {}\n  Size:               {} bytes\n  Fingerprint:        {}\n  Shannon Entropy:    {:.4} bits/byte (max 8.0)\n  Entropy Assessment: {}\n  2FA Recommended:    {}",
            self.path,
            self.size_bytes,
            self.fingerprint,
            self.shannon_entropy,
            self.entropy_assessment,
            self.recommended_for_2fa
        )
    }
}

/// Compute a streaming HMAC-SHA256 over an arbitrary stream.
pub(crate) fn compute_streaming_hmac_sha256<R: Read>(
    key: &[u8],
    prefix: Option<&[u8]>,
    mut reader: R,
) -> Result<(Zeroizing<[u8; 32]>, usize)> {
    // 1. Prepare 64-byte padded key block K'
    let mut k_prime = Zeroizing::new([0u8; 64]);
    if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let digest = hasher.finalize();
        k_prime[..32].copy_from_slice(&digest);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // 2. Compute inner and outer padding blocks
    let mut ipad = Zeroizing::new([0u8; 64]);
    let mut opad = Zeroizing::new([0u8; 64]);
    for i in 0..64 {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    // 3. Inner hash: H(ipad || prefix || message_stream)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(*ipad);
    if let Some(pfx) = prefix {
        inner_hasher.update(pfx);
    }

    let mut buffer = Zeroizing::new([0u8; STREAM_BUFFER_SIZE]);
    let mut total_bytes = 0usize;

    loop {
        let n = reader.read(&mut *buffer)?;
        if n == 0 {
            break;
        }
        total_bytes += n;
        inner_hasher.update(&buffer[..n]);
    }

    let inner_digest = inner_hasher.finalize();

    // 4. Outer hash: H(opad || inner_digest)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(*opad);
    outer_hasher.update(inner_digest);
    let outer_digest = outer_hasher.finalize();

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&outer_digest);
    Ok((out, total_bytes))
}

/// Combine an optional passphrase and keyfile path into a 32-byte cryptographically derived seed.
///
/// - If `passphrase` is present and non-empty: HMAC key is `passphrase.as_bytes()`, prefix message
///   with domain separator `b"shadow-vault:keyfile-v1:"`, and stream keyfile chunks.
/// - If `passphrase` is None or empty: HMAC key is domain separator `b"shadow-vault:keyfile-only:v1"`,
///   and message is streamed keyfile chunks.
/// - If keyfile is 0 bytes: returns `Error::Crypto("keyfile is empty (0 bytes) - must contain secret key material")`.
/// - If keyfile path does not exist or is a directory: returns an appropriate `Error`.
pub fn combine_passphrase_and_keyfile(
    passphrase: Option<&str>,
    keyfile_path: &Path,
) -> Result<Zeroizing<[u8; 32]>> {
    if !keyfile_path.exists() {
        return Err(Error::Crypto(format!(
            "keyfile not found: {}",
            keyfile_path.display()
        )));
    }
    if keyfile_path.is_dir() {
        return Err(Error::Crypto(format!(
            "keyfile path is a directory: {}",
            keyfile_path.display()
        )));
    }

    let file = std::fs::File::open(keyfile_path).map_err(Error::Io)?;
    let meta = file.metadata().map_err(Error::Io)?;
    if meta.len() == 0 {
        return Err(Error::Crypto(
            "keyfile is empty (0 bytes) - must contain secret key material".into(),
        ));
    }

    let (hmac_key, prefix) = match passphrase {
        Some(p) if !p.is_empty() => (p.as_bytes(), Some(DOMAIN_2FA_PREFIX)),
        _ => (DOMAIN_KEYFILE_ONLY, None),
    };

    let reader = std::io::BufReader::new(file);
    let (mac, total_bytes) = compute_streaming_hmac_sha256(hmac_key, prefix, reader)?;

    if total_bytes == 0 {
        return Err(Error::Crypto(
            "keyfile is empty (0 bytes) - must contain secret key material".into(),
        ));
    }

    Ok(mac)
}

/// Generate a cryptographically secure random keyfile of `len` bytes via CSPRNG.
///
/// Ensures all intermediate buffers are wiped with zeroize upon completion.
pub fn generate_keyfile(path: &Path, len: usize) -> Result<()> {
    if !(MIN_KEYFILE_BYTES..=MAX_KEYFILE_BYTES).contains(&len) {
        return Err(Error::Crypto(format!(
            "invalid keyfile length: {len} bytes (must be between {MIN_KEYFILE_BYTES} and {MAX_KEYFILE_BYTES} bytes)"
        )));
    }

    let mut key_material = Zeroizing::new(vec![0u8; len]);
    rand::rngs::OsRng.fill_bytes(&mut key_material);

    std::fs::write(path, &*key_material).map_err(Error::Io)?;
    Ok(())
}

/// Calculate SHA-256 digest of keyfile and return formatted hex string (`SHA256:<hex>`).
pub fn keyfile_fingerprint(path: &Path) -> Result<String> {
    if !path.exists() {
        return Err(Error::Crypto(format!(
            "keyfile not found: {}",
            path.display()
        )));
    }
    if path.is_dir() {
        return Err(Error::Crypto(format!(
            "keyfile path is a directory: {}",
            path.display()
        )));
    }

    let file = std::fs::File::open(path).map_err(Error::Io)?;
    let meta = file.metadata().map_err(Error::Io)?;
    if meta.len() == 0 {
        return Err(Error::Crypto(
            "keyfile is empty (0 bytes) - must contain secret key material".into(),
        ));
    }

    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = Zeroizing::new([0u8; STREAM_BUFFER_SIZE]);
    let mut total_bytes = 0usize;

    loop {
        let n = reader.read(&mut *buffer)?;
        if n == 0 {
            break;
        }
        total_bytes += n;
        hasher.update(&buffer[..n]);
    }

    if total_bytes == 0 {
        return Err(Error::Crypto(
            "keyfile is empty (0 bytes) - must contain secret key material".into(),
        ));
    }

    let digest = hasher.finalize();
    let hex_digest = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok(format!("SHA256:{hex_digest}"))
}

/// Inspect keyfile size, SHA-256 fingerprint, and Shannon entropy metrics.
pub fn inspect_keyfile(path: &Path) -> Result<KeyfileInfo> {
    if !path.exists() {
        return Err(Error::Crypto(format!(
            "keyfile not found: {}",
            path.display()
        )));
    }
    if path.is_dir() {
        return Err(Error::Crypto(format!(
            "keyfile path is a directory: {}",
            path.display()
        )));
    }

    let file = std::fs::File::open(path).map_err(Error::Io)?;
    let meta = file.metadata().map_err(Error::Io)?;
    let size_bytes = meta.len();
    if size_bytes == 0 {
        return Err(Error::Crypto(
            "keyfile is empty (0 bytes) - must contain secret key material".into(),
        ));
    }

    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut byte_counts = [0u64; 256];
    let mut buffer = Zeroizing::new([0u8; STREAM_BUFFER_SIZE]);
    let mut total_bytes = 0usize;

    loop {
        let n = reader.read(&mut *buffer)?;
        if n == 0 {
            break;
        }
        total_bytes += n;
        hasher.update(&buffer[..n]);
        for &b in &buffer[..n] {
            byte_counts[b as usize] += 1;
        }
    }

    if total_bytes == 0 {
        return Err(Error::Crypto(
            "keyfile is empty (0 bytes) - must contain secret key material".into(),
        ));
    }

    let digest = hasher.finalize();
    let hex_digest = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let fingerprint = format!("SHA256:{hex_digest}");

    let total_f = total_bytes as f64;
    let mut shannon_entropy = 0.0f64;
    for &count in &byte_counts {
        if count > 0 {
            let p = count as f64 / total_f;
            shannon_entropy -= p * p.log2();
        }
    }

    let max_entropy = (total_bytes as f64).min(256.0).log2();
    let normalized = if max_entropy > 0.0 {
        shannon_entropy / max_entropy
    } else {
        0.0
    };

    let (entropy_assessment, recommended_for_2fa) = if total_bytes < MIN_KEYFILE_BYTES {
        (
            format!(
                "Unsafe: File is smaller than minimum recommended {} bytes",
                MIN_KEYFILE_BYTES
            ),
            false,
        )
    } else if (total_bytes >= 256 && shannon_entropy >= 7.8)
        || (total_bytes < 256 && normalized >= 0.92)
    {
        (
            "Excellent: High Shannon entropy consistent with CSPRNG random key material".into(),
            true,
        )
    } else if (total_bytes >= 256 && shannon_entropy >= 7.0)
        || (total_bytes < 256 && normalized >= 0.85)
    {
        (
            "Good: Moderate-high Shannon entropy suitable for cryptographic key derivation".into(),
            true,
        )
    } else if (total_bytes >= 256 && shannon_entropy >= 5.0)
        || (total_bytes < 256 && normalized >= 0.65)
    {
        (
            "Warning: Moderate entropy; resembles structured binary or text data".into(),
            false,
        )
    } else {
        (
            "Critical: Low entropy; repetitive patterns or predictable byte distribution".into(),
            false,
        )
    };

    Ok(KeyfileInfo {
        path: path.to_string_lossy().to_string(),
        size_bytes,
        fingerprint,
        shannon_entropy,
        entropy_assessment,
        recommended_for_2fa,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::tempdir;

    #[test]
    fn test_rfc4231_hmac_sha256_vector_1() {
        // RFC 4231 Test Case 1
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let (mac, len) = compute_streaming_hmac_sha256(&key, None, Cursor::new(data)).unwrap();
        assert_eq!(len, 8);
        let hex = mac.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_rfc4231_hmac_sha256_vector_2() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let (mac, len) = compute_streaming_hmac_sha256(key, None, Cursor::new(data)).unwrap();
        assert_eq!(len, 28);
        let hex = mac.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_generate_and_inspect_keyfile() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("master.key");

        generate_keyfile(&kf, 64).unwrap();
        assert_eq!(std::fs::metadata(&kf).unwrap().len(), 64);

        let info = inspect_keyfile(&kf).unwrap();
        assert_eq!(info.size_bytes, 64);
        assert!(info.fingerprint.starts_with("SHA256:"));
        assert!(info.shannon_entropy > 5.0);
        assert!(info.recommended_for_2fa);

        let fp = keyfile_fingerprint(&kf).unwrap();
        assert_eq!(fp, info.fingerprint);
    }

    #[test]
    fn test_combine_passphrase_and_keyfile_deterministic() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("secret.key");
        std::fs::write(&kf, b"very-strong-secret-keyfile-material-12345678").unwrap();

        let k1 = combine_passphrase_and_keyfile(Some("alpha-password"), &kf).unwrap();
        let k2 = combine_passphrase_and_keyfile(Some("alpha-password"), &kf).unwrap();
        assert_eq!(k1, k2);

        // Different passphrase produces different key
        let k3 = combine_passphrase_and_keyfile(Some("beta-password"), &kf).unwrap();
        assert_ne!(k1, k3);

        // Keyfile-only derivation
        let ko1 = combine_passphrase_and_keyfile(None, &kf).unwrap();
        let ko2 = combine_passphrase_and_keyfile(Some(""), &kf).unwrap();
        assert_eq!(ko1, ko2);
        assert_ne!(k1, ko1);
    }

    #[test]
    fn test_tampered_keyfile_produces_distinct_keys() {
        let dir = tempdir().unwrap();
        let kf1 = dir.path().join("key1.bin");
        let kf2 = dir.path().join("key2.bin");

        let mut data = vec![0x42u8; 128];
        std::fs::write(&kf1, &data).unwrap();
        data[64] ^= 0x01; // tamper 1 bit
        std::fs::write(&kf2, &data).unwrap();

        let d1 = combine_passphrase_and_keyfile(Some("pass"), &kf1).unwrap();
        let d2 = combine_passphrase_and_keyfile(Some("pass"), &kf2).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_empty_keyfile_rejected() {
        let dir = tempdir().unwrap();
        let empty_kf = dir.path().join("empty.key");
        std::fs::write(&empty_kf, b"").unwrap();

        let err = combine_passphrase_and_keyfile(Some("pass"), &empty_kf).unwrap_err();
        assert!(err.to_string().contains("keyfile is empty (0 bytes)"));

        assert!(keyfile_fingerprint(&empty_kf).is_err());
        assert!(inspect_keyfile(&empty_kf).is_err());
    }

    #[test]
    fn test_nonexistent_or_directory_keyfile_rejected() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing.key");
        assert!(combine_passphrase_and_keyfile(Some("pass"), &missing).is_err());

        let folder = dir.path().join("folder");
        std::fs::create_dir(&folder).unwrap();
        assert!(combine_passphrase_and_keyfile(Some("pass"), &folder).is_err());
    }

    #[test]
    fn test_invalid_lengths_for_keyfile_generation() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("fail.key");
        assert!(generate_keyfile(&kf, 15).is_err());
        assert!(generate_keyfile(&kf, 1_048_577).is_err());
    }
}
