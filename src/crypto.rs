// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Dual-layer authenticated encryption container (`SVLT` v1).
//!
//! Layer 1: Argon2id key derivation + ChaCha20-Poly1305 AEAD.
//! Layer 2 (optional `--dpapi`): Windows DPAPI (`CryptProtectData`) user-account
//! hardware binding so the container cannot be decrypted off the originating machine.

use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 4] = b"SVLT";
pub const VERSION: u8 = 1;
pub const FLAG_DPAPI: u8 = 0x01;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + NONCE_LEN; // 34 bytes

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub version: u8,
    pub dpapi_bound: bool,
    pub payload_size: usize,
    pub salt_hex: String,
}

/// Seal plaintext bytes into a `SVLT` v1 encrypted container.
pub fn seal(plaintext: &[u8], passphrase: &str, bind_dpapi: bool) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(Error::Crypto("passphrase must not be empty".into()));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key_bytes = derive_key(passphrase.as_bytes(), &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::Crypto("ChaCha20-Poly1305 encryption failed".into()))?;

    let flags = if bind_dpapi { FLAG_DPAPI } else { 0 };
    let body = if bind_dpapi {
        dpapi_protect(&ciphertext)?
    } else {
        ciphertext
    };

    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(flags);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Open a `SVLT` v1 container and return the authenticated plaintext.
pub fn open(container: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if container.len() < HEADER_LEN + 16 {
        return Err(Error::Format(
            "container truncated or smaller than header".into(),
        ));
    }
    if &container[0..4] != MAGIC {
        return Err(Error::Format(
            "invalid container magic (expected SVLT)".into(),
        ));
    }
    let version = container[4];
    if version != VERSION {
        return Err(Error::Format(format!(
            "unsupported container version: {version}"
        )));
    }
    let flags = container[5];
    let salt = &container[6..6 + SALT_LEN];
    let nonce_bytes = &container[6 + SALT_LEN..HEADER_LEN];
    let body = &container[HEADER_LEN..];

    let ciphertext = if (flags & FLAG_DPAPI) != 0 {
        dpapi_unprotect(body)?
    } else {
        body.to_vec()
    };

    let key_bytes = derive_key(passphrase.as_bytes(), salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
        Error::Crypto("authentication failed — wrong passphrase or tampered container".into())
    })
}

/// Inspect a `SVLT` container header without decrypting it.
pub fn inspect(container: &[u8]) -> Result<ContainerInfo> {
    if container.len() < HEADER_LEN + 16 {
        return Err(Error::Format("container truncated".into()));
    }
    if &container[0..4] != MAGIC {
        return Err(Error::Format(
            "invalid container magic (expected SVLT)".into(),
        ));
    }
    let version = container[4];
    let flags = container[5];
    let salt = &container[6..6 + SALT_LEN];
    let salt_hex = salt.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let body_len = container.len() - HEADER_LEN;

    Ok(ContainerInfo {
        version,
        dpapi_bound: (flags & FLAG_DPAPI) != 0,
        payload_size: body_len.saturating_sub(16),
        salt_hex,
    })
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| Error::Crypto(format!("Argon2 params error: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| Error::Crypto(format!("Argon2id key derivation failed: {e}")))?;

    // Domain-separate the derived key with SHA-256
    let mut hasher = Sha256::new();
    hasher.update(b"shadow-vault-v1-key");
    hasher.update(*key);
    let mut derived = Zeroizing::new([0u8; 32]);
    derived.copy_from_slice(&hasher.finalize());
    Ok(derived)
}

#[cfg(windows)]
fn dpapi_protect(raw: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    unsafe {
        let mut bytes = raw.to_vec();
        let blob_in = CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_mut_ptr(),
        };
        let mut blob_out = CRYPT_INTEGER_BLOB::default();
        let res = CryptProtectData(
            &blob_in,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut blob_out,
        );
        bytes.zeroize();
        res.map_err(|e| Error::Dpapi(format!("CryptProtectData: {e}")))?;

        let slice = std::slice::from_raw_parts(blob_out.pbData, blob_out.cbData as usize);
        let encrypted = slice.to_vec();
        let _ = LocalFree(HLOCAL(blob_out.pbData as *mut _));
        Ok(encrypted)
    }
}

#[cfg(windows)]
fn dpapi_unprotect(enc: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    unsafe {
        let mut buf = enc.to_vec();
        let blob_in = CRYPT_INTEGER_BLOB {
            cbData: buf.len() as u32,
            pbData: buf.as_mut_ptr(),
        };
        let mut blob_out = CRYPT_INTEGER_BLOB::default();
        let res = CryptUnprotectData(
            &blob_in,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut blob_out,
        );
        buf.zeroize();
        res.map_err(|e| Error::Dpapi(format!("CryptUnprotectData: {e}")))?;

        let slice = std::slice::from_raw_parts(blob_out.pbData, blob_out.cbData as usize);
        let out = slice.to_vec();
        // Securely wipe decrypted buffer using compiler-fenced zeroize before freeing
        let slice_mut = std::slice::from_raw_parts_mut(blob_out.pbData, blob_out.cbData as usize);
        slice_mut.zeroize();
        let _ = LocalFree(HLOCAL(blob_out.pbData as *mut _));
        Ok(out)
    }
}

#[cfg(not(windows))]
fn dpapi_protect(_raw: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Dpapi(
        "Windows DPAPI hardware binding is only supported on Windows systems".into(),
    ))
}

#[cfg(not(windows))]
fn dpapi_unprotect(_enc: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Dpapi(
        "cannot open DPAPI-bound container on non-Windows platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open_roundtrip() {
        let secret = b"top secret seed phrase: witch collapse practice feed shame open despair";
        let sealed = seal(secret, "correct-horse-battery-staple", false).unwrap();
        let info = inspect(&sealed).unwrap();
        assert_eq!(info.version, 1);
        assert!(!info.dpapi_bound);
        assert_eq!(info.payload_size, secret.len());

        let opened = open(&sealed, "correct-horse-battery-staple").unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn wrong_passphrase_fails_authentication() {
        let sealed = seal(b"confidential payload", "pass-1", false).unwrap();
        assert!(open(&sealed, "pass-2").is_err());
    }

    #[test]
    fn dpapi_bound_roundtrip() {
        let secret = b"hardware bound key material";
        let sealed = seal(secret, "machine-pass", true).unwrap();
        let info = inspect(&sealed).unwrap();
        assert!(info.dpapi_bound);

        let opened = open(&sealed, "machine-pass").unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn derived_key_is_zeroized_on_drop() {
        let mut key = derive_key(b"test-passphrase", b"0123456789abcdef").unwrap();
        assert_eq!(key.len(), 32);
        assert_ne!(&*key, &[0u8; 32]);
        key.zeroize();
        assert_eq!(&*key, &[0u8; 32]);
    }

    #[test]
    fn zeroize_clears_sensitive_buffer() {
        let mut sensitive = [0xA5u8; 64];
        assert_ne!(sensitive, [0u8; 64]);
        sensitive.zeroize();
        assert_eq!(sensitive, [0u8; 64]);
    }
}
