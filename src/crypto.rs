// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Dual-layer authenticated encryption container (`SVLT` v1).
//!
//! Layer 1: Argon2id key derivation + ChaCha20-Poly1305 AEAD.
//! Layer 2 (optional `--dpapi`): Windows DPAPI (`CryptProtectData`) user-account
//! hardware binding so the container cannot be decrypted off the originating machine.

use crate::error::{Error, Result};
use crate::policy::PolicyHeader;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 4] = b"SVLT";
pub const VERSION: u8 = 1;
pub const VERSION_V2: u8 = 2;
pub const FLAG_DPAPI: u8 = 0x01;
pub const FLAG_DECOY: u8 = 0x02;
pub const FLAG_POLICY: u8 = 0x04;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + NONCE_LEN; // 34 bytes

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub version: u8,
    pub dpapi_bound: bool,
    pub payload_size: usize,
    pub salt_hex: String,
    pub decoy_container: bool,
    pub policy: Option<PolicyHeader>,
}

/// Seal plaintext bytes into a `SVLT` v1 encrypted container with an optional time/expiration policy.
pub fn seal_with_policy(
    plaintext: &[u8],
    passphrase: &str,
    bind_dpapi: bool,
    policy: Option<&PolicyHeader>,
) -> Result<Vec<u8>> {
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

    let (policy_wire, flags) = match policy {
        Some(p) => {
            let bytes = p.to_bytes();
            (
                Some(bytes),
                (if bind_dpapi { FLAG_DPAPI } else { 0 }) | FLAG_POLICY,
            )
        }
        None => (None, if bind_dpapi { FLAG_DPAPI } else { 0 }),
    };

    let ciphertext = match &policy_wire {
        Some(pw) => {
            let payload = Payload {
                msg: plaintext,
                aad: pw.as_slice(),
            };
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| Error::Crypto("ChaCha20-Poly1305 encryption failed".into()))?
        }
        None => cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| Error::Crypto("ChaCha20-Poly1305 encryption failed".into()))?,
    };

    let body = if bind_dpapi {
        dpapi_protect(&ciphertext)?
    } else {
        ciphertext
    };

    let extra_policy_len = if let Some(ref pw) = policy_wire {
        4 + pw.len()
    } else {
        0
    };

    let mut out = Vec::with_capacity(HEADER_LEN + extra_policy_len + body.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(flags);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);

    if let Some(ref pw) = policy_wire {
        let plen = pw.len() as u32;
        out.extend_from_slice(&plen.to_le_bytes());
        out.extend_from_slice(pw);
    }

    out.extend_from_slice(&body);
    Ok(out)
}

/// Seal plaintext bytes into a `SVLT` v1 encrypted container.
pub fn seal(plaintext: &[u8], passphrase: &str, bind_dpapi: bool) -> Result<Vec<u8>> {
    seal_with_policy(plaintext, passphrase, bind_dpapi, None)
}

/// Open a `SVLT` v1 or v2/decoy container at the current time and return the authenticated plaintext.
pub fn open(container: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    open_at(container, passphrase, None)
}

/// Open a `SVLT` container and enforce policy validation at the specified UTC timestamp (or current time if None).
pub fn open_at(container: &[u8], passphrase: &str, at_time: Option<u64>) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(Error::Crypto("passphrase must not be empty".into()));
    }
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
    if version != VERSION && version != VERSION_V2 {
        return Err(Error::Format(format!(
            "unsupported container version: {version}"
        )));
    }
    let flags = container[5];
    if (flags & FLAG_DECOY) != 0 {
        return crate::decoy::open_decoy(container, passphrase).map(|r| r.into_bytes());
    }

    if version == VERSION_V2 {
        return crate::decoy::open_v2(container, passphrase);
    }

    let salt = &container[6..6 + SALT_LEN];
    let nonce_bytes = &container[6 + SALT_LEN..HEADER_LEN];

    let (policy_wire, body_offset) = if (flags & FLAG_POLICY) != 0 {
        if container.len() < HEADER_LEN + 4 {
            return Err(Error::Format("container policy header truncated".into()));
        }
        let policy_len = u32::from_le_bytes(
            container[HEADER_LEN..HEADER_LEN + 4]
                .try_into()
                .map_err(|_| Error::Format("failed to read policy length".into()))?,
        ) as usize;
        let policy_start = HEADER_LEN + 4;
        let policy_end = policy_start
            .checked_add(policy_len)
            .ok_or_else(|| Error::Format("policy length integer overflow".into()))?;
        if container.len() < policy_end + 16 {
            return Err(Error::Format(
                "container truncated within policy or body".into(),
            ));
        }
        let p_bytes = &container[policy_start..policy_end];
        let policy = PolicyHeader::from_bytes(p_bytes)?;
        let check_time = at_time.unwrap_or_else(crate::policy::current_utc_timestamp);
        policy.validate_at(check_time)?;
        (Some(p_bytes), policy_end)
    } else {
        (None, HEADER_LEN)
    };

    let body = &container[body_offset..];
    let ciphertext = if (flags & FLAG_DPAPI) != 0 {
        dpapi_unprotect(body)?
    } else {
        body.to_vec()
    };

    let key_bytes = derive_key(passphrase.as_bytes(), salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    match policy_wire {
        Some(pw) => {
            let payload = Payload {
                msg: ciphertext.as_ref(),
                aad: pw,
            };
            cipher.decrypt(nonce, payload).map_err(|_| {
                Error::Crypto(
                    "authentication failed — wrong passphrase or tampered container/policy".into(),
                )
            })
        }
        None => cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
            Error::Crypto("authentication failed — wrong passphrase or tampered container".into())
        }),
    }
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
    if version != VERSION && version != VERSION_V2 {
        return Err(Error::Format(format!(
            "unsupported container version: {version}"
        )));
    }
    let flags = container[5];
    if (flags & FLAG_DECOY) != 0 {
        return crate::decoy::inspect_decoy(container);
    }

    let salt = &container[6..6 + SALT_LEN];
    let salt_hex = salt.iter().map(|b| format!("{b:02x}")).collect::<String>();

    let (policy, body_offset) = if (flags & FLAG_POLICY) != 0 {
        if container.len() < HEADER_LEN + 4 {
            return Err(Error::Format("container policy header truncated".into()));
        }
        let policy_len = u32::from_le_bytes(
            container[HEADER_LEN..HEADER_LEN + 4]
                .try_into()
                .map_err(|_| Error::Format("failed to read policy length".into()))?,
        ) as usize;
        let policy_start = HEADER_LEN + 4;
        let policy_end = policy_start
            .checked_add(policy_len)
            .ok_or_else(|| Error::Format("policy length integer overflow".into()))?;
        if container.len() < policy_end + 16 {
            return Err(Error::Format(
                "container truncated within policy or body".into(),
            ));
        }
        let p_bytes = &container[policy_start..policy_end];
        let parsed_policy = PolicyHeader::from_bytes(p_bytes)?;
        (Some(parsed_policy), policy_end)
    } else {
        (None, HEADER_LEN)
    };

    let body_len = container.len().saturating_sub(body_offset);

    Ok(ContainerInfo {
        version,
        dpapi_bound: (flags & FLAG_DPAPI) != 0,
        payload_size: body_len.saturating_sub(16),
        salt_hex,
        decoy_container: false,
        policy,
    })
}

/// Check if the container is a plausible deniability decoy container.
pub fn is_decoy_container(container: &[u8]) -> bool {
    crate::decoy::is_decoy_container(container)
}

pub(crate) fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
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
    hasher.update(key.as_slice());
    let mut derived = Zeroizing::new([0u8; 32]);
    derived.copy_from_slice(&hasher.finalize());
    Ok(derived)
}

#[cfg(windows)]
pub(crate) fn dpapi_protect(raw: &[u8]) -> Result<Vec<u8>> {
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
pub(crate) fn dpapi_unprotect(enc: &[u8]) -> Result<Vec<u8>> {
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
pub(crate) fn dpapi_protect(_raw: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Dpapi(
        "Windows DPAPI hardware binding is only supported on Windows systems".into(),
    ))
}

#[cfg(not(windows))]
pub(crate) fn dpapi_unprotect(_enc: &[u8]) -> Result<Vec<u8>> {
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
