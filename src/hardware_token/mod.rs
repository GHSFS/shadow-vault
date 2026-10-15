// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! FIDO2 / Windows Hello Hardware Key Credential Binding module (`src/hardware_token/mod.rs`).
//!
//! Provides multi-factor hardware-bound cryptographic key derivation and assertion
//! authentication conforming to W3C WebAuthn and FIDO2 / CTAP 2.1 PRF (HMAC-secret) specifications.

pub mod credential;
pub mod provider;

#[allow(unused_imports)]
pub use credential::{
    default_registry_path, load_registry, save_registry, Fido2Credential, Fido2DeviceType,
    Fido2Header,
};
#[allow(unused_imports)]
pub use provider::{
    derive_hardware_secret, detect_hardware_capabilities, generate_credential,
    verify_hardware_assertion, ProviderStatus, DEFAULT_RP_ID,
};

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Combine base passphrase/keyfile key material with 32-byte hardware token secret.
///
/// Computes:
/// `derived = HMAC-SHA256(hardware_secret, b"shadow-vault-fido2-bound:" || base_key_material)`
pub fn combine_hardware_key_material(
    base_key_material: &[u8],
    hardware_secret: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut data = Vec::with_capacity(25 + base_key_material.len());
    data.extend_from_slice(b"shadow-vault-fido2-bound:");
    data.extend_from_slice(base_key_material);

    let res = hmac_sha256(hardware_secret, &data);
    data.zeroize();
    res
}

/// Resolve a FIDO2 credential from an explicit file path or the system credentials registry.
pub fn resolve_credential(
    cred_path: Option<&Path>,
    expected_id: Option<&[u8]>,
) -> Result<Fido2Credential> {
    if let Some(path) = cred_path {
        let cred = Fido2Credential::load_from_file(path)?;
        if let Some(expected) = expected_id {
            let id_bytes = hex_decode(&cred.id)?;
            if id_bytes != expected {
                return Err(Error::HardwareToken(format!(
                    "specified credential '{}' (id: {}) does not match container credential ID",
                    path.display(),
                    cred.id
                )));
            }
        }
        return Ok(cred);
    }

    // Look up in default registry
    let reg_path = default_registry_path();
    let creds = load_registry(&reg_path)?;

    if let Some(expected) = expected_id {
        let expected_hex = hex_encode(expected);
        for c in &creds {
            if c.id.eq_ignore_ascii_case(&expected_hex) {
                return Ok(c.clone());
            }
        }
        return Err(Error::HardwareToken(format!(
            "no enrolled hardware credential found in registry matching container credential ID (0x{expected_hex})"
        )));
    }

    // Return the first enrolled credential if no specific ID requested
    if let Some(first) = creds.into_iter().next() {
        Ok(first)
    } else {
        Err(Error::HardwareToken(
            "no hardware token credentials enrolled in registry. Enroll one with 'svault fido2 enroll' or provide '--fido2-cred <path>'".into()
        ))
    }
}

/// Enroll a new hardware credential and persist to registry or custom file.
pub fn enroll_credential(
    name: &str,
    device_type: Fido2DeviceType,
    rp_id: Option<&str>,
    user_name: Option<&str>,
    pin: Option<&str>,
    out_path: Option<&Path>,
) -> Result<Fido2Credential> {
    let cred = generate_credential(name, device_type, rp_id, user_name, pin)?;

    if let Some(path) = out_path {
        cred.save_to_file(path)?;
    } else {
        let reg_path = default_registry_path();
        let mut list = load_registry(&reg_path)?;
        list.retain(|c| c.name != name && c.id != cred.id);
        list.push(cred.clone());
        save_registry(&reg_path, &list)?;
    }

    Ok(cred)
}

/// Remove a credential by name or ID from registry.
pub fn remove_credential(identifier: &str, reg_path: Option<&Path>) -> Result<bool> {
    let path = reg_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_registry_path);
    let mut list = load_registry(&path)?;
    let initial_len = list.len();
    list.retain(|c| c.name != identifier && !c.id.eq_ignore_ascii_case(identifier));
    if list.len() < initial_len {
        save_registry(&path, &list)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Structured JSON report for FIDO2 enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2EnrollReport {
    pub status: String,
    pub command: String,
    pub credential_id: String,
    pub name: String,
    pub device_type: String,
    pub rp_id: String,
    pub user_name: String,
    pub saved_to: String,
}

/// Structured JSON report for FIDO2 testing / verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2TestReport {
    pub status: String,
    pub command: String,
    pub credential_id: String,
    pub name: String,
    pub device_type: String,
    pub verified: bool,
    pub derived_secret_fingerprint: String,
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = Zeroizing::new([0u8; BLOCK_SIZE]);

    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hash = hasher.finalize();
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Zeroizing::new([0x36u8; BLOCK_SIZE]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK_SIZE]);
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad.as_slice());
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad.as_slice());
    outer.update(inner_hash);
    let result = outer.finalize();

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&result);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::Format("hex string has odd length".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| Error::Format(format!("invalid hex digit: {e}")))
        })
        .collect()
}
