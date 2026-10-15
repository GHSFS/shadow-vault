// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! FIDO2 / Windows Hello Hardware Key Credential Model & Wire Format (`src/hardware_token/credential.rs`).

use crate::error::{Error, Result};
use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const HEADER_MAGIC: &[u8; 4] = b"SVHW";
pub const HEADER_VERSION: u8 = 1;

pub const FLAG_USER_PRESENCE: u8 = 0x01;
pub const FLAG_USER_VERIFIED: u8 = 0x02;
#[allow(dead_code)]
pub const FLAG_RESIDENT_KEY: u8 = 0x04;

/// Supported FIDO2 / biometric hardware authenticator device types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fido2DeviceType {
    /// Physical FIDO2 USB/NFC security key (YubiKey, SoloKey, Nitrokey, Titan Key)
    Usb,
    /// Windows Hello platform biometric/PIN authenticator (TPM-backed)
    WindowsHello,
    /// Software-emulated / testing virtual hardware token
    Virtual,
}

impl Fido2DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::WindowsHello => "windows_hello",
            Self::Virtual => "virtual",
        }
    }

    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            1 => Ok(Self::Usb),
            2 => Ok(Self::WindowsHello),
            3 => Ok(Self::Virtual),
            other => Err(Error::Format(format!(
                "unknown hardware token device type id: {other}"
            ))),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Usb => 1,
            Self::WindowsHello => 2,
            Self::Virtual => 3,
        }
    }
}

impl std::str::FromStr for Fido2DeviceType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "usb" | "fido2" | "yubikey" => Ok(Self::Usb),
            "hello" | "windows_hello" | "windows-hello" | "tpm" | "biometric" => {
                Ok(Self::WindowsHello)
            }
            "virtual" | "sim" | "mock" | "software" => Ok(Self::Virtual),
            other => Err(Error::HardwareToken(format!(
                "invalid device type '{other}' (expected: usb, hello, virtual)"
            ))),
        }
    }
}

/// Enrolled FIDO2 / Windows Hello hardware credential descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Credential {
    pub id: String,
    pub name: String,
    pub rp_id: String,
    pub user_name: String,
    pub device_type: Fido2DeviceType,
    pub created_at: u64,
    pub public_key_hex: String,
    pub prf_salt_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_seed_hex: Option<String>,
}

impl Fido2Credential {
    /// Retrieve the internal secret seed for HMAC-secret PRF derivation.
    pub fn secret_seed(&self) -> Result<Zeroizing<Vec<u8>>> {
        match &self.secret_seed_hex {
            Some(hex_str) => {
                let bytes = hex_decode(hex_str)?;
                Ok(Zeroizing::new(bytes))
            }
            None => Err(Error::HardwareToken(format!(
                "credential '{}' has no internal PRF secret seed configured",
                self.name
            ))),
        }
    }

    /// Save this credential descriptor to a JSON file.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| Error::HardwareToken(format!("serialization error: {e}")))?;
        fs::write(path, json.as_bytes())?;
        Ok(())
    }

    /// Load a credential descriptor from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let cred: Self = serde_json::from_str(&content)
            .map_err(|e| Error::HardwareToken(format!("deserialization error: {e}")))?;
        Ok(cred)
    }
}

/// Wire representation of FIDO2 hardware binding stored in `SVLT` container header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Header {
    pub device_type: Fido2DeviceType,
    pub flags: u8,
    pub credential_id: Vec<u8>,
    pub rp_id: String,
}

impl Fido2Header {
    pub fn new(device_type: Fido2DeviceType, credential_id: &[u8], rp_id: &str) -> Self {
        Self {
            device_type,
            flags: FLAG_USER_PRESENCE | FLAG_USER_VERIFIED,
            credential_id: credential_id.to_vec(),
            rp_id: rp_id.to_string(),
        }
    }

    /// Serialize header to binary format with IEEE 802.3 CRC-32 integrity tag.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.credential_id.len() + self.rp_id.len());
        buf.extend_from_slice(HEADER_MAGIC);
        buf.push(HEADER_VERSION);
        buf.push(self.device_type.to_u8());
        buf.push(self.flags);

        let cred_len = self.credential_id.len() as u16;
        buf.extend_from_slice(&cred_len.to_le_bytes());
        buf.extend_from_slice(&self.credential_id);

        let rp_bytes = self.rp_id.as_bytes();
        let rp_len = rp_bytes.len() as u16;
        buf.extend_from_slice(&rp_len.to_le_bytes());
        buf.extend_from_slice(rp_bytes);

        let mut hasher = Hasher::new();
        hasher.update(&buf);
        let checksum = hasher.finalize();
        buf.extend_from_slice(&checksum.to_le_bytes());

        buf
    }

    /// Parse binary FIDO2 header and verify CRC-32 integrity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Min length: 4 (magic) + 1 (ver) + 1 (type) + 1 (flags) + 2 (cred_len) + 2 (rp_len) + 4 (crc) = 15 bytes
        if bytes.len() < 15 {
            return Err(Error::Format(
                "hardware token header truncated (smaller than min header)".into(),
            ));
        }

        let body_len = bytes.len() - 4;
        let expected_crc = u32::from_le_bytes(
            bytes[body_len..]
                .try_into()
                .map_err(|_| Error::Format("failed to read CRC-32".into()))?,
        );

        let mut hasher = Hasher::new();
        hasher.update(&bytes[..body_len]);
        let calculated_crc = hasher.finalize();

        if expected_crc != calculated_crc {
            return Err(Error::Format(format!(
                "hardware token header CRC-32 mismatch (computed: 0x{calculated_crc:08x}, expected: 0x{expected_crc:08x})"
            )));
        }

        if &bytes[0..4] != HEADER_MAGIC {
            return Err(Error::Format("invalid hardware token header magic".into()));
        }

        let version = bytes[4];
        if version != HEADER_VERSION {
            return Err(Error::Format(format!(
                "unsupported hardware token header version: {version}"
            )));
        }

        let device_type = Fido2DeviceType::from_u8(bytes[5])?;
        let flags = bytes[6];

        let mut offset = 7;
        let cred_len = u16::from_le_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .map_err(|_| Error::Format("failed to read credential id length".into()))?,
        ) as usize;
        offset += 2;

        if offset + cred_len > body_len {
            return Err(Error::Format(
                "hardware token header credential id out of bounds".into(),
            ));
        }
        let credential_id = bytes[offset..offset + cred_len].to_vec();
        offset += cred_len;

        if offset + 2 > body_len {
            return Err(Error::Format(
                "hardware token header rp_id length out of bounds".into(),
            ));
        }
        let rp_len = u16::from_le_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .map_err(|_| Error::Format("failed to read rp_id length".into()))?,
        ) as usize;
        offset += 2;

        if offset + rp_len > body_len {
            return Err(Error::Format(
                "hardware token header rp_id out of bounds".into(),
            ));
        }
        let rp_id = std::str::from_utf8(&bytes[offset..offset + rp_len])
            .map_err(|e| Error::Format(format!("invalid UTF-8 in rp_id: {e}")))?
            .to_string();

        Ok(Self {
            device_type,
            flags,
            credential_id,
            rp_id,
        })
    }
}

/// Helper function to locate default credentials registry file path.
pub fn default_registry_path() -> PathBuf {
    if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home)
            .join(".shadow-vault")
            .join("fido2_credentials.json")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".shadow-vault")
            .join("fido2_credentials.json")
    } else {
        PathBuf::from(".shadow-vault-fido2.json")
    }
}

/// Load list of registered credentials from registry file.
pub fn load_registry(path: &Path) -> Result<Vec<Fido2Credential>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    let creds: Vec<Fido2Credential> = serde_json::from_str(&content)
        .map_err(|e| Error::HardwareToken(format!("failed to parse credentials registry: {e}")))?;
    Ok(creds)
}

/// Save list of credentials to registry file.
pub fn save_registry(path: &Path, creds: &[Fido2Credential]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(creds)
        .map_err(|e| Error::HardwareToken(format!("serialization error: {e}")))?;
    fs::write(path, json.as_bytes())?;
    Ok(())
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
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
