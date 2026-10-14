// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Container Re-Key & Passphrase Rotation engine (`src/rotate.rs`).
//!
//! Provides atomic re-keying and passphrase rotation for `.svault` containers and
//! steganographic carriers (PNG, BMP, WAV, ASCII armor) with:
//! - Fresh 16-byte salt and 12-byte nonce generation via CSPRNG
//! - Windows DPAPI re-binding: preserve original state, or explicitly enable/disable
//! - Cryptographic policy preservation (PolicyHeader re-authenticated as ChaCha20-Poly1305 AAD)
//! - Optional policy removal via `--clear-policy`
//! - Atomic temporary file creation and replacement (`<path>.tmp.<rand>` -> atomic rename)
//! - Comprehensive zeroization of keys, passphrases, and decrypted buffers

use crate::armor;
use crate::bmp;
use crate::crypto::{
    self, FLAG_DECOY, FLAG_DPAPI, FLAG_POLICY, HEADER_LEN, MAGIC, SALT_LEN, VERSION, VERSION_V2,
};
use crate::error::{Error, Result};
use crate::mp3;
use crate::policy::PolicyHeader;
use crate::stego;
use crate::wav;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Options and credentials for container re-keying and passphrase rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateOptions<'a> {
    pub old_passphrase: Option<&'a str>,
    pub new_passphrase: Option<&'a str>,
    pub old_keyfile: Option<&'a Path>,
    pub new_keyfile: Option<&'a Path>,
    pub dpapi: bool,
    pub no_dpapi: bool,
    pub clear_policy: bool,
}

/// Internal cryptographic result from re-encrypting a container payload.
#[derive(Debug, Clone)]
pub struct RotateResult {
    pub new_container: Vec<u8>,
    pub payload_bytes: usize,
    pub old_dpapi_bound: bool,
    pub new_dpapi_bound: bool,
    pub policy_preserved: bool,
    pub policy_cleared: bool,
    pub new_salt_hex: String,
}

/// User-facing structured report summarizing rotation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateReport {
    pub status: String,
    pub command: String,
    pub carrier_type: String,
    pub input_path: String,
    pub output_path: String,
    pub in_place: bool,
    pub payload_bytes: usize,
    pub old_dpapi_bound: bool,
    pub new_dpapi_bound: bool,
    pub policy_preserved: bool,
    pub policy_cleared: bool,
    pub new_salt_hex: String,
}

/// Steganographic or binary carrier format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CarrierType {
    Vault,
    Png,
    Bmp,
    Wav,
    Armor,
    Mp3,
}

impl std::fmt::Display for CarrierType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vault => write!(f, "vault"),
            Self::Png => write!(f, "png"),
            Self::Bmp => write!(f, "bmp"),
            Self::Wav => write!(f, "wav"),
            Self::Armor => write!(f, "armor"),
            Self::Mp3 => write!(f, "mp3"),
        }
    }
}

/// Detect carrier type from raw file magic / signatures.
pub fn detect_carrier_type(data: &[u8]) -> CarrierType {
    if armor::is_armored(data) {
        CarrierType::Armor
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        CarrierType::Png
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        CarrierType::Wav
    } else if data.starts_with(b"BM") {
        CarrierType::Bmp
    } else if data.starts_with(b"ID3")
        || (data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0)
    {
        CarrierType::Mp3
    } else {
        CarrierType::Vault
    }
}

/// Re-key an in-memory `SVLT` container with fresh salt/nonce and updated credentials/policy.
pub fn rotate_container(container: &[u8], options: &RotateOptions) -> Result<RotateResult> {
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
        return Err(Error::Crypto(
            "decoy container rotation not supported; re-encrypt using encrypt-decoy".into(),
        ));
    }

    let old_dpapi_bound = (flags & FLAG_DPAPI) != 0;
    let old_salt = &container[6..6 + SALT_LEN];
    let old_nonce = &container[6 + SALT_LEN..HEADER_LEN];

    let (policy_wire, body_offset, old_policy) = if (flags & FLAG_POLICY) != 0 {
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
        let parsed = PolicyHeader::from_bytes(p_bytes)?;
        (Some(p_bytes), policy_end, Some(parsed))
    } else {
        (None, HEADER_LEN, None)
    };

    let body = &container[body_offset..];
    let ciphertext = if old_dpapi_bound {
        crypto::dpapi_unprotect(body)?
    } else {
        body.to_vec()
    };

    let old_key_material =
        crypto::resolve_key_material(options.old_passphrase, options.old_keyfile)?;
    let old_key = crypto::derive_key(&old_key_material, old_salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*old_key));
    let nonce = Nonce::from_slice(old_nonce);

    let mut plaintext = Zeroizing::new(match policy_wire {
        Some(pw) => {
            let payload = Payload {
                msg: ciphertext.as_ref(),
                aad: pw,
            };
            cipher.decrypt(nonce, payload).map_err(|_| {
                Error::Crypto(
                    "authentication failed — wrong passphrase or tampered container/policy".into(),
                )
            })?
        }
        None => cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
            Error::Crypto("authentication failed — wrong passphrase or tampered container".into())
        })?,
    });

    let payload_bytes = plaintext.len();

    let new_dpapi_bound = if options.dpapi {
        true
    } else if options.no_dpapi {
        false
    } else {
        old_dpapi_bound
    };

    let (new_policy, policy_preserved, policy_cleared) = if options.clear_policy {
        (None, false, old_policy.is_some())
    } else {
        let preserved = old_policy.is_some();
        (old_policy.as_ref(), preserved, false)
    };

    let new_container = crypto::seal_with_policy_and_keyfile(
        &plaintext,
        options.new_passphrase,
        options.new_keyfile,
        new_dpapi_bound,
        new_policy,
    )?;

    // Proactively zeroize decrypted plaintext buffer
    plaintext.zeroize();

    let new_salt = &new_container[6..6 + SALT_LEN];
    let new_salt_hex = new_salt
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    Ok(RotateResult {
        new_container,
        payload_bytes,
        old_dpapi_bound,
        new_dpapi_bound,
        policy_preserved,
        policy_cleared,
        new_salt_hex,
    })
}

/// Re-key a container or carrier file, auto-detecting format and atomically replacing the target.
pub fn rotate_carrier_file(
    input_path: &Path,
    output_path: &Path,
    options: &RotateOptions,
) -> Result<RotateReport> {
    let raw_bytes = fs::read(input_path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read input file {}: {e}", input_path.display()),
        ))
    })?;

    let carrier_type = detect_carrier_type(&raw_bytes);

    let inner_container = match carrier_type {
        CarrierType::Armor => {
            let text = std::str::from_utf8(&raw_bytes)
                .map_err(|_| Error::Format("armored container is not valid UTF-8".into()))?;
            armor::dearmor_data(text)?.to_vec()
        }
        CarrierType::Png => stego::extract_from_png(&raw_bytes)?,
        CarrierType::Bmp => bmp::extract_from_bmp(&raw_bytes)?,
        CarrierType::Wav => wav::extract_from_wav(&raw_bytes, wav::ExtractWavMode::Auto)?,
        CarrierType::Mp3 => mp3::extract_from_mp3(&raw_bytes, mp3::ExtractMp3Mode::Auto)?,
        CarrierType::Vault => raw_bytes.clone(),
    };

    let res = rotate_container(&inner_container, options)?;

    let final_bytes = match carrier_type {
        CarrierType::Vault => res.new_container,
        CarrierType::Png => stego::embed_in_png(&raw_bytes, &res.new_container)?,
        CarrierType::Bmp => bmp::embed_in_bmp(&raw_bytes, &res.new_container)?,
        CarrierType::Wav => {
            let mode = if wav::extract_from_wav_chunk(&raw_bytes).is_ok() {
                wav::WavMode::Chunk
            } else {
                wav::WavMode::Lsb
            };
            wav::embed_in_wav(&raw_bytes, &res.new_container, mode)?
        }
        CarrierType::Mp3 => {
            let mode = if mp3::extract_from_mp3(&raw_bytes, mp3::ExtractMp3Mode::Frame).is_ok() {
                mp3::Mp3Mode::Frame
            } else {
                mp3::Mp3Mode::Id3v2
            };
            mp3::embed_in_mp3(&raw_bytes, &res.new_container, mode)?
        }
        CarrierType::Armor => {
            let text = std::str::from_utf8(&raw_bytes)
                .map_err(|_| Error::Format("armored file is not valid UTF-8".into()))?;
            let (ds, ps) = if let Ok(meta) = armor::inspect_armor(text) {
                (meta.data_stripes, meta.parity_stripes)
            } else {
                (4, 2)
            };
            let armored_str = armor::armor_data(&res.new_container, ds, ps)?;
            armored_str.into_bytes()
        }
    };

    write_atomic(output_path, &final_bytes)?;

    Ok(RotateReport {
        status: "ok".into(),
        command: "rotate".into(),
        carrier_type: carrier_type.to_string(),
        input_path: input_path.display().to_string(),
        output_path: output_path.display().to_string(),
        in_place: input_path == output_path,
        payload_bytes: res.payload_bytes,
        old_dpapi_bound: res.old_dpapi_bound,
        new_dpapi_bound: res.new_dpapi_bound,
        policy_preserved: res.policy_preserved,
        policy_cleared: res.policy_cleared,
        new_salt_hex: res.new_salt_hex,
    })
}

/// Write `data` to `dest_path` atomically using a temporary file and rename.
pub fn write_atomic(dest_path: &Path, data: &[u8]) -> Result<()> {
    let parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
    let mut rng = rand::thread_rng();
    let rand_id: u64 = rng.gen();
    let file_stem = dest_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");
    let tmp_path = parent.join(format!("{file_stem}.tmp.{rand_id:016x}"));

    if let Err(e) = fs::write(&tmp_path, data) {
        let _ = fs::remove_file(&tmp_path);
        return Err(Error::Io(e));
    }

    if let Err(e) = fs::rename(&tmp_path, dest_path) {
        // Fallback for Windows if direct rename over existing target is blocked
        if dest_path.exists() {
            let _ = fs::remove_file(dest_path);
            if let Err(e2) = fs::rename(&tmp_path, dest_path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(Error::Io(std::io::Error::new(
                    e2.kind(),
                    format!(
                        "atomic replace failed for {}: {e2} (rename error: {e})",
                        dest_path.display()
                    ),
                )));
            }
        } else {
            let _ = fs::remove_file(&tmp_path);
            return Err(Error::Io(e));
        }
    }

    Ok(())
}
