// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod cli;
pub mod container;
pub mod encapsulate;
pub mod keys;

use crate::error::{Error, Result};
use base64::prelude::*;
use std::fs;
use std::path::Path;

#[allow(unused_imports)]
pub use container::{
    inspect_container, open_container, seal_container, PqInspectReport, SvpqHeader,
    MIN_CONTAINER_SIZE,
};
#[allow(unused_imports)]
pub use encapsulate::{
    decapsulate_hybrid, encapsulate_hybrid, EncapsulationResult, MLKEM768_CIPHERTEXT_SIZE,
};
#[allow(unused_imports)]
pub use keys::{
    HybridKeyPair, HybridPrivateKey, HybridPublicKey, ARMOR_FOOTER_PRIVKEY, ARMOR_FOOTER_PUBKEY,
    ARMOR_HEADER_PRIVKEY, ARMOR_HEADER_PUBKEY, HYBRID_PRIVATE_KEY_SIZE, HYBRID_PUBLIC_KEY_SIZE,
    MLKEM768_PUBLIC_KEY_SIZE, MLKEM768_SEED_SIZE, X25519_PRIVATE_KEY_SIZE, X25519_PUBLIC_KEY_SIZE,
};

pub const ARMOR_HEADER_CONTAINER: &str = "-----BEGIN SHADOW VAULT PQ CONTAINER-----";
pub const ARMOR_FOOTER_CONTAINER: &str = "-----END SHADOW VAULT PQ CONTAINER-----";

/// Seal a file into a post-quantum hybrid encrypted container (`SVPQ`), optionally ASCII armored.
pub fn seal_pq_vault<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    recipient_pk: &HybridPublicKey,
    armor: bool,
) -> Result<usize> {
    let plaintext = fs::read(input_path.as_ref()).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read input file: {e}"),
        ))
    })?;

    let mut rng = rand::thread_rng();
    let container_bytes = seal_container(&plaintext, recipient_pk, &mut rng)?;

    let out_data = if armor {
        armor_container(&container_bytes)
    } else {
        container_bytes
    };

    fs::write(output_path.as_ref(), &out_data).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to write container file: {e}"),
        ))
    })?;

    Ok(out_data.len())
}

/// Open an SVPQ post-quantum encrypted container (auto-detecting binary or ASCII armor) and write decrypted plaintext.
pub fn open_pq_vault<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    recipient_sk: &HybridPrivateKey,
) -> Result<usize> {
    let raw_input = fs::read(input_path.as_ref()).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read container file: {e}"),
        ))
    })?;

    let container_bytes = if let Ok(text) = std::str::from_utf8(&raw_input) {
        let trimmed = text.trim();
        if trimmed.starts_with(ARMOR_HEADER_CONTAINER) {
            dearmor_container(trimmed)?
        } else {
            raw_input
        }
    } else {
        raw_input
    };

    let plaintext = open_container(&container_bytes, recipient_sk)?;

    fs::write(output_path.as_ref(), &plaintext).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to write output file: {e}"),
        ))
    })?;

    Ok(plaintext.len())
}

/// Inspect an SVPQ container from a file path or raw buffer.
pub fn inspect_pq_vault<P: AsRef<Path>>(path: P) -> Result<PqInspectReport> {
    let raw_input = fs::read(path.as_ref()).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read container file: {e}"),
        ))
    })?;

    let container_bytes = if let Ok(text) = std::str::from_utf8(&raw_input) {
        let trimmed = text.trim();
        if trimmed.starts_with(ARMOR_HEADER_CONTAINER) {
            dearmor_container(trimmed)?
        } else {
            raw_input
        }
    } else {
        raw_input
    };

    inspect_container(&container_bytes)
}

fn armor_container(data: &[u8]) -> Vec<u8> {
    let b64 = BASE64_STANDARD.encode(data);
    let mut out = String::new();
    out.push_str(ARMOR_HEADER_CONTAINER);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push_str(ARMOR_FOOTER_CONTAINER);
    out.push('\n');
    out.into_bytes()
}

fn dearmor_container(armored: &str) -> Result<Vec<u8>> {
    let mut in_block = false;
    let mut b64_acc = String::new();

    for line in armored.lines() {
        let trimmed = line.trim();
        if trimmed == ARMOR_HEADER_CONTAINER {
            in_block = true;
            continue;
        }
        if trimmed == ARMOR_FOOTER_CONTAINER {
            break;
        }
        if in_block && !trimmed.is_empty() {
            b64_acc.push_str(trimmed);
        }
    }

    if b64_acc.is_empty() {
        return Err(Error::Format(
            "armored container header not found or empty".into(),
        ));
    }

    BASE64_STANDARD
        .decode(b64_acc.as_bytes())
        .map_err(|e| Error::Format(format!("failed to decode armored base64: {e}")))
}
