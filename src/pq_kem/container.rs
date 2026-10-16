// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Error, Result};
use crate::pq_kem::encapsulate::{
    decapsulate_hybrid, encapsulate_hybrid, MLKEM768_CIPHERTEXT_SIZE,
};
use crate::pq_kem::keys::{HybridPrivateKey, HybridPublicKey, X25519_PUBLIC_KEY_SIZE};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use crc32fast::Hasher as Crc32Hasher;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub const MAGIC_SVPQ: &[u8; 4] = b"SVPQ";
pub const CURRENT_VERSION: u8 = 1;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const CRC_SIZE: usize = 4;

/// Header layout size:
/// Magic (4) + Version (1) + Flags (1) + Ephemeral PK (32) + ML-KEM CT (1088) + Nonce (12) + Length (8)
pub const HEADER_SIZE: usize =
    4 + 1 + 1 + X25519_PUBLIC_KEY_SIZE + MLKEM768_CIPHERTEXT_SIZE + NONCE_SIZE + 8; // 1146
pub const MIN_CONTAINER_SIZE: usize = HEADER_SIZE + TAG_SIZE + CRC_SIZE; // 1166

/// Parsed container header metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SvpqHeader {
    pub version: u8,
    pub flags: u8,
    pub ephemeral_x25519_pk: [u8; X25519_PUBLIC_KEY_SIZE],
    pub mlkem_ciphertext: [u8; MLKEM768_CIPHERTEXT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub plaintext_len: u64,
}

impl SvpqHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(MAGIC_SVPQ);
        out.push(self.version);
        out.push(self.flags);
        out.extend_from_slice(&self.ephemeral_x25519_pk);
        out.extend_from_slice(&self.mlkem_ciphertext);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.plaintext_len.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::Format(format!(
                "header too short: expected at least {} bytes, got {}",
                HEADER_SIZE,
                bytes.len()
            )));
        }

        if &bytes[0..4] != MAGIC_SVPQ {
            return Err(Error::Format(
                "invalid container magic: expected 'SVPQ'".into(),
            ));
        }

        let version = bytes[4];
        if version != CURRENT_VERSION {
            return Err(Error::Format(format!(
                "unsupported SVPQ version {version}; this binary supports version {CURRENT_VERSION}"
            )));
        }

        let flags = bytes[5];
        let mut ephemeral_x25519_pk = [0u8; X25519_PUBLIC_KEY_SIZE];
        ephemeral_x25519_pk.copy_from_slice(&bytes[6..6 + X25519_PUBLIC_KEY_SIZE]);

        let ct_start = 6 + X25519_PUBLIC_KEY_SIZE;
        let ct_end = ct_start + MLKEM768_CIPHERTEXT_SIZE;
        let mut mlkem_ciphertext = [0u8; MLKEM768_CIPHERTEXT_SIZE];
        mlkem_ciphertext.copy_from_slice(&bytes[ct_start..ct_end]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[ct_end..ct_end + NONCE_SIZE]);

        let len_start = ct_end + NONCE_SIZE;
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&bytes[len_start..len_start + 8]);
        let plaintext_len = u64::from_be_bytes(len_bytes);

        Ok(Self {
            version,
            flags,
            ephemeral_x25519_pk,
            mlkem_ciphertext,
            nonce,
            plaintext_len,
        })
    }
}

/// Inspection report for an SVPQ post-quantum container.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqInspectReport {
    pub valid_magic: bool,
    pub version: u8,
    pub flags: u8,
    pub ephemeral_x25519_pk_hex: String,
    pub mlkem_ciphertext_len: usize,
    pub plaintext_len: u64,
    pub total_container_bytes: usize,
    pub encrypted_payload_bytes: usize,
    pub crc32_valid: bool,
}

/// Inspect an SVPQ container without requiring decryption keys.
pub fn inspect_container(container_bytes: &[u8]) -> Result<PqInspectReport> {
    if container_bytes.len() < MIN_CONTAINER_SIZE {
        return Err(Error::Format(format!(
            "container too small: expected at least {} bytes, got {}",
            MIN_CONTAINER_SIZE,
            container_bytes.len()
        )));
    }

    let header = SvpqHeader::from_bytes(&container_bytes[..HEADER_SIZE])?;

    // Verify CRC-32
    let data_len = container_bytes.len() - CRC_SIZE;
    let mut hasher = Crc32Hasher::new();
    hasher.update(&container_bytes[..data_len]);
    let computed_crc = hasher.finalize();

    let mut expected_crc_bytes = [0u8; 4];
    expected_crc_bytes.copy_from_slice(&container_bytes[data_len..]);
    let expected_crc = u32::from_be_bytes(expected_crc_bytes);
    let crc32_valid = computed_crc == expected_crc;

    let hex_pk: String = header
        .ephemeral_x25519_pk
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let encrypted_payload_bytes = data_len - HEADER_SIZE;

    Ok(PqInspectReport {
        valid_magic: true,
        version: header.version,
        flags: header.flags,
        ephemeral_x25519_pk_hex: hex_pk,
        mlkem_ciphertext_len: header.mlkem_ciphertext.len(),
        plaintext_len: header.plaintext_len,
        total_container_bytes: container_bytes.len(),
        encrypted_payload_bytes,
        crc32_valid,
    })
}

/// Seal plaintext into a post-quantum hybrid encrypted container (`SVPQ` wire format).
pub fn seal_container<R: CryptoRng + RngCore>(
    plaintext: &[u8],
    recipient_pk: &HybridPublicKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    // 1. Generate hybrid key encapsulation
    let enc_res = encapsulate_hybrid(recipient_pk, rng)?;

    // 2. Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce_bytes);

    // 3. Assemble container header
    let header = SvpqHeader {
        version: CURRENT_VERSION,
        flags: 0,
        ephemeral_x25519_pk: enc_res.ephemeral_x25519_pk,
        mlkem_ciphertext: enc_res.mlkem_ciphertext,
        nonce: nonce_bytes,
        plaintext_len: plaintext.len() as u64,
    };
    let header_bytes = header.to_bytes();

    // 4. Authenticated AEAD Encryption (ChaCha20-Poly1305 with header as AAD)
    let cipher = ChaCha20Poly1305::new_from_slice(&*enc_res.shared_key)
        .map_err(|e| Error::Crypto(format!("failed to initialize ChaCha20Poly1305: {e}")))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad: &header_bytes,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| Error::Crypto(format!("hybrid AEAD encryption failed: {e}")))?;

    // 5. Compute CRC-32 over header + ciphertext
    let mut out = Vec::with_capacity(header_bytes.len() + ciphertext.len() + CRC_SIZE);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ciphertext);

    let mut hasher = Crc32Hasher::new();
    hasher.update(&out);
    let crc = hasher.finalize();
    out.extend_from_slice(&crc.to_be_bytes());

    Ok(out)
}

/// Open and authenticate an SVPQ container using the recipient private key.
pub fn open_container(container_bytes: &[u8], recipient_sk: &HybridPrivateKey) -> Result<Vec<u8>> {
    if container_bytes.len() < MIN_CONTAINER_SIZE {
        return Err(Error::Format(format!(
            "container too small: expected at least {} bytes, got {}",
            MIN_CONTAINER_SIZE,
            container_bytes.len()
        )));
    }

    // 1. Validate CRC-32 checksum before decryption
    let data_len = container_bytes.len() - CRC_SIZE;
    let mut hasher = Crc32Hasher::new();
    hasher.update(&container_bytes[..data_len]);
    let computed_crc = hasher.finalize();

    let mut expected_crc_bytes = [0u8; 4];
    expected_crc_bytes.copy_from_slice(&container_bytes[data_len..]);
    let expected_crc = u32::from_be_bytes(expected_crc_bytes);

    if computed_crc != expected_crc {
        return Err(Error::Format(format!(
            "CRC-32 checksum mismatch: computed 0x{computed_crc:08x}, expected 0x{expected_crc:08x} (container corrupted)"
        )));
    }

    // 2. Parse container header
    let header_bytes = &container_bytes[..HEADER_SIZE];
    let header = SvpqHeader::from_bytes(header_bytes)?;

    // 3. Decapsulate hybrid shared key
    let shared_key = decapsulate_hybrid(
        recipient_sk,
        &header.ephemeral_x25519_pk,
        &header.mlkem_ciphertext,
    )?;

    // 4. Authenticated AEAD Decryption
    let cipher = ChaCha20Poly1305::new_from_slice(&*shared_key)
        .map_err(|e| Error::Crypto(format!("failed to initialize ChaCha20Poly1305: {e}")))?;

    let nonce = Nonce::from_slice(&header.nonce);
    let ciphertext = &container_bytes[HEADER_SIZE..data_len];
    let payload = Payload {
        msg: ciphertext,
        aad: header_bytes,
    };

    let plaintext = cipher.decrypt(nonce, payload).map_err(|_| {
        Error::Crypto(
            "AEAD tag verification failed: incorrect private key or tampered container".into(),
        )
    })?;

    if plaintext.len() as u64 != header.plaintext_len {
        return Err(Error::Format(format!(
            "decrypted plaintext length mismatch: expected {} bytes, got {}",
            header.plaintext_len,
            plaintext.len()
        )));
    }

    Ok(plaintext)
}
