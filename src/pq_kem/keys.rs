// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Error, Result};
use base64::prelude::*;
use ml_kem::kem::KeyExport;
use ml_kem::{DecapsulationKey768, EncapsulationKey768, Seed};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;
pub const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;
pub const MLKEM768_SEED_SIZE: usize = 64;

pub const HYBRID_PUBLIC_KEY_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM768_PUBLIC_KEY_SIZE; // 1216
pub const HYBRID_PRIVATE_KEY_SIZE: usize = X25519_PRIVATE_KEY_SIZE + MLKEM768_SEED_SIZE; // 96

pub const ARMOR_HEADER_PUBKEY: &str = "-----BEGIN SHADOW VAULT KEM PUBLIC KEY-----";
pub const ARMOR_FOOTER_PUBKEY: &str = "-----END SHADOW VAULT KEM PUBLIC KEY-----";
pub const ARMOR_HEADER_PRIVKEY: &str = "-----BEGIN SHADOW VAULT KEM PRIVATE KEY-----";
pub const ARMOR_FOOTER_PRIVKEY: &str = "-----END SHADOW VAULT KEM PRIVATE KEY-----";

/// Recipient post-quantum hybrid public key (X25519 [32B] + ML-KEM-768 [1184B]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicKey {
    pub x25519_pk: [u8; X25519_PUBLIC_KEY_SIZE],
    pub mlkem_ek: [u8; MLKEM768_PUBLIC_KEY_SIZE],
}

impl HybridPublicKey {
    pub fn new(
        x25519_pk: [u8; X25519_PUBLIC_KEY_SIZE],
        mlkem_ek: [u8; MLKEM768_PUBLIC_KEY_SIZE],
    ) -> Result<Self> {
        // Verify ML-KEM public key validity
        EncapsulationKey768::new(&mlkem_ek.into())
            .map_err(|_| Error::Kem("invalid ML-KEM-768 public key encoding".into()))?;

        Ok(Self {
            x25519_pk,
            mlkem_ek,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PUBLIC_KEY_SIZE);
        out.extend_from_slice(&self.x25519_pk);
        out.extend_from_slice(&self.mlkem_ek);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_PUBLIC_KEY_SIZE {
            return Err(Error::Kem(format!(
                "invalid hybrid public key length: expected {}, got {}",
                HYBRID_PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }
        let mut x25519_pk = [0u8; X25519_PUBLIC_KEY_SIZE];
        let mut mlkem_ek = [0u8; MLKEM768_PUBLIC_KEY_SIZE];
        x25519_pk.copy_from_slice(&bytes[..X25519_PUBLIC_KEY_SIZE]);
        mlkem_ek.copy_from_slice(&bytes[X25519_PUBLIC_KEY_SIZE..]);

        Self::new(x25519_pk, mlkem_ek)
    }

    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.to_bytes());
        let hex_str: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        format!("SHA256:{}", hex_str)
    }

    pub fn to_armored(&self) -> String {
        format_armored(ARMOR_HEADER_PUBKEY, ARMOR_FOOTER_PUBKEY, &self.to_bytes())
    }

    pub fn from_armored_or_raw(input: &[u8]) -> Result<Self> {
        if let Ok(text) = std::str::from_utf8(input) {
            let trimmed = text.trim();
            if trimmed.starts_with(ARMOR_HEADER_PUBKEY) {
                let payload = parse_armored(ARMOR_HEADER_PUBKEY, ARMOR_FOOTER_PUBKEY, trimmed)?;
                return Self::from_bytes(&payload);
            }
        }
        Self::from_bytes(input)
    }
}

/// Recipient post-quantum hybrid private key (X25519 secret [32B] + ML-KEM-768 seed [64B]).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridPrivateKey {
    pub x25519_sk: [u8; X25519_PRIVATE_KEY_SIZE],
    pub mlkem_seed: [u8; MLKEM768_SEED_SIZE],
}

impl HybridPrivateKey {
    pub fn new(
        x25519_sk: [u8; X25519_PRIVATE_KEY_SIZE],
        mlkem_seed: [u8; MLKEM768_SEED_SIZE],
    ) -> Self {
        Self {
            x25519_sk,
            mlkem_seed,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PRIVATE_KEY_SIZE);
        out.extend_from_slice(&self.x25519_sk);
        out.extend_from_slice(&self.mlkem_seed);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_PRIVATE_KEY_SIZE {
            return Err(Error::Kem(format!(
                "invalid hybrid private key length: expected {}, got {}",
                HYBRID_PRIVATE_KEY_SIZE,
                bytes.len()
            )));
        }
        let mut x25519_sk = [0u8; X25519_PRIVATE_KEY_SIZE];
        let mut mlkem_seed = [0u8; MLKEM768_SEED_SIZE];
        x25519_sk.copy_from_slice(&bytes[..X25519_PRIVATE_KEY_SIZE]);
        mlkem_seed.copy_from_slice(&bytes[X25519_PRIVATE_KEY_SIZE..]);

        Ok(Self {
            x25519_sk,
            mlkem_seed,
        })
    }

    pub fn public_key(&self) -> HybridPublicKey {
        let secret = StaticSecret::from(self.x25519_sk);
        let x25519_pk: X25519PublicKey = (&secret).into();

        let seed: Seed = self.mlkem_seed.into();
        let dk = DecapsulationKey768::from_seed(seed);
        let ek = dk.encapsulation_key();
        let ek_bytes = ek.to_bytes();

        let mut mlkem_ek = [0u8; MLKEM768_PUBLIC_KEY_SIZE];
        mlkem_ek.copy_from_slice(&ek_bytes);

        HybridPublicKey {
            x25519_pk: *x25519_pk.as_bytes(),
            mlkem_ek,
        }
    }

    pub fn to_armored(&self) -> String {
        format_armored(ARMOR_HEADER_PRIVKEY, ARMOR_FOOTER_PRIVKEY, &self.to_bytes())
    }

    pub fn from_armored_or_raw(input: &[u8]) -> Result<Self> {
        if let Ok(text) = std::str::from_utf8(input) {
            let trimmed = text.trim();
            if trimmed.starts_with(ARMOR_HEADER_PRIVKEY) {
                let payload = parse_armored(ARMOR_HEADER_PRIVKEY, ARMOR_FOOTER_PRIVKEY, trimmed)?;
                return Self::from_bytes(&payload);
            }
        }
        Self::from_bytes(input)
    }
}

/// A complete hybrid keypair holding both public and private components.
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    pub private_key: HybridPrivateKey,
}

impl HybridKeyPair {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut x25519_sk = [0u8; X25519_PRIVATE_KEY_SIZE];
        rng.fill_bytes(&mut x25519_sk);

        let mut mlkem_seed = [0u8; MLKEM768_SEED_SIZE];
        rng.fill_bytes(&mut mlkem_seed);

        let private_key = HybridPrivateKey::new(x25519_sk, mlkem_seed);
        let public_key = private_key.public_key();

        Self {
            public_key,
            private_key,
        }
    }
}

fn format_armored(header: &str, footer: &str, data: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(data);
    let mut out = String::new();
    out.push_str(header);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push_str(footer);
    out.push('\n');
    out
}

fn parse_armored(header: &str, footer: &str, armored: &str) -> Result<Vec<u8>> {
    let mut in_block = false;
    let mut b64_acc = String::new();

    for line in armored.lines() {
        let trimmed = line.trim();
        if trimmed == header {
            in_block = true;
            continue;
        }
        if trimmed == footer {
            break;
        }
        if in_block && !trimmed.is_empty() {
            b64_acc.push_str(trimmed);
        }
    }

    if b64_acc.is_empty() {
        return Err(Error::Kem(format!("armored block '{header}' not found")));
    }

    BASE64_STANDARD
        .decode(b64_acc.as_bytes())
        .map_err(|e| Error::Kem(format!("failed to decode armored base64: {e}")))
}
