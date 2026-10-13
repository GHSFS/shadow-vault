// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Chunked Streaming Authenticated Encryption engine (`src/stream.rs`).
//!
//! Provides constant $O(1)$ memory authenticated streaming encryption for multi-GB files:
//! - Wire format: `MAGIC = b"SVST"`, `VERSION = 1`, `FLAGS` (DPAPI=0x01, Policy=0x04),
//!   `CHUNK_SIZE` (default 4 MiB), `SALT` (16 bytes), `BASE_NONCE` (12 bytes).
//! - Windows DPAPI stream key protection (`FLAG_DPAPI`): derive Argon2id master key,
//!   generate random 32-byte stream key, wrap with ChaCha20-Poly1305 + DPAPI in header
//!   so the streaming loop executes zero DPAPI calls per chunk with constant $O(1)$ RAM.
//! - Per-chunk nonce derivation:
//!   `Sha256(b"shadow-vault:stream-chunk-nonce:v1" || base_nonce || chunk_index.to_le_bytes() || [chunk_tag])[0..12]`.
//! - Per-chunk AAD binding:
//!   `b"SVST"` || `chunk_index.to_le_bytes()` || `[chunk_tag]` || `salt` || `policy_hash`
//!   (binds sequential index, finality tag, salt, and policy to prevent reorder/truncation).
//! - Two-buffer sliding window handles 0-byte streams, small files, exact chunk multiples,
//!   and multi-gigabyte streams without extra allocations.
//! - Proactive memory zeroization via `zeroize::Zeroizing`.

use crate::crypto::{self, resolve_key_material};
use crate::error::{Error, Result};
use crate::policy::PolicyHeader;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 4] = b"SVST";
pub const VERSION: u8 = 1;
pub const FLAG_DPAPI: u8 = 0x01;
pub const FLAG_POLICY: u8 = 0x04;

pub const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB (4,194,304 bytes)
pub const MIN_CHUNK_SIZE: u32 = 1024; // 1 KiB
pub const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024; // 64 MiB

pub const SALT_LEN: usize = 16;
pub const BASE_NONCE_LEN: usize = 12;
pub const BASE_HEADER_LEN: usize = 4 + 1 + 1 + 4 + SALT_LEN + BASE_NONCE_LEN; // 38 bytes

pub const CHUNK_TAG_INTERMEDIATE: u8 = 0x00;
pub const CHUNK_TAG_FINAL: u8 = 0x01;

/// Metadata information about a streaming container header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamInfo {
    pub version: u8,
    pub dpapi_bound: bool,
    pub chunk_size: u32,
    pub salt_hex: String,
    pub base_nonce_hex: String,
    pub policy: Option<PolicyHeader>,
    pub wrapped_key_bytes: usize,
}

/// Execution summary of a stream encryption or decryption run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamSummary {
    pub total_chunks: u64,
    pub total_plaintext_bytes: u64,
    pub total_ciphertext_bytes: u64,
    pub chunk_size: u32,
    pub dpapi_bound: bool,
    pub salt_hex: String,
}

/// Parse a human-friendly chunk size string (e.g. "4m", "64k", "1048576").
pub fn parse_chunk_size(s: &str) -> Result<u32> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(Error::Format("chunk size cannot be empty".into()));
    }
    let (num_str, multiplier) = if trimmed.ends_with(['k', 'K']) {
        (&trimmed[..trimmed.len() - 1], 1024u32)
    } else if trimmed.ends_with(['m', 'M']) {
        (&trimmed[..trimmed.len() - 1], 1024 * 1024u32)
    } else if trimmed.ends_with(['g', 'G']) {
        (&trimmed[..trimmed.len() - 1], 1024 * 1024 * 1024u32)
    } else {
        (trimmed, 1u32)
    };
    let val: u32 = num_str
        .trim()
        .parse()
        .map_err(|_| Error::Format(format!("invalid chunk size: {s}")))?;
    let total = val
        .checked_mul(multiplier)
        .ok_or_else(|| Error::Format(format!("chunk size overflow: {s}")))?;
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&total) {
        return Err(Error::Format(format!(
            "chunk size {total} out of bounds ({MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE})"
        )));
    }
    Ok(total)
}

/// Derive per-chunk 12-byte Nonce from base nonce, sequential index, and finality tag.
fn derive_chunk_nonce(base_nonce: &[u8; 12], chunk_index: u64, chunk_tag: u8) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(b"shadow-vault:stream-chunk-nonce:v1");
    hasher.update(base_nonce);
    hasher.update(chunk_index.to_le_bytes());
    hasher.update([chunk_tag]);
    let digest = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

/// Assemble per-chunk Additional Authenticated Data (AAD) binding.
fn assemble_chunk_aad(
    chunk_index: u64,
    chunk_tag: u8,
    salt: &[u8; 16],
    policy_hash: &[u8; 32],
) -> [u8; 61] {
    let mut aad = [0u8; 61];
    aad[0..4].copy_from_slice(MAGIC);
    aad[4..12].copy_from_slice(&chunk_index.to_le_bytes());
    aad[12] = chunk_tag;
    aad[13..29].copy_from_slice(salt);
    aad[29..61].copy_from_slice(policy_hash);
    aad
}

/// Wrap a 32-byte stream key using ChaCha20-Poly1305 and optional Windows DPAPI.
fn wrap_stream_key(
    master_key: &[u8; 32],
    base_nonce: &[u8; 12],
    salt: &[u8; 16],
    bind_dpapi: bool,
) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>)> {
    if !bind_dpapi {
        let mut hasher = Sha256::new();
        hasher.update(b"shadow-vault:stream-key:v1");
        hasher.update(master_key);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hasher.finalize());
        return Ok((key, Vec::new()));
    }

    let mut stream_key = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(stream_key.as_mut());

    let mut wrap_nonce_hasher = Sha256::new();
    wrap_nonce_hasher.update(b"shadow-vault:stream-wrap-nonce:v1");
    wrap_nonce_hasher.update(base_nonce);
    let wrap_nonce_bytes: [u8; 12] = wrap_nonce_hasher.finalize()[..12].try_into().unwrap();

    let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(master_key));
    let mut wrap_aad = Vec::with_capacity(4 + SALT_LEN);
    wrap_aad.extend_from_slice(b"SVST");
    wrap_aad.extend_from_slice(salt);

    let payload = Payload {
        msg: stream_key.as_slice(),
        aad: &wrap_aad,
    };
    let enc_key = Zeroizing::new(
        wrap_cipher
            .encrypt(Nonce::from_slice(&wrap_nonce_bytes), payload)
            .map_err(|_| Error::Crypto("failed to wrap stream key with master key".into()))?,
    );

    let dpapi_blob = crypto::dpapi_protect(&enc_key)?;
    Ok((stream_key, dpapi_blob))
}

/// Unprotect and unwrap the stream key from container header.
fn unwrap_stream_key(
    master_key: &[u8; 32],
    base_nonce: &[u8; 12],
    salt: &[u8; 16],
    wrapped_blob: &[u8],
    dpapi_bound: bool,
) -> Result<Zeroizing<[u8; 32]>> {
    if !dpapi_bound {
        let mut hasher = Sha256::new();
        hasher.update(b"shadow-vault:stream-key:v1");
        hasher.update(master_key);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hasher.finalize());
        return Ok(key);
    }

    let enc_key = Zeroizing::new(crypto::dpapi_unprotect(wrapped_blob)?);
    let mut wrap_nonce_hasher = Sha256::new();
    wrap_nonce_hasher.update(b"shadow-vault:stream-wrap-nonce:v1");
    wrap_nonce_hasher.update(base_nonce);
    let wrap_nonce_bytes: [u8; 12] = wrap_nonce_hasher.finalize()[..12].try_into().unwrap();

    let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(master_key));
    let mut wrap_aad = Vec::with_capacity(4 + SALT_LEN);
    wrap_aad.extend_from_slice(b"SVST");
    wrap_aad.extend_from_slice(salt);

    let payload = Payload {
        msg: enc_key.as_slice(),
        aad: &wrap_aad,
    };
    let mut plain_key = Zeroizing::new(
        wrap_cipher
            .decrypt(Nonce::from_slice(&wrap_nonce_bytes), payload)
            .map_err(|_| {
                Error::Crypto(
                    "authentication failed — invalid passphrase or tampered stream key".into(),
                )
            })?,
    );

    if plain_key.len() != 32 {
        return Err(Error::Crypto("unwrapped stream key length mismatch".into()));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain_key);
    plain_key.zeroize();
    Ok(key)
}

/// Read up to `buf.len()` bytes from reader into buffer, stopping only on EOF or buffer full.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Encrypt an arbitrary stream using sliding-window chunked AEAD with constant $O(1)$ memory.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    passphrase: Option<&str>,
    keyfile: Option<&Path>,
    bind_dpapi: bool,
    policy: Option<&PolicyHeader>,
    chunk_size: Option<u32>,
) -> Result<StreamSummary> {
    let chunk_sz = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    let key_material = resolve_key_material(passphrase, keyfile)?;

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; BASE_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut base_nonce);

    let master_key = crypto::derive_key(&key_material, &salt)?;
    let (stream_key, wrapped_key_blob) =
        wrap_stream_key(&master_key, &base_nonce, &salt, bind_dpapi)?;

    let mut flags = 0u8;
    if bind_dpapi {
        flags |= FLAG_DPAPI;
    }
    let (policy_wire, policy_hash) = match policy {
        Some(p) => {
            flags |= FLAG_POLICY;
            let bytes = p.to_bytes();
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let mut h = [0u8; 32];
            h.copy_from_slice(&hasher.finalize());
            (Some(bytes), h)
        }
        None => (None, [0u8; 32]),
    };

    // Write Container Header
    let mut header = Vec::with_capacity(BASE_HEADER_LEN + 64);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(flags);
    header.extend_from_slice(&chunk_sz.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);

    if bind_dpapi {
        let wlen = wrapped_key_blob.len() as u32;
        header.extend_from_slice(&wlen.to_le_bytes());
        header.extend_from_slice(&wrapped_key_blob);
    }

    if let Some(ref pw) = policy_wire {
        let plen = pw.len() as u32;
        header.extend_from_slice(&plen.to_le_bytes());
        header.extend_from_slice(pw);
    }

    writer.write_all(&header)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(stream_key.as_slice()));
    let chunk_usize = chunk_sz as usize;

    let mut buf1 = Zeroizing::new(vec![0u8; chunk_usize]);
    let mut buf2 = Zeroizing::new(vec![0u8; chunk_usize]);

    let mut chunk_index: u64 = 0;
    let mut total_plain: u64 = 0;
    let mut total_cipher: u64 = header.len() as u64;

    let mut n1 = read_up_to(reader, buf1.as_mut_slice())?;

    if n1 < chunk_usize {
        // Single final chunk (covers 0-byte streams and payloads < chunk_sz)
        let nonce = derive_chunk_nonce(&base_nonce, chunk_index, CHUNK_TAG_FINAL);
        let aad = assemble_chunk_aad(chunk_index, CHUNK_TAG_FINAL, &salt, &policy_hash);
        let payload = Payload {
            msg: &buf1[..n1],
            aad: &aad,
        };
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| Error::Crypto("streaming chunk encryption failed".into()))?;

        let clen = ciphertext.len() as u32;
        writer.write_all(&clen.to_le_bytes())?;
        writer.write_all(&ciphertext)?;

        total_plain += n1 as u64;
        total_cipher += 4 + clen as u64;

        return Ok(StreamSummary {
            total_chunks: 1,
            total_plaintext_bytes: total_plain,
            total_ciphertext_bytes: total_cipher,
            chunk_size: chunk_sz,
            dpapi_bound: bind_dpapi,
            salt_hex: salt.iter().map(|b| format!("{b:02x}")).collect(),
        });
    }

    // Two-buffer sliding window loop for multi-chunk streams
    let mut n2 = read_up_to(reader, buf2.as_mut_slice())?;
    loop {
        let is_final = n2 == 0;
        let tag = if is_final {
            CHUNK_TAG_FINAL
        } else {
            CHUNK_TAG_INTERMEDIATE
        };
        let nonce = derive_chunk_nonce(&base_nonce, chunk_index, tag);
        let aad = assemble_chunk_aad(chunk_index, tag, &salt, &policy_hash);
        let payload = Payload {
            msg: &buf1[..n1],
            aad: &aad,
        };
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| Error::Crypto("streaming chunk encryption failed".into()))?;

        let clen = ciphertext.len() as u32;
        writer.write_all(&clen.to_le_bytes())?;
        writer.write_all(&ciphertext)?;

        total_plain += n1 as u64;
        total_cipher += 4 + clen as u64;
        chunk_index += 1;

        if is_final {
            break;
        }

        std::mem::swap(&mut buf1, &mut buf2);
        n1 = n2;
        if n1 < chunk_usize {
            n2 = 0;
        } else {
            n2 = read_up_to(reader, buf2.as_mut_slice())?;
        }
    }

    Ok(StreamSummary {
        total_chunks: chunk_index,
        total_plaintext_bytes: total_plain,
        total_ciphertext_bytes: total_cipher,
        chunk_size: chunk_sz,
        dpapi_bound: bind_dpapi,
        salt_hex: salt.iter().map(|b| format!("{b:02x}")).collect(),
    })
}

/// Decrypt an authenticated chunked streaming container with constant $O(1)$ memory.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    passphrase: Option<&str>,
    keyfile: Option<&Path>,
    at_time: Option<u64>,
) -> Result<StreamSummary> {
    let mut base_hdr = [0u8; BASE_HEADER_LEN];
    reader.read_exact(&mut base_hdr).map_err(|_| {
        Error::Format("container truncated: header shorter than minimum wire format".into())
    })?;

    if &base_hdr[0..4] != MAGIC {
        return Err(Error::Format(
            "invalid streaming container magic (expected SVST)".into(),
        ));
    }
    let version = base_hdr[4];
    if version != VERSION {
        return Err(Error::Format(format!(
            "unsupported streaming container version: {version}"
        )));
    }
    let flags = base_hdr[5];
    let dpapi_bound = (flags & FLAG_DPAPI) != 0;
    let has_policy = (flags & FLAG_POLICY) != 0;

    let chunk_size = u32::from_le_bytes(base_hdr[6..10].try_into().unwrap());
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(Error::Format(format!(
            "invalid container chunk size: {chunk_size}"
        )));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&base_hdr[10..26]);
    let mut base_nonce = [0u8; BASE_NONCE_LEN];
    base_nonce.copy_from_slice(&base_hdr[26..38]);

    let mut header_read_bytes = BASE_HEADER_LEN;

    let wrapped_key_blob = if dpapi_bound {
        let mut len_bytes = [0u8; 4];
        reader
            .read_exact(&mut len_bytes)
            .map_err(|_| Error::Format("truncated DPAPI wrapped key length".into()))?;
        let klen = u32::from_le_bytes(len_bytes) as usize;
        if klen > 65536 {
            return Err(Error::Format("DPAPI wrapped key exceeds max length".into()));
        }
        let mut blob = vec![0u8; klen];
        reader
            .read_exact(&mut blob)
            .map_err(|_| Error::Format("truncated DPAPI wrapped key blob".into()))?;
        header_read_bytes += 4 + klen;
        blob
    } else {
        Vec::new()
    };

    let (policy_wire, policy_hash) = if has_policy {
        let mut len_bytes = [0u8; 4];
        reader
            .read_exact(&mut len_bytes)
            .map_err(|_| Error::Format("truncated policy header length".into()))?;
        let plen = u32::from_le_bytes(len_bytes) as usize;
        if plen > 1024 * 1024 {
            return Err(Error::Format("policy header exceeds maximum size".into()));
        }
        let mut pbytes = vec![0u8; plen];
        reader
            .read_exact(&mut pbytes)
            .map_err(|_| Error::Format("truncated policy header bytes".into()))?;
        header_read_bytes += 4 + plen;

        let policy = PolicyHeader::from_bytes(&pbytes)?;
        let check_time = at_time.unwrap_or_else(crate::policy::current_utc_timestamp);
        policy.validate_at(check_time)?;

        let mut hasher = Sha256::new();
        hasher.update(&pbytes);
        let mut h = [0u8; 32];
        h.copy_from_slice(&hasher.finalize());
        (Some(policy), h)
    } else {
        (None, [0u8; 32])
    };
    let _ = policy_wire; // keep reference alive

    let key_material = resolve_key_material(passphrase, keyfile)?;
    let master_key = crypto::derive_key(&key_material, &salt)?;
    let stream_key = unwrap_stream_key(
        &master_key,
        &base_nonce,
        &salt,
        &wrapped_key_blob,
        dpapi_bound,
    )?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(stream_key.as_slice()));
    let max_cipher_chunk = (chunk_size as usize) + 16;
    let mut cipher_buf = Zeroizing::new(vec![0u8; max_cipher_chunk]);

    let mut chunk_index: u64 = 0;
    let mut total_plain: u64 = 0;
    let mut total_cipher: u64 = header_read_bytes as u64;
    let mut seen_final = false;

    loop {
        let mut len_bytes = [0u8; 4];
        match reader.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                if seen_final {
                    break;
                }
                return Err(Error::Format(
                    "stream truncated: unexpected EOF before final chunk".into(),
                ));
            }
            Err(e) => return Err(Error::Io(e)),
        }

        if seen_final {
            return Err(Error::Format(
                "trailing data detected after final chunk marker".into(),
            ));
        }

        let clen = u32::from_le_bytes(len_bytes) as usize;
        if clen < 16 || clen > max_cipher_chunk {
            return Err(Error::Format(format!(
                "invalid chunk length {clen} (expected 16..={max_cipher_chunk})"
            )));
        }

        let cipher_slice = &mut cipher_buf[..clen];
        reader.read_exact(cipher_slice).map_err(|_| {
            Error::Format(format!(
                "stream truncated within chunk {chunk_index} payload"
            ))
        })?;

        // Authenticate chunk: try intermediate or final tag
        let (mut plain, is_final) = if clen < max_cipher_chunk {
            // Must be final chunk because intermediate chunks are always full
            let nonce = derive_chunk_nonce(&base_nonce, chunk_index, CHUNK_TAG_FINAL);
            let aad = assemble_chunk_aad(chunk_index, CHUNK_TAG_FINAL, &salt, &policy_hash);
            let p = cipher
                .decrypt(Nonce::from_slice(&nonce), Payload {
                    msg: cipher_slice,
                    aad: &aad,
                })
                .map_err(|_| {
                    Error::Crypto(format!(
                        "authentication failed on chunk {chunk_index} — wrong passphrase or tampered data"
                    ))
                })?;
            (p, true)
        } else {
            // Full chunk size: could be intermediate or exact-multiple final chunk
            let nonce_inter = derive_chunk_nonce(&base_nonce, chunk_index, CHUNK_TAG_INTERMEDIATE);
            let aad_inter =
                assemble_chunk_aad(chunk_index, CHUNK_TAG_INTERMEDIATE, &salt, &policy_hash);
            match cipher.decrypt(
                Nonce::from_slice(&nonce_inter),
                Payload {
                    msg: cipher_slice,
                    aad: &aad_inter,
                },
            ) {
                Ok(p) => (p, false),
                Err(_) => {
                    let nonce_final = derive_chunk_nonce(&base_nonce, chunk_index, CHUNK_TAG_FINAL);
                    let aad_final =
                        assemble_chunk_aad(chunk_index, CHUNK_TAG_FINAL, &salt, &policy_hash);
                    let p = cipher
                        .decrypt(Nonce::from_slice(&nonce_final), Payload {
                            msg: cipher_slice,
                            aad: &aad_final,
                        })
                        .map_err(|_| {
                            Error::Crypto(format!(
                                "authentication failed on chunk {chunk_index} — wrong passphrase or tampered data"
                            ))
                        })?;
                    (p, true)
                }
            }
        };

        writer.write_all(&plain)?;
        total_plain += plain.len() as u64;
        plain.zeroize();
        total_cipher += 4 + clen as u64;
        chunk_index += 1;

        if is_final {
            seen_final = true;
            let mut trailing_check = [0u8; 1];
            if let Ok(n) = reader.read(&mut trailing_check) {
                if n > 0 {
                    return Err(Error::Format(
                        "trailing unauthenticated data detected after final chunk".into(),
                    ));
                }
            }
            break;
        }
    }

    if !seen_final {
        return Err(Error::Format(
            "stream truncated: no final chunk marker reached".into(),
        ));
    }

    Ok(StreamSummary {
        total_chunks: chunk_index,
        total_plaintext_bytes: total_plain,
        total_ciphertext_bytes: total_cipher,
        chunk_size,
        dpapi_bound,
        salt_hex: salt.iter().map(|b| format!("{b:02x}")).collect(),
    })
}

/// Inspect a streaming container header without decrypting chunks.
pub fn inspect_stream<R: Read>(reader: &mut R) -> Result<StreamInfo> {
    let mut base_hdr = [0u8; BASE_HEADER_LEN];
    reader
        .read_exact(&mut base_hdr)
        .map_err(|_| Error::Format("container truncated: header shorter than 38 bytes".into()))?;

    if &base_hdr[0..4] != MAGIC {
        return Err(Error::Format(
            "invalid streaming container magic (expected SVST)".into(),
        ));
    }
    let version = base_hdr[4];
    if version != VERSION {
        return Err(Error::Format(format!(
            "unsupported streaming container version: {version}"
        )));
    }
    let flags = base_hdr[5];
    let dpapi_bound = (flags & FLAG_DPAPI) != 0;
    let has_policy = (flags & FLAG_POLICY) != 0;
    let chunk_size = u32::from_le_bytes(base_hdr[6..10].try_into().unwrap());

    let salt = &base_hdr[10..26];
    let base_nonce = &base_hdr[26..38];

    let wrapped_key_bytes = if dpapi_bound {
        let mut len_bytes = [0u8; 4];
        reader
            .read_exact(&mut len_bytes)
            .map_err(|_| Error::Format("truncated DPAPI wrapped key length".into()))?;
        let klen = u32::from_le_bytes(len_bytes) as usize;
        let mut skip_buf = vec![0u8; klen];
        reader
            .read_exact(&mut skip_buf)
            .map_err(|_| Error::Format("truncated DPAPI wrapped key bytes".into()))?;
        klen
    } else {
        0
    };

    let policy = if has_policy {
        let mut len_bytes = [0u8; 4];
        reader
            .read_exact(&mut len_bytes)
            .map_err(|_| Error::Format("truncated policy header length".into()))?;
        let plen = u32::from_le_bytes(len_bytes) as usize;
        let mut pbytes = vec![0u8; plen];
        reader
            .read_exact(&mut pbytes)
            .map_err(|_| Error::Format("truncated policy header bytes".into()))?;
        Some(PolicyHeader::from_bytes(&pbytes)?)
    } else {
        None
    };

    Ok(StreamInfo {
        version,
        dpapi_bound,
        chunk_size,
        salt_hex: salt.iter().map(|b| format!("{b:02x}")).collect(),
        base_nonce_hex: base_nonce.iter().map(|b| format!("{b:02x}")).collect(),
        policy,
        wrapped_key_bytes,
    })
}

/// Encrypt an input file into an authenticated streaming container on disk.
pub fn encrypt_file_stream(
    input_path: &Path,
    output_path: &Path,
    passphrase: Option<&str>,
    keyfile: Option<&Path>,
    bind_dpapi: bool,
    policy: Option<&PolicyHeader>,
    chunk_size: Option<u32>,
) -> Result<StreamSummary> {
    let input_file = File::open(input_path).map_err(Error::Io)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, input_file);

    let output_file = File::create(output_path).map_err(Error::Io)?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, output_file);

    let summary = encrypt_stream(
        &mut reader,
        &mut writer,
        passphrase,
        keyfile,
        bind_dpapi,
        policy,
        chunk_size,
    )?;
    writer.flush().map_err(Error::Io)?;
    Ok(summary)
}

/// Decrypt an authenticated streaming container file on disk.
pub fn decrypt_file_stream(
    input_path: &Path,
    output_path: &Path,
    passphrase: Option<&str>,
    keyfile: Option<&Path>,
    at_time: Option<u64>,
) -> Result<StreamSummary> {
    let input_file = File::open(input_path).map_err(Error::Io)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, input_file);

    let output_file = File::create(output_path).map_err(Error::Io)?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, output_file);

    let summary = decrypt_stream(&mut reader, &mut writer, passphrase, keyfile, at_time)?;
    writer.flush().map_err(Error::Io)?;
    Ok(summary)
}

/// Inspect an authenticated streaming container file on disk.
pub fn inspect_stream_file(path: &Path) -> Result<StreamInfo> {
    let file = File::open(path).map_err(Error::Io)?;
    let mut reader = BufReader::new(file);
    inspect_stream(&mut reader)
}
