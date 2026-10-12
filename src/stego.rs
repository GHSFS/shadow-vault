// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Lossless PNG ancillary chunk steganography (`svLt` private critical-safe chunk).
//!
//! Embeds an encrypted `SVLT` container inside a standard PNG image right before
//! the terminal `IEND` chunk with a valid IEEE 802.3 CRC-32 checksum so the PNG
//! renders normally in all image viewers while carrying the hidden vault.

use crate::error::{Error, Result};

const PNG_SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const STEGO_CHUNK_TYPE: &[u8; 4] = b"svLt";
const IEND_CHUNK_TYPE: &[u8; 4] = b"IEND";

/// Embed `payload` into a valid PNG image right before the `IEND` chunk.
pub fn embed_in_png(png_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    validate_png(png_bytes)?;

    // Remove any existing `svLt` chunk first so re-embedding is idempotent.
    let clean_png = strip_stego_chunks(png_bytes)?;

    // Locate the terminal IEND chunk (last 12 bytes in standard PNGs, or scan chunks).
    let iend_offset = find_iend_offset(&clean_png)?;

    let mut out = Vec::with_capacity(clean_png.len() + 12 + payload.len());
    out.extend_from_slice(&clean_png[..iend_offset]);

    // Write `svLt` chunk: [length: u32 BE][type: "svLt"][data][crc32: u32 BE]
    let len_be = (payload.len() as u32).to_be_bytes();
    out.extend_from_slice(&len_be);
    out.extend_from_slice(STEGO_CHUNK_TYPE);
    out.extend_from_slice(payload);

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(STEGO_CHUNK_TYPE);
    hasher.update(payload);
    let crc = hasher.finalize().to_be_bytes();
    out.extend_from_slice(&crc);

    // Append original IEND chunk
    out.extend_from_slice(&clean_png[iend_offset..]);
    Ok(out)
}

/// Extract a hidden `svLt` payload from a PNG image and verify its CRC-32.
pub fn extract_from_png(png_bytes: &[u8]) -> Result<Vec<u8>> {
    validate_png(png_bytes)?;

    let mut offset = 8;
    while offset + 12 <= png_bytes.len() {
        let len = u32::from_be_bytes(
            png_bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| Error::Format("malformed PNG chunk length".into()))?,
        ) as usize;
        let chunk_type = &png_bytes[offset + 4..offset + 8];
        let data_start = offset + 8;
        let data_end = data_start.saturating_add(len);
        if data_end + 4 > png_bytes.len() {
            return Err(Error::Format("truncated PNG chunk data".into()));
        }
        let data = &png_bytes[data_start..data_end];
        let expected_crc = u32::from_be_bytes(
            png_bytes[data_end..data_end + 4]
                .try_into()
                .map_err(|_| Error::Format("malformed PNG chunk CRC".into()))?,
        );

        if chunk_type == STEGO_CHUNK_TYPE {
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(chunk_type);
            hasher.update(data);
            let actual_crc = hasher.finalize();
            if actual_crc != expected_crc {
                return Err(Error::Format(
                    "stego chunk CRC-32 mismatch (corrupted carrier)".into(),
                ));
            }
            return Ok(data.to_vec());
        }

        if chunk_type == IEND_CHUNK_TYPE {
            break;
        }
        offset = data_end + 4;
    }

    Err(Error::Format(
        "no hidden ShadowVault payload found in PNG".into(),
    ))
}

fn validate_png(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 20 || &bytes[0..8] != PNG_SIG {
        return Err(Error::Format("input file is not a valid PNG image".into()));
    }
    Ok(())
}

fn find_iend_offset(png_bytes: &[u8]) -> Result<usize> {
    let mut offset = 8;
    while offset + 12 <= png_bytes.len() {
        let len = u32::from_be_bytes(png_bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let chunk_type = &png_bytes[offset + 4..offset + 8];
        if chunk_type == IEND_CHUNK_TYPE {
            return Ok(offset);
        }
        let next = offset.saturating_add(12).saturating_add(len);
        if next > png_bytes.len() {
            break;
        }
        offset = next;
    }
    Err(Error::Format(
        "PNG image is missing an IEND terminator chunk".into(),
    ))
}

fn strip_stego_chunks(png_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(png_bytes.len());
    out.extend_from_slice(PNG_SIG);

    let mut offset = 8;
    while offset + 12 <= png_bytes.len() {
        let len = u32::from_be_bytes(png_bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let chunk_type = &png_bytes[offset + 4..offset + 8];
        let total_chunk = 12usize.saturating_add(len);
        if offset + total_chunk > png_bytes.len() {
            return Err(Error::Format("truncated PNG chunk while scanning".into()));
        }
        if chunk_type != STEGO_CHUNK_TYPE {
            out.extend_from_slice(&png_bytes[offset..offset + total_chunk]);
        }
        if chunk_type == IEND_CHUNK_TYPE {
            break;
        }
        offset += total_chunk;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_valid_png() -> Vec<u8> {
        // 1x1 transparent PNG
        vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR length + type
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
            0x15, 0xC4, 0x89, // IHDR data + CRC
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82, // IEND
        ]
    }

    #[test]
    fn png_embed_and_extract_roundtrip() {
        let carrier = minimal_valid_png();
        let secret = b"SVLT-hidden-payload-12345";
        let stego_png = embed_in_png(&carrier, secret).unwrap();

        let extracted = extract_from_png(&stego_png).unwrap();
        assert_eq!(extracted, secret);
    }

    #[test]
    fn re_embedding_replaces_previous_payload() {
        let carrier = minimal_valid_png();
        let first = embed_in_png(&carrier, b"first").unwrap();
        let second = embed_in_png(&first, b"second-updated").unwrap();

        let extracted = extract_from_png(&second).unwrap();
        assert_eq!(extracted, b"second-updated");
    }
}
