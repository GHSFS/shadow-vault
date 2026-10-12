// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! 24-bit uncompressed BMP pixel LSB steganography engine with constant-time CRC-32 validation.
//!
//! Embeds an encrypted `SVLT` container inside 24-bit uncompressed Windows BMP images (`BI_RGB`)
//! by modulating only the least significant bits (LSBs) of R, G, B color channels while
//! strictly respecting 4-byte row padding.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

pub const BMP_MAGIC: &[u8; 2] = b"BM";
pub const STEGO_MAGIC: &[u8; 4] = b"svLt";
pub const ENVELOPE_OVERHEAD_BYTES: usize = 12; // 4-byte magic + 4-byte len + 4-byte crc32
pub const MIN_BMP_HEADER_LEN: usize = 54;
pub const BI_RGB: u32 = 0;

/// Parsed metadata for a 24-bit uncompressed Windows BMP carrier image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmpHeader {
    pub file_size: u32,
    pub data_offset: usize,
    pub dib_header_size: u32,
    pub width: u32,
    pub height: u32,
    pub top_down: bool,
    pub planes: u16,
    pub bpp: u16,
    pub compression: u32,
    pub image_size: u32,
    pub row_stride: usize,
    pub row_padding: usize,
    pub channel_bytes: usize,
}

/// Steganographic storage capacity evaluation for a BMP image carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BmpCapacity {
    pub width: u32,
    pub height: u32,
    pub total_pixels: usize,
    pub channel_bytes: usize,
    pub row_stride: usize,
    pub row_padding: usize,
    pub total_capacity_bytes: usize,
    pub max_payload_bytes: usize,
    pub overhead_bytes: usize,
}

impl BmpCapacity {
    #[allow(dead_code)]
    pub fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    #[allow(dead_code)]
    pub fn total_capacity_bytes(&self) -> usize {
        self.total_capacity_bytes
    }
}

impl From<BmpCapacity> for usize {
    fn from(cap: BmpCapacity) -> Self {
        cap.max_payload_bytes
    }
}

impl PartialEq<usize> for BmpCapacity {
    fn eq(&self, other: &usize) -> bool {
        self.max_payload_bytes == *other
    }
}

impl PartialEq<BmpCapacity> for usize {
    fn eq(&self, other: &BmpCapacity) -> bool {
        *self == other.max_payload_bytes
    }
}

impl std::fmt::Display for BmpCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}x{} ({} pixels, payload capacity: {} bytes / {:.2} KiB, total bits: {})",
            self.width,
            self.height,
            self.total_pixels,
            self.max_payload_bytes,
            self.max_payload_bytes as f64 / 1024.0,
            self.channel_bytes
        )
    }
}

/// Parse and validate Windows 24-bit uncompressed BMP header structure.
pub fn parse_bmp_header(bytes: &[u8]) -> Result<BmpHeader> {
    if bytes.len() < MIN_BMP_HEADER_LEN {
        return Err(Error::Format(
            "input file is smaller than minimum BMP header (54 bytes)".into(),
        ));
    }
    if &bytes[0..2] != BMP_MAGIC {
        return Err(Error::Format(
            "input file is not a valid BMP image (missing 'BM' signature)".into(),
        ));
    }

    let file_size = u32::from_le_bytes(bytes[2..6].try_into().unwrap());
    let data_offset = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize;
    let dib_header_size = u32::from_le_bytes(bytes[14..18].try_into().unwrap());

    if dib_header_size < 40 {
        return Err(Error::Format(format!(
            "unsupported BMP DIB header size: {dib_header_size} bytes (minimum 40 bytes required)"
        )));
    }
    let min_offset = 14usize
        .checked_add(dib_header_size as usize)
        .ok_or_else(|| Error::Format("BMP DIB header size causes integer overflow".into()))?;
    if bytes.len() < min_offset {
        return Err(Error::Format(format!(
            "BMP file is truncated ({len} bytes, header requires at least {min_offset} bytes)",
            len = bytes.len()
        )));
    }
    if data_offset < min_offset {
        return Err(Error::Format(format!(
            "invalid BMP pixel data offset: {data_offset} (overlaps header)"
        )));
    }
    if data_offset > bytes.len() {
        return Err(Error::Format(
            "BMP pixel data offset exceeds file size (truncated file)".into(),
        ));
    }

    let width_raw = i32::from_le_bytes(bytes[18..22].try_into().unwrap());
    let height_raw = i32::from_le_bytes(bytes[22..26].try_into().unwrap());

    if width_raw <= 0 {
        return Err(Error::Format(format!(
            "invalid BMP width: {width_raw} (width must be positive)"
        )));
    }
    if height_raw == 0 {
        return Err(Error::Format(
            "invalid BMP height: 0 (height cannot be zero)".into(),
        ));
    }

    let width = width_raw as u32;
    let (height, top_down) = if height_raw < 0 {
        let h = height_raw
            .checked_abs()
            .ok_or_else(|| Error::Format("BMP height overflow".into()))?;
        (h as u32, true)
    } else {
        (height_raw as u32, false)
    };

    let planes = u16::from_le_bytes(bytes[26..28].try_into().unwrap());
    if planes != 1 {
        return Err(Error::Format(format!(
            "unsupported BMP color planes: {planes} (must be 1)"
        )));
    }

    let bpp = u16::from_le_bytes(bytes[28..30].try_into().unwrap());
    if bpp != 24 {
        return Err(Error::Format(format!(
            "unsupported BMP bit depth: {bpp} bpp (only 24-bit uncompressed BI_RGB is supported)"
        )));
    }

    let compression = u32::from_le_bytes(bytes[30..34].try_into().unwrap());
    if compression != BI_RGB {
        return Err(Error::Format(format!(
            "unsupported BMP compression: {compression} (only uncompressed BI_RGB is supported)"
        )));
    }

    let image_size = u32::from_le_bytes(bytes[34..38].try_into().unwrap());

    // Row stride: each row is padded to a multiple of 4 bytes
    // row_bytes = width * 3
    let row_bytes = (width as usize)
        .checked_mul(3)
        .ok_or_else(|| Error::Format("BMP dimensions cause integer overflow".into()))?;
    let row_padding = (4 - (row_bytes % 4)) % 4;
    let row_stride = row_bytes
        .checked_add(row_padding)
        .ok_or_else(|| Error::Format("BMP dimensions cause integer overflow".into()))?;

    let total_pixel_bytes = row_stride
        .checked_mul(height as usize)
        .ok_or_else(|| Error::Format("BMP dimensions cause integer overflow".into()))?;

    if data_offset
        .checked_add(total_pixel_bytes)
        .map_or(true, |end| end > bytes.len())
    {
        return Err(Error::Format(
            "BMP file is truncated (pixel data buffer incomplete)".into(),
        ));
    }

    let channel_bytes = (width as usize)
        .checked_mul(height as usize)
        .and_then(|px| px.checked_mul(3))
        .ok_or_else(|| Error::Format("BMP channel bytes overflow".into()))?;

    Ok(BmpHeader {
        file_size,
        data_offset,
        dib_header_size,
        width,
        height,
        top_down,
        planes,
        bpp,
        compression,
        image_size,
        row_stride,
        row_padding,
        channel_bytes,
    })
}

/// Calculate steganographic data storage capacity for a 24-bit uncompressed BMP carrier.
pub fn get_bmp_capacity(bmp_bytes: &[u8]) -> Result<BmpCapacity> {
    let header = parse_bmp_header(bmp_bytes)?;
    let total_pixels = (header.width as usize).saturating_mul(header.height as usize);
    let total_capacity_bytes = header.channel_bytes / 8;
    let max_payload_bytes = total_capacity_bytes.saturating_sub(ENVELOPE_OVERHEAD_BYTES);

    Ok(BmpCapacity {
        width: header.width,
        height: header.height,
        total_pixels,
        channel_bytes: header.channel_bytes,
        row_stride: header.row_stride,
        row_padding: header.row_padding,
        total_capacity_bytes,
        max_payload_bytes,
        overhead_bytes: ENVELOPE_OVERHEAD_BYTES,
    })
}

/// Embed an encrypted payload into a 24-bit uncompressed BMP carrier image using pixel LSB steganography.
///
/// Modulates only the least significant bits of the R, G, B color channels while respecting
/// 4-byte row padding. Uses a 12-byte envelope: `[magic "svLt": 4B][len: 4B LE][payload: NB][crc32: 4B LE]`.
pub fn embed_in_bmp(bmp_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let header = parse_bmp_header(bmp_bytes)?;

    if payload.len() > u32::MAX as usize {
        return Err(Error::Format("payload too large for BMP LSB header".into()));
    }

    let total_bytes_needed = ENVELOPE_OVERHEAD_BYTES.saturating_add(payload.len());
    let total_bits_needed = total_bytes_needed.saturating_mul(8);

    if header.channel_bytes < total_bits_needed {
        return Err(Error::Format(format!(
            "carrier BMP capacity insufficient for LSB embedding (need {total_bits_needed} bits, carrier has {channel_bytes} bits)",
            channel_bytes = header.channel_bytes
        )));
    }

    // Envelope structure: [magic: 4B][len: 4B LE][payload: NB][crc32: 4B LE]
    let crc = crc32fast::hash(payload);
    let mut envelope = Vec::with_capacity(total_bytes_needed);
    envelope.extend_from_slice(STEGO_MAGIC);
    envelope.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(&crc.to_le_bytes());

    let mut out = bmp_bytes.to_vec();
    let row_channel_bytes = (header.width as usize) * 3;

    for (byte_idx, &byte) in envelope.iter().enumerate() {
        for bit_idx in 0..8 {
            let channel_idx = byte_idx * 8 + bit_idx;
            let bit = (byte >> (7 - bit_idx)) & 1;

            let row = channel_idx / row_channel_bytes;
            let col = channel_idx % row_channel_bytes;
            let offset = header.data_offset + row * header.row_stride + col;

            out[offset] = (out[offset] & 0xFE) | bit;
        }
    }

    Ok(out)
}

/// Extract hidden payload from 24-bit uncompressed BMP carrier image and verify CRC-32 in constant-time.
pub fn extract_from_bmp(bmp_bytes: &[u8]) -> Result<Vec<u8>> {
    let header = parse_bmp_header(bmp_bytes)?;
    let row_channel_bytes = (header.width as usize) * 3;

    if header.channel_bytes < ENVELOPE_OVERHEAD_BYTES * 8 {
        return Err(Error::Format(
            "BMP image pixel data too small for LSB steganography".into(),
        ));
    }

    // Read header: 4 bytes magic + 4 bytes payload length (64 bits = 64 channel bytes)
    let mut header_bytes = [0u8; 8];
    for (byte_idx, item) in header_bytes.iter_mut().enumerate() {
        let mut b = 0u8;
        for bit_idx in 0..8 {
            let channel_idx = byte_idx * 8 + bit_idx;
            let row = channel_idx / row_channel_bytes;
            let col = channel_idx % row_channel_bytes;
            let offset = header.data_offset + row * header.row_stride + col;

            let bit = bmp_bytes[offset] & 1;
            b |= bit << (7 - bit_idx);
        }
        *item = b;
    }

    if &header_bytes[0..4] != STEGO_MAGIC {
        return Err(Error::Format(
            "no hidden ShadowVault payload found in BMP image carrier".into(),
        ));
    }

    let payload_len = u32::from_le_bytes(header_bytes[4..8].try_into().unwrap()) as usize;
    let total_bits_needed = ENVELOPE_OVERHEAD_BYTES
        .saturating_add(payload_len)
        .saturating_mul(8);

    if total_bits_needed > header.channel_bytes {
        return Err(Error::Format(
            "BMP LSB payload length exceeds carrier capacity (corrupted carrier)".into(),
        ));
    }

    // Read payload bytes
    let mut payload = Vec::with_capacity(payload_len);
    for byte_idx in 0..payload_len {
        let mut b = 0u8;
        for bit_idx in 0..8 {
            let channel_idx = (8 + byte_idx) * 8 + bit_idx;
            let row = channel_idx / row_channel_bytes;
            let col = channel_idx % row_channel_bytes;
            let offset = header.data_offset + row * header.row_stride + col;

            let bit = bmp_bytes[offset] & 1;
            b |= bit << (7 - bit_idx);
        }
        payload.push(b);
    }

    // Read 4-byte CRC-32 trailer
    let mut crc_bytes = [0u8; 4];
    for (byte_idx, item) in crc_bytes.iter_mut().enumerate() {
        let mut b = 0u8;
        for bit_idx in 0..8 {
            let channel_idx = (8 + payload_len + byte_idx) * 8 + bit_idx;
            let row = channel_idx / row_channel_bytes;
            let col = channel_idx % row_channel_bytes;
            let offset = header.data_offset + row * header.row_stride + col;

            let bit = bmp_bytes[offset] & 1;
            b |= bit << (7 - bit_idx);
        }
        *item = b;
    }

    let actual_crc = crc32fast::hash(&payload);
    let expected_crc_bytes = crc_bytes;
    let actual_crc_bytes = actual_crc.to_le_bytes();

    if !constant_time_eq_4(&expected_crc_bytes, &actual_crc_bytes) {
        return Err(Error::Format(
            "stego BMP LSB CRC-32 mismatch (corrupted carrier)".into(),
        ));
    }

    Ok(payload)
}

/// Constant-time comparison between two 4-byte arrays (prevents timing side-channel attacks on checksums).
#[inline(never)]
pub fn constant_time_eq_4(a: &[u8; 4], b: &[u8; 4]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Create a minimal valid 24-bit uncompressed BMP image buffer for testing.
///
/// Supports positive height (bottom-up standard DIB) and negative height (top-down DIB).
#[allow(dead_code)]
pub fn create_minimal_bmp(width: u32, height: u32) -> Vec<u8> {
    create_test_bmp_with_fill(width, height, 0x80, false)
}

/// Create a 24-bit uncompressed BMP with specified dimensions, fill byte, and top_down flag.
#[allow(dead_code)]
pub fn create_test_bmp_with_fill(
    width: u32,
    height: u32,
    fill_byte: u8,
    top_down: bool,
) -> Vec<u8> {
    let row_bytes = (width as usize) * 3;
    let row_padding = (4 - (row_bytes % 4)) % 4;
    let row_stride = row_bytes + row_padding;
    let pixel_data_size = row_stride * (height as usize);
    let file_size = (MIN_BMP_HEADER_LEN + pixel_data_size) as u32;

    let mut buf = Vec::with_capacity(file_size as usize);

    // BITMAPFILEHEADER (14 bytes)
    buf.extend_from_slice(BMP_MAGIC); // 0..2: bfType
    buf.extend_from_slice(&file_size.to_le_bytes()); // 2..6: bfSize
    buf.extend_from_slice(&0u16.to_le_bytes()); // 6..8: bfReserved1
    buf.extend_from_slice(&0u16.to_le_bytes()); // 8..10: bfReserved2
    buf.extend_from_slice(&(MIN_BMP_HEADER_LEN as u32).to_le_bytes()); // 10..14: bfOffBits

    // BITMAPINFOHEADER (40 bytes)
    buf.extend_from_slice(&40u32.to_le_bytes()); // 14..18: biSize
    buf.extend_from_slice(&(width as i32).to_le_bytes()); // 18..22: biWidth
    let h_signed = if top_down {
        -(height as i32)
    } else {
        height as i32
    };
    buf.extend_from_slice(&h_signed.to_le_bytes()); // 22..26: biHeight
    buf.extend_from_slice(&1u16.to_le_bytes()); // 26..28: biPlanes
    buf.extend_from_slice(&24u16.to_le_bytes()); // 28..30: biBitCount (24 bpp)
    buf.extend_from_slice(&BI_RGB.to_le_bytes()); // 30..34: biCompression (BI_RGB = 0)
    buf.extend_from_slice(&(pixel_data_size as u32).to_le_bytes()); // 34..38: biSizeImage
    buf.extend_from_slice(&2835u32.to_le_bytes()); // 38..42: biXPelsPerMeter (72 DPI)
    buf.extend_from_slice(&2835u32.to_le_bytes()); // 42..46: biYPelsPerMeter (72 DPI)
    buf.extend_from_slice(&0u32.to_le_bytes()); // 46..50: biClrUsed
    buf.extend_from_slice(&0u32.to_le_bytes()); // 50..54: biClrImportant

    // Pixel data with distinct pixel channel values and padding
    for r in 0..height {
        for c in 0..width {
            let pixel_val = fill_byte.wrapping_add((r * width + c) as u8);
            buf.push(pixel_val); // Blue
            buf.push(pixel_val.wrapping_add(1)); // Green
            buf.push(pixel_val.wrapping_add(2)); // Red
        }
        for pad_i in 0..row_padding {
            buf.push(0xAA ^ (pad_i as u8)); // Specific identifiable padding bytes
        }
    }

    buf
}

/// Create a 24-bit uncompressed BMP with specified DIB header size (e.g. 108 for V4, 124 for V5).
#[allow(dead_code)]
pub fn create_test_bmp_with_dib_size(width: u32, height: u32, dib_size: u32) -> Vec<u8> {
    let row_bytes = (width as usize) * 3;
    let row_padding = (4 - (row_bytes % 4)) % 4;
    let row_stride = row_bytes + row_padding;
    let pixel_data_size = row_stride * (height as usize);
    let data_offset = 14 + dib_size as usize;
    let file_size = (data_offset + pixel_data_size) as u32;

    let mut buf = Vec::with_capacity(file_size as usize);

    // BITMAPFILEHEADER (14 bytes)
    buf.extend_from_slice(BMP_MAGIC);
    buf.extend_from_slice(&file_size.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(data_offset as u32).to_le_bytes());

    // DIB header (dib_size bytes)
    buf.extend_from_slice(&dib_size.to_le_bytes());
    buf.extend_from_slice(&(width as i32).to_le_bytes());
    buf.extend_from_slice(&(height as i32).to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&24u16.to_le_bytes());
    buf.extend_from_slice(&BI_RGB.to_le_bytes());
    buf.extend_from_slice(&(pixel_data_size as u32).to_le_bytes());
    buf.extend_from_slice(&2835u32.to_le_bytes());
    buf.extend_from_slice(&2835u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    let written = 40;
    if (dib_size as usize) > written {
        buf.resize(buf.len() + ((dib_size as usize) - written), 0x5A);
    }

    // Pixel data
    for r in 0..height {
        for c in 0..width {
            let pixel_val = 0x80u8.wrapping_add((r * width + c) as u8);
            buf.push(pixel_val);
            buf.push(pixel_val.wrapping_add(1));
            buf.push(pixel_val.wrapping_add(2));
        }
        for pad_i in 0..row_padding {
            buf.push(0xAA ^ (pad_i as u8));
        }
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bmp_header_parsing_and_capacity_estimation() {
        let bmp = create_minimal_bmp(100, 50);
        let hdr = parse_bmp_header(&bmp).unwrap();
        assert_eq!(hdr.width, 100);
        assert_eq!(hdr.height, 50);
        assert_eq!(hdr.bpp, 24);
        assert!(!hdr.top_down);
        assert_eq!(hdr.row_stride, 300);
        assert_eq!(hdr.row_padding, 0);
        assert_eq!(hdr.channel_bytes, 15_000);

        let cap = get_bmp_capacity(&bmp).unwrap();
        assert_eq!(cap.total_pixels, 5_000);
        assert_eq!(cap.channel_bytes, 15_000);
        assert_eq!(cap.total_capacity_bytes, 15_000 / 8); // 1875
        assert_eq!(cap.max_payload_bytes, 1875 - 12); // 1863
        assert_eq!(cap, 1863usize);
    }

    #[test]
    fn bmp_row_padding_variations() {
        // Test all possible padding lengths: 0, 1, 2, 3 bytes
        for w in [4, 5, 6, 7] {
            let bmp = create_minimal_bmp(w, 8);
            let hdr = parse_bmp_header(&bmp).unwrap();
            let row_bytes = (w as usize) * 3;
            let expected_pad = (4 - (row_bytes % 4)) % 4;
            assert_eq!(hdr.row_padding, expected_pad);
            assert_eq!(hdr.row_stride, row_bytes + expected_pad);
        }
    }

    #[test]
    fn bmp_embed_and_extract_roundtrip() {
        let carrier = create_minimal_bmp(64, 64);
        let payload = b"Hello, 24-bit BMP pixel LSB steganography! ShadowVault secret container.";

        let stego = embed_in_bmp(&carrier, payload).unwrap();
        let extracted = extract_from_bmp(&stego).unwrap();

        assert_eq!(extracted, payload);
    }

    #[test]
    fn bmp_row_padding_bytes_strictly_preserved() {
        // 11x10 BMP: row_bytes = 33, row_padding = 3 bytes per row (330 channel bytes > 216 bits needed)
        let carrier = create_test_bmp_with_fill(11, 10, 0x55, false);
        let hdr = parse_bmp_header(&carrier).unwrap();
        assert_eq!(hdr.row_padding, 3);

        // Record the padding bytes before embedding
        let mut original_padding = Vec::new();
        for r in 0..hdr.height as usize {
            let row_start = hdr.data_offset + r * hdr.row_stride;
            let pad_start = row_start + (hdr.width as usize) * 3;
            original_padding.extend_from_slice(&carrier[pad_start..pad_start + hdr.row_padding]);
        }

        // Embed payload
        let secret = b"pad-test-secret";
        let stego = embed_in_bmp(&carrier, secret).unwrap();

        // Verify the extracted payload
        let extracted = extract_from_bmp(&stego).unwrap();
        assert_eq!(extracted, secret);

        // Verify that every single padding byte in stego image is byte-for-byte identical to original
        let mut stego_padding = Vec::new();
        for r in 0..hdr.height as usize {
            let row_start = hdr.data_offset + r * hdr.row_stride;
            let pad_start = row_start + (hdr.width as usize) * 3;
            stego_padding.extend_from_slice(&stego[pad_start..pad_start + hdr.row_padding]);
        }
        assert_eq!(stego_padding, original_padding);
    }

    #[test]
    fn bmp_top_down_image_support() {
        let carrier = create_test_bmp_with_fill(32, 32, 0x20, true);
        let hdr = parse_bmp_header(&carrier).unwrap();
        assert!(hdr.top_down);
        assert_eq!(hdr.width, 32);
        assert_eq!(hdr.height, 32);

        let secret = b"Top-down DIB payload verified";
        let stego = embed_in_bmp(&carrier, secret).unwrap();
        let extracted = extract_from_bmp(&stego).unwrap();
        assert_eq!(extracted, secret);
    }

    #[test]
    fn bmp_crc_mismatch_fails_extraction() {
        let carrier = create_minimal_bmp(32, 32);
        let payload = b"secret data to corrupt";
        let mut stego = embed_in_bmp(&carrier, payload).unwrap();

        // Flip one LSB inside the payload region
        let hdr = parse_bmp_header(&stego).unwrap();
        let channel_offset = hdr.data_offset + 100; // inside payload bits
        stego[channel_offset] ^= 1;

        let err = extract_from_bmp(&stego).unwrap_err();
        match err {
            Error::Format(msg) => {
                assert!(msg.contains("CRC-32 mismatch"));
            }
            _ => panic!("expected CRC-32 mismatch format error, got {err:?}"),
        }
    }

    #[test]
    fn bmp_reembedding_is_idempotent() {
        let carrier = create_minimal_bmp(40, 40);
        let first = embed_in_bmp(&carrier, b"initial long payload string 1234567890").unwrap();
        let second = embed_in_bmp(&first, b"short replacement").unwrap();

        let extracted = extract_from_bmp(&second).unwrap();
        assert_eq!(extracted, b"short replacement");
    }

    #[test]
    fn bmp_insufficient_capacity_fails() {
        // 4x4 image = 16 pixels = 48 channel bytes = 48 bits = 6 bytes capacity
        // Needs at least 12 bytes overhead = 96 bits = 32 pixels
        let small = create_minimal_bmp(4, 4);
        let err = embed_in_bmp(&small, b"data").unwrap_err();
        match err {
            Error::Format(msg) => {
                assert!(msg.contains("capacity insufficient"));
            }
            _ => panic!("expected capacity error, got {err:?}"),
        }
    }

    #[test]
    fn bmp_empty_payload_roundtrip() {
        let carrier = create_minimal_bmp(10, 10); // 100 pixels = 300 channel bytes > 96 bits
        let stego = embed_in_bmp(&carrier, b"").unwrap();
        let extracted = extract_from_bmp(&stego).unwrap();
        assert_eq!(extracted, b"");
    }

    #[test]
    fn bmp_invalid_carriers_rejected() {
        assert!(parse_bmp_header(&[]).is_err());
        assert!(parse_bmp_header(&[0u8; 30]).is_err());

        // Wrong magic
        let mut not_bmp = create_minimal_bmp(10, 10);
        not_bmp[0] = b'X';
        assert!(parse_bmp_header(&not_bmp).is_err());

        // Unsupported bit depth (e.g. 32 bpp)
        let mut bpp32 = create_minimal_bmp(10, 10);
        bpp32[28] = 32;
        assert!(parse_bmp_header(&bpp32).is_err());

        // Compressed BMP
        let mut compressed = create_minimal_bmp(10, 10);
        compressed[30] = 1;
        assert!(parse_bmp_header(&compressed).is_err());
    }

    #[test]
    fn bmp_constant_time_comparison() {
        let a = [0x12, 0x34, 0x56, 0x78];
        let b = [0x12, 0x34, 0x56, 0x78];
        let c = [0x12, 0x34, 0x56, 0x79];
        assert!(constant_time_eq_4(&a, &b));
        assert!(!constant_time_eq_4(&a, &c));
    }

    #[test]
    fn bmp_extreme_aspect_ratios_and_all_padding_alignments() {
        // Attack extreme aspect ratios and all 4 padding alignments (0, 1, 2, 3 bytes)
        let cases = [
            (1, 500, false), // 1px wide: row_bytes=3, pad=1
            (2, 250, false), // 2px wide: row_bytes=6, pad=2
            (3, 200, false), // 3px wide: row_bytes=9, pad=3
            (4, 150, false), // 4px wide: row_bytes=12, pad=0
            (1, 500, true),  // 1px wide top-down: row_bytes=3, pad=1
            (2, 250, true),  // 2px wide top-down: row_bytes=6, pad=2
            (3, 200, true),  // 3px wide top-down: row_bytes=9, pad=3
            (4, 150, true),  // 4px wide top-down: row_bytes=12, pad=0
            (500, 1, false), // 1px tall: row_bytes=1500, pad=0
            (501, 1, false), // 1px tall: row_bytes=1503, pad=1
            (502, 1, false), // 1px tall: row_bytes=1506, pad=2
            (503, 1, false), // 1px tall: row_bytes=1509, pad=3
            (500, 1, true),  // 1px tall top-down: row_bytes=1500, pad=0
            (501, 1, true),  // 1px tall top-down: row_bytes=1503, pad=1
            (502, 1, true),  // 1px tall top-down: row_bytes=1506, pad=2
            (503, 1, true),  // 1px tall top-down: row_bytes=1509, pad=3
        ];

        for (w, h, top_down) in cases {
            let carrier = create_test_bmp_with_fill(w, h, 0x33, top_down);
            let hdr = parse_bmp_header(&carrier).unwrap();
            let row_bytes = (w as usize) * 3;
            let expected_pad = (4 - (row_bytes % 4)) % 4;
            assert_eq!(hdr.row_padding, expected_pad);
            assert_eq!(hdr.top_down, top_down);

            let cap = get_bmp_capacity(&carrier).unwrap();
            assert!(cap.max_payload_bytes > 0);

            // Record initial padding bytes
            let mut orig_padding = Vec::new();
            for r in 0..hdr.height as usize {
                let row_start = hdr.data_offset + r * hdr.row_stride;
                let pad_start = row_start + row_bytes;
                orig_padding.extend_from_slice(&carrier[pad_start..pad_start + hdr.row_padding]);
            }

            let secret = format!("aspect-ratio-payload-{w}x{h}-{top_down}").into_bytes();
            let stego = embed_in_bmp(&carrier, &secret).unwrap();
            let extracted = extract_from_bmp(&stego).unwrap();
            assert_eq!(
                extracted, secret,
                "failed roundtrip for {w}x{h} top_down={top_down}"
            );

            // Verify all row padding bytes are 100% untouched
            let mut stego_padding = Vec::new();
            for r in 0..hdr.height as usize {
                let row_start = hdr.data_offset + r * hdr.row_stride;
                let pad_start = row_start + row_bytes;
                stego_padding.extend_from_slice(&stego[pad_start..pad_start + hdr.row_padding]);
            }
            assert_eq!(stego_padding, orig_padding, "padding altered in {w}x{h}");
        }
    }

    #[test]
    fn bmp_exact_capacity_boundary() {
        let carrier = create_minimal_bmp(32, 32); // 1024 px = 3072 channels = 384 bytes cap
        let cap = get_bmp_capacity(&carrier).unwrap();
        assert_eq!(cap.max_payload_bytes, 372); // 384 - 12 = 372

        // Exact maximum boundary payload
        let max_payload = vec![0xA5; 372];
        let stego = embed_in_bmp(&carrier, &max_payload).unwrap();
        let extracted = extract_from_bmp(&stego).unwrap();
        assert_eq!(extracted, max_payload);

        // 1 byte over capacity must fail
        let overflow_payload = vec![0xA5; 373];
        let err = embed_in_bmp(&carrier, &overflow_payload).unwrap_err();
        match err {
            Error::Format(msg) => assert!(msg.contains("capacity insufficient")),
            _ => panic!("expected capacity insufficient error"),
        }
    }

    #[test]
    fn bmp_extended_dib_header_v4_and_v5() {
        // Test BITMAPV4HEADER (108B) and BITMAPV5HEADER (124B)
        for dib_size in [108u32, 124u32] {
            let carrier = create_test_bmp_with_dib_size(32, 32, dib_size);
            let hdr = parse_bmp_header(&carrier).unwrap();
            assert_eq!(hdr.dib_header_size, dib_size);
            assert_eq!(hdr.data_offset, 14 + dib_size as usize);

            let secret = format!("secret-in-dib-v{dib_size}").into_bytes();
            let stego = embed_in_bmp(&carrier, &secret).unwrap();
            let extracted = extract_from_bmp(&stego).unwrap();
            assert_eq!(extracted, secret);

            // Verify extended DIB header bytes are 100% byte-for-byte preserved
            assert_eq!(
                &stego[14..14 + dib_size as usize],
                &carrier[14..14 + dib_size as usize]
            );
        }
    }

    #[test]
    fn bmp_malformed_dib_headers_rejected() {
        let base = create_minimal_bmp(16, 16);

        // 1. dib_header_size = u32::MAX
        let mut corrupt = base.clone();
        corrupt[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_bmp_header(&corrupt).is_err());

        // 2. dib_header_size < 40 (e.g. 12 for OS/2 1.x BITMAPCOREHEADER)
        let mut core = base.clone();
        core[14..18].copy_from_slice(&12u32.to_le_bytes());
        let err = parse_bmp_header(&core).unwrap_err();
        match err {
            Error::Format(msg) => assert!(msg.contains("unsupported BMP DIB header size: 12")),
            _ => panic!("expected format error"),
        }

        // 3. data_offset < 14 + dib_header_size
        let mut overlap = base.clone();
        overlap[10..14].copy_from_slice(&40u32.to_le_bytes());
        let err = parse_bmp_header(&overlap).unwrap_err();
        match err {
            Error::Format(msg) => assert!(msg.contains("overlaps header")),
            _ => panic!("expected format error"),
        }

        // 4. biPlanes != 1 (e.g. 0 or 2)
        let mut bad_planes = base.clone();
        bad_planes[26..28].copy_from_slice(&0u16.to_le_bytes());
        assert!(parse_bmp_header(&bad_planes).is_err());
        bad_planes[26..28].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse_bmp_header(&bad_planes).is_err());

        // 5. biCompression != 0 (e.g. 1 = RLE8, 3 = BITFIELDS)
        let mut bad_comp = base.clone();
        bad_comp[30..34].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse_bmp_header(&bad_comp).is_err());
        bad_comp[30..34].copy_from_slice(&3u32.to_le_bytes());
        assert!(parse_bmp_header(&bad_comp).is_err());

        // 6. biBitCount != 24 (e.g. 1, 8, 16, 32)
        for bpp in [1u16, 8, 16, 32] {
            let mut bad_bpp = base.clone();
            bad_bpp[28..30].copy_from_slice(&bpp.to_le_bytes());
            assert!(parse_bmp_header(&bad_bpp).is_err());
        }

        // 7. Width <= 0
        let mut bad_w = base.clone();
        bad_w[18..22].copy_from_slice(&0i32.to_le_bytes());
        assert!(parse_bmp_header(&bad_w).is_err());
        bad_w[18..22].copy_from_slice(&(-10i32).to_le_bytes());
        assert!(parse_bmp_header(&bad_w).is_err());

        // 8. Height == 0 or i32::MIN
        let mut bad_h = base.clone();
        bad_h[22..26].copy_from_slice(&0i32.to_le_bytes());
        assert!(parse_bmp_header(&bad_h).is_err());
        bad_h[22..26].copy_from_slice(&i32::MIN.to_le_bytes());
        assert!(parse_bmp_header(&bad_h).is_err());

        // 9. Truncated pixel data
        let truncated = base[..base.len() - 15].to_vec();
        assert!(parse_bmp_header(&truncated).is_err());
    }

    #[test]
    fn bmp_stego_envelope_tampering_attacks() {
        let carrier = create_minimal_bmp(32, 32);
        let secret = b"super-secret-envelope-data";
        let stego = embed_in_bmp(&carrier, secret).unwrap();

        // 1. Tampered magic
        let mut bad_magic = stego.clone();
        let hdr = parse_bmp_header(&stego).unwrap();
        bad_magic[hdr.data_offset] ^= 1;
        let err = extract_from_bmp(&bad_magic).unwrap_err();
        match err {
            Error::Format(msg) => assert!(msg.contains("no hidden ShadowVault payload found")),
            _ => panic!("expected format error"),
        }

        // 2. Corrupted CRC trailer (flip one bit in trailer region)
        let mut bad_crc = stego.clone();
        let channel_idx = (8 + secret.len()) * 8 + 5;
        let row_channel_bytes = (hdr.width as usize) * 3;
        let row = channel_idx / row_channel_bytes;
        let col = channel_idx % row_channel_bytes;
        let offset = hdr.data_offset + row * hdr.row_stride + col;
        bad_crc[offset] ^= 1;
        let err = extract_from_bmp(&bad_crc).unwrap_err();
        match err {
            Error::Format(msg) => assert!(msg.contains("CRC-32 mismatch")),
            _ => panic!("expected CRC-32 mismatch error"),
        }

        // 3. Spoofed length overflowing carrier capacity
        let mut bad_len = stego.clone();
        // Envelope length is bytes 4..8. Byte 4 bit 0 (channel_idx = 4 * 8 = 32)
        // Flip bits in length field to produce an exorbitant length
        for bit_i in 0..8 {
            let ch_idx = (4 + 3) * 8 + bit_i; // most significant byte of 32-bit LE length
            let r = ch_idx / row_channel_bytes;
            let c = ch_idx % row_channel_bytes;
            let off = hdr.data_offset + r * hdr.row_stride + c;
            bad_len[off] |= 1;
        }
        let err_len = extract_from_bmp(&bad_len).unwrap_err();
        match err_len {
            Error::Format(msg) => {
                assert!(msg.contains("exceeds carrier capacity") || msg.contains("CRC-32 mismatch"))
            }
            _ => panic!("expected capacity or CRC error"),
        }
    }

    #[test]
    fn bmp_exact_minimal_32_and_35_pixel_boundaries() {
        // 32 pixels * 3 channels = 96 bits = exactly 12 bytes envelope (max payload = 0 bytes)
        let carrier_32 = create_test_bmp_with_fill(32, 1, 0x77, false);
        let cap_32 = get_bmp_capacity(&carrier_32).unwrap();
        assert_eq!(cap_32.total_capacity_bytes, 12);
        assert_eq!(cap_32.max_payload_bytes, 0);

        // Empty payload embeds and extracts cleanly
        let stego_empty = embed_in_bmp(&carrier_32, b"").unwrap();
        let extracted_empty = extract_from_bmp(&stego_empty).unwrap();
        assert_eq!(extracted_empty, b"");

        // 1-byte overflow must fail
        assert!(embed_in_bmp(&carrier_32, b"X").is_err());

        // 31 pixels * 3 channels = 93 bits < 96 bits overhead
        let carrier_31 = create_test_bmp_with_fill(31, 1, 0x77, false);
        let cap_31 = get_bmp_capacity(&carrier_31).unwrap();
        assert_eq!(cap_31.total_capacity_bytes, 11);
        assert_eq!(cap_31.max_payload_bytes, 0);
        assert!(embed_in_bmp(&carrier_31, b"").is_err());

        // 35 pixels * 3 channels = 105 bits = 13 bytes total = exactly 1 byte max payload
        let carrier_35 = create_test_bmp_with_fill(35, 1, 0x88, false);
        let cap_35 = get_bmp_capacity(&carrier_35).unwrap();
        assert_eq!(cap_35.total_capacity_bytes, 13);
        assert_eq!(cap_35.max_payload_bytes, 1);

        // 1 byte embeds and extracts cleanly
        let stego_1b = embed_in_bmp(&carrier_35, b"Q").unwrap();
        let extracted_1b = extract_from_bmp(&stego_1b).unwrap();
        assert_eq!(extracted_1b, b"Q");

        // 2 bytes fail
        assert!(embed_in_bmp(&carrier_35, b"QQ").is_err());
    }

    #[test]
    fn bmp_carrier_with_gap_between_header_and_pixel_data() {
        // Create BMP with extra 256-byte gap between DIB header and data_offset
        let width = 32u32;
        let height = 32u32;
        let row_bytes = (width as usize) * 3;
        let row_padding = (4 - (row_bytes % 4)) % 4;
        let row_stride = row_bytes + row_padding;
        let pixel_data_size = row_stride * (height as usize);
        let gap_size = 256usize;
        let data_offset = 54 + gap_size;
        let file_size = (data_offset + pixel_data_size) as u32;

        let mut buf = Vec::with_capacity(file_size as usize);
        buf.extend_from_slice(BMP_MAGIC);
        buf.extend_from_slice(&file_size.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(data_offset as u32).to_le_bytes());

        // DIB header (40 bytes)
        buf.extend_from_slice(&40u32.to_le_bytes());
        buf.extend_from_slice(&(width as i32).to_le_bytes());
        buf.extend_from_slice(&(height as i32).to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&24u16.to_le_bytes());
        buf.extend_from_slice(&BI_RGB.to_le_bytes());
        buf.extend_from_slice(&(pixel_data_size as u32).to_le_bytes());
        buf.extend_from_slice(&2835u32.to_le_bytes());
        buf.extend_from_slice(&2835u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());

        // Gap filled with identifiable pattern
        for i in 0..gap_size {
            buf.push((i % 251) as u8);
        }

        // Pixels
        buf.resize(buf.len() + pixel_data_size, 0x55);

        let hdr = parse_bmp_header(&buf).unwrap();
        assert_eq!(hdr.data_offset, 54 + gap_size);

        let secret = b"secret-preserved-across-gap";
        let stego = embed_in_bmp(&buf, secret).unwrap();
        let extracted = extract_from_bmp(&stego).unwrap();
        assert_eq!(extracted, secret);

        // Verify gap bytes are 100% untouched
        assert_eq!(&stego[54..54 + gap_size], &buf[54..54 + gap_size]);
    }
}
