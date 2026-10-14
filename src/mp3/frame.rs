// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! MPEG Audio Layer III (MP3) frame parser and inter-frame steganography engine.
//!
//! Provides:
//! - Frame syncword detection (0xFFE/0xFFF sync bits and Layer III validation)
//! - Frame length calculation based on MPEG version, bitrate, sample rate, and padding
//! - Inter-frame steganographic embedding and extraction for `Mp3Mode::Frame`
//! - CRC-32 integrity validation and idempotent re-embedding

use crate::error::{Error, Result};
use crate::mp3::id3v2::parse_id3v2;

pub const FRAME_STEGO_MAGIC: &[u8; 4] = b"svLt";
pub const FRAME_OVERHEAD_BYTES: usize = 12; // 4 (magic) + 4 (len) + 4 (crc32)

const MPEG1_L3_BITRATES: [u32; 16] = [
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
];

const MPEG2_L3_BITRATES: [u32; 16] = [
    0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
];

const MPEG1_SAMPLERATES: [u32; 4] = [44100, 48000, 32000, 0];
const MPEG2_SAMPLERATES: [u32; 4] = [22050, 24000, 16000, 0];
const MPEG25_SAMPLERATES: [u32; 4] = [11025, 12000, 8000, 0];

/// Decoded MPEG Audio Layer III frame header information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpegFrameHeader {
    pub version: &'static str,
    pub layer: &'static str,
    pub bitrate_kbps: u32,
    pub sample_rate: u32,
    pub padding: bool,
    pub channel_mode: &'static str,
    pub frame_len: usize,
}

/// Parse a single 4-byte MPEG audio frame header.
pub fn parse_frame_header(header: &[u8]) -> Option<MpegFrameHeader> {
    if header.len() < 4 {
        return None;
    }

    let b0 = header[0];
    let b1 = header[1];
    let b2 = header[2];
    let b3 = header[3];

    // Frame sync: 11 bits set to 1 (0xFF and 0b111x_xxxx)
    if b0 != 0xFF || (b1 & 0xE0) != 0xE0 {
        return None;
    }

    let version_bits = (b1 >> 3) & 0x03;
    let (version, is_mpeg1, is_mpeg2, is_mpeg25) = match version_bits {
        0b11 => ("MPEG-1", true, false, false),
        0b10 => ("MPEG-2", false, true, false),
        0b00 => ("MPEG-2.5", false, false, true),
        _ => return None, // 0b01 is reserved
    };

    let layer_bits = (b1 >> 1) & 0x03;
    if layer_bits != 0b01 {
        // Not Layer III
        return None;
    }
    let layer = "Layer III";

    let bitrate_idx = ((b2 >> 4) & 0x0F) as usize;
    if bitrate_idx == 0 || bitrate_idx == 15 {
        return None; // 0 = free, 15 = bad
    }

    let bitrate_kbps = if is_mpeg1 {
        MPEG1_L3_BITRATES[bitrate_idx]
    } else {
        MPEG2_L3_BITRATES[bitrate_idx]
    };

    let samplerate_idx = ((b2 >> 2) & 0x03) as usize;
    if samplerate_idx == 3 {
        return None; // Reserved
    }

    let sample_rate = if is_mpeg1 {
        MPEG1_SAMPLERATES[samplerate_idx]
    } else if is_mpeg2 {
        MPEG2_SAMPLERATES[samplerate_idx]
    } else if is_mpeg25 {
        MPEG25_SAMPLERATES[samplerate_idx]
    } else {
        return None;
    };

    if sample_rate == 0 || bitrate_kbps == 0 {
        return None;
    }

    let padding = ((b2 >> 1) & 0x01) == 1;
    let pad_slot = if padding { 1 } else { 0 };

    let channel_bits = (b3 >> 6) & 0x03;
    let channel_mode = match channel_bits {
        0b00 => "Stereo",
        0b01 => "Joint Stereo",
        0b10 => "Dual Channel",
        _ => "Single Channel",
    };

    // For Layer III:
    // MPEG-1: frame_len = (144 * bitrate_bps / sample_rate) + pad_slot
    // MPEG-2 / 2.5: frame_len = (72 * bitrate_bps / sample_rate) + pad_slot
    let bitrate_bps = (bitrate_kbps as u64) * 1000;
    let coeff = if is_mpeg1 { 144u64 } else { 72u64 };
    let frame_len = ((coeff * bitrate_bps) / (sample_rate as u64) + (pad_slot as u64)) as usize;

    if frame_len < 4 {
        return None;
    }

    Some(MpegFrameHeader {
        version,
        layer,
        bitrate_kbps,
        sample_rate,
        padding,
        channel_mode,
        frame_len,
    })
}

/// Locate the start of the audio stream in an MP3 carrier (skipping ID3v2 if present).
pub fn find_audio_offset(bytes: &[u8]) -> usize {
    if let Ok(Some((_, audio_offset))) = parse_id3v2(bytes) {
        audio_offset
    } else {
        0
    }
}

/// Scan and count valid MPEG Audio Layer III frames in an MP3 stream.
pub fn scan_mpeg_frames(bytes: &[u8]) -> (Option<MpegFrameHeader>, usize, usize) {
    let audio_start = find_audio_offset(bytes);
    let slice = &bytes[audio_start..];
    let mut offset = 0;
    let mut first_header = None;
    let mut frame_count = 0;
    let mut total_audio_bytes = 0;

    while offset + 4 <= slice.len() {
        if let Some(hdr) = parse_frame_header(&slice[offset..offset + 4]) {
            if first_header.is_none() {
                first_header = Some(hdr);
            }
            let len = hdr.frame_len;
            frame_count += 1;
            total_audio_bytes += len.min(slice.len() - offset);
            offset += len;
        } else {
            offset += 1;
        }
    }

    (first_header, frame_count, total_audio_bytes)
}

/// Find and strip any existing `svLt` inter-frame stego envelope from an audio byte slice.
pub fn strip_frame_stego(audio_bytes: &[u8]) -> (Vec<u8>, bool) {
    let mut i = 0;
    while i + FRAME_OVERHEAD_BYTES <= audio_bytes.len() {
        if &audio_bytes[i..i + 4] == FRAME_STEGO_MAGIC {
            let len = u32::from_le_bytes(audio_bytes[i + 4..i + 8].try_into().unwrap()) as usize;
            let total_len = FRAME_OVERHEAD_BYTES + len;
            if i + total_len <= audio_bytes.len() {
                let payload = &audio_bytes[i + 8..i + 8 + len];
                let expected_crc =
                    u32::from_le_bytes(audio_bytes[i + 8 + len..i + total_len].try_into().unwrap());
                if crc32fast::hash(payload) == expected_crc {
                    let mut clean = Vec::with_capacity(audio_bytes.len() - total_len);
                    clean.extend_from_slice(&audio_bytes[..i]);
                    clean.extend_from_slice(&audio_bytes[i + total_len..]);
                    return (clean, true);
                }
            }
        }
        i += 1;
    }
    (audio_bytes.to_vec(), false)
}

/// Embed an encrypted payload between MPEG Audio Layer III frames with CRC-32 verification.
pub fn embed_in_frame(mp3_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let audio_start = find_audio_offset(mp3_bytes);
    let id3_prefix = &mp3_bytes[..audio_start];
    let audio_slice = &mp3_bytes[audio_start..];

    // Strip previous inter-frame stego envelope for idempotency
    let (clean_audio, _) = strip_frame_stego(audio_slice);

    // Locate the first valid MPEG audio frame in the clean audio
    let mut first_frame_len = None;
    let mut offset = 0;
    while offset + 4 <= clean_audio.len() {
        if let Some(hdr) = parse_frame_header(&clean_audio[offset..offset + 4]) {
            first_frame_len = Some(offset + hdr.frame_len);
            break;
        }
        offset += 1;
    }

    let split_pos = match first_frame_len {
        Some(len) if len <= clean_audio.len() => len,
        _ => {
            return Err(Error::Format(
                "no valid MPEG Audio Layer III frames found in MP3 carrier".into(),
            ));
        }
    };

    // Construct the inter-frame stego envelope
    let crc = crc32fast::hash(payload);
    let mut envelope = Vec::with_capacity(FRAME_OVERHEAD_BYTES + payload.len());
    envelope.extend_from_slice(FRAME_STEGO_MAGIC);
    envelope.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(&crc.to_le_bytes());

    let mut out = Vec::with_capacity(id3_prefix.len() + clean_audio.len() + envelope.len());
    out.extend_from_slice(id3_prefix);
    out.extend_from_slice(&clean_audio[..split_pos]);
    out.extend_from_slice(&envelope);
    out.extend_from_slice(&clean_audio[split_pos..]);

    Ok(out)
}

/// Extract payload from inter-frame stego packet within an MP3 carrier.
pub fn extract_from_frame(mp3_bytes: &[u8]) -> Result<Vec<u8>> {
    let audio_start = find_audio_offset(mp3_bytes);
    let audio_slice = &mp3_bytes[audio_start..];

    // Search for the `svLt` envelope signature in audio stream
    let mut i = 0;
    while i + 4 <= audio_slice.len() {
        if &audio_slice[i..i + 4] == FRAME_STEGO_MAGIC {
            if i + FRAME_OVERHEAD_BYTES > audio_slice.len() {
                return Err(Error::Format(
                    "stego frame packet truncated (header smaller than expected)".into(),
                ));
            }

            let len = u32::from_le_bytes(audio_slice[i + 4..i + 8].try_into().unwrap()) as usize;
            let total_len = FRAME_OVERHEAD_BYTES + len;

            if i + total_len > audio_slice.len() {
                return Err(Error::Format(
                    "stego frame packet truncated (declared length exceeds data)".into(),
                ));
            }

            let payload = &audio_slice[i + 8..i + 8 + len];
            let expected_crc =
                u32::from_le_bytes(audio_slice[i + 8 + len..i + total_len].try_into().unwrap());
            let actual_crc = crc32fast::hash(payload);

            if actual_crc != expected_crc {
                return Err(Error::Format(
                    "stego frame CRC-32 mismatch (corrupted carrier)".into(),
                ));
            }

            return Ok(payload.to_vec());
        }
        i += 1;
    }

    Err(Error::Format(
        "no hidden ShadowVault payload found in MP3 audio frames".into(),
    ))
}
