// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! ID3v2.3 / ID3v2.4 parser, serializer, and private frame (`PRIV`) steganography engine.
//!
//! Handles:
//! - 28-bit syncsafe integer decoding and encoding
//! - Header and frame parsing with metadata preservation (TIT2, TPE1, TALB, APIC, etc.)
//! - Idempotent stripping of prior ShadowVault `PRIV` frames
//! - Injection of `PRIV` frame with owner `ShadowVault\0`, `svLt` magic, length, and CRC-32

use crate::error::{Error, Result};

pub const ID3_HEADER_MAGIC: &[u8; 3] = b"ID3";
pub const PRIV_FRAME_ID: &[u8; 4] = b"PRIV";
pub const SHADOWVAULT_OWNER: &[u8; 12] = b"ShadowVault\0";
pub const STEGO_MAGIC: &[u8; 4] = b"svLt";
pub const PRIV_OVERHEAD_BYTES: usize = 24; // 12 (owner) + 4 (magic) + 4 (len) + 4 (crc32)

/// Represents a single ID3v2 tag frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Id3Frame {
    pub id: [u8; 4],
    pub flags: [u8; 2],
    pub data: Vec<u8>,
}

/// Parsed ID3v2 tag structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Id3v2Tag {
    pub major_version: u8,
    pub revision: u8,
    pub flags: u8,
    pub frames: Vec<Id3Frame>,
    pub tag_total_size: usize,
}

/// Decode a 4-byte 28-bit syncsafe integer (MSB of each byte is 0).
pub fn decode_syncsafe(bytes: [u8; 4]) -> u32 {
    ((bytes[0] as u32 & 0x7F) << 21)
        | ((bytes[1] as u32 & 0x7F) << 14)
        | ((bytes[2] as u32 & 0x7F) << 7)
        | (bytes[3] as u32 & 0x7F)
}

/// Encode a 32-bit integer into a 4-byte 28-bit syncsafe integer.
pub fn encode_syncsafe(val: u32) -> [u8; 4] {
    [
        ((val >> 21) & 0x7F) as u8,
        ((val >> 14) & 0x7F) as u8,
        ((val >> 7) & 0x7F) as u8,
        (val & 0x7F) as u8,
    ]
}

/// Check if byte slice begins with a valid ID3v2 tag header.
pub fn has_id3v2_tag(bytes: &[u8]) -> bool {
    bytes.len() >= 10 && &bytes[0..3] == ID3_HEADER_MAGIC && bytes[3] <= 4
}

/// Parse an ID3v2 tag from an MP3 byte slice, returning the tag and the offset
/// where audio data begins.
pub fn parse_id3v2(bytes: &[u8]) -> Result<Option<(Id3v2Tag, usize)>> {
    if !has_id3v2_tag(bytes) {
        return Ok(None);
    }

    let major = bytes[3];
    let revision = bytes[4];
    let flags = bytes[5];
    let raw_size = [bytes[6], bytes[7], bytes[8], bytes[9]];
    let tag_data_size = decode_syncsafe(raw_size) as usize;

    let has_footer = (flags & 0x10) != 0 && major == 4;
    let header_size = 10;
    let footer_size = if has_footer { 10 } else { 0 };
    let tag_total_size = header_size + tag_data_size + footer_size;

    if bytes.len() < tag_total_size {
        return Err(Error::Format(
            "truncated ID3v2 tag in MP3 carrier (file smaller than tag header size)".into(),
        ));
    }

    let mut frames = Vec::new();
    let mut offset = 10;
    let tag_data_end = 10 + tag_data_size;

    // Handle extended header if present (flag bit 6 = 0x40)
    if (flags & 0x40) != 0 && offset + 4 <= tag_data_end {
        let ext_size = if major == 4 {
            decode_syncsafe([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize
        } else {
            u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize
                + 4
        };
        offset = (offset + ext_size).min(tag_data_end);
    }

    while offset + 10 <= tag_data_end {
        let frame_id = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];

        // Null padding terminates the frame list in ID3v2
        if frame_id[0] == 0x00 {
            break;
        }

        let frame_size = if major == 4 {
            decode_syncsafe([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]) as usize
        } else {
            u32::from_be_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]) as usize
        };

        let frame_flags = [bytes[offset + 8], bytes[offset + 9]];
        let frame_data_start = offset + 10;
        let frame_data_end = frame_data_start + frame_size;

        if frame_data_end > tag_data_end {
            // Reached corrupt or unaligned trailing bytes in tag body
            break;
        }

        let data = bytes[frame_data_start..frame_data_end].to_vec();
        frames.push(Id3Frame {
            id: frame_id,
            flags: frame_flags,
            data,
        });

        offset = frame_data_end;
    }

    Ok(Some((
        Id3v2Tag {
            major_version: major,
            revision,
            flags,
            frames,
            tag_total_size,
        },
        tag_total_size,
    )))
}

/// Strip any existing ShadowVault PRIV frames from the ID3v2 tag for idempotency.
pub fn strip_shadowvault_priv_frames(tag: &mut Id3v2Tag) -> bool {
    let before_len = tag.frames.len();
    tag.frames
        .retain(|f| !(f.id == *PRIV_FRAME_ID && f.data.starts_with(SHADOWVAULT_OWNER)));
    tag.frames.len() != before_len
}

/// Create a new ShadowVault `PRIV` frame encapsulating the given encrypted payload.
pub fn create_shadowvault_priv_frame(payload: &[u8]) -> Id3Frame {
    let crc = crc32fast::hash(payload);
    let mut data = Vec::with_capacity(PRIV_OVERHEAD_BYTES + payload.len());
    data.extend_from_slice(SHADOWVAULT_OWNER);
    data.extend_from_slice(STEGO_MAGIC);
    data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    data.extend_from_slice(payload);
    data.extend_from_slice(&crc.to_le_bytes());

    Id3Frame {
        id: *PRIV_FRAME_ID,
        flags: [0x00, 0x00],
        data,
    }
}

/// Serialize an `Id3v2Tag` to binary format with a 10-byte header.
pub fn serialize_id3v2(tag: &Id3v2Tag) -> Vec<u8> {
    let mut body = Vec::new();

    for frame in &tag.frames {
        body.extend_from_slice(&frame.id);
        let size_bytes = if tag.major_version == 4 {
            encode_syncsafe(frame.data.len() as u32)
        } else {
            (frame.data.len() as u32).to_be_bytes()
        };
        body.extend_from_slice(&size_bytes);
        body.extend_from_slice(&frame.flags);
        body.extend_from_slice(&frame.data);
    }

    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(ID3_HEADER_MAGIC);
    out.push(tag.major_version);
    out.push(tag.revision);
    out.push(tag.flags & !0x40 & !0x10); // Clear extended header and footer flags
    out.extend_from_slice(&encode_syncsafe(body.len() as u32));
    out.extend_from_slice(&body);
    out
}

/// Embed payload into MP3 carrier using ID3v2 PRIV frame, preserving existing tags.
pub fn embed_in_id3v2(mp3_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let (mut tag, audio_offset) = match parse_id3v2(mp3_bytes)? {
        Some((t, off)) => (t, off),
        None => (
            Id3v2Tag {
                major_version: 3,
                revision: 0,
                flags: 0,
                frames: Vec::new(),
                tag_total_size: 0,
            },
            0,
        ),
    };

    // Strip previous ShadowVault PRIV frames for idempotent re-embedding
    strip_shadowvault_priv_frames(&mut tag);

    // Inject new ShadowVault PRIV frame
    let priv_frame = create_shadowvault_priv_frame(payload);
    tag.frames.push(priv_frame);

    let serialized_tag = serialize_id3v2(&tag);
    let audio_slice = &mp3_bytes[audio_offset..];

    let mut out = Vec::with_capacity(serialized_tag.len() + audio_slice.len());
    out.extend_from_slice(&serialized_tag);
    out.extend_from_slice(audio_slice);
    Ok(out)
}

/// Extract payload from ID3v2 PRIV frame.
pub fn extract_from_id3v2(mp3_bytes: &[u8]) -> Result<Vec<u8>> {
    let (tag, _) = match parse_id3v2(mp3_bytes)? {
        Some(res) => res,
        None => {
            return Err(Error::Format("no ID3v2 tag found in MP3 carrier".into()));
        }
    };

    let stego_frame = tag
        .frames
        .iter()
        .find(|f| f.id == *PRIV_FRAME_ID && f.data.starts_with(SHADOWVAULT_OWNER))
        .ok_or_else(|| {
            Error::Format("no hidden ShadowVault PRIV frame found in MP3 ID3v2 tag".into())
        })?;

    if stego_frame.data.len() < PRIV_OVERHEAD_BYTES {
        return Err(Error::Format(
            "stego ID3v2 PRIV frame truncated (header smaller than expected)".into(),
        ));
    }

    let magic = &stego_frame.data[12..16];
    if magic != STEGO_MAGIC {
        return Err(Error::Format(
            "invalid ShadowVault magic in ID3v2 PRIV frame (expected svLt)".into(),
        ));
    }

    let payload_len = u32::from_le_bytes(
        stego_frame.data[16..20]
            .try_into()
            .map_err(|_| Error::Format("failed to parse payload length".into()))?,
    ) as usize;

    let expected_frame_len = PRIV_OVERHEAD_BYTES + payload_len;
    if stego_frame.data.len() < expected_frame_len {
        return Err(Error::Format(
            "stego ID3v2 PRIV frame truncated (data length shorter than declared)".into(),
        ));
    }

    let payload = &stego_frame.data[20..20 + payload_len];
    let expected_crc = u32::from_le_bytes(
        stego_frame.data[20 + payload_len..24 + payload_len]
            .try_into()
            .map_err(|_| Error::Format("failed to parse CRC-32 checksum".into()))?,
    );

    let actual_crc = crc32fast::hash(payload);
    if actual_crc != expected_crc {
        return Err(Error::Format(
            "stego ID3v2 PRIV CRC-32 mismatch (corrupted carrier)".into(),
        ));
    }

    Ok(payload.to_vec())
}

/// Strip any ShadowVault PRIV frames from an MP3 file, returning clean MP3 bytes.
pub fn strip_id3v2_stego(mp3_bytes: &[u8]) -> Result<Vec<u8>> {
    let (mut tag, audio_offset) = match parse_id3v2(mp3_bytes)? {
        Some((t, off)) => (t, off),
        None => return Ok(mp3_bytes.to_vec()),
    };

    let stripped = strip_shadowvault_priv_frames(&mut tag);
    if !stripped {
        return Ok(mp3_bytes.to_vec());
    }

    let audio_slice = &mp3_bytes[audio_offset..];
    if tag.frames.is_empty() {
        // All frames were stripped, return audio stream only
        Ok(audio_slice.to_vec())
    } else {
        let serialized_tag = serialize_id3v2(&tag);
        let mut out = Vec::with_capacity(serialized_tag.len() + audio_slice.len());
        out.extend_from_slice(&serialized_tag);
        out.extend_from_slice(audio_slice);
        Ok(out)
    }
}
