// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! MP3 ID3v2 & Audio Frame Steganography Carrier (`src/mp3/`).
//!
//! Provides zero-trust steganographic embedding and extraction for MPEG Audio Layer III files:
//! - `Mp3Mode::Id3v2`: Conceals encrypted payload within an ID3v2.3 / ID3v2.4 private (`PRIV`)
//!   tag frame with owner `ShadowVault\0`, magic `svLt`, length, and CRC-32 checksum.
//! - `Mp3Mode::Frame`: Conceals encrypted payload inside inter-frame padding between MPEG
//!   audio frames with frame sync validation and CRC-32 integrity checking.

pub mod frame;
pub mod id3v2;

use crate::error::{Error, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Steganography carrier embedding mode for MP3 audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mp3Mode {
    /// ID3v2 tag private frame mode (`PRIV`, owner `ShadowVault\0`)
    #[default]
    Id3v2,
    /// Inter-frame padding steganography mode between MPEG Layer III frames
    Frame,
}

impl std::fmt::Display for Mp3Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Id3v2 => write!(f, "id3v2"),
            Self::Frame => write!(f, "frame"),
        }
    }
}

/// Steganography extraction mode for MP3 audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractMp3Mode {
    /// Auto-detect payload: inspects ID3v2 PRIV frame first, falls back to audio frames
    #[default]
    Auto,
    /// Extract exclusively from ID3v2 PRIV tag frame
    Id3v2,
    /// Extract exclusively from inter-frame padding packet
    Frame,
}

impl std::fmt::Display for ExtractMp3Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Id3v2 => write!(f, "id3v2"),
            Self::Frame => write!(f, "frame"),
        }
    }
}

/// Storage capacity metrics for an MP3 audio carrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mp3Capacity {
    pub mpeg_version: String,
    pub layer: String,
    pub bitrate_kbps: u32,
    pub sample_rate: u32,
    pub channel_mode: String,
    pub num_frames: usize,
    pub total_audio_bytes: usize,
    pub id3v2_present: bool,
    pub id3v2_version: Option<String>,
    pub id3v2_max_payload_bytes: usize,
    pub frame_mode_supported: bool,
}

impl std::fmt::Display for Mp3Capacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MP3 audio ({}, {}, {} kbps, {} Hz, {}, {} frames, ID3v2 max capacity: {} bytes / {:.2} MiB)",
            self.mpeg_version,
            self.layer,
            self.bitrate_kbps,
            self.sample_rate,
            self.channel_mode,
            self.num_frames,
            self.id3v2_max_payload_bytes,
            self.id3v2_max_payload_bytes as f64 / (1024.0 * 1024.0)
        )
    }
}

/// Embed an encrypted payload into an MP3 carrier file using the specified mode.
pub fn embed_in_mp3(mp3_bytes: &[u8], payload: &[u8], mode: Mp3Mode) -> Result<Vec<u8>> {
    match mode {
        Mp3Mode::Id3v2 => {
            // Strip any existing frame stego envelope first so Auto extraction won't return stale frame data
            let audio_start = frame::find_audio_offset(mp3_bytes);
            let id3_part = &mp3_bytes[..audio_start];
            let audio_part = &mp3_bytes[audio_start..];
            let (clean_audio, stripped_frame) = frame::strip_frame_stego(audio_part);

            let base_bytes = if stripped_frame {
                let mut base = Vec::with_capacity(id3_part.len() + clean_audio.len());
                base.extend_from_slice(id3_part);
                base.extend_from_slice(&clean_audio);
                base
            } else {
                mp3_bytes.to_vec()
            };

            id3v2::embed_in_id3v2(&base_bytes, payload)
        }
        Mp3Mode::Frame => {
            // Strip any existing ID3v2 PRIV frames first so Auto extraction won't return stale ID3 data
            let clean_base = id3v2::strip_id3v2_stego(mp3_bytes)?;
            frame::embed_in_frame(&clean_base, payload)
        }
    }
}

/// Extract an encrypted payload from an MP3 carrier file using the specified mode.
pub fn extract_from_mp3(mp3_bytes: &[u8], mode: ExtractMp3Mode) -> Result<Vec<u8>> {
    match mode {
        ExtractMp3Mode::Id3v2 => id3v2::extract_from_id3v2(mp3_bytes),
        ExtractMp3Mode::Frame => frame::extract_from_frame(mp3_bytes),
        ExtractMp3Mode::Auto => {
            // Try ID3v2 PRIV frame extraction first
            match id3v2::extract_from_id3v2(mp3_bytes) {
                Ok(data) => Ok(data),
                Err(id3_err) => {
                    if is_id3v2_corruption_error(&id3_err) {
                        return Err(id3_err);
                    }
                    // Fall back to inter-frame stego extraction
                    match frame::extract_from_frame(mp3_bytes) {
                        Ok(data) => Ok(data),
                        Err(frame_err) => {
                            if is_frame_corruption_error(&frame_err) {
                                Err(frame_err)
                            } else {
                                Err(Error::Format(
                                    "no hidden ShadowVault payload found in MP3 carrier".into(),
                                ))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Calculate steganographic storage capacity and audio parameters for an MP3 carrier.
pub fn get_mp3_capacity(mp3_bytes: &[u8]) -> Result<Mp3Capacity> {
    let id3_info = id3v2::parse_id3v2(mp3_bytes)?;
    let (first_header, num_frames, total_audio_bytes) = frame::scan_mpeg_frames(mp3_bytes);

    if id3_info.is_none() && first_header.is_none() {
        return Err(Error::Format(
            "invalid MP3 carrier (expected ID3 tag or valid MPEG frame sync header)".into(),
        ));
    }

    let (mpeg_version, layer, bitrate_kbps, sample_rate, channel_mode) = match first_header {
        Some(h) => (
            h.version.to_string(),
            h.layer.to_string(),
            h.bitrate_kbps,
            h.sample_rate,
            h.channel_mode.to_string(),
        ),
        None => (
            "Unknown".to_string(),
            "Layer III".to_string(),
            128,
            44100,
            "Stereo".to_string(),
        ),
    };

    let (id3v2_present, id3v2_version) = match id3_info {
        Some((tag, _)) => (
            true,
            Some(format!("2.{}.{}", tag.major_version, tag.revision)),
        ),
        None => (false, None),
    };

    Ok(Mp3Capacity {
        mpeg_version,
        layer,
        bitrate_kbps,
        sample_rate,
        channel_mode,
        num_frames,
        total_audio_bytes,
        id3v2_present,
        id3v2_version,
        id3v2_max_payload_bytes: 256 * 1024 * 1024, // 256 MiB ID3v2 28-bit limit
        frame_mode_supported: num_frames > 0,
    })
}

fn is_id3v2_corruption_error(err: &Error) -> bool {
    match err {
        Error::Format(msg) => {
            msg.contains("CRC-32 mismatch")
                || msg.contains("PRIV frame truncated")
                || msg.contains("shorter than declared")
        }
        _ => false,
    }
}

fn is_frame_corruption_error(err: &Error) -> bool {
    match err {
        Error::Format(msg) => {
            msg.contains("CRC-32 mismatch")
                || msg.contains("packet truncated")
                || msg.contains("exceeds data")
        }
        _ => false,
    }
}
