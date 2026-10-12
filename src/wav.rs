// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! WAV audio steganography engine supporting both RIFF/WAVE subchunk (`svLt`)
//! and 16-bit PCM LSB (Least Significant Bit) modes with CRC-32 validation.

use crate::error::{Error, Result};
use clap::ValueEnum;

const RIFF_MAGIC: &[u8; 4] = b"RIFF";
const WAVE_MAGIC: &[u8; 4] = b"WAVE";
const STEGO_CHUNK_ID: &[u8; 4] = b"svLt";
const FMT_CHUNK_ID: &[u8; 4] = b"fmt ";
const DATA_CHUNK_ID: &[u8; 4] = b"data";
const LSB_MAGIC: &[u8; 4] = b"svLt";
const LSB_OVERHEAD_BYTES: usize = 12; // 4-byte magic + 4-byte len + 4-byte crc

/// Steganography carrier embedding mode for WAV audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum WavMode {
    /// RIFF subchunk mode (`svLt` metadata chunk before or after audio data)
    #[default]
    Chunk,
    /// 16-bit PCM audio sample least-significant-bit replacement mode
    Lsb,
}

impl std::fmt::Display for WavMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chunk => write!(f, "chunk"),
            Self::Lsb => write!(f, "lsb"),
        }
    }
}

/// Steganography extraction mode for WAV audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum ExtractWavMode {
    /// Auto-detect payload: checks RIFF subchunk first, then falls back to LSB
    #[default]
    Auto,
    /// Extract exclusively from RIFF subchunk (`svLt`)
    Chunk,
    /// Extract exclusively from 16-bit PCM LSB stream
    Lsb,
}

impl std::fmt::Display for ExtractWavMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Chunk => write!(f, "chunk"),
            Self::Lsb => write!(f, "lsb"),
        }
    }
}

/// Embed an encrypted payload into a WAV audio file using the specified mode.
pub fn embed_in_wav(wav_bytes: &[u8], payload: &[u8], mode: WavMode) -> Result<Vec<u8>> {
    match mode {
        WavMode::Chunk => embed_in_wav_chunk(wav_bytes, payload),
        WavMode::Lsb => {
            // Strip any existing `svLt` chunk first so Auto-extraction won't return stale chunk data.
            let (clean, trailing) = strip_stego_chunks(wav_bytes)?;
            if clean.len() + trailing.len() != wav_bytes.len() {
                let mut base = clean;
                base.extend_from_slice(&trailing);
                let riff_chunk_data_len = (base.len() - trailing.len()).saturating_sub(8);
                let riff_size = riff_chunk_data_len as u32;
                base[4..8].copy_from_slice(&riff_size.to_le_bytes());
                embed_in_wav_lsb(&base, payload)
            } else {
                embed_in_wav_lsb(wav_bytes, payload)
            }
        }
    }
}

/// Extract an encrypted payload from a WAV audio file using the specified mode.
pub fn extract_from_wav(wav_bytes: &[u8], mode: ExtractWavMode) -> Result<Vec<u8>> {
    match mode {
        ExtractWavMode::Chunk => extract_from_wav_chunk(wav_bytes),
        ExtractWavMode::Lsb => extract_from_wav_lsb(wav_bytes),
        ExtractWavMode::Auto => {
            validate_wav_header(wav_bytes)?;

            match extract_from_wav_chunk(wav_bytes) {
                Ok(data) => Ok(data),
                Err(chunk_err) => {
                    // If chunk extraction failed due to corruption/truncation of an existing stego chunk,
                    // report that corruption error directly rather than masking it with LSB fallback.
                    if is_chunk_corruption_error(&chunk_err) {
                        return Err(chunk_err);
                    }
                    match extract_from_wav_lsb(wav_bytes) {
                        Ok(data) => Ok(data),
                        Err(lsb_err) => {
                            if is_lsb_corruption_error(&lsb_err) {
                                Err(lsb_err)
                            } else {
                                Err(Error::Format(
                                    "no hidden ShadowVault payload found in WAV audio carrier"
                                        .into(),
                                ))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Steganographic storage capacity evaluation for a WAV audio carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WavCapacity {
    pub audio_format: u16,
    pub num_channels: u16,
    pub sample_rate: u32,
    pub bits_per_sample: u16,
    pub num_samples: usize,
    pub lsb_total_capacity_bytes: usize,
    pub lsb_max_payload_bytes: usize,
    pub lsb_overhead_bytes: usize,
    pub chunk_mode_supported: bool,
}

impl std::fmt::Display for WavCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WAV audio (format: {}, channels: {}, {} Hz, {} bps, {} samples, LSB payload capacity: {} bytes / {:.2} KiB)",
            self.audio_format,
            self.num_channels,
            self.sample_rate,
            self.bits_per_sample,
            self.num_samples,
            self.lsb_max_payload_bytes,
            self.lsb_max_payload_bytes as f64 / 1024.0
        )
    }
}

/// Calculate steganographic data storage capacity for a WAV audio carrier.
pub fn get_wav_capacity(wav_bytes: &[u8]) -> Result<WavCapacity> {
    let pcm = parse_wav_pcm_info(wav_bytes)?;
    let num_samples = pcm.data_len / 2;
    let lsb_total_capacity_bytes = num_samples / 8;
    let lsb_max_payload_bytes = lsb_total_capacity_bytes.saturating_sub(LSB_OVERHEAD_BYTES);

    Ok(WavCapacity {
        audio_format: pcm.audio_format,
        num_channels: pcm.num_channels,
        sample_rate: pcm.sample_rate,
        bits_per_sample: pcm.bits_per_sample,
        num_samples,
        lsb_total_capacity_bytes,
        lsb_max_payload_bytes,
        lsb_overhead_bytes: LSB_OVERHEAD_BYTES,
        chunk_mode_supported: true,
    })
}

fn is_chunk_corruption_error(err: &Error) -> bool {
    match err {
        Error::Format(msg) => {
            msg.contains("CRC-32 mismatch")
                || msg.contains("stego chunk truncated")
                || msg.contains("truncated WAV chunk")
        }
        _ => false,
    }
}

fn is_lsb_corruption_error(err: &Error) -> bool {
    match err {
        Error::Format(msg) => {
            msg.contains("CRC-32 mismatch")
                || msg.contains("exceeds carrier capacity")
                || msg.contains("malformed")
                || msg.contains("truncated")
                || msg.contains("missing required")
        }
        _ => false,
    }
}

/// Embed `payload` as a dedicated `svLt` RIFF subchunk with CRC-32 checksum.
pub fn embed_in_wav_chunk(wav_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    validate_wav_header(wav_bytes)?;

    // Strip any existing `svLt` chunk for idempotent re-embedding, separating trailing bytes.
    let (mut clean_chunks, trailing) = strip_stego_chunks(wav_bytes)?;

    // Guarantee 2-byte RIFF chunk alignment before appending svLt chunk
    if (clean_chunks.len() % 2) == 1 {
        clean_chunks.push(0x00);
    }

    let chunk_payload_len = payload.len().saturating_add(4); // payload + 4-byte CRC-32
    if chunk_payload_len > u32::MAX as usize {
        return Err(Error::Format("payload too large for WAV chunk".into()));
    }
    let chunk_size = chunk_payload_len as u32;

    let crc = crc32fast::hash(payload);

    let mut out =
        Vec::with_capacity(clean_chunks.len() + 8 + chunk_payload_len + 1 + trailing.len());
    out.extend_from_slice(&clean_chunks);
    out.extend_from_slice(STEGO_CHUNK_ID);
    out.extend_from_slice(&chunk_size.to_le_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc.to_le_bytes());

    // RIFF chunk alignment: odd chunk payloads must be padded with a 0x00 byte
    if (chunk_size % 2) == 1 {
        out.push(0x00);
    }

    // Preserve any trailing non-chunk bytes AFTER all RIFF subchunks
    out.extend_from_slice(&trailing);

    // Check maximum RIFF container size (standard RIFF uses 32-bit length field)
    let total_file_size = out.len().saturating_sub(8);
    if total_file_size > u32::MAX as usize {
        return Err(Error::Format(
            "resulting WAV file exceeds maximum 4 GiB RIFF container limit".into(),
        ));
    }
    // RIFF chunk size at bytes 4..8 must describe RIFF chunk content only, excluding trailing non-chunk bytes
    let riff_chunk_data_len = (out.len() - trailing.len()).saturating_sub(8);
    let riff_size = riff_chunk_data_len as u32;
    out[4..8].copy_from_slice(&riff_size.to_le_bytes());

    Ok(out)
}

/// Extract hidden payload from an `svLt` RIFF subchunk and verify CRC-32 checksum.
pub fn extract_from_wav_chunk(wav_bytes: &[u8]) -> Result<Vec<u8>> {
    validate_wav_header(wav_bytes)?;

    let mut offset = 12;
    while offset + 8 <= wav_bytes.len() {
        let chunk_id = &wav_bytes[offset..offset + 4];
        let chunk_size =
            u32::from_le_bytes(wav_bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let data_start = offset + 8;
        let data_end = data_start.saturating_add(chunk_size);

        if chunk_id == STEGO_CHUNK_ID {
            if data_end > wav_bytes.len() {
                return Err(Error::Format(
                    "stego chunk truncated (unexpected end of file)".into(),
                ));
            }
            if chunk_size < 4 {
                return Err(Error::Format(
                    "stego chunk truncated (missing CRC-32)".into(),
                ));
            }
            let payload = &wav_bytes[data_start..data_end - 4];
            let expected_crc =
                u32::from_le_bytes(wav_bytes[data_end - 4..data_end].try_into().unwrap());
            let actual_crc = crc32fast::hash(payload);
            if actual_crc != expected_crc {
                return Err(Error::Format(
                    "stego chunk CRC-32 mismatch (corrupted carrier)".into(),
                ));
            }
            return Ok(payload.to_vec());
        }

        if data_end > wav_bytes.len() {
            // Trailing non-chunk bytes or unaligned data at end of file
            break;
        }
        let pad = if chunk_size % 2 == 1 { 1 } else { 0 };
        let next_offset = data_end.saturating_add(pad);

        offset = next_offset;
    }

    if offset < wav_bytes.len() && wav_bytes[offset..].starts_with(STEGO_CHUNK_ID) {
        return Err(Error::Format(
            "stego chunk truncated (missing chunk header)".into(),
        ));
    }

    Err(Error::Format(
        "no hidden ShadowVault chunk payload found in WAV audio carrier".into(),
    ))
}

/// Embed `payload` into 16-bit PCM audio sample least significant bits (LSB)
/// with magic header and CRC-32 validation.
pub fn embed_in_wav_lsb(wav_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let pcm = parse_wav_pcm_info(wav_bytes)?;

    if payload.len() > u32::MAX as usize {
        return Err(Error::Format("payload too large for LSB header".into()));
    }

    let num_samples = pcm.data_len / 2;
    let total_bytes_needed = LSB_OVERHEAD_BYTES.saturating_add(payload.len());
    let total_samples_needed = total_bytes_needed.saturating_mul(8);

    if num_samples < total_samples_needed {
        return Err(Error::Format(format!(
            "carrier audio capacity insufficient for LSB embedding (need {total_samples_needed} samples, carrier has {num_samples})"
        )));
    }

    // Envelope structure: [magic: 4B][len: 4B LE][payload: NB][crc32: 4B LE]
    let crc = crc32fast::hash(payload);
    let mut envelope = Vec::with_capacity(total_bytes_needed);
    envelope.extend_from_slice(LSB_MAGIC);
    envelope.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(&crc.to_le_bytes());

    let mut out = wav_bytes.to_vec();

    for (byte_idx, &byte) in envelope.iter().enumerate() {
        for bit_idx in 0..8 {
            let sample_idx = byte_idx * 8 + bit_idx;
            let bit = (byte >> (7 - bit_idx)) & 1;
            // In 16-bit PCM little-endian, sample low-byte is at sample_idx * 2
            let low_byte_offset = pcm.data_offset + sample_idx * 2;
            out[low_byte_offset] = (out[low_byte_offset] & 0xFE) | bit;
        }
    }

    Ok(out)
}

/// Extract hidden payload from 16-bit PCM audio sample LSB stream and verify CRC-32.
pub fn extract_from_wav_lsb(wav_bytes: &[u8]) -> Result<Vec<u8>> {
    let pcm = parse_wav_pcm_info(wav_bytes)?;
    let num_samples = pcm.data_len / 2;

    if num_samples < LSB_OVERHEAD_BYTES * 8 {
        return Err(Error::Format(
            "audio data chunk too small for LSB steganography".into(),
        ));
    }

    // Read header: 4 bytes magic + 4 bytes payload length (64 samples)
    let mut header_bytes = [0u8; 8];
    for (byte_idx, item) in header_bytes.iter_mut().enumerate() {
        let mut b = 0u8;
        for bit_idx in 0..8 {
            let sample_idx = byte_idx * 8 + bit_idx;
            let low_byte_offset = pcm.data_offset + sample_idx * 2;
            let bit = wav_bytes[low_byte_offset] & 1;
            b |= bit << (7 - bit_idx);
        }
        *item = b;
    }

    if &header_bytes[0..4] != LSB_MAGIC {
        return Err(Error::Format(
            "no hidden ShadowVault LSB payload found in WAV audio carrier".into(),
        ));
    }

    let payload_len = u32::from_le_bytes(header_bytes[4..8].try_into().unwrap()) as usize;
    let total_samples_needed = LSB_OVERHEAD_BYTES
        .saturating_add(payload_len)
        .saturating_mul(8);

    if total_samples_needed > num_samples {
        return Err(Error::Format(
            "LSB payload length exceeds carrier capacity (corrupted carrier)".into(),
        ));
    }

    // Read payload bytes
    let mut payload = Vec::with_capacity(payload_len);
    for byte_idx in 0..payload_len {
        let mut b = 0u8;
        for bit_idx in 0..8 {
            let sample_idx = (8 + byte_idx) * 8 + bit_idx;
            let low_byte_offset = pcm.data_offset + sample_idx * 2;
            let bit = wav_bytes[low_byte_offset] & 1;
            b |= bit << (7 - bit_idx);
        }
        payload.push(b);
    }

    // Read 4-byte CRC-32 trailer
    let mut crc_bytes = [0u8; 4];
    for (byte_idx, item) in crc_bytes.iter_mut().enumerate() {
        let mut b = 0u8;
        for bit_idx in 0..8 {
            let sample_idx = (8 + payload_len + byte_idx) * 8 + bit_idx;
            let low_byte_offset = pcm.data_offset + sample_idx * 2;
            let bit = wav_bytes[low_byte_offset] & 1;
            b |= bit << (7 - bit_idx);
        }
        *item = b;
    }

    let expected_crc = u32::from_le_bytes(crc_bytes);
    let actual_crc = crc32fast::hash(&payload);

    if actual_crc != expected_crc {
        return Err(Error::Format(
            "stego LSB CRC-32 mismatch (corrupted carrier)".into(),
        ));
    }

    Ok(payload)
}

fn validate_wav_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 12 {
        return Err(Error::Format(
            "input file is smaller than WAV header (truncated)".into(),
        ));
    }
    if &bytes[0..4] != RIFF_MAGIC {
        return Err(Error::Format(
            "input file is not a valid RIFF carrier".into(),
        ));
    }
    if &bytes[8..12] != WAVE_MAGIC {
        return Err(Error::Format(
            "input file is not a valid WAVE audio file".into(),
        ));
    }
    Ok(())
}

fn strip_stego_chunks(wav_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut clean_chunks = Vec::with_capacity(wav_bytes.len());
    clean_chunks.extend_from_slice(&wav_bytes[0..12]);

    let mut offset = 12;
    while offset + 8 <= wav_bytes.len() {
        let chunk_id = &wav_bytes[offset..offset + 4];
        let chunk_size =
            u32::from_le_bytes(wav_bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let data_start = offset + 8;
        let data_end = data_start.saturating_add(chunk_size);
        if data_end > wav_bytes.len() {
            if chunk_id == STEGO_CHUNK_ID {
                return Err(Error::Format(
                    "stego chunk truncated while scanning chunks".into(),
                ));
            }
            break;
        }
        let pad = if chunk_size % 2 == 1 { 1 } else { 0 };
        let chunk_full_end = (data_end + pad).min(wav_bytes.len());

        if chunk_id != STEGO_CHUNK_ID {
            clean_chunks.extend_from_slice(&wav_bytes[offset..chunk_full_end]);
            // If the carrier had an odd-sized chunk at EOF missing its 0x00 pad byte,
            // append the pad byte to maintain RIFF 2-byte chunk alignment!
            if chunk_full_end == data_end && pad == 1 {
                clean_chunks.push(0x00);
            }
        }
        offset = chunk_full_end;
    }

    let trailing = if offset < wav_bytes.len() {
        wav_bytes[offset..].to_vec()
    } else {
        Vec::new()
    };

    Ok((clean_chunks, trailing))
}

struct WavPcmInfo {
    #[allow(dead_code)]
    audio_format: u16,
    #[allow(dead_code)]
    num_channels: u16,
    #[allow(dead_code)]
    sample_rate: u32,
    #[allow(dead_code)]
    bits_per_sample: u16,
    data_offset: usize,
    data_len: usize,
}

fn parse_wav_pcm_info(wav_bytes: &[u8]) -> Result<WavPcmInfo> {
    validate_wav_header(wav_bytes)?;

    let mut fmt_info = None;
    let mut data_info = None;

    let mut offset = 12;
    while offset + 8 <= wav_bytes.len() {
        let chunk_id = &wav_bytes[offset..offset + 4];
        let chunk_size =
            u32::from_le_bytes(wav_bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let data_start = offset + 8;
        let data_end = data_start.saturating_add(chunk_size);
        if data_end > wav_bytes.len() {
            if chunk_id == FMT_CHUNK_ID || chunk_id == DATA_CHUNK_ID {
                return Err(Error::Format("truncated WAV chunk data".into()));
            }
            break;
        }
        let pad = if chunk_size % 2 == 1 { 1 } else { 0 };

        if chunk_id == FMT_CHUNK_ID {
            if chunk_size < 16 {
                return Err(Error::Format("malformed fmt chunk: too small".into()));
            }
            let audio_format =
                u16::from_le_bytes(wav_bytes[data_start..data_start + 2].try_into().unwrap());
            let num_channels = u16::from_le_bytes(
                wav_bytes[data_start + 2..data_start + 4]
                    .try_into()
                    .unwrap(),
            );
            let sample_rate = u32::from_le_bytes(
                wav_bytes[data_start + 4..data_start + 8]
                    .try_into()
                    .unwrap(),
            );
            let bits_per_sample = u16::from_le_bytes(
                wav_bytes[data_start + 14..data_start + 16]
                    .try_into()
                    .unwrap(),
            );
            fmt_info = Some((audio_format, num_channels, sample_rate, bits_per_sample));
        } else if chunk_id == DATA_CHUNK_ID {
            data_info = Some((data_start, chunk_size));
        }

        offset = data_end.saturating_add(pad);
    }

    let (audio_format, num_channels, sample_rate, bits_per_sample) =
        fmt_info.ok_or_else(|| Error::Format("WAV file missing required 'fmt ' chunk".into()))?;
    let (data_offset, data_len) =
        data_info.ok_or_else(|| Error::Format("WAV file missing required 'data' chunk".into()))?;

    if num_channels == 0 {
        return Err(Error::Format(
            "malformed fmt chunk: zero audio channels".into(),
        ));
    }
    if sample_rate == 0 {
        return Err(Error::Format(
            "malformed fmt chunk: zero sample rate".into(),
        ));
    }
    if audio_format != 1 {
        return Err(Error::Format(format!(
            "unsupported WAV audio format {audio_format} (only uncompressed PCM format 1 is supported)"
        )));
    }
    if bits_per_sample != 16 {
        return Err(Error::Format(format!(
            "unsupported bit depth {bits_per_sample}-bit (only 16-bit PCM WAV audio is supported for LSB steganography)"
        )));
    }

    Ok(WavPcmInfo {
        audio_format,
        num_channels,
        sample_rate,
        bits_per_sample,
        data_offset,
        data_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a valid uncompressed 16-bit PCM WAV in memory.
    pub fn create_test_wav(num_samples: usize) -> Vec<u8> {
        let sample_bytes = num_samples * 2;
        let riff_size = (36 + sample_bytes) as u32;

        let mut wav = Vec::with_capacity(44 + sample_bytes);
        // RIFF header
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&riff_size.to_le_bytes());
        wav.extend_from_slice(b"WAVE");

        // fmt chunk (16-bit mono 44.1 kHz PCM)
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes()); // subchunk size
        wav.extend_from_slice(&1u16.to_le_bytes()); // audio format 1 (PCM)
        wav.extend_from_slice(&1u16.to_le_bytes()); // channels: 1 (mono)
        wav.extend_from_slice(&44100u32.to_le_bytes()); // sample rate
        wav.extend_from_slice(&88200u32.to_le_bytes()); // byte rate (44100 * 1 * 16 / 8)
        wav.extend_from_slice(&2u16.to_le_bytes()); // block align
        wav.extend_from_slice(&16u16.to_le_bytes()); // bits per sample

        // data chunk
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&(sample_bytes as u32).to_le_bytes());
        for i in 0..num_samples {
            // Triangular sample wave: low-magnitude audible-range samples
            let sample = ((i % 100) as i16) * 100;
            wav.extend_from_slice(&sample.to_le_bytes());
        }

        wav
    }

    #[test]
    fn wav_chunk_embed_and_extract_roundtrip() {
        let carrier = create_test_wav(100);
        let secret = b"super-secret-vault-payload-wav-chunk";

        let stego = embed_in_wav(&carrier, secret, WavMode::Chunk).unwrap();
        assert_eq!(&stego[0..4], b"RIFF");
        assert_eq!(&stego[8..12], b"WAVE");

        let extracted = extract_from_wav(&stego, ExtractWavMode::Chunk).unwrap();
        assert_eq!(extracted, secret);
    }

    #[test]
    fn wav_chunk_reembedding_is_idempotent() {
        let carrier = create_test_wav(100);
        let first = embed_in_wav(&carrier, b"initial payload", WavMode::Chunk).unwrap();
        let second = embed_in_wav(&first, b"updated payload", WavMode::Chunk).unwrap();

        let extracted = extract_from_wav(&second, ExtractWavMode::Chunk).unwrap();
        assert_eq!(extracted, b"updated payload");
    }

    #[test]
    fn wav_chunk_crc_mismatch_fails() {
        let carrier = create_test_wav(100);
        let mut stego = embed_in_wav(&carrier, b"data to corrupt", WavMode::Chunk).unwrap();

        // Corrupt the first payload byte of the svLt chunk
        let svlt_pos = stego.windows(4).position(|w| w == b"svLt").unwrap();
        stego[svlt_pos + 8] ^= 0xFF;

        let res = extract_from_wav(&stego, ExtractWavMode::Chunk);
        assert!(res.is_err());
    }

    #[test]
    fn wav_lsb_embed_and_extract_roundtrip() {
        // 50 bytes payload + 12 bytes overhead = 62 bytes * 8 = 496 samples needed
        let carrier = create_test_wav(600);
        let secret = b"audio-lsb-steganography-payload-0123456789";

        let stego = embed_in_wav(&carrier, secret, WavMode::Lsb).unwrap();
        // LSB mode preserves carrier byte length exactly
        assert_eq!(stego.len(), carrier.len());

        let extracted = extract_from_wav(&stego, ExtractWavMode::Lsb).unwrap();
        assert_eq!(extracted, secret);
    }

    #[test]
    fn wav_lsb_reembedding_is_idempotent() {
        let carrier = create_test_wav(600);
        let first = embed_in_wav(&carrier, b"first lsb", WavMode::Lsb).unwrap();
        let second = embed_in_wav(&first, b"second lsb replaced", WavMode::Lsb).unwrap();

        let extracted = extract_from_wav(&second, ExtractWavMode::Lsb).unwrap();
        assert_eq!(extracted, b"second lsb replaced");
    }

    #[test]
    fn wav_lsb_insufficient_capacity_fails() {
        let carrier = create_test_wav(50); // only 50 samples available
        let secret = b"this payload is definitely too large for fifty samples";

        let res = embed_in_wav(&carrier, secret, WavMode::Lsb);
        assert!(res.is_err());
    }

    #[test]
    fn wav_lsb_crc_mismatch_fails() {
        let carrier = create_test_wav(600);
        let mut stego = embed_in_wav(&carrier, b"lsb data integrity", WavMode::Lsb).unwrap();

        // Corrupt a sample LSB in the data section (e.g. sample 80)
        let sample_byte = 44 + 80 * 2;
        stego[sample_byte] ^= 0x01;

        let res = extract_from_wav(&stego, ExtractWavMode::Lsb);
        assert!(res.is_err());
    }

    #[test]
    fn wav_auto_extracts_both_chunk_and_lsb() {
        let carrier = create_test_wav(600);
        let chunk_secret = b"chunk secret test";
        let lsb_secret = b"lsb secret test";

        let stego_chunk = embed_in_wav(&carrier, chunk_secret, WavMode::Chunk).unwrap();
        let extracted_chunk = extract_from_wav(&stego_chunk, ExtractWavMode::Auto).unwrap();
        assert_eq!(extracted_chunk, chunk_secret);

        let stego_lsb = embed_in_wav(&carrier, lsb_secret, WavMode::Lsb).unwrap();
        let extracted_lsb = extract_from_wav(&stego_lsb, ExtractWavMode::Auto).unwrap();
        assert_eq!(extracted_lsb, lsb_secret);
    }

    #[test]
    fn wav_invalid_carrier_rejected() {
        let dummy = b"not a wav file at all";
        assert!(embed_in_wav(dummy, b"test", WavMode::Chunk).is_err());
        assert!(extract_from_wav(dummy, ExtractWavMode::Auto).is_err());
    }

    #[test]
    fn wav_chunk_odd_payload_padding() {
        let carrier = create_test_wav(100);
        let secret = b"15-byte-payload"; // exactly 15 bytes (odd)
        let stego = embed_in_wav(&carrier, secret, WavMode::Chunk).unwrap();
        // RIFF chunk payload has 15 + 4 = 19 bytes (odd), so it must be padded to even
        let extracted = extract_from_wav(&stego, ExtractWavMode::Chunk).unwrap();
        assert_eq!(extracted, secret);
    }

    #[test]
    fn wav_lsb_exact_capacity_boundary() {
        let secret = b"exact-boundary-payload";
        let total_bytes = LSB_OVERHEAD_BYTES + secret.len();
        let exact_samples = total_bytes * 8;

        // Carrier with exactly the required sample count
        let carrier = create_test_wav(exact_samples);
        let stego = embed_in_wav(&carrier, secret, WavMode::Lsb).unwrap();
        let extracted = extract_from_wav(&stego, ExtractWavMode::Lsb).unwrap();
        assert_eq!(extracted, secret);

        // One sample less must fail
        let short_carrier = create_test_wav(exact_samples - 1);
        assert!(embed_in_wav(&short_carrier, secret, WavMode::Lsb).is_err());
    }

    #[test]
    fn wav_empty_payload_roundtrip() {
        let carrier = create_test_wav(100);
        let empty = b"";

        let stego_chunk = embed_in_wav(&carrier, empty, WavMode::Chunk).unwrap();
        let extracted_chunk = extract_from_wav(&stego_chunk, ExtractWavMode::Chunk).unwrap();
        assert_eq!(extracted_chunk, empty);

        let stego_lsb = embed_in_wav(&carrier, empty, WavMode::Lsb).unwrap();
        let extracted_lsb = extract_from_wav(&stego_lsb, ExtractWavMode::Lsb).unwrap();
        assert_eq!(extracted_lsb, empty);
    }

    #[test]
    fn wav_auto_detects_corrupted_chunk_without_lsb_fallback() {
        let carrier = create_test_wav(100);
        let mut stego = embed_in_wav(&carrier, b"data to corrupt", WavMode::Chunk).unwrap();

        // Corrupt the first payload byte of the svLt chunk
        let svlt_pos = stego.windows(4).position(|w| w == b"svLt").unwrap();
        stego[svlt_pos + 8] ^= 0xFF;

        let res = extract_from_wav(&stego, ExtractWavMode::Auto);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("CRC-32 mismatch"),
            "expected CRC-32 mismatch error, got: {err_msg}"
        );
    }

    #[test]
    fn wav_auto_detects_corrupted_lsb() {
        let carrier = create_test_wav(600);
        let mut stego = embed_in_wav(&carrier, b"data to corrupt", WavMode::Lsb).unwrap();

        // Corrupt an LSB sample in the payload section
        let sample_byte = 44 + 80 * 2;
        stego[sample_byte] ^= 0x01;

        let res = extract_from_wav(&stego, ExtractWavMode::Auto);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("CRC-32 mismatch"),
            "expected CRC-32 mismatch error, got: {err_msg}"
        );
    }

    #[test]
    fn wav_non_pcm_carrier_rejected_in_lsb_accepted_in_chunk() {
        // Create 24-bit PCM WAV
        let num_samples = 200;
        let sample_bytes = num_samples * 3;
        let riff_size = (36 + sample_bytes) as u32;
        let mut wav24 = Vec::with_capacity(44 + sample_bytes);
        wav24.extend_from_slice(b"RIFF");
        wav24.extend_from_slice(&riff_size.to_le_bytes());
        wav24.extend_from_slice(b"WAVE");
        wav24.extend_from_slice(b"fmt ");
        wav24.extend_from_slice(&16u32.to_le_bytes());
        wav24.extend_from_slice(&1u16.to_le_bytes()); // PCM
        wav24.extend_from_slice(&1u16.to_le_bytes()); // mono
        wav24.extend_from_slice(&44100u32.to_le_bytes());
        wav24.extend_from_slice(&132300u32.to_le_bytes());
        wav24.extend_from_slice(&3u16.to_le_bytes());
        wav24.extend_from_slice(&24u16.to_le_bytes()); // 24-bit
        wav24.extend_from_slice(b"data");
        wav24.extend_from_slice(&(sample_bytes as u32).to_le_bytes());
        wav24.resize(44 + sample_bytes, 0x42);

        // LSB must reject 24-bit
        assert!(embed_in_wav(&wav24, b"test", WavMode::Lsb).is_err());

        // Chunk mode must succeed on 24-bit WAV
        let stego = embed_in_wav(&wav24, b"secret in 24bit", WavMode::Chunk).unwrap();
        let extracted = extract_from_wav(&stego, ExtractWavMode::Chunk).unwrap();
        assert_eq!(extracted, b"secret in 24bit");
    }

    #[test]
    fn wav_malformed_fmt_zero_channels_rejected() {
        let mut carrier = create_test_wav(100);
        // zero out num_channels field at offset 22..24
        carrier[22] = 0;
        carrier[23] = 0;

        assert!(embed_in_wav(&carrier, b"test", WavMode::Lsb).is_err());
        let auto_res = extract_from_wav(&carrier, ExtractWavMode::Auto);
        assert!(auto_res.is_err());
        assert!(auto_res.unwrap_err().to_string().contains("malformed"));
    }

    #[test]
    fn wav_chunk_with_trailing_non_chunk_bytes() {
        let mut carrier = create_test_wav(100);
        let trailing_data = b"ID3v2-trailing-tag-or-padding-data";
        carrier.extend_from_slice(trailing_data);

        let secret = b"secret payload with trailing bytes";
        let stego = embed_in_wav(&carrier, secret, WavMode::Chunk).unwrap();

        // Must extract cleanly in both Chunk and Auto modes
        let extracted_chunk = extract_from_wav(&stego, ExtractWavMode::Chunk).unwrap();
        assert_eq!(extracted_chunk, secret);

        let extracted_auto = extract_from_wav(&stego, ExtractWavMode::Auto).unwrap();
        assert_eq!(extracted_auto, secret);

        // Trailing bytes must be preserved at end of carrier
        assert!(stego.ends_with(trailing_data));

        // Re-embedding must be idempotent even with trailing bytes
        let re_embedded = embed_in_wav(&stego, b"updated-secret", WavMode::Chunk).unwrap();
        let extracted_updated = extract_from_wav(&re_embedded, ExtractWavMode::Chunk).unwrap();
        assert_eq!(extracted_updated, b"updated-secret");
        assert!(re_embedded.ends_with(trailing_data));
    }

    #[test]
    fn wav_auto_detects_truncated_chunk_without_lsb_fallback() {
        let carrier = create_test_wav(100);
        let stego = embed_in_wav(&carrier, b"data to truncate", WavMode::Chunk).unwrap();

        // Truncate last 5 bytes cutting off the svLt chunk payload/CRC
        let truncated = &stego[..stego.len() - 5];
        let res = extract_from_wav(truncated, ExtractWavMode::Auto);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("truncated"),
            "expected truncation error, got: {err_msg}"
        );
    }

    #[test]
    fn wav_auto_detects_partial_chunk_header_at_eof() {
        let mut carrier = create_test_wav(100);
        carrier.extend_from_slice(b"svLt\x01"); // only 5 bytes of chunk header

        let res = extract_from_wav(&carrier, ExtractWavMode::Auto);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("truncated"),
            "expected truncation error, got: {err_msg}"
        );
    }

    #[test]
    fn wav_chunk_carrier_with_unpadded_odd_chunk() {
        let mut carrier = create_test_wav(100);
        // Append an unpadded odd chunk at EOF
        carrier.extend_from_slice(b"oddC");
        carrier.extend_from_slice(&5u32.to_le_bytes()); // 5 bytes data (odd)
        carrier.extend_from_slice(b"12345"); // no 0x00 pad byte

        let secret = b"secret in unpadded carrier";
        let stego = embed_in_wav(&carrier, secret, WavMode::Chunk).unwrap();
        let extracted = extract_from_wav(&stego, ExtractWavMode::Chunk).unwrap();
        assert_eq!(extracted, secret);
    }

    #[test]
    fn wav_riff_size_excludes_trailing_non_chunk_bytes() {
        let mut carrier = create_test_wav(100);
        let trailing_data = b"ID3v2-metadata-tag";
        carrier.extend_from_slice(trailing_data);

        let secret = b"secret payload";
        let stego = embed_in_wav(&carrier, secret, WavMode::Chunk).unwrap();

        let riff_size = u32::from_le_bytes(stego[4..8].try_into().unwrap()) as usize;
        // The RIFF container size at 4..8 must describe RIFF chunk data only, NOT trailing non-chunk bytes
        assert_eq!(8 + riff_size + trailing_data.len(), stego.len());
    }

    #[test]
    fn wav_reembed_lsb_over_chunk_stego_replaces_stale_chunk_in_auto() {
        let carrier = create_test_wav(600);
        let stego_chunk = embed_in_wav(&carrier, b"stale chunk payload", WavMode::Chunk).unwrap();
        let stego_lsb = embed_in_wav(&stego_chunk, b"fresh lsb payload", WavMode::Lsb).unwrap();

        // Auto mode must extract the freshly embedded LSB payload, not the stale chunk!
        let extracted_auto = extract_from_wav(&stego_lsb, ExtractWavMode::Auto).unwrap();
        assert_eq!(extracted_auto, b"fresh lsb payload");
    }

    #[test]
    fn wav_auto_detects_carrier_missing_fmt_or_data_chunk() {
        // Create carrier with RIFF WAVE but missing fmt chunk
        let mut carrier = Vec::new();
        carrier.extend_from_slice(b"RIFF");
        carrier.extend_from_slice(&20u32.to_le_bytes());
        carrier.extend_from_slice(b"WAVE");
        carrier.extend_from_slice(b"data");
        carrier.extend_from_slice(&8u32.to_le_bytes());
        carrier.extend_from_slice(&[0u8; 8]);

        let res = extract_from_wav(&carrier, ExtractWavMode::Auto);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("fmt") || err_msg.contains("missing"),
            "expected format error about missing chunk, got: {err_msg}"
        );
    }
}
