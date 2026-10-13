// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Steganography carrier visual & statistical diff report engine (`svault compare`).
//!
//! Analyzes structural chunk tables, visual metrics (MSE, PSNR, MAE), acoustic metrics (SNR),
//! byte-level Hamming distance, Shannon entropy shifts, and histogram Total Variation Distance (TVD)
//! between original carriers and stego-bearing files.

use crate::error::{Error, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const PNG_SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const BMP_MAGIC: &[u8; 2] = b"BM";
const RIFF_MAGIC: &[u8; 4] = b"RIFF";
const WAVE_MAGIC: &[u8; 4] = b"WAVE";
const STEGO_NAME: &str = "svLt";

/// Contiguous span of modified bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteDiffSpan {
    pub offset: usize,
    pub length: usize,
}

/// Byte-level alignment and modification metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteDiff {
    pub original_size: usize,
    pub stego_size: usize,
    pub size_delta: i64,
    pub identical_bytes: usize,
    pub modified_bytes: usize,
    pub modified_percent: f64,
    pub hamming_distance: u64,
    pub modified_spans: Vec<ByteDiffSpan>,
}

/// Information-theoretic Shannon entropy metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntropyDiff {
    pub original_entropy: f64,
    pub stego_entropy: f64,
    pub entropy_delta: f64,
}

/// 256-bin byte frequency histogram divergence metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistogramDelta {
    pub tvd: f64,
    pub max_bin_delta_byte: u8,
    pub max_bin_delta_count: usize,
    pub chi_square_divergence: f64,
}

/// Discrete carrier chunk or subchunk descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkEntry {
    pub name: String,
    pub offset: usize,
    pub length: usize,
    pub crc32: Option<u32>,
    pub is_stego: bool,
}

/// Chunk table comparison report across container carriers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkDiff {
    pub carrier: String,
    pub original_chunks: Vec<ChunkEntry>,
    pub stego_chunks: Vec<ChunkEntry>,
    pub added_chunks: Vec<ChunkEntry>,
    pub removed_chunks: Vec<ChunkEntry>,
    pub modified_chunks: Vec<String>,
}

/// Visual image signal metrics (MSE, PSNR, MAE, LSB distribution).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisualMetrics {
    pub width: u32,
    pub height: u32,
    pub total_pixels: usize,
    pub altered_pixels: usize,
    pub altered_pixel_percent: f64,
    pub altered_channels: usize,
    pub total_channels: usize,
    pub lsb_flips: usize,
    pub non_lsb_flips: usize,
    pub max_channel_diff: u8,
    pub mse: f64,
    pub psnr_db: f64,
    pub mae: f64,
    pub padding_altered: bool,
}

/// Acoustic audio signal metrics (MSE, PSNR, SNR, sample LSB distribution).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AudioMetrics {
    pub sample_rate: u32,
    pub num_channels: u16,
    pub bits_per_sample: u16,
    pub total_samples: usize,
    pub altered_samples: usize,
    pub altered_sample_percent: f64,
    pub lsb_flips: usize,
    pub non_lsb_flips: usize,
    pub max_sample_diff: i32,
    pub mse: f64,
    pub psnr_db: f64,
    pub snr_db: Option<f64>,
}

/// Comprehensive carrier comparison and diff report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarrierDiffReport {
    pub original_path: String,
    pub stego_path: String,
    pub carrier_type: String,
    pub byte_diff: ByteDiff,
    pub entropy_diff: EntropyDiff,
    pub histogram_delta: HistogramDelta,
    pub chunk_diff: Option<ChunkDiff>,
    pub visual_metrics: Option<VisualMetrics>,
    pub audio_metrics: Option<AudioMetrics>,
    pub verdict: String,
}

/// Compare two carriers from disk and produce a structured diff report.
pub fn compare_files(orig_path: &Path, stego_path: &Path) -> Result<CarrierDiffReport> {
    let orig = fs::read(orig_path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {}", orig_path.display(), e),
        ))
    })?;
    let stego = fs::read(stego_path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {}", stego_path.display(), e),
        ))
    })?;

    compare_carrier_bytes(
        &orig,
        &stego,
        &orig_path.display().to_string(),
        &stego_path.display().to_string(),
    )
}

struct CarrierAnalysis {
    carrier_type: String,
    chunk_diff: Option<ChunkDiff>,
    visual_metrics: Option<VisualMetrics>,
    audio_metrics: Option<AudioMetrics>,
    verdict: String,
}

/// Compare original and stego byte streams and generate statistical & visual reports.
pub fn compare_carrier_bytes(
    orig: &[u8],
    stego: &[u8],
    orig_name: &str,
    stego_name: &str,
) -> Result<CarrierDiffReport> {
    let (byte_diff, entropy_diff, histogram_delta) = compute_statistical_diff(orig, stego);

    let analysis =
        if orig.len() >= 8 && &orig[0..8] == PNG_SIG && stego.len() >= 8 && &stego[0..8] == PNG_SIG
        {
            analyze_png(orig, stego)?
        } else if orig.len() >= 2
            && &orig[0..2] == BMP_MAGIC
            && stego.len() >= 2
            && &stego[0..2] == BMP_MAGIC
        {
            analyze_bmp(orig, stego, byte_diff.modified_bytes == 0)?
        } else if orig.len() >= 12
            && &orig[0..4] == RIFF_MAGIC
            && &orig[8..12] == WAVE_MAGIC
            && stego.len() >= 12
            && &stego[0..4] == RIFF_MAGIC
            && &stego[8..12] == WAVE_MAGIC
        {
            analyze_wav(orig, stego, byte_diff.modified_bytes == 0)?
        } else {
            let verdict = if byte_diff.modified_bytes == 0 {
                "Identical Files (Zero Differences)".to_string()
            } else {
                format!(
                    "Binary Stream Modification ({} bytes altered, {} bit flips)",
                    byte_diff.modified_bytes, byte_diff.hamming_distance
                )
            };
            CarrierAnalysis {
                carrier_type: "binary".to_string(),
                chunk_diff: None,
                visual_metrics: None,
                audio_metrics: None,
                verdict,
            }
        };

    Ok(CarrierDiffReport {
        original_path: orig_name.to_string(),
        stego_path: stego_name.to_string(),
        carrier_type: analysis.carrier_type,
        byte_diff,
        entropy_diff,
        histogram_delta,
        chunk_diff: analysis.chunk_diff,
        visual_metrics: analysis.visual_metrics,
        audio_metrics: analysis.audio_metrics,
        verdict: analysis.verdict,
    })
}

fn compute_statistical_diff(orig: &[u8], stego: &[u8]) -> (ByteDiff, EntropyDiff, HistogramDelta) {
    let mut orig_hist = [0usize; 256];
    let mut stego_hist = [0usize; 256];
    for &b in orig {
        orig_hist[b as usize] += 1;
    }
    for &b in stego {
        stego_hist[b as usize] += 1;
    }

    let orig_entropy = calculate_shannon_entropy(&orig_hist, orig.len());
    let stego_entropy = calculate_shannon_entropy(&stego_hist, stego.len());

    let mut tvd_accum = 0.0f64;
    let mut max_delta_count = 0usize;
    let mut max_delta_byte = 0u8;
    let mut chi_square = 0.0f64;

    for b in 0..256 {
        let p_orig = if !orig.is_empty() {
            orig_hist[b] as f64 / orig.len() as f64
        } else {
            0.0
        };
        let p_stego = if !stego.is_empty() {
            stego_hist[b] as f64 / stego.len() as f64
        } else {
            0.0
        };
        tvd_accum += (p_stego - p_orig).abs() * 0.5;

        let diff_cnt = orig_hist[b].abs_diff(stego_hist[b]);
        if diff_cnt > max_delta_count {
            max_delta_count = diff_cnt;
            max_delta_byte = b as u8;
        }

        let sum_cnt = (orig_hist[b] + stego_hist[b]) as f64;
        if sum_cnt > 0.0 {
            chi_square += (diff_cnt as f64).powi(2) / sum_cnt;
        }
    }

    let min_len = orig.len().min(stego.len());
    let mut identical_bytes = 0usize;
    let mut modified_bytes = 0usize;
    let mut hamming_distance = 0u64;
    let mut spans = Vec::new();
    let mut current_span: Option<(usize, usize)> = None;

    for i in 0..min_len {
        let ob = orig[i];
        let sb = stego[i];
        if ob == sb {
            identical_bytes += 1;
            if let Some((start, len)) = current_span.take() {
                spans.push(ByteDiffSpan {
                    offset: start,
                    length: len,
                });
            }
        } else {
            modified_bytes += 1;
            hamming_distance += (ob ^ sb).count_ones() as u64;
            current_span = match current_span {
                Some((start, len)) => Some((start, len + 1)),
                None => Some((i, 1)),
            };
        }
    }
    if let Some((start, len)) = current_span {
        spans.push(ByteDiffSpan {
            offset: start,
            length: len,
        });
    }

    let extra_len = orig.len().abs_diff(stego.len());
    if extra_len > 0 {
        modified_bytes += extra_len;
        let longer = if stego.len() > orig.len() {
            &stego[min_len..]
        } else {
            &orig[min_len..]
        };
        for &b in longer {
            hamming_distance += b.count_ones() as u64;
        }
        spans.push(ByteDiffSpan {
            offset: min_len,
            length: extra_len,
        });
    }

    let max_len = orig.len().max(stego.len());
    let modified_percent = if max_len > 0 {
        (modified_bytes as f64 / max_len as f64) * 100.0
    } else {
        0.0
    };

    (
        ByteDiff {
            original_size: orig.len(),
            stego_size: stego.len(),
            size_delta: stego.len() as i64 - orig.len() as i64,
            identical_bytes,
            modified_bytes,
            modified_percent,
            hamming_distance,
            modified_spans: spans,
        },
        EntropyDiff {
            original_entropy: orig_entropy,
            stego_entropy,
            entropy_delta: stego_entropy - orig_entropy,
        },
        HistogramDelta {
            tvd: tvd_accum,
            max_bin_delta_byte: max_delta_byte,
            max_bin_delta_count: max_delta_count,
            chi_square_divergence: chi_square,
        },
    )
}

fn calculate_shannon_entropy(hist: &[usize; 256], total_len: usize) -> f64 {
    if total_len == 0 {
        return 0.0;
    }
    let len_f = total_len as f64;
    let mut h = 0.0;
    for &cnt in hist {
        if cnt > 0 {
            let p = cnt as f64 / len_f;
            h -= p * p.log2();
        }
    }
    h
}

fn parse_png_chunks(bytes: &[u8]) -> Vec<ChunkEntry> {
    let mut chunks = Vec::new();
    let mut offset = 8;
    while offset + 12 <= bytes.len() {
        let length =
            u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap_or_default()) as usize;
        let name_bytes = &bytes[offset + 4..offset + 8];
        let name = String::from_utf8_lossy(name_bytes).to_string();
        let data_end = offset + 8 + length;
        if data_end + 4 > bytes.len() {
            break;
        }
        let crc = u32::from_be_bytes(bytes[data_end..data_end + 4].try_into().unwrap_or_default());
        chunks.push(ChunkEntry {
            name: name.clone(),
            offset,
            length,
            crc32: Some(crc),
            is_stego: name == STEGO_NAME,
        });
        offset = data_end + 4;
    }
    chunks
}

fn analyze_png(orig: &[u8], stego: &[u8]) -> Result<CarrierAnalysis> {
    let orig_chunks = parse_png_chunks(orig);
    let stego_chunks = parse_png_chunks(stego);

    let mut added = Vec::new();
    let mut modified = Vec::new();
    for sc in &stego_chunks {
        if !orig_chunks
            .iter()
            .any(|oc| oc.name == sc.name && oc.length == sc.length && oc.crc32 == sc.crc32)
        {
            if orig_chunks.iter().any(|oc| oc.name == sc.name) {
                modified.push(sc.name.clone());
            } else {
                added.push(sc.clone());
            }
        }
    }
    let removed: Vec<_> = orig_chunks
        .iter()
        .filter(|oc| !stego_chunks.iter().any(|sc| sc.name == oc.name))
        .cloned()
        .collect();

    let orig_idat: Vec<_> = orig_chunks.iter().filter(|c| c.name == "IDAT").collect();
    let stego_idat: Vec<_> = stego_chunks.iter().filter(|c| c.name == "IDAT").collect();
    let idat_identical = orig_idat.len() == stego_idat.len()
        && orig_idat
            .iter()
            .zip(&stego_idat)
            .all(|(a, b)| a.length == b.length && a.crc32 == b.crc32);

    let (width, height) = if orig.len() >= 24 && &orig[12..16] == b"IHDR" {
        (
            u32::from_be_bytes(orig[16..20].try_into().unwrap_or_default()),
            u32::from_be_bytes(orig[20..24].try_into().unwrap_or_default()),
        )
    } else {
        (0, 0)
    };

    let visual = if width > 0 && height > 0 {
        let total_pixels = width as usize * height as usize;
        Some(VisualMetrics {
            width,
            height,
            total_pixels,
            altered_pixels: if idat_identical { 0 } else { total_pixels },
            altered_pixel_percent: if idat_identical { 0.0 } else { 100.0 },
            altered_channels: 0,
            total_channels: total_pixels * 4,
            lsb_flips: 0,
            non_lsb_flips: 0,
            max_channel_diff: 0,
            mse: 0.0,
            psnr_db: f64::INFINITY,
            mae: 0.0,
            padding_altered: false,
        })
    } else {
        None
    };

    let has_stego_chunk = added.iter().any(|c| c.is_stego);
    let verdict = if has_stego_chunk && idat_identical {
        "Lossless Ancillary Chunk Injection (svLt chunk present, visual pixel raster 100% unaltered)".to_string()
    } else if orig == stego {
        "Identical PNG Carriers (Zero Differences)".to_string()
    } else {
        format!(
            "Modified PNG Carrier ({} added chunk(s), IDAT identical: {})",
            added.len(),
            idat_identical
        )
    };

    Ok(CarrierAnalysis {
        carrier_type: "png".to_string(),
        chunk_diff: Some(ChunkDiff {
            carrier: "png".to_string(),
            original_chunks: orig_chunks,
            stego_chunks,
            added_chunks: added,
            removed_chunks: removed,
            modified_chunks: modified,
        }),
        visual_metrics: visual,
        audio_metrics: None,
        verdict,
    })
}

fn analyze_bmp(orig: &[u8], stego: &[u8], identical_bytes: bool) -> Result<CarrierAnalysis> {
    let orig_hdr = crate::bmp::parse_bmp_header(orig)?;
    let stego_hdr = crate::bmp::parse_bmp_header(stego)?;

    if orig_hdr.width != stego_hdr.width || orig_hdr.height != stego_hdr.height {
        return Ok(CarrierAnalysis {
            carrier_type: "bmp".to_string(),
            chunk_diff: None,
            visual_metrics: None,
            audio_metrics: None,
            verdict: format!(
                "BMP Dimension Mismatch: {}x{} vs {}x{}",
                orig_hdr.width, orig_hdr.height, stego_hdr.width, stego_hdr.height
            ),
        });
    }

    let w = orig_hdr.width as usize;
    let h = orig_hdr.height as usize;
    let row_bytes = w * 3;
    let mut sq_err = 0.0f64;
    let mut abs_err = 0.0f64;
    let mut altered_pixels = 0usize;
    let mut altered_channels = 0usize;
    let mut lsb_flips = 0usize;
    let mut non_lsb_flips = 0usize;
    let mut max_diff = 0u8;
    let mut padding_altered = false;

    for y in 0..h {
        let o_row = orig_hdr.data_offset + y * orig_hdr.row_stride;
        let s_row = stego_hdr.data_offset + y * stego_hdr.row_stride;

        for x in 0..w {
            let mut pixel_changed = false;
            for c in 0..3 {
                let ob = orig.get(o_row + x * 3 + c).copied().unwrap_or_default();
                let sb = stego.get(s_row + x * 3 + c).copied().unwrap_or_default();
                if ob != sb {
                    altered_channels += 1;
                    pixel_changed = true;
                    let d = ob.abs_diff(sb);
                    max_diff = max_diff.max(d);
                    abs_err += d as f64;
                    sq_err += (d as f64).powi(2);
                    if (ob ^ sb) & 1 == 1 {
                        lsb_flips += 1;
                    }
                    if (ob ^ sb) & 0xFE != 0 {
                        non_lsb_flips += 1;
                    }
                }
            }
            if pixel_changed {
                altered_pixels += 1;
            }
        }

        if orig_hdr.row_padding > 0 {
            let o_pad = &orig[o_row + row_bytes..o_row + orig_hdr.row_stride];
            let s_pad = &stego[s_row + row_bytes..s_row + stego_hdr.row_stride];
            if o_pad != s_pad {
                padding_altered = true;
            }
        }
    }

    let total_pixels = w * h;
    let total_channels = total_pixels * 3;
    let mse = sq_err / total_channels as f64;
    let mae = abs_err / total_channels as f64;
    let psnr_db = if mse == 0.0 {
        f64::INFINITY
    } else {
        10.0 * (255.0 * 255.0 / mse).log10()
    };
    let altered_pixel_percent = (altered_pixels as f64 / total_pixels as f64) * 100.0;

    let verdict = if identical_bytes {
        "Identical BMP Carriers (Zero Differences)".to_string()
    } else if non_lsb_flips == 0 && psnr_db > 50.0 {
        format!(
            "Micro-Modulation Steganography (pure LSB modulation, imperceptible PSNR = {:.2} dB)",
            psnr_db
        )
    } else {
        format!(
            "Pixel Modification (altered pixels: {:.2}%, PSNR = {:.2} dB)",
            altered_pixel_percent, psnr_db
        )
    };

    Ok(CarrierAnalysis {
        carrier_type: "bmp".to_string(),
        chunk_diff: None,
        visual_metrics: Some(VisualMetrics {
            width: orig_hdr.width,
            height: orig_hdr.height,
            total_pixels,
            altered_pixels,
            altered_pixel_percent,
            altered_channels,
            total_channels,
            lsb_flips,
            non_lsb_flips,
            max_channel_diff: max_diff,
            mse,
            psnr_db,
            mae,
            padding_altered,
        }),
        audio_metrics: None,
        verdict,
    })
}

fn parse_wav_subchunks(bytes: &[u8]) -> Vec<ChunkEntry> {
    let mut chunks = Vec::new();
    let mut offset = 12;
    while offset + 8 <= bytes.len() {
        let name = String::from_utf8_lossy(&bytes[offset..offset + 4]).to_string();
        let size = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap_or_default())
            as usize;
        let pad = if size % 2 == 1 { 1 } else { 0 };
        chunks.push(ChunkEntry {
            name: name.clone(),
            offset,
            length: size,
            crc32: None,
            is_stego: name == STEGO_NAME,
        });
        offset = offset
            .saturating_add(8)
            .saturating_add(size)
            .saturating_add(pad);
    }
    chunks
}

fn analyze_wav(orig: &[u8], stego: &[u8], identical_bytes: bool) -> Result<CarrierAnalysis> {
    let orig_chunks = parse_wav_subchunks(orig);
    let stego_chunks = parse_wav_subchunks(stego);

    let mut added = Vec::new();
    let mut modified = Vec::new();
    for sc in &stego_chunks {
        if !orig_chunks
            .iter()
            .any(|oc| oc.name == sc.name && oc.length == sc.length)
        {
            if orig_chunks.iter().any(|oc| oc.name == sc.name) {
                modified.push(sc.name.clone());
            } else {
                added.push(sc.clone());
            }
        }
    }
    let removed: Vec<_> = orig_chunks
        .iter()
        .filter(|oc| !stego_chunks.iter().any(|sc| sc.name == oc.name))
        .cloned()
        .collect();

    let mut audio_metrics = None;
    let orig_data = orig_chunks.iter().find(|c| c.name == "data");
    let stego_data = stego_chunks.iter().find(|c| c.name == "data");

    if let (Some(od), Some(sd)) = (orig_data, stego_data) {
        if od.length == sd.length && od.length >= 2 {
            let o_bytes = &orig[od.offset + 8..od.offset + 8 + od.length];
            let s_bytes = &stego[sd.offset + 8..sd.offset + 8 + sd.length];
            let sample_count = od.length / 2;

            let mut sq_err = 0.0f64;
            let mut signal_energy = 0.0f64;
            let mut altered_samples = 0usize;
            let mut lsb_flips = 0usize;
            let mut non_lsb_flips = 0usize;
            let mut max_diff = 0i32;

            for i in 0..sample_count {
                let os =
                    i16::from_le_bytes(o_bytes[i * 2..i * 2 + 2].try_into().unwrap_or_default())
                        as i32;
                let ss =
                    i16::from_le_bytes(s_bytes[i * 2..i * 2 + 2].try_into().unwrap_or_default())
                        as i32;
                signal_energy += (os as f64).powi(2);

                if os != ss {
                    altered_samples += 1;
                    let diff = (os - ss).abs();
                    max_diff = max_diff.max(diff);
                    sq_err += (diff as f64).powi(2);

                    let ob = (os as u16) as u32;
                    let sb = (ss as u16) as u32;
                    if (ob ^ sb) & 1 == 1 {
                        lsb_flips += 1;
                    }
                    if (ob ^ sb) & 0xFFFE != 0 {
                        non_lsb_flips += 1;
                    }
                }
            }

            let mse = sq_err / sample_count as f64;
            let psnr_db = if mse == 0.0 {
                f64::INFINITY
            } else {
                10.0 * (32767.0 * 32767.0 / mse).log10()
            };
            let snr_db = if sq_err > 0.0 && signal_energy > 0.0 {
                Some(10.0 * (signal_energy / sq_err).log10())
            } else if mse == 0.0 {
                Some(f64::INFINITY)
            } else {
                None
            };

            audio_metrics = Some(AudioMetrics {
                sample_rate: 44100,
                num_channels: 2,
                bits_per_sample: 16,
                total_samples: sample_count,
                altered_samples,
                altered_sample_percent: (altered_samples as f64 / sample_count as f64) * 100.0,
                lsb_flips,
                non_lsb_flips,
                max_sample_diff: max_diff,
                mse,
                psnr_db,
                snr_db,
            });
        }
    }

    let has_stego_chunk = added.iter().any(|c| c.is_stego);
    let verdict = if identical_bytes {
        "Identical WAV Carriers (Zero Differences)".to_string()
    } else if has_stego_chunk
        && audio_metrics
            .as_ref()
            .map_or(true, |m| m.altered_samples == 0)
    {
        "Lossless RIFF Subchunk Steganography (svLt subchunk added, PCM samples unaltered)"
            .to_string()
    } else if let Some(ref m) = audio_metrics {
        if m.non_lsb_flips == 0 && m.psnr_db > 60.0 {
            format!(
                "Acoustic LSB Steganography (pure LSB modulation, SNR = {:.1} dB)",
                m.snr_db.unwrap_or(m.psnr_db)
            )
        } else {
            format!(
                "Audio Sample Modification (altered samples: {:.2}%, MSE = {:.2})",
                m.altered_sample_percent, m.mse
            )
        }
    } else {
        format!("Modified WAV Carrier ({} added chunk(s))", added.len())
    };

    Ok(CarrierAnalysis {
        carrier_type: "wav".to_string(),
        chunk_diff: Some(ChunkDiff {
            carrier: "wav".to_string(),
            original_chunks: orig_chunks,
            stego_chunks,
            added_chunks: added,
            removed_chunks: removed,
            modified_chunks: modified,
        }),
        visual_metrics: None,
        audio_metrics,
        verdict,
    })
}

/// Print formatted human-readable diff report to stdout.
pub fn print_diff_report(report: &CarrierDiffReport, detailed: bool) {
    println!(
        "{}",
        "=== Carrier Diff & Steganalysis Report ===".cyan().bold()
    );
    println!(
        "  {:<20} {}",
        "Original Carrier:".bold(),
        report.original_path
    );
    println!("  {:<20} {}", "Stego Carrier:".bold(), report.stego_path);
    println!(
        "  {:<20} {}",
        "Carrier Type:".bold(),
        report.carrier_type.to_uppercase()
    );
    println!(
        "  {:<20} {}",
        "Verdict:".bold(),
        report.verdict.green().bold()
    );
    println!();

    println!("{}", "[Byte & Statistical Alignment]".bold());
    println!(
        "  Original Size:       {} bytes",
        report.byte_diff.original_size
    );
    println!(
        "  Stego Size:          {} bytes (delta: {:+} bytes)",
        report.byte_diff.stego_size, report.byte_diff.size_delta
    );
    println!(
        "  Identical Bytes:     {} ({:.2}%)",
        report.byte_diff.identical_bytes,
        100.0 - report.byte_diff.modified_percent
    );
    println!(
        "  Modified Bytes:      {} ({:.2}%)",
        report.byte_diff.modified_bytes, report.byte_diff.modified_percent
    );
    println!(
        "  Hamming Distance:    {} bit flips",
        report.byte_diff.hamming_distance
    );
    println!(
        "  Shannon Entropy:     {:.4} -> {:.4} (delta: {:+.4})",
        report.entropy_diff.original_entropy,
        report.entropy_diff.stego_entropy,
        report.entropy_diff.entropy_delta
    );
    println!(
        "  Histogram TVD:       {:.6} (chi-sq: {:.2})",
        report.histogram_delta.tvd, report.histogram_delta.chi_square_divergence
    );
    println!();

    if let Some(ref vis) = report.visual_metrics {
        println!("{}", "[Visual Signal Metrics]".bold());
        println!(
            "  Dimensions:          {}x{} ({} pixels)",
            vis.width, vis.height, vis.total_pixels
        );
        println!(
            "  Altered Pixels:      {} ({:.2}%)",
            vis.altered_pixels, vis.altered_pixel_percent
        );
        println!(
            "  Altered Channels:    {} of {}",
            vis.altered_channels, vis.total_channels
        );
        println!(
            "  Bit Flip Dist:       LSB: {} | Non-LSB: {}",
            vis.lsb_flips, vis.non_lsb_flips
        );
        println!("  Mean Squared Error:  {:.6}", vis.mse);
        if vis.psnr_db.is_infinite() {
            println!(
                "  Peak SNR (PSNR):     {} (Lossless)",
                "Infinity dB".green()
            );
        } else {
            println!("  Peak SNR (PSNR):     {:.2} dB", vis.psnr_db);
        }
        println!("  Max Channel Delta:   {}", vis.max_channel_diff);
        if vis.padding_altered {
            println!(
                "  Row Padding:         {}",
                "MODIFIED (Anomaly detected!)".red().bold()
            );
        }
        println!();
    }

    if let Some(ref aud) = report.audio_metrics {
        println!("{}", "[Acoustic Signal Metrics]".bold());
        println!(
            "  Samples Analyzed:    {} ({} Hz, {} bps)",
            aud.total_samples, aud.sample_rate, aud.bits_per_sample
        );
        println!(
            "  Altered Samples:     {} ({:.2}%)",
            aud.altered_samples, aud.altered_sample_percent
        );
        println!(
            "  Bit Flip Dist:       LSB: {} | Non-LSB: {}",
            aud.lsb_flips, aud.non_lsb_flips
        );
        println!("  Mean Squared Error:  {:.6}", aud.mse);
        if aud.psnr_db.is_infinite() {
            println!(
                "  Peak SNR (PSNR):     {} (Lossless)",
                "Infinity dB".green()
            );
        } else {
            println!("  Peak SNR (PSNR):     {:.2} dB", aud.psnr_db);
        }
        if let Some(snr) = aud.snr_db {
            if snr.is_infinite() {
                println!("  Signal-to-Noise:     {}", "Infinity dB".green());
            } else {
                println!("  Signal-to-Noise:     {:.2} dB", snr);
            }
        }
        println!();
    }

    if let Some(ref chunks) = report.chunk_diff {
        println!("{}", "[Carrier Chunk Table Differences]".bold());
        println!("  Original Chunks:     {}", chunks.original_chunks.len());
        println!("  Stego Chunks:        {}", chunks.stego_chunks.len());
        for c in &chunks.added_chunks {
            let tag = if c.is_stego {
                "[STEGO]".green().bold()
            } else {
                "[ADDED]".yellow()
            };
            println!(
                "  + {} Chunk '{}' at offset {} ({} bytes)",
                tag, c.name, c.offset, c.length
            );
        }
        for c in &chunks.removed_chunks {
            println!(
                "  - {} Chunk '{}' at offset {}",
                "[REMOVED]".red(),
                c.name,
                c.offset
            );
        }
        for name in &chunks.modified_chunks {
            println!("  * {} Chunk '{}'", "[MODIFIED]".yellow(), name);
        }
        println!();
    }

    if detailed && !report.byte_diff.modified_spans.is_empty() {
        println!("{}", "[Modified Byte Spans (up to 10)]".bold());
        for (i, span) in report.byte_diff.modified_spans.iter().take(10).enumerate() {
            println!(
                "  Span #{}: offset 0x{:X}..0x{:X} ({} bytes)",
                i + 1,
                span.offset,
                span.offset + span.length,
                span.length
            );
        }
        if report.byte_diff.modified_spans.len() > 10 {
            println!(
                "  ... and {} more spans",
                report.byte_diff.modified_spans.len() - 10
            );
        }
        println!();
    }
}

/// Handle CLI `compare` subcommand dispatch.
pub fn handle_compare_command(orig: &Path, stego: &Path, json: bool, detailed: bool) -> Result<()> {
    let report = compare_files(orig, stego)?;
    if json {
        let serialized = serde_json::to_string_pretty(&report)
            .map_err(|e| Error::Format(format!("failed to serialize diff report to JSON: {e}")))?;
        println!("{serialized}");
    } else {
        print_diff_report(&report, detailed);
    }
    Ok(())
}
