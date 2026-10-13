// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for Milestone M14: Stego Carrier Visual & Statistical Diff Report (`src/diff.rs`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn svault() -> Command {
    Command::cargo_bin("svault").expect("svault binary exists")
}

fn create_test_png() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR len=13
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, // 2x2
        0x08, 0x06, 0x00, 0x00, 0x00, // 8-bit RGBA
        0x72, 0xB6, 0x0D, 0x24, // IHDR CRC
        0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, // IDAT len=10
        0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, // IDAT data
        0x0D, 0x0A, 0x2D, 0xB4, // IDAT CRC
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND len=0
        0xAE, 0x42, 0x60, 0x82, // IEND CRC
    ]
}

fn create_test_bmp(width: u32, height: u32) -> Vec<u8> {
    let row_bytes = (width as usize) * 3;
    let row_padding = (4 - (row_bytes % 4)) % 4;
    let row_stride = row_bytes + row_padding;
    let pixel_data_size = row_stride * (height as usize);
    let file_size = (54 + pixel_data_size) as u32;

    let mut buf = Vec::with_capacity(file_size as usize);
    buf.extend_from_slice(b"BM");
    buf.extend_from_slice(&file_size.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&54u32.to_le_bytes());

    buf.extend_from_slice(&40u32.to_le_bytes());
    buf.extend_from_slice(&(width as i32).to_le_bytes());
    buf.extend_from_slice(&(height as i32).to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&24u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&(pixel_data_size as u32).to_le_bytes());
    buf.extend_from_slice(&2835u32.to_le_bytes());
    buf.extend_from_slice(&2835u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    for y in 0..height {
        for x in 0..width {
            let b = ((x * 17 + y * 31) % 256) as u8;
            let g = ((x * 43 + y * 13) % 256) as u8;
            let r = ((x * 59 + y * 71) % 256) as u8;
            buf.push(b);
            buf.push(g);
            buf.push(r);
        }
        buf.resize(buf.len() + row_padding, 0);
    }
    buf
}

fn create_test_wav(num_samples: usize) -> Vec<u8> {
    let sample_bytes = num_samples * 2;
    let riff_size = (36 + sample_bytes) as u32;
    let mut wav = Vec::with_capacity(44 + sample_bytes);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&riff_size.to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&1u16.to_le_bytes()); // Mono
    wav.extend_from_slice(&44100u32.to_le_bytes());
    wav.extend_from_slice(&88200u32.to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&(sample_bytes as u32).to_le_bytes());
    for i in 0..num_samples {
        let sample = ((i % 100) as i16) * 100;
        wav.extend_from_slice(&sample.to_le_bytes());
    }
    wav
}

#[test]
fn test_compare_png_chunk_stego_roundtrip() {
    let dir = tempdir().unwrap();
    let orig_png = dir.path().join("orig.png");
    let stego_png = dir.path().join("stego.png");
    let secret = dir.path().join("secret.txt");

    fs::write(&orig_png, create_test_png()).unwrap();
    fs::write(&secret, b"stealthy secret in png").unwrap();

    svault()
        .args([
            "embed",
            "-c",
            orig_png.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego_png.to_str().unwrap(),
            "-p",
            "png-diff-pass",
        ])
        .assert()
        .success();

    // Human terminal compare
    svault()
        .args([
            "compare",
            orig_png.to_str().unwrap(),
            stego_png.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Carrier Diff & Steganalysis Report",
        ))
        .stdout(predicate::str::contains("PNG"))
        .stdout(predicate::str::contains(
            "Lossless Ancillary Chunk Injection",
        ))
        .stdout(predicate::str::contains("Chunk 'svLt'"));

    // JSON compare
    let output = svault()
        .args([
            "compare",
            orig_png.to_str().unwrap(),
            stego_png.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json_val: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json_val["carrier_type"], "png");
    assert!(json_val["chunk_diff"]["added_chunks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "svLt"));
    assert_eq!(json_val["visual_metrics"]["altered_pixels"], 0);
    assert_eq!(json_val["visual_metrics"]["mse"], 0.0);
}

#[test]
fn test_compare_bmp_lsb_roundtrip() {
    let dir = tempdir().unwrap();
    let orig_bmp = dir.path().join("orig.bmp");
    let stego_bmp = dir.path().join("stego.bmp");
    let secret = dir.path().join("secret.txt");

    fs::write(&orig_bmp, create_test_bmp(64, 64)).unwrap();
    fs::write(&secret, b"bmp lsb diff payload").unwrap();

    svault()
        .args([
            "embed-bmp",
            "-c",
            orig_bmp.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego_bmp.to_str().unwrap(),
            "-p",
            "bmp-diff-pass",
        ])
        .assert()
        .success();

    // Run compare
    let output = svault()
        .args([
            "compare",
            orig_bmp.to_str().unwrap(),
            stego_bmp.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json_val: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json_val["carrier_type"], "bmp");
    assert!(
        json_val["visual_metrics"]["altered_pixels"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(json_val["visual_metrics"]["lsb_flips"].as_u64().unwrap() > 0);
    assert_eq!(json_val["visual_metrics"]["non_lsb_flips"], 0);
    assert!(json_val["visual_metrics"]["psnr_db"].as_f64().unwrap() > 50.0);
    assert_eq!(json_val["visual_metrics"]["padding_altered"], false);
}

#[test]
fn test_compare_wav_chunk_and_lsb_roundtrip() {
    let dir = tempdir().unwrap();
    let orig_wav = dir.path().join("orig.wav");
    let stego_chunk = dir.path().join("stego_chunk.wav");
    let stego_lsb = dir.path().join("stego_lsb.wav");
    let secret = dir.path().join("secret.txt");

    fs::write(&orig_wav, create_test_wav(4000)).unwrap();
    fs::write(&secret, b"wav audio stego diff").unwrap();

    // Embed chunk mode
    svault()
        .args([
            "embed-wav",
            "-c",
            orig_wav.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego_chunk.to_str().unwrap(),
            "-p",
            "wav-pass",
            "--mode",
            "chunk",
        ])
        .assert()
        .success();

    // Embed lsb mode
    svault()
        .args([
            "embed-wav",
            "-c",
            orig_wav.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego_lsb.to_str().unwrap(),
            "-p",
            "wav-pass",
            "--mode",
            "lsb",
        ])
        .assert()
        .success();

    // Compare chunk mode
    let out_chunk = svault()
        .args([
            "compare",
            orig_wav.to_str().unwrap(),
            stego_chunk.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let val_chunk: serde_json::Value = serde_json::from_slice(&out_chunk).unwrap();
    assert_eq!(val_chunk["carrier_type"], "wav");
    assert!(val_chunk["chunk_diff"]["added_chunks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "svLt"));
    assert_eq!(val_chunk["audio_metrics"]["altered_samples"], 0);

    // Compare lsb mode
    let out_lsb = svault()
        .args([
            "compare",
            orig_wav.to_str().unwrap(),
            stego_lsb.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let val_lsb: serde_json::Value = serde_json::from_slice(&out_lsb).unwrap();
    assert_eq!(val_lsb["carrier_type"], "wav");
    assert!(
        val_lsb["audio_metrics"]["altered_samples"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(val_lsb["audio_metrics"]["lsb_flips"].as_u64().unwrap() > 0);
    assert_eq!(val_lsb["audio_metrics"]["non_lsb_flips"], 0);
}

#[test]
fn test_compare_identical_and_binary_files() {
    let dir = tempdir().unwrap();
    let file_a = dir.path().join("file_a.bin");
    let file_b = dir.path().join("file_b.bin");

    fs::write(&file_a, b"identical content buffer 1234567890").unwrap();
    fs::write(&file_b, b"different content buffer 0987654321").unwrap();

    // Identical comparison
    let out_id = svault()
        .args([
            "compare",
            file_a.to_str().unwrap(),
            file_a.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let val_id: serde_json::Value = serde_json::from_slice(&out_id).unwrap();
    assert_eq!(val_id["byte_diff"]["modified_bytes"], 0);
    assert_eq!(val_id["byte_diff"]["hamming_distance"], 0);
    assert_eq!(val_id["histogram_delta"]["tvd"], 0.0);
    assert!(val_id["verdict"].as_str().unwrap().contains("Identical"));

    // Alias test: svault diff
    svault()
        .args([
            "diff",
            file_a.to_str().unwrap(),
            file_b.to_str().unwrap(),
            "--detailed",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Carrier Diff & Steganalysis Report",
        ))
        .stdout(predicate::str::contains("Modified Byte Spans"));
}
