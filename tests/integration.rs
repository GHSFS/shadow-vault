// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn cli_version_and_help_work() {
    Command::cargo_bin("svault")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("svault 0.3.0"));

    Command::cargo_bin("svault")
        .unwrap()
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("svault 0.3.0"));

    Command::cargo_bin("svault")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ShadowVault"))
        .stdout(predicate::str::contains("encrypt"))
        .stdout(predicate::str::contains("encrypt-decoy"))
        .stdout(predicate::str::contains("decrypt"))
        .stdout(predicate::str::contains("decrypt-decoy"))
        .stdout(predicate::str::contains("embed"))
        .stdout(predicate::str::contains("extract"))
        .stdout(predicate::str::contains("embed-wav"))
        .stdout(predicate::str::contains("extract-wav"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("shred"));

    Command::cargo_bin("svault")
        .unwrap()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("ShadowVault"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["embed-wav", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("embed-wav"))
        .stdout(predicate::str::contains("--mode"))
        .stdout(predicate::str::contains("--lsb"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["embed-wav", "-h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("embed-wav"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["extract-wav", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("extract-wav"))
        .stdout(predicate::str::contains("--mode"))
        .stdout(predicate::str::contains("--lsb"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["extract-wav", "-h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("extract-wav"));
}

#[test]
fn cli_encrypt_inspect_and_decrypt_roundtrip() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("secret.txt");
    let vault_path = dir.path().join("secret.svault");
    let out_path = dir.path().join("restored.txt");

    let payload = b"recovery key: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    fs::write(&src_path, payload).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            src_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "vault-master-pass",
            "--dpapi",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("dpapi_bound:       true"));

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "vault-master-pass",
        ])
        .assert()
        .success();

    let restored = fs::read(&out_path).unwrap();
    assert_eq!(restored, payload);
}

#[test]
fn cli_png_embed_and_extract_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.png");
    let secret_path = dir.path().join("note.txt");
    let stego_path = dir.path().join("stego.png");
    let extracted_path = dir.path().join("extracted.txt");

    let minimal_png: [u8; 67] = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    fs::write(&carrier_path, minimal_png).unwrap();
    fs::write(&secret_path, b"hidden inside PNG carrier").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "png-secret-key",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            extracted_path.to_str().unwrap(),
            "-p",
            "png-secret-key",
        ])
        .assert()
        .success();

    let extracted = fs::read(&extracted_path).unwrap();
    assert_eq!(extracted, b"hidden inside PNG carrier");
}

fn generate_pcm_wav(num_samples: usize) -> Vec<u8> {
    let sample_bytes = num_samples * 2;
    let riff_size = (36 + sample_bytes) as u32;
    let mut wav = Vec::with_capacity(44 + sample_bytes);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&riff_size.to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
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
fn cli_wav_chunk_embed_inspect_and_extract_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.wav");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego_chunk.wav");
    let extracted_path = dir.path().join("extracted_chunk.txt");

    let wav = generate_pcm_wav(200);
    fs::write(&carrier_path, wav).unwrap();
    let payload = b"classified audio carrier note via RIFF chunk";
    fs::write(&secret_path, payload).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-wav",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "wav-chunk-secret-pass",
            "--mode",
            "chunk",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 1"))
        .stdout(predicate::str::contains("dpapi_bound:       false"));

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-wav",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            extracted_path.to_str().unwrap(),
            "-p",
            "wav-chunk-secret-pass",
        ])
        .assert()
        .success();

    let extracted = fs::read(&extracted_path).unwrap();
    assert_eq!(extracted, payload);
}

#[test]
fn cli_wav_lsb_embed_inspect_and_extract_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.wav");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego_lsb.wav");
    let extracted_path = dir.path().join("extracted_lsb.txt");

    // Needs enough samples: (payload.len() + 34 container header + 16 mac + 12 LSB overhead) * 8
    let wav = generate_pcm_wav(1500);
    fs::write(&carrier_path, wav).unwrap();
    let payload = b"top-secret audio payload hidden in 16-bit PCM sample LSBs";
    fs::write(&secret_path, payload).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-wav",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "wav-lsb-secret-pass",
            "--lsb",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 1"));

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-wav",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            extracted_path.to_str().unwrap(),
            "-p",
            "wav-lsb-secret-pass",
            "--mode",
            "lsb",
        ])
        .assert()
        .success();

    let extracted = fs::read(&extracted_path).unwrap();
    assert_eq!(extracted, payload);

    // Verify default auto mode also extracts LSB payload cleanly
    let auto_extracted_path = dir.path().join("auto_extracted_lsb.txt");
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-wav",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            auto_extracted_path.to_str().unwrap(),
            "-p",
            "wav-lsb-secret-pass",
        ])
        .assert()
        .success();

    let auto_extracted = fs::read(&auto_extracted_path).unwrap();
    assert_eq!(auto_extracted, payload);
}

#[test]
fn cli_wav_cross_mode_reembedding_and_auto_extract() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier_cross.wav");
    let secret1_path = dir.path().join("secret1.txt");
    let secret2_path = dir.path().join("secret2.txt");
    let stego1_path = dir.path().join("stego1.wav");
    let stego2_path = dir.path().join("stego2.wav");
    let extracted_path = dir.path().join("extracted_final.txt");

    let wav = generate_pcm_wav(1500);
    fs::write(&carrier_path, wav).unwrap();
    fs::write(&secret1_path, b"initial chunk secret").unwrap();
    fs::write(&secret2_path, b"updated lsb secret replaces prior chunk").unwrap();

    // 1. Embed using chunk mode
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-wav",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            secret1_path.to_str().unwrap(),
            "-o",
            stego1_path.to_str().unwrap(),
            "-p",
            "cross-pass-1",
            "--mode",
            "chunk",
        ])
        .assert()
        .success();

    // 2. Re-embed on top of stego1 using LSB mode
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-wav",
            "-c",
            stego1_path.to_str().unwrap(),
            "-s",
            secret2_path.to_str().unwrap(),
            "-o",
            stego2_path.to_str().unwrap(),
            "-p",
            "cross-pass-2",
            "--lsb",
        ])
        .assert()
        .success();

    // 3. Extract with default Auto mode
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-wav",
            "-c",
            stego2_path.to_str().unwrap(),
            "-o",
            extracted_path.to_str().unwrap(),
            "-p",
            "cross-pass-2",
        ])
        .assert()
        .success();

    let extracted = fs::read(&extracted_path).unwrap();
    assert_eq!(extracted, b"updated lsb secret replaces prior chunk");
}

#[test]
fn cli_decoy_encrypt_inspect_and_dual_decrypt_roundtrip() {
    let dir = tempdir().unwrap();
    let primary_path = dir.path().join("primary_secret.txt");
    let decoy_path = dir.path().join("decoy_harmless.txt");
    let vault_path = dir.path().join("vault.svault");
    let out_primary_path = dir.path().join("out_primary.txt");
    let out_decoy_path = dir.path().join("out_decoy.txt");
    let out_decoy_explicit = dir.path().join("out_decoy_explicit.txt");

    let primary_data = b"classified master seed: 0xDEADBEEFCAFE00112233445566778899";
    let decoy_data = b"harmless shopping list: apples, bananas, whole milk";
    fs::write(&primary_path, primary_data).unwrap();
    fs::write(&decoy_path, decoy_data).unwrap();

    // 1. Encrypt dual-password plausible deniability container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt-decoy",
            "-i",
            primary_path.to_str().unwrap(),
            "-d",
            decoy_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "primary-top-secret-pass",
            "--decoy-passphrase",
            "decoy-coercion-pass",
        ])
        .assert()
        .success();

    // 2. Inspect recognizes decoy container and respects deniability
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 2"))
        .stdout(predicate::str::contains("dpapi_bound:       false"))
        .stdout(predicate::str::contains(
            "container_type:    decoy (plausible deniability)",
        ));

    // 3. Seamlessly decrypt primary secret with primary passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_primary_path.to_str().unwrap(),
            "-p",
            "primary-top-secret-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_primary_path).unwrap(), primary_data);

    // 4. Seamlessly decrypt decoy payload with decoy passphrase using standard decrypt command
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_decoy_path.to_str().unwrap(),
            "-p",
            "decoy-coercion-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_decoy_path).unwrap(), decoy_data);

    // 5. Decrypt using explicit decrypt-decoy subcommand
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt-decoy",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_decoy_explicit.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-coercion-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_decoy_explicit).unwrap(), decoy_data);

    // 6. Wrong passphrase fails authentication
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            dir.path().join("fail.txt").to_str().unwrap(),
            "-p",
            "wrong-compromised-pass",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_encrypt_with_decoy_flags_and_dpapi_roundtrip() {
    let dir = tempdir().unwrap();
    let primary_path = dir.path().join("prim.txt");
    let decoy_path = dir.path().join("decoy.txt");
    let vault_path = dir.path().join("vault_dpapi.svault");
    let out_p = dir.path().join("out_p.txt");
    let out_d = dir.path().join("out_d.txt");

    let p_data = b"hardware bound primary payload under dpapi";
    let d_data = b"hardware bound decoy payload under dpapi";
    fs::write(&primary_path, p_data).unwrap();
    fs::write(&decoy_path, d_data).unwrap();

    // Use standard encrypt command with --decoy and --decoy-passphrase flags and --dpapi
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            primary_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "prim-key-123",
            "--decoy",
            decoy_path.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-key-456",
            "--dpapi",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("dpapi_bound:       true"))
        .stdout(predicate::str::contains(
            "container_type:    decoy (plausible deniability)",
        ));

    // Decrypt primary
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_p.to_str().unwrap(),
            "-p",
            "prim-key-123",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_p).unwrap(), p_data);

    // Decrypt decoy
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_d.to_str().unwrap(),
            "-p",
            "decoy-key-456",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_d).unwrap(), d_data);
}

#[test]
fn cli_decoy_embedded_in_png_and_wav_roundtrip() {
    let dir = tempdir().unwrap();
    let primary_path = dir.path().join("hidden_note.txt");
    let decoy_path = dir.path().join("decoy_note.txt");
    let decoy_vault_path = dir.path().join("decoy.svault");
    let carrier_png = dir.path().join("carrier.png");
    let stego_png = dir.path().join("stego_decoy.png");
    let carrier_wav = dir.path().join("carrier.wav");
    let stego_wav = dir.path().join("stego_decoy.wav");

    let p_data = b"ultra-secret operation: project aegis";
    let d_data = b"innocent recipe: chocolate chip cookies";
    fs::write(&primary_path, p_data).unwrap();
    fs::write(&decoy_path, d_data).unwrap();

    // 1. Create decoy container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt-decoy",
            "-i",
            primary_path.to_str().unwrap(),
            "-d",
            decoy_path.to_str().unwrap(),
            "-o",
            decoy_vault_path.to_str().unwrap(),
            "-p",
            "prim-stego-pass",
            "--decoy-passphrase",
            "decoy-stego-pass",
        ])
        .assert()
        .success();

    // 2. Embed decoy container in PNG image
    let minimal_png: [u8; 67] = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    fs::write(&carrier_png, minimal_png).unwrap();

    // Embed the decoy vault into PNG
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed",
            "-c",
            carrier_png.to_str().unwrap(),
            "-s",
            decoy_vault_path.to_str().unwrap(),
            "-o",
            stego_png.to_str().unwrap(),
            "-p",
            "outer-carrier-pass",
        ])
        .assert()
        .success();

    // Extract outer container from PNG
    let extracted_vault_path = dir.path().join("extracted_decoy.svault");
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract",
            "-c",
            stego_png.to_str().unwrap(),
            "-o",
            extracted_vault_path.to_str().unwrap(),
            "-p",
            "outer-carrier-pass",
        ])
        .assert()
        .success();

    // The extracted vault is the dual-slot container: unlock primary and decoy
    let out_p = dir.path().join("ext_p.txt");
    let out_d = dir.path().join("ext_d.txt");

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            extracted_vault_path.to_str().unwrap(),
            "-o",
            out_p.to_str().unwrap(),
            "-p",
            "prim-stego-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_p).unwrap(), p_data);

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            extracted_vault_path.to_str().unwrap(),
            "-o",
            out_d.to_str().unwrap(),
            "-p",
            "decoy-stego-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_d).unwrap(), d_data);

    // 3. Embed decoy container in WAV carrier
    let wav = generate_pcm_wav(500);
    fs::write(&carrier_wav, wav).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-wav",
            "-c",
            carrier_wav.to_str().unwrap(),
            "-s",
            decoy_vault_path.to_str().unwrap(),
            "-o",
            stego_wav.to_str().unwrap(),
            "-p",
            "outer-wav-pass",
            "--mode",
            "chunk",
        ])
        .assert()
        .success();

    let extracted_wav_vault = dir.path().join("extracted_wav_decoy.svault");
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-wav",
            "-c",
            stego_wav.to_str().unwrap(),
            "-o",
            extracted_wav_vault.to_str().unwrap(),
            "-p",
            "outer-wav-pass",
        ])
        .assert()
        .success();

    let wav_p = dir.path().join("wav_p.txt");
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            extracted_wav_vault.to_str().unwrap(),
            "-o",
            wav_p.to_str().unwrap(),
            "-p",
            "prim-stego-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&wav_p).unwrap(), p_data);
}

#[test]
fn cli_v2_padding_roundtrip() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("v2_secret.txt");
    let vault_path = dir.path().join("v2_padded.svault");
    let out_path = dir.path().join("v2_restored.txt");

    let payload = b"v2 single payload with explicit 1024-byte padding";
    fs::write(&src_path, payload).unwrap();

    // Encrypt with --padding 1024
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            src_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "v2-padding-passphrase",
            "--padding",
            "1024",
        ])
        .assert()
        .success();

    // Inspect verifies container version 2
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 2"));

    // Decrypt recovers original secret
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "v2-padding-passphrase",
        ])
        .assert()
        .success();

    let restored = fs::read(&out_path).unwrap();
    assert_eq!(restored, payload);
}

#[test]
fn cli_embed_png_direct_decoy_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.png");
    let secret_path = dir.path().join("prim.txt");
    let decoy_path = dir.path().join("dec.txt");
    let stego_path = dir.path().join("stego.png");
    let out_prim_path = dir.path().join("out_prim.txt");
    let out_dec_path = dir.path().join("out_dec.txt");

    let minimal_png: [u8; 67] = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    fs::write(&carrier_path, minimal_png).unwrap();
    fs::write(&secret_path, b"primary secret in png").unwrap();
    fs::write(&decoy_path, b"decoy note in png").unwrap();

    // Embed directly with --decoy and --decoy-passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "prim-png-pass",
            "--decoy",
            decoy_path.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-png-pass",
        ])
        .assert()
        .success();

    // Inspect recognizes decoy container in PNG
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 2"))
        .stdout(predicate::str::contains("decoy_container:   true"));

    // Extract primary
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_prim_path.to_str().unwrap(),
            "-p",
            "prim-png-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_prim_path).unwrap(), b"primary secret in png");

    // Extract decoy via --decoy-passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_dec_path.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-png-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_dec_path).unwrap(), b"decoy note in png");
}

#[test]
fn cli_embed_wav_direct_decoy_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.wav");
    let secret_path = dir.path().join("prim.txt");
    let decoy_path = dir.path().join("dec.txt");
    let stego_path = dir.path().join("stego.wav");
    let out_prim_path = dir.path().join("out_prim.txt");
    let out_dec_path = dir.path().join("out_dec.txt");

    let wav = generate_pcm_wav(400);
    fs::write(&carrier_path, wav).unwrap();
    fs::write(&secret_path, b"primary secret in wav carrier").unwrap();
    fs::write(&decoy_path, b"decoy note in wav carrier").unwrap();

    // Embed directly into WAV with --decoy and --decoy-passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-wav",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "prim-wav-pass",
            "--decoy",
            decoy_path.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-wav-pass",
        ])
        .assert()
        .success();

    // Inspect recognizes decoy container in WAV
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 2"))
        .stdout(predicate::str::contains("decoy_container:   true"));

    // Extract primary
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-wav",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_prim_path.to_str().unwrap(),
            "-p",
            "prim-wav-pass",
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&out_prim_path).unwrap(),
        b"primary secret in wav carrier"
    );

    // Extract decoy
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-wav",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_dec_path.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-wav-pass",
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&out_dec_path).unwrap(),
        b"decoy note in wav carrier"
    );
}
