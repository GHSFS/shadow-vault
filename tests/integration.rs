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
        .stdout(predicate::str::contains("svault 0.4.0"));

    Command::cargo_bin("svault")
        .unwrap()
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("svault 0.4.0"));

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
        .stdout(predicate::str::contains("split"))
        .stdout(predicate::str::contains("combine"))
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

#[test]
fn cli_decoy_flag_validation_and_alias() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let decoy = dir.path().join("dec.txt");
    let out = dir.path().join("out.svault");
    fs::write(&src, b"primary").unwrap();
    fs::write(&decoy, b"decoy").unwrap();

    // 1. --decoy without --decoy-passphrase fails
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "p1",
            "--decoy",
            decoy.to_str().unwrap(),
        ])
        .assert()
        .failure();

    // 2. --decoy-passphrase without --decoy fails
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "p1",
            "--decoy-passphrase",
            "p2",
        ])
        .assert()
        .failure();

    // 3. encrypt-decoy accepts --input as alias for --primary
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt-decoy",
            "--input",
            src.to_str().unwrap(),
            "-d",
            decoy.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "p1",
            "--decoy-passphrase",
            "p2",
        ])
        .assert()
        .success();
}

#[test]
fn cli_embed_wav_lsb_direct_decoy_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier_lsb.wav");
    let secret_path = dir.path().join("prim.txt");
    let decoy_path = dir.path().join("dec.txt");
    let stego_path = dir.path().join("stego_lsb.wav");
    let out_prim_path = dir.path().join("out_prim.txt");
    let out_dec_path = dir.path().join("out_dec.txt");

    // Decoy container is ~350 bytes; (350 + 12) * 8 = 2896 samples minimum.
    let wav = generate_pcm_wav(4000);
    fs::write(&carrier_path, wav).unwrap();
    fs::write(&secret_path, b"acoustic classified primary secret").unwrap();
    fs::write(&decoy_path, b"acoustic harmless decoy shopping list").unwrap();

    // Embed directly into WAV sample LSBs with --lsb
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
            "prim-lsb-pass",
            "--decoy",
            decoy_path.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-lsb-pass",
            "--lsb",
        ])
        .assert()
        .success();

    // Inspect recognizes decoy container in WAV LSB carrier
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 2"))
        .stdout(predicate::str::contains("decoy_container:   true"));

    // Extract primary seamlessly with -p
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-wav",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_prim_path.to_str().unwrap(),
            "-p",
            "prim-lsb-pass",
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&out_prim_path).unwrap(),
        b"acoustic classified primary secret"
    );

    // Extract decoy via --decoy-passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-wav",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_dec_path.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-lsb-pass",
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&out_dec_path).unwrap(),
        b"acoustic harmless decoy shopping list"
    );
}

#[test]
fn cli_empty_passphrase_rejected() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let out = dir.path().join("out.svault");
    fs::write(&src, b"data").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_encrypt_decoy_identical_passphrases_rejected() {
    let dir = tempdir().unwrap();
    let prim = dir.path().join("prim.txt");
    let dec = dir.path().join("dec.txt");
    let out = dir.path().join("out.svault");
    fs::write(&prim, b"primary classified").unwrap();
    fs::write(&dec, b"decoy harmless").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt-decoy",
            "-i",
            prim.to_str().unwrap(),
            "-d",
            dec.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "same-password-123",
            "--decoy-passphrase",
            "same-password-123",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_decoy_command_aliases_work() {
    let dir = tempdir().unwrap();
    let prim = dir.path().join("prim.txt");
    let dec = dir.path().join("dec.txt");
    let vault = dir.path().join("vault.svault");
    let out_p = dir.path().join("out_p.txt");
    let out_d = dir.path().join("out_d.txt");

    fs::write(&prim, b"secret under enc-decoy alias").unwrap();
    fs::write(&dec, b"decoy under enc-decoy alias").unwrap();

    // 1. enc-decoy alias
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "enc-decoy",
            "-i",
            prim.to_str().unwrap(),
            "-d",
            dec.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "alias-p-pass",
            "--decoy-passphrase",
            "alias-d-pass",
        ])
        .assert()
        .success();

    // 2. dec-decoy alias for primary secret
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "dec-decoy",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            out_p.to_str().unwrap(),
            "-p",
            "alias-p-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_p).unwrap(), b"secret under enc-decoy alias");

    // 3. dec-decoy alias for decoy payload
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "dec-decoy",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            out_d.to_str().unwrap(),
            "--decoy-passphrase",
            "alias-d-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_d).unwrap(), b"decoy under enc-decoy alias");
}

#[test]
fn cli_decrypt_empty_passphrases_rejected() {
    let dir = tempdir().unwrap();
    let prim = dir.path().join("prim.txt");
    let dec = dir.path().join("dec.txt");
    let vault = dir.path().join("vault.svault");
    let out = dir.path().join("out.txt");

    fs::write(&prim, b"primary").unwrap();
    fs::write(&dec, b"decoy").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt-decoy",
            "-i",
            prim.to_str().unwrap(),
            "-d",
            dec.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "p-pass",
            "--decoy-passphrase",
            "d-pass",
        ])
        .assert()
        .success();

    // Decrypt with empty --decoy-passphrase fails
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--decoy-passphrase",
            "",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_split_and_combine_with_file_prefix_roundtrip() {
    let dir = tempdir().unwrap();
    let secret_file = dir.path().join("master_seed.txt");
    let prefix = dir.path().join("shares").join("share");
    let recovered_file = dir.path().join("recovered_seed.txt");

    let secret_data = b"GHSFS-MASTER-RECOVERY-KEY-8f3a9e1b2c4d5e6f7a8b9c0d1e2f3a4b";
    fs::write(&secret_file, secret_data).unwrap();

    // Split 3-of-5 with output prefix
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "split",
            "-i",
            secret_file.to_str().unwrap(),
            "-m",
            "3",
            "-n",
            "5",
            "-o",
            prefix.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("split 58 bytes into 5 shares"));

    let s1 = format!("{}_1.share", prefix.display());
    let s2 = format!("{}_2.share", prefix.display());
    let s3 = format!("{}_3.share", prefix.display());
    let s4 = format!("{}_4.share", prefix.display());
    let s5 = format!("{}_5.share", prefix.display());

    assert!(std::path::Path::new(&s1).exists());
    assert!(std::path::Path::new(&s2).exists());
    assert!(std::path::Path::new(&s3).exists());
    assert!(std::path::Path::new(&s4).exists());
    assert!(std::path::Path::new(&s5).exists());

    // Combine any 3 shares (e.g. 2, 4, 5)
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "combine",
            &s2,
            &s4,
            &s5,
            "-o",
            recovered_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("combined 3 shares"));

    let recovered_data = fs::read(&recovered_file).unwrap();
    assert_eq!(recovered_data, secret_data);

    // Combine another combination (1, 3, 5)
    let recovered_file_2 = dir.path().join("recovered_seed_2.txt");
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "combine",
            &s1,
            &s3,
            &s5,
            "-o",
            recovered_file_2.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&recovered_file_2).unwrap(), secret_data);
}

#[test]
fn cli_split_string_secret_and_combine_stdout() {
    let secret = "correct horse battery staple 2026";

    // Split via -s flag into compact output
    let output = Command::cargo_bin("svault")
        .unwrap()
        .args(["split", "-s", secret, "-m", "2", "-n", "3", "--compact"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = output_str.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3);

    // Combine shares 0 and 2
    let combine_output = Command::cargo_bin("svault")
        .unwrap()
        .args(["combine", lines[0], lines[2]])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let recovered_str = String::from_utf8(combine_output).unwrap();
    assert_eq!(recovered_str.trim(), secret);
}

#[test]
fn cli_split_json_and_combine_json() {
    let secret = "alpha-bravo-charlie-delta";

    let split_out = Command::cargo_bin("svault")
        .unwrap()
        .args(["split", "-s", secret, "-m", "2", "-n", "3", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let shares: Vec<serde_json::Value> =
        serde_json::from_slice(&split_out).expect("valid JSON shares array");
    assert_eq!(shares.len(), 3);

    let s1 = serde_json::to_string(&shares[0]).unwrap();
    let s2 = serde_json::to_string(&shares[1]).unwrap();

    let combine_out = Command::cargo_bin("svault")
        .unwrap()
        .args(["combine", &s1, &s2, "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let res: serde_json::Value =
        serde_json::from_slice(&combine_out).expect("valid combine JSON output");
    assert_eq!(res["success"], true);
    assert_eq!(res["secret_utf8"], secret);
}

#[test]
fn cli_combine_insufficient_shares_fails() {
    let dir = tempdir().unwrap();
    let prefix = dir.path().join("share");
    let secret = "insufficient shares test secret";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "split",
            "-s",
            secret,
            "-m",
            "3",
            "-n",
            "5",
            "-o",
            prefix.to_str().unwrap(),
        ])
        .assert()
        .success();

    let s1 = format!("{}_1.share", prefix.display());
    let s2 = format!("{}_2.share", prefix.display());

    // Provide only 2 shares when 3 required
    Command::cargo_bin("svault")
        .unwrap()
        .args(["combine", &s1, &s2])
        .assert()
        .failure()
        .stderr(predicate::str::contains("insufficient shares"));
}

#[test]
fn cli_combine_tampered_share_fails() {
    let dir = tempdir().unwrap();
    let prefix = dir.path().join("share");
    let secret = "tamper detection test secret";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "split",
            "-s",
            secret,
            "-m",
            "2",
            "-n",
            "3",
            "-o",
            prefix.to_str().unwrap(),
        ])
        .assert()
        .success();

    let s1 = format!("{}_1.share", prefix.display());
    let s2 = format!("{}_2.share", prefix.display());

    // Tamper with share 1 text
    let original = fs::read_to_string(&s1).unwrap();
    let tampered = original.replace("Payload: ", "Payload: ABCD");
    fs::write(&s1, tampered).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["combine", &s1, &s2])
        .assert()
        .failure();
}

#[test]
fn cli_split_argument_validation() {
    // Threshold > Total
    Command::cargo_bin("svault")
        .unwrap()
        .args(["split", "-s", "test", "-m", "5", "-n", "3"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be less than threshold"));

    // Threshold < 2
    Command::cargo_bin("svault")
        .unwrap()
        .args(["split", "-s", "test", "-m", "1", "-n", "3"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("threshold M must be at least 2"));
}

#[test]
fn cli_split_svault_container_and_reconstruct_decrypt() {
    let dir = tempdir().unwrap();
    let raw_secret = dir.path().join("data.bin");
    let vault = dir.path().join("vault.svault");
    let prefix = dir.path().join("vshares").join("vshare");
    let recovered_vault = dir.path().join("recovered_vault.svault");
    let restored = dir.path().join("restored.bin");

    let payload = b"Deep Vault Plaintext Payload Protected by Argon2id + ChaCha20 + Shamir 2026!";
    fs::write(&raw_secret, payload).unwrap();

    // 1. Encrypt data into .svault container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            raw_secret.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "container-passphrase-42",
        ])
        .assert()
        .success();

    // 2. Split the entire .svault container into 3-of-4 Shamir shares
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "split",
            "-i",
            vault.to_str().unwrap(),
            "-m",
            "3",
            "-n",
            "4",
            "-o",
            prefix.to_str().unwrap(),
        ])
        .assert()
        .success();

    let s1 = format!("{}_1.share", prefix.display());
    let s2 = format!("{}_2.share", prefix.display());
    let s4 = format!("{}_4.share", prefix.display());

    // 3. Combine shares 1, 2, 4 to recover the .svault container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "combine",
            &s1,
            &s2,
            &s4,
            "-o",
            recovered_vault.to_str().unwrap(),
        ])
        .assert()
        .success();

    // 4. Decrypt the recovered .svault container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            recovered_vault.to_str().unwrap(),
            "-o",
            restored.to_str().unwrap(),
            "-p",
            "container-passphrase-42",
        ])
        .assert()
        .success();

    let restored_bytes = fs::read(&restored).unwrap();
    assert_eq!(restored_bytes, payload);
}
