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
        .stdout(predicate::str::contains("svault 0.12.0"));

    Command::cargo_bin("svault")
        .unwrap()
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("svault 0.12.0"));

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
        .stdout(predicate::str::contains("embed-bmp"))
        .stdout(predicate::str::contains("extract-bmp"))
        .stdout(predicate::str::contains("capacity"))
        .stdout(predicate::str::contains("split"))
        .stdout(predicate::str::contains("combine"))
        .stdout(predicate::str::contains("armor"))
        .stdout(predicate::str::contains("dearmor"))
        .stdout(predicate::str::contains("repair"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("audit"))
        .stdout(predicate::str::contains("totp"))
        .stdout(predicate::str::contains("clip"))
        .stdout(predicate::str::contains("shred"))
        .stdout(predicate::str::contains("pack-dir"))
        .stdout(predicate::str::contains("unpack-dir"));

    Command::cargo_bin("svault")
        .unwrap()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("ShadowVault"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["totp", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("totp"))
        .stdout(predicate::str::contains("add"))
        .stdout(predicate::str::contains("code"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("remove"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("import"))
        .stdout(predicate::str::contains("export"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("audit"))
        .stdout(predicate::str::contains("--passphrase"))
        .stdout(predicate::str::contains("--json"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", "-h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("audit"));

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

    Command::cargo_bin("svault")
        .unwrap()
        .args(["embed-bmp", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("embed-bmp"))
        .stdout(predicate::str::contains("--carrier"))
        .stdout(predicate::str::contains("--secret"))
        .stdout(predicate::str::contains("--output"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["embed-bmp", "-h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("embed-bmp"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["extract-bmp", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("extract-bmp"))
        .stdout(predicate::str::contains("--carrier"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--clip"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["extract-bmp", "-h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("extract-bmp"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("capacity"))
        .stdout(predicate::str::contains("--json"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", "-h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("capacity"));
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

#[test]
fn cli_audit_passphrase_direct_text_and_json() {
    // 1. Weak passphrase test
    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", "-p", "P@ssw0rd123"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Passphrase Strength & Entropy Audit",
        ))
        .stdout(predicate::str::contains("VERY WEAK"))
        .stdout(predicate::str::contains("Findings & Anomalies:"));

    // 2. Strong passphrase in JSON format
    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", "-p", "Kx9#mQ2$vL8!zW5&pT4@", "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["passphrase"]["score"], 4);
    assert_eq!(json["passphrase"]["strength"], "very_strong");
    assert!(
        json["passphrase"]["effective_entropy_bits"]
            .as_f64()
            .unwrap()
            > 80.0
    );
}

#[test]
fn cli_audit_container_roundtrip() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("secret.txt");
    let vault_path = dir.path().join("secret.svault");

    let payload = b"sensitive classified research notes";
    fs::write(&src_path, payload).unwrap();

    // Encrypt
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            src_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "super-safe-audit-pass-1234",
        ])
        .assert()
        .success();

    // Audit terminal text output
    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Carrier Steganalysis & Integrity Audit",
        ))
        .stdout(predicate::str::contains("ENCRYPTED CONTAINER"))
        .stdout(predicate::str::contains("Container Version:     v1"))
        .stdout(predicate::str::contains("Ciphertext Shannon entropy"));

    // Audit JSON output
    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", vault_path.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["carrier"]["verdict"], "encrypted_container");
    assert_eq!(json["carrier"]["details"]["container_version"], 1);
    assert_eq!(json["carrier"]["details"]["dpapi_bound"], false);
    assert!(json["carrier"]["shannon_entropy"].as_f64().unwrap() > 0.0);
}

#[test]
fn cli_audit_png_stego_carrier() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.png");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego.png");

    let raw_png = vec![
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
        0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR len 13
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15,
        0xc4, 0x89, // CRC
        0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, // IDAT len 10
        0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d,
        0xb4, // CRC
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, // IEND len 0
        0xae, 0x42, 0x60, 0x82, // CRC
    ];
    fs::write(&carrier_path, &raw_png).unwrap();
    fs::write(&secret_path, b"audit-png-payload").unwrap();

    // 1. Audit clean carrier before embedding
    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", carrier_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("CLEAN CARRIER"));

    // 2. Embed payload
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
            "png-audit-passphrase-2026",
        ])
        .assert()
        .success();

    // 3. Audit stego carrier
    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("STEGO CARRIER DETECTED"))
        .stdout(predicate::str::contains(
            "Stego Chunk ('svLt'):  present (active)",
        ))
        .stdout(predicate::str::contains("extract with 'svault extract'"));

    // 4. Audit stego carrier with JSON output
    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", stego_path.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["carrier"]["verdict"], "stego_carrier_detected");
    assert_eq!(json["carrier"]["details"]["stego_chunk_present"], true);
}

#[test]
fn cli_audit_wav_stego_carrier() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.wav");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego.wav");

    let num_samples = 2000;
    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    let riff_size = 36 + (num_samples * 2) as u32;
    wav.extend_from_slice(&riff_size.to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&44100u32.to_le_bytes());
    wav.extend_from_slice(&(44100u32 * 2).to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    let data_size = (num_samples * 2) as u32;
    wav.extend_from_slice(&data_size.to_le_bytes());
    for i in 0..num_samples {
        let sample = ((i as f64 * 0.1).sin() * 8000.0) as i16;
        wav.extend_from_slice(&sample.to_le_bytes());
    }

    fs::write(&carrier_path, &wav).unwrap();
    fs::write(&secret_path, b"audit-wav-payload").unwrap();

    // Embed in chunk mode
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
            "wav-audit-passphrase-2026",
            "--mode",
            "chunk",
        ])
        .assert()
        .success();

    // Audit stego WAV
    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("STEGO CARRIER DETECTED"))
        .stdout(predicate::str::contains(
            "extract with 'svault extract-wav'",
        ));
}

#[test]
fn cli_audit_decoy_container() {
    let dir = tempdir().unwrap();
    let primary_path = dir.path().join("primary.txt");
    let decoy_path = dir.path().join("decoy.txt");
    let vault_path = dir.path().join("decoy.svault");

    fs::write(&primary_path, b"true confidential seed").unwrap();
    fs::write(&decoy_path, b"grocery list").unwrap();

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
            "primary-passphrase-2026",
            "--decoy-passphrase",
            "decoy-passphrase-2026",
            "--padding",
            "64",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Plausible deniability dual-slot decoy container detected",
        ))
        .stdout(predicate::str::contains("Decoy Container:       true"));
}

#[test]
fn cli_audit_piped_stdin() {
    Command::cargo_bin("svault")
        .unwrap()
        .arg("audit")
        .write_stdin("MySuperSecurePassphraseWithSymbols!2026")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Passphrase Strength & Entropy Audit",
        ))
        .stdout(predicate::str::contains("Effective Entropy:"));
}

#[test]
fn cli_audit_combined_carrier_and_passphrase() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("secret.txt");
    let vault_path = dir.path().join("combined.svault");

    fs::write(&src_path, b"test-secret-data").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            src_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "pass-phrase-test-1",
        ])
        .assert()
        .success();

    // Audit both file and passphrase together
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "audit",
            vault_path.to_str().unwrap(),
            "-p",
            "audit-candidate-password-42!",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Passphrase Strength & Entropy Audit",
        ))
        .stdout(predicate::str::contains(
            "Carrier Steganalysis & Integrity Audit",
        ));
}

#[test]
fn cli_audit_utf8_korean_passphrase() {
    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", "-p", "안전한보안비밀번호2026!#", "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["passphrase"]["length_chars"], 15);
    assert!(
        json["passphrase"]["effective_entropy_bits"]
            .as_f64()
            .unwrap()
            > 40.0
    );
    assert!(json["passphrase"]["score"].as_u64().unwrap() >= 2);
}

#[test]
fn cli_audit_wav_lsb_exact_payload_size() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.wav");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego_lsb.wav");

    let num_samples = 3000;
    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    let riff_size = 36 + (num_samples * 2) as u32;
    wav.extend_from_slice(&riff_size.to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&44100u32.to_le_bytes());
    wav.extend_from_slice(&(44100u32 * 2).to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    let data_size = (num_samples * 2) as u32;
    wav.extend_from_slice(&data_size.to_le_bytes());
    for i in 0..num_samples {
        let sample = ((i as f64 * 0.1).sin() * 8000.0) as i16;
        wav.extend_from_slice(&sample.to_le_bytes());
    }

    let secret_bytes = b"audit-lsb-secret!"; // 17 bytes
    fs::write(&carrier_path, &wav).unwrap();
    fs::write(&secret_path, secret_bytes).unwrap();

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
            "lsb-exact-payload-pass",
            "--lsb",
        ])
        .assert()
        .success();

    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", stego_path.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["carrier"]["verdict"], "stego_carrier_detected");
    assert_eq!(json["carrier"]["details"]["stego_lsb_present"], true);
    // Verified: payload length is decoded as little-endian and matches exact container size
    let payload_bytes = json["carrier"]["details"]["payload_bytes"]
        .as_u64()
        .unwrap();
    assert!(
        payload_bytes > 0 && payload_bytes < 500,
        "payload_bytes must be small realistic container size, got {payload_bytes}"
    );
}

#[test]
fn cli_audit_wav_corrupted_crc_anomaly() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.wav");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego_corrupt.wav");

    let num_samples = 2000;
    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    let riff_size = 36 + (num_samples * 2) as u32;
    wav.extend_from_slice(&riff_size.to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&44100u32.to_le_bytes());
    wav.extend_from_slice(&(44100u32 * 2).to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    let data_size = (num_samples * 2) as u32;
    wav.extend_from_slice(&data_size.to_le_bytes());
    for i in 0..num_samples {
        let sample = ((i as f64 * 0.1).sin() * 8000.0) as i16;
        wav.extend_from_slice(&sample.to_le_bytes());
    }

    fs::write(&carrier_path, &wav).unwrap();
    fs::write(&secret_path, b"audit-corrupt-data").unwrap();

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
            "corrupt-pass",
            "--mode",
            "chunk",
        ])
        .assert()
        .success();

    // Tamper the last byte of the file (chunk CRC)
    let mut stego_bytes = fs::read(&stego_path).unwrap();
    let last = stego_bytes.len() - 1;
    stego_bytes[last] ^= 0xFF;
    fs::write(&stego_path, &stego_bytes).unwrap();

    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", stego_path.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["carrier"]["verdict"], "suspicious_anomaly");
}

#[test]
fn cli_audit_empty_file_and_truncated_container() {
    let dir = tempdir().unwrap();
    let empty_path = dir.path().join("empty.bin");
    let trunc_path = dir.path().join("trunc.svault");

    fs::write(&empty_path, b"").unwrap();

    let mut trunc_data = vec![0u8; 40];
    trunc_data[0..4].copy_from_slice(b"SVLT");
    trunc_data[4] = 1;
    fs::write(&trunc_path, &trunc_data).unwrap();

    let assert_empty = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", empty_path.to_str().unwrap(), "--json"])
        .assert()
        .success();
    let out_empty = String::from_utf8(assert_empty.get_output().stdout.clone()).unwrap();
    let json_empty: serde_json::Value = serde_json::from_str(&out_empty).unwrap();
    assert_eq!(json_empty["carrier"]["verdict"], "suspicious_anomaly");

    let assert_trunc = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", trunc_path.to_str().unwrap(), "--json"])
        .assert()
        .success();
    let out_trunc = String::from_utf8(assert_trunc.get_output().stdout.clone()).unwrap();
    let json_trunc: serde_json::Value = serde_json::from_str(&out_trunc).unwrap();
    assert_eq!(json_trunc["carrier"]["verdict"], "suspicious_anomaly");
}

#[test]
fn cli_audit_apng_carrier() {
    let dir = tempdir().unwrap();
    let apng_path = dir.path().join("carrier.png");

    fn make_png_chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
        chunk.extend_from_slice(chunk_type);
        chunk.extend_from_slice(data);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(chunk_type);
        hasher.update(data);
        chunk.extend_from_slice(&hasher.finalize().to_be_bytes());
        chunk
    }

    let mut apng = Vec::new();
    apng.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let ihdr_data = [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
    apng.extend_from_slice(&make_png_chunk(b"IHDR", &ihdr_data));
    let actl_data = [0, 0, 0, 2, 0, 0, 0, 0];
    apng.extend_from_slice(&make_png_chunk(b"acTL", &actl_data));
    let fctl_data = [0u8; 26];
    apng.extend_from_slice(&make_png_chunk(b"fcTL", &fctl_data));
    let idat_data = [0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01];
    apng.extend_from_slice(&make_png_chunk(b"IDAT", &idat_data));
    apng.extend_from_slice(&make_png_chunk(b"IEND", &[]));

    fs::write(&apng_path, &apng).unwrap();

    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", apng_path.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["carrier"]["verdict"], "clean_carrier");
    let findings = json["carrier"]["findings"].as_array().unwrap();
    assert!(findings
        .iter()
        .any(|f| f.as_str().unwrap().contains("APNG")));
}

#[test]
fn cli_audit_wav_non_standard_sample_rate() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("hires_192k.wav");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("hires_stego.wav");

    let num_samples = 2000;
    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    let riff_size = 36 + (num_samples * 2) as u32;
    wav.extend_from_slice(&riff_size.to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&192000u32.to_le_bytes()); // 192 kHz sample rate
    wav.extend_from_slice(&(192000u32 * 2).to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    let data_size = (num_samples * 2) as u32;
    wav.extend_from_slice(&data_size.to_le_bytes());
    for i in 0..num_samples {
        let sample = ((i as f64 * 0.1).sin() * 8000.0) as i16;
        wav.extend_from_slice(&sample.to_le_bytes());
    }

    fs::write(&carrier_path, &wav).unwrap();
    fs::write(&secret_path, b"audit-hires-payload").unwrap();

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
            "hires-pass-test",
            "--mode",
            "chunk",
        ])
        .assert()
        .success();

    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", stego_path.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["carrier"]["verdict"], "stego_carrier_detected");
    assert_eq!(json["carrier"]["details"]["stego_chunk_present"], true);
}

#[test]
fn cli_audit_passphrase_vertical_keyboard_walk() {
    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", "-p", "qazwsxedc99!", "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["passphrase"]["has_keyboard_walk"], true);
}

#[test]
fn cli_totp_add_and_generate_code_fixed_timestamp() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("totp.svault");
    let pass = "test_totp_pass_2026!";

    // 1. Add record with RFC Base32 secret for "12345678901234567890"
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "github",
            "--secret",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("added TOTP 2FA record 'github'"));

    // 2. Generate code at timestamp 59 (step = 1 -> RFC code 287082 for 6 digits)
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "code",
            "github",
            "--time",
            "59",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("287082"))
        .stdout(predicate::str::contains("1s remaining"))
        .stdout(predicate::str::contains("["));
}

#[test]
fn cli_totp_code_json_output() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("totp.svault");
    let pass = "test_totp_json_pass!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "aws",
            "--secret",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "--issuer",
            "Amazon",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    let assert_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "code",
            "aws",
            "--time",
            "59",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--json",
        ])
        .assert()
        .success();

    let output = String::from_utf8(assert_cmd.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["name"], "aws");
    assert_eq!(json["issuer"], "Amazon");
    assert_eq!(json["code"], "287082");
    assert_eq!(json["remaining_seconds"], 1);
    assert_eq!(json["period"], 30);
    assert_eq!(json["digits"], 6);
    assert_eq!(json["algorithm"], "SHA1");
}

#[test]
fn cli_totp_add_via_uri_and_list_plain_and_json() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("totp.svault");
    let pass = "test_totp_uri_pass!";

    // Add via URI
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "--uri",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"));

    // Plain list
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "list",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"))
        .stdout(predicate::str::contains("GitHub"));

    // JSON list
    let assert_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "list",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--json",
        ])
        .assert()
        .success();

    let output = String::from_utf8(assert_cmd.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(json.is_array());
    let list = json.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "alice");
    assert_eq!(list[0]["issuer"], "GitHub");
}

#[test]
fn cli_totp_verify_with_skew() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("totp.svault");
    let pass = "test_totp_verify_pass!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "test_user",
            "--secret",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Verify valid code at time 59 (code 287082)
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "verify",
            "test_user",
            "287082",
            "--time",
            "59",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));

    // Verify with JSON
    let assert_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "verify",
            "test_user",
            "287082",
            "--time",
            "59",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--json",
        ])
        .assert()
        .success();

    let output = String::from_utf8(assert_cmd.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["valid"], true);

    // Verify with time skew (window + 1): at time 65, step is 2, skew 1 checks step 1, 2, 3 -> code 287082 still valid!
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "verify",
            "test_user",
            "287082",
            "--time",
            "65",
            "--skew",
            "1",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));

    // Outside skew: at time 150 (step 5), step difference > 1 -> invalid!
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "verify",
            "test_user",
            "287082",
            "--time",
            "150",
            "--skew",
            "1",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .failure();
}

#[test]
fn cli_totp_remove_record() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("totp.svault");
    let pass = "test_totp_remove_pass!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "removable",
            "--secret",
            "JBSWY3DPEHPK3PXP",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Remove
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "remove",
            "removable",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed TOTP record 'removable'"));

    // Code generation should now fail
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "code",
            "removable",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .failure();
}

#[test]
fn cli_totp_invalid_passphrase_error_handling() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("totp.svault");
    let pass = "correct_totp_pass_99!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "account1",
            "--secret",
            "JBSWY3DPEHPK3PXP",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Access with wrong passphrase should fail
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "list",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            "wrong_password_here",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_totp_export_and_import() {
    let dir = tempdir().unwrap();
    let vault1 = dir.path().join("totp1.svault");
    let vault2 = dir.path().join("totp2.svault");
    let pass = "test_totp_roundtrip_pass!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "export_test",
            "--secret",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "--issuer",
            "ExportCo",
            "--vault",
            vault1.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Export URI
    let assert_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "export",
            "export_test",
            "--vault",
            vault1.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    let uri_str = String::from_utf8(assert_cmd.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    assert!(uri_str.starts_with("otpauth://totp/"));

    // Import into second vault
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "import",
            "--uri",
            &uri_str,
            "--vault",
            vault2.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("imported 1 record(s)"));

    // Verify code generated from second vault matches
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "code",
            "export_test",
            "--time",
            "59",
            "--vault",
            vault2.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("287082"));
}

#[test]
#[cfg(windows)]
fn cli_totp_dpapi_hardware_bound_roundtrip() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("dpapi_totp.svault");
    let pass = "test_dpapi_totp_pass!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "hardware_acc",
            "--secret",
            "JBSWY3DPEHPK3PXP",
            "--dpapi",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("dpapi=true"));

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "code",
            "hardware_acc",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();
}

#[test]
fn cli_audit_stdin_target_dash() {
    let clean_png = vec![
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // signature
        0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR len 13
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15,
        0xc4, 0x89, // CRC
        0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, // IDAT len 10
        0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d,
        0xb4, // CRC
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, // IEND len 0
        0xae, 0x42, 0x60, 0x82, // CRC
    ];

    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", "-"])
        .write_stdin(clean_png)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Carrier Steganalysis & Integrity Audit",
        ))
        .stdout(predicate::str::contains("PNG Image Carrier"))
        .stdout(predicate::str::contains("CLEAN CARRIER"));
}

#[test]
fn cli_audit_stdin_binary_auto_detect() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("piped_secret.txt");
    let vault_path = dir.path().join("piped_vault.svault");

    fs::write(&src_path, b"piped-auto-detect-secret").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            src_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "piped-pass-1234",
        ])
        .assert()
        .success();

    let vault_bytes = fs::read(&vault_path).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .arg("audit")
        .write_stdin(vault_bytes)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Carrier Steganalysis & Integrity Audit",
        ))
        .stdout(predicate::str::contains("ShadowVault Encrypted Container"))
        .stdout(predicate::str::contains("ENCRYPTED CONTAINER"));
}

#[test]
fn cli_audit_stdin_dash_with_passphrase() {
    let clean_png = vec![
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ];

    let assert_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", "-", "-p", "MySuperSecurePassphrase!2026", "--json"])
        .write_stdin(clean_png)
        .assert()
        .success();

    let output = String::from_utf8(assert_cmd.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["carrier"]["carrier_type"], "png_image");
    assert_eq!(json["passphrase"]["score"], 4);
}

#[test]
fn cli_audit_mixed_case_sequential_passphrase() {
    let assert_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", "-p", "AbCdEf999!", "--json"])
        .assert()
        .success();

    let output = String::from_utf8(assert_json.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["passphrase"]["has_sequential"], true);
}

static CLIPBOARD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn cli_clipboard_guard_integration_suite() {
    let _lock = CLIPBOARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Copy and Paste Roundtrip
    let secret = "test_clipboard_guard_secret_value_12345!";
    Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "copy", secret, "--ttl", "0", "--quiet"])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "paste"])
        .assert()
        .success()
        .stdout(predicate::str::contains(secret));

    // 2. Paste JSON and Status JSON
    let assert_paste = Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "paste", "--json"])
        .assert()
        .success();

    let output_paste = String::from_utf8(assert_paste.get_output().stdout.clone()).unwrap();
    let json_paste: serde_json::Value = serde_json::from_str(&output_paste).unwrap();
    assert_eq!(json_paste["has_text"], true);
    assert_eq!(json_paste["text"], secret);

    let assert_status = Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "status", "--json"])
        .assert()
        .success();

    let output_status = String::from_utf8(assert_status.get_output().stdout.clone()).unwrap();
    let json_status: serde_json::Value = serde_json::from_str(&output_status).unwrap();
    assert_eq!(json_status["has_text"], true);
    assert_eq!(json_status["bytes"], secret.len());
    assert_eq!(json_status["characters"], secret.chars().count());
    assert!(json_status["sha256"].is_string());

    // 3. Clear and verify empty status
    Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "clear"])
        .assert()
        .success()
        .stdout(predicate::str::contains("clipboard cleared"));

    let assert_empty = Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "status", "--json"])
        .assert()
        .success();

    let output_empty = String::from_utf8(assert_empty.get_output().stdout.clone()).unwrap();
    let json_empty: serde_json::Value = serde_json::from_str(&output_empty).unwrap();
    assert_eq!(json_empty["has_text"], false);

    // 4. Aliases work ('clipboard set', 'clipboard get', 'clipboard info', 'clipboard wipe')
    let alias_secret = "aliased_clipboard_token_99";
    Command::cargo_bin("svault")
        .unwrap()
        .args(["clipboard", "set", alias_secret, "--ttl", "0", "--quiet"])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["clipboard", "get"])
        .assert()
        .success()
        .stdout(predicate::str::contains(alias_secret));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["clipboard", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Windows Clipboard Status"));

    Command::cargo_bin("svault")
        .unwrap()
        .args(["clipboard", "wipe"])
        .assert()
        .success();

    // 5. TOTP Code with --clip flag
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("totp_clip.svault");
    let pass = "test_totp_clip_pass!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "ClipUser",
            "--secret",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Generate code at time 59 (RFC 6238 code = 287082) with --clip
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "code",
            "ClipUser",
            "--time",
            "59",
            "--vault",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--clip",
            "--clip-ttl",
            "0",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "paste"])
        .assert()
        .success()
        .stdout(predicate::str::contains("287082"));

    // 6. Decrypt with --clip flag
    let src_path = dir.path().join("secret.txt");
    let enc_path = dir.path().join("secret.svault");
    let out_path = dir.path().join("decrypted.txt");
    let dec_secret = "SuperSecretDecryptedKeyToClipboard2026!";
    let dec_pass = "my-secure-decrypt-pass!";

    fs::write(&src_path, dec_secret).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            src_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            dec_pass,
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            dec_pass,
            "--clip",
            "--clip-ttl",
            "0",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "paste"])
        .assert()
        .success()
        .stdout(predicate::str::contains(dec_secret));

    // 7. Extract-BMP with --clip flag
    let bmp_carrier_path = dir.path().join("carrier.bmp");
    let bmp_secret_path = dir.path().join("bmp_secret.txt");
    let bmp_stego_path = dir.path().join("bmp_stego.bmp");
    let bmp_out_path = dir.path().join("bmp_out.txt");
    let bmp_clip_secret = "BmpClipboardSecretKey2026!";
    let bmp_pass = "bmp-clip-pass-123";

    fs::write(&bmp_carrier_path, generate_24bit_bmp(64, 64)).unwrap();
    fs::write(&bmp_secret_path, bmp_clip_secret).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-bmp",
            "-c",
            bmp_carrier_path.to_str().unwrap(),
            "-s",
            bmp_secret_path.to_str().unwrap(),
            "-o",
            bmp_stego_path.to_str().unwrap(),
            "-p",
            bmp_pass,
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-bmp",
            "-c",
            bmp_stego_path.to_str().unwrap(),
            "-o",
            bmp_out_path.to_str().unwrap(),
            "-p",
            bmp_pass,
            "--clip",
            "--clip-ttl",
            "0",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "paste"])
        .assert()
        .success()
        .stdout(predicate::str::contains(bmp_clip_secret));

    // 8. Extract-BMP direct to clipboard without --output (zero disk write)
    let direct_secret = "direct-to-clipboard-token-bmp-2026!";
    let direct_secret_path = dir.path().join("bmp_direct_secret.txt");
    let direct_stego_path = dir.path().join("bmp_direct_stego.bmp");
    fs::write(&direct_secret_path, direct_secret).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-bmp",
            "-c",
            bmp_carrier_path.to_str().unwrap(),
            "-s",
            direct_secret_path.to_str().unwrap(),
            "-o",
            direct_stego_path.to_str().unwrap(),
            "-p",
            "direct-clip-pass-1234",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-bmp",
            "-c",
            direct_stego_path.to_str().unwrap(),
            "-p",
            "direct-clip-pass-1234",
            "--clip",
            "--clip-ttl",
            "0",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "paste"])
        .assert()
        .success()
        .stdout(predicate::str::contains(direct_secret));

    // 9. Extract-BMP binary payload to clipboard in Base64 without --output
    use base64::Engine;
    let bin_carrier_path = dir.path().join("carrier_bin.bmp");
    let bin_secret_path = dir.path().join("secret_bin.bin");
    let bin_stego_path = dir.path().join("stego_bin.bmp");

    fs::write(&bin_carrier_path, generate_24bit_bmp(64, 64)).unwrap();
    let binary_secret = vec![0x00, 0xFF, 0xFE, 0x80, 0x90, 0x12, 0x34, 0x56, 0xAA, 0xBB];
    fs::write(&bin_secret_path, &binary_secret).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-bmp",
            "-c",
            bin_carrier_path.to_str().unwrap(),
            "-s",
            bin_secret_path.to_str().unwrap(),
            "-o",
            bin_stego_path.to_str().unwrap(),
            "-p",
            "bin-clip-pass-9999",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-bmp",
            "-c",
            bin_stego_path.to_str().unwrap(),
            "-p",
            "bin-clip-pass-9999",
            "--clip",
            "--clip-ttl",
            "0",
        ])
        .assert()
        .success();

    let paste_out = Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "paste"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let paste_str = String::from_utf8(paste_out).unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(paste_str.trim())
        .expect("clipboard should hold valid base64 for binary secret");
    assert_eq!(decoded, binary_secret);

    // Final clean up
    Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "clear"])
        .assert()
        .success();
}

fn generate_24bit_bmp(width: u32, height: u32) -> Vec<u8> {
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

#[test]
fn cli_capacity_bmp_wav_png_and_json() {
    let dir = tempdir().unwrap();
    let bmp_path = dir.path().join("carrier.bmp");
    let wav_path = dir.path().join("carrier.wav");
    let png_path = dir.path().join("carrier.png");
    let invalid_path = dir.path().join("carrier.bin");

    fs::write(&bmp_path, generate_24bit_bmp(100, 100)).unwrap();
    fs::write(&wav_path, generate_pcm_wav(4000)).unwrap();
    let minimal_png: [u8; 67] = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    fs::write(&png_path, minimal_png).unwrap();
    fs::write(&invalid_path, b"not a carrier").unwrap();

    // 1. BMP capacity (text & JSON)
    Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", bmp_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("BMP 24-bit Image Carrier"))
        .stdout(predicate::str::contains("100 x 100"))
        .stdout(predicate::str::contains(
            "Max Usable Payload:    3738 bytes",
        ));

    let bmp_json_output = Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", bmp_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let bmp_val: serde_json::Value = serde_json::from_slice(&bmp_json_output).unwrap();
    assert_eq!(bmp_val["carrier_type"], "bmp");
    assert_eq!(bmp_val["width"], 100);
    assert_eq!(bmp_val["height"], 100);
    assert_eq!(bmp_val["total_pixels"], 10000);
    assert_eq!(bmp_val["max_payload_bytes"], 3738);

    // 2. WAV capacity (text & JSON)
    Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", wav_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("WAV Audio Carrier"))
        .stdout(predicate::str::contains("Mode: LSB Capacity:"))
        .stdout(predicate::str::contains("Mode: Chunk Capacity:"));

    let wav_json_output = Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", wav_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let wav_val: serde_json::Value = serde_json::from_slice(&wav_json_output).unwrap();
    assert_eq!(wav_val["carrier_type"], "wav");
    assert_eq!(wav_val["num_samples"], 4000);
    assert_eq!(wav_val["lsb_max_payload_bytes"], 488);
    assert_eq!(wav_val["chunk_mode_supported"], true);

    // 3. PNG capacity (text & JSON)
    Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", png_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("PNG Image Carrier"))
        .stdout(predicate::str::contains("Mode: Chunk Capacity:"));

    let png_json_output = Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", png_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let png_val: serde_json::Value = serde_json::from_slice(&png_json_output).unwrap();
    assert_eq!(png_val["carrier_type"], "png");
    assert_eq!(png_val["mode"], "chunk");

    // 4. Invalid carrier fails
    Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", invalid_path.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn cli_bmp_embed_inspect_and_extract_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.bmp");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego.bmp");
    let extracted_path = dir.path().join("extracted.txt");

    fs::write(&carrier_path, generate_24bit_bmp(64, 64)).unwrap();
    let secret = b"bmp stego secret - shadow vault 24-bit LSB roundtrip!";
    fs::write(&secret_path, secret).unwrap();

    // 1. Embed BMP
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-bmp",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "bmp-passphrase-1234",
            "--padding",
            "64",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("embedded"));

    // 2. Inspect stego BMP
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version:"))
        .stdout(predicate::str::contains("payload_bytes:"));

    // 3. Extract BMP
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-bmp",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            extracted_path.to_str().unwrap(),
            "-p",
            "bmp-passphrase-1234",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("extracted"));

    let extracted = fs::read(&extracted_path).unwrap();
    assert_eq!(extracted, secret);
}

#[test]
fn cli_bmp_embed_with_decoy_flags_and_dual_extract() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.bmp");
    let primary_path = dir.path().join("primary.txt");
    let decoy_path = dir.path().join("decoy.txt");
    let stego_path = dir.path().join("stego_decoy.bmp");
    let out_primary = dir.path().join("out_primary.txt");
    let out_decoy = dir.path().join("out_decoy.txt");

    fs::write(&carrier_path, generate_24bit_bmp(120, 80)).unwrap();
    let primary_data = b"TOP-SECRET primary payload concealed in BMP LSB";
    let decoy_data = b"Plausible decoy innocent document for coercion";
    fs::write(&primary_path, primary_data).unwrap();
    fs::write(&decoy_path, decoy_data).unwrap();

    // Embed decoy in BMP
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-bmp",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            primary_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "primary-super-secret-key",
            "--decoy",
            decoy_path.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-innocent-key",
        ])
        .assert()
        .success();

    // Inspect stego BMP should detect decoy container
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("decoy_container:   true"));

    // Extract with primary passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-bmp",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_primary.to_str().unwrap(),
            "-p",
            "primary-super-secret-key",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_primary).unwrap(), primary_data);

    // Extract with decoy passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-bmp",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_decoy.to_str().unwrap(),
            "-p",
            "decoy-innocent-key",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out_decoy).unwrap(), decoy_data);
}

#[test]
fn cli_audit_bmp_clean_and_stego_and_json() {
    let dir = tempdir().unwrap();
    let clean_path = dir.path().join("clean.bmp");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego.bmp");

    fs::write(&clean_path, generate_24bit_bmp(60, 60)).unwrap();
    fs::write(&secret_path, b"audit bmp test payload").unwrap();

    // 1. Audit clean BMP
    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", clean_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("BMP Image Carrier"))
        .stdout(predicate::str::contains("CLEAN CARRIER"));

    let clean_audit_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", clean_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let clean_json: serde_json::Value = serde_json::from_slice(&clean_audit_json).unwrap();
    assert_eq!(clean_json["carrier"]["carrier_type"], "bmp_image");
    assert_eq!(clean_json["carrier"]["verdict"], "clean_carrier");
    assert_eq!(clean_json["carrier"]["details"]["stego_lsb_present"], false);

    // 2. Embed and audit stego BMP
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-bmp",
            "-c",
            clean_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "audit-stego-pass-2026",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("BMP Image Carrier"))
        .stdout(predicate::str::contains("STEGO CARRIER DETECTED"))
        .stdout(predicate::str::contains(
            "Stego Pixel LSB:       present (active)",
        ));

    let stego_audit_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", stego_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stego_json: serde_json::Value = serde_json::from_slice(&stego_audit_json).unwrap();
    assert_eq!(stego_json["carrier"]["carrier_type"], "bmp_image");
    assert_eq!(stego_json["carrier"]["verdict"], "stego_carrier_detected");
    assert_eq!(stego_json["carrier"]["details"]["stego_lsb_present"], true);
}

#[test]
fn cli_bmp_error_handling() {
    let dir = tempdir().unwrap();
    let small_bmp = dir.path().join("small.bmp");
    let secret_path = dir.path().join("secret.txt");
    let out_bmp = dir.path().join("out.bmp");
    let out_txt = dir.path().join("out.txt");

    // 4x4 image = 16 pixels = 48 channel bytes = 48 bits < 96 bits overhead
    fs::write(&small_bmp, generate_24bit_bmp(4, 4)).unwrap();
    fs::write(&secret_path, b"data to fail").unwrap();

    // 1. Capacity insufficient fails
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-bmp",
            "-c",
            small_bmp.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            out_bmp.to_str().unwrap(),
            "-p",
            "fail-pass",
        ])
        .assert()
        .failure();

    // 2. Wrong passphrase on extract-bmp fails
    let carrier_bmp = dir.path().join("carrier.bmp");
    let stego_bmp = dir.path().join("stego.bmp");
    fs::write(&carrier_bmp, generate_24bit_bmp(60, 60)).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-bmp",
            "-c",
            carrier_bmp.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_bmp.to_str().unwrap(),
            "-p",
            "correct-passphrase",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-bmp",
            "-c",
            stego_bmp.to_str().unwrap(),
            "-o",
            out_txt.to_str().unwrap(),
            "-p",
            "wrong-passphrase",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_capacity_truncated_and_invalid_bmp() {
    let dir = tempdir().unwrap();
    let truncated_path = dir.path().join("truncated.bmp");
    let bpp32_path = dir.path().join("bpp32.bmp");

    fs::write(&truncated_path, b"BMshort").unwrap();

    let mut bpp32 = generate_24bit_bmp(16, 16);
    bpp32[28] = 32; // set to 32 bpp
    fs::write(&bpp32_path, bpp32).unwrap();

    // 1. Truncated BMP capacity fails with descriptive error
    Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", truncated_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("smaller than minimum BMP header"));

    // 2. 32 bpp BMP capacity fails with descriptive error
    Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", bpp32_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unsupported BMP bit depth: 32 bpp",
        ));
}

#[test]
fn cli_audit_truncated_bmp() {
    let dir = tempdir().unwrap();
    let truncated_path = dir.path().join("truncated.bmp");
    fs::write(&truncated_path, b"BMtruncated_carrier_data").unwrap();

    // 1. Text audit
    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", truncated_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("BMP Image Carrier"))
        .stdout(predicate::str::contains("SUSPICIOUS ANOMALY"))
        .stdout(predicate::str::contains("Truncated BMP carrier"));

    // 2. JSON audit
    let audit_json = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", truncated_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let val: serde_json::Value = serde_json::from_slice(&audit_json).unwrap();
    assert_eq!(val["carrier"]["carrier_type"], "bmp_image");
    assert_eq!(val["carrier"]["verdict"], "suspicious_anomaly");
}

#[test]
fn cli_bmp_extreme_aspect_ratio_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("extreme_1x500.bmp");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego.bmp");
    let out_path = dir.path().join("extracted.txt");

    fs::write(&carrier_path, generate_24bit_bmp(1, 500)).unwrap();
    let secret_data =
        b"extreme 1x500 aspect ratio BMP stego roundtrip with row padding preservation!";
    fs::write(&secret_path, secret_data).unwrap();

    // Embed
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-bmp",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "aspect-ratio-pass-2026",
            "--padding",
            "16",
        ])
        .assert()
        .success();

    // Inspect
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version:"));

    // Extract
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-bmp",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "aspect-ratio-pass-2026",
        ])
        .assert()
        .success();

    let extracted = fs::read(&out_path).unwrap();
    assert_eq!(extracted, secret_data);
}

#[test]
fn cli_extract_bmp_missing_both_output_and_clip_fails() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.bmp");
    fs::write(&carrier_path, generate_24bit_bmp(16, 16)).unwrap();

    // Omitting both --output and --clip must fail with clap usage error
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-bmp",
            "-c",
            carrier_path.to_str().unwrap(),
            "-p",
            "some-pass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--output <OUTPUT>"));
}

#[test]
fn cli_armor_and_dearmor_vault_roundtrip() {
    let dir = tempdir().unwrap();
    let secret_path = dir.path().join("secret.txt");
    let vault_path = dir.path().join("vault.svault");
    let asc_path = dir.path().join("vault.svault.asc");
    let recovered_vault_path = dir.path().join("recovered.svault");
    let decrypted_txt_path = dir.path().join("decrypted.txt");

    let secret_data = b"Enterprise cryptographic vault protected by Cauchy MDS Reed-Solomon armor!";
    fs::write(&secret_path, secret_data).unwrap();

    // 1. Encrypt into .svault
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "armor-vault-pass-2026",
        ])
        .assert()
        .success();

    // 2. Armor into .svault.asc with K=4, M=2
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-k",
            "4",
            "-m",
            "2",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("armored"))
        .stdout(predicate::str::contains("stripes: 4+2"));

    let asc_content = fs::read_to_string(&asc_path).unwrap();
    assert!(asc_content.contains("-----BEGIN SHADOW VAULT ARMORED FILE-----"));
    assert!(asc_content.contains("-----END SHADOW VAULT ARMORED FILE-----"));
    assert!(asc_content.contains("Data-Stripes: 4"));
    assert!(asc_content.contains("Parity-Stripes: 2"));

    // 3. Dearmor back into .svault
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "dearmor",
            "-i",
            asc_path.to_str().unwrap(),
            "-o",
            recovered_vault_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("dearmored"));

    let original_vault_bytes = fs::read(&vault_path).unwrap();
    let recovered_vault_bytes = fs::read(&recovered_vault_path).unwrap();
    assert_eq!(recovered_vault_bytes, original_vault_bytes);

    // 4. Decrypt recovered .svault and verify plaintext
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            recovered_vault_path.to_str().unwrap(),
            "-o",
            decrypted_txt_path.to_str().unwrap(),
            "-p",
            "armor-vault-pass-2026",
        ])
        .assert()
        .success();

    let decrypted = fs::read(&decrypted_txt_path).unwrap();
    assert_eq!(decrypted, secret_data);
}

#[test]
fn cli_inspect_armored_container() {
    let dir = tempdir().unwrap();
    let secret_path = dir.path().join("secret.bin");
    let vault_path = dir.path().join("vault.svault");
    let asc_path = dir.path().join("vault.svault.asc");

    fs::write(&secret_path, b"Inspection vector for ASCII armor!").unwrap();

    // Encrypt
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "inspect-pass-2026",
        ])
        .assert()
        .success();

    // Armor
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-k",
            "3",
            "-m",
            "2",
        ])
        .assert()
        .success();

    // Inspect armored container directly
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", asc_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("armored_container: true"))
        .stdout(predicate::str::contains(
            "armor_mode:        Cauchy-RS-GF256",
        ))
        .stdout(predicate::str::contains("data_stripes:      3"))
        .stdout(predicate::str::contains("parity_stripes:    2"))
        .stdout(predicate::str::contains("intact_stripes:    5/5"))
        .stdout(predicate::str::contains("container_version: 1"));
}

#[test]
fn cli_audit_armored_clean_and_json() {
    let dir = tempdir().unwrap();
    let secret_path = dir.path().join("plain.txt");
    let asc_path = dir.path().join("plain.txt.asc");

    fs::write(&secret_path, b"Auditing ASCII armor resilience and parity!").unwrap();

    // Armor directly
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-k",
            "4",
            "-m",
            "2",
        ])
        .assert()
        .success();

    // 1. Text audit
    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", asc_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("ASCII Armored Container"))
        .stdout(predicate::str::contains("All 6 stripes intact"));

    // 2. JSON audit
    let output = Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", asc_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let val: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(val["carrier"]["carrier_type"], "armored_ascii");
    assert_eq!(val["carrier"]["verdict"], "encrypted_container");
    assert_eq!(val["carrier"]["details"]["total_chunks_or_subchunks"], 6);
}

#[test]
fn cli_repair_and_dearmor_corrupted_stripe() {
    let dir = tempdir().unwrap();
    let secret_path = dir.path().join("secret.txt");
    let vault_path = dir.path().join("vault.svault");
    let asc_path = dir.path().join("vault.svault.asc");
    let repaired_asc_path = dir.path().join("repaired.svault.asc");
    let recovered_vault_path = dir.path().join("recovered.svault");
    let decrypted_txt_path = dir.path().join("decrypted.txt");

    let secret_data = b"Self-healing Reed-Solomon test vector via CLI repair subcommand!";
    fs::write(&secret_path, secret_data).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "self-heal-pass-2026",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-k",
            "4",
            "-m",
            "2",
        ])
        .assert()
        .success();

    // Corrupt Stripe 1 in the armored text
    let original_asc = fs::read_to_string(&asc_path).unwrap();
    let mut corrupted_asc = String::new();
    let mut in_stripe_1 = false;
    for line in original_asc.lines() {
        if line.contains("=== STRIPE 1 (DATA)") {
            in_stripe_1 = true;
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        } else if in_stripe_1 && line.starts_with("=== STRIPE") {
            in_stripe_1 = false;
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        } else if in_stripe_1 && !line.is_empty() {
            corrupted_asc.push_str("CORRUPTED_BASE64_LINE_XYZ\n");
        } else {
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        }
    }
    fs::write(&asc_path, &corrupted_asc).unwrap();

    // Audit must flag suspicious anomaly with stripe CRC mismatch
    Command::cargo_bin("svault")
        .unwrap()
        .args(["audit", asc_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("SUSPICIOUS ANOMALY"))
        .stdout(predicate::str::contains(
            "Stripe #1 (data) CRC-32 checksum mismatch",
        ));

    // Run repair subcommand with --json
    let repair_output = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repair",
            "-i",
            asc_path.to_str().unwrap(),
            "-o",
            repaired_asc_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let rep_val: serde_json::Value = serde_json::from_slice(&repair_output).unwrap();
    assert_eq!(rep_val["success"], true);
    assert_eq!(rep_val["corrupted_stripes"], 1);
    assert_eq!(rep_val["reconstructed_stripes"], 1);

    // Dearmor repaired container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "dearmor",
            "-i",
            repaired_asc_path.to_str().unwrap(),
            "-o",
            recovered_vault_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Decrypt and verify
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            recovered_vault_path.to_str().unwrap(),
            "-o",
            decrypted_txt_path.to_str().unwrap(),
            "-p",
            "self-heal-pass-2026",
        ])
        .assert()
        .success();

    let decrypted = fs::read(&decrypted_txt_path).unwrap();
    assert_eq!(decrypted, secret_data);
}

#[test]
fn cli_repair_binary_flag_reconstructs_directly() {
    let dir = tempdir().unwrap();
    let secret_path = dir.path().join("secret.bin");
    let asc_path = dir.path().join("direct.asc");
    let recovered_path = dir.path().join("direct_repaired.bin");

    let secret_data = b"Direct binary extraction via repair --binary flag.";
    fs::write(&secret_path, secret_data).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-k",
            "3",
            "-m",
            "2",
        ])
        .assert()
        .success();

    // Corrupt Stripe 0
    let original_asc = fs::read_to_string(&asc_path).unwrap();
    let mut corrupted_asc = String::new();
    let mut in_stripe_0 = false;
    for line in original_asc.lines() {
        if line.contains("=== STRIPE 0 (DATA)") {
            in_stripe_0 = true;
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        } else if in_stripe_0 && line.starts_with("=== STRIPE") {
            in_stripe_0 = false;
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        } else if in_stripe_0 && !line.is_empty() {
            corrupted_asc.push_str("BAD_DATA_0000\n");
        } else {
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        }
    }
    fs::write(&asc_path, &corrupted_asc).unwrap();

    // Repair with --binary
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repair",
            "-i",
            asc_path.to_str().unwrap(),
            "-o",
            recovered_path.to_str().unwrap(),
            "--binary",
        ])
        .assert()
        .success();

    let recovered = fs::read(&recovered_path).unwrap();
    assert_eq!(recovered, secret_data);
}

#[test]
fn cli_dearmor_transparent_auto_recovery() {
    let dir = tempdir().unwrap();
    let secret_path = dir.path().join("secret.txt");
    let asc_path = dir.path().join("auto_repair.asc");
    let recovered_path = dir.path().join("recovered.txt");

    let secret_data = b"Transparent error correction during dearmor command execution.";
    fs::write(&secret_path, secret_data).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-k",
            "4",
            "-m",
            "2",
        ])
        .assert()
        .success();

    // Corrupt Stripe 2
    let original_asc = fs::read_to_string(&asc_path).unwrap();
    let mut corrupted_asc = String::new();
    let mut in_stripe_2 = false;
    for line in original_asc.lines() {
        if line.contains("=== STRIPE 2 (DATA)") {
            in_stripe_2 = true;
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        } else if in_stripe_2 && line.starts_with("=== STRIPE") {
            in_stripe_2 = false;
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        } else if in_stripe_2 && !line.is_empty() {
            corrupted_asc.push_str("BAD_STRIPE_2_PAYLOAD\n");
        } else {
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        }
    }
    fs::write(&asc_path, &corrupted_asc).unwrap();

    // Dearmor directly from corrupted file without explicit repair
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "dearmor",
            "-i",
            asc_path.to_str().unwrap(),
            "-o",
            recovered_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let recovered = fs::read(&recovered_path).unwrap();
    assert_eq!(recovered, secret_data);
}

#[test]
fn cli_dearmor_excessive_corruption_fails() {
    let dir = tempdir().unwrap();
    let secret_path = dir.path().join("secret.txt");
    let asc_path = dir.path().join("excessive.asc");
    let out_path = dir.path().join("out.txt");

    fs::write(&secret_path, b"Excessive corruption test vector").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-k",
            "4",
            "-m",
            "2",
        ])
        .assert()
        .success();

    // Corrupt 3 stripes (stripes 0, 1, 2) when parity capacity M=2
    let original_asc = fs::read_to_string(&asc_path).unwrap();
    let mut corrupted_asc = String::new();
    let mut in_bad = false;
    for line in original_asc.lines() {
        if line.contains("=== STRIPE 0 ")
            || line.contains("=== STRIPE 1 ")
            || line.contains("=== STRIPE 2 ")
        {
            in_bad = true;
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        } else if in_bad && line.starts_with("=== STRIPE") {
            in_bad = false;
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        } else if in_bad && !line.is_empty() {
            corrupted_asc.push_str("CORRUPTED\n");
        } else {
            corrupted_asc.push_str(line);
            corrupted_asc.push('\n');
        }
    }
    fs::write(&asc_path, &corrupted_asc).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "dearmor",
            "-i",
            asc_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecoverable corruption"));
}

#[test]
fn cli_armor_and_dearmor_clipboard_guard() {
    let _lock = CLIPBOARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let secret_path = dir.path().join("clip_secret.txt");
    let asc_path = dir.path().join("clip_vault.asc");

    let secret_data = b"Auto-expiring clipboard test with Reed-Solomon armor!";
    fs::write(&secret_path, secret_data).unwrap();

    // 1. Armor with --clip and short TTL
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "--clip",
            "--clip-ttl",
            "2",
        ])
        .assert()
        .success();

    // 2. Dearmor with --clip and short TTL
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "dearmor",
            "-i",
            asc_path.to_str().unwrap(),
            "--clip",
            "--clip-ttl",
            "2",
        ])
        .assert()
        .success();
}

#[test]
fn cli_decrypt_directly_from_corrupted_armored_container() {
    let dir = tempdir().unwrap();
    let secret_path = dir.path().join("direct_secret.txt");
    let vault_path = dir.path().join("direct.svault");
    let asc_path = dir.path().join("direct.svault.asc");
    let decrypted_path = dir.path().join("direct_out.txt");

    let secret_data = b"Direct decrypt from corrupted .svault.asc with transparent RS repair";
    fs::write(&secret_path, secret_data).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "direct-asc-pass-2026",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-k",
            "4",
            "-m",
            "2",
        ])
        .assert()
        .success();

    // Corrupt stripe 0 in the armored container
    let asc_text = fs::read_to_string(&asc_path).unwrap();
    let corrupted_asc = asc_text.replace(
        "=== STRIPE 0 (DATA)",
        "=== STRIPE 0 (DATA) CRC32: 00000000 ===",
    );
    fs::write(&asc_path, &corrupted_asc).unwrap();

    // Directly pass corrupted .svault.asc into `svault decrypt`
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            asc_path.to_str().unwrap(),
            "-o",
            decrypted_path.to_str().unwrap(),
            "-p",
            "direct-asc-pass-2026",
        ])
        .assert()
        .success();

    let restored = fs::read(&decrypted_path).unwrap();
    assert_eq!(restored, secret_data);
}

#[test]
fn cli_pack_and_unpack_dir_basic_roundtrip() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("source_files");
    let vault_path = dir.path().join("archive.svault");
    let dst_dir = dir.path().join("extracted_files");

    fs::create_dir_all(src_dir.join("nested")).unwrap();
    fs::write(src_dir.join("root.txt"), b"root file contents 12345").unwrap();
    fs::write(
        src_dir.join("nested").join("deep.dat"),
        b"deeply nested binary payload \x00\xff\xfe",
    )
    .unwrap();
    fs::write(src_dir.join("empty.txt"), b"").unwrap();

    let pass = "archive-master-passphrase-2026!";

    // Pack directory
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--list",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("packed"));

    // Verify inspect recognizes container
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 1"));

    // Unpack directory
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("unpacked"));

    assert_eq!(
        fs::read(dst_dir.join("root.txt")).unwrap(),
        b"root file contents 12345"
    );
    assert_eq!(
        fs::read(dst_dir.join("nested").join("deep.dat")).unwrap(),
        b"deeply nested binary payload \x00\xff\xfe"
    );
    assert_eq!(fs::read(dst_dir.join("empty.txt")).unwrap(), b"");
}

#[test]
fn cli_unpack_dir_list_plain_and_json() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let vault_path = dir.path().join("archive.svault");

    fs::create_dir_all(src_dir.join("sub")).unwrap();
    fs::write(src_dir.join("a.txt"), b"apple").unwrap();
    fs::write(src_dir.join("sub").join("b.txt"), b"banana").unwrap();

    let pass = "list-test-pass!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Plain listing
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--list",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("a.txt"))
        .stdout(predicate::str::contains("sub/b.txt"))
        .stdout(predicate::str::contains("archive contains"));

    // JSON listing
    let assert_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--list",
            "--json",
        ])
        .assert()
        .success();

    let output = String::from_utf8(assert_cmd.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["file_count"], 2);
    assert!(json["entries"].as_array().unwrap().len() >= 2);
}

#[test]
fn cli_unpack_dir_verify_only_plain_and_json() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let vault_path = dir.path().join("archive.svault");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("hello.txt"), b"hello integrity check").unwrap();

    let pass = "verify-test-pass!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Plain verify-only
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--verify-only",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"))
        .stdout(predicate::str::contains("digests intact"));

    // JSON verify-only
    let assert_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--verify-only",
            "--json",
        ])
        .assert()
        .success();

    let output = String::from_utf8(assert_cmd.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["valid"], true);
    assert_eq!(json["files_verified"], 1);
}

#[test]
fn cli_unpack_dir_overwrite_protection() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let vault_path = dir.path().join("archive.svault");
    let dst_dir = dir.path().join("dst");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("file.txt"), b"packed version").unwrap();

    let pass = "overwrite-pass!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // First unpack succeeds
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Second unpack without --overwrite fails
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .failure();

    // Second unpack with --overwrite succeeds
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            pass,
            "--overwrite",
        ])
        .assert()
        .success();
}

#[test]
fn cli_pack_dir_with_dpapi_and_unpack() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let vault_path = dir.path().join("archive.svault");
    let dst_dir = dir.path().join("dst");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("dpapi_secret.txt"),
        b"dpapi hardware bound archive",
    )
    .unwrap();

    let pass = "dpapi-archive-pass-123!";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            pass,
            "--dpapi",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("dpapi=true"));

    // Inspect confirms DPAPI binding
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("dpapi_bound:       true"));

    // Unpack DPAPI container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(dst_dir.join("dpapi_secret.txt")).unwrap(),
        b"dpapi hardware bound archive"
    );
}

#[test]
fn cli_pack_and_unpack_dir_stego_png() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let carrier_path = dir.path().join("cover.png");
    let stego_path = dir.path().join("stego.png");
    let dst_dir = dir.path().join("dst");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("photo_note.txt"), b"hidden folder in PNG!").unwrap();

    let minimal_png: [u8; 67] = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    fs::write(&carrier_path, minimal_png).unwrap();

    let pass = "png-pack-pass!";

    // Pack directory into PNG stego carrier
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            pass,
            "--carrier",
            carrier_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Inspect stego PNG
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 1"));

    // Unpack directly from stego PNG
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            stego_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(dst_dir.join("photo_note.txt")).unwrap(),
        b"hidden folder in PNG!"
    );
}

#[test]
fn cli_pack_and_unpack_dir_stego_wav() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let carrier_path = dir.path().join("cover.wav");
    let stego_path = dir.path().join("stego.wav");
    let dst_dir = dir.path().join("dst");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("audio_note.txt"), b"hidden archive in WAV!").unwrap();

    fs::write(&carrier_path, generate_pcm_wav(4000)).unwrap();

    let pass = "wav-pack-pass!";

    // Pack directory into WAV carrier
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            pass,
            "--carrier",
            carrier_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Inspect stego WAV
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 1"));

    // Unpack directly from stego WAV
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            stego_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(dst_dir.join("audio_note.txt")).unwrap(),
        b"hidden archive in WAV!"
    );
}

#[test]
fn cli_pack_and_unpack_dir_stego_bmp() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let carrier_path = dir.path().join("cover.bmp");
    let stego_path = dir.path().join("stego.bmp");
    let dst_dir = dir.path().join("dst");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("bmp_note.txt"),
        b"hidden folder in BMP carrier!",
    )
    .unwrap();

    fs::write(&carrier_path, generate_24bit_bmp(128, 128)).unwrap();

    let pass = "bmp-pack-pass!";

    // Pack directory into BMP carrier
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            pass,
            "--carrier",
            carrier_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Inspect stego BMP
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_version: 1"));

    // Unpack directly from stego BMP
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            stego_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(dst_dir.join("bmp_note.txt")).unwrap(),
        b"hidden folder in BMP carrier!"
    );
}

#[test]
fn cli_pack_and_unpack_dir_armor_asc() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let asc_path = dir.path().join("archive.svault.asc");
    let dst_dir = dir.path().join("dst");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("armored_note.txt"),
        b"Reed-Solomon armored archive!",
    )
    .unwrap();

    let pass = "armor-pack-pass!";

    // Pack directory with --armor
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-p",
            pass,
            "--armor",
        ])
        .assert()
        .success();

    let asc_text = fs::read_to_string(&asc_path).unwrap();
    assert!(asc_text.contains("BEGIN SHADOW VAULT ARMORED FILE"));

    // Inspect armored container
    Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", asc_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("armored_container: true"));

    // Unpack directly from .svault.asc
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            asc_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(dst_dir.join("armored_note.txt")).unwrap(),
        b"Reed-Solomon armored archive!"
    );
}

#[test]
fn cli_unpack_dir_wrong_passphrase_fails() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let vault_path = dir.path().join("archive.svault");
    let dst_dir = dir.path().join("dst");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("secret.txt"), b"sensitive").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "correct-pass",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            dst_dir.to_str().unwrap(),
            "-p",
            "wrong-pass",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_pack_dir_json_output() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let vault_path = dir.path().join("archive.svault");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("file1.txt"), b"hello").unwrap();
    fs::write(src_dir.join("file2.txt"), b"world!").unwrap();

    let assert_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "json-pack-pass",
            "--json",
        ])
        .assert()
        .success();

    let output = String::from_utf8(assert_cmd.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["files_packed"], 2);
    assert_eq!(json["total_bytes"], 11);
    assert!(json["archive_size"].as_u64().unwrap() > 0);
}
