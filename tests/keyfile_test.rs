// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for Milestone M12: Keyfile + Passphrase Two-Factor Key Derivation (`src/keyfile.rs`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn svault() -> Command {
    Command::cargo_bin("svault").expect("svault binary exists")
}

#[test]
fn test_keyfile_generate_and_inspect_cli() {
    let dir = tempdir().unwrap();
    let keyfile_path = dir.path().join("hardware_token.key");

    // 1. Generate 64-byte CSPRNG keyfile
    svault()
        .args([
            "keyfile",
            "generate",
            "-o",
            keyfile_path.to_str().unwrap(),
            "--bytes",
            "64",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("generated cryptographic keyfile"))
        .stdout(predicate::str::contains("64 bytes"))
        .stdout(predicate::str::contains("fingerprint: SHA256:"));

    assert!(keyfile_path.exists());
    let metadata = fs::metadata(&keyfile_path).unwrap();
    assert_eq!(metadata.len(), 64);

    // 2. Inspect keyfile in plain text format
    svault()
        .args(["keyfile", "inspect", keyfile_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Keyfile Inspection Report"))
        .stdout(predicate::str::contains("Size:               64 bytes"))
        .stdout(predicate::str::contains("2FA Recommended:    true"));

    // 3. Inspect keyfile in structured JSON format
    let inspect_json = svault()
        .args([
            "keyfile",
            "inspect",
            keyfile_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json_val: serde_json::Value =
        serde_json::from_slice(&inspect_json).expect("valid json output");
    assert_eq!(json_val["size_bytes"], 64);
    assert!(json_val["fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));
    assert_eq!(json_val["recommended_for_2fa"], true);

    // 4. Output standalone fingerprint
    svault()
        .args(["keyfile", "fingerprint", keyfile_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("SHA256:"));
}

#[test]
fn test_keyfile_2fa_encrypt_and_decrypt_roundtrip() {
    let dir = tempdir().unwrap();
    let secret_file = dir.path().join("confidential.txt");
    let keyfile_path = dir.path().join("usb_token.key");
    let vault_file = dir.path().join("sealed.svault");
    let restored_file = dir.path().join("restored.txt");

    let secret_payload = b"Top secret operational keys protected by 2FA keyfile";
    fs::write(&secret_file, secret_payload).unwrap();

    // Generate random 128-byte keyfile
    svault()
        .args([
            "keyfile",
            "generate",
            "-o",
            keyfile_path.to_str().unwrap(),
            "--bytes",
            "128",
        ])
        .assert()
        .success();

    // Encrypt with 2FA: Passphrase + Keyfile
    svault()
        .args([
            "encrypt",
            "-i",
            secret_file.to_str().unwrap(),
            "-o",
            vault_file.to_str().unwrap(),
            "-p",
            "master-passphrase-alpha",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypted"));

    // Decrypt with 2FA: Correct Passphrase + Correct Keyfile
    svault()
        .args([
            "decrypt",
            "-i",
            vault_file.to_str().unwrap(),
            "-o",
            restored_file.to_str().unwrap(),
            "-p",
            "master-passphrase-alpha",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("decrypted"));

    let restored = fs::read(&restored_file).unwrap();
    assert_eq!(restored, secret_payload);
}

#[test]
fn test_keyfile_only_mode_roundtrip() {
    let dir = tempdir().unwrap();
    let secret_file = dir.path().join("token.txt");
    let keyfile_path = dir.path().join("hardware.key");
    let vault_file = dir.path().join("hardware_sealed.svault");
    let restored_file = dir.path().join("restored_token.txt");

    let secret_payload = b"Encrypted using hardware keyfile alone without user password";
    fs::write(&secret_file, secret_payload).unwrap();

    svault()
        .args([
            "keyfile",
            "generate",
            "-o",
            keyfile_path.to_str().unwrap(),
            "--bytes",
            "64",
        ])
        .assert()
        .success();

    // Encrypt with keyfile only (no -p flag)
    svault()
        .args([
            "encrypt",
            "-i",
            secret_file.to_str().unwrap(),
            "-o",
            vault_file.to_str().unwrap(),
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypted"));

    // Decrypt with keyfile only (no -p flag)
    svault()
        .args([
            "decrypt",
            "-i",
            vault_file.to_str().unwrap(),
            "-o",
            restored_file.to_str().unwrap(),
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("decrypted"));

    let restored = fs::read(&restored_file).unwrap();
    assert_eq!(restored, secret_payload);
}

#[test]
fn test_keyfile_wrong_keyfile_or_passphrase_fails() {
    let dir = tempdir().unwrap();
    let secret_file = dir.path().join("data.txt");
    let key1 = dir.path().join("key1.key");
    let key2 = dir.path().join("key2.key");
    let vault_file = dir.path().join("vault.svault");
    let restored_file = dir.path().join("out.txt");

    fs::write(&secret_file, b"test secret content").unwrap();

    // Generate two distinct keyfiles
    svault()
        .args(["keyfile", "generate", "-o", key1.to_str().unwrap()])
        .assert()
        .success();
    svault()
        .args(["keyfile", "generate", "-o", key2.to_str().unwrap()])
        .assert()
        .success();

    // Encrypt with key1 + pass "correct-pass"
    svault()
        .args([
            "encrypt",
            "-i",
            secret_file.to_str().unwrap(),
            "-o",
            vault_file.to_str().unwrap(),
            "-p",
            "correct-pass",
            "-k",
            key1.to_str().unwrap(),
        ])
        .assert()
        .success();

    // 1. Wrong keyfile (key2 instead of key1) with correct passphrase -> FAILS
    svault()
        .args([
            "decrypt",
            "-i",
            vault_file.to_str().unwrap(),
            "-o",
            restored_file.to_str().unwrap(),
            "-p",
            "correct-pass",
            "-k",
            key2.to_str().unwrap(),
        ])
        .assert()
        .failure();

    // 2. Correct keyfile (key1) with wrong passphrase -> FAILS
    svault()
        .args([
            "decrypt",
            "-i",
            vault_file.to_str().unwrap(),
            "-o",
            restored_file.to_str().unwrap(),
            "-p",
            "wrong-pass",
            "-k",
            key1.to_str().unwrap(),
        ])
        .assert()
        .failure();

    // 3. Omitted keyfile (passphrase only) -> FAILS
    svault()
        .args([
            "decrypt",
            "-i",
            vault_file.to_str().unwrap(),
            "-o",
            restored_file.to_str().unwrap(),
            "-p",
            "correct-pass",
        ])
        .assert()
        .failure();
}

#[test]
fn test_keyfile_tampering_and_empty_file_checks() {
    let dir = tempdir().unwrap();
    let secret_file = dir.path().join("data.txt");
    let keyfile_path = dir.path().join("key.bin");
    let empty_key = dir.path().join("empty.bin");
    let vault_file = dir.path().join("vault.svault");
    let restored_file = dir.path().join("out.txt");

    fs::write(&secret_file, b"integrity test payload").unwrap();
    fs::write(&empty_key, b"").unwrap(); // 0 bytes

    // 1. Empty keyfile should be rejected immediately
    svault()
        .args([
            "encrypt",
            "-i",
            secret_file.to_str().unwrap(),
            "-o",
            vault_file.to_str().unwrap(),
            "-k",
            empty_key.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("keyfile is empty"));

    // 2. Generate valid keyfile
    svault()
        .args([
            "keyfile",
            "generate",
            "-o",
            keyfile_path.to_str().unwrap(),
            "--bytes",
            "64",
        ])
        .assert()
        .success();

    // Encrypt
    svault()
        .args([
            "encrypt",
            "-i",
            secret_file.to_str().unwrap(),
            "-o",
            vault_file.to_str().unwrap(),
            "-p",
            "secure-pass",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // 3. Mutate 1 byte in the keyfile -> decryption MUST fail
    let mut key_bytes = fs::read(&keyfile_path).unwrap();
    key_bytes[10] ^= 0x01; // flip 1 bit
    fs::write(&keyfile_path, &key_bytes).unwrap();

    svault()
        .args([
            "decrypt",
            "-i",
            vault_file.to_str().unwrap(),
            "-o",
            restored_file.to_str().unwrap(),
            "-p",
            "secure-pass",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn test_keyfile_stego_png_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_png = dir.path().join("carrier.png");
    let stego_png = dir.path().join("stego.png");
    let secret_file = dir.path().join("hidden.txt");
    let keyfile_path = dir.path().join("stego.key");
    let extracted_file = dir.path().join("extracted.txt");

    // Generate a minimal valid 1x1 PNG carrier
    let minimal_png: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk len=13
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
        0x08, 0x06, 0x00, 0x00, 0x00, // 8-bit RGBA
        0x1F, 0x15, 0xC4, 0x89, // IHDR CRC
        0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, // IDAT chunk len=10
        0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, // zlib compressed pixel
        0x0D, 0x0A, 0x2D, 0xB4, // IDAT CRC
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND chunk len=0
        0xAE, 0x42, 0x60, 0x82, // IEND CRC
    ];
    fs::write(&carrier_png, minimal_png).unwrap();

    let secret_data = b"Hidden PNG steganography payload with 2FA keyfile protection";
    fs::write(&secret_file, secret_data).unwrap();

    // Generate keyfile
    svault()
        .args([
            "keyfile",
            "generate",
            "-o",
            keyfile_path.to_str().unwrap(),
            "--bytes",
            "64",
        ])
        .assert()
        .success();

    // Embed into PNG with 2FA
    svault()
        .args([
            "embed",
            "-c",
            carrier_png.to_str().unwrap(),
            "-s",
            secret_file.to_str().unwrap(),
            "-o",
            stego_png.to_str().unwrap(),
            "-p",
            "png-stego-passphrase",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("embedded"));

    // Extract from PNG with 2FA
    svault()
        .args([
            "extract",
            "-c",
            stego_png.to_str().unwrap(),
            "-o",
            extracted_file.to_str().unwrap(),
            "-p",
            "png-stego-passphrase",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("extracted"));

    let extracted = fs::read(&extracted_file).unwrap();
    assert_eq!(extracted, secret_data);
}

#[test]
fn test_keyfile_directory_packing_roundtrip() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("source_dir");
    let keyfile_path = dir.path().join("archive.key");
    let archive_vault = dir.path().join("dir_archive.svault");
    let out_dir = dir.path().join("extracted_dir");

    fs::create_dir_all(src_dir.join("sub")).unwrap();
    fs::write(src_dir.join("file1.txt"), b"File 1 content in archive").unwrap();
    fs::write(
        src_dir.join("sub/file2.txt"),
        b"File 2 nested in sub directory",
    )
    .unwrap();

    // Generate keyfile
    svault()
        .args([
            "keyfile",
            "generate",
            "-o",
            keyfile_path.to_str().unwrap(),
            "--bytes",
            "64",
        ])
        .assert()
        .success();

    // Pack directory with 2FA
    svault()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            archive_vault.to_str().unwrap(),
            "-p",
            "pack-archive-passphrase",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("packed 2 files"));

    // Unpack directory with 2FA
    svault()
        .args([
            "unpack-dir",
            "-i",
            archive_vault.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
            "-p",
            "pack-archive-passphrase",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("unpacked 2 files"));

    assert_eq!(
        fs::read(out_dir.join("file1.txt")).unwrap(),
        b"File 1 content in archive"
    );
    assert_eq!(
        fs::read(out_dir.join("sub/file2.txt")).unwrap(),
        b"File 2 nested in sub directory"
    );
}
