// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for Milestone M11: Time-Lock & Expiration Policy Header (`src/policy.rs`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn svault() -> Command {
    Command::cargo_bin("svault").expect("svault binary exists")
}

#[test]
fn test_policy_encrypt_and_decrypt_active_window() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("secret.txt");
    let vault = dir.path().join("vault.svault");
    let restored = dir.path().join("restored.txt");

    fs::write(&input, b"confidential payload within valid policy window").unwrap();

    // Encrypt with policy: not-before now, expires in 2 hours
    svault()
        .args([
            "encrypt",
            "-i",
            input.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "active-policy-passphrase",
            "--expires-in",
            "2h",
            "--policy-desc",
            "Active Window Test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypted"));

    // Inspect should show active policy
    svault()
        .args(["inspect", vault.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("policy_header:     present"))
        .stdout(predicate::str::contains("ACTIVE"))
        .stdout(predicate::str::contains("Active Window Test"));

    // Decrypt should succeed
    svault()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            restored.to_str().unwrap(),
            "-p",
            "active-policy-passphrase",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("decrypted"));

    let recovered = fs::read(&restored).unwrap();
    assert_eq!(
        recovered,
        b"confidential payload within valid policy window"
    );
}

#[test]
fn test_policy_time_lock_refuses_decryption_until_unlocked() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("future.txt");
    let vault = dir.path().join("timelocked.svault");
    let restored = dir.path().join("restored.txt");

    fs::write(&input, b"locked until future escrow time").unwrap();

    // Lock vault until 24 hours in the future
    svault()
        .args([
            "encrypt",
            "-i",
            input.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "future-escrow-key",
            "--not-before",
            "+24h",
            "--policy-desc",
            "Escrow 2026",
        ])
        .assert()
        .success();

    // Inspect should show TIME-LOCKED
    svault()
        .args(["inspect", vault.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("TIME-LOCKED"))
        .stdout(predicate::str::contains("Escrow 2026"));

    // Normal decryption must fail with time-lock error
    svault()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            restored.to_str().unwrap(),
            "-p",
            "future-escrow-key",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("time-locked"));

    // Simulated decryption at future timestamp (+25 hours = 90000s) should succeed
    let future_ts = 2000000000u64; // arbitrary future date
    let future_vault = dir.path().join("future_vault.svault");

    svault()
        .args([
            "encrypt",
            "-i",
            input.to_str().unwrap(),
            "-o",
            future_vault.to_str().unwrap(),
            "-p",
            "simulated-future-key",
            "--not-before",
            "1999999000",
            "--expires-at",
            "2000001000",
        ])
        .assert()
        .success();

    svault()
        .args([
            "decrypt",
            "-i",
            future_vault.to_str().unwrap(),
            "-o",
            restored.to_str().unwrap(),
            "-p",
            "simulated-future-key",
            "--at-time",
            &future_ts.to_string(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(&restored).unwrap(),
        b"locked until future escrow time"
    );
}

#[test]
fn test_policy_expired_vault_refuses_decryption() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("expired.txt");
    let vault = dir.path().join("expired.svault");
    let restored = dir.path().join("restored.txt");

    fs::write(&input, b"self-expiring data").unwrap();

    // Set expiration in the past (Unix timestamp 1000)
    svault()
        .args([
            "encrypt",
            "-i",
            input.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "expired-passphrase",
            "--expires-at",
            "1000",
            "--policy-desc",
            "Past Expiration",
        ])
        .assert()
        .success();

    // Inspect should report EXPIRED
    svault()
        .args(["inspect", vault.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("EXPIRED"));

    // Decryption must fail with expired error
    svault()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            restored.to_str().unwrap(),
            "-p",
            "expired-passphrase",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("expired"));
}

#[test]
fn test_policy_aead_tampering_causes_authentication_failure() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sensitive.txt");
    let vault = dir.path().join("tamper.svault");
    let restored = dir.path().join("restored.txt");

    fs::write(&input, b"highly sensitive trade secrets").unwrap();

    // Create a vault with expiration
    svault()
        .args([
            "encrypt",
            "-i",
            input.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "tamper-defense-key",
            "--expires-in",
            "7d",
            "--policy-desc",
            "Tamper Proof Policy",
        ])
        .assert()
        .success();

    let mut vault_bytes = fs::read(&vault).unwrap();

    // Modify a byte within the policy payload (bytes after HEADER_LEN + 4)
    // HEADER_LEN is 34. Byte 34..38 is policy_len. Byte 38.. is policy wire data.
    assert!(vault_bytes.len() > 60);
    vault_bytes[40] ^= 0x01; // flip 1 bit in policy header
    fs::write(&vault, &vault_bytes).unwrap();

    // Decryption must fail because Poly1305 AAD authentication rejects the tampered policy!
    svault()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            restored.to_str().unwrap(),
            "-p",
            "tamper-defense-key",
        ])
        .assert()
        .failure();
}

#[test]
fn test_policy_json_inspect_output() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("data.txt");
    let vault = dir.path().join("json_inspect.svault");

    fs::write(&input, b"json policy inspection test payload").unwrap();

    svault()
        .args([
            "encrypt",
            "-i",
            input.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "json-inspect-pass",
            "--not-before",
            "+1h",
            "--expires-in",
            "24h",
            "--policy-desc",
            "JSON-Policy-Audit",
        ])
        .assert()
        .success();

    let output = svault()
        .args(["inspect", vault.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).expect("valid json output");
    assert_eq!(parsed["container_version"], 1);
    assert_eq!(parsed["policy"]["description"], "JSON-Policy-Audit");
    assert!(parsed["policy"]["not_before"].is_number());
    assert!(parsed["policy"]["expires_at"].is_number());
    assert_eq!(parsed["policy"]["status"]["status"], "time_locked");
}

#[test]
fn test_policy_with_stego_png_carrier() {
    let dir = tempdir().unwrap();
    let carrier_png = dir.path().join("carrier.png");
    let secret = dir.path().join("secret.txt");
    let stego_out = dir.path().join("stego.png");
    let extracted = dir.path().join("extracted.txt");

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
    fs::write(&secret, b"steganographic policy test payload").unwrap();

    // Embed secret with 1-hour expiration into PNG carrier
    svault()
        .args([
            "embed",
            "-c",
            carrier_png.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego_out.to_str().unwrap(),
            "-p",
            "png-policy-pass",
            "--expires-in",
            "1h",
            "--policy-desc",
            "PNG Embedded Secret",
        ])
        .assert()
        .success();

    // Inspect stego PNG should report policy
    svault()
        .args(["inspect", stego_out.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("policy_header:     present"))
        .stdout(predicate::str::contains("PNG Embedded Secret"));

    // Extract should succeed
    svault()
        .args([
            "extract",
            "-c",
            stego_out.to_str().unwrap(),
            "-o",
            extracted.to_str().unwrap(),
            "-p",
            "png-policy-pass",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(&extracted).unwrap(),
        b"steganographic policy test payload"
    );
}

#[test]
fn test_policy_directory_packing_and_expiration() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("source_dir");
    let vault_pkg = dir.path().join("archive.svault");
    let out_dir = dir.path().join("out_dir");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("file1.txt"), b"directory packing with policy").unwrap();

    // Pack directory with expired timestamp
    svault()
        .args([
            "pack-dir",
            "-i",
            src_dir.to_str().unwrap(),
            "-o",
            vault_pkg.to_str().unwrap(),
            "-p",
            "archive-policy-pass",
            "--expires-at",
            "500",
            "--policy-desc",
            "Expired Directory Package",
        ])
        .assert()
        .success();

    // Unpack should fail due to policy expiration
    svault()
        .args([
            "unpack-dir",
            "-i",
            vault_pkg.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
            "-p",
            "archive-policy-pass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("expired"));
}
