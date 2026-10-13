// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_guard_companion_roundtrip_and_success_reset() {
    let tmp = tempdir().unwrap();
    let secret_path = tmp.path().join("secret.txt");
    let vault_path = tmp.path().join("guarded.svault");
    let out_path = tmp.path().join("decrypted.txt");
    let guard_file = tmp.path().join("guarded.svault.guard");

    fs::write(&secret_path, b"super confidential mission payload").unwrap();

    // 1. Encrypt with max-attempts = 3 and companion file
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "CorrectPass123!",
            "--max-attempts",
            "3",
            "--guard-companion",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("armed guard for"))
        .stdout(predicate::str::contains("max_attempts=3"));

    assert!(vault_path.exists());
    assert!(guard_file.exists());

    // 2. Inspect guard status in JSON format
    let status_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "status",
            "-t",
            vault_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();

    let json_str = String::from_utf8(status_cmd.get_output().stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["max_attempts"], 3);
    assert_eq!(parsed["failed_attempts"], 0);
    assert_eq!(parsed["remaining_attempts"], 3);
    assert_eq!(parsed["companion"], true);

    // 3. Failed attempt with wrong passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "WrongPassphrase1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Authentication failed (attempt 1/3)",
        ));

    // Guard status should now show 1 failed attempt, 2 remaining
    let status_cmd2 = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "status",
            "-t",
            vault_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();
    let parsed2: serde_json::Value =
        serde_json::from_str(&String::from_utf8(status_cmd2.get_output().stdout.clone()).unwrap())
            .unwrap();
    assert_eq!(parsed2["failed_attempts"], 1);
    assert_eq!(parsed2["remaining_attempts"], 2);

    // 4. Successful attempt with correct passphrase resets failed attempts to 0
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "CorrectPass123!",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("decrypted 34 bytes"));

    assert_eq!(
        fs::read(&out_path).unwrap(),
        b"super confidential mission payload"
    );

    // Inspect guard status again: failed_attempts should be reset to 0
    let status_cmd3 = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "status",
            "-t",
            vault_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();
    let parsed3: serde_json::Value =
        serde_json::from_str(&String::from_utf8(status_cmd3.get_output().stdout.clone()).unwrap())
            .unwrap();
    assert_eq!(parsed3["failed_attempts"], 0);
    assert_eq!(parsed3["remaining_attempts"], 3);
}

#[test]
fn test_guard_max_attempts_triggers_self_shred() {
    let tmp = tempdir().unwrap();
    let secret_path = tmp.path().join("classified.dat");
    let vault_path = tmp.path().join("secure.svault");
    let out_path = tmp.path().join("dump.dat");
    let guard_file = tmp.path().join("secure.svault.guard");

    fs::write(&secret_path, b"critical defense plans").unwrap();

    // Encrypt with threshold = 2
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "MasterSecret!",
            "--max-attempts",
            "2",
            "--guard-companion",
        ])
        .assert()
        .success();

    assert!(vault_path.exists());
    assert!(guard_file.exists());

    // Attempt 1: wrong password -> warning (attempt 1/2)
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "BadGuess1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Authentication failed (attempt 1/2)",
        ));

    assert!(vault_path.exists());

    // Attempt 2: threshold exceeded -> triggers permanent multi-pass self-shred!
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "BadGuess2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("CRITICAL SECURITY ALERT:"))
        .stderr(predicate::str::contains(
            "MAXIMUM PASSPHRASE ATTEMPTS EXCEEDED",
        ))
        .stderr(predicate::str::contains("permanently shredded"));

    // Target vault must be completely wiped and deleted from disk!
    assert!(
        !vault_path.exists(),
        "vault file must be shredded and unlinked"
    );
    assert!(
        !guard_file.exists(),
        "guard companion file must be cleaned up"
    );

    // Subsequent access attempt should fail immediately as file is gone
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "MasterSecret!",
        ])
        .assert()
        .failure();
}

#[test]
fn test_guard_stealth_ledger_mode_and_reset() {
    let tmp = tempdir().unwrap();
    let stealth_dir = tmp.path().join("stealth_guards");
    let secret_path = tmp.path().join("secret.txt");
    let vault_path = tmp.path().join("stealth.svault");
    let out_path = tmp.path().join("out.txt");

    fs::write(&secret_path, b"stealth ledger data").unwrap();

    // Encrypt in stealth mode using SVAULT_GUARD_DIR env var
    Command::cargo_bin("svault")
        .unwrap()
        .env("SVAULT_GUARD_DIR", stealth_dir.to_str().unwrap())
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "StealthPass123",
            "--max-attempts",
            "4",
        ])
        .assert()
        .success();

    // Companion file must NOT exist in the vault directory
    let companion = tmp.path().join("stealth.svault.guard");
    assert!(!companion.exists());

    // Stealth ledger directory must exist and contain the hashed guard file
    assert!(stealth_dir.exists());

    // List guards in stealth ledger
    let list_cmd = Command::cargo_bin("svault")
        .unwrap()
        .env("SVAULT_GUARD_DIR", stealth_dir.to_str().unwrap())
        .args(["guard", "list", "--json"])
        .assert()
        .success();

    let list_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8(list_cmd.get_output().stdout.clone()).unwrap())
            .unwrap();
    assert!(!list_json.as_array().unwrap().is_empty());

    // Attempt with wrong password
    Command::cargo_bin("svault")
        .unwrap()
        .env("SVAULT_GUARD_DIR", stealth_dir.to_str().unwrap())
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "WrongGuess",
        ])
        .assert()
        .failure();

    // Check status shows failed attempt = 1
    let status_cmd = Command::cargo_bin("svault")
        .unwrap()
        .env("SVAULT_GUARD_DIR", stealth_dir.to_str().unwrap())
        .args([
            "guard",
            "status",
            "-t",
            vault_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();
    let status_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8(status_cmd.get_output().stdout.clone()).unwrap())
            .unwrap();
    assert_eq!(status_json["failed_attempts"], 1);

    // Reset failed attempts via CLI
    Command::cargo_bin("svault")
        .unwrap()
        .env("SVAULT_GUARD_DIR", stealth_dir.to_str().unwrap())
        .args(["guard", "reset", "-t", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("reset failed attempts counter"));

    // Verify counter is back to 0
    let status_cmd2 = Command::cargo_bin("svault")
        .unwrap()
        .env("SVAULT_GUARD_DIR", stealth_dir.to_str().unwrap())
        .args([
            "guard",
            "status",
            "-t",
            vault_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();
    let status_json2: serde_json::Value =
        serde_json::from_str(&String::from_utf8(status_cmd2.get_output().stdout.clone()).unwrap())
            .unwrap();
    assert_eq!(status_json2["failed_attempts"], 0);
}

#[test]
fn test_guard_dead_man_switch_and_checkin() {
    let tmp = tempdir().unwrap();
    let secret_path = tmp.path().join("intel.txt");
    let vault_path = tmp.path().join("deadman.svault");
    let out_path = tmp.path().join("intel_out.txt");

    fs::write(&secret_path, b"eyes-only operation intel").unwrap();

    // Arm vault with dead-man switch of 10 minutes (600s)
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "AlphaBravo1!",
            "--max-attempts",
            "5",
            "--dead-man",
            "10m",
            "--guard-companion",
        ])
        .assert()
        .success();

    // Check status at +5m (not expired)
    let status_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "status",
            "-t",
            vault_path.to_str().unwrap(),
            "--at-time",
            "+5m",
            "--json",
        ])
        .assert()
        .success();
    let status_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8(status_cmd.get_output().stdout.clone()).unwrap())
            .unwrap();
    assert_eq!(status_json["dead_man_expired"], false);

    // Operator checks in and extends interval to 2 hours
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "checkin",
            "-t",
            vault_path.to_str().unwrap(),
            "--interval",
            "2h",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("checked-in dead-man switch"));

    // Verify deadline was pushed forward
    let status_cmd2 = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "status",
            "-t",
            vault_path.to_str().unwrap(),
            "--at-time",
            "+1h",
            "--json",
        ])
        .assert()
        .success();
    let status_json2: serde_json::Value =
        serde_json::from_str(&String::from_utf8(status_cmd2.get_output().stdout.clone()).unwrap())
            .unwrap();
    assert_eq!(status_json2["dead_man_expired"], false);

    // Access after expiration (+5h) triggers immediate dead-man self-shred!
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "AlphaBravo1!",
            "--at-time",
            "+5h",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("DeadManSwitchExpired"));

    // Target file must be permanently shredded and removed!
    assert!(!vault_path.exists());
}

#[test]
fn test_guard_tamper_detection_rejects_modified_ledger() {
    let tmp = tempdir().unwrap();
    let secret_path = tmp.path().join("secure.txt");
    let vault_path = tmp.path().join("tamper_test.svault");
    let guard_path = tmp.path().join("tamper_test.svault.guard");
    let out_path = tmp.path().join("tamper_out.txt");

    fs::write(&secret_path, b"unmodified payload").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "TamperProofPass!",
            "--max-attempts",
            "3",
            "--guard-companion",
        ])
        .assert()
        .success();

    assert!(guard_path.exists());

    // Read and maliciously alter the guard file (e.g. increase max_attempts without updating signature)
    let raw_guard = fs::read_to_string(&guard_path).unwrap();
    let mut parsed: serde_json::Value = serde_json::from_str(&raw_guard).unwrap();
    parsed["max_attempts"] = serde_json::json!(9999);
    fs::write(&guard_path, serde_json::to_string_pretty(&parsed).unwrap()).unwrap();

    // Attempting to access vault must fail due to cryptographic signature mismatch
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "TamperProofPass!",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("tampering detected"));
}

#[test]
fn test_guard_disarm_and_emergency_trigger() {
    let tmp = tempdir().unwrap();
    let secret_path = tmp.path().join("file.txt");
    let vault_path = tmp.path().join("disarm_test.svault");
    let guard_file = tmp.path().join("disarm_test.svault.guard");

    fs::write(&secret_path, b"sample file content").unwrap();

    // Arm file
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            secret_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "SomePass123",
            "--max-attempts",
            "3",
            "--guard-companion",
        ])
        .assert()
        .success();

    assert!(guard_file.exists());

    // Disarm guard
    Command::cargo_bin("svault")
        .unwrap()
        .args(["guard", "disarm", "-t", vault_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("disarmed and removed"));

    assert!(!guard_file.exists());
    assert!(vault_path.exists());

    // Emergency trigger without --force must fail
    Command::cargo_bin("svault")
        .unwrap()
        .args(["guard", "trigger", "-t", vault_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Specify --force to confirm"));

    assert!(vault_path.exists());

    // Emergency trigger with --force shreds the target
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "trigger",
            "-t",
            vault_path.to_str().unwrap(),
            "--force",
            "--passes",
            "2",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("emergency triggered: shredded"));

    assert!(!vault_path.exists());
}

#[test]
fn test_guard_stego_png_carrier_self_shred() {
    let tmp = tempdir().unwrap();
    let carrier_path = tmp.path().join("carrier.png");
    let secret_path = tmp.path().join("secret.txt");
    let stego_path = tmp.path().join("stego.png");
    let out_path = tmp.path().join("extracted.txt");

    // Generate a valid minimal 1x1 PNG image
    let minimal_png: [u8; 67] = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15,
        0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, // IDAT
        0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
        0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND
        0xAE, 0x42, 0x60, 0x82,
    ];
    fs::write(&carrier_path, minimal_png).unwrap();
    fs::write(&secret_path, b"hidden in png").unwrap();

    // Embed secret into PNG
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
            "CarrierPass123",
        ])
        .assert()
        .success();

    assert!(stego_path.exists());

    // Arm the stego PNG carrier with max-attempts = 2
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "arm",
            "-t",
            stego_path.to_str().unwrap(),
            "-m",
            "2",
            "--companion",
        ])
        .assert()
        .success();

    // Attempt 1 with wrong password
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "WrongGuess1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("attempt 1/2"));

    assert!(stego_path.exists());

    // Attempt 2 with wrong password: limit reached -> carrier image shredded!
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "WrongGuess2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "MAXIMUM PASSPHRASE ATTEMPTS EXCEEDED",
        ))
        .stderr(predicate::str::contains("permanently shredded"));

    // Carrier PNG must be shredded and unlinked
    assert!(!stego_path.exists());
}
