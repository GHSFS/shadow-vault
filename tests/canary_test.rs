// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn create_sample_vault(dir: &std::path::Path, name: &str, secret: &[u8]) -> std::path::PathBuf {
    let plain = dir.join(format!("{name}.txt"));
    let vault = dir.join(format!("{name}.svault"));
    fs::write(&plain, secret).unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            plain.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "test_passphrase_1234",
        ])
        .assert()
        .success();

    let _ = fs::remove_file(plain);
    vault
}

#[test]
fn test_canary_init_and_verify_clean_roundtrip() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    create_sample_vault(root, "vault1", b"Top secret data 1");
    create_sample_vault(root, "vault2", b"Top secret data 2");

    // Initialize canary
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "init", "-d", root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("initialized canary manifest"))
        .stdout(predicate::str::contains("vault1.svault"))
        .stdout(predicate::str::contains("vault2.svault"));

    assert!(root.join(".svault-canary.json").exists());

    // Verify canary
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "verify", "-d", root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("ALL CANARIES INTACT")
                .or(predicate::str::contains("All 2 canary files intact")),
        );
}

#[test]
fn test_canary_detects_modified_container() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let vault1 = create_sample_vault(root, "vault1", b"Secret data Alpha");
    create_sample_vault(root, "vault2", b"Secret data Beta");

    // Init manifest
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "init", "-d", root.to_str().unwrap()])
        .assert()
        .success();

    // Tamper with vault1 by appending a corrupt byte
    let mut bytes = fs::read(&vault1).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    fs::write(&vault1, bytes).unwrap();

    // Verify should fail and detect modification
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "verify", "-d", root.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("MODIFIED"))
        .stdout(predicate::str::contains("vault1.svault"));
}

#[test]
fn test_canary_detects_missing_container() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let vault1 = create_sample_vault(root, "vault1", b"Sensitive documents");
    create_sample_vault(root, "vault2", b"Financial records");

    // Init manifest
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "init", "-d", root.to_str().unwrap()])
        .assert()
        .success();

    // Delete vault1
    fs::remove_file(vault1).unwrap();

    // Verify should fail and report MISSING
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "verify", "-d", root.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("MISSING"))
        .stdout(predicate::str::contains("vault1.svault"));
}

#[test]
fn test_canary_detects_untracked_files_strict() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    create_sample_vault(root, "vault1", b"Primary vault");

    // Init manifest
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "init", "-d", root.to_str().unwrap()])
        .assert()
        .success();

    // Inject untracked file
    let rogue = root.join("rogue.svault");
    fs::write(&rogue, b"Untracked hostile injected container").unwrap();

    // Normal verify warns but passes if tracked files intact
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "verify", "-d", root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("UNTRACKED"));

    // Strict verify must fail when untracked files are detected
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "verify", "-d", root.to_str().unwrap(), "--strict"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("UNTRACKED"));
}

#[test]
fn test_canary_hmac_passphrase_signing_and_verification() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    create_sample_vault(root, "secure_vault", b"Air-gapped sensitive assets");

    // Init with passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "canary",
            "init",
            "-d",
            root.to_str().unwrap(),
            "-p",
            "canary_passphrase_auth_99",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("auth: hmac-sha256"));

    // Verify with correct passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "canary",
            "verify",
            "-d",
            root.to_str().unwrap(),
            "-p",
            "canary_passphrase_auth_99",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature:   VALID"))
        .stdout(predicate::str::contains("Zero tampering detected"));
}

#[test]
fn test_canary_wrong_passphrase_rejection() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    create_sample_vault(root, "guarded_vault", b"Hardware bound tokens");

    // Init with passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "canary",
            "init",
            "-d",
            root.to_str().unwrap(),
            "-p",
            "correct_passphrase_88",
        ])
        .assert()
        .success();

    // Verify with wrong passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "canary",
            "verify",
            "-d",
            root.to_str().unwrap(),
            "-p",
            "incorrect_passphrase_fake",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("INVALID / TAMPERED"));
}

#[test]
fn test_canary_tampered_manifest_rejection() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    create_sample_vault(root, "vault1", b"Data integrity test");

    // Init manifest
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "init", "-d", root.to_str().unwrap()])
        .assert()
        .success();

    // Tamper with manifest file directly (e.g. change file size in JSON)
    let manifest_path = root.join(".svault-canary.json");
    let content = fs::read_to_string(&manifest_path).unwrap();
    let tampered = content.replace("\"size_bytes\":", "\"size_bytes\": 99999 + ");
    fs::write(&manifest_path, tampered).unwrap();

    // Verify should detect manifest corruption / invalid JSON
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "verify", "-d", root.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn test_canary_carrier_format_detection() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    create_sample_vault(root, "core_vault", b"Core credentials");

    let asc_path = root.join("backup.svault.asc");
    fs::write(
        &asc_path,
        b"-----BEGIN SHADOW VAULT-----\nDummyArmoredContent\n-----END SHADOW VAULT-----\n",
    )
    .unwrap();

    // Init manifest
    Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "init", "-d", root.to_str().unwrap(), "--all"])
        .assert()
        .success();

    let manifest_path = root.join(".svault-canary.json");
    let manifest_str = fs::read_to_string(&manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_str).unwrap();

    let files = manifest["files"].as_array().unwrap();
    let vault_entry = files
        .iter()
        .find(|e| e["path"] == "core_vault.svault")
        .unwrap();
    assert_eq!(vault_entry["carrier"], "svault");

    let asc_entry = files
        .iter()
        .find(|e| e["path"] == "backup.svault.asc")
        .unwrap();
    assert_eq!(asc_entry["carrier"], "armor_asc");
}

#[test]
fn test_canary_cli_json_output_mode() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    create_sample_vault(root, "json_vault", b"JSON test secret data");

    // Init with --json
    let assert_init = Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "init", "-d", root.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let init_stdout = String::from_utf8(assert_init.get_output().stdout.clone()).unwrap();
    let init_json: serde_json::Value = serde_json::from_str(&init_stdout).unwrap();
    assert_eq!(init_json["status"], "ok");
    assert_eq!(init_json["total_tracked"], 1);
    assert!(!init_json["canary_id"].as_str().unwrap().is_empty());

    // Verify with --json
    let assert_ver = Command::cargo_bin("svault")
        .unwrap()
        .args(["canary", "verify", "-d", root.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let ver_stdout = String::from_utf8(assert_ver.get_output().stdout.clone()).unwrap();
    let ver_json: serde_json::Value = serde_json::from_str(&ver_stdout).unwrap();
    assert_eq!(ver_json["status"], "ok");
    assert_eq!(ver_json["is_clean"], true);
    assert_eq!(ver_json["signature_valid"], true);
    assert_eq!(ver_json["intact_count"], 1);
    assert_eq!(ver_json["modified_count"], 0);
    assert_eq!(ver_json["missing_count"], 0);
}

#[test]
fn test_canary_2fa_keyfile_signing() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    create_sample_vault(root, "token_vault", b"Hardware protected assets");

    let keyfile_path = dir.path().join("hardware.key");
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "keyfile",
            "generate",
            "-o",
            keyfile_path.to_str().unwrap(),
            "-b",
            "64",
        ])
        .assert()
        .success();

    // Init canary with keyfile + passphrase 2FA
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "canary",
            "init",
            "-d",
            root.to_str().unwrap(),
            "-k",
            keyfile_path.to_str().unwrap(),
            "-p",
            "two_factor_canary_passphrase",
        ])
        .assert()
        .success();

    // Verify canary with same 2FA
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "canary",
            "verify",
            "-d",
            root.to_str().unwrap(),
            "-k",
            keyfile_path.to_str().unwrap(),
            "-p",
            "two_factor_canary_passphrase",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature:   VALID"));
}
