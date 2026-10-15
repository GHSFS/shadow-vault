// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for Milestone M22: FIDO2 / Windows Hello Hardware Key Credential Binding.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn svault() -> Command {
    Command::cargo_bin("svault").expect("svault binary exists")
}

fn enroll_cred(dir: &Path, name: &str, dev_type: &str, pin: Option<&str>) -> PathBuf {
    let path = dir.join(format!("{name}.json"));
    let mut args = vec![
        "fido2",
        "enroll",
        name,
        "--type",
        dev_type,
        "--output",
        path.to_str().unwrap(),
    ];
    if let Some(p) = pin {
        args.push("--pin");
        args.push(p);
    }
    svault().args(args).assert().success();
    path
}

#[test]
fn test_fido2_status_plain() {
    svault()
        .args(["fido2", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "HARDWARE TOKEN & WEBAUTHN CAPABILITIES",
        ))
        .stdout(predicate::str::contains("Windows Hello Supported:"))
        .stdout(predicate::str::contains("WebAuthN DLL Available:"))
        .stdout(predicate::str::contains("FIDO2 USB Keys Supported:"))
        .stdout(predicate::str::contains("Active Default Engine:"));
}

#[test]
fn test_fido2_status_json() {
    let out = svault()
        .args(["fido2", "status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON from status");
    assert!(json.get("windows_hello_supported").is_some());
    assert!(json.get("webauthn_dll_available").is_some());
    assert!(json.get("usb_fido2_detected").is_some());
    assert!(json.get("active_device_type").is_some());
}

#[test]
fn test_fido2_enroll_file_and_test_assertion() {
    let dir = tempdir().unwrap();
    let cred_path = dir.path().join("yubikey_test.json");

    let enroll_out = svault()
        .args([
            "fido2",
            "enroll",
            "yubikey-corp",
            "--type",
            "usb",
            "--user",
            "alice",
            "--output",
            cred_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&enroll_out).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["name"], "yubikey-corp");
    assert_eq!(json["device_type"], "usb");
    assert_eq!(json["user_name"], "alice");
    assert!(cred_path.exists());

    svault()
        .args(["fido2", "test", cred_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("authenticator assertion verified"))
        .stdout(predicate::str::contains("yubikey-corp"))
        .stdout(predicate::str::contains("prf_fingerprint:"));

    let test_out = svault()
        .args(["fido2", "test", cred_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let test_json: serde_json::Value = serde_json::from_slice(&test_out).unwrap();
    assert_eq!(test_json["status"], "ok");
    assert_eq!(test_json["verified"], true);
    assert_eq!(
        test_json["derived_secret_fingerprint"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn test_fido2_enroll_with_pin() {
    let dir = tempdir().unwrap();
    let cred_path = enroll_cred(dir.path(), "hello-pin", "hello", Some("849201"));

    svault()
        .args([
            "fido2",
            "test",
            cred_path.to_str().unwrap(),
            "--pin",
            "849201",
            "--json",
        ])
        .assert()
        .success();
}

#[test]
fn test_fido2_encrypt_decrypt_basic_roundtrip() {
    let dir = tempdir().unwrap();
    let cred_path = enroll_cred(dir.path(), "fido-key-1", "usb", None);
    let plain_path = dir.path().join("secret.txt");
    let vault_path = dir.path().join("vault.svault");
    let out_path = dir.path().join("decrypted.txt");

    let payload = b"Top secret operational credentials bound to physical hardware key.";
    fs::write(&plain_path, payload).unwrap();

    svault()
        .args([
            "encrypt",
            "-i",
            plain_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
            "-p",
            "master-passphrase-2026",
        ])
        .assert()
        .success();

    let inspect_out = svault()
        .args(["inspect", vault_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let inspect_json: serde_json::Value = serde_json::from_slice(&inspect_out).unwrap();
    assert_eq!(inspect_json["fido2_bound"], true);
    assert_eq!(inspect_json["fido2"]["device_type"], "usb");

    svault()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
            "-p",
            "master-passphrase-2026",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&out_path).unwrap(), payload);
}

#[test]
fn test_fido2_encrypt_decrypt_keyfile_multi_factor() {
    let dir = tempdir().unwrap();
    let cred_path = enroll_cred(dir.path(), "fido-2fa", "usb", None);
    let keyfile_path = dir.path().join("hardware_token.key");
    let plain_path = dir.path().join("secret.txt");
    let vault_path = dir.path().join("vault_2fa.svault");
    let out_path = dir.path().join("recovered.txt");

    let payload = b"Multi-factor authentication: Keyfile + FIDO2 physical token.";
    fs::write(&plain_path, payload).unwrap();

    svault()
        .args([
            "keyfile",
            "generate",
            "-o",
            keyfile_path.to_str().unwrap(),
            "--bytes",
            "32",
        ])
        .assert()
        .success();

    svault()
        .args([
            "encrypt",
            "-i",
            plain_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "--keyfile",
            keyfile_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    svault()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "--keyfile",
            keyfile_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&out_path).unwrap(), payload);
}

#[test]
fn test_fido2_wrong_credential_rejected() {
    let dir = tempdir().unwrap();
    let cred1 = enroll_cred(dir.path(), "key1", "usb", None);
    let cred2 = enroll_cred(dir.path(), "key2", "usb", None);
    let (plain, vault, out) = (
        dir.path().join("s.txt"),
        dir.path().join("v.svault"),
        dir.path().join("o.txt"),
    );

    fs::write(&plain, b"Strict credential binding test").unwrap();

    svault()
        .args([
            "encrypt",
            "-i",
            plain.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "--fido2-cred",
            cred1.to_str().unwrap(),
            "-p",
            "pass1",
        ])
        .assert()
        .success();

    svault()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--fido2-cred",
            cred2.to_str().unwrap(),
            "-p",
            "pass1",
        ])
        .assert()
        .failure();
}

#[test]
fn test_fido2_wrong_passphrase_rejected() {
    let dir = tempdir().unwrap();
    let cred = enroll_cred(dir.path(), "key-auth", "usb", None);
    let (plain, vault, out) = (
        dir.path().join("s.txt"),
        dir.path().join("v.svault"),
        dir.path().join("o.txt"),
    );

    fs::write(&plain, b"Password verification test").unwrap();

    svault()
        .args([
            "encrypt",
            "-i",
            plain.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "--fido2-cred",
            cred.to_str().unwrap(),
            "-p",
            "correct_pass",
        ])
        .assert()
        .success();

    svault()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--fido2-cred",
            cred.to_str().unwrap(),
            "-p",
            "wrong_pass",
        ])
        .assert()
        .failure();
}

#[test]
fn test_fido2_tampered_container_rejected() {
    let dir = tempdir().unwrap();
    let cred = enroll_cred(dir.path(), "tamper-key", "usb", None);
    let (plain, vault, out) = (
        dir.path().join("s.txt"),
        dir.path().join("v.svault"),
        dir.path().join("o.txt"),
    );

    fs::write(&plain, b"Integrity tampering test").unwrap();

    svault()
        .args([
            "encrypt",
            "-i",
            plain.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "--fido2-cred",
            cred.to_str().unwrap(),
            "-p",
            "pass",
        ])
        .assert()
        .success();

    let mut raw = fs::read(&vault).unwrap();
    let idx = raw.len() - 1;
    raw[idx] ^= 0xFF;
    fs::write(&vault, &raw).unwrap();

    svault()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--fido2-cred",
            cred.to_str().unwrap(),
            "-p",
            "pass",
        ])
        .assert()
        .failure();
}

#[test]
fn test_fido2_rotate_lifecycle() {
    let dir = tempdir().unwrap();
    let cred = enroll_cred(dir.path(), "rot-key", "usb", None);
    let (plain, vault, out) = (
        dir.path().join("s.txt"),
        dir.path().join("v.svault"),
        dir.path().join("o.txt"),
    );

    let payload = b"Rotation lifecycle: standard -> fido2-bound -> standard.";
    fs::write(&plain, payload).unwrap();

    svault()
        .args([
            "encrypt",
            "-i",
            plain.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            "pass1",
        ])
        .assert()
        .success();

    svault()
        .args([
            "rotate",
            "-i",
            vault.to_str().unwrap(),
            "--in-place",
            "--old-passphrase",
            "pass1",
            "--new-passphrase",
            "pass2",
            "--fido2",
            "--fido2-cred",
            cred.to_str().unwrap(),
        ])
        .assert()
        .success();

    let inspect_out = svault()
        .args(["inspect", vault.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let inspect_json: serde_json::Value = serde_json::from_slice(&inspect_out).unwrap();
    assert_eq!(inspect_json["fido2_bound"], true);

    svault()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--fido2-cred",
            cred.to_str().unwrap(),
            "-p",
            "pass2",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out).unwrap(), payload);

    svault()
        .args([
            "rotate",
            "-i",
            vault.to_str().unwrap(),
            "--in-place",
            "--old-passphrase",
            "pass2",
            "--new-passphrase",
            "pass3",
            "--fido2-cred",
            cred.to_str().unwrap(),
            "--no-fido2",
        ])
        .assert()
        .success();

    let out2 = dir.path().join("o2.txt");
    svault()
        .args([
            "decrypt",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            out2.to_str().unwrap(),
            "-p",
            "pass3",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out2).unwrap(), payload);
}

#[test]
fn test_fido2_remove_nonexistent_reporting() {
    let dir = tempdir().unwrap();
    let reg_path = dir.path().join("custom_registry.json");

    let out = svault()
        .args([
            "fido2",
            "remove",
            "non_existent_key_9999",
            "--registry",
            reg_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["command"], "fido2 remove");
    assert_eq!(json["removed"], false);
}
