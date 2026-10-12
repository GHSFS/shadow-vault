// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn cli_version_and_help_work() {
    let mut cmd = Command::cargo_bin("svault").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
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
