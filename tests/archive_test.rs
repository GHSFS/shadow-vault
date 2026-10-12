// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_archive_cli_pack_and_unpack_roundtrip() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let vault = dir.path().join("vault.svault");

    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("file1.txt"), b"contents of file 1").unwrap();
    fs::write(
        src.join("sub").join("file2.bin"),
        b"binary payload \x01\x02\x03",
    )
    .unwrap();

    let pass = "archive_domain_test_pass!";

    // Pack
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            pass,
            "--list",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("packed 2 files"));

    // Verify-only
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault.to_str().unwrap(),
            "-p",
            pass,
            "--verify-only",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("verified 2 files"));

    // List
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault.to_str().unwrap(),
            "-p",
            pass,
            "--list",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("file1.txt"))
        .stdout(predicate::str::contains("sub/file2.bin"));

    // Unpack
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("unpacked 2 files"));

    assert_eq!(
        fs::read(dst.join("file1.txt")).unwrap(),
        b"contents of file 1"
    );
    assert_eq!(
        fs::read(dst.join("sub").join("file2.bin")).unwrap(),
        b"binary payload \x01\x02\x03"
    );
}

#[test]
fn test_archive_cli_overwrite_guard() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let vault = dir.path().join("vault.svault");

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("data.txt"), b"v1").unwrap();

    let pass = "overwrite_test_pass";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Extract once
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .success();

    // Extract again without overwrite fails
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
            "-p",
            pass,
        ])
        .assert()
        .failure();

    // Extract with overwrite succeeds
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
            "-p",
            pass,
            "--overwrite",
        ])
        .assert()
        .success();
}

#[test]
fn test_archive_cli_json_modes() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let vault = dir.path().join("vault.svault");

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("f1.txt"), b"123").unwrap();

    let pass = "json_mode_pass";

    // Pack with JSON
    let assert_pack = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "pack-dir",
            "-i",
            src.to_str().unwrap(),
            "-o",
            vault.to_str().unwrap(),
            "-p",
            pass,
            "--json",
        ])
        .assert()
        .success();

    let pack_out = String::from_utf8(assert_pack.get_output().stdout.clone()).unwrap();
    let pack_json: serde_json::Value = serde_json::from_str(&pack_out).unwrap();
    assert_eq!(pack_json["status"], "ok");
    assert_eq!(pack_json["files_packed"], 1);

    // Verify with JSON
    let assert_verify = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "unpack-dir",
            "-i",
            vault.to_str().unwrap(),
            "-p",
            pass,
            "--verify-only",
            "--json",
        ])
        .assert()
        .success();

    let verify_out = String::from_utf8(assert_verify.get_output().stdout.clone()).unwrap();
    let verify_json: serde_json::Value = serde_json::from_str(&verify_out).unwrap();
    assert_eq!(verify_json["valid"], true);
}
