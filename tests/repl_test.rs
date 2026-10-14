// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration test suite for Milestone M20 — Interactive Terminal Vault Shell (`svault repl`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_repl_exec_set_get_and_save() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("test_store.svault");

    // 1. Create and populate vault via --exec batch
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "--vault",
            vault_path.to_str().unwrap(),
            "--passphrase",
            "SessionMasterPass99!",
            "--exec",
            "set api_key secret_token_123 --tag prod; set db_pass hunter2; save",
        ])
        .assert()
        .success();

    assert!(vault_path.exists());

    // 2. Query secret with --raw
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "--vault",
            vault_path.to_str().unwrap(),
            "--passphrase",
            "SessionMasterPass99!",
            "--exec",
            "get api_key --raw",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret_token_123"));

    // 3. Query list in JSON mode
    let assert_list = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "--vault",
            vault_path.to_str().unwrap(),
            "--passphrase",
            "SessionMasterPass99!",
            "--json",
            "--exec",
            "list",
        ])
        .assert()
        .success();

    let output_str = String::from_utf8(assert_list.get_output().stdout.clone()).unwrap();
    assert!(output_str.contains("api_key"));
    assert!(output_str.contains("db_pass"));
    assert!(output_str.contains("prod"));
}

#[test]
fn test_repl_save_and_reopen_integrity() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("integrity.svault");

    // Initialize vault with 2 items
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "CorrectPass123!",
            "-e",
            "set service_a key_a; set service_b key_b; save",
        ])
        .assert()
        .success();

    // Reopen, delete service_a, save
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "CorrectPass123!",
            "-e",
            "del service_a; save",
        ])
        .assert()
        .success();

    // Reopen, verify service_a is gone and service_b exists
    let assert_get_b = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "CorrectPass123!",
            "-e",
            "get service_b --raw",
        ])
        .assert()
        .success();
    let out_b = String::from_utf8(assert_get_b.get_output().stdout.clone()).unwrap();
    assert!(out_b.contains("key_b"));

    // Verifying service_a causes error
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "CorrectPass123!",
            "-e",
            "get service_a",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found in vault"));
}

#[test]
fn test_repl_readonly_mode() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("readonly.svault");

    // Setup initial data
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "ReadOnlyPass!",
            "-e",
            "set safe_key safe_val; save",
        ])
        .assert()
        .success();

    // Opening with --readonly and attempting mutation must fail
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "ReadOnlyPass!",
            "--readonly",
            "-e",
            "set forbidden_key forbidden_val",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("read-only"));

    // Deleting in read-only mode must fail
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "ReadOnlyPass!",
            "--readonly",
            "-e",
            "del safe_key",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("read-only"));

    // Querying in read-only mode works
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "ReadOnlyPass!",
            "--readonly",
            "-e",
            "get safe_key --raw",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("safe_val"));
}

#[test]
fn test_repl_piped_stdin() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("piped.svault");

    let script = "set secret1 value1\nset secret2 value2\nsave\nexit\n";

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "PipedSessionPass!",
        ])
        .write_stdin(script)
        .assert()
        .success();

    assert!(vault_path.exists());

    // Verify written secrets
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "PipedSessionPass!",
            "-e",
            "get secret1 --raw",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("value1"));
}

#[test]
fn test_repl_status_and_json_mode() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("status.svault");

    let assert_status = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "StatusPass!",
            "--json",
            "-e",
            "set k1 v1; status",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert_status.get_output().stdout.clone()).unwrap();
    assert!(out.contains("\"command\": \"status\""));
    assert!(out.contains("\"entries\": 1"));
    assert!(out.contains("\"dirty\": true"));
}

#[test]
fn test_repl_export_and_import() {
    let dir = tempdir().unwrap();
    let vault1 = dir.path().join("vault1.svault");
    let vault2 = dir.path().join("vault2.svault");
    let export_file = dir.path().join("exported.json");

    // Populate vault1
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault1.to_str().unwrap(),
            "-p",
            "SyncPass1!",
            "-e",
            &format!(
                "set exp1 val1 --tag test; set exp2 val2; export {}",
                export_file.display()
            ),
        ])
        .assert()
        .success();

    assert!(export_file.exists());
    let export_content = fs::read_to_string(&export_file).unwrap();
    assert!(export_content.contains("exp1"));
    assert!(export_content.contains("val1"));

    // Import into fresh vault2
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault2.to_str().unwrap(),
            "-p",
            "SyncPass2!",
            "-e",
            &format!("import {}; save", export_file.display()),
        ])
        .assert()
        .success();

    // Verify imported contents in vault2
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault2.to_str().unwrap(),
            "-p",
            "SyncPass2!",
            "-e",
            "get exp1 --raw",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("val1"));
}

#[test]
fn test_repl_wrong_passphrase_fails() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("locked.svault");

    // Create vault
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "CorrectPassphrase1!",
            "-e",
            "set my_token secret123; save",
        ])
        .assert()
        .success();

    // Attempting to open with wrong passphrase must fail
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "WrongPassphrase!",
            "-e",
            "list",
        ])
        .assert()
        .failure();
}

#[test]
fn test_repl_keyfile_2fa() {
    let dir = tempdir().unwrap();
    let keyfile_path = dir.path().join("master.key");
    let vault_path = dir.path().join("keyfile_vault.svault");

    // 1. Generate keyfile
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

    // 2. Open REPL with keyfile + passphrase and store secret
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "2faPassphrase!",
            "-k",
            keyfile_path.to_str().unwrap(),
            "-e",
            "set secure_api key_in_2fa; save",
        ])
        .assert()
        .success();

    // 3. Re-read secret with keyfile + passphrase
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "2faPassphrase!",
            "-k",
            keyfile_path.to_str().unwrap(),
            "-e",
            "get secure_api --raw",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("key_in_2fa"));

    // 4. Reading without keyfile fails
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "2faPassphrase!",
            "-e",
            "get secure_api",
        ])
        .assert()
        .failure();
}

#[test]
fn test_repl_masked_preview_and_reveal() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("masking.svault");

    // Set a long secret
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "MaskingPass!",
            "-e",
            "set long_secret super_califragilistic_expialidocious; save",
        ])
        .assert()
        .success();

    // Default get shows masked preview
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "MaskingPass!",
            "-e",
            "get long_secret",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("••••••••"));

    // Reveal shows unmasked plaintext
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "repl",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "MaskingPass!",
            "-e",
            "get long_secret --reveal",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "super_califragilistic_expialidocious",
        ));
}
