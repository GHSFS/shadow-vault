// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Dedicated integration test suite for Milestone M16:
//! Deterministic & CSPRNG Passphrase Generator (`svault keygen` / `passgen`).

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn test_keygen_diceware_default_and_custom_options() {
    let mut cmd = Command::cargo_bin("svault").unwrap();
    cmd.args(["keygen", "--words", "6"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let trimmed = stdout.trim();

    let parts: Vec<&str> = trimmed.split('-').collect();
    assert_eq!(parts.len(), 6, "Expected 6 hyphen-separated words");
    for part in parts {
        assert!(
            part.chars().all(|c| c.is_ascii_lowercase()),
            "Word should be lowercase: {part}"
        );
    }

    // Custom separator, capitalization, and numbers
    let mut cmd_custom = Command::cargo_bin("svault").unwrap();
    cmd_custom.args([
        "keygen",
        "--words",
        "4",
        "--separator",
        ".",
        "--capitalize",
        "--number",
    ]);
    let assert_custom = cmd_custom.assert().success();
    let stdout_custom = String::from_utf8(assert_custom.get_output().stdout.clone()).unwrap();
    let trimmed_custom = stdout_custom.trim();

    let parts_custom: Vec<&str> = trimmed_custom.split('.').collect();
    assert_eq!(parts_custom.len(), 4, "Expected 4 dot-separated words");
    for part in parts_custom {
        let first = part.chars().next().unwrap();
        assert!(first.is_ascii_uppercase(), "Word should be capitalized");
        let last = part.chars().last().unwrap();
        assert!(last.is_ascii_digit(), "Word should end with a digit");
    }
}

#[test]
fn test_keygen_characters_options() {
    // Alphanumeric without symbols
    let mut cmd_no_sym = Command::cargo_bin("svault").unwrap();
    cmd_no_sym.args(["keygen", "--length", "24", "--no-symbols"]);
    let assert_no_sym = cmd_no_sym.assert().success();
    let out_no_sym = String::from_utf8(assert_no_sym.get_output().stdout.clone()).unwrap();
    let trimmed_no_sym = out_no_sym.trim();

    assert_eq!(trimmed_no_sym.len(), 24);
    assert!(
        trimmed_no_sym.chars().all(|c| c.is_ascii_alphanumeric()),
        "Expected only alphanumeric characters"
    );

    // Exclude ambiguous characters
    let mut cmd_ambig = Command::cargo_bin("svault").unwrap();
    cmd_ambig.args(["keygen", "--length", "40", "--exclude-ambiguous"]);
    let assert_ambig = cmd_ambig.assert().success();
    let out_ambig = String::from_utf8(assert_ambig.get_output().stdout.clone()).unwrap();
    let trimmed_ambig = out_ambig.trim();

    assert_eq!(trimmed_ambig.len(), 40);
    let ambiguous_chars = "0Oo1lI|8B";
    for ch in trimmed_ambig.chars() {
        assert!(
            !ambiguous_chars.contains(ch),
            "Ambiguous character '{ch}' found in output: {trimmed_ambig}"
        );
    }
}

#[test]
fn test_keygen_raw_bytes_modes() {
    // Hex mode (default for bytes)
    let mut cmd_hex = Command::cargo_bin("svault").unwrap();
    cmd_hex.args(["keygen", "--bytes", "32"]);
    let assert_hex = cmd_hex.assert().success();
    let out_hex = String::from_utf8(assert_hex.get_output().stdout.clone()).unwrap();
    let trimmed_hex = out_hex.trim();

    assert_eq!(trimmed_hex.len(), 64, "32 bytes hex should be 64 chars");
    assert!(trimmed_hex.chars().all(|c| c.is_ascii_hexdigit()));

    // Base64 mode
    let mut cmd_b64 = Command::cargo_bin("svault").unwrap();
    cmd_b64.args(["keygen", "--bytes", "32", "--base64"]);
    let assert_b64 = cmd_b64.assert().success();
    let out_b64 = String::from_utf8(assert_b64.get_output().stdout.clone()).unwrap();
    let trimmed_b64 = out_b64.trim();

    use base64::prelude::*;
    let decoded = BASE64_STANDARD.decode(trimmed_b64).expect("invalid base64");
    assert_eq!(decoded.len(), 32);

    // Base32 mode
    let mut cmd_b32 = Command::cargo_bin("svault").unwrap();
    cmd_b32.args(["keygen", "--bytes", "20", "--base32"]);
    let assert_b32 = cmd_b32.assert().success();
    let out_b32 = String::from_utf8(assert_b32.get_output().stdout.clone()).unwrap();
    let trimmed_b32 = out_b32.trim();

    // Base32 for 20 bytes is 32 characters
    assert_eq!(trimmed_b32.len(), 32);
    assert!(trimmed_b32.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn test_keygen_numeric_pin() {
    let mut cmd = Command::cargo_bin("svault").unwrap();
    cmd.args(["keygen", "--pin", "8"]);
    let assert = cmd.assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let trimmed = out.trim();

    assert_eq!(trimmed.len(), 8);
    assert!(trimmed.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn test_keygen_deterministic_seed_reproducibility() {
    let mut cmd1 = Command::cargo_bin("svault").unwrap();
    cmd1.args([
        "keygen",
        "--words",
        "5",
        "--seed",
        "quantum-master-seed-2026",
        "--context",
        "github-backup",
    ]);
    let out1 = String::from_utf8(cmd1.assert().success().get_output().stdout.clone()).unwrap();

    let mut cmd2 = Command::cargo_bin("svault").unwrap();
    cmd2.args([
        "keygen",
        "--words",
        "5",
        "--seed",
        "quantum-master-seed-2026",
        "--context",
        "github-backup",
    ]);
    let out2 = String::from_utf8(cmd2.assert().success().get_output().stdout.clone()).unwrap();

    assert_eq!(
        out1.trim(),
        out2.trim(),
        "Identical seed and context must yield deterministic identical passphrases"
    );

    // Different context must produce different output
    let mut cmd3 = Command::cargo_bin("svault").unwrap();
    cmd3.args([
        "keygen",
        "--words",
        "5",
        "--seed",
        "quantum-master-seed-2026",
        "--context",
        "aws-root",
    ]);
    let out3 = String::from_utf8(cmd3.assert().success().get_output().stdout.clone()).unwrap();
    assert_ne!(out1.trim(), out3.trim());
}

#[test]
fn test_keygen_json_output_mode() {
    let mut cmd = Command::cargo_bin("svault").unwrap();
    cmd.args(["keygen", "--words", "6", "--json"]);
    let assert = cmd.assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    let parsed: Value = serde_json::from_str(&out).expect("invalid JSON output");
    assert!(parsed.is_array());
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);

    let first = &arr[0];
    assert_eq!(first["mode"], "diceware");
    assert!(first["secret"].is_string());
    assert!(first["keyspace_entropy_bits"].as_f64().unwrap() >= 66.0);
    assert_eq!(first["rating"], "strong");
    assert!(first["score"].as_u64().is_some());
}

#[test]
fn test_keygen_entropy_flag_and_aliases() {
    // Check --entropy detailed report
    let mut cmd = Command::cargo_bin("svault").unwrap();
    cmd.args(["keygen", "--length", "25", "--entropy"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Generated Secret:"))
        .stdout(predicate::str::contains("Strength Rating:"))
        .stdout(predicate::str::contains("Keyspace Entropy:"))
        .stdout(predicate::str::contains("Shannon Entropy:"))
        .stdout(predicate::str::contains("Effective Entropy:"));

    // Check alias: passgen
    let mut cmd_alias1 = Command::cargo_bin("svault").unwrap();
    cmd_alias1.args(["passgen", "--pin", "6"]);
    cmd_alias1.assert().success();

    // Check alias: gen-key
    let mut cmd_alias2 = Command::cargo_bin("svault").unwrap();
    cmd_alias2.args(["gen-key", "--bytes", "16"]);
    cmd_alias2.assert().success();
}

#[test]
fn test_keygen_multi_candidate_count() {
    let mut cmd = Command::cargo_bin("svault").unwrap();
    cmd.args(["keygen", "--words", "4", "--count", "3"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("=== [GENERATED SECRETS (3)] ==="))
        .stdout(predicate::str::contains(" 1. "))
        .stdout(predicate::str::contains(" 2. "))
        .stdout(predicate::str::contains(" 3. "));
}
