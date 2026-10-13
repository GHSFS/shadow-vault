// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Domain integration tests for Milestone M13: Chunked Streaming Encryption (`src/stream.rs`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn svault() -> Command {
    Command::cargo_bin("svault").expect("svault binary exists")
}

#[test]
fn test_stream_empty_0byte_roundtrip() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("empty.txt");
    let enc_path = dir.path().join("empty.svault");
    let dec_path = dir.path().join("empty_dec.txt");

    fs::write(&input_path, b"").unwrap();

    // 1. Encrypt 0-byte stream using 'svault stream enc'
    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "stream-pass-zero",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypted 0 bytes in 1 chunks"));

    assert!(enc_path.exists());

    // 2. Inspect streaming container header
    svault()
        .args(["stream", "inspect", enc_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("container_type:    stream"))
        .stdout(predicate::str::contains("container_version: 1"))
        .stdout(predicate::str::contains("dpapi_bound:       false"));

    // 3. Inspect structured JSON output
    let inspect_out = svault()
        .args(["stream", "inspect", enc_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json_val: serde_json::Value =
        serde_json::from_slice(&inspect_out).expect("valid inspect json");
    assert_eq!(json_val["container_type"], "stream");
    assert_eq!(json_val["container_version"], 1);
    assert_eq!(json_val["dpapi_bound"], false);

    // 4. Decrypt 0-byte stream using 'svault stream dec'
    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "stream-pass-zero",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("decrypted 0 bytes in 1 chunks"));

    let dec_data = fs::read(&dec_path).unwrap();
    assert_eq!(dec_data, b"");

    // 5. Test auto-detect stream in standard 'svault decrypt'
    let auto_dec_path = dir.path().join("empty_auto_dec.txt");
    svault()
        .args([
            "decrypt",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            auto_dec_path.to_str().unwrap(),
            "-p",
            "stream-pass-zero",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("decrypted 0 bytes in 1 chunks"));

    assert_eq!(fs::read(&auto_dec_path).unwrap(), b"");
}

#[test]
fn test_stream_small_file_roundtrip() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("secret.txt");
    let enc_path = dir.path().join("secret.svault");
    let dec_path = dir.path().join("secret_dec.txt");

    let payload = b"ShadowVault M13 Chunked Streaming Encryption Test Payload. Constant O(1) RAM.";
    fs::write(&input_path, payload).unwrap();

    // Encrypt with explicit 64k chunk size
    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "correct-passphrase",
            "--chunk-size",
            "64k",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "encrypted {} bytes in 1 chunks",
            payload.len()
        )));

    // Decrypt
    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "correct-passphrase",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "decrypted {} bytes in 1 chunks",
            payload.len()
        )));

    assert_eq!(fs::read(&dec_path).unwrap(), payload);
}

#[test]
fn test_stream_exact_chunk_boundary_roundtrip() {
    let dir = tempdir().unwrap();
    let chunk_size: usize = 65536; // 64 KiB
    let enc_path = dir.path().join("exact.svault");
    let dec_path = dir.path().join("exact_dec.bin");

    // Case 1: Exactly 1 chunk (65,536 bytes)
    let mut exact_1 = vec![0u8; chunk_size];
    for (i, b) in exact_1.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let input_1 = dir.path().join("exact_1.bin");
    fs::write(&input_1, &exact_1).unwrap();

    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_1.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "exact-boundary-pass",
            "--chunk-size",
            "64k",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "encrypted 65536 bytes in 1 chunks",
        ));

    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "exact-boundary-pass",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "decrypted 65536 bytes in 1 chunks",
        ));

    assert_eq!(fs::read(&dec_path).unwrap(), exact_1);

    // Case 2: Exactly 2 chunks (131,072 bytes)
    let mut exact_2 = vec![0u8; chunk_size * 2];
    for (i, b) in exact_2.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let input_2 = dir.path().join("exact_2.bin");
    fs::write(&input_2, &exact_2).unwrap();

    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_2.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "exact-boundary-pass",
            "--chunk-size",
            "64k",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "encrypted 131072 bytes in 2 chunks",
        ));

    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "exact-boundary-pass",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "decrypted 131072 bytes in 2 chunks",
        ));

    assert_eq!(fs::read(&dec_path).unwrap(), exact_2);
}

#[test]
fn test_stream_multi_chunk_streaming() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("multichunk.bin");
    let enc_path = dir.path().join("multichunk.svault");
    let dec_path = dir.path().join("multichunk_dec.bin");

    // 200,000 bytes with 64 KiB chunks -> 4 chunks (65536, 65536, 65536, 3392)
    let total_len = 200_000usize;
    let mut data = vec![0u8; total_len];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ((i * 7 + 13) % 256) as u8;
    }
    fs::write(&input_path, &data).unwrap();

    // Use standard 'svault encrypt --stream' flag
    svault()
        .args([
            "encrypt",
            "--stream",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "stream-test-key",
            "--chunk-size",
            "64k",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "encrypted 200000 bytes in 4 chunks",
        ));

    // Decrypt using standard 'svault decrypt' (auto-detect stream)
    svault()
        .args([
            "decrypt",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "stream-test-key",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "decrypted 200000 bytes in 4 chunks",
        ));

    assert_eq!(fs::read(&dec_path).unwrap(), data);
}

#[test]
fn test_stream_2fa_keyfile_roundtrip() {
    let dir = tempdir().unwrap();
    let keyfile_path = dir.path().join("token.key");
    let input_path = dir.path().join("classified.txt");
    let enc_path = dir.path().join("classified.svault");
    let dec_path = dir.path().join("classified_dec.txt");

    // 1. Generate keyfile
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

    let secret = b"TOP SECRET MISSION INSTRUCTIONS FOR 2FA STREAM";
    fs::write(&input_path, secret).unwrap();

    // 2. Encrypt with passphrase + keyfile
    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "mission-passphrase",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // 3. Decrypt with passphrase only (missing keyfile) -> must fail
    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "mission-passphrase",
        ])
        .assert()
        .failure();

    // 4. Decrypt with both passphrase + keyfile -> must succeed
    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "mission-passphrase",
            "-k",
            keyfile_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&dec_path).unwrap(), secret);
}

#[test]
fn test_stream_policy_timelock_and_expiration() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("timelocked.txt");
    let enc_path = dir.path().join("timelocked.svault");
    let dec_path = dir.path().join("timelocked_dec.txt");

    fs::write(&input_path, b"Time-locked streaming payload").unwrap();

    // 1. Encrypt with --not-before +1h (time-locked)
    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "time-lock-pass",
            "--not-before",
            "+1h",
            "--policy-desc",
            "Escrow streaming test",
        ])
        .assert()
        .success();

    // Decrypt now -> fails (vault is time-locked)
    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "time-lock-pass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("time-locked until"));

    // Decrypt simulated at +2h -> succeeds
    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "time-lock-pass",
            "--at-time",
            "+2h",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(&dec_path).unwrap(),
        b"Time-locked streaming payload"
    );

    // 2. Encrypt with past expiration timestamp -> fails immediately on decrypt
    let expired_enc_path = dir.path().join("expired.svault");
    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            expired_enc_path.to_str().unwrap(),
            "-p",
            "expired-pass",
            "--expires-at",
            "1700000000",
        ])
        .assert()
        .success();

    svault()
        .args([
            "stream",
            "dec",
            "-i",
            expired_enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "expired-pass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("vault expired at"));
}

#[test]
fn test_stream_tamper_rejection() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("tamper_in.txt");
    let enc_path = dir.path().join("tampered.svault");
    let dec_path = dir.path().join("tamper_out.txt");

    fs::write(&input_path, b"Tamper resilience verification stream").unwrap();

    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "tamper-pass",
        ])
        .assert()
        .success();

    // Modify 1 byte in the ciphertext chunk
    let mut data = fs::read(&enc_path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0x55;
    fs::write(&enc_path, &data).unwrap();

    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "tamper-pass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("authentication failed"));
}

#[test]
fn test_stream_truncated_rejection() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("trunc_in.bin");
    let enc_path = dir.path().join("trunc.svault");
    let dec_path = dir.path().join("trunc_out.bin");

    // 150 KiB with 64 KiB chunks -> 3 chunks
    let data = vec![0x42u8; 150_000];
    fs::write(&input_path, &data).unwrap();

    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "trunc-pass",
            "--chunk-size",
            "64k",
        ])
        .assert()
        .success();

    // Truncate off the last 10,000 bytes
    let enc_bytes = fs::read(&enc_path).unwrap();
    fs::write(&enc_path, &enc_bytes[..enc_bytes.len() - 10000]).unwrap();

    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "trunc-pass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("truncated"));
}

#[test]
fn test_stream_audit_detection() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("audit_in.txt");
    let enc_path = dir.path().join("audit.svault");

    fs::write(&input_path, b"Auditable streaming container payload").unwrap();

    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "audit-pass",
        ])
        .assert()
        .success();

    // Run 'svault audit' on the streaming container
    svault()
        .args(["audit", enc_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("ShadowVault Streaming Container"))
        .stdout(predicate::str::contains("ENCRYPTED CONTAINER"));

    // Run 'svault audit --json'
    let audit_out = svault()
        .args(["audit", enc_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json_val: serde_json::Value = serde_json::from_slice(&audit_out).expect("valid audit json");
    assert_eq!(json_val["carrier"]["carrier_type"], "stream_container");
    assert_eq!(json_val["carrier"]["verdict"], "encrypted_container");
}

#[cfg(windows)]
#[test]
fn test_stream_dpapi_hardware_binding() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("dpapi_in.txt");
    let enc_path = dir.path().join("dpapi.svault");
    let dec_path = dir.path().join("dpapi_dec.txt");

    let secret = b"DPAPI Windows hardware bound streaming payload!";
    fs::write(&input_path, secret).unwrap();

    // Encrypt with --dpapi flag
    svault()
        .args([
            "stream",
            "enc",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-p",
            "dpapi-stream-pass",
            "--dpapi",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("dpapi=true"));

    // Inspect confirms dpapi_bound: true
    svault()
        .args(["stream", "inspect", enc_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("dpapi_bound:       true"));

    // Decrypt succeeds on originating Windows machine
    svault()
        .args([
            "stream",
            "dec",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-p",
            "dpapi-stream-pass",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&dec_path).unwrap(), secret);
}
