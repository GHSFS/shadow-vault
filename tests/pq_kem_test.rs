// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_pq_kem_key_generation_and_armoring() {
    let dir = tempdir().unwrap();
    let pubkey_path = dir.path().join("recipient.pub");
    let privkey_path = dir.path().join("recipient.key");

    // Generate keys via CLI
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem",
            "keygen",
            "--pubkey",
            pubkey_path.to_str().unwrap(),
            "--privkey",
            privkey_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Post-Quantum Hybrid Keypair Generated",
        ))
        .stdout(predicate::str::contains("X25519 + ML-KEM-768 (FIPS 203)"))
        .stdout(predicate::str::contains("SHA256:"));

    assert!(pubkey_path.exists());
    assert!(privkey_path.exists());

    let pub_content = fs::read_to_string(&pubkey_path).unwrap();
    assert!(pub_content.starts_with("-----BEGIN SHADOW VAULT KEM PUBLIC KEY-----"));
    assert!(pub_content.contains("-----END SHADOW VAULT KEM PUBLIC KEY-----"));

    let priv_content = fs::read_to_string(&privkey_path).unwrap();
    assert!(priv_content.starts_with("-----BEGIN SHADOW VAULT KEM PRIVATE KEY-----"));
    assert!(priv_content.contains("-----END SHADOW VAULT KEM PRIVATE KEY-----"));
}

#[test]
fn test_pq_kem_seal_and_open_roundtrip_binary() {
    let dir = tempdir().unwrap();
    let pubkey_path = dir.path().join("test.pub");
    let privkey_path = dir.path().join("test.key");
    let input_path = dir.path().join("secret.txt");
    let container_path = dir.path().join("secret.svault.pq");
    let recovered_path = dir.path().join("recovered.txt");

    // 1. Generate keys
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-keygen",
            "-p",
            pubkey_path.to_str().unwrap(),
            "-s",
            privkey_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // 2. Prepare test payload
    let test_secret =
        b"Quantum-resistant vault payload protected by X25519 and ML-KEM-768 hybrid encapsulation.";
    fs::write(&input_path, test_secret).unwrap();

    // 3. Seal container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-seal",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            container_path.to_str().unwrap(),
            "-k",
            pubkey_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Post-Quantum Vault Sealed Successfully",
        ));

    assert!(container_path.exists());
    let raw_bytes = fs::read(&container_path).unwrap();
    assert_eq!(&raw_bytes[0..4], b"SVPQ");

    // 4. Inspect container
    Command::cargo_bin("svault")
        .unwrap()
        .args(["kem-inspect", "-i", container_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Format           : SVPQ v1"))
        .stdout(predicate::str::contains("CRC-32 Valid     : true"))
        .stdout(predicate::str::contains("ML-KEM-768 CT    : 1088 bytes"));

    // 5. Open container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-open",
            "-i",
            container_path.to_str().unwrap(),
            "-o",
            recovered_path.to_str().unwrap(),
            "-k",
            privkey_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Post-Quantum Vault Opened Successfully",
        ))
        .stdout(predicate::str::contains("VERIFIED (Poly1305 + CRC-32)"));

    let recovered = fs::read(&recovered_path).unwrap();
    assert_eq!(recovered, test_secret);
}

#[test]
fn test_pq_kem_seal_and_open_roundtrip_armored() {
    let dir = tempdir().unwrap();
    let pubkey_path = dir.path().join("alice.pub");
    let privkey_path = dir.path().join("alice.key");
    let input_path = dir.path().join("plain.bin");
    let container_path = dir.path().join("sealed.asc");
    let output_path = dir.path().join("unsealed.bin");

    // Keygen
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem",
            "keygen",
            "-p",
            pubkey_path.to_str().unwrap(),
            "-s",
            privkey_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let sample_payload = vec![0x42u8; 8192]; // 8 KiB buffer
    fs::write(&input_path, &sample_payload).unwrap();

    // Seal with --armor
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem",
            "seal",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            container_path.to_str().unwrap(),
            "-k",
            pubkey_path.to_str().unwrap(),
            "--armor",
        ])
        .assert()
        .success();

    let armored_str = fs::read_to_string(&container_path).unwrap();
    assert!(armored_str.starts_with("-----BEGIN SHADOW VAULT PQ CONTAINER-----"));
    assert!(armored_str.contains("-----END SHADOW VAULT PQ CONTAINER-----"));

    // Inspect armored container
    Command::cargo_bin("svault")
        .unwrap()
        .args(["kem", "inspect", "-i", container_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("CRC-32 Valid     : true"));

    // Open armored container
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem",
            "open",
            "-i",
            container_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "-k",
            privkey_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let unsealed = fs::read(&output_path).unwrap();
    assert_eq!(unsealed, sample_payload);
}

#[test]
fn test_pq_kem_wrong_private_key_fails_authentication() {
    let dir = tempdir().unwrap();
    let alice_pub = dir.path().join("alice.pub");
    let alice_key = dir.path().join("alice.key");
    let bob_pub = dir.path().join("bob.pub");
    let bob_key = dir.path().join("bob.key");

    let input_path = dir.path().join("message.txt");
    let container_path = dir.path().join("message.svault.pq");
    let output_path = dir.path().join("output.txt");

    fs::write(&input_path, b"Top secret data for Alice only.").unwrap();

    // Generate Alice keypair
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-keygen",
            "-p",
            alice_pub.to_str().unwrap(),
            "-s",
            alice_key.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Generate Bob keypair
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-keygen",
            "-p",
            bob_pub.to_str().unwrap(),
            "-s",
            bob_key.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Seal for Alice
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-seal",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            container_path.to_str().unwrap(),
            "-k",
            alice_pub.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Attempt to open using Bob's private key -> MUST FAIL
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-open",
            "-i",
            container_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "-k",
            bob_key.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn test_pq_kem_tampering_detection() {
    let dir = tempdir().unwrap();
    let pub_path = dir.path().join("node.pub");
    let key_path = dir.path().join("node.key");
    let input_path = dir.path().join("original.txt");
    let container_path = dir.path().join("vault.svault.pq");
    let output_path = dir.path().join("output.txt");

    fs::write(&input_path, b"Immutable financial transaction record.").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-keygen",
            "-p",
            pub_path.to_str().unwrap(),
            "-s",
            key_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-seal",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            container_path.to_str().unwrap(),
            "-k",
            pub_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut bytes = fs::read(&container_path).unwrap();

    // 1. Flip a bit in the encrypted payload
    let tamper_pos = bytes.len() - 20;
    bytes[tamper_pos] ^= 0x01;
    fs::write(&container_path, &bytes).unwrap();

    // Must fail either CRC-32 or AEAD authentication
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-open",
            "-i",
            container_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "-k",
            key_path.to_str().unwrap(),
        ])
        .assert()
        .failure();

    // 2. Truncate container to corrupt format
    fs::write(&container_path, &bytes[..100]).unwrap();
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem-open",
            "-i",
            container_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "-k",
            key_path.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn test_pq_kem_json_output_mode() {
    let dir = tempdir().unwrap();
    let pub_path = dir.path().join("json.pub");
    let key_path = dir.path().join("json.key");
    let in_path = dir.path().join("in.txt");
    let out_path = dir.path().join("out.svault.pq");
    let dec_path = dir.path().join("dec.txt");

    fs::write(&in_path, b"JSON automation testing payload").unwrap();

    // 1. Keygen JSON
    let keygen_out = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem",
            "keygen",
            "-p",
            pub_path.to_str().unwrap(),
            "-s",
            key_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let keygen_json: serde_json::Value = serde_json::from_slice(&keygen_out).unwrap();
    assert_eq!(keygen_json["algorithm"], "X25519 + ML-KEM-768 (FIPS 203)");
    assert!(keygen_json["fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));

    // 2. Seal JSON
    let seal_out = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem",
            "seal",
            "-i",
            in_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-k",
            pub_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let seal_json: serde_json::Value = serde_json::from_slice(&seal_out).unwrap();
    assert_eq!(
        seal_json["algorithm"],
        "X25519 + ML-KEM-768 + ChaCha20-Poly1305"
    );
    assert!(seal_json["container_bytes"].as_u64().unwrap() > 1160);

    // 3. Inspect JSON
    let inspect_out = Command::cargo_bin("svault")
        .unwrap()
        .args(["kem", "inspect", "-i", out_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let inspect_json: serde_json::Value = serde_json::from_slice(&inspect_out).unwrap();
    assert_eq!(inspect_json["valid_magic"], true);
    assert_eq!(inspect_json["crc32_valid"], true);
    assert_eq!(inspect_json["mlkem_ciphertext_len"], 1088);

    // 4. Open JSON
    let open_out = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "kem",
            "open",
            "-i",
            out_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-k",
            key_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let open_json: serde_json::Value = serde_json::from_slice(&open_out).unwrap();
    assert_eq!(open_json["verified"], true);
    assert_eq!(open_json["plaintext_bytes"], 31);
}
