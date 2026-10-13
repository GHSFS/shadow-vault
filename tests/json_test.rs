// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_json_encrypt_and_decrypt_mode() {
    let dir = tempdir().unwrap();
    let plain_path = dir.path().join("plain.txt");
    let vault_path = dir.path().join("plain.svault");
    let out_path = dir.path().join("recovered.txt");

    fs::write(&plain_path, b"Confidential JSON mode test payload").unwrap();

    let assert_enc = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt",
            "-i",
            plain_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "super_secret_json_pass!123",
            "--json",
        ])
        .assert()
        .success();

    let enc_stdout = String::from_utf8(assert_enc.get_output().stdout.clone()).unwrap();
    let enc_json: serde_json::Value = serde_json::from_str(&enc_stdout).unwrap();
    assert_eq!(enc_json["status"], "ok");
    assert_eq!(enc_json["command"], "encrypt");
    assert_eq!(enc_json["plaintext_bytes"], 35);

    // Inspect container with --json
    let assert_insp = Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", vault_path.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let insp_stdout = String::from_utf8(assert_insp.get_output().stdout.clone()).unwrap();
    let insp_json: serde_json::Value = serde_json::from_str(&insp_stdout).unwrap();
    assert_eq!(insp_json["carrier_type"], "vault");
    assert_eq!(insp_json["payload_bytes"], 35);

    let assert_dec = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-p",
            "super_secret_json_pass!123",
            "--json",
        ])
        .assert()
        .success();

    let dec_stdout = String::from_utf8(assert_dec.get_output().stdout.clone()).unwrap();
    let dec_json: serde_json::Value = serde_json::from_str(&dec_stdout).unwrap();
    assert_eq!(dec_json["status"], "ok");
    assert_eq!(dec_json["command"], "decrypt");
    assert_eq!(dec_json["plaintext_bytes"], 35);
    assert_eq!(
        fs::read(&out_path).unwrap(),
        b"Confidential JSON mode test payload"
    );
}

#[test]
fn test_json_encrypt_decoy_and_decrypt_decoy() {
    let dir = tempdir().unwrap();
    let primary_path = dir.path().join("primary.txt");
    let decoy_path = dir.path().join("decoy.txt");
    let vault_path = dir.path().join("dual.svault");
    let out_decoy_path = dir.path().join("out_decoy.txt");

    fs::write(&primary_path, b"Top secret primary hidden intelligence").unwrap();
    fs::write(&decoy_path, b"Harmless decoy shopping grocery list").unwrap();

    let assert_enc = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "encrypt-decoy",
            "-i",
            primary_path.to_str().unwrap(),
            "-d",
            decoy_path.to_str().unwrap(),
            "-o",
            vault_path.to_str().unwrap(),
            "-p",
            "primary_pass_2026",
            "--decoy-passphrase",
            "decoy_pass_2026",
            "--json",
        ])
        .assert()
        .success();

    let enc_stdout = String::from_utf8(assert_enc.get_output().stdout.clone()).unwrap();
    let enc_json: serde_json::Value = serde_json::from_str(&enc_stdout).unwrap();
    assert_eq!(enc_json["status"], "ok");
    assert_eq!(enc_json["command"], "encrypt-decoy");
    assert_eq!(enc_json["decoy_bytes"], 36);

    let assert_dec = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "decrypt",
            "-i",
            vault_path.to_str().unwrap(),
            "-o",
            out_decoy_path.to_str().unwrap(),
            "-p",
            "decoy_pass_2026",
            "--json",
        ])
        .assert()
        .success();

    let dec_stdout = String::from_utf8(assert_dec.get_output().stdout.clone()).unwrap();
    let dec_json: serde_json::Value = serde_json::from_str(&dec_stdout).unwrap();
    assert_eq!(dec_json["status"], "ok");
    assert_eq!(dec_json["command"], "decrypt");
    assert_eq!(dec_json["plaintext_bytes"], 36);
    assert_eq!(
        fs::read(&out_decoy_path).unwrap(),
        b"Harmless decoy shopping grocery list"
    );
}

#[test]
fn test_json_armor_dearmor_and_shred() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("original.dat");
    let asc_path = dir.path().join("armored.svault.asc");
    let dearmored_path = dir.path().join("restored.dat");

    fs::write(&src_path, b"Resilient Cauchy MDS parity test payload").unwrap();

    // Armor with JSON
    let assert_arm = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "armor",
            "-i",
            src_path.to_str().unwrap(),
            "-o",
            asc_path.to_str().unwrap(),
            "-k",
            "4",
            "-m",
            "2",
            "--json",
        ])
        .assert()
        .success();

    let arm_stdout = String::from_utf8(assert_arm.get_output().stdout.clone()).unwrap();
    let arm_json: serde_json::Value = serde_json::from_str(&arm_stdout).unwrap();
    assert_eq!(arm_json["status"], "ok");
    assert_eq!(arm_json["command"], "armor");
    assert_eq!(arm_json["data_stripes"], 4);
    assert_eq!(arm_json["parity_stripes"], 2);

    // Inspect armored container with JSON
    let assert_insp = Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", asc_path.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let insp_stdout = String::from_utf8(assert_insp.get_output().stdout.clone()).unwrap();
    let insp_json: serde_json::Value = serde_json::from_str(&insp_stdout).unwrap();
    assert_eq!(insp_json["carrier_type"], "armor");

    // Dearmor with JSON
    let assert_dearm = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "dearmor",
            "-i",
            asc_path.to_str().unwrap(),
            "-o",
            dearmored_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();

    let dearm_stdout = String::from_utf8(assert_dearm.get_output().stdout.clone()).unwrap();
    let dearm_json: serde_json::Value = serde_json::from_str(&dearm_stdout).unwrap();
    assert_eq!(dearm_json["status"], "ok");
    assert_eq!(dearm_json["command"], "dearmor");
    assert_eq!(
        fs::read(&dearmored_path).unwrap(),
        b"Resilient Cauchy MDS parity test payload"
    );

    // Shred with JSON
    let assert_shred = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "shred",
            dearmored_path.to_str().unwrap(),
            "--passes",
            "3",
            "--json",
        ])
        .assert()
        .success();

    let shred_stdout = String::from_utf8(assert_shred.get_output().stdout.clone()).unwrap();
    let shred_json: serde_json::Value = serde_json::from_str(&shred_stdout).unwrap();
    assert_eq!(shred_json["status"], "ok");
    assert_eq!(shred_json["command"], "shred");
    assert_eq!(shred_json["passes"], 3);
    assert!(!dearmored_path.exists());
}

#[test]
fn test_json_keyfile_commands() {
    let dir = tempdir().unwrap();
    let kf_path = dir.path().join("master.key");

    let assert_gen = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "keyfile",
            "generate",
            "-o",
            kf_path.to_str().unwrap(),
            "-b",
            "64",
            "--json",
        ])
        .assert()
        .success();

    let gen_stdout = String::from_utf8(assert_gen.get_output().stdout.clone()).unwrap();
    let gen_json: serde_json::Value = serde_json::from_str(&gen_stdout).unwrap();
    assert_eq!(gen_json["status"], "ok");
    assert_eq!(gen_json["command"], "keyfile generate");
    assert_eq!(gen_json["bytes"], 64);
    assert!(gen_json["fingerprint"].is_string());

    let assert_fp = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "keyfile",
            "fingerprint",
            kf_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();

    let fp_stdout = String::from_utf8(assert_fp.get_output().stdout.clone()).unwrap();
    let fp_json: serde_json::Value = serde_json::from_str(&fp_stdout).unwrap();
    assert_eq!(fp_json["fingerprint"], gen_json["fingerprint"]);
}

#[test]
fn test_json_totp_and_guard_lifecycle() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("tokens.svault");

    // TOTP Add with JSON
    let assert_add = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "add",
            "GitHub:octocat",
            "-s",
            "JBSWY3DPEHPK3PXP",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "totp_vault_pass_2026",
            "--json",
        ])
        .assert()
        .success();

    let add_stdout = String::from_utf8(assert_add.get_output().stdout.clone()).unwrap();
    let add_json: serde_json::Value = serde_json::from_str(&add_stdout).unwrap();
    assert_eq!(add_json["status"], "ok");
    assert_eq!(add_json["command"], "totp add");
    assert_eq!(add_json["name"], "GitHub:octocat");

    // TOTP Remove with JSON
    let assert_rm = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "totp",
            "remove",
            "GitHub:octocat",
            "-v",
            vault_path.to_str().unwrap(),
            "-p",
            "totp_vault_pass_2026",
            "--json",
        ])
        .assert()
        .success();

    let rm_stdout = String::from_utf8(assert_rm.get_output().stdout.clone()).unwrap();
    let rm_json: serde_json::Value = serde_json::from_str(&rm_stdout).unwrap();
    assert_eq!(rm_json["status"], "ok");
    assert_eq!(rm_json["command"], "totp remove");

    // Guard Lifecycle with JSON
    let guarded_file = dir.path().join("secure_asset.dat");
    fs::write(&guarded_file, b"Target protected by stealth guard").unwrap();

    let assert_arm = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "arm",
            "-t",
            guarded_file.to_str().unwrap(),
            "-m",
            "3",
            "--companion",
            "--json",
        ])
        .assert()
        .success();

    let arm_stdout = String::from_utf8(assert_arm.get_output().stdout.clone()).unwrap();
    let arm_json: serde_json::Value = serde_json::from_str(&arm_stdout).unwrap();
    assert_eq!(arm_json["status"], "ok");
    assert_eq!(arm_json["command"], "guard arm");
    assert_eq!(arm_json["max_attempts"], 3);

    // Guard Reset with JSON
    let assert_reset = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "reset",
            "-t",
            guarded_file.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();

    let reset_stdout = String::from_utf8(assert_reset.get_output().stdout.clone()).unwrap();
    let reset_json: serde_json::Value = serde_json::from_str(&reset_stdout).unwrap();
    assert_eq!(reset_json["status"], "ok");
    assert_eq!(reset_json["command"], "guard reset");
    assert_eq!(reset_json["failed_attempts"], 0);

    // Guard Disarm with JSON
    let assert_disarm = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "guard",
            "disarm",
            "-t",
            guarded_file.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();

    let disarm_stdout = String::from_utf8(assert_disarm.get_output().stdout.clone()).unwrap();
    let disarm_json: serde_json::Value = serde_json::from_str(&disarm_stdout).unwrap();
    assert_eq!(disarm_json["status"], "ok");
    assert_eq!(disarm_json["command"], "guard disarm");
    assert_eq!(disarm_json["disarmed"], true);
}

#[test]
fn test_json_png_stego_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("carrier.png");
    let secret_path = dir.path().join("secret.txt");
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
    fs::write(&secret_path, b"Hidden PNG stego secret").unwrap();

    let assert_embed = Command::cargo_bin("svault")
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
            "png_stego_pass_2026",
            "--json",
        ])
        .assert()
        .success();

    let embed_stdout = String::from_utf8(assert_embed.get_output().stdout.clone()).unwrap();
    let embed_json: serde_json::Value = serde_json::from_str(&embed_stdout).unwrap();
    assert_eq!(embed_json["status"], "ok");
    assert_eq!(embed_json["command"], "embed");
    assert_eq!(embed_json["carrier_type"], "png");

    let assert_insp = Command::cargo_bin("svault")
        .unwrap()
        .args(["inspect", stego_path.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let insp_stdout = String::from_utf8(assert_insp.get_output().stdout.clone()).unwrap();
    let insp_json: serde_json::Value = serde_json::from_str(&insp_stdout).unwrap();
    assert_eq!(insp_json["carrier_type"], "png");

    let assert_ext = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            extracted_path.to_str().unwrap(),
            "-p",
            "png_stego_pass_2026",
            "--json",
        ])
        .assert()
        .success();

    let ext_stdout = String::from_utf8(assert_ext.get_output().stdout.clone()).unwrap();
    let ext_json: serde_json::Value = serde_json::from_str(&ext_stdout).unwrap();
    assert_eq!(ext_json["status"], "ok");
    assert_eq!(ext_json["command"], "extract");
    assert_eq!(
        fs::read(&extracted_path).unwrap(),
        b"Hidden PNG stego secret"
    );
}

#[test]
fn test_json_clip_operations() {
    let assert_copy = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "clip",
            "copy",
            "ephemeral_json_clip_test",
            "--ttl",
            "0",
            "--json",
        ])
        .assert()
        .success();

    let copy_stdout = String::from_utf8(assert_copy.get_output().stdout.clone()).unwrap();
    let copy_json: serde_json::Value = serde_json::from_str(&copy_stdout).unwrap();
    assert_eq!(copy_json["status"], "ok");
    assert_eq!(copy_json["command"], "clip copy");

    let assert_clear = Command::cargo_bin("svault")
        .unwrap()
        .args(["clip", "clear", "--json"])
        .assert()
        .success();

    let clear_stdout = String::from_utf8(assert_clear.get_output().stdout.clone()).unwrap();
    let clear_json: serde_json::Value = serde_json::from_str(&clear_stdout).unwrap();
    assert_eq!(clear_json["status"], "ok");
    assert_eq!(clear_json["command"], "clip clear");
}
