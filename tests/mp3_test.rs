// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Isolated domain integration test suite for MP3 ID3v2 & Audio Frame Stego Carrier (M21).
//!
//! Validates:
//! - ID3v2 PRIV frame steganography roundtrip & idempotency
//! - Inter-frame padding steganography roundtrip
//! - Transparent auto-detection mode across both embedding schemes
//! - Plausible deniability decoy container embedding in MP3
//! - Metadata preservation for existing ID3v2 tags (TIT2, TPE1)
//! - Tampered payload and corrupted CRC-32 carrier rejection
//! - Windows DPAPI hardware binding & time-lock expiration policies
//! - CLI `embed-mp3`, `extract-mp3`, `capacity` roundtrips & structured `--json` mode

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

/// Construct synthetic MPEG-1 Audio Layer III frames for test carriers.
fn make_synthetic_mp3_frames(num_frames: usize) -> Vec<u8> {
    // MPEG-1 Layer III, 128 kbps, 44100 Hz, Stereo, no padding
    // Frame size = (144 * 128000 / 44100) + 0 = 417 bytes
    let frame_len = 417;
    let mut out = Vec::with_capacity(num_frames * frame_len);
    for f in 0..num_frames {
        let mut frame = vec![0x55; frame_len];
        frame[0] = 0xFF;
        frame[1] = 0xFB; // MPEG-1, Layer III, no CRC
        frame[2] = 0x90; // 128 kbps, 44100 Hz, no padding
        frame[3] = 0x00; // Stereo
                         // Deterministic audio payload noise
        for (i, b) in frame[4..].iter_mut().enumerate() {
            *b = ((f * 31 + i * 17) % 251) as u8;
        }
        out.extend_from_slice(&frame);
    }
    out
}

/// Construct synthetic MP3 carrier with pre-existing ID3v2.3 tags (TIT2 and TPE1).
fn make_synthetic_mp3_with_tags(title: &str, artist: &str) -> Vec<u8> {
    let mut tag_body = Vec::new();

    // TIT2 frame (Title)
    tag_body.extend_from_slice(b"TIT2");
    let title_payload_len = 1 + title.len(); // 1 byte encoding (0x00 = ISO-8859-1) + str
    tag_body.extend_from_slice(&(title_payload_len as u32).to_be_bytes());
    tag_body.extend_from_slice(&[0x00, 0x00]); // flags
    tag_body.push(0x00); // encoding indicator
    tag_body.extend_from_slice(title.as_bytes());

    // TPE1 frame (Lead artist)
    tag_body.extend_from_slice(b"TPE1");
    let artist_payload_len = 1 + artist.len();
    tag_body.extend_from_slice(&(artist_payload_len as u32).to_be_bytes());
    tag_body.extend_from_slice(&[0x00, 0x00]);
    tag_body.push(0x00);
    tag_body.extend_from_slice(artist.as_bytes());

    // ID3v2.3 header (10 bytes)
    let mut out = Vec::new();
    out.extend_from_slice(b"ID3");
    out.push(3); // Major version 3
    out.push(0); // Revision 0
    out.push(0); // Flags
    let syncsafe_size = [
        ((tag_body.len() >> 21) & 0x7F) as u8,
        ((tag_body.len() >> 14) & 0x7F) as u8,
        ((tag_body.len() >> 7) & 0x7F) as u8,
        (tag_body.len() & 0x7F) as u8,
    ];
    out.extend_from_slice(&syncsafe_size);
    out.extend_from_slice(&tag_body);

    // Append 5 MPEG frames
    out.extend_from_slice(&make_synthetic_mp3_frames(5));
    out
}

#[test]
fn test_mp3_id3v2_priv_embed_and_extract_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("track.mp3");
    let secret_path = dir.path().join("secret.txt");
    let stego_path = dir.path().join("stego.mp3");
    let extracted_path = dir.path().join("extracted.txt");

    let mp3_data = make_synthetic_mp3_with_tags("Starlight Sonata", "Maestro Alex");
    fs::write(&carrier_path, &mp3_data).unwrap();
    fs::write(&secret_path, b"Classified cryptographic memo in ID3v2 tag!").unwrap();

    // Embed in ID3v2 mode
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "--carrier",
            carrier_path.to_str().unwrap(),
            "--secret",
            secret_path.to_str().unwrap(),
            "--output",
            stego_path.to_str().unwrap(),
            "--passphrase",
            "mp3_super_passphrase!2026",
            "--mode",
            "id3v2",
        ])
        .assert()
        .success();

    // Extract in ID3v2 mode
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "--carrier",
            stego_path.to_str().unwrap(),
            "--output",
            extracted_path.to_str().unwrap(),
            "--passphrase",
            "mp3_super_passphrase!2026",
            "--mode",
            "id3v2",
        ])
        .assert()
        .success();

    let recovered = fs::read(&extracted_path).unwrap();
    assert_eq!(recovered, b"Classified cryptographic memo in ID3v2 tag!");

    // Test idempotency: re-embedding over stego carrier replaces previous PRIV frame without bloating
    let stego_path_v2 = dir.path().join("stego_v2.mp3");
    fs::write(&secret_path, b"Updated memo replace test!").unwrap();
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "-c",
            stego_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path_v2.to_str().unwrap(),
            "-p",
            "mp3_super_passphrase!2026",
            "--mode",
            "id3v2",
        ])
        .assert()
        .success();

    let extracted_v2 = dir.path().join("extracted_v2.txt");
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            stego_path_v2.to_str().unwrap(),
            "-o",
            extracted_v2.to_str().unwrap(),
            "-p",
            "mp3_super_passphrase!2026",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(&extracted_v2).unwrap(),
        b"Updated memo replace test!"
    );
}

#[test]
fn test_mp3_frame_inter_frame_embed_and_extract_roundtrip() {
    let dir = tempdir().unwrap();
    let carrier_path = dir.path().join("raw_frames.mp3");
    let secret_path = dir.path().join("secret.bin");
    let stego_path = dir.path().join("frame_stego.mp3");
    let extracted_path = dir.path().join("frame_extracted.bin");

    // Pure audio frames without ID3 header
    let mp3_data = make_synthetic_mp3_frames(6);
    fs::write(&carrier_path, &mp3_data).unwrap();
    let raw_payload = vec![0x7A; 512];
    fs::write(&secret_path, &raw_payload).unwrap();

    // Embed in frame mode via --frame flag
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "-c",
            carrier_path.to_str().unwrap(),
            "-s",
            secret_path.to_str().unwrap(),
            "-o",
            stego_path.to_str().unwrap(),
            "-p",
            "frame_secret_pass!456",
            "--frame",
        ])
        .assert()
        .success();

    // Extract using explicit frame mode
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            stego_path.to_str().unwrap(),
            "-o",
            extracted_path.to_str().unwrap(),
            "-p",
            "frame_secret_pass!456",
            "--mode",
            "frame",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&extracted_path).unwrap(), raw_payload);
}

#[test]
fn test_mp3_auto_detection_mode() {
    let dir = tempdir().unwrap();

    // 1. Auto mode extracting from ID3v2
    let id3_carrier = dir.path().join("auto_id3.mp3");
    let id3_secret = dir.path().join("id3_secret.txt");
    let id3_stego = dir.path().join("auto_id3_stego.mp3");
    let id3_out = dir.path().join("auto_id3_out.txt");

    fs::write(
        &id3_carrier,
        make_synthetic_mp3_with_tags("Track A", "Band B"),
    )
    .unwrap();
    fs::write(&id3_secret, b"Auto test from ID3").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "-c",
            id3_carrier.to_str().unwrap(),
            "-s",
            id3_secret.to_str().unwrap(),
            "-o",
            id3_stego.to_str().unwrap(),
            "-p",
            "pass_auto",
            "--mode",
            "id3v2",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            id3_stego.to_str().unwrap(),
            "-o",
            id3_out.to_str().unwrap(),
            "-p",
            "pass_auto",
            "--mode",
            "auto",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&id3_out).unwrap(), b"Auto test from ID3");

    // 2. Auto mode extracting from audio frames
    let frame_carrier = dir.path().join("auto_frame.mp3");
    let frame_secret = dir.path().join("frame_secret.txt");
    let frame_stego = dir.path().join("auto_frame_stego.mp3");
    let frame_out = dir.path().join("auto_frame_out.txt");

    fs::write(&frame_carrier, make_synthetic_mp3_frames(4)).unwrap();
    fs::write(&frame_secret, b"Auto test from Frame").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "-c",
            frame_carrier.to_str().unwrap(),
            "-s",
            frame_secret.to_str().unwrap(),
            "-o",
            frame_stego.to_str().unwrap(),
            "-p",
            "pass_auto",
            "--frame",
        ])
        .assert()
        .success();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            frame_stego.to_str().unwrap(),
            "-o",
            frame_out.to_str().unwrap(),
            "-p",
            "pass_auto",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&frame_out).unwrap(), b"Auto test from Frame");
}

#[test]
fn test_mp3_decoy_passphrase_plausible_deniability() {
    let dir = tempdir().unwrap();
    let carrier = dir.path().join("decoy_carrier.mp3");
    let secret = dir.path().join("real_secret.txt");
    let decoy = dir.path().join("decoy_secret.txt");
    let stego = dir.path().join("decoy_stego.mp3");
    let out_real = dir.path().join("out_real.txt");
    let out_decoy = dir.path().join("out_decoy.txt");

    fs::write(
        &carrier,
        make_synthetic_mp3_with_tags("Decoy Track", "DJ Cover"),
    )
    .unwrap();
    fs::write(&secret, b"Confidential Nuclear Blueprints").unwrap();
    fs::write(&decoy, b"Harmless Grocery Shopping List").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "-c",
            carrier.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "-p",
            "primary_secret_key!999",
            "-d",
            decoy.to_str().unwrap(),
            "--decoy-passphrase",
            "duress_coerced_passphrase!111",
        ])
        .assert()
        .success();

    // Unlock with primary passphrase -> gets real secret
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            stego.to_str().unwrap(),
            "-o",
            out_real.to_str().unwrap(),
            "-p",
            "primary_secret_key!999",
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&out_real).unwrap(),
        b"Confidential Nuclear Blueprints"
    );

    // Unlock with decoy passphrase -> gets decoy secret
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            stego.to_str().unwrap(),
            "-o",
            out_decoy.to_str().unwrap(),
            "--decoy-passphrase",
            "duress_coerced_passphrase!111",
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&out_decoy).unwrap(),
        b"Harmless Grocery Shopping List"
    );
}

#[test]
fn test_mp3_metadata_preservation() {
    let dir = tempdir().unwrap();
    let carrier = dir.path().join("tagged.mp3");
    let secret = dir.path().join("doc.txt");
    let stego = dir.path().join("tagged_stego.mp3");

    let original_bytes = make_synthetic_mp3_with_tags("Elysium Beats", "Acoustic Mirage");
    fs::write(&carrier, &original_bytes).unwrap();
    fs::write(&secret, b"Protected Payload").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "-c",
            carrier.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "-p",
            "pass_tag_preserve",
        ])
        .assert()
        .success();

    let stego_bytes = fs::read(&stego).unwrap();

    // Verify existing ID3v2 tags remain intact inside stego container
    assert!(stego_bytes.windows(4).any(|w| w == b"TIT2"));
    assert!(stego_bytes.windows(4).any(|w| w == b"TPE1"));
    assert!(stego_bytes.windows(13).any(|w| w == b"Elysium Beats"));
    assert!(stego_bytes.windows(15).any(|w| w == b"Acoustic Mirage"));
    assert!(stego_bytes.windows(4).any(|w| w == b"PRIV"));
    assert!(stego_bytes.windows(11).any(|w| w == b"ShadowVault"));
}

#[test]
fn test_mp3_tampered_crc32_and_corruption_detection() {
    let dir = tempdir().unwrap();
    let carrier = dir.path().join("valid.mp3");
    let secret = dir.path().join("secret.txt");
    let stego = dir.path().join("stego.mp3");
    let out = dir.path().join("out.txt");

    fs::write(
        &carrier,
        make_synthetic_mp3_with_tags("Clean Song", "Clean Artist"),
    )
    .unwrap();
    fs::write(&secret, b"Tamper Resistance Test Payload").unwrap();

    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "-c",
            carrier.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "-p",
            "pass_tamper_test",
        ])
        .assert()
        .success();

    // Intentionally mutate byte inside PRIV payload
    let mut stego_bytes = fs::read(&stego).unwrap();
    // Locate `ShadowVault\0` and flip byte in payload area
    if let Some(pos) = stego_bytes.windows(11).position(|w| w == b"ShadowVault") {
        let mutate_pos = pos + 25; // Inside encrypted payload
        if mutate_pos < stego_bytes.len() {
            stego_bytes[mutate_pos] ^= 0xFF;
        }
    }
    fs::write(&stego, &stego_bytes).unwrap();

    // Extraction must fail due to CRC-32 mismatch or cryptographic authentication failure
    let assert_res = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            stego.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "pass_tamper_test",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert_res.get_output().stderr);
    assert!(stderr.contains("CRC-32 mismatch") || stderr.contains("authentication failed"));
}

#[test]
fn test_cli_embed_extract_capacity_roundtrip_and_json() {
    let dir = tempdir().unwrap();
    let carrier = dir.path().join("cli_test.mp3");
    let secret = dir.path().join("cli_secret.txt");
    let stego = dir.path().join("cli_stego.mp3");
    let out = dir.path().join("cli_out.txt");

    fs::write(
        &carrier,
        make_synthetic_mp3_with_tags("Symphony 9", "Beethoven"),
    )
    .unwrap();
    fs::write(&secret, b"CLI and JSON Verification Payload").unwrap();

    // 1. Capacity inspection in JSON mode
    let cap_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args(["capacity", carrier.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let cap_stdout = String::from_utf8(cap_cmd.get_output().stdout.clone()).unwrap();
    let cap_json: serde_json::Value = serde_json::from_str(&cap_stdout).unwrap();
    assert_eq!(cap_json["carrier_type"], "mp3");
    assert_eq!(cap_json["mpeg_version"], "MPEG-1");
    assert_eq!(cap_json["layer"], "Layer III");
    assert_eq!(cap_json["id3v2_present"], true);

    // 2. Embed with --json
    let embed_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "-c",
            carrier.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "-p",
            "json_cli_pass!888",
            "--json",
        ])
        .assert()
        .success();

    let embed_stdout = String::from_utf8(embed_cmd.get_output().stdout.clone()).unwrap();
    let embed_json: serde_json::Value = serde_json::from_str(&embed_stdout).unwrap();
    assert_eq!(embed_json["status"], "ok");
    assert_eq!(embed_json["command"], "embed-mp3");
    assert_eq!(embed_json["carrier_type"], "mp3");

    // 3. Extract with --json
    let extract_cmd = Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            stego.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "json_cli_pass!888",
            "--json",
        ])
        .assert()
        .success();

    let extract_stdout = String::from_utf8(extract_cmd.get_output().stdout.clone()).unwrap();
    let extract_json: serde_json::Value = serde_json::from_str(&extract_stdout).unwrap();
    assert_eq!(extract_json["status"], "ok");
    assert_eq!(extract_json["command"], "extract-mp3");
    assert_eq!(extract_json["carrier_type"], "mp3");

    assert_eq!(
        fs::read(&out).unwrap(),
        b"CLI and JSON Verification Payload"
    );
}

#[test]
fn test_mp3_dpapi_and_policy_timelock() {
    let dir = tempdir().unwrap();
    let carrier = dir.path().join("policy_carrier.mp3");
    let secret = dir.path().join("policy_secret.txt");
    let stego = dir.path().join("policy_stego.mp3");
    let out = dir.path().join("policy_out.txt");

    fs::write(
        &carrier,
        make_synthetic_mp3_with_tags("TimeLock Aria", "Chrono"),
    )
    .unwrap();
    fs::write(&secret, b"Time-Locked Top Secret Audio Data").unwrap();

    // Embed with DPAPI and time-lock policy: active only after 2026-01-01 and expires 2026-12-31
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "embed-mp3",
            "-c",
            carrier.to_str().unwrap(),
            "-s",
            secret.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "-p",
            "policy_pass_2026",
            "--dpapi",
            "--not-before",
            "2026-01-01T00:00:00Z",
            "--expires-at",
            "2026-12-31T23:59:59Z",
            "--policy-desc",
            "Operational window for 2026",
        ])
        .assert()
        .success();

    // Decrypting before not_before should fail
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            stego.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "policy_pass_2026",
            "--at-time",
            "2025-12-31T23:59:59Z",
        ])
        .assert()
        .failure();

    // Decrypting within valid window (e.g. 2026-06-01) should succeed
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            stego.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "policy_pass_2026",
            "--at-time",
            "2026-06-01T12:00:00Z",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(&out).unwrap(),
        b"Time-Locked Top Secret Audio Data"
    );

    // Decrypting after expires_at should fail
    Command::cargo_bin("svault")
        .unwrap()
        .args([
            "extract-mp3",
            "-c",
            stego.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-p",
            "policy_pass_2026",
            "--at-time",
            "2027-01-01T00:00:00Z",
        ])
        .assert()
        .failure();
}
