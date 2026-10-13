// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for Milestone M18: Container Re-Key & Passphrase Rotation (`src/rotate.rs`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn svault() -> Command {
    Command::cargo_bin("svault").expect("svault binary exists")
}

fn sv(args: &[&str]) -> assert_cmd::assert::Assert {
    svault().args(args).assert()
}

fn create_test_png() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x06, 0x00, 0x00, 0x00, 0x72,
        0xB6, 0x0D, 0x24, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ]
}

fn create_test_bmp(w: u32, h: u32) -> Vec<u8> {
    let row_stride = (w as usize * 3 + 3) & !3;
    let data_len = row_stride * h as usize;
    let mut b = Vec::with_capacity(54 + data_len);
    b.extend_from_slice(b"BM");
    b.extend_from_slice(&((54 + data_len) as u32).to_le_bytes());
    b.extend_from_slice(&[0u8; 4]);
    b.extend_from_slice(&54u32.to_le_bytes());
    b.extend_from_slice(&40u32.to_le_bytes());
    b.extend_from_slice(&(w as i32).to_le_bytes());
    b.extend_from_slice(&(h as i32).to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&24u16.to_le_bytes());
    b.extend_from_slice(&[0u8; 24]);
    b.resize(54 + data_len, 0x80);
    b
}

fn create_test_wav(samples: usize) -> Vec<u8> {
    let data_len = samples * 2;
    let mut w = Vec::with_capacity(44 + data_len);
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&((36 + data_len) as u32).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&44100u32.to_le_bytes());
    w.extend_from_slice(&88200u32.to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&(data_len as u32).to_le_bytes());
    w.resize(44 + data_len, 0x55);
    w
}

#[test]
fn test_rotate_standard_container_roundtrip() {
    let dir = tempdir().unwrap();
    let (sec, vlt, rot, res) = (
        dir.path().join("s.txt"),
        dir.path().join("v.svault"),
        dir.path().join("r.svault"),
        dir.path().join("res.txt"),
    );
    let (s, v, r, out) = (
        sec.to_str().unwrap(),
        vlt.to_str().unwrap(),
        rot.to_str().unwrap(),
        res.to_str().unwrap(),
    );
    fs::write(&sec, b"rotatable-high-value-payload").unwrap();

    sv(&["encrypt", "-i", s, "-o", v, "-p", "k1"]).success();
    sv(&["rotate", "-i", v, "-o", r, "-p", "k1", "-n", "k2"])
        .success()
        .stdout(predicate::str::contains("rotated"));

    // Old passphrase fails; new succeeds
    sv(&["decrypt", "-i", r, "-o", out, "-p", "k1"]).failure();
    sv(&["decrypt", "-i", r, "-o", out, "-p", "k2"]).success();
    assert_eq!(fs::read(&res).unwrap(), b"rotatable-high-value-payload");
}

#[test]
fn test_rotate_in_place_atomic() {
    let dir = tempdir().unwrap();
    let (sec, vlt, res) = (
        dir.path().join("s.txt"),
        dir.path().join("v.svault"),
        dir.path().join("res.txt"),
    );
    let (s, v, out) = (
        sec.to_str().unwrap(),
        vlt.to_str().unwrap(),
        res.to_str().unwrap(),
    );
    fs::write(&sec, b"in-place-atomic-rekey-content").unwrap();

    sv(&["encrypt", "-i", s, "-o", v, "-p", "old-pass"]).success();
    sv(&[
        "rotate",
        "-i",
        v,
        "--in-place",
        "-p",
        "old-pass",
        "-n",
        "new-pass",
    ])
    .success();

    sv(&["decrypt", "-i", v, "-o", out, "-p", "old-pass"]).failure();
    sv(&["decrypt", "-i", v, "-o", out, "-p", "new-pass"]).success();
    assert_eq!(fs::read(&res).unwrap(), b"in-place-atomic-rekey-content");
}

#[test]
fn test_rotate_wrong_old_passphrase_fails() {
    let dir = tempdir().unwrap();
    let (sec, vlt, rot) = (
        dir.path().join("s.txt"),
        dir.path().join("v.svault"),
        dir.path().join("no.svault"),
    );
    let (s, v, r) = (
        sec.to_str().unwrap(),
        vlt.to_str().unwrap(),
        rot.to_str().unwrap(),
    );
    fs::write(&sec, b"correct-content").unwrap();

    sv(&["encrypt", "-i", s, "-o", v, "-p", "old-key"]).success();
    sv(&["rotate", "-i", v, "-o", r, "-p", "wrong", "-n", "new"]).failure();
    assert!(!rot.exists());
}

#[test]
fn test_rotate_stego_png_carrier() {
    let dir = tempdir().unwrap();
    let (car, sec, stego, rot, res) = (
        dir.path().join("c.png"),
        dir.path().join("s.txt"),
        dir.path().join("st.png"),
        dir.path().join("rt.png"),
        dir.path().join("res.txt"),
    );
    let (c, s, st, rt, out) = (
        car.to_str().unwrap(),
        sec.to_str().unwrap(),
        stego.to_str().unwrap(),
        rot.to_str().unwrap(),
        res.to_str().unwrap(),
    );
    fs::write(&car, create_test_png()).unwrap();
    fs::write(&sec, b"png-stego-rekey-secret").unwrap();

    sv(&["embed", "-s", s, "-c", c, "-o", st, "-p", "p1"]).success();
    sv(&["rotate", "-i", st, "-o", rt, "-p", "p1", "-n", "p2"])
        .success()
        .stdout(predicate::str::contains("png"));

    sv(&["extract", "-c", rt, "-o", out, "-p", "p1"]).failure();
    sv(&["extract", "-c", rt, "-o", out, "-p", "p2"]).success();
    assert_eq!(fs::read(&res).unwrap(), b"png-stego-rekey-secret");
}

#[test]
fn test_rotate_stego_bmp_and_wav_carriers() {
    let dir = tempdir().unwrap();
    let sec = dir.path().join("s.txt");
    let s = sec.to_str().unwrap();
    fs::write(&sec, b"audio-visual-multicarrier-secret").unwrap();

    // BMP carrier in-place
    let (bmp_car, bmp_st, bmp_res) = (
        dir.path().join("c.bmp"),
        dir.path().join("st.bmp"),
        dir.path().join("rb.txt"),
    );
    let (bc, bst, bres) = (
        bmp_car.to_str().unwrap(),
        bmp_st.to_str().unwrap(),
        bmp_res.to_str().unwrap(),
    );
    fs::write(&bmp_car, create_test_bmp(32, 32)).unwrap();
    sv(&["embed-bmp", "-s", s, "-c", bc, "-o", bst, "-p", "bp1"]).success();
    sv(&["rotate", "-i", bst, "--in-place", "-p", "bp1", "-n", "bp2"])
        .success()
        .stdout(predicate::str::contains("bmp"));
    sv(&["extract-bmp", "-c", bst, "-o", bres, "-p", "bp2"]).success();
    assert_eq!(
        fs::read(&bmp_res).unwrap(),
        b"audio-visual-multicarrier-secret"
    );

    // WAV carrier in-place
    let (wav_car, wav_st, wav_res) = (
        dir.path().join("c.wav"),
        dir.path().join("st.wav"),
        dir.path().join("rw.txt"),
    );
    let (wc, wst, wres) = (
        wav_car.to_str().unwrap(),
        wav_st.to_str().unwrap(),
        wav_res.to_str().unwrap(),
    );
    fs::write(&wav_car, create_test_wav(1000)).unwrap();
    sv(&["embed-wav", "-s", s, "-c", wc, "-o", wst, "-p", "wp1"]).success();
    sv(&["rotate", "-i", wst, "--in-place", "-p", "wp1", "-n", "wp2"])
        .success()
        .stdout(predicate::str::contains("wav"));
    sv(&["extract-wav", "-c", wst, "-o", wres, "-p", "wp2"]).success();
    assert_eq!(
        fs::read(&wav_res).unwrap(),
        b"audio-visual-multicarrier-secret"
    );
}

#[test]
fn test_rotate_ascii_armor() {
    let dir = tempdir().unwrap();
    let (sec, vlt, asc, rot_asc, res) = (
        dir.path().join("s.txt"),
        dir.path().join("v.svault"),
        dir.path().join("v.asc"),
        dir.path().join("r.asc"),
        dir.path().join("res.txt"),
    );
    let (s, v, a, ra, out) = (
        sec.to_str().unwrap(),
        vlt.to_str().unwrap(),
        asc.to_str().unwrap(),
        rot_asc.to_str().unwrap(),
        res.to_str().unwrap(),
    );
    fs::write(&sec, b"armored-ascii-secret-text").unwrap();

    sv(&["encrypt", "-i", s, "-o", v, "-p", "ap1"]).success();
    sv(&["armor", "-i", v, "-o", a]).success();
    sv(&["rotate", "-i", a, "-o", ra, "-p", "ap1", "-n", "ap2"])
        .success()
        .stdout(predicate::str::contains("armor"));

    let content = fs::read_to_string(&rot_asc).unwrap();
    assert!(content.contains("-----BEGIN SHADOW VAULT ARMORED FILE-----"));

    sv(&["decrypt", "-i", ra, "-o", out, "-p", "ap2"]).success();
    assert_eq!(fs::read(&res).unwrap(), b"armored-ascii-secret-text");
}

#[test]
fn test_rotate_policy_timelock_preservation_and_clear() {
    let dir = tempdir().unwrap();
    let (sec, lck, rot, clr, res) = (
        dir.path().join("s.txt"),
        dir.path().join("lck.svault"),
        dir.path().join("rot.svault"),
        dir.path().join("clr.svault"),
        dir.path().join("res.txt"),
    );
    let (s, l, r, c, out) = (
        sec.to_str().unwrap(),
        lck.to_str().unwrap(),
        rot.to_str().unwrap(),
        clr.to_str().unwrap(),
        res.to_str().unwrap(),
    );
    fs::write(&sec, b"escrow-timelocked-payload").unwrap();

    sv(&[
        "encrypt",
        "-i",
        s,
        "-o",
        l,
        "-p",
        "ep1",
        "--not-before",
        "+24h",
        "--policy-desc",
        "Escrow 2026",
    ])
    .success();

    // Rotate preserving time-lock
    sv(&["rotate", "-i", l, "-o", r, "-p", "ep1", "-n", "ep2"])
        .success()
        .stdout(predicate::str::contains("policy_preserved: true"));

    sv(&["inspect", r])
        .success()
        .stdout(predicate::str::contains("TIME-LOCKED"))
        .stdout(predicate::str::contains("Escrow 2026"));

    // Current time decryption fails due to time-lock
    sv(&["decrypt", "-i", r, "-o", out, "-p", "ep2"])
        .failure()
        .stderr(predicate::str::contains("time-locked"));

    // Rotate with --clear-policy removes time-lock
    sv(&[
        "rotate",
        "-i",
        r,
        "-o",
        c,
        "-p",
        "ep2",
        "-n",
        "ep3",
        "--clear-policy",
    ])
    .success()
    .stdout(predicate::str::contains("policy_cleared: true"));

    sv(&["decrypt", "-i", c, "-o", out, "-p", "ep3"]).success();
    assert_eq!(fs::read(&res).unwrap(), b"escrow-timelocked-payload");
}

#[test]
fn test_rotate_dpapi_toggle_and_json_output() {
    let dir = tempdir().unwrap();
    let (sec, pln, dp, nodp) = (
        dir.path().join("s.txt"),
        dir.path().join("p.svault"),
        dir.path().join("dp.svault"),
        dir.path().join("nodp.svault"),
    );
    let (s, p, d, nd) = (
        sec.to_str().unwrap(),
        pln.to_str().unwrap(),
        dp.to_str().unwrap(),
        nodp.to_str().unwrap(),
    );
    fs::write(&sec, b"dpapi-rotation-validation").unwrap();

    sv(&["encrypt", "-i", s, "-o", p, "-p", "p1"]).success();

    // Rotate with --dpapi and JSON output
    let out1 = sv(&[
        "rotate", "-i", p, "-o", d, "-p", "p1", "-n", "p2", "--dpapi", "--json",
    ])
    .success()
    .get_output()
    .stdout
    .clone();

    let v1: serde_json::Value = serde_json::from_str(&String::from_utf8(out1).unwrap()).unwrap();
    assert_eq!(v1["status"], "ok");
    assert_eq!(v1["command"], "rotate");
    assert_eq!(v1["old_dpapi_bound"], false);
    assert_eq!(v1["new_dpapi_bound"], true);
    assert_eq!(v1["new_salt_hex"].as_str().unwrap().len(), 32);

    // Rotate with --no-dpapi
    let out2 = sv(&[
        "rotate",
        "-i",
        d,
        "-o",
        nd,
        "-p",
        "p2",
        "-n",
        "p3",
        "--no-dpapi",
        "--json",
    ])
    .success()
    .get_output()
    .stdout
    .clone();

    let v2: serde_json::Value = serde_json::from_str(&String::from_utf8(out2).unwrap()).unwrap();
    assert_eq!(v2["old_dpapi_bound"], true);
    assert_eq!(v2["new_dpapi_bound"], false);
}
