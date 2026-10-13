// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Detached Integrity Manifest & Canary Verification Engine (`src/canary.rs`).
//!
//! Provides cryptographic tamper canary tracking for `.svault` containers and stego carriers:
//! - Detached manifest generation (`svault canary init`) and verification (`svault canary verify`)
//! - Multi-carrier format auto-detection (`svault`, `stream`, `archive`, `png_stego`, `bmp_stego`, `wav_stego`, `armor_asc`, `shamir_share`)
//! - Argon2id + HMAC-SHA256 authenticated tamper canaries with optional passphrase & keyfile 2FA
//! - Constant-time signature verification preventing timing analysis attacks
//! - Detection of modified files (bit rot/tampering), missing files (deletion), and untracked files
//! - Machine-readable JSON output and human-crafted terminal status reports

use crate::error::{Error, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const CANARY_MANIFEST_VERSION: u32 = 1;
pub const DEFAULT_CANARY_FILENAME: &str = ".svault-canary.json";

/// Header metadata for a detached integrity canary manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryHeader {
    pub version: u32,
    pub canary_id: String,
    pub created_at_utc: u64,
    pub created_at_iso: String,
    pub auth_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    pub signature: String,
}

/// Metadata entry tracking an individual file within the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryEntry {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub carrier: String,
    pub modified_utc: u64,
}

/// Detached canary manifest on-disk serialization structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryManifest {
    pub header: CanaryHeader,
    pub files: Vec<CanaryEntry>,
}

/// Verification status for an individual file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileIntegrityStatus {
    Intact,
    Modified,
    Missing,
    Untracked,
}

/// Detailed verification result record for a tracked or untracked file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileVerificationRecord {
    pub path: String,
    pub status: FileIntegrityStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Structured summary report returned by `init_canary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryInitReport {
    pub status: String,
    pub manifest_path: String,
    pub canary_id: String,
    pub created_at_iso: String,
    pub auth_mode: String,
    pub total_tracked: usize,
    pub root_dir: String,
    pub files: Vec<CanaryEntry>,
}

/// Structured summary report returned by `verify_canary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryVerifyReport {
    pub status: String,
    pub is_clean: bool,
    pub manifest_path: String,
    pub canary_id: String,
    pub created_at_iso: String,
    pub auth_mode: String,
    pub signature_valid: bool,
    pub total_tracked: usize,
    pub intact_count: usize,
    pub modified_count: usize,
    pub missing_count: usize,
    pub untracked_count: usize,
    pub records: Vec<FileVerificationRecord>,
}

/// Encode bytes into lowercase hexadecimal string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Decode a hexadecimal string into raw bytes.
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let trimmed = hex.trim();
    if trimmed.len() % 2 != 0 {
        return None;
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16).ok())
        .collect()
}

/// Compute SHA-256 digest and file length in bytes using streaming 64 KiB buffer.
pub fn compute_file_sha256(path: &Path) -> Result<(String, u64)> {
    let mut file = fs::File::open(path).map_err(Error::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let n = file.read(&mut buffer).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total_bytes += n as u64;
    }

    Ok((hex_encode(&hasher.finalize()), total_bytes))
}

/// Detect steganographic or container carrier format from file magic and inspection.
pub fn detect_carrier_format(path: &Path) -> Result<String> {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok("file".into()),
    };
    let mut header = [0u8; 512];
    let n = file.read(&mut header).map_err(Error::Io)?;
    let prefix = &header[..n];

    if prefix.starts_with(b"SVLT") {
        Ok("svault".into())
    } else if prefix.starts_with(b"SVST") {
        Ok("stream".into())
    } else if prefix.starts_with(b"SVAR") {
        Ok("archive".into())
    } else if crate::armor::is_armored(prefix) {
        Ok("armor_asc".into())
    } else if prefix.starts_with(b"\x89PNG\r\n\x1a\n") {
        if let Ok(bytes) = fs::read(path) {
            if bytes.windows(4).any(|w| w == b"svLt") {
                return Ok("png_stego".into());
            }
        }
        Ok("png".into())
    } else if prefix.starts_with(b"BM") {
        if let Ok(bytes) = fs::read(path) {
            if crate::bmp::extract_from_bmp(&bytes).is_ok() {
                return Ok("bmp_stego".into());
            }
        }
        Ok("bmp".into())
    } else if prefix.len() >= 12 && &prefix[0..4] == b"RIFF" && &prefix[8..12] == b"WAVE" {
        if let Ok(bytes) = fs::read(path) {
            if crate::wav::extract_from_wav(&bytes, crate::wav::ExtractWavMode::Auto).is_ok() {
                return Ok("wav_stego".into());
            }
        }
        Ok("wav".into())
    } else if prefix.starts_with(b"-----BEGIN SHADOW VAULT SHARE-----")
        || prefix.starts_with(b"SVLT-S1-")
    {
        Ok("shamir_share".into())
    } else {
        match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
            "svault" => Ok("svault".into()),
            "png" => Ok("png".into()),
            "bmp" => Ok("bmp".into()),
            "wav" => Ok("wav".into()),
            "asc" => Ok("armor_asc".into()),
            "share" => Ok("shamir_share".into()),
            _ => Ok("file".into()),
        }
    }
}

/// Generate canonical representation of canary entries for deterministic signing.
fn canonical_manifest_string(
    canary_id: &str,
    created_at_utc: u64,
    auth_mode: &str,
    files: &[CanaryEntry],
) -> String {
    let mut canonical = format!("canary-v1:{}:{}:{}:", canary_id, created_at_utc, auth_mode);
    for f in files {
        canonical.push_str(&format!(
            "path={};size={};sha256={};carrier={};modified={}\n",
            f.path, f.size_bytes, f.sha256, f.carrier, f.modified_utc
        ));
    }
    canonical
}

/// Test whether a path is a candidate for canary tracking.
fn is_candidate_file(path: &Path, manifest_target: Option<&Path>, include_all: bool) -> bool {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if file_name.starts_with(".svault-canary")
        || file_name == "canary.json"
        || file_name.ends_with(".tmp")
    {
        return false;
    }
    if let Some(target) = manifest_target {
        if path == target {
            return false;
        }
        if let (Ok(p_canon), Ok(t_canon)) = (path.canonicalize(), target.canonicalize()) {
            if p_canon == t_canon {
                return false;
            }
        }
    }
    if include_all {
        return true;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "svault" | "png" | "bmp" | "wav" | "asc" | "share" => true,
        _ => {
            if let Ok(mut f) = fs::File::open(path) {
                let mut magic = [0u8; 16];
                if let Ok(n) = f.read(&mut magic) {
                    let pre = &magic[..n];
                    pre.starts_with(b"SVLT")
                        || pre.starts_with(b"SVST")
                        || pre.starts_with(b"SVAR")
                        || pre.starts_with(b"-----BEGIN SHADOW VAULT")
                } else {
                    false
                }
            } else {
                false
            }
        }
    }
}

/// Recursively collect candidate files within directory tree.
fn collect_files_recursive(
    current: &Path,
    manifest_target: Option<&Path>,
    include_all: bool,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    if !current.exists() {
        return Ok(());
    }
    if current.is_file() {
        if is_candidate_file(current, manifest_target, include_all) {
            out.push(current.to_path_buf());
        }
        return Ok(());
    }
    let entries = fs::read_dir(current).map_err(Error::Io)?;
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name == ".git"
            || file_name == "target"
            || file_name == "node_modules"
            || file_name == ".cargo"
        {
            continue;
        }
        if path.is_dir() {
            collect_files_recursive(&path, manifest_target, include_all, out)?;
        } else if is_candidate_file(&path, manifest_target, include_all) {
            out.push(path);
        }
    }
    Ok(())
}

/// Initialize a detached canary integrity manifest for target directory or file.
pub fn init_canary(
    dir: &Path,
    output_manifest: Option<&Path>,
    passphrase: Option<&str>,
    keyfile: Option<&Path>,
    include_all: bool,
) -> Result<CanaryInitReport> {
    if !dir.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("target path does not exist: {}", dir.display()),
        )));
    }

    let manifest_path = output_manifest.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        if dir.is_dir() {
            dir.join(DEFAULT_CANARY_FILENAME)
        } else {
            let mut p = dir.to_path_buf();
            p.set_extension("canary.json");
            p
        }
    });

    let mut candidate_files = Vec::new();
    collect_files_recursive(dir, Some(&manifest_path), include_all, &mut candidate_files)?;

    let mut entries = Vec::with_capacity(candidate_files.len());
    for file in candidate_files {
        let rel_path = if dir.is_dir() {
            file.strip_prefix(dir).unwrap_or(&file)
        } else {
            file.file_name().map(Path::new).unwrap_or(&file)
        };

        let rel_str = rel_path
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");

        let (sha256_hex, size_bytes) = compute_file_sha256(&file)?;
        let carrier = detect_carrier_format(&file)?;
        let modified_utc = file
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        entries.push(CanaryEntry {
            path: rel_str,
            size_bytes,
            sha256: sha256_hex,
            carrier,
            modified_utc,
        });
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let mut canary_id_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut canary_id_bytes);
    let canary_id = hex_encode(&canary_id_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let created_at_iso = crate::policy::format_iso8601_utc(now);

    let (auth_mode, salt, signature) = if passphrase.is_some() || keyfile.is_some() {
        let mut salt_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        let key_mat = crate::crypto::resolve_key_material(passphrase, keyfile)?;
        let derived_key = crate::crypto::derive_key(&key_mat, &salt_bytes)?;
        let canonical = canonical_manifest_string(&canary_id, now, "hmac-sha256", &entries);
        let hmac_bytes = crate::totp::hmac(
            crate::totp::HashAlgorithm::Sha256,
            &*derived_key,
            canonical.as_bytes(),
        );
        (
            "hmac-sha256".to_string(),
            Some(hex_encode(&salt_bytes)),
            hex_encode(&hmac_bytes),
        )
    } else {
        let canonical = canonical_manifest_string(&canary_id, now, "sha256", &entries);
        let mut hasher = Sha256::new();
        hasher.update(b"shadow-vault:canary:unauthenticated:");
        hasher.update(canonical.as_bytes());
        ("sha256".to_string(), None, hex_encode(&hasher.finalize()))
    };

    let manifest = CanaryManifest {
        header: CanaryHeader {
            version: CANARY_MANIFEST_VERSION,
            canary_id: canary_id.clone(),
            created_at_utc: now,
            created_at_iso: created_at_iso.clone(),
            auth_mode: auth_mode.clone(),
            salt,
            signature,
        },
        files: entries.clone(),
    };

    let json_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| Error::Format(e.to_string()))?;
    fs::write(&manifest_path, json_bytes).map_err(Error::Io)?;

    Ok(CanaryInitReport {
        status: "ok".into(),
        manifest_path: manifest_path.display().to_string(),
        canary_id,
        created_at_iso,
        auth_mode,
        total_tracked: entries.len(),
        root_dir: dir.display().to_string(),
        files: entries,
    })
}

/// Verify on-disk files against a detached canary manifest.
pub fn verify_canary(
    dir: &Path,
    manifest_path: Option<&Path>,
    passphrase: Option<&str>,
    keyfile: Option<&Path>,
    strict: bool,
) -> Result<CanaryVerifyReport> {
    if !dir.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("target path does not exist: {}", dir.display()),
        )));
    }

    let resolved_manifest = match manifest_path {
        Some(p) => p.to_path_buf(),
        None => {
            let primary = dir.join(DEFAULT_CANARY_FILENAME);
            if primary.exists() {
                primary
            } else {
                let fallback = dir.join("canary.json");
                if fallback.exists() {
                    fallback
                } else {
                    return Err(Error::Canary(format!(
                        "canary manifest not found in directory: {}",
                        dir.display()
                    )));
                }
            }
        }
    };

    let manifest_bytes = fs::read(&resolved_manifest).map_err(Error::Io)?;
    let manifest: CanaryManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| Error::Canary(format!("malformed canary manifest JSON: {e}")))?;

    if manifest.header.version != CANARY_MANIFEST_VERSION {
        return Err(Error::Canary(format!(
            "unsupported canary manifest version: {} (supported: {})",
            manifest.header.version, CANARY_MANIFEST_VERSION
        )));
    }

    let signature_valid = match manifest.header.auth_mode.as_str() {
        "hmac-sha256" => {
            if passphrase.is_none() && keyfile.is_none() {
                false
            } else {
                let salt_hex = manifest.header.salt.as_deref().unwrap_or_default();
                let salt_bytes = hex_decode(salt_hex).unwrap_or_default();
                if let Ok(key_mat) = crate::crypto::resolve_key_material(passphrase, keyfile) {
                    if let Ok(derived_key) = crate::crypto::derive_key(&key_mat, &salt_bytes) {
                        let canonical = canonical_manifest_string(
                            &manifest.header.canary_id,
                            manifest.header.created_at_utc,
                            &manifest.header.auth_mode,
                            &manifest.files,
                        );
                        let expected_hmac = crate::totp::hmac(
                            crate::totp::HashAlgorithm::Sha256,
                            &*derived_key,
                            canonical.as_bytes(),
                        );
                        let declared_sig =
                            hex_decode(&manifest.header.signature).unwrap_or_default();
                        crate::shamir::constant_time_eq(&declared_sig, &expected_hmac)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
        "sha256" => {
            let canonical = canonical_manifest_string(
                &manifest.header.canary_id,
                manifest.header.created_at_utc,
                &manifest.header.auth_mode,
                &manifest.files,
            );
            let mut hasher = Sha256::new();
            hasher.update(b"shadow-vault:canary:unauthenticated:");
            hasher.update(canonical.as_bytes());
            let expected_digest = hasher.finalize();
            let declared_sig = hex_decode(&manifest.header.signature).unwrap_or_default();
            crate::shamir::constant_time_eq(&declared_sig, &expected_digest)
        }
        _ => false,
    };

    let mut records = Vec::new();
    let mut intact_count = 0usize;
    let mut modified_count = 0usize;
    let mut missing_count = 0usize;

    for entry in &manifest.files {
        let file_path = if dir.is_dir() {
            dir.join(Path::new(&entry.path))
        } else {
            dir.to_path_buf()
        };

        if !file_path.exists() {
            missing_count += 1;
            records.push(FileVerificationRecord {
                path: entry.path.clone(),
                status: FileIntegrityStatus::Missing,
                expected_size: Some(entry.size_bytes),
                actual_size: None,
                expected_sha256: Some(entry.sha256.clone()),
                actual_sha256: None,
                carrier: Some(entry.carrier.clone()),
                message: Some("file missing from disk".into()),
            });
            continue;
        }

        match compute_file_sha256(&file_path) {
            Ok((actual_sha, actual_size)) => {
                if actual_size != entry.size_bytes || actual_sha != entry.sha256 {
                    modified_count += 1;
                    records.push(FileVerificationRecord {
                        path: entry.path.clone(),
                        status: FileIntegrityStatus::Modified,
                        expected_size: Some(entry.size_bytes),
                        actual_size: Some(actual_size),
                        expected_sha256: Some(entry.sha256.clone()),
                        actual_sha256: Some(actual_sha),
                        carrier: Some(entry.carrier.clone()),
                        message: Some(if actual_size != entry.size_bytes {
                            format!(
                                "size mismatch: expected {} bytes, got {}",
                                entry.size_bytes, actual_size
                            )
                        } else {
                            "SHA-256 digest mismatch (payload altered)".into()
                        }),
                    });
                } else {
                    intact_count += 1;
                    records.push(FileVerificationRecord {
                        path: entry.path.clone(),
                        status: FileIntegrityStatus::Intact,
                        expected_size: Some(entry.size_bytes),
                        actual_size: Some(actual_size),
                        expected_sha256: Some(entry.sha256.clone()),
                        actual_sha256: Some(actual_sha),
                        carrier: Some(entry.carrier.clone()),
                        message: None,
                    });
                }
            }
            Err(e) => {
                modified_count += 1;
                records.push(FileVerificationRecord {
                    path: entry.path.clone(),
                    status: FileIntegrityStatus::Modified,
                    expected_size: Some(entry.size_bytes),
                    actual_size: None,
                    expected_sha256: Some(entry.sha256.clone()),
                    actual_sha256: None,
                    carrier: Some(entry.carrier.clone()),
                    message: Some(format!("failed to read file: {e}")),
                });
            }
        }
    }

    let mut untracked_count = 0usize;
    if dir.is_dir() {
        let mut disk_files = Vec::new();
        collect_files_recursive(dir, Some(&resolved_manifest), true, &mut disk_files)?;
        for file in disk_files {
            let rel_path = file.strip_prefix(dir).unwrap_or(&file);
            let rel_str = rel_path
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            if !manifest.files.iter().any(|e| e.path == rel_str) {
                untracked_count += 1;
                records.push(FileVerificationRecord {
                    path: rel_str,
                    status: FileIntegrityStatus::Untracked,
                    expected_size: None,
                    actual_size: file.metadata().map(|m| m.len()).ok(),
                    expected_sha256: None,
                    actual_sha256: None,
                    carrier: detect_carrier_format(&file).ok(),
                    message: Some("untracked file found in target directory".into()),
                });
            }
        }
    }

    let is_clean = signature_valid
        && modified_count == 0
        && missing_count == 0
        && (!strict || untracked_count == 0);

    Ok(CanaryVerifyReport {
        status: if is_clean {
            "ok".into()
        } else {
            "compromised".into()
        },
        is_clean,
        manifest_path: resolved_manifest.display().to_string(),
        canary_id: manifest.header.canary_id,
        created_at_iso: manifest.header.created_at_iso,
        auth_mode: manifest.header.auth_mode,
        signature_valid,
        total_tracked: manifest.files.len(),
        intact_count,
        modified_count,
        missing_count,
        untracked_count,
        records,
    })
}
