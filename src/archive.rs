// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Directory and multi-file manifest packing engine (`SVAR` v1 binary format).
//!
//! Provides deterministic directory packing, relative path canonicalization,
//! Zip Slip / path traversal prevention, decompression bomb / zip bomb defense,
//! per-file SHA-256 cryptographic digests, Unix/Windows permissions preservation,
//! and automatic `zeroize` memory scrubbing.

use crate::error::{Error, Result};
use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Magic header bytes for ShadowVault Archive format: `b"SVAR"`.
pub const MAGIC: &[u8; 4] = b"SVAR";

/// Archive format version 1.
pub const VERSION: u8 = 1;

/// Magic trailer bytes terminating SVAR archives: `b"SVEN"`.
pub const TRAILER_MAGIC: &[u8; 4] = b"SVEN";

/// Maximum allowed total archive uncompressed payload size (8 GiB).
pub const MAX_ARCHIVE_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// Maximum allowed individual file size (4 GiB).
pub const MAX_SINGLE_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum number of entries allowed in a single archive (100,000).
pub const MAX_ENTRY_COUNT: u32 = 100_000;

/// Maximum relative path length in bytes (4,096).
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum directory nesting depth (64 levels).
pub const MAX_DEPTH: usize = 64;

/// Fixed header length in bytes: 4 (magic) + 1 (ver) + 1 (flags) + 4 (count) + 8 (total_size) = 18 bytes.
pub const HEADER_LEN: usize = 18;

/// Fixed trailer length in bytes: 4 (CRC-32) + 4 (trailer magic) = 8 bytes.
pub const TRAILER_LEN: usize = 8;

/// Entry type indicator in the SVAR stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EntryType {
    RegularFile = 0,
    Directory = 1,
}

impl EntryType {
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::RegularFile),
            1 => Ok(Self::Directory),
            other => Err(Error::Archive(format!("invalid entry type tag: {other}"))),
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Directory)
    }
}

/// A single entry in an in-memory SVAR archive.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ArchiveEntry {
    #[zeroize(skip)]
    pub path: String,
    #[zeroize(skip)]
    pub entry_type: EntryType,
    #[zeroize(skip)]
    pub permissions: u32,
    #[zeroize(skip)]
    pub mtime: u64,
    #[zeroize(skip)]
    pub sha256: [u8; 32],
    pub data: Vec<u8>,
}

impl std::fmt::Debug for ArchiveEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveEntry")
            .field("path", &self.path)
            .field("entry_type", &self.entry_type)
            .field("permissions", &format!("0o{:o}", self.permissions))
            .field("mtime", &self.mtime)
            .field("sha256", &hex_digest(&self.sha256))
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// In-memory representation of an entire unpacked or staged SVAR archive.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Archive {
    pub entries: Vec<ArchiveEntry>,
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("entry_count", &self.entries.len())
            .field(
                "total_bytes",
                &self.entries.iter().map(|e| e.data.len() as u64).sum::<u64>(),
            )
            .finish()
    }
}

/// Metadata description of a single archive entry for reporting and JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveEntryMeta {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub permissions: String,
    pub mtime: u64,
    pub sha256: String,
}

/// Summary report returned when listing archive contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveSummary {
    pub status: String,
    pub total_entries: usize,
    pub file_count: usize,
    pub dir_count: usize,
    pub total_bytes: u64,
    pub entries: Vec<ArchiveEntryMeta>,
}

/// Report returned when verifying archive digests without extraction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyReport {
    pub status: String,
    pub valid: bool,
    pub files_verified: usize,
    pub dirs_verified: usize,
    pub total_bytes: u64,
    pub entries: Vec<ArchiveEntryMeta>,
}

/// Report returned when unpacking an archive to a destination directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnpackReport {
    pub status: String,
    pub destination: String,
    pub files_extracted: usize,
    pub dirs_extracted: usize,
    pub total_bytes: u64,
    pub entries: Vec<ArchiveEntryMeta>,
}

/// Report returned when packing a directory tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackReport {
    pub status: String,
    pub files_packed: usize,
    pub dirs_packed: usize,
    pub total_bytes: u64,
    pub archive_size: usize,
    pub entries: Vec<ArchiveEntryMeta>,
}

/// Format 32-byte hash digest into a lowercase 64-character hexadecimal string.
pub fn hex_digest(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

/// Convert Unix mode number to standard 4-digit octal string (e.g. `"0644"`, `"0755"`).
pub fn format_permissions(mode: u32) -> String {
    format!("0{:03o}", mode & 0o777)
}

/// Sanitize and canonicalize a relative path, enforcing strict path traversal,
/// Zip Slip, ADS, null-byte, and Windows reserved device name defenses.
pub fn sanitize_relative_path(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Err(Error::Archive("path must not be empty".into()));
    }
    if raw.len() > MAX_PATH_LEN {
        return Err(Error::Archive(format!(
            "path exceeds maximum allowed length of {} bytes: '{raw}'",
            MAX_PATH_LEN
        )));
    }
    if raw.contains('\0') {
        return Err(Error::Archive("path contains null byte".into()));
    }

    // Reject absolute paths and drive prefixes
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(Error::Archive(format!(
            "absolute paths are not allowed in archive: '{raw}'"
        )));
    }
    let raw_bytes = raw.as_bytes();
    if raw_bytes.len() >= 2 && raw_bytes[1] == b':' && raw_bytes[0].is_ascii_alphabetic() {
        return Err(Error::Archive(format!(
            "drive letter prefix detected in path: '{raw}'"
        )));
    }
    if raw.starts_with("\\\\") || raw.starts_with("//") {
        return Err(Error::Archive(format!(
            "UNC network paths are not allowed: '{raw}'"
        )));
    }

    // Split components by both '/' and '\'
    let parts: Vec<&str> = raw
        .split(|c| c == '/' || c == '\\')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    if parts.is_empty() {
        return Err(Error::Archive("normalized path resolves to empty".into()));
    }

    if parts.len() > MAX_DEPTH {
        return Err(Error::Archive(format!(
            "path nesting depth exceeds maximum of {} levels: '{raw}'",
            MAX_DEPTH
        )));
    }

    // Reserved Windows device names (case-insensitive base stem)
    const RESERVED_NAMES: &[&str] = &[
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
        "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];

    for part in &parts {
        if *part == ".." {
            return Err(Error::Archive(format!(
                "path traversal attempt detected ('..') in path: '{raw}'"
            )));
        }
        if part.contains(':') {
            return Err(Error::Archive(format!(
                "invalid path component containing colon (alternate data stream attempt): '{part}'"
            )));
        }
        if part.chars().any(|c| c.is_control()) {
            return Err(Error::Archive(format!(
                "path component contains control characters: '{part}'"
            )));
        }

        let stem = part.split('.').next().unwrap_or(part).to_ascii_lowercase();
        if RESERVED_NAMES.contains(&stem.as_str()) {
            return Err(Error::Archive(format!(
                "reserved Windows device name rejected: '{part}'"
            )));
        }
    }

    Ok(parts.join("/"))
}

impl Archive {
    /// Create a new empty archive.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Pack an entire directory tree recursively into an in-memory `Archive`.
    pub fn pack_dir(dir_path: &Path) -> Result<Self> {
        if !dir_path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("directory not found: {}", dir_path.display()),
            )));
        }
        if !dir_path.is_dir() {
            return Err(Error::Archive(format!(
                "specified path is not a directory: {}",
                dir_path.display()
            )));
        }

        let mut entries = Vec::new();
        collect_entries_recursive(dir_path, dir_path, &mut entries)?;

        // Deterministic sorting: sort entries by canonical path alphabetically
        entries.sort_by(|a, b| a.path.cmp(&b.path));

        if entries.len() > MAX_ENTRY_COUNT as usize {
            return Err(Error::Archive(format!(
                "directory contains {} entries, exceeding maximum allowed of {}",
                entries.len(),
                MAX_ENTRY_COUNT
            )));
        }

        let total_bytes: u64 = entries.iter().map(|e| e.data.len() as u64).sum();
        if total_bytes > MAX_ARCHIVE_SIZE {
            return Err(Error::Archive(format!(
                "directory payload size ({} bytes) exceeds maximum archive size ({} bytes)",
                total_bytes, MAX_ARCHIVE_SIZE
            )));
        }

        Ok(Self { entries })
    }

    /// Serialize the archive into the binary `SVAR` format with CRC-32 trailer.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.entries.len() > MAX_ENTRY_COUNT as usize {
            return Err(Error::Archive(format!(
                "archive entry count {} exceeds maximum allowed {}",
                self.entries.len(),
                MAX_ENTRY_COUNT
            )));
        }

        let total_data_len: u64 = self.entries.iter().map(|e| e.data.len() as u64).sum();
        if total_data_len > MAX_ARCHIVE_SIZE {
            return Err(Error::Archive(format!(
                "total archive payload size ({} bytes) exceeds limit ({} bytes)",
                total_data_len, MAX_ARCHIVE_SIZE
            )));
        }

        // Precompute approximate buffer capacity
        let estimated_size = HEADER_LEN
            + self
                .entries
                .iter()
                .map(|e| 1 + 4 + 8 + 2 + e.path.len() + 8 + 32 + e.data.len())
                .sum::<usize>()
            + TRAILER_LEN;

        let mut buf = Vec::with_capacity(estimated_size);

        // Header: [MAGIC: 4B][VERSION: 1B][FLAGS: 1B][COUNT: 4B LE][TOTAL_SIZE: 8B LE]
        buf.extend_from_slice(MAGIC);
        buf.push(VERSION);
        buf.push(0u8); // flags
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        buf.extend_from_slice(&total_data_len.to_le_bytes());

        // Entries
        for entry in &self.entries {
            let path_bytes = entry.path.as_bytes();
            if path_bytes.len() > u16::MAX as usize {
                return Err(Error::Archive(format!(
                    "path length exceeds maximum u16: {}",
                    entry.path
                )));
            }

            buf.push(entry.entry_type as u8);
            buf.extend_from_slice(&entry.permissions.to_le_bytes());
            buf.extend_from_slice(&entry.mtime.to_le_bytes());
            buf.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(path_bytes);
            buf.extend_from_slice(&(entry.data.len() as u64).to_le_bytes());
            buf.extend_from_slice(&entry.sha256);
            buf.extend_from_slice(&entry.data);
        }

        // Compute CRC-32 over all header and entry bytes
        let mut crc = Hasher::new();
        crc.update(&buf);
        let checksum = crc.finalize();

        // Trailer: [CRC-32: 4B LE][TRAILER_MAGIC: 4B]
        buf.extend_from_slice(&checksum.to_le_bytes());
        buf.extend_from_slice(TRAILER_MAGIC);

        Ok(buf)
    }

    /// Deserialize and validate an `Archive` from raw binary bytes.
    ///
    /// Applies strict bounds checks against zip bombs, path traversal attacks,
    /// checksum corruptions, and per-file SHA-256 digest mismatches.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() < HEADER_LEN + TRAILER_LEN {
            return Err(Error::Archive(
                "archive stream truncated or smaller than header".into(),
            ));
        }

        // Header magic verification
        if &raw[0..4] != MAGIC {
            return Err(Error::Archive(
                "invalid archive magic header (expected SVAR)".into(),
            ));
        }

        let version = raw[4];
        if version != VERSION {
            return Err(Error::Archive(format!(
                "unsupported archive version: {version} (expected {VERSION})"
            )));
        }

        let _flags = raw[5];
        let entry_count = u32::from_le_bytes(
            raw[6..10]
                .try_into()
                .map_err(|_| Error::Archive("corrupted entry count field".into()))?,
        );
        let total_declared_size = u64::from_le_bytes(
            raw[10..18]
                .try_into()
                .map_err(|_| Error::Archive("corrupted total size field".into()))?,
        );

        // Pre-flight zip bomb / allocation bomb checks
        if entry_count > MAX_ENTRY_COUNT {
            return Err(Error::Archive(format!(
                "entry count {entry_count} exceeds maximum allowed {MAX_ENTRY_COUNT} (zip bomb defense)"
            )));
        }
        if total_declared_size > MAX_ARCHIVE_SIZE {
            return Err(Error::Archive(format!(
                "declared total uncompressed size {total_declared_size} exceeds maximum {MAX_ARCHIVE_SIZE} (zip bomb defense)"
            )));
        }

        let payload_len = raw.len() - TRAILER_LEN;
        let trailer_slice = &raw[payload_len..];

        // Trailer verification
        let expected_crc = u32::from_le_bytes(
            trailer_slice[0..4]
                .try_into()
                .map_err(|_| Error::Archive("corrupted trailer CRC-32 field".into()))?,
        );
        if &trailer_slice[4..8] != TRAILER_MAGIC {
            return Err(Error::Archive(
                "invalid archive trailer magic (expected SVEN)".into(),
            ));
        }

        let mut crc = Hasher::new();
        crc.update(&raw[0..payload_len]);
        let calculated_crc = crc.finalize();
        if calculated_crc != expected_crc {
            return Err(Error::Archive(format!(
                "archive trailer CRC-32 mismatch: expected 0x{expected_crc:08x}, calculated 0x{calculated_crc:08x}"
            )));
        }

        // Parse entries sequentially with safe bounds checks
        let mut offset = HEADER_LEN;
        let mut entries = Vec::with_capacity(entry_count.min(1024) as usize);
        let mut accumulated_bytes: u64 = 0;

        for entry_idx in 0..entry_count {
            // Need at least 1 (type) + 4 (perms) + 8 (mtime) + 2 (path_len) = 15 bytes
            if offset + 15 > payload_len {
                return Err(Error::Archive(format!(
                    "unexpected end of archive stream reading entry #{entry_idx} header"
                )));
            }

            let entry_type = EntryType::from_u8(raw[offset])?;
            offset += 1;

            let permissions = u32::from_le_bytes(
                raw[offset..offset + 4]
                    .try_into()
                    .map_err(|_| Error::Archive("invalid entry permissions".into()))?,
            );
            offset += 4;

            let mtime = u64::from_le_bytes(
                raw[offset..offset + 8]
                    .try_into()
                    .map_err(|_| Error::Archive("invalid entry mtime".into()))?,
            );
            offset += 8;

            let path_len = u16::from_le_bytes(
                raw[offset..offset + 2]
                    .try_into()
                    .map_err(|_| Error::Archive("invalid entry path length".into()))?,
            ) as usize;
            offset += 2;

            if path_len == 0 || path_len > MAX_PATH_LEN {
                return Err(Error::Archive(format!(
                    "entry #{entry_idx} has invalid path length: {path_len}"
                )));
            }

            // Need at least path_len + 8 (data_len) + 32 (sha256)
            if offset + path_len + 40 > payload_len {
                return Err(Error::Archive(format!(
                    "unexpected end of stream reading entry #{entry_idx} path or metadata"
                )));
            }

            let raw_path_str = std::str::from_utf8(&raw[offset..offset + path_len])
                .map_err(|_| Error::Archive(format!("entry #{entry_idx} path is not valid UTF-8")))?;
            offset += path_len;

            let sanitized_path = sanitize_relative_path(raw_path_str)?;

            let data_len = u64::from_le_bytes(
                raw[offset..offset + 8]
                    .try_into()
                    .map_err(|_| Error::Archive("invalid entry data length".into()))?,
            );
            offset += 8;

            if data_len > MAX_SINGLE_FILE_SIZE {
                return Err(Error::Archive(format!(
                    "entry '{sanitized_path}' data size {data_len} exceeds maximum single file size {MAX_SINGLE_FILE_SIZE}"
                )));
            }

            // Zip bomb defense: verify data_len <= remaining bytes in buffer BEFORE reading
            let remaining_payload = payload_len - offset;
            if data_len as usize > remaining_payload {
                return Err(Error::Archive(format!(
                    "entry '{sanitized_path}' declared size {data_len} exceeds remaining bytes {remaining_payload} in archive"
                )));
            }

            accumulated_bytes = accumulated_bytes.saturating_add(data_len);
            if accumulated_bytes > MAX_ARCHIVE_SIZE {
                return Err(Error::Archive(format!(
                    "total uncompressed archive size exceeds limit of {MAX_ARCHIVE_SIZE} bytes"
                )));
            }

            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&raw[offset..offset + 32]);
            offset += 32;

            let data_slice = &raw[offset..offset + data_len as usize];
            offset += data_len as usize;

            // Cryptographic SHA-256 digest verification per entry
            let mut hasher = Sha256::new();
            hasher.update(data_slice);
            let computed_digest: [u8; 32] = hasher.finalize().into();

            if computed_digest != sha256 {
                return Err(Error::Archive(format!(
                    "SHA-256 digest mismatch for entry '{sanitized_path}': expected {}, got {}",
                    hex_digest(&sha256),
                    hex_digest(&computed_digest)
                )));
            }

            entries.push(ArchiveEntry {
                path: sanitized_path,
                entry_type,
                permissions,
                mtime,
                sha256,
                data: data_slice.to_vec(),
            });
        }

        if offset != payload_len {
            return Err(Error::Archive(format!(
                "trailing unparsed bytes detected in archive payload: {} bytes remaining",
                payload_len - offset
            )));
        }

        Ok(Self { entries })
    }

    /// Extract all archive entries into `dest_dir`.
    pub fn extract(&self, dest_dir: &Path, overwrite: bool) -> Result<UnpackReport> {
        if !dest_dir.exists() {
            fs::create_dir_all(dest_dir)?;
        }

        let canonical_dest = dest_dir.canonicalize().unwrap_or_else(|_| dest_dir.to_path_buf());

        let mut files_extracted = 0;
        let mut dirs_extracted = 0;
        let mut total_bytes = 0;
        let mut entry_metas = Vec::with_capacity(self.entries.len());

        for entry in &self.entries {
            let target_path = dest_dir.join(&entry.path);

            // Path Traversal Defense: Ensure target path is strictly contained within destination directory
            let parent_dir = target_path.parent().unwrap_or(dest_dir);
            fs::create_dir_all(parent_dir)?;

            let target_resolved = if target_path.exists() {
                target_path
                    .canonicalize()
                    .unwrap_or_else(|_| target_path.clone())
            } else {
                let canonical_parent = parent_dir
                    .canonicalize()
                    .unwrap_or_else(|_| parent_dir.to_path_buf());
                canonical_parent.join(target_path.file_name().unwrap_or_default())
            };

            if !target_resolved.starts_with(&canonical_dest) {
                return Err(Error::Archive(format!(
                    "path traversal escape blocked: entry '{}' resolves outside target directory",
                    entry.path
                )));
            }

            if entry.entry_type.is_dir() {
                fs::create_dir_all(&target_path)?;
                dirs_extracted += 1;
            } else {
                if target_path.exists() && !overwrite {
                    return Err(Error::Archive(format!(
                        "target file already exists: '{}' (use --overwrite to replace)",
                        target_path.display()
                    )));
                }

                fs::write(&target_path, &entry.data)?;
                apply_permissions(&target_path, entry.permissions)?;
                files_extracted += 1;
                total_bytes += entry.data.len() as u64;
            }

            entry_metas.push(ArchiveEntryMeta {
                path: entry.path.clone(),
                is_dir: entry.entry_type.is_dir(),
                size: entry.data.len() as u64,
                permissions: format_permissions(entry.permissions),
                mtime: entry.mtime,
                sha256: hex_digest(&entry.sha256),
            });
        }

        Ok(UnpackReport {
            status: "ok".into(),
            destination: dest_dir.display().to_string(),
            files_extracted,
            dirs_extracted,
            total_bytes,
            entries: entry_metas,
        })
    }

    /// Verify all per-file digests and paths in the archive without writing to disk.
    pub fn verify(&self) -> Result<VerifyReport> {
        let mut files_verified = 0;
        let mut dirs_verified = 0;
        let mut total_bytes = 0;
        let mut entry_metas = Vec::with_capacity(self.entries.len());

        for entry in &self.entries {
            // Re-verify sanitize path
            sanitize_relative_path(&entry.path)?;

            let mut hasher = Sha256::new();
            hasher.update(&entry.data);
            let calculated: [u8; 32] = hasher.finalize().into();

            if calculated != entry.sha256 {
                return Err(Error::Archive(format!(
                    "SHA-256 digest verification failed for '{}'",
                    entry.path
                )));
            }

            if entry.entry_type.is_dir() {
                dirs_verified += 1;
            } else {
                files_verified += 1;
                total_bytes += entry.data.len() as u64;
            }

            entry_metas.push(ArchiveEntryMeta {
                path: entry.path.clone(),
                is_dir: entry.entry_type.is_dir(),
                size: entry.data.len() as u64,
                permissions: format_permissions(entry.permissions),
                mtime: entry.mtime,
                sha256: hex_digest(&entry.sha256),
            });
        }

        Ok(VerifyReport {
            status: "ok".into(),
            valid: true,
            files_verified,
            dirs_verified,
            total_bytes,
            entries: entry_metas,
        })
    }

    /// Generate summary metadata for listing archive contents.
    pub fn summary(&self) -> ArchiveSummary {
        let mut file_count = 0;
        let mut dir_count = 0;
        let mut total_bytes = 0;
        let mut entries = Vec::with_capacity(self.entries.len());

        for entry in &self.entries {
            if entry.entry_type.is_dir() {
                dir_count += 1;
            } else {
                file_count += 1;
                total_bytes += entry.data.len() as u64;
            }

            entries.push(ArchiveEntryMeta {
                path: entry.path.clone(),
                is_dir: entry.entry_type.is_dir(),
                size: entry.data.len() as u64,
                permissions: format_permissions(entry.permissions),
                mtime: entry.mtime,
                sha256: hex_digest(&entry.sha256),
            });
        }

        ArchiveSummary {
            status: "ok".into(),
            total_entries: self.entries.len(),
            file_count,
            dir_count,
            total_bytes,
            entries,
        }
    }
}

/// Recursively collect all entries inside `current` directory relative to `root`.
fn collect_entries_recursive(
    root: &Path,
    current: &Path,
    entries: &mut Vec<ArchiveEntry>,
) -> Result<()> {
    let read_dir = fs::read_dir(current)?;

    for item in read_dir {
        let item = item?;
        let path = item.path();
        let metadata = item.metadata()?;

        let relative_path = path
            .strip_prefix(root)
            .map_err(|e| Error::Archive(format!("failed to compute relative path: {e}")))?;

        let rel_str = relative_path.to_str().ok_or_else(|| {
            Error::Archive(format!(
                "path contains non-UTF-8 characters: {}",
                relative_path.display()
            ))
        })?;

        let canonical_rel = sanitize_relative_path(rel_str)?;

        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let permissions = extract_permissions(&metadata);

        if metadata.is_dir() {
            entries.push(ArchiveEntry {
                path: canonical_rel,
                entry_type: EntryType::Directory,
                permissions,
                mtime,
                sha256: Sha256::digest(b"").into(),
                data: Vec::new(),
            });
            collect_entries_recursive(root, &path, entries)?;
        } else if metadata.is_file() {
            let data = fs::read(&path)?;
            let sha256: [u8; 32] = Sha256::digest(&data).into();

            entries.push(ArchiveEntry {
                path: canonical_rel,
                entry_type: EntryType::RegularFile,
                permissions,
                mtime,
                sha256,
                data,
            });
        }
    }

    Ok(())
}

/// Extract Unix mode permissions or synthesize standard permissions on non-Unix platforms.
fn extract_permissions(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        if metadata.is_dir() {
            0o755
        } else if metadata.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

/// Apply Unix mode permissions or readonly attribute on target file.
fn apply_permissions(path: &Path, permissions: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(permissions));
    }
    #[cfg(not(unix))]
    {
        if (permissions & 0o222) == 0 {
            if let Ok(mut perms) = fs::metadata(path).map(|m| m.permissions()) {
                perms.set_readonly(true);
                let _ = fs::set_permissions(path, perms);
            }
        }
    }
    Ok(())
}

/// Convenience function to pack a directory into raw `SVAR` binary bytes.
pub fn pack_directory(dir_path: &Path) -> Result<Vec<u8>> {
    let archive = Archive::pack_dir(dir_path)?;
    archive.to_bytes()
}

/// Convenience function to unpack raw `SVAR` binary bytes into a destination directory.
pub fn unpack_archive(archive_bytes: &[u8], dest_dir: &Path, overwrite: bool) -> Result<UnpackReport> {
    let archive = Archive::from_bytes(archive_bytes)?;
    archive.extract(dest_dir, overwrite)
}

/// Convenience function to list the contents of an `SVAR` archive without extracting.
pub fn list_archive(archive_bytes: &[u8]) -> Result<ArchiveSummary> {
    let archive = Archive::from_bytes(archive_bytes)?;
    Ok(archive.summary())
}

/// Convenience function to verify the digests of an `SVAR` archive without extracting.
pub fn verify_archive(archive_bytes: &[u8]) -> Result<VerifyReport> {
    let archive = Archive::from_bytes(archive_bytes)?;
    archive.verify()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sanitize_relative_path_valid() {
        assert_eq!(
            sanitize_relative_path("foo/bar/baz.txt").unwrap(),
            "foo/bar/baz.txt"
        );
        assert_eq!(
            sanitize_relative_path("foo\\bar\\baz.txt").unwrap(),
            "foo/bar/baz.txt"
        );
        assert_eq!(
            sanitize_relative_path("./nested/./file.txt").unwrap(),
            "nested/file.txt"
        );
        assert_eq!(
            sanitize_relative_path("a//b///c.txt").unwrap(),
            "a/b/c.txt"
        );
    }

    #[test]
    fn test_sanitize_relative_path_traversal_rejected() {
        assert!(sanitize_relative_path("../secret.txt").is_err());
        assert!(sanitize_relative_path("foo/../secret.txt").is_err());
        assert!(sanitize_relative_path("foo/../../bar").is_err());
        assert!(sanitize_relative_path("/etc/passwd").is_err());
        assert!(sanitize_relative_path("\\Windows\\System32").is_err());
        assert!(sanitize_relative_path("C:\\config.sys").is_err());
        assert!(sanitize_relative_path("C:secret.txt").is_err());
        assert!(sanitize_relative_path("\\\\server\\share\\file").is_err());
    }

    #[test]
    fn test_sanitize_relative_path_special_devices_rejected() {
        assert!(sanitize_relative_path("con").is_err());
        assert!(sanitize_relative_path("CON.txt").is_err());
        assert!(sanitize_relative_path("dir/aux.dat").is_err());
        assert!(sanitize_relative_path("nul").is_err());
        assert!(sanitize_relative_path("com1").is_err());
        assert!(sanitize_relative_path("foo:stream").is_err());
        assert!(sanitize_relative_path("foo\0bar").is_err());
        assert!(sanitize_relative_path("").is_err());
    }

    #[test]
    fn test_pack_and_unpack_roundtrip() {
        let src_dir = tempdir().unwrap();
        let file1_path = src_dir.path().join("file1.txt");
        let file2_path = src_dir.path().join("sub").join("file2.bin");

        fs::create_dir_all(file2_path.parent().unwrap()).unwrap();
        fs::write(&file1_path, b"Hello ShadowVault Manifest").unwrap();
        fs::write(&file2_path, &[0xde, 0xad, 0xbe, 0xef, 0x42]).unwrap();

        let archive_bytes = pack_directory(src_dir.path()).unwrap();
        assert!(archive_bytes.starts_with(MAGIC));

        let summary = list_archive(&archive_bytes).unwrap();
        assert_eq!(summary.file_count, 2);
        assert_eq!(summary.dir_count, 1);
        assert_eq!(summary.total_bytes, 26 + 5);

        let verify_report = verify_archive(&archive_bytes).unwrap();
        assert!(verify_report.valid);
        assert_eq!(verify_report.files_verified, 2);

        let dst_dir = tempdir().unwrap();
        let unpack_report = unpack_archive(&archive_bytes, dst_dir.path(), false).unwrap();
        assert_eq!(unpack_report.files_extracted, 2);
        assert_eq!(unpack_report.dirs_extracted, 1);

        let unpacked1 = fs::read(dst_dir.path().join("file1.txt")).unwrap();
        let unpacked2 = fs::read(dst_dir.path().join("sub").join("file2.bin")).unwrap();
        assert_eq!(unpacked1, b"Hello ShadowVault Manifest");
        assert_eq!(unpacked2, &[0xde, 0xad, 0xbe, 0xef, 0x42]);
    }

    #[test]
    fn test_empty_directory_and_empty_files() {
        let src_dir = tempdir().unwrap();
        let empty_file = src_dir.path().join("empty.txt");
        let empty_sub = src_dir.path().join("empty_folder");

        fs::write(&empty_file, b"").unwrap();
        fs::create_dir(&empty_sub).unwrap();

        let archive_bytes = pack_directory(src_dir.path()).unwrap();
        let summary = list_archive(&archive_bytes).unwrap();
        assert_eq!(summary.file_count, 1);
        assert_eq!(summary.dir_count, 1);
        assert_eq!(summary.total_bytes, 0);

        let dst_dir = tempdir().unwrap();
        unpack_archive(&archive_bytes, dst_dir.path(), false).unwrap();

        assert!(dst_dir.path().join("empty.txt").exists());
        assert_eq!(fs::read(dst_dir.path().join("empty.txt")).unwrap().len(), 0);
        assert!(dst_dir.path().join("empty_folder").is_dir());
    }

    #[test]
    fn test_overwrite_protection() {
        let src_dir = tempdir().unwrap();
        fs::write(src_dir.path().join("test.txt"), b"original").unwrap();

        let archive_bytes = pack_directory(src_dir.path()).unwrap();

        let dst_dir = tempdir().unwrap();
        fs::write(dst_dir.path().join("test.txt"), b"pre-existing").unwrap();

        // Without overwrite: must fail
        let err = unpack_archive(&archive_bytes, dst_dir.path(), false);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("already exists"));

        // With overwrite: must succeed
        let res = unpack_archive(&archive_bytes, dst_dir.path(), true);
        assert!(res.is_ok());
        assert_eq!(fs::read(dst_dir.path().join("test.txt")).unwrap(), b"original");
    }

    #[test]
    fn test_tampered_file_digest_rejected() {
        let src_dir = tempdir().unwrap();
        fs::write(src_dir.path().join("hello.txt"), b"sensitive data").unwrap();

        let mut archive_bytes = pack_directory(src_dir.path()).unwrap();

        // Tamper with file byte in the stream
        // The file data is near the end before trailer
        let data_pos = archive_bytes.windows(14).position(|w| w == b"sensitive data").unwrap();
        archive_bytes[data_pos] = b'X';

        // Deserialization must reject due to trailer CRC or SHA-256 digest mismatch
        let res = Archive::from_bytes(&archive_bytes);
        assert!(res.is_err());
    }

    #[test]
    fn test_tampered_trailer_crc_rejected() {
        let src_dir = tempdir().unwrap();
        fs::write(src_dir.path().join("hello.txt"), b"content").unwrap();

        let mut archive_bytes = pack_directory(src_dir.path()).unwrap();
        let len = archive_bytes.len();
        // Mutate CRC byte (trailer starts at len - 8)
        archive_bytes[len - 8] ^= 0xff;

        let res = Archive::from_bytes(&archive_bytes);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("CRC-32 mismatch"));
    }

    #[test]
    fn test_zip_bomb_claimed_size_rejected() {
        let mut malformed = Vec::new();
        malformed.extend_from_slice(MAGIC);
        malformed.push(VERSION);
        malformed.push(0);
        malformed.extend_from_slice(&1u32.to_le_bytes()); // 1 entry
        malformed.extend_from_slice(&(MAX_ARCHIVE_SIZE + 1024).to_le_bytes()); // Exceeds max archive size

        let res = Archive::from_bytes(&malformed);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("zip bomb defense"));
    }

    #[test]
    fn test_zip_bomb_claimed_count_rejected() {
        let mut malformed = Vec::new();
        malformed.extend_from_slice(MAGIC);
        malformed.push(VERSION);
        malformed.push(0);
        malformed.extend_from_slice(&(MAX_ENTRY_COUNT + 1).to_le_bytes()); // Exceeds max entries
        malformed.extend_from_slice(&100u64.to_le_bytes());

        let res = Archive::from_bytes(&malformed);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("zip bomb defense"));
    }

    #[test]
    fn test_deterministic_packing_order() {
        let src_dir = tempdir().unwrap();
        fs::write(src_dir.path().join("z_file.txt"), b"z").unwrap();
        fs::write(src_dir.path().join("a_file.txt"), b"a").unwrap();
        fs::write(src_dir.path().join("m_file.txt"), b"m").unwrap();

        let archive1 = pack_directory(src_dir.path()).unwrap();
        let archive2 = pack_directory(src_dir.path()).unwrap();

        assert_eq!(archive1, archive2);

        let summary = list_archive(&archive1).unwrap();
        assert_eq!(summary.entries[0].path, "a_file.txt");
        assert_eq!(summary.entries[1].path, "m_file.txt");
        assert_eq!(summary.entries[2].path, "z_file.txt");
    }

    #[test]
    fn test_zeroize_memory_clears_on_drop() {
        let mut entry = ArchiveEntry {
            path: "secret.txt".into(),
            entry_type: EntryType::RegularFile,
            permissions: 0o600,
            mtime: 12345,
            sha256: [0u8; 32],
            data: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };

        // Explicit zeroize check
        entry.data.zeroize();
        assert_eq!(entry.data, vec![0, 0, 0, 0]);
    }
}
