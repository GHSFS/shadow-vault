// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Encrypted in-memory key-value secret store for interactive REPL shell.

use crate::armor;
use crate::bmp;
use crate::crypto;
use crate::error::{Error, Result};
use crate::stego;
use crate::wav;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use zeroize::Zeroize;

/// Individual secret record stored in the encrypted key-value vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEntry {
    pub key: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Drop for SecretEntry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl SecretEntry {
    pub fn new(key: impl Into<String>, value: impl Into<String>, tag: Option<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            key: key.into(),
            value: value.into(),
            tag,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn update_value(&mut self, new_value: impl Into<String>, tag: Option<String>) {
        self.value.zeroize();
        self.value = new_value.into();
        if tag.is_some() {
            self.tag = tag;
        }
        self.updated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }

    pub fn masked_preview(&self) -> String {
        if self.value.len() <= 4 {
            "*".repeat(self.value.len())
        } else {
            let prefix: String = self.value.chars().take(2).collect();
            let suffix: String = self
                .value
                .chars()
                .rev()
                .take(2)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("{prefix}••••••••{suffix} ({} chars)", self.value.len())
        }
    }
}

/// In-memory key-value vault containing encrypted secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValueVault {
    pub version: u32,
    pub entries: BTreeMap<String, SecretEntry>,
    #[serde(skip)]
    pub dpapi_bound: bool,
    #[serde(skip)]
    pub dirty: bool,
}

impl Default for KeyValueVault {
    fn default() -> Self {
        Self {
            version: 1,
            entries: BTreeMap::new(),
            dpapi_bound: false,
            dirty: false,
        }
    }
}

impl Drop for KeyValueVault {
    fn drop(&mut self) {
        for entry in self.entries.values_mut() {
            entry.value.zeroize();
        }
    }
}

impl KeyValueVault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&SecretEntry> {
        self.entries.get(key)
    }

    pub fn set(&mut self, key: String, value: String, tag: Option<String>) -> bool {
        let is_update = if let Some(entry) = self.entries.get_mut(&key) {
            entry.update_value(value, tag);
            true
        } else {
            let entry = SecretEntry::new(key.clone(), value, tag);
            self.entries.insert(key, entry);
            false
        };
        self.dirty = true;
        is_update
    }

    pub fn remove(&mut self, key: &str) -> Option<SecretEntry> {
        let removed = self.entries.remove(key);
        if removed.is_some() {
            self.dirty = true;
        }
        removed
    }

    pub fn list(&self, filter: Option<&str>) -> Vec<&SecretEntry> {
        match filter {
            Some(f) if !f.is_empty() => {
                let needle = f.to_lowercase();
                self.entries
                    .values()
                    .filter(|e| {
                        e.key.to_lowercase().contains(&needle)
                            || e.tag
                                .as_deref()
                                .map(|t| t.to_lowercase().contains(&needle))
                                .unwrap_or(false)
                    })
                    .collect()
            }
            _ => self.entries.values().collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    #[allow(dead_code)]
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Load existing vault from container path or create empty if file does not exist.
    pub fn load_or_new(
        path: &Path,
        passphrase: Option<&str>,
        keyfile: Option<&Path>,
    ) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        Self::load(path, passphrase, keyfile)
    }

    /// Load and decrypt existing vault from file path.
    pub fn load(path: &Path, passphrase: Option<&str>, keyfile: Option<&Path>) -> Result<Self> {
        let raw = fs::read(path).map_err(Error::Io)?;

        // Transparent carrier / ASCII armor decoding
        let container = if armor::is_armored(&raw) {
            let text = std::str::from_utf8(&raw)
                .map_err(|e| Error::Format(format!("armored container UTF-8 error: {e}")))?;
            armor::dearmor_data(text)?.to_vec()
        } else if raw.starts_with(b"\x89PNG\r\n\x1a\n") {
            stego::extract_from_png(&raw)?
        } else if raw.len() >= 12 && &raw[0..4] == b"RIFF" && &raw[8..12] == b"WAVE" {
            wav::extract_from_wav(&raw, wav::ExtractWavMode::Auto)?
        } else if raw.starts_with(b"BM") {
            bmp::extract_from_bmp(&raw)?
        } else if raw.starts_with(b"ID3")
            || (raw.len() >= 2 && raw[0] == 0xFF && (raw[1] & 0xE0) == 0xE0)
        {
            crate::mp3::extract_from_mp3(&raw, crate::mp3::ExtractMp3Mode::Auto)?
        } else {
            raw
        };

        if container.len() < crypto::HEADER_LEN || &container[0..4] != crypto::MAGIC {
            return Err(Error::Format(
                "invalid vault container magic (expected SVLT)".into(),
            ));
        }

        let flags = container[5];
        let dpapi_bound = (flags & crypto::FLAG_DPAPI) != 0;

        let mut plain = crypto::open_at_with_keyfile(&container, passphrase, keyfile, None)?;
        let json_str = std::str::from_utf8(&plain)
            .map_err(|e| Error::Format(format!("decrypted vault payload is not UTF-8: {e}")))?;

        let mut vault: Self = serde_json::from_str(json_str)
            .map_err(|e| Error::Format(format!("failed to parse vault JSON structure: {e}")))?;

        plain.zeroize();

        vault.dpapi_bound = dpapi_bound;
        vault.dirty = false;
        Ok(vault)
    }

    /// Save in-memory vault back to encrypted container atomically.
    pub fn save(
        &mut self,
        path: &Path,
        passphrase: Option<&str>,
        keyfile: Option<&Path>,
        bind_dpapi: bool,
    ) -> Result<()> {
        let mut json_str = serde_json::to_string(&self)
            .map_err(|e| Error::Format(format!("failed to serialize vault to JSON: {e}")))?;

        let sealed_res = crypto::seal_with_policy_and_keyfile(
            json_str.as_bytes(),
            passphrase,
            keyfile,
            bind_dpapi,
            None,
        );
        json_str.zeroize();
        let sealed = sealed_res?;

        // Atomic write via temporary file
        let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
        if !parent_dir.as_os_str().is_empty() && !parent_dir.exists() {
            fs::create_dir_all(parent_dir).map_err(Error::Io)?;
        }

        let rand_suffix: u64 = rand::random();
        let tmp_path = parent_dir.join(format!(
            ".{}.tmp.{}",
            path.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_else(|| "vault".into()),
            rand_suffix
        ));

        fs::write(&tmp_path, &sealed).map_err(Error::Io)?;
        fs::rename(&tmp_path, path).map_err(Error::Io)?;

        self.dpapi_bound = bind_dpapi;
        self.dirty = false;
        Ok(())
    }

    /// Export entries to human-readable JSON format.
    pub fn export_json(&self, raw: bool) -> Result<String> {
        if raw {
            let map: BTreeMap<String, String> = self
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), v.value.clone()))
                .collect();
            serde_json::to_string_pretty(&map)
                .map_err(|e| Error::Format(format!("JSON export failed: {e}")))
        } else {
            let list: Vec<&SecretEntry> = self.entries.values().collect();
            serde_json::to_string_pretty(&list)
                .map_err(|e| Error::Format(format!("JSON export failed: {e}")))
        }
    }

    /// Import entries from JSON string.
    pub fn import_json(&mut self, json_str: &str) -> Result<usize> {
        let mut count = 0;
        // Attempt parsing as array of SecretEntry first
        if let Ok(mut entries) = serde_json::from_str::<Vec<SecretEntry>>(json_str) {
            for entry in &mut entries {
                let key = std::mem::take(&mut entry.key);
                let value = std::mem::take(&mut entry.value);
                let tag = entry.tag.take();
                self.set(key, value, tag);
                count += 1;
            }
            return Ok(count);
        }

        // Attempt parsing as simple key-value map
        if let Ok(map) = serde_json::from_str::<BTreeMap<String, String>>(json_str) {
            for (k, v) in map {
                self.set(k, v, None);
                count += 1;
            }
            return Ok(count);
        }

        Err(Error::Format(
            "unrecognized JSON format for vault import (expected array of entries or key-value map)"
                .into(),
        ))
    }
}
