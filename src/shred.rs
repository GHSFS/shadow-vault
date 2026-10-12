// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Multi-pass secure file shredder (0x00 -> 0xFF -> CSPRNG random -> truncate -> unlink).

use crate::error::Result;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Overwrite a file with 3 passes (zeros, ones, random bytes), flush to disk,
/// truncate to 0 bytes, and remove the directory entry.
pub fn shred_file(path: &Path, passes: u8) -> Result<u64> {
    let meta = fs::metadata(path)?;
    let len = meta.len();

    if len > 0 {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let chunk_size = 64 * 1024;
        let mut buf = vec![0u8; chunk_size];
        let total_passes = passes.max(1);

        for pass in 0..total_passes {
            file.seek(SeekFrom::Start(0))?;
            let mut remaining = len as usize;
            while remaining > 0 {
                let to_write = remaining.min(chunk_size);
                match pass % 3 {
                    0 => buf[..to_write].fill(0x00),
                    1 => buf[..to_write].fill(0xFF),
                    _ => rand::thread_rng().fill_bytes(&mut buf[..to_write]),
                }
                file.write_all(&buf[..to_write])?;
                remaining -= to_write;
            }
            file.sync_all()?;
        }

        file.set_len(0)?;
        file.sync_all()?;
    }

    fs::remove_file(path)?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn shreds_and_removes_target_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        fs::write(&path, [0x42u8; 4096]).unwrap();

        assert!(path.exists());
        let wiped = shred_file(&path, 3).unwrap();
        assert_eq!(wiped, 4096);
        assert!(!path.exists());
    }
}
