# Progress: teamwork_preview_reviewer_1

## Task
Adversarial Review of M08 (BMP 24-bit Pixel LSB Steganography Engine & v0.8.0).

## Independent Requirements Understanding
1. Pure-Rust 24-bit uncompressed BMP pixel LSB steganography engine in `src/bmp.rs`.
2. Apache-2.0 + GHSFS NOTICE headers in `src/bmp.rs`.
3. 12-byte envelope: `[magic: "svLt" (4B)][len: 4B LE][payload: NB][crc32: 4B LE]` with constant-time CRC-32 validation.
4. Correct BMP row padding bypass: only R/G/B pixel channel bytes are modulated; 4-byte alignment row padding bytes MUST remain untouched.
5. Capacity estimation: `get_bmp_capacity` in `src/bmp.rs` and CLI `svault capacity <carrier> [--json]`.
6. CLI commands `embed-bmp` and `extract-bmp` in `src/cli.rs` and `src/main.rs` with `--clip` and `--clip-ttl`.
7. BMP detection wired into `inspect` and `audit`.
8. Cargo.toml version 0.8.0.
9. Documentation updates in README.md, CHANGELOG.md, TASK_BACKLOG.md (M08 completed, M45/M46 added).
10. Strict zero AI attribution and zero warnings in fmt/clippy/test.

## Adversarial Findings & Fixes
- [x] **Defect 1: Truncated BMP bypassed `audit_bmp_carrier` in `src/audit.rs`**:
  - `audit_carrier_bytes` had condition `data.starts_with(crate::bmp::BMP_MAGIC) && data.len() >= 54`.
  - When a file started with `b"BM"` but was smaller than 54 bytes (truncated), it skipped `audit_bmp_carrier` entirely and fell through to generic binary audit, leaving the dedicated `< 54` truncation handler in `audit_bmp_carrier` as unreachable dead code.
  - Fixed by changing condition to `data.starts_with(crate::bmp::BMP_MAGIC)` so truncated BMPs are routed to `audit_bmp_carrier`, which correctly flags `SuspiciousAnomaly` with `"Truncated BMP carrier (less than 54 bytes for file and DIB headers)"`.
- [x] **Defect 2: Integer overflow risks in `src/bmp.rs`**:
  - `min_offset`: `14 + dib_header_size as usize` could overflow on 32-bit platforms if `dib_header_size` is near `u32::MAX`.
  - `row_stride`: `row_bytes + row_padding` could overflow if `row_bytes` is near `usize::MAX`.
  - `total_pixels`: unchecked multiplication.
  - Fixed: used `checked_add` for `min_offset` and `row_stride`, checked `bytes.len() < min_offset`, and used `saturating_mul` for `total_pixels`.
- [x] **Defect 3: CLI error reporting clarity in `src/main.rs`**:
  - `svault capacity` and `svault inspect` had `raw.starts_with(b"BM") && raw.len() >= 54`.
  - Truncated files starting with `b"BM"` fell through to "unsupported carrier format" or "container too short (< 22 bytes)" instead of reporting BMP format errors.
  - Fixed by matching `raw.starts_with(b"BM")` directly so informative BMP header errors are returned.
- [x] **Adversarial Test Suite Expanded**:
  - Added unit test `bmp_extreme_aspect_ratios_and_all_padding_alignments` attacking 12 extreme aspect ratios (1x500, 2x250, 3x200, 4x150 in both bottom-up and top-down orientations, plus 500x1, 501x1, 502x1, 503x1) across all padding byte alignments (0, 1, 2, 3) verifying byte-for-byte padding preservation.
  - Added unit test `bmp_exact_capacity_boundary` testing 100% boundary capacity usage and 1-byte overflow rejection.
  - Added unit test `bmp_extended_dib_header_v4_and_v5` testing BITMAPV4HEADER (108B) and BITMAPV5HEADER (124B) support with 100% header preservation.
  - Added unit test `bmp_malformed_dib_headers_rejected` testing 9 header corruption vectors (u32::MAX dib size, dib size < 40, overlapping data offset, invalid planes, invalid compression, invalid bit depths, zero/negative width, zero/overflow height, truncated buffers).
  - Added unit test `bmp_stego_envelope_tampering_attacks` testing tampered magic and CRC trailer bit flips.
  - Added unit tests in `src/audit.rs`: `audit_bmp_truncated_header_anomaly` and `audit_bmp_v4_header_clean_and_stego`.
  - Added integration tests in `tests/integration.rs`: `cli_capacity_truncated_and_invalid_bmp`, `cli_audit_truncated_bmp`, `cli_bmp_extreme_aspect_ratio_roundtrip`.
- [x] **Verification**:
  - `cargo fmt --check`: 100% pass (exit code 0).
  - `cargo clippy --all-targets -- -D warnings`: 100% pass (0 warnings).
  - `cargo test`: 210 passed (150 unit + 60 integration), 0 failed.
  - `node scripts/check.mjs`: 100% pass (tests, fmt, clippy, and asset sweep).
