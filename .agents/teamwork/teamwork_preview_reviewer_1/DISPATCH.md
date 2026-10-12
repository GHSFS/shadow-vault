# Dispatch for teamwork_preview_reviewer_1

Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\shadow-vault\.agents\teamwork\teamwork_preview_reviewer_1
Project root: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\shadow-vault

<original_task>
This is a single self-contained fix; keep it small and focused.

Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\shadow-vault
Integrity mode: development

Requirements:
R1: Implement 24-bit uncompressed BMP pixel LSB steganography engine in src/bmp.rs with Apache-2.0 and GHSFS NOTICE headers. Support embedding and extracting encrypted SVLT containers with 12-byte envelope ([magic svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]) and constant-time CRC-32 validation. Respect row padding by only modulating R/G/B pixel channel bytes.
R2: Provide capacity estimation in src/bmp.rs (get_bmp_capacity) and universal carrier capacity command `svault capacity <carrier>` (with `--json` support). Integrate `embed-bmp` and `extract-bmp` in src/cli.rs and src/main.rs, with `--clip` and `--clip-ttl` clipboard integration, and wire BMP detection into `inspect` and `audit`.
R3: Update Cargo.toml version to 0.8.0. Write unit tests in src/bmp.rs and integration tests in tests/integration.rs.
R4: Update README.md, CHANGELOG.md, TASK_BACKLOG.md (mark M08 completed and proactively add M45/M46).

Acceptance Criteria:
- All unit and integration tests pass with zero warnings in cargo fmt, cargo clippy, and cargo test.
- Zero AI attribution anywhere.
- Pure Rust, zero external image codec dependencies.
</original_task>

<prior_attempt>
# Handoff Report: M08 — BMP 24-bit Pixel LSB Steganography Engine & v0.8.0

## Executive Summary
Milestone M08 is fully implemented, verified, and integrated into `shadow-vault` (`svault`).
The system supports pure-Rust bit-level 24-bit uncompressed BMP pixel LSB steganography with strict 4-byte row padding preservation, a 12-byte tamper-resistant stego envelope, constant-time CRC-32 validation, universal carrier capacity estimation (`svault capacity <carrier>`), CLI subcommands (`embed-bmp`, `extract-bmp`), plausible deniability decoy vault embedding, auto-expiring clipboard guard integration (`--clip`), zero-knowledge header inspection (`inspect`), and carrier security auditing (`audit`).

## Modified / Created Files
1. `src/bmp.rs` (New):
   - Apache-2.0 and GHSFS NOTICE header.
   - BMP header structures: `BITMAPFILEHEADER` (14 bytes) and `BITMAPINFOHEADER` (40 bytes).
   - Validates uncompressed 24 bpp `BI_RGB` format, dimensions > 0, data offset bounds.
   - Height handling: Top-down (negative height) and bottom-up (positive height) support.
   - Row stride & padding: Calculates `row_bytes = width * 3`, `row_padding = (4 - (row_bytes % 4)) % 4`, `row_stride = row_bytes + row_padding`. Pixel channel index $k$ maps to row $k / (width \times 3)$ and column $k \pmod{width \times 3}$. File byte offset: `data_offset + row * row_stride + col`. Padding bytes are strictly bypassed.
   - 12-byte envelope framing: `[magic "svLt": 4B][len: 4B LE][payload: NB][crc32: 4B LE]`.
   - Constant-time CRC-32 verification via `constant_time_eq_4` using bitwise XOR accumulation.
   - `get_bmp_capacity(&[u8]) -> Result<BmpCapacity>` returning total pixels, usable payload bytes, and stego overhead (12 bytes).
   - `embed_in_bmp(carrier: &[u8], payload: &[u8]) -> Result<Vec<u8>>`.
   - `extract_from_bmp(carrier: &[u8]) -> Result<Vec<u8>>`.
   - Test helper `create_minimal_bmp(width, height, fill_color)` generating valid 24-bit uncompressed BMP buffers with arbitrary dimensions and padding.
   - 11 unit tests covering roundtrip, empty payload, maximum capacity boundary, capacity overflow, corrupted CRC, corrupted magic, invalid BMP headers, padding verification, non-24bpp rejection, compressed BMP rejection, and top-down BMP support.

2. `src/wav.rs`:
   - Added `WavCapacity` struct (`total_samples`, `chunk_usable_capacity_bytes`, `lsb_usable_capacity_bytes`, `stego_overhead_bytes`).
   - Added `get_wav_capacity(&[u8]) -> Result<WavCapacity>` helper.

3. `src/audit.rs`:
   - Added `CarrierType::BmpImage`.
   - Updated `audit_carrier_bytes` to detect BMP (`b"BM"` and `>= 54` bytes).
   - Implemented `audit_bmp_carrier` auditing BMP header validity, dimensions, pixel count, usable capacity, and LSB envelope presence / CRC validity.
   - Reused `CarrierDetails::stego_lsb_present` for JSON backward compatibility while displaying `Stego Pixel LSB: present (active)` in terminal output.
   - 3 unit tests for clean BMP, stego BMP, and corrupt BMP audit.

4. `src/cli.rs`:
   - Added `Commands::Capacity { carrier: PathBuf, json: bool }`.
   - Added `Commands::EmbedBmp { carrier, secret, out, passphrase, decoy, decoy_passphrase, padding }`.
   - Added `Commands::ExtractBmp { carrier, out, passphrase, decoy_passphrase, clip, clip_ttl }`.
   - Updated `Inspect` command docstring.

5. `src/main.rs`:
   - Registered `mod bmp;`.
   - Implemented handlers for `Capacity`, `EmbedBmp`, `ExtractBmp`.
   - Enhanced `Capacity` handler to support BMP, WAV (Chunk & LSB), and PNG with `--json` option.
   - Wired BMP carrier detection into `inspect` and `audit`.
   - Integrated clipboard guard (`--clip`, `--clip-ttl`) into `ExtractBmp`.

6. `Cargo.toml`:
   - Bumped version to `0.8.0`.

7. `tests/integration.rs`:
   - Updated version assertions from `0.7.0` to `0.8.0`.
   - Added test helper `generate_24bit_bmp(width, height)`.
   - Added `cli_capacity_bmp_wav_png_and_json` testing CLI capacity calculation across BMP, WAV, and PNG.
   - Added `cli_bmp_embed_inspect_and_extract_roundtrip` testing end-to-end encryption, inspect, and decryption.
   - Added `cli_bmp_embed_with_decoy_flags_and_dual_extract` testing plausible deniability decoy vault embedding into BMP.
   - Sequenced BMP clipboard extraction as Step 7 within `cli_clipboard_guard_integration_suite` to eliminate Windows clipboard OS singleton race conditions.
   - Added `cli_audit_bmp_clean_and_stego_and_json` testing BMP audit for clean, stego, and `--json` outputs.
   - Added `cli_bmp_error_handling` testing non-existent files, small capacity carriers, invalid passphrases, and corrupt envelopes.

8. `CHANGELOG.md`:
   - Added `## [0.8.0] - 2026-10-12` section documenting all new features, enhancements, and security improvements.

9. `TASK_BACKLOG.md`:
   - Marked M08 as completed `[x]`.
   - Added pending milestones M45 (Tar/PAX Directory Steganography) and M46 (WebP Lossless Stego Carrier).

10. `README.md`:
    - Updated English and Korean Overview, Features, Architecture diagram, and Quick Start / Usage Summary with BMP steganography and capacity commands.

11. `dev_logs/WORK_LOG.md`:
    - Recorded M08 implementation, adversarial review, and verification log.

## Verification Record
- `cargo fmt --check`: Passed (exit code 0).
- `cargo clippy --all-targets -- -D warnings`: Passed with 0 warnings (exit code 0).
- `cargo test`: 200 passed (143 unit + 57 integration), 0 failed.
- `node scripts/check.mjs`: Passed (Rust fmt, clippy, test, and Markdown/SVG asset sweep 100% clean).
- Zero AI attribution check: 0 disallowed words found across all modified files.
</prior_attempt>

<additional_context>
The orchestrator personally re-ran the full test suite and validation scripts:
- cargo test passed with 200 tests (143 unit, 57 integration).
- node scripts/check.mjs passed with exit code 0.

Open Issues Ledger from previous round:
- Real-world multi-gigabyte BMP images (tested up to 500x500 24-bit BMP in automated tests due to CI test execution time constraints) [Round 1: implementer]
- Rare BMP variants using BITMAPV4HEADER (108B) or BITMAPV5HEADER (124B); the engine requires standard BITMAPINFOHEADER (40B) and rejects others with a descriptive error [Round 1: implementer]
- Non-Windows environments for clipboard integration (the crate target environment is Windows x64 per project configuration) [Round 1: implementer]
- Minor Robustness Risk — Non-standard DIB header sizes (such as OS/2 BITMAPCOREHEADER 12B, or BITMAPV4HEADER / BITMAPV5HEADER) are treated as unsupported and rejected rather than parsed [Round 1: implementer]
- Minor Robustness Risk — Flat, solid-color BMP carriers modified by LSB steganography may exhibit noticeable LSB bit-plane noise under specialized steganalysis tools if the payload spans a large percentage of the image [Round 1: implementer]
- Reviewers should attack DIB headers with unconventional header size values or unusual biPlanes/biCompression combinations to verify that src/bmp.rs consistently rejects them cleanly without panic [Round 1: implementer]
- Reviewers should test embedding into extreme aspect ratio carriers (e.g. 1x10000 or 10000x1 pixels) with various padding alignments (1, 2, 3 bytes) [Round 1: implementer]
</additional_context>
