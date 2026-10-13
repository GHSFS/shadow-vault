# Dispatch for teamwork_preview_reviewer_3

Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\shadow-vault\.agents\teamwork\teamwork_preview_reviewer_3
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
# Reviewer Round 2 Handoff Report — Milestone M08

## 1. What Was Audited
- Module: `src/bmp.rs` (24-bit uncompressed BMP pixel LSB carrier engine)
- Carrier Capacity: `svault capacity <carrier>` across BMP, WAV, PNG carriers
- CLI Subcommands: `embed-bmp`, `extract-bmp`, with `--clip` and `--clip-ttl` clipboard integration
- Decoy & Container Inspection: BMP container detection wired into `inspect` and `audit`
- Cryptographic & Steganographic Properties:
  - 12-byte stego envelope: `[magic "svLt": 4B][len: 4B LE][payload: NB][crc32: 4B LE]`
  - Timing attack resilience on CRC-32 verification
  - Scanline row padding modulation avoidance (respecting stride padding)
  - Top-down (`height < 0`) vs bottom-up (`height > 0`) scanline ordering
  - DIB header sizes (BITMAPINFOHEADER 40B, BITMAPV4HEADER 108B, BITMAPV5HEADER 124B) and gap handling before `data_offset`

## 2. Defects Identified & Fixed

### Issue 1: Fatal Usability & Opsec Bug in Direct Clipboard Extraction
- **Input:**
  `svault extract-bmp -c landscape-stego.bmp -p "primary-pass" --clip --clip-ttl 15`
  (advertised in README.md as zero-disk-write extraction)
- **Expected:** Extracts decrypted payload directly into Windows clipboard without requiring or writing to a disk file.
- **Actual:** Clap CLI crashed with `error: the following required arguments were not provided: --output <OUTPUT>`. Forcing `-o temp.txt` caused decrypted plaintext to be leaked to persistent disk storage, violating the advertised opsec guarantee.
- **Root Cause:** In `src/cli.rs`, `output: PathBuf` was marked as an unconditional required parameter across `Decrypt`, `DecryptDecoy`, `Extract`, `ExtractWav`, and `ExtractBmp`.
- **Fix:** Changed `output` to `Option<PathBuf>` with `#[arg(short, long, required_unless_present = "clip")]` across all 5 extraction/decryption commands. In `src/main.rs`, guarded filesystem writes behind `if let Some(ref out_path) = output`, allowing pure in-memory transfer to clipboard when `-o` is omitted and `--clip` is supplied.

### Issue 2: Compiler Optimization Risk in Constant-Time Equality
- **Input:** High optimization levels (`--release` / LTO).
- **Expected:** Constant-time 4-byte CRC-32 equality comparison without early exit branching or compiler loop unrolling optimizations that could introduce measurable timing side channels.
- **Actual:** `constant_time_eq_4` in `src/bmp.rs` was not annotated to inhibit inlining.
- **Fix:** Explicitly annotated `constant_time_eq_4` with `#[inline(never)]`.

### Issue 3: Missing Edge Cases in Carrier & Header Parsing
- **Covered:**
  - Minimal 32-pixel carrier (0-byte payload roundtrip, 1-byte overflow rejection)
  - 31-pixel carrier rejection (< 96 bits capacity)
  - Minimal 35-pixel carrier (1-byte payload roundtrip)
  - Extreme aspect ratio: 1px-tall top-down bitmaps (`(500, 1, true)`, `(501, 1, true)`)
  - Carrier with large gap between DIB header and `data_offset` (verified non-pixel gap bytes remain 100% bit-for-bit identical before and after embedding)
  - Spoofed envelope length overflowing carrier pixel capacity rejected cleanly without panic

### Issue 4: OS Clipboard Race Condition in Concurrent Integration Tests
- **Input:** Concurrent `cargo test` execution on Windows.
- **Expected:** Tests reading/writing system clipboard do not clobber each other.
- **Actual:** Standalone clipboard tests ran concurrently across threads, overwriting the global Windows clipboard.
- **Fix:** Sequenced direct-to-clipboard extraction and Base64 non-UTF8 extraction deterministically inside `cli_clipboard_guard_integration_suite`, and verified missing-output usage error via `cli_extract_bmp_missing_both_output_and_clip_fails`.

### Issue 5: Clippy Lint Fixes
- Fixed `clippy::same-item-push` in `src/bmp.rs` unit tests using `buf.resize`.
- Cleaned up `div_ceil` and matrix indexing lints in newly introduced modules.

## 3. Verification Summary
- `cargo fmt --check`: Passed (exit 0)
- `cargo clippy --all-targets -- -D warnings`: Passed with zero warnings (exit 0)
- `cargo test`:
  - 165 unit tests passed, 0 failed
  - 61 integration tests passed, 0 failed
- `node scripts/check.mjs`: Universal verification pipeline passed 100% (exit 0)
- Zero AI tool attributions verified across all project files.
</prior_attempt>

<additional_context>
The orchestrator personally re-ran node scripts/check.mjs and cargo test:
- node scripts/check.mjs passed exit 0.
- When running multi-threaded cargo test on Windows, standalone test `cli_armor_and_dearmor_clipboard_guard` can intermittently race with `cli_clipboard_guard_integration_suite` over the global OS clipboard.

Open Issues Ledger from previous round:
- Real-world multi-gigabyte BMP files (> 2 GiB) not executed in automated CI test suite due to memory and execution time constraints [Round 2: reviewer 1]
- Non-Windows clipboard platforms (crate target environment is Windows x64 per project specification) [Round 2: reviewer 1]
- Minor Robustness Risk: Flat, solid-color BMP images modified by LSB steganography exhibit LSB bit-plane noise that can be detected by specialized chi-square steganalysis if payload fills a high percentage of pixels [Round 2: reviewer 1]
- Minor Robustness Risk: Non-standard DIB header sizes below 40 bytes (such as OS/2 1.x 12-byte BITMAPCOREHEADER) are rejected as unsupported formats rather than converted [Round 2: reviewer 1]
- Flaky concurrency risk: Standalone clipboard tests (e.g. cli_armor_and_dearmor_clipboard_guard) run concurrently with cli_clipboard_guard_integration_suite in default multi-threaded cargo test, which can intermittently clobber the shared Windows clipboard [Round 3: orchestrator]
</additional_context>
