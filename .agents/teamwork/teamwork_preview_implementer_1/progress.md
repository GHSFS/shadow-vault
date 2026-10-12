# Progress: 24-bit BMP LSB Steganography Engine Implementation

## Objective
Implement pure-Rust 24-bit uncompressed BMP LSB steganography engine with envelope, constant-time CRC validation, row padding awareness, universal capacity estimation, CLI integration, inspect/audit carrier detection, version bump to 0.8.0, and documentation updates.

## Status Checklist
- [x] Baseline test verification (129 unit tests, 52 integration tests passing)
- [x] R1: BMP Engine (`src/bmp.rs`)
  - [x] Apache-2.0 + GHSFS NOTICE header
  - [x] BMP structure parsing (BITMAPFILEHEADER 14B, BITMAPINFOHEADER 40B, 24 bpp, uncompressed BI_RGB)
  - [x] Top-down vs bottom-up height handling (negative vs positive height)
  - [x] Row stride with 4-byte padding calculation; only modulate RGB pixel channels
  - [x] 12-byte envelope: `[magic "svLt": 4B][len: 4B LE][payload: NB][crc32: 4B LE]`
  - [x] Constant-time CRC-32 comparison (`constant_time_eq_4`)
  - [x] Capacity calculation (`get_bmp_capacity`)
  - [x] Unit tests for BMP parsing, embedding, extracting, edge cases, corruption, padding (11 unit tests)
- [x] R2: CLI & Universal Carrier Capacity Command
  - [x] `svault capacity <carrier> [--json]` in `src/cli.rs` and `src/main.rs`
  - [x] Universal capacity support: BMP, WAV (Chunk & LSB), PNG
  - [x] `embed-bmp` and `extract-bmp` commands in `src/cli.rs` and `src/main.rs`
  - [x] `--clip` and `--clip-ttl` clipboard integration for `extract-bmp`
  - [x] Wire BMP detection into `inspect` in `src/main.rs`
  - [x] Wire BMP detection and security audit into `audit` in `src/audit.rs` and `src/main.rs`
- [x] R3: Version bump & Tests
  - [x] Cargo.toml version bump to 0.8.0
  - [x] Unit tests in `src/bmp.rs` (11 unit tests)
  - [x] Integration tests in `tests/integration.rs` (capacity, embed-bmp, extract-bmp, inspect, audit, decoy, clipboard, error cases - 5 new suites)
- [x] R4: Documentation & Backlog
  - [x] README.md updates (version 0.8.0, BMP commands, capacity command, English & Korean)
  - [x] CHANGELOG.md (v0.8.0 release notes)
  - [x] TASK_BACKLOG.md (mark M08 completed, add M45/M46)
  - [x] dev_logs/WORK_LOG.md (record M08 audit log)
- [x] Verification
  - [x] cargo fmt --check (Clean, exit code 0)
  - [x] cargo clippy --all-targets -- -D warnings (0 warnings, exit code 0)
  - [x] cargo test (200 tests passing: 143 unit + 57 integration)
  - [x] Zero AI attribution audit (Clean across all files)
  - [x] Write handoff.md and send completion message
