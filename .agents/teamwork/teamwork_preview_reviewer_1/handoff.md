> [!WARNING] **Skepticism Disclaimer**
> Moderate confidence: Tested against 12 extreme aspect ratios, all padding alignments (0-3 bytes), extended V4/V5 DIB headers, malformed DIB headers, arithmetic boundaries, truncated carriers, and envelope corruption; passed full suite of 210 tests with zero clippy/fmt warnings, but untested on physical multi-gigabyte BMP images due to environment constraints.

## 1. What the prior attempt got wrong
1. **Truncated BMP carrier (< 54 bytes) bypassed dedicated audit inspection in `src/audit.rs`**:
   - **Input:** Carrier buffer starting with `b"BM"` of length < 54 bytes (e.g., `b"BMtruncated"`).
   - **Expected:** Audited as `CarrierType::BmpImage` with verdict `CarrierVerdict::SuspiciousAnomaly` and anomaly message `"Truncated BMP carrier (less than 54 bytes for file and DIB headers)"`.
   - **Actual:** Fell through to `audit_binary_data` as generic raw binary, rendering the dedicated truncation check at lines 1124–1149 in `audit_bmp_carrier` unreachable dead code.
   - **Root cause:** Dispatch condition in `audit_carrier_bytes` at line 539 checked `data.starts_with(crate::bmp::BMP_MAGIC) && data.len() >= 54`.

2. **Integer overflow vulnerabilities on 32-bit platforms and missing buffer bound checks in `src/bmp.rs`**:
   - **Input:** BMP header with `dib_header_size = u32::MAX`, or `width` near `usize::MAX / 3`.
   - **Expected:** Graceful error rejection returning `Error::Format(...)` without panic.
   - **Actual:** `14 + dib_header_size as usize` and `row_bytes + row_padding` used raw addition, risking integer overflow panics in debug mode or wrapping on 32-bit targets. In addition, `bytes.len() < min_offset` was not checked before header parsing.
   - **Root cause:** Missing `checked_add` validation for `min_offset` and `row_stride`, and missing pre-check `bytes.len() < min_offset`.

3. **Confusing error reporting for truncated BMP files in CLI commands (`capacity`, `inspect`) in `src/main.rs`**:
   - **Input:** `svault capacity truncated.bmp` or `svault inspect truncated.bmp` on files starting with `BM` but < 54 bytes.
   - **Expected:** Descriptive error explaining that the BMP is smaller than the minimum 54-byte BMP header.
   - **Actual:** Bypassed BMP detection due to `&& raw.len() >= 54`, resulting in misleading errors like `"unsupported carrier format for capacity estimation"` or `"container too short (< 22 bytes)"`.
   - **Root cause:** Rigid `&& raw.len() >= 54` guards on format detection branches in `src/main.rs`.

4. **Untested edge cases from implementer ledger**:
   - Untested extreme aspect ratios (1xN, Nx1) with various row padding (1, 2, 3 bytes).
   - Untested extended DIB headers (BITMAPV4HEADER 108B, BITMAPV5HEADER 124B).
   - Untested envelope corruption (tampered magic, spoofed length, corrupted CRC trailer bits).
   - Untested exact capacity boundary (100% full payload vs 1 byte overflow).

## 2. What I changed
- `src/bmp.rs`:
  - Hardened `parse_bmp_header`: added `checked_add` for `min_offset` and `row_stride`, added `bytes.len() < min_offset` truncation pre-check, and changed `total_pixels` to `saturating_mul`.
  - Added test helper `create_test_bmp_with_dib_size(width, height, dib_size)` to support testing extended DIB headers (V4 108B and V5 124B).
  - Added unit test `bmp_extreme_aspect_ratios_and_all_padding_alignments` covering 12 extreme aspect ratio configurations across bottom-up and top-down orientations, verifying byte-for-byte row padding preservation.
  - Added unit test `bmp_exact_capacity_boundary` testing 100% capacity utilization boundary and 1-byte overflow rejection.
  - Added unit test `bmp_extended_dib_header_v4_and_v5` validating standard preservation and extraction from 108B and 124B DIB headers.
  - Added unit test `bmp_malformed_dib_headers_rejected` testing 9 corruption vectors (u32::MAX dib size, dib size < 40, overlapping data offset, invalid planes, invalid compression, invalid bit depths, zero/negative width, zero/overflow height, truncated buffers).
  - Added unit test `bmp_stego_envelope_tampering_attacks` testing tampered magic and bit-flipped CRC trailers.
- `src/audit.rs`:
  - Updated `audit_carrier_bytes` to route any buffer starting with `BMP_MAGIC` to `audit_bmp_carrier`, activating the dedicated `< 54` byte truncation anomaly check.
  - Added unit tests `audit_bmp_truncated_header_anomaly` and `audit_bmp_v4_header_clean_and_stego`.
- `src/main.rs`:
  - Removed `&& raw_bytes.len() >= 54` guard from `Commands::Capacity`, `Commands::Inspect`, and `Commands::Audit` stdin detection, allowing BMP format handlers to provide accurate format error diagnostics.
- `tests/integration.rs`:
  - Added integration test `cli_capacity_truncated_and_invalid_bmp` verifying CLI capacity error reporting on truncated and non-24bpp BMPs.
  - Added integration test `cli_audit_truncated_bmp` verifying text and JSON audit reporting of truncated BMPs.
  - Added integration test `cli_bmp_extreme_aspect_ratio_roundtrip` verifying end-to-end encryption, inspect, and decryption into a 1x500 BMP carrier.

## 3. Verification Record
- **Deep Verification (ran actual tests):**
  - `cargo fmt --check`: Passed (exit code 0).
  - `cargo clippy --all-targets -- -D warnings`: Passed with 0 warnings (exit code 0).
  - `cargo test`: 210 passed (150 unit + 60 integration), 0 failed (exit code 0).
  - `node scripts/check.mjs`: Passed with exit code 0 (all test, fmt, clippy, and Markdown/SVG asset sweep gates clean).
- **Shallow Verification (manual only):**
  - None; all verification executed via automated compiler and test harness commands.
- **Unverified aspects:**
  - Real-world multi-gigabyte BMP files (> 2 GiB) not executed in automated CI test suite due to memory and execution time constraints.
  - Non-Windows clipboard platforms (crate target environment is Windows x64 per project specification).

## 4. Known Issues
- `Minor Robustness Risk`: Flat, solid-color BMP images modified by LSB steganography exhibit LSB bit-plane noise that can be detected by specialized chi-square steganalysis if payload fills a high percentage of pixels.
- `Minor Robustness Risk`: Non-standard DIB header sizes below 40 bytes (such as OS/2 1.x 12-byte BITMAPCOREHEADER) are rejected as unsupported formats rather than converted.

## 5. Remaining risk & next step
- Task M08 is complete and verified. The BMP 24-bit LSB steganography engine, universal capacity command, and CLI integration are robust, secure, and fully verified with 210 passing tests and zero warnings.
- The next milestone in `TASK_BACKLOG.md` is **M09 — Reed-Solomon / Parity Error-Correcting Armor (`src/armor.rs`)**.
