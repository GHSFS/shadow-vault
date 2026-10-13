# Adversarial Review & QA Handoff Report (Round 2): M05 Passphrase Strength & Entropy Auditor

- **Agent Role**: Adversarial Reviewer & QA (`reviewer@swe_light`, `qa@swe_light`)
- **Version**: `0.5.0`
- **Target Repository**: `c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\shadow-vault`
- **Date**: 2026-10-12

---

## 1. What the Prior Attempt Got Wrong

### Issue 1: Truncated / Corrupted Embedded Containers in Stego Carriers Masked as Valid Stego
- **Input**: PNG or WAV carrier containing an `svLt` chunk or LSB stream with a truncated `< 50` byte payload starting with `SVLT` (e.g. 40 bytes missing Poly1305 MAC tag), or containing an unsupported container version (e.g. `v99`), invalid flags, or degraded salt entropy.
- **Expected**: Flagged as `SuspiciousAnomaly` with an anomaly describing that the embedded container is truncated or corrupt.
- **Actual**: `parse_svault_header` returned `None` on truncated containers, pushing zero anomalies. The carrier was classified as `StegoCarrierDetected` without warning the user that the container cannot be decrypted. For unsupported versions or invalid flags, `parse_svault_header` extracted them without flagging anomalies.
- **Root Cause**: `audit_png_carrier` and `audit_wav_carrier` did not validate container integrity, relying on basic header unpacking rather than auditing embedded container validity.

### Issue 2: Missing WAV Carrier `fmt ` and `data` Chunk Integrity Verification
- **Input**: Malformed WAV audio carrier missing required `fmt ` chunk, missing required `data` chunk, or having `num_channels == 0` or `sample_rate == 0`.
- **Expected**: Flagged with `SuspiciousAnomaly` describing missing or invalid RIFF subchunks.
- **Actual**: `audit_wav_carrier` traversed subchunks but never verified whether `fmt ` or `data` chunks existed, reporting `CleanCarrier` on unplayable, corrupted audio files.
- **Root Cause**: Subchunk traversal loop in `audit_wav_carrier` lacked required chunk presence tracking and `fmt ` header field validation.

### Issue 3: Non-16-bit PCM WAV Carriers Causing Blind Out-of-Spec LSB Sampling
- **Input**: 24-bit PCM, 32-bit float, or non-PCM audio WAV carrier with a `data` chunk.
- **Expected**: Report that 16-bit PCM LSB steganography is unsupported for non-16-bit audio rather than reading nonsensical byte offsets.
- **Actual**: `audit_wav_carrier` sampled bytes via `(0..128).step_by(2)` assuming 16-bit PCM blindly without checking `bits_per_sample == 16 && audio_format == 1`.
- **Root Cause**: `audit_wav_carrier` did not check the parsed `fmt ` chunk before initiating LSB steganography analysis.

### Issue 4: Missing PNG `IHDR` Chunk Compliance, Multi-`IHDR` Detection, and Lack of APNG Support
- **Input**: PNG carrier missing `IHDR` (e.g. starting directly with `IDAT` or `tEXt`), containing multiple `IHDR` chunks, or valid Animated PNG (APNG) with `acTL`/`fcTL` chunks.
- **Expected**: Non-IHDR first chunk or multiple `IHDR` chunks flagged as `SuspiciousAnomaly`. APNG carriers recognized and reported in findings.
- **Actual**: `audit_png_carrier` ignored chunk order, accepted non-IHDR initial chunks, ignored duplicate IHDR chunks, and did not recognize APNG streams.
- **Root Cause**: No state tracking for `ihdr_seen` or APNG chunk types (`acTL`) in `audit_png_carrier`.

### Issue 5: Decoy Container Layout Corruption Ignored in Direct Container Audit
- **Input**: Decoy container (`.svault`) with corrupted `decoy_body_len` header field or broken hidden slot structure.
- **Expected**: Flagged as `SuspiciousAnomaly` with anomaly warning.
- **Actual**: `crate::decoy::inspect_decoy(data).ok()` silently discarded the `Err`, setting `payload_bytes = None` without adding an anomaly.
- **Root Cause**: Silent `.ok()` conversion without recording error into `anomalies`.

### Issue 6: Memory Zeroization Gap in WAV LSB Payload Extraction Buffer (R4)
- **Input**: WAV carrier with active 16-bit PCM LSB stream.
- **Expected**: Extracted ciphertext payload buffer in memory wiped on drop.
- **Actual**: `payload_buf` was allocated as a raw `Vec<u8>` without `Zeroizing`.
- **Root Cause**: Omission of `Zeroizing` wrapper on `payload_buf` in `audit_wav_carrier`.

### Issue 7: Incomplete Keyboard Walks, 4-Gram Repetitions, and Null Byte Classification in Text Files
- **Input**:
  - Passphrases with common vertical QWERTY column walks (`1qaz`, `qazwsx`, `rfvtgb`).
  - Passphrases with 4-gram repetitions (`testtest`, `passpass`).
  - Passphrases with non-printable ASCII control characters (`pass\0word`, `\x1b`).
  - Binary files with ASCII text headers followed by `0x00`.
- **Expected**:
  - Vertical walks flagged as `has_keyboard_walk`.
  - 4-gram repeats flagged as `has_repeats`.
  - Control characters flagged in findings without falsely giving +128 to `pool_size`.
  - Binary files with null bytes rejected from `is_likely_text`.
- **Actual**:
  - Vertical walks missed (`ROWS` only had horizontal rows).
  - 4-gram repeats missed (checked only `w in 2..=3`).
  - ASCII `\0` was treated as Unicode, adding 128 to pool size.
  - Files with null bytes could be misclassified as plaintext.
- **Root Cause**: Incomplete pattern heuristics and control character classification gap in `audit_passphrase`.

---

## 2. What I Changed

### `src/audit.rs`
1. **`audit_embedded_container` Routine**:
   - Replaced basic `parse_svault_header` with full validation of container length ($\ge 50$ bytes for Poly1305 MAC), supported versions (v1, v2), valid flag bits, and KDF salt Shannon entropy ($\ge 2.5$).
   - Flags truncated or corrupted embedded containers inside PNG and WAV carriers as `SuspiciousAnomaly`.
2. **PNG Specification Compliance & APNG Steganalysis**:
   - Enforced that chunk 0 must be `IHDR` with length 13.
   - Enforced maximum chunk length of $2^{31} - 1$ bytes (RFC 2083).
   - Flagged duplicate `IHDR` chunks.
   - Added APNG (`acTL`, `fcTL`) stream detection and length validation.
3. **WAV Audio Carrier Specification & Format Hardening**:
   - Tracked and verified required `fmt ` and `data` subchunks.
   - Validated `num_channels > 0`, `sample_rate > 0`, and `bits_per_sample > 0`.
   - Restricted 16-bit PCM LSB analysis strictly to uncompressed 16-bit PCM (`audio_format == 1 && bits_per_sample == 16`). Reported non-16-bit audio in findings without false LSB inspection.
   - Detected missing 0x00 word-boundary padding byte on odd-sized subchunks at EOF.
4. **Decoy Container Audit Hardening**:
   - Captured `inspect_decoy` errors directly into `anomalies` as `Decoy container layout anomaly`.
5. **Memory Hardening (`zeroize`, R4)**:
   - Wrapped extracted `payload_buf` in `Zeroizing` in `audit_wav_carrier`.
   - Wrapped intermediate strings in `Zeroizing` in `check_repetitions` and `check_keyboard_walks`.
6. **Passphrase Pattern Detection & Text Validation**:
   - Added QWERTY vertical column walks (`1qaz`, `2wsx`, `3edc`, `4rfv`, `5tgb`, `6yhn`, `7ujm`, `8ik,`, `9ol.`, `0p`, `qaz`, `wsx`, `edc`, `rfv`, `tgb`, `yhn`, `ujm`).
   - Extended repetition checking to 4-grams (`w in 2..=4`) for passwords $\ge 8$ characters.
   - Handled ASCII control characters (`\0`..`\x1f`) separately from Unicode, warning in findings without inflating `pool_size`.
   - Filtered null bytes (`0x00`) in `is_likely_text` across the first 8 KB.
   - Expanded dictionary list with top common passwords (`testing`, `keyboard`, `hunter2`, `computer`, `sunshine`).
7. **Adversarial Unit Tests**:
   - Added 13 new unit tests (101 unit tests total in `src/audit.rs`).

### `tests/integration.rs`
- Added 3 adversarial integration tests:
  - `cli_audit_apng_carrier`: Tests APNG detection and clean verdict in JSON output.
  - `cli_audit_wav_non_standard_sample_rate`: Tests 192 kHz high-res audio carrier with chunk steganography.
  - `cli_audit_passphrase_vertical_keyboard_walk`: Tests vertical keyboard walk detection via CLI JSON report.
- Total integration tests: 39 tests.

### `CHANGELOG.md` & `dev_logs/WORK_LOG.md`
- Documented R2 adversarial audit fixes and updated test verification count to 140 tests.

---

## 3. Verification Record

- **Deep Verification (ran actual tests)**:
  - `cargo fmt --all -- --check`: Clean (exit code: 0)
  - `cargo clippy --all-targets -- -D warnings`: 0 warnings, passed (exit code: 0)
  - `cargo test --all-targets`: 140 passed (101 unit + 39 integration, 0 failed, exit code: 0)
  - `node scripts/check.mjs`: 100% passed (140 tests + asset integrity sweep passed, exit code: 0)
  - Zero AI attribution sweep: 0 violations across all project source files, manifests, docs, and tests.
- **Shallow Verification (manual only)**:
  - None; all audit behaviors verified through automated compiler and test harness runs.
- **Unverified aspects**:
  - Files $> 2$ GB (whole-file `fs::read` is used; chunked streaming is slated for M13).

---

## 4. Known Issues
- `Minor Robustness Risk`: Whole-file `fs::read` in `audit_file` loads entire carrier into RAM. Suitable for standard stego carriers (PNGs, WAVs under 500 MB) but not multi-GB files (deferred to M13).
- `Minor Robustness Risk`: WAV LSB audit only supports 16-bit uncompressed PCM; non-16-bit audio is noted in findings as unsupported for LSB steganography rather than partially decoded.

---

## 5. Remaining Risk & Next Step
- All R1-R4 requirements are fully implemented, verified, and hardened with 140 passing automated tests.
- The repository is in a clean, production-ready state for milestone M05.
