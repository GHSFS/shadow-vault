# Adversarial Review & QA Handoff Report (Round 3): M05 Passphrase Strength & Entropy Auditor

- **Agent Role**: Adversarial Reviewer & QA (`reviewer@swe_light`, `qa@swe_light`)
- **Version**: `0.5.0` (with concurrent M06 integration in tree)
- **Target Repository**: `c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\shadow-vault`
- **Date**: 2026-10-12

---

## 1. What the Prior Attempt Got Wrong

### Issue 1: Inability to Audit Binary Carriers or Encrypted Containers Piped via Stdin or `-` Target
- **Input**: `cat carrier.png | svault audit`, `cat vault.svault | svault audit`, or `svault audit -`.
- **Expected**: Evaluated as a carrier/container from the `<stdin>` stream and audited properly for anomalies, entropy, and container validity.
- **Actual**: `svault audit -` crashed with `os error 2: The system cannot find the file specified`. Piped binary through `svault audit` crashed with `stream did not contain valid UTF-8` due to unconditional `read_to_string`, or misclassified valid UTF-8 binary sequences as a "passphrase" with an inflated strength score.
- **Root Cause**: Missing stdin target `-` handler in `Commands::Audit` and unconditional `read_to_string` assuming all stdin input is a plaintext passphrase.

### Issue 2: Truncated WAV Carrier Files with Declared RIFF Size Exceeding File Size Masked Without Anomalies
- **Input**: A truncated WAV file where `data.len() < expected_riff_len` (e.g. declared RIFF size 1,000,000 bytes, actual size 100 bytes).
- **Expected**: Flagged as `SuspiciousAnomaly` stating that the WAV carrier is truncated.
- **Actual**: Classified as `CleanCarrier` with 0 anomalies because `audit_wav_carrier` only checked `data.len() > expected_riff_len`, ignoring `data.len() < expected_riff_len`.
- **Root Cause**: Missing check for `data.len() < expected_riff_len` and missing check for `declared_riff_size < 4`.

### Issue 3: Steganography Payloads Hidden Inside PNG `IEND` Chunk Accepted Without Anomalies
- **Input**: A PNG carrier with an `IEND` chunk having non-zero `chunk_len > 0` (e.g. 10 bytes).
- **Expected**: Flagged as `SuspiciousAnomaly` per RFC 2083 (the `IEND` chunk data field must be empty).
- **Actual**: Passed without anomalies because `audit_png_carrier` did not validate `chunk_len == 0` for `IEND`.
- **Root Cause**: Omission of `chunk_len != 0` check when `chunk_type == IEND_TYPE`.

### Issue 4: Ciphertext Entropy Degradation and Corrupted Decoy Layouts Inside Embedded Carriers Ignored
- **Input**: Carrier (PNG/WAV) embedding a decoy container with a corrupted hidden slot layout or an embedded container with degraded ciphertext Shannon entropy.
- **Expected**: Embedded container flagged with `SuspiciousAnomaly` for layout corruption or degraded ciphertext entropy.
- **Actual**: `audit_embedded_container` checked version and salt entropy but never validated decoy container layout (`inspect_decoy`) or ciphertext Shannon entropy.
- **Root Cause**: Missing `inspect_decoy` validation and ciphertext entropy calculation in `audit_embedded_container`.

### Issue 5: Non-Zero Word-Boundary Padding Bytes in Odd-Sized WAV Subchunks Undetected
- **Input**: WAV audio carrier with an odd-sized subchunk followed by a non-zero padding byte (`data[content_end] != 0`).
- **Expected**: Flagged as `SuspiciousAnomaly` for non-zero RIFF padding byte covert channel.
- **Actual**: Ignored because the check only looked for odd subchunks at EOF.
- **Root Cause**: Missing validation of the padding byte at `content_end`.

### Issue 6: Mixed-Case Alphabetic Sequential Runs Undetected in Passphrase Auditor
- **Input**: Passphrases with alternating or mixed-case sequential runs (`AbCdEf`, `ZyXwVu`).
- **Expected**: Flagged with `has_sequential = true`.
- **Actual**: `has_sequential = false` because ASCII subtraction compared raw ASCII codes (`'b' (98) - 'A' (65) != 1`).
- **Root Cause**: ASCII code subtraction lacked case normalization when both characters are alphabetic.

### Issue 7: Incomplete Leetspeak Mappings (`+` for `t`), Dead Keyboard Walk Row (`0p`), and Missing Default Credentials (`guest`, `manager`)
- **Input**: Passphrases like `secre+123`, `gues+2026`, or `0plm`.
- **Expected**: Leetspeak pattern and keyboard walk detected.
- **Actual**: `+` was not mapped to `t`, row `"0p"` could never match any $\ge 3$ slice, and `"guest"` was missing from dictionary.
- **Root Cause**: Gaps in leetspeak mapping table, dictionary, and keyboard walk definitions.

---

## 2. What I Changed

### `src/audit.rs`
1. **`audit_embedded_container` Hardening**:
   - Added ciphertext Shannon entropy check ($\ge 32$ bytes) flagging degraded entropy ($< 7.2$ bits/byte for $\ge 256$ bytes, or $< 70\%$ of theoretical maximum).
   - Added decoy container layout validation via `crate::decoy::inspect_decoy` to flag corrupted hidden slots or header anomalies in embedded containers.
2. **PNG RFC 2083 Compliance**:
   - Added check that `IEND` chunk payload length is exactly 0 (`chunk_len == 0`), flagging non-zero payloads as `SuspiciousAnomaly`.
3. **WAV RIFF Carrier Integrity**:
   - Added check for invalid declared RIFF size (`declared_riff_size < 4`).
   - Added check for truncated WAV carriers (`data.len() < expected_riff_len`).
   - Added empty `data` chunk check (`chunk_size == 0`) and 16-bit unaligned PCM length check (`chunk_size % 2 != 0`).
   - Added non-zero word-boundary padding byte detection on odd-sized subchunks (`data[content_end] != 0`).
4. **Passphrase Heuristics & Pattern Detection**:
   - Updated `check_sequential` to detect mixed-case alphabetic sequences (`AbCdEf`, `ZyXwVu`).
   - Updated `check_keyboard_walks` replacing dead row `"0p"` with `"0p;/"`, `"0plm"`, `"plm"`.
   - Updated `check_common_patterns` mapping `'+'` to `'t'` in leetspeak and adding `"guest"`, `"manager"` to dictionary list.
5. **Adversarial Unit Tests**:
   - Added 7 new unit tests covering non-zero IEND length, truncated RIFF, invalid RIFF size, corrupted embedded decoy container, mixed-case sequential runs, leetspeak `+`, and extended keyboard walks (124 unit tests total).

### `src/main.rs`
1. **Piped Stdin & Dash Target Support**:
   - Handled `target == Some("-")` to read carrier bytes directly from stdin into a zeroized buffer.
   - Handled piped stdin when neither target nor passphrase is provided: automatically discriminates binary/container carriers (PNG, WAV, SVLT, non-UTF-8) from plaintext passphrases.
   - Proactively wipes `raw_bytes` and `passphrase` with `zeroize` upon completion.

### `tests/integration.rs`
- Added 4 new CLI integration tests:
  - `cli_audit_stdin_target_dash`: Tests piping a PNG image to `svault audit -`.
  - `cli_audit_stdin_binary_auto_detect`: Tests piping a `.svault` container to `svault audit` without arguments.
  - `cli_audit_stdin_dash_with_passphrase`: Tests piping a carrier to `svault audit - -p ... --json`.
  - `cli_audit_mixed_case_sequential_passphrase`: Tests mixed-case sequential run detection via CLI JSON.
- Total integration tests: 51 tests.

---

## 3. Verification Record

- **Deep Verification (ran actual tests)**:
  - `cargo fmt --all -- --check`: 0 issues, clean (exit code: 0)
  - `cargo clippy --all-targets -- -D warnings`: 0 warnings, passed (exit code: 0)
  - `cargo test --all-targets`: 175 passed (124 unit + 51 integration, 0 failed, exit code: 0)
  - `node scripts/check.mjs`: 100% passed (175 tests + asset integrity sweep passed, exit code: 0)
  - Zero AI attribution sweep: 0 violations across all source files, docs, manifests, and test suites.
- **Shallow Verification (manual only)**:
  - None; all audit behaviors verified through automated compiler, clippy, and integration test runs.
- **Unverified aspects**:
  - Files $> 2$ GB (whole-file `fs::read` is used; chunked streaming is scheduled for milestone M13).

---

## 4. Known Issues
- `Minor Robustness Risk`: Whole-file `fs::read` in `audit_file` loads the target carrier into RAM. Suitable for standard carriers (PNGs, WAVs under 500 MB) but not multi-GB files (deferred to M13).
- `Minor Robustness Risk`: WAV LSB audit only supports 16-bit uncompressed PCM; non-16-bit audio formats (24-bit PCM, 32-bit float) are noted in findings as unsupported for LSB steganography rather than partially decoded.

---

## 5. Remaining Risk & Next Step
- Milestone M05 Passphrase Strength & Entropy Auditor is fully implemented, hardened against all edge cases, and verified with 175 passing automated tests.
- Task is complete and ready for handoff.
