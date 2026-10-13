> [!WARNING] **Skepticism Disclaimer**
> While `node scripts/check.mjs` was passing before this round, adversarial probing exposed unpadded carrier odd-chunk misalignment, corrupted RIFF container sizing over trailing non-chunk metadata, silent masking of missing fmt/data chunks in Auto mode, and stale chunk payload masking during cross-mode re-embedding, which I reproduced with failing unit tests, fixed, and verified across 37 passing tests.

## 1. What the prior attempt got wrong
- **Issue 1: Carrier odd subchunk missing EOF pad byte broke RIFF 2-byte chunk alignment in `embed_in_wav_chunk`**
  - Input: WAV carrier containing an odd-sized subchunk at EOF (e.g. 5 bytes) missing the optional/terminal 0x00 pad byte, embedded via `embed_in_wav(..., WavMode::Chunk)`.
  - Expected: Embedded `svLt` chunk remains aligned to a 2-byte boundary and extracts cleanly.
  - Actual: `clean_chunks.len()` was odd. `embed_in_wav_chunk` appended `svLt` at an odd byte offset. When `extract_from_wav_chunk` scanned the file, it advanced by 2-byte chunk alignment past the odd chunk, landing 1 byte past the start of `svLt` (`vLt...`), failing with `no hidden ShadowVault chunk payload found in WAV audio carrier`.
  - Root cause: (a) `strip_stego_chunks` did not pad odd chunks that lacked terminal padding; (b) `embed_in_wav_chunk` did not ensure `clean_chunks.len()` was 2-byte aligned before appending `svLt`.

- **Issue 2: Trailing non-chunk metadata incorrectly included in RIFF header chunk size**
  - Input: Carrier WAV with trailing non-chunk metadata (e.g. ID3v2 tag at EOF), embedded via `embed_in_wav(..., WavMode::Chunk)`.
  - Expected: RIFF header size at bytes 4..8 (`riff_size`) describes only RIFF chunk content (`8 + riff_size + trailing.len() == stego.len()`), leaving trailing non-chunk bytes outside the RIFF container.
  - Actual: `riff_size` was computed as `out.len() - 8`, which included `trailing.len()`. Standard RIFF parsers reading the container attempted to parse the trailing non-chunk bytes as another RIFF subchunk and failed.
  - Root cause: `embed_in_wav_chunk` set `riff_size = out.len().saturating_sub(8)` rather than `(out.len() - trailing.len()).saturating_sub(8)`.

- **Issue 3: Stale `svLt` chunk payload masked newly embedded LSB payload in `ExtractWavMode::Auto`**
  - Input: Carrier WAV previously containing an `svLt` chunk (from `--mode chunk`), re-embedded with `--lsb`, and extracted via default Auto mode (`svault extract-wav`).
  - Expected: Extract the newly embedded LSB payload.
  - Actual: `embed_in_wav(..., WavMode::Lsb)` did not strip the prior `svLt` chunk. In `ExtractWavMode::Auto`, `extract_from_wav_chunk` matched the old `svLt` chunk first, returning the stale chunk secret instead of the new LSB secret.
  - Root cause: Missing stego chunk stripping in `embed_in_wav(..., WavMode::Lsb)`.

- **Issue 4: Corrupted WAV carrier missing required `fmt ` or `data` chunk silently masked in `ExtractWavMode::Auto`**
  - Input: WAV carrier missing required `'fmt '` chunk or `'data'` chunk, extracted via Auto mode.
  - Expected: Surface explicit carrier format error (`WAV file missing required 'fmt ' chunk`).
  - Actual: Fell back to LSB, LSB returned `WAV file missing required 'fmt ' chunk`, but `is_lsb_corruption_error` did not match `"missing required"`, falling through to generic `no hidden ShadowVault payload found in WAV audio carrier`.
  - Root cause: `is_lsb_corruption_error` omitted `"missing required"` check.

## 2. What I changed
- `src/wav.rs`:
  - Updated `embed_in_wav` when `mode == WavMode::Lsb` to strip prior `svLt` chunks via `strip_stego_chunks`, update RIFF size header if stripped, and embed cleanly into LSB to prevent stale chunk masking in Auto mode.
  - Updated `embed_in_wav_chunk` to pad `clean_chunks` to an even length (`clean_chunks.len() % 2 == 1 -> push(0x00)`) guaranteeing 2-byte RIFF chunk alignment before appending `svLt`.
  - Fixed `riff_size` calculation in `embed_in_wav_chunk` to `(out.len() - trailing.len()).saturating_sub(8) as u32` so trailing non-chunk bytes remain outside the RIFF container.
  - Updated `strip_stego_chunks` to append a pad byte to `clean_chunks` when an odd-sized chunk at EOF was missing its 0x00 pad byte.
  - Expanded `is_lsb_corruption_error` to include `"missing required"` so missing `fmt ` or `data` chunk errors surface accurately in Auto mode.
  - Added 4 unit tests: `wav_chunk_carrier_with_unpadded_odd_chunk`, `wav_riff_size_excludes_trailing_non_chunk_bytes`, `wav_reembed_lsb_over_chunk_stego_replaces_stale_chunk_in_auto`, and `wav_auto_detects_carrier_missing_fmt_or_data_chunk`.
- `tests/integration.rs`:
  - Added CLI auto extraction verification for LSB mode without `--mode lsb` flag.
  - Added `cli_wav_cross_mode_reembedding_and_auto_extract` integration test confirming CLI roundtrip when re-embedding across chunk and LSB modes.

## 3. Verification Record
- **Deep Verification (ran actual tests):**
  - `node scripts/check.mjs`: Exited 0 with all checks passed (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`).
  - Unit tests: 31 tests passed in `src/main.rs` (25 in `wav.rs`, 5 in `crypto.rs`, 2 in `stego.rs`, 1 in `shred.rs`).
  - Integration tests: 6 tests passed in `tests/integration.rs` (`cli_version_and_help_work`, `cli_encrypt_inspect_and_decrypt_roundtrip`, `cli_png_embed_and_extract_roundtrip`, `cli_wav_chunk_embed_inspect_and_extract_roundtrip`, `cli_wav_lsb_embed_inspect_and_extract_roundtrip`, `cli_wav_cross_mode_reembedding_and_auto_extract`).
- **Shallow Verification (manual only):**
  - Attribution check: 0 AI tool attributions found across repository.
  - License and NOTICE header check: Apache-2.0 and GHSFS NOTICE headers present.
- **Unverified aspects:**
  - Physical 4 GiB disk allocation on disk during test execution (boundary checked via 64-bit integer arithmetic; physical 4 GiB allocation omitted to avoid CI OOM).

## 4. Known Issues
- `Minor Robustness Risk` — Non-standard audio formats (e.g. IEEE float 3 or ADPCM in WAV) are rejected in LSB mode with format error; RIFF subchunk mode (`--mode chunk`) accepts any valid RIFF/WAVE container regardless of audio encoding.

## 5. Remaining risk & next step
- Milestone M02 implementation is now resilient to carrier subchunk alignment irregularities, trailing metadata container sizing, cross-mode re-embedding collisions, and malformed carrier error masking.
- Next step: Milestone M02 review is complete and ready for victory auditor / orchestrator handoff.
