# Milestone M03 — Adversarial Review Round 2 & QA Handoff Report

> **Milestone:** M03 — Plausible Deniability / Dual-Password Decoy Vault (`src/decoy.rs`) & Proactive Evolution (M26+)  
> **Integrity Mode:** Development  
> **Target Version:** v0.3.0  
> **Reviewer:** Teamwork Adversarial Reviewer & QA (`reviewer_m03_r2`)  
> **Date:** 2026-10-12  

---

## 1. Adversarial Review Summary & Discrepancies Found

While Reviewer Round 1 (`reviewer_m03_r1`) correctly addressed timing asymmetry between slots and checked arithmetic in buffer allocations, a deeper adversarial audit in Round 2 revealed five critical latent defects, performance leaks, and container-confusion vulnerabilities:

### Issue 1: False-Positive Decoy Container Classification in `is_decoy_container` on Large Payloads
- **Input:** Container with a decoy payload > 16 bytes (e.g. 150 bytes) truncated inside the hidden slot such that total length exceeds 98 bytes (`DECOY_HEADER_LEN + 16 + MIN_HIDDEN_SLOT_LEN`).
- **Expected:** `is_decoy_container` returns `false` because the container does not contain a complete hidden slot.
- **Actual:** `is_decoy_container` returned `true`. The previous test `decoy_truncated_hidden_slot_rejected` only passed because the test payload happened to be small enough that the entire truncated buffer was under 98 bytes. For any realistic payload, `is_decoy_container` falsely recognized truncated containers.
- **Root Cause:** Hardcoded assumption of 16-byte decoy body length in `is_decoy_container` instead of dynamic `parse_decoy_body_len(container).is_ok()` validation.

### Issue 2: Container Type & Version Confusion in `open_v2`
- **Input:** A dual-password decoy container (`FLAG_DECOY` set, version 2) passed to `open_v2`.
- **Expected:** Immediate rejection with `Error::Format` notifying the caller that the container is a decoy container.
- **Actual:** `open_v2` accepted the container because `version == VERSION_V2`, interpreted the 4-byte `decoy_body_len` header field as ciphertext, ran an expensive 19 MiB Argon2id key derivation, and failed with a misleading `Error::Crypto("authentication failed — wrong passphrase or tampered container")`.
- **Root Cause:** Missing `(flags & FLAG_DECOY) != 0` check in `open_v2`.

### Issue 3: Structural Format Error Masking & Wasted Argon2id Probing in `open_decoy`
- **Input:** A decoy container with corrupted `decoy_body_len` (< 16 or exceeding buffer size), or a container where ChaCha20-Poly1305 MAC tag verified but the inner payload frame was corrupted.
- **Expected:** Immediate `Error::Format` reporting structural corruption without deriving keys.
- **Actual:** `open_decoy` failed to invoke `parse_decoy_body_len` upfront, proceeded to probe slots, and discarded underlying `Error::Format` errors, emitting a false `Error::Crypto("authentication failed — wrong passphrase or tampered container")`.
- **Root Cause:** Incomplete upfront header validation in `open_decoy` and blind fallback masking `Error::Format` as wrong-passphrase error.

### Issue 4: Redundant Argon2id Key Derivation on DPAPI Hardware Binding Failure in `open_decoy`
- **Input:** A DPAPI-bound container opened on an unauthorized machine or non-Windows platform.
- **Expected:** Immediate `Error::Dpapi` return in $1 \times$ time without running a second expensive Argon2id derivation on the hidden slot.
- **Actual:** When `open_decoy_slot` failed with `Error::Dpapi`, `open_decoy` still proceeded to call `open_primary_slot`, executing an unneeded ~500ms Argon2id key derivation before returning `Error::Dpapi`.
- **Root Cause:** Missing short-circuit on `Error::Dpapi` after `open_decoy_slot`.

### Issue 5: Unchecked Empty Passphrases in Decryption Entry Points
- **Input:** Empty string `""` passed to `crypto::open`, `open_primary_slot`, `open_decoy_slot`, or `open_v2`.
- **Expected:** Immediate `Error::Crypto("passphrase must not be empty")` without running Argon2id.
- **Actual:** Executed full Argon2id key derivation on empty passphrase, wasting ~500ms CPU time and 19 MiB RAM before authentication failure.
- **Root Cause:** Missing `passphrase.is_empty()` guard across several public decryption functions.

### Issue 6: Steganography LSB Carrier Coverage Gap
- **Input:** `svault embed-wav --lsb --decoy <decoy> ...`
- **Expected:** Machine-verified integration roundtrip for dual-password decoy container embedding inside 16-bit PCM WAV audio sample LSBs.
- **Actual:** Previous test suite only tested `--mode chunk`.
- **Root Cause:** Omission in previous integration test coverage.

---

## 2. Changes Applied in Round 2

### 2.1 `src/decoy.rs`
- **Dynamic Decoy Container Validation:**
  - Updated `is_decoy_container` to call `parse_decoy_body_len(container).is_ok()` ensuring container length dynamically matches `DECOY_HEADER_LEN + decoy_body_len + MIN_HIDDEN_SLOT_LEN`.
- **Upfront Decoy Length Check in `open_decoy`:**
  - Added `parse_decoy_body_len(container)?;` before slot probing, rejecting malformed containers immediately in 0.001ms.
- **DPAPI Short-Circuit & Format Error Preservation:**
  - Short-circuits immediately if `open_decoy_slot` returns `Error::Dpapi`.
  - Preserves and surfaces `Error::Format` from `open_primary_slot` if payload framing is corrupted after valid MAC authentication.
- **Anti-Confusion Guard in `open_v2`:**
  - Explicitly rejects containers with `FLAG_DECOY` set with `Error::Format`.
- **Empty Passphrase Defense:**
  - Added early `passphrase.is_empty()` checks to `open_primary_slot`, `open_decoy_slot`, and `open_v2`.
- **Checked Arithmetic in `open_decoy_slot`:**
  - Replaced `DECOY_HEADER_LEN + decoy_body_len` with `DECOY_HEADER_LEN.checked_add(decoy_body_len)`.
- **New Unit Tests Added:**
  - `decoy_is_decoy_container_large_body_truncated_hidden_slot`: verifies `!is_decoy_container` on 150-byte decoy container truncated in hidden slot.
  - `decoy_open_v2_rejects_decoy_container`: verifies `open_v2` rejects decoy containers.
  - `decoy_empty_passphrase_rejected_in_all_entry_points`: verifies all decryption entry points immediately reject `""`.
  - Updated `decoy_body_len_underflow_rejected`: verifies `Error::Format` is preserved.

### 2.2 `src/crypto.rs`
- Added early `passphrase.is_empty()` check to `crypto::open`.

### 2.3 `tests/integration.rs`
- Added `cli_embed_wav_lsb_direct_decoy_roundtrip`: verifies direct `--decoy` embedding into 16-bit PCM WAV LSBs, `inspect` auto-detection, and extraction of both primary and decoy payloads.
- Added `cli_empty_passphrase_rejected`: verifies CLI cleanly rejects empty passphrase.

---

## 3. Verification Record

- **Deep Verification (ran actual tests):**
  - `cargo fmt --all`: Clean, exit code 0.
  - `cargo clippy --all-targets -- -D warnings`: 0 warnings, exit code 0.
  - `cargo test --all-targets`: 65 tests passed (50 unit + 15 integration), 0 failed, exit code 0.
  - `node scripts/check.mjs`: Clean exit code 0.
- **Shallow Verification (manual only):**
  - None; all claims machine-verified.
- **Unverified aspects:**
  - Linux/macOS DPAPI mock behavior under cross-compilation (validated conditionally via `#[cfg(not(windows))]` error returns).

---

## 4. Known Issues

- `Fatal Functional Bug`: None.
- `Shallow Verification`: None.
- `Minor Robustness Risk`: Very large files (>2GB) load entirely into memory buffers for encryption/decryption (tracked for M13 Chunked Streaming).

---

## 5. Remaining Risk & Next Step

Milestone M03 is thoroughly hardened, adversarial defects have been fixed, and all 65 tests pass. The codebase is ready for Milestone M04 (Shamir's Secret Sharing `M-of-N` Key Splitting, `src/shamir.rs`).
