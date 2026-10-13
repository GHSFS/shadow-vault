# Milestone M03 — Adversarial Review Round 3 & QA Final Handoff Report

> **Milestone:** M03 — Plausible Deniability / Dual-Password Decoy Vault (`src/decoy.rs`) & Proactive Evolution (M26+)  
> **Integrity Mode:** Development  
> **Target Version:** v0.3.0  
> **Reviewer:** Teamwork Adversarial Reviewer & QA (`reviewer_m03_r3`)  
> **Date:** 2026-10-12  

---

## 1. Adversarial Review Summary & Discrepancies Found

A comprehensive adversarial audit of the Milestone M03 implementation and prior attempts revealed six subtle latent defects, memory security exposures, and bounds issues:

### Issue 1: Slicing Index Out-of-Bounds Panic Risk in `parse_decoy_body_len`
- **Input:** Buffer smaller than `DECOY_HEADER_LEN` (38 bytes) passed to `parse_decoy_body_len`.
- **Expected:** Safe return of `Err(Error::Format("decoy container header truncated"))`.
- **Actual:** Direct slicing `container[HEADER_LEN..DECOY_HEADER_LEN]` (indices 34..38) caused a thread panic on undersized slices.
- **Root Cause:** Missing length boundary guard `if container.len() < DECOY_HEADER_LEN` at the start of `parse_decoy_body_len`.

### Issue 2: Framing Inconsistency and Wasted KDF Overhead on Undersized Hidden Slot
- **Input:** Decoy container with hidden slot length between 44 and 47 bytes (matching previous `MIN_HIDDEN_SLOT_LEN = 44`).
- **Expected:** Immediate rejection before key derivation, because the hidden payload frame requires at minimum 4 bytes length + 16 bytes tag = 20 bytes ciphertext (`SALT_LEN (16) + NONCE_LEN (12) + 20 = 48` bytes minimum).
- **Actual:** `MIN_HIDDEN_SLOT_LEN` was set to 44 bytes (only 16 bytes ciphertext, representing 0 bytes payload), causing `open_primary_slot` to run an expensive 19 MiB Argon2id key derivation (~500ms) only to fail later at frame unpacking.
- **Root Cause:** Underestimated minimum framing size for hidden slot ciphertext in `MIN_HIDDEN_SLOT_LEN` and absence of early ciphertext length validation before `derive_key`.

### Issue 3: Error Masking and Fallthrough on Empty Passphrases in `open_decoy_explicit`
- **Input:** `open_decoy_explicit` called with `decoy_passphrase: Some("")` or `passphrase: Some("")`.
- **Expected:** Return `Err(Error::Crypto("passphrase must not be empty"))`.
- **Actual:** The `if !decoy_p.is_empty()` guard caused the empty string to be skipped as if not supplied, falling through to `passphrase` or returning `"either --passphrase or --decoy-passphrase must be provided"`, masking empty passphrase errors.
- **Root Cause:** Guard `if !p.is_empty()` treated an empty string as "not provided" instead of validating that supplied passphrases are non-empty.

### Issue 4: Stack Memory Bleed of Derived Key Material in `derive_key`
- **Input:** `derive_key` updating hasher with `*key`.
- **Expected:** Key material passed by reference to hashing functions directly from zeroized buffer.
- **Actual:** `hasher.update(*key)` dereferenced `key` by value, copying 32 sensitive bytes onto the un-zeroized stack frame before passing a reference to SHA-256.
- **Root Cause:** Value dereference `*key` instead of slice borrow `key.as_slice()`.

### Issue 5: Redundant Plaintext Heap Allocation and Clone in `open_decoy_slot`
- **Input:** Decrypted decoy payload in `open_decoy_slot`.
- **Expected:** Return decrypted `Vec<u8>` directly with single allocation.
- **Actual:** Wrapped `plain: Vec<u8>` in `Zeroizing::new(plain)` and then called `.to_vec()`, allocating a duplicate heap buffer while zeroing only the initial instance, leaving an extra copy of the decoy plaintext in memory.
- **Root Cause:** Calling `.to_vec()` on `Zeroizing<Vec<u8>>`.

### Issue 6: 32-bit Integer Truncation in File Shredder (`src/shred.rs`)
- **Input:** Shredding a file larger than 4GB on 32-bit architectures.
- **Expected:** Shred full `len: u64` bytes.
- **Actual:** `let mut remaining = len as usize;` truncated the file size to `len & 0xFFFFFFFF`.
- **Root Cause:** Premature cast to `usize` before chunked write loop.

### Issue 7: Flaky Shannon Entropy Assertion on Undersized Sample
- **Input:** Running `decoy_hidden_slot_indistinguishable_from_random` with default small padding (~300 bytes sample).
- **Expected:** Deterministically passing Shannon entropy assertion across all test runs.
- **Actual:** In ~10% of test runs with default padding, random coupon-collector distribution across 256 byte values resulted in an entropy of ~7.180 bits/byte, causing `assert!(entropy > 7.2)` to intermittently fail.
- **Root Cause:** High statistical variance when estimating discrete entropy over a 256-symbol alphabet with only ~300 samples ($E[\text{empty buckets}] \approx 79$).
- **Resolution:** Tested with explicit 2048-byte padding sample ($E[\text{samples/bucket}] = 8$) and asserted `entropy > 7.7`, eliminating flakiness completely.

---

## 2. Changes Applied in Round 3

### 2.1 `src/decoy.rs`
- **Header Bounds Safety:** Added `if container.len() < DECOY_HEADER_LEN { return Err(Error::Format(...)); }` inside `parse_decoy_body_len`.
- **Framing Boundary Correction:** Updated `MIN_HIDDEN_SLOT_LEN` from 44 to 48 bytes (`SALT_LEN + NONCE_LEN + 4 + 16`).
- **Early Ciphertext Length Guard:** Added `if hidden_ciphertext.len() < 20` in `open_primary_slot` and `if ciphertext.len() < 16` in `open_decoy_slot` to reject truncated ciphertext immediately before running Argon2id.
- **Format Error Short-Circuit:** In `open_decoy`, short-circuits on `if let Err(Error::Format(e)) = decoy_res`.
- **Strict Explicit Passphrase Validation:** Updated `open_decoy_explicit` to immediately return `Error::Crypto("passphrase must not be empty")` when an empty string is passed in `Some("")`.
- **Single Heap Allocation:** Replaced `let zeroizing_plain = Zeroizing::new(plain); Ok(zeroizing_plain.to_vec())` with `Ok(plain)` in `open_decoy_slot`.
- **Statistical Flakiness Fix in Entropy Test:** Increased test sample padding to 2048 bytes and asserted `entropy > 7.7`.
- **New Unit Tests Added:**
  - `decoy_parse_body_len_truncated_header_does_not_panic`: verifies buffer < 38 bytes returns error without panic.
  - `decoy_ciphertext_underflow_in_hidden_slot`: verifies hidden slot with < 20 bytes ciphertext fails with format error before KDF.
  - Updated `decoy_empty_passphrase_rejected_in_all_entry_points`: verifies `open_decoy_explicit` with empty passphrases.

### 2.2 `src/crypto.rs`
- In `derive_key`, replaced `hasher.update(*key)` with `hasher.update(key.as_slice())` to prevent stack copying of key material.

### 2.3 `src/shred.rs`
- Fixed `shred_file` remaining length loop to track `u64` and subtract `to_write as u64`, ensuring 64-bit bounds safety on all targets.

### 2.4 `tests/integration.rs`
- Added `cli_encrypt_decoy_identical_passphrases_rejected`: verifies CLI rejects identical primary and decoy passphrases.
- Added `cli_decoy_command_aliases_work`: verifies `enc-decoy` and `dec-decoy` subcommands work end-to-end.
- Added `cli_decrypt_empty_passphrases_rejected`: verifies CLI cleanly rejects empty decryption passphrases.

---

## 3. Verification Record

- **Deep Verification (ran actual tests):**
  - `cargo fmt --all`: Clean, exit code 0.
  - `cargo clippy --all-targets -- -D warnings`: 0 warnings, exit code 0.
  - `cargo test --all-targets`: 70 tests passed (52 unit + 18 integration), 0 failed, exit code 0.
  - `node scripts/check.mjs`: Clean exit code 0.
- **Shallow Verification (manual only):**
  - None; all claims machine-verified.
- **Unverified aspects:**
  - Linux/macOS DPAPI behavior under cross-compilation (validated via `#[cfg(not(windows))]` error stubs).

---

## 4. Known Issues

- `Fatal Functional Bug`: None.
- `Shallow Verification`: None.
- `Minor Robustness Risk`: Very large files (>2GB) load entirely into memory buffers for encryption/decryption (tracked for M13 Chunked Streaming).

---

## 5. Remaining Risk & Next Step

Milestone M03 is fully hardened, memory-audited, bounds-safe, and passes all 70 machine-verified tests. The milestone is ready for Sentinel Victory Audit.
