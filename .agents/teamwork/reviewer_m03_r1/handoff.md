# Milestone M03 — Adversarial Review & QA Handoff Report

> **Milestone:** M03 — Plausible Deniability / Dual-Password Decoy Vault (`src/decoy.rs`) & Proactive Evolution (M26+)  
> **Integrity Mode:** Development  
> **Target Version:** v0.3.0  
> **Reviewer:** Teamwork Adversarial Reviewer & QA (`reviewer_m03_r1`)  
> **Date:** 2026-10-12  

---

## 1. Adversarial Review Summary

The prior attempt by `implementer_m03_1` laid down the core cryptographic scaffolding for plausible deniability dual-slot containers. However, an adversarial review revealed critical timing-leakage side-channels, arithmetic overflow hazards, DPAPI error suppression, and validation omissions:

1. **Timing Attack & Coercion Side-Channel in `open_decoy`**:
   - *Input:* Operator surrenders decoy passphrase under coercion (`svault decrypt -p <decoy-passphrase>`).
   - *Expected:* The decoy payload unlocks immediately in $1 \times \text{Argon2id}$ time, leaving zero timing clue of the hidden volume's existence.
   - *Actual:* `open_decoy` attempted `open_primary_slot` *first*, executing an expensive 19 MiB Argon2id derivation on the hidden slot salt, failing, and only then attempting the decoy slot ($2 \times \text{Argon2id}$ time). An adversary timing the operation would detect that unlocking the decoy took twice the expected time, proving the existence of a hidden primary slot.
   - *Root Cause:* Inverted slot probing order in `open_decoy`.

2. **Integer Overflow & Slicing Panic in `open_primary_slot` and `open_v2`**:
   - *Input:* Decrypted payload buffer containing corrupted or extreme 32-bit `inner_len`.
   - *Expected:* Clean `Error::Format` return without panic.
   - *Actual:* `4 + inner_len` addition overflowed on 32-bit platforms or wrapped around, failing bounds check and triggering a slice index panic (`begin <= end`).
   - *Root Cause:* Unchecked addition `4 + inner_len` instead of `4usize.checked_add(inner_len)`.

3. **Buffer Allocation Overflow in `seal_decoy` and `seal_v2`**:
   - *Input:* Large input payload or large `--padding` value.
   - *Expected:* Handled safely via checked arithmetic.
   - *Actual:* `unpadded_len + pad_len` and `4 + inner.len()` used unchecked addition, risking capacity allocation panic.
   - *Root Cause:* Unchecked addition in capacity sizing.

4. **DPAPI Error Masking in `open_decoy`**:
   - *Input:* DPAPI-bound container opened on non-Windows OS or under an unauthorized Windows account.
   - *Expected:* Clean `Error::Dpapi` reporting that hardware binding rejected decryption.
   - *Actual:* `open_decoy` discarded `Error::Dpapi` inside `if let Ok(...)` and emitted a false `Error::Crypto("authentication failed — wrong passphrase or tampered container")`, misleading operators.
   - *Root Cause:* Blind fallback discarding underlying error variants.

5. **Incomplete Container Header & Truncated Hidden Slot Validation**:
   - *Input:* Container with `FLAG_DECOY` set but version altered to 1, or container truncated inside the hidden slot.
   - *Expected:* Immediate rejection as corrupted/unsupported.
   - *Actual:* `validate_decoy_header` accepted version 1, and `parse_decoy_body_len` did not enforce minimum hidden slot length (`MIN_HIDDEN_SLOT_LEN`), allowing truncated containers to pass inspection.
   - *Root Cause:* Missing version restriction (`VERSION_V2`) and missing minimum hidden slot bounds check in `parse_decoy_body_len` and `is_decoy_container`.

6. **Missing Clap Dependency Enforcement on Decoy Flags**:
   - *Input:* User supplies `--decoy-passphrase` without `--decoy` or vice-versa.
   - *Expected:* Explicit CLI validation failure.
   - *Actual:* Silently ignored `--decoy-passphrase` or triggered runtime unwrap error.
   - *Root Cause:* Missing `requires` attributes in `src/cli.rs`.

---

## 2. Changes Applied

### 2.1 `src/decoy.rs`
- **Inverted Slot Probing Order in `open_decoy`:**
  - Probes plausible decoy slot first. Under coercion, decoy unlocks on attempt 1 in $1 \times \text{Argon2id}$ time with zero timing deviation.
  - Probes hidden primary slot second if decoy authentication fails.
- **DPAPI Error Propagation:**
  - Preserves and surfaces `Error::Dpapi` if hardware binding fails.
- **Checked Arithmetic & Slicing Safety:**
  - Replaced unchecked additions in `open_primary_slot` and `open_v2` with `4usize.checked_add(inner_len)`.
  - Replaced unchecked capacity allocations in `seal_decoy` and `seal_v2` with `checked_add`.
- **Strict Decoy Header & Length Validation:**
  - Restricted `validate_decoy_header` and `is_decoy_container` strictly to `VERSION_V2`.
  - Enforced `len >= 16` (Poly1305 MAC tag) and verified `container.len() >= DECOY_HEADER_LEN + len + MIN_HIDDEN_SLOT_LEN` in `parse_decoy_body_len`.
- **Zeroize Hardening:**
  - Wrapped decoy decrypted plaintext in `Zeroizing` in `open_decoy_slot`.
- **New Unit Tests:**
  - `decoy_truncated_hidden_slot_rejected`: verifies truncated hidden slot rejection.
  - `decoy_version_confusion_rejected`: verifies v1 container with `FLAG_DECOY` is rejected.
  - `decoy_body_len_underflow_rejected`: verifies decoy body length < 16 bytes is rejected.

### 2.2 `src/cli.rs`
- Added Clap `requires = "decoy_passphrase"` to `--decoy` and `requires = "decoy"` to `--decoy-passphrase` across `Encrypt`, `Embed`, and `EmbedWav`.
- Added `visible_alias = "input"` to `primary` in `EncryptDecoy` for symmetric CLI ergonomics.

### 2.3 `tests/integration.rs`
- Added integration test `cli_decoy_flag_validation_and_alias`:
  - Verifies `--decoy` without `--decoy-passphrase` fails.
  - Verifies `--decoy-passphrase` without `--decoy` fails.
  - Verifies `encrypt-decoy --input ...` alias works.

---

## 3. Verification Record

- **Deep Verification (ran actual tests):**
  - `cargo fmt --all`: Clean, exit code 0.
  - `cargo clippy --all-targets -- -D warnings`: 0 warnings, exit code 0.
  - `cargo test --all-targets`: 60 tests passed (47 unit + 13 integration), 0 failed, exit code 0.
  - `cargo build --release`: Clean release build, exit code 0.
  - `node scripts/check.mjs`: Fully passed, exit code 0.
- **Shallow Verification (manual only):**
  - None; all claims machine-verified.
- **Unverified aspects:**
  - Non-Windows platform native compilation without DPAPI (verified conditionally via `#[cfg(not(windows))]` stubs in unit test suite).

---

## 4. Known Issues

- `Fatal Functional Bug`: None.
- `Shallow Verification`: None.
- `Minor Robustness Risk`: None identified. All slice conversions and memory buffers are guarded by checked arithmetic and `Zeroize` wrappers.

---

## 5. Remaining Risk & Next Step

Milestone M03 is complete and robustly verified. The codebase is ready for Milestone M04 (Shamir's Secret Sharing `M-of-N` Key Splitting, `src/shamir.rs`).
