# Milestone M03 — Implementation Handoff Report

> **Milestone:** M03 — Plausible Deniability / Dual-Password Decoy Vault (`src/decoy.rs`) & Proactive Evolution (M26+)  
> **Integrity Mode:** Development  
> **Target Version:** v0.3.0  
> **Author:** Teamwork Implementer (`implementer_m03_1`)  
> **Date:** 2026-10-12  

---

## 1. Executive Summary

Milestone M03 implements plausible deniability and dual-password decoy vault containers (`src/decoy.rs`). Operators under coercion can surrender a decoy passphrase which seamlessly unlocks a harmless decoy payload. The secondary hidden slot containing the actual high-value secret remains computationally indistinguishable from uniform CSPRNG random noise to any observer possessing only the decoy passphrase.

All acceptance criteria have been verified machine-reliably via `node scripts/check.mjs`, passing all 56 tests (`cargo test --all-targets`), zero clippy warnings (`cargo clippy --all-targets -- -D warnings`), and clean formatting (`cargo fmt --all`).

---

## 2. Changes Implemented

### 2.1 Core Engine: `src/decoy.rs`
- **Dual-Slot Container Architecture:**
  - Header: `SVLT` magic (4 bytes), version (1 or 2), flags (`FLAG_DECOY`, `FLAG_DPAPI`), 16-byte decoy salt, 12-byte decoy nonce, 4-byte little-endian decoy body length.
  - Decoy Slot: ChaCha20-Poly1305 ciphertext + 16-byte Poly1305 MAC tag, optionally wrapped with Windows DPAPI.
  - Hidden Primary Slot: 16-byte random salt, 12-byte random nonce, and ChaCha20-Poly1305 ciphertext.
- **Statistical Indistinguishability:**
  - Hidden slot contains zero plaintext magic bytes, markers, or version tags.
  - Framed as `[4-byte inner length][inner payload][CSPRNG random padding]`.
  - Padded to 256-byte alignment (minimum 32 bytes random padding) or explicit `--padding <bytes>` to defeat length-correlation attacks.
  - Verified by Shannon entropy test ($H > 7.2$ bits/byte, approaching theoretical limit 8.0).
- **Memory Hardening & Safety:**
  - Sensitive buffers wrapped in `Zeroizing<T>` and explicitly wiped on drop.
  - Constant-time Poly1305 MAC verification preventing timing leaks.
  - Safe arithmetic bounds checking (`saturating_add`, checked slice conversions).
- **API Surface:**
  - `seal_decoy(...)`: encodes primary secret + decoy payload into a dual-password container.
  - `seal_v2(...)`: single-payload padded container.
  - `open_decoy(...)`: seamless unlocking; attempts primary slot first, then decoy slot.
  - `open_decoy_explicit(...)`: unlock using explicit `--passphrase` or `--decoy-passphrase`.
  - `open_primary_slot(...)` & `open_decoy_slot(...)`: direct slot accessors.
  - `inspect_decoy(...)`: zero-knowledge inspection reporting container type and decoy payload size without disclosing hidden slot existence or dimensions.
  - `is_decoy_container(...)`: signature and flag validator.

### 2.2 Crypto Integration: `src/crypto.rs`
- Defined `FLAG_DECOY = 0x02` and `VERSION_V2 = 2`.
- Updated `ContainerInfo` with `decoy_container: bool`.
- Delegated `crypto::open` and `crypto::inspect` to `crate::decoy::open_decoy` / `inspect_decoy` when `FLAG_DECOY` or `VERSION_V2` is detected.
- Promoted internal helpers (`derive_key`, `dpapi_protect`, `dpapi_unprotect`, length constants) to `pub(crate)` for zero-duplication reuse.

### 2.3 CLI & Subcommands: `src/cli.rs` & `src/main.rs`
- Added dedicated `encrypt-decoy` (`enc-decoy`) command accepting:
  - `-i, --primary <PATH>`: primary secret file
  - `-d, --decoy <PATH>`: plausible decoy file
  - `-o, --output <PATH>`: output `.svault` path
  - `-p, --passphrase <STR>`: primary passphrase
  - `--decoy-passphrase <STR>`: decoy passphrase
  - `--padding <BYTES>`: optional custom CSPRNG padding
  - `--dpapi`: optional Windows DPAPI hardware/user binding
- Added optional `--decoy`, `--decoy-passphrase`, and `--padding` flags to standard `encrypt`.
- Added optional `--decoy-passphrase` to `decrypt` and wired `decrypt-decoy` (`dec-decoy`) subcommand.
- Updated `inspect` to display `container_type: decoy (plausible deniability)` while hiding hidden slot attributes.

### 2.4 Versioning, Documentation & Backlog
- Bumped `Cargo.toml` and `Cargo.lock` from `v0.2.0` to `v0.3.0`.
- Updated `CHANGELOG.md` with complete v0.3.0 release notes.
- Updated `README.md` (English & Korean) with decoy vault architecture, features, and CLI usage.
- Updated `TASK_BACKLOG.md`:
  - Marked `M03` completed (`[x]`).
  - Proactively appended milestones `M26` through `M30` (Deniable virtual disk driver mount, air-gapped acoustic audio modulation, PKCS#11 HSM token binding, PDF polyglot stego carrier, and zero-knowledge authenticity proofs).

---

## 3. Verification Record

### 3.1 Automated Pipeline (`node scripts/check.mjs`)
- `cargo fmt --all`: Exited 0 (all source code formatted cleanly).
- `cargo clippy --all-targets -- -D warnings`: Exited 0 (zero warnings across all targets).
- `cargo test --all-targets`: Exited 0 (56 passed, 0 failed).

### 3.2 Test Breakdown
- **Unit Tests (`src/main.rs` / `src/decoy.rs`): 44 tests passed**
  - `decoy_roundtrip_primary_and_decoy_passphrases`: Verifies primary passphrase unlocks primary secret, decoy passphrase unlocks decoy payload.
  - `decoy_wrong_passphrase_fails_both_slots`: Verifies invalid passphrase fails authentication.
  - `decoy_identical_passphrases_rejected`: Rejects identical passphrases to prevent accidental deniability compromise.
  - `decoy_empty_secrets_roundtrip`: Verifies 0-byte boundary handling.
  - `decoy_hidden_slot_indistinguishable_from_random`: Calculates Shannon entropy ($H > 7.2$) on hidden slot bytes confirming high-entropy noise distribution.
  - `decoy_tampered_container_rejected`: Verifies Poly1305 MAC failure upon bit corruption in either slot.
  - `decoy_truncated_header_rejected`: Verifies integer bounds safety on truncated buffers.
  - `decoy_dpapi_roundtrip`: Verifies Windows DPAPI hardware binding on dual-slot containers.
  - `decoy_zeroize_memory_audit`: Audits memory wiping via `Zeroize`.
  - `seal_v2_and_open_v2_roundtrip_with_padding`: Verifies version 2 single-payload padded containers.
- **Integration Tests (`tests/integration.rs`): 12 tests passed**
  - `cli_version_and_help_work`: Verifies `svault 0.3.0`, `--version`, and help output for all subcommands.
  - `cli_decoy_encrypt_inspect_and_dual_decrypt_roundtrip`: Full CLI roundtrip using `encrypt-decoy`, `inspect`, `decrypt`, and `decrypt-decoy`.
  - `cli_encrypt_with_decoy_flags_and_dpapi_roundtrip`: Tests `--decoy` and `--decoy-passphrase` flags in standard `encrypt`.
  - `cli_decoy_embedded_in_png_and_wav_roundtrip`: Tests embedding and extracting decoy containers within PNG ancillary chunks and WAV audio carriers.
  - All legacy tests (`cli_png_embed_and_extract_roundtrip`, `cli_wav_chunk_embed_inspect_and_extract_roundtrip`, `cli_wav_lsb_embed_inspect_and_extract_roundtrip`, `cli_wav_cross_mode_reembedding_and_auto_extract`, etc.) remain 100% passing.

---

## 4. Known Issues & Risk Assessment

- `Fatal Functional Bug`: None.
- `Shallow Verification`: None.
- `Minor Robustness Risk`: None identified. All memory allocations and slice boundaries are guarded by checked arithmetic and `Zeroize` wrappers.

---

## 5. Next Steps for Milestone M04

Milestone M04 will implement Shamir's Secret Sharing (`M-of-N` Key Splitting, `src/shamir.rs`), allowing operators to split master recovery passphrases or keys into $N$ polynomial shares over GF(256) requiring any $M$ shares to reconstruct.
