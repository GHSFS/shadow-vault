# ShadowVault (`shadow-vault`) — Hourly Autonomous Development Backlog

> Owned and licensed by **GHSFS** under **Apache License 2.0 + NOTICE**.
> Each scheduled run picks the **first `[ ]` unchecked item** below, implements the module + CLI integration + unit/integration tests, verifies `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --all-targets`, marks the item `[x]`, updates `CHANGELOG.md` and `README.md`, and pushes the commit to `GHSFS/shadow-vault`.

## Completed
- [x] **M01 — Core `SVLT` v1 Container & PNG Steganography Foundation**: Argon2id + ChaCha20-Poly1305 AEAD, Windows DPAPI dual-layer binding (`--dpapi`), lossless PNG `svLt` chunk embedding/extraction, header inspection, and 3-pass secure file shredding (`svault shred`).

## Pending Hourly Milestones
- [ ] **M02 — WAV Audio Carrier Steganography (`src/wav.rs`)**: Embed and extract encrypted `SVLT` payloads inside uncompressed 16-bit PCM `.wav` audio files (`RIFF`/`WAVE` subchunk + LSB mode) with `svault embed-wav` / `svault extract-wav` commands and roundtrip tests.
- [ ] **M03 — Plausible Deniability / Dual-Password Decoy Vault (`src/decoy.rs`)**: Support embedding both a decoy payload (unlocked with `--decoy-passphrase`) and a primary hidden payload (unlocked with `--passphrase`) inside a single container so coercion reveals only the harmless decoy.
- [ ] **M04 — Shamir's Secret Sharing (`M-of-N` Key Splitting, `src/shamir.rs`)**: Split a master recovery key or secret into $N$ GF(256) shares requiring any $M$ shares to reconstruct (`svault split -m 3 -n 5` / `svault combine`).
- [ ] **M05 — Passphrase Strength & Entropy Auditor (`src/audit.rs`)**: Shannon entropy bits-per-byte calculator, common-pattern detector, and carrier steganalysis anomaly check (`svault audit <file>`).
- [ ] **M06 — RFC 6238 TOTP 2FA Vault (`src/totp.rs`)**: Encrypted local TOTP secret store inside `.svault` with live 6-digit code generation (`svault totp add`, `svault totp code`).
- [ ] **M07 — Auto-Expiring Clipboard Guard (`src/clipboard_guard.rs`)**: Copy decrypted secrets or TOTP codes to the Windows clipboard and automatically scrub/clear the clipboard after $N$ seconds (`--clip-ttl 15`).
- [ ] **M08 — BMP 24-bit Pixel LSB Carrier Engine (`src/bmp.rs`)**: Pure bit-level R/G/B least-significant-bit steganography across 24-bit `.bmp` images with capacity estimation (`svault capacity <carrier>`).
- [ ] **M09 — Reed-Solomon / Parity Error-Correcting Armor (`src/armor.rs`)**: Add block parity recovery stripes and ASCII-armored `.svault.asc` export/import so containers survive partial bit rot or text paste channels.
- [ ] **M10 — Directory & Multi-File Manifest Packing (`src/archive.rs`)**: Pack an entire directory tree (relative paths, permissions, SHA-256 per-file digests) into a single encrypted `SVLT` container (`svault pack-dir` / `svault unpack-dir`).
- [ ] **M11 — Time-Lock & Expiration Policy Header (`src/policy.rs`)**: Optional `not_before` and `expires_at` UTC timestamps authenticated via ChaCha20-Poly1305 AAD so expired vaults refuse decryption.
- [ ] **M12 — Keyfile + Passphrase Two-Factor Key Derivation (`src/keyfile.rs`)**: Combine an external hardware/USB keyfile (`--keyfile <path>`) with the user passphrase via HMAC-SHA256 pre-hashing before Argon2id.
- [ ] **M13 — Chunked Streaming Encryption for Multi-GB Files (`src/stream.rs`)**: 4 MiB authenticated chunk streaming with per-chunk nonce derivation so multi-gigabyte archives encrypt with constant O(1) RAM.
- [ ] **M14 — Stego Carrier Visual & Statistical Diff Report (`src/diff.rs`)**: Compare original vs. stego carrier (PSNR, MSE, byte-histogram delta, chunk table diff) via `svault compare <orig> <stego>`.
- [ ] **M15 — Dead-Man's Switch / Max-Attempt Self-Shred (`src/guard.rs`)**: Optional local attempt counter that triggers `shred::shred_file` on the vault if $K$ consecutive wrong passphrase attempts occur.
- [ ] **M16 —Deterministic Passphrase Generator (`src/passgen.rs`)**: CSPRNG passphrase & diceware recovery phrase generator (`svault keygen --words 6` / `--bytes 32`).
- [ ] **M17 — JSON Output Mode (`--json`) Across All Subcommands**: Structured machine-readable JSON output for `inspect`, `audit`, `compare`, and `keygen` for scripting pipelines.
- [ ] **M18 — Container Re-Key & Passphrase Rotation (`svault rotate`)**: Atomically re-encrypt an existing `.svault` or stego PNG with a new passphrase, fresh salt/nonce, and updated DPAPI binding.
- [ ] **M19 — Detached Integrity Manifest & Canary Verification (`src/canary.rs`)**: Generate and verify signed SHA-256 tamper canaries for a directory of `.svault` / stego files (`svault canary init` / `svault canary verify`).
- [ ] **M20 — Interactive Terminal Vault Shell (`svault repl`)**: In-memory session loop that unlocks a key-value secret store once and lets the operator query/add/remove secrets without touching disk in plaintext.
