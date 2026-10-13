# ShadowVault Roadmap

This document tracks shipped features and upcoming cryptographic, steganographic, and hardware-security capabilities planned for `svault`.

---

## Shipped Capabilities

- [x] **Core `SVLT` Container & PNG Chunk Steganography** — Authenticated encryption using Argon2id key derivation and ChaCha20-Poly1305 AEAD, optional Windows DPAPI hardware binding (`--dpapi`), lossless PNG `svLt` chunk injection/extraction, header inspection, and 3-pass file shredding (`svault shred`).
- [x] **WAV Audio Carrier Steganography (`src/wav.rs`)** — Conceal and extract encrypted payloads inside uncompressed 16-bit PCM `.wav` files via dedicated `RIFF`/`WAVE` subchunks or least-significant-bit (LSB) sample encoding (`svault embed-wav` / `svault extract-wav`).
- [x] **Plausible Deniability / Dual-Password Decoy Vault (`src/decoy.rs`)** — Pack both a harmless decoy payload (`--decoy-passphrase`) and a primary secret payload (`--passphrase`) inside a single container indistinguishable from uniform random noise.
- [x] **Shamir's Secret Sharing over GF(256) (`src/shamir.rs`)** — Split recovery keys or containers into $N$ shares requiring any $M$ shares to reconstruct (`svault split` / `svault combine`), with branchless constant-time field arithmetic and dual SHA-256 + CRC-32 integrity checks.
- [x] **Passphrase Strength & Carrier Steganalysis Auditor (`src/audit.rs`)** — Shannon entropy calculation, chi-square randomness testing, keyboard-walk pattern detection, and structural anomaly inspection across PNG/WAV carriers (`svault audit`).
- [x] **RFC 6238 TOTP Two-Factor Vault (`src/totp.rs`)** — Encrypted local TOTP secret storage inside `.svault` containers with live 6/8-digit code generation (`svault totp add`, `svault totp code`), `otpauth://` URI support, and HMAC-SHA1/256/512 engines.
- [x] **Auto-Expiring Windows Clipboard Guard (`src/clipboard_guard.rs`)** — Copy decrypted secrets or TOTP codes directly to the Windows clipboard with cloud/history suppression and automatic zeroization after a configurable TTL (`--clip-ttl`).
- [x] **24-bit BMP Pixel LSB Carrier Engine (`src/bmp.rs`)** — Bit-level R/G/B least-significant-bit steganography across uncompressed 24-bit `.bmp` images with scanline padding preservation and capacity estimation (`svault capacity`).
- [x] **Reed-Solomon Error-Correcting Armor (`src/armor.rs`)** — Cauchy MDS Reed-Solomon parity stripes over GF(256) and PEM-style `.svault.asc` ASCII armoring (`svault armor`, `svault dearmor`, `svault repair`) to recover vaults from bit rot or transport corruption.
- [x] **Directory & Multi-File Manifest Packing (`src/archive.rs`)** — Pack entire directory trees with relative paths, zip bomb defenses, path traversal protection, and per-file SHA-256 digests into a single sealed `SVLT` container (`svault pack-dir` / `svault unpack-dir`).
- [x] **Time-Lock & Expiration Policy Headers (`src/policy.rs`)** — Authenticate `not_before` and `expires_at` UTC timestamps via ChaCha20-Poly1305 AEAD additional authenticated data (`aad`) with Howard Hinnant calendar conversions, ISO-8601 formatting/parsing, and temporal access policy enforcement (`--not-before`, `--expires-at`, `--expires-in`, `--at-time`).
- [x] **Keyfile + Passphrase Two-Factor Derivation (`src/keyfile.rs`)** — Combine external hardware or USB keyfiles (`--keyfile <path>`) with user passphrases via streaming 64 KiB HMAC-SHA256 pre-hashing prior to Argon2id key derivation, supporting 2FA and keyfile-only modes with CSPRNG generation, SHA-256 fingerprinting, and Shannon entropy analysis.
- [x] **Chunked Streaming Encryption for Multi-GB Files (`src/stream.rs`)** — 4 MiB authenticated chunk streaming with per-chunk nonce derivation (`SVST` v1 container) for constant $O(1)$ memory usage on large archives, Windows DPAPI stream key protection, policy time-lock/expiration enforcement, transparent CLI streaming (`svault stream`), and automatic streaming container detection.

---

## Planned Milestones

### Archive & Container Management
- [ ] **Hardware Security Token Hotplug Auto-Lock (`src/token_guard.rs`)** — Monitor USB/PnP security token insertion and removal events via Windows device notification routines to instantly trigger `zeroize` wiping on active memory keys and lock session state upon token detachment.
- [ ] **Container Re-Key & Passphrase Rotation (`svault rotate`)** — Atomically re-encrypt existing `.svault` or stego carriers with fresh salts, nonces, and updated passphrases.
- [ ] **PKCS#11 Smartcard & YubiKey PIV Key Binding (`src/piv.rs`)** — Decrypt vaults using RSA/EC private keys stored on hardware security tokens via PKCS#11 / Windows PIV minidriver (`--piv-slot`).
- [ ] **Detached Integrity Manifest & Canary Verification (`src/canary.rs`)** — Generate and verify signed SHA-256 tamper canaries across vault directories (`svault canary init` / `svault canary verify`).
- [ ] **Interactive In-Memory Vault Shell (`svault repl`)** — Unlock a key-value secret store once in non-pageable memory and query or update entries interactively without touching disk in plaintext.

### Advanced Steganography & Covert Transports
- [ ] **Stego Carrier Visual & Statistical Diff Report (`src/diff.rs`)** — Compute PSNR, MSE, byte-histogram deltas, and chunk table diffs between original and stego carriers (`svault compare`).
- [ ] **MP3 ID3v2 & Frame Padding Steganography (`src/mp3.rs`)** — Embed encrypted containers inside MPEG Audio Layer III files while preserving playback and stream CRC integrity (`svault embed-mp3` / `svault extract-mp3`).
- [ ] **WebP Lossless Stego Carrier Engine (`src/webp.rs`)** — RIFF/WEBP VP8L lossless pixel steganography with metadata preservation (`svault embed-webp` / `svault extract-webp`).
- [ ] **FLAC Lossless Audio Carrier Steganography (`src/flac.rs`)** — Conceal encrypted containers inside FLAC `APPLICATION` metadata blocks and verbatim subframe residual LSB channels (`svault embed-flac` / `svault extract-flac`).
- [ ] **PDF Cross-Reference Stream Steganography (`src/pdf.rs`)** — Conceal containers within incremental PDF revision updates while maintaining document viewability (`svault embed-pdf` / `svault extract-pdf`).
- [ ] **Tar / PAX Archive Header Steganography (`src/tar_stego.rs`)** — Hide containers inside POSIX tar extended headers and trailing padding blocks without breaking standard archive extraction.
- [ ] **Nested Multi-Carrier Steganography (`src/deep_stego.rs`)** — Recursive steganography embedding encrypted audio carriers inside lossless images (`svault nest-embed` / `svault nest-extract`).
- [ ] **QR Code & Optical Air-Gap Bootstrap (`src/qr.rs`, `src/qr_stego.rs`)** — Render and decode terminal/SVG QR codes for offline TOTP provisioning and air-gapped payload transfer.
- [ ] **Air-Gapped Acoustic FSK/OFDM Modulation (`src/acoustic.rs`)** — Encode and decode containers as audio waveforms for offline acoustic transmission (`svault tx-audio` / `svault rx-audio`).
- [ ] **Covert HTTP/2 & DNS-over-HTTPS Framing (`src/network_stego.rs`, `src/doh_stego.rs`)** — Frame encrypted payloads inside synthetic HTTP headers or RFC 8484 DoH envelopes for forensic transport testing.
- [ ] **Fountain Code / Rateless Erasure Streaming (`src/fountain.rs`)** — Rateless Luby Transform droplet encoding over paste or optical streams (`svault fountain-encode` / `svault fountain-decode`).

### Modern & Post-Quantum Cryptography
- [ ] **age-Compatible X25519 Public-Key Sealing (`src/age_box.rs`)** — Seal containers for recipient `age1...` Bech32 keys or `ssh-ed25519` public keys without shared passphrases (`svault seal -r <pubkey>`).
- [ ] **Minisign-Compatible Ed25519 Detached Signatures (`src/sign.rs`)** — Sign and verify encrypted vaults and stego carriers with compact Ed25519 keys (`svault sign` / `svault verify`).
- [ ] **Post-Quantum Hybrid Key Encapsulation (`src/pq_kem.rs`)** — Combine X25519 with NIST FIPS 203 ML-KEM-768 (Kyber) for quantum-resistant vault sealing (`svault kem-seal` / `svault kem-open`).
- [ ] **Stateful Hash-Based Signatures (`src/hash_sig.rs`)** — XMSS / LMS post-quantum signatures for long-term container attestation.
- [ ] **Threshold Schnorr & Ed25519 Signatures (`src/threshold_sig.rs`)** — Cooperative $T$-of-$N$ signing without reconstructing the private key in a single buffer.
- [ ] **Zero-Knowledge Container Authenticity Proofs (`src/zkp.rs`)** — Prove possession or authenticity of a sealed payload without revealing the underlying secret (`svault zkp-prove` / `svault zkp-verify`).
- [ ] **Blind Index & Searchable Encrypted Metadata (`src/blind_index.rs`)** — HMAC-blinded Bloom filters for fast keyword lookups across sealed vaults without leaking query terms.

### Hardware Security & OS Hardening
- [ ] **Memory-Locked Non-Pageable RAM Core (`src/mem_guard.rs`)** — Lock sensitive buffers in physical RAM via Windows `VirtualLock` and Unix `mlock` to prevent swap file leakage.
- [ ] **Dead-Man's Switch / Max-Attempt Self-Shred (`src/guard.rs`)** — Trigger automatic 3-pass shredding after $K$ consecutive failed authentication attempts.
- [ ] **CSPRNG Passphrase & Diceware Generator (`src/passgen.rs`)** — High-entropy passphrase and recovery phrase generation (`svault keygen`).
- [ ] **Structured JSON Output Mode (`--json`)** — Machine-readable JSON output across `inspect`, `audit`, `compare`, and `keygen` for CLI pipelines.
- [ ] **FIDO2 / Windows Hello Biometric Binding (`src/hardware_token.rs`, `src/biometric.rs`)** — Bind vault keys to hardware authenticators and Windows Hello via Win32 `NCrypt` / WebAuthn APIs.
- [ ] **TPM 2.0 PCR Sealing & Attestation (`src/tpm.rs`)** — Seal keys to Windows TPM 2.0 Platform Configuration Registers (`--tpm-pcr`).
- [ ] **PKCS#11 & YubiKey PIV Smartcard Unlocking (`src/pkcs11.rs`, `src/piv.rs`)** — Hardware token key wrapping via PKCS#11 and PIV slot 9D/9E challenge-response.
- [ ] **USB Security Token Removal Auto-Lock (`src/usb_lock.rs`)** — Monitor Windows PnP device removal events to immediately zeroize active session keys when a hardware token is unplugged.
- [ ] **Virtual Disk Mount Integration (`src/mount.rs`)** — Mount `.svault` containers as virtual drives exposing decoy or primary filesystems depending on the unlock credentials.
