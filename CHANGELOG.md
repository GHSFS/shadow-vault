# Changelog

All notable changes to `shadow-vault` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-10-12

### Added
- Shamir's Secret Sharing engine over $\text{GF}(256)$ (`src/shamir.rs`) for information-theoretically secure $M$-of-$N$ master recovery key and secret splitting.
- Constant-time branchless peasant multiplication and inversion in $\text{GF}(256)$ via Fermat's Little Theorem ($a^{-1} = a^{254}$), with zero data-dependent branches or secret-dependent lookup tables.
- Horner's rule polynomial evaluation and fast Lagrange interpolation at $x = 0$ with precomputed coordinate basis multipliers.
- Dual-layer integrity verification: embedded SHA-256 secret digest for post-reconstruction authentication and per-share CRC-32 checksums for corruption detection.
- Multi-format share serialization: ASCII armored blocks (`-----BEGIN SHADOW VAULT SHARE-----`), compact single-line strings (`SVLT-S1-...`), and structured JSON.
- CLI subcommands `svault split` (aliases: `share`) and `svault combine` (aliases: `recover`, `reconstruct`) with support for file prefixes, piped stdin, direct text secrets, and full `.svault` container splitting.
- Proactive memory zeroization (`zeroize`) wiping share payloads, random polynomial coefficients, and reconstructed secret buffers upon drop.
- Comprehensive unit and integration tests (69 unit + 25 integration, 94 total tests) covering all $\binom{5}{3} = 10$ combinations, large binary payloads, JSON output, and CLI roundtrips.

## [0.3.0] - 2026-10-12

### Added
- Plausible deniability and dual-password decoy vault container engine (`src/decoy.rs`) embedding both primary hidden secrets and harmless decoy payloads within a single container.
- High-entropy hidden slot design: hidden payload slot is statistically indistinguishable from uniform random noise (CSPRNG padding and ChaCha20-Poly1305 ciphertext) to an adversary holding only the decoy passphrase.
- Dedicated CLI subcommands `encrypt-decoy` and `decrypt-decoy`, plus dual-payload flags `--decoy` and `--decoy-passphrase` in `encrypt` and `decrypt`.
- Seamless dual-passphrase decryption: `svault decrypt` unlocks either the primary secret or the decoy secret depending on which passphrase is supplied.
- Deniability-respecting container header inspection (`svault inspect`): identifies decoy containers (`container_type: decoy (plausible deniability)`) and reports outer decoy metadata without disclosing hidden slot existence or dimensions.
- Zeroize memory audit, constant-time Poly1305 tag verification, and integer bounds safety across decoy framing and unpacking routines.
- Comprehensive unit and integration test suite covering dual-password roundtrips, cross-carrier embedding (PNG and WAV), wrong passphrase rejections, and Shannon entropy randomness validation.

## [0.2.0] - 2026-10-12

### Added
- WAV audio carrier steganography engine (`src/wav.rs`) supporting both RIFF/WAVE subchunk (`svLt`) and 16-bit PCM LSB replacement modes with CRC-32 validation.
- CLI subcommands `embed-wav` and `extract-wav` supporting `--mode chunk`, `--mode lsb`, `--lsb`, and `--mode auto`.
- WAV carrier auto-detection in `svault inspect` for inspecting embedded vault containers without prior manual extraction.
- Proactive memory zeroization hardening (`zeroize`) across Argon2id key derivation buffers, ChaCha20 keys, and decrypted DPAPI memory buffers in `src/crypto.rs`.
- Comprehensive unit and integration tests for WAV subchunk, PCM LSB, CRC mismatch verification, and auto extraction.

## [0.1.0] - 2026-10-12

### Added
- Initial `SVLT` v1 container format with Argon2id key derivation and ChaCha20-Poly1305 AEAD encryption.
- Optional Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`) hardware/user-session dual-layer binding (`--dpapi`).
- Lossless PNG ancillary chunk (`svLt`) steganography engine with IEEE 802.3 CRC-32 integrity checks (`svault embed` / `svault extract`).
- Container & carrier header inspection command (`svault inspect`).
- 3-pass secure file shredder (`svault shred`).
- Apache-2.0 license and `NOTICE` attribution file owned by `GHSFS`.
