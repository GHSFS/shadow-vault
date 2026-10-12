# Changelog

All notable changes to `shadow-vault` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
