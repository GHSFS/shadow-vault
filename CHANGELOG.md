# Changelog

All notable changes to `shadow-vault` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-12

### Added
- Initial `SVLT` v1 container format with Argon2id key derivation and ChaCha20-Poly1305 AEAD encryption.
- Optional Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`) hardware/user-session dual-layer binding (`--dpapi`).
- Lossless PNG ancillary chunk (`svLt`) steganography engine with IEEE 802.3 CRC-32 integrity checks (`svault embed` / `svault extract`).
- Container & carrier header inspection command (`svault inspect`).
- 3-pass secure file shredder (`svault shred`).
- Apache-2.0 license and `NOTICE` attribution file owned by `GHSFS`.
