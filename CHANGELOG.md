# Changelog

All notable changes to `shadow-vault` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-10-12

### Added
- Auto-Expiring Clipboard Guard Engine (`src/clipboard_guard.rs`).
- Native Windows Win32 API clipboard subsystem integration via `windows` 0.58 (`OpenClipboard`, `EmptyClipboard`, `SetClipboardData`, `CloseClipboard`, `GetClipboardData`, `RegisterClipboardFormatW`, and `GlobalAlloc`/`GlobalLock`/`GlobalUnlock`).
- Windows 10/11 Clipboard History and Cloud Sync suppression: automatically registers and writes suppression flags:
  - `CanIncludeInClipboardHistory` (DWORD 0)
  - `ExcludeClipboardContentFromMonitorProcessing` (DWORD 1)
  - `Clipboard Viewer Ignore` (DWORD 1)
- Constant-time SHA-256 fingerprint verification (`constant_time_eq_32`) preventing race conditions and ensuring the clipboard is cleared only if it still holds the protected secret, preserving subsequent user clipboard updates.
- Real-time terminal visual progress countdown bar (`[████████░░] 12s remaining`), non-blocking console input detection for early Enter-to-clear, and daemon mode for headless execution.
- CLI subcommands:
  - `svault clip copy <text>` (aliases: `set`): Copy secret with configurable auto-expiring TTL (`--ttl <seconds>`) and optional silent mode (`--silent`).
  - `svault clip paste` (aliases: `get`): Read and output current clipboard contents.
  - `svault clip clear` (aliases: `wipe`): Instantly purge and zeroize clipboard content.
  - `svault clip status` (aliases: `info`): Inspect clipboard format metadata and history exclusion status.
- Integration across secret retrieval commands:
  - Added `--clip` and `--clip-ttl <seconds>` flags to `decrypt`, `decrypt-decoy`, `extract`, `extract-wav`, and `totp code`.
- Proactive memory zeroization (`zeroize`) wiping intermediate UTF-16 buffers and secret bytes upon completion.
- Comprehensive test coverage: 129 unit tests and 52 integration tests (181 total tests, 100% pass).

## [0.6.0] - 2026-10-12

### Added
- RFC 6238 TOTP (Time-based One-Time Password) & RFC 4226 HOTP 2FA Vault Engine (`src/totp.rs`).
- Zero-dependency Base32 codec (`base32_decode`, `base32_encode`) conforming to RFC 4648 with case-insensitivity, whitespace/hyphen tolerance, and `Zeroizing<Vec<u8>>` secret buffer clearing.
- Self-contained RFC 3174 SHA-1 implementation operating on 32-bit state without external dependencies.
- RFC 2104 HMAC implementation supporting `SHA1`, `SHA256`, and `SHA512` with block-level padding and internal zeroization.
- RFC 4226 dynamic truncation producing 6-to-8 digit OTP tokens, verified against RFC 4226 Appendix D vectors.
- RFC 6238 time-step calculation with configurable periods (default: 30s), verified against all RFC 6238 Appendix B test vectors across SHA-1, SHA-256, and SHA-512.
- Timing-attack-resistant constant-time code comparison (`constant_time_eq`) with configurable window skew tolerance ($\pm S$).
- Live terminal visual countdown progress bar (`render_progress_bar`, e.g., `[████████░░] 19s remaining`).
- Key URI format (`otpauth://totp/...`) parser and canonical serializer for seamless interoperability with Google Authenticator, Bitwarden, and 1Password.
- Encrypted `TotpVault` container sealed inside `.svault` files using Argon2id + ChaCha20-Poly1305 AEAD and optional Windows DPAPI hardware binding.
- CLI subcommands:
  - `svault totp add`: Add new 2FA credentials via `--secret` or `--uri`.
  - `svault totp code`: Generate current live 2FA code with visual countdown bar or `--json`.
  - `svault totp list`: List stored accounts with issuer, algorithm, and period metadata.
  - `svault totp remove`: Securely delete an account from the encrypted vault.
  - `svault totp verify`: Verify an OTP code against skew tolerance windows.
  - `svault totp import`: Batch import accounts from key URIs or export files.
  - `svault totp export`: Export stored accounts as standard `otpauth://` URIs.
- Machine-readable `--json` output across `code`, `list`, `verify`, and `export` actions.
- Comprehensive test coverage: 124 unit tests and 51 integration tests (175 total tests, 100% pass).

## [0.5.0] - 2026-10-12

### Added
- Passphrase Strength & Steganography Carrier Entropy Auditor (`src/audit.rs`) with subcommands `svault audit <target>` and `svault audit -p <passphrase>`.
- Shannon entropy calculator ($H = -\sum p_i \log_2 p_i$ bits/byte) and Chi-square ($\chi^2$, $df=255$) goodness-of-fit uniformity analysis across plaintext, ciphertext, and media files.
- Passphrase resilience scoring ($0..=4$), character pool diversity analysis, and effective entropy estimation with pattern penalties.
- Predictive vulnerability pattern detectors: consecutive character repetitions, ascending/descending alphanumeric sequences, common keyboard walks (QWERTY layout), and leetspeak-deobfuscated dictionary matching against common weak passwords.
- Multi-threat brute force crack time estimation across online rate-limited (100/s), offline Argon2id ($10^3$/s), and offline GPU hash cluster ($10^{10}$/s) attack vectors.
- Steganography carrier anomaly audit:
  - PNG image chunk validation, private `svLt` chunk detection and CRC-32 verification, and post-IEND trailing byte detection (EOF injection detection).
  - WAV audio RIFF subchunk analysis and 16-bit PCM sample LSB steganography stream detection with magic header validation.
  - `SVLT` container header integrity, salt entropy validation, and ciphertext Shannon entropy verification.
- Structured machine-readable JSON output mode (`svault audit --json`) for automated scripting and CI/CD security pipelines.
- Proactive memory zeroization (`zeroize`) wiping intermediate passphrase buffers and leetspeak deobfuscation buffers from memory upon scope exit.
- Comprehensive unit and integration tests (101 unit + 39 integration, 140 total tests) validating passphrase audits, carrier steganalysis, JSON schema, and CLI roundtrips.

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
