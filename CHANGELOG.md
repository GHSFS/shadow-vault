# Changelog

All notable changes to `shadow-vault` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.22.0] - 2026-10-15

### Added
- FIDO2 / Windows Hello Hardware Key Credential Binding (`src/hardware_token/`):
  - Added multi-factor hardware security key binding support conforming to W3C WebAuthn and FIDO2 / CTAP 2.1 PRF (HMAC-secret) specifications.
  - Decomposed into modular architecture (`src/hardware_token/credential.rs`, `src/hardware_token/provider.rs`, `src/hardware_token/mod.rs`), each under 310 lines.
  - Hardware Authenticator Device Support:
    - `usb`: Physical FIDO2 USB/NFC security keys (YubiKey, SoloKey, Nitrokey, Titan Key).
    - `windows_hello`: Windows Hello platform biometric / PIN authenticators with TPM hardware security module backing.
    - `virtual`: Software-emulated testing authenticators.
  - Cryptographic Key Derivation & Wire Integrity:
    - Added container flag `FLAG_FIDO2 = 0x08`.
    - Extended wire container header with a 4-byte length-prefixed binary header (`SVHW`, version 1, device type, user presence/verification flags, credential ID, RP ID) protected by IEEE 802.3 CRC-32 checksums and ChaCha20-Poly1305 AEAD additional authenticated data (`aad`).
    - Derived 32-byte hardware secrets via CTAP2 PRF / HMAC-secret challenge-response from container salt, and combined with Argon2id base key material via `HMAC-SHA256(hardware_secret, b"shadow-vault-fido2-bound:" || base_key_material)`.
  - CLI Subcommands & Options (`svault fido2`):
    - `svault fido2 enroll`: enrolls new security keys with custom friendly names, device types, relying party IDs, usernames, and authorization PINs, with local descriptor saving or persistent registry integration.
    - `svault fido2 list`: lists enrolled credentials in the credential registry with JSON output support.
    - `svault fido2 test`: executes live challenge-response authenticator assertions and outputs derived secret fingerprints.
    - `svault fido2 remove`: removes credentials from the registry by name or ID.
    - `svault fido2 status`: inspects host platform hardware token capabilities (Windows Hello, WebAuthn API DLL, USB HID detection).
  - Multi-Factor Operations Across Vaults:
    - Added `--fido2`, `--fido2-cred <path>`, and `--fido2-pin <pin>` across `encrypt`, `decrypt`, and `rotate`.
    - Seamless 2FA combination: supports Passphrase + FIDO2, Keyfile + FIDO2, and Windows DPAPI + FIDO2.
    - Added hardware credential binding toggle in `rotate` (`--fido2` to bind, `--no-fido2` to unbind) with time-lock preservation.
  - Proactive `Zeroize` memory wiping on sensitive PRF seeds and effective key material.
- Dedicated Domain Integration Test Suite (`tests/hardware_token_test.rs`):
  - 11 comprehensive integration tests covering hardware capabilities inspection, credential enrollment, PIN authorization, assertion testing, basic & 2FA keyfile roundtrips, wrong credential rejection, tamper rejection, rotation lifecycle, and CLI JSON outputs (100% pass, 515 lines).

## [0.21.0] - 2026-10-14

### Added
- MP3 ID3v2 & Audio Frame Steganography Engine (`src/mp3/`):
  - Added `svault embed-mp3` (alias: `hide-mp3`) and `svault extract-mp3` (alias: `unhide-mp3`) for zero-trust steganographic storage inside MPEG Audio Layer III files.
  - Decomposed into modular architecture (`src/mp3/id3v2.rs`, `src/mp3/frame.rs`, `src/mp3/mod.rs`), each strictly under 340 lines.
  - Dual Steganography Modes:
    - `id3v2` mode (`--mode id3v2`): Conceals encrypted payload within an ID3v2.3 / ID3v2.4 private (`PRIV`) frame with owner identifier `ShadowVault\0`, magic `svLt`, payload length, and CRC-32 integrity checksum. Handles 28-bit syncsafe integers, strips previous ShadowVault frames for idempotent re-embedding, and preserves all existing metadata tags (e.g. TIT2 title, TPE1 artist, TALB album, APIC cover art).
    - `frame` mode (`--mode frame` / `--frame`): Embeds payload into inter-frame padding between MPEG Audio Layer III frames with 0xFFE/0xFFF syncword validation, layer III bit verification, frame length calculation from bitrates/sampling rates/padding bits, and CRC-32 checksums.
    - `auto` extraction mode (`--mode auto`, default): Automatically probes ID3v2 PRIV frames first and falls back to MPEG audio frames with immediate error reporting on carrier corruption or CRC mismatch.
  - Carrier Storage Capacity Estimation:
    - Wired `svault capacity <carrier>` to inspect MP3 files, reporting MPEG version, layer, bitrate, sample rate, channel mode, frame count, total audio bytes, and ID3v2 metadata presence with structured `--json` mode.
  - Ecosystem Integration:
    - Added transparent MP3 carrier rotation (`svault rotate`) in `src/rotate.rs`.
    - Added MP3 format and stego detection in `src/canary.rs` (`detect_carrier_format`).
    - Added transparent MP3 secret extraction in in-memory terminal vault shell (`src/repl/store.rs`).
    - Added MP3 carrier support to directory packaging and unpacking (`pack-dir` / `unpack-dir`) and container inspection (`inspect`).
  - Plausible deniability decoy container embedding (`--decoy`, `--decoy-passphrase`) and zeroize wiping of sensitive passphrase buffers.
- Dedicated Domain Integration Test Suite (`tests/mp3_test.rs`):
  - 8 comprehensive integration tests covering ID3v2 PRIV roundtrips, inter-frame padding embedding, auto-detection mode, decoy plausible deniability, ID3 tag metadata preservation, CRC-32 tamper rejection, DPAPI hardware binding with policy time-locks, and CLI `--json` outputs (100% pass, 674 lines).

## [0.20.0] - 2026-10-14

### Added
- Interactive In-Memory Terminal Vault Shell (`src/repl/`):
  - Added `svault repl` (alias: `shell`) to unlock encrypted key-value secret containers once into memory, enabling operators to query, store, remove, import, and export secrets without touching disk in plaintext.
  - Decomposed into clean modular architecture (`src/repl/store.rs`, `src/repl/command.rs`, `src/repl/mod.rs`), each well under the 500-line soft ceiling.
  - Interactive Shell Commands:
    - `list [filter]` (alias: `ls`): displays secret keys, tags, byte lengths, and update timestamps with optional keyword filtering.
    - `get <key>`: queries secrets with masked preview by default, unmasked reveal (`--reveal`), raw string extraction (`--raw`), and auto-expiring clipboard protection (`--clip`, `--clip-ttl <sec>`).
    - `set <key> <value>` (aliases: `add`, `put`): inserts or updates secret records in memory with optional organizational tags (`--tag`).
    - `del <key>` (aliases: `rm`, `delete`): removes secret entries from the active session.
    - `save` (aliases: `write`, `commit`): re-encrypts the in-memory store and atomically persists it to disk via temporary file rename.
    - `status` (alias: `info`): inspects active session state, uptime, command counter, dirty modification flag, DPAPI binding, and vault path.
    - `export <path>`: exports key-value entries to formatted JSON or raw key-value mapping (`--raw`).
    - `import <path>`: imports secrets into the current session from structured JSON files.
    - `clear` (alias: `cls`): clears terminal viewport.
    - `exit` (aliases: `quit`, `q`): securely zeroizes sensitive in-memory buffers and quits, preventing accidental data loss if modified unless forced (`exit!`, `exit --force`).
  - Non-interactive batch execution: executes single or semicolon-separated commands via `--exec "<cmd>; <cmd>"` or standard input piping (`stdin`).
  - Read-only auditing mode (`--readonly`): strictly prohibits mutations (`set`, `del`, `save`, `import`) for secure auditing and read-only extraction.
  - Automatic session saving (`--auto-save`): automatically re-encrypts dirty vaults upon session termination.
  - Structured machine-readable JSON output mode (`--json`) across all REPL commands and status reports.
  - Memory hardening: implements `Zeroize` on `SecretEntry` and `KeyValueVault` to ensure compiler-fenced zeroization of plaintext values on drop.
- Dedicated Domain Integration Test Suite (`tests/repl_test.rs`):
  - 9 comprehensive integration tests covering in-memory CRUD operations, atomic save & reload integrity, read-only mode protection, piped standard input scripting, status inspection and JSON mode, JSON export and import, wrong passphrase failure rejection, keyfile 2FA integration, and masked vs reveal previews (100% pass, 382 lines).

## [0.19.0] - 2026-10-13

### Added
- Detached Integrity Manifest & Canary Verification Engine (`src/canary.rs`):
  - Added `svault canary init` (aliases: `create`, `generate`) to generate signed tamper canary manifests (`.svault-canary.json`) tracking files, byte sizes, and cryptographic SHA-256 digests across directory trees.
  - Added `svault canary verify` (aliases: `check`, `audit`) to inspect on-disk files against manifests, detecting modified files (bit rot, unauthorized alterations), missing files (deletion), and untracked files with optional `--strict` enforcement.
  - Multi-carrier format auto-detection: automatically identifies `.svault` binary containers, `SVST` chunked streams, `SVAR` directory packages, lossless PNG stego carriers (`svLt` chunks), 24-bit BMP pixel LSB carriers, 16-bit PCM WAV audio carriers, Cauchy Reed-Solomon ASCII armor (`.svault.asc`), and Shamir recovery shares.
  - Cryptographic tamper-proofing: Argon2id key derivation + HMAC-SHA256 signature authentication when protected with a passphrase (`--passphrase`) or keyfile (`--keyfile`), with constant-time signature verification preventing timing analysis attacks.
  - Canonical manifest representation: deterministic lexicographical sorting and format normalization ensuring repeatable signature generation across operating systems.
  - Structured machine-readable JSON output mode (`--json`) for automated CI/CD pipelines and deployment integrity sweeps.
- Dedicated Domain Integration Test Suite (`tests/canary_test.rs`):
  - 10 comprehensive integration tests covering clean roundtrip verification, modified container detection, missing file reporting, strict untracked file enforcement, HMAC passphrase signing and verification, invalid passphrase rejection, tampered manifest detection, carrier format classification, keyfile 2FA binding, and JSON output mode (100% pass, 303 lines).

## [0.18.0] - 2026-10-13

### Added
- Container Re-Key & Passphrase Rotation Engine (`src/rotate.rs`):
  - Seamless re-keying and credential rotation via new `svault rotate` subcommand (alias: `rekey`).
  - Multi-carrier auto-detection supporting standard `.svault` binary containers, stego carriers (PNG `svLt` ancillary chunks, BMP 24-bit pixel LSB, WAV RIFF subchunk and LSB), and Cauchy Reed-Solomon ASCII armor (`.svault.asc`).
  - Fresh CSPRNG entropy: generates independent 16-byte random salt and 12-byte random nonce for every rotation operation, ensuring zero nonce reuse.
  - Windows DPAPI hardware binding control: preserves existing DPAPI configuration by default, or allows explicit enablement (`--dpapi`) and removal (`--no-dpapi`).
  - Cryptographic time-lock & expiration policy preservation: retains authenticated `PolicyHeader` across rotations with ChaCha20-Poly1305 AAD verification, with an optional `--clear-policy` flag to strip policy headers.
  - Atomic in-place file replacement: performs updates via temporary files (`<path>.tmp.<rand>`) with atomic filesystem rename, preventing file corruption in case of unexpected process interruptions.
  - Proactive zeroization: enforces secure memory wiping across all keys, passphrases, and decrypted plaintext buffers.
  - Machine-readable structured JSON report mode (`--json`).
- Dedicated Domain Integration Test Suite (`tests/rotate_test.rs`):
  - 8 comprehensive integration tests covering standard binary containers, atomic in-place rewrites, PNG/BMP/WAV stego carriers, ASCII armored containers, policy time-lock preservation and clearance, DPAPI toggle, authentication failure rejection, and JSON output mode (100% pass, under 400 lines).

## [0.17.0] - 2026-10-13

### Added
- Unified Machine-Readable JSON Output Mode (`--json`) Across All Subcommands:
  - Standardized structured JSON responses across the entire CLI command surface: `encrypt`, `decrypt`, `encrypt-decoy`, `decrypt-decoy`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `armor`, `dearmor`, `repair`, `shred`, `split`, `combine`, `keyfile`, `totp`, `clip`, `guard`, `pack-dir`, `unpack-dir`, `inspect`, `audit`, `compare`, and `keygen`.
  - Consistent envelope schema format with `"status": "ok"`, `"command": "<subcommand>"`, target paths, payload/cipher byte counters, timing metrics, and cryptographic hashes.
  - Carrier type classification in `inspect` JSON output (`carrier_type: "vault" | "stream" | "png" | "wav" | "bmp" | "armor"`).
  - Dedicated Domain Integration Test Suite (`tests/json_test.rs`):
    - 7 comprehensive integration tests covering end-to-end JSON workflows across standard encryption/decryption, dual-password decoy containers, Cauchy Reed-Solomon parity armoring and multi-pass shredding, keyfile generation and fingerprinting, TOTP vault management, Dead-Man guard lifecycle operations, PNG stego embedding/extraction, and clipboard guard operations (100% pass).
    - Fully compliant with modular architecture guidelines (483 lines, under 500-line soft ceiling).

## [0.16.0] - 2026-10-13

### Added
- Deterministic & CSPRNG Passphrase Generator Engine (`src/passgen/`):
  - BIP-39 Diceware recovery phrase generator (`src/passgen/words.rs`, `src/passgen/wordlist.rs`):
    - Curated static dictionary of 2,048 BIP-39 mnemonic words (11.0 bits theoretical keyspace entropy per word).
    - Customizable word count (`--words <N>`, default 6 words for ~66 bits of entropy).
    - Configurable word separators (`--separator <STR>`, default `-`).
    - TitleCase capitalization (`--capitalize`) and inline numeric digit attachment (`--number`).
  - Cryptographic random character passphrase & numeric PIN generator (`src/passgen/chars.rs`):
    - Configurable character length (`--length <N>`, default: 20).
    - Granular character set controls (`--no-symbols`, `--no-numbers`, `--no-upper`).
    - Guaranteed class diversity: ensures at least one character from each active character class followed by uniform Fisher-Yates shuffling.
    - Ambiguous character elimination (`--exclude-ambiguous` filters out `0`, `O`, `o`, `1`, `l`, `I`, `8`, `B`, `|`).
    - Numeric PIN mode (`--pin <N>`).
  - Raw cryptographic byte token generation (`src/passgen/bytes.rs`):
    - Generates CSPRNG random bytes (`--bytes <N>`) with selectable encodings: lowercase hexadecimal (default), standard RFC 4648 Base64 (`--base64`), or RFC 4648 Base32 (`--base32`, compatible with TOTP authenticator secrets).
  - Deterministic reproducible seed derivation:
    - Master seed and context input (`--seed <STR>`, `--context <STR>`) with HMAC-SHA256 derivation into `rand::rngs::StdRng` for reproducible credential generation.
  - Multi-candidate generation (`--count <N>`):
    - Generates $N$ candidate passphrases or keys in a single invocation.
  - Cryptographic keyspace and empirical Shannon entropy assessment (`src/passgen/entropy.rs`):
    - Evaluates theoretical keyspace entropy and empirical distribution metrics from `src/audit.rs`.
    - 5-tier resilience classification badge (`WEAK`, `FAIR`, `STRONG`, `VERY STRONG`, `MILITARY GRADE`).
    - Offline crack time estimates across online rate-limited, Argon2id, and high-throughput GPU threat models.
    - Detailed evaluation flag (`--entropy`).
  - Auto-expiring clipboard guard integration (`--clip`, `--clip-ttl <SECONDS>`):
    - Automatically copies generated secrets to clipboard via `src/clipboard_guard.rs` with Windows clipboard history suppression and TTL memory scrubbing.
  - Structured machine-readable JSON output (`--json`):
    - Exports generated candidates, mode, entropy metrics, strength scores, and crack times.
- Dedicated `keygen` CLI subcommand suite (`svault keygen`, aliases: `svault passgen`, `svault gen-key`).
- Dedicated Domain Integration Test Suite (`tests/passgen_test.rs`):
  - 8 comprehensive integration tests covering Diceware defaults and options, character diversity, ambiguity filtering, raw byte encodings (Hex, Base64, Base32), numeric PINs, deterministic seed reproducibility, multi-candidate generation, JSON output mode, and CLI aliases (100% pass).

## [0.15.0] - 2026-10-13

### Added
- Dead-Man's Switch and Maximum Attempt Self-Destruction Guard Engine (`src/guard.rs`):
  - Authenticated attempt tracking ledger:
    - Protects containers and carriers against unauthorized brute-force attempts and coercive access by maintaining a cryptographically signed attempt ledger (`GuardPolicy`).
    - Configurable maximum attempt thresholds (`--max-attempts`, default: 3). Failed authentication attempts increment the ledger and issue countdown warnings; successful authentication resets failed counters to zero.
    - Multi-pass cryptographic self-shredding: reaching the threshold $K$ triggers a 3-pass DoD-style overwrite (`0x00`, `0xFF`, CSPRNG), flushes hardware buffers (`sync_all`), and permanently deletes the target vault and its ledger.
  - Inactivity dead-man switch timer:
    - Supports inactivity deadline intervals (`--dead-man 7d`, `24h`) and explicit deadlines (`--deadline <ISO8601>`).
    - Operators can check in (`svault guard checkin -t <target> [--interval <dur>]`) to extend the operational window. If the deadline lapses without check-in, the vault automatically executes self-destruction on the next access attempt.
  - Dual storage topologies:
    - Stealth ledger mode (default): stores hashed guard policies in the operator's profile directory (`~/.shadow-vault/guards/<path_hash>.guard`), keeping guard enforcement hidden from filesystem inspection. Configurable via `SVAULT_GUARD_DIR`.
    - Portable companion file mode (`--companion`, `--guard-companion`): stores guard policies alongside targets as `<target>.guard`.
  - Cryptographic tamper resistance:
    - Ledger files are signed with machine-bound seeds and SHA-256 digests over all policy fields. Any unauthorized modification to attempt counters or timestamps causes immediate signature verification failure (`tampering detected`), halting decryption before keys are exposed.
  - Direct carrier and archive protection:
    - Transparent integration across standard vaults, streaming containers, directory archives (`pack-dir`/`unpack-dir`), and steganography carriers (PNG, WAV, BMP).
- Dedicated `guard` CLI subcommand suite (`svault guard`):
  - `svault guard arm -t <target> [-m <max_attempts>] [--dead-man <dur>] [--deadline <ts>] [--passes <n>] [--companion]`: arms a file with guard protections.
  - `svault guard status -t <target> [--json] [--at-time <ts>]`: inspects attempt counts, deadlines, and active policies.
  - `svault guard reset -t <target>`: resets failed attempts counter back to zero.
  - `svault guard checkin -t <target> [--interval <dur>]`: extends dead-man switch expiration window.
  - `svault guard disarm -t <target>`: removes active guard protection without modifying the target.
  - `svault guard trigger -t <target> --force [--passes <n>]`: triggers immediate emergency multi-pass shredding.
  - `svault guard list [--json] [--at-time <ts>]`: enumerates all active stealth guard ledgers.
- Dedicated Domain Integration Test Suite (`tests/guard_test.rs`):
  - 7 integration tests covering companion file mode, stealth ledger mode, success attempt resets, threshold self-shredding, dead-man expiration and check-in, ledger tampering rejection, disarm and forced emergency shredding, and stego PNG carrier self-shredding (100% pass).

## [0.14.0] - 2026-10-13

### Added
- Steganography Carrier Visual & Statistical Diff Report Engine (`src/diff.rs`):
  - Visual image signal quality metrics (MSE, PSNR, MAE):
    - Computes pixel channel squared errors, peak signal-to-noise ratio in decibels ($PSNR = 10 \cdot \log_{10}(255^2 / MSE)$), mean absolute error, and altered pixel percentage for 24-bit uncompressed BMP and PNG images.
    - Bit flip classification: isolates LSB (bit 0) modulations from non-LSB flips to verify pure micro-modulation steganography.
    - Anomaly detection for BMP 4-byte row stride padding modifications.
  - Acoustic audio signal quality metrics (SNR, PSNR, MSE):
    - Evaluates 16-bit PCM audio sample errors, signal-to-noise ratio in decibels ($SNR = 10 \cdot \log_{10}(\sum S_{orig}^2 / \sum (S_{orig} - S_{stego})^2)$), and sample alteration ratios for WAV audio carriers.
  - Structural carrier chunk table diff:
    - PNG chunk inspection: compares `IHDR`, `IDAT`, `IEND`, and injected `svLt` ancillary chunks, verifying whether IDAT raster pixels remain 100% unaltered.
    - WAV RIFF subchunk comparison: tracks added `svLt` metadata subchunks and PCM `data` subchunk modifications.
  - Information-theoretic & byte frequency histogram divergence:
    - Shannon entropy shift ($\Delta H = H_{stego} - H_{orig}$) in bits per byte.
    - 256-bin byte frequency Total Variation Distance ($TVD = \frac{1}{2} \sum |p_{stego} - p_{orig}|$) and Chi-Square divergence ($\chi^2$).
    - Byte-level Hamming distance bit flips and modified byte span ranges.
- Dedicated `compare` CLI command (`svault compare <ORIGINAL> <STEGO>`):
  - Subcommand aliases: `svault diff`.
  - Rich colored terminal report with carrier auto-detection, signal metrics, chunk table diffs, and steganographic verdict.
  - `--json` machine-readable output mode for automated forensic analysis and CI pipelines.
  - `--detailed` flag for extended byte span offsets and histogram delta bins.
- Dedicated Domain Integration Test Suite (`tests/diff_test.rs`):
  - 4 integration tests covering PNG lossless ancillary chunk comparison, BMP LSB micro-modulation analysis, WAV RIFF chunk vs LSB sample comparison, identical file baseline, binary diff with spans, and JSON output mode.

## [0.13.0] - 2026-10-13

### Added
- Chunked Streaming Encryption Engine for Multi-GB Files (`src/stream.rs`):
  - Constant $O(1)$ memory two-buffer sliding window supporting arbitrary file sizes (from 0 bytes to multi-gigabyte files) with zero whole-file buffering.
  - Authenticated `SVST` v1 binary wire format:
    - 38-byte base header: magic `b"SVST"` (4B), version 1 (1B), flags (1B), chunk size (4B LE, 64 KiB–64 MiB, default 4 MiB), salt (16B), and base nonce (12B).
    - Optional authenticated policy header (`SVPO` v1) with temporal access rules (time-lock, expiration).
    - Windows DPAPI stream key protection: 32-byte CSPRNG stream key wrapped with Argon2id-derived ChaCha20-Poly1305 key and bound to machine/user credentials via `CryptProtectData`.
  - Cryptographic chunking & tamper resistance:
    - Per-chunk unique nonce derivation: `SHA256(b"shadow-vault:stream-chunk-nonce:v1" || base_nonce || chunk_index.to_le_bytes() || [chunk_tag])[0..12]`.
    - Per-chunk Additional Authenticated Data (AAD): `b"SVST" || chunk_index.to_le_bytes() || [chunk_tag] || salt || policy_hash`, preventing chunk reordering, truncation, injection, or cross-container splicing attacks.
    - Clean chunk boundary handling: intermediate chunk tag `0x00`, final chunk tag `0x01` (including 0-byte plaintext empty chunk).
- Dedicated `stream` CLI subcommand (`svault stream`):
  - `svault stream encrypt -i <input> -o <output> [-p <pass>] [-k <keyfile>] [--chunk-size <size>] [--dpapi] [--not-before <ts>] [--expires-at <ts>]`: streaming encryption.
  - `svault stream decrypt -i <input> -o <output> [-p <pass>] [-k <keyfile>] [--at-time <ts>]`: streaming decryption.
  - `svault stream inspect <container> [--json]`: zero-decryption header inspection of streaming containers.
- Transparent CLI integration & auto-detection:
  - Added `--stream` flag and `--chunk-size <size>` to `svault encrypt` and `svault decrypt`.
  - Auto-detection: `svault decrypt` and `svault inspect` automatically recognize the `b"SVST"` magic header and dispatch directly to the streaming engine without loading entire containers into memory.
- Steganalysis & Carrier Audit Integration (`src/audit.rs`):
  - Added `CarrierType::StreamContainer` and `audit_stream_container` recognizing `b"SVST"` streaming containers.
  - Computes Shannon entropy, chunk structure, DPAPI binding, and policy header integrity.
- Comprehensive Domain Integration Test Suite (`tests/stream_test.rs`):
  - 10 integration tests covering 0-byte roundtrip, small file roundtrip, exact 64 KiB chunk boundary, multi-chunk roundtrip with auto-detect, 2FA keyfile streaming, policy time-lock and expiration enforcement, chunk tampering rejection, truncated stream detection, carrier audit inspection, and Windows DPAPI hardware binding (100% pass).

## [0.12.0] - 2026-10-13

### Added
- Keyfile + Passphrase Two-Factor Key Derivation engine (`src/keyfile.rs`).
- Streaming 64 KiB HMAC-SHA256 pre-hashing:
  - Constant memory footprint regardless of keyfile size, streaming files of arbitrary length (16 bytes up to multi-megabyte hardware dumps) through a 64 KiB `Zeroizing` buffer.
  - Two-factor authentication (2FA) key derivation: `HMAC-SHA256(key = passphrase, data = "shadow-vault:keyfile-v1:" || keyfile_stream)`, producing a 256-bit high-entropy seed fed into Argon2id.
  - Keyfile-only derivation mode: applies domain separator `b"shadow-vault:keyfile-only:v1"`, enabling passwordless hardware-bound vault operations.
  - Strict validation: rejects empty (0-byte) keyfiles, directory paths, and nonexistent files with descriptive errors.
- Dedicated `keyfile` management CLI command (`svault keyfile`):
  - `svault keyfile generate -o <path> [--bytes 64]`: generates cryptographically secure random keyfiles using OS CSPRNG (`rand::rngs::OsRng`).
  - `svault keyfile inspect <path> [--json]`: audits keyfile size, SHA-256 fingerprint, and Shannon entropy with sample-size normalization.
  - `svault keyfile fingerprint <path>`: prints raw `SHA256:<hex>` fingerprint for verification without leaking key material.
- Universal CLI integration:
  - Added `-k` / `--keyfile <path>` flag to `encrypt`, `decrypt`, `embed`, `extract`, `embed-wav`, `extract-wav`, `embed-bmp`, `extract-bmp`, `pack-dir`, `unpack-dir`, and decoy vaults.
  - Made `--passphrase` optional when `--keyfile` is present on `encrypt`, `embed`, and `pack-dir`, enabling keyfile-only encryption.
- Proactive memory zeroization:
  - Intermediate key blocks, inner/outer HMAC buffers, stream chunks, and final combined secrets are zeroized upon drop via `zeroize::Zeroizing`.
- Comprehensive domain integration test suite (`tests/keyfile_test.rs`):
  - 7 integration tests covering CLI generation, inspection, 2FA roundtrip, keyfile-only mode, wrong keyfile rejection, wrong passphrase rejection, 1-bit tamper detection, empty file rejection, stego PNG carrier with 2FA, and directory packing with 2FA (100% pass).

## [0.11.0] - 2026-10-13

### Added
- Time-Lock & Expiration Policy Header Engine (`src/policy.rs`).
- Authenticated `SVPO` binary wire header format (28+ bytes):
  - Magic prefix `b"SVPO"`, version 1, flags (`FLAG_NOT_BEFORE`, `FLAG_EXPIRES_AT`, `FLAG_DESCRIPTION`), 64-bit UTC timestamps (`created_at`, `not_before`, `expires_at`), optional UTF-8 policy description (up to 256 bytes), and trailing CRC-32 integrity checksum.
- ChaCha20-Poly1305 AEAD Additional Authenticated Data (`aad`) binding:
  - Cryptographically binds the binary policy header directly into the container AEAD ciphertext authentication tag.
  - Zero-tampering guarantee: modifying timestamps or policy descriptions results in immediate Poly1305 authentication rejection.
- Temporal access policy enforcement:
  - Time-lock escrow: vaults configured with `--not-before` reject decryption with `TimeLocked` until the unlock timestamp has passed.
  - Expiration policy: vaults configured with `--expires-at` or `--expires-in` reject decryption with `Expired` once the lifetime has elapsed.
- Howard Hinnant Gregorian calendar algorithms:
  - Zero-dependency, pure-integer civil date conversions (`days_to_ymd`, `ymd_to_days`) handling all Gregorian leap year rules accurately across the full 64-bit timestamp range.
- Flexible CLI parsing and ISO-8601 formatting:
  - Supports ISO-8601 strings (`YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SSZ`), raw Unix timestamps (`1791850000`), and human relative durations (`+1h`, `+7d`, `+30m`, `+1y`).
- Command-line interface integration:
  - Added `--not-before <ts>`, `--expires-at <ts>`, `--expires-in <dur>`, and `--policy-desc <text>` to `encrypt`, `embed`, `embed-wav`, `embed-bmp`, and `pack-dir`.
  - Added `--at-time <ts>` simulation flag to `decrypt`, `decrypt-decoy`, `extract`, `extract-wav`, `extract-bmp`, and `unpack-dir`.
  - Added `--json` flag to `inspect` for machine-readable container and policy metadata.
- Forensics, Steganalysis & Inspection:
  - `svault inspect` displays comprehensive policy metadata: status (`ACTIVE`, `TIMELOCKED`, `EXPIRED`), remaining or elapsed seconds, formatted UTC dates, and description.
  - `svault audit` detects `FLAG_POLICY`, audits policy header integrity, and dynamically aligns ciphertext entropy scanning from the post-policy offset.
- Comprehensive test coverage:
  - 187 unit tests, 3 archive tests, 81 integration tests, and 7 dedicated policy integration tests (`tests/policy_test.rs`) covering active window decryption, time-lock rejection, expiration rejection, Poly1305 AAD tampering rejection, JSON inspect output, stego PNG carriers, and directory archive policy enforcement (278 total tests, 100% pass).

## [0.10.0] - 2026-10-12

### Added
- Directory & Multi-File Manifest Packing Engine (`src/archive.rs`).
- `SVAR` v1 binary archive specification with 18-byte header (`[magic "SVAR": 4B][version 1: 1B][flags: 1B][count: 4B LE][total_size: 8B LE]`) and 8-byte trailer (`[crc32: 4B LE][magic "SVEN": 4B]`).
- Relative path canonicalization and multi-layered Zip Slip / path traversal defense:
  - Rejects `..`, absolute paths, Windows drive letters, UNC shares, colon alternate data streams (ADS), null bytes, and control characters.
  - Rejects Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
  - Verifies extracted paths resolve strictly inside the target destination directory.
- Decompression bomb / Zip bomb protection:
  - Strict caps on maximum total archive size (8 GiB), single file size (4 GiB), entry count (100,000), path length (4,096 bytes), and nesting depth (64 levels).
  - Validates entry length against remaining buffer before allocating data buffers to prevent OOM memory exhaustion.
- Cryptographic SHA-256 per-file manifests:
  - Calculates and embeds authentic SHA-256 digests for each entry.
  - Automatically validates integrity during unpacking and in-memory verification.
- Unix mode and Windows file permissions preservation:
  - Preserves Unix permission bits and Windows readonly attributes in archive manifests.
- Deterministic alphabetical entry sorting:
  - Sorts relative paths canonically for reproducible, deterministic byte-for-byte archives.
- Proactive memory zeroization:
  - Implements `Zeroize` and `ZeroizeOnDrop` across `ArchiveEntry` and `Archive` structures.
- CLI subcommands:
  - `svault pack-dir` (visible alias: `pack`): Packs directory trees into `.svault` containers, with `--dpapi` hardware binding, `--armor` Reed-Solomon export, `--carrier` embedding (PNG, WAV, BMP), `--list`, and `--json`.
  - `svault unpack-dir` (visible alias: `unpack`): Unpacks sealed archives from `.svault`, `.svault.asc`, PNG, WAV, or BMP carriers, supporting `--list`, `--verify-only`, `--overwrite`, and `--json`.
- Transparent stego & armor carrier handling:
  - Seamlessly extracts containers from ASCII armor, PNG chunks, WAV subchunks, or BMP LSB carriers when unpacking.
- Comprehensive test coverage: 180 unit tests, 3 domain archive tests, and 81 integration tests (264 total tests, 100% pass).

## [0.9.0] - 2026-10-12

### Added
- Cauchy MDS Reed-Solomon Error-Correcting Armor Engine (`src/armor.rs`).
- Finite Field arithmetic over $\text{GF}(256)$ with Rijndael polynomial $x^8 + x^4 + x^3 + x + 1$ ($\mathtt{0x11B}$).
- Maximum Distance Separable (MDS) code generator matrix $[I_K; A]$ with Cauchy matrix entries $A_{i, j} = \frac{1}{(K + i) \oplus j}$, guaranteeing that ANY $K$ intact shards out of $K + M$ total stripes uniquely and completely reconstruct all $K$ original data shards.
- Gaussian elimination in $\text{GF}(256)$ with partial pivoting for exact matrix inversion.
- ASCII armored export/import format (`.svault.asc`) with per-stripe CRC-32 integrity checksums, overall SHA-256 digest binding, and 64-character line-wrapped Base64 encoding.
- Automated corruption detection, erasure isolation, and self-healing repair (`repair_armored`) with detailed JSON diagnostic reporting.
- CLI subcommands:
  - `svault armor <flags>` (visible alias: `asc`): Convert a `.svault` container or secret file into an error-correcting ASCII armored file (`.svault.asc`) with configurable data stripes (`-k`) and Cauchy MDS parity stripes (`-m`), plus auto-expiring clipboard guard (`--clip`).
  - `svault dearmor <flags>` (visible aliases: `de-armor`, `unarmor`): Decode `.svault.asc` back into original container or secret file, with transparent Cauchy RS erasure reconstruction if corrupted stripes are detected.
  - `svault repair <flags>` (visible alias: `fix`): Inspect and repair corrupted `.svault.asc` files, regenerating a clean armored document or exporting directly to binary with `--binary`, plus `--json` diagnostic reporting.
- Forensics, Decryption & Steganalysis Integration:
  - Transparent `.svault.asc` dearmoring and Cauchy RS self-healing directly in `svault decrypt` and `svault decrypt-decoy`.
  - Auto-detection of armored files in `svault inspect <target>`, extracting and displaying armor stripe statistics and inner container metadata.
  - Auto-detection of armored files in `svault audit <target>`, auditing stripe CRC-32 checksums, anomaly detection, and reconstruction recommendations.
- Auto-expiring Clipboard Guard Integration:
  - Added `--clip` and `--clip-ttl <seconds>` flags to `armor`, `dearmor`, and `repair`.
- Cryptographic Hardening & Memory Safety:
  - Constant-time verification (`constant_time_eq`) for per-stripe CRC-32 checksums and overall SHA-256 payload digests.
  - Strict bounds and overflow validation on untrusted armor headers, plus duplicate/out-of-range stripe index rejection.
  - Proactive memory zeroization (`Zeroize` / `Zeroizing`) across data shards, parity shards, Base64 buffers, Gaussian elimination matrices, and reconstructed secret buffers.
- Comprehensive test coverage: 168 unit tests and 70 integration tests (238 total tests, 100% pass).

## [0.8.0] - 2026-10-12

### Added
- 24-bit Uncompressed Windows BMP Pixel LSB Steganography Engine (`src/bmp.rs`).
- Pure Rust implementation with zero external image codec dependencies.
- Strict 4-byte row padding preservation: calculates exact row stride and modulates only R, G, B color channels while leaving all padding bytes byte-for-byte untouched.
- 12-byte stego envelope: `[magic "svLt": 4B][len: 4B LE][payload: NB][crc32: 4B LE]`.
- Constant-time CRC-32 validation (`constant_time_eq_4`) protecting against checksum timing attacks.
- Dual DIB orientation support: bottom-up standard bitmaps (positive height) and top-down bitmaps (negative height).
- Universal carrier capacity estimation engine and CLI command: `svault capacity <carrier>` (visible alias: `cap`) with `--json` support across BMP, WAV, and PNG carriers.
- CLI subcommands:
  - `svault embed-bmp <flags>` (visible alias: `hide-bmp`): Encrypt and conceal sensitive files inside 24-bit BMP carriers, with plausible deniability decoy support (`--decoy`, `--decoy-passphrase`), custom padding (`--padding`), and Windows DPAPI hardware binding (`--dpapi`).
  - `svault extract-bmp <flags>` (visible alias: `unhide-bmp`): Extract and decrypt hidden payloads from 24-bit BMP carriers, with optional auto-expiring clipboard integration (`--clip`, `--clip-ttl`).
  - `svault capacity <carrier>`: Universal capacity reporting in text or structured JSON.
- Stego carrier detection and forensic inspection:
  - Wired BMP detection and payload extraction into `svault inspect <target>`.
  - Wired BMP carrier detection and steganalysis anomaly checking into `svault audit <target>`.
- Comprehensive test coverage: 143 unit tests and 57 integration tests (200 total tests, 100% pass).

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
